//! At-rest protection for long-term private key material
//! (`identity.json`, `cryptkey.dat`).
//!
//! On Windows we wrap secret blobs with DPAPI (`CryptProtectData` /
//! `CryptUnprotectData`) scoped to the **current user account**, so a copied
//! or backed-up key file cannot be read under another account or on another
//! machine. This is defense-in-depth on top of the restricted file ACL the
//! files already get — the ACL stops same-machine snooping; DPAPI stops a
//! stolen/exfiltrated file from being usable elsewhere.
//!
//! On Unix we wrap with XChaCha20-Poly1305 keyed by HKDF-SHA256 of this
//! machine's identity plus the real uid (`EMBRSEC4`). Fail closed if the
//! machine-id cannot be read. Restricted file mode (`0600`) remains.
//!
//! Wire format: `MAGIC (8 bytes) || ciphertext` (`EMBRSEC1` = DPAPI,
//! `EMBRSEC2` = XChaCha20-Poly1305 + concatenated IKM (legacy Unix),
//! `EMBRSEC3` = XChaCha20-Poly1305 + length-prefixed IKM and optional
//! OS keyring wrapping key, `EMBRSEC4` = as V3 but keyed by uid instead of
//! `$USER`). Files without MAGIC are treated as legacy plaintext and are
//! transparently re-saved in protected form by the callers on next load.

use zeroize::Zeroizing;

/// Marker prefixing a DPAPI-wrapped blob (Windows).
const MAGIC: &[u8; 8] = b"EMBRSEC1";
/// Marker prefixing an XChaCha20-Poly1305 blob (Unix, concatenated IKM).
const MAGIC_V2: &[u8; 8] = b"EMBRSEC2";
/// Unix wrap with length-prefixed HKDF IKM and optional keyring key.
const MAGIC_V3: &[u8; 8] = b"EMBRSEC3";
/// As V3, but the HKDF identity component is the real uid rather than `$USER`.
///
/// `$USER`/`$LOGNAME` are absent under launchers that do not run a PAM session
/// (bare systemd units, `env -i`, some AppImage/desktop wrappers), which made
/// the V3 HKDF key underivable and a healthy profile unopenable; and they are
/// caller-settable, so the same uid could derive two different keys across
/// launches. `getuid()` has neither problem.
const MAGIC_V4: &[u8; 8] = b"EMBRSEC4";

#[cfg(not(target_os = "windows"))]
const KEY_SRC_HKDF: u8 = 0;
#[cfg(not(target_os = "windows"))]
const KEY_SRC_KEYRING: u8 = 1;

/// Extra entropy mixed into DPAPI so a protected blob can only be unwrapped by
/// this application's code path (not by another DPAPI consumer on the system).
#[cfg(target_os = "windows")]
const ENTROPY: &[u8] = b"ember-secret-store-v1";

/// True if `stored` is readable but sealed under a superseded scheme, so the
/// caller should re-`protect` it after a successful `unprotect`.
///
/// `EMBRSEC2`/`EMBRSEC3` derive their key from `$USER`, which a launcher need
/// not export — so a profile can become unopenable through no fault of its own,
/// and `EMBRSEC4` (keyed by `getuid()`) exists to remove that dependency. A
/// legacy blob only stops depending on the environment once it has been
/// rewritten, and nothing rewrites it on its own: `is_protected` is true for
/// these, so the callers' "protect it if it is bare plaintext" path never fires.
///
/// Platform-independent by design. On Windows these magics belong to another
/// platform's scheme and `unprotect` refuses them outright, so the caller never
/// reaches a re-wrap.
pub fn needs_rewrap(stored: &[u8]) -> bool {
    stored.len() >= 8 && (&stored[..8] == MAGIC_V2 || &stored[..8] == MAGIC_V3)
}

/// True if `stored` is already in a protected (MAGIC-tagged) form.
pub fn is_protected(stored: &[u8]) -> bool {
    stored.len() >= 8
        && (&stored[..8] == MAGIC
            || &stored[..8] == MAGIC_V2
            || &stored[..8] == MAGIC_V3
            || &stored[..8] == MAGIC_V4)
}

/// Wrap `plaintext` for at-rest storage. On success returns
/// `MAGIC || ciphertext`.
///
/// A protect failure returns `Err` and the caller MUST NOT fall back to
/// writing the secret unencrypted.
pub fn protect(plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    #[cfg(target_os = "windows")]
    {
        match win::protect(plaintext, ENTROPY) {
            Ok(ct) => {
                let mut out = Vec::with_capacity(MAGIC.len() + ct.len());
                out.extend_from_slice(MAGIC);
                out.extend_from_slice(&ct);
                Ok(out)
            }
            Err(e) => Err(anyhow::anyhow!(
                "DPAPI protect failed ({e}); refusing to write secret material unencrypted"
            )),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        unix::protect(plaintext)
    }
}

/// Inverse of [`protect`]. MAGIC-tagged blobs are decrypted; anything else is
/// treated as legacy plaintext. Returns `Err` when a tagged blob fails to
/// decrypt (wrong user/machine, or corruption) — callers treat that like a
/// corrupt secret file rather than silently rotating identity.
///
/// The result is `Zeroizing` because it is the long-term private key material
/// itself (identity, SecIdent keypair, chat-history key): without a wiping
/// destructor the plaintext survives in freed heap for the rest of the process
/// lifetime and lands in any crash dump written afterwards.
pub fn unprotect(stored: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if stored.len() >= 8 && &stored[..8] == MAGIC {
        #[cfg(target_os = "windows")]
        {
            return win::unprotect(&stored[MAGIC.len()..], ENTROPY)
                .map_err(|e| anyhow::anyhow!("DPAPI unprotect failed: {e}"));
        }
        #[cfg(not(target_os = "windows"))]
        {
            anyhow::bail!(
                "secret file is DPAPI-protected but this is a non-Windows build; \
                 move the file back to the Windows machine that created it"
            );
        }
    }
    if stored.len() >= 8
        && (&stored[..8] == MAGIC_V2 || &stored[..8] == MAGIC_V3 || &stored[..8] == MAGIC_V4)
    {
        #[cfg(not(target_os = "windows"))]
        {
            return unix::unprotect(stored);
        }
        #[cfg(target_os = "windows")]
        {
            anyhow::bail!(
                "secret file is Unix-protected but this is a Windows build; \
                 move the file back to the machine that created it"
            );
        }
    }
    Ok(Zeroizing::new(stored.to_vec()))
}

/// Key-derivation composition, deliberately **not** behind a platform `cfg`.
///
/// Everything here is pure: no syscall, no filesystem, no `libc`. It lives
/// outside the `unix` module so that `cargo check` and the test suite cover it
/// on every host, including Windows. Only the three things that genuinely
/// cannot be — reading the machine id, `getuid`, and the passwd lookup — stay
/// Unix-gated, and each is a thin wrapper that feeds these functions.
///
/// That split matters because the Unix wrapping scheme cannot be compiled on a
/// Windows-only toolchain (`aws-lc-sys` needs a Linux C cross-compiler for a
/// `--target` build), so anything left inside the `cfg` is verified by CI alone.
///
/// The `dead_code` allow is scoped to Windows on purpose: there is no Windows
/// caller — being compiled and unit-tested on this host is the entire point —
/// but on Unix these are load-bearing, so an unused one there is still a
/// warning worth seeing.
#[cfg_attr(target_os = "windows", allow(dead_code))]
mod derive {
    use hkdf::Hkdf;
    use sha2::Sha256;

    pub fn push_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(data);
    }

    pub fn expand(salt: &[u8], info: &[u8], ikm: &[u8]) -> anyhow::Result<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
        let mut key = [0u8; 32];
        hk.expand(info, &mut key)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
        Ok(key)
    }

    /// Input keying material for `EMBRSEC4`.
    ///
    /// `uid` is a plain `u32` rather than `libc::uid_t` so this composes without
    /// the Unix-only dependency; the two are the same type on every target this
    /// ships to.
    pub fn uid_ikm(id: &[u8], uid: u32) -> Vec<u8> {
        let mut ikm = Vec::new();
        push_len_prefixed(&mut ikm, id);
        push_len_prefixed(&mut ikm, &uid.to_be_bytes());
        ikm
    }

    /// Input keying material for `EMBRSEC2` (concatenated) and `EMBRSEC3`
    /// (length-prefixed). Reproduces what was used at write time byte for byte,
    /// so neither form may change.
    pub fn legacy_ikm(id: &[u8], username: &str, length_prefixed: bool) -> Vec<u8> {
        let mut ikm = Vec::new();
        if length_prefixed {
            push_len_prefixed(&mut ikm, id);
            push_len_prefixed(&mut ikm, username.as_bytes());
        } else {
            ikm.extend_from_slice(id);
            ikm.extend_from_slice(username.as_bytes());
        }
        ikm
    }

    /// The identities a legacy blob might have been sealed under, in the order
    /// to try them.
    ///
    /// `$USER` then `$LOGNAME` first, because that is exactly what the old
    /// derivation read, so an install where the environment is intact keeps
    /// deriving the same key on the first attempt. The passwd name comes last as
    /// a recovery path for launchers that export no environment (a systemd unit
    /// without a PAM session, `env -i`, some AppImage wrappers), where the old
    /// scheme could not derive its key at all and a healthy profile would not
    /// open. It is not a guess: `login`/PAM sets `$USER` *from* the passwd
    /// entry, so on the overwhelming majority of installs it is the same string.
    ///
    /// Empty values are dropped and duplicates collapsed, so the common case
    /// where all three agree costs exactly one derivation.
    pub fn ordered_legacy_usernames(candidates: &[Option<String>]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for name in candidates.iter().flatten() {
            if !name.is_empty() && !out.iter().any(|held| held == name) {
                out.push(name.clone());
            }
        }
        out
    }
}

#[cfg(test)]
mod derive_tests {
    use super::derive::*;

    #[test]
    fn uid_ikm_is_unambiguous_and_uid_dependent() {
        // Length prefixes mean no (machine-id, uid) pair can collide with a
        // different pair by concatenating to the same bytes.
        assert_ne!(uid_ikm(b"ab", 1), uid_ikm(b"a", 0x62000001));
        assert_ne!(uid_ikm(b"machine", 1000), uid_ikm(b"machine", 1001));
        assert_eq!(uid_ikm(b"machine", 1000), uid_ikm(b"machine", 1000));
    }

    #[test]
    fn legacy_ikm_keeps_both_historical_shapes() {
        // V2 concatenated; V3 length-prefixed. Both must stay reproducible.
        assert_eq!(legacy_ikm(b"mid", "bob", false), b"midbob".to_vec());
        let v3 = legacy_ikm(b"mid", "bob", true);
        assert_eq!(&v3[..4], &3u32.to_be_bytes());
        assert_eq!(&v3[4..7], b"mid");
        assert_eq!(&v3[7..11], &3u32.to_be_bytes());
        assert_eq!(&v3[11..], b"bob");
        // The V2 shape is genuinely ambiguous, which is why V3 exists.
        assert_eq!(
            legacy_ikm(b"ab", "c", false),
            legacy_ikm(b"a", "bc", false)
        );
        assert_ne!(legacy_ikm(b"ab", "c", true), legacy_ikm(b"a", "bc", true));
    }

    #[test]
    fn legacy_username_order_prefers_the_environment_and_dedupes() {
        let all_same = ordered_legacy_usernames(&[
            Some("bob".into()),
            Some("bob".into()),
            Some("bob".into()),
        ]);
        assert_eq!(all_same, vec!["bob".to_string()], "one derivation, not three");

        let ordered = ordered_legacy_usernames(&[
            Some("envuser".into()),
            None,
            Some("passwduser".into()),
        ]);
        assert_eq!(
            ordered,
            vec!["envuser".to_string(), "passwduser".to_string()],
            "the environment is tried first so existing installs are unaffected"
        );

        // The case the passwd fallback exists for: no environment at all.
        assert_eq!(
            ordered_legacy_usernames(&[None, None, Some("passwduser".into())]),
            vec!["passwduser".to_string()]
        );
        // And empty strings are not identities.
        assert!(ordered_legacy_usernames(&[Some(String::new()), None, None]).is_empty());
    }

    #[test]
    fn expand_is_deterministic_and_salt_separated() {
        let a = expand(b"salt-a", b"info", b"ikm").unwrap();
        assert_eq!(a, expand(b"salt-a", b"info", b"ikm").unwrap());
        assert_ne!(a, expand(b"salt-b", b"info", b"ikm").unwrap());
        assert_ne!(a, expand(b"salt-a", b"info-2", b"ikm").unwrap());
    }
}

#[cfg(not(target_os = "windows"))]
mod unix {
    use super::derive::{expand, legacy_ikm, ordered_legacy_usernames, uid_ikm};
    use super::{KEY_SRC_HKDF, KEY_SRC_KEYRING, MAGIC_V2, MAGIC_V3, MAGIC_V4};
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{Key as ChaChaKey, XChaCha20Poly1305, XNonce};
    use hkdf::Hkdf;
    use rand::{rngs::OsRng, RngCore};
    use sha2::Sha256;
    use zeroize::{Zeroize, Zeroizing};

    const NONCE_LEN: usize = 24;
    const HKDF_SALT_V2: &[u8] = b"ember-secret-store-v2";
    const HKDF_INFO_V2: &[u8] = b"ember-secret-store-v2-key";
    const HKDF_SALT_V3: &[u8] = b"ember-secret-store-v3";
    const HKDF_INFO_V3: &[u8] = b"ember-secret-store-v3-key";
    const HKDF_SALT_V4: &[u8] = b"ember-secret-store-v4";
    const HKDF_INFO_V4: &[u8] = b"ember-secret-store-v4-key";

    fn machine_id() -> anyhow::Result<Vec<u8>> {
        #[cfg(target_os = "linux")]
        {
            for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
                if let Ok(s) = std::fs::read_to_string(path) {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        return Ok(trimmed.as_bytes().to_vec());
                    }
                }
            }
            anyhow::bail!("machine-id unreadable")
        }
        #[cfg(target_os = "macos")]
        {
            let mut uuid = [0u8; 16];
            let wait = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: `uuid` is a 16-byte buffer; `wait` is a valid timespec.
            let rc = unsafe { libc::gethostuuid(uuid.as_mut_ptr(), &wait) };
            if rc != 0 || uuid.iter().all(|&b| b == 0) {
                anyhow::bail!("gethostuuid failed");
            }
            Ok(uuid.to_vec())
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            anyhow::bail!("no machine-id source on this Unix target")
        }
    }

    /// The login name the passwd database gives for our real uid.
    ///
    /// The recovery half of [`legacy_username_candidates`]: `$USER` is absent
    /// under launchers with no PAM session, and this is where `login` would have
    /// read it from in the first place.
    fn passwd_username() -> Option<String> {
        // SAFETY: `getpwuid` returns a pointer into a static buffer owned by
        // libc, valid until the next passwd call on this thread. We copy out of
        // `pw_name` before returning and make no further passwd calls in
        // between, and we null-check both the entry and the name pointer.
        unsafe {
            let uid = libc::getuid();
            let pw = libc::getpwuid(uid);
            if pw.is_null() || (*pw).pw_name.is_null() {
                return None;
            }
            std::ffi::CStr::from_ptr((*pw).pw_name)
                .to_str()
                .ok()
                .map(str::to_owned)
        }
    }

    /// Every identity an `EMBRSEC2`/`EMBRSEC3` blob might have been sealed
    /// under, in the order to try them. See
    /// [`super::derive::ordered_legacy_usernames`] for why this order.
    fn legacy_username_candidates() -> Vec<String> {
        ordered_legacy_usernames(&[
            std::env::var("USER").ok(),
            std::env::var("LOGNAME").ok(),
            passwd_username(),
        ])
    }

    fn hkdf_key_uid(salt: &[u8], info: &[u8]) -> anyhow::Result<[u8; 32]> {
        let id = machine_id()?;
        // SAFETY: `getuid` takes no arguments, cannot fail, and touches no
        // caller-owned memory.
        let uid = unsafe { libc::getuid() };
        expand(salt, info, &uid_ikm(&id, uid))
    }

    /// Decrypt a legacy (`EMBRSEC2`/`EMBRSEC3`) body, trying each plausible
    /// identity until one authenticates.
    ///
    /// Trying several derivations cannot widen what a key opens — the Poly1305
    /// tag is still the only thing that decides, and each candidate is a
    /// derivation the old scheme could itself have produced. What it buys is
    /// recoverability: a profile whose `$USER` is simply not exported was
    /// previously unopenable, with the failure surfacing as "your keyring is
    /// locked", which sent the user to fix something that was never wrong.
    fn decrypt_legacy(
        salt: &[u8],
        info: &[u8],
        length_prefixed: bool,
        nonce: &[u8],
        ct: &[u8],
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let id = machine_id()?;
        let candidates = legacy_username_candidates();
        if candidates.is_empty() {
            anyhow::bail!(
                "no legacy identity available: neither $USER/$LOGNAME nor the passwd \
                 entry for this uid could be read"
            );
        }
        let mut last_err = None;
        for name in &candidates {
            let mut key = expand(salt, info, &legacy_ikm(&id, name, length_prefixed))?;
            let result = decrypt_with(&key, nonce, ct);
            key.zeroize();
            match result {
                Ok(plain) => return Ok(plain),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("legacy secret decrypt failed")))
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn keyring_entry() -> anyhow::Result<keyring::Entry> {
        keyring::Entry::new("ember-p2p", "secret-store-v3")
            .map_err(|e| anyhow::anyhow!("keyring: {e}"))
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn decode_keyring_key(stored: &str) -> anyhow::Result<[u8; 32]> {
        let bytes =
            hex::decode(stored.trim()).map_err(|_| anyhow::anyhow!("keyring key is not hex"))?;
        if bytes.len() != 32 {
            anyhow::bail!("keyring key wrong length");
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    }

    /// Read the keyring-held wrapping key, never creating one.
    ///
    /// This is what the decrypt path must use. Minting a key here would be
    /// unrecoverable: `set_password` replaces the key every existing
    /// `KEY_SRC_KEYRING` blob was sealed under, so a keyring that is merely
    /// unreachable for one launch (locked collection, no D-Bus session, a
    /// login keyring that was reset) would turn `identity.json` and
    /// `cryptkey.dat` into permanently undecryptable files — destroying the
    /// KAD ID, user hash, friendships and credits the surrounding code exists
    /// to preserve.
    fn keyring_wrapping_key_existing() -> anyhow::Result<[u8; 32]> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let entry = keyring_entry()?;
            let stored = entry
                .get_password()
                .map_err(|e| anyhow::anyhow!("keyring read: {e}"))?;
            decode_keyring_key(&stored)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            anyhow::bail!("no keyring on this Unix target")
        }
    }

    /// Read the wrapping key for sealing, minting one only when the entry is
    /// genuinely absent.
    ///
    /// Every other error is propagated so `protect` falls back to the
    /// machine-id HKDF key and records that choice in the source byte, rather
    /// than overwriting a key it could not read.
    fn keyring_wrapping_key_for_protect() -> anyhow::Result<[u8; 32]> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let entry = keyring_entry()?;
            match entry.get_password() {
                Ok(stored) => decode_keyring_key(&stored),
                Err(keyring::Error::NoEntry) => {
                    let mut key = [0u8; 32];
                    OsRng.fill_bytes(&mut key);
                    entry
                        .set_password(&hex::encode(key))
                        .map_err(|e| anyhow::anyhow!("keyring store: {e}"))?;
                    Ok(key)
                }
                Err(e) => Err(anyhow::anyhow!("keyring read: {e}")),
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            anyhow::bail!("no keyring on this Unix target")
        }
    }

    fn encrypt_with(key: &[u8; 32], plaintext: &[u8]) -> anyhow::Result<( [u8; NONCE_LEN], Vec<u8>)> {
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .map_err(|_| anyhow::anyhow!("XChaCha20-Poly1305 protect failed"))?;
        Ok((nonce, encrypted))
    }

    fn decrypt_with(key: &[u8; 32], nonce: &[u8], ct: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
        let plain = cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: &[],
                },
            )
            .map_err(|_| anyhow::anyhow!("XChaCha20-Poly1305 unprotect failed"))?;
        Ok(Zeroizing::new(plain))
    }

    pub fn protect(plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (src, mut key) = match keyring_wrapping_key_for_protect() {
            Ok(k) => (KEY_SRC_KEYRING, k),
            Err(_) => (KEY_SRC_HKDF, hkdf_key_uid(HKDF_SALT_V4, HKDF_INFO_V4)?),
        };
        let result = encrypt_with(&key, plaintext);
        key.zeroize();
        let (nonce, encrypted) = result?;
        let mut out = Vec::with_capacity(MAGIC_V4.len() + 1 + NONCE_LEN + encrypted.len());
        out.extend_from_slice(MAGIC_V4);
        out.push(src);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&encrypted);
        Ok(out)
    }

    pub fn unprotect(stored: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        // V3 and V4 share a body layout and differ only in how the
        // `KEY_SRC_HKDF` key is derived; `KEY_SRC_KEYRING` blobs are unaffected
        // by the identity component and read the same either way.
        let versioned = if stored.len() >= 8 && &stored[..8] == MAGIC_V4 {
            Some(("EMBRSEC4", true))
        } else if stored.len() >= 8 && &stored[..8] == MAGIC_V3 {
            Some(("EMBRSEC3", false))
        } else {
            None
        };
        if let Some((label, uid_keyed)) = versioned {
            if stored.len() < 8 + 1 + NONCE_LEN {
                anyhow::bail!("{label} blob too short");
            }
            let src = stored[8];
            let nonce = &stored[9..9 + NONCE_LEN];
            let ct = &stored[9 + NONCE_LEN..];
            if src == KEY_SRC_HKDF && !uid_keyed {
                return decrypt_legacy(HKDF_SALT_V3, HKDF_INFO_V3, true, nonce, ct);
            }
            let mut key = match src {
                KEY_SRC_KEYRING => keyring_wrapping_key_existing()?,
                KEY_SRC_HKDF => hkdf_key_uid(HKDF_SALT_V4, HKDF_INFO_V4)?,
                _ => anyhow::bail!("unknown {label} key source"),
            };
            let result = decrypt_with(&key, nonce, ct);
            key.zeroize();
            return result;
        }
        if stored.len() >= 8 && &stored[..8] == MAGIC_V2 {
            let body = &stored[MAGIC_V2.len()..];
            if body.len() < NONCE_LEN {
                anyhow::bail!("EMBRSEC2 blob too short");
            }
            return decrypt_legacy(
                HKDF_SALT_V2,
                HKDF_INFO_V2,
                false,
                &body[..NONCE_LEN],
                &body[NONCE_LEN..],
            );
        }
        anyhow::bail!("not a Unix-protected secret blob")
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The whole point of moving off `$USER`: the same uid must derive the
        /// same wrapping key no matter what the launcher exported, including
        /// exporting nothing at all.
        #[test]
        fn uid_derived_key_is_stable_across_differing_usernames() {
            let previous_user = std::env::var("USER").ok();
            let previous_logname = std::env::var("LOGNAME").ok();

            std::env::set_var("USER", "alice");
            std::env::set_var("LOGNAME", "alice");
            let first = hkdf_key_uid(HKDF_SALT_V4, HKDF_INFO_V4);
            std::env::set_var("USER", "bob");
            std::env::set_var("LOGNAME", "bob");
            let second = hkdf_key_uid(HKDF_SALT_V4, HKDF_INFO_V4);
            std::env::remove_var("USER");
            std::env::remove_var("LOGNAME");
            let third = hkdf_key_uid(HKDF_SALT_V4, HKDF_INFO_V4);

            match previous_user {
                Some(v) => std::env::set_var("USER", v),
                None => std::env::remove_var("USER"),
            }
            match previous_logname {
                Some(v) => std::env::set_var("LOGNAME", v),
                None => std::env::remove_var("LOGNAME"),
            }

            // A host without a readable machine-id fails closed at every call;
            // the invariant under test is only meaningful when it succeeds.
            if let Ok(expected) = first {
                assert_eq!(second.unwrap(), expected, "$USER must not affect the key");
                assert_eq!(
                    third.unwrap(),
                    expected,
                    "an unset $USER must still derive the key"
                );
            }
        }

    }
}

#[cfg(target_os = "windows")]
mod win {
    use std::os::raw::c_void;
    use zeroize::{Zeroize, Zeroizing};

    /// Win32 `DATA_BLOB` (a.k.a. `CRYPTOAPI_BLOB`).
    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    /// `CRYPTPROTECT_UI_FORBIDDEN` — never show UI; fail instead (we run headless
    /// from a network task).
    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            p_data_in: *const DataBlob,
            sz_data_descr: *const u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut c_void,
            p_prompt_struct: *mut c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;
        fn CryptUnprotectData(
            p_data_in: *const DataBlob,
            pp_sz_data_descr: *mut *mut u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut c_void,
            p_prompt_struct: *mut c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
    }

    fn blob(data: &[u8]) -> DataBlob {
        DataBlob {
            // DPAPI inputs are far smaller than u32::MAX; clamp defensively.
            cb_data: data.len().min(u32::MAX as usize) as u32,
            pb_data: data.as_ptr() as *mut u8,
        }
    }

    /// Copy the Windows-allocated output blob into an owned `Vec`, wipe the
    /// original, and release it with `LocalFree`.
    ///
    /// `LocalFree` returns the pages to the process heap without clearing
    /// them, so for `CryptUnprotectData` the decrypted key material would stay
    /// legible in freed memory (and in a crash dump) until something else
    /// happened to reuse the allocation. `Zeroize` for `[u8]` writes through a
    /// volatile pointer and fences, so the wipe cannot be optimised away as a
    /// dead store to memory we are about to free.
    ///
    /// # Safety
    /// `out` must be an output blob populated by a successful
    /// `CryptProtectData`/`CryptUnprotectData` call (non-null `pb_data`).
    unsafe fn take_out_blob(out: &DataBlob) -> Vec<u8> {
        let buffer = std::slice::from_raw_parts_mut(out.pb_data, out.cb_data as usize);
        let v = buffer.to_vec();
        buffer.zeroize();
        LocalFree(out.pb_data as *mut c_void);
        v
    }

    pub fn protect(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String> {
        let in_blob = blob(plaintext);
        let ent_blob = blob(entropy);
        let mut out = DataBlob {
            cb_data: 0,
            pb_data: std::ptr::null_mut(),
        };
        // SAFETY: `in_blob`/`ent_blob` borrow live slices for the duration of
        // the call; all other pointer args are null/optional per the DPAPI
        // contract. On success Windows allocates `out.pb_data`, which
        // `take_out_blob` copies and frees.
        let ok = unsafe {
            CryptProtectData(
                &in_blob,
                std::ptr::null(),
                &ent_blob,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 || out.pb_data.is_null() {
            return Err("CryptProtectData failed".to_string());
        }
        Ok(unsafe { take_out_blob(&out) })
    }

    pub fn unprotect(ciphertext: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        let in_blob = blob(ciphertext);
        let ent_blob = blob(entropy);
        let mut out = DataBlob {
            cb_data: 0,
            pb_data: std::ptr::null_mut(),
        };
        // SAFETY: see `protect`. The entropy must match what was used to
        // protect, otherwise DPAPI fails and we return Err.
        let ok = unsafe {
            CryptUnprotectData(
                &in_blob,
                std::ptr::null_mut(),
                &ent_blob,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 || out.pb_data.is_null() {
            return Err("CryptUnprotectData failed".to_string());
        }
        // Moving the `Vec` into `Zeroizing` rehomes the pointer, not the bytes,
        // so the plaintext never exists in a second buffer.
        Ok(Zeroizing::new(unsafe { take_out_blob(&out) }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_protect_unprotect() {
        let secret = b"super secret key material \x00\x01\x02";
        let wrapped = protect(secret).expect("protect");
        let recovered = unprotect(&wrapped).expect("unprotect");
        assert_eq!(&recovered[..], &secret[..]);
    }

    #[test]
    fn legacy_plaintext_passes_through() {
        // A blob without MAGIC is returned unchanged (legacy migration path).
        let legacy = b"{\"kad_id\":[1,2,3]}";
        assert!(!is_protected(legacy));
        assert_eq!(&unprotect(legacy).unwrap()[..], &legacy[..]);
    }

    #[test]
    fn superseded_unix_schemes_ask_to_be_rewrapped() {
        // The point of the signal: these are readable, so `is_protected` is
        // true and the callers' plaintext-upgrade path never fires — without an
        // explicit ask they would keep their `$USER` dependency forever.
        for magic in [b"EMBRSEC2", b"EMBRSEC3"] {
            let mut blob = magic.to_vec();
            blob.extend_from_slice(&[0u8; 40]);
            assert!(super::needs_rewrap(&blob));
            assert!(super::is_protected(&blob));
        }
        let mut current = b"EMBRSEC4".to_vec();
        current.extend_from_slice(&[0u8; 40]);
        assert!(!super::needs_rewrap(&current), "the current scheme is final");
        let mut dpapi = b"EMBRSEC1".to_vec();
        dpapi.extend_from_slice(&[0u8; 40]);
        assert!(!super::needs_rewrap(&dpapi));
        assert!(!super::needs_rewrap(b"short"));
        assert!(!super::needs_rewrap(b"plaintext with no magic at all"));
    }

    #[test]
    fn foreign_platform_magic_is_rejected() {
        #[cfg(target_os = "windows")]
        {
            let mut blob = Vec::from(*b"EMBRSEC2");
            blob.extend_from_slice(&[0u8; 40]);
            assert!(is_protected(&blob));
            assert!(unprotect(&blob).is_err());
            let mut v3 = Vec::from(*b"EMBRSEC3");
            v3.extend_from_slice(&[0u8; 40]);
            assert!(is_protected(&v3));
            assert!(unprotect(&v3).is_err());
            let mut v4 = Vec::from(*b"EMBRSEC4");
            v4.extend_from_slice(&[0u8; 40]);
            assert!(is_protected(&v4));
            assert!(unprotect(&v4).is_err());
        }
        #[cfg(not(target_os = "windows"))]
        {
            let mut blob = Vec::from(*b"EMBRSEC1");
            blob.extend_from_slice(&[0u8; 40]);
            assert!(is_protected(&blob));
            assert!(unprotect(&blob).is_err());
            let wrapped = protect(b"secret-material").expect("protect");
            assert!(is_protected(&wrapped));
            assert_ne!(&wrapped, b"secret-material");
            assert_eq!(&unprotect(&wrapped).unwrap()[..], b"secret-material");
        }
    }
}
