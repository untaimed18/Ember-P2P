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
//! machine's identity plus the username (`EMBRSEC2`). Fail closed if the
//! machine-id cannot be read. Restricted file mode (`0600`) remains.
//!
//! Wire format: `MAGIC (8 bytes) || ciphertext` (`EMBRSEC1` = DPAPI,
//! `EMBRSEC2` = XChaCha20-Poly1305 + concatenated IKM (legacy Unix),
//! `EMBRSEC3` = XChaCha20-Poly1305 + length-prefixed IKM and optional
//! OS keyring wrapping key). Files without MAGIC are treated as legacy
//! plaintext and are transparently re-saved in protected form by the
//! callers on next load.

use zeroize::Zeroizing;

/// Marker prefixing a DPAPI-wrapped blob (Windows).
const MAGIC: &[u8; 8] = b"EMBRSEC1";
/// Marker prefixing an XChaCha20-Poly1305 blob (Unix, concatenated IKM).
const MAGIC_V2: &[u8; 8] = b"EMBRSEC2";
/// Unix wrap with length-prefixed HKDF IKM and optional keyring key.
const MAGIC_V3: &[u8; 8] = b"EMBRSEC3";

#[cfg(not(target_os = "windows"))]
const KEY_SRC_HKDF: u8 = 0;
#[cfg(not(target_os = "windows"))]
const KEY_SRC_KEYRING: u8 = 1;

/// Extra entropy mixed into DPAPI so a protected blob can only be unwrapped by
/// this application's code path (not by another DPAPI consumer on the system).
#[cfg(target_os = "windows")]
const ENTROPY: &[u8] = b"ember-secret-store-v1";

/// True if `stored` is already in a protected (MAGIC-tagged) form.
pub fn is_protected(stored: &[u8]) -> bool {
    stored.len() >= 8
        && (&stored[..8] == MAGIC || &stored[..8] == MAGIC_V2 || &stored[..8] == MAGIC_V3)
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
    if stored.len() >= 8 && (&stored[..8] == MAGIC_V2 || &stored[..8] == MAGIC_V3) {
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

#[cfg(not(target_os = "windows"))]
mod unix {
    use super::{KEY_SRC_HKDF, KEY_SRC_KEYRING, MAGIC_V2, MAGIC_V3};
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

    fn username() -> anyhow::Result<String> {
        let name = std::env::var("USER").or_else(|_| std::env::var("LOGNAME"));
        match name {
            Ok(s) if !s.is_empty() => Ok(s),
            _ => anyhow::bail!("username unreadable"),
        }
    }

    fn push_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(data);
    }

    fn hkdf_key(salt: &[u8], info: &[u8], length_prefixed: bool) -> anyhow::Result<[u8; 32]> {
        let id = machine_id()?;
        let user = username()?;
        let mut ikm = Vec::new();
        if length_prefixed {
            push_len_prefixed(&mut ikm, &id);
            push_len_prefixed(&mut ikm, user.as_bytes());
        } else {
            ikm.extend_from_slice(&id);
            ikm.extend_from_slice(user.as_bytes());
        }
        let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
        let mut key = [0u8; 32];
        hk.expand(info, &mut key)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
        Ok(key)
    }

    fn keyring_wrapping_key() -> anyhow::Result<[u8; 32]> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let entry = keyring::Entry::new("ember-p2p", "secret-store-v3")
                .map_err(|e| anyhow::anyhow!("keyring: {e}"))?;
            match entry.get_password() {
                Ok(s) => {
                    let bytes = hex::decode(s.trim())
                        .map_err(|_| anyhow::anyhow!("keyring key is not hex"))?;
                    if bytes.len() != 32 {
                        anyhow::bail!("keyring key wrong length");
                    }
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    Ok(key)
                }
                Err(_) => {
                    let mut key = [0u8; 32];
                    OsRng.fill_bytes(&mut key);
                    entry
                        .set_password(&hex::encode(key))
                        .map_err(|e| anyhow::anyhow!("keyring store: {e}"))?;
                    Ok(key)
                }
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
        let (src, mut key) = match keyring_wrapping_key() {
            Ok(k) => (KEY_SRC_KEYRING, k),
            Err(_) => (
                KEY_SRC_HKDF,
                hkdf_key(HKDF_SALT_V3, HKDF_INFO_V3, true)?,
            ),
        };
        let result = encrypt_with(&key, plaintext);
        key.zeroize();
        let (nonce, encrypted) = result?;
        let mut out = Vec::with_capacity(MAGIC_V3.len() + 1 + NONCE_LEN + encrypted.len());
        out.extend_from_slice(MAGIC_V3);
        out.push(src);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&encrypted);
        Ok(out)
    }

    pub fn unprotect(stored: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        if stored.len() >= 8 && &stored[..8] == MAGIC_V3 {
            if stored.len() < 8 + 1 + NONCE_LEN {
                anyhow::bail!("EMBRSEC3 blob too short");
            }
            let src = stored[8];
            let nonce = &stored[9..9 + NONCE_LEN];
            let ct = &stored[9 + NONCE_LEN..];
            let mut key = match src {
                KEY_SRC_KEYRING => keyring_wrapping_key()?,
                KEY_SRC_HKDF => hkdf_key(HKDF_SALT_V3, HKDF_INFO_V3, true)?,
                _ => anyhow::bail!("unknown EMBRSEC3 key source"),
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
            let mut key = hkdf_key(HKDF_SALT_V2, HKDF_INFO_V2, false)?;
            let result = decrypt_with(&key, &body[..NONCE_LEN], &body[NONCE_LEN..]);
            key.zeroize();
            return result;
        }
        anyhow::bail!("not a Unix-protected secret blob")
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
