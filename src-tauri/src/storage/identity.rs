use std::path::Path;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::info;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::network::ember::crypto;
use crate::network::kad::types::KadId;

/// Persistent node identity, equivalent to eMule's preferencesKad.dat + preferences.dat.
/// The KAD ID and user hash are generated once and reused across sessions so other
/// nodes recognize us in their routing tables and credit systems.
///
/// Security notes:
/// - On-disk layout is a protected JSON payload written via
///   `security::atomic_write` with `restrict=true`, which applies mode 0o600 on
///   Unix and a Windows ACL limiting access to the current user (see
///   `restrict_file_permissions`).
/// - Windows releases wrap the serialized identity with current-user DPAPI
///   (`CryptProtectData` / `CryptUnprotectData`) via `secret_store`. Non-Windows
///   developer/CI builds retain the restricted-file-permission fallback.
///   The identity is not a cryptographic secret that rotates, but leaking
///   `user_hash` / `ember_hash` deanonymizes the node across sessions.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct NodeIdentity {
    pub kad_id: [u8; 16],
    pub user_hash: [u8; 16],
    /// Random seed for generating UDP verify keys (stable per session in eMule,
    /// but we persist it so verify keys remain valid across short restarts)
    pub udp_key_seed: u32,
    /// Ember node ID: BLAKE3(ed25519_public_key)[0..16].
    /// Derived deterministically from the Ed25519 keypair.
    #[serde(default)]
    pub ember_hash: [u8; 16],
    /// Ed25519 secret key (32 bytes). Used for signing DHT messages and records.
    #[serde(default)]
    pub ed25519_secret_key: [u8; 32],
    /// Ed25519 public key (32 bytes). Shared with other Ember nodes for verification.
    #[serde(default)]
    pub ed25519_public_key: [u8; 32],
    /// X25519 static private key (32 bytes) for Noise protocol transport encryption.
    #[serde(default)]
    pub noise_private_key: [u8; 32],
    /// X25519 static public key (32 bytes) for Noise protocol transport encryption.
    #[serde(default)]
    pub noise_public_key: [u8; 32],
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("kad_id", &"[redacted]")
            .field("user_hash", &"[redacted]")
            .field("udp_key_seed", &"[redacted]")
            .field("ember_hash", &"[redacted]")
            .field("ed25519_secret_key", &"[redacted]")
            .field("ed25519_public_key", &"[redacted]")
            .field("noise_private_key", &"[redacted]")
            .field("noise_public_key", &"[redacted]")
            .finish()
    }
}

impl NodeIdentity {
    fn generate() -> anyhow::Result<Self> {
        let mut rng = OsRng;
        let mut kad_id = [0u8; 16];
        let mut user_hash = [0u8; 16];
        rng.fill_bytes(&mut kad_id);
        rng.fill_bytes(&mut user_hash);
        if user_hash[0] == 14 {
            user_hash[0] = 15;
        }
        let udp_key_seed: u32 = rng.next_u32();

        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key();
        let ember_hash = crypto::node_id_from_public_key(&public_key);

        let noise_params: snow::params::NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .expect("static Noise pattern string is always valid");
        let noise_keypair = snow::Builder::new(noise_params)
            .generate_keypair()
            .map_err(|e| anyhow::anyhow!("Noise keypair generation failed: {e:?}"))?;
        let mut noise_private_key = [0u8; 32];
        let mut noise_public_key = [0u8; 32];
        noise_private_key.copy_from_slice(&noise_keypair.private);
        noise_public_key.copy_from_slice(&noise_keypair.public);

        Ok(NodeIdentity {
            kad_id,
            user_hash,
            udp_key_seed,
            ember_hash,
            ed25519_secret_key: signing_key.to_bytes(),
            ed25519_public_key: public_key.to_bytes(),
            noise_private_key,
            noise_public_key,
        })
    }

    pub fn kad_id(&self) -> KadId {
        KadId(self.kad_id)
    }

    /// Load identity from disk, or generate and save a new one.
    ///
    /// Identity loss silently rotates `user_hash` / `ember_hash`, which breaks
    /// the user's KAD reputation, credits, and friend relationships. So on a
    /// *parse failure* (malformed JSON) we **refuse to start** rather than
    /// generate a new identity: the raw file is moved aside with a `.corrupt`
    /// suffix and the user is expected to either restore from a backup or
    /// explicitly delete both files to consent to a reset.
    ///
    /// Only the `NotFound` case (genuinely no identity yet) triggers automatic
    /// generation.
    pub fn load_or_create(data_dir: &Path) -> anyhow::Result<Self> {
        let path = data_dir.join("identity.json");
        #[cfg(target_os = "windows")]
        let protected_marker = data_dir.join("identity.protected");
        // A crash inside `atomic_write`'s Windows replace-fallback can leave the
        // identity parked under its backup name with nothing at `path`. Reaching
        // the `NotFound` arm below would then mint a fresh KAD id and user hash and
        // discard every friendship and upload credit — the one loss this function
        // otherwise goes out of its way to refuse. Restore first; a no-op when
        // there is nothing parked.
        crate::security::recover_interrupted_replace(&path);
        #[cfg(target_os = "windows")]
        crate::security::recover_interrupted_replace(&protected_marker);
        match std::fs::read(&path) {
            Ok(raw) => {
                // Unwrap DPAPI at-rest protection. Legacy plaintext files pass
                // through unchanged and are re-saved in protected form below.
                let was_protected = crate::storage::secret_store::is_protected(&raw);
                #[cfg(target_os = "windows")]
                if protected_marker.exists() && !was_protected {
                    anyhow::bail!(
                        "Identity protection downgrade detected at {}: this installation has \
                         previously stored a DPAPI-protected identity, but identity.json is now \
                         plaintext. Refusing the replacement to prevent silent identity takeover.",
                        path.display()
                    );
                }
                let data = match crate::storage::secret_store::unprotect(&raw) {
                    Ok(d) => d,
                    Err(unwrap_err) => {
                        tracing::error!("identity.json could not be decrypted: {unwrap_err}");
                        let bak = path.with_extension("json.corrupt");
                        let backup_note = match std::fs::copy(&path, &bak) {
                            Ok(_) => {
                                crate::security::restrict_file_permissions(&bak);
                                format!("A copy has been saved to {}. ", bak.display())
                            }
                            Err(bak_err) => {
                                tracing::warn!(
                                    "Failed to back up undecryptable identity.json: {bak_err}"
                                );
                                String::new()
                            }
                        };
                        // The recoverable cause differs by platform, and naming
                        // the wrong one sends the user somewhere useless. On
                        // Unix the usual reason is a keyring that is simply not
                        // reachable this launch (locked collection, or no D-Bus
                        // session because the app was started from a TTY or over
                        // SSH) — the file is intact and unlocking it is the fix.
                        #[cfg(target_os = "windows")]
                        let recovery = "Sign in as the original Windows user, or restore/delete \
                                        identity.json to reset.";
                        #[cfg(not(target_os = "windows"))]
                        let recovery = "If your login keyring is locked or unavailable (for \
                                        example when starting from a TTY or over SSH), unlock it \
                                        and start Ember again — the file itself is probably \
                                        intact. Otherwise restore/delete identity.json to reset.";
                        #[cfg(target_os = "windows")]
                        let cause = "is protected for a different Windows user account or is \
                                     corrupt";
                        #[cfg(not(target_os = "windows"))]
                        let cause = "could not be unwrapped with this machine's key store";
                        return Err(anyhow::anyhow!(
                            "Identity file at {} {} ({}). {}Refusing to generate a new identity \
                             automatically because this would permanently reset your KAD ID, \
                             user hash, friend relationships, and upload credits. {}",
                            path.display(),
                            cause,
                            unwrap_err,
                            backup_note,
                            recovery
                        ));
                    }
                };
                match serde_json::from_slice::<NodeIdentity>(&data) {
                    Ok(mut id) => {
                        // A legacy (unprotected) file is treated as needing
                        // migration so it gets re-saved in DPAPI-wrapped form.
                        let mut migrated = !was_protected;

                        // Migrate: older identities lack Ed25519 keys
                        if id.ed25519_secret_key == [0u8; 32] {
                            let signing_key = SigningKey::generate(&mut OsRng);
                            let public_key = signing_key.verifying_key();
                            id.ed25519_secret_key = signing_key.to_bytes();
                            id.ed25519_public_key = public_key.to_bytes();
                            id.ember_hash = crypto::node_id_from_public_key(&public_key);
                            migrated = true;
                            info!(
                                "Migrated identity: generated Ed25519 keypair, derived ember_hash"
                            );
                        } else if id.ember_hash == [0u8; 16] {
                            // Has keys but ember_hash wasn't derived yet
                            if let Some(pk) =
                                crypto::verifying_key_from_bytes(&id.ed25519_public_key)
                            {
                                id.ember_hash = crypto::node_id_from_public_key(&pk);
                                migrated = true;
                                info!("Migrated identity: derived ember_hash from existing Ed25519 key");
                            }
                        }

                        // Migrate: older identities lack Noise static keys
                        if id.noise_private_key == [0u8; 32] {
                            // Propagate instead of panicking: a parse/RNG failure
                            // during migration should surface as a clean startup
                            // error (caught by the caller), never crash the app.
                            let noise_params: snow::params::NoiseParams =
                                "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().map_err(|e| {
                                    anyhow::anyhow!(
                                        "invalid Noise params during identity migration: {e:?}"
                                    )
                                })?;
                            let noise_keypair = snow::Builder::new(noise_params)
                                .generate_keypair()
                                .map_err(|e| {
                                    anyhow::anyhow!(
                                        "Noise keypair generation failed during identity migration: {e:?}"
                                    )
                                })?;
                            id.noise_private_key.copy_from_slice(&noise_keypair.private);
                            id.noise_public_key.copy_from_slice(&noise_keypair.public);
                            migrated = true;
                            info!("Migrated identity: generated Noise static keypair");
                        }

                        if migrated {
                            // Both buffers are the Ed25519 and Noise private keys
                            // in the clear — the serialized JSON always, and
                            // `protect`'s output too on non-Windows builds where
                            // it is a pass-through. A plain `Vec<u8>` leaves them
                            // in freed heap for the rest of the process lifetime
                            // and in any crash dump written afterwards; that is
                            // the exact reason `secret_store::unprotect` hands
                            // back `Zeroizing`.
                            let updated = Zeroizing::new(serde_json::to_vec_pretty(&id)?);
                            let protected =
                                Zeroizing::new(crate::storage::secret_store::protect(&updated)?);
                            crate::security::atomic_write(&path, &protected, true)?;
                        }
                        #[cfg(target_os = "windows")]
                        if was_protected || migrated {
                            crate::security::atomic_write(&protected_marker, b"DPAPI-v1", true)?;
                        }
                        info!(
                            "Loaded persistent identity (KAD ID={}…)",
                            &hex::encode(id.kad_id)[..4]
                        );
                        Ok(id)
                    }
                    Err(parse_err) => {
                        tracing::error!("identity.json is corrupt: {parse_err}");
                        let bak = path.with_extension("json.corrupt");
                        let backup_note = match std::fs::copy(&path, &bak) {
                            Ok(_) => {
                                crate::security::restrict_file_permissions(&bak);
                                format!("A copy has been saved to {}. ", bak.display())
                            }
                            Err(bak_err) => {
                                tracing::warn!(
                                    "Failed to back up corrupt identity.json: {bak_err}"
                                );
                                String::new()
                            }
                        };
                        Err(anyhow::anyhow!(
                            "Identity file at {} is corrupt ({}). {}\
                             Refusing to generate a new identity automatically because this would \
                             permanently reset your KAD ID, user hash, friend relationships, and \
                             upload credits. To reset, delete the identity.json file and restart; \
                             to recover, restore a backup copy of identity.json.",
                            path.display(),
                            parse_err,
                            backup_note
                        ))
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let id = Self::generate()?;
                let data = Zeroizing::new(serde_json::to_vec_pretty(&id)?);
                let protected = Zeroizing::new(crate::storage::secret_store::protect(&data)?);
                std::fs::create_dir_all(data_dir)?;
                crate::security::atomic_write(&path, &protected, true)?;
                #[cfg(target_os = "windows")]
                crate::security::atomic_write(&protected_marker, b"DPAPI-v1", true)?;
                info!(
                    "Generated new identity (KAD ID={}…)",
                    &hex::encode(id.kad_id)[..4]
                );
                Ok(id)
            }
            Err(e) => {
                // For permission-denied / transient I/O errors, do NOT generate a
                // new identity — the real file may still be on disk and readable
                // next launch. Surface the error instead of masking it.
                Err(anyhow::anyhow!(
                    "Failed to read identity file at {}: {}. Fix the underlying I/O error \
                     (permissions, disk, antivirus) and restart.",
                    path.display(),
                    e
                ))
            }
        }
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[test]
    fn protected_marker_rejects_plaintext_replacement() {
        let dir = std::env::temp_dir().join(format!(
            "ember-identity-downgrade-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let identity = NodeIdentity::generate().expect("test identity");
        std::fs::write(
            dir.join("identity.json"),
            serde_json::to_vec_pretty(&identity).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("identity.protected"), b"DPAPI-v1").unwrap();
        let error = NodeIdentity::load_or_create(&dir).unwrap_err().to_string();
        assert!(error.contains("downgrade"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
