use std::path::Path;

use ed25519_dalek::SigningKey;
use rand::Rng;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tracing::info;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::network::ember::crypto;
use crate::network::kad::types::KadId;

/// Persistent node identity, equivalent to eMule's preferencesKad.dat + preferences.dat.
/// The KAD ID and user hash are generated once and reused across sessions so other
/// nodes recognize us in their routing tables and credit systems.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
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

impl NodeIdentity {
    fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut kad_id = [0u8; 16];
        let mut user_hash = [0u8; 16];
        rng.fill(&mut kad_id);
        rng.fill(&mut user_hash);
        if user_hash[0] == 14 {
            user_hash[0] = 15;
        }
        let udp_key_seed: u32 = rng.gen();

        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key();
        let ember_hash = crypto::node_id_from_public_key(&public_key);

        let noise_params: snow::params::NoiseParams =
            "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
        let noise_keypair = snow::Builder::new(noise_params)
            .generate_keypair()
            .unwrap();
        let mut noise_private_key = [0u8; 32];
        let mut noise_public_key = [0u8; 32];
        noise_private_key.copy_from_slice(&noise_keypair.private);
        noise_public_key.copy_from_slice(&noise_keypair.public);

        NodeIdentity {
            kad_id,
            user_hash,
            udp_key_seed,
            ember_hash,
            ed25519_secret_key: signing_key.to_bytes(),
            ed25519_public_key: public_key.to_bytes(),
            noise_private_key,
            noise_public_key,
        }
    }

    pub fn kad_id(&self) -> KadId {
        KadId(self.kad_id)
    }

    /// Return the Ed25519 signing key reconstructed from stored secret bytes.
    pub fn signing_key(&self) -> SigningKey {
        crypto::signing_key_from_bytes(&self.ed25519_secret_key)
    }

    /// Return the Ed25519 verifying (public) key reconstructed from stored bytes.
    pub fn verifying_key(&self) -> Option<ed25519_dalek::VerifyingKey> {
        crypto::verifying_key_from_bytes(&self.ed25519_public_key)
    }

    /// Load identity from disk, or generate and save a new one.
    pub fn load_or_create(data_dir: &Path) -> anyhow::Result<Self> {
        let path = data_dir.join("identity.json");
        match std::fs::read_to_string(&path) {
            Ok(data) => {
                match serde_json::from_str::<NodeIdentity>(&data) {
                    Ok(mut id) => {
                        let mut migrated = false;

                        // Migrate: older identities lack Ed25519 keys
                        if id.ed25519_secret_key == [0u8; 32] {
                            let signing_key = SigningKey::generate(&mut OsRng);
                            let public_key = signing_key.verifying_key();
                            id.ed25519_secret_key = signing_key.to_bytes();
                            id.ed25519_public_key = public_key.to_bytes();
                            id.ember_hash = crypto::node_id_from_public_key(&public_key);
                            migrated = true;
                            info!("Migrated identity: generated Ed25519 keypair, derived ember_hash");
                        } else if id.ember_hash == [0u8; 16] {
                            // Has keys but ember_hash wasn't derived yet
                            if let Some(pk) = crypto::verifying_key_from_bytes(&id.ed25519_public_key) {
                                id.ember_hash = crypto::node_id_from_public_key(&pk);
                                migrated = true;
                                info!("Migrated identity: derived ember_hash from existing Ed25519 key");
                            }
                        }

                        // Migrate: older identities lack Noise static keys
                        if id.noise_private_key == [0u8; 32] {
                            let noise_params: snow::params::NoiseParams =
                                "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
                            let noise_keypair = snow::Builder::new(noise_params)
                                .generate_keypair()
                                .unwrap();
                            id.noise_private_key.copy_from_slice(&noise_keypair.private);
                            id.noise_public_key.copy_from_slice(&noise_keypair.public);
                            migrated = true;
                            info!("Migrated identity: generated Noise static keypair");
                        }

                        if migrated {
                            let updated = serde_json::to_string_pretty(&id)?;
                            let tmp_path = path.with_extension("json.tmp");
                            crate::security::write_file_restricted(&tmp_path, updated.as_bytes())?;
                            std::fs::rename(&tmp_path, &path)?;
                        }
                        info!("Loaded persistent identity (KAD ID={}…)", &hex::encode(id.kad_id)[..4]);
                        return Ok(id);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse identity.json, regenerating: {e}");
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!("Failed to read identity.json, regenerating: {e}");
            }
        }

        let id = Self::generate();
        let data = serde_json::to_string_pretty(&id)?;
        std::fs::create_dir_all(data_dir)?;
        let tmp_path = path.with_extension("json.tmp");
        crate::security::write_file_restricted(&tmp_path, data.as_bytes())?;
        std::fs::rename(&tmp_path, &path)?;
        info!("Generated new identity (KAD ID={}…)", &hex::encode(id.kad_id)[..4]);
        Ok(id)
    }
}
