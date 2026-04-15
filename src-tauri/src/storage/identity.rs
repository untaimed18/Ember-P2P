use std::path::Path;

use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::info;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::network::kad::types::KadId;

/// Persistent node identity, equivalent to eMule's preferencesKad.dat + preferences.dat.
/// The KAD ID and user hash are generated once and reused across sessions so other
/// nodes recognize us in their routing tables and credit systems.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct NodeIdentity {
    pub kad_id: [u8; 16],
    pub user_hash: [u8; 16],
    /// Random seed for generating UDP verify keys (stable per session in eMule,
    /// but we persist it so verify keys remain valid across short restarts)
    pub udp_key_seed: u32,
    /// Separate Ember-specific identity used exclusively for the friend system.
    /// Only exchanged with other Ember clients via EmuleInfo.
    #[serde(default)]
    pub ember_hash: [u8; 16],
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("kad_id", &"[redacted]")
            .field("user_hash", &"[redacted]")
            .field("udp_key_seed", &"[redacted]")
            .field("ember_hash", &"[redacted]")
            .finish()
    }
}

impl NodeIdentity {
    fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut kad_id = [0u8; 16];
        let mut user_hash = [0u8; 16];
        let mut ember_hash = [0u8; 16];
        rng.fill(&mut kad_id);
        rng.fill(&mut user_hash);
        rng.fill(&mut ember_hash);
        // eMule convention: first byte of user_hash must not be 0x0E (reserved for "secure ident")
        if user_hash[0] == 14 {
            user_hash[0] = 15;
        }
        let udp_key_seed: u32 = rng.gen();
        NodeIdentity {
            kad_id,
            user_hash,
            udp_key_seed,
            ember_hash,
        }
    }

    pub fn kad_id(&self) -> KadId {
        KadId(self.kad_id)
    }

    /// Load identity from disk, or generate and save a new one.
    pub fn load_or_create(data_dir: &Path) -> anyhow::Result<Self> {
        let path = data_dir.join("identity.json");
        match std::fs::read_to_string(&path) {
            Ok(data) => {
                match serde_json::from_str::<NodeIdentity>(&data) {
                    Ok(mut id) => {
                        // Migrate: older identity files lack ember_hash (deserialized as all-zero)
                        if id.ember_hash == [0u8; 16] {
                            let mut rng = rand::thread_rng();
                            rng.fill(&mut id.ember_hash);
                            let updated = serde_json::to_string_pretty(&id)?;
                            let tmp_path = path.with_extension("json.tmp");
                            crate::security::write_file_restricted(&tmp_path, updated.as_bytes())?;
                            std::fs::rename(&tmp_path, &path)?;
                            info!("Migrated identity: generated ember_hash");
                        }
                        info!("Loaded persistent identity (KAD ID={}…)", &hex::encode(id.kad_id)[..4]);
                        return Ok(id);
                    }
                    Err(e) => {
                        tracing::error!("Failed to parse identity.json, regenerating: {e}");
                        let bak = path.with_extension("json.corrupt.bak");
                        if let Err(bak_err) = std::fs::rename(&path, &bak) {
                            tracing::warn!("Failed to backup corrupt identity.json: {bak_err}");
                        } else {
                            tracing::info!("Backed up corrupt identity to {}", bak.display());
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::error!("Failed to read identity.json, regenerating: {e}");
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
