use std::path::Path;

use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::network::kad::types::KadId;

/// Persistent node identity, equivalent to eMule's preferencesKad.dat + preferences.dat.
/// The KAD ID and user hash are generated once and reused across sessions so other
/// nodes recognize us in their routing tables and credit systems.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub kad_id: [u8; 16],
    pub user_hash: [u8; 16],
    /// Random seed for generating UDP verify keys (stable per session in eMule,
    /// but we persist it so verify keys remain valid across short restarts)
    pub udp_key_seed: u32,
}

impl NodeIdentity {
    fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut kad_id = [0u8; 16];
        let mut user_hash = [0u8; 16];
        rng.fill(&mut kad_id);
        rng.fill(&mut user_hash);
        // eMule convention: first byte of user_hash must not be 0x0E (reserved for "secure ident")
        if user_hash[5] == 14 {
            user_hash[5] = 15;
        }
        let udp_key_seed: u32 = rng.gen();
        NodeIdentity {
            kad_id,
            user_hash,
            udp_key_seed,
        }
    }

    pub fn kad_id(&self) -> KadId {
        KadId(self.kad_id)
    }

    /// Load identity from disk, or generate and save a new one.
    pub fn load_or_create(data_dir: &Path) -> anyhow::Result<Self> {
        let path = data_dir.join("identity.json");
        if path.exists() {
            let data = std::fs::read_to_string(&path)?;
            match serde_json::from_str::<NodeIdentity>(&data) {
                Ok(id) => {
                    info!(
                        "Loaded persistent identity: KAD ID={}, user_hash={}",
                        hex::encode(id.kad_id),
                        hex::encode(id.user_hash),
                    );
                    return Ok(id);
                }
                Err(e) => {
                    tracing::warn!("Failed to parse identity.json, regenerating: {e}");
                }
            }
        }

        let id = Self::generate();
        let data = serde_json::to_string_pretty(&id)?;
        std::fs::create_dir_all(data_dir)?;
        std::fs::write(&path, data)?;
        info!(
            "Generated new identity: KAD ID={}, user_hash={}",
            hex::encode(id.kad_id),
            hex::encode(id.user_hash),
        );
        Ok(id)
    }
}
