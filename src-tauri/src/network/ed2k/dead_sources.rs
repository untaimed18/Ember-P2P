use std::collections::HashMap;

use tracing::debug;

/// eMule: BLOCKTIME — base blocking duration for dead sources (15 minutes)
const BLOCKTIME_SECS: i64 = 900;
/// eMule: BLOCKTIMEFW — longer blocking for firewalled sources (30 minutes)
const BLOCKTIMEFW_SECS: i64 = 1800;
/// eMule: FILEREASKTIME — minimum time between file re-asks (29 minutes)
pub const FILEREASKTIME_SECS: i64 = 1740;
/// eMule: SOURCECLIENTREASKS — normal source re-ask interval (40 minutes)
pub const SOURCECLIENTREASKS_SECS: i64 = 2400;
/// eMule: DOWNLOADTIMEOUT — no data timeout (100 seconds)
#[allow(dead_code)]
pub const DOWNLOADTIMEOUT_SECS: i64 = 100;
/// Cleanup interval (5 minutes)
const CLEANUP_INTERVAL_SECS: i64 = 300;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct DeadSourceKey {
    client_id: u32,
    ip: u32,
    port: u16,
}

pub struct DeadSourceList {
    sources: HashMap<DeadSourceKey, i64>,
    last_cleanup: i64,
}

impl DeadSourceList {
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
            last_cleanup: 0,
        }
    }

    pub fn add_dead_source(&mut self, client_id: u32, ip: u32, port: u16, firewalled: bool) {
        let now = chrono::Utc::now().timestamp();
        let block_time = if firewalled { BLOCKTIMEFW_SECS } else { BLOCKTIME_SECS };
        let expiry = now + block_time;

        let key = DeadSourceKey { client_id, ip, port };
        self.sources.insert(key, expiry);

        if now - self.last_cleanup > CLEANUP_INTERVAL_SECS {
            self.cleanup();
        }
    }

    pub fn is_dead_source(&mut self, client_id: u32, ip: u32, port: u16) -> bool {
        let now = chrono::Utc::now().timestamp();
        if now - self.last_cleanup > CLEANUP_INTERVAL_SECS {
            self.cleanup();
        }
        let key = DeadSourceKey { client_id, ip, port };
        if let Some(&expiry) = self.sources.get(&key) {
            now < expiry
        } else {
            false
        }
    }

    pub fn cleanup(&mut self) {
        let now = chrono::Utc::now().timestamp();
        let before = self.sources.len();
        self.sources.retain(|_, expiry| *expiry > now);
        let removed = before - self.sources.len();
        if removed > 0 {
            debug!("Dead source cleanup: removed {removed} expired entries, {} remaining", self.sources.len());
        }
        self.last_cleanup = now;
    }

    pub fn len(&self) -> usize {
        self.sources.len()
    }

    pub fn remove(&mut self, client_id: u32, ip: u32, port: u16) {
        let key = DeadSourceKey { client_id, ip, port };
        self.sources.remove(&key);
    }
}
