use std::collections::HashMap;

use tracing::debug;

/// eMule: BLOCKTIME — base blocking duration for global dead sources (15 minutes)
const BLOCKTIME_SECS: i64 = 900;
/// eMule: BLOCKTIMEFW — longer blocking for firewalled sources (30 minutes)
const BLOCKTIMEFW_SECS: i64 = 1800;
/// eMule per-file dead source timeout (45 minutes) — longer because file-specific
/// failures are more likely to persist than transient global failures
const BLOCKTIME_PER_FILE_SECS: i64 = 2700;
/// eMule: FILEREASKTIME — minimum time between file re-asks (29 minutes)
pub const FILEREASKTIME_SECS: i64 = 1740;
/// eMule: SOURCECLIENTREASKS — normal source re-ask interval (40 minutes)
#[allow(dead_code)]
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

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct PerFileDeadKey {
    file_hash: [u8; 16],
    ip: u32,
    port: u16,
}

pub struct DeadSourceList {
    /// Global dead source list (eMule: theApp.clientlist->m_globDeadSourceList)
    sources: HashMap<DeadSourceKey, i64>,
    /// Per-file dead source list (eMule: CPartFile::m_DeadSourceList)
    per_file: HashMap<PerFileDeadKey, i64>,
    last_cleanup: i64,
}

impl DeadSourceList {
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
            per_file: HashMap::new(),
            last_cleanup: 0,
        }
    }

    /// Add a source to the global dead list.
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

    /// Add a source to the per-file dead list (longer timeout, file-specific failure).
    pub fn add_dead_source_for_file(&mut self, file_hash: [u8; 16], ip: u32, port: u16) {
        let now = chrono::Utc::now().timestamp();
        let expiry = now + BLOCKTIME_PER_FILE_SECS;

        let key = PerFileDeadKey { file_hash, ip, port };
        self.per_file.insert(key, expiry);

        if now - self.last_cleanup > CLEANUP_INTERVAL_SECS {
            self.cleanup();
        }
    }

    /// Check if a source is dead globally (any file).
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

    /// Check if a source is dead for a specific file (checks both global and per-file lists).
    pub fn is_dead_source_for_file(&mut self, file_hash: &[u8; 16], ip: u32, port: u16) -> bool {
        if self.is_dead_source(0, ip, port) {
            return true;
        }
        let now = chrono::Utc::now().timestamp();
        let key = PerFileDeadKey { file_hash: *file_hash, ip, port };
        if let Some(&expiry) = self.per_file.get(&key) {
            now < expiry
        } else {
            false
        }
    }

    pub fn cleanup(&mut self) {
        let now = chrono::Utc::now().timestamp();
        let before_global = self.sources.len();
        let before_file = self.per_file.len();
        self.sources.retain(|_, expiry| *expiry > now);
        self.per_file.retain(|_, expiry| *expiry > now);
        let removed = (before_global - self.sources.len()) + (before_file - self.per_file.len());
        if removed > 0 {
            debug!(
                "Dead source cleanup: removed {removed} expired entries ({} global, {} per-file remaining)",
                self.sources.len(), self.per_file.len()
            );
        }
        self.last_cleanup = now;
    }

    pub fn len(&self) -> usize {
        self.sources.len() + self.per_file.len()
    }

    pub fn remove(&mut self, client_id: u32, ip: u32, port: u16) {
        let key = DeadSourceKey { client_id, ip, port };
        self.sources.remove(&key);
    }

    /// Remove a source from the per-file dead list (e.g. on successful download).
    pub fn remove_for_file(&mut self, file_hash: &[u8; 16], ip: u32, port: u16) {
        let key = PerFileDeadKey { file_hash: *file_hash, ip, port };
        self.per_file.remove(&key);
    }
}
