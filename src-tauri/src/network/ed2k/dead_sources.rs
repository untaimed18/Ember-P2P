use std::collections::HashMap;

use tracing::debug;

/// eMule: BLOCKTIME — base blocking duration for global dead sources (15 minutes)
const BLOCKTIME_SECS: i64 = 900;
/// eMule: BLOCKTIMEFW — longer blocking for firewalled sources (30 minutes)
const BLOCKTIMEFW_SECS: i64 = 1800;
/// eMule per-file dead source timeout (45 minutes) — longer because file-specific
/// failures are more likely to persist than transient global failures
const BLOCKTIME_PER_FILE_SECS: i64 = 2700;
/// Shorter cooldown for transient failures (10 minutes) — gives the source
/// time to recover without wasting bandwidth on tight retry loops
const BLOCKTIME_TRANSIENT_SECS: i64 = 600;
/// eMule: FILEREASKTIME — minimum time between file re-asks (29 minutes)
pub const FILEREASKTIME_SECS: i64 = 1740;
/// eMule: SOURCECLIENTREASKS — normal source re-ask interval (40 minutes)
pub const SOURCECLIENTREASKS_SECS: i64 = 2400;
/// eMule: DOWNLOADTIMEOUT — no data timeout (100 seconds)
pub const DOWNLOADTIMEOUT_SECS: i64 = 100;
/// Cleanup interval (5 minutes)
const CLEANUP_INTERVAL_SECS: i64 = 300;
/// D14: hard caps on map size. A long-running session with heavy churn
/// (buggy swarms, IP filtering, mass failures) can otherwise grow these
/// maps without bound. When we exceed the cap, oldest-expiring entries
/// are dropped first — they're closest to becoming usable again anyway.
const MAX_GLOBAL_DEAD_ENTRIES: usize = 20_000;
const MAX_PER_FILE_DEAD_ENTRIES: usize = 20_000;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct DeadSourceKey {
    client_id: u32,
    ip: u32,
    port: u16,
    /// eMule includes user_hash for LowID Kad sources
    user_hash: Option<[u8; 16]>,
    /// eMule includes Kad port for dual-port matching
    kad_port: u16,
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

    /// Drop the soonest-to-expire entries until `self.sources` is under
    /// `MAX_GLOBAL_DEAD_ENTRIES`. Used when cleanup alone can't keep up
    /// (e.g. steady churn of new dead sources before any prior ones expire).
    fn evict_global_overflow(&mut self) {
        while self.sources.len() > MAX_GLOBAL_DEAD_ENTRIES {
            if let Some((oldest_key, _)) = self
                .sources
                .iter()
                .min_by_key(|(_, expiry)| **expiry)
                .map(|(k, v)| (k.clone(), *v))
            {
                self.sources.remove(&oldest_key);
            } else {
                break;
            }
        }
    }

    fn evict_per_file_overflow(&mut self) {
        while self.per_file.len() > MAX_PER_FILE_DEAD_ENTRIES {
            if let Some((oldest_key, _)) = self
                .per_file
                .iter()
                .min_by_key(|(_, expiry)| **expiry)
                .map(|(k, v)| (k.clone(), *v))
            {
                self.per_file.remove(&oldest_key);
            } else {
                break;
            }
        }
    }

    /// Add a source to the global dead list.
    pub fn add_dead_source(&mut self, client_id: u32, ip: u32, port: u16, firewalled: bool) {
        let now = chrono::Utc::now().timestamp();
        let block_time = if firewalled { BLOCKTIMEFW_SECS } else { BLOCKTIME_SECS };
        let expiry = now + block_time;

        let key = DeadSourceKey { client_id, ip, port, user_hash: None, kad_port: 0 };
        self.sources.insert(key, expiry);

        if now - self.last_cleanup > CLEANUP_INTERVAL_SECS {
            self.cleanup();
        }
        self.evict_global_overflow();
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
        self.evict_per_file_overflow();
    }

    /// Add a source to the per-file dead list with a shorter cooldown for
    /// transient failures (connection timeout, EOF, etc.). The source will
    /// be eligible for retry sooner than a permanent failure.
    pub fn add_transient_dead_source_for_file(&mut self, file_hash: [u8; 16], ip: u32, port: u16) {
        let now = chrono::Utc::now().timestamp();
        let key = PerFileDeadKey { file_hash, ip, port };
        let existing = self.per_file.get(&key).copied().unwrap_or(0);
        let expiry = now + BLOCKTIME_TRANSIENT_SECS;
        if expiry > existing {
            self.per_file.insert(key, expiry);
        }

        if now - self.last_cleanup > CLEANUP_INTERVAL_SECS {
            self.cleanup();
        }
        self.evict_per_file_overflow();
    }

    /// Check if a source is dead globally (any file).
    pub fn is_dead_source(&mut self, client_id: u32, ip: u32, port: u16) -> bool {
        let now = chrono::Utc::now().timestamp();
        if now - self.last_cleanup > CLEANUP_INTERVAL_SECS {
            self.cleanup();
        }
        let key = DeadSourceKey { client_id, ip, port, user_hash: None, kad_port: 0 };
        if let Some(&expiry) = self.sources.get(&key) {
            now < expiry
        } else {
            false
        }
    }

    /// Check if a source is dead for a specific file (checks both global and per-file lists).
    /// For HighID sources, eMule uses the IP as the client_id, so we check both
    /// client_id=0 and client_id=ip to cover all registration paths.
    pub fn is_dead_source_for_file(&mut self, file_hash: &[u8; 16], ip: u32, port: u16) -> bool {
        if self.is_dead_source(0, ip, port) {
            return true;
        }
        if ip != 0 && self.is_dead_source(ip, ip, port) {
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
        let key = DeadSourceKey { client_id, ip, port, user_hash: None, kad_port: 0 };
        self.sources.remove(&key);
    }

    /// Remove a source from the per-file dead list (e.g. on successful download).
    pub fn remove_for_file(&mut self, file_hash: &[u8; 16], ip: u32, port: u16) {
        let key = PerFileDeadKey { file_hash: *file_hash, ip, port };
        self.per_file.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_hash(b: u8) -> [u8; 16] { [b; 16] }

    /// L6: a freshly added source is seen as dead until its window expires.
    #[test]
    fn add_and_check_global_dead() {
        let mut d = DeadSourceList::new();
        d.add_dead_source(0, 0x01020304, 4662, false);
        assert!(d.is_dead_source(0, 0x01020304, 4662));
        assert!(!d.is_dead_source(0, 0x01020305, 4662));
    }

    /// L6: per-file block set doesn't leak into other files.
    #[test]
    fn per_file_isolation() {
        let mut d = DeadSourceList::new();
        d.add_dead_source_for_file(file_hash(1), 0x11223344, 4662);
        assert!(d.is_dead_source_for_file(&file_hash(1), 0x11223344, 4662));
        assert!(!d.is_dead_source_for_file(&file_hash(2), 0x11223344, 4662));
    }

    /// L6 / D14: adding past `MAX_GLOBAL_DEAD_ENTRIES` does not grow the
    /// global map without bound — the oldest-expiring entries are evicted.
    #[test]
    fn global_evicts_oldest_when_at_cap() {
        let mut d = DeadSourceList::new();
        for i in 0..(MAX_GLOBAL_DEAD_ENTRIES + 50) as u32 {
            d.add_dead_source(0, i, 4662, false);
        }
        assert!(d.sources.len() <= MAX_GLOBAL_DEAD_ENTRIES);
    }

    /// L6 / D14: per-file map also caps.
    #[test]
    fn per_file_evicts_oldest_when_at_cap() {
        let mut d = DeadSourceList::new();
        for i in 0..(MAX_PER_FILE_DEAD_ENTRIES + 25) as u32 {
            d.add_dead_source_for_file(file_hash(0), i, 4662);
        }
        assert!(d.per_file.len() <= MAX_PER_FILE_DEAD_ENTRIES);
    }

    /// L6: transient failures use the shorter cooldown, so a peer marked
    /// dead once transiently is still covered but has less penalty than
    /// a permanent failure. This test just asserts behaviour is consistent
    /// (entry present after add).
    #[test]
    fn transient_entry_registers() {
        let mut d = DeadSourceList::new();
        d.add_transient_dead_source_for_file(file_hash(7), 0xFFEEDDCC, 4662);
        assert!(d.is_dead_source_for_file(&file_hash(7), 0xFFEEDDCC, 4662));
    }
}
