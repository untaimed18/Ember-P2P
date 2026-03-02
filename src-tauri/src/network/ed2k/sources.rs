use std::collections::HashMap;
use std::net::Ipv4Addr;

const MAX_SOURCES_PER_FILE: usize = 500;
const SOURCE_EXPIRY_SECS: i64 = 3600;
const MAX_SOURCES_IN_RESPONSE: usize = 50;
const MAX_TRACKED_FILES: usize = 500;

#[derive(Debug, Clone)]
pub struct SourceEntry {
    pub ip: Ipv4Addr,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub last_seen: i64,
    pub user_hash: [u8; 16],
    /// LowID server-assigned client ID (0 = HighID, connectable directly)
    pub client_id: u32,
    /// Timestamp of last OP_REASKFILEPING sent to this source (0 = never asked)
    pub last_asked: i64,
}

/// Tracks known sources (peers) per file hash for source exchange responses.
#[derive(Debug)]
pub struct SourceManager {
    sources: HashMap<[u8; 16], Vec<SourceEntry>>,
    max_per_file: usize,
}

impl Default for SourceManager {
    fn default() -> Self { Self::new() }
}

impl SourceManager {
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
            max_per_file: MAX_SOURCES_PER_FILE,
        }
    }

    pub fn set_max_per_file(&mut self, max: u32) {
        self.max_per_file = (max as usize).max(50);
    }

    pub fn register_source(&mut self, file_hash: [u8; 16], ip: Ipv4Addr, tcp_port: u16) {
        self.register_source_with_hash(file_hash, ip, tcp_port, [0u8; 16]);
    }

    pub fn register_source_with_hash(&mut self, file_hash: [u8; 16], ip: Ipv4Addr, tcp_port: u16, user_hash: [u8; 16]) {
        self.register_source_full(file_hash, ip, tcp_port, 0, user_hash);
    }

    pub fn register_source_full(&mut self, file_hash: [u8; 16], ip: Ipv4Addr, tcp_port: u16, udp_port: u16, user_hash: [u8; 16]) {
        let now = chrono::Utc::now().timestamp();
        let entries = self.sources.entry(file_hash).or_default();

        if let Some(existing) = entries.iter_mut().find(|e| e.ip == ip && e.tcp_port == tcp_port) {
            existing.last_seen = now;
            if user_hash != [0u8; 16] {
                existing.user_hash = user_hash;
            }
            if udp_port > 0 {
                existing.udp_port = udp_port;
            }
            return;
        }

        if entries.len() >= self.max_per_file {
            entries.sort_by_key(|e| e.last_seen);
            entries.remove(0);
        }

        entries.push(SourceEntry {
            ip,
            tcp_port,
            udp_port,
            last_seen: now,
            user_hash,
            client_id: 0,
            last_asked: 0,
        });

        if self.sources.len() > MAX_TRACKED_FILES {
            self.cleanup_expired();
        }
    }

    /// Build an OP_ANSWERSOURCES2 response payload for the given file hash.
    /// Format (SX version 2): <version 1><file_hash 16><count 2><sources...>
    /// Each source (v2): <userID 4><tcp_port 2><server_ip 4><server_port 2><user_hash 16> = 28 bytes
    pub fn build_answer_sources2(
        &self,
        file_hash: &[u8; 16],
        exclude_ip: Ipv4Addr,
    ) -> Vec<u8> {
        let now = chrono::Utc::now().timestamp();
        let version: u8 = 2;

        let sources: Vec<&SourceEntry> = self
            .sources
            .get(file_hash)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| {
                        e.ip != exclude_ip
                            && (now - e.last_seen) < SOURCE_EXPIRY_SECS
                    })
                    .take(MAX_SOURCES_IN_RESPONSE)
                    .collect()
            })
            .unwrap_or_default();

        let mut resp = Vec::with_capacity(1 + 16 + 2 + sources.len() * 28);
        resp.push(version);
        resp.extend_from_slice(file_hash);
        resp.extend_from_slice(&(sources.len() as u16).to_le_bytes());
        for src in &sources {
            resp.extend_from_slice(&src.ip.octets());              // userID/IP (4)
            resp.extend_from_slice(&src.tcp_port.to_le_bytes());   // TCP port (2)
            resp.extend_from_slice(&0u32.to_le_bytes());           // server IP (4) - 0=KAD
            resp.extend_from_slice(&0u16.to_le_bytes());           // server port (2)
            resp.extend_from_slice(&src.user_hash);                // user hash (16)
        }

        resp
    }

    pub fn cleanup_expired(&mut self) {
        let now = chrono::Utc::now().timestamp();
        for entries in self.sources.values_mut() {
            entries.retain(|e| (now - e.last_seen) < SOURCE_EXPIRY_SECS);
        }
        self.sources.retain(|_, v| !v.is_empty());
    }

    pub fn source_count(&self, file_hash: &[u8; 16]) -> usize {
        self.sources.get(file_hash).map(|v| v.len()).unwrap_or(0)
    }

    /// Return non-expired sources that have UDP ports (without reask gating).
    #[allow(dead_code)]
    pub fn get_udp_sources(&self, file_hash: &[u8; 16]) -> Vec<(Ipv4Addr, u16, u16)> {
        let now = chrono::Utc::now().timestamp();
        self.sources
            .get(file_hash)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| (now - e.last_seen) < SOURCE_EXPIRY_SECS && e.udp_port > 0)
                    .map(|e| (e.ip, e.tcp_port, e.udp_port))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return UDP sources due for a re-ask (eMule: SOURCECLIENTREASKS interval).
    /// Only returns sources whose `last_asked` is older than `reask_interval` seconds ago.
    pub fn get_udp_sources_due_for_reask(
        &self,
        file_hash: &[u8; 16],
        reask_interval: i64,
    ) -> Vec<(Ipv4Addr, u16, u16)> {
        let now = chrono::Utc::now().timestamp();
        self.sources
            .get(file_hash)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| {
                        (now - e.last_seen) < SOURCE_EXPIRY_SECS
                            && e.udp_port > 0
                            && (now - e.last_asked) >= reask_interval
                    })
                    .map(|e| (e.ip, e.tcp_port, e.udp_port))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Mark a source as asked (update `last_asked` timestamp).
    pub fn mark_asked(&mut self, file_hash: &[u8; 16], ip: Ipv4Addr, port: u16) {
        let now = chrono::Utc::now().timestamp();
        if let Some(entries) = self.sources.get_mut(file_hash) {
            if let Some(entry) = entries.iter_mut().find(|e| e.ip == ip && e.tcp_port == port) {
                entry.last_asked = now;
            }
        }
    }

    /// Return non-expired HighID sources for a file (directly connectable).
    pub fn get_sources(&self, file_hash: &[u8; 16]) -> Vec<(Ipv4Addr, u16)> {
        let now = chrono::Utc::now().timestamp();
        self.sources
            .get(file_hash)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| (now - e.last_seen) < SOURCE_EXPIRY_SECS && e.client_id == 0 && !e.ip.is_unspecified())
                    .map(|e| (e.ip, e.tcp_port))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Register a LowID source (behind NAT, needs server callback to reach).
    pub fn register_lowid_source(&mut self, file_hash: [u8; 16], client_id: u32, port: u16) {
        let now = chrono::Utc::now().timestamp();
        let entries = self.sources.entry(file_hash).or_default();

        if let Some(existing) = entries.iter_mut().find(|e| e.client_id == client_id && client_id > 0) {
            existing.last_seen = now;
            existing.tcp_port = port;
            return;
        }

        if entries.len() >= self.max_per_file {
            entries.sort_by_key(|e| e.last_seen);
            entries.remove(0);
        }

        entries.push(SourceEntry {
            ip: Ipv4Addr::UNSPECIFIED,
            tcp_port: port,
            udp_port: 0,
            last_seen: now,
            user_hash: [0u8; 16],
            client_id,
            last_asked: 0,
        });
    }

    /// Return non-expired LowID sources that need server callbacks.
    pub fn get_lowid_sources(&self, file_hash: &[u8; 16]) -> Vec<(u32, u16)> {
        let now = chrono::Utc::now().timestamp();
        self.sources
            .get(file_hash)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| (now - e.last_seen) < SOURCE_EXPIRY_SECS && e.client_id > 0)
                    .map(|e| (e.client_id, e.tcp_port))
                    .collect()
            })
            .unwrap_or_default()
    }
}
