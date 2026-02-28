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
    pub last_seen: i64,
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
        let now = chrono::Utc::now().timestamp();
        let entries = self.sources.entry(file_hash).or_default();

        if let Some(existing) = entries.iter_mut().find(|e| e.ip == ip && e.tcp_port == tcp_port) {
            existing.last_seen = now;
            return;
        }

        if entries.len() >= self.max_per_file {
            entries.sort_by_key(|e| e.last_seen);
            entries.remove(0);
        }

        entries.push(SourceEntry {
            ip,
            tcp_port,
            last_seen: now,
        });

        if self.sources.len() > MAX_TRACKED_FILES {
            self.cleanup_expired();
        }
    }

    /// Build an OP_ANSWERSOURCES2 response payload for the given file hash.
    /// Format: <version 1><file_hash 16><count 2><sources...>
    /// Each source: <ip 4><tcp_port 2><udp_port 2> (version 2+ format)
    pub fn build_answer_sources2(
        &self,
        file_hash: &[u8; 16],
        exclude_ip: Ipv4Addr,
    ) -> Vec<u8> {
        let now = chrono::Utc::now().timestamp();
        let version: u8 = 2; // SX_CURRENT_VERSION used by eMule

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

        let mut resp = Vec::with_capacity(1 + 16 + 2 + sources.len() * 8);
        resp.push(version);
        resp.extend_from_slice(file_hash);
        resp.extend_from_slice(&(sources.len() as u16).to_le_bytes());
        for src in &sources {
            resp.extend_from_slice(&src.ip.octets());
            resp.extend_from_slice(&src.tcp_port.to_le_bytes());
            resp.extend_from_slice(&0u16.to_le_bytes()); // udp_port (0 = unknown)
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
}
