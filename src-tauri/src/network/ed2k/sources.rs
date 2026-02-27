use std::collections::HashMap;
use std::net::Ipv4Addr;

const MAX_SOURCES_PER_FILE: usize = 500;
const SOURCE_EXPIRY_SECS: i64 = 3600;
const MAX_SOURCES_IN_RESPONSE: usize = 50;

#[derive(Debug, Clone)]
pub struct SourceEntry {
    pub ip: Ipv4Addr,
    pub tcp_port: u16,
    pub last_seen: i64,
}

/// Tracks known sources (peers) per file hash for source exchange responses.
#[derive(Debug, Default)]
pub struct SourceManager {
    sources: HashMap<[u8; 16], Vec<SourceEntry>>,
}

impl SourceManager {
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
        }
    }

    pub fn register_source(&mut self, file_hash: [u8; 16], ip: Ipv4Addr, tcp_port: u16) {
        let now = chrono::Utc::now().timestamp();
        let entries = self.sources.entry(file_hash).or_default();

        if let Some(existing) = entries.iter_mut().find(|e| e.ip == ip && e.tcp_port == tcp_port) {
            existing.last_seen = now;
            return;
        }

        if entries.len() >= MAX_SOURCES_PER_FILE {
            entries.sort_by_key(|e| e.last_seen);
            entries.remove(0);
        }

        entries.push(SourceEntry {
            ip,
            tcp_port,
            last_seen: now,
        });
    }

    /// Build an OP_ANSWERSOURCES2 response payload for the given file hash,
    /// excluding the requesting peer's address.
    pub fn build_answer_sources2(
        &self,
        file_hash: &[u8; 16],
        exclude_ip: Ipv4Addr,
    ) -> Vec<u8> {
        let now = chrono::Utc::now().timestamp();
        let mut resp = Vec::with_capacity(18 + MAX_SOURCES_IN_RESPONSE * 12);
        resp.extend_from_slice(file_hash);

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

        resp.extend_from_slice(&(sources.len() as u16).to_le_bytes());
        for src in &sources {
            resp.extend_from_slice(&src.ip.octets());
            resp.extend_from_slice(&src.tcp_port.to_le_bytes());
            resp.extend_from_slice(&0u32.to_le_bytes()); // server_ip (0 = KAD)
            resp.extend_from_slice(&0u16.to_le_bytes()); // server_port
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
