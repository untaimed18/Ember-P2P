use std::collections::HashMap;

use tracing::debug;

use super::messages::{PublishEntry, SearchResultEntry};
use super::types::*;

const MAX_ENTRIES_PER_KEY: usize = 300;
const MAX_TOTAL_ENTRIES: usize = 50_000;
const KEYWORD_TTL_SECS: i64 = 86_400; // 24 hours
const SOURCE_TTL_SECS: i64 = 18_000; // 5 hours
const NOTES_TTL_SECS: i64 = 86_400; // 24 hours
const MAX_NOTES_PER_FILE: usize = 150;

#[derive(Debug, Clone)]
pub struct StoredEntry {
    pub id: KadId,
    pub tags: Vec<KadTag>,
    pub stored_at: i64,
    pub ttl_secs: i64,
}

impl StoredEntry {
    pub fn is_expired(&self, now: i64) -> bool {
        now - self.stored_at > self.ttl_secs
    }
}

pub struct DhtStore {
    keyword_entries: HashMap<KadId, Vec<StoredEntry>>,
    source_entries: HashMap<KadId, Vec<StoredEntry>>,
    notes_entries: HashMap<KadId, Vec<StoredEntry>>,
    total_count: usize,
    local_id: KadId,
}

impl DhtStore {
    pub fn new() -> Self {
        DhtStore {
            keyword_entries: HashMap::new(),
            source_entries: HashMap::new(),
            notes_entries: HashMap::new(),
            total_count: 0,
            local_id: KadId::zero(),
        }
    }

    pub fn set_local_id(&mut self, id: KadId) {
        self.local_id = id;
    }

    /// Check if the target is within our tolerance zone for accepting publishes.
    pub fn is_within_tolerance(&self, target: &KadId) -> bool {
        let distance = self.local_id.xor_distance(target);
        let d = u32::from_be_bytes([distance.0[0], distance.0[1], distance.0[2], distance.0[3]]);
        d <= SEARCH_TOLERANCE
    }

    pub fn store_keyword_entries(&mut self, target: &KadId, entries: Vec<PublishEntry>) -> u8 {
        let bucket = self.keyword_entries.entry(*target).or_default();

        for entry in entries {
            if self.total_count >= MAX_TOTAL_ENTRIES {
                break;
            }
            if bucket.len() >= MAX_ENTRIES_PER_KEY {
                break;
            }
            if bucket.iter().any(|e| e.id == entry.id) {
                continue;
            }
            bucket.push(StoredEntry {
                id: entry.id,
                tags: entry.tags,
                stored_at: chrono::Utc::now().timestamp(),
                ttl_secs: KEYWORD_TTL_SECS,
            });
            self.total_count += 1;
        }

        self.compute_load()
    }

    pub fn store_source_entry(
        &mut self,
        target: &KadId,
        sender_id: KadId,
        mut tags: Vec<KadTag>,
        sender_ip: std::net::Ipv4Addr,
        sender_port: u16,
    ) -> u8 {
        let bucket = self.source_entries.entry(*target).or_default();

        if self.total_count >= MAX_TOTAL_ENTRIES || bucket.len() >= MAX_ENTRIES_PER_KEY {
            return self.compute_load();
        }

        // Remove existing entry from same sender
        bucket.retain(|e| e.id != sender_id);

        // Always override source IP with the actual packet sender IP to prevent spoofing.
        // A publisher can specify a port (for TCP connections) but the IP must be verified.
        let ip_u32 = u32::from_be_bytes(sender_ip.octets());
        tags.retain(|t| !matches!(&t.name, TagName::Id(TAG_SOURCEIP)));
        tags.push(KadTag {
            name: TagName::Id(TAG_SOURCEIP),
            value: TagValue::Uint32(ip_u32),
        });
        let has_port = tags.iter().any(|t| matches!(&t.name, TagName::Id(TAG_SOURCEPORT)));
        if !has_port {
            tags.push(KadTag {
                name: TagName::Id(TAG_SOURCEPORT),
                value: TagValue::Uint16(sender_port),
            });
        }

        bucket.push(StoredEntry {
            id: sender_id,
            tags,
            stored_at: chrono::Utc::now().timestamp(),
            ttl_secs: SOURCE_TTL_SECS,
        });
        self.total_count += 1;

        self.compute_load()
    }

    pub fn search_keywords(&self, target: &KadId) -> Vec<SearchResultEntry> {
        self.keyword_entries
            .get(target)
            .map(|entries| {
                entries
                    .iter()
                    .map(|e| SearchResultEntry {
                        id: e.id,
                        tags: e.tags.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn search_sources(&self, target: &KadId) -> Vec<SearchResultEntry> {
        self.source_entries
            .get(target)
            .map(|entries| {
                entries
                    .iter()
                    .map(|e| SearchResultEntry {
                        id: e.id,
                        tags: e.tags.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn store_notes_entry(
        &mut self,
        target: &KadId,
        sender_id: KadId,
        tags: Vec<KadTag>,
    ) -> u8 {
        let bucket = self.notes_entries.entry(*target).or_default();

        if self.total_count >= MAX_TOTAL_ENTRIES || bucket.len() >= MAX_NOTES_PER_FILE {
            return self.compute_load();
        }

        bucket.retain(|e| e.id != sender_id);

        bucket.push(StoredEntry {
            id: sender_id,
            tags,
            stored_at: chrono::Utc::now().timestamp(),
            ttl_secs: NOTES_TTL_SECS,
        });
        self.total_count += 1;

        self.compute_load()
    }

    pub fn search_notes(&self, target: &KadId) -> Vec<SearchResultEntry> {
        self.notes_entries
            .get(target)
            .map(|entries| {
                entries
                    .iter()
                    .map(|e| SearchResultEntry {
                        id: e.id,
                        tags: e.tags.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn cleanup_expired(&mut self) {
        let now = chrono::Utc::now().timestamp();
        let mut removed = 0usize;

        for entries in self.keyword_entries.values_mut() {
            let before = entries.len();
            entries.retain(|e| !e.is_expired(now));
            removed += before - entries.len();
        }
        self.keyword_entries.retain(|_, v| !v.is_empty());

        for entries in self.source_entries.values_mut() {
            let before = entries.len();
            entries.retain(|e| !e.is_expired(now));
            removed += before - entries.len();
        }
        self.source_entries.retain(|_, v| !v.is_empty());

        for entries in self.notes_entries.values_mut() {
            let before = entries.len();
            entries.retain(|e| !e.is_expired(now));
            removed += before - entries.len();
        }
        self.notes_entries.retain(|_, v| !v.is_empty());

        self.total_count = self.total_count.saturating_sub(removed);
        if removed > 0 {
            debug!("DHT store cleanup: removed {removed} expired entries");
        }
    }

    fn compute_load(&self) -> u8 {
        let ratio = self.total_count as f64 / MAX_TOTAL_ENTRIES as f64;
        (ratio * 100.0).min(100.0) as u8
    }
}
