use std::collections::HashMap;

use tracing::debug;

use super::messages::{PublishEntry, SearchResultEntry};
use super::types::*;

const MAX_ENTRIES_PER_KEY: usize = 1000;
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
    /// The KAD ID of the node that published this entry (used for dedup).
    pub source_id: KadId,
}

impl StoredEntry {
    pub fn is_expired(&self, now: i64) -> bool {
        now.saturating_sub(self.stored_at) > self.ttl_secs
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
        distance.chunk(0) <= SEARCH_TOLERANCE
    }

    pub fn store_keyword_entries(
        &mut self,
        target: &KadId,
        entries: Vec<PublishEntry>,
        sender_id: &KadId,
    ) -> u8 {
        let bucket = self.keyword_entries.entry(*target).or_default();
        let now = chrono::Utc::now().timestamp();

        let len_before = bucket.len();
        bucket.retain(|e| !e.is_expired(now));
        self.total_count = self.total_count.saturating_sub(len_before - bucket.len());

        for entry in entries {
            if let Some(pos) = bucket.iter().position(|e| e.id == entry.id && e.source_id == *sender_id) {
                bucket[pos].tags = entry.tags;
                bucket[pos].stored_at = now;
            } else {
                if self.total_count >= MAX_TOTAL_ENTRIES {
                    break;
                }
                if bucket.len() >= MAX_ENTRIES_PER_KEY {
                    break;
                }
                bucket.push(StoredEntry {
                    id: entry.id,
                    tags: entry.tags,
                    stored_at: now,
                    ttl_secs: KEYWORD_TTL_SECS,
                    source_id: *sender_id,
                });
                self.total_count += 1;
            }
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
        let now = chrono::Utc::now().timestamp();

        let len_before = bucket.len();
        bucket.retain(|e| !e.is_expired(now) && e.id != sender_id);
        let removed = len_before - bucket.len();
        self.total_count = self.total_count.saturating_sub(removed);

        if self.total_count >= MAX_TOTAL_ENTRIES || bucket.len() >= MAX_ENTRIES_PER_KEY {
            return self.compute_load();
        }

        const MAX_SOURCES_PER_IP: usize = 3;
        let ip_u32 = u32::from_be_bytes(sender_ip.octets());
        let ip_count = bucket.iter()
            .filter(|e| {
                e.tags.iter().any(|t| matches!(&t.name, TagName::Id(TAG_SOURCEIP)) && matches!(&t.value, TagValue::Uint32(v) if *v == ip_u32))
            })
            .count();
        if ip_count >= MAX_SOURCES_PER_IP {
            return self.compute_load();
        }

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
        let has_uport = tags.iter().any(|t| matches!(&t.name, TagName::Id(TAG_SOURCEUPORT)));
        if !has_uport {
            tags.push(KadTag {
                name: TagName::Id(TAG_SOURCEUPORT),
                value: TagValue::Uint16(sender_port),
            });
        }

        bucket.push(StoredEntry {
            id: sender_id,
            tags,
            stored_at: chrono::Utc::now().timestamp(),
            ttl_secs: SOURCE_TTL_SECS,
            source_id: sender_id,
        });
        self.total_count += 1;

        self.compute_load()
    }

    pub fn search_keywords(&self, target: &KadId) -> Vec<SearchResultEntry> {
        let now = chrono::Utc::now().timestamp();
        self.keyword_entries
            .get(target)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| !e.is_expired(now))
                    .map(|e| SearchResultEntry {
                        id: e.id,
                        tags: e.tags.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn search_sources(&self, target: &KadId) -> Vec<SearchResultEntry> {
        let now = chrono::Utc::now().timestamp();
        self.source_entries
            .get(target)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| !e.is_expired(now))
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
        let now = chrono::Utc::now().timestamp();

        let len_before = bucket.len();
        bucket.retain(|e| !e.is_expired(now) && e.id != sender_id);
        let removed = len_before - bucket.len();
        self.total_count = self.total_count.saturating_sub(removed);

        if self.total_count >= MAX_TOTAL_ENTRIES || bucket.len() >= MAX_NOTES_PER_FILE {
            return self.compute_load();
        }

        bucket.push(StoredEntry {
            id: sender_id,
            tags,
            stored_at: chrono::Utc::now().timestamp(),
            ttl_secs: NOTES_TTL_SECS,
            source_id: sender_id,
        });
        self.total_count += 1;

        self.compute_load()
    }

    pub fn search_notes(&self, target: &KadId) -> Vec<SearchResultEntry> {
        let now = chrono::Utc::now().timestamp();
        self.notes_entries
            .get(target)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| !e.is_expired(now))
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

    /// Returns a 0-100 load percentage suitable for the KADEMLIA2_PUBLISH_RES
    /// `byLoad` field. K16: eMule 0.50a's `CIndexed::SendPublishResponse`
    /// computes this as `(m_uTotalIndexLoad * 100) / m_uMaxIndexLoad`,
    /// i.e. a straight percentage capped at 100 — which is what this does.
    /// Peers that treat load ≥ 100 as "skip this node for now" work
    /// correctly against us because we never emit values above 100 here;
    /// our receive-side handlers also treat `load >= 100` as an
    /// informational bucket-full signal (see PublishRes handling).
    fn compute_load(&self) -> u8 {
        let ratio = self.total_count as f64 / MAX_TOTAL_ENTRIES as f64;
        (ratio * 100.0).min(100.0) as u8
    }
}
