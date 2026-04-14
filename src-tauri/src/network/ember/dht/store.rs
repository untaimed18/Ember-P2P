use std::collections::HashMap;
use std::time::{Duration, Instant};

use tracing::debug;

use super::EmberNodeId;

/// Maximum records per key (anti-spam).
const MAX_RECORDS_PER_KEY: usize = 300;
/// Maximum total keys stored.
const MAX_KEYS: usize = 50_000;
/// Default record TTL.
const DEFAULT_RECORD_TTL: Duration = Duration::from_secs(24 * 3600);

/// A signed record stored in the DHT.
#[derive(Debug, Clone)]
pub struct DhtRecord {
    /// The raw record data (application-specific encoding).
    pub data: Vec<u8>,
    /// Ed25519 signature over the record data from the publisher.
    pub signature: [u8; 64],
    /// Ed25519 public key of the publisher.
    pub publisher_key: [u8; 32],
    /// When this record was stored locally.
    pub stored_at: Instant,
    /// When this record expires.
    pub expires_at: Instant,
}

/// Local DHT key-value store for Ember DHT.
///
/// Stores signed records indexed by 16-byte keys (BLAKE3 hashes of keywords,
/// file hashes, etc.). Each key can have multiple records (e.g., multiple
/// sources for the same file).
pub struct DhtStore {
    entries: HashMap<[u8; 16], Vec<DhtRecord>>,
}

impl DhtStore {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Store a record under a key. Returns true if stored, false if rejected.
    pub fn store(
        &mut self,
        key: [u8; 16],
        data: Vec<u8>,
        signature: [u8; 64],
        publisher_key: [u8; 32],
    ) -> bool {
        if self.entries.len() >= MAX_KEYS && !self.entries.contains_key(&key) {
            debug!("DHT store full ({MAX_KEYS} keys), rejecting new key");
            return false;
        }

        let now = Instant::now();
        let record = DhtRecord {
            data,
            signature,
            publisher_key,
            stored_at: now,
            expires_at: now + DEFAULT_RECORD_TTL,
        };

        let records = self.entries.entry(key).or_insert_with(Vec::new);

        // Deduplicate: replace if same publisher already has a record for this key
        if let Some(pos) = records.iter().position(|r| r.publisher_key == publisher_key) {
            records[pos] = record;
            return true;
        }

        if records.len() >= MAX_RECORDS_PER_KEY {
            debug!("Key {} has {MAX_RECORDS_PER_KEY} records, rejecting", hex::encode(key));
            return false;
        }

        records.push(record);
        true
    }

    /// Retrieve all records for a key.
    pub fn get(&self, key: &[u8; 16]) -> Option<&Vec<DhtRecord>> {
        self.entries.get(key)
    }

    /// Remove expired records. Returns how many were removed.
    pub fn expire(&mut self) -> usize {
        let now = Instant::now();
        let mut total_removed = 0;

        self.entries.retain(|_, records| {
            let before = records.len();
            records.retain(|r| r.expires_at > now);
            total_removed += before - records.len();
            !records.is_empty()
        });

        if total_removed > 0 {
            debug!("Expired {total_removed} DHT records");
        }
        total_removed
    }

    /// Total number of records across all keys.
    pub fn total_records(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum()
    }

    /// Number of distinct keys.
    pub fn key_count(&self) -> usize {
        self.entries.len()
    }

    /// Check if we are responsible for storing a key based on proximity.
    /// A node stores a key if its distance to the key is within tolerance.
    pub fn should_store(local_id: &EmberNodeId, key: &[u8; 16]) -> bool {
        let key_id = EmberNodeId(*key);
        let dist = local_id.distance(&key_id);
        // Accept if the distance's leading bit is within the close half of the ID space
        match dist.leading_bit_index() {
            None => true,
            Some(bit) => bit < 120, // tolerant threshold for early network
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_get() {
        let mut store = DhtStore::new();
        let key = [1u8; 16];
        assert!(store.store(key, vec![42], [0u8; 64], [0xAA; 32]));
        assert_eq!(store.total_records(), 1);
        assert_eq!(store.key_count(), 1);

        let records = store.get(&key).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].data, vec![42]);
    }

    #[test]
    fn deduplicates_by_publisher() {
        let mut store = DhtStore::new();
        let key = [1u8; 16];
        let publisher = [0xAA; 32];

        store.store(key, vec![1], [0u8; 64], publisher);
        store.store(key, vec![2], [0u8; 64], publisher); // same publisher
        store.store(key, vec![3], [0u8; 64], [0xBB; 32]); // different publisher

        assert_eq!(store.total_records(), 2);
        let records = store.get(&key).unwrap();
        assert_eq!(records[0].data, vec![2]); // updated
        assert_eq!(records[1].data, vec![3]);
    }

    #[test]
    fn expire_removes_old_records() {
        let mut store = DhtStore::new();
        let key = [1u8; 16];

        // Manually insert an expired record
        let record = DhtRecord {
            data: vec![1],
            signature: [0u8; 64],
            publisher_key: [0xAA; 32],
            stored_at: Instant::now() - Duration::from_secs(100),
            expires_at: Instant::now() - Duration::from_secs(1),
        };
        store.entries.entry(key).or_default().push(record);

        assert_eq!(store.total_records(), 1);
        let removed = store.expire();
        assert_eq!(removed, 1);
        assert_eq!(store.total_records(), 0);
        assert_eq!(store.key_count(), 0);
    }
}
