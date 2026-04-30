use std::collections::HashMap;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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
    ///
    /// Verifies the Ed25519 signature over `data` with `publisher_key`
    /// before insert. Without this check, callers that forgot to
    /// verify on the wire path (or future call sites that bypass the
    /// signing step) would let arbitrary forged records into the DHT
    /// — a spam/poisoning vector. Verification failure logs at
    /// `debug!` and returns false; the caller decides how loud to be.
    pub fn store(
        &mut self,
        key: [u8; 16],
        data: Vec<u8>,
        signature: [u8; 64],
        publisher_key: [u8; 32],
    ) -> bool {
        if !verify_record_signature(&data, &signature, &publisher_key) {
            debug!(
                "DHT store: signature verification failed for key {} from publisher {}",
                hex::encode(key),
                hex::encode(publisher_key),
            );
            return false;
        }

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

/// Verify an Ed25519 signature over `data` with `publisher_key`.
/// Returns false on any failure (malformed key, malformed sig, or
/// signature mismatch).
fn verify_record_signature(data: &[u8], signature: &[u8; 64], publisher_key: &[u8; 32]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(publisher_key) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    vk.verify(data, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    /// Generate a (publisher_key, sign_fn) pair for tests so the
    /// store's signature check accepts the inputs.
    fn keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn sign(sk: &SigningKey, data: &[u8]) -> [u8; 64] {
        sk.sign(data).to_bytes()
    }

    #[test]
    fn store_and_get() {
        let mut store = DhtStore::new();
        let key = [1u8; 16];
        let (sk, pk) = keypair();
        let data = vec![42];
        let sig = sign(&sk, &data);
        assert!(store.store(key, data.clone(), sig, pk));
        assert_eq!(store.total_records(), 1);
        assert_eq!(store.key_count(), 1);

        let records = store.get(&key).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].data, data);
    }

    #[test]
    fn deduplicates_by_publisher() {
        let mut store = DhtStore::new();
        let key = [1u8; 16];
        let (sk_a, pk_a) = keypair();
        let (sk_b, pk_b) = keypair();

        let d1 = vec![1u8];
        let d2 = vec![2u8];
        let d3 = vec![3u8];
        store.store(key, d1.clone(), sign(&sk_a, &d1), pk_a);
        store.store(key, d2.clone(), sign(&sk_a, &d2), pk_a); // same publisher
        store.store(key, d3.clone(), sign(&sk_b, &d3), pk_b); // different publisher

        assert_eq!(store.total_records(), 2);
        let records = store.get(&key).unwrap();
        assert_eq!(records[0].data, d2); // updated
        assert_eq!(records[1].data, d3);
    }

    #[test]
    fn rejects_bad_signature() {
        let mut store = DhtStore::new();
        let key = [1u8; 16];
        let (_sk, pk) = keypair();
        // bogus signature for `data`
        assert!(!store.store(key, vec![42], [0u8; 64], pk));
        assert_eq!(store.total_records(), 0);
    }

    #[test]
    fn rejects_bad_publisher_key() {
        let mut store = DhtStore::new();
        let key = [1u8; 16];
        let (sk, _pk) = keypair();
        let data = vec![42u8];
        let sig = sign(&sk, &data);
        // sign with sk but claim a different publisher_key
        assert!(!store.store(key, data, sig, [0xCC; 32]));
        assert_eq!(store.total_records(), 0);
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
            stored_at: Instant::now()
                .checked_sub(Duration::from_secs(100))
                .unwrap_or_else(Instant::now),
            expires_at: Instant::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap_or_else(Instant::now),
        };
        store.entries.entry(key).or_default().push(record);

        assert_eq!(store.total_records(), 1);
        let removed = store.expire();
        assert_eq!(removed, 1);
        assert_eq!(store.total_records(), 0);
        assert_eq!(store.key_count(), 0);
    }
}
