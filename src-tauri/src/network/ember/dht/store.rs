use std::collections::HashMap;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use tracing::debug;

use super::publish::RECORD_TYPE_SOURCE;
use super::EmberNodeId;

/// Maximum records per key (anti-spam).
const MAX_RECORDS_PER_KEY: usize = 300;
/// Maximum total keys stored.
const MAX_KEYS: usize = 50_000;
/// Default record TTL.
const DEFAULT_RECORD_TTL: Duration = Duration::from_secs(24 * 3600);
/// How far a record's signed creation timestamp may sit in the future before
/// we treat it as bogus (clock-skew tolerance between peers).
const CLOCK_SKEW_TOLERANCE_SECS: i64 = 3600;

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
    /// When we last (re)published this record to the closest nodes. Used by
    /// the maintenance loop to replicate records on a schedule so they
    /// survive node churn. Initialised to the store time so a freshly
    /// stored record isn't immediately republished.
    pub last_republished: Instant,
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
    ///
    /// `created_at` is the publisher's signed creation timestamp (unix
    /// seconds). The record's expiry is derived from it rather than from the
    /// moment we happen to receive it, so replaying an old (still validly
    /// signed) record cannot revive it with a fresh local TTL: it expires
    /// `DEFAULT_RECORD_TTL` after the publisher created it, full stop. A
    /// record dated past its TTL, or implausibly far in the future, is
    /// rejected outright.
    pub fn store(
        &mut self,
        key: [u8; 16],
        data: Vec<u8>,
        signature: [u8; 64],
        publisher_key: [u8; 32],
        created_at: i64,
    ) -> bool {
        if !verify_record_signature(&data, &signature, &publisher_key) {
            debug!(
                "DHT store: signature verification failed for key {} from publisher {}",
                hex::encode(key),
                hex::encode(publisher_key),
            );
            return false;
        }

        // Derive remaining lifetime from the signed creation time.
        let ttl_secs = DEFAULT_RECORD_TTL.as_secs() as i64;
        let now_unix = chrono::Utc::now().timestamp();
        if created_at > now_unix + CLOCK_SKEW_TOLERANCE_SECS {
            debug!(
                "DHT store: rejecting record for key {} dated {}s in the future",
                hex::encode(key),
                created_at - now_unix,
            );
            return false;
        }
        let age = now_unix.saturating_sub(created_at).max(0);
        if age >= ttl_secs {
            debug!(
                "DHT store: rejecting record for key {} already past TTL (age {age}s)",
                hex::encode(key),
            );
            return false;
        }

        if self.entries.len() >= MAX_KEYS && !self.entries.contains_key(&key) {
            debug!("DHT store full ({MAX_KEYS} keys), rejecting new key");
            return false;
        }

        let now = Instant::now();
        let expires_at = now + Duration::from_secs((ttl_secs - age) as u64);
        let record = DhtRecord {
            data,
            signature,
            publisher_key,
            stored_at: now,
            expires_at,
            last_republished: now,
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

    /// Retrieve all records for a key (including any that have lapsed but not
    /// yet been swept by [`Self::expire`]). Prefer [`Self::get_live`] on the
    /// serving path.
    pub fn get(&self, key: &[u8; 16]) -> Option<&Vec<DhtRecord>> {
        self.entries.get(key)
    }

    /// Retrieve the **non-expired** records for a key. The FIND_VALUE responder
    /// uses this so a lookup never receives a record past its TTL even if the
    /// periodic `expire()` sweep hasn't run since it lapsed. Returns an empty
    /// vec when the key is absent or every record for it has expired.
    pub fn get_live(&self, key: &[u8; 16]) -> Vec<&DhtRecord> {
        let now = Instant::now();
        match self.entries.get(key) {
            Some(records) => records.iter().filter(|r| r.expires_at > now).collect(),
            None => Vec::new(),
        }
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

    /// Collect records due for republish — those not (re)published within
    /// `interval` (or all of them when `force`) — and mark the returned
    /// ones as republished now. `max` bounds the batch so one maintenance
    /// cycle can't fan out an unbounded number of publishes. Returns each
    /// record's `(data, signature)`; the caller reconstructs the
    /// `SignedRecord` and re-stores it on the current closest nodes.
    pub fn take_republish_batch(
        &mut self,
        interval: Duration,
        max: usize,
        force: bool,
    ) -> Vec<(Vec<u8>, [u8; 64])> {
        let now = Instant::now();
        let mut out = Vec::new();
        for records in self.entries.values_mut() {
            for r in records.iter_mut() {
                if out.len() >= max {
                    return out;
                }
                // Source records are never relayed by a third party: their
                // signed payload binds an address to the original publisher, so
                // a re-STORE from us (a different IP) is correctly rejected by
                // the receiver's anti-reflection check. The original publisher
                // re-announces its own source records on its publish tick, so
                // they stay alive without storer-side replication. Only
                // address-free records (e.g. keyword) replicate here.
                if r.data.first() == Some(&RECORD_TYPE_SOURCE) {
                    continue;
                }
                let due = force || now.duration_since(r.last_republished) >= interval;
                if due {
                    r.last_republished = now;
                    out.push((r.data.clone(), r.signature));
                }
            }
        }
        out
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

    /// "Now" as a unix timestamp — the common created_at for fresh test
    /// records.
    fn now_ts() -> i64 {
        chrono::Utc::now().timestamp()
    }

    #[test]
    fn store_and_get() {
        let mut store = DhtStore::new();
        let key = [1u8; 16];
        let (sk, pk) = keypair();
        let data = vec![42];
        let sig = sign(&sk, &data);
        assert!(store.store(key, data.clone(), sig, pk, now_ts()));
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
        store.store(key, d1.clone(), sign(&sk_a, &d1), pk_a, now_ts());
        store.store(key, d2.clone(), sign(&sk_a, &d2), pk_a, now_ts()); // same publisher
        store.store(key, d3.clone(), sign(&sk_b, &d3), pk_b, now_ts()); // different publisher

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
        assert!(!store.store(key, vec![42], [0u8; 64], pk, now_ts()));
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
        assert!(!store.store(key, data, sig, [0xCC; 32], now_ts()));
        assert_eq!(store.total_records(), 0);
    }

    #[test]
    fn republish_batch_respects_interval_and_force() {
        let mut store = DhtStore::new();
        let (sk, pk) = keypair();
        let d = vec![7u8];
        assert!(store.store([1u8; 16], d.clone(), sign(&sk, &d), pk, now_ts()));

        // Freshly stored ⇒ not due within a long interval.
        let due = store.take_republish_batch(Duration::from_secs(3600), 10, false);
        assert!(due.is_empty(), "a just-stored record is not due for republish");

        // `force` overrides the interval and returns it.
        let forced = store.take_republish_batch(Duration::from_secs(3600), 10, true);
        assert_eq!(forced.len(), 1);
        assert_eq!(forced[0].0, d);

        // A zero interval makes everything due (and `max` bounds the batch).
        let d2 = vec![8u8];
        let (sk2, pk2) = keypair();
        assert!(store.store([2u8; 16], d2.clone(), sign(&sk2, &d2), pk2, now_ts()));
        let all_due = store.take_republish_batch(Duration::from_secs(0), 1, false);
        assert_eq!(all_due.len(), 1, "max bounds the batch to 1");
    }

    #[test]
    fn source_records_are_not_republished() {
        let mut store = DhtStore::new();
        // A "source" record is any blob whose first byte is RECORD_TYPE_SOURCE;
        // its address is bound to the original publisher, so a re-STORE from us
        // (a different IP) would be rejected — we must not relay it.
        let (sk, pk) = keypair();
        let mut src = vec![RECORD_TYPE_SOURCE];
        src.extend_from_slice(&[1u8; 32]);
        assert!(store.store([1u8; 16], src.clone(), sign(&sk, &src), pk, now_ts()));

        // A non-source (keyword) record stays eligible for replication.
        let (sk2, pk2) = keypair();
        let mut kw = vec![0x01u8];
        kw.extend_from_slice(&[2u8; 32]);
        assert!(store.store([2u8; 16], kw.clone(), sign(&sk2, &kw), pk2, now_ts()));

        // Even with `force`, only the non-source record is handed back.
        let batch = store.take_republish_batch(Duration::from_secs(0), 10, true);
        assert_eq!(batch.len(), 1, "source records must be excluded from republish");
        assert_eq!(batch[0].0, kw);
    }

    #[test]
    fn rejects_record_dated_past_ttl() {
        let mut store = DhtStore::new();
        let (sk, pk) = keypair();
        let d = vec![1u8];
        // A record created just over the 24h TTL ago is already dead and must
        // not be revived with a fresh local TTL (replay defense).
        let stale_ts = now_ts() - (24 * 3600 + 60);
        assert!(!store.store([1u8; 16], d.clone(), sign(&sk, &d), pk, stale_ts));
        assert_eq!(store.total_records(), 0);
    }

    #[test]
    fn rejects_record_dated_far_in_future() {
        let mut store = DhtStore::new();
        let (sk, pk) = keypair();
        let d = vec![1u8];
        let future_ts = now_ts() + (CLOCK_SKEW_TOLERANCE_SECS + 60);
        assert!(!store.store([1u8; 16], d.clone(), sign(&sk, &d), pk, future_ts));
        assert_eq!(store.total_records(), 0);
    }

    #[test]
    fn expiry_tracks_creation_time_not_receipt() {
        let mut store = DhtStore::new();
        let (sk, pk) = keypair();
        let d = vec![1u8];
        // Created 23h ago ⇒ stored with ~1h of life left, not a fresh 24h.
        let old_ts = now_ts() - 23 * 3600;
        assert!(store.store([5u8; 16], d.clone(), sign(&sk, &d), pk, old_ts));
        let recs = store.get(&[5u8; 16]).unwrap();
        let remaining = recs[0].expires_at.saturating_duration_since(Instant::now());
        assert!(
            remaining <= Duration::from_secs(3600 + 60)
                && remaining >= Duration::from_secs(3600 - 300),
            "expected ~1h of remaining TTL, got {remaining:?}"
        );
    }

    #[test]
    fn get_live_skips_expired_records() {
        let mut store = DhtStore::new();
        let key = [9u8; 16];
        let (sk, pk) = keypair();
        let d = vec![1u8];
        assert!(store.store(key, d.clone(), sign(&sk, &d), pk, now_ts()));
        assert_eq!(store.get_live(&key).len(), 1);

        // Force-expire the record in place (without running the sweep).
        for r in store.entries.get_mut(&key).unwrap() {
            r.expires_at = Instant::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap_or_else(Instant::now);
        }
        assert!(
            store.get_live(&key).is_empty(),
            "an expired record must not be served to a FIND_VALUE"
        );
        // Raw get() still sees it, proving the filtering lives in get_live.
        assert_eq!(store.get(&key).unwrap().len(), 1);
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
            last_republished: Instant::now(),
        };
        store.entries.entry(key).or_default().push(record);

        assert_eq!(store.total_records(), 1);
        let removed = store.expire();
        assert_eq!(removed, 1);
        assert_eq!(store.total_records(), 0);
        assert_eq!(store.key_count(), 0);
    }
}
