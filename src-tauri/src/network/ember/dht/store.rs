use std::collections::HashMap;
use std::time::{Duration, Instant};

use tracing::debug;

use crate::network::ember::crypto;

use super::publish::RECORD_TYPE_SOURCE;
use super::{scale, EmberNodeId};

/// Maximum records per key (anti-spam).
const MAX_RECORDS_PER_KEY: usize = 300;
/// Maximum total keys stored.
const MAX_KEYS: usize = 50_000;
/// Ceiling on resident record bytes.
///
/// Key and per-key counts alone left the total unbounded: 50,000 keys times
/// 300 records is far more than a desktop application should ever hold, and
/// an attacker choosing keys can steer records at us deliberately. This is
/// the limit that actually protects memory; when it is reached the least
/// valuable records (furthest from our ID, then nearest expiry) are dropped
/// rather than refusing the newcomer, so a full store still tracks the keys
/// we are most responsible for.
const MAX_STORE_BYTES: usize = 48 * 1024 * 1024;
/// Default record TTL.
const DEFAULT_RECORD_TTL: Duration = Duration::from_secs(24 * 3600);
/// How far a record's signed creation timestamp may sit in the future before
/// we treat it as bogus (clock-skew tolerance between peers).
const CLOCK_SKEW_TOLERANCE_SECS: i64 = 3600;

/// One live key in the local store, for the diagnostic UI (slice 16).
#[derive(Debug, Clone)]
pub struct DhtStoreEntry {
    pub key: [u8; 16],
    pub record_count: u32,
    pub keyword_records: u32,
    pub source_records: u32,
}

/// A signed record stored in the DHT.
#[derive(Debug, Clone)]
pub struct DhtRecord {
    /// The raw record data (application-specific encoding).
    pub data: Vec<u8>,
    /// Ed25519 signature over the record data from the publisher.
    pub signature: [u8; 64],
    /// Ed25519 public key of the publisher.
    pub publisher_key: [u8; 32],
    /// When this record was stored locally. Retained for diagnostics and
    /// `Debug` output; expiry and replication are driven by `expires_at`
    /// and `last_republished` rather than by store time.
    #[allow(dead_code)]
    pub stored_at: Instant,
    /// The publisher's signed creation time, kept so a replayed older copy
    /// cannot replace a newer one.
    pub created_at: i64,
    /// Address the per-IP source cap counts this record against, when it
    /// should not be the one the record declares.
    ///
    /// A firewalled source record is exempt from the anti-reflection IP bind,
    /// so its declared address is unverified and an attacker can invent a new
    /// one per record — each getting a fresh quota. Those are attributed to
    /// the peer we actually received them from instead.
    pub attributed_ip: Option<std::net::Ipv4Addr>,
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
    /// Current permissiveness of the abuse limits, refreshed from the routing
    /// table. Defaults to the most permissive tier so a store used before the
    /// scale is known never rejects a legitimate record.
    scale: scale::NetworkScale,
    /// Where the next republish scan resumes: the key to start at and how
    /// many of its records the previous pass already took. `None` starts a
    /// fresh pass. Keyed rather than positional, because the map's iteration
    /// order reshuffles on every mutation.
    republish_cursor: Option<([u8; 16], usize)>,
    /// Running total of record body bytes, so the byte budget can be checked
    /// without walking every key.
    bytes: usize,
    /// Our node ID, used to decide which records are least worth keeping when
    /// the budget is reached. `None` until set, in which case eviction falls
    /// back to expiry order alone.
    local_id: Option<EmberNodeId>,
    /// Resident-byte ceiling. A field rather than a constant so tests can
    /// exercise eviction without signing tens of thousands of records.
    byte_budget: usize,
}

impl DhtStore {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            scale: scale::NetworkScale::Bootstrap,
            republish_cursor: None,
            bytes: 0,
            local_id: None,
            byte_budget: MAX_STORE_BYTES,
        }
    }

    /// Track how permissive the abuse limits should currently be.
    pub fn set_scale(&mut self, scale: scale::NetworkScale) {
        self.scale = scale;
    }

    /// Tell the store our node ID so it can rank records by responsibility
    /// when the byte budget forces an eviction.
    pub fn set_local_id(&mut self, local_id: EmberNodeId) {
        self.local_id = Some(local_id);
    }

    /// Resident record bytes. The observable side of the byte budget, kept
    /// for the tests that pin eviction and for diagnostics.
    #[allow(dead_code)]
    pub fn byte_len(&self) -> usize {
        self.bytes
    }

    /// Shrink the byte ceiling so eviction can be exercised without signing
    /// tens of thousands of records (Ed25519 verification dominates in a
    /// debug build).
    #[cfg(test)]
    fn set_byte_budget_for_test(&mut self, budget: usize) {
        self.byte_budget = budget;
    }

    /// Free space by dropping the records we are least responsible for.
    ///
    /// Ranking is by XOR distance from our own ID first — a record far from
    /// us is one many other nodes are better placed to serve — and by nearest
    /// expiry within that, so the drop costs the network as little as
    /// possible.
    /// `spare` is the key of a record we have just accepted; it is never
    /// chosen as a victim, so `store` cannot report success for a record that
    /// this call then throws away.
    fn enforce_byte_budget(&mut self, spare: &[u8; 16]) {
        if self.bytes <= self.byte_budget {
            return;
        }
        // Free down to a low-water mark rather than to exactly the budget.
        // Ranking the whole store is O(n log n), and trimming to the line
        // would re-run it on every subsequent insert; with headroom it runs
        // once per ~10% of capacity instead.
        let target = self.byte_budget - self.byte_budget / 10;
        let local = self.local_id;

        // Rank keys, not individual records: every record under a key shares
        // the key's distance, so the choice of which key to give up is the
        // only one distance can decide. Expiry then picks the order within a
        // key.
        let mut ranked: Vec<([u8; 16], [u8; 16])> = self
            .entries
            .keys()
            .filter(|key| *key != spare)
            .map(|key| {
                let distance = match local {
                    Some(id) => {
                        let mut d = [0u8; 16];
                        for i in 0..16 {
                            d[i] = id.0[i] ^ key[i];
                        }
                        d
                    }
                    None => [0u8; 16],
                };
                (*key, distance)
            })
            .collect();
        // Furthest from us first: those are the keys other nodes are best
        // placed to serve.
        ranked.sort_by(|a, b| b.1.cmp(&a.1));

        let mut dropped = 0usize;
        'keys: for (key, _) in ranked {
            let Some(records) = self.entries.get_mut(&key) else {
                continue;
            };
            while self.bytes > target {
                // Within a key, give up whatever expires soonest — it is
                // worth the least to the network.
                let Some(soonest) = records
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, r)| r.expires_at)
                    .map(|(i, _)| i)
                else {
                    break;
                };
                let victim = records.remove(soonest);
                self.bytes = self.bytes.saturating_sub(victim.data.len());
                dropped += 1;
            }
            if records.is_empty() {
                self.entries.remove(&key);
            }
            if self.bytes <= target {
                break 'keys;
            }
        }
        if dropped > 0 {
            debug!(
                "DHT store over budget: dropped {dropped} record(s), now {} bytes",
                self.bytes
            );
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
        self.store_attributed(key, data, signature, publisher_key, created_at, None)
    }

    /// [`Self::store`], attributing the record to `attributed_ip` for the
    /// per-IP source cap instead of the address it declares.
    ///
    /// Used for firewalled source records, whose declared address is exempt
    /// from the anti-reflection bind and therefore unverified: without this
    /// one host can invent a fresh address per record and claim a whole key.
    pub fn store_attributed(
        &mut self,
        key: [u8; 16],
        data: Vec<u8>,
        signature: [u8; 64],
        publisher_key: [u8; 32],
        created_at: i64,
        attributed_ip: Option<std::net::Ipv4Addr>,
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
        let incoming_ember = ember_digest_from_record_data(&data);
        let incoming_file = file_hash_from_record_data(&data);
        let record = DhtRecord {
            data,
            signature,
            publisher_key,
            stored_at: now,
            created_at,
            attributed_ip,
            expires_at,
            last_republished: now,
        };

        let records = self.entries.entry(key).or_insert_with(Vec::new);

        // Deduplicate on (publisher, file), not on publisher alone. A keyword
        // key legitimately holds one record per file a publisher shares under
        // that word, so matching on the publisher would make each new file
        // overwrite the last and leave exactly one discoverable file per
        // keyword per peer. For a source key every record already describes
        // the same file, so adding the file hash changes nothing there.
        //
        // Prefer a non-zero ember_file_hash over a later all-zero republish so
        // pre-upgrade zero digests do not clobber a real content hash.
        if let Some(pos) = records.iter().position(|r| {
            r.publisher_key == publisher_key && file_hash_from_record_data(&r.data) == incoming_file
        }) {
            // Never let an older copy displace a newer one. Records are
            // public — anyone can harvest `data || signature` from a
            // FOUND_VALUE — so without this an attacker could keep re-storing
            // the oldest copy they had seen and pin a publisher's record to
            // that copy's (earlier) expiry, or roll back its metadata.
            if records[pos].created_at > created_at {
                debug!(
                    "Key {} already holds a newer record from this publisher, ignoring replay",
                    hex::encode(key)
                );
                return true;
            }

            let existing_ember = ember_digest_from_record_data(&records[pos].data);
            if existing_ember != [0u8; 32] && incoming_ember == [0u8; 32] {
                // Keep the richer digest, but still treat this as the
                // republish it is: the publisher is alive and re-announcing,
                // so the record's life should be extended. Previously this
                // ACKed and did nothing, letting a publisher whose file has
                // left the local index watch its record expire on schedule
                // while every republish reported success.
                records[pos].created_at = created_at;
                records[pos].expires_at = expires_at;
                records[pos].last_republished = now;
                return true;
            }
            let old_len = records[pos].data.len();
            let new_len = record.data.len();
            records[pos] = record;
            debug_assert!(
                self.bytes >= old_len,
                "byte counter fell behind resident records"
            );
            self.bytes = self.bytes + new_len - old_len.min(self.bytes);
            self.enforce_byte_budget(&key);
            return true;
        }

        // Note on publisher diversity: a per-sender cap on how many distinct
        // publisher identities may be introduced under one key is tempting,
        // but it would break replication. A storer legitimately re-publishes
        // many different publishers' records to the nodes closest to a key,
        // so "one sender introducing many publishers" is normal Kademlia
        // behaviour rather than an attack signature. Publisher spam is bounded
        // instead by MAX_RECORDS_PER_KEY, the byte budget, the per-IP source
        // cap below, and the per-peer STORE rate limit.

        // Per-IP cap on source records, mirroring KAD's MAX_SOURCES_PER_IP.
        // A source record names an address to download from, so without this
        // one host can claim to hold every copy of a file and crowd the real
        // sources out of the answer.
        //
        // Counted against the attributed address where there is one, so a
        // firewalled source — whose declared address nothing verifies —
        // cannot buy a fresh quota per invented address.
        let incoming_ip = record
            .attributed_ip
            .or_else(|| source_ip_from_record_data(&record.data));
        if let Some(ip) = incoming_ip {
            let max_per_ip = self.scale.max_sources_per_ip();
            let same_ip = records
                .iter()
                .filter(|r| {
                    r.attributed_ip
                        .or_else(|| source_ip_from_record_data(&r.data))
                        == Some(ip)
                })
                .count();
            if same_ip >= max_per_ip {
                debug!(
                    "Key {} already has {same_ip} source record(s) attributed to {ip}, rejecting",
                    hex::encode(key)
                );
                return false;
            }
        }

        if records.len() >= MAX_RECORDS_PER_KEY {
            debug!(
                "Key {} has {MAX_RECORDS_PER_KEY} records, rejecting",
                hex::encode(key)
            );
            return false;
        }

        self.bytes += record.data.len();
        records.push(record);
        self.enforce_byte_budget(&key);
        true
    }

    /// Retrieve all records for a key (including any that have lapsed but not
    /// yet been swept by [`Self::expire`]). Prefer [`Self::get_live`] on the
    /// serving path.
    ///
    /// Only this module's tests call it, precisely because they need to
    /// observe pre-sweep state that `get_live` deliberately hides.
    #[allow(dead_code)]
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

        let mut freed = 0usize;
        self.entries.retain(|_, records| {
            let before = records.len();
            records.retain(|r| {
                let live = r.expires_at > now;
                if !live {
                    freed += r.data.len();
                }
                live
            });
            total_removed += before - records.len();
            !records.is_empty()
        });
        self.bytes = self.bytes.saturating_sub(freed);

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
        let ordered: Vec<[u8; 16]> = self.entries.keys().copied().collect();
        let key_count = ordered.len();
        if key_count == 0 {
            self.republish_cursor = None;
            return out;
        }

        // Resume at the key we stopped on, and at the record within it.
        // Restarting from the beginning every pass meant that once more
        // records were due than one batch could carry, the same prefix was
        // replicated over and over and the tail was never reached.
        //
        // The resume point is a key rather than a position: `entries` is a
        // HashMap whose iteration order reshuffles whenever it is mutated,
        // and inbound stores, expiry and budget eviction mutate it constantly
        // between ticks, so a saved index would point somewhere arbitrary.
        let (start, mut skip_records) = match self.republish_cursor {
            // The key may have shrunk or vanished since we noted it. If it is
            // gone — expiry or budget eviction between ticks — the record index
            // belongs to nothing, and carrying it over made the pass skip that
            // many records of whichever key now happens to sort first.
            Some((key, idx)) => match ordered.iter().position(|k| *k == key) {
                Some(at) => (at, idx),
                None => (0, 0),
            },
            None => (0, 0),
        };

        for offset in 0..key_count {
            let key = ordered[(start + offset) % key_count];
            let Some(records) = self.entries.get_mut(&key) else {
                skip_records = 0;
                continue;
            };
            for (idx, r) in records.iter_mut().enumerate() {
                // Only the key we resumed at has records already taken.
                if idx < skip_records {
                    continue;
                }
                if out.len() >= max {
                    // Note the exact record to resume at. Recording only the
                    // key would re-send this key's prefix on every call and,
                    // under `force` (where everything is always due), never
                    // reach the records past `max`.
                    self.republish_cursor = Some((key, idx));
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
            skip_records = 0;
        }
        // The pass covered every key, so the next one starts fresh.
        self.republish_cursor = None;
        out
    }

    /// Make a record due for republish again after its re-store was dropped
    /// before it reached the wire.
    ///
    /// `take_republish_batch` stamps every record it hands out, but the caller
    /// can still fail to queue one: `EmberBatchPublisher::enqueue` refuses
    /// when the target list is momentarily empty (an ipfilter reload, a
    /// staleness purge, a cold start) or when the queue cap would be
    /// overshot. Left stamped, the record sat unreplicated for a full hour
    /// against a 24-hour TTL — drifting out of the k-closest set during churn
    /// while the diagnostics counted a republish that never happened.
    pub fn mark_republish_due(&mut self, key: &[u8; 16], signature: &[u8; 64]) {
        let Some(records) = self.entries.get_mut(key) else {
            return;
        };
        let Some(record) = records.iter_mut().find(|r| r.signature == *signature) else {
            return;
        };
        // Any sufficiently old stamp makes it due on the next pass; the exact
        // value does not matter because `due` is a threshold test.
        record.last_republished = Instant::now()
            .checked_sub(Duration::from_secs(86_400))
            .unwrap_or_else(Instant::now);
    }

    /// Total number of records across all keys.
    pub fn total_records(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum()
    }

    /// Number of distinct keys.
    pub fn key_count(&self) -> usize {
        self.entries.len()
    }

    /// Snapshot of live keys for the diagnostic UI. Sorted by record count
    /// descending, capped at `max`.
    pub fn snapshot(&self, max: usize) -> Vec<DhtStoreEntry> {
        let now = Instant::now();
        let mut out: Vec<DhtStoreEntry> = self
            .entries
            .iter()
            .filter_map(|(key, records)| {
                let live: Vec<_> = records.iter().filter(|r| r.expires_at > now).collect();
                if live.is_empty() {
                    return None;
                }
                let mut keyword_records = 0u32;
                let mut source_records = 0u32;
                for r in &live {
                    match r.data.first() {
                        Some(&RECORD_TYPE_SOURCE) => {
                            source_records = source_records.saturating_add(1);
                        }
                        _ => {
                            keyword_records = keyword_records.saturating_add(1);
                        }
                    }
                }
                Some(DhtStoreEntry {
                    key: *key,
                    record_count: live.len() as u32,
                    keyword_records,
                    source_records,
                })
            })
            .collect();
        out.sort_by(|a, b| b.record_count.cmp(&a.record_count));
        out.truncate(max);
        out
    }
}

/// The address a source record points at, or `None` for any other record
/// type or a truncated body.
///
/// The contact block sits after the variable-length file name, so the offset
/// has to be read out of the record rather than being a constant.
fn source_ip_from_record_data(data: &[u8]) -> Option<std::net::Ipv4Addr> {
    use super::publish::{RECORD_HEADER_LEN, SOURCE_CONTACT_WIRE_LEN};

    if data.first() != Some(&RECORD_TYPE_SOURCE) || data.len() < RECORD_HEADER_LEN {
        return None;
    }
    let name_len = u16::from_le_bytes([
        data[RECORD_HEADER_LEN - 2],
        data[RECORD_HEADER_LEN - 1],
    ]) as usize;
    let off = RECORD_HEADER_LEN.checked_add(name_len)?;
    // The whole contact block, not just the four address bytes: a record
    // truncated mid-block is one `SignedRecord::from_wire` rejects outright,
    // and reading an address out of it here would disagree with that.
    if data.len() < off + SOURCE_CONTACT_WIRE_LEN {
        return None;
    }
    Some(std::net::Ipv4Addr::new(
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
    ))
}

/// The eD2K file hash embedded in a record body, at the fixed offset that
/// follows `record_type` and `keyword_hash`. Zero when the body is truncated.
fn file_hash_from_record_data(data: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    if data.len() >= 33 {
        out.copy_from_slice(&data[17..33]);
    }
    out
}

fn ember_digest_from_record_data(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    if data.len() >= 65 {
        out.copy_from_slice(&data[33..65]);
    }
    out
}

/// Verify an Ed25519 signature over `data` with `publisher_key`.
/// Returns false on any failure (malformed key, malformed sig, or
/// signature mismatch). Uses the same strict verify as frame / record
/// parse paths so weak-key forgeries cannot sneak in via `store` alone.
fn verify_record_signature(data: &[u8], signature: &[u8; 64], publisher_key: &[u8; 32]) -> bool {
    let Some(vk) = crypto::verifying_key_from_bytes(publisher_key) else {
        return false;
    };
    crypto::verify(&vk, data, signature)
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
    fn one_publisher_keeps_a_record_per_file_under_a_keyword() {
        // A keyword key holds one record per file sharing that word, so two
        // files from the same peer must both survive. Deduplicating on the
        // publisher alone left a peer with a single discoverable file per
        // keyword, whichever it published last.
        use super::super::publish::SignedRecord;

        let mut store = DhtStore::new();
        let sk = SigningKey::generate(&mut OsRng);

        let first = SignedRecord::keyword("ubuntu", [0xA1; 16], [0u8; 32], 100, "ubuntu-24.iso", &sk);
        let second =
            SignedRecord::keyword("ubuntu", [0xB2; 16], [0u8; 32], 200, "ubuntu-22.iso", &sk);
        assert_eq!(
            first.keyword_hash, second.keyword_hash,
            "both files live under the same keyword key"
        );
        assert_eq!(first.publisher_key, second.publisher_key);

        let key = first.keyword_hash;
        for rec in [&first, &second] {
            assert!(store.store(
                key,
                rec.data.clone(),
                rec.signature,
                rec.publisher_key,
                rec.timestamp,
            ));
        }

        assert_eq!(store.total_records(), 2, "both files remain discoverable");

        // Republishing the first file still replaces its own record rather
        // than accumulating duplicates.
        let refreshed =
            SignedRecord::keyword("ubuntu", [0xA1; 16], [0u8; 32], 100, "ubuntu-24.iso", &sk);
        assert!(store.store(
            key,
            refreshed.data.clone(),
            refreshed.signature,
            refreshed.publisher_key,
            refreshed.timestamp,
        ));
        assert_eq!(store.total_records(), 2, "a republish is not a new record");
    }

    /// A source record names an address to download from. Without a per-IP
    /// cap one host can claim to hold every copy of a file and crowd the
    /// genuine sources out of the answer.
    #[test]
    fn one_address_cannot_claim_every_source_slot() {
        use super::super::publish::{SignedRecord, SourceContact};
        use std::net::Ipv4Addr;

        let mut store = DhtStore::new();
        store.set_scale(scale::NetworkScale::Established);
        let file_hash = [0x77u8; 16];
        let key = super::super::publish::source_key(&file_hash);
        let squatter = Ipv4Addr::new(198, 51, 1, 9);

        let mut accepted = 0;
        for i in 0..10u8 {
            let sk = SigningKey::from_bytes(&[i.wrapping_add(1); 32]);
            let rec = SignedRecord::source(
                file_hash,
                [0u8; 32],
                1,
                "big.iso",
                SourceContact {
                    ip: squatter,
                    tcp_port: 4662,
                    udp_port: 4672,
                    flags: 0,
                    noise_pub: [i; 32],
                },
                &sk,
            );
            if store.store(key, rec.data.clone(), rec.signature, rec.publisher_key, rec.timestamp) {
                accepted += 1;
            }
        }
        assert_eq!(
            accepted,
            scale::NetworkScale::Established.max_sources_per_ip(),
            "the cap must bound how many sources one address contributes"
        );

        // A different address is unaffected by the squatter's quota.
        let sk = SigningKey::from_bytes(&[200u8; 32]);
        let honest = SignedRecord::source(
            file_hash,
            [0u8; 32],
            1,
            "big.iso",
            SourceContact {
                ip: Ipv4Addr::new(198, 51, 2, 9),
                tcp_port: 4662,
                udp_port: 4672,
                flags: 0,
                noise_pub: [9u8; 32],
            },
            &sk,
        );
        assert!(
            store.store(
                key,
                honest.data.clone(),
                honest.signature,
                honest.publisher_key,
                honest.timestamp
            ),
            "a genuine source from another address must still be accepted"
        );
    }

    /// Records are public, so anyone can harvest one from a FOUND_VALUE and
    /// re-store it. An older copy must not displace a newer one, or a
    /// publisher's record can be pinned to the older copy's earlier expiry.
    #[test]
    fn an_older_copy_cannot_displace_a_newer_record() {
        use super::super::publish::SignedRecord;

        let mut store = DhtStore::new();
        let sk = SigningKey::generate(&mut OsRng);
        let old = SignedRecord::keyword("ubuntu", [1u8; 16], [7u8; 32], 10, "old.iso", &sk);
        let mut newer =
            SignedRecord::keyword("ubuntu", [1u8; 16], [8u8; 32], 10, "new.iso", &sk);
        // Same publisher and file, published later.
        newer.timestamp = old.timestamp + 60;

        let key = old.keyword_hash;
        assert!(store.store(
            key,
            newer.data.clone(),
            newer.signature,
            newer.publisher_key,
            newer.timestamp
        ));
        // Replaying the older copy must not take effect.
        assert!(store.store(
            key,
            old.data.clone(),
            old.signature,
            old.publisher_key,
            old.timestamp
        ));

        let held = store.get(&key).expect("record present");
        assert_eq!(held.len(), 1);
        assert_eq!(
            held[0].created_at, newer.timestamp,
            "the newer record must survive the replay"
        );
    }

    /// A publisher whose file has left the local index republishes with a
    /// zero digest. That is a genuine liveness signal, so it must extend the
    /// record rather than being ACKed and discarded.
    #[test]
    fn a_zero_digest_republish_still_extends_the_record() {
        use super::super::publish::SignedRecord;

        let mut store = DhtStore::new();
        let sk = SigningKey::generate(&mut OsRng);
        let rich = SignedRecord::keyword("ubuntu", [1u8; 16], [9u8; 32], 10, "f.iso", &sk);
        let key = rich.keyword_hash;
        assert!(store.store(
            key,
            rich.data.clone(),
            rich.signature,
            rich.publisher_key,
            rich.timestamp
        ));
        let first_expiry = store.get(&key).unwrap()[0].expires_at;

        let mut bare = SignedRecord::keyword("ubuntu", [1u8; 16], [0u8; 32], 10, "f.iso", &sk);
        bare.timestamp = rich.timestamp + 120;
        assert!(store.store(
            key,
            bare.data.clone(),
            bare.signature,
            bare.publisher_key,
            bare.timestamp
        ));

        let held = store.get(&key).expect("record present");
        assert_eq!(held.len(), 1);
        assert_eq!(
            ember_digest_from_record_data(&held[0].data),
            [9u8; 32],
            "the richer digest is kept"
        );
        assert!(
            held[0].expires_at > first_expiry,
            "but the republish must still extend the record's life"
        );
    }

    /// Key and per-key counts left total memory unbounded, and an attacker
    /// can choose keys that land on us. The byte budget is the limit that
    /// actually protects memory.
    #[test]
    fn the_store_stays_within_its_byte_budget() {
        let mut store = DhtStore::new();
        store.set_local_id(EmberNodeId([0u8; 16]));
        let budget = 64 * 1024;
        store.set_byte_budget_for_test(budget);

        let body = vec![super::super::publish::RECORD_TYPE_KEYWORD; 1024];
        let (sk, pk) = keypair();
        let sig = sign(&sk, &body);
        // Twice the budget's worth, so eviction has to run repeatedly.
        let needed = (budget / body.len()) * 2;

        for i in 0..needed {
            let mut key = [0u8; 16];
            key[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            store.store(key, body.clone(), sig, pk, now_ts());
        }

        assert!(
            store.byte_len() <= budget,
            "store held {} bytes, over the {budget} budget",
            store.byte_len()
        );
        // Whatever we said we stored, we must actually still hold. Returning
        // true for a record that eviction removed on the way out would have
        // us ACK a replica the publisher does not have.
        let mut key = [0u8; 16];
        key[0..8].copy_from_slice(&((needed - 1) as u64).to_le_bytes());
        assert!(
            store.get_live(&key).len() == 1,
            "the last accepted record must survive its own insert"
        );
        assert!(store.total_records() > 0, "eviction must not empty the store");

        // Expiring records returns their bytes to the budget.
        let before = store.byte_len();
        store.expire();
        assert!(store.byte_len() <= before);
    }

    /// Under `force` every record is always due, so a key holding more
    /// records than one batch can carry would return the same prefix forever
    /// and never reach its tail.
    #[test]
    fn a_forced_republish_reaches_the_tail_of_a_crowded_key() {
        let mut store = DhtStore::new();
        let key = [0x42u8; 16];
        let total = 12usize;
        for i in 0..total {
            let sk = SigningKey::generate(&mut OsRng);
            let pk = sk.verifying_key().to_bytes();
            let data = vec![super::super::publish::RECORD_TYPE_KEYWORD, i as u8, 0, 0];
            assert!(store.store(key, data.clone(), sign(&sk, &data), pk, now_ts()));
        }
        assert_eq!(store.get(&key).unwrap().len(), total);

        let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        for _ in 0..total {
            if seen.len() == total {
                break;
            }
            for (data, _sig) in store.take_republish_batch(Duration::from_secs(3600), 4, true) {
                seen.insert(data);
            }
        }
        assert_eq!(
            seen.len(),
            total,
            "a forced pass must eventually cover every record under one key"
        );
    }

    /// With more records due than one batch can carry, restarting the scan
    /// from the beginning each pass replicated the same prefix forever and
    /// never reached the tail.
    #[test]
    fn republish_reaches_every_record_across_passes() {
        let mut store = DhtStore::new();
        let (sk, pk) = keypair();
        let total = 20usize;
        for i in 0..total {
            // Keyword records: source records are deliberately not relayed by
            // storers, so they would be skipped by this scan.
            let data = vec![super::super::publish::RECORD_TYPE_KEYWORD, i as u8, 0, 0];
            assert!(store.store(
                [i as u8; 16],
                data.clone(),
                sign(&sk, &data),
                pk,
                now_ts()
            ));
        }

        // Batches of 3 with a zero interval, so everything is always due. A
        // scan that resumes where it left off covers all 20 in a handful of
        // passes; one that restarts each time never gets past the first 3.
        let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        let mut passes = 0;
        while seen.len() < total && passes < total {
            for (data, _sig) in store.take_republish_batch(Duration::from_secs(0), 3, false) {
                seen.insert(data);
            }
            passes += 1;
        }
        assert_eq!(
            seen.len(),
            total,
            "every record must be republished, not just the first few (after {passes} passes)"
        );
        assert!(
            passes <= total.div_ceil(3) + 1,
            "coverage took {passes} passes, more than a fair scan needs"
        );
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
        assert!(
            due.is_empty(),
            "a just-stored record is not due for republish"
        );

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
        assert_eq!(
            batch.len(),
            1,
            "source records must be excluded from republish"
        );
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
            created_at: now_ts() - 100,
            attributed_ip: None,
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

    #[test]
    fn prefers_nonzero_ember_over_zero_republish() {
        let mut store = DhtStore::new();
        let (sk, pk) = keypair();
        let key = [7u8; 16];
        // Packed layout: type(1) + keyword(16) + file(16) + ember(32) …
        let mut good = vec![0u8; 65];
        good[33..65].fill(0xAB);
        assert!(store.store(key, good.clone(), sign(&sk, &good), pk, now_ts()));
        let zero_ember = vec![0u8; 65];
        assert!(store.store(
            key,
            zero_ember.clone(),
            sign(&sk, &zero_ember),
            pk,
            now_ts()
        ));
        let kept = &store.get(&key).unwrap()[0].data;
        assert_eq!(&kept[33..65], &good[33..65]);
    }

    #[test]
    fn store_churn_soak_expire_and_republish() {
        let mut store = DhtStore::new();
        let (sk, pk) = keypair();
        for i in 0u8..64 {
            let key = [i; 16];
            let mut data = vec![0u8; 65];
            data[0] = 1;
            data[33] = i;
            assert!(store.store(key, data.clone(), sign(&sk, &data), pk, now_ts()));
        }
        assert!(store.total_records() >= 64);
        // Force-expire half the keys in place, then sweep.
        for i in 0u8..32 {
            let key = [i; 16];
            if let Some(recs) = store.entries.get_mut(&key) {
                for r in recs.iter_mut() {
                    r.expires_at = Instant::now()
                        .checked_sub(Duration::from_secs(1))
                        .unwrap_or_else(Instant::now);
                }
            }
        }
        let removed = store.expire();
        assert!(removed >= 32);
        let batch = store.take_republish_batch(Duration::from_secs(0), 16, true);
        assert!(!batch.is_empty());
    }
}
