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

/// What one resident record costs the budget.
///
/// Counting only `data.len()` understated the real figure badly: a `DhtRecord`
/// carries a 64-byte signature, a 32-byte publisher key, three `Instant`s and
/// the rest of its fields alongside the blob, so at the minimum record size the
/// struct outweighs its own payload and a "48 MB" store was holding closer to
/// 120 MB. Charging the fixed overhead as well makes the ceiling mean roughly
/// what it says. The `Vec`/`HashMap` allocation headers are still uncounted,
/// which is a rounding error next to this.
fn record_cost(data_len: usize) -> usize {
    data_len + std::mem::size_of::<DhtRecord>()
}
/// Record TTL for everything that is not a source record.
const KEYWORD_RECORD_TTL: Duration = Duration::from_secs(24 * 3600);
/// Record TTL for source records.
///
/// A source record names an address to download from, so it stops being true
/// the moment that peer goes offline. A keyword record only says a file exists
/// under a word, which stays true whoever is online, so the two do not deserve
/// the same lifetime. Sharing one 24-hour TTL meant a peer that left kept being
/// handed to downloaders for the rest of the day, and nothing about the record
/// hinted that it was stale.
///
/// Publishers re-announce their own source records every two hours
/// (`EMBER_SOURCE_REPUBLISH` in `network::mod`), so six hours survives two
/// missed republishes while clearing a departed peer four times sooner than
/// before. KAD settles on five hours against a five-hour republish, which is a
/// tighter margin than this.
const SOURCE_RECORD_TTL: Duration = Duration::from_secs(6 * 3600);

/// How long a record of this type lives, from its leading type byte.
fn record_ttl(data: &[u8]) -> Duration {
    match data.first() {
        Some(&RECORD_TYPE_SOURCE) => SOURCE_RECORD_TTL,
        _ => KEYWORD_RECORD_TTL,
    }
}
/// How far a record's signed creation timestamp may sit in the future before
/// we treat it as bogus (clock-skew tolerance between peers).
const CLOCK_SKEW_TOLERANCE_SECS: i64 = 3600;

/// One record on its way to or from disk.
///
/// Everything here is either signed by the publisher or re-derived on load, so
/// a tampered file cannot introduce a record: [`DhtStore::restore`] feeds each
/// one back through the ordinary validating store path, which re-checks the
/// signature and recomputes expiry from `created_at`. A record already past its
/// TTL is simply refused, so the file cleans itself up.
#[derive(Debug, Clone)]
pub struct PersistedRecord {
    pub key: [u8; 16],
    pub data: Vec<u8>,
    pub signature: [u8; 64],
    pub publisher_key: [u8; 32],
    pub created_at: i64,
    pub attributed_ip: Option<std::net::Ipv4Addr>,
}

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
    /// Set when a republish was handed out but never made it onto the wire,
    /// so the next pass picks the record up regardless of the clock.
    ///
    /// A flag rather than an old `last_republished`: `Instant` counts from
    /// boot, so `Instant::now() - 24h` is not representable on a machine that
    /// has been up for less than a day and the saturating fallback stamped the
    /// record as *just* republished — the exact opposite of due, and silently,
    /// on what is the common desktop case.
    pub republish_due: bool,
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
    /// Distinct-key ceiling. A field for the same reason as `byte_budget`:
    /// filling 50,000 keys for real would mean 50,000 signature verifications.
    key_budget: usize,
    /// Records refused for want of a free key slot, after eviction was tried.
    key_cap_rejections: u64,
    /// Upper bound on the XOR distance of the furthest key currently held,
    /// or `None` when unknown.
    ///
    /// Exists to keep the *refusal* path O(1) once the key map is full. Without
    /// it, every record of a flood aimed at random distant keys would drive a
    /// full scan looking for a victim — turning a cap meant to bound memory
    /// into a way to burn CPU.
    ///
    /// Only ever an over-estimate: it is set from a real scan, removals
    /// elsewhere can only bring the true furthest closer, and inserting a new
    /// key clears it rather than risking a value that is too small. Over-
    /// estimating costs an extra scan; under-estimating would refuse a key we
    /// should have taken, so the direction matters.
    furthest_key_distance: Option<[u8; 16]>,
}

/// XOR distance between two 128-bit ids.
fn xor_distance(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut d = [0u8; 16];
    for i in 0..16 {
        d[i] = a[i] ^ b[i];
    }
    d
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
            key_budget: MAX_KEYS,
            key_cap_rejections: 0,
            furthest_key_distance: None,
        }
    }

    /// Cumulative count of records refused for want of a free key slot.
    pub fn key_cap_rejections(&self) -> u64 {
        self.key_cap_rejections
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

    /// Shrink the distinct-key ceiling so the cap and its eviction can be
    /// exercised without filling 50,000 keys.
    #[cfg(test)]
    fn set_key_budget_for_test(&mut self, budget: usize) {
        self.key_budget = budget;
    }

    /// Drop a key and everything under it, keeping the byte total in step.
    fn drop_key(&mut self, key: &[u8; 16]) {
        if let Some(records) = self.entries.remove(key) {
            for record in records {
                self.bytes = self.bytes.saturating_sub(record_cost(record.data.len()));
            }
        }
    }

    /// Make room for a key we do not yet hold. Returns whether there is space.
    ///
    /// The byte budget evicts; this cap used to refuse outright, so once
    /// [`MAX_KEYS`] distinct keys were held every new key was turned away —
    /// including ones this node is the closest in the network to. A publisher
    /// spreading records over random keys could therefore fill the map and
    /// deny service for the keys that actually belong here.
    ///
    /// Expired keys go first, being free. Otherwise the furthest key from us
    /// is given up, and only when the incoming key is closer than it. That
    /// ordering is what makes the eviction safe rather than a new lever: a
    /// flood of distant keys finds nothing it is allowed to displace, while a
    /// key we are genuinely responsible for always finds room.
    fn make_room_for_key(&mut self, incoming: &[u8; 16]) -> bool {
        if self.entries.len() < self.key_budget {
            return true;
        }
        // Without our own id there is no notion of responsibility, so there is
        // no principled victim to choose.
        let Some(local) = self.local_id else {
            return false;
        };
        let incoming_distance = xor_distance(&local.0, incoming);

        // The O(1) refusal that keeps a flood cheap. Safe because the bound
        // over-estimates: anything it rejects, a full scan would reject too.
        if let Some(bound) = self.furthest_key_distance {
            if incoming_distance >= bound {
                return false;
            }
        }

        let now = Instant::now();
        let expired: Vec<[u8; 16]> = self
            .entries
            .iter()
            .filter(|(_, records)| records.iter().all(|r| r.expires_at <= now))
            .map(|(key, _)| *key)
            .collect();
        if !expired.is_empty() {
            for key in expired {
                self.drop_key(&key);
            }
            self.furthest_key_distance = None;
            if self.entries.len() < self.key_budget {
                return true;
            }
        }

        // Furthest key to evict, and the next-furthest to seed the bound with
        // once it is gone — both from a single pass.
        let mut furthest: Option<([u8; 16], [u8; 16])> = None;
        let mut runner_up: Option<[u8; 16]> = None;
        for key in self.entries.keys() {
            let distance = xor_distance(&local.0, key);
            match furthest {
                Some((_, current)) if distance > current => {
                    runner_up = Some(current);
                    furthest = Some((*key, distance));
                }
                Some(_) => {
                    if runner_up.is_none_or(|r| distance > r) {
                        runner_up = Some(distance);
                    }
                }
                None => furthest = Some((*key, distance)),
            }
        }

        let Some((furthest_key, furthest_distance)) = furthest else {
            return false;
        };
        if incoming_distance >= furthest_distance {
            self.furthest_key_distance = Some(furthest_distance);
            return false;
        }

        self.drop_key(&furthest_key);
        debug!(
            "DHT store at the {}-key cap: gave up {} for a key closer to us",
            self.key_budget,
            hex::encode(furthest_key)
        );
        // The caller inserts `incoming` next, so the bound has to cover it.
        self.furthest_key_distance = Some(match runner_up {
            Some(r) if r >= incoming_distance => r,
            _ => incoming_distance,
        });
        true
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
                    Some(id) => xor_distance(&id.0, key),
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
                self.bytes = self.bytes.saturating_sub(record_cost(victim.data.len()));
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
    /// [`record_ttl`] after the publisher created it, full stop. A record dated
    /// past its TTL, or implausibly far in the future, is rejected outright.
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
        let ttl_secs = record_ttl(&data).as_secs() as i64;
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

        if !self.entries.contains_key(&key) {
            if !self.make_room_for_key(&key) {
                self.key_cap_rejections = self.key_cap_rejections.saturating_add(1);
                debug!(
                    "DHT store full ({} keys) and holds nothing further away than {}; rejecting",
                    self.key_budget,
                    hex::encode(key)
                );
                return false;
            }
            // A new key can sit further out than the cached bound, and the
            // bound is only safe while it over-estimates. Clearing it costs one
            // scan later; during a flood at capacity nothing is inserted, so it
            // survives exactly when it is doing work.
            self.furthest_key_distance = None;
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
            republish_due: false,
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
            let old_len = record_cost(records[pos].data.len());
            let new_len = record_cost(record.data.len());
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
            // The key is full. Refusing outright handed it to whoever filled it
            // first, and filling it is cheap: records dedupe on (publisher,
            // file), so one identity can take all MAX_RECORDS_PER_KEY slots
            // under a popular word by varying the file hash, then hold them
            // indefinitely by republishing. Every other publisher's records for
            // that word became unstorable, which is to say undiscoverable.
            //
            // Capping how many slots one *sender* may introduce would break
            // replication, for the reason in the note above. But the *author*
            // of each record is signed, and charging slots to the author is
            // both safe for replication — a storer's re-STORE is charged to the
            // original publisher, not to the storer — and exactly the fairness
            // wanted here.
            //
            // So displace the publisher holding the most slots, but only while
            // it holds more than this newcomer would after being admitted. That
            // is max-min fairness by water-filling: a publisher may use as much
            // of a key as nobody else is asking for, every admission strictly
            // reduces the imbalance, and N publishers converge on an even split
            // with no per-publisher quota to pick or tune. A publisher that is
            // already the heaviest cannot displace anyone, so the flood above
            // stops at its fair share instead of the whole key.
            let mut held: HashMap<[u8; 32], usize> = HashMap::new();
            for r in records.iter() {
                *held.entry(r.publisher_key).or_insert(0) += 1;
            }
            let mine = held.get(&publisher_key).copied().unwrap_or(0);
            // Ties break on the key bytes so the choice is deterministic
            // rather than dependent on HashMap iteration order.
            let heaviest = held
                .iter()
                .max_by_key(|(pk, count)| (**count, **pk))
                .map(|(pk, count)| (*pk, *count));
            let Some((heaviest_key, heaviest_count)) = heaviest else {
                return false;
            };
            if heaviest_count <= mine + 1 {
                debug!(
                    "Key {} is full and publisher {} is already at its share, rejecting",
                    hex::encode(key),
                    hex::encode(publisher_key),
                );
                return false;
            }
            // Within that publisher's slots give up whatever expires soonest:
            // it is worth the least to the network, matching the ranking
            // `enforce_byte_budget` uses.
            let Some(victim) = records
                .iter()
                .enumerate()
                .filter(|(_, r)| r.publisher_key == heaviest_key)
                .min_by_key(|(_, r)| r.expires_at)
                .map(|(i, _)| i)
            else {
                return false;
            };
            let evicted = records.remove(victim);
            self.bytes = self
                .bytes
                .saturating_sub(record_cost(evicted.data.len()));
            debug!(
                "Key {} full: displaced a record from publisher {} ({heaviest_count} slots) for {}",
                hex::encode(key),
                hex::encode(heaviest_key),
                hex::encode(publisher_key),
            );
        }

        self.bytes += record_cost(record.data.len());
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
                    freed += record_cost(r.data.len());
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
                let due =
                    force || r.republish_due || now.duration_since(r.last_republished) >= interval;
                if due {
                    r.last_republished = now;
                    r.republish_due = false;
                    out.push((r.data.clone(), r.signature));
                }
            }
            skip_records = 0;
        }
        // The pass covered every key, so the next one starts fresh.
        self.republish_cursor = None;
        out
    }

    /// Records worth carrying across a restart, closest keys first.
    ///
    /// A restart drops every record this node was holding for other publishers.
    /// Storer replication refills them within the hour and the original
    /// publishers re-announce on their own schedule, so nothing is lost
    /// permanently — but on a young network with few replicas per record, and
    /// especially when an update restarts many nodes at once, that leaves a
    /// window where content is simply missing. Carrying the store over closes it.
    ///
    /// Ordered by distance from our own ID so a truncated save keeps the keys we
    /// are most responsible for, matching how the byte budget chooses what to
    /// drop.
    pub fn persistable(&self, max: usize) -> Vec<PersistedRecord> {
        let now = Instant::now();
        let mut keys: Vec<[u8; 16]> = self.entries.keys().copied().collect();
        if let Some(local) = self.local_id {
            keys.sort_by_key(|key| xor_distance(&local.0, key));
        }

        let mut out = Vec::new();
        for key in keys {
            let Some(records) = self.entries.get(&key) else {
                continue;
            };
            for record in records {
                if out.len() >= max {
                    return out;
                }
                // No point writing something that expires before the next
                // launch reads it.
                if record.expires_at <= now {
                    continue;
                }
                out.push(PersistedRecord {
                    key,
                    data: record.data.clone(),
                    signature: record.signature,
                    publisher_key: record.publisher_key,
                    created_at: record.created_at,
                    attributed_ip: record.attributed_ip,
                });
            }
        }
        out
    }

    /// Feed persisted records back in through the ordinary store path.
    ///
    /// Returns how many were accepted. Everything the live path enforces still
    /// applies — signature, TTL from the signed creation time, per-key and
    /// per-IP caps, the byte budget — so a file that was edited, truncated, or
    /// simply left too long cannot put anything in the store that a peer could
    /// not have sent us legitimately.
    pub fn restore(&mut self, records: Vec<PersistedRecord>) -> usize {
        let mut accepted = 0usize;
        for record in records {
            if self.store_attributed(
                record.key,
                record.data,
                record.signature,
                record.publisher_key,
                record.created_at,
                record.attributed_ip,
            ) {
                accepted += 1;
            }
        }
        accepted
    }

    /// How many records are waiting to be replicated onward — those a
    /// [`Self::take_republish_batch`] pass would hand out right now.
    ///
    /// Purely a gauge, so a maintainer can see replication falling behind its
    /// per-cycle budget instead of inferring it from a flat republish counter.
    /// Source records are excluded for the same reason the batch skips them.
    pub fn republish_backlog(&self, interval: Duration) -> usize {
        let now = Instant::now();
        self.entries
            .values()
            .flat_map(|records| records.iter())
            .filter(|r| r.data.first() != Some(&RECORD_TYPE_SOURCE))
            .filter(|r| r.republish_due || now.duration_since(r.last_republished) >= interval)
            .count()
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
        record.republish_due = true;
    }

    /// Total number of records across all keys.
    pub fn total_records(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum()
    }

    /// Number of distinct keys.
    pub fn key_count(&self) -> usize {
        self.entries.len()
    }

    /// Records this node holds that were **not** authored by
    /// `local_publisher_key` — genuinely stored on another publisher's
    /// behalf, as opposed to a record of this node's own that happens to
    /// have landed in its own store (this node can be one of the k-closest
    /// nodes to its own content). Expired records are excluded, matching
    /// [`Self::get_live`] rather than the raw [`Self::get`].
    ///
    /// Returns `(keys_with_at_least_one_foreign_record, foreign_record_count)`.
    pub fn foreign_stats(&self, local_publisher_key: &[u8; 32]) -> (usize, usize) {
        let now = Instant::now();
        let mut keys = 0usize;
        let mut records = 0usize;
        for recs in self.entries.values() {
            let mut any = false;
            for r in recs {
                if r.expires_at > now && &r.publisher_key != local_publisher_key {
                    records += 1;
                    any = true;
                }
            }
            if any {
                keys += 1;
            }
        }
        (keys, records)
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

    /// A store filled to its key cap with keys at a fixed XOR distance from a
    /// local id of all-zeroes, so "closer" and "further" are just the leading
    /// byte. Returns the store, ready at capacity.
    fn store_at_key_cap(first_byte: u8, keys: usize) -> DhtStore {
        let mut store = DhtStore::new();
        store.set_local_id(EmberNodeId([0u8; 16]));
        store.set_key_budget_for_test(keys);
        for i in 0..keys {
            let mut key = [0u8; 16];
            key[0] = first_byte;
            key[1] = (i >> 8) as u8;
            key[2] = (i & 0xFF) as u8;
            let (sk, pk) = keypair();
            let data = vec![i as u8];
            let sig = sign(&sk, &data);
            assert!(store.store(key, data, sig, pk, now_ts()));
        }
        assert_eq!(store.key_count(), keys);
        store
    }

    /// Fill one keyword key with `count` records from a single publisher, one
    /// per invented file hash — what a flooder does to claim a whole word.
    /// Returns the key they landed on.
    fn fill_keyword_key(store: &mut DhtStore, sk: &SigningKey, count: usize) -> [u8; 16] {
        use super::super::publish::SignedRecord;

        let mut key = [0u8; 16];
        for i in 0..count {
            let mut file = [0u8; 16];
            file[0] = (i >> 8) as u8;
            file[1] = (i & 0xFF) as u8;
            let rec = SignedRecord::keyword("ubuntu", file, [0u8; 32], 100, "spam.iso", sk);
            key = rec.keyword_hash;
            assert!(store.store(
                key,
                rec.data.clone(),
                rec.signature,
                rec.publisher_key,
                rec.timestamp,
            ));
        }
        key
    }

    /// The cap used to refuse outright, so a publisher spreading records over
    /// random keys could fill the map and lock out the keys this node is the
    /// closest in the network to — the ones it exists to serve.
    #[test]
    fn a_closer_key_displaces_the_furthest_when_the_map_is_full() {
        let mut store = store_at_key_cap(0xF0, 8);

        let near = [0x01u8; 16];
        let (sk, pk) = keypair();
        let data = vec![0xAAu8];
        let sig = sign(&sk, &data);
        assert!(
            store.store(near, data, sig, pk, now_ts()),
            "a key we are responsible for must find room"
        );

        assert_eq!(store.key_count(), 8, "the cap still holds");
        assert!(store.get(&near).is_some(), "and the close key is present");
        assert_eq!(
            store.key_cap_rejections(),
            0,
            "displacing is not a rejection"
        );
    }

    /// The other half of the policy, and what keeps eviction from being a new
    /// lever: a distant key finds nothing it is allowed to push out.
    #[test]
    fn a_distant_key_cannot_displace_a_closer_one() {
        let mut store = store_at_key_cap(0x01, 8);

        let far = [0xFFu8; 16];
        let (sk, pk) = keypair();
        let data = vec![0xBBu8];
        let sig = sign(&sk, &data);
        assert!(
            !store.store(far, data, sig, pk, now_ts()),
            "a key further out than everything held must be refused"
        );

        assert_eq!(store.key_count(), 8);
        assert!(store.get(&far).is_none());
        assert_eq!(store.key_cap_rejections(), 1);
    }

    /// The refusal above has to stay cheap. A flood aimed at distant keys is
    /// answered from the cached bound rather than a scan per record, so the
    /// cap cannot be turned from a memory bound into a CPU cost.
    #[test]
    fn repeated_distant_keys_are_refused_without_rescanning() {
        let mut store = store_at_key_cap(0x01, 8);

        for i in 0..64u8 {
            let mut far = [0xFFu8; 16];
            far[15] = i;
            let (sk, pk) = keypair();
            let data = vec![i];
            let sig = sign(&sk, &data);
            assert!(!store.store(far, data, sig, pk, now_ts()));
        }

        assert_eq!(store.key_count(), 8, "nothing was displaced");
        assert_eq!(store.key_cap_rejections(), 64);
        assert!(
            store.furthest_key_distance.is_some(),
            "the bound must be cached, or every refusal costs a full scan"
        );
    }

    /// Inserting a new key can put one further out than the cached bound, so
    /// the bound must be dropped rather than left too small — a bound that
    /// under-estimates refuses keys the store should have taken.
    #[test]
    fn a_new_key_clears_the_cached_bound() {
        let mut store = store_at_key_cap(0x01, 8);

        // Provoke a refusal so the bound is populated.
        let far = [0xFFu8; 16];
        let (sk, pk) = keypair();
        let data = vec![1u8];
        assert!(!store.store(far, data.clone(), sign(&sk, &data), pk, now_ts()));
        assert!(store.furthest_key_distance.is_some());

        // Room again, then a genuinely new key.
        store.set_key_budget_for_test(16);
        let fresh = [0x02u8; 16];
        let (sk2, pk2) = keypair();
        let d2 = vec![2u8];
        assert!(store.store(fresh, d2.clone(), sign(&sk2, &d2), pk2, now_ts()));
        assert!(
            store.furthest_key_distance.is_none(),
            "a new key invalidates the bound"
        );
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

    /// Records dedupe on (publisher, file), so one identity can take every
    /// slot under a popular word just by varying the file hash, and hold them
    /// by republishing. While a full key was refused outright, that handed the
    /// word to whoever filled it first and made every other publisher's files
    /// for it unstorable, which is to say undiscoverable.
    #[test]
    fn one_publisher_cannot_lock_everyone_out_of_a_keyword() {
        use super::super::publish::SignedRecord;

        let mut store = DhtStore::new();
        let spammer = SigningKey::generate(&mut OsRng);
        let key = fill_keyword_key(&mut store, &spammer, MAX_RECORDS_PER_KEY);
        assert_eq!(store.get(&key).map(|r| r.len()), Some(MAX_RECORDS_PER_KEY));

        let honest = SigningKey::generate(&mut OsRng);
        let good = SignedRecord::keyword("ubuntu", [0xEE; 16], [0u8; 32], 4096, "real.iso", &honest);
        assert!(
            store.store(
                key,
                good.data.clone(),
                good.signature,
                good.publisher_key,
                good.timestamp,
            ),
            "an honest publisher must still reach a key somebody else filled"
        );

        let records = store.get(&key).unwrap();
        assert_eq!(
            records.len(),
            MAX_RECORDS_PER_KEY,
            "admitting the newcomer must not grow the key past its cap"
        );
        assert!(
            records.iter().any(|r| r.publisher_key == good.publisher_key),
            "the newcomer's record is the one that was admitted"
        );
    }

    /// Displacing the heaviest publisher only while it holds more than the
    /// arrival would is max-min fairness by water-filling: the split evens out
    /// on its own, and once it has, neither side can take from the other. The
    /// flood therefore settles at a fair share instead of the whole key, with
    /// no per-publisher quota to pick.
    #[test]
    fn a_contested_keyword_settles_on_an_even_split() {
        use super::super::publish::SignedRecord;

        let mut store = DhtStore::new();
        let spammer = SigningKey::generate(&mut OsRng);
        let key = fill_keyword_key(&mut store, &spammer, MAX_RECORDS_PER_KEY);

        let honest = SigningKey::generate(&mut OsRng);
        let honest_pk = honest.verifying_key().to_bytes();
        let mut admitted = 0usize;
        for i in 0..MAX_RECORDS_PER_KEY {
            let mut file = [0xC0u8; 16];
            file[0] = (i >> 8) as u8;
            file[1] = (i & 0xFF) as u8;
            let rec = SignedRecord::keyword("ubuntu", file, [0u8; 32], 4096, "real.iso", &honest);
            if store.store(
                key,
                rec.data.clone(),
                rec.signature,
                rec.publisher_key,
                rec.timestamp,
            ) {
                admitted += 1;
            }
        }

        let records = store.get(&key).unwrap();
        let held_by_honest = records
            .iter()
            .filter(|r| r.publisher_key == honest_pk)
            .count();
        assert_eq!(
            admitted,
            MAX_RECORDS_PER_KEY / 2,
            "the contest converges rather than running to either extreme"
        );
        assert_eq!(held_by_honest, MAX_RECORDS_PER_KEY / 2);
        assert_eq!(records.len(), MAX_RECORDS_PER_KEY, "the key stays full");

        // With the key evenly split, the original flooder cannot buy back a
        // slot either: it is no longer holding more than the arrival would.
        let more = SignedRecord::keyword("ubuntu", [0x5A; 16], [0u8; 32], 100, "spam.iso", &spammer);
        assert!(
            !store.store(
                key,
                more.data.clone(),
                more.signature,
                more.publisher_key,
                more.timestamp,
            ),
            "a publisher at its share must not displace anyone"
        );
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

    /// A republish that never reached the wire has to come back around. This
    /// used to be expressed as "stamp it 24 hours ago", which `Instant` cannot
    /// represent on a machine booted more recently than that — so the
    /// saturating fallback marked the record as freshly republished and it sat
    /// out the whole interval instead.
    #[test]
    fn a_dropped_republish_is_due_again_on_the_next_pass() {
        let mut store = DhtStore::new();
        let (sk, pk) = keypair();
        let key = [3u8; 16];
        let d = vec![0x01u8, 9, 9];
        let sig = sign(&sk, &d);
        assert!(store.store(key, d.clone(), sig, pk, now_ts()));

        // Handed out once, which stamps it as republished.
        let batch = store.take_republish_batch(Duration::from_secs(3600), 10, true);
        assert_eq!(batch.len(), 1);
        assert!(
            store
                .take_republish_batch(Duration::from_secs(3600), 10, false)
                .is_empty(),
            "still inside the interval"
        );

        // The caller could not queue it, so it must be offered again — with
        // the interval unchanged and no reliance on how long the host has
        // been up.
        store.mark_republish_due(&key, &sig);
        let again = store.take_republish_batch(Duration::from_secs(3600), 10, false);
        assert_eq!(again.len(), 1, "a dropped republish must be retried");
        assert_eq!(again[0].0, d);

        // And it is a one-shot: the retry consumed the flag.
        assert!(store
            .take_republish_batch(Duration::from_secs(3600), 10, false)
            .is_empty());
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

    /// A source record names an address to download from, so it stops being
    /// true the moment that peer goes offline; a keyword record only says a
    /// file exists under a word and stays true regardless. Giving both the
    /// keyword lifetime meant a peer that left was still handed to downloaders
    /// for the rest of the day.
    /// A restart used to drop every record held for other publishers. On a young
    /// network with few replicas each — or when an update restarts many nodes at
    /// once — that content is missing until replication refills it.
    #[test]
    fn the_store_survives_a_restart_without_trusting_the_file() {
        use super::super::publish::SignedRecord;

        let sk = SigningKey::generate(&mut OsRng);
        let mut store = DhtStore::new();
        store.set_local_id(EmberNodeId([0u8; 16]));

        // Three files sharing one word: one key holding three records, which is
        // the shape a keyword key normally has.
        let mut key = [0u8; 16];
        for i in 0..3u8 {
            let rec = SignedRecord::keyword("ubuntu", [i; 16], [0u8; 32], 100, "u.iso", &sk);
            key = rec.keyword_hash;
            assert!(store.store(
                key,
                rec.data.clone(),
                rec.signature,
                rec.publisher_key,
                rec.timestamp,
            ));
        }
        assert_eq!(store.total_records(), 3);

        let saved = store.persistable(100);
        assert_eq!(saved.len(), 3);

        // A fresh store, as a restart would build it.
        let mut restored = DhtStore::new();
        restored.set_local_id(EmberNodeId([0u8; 16]));
        assert_eq!(restored.restore(saved.clone()), 3);
        assert_eq!(restored.total_records(), 3);
        assert_eq!(
            restored.get_live(&key).len(),
            3,
            "every record under the key came back"
        );

        // The file is not trusted: a record whose body was edited fails the same
        // signature check every live STORE passes through.
        let mut tampered = saved.clone();
        tampered[0].data.push(0xFF);
        let mut victim = DhtStore::new();
        assert_eq!(
            victim.restore(tampered),
            2,
            "the edited record must be refused and the others kept"
        );

        // Expiry is recomputed from the signed creation time rather than from
        // when we happen to read the file, so a stale save cannot revive records
        // that died while we were closed.
        let mut aged = saved.clone();
        for record in &mut aged {
            record.created_at -= KEYWORD_RECORD_TTL.as_secs() as i64 + 60;
        }
        let mut later = DhtStore::new();
        assert_eq!(later.restore(aged), 0, "expired records must not come back");
    }

    #[test]
    fn a_source_record_dies_sooner_than_a_keyword_record() {
        use super::super::publish::{source_key, SignedRecord, SourceContact};
        use std::net::Ipv4Addr;

        let sk = SigningKey::generate(&mut OsRng);
        let mut store = DhtStore::new();
        // Past a source's life, comfortably inside a keyword's.
        let age = SOURCE_RECORD_TTL.as_secs() as i64 + 60;
        assert!(
            age < KEYWORD_RECORD_TTL.as_secs() as i64,
            "the ages must straddle exactly one of the two TTLs"
        );

        let word = SignedRecord::keyword("ubuntu", [0x11; 16], [0u8; 32], 100, "u.iso", &sk);
        assert!(
            store.store(
                word.keyword_hash,
                word.data.clone(),
                word.signature,
                word.publisher_key,
                now_ts() - age,
            ),
            "a keyword record of this age is still worth holding"
        );

        let file_hash = [0x22u8; 16];
        let src = SignedRecord::source(
            file_hash,
            [0u8; 32],
            100,
            "u.iso",
            SourceContact {
                ip: Ipv4Addr::new(198, 51, 100, 7),
                tcp_port: 4662,
                udp_port: 4672,
                flags: 0,
                noise_pub: [1u8; 32],
            },
            &sk,
        );
        assert!(
            !store.store(
                source_key(&file_hash),
                src.data.clone(),
                src.signature,
                src.publisher_key,
                now_ts() - age,
            ),
            "a source record this old points at a peer that left hours ago"
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
            republish_due: false,
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

    /// The whole point of `foreign_stats` is telling "storing for others"
    /// apart from "my own record happens to be in my own store" — so a
    /// record we authored ourselves must not count towards it.
    #[test]
    fn foreign_stats_excludes_our_own_records_and_expired_ones() {
        use super::super::publish::SignedRecord;

        let mut store = DhtStore::new();
        let us = SigningKey::generate(&mut OsRng);
        let us_pk = us.verifying_key().to_bytes();
        let them = SigningKey::generate(&mut OsRng);
        let them_pk = them.verifying_key().to_bytes();

        let ours = SignedRecord::keyword("ubuntu", [1u8; 16], [0u8; 32], 100, "mine.iso", &us);
        let theirs =
            SignedRecord::keyword("fedora", [2u8; 16], [0u8; 32], 200, "theirs.iso", &them);
        assert!(store.store(
            ours.keyword_hash,
            ours.data.clone(),
            ours.signature,
            ours.publisher_key,
            ours.timestamp
        ));
        assert!(store.store(
            theirs.keyword_hash,
            theirs.data.clone(),
            theirs.signature,
            theirs.publisher_key,
            theirs.timestamp
        ));

        let (keys, records) = store.foreign_stats(&us_pk);
        assert_eq!(keys, 1, "only the other publisher's key counts");
        assert_eq!(records, 1, "our own record must not count as foreign");

        // An expired foreign record must not count either.
        for r in store.entries.get_mut(&theirs.keyword_hash).unwrap() {
            r.expires_at = Instant::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap_or_else(Instant::now);
        }
        let (keys, records) = store.foreign_stats(&us_pk);
        assert_eq!(keys, 0, "an expired foreign record must not count");
        assert_eq!(records, 0);

        // Sanity: nothing crashes and returns zero for a key we hold nothing
        // foreign under.
        let (keys, records) = store.foreign_stats(&them_pk);
        assert_eq!(keys, 1, "our own record is foreign from their point of view");
        assert_eq!(records, 1);
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
