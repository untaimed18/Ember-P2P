use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use tracing::debug;

use crate::network::ember::crypto;

use super::publish::{
    channel_kind_from_data, CHANNEL_KIND_PRESENCE, RECORD_TYPE_CHANNEL, RECORD_TYPE_SOURCE,
};
use super::{scale, EmberNodeId};

/// Maximum records per key (anti-spam).
///
/// KAD's equivalent is 1000 entries per keyword and this used to be 300, which
/// made Ember hold under a third of what the network it replaces serves for the
/// same word. The ratio against [`MAX_RECORDS_PER_PUBLISHER_PER_KEY`] was always
/// right; the absolute number was the part a user felt.
///
/// [`MAX_STORE_BYTES`] is deliberately left where it is, so this raises capacity
/// per *key* without raising what the process may resident-hold. Whichever binds
/// first, the byte budget still sheds the records this node is least responsible
/// for rather than refusing the newcomer — so the interaction degrades by
/// distance, not by arrival order.
const MAX_RECORDS_PER_KEY: usize = 1000;
/// Maximum records one publisher may hold under a single key.
///
/// 15% of the key, matching both the ratio *and* the absolute allowance KAD
/// enforces (150 of 1000 entries per sender), so no single identity can crowd a
/// keyword out on its own.
///
/// The ratio alone was not enough. Every storer applies this same cap to the
/// same publisher key, so the ceiling is network-wide rather than per-node: at
/// 45 a user sharing 200 files with a word in common had 45 of them findable
/// under it *anywhere*, against KAD's 150. Reaching those records also needs
/// `FIND_VALUE` paging, since a datagram carries about five — raising this while
/// a peer could only ever serve its first window would have bought nothing but
/// replication traffic.
///
/// Enforced only by refusal. An earlier attempt at this displaced whichever
/// publisher held the most slots when a key was full, which reads as fairness
/// and is in fact an eviction primitive: publisher identity is a free keypair,
/// so an arrival with no slots always outranked an established publisher and
/// evicted one of its records. A few hundred keypairs stripped a healthy keyword
/// to one record per honest publisher, after which every holder had one, nobody
/// outranked anybody, and the key admitted no one ever again. Before that change
/// a full key merely refused newcomers, which at least left incumbents intact.
///
/// The lesson is worth keeping: while identity is free, a per-publisher rule can
/// only ever *withhold* capacity, never move it. Filling an empty key with seven
/// identities is still possible, here as in KAD; bounding that needs something
/// scarcer than a keypair, such as address diversity or proof of work.
///
/// Applies to our own records too, since `store_own_record` goes through the same
/// path: a user sharing more than 150 files under one word serves at most 150 of
/// them from their *own* store. That costs nothing in discoverability — every
/// record is still published to the nodes closest to the key, which is where
/// searchers look — and it is the same allowance we grant everyone else.
const MAX_RECORDS_PER_PUBLISHER_PER_KEY: usize = 150;
/// Maximum total keys stored.
const MAX_KEYS: usize = 50_000;
/// Ceiling on resident record bytes.
///
/// Key and per-key counts alone left the total unbounded: 50,000 keys times
/// 1000 records is far more than a desktop application should ever hold, and
/// an attacker choosing keys can steer records at us deliberately. This is
/// the limit that actually protects memory; when it is reached the least
/// valuable records (furthest from our ID, then nearest expiry) are dropped
/// rather than refusing the newcomer, so a full store still tracks the keys
/// we are most responsible for.
const MAX_STORE_BYTES: usize = 48 * 1024 * 1024;

/// Distinct keys one publisher may hold before admission and eviction treat it
/// as crowding everyone else out.
///
/// Our node ID leads every frame we send, so a publisher can mint keys at any
/// XOR distance from it just by varying the low bytes — there is no hash to
/// grind — and both [`DhtStore::make_room_for_key`] and
/// [`DhtStore::enforce_byte_budget`] rank purely by that distance. Without a
/// share bound, one identity filling the map with keys a hair from our ID makes
/// every honest key look further away than everything held: the key cap then
/// refuses honest keys outright and the byte budget evicts honest records in
/// the flooder's favour.
///
/// An eighth of the map, which no honest remote publisher approaches. A record
/// only lands here when we are among the k closest to its key, so one peer
/// holding 6,250 of our 50,000 keys means either a library the rest of the
/// network is far better placed to hold or a publisher steering keys at us.
///
/// This can only ever *withhold* space, never move it — the same discipline
/// [`MAX_RECORDS_PER_PUBLISHER_PER_KEY`] records above, for the same reason.
/// Identity is a free keypair, so any rule that lets a publisher holding little
/// displace one holding much is an eviction primitive rather than fairness. It
/// follows that a Sybil spending one keypair per key is not bounded by this at
/// all; bounding that still needs something scarcer than a keypair.
const MAX_KEYS_PER_PUBLISHER: usize = MAX_KEYS / 8;

/// The same share of [`MAX_STORE_BYTES`], so the memory budget cannot be taken
/// with few keys and large records instead of many small ones.
const MAX_BYTES_PER_PUBLISHER: usize = MAX_STORE_BYTES / 8;

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

/// Presence records are re-announced by members every 10 minutes; a 45-minute
/// TTL survives a few missed republishes without keeping a departed member
/// listed for a full day.
const CHANNEL_PRESENCE_TTL: Duration = Duration::from_secs(45 * 60);

/// How long a record of this type lives, from its leading type byte.
fn record_ttl(data: &[u8]) -> Duration {
    match data.first() {
        Some(&RECORD_TYPE_SOURCE) => SOURCE_RECORD_TTL,
        Some(&RECORD_TYPE_CHANNEL) if channel_kind_from_data(data) == Some(CHANNEL_KIND_PRESENCE) => {
            CHANNEL_PRESENCE_TTL
        }
        _ => KEYWORD_RECORD_TTL,
    }
}
/// How far a record's signed creation timestamp may sit in the future before
/// we treat it as bogus (clock-skew tolerance between peers).
const CLOCK_SKEW_TOLERANCE_SECS: i64 = 3600;

/// One record on its way to or from disk.
///
/// Only `data` and `signature` are load-bearing on the way back in. Everything
/// else is written for the older builds that read this file and is re-derived
/// from the signed body by [`DhtStore::restore`] — the key it is filed under, the
/// publisher, and the creation time its expiry is computed from — because none of
/// these fields is covered by the signature, so believing them would let anything
/// that can write here file a genuine record under the wrong key or with a life
/// it was never granted. A record already past its TTL is refused, so the file
/// cleans itself up.
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

/// Cumulative store refusals, broken down by the cap or check that fired.
#[derive(Debug, Clone, Copy, Default)]
pub struct StoreRejectStats {
    pub signature: u64,
    pub timestamp: u64,
    pub key_cap: u64,
    pub source_ip_cap: u64,
    pub publisher_cap: u64,
    pub per_key_cap: u64,
    pub unparseable: u64,
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

/// What one publisher currently occupies.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct PublisherLoad {
    /// Distinct keys it holds at least one record under.
    keys: usize,
    /// Resident bytes, charged exactly as the store-wide total is.
    bytes: usize,
}

/// Per-publisher occupancy of the store, kept so [`MAX_KEYS_PER_PUBLISHER`] and
/// [`MAX_BYTES_PER_PUBLISHER`] can be answered without scanning 50,000 keys on
/// the store hot path.
///
/// Every path that inserts, replaces, evicts, expires or drops a record goes
/// through [`Self::charge`] / [`Self::discharge`], and nothing else may touch
/// the map. That single rule is the whole safety argument: admission depends on
/// these counts, so drift is permanent in either direction — too high refuses an
/// honest publisher for the life of the process, too low retires the bound
/// silently.
///
/// Deliberately not `Default`: a zero share reads as "everyone is over their
/// share", which is the one value that must never be reachable by accident.
struct PublisherIndex {
    load: HashMap<[u8; 32], PublisherLoad>,
    /// How many publishers are currently past a share, so "is anyone crowding
    /// the store?" stays O(1) on the refusal path.
    over_share: usize,
    key_share: usize,
    byte_share: usize,
    /// Our own publisher key, never counted as crowding. The shares exist to
    /// stop one *remote* identity taking the store, and `store_own_record`
    /// files our own records through this same path, so counting them would
    /// make a large local library refuse itself — and our own search reads our
    /// own store first.
    local: Option<[u8; 32]>,
    /// Set by a scan that found no key held solely by over-share publishers,
    /// cleared by any charge or discharge. Without it, a flood arriving while
    /// one publisher sits over its share buys a full scan per refused record —
    /// exactly what `furthest_key_distance` exists to prevent for distance.
    no_crowding_victim: bool,
}

impl PublisherIndex {
    fn new(key_share: usize, byte_share: usize) -> Self {
        Self {
            load: HashMap::new(),
            over_share: 0,
            key_share,
            byte_share,
            local: None,
            no_crowding_victim: false,
        }
    }

    /// Whether `publisher` is holding more of the store than its share.
    fn over_share(&self, publisher: &[u8; 32]) -> bool {
        if self.local.as_ref() == Some(publisher) {
            return false;
        }
        self.load
            .get(publisher)
            .is_some_and(|l| l.keys >= self.key_share || l.bytes >= self.byte_share)
    }

    /// Whether anyone at all is. O(1), so the refusal path can ask per record.
    fn anyone_over_share(&self) -> bool {
        self.over_share > 0
    }

    /// Note a record entering the store. `first_under_key` is whether this
    /// publisher held nothing else under that key.
    fn charge(&mut self, publisher: &[u8; 32], bytes: usize, first_under_key: bool) {
        self.no_crowding_victim = false;
        let counted = self.local.as_ref() != Some(publisher);
        let (key_share, byte_share) = (self.key_share, self.byte_share);
        let load = self.load.entry(*publisher).or_default();
        let was = counted && (load.keys >= key_share || load.bytes >= byte_share);
        load.bytes = load.bytes.saturating_add(bytes);
        if first_under_key {
            load.keys = load.keys.saturating_add(1);
        }
        let now = counted && (load.keys >= key_share || load.bytes >= byte_share);
        if now && !was {
            self.over_share = self.over_share.saturating_add(1);
        }
    }

    /// Note a record leaving it. `last_under_key` is whether that was this
    /// publisher's last record under that key.
    fn discharge(&mut self, publisher: &[u8; 32], bytes: usize, last_under_key: bool) {
        self.no_crowding_victim = false;
        let counted = self.local.as_ref() != Some(publisher);
        let (key_share, byte_share) = (self.key_share, self.byte_share);
        let Some(load) = self.load.get_mut(publisher) else {
            return;
        };
        let was = counted && (load.keys >= key_share || load.bytes >= byte_share);
        load.bytes = load.bytes.saturating_sub(bytes);
        if last_under_key {
            load.keys = load.keys.saturating_sub(1);
        }
        let now = counted && (load.keys >= key_share || load.bytes >= byte_share);
        if was && !now {
            self.over_share = self.over_share.saturating_sub(1);
        }
        // Dropping spent entries is what bounds the map by the resident record
        // set rather than by every publisher ever seen.
        if load.keys == 0 && load.bytes == 0 {
            self.load.remove(publisher);
        }
    }

    fn set_local(&mut self, publisher: [u8; 32]) {
        self.local = Some(publisher);
        self.recount();
    }

    #[cfg(test)]
    fn set_shares(&mut self, key_share: usize, byte_share: usize) {
        self.key_share = key_share;
        self.byte_share = byte_share;
        self.recount();
    }

    /// Re-derive `over_share` after a change to what "over share" means.
    fn recount(&mut self) {
        let local = self.local;
        let (key_share, byte_share) = (self.key_share, self.byte_share);
        self.over_share = self
            .load
            .iter()
            .filter(|(publisher, load)| {
                local.as_ref() != Some(*publisher)
                    && (load.keys >= key_share || load.bytes >= byte_share)
            })
            .count();
    }
}

/// Local DHT key-value store for Ember DHT.
///
/// Stores signed records indexed by 16-byte keys (BLAKE3 hashes of keywords,
/// file hashes, etc.). Each key can have multiple records (e.g., multiple
/// sources for the same file).
pub struct DhtStore {
    entries: HashMap<[u8; 16], Vec<DhtRecord>>,
    /// Who holds how much of `entries`. See [`PublisherIndex`].
    publisher_index: PublisherIndex,
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
    /// Signature did not verify against the claimed publisher key.
    signature_rejections: u64,
    /// Creation timestamp too far in the future, or already past TTL.
    timestamp_rejections: u64,
    /// Per-IP source-record cap (`max_sources_per_ip`).
    source_ip_cap_rejections: u64,
    /// One publisher already holds `MAX_RECORDS_PER_PUBLISHER_PER_KEY` here.
    publisher_cap_rejections: u64,
    /// The key already holds `MAX_RECORDS_PER_KEY` live records.
    per_key_cap_rejections: u64,
    /// Body too short to carry a record header, so nothing could ever parse it.
    unparseable_rejections: u64,
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
            publisher_index: PublisherIndex::new(MAX_KEYS_PER_PUBLISHER, MAX_BYTES_PER_PUBLISHER),
            scale: scale::NetworkScale::Bootstrap,
            republish_cursor: None,
            bytes: 0,
            local_id: None,
            byte_budget: MAX_STORE_BYTES,
            key_budget: MAX_KEYS,
            key_cap_rejections: 0,
            signature_rejections: 0,
            timestamp_rejections: 0,
            source_ip_cap_rejections: 0,
            publisher_cap_rejections: 0,
            per_key_cap_rejections: 0,
            unparseable_rejections: 0,
            furthest_key_distance: None,
        }
    }

    /// Cumulative store refusals broken down by cause.
    pub fn reject_stats(&self) -> StoreRejectStats {
        StoreRejectStats {
            signature: self.signature_rejections,
            timestamp: self.timestamp_rejections,
            key_cap: self.key_cap_rejections,
            source_ip_cap: self.source_ip_cap_rejections,
            publisher_cap: self.publisher_cap_rejections,
            per_key_cap: self.per_key_cap_rejections,
            unparseable: self.unparseable_rejections,
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

    /// Tell the store which publisher key is our own, so the per-publisher
    /// shares never apply to records we authored. See [`PublisherIndex::local`].
    pub fn set_local_publisher_key(&mut self, publisher_key: [u8; 32]) {
        self.publisher_index.set_local(publisher_key);
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

    /// Shrink the per-publisher shares so the fairness bound can be exercised
    /// without minting thousands of keys. Left at the production values by the
    /// budget setters above on purpose: those shrink the *store*, and a share
    /// that shrank with it would make a lone publisher in a tiny test store
    /// look like it was crowding the network out.
    #[cfg(test)]
    fn set_publisher_shares_for_test(&mut self, keys: usize, bytes: usize) {
        self.publisher_index.set_shares(keys, bytes);
    }

    /// Drop a key and everything under it, keeping the byte total and the
    /// per-publisher index in step.
    fn drop_key(&mut self, key: &[u8; 16]) {
        if let Some(records) = self.entries.remove(key) {
            // One key slot per publisher, however many records it held here.
            let mut released: HashSet<[u8; 32]> = HashSet::new();
            for record in records {
                let cost = record_cost(record.data.len());
                self.bytes = self.bytes.saturating_sub(cost);
                let last = released.insert(record.publisher_key);
                self.publisher_index
                    .discharge(&record.publisher_key, cost, last);
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
    /// Expired keys go first, being free. Then a key held only by publishers
    /// past their share, since those slots were taken by crowding rather than
    /// by responsibility. Otherwise the furthest key from us is given up, and
    /// only when the incoming key is closer than it. That ordering is what
    /// makes the eviction safe rather than a new lever: a flood of distant keys
    /// finds nothing it is allowed to displace, while a key we are genuinely
    /// responsible for always finds room.
    fn make_room_for_key(&mut self, incoming: &[u8; 16], publisher: &[u8; 32]) -> bool {
        if self.entries.len() < self.key_budget {
            return true;
        }
        // Without our own id there is no notion of responsibility, so there is
        // no principled victim to choose.
        let Some(local) = self.local_id else {
            return false;
        };
        // A publisher already holding its share of the map gets no further key
        // slot, whatever the distance says. Refusal only, never displacement —
        // see MAX_KEYS_PER_PUBLISHER.
        if self.publisher_index.over_share(publisher) {
            return false;
        }
        let incoming_distance = xor_distance(&local.0, incoming);

        // The O(1) refusal that keeps a flood cheap. Safe because the bound
        // over-estimates: anything it rejects, a full scan would reject too.
        //
        // Stood down only while someone is over their share and the last scan
        // did find a key we may take from them, because then distance is no
        // longer the only thing that decides. `no_crowding_victim` is what keeps
        // that from handing a flooder a full scan per refused record.
        if let Some(bound) = self.furthest_key_distance {
            if incoming_distance >= bound
                && (!self.publisher_index.anyone_over_share()
                    || self.publisher_index.no_crowding_victim)
            {
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

        // Furthest key to evict, the next-furthest to seed the bound with once
        // it is gone, and the furthest key held *only* by publishers past their
        // share — all from a single pass. The per-record test is skipped
        // entirely when nobody is over share, which is the normal case.
        let mut furthest: Option<([u8; 16], [u8; 16])> = None;
        let mut runner_up: Option<[u8; 16]> = None;
        let mut crowding: Option<([u8; 16], [u8; 16])> = None;
        let index = &self.publisher_index;
        let look_for_crowding = index.anyone_over_share();
        for (key, records) in self.entries.iter() {
            let distance = xor_distance(&local.0, key);
            if look_for_crowding
                && !records.is_empty()
                && crowding.is_none_or(|(_, held)| distance > held)
                && records.iter().all(|r| index.over_share(&r.publisher_key))
            {
                crowding = Some((*key, distance));
            }
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

        // Giving up a crowding publisher's key ahead of our own furthest is
        // what stops one identity that filled the map from locking every honest
        // key out: it holds those slots only because it chose keys next to our
        // ID, which is free to do. The incoming publisher is under its share
        // (checked above), so this can never be used to strip an incumbent.
        if let Some((victim, _)) = crowding {
            self.drop_key(&victim);
            debug!(
                "DHT store at the {}-key cap: gave up {} from a publisher over its share",
                self.key_budget,
                hex::encode(victim)
            );
            return true;
        }
        if look_for_crowding {
            self.publisher_index.no_crowding_victim = true;
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
        let index = &self.publisher_index;
        let crowded = index.anyone_over_share();
        let mut ranked: Vec<([u8; 16], bool, [u8; 16])> = self
            .entries
            .iter()
            .filter(|(key, _)| *key != spare)
            .map(|(key, records)| {
                let distance = match local {
                    Some(id) => xor_distance(&id.0, key),
                    None => [0u8; 16],
                };
                // Keys held only by publishers past their share go first,
                // whatever the distance. Ranking on distance alone made the
                // budget an eviction primitive: our own ID is public, so a
                // flooder can mint keys nearer to us than any honest one and
                // have every honest record dropped in its favour.
                let crowding = crowded
                    && !records.is_empty()
                    && records.iter().all(|r| index.over_share(&r.publisher_key));
                (*key, crowding, distance)
            })
            .collect();
        // Crowding first, then furthest from us: those are the keys other nodes
        // are best placed to serve.
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.2.cmp(&a.2)));

        let mut dropped = 0usize;
        'keys: for (key, _, _) in ranked {
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
                let cost = record_cost(victim.data.len());
                self.bytes = self.bytes.saturating_sub(cost);
                let last = !records
                    .iter()
                    .any(|r| r.publisher_key == victim.publisher_key);
                self.publisher_index
                    .discharge(&victim.publisher_key, cost, last);
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
        // A body that cannot pack into a FOUND_VALUE even as the only blob
        // would store-but-hide: live under the key, skipped by the packer,
        // and if every live record is oversized the peer answers FOUND_NODE
        // as if the key were empty. Decode already refuses these; this
        // covers store_own_record and restore, which never go through the wire.
        if data.len() > super::messages::MAX_STORE_RECORD_BYTES {
            debug!(
                "DHT store: rejecting {}-byte record for key {} (max {})",
                data.len(),
                hex::encode(key),
                super::messages::MAX_STORE_RECORD_BYTES
            );
            return false;
        }
        // The other end of the same argument: a body too short to hold a record
        // header parses nowhere, so it could only sit under the key being
        // counted as held while every reader refused it. Enforcing the floor
        // here rather than only at the framings that happen to parse first is
        // what lets the FOUND_VALUE packer stop scanning a key on
        // `MIN_FOUND_VALUE_RECORD_BYTES` — a floor it may only assume for as
        // long as the store holds to it.
        if data.len() < super::messages::MIN_STORE_RECORD_BYTES {
            self.unparseable_rejections = self.unparseable_rejections.saturating_add(1);
            debug!(
                "DHT store: rejecting {}-byte record for key {} (min {})",
                data.len(),
                hex::encode(key),
                super::messages::MIN_STORE_RECORD_BYTES
            );
            return false;
        }
        if !verify_record_signature(&data, &signature, &publisher_key) {
            self.signature_rejections = self.signature_rejections.saturating_add(1);
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
            self.timestamp_rejections = self.timestamp_rejections.saturating_add(1);
            debug!(
                "DHT store: rejecting record for key {} dated {}s in the future",
                hex::encode(key),
                created_at - now_unix,
            );
            return false;
        }
        let age = now_unix.saturating_sub(created_at).max(0);
        if age >= ttl_secs {
            self.timestamp_rejections = self.timestamp_rejections.saturating_add(1);
            debug!(
                "DHT store: rejecting record for key {} already past TTL (age {age}s)",
                hex::encode(key),
            );
            return false;
        }

        if !self.entries.contains_key(&key) {
            if !self.make_room_for_key(&key, &publisher_key) {
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

        let records = self.entries.entry(key).or_default();

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
            // A replacement, so the publisher's key count is unchanged and only
            // the byte charge moves.
            self.publisher_index
                .discharge(&publisher_key, old_len, false);
            self.publisher_index.charge(&publisher_key, new_len, false);
            self.enforce_byte_budget(&key);
            return true;
        }

        // Note on publisher diversity: a per-sender cap on how many distinct
        // publisher identities may be introduced under one key is tempting,
        // but it would break replication. A storer legitimately re-publishes
        // many different publishers' records to the nodes closest to a key,
        // so "one sender introducing many publishers" is normal Kademlia
        // behaviour rather than an attack signature. What is bounded instead is
        // how much of a key any one *author* may hold
        // (MAX_RECORDS_PER_PUBLISHER_PER_KEY below), alongside
        // MAX_RECORDS_PER_KEY, the byte budget, the per-IP source cap below, and
        // the per-peer STORE rate limit.

        // Reclaim this key's lapsed records before any cap counts them. All three
        // caps below count what is resident, and a record past its `expires_at` is
        // already invisible to `get_live` while still holding its slot until a
        // sweep removes it. The periodic sweep runs every five minutes
        // (`expire_records` on the cleanup timer), so without this a key at its
        // per-key cap — or a source key at its per-IP cap, which is as low as three
        // — refused genuine records for up to that long after the records blocking
        // them had died. Placed above the per-IP check for exactly that reason.
        //
        // Safe to run after the dedupe branch above rather than before it: a record
        // this one could dedupe against cannot itself be lapsed, because
        // `store_attributed` has already refused anything whose age exceeds its TTL.
        let mut reclaimed = 0usize;
        let mut lapsed: Vec<([u8; 32], usize)> = Vec::new();
        records.retain(|r| {
            if r.expires_at <= now {
                let cost = record_cost(r.data.len());
                reclaimed += cost;
                lapsed.push((r.publisher_key, cost));
                false
            } else {
                true
            }
        });
        self.bytes = self.bytes.saturating_sub(reclaimed);
        // A publisher gives up its key slot once, however many of its records
        // under this key lapsed together.
        let mut released: HashSet<[u8; 32]> = HashSet::new();
        for (author, cost) in lapsed {
            let last = !records.iter().any(|r| r.publisher_key == author) && released.insert(author);
            self.publisher_index.discharge(&author, cost, last);
        }

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
                self.source_ip_cap_rejections = self.source_ip_cap_rejections.saturating_add(1);
                debug!(
                    "Key {} already has {same_ip} source record(s) attributed to {ip}, rejecting",
                    hex::encode(key)
                );
                return false;
            }
        }

        // What one publisher may hold under this key. Records dedupe on
        // (publisher, file), so without this a single identity takes every slot
        // under a popular word by varying the file hash and holds them by
        // republishing, leaving every other publisher's records for that word
        // unstorable and so undiscoverable.
        //
        // Charged to the record's signed *author*, not to the peer that sent it.
        // That distinction is what makes the cap safe for replication: a storer
        // relaying fifty publishers' records charges each to its own author, so
        // each stays under its own allowance, whereas a per-sender cap would
        // refuse honest replication outright.
        let mine = records
            .iter()
            .filter(|r| r.publisher_key == publisher_key)
            .count();
        if mine >= MAX_RECORDS_PER_PUBLISHER_PER_KEY {
            self.publisher_cap_rejections = self.publisher_cap_rejections.saturating_add(1);
            debug!(
                "Key {} already holds {mine} record(s) from publisher {}, rejecting",
                hex::encode(key),
                hex::encode(publisher_key),
            );
            return false;
        }

        if records.len() >= MAX_RECORDS_PER_KEY {
            self.per_key_cap_rejections = self.per_key_cap_rejections.saturating_add(1);
            debug!(
                "Key {} has {MAX_RECORDS_PER_KEY} records, rejecting",
                hex::encode(key)
            );
            return false;
        }

        let cost = record_cost(record.data.len());
        self.bytes += cost;
        records.push(record);
        // `mine` was counted a few lines up, before the push, so zero there
        // means this record is what puts the publisher on this key.
        self.publisher_index.charge(&publisher_key, cost, mine == 0);
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
        self.live_records(key).collect()
    }

    /// [`Self::get_live`] without the intermediate `Vec`, for a caller that
    /// walks the key once and keeps nothing.
    ///
    /// Same records, same order, same expiry cutoff — taken when the iterator is
    /// built, so a long walk cannot see a record lapse midway and disagree with
    /// itself. A multi-keyword `FIND_VALUE` reads up to
    /// [`super::messages::MAX_FIND_VALUE_KEYS`] keys for nothing but the file
    /// hashes their records declare, and collecting each of those into a vector
    /// of up to [`MAX_RECORDS_PER_KEY`] references is an allocation per key on
    /// the single task that also drives eD2K, KAD and every UI event.
    pub fn live_records<'a>(&'a self, key: &[u8; 16]) -> impl Iterator<Item = &'a DhtRecord> + 'a {
        let now = Instant::now();
        self.entries
            .get(key)
            .into_iter()
            .flatten()
            .filter(move |r| r.expires_at > now)
    }

    /// Remove expired records. Returns how many were removed.
    pub fn expire(&mut self) -> usize {
        let now = Instant::now();
        let mut total_removed = 0;

        let mut freed = 0usize;
        // Collected rather than applied in place: the closure cannot reach the
        // index while `entries` is being retained.
        let mut released: Vec<([u8; 32], usize, bool)> = Vec::new();
        self.entries.retain(|_, records| {
            let before = records.len();
            let mut lapsed: Vec<([u8; 32], usize)> = Vec::new();
            records.retain(|r| {
                let live = r.expires_at > now;
                if !live {
                    let cost = record_cost(r.data.len());
                    freed += cost;
                    lapsed.push((r.publisher_key, cost));
                }
                live
            });
            total_removed += before - records.len();
            let mut gave_up_key: HashSet<[u8; 32]> = HashSet::new();
            for (author, cost) in lapsed {
                let last = !records.iter().any(|r| r.publisher_key == author)
                    && gave_up_key.insert(author);
                released.push((author, cost, last));
            }
            !records.is_empty()
        });
        self.bytes = self.bytes.saturating_sub(freed);
        for (author, cost, last) in released {
            self.publisher_index.discharge(&author, cost, last);
        }
        if total_removed > 0 {
            debug!("Expired {total_removed} DHT records");
        }
        total_removed
    }

    /// Remove records `publisher_key` published for `file_hash` (keyword and
    /// source). Friends-only after a public publish drops our local copies
    /// immediately; remote replicas still expire on TTL.
    pub fn drop_publisher_file(&mut self, publisher_key: &[u8; 32], file_hash: &[u8; 16]) -> usize {
        let mut total_removed = 0;
        let mut freed = 0usize;
        let mut released: Vec<([u8; 32], usize, bool)> = Vec::new();
        self.entries.retain(|_, records| {
            let before = records.len();
            let mut dropped: Vec<([u8; 32], usize)> = Vec::new();
            records.retain(|r| {
                let ours = &r.publisher_key == publisher_key
                    && file_hash_from_record_data(&r.data) == *file_hash;
                if ours {
                    let cost = record_cost(r.data.len());
                    freed += cost;
                    dropped.push((r.publisher_key, cost));
                }
                !ours
            });
            total_removed += before - records.len();
            let mut gave_up_key: HashSet<[u8; 32]> = HashSet::new();
            for (author, cost) in dropped {
                let last = !records.iter().any(|r| r.publisher_key == author)
                    && gave_up_key.insert(author);
                released.push((author, cost, last));
            }
            !records.is_empty()
        });
        self.bytes = self.bytes.saturating_sub(freed);
        for (author, cost, last) in released {
            self.publisher_index.discharge(&author, cost, last);
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
                if r.data.first() == Some(&RECORD_TYPE_SOURCE)
                    || channel_kind_from_data(&r.data) == Some(CHANNEL_KIND_PRESENCE)
                {
                    continue;
                }
                // A lapsed record is not worth a replica set of frames. Expiry is
                // derived from the publisher's signed creation time and we re-send
                // the identical bytes, so every recipient computes the same death
                // time and refuses it. Records stay resident until the five-minute
                // sweep collects them, and the maintenance tick that republishes
                // runs on its own schedule, so one that dies between sweeps would
                // otherwise be fanned out once for nothing. `persistable` skips
                // them on the same reasoning.
                if r.expires_at <= now {
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
                // Source records are deliberately not carried over. Each one names
                // an address to download from, and the live path binds that claim
                // to the peer it arrived from — matching the sender's address for
                // a reachable source, or attributing the sending peer's address
                // for a firewalled one that cannot be checked directly. Neither
                // binding can be reproduced from a file, so persisting them would
                // mean restoring an address claim nothing vouches for. Their
                // publisher re-announces every two hours regardless, so the most
                // this costs is a short gap in our own copy.
                if record.data.first() == Some(&RECORD_TYPE_SOURCE) {
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
    /// Returns how many were accepted. The signature, the TTL derived from the
    /// signed creation time, the per-publisher and per-key caps and the byte and
    /// key budgets all apply exactly as they do to a record off the wire, and the
    /// key a record is filed under is re-derived from its own signed body rather
    /// than trusted from the file — so anything that can write to the data
    /// directory still cannot place a record under a key its publisher never
    /// signed for.
    ///
    /// Two checks from the live path do not apply here, for different reasons. The
    /// source-record address bind is handled by not persisting the records that
    /// need it (see [`Self::persistable`]). The proximity gate — are we among the
    /// closest to this key — is waived instead: having held the key last session is
    /// the answer, and at restore time no eviction pressure exists to abuse anyway,
    /// since it runs against an empty store with far fewer records than the key
    /// budget.
    pub fn restore(&mut self, records: Vec<PersistedRecord>) -> usize {
        let mut accepted = 0usize;
        for record in records {
            if record.data.first() == Some(&RECORD_TYPE_SOURCE) {
                continue;
            }
            // Take the key, the author and the creation time from the record's own
            // signed body, never from the fields beside it in the file. Nothing
            // signs those, so trusting them let anything able to write here file a
            // genuine record under an unrelated key, or hand it a life its
            // publisher never granted — and a raised creation time also pinned the
            // newer-copy guard above against that publisher's real republishes for
            // as long as the skew allowance.
            //
            // A few records legitimately carry a file `created_at` later than their
            // signed timestamp, because the zero-digest republish branch above
            // advances it while keeping the older signed body. Those restore with
            // the shorter life the signature actually supports, which is what every
            // other node in the network already computes for them.
            let Some((key, publisher_key, created_at)) =
                signed_identity_from_record_data(&record.data)
            else {
                continue;
            };
            if self.store_attributed(
                key,
                record.data,
                record.signature,
                publisher_key,
                created_at,
                None,
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
            .filter(|r| channel_kind_from_data(&r.data) != Some(CHANNEL_KIND_PRESENCE))
            // Counted on the same terms the batch selects on, or the gauge
            // reports work that will never be done.
            .filter(|r| r.expires_at > now)
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

    /// Re-derive the per-publisher index from `entries` and assert it matches.
    ///
    /// The index is maintained incrementally on every mutation path, and
    /// admission depends on it, so a drift that goes unnoticed is permanent.
    /// This is the check that makes "audit every mutation site" verifiable
    /// rather than a claim.
    #[cfg(test)]
    fn assert_publisher_index_consistent(&self) {
        let mut expected: HashMap<[u8; 32], PublisherLoad> = HashMap::new();
        for records in self.entries.values() {
            let mut counted: HashSet<[u8; 32]> = HashSet::new();
            for r in records {
                let load = expected.entry(r.publisher_key).or_default();
                load.bytes += record_cost(r.data.len());
                if counted.insert(r.publisher_key) {
                    load.keys += 1;
                }
            }
        }
        assert_eq!(
            self.publisher_index.load.len(),
            expected.len(),
            "the index tracks {} publishers, the store holds records from {}",
            self.publisher_index.load.len(),
            expected.len()
        );
        for (publisher, want) in &expected {
            let got = self.publisher_index.load.get(publisher).copied();
            assert_eq!(
                got,
                Some(*want),
                "index drifted for publisher {}",
                hex::encode(publisher)
            );
        }
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
    let name_len =
        u16::from_le_bytes([data[RECORD_HEADER_LEN - 2], data[RECORD_HEADER_LEN - 1]]) as usize;
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

/// The key, author and creation time a record body declares, at the fixed
/// offsets `SignedRecord::from_wire` reads them from. `None` for a body too short
/// to be a record at all.
///
/// Deliberately does not verify, and does not need to: the only caller
/// ([`DhtStore::restore`]) hands the same bytes straight to `store_attributed`,
/// which verifies the signature over exactly this range — so if these fields are
/// wrong the record is refused a moment later, and if it is accepted they were
/// signed. Going through `from_wire` for this instead cost a second Ed25519
/// verification per record on the synchronous startup path, doubling the work the
/// persisted-record ceiling was sized against.
fn signed_identity_from_record_data(data: &[u8]) -> Option<([u8; 16], [u8; 32], i64)> {
    // Both length checks `from_wire` applies, so a body it would call malformed is
    // not admitted here either. The second one is easy to leave out and matters:
    // without it a signed body claiming a longer name than it carries is stored,
    // costing a slot and a `FIND_VALUE` answer that every reader then rejects,
    // since they all re-parse through `from_wire`.
    if data.len() < 115 {
        return None;
    }
    let name_len = u16::from_le_bytes([data[113], data[114]]) as usize;
    if data.len() < 115 + name_len {
        return None;
    }
    let key: [u8; 16] = data[1..17].try_into().ok()?;
    let publisher_key: [u8; 32] = data[73..105].try_into().ok()?;
    let created_at = i64::from_le_bytes(data[105..113].try_into().ok()?);
    Some((key, publisher_key, created_at))
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

    /// Zero-pad a synthetic record body out to the shortest length the store
    /// accepts.
    ///
    /// Most tests below exercise capacity, eviction, attribution or replication
    /// and never parse the body, so they carry only the few leading bytes that
    /// tell their records apart — but the store refuses anything too short to
    /// hold a record header, so those bytes have to sit inside a body of at
    /// least that length. Padding with zeroes leaves the type byte, the file
    /// hash and the ember digest reading exactly as they did when the body was
    /// shorter than all three.
    fn padded(prefix: &[u8]) -> Vec<u8> {
        let mut data = prefix.to_vec();
        if data.len() < super::super::messages::MIN_STORE_RECORD_BYTES {
            data.resize(super::super::messages::MIN_STORE_RECORD_BYTES, 0);
        }
        data
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
            let data = padded(&[i as u8]);
            let sig = sign(&sk, &data);
            assert!(store.store(key, data, sig, pk, now_ts()));
        }
        assert_eq!(store.key_count(), keys);
        store
    }

    /// Offer `count` records for one keyword key from a single publisher, one
    /// per invented file hash — what a flooder does to claim a whole word.
    /// Returns the key they landed on. Refusals are expected once the
    /// per-publisher share is reached, so nothing here asserts admission.
    fn fill_keyword_key(store: &mut DhtStore, sk: &SigningKey, count: usize) -> [u8; 16] {
        use super::super::publish::SignedRecord;

        let mut key = [0u8; 16];
        for i in 0..count {
            let mut file = [0u8; 16];
            file[0] = (i >> 8) as u8;
            file[1] = (i & 0xFF) as u8;
            let rec = SignedRecord::keyword("ubuntu", file, [0u8; 32], 100, "spam.iso", sk);
            key = rec.keyword_hash;
            store.store(
                key,
                rec.data.clone(),
                rec.signature,
                rec.publisher_key,
                rec.timestamp,
            );
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
        let data = padded(&[0xAA]);
        let sig = sign(&sk, &data);
        assert!(
            store.store(near, data, sig, pk, now_ts()),
            "a key we are responsible for must find room"
        );

        assert_eq!(store.key_count(), 8, "the cap still holds");
        assert!(store.get(&near).is_some(), "and the close key is present");
        assert_eq!(
            store.reject_stats().key_cap,
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
        let data = padded(&[0xBB]);
        let sig = sign(&sk, &data);
        assert!(
            !store.store(far, data, sig, pk, now_ts()),
            "a key further out than everything held must be refused"
        );

        assert_eq!(store.key_count(), 8);
        assert!(store.get(&far).is_none());
        assert_eq!(store.reject_stats().key_cap, 1);
    }

    /// Our node ID leads every frame we send, so a publisher can mint keys a
    /// hair from it by varying the low bytes — no hash to grind — and the key
    /// cap ranks purely by that distance. Once the map is full those keys make
    /// every honest key look further away than everything held. A publisher
    /// already at its share gets no further slot, however close it aims.
    #[test]
    fn a_publisher_at_its_share_gets_no_more_key_slots() {
        let mut store = DhtStore::new();
        store.set_local_id(EmberNodeId([0u8; 16]));
        store.set_key_budget_for_test(8);
        store.set_publisher_shares_for_test(4, usize::MAX);

        let (hog, hog_pk) = keypair();
        // Half the map to one publisher, half spread across distinct ones, all
        // at the same distance so only the share can decide anything.
        for i in 0..8u8 {
            let mut key = [0x20u8; 16];
            key[15] = i;
            let data = padded(&[i]);
            if i < 4 {
                assert!(store.store(key, data.clone(), sign(&hog, &data), hog_pk, now_ts()));
            } else {
                let (sk, pk) = keypair();
                assert!(store.store(key, data.clone(), sign(&sk, &data), pk, now_ts()));
            }
        }
        assert_eq!(store.key_count(), 8, "the map has to be full to be in play");

        // A key right against our ID — closer than everything held, so distance
        // alone would have displaced an honest key for it.
        let near = [0u8; 16];
        let data = padded(&[0xAA]);
        assert!(
            !store.store(near, data.clone(), sign(&hog, &data), hog_pk, now_ts()),
            "a publisher over its share must be refused however close its key is"
        );
        assert_eq!(store.key_count(), 8, "and nothing may be displaced for it");
        assert_eq!(store.reject_stats().key_cap, 1);
        store.assert_publisher_index_consistent();
    }

    /// The other half of the same rule, and what makes it more than a refusal:
    /// a publisher that filled the map holds those slots only because choosing
    /// keys next to us is free, so when room is needed its keys go before an
    /// honest publisher's. Otherwise being closer stays a way to displace
    /// honest records, which is the whole trick.
    #[test]
    fn a_crowding_publisher_loses_a_key_before_an_honest_one() {
        let mut store = DhtStore::new();
        store.set_local_id(EmberNodeId([0u8; 16]));
        store.set_key_budget_for_test(8);
        store.set_publisher_shares_for_test(4, usize::MAX);

        let (hog, hog_pk) = keypair();
        let mut hog_keys = Vec::new();
        for i in 0..4u8 {
            let mut key = [0u8; 16];
            key[15] = i;
            hog_keys.push(key);
            let data = padded(&[i]);
            assert!(store.store(key, data.clone(), sign(&hog, &data), hog_pk, now_ts()));
        }
        let mut honest_keys = Vec::new();
        for i in 4..8u8 {
            let mut key = [0x40u8; 16];
            key[15] = i;
            honest_keys.push(key);
            let (sk, pk) = keypair();
            let data = padded(&[i]);
            assert!(store.store(key, data.clone(), sign(&sk, &data), pk, now_ts()));
        }

        // Further from us than everything held, so the distance rule alone
        // refuses it outright.
        let far = [0xFFu8; 16];
        let (newcomer, newcomer_pk) = keypair();
        let data = padded(&[0xEE]);
        assert!(
            store.store(far, data.clone(), sign(&newcomer, &data), newcomer_pk, now_ts()),
            "a crowding publisher's key is the one to give up"
        );
        assert_eq!(store.key_count(), 8);
        for key in &honest_keys {
            assert!(
                store.get(key).is_some(),
                "no honest key may be displaced for it"
            );
        }
        assert_eq!(
            hog_keys.iter().filter(|k| store.get(k).is_some()).count(),
            3,
            "exactly one of the crowding publisher's keys should have gone"
        );
        store.assert_publisher_index_consistent();
    }

    /// The byte budget ranks the same way, so a fill from keys chosen next to
    /// our ID evicted honest records rather than the flooder's own.
    #[test]
    fn the_byte_budget_drops_a_crowding_publisher_before_an_honest_one() {
        let mut store = DhtStore::new();
        store.set_local_id(EmberNodeId([0u8; 16]));
        store.set_publisher_shares_for_test(4, usize::MAX);

        let body = vec![super::super::publish::RECORD_TYPE_KEYWORD; 1024];
        store.set_byte_budget_for_test(record_cost(body.len()) * 8);

        let (hog, hog_pk) = keypair();
        let hog_sig = sign(&hog, &body);
        let mut hog_keys = Vec::new();
        for i in 0..4u8 {
            let mut key = [0u8; 16];
            key[15] = i;
            hog_keys.push(key);
            assert!(store.store(key, body.clone(), hog_sig, hog_pk, now_ts()));
        }
        let mut honest_keys = Vec::new();
        for i in 4..8u8 {
            let mut key = [0x40u8; 16];
            key[15] = i;
            honest_keys.push(key);
            let (sk, pk) = keypair();
            assert!(store.store(key, body.clone(), sign(&sk, &body), pk, now_ts()));
        }

        // One more record takes the store over budget, so eviction has to pick
        // a victim.
        let (last, last_pk) = keypair();
        assert!(store.store([0x7Fu8; 16], body.clone(), sign(&last, &body), last_pk, now_ts()));

        for key in &honest_keys {
            assert!(
                store.get_live(key).len() == 1,
                "an honest publisher's record must survive a crowding publisher's"
            );
        }
        assert!(
            hog_keys.iter().filter(|k| !store.get_live(k).is_empty()).count() < 4,
            "the crowding publisher is what the budget should have come out of"
        );
        assert!(store.byte_len() <= store.byte_budget);
        store.assert_publisher_index_consistent();
    }

    /// Admission depends on the per-publisher index, so a drift in it is
    /// permanent: too high refuses an honest publisher for the life of the
    /// process, too low retires the bound silently. Churn a store through every
    /// path that moves a record and re-derive the index from scratch each time.
    #[test]
    fn the_publisher_index_survives_every_path_that_moves_a_record() {
        use super::super::publish::SignedRecord;

        let mut store = DhtStore::new();
        store.set_local_id(EmberNodeId([0u8; 16]));

        // Several publishers, several files each, sharing keywords so keys hold
        // records from more than one author.
        for word in ["ubuntu", "debian", "fedora"] {
            for p in 0..4u8 {
                let sk = SigningKey::from_bytes(&[p + 1; 32]);
                for f in 0..3u8 {
                    let mut file = [0u8; 16];
                    file[0] = p;
                    file[1] = f;
                    let rec = SignedRecord::keyword(word, file, [0u8; 32], 100, "f.iso", &sk);
                    assert!(store.store(
                        rec.keyword_hash,
                        rec.data.clone(),
                        rec.signature,
                        rec.publisher_key,
                        rec.timestamp,
                    ));
                }
            }
        }
        assert_eq!(store.total_records(), 36);
        store.assert_publisher_index_consistent();

        // A republish replaces in place: the byte charge moves, the key count
        // must not.
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let again =
            SignedRecord::keyword("ubuntu", [0u8; 16], [0u8; 32], 100, "a-longer-name.iso", &sk);
        assert!(store.store(
            again.keyword_hash,
            again.data.clone(),
            again.signature,
            again.publisher_key,
            again.timestamp,
        ));
        assert_eq!(store.total_records(), 36, "a republish is not a new record");
        store.assert_publisher_index_consistent();

        // Expiry, taking some of a publisher's records under a key but not all.
        for records in store.entries.values_mut() {
            for (i, r) in records.iter_mut().enumerate() {
                if i % 3 == 0 {
                    r.expires_at = Instant::now()
                        .checked_sub(Duration::from_secs(1))
                        .unwrap_or_else(Instant::now);
                }
            }
        }
        assert!(store.expire() > 0);
        store.assert_publisher_index_consistent();

        // Byte eviction, which takes records one at a time and drops a key once
        // it empties.
        store.set_byte_budget_for_test(store.byte_len() / 2);
        let (spare, spare_pk) = keypair();
        let body = vec![super::super::publish::RECORD_TYPE_KEYWORD; 512];
        assert!(store.store([0x7Fu8; 16], body.clone(), sign(&spare, &body), spare_pk, now_ts()));
        store.assert_publisher_index_consistent();

        // The key cap, which drops whole keys at once.
        assert!(store.key_count() > 0);
        store.set_key_budget_for_test(store.key_count());
        let (closest, closest_pk) = keypair();
        let near = padded(&[super::super::publish::RECORD_TYPE_KEYWORD, 3]);
        assert!(store.store([0u8; 16], near.clone(), sign(&closest, &near), closest_pk, now_ts()));
        store.assert_publisher_index_consistent();

        // And a restore, which files records back through this same path.
        let saved = store.persistable(1000);
        let mut restored = DhtStore::new();
        restored.set_local_id(EmberNodeId([0u8; 16]));
        assert!(restored.restore(saved) > 0);
        restored.assert_publisher_index_consistent();
    }

    /// A body that cannot pack into a FOUND_VALUE even as the only blob must
    /// not enter the store: that is the store-but-hide case, and store_own_record
    /// / restore never pass through wire decode.
    #[test]
    fn an_unservable_record_body_is_refused() {
        let mut store = DhtStore::new();
        let (sk, pk) = keypair();
        let data = vec![0xCCu8; super::super::messages::MAX_STORE_RECORD_BYTES + 1];
        let sig = sign(&sk, &data);
        assert!(
            !store.store([0x11; 16], data, sig, pk, now_ts()),
            "a body past the FOUND_VALUE pack budget must not be stored"
        );
        assert_eq!(store.key_count(), 0);
    }

    /// The other end of the same range, and the floor the `FOUND_VALUE`
    /// packer's early stop is derived from: a body too short to carry a record
    /// header parses nowhere, so holding one would cost a key slot and an
    /// answer every reader discards. While the store could hold one, the packer
    /// could not assume a record was worth more than a length prefix and a
    /// signature — see `MIN_FOUND_VALUE_RECORD_BYTES`.
    #[test]
    fn a_body_too_short_to_parse_is_refused_and_counted() {
        use super::super::publish::SignedRecord;

        let min = super::super::messages::MIN_STORE_RECORD_BYTES;
        let mut store = DhtStore::new();
        let (sk, pk) = keypair();

        // Signed over its own bytes, so the length is the only thing left that
        // can refuse it.
        let short = vec![super::super::publish::RECORD_TYPE_KEYWORD; min - 1];
        assert!(
            !store.store([0x11; 16], short.clone(), sign(&sk, &short), pk, now_ts()),
            "a body too short to carry a record header must not be stored"
        );
        assert_eq!(store.key_count(), 0);
        assert_eq!(store.reject_stats().unparseable, 1);
        assert_eq!(
            store.reject_stats().signature,
            0,
            "the length refused it, not the signature"
        );

        // The positive control is a real record at exactly the floor: an empty
        // file name leaves a keyword record's header and nothing after it.
        let exact = SignedRecord::keyword("ubuntu", [0x22; 16], [0u8; 32], 100, "", &sk);
        assert_eq!(
            exact.data.len(),
            min,
            "an empty name is the shortest a publisher can sign"
        );
        assert!(
            store.store(
                exact.keyword_hash,
                exact.data.clone(),
                exact.signature,
                exact.publisher_key,
                exact.timestamp,
            ),
            "the shortest parseable body must still be accepted"
        );
        assert_eq!(
            store.reject_stats().unparseable,
            1,
            "a body at the floor is not one under it"
        );
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
            let data = padded(&[i]);
            let sig = sign(&sk, &data);
            assert!(!store.store(far, data, sig, pk, now_ts()));
        }

        assert_eq!(store.key_count(), 8, "nothing was displaced");
        assert_eq!(store.reject_stats().key_cap, 64);
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
        let data = padded(&[1]);
        assert!(!store.store(far, data.clone(), sign(&sk, &data), pk, now_ts()));
        assert!(store.furthest_key_distance.is_some());

        // Room again, then a genuinely new key.
        store.set_key_budget_for_test(16);
        let fresh = [0x02u8; 16];
        let (sk2, pk2) = keypair();
        let d2 = padded(&[2]);
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
        let data = padded(&[42]);
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

        let d1 = padded(&[1]);
        let d2 = padded(&[2]);
        let d3 = padded(&[3]);
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

        let first =
            SignedRecord::keyword("ubuntu", [0xA1; 16], [0u8; 32], 100, "ubuntu-24.iso", &sk);
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

    /// Keyword capacity is a user-visible number, not just an anti-abuse knob:
    /// every storer applies the same per-publisher cap to the same key, so it is
    /// the network-wide ceiling on how many of one user's files are findable
    /// under one word. At 45 of 300 that was under a third of what KAD serves
    /// for the same word, on a network meant to replace it.
    ///
    /// Pinned at KAD's own numbers, and pinned together: the ratio is what stops
    /// one identity crowding a keyword out, and raising either alone breaks it.
    #[test]
    fn keyword_capacity_matches_kad() {
        assert_eq!(MAX_RECORDS_PER_KEY, 1000, "KAD's entries per keyword");
        assert_eq!(
            MAX_RECORDS_PER_PUBLISHER_PER_KEY, 150,
            "KAD's entries per sender"
        );
        assert_eq!(
            MAX_RECORDS_PER_KEY / MAX_RECORDS_PER_PUBLISHER_PER_KEY,
            6,
            "no identity may hold more than about a sixth of a key"
        );
    }

    /// Records dedupe on (publisher, file), so one identity can offer a record
    /// per invented file under a popular word. Without a per-publisher bound it
    /// took every slot and held them by republishing, leaving every other
    /// publisher's files for that word unstorable, which is to say
    /// undiscoverable.
    #[test]
    fn one_publisher_cannot_take_more_than_its_share_of_a_keyword() {
        use super::super::publish::SignedRecord;

        let mut store = DhtStore::new();
        let spammer = SigningKey::generate(&mut OsRng);
        // Offer a record for the whole key; only the share may be admitted.
        let key = fill_keyword_key(&mut store, &spammer, MAX_RECORDS_PER_KEY);
        assert_eq!(
            store.get(&key).map(|r| r.len()),
            Some(MAX_RECORDS_PER_PUBLISHER_PER_KEY),
            "one identity is held to its share however many files it offers"
        );
        assert!(
            store.reject_stats().publisher_cap > 0,
            "refusals past the publisher share must be counted, not only logged"
        );

        let honest = SigningKey::generate(&mut OsRng);
        let good =
            SignedRecord::keyword("ubuntu", [0xEE; 16], [0u8; 32], 4096, "real.iso", &honest);
        assert!(
            store.store(
                key,
                good.data.clone(),
                good.signature,
                good.publisher_key,
                good.timestamp,
            ),
            "the rest of the key stays available to everybody else"
        );
    }

    /// A record past its TTL is already invisible to `get_live`, but it keeps its
    /// slot until a sweep removes it — and the sweep only runs every five minutes.
    /// Every cap counts resident records, so a key holding nothing but dead records
    /// used to refuse genuine ones for the rest of that interval. The per-IP source
    /// cap is the sharpest case, at three.
    #[test]
    fn a_key_full_of_dead_records_still_admits_a_live_one() {
        use super::super::publish::{source_key, SignedRecord, SourceContact};
        use std::net::Ipv4Addr;

        let mut store = DhtStore::new();
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let contact = SourceContact {
            ip,
            tcp_port: 4662,
            udp_port: 4672,
            flags: 0,
            noise_pub: [7u8; 32],
            ..Default::default()
        };
        let file = [0xD1u8; 16];
        let key = source_key(&file);

        // Fill the address's whole source allowance, from distinct publishers so
        // only the per-IP cap is in play.
        let max_per_ip = store.scale.max_sources_per_ip();
        for p in 0..max_per_ip {
            let sk = SigningKey::from_bytes(&[p as u8 + 1; 32]);
            let rec = SignedRecord::source(file, [0u8; 32], 100, "iso", contact, &sk);
            assert!(store.store_attributed(
                key,
                rec.data.clone(),
                rec.signature,
                rec.publisher_key,
                rec.timestamp,
                Some(ip),
            ));
        }
        let newcomer = SigningKey::from_bytes(&[0xF0; 32]);
        let blocked = SignedRecord::source(file, [0u8; 32], 100, "iso", contact, &newcomer);
        assert!(
            !store.store_attributed(
                key,
                blocked.data.clone(),
                blocked.signature,
                blocked.publisher_key,
                blocked.timestamp,
                Some(ip),
            ),
            "the allowance really is spent while those records are alive"
        );

        // Kill them all, without sweeping — exactly the state the store is in
        // between periodic sweeps.
        let bytes_before = store.byte_len();
        for record in store.entries.get_mut(&key).expect("the key").iter_mut() {
            record.expires_at = Instant::now() - Duration::from_secs(1);
        }
        assert!(
            store.get_live(&key).is_empty(),
            "they are already invisible to readers"
        );

        assert!(
            store.store_attributed(
                key,
                blocked.data.clone(),
                blocked.signature,
                blocked.publisher_key,
                blocked.timestamp,
                Some(ip),
            ),
            "a dead record must not keep a live one out until the next sweep"
        );
        assert_eq!(
            store.get_live(&key).len(),
            1,
            "and the dead ones are gone rather than merely hidden"
        );
        assert!(
            store.byte_len() < bytes_before,
            "reclaiming them has to give their bytes back too"
        );
    }

    /// The regression this replaced: the share used to be enforced by
    /// displacing whichever publisher held the most slots, which is an eviction
    /// primitive rather than fairness. Publisher identity is a free keypair, so
    /// an arrival holding nothing always outranked an established publisher and
    /// took one of its records; a few hundred keypairs stripped a healthy
    /// keyword bare and then locked it, because once every holder had one slot
    /// nobody outranked anybody and the key admitted no one. A full key must
    /// refuse, never displace.
    #[test]
    fn a_full_keyword_never_evicts_an_incumbent() {
        use super::super::publish::SignedRecord;

        let mut store = DhtStore::new();
        let mut key = [0u8; 16];
        let mut incumbents: Vec<[u8; 32]> = Vec::new();
        // Fill the key legitimately: enough distinct publishers, each within
        // its share, to reach the per-key cap.
        'fill: for p in 0..16u8 {
            let sk = SigningKey::from_bytes(&[p.wrapping_add(1); 32]);
            for i in 0..MAX_RECORDS_PER_PUBLISHER_PER_KEY {
                let mut file = [0u8; 16];
                file[0] = p;
                file[1] = i as u8;
                let rec = SignedRecord::keyword("ubuntu", file, [0u8; 32], 100, "real.iso", &sk);
                key = rec.keyword_hash;
                if !store.store(
                    key,
                    rec.data.clone(),
                    rec.signature,
                    rec.publisher_key,
                    rec.timestamp,
                ) {
                    break 'fill;
                }
                incumbents.push(rec.publisher_key);
            }
        }
        assert_eq!(
            store.get(&key).map(|r| r.len()),
            Some(MAX_RECORDS_PER_KEY),
            "the key must be legitimately full for this test to mean anything"
        );
        let before = store.get(&key).unwrap().len();

        // A Sybil flood: a fresh identity per record, each holding nothing, so
        // each would have outranked every incumbent under the old rule.
        for s in 0..64u16 {
            let mut seed = [0xA0u8; 32];
            seed[0] = (s >> 8) as u8;
            seed[1] = (s & 0xFF) as u8;
            let sk = SigningKey::from_bytes(&seed);
            let rec = SignedRecord::keyword("ubuntu", [0xC7; 16], [0u8; 32], 100, "spam.iso", &sk);
            assert!(
                !store.store(
                    key,
                    rec.data.clone(),
                    rec.signature,
                    rec.publisher_key,
                    rec.timestamp,
                ),
                "a full key must refuse a newcomer rather than evict for it"
            );
        }

        let after = store.get(&key).unwrap();
        assert_eq!(after.len(), before, "no record was displaced");
        for publisher in &incumbents {
            assert!(
                after.iter().any(|r| &r.publisher_key == publisher),
                "every incumbent publisher still holds records"
            );
        }
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
                    ..Default::default()
                },
                &sk,
            );
            if store.store(
                key,
                rec.data.clone(),
                rec.signature,
                rec.publisher_key,
                rec.timestamp,
            ) {
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
                noise_pub: [200u8; 32],
                ..Default::default()
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
        let mut newer = SignedRecord::keyword("ubuntu", [1u8; 16], [8u8; 32], 10, "new.iso", &sk);
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
        assert!(
            store.total_records() > 0,
            "eviction must not empty the store"
        );

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
            let data = padded(&[super::super::publish::RECORD_TYPE_KEYWORD, i as u8]);
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
            let data = padded(&[super::super::publish::RECORD_TYPE_KEYWORD, i as u8]);
            assert!(store.store([i as u8; 16], data.clone(), sign(&sk, &data), pk, now_ts()));
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
        assert!(!store.store(key, padded(&[42]), [0u8; 64], pk, now_ts()));
        assert_eq!(store.total_records(), 0);
        assert_eq!(store.reject_stats().signature, 1);
    }

    #[test]
    fn rejects_bad_publisher_key() {
        let mut store = DhtStore::new();
        let key = [1u8; 16];
        let (sk, _pk) = keypair();
        let data = padded(&[42]);
        let sig = sign(&sk, &data);
        // sign with sk but claim a different publisher_key
        assert!(!store.store(key, data, sig, [0xCC; 32], now_ts()));
        assert_eq!(store.total_records(), 0);
        assert_eq!(store.reject_stats().signature, 1);
    }

    #[test]
    fn republish_batch_respects_interval_and_force() {
        let mut store = DhtStore::new();
        let (sk, pk) = keypair();
        let d = padded(&[7]);
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
        let d2 = padded(&[8]);
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
        let d = padded(&[0x01, 9, 9]);
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
        let src = padded(&[RECORD_TYPE_SOURCE, 1]);
        assert!(store.store([1u8; 16], src.clone(), sign(&sk, &src), pk, now_ts()));

        // A non-source (keyword) record stays eligible for replication.
        let (sk2, pk2) = keypair();
        let kw = padded(&[0x01u8, 2]);
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
        let d = padded(&[1]);
        // A record created just over the 24h TTL ago is already dead and must
        // not be revived with a fresh local TTL (replay defense).
        let stale_ts = now_ts() - (24 * 3600 + 60);
        assert!(!store.store([1u8; 16], d.clone(), sign(&sk, &d), pk, stale_ts));
        assert_eq!(store.total_records(), 0);
        assert_eq!(store.reject_stats().timestamp, 1);
    }

    #[test]
    fn rejects_record_dated_far_in_future() {
        let mut store = DhtStore::new();
        let (sk, pk) = keypair();
        let d = padded(&[1]);
        let future_ts = now_ts() + (CLOCK_SKEW_TOLERANCE_SECS + 60);
        assert!(!store.store([1u8; 16], d.clone(), sign(&sk, &d), pk, future_ts));
        assert_eq!(store.total_records(), 0);
        assert_eq!(store.reject_stats().timestamp, 1);
    }

    #[test]
    fn expiry_tracks_creation_time_not_receipt() {
        let mut store = DhtStore::new();
        let (sk, pk) = keypair();
        let d = padded(&[1]);
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

        // Nor is the key trusted. Rewriting it in the file must not file a
        // validly signed record under an unrelated word — the record goes where
        // its own signed body says, which is the binding the live path gets from
        // `accept_record`.
        let mut misfiled = saved.clone();
        for record in &mut misfiled {
            record.key = [0x99; 16];
        }
        let mut elsewhere = DhtStore::new();
        assert_eq!(elsewhere.restore(misfiled), 3);
        assert!(
            elsewhere.get_live(&[0x99; 16]).is_empty(),
            "nothing may land under the key the file claimed"
        );
        assert_eq!(
            elsewhere.get_live(&key).len(),
            3,
            "the records land under the key their publisher signed"
        );

        // Expiry is recomputed from the signed creation time rather than from when
        // we happen to read the file, so a stale save cannot revive records that
        // died while we were closed. Aged by rewriting the timestamp inside the
        // signed body and re-signing, because that is the only copy that counts.
        let mut aged = saved.clone();
        for record in &mut aged {
            let old = i64::from_le_bytes(record.data[105..113].try_into().unwrap())
                - KEYWORD_RECORD_TTL.as_secs() as i64
                - 60;
            record.data[105..113].copy_from_slice(&old.to_le_bytes());
            record.signature = crate::network::ember::crypto::sign(&sk, &record.data);
            record.created_at = old;
        }
        let mut later = DhtStore::new();
        assert_eq!(later.restore(aged), 0, "expired records must not come back");

        // And the file's own copy of the creation time buys nothing. It is not
        // covered by the signature, so believing it let anything able to write here
        // hand a long-dead record a fresh full life — and pin the newer-copy guard
        // against the publisher's real republishes while it lasted.
        let mut backdated = saved.clone();
        for record in &mut backdated {
            let real = i64::from_le_bytes(record.data[105..113].try_into().unwrap());
            let stale = real - KEYWORD_RECORD_TTL.as_secs() as i64 - 60;
            record.data[105..113].copy_from_slice(&stale.to_le_bytes());
            record.signature = crate::network::ember::crypto::sign(&sk, &record.data);
            // The file claims they are current; only the body says otherwise.
            record.created_at = chrono::Utc::now().timestamp();
        }
        let mut fooled = DhtStore::new();
        assert_eq!(
            fooled.restore(backdated),
            0,
            "the file's creation time must not be able to revive a record"
        );
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
                ..Default::default()
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

    /// A room's public-index record is published once, when the room is created
    /// (`commands::channels::create_channel`), and nothing republishes it.
    /// Replication cannot make up the difference, which is the point of this
    /// test: remaining life is derived from the publisher's signed creation
    /// time, so a storer offered the identical bytes past the TTL refuses them
    /// rather than granting a fresh 24 hours. Discover (`gather_channels`)
    /// walks exactly these keys, so a public room stops being discoverable one
    /// TTL after creation whether or not its owner is online.
    #[test]
    fn a_channel_index_record_cannot_outlive_its_signed_creation_time() {
        use super::super::publish::SignedRecord;
        use crate::network::ember::channel::ChannelIdentity;

        let ident = ChannelIdentity::generate();
        let record = SignedRecord::channel_index(
            "Lobby",
            ident.channel_id,
            ident.pubkey,
            false,
            &ident.signing_key,
        );
        let ttl = KEYWORD_RECORD_TTL.as_secs() as i64;

        let mut inside = DhtStore::new();
        assert!(
            inside.store(
                record.keyword_hash,
                record.data.clone(),
                record.signature,
                record.publisher_key,
                now_ts() - ttl + 600,
            ),
            "ten minutes short of the TTL a storer still holds the listing"
        );
        assert_eq!(inside.get_live(&record.keyword_hash).len(), 1);

        // What a replica re-offering the record looks like once the owner has
        // not re-signed a newer one.
        let mut lapsed = DhtStore::new();
        assert!(
            !lapsed.store(
                record.keyword_hash,
                record.data.clone(),
                record.signature,
                record.publisher_key,
                now_ts() - ttl - 600,
            ),
            "past the TTL the same signed bytes buy no further life"
        );
        assert!(lapsed.get_live(&record.keyword_hash).is_empty());

        // And what the owner's republish does instead: index records dedupe on
        // publisher plus room id, so a newly signed listing takes the aged
        // one's place with a full TTL rather than piling up beside it.
        let renewed = SignedRecord::channel_index(
            "Lobby",
            ident.channel_id,
            ident.pubkey,
            false,
            &ident.signing_key,
        );
        assert!(inside.store(
            renewed.keyword_hash,
            renewed.data.clone(),
            renewed.signature,
            renewed.publisher_key,
            now_ts(),
        ));
        let held = inside.get_live(&renewed.keyword_hash);
        assert_eq!(held.len(), 1, "a republish replaces, it does not accumulate");
        assert!(
            held[0].expires_at > Instant::now() + Duration::from_secs((ttl - 3600) as u64),
            "the replacement carries a fresh full lifetime"
        );
    }

    #[test]
    fn get_live_skips_expired_records() {
        let mut store = DhtStore::new();
        let key = [9u8; 16];
        let (sk, pk) = keypair();
        let d = padded(&[1]);
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
        let mut good = padded(&[super::super::publish::RECORD_TYPE_KEYWORD]);
        good[33..65].fill(0xAB);
        assert!(store.store(key, good.clone(), sign(&sk, &good), pk, now_ts()));
        let zero_ember = padded(&[super::super::publish::RECORD_TYPE_KEYWORD]);
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
        assert_eq!(
            keys, 1,
            "our own record is foreign from their point of view"
        );
        assert_eq!(records, 1);
    }

    #[test]
    fn store_churn_soak_expire_and_republish() {
        let mut store = DhtStore::new();
        let (sk, pk) = keypair();
        for i in 0u8..64 {
            let key = [i; 16];
            let mut data = padded(&[1]);
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
