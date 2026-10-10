use std::collections::{BTreeSet, HashMap, HashSet};
use zeroize::ZeroizeOnDrop;

const MAX_CREDIT_RATIO: f64 = 10.0;
const MIN_CREDIT_RATIO: f64 = 1.0;

/// Hard ceiling on per-peer credit records held in memory. The 90-day
/// `cleanup_stale` sweep is the primary reaper; this cap is a backstop so a
/// peer churning `user_hash` (or Ember pubkey) across reconnects — each
/// OP_PUBLICKEY seeds a record via `get_or_create` — can't grow the maps
/// without bound between sweeps. At capacity, inserting a new record evicts
/// the least-recently-seen one, mirroring the bounded DHT store / comment maps.
const MAX_CREDIT_RECORDS: usize = 50_000;

/// Upper bound on binding-only eD2K→Ember mappings held in memory; see
/// [`CreditManager::note_bound_ember_hash`].
const MAX_BOUND_EMBER_HASHES: usize = 4_096;

/// `last_seen` ordering over one credit map, so eviction at
/// `MAX_CREDIT_RECORDS` pops the oldest key instead of scanning the map under
/// the credit lock on every new Hello.
///
/// `get_or_create` hands out `&mut` to the record, so a caller can rewrite
/// `last_seen` behind the index's back (the startup loader does exactly that).
/// Eviction therefore re-checks the popped entry against the record, and
/// `cleanup_stale` re-syncs every key.
#[derive(Debug)]
struct LastSeenIndex<K: Ord + Copy + std::hash::Hash> {
    order: BTreeSet<(i64, K)>,
    indexed_at: HashMap<K, i64>,
}

impl<K: Ord + Copy + std::hash::Hash> Default for LastSeenIndex<K> {
    fn default() -> Self {
        Self {
            order: BTreeSet::new(),
            indexed_at: HashMap::new(),
        }
    }
}

impl<K: Ord + Copy + std::hash::Hash> LastSeenIndex<K> {
    fn set(&mut self, key: K, last_seen: i64) {
        match self.indexed_at.insert(key, last_seen) {
            Some(old) if old == last_seen => return,
            Some(old) => {
                self.order.remove(&(old, key));
            }
            None => {}
        }
        self.order.insert((last_seen, key));
    }

    fn remove(&mut self, key: &K) {
        if let Some(old) = self.indexed_at.remove(key) {
            self.order.remove(&(old, *key));
        }
    }

    /// Least-recently-seen key in `map`, correcting stale entries on the way.
    fn oldest<V>(&mut self, map: &HashMap<K, V>, last_seen_of: impl Fn(&V) -> i64) -> Option<K> {
        while let Some(&(indexed, key)) = self.order.first() {
            match map.get(&key) {
                None => self.remove(&key),
                Some(record) => {
                    let actual = last_seen_of(record);
                    if actual == indexed {
                        return Some(key);
                    }
                    self.set(key, actual);
                }
            }
        }
        None
    }
}

// --- Ember credit scoring constants ---
//
// The Ember credit system layers three multiplicative factors on top of the
// baseline eMule credit-ratio formula: time-decayed ratio, session
// reliability, and upload-speed fairness. Each factor is clamped to a
// narrow band so no single signal can dominate scoring; the plan target is
// "slightly more nuanced than eMule", not "completely rewrite priority".
//
// Exposed at module level so the unit tests can reference the same
// constants the runtime uses — avoids the "tests pass but drift from
// code" trap.

/// EWMA smoothing weight for new session speed samples. The new sample
/// contributes `EMBER_SPEED_EWMA_ALPHA` and the prior average
/// contributes `1 - EMBER_SPEED_EWMA_ALPHA`. 0.3 gives the series a
/// visible memory (prior ~3 sessions still show through) while still
/// tracking persistent speed changes over ~10 sessions.
pub(crate) const EMBER_SPEED_EWMA_ALPHA: f64 = 0.3;

/// Minimum session duration (seconds) that's allowed to update the EWMA
/// speed estimate. Sub-second sessions are dominated by handshake
/// overhead and produce wildly noisy "speeds"; ignoring them keeps the
/// EWMA honest for the real data-transfer sessions it's trying to
/// characterise.
pub(crate) const EMBER_MIN_SESSION_SECS_FOR_SPEED: u64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentState {
    Unknown,
    Verified,
    Failed,
    BadGuy,
    Needed,
}

impl IdentState {
    /// Stable on-disk encoding used by both the SQLite `credits.ident_state`
    /// column and the versioned `clients.met` cache. Keep these values fixed;
    /// changing them would reinterpret existing persisted records.
    pub fn to_u8(self) -> u8 {
        match self {
            IdentState::Unknown => 0,
            IdentState::Verified => 1,
            IdentState::Failed => 2,
            IdentState::BadGuy => 3,
            IdentState::Needed => 4,
        }
    }

    pub fn from_u8(v: u8) -> IdentState {
        match v {
            1 => IdentState::Verified,
            2 => IdentState::Failed,
            3 => IdentState::BadGuy,
            4 => IdentState::Needed,
            _ => IdentState::Unknown,
        }
    }
}

/// Magic word that prefixes the versioned `clients.met` cache. Chosen so that,
/// read as the legacy `count: u32` header, it dwarfs the 50k record cap — so
/// even an older build that didn't know about the format would safely load
/// nothing from a v1 file rather than misparsing it.
const CLIENTS_MET_MAGIC: u32 = 0xE3B2_0001;
/// Layout version that follows the magic.
///
/// v1: user_hash, uploaded, downloaded, last_seen, ident_ip, ident_state,
/// public_key.
///
/// v2: appends a per-record Ember-identity trailer after the
/// public key — a presence byte followed by 16 bytes of `ember_hash` when
/// set. This survives the eD2K user_hash ↔ Ember identity binding
/// (`set_ember_hash`) across restarts, which is what lets friend rendezvous
/// discovery relocate `sources.met` rows before a fresh HELLO re-binds it
/// in-memory (see `reseed_friend_endpoint` in `network/mod.rs`). Readers
/// stay backward compatible with v1 files (no trailer to read).
///
/// v3: appends the crypto-anchor section (see
/// [`CLIENTS_MET_ANCHOR_MAGIC`]) *after* the record array. The per-record
/// layout is byte-identical to v2 on purpose: a v2 reader consumes exactly
/// `count` records and stops, so it ignores the section instead of
/// mis-framing the record after it, and a v2 file simply has no section for
/// us to find.
///
/// v4 (current): appends the identity section (see
/// [`CLIENTS_MET_IDENTITY_MAGIC`]) after the crypto-anchor section, carrying
/// each record's Hello nickname and client-software string. Same containment
/// trick as v3 — the per-record layout is untouched, so a v2/v3 reader
/// consumes `count` records and never looks further.
const CLIENTS_MET_VERSION: u8 = 4;

/// Introduces the v3 crypto-anchor section: `magic | u32 count | count ×
/// 16-byte user_hash`, naming the records whose credits are already anchored
/// to a key that proved itself ([`CreditRecord::crypto_verified_once`]).
///
/// It has to be persisted, not derived. eMule's equivalent anchor
/// (`CreditStruct::nKeySize`, written only inside `CClientCredits::Verified`)
/// lives in the credit struct on disk and is monotonic, but `ident_state`
/// is not: any peer can drive a record out of `Verified` by claiming its
/// user_hash — which travels in the clear in every Hello — from another IP
/// and failing the challenge that `secident_request_state` then issues. If
/// the anchor were reconstructed from a persisted `Failed`, the honest
/// peer's totals would be reset to 1 the next time it re-proved itself.
const CLIENTS_MET_ANCHOR_MAGIC: u32 = 0xE3B2_0003;

/// Introduces the v4 identity section: `magic | u32 count | count × (16-byte
/// user_hash | u8 name_len | name | u8 software_len | software)`.
///
/// Separate from the record array rather than added to it, for the reason the
/// anchor section is: the per-record layout stays byte-identical, so a build
/// that stops after `count` records still reads this file correctly.
///
/// Length-prefixed with a single byte because [`MAX_IDENTITY_LEN`] bounds
/// both strings well under 255.
const CLIENTS_MET_IDENTITY_MAGIC: u32 = 0xE3B2_0004;

pub const CRYPT_CIP_REMOTECLIENT: u8 = 10;
pub const CRYPT_CIP_LOCALCLIENT: u8 = 20;
pub const CRYPT_CIP_NONECLIENT: u8 = 30;

/// Cap on a stored nickname or client-software string.
///
/// Both come off the wire and are persisted, so an unbounded value would let
/// one peer grow `clients.met` and the `credits` table without limit. The
/// eD2K Hello tag is already bounded by the frame, but the record outlives
/// the frame. Well above any real nickname.
const MAX_IDENTITY_LEN: usize = 64;

/// Bound a peer-supplied identity string without splitting a UTF-8 character.
fn truncate_identity(value: &str) -> String {
    if value.len() <= MAX_IDENTITY_LEN {
        return value.to_string();
    }
    let mut end = MAX_IDENTITY_LEN;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

#[derive(Debug, Clone)]
pub struct CreditRecord {
    pub user_hash: [u8; 16],
    pub uploaded: u64,
    pub downloaded: u64,
    pub last_seen: i64,
    pub public_key: Vec<u8>,
    pub ident_state: IdentState,
    pub ident_ip: u32,
    /// Ember node id (`BLAKE3(ed25519_pubkey)[0..16]`) learned when an
    /// Ember hello binding check succeeds for this eD2K user hash.
    /// Distinct from SecIdent RSA `public_key` — used by Known Clients
    /// to mark friends (friends are keyed by ember hash, not user hash).
    pub ember_hash: Option<[u8; 16]>,
    /// Whether these credits have ever been anchored to a *proven* key.
    ///
    /// eMule reads this off `CreditStruct::nKeySize`, which it only ever
    /// fills in from inside `CClientCredits::Verified()` — so for eMule "a
    /// key is stored" and "a key has proven itself" are the same fact. Ours
    /// aren't: [`CreditManager::set_public_key`] binds the key the moment
    /// `OP_PUBLICKEY` arrives, long before any challenge is answered, so a
    /// bound key says nothing about verification and neither does
    /// `ident_state` (the inbound path parks at `Needed` in between).
    ///
    /// Persisted in the v3 `clients.met` crypto-anchor section (see
    /// `CLIENTS_MET_ANCHOR_MAGIC`) rather than derived, because
    /// `ident_state` is not monotonic and a remote peer can drive it
    /// backwards out of `Verified`. Files that predate the section fall
    /// back to `ident_state == Verified` on load.
    ///
    /// NOTE: the primary credit store is the SQLite `credits` table
    /// (`clients.met` is only the fallback cache used when that table is
    /// empty), so the anchor has to be carried in that table's row as well
    /// or the reset stays reachable across every restart.
    pub crypto_verified_once: bool,
    /// Peer's Hello nickname (`CT_NAME`) the last time it told us one.
    ///
    /// Identity, not accounting, but it lives here because this record is the
    /// only thing the Known eD2K Peers tab has to build a row from — and that
    /// tab is a lifetime ledger, so almost none of its rows have a live
    /// session to ask. Persisted in the SQLite `credits` table (v47) and in
    /// the v4 `clients.met` identity section.
    ///
    /// Only ever overwritten by a *non-empty* value (see
    /// [`CreditManager::note_client_identity`]), so a later handshake that
    /// omits the tag does not erase a name we already had.
    pub peer_name: String,
    /// Client software and version, as `client_software_from_caps` renders it.
    pub client_software: String,
    /// IPv4 (big-endian, like `ident_ip`) of the last session we held with
    /// this peer, whatever SecIdent made of it.
    ///
    /// Display only. `ident_ip` is the address an identity was *proven* from
    /// and drives BadGuy detection, so it is only written after a signature
    /// verifies — which leaves it at 0 for every peer that lacks SecIdent,
    /// never finishes the challenge, or meets us while our own key is
    /// unavailable. The Known Clients tab fell back to nothing for those and
    /// showed no IP and no flag. This field is what it falls back to instead,
    /// and nothing that scores or trusts a peer reads it.
    pub seen_ip: u32,
    /// Ember node id a non-friend peer advertised, kept once SecIdent proved
    /// the address it came from owns this `user_hash`.
    ///
    /// Display only: it is what keeps an Ember peer on the Known Ember Peers
    /// tab after it leaves the queue or Ember restarts. [`Self::ember_hash`]
    /// is the friend-proven link and is what friend recognition reads; this
    /// never displaces it and nothing that grants, scores or recognises a
    /// peer reads this. Set by [`CreditManager::promote_proven_ember`].
    pub proven_ember_hash: Option<[u8; 16]>,
}

/// Credit record for verified Ember peers.
///
/// Identity is anchored on the peer's 32-byte Ed25519 public key rather
/// than the wire `user_hash` so a peer can't farm credit by cycling
/// user_hash bytes — the credit row is bound to a keypair they must
/// prove possession of via the PoP state machine in `ember_auth.rs`.
/// `ident_verified == true` implies the peer completed full Ed25519
/// proof-of-possession on at least one session; binding-only peers
/// (older Ember releases that don't ship the AUTH opcodes) still get a
/// record so their activity is tracked.
///
/// The upload queue does not score from this record: every peer is
/// ranked by eMule's formula over the `user_hash` ledger, which every
/// transfer writes as well, so an eMule user is never ranked below an
/// Ember one for the same history. The session counts and the
/// `avg_upload_speed` EWMA are kept as history only.
#[derive(Debug, Clone)]
pub struct EmberCreditRecord {
    pub pub_key: [u8; 32],
    pub uploaded: u64,
    pub downloaded: u64,
    pub last_upload_time: i64,
    pub last_download_time: i64,
    pub completed_sessions: u32,
    pub total_sessions: u32,
    pub avg_upload_speed: u64,
    pub last_seen: i64,
    pub ident_verified: bool,
}

impl EmberCreditRecord {
    pub fn new(pub_key: [u8; 32]) -> Self {
        Self {
            pub_key,
            uploaded: 0,
            downloaded: 0,
            last_upload_time: 0,
            last_download_time: 0,
            completed_sessions: 0,
            total_sessions: 0,
            avg_upload_speed: 0,
            last_seen: chrono::Utc::now().timestamp(),
            ident_verified: false,
        }
    }

    /// Apply a new session-observation to the EWMA. Ignores sessions
    /// too short to produce a useful speed sample (handshake noise
    /// dominates). The first real sample seeds the EWMA rather than
    /// being smoothed with the 0 default — that way a fresh record
    /// reflects what we actually measured rather than half-mixing
    /// with a zero.
    pub fn record_session(&mut self, bytes_transferred: u64, duration_secs: u64, completed: bool) {
        self.total_sessions = self.total_sessions.saturating_add(1);
        if completed {
            self.completed_sessions = self.completed_sessions.saturating_add(1);
        }
        if duration_secs >= EMBER_MIN_SESSION_SECS_FOR_SPEED && bytes_transferred > 0 {
            let sample = (bytes_transferred as f64) / (duration_secs as f64);
            let new_avg = if self.avg_upload_speed == 0 {
                sample
            } else {
                EMBER_SPEED_EWMA_ALPHA * sample
                    + (1.0 - EMBER_SPEED_EWMA_ALPHA) * (self.avg_upload_speed as f64)
            };
            self.avg_upload_speed = new_avg.round().max(0.0) as u64;
        }
        self.last_seen = chrono::Utc::now().timestamp();
    }
}

impl CreditRecord {
    pub fn new(user_hash: [u8; 16]) -> Self {
        Self {
            user_hash,
            uploaded: 0,
            downloaded: 0,
            last_seen: chrono::Utc::now().timestamp(),
            public_key: Vec::new(),
            ident_state: IdentState::Unknown,
            ident_ip: 0,
            ember_hash: None,
            crypto_verified_once: false,
            peer_name: String::new(),
            client_software: String::new(),
            seen_ip: 0,
            proven_ember_hash: None,
        }
    }
}

/// SecIdent credit tracker.
///
/// ## Cryptographic threat model
///
/// SecIdent is **wire-compatible with eMule 0.50a**, and therefore uses the
/// same parameters as the rest of the ecosystem:
///
/// - **RSA keys are 384 bits.** By modern standards this is well below the
///   2048-bit minimum for strong signing keys. A motivated attacker with
///   significant compute could potentially factor a captured public key and
///   forge signatures, spoofing another peer's credit identity.
/// - **Signatures use SHA-1** over the challenge material. SHA-1 is broken
///   for collision resistance but only second-preimage attacks would matter
///   here (signing a specific challenge); those are still infeasible.
/// - **Keys are reused across sessions** (persisted in `cryptkey.dat`). Loss
///   of the key file silently forfeits accumulated credits; access to the
///   file lets anyone impersonate this node.
///
/// The practical impact is limited by what credits actually buy: upload
/// queue priority in eMule-family clients. Forged SecIdent cannot read
/// another peer's shared files, downgrade our own transfers, or intercept
/// content — it can only let an attacker reap the slot advantage the
/// legitimate peer built up.
///
/// We accept these parameters because:
/// 1. Raising the key size or hash would break interop with every eMule
///    peer we participate with — the whole point of this feature is the
///    shared network-wide credit ledger.
/// 2. The stronger security property ("no one downloads our files without
///    paying") is provided by the upload slot / queue rules, not by
///    SecIdent itself.
///
/// Do **not** rely on SecIdent for any property stronger than "this peer
/// has the same cryptkey file it had last time". Everything that actually
/// matters for file integrity is covered by MD4 part hashes and AICH.
///
/// ## The Ember fence
///
/// What keeps the weak parameters above tolerable is that **no Ember-side
/// grant reads a [`CreditRecord`]**. Upload queue position does, for every
/// peer alike, because it is eMule's rule and an eD2K grant; friend-level
/// access is gated on `friend_connect::perform_ember_auth`, a signature
/// round-trip over a fresh nonce. Forging a 384-bit RSA identity buys eD2K
/// queue priority and nothing on the overlay.
///
/// The one place the two identity spaces meet is the `user_hash ↔ ember_hash`
/// binding ([`Self::set_ember_hash`] and its two lookups), and it is not a way
/// through: it only decides whether *we* try to escalate one of our own
/// downloads to a friend transfer, and that attempt is authenticated on
/// connect like any other. The binding steers our outbound behaviour; it never
/// grants an inbound peer anything.
///
/// Keep it that way. If a future Ember decision needs a reputation input, take
/// it from [`EmberCreditRecord`] — reaching across to the eD2K ledger would
/// put overlay trust behind a 384-bit key, which is the one thing this
/// threat model does not cover.
#[derive(ZeroizeOnDrop)]
pub struct CreditManager {
    #[zeroize(skip)]
    credits: HashMap<[u8; 16], CreditRecord>,
    /// Enhanced credit records for Ember peers, keyed on Ed25519
    /// public key. Parallel to `credits` rather than sharing storage
    /// because the key material is different (32-byte pubkey vs.
    /// 16-byte user_hash) and the scoring formula is different
    /// (decay + reliability + speed factors, not just bytes).
    /// Only populated for peers that have either passed binding
    /// verification or full PoP on at least one session.
    #[zeroize(skip)]
    ember_credits: HashMap<[u8; 32], EmberCreditRecord>,
    #[zeroize(skip)]
    credit_seen: LastSeenIndex<[u8; 16]>,
    #[zeroize(skip)]
    ember_seen: LastSeenIndex<[u8; 32]>,
    /// eD2K user hash → Ember hash learned from an offline binding check on a
    /// session that was not Noise-authenticated, with the IPv4 that session
    /// came from. Anyone can mint a keypair that passes binding and pair it
    /// with a public user hash, so these are never persisted and never
    /// displace [`CreditRecord::ember_hash`]; one only reaches
    /// [`CreditRecord::proven_ember_hash`] once SecIdent verifies that same
    /// address.
    #[zeroize(skip)]
    bound_ember_hashes: HashMap<[u8; 16], ([u8; 16], u32)>,
    #[zeroize(skip)]
    our_public_key: Vec<u8>,
    our_private_key: Vec<u8>,
    #[zeroize(skip)]
    crypto_available: bool,
    /// True when cryptkey.dat exists but could not be used (undecryptable or
    /// corrupt). Distinct from first-run "never had RSA": the permissive
    /// credit path must not run, or a stolen/unreadable key would silently
    /// grant credits to unverified peers.
    #[zeroize(skip)]
    crypto_unreadable: bool,
    /// Whether anything has changed since the last successful flush.
    ///
    /// Persisting credits is expensive — a SQLite transaction, an
    /// `incremental_vacuum`, and a full `clients.met` rewrite with an
    /// fsync — and the 60s flush timer used to pay all of it unconditionally,
    /// rewriting identical bytes ~1,440 times a day on a node whose peers had
    /// gone quiet. Mirrors the `KnownFileList` dirty/generation pair so an
    /// edit landing *during* a flush is not mistaken for one the flush covered.
    #[zeroize(skip)]
    dirty: bool,
    #[zeroize(skip)]
    dirty_generation: u64,
    /// Keys whose SQLite row may differ from memory: created, mutated, or
    /// evicted since they were last handed to a flush. A key absent from its
    /// map at flush time is a row to delete.
    #[zeroize(skip)]
    unsaved_credit_keys: HashSet<[u8; 16]>,
    #[zeroize(skip)]
    unsaved_ember_keys: HashSet<[u8; 32]>,
    /// Keys handed to a flush that has not confirmed success. They stay here
    /// until [`Self::finish_flush`], so a failed, panicked or aborted flush is
    /// retried by the next one instead of dropping the rows.
    #[zeroize(skip)]
    in_flight_credit_keys: HashSet<[u8; 16]>,
    #[zeroize(skip)]
    in_flight_ember_keys: HashSet<[u8; 32]>,
    /// Until one flush has succeeded, which rows on disk match memory is
    /// unknown: startup may have loaded from SQLite or fallen back to
    /// `clients.met`. The first flush reconciles the whole table against
    /// SQLite instead of upserting every key, which is why the loaders
    /// (`insert_loaded_credit`) mark nothing.
    #[zeroize(skip)]
    needs_full_sync: bool,
    /// Bumped by every [`Self::begin_flush`]; see [`Self::finish_flush`].
    #[zeroize(skip)]
    flush_epoch: u64,
}

/// What the next credit flush must write, from [`CreditManager::begin_flush`].
///
/// With `full_sync` the key lists are empty and the caller reconciles every
/// record. Otherwise each key is either upserted (still in the map) or
/// deleted (gone from it).
#[derive(Debug, Default)]
pub struct CreditFlushKeys {
    pub full_sync: bool,
    pub credit_keys: Vec<[u8; 16]>,
    pub ember_keys: Vec<[u8; 32]>,
    epoch: u64,
}

impl CreditFlushKeys {
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        !self.full_sync && self.credit_keys.is_empty() && self.ember_keys.is_empty()
    }
}

impl CreditManager {
    pub fn new() -> Self {
        Self {
            credits: HashMap::new(),
            ember_credits: HashMap::new(),
            credit_seen: LastSeenIndex::default(),
            ember_seen: LastSeenIndex::default(),
            bound_ember_hashes: HashMap::new(),
            our_public_key: Vec::new(),
            our_private_key: Vec::new(),
            crypto_available: false,
            crypto_unreadable: false,
            dirty: false,
            dirty_generation: 0,
            unsaved_credit_keys: HashSet::new(),
            unsaved_ember_keys: HashSet::new(),
            in_flight_credit_keys: HashSet::new(),
            in_flight_ember_keys: HashSet::new(),
            needs_full_sync: true,
            flush_epoch: 0,
        }
    }

    /// Mark the in-memory credit state as needing a flush.
    ///
    /// Reached (through `mark_credit_unsaved` / `mark_ember_unsaved`, which
    /// also record the key) from `get_or_create` / `get_or_create_ember` — the
    /// only two methods that hand out `&mut` to a record, and therefore the choke point
    /// every mutating operation (`add_uploaded`, `set_public_key`,
    /// `set_ident_state`, `record_ember_session`, …) already routes through.
    /// Deliberately over-approximates: a caller that takes `&mut` and changes
    /// nothing still marks dirty. An extra flush is cheap; a missed one loses
    /// the user's accumulated upload credit.
    fn touch_dirty(&mut self) {
        self.dirty = true;
        self.dirty_generation = self.dirty_generation.saturating_add(1);
    }

    /// True when a flush would persist something not already on disk.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Generation to hand back to [`Self::mark_saved_if_generation`] after a
    /// successful flush. Captured before the flush starts.
    pub fn dirty_generation(&self) -> u64 {
        self.dirty_generation
    }

    /// Clear the dirty flag only if nothing was modified since `generation`
    /// was taken. A mutation that lands mid-flush leaves the flag set, so the
    /// next tick persists it rather than dropping it on the floor.
    pub fn mark_saved_if_generation(&mut self, generation: u64) {
        if self.dirty_generation == generation {
            self.dirty = false;
        }
    }

    fn mark_credit_unsaved(&mut self, user_hash: [u8; 16]) {
        self.unsaved_credit_keys.insert(user_hash);
        self.touch_dirty();
    }

    fn mark_ember_unsaved(&mut self, pub_key: [u8; 32]) {
        self.unsaved_ember_keys.insert(pub_key);
        self.touch_dirty();
    }

    /// Hand the rows the next flush must write to the caller, which snapshots
    /// them under the same lock. Keys from an earlier flush that never
    /// reported success are included again.
    pub fn begin_flush(&mut self) -> CreditFlushKeys {
        self.in_flight_credit_keys
            .extend(self.unsaved_credit_keys.drain());
        self.in_flight_ember_keys
            .extend(self.unsaved_ember_keys.drain());
        self.flush_epoch = self.flush_epoch.wrapping_add(1);
        if self.needs_full_sync {
            return CreditFlushKeys {
                full_sync: true,
                epoch: self.flush_epoch,
                ..CreditFlushKeys::default()
            };
        }
        CreditFlushKeys {
            full_sync: false,
            credit_keys: self.in_flight_credit_keys.iter().copied().collect(),
            ember_keys: self.in_flight_ember_keys.iter().copied().collect(),
            epoch: self.flush_epoch,
        }
    }

    /// The flush that `keys` came from reached SQLite. Edits made since its
    /// [`Self::begin_flush`] are in the unsaved sets and are not affected.
    pub fn finish_flush(&mut self, keys: &CreditFlushKeys) {
        // A later `begin_flush` merged everything in flight into its own
        // batch, and the in-flight sets are that batch's only retry record.
        // Clearing them (or `needs_full_sync`) here would lose those keys if
        // the later flush then fails, so only the latest flush settles them.
        if keys.epoch != self.flush_epoch {
            return;
        }
        self.in_flight_credit_keys.clear();
        self.in_flight_ember_keys.clear();
        if keys.full_sync {
            self.needs_full_sync = false;
        }
    }

    /// Load or generate the RSA keypair for secure identification.
    /// eMule persists this in cryptkey.dat; we use a data_dir file.
    pub fn load_or_create_keypair(&mut self, data_dir: &std::path::Path) {
        let key_path = data_dir.join("cryptkey.dat");
        // A crash inside `atomic_write`'s Windows replace-fallback can leave the
        // only copy under `cryptkey.dat.ember-replace-bak`. Treating that as a
        // first run would mint a new SecIdent key and then `atomic_write` would
        // restore the bak only to overwrite it with the replacement.
        crate::security::recover_interrupted_replace(&key_path);
        // A read failure is NOT "no file yet". `cryptkey.dat` can be present
        // and intact but momentarily unreadable — an antivirus or backup agent
        // holding it open produces `ERROR_SHARING_VIOLATION` on Windows and
        // `EACCES` elsewhere, the same causes `identity.rs` names. Treating
        // that as a first run fell through to `generate_rsa_keypair` and
        // atomically overwrote the real keypair with no backup, permanently
        // destroying the SecIdent identity and every credit balance peers hold
        // against it. Only a genuine absence may mint a key; anything else
        // fails closed for the session exactly as the undecryptable and
        // corrupt paths below do.
        let existing = match std::fs::read(&key_path) {
            Ok(raw) => Some(raw),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // The recover above restores a parked backup whenever the
                // destination is absent, so one still sitting here means that
                // restore failed. The keypair exists and is only unreachable,
                // which is the unreadable case below rather than a first run.
                if crate::security::interrupted_replace_backup_exists(&key_path) {
                    tracing::error!(
                        "cryptkey.dat is missing but an interrupted replace parked a copy that \
                         could not be restored; leaving SecIdent disabled this session and NOT \
                         regenerating (restore cryptkey.dat.ember-replace-bak to recover the \
                         keypair and the credits peers hold against it)"
                    );
                    self.crypto_available = false;
                    self.crypto_unreadable = true;
                    return;
                }
                None
            }
            Err(e) => {
                tracing::error!(
                    "cryptkey.dat exists but could not be read ({e}); leaving SecIdent \
                     disabled this session and NOT regenerating (the keypair is intact \
                     and will load once whatever holds the file releases it)"
                );
                self.crypto_available = false;
                self.crypto_unreadable = true;
                return;
            }
        };
        if let Some(raw) = existing {
            let was_protected = crate::storage::secret_store::is_protected(&raw);
            // Unwrap DPAPI at-rest protection; legacy plaintext passes through
            // unchanged. `unprotect` only returns Err when the file carries
            // the DPAPI magic but cannot be decrypted (wrong Windows user,
            // transient DPAPI failure, file copied from another machine).
            // That is NOT corruption, so we fail CLOSED: back the file up,
            // leave SecIdent disabled for this session, and return WITHOUT
            // regenerating. Regenerating here would permanently destroy a
            // recoverable keypair (the old behavior). Mirrors identity.rs.
            let data = match crate::storage::secret_store::unprotect(&raw) {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!(
                        "cryptkey.dat is protected but could not be decrypted ({e}); \
                         leaving SecIdent disabled this session and NOT regenerating \
                         (the keypair may be recoverable on the correct account, or on \
                         Linux once the login keyring is unlocked)"
                    );
                    let backup = key_path.with_extension("dat.undecryptable");
                    let _ = std::fs::copy(&key_path, &backup);
                    self.crypto_available = false;
                    self.crypto_unreadable = true;
                    return;
                }
            };
            if data.len() >= 8 {
                let pub_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
                // checked_add guards a 32-bit-usize overflow where a crafted
                // pub_len near usize::MAX could wrap past the length check.
                if pub_len.checked_add(8).is_some_and(|min| data.len() >= min) {
                    let pub_key = data[4..4 + pub_len].to_vec();
                    let priv_off = 4 + pub_len;
                    let priv_len = u32::from_le_bytes([
                        data[priv_off],
                        data[priv_off + 1],
                        data[priv_off + 2],
                        data[priv_off + 3],
                    ]) as usize;
                    let priv_end = priv_off
                        .checked_add(4)
                        .and_then(|o| o.checked_add(priv_len));
                    if priv_end.is_some_and(|end| data.len() >= end) {
                        let priv_key = data[priv_off + 4..priv_off + 4 + priv_len].to_vec();
                        if !pub_key.is_empty() && !priv_key.is_empty() {
                            // Normalise legacy PKCS#1 public keys from older
                            // Ember builds to SPKI so peers' X509PublicKey
                            // decoders accept them (see
                            // `normalize_public_key_to_spki` and
                            // `generate_rsa_keypair` for why this matters).
                            // If re-encoding changes the bytes, rewrite the
                            // keyfile atomically so the next launch starts
                            // clean.
                            let (final_pub, migrated) = match normalize_public_key_to_spki(&pub_key)
                            {
                                Some(n) => {
                                    let migrated = n != pub_key;
                                    (n, migrated)
                                }
                                None => (pub_key.clone(), false),
                            };
                            self.our_public_key = final_pub;
                            self.our_private_key = priv_key;
                            self.crypto_available = true;
                            self.crypto_unreadable = false;
                            tracing::info!("Loaded RSA keypair from {}", key_path.display());
                            // Rewrite when the public key was SPKI-normalised,
                            // the file was still legacy plaintext (so it gets
                            // wrapped with at-rest protection), or it is wrapped
                            // under a superseded scheme — a Unix
                            // `EMBRSEC2`/`EMBRSEC3` blob is keyed by `$USER` and
                            // only stops depending on that once rewritten.
                            if migrated
                                || !was_protected
                                || crate::storage::secret_store::needs_rewrap(&raw)
                            {
                                let mut out = Vec::new();
                                out.extend_from_slice(
                                    &(self.our_public_key.len() as u32).to_le_bytes(),
                                );
                                out.extend_from_slice(&self.our_public_key);
                                out.extend_from_slice(
                                    &(self.our_private_key.len() as u32).to_le_bytes(),
                                );
                                out.extend_from_slice(&self.our_private_key);
                                match crate::storage::secret_store::protect(&out) {
                                    Ok(protected) => {
                                        if let Err(e) = crate::security::atomic_write(
                                            &key_path, &protected, true,
                                        ) {
                                            tracing::warn!(
                                                "Failed to persist protected/normalised keypair: {e}"
                                            );
                                        } else if migrated {
                                            tracing::info!(
                                                "Migrated cryptkey.dat public key from PKCS#1 to SPKI"
                                            );
                                        }
                                    }
                                    Err(e) => tracing::error!("Not persisting cryptkey.dat: {e}"),
                                }
                            }
                            return;
                        }
                    }
                }
            }
            // An eMule or aMule `cryptkey.dat` copied in by someone moving
            // over. It is the identity peers hold that user's credits against,
            // so adopting it is the point; calling it corrupt left SecIdent off
            // for good (issue 126).
            if !was_protected {
                if let Some((public, private)) = decode_emule_cryptkey(&data) {
                    let original = key_path.with_extension("dat.emule");
                    if std::fs::copy(&key_path, &original).is_ok() {
                        crate::security::restrict_file_permissions(&original);
                    }
                    let rewritten = encode_keypair_file(&public, &private).and_then(|bytes| {
                        crate::security::atomic_write(&key_path, &bytes, true)
                            .map_err(anyhow::Error::from)
                    });
                    match rewritten {
                        Ok(()) => tracing::info!(
                            "Adopted an eMule-format cryptkey.dat; the original is kept as cryptkey.dat.emule"
                        ),
                        Err(e) => tracing::warn!(
                            "Adopted an eMule-format cryptkey.dat for this session but could not rewrite it: {e}"
                        ),
                    }
                    self.our_public_key = public;
                    self.our_private_key = private;
                    self.crypto_available = true;
                    self.crypto_unreadable = false;
                    return;
                }
            }
            let backup = key_path.with_extension(format!(
                "dat.{}.corrupt",
                chrono::Utc::now().format("%Y%m%d%H%M%S")
            ));
            if let Err(e) = std::fs::copy(&key_path, &backup) {
                tracing::warn!("Failed to preserve corrupt cryptkey.dat: {e}");
            } else {
                crate::security::restrict_file_permissions(&backup);
            }
            tracing::error!(
                "cryptkey.dat is corrupt; SecIdent remains disabled and the keypair was NOT regenerated"
            );
            self.crypto_available = false;
            self.crypto_unreadable = true;
            return;
        }

        let (public_key, private_key) = generate_rsa_keypair();
        self.our_public_key = public_key;
        self.our_private_key = private_key;
        self.crypto_available = !self.our_public_key.is_empty();
        self.crypto_unreadable = false;

        if !self.our_public_key.is_empty() {
            let mut out = Vec::new();
            out.extend_from_slice(&(self.our_public_key.len() as u32).to_le_bytes());
            out.extend_from_slice(&self.our_public_key);
            out.extend_from_slice(&(self.our_private_key.len() as u32).to_le_bytes());
            out.extend_from_slice(&self.our_private_key);
            match crate::storage::secret_store::protect(&out) {
                Ok(protected) => match crate::security::atomic_write(&key_path, &protected, true) {
                    Ok(()) => tracing::info!(
                        "Generated and saved new RSA keypair to {}",
                        key_path.display()
                    ),
                    Err(e) => tracing::warn!("Failed to save RSA keypair: {e}"),
                },
                Err(e) => tracing::error!("Not persisting RSA keypair: {e}"),
            }
        }
    }

    pub fn get_or_create(&mut self, user_hash: [u8; 16]) -> &mut CreditRecord {
        // Every mutating credit operation (set_public_key, set_ident_state,
        // check_identity_ip, add_uploaded, add_downloaded) routes through
        // here, so this is the single place to keep `last_seen` honest.
        // Read-only paths (`get_score_ratio`, `get_current_ident_state`,
        // `secident_request_state`, `verify_signature`) use
        // `self.credits.get(...)` and therefore do NOT bump the timestamp,
        // which is correct — those are just queries, not "we saw them now"
        // events.
        //
        // Without this bump, `last_seen` was only ever advanced by
        // `add_uploaded` / `add_downloaded`. Peers that connected, did a
        // partial handshake, and never transferred bytes (Unknown / Failed
        // / Needed states) kept their creation-time `last_seen` forever,
        // so the 90-day `cleanup_stale` sweep evicted them by *first
        // contact* age rather than *last contact* age — visible in the
        // Known Clients tab as months-old "Unknown" rows for peers we
        // actually still talked to recently.
        let now = chrono::Utc::now().timestamp();
        // Backstop the table size before inserting a brand-new record (see
        // MAX_CREDIT_RECORDS): when full, evict the least-recently-seen entry.
        // Only runs on genuine inserts — updating an existing record can't grow
        // the map, so it never evicts.
        self.make_room_for_credit(&user_hash);
        // Before handing out `&mut`: the caller may mutate any field, and once
        // `record` is borrowed from `self` we can no longer touch the flag.
        self.mark_credit_unsaved(user_hash);
        self.credit_seen.set(user_hash, now);
        let record = self
            .credits
            .entry(user_hash)
            .or_insert_with(|| CreditRecord::new(user_hash));
        record.last_seen = now;
        record
    }

    fn make_room_for_credit(&mut self, incoming: &[u8; 16]) {
        if self.credits.contains_key(incoming) || self.credits.len() < MAX_CREDIT_RECORDS {
            return;
        }
        if let Some(oldest) = self.credit_seen.oldest(&self.credits, |r| r.last_seen) {
            self.credits.remove(&oldest);
            self.credit_seen.remove(&oldest);
            self.mark_credit_unsaved(oldest);
        }
    }

    /// Adopt a record read from storage exactly as stored, indexed at its
    /// persisted `last_seen`.
    ///
    /// Unlike [`Self::get_or_create`] this neither bumps `last_seen` nor marks
    /// the row for rewrite: it already matches disk, and the first flush
    /// reconciles the whole table anyway (`needs_full_sync`). Past
    /// `MAX_CREDIT_RECORDS` the least-recently-seen record by stored age —
    /// possibly this one — is dropped and queued for deletion, so a store
    /// that outgrew the cap keeps its most recent peers.
    pub fn insert_loaded_credit(&mut self, record: CreditRecord) {
        let user_hash = record.user_hash;
        if let Some(existing) = self.credits.get_mut(&user_hash) {
            self.credit_seen.set(user_hash, record.last_seen);
            *existing = record;
            return;
        }
        if self.credits.len() >= MAX_CREDIT_RECORDS {
            if let Some(oldest) = self.credit_seen.oldest(&self.credits, |r| r.last_seen) {
                let oldest_seen = self.credits.get(&oldest).map_or(i64::MAX, |r| r.last_seen);
                if record.last_seen <= oldest_seen {
                    self.mark_credit_unsaved(user_hash);
                    return;
                }
                self.credits.remove(&oldest);
                self.credit_seen.remove(&oldest);
                self.mark_credit_unsaved(oldest);
            }
        }
        self.credit_seen.set(user_hash, record.last_seen);
        self.credits.insert(user_hash, record);
    }

    /// Ember counterpart of [`Self::insert_loaded_credit`].
    pub fn insert_loaded_ember_credit(&mut self, record: EmberCreditRecord) {
        let pub_key = record.pub_key;
        if let Some(existing) = self.ember_credits.get_mut(&pub_key) {
            self.ember_seen.set(pub_key, record.last_seen);
            *existing = record;
            return;
        }
        if self.ember_credits.len() >= MAX_CREDIT_RECORDS {
            if let Some(oldest) = self.ember_seen.oldest(&self.ember_credits, |r| r.last_seen) {
                let oldest_seen = self
                    .ember_credits
                    .get(&oldest)
                    .map_or(i64::MAX, |r| r.last_seen);
                if record.last_seen <= oldest_seen {
                    self.mark_ember_unsaved(pub_key);
                    return;
                }
                self.ember_credits.remove(&oldest);
                self.ember_seen.remove(&oldest);
                self.mark_ember_unsaved(oldest);
            }
        }
        self.ember_seen.set(pub_key, record.last_seen);
        self.ember_credits.insert(pub_key, record);
    }

    /// Remember what a peer calls itself and what it runs.
    ///
    /// Both strings come from `PeerCapabilities`, which is the only place
    /// either exists. Neither is trusted for anything — they are peer-supplied
    /// display text, and the Known eD2K Peers tab renders them as such — so
    /// this deliberately records them without validation beyond a length
    /// bound.
    ///
    /// Called from both directions, but not symmetrically. The upload handler
    /// calls it *at* the handshake, because a peer that only ever asks us for
    /// files may never transfer a byte and still deserves a name. The download
    /// side calls it when a part verifies, alongside `add_downloaded`: its
    /// seven connect paths have all converged on one pair of variables by
    /// then, and the lock is already held.
    ///
    /// An empty argument leaves the stored value alone. A client that sends
    /// `CT_NAME` on its first handshake and omits it on a later one is
    /// common, and treating the omission as "my name is now blank" would lose
    /// the name for exactly the peers we talk to most.
    ///
    /// `peer_ip` is the address of the session this came from, recorded as
    /// [`CreditRecord::seen_ip`]. Unlike the strings it always replaces the
    /// stored value: a peer on a dynamic address should show where it is now.
    pub fn note_client_identity(
        &mut self,
        user_hash: [u8; 16],
        peer_ip: Option<std::net::IpAddr>,
        peer_name: &str,
        client_software: &str,
    ) {
        let seen_ip = peer_ip
            .and_then(|ip| match ip {
                std::net::IpAddr::V4(v4) => Some(v4),
                std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
            })
            .filter(|v4| !v4.is_unspecified())
            .map(|v4| u32::from_be_bytes(v4.octets()));
        if user_hash == [0u8; 16]
            || (peer_name.is_empty() && client_software.is_empty() && seen_ip.is_none())
        {
            return;
        }
        let record = self.get_or_create(user_hash);
        if !peer_name.is_empty() {
            record.peer_name = truncate_identity(peer_name);
        }
        if !client_software.is_empty() {
            record.client_software = truncate_identity(client_software);
        }
        if let Some(ip) = seen_ip {
            record.seen_ip = ip;
        }
    }

    /// Accumulate upload credit, unless the peer's identity state forbids it —
    /// see [`Self::credit_accepted`] for which states those are and why.
    /// Returns false if the accrual was rejected.
    ///
    /// `current_ip` is the peer's live IPv4 as a big-endian `u32` (`0` when
    /// unknown), judged like eMule's `AddUploaded(bytes, dwForIP)`.
    pub fn add_uploaded(&mut self, user_hash: [u8; 16], current_ip: u32, bytes: u64) -> bool {
        if !self.credit_accepted(&user_hash, current_ip) {
            return false;
        }
        let record = self.get_or_create(user_hash);
        record.uploaded = record.uploaded.saturating_add(bytes);
        // `last_seen` already bumped by `get_or_create` above.
        true
    }

    /// `current_ip` as for [`Self::add_uploaded`]; see [`credit_ip`].
    pub fn add_downloaded(&mut self, user_hash: [u8; 16], current_ip: u32, bytes: u64) -> bool {
        if !self.credit_accepted(&user_hash, current_ip) {
            return false;
        }
        let record = self.get_or_create(user_hash);
        record.downloaded = record.downloaded.saturating_add(bytes);
        // `last_seen` already bumped by `get_or_create` above.
        true
    }

    /// Whether a credit accrual for `user_hash` is allowed.
    ///
    /// Mirrors eMule's rule, which rejects exactly three states and only when
    /// crypto is available: `IS_IDFAILED`, `IS_IDBADGUY` and `IS_IDNEEDED`
    /// (`ClientCredits.cpp:55-85`). `IS_NOTAVAILABLE` — a peer that has never
    /// advertised a public key, which is [`IdentState::Unknown`] here — falls
    /// through and accrues normally.
    ///
    /// This used to demand `Verified` whenever crypto was available, which meant
    /// a peer that does not do SecIdent at all could never accumulate
    /// `downloaded`. Its ratio was then pinned at `MIN_CREDIT_RATIO` forever, so
    /// its queue score could never rise and the soft-zone gate refused it
    /// once the queue filled — a peer permanently denied the standing its
    /// uploads had earned.
    ///
    /// Framing it as anti-farming did not hold up either: `add_uploaded` records
    /// bytes that *lower* a peer's ratio, and `add_downloaded` only counts bytes
    /// the peer actually sent us. Rotating user hashes to dodge either one just
    /// resets the peer to neutral, which is worse for it than keeping its record.
    /// What hash rotation can still do is grow the map, and that is bounded
    /// where it should be — by `MAX_CREDIT_RECORDS` and the sweep — rather than
    /// by refusing honest peers credit.
    ///
    /// Still judged from the *existing* record without creating one, so the
    /// rejected states cannot seed an entry per rotated hash. The state is the
    /// IP-aware one, so a verified hash replayed from another address is
    /// `BadGuy` here too.
    fn credit_accepted(&self, user_hash: &[u8; 16], current_ip: u32) -> bool {
        if self.crypto_unreadable {
            return false;
        }
        let ident_state = self.get_current_ident_state(user_hash, current_ip);
        let rejected = if self.crypto_available {
            matches!(
                ident_state,
                IdentState::Failed | IdentState::BadGuy | IdentState::Needed
            )
        } else {
            // No local key, so `Needed` is a state we can never resolve and must
            // not punish; eMule likewise skips the whole check when
            // `CryptoAvailable()` is false.
            matches!(ident_state, IdentState::Failed | IdentState::BadGuy)
        };
        !rejected
    }

    pub fn crypto_unreadable(&self) -> bool {
        self.crypto_unreadable
    }

    /// `"available"` | `"unavailable"` | `"broken"` for `NetworkStats`.
    pub fn secident_status(&self) -> &'static str {
        if self.crypto_unreadable {
            "broken"
        } else if self.crypto_available {
            "available"
        } else {
            "unavailable"
        }
    }

    /// eMule IS_IDBADGUY: pin the address a verified identity was last proven
    /// from, so `get_current_ident_state` can flag a replay from somewhere
    /// else without mutating the stored state.
    ///
    /// The pin is refreshed on every successful verification, not only the
    /// first. Its sole caller runs immediately after `verify_signature`
    /// succeeds, so the peer has just proved possession of the key bound to
    /// this hash from `current_ip` — there is nothing left to be suspicious
    /// of. Writing only when `ident_ip == 0` meant a peer on a dynamic
    /// address was re-challenged (`secident_request_state` deliberately
    /// re-asks when the IP moved), passed, and then had the result thrown
    /// away: the stale pin kept it `BadGuy` forever, which zeroes its queue
    /// score and can refuse it a slot outright once the queue is busy.
    pub fn check_identity_ip(&mut self, user_hash: [u8; 16], current_ip: u32) {
        let record = self.get_or_create(user_hash);
        if record.ident_state == IdentState::Verified {
            record.ident_ip = current_ip;
        }
        self.promote_proven_ember(user_hash);
    }

    /// eMule CClientCredits::GetCurrentIdentState(dwForIP): returns BadGuy
    /// dynamically when a verified client's IP doesn't match, without mutating
    /// the stored ident_state.
    pub fn get_current_ident_state(&self, user_hash: &[u8; 16], current_ip: u32) -> IdentState {
        match self.credits.get(user_hash) {
            Some(record) => {
                // Only flag BadGuy when we have a CURRENT IP to compare against.
                // `current_ip == 0` means the caller doesn't know the peer's
                // live address (e.g. a disconnected/queued LowID peer in a UI
                // snapshot, or a peer awaiting callback). With no current IP we
                // can't conclude the verified identity moved, so fall back to the
                // stored state instead of spuriously labelling a verified peer a
                // BadGuy (which also wrongly floored their credit ratio).
                if record.ident_state == IdentState::Verified
                    && record.ident_ip != 0
                    && current_ip != 0
                    && record.ident_ip != current_ip
                {
                    IdentState::BadGuy
                } else {
                    record.ident_state
                }
            }
            None => IdentState::Unknown,
        }
    }

    /// eMule credit ratio formula from CClientCredits::GetScoreRatio.
    /// Returns 1.0 for `Failed` / `BadGuy` / `Needed` when crypto is available
    /// (`IS_IDFAILED` / `IS_IDBADGUY` / `IS_IDNEEDED`). `Unknown`
    /// (`IS_NOTAVAILABLE`) is floored only when the peer advertised a SecIdent
    /// public key and then failed to complete the exchange.
    pub fn get_score_ratio(&self, user_hash: &[u8; 16], current_ip: u32) -> f64 {
        let record = match self.credits.get(user_hash) {
            Some(r) => r,
            None => return MIN_CREDIT_RATIO,
        };
        let ident = self.get_current_ident_state(user_hash, current_ip);
        if self.crypto_unreadable {
            return MIN_CREDIT_RATIO;
        }
        if self.crypto_available {
            let floor = match ident {
                IdentState::Failed | IdentState::BadGuy | IdentState::Needed => true,
                IdentState::Unknown => !record.public_key.is_empty(),
                IdentState::Verified => false,
            };
            if floor {
                return MIN_CREDIT_RATIO;
            }
        }

        // eMule: if downloaded < 1MB, return 1.0 (no credits for trivial transfers)
        if record.downloaded < 1_048_576 {
            return MIN_CREDIT_RATIO;
        }

        let uploaded = record.uploaded.max(1) as f64;
        let downloaded = record.downloaded as f64;

        let ratio1 = (downloaded * 2.0) / uploaded;
        let ratio2 = (downloaded / 1_048_576.0 + 2.0).sqrt();
        // eMule result3: linear ramp from 1.0 at 1 MB to 3.34 at ~9.2 MB, then 10.0
        let ratio3 = if downloaded < 9_646_899.0 {
            (downloaded - 1_048_576.0) / 8_598_323.0 * 2.34 + 1.0
        } else {
            MAX_CREDIT_RATIO
        };

        ratio1
            .min(ratio2)
            .min(ratio3)
            .clamp(MIN_CREDIT_RATIO, MAX_CREDIT_RATIO)
    }

    /// Queue score for upload slot selection.
    /// Matches eMule CUpDownClient::GetScore: wait_seconds * credit_ratio * (file_prio / 10)
    pub fn get_queue_score(
        &self,
        user_hash: &[u8; 16],
        wait_secs: u64,
        file_priority: f64,
        current_ip: u32,
    ) -> f64 {
        let ident = self.get_current_ident_state(user_hash, current_ip);
        if matches!(ident, IdentState::BadGuy) {
            return 0.0;
        }
        let ratio = self.get_score_ratio(user_hash, current_ip);
        let wait = wait_secs as f64;
        wait * ratio * file_priority
    }

    pub fn our_public_key(&self) -> &[u8] {
        &self.our_public_key
    }

    pub fn secident_request_state(
        &self,
        user_hash: &[u8; 16],
        current_ip: u32,
        peer_level: u8,
    ) -> Option<u8> {
        if !self.crypto_available {
            return None;
        }
        if peer_level == 0 {
            return None;
        }
        match self.credits.get(user_hash) {
            // `ident_ip == current_ip` alone isn't enough when both are `0`
            // (e.g. LowID peers or a stale record from a legacy clients.met
            // that never recorded an IP): that comparison is vacuously true
            // without ever having pinned the identity to a real address, so
            // require both sides to be non-zero before skipping the
            // challenge. Mirrors the same non-zero requirement
            // `get_current_ident_state` uses for its BadGuy comparison.
            Some(record)
                if !record.public_key.is_empty()
                    && record.ident_state == IdentState::Verified
                    && record.ident_ip != 0
                    && current_ip != 0
                    && record.ident_ip == current_ip =>
            {
                None
            }
            Some(record) if !record.public_key.is_empty() => Some(1),
            _ => Some(2),
        }
    }

    pub fn has_public_key(&self, user_hash: &[u8; 16]) -> bool {
        self.credits
            .get(user_hash)
            .map(|r| !r.public_key.is_empty())
            .unwrap_or(false)
    }

    pub fn create_signature_for_peer(
        &self,
        peer_user_hash: &[u8; 16],
        challenge: u32,
        challenge_ip: u32,
        challenge_ip_kind: Option<u8>,
    ) -> Vec<u8> {
        let record = match self.credits.get(peer_user_hash) {
            Some(r) if !r.public_key.is_empty() => r,
            _ => return Vec::new(),
        };
        sign_challenge(
            &self.our_private_key,
            &record.public_key,
            challenge,
            challenge_ip,
            challenge_ip_kind,
        )
    }

    pub fn verify_signature(
        &self,
        user_hash: &[u8; 16],
        challenge: u32,
        challenge_ip_kind: Option<u8>,
        peer_ip: u32,
        local_ip_for_remoteclient: u32,
        signature: &[u8],
    ) -> bool {
        let record = match self.credits.get(user_hash) {
            Some(r) if !r.public_key.is_empty() => r,
            _ => return false,
        };
        verify_challenge(
            &record.public_key,
            &self.our_public_key,
            challenge,
            challenge_ip_kind,
            peer_ip,
            local_ip_for_remoteclient,
            signature,
        )
    }

    /// Bind a peer's RSA public key to their user hash. Returns whether the
    /// key is bound to this hash once the call returns.
    ///
    /// Trust on first use: the first key seen for a hash owns that identity,
    /// and a *different* key arriving later is refused rather than silently
    /// replacing it. Overwriting was a credit-theft primitive — a user hash
    /// travels in the clear in every Hello, so anyone who had seen a peer
    /// could connect claiming that hash, push their own key, and inherit the
    /// balances bound to it. Recovery was impossible: `secident_request_state`
    /// only asks for a key when none is stored, so the genuine peer was never
    /// asked again, its signatures no longer matched, and it was pinned at
    /// `IdentState::Failed` with credit refused from then on.
    ///
    /// The residual limitation is inherent to eD2K: a hash nobody has bound
    /// yet can be claimed by whoever gets there first, and a peer that
    /// genuinely rotates its keypair stays unverified until its record ages
    /// out of `cleanup_stale`. Both are strictly better than handing an
    /// attacker an established identity.
    #[must_use = "a refused key means this peer is not the identity it claims; \
                  callers that go on to trust it are the bug this return exists to catch"]
    pub fn set_public_key(&mut self, user_hash: [u8; 16], key: Vec<u8>) -> bool {
        if key.is_empty() {
            return false;
        }
        if key.len() > 4096 {
            tracing::warn!(
                "Rejecting oversized public key ({} bytes) from {}",
                key.len(),
                crate::security::short_hash(&user_hash)
            );
            return false;
        }
        let record = self.get_or_create(user_hash);
        if record.public_key.is_empty() {
            record.public_key = key;
            return true;
        }
        if record.public_key == key {
            return true;
        }
        tracing::warn!(
            "Refusing a public key that differs from the one already bound to {}; \
             keeping the established identity",
            crate::security::short_hash(&user_hash)
        );
        false
    }

    /// Persist the Ember identity bound to an eD2K `user_hash`. Only for
    /// identities proven on this session (Noise-authenticated friend
    /// sessions); a bare `verify_ember_hash_binding` pass goes through
    /// [`Self::note_bound_ember_hash`] instead. No-op for the all-zero
    /// sentinel hashes. Overwrites a previous binding so a peer that rotated
    /// keys still links correctly.
    pub fn set_ember_hash(&mut self, user_hash: [u8; 16], ember_hash: [u8; 16]) {
        if user_hash == [0u8; 16] || ember_hash == [0u8; 16] {
            return;
        }
        self.bound_ember_hashes.remove(&user_hash);
        let record = self.get_or_create(user_hash);
        record.ember_hash = Some(ember_hash);
    }

    /// [`Self::set_ember_hash`] for a `user_hash` the Ember identity only
    /// *claims*: a Noise session proves the key, but the eD2K hash in its
    /// HELLO is whatever the peer put there. Persists the link only when the
    /// user hash is unbound, already bound to this identity, or bound to one
    /// `replaceable` gives up (one that is no longer a friend, say), so one
    /// friend cannot take over another's hash. `false` when nothing was written.
    pub fn claim_ember_hash(
        &mut self,
        user_hash: [u8; 16],
        ember_hash: [u8; 16],
        replaceable: impl FnOnce([u8; 16]) -> bool,
    ) -> bool {
        if user_hash == [0u8; 16] || ember_hash == [0u8; 16] {
            return false;
        }
        if let Some(bound) = self.credits.get(&user_hash).and_then(|record| record.ember_hash) {
            if bound != ember_hash && !replaceable(bound) {
                return false;
            }
        }
        self.set_ember_hash(user_hash, ember_hash);
        true
    }

    /// The Ember identity persisted for `user_hash`, if any.
    pub fn persisted_ember_hash(&self, user_hash: &[u8; 16]) -> Option<[u8; 16]> {
        self.credits.get(user_hash).and_then(|record| record.ember_hash)
    }

    /// Remember, for this run only, the Ember identity an unauthenticated
    /// session bound to `user_hash` with the offline binding check.
    ///
    /// The binding only proves the pubkey hashes to the Ember hash; it says
    /// nothing about who owns the eD2K user hash, which travels in the clear.
    /// Writing it to the persisted record let anyone with a fresh keypair
    /// claim a friend's user hash and break friend source recognition. A
    /// persisted mapping always wins over this one in the lookups.
    ///
    /// `peer_ip` is the session's IPv4 (big-endian, as `ident_ip`), or 0
    /// when it has none; it is what lets SecIdent later vouch for the link.
    pub fn note_bound_ember_hash(&mut self, user_hash: [u8; 16], ember_hash: [u8; 16], peer_ip: u32) {
        if user_hash == [0u8; 16] || ember_hash == [0u8; 16] {
            return;
        }
        if !self.bound_ember_hashes.contains_key(&user_hash)
            && self.bound_ember_hashes.len() >= MAX_BOUND_EMBER_HASHES
        {
            if let Some(victim) = self.bound_ember_hashes.keys().next().copied() {
                self.bound_ember_hashes.remove(&victim);
            }
        }
        self.bound_ember_hashes.insert(user_hash, (ember_hash, peer_ip));
        self.promote_proven_ember(user_hash);
    }

    /// Put back a stored [`CreditRecord::proven_ember_hash`]. Like
    /// [`Self::insert_loaded_credit`] it leaves `last_seen` and the save
    /// state alone, and a link to a record no longer held is dropped.
    pub fn restore_proven_ember_hash(&mut self, user_hash: [u8; 16], ember_hash: [u8; 16]) {
        if let Some(record) = self.credits.get_mut(&user_hash) {
            record.proven_ember_hash = Some(ember_hash);
        }
    }

    /// A session address as [`CreditRecord::ident_ip`] stores it: big-endian
    /// IPv4, IPv4-mapped IPv6 unwrapped, and 0 for anything else. Shared by
    /// [`Self::note_bound_ember_hash`]'s callers and the SecIdent handler so
    /// the two addresses compare.
    pub fn ident_ip_of(addr: std::net::SocketAddr) -> u32 {
        match addr.ip() {
            std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
            std::net::IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(|v4| u32::from_be_bytes(v4.octets()))
                .unwrap_or(0),
        }
    }

    /// Keep the session's Ember binding for display once SecIdent has proven,
    /// this run, that the address it came from owns `user_hash`.
    ///
    /// The binding shows the client is an Ember node with that key; SecIdent
    /// shows the same address holds the user hash's RSA key. Together the
    /// link is as strong as the rest of the credit row, so it is worth
    /// remembering across sessions — for the Known Ember Peers tab only.
    /// Runs from both ends, since either proof can land first.
    fn promote_proven_ember(&mut self, user_hash: [u8; 16]) {
        let Some(&(ember_hash, bound_ip)) = self.bound_ember_hashes.get(&user_hash) else {
            return;
        };
        let proven = self.credits.get(&user_hash).is_some_and(|record| {
            record.ident_state == IdentState::Verified
                && record.ident_ip != 0
                && record.ident_ip == bound_ip
                && record.proven_ember_hash != Some(ember_hash)
        });
        if proven {
            self.mark_credit_unsaved(user_hash);
            if let Some(record) = self.credits.get_mut(&user_hash) {
                record.proven_ember_hash = Some(ember_hash);
            }
        }
    }

    /// Reverse of [`Self::set_ember_hash`]: find the eD2K `user_hash` we last
    /// bound to this Ember identity. Used to relocate download sources when
    /// friend discovery learns a fresh IP:port.
    pub fn find_user_hash_by_ember(&self, ember_hash: &[u8; 16]) -> Option<[u8; 16]> {
        if *ember_hash == [0u8; 16] {
            return None;
        }
        self.credits
            .iter()
            .find_map(|(user_hash, record)| {
                (record.ember_hash.as_ref() == Some(ember_hash)).then_some(*user_hash)
            })
            .or_else(|| {
                self.bound_ember_hashes
                    .iter()
                    .find_map(|(user_hash, (bound, _))| {
                        let persisted = self
                            .credits
                            .get(user_hash)
                            .and_then(|record| record.ember_hash);
                        (bound == ember_hash && persisted.is_none()).then_some(*user_hash)
                    })
            })
    }

    /// The Ember identity bound to `user_hash`, if we have ever seen one.
    ///
    /// Inverse of [`Self::find_user_hash_by_ember`]. `clients.met` persists this
    /// binding, so it survives a restart — which is what lets a friend source be
    /// recognised as a friend after relaunch, when the in-memory
    /// download-to-friend binding is gone.
    pub fn find_ember_by_user_hash(&self, user_hash: &[u8; 16]) -> Option<[u8; 16]> {
        if *user_hash == [0u8; 16] {
            return None;
        }
        self.credits
            .get(user_hash)
            .and_then(|record| record.ember_hash)
            .or_else(|| self.bound_ember_hashes.get(user_hash).map(|(eh, _)| *eh))
    }

    pub fn set_ident_state(&mut self, user_hash: [u8; 16], state: IdentState) {
        let record = self.get_or_create(user_hash);
        // eMule Verified(): on first-time crypto verification, reset pre-existing
        // credits to prevent credit theft via identity spoofing before crypto
        // was established.
        //
        // "First time" has to mean "these credits were never anchored to a
        // proven key" (`crypto_verified_once`), not "we have never seen a
        // key". Testing `ident_state == Unknown` made this dead code on the
        // whole inbound path: `upload.rs` answers `OP_PUBLICKEY` by binding
        // the key and immediately setting `Needed`, so verification always
        // arrived at `Needed`, never `Unknown` — and `Needed` is persisted in
        // clients.met, so it stayed dead across restarts. A record can hold
        // credits with no key bound (accrued while `crypto_available == false`,
        // or imported from a legacy clients.met), and a user_hash travels in
        // the clear in every Hello, so whoever claims it first gets TOFU'd and
        // would have inherited the victim's totals — and their score
        // multiplier and queue position with it.
        if state == IdentState::Verified
            && !record.crypto_verified_once
            && (record.uploaded > 0 || record.downloaded > 0)
        {
            // Log only the user-hash prefix — the full 16-byte value is PII
            // that can be correlated across sessions. 4 bytes is enough for a
            // developer to correlate with a peer log entry.
            tracing::info!(
                "Resetting credits for peer {}\u{2026} on first SecureIdent verification (was up={} down={})",
                &hex::encode(user_hash)[..8], record.uploaded, record.downloaded
            );
            record.uploaded = 1;
            record.downloaded = 1;
        }
        if state == IdentState::Verified {
            // Sticky, so a peer that later fails a challenge (or that a
            // stranger claiming the same user_hash fails on its behalf) isn't
            // charged the reset a second time when it re-proves itself. It is
            // also persisted (v3 clients.met anchor section), because that
            // failed challenge is remembered as `ident_state = Failed` and
            // deriving the anchor from the state would hand the reset back to
            // the attacker one restart later.
            record.crypto_verified_once = true;
        }
        record.ident_state = state;
    }

    pub fn all_records(&self) -> Vec<&CreditRecord> {
        self.credits.values().collect()
    }

    /// Lookup a single credit record by user hash. Returns `None` for
    /// peers we have not yet recorded any credit data for (the upload
    /// pane uses this to populate the per-row uploaded/downloaded
    /// totals on the Queued tab without round-tripping through
    /// `all_records`).
    pub fn get_record(&self, user_hash: &[u8; 16]) -> Option<&CreditRecord> {
        self.credits.get(user_hash)
    }

    pub fn cleanup_stale(&mut self, max_age_days: i64) {
        let cutoff = chrono::Utc::now().timestamp() - (max_age_days * 86400);
        let before = self.credits.len() + self.ember_credits.len();
        let unsaved_credit_keys = &mut self.unsaved_credit_keys;
        let credit_seen = &mut self.credit_seen;
        self.credits.retain(|k, r| {
            let keep = r.last_seen > cutoff;
            if keep {
                credit_seen.set(*k, r.last_seen);
            } else {
                credit_seen.remove(k);
                unsaved_credit_keys.insert(*k);
            }
            keep
        });
        // Same cutoff for Ember records so the two tables age in
        // lockstep. `last_seen` on EmberCreditRecord is bumped by
        // every credit-granting or session-recording operation, so
        // active peers stay regardless of their public-key format.
        let unsaved_ember_keys = &mut self.unsaved_ember_keys;
        let ember_seen = &mut self.ember_seen;
        self.ember_credits.retain(|k, r| {
            let keep = r.last_seen > cutoff;
            if keep {
                ember_seen.set(*k, r.last_seen);
            } else {
                ember_seen.remove(k);
                unsaved_ember_keys.insert(*k);
            }
            keep
        });
        // Only dirty when the sweep actually evicted something. This runs on
        // the same 60s tick as the flush, so bumping unconditionally would
        // re-dirty the state every tick and defeat the gate entirely.
        if self.credits.len() + self.ember_credits.len() != before {
            self.touch_dirty();
        }
    }

    // ---- Ember credit helpers ----

    /// Look up or create an Ember credit record for this pubkey.
    /// Mirrors `get_or_create` on the eMule side: bumps `last_seen`
    /// so evictions track contact freshness. Non-mutating queries
    /// (`get_ember_record`) route through `ember_credits.get` and
    /// deliberately do NOT bump the timestamp.
    pub fn get_or_create_ember(&mut self, pub_key: [u8; 32]) -> &mut EmberCreditRecord {
        let now = chrono::Utc::now().timestamp();
        // Same backstop as `get_or_create` (see MAX_CREDIT_RECORDS): evict the
        // least-recently-seen Ember record when inserting a new one at capacity.
        if !self.ember_credits.contains_key(&pub_key)
            && self.ember_credits.len() >= MAX_CREDIT_RECORDS
        {
            if let Some(oldest) = self.ember_seen.oldest(&self.ember_credits, |r| r.last_seen) {
                self.ember_credits.remove(&oldest);
                self.ember_seen.remove(&oldest);
                self.mark_ember_unsaved(oldest);
            }
        }
        // Same reason as `get_or_create`: flag before the borrow escapes.
        self.mark_ember_unsaved(pub_key);
        self.ember_seen.set(pub_key, now);
        let record = self
            .ember_credits
            .entry(pub_key)
            .or_insert_with(|| EmberCreditRecord::new(pub_key));
        record.last_seen = now;
        record
    }

    pub fn get_ember_record(&self, pub_key: &[u8; 32]) -> Option<&EmberCreditRecord> {
        self.ember_credits.get(pub_key)
    }

    pub fn all_ember_records(&self) -> Vec<&EmberCreditRecord> {
        self.ember_credits.values().collect()
    }

    /// Credit peer `pub_key` for `bytes` they uploaded to us. `verified`
    /// must be `true` (full PoP completed on this session) for bytes to
    /// land on the record — without PoP a spoofer who claimed the
    /// pubkey could farm credit for a genuine peer. Binding-only
    /// peers still get their bytes tracked via the legacy `CreditRecord`
    /// upstream; this method only governs the Ember-specific ledger.
    ///
    /// Returns `true` when the write landed, `false` when it was
    /// rejected so callers can emit a metric/log.
    pub fn add_ember_uploaded(&mut self, pub_key: [u8; 32], bytes: u64, verified: bool) -> bool {
        if !verified {
            return false;
        }
        let now = chrono::Utc::now().timestamp();
        let record = self.get_or_create_ember(pub_key);
        record.uploaded = record.uploaded.saturating_add(bytes);
        record.last_upload_time = now;
        record.ident_verified = true;
        true
    }

    pub fn add_ember_downloaded(&mut self, pub_key: [u8; 32], bytes: u64, verified: bool) -> bool {
        if !verified {
            return false;
        }
        let now = chrono::Utc::now().timestamp();
        let record = self.get_or_create_ember(pub_key);
        record.downloaded = record.downloaded.saturating_add(bytes);
        record.last_download_time = now;
        record.ident_verified = true;
        true
    }

    /// Record a completed/aborted upload session for the peer so the
    /// session counts and speed EWMA stay up to date. Called from
    /// `upload.rs` once per session (normal completion OR mid-session
    /// failure) — NOT once per chunk.
    ///
    /// `completed == true` iff the session ended in the "healthy"
    /// state (out-of-parts, session-limit expired, queue rotation).
    /// `false` for aborted sessions (connection closed mid-transfer,
    /// queue-full reissues, etc.).
    pub fn record_ember_session(
        &mut self,
        pub_key: [u8; 32],
        bytes_transferred: u64,
        duration_secs: u64,
        completed: bool,
        verified: bool,
    ) {
        if !verified {
            return;
        }
        let record = self.get_or_create_ember(pub_key);
        record.record_session(bytes_transferred, duration_secs, completed);
        record.ident_verified = true;
    }

    /// Serialize credits to the versioned `clients.met` cache format. Adds
    /// `ident_ip` + `ident_state` per record (vs. the original layout) so the
    /// Known Clients tab's last-IP and country flag survive a restart. Old
    /// builds reading this file see the magic as an implausibly large record
    /// count and load nothing rather than misparsing — see `load_from_file`.
    /// The v3 crypto-anchor section is appended after the record array, where
    /// a v2 reader (which stops after `count` records) never looks.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Keep a record even with zero credits when it carries an Ember
        // identity binding — that binding is what lets friend rendezvous
        // discovery relocate download sources on a fresh launch, before any
        // upload/download has happened this session.
        let records: Vec<_> = self
            .credits
            .values()
            .filter(|r| r.uploaded > 0 || r.downloaded > 0 || r.ember_hash.is_some())
            .collect();
        buf.extend_from_slice(&CLIENTS_MET_MAGIC.to_le_bytes());
        buf.push(CLIENTS_MET_VERSION);
        buf.extend_from_slice(&(records.len() as u32).to_le_bytes());
        for r in &records {
            buf.extend_from_slice(&r.user_hash);
            buf.extend_from_slice(&r.uploaded.to_le_bytes());
            buf.extend_from_slice(&r.downloaded.to_le_bytes());
            buf.extend_from_slice(&r.last_seen.to_le_bytes());
            buf.extend_from_slice(&r.ident_ip.to_le_bytes());
            buf.push(r.ident_state.to_u8());
            buf.extend_from_slice(&(r.public_key.len() as u16).to_le_bytes());
            buf.extend_from_slice(&r.public_key);
            // v2 trailer.
            match r.ember_hash {
                Some(eh) => {
                    buf.push(1);
                    buf.extend_from_slice(&eh);
                }
                None => buf.push(0),
            }
        }
        // v3 crypto-anchor section. Always emitted, even when empty: an
        // absent section means "written before v3, fall back to
        // `ident_state`", which is a different answer from "no record is
        // anchored yet".
        let anchored: Vec<&[u8; 16]> = records
            .iter()
            .filter(|r| r.crypto_verified_once)
            .map(|r| &r.user_hash)
            .collect();
        buf.extend_from_slice(&CLIENTS_MET_ANCHOR_MAGIC.to_le_bytes());
        buf.extend_from_slice(&(anchored.len() as u32).to_le_bytes());
        for user_hash in anchored {
            buf.extend_from_slice(user_hash);
        }
        // v4 identity section. Only records that have told us something are
        // listed, so a ledger full of hash-only peers costs 8 bytes.
        //
        // Drawn from `records`, which is already filtered above — so a peer we
        // have merely been introduced to, with no bytes and no Ember binding,
        // has no row here to hang a name on. That is deliberate: this file is
        // only the fallback cache for when the SQLite `credits` table comes up
        // empty, and that table keeps every row unfiltered. Losing a name for
        // a peer we never traded with, in the rare case the database is lost,
        // is not worth caching a row the filter exists to omit.
        let named: Vec<&&CreditRecord> = records
            .iter()
            .filter(|r| !r.peer_name.is_empty() || !r.client_software.is_empty())
            .collect();
        buf.extend_from_slice(&CLIENTS_MET_IDENTITY_MAGIC.to_le_bytes());
        buf.extend_from_slice(&(named.len() as u32).to_le_bytes());
        for r in named {
            // `truncate_identity` bounds both on the way in, so the casts
            // below cannot wrap. Re-applied here rather than assumed, because
            // this is the byte that frames the field on disk.
            let name = truncate_identity(&r.peer_name);
            let software = truncate_identity(&r.client_software);
            buf.extend_from_slice(&r.user_hash);
            buf.push(name.len() as u8);
            buf.extend_from_slice(name.as_bytes());
            buf.push(software.len() as u8);
            buf.extend_from_slice(software.as_bytes());
        }
        buf
    }

    /// Load credits from clients.met.
    pub fn load_from_file(&mut self, path: &std::path::Path) -> std::io::Result<usize> {
        crate::security::recover_interrupted_replace(path);
        let metadata = std::fs::metadata(path)?;
        if metadata.len() > 50 * 1024 * 1024 {
            tracing::warn!("clients.met too large ({} bytes), skipping", metadata.len());
            return Ok(0);
        }
        let data = std::fs::read(path)?;
        if data.len() < 4 {
            return Ok(0);
        }

        // Format detection. The versioned (v1) cache leads with CLIENTS_MET_MAGIC
        // followed by a version byte and the record count; the original layout
        // started straight with the count. We branch on the magic and, for v1,
        // read the two extra per-record fields (ident_ip + ident_state).
        let versioned =
            u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == CLIENTS_MET_MAGIC;
        // v1 had no Ember-identity trailer; v2 appends one per record (see
        // `CLIENTS_MET_VERSION` doc comment). `versioned` alone doesn't
        // distinguish the two, so check the version byte directly.
        let has_ember_trailer = versioned && data.len() > 4 && data[4] >= 2;
        // Same idea for the v3 crypto-anchor section, which follows the whole
        // record array rather than sitting inside a record.
        let has_anchor_section = versioned && data.len() > 4 && data[4] >= 3;
        // And for the v4 identity section, which follows the anchor section.
        let has_identity_section = versioned && data.len() > 4 && data[4] >= 4;
        let (count, mut offset) = if versioned {
            if data.len() < 9 {
                return Ok(0);
            }
            (
                u32::from_le_bytes([data[5], data[6], data[7], data[8]]) as usize,
                9usize,
            )
        } else {
            (
                u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize,
                4usize,
            )
        };
        // Fixed-size prefix preceding the variable-length public key.
        let fixed_prefix = if versioned {
            16 + 8 + 8 + 8 + 4 + 1 + 2
        } else {
            16 + 8 + 8 + 8 + 2
        };

        let read_err = || std::io::Error::new(std::io::ErrorKind::InvalidData, "bad credit record");
        let mut loaded = 0;
        let expected = count.min(50000);
        let mut loaded_hashes: Vec<[u8; 16]> = Vec::new();
        for _ in 0..expected {
            if offset + fixed_prefix > data.len() {
                break;
            }
            let mut user_hash = [0u8; 16];
            user_hash.copy_from_slice(&data[offset..offset + 16]);
            offset += 16;
            let uploaded = u64::from_le_bytes(
                data[offset..offset + 8]
                    .try_into()
                    .map_err(|_| read_err())?,
            );
            offset += 8;
            let downloaded = u64::from_le_bytes(
                data[offset..offset + 8]
                    .try_into()
                    .map_err(|_| read_err())?,
            );
            offset += 8;
            let last_seen = i64::from_le_bytes(
                data[offset..offset + 8]
                    .try_into()
                    .map_err(|_| read_err())?,
            );
            offset += 8;
            let (ident_ip, ident_state) = if versioned {
                let ip = u32::from_le_bytes(
                    data[offset..offset + 4]
                        .try_into()
                        .map_err(|_| read_err())?,
                );
                offset += 4;
                let st = IdentState::from_u8(data[offset]);
                offset += 1;
                (ip, st)
            } else {
                (0, IdentState::Unknown)
            };
            let pk_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            // Public keys are at most a few hundred bytes; an absurd length
            // means a corrupt/hostile clients.met, so stop parsing the rest.
            if pk_len > 4096 {
                break;
            }
            let public_key = if offset + pk_len <= data.len() {
                let pk = data[offset..offset + pk_len].to_vec();
                offset += pk_len;
                pk
            } else {
                break;
            };
            let ember_hash = if has_ember_trailer {
                if offset >= data.len() {
                    break;
                }
                let has_hash = data[offset] == 1;
                offset += 1;
                if has_hash {
                    if offset + 16 > data.len() {
                        break;
                    }
                    let mut eh = [0u8; 16];
                    eh.copy_from_slice(&data[offset..offset + 16]);
                    offset += 16;
                    Some(eh)
                } else {
                    None
                }
            } else {
                None
            };
            let record = CreditRecord {
                user_hash,
                uploaded,
                downloaded,
                last_seen,
                public_key,
                // Identification is per session, like the database load in
                // `network::mod`; the stored state still seeds the anchor
                // below.
                ident_state: match ident_state {
                    IdentState::Verified | IdentState::Failed => IdentState::Needed,
                    other => other,
                },
                ident_ip,
                ember_hash,
                // Fallback for files written before v3, which the anchor
                // section below can only strengthen. A persisted `Verified`
                // was reached by `set_ident_state(Verified)`, i.e. by a
                // challenge this record's own key answered, so it is the best
                // guess available for those files — but only a guess: it is
                // exactly the state a stranger can knock back to `Failed`,
                // which is why v3 stores the anchor instead.
                crypto_verified_once: ident_state == IdentState::Verified,
                // Filled from the v4 section below, which is keyed by
                // user_hash and may name only some of these records.
                peer_name: String::new(),
                client_software: String::new(),
                // `clients.met` has no field for these; the SQLite table,
                // which is the primary store, does.
                seen_ip: 0,
                proven_ember_hash: None,
            };
            self.insert_loaded_credit(record);
            loaded_hashes.push(user_hash);
            loaded += 1;
        }
        // Only read the anchor section when every record parsed: a truncated
        // array leaves `offset` mid-record, where a chance 4-byte match would
        // fabricate anchors for rows that never earned one.
        //
        // The section only ever adds anchors, it never clears the fallback
        // above. Nothing in the codebase reaches a persisted `Verified`
        // without having gone through `set_ident_state(Verified)` — the one
        // exception restores it from the SQLite `credits` table, i.e. from an
        // earlier verification — so "Verified but absent from the section"
        // means the writer had no anchor column to read, not that the record
        // is unanchored.
        if has_anchor_section && loaded == expected {
            if let Some(anchored) = read_anchor_section(&data, offset) {
                for user_hash in &loaded_hashes {
                    if !anchored.contains(user_hash) {
                        continue;
                    }
                    if let Some(record) = self.credits.get_mut(user_hash) {
                        record.crypto_verified_once = true;
                    }
                }
            }
            // The identity section sits after the anchor section, so it can
            // only be located once that one's length is known. Same
            // all-or-nothing rule: a section we cannot frame is skipped, and
            // a missing name is simply a row we have never been introduced to.
            if has_identity_section {
                if let Some(after_anchors) = anchor_section_end(&data, offset) {
                    for (user_hash, peer_name, client_software) in
                        read_identity_section(&data, after_anchors)
                    {
                        if let Some(record) = self.credits.get_mut(&user_hash) {
                            record.peer_name = peer_name;
                            record.client_software = client_software;
                        }
                    }
                }
            }
        }
        // Loading matches disk, so this is not itself a change to persist —
        // except when the file we just read predates the current format. The
        // flush is dirty-gated now, so an older `clients.met` would otherwise
        // never be rewritten and would stay on the old layout indefinitely.
        if !has_identity_section {
            self.touch_dirty();
        }
        tracing::info!("Loaded {} credit records from {}", loaded, path.display());
        Ok(loaded)
    }
}

/// Read the v3 crypto-anchor section sitting at `offset`, i.e. the set of
/// user hashes whose credits are already anchored to a proven key.
///
/// `None` means there is no section we can trust — an older file, or one
/// truncated mid-section — and the caller keeps the `ident_state` fallback
/// rather than clearing anchors it failed to read. The size of the set is
/// bounded by the bytes actually present, so a bogus count can't make us
/// allocate.
fn read_anchor_section(data: &[u8], offset: usize) -> Option<HashSet<[u8; 16]>> {
    let header = data.get(offset..offset + 8)?;
    if u32::from_le_bytes(header[0..4].try_into().ok()?) != CLIENTS_MET_ANCHOR_MAGIC {
        return None;
    }
    let count = u32::from_le_bytes(header[4..8].try_into().ok()?) as usize;
    let body_start = offset + 8;
    let body_end = count.checked_mul(16)?.checked_add(body_start)?;
    let body = data.get(body_start..body_end)?;
    Some(
        body.chunks_exact(16)
            .map(|chunk| {
                let mut user_hash = [0u8; 16];
                user_hash.copy_from_slice(chunk);
                user_hash
            })
            .collect(),
    )
}

/// Offset just past the v3 crypto-anchor section that starts at `offset`.
///
/// `None` when there is no framable section there, which is the same
/// condition [`read_anchor_section`] returns `None` for — the v4 section that
/// follows cannot be located either way.
///
/// Deliberately re-derives the anchor section's length rather than having
/// [`read_anchor_section`] return it, so that function's signature stays as
/// it was. The two must therefore agree on the header layout: change one and
/// change this.
fn anchor_section_end(data: &[u8], offset: usize) -> Option<usize> {
    let header = data.get(offset..offset + 8)?;
    if u32::from_le_bytes(header[0..4].try_into().ok()?) != CLIENTS_MET_ANCHOR_MAGIC {
        return None;
    }
    let count = u32::from_le_bytes(header[4..8].try_into().ok()?) as usize;
    let end = count.checked_mul(16)?.checked_add(offset + 8)?;
    // Must actually be present, not merely arithmetically implied, or the
    // identity read would start past the end of a truncated file.
    if end > data.len() {
        return None;
    }
    Some(end)
}

/// Read the v4 identity section sitting at `offset`.
///
/// Returns what it could frame and stops at the first malformed entry rather
/// than failing the whole load: these are display strings, so a truncated
/// tail costs a few names and nothing else. An empty result covers "no
/// section here", which is what a v3 file looks like.
#[allow(clippy::type_complexity)]
fn read_identity_section(data: &[u8], offset: usize) -> Vec<([u8; 16], String, String)> {
    let mut out = Vec::new();
    let Some(header) = data.get(offset..offset + 8) else {
        return out;
    };
    if u32::from_le_bytes(header[0..4].try_into().unwrap_or_default()) != CLIENTS_MET_IDENTITY_MAGIC
    {
        return out;
    }
    let count = u32::from_le_bytes(header[4..8].try_into().unwrap_or_default()) as usize;
    let mut cursor = offset + 8;
    // Bounded by the record cap, so a bogus count cannot make us spin or
    // reserve.
    for _ in 0..count.min(MAX_CREDIT_RECORDS) {
        let Some(hash_bytes) = data.get(cursor..cursor + 16) else {
            break;
        };
        let mut user_hash = [0u8; 16];
        user_hash.copy_from_slice(hash_bytes);
        cursor += 16;

        let read_string = |cursor: &mut usize| -> Option<String> {
            let len = *data.get(*cursor)? as usize;
            *cursor += 1;
            let bytes = data.get(*cursor..*cursor + len)?;
            *cursor += len;
            // Lossy rather than a hard failure: the name came off the wire
            // and was only ever display text.
            Some(String::from_utf8_lossy(bytes).into_owned())
        };
        let Some(peer_name) = read_string(&mut cursor) else {
            break;
        };
        let Some(client_software) = read_string(&mut cursor) else {
            break;
        };
        out.push((user_hash, peer_name, client_software));
    }
    out
}

fn generate_rsa_keypair() -> (Vec<u8>, Vec<u8>) {
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use rsa::RsaPrivateKey;

    let mut rng = rand::thread_rng();
    // 384-bit RSA matches eMule's SecureIdent key size for wire-level compatibility.
    // This is intentionally low by modern standards; it provides credit-abuse
    // deterrence rather than strong cryptographic security.
    let bits = 384;
    let private_key = match RsaPrivateKey::new(&mut rng, bits) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("RSA keygen failed: {e}, credits will be disabled");
            return (Vec::new(), Vec::new());
        }
    };
    let public_key = private_key.to_public_key();

    let priv_der = match private_key.to_pkcs8_der() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("RSA private key encode failed: {e}");
            return (Vec::new(), Vec::new());
        }
    };
    // Emit the public key as an X.509 SubjectPublicKeyInfo (SPKI) — the
    // SEQUENCE { AlgorithmIdentifier{rsaEncryption,NULL}, BIT STRING{n,e} }
    // envelope. That's what eMule's Crypto++ produces from
    // `pubkey.GetMaterial().Save(asink)` in CClientCreditsList::InitalizeCrypting,
    // and that's the format its `RSASSA_PKCS1v15_SHA_Verifier(StringSource&)`
    // constructor feeds into X509PublicKey::BERDecode when verifying our
    // signatures in CClientCreditsList::VerifyIdent. An earlier version of
    // this code used the inner `to_pkcs1_der()` RSAPublicKey form — that
    // parses fine with our own rsa-crate fallback on verify, but Crypto++'s
    // X509PublicKey BERDecode refuses it, which silently tripped the
    // `try {...} catch(...)` in VerifyIdent and pinned our peers at
    // `Identification: Invalid` even though uploads were flowing. ~78 bytes
    // for a 384-bit key, well within eMule's `MAXPUBKEYSIZE = 80`.
    let pub_der = match public_key.to_public_key_der() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("RSA public key encode failed: {e}");
            return (Vec::new(), Vec::new());
        }
    };

    (pub_der.as_ref().to_vec(), priv_der.as_bytes().to_vec())
}

/// A peer address as the IPv4 `u32` the identity checks compare, `0` when it
/// has none.
pub(crate) fn credit_ip(addr: std::net::SocketAddr) -> u32 {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or(0, |v4| u32::from_be_bytes(v4.octets())),
    }
}

/// `cryptkey.dat` as eMule and aMule write it: the RSA-384 private key as
/// PKCS#8 DER, base64-encoded by Crypto++ with a line break every 72 columns
/// (`CClientCreditsList::CreateKeyPair`). Raw DER, and PKCS#1 rather than
/// PKCS#8, are accepted too, for a file someone has already converted.
///
/// Returns `(public SPKI, private PKCS#8)`, the pair Ember stores. Only 384-bit
/// keys are taken: that is the size eMule's SecIdent uses, and the one whose
/// public key fits the 80-byte `MAXPUBKEYSIZE` peers accept.
pub(crate) fn decode_emule_cryptkey(raw: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    use base64::Engine as _;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;

    let der = if raw.first() == Some(&0x30) {
        raw.to_vec()
    } else {
        let text: Vec<u8> = raw
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        base64::engine::general_purpose::STANDARD.decode(text).ok()?
    };
    let key = RsaPrivateKey::from_pkcs8_der(&der)
        .or_else(|_| RsaPrivateKey::from_pkcs1_der(&der))
        .ok()?;
    if key.size() * 8 != 384 {
        return None;
    }
    let public = key.to_public_key().to_public_key_der().ok()?;
    let private = key.to_pkcs8_der().ok()?;
    Some((public.as_ref().to_vec(), private.as_bytes().to_vec()))
}

/// Ember's `cryptkey.dat` bytes for a keypair, wrapped for this account:
/// `u32 LE len | public SPKI | u32 LE len | private PKCS#8`, then
/// `secret_store::protect`.
pub(crate) fn encode_keypair_file(public_der: &[u8], private_der: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(8 + public_der.len() + private_der.len());
    out.extend_from_slice(&(public_der.len() as u32).to_le_bytes());
    out.extend_from_slice(public_der);
    out.extend_from_slice(&(private_der.len() as u32).to_le_bytes());
    out.extend_from_slice(private_der);
    crate::storage::secret_store::protect(&out)
}

/// Re-encode a cached public key as SPKI if it's in the bare PKCS#1
/// `RSAPublicKey` form. Users who ran an older build of Ember have an
/// on-disk `cryptkey.dat` whose `our_public_key` field is PKCS#1 — valid
/// cryptographically, but incompatible with eMule's X509PublicKey decoder
/// (see `generate_rsa_keypair` above). On load we parse whichever form
/// we find and normalise to SPKI in memory so every outgoing OP_PUBLICKEY
/// uses the eMule-compatible envelope. Returns `None` and leaves the
/// original bytes alone if the key parses as neither (likely corrupt,
/// caller will regenerate).
fn normalize_public_key_to_spki(pub_der: &[u8]) -> Option<Vec<u8>> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
    use rsa::RsaPublicKey;

    if RsaPublicKey::from_public_key_der(pub_der).is_ok() {
        return Some(pub_der.to_vec());
    }
    let key = RsaPublicKey::from_pkcs1_der(pub_der).ok()?;
    let spki = key.to_public_key_der().ok()?;
    Some(spki.as_ref().to_vec())
}

fn sign_challenge(
    private_key_der: &[u8],
    peer_public_key: &[u8],
    challenge: u32,
    challenge_ip: u32,
    challenge_ip_kind: Option<u8>,
) -> Vec<u8> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::SignerMut;
    use rsa::RsaPrivateKey;
    use sha1::Sha1;

    let key = match RsaPrivateKey::from_pkcs8_der(private_key_der) {
        Ok(k) => k,
        Err(_) => return Vec::new(),
    };
    let mut signing_key = SigningKey::<Sha1>::new(key);

    let mut msg = Vec::with_capacity(peer_public_key.len() + 9);
    msg.extend_from_slice(peer_public_key);
    msg.extend_from_slice(&challenge.to_le_bytes());
    if let Some(kind) = challenge_ip_kind {
        msg.extend_from_slice(&challenge_ip.to_le_bytes());
        msg.push(kind);
    }

    match signing_key.try_sign(&msg) {
        Ok(sig) => {
            let bytes: Box<[u8]> = sig.into();
            bytes.into_vec()
        }
        Err(_) => Vec::new(),
    }
}

fn verify_challenge(
    public_key_der: &[u8],
    our_public_key: &[u8],
    challenge: u32,
    challenge_ip_kind: Option<u8>,
    peer_ip: u32,
    local_ip_for_remoteclient: u32,
    signature: &[u8],
) -> bool {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use rsa::RsaPublicKey;
    use sha1::Sha1;

    // eMule sends raw PKCS#1 RSA public key DER {n, e}. Try PKCS#1 first,
    // then fall back to SPKI for forward compatibility.
    let key = match RsaPublicKey::from_pkcs1_der(public_key_der).or_else(|_| {
        use rsa::pkcs8::DecodePublicKey;
        RsaPublicKey::from_public_key_der(public_key_der)
    }) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let verifying_key = VerifyingKey::<Sha1>::new(key);

    let mut msg = Vec::with_capacity(our_public_key.len() + 9);
    msg.extend_from_slice(our_public_key);
    msg.extend_from_slice(&challenge.to_le_bytes());
    if let Some(kind) = challenge_ip_kind {
        let challenge_ip = match kind {
            CRYPT_CIP_LOCALCLIENT => peer_ip,
            CRYPT_CIP_REMOTECLIENT => local_ip_for_remoteclient,
            CRYPT_CIP_NONECLIENT => 0,
            _ => return false,
        };
        msg.extend_from_slice(&challenge_ip.to_le_bytes());
        msg.push(kind);
    }

    let sig = match Signature::try_from(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    verifying_key.verify(&msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A user hash is public — it goes out in the clear in every Hello — so
    /// "whoever sends a key last owns the identity" let anyone claim a peer's
    /// hash, inherit its credit, and lock the real peer out of verifying for
    /// good. First key seen wins.
    #[test]
    fn a_second_differing_public_key_cannot_displace_the_first() {
        let mut cm = CreditManager::new();
        let victim = [0x11u8; 16];
        let honest = vec![0xAAu8; 64];
        let attacker = vec![0xBBu8; 64];

        assert!(cm.set_public_key(victim, honest.clone()));
        assert!(
            !cm.set_public_key(victim, attacker),
            "a different key for a bound hash must be refused",
        );
        assert_eq!(
            cm.get_record(&victim).unwrap().public_key,
            honest,
            "the originally bound key must survive",
        );
        assert!(
            cm.set_public_key(victim, honest),
            "re-sending the same key stays a no-op success",
        );
    }

    /// Regression: a verified peer that moves to a new address is
    /// re-challenged and passes, so the pin must follow it. Leaving the old
    /// pin in place reported `BadGuy` forever, which zeroes the queue score.
    #[test]
    fn reverifying_from_a_new_address_clears_the_badguy_state() {
        let mut cm = CreditManager::new();
        let peer = [0x22u8; 16];
        let first_ip = 0x0A00_0001u32;
        let second_ip = 0x0A00_0002u32;

        cm.set_ident_state(peer, IdentState::Verified);
        cm.check_identity_ip(peer, first_ip);
        assert_eq!(
            cm.get_current_ident_state(&peer, second_ip),
            IdentState::BadGuy,
            "an unverified move must still look like a replay",
        );

        // The peer answered a fresh challenge from its new address.
        cm.set_ident_state(peer, IdentState::Verified);
        cm.check_identity_ip(peer, second_ip);
        assert_eq!(
            cm.get_current_ident_state(&peer, second_ip),
            IdentState::Verified,
            "a peer that re-proved its identity must not stay BadGuy",
        );
    }

    #[test]
    fn upload_credit_is_refused_for_a_verified_hash_seen_from_another_ip() {
        let mut cm = CreditManager::new();
        let peer = [0x23u8; 16];
        let proven_ip = 0x0A00_0001u32;
        let other_ip = 0x0A00_0002u32;
        cm.set_ident_state(peer, IdentState::Verified);
        cm.check_identity_ip(peer, proven_ip);

        assert!(!cm.add_uploaded(peer, other_ip, 4096));
        assert_eq!(cm.get_record(&peer).unwrap().uploaded, 0);

        assert!(cm.add_uploaded(peer, proven_ip, 4096));
        assert!(cm.add_uploaded(peer, 0, 1024), "no live IP falls back to the stored state");
        assert_eq!(cm.get_record(&peer).unwrap().uploaded, 5120);
    }

    /// The inbound (upload) ordering is `Unknown -> Needed -> Verified`,
    /// because `upload.rs` binds the key on `OP_PUBLICKEY` and immediately
    /// sets `Needed`. The old `ident_state == Unknown` guard therefore never
    /// fired there, so a stranger could claim a user_hash that carried
    /// credits but no bound key, TOFU its own key in, answer one challenge
    /// and inherit the totals.
    #[test]
    fn first_verification_resets_credits_inherited_through_the_needed_state() {
        let mut cm = CreditManager::new();
        let victim = [0x33u8; 16];
        {
            let r = cm.get_or_create(victim);
            r.uploaded = 50 * 1024 * 1024;
            r.downloaded = 10 * 1024 * 1024;
        }

        // Attacker binds its own key to the unbound hash (TOFU), which parks
        // the record at `Needed`, then answers the challenge.
        assert!(cm.set_public_key(victim, vec![0xBBu8; 64]));
        cm.set_ident_state(victim, IdentState::Needed);
        cm.set_ident_state(victim, IdentState::Verified);

        let record = cm.get_record(&victim).expect("record");
        assert_eq!(record.uploaded, 1, "inherited upload total must be wiped");
        assert_eq!(
            record.downloaded, 1,
            "inherited download total must be wiped"
        );
    }

    /// The reset is a one-shot: once a key has proven itself, a peer that
    /// re-verifies (new address, new session, or after a stranger failed a
    /// challenge on its user_hash) must keep what it earned.
    #[test]
    fn reverification_does_not_wipe_already_anchored_credits() {
        let mut cm = CreditManager::new();
        let peer = [0x44u8; 16];
        assert!(cm.set_public_key(peer, vec![0xAAu8; 64]));
        cm.set_ident_state(peer, IdentState::Needed);
        cm.set_ident_state(peer, IdentState::Verified);
        {
            let r = cm.get_or_create(peer);
            r.uploaded = 4096;
            r.downloaded = 8192;
        }

        cm.set_ident_state(peer, IdentState::Verified);
        cm.set_ident_state(peer, IdentState::Failed);
        cm.set_ident_state(peer, IdentState::Verified);

        let record = cm.get_record(&peer).expect("record");
        assert_eq!(record.uploaded, 4096);
        assert_eq!(record.downloaded, 8192);
    }

    /// `ident_state` is persisted, so a `Needed` record survives a restart —
    /// which is what kept the old guard dead across launches. Only a
    /// persisted `Verified` may load as already-anchored.
    #[test]
    fn a_persisted_needed_record_still_faces_the_reset_after_restart() {
        let mut cm = CreditManager::new();
        let victim = [0x55u8; 16];
        {
            let r = cm.get_or_create(victim);
            r.uploaded = 1_000_000;
            r.downloaded = 2_000_000;
            r.public_key = vec![0xBBu8; 64];
            r.ident_state = IdentState::Needed;
        }
        let bytes = cm.serialize();
        let path =
            std::env::temp_dir().join(format!("ember-clients-needed-{}.met", unique_nanos()));
        std::fs::write(&path, &bytes).unwrap();

        let mut restored = CreditManager::new();
        restored.load_from_file(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(
            !restored.get_record(&victim).unwrap().crypto_verified_once,
            "a stored `Needed` must not load as already crypto-verified",
        );

        restored.set_ident_state(victim, IdentState::Verified);
        let record = restored.get_record(&victim).expect("record");
        assert_eq!(record.uploaded, 1);
        assert_eq!(record.downloaded, 1);
    }

    /// `ident_state` is not monotonic, so it cannot carry the anchor across a
    /// restart. A stranger who claims a peer's user_hash (it is in the clear
    /// in every Hello) from a different address draws a challenge out of
    /// `secident_request_state` even though the record is already `Verified`;
    /// answering it with a bogus signature persists `Failed`. Reconstructing
    /// the anchor from that state wiped the victim's totals the next time it
    /// re-proved itself — remote griefing for the price of one restart.
    #[test]
    fn a_failed_challenge_from_a_stranger_cannot_wipe_credits_across_a_restart() {
        let mut cm = CreditManager::new();
        let victim = [0x66u8; 16];
        assert!(cm.set_public_key(victim, vec![0xAAu8; 64]));
        cm.set_ident_state(victim, IdentState::Needed);
        cm.set_ident_state(victim, IdentState::Verified);
        {
            let r = cm.get_or_create(victim);
            r.uploaded = 50 * 1024 * 1024;
            r.downloaded = 10 * 1024 * 1024;
        }
        // The attacker's forged signature fails, and `transfer.rs` records
        // that as `Failed` on the victim's record.
        cm.set_ident_state(victim, IdentState::Failed);

        let bytes = cm.serialize();
        let path = std::env::temp_dir().join(format!(
            "ember_clients_met_anchor_{}_{}.met",
            std::process::id(),
            unique_nanos(),
        ));
        std::fs::write(&path, &bytes).expect("write temp clients.met");
        let mut restored = CreditManager::new();
        restored.load_from_file(&path).expect("load v3 clients.met");
        let _ = std::fs::remove_file(&path);

        assert!(
            restored.get_record(&victim).unwrap().crypto_verified_once,
            "the anchor must outlive a persisted `Failed`",
        );

        // The victim reconnects and passes its own challenge.
        restored.set_ident_state(victim, IdentState::Verified);
        let record = restored.get_record(&victim).expect("record");
        assert_eq!(
            record.uploaded,
            50 * 1024 * 1024,
            "an honest peer's uploads must survive the round trip"
        );
        assert_eq!(
            record.downloaded,
            10 * 1024 * 1024,
            "an honest peer's downloads must survive the round trip"
        );
    }

    /// A clients.met written before v3 has no anchor section, so the loader
    /// falls back to the old reconstruction rather than treating every record
    /// as unanchored (which would wipe every verified peer once).
    #[test]
    fn a_pre_v3_file_falls_back_to_reconstructing_the_anchor_from_ident_state() {
        let verified = [0x77u8; 16];
        let needed = [0x78u8; 16];
        let mut v2 = Vec::new();
        v2.extend_from_slice(&CLIENTS_MET_MAGIC.to_le_bytes());
        v2.push(2);
        v2.extend_from_slice(&2u32.to_le_bytes());
        for (user_hash, state) in [
            (verified, IdentState::Verified),
            (needed, IdentState::Needed),
        ] {
            v2.extend_from_slice(&user_hash);
            v2.extend_from_slice(&4096u64.to_le_bytes());
            v2.extend_from_slice(&8192u64.to_le_bytes());
            v2.extend_from_slice(&1_700_000_000i64.to_le_bytes());
            v2.extend_from_slice(&0x0102_0304u32.to_le_bytes());
            v2.push(state.to_u8());
            v2.extend_from_slice(&0u16.to_le_bytes());
            v2.push(0);
        }

        let path = std::env::temp_dir().join(format!(
            "ember_clients_met_v2_no_anchor_{}_{}.met",
            std::process::id(),
            unique_nanos(),
        ));
        std::fs::write(&path, &v2).expect("write v2 clients.met");
        let mut cm = CreditManager::new();
        let n = cm.load_from_file(&path).expect("load v2 clients.met");
        let _ = std::fs::remove_file(&path);

        assert_eq!(n, 2);
        assert!(
            cm.get_record(&verified).unwrap().crypto_verified_once,
            "a stored `Verified` is the best anchor guess a v2 file offers",
        );
        assert!(
            !cm.get_record(&needed).unwrap().crypto_verified_once,
            "a stored `Needed` must still face the reset",
        );
    }

    /// A v3 file can be written by a build whose *other* credit store — the
    /// SQLite `credits` table, which is the primary one — doesn't carry the
    /// anchor yet, so its section comes out empty while the records restored
    /// from that table say `Verified`. Those records were verified in an
    /// earlier session, so the section may only add anchors, never clear the
    /// `ident_state` fallback; otherwise every verified peer would be wiped
    /// once on the first fallback load.
    #[test]
    fn a_verified_record_missing_from_the_anchor_section_keeps_its_anchor() {
        let peer = [0x7Au8; 16];
        let mut v3 = Vec::new();
        v3.extend_from_slice(&CLIENTS_MET_MAGIC.to_le_bytes());
        v3.push(3);
        v3.extend_from_slice(&1u32.to_le_bytes());
        v3.extend_from_slice(&peer);
        v3.extend_from_slice(&4096u64.to_le_bytes());
        v3.extend_from_slice(&8192u64.to_le_bytes());
        v3.extend_from_slice(&1_700_000_000i64.to_le_bytes());
        v3.extend_from_slice(&0x0102_0304u32.to_le_bytes());
        v3.push(IdentState::Verified.to_u8());
        v3.extend_from_slice(&0u16.to_le_bytes());
        v3.push(0);
        v3.extend_from_slice(&CLIENTS_MET_ANCHOR_MAGIC.to_le_bytes());
        v3.extend_from_slice(&0u32.to_le_bytes());

        let path = std::env::temp_dir().join(format!(
            "ember_clients_met_v3_empty_anchor_{}_{}.met",
            std::process::id(),
            unique_nanos(),
        ));
        std::fs::write(&path, &v3).expect("write v3 clients.met");
        let mut cm = CreditManager::new();
        let n = cm.load_from_file(&path).expect("load v3 clients.met");
        let _ = std::fs::remove_file(&path);

        assert_eq!(n, 1);
        assert!(
            cm.get_record(&peer).unwrap().crypto_verified_once,
            "an empty section must not demote a persisted `Verified`",
        );
    }

    /// The v3 section is strictly appended. The record array must stay
    /// byte-identical to v2, because an older build reads exactly `count`
    /// records and stops: anything added *inside* a record would shift the
    /// next one and cost the user their whole ledger on a downgrade.
    #[test]
    fn the_anchor_section_is_appended_after_an_unchanged_record_array() {
        let mut cm = CreditManager::new();
        let hash = [0x79u8; 16];
        {
            let r = cm.get_or_create(hash);
            r.uploaded = 4096;
            r.downloaded = 8192;
            r.last_seen = 1_700_000_123;
            r.ident_ip = 0x0102_0304;
            r.ident_state = IdentState::Verified;
            r.public_key = vec![0xABu8; 12];
            r.crypto_verified_once = true;
        }

        let mut expected = Vec::new();
        expected.extend_from_slice(&CLIENTS_MET_MAGIC.to_le_bytes());
        expected.push(CLIENTS_MET_VERSION);
        expected.extend_from_slice(&1u32.to_le_bytes());
        // --- unchanged v2 record ---
        expected.extend_from_slice(&hash);
        expected.extend_from_slice(&4096u64.to_le_bytes());
        expected.extend_from_slice(&8192u64.to_le_bytes());
        expected.extend_from_slice(&1_700_000_123i64.to_le_bytes());
        expected.extend_from_slice(&0x0102_0304u32.to_le_bytes());
        expected.push(IdentState::Verified.to_u8());
        expected.extend_from_slice(&12u16.to_le_bytes());
        expected.extend_from_slice(&[0xABu8; 12]);
        expected.push(0);
        // --- v3 anchor section ---
        expected.extend_from_slice(&CLIENTS_MET_ANCHOR_MAGIC.to_le_bytes());
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&hash);
        // --- v4 identity section, empty: this peer never named itself ---
        expected.extend_from_slice(&CLIENTS_MET_IDENTITY_MAGIC.to_le_bytes());
        expected.extend_from_slice(&0u32.to_le_bytes());

        // The version byte stays >= 2, so an older reader still expects the
        // per-record Ember trailer that v3 keeps writing.
        assert_eq!(cm.serialize(), expected);
    }

    /// The nickname and client-software columns behind the Known eD2K Peers
    /// tab have to survive a restart, because that tab is a lifetime ledger:
    /// nearly every row it draws belongs to a peer with no open session, so
    /// there is nothing to ask at render time.
    #[test]
    fn a_peers_name_and_client_survive_the_clients_met_round_trip() {
        let mut cm = CreditManager::new();
        let named = [0x41u8; 16];
        let anonymous = [0x42u8; 16];
        {
            let r = cm.get_or_create(named);
            r.uploaded = 4096;
            r.peer_name = "Pöttinger".to_string();
            r.client_software = "eMule 0.60a".to_string();
        }
        {
            let r = cm.get_or_create(anonymous);
            r.uploaded = 1024;
        }

        let path = std::env::temp_dir().join(format!(
            "ember_clients_met_identity_{}_{}.met",
            std::process::id(),
            unique_nanos(),
        ));
        std::fs::write(&path, cm.serialize()).expect("write v4 clients.met");
        let mut restored = CreditManager::new();
        let n = restored.load_from_file(&path).expect("load v4 clients.met");
        let _ = std::fs::remove_file(&path);

        assert_eq!(n, 2);
        let back = restored.get_record(&named).expect("named record");
        assert_eq!(back.peer_name, "Pöttinger");
        assert_eq!(back.client_software, "eMule 0.60a");
        let blank = restored.get_record(&anonymous).expect("anonymous record");
        assert_eq!(blank.peer_name, "");
        assert_eq!(blank.client_software, "");
    }

    /// A v3 file has no identity section, and reading one must not be
    /// mistaken for finding an empty one — nor may it disturb the anchor
    /// section that does sit at that offset.
    #[test]
    fn a_pre_v4_file_loads_without_an_identity_section() {
        let peer = [0x43u8; 16];
        let mut v3 = Vec::new();
        v3.extend_from_slice(&CLIENTS_MET_MAGIC.to_le_bytes());
        v3.push(3);
        v3.extend_from_slice(&1u32.to_le_bytes());
        v3.extend_from_slice(&peer);
        v3.extend_from_slice(&4096u64.to_le_bytes());
        v3.extend_from_slice(&8192u64.to_le_bytes());
        v3.extend_from_slice(&1_700_000_000i64.to_le_bytes());
        v3.extend_from_slice(&0x0102_0304u32.to_le_bytes());
        v3.push(IdentState::Verified.to_u8());
        v3.extend_from_slice(&0u16.to_le_bytes());
        v3.push(0);
        v3.extend_from_slice(&CLIENTS_MET_ANCHOR_MAGIC.to_le_bytes());
        v3.extend_from_slice(&1u32.to_le_bytes());
        v3.extend_from_slice(&peer);

        let path = std::env::temp_dir().join(format!(
            "ember_clients_met_v3_no_identity_{}_{}.met",
            std::process::id(),
            unique_nanos(),
        ));
        std::fs::write(&path, &v3).expect("write v3 clients.met");
        let mut cm = CreditManager::new();
        let n = cm.load_from_file(&path).expect("load v3 clients.met");
        let _ = std::fs::remove_file(&path);

        assert_eq!(n, 1);
        let record = cm.get_record(&peer).expect("record");
        assert_eq!(record.peer_name, "");
        assert!(
            record.crypto_verified_once,
            "the anchor section still had to be read",
        );
    }

    /// A peer that sent `CT_NAME` once and omits it on the next handshake
    /// still has a name. Treating the omission as a new, empty value would
    /// blank the name for exactly the peers reconnected to most often.
    #[test]
    fn a_later_handshake_without_a_name_does_not_erase_the_stored_one() {
        let mut cm = CreditManager::new();
        let peer = [0x44u8; 16];
        cm.note_client_identity(peer, None, "Aoife", "eMule 0.60a");
        cm.note_client_identity(peer, None, "", "eMule 0.60b");
        let record = cm.get_record(&peer).expect("record");
        assert_eq!(record.peer_name, "Aoife");
        assert_eq!(
            record.client_software, "eMule 0.60b",
            "a value that *was* sent still updates",
        );
    }

    /// Both strings are peer-supplied and persisted, so an unbounded one
    /// would let a single peer grow the ledger without limit. The cut must
    /// not split a character, or the stored name is invalid UTF-8 away from
    /// being a panic.
    #[test]
    fn a_hostile_identity_is_bounded_without_splitting_a_character() {
        let mut cm = CreditManager::new();
        let peer = [0x45u8; 16];
        // 3 bytes each, so the cap lands mid-character if taken naively.
        let long = "☃".repeat(100);
        cm.note_client_identity(peer, None, &long, "");
        let stored = &cm.get_record(&peer).expect("record").peer_name;
        assert!(stored.len() <= MAX_IDENTITY_LEN, "{}", stored.len());
        assert!(stored.chars().all(|c| c == '☃'), "{stored}");
    }

    /// A peer that never completes SecIdent still gets an address on its
    /// ledger row, and recording it leaves the identity pin alone.
    #[test]
    fn a_session_records_the_address_without_touching_the_ident_pin() {
        let mut cm = CreditManager::new();
        let peer = [0x46u8; 16];
        let first: std::net::IpAddr = std::net::Ipv4Addr::new(9, 8, 7, 6).into();
        let moved: std::net::IpAddr = std::net::Ipv4Addr::new(9, 8, 7, 7).into();

        cm.note_client_identity(peer, Some(first), "", "");
        let record = cm.get_record(&peer).expect("an address alone creates the row");
        assert_eq!(record.seen_ip, 0x0908_0706);
        assert_eq!(record.ident_ip, 0, "only a verified signature pins ident_ip");

        cm.note_client_identity(peer, Some(moved), "Aoife", "");
        assert_eq!(cm.get_record(&peer).unwrap().seen_ip, 0x0908_0707, "the newest session wins");

        cm.note_client_identity(peer, None, "Aoife", "");
        assert_eq!(cm.get_record(&peer).unwrap().seen_ip, 0x0908_0707, "no address keeps the last");
    }

    /// Monotonic-ish suffix for temp filenames so concurrent test runs don't
    /// collide on a shared temp path.
    fn unique_nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }

    /// eMule's Crypto++ `RSASSA_PKCS1v15_SHA_Verifier(StringSource&)`
    /// constructor feeds the raw OP_PUBLICKEY bytes into
    /// `X509PublicKey::BERDecode`, which expects a SubjectPublicKeyInfo
    /// envelope: `SEQUENCE { AlgorithmIdentifier{rsaEncryption, NULL},
    /// BIT STRING { SEQUENCE { n, e } } }`. If we emit bare PKCS#1
    /// `SEQUENCE { n, e }` eMule throws inside the try/catch and our
    /// session ends up at IS_IDFAILED. Guard against regressing back to
    /// PKCS#1 by asserting the generated key starts with the SPKI outer
    /// SEQUENCE followed immediately by the algorithm-identifier
    /// SEQUENCE whose contents start with the rsaEncryption OID.
    #[test]
    fn generated_public_key_is_spki_and_fits_emule_buffer() {
        let (pub_der, priv_der) = generate_rsa_keypair();
        assert!(!pub_der.is_empty() && !priv_der.is_empty(), "keygen failed");
        assert!(
            pub_der.len() <= 80,
            "pub key {} bytes exceeds eMule MAXPUBKEYSIZE=80",
            pub_der.len()
        );

        // SPKI byte-prefix sanity — not a full ASN.1 parse, just enough to
        // distinguish PKCS#1 `SEQUENCE { INTEGER n, INTEGER e }` (which
        // starts 0x30 <len> 0x02 ...) from SPKI `SEQUENCE { SEQUENCE {
        // OID rsaEncryption, NULL }, BIT STRING ... }` (starts 0x30 <len>
        // 0x30 0x0D 0x06 0x09 ...).
        assert_eq!(pub_der[0], 0x30, "SPKI must start with SEQUENCE tag");
        // Skip the outer SEQUENCE length (1 or 2 bytes depending on content size).
        let algid_pos = if pub_der[1] & 0x80 == 0 {
            2
        } else {
            2 + (pub_der[1] & 0x7F) as usize
        };
        assert_eq!(
            pub_der[algid_pos], 0x30,
            "SPKI body must begin with AlgorithmIdentifier SEQUENCE, got 0x{:02X} — \
             we probably regressed to PKCS#1 output",
            pub_der[algid_pos]
        );
        assert_eq!(
            pub_der[algid_pos + 2],
            0x06,
            "AlgorithmIdentifier must start with OID"
        );

        // A round-trip through the decoder we actually use on verify must work:
        // this is the same path eMule takes before it tries to crypto-verify us.
        use rsa::pkcs8::DecodePublicKey;
        rsa::RsaPublicKey::from_public_key_der(&pub_der).expect("generated key must parse as SPKI");
    }

    /// Confirm `normalize_public_key_to_spki` upgrades a legacy
    /// PKCS#1-encoded public key (what older Ember builds persisted in
    /// cryptkey.dat) to the SPKI envelope on load, so existing users
    /// don't have to delete their keyfile to get secure identification
    /// working.
    #[test]
    fn normalize_pkcs1_public_key_to_spki() {
        use rsa::pkcs1::EncodeRsaPublicKey;
        use rsa::pkcs8::DecodePublicKey;
        use rsa::RsaPrivateKey;

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 384).expect("keygen");
        let pkcs1 = private_key
            .to_public_key()
            .to_pkcs1_der()
            .expect("pkcs1 encode")
            .as_ref()
            .to_vec();
        assert!(
            rsa::RsaPublicKey::from_public_key_der(&pkcs1).is_err(),
            "test fixture precondition: raw PKCS#1 must NOT parse as SPKI",
        );

        let spki = normalize_public_key_to_spki(&pkcs1).expect("normalisation returned None");
        rsa::RsaPublicKey::from_public_key_der(&spki).expect("normalised key must parse as SPKI");
        assert_ne!(spki, pkcs1, "normalisation must actually re-encode the key");

        // A key that's already SPKI should come back byte-identical.
        let already_spki = normalize_public_key_to_spki(&spki).expect("idempotent normalise");
        assert_eq!(already_spki, spki);
    }

    /// Regression: every mutating credit operation must bump
    /// `last_seen` so the 90-day `cleanup_stale` sweep evicts records
    /// based on time-since-last-contact, not time-since-first-contact.
    /// Before this was fixed, peers we connected with regularly but
    /// never traded bytes with (Unknown / Failed / Needed states) kept
    /// their creation-time timestamp forever and aged out at first
    /// contact + 90d, surfacing in the Known Clients tab as months-old
    /// entries we had in fact talked to that morning.
    #[test]
    fn last_seen_bumps_on_every_mutation() {
        let mut cm = CreditManager::new();
        let user = [0x42u8; 16];

        // Seed a record dated to ~120 days ago by hand so any
        // cleanup_stale(90) call would normally evict it. Each mutation
        // below must push `last_seen` forward to roughly "now", proving
        // the timestamp tracks contact freshness.
        let stale_ts = chrono::Utc::now().timestamp() - 120 * 86400;
        {
            let r = cm.get_or_create(user);
            r.last_seen = stale_ts;
        }
        let now_floor = chrono::Utc::now().timestamp() - 5;

        // 1. set_public_key — the most common "we just heard from them" event.
        {
            let r = cm.get_or_create(user);
            r.last_seen = stale_ts;
        }
        assert!(cm.set_public_key(user, vec![0xAB; 64]));
        assert!(
            cm.get_record(&user).unwrap().last_seen >= now_floor,
            "set_public_key must bump last_seen",
        );

        // 2. set_ident_state — every state transition counts.
        {
            let r = cm.get_or_create(user);
            r.last_seen = stale_ts;
        }
        cm.set_ident_state(user, IdentState::Verified);
        assert!(
            cm.get_record(&user).unwrap().last_seen >= now_floor,
            "set_ident_state must bump last_seen",
        );

        // 3. check_identity_ip — a successful signature means we just
        //    completed a SecIdent round trip with this peer.
        {
            let r = cm.get_or_create(user);
            r.last_seen = stale_ts;
        }
        cm.check_identity_ip(user, 0x0100_0000);
        assert!(
            cm.get_record(&user).unwrap().last_seen >= now_floor,
            "check_identity_ip must bump last_seen",
        );

        // 4 & 5. add_uploaded / add_downloaded must bump too — these are
        //        the original paths that did so explicitly. After the
        //        get_or_create refactor they bump via the helper, so
        //        prove the path still works (regardless of accept/reject
        //        outcome — the peer talked to us, that counts).
        {
            let r = cm.get_or_create(user);
            r.last_seen = stale_ts;
        }
        let _ = cm.add_uploaded(user, 0, 1024);
        assert!(
            cm.get_record(&user).unwrap().last_seen >= now_floor,
            "add_uploaded must bump last_seen",
        );
        {
            let r = cm.get_or_create(user);
            r.last_seen = stale_ts;
        }
        let _ = cm.add_downloaded(user, 0, 1024);
        assert!(
            cm.get_record(&user).unwrap().last_seen >= now_floor,
            "add_downloaded must bump last_seen",
        );

        // Read-only queries must NOT bump — those don't represent
        // contact, and bumping on every poll would defeat cleanup_stale
        // entirely (a record would never expire as long as the UI was
        // open). Re-stale and assert the timestamp survives a query.
        {
            let r = cm.get_or_create(user);
            r.last_seen = stale_ts;
        }
        let _ = cm.get_score_ratio(&user, 0);
        let _ = cm.get_current_ident_state(&user, 0);
        let _ = cm.get_record(&user);
        assert_eq!(
            cm.get_record(&user).unwrap().last_seen,
            stale_ts,
            "read-only credit queries must NOT touch last_seen",
        );
    }

    /// `cleanup_stale` evicts records past the cutoff regardless of
    /// `ident_state`. Without `last_seen` being kept fresh on every
    /// contact, the Known Clients list would slowly fill with months-
    /// old "Unknown" entries — the symptom that surfaced in the UI.
    #[test]
    fn cleanup_stale_evicts_past_cutoff() {
        let mut cm = CreditManager::new();
        let fresh = [0x01u8; 16];
        let stale = [0x02u8; 16];
        let now = chrono::Utc::now().timestamp();
        cm.get_or_create(fresh).last_seen = now;
        cm.get_or_create(stale).last_seen = now - 100 * 86400;

        cm.cleanup_stale(90);
        assert!(
            cm.get_record(&fresh).is_some(),
            "fresh record must survive 90d cutoff"
        );
        assert!(
            cm.get_record(&stale).is_none(),
            "100d-old record must be pruned"
        );
    }

    /// A fresh manager owes disk nothing, and any record mutation makes it
    /// owe one flush. The 60s credit flush is gated on this, so a mutation
    /// that failed to set it would lose the user's accumulated upload credit.
    #[test]
    fn a_record_mutation_marks_the_manager_dirty() {
        let mut cm = CreditManager::new();
        assert!(!cm.is_dirty(), "a new manager has nothing to persist");

        cm.add_uploaded([0x01u8; 16], 0, 4096);
        assert!(cm.is_dirty(), "granting upload credit must request a flush");

        let generation = cm.dirty_generation();
        cm.mark_saved_if_generation(generation);
        assert!(!cm.is_dirty(), "a completed flush clears the debt");

        cm.add_downloaded([0x01u8; 16], 0, 4096);
        assert!(cm.is_dirty(), "a later edit re-arms the flush");
    }

    /// The flush captures a generation, then does its DB and `clients.met`
    /// work without the lock. An edit landing in that window is *not* covered
    /// by the snapshot being written, so the flag has to survive it — this is
    /// the difference between "saved a moment late" and "silently dropped".
    #[test]
    fn an_edit_during_a_flush_is_not_marked_saved() {
        let mut cm = CreditManager::new();
        cm.add_uploaded([0x07u8; 16], 0, 1024);
        let in_flight = cm.dirty_generation();

        // Lands while the blocking write is still running.
        cm.add_uploaded([0x08u8; 16], 0, 2048);

        cm.mark_saved_if_generation(in_flight);
        assert!(
            cm.is_dirty(),
            "the edit the snapshot did not include must still be owed to disk"
        );
    }

    /// `cleanup_stale` runs on the same 60s tick as the flush. Bumping the
    /// generation on a sweep that evicted nothing would re-dirty the state
    /// every cycle and turn the gate back into an unconditional write.
    #[test]
    fn a_sweep_that_evicts_nothing_leaves_the_manager_clean() {
        let mut cm = CreditManager::new();
        cm.get_or_create([0x09u8; 16]);
        let generation = cm.dirty_generation();
        cm.mark_saved_if_generation(generation);
        assert!(!cm.is_dirty());

        cm.cleanup_stale(90);
        assert!(
            !cm.is_dirty(),
            "a no-op sweep must not schedule another full rewrite"
        );

        // ...but one that actually evicts does have to be persisted.
        let stale = [0x0Au8; 16];
        cm.get_or_create(stale).last_seen = chrono::Utc::now().timestamp() - 100 * 86400;
        let generation = cm.dirty_generation();
        cm.mark_saved_if_generation(generation);
        cm.cleanup_stale(90);
        assert!(
            cm.is_dirty(),
            "an eviction changes what belongs on disk and must be flushed"
        );
    }

    /// The first flush reconciles everything; later ones carry only the keys
    /// touched since, and a flush that never confirms success hands its keys
    /// to the next one rather than losing them.
    #[test]
    fn flush_keys_cover_edits_and_evictions_and_survive_a_failed_flush() {
        let mut cm = CreditManager::new();
        let first = cm.begin_flush();
        assert!(first.full_sync, "nothing is known about disk before one flush lands");
        cm.finish_flush(&first);
        assert!(cm.begin_flush().is_empty(), "a clean manager owes no rows");

        let a = [0x11u8; 16];
        let b = [0x12u8; 16];
        let pk = [0x21u8; 32];
        cm.add_uploaded(a, 0, 10);
        cm.add_ember_uploaded(pk, 10, true);
        let failed = cm.begin_flush();
        assert!(!failed.full_sync);
        assert_eq!(failed.credit_keys, vec![a]);
        assert_eq!(failed.ember_keys, vec![pk]);

        // That flush failed (no `finish_flush`); a later edit joins the retry.
        cm.add_uploaded(b, 0, 10);
        let retry = cm.begin_flush();
        let mut keys = retry.credit_keys.clone();
        keys.sort();
        assert_eq!(keys, vec![a, b], "a failed flush must not drop its rows");
        assert_eq!(retry.ember_keys, vec![pk]);
        cm.finish_flush(&retry);
        assert!(cm.begin_flush().is_empty());

        cm.get_or_create(a).last_seen = chrono::Utc::now().timestamp() - 100 * 86400;
        cm.get_or_create_ember(pk).last_seen = chrono::Utc::now().timestamp() - 100 * 86400;
        let edited = cm.begin_flush();
        cm.finish_flush(&edited);
        cm.cleanup_stale(90);
        let evicted = cm.begin_flush();
        assert_eq!(evicted.credit_keys, vec![a], "an evicted row must be deleted on disk");
        assert_eq!(evicted.ember_keys, vec![pk]);
        assert!(cm.get_record(&a).is_none() && cm.get_ember_record(&pk).is_none());
    }

    /// A flush that finishes after a newer one has begun must not settle the
    /// newer one's keys: if the newer flush then fails, they would be in
    /// neither set and never reach SQLite.
    #[test]
    fn an_older_flush_finishing_late_cannot_settle_a_newer_ones_keys() {
        let mut cm = CreditManager::new();
        let a = [0x31u8; 16];
        let b = [0x32u8; 16];

        let startup = cm.begin_flush();
        cm.add_uploaded(a, 0, 10);
        let periodic = cm.begin_flush();
        assert!(periodic.full_sync, "nothing has confirmed the first sync yet");
        cm.finish_flush(&startup);
        // `periodic` fails: no `finish_flush`.
        let retry = cm.begin_flush();
        assert!(retry.full_sync, "a stale finish must not cancel the pending full sync");
        cm.finish_flush(&retry);
        assert!(cm.begin_flush().is_empty(), "the latest flush settles everything");

        cm.add_uploaded(a, 0, 10);
        let older = cm.begin_flush();
        cm.add_uploaded(b, 0, 10);
        let _newer = cm.begin_flush();
        cm.finish_flush(&older);
        // `newer` fails.
        let mut keys = cm.begin_flush().credit_keys;
        keys.sort();
        assert_eq!(keys, vec![a, b], "keys handed to the failed newer flush must survive");
    }

    /// The credit map must stay bounded under user_hash churn (a peer
    /// rotating its hash across reconnects, seeding one record per OP_PUBLICKEY)
    /// even between 90-day cleanup sweeps. See MAX_CREDIT_RECORDS.
    #[test]
    fn credits_map_is_bounded() {
        let mut cm = CreditManager::new();
        for i in 0..(MAX_CREDIT_RECORDS as u64 + 50) {
            let mut h = [0u8; 16];
            h[..8].copy_from_slice(&i.to_le_bytes());
            cm.get_or_create(h);
        }
        assert!(
            cm.credits.len() <= MAX_CREDIT_RECORDS,
            "credit map ({}) must stay within MAX_CREDIT_RECORDS ({})",
            cm.credits.len(),
            MAX_CREDIT_RECORDS,
        );
    }

    #[test]
    fn eviction_at_capacity_drops_the_least_recently_seen_record() {
        let key = |i: u64| {
            let mut h = [0u8; 16];
            h[..8].copy_from_slice(&i.to_le_bytes());
            h[15] = 1;
            h
        };
        let mut cm = CreditManager::new();
        let now = chrono::Utc::now().timestamp();
        for i in 0..MAX_CREDIT_RECORDS as u64 {
            cm.get_or_create(key(i)).last_seen = now;
        }
        // Rewritten through the `&mut` behind the index's back, the way the
        // startup loader restores persisted timestamps before its sweep.
        cm.get_or_create(key(777)).last_seen = now - 10 * 86400;
        cm.get_or_create(key(42)).last_seen = now - 20 * 86400;
        cm.cleanup_stale(90);
        let settled = cm.begin_flush();
        cm.finish_flush(&settled);

        cm.get_or_create(key(u64::MAX));
        assert_eq!(cm.credits.len(), MAX_CREDIT_RECORDS);
        assert!(cm.get_record(&key(42)).is_none(), "oldest record is evicted");
        assert!(cm.get_record(&key(777)).is_some());
        let flush = cm.begin_flush();
        assert!(
            flush.credit_keys.contains(&key(42)),
            "an evicted row must still reach the flush so SQLite deletes it"
        );
        cm.finish_flush(&flush);

        cm.get_or_create(key(u64::MAX - 1));
        assert!(cm.get_record(&key(777)).is_none(), "next oldest goes next");
        assert!(cm.get_record(&key(u64::MAX)).is_some());
    }

    #[test]
    fn loading_past_the_cap_keeps_the_most_recently_seen_records() {
        let key = |i: u64| {
            let mut h = [0u8; 16];
            h[..8].copy_from_slice(&i.to_le_bytes());
            h[15] = 3;
            h
        };
        let now = chrono::Utc::now().timestamp();
        let extra = 100u64;
        let total = MAX_CREDIT_RECORDS as u64 + extra;
        // Ages are a permutation of 0..total in an order unrelated to the
        // keys, as SQLite hands rows back in no particular age order.
        let age_of = |i: u64| ((i * 7919) % total) as i64;
        let mut cm = CreditManager::new();
        for i in 0..total {
            let mut record = CreditRecord::new(key(i));
            record.last_seen = now - age_of(i);
            record.uploaded = i;
            cm.insert_loaded_credit(record);
        }
        assert_eq!(cm.credits.len(), MAX_CREDIT_RECORDS);
        let cutoff = now - (MAX_CREDIT_RECORDS as i64 - 1);
        for i in 0..total {
            let kept = cm.get_record(&key(i)).is_some();
            assert_eq!(
                kept,
                now - age_of(i) >= cutoff,
                "row {i} (age {}s) kept={kept}",
                age_of(i)
            );
        }

        let flush = cm.begin_flush();
        assert!(flush.full_sync, "the first flush still reconciles the whole table");
        let mut ember_cm = CreditManager::new();
        for i in 0..10u64 {
            let mut pk = [0u8; 32];
            pk[..8].copy_from_slice(&i.to_le_bytes());
            let mut record = EmberCreditRecord::new(pk);
            record.last_seen = now - i as i64;
            ember_cm.insert_loaded_ember_credit(record);
        }
        assert!(
            !ember_cm.is_dirty(),
            "rows that fit and match disk are not queued for a rewrite"
        );
        assert_eq!(ember_cm.get_ember_record(&[0u8; 32]).map(|r| r.last_seen), Some(now));
    }

    #[test]
    fn eviction_skips_a_record_touched_since_it_was_oldest() {
        let key = |i: u64| {
            let mut h = [0u8; 16];
            h[..8].copy_from_slice(&i.to_le_bytes());
            h[15] = 2;
            h
        };
        let mut cm = CreditManager::new();
        let now = chrono::Utc::now().timestamp();
        for i in 0..MAX_CREDIT_RECORDS as u64 {
            cm.get_or_create(key(i)).last_seen = now - 1_000 + (i % 500) as i64;
        }
        cm.cleanup_stale(90);
        // key(0) is among the oldest until it is seen again.
        cm.add_uploaded(key(0), 0, 1);
        cm.get_or_create(key(u64::MAX));
        assert!(cm.get_record(&key(0)).is_some(), "a freshly seen record survives");
        assert_eq!(cm.credits.len(), MAX_CREDIT_RECORDS);
    }

    /// A friend's session proves its key, not the eD2K hash it names, so it
    /// may not take over a hash already bound to someone else.
    #[test]
    fn a_claimed_user_hash_never_displaces_another_identitys_binding() {
        let mut cm = CreditManager::new();
        let victim = [0x53u8; 16];
        let victim_ember = [0x64u8; 16];
        let friend_ember = [0x65u8; 16];
        assert!(cm.claim_ember_hash(victim, victim_ember, |_| false), "unbound: taken");
        assert!(cm.claim_ember_hash(victim, victim_ember, |_| false), "same identity: fine");
        assert!(!cm.claim_ember_hash(victim, friend_ember, |_| false));
        assert_eq!(cm.get_record(&victim).and_then(|r| r.ember_hash), Some(victim_ember));
        // An identity that is no longer a friend gives the hash up.
        assert!(cm.claim_ember_hash(victim, friend_ember, |bound| bound == victim_ember));
        assert_eq!(cm.persisted_ember_hash(&victim), Some(friend_ember));
    }

    #[test]
    fn binding_only_ember_hash_is_session_scoped_and_never_displaces_a_persisted_one() {
        let mut cm = CreditManager::new();
        let friend_user_hash = [0x51u8; 16];
        let friend_ember = [0x61u8; 16];
        let attacker_ember = [0x62u8; 16];
        cm.set_ember_hash(friend_user_hash, friend_ember);

        cm.note_bound_ember_hash(friend_user_hash, attacker_ember, 0x0A00_0009);
        assert_eq!(cm.find_ember_by_user_hash(&friend_user_hash), Some(friend_ember));
        assert_eq!(cm.find_user_hash_by_ember(&friend_ember), Some(friend_user_hash));
        assert_eq!(cm.find_user_hash_by_ember(&attacker_ember), None);
        assert_eq!(
            cm.get_record(&friend_user_hash).and_then(|r| r.ember_hash),
            Some(friend_ember)
        );

        let stranger = [0x52u8; 16];
        let stranger_ember = [0x63u8; 16];
        cm.note_bound_ember_hash(stranger, stranger_ember, 0x0A00_0009);
        assert_eq!(cm.find_ember_by_user_hash(&stranger), Some(stranger_ember));
        assert_eq!(cm.find_user_hash_by_ember(&stranger_ember), Some(stranger));
        assert!(
            cm.get_record(&stranger).is_none(),
            "a binding-only mapping must not create a persisted credit row"
        );
    }

    /// A binding is kept for display only once SecIdent has proven, this run,
    /// that the same address owns the user hash — whichever proof lands first.
    #[test]
    fn a_binding_is_kept_for_display_only_once_secident_vouches_for_its_address() {
        let ip = 0x0A00_0001;
        let ember = [0x71u8; 16];

        // SecIdent first, then the binding from the same address.
        let mut cm = CreditManager::new();
        let peer = [0x41u8; 16];
        cm.set_ident_state(peer, IdentState::Verified);
        cm.check_identity_ip(peer, ip);
        cm.note_bound_ember_hash(peer, ember, ip);
        let record = cm.get_record(&peer).expect("record");
        assert_eq!(record.proven_ember_hash, Some(ember));
        assert_eq!(record.ember_hash, None, "the friend link is left alone");

        // The binding first, then SecIdent from the same address.
        let late = [0x42u8; 16];
        cm.note_bound_ember_hash(late, ember, ip);
        assert_eq!(cm.get_record(&late).and_then(|r| r.proven_ember_hash), None);
        cm.set_ident_state(late, IdentState::Verified);
        cm.check_identity_ip(late, ip);
        assert_eq!(cm.get_record(&late).and_then(|r| r.proven_ember_hash), Some(ember));

        // A binding from another address than the one SecIdent proved is not
        // vouched for: the user hash travels in the clear.
        let claimed = [0x43u8; 16];
        cm.set_ident_state(claimed, IdentState::Verified);
        cm.check_identity_ip(claimed, ip);
        cm.note_bound_ember_hash(claimed, [0x72u8; 16], 0x0A00_0002);
        assert_eq!(cm.get_record(&claimed).and_then(|r| r.proven_ember_hash), None);

        // Nor is one SecIdent has not verified at all.
        let unverified = [0x44u8; 16];
        cm.get_or_create(unverified);
        cm.note_bound_ember_hash(unverified, ember, ip);
        assert_eq!(cm.get_record(&unverified).and_then(|r| r.proven_ember_hash), None);
    }

    // ---- Ember credit tests ----

    /// Unverified peers cannot farm Ember credit — the `add_ember_uploaded`
    /// and `add_ember_downloaded` helpers must reject writes when
    /// `verified == false`. Without this check a hash-spoofer could
    /// claim a verified friend's pubkey on the wire and burn
    /// their real reputation by uploading garbage in their name.
    #[test]
    fn ember_credit_writes_require_verification() {
        let mut cm = CreditManager::new();
        let pk = [0xEBu8; 32];

        assert!(
            !cm.add_ember_uploaded(pk, 4096, false),
            "unverified upload must be rejected"
        );
        assert!(
            !cm.add_ember_downloaded(pk, 4096, false),
            "unverified download must be rejected"
        );
        assert!(
            cm.get_ember_record(&pk).is_none(),
            "rejected writes must not create a record"
        );

        assert!(cm.add_ember_uploaded(pk, 4096, true));
        assert!(cm.add_ember_downloaded(pk, 2048, true));
        let r = cm.get_ember_record(&pk).expect("verified writes must land");
        assert_eq!(r.uploaded, 4096);
        assert_eq!(r.downloaded, 2048);
        assert!(r.ident_verified, "verified writes must set ident_verified");
    }

    /// `record_ember_session` tracks completion + speed EWMA. A first
    /// session seeds the EWMA directly (no smoothing with the zero
    /// default) so the ratio is honest on cold start.
    #[test]
    fn record_ember_session_seeds_ewma_on_first_sample() {
        let mut cm = CreditManager::new();
        let pk = [0xC0u8; 32];

        // Short/fast session — 1 MiB over 10s = ~104857 bytes/sec.
        // Below the 5s floor this would be dropped; above it the
        // first real sample should seed the EWMA directly.
        cm.record_ember_session(pk, 1_048_576, 10, true, true);
        let r = cm.get_ember_record(&pk).unwrap();
        assert_eq!(r.total_sessions, 1);
        assert_eq!(r.completed_sessions, 1);
        let expected = (1_048_576_f64 / 10.0).round() as u64;
        assert_eq!(
            r.avg_upload_speed, expected,
            "first sample must seed EWMA without prior-zero mixing"
        );
    }

    /// Subsequent sessions smooth with `EMBER_SPEED_EWMA_ALPHA` so a
    /// single outlier can't yank the long-run estimate. A fast
    /// session after a slow one should move the average but not
    /// all the way to the new value.
    #[test]
    fn record_ember_session_ewma_smooths_subsequent_samples() {
        let mut cm = CreditManager::new();
        let pk = [0xA1u8; 32];

        cm.record_ember_session(pk, 100 * 1024, 10, true, true);
        let base = cm.get_ember_record(&pk).unwrap().avg_upload_speed;

        // Now a 10× faster session. The EWMA should move upward but
        // well short of the full 10× — with α = 0.3, expect roughly
        // 0.3 × fast + 0.7 × base.
        cm.record_ember_session(pk, 1000 * 1024, 10, true, true);
        let after = cm.get_ember_record(&pk).unwrap().avg_upload_speed;
        assert!(after > base, "fast session should pull average up");
        let new_sample = 1000u64 * 1024 / 10;
        assert!(
            after < new_sample,
            "α=0.3 smoothing must NOT fully adopt the new sample (got {after}, new {new_sample})",
        );
    }

    /// Too-short sessions skip the EWMA update (noise dominates) but
    /// still count toward total_sessions / completed_sessions so
    /// reliability doesn't get hidden for rapid disconnects.
    #[test]
    fn record_ember_session_skips_ewma_for_tiny_sessions() {
        let mut cm = CreditManager::new();
        let pk = [0x07u8; 32];

        cm.record_ember_session(pk, 99_999, 1, false, true);
        let r = cm.get_ember_record(&pk).unwrap();
        assert_eq!(r.total_sessions, 1);
        assert_eq!(
            r.completed_sessions, 0,
            "aborted session must NOT count completed"
        );
        assert_eq!(
            r.avg_upload_speed, 0,
            "sub-threshold sessions must NOT touch EWMA"
        );
    }

    /// `cleanup_stale` prunes the Ember table in lockstep with the
    /// eMule table so one doesn't silently outlast the other.
    #[test]
    fn cleanup_stale_also_prunes_ember_records() {
        let mut cm = CreditManager::new();
        let fresh = [0xF0u8; 32];
        let stale = [0x5Au8; 32];
        let now = chrono::Utc::now().timestamp();
        cm.get_or_create_ember(fresh).last_seen = now;
        cm.get_or_create_ember(stale).last_seen = now - 100 * 86400;

        cm.cleanup_stale(90);
        assert!(cm.get_ember_record(&fresh).is_some());
        assert!(cm.get_ember_record(&stale).is_none());
    }

    /// Regression for the "Known Clients IP + country flag disappear after
    /// relaunch" bug: `ident_ip` and `ident_state` must survive a
    /// serialize → load round-trip through the versioned clients.met cache.
    #[test]
    fn clients_met_roundtrip_preserves_ident_fields() {
        let mut cm = CreditManager::new();
        let hash = [0x42u8; 16];
        {
            let r = cm.get_or_create(hash);
            r.uploaded = 4096; // pass the >0 serialize filter
            r.downloaded = 8192;
            r.last_seen = 1_700_000_123;
            r.ident_ip = 0x0102_0304;
            r.ident_state = IdentState::Verified;
            r.public_key = vec![0xAB; 12];
        }
        let bytes = cm.serialize();
        // Sanity: the versioned magic must lead the buffer.
        assert_eq!(&bytes[0..4], &CLIENTS_MET_MAGIC.to_le_bytes());

        let path = std::env::temp_dir().join(format!(
            "ember_clients_met_roundtrip_{}_{}.met",
            std::process::id(),
            unique_nanos(),
        ));
        std::fs::write(&path, &bytes).expect("write temp clients.met");

        let mut loaded = CreditManager::new();
        let n = loaded
            .load_from_file(&path)
            .expect("load versioned clients.met");
        let _ = std::fs::remove_file(&path);

        assert_eq!(n, 1);
        let rec = loaded.get_record(&hash).expect("record must load");
        assert_eq!(rec.ident_ip, 0x0102_0304, "ident_ip must survive restart");
        // Identification is per session, as in eMule: the peer proves its key
        // again, and the anchor keeps its totals through that.
        assert_eq!(
            rec.ident_state,
            IdentState::Needed,
            "a verified peer must identify again after a restart"
        );
        assert!(rec.crypto_verified_once, "the anchor must survive restart");
        assert_eq!(rec.uploaded, 4096);
        assert_eq!(rec.downloaded, 8192);
        assert_eq!(rec.last_seen, 1_700_000_123);
        assert_eq!(rec.public_key, vec![0xAB; 12]);
    }

    /// The v2 Ember-identity binding (`ember_hash`) must survive a
    /// serialize → load round-trip, including for a record that has zero
    /// credits — this is what lets friend rendezvous discovery relocate
    /// download sources for a friend on a fresh launch, before any
    /// upload/download has happened this session (see
    /// `reseed_friend_endpoint` in `network/mod.rs`).
    #[test]
    fn clients_met_v2_roundtrip_preserves_ember_hash_even_with_zero_credits() {
        let mut cm = CreditManager::new();
        let bound_hash = [0x11u8; 16];
        let unbound_hash = [0x22u8; 16];
        let ember_id = [0x99u8; 16];
        cm.set_ember_hash(bound_hash, ember_id);
        // Zero credits — would have been dropped entirely under the old
        // "uploaded > 0 || downloaded > 0" filter.
        assert_eq!(cm.get_or_create(bound_hash).uploaded, 0);
        // A record with no Ember binding and zero credits must still be
        // dropped, same as before.
        let _ = cm.get_or_create(unbound_hash);

        let bytes = cm.serialize();
        assert_eq!(bytes[4], CLIENTS_MET_VERSION);

        let path = std::env::temp_dir().join(format!(
            "ember_clients_met_v2_ember_hash_{}_{}.met",
            std::process::id(),
            unique_nanos(),
        ));
        std::fs::write(&path, &bytes).expect("write temp clients.met");

        let mut loaded = CreditManager::new();
        let n = loaded.load_from_file(&path).expect("load v2 clients.met");
        let _ = std::fs::remove_file(&path);

        assert_eq!(n, 1, "only the ember-bound record should be persisted");
        let rec = loaded.get_record(&bound_hash).expect("record must load");
        assert_eq!(rec.ember_hash, Some(ember_id));
        assert_eq!(
            loaded.find_user_hash_by_ember(&ember_id),
            Some(bound_hash),
            "reverse lookup must work after a restart"
        );
        // The user_hash → Ember direction must survive the same round trip.
        // Friend transfer escalation depends on it: after a relaunch the
        // in-memory download-to-friend binding is gone, so a failed source is
        // recognised as a friend only by resolving its stored user hash back to
        // an Ember identity.
        assert_eq!(
            loaded.find_ember_by_user_hash(&bound_hash),
            Some(ember_id),
            "forward lookup must work after a restart"
        );
        assert!(loaded.get_record(&unbound_hash).is_none());
    }

    #[test]
    fn find_ember_by_user_hash_ignores_unbound_and_sentinel_hashes() {
        let mut cm = CreditManager::new();
        let bound = [0x31u8; 16];
        let unbound = [0x32u8; 16];
        let ember_id = [0x41u8; 16];
        cm.set_ember_hash(bound, ember_id);
        let _ = cm.get_or_create(unbound);

        assert_eq!(cm.find_ember_by_user_hash(&bound), Some(ember_id));
        assert_eq!(
            cm.find_ember_by_user_hash(&unbound),
            None,
            "a peer we have never bound to an Ember identity is not a friend"
        );
        assert_eq!(cm.find_ember_by_user_hash(&[0u8; 16]), None);
        assert_eq!(
            cm.find_ember_by_user_hash(&[0x99u8; 16]),
            None,
            "an unknown user hash must not resolve"
        );
    }

    /// A pre-v1 (legacy) clients.met — count-prefixed, no ident fields — must
    /// still load on a new build, defaulting ident_ip/ident_state. This keeps
    /// users upgrading from an older build from losing their credit ledger.
    #[test]
    fn clients_met_legacy_format_still_loads() {
        let hash = [0x7Fu8; 16];
        let public_key = vec![0xCDu8; 6];
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&1u32.to_le_bytes()); // count
        legacy.extend_from_slice(&hash);
        legacy.extend_from_slice(&2048u64.to_le_bytes()); // uploaded
        legacy.extend_from_slice(&1024u64.to_le_bytes()); // downloaded
        legacy.extend_from_slice(&1_699_999_999i64.to_le_bytes()); // last_seen
        legacy.extend_from_slice(&(public_key.len() as u16).to_le_bytes());
        legacy.extend_from_slice(&public_key);

        let path = std::env::temp_dir().join(format!(
            "ember_clients_met_legacy_{}_{}.met",
            std::process::id(),
            unique_nanos(),
        ));
        std::fs::write(&path, &legacy).expect("write legacy clients.met");

        let mut cm = CreditManager::new();
        let n = cm.load_from_file(&path).expect("load legacy clients.met");
        let _ = std::fs::remove_file(&path);

        assert_eq!(n, 1);
        let rec = cm.get_record(&hash).expect("legacy record must load");
        assert_eq!(rec.uploaded, 2048);
        assert_eq!(rec.downloaded, 1024);
        assert_eq!(rec.last_seen, 1_699_999_999);
        assert_eq!(rec.public_key, public_key);
        assert_eq!(rec.ident_ip, 0, "legacy rows default ident_ip to 0");
        assert_eq!(
            rec.ident_state,
            IdentState::Unknown,
            "legacy rows default to Unknown"
        );
    }

    #[test]
    fn load_or_create_keypair_restores_interrupted_replace() {
        let dir = std::env::temp_dir().join(format!(
            "ember-cryptkey-recover-{}-{}",
            std::process::id(),
            unique_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut first = CreditManager::new();
        first.load_or_create_keypair(&dir);
        let path = dir.join("cryptkey.dat");
        let original = std::fs::read(&path).expect("keypair must be written");
        let bak = path.with_file_name("cryptkey.dat.ember-replace-bak");
        std::fs::rename(&path, &bak).unwrap();

        let mut second = CreditManager::new();
        second.load_or_create_keypair(&dir);
        let restored = std::fs::read(&path).expect("bak must be restored to cryptkey.dat");
        assert_eq!(
            restored, original,
            "interrupted replace must not mint a replacement SecIdent key"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_cryptkey_refuses_all_credits() {
        let dir = std::env::temp_dir().join(format!(
            "ember-cryptkey-corrupt-{}-{}",
            std::process::id(),
            unique_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cryptkey.dat"), b"not-a-keypair").unwrap();
        let mut cm = CreditManager::new();
        cm.load_or_create_keypair(&dir);
        assert!(cm.crypto_unreadable());
        assert_eq!(cm.secident_status(), "broken");
        let peer = [0x33u8; 16];
        assert!(!cm.add_uploaded(peer, 0, 2_000_000));
        assert_eq!(cm.get_score_ratio(&peer, 0), MIN_CREDIT_RATIO);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Issue 126: eMule's `cryptkey.dat` copied into the data folder used to be
    /// quarantined as corrupt, leaving SecIdent off and the user's credits on
    /// the network unreachable.
    #[test]
    fn an_emule_cryptkey_dropped_in_is_adopted_and_rewritten() {
        use base64::Engine as _;
        use rsa::pkcs8::EncodePrivateKey;
        let dir = std::env::temp_dir().join(format!(
            "ember-cryptkey-emule-{}-{}",
            std::process::id(),
            unique_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 384).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(key.to_pkcs8_der().unwrap().as_bytes());
        let wrapped: String = b64
            .as_bytes()
            .chunks(72)
            .map(|line| format!("{}\n", String::from_utf8_lossy(line)))
            .collect();
        std::fs::write(dir.join("cryptkey.dat"), &wrapped).unwrap();

        let mut cm = CreditManager::new();
        cm.load_or_create_keypair(&dir);
        assert!(!cm.crypto_unreadable());
        let adopted = cm.our_public_key().to_vec();
        assert!(dir.join("cryptkey.dat.emule").exists(), "the original is kept");

        let mut again = CreditManager::new();
        again.load_or_create_keypair(&dir);
        assert_eq!(again.our_public_key(), adopted.as_slice(), "rewritten in Ember's layout");

        let bits_512 = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 512).unwrap();
        assert!(decode_emule_cryptkey(bits_512.to_pkcs8_der().unwrap().as_bytes()).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
