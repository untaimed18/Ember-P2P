//! Persistent uniqueness store for Channel usernames and room names.
//!
//! This is a directory, not an authority over chat: the file records who
//! claimed a handle and which public names are listed. Join secrets, content
//! keys, and author signatures stay on the clients.

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use serde::{Deserialize, Serialize};

pub const USERNAME_MAX: usize = 12;
pub const CHANNEL_NAME_MAX: usize = 64;
pub const USERNAME_MIN: usize = 2;
/// Drop a quiet public listing from Discover after this long. The name stays
/// reserved until [`NAME_RELEASE_SECS`] so a successor still has the year-long
/// claim window, without leaving dead rooms in the directory forever.
pub const CHANNEL_DIRECTORY_STALE_SECS: i64 = 7 * 24 * 60 * 60;
/// Free an abandoned room name after this long without an owner refresh, so a
/// dead room cannot reserve a word forever. Matches the longest succession
/// window, which is the most silence an owner can ask members to tolerate.
/// A room with a nominee is held longer; see [`NOMINEE_GRACE_SECS`].
pub const NAME_RELEASE_SECS: i64 = 365 * 24 * 60 * 60;
/// How long a nominated room's name outlives the moment its nominee becomes
/// eligible to take it.
///
/// Without it a [`CLAIM_AFTER_DAYS_MAX`] nomination became eligible at the
/// same second the record was reaped, and every claim reaps first, so any
/// stranger's claim could free and take the name before the nominee's
/// handover landed. The grace gives the nominee's client time to notice the
/// owner has gone quiet and act.
pub const NOMINEE_GRACE_SECS: i64 = 30 * 24 * 60 * 60;
/// How long a room's previous name stays reserved to it after a rename.
///
/// Members on older builds, stale invite links and Discover records still in
/// the DHT go on showing the old name for a while. Freeing it at once would let
/// anyone claim it in that window and be taken for the room that just left it.
/// The owner may rename back to it until then.
pub const RETIRED_NAME_HOLD_SECS: i64 = 30 * 24 * 60 * 60;
/// Least time between two renames of one room. A room that keeps changing its
/// name is one its members stop recognising.
pub const RENAME_INTERVAL_SECS: i64 = 24 * 60 * 60;
/// Retired names one room may hold at once. Each is a name nobody else can
/// claim for [`RETIRED_NAME_HOLD_SECS`], so without a ceiling a room renaming
/// once a day could sit on thirty names at a time. Past it the oldest is freed
/// outright: it is the one members and stale links are least likely to still
/// show.
pub const MAX_RETIRED_NAMES: usize = 3;
/// Free a Channel username that has not been seen in a room for this long.
pub const USERNAME_IDLE_SECS: i64 = 365 * 24 * 60 * 60;
/// Silence windows a nomination may carry, mirroring the range the clients
/// clamp to. Outside it the registry and the members would disagree about when
/// a room has actually changed hands.
pub const CLAIM_AFTER_DAYS_MIN: u32 = 7;
pub const CLAIM_AFTER_DAYS_MAX: u32 = 365;

/// Hard ceilings on the registry maps, in the spirit of `MAX_STORE_ENTRIES`
/// and friends in `main.rs`.
///
/// Every other shared map on this server is bounded; these were not, and two
/// endpoints write into them from unauthenticated requests whose only cost is
/// generating a throwaway keypair. A username claim is retained for
/// [`USERNAME_IDLE_SECS`] and a tombstone is retained forever, so unbounded
/// growth here is permanent: it does not recover when the flood stops, and
/// because every flush rewrites the whole document, every later flush pays for
/// the accumulated size.
///
/// Refusing past the cap rather than evicting is deliberate. Evicting a
/// username hands someone else's handle to whoever asks next, and evicting a
/// tombstone un-deletes a room its owner destroyed — both worse than refusing
/// a claim. The rate limits on the two writing endpoints are what keep an
/// honest deployment from ever reaching these numbers.
pub const MAX_USERNAMES: usize = 100_000;
pub const MAX_CHANNEL_NAMES: usize = 100_000;
pub const MAX_DELETED: usize = 100_000;

/// Listings per `/v4/channels/directory` page. A listing is at most ~270 bytes
/// of JSON (32 + 64 hex characters of ids plus a 64-byte display name that
/// escaping can at most double), so a full page stays well under the client's
/// 256 KiB response bound — including for clients that predate paging and
/// only ever read the first page.
pub const DIRECTORY_PAGE_SIZE: usize = 500;
/// Listings the directory serves in total, across all pages, in rank order.
/// Matches what a paging client follows (ten pages).
pub const MAX_DIRECTORY_LISTINGS: usize = 5_000;
/// A cached ranking is rebuilt at least this often, since listings drop out on
/// age as well as on writes.
const DIRECTORY_CACHE_MAX_AGE_SECS: i64 = 60;
/// Writes invalidate the cached ranking, but it is rebuilt no more often than
/// this: a rebuild is a scan of every name, and every owner refresh is a write.
const DIRECTORY_REBUILD_MIN_SECS: i64 = if cfg!(test) { 0 } else { 2 };

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelNameRecord {
    pub channel_id: String,
    pub pubkey: String,
    pub private: bool,
    pub deleted: bool,
    /// Original casing after stripping controls. Empty in files written
    /// before this field existed; the directory then falls back to the
    /// normalised map key.
    #[serde(default)]
    pub display: String,
    /// Unix seconds of the last signed name claim. 0 in files written before
    /// this field existed; load grandfathers those to "now" so a deploy does
    /// not reap every existing room.
    #[serde(default)]
    pub refreshed_at: i64,
    /// User pubkey (64-char hex) the owner nominated to inherit the room, or
    /// empty. Lets the nominee move the name to their successor room once the
    /// owner has been silent for `claim_after_days`, mirroring the takeover
    /// rule the members enforce over the DHT.
    #[serde(default)]
    pub nominee: String,
    /// Days of owner silence before `nominee` may move the name. 0 disables it.
    #[serde(default)]
    pub claim_after_days: u32,
    /// Unix seconds the name was first claimed; kept across handovers. Ranks
    /// the directory by seniority. 0 in files written before this field
    /// existed, which ranks those rooms ahead of every newer one.
    #[serde(default)]
    pub created_at: i64,
    /// Channel id this name was last handed over from, or empty. Lets a
    /// retried handover recognise that it already happened.
    #[serde(default)]
    pub handed_over_from: String,
    /// Unix seconds this stopped being the room's name, or 0 while it is. A
    /// retired name is not listed and cannot be claimed by another room until
    /// [`RETIRED_NAME_HOLD_SECS`] have passed.
    #[serde(default)]
    pub retired_at: i64,
    /// Unix seconds of the rename that gave the room this name, or 0 if it
    /// was never renamed. Enforces [`RENAME_INTERVAL_SECS`].
    #[serde(default)]
    pub renamed_at: i64,
    /// User key of the nominee whose takeover bound this name to its current
    /// channel, or empty (an explicit transfer, whose new owner's user key the
    /// registry never learns, or a record older than this field). A handover
    /// retry signed by this key counts as the successor being alive, as does
    /// one signed by the successor room's own key; see
    /// [`ChannelRegistry::handover_channel_name`]. Records written while the
    /// first retry after an explicit transfer named it keep whom it named.
    #[serde(default)]
    pub inheritor: String,
}

impl ChannelNameRecord {
    fn has_nominee(&self) -> bool {
        self.claim_after_days > 0 && !self.nominee.is_empty()
    }

    /// The room's current name: neither destroyed nor left behind by a rename.
    fn is_current(&self) -> bool {
        !self.deleted && self.retired_at == 0
    }

    /// Whether the owner has been silent long enough that the name is free.
    fn abandoned(&self, now: i64) -> bool {
        if self.deleted {
            return false;
        }
        if self.retired_at > 0 {
            return now.saturating_sub(self.retired_at) > RETIRED_NAME_HOLD_SECS;
        }
        let ts = if self.refreshed_at > 0 {
            self.refreshed_at
        } else {
            now
        };
        now.saturating_sub(ts) > self.release_after_secs()
    }

    /// Owner silence after which [`ChannelRegistry::reap_stale`] frees the name.
    fn release_after_secs(&self) -> i64 {
        if !self.has_nominee() {
            return NAME_RELEASE_SECS;
        }
        let eligible_after = i64::from(self.claim_after_days).saturating_mul(86_400);
        NAME_RELEASE_SECS.max(eligible_after.saturating_add(NOMINEE_GRACE_SECS))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct DirectoryListing {
    pub channel_id: String,
    pub pubkey: String,
    pub name: String,
}

/// Position in the ranked directory: `(created_at, channel_id)`, which is
/// unique per live listing and never changes while a room holds its name, so
/// "strictly after the last one you saw" pages consistently while rooms come
/// and go. On the wire it is `"<created_at>.<channel_id>"`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DirectoryCursor {
    created_at: i64,
    channel_id: String,
}

impl DirectoryCursor {
    pub fn parse(raw: &str) -> Option<Self> {
        let (created_at, channel_id) = raw.split_once('.')?;
        if created_at.is_empty()
            || created_at.len() > 19
            || !created_at.bytes().all(|b| b.is_ascii_digit())
            || channel_id.len() != 32
            || !channel_id.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return None;
        }
        Some(Self {
            created_at: created_at.parse().ok()?,
            channel_id: channel_id.to_ascii_lowercase(),
        })
    }

    pub fn encode(&self) -> String {
        format!("{}.{}", self.created_at, self.channel_id)
    }
}

#[derive(Debug)]
pub struct DirectoryPage {
    pub channels: Vec<DirectoryListing>,
    /// Present only while listings remain after this page.
    pub next_cursor: Option<String>,
}

#[derive(Debug)]
struct RankedDirectory {
    generation: u64,
    built_at: i64,
    entries: Vec<(DirectoryCursor, DirectoryListing)>,
}

/// The sorted tombstone list `/v4/channels/deleted` pages through, kept like
/// [`RankedDirectory`].
#[derive(Debug)]
struct DeletedIds {
    generation: u64,
    built_at: i64,
    ids: Arc<Vec<String>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct RegistryFile {
    #[serde(default)]
    usernames: HashMap<String, String>,
    #[serde(default)]
    names: HashMap<String, ChannelNameRecord>,
    #[serde(default)]
    deleted: HashSet<String>,
    /// Last activity per user pubkey (64-char hex). Missing keys are
    /// grandfathered on load.
    #[serde(default)]
    username_activity: HashMap<String, i64>,
}

/// Borrowed mirror of [`RegistryFile`] used for writing.
///
/// Building an owned `RegistryFile` would copy all four maps on every flush —
/// including `deleted`, a permanent tombstone set that only ever grows. Serde
/// emits an identical document either way.
///
/// The tombstones themselves are deliberately kept forever: only an owner can
/// destroy a room, and `owner_delete_keeps_the_name_retired` pins that such a
/// name must never become claimable again. Expiring them would be a policy
/// change, not a leak fix.
#[derive(Serialize)]
struct RegistryFileRef<'a> {
    usernames: &'a HashMap<String, String>,
    names: &'a HashMap<String, ChannelNameRecord>,
    deleted: &'a HashSet<String>,
    username_activity: &'a HashMap<String, i64>,
}

#[derive(Debug)]
pub struct ChannelRegistry {
    path: Option<PathBuf>,
    usernames: HashMap<String, String>,
    by_pubkey: HashMap<String, String>,
    names: HashMap<String, ChannelNameRecord>,
    deleted: HashSet<String>,
    username_activity: HashMap<String, i64>,
    /// Lowercase channel id -> keys in `names` whose record names that id,
    /// deleted records included.
    by_channel: HashMap<String, Vec<String>>,
    /// [`confusable_key`] -> keys in `names` with that skeleton, deleted
    /// records included (a lookalike of a retired name stays refused).
    by_skeleton: HashMap<String, Vec<String>>,
    /// Set by every mutation, cleared when a snapshot is taken for writing.
    /// Shared with the [`PersistJob`] so a failed write can re-arm it.
    dirty: Arc<AtomicBool>,
    /// Bumped by every mutation; invalidates the cached directory ranking and
    /// identifies what a [`PersistJob`] covers.
    generation: u64,
    /// Generation of the latest mutation that must be on disk before it is
    /// acknowledged (see [`Self::touch_durable`]).
    durable_generation: u64,
    directory_cache: Mutex<Option<Arc<RankedDirectory>>>,
    deleted_cache: Mutex<Option<DeletedIds>>,
    /// Ticket dispenser and completion gate for [`PersistJob::write`]. See
    /// [`PersistGate`].
    persist_gate: Arc<PersistGate>,
    /// Set when the file on disk could not be read and no backup could stand
    /// in for it. See [`load_registry_file`].
    read_only: bool,
    /// Set once the final shutdown snapshot has been taken: later writes are
    /// refused rather than acknowledged and then lost.
    closed: bool,
}

/// A serialised registry snapshot waiting to be written to disk.
///
/// Taken under the registry lock (a read lock is enough) and written after
/// it is released, on a blocking thread.
pub struct PersistJob {
    gate: Arc<PersistGate>,
    ticket: u64,
    generation: u64,
    path: PathBuf,
    bytes: Vec<u8>,
    dirty: Arc<AtomicBool>,
}

impl PersistJob {
    /// Registry generation this snapshot includes every mutation up to.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Blocking. Returns whether the snapshot (or a newer one) is on disk;
    /// on failure the registry is marked dirty again so the next flush retries.
    pub fn write(self) -> bool {
        let ok = write_registry(&self.gate, self.ticket, &self.path, &self.bytes);
        if !ok {
            self.dirty.store(true, Ordering::Release);
        }
        ok
    }
}

/// Orders the registry's disk writes.
///
/// Snapshots are written on blocking threads, so two can be in flight at
/// once: each takes a monotonic ticket when it is serialised, and a write
/// whose ticket is older than what has already landed is dropped rather than
/// rewinding the file to stale content.
#[derive(Debug)]
struct PersistGate {
    next_ticket: AtomicU64,
    /// Highest ticket already written. Guarded by a blocking mutex because it
    /// is only ever touched from inside `spawn_blocking`.
    written: Mutex<u64>,
}

impl PersistGate {
    fn new() -> Self {
        Self {
            next_ticket: AtomicU64::new(0),
            written: Mutex::new(0),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryError {
    InvalidName,
    Taken,
    Forbidden,
    /// A registry map is at its hard ceiling. Distinct from `Taken` so the
    /// handler can answer 503 rather than 409: nothing is wrong with the name
    /// the caller asked for, the server simply has no room to record it.
    Full,
    /// The registry on disk could not be loaded, so nothing may be written
    /// until an operator restores it. Answered with 503.
    ReadOnly,
    /// The room was renamed less than [`RENAME_INTERVAL_SECS`] ago.
    RenameTooSoon,
}

impl ChannelRegistry {
    fn from_parts(path: Option<PathBuf>, parsed: RegistryFile, read_only: bool) -> Self {
        let mut by_pubkey = HashMap::new();
        for (name, pubkey) in &parsed.usernames {
            by_pubkey.insert(pubkey.to_ascii_lowercase(), name.clone());
        }
        let mut reg = Self {
            path,
            usernames: parsed.usernames,
            by_pubkey,
            names: HashMap::with_capacity(parsed.names.len()),
            deleted: parsed.deleted,
            username_activity: parsed.username_activity,
            by_channel: HashMap::new(),
            by_skeleton: HashMap::new(),
            dirty: Arc::new(AtomicBool::new(false)),
            generation: 0,
            durable_generation: 0,
            directory_cache: Mutex::new(None),
            deleted_cache: Mutex::new(None),
            persist_gate: Arc::new(PersistGate::new()),
            read_only,
            closed: false,
        };
        for (name, rec) in parsed.names {
            reg.insert_name(name, rec);
        }
        reg
    }

    pub fn in_memory() -> Self {
        Self::from_parts(None, RegistryFile::default(), false)
    }

    pub fn load(path: PathBuf) -> Self {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let (parsed, read_only) = load_registry_file(&path);
        let mut reg = Self::from_parts(Some(path), parsed, read_only);
        if reg.grandfather_legacy_timestamps(unix_now()) {
            reg.touch();
        }
        reg
    }

    fn insert_name(&mut self, name: String, rec: ChannelNameRecord) {
        self.by_channel
            .entry(rec.channel_id.to_ascii_lowercase())
            .or_default()
            .push(name.clone());
        self.by_skeleton
            .entry(confusable_key(&name))
            .or_default()
            .push(name.clone());
        self.names.insert(name, rec);
    }

    fn remove_name(&mut self, name: &str) -> Option<ChannelNameRecord> {
        let rec = self.names.remove(name)?;
        detach_name(&mut self.by_channel, &rec.channel_id.to_ascii_lowercase(), name);
        detach_name(&mut self.by_skeleton, &confusable_key(name), name);
        Some(rec)
    }

    /// Keys in `names` whose record names `channel_id` (lowercase).
    fn names_of_channel(&self, channel_id: &str) -> &[String] {
        self.by_channel
            .get(channel_id)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    fn live_name_of_channel(&self, channel_id: &str) -> Option<String> {
        self.names_of_channel(channel_id)
            .iter()
            .find(|name| self.names.get(*name).is_some_and(ChannelNameRecord::is_current))
            .cloned()
    }

    /// Forget every name in `candidates` whose owner has gone quiet for good.
    fn reap_abandoned_names(&mut self, candidates: Vec<String>, now: i64) -> bool {
        let mut changed = false;
        for name in candidates {
            if self.names.get(&name).is_some_and(|rec| rec.abandoned(now)) {
                self.remove_name(&name);
                changed = true;
            }
        }
        changed
    }

    fn username_idle(&self, pubkey: &str, now: i64) -> bool {
        let ts = self.username_activity.get(pubkey).copied().unwrap_or(now);
        now.saturating_sub(ts) > USERNAME_IDLE_SECS
    }

    fn release_username(&mut self, name: &str) -> bool {
        let Some(pk) = self.usernames.remove(name) else {
            return false;
        };
        self.by_pubkey.remove(&pk);
        self.username_activity.remove(&pk);
        true
    }

    /// Whether [`Self::load`] could not read the registry and is refusing
    /// every write for the life of the process.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn writable(&self) -> Result<(), RegistryError> {
        if self.read_only || self.closed {
            Err(RegistryError::ReadOnly)
        } else {
            Ok(())
        }
    }

    /// Record that state changed. Nothing is written here: the owner of the
    /// registry flushes a snapshot on its own schedule (see
    /// [`Self::take_persist_job`]), so a burst of refreshes costs one write.
    fn touch(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        if !self.read_only && self.path.is_some() {
            self.dirty.store(true, Ordering::Release);
        }
    }

    /// Record a change nothing would recreate if it were lost — a new claim, a
    /// tombstone, a handover, a nomination, a privacy change — as opposed to a
    /// refresh the owner repeats anyway. Callers wait for
    /// [`Self::durable_generation`] to reach disk before acknowledging.
    fn touch_durable(&mut self) {
        self.touch();
        if !self.read_only && self.path.is_some() {
            self.durable_generation = self.generation;
        }
    }

    /// Only moves on a registry that persists, so an in-memory registry never
    /// makes a caller wait.
    pub fn durable_generation(&self) -> u64 {
        self.durable_generation
    }

    /// Whether a mutation has not been handed to a [`PersistJob`] yet.
    #[cfg(test)]
    pub fn has_pending_writes(&self) -> bool {
        !self.read_only && self.path.is_some() && self.dirty.load(Ordering::Acquire)
    }

    /// Serialise the registry for writing if anything changed since the last
    /// snapshot. Needs only `&self`, so callers can hold a read lock.
    ///
    /// Tickets follow snapshot order: clearing `dirty` and taking the ticket
    /// both happen under the caller's lock, and a second snapshot can only
    /// find `dirty` set again after a mutation, which needs the write lock
    /// this caller is holding off.
    pub fn take_persist_job(&self) -> Option<PersistJob> {
        if self.read_only {
            return None;
        }
        let path = self.path.as_ref()?;
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return None;
        }
        let file = RegistryFileRef {
            usernames: &self.usernames,
            names: &self.names,
            deleted: &self.deleted,
            username_activity: &self.username_activity,
        };
        let bytes = match serde_json::to_vec(&file) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(%error, "could not serialise the channels registry");
                self.dirty.store(true, Ordering::Release);
                return None;
            }
        };
        let ticket = self.persist_gate.next_ticket.fetch_add(1, Ordering::AcqRel) + 1;
        Some(PersistJob {
            gate: self.persist_gate.clone(),
            ticket,
            generation: self.generation,
            path: path.clone(),
            bytes,
            dirty: self.dirty.clone(),
        })
    }

    /// Refuse every later write. Called under the write lock right before the
    /// final shutdown snapshot, so nothing acknowledged after it can be lost.
    pub fn close_for_shutdown(&mut self) {
        self.closed = true;
    }

    #[cfg(test)]
    pub fn flush_blocking(&self) -> bool {
        self.take_persist_job().is_none_or(PersistJob::write)
    }

    pub fn claim_username(&mut self, pubkey_hex: &str, name: &str) -> Result<(), RegistryError> {
        self.claim_username_at(pubkey_hex, name, unix_now())
    }

    pub fn claim_username_at(
        &mut self,
        pubkey_hex: &str,
        name: &str,
        now: i64,
    ) -> Result<(), RegistryError> {
        self.writable()?;
        let normalized = normalize_username(name).ok_or(RegistryError::InvalidName)?;
        let pk = pubkey_hex.to_ascii_lowercase();
        if pk.len() != 64 || hex::decode(&pk).map(|b| b.len()).unwrap_or(0) != 32 {
            return Err(RegistryError::InvalidName);
        }
        // Only the handle being claimed can change this claim's outcome, so
        // only it is reaped here; the sweeper reaps the rest.
        if self
            .usernames
            .get(&normalized)
            .is_some_and(|owner| self.username_idle(owner, now))
            && self.release_username(&normalized)
        {
            self.touch();
        }
        if let Some(owner) = self.usernames.get(&normalized) {
            if owner.eq_ignore_ascii_case(&pk) {
                self.username_activity.insert(pk, now);
                self.touch();
                return Ok(());
            }
            return Err(RegistryError::Taken);
        }
        if let Some(old) = self.by_pubkey.remove(&pk) {
            self.usernames.remove(&old);
            self.touch();
        }
        // Checked after the rename path above, which is net-neutral on size.
        // At the cap every idle handle is reaped first, so a full map of
        // abandoned handles does not refuse a live claimant.
        if self.usernames.len() >= MAX_USERNAMES {
            self.reap_stale(now);
        }
        if self.usernames.len() >= MAX_USERNAMES {
            tracing::warn!(
                usernames = self.usernames.len(),
                "channel username registry is at its cap; refusing new claims"
            );
            return Err(RegistryError::Full);
        }
        self.usernames.insert(normalized.clone(), pk.clone());
        self.by_pubkey.insert(pk.clone(), normalized);
        self.username_activity.insert(pk, now);
        self.touch_durable();
        Ok(())
    }

    /// Whether this pubkey already holds this username.
    ///
    /// The username counterpart to [`Self::has_channel`], and there for the
    /// same reason: the creation budget should charge for taking a *new*
    /// handle, not for the periodic re-claim that keeps an existing one from
    /// ageing out after [`USERNAME_IDLE_SECS`]. Charging the refresh would
    /// eventually free the handle of a user who is still active.
    pub fn holds_username(&self, pubkey_hex: &str, name: &str) -> bool {
        let Some(normalized) = normalize_username(name) else {
            return false;
        };
        self.usernames
            .get(&normalized)
            .is_some_and(|owner| owner.eq_ignore_ascii_case(pubkey_hex))
    }

    /// Whether this room already holds a name here.
    ///
    /// Lets the creation budget charge for standing a room up without charging
    /// its owner for keeping it: a re-claim of a name the room already has is
    /// the refresh path, and refusing that would eventually free the name of a
    /// room that is very much alive.
    pub fn has_channel(&self, channel_id: &str) -> bool {
        self.live_name_of_channel(&channel_id.to_ascii_lowercase())
            .is_some()
    }

    pub fn claim_channel_name(
        &mut self,
        channel_id: &str,
        pubkey_hex: &str,
        name: &str,
        private: bool,
    ) -> Result<(), RegistryError> {
        self.claim_channel_name_at(channel_id, pubkey_hex, name, private, unix_now())
    }

    pub fn claim_channel_name_at(
        &mut self,
        channel_id: &str,
        pubkey_hex: &str,
        name: &str,
        private: bool,
        now: i64,
    ) -> Result<(), RegistryError> {
        self.writable()?;
        let display = strip_invisible(name);
        let normalized = normalize_channel_name(name).ok_or(RegistryError::InvalidName)?;
        let id = channel_id.to_ascii_lowercase();
        let pk = pubkey_hex.to_ascii_lowercase();
        if id.len() != 32
            || pk.len() != 64
            || hex::decode(&id).map(|b| b.len()).unwrap_or(0) != 16
            || hex::decode(&pk).map(|b| b.len()).unwrap_or(0) != 32
        {
            return Err(RegistryError::InvalidName);
        }
        if self.deleted.contains(&id) {
            return Err(RegistryError::Taken);
        }
        let skeleton = confusable_key(&normalized);
        // Every record the checks below consult: the exact name, this room's
        // own name, and every lookalike. An abandoned one among them must read
        // as free, exactly as if the whole registry had been reaped first —
        // which is what this used to do on every claim. Nominee grace is part
        // of `abandoned`, so a nominated room is not freed early here either.
        let mut candidates = vec![normalized.clone()];
        candidates.extend_from_slice(self.names_of_channel(&id));
        if let Some(lookalikes) = self.by_skeleton.get(&skeleton) {
            candidates.extend_from_slice(lookalikes);
        }
        if self.reap_abandoned_names(candidates, now) {
            self.touch();
        }
        // One name per room. A claim for a different one is refused rather
        // than read as a rename: owners re-claim on a timer with whatever name
        // their device holds, and a stale one — trimmed by an older build,
        // restored from a backup, left by a failed local write — would
        // otherwise rename the room with nobody having asked. Renaming is
        // [`Self::rename_channel_name_at`], and so is going back to a name this
        // room retired: the exact-key block below refuses that here too.
        //
        // The claim is still signed by the room's own key, though, so it says
        // the room is alive, and its name is kept from ageing out. That is all
        // that keeps a successor on a build without the handover retry's room
        // key signature — one whose device holds a name other than this — from
        // losing the name it inherited while still in use.
        if let Some(existing) = self
            .live_name_of_channel(&id)
            .filter(|existing| *existing != normalized)
        {
            if let Some(rec) = self
                .names
                .get_mut(&existing)
                .filter(|rec| rec.pubkey.eq_ignore_ascii_case(&pk))
            {
                rec.refreshed_at = now;
                self.touch();
            }
            return Err(RegistryError::Taken);
        }
        // Reject a name that merely *looks* like one already on record. Scoped
        // to other rooms, so an owner refreshing or re-casing its own claim
        // still passes, and skipped when the exact key already exists because
        // the block below handles that case with the owner check it needs.
        //
        // Tombstones count. The exact-key path below refuses an owner-deleted
        // name permanently, so exempting those rows here would have left a
        // homoglyph of a retired name claimable while the name itself never
        // comes back — the impersonation this check exists to stop, aimed at a
        // room that no longer has an owner to notice.
        if !self.names.contains_key(&normalized)
            && self.by_skeleton.get(&skeleton).is_some_and(|lookalikes| {
                lookalikes.iter().any(|existing| {
                    self.names
                        .get(existing)
                        .is_some_and(|rec| !rec.channel_id.eq_ignore_ascii_case(&id))
                })
            })
        {
            return Err(RegistryError::Taken);
        }
        if let Some(existing) = self.names.get_mut(&normalized) {
            // A retired name of this very room counts as taken here: going
            // back to it is a rename, with the interval that comes with one.
            if existing.deleted
                || existing.retired_at != 0
                || !(existing.channel_id.eq_ignore_ascii_case(&id)
                    && existing.pubkey.eq_ignore_ascii_case(&pk))
            {
                return Err(RegistryError::Taken);
            }
            let changed = existing.private != private || existing.display != display;
            existing.private = private;
            existing.display = display;
            existing.refreshed_at = now;
            if changed {
                self.touch_durable();
            } else {
                self.touch();
            }
            return Ok(());
        }
        // Only reached when this is a genuinely new name — every refresh and
        // re-case path above returns before here — so the cap cannot lock an
        // existing room out of keeping its own claim alive.
        if self.names.len() >= MAX_CHANNEL_NAMES {
            self.reap_stale(now);
        }
        if self.names.len() >= MAX_CHANNEL_NAMES {
            tracing::warn!(
                names = self.names.len(),
                "channel name registry is at its cap; refusing new claims"
            );
            return Err(RegistryError::Full);
        }
        self.insert_name(
            normalized,
            ChannelNameRecord {
                channel_id: id,
                pubkey: pk,
                private,
                deleted: false,
                display,
                refreshed_at: now,
                nominee: String::new(),
                claim_after_days: 0,
                created_at: now,
                handed_over_from: String::new(),
                retired_at: 0,
                renamed_at: 0,
                inheritor: String::new(),
            },
        );
        self.touch_durable();
        Ok(())
    }

    #[cfg(test)]
    pub fn rename_channel_name(
        &mut self,
        channel_id: &str,
        pubkey_hex: &str,
        name: &str,
        private: bool,
    ) -> Result<(), RegistryError> {
        self.rename_channel_name_at(channel_id, pubkey_hex, name, private, unix_now())
    }

    /// Move a room from the name it holds to `name`, signed by the channel key.
    ///
    /// The old name is retired rather than freed, and stays this room's for
    /// [`RETIRED_NAME_HOLD_SECS`] so nobody can take it and pass for the room
    /// while members and links still show it; the owner may rename back to it
    /// in that time. At most once per [`RENAME_INTERVAL_SECS`].
    ///
    /// Asking for the name the room already holds is a refresh (or a
    /// re-casing), so a retry after a lost answer succeeds rather than reading
    /// as a second rename. A room with no name here yet simply claims one.
    pub fn rename_channel_name_at(
        &mut self,
        channel_id: &str,
        pubkey_hex: &str,
        name: &str,
        private: bool,
        now: i64,
    ) -> Result<(), RegistryError> {
        self.writable()?;
        let display = strip_invisible(name);
        let normalized = normalize_channel_name(name).ok_or(RegistryError::InvalidName)?;
        let id = channel_id.to_ascii_lowercase();
        let pk = pubkey_hex.to_ascii_lowercase();
        if id.len() != 32
            || pk.len() != 64
            || hex::decode(&id).map(|b| b.len()).unwrap_or(0) != 16
            || hex::decode(&pk).map(|b| b.len()).unwrap_or(0) != 32
        {
            return Err(RegistryError::InvalidName);
        }
        if self.deleted.contains(&id) {
            return Err(RegistryError::Taken);
        }
        let skeleton = confusable_key(&normalized);
        // The same records the claim path reaps before judging, for the same
        // reason: an abandoned one among them must read as free.
        let mut candidates = vec![normalized.clone()];
        candidates.extend_from_slice(self.names_of_channel(&id));
        if let Some(lookalikes) = self.by_skeleton.get(&skeleton) {
            candidates.extend_from_slice(lookalikes);
        }
        if self.reap_abandoned_names(candidates, now) {
            self.touch();
        }
        let from = match self.live_name_of_channel(&id) {
            Some(from) if from != normalized => from,
            _ => return self.claim_channel_name_at(channel_id, pubkey_hex, name, private, now),
        };
        let Some(current) = self.names.get(&from) else {
            return Err(RegistryError::InvalidName);
        };
        if !current.pubkey.eq_ignore_ascii_case(&pk) {
            return Err(RegistryError::Forbidden);
        }
        if current.renamed_at > 0 && now.saturating_sub(current.renamed_at) < RENAME_INTERVAL_SECS {
            return Err(RegistryError::RenameTooSoon);
        }
        // Lookalikes held by other rooms, tombstones included, exactly as for
        // a claim. Skipped when the exact key is on record; the block below
        // decides that case.
        if !self.names.contains_key(&normalized)
            && self.by_skeleton.get(&skeleton).is_some_and(|lookalikes| {
                lookalikes.iter().any(|existing| {
                    self.names
                        .get(existing)
                        .is_some_and(|rec| !rec.channel_id.eq_ignore_ascii_case(&id))
                })
            })
        {
            return Err(RegistryError::Taken);
        }
        if let Some(existing) = self.names.get(&normalized) {
            // Only one of this room's own retired names may be taken back.
            if existing.deleted
                || existing.retired_at == 0
                || !(existing.channel_id.eq_ignore_ascii_case(&id)
                    && existing.pubkey.eq_ignore_ascii_case(&pk))
            {
                return Err(RegistryError::Taken);
            }
        } else if self.names.len() >= MAX_CHANNEL_NAMES {
            self.reap_stale(now);
            if self.names.len() >= MAX_CHANNEL_NAMES {
                return Err(RegistryError::Full);
            }
        }
        self.apply_rename(&from, normalized, display, private, now);
        self.release_surplus_retired_names(&id);
        self.touch_durable();
        Ok(())
    }

    /// Move a room from the name it holds, `from`, to `to`, retiring `from`.
    ///
    /// What belongs to the room rather than to the word travels with it: its
    /// seniority in the directory, its nominee, the handover it came from.
    /// `to` is either a name not on record or one this room retired earlier;
    /// the caller has checked which.
    fn apply_rename(&mut self, from: &str, to: String, display: String, private: bool, now: i64) {
        let Some(old) = self.names.get_mut(from) else {
            return;
        };
        old.retired_at = now;
        let renamed = ChannelNameRecord {
            channel_id: old.channel_id.clone(),
            pubkey: old.pubkey.clone(),
            private,
            deleted: false,
            display,
            refreshed_at: now,
            nominee: old.nominee.clone(),
            claim_after_days: old.claim_after_days,
            created_at: old.created_at,
            handed_over_from: old.handed_over_from.clone(),
            retired_at: 0,
            renamed_at: now,
            inheritor: old.inheritor.clone(),
        };
        // Replaced in place when it is one of this room's retired names: same
        // key and same room, so neither index needs to move.
        if let Some(existing) = self.names.get_mut(&to) {
            *existing = renamed;
        } else {
            self.insert_name(to, renamed);
        }
    }

    /// Free the oldest of `channel_id`'s retired names past
    /// [`MAX_RETIRED_NAMES`].
    fn release_surplus_retired_names(&mut self, channel_id: &str) {
        let mut retired: Vec<(i64, String)> = self
            .names_of_channel(channel_id)
            .iter()
            .filter_map(|name| {
                let rec = self.names.get(name)?;
                (!rec.deleted && rec.retired_at > 0).then(|| (rec.retired_at, name.clone()))
            })
            .collect();
        if retired.len() <= MAX_RETIRED_NAMES {
            return;
        }
        retired.sort();
        let surplus = retired.len() - MAX_RETIRED_NAMES;
        for (_, name) in retired.into_iter().take(surplus) {
            self.remove_name(&name);
        }
    }

    /// Record who may inherit this room's name, signed by the channel key.
    /// An empty nominee or a zero window clears the nomination.
    pub fn set_channel_nominee(
        &mut self,
        channel_id: &str,
        pubkey_hex: &str,
        nominee_hex: &str,
        claim_after_days: u32,
    ) -> Result<(), RegistryError> {
        self.writable()?;
        let id = channel_id.to_ascii_lowercase();
        let pk = pubkey_hex.to_ascii_lowercase();
        let nominee = nominee_hex.to_ascii_lowercase();
        let clearing = nominee.is_empty() || claim_after_days == 0;
        if !clearing
            && (nominee.len() != 64
                || hex::decode(&nominee).is_err()
                || !(CLAIM_AFTER_DAYS_MIN..=CLAIM_AFTER_DAYS_MAX).contains(&claim_after_days))
        {
            return Err(RegistryError::InvalidName);
        }
        let Some(rec) = self
            .live_name_of_channel(&id)
            .and_then(|name| self.names.get_mut(&name))
        else {
            return Err(RegistryError::InvalidName);
        };
        if !rec.pubkey.eq_ignore_ascii_case(&pk) {
            return Err(RegistryError::Forbidden);
        }
        let (nominee, claim_after_days) = if clearing {
            (String::new(), 0)
        } else {
            (nominee, claim_after_days)
        };
        if rec.nominee == nominee && rec.claim_after_days == claim_after_days {
            return Ok(());
        }
        rec.nominee = nominee;
        rec.claim_after_days = claim_after_days;
        self.touch_durable();
        Ok(())
    }

    /// Move a name from the room that holds it to its successor.
    ///
    /// A handoff mints a fresh channel key, so the successor room has an id the
    /// name has never been bound to and cannot claim it while the old record
    /// stands. `signer_hex` is authorized two ways, matching the two ways a room
    /// changes hands: the outgoing owner's channel key signs an explicit
    /// transfer, or the nominee's user key signs a takeover once the owner has
    /// been silent for the window they published.
    pub fn handover_channel_name(
        &mut self,
        old_channel_id: &str,
        new_channel_id: &str,
        new_pubkey_hex: &str,
        signer_hex: &str,
        now: i64,
    ) -> Result<(), RegistryError> {
        self.writable()?;
        let old_id = old_channel_id.to_ascii_lowercase();
        let new_id = new_channel_id.to_ascii_lowercase();
        let new_pk = new_pubkey_hex.to_ascii_lowercase();
        let signer = signer_hex.to_ascii_lowercase();
        if new_id.len() != 32
            || new_pk.len() != 64
            || hex::decode(&new_id).map(|b| b.len()).unwrap_or(0) != 16
            || hex::decode(&new_pk).map(|b| b.len()).unwrap_or(0) != 32
        {
            return Err(RegistryError::InvalidName);
        }
        if new_id == old_id {
            return Err(RegistryError::InvalidName);
        }
        // A destroyed room does not get to pass its name on, and the successor
        // must not already be holding one — the same one-name-per-room rule
        // `claim_channel_name_at` enforces.
        if self.deleted.contains(&old_id) || self.deleted.contains(&new_id) {
            return Err(RegistryError::Taken);
        }
        if let Some(held) = self.live_name_of_channel(&new_id) {
            // This exact handover already happened, e.g. a retry after its
            // first answer was lost. Anything else holding the successor's
            // name is a conflict.
            let Some(rec) = self.names.get_mut(&held) else {
                return Err(RegistryError::Taken);
            };
            if !(rec.pubkey.eq_ignore_ascii_case(&new_pk)
                && rec.handed_over_from.eq_ignore_ascii_case(&old_id))
            {
                return Err(RegistryError::Taken);
            }
            // A successor whose device holds a name other than the registry's
            // — one an older build trimmed, say — has every name claim
            // refused, falls back to retrying this handover, and ends up here
            // on each refresh pass. That makes this the only request showing
            // the room is alive, so it has to count as a refresh, or the room
            // leaves Discover after a week and loses its name after a year
            // while still in use.
            //
            // Nothing above checked the signer's authority, though, so only a
            // key that speaks for the room now counts; anyone else's request
            // would keep a dead room's name held. That is the successor room's
            // own key, which hashes to the id the name is bound to, or the
            // nominee whose takeover moved it here. Nobody is named from the
            // retries themselves: after an explicit transfer the first key to
            // ask would otherwise become the one whose requests hold the name,
            // and that can be anyone's.
            let successor_signed = channel_id_of_key(&signer).as_deref() == Some(new_id.as_str());
            let inheritor_signed = !rec.inheritor.is_empty() && rec.inheritor == signer;
            if successor_signed || inheritor_signed {
                rec.refreshed_at = now;
                self.touch();
            }
            return Ok(());
        }
        let Some(name) = self.live_name_of_channel(&old_id) else {
            return Err(RegistryError::InvalidName);
        };
        let Some(rec) = self.names.get_mut(&name) else {
            return Err(RegistryError::InvalidName);
        };
        let by_owner = rec.pubkey.eq_ignore_ascii_case(&signer);
        let by_nominee = rec.has_nominee()
            && rec.nominee.eq_ignore_ascii_case(&signer)
            && now.saturating_sub(rec.refreshed_at)
                >= i64::from(rec.claim_after_days).saturating_mul(86_400);
        if !by_owner && !by_nominee {
            return Err(RegistryError::Forbidden);
        }
        let previous_id = rec.channel_id.to_ascii_lowercase();
        // An explicit transfer may go to anyone, not only the nominee, so the
        // registry does not know the new owner's user key; its retries are
        // signed with the successor room's key instead. See the retry above.
        rec.inheritor = if by_nominee { signer.clone() } else { String::new() };
        rec.channel_id = new_id.clone();
        rec.pubkey = new_pk;
        rec.refreshed_at = now;
        rec.handed_over_from = previous_id.clone();
        // The nomination belonged to the previous owner; the new one publishes
        // their own, and leaving it would let the old nominee take the name a
        // second time.
        rec.nominee = String::new();
        rec.claim_after_days = 0;
        detach_name(&mut self.by_channel, &previous_id, &name);
        self.by_channel.entry(new_id).or_default().push(name);
        self.touch_durable();
        Ok(())
    }

    pub fn delete_channel(
        &mut self,
        channel_id: &str,
        pubkey_hex: &str,
    ) -> Result<(), RegistryError> {
        self.writable()?;
        let id = channel_id.to_ascii_lowercase();
        let pk = pubkey_hex.to_ascii_lowercase();
        let held = self.names_of_channel(&id).to_vec();
        if held.iter().any(|name| {
            self.names
                .get(name)
                .is_some_and(|rec| !rec.pubkey.eq_ignore_ascii_case(&pk))
        }) {
            return Err(RegistryError::Forbidden);
        }
        let mut found = false;
        for name in &held {
            if let Some(rec) = self.names.get_mut(name) {
                rec.deleted = true;
                found = true;
            }
        }
        if !found && self.deleted.contains(&id) {
            return Ok(());
        }
        // Tombstones are kept forever by policy (see `RegistryFileRef`), which
        // makes this the one map an attacker can grow permanently — a delete
        // for an id that never had a name claim is accepted on the strength of
        // a freshly generated keypair. Bound it. A room that *does* hold a
        // name is still tombstoned below even at the cap, because its record
        // is already marked deleted and refusing would leave the two
        // disagreeing.
        if !found && self.deleted.len() >= MAX_DELETED {
            tracing::warn!(
                deleted = self.deleted.len(),
                "channel tombstone set is at its cap; refusing to record an unknown id"
            );
            return Err(RegistryError::Full);
        }
        // Owner can tombstone an id even if the name claim never landed, so
        // Discover cannot keep serving a room they have destroyed.
        self.deleted.insert(id);
        self.touch_durable();
        Ok(())
    }

    #[cfg(test)]
    pub fn public_directory(&self) -> Vec<DirectoryListing> {
        self.public_directory_at(unix_now())
    }

    #[cfg(test)]
    pub fn public_directory_at(&self, now: i64) -> Vec<DirectoryListing> {
        self.ranked_directory(now)
            .into_iter()
            .map(|(_, listing)| listing)
            .collect()
    }

    /// Every listing the directory serves, in rank order: oldest claim first,
    /// capped at [`MAX_DIRECTORY_LISTINGS`].
    ///
    /// Seniority rather than recency, because recency is what a flood has: a
    /// script standing up names (and refreshing them) looks exactly as active
    /// as a real room, but it cannot make its names older than rooms that were
    /// already listed. Only rooms whose owner refreshed within
    /// [`CHANNEL_DIRECTORY_STALE_SECS`] are listed at all, so an established
    /// room that has gone quiet stops holding a slot.
    fn ranked_directory(&self, now: i64) -> Vec<(DirectoryCursor, DirectoryListing)> {
        let mut out: Vec<(DirectoryCursor, DirectoryListing)> = self
            .names
            .iter()
            .filter(|(_, rec)| {
                !rec.private
                    && rec.is_current()
                    && !self.deleted.contains(&rec.channel_id)
                    && now.saturating_sub(rec.refreshed_at) <= CHANNEL_DIRECTORY_STALE_SECS
            })
            .map(|(name, rec)| {
                (
                    DirectoryCursor {
                        created_at: rec.created_at.max(0),
                        channel_id: rec.channel_id.to_ascii_lowercase(),
                    },
                    DirectoryListing {
                        channel_id: rec.channel_id.clone(),
                        pubkey: rec.pubkey.clone(),
                        name: if rec.display.is_empty() {
                            name.clone()
                        } else {
                            rec.display.clone()
                        },
                    },
                )
            })
            .collect();
        if out.len() > MAX_DIRECTORY_LISTINGS {
            out.select_nth_unstable_by(MAX_DIRECTORY_LISTINGS - 1, |a, b| a.0.cmp(&b.0));
            out.truncate(MAX_DIRECTORY_LISTINGS);
        }
        out.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// One page of the ranked directory, starting strictly after `cursor`.
    pub fn directory_page(&self, cursor: Option<&DirectoryCursor>, limit: usize) -> DirectoryPage {
        self.directory_page_at(cursor, limit, unix_now(), DIRECTORY_REBUILD_MIN_SECS)
    }

    /// The ranking is cached, so serving a page costs a binary search and a
    /// copy of at most `limit` listings rather than a scan and sort of every
    /// name. Writes invalidate it, but it is rebuilt at most once per
    /// `rebuild_min_secs`, so a page can lag a write by that long.
    pub fn directory_page_at(
        &self,
        cursor: Option<&DirectoryCursor>,
        limit: usize,
        now: i64,
        rebuild_min_secs: i64,
    ) -> DirectoryPage {
        let ranked = self.cached_ranking(now, rebuild_min_secs);
        let start = cursor.map_or(0, |cursor| {
            ranked.entries.partition_point(|(key, _)| key <= cursor)
        });
        let end = start.saturating_add(limit.max(1)).min(ranked.entries.len());
        let page = &ranked.entries[start.min(end)..end];
        DirectoryPage {
            channels: page.iter().map(|(_, listing)| listing.clone()).collect(),
            next_cursor: (end < ranked.entries.len())
                .then(|| page.last().map(|(key, _)| key.encode()))
                .flatten(),
        }
    }

    fn cached_ranking(&self, now: i64, rebuild_min_secs: i64) -> Arc<RankedDirectory> {
        let mut cache = self
            .directory_cache
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(cached) = cache.as_ref() {
            let age = now.saturating_sub(cached.built_at);
            let usable = (0..DIRECTORY_CACHE_MAX_AGE_SECS).contains(&age)
                && (cached.generation == self.generation || age < rebuild_min_secs);
            if usable {
                return cached.clone();
            }
        }
        let built = Arc::new(RankedDirectory {
            generation: self.generation,
            built_at: now,
            entries: self.ranked_directory(now),
        });
        *cache = Some(built.clone());
        built
    }

    /// Drop abandoned usernames and room names. Owner-deleted names stay
    /// retired; abandoned ones are forgotten so someone else can claim them.
    ///
    /// Deliberately *not* a tombstone. Only the owner can destroy a room, and
    /// a silent owner is not proof the room is dead — its members may still be
    /// talking. Forgetting the claim frees the name and takes the room out of
    /// the directory without evicting anyone, and it keeps the tombstone list
    /// bounded by real deletions instead of growing forever.
    ///
    /// Runs from the sweeper, not from claims: a claim reaps only the records
    /// that decide its own outcome, which gives it the same answer.
    pub fn reap_stale(&mut self, now: i64) -> bool {
        if self.read_only || self.closed {
            return false;
        }
        let mut changed = self.grandfather_legacy_timestamps(now);
        let idle_names: Vec<String> = self
            .usernames
            .iter()
            .filter(|(_, pk)| self.username_idle(pk, now))
            .map(|(name, _)| name.clone())
            .collect();
        for name in idle_names {
            changed |= self.release_username(&name);
        }
        let abandoned: Vec<String> = self
            .names
            .iter()
            .filter(|(_, rec)| rec.abandoned(now))
            .map(|(name, _)| name.clone())
            .collect();
        changed |= self.reap_abandoned_names(abandoned, now);
        if changed {
            self.touch();
        }
        changed
    }

    fn grandfather_legacy_timestamps(&mut self, now: i64) -> bool {
        let mut changed = false;
        for rec in self.names.values_mut() {
            if rec.deleted || rec.refreshed_at > 0 {
                continue;
            }
            rec.refreshed_at = now;
            changed = true;
        }
        for pk in self.usernames.values() {
            if self.username_activity.contains_key(pk) {
                continue;
            }
            self.username_activity.insert(pk.clone(), now);
            changed = true;
        }
        changed
    }

    pub fn deleted_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.deleted.iter().cloned().collect();
        for rec in self.names.values() {
            if rec.deleted {
                ids.push(rec.channel_id.clone());
            }
        }
        ids.sort();
        ids.dedup();
        ids
    }

    /// Whether this channel id is already tombstoned.
    ///
    /// Lets `delete_channel_v4` tell a first deletion from an idempotent
    /// repeat without cloning the whole tombstone set.
    pub fn is_deleted(&self, channel_id: &str) -> bool {
        let id = channel_id.to_ascii_lowercase();
        if self.deleted.contains(&id) {
            return true;
        }
        self.names_of_channel(&id)
            .iter()
            .any(|name| self.names.get(name).is_some_and(|rec| rec.deleted))
    }

    /// One page of [`Self::deleted_ids`], starting after `after`.
    ///
    /// `/v4/channels/deleted` is unauthenticated and polled by every client.
    /// The list is sorted, so a plain "greater than the last id you saw"
    /// cursor pages it without server-side state, and it is cached like the
    /// directory ranking: rebuilt only after a write, and then at most once
    /// per [`DIRECTORY_REBUILD_MIN_SECS`]. Built per request, every page
    /// cloned and sorted the whole tombstone set under the registry lock.
    pub fn deleted_ids_page(&self, after: Option<&str>, limit: usize) -> Vec<String> {
        self.deleted_ids_page_at(after, limit, unix_now(), DIRECTORY_REBUILD_MIN_SECS)
    }

    fn deleted_ids_page_at(
        &self,
        after: Option<&str>,
        limit: usize,
        now: i64,
        rebuild_min_secs: i64,
    ) -> Vec<String> {
        let all = self.cached_deleted_ids(now, rebuild_min_secs);
        let start = match after {
            Some(cursor) => all.partition_point(|id| id.as_str() <= cursor),
            None => 0,
        };
        all.iter().skip(start).take(limit).cloned().collect()
    }

    fn cached_deleted_ids(&self, now: i64, rebuild_min_secs: i64) -> Arc<Vec<String>> {
        let mut cache = self
            .deleted_cache
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(cached) = cache.as_ref() {
            let age = now.saturating_sub(cached.built_at);
            let usable = (0..DIRECTORY_CACHE_MAX_AGE_SECS).contains(&age)
                && (cached.generation == self.generation || age < rebuild_min_secs);
            if usable {
                return cached.ids.clone();
            }
        }
        let ids = Arc::new(self.deleted_ids());
        *cache = Some(DeletedIds {
            generation: self.generation,
            built_at: now,
            ids: ids.clone(),
        });
        ids
    }
}

fn detach_name(index: &mut HashMap<String, Vec<String>>, key: &str, name: &str) {
    if let Some(names) = index.get_mut(key) {
        names.retain(|existing| existing != name);
        if names.is_empty() {
            index.remove(key);
        }
    }
}

/// Where [`atomic_write`] parks the previous copy while it swaps in a new one.
fn backup_path(dest: &Path) -> PathBuf {
    let mut name = dest.file_name().unwrap_or_default().to_os_string();
    name.push(".bak");
    dest.with_file_name(name)
}

/// `Ok(None)` only when the file does not exist; every other failure to read
/// or parse it is an error.
fn read_registry_file(path: &Path) -> Result<Option<RegistryFile>, String> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| format!("parse: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("read: {e}")),
    }
}

/// Copy an unreadable registry file aside so the evidence survives whatever
/// an operator does next.
fn quarantine(path: &Path) {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".corrupt-{}", unix_now()));
    let aside = path.with_file_name(name);
    match fs::copy(path, &aside) {
        Ok(_) => tracing::error!(
            path = %path.display(),
            copy = %aside.display(),
            "kept a copy of the unreadable channels registry"
        ),
        Err(e) => tracing::error!(
            path = %path.display(),
            error = %e,
            "could not copy the unreadable channels registry aside"
        ),
    }
}

/// Decide what the registry starts with, and whether it may ever be written.
///
/// Only a missing file with no backup is a first run. Anything else that
/// fails to load used to be read as an empty registry, and the next claim
/// then persisted that emptiness over the file — releasing every username and
/// room name on record to whoever asked next.
///
/// When neither the file nor its backup can be read, the registry comes up
/// empty and read-only instead of refusing to start: every other endpoint on
/// this server works without it, and on Fly an exit is a restart loop that
/// would take presence, punching and the relay down over a problem confined
/// to channel names. Read-only never touches the file, so an operator can
/// restore it and restart; until then channel writes answer 503.
fn load_registry_file(dest: &Path) -> (RegistryFile, bool) {
    let backup = backup_path(dest);
    match read_registry_file(dest) {
        Ok(Some(file)) => {
            // Leftover from a completed write; the destination is current.
            if backup.exists() {
                let _ = fs::remove_file(&backup);
            }
            (file, false)
        }
        // `atomic_write` on Windows was interrupted after moving the old copy
        // aside and before the new one landed.
        Ok(None) => match read_registry_file(&backup) {
            Ok(None) => (RegistryFile::default(), false),
            Ok(Some(file)) => {
                if let Err(e) = fs::rename(&backup, dest) {
                    tracing::warn!(error = %e, "could not move the channels registry backup back into place");
                }
                tracing::warn!(
                    path = %dest.display(),
                    "restored the channels registry from its backup after an interrupted write"
                );
                (file, false)
            }
            Err(err) => {
                tracing::error!(
                    path = %backup.display(),
                    error = %err,
                    "channels registry is missing and its backup is unreadable; refusing all channel writes"
                );
                quarantine(&backup);
                (RegistryFile::default(), true)
            }
        },
        Err(err) => {
            tracing::error!(path = %dest.display(), error = %err, "channels registry is unreadable");
            quarantine(dest);
            match read_registry_file(&backup) {
                Ok(Some(file)) => {
                    // Overwrite the bad copy now, while the backup is intact,
                    // rather than leaving it for `atomic_write` — which on
                    // Windows deletes the backup before it replaces `dest`.
                    if let Err(e) = fs::copy(&backup, dest) {
                        tracing::warn!(error = %e, "could not restore the channels registry from its backup");
                    }
                    tracing::warn!(
                        path = %backup.display(),
                        "loaded the channels registry from its backup"
                    );
                    (file, false)
                }
                Ok(None) => {
                    tracing::error!(
                        path = %dest.display(),
                        "no channels registry backup to fall back on; refusing all channel writes"
                    );
                    (RegistryFile::default(), true)
                }
                Err(backup_err) => {
                    tracing::error!(
                        path = %backup.display(),
                        error = %backup_err,
                        "channels registry backup is unreadable too; refusing all channel writes"
                    );
                    quarantine(&backup);
                    (RegistryFile::default(), true)
                }
            }
        }
    }
}

/// Write one registry snapshot, skipping it if a newer one already landed.
///
/// The mutex also serialises concurrent writers, which matters beyond
/// ordering: `atomic_write` on Windows moves the destination aside before
/// renaming, and two of those interleaving would fight over the same backup
/// path.
fn write_registry(gate: &PersistGate, ticket: u64, dest: &Path, bytes: &[u8]) -> bool {
    let mut written = match gate.written.lock() {
        Ok(guard) => guard,
        // Another writer panicked mid-write. The file is still consistent —
        // `atomic_write` only ever renames a fully-synced temp into place — so
        // take the lock back and continue rather than leaving the registry
        // unwritable for the life of the process.
        Err(poisoned) => poisoned.into_inner(),
    };
    if *written >= ticket {
        // A newer snapshot is already on disk; this one would rewind it.
        return true;
    }
    let tmp = dest.with_extension("json.tmp");
    if atomic_write(&tmp, dest, bytes).is_err() {
        tracing::warn!(path = %dest.display(), "could not persist the channels registry");
        return false;
    }
    *written = ticket;
    true
}

fn atomic_write(tmp: &Path, dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    {
        let mut file = fs::File::create(tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }

    // On Unix, `rename` replaces atomically and there is nothing to arrange.
    #[cfg(not(windows))]
    {
        fs::rename(tmp, dest)?;
        Ok(())
    }

    // Windows cannot rename over an existing file. Deleting the destination
    // first is the obvious workaround and the dangerous one: if the rename
    // then fails — a scanner or backup agent holding a handle, a transient
    // sharing violation, the process dying inside the window — the
    // destination is already gone and the new content is still parked under
    // the temp name. The server comes back with no registry at all, which
    // releases every username and channel-name claim for anyone to re-take.
    //
    // So move the old copy aside instead of destroying it: at every point
    // between here and the end of the function, the previous registry exists
    // under either `dest` or `backup`, and `load_registry_file` picks it up
    // on the next load.
    #[cfg(windows)]
    {
        let backup = backup_path(dest);
        let parked = if dest.exists() {
            let _ = fs::remove_file(&backup);
            fs::rename(dest, &backup)?;
            true
        } else {
            false
        };
        match fs::rename(tmp, dest) {
            Ok(()) => {
                if parked {
                    let _ = fs::remove_file(&backup);
                }
                Ok(())
            }
            Err(e) => {
                // Put the original back rather than leaving nothing at `dest`.
                // If even this fails the backup stays put, which is exactly
                // what the recovery path on next load looks for.
                if parked {
                    let _ = fs::rename(&backup, dest);
                }
                Err(e)
            }
        }
    }
}

pub fn normalize_username(raw: &str) -> Option<String> {
    let cleaned = strip_invisible(raw);
    if cleaned.len() < USERNAME_MIN || cleaned.len() > USERNAME_MAX {
        return None;
    }
    if !cleaned.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    if cleaned.eq_ignore_ascii_case("anonymous") {
        return None;
    }
    Some(cleaned.to_lowercase())
}

pub fn normalize_channel_name(raw: &str) -> Option<String> {
    let cleaned = strip_invisible(raw);
    if cleaned.is_empty() || cleaned.len() > CHANNEL_NAME_MAX {
        return None;
    }
    if cleaned.eq_ignore_ascii_case("anonymous") {
        return None;
    }
    Some(cleaned.to_lowercase())
}

/// Fold a channel name to its Unicode confusable skeleton (UTS #39), for
/// deciding whether two names would look the same to a user.
///
/// [`normalize_channel_name`] case-folds and nothing else, so `"Lobby"` and
/// `"Lοbby"` — the second with a Greek omicron — are distinct keys and both
/// claimable. Since creating a room is unprivileged, anyone could register a
/// name visually identical to an established one, have it served to every
/// client's Discover directory, and (because the directory sorts by name) land
/// it directly beside the room it mimics. Usernames were never exposed to
/// this: `normalize_username` requires `is_ascii_alphanumeric`, which removes
/// the homoglyph primitive outright.
///
/// This is deliberately kept *separate* from the map key rather than replacing
/// it. Re-keying would strand every name already on record under its old key —
/// making each one look unclaimed and therefore re-claimable, which is a far
/// worse version of the problem being fixed — and the skeleton is a matching
/// form, not a display form: it maps `l`, `1` and `I` onto one representative,
/// so a legacy record with no stored `display` would render as mojibake in the
/// directory's fallback path.
fn confusable_key(name: &str) -> String {
    use unicode_security::confusable_detection::skeleton;
    skeleton(&name.to_lowercase()).collect()
}

/// Channel id (lowercase hex) a room key hashes to, mirroring
/// `channel_id_matches_pubkey` in `main.rs`, or `None` for a malformed key.
fn channel_id_of_key(pubkey_hex: &str) -> Option<String> {
    let pubkey = hex::decode(pubkey_hex).ok().filter(|b| b.len() == 32)?;
    Some(hex::encode(&blake3::hash(&pubkey).as_bytes()[..16]))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn strip_invisible(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control() && *c != '\0' && !is_bidi_or_zero_width(*c))
        .collect::<String>()
        .trim()
        .to_string()
}

fn is_bidi_or_zero_width(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'
            | '\u{200C}'
            | '\u{200D}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'
            | '\u{202B}'
            | '\u{202C}'
            | '\u{202D}'
            | '\u{202E}'
            | '\u{2066}'
            | '\u{2067}'
            | '\u{2068}'
            | '\u{2069}'
            | '\u{FEFF}'
            | '\u{061C}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The username map is one of two an unauthenticated caller can grow, and
    /// entries are held for a year. Refusing at the cap — rather than evicting
    /// — matters: eviction would hand someone else's handle to whoever asked
    /// next.
    #[test]
    fn the_username_map_refuses_new_claims_at_its_cap() {
        let mut reg = ChannelRegistry::in_memory();
        // Filled directly rather than through `claim_username`, which would
        // spend the creation budget a hundred thousand times over.
        let now = unix_now();
        for i in 0..MAX_USERNAMES {
            let pk = format!("{i:064x}");
            let name = format!("u{i:x}");
            reg.usernames.insert(name.clone(), pk.clone());
            reg.by_pubkey.insert(pk.clone(), name);
            reg.username_activity.insert(pk, now);
        }

        let overflow = format!("{:064x}", MAX_USERNAMES + 1);
        assert_eq!(
            reg.claim_username(&overflow, "onemore"),
            Err(RegistryError::Full)
        );

        // An existing holder refreshing its own handle is the keep-alive path
        // and must not be refused, or the cap would start expiring live users.
        let existing = format!("{:064x}", 0);
        assert!(reg.claim_username(&existing, "u0").is_ok());

        // Nor may a holder be blocked from renaming: that swap is net-neutral
        // on map size, so the cap has no reason to reject it.
        assert!(reg.claim_username(&existing, "renamed").is_ok());
    }

    /// Tombstones are kept forever by policy, so an id that never held a name
    /// is the one unbounded write on the server. A known room is still
    /// tombstoned at the cap — its record is already marked deleted, and
    /// refusing would leave the two halves disagreeing.
    #[test]
    fn the_tombstone_set_refuses_unknown_ids_at_its_cap() {
        let mut reg = ChannelRegistry::in_memory();
        for i in 0..MAX_DELETED {
            reg.deleted.insert(format!("{i:032x}"));
        }
        let unknown_pk = "cc".repeat(32);
        let unknown_id = format!("{:032x}", MAX_DELETED + 1);
        assert_eq!(
            reg.delete_channel(&unknown_id, &unknown_pk),
            Err(RegistryError::Full)
        );

        let owner = ed25519_test_pubkey();
        let owned_id = "ab".repeat(16);
        assert!(reg.claim_channel_name(&owned_id, &owner, "lobby", false).is_ok());
        assert!(
            reg.delete_channel(&owned_id, &owner).is_ok(),
            "an owner must still be able to destroy a room they actually hold"
        );
    }

    /// `is_deleted` is what decides whether a delete costs creation budget, so
    /// a repeat of an already-tombstoned id has to read as deleted through
    /// both the tombstone set and a name record marked deleted.
    #[test]
    fn is_deleted_sees_both_tombstones_and_deleted_name_records() {
        let mut reg = ChannelRegistry::in_memory();
        let owner = ed25519_test_pubkey();
        let id = "ab".repeat(16);
        assert!(!reg.is_deleted(&id));
        assert!(reg.claim_channel_name(&id, &owner, "lobby", false).is_ok());
        assert!(!reg.is_deleted(&id));
        assert!(reg.delete_channel(&id, &owner).is_ok());
        assert!(reg.is_deleted(&id), "a destroyed room reads as deleted");
        assert!(
            reg.is_deleted(&id.to_uppercase()),
            "ids are compared case-insensitively"
        );
    }

    /// Paging has to cover the whole set exactly once, in order and without
    /// gaps, or a client would silently keep a room its owner destroyed.
    #[test]
    fn deleted_ids_page_walks_the_whole_set_once() {
        let mut reg = ChannelRegistry::in_memory();
        for i in 0..25 {
            reg.deleted.insert(format!("{i:032x}"));
        }
        let expected = reg.deleted_ids();
        assert_eq!(expected.len(), 25);

        let mut walked: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = reg.deleted_ids_page(cursor.as_deref(), 10);
            if page.is_empty() {
                break;
            }
            cursor = page.last().cloned();
            walked.extend(page);
        }
        assert_eq!(walked, expected, "paging must reproduce the full list in order");

        // A cursor past the end yields nothing rather than wrapping.
        assert!(reg.deleted_ids_page(Some(&"f".repeat(32)), 10).is_empty());
    }

    /// The cached list is served until a write, then rebuilt once the minimum
    /// interval has passed, so a deletion shows up without a sort per request.
    #[test]
    fn the_deleted_list_is_cached_until_a_write() {
        let mut reg = ChannelRegistry::in_memory();
        let now = 1_000_000;
        assert!(reg.deleted_ids_page_at(None, 10, now, 2).is_empty());

        let id = "ab".repeat(16);
        reg.delete_channel(&id, &"cd".repeat(32)).expect("tombstoned");
        assert!(
            reg.deleted_ids_page_at(None, 10, now + 1, 2).is_empty(),
            "within the rebuild interval the cached list stands"
        );
        assert_eq!(reg.deleted_ids_page_at(None, 10, now + 2, 2), vec![id.clone()]);

        // No write since: still served from the cache, not rebuilt.
        reg.deleted.insert("ff".repeat(16));
        assert_eq!(reg.deleted_ids_page_at(None, 10, now + 10, 2), vec![id]);
    }

    fn ed25519_test_pubkey() -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x5Au8; 32]);
        hex::encode(key.verifying_key().to_bytes())
    }

    #[test]
    fn username_first_write_wins_and_rename_releases_the_old_name() {
        let mut reg = ChannelRegistry::in_memory();
        let alice = "aa".repeat(32);
        let bob = "bb".repeat(32);
        assert!(reg.claim_username(&alice, "Ada").is_ok());
        assert_eq!(reg.claim_username(&bob, "ada"), Err(RegistryError::Taken));
        assert!(reg.claim_username(&alice, "Lovelace").is_ok());
        assert!(reg.claim_username(&bob, "Ada").is_ok());
    }

    #[test]
    fn username_allows_only_short_ascii_alphanumerics() {
        assert_eq!(normalize_username("Ada"), Some("ada".into()));
        assert_eq!(normalize_username("Ada1"), Some("ada1".into()));
        assert_eq!(normalize_username("A"), None);
        assert_eq!(normalize_username("Ada Lovelace"), None);
        assert_eq!(normalize_username("Ada_1"), None);
        assert_eq!(normalize_username(&"x".repeat(13)), None);
        assert_eq!(normalize_username("Anonymous"), None);
    }

    #[test]
    fn channel_name_conflict_hides_whether_the_room_is_private() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        assert!(reg.claim_channel_name(&id, &pk, "Lobby", true).is_ok());
        assert!(reg
            .public_directory()
            .is_empty(), "private names stay off the directory");
        let other = "33".repeat(16);
        let other_pk = "44".repeat(32);
        assert_eq!(
            reg.claim_channel_name(&other, &other_pk, "lobby", false),
            Err(RegistryError::Taken)
        );
    }

    /// A name that merely looks like one already taken must be refused, or
    /// anyone can stand up a visually identical room beside an established one
    /// in Discover.
    #[test]
    fn a_confusable_channel_name_cannot_be_claimed() {
        let mut reg = ChannelRegistry::in_memory();
        assert!(reg
            .claim_channel_name(&"11".repeat(16), &"22".repeat(32), "Lobby", false)
            .is_ok());

        // Greek omicron (U+03BF) for the Latin "o".
        assert_eq!(
            reg.claim_channel_name(&"33".repeat(16), &"44".repeat(32), "L\u{03BF}bby", false),
            Err(RegistryError::Taken),
            "a homoglyph of a taken name must not be claimable"
        );
        // Cyrillic small "о" (U+043E).
        assert_eq!(
            reg.claim_channel_name(&"55".repeat(16), &"66".repeat(32), "L\u{043E}bby", false),
            Err(RegistryError::Taken)
        );
        // A genuinely different name is unaffected.
        assert!(reg
            .claim_channel_name(&"77".repeat(16), &"88".repeat(32), "Lounge", false)
            .is_ok());
    }

    /// `persist` writes through a borrowed mirror of `RegistryFile` to avoid
    /// cloning four maps — one of them the permanent tombstone set — on every
    /// claim, nomination, delete and reap. The two must serialise identically
    /// or the next load reads a different file than the one that was written.
    #[test]
    fn the_borrowed_write_form_serialises_exactly_like_the_owned_one() {
        let mut reg = ChannelRegistry::in_memory();
        assert!(reg.claim_username(&"aa".repeat(32), "Ada").is_ok());
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        assert!(reg.claim_channel_name(&id, &pk, "Lobby", false).is_ok());
        assert!(reg
            .set_channel_nominee(&id, &pk, &"bb".repeat(32), 7)
            .is_ok());
        let gone = "33".repeat(16);
        let gone_pk = "44".repeat(32);
        assert!(reg.claim_channel_name(&gone, &gone_pk, "Gone", false).is_ok());
        assert!(reg.delete_channel(&gone, &gone_pk).is_ok());

        let borrowed = serde_json::to_vec(&RegistryFileRef {
            usernames: &reg.usernames,
            names: &reg.names,
            deleted: &reg.deleted,
            username_activity: &reg.username_activity,
        })
        .expect("borrowed form serialises");
        let owned = serde_json::to_vec(&RegistryFile {
            usernames: reg.usernames.clone(),
            names: reg.names.clone(),
            deleted: reg.deleted.clone(),
            username_activity: reg.username_activity.clone(),
        })
        .expect("owned form serialises");

        assert_eq!(
            String::from_utf8(borrowed).unwrap(),
            String::from_utf8(owned).unwrap()
        );
    }

    /// A handoff moves the name's record rather than re-claiming it, so it
    /// must not be exposed to the confusable scan — the successor is taking
    /// the *same* name, which necessarily collides with itself. Pinned because
    /// the scan and the handover live in different functions and nothing else
    /// would notice if handover started routing through the claim path.
    #[test]
    fn a_handover_keeps_the_name_and_is_not_blocked_by_the_confusable_scan() {
        let mut reg = ChannelRegistry::in_memory();
        let old_id = "11".repeat(16);
        let old_pk = "22".repeat(32);
        let new_id = "33".repeat(16);
        let new_pk = "44".repeat(32);
        assert!(reg.claim_channel_name(&old_id, &old_pk, "Lobby", false).is_ok());

        assert!(reg
            .handover_channel_name(&old_id, &new_id, &new_pk, &old_pk, unix_now())
            .is_ok());

        let listing = reg.public_directory();
        assert_eq!(listing.len(), 1, "the name moved rather than duplicating");
        assert_eq!(listing[0].channel_id, new_id);
        assert_eq!(listing[0].name, "Lobby");

        // And the successor, now the holder, can still refresh its own claim —
        // the scan skips same-channel rows, so its own name is not a lookalike
        // of itself.
        assert!(reg
            .claim_channel_name(&new_id, &new_pk, "Lobby", false)
            .is_ok());
    }

    /// The predecessor's record is gone after a handoff, so a successor that
    /// wants a *different* name is judged against every other room and not
    /// against the room it replaced.
    #[test]
    fn a_successor_can_take_a_different_name_after_a_handover() {
        let mut reg = ChannelRegistry::in_memory();
        let old_id = "11".repeat(16);
        let old_pk = "22".repeat(32);
        let new_id = "33".repeat(16);
        let new_pk = "44".repeat(32);
        assert!(reg.claim_channel_name(&old_id, &old_pk, "Lobby", false).is_ok());
        assert!(reg
            .handover_channel_name(&old_id, &new_id, &new_pk, &old_pk, unix_now())
            .is_ok());

        // One name per room, so a plain claim for another is refused ...
        assert_eq!(
            reg.claim_channel_name(&new_id, &new_pk, "Lounge", false),
            Err(RegistryError::Taken)
        );
        // ... and a rename, the same as for any owner, retires "Lobby" to the
        // successor rather than keeping it alongside "Lounge".
        assert!(reg.rename_channel_name(&new_id, &new_pk, "Lounge", false).is_ok());
        let listing = reg.public_directory();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].name, "Lounge");
        assert_eq!(
            reg.claim_channel_name(&old_id, &old_pk, "Lobby", false),
            Err(RegistryError::Taken),
            "the room it came from cannot take the retired name back"
        );
    }

    /// An owner-deleted name never comes back, so a lookalike of one must not
    /// either — otherwise the retirement just moves the name one homoglyph
    /// away, to a room whose owner is gone and cannot object.
    #[test]
    fn a_confusable_of_a_retired_name_is_also_refused() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        assert!(reg.claim_channel_name(&id, &pk, "Lobby", false).is_ok());
        assert!(reg.delete_channel(&id, &pk).is_ok());

        assert_eq!(
            reg.claim_channel_name(&"33".repeat(16), &"44".repeat(32), "Lobby", false),
            Err(RegistryError::Taken),
            "the exact retired name stays retired"
        );
        assert_eq!(
            reg.claim_channel_name(&"55".repeat(16), &"66".repeat(32), "L\u{03BF}bby", false),
            Err(RegistryError::Taken),
            "and so does a homoglyph of it"
        );
    }

    /// The confusable check is scoped to *other* rooms, so an owner refreshing
    /// or re-casing its own claim still succeeds.
    #[test]
    fn an_owner_can_still_refresh_its_own_name() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        assert!(reg.claim_channel_name(&id, &pk, "Lobby", false).is_ok());
        assert!(
            reg.claim_channel_name(&id, &pk, "LOBBY", false).is_ok(),
            "re-casing is a refresh of the same normalised key"
        );
    }

    #[test]
    fn delete_requires_the_channel_key_and_retires_the_name() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        assert!(reg.claim_channel_name(&id, &pk, "Lobby", false).is_ok());
        assert_eq!(
            reg.delete_channel(&id, &"99".repeat(32)),
            Err(RegistryError::Forbidden)
        );
        assert!(reg.delete_channel(&id, &pk).is_ok());
        assert!(reg.public_directory().is_empty());
        assert!(reg.deleted_ids().contains(&id));
        assert_eq!(
            reg.claim_channel_name(&"aa".repeat(16), &"bb".repeat(32), "Lobby", false),
            Err(RegistryError::Taken),
            "a deleted name must not be reclaimable"
        );
    }

    #[test]
    fn public_directory_omits_deleted_and_private_rooms() {
        let mut reg = ChannelRegistry::in_memory();
        let pub_id = "11".repeat(16);
        let pub_pk = "22".repeat(32);
        let priv_id = "33".repeat(16);
        let priv_pk = "44".repeat(32);
        assert!(reg.claim_channel_name(&pub_id, &pub_pk, "Open", false).is_ok());
        assert!(reg.claim_channel_name(&priv_id, &priv_pk, "Secret", true).is_ok());
        assert_eq!(reg.public_directory().len(), 1);
        assert_eq!(reg.public_directory()[0].channel_id, pub_id);
        assert_eq!(
            reg.public_directory()[0].name, "Open",
            "the directory must keep the owner's casing"
        );
        assert!(reg.delete_channel(&pub_id, &pub_pk).is_ok());
        assert!(reg.public_directory().is_empty());
    }

    /// Owners re-claim on a timer with whatever name their device holds, so a
    /// claim for a different name must never rename the room by itself.
    #[test]
    fn one_channel_cannot_claim_a_second_name() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        let t0 = 1_000_000;
        assert!(reg.claim_channel_name_at(&id, &pk, "Lobby", false, t0).is_ok());
        assert_eq!(
            reg.claim_channel_name_at(&id, &pk, "Elsewhere", false, t0 + 10),
            Err(RegistryError::Taken)
        );
        assert_eq!(
            reg.claim_channel_name_at(&id, &pk, "Lobby Chat", false, t0 + 10),
            Err(RegistryError::Taken),
            "nor a stale or trimmed form of the name"
        );
        let listed = reg.public_directory_at(t0 + 10);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "Lobby");
    }

    #[test]
    fn a_second_name_is_a_rename_that_retires_the_first() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        let t0 = 1_000_000;
        assert!(reg.claim_channel_name_at(&id, &pk, "Lobby", false, t0).is_ok());
        assert!(reg.rename_channel_name_at(&id, &pk, "Elsewhere", false, t0 + 10).is_ok());
        let listed = reg.public_directory_at(t0 + 10);
        assert_eq!(listed.len(), 1, "still one listing for the room");
        assert_eq!(listed[0].name, "Elsewhere");
        assert!(reg.has_channel(&id));
        assert!(
            reg.claim_channel_name_at(&id, &pk, "Elsewhere", false, t0 + 20).is_ok(),
            "the owner's refresh now claims the new name"
        );
        assert_eq!(
            reg.claim_channel_name_at(&id, &pk, "Lobby", false, t0 + 20),
            Err(RegistryError::Taken),
            "and a device still holding the old one cannot rename the room back"
        );
    }

    #[test]
    fn a_rename_needs_the_rooms_key() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        assert!(reg.claim_channel_name(&id, &pk, "Lobby", false).is_ok());
        assert_eq!(
            reg.rename_channel_name(&id, &"99".repeat(32), "Elsewhere", false),
            Err(RegistryError::Forbidden)
        );
    }

    /// A retry after a lost answer asks for the name the room now holds, and
    /// must succeed rather than read as a second rename inside the day.
    #[test]
    fn renaming_to_the_current_name_is_a_refresh() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        let t0 = 1_000_000;
        assert!(reg.claim_channel_name_at(&id, &pk, "Lobby", false, t0).is_ok());
        assert!(reg.rename_channel_name_at(&id, &pk, "Den", false, t0 + 5).is_ok());
        assert!(reg.rename_channel_name_at(&id, &pk, "Den", false, t0 + 6).is_ok());
        assert!(
            reg.rename_channel_name_at(&id, &pk, "DEN", false, t0 + 7).is_ok(),
            "nor is a re-casing"
        );
        assert_eq!(reg.public_directory_at(t0 + 7)[0].name, "DEN");
        assert_eq!(reg.names.get("den").unwrap().renamed_at, t0 + 5);
    }

    #[test]
    fn a_room_with_no_name_yet_claims_one_by_renaming() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        assert!(reg.rename_channel_name(&id, &pk, "Lobby", false).is_ok());
        assert!(reg.has_channel(&id));
    }

    #[test]
    fn a_retired_name_stays_the_rooms_for_thirty_days() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        let other_id = "33".repeat(16);
        let other_pk = "44".repeat(32);
        let t0 = 1_000_000;
        assert!(reg.claim_channel_name_at(&id, &pk, "Lobby", false, t0).is_ok());
        assert!(reg.rename_channel_name_at(&id, &pk, "Elsewhere", false, t0).is_ok());
        assert_eq!(
            reg.claim_channel_name_at(&other_id, &other_pk, "Lobby", false, t0 + 86_400),
            Err(RegistryError::Taken),
            "nobody else can pose as the room while members still see the old name"
        );
        assert_eq!(
            reg.claim_channel_name_at(&other_id, &other_pk, "L\u{03BF}bby", false, t0 + 86_400),
            Err(RegistryError::Taken),
            "nor under a lookalike of it"
        );
        let after_hold = t0 + RETIRED_NAME_HOLD_SECS + 1;
        // The room keeps refreshing its current name, so only the retired one lapses.
        assert!(reg.claim_channel_name_at(&id, &pk, "Elsewhere", false, after_hold).is_ok());
        assert!(reg.claim_channel_name_at(&other_id, &other_pk, "Lobby", false, after_hold).is_ok());
    }

    #[test]
    fn the_owner_can_rename_back_to_a_retired_name() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        let t0 = 1_000_000;
        assert!(reg.claim_channel_name_at(&id, &pk, "Lobby", false, t0).is_ok());
        assert!(reg.rename_channel_name_at(&id, &pk, "Elsewhere", false, t0).is_ok());
        let later = t0 + RENAME_INTERVAL_SECS;
        assert_eq!(
            reg.claim_channel_name_at(&id, &pk, "LOBBY", false, later),
            Err(RegistryError::Taken),
            "a plain claim never takes a retired name back"
        );
        assert!(reg.rename_channel_name_at(&id, &pk, "LOBBY", false, later).is_ok());
        let listed = reg.public_directory_at(later);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "LOBBY");
    }

    /// Each retired name is one nobody else may claim for a month, so a room
    /// cannot collect them without limit.
    #[test]
    fn a_room_keeps_only_its_newest_retired_names() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        let other_id = "33".repeat(16);
        let other_pk = "44".repeat(32);
        let t0 = 1_000_000;
        assert!(reg.claim_channel_name_at(&id, &pk, "Name0", false, t0).is_ok());
        for i in 1..=MAX_RETIRED_NAMES + 1 {
            let at = t0 + i as i64 * RENAME_INTERVAL_SECS;
            assert!(reg.rename_channel_name_at(&id, &pk, &format!("Name{i}"), false, at).is_ok());
        }
        let now = t0 + (MAX_RETIRED_NAMES as i64 + 1) * RENAME_INTERVAL_SECS;
        let retired = reg
            .names_of_channel(&id)
            .iter()
            .filter(|name| reg.names.get(*name).is_some_and(|rec| rec.retired_at > 0))
            .count();
        assert_eq!(retired, MAX_RETIRED_NAMES);
        assert!(!reg.names.contains_key("name0"), "the oldest was freed");
        assert!(reg.claim_channel_name_at(&other_id, &other_pk, "Name0", false, now).is_ok());
        assert_eq!(
            reg.claim_channel_name_at(&"55".repeat(16), &"66".repeat(32), "Name1", false, now),
            Err(RegistryError::Taken),
            "the newer ones are still held"
        );
    }

    #[test]
    fn a_room_renames_at_most_once_a_day() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        let t0 = 1_000_000;
        assert!(reg.claim_channel_name_at(&id, &pk, "Lobby", false, t0).is_ok());
        assert!(
            reg.rename_channel_name_at(&id, &pk, "First", false, t0 + 5).is_ok(),
            "the first rename is not held back by the room being new"
        );
        assert_eq!(
            reg.rename_channel_name_at(&id, &pk, "Second", false, t0 + RENAME_INTERVAL_SECS - 1),
            Err(RegistryError::RenameTooSoon)
        );
        assert_eq!(
            reg.rename_channel_name_at(&id, &pk, "Lobby", false, t0 + 60),
            Err(RegistryError::RenameTooSoon),
            "going back to the old name is a rename too"
        );
        assert!(
            reg.claim_channel_name_at(&id, &pk, "first", false, t0 + 60).is_ok(),
            "re-casing the current name is a refresh, not a rename"
        );
        assert!(reg
            .rename_channel_name_at(&id, &pk, "Second", false, t0 + 5 + RENAME_INTERVAL_SECS)
            .is_ok());
    }

    #[test]
    fn a_rename_keeps_the_rooms_seniority_and_nominee() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        let nominee = "55".repeat(32);
        let t0 = 1_000_000;
        assert!(reg.claim_channel_name_at(&id, &pk, "Lobby", false, t0).is_ok());
        assert!(reg.set_channel_nominee(&id, &pk, &nominee, 30).is_ok());
        assert!(reg.rename_channel_name_at(&id, &pk, "Elsewhere", false, t0 + 999).is_ok());
        let rec = reg.names.get("elsewhere").expect("renamed record");
        assert_eq!(rec.created_at, t0);
        assert_eq!(rec.nominee, nominee);
        assert_eq!(rec.claim_after_days, 30);
    }

    #[test]
    fn a_rename_cannot_take_another_rooms_name() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        assert!(reg.claim_channel_name(&id, &pk, "Lobby", false).is_ok());
        assert!(reg.claim_channel_name(&"33".repeat(16), &"44".repeat(32), "Taken", false).is_ok());
        assert_eq!(
            reg.rename_channel_name(&id, &pk, "Taken", false),
            Err(RegistryError::Taken)
        );
        assert_eq!(
            reg.rename_channel_name(&id, &pk, "T\u{0430}ken", false),
            Err(RegistryError::Taken),
            "nor a lookalike of it"
        );
        assert_eq!(reg.public_directory().iter().filter(|l| l.channel_id == id).count(), 1);
        assert_eq!(reg.public_directory()[0].name, "Lobby");
    }

    #[test]
    fn deleting_a_renamed_room_retires_every_name_it_held() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        assert!(reg.claim_channel_name(&id, &pk, "Lobby", false).is_ok());
        assert!(reg.rename_channel_name(&id, &pk, "Elsewhere", false).is_ok());
        assert!(reg.delete_channel(&id, &pk).is_ok());
        for name in ["Lobby", "Elsewhere"] {
            assert_eq!(
                reg.claim_channel_name(&"33".repeat(16), &"44".repeat(32), name, false),
                Err(RegistryError::Taken)
            );
        }
    }

    #[test]
    fn persist_round_trip_keeps_claims() {
        let path = std::env::temp_dir().join(format!(
            "ember-channels-registry-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_file(&path);
        let alice = "aa".repeat(32);
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        {
            let mut reg = ChannelRegistry::load(path.clone());
            assert!(reg.claim_username(&alice, "Ada").is_ok());
            assert!(reg.claim_channel_name(&id, &pk, "Lobby", false).is_ok());
            assert!(reg.flush_blocking());
        }
        let mut reloaded = ChannelRegistry::load(path.clone());
        assert_eq!(reloaded.public_directory().len(), 1);
        assert_eq!(
            reloaded.claim_username(&"bb".repeat(32), "Ada"),
            Err(RegistryError::Taken)
        );
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("json.tmp"));
    }

    #[test]
    fn abandoned_room_leaves_the_directory_then_frees_the_name() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        let t0 = 1_700_000_000;
        assert!(reg.claim_channel_name_at(&id, &pk, "Lobby", false, t0).is_ok());
        assert_eq!(reg.public_directory_at(t0).len(), 1);
        assert!(
            reg.public_directory_at(t0 + CHANNEL_DIRECTORY_STALE_SECS + 1)
                .is_empty(),
            "a quiet listing must drop out of Discover after a week"
        );
        let other = "33".repeat(16);
        let other_pk = "44".repeat(32);
        assert_eq!(
            reg.claim_channel_name_at(&other, &other_pk, "Lobby", false, t0 + CHANNEL_DIRECTORY_STALE_SECS + 1),
            Err(RegistryError::Taken),
            "the name stays reserved through the succession window"
        );
        let release_at = t0 + NAME_RELEASE_SECS + 1;
        assert!(reg.reap_stale(release_at));
        assert!(
            !reg.deleted_ids().contains(&id),
            "reaping frees a name; it must not tombstone a room nobody deleted"
        );
        assert!(
            reg.claim_channel_name_at(&other, &other_pk, "Lobby", false, release_at)
                .is_ok(),
            "an abandoned name must be claimable again"
        );
        assert_eq!(
            reg.claim_channel_name_at(&id, &pk, "Lobby", false, release_at),
            Err(RegistryError::Taken),
            "the returning owner cannot take a name somebody else now holds"
        );
        assert!(
            reg.claim_channel_name_at(&id, &pk, "Elsewhere", false, release_at)
                .is_ok(),
            "a returning owner can still list their room under a free name"
        );
    }

    #[test]
    fn owner_delete_keeps_the_name_retired() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        let t0 = 1_700_000_000;
        assert!(reg.claim_channel_name_at(&id, &pk, "Lobby", false, t0).is_ok());
        assert!(reg.delete_channel(&id, &pk).is_ok());
        let later = t0 + NAME_RELEASE_SECS + 1;
        reg.reap_stale(later);
        assert_eq!(
            reg.claim_channel_name_at(&"33".repeat(16), &"44".repeat(32), "Lobby", false, later),
            Err(RegistryError::Taken),
            "an owner-deleted name must not come back"
        );
    }

    /// A transfer mints a new channel key, so without a handover the name stays
    /// bound to the room the members have already left behind.
    #[test]
    fn the_outgoing_owner_can_hand_the_name_to_the_successor() {
        let mut reg = ChannelRegistry::in_memory();
        let old_id = "11".repeat(16);
        let old_pk = "22".repeat(32);
        let new_id = "33".repeat(16);
        let new_pk = "44".repeat(32);
        let t0 = 1_700_000_000;
        assert!(reg.claim_channel_name_at(&old_id, &old_pk, "Lobby", false, t0).is_ok());
        assert_eq!(
            reg.handover_channel_name(&old_id, &new_id, &new_pk, &"99".repeat(32), t0),
            Err(RegistryError::Forbidden),
            "a stranger cannot move somebody else's name"
        );
        assert!(reg
            .handover_channel_name(&old_id, &new_id, &new_pk, &old_pk, t0)
            .is_ok());
        let dir = reg.public_directory_at(t0);
        assert_eq!(dir.len(), 1);
        assert_eq!(dir[0].channel_id, new_id, "the listing follows the room");
        assert_eq!(dir[0].name, "Lobby");
        assert!(
            reg.claim_channel_name_at(&new_id, &new_pk, "Lobby", false, t0)
                .is_ok(),
            "the new owner's own refresh keeps working"
        );
    }

    /// Succession happens precisely because the owner is gone, so the nominee
    /// they published has to be able to move the name without them.
    #[test]
    fn the_nominee_can_take_the_name_only_after_the_published_silence() {
        let mut reg = ChannelRegistry::in_memory();
        let old_id = "11".repeat(16);
        let old_pk = "22".repeat(32);
        let new_id = "33".repeat(16);
        let new_pk = "44".repeat(32);
        let nominee = "55".repeat(32);
        let t0 = 1_700_000_000;
        assert!(reg.claim_channel_name_at(&old_id, &old_pk, "Lobby", false, t0).is_ok());
        assert_eq!(
            reg.handover_channel_name(&old_id, &new_id, &new_pk, &nominee, t0),
            Err(RegistryError::Forbidden),
            "an unregistered nominee has no authority"
        );
        assert!(reg.set_channel_nominee(&old_id, &old_pk, &nominee, 7).is_ok());
        assert_eq!(
            reg.handover_channel_name(&old_id, &new_id, &new_pk, &nominee, t0 + 6 * 86_400),
            Err(RegistryError::Forbidden),
            "the window has not elapsed"
        );
        assert!(reg
            .handover_channel_name(&old_id, &new_id, &new_pk, &nominee, t0 + 7 * 86_400)
            .is_ok());
        // The nomination must not carry over, or the same key could walk the
        // name onward from the room it just handed it to.
        let third_id = "66".repeat(16);
        let third_pk = "77".repeat(32);
        assert_eq!(
            reg.handover_channel_name(&old_id, &third_id, &third_pk, &nominee, t0 + 400 * 86_400),
            Err(RegistryError::InvalidName),
            "the old room no longer holds the name"
        );
        assert_eq!(
            reg.handover_channel_name(&new_id, &third_id, &third_pk, &nominee, t0 + 400 * 86_400),
            Err(RegistryError::Forbidden),
            "the nomination did not survive the handover"
        );
    }

    /// An owner who is still refreshing has not been succeeded, and the server
    /// must reach the same verdict the members do over the DHT.
    #[test]
    fn a_live_owner_keeps_the_name_from_their_nominee() {
        let mut reg = ChannelRegistry::in_memory();
        let old_id = "11".repeat(16);
        let old_pk = "22".repeat(32);
        let nominee = "55".repeat(32);
        let t0 = 1_700_000_000;
        assert!(reg.claim_channel_name_at(&old_id, &old_pk, "Lobby", false, t0).is_ok());
        assert!(reg.set_channel_nominee(&old_id, &old_pk, &nominee, 7).is_ok());
        let much_later = t0 + 300 * 86_400;
        assert!(reg
            .claim_channel_name_at(&old_id, &old_pk, "Lobby", false, much_later)
            .is_ok());
        assert_eq!(
            reg.handover_channel_name(
                &old_id,
                &"33".repeat(16),
                &"44".repeat(32),
                &nominee,
                much_later + 86_400
            ),
            Err(RegistryError::Forbidden),
            "refreshing the claim resets the silence the nominee needs"
        );
    }

    /// The members refuse a takeover outside 7–365 days, so a nomination the
    /// registry would honour sooner could move the name off a room nobody has
    /// actually left.
    #[test]
    fn a_nomination_window_outside_the_agreed_range_is_refused() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        let nominee = "55".repeat(32);
        let t0 = 1_700_000_000;
        assert!(reg.claim_channel_name_at(&id, &pk, "Lobby", false, t0).is_ok());
        assert_eq!(
            reg.set_channel_nominee(&id, &pk, &nominee, 1),
            Err(RegistryError::InvalidName)
        );
        assert_eq!(
            reg.set_channel_nominee(&id, &pk, &nominee, 366),
            Err(RegistryError::InvalidName)
        );
        assert!(reg
            .set_channel_nominee(&id, &pk, &nominee, CLAIM_AFTER_DAYS_MIN)
            .is_ok());
        assert!(reg
            .set_channel_nominee(&id, &pk, &nominee, CLAIM_AFTER_DAYS_MAX)
            .is_ok());
    }

    #[test]
    fn a_nominee_cannot_be_set_by_anyone_but_the_room_key() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        let t0 = 1_700_000_000;
        assert!(reg.claim_channel_name_at(&id, &pk, "Lobby", false, t0).is_ok());
        assert_eq!(
            reg.set_channel_nominee(&id, &"99".repeat(32), &"55".repeat(32), 7),
            Err(RegistryError::Forbidden)
        );
        assert!(reg.set_channel_nominee(&id, &pk, &"55".repeat(32), 7).is_ok());
        assert!(reg.set_channel_nominee(&id, &pk, "", 0).is_ok());
        assert_eq!(
            reg.handover_channel_name(&id, &"33".repeat(16), &"44".repeat(32), &"55".repeat(32), t0 + 400 * 86_400),
            Err(RegistryError::Forbidden),
            "a withdrawn nomination confers nothing"
        );
    }

    #[test]
    fn idle_username_is_released_after_a_year() {
        let mut reg = ChannelRegistry::in_memory();
        let alice = "aa".repeat(32);
        let bob = "bb".repeat(32);
        let t0 = 1_700_000_000;
        assert!(reg.claim_username_at(&alice, "Ada", t0).is_ok());
        assert_eq!(
            reg.claim_username_at(&bob, "Ada", t0 + 10),
            Err(RegistryError::Taken)
        );
        assert!(reg.claim_username_at(&alice, "Ada", t0 + 10).is_ok());
        let still_held = t0 + 10 + USERNAME_IDLE_SECS;
        assert_eq!(
            reg.claim_username_at(&bob, "Ada", still_held),
            Err(RegistryError::Taken),
            "activity must reset the idle clock"
        );
        let released = still_held + USERNAME_IDLE_SECS + 1;
        assert!(
            reg.claim_username_at(&bob, "Ada", released).is_ok(),
            "a year without activity frees the handle"
        );
    }

    fn nominated_lobby(reg: &mut ChannelRegistry, days: u32, t0: i64) -> (String, String, String) {
        let old_id = "11".repeat(16);
        let old_pk = "22".repeat(32);
        let nominee = "55".repeat(32);
        assert!(reg.claim_channel_name_at(&old_id, &old_pk, "Lobby", false, t0).is_ok());
        assert!(reg.set_channel_nominee(&old_id, &old_pk, &nominee, days).is_ok());
        (old_id, old_pk, nominee)
    }

    /// At the longest window the nominee became eligible in the same second
    /// the record was reaped, and every claim reaps first — so a stranger
    /// could free and take the name one second into the nominee's turn.
    #[test]
    fn a_max_window_nominee_is_not_raced_by_the_reaper() {
        let mut reg = ChannelRegistry::in_memory();
        let t0 = 1_700_000_000;
        let (old_id, _, nominee) = nominated_lobby(&mut reg, CLAIM_AFTER_DAYS_MAX, t0);
        let eligible = t0 + i64::from(CLAIM_AFTER_DAYS_MAX) * 86_400;
        assert_eq!(eligible, t0 + NAME_RELEASE_SECS, "the boundary this pins");

        let stranger_id = "99".repeat(16);
        let stranger_pk = "88".repeat(32);
        for at in [eligible, eligible + 1, eligible + NOMINEE_GRACE_SECS] {
            assert_eq!(
                reg.claim_channel_name_at(&stranger_id, &stranger_pk, "Lobby", false, at),
                Err(RegistryError::Taken),
                "the name must stay reserved for the nominee at {}",
                at - t0
            );
        }
        assert!(
            reg.handover_channel_name(
                &old_id,
                &"33".repeat(16),
                &"44".repeat(32),
                &nominee,
                eligible + NOMINEE_GRACE_SECS
            )
            .is_ok(),
            "the nominee can still take it on the last second of the grace"
        );
    }

    #[test]
    fn an_unclaimed_nomination_is_reaped_after_its_grace() {
        let mut reg = ChannelRegistry::in_memory();
        let t0 = 1_700_000_000;
        nominated_lobby(&mut reg, CLAIM_AFTER_DAYS_MAX, t0);
        let deadline = t0 + i64::from(CLAIM_AFTER_DAYS_MAX) * 86_400 + NOMINEE_GRACE_SECS;
        assert!(!reg.reap_stale(deadline));
        assert!(reg.reap_stale(deadline + 1));
        assert!(reg
            .claim_channel_name_at(&"99".repeat(16), &"88".repeat(32), "Lobby", false, deadline + 1)
            .is_ok());
    }

    /// The grace only ever extends a hold: a short window still keeps the
    /// name for the full release period, and an unnominated room is reaped
    /// exactly as before.
    #[test]
    fn a_short_nomination_or_none_keeps_the_ordinary_release_time() {
        let t0 = 1_700_000_000;
        let mut nominated = ChannelRegistry::in_memory();
        nominated_lobby(&mut nominated, CLAIM_AFTER_DAYS_MIN, t0);
        assert!(!nominated.reap_stale(t0 + NAME_RELEASE_SECS));
        assert!(nominated.reap_stale(t0 + NAME_RELEASE_SECS + 1));

        let mut plain = ChannelRegistry::in_memory();
        assert!(plain
            .claim_channel_name_at(&"11".repeat(16), &"22".repeat(32), "Lobby", false, t0)
            .is_ok());
        assert!(!plain.reap_stale(t0 + NAME_RELEASE_SECS));
        assert!(plain.reap_stale(t0 + NAME_RELEASE_SECS + 1));
    }

    /// A fresh directory per test, removed on drop.
    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "ember-registry-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn registry(&self) -> PathBuf {
            self.0.join("channels.json")
        }

        fn corrupt_copies(&self) -> usize {
            fs::read_dir(&self.0)
                .unwrap()
                .filter(|e| {
                    e.as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .contains(".corrupt-")
                })
                .count()
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Writes a registry holding the username "Ada" through the real path.
    fn seed_registry(path: &Path) {
        let mut reg = ChannelRegistry::load(path.to_path_buf());
        assert!(!reg.is_read_only());
        assert!(reg.claim_username(&"aa".repeat(32), "Ada").is_ok());
        assert!(reg.flush_blocking());
    }

    fn holds_ada(reg: &ChannelRegistry) -> bool {
        reg.holds_username(&"aa".repeat(32), "Ada")
    }

    #[test]
    fn a_missing_registry_with_no_backup_is_a_writable_first_run() {
        let dir = ScratchDir::new("fresh");
        let mut reg = ChannelRegistry::load(dir.registry());
        assert!(!reg.is_read_only());
        assert!(reg.claim_username(&"aa".repeat(32), "Ada").is_ok());
        assert!(reg.flush_blocking());
        assert!(dir.registry().exists());
        assert_eq!(dir.corrupt_copies(), 0);
    }

    #[test]
    fn a_corrupt_registry_with_no_backup_goes_read_only_and_is_never_overwritten() {
        let dir = ScratchDir::new("corrupt");
        let garbage = b"{\"usernames\": {\"ada\": \"aa";
        fs::write(dir.registry(), garbage).unwrap();

        let mut reg = ChannelRegistry::load(dir.registry());
        assert!(reg.is_read_only());
        assert_eq!(
            reg.claim_username(&"bb".repeat(32), "Ada"),
            Err(RegistryError::ReadOnly),
            "an unreadable registry must not hand out names it may already hold"
        );
        assert_eq!(
            reg.claim_channel_name(&"11".repeat(16), &"22".repeat(32), "Lobby", false),
            Err(RegistryError::ReadOnly)
        );
        assert_eq!(
            reg.delete_channel(&"11".repeat(16), &"22".repeat(32)),
            Err(RegistryError::ReadOnly)
        );
        assert_eq!(
            reg.set_channel_nominee(&"11".repeat(16), &"22".repeat(32), &"55".repeat(32), 7),
            Err(RegistryError::ReadOnly)
        );
        assert_eq!(
            reg.handover_channel_name(
                &"11".repeat(16),
                &"33".repeat(16),
                &"44".repeat(32),
                &"22".repeat(32),
                unix_now()
            ),
            Err(RegistryError::ReadOnly)
        );
        assert!(!reg.reap_stale(unix_now()));
        assert!(!reg.has_pending_writes());
        assert!(reg.take_persist_job().is_none(), "read-only never produces a write");

        assert_eq!(
            fs::read(dir.registry()).unwrap(),
            garbage,
            "the original must be left exactly as found"
        );
        assert_eq!(dir.corrupt_copies(), 1, "and a copy kept aside");
    }

    #[test]
    fn a_corrupt_registry_falls_back_to_its_backup() {
        let dir = ScratchDir::new("backup");
        seed_registry(&dir.registry());
        fs::copy(dir.registry(), backup_path(&dir.registry())).unwrap();
        fs::write(dir.registry(), b"not json").unwrap();

        let reg = ChannelRegistry::load(dir.registry());
        assert!(!reg.is_read_only());
        assert!(holds_ada(&reg), "claims come back from the backup");
        assert_eq!(dir.corrupt_copies(), 1);
        assert!(
            matches!(read_registry_file(&dir.registry()), Ok(Some(_))),
            "the good copy is put back under the real name"
        );

        let reloaded = ChannelRegistry::load(dir.registry());
        assert!(holds_ada(&reloaded));
        assert!(
            !backup_path(&dir.registry()).exists(),
            "once the destination reads cleanly the backup is ordinary leftover"
        );
    }

    #[test]
    fn a_corrupt_registry_and_a_corrupt_backup_go_read_only() {
        let dir = ScratchDir::new("both");
        fs::write(dir.registry(), b"not json").unwrap();
        fs::write(backup_path(&dir.registry()), b"nor this").unwrap();

        let reg = ChannelRegistry::load(dir.registry());
        assert!(reg.is_read_only());
        assert_eq!(dir.corrupt_copies(), 2, "both unreadable files are kept aside");
        assert_eq!(fs::read(dir.registry()).unwrap(), b"not json");
    }

    #[test]
    fn an_interrupted_write_is_recovered_from_the_backup() {
        let dir = ScratchDir::new("interrupted");
        seed_registry(&dir.registry());
        fs::rename(dir.registry(), backup_path(&dir.registry())).unwrap();

        let reg = ChannelRegistry::load(dir.registry());
        assert!(!reg.is_read_only());
        assert!(holds_ada(&reg));
        assert!(dir.registry().exists());
        assert!(!backup_path(&dir.registry()).exists());
    }

    #[test]
    fn a_missing_registry_with_a_corrupt_backup_goes_read_only() {
        let dir = ScratchDir::new("badbackup");
        fs::write(backup_path(&dir.registry()), b"not json").unwrap();

        let reg = ChannelRegistry::load(dir.registry());
        assert!(reg.is_read_only(), "a backup on disk means there was a registry");
        assert!(!dir.registry().exists(), "and nothing is written in its place");
        assert_eq!(dir.corrupt_copies(), 1);
    }

    #[test]
    fn an_empty_registry_file_is_treated_as_corrupt() {
        let dir = ScratchDir::new("empty");
        fs::write(dir.registry(), b"").unwrap();
        assert!(ChannelRegistry::load(dir.registry()).is_read_only());
    }

    fn user_key(i: usize) -> String {
        format!("{:064x}", i + 1)
    }

    fn room_id(i: usize) -> String {
        format!("{:032x}", i + 1)
    }

    /// A burst of refreshes is one write, taken when the owner flushes, and in
    /// compact form.
    #[test]
    fn writes_are_debounced_until_a_flush() {
        let dir = ScratchDir::new("debounce");
        let mut reg = ChannelRegistry::load(dir.registry());
        assert!(!reg.has_pending_writes(), "loading an empty registry writes nothing");
        for i in 0..50 {
            assert!(reg.claim_username(&user_key(i), &format!("user{i}")).is_ok());
        }
        assert!(!dir.registry().exists(), "no claim writes the file itself");
        assert!(reg.has_pending_writes());

        let job = reg.take_persist_job().expect("mutations leave a snapshot to write");
        assert!(reg.take_persist_job().is_none(), "one snapshot covers the whole burst");
        assert!(!reg.has_pending_writes());
        assert!(job.write());
        let bytes = fs::read(dir.registry()).unwrap();
        assert!(!bytes.contains(&b'\n'), "snapshots are written compact");

        let reloaded = ChannelRegistry::load(dir.registry());
        assert!(reloaded.holds_username(&user_key(49), "user49"));

        assert!(reg.claim_username(&user_key(0), "user0").is_ok());
        assert!(reg.has_pending_writes(), "a refresh re-arms the flush");
    }

    /// Only changes nothing would recreate are durable; refreshes and an
    /// in-memory registry never make a caller wait for disk.
    #[test]
    fn only_state_creating_writes_are_durable() {
        let dir = ScratchDir::new("durable");
        let mut reg = ChannelRegistry::load(dir.registry());
        let t0 = 1_700_000_000;
        let mut last = reg.durable_generation();
        let mut step = |reg: &ChannelRegistry, durable: bool, what: &str| {
            let now = reg.durable_generation();
            assert_eq!(now > last, durable, "{what}");
            last = now;
        };
        assert!(reg.claim_username_at(&user_key(0), "Ada", t0).is_ok());
        step(&reg, true, "a new username");
        assert!(reg.claim_username_at(&user_key(0), "Ada", t0 + 1).is_ok());
        step(&reg, false, "a username refresh");
        assert!(reg.claim_channel_name_at(&room_id(0), &user_key(0), "Lobby", false, t0).is_ok());
        step(&reg, true, "a new room name");
        assert!(reg.claim_channel_name_at(&room_id(0), &user_key(0), "Lobby", false, t0 + 1).is_ok());
        step(&reg, false, "a room refresh");
        assert!(reg.claim_channel_name_at(&room_id(0), &user_key(0), "Lobby", true, t0 + 2).is_ok());
        step(&reg, true, "going private");
        assert!(reg.set_channel_nominee(&room_id(0), &user_key(0), &user_key(5), 7).is_ok());
        step(&reg, true, "a nomination");
        assert!(reg.set_channel_nominee(&room_id(0), &user_key(0), &user_key(5), 7).is_ok());
        step(&reg, false, "an unchanged nomination");
        assert!(reg
            .handover_channel_name(&room_id(0), &room_id(1), &user_key(1), &user_key(0), t0 + 3)
            .is_ok());
        step(&reg, true, "a handover");
        assert!(reg.delete_channel(&room_id(1), &user_key(1)).is_ok());
        step(&reg, true, "a delete");
        let job = reg.take_persist_job().unwrap();
        assert_eq!(job.generation(), reg.generation, "a snapshot covers every mutation so far");

        let mut memory = ChannelRegistry::in_memory();
        assert!(memory.claim_username_at(&user_key(0), "Ada", t0).is_ok());
        assert_eq!(memory.durable_generation(), 0);
    }

    #[test]
    fn a_failed_write_is_retried_by_the_next_flush() {
        let dir = ScratchDir::new("retry");
        let nested = dir.0.join("nested");
        let path = nested.join("channels.json");
        let mut reg = ChannelRegistry::load(path.clone());
        assert!(reg.claim_username(&user_key(0), "Ada").is_ok());
        fs::remove_dir_all(&nested).unwrap();
        assert!(!reg.take_persist_job().unwrap().write());
        assert!(reg.has_pending_writes(), "the lost write is still owed");
        fs::create_dir_all(&nested).unwrap();
        assert!(reg.flush_blocking());
        assert!(ChannelRegistry::load(path).holds_username(&user_key(0), "Ada"));
    }

    /// Two snapshots can be in flight at once; the older must never land last.
    #[test]
    fn an_older_snapshot_never_overwrites_a_newer_one() {
        let dir = ScratchDir::new("order");
        let mut reg = ChannelRegistry::load(dir.registry());
        assert!(reg.claim_username(&user_key(0), "Ada").is_ok());
        let older = reg.take_persist_job().unwrap();
        assert!(reg.claim_username(&user_key(1), "Bob").is_ok());
        let newer = reg.take_persist_job().unwrap();
        assert!(newer.write());
        assert!(older.write(), "a superseded snapshot is simply dropped");
        let reloaded = ChannelRegistry::load(dir.registry());
        assert!(reloaded.holds_username(&user_key(1), "Bob"));
    }

    /// The final snapshot carries the last acknowledged write, and nothing is
    /// acknowledged after it.
    #[test]
    fn closing_for_shutdown_flushes_and_refuses_later_writes() {
        let dir = ScratchDir::new("shutdown");
        let mut reg = ChannelRegistry::load(dir.registry());
        assert!(reg.claim_username(&user_key(0), "Ada").is_ok());
        reg.close_for_shutdown();
        assert!(reg.take_persist_job().expect("pending write").write());
        assert_eq!(
            reg.claim_username(&user_key(1), "Bob"),
            Err(RegistryError::ReadOnly)
        );
        assert!(!reg.reap_stale(unix_now() + 2 * USERNAME_IDLE_SECS));
        assert!(!reg.has_pending_writes());
        assert!(ChannelRegistry::load(dir.registry()).holds_username(&user_key(0), "Ada"));
    }

    /// Claims no longer reap the whole registry, so each must still find an
    /// abandoned name free on its own — the exact name, a lookalike of it, and
    /// the claimant room's own lapsed name.
    #[test]
    fn a_claim_reaps_exactly_the_abandoned_records_it_depends_on() {
        let t0 = 1_700_000_000;
        let released = t0 + NAME_RELEASE_SECS + 1;
        let mut reg = ChannelRegistry::in_memory();
        assert!(reg.claim_channel_name_at(&room_id(0), &user_key(0), "Lobby", false, t0).is_ok());
        assert!(reg.claim_channel_name_at(&room_id(1), &user_key(1), "Lounge", false, t0).is_ok());
        assert!(reg.claim_channel_name_at(&room_id(2), &user_key(2), "Attic", false, t0).is_ok());

        assert_eq!(
            reg.claim_channel_name_at(&room_id(3), &user_key(3), "Lobby", false, released - 1),
            Err(RegistryError::Taken),
            "not yet released"
        );
        assert!(reg
            .claim_channel_name_at(&room_id(3), &user_key(3), "Lobby", false, released)
            .is_ok());
        assert!(
            reg.claim_channel_name_at(&room_id(4), &user_key(4), "L\u{03BF}unge", false, released)
                .is_ok(),
            "a lookalike of an abandoned name is free once it is"
        );
        assert!(
            reg.claim_channel_name_at(&room_id(2), &user_key(2), "Cellar", false, released)
                .is_ok(),
            "a returning owner's lapsed name no longer pins their room"
        );
        assert!(reg.names.len() == 3 && !reg.names.contains_key("attic"));
    }

    #[test]
    fn a_nominated_name_is_only_freed_by_a_claim_after_its_grace() {
        let mut reg = ChannelRegistry::in_memory();
        let t0 = 1_700_000_000;
        nominated_lobby(&mut reg, CLAIM_AFTER_DAYS_MAX, t0);
        let deadline = t0 + i64::from(CLAIM_AFTER_DAYS_MAX) * 86_400 + NOMINEE_GRACE_SECS;
        assert_eq!(
            reg.claim_channel_name_at(&"99".repeat(16), &"88".repeat(32), "Lobby", false, deadline),
            Err(RegistryError::Taken)
        );
        assert!(reg
            .claim_channel_name_at(&"99".repeat(16), &"88".repeat(32), "Lobby", false, deadline + 1)
            .is_ok());
    }

    #[test]
    fn channel_indexes_follow_handover_delete_and_reap() {
        let mut reg = ChannelRegistry::in_memory();
        let t0 = 1_700_000_000;
        let (old_id, new_id) = (room_id(0), room_id(1));
        assert!(reg.claim_channel_name_at(&old_id, &user_key(0), "Lobby", false, t0).is_ok());
        assert!(reg
            .handover_channel_name(&old_id, &new_id, &user_key(1), &user_key(0), t0)
            .is_ok());
        assert!(!reg.has_channel(&old_id));
        assert!(reg.has_channel(&new_id.to_uppercase()));
        assert_eq!(reg.names["lobby"].created_at, t0, "a handover keeps seniority");
        assert!(reg.delete_channel(&new_id, &user_key(1)).is_ok());
        assert!(reg.is_deleted(&new_id));
        assert!(!reg.has_channel(&new_id));

        let lapsed = room_id(2);
        assert!(reg.claim_channel_name_at(&lapsed, &user_key(2), "Attic", false, t0).is_ok());
        assert!(reg.reap_stale(t0 + NAME_RELEASE_SECS + 1));
        assert!(!reg.by_channel.contains_key(&lapsed));
        assert!(!reg.by_skeleton.contains_key(&confusable_key("attic")));
        assert!(
            reg.by_skeleton.contains_key(&confusable_key("lobby")),
            "a tombstoned name keeps its skeleton"
        );
    }

    #[test]
    fn a_successors_handover_retry_keeps_its_room_alive() {
        let mut reg = ChannelRegistry::in_memory();
        let t0 = 1_700_000_000;
        let owner = user_key(0);
        let old_id = channel_id_of_key(&owner).unwrap();
        let (new_id, new_pk) = (room_id(1), user_key(1));
        let nominee = user_key(2);
        assert!(reg.claim_channel_name_at(&old_id, &owner, "Lobby", false, t0).is_ok());
        assert!(reg.set_channel_nominee(&old_id, &owner, &nominee, 7).is_ok());
        let takeover = t0 + 8 * 86_400;
        assert!(reg
            .handover_channel_name(&old_id, &new_id, &new_pk, &nominee, takeover)
            .is_ok());

        // Its device holds some other name, so its claims are refused and it
        // retries the handover instead: that has to count as a refresh.
        let later = takeover + 6 * 86_400;
        assert!(reg.handover_channel_name(&old_id, &new_id, &new_pk, &nominee, later).is_ok());
        assert_eq!(reg.names.get("lobby").unwrap().refreshed_at, later);

        let stranger = user_key(9);
        assert!(reg
            .handover_channel_name(&old_id, &new_id, &new_pk, &stranger, later + 86_400)
            .is_ok());
        assert_eq!(
            reg.names.get("lobby").unwrap().refreshed_at,
            later,
            "nobody else's request keeps the room's name held"
        );
    }

    /// After an explicit transfer the registry does not know the new owner's
    /// user key, so only the successor room's own key keeps the name alive —
    /// the first stranger to retry does not get to become the one who does.
    #[test]
    fn after_an_explicit_transfer_only_the_successor_room_key_refreshes() {
        let mut reg = ChannelRegistry::in_memory();
        let t0 = 1_700_000_000;
        let owner = user_key(0);
        let old_id = channel_id_of_key(&owner).unwrap();
        let new_pk = user_key(1);
        let new_id = channel_id_of_key(&new_pk).unwrap();
        let stranger = user_key(3);
        assert!(reg.claim_channel_name_at(&old_id, &owner, "Lobby", false, t0).is_ok());
        assert!(reg.handover_channel_name(&old_id, &new_id, &new_pk, &owner, t0).is_ok());
        assert!(reg.names.get("lobby").unwrap().inheritor.is_empty());

        assert!(reg.handover_channel_name(&old_id, &new_id, &new_pk, &stranger, t0 + 10).is_ok());
        assert_eq!(
            reg.names.get("lobby").unwrap().refreshed_at,
            t0,
            "a stranger's retry keeps nothing alive"
        );
        assert!(reg.names.get("lobby").unwrap().inheritor.is_empty(), "nor names anyone");
        assert!(reg.handover_channel_name(&old_id, &new_id, &new_pk, &owner, t0 + 20).is_ok());
        assert_eq!(
            reg.names.get("lobby").unwrap().refreshed_at,
            t0,
            "the outgoing owner's retries say nothing about the successor"
        );

        assert!(reg.handover_channel_name(&old_id, &new_id, &new_pk, &new_pk, t0 + 30).is_ok());
        assert_eq!(reg.names.get("lobby").unwrap().refreshed_at, t0 + 30);
        assert!(reg.handover_channel_name(&old_id, &new_id, &new_pk, &stranger, t0 + 40).is_ok());
        assert_eq!(reg.names.get("lobby").unwrap().refreshed_at, t0 + 30);
    }

    /// A successor on a build whose handover retries carry only its user key
    /// still re-claims with its room key; refused for holding another name,
    /// that claim still keeps the name it inherited alive — and nobody else's
    /// claim does.
    #[test]
    fn a_room_keys_claim_for_another_name_keeps_its_own_name_alive() {
        let mut reg = ChannelRegistry::in_memory();
        let t0 = 1_700_000_000;
        let owner = user_key(0);
        let old_id = channel_id_of_key(&owner).unwrap();
        let new_pk = user_key(1);
        let new_id = channel_id_of_key(&new_pk).unwrap();
        assert!(reg.claim_channel_name_at(&old_id, &owner, "Lobby", false, t0).is_ok());
        assert!(reg.handover_channel_name(&old_id, &new_id, &new_pk, &owner, t0).is_ok());

        assert_eq!(
            reg.claim_channel_name_at(&new_id, &new_pk, "Attic", false, t0 + 50),
            Err(RegistryError::Taken),
            "still one name per room"
        );
        assert_eq!(reg.names.get("lobby").unwrap().refreshed_at, t0 + 50);
        assert!(!reg.names.contains_key("attic"));

        let other_pk = user_key(2);
        let other_id = channel_id_of_key(&other_pk).unwrap();
        assert!(reg.claim_channel_name_at(&other_id, &other_pk, "Den", false, t0 + 60).is_ok());
        assert_eq!(
            reg.claim_channel_name_at(&other_id, &other_pk, "Lobby", false, t0 + 70),
            Err(RegistryError::Taken)
        );
        assert_eq!(reg.names.get("lobby").unwrap().refreshed_at, t0 + 50);
    }

    /// A retried handover (its first answer lost, or answered 503 while the
    /// write was still pending) must read as done, not as "name taken".
    #[test]
    fn a_repeated_handover_is_idempotent() {
        let mut reg = ChannelRegistry::in_memory();
        let t0 = 1_700_000_000;
        // The outgoing owner's retry: its key really is the old room's.
        let old_id = channel_id_of_key(&user_key(0)).unwrap();
        let new_id = room_id(1);
        assert!(reg.claim_channel_name_at(&old_id, &user_key(0), "Lobby", false, t0).is_ok());
        assert!(reg
            .handover_channel_name(&old_id, &new_id, &user_key(1), &user_key(0), t0)
            .is_ok());
        let generation = reg.generation;
        assert!(reg
            .handover_channel_name(&old_id, &new_id.to_uppercase(), &user_key(1), &user_key(0), t0 + 5)
            .is_ok());
        assert_eq!(reg.generation, generation, "the retry changes nothing");
        assert_eq!(
            reg.handover_channel_name(&old_id, &new_id, &user_key(2), &user_key(0), t0 + 5),
            Err(RegistryError::Taken),
            "a different successor key is not the same handover"
        );
        assert_eq!(
            reg.handover_channel_name(&room_id(7), &new_id, &user_key(1), &user_key(0), t0 + 5),
            Err(RegistryError::Taken),
            "nor is one from a different room"
        );

        assert_eq!(
            reg.names.get("lobby").unwrap().refreshed_at,
            t0,
            "the outgoing owner's retry says nothing about the successor being alive"
        );

        // A successor that already held a name of its own is still refused.
        assert!(reg.claim_channel_name_at(&room_id(2), &user_key(2), "Attic", false, t0).is_ok());
        assert!(reg.claim_channel_name_at(&room_id(3), &user_key(3), "Cellar", false, t0).is_ok());
        assert_eq!(
            reg.handover_channel_name(&room_id(2), &room_id(3), &user_key(3), &user_key(2), t0),
            Err(RegistryError::Taken)
        );
    }

    fn walk_directory(reg: &ChannelRegistry, limit: usize, now: i64) -> (Vec<String>, usize) {
        let mut ids = Vec::new();
        let mut cursor = None;
        let mut pages = 0;
        loop {
            let page = reg.directory_page_at(cursor.as_ref(), limit, now, 0);
            pages += 1;
            assert!(page.channels.len() <= limit);
            ids.extend(page.channels.into_iter().map(|listing| listing.channel_id));
            match page.next_cursor {
                Some(next) => cursor = Some(DirectoryCursor::parse(&next).expect("own cursor")),
                None => return (ids, pages),
            }
        }
    }

    #[test]
    fn directory_pages_cover_every_listing_once_in_rank_order() {
        let mut reg = ChannelRegistry::in_memory();
        let t0 = 1_700_000_000;
        for i in 0..1_203 {
            // Several rooms per second, so ties on `created_at` are exercised.
            let at = t0 + (i as i64 * 7919) % 400;
            assert!(reg
                .claim_channel_name_at(&room_id(i), &user_key(i), &format!("room{i}"), false, at)
                .is_ok());
        }
        let now = t0 + 400;
        let expected: Vec<String> = reg
            .public_directory_at(now)
            .into_iter()
            .map(|listing| listing.channel_id)
            .collect();
        assert_eq!(expected.len(), 1_203);
        let (walked, pages) = walk_directory(&reg, DIRECTORY_PAGE_SIZE, now);
        assert_eq!(pages, 3);
        assert_eq!(walked, expected, "pages reproduce the ranking exactly");

        let ranked = reg.ranked_directory(now);
        assert!(ranked.windows(2).all(|pair| pair[0].0 < pair[1].0), "strict order");

        // A room created mid-walk ranks last, so it is picked up rather than
        // shifting rows under a cursor already handed out.
        let first = reg.directory_page_at(None, DIRECTORY_PAGE_SIZE, now, 0);
        assert!(reg
            .claim_channel_name_at(&room_id(5_000), &user_key(5_000), "latecomer", false, now)
            .is_ok());
        let cursor = DirectoryCursor::parse(first.next_cursor.as_deref().unwrap()).unwrap();
        let (rest, _) = {
            let mut ids = Vec::new();
            let mut cursor = Some(cursor);
            loop {
                let page = reg.directory_page_at(cursor.as_ref(), DIRECTORY_PAGE_SIZE, now, 0);
                ids.extend(page.channels.into_iter().map(|listing| listing.channel_id));
                match page.next_cursor {
                    Some(next) => cursor = DirectoryCursor::parse(&next),
                    None => break (ids, ()),
                }
            }
        };
        assert_eq!(rest.len(), 1_203 - DIRECTORY_PAGE_SIZE + 1);
        assert_eq!(rest.last(), Some(&room_id(5_000)));
    }

    #[test]
    fn a_flood_of_new_rooms_cannot_push_established_ones_out() {
        let mut reg = ChannelRegistry::in_memory();
        let t0 = 1_700_000_000;
        for i in 0..10 {
            assert!(reg
                .claim_channel_name_at(&room_id(i), &user_key(i), &format!("est{i}"), false, t0)
                .is_ok());
        }
        let flood_at = t0 + 3_600;
        for i in 10..(10 + MAX_DIRECTORY_LISTINGS + 50) {
            assert!(reg
                .claim_channel_name_at(&room_id(i), &user_key(i), &format!("f{i}"), false, flood_at)
                .is_ok());
        }
        let listed = reg.public_directory_at(flood_at);
        assert_eq!(listed.len(), MAX_DIRECTORY_LISTINGS, "the directory is capped");
        for (i, listing) in listed.iter().enumerate().take(10) {
            assert_eq!(listing.channel_id, room_id(i), "established rooms rank first");
        }
        let (walked, pages) = walk_directory(&reg, DIRECTORY_PAGE_SIZE, flood_at);
        assert_eq!(walked.len(), MAX_DIRECTORY_LISTINGS);
        assert_eq!(pages, MAX_DIRECTORY_LISTINGS / DIRECTORY_PAGE_SIZE);
    }

    /// A client that predates paging reads one page and must accept it: its
    /// response limit is 256 KiB, whatever the names contain.
    #[test]
    fn a_first_page_of_worst_case_names_fits_a_legacy_client() {
        let mut reg = ChannelRegistry::in_memory();
        let now = unix_now();
        for i in 0..(DIRECTORY_PAGE_SIZE + 10) {
            let name = format!("{i:04}{}", "\"".repeat(CHANNEL_NAME_MAX - 4));
            assert_eq!(name.len(), CHANNEL_NAME_MAX);
            assert!(reg
                .claim_channel_name_at(&room_id(i), &user_key(i), &name, false, now)
                .is_ok());
        }
        let page = reg.directory_page(None, DIRECTORY_PAGE_SIZE);
        assert_eq!(page.channels.len(), DIRECTORY_PAGE_SIZE);
        assert!(page.next_cursor.is_some());
        let body = serde_json::to_vec(&serde_json::json!({
            "channels": page.channels,
            "next_cursor": page.next_cursor,
        }))
        .unwrap();
        assert!(body.len() < 256 * 1024, "first page is {} bytes", body.len());
    }

    #[test]
    fn directory_cursors_round_trip_and_reject_garbage() {
        let cursor = DirectoryCursor::parse(&format!("1700000000.{}", "AB".repeat(16))).unwrap();
        assert_eq!(cursor.encode(), format!("1700000000.{}", "ab".repeat(16)));
        for bad in [
            "",
            ".",
            "12",
            "-1.00000000000000000000000000000000",
            "1.0000000000000000000000000000000",
            "1.0000000000000000000000000000000g",
            "99999999999999999999.00000000000000000000000000000000",
            "1.00000000000000000000000000000000.1",
        ] {
            assert!(DirectoryCursor::parse(bad).is_none(), "{bad:?}");
        }
    }

    /// Writes invalidate the cached ranking but rebuild it at most once per
    /// interval, and age alone forces a rebuild.
    #[test]
    fn the_directory_ranking_is_cached_between_rebuilds() {
        let mut reg = ChannelRegistry::in_memory();
        let t0 = 1_700_000_000;
        assert!(reg.claim_channel_name_at(&room_id(0), &user_key(0), "Lobby", false, t0).is_ok());
        let count = |reg: &ChannelRegistry, now| reg.directory_page_at(None, 10, now, 2).channels.len();
        assert_eq!(count(&reg, t0), 1);
        assert!(reg.claim_channel_name_at(&room_id(1), &user_key(1), "Lounge", false, t0).is_ok());
        assert_eq!(count(&reg, t0 + 1), 1, "a write inside the interval is not rebuilt yet");
        assert_eq!(count(&reg, t0 + 2), 2);

        // With no writes at all, a listing still ages out once the cache does.
        let stale = t0 + CHANNEL_DIRECTORY_STALE_SECS + 1;
        assert_eq!(count(&reg, stale), 0);
    }
}
