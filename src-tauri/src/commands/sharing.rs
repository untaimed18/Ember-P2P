use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tauri::Emitter;
use tauri::Manager;
use tauri_plugin_dialog::DialogExt;

use tokio::sync::RwLock;

/// How long a claim keeps other passes off a path. Comfortably longer than
/// [`HASH_STALL_TIMEOUT`], so a merely slow drain is never raced, but finite:
/// `spawn_blocking` cannot be aborted, and a read wedged in the kernel (offline
/// cloud placeholder, dropped network share, antivirus hold) never returns, so
/// a permanent claim would leave that file unindexed for the rest of the
/// session with only a log line to say why. Counted from the last progress the
/// consumer saw rather than from the claim, since a large file on a slow drive
/// is read for far longer than this.
const IN_FLIGHT_HASH_LEASE: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// How long a hash may go without reading a byte before the pass gives up
/// waiting for it and moves on.
///
/// Measured from the last progress rather than from the start. A ceiling on
/// the whole read cannot tell a wedged read from a large file on a slow drive:
/// a 20 GB archive on a USB disk at 40 MB/s takes over eight minutes, so it
/// timed out on every launch, and the result it went on to compute was thrown
/// away. The file never reached known.met and was read end to end again on the
/// next launch, and the one after, for as long as it stayed shared.
pub(crate) const HASH_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// How often a waiting pass looks at a hash's progress counter.
const HASH_PROGRESS_POLL: std::time::Duration = std::time::Duration::from_secs(5);

/// Paces the `file-hash-progress` stream that drives the library scan's
/// progress UI.
///
/// The emit sits in a per-file loop whose body, for small files, finishes in
/// about a millisecond — so on an SSD it produced thousands of events per
/// second, each serialised to JSON, pushed across the Tauri IPC bridge, and
/// assigned into a Svelte `$state` that re-renders on every write. The window
/// got *less* responsive the faster the disk was. The `shared-files-changed`
/// emit in the same loop was already rate-limited; this is the same treatment.
///
/// Only the in-loop updates are paced. Both callers emit an unthrottled
/// terminal `done` event after the loop, so the bar always lands on full.
struct HashProgressEmitter {
    last_emit: Option<std::time::Instant>,
    /// How many files in this pass are a one-time digest top-up rather than
    /// something newly discovered.
    ///
    /// Reported so the UI can say which it is. A library carried over from a
    /// build that predates `ember_file_hash` has every record queued for a
    /// top-up, and reading that many files takes as long as reading the library
    /// — hours on a big share, days on a very big one. Shown as an ordinary
    /// "scanning" bar it looks like Ember is re-hashing from scratch and has
    /// hung, which is precisely what it was reported as. It is neither: the
    /// files stay shared and servable throughout, and the pass never runs again.
    upgrading: usize,
}

impl HashProgressEmitter {
    /// Fast enough to read as continuous, slow enough that the webview keeps
    /// up with a disk hashing thousands of small files a second.
    const MIN_INTERVAL: std::time::Duration = std::time::Duration::from_millis(150);

    fn new(files_to_hash: &[FileInfo]) -> Self {
        Self {
            last_emit: None,
            upgrading: files_to_hash
                .iter()
                .filter(|f| f.id.starts_with(crate::search::index::REHASH_ID_PREFIX))
                .count(),
        }
    }

    fn emit(&mut self, app: &tauri::AppHandle, current: usize, total: usize, file_name: &str) {
        let now = std::time::Instant::now();
        // The first update always goes out, so the bar appears immediately
        // rather than after the first interval.
        if self
            .last_emit
            .is_some_and(|at| now.duration_since(at) < Self::MIN_INTERVAL)
        {
            return;
        }
        self.last_emit = Some(now);
        let _ = app.emit(
            "file-hash-progress",
            serde_json::json!({
                "current": current,
                "total": total,
                "file_name": file_name,
                "upgrading": self.upgrading,
            }),
        );
    }
}

/// Paths whose `hash_file_cancellable` is still running after the 5-minute
/// scan timeout. The scan continues, but a later pass must not start a second
/// blocking hash of the same file until the first drain completes or its lease
/// expires.
///
/// Claims carry a generation so a drain that finishes after its lease was taken
/// over releases only its own claim, never the newer one — the same
/// "only if still current" rule the scan cancel flags use.
fn hashing_in_flight() -> &'static Mutex<HashMap<String, (u64, std::time::Instant)>> {
    static CLAIMS: OnceLock<Mutex<HashMap<String, (u64, std::time::Instant)>>> = OnceLock::new();
    CLAIMS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Claim `path` for hashing, returning the generation to release it with.
/// `None` means another pass holds an unexpired claim.
fn try_claim_in_flight_hash(path: &str) -> Option<u64> {
    static NEXT_CLAIM: AtomicU64 = AtomicU64::new(1);
    let now = std::time::Instant::now();
    let mut claims = hashing_in_flight()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some((_, claimed_at)) = claims.get(path) {
        if now.duration_since(*claimed_at) < IN_FLIGHT_HASH_LEASE {
            return None;
        }
        warn!(
            "Previous hash of {path} has been draining for over {}s; retrying it",
            IN_FLIGHT_HASH_LEASE.as_secs()
        );
    }
    let claim = NEXT_CLAIM.fetch_add(1, Ordering::Relaxed);
    claims.insert(path.to_string(), (claim, now));
    Some(claim)
}

pub(crate) fn release_in_flight_hash(path: &str, claim: u64) {
    let mut claims = hashing_in_flight()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if claims.get(path).is_some_and(|(current, _)| *current == claim) {
        claims.remove(path);
    }
}

/// Restart `claim`'s lease on `path`, if it is still the current one.
fn renew_in_flight_hash(path: &str, claim: u64) {
    let mut claims = hashing_in_flight()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some((current, claimed_at)) = claims.get_mut(path) {
        if *current == claim {
            *claimed_at = std::time::Instant::now();
        }
    }
}

/// A hash read made no progress for the whole stall window.
#[derive(Debug)]
pub(crate) struct HashStalled;

/// Wait for a started hash for as long as it keeps reading.
///
/// Gives up only after [`HASH_STALL_TIMEOUT`] passes with `progress` standing
/// still, and renews the claim on `path` each time it moves. The task keeps
/// running either way; on `Err` the caller owns draining it.
pub(crate) async fn await_hash(
    task: &mut tokio::task::JoinHandle<HashPassResult>,
    progress: &AtomicU64,
    path: &str,
    claim: u64,
) -> Result<Result<HashPassResult, tokio::task::JoinError>, HashStalled> {
    await_hash_within(task, progress, HASH_STALL_TIMEOUT, || {
        renew_in_flight_hash(path, claim)
    })
    .await
}

async fn await_hash_within(
    task: &mut tokio::task::JoinHandle<HashPassResult>,
    progress: &AtomicU64,
    stall: std::time::Duration,
    mut on_progress: impl FnMut(),
) -> Result<Result<HashPassResult, tokio::task::JoinError>, HashStalled> {
    let mut seen = progress.load(Ordering::Relaxed);
    let mut deadline = tokio::time::Instant::now() + stall;
    loop {
        let wake = (tokio::time::Instant::now() + HASH_PROGRESS_POLL).min(deadline);
        if let Ok(result) = tokio::time::timeout_at(wake, &mut *task).await {
            return Ok(result);
        }
        let now = progress.load(Ordering::Relaxed);
        if now != seen {
            seen = now;
            deadline = tokio::time::Instant::now() + stall;
            on_progress();
        } else if tokio::time::Instant::now() >= deadline {
            return Err(HashStalled);
        }
    }
}

/// What a single queued file's hash pass produces.
type HashPassResult = anyhow::Result<(String, String, Vec<[u8; 16]>, String, u64, i64)>;

/// Which one-time repairs a row still wants, given what `known.met` supplied.
///
/// Both are top-ups to a record that is already complete enough to serve: the
/// file has an ed2k id and its part hashes, so it is shared, searchable and
/// downloadable whether or not either of these is ever filled in.
///
/// A single-part file legitimately has no AICH root, so an empty one there is
/// the stored answer rather than a gap to fill. "Single part" has to be the
/// hasher's own boundary — `file_size < PARTSIZE` — because a file of exactly
/// `PARTSIZE` is two parts to it (one of data, one empty) and it does compute a
/// root. Asking with `>` instead left that one size unable to recover a missing
/// root through any route, since this is what decides whether it is computed.
/// Taken apart from `FileInfo` so the narrow [`TopUpRow`] answers it with the
/// same code rather than a copy of the rule — the drift `wants_hash_top_up`
/// warns about, one layer down.
fn wanted_digests(
    aich_hash: &str,
    ember_file_hash: &str,
    size: u64,
) -> crate::network::ed2k::hash::WantedDigests {
    crate::network::ed2k::hash::WantedDigests {
        aich: aich_hash.is_empty() && size >= crate::network::ed2k::hash::PARTSIZE,
        ember: ember_file_hash.is_empty(),
    }
}

fn wanted_top_up(file: &FileInfo) -> crate::network::ed2k::hash::WantedDigests {
    wanted_digests(&file.aich_hash, &file.ember_file_hash, file.size)
}

/// Whether a row has nothing left to top up.
fn top_up_complete(want: crate::network::ed2k::hash::WantedDigests) -> bool {
    !want.aich && !want.ember
}

/// Whether a row still wants one of the background repairs.
///
/// The startup path in `lib.rs` resolves `known.met` itself rather than going
/// through [`resolve_from_known`], so it needs the same question answered by
/// the same code — the two classifications drifting apart is how a file ends up
/// queued in one place and skipped in the other.
pub(crate) fn wants_hash_top_up(file: &FileInfo) -> bool {
    !file.hash.is_empty() && !top_up_complete(wanted_top_up(file))
}

/// The ed2k hash and AICH root to carry forward for a row that needs only a
/// top-up, with what to compute, or `None` when it needs the full pass.
///
/// Keyed on what the row actually has rather than on how it was queued: we hold
/// the ed2k hash, and at least one of the two top-ups is outstanding. A row with
/// no ed2k hash has never been hashed and needs everything; a row with nothing
/// outstanding is here for some other reason and takes the full pass rather
/// than a whole-file read that would compute nothing.
///
/// This deliberately does not look at the id. It used to require the `rehash:`
/// prefix, which was true of every caller at the time and silently wrong once
/// the background pass started passing rows under their real content-hash
/// ids — they would have taken the full three-algorithm pass for want of a
/// prefix, on exactly the libraries where the saving matters most.
/// What the hash pipeline needs from a row, so it can schedule work for either
/// the scan's `FileInfo` rows or the top-up's narrow ones.
///
/// It reads three things and nothing else — where the file is, what to call it
/// in a log, and which digests to ask for — which is what lets the background
/// pass queue something far smaller than a whole `FileInfo`.
pub(crate) trait HashCandidate {
    fn path(&self) -> &str;
    fn name(&self) -> &str;
    fn top_up(&self) -> Option<TopUpInputs>;
}

/// The stored digests handed to a top-up read, plus which of them to recompute.
/// All three travel even when only one is wanted: whatever the pass is not asked
/// for is handed back unchanged rather than blank, because the caller assigns
/// the result onto the row.
pub(crate) type TopUpInputs = (
    String,
    String,
    String,
    crate::network::ed2k::hash::WantedDigests,
);

/// The columns the background top-up pass reads, and nothing else.
///
/// The queue used to hold whole `FileInfo` rows. It is fed from the startup
/// hydration, where on the run that matters most — a first launch after an
/// upgrade, on a library big enough to have paginated — that is every shared
/// file, resident twice until the pass drains it. `FileInfo` carries nine
/// `String` fields and a dozen counters; the pass reads five and two. Nothing
/// here is a copy of state that can change underneath it either: the size and
/// mtime are the ones discovery recorded, which is exactly what the
/// changed-since-discovery check wants to compare against.
#[derive(Clone)]
pub(crate) struct TopUpRow {
    pub(crate) path: String,
    pub(crate) name: String,
    pub(crate) hash: String,
    pub(crate) aich_hash: String,
    pub(crate) ember_file_hash: String,
    pub(crate) size: u64,
    pub(crate) modified_at: i64,
}

impl TopUpRow {
    /// `None` when the row has nothing to top up, so the queue never holds a
    /// file it would immediately skip.
    fn from_file(file: &FileInfo) -> Option<Self> {
        if !wants_hash_top_up(file) {
            return None;
        }
        Some(Self {
            path: file.path.clone(),
            name: file.name.clone(),
            hash: file.hash.clone(),
            aich_hash: file.aich_hash.clone(),
            ember_file_hash: file.ember_file_hash.clone(),
            size: file.size,
            modified_at: file.modified_at,
        })
    }

    fn wanted(&self) -> crate::network::ed2k::hash::WantedDigests {
        wanted_digests(&self.aich_hash, &self.ember_file_hash, self.size)
    }
}

impl HashCandidate for TopUpRow {
    fn path(&self) -> &str {
        &self.path
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn top_up(&self) -> Option<TopUpInputs> {
        if self.hash.is_empty() {
            return None;
        }
        let want = self.wanted();
        if top_up_complete(want) {
            return None;
        }
        Some((
            self.hash.clone(),
            self.aich_hash.clone(),
            self.ember_file_hash.clone(),
            want,
        ))
    }
}

impl HashCandidate for FileInfo {
    fn path(&self) -> &str {
        &self.path
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn top_up(&self) -> Option<TopUpInputs> {
        top_up_inputs(self)
    }
}

fn top_up_inputs(file: &FileInfo) -> Option<TopUpInputs> {
    if file.hash.is_empty() {
        return None;
    }
    let want = wanted_top_up(file);
    if top_up_complete(want) {
        return None;
    }
    // All three stored values travel, including the ones being recomputed:
    // whatever the pass is not asked for is handed back unchanged rather than
    // blank, because the caller assigns the result onto the row.
    Some((
        file.hash.clone(),
        file.aich_hash.clone(),
        file.ember_file_hash.clone(),
        want,
    ))
}

/// What the look-ahead has for the consumer right now.
///
/// `Busy` and `Done` were once the same answer — `None` — and that conflation
/// was a bug the moment a device could be occupied by a read the pass did not
/// start. Every consumer treats "nothing to hand out" as "the pass is over", so
/// a download verifying itself on the same drive ended the scan early, silently
/// skipped every remaining file, and let the resume cursor advance past them.
pub(crate) enum NextHash {
    Ready(StartedHash),
    /// Every device with work left is at its read limit. Nothing to do but
    /// wait; the queues are not empty.
    Busy,
    /// Queues are empty. The pass is finished.
    Done,
}

/// How long the pass defers to reads it does not own before proceeding anyway.
///
/// A verification takes seconds to minutes. A `spawn_blocking` read wedged on a
/// drive that stopped answering never returns at all, and cannot be aborted —
/// its guard would otherwise stall this and every later scan for the life of
/// the process. Courtesy with a deadline, rather than a new way to hang.
const EXTERNAL_READ_GRACE: std::time::Duration = std::time::Duration::from_secs(120);

/// One file hash started ahead of the loop that will consume it.
pub(crate) struct StartedHash {
    pub(crate) index: usize,
    /// Which device's budget this read is spending, so it can be given back.
    pub(crate) device: usize,
    pub(crate) claim: u64,
    /// Bytes the read has consumed so far; see [`await_hash`].
    pub(crate) progress: Arc<AtomicU64>,
    pub(crate) task: tokio::task::JoinHandle<HashPassResult>,
}

/// Keeps up to `concurrency` file hashes running ahead of the consumer, handing
/// them back in queue order.
///
/// The scan loop used to spawn one hash, await it, do its bookkeeping, and only
/// then start the next — so on a disk that can serve several reads at once the
/// drive sat idle for every CPU-bound stretch and the CPU sat idle for every
/// read. Nothing about the loop's bookkeeping wants to be concurrent, though:
/// it writes the index, hands off part hashes and moves counters, all of which
/// must stay ordered and serialized. So the overlap is confined to the part
/// that benefits, and results still arrive one at a time and in queue order —
/// the loop body downstream of this is unchanged.
///
/// The width is decided per device by [`crate::sharing::disk::device_hash_limit`],
/// which answers 1 for anything that might seek. That is the safeguard, and it
/// is applied to each drive separately: concurrent reads on one spindle turn
/// into head travel, but one read each on four drives is four drives working
/// instead of three sitting idle. A library on a single mechanical disk still
/// reads exactly one file at a time.
pub(crate) struct HashLookahead<'a, T: HashCandidate> {
    files: &'a [T],
    /// One queue per distinct device, each holding its files in discovery
    /// order, plus how many of its reads may be in flight at once.
    devices: Vec<DeviceQueue>,
    /// Round-robin cursor over `devices`, so no drive is starved by a longer
    /// queue on another.
    cursor: usize,
    cancel: Arc<AtomicBool>,
    inflight: std::collections::VecDeque<StartedHash>,
    /// The device of the row handed to the consumer, which is still being read
    /// as far as the drive is concerned until the consumer comes back for the
    /// next one.
    handed_out: Option<usize>,
    /// Latched once [`EXTERNAL_READ_GRACE`] has elapsed with no progress, and
    /// held until the other readers actually finish. Without the latch the
    /// decision was re-derived from `busy_since`, which every hand-out clears.
    ignoring_external: bool,
    /// When the pass first found every remaining device occupied by a read it
    /// did not start. Cleared as soon as one is handed out again.
    busy_since: Option<std::time::Instant>,
    /// Files passed over because another pass still holds their claim. The
    /// caller must treat a non-zero count as an incomplete page, or the resume
    /// cursor advances past a file nothing hashed.
    skipped: usize,
}

/// One device's share of the pass.
struct DeviceQueue {
    /// Identity, kept so the scheduler can ask how busy this device is with
    /// work that is not ours. `None` for devices we could not identify.
    key: Option<String>,
    limit: usize,
    pending: std::collections::VecDeque<usize>,
}

impl<'a, T: HashCandidate> HashLookahead<'a, T> {
    pub(crate) fn new(files: &'a [T], cancel: Arc<AtomicBool>) -> Self {
        // Group by physical device. Memoised on the parent directory because a
        // file and its directory are always on the same device, and resolving
        // one costs a syscall per path on Linux — tens of thousands of them on
        // the libraries this matters for.
        //
        // Every path whose device could not be identified shares the `None`
        // group, and that group reads one file at a time. Splitting them apart
        // would be asserting they are on different drives on the strength of
        // not knowing what drive either of them is on.
        let mut by_key: HashMap<Option<String>, usize> = HashMap::new();
        let mut parent_devices: HashMap<String, Option<crate::sharing::disk::DeviceInfo>> =
            HashMap::new();
        let mut devices: Vec<DeviceQueue> = Vec::new();
        for (index, file) in files.iter().enumerate() {
            let path = std::path::Path::new(file.path());
            let parent = path
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            let info = parent_devices
                .entry(parent)
                .or_insert_with(|| crate::sharing::disk::describe_device(path))
                .clone();
            let device = *by_key
                .entry(info.as_ref().map(|d| d.key.clone()))
                .or_insert_with(|| {
                    devices.push(DeviceQueue {
                        key: info.as_ref().map(|d| d.key.clone()),
                        limit: info.as_ref().map_or(1, |d| d.concurrency),
                        pending: std::collections::VecDeque::new(),
                    });
                    devices.len() - 1
                });
            devices[device].pending.push_back(index);
        }
        Self {
            files,
            devices,
            cursor: 0,
            cancel,
            inflight: std::collections::VecDeque::new(),
            handed_out: None,
            ignoring_external: false,
            busy_since: None,
            skipped: 0,
        }
    }

    /// Reads in flight on one device, counting the row the consumer holds and
    /// any read someone else is running on the same drive.
    ///
    /// The external count is what keeps a completing download from turning a
    /// carefully rationed one-read-at-a-time pass into two: the transfer never
    /// waits, so the scan is the side that has to notice and stand down. Past
    /// [`EXTERNAL_READ_GRACE`] it stops counting them, so a read that will
    /// never finish cannot stall the pass forever.
    fn device_inflight(&self, device: usize) -> usize {
        let ours = self.inflight.iter().filter(|s| s.device == device).count()
            + usize::from(self.handed_out == Some(device));
        if self.ignoring_external || self.waited_out_external() {
            return ours;
        }
        ours + crate::sharing::disk::external_reads(self.devices[device].key.as_deref())
    }

    /// Whether we have deferred to other readers for long enough.
    fn waited_out_external(&self) -> bool {
        self.busy_since
            .is_some_and(|since| since.elapsed() >= EXTERNAL_READ_GRACE)
    }

    fn total_inflight(&self) -> usize {
        self.inflight.len() + usize::from(self.handed_out.is_some())
    }

    /// The next `(file, device)` that may start: round-robin over the devices
    /// with room, so a drive is never held up waiting for another's queue.
    fn take_next_startable(&mut self) -> Option<(usize, usize)> {
        for offset in 0..self.devices.len() {
            let device = (self.cursor + offset) % self.devices.len();
            if self.devices[device].pending.is_empty() {
                continue;
            }
            if self.device_inflight(device) >= self.devices[device].limit {
                continue;
            }
            let index = self.devices[device].pending.pop_front()?;
            self.cursor = (device + 1) % self.devices.len();
            return Some((index, device));
        }
        None
    }

    /// How many files this pass could not start. See [`Self::skipped`].
    pub(crate) fn skipped(&self) -> usize {
        self.skipped
    }

    /// Identity of the device a handed-out read is spending, for a caller that
    /// has to keep it accounted for after taking the read over.
    ///
    /// A `spawn_blocking` read that hits its timeout cannot be cancelled, so
    /// the consumer detaches it into a drain task — and from that moment this
    /// pass stops counting it. Nothing else does either, so `device_inflight`
    /// sees the drive as free and `fill` starts another read on top of the one
    /// still going: one extra concurrent read per device per timeout, on
    /// precisely the wedging storage the timeout exists for, defeating both
    /// the per-device limit and `MAX_TOTAL_HASH_CONCURRENCY`. Pair this with
    /// [`crate::sharing::disk::note_external_read_for_key`] and hold the guard
    /// for the life of the drain.
    pub(crate) fn device_key(&self, device: usize) -> Option<&str> {
        self.devices.get(device).and_then(|d| d.key.as_deref())
    }

    /// The next started hash in queue order, or `None` when the queue is spent.
    ///
    /// Tops the window up *before* handing one out, never after. The one it
    /// returns is still running as far as the disk is concerned — the caller
    /// has yet to await it — so it is part of the window, and refilling
    /// afterwards would leave `concurrency + 1` reads outstanding. At a
    /// concurrency of 1 that is the difference between the strictly sequential
    /// pass a spinning disk needs and two concurrent reads, which is the exact
    /// thing `sharing::disk` exists to prevent.
    pub(crate) fn next_started(&mut self) -> NextHash {
        // The consumer asking for another row is what tells us the previous one
        // is finished; nothing else reports back into here. Releasing its
        // device slot first is what lets `fill` start that drive's next file.
        self.handed_out = None;
        // Latch the decision to stop deferring, rather than re-deriving it from
        // a timer that the next hand-out clears. `busy_since` is reset every
        // time a row goes out, so without this the grace bought exactly one
        // file and then started over: against a read that never returns — the
        // case the grace exists for — the pass advanced one file per two
        // minutes forever, which on a large library is indistinguishable from
        // the hang it was meant to break.
        if self.waited_out_external() {
            self.ignoring_external = true;
        }
        // Drop the latch once the readers we stood down for have actually
        // gone, so a later stall gets its own full grace period instead of
        // inheriting this one.
        if self.ignoring_external
            && self
                .devices
                .iter()
                .all(|d| crate::sharing::disk::external_reads(d.key.as_deref()) == 0)
        {
            self.ignoring_external = false;
            self.busy_since = None;
        }
        self.fill();
        if let Some(started) = self.inflight.pop_front() {
            self.busy_since = None;
            self.handed_out = Some(started.device);
            return NextHash::Ready(started);
        }
        // Nothing in flight. Whether that means "finished" or "wait" is decided
        // by the queues, not by this moment's capacity: work still pending with
        // nothing running means every device holding it is busy with somebody
        // else's read.
        if self.devices.iter().all(|d| d.pending.is_empty()) {
            self.busy_since = None;
            return NextHash::Done;
        }
        self.busy_since.get_or_insert_with(std::time::Instant::now);
        NextHash::Busy
    }

    fn fill(&mut self) {
        while self.total_inflight() < crate::sharing::disk::MAX_TOTAL_HASH_CONCURRENCY {
            let Some((index, device)) = self.take_next_startable() else {
                break;
            };
            let file = &self.files[index];
            let Some(claim) = try_claim_in_flight_hash(file.path()) else {
                warn!(
                    "Skipping hash of {} — a previous timed-out hash is still running",
                    file.name()
                );
                self.skipped += 1;
                continue;
            };
            let path = file.path().to_string();
            let cancel = self.cancel.clone();
            let top_up = file.top_up();
            let progress = Arc::new(AtomicU64::new(0));
            let read = progress.clone();
            let task = tokio::task::spawn_blocking(move || {
                let path = std::path::Path::new(&path);
                match top_up {
                    Some((ed2k, aich, ember, want)) => FileIndexer::hash_file_top_up_cancellable(
                        path, ed2k, aich, ember, want, &cancel, &read,
                    ),
                    None => FileIndexer::hash_file_cancellable(path, &cancel, &read),
                }
            });
            self.inflight.push_back(StartedHash {
                index,
                device,
                claim,
                progress,
                task,
            });
        }
    }

    /// Let go of one started hash the consumer will not process, releasing its
    /// claim only once the task has actually stopped.
    ///
    /// Every row this hands out is claimed, and the claim is the consumer's to
    /// release — so any row that does not reach the consumer's `match` has to
    /// come back through here. Dropping it instead would detach the task and
    /// strand the claim until the 15-minute lease expired, and the next scan
    /// would refuse to touch that file. Same drain the per-file timeout branch
    /// performs, for the same reason.
    pub(crate) fn drain_started(&self, started: StartedHash) {
        let path = self.files[started.index].path().to_string();
        tokio::spawn(async move {
            let _ = started.task.await;
            release_in_flight_hash(&path, started.claim);
        });
    }

    /// What this pass decided to do, once, before it starts. Worth a line in
    /// the log because "days" versus "hours" on a big library is entirely down
    /// to how many drives it found and what each of them said about seeking.
    pub(crate) fn log_plan(&self, what: &str, total: usize) {
        let width: usize = self.devices.iter().map(|d| d.limit).sum();
        if self.devices.len() > 1 || width > 1 {
            info!(
                "{what} {total} files across {} device(s), up to {} concurrent read(s)",
                self.devices.len(),
                width.min(crate::sharing::disk::MAX_TOTAL_HASH_CONCURRENCY),
            );
        }
    }

    /// Let go of everything still queued. Cancelling breaks out of the consumer
    /// loop with the look-ahead window still full, and every file in it is
    /// claimed.
    ///
    /// Returns the indices it detached. These reads were already running, so
    /// unlike [`Self::unstarted`] their results are genuinely lost — and a
    /// caller that tracks which files it has already offered needs to know
    /// that, or it will go on believing they were handled.
    pub(crate) fn abandon(&mut self) -> Vec<usize> {
        let pending: Vec<StartedHash> = self.inflight.drain(..).collect();
        let mut abandoned = Vec::with_capacity(pending.len());
        for started in pending {
            abandoned.push(started.index);
            self.drain_started(started);
        }
        abandoned
    }

    /// Indices still queued behind the look-ahead window, in device order.
    ///
    /// [`Self::abandon`] settles the reads already running; these never
    /// started, so a caller stopping early can hand them back to whatever owns
    /// the work list instead of dropping them on the floor. Drains, so calling
    /// it twice yields nothing the second time.
    pub(crate) fn unstarted(&mut self) -> Vec<usize> {
        let mut out = Vec::new();
        for device in &mut self.devices {
            out.extend(device.pending.drain(..));
        }
        out
    }
}

/// Maximum bytes for any single filesystem path accepted from the
/// frontend. Mirrors `commands::settings::MAX_PATH_LEN` so the
/// pre-canonicalize path length check is consistent across the
/// "save settings" path and the explicit add/remove paths.
const MAX_PATH_LEN: usize = 4 * 1024;
/// Maximum file-id count in a single batch sharing operation. Bounds
/// the IPC payload and the per-call DB transaction size.
const MAX_BATCH_IDS: usize = 10_000;
const MAX_BATCH_PATH_BYTES: usize = 8 * 1024 * 1024;
const MAX_SCAN_MISSING_RESULTS: usize = 10_000;
/// Upper bound on the number of paths accepted by `remove_missing_files` in a
/// single IPC call. Generous enough for any realistic library while bounding a
/// compromised-webview payload (and the per-call stat loop / index lock hold).
const MAX_REMOVE_MISSING_PATHS: usize = 200_000;

fn check_path_batch(paths: &[String], max_count: usize) -> Result<(), String> {
    if paths.len() > max_count {
        return Err(coded_ctx(
            "sharing_batch_too_large",
            format!("Too many paths in one batch (max {max_count})"),
            paths.len(),
        ));
    }
    let mut total = 0usize;
    for path in paths {
        if path.len() > MAX_PATH_LEN {
            return Err(coded_ctx(
                "sharing_file_path_too_long",
                format!("File path exceeds {MAX_PATH_LEN} bytes"),
                path.len(),
            ));
        }
        total = total.saturating_add(path.len());
        if total > MAX_BATCH_PATH_BYTES {
            return Err(coded_ctx(
                "sharing_batch_bytes_too_large",
                format!("Path batch exceeds {MAX_BATCH_PATH_BYTES} bytes"),
                total,
            ));
        }
    }
    Ok(())
}

/// Result of a missing-file filesystem probe. `paths` is capped; when
/// `truncated` is true, `total_missing` is still the full count so the UI can
/// warn instead of silently under-reporting.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissingScanResult {
    pub paths: Vec<String>,
    pub truncated: bool,
    pub total_missing: u32,
}

struct ScanGuard(Arc<AtomicUsize>);
impl Drop for ScanGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

static RELOAD_COUNTER: AtomicUsize = AtomicUsize::new(0);
static RELOAD_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
static MEDIA_METADATA_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// How many further pages one `reload_shared_files` trigger may queue for
/// itself while discovery keeps stopping at the per-folder file cap.
///
/// Discovery returns at most `MAX_DISCOVERED_FILES` files plus a resume cursor,
/// and nothing advances that cursor on a timer: a 500k-file library needed one
/// manual "Reload" per 100k files before pages 2..5 existed in `known.met` at
/// all, and nothing told the user that. The ceiling is what keeps the
/// self-rescheduling from degenerating into a permanent rescan loop — a folder
/// that stays truncated converges by at most this many extra pages per trigger
/// and then waits for the user, the FS watcher, or the next launch.
const MAX_CHAINED_SCAN_PAGES: u32 = 8;

/// Idle gap before a chained page starts. Deliberately long: this is
/// catch-up nobody is waiting on, and the page just finished has its own hash
/// pass to drain, so the app must be idle in between rather than scanning
/// back-to-back.
const CHAINED_SCAN_PAGE_DELAY: std::time::Duration = std::time::Duration::from_secs(60);

/// Slice length for waiting out `CHAINED_SCAN_PAGE_DELAY`. Shutdown raises
/// `bw_shutdown` and then joins the registered background scans with a 3s
/// grace, so a single long sleep would make every exit pay that grace in full.
const CHAINED_SCAN_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// Which kind of pass holds [`RELOAD_IN_FLIGHT`], so work turned away by it
/// can tell a full reload (which runs its own page chain) from a scoped
/// rescan (which does not, and will be done shortly).
static RELOAD_FLIGHT_KIND: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
const FLIGHT_NONE: u8 = 0;
const FLIGHT_FULL: u8 = 1;
const FLIGHT_SCOPED: u8 = 2;

/// Clears [`RELOAD_FLIGHT_KIND`] when the pass that set it ends.
struct ReloadFlightKind;

impl ReloadFlightKind {
    fn set(scoped: bool) -> Self {
        RELOAD_FLIGHT_KIND.store(
            if scoped { FLIGHT_SCOPED } else { FLIGHT_FULL },
            Ordering::Release,
        );
        Self
    }
}

impl Drop for ReloadFlightKind {
    fn drop(&mut self) {
        RELOAD_FLIGHT_KIND.store(FLIGHT_NONE, Ordering::Release);
    }
}

/// How long work turned away by a running pass waits before trying again.
const RELOAD_BUSY_RETRY: std::time::Duration = std::time::Duration::from_secs(5);
/// Ceiling on the backoff between those retries.
const RELOAD_BUSY_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(60);

async fn remove_cancel_flag_if_current(
    flags: &Arc<RwLock<std::collections::HashMap<String, Arc<AtomicBool>>>>,
    key: &str,
    ours: &Arc<AtomicBool>,
) {
    let mut flags = flags.write().await;
    if flags
        .get(key)
        .is_some_and(|current| Arc::ptr_eq(current, ours))
    {
        flags.remove(key);
    }
}

use crate::app_state::AppState;
use crate::commands::errors::{await_reply, bounded_send, coded, coded_ctx};
use crate::network::NetworkCommand;
use crate::search::index::LocalIndex;
use crate::sharing::indexer::FileIndexer;
use crate::storage::known_files::{priority_str_to_u8, priority_u8_to_str, KnownFileList};
use crate::types::*;
use tracing::{debug, info, warn};

async fn reconcile_shared_files(
    network_tx: &tokio::sync::mpsc::Sender<NetworkCommand>,
) -> Result<(), String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    bounded_send(network_tx, NetworkCommand::SharedFilesChangedAck { tx }).await?;
    await_reply(
        rx,
        "sharing_reconcile_failed",
        "Failed to reconcile shared files",
    )
    .await?
}

/// Ask the network task to withdraw our Ember DHT publications for files that
/// have stopped being offered.
///
/// Best effort by design: the share state is already committed by the time this
/// runs, so a saturated command channel must not fail the user's action. The
/// cost of it not landing is bounded — the records lapse on their own TTL and
/// the next reconcile darkens the badge.
async fn unpublish_ember_files(
    network_tx: &tokio::sync::mpsc::Sender<NetworkCommand>,
    file_hashes: Vec<String>,
) {
    if file_hashes.is_empty() {
        return;
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    if let Err(e) = bounded_send(
        network_tx,
        NetworkCommand::UnpublishEmberFiles { file_hashes, tx },
    )
    .await
    {
        warn!("Failed to withdraw Ember publications (best-effort): {e}");
        return;
    }
    // Awaited directly rather than through `await_reply`: that mints a coded
    // error for the frontend to translate, and this reply is only ever logged.
    // The ack is here to make the ordering explicit — the retraction lands
    // before the reconcile that follows it — not to be reported.
    match tokio::time::timeout(crate::commands::errors::CMD_REPLY_TIMEOUT, rx).await {
        Ok(Ok(count)) => debug!("Ember: withdrew publications for {count} file(s)"),
        Ok(Err(_)) => warn!("Ember publication withdrawal was dropped by the network task"),
        Err(_) => warn!("Ember publication withdrawal was not acknowledged in time"),
    }
}

/// The hashes among `removed` that no surviving index row still offers publicly.
///
/// Removing one copy of content shared from two folders is not a retraction:
/// the other row keeps the file listable, so its Ember records have to stay
/// exactly where they are.
///
/// The survivor has to be *publicly listable*, not merely present. Ember only
/// publishes `is_public_listable()` files, so a surviving row that is unshared
/// or friends-only is not offering the content and its hash should be withdrawn
/// like any other. Testing mere presence would have depended on share state
/// being uniform across every row of a hash — true today, because every
/// mutation in `LocalIndex` is content-wide, but enforced in a different module
/// with nothing tying the two together. This way the decision is answerable from
/// the rows themselves.
fn hashes_no_longer_offered(index: &LocalIndex, removed: &[String]) -> Vec<String> {
    if removed.is_empty() {
        return Vec::new();
    }
    let surviving: HashSet<String> = index
        .all_files()
        .iter()
        .filter(|file| !file.hash.is_empty() && file.is_public_listable())
        .map(|file| file.hash.to_ascii_lowercase())
        .collect();
    let mut seen = HashSet::new();
    removed
        .iter()
        .filter(|hash| !hash.is_empty())
        .map(|hash| hash.to_ascii_lowercase())
        .filter(|hash| !surviving.contains(hash) && seen.insert(hash.clone()))
        .collect()
}

async fn reconcile_shared_files_best_effort(
    network_tx: &tokio::sync::mpsc::Sender<NetworkCommand>,
) {
    if let Err(e) = reconcile_shared_files(network_tx).await {
        warn!("Failed to reconcile shared files (best-effort): {e}");
    }
}

pub(crate) fn fresh_part_hash_key(hash: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(hash).ok()?;
    if bytes.len() != 16 {
        return None;
    }
    let mut key = [0u8; 16];
    key.copy_from_slice(&bytes);
    Some(key)
}

pub(crate) fn fresh_part_hash_handoff(
    hash: &str,
    part_hashes: Vec<[u8; 16]>,
) -> Option<([u8; 16], Vec<[u8; 16]>)> {
    let file_hash = fresh_part_hash_key(hash)?;
    (!part_hashes.is_empty()).then_some((file_hash, part_hashes))
}

pub(crate) async fn cache_fresh_part_hash_handoff(
    fresh_part_hashes: &Arc<RwLock<std::collections::HashMap<[u8; 16], Vec<[u8; 16]>>>>,
    finalized: bool,
    handoff: Option<([u8; 16], Vec<[u8; 16]>)>,
) {
    if finalized {
        if let Some((file_hash, part_hashes)) = handoff {
            fresh_part_hashes
                .write()
                .await
                .insert(file_hash, part_hashes);
        }
    }
}

fn fresh_part_hashes_exclusively_under_roots(
    files: &[FileInfo],
    roots: &[String],
) -> HashSet<[u8; 16]> {
    let removed_hashes = files
        .iter()
        .filter(|file| {
            roots
                .iter()
                .any(|root| crate::security::path_within_dir(&file.path, root))
        })
        .filter_map(|file| fresh_part_hash_key(&file.hash))
        .collect::<HashSet<_>>();
    let retained_hashes = files
        .iter()
        .filter(|file| {
            !roots
                .iter()
                .any(|root| crate::security::path_within_dir(&file.path, root))
        })
        .filter_map(|file| fresh_part_hash_key(&file.hash))
        .collect::<HashSet<_>>();
    removed_hashes
        .difference(&retained_hashes)
        .copied()
        .collect()
}

fn unreferenced_fresh_part_hashes(
    files: &[FileInfo],
    candidates: &HashSet<[u8; 16]>,
) -> HashSet<[u8; 16]> {
    let referenced = files
        .iter()
        .filter_map(|file| fresh_part_hash_key(&file.hash))
        .collect::<HashSet<_>>();
    candidates.difference(&referenced).copied().collect()
}

fn fresh_part_hashes_removed_by_reload(
    before: &[FileInfo],
    after: &[FileInfo],
    folders: &[String],
) -> HashSet<[u8; 16]> {
    let candidates = before
        .iter()
        .filter(|file| file_in_shared_folders(&file.path, folders))
        .filter_map(|file| fresh_part_hash_key(&file.hash))
        .collect::<HashSet<_>>();
    unreferenced_fresh_part_hashes(after, &candidates)
}

async fn discard_fresh_part_hashes(
    fresh_part_hashes: &Arc<RwLock<std::collections::HashMap<[u8; 16], Vec<[u8; 16]>>>>,
    hashes: &HashSet<[u8; 16]>,
) {
    if hashes.is_empty() {
        return;
    }
    fresh_part_hashes
        .write()
        .await
        .retain(|hash, _| !hashes.contains(hash));
}

fn effective_shared_root_changes(
    removed_roots: &[String],
    added_roots: &[String],
    active_roots: &[String],
) -> (Vec<String>, Vec<String>) {
    let removed = removed_roots
        .iter()
        .filter(|root| !file_in_shared_folders(root, active_roots))
        .cloned()
        .collect();
    let added = added_roots
        .iter()
        .filter(|root| file_in_shared_folders(root, active_roots))
        .cloned()
        .collect();
    (removed, added)
}

/// Apply a `shared_folders` change made through the generic Settings command.
/// The explicit add/remove commands have equivalent logic, but Settings can
/// replace the entire root list in one save and must revoke removed roots
/// before any fallible network publication work.
pub(crate) async fn reconcile_shared_folder_roots(
    app: &tauri::AppHandle,
    state: &AppState,
    removed_roots: &[String],
    added_roots: &[String],
) {
    // This runs detached, queued behind `scan_coordination`, which a first-run
    // library hash pass can hold for hours. Shutdown aborts the scan holding
    // that lock, which releases this task — so without the gate a settings
    // change made hours earlier wakes up during exit and starts a fresh reload
    // behind the authoritative flush. The config it would reconcile is already
    // saved; the in-memory revocation below has no consumer left once the
    // upload listener is gone.
    if state.bw_shutdown.load(Ordering::Acquire) {
        debug!("Shared-folder root reconcile declined: shutdown in progress");
        return;
    }

    // The upload listener consults this list before serving an index row, so
    // update it before waiting for a scan. This is the immediate revocation
    // boundary even while a long-running discovery pass still owns
    // `scan_coordination`.
    let immediate_active_roots = state.config.read().await.settings.shared_folders.clone();
    *state.upload_shared_folders.write().await = immediate_active_roots;

    // Signal per-folder scans under removed roots BEFORE queueing on
    // `scan_coordination`, mirroring `remove_shared_folder`. Signaled only
    // after the lock, the flags could never shorten the wait for a running
    // scan of a root that is being removed. Broad startup/reload generations
    // are deliberately left running (see `scan_can_write_under`).
    if !removed_roots.is_empty() {
        let flags = state.hash_cancel_flags.read().await;
        for (scan_key, flag) in flags.iter() {
            if removed_roots
                .iter()
                .any(|root| scan_can_write_under(scan_key, root))
            {
                flag.store(true, Ordering::Relaxed);
            }
        }
    }

    // Scans persist their resume cursors while holding scan_coordination and
    // then settings_save_lock. Take those locks in that same order here, and
    // snapshot Settings only after acquiring scan_coordination so a later
    // settings save cannot leave the watcher/index on an obsolete root list.
    let scan_coordination_guard = state.scan_coordination.lock().await;
    let settings_save_guard = state.settings_save_lock.lock().await;
    let active_roots = state.config.read().await.settings.shared_folders.clone();
    let (effective_removed_roots, effective_added_roots) =
        effective_shared_root_changes(removed_roots, added_roots, &active_roots);
    *state.upload_shared_folders.write().await = active_roots.clone();

    let (removed_row_count, removed_hashes, unpublish) = if effective_removed_roots.is_empty() {
        (0, HashSet::new(), Vec::new())
    } else {
        {
            let flags = state.hash_cancel_flags.read().await;
            for (scan_key, flag) in flags.iter() {
                if effective_removed_roots
                    .iter()
                    .any(|root| scan_can_write_under(scan_key, root))
                {
                    flag.store(true, Ordering::Relaxed);
                }
            }
        }

        let mut index = state.local_index.write().await;
        let removed_files = index.remove_files_outside_folders(&active_roots);
        let candidates = removed_files
            .iter()
            .filter_map(|file| fresh_part_hash_key(&file.hash))
            .collect::<HashSet<_>>();
        let hashes = unreferenced_fresh_part_hashes(index.all_files(), &candidates);
        let dropped: Vec<String> = removed_files.iter().map(|file| file.hash.clone()).collect();
        let unpublish = hashes_no_longer_offered(&index, &dropped);
        (removed_files.len(), hashes, unpublish)
    };

    if let Some(watcher) = state.shared_folder_watcher.as_ref() {
        watcher.sync_paths(&active_roots);
    }
    {
        let config = state.config.read().await;
        sync_asset_protocol_scope(app, &config);
    }
    drop(settings_save_guard);
    drop(scan_coordination_guard);

    if removed_row_count > 0 {
        discard_fresh_part_hashes(&state.fresh_part_hashes, &removed_hashes).await;
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
    }

    // Do this after local revocation. A saturated or stopped network task may
    // defer publication changes, but must never keep a removed root visible
    // in the local upload/index state.
    unpublish_ember_files(&state.network_tx, unpublish).await;
    reconcile_shared_files_best_effort(&state.network_tx).await;

    if !effective_added_roots.is_empty() {
        // A full reload shares the established bounded discovery/hash path and
        // guarantees every newly-added root is picked up without duplicating
        // the per-folder scan machinery here.
        let state_ref = app.state::<AppState>();
        if let Err(e) = reload_shared_files(app.clone(), state_ref).await {
            warn!("Failed to schedule discovery for newly configured shared folders: {e}");
        }
    }

    let _ = app.emit(
        "shared-files-changed",
        serde_json::json!({
            "removed_folders": effective_removed_roots,
            "added_folders": effective_added_roots,
            "phase": "settings-roots-reconciled",
        }),
    );
}

async fn persist_shared_states(
    network_tx: &tokio::sync::mpsc::Sender<NetworkCommand>,
    hashes: &[String],
    shared: bool,
) -> Result<(), String> {
    if hashes.is_empty() {
        return Ok(());
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    let updates = hashes
        .iter()
        .filter(|hash| !hash.is_empty())
        .map(|hash| (hash.clone(), shared))
        .collect();
    bounded_send(network_tx, NetworkCommand::SetFilesShared { updates, tx }).await?;
    await_reply(
        rx,
        "sharing_persist_state_failed",
        "Failed to persist file sharing state",
    )
    .await??;
    Ok(())
}

async fn persist_friends_only_states(
    network_tx: &tokio::sync::mpsc::Sender<NetworkCommand>,
    hashes: &[String],
    friends_only: bool,
) -> Result<(), String> {
    if hashes.is_empty() {
        return Ok(());
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    let updates = hashes
        .iter()
        .filter(|hash| !hash.is_empty())
        .map(|hash| (hash.clone(), friends_only))
        .collect();
    bounded_send(
        network_tx,
        NetworkCommand::SetFilesFriendsOnly { updates, tx },
    )
    .await?;
    await_reply(
        rx,
        "sharing_persist_scope_failed",
        "Failed to persist file share scope",
    )
    .await??;
    Ok(())
}

async fn persist_upload_priorities(
    network_tx: &tokio::sync::mpsc::Sender<NetworkCommand>,
    hashes: &[String],
    priority: u8,
) -> Result<(), String> {
    let file_hashes = hashes
        .iter()
        .filter(|hash| !hash.is_empty())
        .cloned()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if file_hashes.is_empty() {
        return Ok(());
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    bounded_send(
        network_tx,
        NetworkCommand::SetUploadPriorities {
            file_hashes,
            priority,
            tx,
        },
    )
    .await?;
    await_reply(
        rx,
        "sharing_persist_priority_failed",
        "Failed to persist upload priority",
    )
    .await?
}

async fn persist_priority_snapshot(
    network_tx: &tokio::sync::mpsc::Sender<NetworkCommand>,
    files: &[FileInfo],
) -> Result<(), String> {
    let mut by_priority: std::collections::HashMap<u8, HashSet<String>> =
        std::collections::HashMap::new();
    for file in files {
        if !file.hash.is_empty() {
            by_priority
                .entry(priority_str_to_u8(&file.priority))
                .or_default()
                .insert(file.hash.clone());
        }
    }
    for (priority, hashes) in by_priority {
        persist_upload_priorities(
            network_tx,
            &hashes.into_iter().collect::<Vec<_>>(),
            priority,
        )
        .await?;
    }
    Ok(())
}

fn paths_equal_ignore_case(a: &str, b: &str) -> bool {
    let normalize = |path: &str| {
        crate::search::index::normalize_path_key(path)
            .trim_end_matches(['/', '\\'])
            .to_string()
    };
    normalize(a) == normalize(b)
}

/// Whether a registered scan generation can add files at or below
/// `removed_folder`.
///
/// Per-folder scan keys are their canonical roots. Startup/reload generations
/// are deliberately not cancelled here: their snapshots may predate a newly
/// added folder and therefore be unrelated. The shared scan-coordination guard
/// below either lets an already-running broad scan finish before removal, or
/// makes a queued broad scan start afterward; startup/reload both re-filter
/// against current config before writes, so neither ordering can resurrect the
/// removed folder.
fn scan_can_write_under(scan_key: &str, removed_folder: &str) -> bool {
    if scan_key.starts_with("__") {
        return false;
    }
    crate::security::path_within_dir(scan_key, removed_folder)
        || crate::security::path_within_dir(removed_folder, scan_key)
}

/// The stored shared folder a removal request names, spelled as stored.
/// Matched on the canonical form and on the spelling the request carried,
/// since an offline root cannot canonicalize.
fn stored_shared_folder(
    shared_folders: &[String],
    canonical: Option<&str>,
    requested: &str,
) -> Option<String> {
    shared_folders
        .iter()
        .find(|stored| {
            canonical.is_some_and(|canonical| paths_equal_ignore_case(stored, canonical))
                || paths_equal_ignore_case(stored, requested)
        })
        .cloned()
}

/// Whether an unshare request names a stored shared folder or something inside
/// one. Only then may the drive-aware prefix operations act on it.
fn unshare_target_is_shared(shared_folders: &[String], requested: &str) -> bool {
    shared_folders
        .iter()
        .any(|stored| crate::security::path_within_dir(requested, stored))
}

pub(crate) async fn refresh_file_cache(
    index: &Arc<RwLock<LocalIndex>>,
    cache: &Arc<RwLock<Vec<FileInfo>>>,
) {
    let (snap_raw, previous_flags) =
        tokio::join!(async { index.read().await.all_files().to_vec() }, async {
            let cached = cache.read().await;
            cached
                .iter()
                .map(|file| {
                    (
                        crate::search::index::normalize_path_key(&file.path),
                        (file.shared_kad, file.shared_ed2k, file.shared_ember),
                    )
                })
                .collect::<std::collections::HashMap<_, _>>()
        },);
    let mut snap = snap_raw;
    for file in &mut snap {
        let key = crate::search::index::normalize_path_key(&file.path);
        if let Some((shared_kad, shared_ed2k, shared_ember)) = previous_flags.get(&key) {
            // `is_public_listable`, not `shared` alone — the same predicate
            // `apply_publish_badges` uses on the network side. Gating on
            // `shared` left a stale badge lit after a file was restricted to
            // friends, right up until the next network-side refresh, which is
            // the one case where the badge is saying something untrue about
            // who can see the file.
            let listable = file.is_public_listable() && !file.hash.is_empty();
            file.shared_kad = listable && *shared_kad;
            file.shared_ed2k = listable && *shared_ed2k;
            file.shared_ember = listable && *shared_ember;
        }
    }
    *cache.write().await = snap;
}

async fn rollback_index_mutation(state: &AppState, snapshot: Vec<FileInfo>) {
    {
        let mut index = state.local_index.write().await;
        index.restore_snapshot(snapshot);
    }
    refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
}

/// Put back the rows a share mutation flipped, and only those: a scan may
/// have hashed rows, or another command changed them, since it was made.
async fn revert_share_mutation(
    state: &AppState,
    mutation: &crate::search::index::ShareMutation,
    shared: bool,
) {
    state
        .local_index
        .write()
        .await
        .revert_share_mutation(mutation, shared);
    refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
}

async fn persist_share_mutation(
    state: &AppState,
    mutation: &crate::search::index::ShareMutation,
    shared: bool,
) -> Result<(), String> {
    if let Err(e) = persist_shared_states(&state.network_tx, &mutation.hashes, shared).await {
        revert_share_mutation(state, mutation, shared).await;
        return Err(e);
    }
    let pending_updates = mutation
        .pending_paths
        .iter()
        .cloned()
        .map(|path| (path, shared))
        .collect::<Vec<_>>();
    if let Err(e) =
        persist_pending_intents(state, &pending_updates, &[], &mutation.hashed_paths, &[]).await
    {
        // The known.met half already committed. Compensate it before rolling
        // back the optimistic index so a failed config write cannot leave the
        // next restart with the opposite share state.
        let persistence_rollback =
            persist_shared_states(&state.network_tx, &mutation.hashes, !shared).await;
        revert_share_mutation(state, mutation, shared).await;
        return match persistence_rollback {
            Ok(()) => Err(e),
            Err(rollback_error) => Err(coded_ctx(
                "sharing_state_rollback_failed",
                "Share-state save and rollback both failed",
                format!("{e}; rollback: {rollback_error}"),
            )),
        };
    }
    // Past every rollback path, so a retraction is never applied to a file that
    // ends up still shared. `mutation.hashes` is already the set of hashes whose
    // share state actually flipped, and unsharing by path flips every copy of
    // that content, so nothing else in the index can still be offering them.
    if !shared {
        unpublish_ember_files(&state.network_tx, mutation.hashes.clone()).await;
    }
    reconcile_shared_files_best_effort(&state.network_tx).await;
    Ok(())
}

/// known.met is up to 256 MiB, so the read and parse stay off the async
/// runtime.
async fn load_known_files() -> Result<KnownFileList, String> {
    let data_dir = crate::storage::paths::resolve_data_dir();
    tokio::task::spawn_blocking(move || {
        let known = KnownFileList::load(&data_dir.join("known.met"));
        // Callers go straight on to resolve share state per file; wait out a
        // startup share-intent migration here rather than on a runtime
        // worker.
        crate::storage::share_intent::wait_until_initialized();
        known
    })
    .await
    .map_err(|e| {
        coded_ctx(
            "sharing_known_files_load_error",
            "Could not read the known-file catalog",
            e,
        )
    })
}

pub(crate) fn shared_access_dirs(config: &crate::storage::config::AppConfig) -> Vec<String> {
    let mut allowed_dirs = config.settings.shared_folders.clone();
    let download_dir = std::path::PathBuf::from(&config.settings.download_folder)
        .join("Downloads")
        .to_string_lossy()
        .to_string();
    allowed_dirs.push(download_dir);
    allowed_dirs.push(config.settings.download_folder.clone());
    allowed_dirs
}

/// Legacy call site retained while media moves to the dynamic `ember-media`
/// protocol. The Tauri asset scope is intentionally not granted any folders:
/// `allow_directory` cannot revoke a previous root without making a later
/// re-add permanently inaccessible in this process.
pub(crate) fn sync_asset_protocol_scope(
    _app: &tauri::AppHandle,
    _config: &crate::storage::config::AppConfig,
) {
}

fn percent_decode_path(value: &str) -> Option<String> {
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let high = *bytes.get(i + 1)?;
            let low = *bytes.get(i + 2)?;
            let nibble = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            out.push((nibble(high)? << 4) | nibble(low)?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn media_content_type(path: &std::path::Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" | "opus" => "audio/ogg",
        "aac" => "audio/aac",
        "flac" => "audio/flac",
        "m4a" => "audio/mp4",
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        _ => "application/octet-stream",
    }
}

const MAX_MEDIA_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

fn parse_single_range(range: Option<&str>, length: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(range) = range else {
        return Ok(None);
    };
    let range = range.strip_prefix("bytes=").ok_or(())?;
    let (start, end) = range.split_once('-').ok_or(())?;
    if start.contains(',') || end.contains(',') || length == 0 {
        return Err(());
    }
    if start.is_empty() {
        let suffix = end.parse::<u64>().map_err(|_| ())?.min(length);
        if suffix == 0 {
            return Err(());
        }
        return Ok(Some((
            length.saturating_sub(suffix),
            length.saturating_sub(1),
        )));
    }
    let start = start.parse::<u64>().map_err(|_| ())?;
    if start >= length {
        return Err(());
    }
    let end = if end.is_empty() {
        length - 1
    } else {
        end.parse::<u64>().map_err(|_| ())?.min(length - 1)
    };
    (start <= end).then_some((start, end)).ok_or(()).map(Some)
}

/// Serve in-app media with a containment decision made at request time, not
/// only when the UI originally created the URL. This makes a removed share root
/// immediately inaccessible even if a stale WebView URL is retained.
pub(crate) async fn serve_media_request(
    app: tauri::AppHandle,
    encoded_path: String,
    range: Option<String>,
) -> tauri::http::Response<Vec<u8>> {
    let Some(file_path) = percent_decode_path(&encoded_path) else {
        return tauri::http::Response::builder()
            .status(tauri::http::StatusCode::BAD_REQUEST)
            .body(b"invalid media path".to_vec())
            .unwrap_or_default();
    };
    let (allowed_dirs, indexed_paths) = {
        let state = app.state::<AppState>();
        let config = state.config.read().await;
        let allowed_dirs = shared_access_dirs(&config);
        drop(config);
        let index = state.local_index.read().await;
        let indexed_paths = index
            .all_files()
            .iter()
            .map(|file| {
                (
                    crate::search::index::normalize_path_key(&file.path),
                    file.name.clone(),
                )
            })
            .collect::<std::collections::HashMap<_, _>>();
        (allowed_dirs, indexed_paths)
    };
    let result = tokio::task::spawn_blocking(move || {
        // Open through the approved parent handle so a final-component symlink
        // swap between containment check and read cannot redirect the bytes.
        let (canonical, mut file) = crate::security::filesystem::open_existing_approved(
            std::path::Path::new(&file_path),
            &allowed_dirs,
            false,
        )?;
        let indexed_name = indexed_paths.get(&crate::search::index::normalize_path_key(
            &canonical.to_string_lossy(),
        ));
        if indexed_name.is_none()
            || !crate::security::filesystem::passive_type_agrees(
                indexed_name.map(String::as_str).unwrap_or_default(),
                &canonical,
            )
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "media path is not currently authorized",
            ));
        }
        let length = file.metadata()?.len();
        let selected_range = parse_single_range(range.as_deref(), length)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid range"))?;
        if length == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "empty media file",
            ));
        }
        let (start, requested_end) = selected_range.unwrap_or((0, length - 1));
        // Tauri URI responders take an owned byte buffer, not an async stream.
        // Cap each response so `bytes=0-` and range-less requests cannot turn a
        // multi-gigabyte video into one allocation. Media engines issue follow-up
        // byte ranges after a valid 206 response.
        let end =
            requested_end.min(start.saturating_add(MAX_MEDIA_RESPONSE_BYTES.saturating_sub(1)));
        let partial = start != 0 || end != length - 1;
        let bytes_len = end.saturating_sub(start).saturating_add(1);
        let mut body = vec![0; bytes_len as usize];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut body)?;
        Ok::<_, std::io::Error>((canonical, length, start, end, partial, body))
    })
    .await;
    let (canonical, length, start, end, partial, body) = match result {
        Ok(Ok(response)) => response,
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::InvalidInput => {
            return tauri::http::Response::builder()
                .status(tauri::http::StatusCode::RANGE_NOT_SATISFIABLE)
                .body(b"invalid media range".to_vec())
                .unwrap_or_default();
        }
        _ => {
            return tauri::http::Response::builder()
                .status(tauri::http::StatusCode::NOT_FOUND)
                .body(b"media is unavailable".to_vec())
                .unwrap_or_default();
        }
    };
    let mut response = tauri::http::Response::builder()
        .status(if partial {
            tauri::http::StatusCode::PARTIAL_CONTENT
        } else {
            tauri::http::StatusCode::OK
        })
        .header(
            tauri::http::header::CONTENT_TYPE,
            media_content_type(&canonical),
        )
        .header(tauri::http::header::ACCEPT_RANGES, "bytes")
        .header(tauri::http::header::CONTENT_LENGTH, body.len().to_string());
    if partial {
        response = response.header(
            tauri::http::header::CONTENT_RANGE,
            format!("bytes {start}-{end}/{length}"),
        );
    }
    response.body(body).unwrap_or_default()
}

/// `shared_folders` must be the stored shared list (or a subset of it, or
/// paths under it): a whole shared drive contains its files, which
/// `path_matches_dir` would deny.
pub(crate) fn file_in_shared_folders(file_path: &str, shared_folders: &[String]) -> bool {
    shared_folders
        .iter()
        .any(|folder| crate::security::path_within_dir(file_path, folder))
}

async fn delete_file_with_retry(
    path: &std::path::Path,
    allowed_roots: &[String],
    expected: &crate::security::filesystem::ObjectIdentity,
    max_attempts: u32,
    delay_ms: u64,
) -> Result<(), String> {
    let mut last_error = None;
    for attempt in 1..=max_attempts {
        let delete_path = path.to_path_buf();
        let allowed = allowed_roots.to_vec();
        let expected = expected.clone();
        match tokio::task::spawn_blocking(move || {
            crate::security::filesystem::remove_approved_file_if_identity(
                &delete_path,
                &allowed,
                &expected,
            )
        })
        .await
        {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(e)) => {
                last_error = Some(e);
                if attempt < max_attempts {
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                }
            }
            Err(e) => {
                return Err(coded_ctx(
                    "sharing_delete_failed",
                    format!("Delete task failed for {}", path.display()),
                    e,
                ));
            }
        }
    }
    Err(coded_ctx(
        "sharing_delete_failed",
        format!("Failed to delete {}", path.display()),
        last_error
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string()),
    ))
}

/// What a discovery pass found, split by how badly the work is needed.
///
/// The split is the whole point: a file with no usable `known.met` record
/// cannot be served, searched or published until it is hashed, so the scan has
/// to wait for it. A file that is merely missing an AICH root or an Ember
/// digest already has its ed2k id and its part hashes and is servable right
/// now — those two buy a downloader cheaper corruption recovery and an extra
/// end-to-end check respectively, and nothing else. Making the scan wait for
/// either conflated "the Library is incomplete" with "the Library could be
/// slightly better", and on a large library it is the second list that takes
/// days.
#[derive(Default)]
struct ResolvedWork {
    /// Cannot be served until hashed. The scan blocks on these.
    needs_hashing: Vec<FileInfo>,
    /// Servable already; wants an AICH root, an Ember digest, or both. Topped
    /// up in the background, at whatever pace the drives can spare.
    needs_top_up: Vec<FileInfo>,
}

fn resolve_from_known(files: &mut [FileInfo], known: &KnownFileList) -> ResolvedWork {
    let mut work = ResolvedWork::default();
    let needs_hashing = &mut work.needs_hashing;
    for file in files.iter_mut() {
        if let Some(record) = known.find_by_path_and_meta(&file.path, file.size, file.modified_at) {
            let hash = hex::encode(record.file_hash);
            file.id = hash.clone();
            file.hash = hash;
            file.aich_hash = record.aich_hash.clone();
            file.ember_file_hash = record.ember_file_hash.clone();
            // Restore the per-file priority and shared/unshared choice from
            // known.met — without this, every rediscovery (folder add,
            // reload, or cold startup) silently reset a custom priority back
            // to "normal" and re-shared a file the user had explicitly
            // unshared.
            file.priority = priority_u8_to_str(record.upload_priority).to_string();
            file.shared =
                crate::storage::share_intent::effective_shared(&record.file_hash, record.is_shared);
            // Restore the friends-only restriction from the same record. The
            // in-memory carry-over in `preserve_runtime_state` only helps when a
            // live row already exists; a cold rediscovery has nothing to carry
            // from, and leaving this false would publish a restricted file to
            // the open network until the next restart put the flag back.
            file.friends_only = record.friends_only;
            // The Library's Top Uploads panel and all-time activity columns
            // are populated from these persisted known.met counters. Restore
            // them with the hash instead of showing an empty Library until the
            // network cache refresh happens to run.
            file.alltime_requests = record.all_time_requested;
            file.alltime_accepted = record.all_time_accepted;
            file.alltime_transferred = record.all_time_transferred;
            // Restore the last-known Peers count so the UI doesn't flash
            // back to 0 until the next 60s source-count sync completes.
            file.complete_sources = record.complete_sources;
            // Both one-time repairs go to the same background pass. Kept in
            // step with the startup path in `lib.rs`.
            //
            // The scan's dividing line is whether a file can be served at all,
            // and neither of these crosses it. A row matched here has its ed2k
            // id and its part hashes, so it stays shared, searchable,
            // publishable and uploadable throughout — which is why it keeps its
            // content-hash id and enters the index as an ordinary entry rather
            // than a placeholder.
            //
            // A missing AICH root used to hold the scan up, on the grounds that
            // it is eD2k protocol data rather than an Ember extra. That is true
            // of its value and not of its urgency: without it a corrupt chunk
            // costs a downloader a re-fetch of the whole 9500 KiB part instead
            // of one 180 KiB block, which is what every client did before eMule
            // 0.44 and only costs anything once corruption actually happens.
            // The wait, meanwhile, was certain — a library whose previous scan
            // never finished has no roots for most of it, so blocking on them
            // re-read the entire share in the foreground at the
            // three-algorithm rate, while the digest pass sat behind
            // `scanning_count` waiting its turn to read every byte a second
            // time. Merged, it is one read per file for both.
            //
            // A missing Ember digest is an Ember-only extra that buys the
            // downloader a whole-file check. Queueing these into the scan is
            // what made a Reload re-read every byte of the library — days, on a
            // large share spread over external drives, against the minutes the
            // same reload takes in aMule, which has no digest to migrate and so
            // never re-reads at all.
            if wants_hash_top_up(file) {
                work.needs_top_up.push(file.clone());
            }
        } else {
            needs_hashing.push(file.clone());
        }
    }
    work
}

/// Share of the wall clock the background digest pass is allowed to keep the
/// drives busy. The rest is spent asleep, so a library that is also being
/// uploaded from, downloaded to or simply browsed still gets its share of the
/// disk. Eight tenths is high enough that the backfill finishes in a comparable
/// time to a foreground pass and low enough that nothing else starves.
const BACKFILL_DUTY_CYCLE: f64 = 0.8;

/// Longest single pause between files, so one enormous file cannot put the
/// pass to sleep for minutes.
const BACKFILL_MAX_PAUSE: std::time::Duration = std::time::Duration::from_secs(2);

/// State of the one background top-up pass, which is global because the work
/// is: it is keyed on the library, not on whichever scan happened to notice.
static HASH_TOP_UP: std::sync::OnceLock<tokio::sync::Mutex<HashTopUp>> = std::sync::OnceLock::new();

#[derive(Default)]
struct HashTopUp {
    running: bool,
    cancel: Option<Arc<AtomicBool>>,
    /// Paths already queued or done this session, so overlapping scans of the
    /// same folders do not hash the same file twice.
    seen: HashSet<String>,
    /// Content hashes this pass already has a file queued for.
    ///
    /// Both repairs are derived from the bytes, so one answer covers every copy
    /// of the same content — `set_top_up_digests_by_hash` stamps onto every
    /// index row sharing the hash — and reading the other copies is a whole
    /// file read each for an
    /// answer already in hand, on a pass written to be gentle with the drives.
    ///
    /// Deliberately not folded into `seen`: a skipped copy's *path* stays
    /// unseen, so if the copy that was queued fails, the next scan offers the
    /// others again. And if it succeeded, their index rows now carry both, and
    /// `queue_hash_top_up`'s `wants_hash_top_up` check drops them without a
    /// read. Cleared when the pass ends, alongside `running`.
    queued_hashes: HashSet<String>,
    queued: Vec<TopUpRow>,
    done: usize,
    total: usize,
}

fn hash_top_up() -> &'static tokio::sync::Mutex<HashTopUp> {
    HASH_TOP_UP.get_or_init(Default::default)
}

/// Hand a scan's one-time repairs — missing AICH roots, missing Ember
/// digests — to the background pass.
///
/// Additive: a second scan while one is running appends to the same queue
/// rather than starting a competing pass, which is what keeps the per-device
/// read limits meaningful.
pub(crate) async fn queue_hash_top_up(app: tauri::AppHandle, files: &[FileInfo]) {
    if files.is_empty() {
        return;
    }
    // Stop latches `hashing_paused` before it flips the cancel flags, so a
    // scan already past its own cancel check still reaches here. Without this
    // that scan spawned a fresh worker with a fresh cancel flag and the drives
    // started up again moments after the user asked them to stop. The files
    // are not lost: they are offered again by the next scan or resume.
    if app
        .state::<AppState>()
        .hashing_paused
        .load(Ordering::Relaxed)
    {
        return;
    }
    let mut state = hash_top_up().lock().await;
    for file in files {
        // A row with no ed2k hash has never been hashed and belongs to the
        // scan, not here; a row with both top-ups already present would be a
        // whole-file read that computes nothing. Narrowed here rather than by
        // the caller, so nothing upstream has to clone a whole row to ask.
        let Some(row) = TopUpRow::from_file(file) else {
            continue;
        };
        let path_key = crate::search::index::normalize_path_key(&row.path);
        // Path first, and without recording anything: this row is already
        // queued or done, so it must not consume the content reservation
        // below on behalf of a copy it is not.
        if state.seen.contains(&path_key) {
            continue;
        }
        // One copy per content hash. A skipped copy's path stays out of
        // `seen`, so a later scan can offer it if the copy we kept never
        // produces a digest. See `queued_hashes`.
        if !state.queued_hashes.insert(row.hash.to_ascii_lowercase()) {
            continue;
        }
        state.seen.insert(path_key);
        state.total += 1;
        state.queued.push(row);
    }
    if state.running || state.queued.is_empty() {
        return;
    }
    let cancel = Arc::new(AtomicBool::new(false));
    state.running = true;
    state.cancel = Some(cancel.clone());
    drop(state);
    // Registered like any other background scan so shutdown joins it. It holds
    // `local_index.write()` and updates `known_files`, which is precisely the
    // race `await_background_scans` was added to close; detaching it here left
    // it outside that fence.
    let app_for_registry = app.clone();
    let handle = tokio::spawn(async move { run_hash_top_up(app, cancel).await });
    app_for_registry
        .state::<AppState>()
        .register_background_scan(handle)
        .await;
}

/// Stop the background pass. Nothing is lost: a file whose root or digest was
/// never computed is simply still missing one, and the next launch finds it
/// again.
/// A folder scan ended before it could index anything. Logged only, this left
/// the Library showing a scan that never finished, with no word of why.
pub(crate) fn report_scan_failure(app: &tauri::AppHandle, folder: Option<&str>) {
    let _ = app.emit(
        "file-hash-progress",
        serde_json::json!({ "done": true, "current": 0, "total": 0, "file_name": "" }),
    );
    let _ = app.emit(
        "shared-folder-scan-failed",
        serde_json::json!({ "folder": folder }),
    );
}

/// Whether the background digest pass is reading files right now. A lock held
/// by someone else counts as running: it is only held to start, stop or feed
/// the pass, so guessing "idle" is the direction that interrupts it.
pub(crate) fn hash_top_up_running() -> bool {
    match HASH_TOP_UP.get() {
        None => false,
        Some(state) => state.try_lock().map_or(true, |state| state.running),
    }
}

pub(crate) async fn cancel_hash_top_up() {
    let state = hash_top_up().lock().await;
    if let Some(cancel) = state.cancel.as_ref() {
        cancel.store(true, Ordering::Relaxed);
    }
}

/// `(done, total)` for the Library's status line, or `None` when idle.
pub(crate) async fn hash_top_up_progress() -> Option<(usize, usize)> {
    let state = hash_top_up().lock().await;
    state.running.then_some((state.done, state.total))
}

/// Fill in missing AICH roots and Ember digests, quietly, for as long as it
/// takes.
///
/// Both in one pass, and one read per file: a row can be missing either or
/// both, and asking for them separately would walk the same bytes twice. That
/// is not hypothetical — while the AICH half ran in the foreground, this pass
/// waited on `scanning_count` and then re-read every file the scan had just
/// finished reading.
///
/// Deliberately unlike the scan loop it replaces. Nothing here is a
/// placeholder: every row is already in the index under its real content hash
/// and is served throughout, so there is no pending id to finalize, nothing to
/// abandon on failure, and cancelling costs only the work not yet done. A file
/// that fails, or that changed underneath us, is just left for next time.
async fn run_hash_top_up(app: tauri::AppHandle, cancel: Arc<AtomicBool>) {
    let state = app.state::<AppState>();
    let local_index = state.local_index.clone();
    let file_cache = state.cached_shared_files.clone();
    let network_tx = state.network_tx.clone();
    let scanning = state.scanning_count.clone();
    let mut updated_since_reconcile = 0usize;
    let mut last_checkpoint = std::time::Instant::now();

    // Assigned by the single `break` below, which is the loop's only exit.
    let finished: (usize, usize);
    loop {
        // Taking the next batch and deciding to stop happen under one lock,
        // because `queue_hash_top_up` declines to start a second worker
        // while `running` is set. Clearing that flag outside this critical
        // section would let a scan queue work into the gap, see a worker that
        // is still nominally running, and have its files sit there until some
        // later scan happened to queue more.
        let batch = {
            let mut backfill = hash_top_up().lock().await;
            let batch = std::mem::take(&mut backfill.queued);
            if batch.is_empty() || cancel.load(Ordering::Relaxed) {
                // Cancelled with work still queued — put it back rather than
                // dropping it. `seen` would otherwise keep the next scan from
                // re-offering the same files, so discarding here would lose
                // them until a restart. Clearing `running` under this same lock
                // means the next `queue_hash_top_up` starts a fresh worker,
                // with a fresh cancel flag, that picks this up where it stopped.
                backfill.queued = batch;
                backfill.running = false;
                backfill.cancel = None;
                finished = (backfill.done, backfill.total);
                // The tally belongs to the queue, not to the worker. Reset it
                // only when the queue really is empty, so a pass that resumes
                // after a cancel continues counting rather than restarting at
                // zero against a total that no longer includes what is left.
                if backfill.queued.is_empty() {
                    backfill.done = 0;
                    backfill.total = 0;
                    // Released with the tally, and for the same reason: the
                    // reservations belong to the queue. Held while work
                    // remains so a scan arriving mid-pass cannot queue a
                    // second copy of something still waiting, and dropped once
                    // there is nothing left for them to protect — which is
                    // what lets a later scan retry the copies passed over if
                    // the one that was kept failed.
                    backfill.queued_hashes.clear();
                }
                break;
            }
            batch
        };

        let mut pipeline = HashLookahead::new(&batch, cancel.clone());
        pipeline.log_plan("Topping up AICH roots and Ember digests for", batch.len());
        loop {
            // Stand aside for any real scan. A scan is hashing files the
            // Library cannot show until it finishes; this is topping up an
            // optional digest on files that already work. Running both puts two
            // readers on the same drives and makes the one the user is watching
            // slower. Checked before `next_started`, which is what starts the
            // next read — the one already in flight finishes, and nothing new
            // begins until the scan is done.
            while scanning.load(Ordering::Relaxed) > 0 && !cancel.load(Ordering::Relaxed) {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            let started = match pipeline.next_started() {
                NextHash::Ready(started) => started,
                // A drive busy with someone else's read. Wait — dropping out
                // here would abandon the rest of the batch, and `seen` would
                // stop a later scan from offering those files again.
                NextHash::Busy => {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    continue;
                }
                NextHash::Done => break,
            };
            if cancel.load(Ordering::Relaxed) {
                pipeline.drain_started(started);
                break;
            }
            let file = &batch[started.index];
            let began = std::time::Instant::now();
            let mut task = started.task;
            // An external drive that stops answering must not wedge the pass
            // for the rest of the session. Same stall window the scan uses, and
            // the same handling: the claim stays held by a detached drain until
            // the read really does return, so nothing else tries the file in
            // the meantime.
            let Ok(outcome) =
                await_hash(&mut task, &started.progress, &file.path, started.claim).await
            else {
                warn!("Hash top-up stalled on {}", file.name);
                pipeline.drain_started(StartedHash {
                    index: started.index,
                    device: started.device,
                    claim: started.claim,
                    progress: started.progress,
                    task,
                });
                // Counted as dealt with. It is not retried this pass, and a
                // progress line that can never reach its total reads as stuck.
                hash_top_up().lock().await.done += 1;
                continue;
            };
            release_in_flight_hash(&file.path, started.claim);

            match outcome {
                Ok(Ok((
                    _,
                    aich_hash,
                    part_hashes,
                    ember_file_hash,
                    hashed_size,
                    hashed_modified_at,
                ))) => {
                    // The file must still be the one known.met described. A
                    // digest-only pass carries the stored ed2k forward rather
                    // than recomputing it, so size and mtime are the only
                    // evidence that the bytes we just read are the bytes that
                    // hash belongs to. Anything else is a file edited since
                    // discovery, and attaching these to its old hash would
                    // record repair data that verifies nothing. The AICH route
                    // has already made the stronger check — it recomputes the
                    // ed2k and fails the file outright on a mismatch — but this
                    // still has to run for the digest-only route, which never
                    // recomputes the MD4.
                    if hashed_size != file.size || hashed_modified_at != file.modified_at {
                        debug!("Skipping top-up for {}: changed since discovery", file.name);
                    } else if aich_hash.is_empty()
                        && ember_file_hash.is_empty()
                        && part_hashes.is_empty()
                    {
                        debug!("Top-up pass produced nothing for {}", file.name);
                    } else {
                        // The AICH route recomputes the MD4 and so the hashset,
                        // which a record whose stored list was empty or dropped
                        // for the wrong length has no other way to get back.
                        // Handed over like the scan's, and drained by the same
                        // reconcile.
                        let handoff = fresh_part_hash_handoff(&file.hash, part_hashes);
                        // One walk of the index, not one per digest: this runs
                        // per repaired file under the write lock that search and
                        // the Library UI contend on. Empty values are ignored
                        // rather than cleared, so whichever repair was not asked
                        // for on this file leaves the stored value alone.
                        let (changed, indexed) = {
                            let mut index = local_index.write().await;
                            let changed = index.set_top_up_digests_by_hash(
                                &file.hash,
                                &ember_file_hash,
                                &aich_hash,
                            );
                            (changed, changed || index.get_by_hash(&file.hash).is_some())
                        };
                        if changed || (indexed && handoff.is_some()) {
                            updated_since_reconcile += 1;
                        }
                        cache_fresh_part_hash_handoff(&state.fresh_part_hashes, indexed, handoff)
                            .await;
                    }
                }
                Ok(Err(e)) => debug!("Hash top-up failed for {}: {e}", file.name),
                Err(e) => warn!("Hash top-up task panicked for {}: {e}", file.name),
            }

            {
                let mut backfill = hash_top_up().lock().await;
                backfill.done += 1;
            }

            // Every so often, push what we have into known.met, so a pass that
            // runs for hours and is then interrupted keeps its progress instead
            // of starting over on the next launch.
            //
            // Bounded by elapsed time as well as by count. On a count alone, a
            // library of large files on slow external drives can spend a long
            // while short of 256 repairs, and all of it is lost on exit: the
            // shutdown path cancels this pass and then gives background scans a
            // 3 s grace, while the final flush below can need up to 2 s to send
            // plus a 15 s ack. Whole-file reads are far too expensive to redo,
            // so cap the exposure at a wall-clock window rather than at a file
            // count that says nothing about how long they took.
            const CHECKPOINT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
            if updated_since_reconcile > 0
                && (updated_since_reconcile >= 256
                    || last_checkpoint.elapsed() >= CHECKPOINT_INTERVAL)
            {
                updated_since_reconcile = 0;
                last_checkpoint = std::time::Instant::now();
                refresh_file_cache(&local_index, &file_cache).await;
                reconcile_shared_files_best_effort(&network_tx).await;
            }

            // Give the drives back their share, proportionally, so a big file
            // yields more than a small one and the ratio holds whatever the
            // library looks like.
            //
            // `began` measures the wait for this row rather than the read
            // itself: with a look-ahead running, the read started earlier and
            // may already have finished. That biases the pause downward, never
            // up — the pass stays at least as courteous as this asks for, and
            // at worst runs closer to full speed, which is the direction to err
            // in for work the user is waiting to see the end of.
            let pause = began
                .elapsed()
                .mul_f64((1.0 - BACKFILL_DUTY_CYCLE) / BACKFILL_DUTY_CYCLE)
                .min(BACKFILL_MAX_PAUSE);
            if !pause.is_zero() {
                tokio::time::sleep(pause).await;
            }
        }
        // Breaking out on cancel leaves the look-ahead window full of claimed,
        // still-running reads. Same reason the scan loops do this: dropping
        // them strands each claim until its 15-minute lease expires, and
        // nothing may hash those paths in the meantime.
        let abandoned = pipeline.abandon();
        // Everything the window never reached goes back on the queue. The
        // top-of-loop cancel branch can only return `batch` — which
        // `mem::take` emptied — so without this the rest of the batch was
        // dropped here, and `seen` then kept every one of those paths from
        // being re-offered for the rest of the session. That is the loss the
        // branch's own comment says must not happen; it just could not see
        // these files, because the look-ahead owns them.
        let unstarted = pipeline.unstarted();
        // Files the look-ahead could not claim are never coming back this
        // pass, so count them finished or `done` can never reach `total` — the
        // same "a progress line that can never reach its total reads as stuck"
        // the timeout branch above guards against.
        let skipped = pipeline.skipped();
        if !unstarted.is_empty() || skipped > 0 || !abandoned.is_empty() {
            let mut backfill = hash_top_up().lock().await;
            // Abandoned reads were detached mid-file, so they produced nothing —
            // but their paths are in `seen`, which is never cleared, so
            // `queue_hash_top_up` would skip them for the life of the process
            // and the repair would not happen until the next launch. Forget the
            // path so a later scan can offer it again. Not re-queued directly:
            // the detached task still holds this path's in-flight claim until it
            // settles, and going back through `queue_hash_top_up` is what takes a
            // fresh one.
            //
            // Counted as done for the same reason `skipped` is — they are not
            // coming back in *this* pass, and a progress line that can never
            // reach its total reads as stuck.
            backfill.done = backfill
                .done
                .saturating_add(skipped)
                .saturating_add(abandoned.len());
            for index in abandoned {
                if let Some(file) = batch.get(index) {
                    backfill
                        .seen
                        .remove(&crate::search::index::normalize_path_key(&file.path));
                    backfill
                        .queued_hashes
                        .remove(&file.hash.to_ascii_lowercase());
                }
            }
            for index in unstarted {
                backfill.queued.push(batch[index].clone());
            }
        }
    }

    if updated_since_reconcile > 0 {
        refresh_file_cache(&local_index, &file_cache).await;
        reconcile_shared_files_best_effort(&network_tx).await;
    }
    let (done, total) = finished;
    info!("Hash top-up finished: {done}/{total}");
}

/// After hashing, restore share-intent and friends-only from known.met by
/// hash. Path+meta matching already did this at discovery; a rehash (mtime
/// changed, content unchanged) would otherwise keep `discover_file`'s
/// `friends_only: false` and publish a restricted file to the open network.
fn restore_known_hash_flags(file: &mut FileInfo, known: &KnownFileList) {
    let Ok(bytes) = hex::decode(&file.hash) else {
        return;
    };
    if bytes.len() != 16 {
        return;
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&bytes);
    file.shared = crate::storage::share_intent::effective_shared(&hash, file.shared);
    if let Some(record) = known.find_by_hash(&hash) {
        file.friends_only = record.friends_only;
    }
}

/// Apply a folder's configured default priority only to paths that need a new
/// hash. Known files keep their persisted per-file priority, while pending
/// files and their later hash-completion replacements inherit this value.
fn apply_folder_defaults_to_new_files(
    discovered: &mut [FileInfo],
    files_to_hash: &mut [FileInfo],
    folder_priorities: &std::collections::HashMap<String, String>,
) {
    if folder_priorities.is_empty() || files_to_hash.is_empty() {
        return;
    }
    let pending_paths = files_to_hash
        .iter()
        .map(|file| crate::search::index::normalize_path_key(&file.path))
        .collect::<HashSet<_>>();
    let priority_for_path = |path: &str| {
        folder_priorities
            .iter()
            .filter(|(folder, priority)| {
                !priority.is_empty() && crate::security::path_within_dir(path, folder)
            })
            .max_by_key(|(folder, _)| folder.len())
            .map(|(_, priority)| priority.clone())
    };
    for file in discovered.iter_mut().filter(|file| {
        pending_paths.contains(&crate::search::index::normalize_path_key(&file.path))
    }) {
        if let Some(priority) = priority_for_path(&file.path) {
            file.priority = priority;
        }
    }
    for file in files_to_hash.iter_mut() {
        if let Some(priority) = priority_for_path(&file.path) {
            file.priority = priority;
        }
    }
}

/// Unshare newly hashed files that sit in a folder the user shared by dropping
/// only some of its contents. Already-hashed files keep known.met; explicit
/// pending share intents applied after this still win.
pub(crate) fn apply_folder_allowlists(
    discovered: &mut [FileInfo],
    files_to_hash: &mut [FileInfo],
    allowlists: &std::collections::HashMap<String, Vec<String>>,
) {
    if allowlists.is_empty() || files_to_hash.is_empty() {
        return;
    }
    let lists: Vec<(String, HashSet<String>)> = allowlists
        .iter()
        .map(|(folder, files)| (folder.clone(), files.iter().cloned().collect::<HashSet<_>>()))
        .collect();
    let pending_paths = files_to_hash
        .iter()
        .map(|file| crate::search::index::normalize_path_key(&file.path))
        .collect::<HashSet<_>>();
    let apply = |file: &mut FileInfo| {
        let Some((_, allowed)) = lists
            .iter()
            .filter(|(folder, _)| crate::security::path_within_dir(&file.path, folder))
            .max_by_key(|(folder, _)| folder.len())
        else {
            return;
        };
        let key = crate::search::index::normalize_path_key(&file.path);
        file.shared = allowlist_permits(allowed, &key);
    };
    for file in discovered
        .iter_mut()
        .filter(|file| pending_paths.contains(&crate::search::index::normalize_path_key(&file.path)))
    {
        apply(file);
    }
    for file in files_to_hash {
        apply(file);
    }
}

/// Unshare the known files a partly shared folder's list does not offer: those
/// withheld from it, which discovery walks so the Library keeps them. known.met
/// holds one flag per content hash, which says shared whenever another copy is
/// offered. Files still to be hashed are [`apply_folder_allowlists`]'s.
pub(crate) fn withhold_unlisted_known_files(
    discovered: &mut [FileInfo],
    allowlists: &std::collections::HashMap<String, Vec<String>>,
) {
    if allowlists.is_empty() {
        return;
    }
    let offers = crate::sharing::indexer::AllowlistOffers::new(allowlists);
    for file in discovered
        .iter_mut()
        .filter(|file| file.shared && !file.hash.is_empty())
    {
        if !offers.offers(&file.path) {
            file.shared = false;
        }
    }
}

/// Take back from a share `mutation`, which flips every copy of a content
/// hash, the rows their partly shared folder's list does not offer: a copy
/// withheld there keeps that choice, and its name stays off the network.
fn keep_unlisted_copies_unshared(
    index: &mut LocalIndex,
    mutation: &mut crate::search::index::ShareMutation,
    offers: &crate::sharing::indexer::AllowlistOffers,
) {
    let unlisted = crate::search::index::ShareMutation {
        pending_paths: mutation.pending_paths.iter().filter(|path| !offers.offers(path)).cloned().collect(),
        hashed_paths: mutation.hashed_paths.iter().filter(|path| !offers.offers(path)).cloned().collect(),
        ..Default::default()
    };
    if unlisted.pending_paths.is_empty() && unlisted.hashed_paths.is_empty() {
        return;
    }
    index.revert_share_mutation(&unlisted, true);
    mutation.pending_paths.retain(|path| offers.offers(path));
    mutation.hashed_paths.retain(|path| offers.offers(path));
    mutation.changed_paths = mutation.pending_paths.len() + mutation.hashed_paths.len();
}

/// Whether one allowlist entry offers the file or folder at `key`. An entry
/// is a file, or a folder whose whole contents are offered; both are
/// `normalize_path_key` forms.
pub(crate) fn path_key_covers(entry: &str, key: &str) -> bool {
    key == entry
        || key
            .strip_prefix(entry)
            .is_some_and(|rest| rest.starts_with(std::path::MAIN_SEPARATOR))
}

use crate::sharing::indexer::allowlist_permits;

/// A folder freshly added under an allowlist offers exactly that list, whatever
/// known.met remembers of its files from an earlier share of the same folder.
/// [`apply_folder_allowlists`] only reaches files that still need hashing, so
/// without this every previously hashed file came back with its old
/// `is_shared` and went straight onto the network. Returns the content hashes
/// it withheld: known.met's own flag is what the next scan restores, so the
/// caller has to persist them.
fn withhold_known_files_outside_allowlist(
    discovered: &mut [FileInfo],
    folder: &str,
    allowlists: &std::collections::HashMap<String, Vec<String>>,
) -> Vec<String> {
    let Some(list) = allowlists.get(&crate::search::index::normalize_path_key(folder)) else {
        return Vec::new();
    };
    let allowed = list.iter().cloned().collect::<HashSet<_>>();
    let mut withheld = Vec::new();
    for file in discovered
        .iter_mut()
        .filter(|file| file.shared && !file.hash.is_empty())
    {
        let key = crate::search::index::normalize_path_key(&file.path);
        if crate::security::path_within_dir(&file.path, folder)
            && !allowlist_permits(&allowed, &key)
        {
            file.shared = false;
            withheld.push(file.hash.to_ascii_lowercase());
        }
    }
    withheld.sort();
    withheld.dedup();
    withheld
}

/// The content hashes of `withheld` that no Library row offers. known.met
/// holds one flag per content hash, so a copy still offered from another
/// folder keeps it.
fn not_offered_by_the_library(index: &LocalIndex, withheld: Vec<String>) -> Vec<String> {
    if withheld.is_empty() {
        return withheld;
    }
    let offered = index
        .all_files()
        .iter()
        .filter(|file| file.shared && !file.hash.is_empty())
        .map(|file| file.hash.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    withheld
        .into_iter()
        .filter(|hash| !offered.contains(hash))
        .collect()
}

/// The known.met side of [`withhold_known_files_outside_allowlist`], for a
/// folder whose first scan is a full reload rather than its own pass.
fn known_hashes_outside_allowlist(
    known: &KnownFileList,
    folder: &str,
    allowlists: &std::collections::HashMap<String, Vec<String>>,
) -> Vec<String> {
    let Some(list) = allowlists.get(&crate::search::index::normalize_path_key(folder)) else {
        return Vec::new();
    };
    let allowed = list.iter().cloned().collect::<HashSet<_>>();
    let mut withheld = known
        .all_records()
        .filter(|record| {
            record.is_shared
                && crate::security::path_within_dir(&record.file_path, folder)
                && !allowlist_permits(
                    &allowed,
                    &crate::search::index::normalize_path_key(&record.file_path),
                )
        })
        .map(|record| hex::encode(record.file_hash))
        .collect::<Vec<_>>();
    withheld.sort();
    withheld.dedup();
    withheld
}

pub(crate) fn apply_pending_intents(
    discovered: &mut [FileInfo],
    files_to_hash: &mut [FileInfo],
    pending_share_states: &std::collections::HashMap<String, bool>,
    pending_file_priorities: &std::collections::HashMap<String, String>,
) {
    let pending_paths = files_to_hash
        .iter()
        .map(|file| crate::search::index::normalize_path_key(&file.path))
        .collect::<HashSet<_>>();
    let apply = |file: &mut FileInfo| {
        let key = crate::search::index::normalize_path_key(&file.path);
        if let Some(shared) = pending_share_states.get(&key) {
            file.shared = *shared;
        }
        if let Some(priority) = pending_file_priorities.get(&key) {
            file.priority = priority.clone();
        }
    };
    for file in discovered.iter_mut().filter(|file| {
        pending_paths.contains(&crate::search::index::normalize_path_key(&file.path))
    }) {
        apply(file);
    }
    for file in files_to_hash {
        apply(file);
    }
}

async fn persist_pending_intents(
    state: &AppState,
    share_updates: &[(String, bool)],
    priority_updates: &[(String, String)],
    share_removals: &[String],
    priority_removals: &[String],
) -> Result<(), String> {
    write_pending_intents(
        state,
        share_updates,
        priority_updates,
        share_removals,
        priority_removals,
        true,
    )
    .await
}

/// [`persist_pending_intents`], with `user_driven` deciding whether updates
/// bump the visible settings revision.
async fn write_pending_intents(
    state: &AppState,
    share_updates: &[(String, bool)],
    priority_updates: &[(String, String)],
    share_removals: &[String],
    priority_removals: &[String],
    user_driven: bool,
) -> Result<(), String> {
    if share_updates.is_empty()
        && priority_updates.is_empty()
        && share_removals.is_empty()
        && priority_removals.is_empty()
    {
        return Ok(());
    }
    let _settings_save_guard = state.settings_save_lock.lock().await;
    let mut settings = {
        let config = state.config.read().await;
        config.settings.clone()
    };
    for (path, shared) in share_updates {
        settings
            .pending_share_states
            .insert(crate::search::index::normalize_path_key(path), *shared);
    }
    for (path, priority) in priority_updates {
        settings.pending_file_priorities.insert(
            crate::search::index::normalize_path_key(path),
            priority.clone(),
        );
    }
    // A pending intent is a one-shot handoff for a file that was still
    // hashing. Once the file is hashed (or an explicit change is applied to
    // the hashed row), known.met owns the state and the intent must die —
    // a stale entry would re-apply on the next rehash and silently flip a
    // share/priority the user has since changed.
    let mut removed_any = false;
    for path in share_removals {
        removed_any |= settings
            .pending_share_states
            .remove(&crate::search::index::normalize_path_key(path))
            .is_some();
    }
    for path in priority_removals {
        removed_any |= settings
            .pending_file_priorities
            .remove(&crate::search::index::normalize_path_key(path))
            .is_some();
    }
    if share_updates.is_empty() && priority_updates.is_empty() && !removed_any {
        return Ok(());
    }
    // Only user-driven updates bump the visible settings revision; internal
    // intent cleanup must not make an open Settings form spuriously stale
    // (same rationale as `persist_scan_cursors`).
    if user_driven && (!share_updates.is_empty() || !priority_updates.is_empty()) {
        settings.settings_revision = settings.settings_revision.saturating_add(1);
    }
    let save_data = {
        let config = state.config.read().await;
        config
            .prepare_save_settings(&settings)
            .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?
    };
    let (data, tmp, final_path) = save_data;
    tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
    })
    .await
    .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?
    .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?;
    state.config.write().await.settings = settings;
    Ok(())
}

pub(crate) async fn persist_folder_allowlists(
    state: &AppState,
    updates: &[(String, Vec<String>)],
    removals: &[String],
) -> Result<(), String> {
    if updates.is_empty() && removals.is_empty() {
        return Ok(());
    }
    edit_folder_allowlists(state, |lists| {
        for (folder, files) in updates {
            let folder_key = crate::search::index::normalize_path_key(folder);
            let file_keys = files
                .iter()
                .map(|path| crate::search::index::normalize_path_key(path))
                .collect::<Vec<_>>();
            lists.insert(folder_key, file_keys);
        }
        for folder in removals {
            lists.remove(&crate::search::index::normalize_path_key(folder));
        }
        true
    })
    .await
}

/// Read-modify-write the folder allowlists as one atomic step.
///
/// The read has to happen under `settings_save_lock`, not before it. Callers
/// that compute a replacement list from a snapshot taken earlier — "this list
/// minus the file being unshared" — would otherwise write back a list that
/// predates a concurrent edit, silently dropping a file another command had
/// just added to the same folder.
///
/// `edit` returns whether it changed anything; `false` skips the disk write.
async fn edit_folder_allowlists<F>(state: &AppState, edit: F) -> Result<(), String>
where
    F: FnOnce(&mut std::collections::HashMap<String, Vec<String>>) -> bool,
{
    edit_folder_lists(state, |allowlists, _| edit(allowlists)).await
}

/// [`edit_folder_allowlists`], with the withheld files beside the allowlists.
/// The withheld files are tidied against the edited allowlists either way.
async fn edit_folder_lists<F>(state: &AppState, edit: F) -> Result<(), String>
where
    F: FnOnce(
        &mut std::collections::HashMap<String, Vec<String>>,
        &mut std::collections::HashMap<String, Vec<String>>,
    ) -> bool,
{
    let _settings_save_guard = state.settings_save_lock.lock().await;
    let mut settings = {
        let config = state.config.read().await;
        config.settings.clone()
    };
    let edited = edit(
        &mut settings.pending_folder_allowlists,
        &mut settings.withheld_folder_files,
    );
    let tidied = tidy_withheld(&settings.pending_folder_allowlists, &mut settings.withheld_folder_files);
    if !edited && !tidied {
        return Ok(());
    }
    settings.settings_revision = settings.settings_revision.saturating_add(1);
    let save_data = {
        let config = state.config.read().await;
        config
            .prepare_save_settings(&settings)
            .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?
    };
    let (data, tmp, final_path) = save_data;
    tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
    })
    .await
    .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?
    .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?;
    state.config.write().await.settings = settings;
    Ok(())
}

/// Keep only the withheld files that still mean something: those in a folder
/// that has an allowlist, and that the allowlist does not offer (a file shared
/// again, or taken in by a folder entry, is walked as part of the list).
/// Returns whether anything went.
fn tidy_withheld(
    allowlists: &std::collections::HashMap<String, Vec<String>>,
    withheld: &mut std::collections::HashMap<String, Vec<String>>,
) -> bool {
    let mut changed = false;
    withheld.retain(|folder, files| {
        let Some(list) = allowlists.get(folder) else {
            changed = true;
            return false;
        };
        let allowed = list.iter().cloned().collect::<HashSet<_>>();
        let before = files.len();
        let mut seen = HashSet::new();
        files.retain(|file| {
            crate::security::path_within_dir(file, folder)
                && !allowlist_permits(&allowed, file)
                && seen.insert(file.clone())
        });
        changed |= files.len() != before;
        if files.is_empty() {
            changed = true;
            return false;
        }
        true
    });
    changed
}

/// Sweep pending share/priority intents whose files are now hashed. A pending
/// intent is a one-shot handoff from "user changed a file that was still
/// hashing" to the hash-completion path; once the row is hashed, known.met
/// owns the state. Entries left behind (pre-fix builds, crashes between
/// finalize and cleanup) would re-apply on the next rehash and silently flip
/// share/priority choices the user has since changed. Called after every
/// completed hash pass. Entries whose path has no hashed index row are kept —
/// they may belong to genuinely pending files in a later scan page.
pub(crate) async fn prune_pending_intents_for_hashed(state: &AppState) {
    let hashed_keys: HashSet<String> = {
        let index = state.local_index.read().await;
        index
            .all_files()
            .iter()
            .filter(|f| !f.hash.is_empty())
            .map(|f| crate::search::index::normalize_path_key(&f.path))
            .collect()
    };
    if hashed_keys.is_empty() {
        return;
    }
    let (share_stale, priority_stale) = {
        let config = state.config.read().await;
        (
            config
                .settings
                .pending_share_states
                .keys()
                .filter(|key| hashed_keys.contains(*key))
                .cloned()
                .collect::<Vec<_>>(),
            config
                .settings
                .pending_file_priorities
                .keys()
                .filter(|key| hashed_keys.contains(*key))
                .cloned()
                .collect::<Vec<_>>(),
        )
    };
    if share_stale.is_empty() && priority_stale.is_empty() {
        return;
    }
    if let Err(e) = persist_pending_intents(state, &[], &[], &share_stale, &priority_stale).await {
        warn!(
            "Failed to prune {} stale pending intents: {e}",
            share_stale.len() + priority_stale.len()
        );
    } else {
        info!(
            "Pruned {} pending share and {} pending priority intents for hashed files",
            share_stale.len(),
            priority_stale.len()
        );
    }
}

/// Persist completed shared-folder discovery pages. Cursors are advanced only
/// after the page has entered the in-memory index; if this save fails, a later
/// scan may repeat a page but it can never skip files.
/// `never_rewind` is for callers that deliberately rescan from the beginning
/// (startup) rather than resuming. Their page-1 cursor is always behind a
/// cursor a reload has advanced, so persisting it unconditionally would rewind
/// progress on every launch — a folder past the file cap could then never be
/// cycled through by anyone who restarts the app regularly. Pages advance in
/// sorted order, so "further along" is just the greater normalized key. An
/// explicit `None` still clears: it means the page reached the folder's end.
pub(crate) async fn persist_scan_cursors(
    state: &AppState,
    updates: &std::collections::HashMap<String, Option<String>>,
    never_rewind: bool,
) -> Result<(), String> {
    if updates.is_empty() {
        return Ok(());
    }
    let _settings_save_guard = state.settings_save_lock.lock().await;
    let mut settings = {
        let config = state.config.read().await;
        config.settings.clone()
    };
    let cursors_before = settings.shared_folder_scan_cursors.clone();
    for (folder, cursor) in updates {
        match cursor {
            Some(value) => {
                let key = crate::search::index::normalize_path_key(folder);
                if never_rewind
                    && settings
                        .shared_folder_scan_cursors
                        .get(&key)
                        .is_some_and(|stored| stored.as_str() >= value.as_str())
                {
                    continue;
                }
                settings
                    .shared_folder_scan_cursors
                    .insert(key, value.clone());
            }
            None => {
                settings
                    .shared_folder_scan_cursors
                    .remove(&crate::search::index::normalize_path_key(folder));
            }
        }
    }
    // Nothing moved: every update either repeated the stored cursor or was
    // declined by `never_rewind`. Writing anyway rewrote settings.json on
    // every scan, which on Linux turned each rescan into a visible
    // "Config saved" churn cycle.
    if settings.shared_folder_scan_cursors == cursors_before {
        return Ok(());
    }
    // Scan cursors are internal recovery bookkeeping, not a user setting;
    // changing the visible revision here would make an open Settings form
    // spuriously stale whenever a large folder advances a page.
    let (data, tmp, final_path) = {
        let config = state.config.read().await;
        config
            .prepare_save_settings(&settings)
            .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?
    };
    tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
    })
    .await
    .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?
    .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?;
    state.config.write().await.settings = settings;
    Ok(())
}

/// What a successful [`add_shared_folder`] actually did.
///
/// Re-adding a folder is a no-op rather than an error, but the two are worth
/// telling apart when reporting back: the folder picker is the OS dialog, which
/// cannot mark the folders already being shared, so "you already share this
/// one" is the only way the user finds out — and reporting it as a fresh add
/// (which is what a bare `Ok(())` made every caller do) is the answer that
/// leaves them none the wiser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FolderAddOutcome {
    /// Newly shared; a background discovery + hash pass is running.
    Added,
    /// Already in the shared list, so nothing changed and nothing was scanned.
    AlreadyShared,
}

/// eMule-style shared folder addition -- returns IMMEDIATELY.
/// All discovery and hashing runs in a background task:
///   Phase 1: discover files (metadata only) → show in UI via event
///   Phase 2: hash files one at a time → update UI + publish to KAD
pub(crate) async fn add_shared_folder(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<FolderAdd, String> {
    add_shared_folder_limited(app, state, path, None).await
}

/// What [`add_shared_folder_limited`] did with the entries it was asked to
/// limit a folder to.
#[derive(Debug)]
pub(crate) struct FolderAdd {
    pub(crate) outcome: FolderAddOutcome,
    /// The folder as it is stored in the shared list.
    pub(crate) folder: String,
    /// The limiting files, spelled the way discovery records them. Empty for a
    /// whole-folder add.
    pub(crate) files: Vec<String>,
    /// The limiting folders, likewise. Everything under one is offered.
    pub(crate) dirs: Vec<String>,
    /// An already-shared folder's allowlist took on entries it did not have.
    pub(crate) allowlist_grew: bool,
}

/// `path` spelled the way discovery will record it once its folder is shared:
/// a directory canonicalized, which is how `add_shared_folder` stores a folder
/// and so the root discovery walks, and a file as its canonicalized parent
/// with the name joined back on. Discovery never resolves the file itself, so
/// neither may this. `None` when the path cannot be resolved. Blocking.
fn discovery_form(path: &std::path::Path) -> Option<(String, bool)> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    let resolved = if meta.is_dir() {
        path.canonicalize().ok()?
    } else {
        path.parent()?.canonicalize().ok()?.join(path.file_name()?)
    };
    Some((
        crate::commands::share_browser::display_fs_path(&resolved),
        meta.is_dir(),
    ))
}

/// Replace every allowlist at or under a folder being newly shared with
/// exactly the one this add asked for, or none for a whole-folder add. One
/// left from an earlier share of the same folder would otherwise go on
/// limiting a folder the user has just shared in full.
fn set_added_folder_allowlist(
    lists: &mut std::collections::HashMap<String, Vec<String>>,
    folder: &str,
    limit: Option<&(Vec<String>, Vec<String>)>,
) {
    lists.retain(|listed, _| !crate::security::path_within_dir(listed, folder));
    if let Some((files, dirs)) = limit {
        lists.insert(
            crate::search::index::normalize_path_key(folder),
            files
                .iter()
                .chain(dirs)
                .map(|path| crate::search::index::normalize_path_key(path))
                .collect(),
        );
    }
}

/// Merge `entries` into an already-shared folder's allowlist. A folder with no
/// allowlist is a full share and already offers them. Returns whether the
/// list grew. With `may_grow` false, a list that would grow is left alone and
/// the add is refused; one that already covers `entries` is fine either way.
async fn extend_folder_allowlist(
    state: &AppState,
    folder: &str,
    entries: &[String],
    may_grow: bool,
) -> Result<bool, String> {
    let key = crate::search::index::normalize_path_key(folder);
    let mut grew = false;
    let mut refused = false;
    edit_folder_allowlists(state, |lists| {
        let Some(list) = lists.get_mut(&key) else {
            return false;
        };
        let mut listed = list.iter().cloned().collect::<HashSet<_>>();
        let missing: Vec<String> = entries
            .iter()
            .map(|entry| crate::search::index::normalize_path_key(entry))
            .filter(|entry| !allowlist_permits(&listed, entry))
            .collect();
        if missing.is_empty() {
            return false;
        }
        if !may_grow {
            refused = true;
            return false;
        }
        for entry in missing {
            if !allowlist_permits(&listed, &entry) {
                listed.insert(entry.clone());
                list.push(entry);
            }
        }
        grew = true;
        true
    })
    .await?;
    if refused {
        return Err(coded(
            "sharing_share_not_confirmed",
            "Nothing was shared because it was not confirmed",
        ));
    }
    Ok(grew)
}

/// Ask, in a dialog the renderer can neither draw nor dismiss, whether to share
/// a whole drive. Every add whose folder the OS handed us (picker, drop)
/// arrives here. The in-app browser asks once for its whole selection instead,
/// drive warning included, so it is not asked a second time; see
/// [`ShareApproval::Confirmed`].
pub(crate) async fn confirm_drive_root_share(app: &tauri::AppHandle, root: &std::path::Path) -> bool {
    use tauri_plugin_dialog::{MessageDialogButtons, MessageDialogKind};
    let shown = crate::commands::share_browser::display_fs_path(root);
    let prompt = format!(
        "Share the entire drive {}?\n\nEvery file on it, in every folder, will be offered to other peers. \
         Only do this for a drive that holds nothing but files you mean to share.",
        crate::commands::settings::elide_for_dialog(&shown)
    );
    let app = app.clone();
    tokio::task::spawn_blocking(move || {
        app.dialog()
            .message(prompt)
            .title("Share a whole drive?")
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancelCustom(
                "Share the drive".to_string(),
                "Cancel".to_string(),
            ))
            .blocking_show()
    })
    .await
    .unwrap_or(false)
}

/// [`add_shared_folder`], optionally offering only `only` out of the folder:
/// files, or folders whose whole contents are offered.
///
/// The allowlist is keyed here, by the canonical path the folder is stored
/// under and discovery walks, and is written by the same save that adds the
/// folder. Keyed by the path as dropped or browsed, a mapped network drive, a
/// `subst` drive or a junction matched nothing in the scan, and the whole
/// folder went onto the network. An entry that does not resolve under the
/// folder is left off rather than widening the share, and a limit none of
/// whose entries resolve is refused.
///
/// A folder that is already shared, or that sits inside a shared folder, is
/// not added again: `only` joins that share's allowlist when it has one, and a
/// full share offers them already. Either way the caller still has to offer
/// any of `files` that are indexed but unshared.
///
/// Only for a folder the OS itself handed the backend: one chosen in the
/// native folder picker, or a directory dropped on the native window. Not the
/// folder holding a dropped file, which the OS never handed over, and not a
/// path the renderer named; those go through [`add_shared_folder_approved`]
/// with the roots the user confirmed natively.
pub(crate) async fn add_shared_folder_limited(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
    only: Option<Vec<String>>,
) -> Result<FolderAdd, String> {
    add_shared_folder_approved(app, state, path, only, ShareApproval::Native).await
}

/// Who vouches for an add that would put a folder on the shared list, or let
/// more of an already partly shared folder onto the network.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ShareApproval<'a> {
    /// The OS handed the backend this path, so the gesture is the user's
    /// answer. Only a whole drive is still asked about.
    Native,
    /// Only these roots, which the user approved in a native dialog that also
    /// carried any whole-drive warning, may become new shares or have their
    /// allowlist grow. Anything else is refused where the add commits, so a
    /// folder unshared between that dialog and the add cannot slip in unasked.
    Confirmed(&'a [String]),
}

impl ShareApproval<'_> {
    fn permits(&self, root: &str) -> bool {
        match self {
            ShareApproval::Native => true,
            ShareApproval::Confirmed(approved) => approved
                .iter()
                .any(|approved| paths_equal_ignore_case(approved, root)),
        }
    }
}

/// [`add_shared_folder_limited`] under an explicit [`ShareApproval`].
pub(crate) async fn add_shared_folder_approved(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
    only: Option<Vec<String>>,
    approval: ShareApproval<'_>,
) -> Result<FolderAdd, String> {
    if path.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "sharing_folder_path_too_long",
            format!("Folder path exceeds {MAX_PATH_LEN} bytes"),
            MAX_PATH_LEN,
        ));
    }
    if let Some(entries) = only.as_ref() {
        check_path_batch(entries, MAX_BATCH_IDS)?;
    }
    // Run the blocking filesystem checks off the async runtime: on a slow or
    // disconnected network path, exists()/is_dir()/canonicalize() can block a
    // worker thread for the OS timeout.
    let (canonical, resolved_only) = tokio::task::spawn_blocking({
        let path = path.clone();
        move || -> Result<(std::path::PathBuf, Option<Vec<(String, bool)>>), String> {
            let p = std::path::Path::new(&path);
            if !p.exists() || !p.is_dir() {
                return Err(coded(
                    "sharing_path_not_dir",
                    "Path does not exist or is not a directory",
                ));
            }
            let canonical = p
                .canonicalize()
                .map_err(|e| coded_ctx("sharing_invalid_path", "Invalid path", e))?;
            let resolved = only.map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| discovery_form(std::path::Path::new(entry)))
                    .collect::<Vec<_>>()
            });
            Ok((canonical, resolved))
        }
    })
    .await
    .map_err(|e| coded_ctx("sharing_task_failed", "Task failed", e))??;

    // A whole volume makes every path on it pass `is_path_within_dirs`, so it
    // is never the system drive or the one holding the user's profile. A
    // dedicated data drive is allowed once the user confirms below, since that
    // is how an eMule archive spread over drives has always been shared.
    let drive_root = crate::sharing::drive_root_share(&canonical);
    if drive_root == crate::sharing::DriveRootShare::Refused {
        return Err(coded_ctx(
            "sharing_cannot_share_root",
            "Cannot share the system drive or the drive holding your user profile",
            canonical.display(),
        ));
    }

    // Refuse system / sensitive path segments (shared with the indexer so
    // nested `.ssh` etc. are also skipped when walking an allowed parent).
    for component in canonical.components() {
        if let std::path::Component::Normal(seg) = component {
            if crate::sharing::is_sensitive_dir_name(&seg.to_string_lossy()) {
                return Err(coded_ctx(
                    "sharing_cannot_share_system_dir",
                    "Cannot share system directory",
                    canonical.display(),
                ));
            }
        }
    }

    // Refuse Ember's own data directory (config, identity, known.met, …),
    // and refuse a parent that contains it (indexer would otherwise walk in).
    let data_dir = crate::storage::paths::resolve_data_dir();
    let data_canon = data_dir.canonicalize().unwrap_or(data_dir.clone());
    let share_covers_data_dir = data_canon == canonical
        || data_canon.starts_with(&canonical)
        || paths_equal_ignore_case(&canonical.to_string_lossy(), &data_dir.to_string_lossy())
        || crate::security::path_matches_dir(
            &data_canon.to_string_lossy(),
            &canonical.to_string_lossy(),
        );
    if share_covers_data_dir {
        return Err(coded_ctx(
            "sharing_cannot_share_data_dir",
            "Cannot share Ember data directory or a parent of it",
            canonical.display(),
        ));
    }

    let canonical_str = canonical.to_string_lossy().to_string();
    if drive_root == crate::sharing::DriveRootShare::NeedsConfirmation
        && matches!(approval, ShareApproval::Native)
    {
        // A drive shared in part never carried the whole-drive warning, and a
        // whole-folder add is how the picker goes on to lift its allowlist.
        let asked_before = {
            let config = state.config.read().await;
            let settings = &config.settings;
            let shared = settings
                .shared_folders
                .iter()
                .any(|f| paths_equal_ignore_case(f, &canonical_str));
            let limited = settings
                .pending_folder_allowlists
                .keys()
                .any(|key| paths_equal_ignore_case(key, &canonical_str));
            shared && (!limited || resolved_only.is_some())
        };
        if !asked_before && !confirm_drive_root_share(&app, &canonical).await {
            return Err(coded_ctx(
                "sharing_drive_root_declined",
                "The drive was not shared",
                canonical.display(),
            ));
        }
    }
    let limit = match resolved_only {
        Some(entries) => {
            let mut files = Vec::new();
            let mut dirs = Vec::new();
            let mut whole = false;
            for (entry, is_dir) in entries {
                if !crate::security::path_within_dir(&entry, &canonical_str) {
                    continue;
                }
                if is_dir {
                    whole |= paths_equal_ignore_case(&entry, &canonical_str);
                    dirs.push(entry);
                } else {
                    files.push(entry);
                }
            }
            if files.is_empty() && dirs.is_empty() {
                return Err(coded_ctx(
                    "sharing_invalid_path",
                    "Invalid path",
                    format!("nothing selected resolves inside {canonical_str}"),
                ));
            }
            (!whole).then_some((files, dirs))
        }
        None => None,
    };
    // Build (but don't yet commit) the settings we intend to save. Persisting to
    // disk before mutating the in-memory config and the live upload list ensures
    // a failed write can't leave them advertising a folder that isn't saved.
    // Case-insensitive on Windows: `Vec::contains` is case-sensitive, so adding
    // `C:\Media` then `c:\media` would store both, double-scan, and make later
    // unshare/remove (which use paths_equal_ignore_case) inconsistent.
    let settings_save_guard = state.settings_save_lock.lock().await;
    let save_data = {
        let config = state.config.read().await;
        // Only some files of a folder inside a share: they belong to that
        // share, and adding their folder would be refused as an overlap.
        let existing = config.settings.shared_folders.iter().find(|f| {
            paths_equal_ignore_case(f, &canonical_str)
                || (limit.is_some() && crate::security::path_within_dir(&canonical_str, f))
        });
        if let Some(existing) = existing {
            Err(existing.clone())
        } else {
            if let Some(existing) = config.settings.shared_folders.iter().find(|existing| {
                crate::commands::settings::shared_paths_overlap(
                    std::path::Path::new(existing),
                    &canonical,
                )
            }) {
                return Err(coded_ctx(
                    "sharing_folder_overlap",
                    "Shared folders must not overlap",
                    format!("{existing} and {canonical_str}"),
                ));
            }
            // Checked under the save lock, against the list this add commits
            // to, so "not new when the dialog was drawn" cannot go stale.
            if !approval.permits(&canonical_str) {
                return Err(coded(
                    "sharing_share_not_confirmed",
                    "Nothing was shared because it was not confirmed",
                ));
            }
            let mut new_settings = config.settings.clone();
            new_settings.shared_folders.push(canonical_str.clone());
            set_added_folder_allowlist(
                &mut new_settings.pending_folder_allowlists,
                &canonical_str,
                limit.as_ref(),
            );
            new_settings
                .withheld_folder_files
                .retain(|listed, _| !crate::security::path_within_dir(listed, &canonical_str));
            new_settings.settings_revision = config.settings.settings_revision.saturating_add(1);
            Ok(config
                .prepare_save_settings(&new_settings)
                .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?)
        }
    };
    let (data, tmp, final_path) = match save_data {
        Ok(save_data) => save_data,
        Err(existing) => {
            drop(settings_save_guard);
            info!("Folder {canonical_str} is already shared, skipping duplicate scan");
            let (files, dirs) = limit.unwrap_or_default();
            let entries = files.iter().chain(&dirs).cloned().collect::<Vec<_>>();
            let allowlist_grew = if entries.is_empty() {
                false
            } else {
                extend_folder_allowlist(&state, &existing, &entries, approval.permits(&existing))
                    .await?
            };
            return Ok(FolderAdd {
                outcome: FolderAddOutcome::AlreadyShared,
                folder: existing,
                files,
                dirs,
                allowlist_grew,
            });
        }
    };
    let limited = limit.is_some();
    let mut roots = {
        let config = state.config.read().await;
        let mut roots = config.settings.shared_folders.clone();
        if !config.settings.download_folder.is_empty() {
            roots.push(config.settings.download_folder.clone());
        }
        roots
    };
    roots.push(canonical_str.clone());
    let registry = state.approved_roots.clone();
    let approved = canonical_str.clone();
    tokio::task::spawn_blocking(move || {
        super::settings::persist_with_root_transaction(
            registry,
            &roots,
            std::slice::from_ref(&approved),
            &[],
            || crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path),
        )
    })
    .await
    .map_err(|e| coded_ctx("sharing_config_transaction_error", "Config save error", e))?
    .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?;
    // The addition is durable on disk now; commit it in-memory and to the live
    // upload list. Both re-checks stay idempotent against a concurrent add of
    // the same path.
    {
        let mut config = state.config.write().await;
        if !config
            .settings
            .shared_folders
            .iter()
            .any(|f| paths_equal_ignore_case(f, &canonical_str))
        {
            config.settings.shared_folders.push(canonical_str.clone());
        }
        set_added_folder_allowlist(
            &mut config.settings.pending_folder_allowlists,
            &canonical_str,
            limit.as_ref(),
        );
        config
            .settings
            .withheld_folder_files
            .retain(|listed, _| !crate::security::path_within_dir(listed, &canonical_str));
        config.settings.settings_revision = config.settings.settings_revision.saturating_add(1);
    }
    drop(settings_save_guard);
    {
        let mut live = state.upload_shared_folders.write().await;
        if !live
            .iter()
            .any(|f| paths_equal_ignore_case(f, &canonical_str))
        {
            live.push(canonical_str.clone());
        }
    }
    let (files, dirs) = limit.unwrap_or_default();
    let added = FolderAdd {
        outcome: FolderAddOutcome::Added,
        folder: canonical_str.clone(),
        files,
        dirs,
        allowlist_grew: false,
    };

    // Adding a folder is an explicit user action that should resume hashing
    // even if a previous Stop left the pause latch set.
    state.hashing_paused.store(false, Ordering::Relaxed);

    // Start watching the new folder (and anything else currently shared).
    if let Some(watcher) = state.shared_folder_watcher.as_ref() {
        let folders = state.config.read().await.settings.shared_folders.clone();
        watcher.sync_paths(&folders);
    }
    {
        let config = state.config.read().await;
        sync_asset_protocol_scope(&app, &config);
    }

    // FS changes deferred during pause must not be lost when add-folder
    // clears the latch but only scans the new path. A full reload covers
    // every share (including the folder just added) and clears the dirty bit.
    if state.hashing_fs_dirty.load(Ordering::Relaxed) {
        info!("FS changes deferred during pause; running full shared-folder reload");
        // The reload resolves known.met the way it would for any established
        // folder, so the files this add withholds have to be unshared there
        // before it reads them.
        if limited {
            let allowlists = state
                .config
                .read()
                .await
                .settings
                .pending_folder_allowlists
                .clone();
            let withheld = known_hashes_outside_allowlist(
                &load_known_files().await?,
                &canonical_str,
                &allowlists,
            );
            let withheld = not_offered_by_the_library(&*state.local_index.read().await, withheld);
            if let Err(error) = persist_shared_states(&state.network_tx, &withheld, false).await {
                warn!(
                    "Files outside the new allowlist on {canonical_str} were not unshared: {error}"
                );
            }
        }
        // Still an add from the caller's point of view: the folder went into the
        // shared list above, and the reload is how it gets scanned.
        reload_shared_files(app, state).await?;
        return Ok(added);
    }

    let local_index = state.local_index.clone();
    let file_cache = state.cached_shared_files.clone();
    let network_tx = state.network_tx.clone();
    let scanning = state.scanning_count.clone();
    let scan_coordination = state.scan_coordination.clone();
    let cancel_flags = state.hash_cancel_flags.clone();
    let fresh_part_hashes = state.fresh_part_hashes.clone();
    let config = state.config.clone();
    let scan_truncated = state.library_scan_truncated.clone();

    let cancel_flag = Arc::new(AtomicBool::new(false));
    let cancel_key = canonical_str.clone();
    cancel_flags
        .write()
        .await
        .insert(cancel_key.clone(), cancel_flag.clone());

    let scan_handle = tokio::spawn(async move {
        // Held for the whole scan and released when this task ends. Deliberately
        // not handed to the hash-timeout drain: that drain can block indefinitely
        // on a stuck read, which would wedge every later scan.
        let _coordination_guard = scan_coordination.clone().lock_owned().await;
        scanning.fetch_add(1, Ordering::Relaxed);
        let scan_guard = ScanGuard(scanning.clone());

        let discover_path = canonical_str.clone();
        let scope = {
            let cfg = config.read().await;
            crate::sharing::indexer::DiscoveryScope::for_root(
                &canonical_str,
                &crate::sharing::indexer::discovery_lists(
                    &cfg.settings.pending_folder_allowlists,
                    &cfg.settings.withheld_folder_files,
                ),
            )
        };
        let discovery = match tokio::task::spawn_blocking(move || {
            FileIndexer::discover_directory_page_in(&discover_path, None, scope.as_ref())
        })
        .await
        {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Discovery failed for {path}: {e}");
                remove_cancel_flag_if_current(&cancel_flags, &cancel_key, &cancel_flag).await;
                report_scan_failure(&app, Some(&path));
                return;
            }
        };
        if discovery.truncated {
            warn!(
                "Discovery for {path} reached the per-folder file cap; additional files will be picked up by a later scan"
            );
            scan_truncated.store(true, Ordering::Relaxed);
            let _ = app.emit(
                "shared-files-scan-truncated",
                serde_json::json!({ "folder": path, "limit": 100_000 }),
            );
        }
        let discovery_next_cursor = discovery.next_cursor;
        let mut discovered = discovery.files;

        let total_files = discovered.len();
        info!("Discovered {total_files} files in {path}");

        let still_shared = {
            let cfg = config.read().await;
            file_in_shared_folders(&canonical_str, &cfg.settings.shared_folders)
        };
        if cancel_flag.load(Ordering::Relaxed) || !still_shared {
            info!("Hashing cancelled during discovery for {path}");
            remove_cancel_flag_if_current(&cancel_flags, &cancel_key, &cancel_flag).await;
            let _ = app.emit(
                "file-hash-progress",
                serde_json::json!({ "done": true, "current": 0, "total": 0, "file_name": "" }),
            );
            return;
        }

        let known_list = match load_known_files().await {
            Ok(known_list) => known_list,
            Err(e) => {
                tracing::error!("known.met load failed for {path}: {e}");
                remove_cancel_flag_if_current(&cancel_flags, &cancel_key, &cancel_flag).await;
                return;
            }
        };
        let ResolvedWork {
            needs_hashing: mut files_to_hash,
            needs_top_up,
        } = resolve_from_known(&mut discovered, &known_list);
        let (
            folder_priorities,
            pending_share_states,
            pending_file_priorities,
            pending_folder_allowlists,
        ) = {
            let cfg = config.read().await;
            (
                cfg.settings.folder_priorities.clone(),
                cfg.settings.pending_share_states.clone(),
                cfg.settings.pending_file_priorities.clone(),
                cfg.settings.pending_folder_allowlists.clone(),
            )
        };
        apply_folder_defaults_to_new_files(&mut discovered, &mut files_to_hash, &folder_priorities);
        apply_folder_allowlists(
            &mut discovered,
            &mut files_to_hash,
            &pending_folder_allowlists,
        );
        withhold_unlisted_known_files(&mut discovered, &pending_folder_allowlists);
        let withheld = if limited {
            let mut withheld = withhold_known_files_outside_allowlist(
                &mut discovered,
                &canonical_str,
                &pending_folder_allowlists,
            );
            // Discovery walks only the list, so the rest of an earlier share
            // of this folder is in known.met alone, still marked shared, and
            // startup hydration would bring it back offered.
            withheld.extend(known_hashes_outside_allowlist(
                &known_list,
                &canonical_str,
                &pending_folder_allowlists,
            ));
            withheld.sort();
            withheld.dedup();
            withheld
        } else {
            Vec::new()
        };
        apply_pending_intents(
            &mut discovered,
            &mut files_to_hash,
            &pending_share_states,
            &pending_file_priorities,
        );

        let withheld = {
            let mut index = local_index.write().await;
            // Re-check cancellation after the lock-free known.met read above.
            // `remove_shared_folder` may have flipped our cancel flag (and
            // cleared the index for this folder) in that window; adding the
            // discovered set now would re-index a folder the user just
            // unshared. The cancel flag is set before the config/index are
            // mutated by removal, so this load closes the TOCTOU window.
            if cancel_flag.load(Ordering::Relaxed) {
                drop(index);
                info!("Hashing cancelled before indexing for {path}");
                remove_cancel_flag_if_current(&cancel_flags, &cancel_key, &cancel_flag).await;
                let _ = app.emit(
                    "file-hash-progress",
                    serde_json::json!({ "done": true, "current": 0, "total": 0, "file_name": "" }),
                );
                return;
            }
            index.add_files(discovered);
            not_offered_by_the_library(&index, withheld)
        };
        refresh_file_cache(&local_index, &file_cache).await;
        if let Err(error) = persist_shared_states(&network_tx, &withheld, false).await {
            warn!("Files outside the allowlist on {path} were not unshared in known.met: {error}");
        }

        let _ = app.emit(
            "shared-files-changed",
            serde_json::json!({
                "folder": path,
                "count": total_files,
                "phase": "discovered",
            }),
        );

        let total_to_hash = files_to_hash.len();
        let mut hashed_count: usize = 0;
        let mut last_cache_refresh = std::time::Instant::now();
        let mut hash_progress = HashProgressEmitter::new(&files_to_hash);
        let mut was_cancelled = false;

        // One read at a time per device, more only where that device reported
        // no seek penalty; see `sharing::disk`.
        let mut pipeline = HashLookahead::new(&files_to_hash, cancel_flag.clone());
        pipeline.log_plan("Hashing", total_to_hash);
        loop {
            let started = match pipeline.next_started() {
                NextHash::Ready(started) => started,
                // Every drive with work left is busy with a read we did not
                // start — a download verifying itself, most likely. Wait for
                // it rather than piling on, and never mistake it for the end
                // of the pass.
                NextHash::Busy => {
                    if cancel_flag.load(Ordering::Relaxed) {
                        was_cancelled = true;
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    continue;
                }
                NextHash::Done => break,
            };
            if cancel_flag.load(Ordering::Relaxed) {
                info!("Hashing cancelled for {path} at {hashed_count}/{total_to_hash}");
                was_cancelled = true;
                // This row is already claimed and running: it has to go back
                // through the drain like the rest of the window, or its claim
                // outlives the scan. The old loop checked cancellation before
                // claiming, so there was nothing here to hand back.
                pipeline.drain_started(started);
                break;
            }

            let file = &files_to_hash[started.index];
            let file_temp_id = file.id.clone();
            let hash_claim = started.claim;
            let mut hash_task = started.task;

            debug!(
                "Hashing file {}/{}: {}",
                hashed_count + 1,
                total_to_hash,
                file.name
            );

            hash_progress.emit(&app, hashed_count + 1, total_to_hash, &file.name);

            let hash_result =
                await_hash(&mut hash_task, &started.progress, &file.path, hash_claim).await;

            match hash_result {
                Ok(Ok(Ok((
                    ed2k_hash,
                    aich_hash,
                    part_hashes,
                    ember_file_hash,
                    hashed_size,
                    hashed_modified_at,
                )))) => {
                    debug!(
                        "Hash complete: {} -> {}",
                        file.name,
                        &ed2k_hash[..ed2k_hash.len().min(8)]
                    );
                    let mut updated_file = file.clone();
                    updated_file.id = ed2k_hash.clone();
                    updated_file.hash = ed2k_hash;
                    updated_file.aich_hash = aich_hash;
                    updated_file.ember_file_hash = ember_file_hash;
                    updated_file.size = hashed_size;
                    updated_file.modified_at = hashed_modified_at;
                    restore_known_hash_flags(&mut updated_file, &known_list);

                    let still_shared = {
                        let cfg = config.read().await;
                        file_in_shared_folders(&updated_file.path, &cfg.settings.shared_folders)
                    };
                    // Retain the handoff only after its completed index row
                    // is committed. A cancelled folder scan drops its pending
                    // row, and caching first would leave no later
                    // reconciliation path to drain these part hashes.
                    let fresh_handoff = still_shared
                        .then(|| fresh_part_hash_handoff(&updated_file.hash, part_hashes))
                        .flatten();
                    let finalized = {
                        let mut index = local_index.write().await;
                        if !cancel_flag.load(Ordering::Relaxed) && still_shared {
                            // Preserve share/priority changes made while this
                            // pending row was hashing. If it was removed by a
                            // concurrent unshare/cancel, do not resurrect it.
                            index
                                .finalize_pending_hash(&file_temp_id, updated_file.clone())
                                .is_some()
                        } else if still_shared {
                            // Cancelled. A re-hash row is already servable and
                            // keeps its place; only an unhashed row is dropped.
                            index.abandon_hash_placeholder(&file_temp_id);
                            false
                        } else {
                            index.remove_file_by_id(&file_temp_id);
                            false
                        }
                    };
                    cache_fresh_part_hash_handoff(&fresh_part_hashes, finalized, fresh_handoff)
                        .await;

                    if !cancel_flag.load(Ordering::Relaxed) && still_shared {
                        hashed_count += 1;
                    }
                    if !cancel_flag.load(Ordering::Relaxed)
                        && still_shared
                        && last_cache_refresh.elapsed() >= std::time::Duration::from_secs(5)
                    {
                        refresh_file_cache(&local_index, &file_cache).await;
                        let _ = app.emit(
                            "shared-files-changed",
                            serde_json::json!({ "phase": "hash-progress" }),
                        );
                        last_cache_refresh = std::time::Instant::now();
                    }
                    release_in_flight_hash(&file.path, hash_claim);
                }
                Ok(Ok(Err(e))) => {
                    let msg = e.to_string();
                    if msg.contains("cancelled") {
                        info!("Hashing cancelled mid-file for {path}");
                        was_cancelled = true;
                        let mut index = local_index.write().await;
                        index.abandon_hash_placeholder(&file_temp_id);
                        release_in_flight_hash(&file.path, hash_claim);
                        break;
                    }
                    warn!("Failed to hash {}: {e}", file.name);
                    let mut index = local_index.write().await;
                    index.abandon_hash_placeholder(&file_temp_id);
                    release_in_flight_hash(&file.path, hash_claim);
                }
                Ok(Err(e)) => {
                    tracing::error!("Hash task panicked for {}: {e}", file.name);
                    let mut index = local_index.write().await;
                    index.abandon_hash_placeholder(&file_temp_id);
                    release_in_flight_hash(&file.path, hash_claim);
                }
                Err(HashStalled) => {
                    // One stuck file must not end the scan. Cancelling the whole
                    // pass and dropping this folder's pending rows left every
                    // file after this one un-indexed, and it recurred on every
                    // retry because the queue is walked in a stable order.
                    // Leave the row pending and move on to the next file.
                    warn!(
                        "Hash of {} read nothing for {} min (file may be on cloud storage or locked); leaving pending for retry",
                        file.name,
                        HASH_STALL_TIMEOUT.as_secs() / 60
                    );
                    // Drain the abandoned blocking hash for its log line only,
                    // holding no scan lease. Dropping a JoinHandle does not stop
                    // `spawn_blocking`, and the read may be stuck in the kernel
                    // where the cancel flag cannot reach it — handing the
                    // coordination/scan guards to that wait would block every
                    // later reload and stall shutdown for the rest of the session.
                    let timed_out_name = file.name.clone();
                    let timed_out_path = file.path.clone();
                    // The read is still going; keep its drive spoken for until
                    // it really ends, or the look-ahead treats the device as
                    // free and stacks another read on top of it.
                    let orphan_device = crate::sharing::disk::note_external_read_for_key(
                        pipeline.device_key(started.device),
                    );
                    tokio::spawn(async move {
                        let _orphan_device = orphan_device;
                        let result = hash_task.await;
                        release_in_flight_hash(&timed_out_path, hash_claim);
                        if let Err(error) = result {
                            tracing::warn!(
                                "Timed-out hash task for {timed_out_name} failed while draining: {error}"
                            );
                        }
                    });
                    continue;
                }
            }
        }
        // Cancelling leaves the look-ahead window full of claimed, still-running
        // hashes; hand them off to drain rather than stranding their claims.
        pipeline.abandon();
        // A file another pass still held leaves this page unfinished, so the
        // resume cursor must not move past it; one that failed or stalled is
        // retried by the next walk of the page instead. See the reload loop.
        let page_complete = pipeline.skipped() == 0;

        {
            let mut index = local_index.write().await;
            if was_cancelled {
                // Scope the pending cleanup to THIS folder so a concurrent scan
                // of another folder keeps its in-progress entries (the global
                // `remove_pending_files` would drop them too).
                index.remove_pending_files_under(std::slice::from_ref(&canonical_str));
            }
            index.rebuild();
        }

        if !was_cancelled && page_complete {
            let mut cursor_update = std::collections::HashMap::new();
            cursor_update.insert(canonical_str.clone(), discovery_next_cursor);
            let app_state = app.state::<AppState>();
            if let Err(error) = persist_scan_cursors(&app_state, &cursor_update, false).await {
                warn!(
                    "Shared-folder page was indexed but its resume cursor was not saved: {error}"
                );
            }
        }
        refresh_file_cache(&local_index, &file_cache).await;

        if !was_cancelled {
            let all_files = {
                let index = local_index.read().await;
                index
                    .all_files()
                    .iter()
                    .filter(|f| {
                        crate::security::path_within_dir(&f.path, &canonical_str)
                            && !f.hash.is_empty()
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            };
            if !all_files.is_empty() {
                if let Err(e) =
                    network_tx.try_send(NetworkCommand::AnnounceFiles { files: all_files })
                {
                    warn!("Failed to queue AnnounceFiles: {e}");
                }
            }
        }

        reconcile_shared_files_best_effort(&network_tx).await;
        if !was_cancelled {
            // known.met now owns the state of everything hashed this pass —
            // sweep any pending intents that were handed off (or left stale
            // by an earlier build/crash) so they can't re-apply on a rehash.
            let app_state = app.state::<AppState>();
            prune_pending_intents_for_hashed(&app_state).await;
            // Only now, with every file that could not be served already
            // hashed, hand the optional repairs to the background. Cancelling
            // the scan skips this too: Stop means leave the disks alone.
            queue_hash_top_up(app.clone(), &needs_top_up).await;
        }
        remove_cancel_flag_if_current(&cancel_flags, &cancel_key, &cancel_flag).await;

        let from_known = total_files.saturating_sub(total_to_hash);
        if was_cancelled {
            info!("Hashing stopped for {path}: {hashed_count}/{total_to_hash} hashed before cancel, {from_known} from known.met");
        } else {
            info!("Background hashing complete: {hashed_count}/{total_to_hash} hashed, {from_known} from known.met ({path})");
        }

        let _ = app.emit(
            "file-hash-progress",
            serde_json::json!({
                "current": total_to_hash,
                "total": total_to_hash,
                "file_name": "",
                "done": true,
            }),
        );
        drop(scan_guard);
    });

    // Track the scan so shutdown can wait for it (and abort it after the grace
    // window) instead of flushing local_index / known.met while a discovery +
    // hash walk is still mutating them.
    state.register_background_scan(scan_handle).await;

    Ok(added)
}

/// Outcome of one trip through the folder picker.
///
/// Split rather than a flat "these are shared now" list because the OS dialog
/// shows a plain folder tree with no way to mark what is already shared, so a
/// selection that changed nothing is indistinguishable from one that worked
/// unless the result says so.
#[derive(Debug, Default, serde::Serialize)]
pub struct SharedFolderPick {
    /// Folders this selection newly shared. A background scan is running for
    /// each.
    pub added: Vec<String>,
    /// Folders the user picked that were already in the shared list.
    pub already_shared: Vec<String>,
    /// Files added to a folder that was already shared. A new folder's files
    /// are not listed here; they show up when that folder's scan finishes.
    pub files_shared: Vec<String>,
    /// Errors for the part of a selection that did not land when some of it
    /// did. A selection that shares nothing fails outright instead.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub failed: Vec<String>,
}

/// Open a trusted native directory picker and add the selected folder.
///
/// Kept as a fallback for paths the in-app Explorer cannot reach (some UNC
/// locations, unusual devices). The Library's primary add-folder UI is
/// [`crate::commands::share_browser`], which lists folders and shares by
/// session token rather than by a path the renderer invented.
#[tauri::command]
pub async fn pick_shared_folder(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    state: tauri::State<'_, AppState>,
    title: Option<String>,
) -> Result<SharedFolderPick, String> {
    let dialog_title = super::picker_title(title, "Choose folders to share");
    if window.label() != "main" {
        return Err(coded(
            "sharing_picker_wrong_window",
            "Shared folders can only be selected from the main window",
        ));
    }
    let picker_app = app.clone();
    // Plural picker: adding several folders used to mean reopening this dialog
    // once per folder, which is the same papercut dropping them was supposed to
    // avoid. Every returned path is authorized the same way a single one was.
    let selected = tokio::task::spawn_blocking(move || {
        picker_app
            .dialog()
            .file()
            .set_title(dialog_title)
            .blocking_pick_folders()
            .map(|folders| {
                folders
                    .into_iter()
                    .map(|folder| {
                        folder.into_path().map_err(|error| {
                            coded_ctx(
                                "sharing_invalid_picker_path",
                                "Invalid selected folder",
                                error,
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()
            })
            .transpose()
    })
    .await
    .map_err(|error| coded_ctx("sharing_picker_task_failed", "Folder picker failed", error))??;

    let Some(paths) = selected else {
        return Ok(SharedFolderPick::default());
    };
    // Choosing a folder here means the whole folder, exactly as it does in the
    // in-app browser: drop any allowlist limiting it, and offer every file
    // under it that was taken off the network one at a time.
    let mut result = SharedFolderPick::default();
    for path in paths {
        let display_path = path.to_string_lossy().into_owned();
        // One bad folder must not discard the rest of the selection.
        match add_shared_folder_limited(app.clone(), state.clone(), display_path.clone(), None)
            .await
        {
            Ok(added) if added.outcome == FolderAddOutcome::Added => {
                result.added.push(display_path)
            }
            Ok(added) => {
                // The stored form, which is what the allowlist and the index
                // rows are keyed by; the picked spelling may be a mapped drive.
                let folder = added.folder;
                let before = FolderListsBefore::take(&state).await;
                if let Err(error) = clear_allowlists_under(&state, &folder).await {
                    tracing::warn!("Could not lift the file limit on {display_path}: {error}");
                    result.failed.push(error);
                }
                match share_all_in_folder(app.clone(), state.inner(), &folder, &before).await {
                    Ok(files) if files.is_empty() => result.already_shared.push(display_path),
                    Ok(files) => result.files_shared.extend(files),
                    Err(error) => {
                        tracing::warn!("Could not offer the rest of {display_path}: {error}");
                        result.failed.push(error);
                    }
                }
            }
            Err(error) => {
                tracing::warn!("Selected folder {display_path} was not shared: {error}");
                result.failed.push(error);
            }
        }
    }
    finish_pick(result)
}

/// Picking folders and being told nothing at all is worse than the single-add
/// version this replaced, which propagated its error to the UI. Fail only when
/// *nothing* landed at all — neither a fresh add nor an already-shared one,
/// which the caller reports on its own terms. On a partial success the
/// folders that worked are visible in the library, and failing the whole call
/// would hide them, so the errors travel alongside instead.
pub(crate) fn finish_pick(mut result: SharedFolderPick) -> Result<SharedFolderPick, String> {
    if result.added.is_empty()
        && result.already_shared.is_empty()
        && result.files_shared.is_empty()
        && !result.failed.is_empty()
    {
        return Err(result.failed.swap_remove(0));
    }
    Ok(result)
}

/// Paths a single drop may carry before it is refused outright. Generous for
/// any deliberate gesture; a guard against a stray select-all, whose only cost
/// otherwise is thousands of blocking `is_dir` calls for folders nobody meant
/// to share.
const MAX_DROPPED_PATHS: usize = 512;

/// Folders a drop shares without asking. Beyond this the whole batch is put to
/// the user, because dropping more folders than you meant to is the mistake the
/// gesture makes easy and the number itself is the warning.
const DROP_CONFIRM_FOLDER_COUNT: usize = 8;

/// Report the outcome of a drag-drop share to the UI.
///
/// Both halves matter. Silence on success leaves the user guessing whether the
/// drop registered; silence on failure is worse, because the gesture is the
/// whole feature and a drop that shares nothing would look exactly like one the
/// app never received. Unlike the picker there is no return value to carry
/// either — the drop arrives on a window event, with no call to fail.
fn emit_drop_result(app: &tauri::AppHandle, added: usize, failed: usize) {
    if added > 0 {
        let _ = app.emit(
            "shared-folders-added",
            serde_json::json!({ "count": added }),
        );
    }
    if failed > 0 {
        let _ = app.emit(
            "shared-folders-add-failed",
            serde_json::json!({ "count": failed }),
        );
    }
}

/// Share everything an OS drag-drop delivered to the native window.
///
/// Called from the window event handler, never over IPC. That distinction is
/// the whole point: `add_shared_folder` is deliberately not an invokable
/// command, so the renderer cannot name a folder to share, and the folder
/// picker used to be the only way to authorize one. A drop reported by the OS
/// to the native window has the same provenance — a compromised webview cannot
/// synthesize one — so it can be honoured directly instead of being reduced to
/// a prompt that reopens the picker, which is what it used to do.
///
/// Dropped directories are shared immediately. Dropped files cannot be: sharing
/// here is folder-granular, so the only thing a file can mean is "share the
/// folder holding it", which is a much larger action than the gesture implies
/// and is therefore put to the user first.
pub async fn share_dropped_paths(app: tauri::AppHandle, paths: Vec<std::path::PathBuf>) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    if paths.is_empty() {
        return;
    }
    // A drop is one gesture but its payload is whatever the file manager had
    // selected, so it is attacker-free but not size-free: every path below costs
    // a blocking `is_dir`, and a careless select-all can be tens of thousands.
    // Refuse the whole thing rather than silently working on a prefix.
    if paths.len() > MAX_DROPPED_PATHS {
        tracing::warn!(
            "Ignoring a drop of {} paths; the limit is {MAX_DROPPED_PATHS}",
            paths.len()
        );
        let _ = app.emit(
            "shared-folder-drop-rejected",
            serde_json::json!({ "reason": "too_many", "limit": MAX_DROPPED_PATHS }),
        );
        return;
    }

    // Everything that would make sharing your whole profile a single careless
    // drag. `add_shared_folder` already refuses a filesystem root, the sensitive
    // system names, and Ember's own data directory, but a home directory is
    // none of those: `C:\Users\you` has an ordinary name and a parent, and
    // sharing it hands out Documents, Desktop and Pictures in one go.
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(std::path::PathBuf::from)
        .and_then(|h| h.canonicalize().ok());

    // Classify off the async runtime: `is_dir` on a disconnected network or
    // removable path blocks for the OS timeout, and this runs on a user gesture.
    let sorted = tokio::task::spawn_blocking(move || {
        let mut folders: Vec<String> = Vec::new();
        let mut broad: Vec<String> = Vec::new();
        let mut parents: Vec<String> = Vec::new();
        let mut files: Vec<String> = Vec::new();
        for path in paths {
            if path.is_dir() {
                // Compare canonically, or a drop of `C:\Users\you\..\you` walks
                // straight past the check it is here to fail.
                let covers_home = path
                    .canonicalize()
                    .ok()
                    .zip(home.as_ref())
                    .is_some_and(|(candidate, home)| home.starts_with(&candidate));
                if covers_home {
                    broad.push(path.to_string_lossy().into_owned());
                } else {
                    folders.push(path.to_string_lossy().into_owned());
                }
            } else if path.is_file() {
                files.push(path.to_string_lossy().into_owned());
                if let Some(parent) = path.parent() {
                    parents.push(parent.to_string_lossy().into_owned());
                }
            }
        }
        for list in [&mut folders, &mut broad, &mut parents, &mut files] {
            list.sort();
            list.dedup();
        }
        (folders, broad, parents, files)
    })
    .await;
    let Ok((folders, broad, parents, files)) = sorted else {
        return;
    };

    if folders.is_empty() && broad.is_empty() && parents.is_empty() {
        // Every path vanished between the drop and the stat, or none of them was
        // a file or a directory. Saying nothing is the one remaining way a drop
        // can look exactly like one the app never received.
        let _ = app.emit(
            "shared-folder-drop-rejected",
            serde_json::json!({ "reason": "nothing" }),
        );
        return;
    }

    // One prompt per drop, so decide up front what it is about. A large batch is
    // questioned as a whole: sharing eight folders and asking about the ninth
    // would be a strange way to warn someone that they dropped more than they
    // meant to.
    let bulk = folders.len() + broad.len() + parents.len() > DROP_CONFIRM_FOLDER_COUNT;
    // Reason priority, not category priority: a batch that happens to include a
    // folder covering your home directory is precisely the drop that must not be
    // described merely as "9 folders". The count is the lesser of the two
    // warnings, so it never gets to hide the other.
    let reason = if !broad.is_empty() {
        "broad"
    } else if bulk {
        "many"
    } else {
        "files"
    };
    let (share_now, confirm) = if bulk {
        let mut all = folders;
        all.extend(broad);
        all.extend(parents);
        all.sort();
        all.dedup();
        (Vec::new(), all)
    } else {
        let mut confirm = broad;
        confirm.extend(parents);
        confirm.sort();
        confirm.dedup();
        (folders, confirm)
    };

    let mut added = 0usize;
    let mut failed = 0usize;
    for folder in outermost_folders(share_now) {
        match add_shared_folder(app.clone(), state.clone(), folder.clone()).await {
            Ok(add) if add.outcome == FolderAddOutcome::AlreadyShared => {
                // A re-drop of an already-shared folder still counts as success
                // here: the drop confirmation only reports how many landed, and
                // "already shared" is not a failure to tell the user about.
                match share_partial_folder_whole(&app, &state, &add.folder).await {
                    Ok(()) => added += 1,
                    Err(error) => {
                        failed += 1;
                        tracing::warn!("Dropped folder {folder} was not shared whole: {error}");
                    }
                }
            }
            Ok(_) => added += 1,
            Err(error) => {
                failed += 1;
                tracing::warn!("Dropped folder {folder} was not shared: {error}");
            }
        }
    }
    emit_drop_result(&app, added, failed);

    if confirm.is_empty() {
        return;
    }
    queue_drop_confirmation(&app, &state, confirm, files, reason).await;
}

/// What handing over an already-shared folder again means, as in the folder
/// picker: the whole folder. One shared in part loses its allowlist and has
/// every file under it offered; one shared whole is left as it is.
async fn share_partial_folder_whole(
    app: &tauri::AppHandle,
    state: &AppState,
    folder: &str,
) -> Result<(), String> {
    let partial = state
        .config
        .read()
        .await
        .settings
        .pending_folder_allowlists
        .keys()
        .any(|key| paths_equal_ignore_case(key, folder));
    if !partial {
        return Ok(());
    }
    let before = FolderListsBefore::take(state).await;
    clear_allowlists_under(state, folder).await?;
    share_all_in_folder(app.clone(), state, folder, &before).await?;
    Ok(())
}

/// Park folders a drop cannot honour outright and ask the user about them.
///
/// The paths stay here while the question is outstanding; the frontend gets a
/// token and display names only, and answers with the token. That is what keeps
/// a dropped path authorization: it was authorization because the OS handed it
/// to the native window, and a round trip through the renderer would make it
/// something the renderer chose instead.
async fn queue_drop_confirmation(
    app: &tauri::AppHandle,
    state: &tauri::State<'_, AppState>,
    folders: Vec<String>,
    files: Vec<String>,
    reason: &'static str,
) {
    let token = crate::commands::js_safe_token();
    let names: Vec<String> = folders
        .iter()
        .map(|p| {
            std::path::Path::new(p)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| p.clone())
        })
        .collect();
    let parents: Vec<String> = folders
        .iter()
        .filter(|folder| {
            files.iter().any(|file| {
                std::path::Path::new(file)
                    .parent()
                    .is_some_and(|parent| paths_equal_ignore_case(&parent.to_string_lossy(), folder))
            })
        })
        .cloned()
        .collect();
    let kept_files = if reason == "files" { files } else { Vec::new() };
    {
        let mut pending = state.pending_folder_drop.lock().await;
        // The reason rides on the event only: it decides the wording, and the
        // answer is the same set of folders whatever prompted the question.
        *pending = Some(crate::app_state::PendingFolderDrop {
            token,
            folders,
            files: kept_files,
            parents,
        });
    }
    let _ = app.emit(
        "shared-folder-drop-pending",
        serde_json::json!({ "token": token, "folders": names, "reason": reason }),
    );
}

/// Approve the folders a dropped file asked about, identified by the token the
/// backend issued. Nothing here trusts a path from the renderer: a stale or
/// invented token simply finds no pending drop.
///
/// The renderer's answer is enough only for what the OS handed over. Sharing
/// the whole folder a dropped file sits in, or a whole drive, is put to the
/// user again in a native dialog first, since the renderer could otherwise
/// pick "the whole folder" on the user's behalf.
#[tauri::command]
pub async fn confirm_dropped_folders(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    token: u64,
    only_dropped_files: Option<bool>,
) -> Result<usize, String> {
    let pending = {
        let mut pending = state.pending_folder_drop.lock().await;
        match pending.as_ref() {
            // Taken, not peeked: one answer per prompt, so a replayed
            // confirmation cannot re-share after the user removed the folder.
            Some(p) if p.token == token => pending.take(),
            _ => return Ok(0),
        }
    };
    let Some(pending) = pending else {
        return Ok(0);
    };
    let folders = outermost_folders(pending.folders);
    let files = pending.files;
    let parents = pending.parents;
    let only_files = only_dropped_files == Some(true) && !files.is_empty();
    let plan: Vec<(String, Option<Vec<String>>, bool)> = folders
        .into_iter()
        .map(|folder| {
            let only = if only_files {
                let in_folder: Vec<String> = files
                    .iter()
                    .filter(|file| crate::security::path_within_dir(file, &folder))
                    .cloned()
                    .collect();
                if in_folder.is_empty() {
                    tracing::warn!(
                        "No dropped files matched folder {folder}; sharing the whole folder"
                    );
                    None
                } else {
                    Some(in_folder)
                }
            } else {
                None
            };
            let handed_over = !parents
                .iter()
                .any(|parent| paths_equal_ignore_case(parent, &folder));
            (folder, only, handed_over)
        })
        .collect();
    // Spelled the way the add stores a folder, which is what the approval
    // below is matched against and the shared list is compared in.
    let plan = tokio::task::spawn_blocking(move || {
        plan.into_iter()
            .map(|(folder, only, handed_over)| {
                let stored = std::path::Path::new(&folder)
                    .canonicalize()
                    .map(|canonical| crate::commands::share_browser::display_fs_path(&canonical))
                    .unwrap_or(folder);
                (stored, only, handed_over)
            })
            .collect::<Vec<_>>()
    })
    .await
    .map_err(|e| coded_ctx("sharing_task_failed", "Task failed", e))?;
    let shared: Vec<std::path::PathBuf> = state
        .config
        .read()
        .await
        .settings
        .shared_folders
        .iter()
        .map(std::path::PathBuf::from)
        .collect();
    let to_confirm = drop_roots_to_confirm(
        plan.iter()
            .map(|(folder, only, handed_over)| (folder.as_str(), only.is_none(), *handed_over)),
        &shared,
    );
    if to_confirm.len() > crate::commands::share_browser::MAX_CONFIRM_ROOTS {
        return Err(crate::commands::share_browser::too_many_to_confirm());
    }
    if !to_confirm.is_empty()
        && !crate::commands::share_browser::confirm_share_roots(
            &app,
            &to_confirm,
            crate::commands::share_browser::ShareOrigin::Drop,
        )
        .await
    {
        return Err(coded(
            "sharing_share_not_confirmed",
            "Nothing was shared because it was not confirmed",
        ));
    }
    // Every folder shared whole is now either handed over by the OS or
    // confirmed above. One limited to the dropped files offers only what the OS
    // handed over, wherever its allowlist ends up, so it keeps native standing.
    let approved: Vec<String> = plan.iter().map(|(folder, ..)| folder.clone()).collect();
    let mut added = 0usize;
    let mut failed = 0usize;
    for (folder, only, handed_over) in plan {
        let approval = if only.is_some() {
            ShareApproval::Native
        } else {
            ShareApproval::Confirmed(&approved)
        };
        let before = FolderListsBefore::take(&state).await;
        match add_shared_folder_approved(app.clone(), state.clone(), folder.clone(), only, approval)
            .await
        {
            // See the folder-drop path: an already-shared folder is a success.
            Ok(add) => {
                if add.outcome == FolderAddOutcome::AlreadyShared && add.allowlist_grew {
                    // Discovery skipped them while they were off the allowlist.
                    admit_known_files(&state, &before, &add.files).await;
                    queue_rescan(&app, add.files.iter().map(std::path::PathBuf::from).collect());
                }
                if add.outcome == FolderAddOutcome::AlreadyShared && !add.files.is_empty() {
                    // The allowlist only covers files the next scan finds;
                    // ones already indexed and unshared need offering now.
                    if let Err(error) = batch_share(app.clone(), state.clone(), add.files).await {
                        failed += 1;
                        tracing::warn!(
                            "Dropped files in already-shared folder {folder} were not shared: {error}"
                        );
                        continue;
                    }
                } else if add.outcome == FolderAddOutcome::AlreadyShared
                    && handed_over
                    && !crate::sharing::is_volume_root(std::path::Path::new(&add.folder))
                {
                    // A folder the OS did not hand over was only chosen in the
                    // renderer, and widening a partial share, or one of a
                    // whole drive, needs a native confirmation this path does
                    // not ask for.
                    if let Err(error) = share_partial_folder_whole(&app, &state, &add.folder).await {
                        failed += 1;
                        tracing::warn!("Dropped folder {folder} was not shared whole: {error}");
                        continue;
                    }
                }
                added += 1;
            }
            Err(error) => {
                failed += 1;
                tracing::warn!("Dropped file's folder {folder} was not shared: {error}");
            }
        }
    }
    emit_drop_result(&app, added, failed);
    Ok(added)
}

/// The folders of a confirmed drop, as `(folder, shared whole, handed over by
/// the OS)`, that still need a native confirmation: any shared whole that the
/// OS did not hand over, and any whole drive, which the add does not ask about
/// itself under a [`ShareApproval::Confirmed`]. One already shared, or
/// overlapping a share, changes nothing or is refused, so it is not asked about.
fn drop_roots_to_confirm<'a>(
    plan: impl Iterator<Item = (&'a str, bool, bool)>,
    shared: &[std::path::PathBuf],
) -> Vec<crate::commands::share_browser::NewShareRoot> {
    use crate::commands::share_browser::{overlaps_share, NewShareRoot, ShareScope};
    let mut roots: Vec<NewShareRoot> = plan
        .filter(|(folder, whole, _)| *whole && !overlaps_share(folder, shared))
        .filter_map(|(folder, _, handed_over)| {
            let root = NewShareRoot::new(folder, ShareScope::Whole);
            (!handed_over || root.whole_drive).then_some(root)
        })
        .collect();
    roots.sort_by_key(|root| !root.whole_drive);
    roots
}

#[cfg(test)]
mod drop_confirmation_tests {
    use super::drop_roots_to_confirm;
    use std::path::PathBuf;

    #[test]
    fn only_a_parent_shared_whole_or_a_drive_needs_confirming() {
        let (parent, dropped, limited, shared, inside, drive) = if cfg!(windows) {
            (
                r"C:\Photos",
                r"C:\Music",
                r"C:\Docs",
                r"\\?\C:\Shared",
                r"C:\Shared\Sub",
                Some(r"E:\"),
            )
        } else {
            ("/photos", "/music", "/docs", "/shared", "/shared/sub", None)
        };
        let mut plan = vec![
            (parent, true, false),
            (dropped, true, true),
            (limited, false, false),
            (inside, true, false),
        ];
        plan.extend(drive.map(|drive| (drive, true, true)));
        let roots = drop_roots_to_confirm(plan.into_iter(), &[PathBuf::from(shared)]);
        let paths: Vec<&str> = roots.iter().map(|root| root.path.as_str()).collect();
        let mut expected: Vec<&str> = drive.into_iter().collect();
        expected.push(parent);
        assert_eq!(
            paths, expected,
            "a dropped folder, one limited to dropped files and one inside a share are not asked about"
        );
    }
}

/// `folders` without any that sit inside another of them, or repeat one.
/// Adding the outer folder already covers the inner one's files, and adding
/// both is refused as an overlap — which a drop of files from `C:\A` and
/// `C:\A\B` reported as a failure even though everything was shared.
fn outermost_folders(folders: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(folders.len());
    for folder in &folders {
        let nested = folders.iter().any(|other| {
            !paths_equal_ignore_case(other, folder)
                && crate::security::path_within_dir(folder, other)
        });
        if !nested && !out.iter().any(|kept| paths_equal_ignore_case(kept, folder)) {
            out.push(folder.clone());
        }
    }
    out
}

/// Discard a pending dropped-file prompt the user declined, so a later
/// confirmation cannot resurrect it.
#[tauri::command]
pub async fn dismiss_dropped_folders(
    state: tauri::State<'_, AppState>,
    token: u64,
) -> Result<(), String> {
    let mut pending = state.pending_folder_drop.lock().await;
    if pending.as_ref().is_some_and(|p| p.token == token) {
        *pending = None;
    }
    Ok(())
}

#[tauri::command]
pub async fn remove_shared_folder(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<(), String> {
    if path.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "sharing_folder_path_too_long",
            format!("Folder path exceeds {MAX_PATH_LEN} bytes"),
            MAX_PATH_LEN,
        ));
    }
    // Canonicalize off the async runtime (blocking I/O on slow/network paths).
    // An unavailable USB/network root cannot canonicalize, but it still must
    // be removable. In that case only accept an exact normalized entry already
    // present in configuration; never fall back to an arbitrary raw path.
    let resolved_path = tokio::task::spawn_blocking({
        let path = path.clone();
        move || -> Result<String, String> {
            std::path::Path::new(&path)
                .canonicalize()
                .map(|p| p.to_string_lossy().to_string())
                .map_err(|e| {
                    coded_ctx(
                        "sharing_invalid_folder_path",
                        format!("Invalid folder path '{path}'"),
                        e,
                    )
                })
        }
    })
    .await
    .map_err(|e| coded_ctx("sharing_task_failed", "Task failed", e))?;
    // Everything below removes rows and state at or under this folder, and a
    // shared drive root covers its whole drive, so it has to be a folder the
    // user actually shared: a request naming an unshared drive must not wipe
    // that drive's rows.
    let canonical_path = {
        let config = state.config.read().await;
        match stored_shared_folder(
            &config.settings.shared_folders,
            resolved_path.as_deref().ok(),
            &path,
        ) {
            Some(stored) => stored,
            None => {
                return Err(match resolved_path {
                    Err(canonical_error) => canonical_error,
                    Ok(_) => coded_ctx(
                        "sharing_folder_not_shared",
                        "Folder is not a shared folder",
                        &path,
                    ),
                })
            }
        }
    };
    // `add_shared_folder` stores the *canonical* form in
    // `shared_folders` and `upload_shared_folders`; the cancel-flag
    // map is also keyed by canonical paths. Comparing against the
    // raw `path` argument here would let an equivalent-but-not-equal
    // representation (extended `\\?\` form, trailing separator,
    // case difference not handled by `paths_equal_ignore_case`) leak:
    // we'd strip the index entries (which canonicalize internally)
    // but leave `shared_folders` populated, re-sharing on next scan.
    // Use `canonical_path` for every comparison.
    {
        let flags = state.hash_cancel_flags.read().await;
        // Cancel only generations whose scan roots can write under the folder
        // being removed. Broad startup/reload generations are safely ordered by
        // `scan_coordination` and may not contain a recently added folder, so
        // leave them (and unrelated per-folder scans) running. Do not remove
        // entries here: each generation owns its flag and generation-aware
        // cleanup removes it only when the Arc still matches the map's current
        // value.
        for (scan_key, flag) in flags.iter() {
            if scan_can_write_under(scan_key, &canonical_path) {
                flag.store(true, Ordering::Relaxed);
            }
        }
    }
    // Persist the removal to disk before committing it in-memory or to the live
    // upload list, so a failed write can't drop a folder that's still saved.
    let settings_save_guard = state.settings_save_lock.lock().await;
    let save_data = {
        let config = state.config.read().await;
        let mut new_settings = config.settings.clone();
        new_settings
            .shared_folders
            .retain(|f| !paths_equal_ignore_case(f, &canonical_path));
        new_settings
            .folder_priorities
            .retain(|folder, _| !paths_equal_ignore_case(folder, &canonical_path));
        new_settings
            .pending_share_states
            .retain(|path, _| !crate::security::path_within_dir(path, &canonical_path));
        new_settings
            .pending_file_priorities
            .retain(|path, _| !crate::security::path_within_dir(path, &canonical_path));
        new_settings
            .pending_folder_allowlists
            .retain(|folder, _| !crate::security::path_within_dir(folder, &canonical_path));
        new_settings
            .withheld_folder_files
            .retain(|folder, _| !crate::security::path_within_dir(folder, &canonical_path));
        new_settings
            .shared_folder_scan_cursors
            .retain(|folder, _| !paths_equal_ignore_case(folder, &canonical_path));
        new_settings.settings_revision = config.settings.settings_revision.saturating_add(1);
        config
            .prepare_save_settings(&new_settings)
            .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?
    };
    let roots = {
        let config = state.config.read().await;
        let mut roots: Vec<String> = config
            .settings
            .shared_folders
            .iter()
            .filter(|root| !paths_equal_ignore_case(root, &canonical_path))
            .cloned()
            .collect();
        if !config.settings.download_folder.is_empty() {
            roots.push(config.settings.download_folder.clone());
        }
        roots
    };
    let registry = state.approved_roots.clone();
    let (data, tmp, final_path) = save_data;
    tokio::task::spawn_blocking(move || {
        super::settings::persist_with_root_transaction(registry, &roots, &[], &[], || {
            crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
        })
    })
    .await
    .map_err(|e| coded_ctx("sharing_config_transaction_error", "Config save error", e))?
    .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?;
    {
        let mut config = state.config.write().await;
        config
            .settings
            .shared_folders
            .retain(|f| !paths_equal_ignore_case(f, &canonical_path));
        config
            .settings
            .folder_priorities
            .retain(|folder, _| !paths_equal_ignore_case(folder, &canonical_path));
        config
            .settings
            .pending_share_states
            .retain(|path, _| !crate::security::path_within_dir(path, &canonical_path));
        config
            .settings
            .pending_file_priorities
            .retain(|path, _| !crate::security::path_within_dir(path, &canonical_path));
        config
            .settings
            .pending_folder_allowlists
            .retain(|folder, _| !crate::security::path_within_dir(folder, &canonical_path));
        config
            .settings
            .withheld_folder_files
            .retain(|folder, _| !crate::security::path_within_dir(folder, &canonical_path));
        config
            .settings
            .shared_folder_scan_cursors
            .retain(|folder, _| !paths_equal_ignore_case(folder, &canonical_path));
        config.settings.settings_revision = config.settings.settings_revision.saturating_add(1);
    }
    drop(settings_save_guard);
    {
        let mut live = state.upload_shared_folders.write().await;
        live.retain(|f| !paths_equal_ignore_case(f, &canonical_path));
    }

    // Revocation above is intentionally ahead of this wait: a long-running
    // startup/reload scan must not leave the folder uploadable or media-
    // accessible while removal waits for its final index cleanup. Once the
    // existing generation yields, remove any rows it raced to add.
    let scan_coordination_guard = state.scan_coordination.lock().await;
    let (removed_hashes, unpublish) = {
        let mut index = state.local_index.write().await;
        let hashes = fresh_part_hashes_exclusively_under_roots(
            index.all_files(),
            std::slice::from_ref(&canonical_path),
        );
        let dropped: Vec<String> = index
            .all_files()
            .iter()
            .filter(|file| crate::security::path_within_dir(&file.path, &canonical_path))
            .map(|file| file.hash.clone())
            .collect();
        index.remove_files_by_path_prefix(&canonical_path);
        let unpublish = hashes_no_longer_offered(&index, &dropped);
        (hashes, unpublish)
    };
    discard_fresh_part_hashes(&state.fresh_part_hashes, &removed_hashes).await;
    refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
    drop(scan_coordination_guard);
    unpublish_ember_files(&state.network_tx, unpublish).await;

    // Stop watching the removed folder.
    if let Some(watcher) = state.shared_folder_watcher.as_ref() {
        let folders = state.config.read().await.settings.shared_folders.clone();
        watcher.sync_paths(&folders);
    }
    {
        let config = state.config.read().await;
        sync_asset_protocol_scope(&app, &config);
    }

    reconcile_shared_files_best_effort(&state.network_tx).await;
    let _ = app.emit(
        "shared-files-changed",
        serde_json::json!({ "folder": path, "removed": true }),
    );

    Ok(())
}

#[tauri::command]
pub async fn get_shared_files(state: tauri::State<'_, AppState>) -> Result<Vec<FileInfo>, String> {
    let cached = state.cached_shared_files.read().await;
    Ok(cached.clone())
}

/// [`get_shared_files`] for a caller that already holds a copy.
#[derive(serde::Serialize)]
pub struct SharedFilesSnapshot {
    /// Changes whenever any row's serialized form does.
    pub etag: String,
    /// `None` when the library still matches the caller's `etag`.
    pub files: Option<Vec<FileInfo>>,
}

/// Hashing the cached rows costs a fraction of cloning, serializing and
/// shipping them, so a Library refresh with nothing new skips all three.
#[tauri::command]
pub async fn get_shared_files_if_changed(
    state: tauri::State<'_, AppState>,
    etag: Option<String>,
) -> Result<SharedFilesSnapshot, String> {
    let cached = state.cached_shared_files.read().await;
    let current = format!(
        "{:016x}",
        crate::sharing::manager::serde_fingerprint_rows(cached.iter())
    );
    let files = (etag.as_deref() != Some(current.as_str())).then(|| cached.clone());
    Ok(SharedFilesSnapshot {
        etag: current,
        files,
    })
}

/// Count and total byte size of files the user is *actively sharing*
/// (the `shared` flag is set). Distinct from the total number of files
/// indexed in the library (which includes unshared files). Returns a
/// compact summary so the always-mounted status bar can show
/// "Files Shared N (size)" without shipping the whole `Vec<FileInfo>`
/// over IPC on every refresh.
#[derive(serde::Serialize)]
pub struct SharedFileStats {
    pub count: usize,
    pub total_bytes: u64,
}

#[tauri::command]
pub async fn get_shared_file_count(
    state: tauri::State<'_, AppState>,
) -> Result<SharedFileStats, String> {
    let cached = state.cached_shared_files.read().await;
    let mut count = 0usize;
    let mut total_bytes = 0u64;
    for f in cached.iter().filter(|f| f.shared) {
        count += 1;
        total_bytes = total_bytes.saturating_add(f.size);
    }
    Ok(SharedFileStats { count, total_bytes })
}

/// Upper bound on hashes per [`library_has_hashes`] call. A friend browse
/// shows at most 1,000 rows; this only bounds a runaway caller.
const MAX_LIBRARY_HASH_CHECK: usize = 5_000;

/// Which of `hashes` (eD2K MD4 hex, any case) are in the library, shared or
/// not, returned lowercased. Lets a caller mark files the user already has
/// without shipping the whole `Vec<FileInfo>` over IPC.
#[tauri::command]
pub async fn library_has_hashes(
    state: tauri::State<'_, AppState>,
    hashes: Vec<String>,
) -> Result<Vec<String>, String> {
    if hashes.len() > MAX_LIBRARY_HASH_CHECK {
        return Err(coded_ctx(
            "sharing_batch_too_large",
            format!("Too many hashes in one batch (max {MAX_LIBRARY_HASH_CHECK})"),
            MAX_LIBRARY_HASH_CHECK,
        ));
    }
    let cached = state.cached_shared_files.read().await;
    Ok(hashes_in_library(
        &hashes,
        cached.iter().map(|f| f.hash.as_str()),
    ))
}

fn hashes_in_library<'a>(
    hashes: &[String],
    library_hashes: impl IntoIterator<Item = &'a str>,
) -> Vec<String> {
    // Only a 32-char MD4 hex can match a library row, so anything else is
    // dropped before it is copied.
    let mut wanted: HashSet<String> = hashes
        .iter()
        .filter(|h| h.len() == 32)
        .map(|h| h.to_ascii_lowercase())
        .collect();
    let mut found = Vec::new();
    for hash in library_hashes {
        if wanted.is_empty() {
            break;
        }
        // Still-hashing rows carry an empty hash.
        if hash.is_empty() {
            continue;
        }
        let hit = if hash.bytes().any(|b| b.is_ascii_uppercase()) {
            wanted.take(hash.to_ascii_lowercase().as_str())
        } else {
            wanted.take(hash)
        };
        if let Some(h) = hit {
            found.push(h);
        }
    }
    found
}

#[tauri::command]
pub async fn get_shared_folders(state: tauri::State<'_, AppState>) -> Result<Vec<String>, String> {
    let config = state.config.read().await;
    Ok(config.settings.shared_folders.clone())
}

/// Shared folders that are there on disk but not approved, so nothing in them
/// can be uploaded until the user re-approves them.
///
/// An offline folder is not one of them: it keeps whatever approval it had and
/// comes back with its drive, and re-approving it could not capture anything.
#[tauri::command]
pub async fn get_unapproved_shared_folders(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let folders = state.config.read().await.settings.shared_folders.clone();
    let Ok(registry) = crate::security::filesystem::approved_roots() else {
        return Ok(Vec::new());
    };
    tokio::task::spawn_blocking(move || {
        folders
            .into_iter()
            .filter(|folder| {
                let path = std::path::Path::new(folder);
                std::fs::symlink_metadata(path).is_ok() && registry.verify_root(path).is_err()
            })
            .collect()
    })
    .await
    .map_err(|error| coded_ctx("sharing_task_failed", "Task failed", error))
}

/// Re-approve a shared folder Ember stopped recognising, once the user has
/// confirmed it in a native dialog. Returns whether the folder is approved
/// afterwards.
///
/// Re-approval trusts whatever object now sits at the path, which is right
/// after a drive was reconnected and exactly wrong after something else was
/// put there, so the renderer may ask but only the user can answer: the dialog
/// is drawn by the OS, where the webview cannot reach it.
#[tauri::command]
pub async fn reapprove_shared_folder(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<bool, String> {
    let is_shared = |settings: &crate::types::AppSettings| settings.shared_folders.contains(&path);
    if !is_shared(&state.config.read().await.settings) {
        return Err(coded("sharing_folder_not_shared", "Folder is not a shared folder"));
    }
    let registry = crate::security::filesystem::approved_roots()
        .map_err(|error| coded_ctx("sharing_reapprove_failed", "Could not re-approve the folder", error))?;

    let prompt = format!(
        "Ember no longer recognises the shared folder at:\n\n{}\n\nRe-approve it only if you reconnected its drive or moved the folder yourself. If something else was put at this path, re-approving shares whatever is there now.",
        crate::commands::settings::elide_for_dialog(&path)
    );
    let dialog_app = app.clone();
    let dialog_registry = registry.clone();
    let folder = path.clone();
    // `None`: nothing to authorize, because the folder is approved already.
    let answer = tokio::task::spawn_blocking(move || {
        let target = std::path::Path::new(&folder);
        if std::fs::symlink_metadata(target).is_err() {
            return Err(coded("sharing_folder_not_exist", "Folder does not exist"));
        }
        if dialog_registry.verify_root(target).is_ok() {
            return Ok(None);
        }
        Ok(Some(
            dialog_app
                .dialog()
                .message(prompt)
                .title("Re-approve shared folder?")
                .kind(tauri_plugin_dialog::MessageDialogKind::Warning)
                .buttons(tauri_plugin_dialog::MessageDialogButtons::OkCancelCustom(
                    "Re-approve".to_string(),
                    "Keep blocked".to_string(),
                ))
                .blocking_show(),
        ))
    })
    .await
    .map_err(|error| coded_ctx("sharing_task_failed", "Task failed", error))??;
    match answer {
        None => return Ok(true),
        Some(false) => return Ok(false),
        Some(true) => {}
    }

    // Held so the grant cannot interleave with a settings save's own root
    // transaction, and re-read under it: the folder may have been removed
    // while the dialog was open.
    let _settings_save_guard = state.settings_save_lock.lock().await;
    let settings = state.config.read().await.settings.clone();
    if !is_shared(&settings) {
        return Err(coded("sharing_folder_not_shared", "Folder is not a shared folder"));
    }
    let mut roots = settings.shared_folders.clone();
    if !settings.download_folder.is_empty() {
        roots.push(settings.download_folder.clone());
    }
    let folder = path.clone();
    tokio::task::spawn_blocking(move || registry.reapprove_roots(&roots, std::slice::from_ref(&folder)))
        .await
        .map_err(|error| coded_ctx("sharing_task_failed", "Task failed", error))?
        .map_err(|error| coded_ctx("sharing_reapprove_failed", "Could not re-approve the folder", error))?;
    info!("Re-approved shared folder {path} on the user's confirmation");
    Ok(true)
}

/// Map a lofty `FileType` to a short eMule-style codec label.
fn media_file_type_label(ft: lofty::file::FileType) -> String {
    use lofty::file::FileType;
    match ft {
        FileType::Mpeg => "mp3".to_string(),
        FileType::Mp4 => "aac".to_string(),
        FileType::Aac => "aac".to_string(),
        FileType::Flac => "flac".to_string(),
        FileType::Vorbis => "vorbis".to_string(),
        FileType::Opus => "opus".to_string(),
        FileType::Speex => "speex".to_string(),
        FileType::Wav => "wav".to_string(),
        FileType::Aiff => "aiff".to_string(),
        FileType::Ape => "ape".to_string(),
        FileType::WavPack => "wavpack".to_string(),
        other => format!("{other:?}").to_lowercase(),
    }
}

/// Extract media metadata (duration/bitrate/codec/tags) from a media file using
/// lofty (header-only read; no full decode). Returns `None` for non-media files
/// or on any parse error so the caller can treat "no media" uniformly. Audio
/// formats are covered; video files generally return `None`.
pub(crate) fn extract_media_metadata(path: &str) -> Option<crate::types::MediaMetadata> {
    use lofty::file::{AudioFile, TaggedFileExt};
    use lofty::probe::Probe;
    use lofty::tag::Accessor;

    let tagged = Probe::open(path).ok()?.read().ok()?;
    let props = tagged.properties();
    let mut media = crate::types::MediaMetadata::default();

    let secs = props.duration().as_secs();
    if secs > 0 {
        media.duration = Some(secs.min(u32::MAX as u64) as u32);
    }
    media.bitrate = props.audio_bitrate().filter(|b| *b > 0);
    media.codec = Some(media_file_type_label(tagged.file_type()));

    if let Some(tag) = tagged.primary_tag().or_else(|| tagged.first_tag()) {
        media.artist = tag
            .artist()
            .map(|c| c.to_string())
            .filter(|s| !s.is_empty());
        media.album = tag.album().map(|c| c.to_string()).filter(|s| !s.is_empty());
        media.title = tag.title().map(|c| c.to_string()).filter(|s| !s.is_empty());
    }

    media.into_option()
}

/// On-demand media metadata for a single shared file (used by the library
/// properties drawer). Restricted to files inside shared folders so the IPC
/// surface can't be used to probe arbitrary paths. Returns `None` when the
/// file isn't a recognized media file.
#[tauri::command]
pub async fn get_file_media_metadata(
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<Option<crate::types::MediaMetadata>, String> {
    let _single_flight = crate::security::try_begin_single_flight(&MEDIA_METADATA_IN_FLIGHT)
        .ok_or_else(|| {
            coded(
                "sharing_media_request_in_flight",
                "Another media metadata request is already running",
            )
        })?;
    if file_path.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "sharing_file_path_too_long",
            format!("File path exceeds {MAX_PATH_LEN} bytes"),
            MAX_PATH_LEN,
        ));
    }
    let allowed_dirs = {
        let config = state.config.read().await;
        shared_access_dirs(&config)
    };
    tokio::task::spawn_blocking(move || {
        // Canonicalize + containment-check (mirrors open_shared_file /
        // delete_shared_file) rather than a string-prefix match. A path that
        // normalizes under a shared folder but resolves via symlink/junction to
        // an arbitrary location must not be probable through this IPC surface.
        // `verify_existing_path`, not a bare containment check. This was the
        // last path command still using `is_path_within_dirs`, which only
        // canonicalizes and compares prefixes — it does not require the root
        // to still hold the volume-serial + file-id identity it was approved
        // with. A retargeted junction (exactly what the approved-root
        // registry exists to catch, and what
        // `junction_retarget_invalidates_approved_root` pins) therefore let
        // this command read media tags from outside the shared tree and act
        // as an existence oracle for arbitrary paths under the swapped root.
        let path = std::path::Path::new(&file_path);
        let canonical = crate::security::filesystem::verify_existing_path(path, &allowed_dirs)
            .map_err(|e| {
                coded_ctx(
                    "sharing_file_not_shared",
                    "File is not in a shared folder",
                    e,
                )
            })?;
        let cstr = canonical.to_string_lossy();
        Ok(extract_media_metadata(&cstr))
    })
    .await
    .map_err(|e| coded_ctx("sharing_media_task_failed", "Media task failed", e))?
}

/// Current per-folder default upload priorities (folder path -> priority).
#[tauri::command]
pub async fn get_folder_priorities(
    state: tauri::State<'_, AppState>,
) -> Result<std::collections::HashMap<String, String>, String> {
    let config = state.config.read().await;
    Ok(config.settings.folder_priorities.clone())
}

/// Set (or clear, with an empty/`none` priority) the default upload priority
/// for a shared folder. The default is persisted and applied immediately to
/// every file currently indexed under the folder, mirroring eMule's
/// per-directory priority. Returns the number of files updated.
#[tauri::command]
pub async fn set_folder_priority(
    state: tauri::State<'_, AppState>,
    folder_path: String,
    priority: String,
) -> Result<u32, String> {
    let clearing = priority.is_empty() || priority == "none";
    if !clearing {
        let valid = ["verylow", "low", "normal", "high", "release", "auto"];
        if !valid.contains(&priority.as_str()) {
            return Err(coded_ctx(
                "sharing_invalid_priority",
                "Invalid priority",
                &priority,
            ));
        }
    }
    let settings_save_guard = state.settings_save_lock.lock().await;
    let (new_settings, save_data) = {
        let config = state.config.read().await;
        if !config
            .settings
            .shared_folders
            .iter()
            .any(|f| paths_equal_ignore_case(f, &folder_path))
        {
            return Err(coded(
                "sharing_folder_not_shared",
                "Folder is not a shared folder",
            ));
        }
        let mut new_settings = config.settings.clone();
        // Drop any case-variant key first so the map never accumulates dupes.
        new_settings
            .folder_priorities
            .retain(|k, _| !paths_equal_ignore_case(k, &folder_path));
        if !clearing {
            new_settings
                .folder_priorities
                .insert(folder_path.clone(), priority.clone());
        }
        new_settings.settings_revision = config.settings.settings_revision.saturating_add(1);
        let save_data = config
            .prepare_save_settings(&new_settings)
            .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?;
        (new_settings, save_data)
    };

    // Clearing only stops the default from being re-applied; existing files
    // keep whatever priority they currently have.
    if clearing {
        let (data, tmp, final_path) = save_data;
        tokio::task::spawn_blocking(move || {
            crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
        })
        .await
        .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?
        .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?;
        state.config.write().await.settings = new_settings;
        drop(settings_save_guard);
        info!("Cleared folder priority for {folder_path}");
        return Ok(0);
    }

    // Apply hash-wide file priorities first, but keep a complete snapshot so a
    // known.met or config write failure can restore both persistence domains.
    let (index_snapshot, changed) = {
        let mut index = state.local_index.write().await;
        let snapshot = index.all_files().to_vec();
        let changed = index.set_priority_under_folder(&folder_path, &priority);
        (snapshot, changed)
    };
    if !changed.is_empty() {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        let hashes = changed
            .iter()
            .map(|(_, hash)| hash.clone())
            .filter(|hash| !hash.is_empty())
            .collect::<Vec<_>>();
        if let Err(error) =
            persist_upload_priorities(&state.network_tx, &hashes, priority_str_to_u8(&priority))
                .await
        {
            rollback_index_mutation(&state, index_snapshot).await;
            return Err(error);
        }
    }

    let (data, tmp, final_path) = save_data;
    let config_result = tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
    })
    .await
    .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))
    .and_then(|result| {
        result.map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))
    });
    if let Err(error) = config_result {
        let rollback_result = persist_priority_snapshot(&state.network_tx, &index_snapshot).await;
        rollback_index_mutation(&state, index_snapshot).await;
        return match rollback_result {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(coded_ctx(
                "sharing_priority_rollback_failed",
                "Folder priority save and rollback both failed",
                format!("{error}; rollback: {rollback_error}"),
            )),
        };
    }
    state.config.write().await.settings = new_settings;
    drop(settings_save_guard);
    info!(
        "Set folder priority {priority} for {folder_path} ({} files)",
        changed.len()
    );
    Ok(changed.len() as u32)
}

#[tauri::command]
pub async fn set_file_priority(
    state: tauri::State<'_, AppState>,
    file_path: String,
    priority: String,
) -> Result<(), String> {
    let valid = ["verylow", "low", "normal", "high", "release", "auto"];
    if !valid.contains(&priority.as_str()) {
        return Err(coded_ctx(
            "sharing_invalid_priority",
            "Invalid priority",
            &priority,
        ));
    }
    let (snapshot, changed, file_hash) = {
        let mut index = state.local_index.write().await;
        let snapshot = index.all_files().to_vec();
        if index.get_by_path(&file_path).is_none() {
            return Err(coded("sharing_file_not_found", "File not found"));
        }
        let changed = index.set_file_priority_by_path(&file_path, &priority);
        (
            snapshot,
            changed,
            index.get_by_path(&file_path).map(|f| f.hash.clone()),
        )
    };
    if !changed {
        return Ok(());
    }
    refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
    if let Some(hash) = file_hash.filter(|h| !h.is_empty()) {
        if let Err(e) =
            persist_upload_priorities(&state.network_tx, &[hash], priority_str_to_u8(&priority))
                .await
        {
            rollback_index_mutation(&state, snapshot).await;
            return Err(e);
        }
        // known.met now owns this priority — drop any intent recorded for the
        // path while it was still hashing, or a later rehash would revert the
        // user's choice. Best-effort: a stale entry is also swept by the
        // post-scan prune.
        if let Err(e) = persist_pending_intents(&state, &[], &[], &[], std::slice::from_ref(&file_path)).await {
            warn!("Failed to clear pending priority intent for {file_path}: {e}");
        }
    } else {
        if let Err(e) = persist_pending_intents(
            &state,
            &[],
            &[(file_path.clone(), priority.clone())],
            &[],
            &[],
        )
        .await
        {
            rollback_index_mutation(&state, snapshot).await;
            return Err(e);
        }
    }
    info!("Set priority for {} to {}", file_path, priority);
    Ok(())
}

/// Bulk-set upload priority for many files in a single Tauri call. Returns
/// the number of files actually updated (paths that did not match a known
/// shared file are silently skipped). Cuts N invoke round-trips down to 1
/// for the library multi-select action.
#[tauri::command]
pub async fn batch_set_priority(
    state: tauri::State<'_, AppState>,
    file_paths: Vec<String>,
    priority: String,
) -> Result<u32, String> {
    check_path_batch(&file_paths, MAX_BATCH_IDS)?;
    let valid = ["verylow", "low", "normal", "high", "release", "auto"];
    if !valid.contains(&priority.as_str()) {
        return Err(coded_ctx(
            "sharing_invalid_priority",
            "Invalid priority",
            &priority,
        ));
    }
    let (snapshot, count, hashes, pending_updates, hashed_paths) = {
        let mut index = state.local_index.write().await;
        let snapshot = index.all_files().to_vec();
        let mut n = 0u32;
        let mut hashes = Vec::new();
        let mut pending_updates: Vec<(String, String)> = Vec::new();
        let mut hashed_paths: Vec<String> = Vec::new();
        for path in &file_paths {
            let changed_paths = index.set_file_priority_by_path_count(path, &priority);
            if changed_paths > 0 {
                n = n.saturating_add(changed_paths as u32);
                if let Some(f) = index.get_by_path(path) {
                    if !f.hash.is_empty() {
                        hashes.push(f.hash.clone());
                        hashed_paths.push(path.clone());
                    } else {
                        // Still hashing: record the choice as a pending
                        // intent so it survives a restart, mirroring
                        // `set_file_priority`.
                        pending_updates.push((path.clone(), priority.clone()));
                    }
                }
            }
        }
        (snapshot, n, hashes, pending_updates, hashed_paths)
    };
    if count > 0 {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        if let Err(e) =
            persist_upload_priorities(&state.network_tx, &hashes, priority_str_to_u8(&priority))
                .await
        {
            rollback_index_mutation(&state, snapshot).await;
            return Err(e);
        }
        if let Err(e) =
            persist_pending_intents(&state, &[], &pending_updates, &[], &hashed_paths).await
        {
            rollback_index_mutation(&state, snapshot).await;
            return Err(e);
        }
        info!(
            "Batch set priority to {priority} for {count}/{} files",
            file_paths.len()
        );
    }
    Ok(count)
}

/// Bulk-share many files in a single Tauri call. Returns the count of
/// files actually flipped to shared (already-shared paths and unknown
/// paths contribute 0).
#[tauri::command]
pub async fn batch_share(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    file_paths: Vec<String>,
) -> Result<u32, String> {
    check_path_batch(&file_paths, MAX_BATCH_IDS)?;
    let offers = crate::sharing::indexer::AllowlistOffers::new(
        &state.config.read().await.settings.pending_folder_allowlists,
    );
    let mutation = {
        let mut index = state.local_index.write().await;
        let mut mutation = index.set_shared_by_paths(&file_paths, true);
        keep_unlisted_copies_unshared(&mut index, &mut mutation, &offers);
        mutation
    };
    let count = mutation.changed_paths as u32;
    if count > 0 {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        persist_share_mutation(&state, &mutation, true).await?;
        let _ = app.emit(
            "shared-files-changed",
            serde_json::json!({ "shared": count }),
        );
        info!("Batch shared {count}/{} files", file_paths.len());
    }
    Ok(count)
}

/// Restrict a batch of files to mutual friends, or return them to the open
/// network. Returns the count of files actually flipped.
///
/// A restricted file stays in the library and keeps its `shared` flag; what
/// changes is who may see and fetch it. Reconciliation after the write pulls
/// it out of the ed2k offer list and the KAD publish set, so an already
/// published file stops being discoverable rather than merely being hidden
/// from browse.
#[tauri::command]
pub async fn set_files_friends_only(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    file_paths: Vec<String>,
    friends_only: bool,
) -> Result<u32, String> {
    check_path_batch(&file_paths, MAX_BATCH_IDS)?;
    let (snapshot, mutation) = {
        let mut index = state.local_index.write().await;
        let snapshot = index.all_files().to_vec();
        let mutation = index.set_friends_only_by_paths(&file_paths, friends_only);
        (snapshot, mutation)
    };
    let count = mutation.changed_paths as u32;
    if count > 0 {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        if let Err(e) =
            persist_friends_only_states(&state.network_tx, &mutation.hashes, friends_only).await
        {
            rollback_index_mutation(&state, snapshot).await;
            return Err(e);
        }
        // Republish/re-offer so a newly restricted file is withdrawn from the
        // server offer list and the KAD publish set immediately.
        reconcile_shared_files_best_effort(&state.network_tx).await;
        let _ = app.emit(
            "shared-files-changed",
            serde_json::json!({ "friendsOnly": count }),
        );
        info!(
            "Set friends_only={friends_only} on {count}/{} files",
            file_paths.len()
        );
    }
    Ok(count)
}

/// Offer every indexed file under `folder`, and scan it for the ones that are
/// not indexed. Used when a partial share (an allowlist) is promoted to a full
/// folder share, whose files off the allowlist discovery never walked. Returns
/// the paths that changed. Files already offered are left out of that list.
/// `before` is how the folder lists stood before the promotion; see
/// [`admit_known_files`].
pub(crate) async fn share_all_in_folder(
    app: tauri::AppHandle,
    state: &AppState,
    folder: &str,
    before: &FolderListsBefore,
) -> Result<Vec<String>, String> {
    admit_known_files(state, before, &[folder.to_string()]).await;
    offer_all_in_folder(app, state, folder).await
}

/// [`share_all_in_folder`] for a caller that has already run
/// [`admit_known_files`] over `folder`.
pub(crate) async fn offer_all_in_folder(
    app: tauri::AppHandle,
    state: &AppState,
    folder: &str,
) -> Result<Vec<String>, String> {
    queue_rescan(&app, vec![std::path::PathBuf::from(folder)]);
    let offers = crate::sharing::indexer::AllowlistOffers::new(
        &state.config.read().await.settings.pending_folder_allowlists,
    );
    let mutation = {
        let mut index = state.local_index.write().await;
        let mut mutation = index.set_shared_by_path_prefix(folder, true);
        keep_unlisted_copies_unshared(&mut index, &mut mutation, &offers);
        mutation
    };
    let paths = mutation
        .pending_paths
        .iter()
        .chain(mutation.hashed_paths.iter())
        .cloned()
        .collect::<Vec<_>>();
    if mutation.changed_paths > 0 {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        persist_share_mutation(state, &mutation, true).await?;
        let _ = app.emit(
            "shared-files-changed",
            serde_json::json!({ "shared": mutation.changed_paths, "folder": folder }),
        );
    }
    Ok(paths)
}

/// The folder allowlists and withheld files as they stood before an edit that
/// may offer more of a partly shared folder, for [`admit_known_files`].
#[derive(Debug, Clone, Default)]
pub(crate) struct FolderListsBefore {
    allowlists: std::collections::HashMap<String, Vec<String>>,
    withheld: std::collections::HashMap<String, Vec<String>>,
}

impl FolderListsBefore {
    pub(crate) async fn take(state: &AppState) -> Self {
        let config = state.config.read().await;
        Self {
            allowlists: config.settings.pending_folder_allowlists.clone(),
            withheld: config.settings.withheld_folder_files.clone(),
        }
    }
}

/// Mark shared in known.met the files under `under` that an allowlist edit has
/// just let a partly shared folder offer, where known.met still has them
/// unshared: 1.7.0 walked every file of such a folder and unshared the ones
/// off its list, and discovery since walks only the list, so the rescan that
/// indexes them would restore that flag. Run before that rescan.
///
/// Only files the lists did not offer before are touched, so a file the user
/// unshared inside what was already offered keeps that choice. So does a
/// withheld file, one a pending intent keeps unshared, one the Library has a
/// row for (the row is its current state) and one whose content a Library row
/// has taken off the network. Best effort: on failure the files stay unshared.
pub(crate) async fn admit_known_files(state: &AppState, before: &FolderListsBefore, under: &[String]) {
    if under.is_empty() {
        return;
    }
    let (after, kept_unshared) = {
        let config = state.config.read().await;
        let settings = &config.settings;
        let kept = before
            .withheld
            .values()
            .flatten()
            .cloned()
            .chain(
                settings
                    .pending_share_states
                    .iter()
                    .filter(|(_, shared)| !**shared)
                    .map(|(path, _)| path.clone()),
            )
            .collect::<HashSet<_>>();
        (settings.pending_folder_allowlists.clone(), kept)
    };
    if after == before.allowlists {
        return;
    }
    let known = match load_known_files().await {
        Ok(known) => known,
        Err(error) => {
            warn!("Files newly offered by a partial share were left as known.met has them: {error}");
            return;
        }
    };
    let under = under.to_vec();
    let before_lists = before.allowlists.clone();
    let candidates = tokio::task::spawn_blocking(move || {
        newly_admitted_unshared(
            known.all_records(),
            &under,
            &crate::sharing::indexer::AllowlistOffers::new(&before_lists),
            &crate::sharing::indexer::AllowlistOffers::new(&after),
            &kept_unshared,
        )
    })
    .await
    .unwrap_or_default();
    if candidates.is_empty() {
        return;
    }
    let mut hashes = {
        let index = state.local_index.read().await;
        let off_network = index
            .all_files()
            .iter()
            .filter(|file| !file.shared && !file.hash.is_empty())
            .map(|file| file.hash.to_ascii_lowercase())
            .collect::<HashSet<_>>();
        candidates
            .into_iter()
            .filter(|(path, hash)| index.get_by_path(path).is_none() && !off_network.contains(hash))
            .map(|(_, hash)| hash)
            .collect::<Vec<_>>()
    };
    hashes.sort();
    hashes.dedup();
    match persist_shared_states(&state.network_tx, &hashes, true).await {
        Ok(()) if !hashes.is_empty() => {
            info!("Marked {} file(s) a partial share now offers as shared in known.met", hashes.len());
        }
        Ok(()) => {}
        Err(error) => warn!("Files newly offered by a partial share were left unshared: {error}"),
    }
}

/// `(path, content hash)` of the known.met records under `under` that are
/// unshared, that `after` offers and `before` did not, and that are not in
/// `kept_unshared` (normalized paths).
fn newly_admitted_unshared<'a>(
    records: impl Iterator<Item = &'a crate::storage::known_files::KnownFileRecord>,
    under: &[String],
    before: &crate::sharing::indexer::AllowlistOffers,
    after: &crate::sharing::indexer::AllowlistOffers,
    kept_unshared: &HashSet<String>,
) -> Vec<(String, String)> {
    let under = under
        .iter()
        .map(|entry| crate::search::index::normalize_path_key(entry))
        .collect::<HashSet<_>>();
    // `..=at` as well, for a drive root, whose key keeps its separator.
    let is_under = |key: &str| {
        under.contains(key)
            || key.match_indices(std::path::MAIN_SEPARATOR).any(|(at, _)| {
                under.contains(&key[..at]) || under.contains(&key[..=at])
            })
    };
    records
        .filter(|record| !record.is_shared && !record.file_path.is_empty())
        .filter(|record| {
            let key = crate::search::index::normalize_path_key(&record.file_path);
            is_under(&key)
                && !kept_unshared.contains(&key)
                && after.offers(&record.file_path)
                && !before.offers(&record.file_path)
        })
        .map(|record| (record.file_path.clone(), hex::encode(record.file_hash)))
        .collect()
}

/// Bulk-unshare many files in a single Tauri call. Returns the count of
/// files actually flipped to unshared.
#[tauri::command]
pub async fn batch_unshare(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    file_paths: Vec<String>,
) -> Result<u32, String> {
    check_path_batch(&file_paths, MAX_BATCH_IDS)?;
    let mutation = state.local_index.write().await.set_shared_by_paths(&file_paths, false);
    let count = mutation.changed_paths as u32;
    if count > 0 {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        persist_share_mutation(&state, &mutation, false).await?;
        let _ = app.emit(
            "shared-files-changed",
            serde_json::json!({ "unshared": count }),
        );
        info!("Batch unshared {count}/{} files", file_paths.len());
    }
    // Same reason as `unshare_file`: an allowlist that still names these
    // files would re-offer them on the next scan. Includes the other copies
    // the mutation unshared by hash, not just the requested paths.
    let mut cleared = file_paths;
    cleared.extend(mutation.hashed_paths);
    cleared.extend(mutation.pending_paths);
    drop_from_allowlists(&state, &cleared).await?;
    Ok(count)
}

#[tauri::command]
pub async fn reload_shared_files(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    reload_shared_files_page(app, &state, MAX_CHAINED_SCAN_PAGES, None).await
}

/// Rescan only `paths` — the files and folders filesystem events named — and
/// reconcile the index at and under each of them, leaving every other row of
/// every shared folder alone.
///
/// What the FS watcher runs for an ordinary change. A full reload walks every
/// root, re-reads `known.met` and re-announces the whole library, which is
/// the wrong price for one file landing in one folder — and it was paid on
/// every coalescing window for as long as anything kept writing.
pub(crate) async fn rescan_shared_paths(
    app: tauri::AppHandle,
    state: &AppState,
    paths: Vec<std::path::PathBuf>,
) -> Result<(), String> {
    reload_shared_files_page(app, state, 0, Some(paths)).await
}

/// `paths` without any that lie inside another of them, whose walk already
/// covers them.
fn outermost_paths(mut paths: Vec<std::path::PathBuf>) -> Vec<std::path::PathBuf> {
    paths.sort();
    paths.dedup();
    let all = paths.clone();
    paths.retain(|path| !all.iter().any(|other| other != path && path.starts_with(other)));
    paths
}

/// Unix seconds, in the unit `FileInfo::modified_at` uses.
fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// Take out of `files_to_hash` the files modified too recently to be finished
/// this pass. A file the index already holds hashed at this exact size and
/// mtime is not being written — a download that just completed, say, whose
/// `known.met` record has not reached disk yet — and is left to hash as before.
///
/// Their discovery rows stay in the pass's discovered set on purpose. The
/// reconcile places each over the file's existing row, which carries its
/// share state, friends-only restriction, priority and counters onto the
/// unhashed placeholder, and the settle recheck's own placeholder and the
/// hash completion carry them on from there. Dropping the row instead made
/// the file come back as a brand-new public share once it settled: its new
/// size, mtime and hash match nothing that remembers the old choices.
fn take_settling_files(
    files_to_hash: &mut Vec<FileInfo>,
    index: &LocalIndex,
    now: i64,
) -> Vec<FileInfo> {
    let mut settling = Vec::new();
    files_to_hash.retain(|file| {
        let indexed_as_is = index.get_by_path(&file.path).is_some_and(|row| {
            !row.hash.is_empty() && row.size == file.size && row.modified_at == file.modified_at
        });
        if !indexed_as_is && crate::sharing::indexer::still_settling(file.modified_at, now) {
            settling.push(file.clone());
            false
        } else {
            true
        }
    });
    settling
}

/// Normalized paths of the unhashed placeholder rows at or under `folders`.
fn unhashed_placeholders_under(index: &LocalIndex, folders: &[String]) -> HashSet<String> {
    index
        .all_files()
        .iter()
        .filter(|file| {
            file.id.starts_with(crate::search::index::PENDING_ID_PREFIX)
                && file_in_shared_folders(&file.path, folders)
        })
        .map(|file| crate::search::index::normalize_path_key(&file.path))
        .collect()
}

/// The folders of `reloaded` whose own listing was complete, so a pass may
/// remove the rows under them it did not find, whatever another folder's page
/// was. One overlapping a folder in `incomplete` is left out: the partial page
/// of an enclosing or nested share may be all that lists some of its rows.
fn authoritative_folders(reloaded: &[String], incomplete: &[String]) -> Vec<String> {
    reloaded
        .iter()
        .filter(|folder| {
            !incomplete.iter().any(|partial| {
                crate::security::path_within_dir(folder, partial)
                    || crate::security::path_within_dir(partial, folder)
            })
        })
        .cloned()
        .collect()
}

/// The rows under those of `unreadable`, subfolders a full pass could not
/// list, that lie in a folder it reloaded.
fn rows_under_unreadable(index: &LocalIndex, unreadable: &[String], reloaded: &[String]) -> Vec<FileInfo> {
    let unreadable = unreadable
        .iter()
        .filter(|folder| file_in_shared_folders(folder, reloaded) && index.has_rows_at_or_under(folder))
        .cloned()
        .collect::<Vec<_>>();
    if unreadable.is_empty() {
        return Vec::new();
    }
    index
        .all_files()
        .iter()
        .filter(|file| file_in_shared_folders(&file.path, &unreadable))
        .cloned()
        .collect()
}

/// Take out of each finished paged cycle's doomed rows those whose file is on
/// disk as indexed, where discovery under `roots` with `discovery_lists`
/// would find it: deleted and put back after its page ran, with no event to
/// tell the cycle. The check runs on the blocking pool. Also returns the
/// doomed rows as they were checked, `(fingerprint, size, modified_at)`: a row
/// written at one of those paths since, by a download completing there, is
/// not the one the cycle found missing.
async fn spare_rows_back_on_disk(
    index: &RwLock<LocalIndex>,
    mut finished: Vec<(String, HashSet<u64>)>,
    roots: Vec<String>,
    discovery_lists: std::collections::HashMap<String, Vec<String>>,
) -> (Vec<(String, HashSet<u64>)>, HashSet<(u64, u64, i64)>) {
    if finished.is_empty() {
        return (finished, HashSet::new());
    }
    let rows = {
        let index = index.read().await;
        index
            .all_files()
            .iter()
            .filter(|file| {
                let print = crate::sharing::paged_cycle::fingerprint(&file.path);
                finished.iter().any(|(folder, doomed)| {
                    doomed.contains(&print) && crate::security::path_within_dir(&file.path, folder)
                })
            })
            .map(|file| (file.path.clone(), file.size, file.modified_at))
            .collect::<Vec<_>>()
    };
    let checked = rows
        .iter()
        .map(|(path, size, modified_at)| (crate::sharing::paged_cycle::fingerprint(path), *size, *modified_at))
        .collect::<HashSet<_>>();
    let back = match tokio::task::spawn_blocking(move || {
        let scopes = crate::sharing::indexer::DiscoveryScopes::new(&discovery_lists);
        crate::sharing::paged_cycle::still_on_disk(&rows, &roots, &scopes)
    })
    .await
    {
        Ok(back) => back,
        Err(error) => {
            warn!("Could not re-check the files a paged scan found missing: {error}");
            HashSet::new()
        }
    };
    for (_, doomed) in &mut finished {
        doomed.retain(|print| !back.contains(print));
    }
    finished.retain(|(_, doomed)| !doomed.is_empty());
    (finished, checked)
}

/// `remove_pending_files_under(folders)`, sparing the placeholders whose
/// normalized path is in `keep`.
fn remove_pending_rows_except(index: &mut LocalIndex, folders: &[String], keep: &HashSet<String>) {
    let kept = index
        .all_files()
        .iter()
        .filter(|file| {
            file.id.starts_with(crate::search::index::PENDING_ID_PREFIX)
                && keep.contains(&crate::search::index::normalize_path_key(&file.path))
        })
        .cloned()
        .collect::<Vec<_>>();
    index.remove_pending_files_under(folders);
    index.add_files(kept);
}

/// Path-keyed intents that keep a settling file's restrictions across a
/// restart: `(share updates, priority updates)` for [`write_pending_intents`].
///
/// Once a file's hashed row gives way to its settle placeholder, nothing on
/// disk remembers its choices by anything that still matches it — `known.met`
/// and the share-intent store are keyed by the old hash — so a restart before
/// the recheck rediscovers it as a new public share. A pending intent is keyed
/// by path, the startup scan applies it to that rediscovery, and it is pruned
/// once the file is hashed again. A friends-only file is recorded as unshared:
/// there is no path-keyed friends-only intent, and failing closed beats
/// coming back public. In-session the placeholder carries the exact state and
/// wins over the intent. Only a hashed row is recorded — a placeholder's
/// choices were recorded when it replaced that row, and a later explicit
/// change by the user must not be overwritten here.
fn settle_carry_over_intents(
    settling: &[FileInfo],
    index: &LocalIndex,
    existing_share_intents: &std::collections::HashMap<String, bool>,
    existing_priority_intents: &std::collections::HashMap<String, String>,
) -> (Vec<(String, bool)>, Vec<(String, String)>) {
    let mut shares = Vec::new();
    let mut priorities = Vec::new();
    for file in settling {
        let Some(row) = index.get_by_path(&file.path) else {
            continue;
        };
        if row.hash.is_empty() {
            continue;
        }
        let key = crate::search::index::normalize_path_key(&row.path);
        if (!row.shared || row.friends_only) && !existing_share_intents.contains_key(&key) {
            shares.push((row.path.clone(), false));
        }
        if row.priority != "normal" && !existing_priority_intents.contains_key(&key) {
            priorities.push((row.path.clone(), row.priority.clone()));
        }
    }
    (shares, priorities)
}

/// Split a scoped rescan's discoveries three ways before `known.met` is read:
/// rows the index already holds for exactly this size and mtime (reused
/// as-is), files still being written (deferred), and the rest. Only the rest
/// needs `known.met`, so a pass that finds nothing else — an external writer's
/// file growing, the common case — never loads it.
fn split_scoped_discoveries(
    discovered: Vec<FileInfo>,
    index: &LocalIndex,
    now: i64,
) -> (Vec<FileInfo>, Vec<FileInfo>, Vec<FileInfo>) {
    let mut unchanged = Vec::new();
    let mut settling = Vec::new();
    let mut rest = Vec::new();
    for file in discovered {
        match index.get_by_path(&file.path) {
            Some(row)
                if !row.hash.is_empty()
                    && row.size == file.size
                    && row.modified_at == file.modified_at =>
            {
                unchanged.push(row.clone());
            }
            _ if crate::sharing::indexer::still_settling(file.modified_at, now) => settling.push(file),
            _ => rest.push(file),
        }
    }
    (unchanged, settling, rest)
}

/// Rescan files left to settle once the newest of them has gone quiet.
fn schedule_settle_recheck(app: &tauri::AppHandle, settling: &[FileInfo], now: i64) {
    let newest = settling
        .iter()
        .map(|file| file.modified_at)
        .max()
        .unwrap_or(now);
    let wait = newest
        .saturating_add(crate::sharing::indexer::SETTLE_PERIOD_SECS)
        .saturating_sub(now)
        .clamp(1, 2 * crate::sharing::indexer::SETTLE_PERIOD_SECS) as u64
        + 2;
    let wait = std::time::Duration::from_secs(wait);
    let paths = settling
        .iter()
        .map(|file| std::path::PathBuf::from(&file.path))
        .collect::<Vec<_>>();
    info!(
        "{} file(s) are still being written; hashing them once they settle ({}s)",
        paths.len(),
        wait.as_secs()
    );
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    match state.shared_folder_watcher.as_ref() {
        Some(watcher) => watcher.queue_rescan_after(paths, wait),
        None => {
            tokio::spawn(settle_recheck_without_watcher(app.clone(), paths, wait));
        }
    }
}

/// Scan `paths` now, the way a filesystem event would: files and folders a
/// partly shared folder has just taken on, which discovery left alone while
/// they were off its allowlist and so are not in the index to be shared.
pub(crate) fn queue_rescan(app: &tauri::AppHandle, paths: Vec<std::path::PathBuf>) {
    if paths.is_empty() {
        return;
    }
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    match state.shared_folder_watcher.as_ref() {
        Some(watcher) => watcher.queue_rescan_after(paths, std::time::Duration::ZERO),
        None => {
            tokio::spawn(settle_recheck_without_watcher(
                app.clone(),
                paths,
                std::time::Duration::ZERO,
            ));
        }
    }
}

/// [`schedule_settle_recheck`] when live folder tracking is off. Boxed for the
/// same reason as [`chained_scan_page`]: it is mutually recursive with
/// [`reload_shared_files_page`].
fn settle_recheck_without_watcher(
    app: tauri::AppHandle,
    paths: Vec<std::path::PathBuf>,
    wait: std::time::Duration,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async move {
        tokio::time::sleep(wait).await;
        let mut backoff = RELOAD_BUSY_RETRY;
        loop {
            let Some(state) = app.try_state::<AppState>() else {
                return;
            };
            if state.bw_shutdown.load(Ordering::Acquire) {
                return;
            }
            // A pass can hold the flight for hours on a first-run library, so
            // this outlasts it rather than giving up; a Stop is latched by the
            // rescan itself.
            match rescan_shared_paths(app.clone(), &state, paths.clone()).await {
                Err(error) if error.contains("sharing_reload_in_flight") => {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(RELOAD_BUSY_RETRY_MAX);
                }
                _ => return,
            }
        }
    })
}

/// Wait out the gap between chained pages, then run the next one.
///
/// Boxed because the chain is mutually recursive with
/// [`reload_shared_files_page`], which needs one concrete future type to
/// terminate the type cycle on.
fn chained_scan_page(
    app: tauri::AppHandle,
    chained_pages_left: u32,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async move {
        let deadline = std::time::Instant::now() + CHAINED_SCAN_PAGE_DELAY;
        loop {
            {
                let Some(state) = app.try_state::<AppState>() else {
                    return;
                };
                // An explicit Stop must not be undone behind the user's back —
                // the FS watcher declines a reload for the same reason — and
                // shutdown raises `bw_shutdown` before joining the scans it
                // tracks, so noticing it here is what keeps exit prompt.
                if state.bw_shutdown.load(Ordering::Acquire)
                    || state.hashing_paused.load(Ordering::Relaxed)
                {
                    return;
                }
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(CHAINED_SCAN_POLL_INTERVAL).await;
        }
        loop {
            let Some(state) = app.try_state::<AppState>() else {
                return;
            };
            if state.bw_shutdown.load(Ordering::Acquire)
                || state.hashing_paused.load(Ordering::Relaxed)
            {
                return;
            }
            match reload_shared_files_page(app.clone(), &state, chained_pages_left, None).await {
                // A full reload resumes from the same cursor and chains its own
                // pages. A scoped rescan does neither, and giving up behind one
                // left every later page of a large library unindexed.
                Err(error)
                    if error.contains("sharing_reload_in_flight")
                        && RELOAD_FLIGHT_KIND.load(Ordering::Acquire) != FLIGHT_FULL =>
                {
                    tokio::time::sleep(RELOAD_BUSY_RETRY).await;
                }
                Err(error) => {
                    debug!("Chained shared-folder scan page did not start: {error}");
                    return;
                }
                Ok(()) => return,
            }
        }
    })
}

/// Register the next chained page as a tracked background scan so shutdown can
/// abort it, instead of leaving an untracked task able to start a fresh scan
/// while the exit flush is running.
async fn schedule_chained_scan_page(app: tauri::AppHandle, chained_pages_left: u32) {
    let handle = tokio::spawn(chained_scan_page(app.clone(), chained_pages_left));
    if let Some(state) = app.try_state::<AppState>() {
        state.register_background_scan(handle).await;
    }
}

/// `chained_pages_left` is how many *further* truncated pages this trigger may
/// queue for itself; see [`MAX_CHAINED_SCAN_PAGES`]. `scope` limits the pass to
/// those paths; see [`rescan_shared_paths`].
async fn reload_shared_files_page(
    app: tauri::AppHandle,
    state: &AppState,
    chained_pages_left: u32,
    scope: Option<Vec<std::path::PathBuf>>,
) -> Result<(), String> {
    // Shutdown raises `bw_shutdown` before joining the scans it tracks. A
    // reload that starts after that point takes `local_index.write()` and
    // updates `known_files` behind the authoritative flush, then gets aborted
    // mid-write — the half-written `known.met` the join exists to prevent. The
    // chained-page gap already declines for this reason; the entry point has
    // to as well, because the FS watcher and the Settings root reconcile can
    // both arrive here during exit. Not an error: there is nothing left to do.
    if state.bw_shutdown.load(Ordering::Acquire) {
        debug!("Shared-file reload declined: shutdown in progress");
        return Ok(());
    }
    let scoped = scope.is_some();
    // Nobody asked for a scoped pass, so it must not undo a Stop; the latch
    // hands the change to the full reload that resuming runs.
    if scoped && state.hashing_paused.load(Ordering::Relaxed) {
        state.hashing_fs_dirty.store(true, Ordering::Relaxed);
        return Ok(());
    }
    let reload_flight =
        crate::security::try_begin_single_flight(&RELOAD_IN_FLIGHT).ok_or_else(|| {
            coded(
                "sharing_reload_in_flight",
                "A shared-file reload is already running",
            )
        })?;
    let flight_kind = ReloadFlightKind::set(scoped);
    if !scoped {
        // Manual reload / resume always clear the pause latch. The FS watcher
        // never reaches this path while paused (it checks hashing_paused
        // first). A scoped pass re-walks no root, so it leaves the truncation
        // banner to the pass that can re-evaluate it.
        state.hashing_paused.store(false, Ordering::Relaxed);
        state.hashing_fs_dirty.store(false, Ordering::Relaxed);
        state.library_scan_truncated.store(false, Ordering::Relaxed);
    }

    let local_index = state.local_index.clone();
    let file_cache = state.cached_shared_files.clone();
    let network_tx = state.network_tx.clone();
    let scanning = state.scanning_count.clone();
    let scan_coordination = state.scan_coordination.clone();
    let cancel_flags = state.hash_cancel_flags.clone();
    let fresh_part_hashes = state.fresh_part_hashes.clone();
    let config = state.config.clone();
    let scan_truncated = state.library_scan_truncated.clone();

    let cancel_flag = Arc::new(AtomicBool::new(false));
    let reload_key = format!(
        "__reload_{}__",
        RELOAD_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    {
        let mut flags = cancel_flags.write().await;
        // Single-flight: signal any reload already in progress to stop before
        // starting this one. Two concurrent reloads would race on the shared
        // local index and emit conflicting progress events; the newest request
        // wins. (Only `__reload_*` keys are reloads — other entries are
        // per-file hash-cancel flags, which we must not touch.)
        for (key, flag) in flags.iter() {
            if key.starts_with("__reload_") {
                flag.store(true, Ordering::Relaxed);
            }
        }
        flags.insert(reload_key.clone(), cancel_flag.clone());
    }

    let scan_handle = tokio::spawn(async move {
        // Held for the whole reload and released when this task ends. Deliberately
        // not handed to the hash-timeout drain: that drain can block indefinitely
        // on a stuck read, which would wedge every later reload.
        let _reload_flight_guard = reload_flight;
        // Declared after the flight guard so it drops first: the kind is
        // cleared while the flight is still ours, never over a newer pass's.
        let _flight_kind = flight_kind;
        let _coordination_guard = scan_coordination.clone().lock_owned().await;
        scanning.fetch_add(1, Ordering::Relaxed);
        let scan_guard = ScanGuard(scanning.clone());

        // Read only once the lock is held: a pass queued behind a long scan
        // must walk the folders and lists as they stand when it runs.
        let (folders, scan_cursors, discovery_allowlists) = {
            let config = config.read().await;
            (
                config.settings.shared_folders.clone(),
                config.settings.shared_folder_scan_cursors.clone(),
                crate::sharing::indexer::discovery_lists(
                    &config.settings.pending_folder_allowlists,
                    &config.settings.withheld_folder_files,
                ),
            )
        };
        let discovery_folders = folders.clone();
        let cursors_before_scan = scan_cursors.clone();
        let discovery_cursors = scan_cursors;
        let recheck_lists = if scoped {
            Default::default()
        } else {
            discovery_allowlists.clone()
        };

        // `truncated` gates the user-facing cap warning; `incomplete` gates
        // reconciliation, per folder. A resumed page is always partial but only
        // rarely truncated, so they cannot share one flag.
        // `scanned_paths` is what a scoped pass examined and may reconcile
        // under; empty for a full pass, which reconciles whole roots.
        // `incomplete` names the folders, or a scoped pass's paths, whose
        // listing was partial; `unreadable`, the subfolders a full pass could
        // not list.
        let (
            mut discovered,
            discovery_truncated,
            discovery_incomplete,
            discovery_cursor_updates,
            scanned_paths,
            discovery_pages,
            discovery_unreadable,
        ): (
            Vec<FileInfo>,
            bool,
            Vec<String>,
            std::collections::HashMap<String, Option<String>>,
            Vec<String>,
            Vec<(String, crate::sharing::paged_cycle::PageFacts)>,
            Vec<String>,
        ) = match tokio::task::spawn_blocking(move || {
            let mut files = Vec::new();
            let mut truncated = false;
            let mut incomplete = Vec::new();
            let mut cursor_updates = std::collections::HashMap::new();
            let mut scanned = Vec::new();
            let mut pages = Vec::new();
            let mut unreadable = Vec::new();
            let scopes = crate::sharing::indexer::DiscoveryScopes::new(&discovery_allowlists);
            if let Some(paths) = scope {
                for path in outermost_paths(paths) {
                    match FileIndexer::discover_scoped_path(&discovery_folders, &scopes, &path) {
                        crate::sharing::indexer::ScopedDiscovery::Skip => {}
                        crate::sharing::indexer::ScopedDiscovery::Removed => {
                            scanned.push(path.to_string_lossy().into_owned());
                        }
                        crate::sharing::indexer::ScopedDiscovery::Found {
                            files: found,
                            partial: found_partial,
                        } => {
                            let path = path.to_string_lossy().into_owned();
                            if found_partial {
                                incomplete.push(path.clone());
                            }
                            files.extend(found);
                            scanned.push(path);
                        }
                    }
                }
                return (files, truncated, incomplete, cursor_updates, scanned, pages, unreadable);
            }
            for folder in &discovery_folders {
                let key = crate::search::index::normalize_path_key(folder);
                let cursor = discovery_cursors.get(&key).cloned();
                let result = FileIndexer::discover_directory_page_in(
                    folder,
                    cursor.as_deref(),
                    scopes.for_root(folder),
                );
                truncated |= result.truncated;
                if result.partial {
                    incomplete.push(folder.clone());
                }
                pages.push((
                    folder.clone(),
                    crate::sharing::paged_cycle::PageFacts {
                        cursor,
                        next: result.next_cursor.clone(),
                        frontier_trimmed: result.frontier_trimmed,
                    },
                ));
                cursor_updates.insert(folder.clone(), result.next_cursor);
                unreadable.extend(result.unreadable);
                files.extend(result.files);
            }
            (files, truncated, incomplete, cursor_updates, scanned, pages, unreadable)
        })
        .await
        {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Reload discovery failed: {e}");
                remove_cancel_flag_if_current(&cancel_flags, &reload_key, &cancel_flag).await;
                report_scan_failure(&app, None);
                return;
            }
        };
        if discovery_truncated {
            warn!(
                "Reload discovery reached the per-folder file cap; retaining existing entries not seen in this partial scan"
            );
            scan_truncated.store(true, Ordering::Relaxed);
            let _ = app.emit(
                "shared-files-scan-truncated",
                serde_json::json!({ "folders": folders, "limit": 100_000 }),
            );
        }

        let total_files = discovered.len();

        let current_folders = {
            let cfg = config.read().await;
            cfg.settings.shared_folders.clone()
        };
        // For a scoped pass the "folders" reconciled are the examined paths
        // themselves, each only while a current root still covers it.
        let reloaded_folders = if scoped {
            scanned_paths
                .into_iter()
                .filter(|path| {
                    current_folders
                        .iter()
                        .any(|current| crate::security::path_within_dir(path, current))
                })
                .collect::<Vec<_>>()
        } else {
            folders
                .iter()
                .filter(|folder| {
                    current_folders
                        .iter()
                        .any(|current| paths_equal_ignore_case(current, folder))
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        discovered.retain(|file| file_in_shared_folders(&file.path, &reloaded_folders));
        if scoped && reloaded_folders.is_empty() {
            remove_cancel_flag_if_current(&cancel_flags, &reload_key, &cancel_flag).await;
            return;
        }

        if cancel_flag.load(Ordering::Relaxed) {
            info!("Reload cancelled during discovery");
            remove_cancel_flag_if_current(&cancel_flags, &reload_key, &cancel_flag).await;
            let _ = app.emit(
                "file-hash-progress",
                serde_json::json!({ "done": true, "current": 0, "total": 0, "file_name": "" }),
            );
            return;
        }

        let settle_now = unix_now_secs();
        let (unchanged_rows, early_settling) = if scoped {
            let index = local_index.read().await;
            let (unchanged, settling, rest) =
                split_scoped_discoveries(std::mem::take(&mut discovered), &index, settle_now);
            discovered = rest;
            (unchanged, settling)
        } else {
            (Vec::new(), Vec::new())
        };
        let known_list = if discovered.is_empty() {
            KnownFileList::new()
        } else {
            match load_known_files().await {
                Ok(known_list) => known_list,
                Err(e) => {
                    tracing::error!("Reload known.met load failed: {e}");
                    remove_cancel_flag_if_current(&cancel_flags, &reload_key, &cancel_flag).await;
                    return;
                }
            }
        };
        let ResolvedWork {
            needs_hashing: mut files_to_hash,
            needs_top_up,
        } = resolve_from_known(&mut discovered, &known_list);
        // Files still being written get the same new-file treatment
        // (allowlist, intents, folder default) as a file about to be hashed —
        // their placeholder row is what a brand-new file enters the index as —
        // and are held back from hashing just below.
        discovered.extend(early_settling.iter().cloned());
        files_to_hash.extend(early_settling);
        let (
            folder_priorities,
            pending_share_states,
            pending_file_priorities,
            pending_folder_allowlists,
        ) = {
            let cfg = config.read().await;
            (
                cfg.settings.folder_priorities.clone(),
                cfg.settings.pending_share_states.clone(),
                cfg.settings.pending_file_priorities.clone(),
                cfg.settings.pending_folder_allowlists.clone(),
            )
        };
        apply_folder_defaults_to_new_files(&mut discovered, &mut files_to_hash, &folder_priorities);
        apply_folder_allowlists(
            &mut discovered,
            &mut files_to_hash,
            &pending_folder_allowlists,
        );
        withhold_unlisted_known_files(&mut discovered, &pending_folder_allowlists);
        apply_pending_intents(
            &mut discovered,
            &mut files_to_hash,
            &pending_share_states,
            &pending_file_priorities,
        );
        let (settling, settle_share_intents, settle_priority_intents) = {
            let index = local_index.read().await;
            let settling = take_settling_files(&mut files_to_hash, &index, settle_now);
            let (shares, priorities) = settle_carry_over_intents(
                &settling,
                &index,
                &pending_share_states,
                &pending_file_priorities,
            );
            (settling, shares, priorities)
        };
        // Recorded before the reconcile hands the old rows' state to their
        // placeholders, so there is no moment when only memory holds it.
        if let Err(error) = write_pending_intents(
            &app.state::<AppState>(),
            &settle_share_intents,
            &settle_priority_intents,
            &[],
            &[],
            false,
        )
        .await
        {
            warn!("Could not record the restrictions of files still being written: {error}");
        }
        discovered.extend(unchanged_rows);
        // What a subfolder that could not be listed holds is unknown, not gone:
        // its rows count as found, so neither the reconcile nor a finished
        // paged cycle removes them.
        if !discovery_unreadable.is_empty() {
            let index = local_index.read().await;
            discovered.extend(rows_under_unreadable(&index, &discovery_unreadable, &reloaded_folders));
        }

        // Folders past the page cap reconcile once per cursor cycle; see
        // `sharing::paged_cycle`.
        let finished_cycles = {
            let index = local_index.read().await;
            {
                let mut cycles = crate::sharing::paged_cycle::cycles()
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if scoped {
                    cycles.note_found(discovered.iter().map(|file| file.path.as_str()));
                    Vec::new()
                } else {
                    cycles.retain_roots(&reloaded_folders);
                    discovery_pages
                        .iter()
                        .filter(|(folder, _)| {
                            reloaded_folders.iter().any(|active| paths_equal_ignore_case(active, folder))
                        })
                        .filter_map(|(folder, facts)| {
                            let under = |path: &str| crate::security::path_within_dir(path, folder);
                            cycles
                                .note_page(
                                    folder,
                                    facts,
                                    || {
                                        index
                                            .all_files()
                                            .iter()
                                            .filter(|file| under(&file.path))
                                            .map(|file| file.path.clone())
                                            .collect()
                                    },
                                    discovered
                                        .iter()
                                        .filter(|file| under(&file.path))
                                        .map(|file| file.path.as_str()),
                                )
                                .filter(|doomed| !doomed.is_empty())
                                .map(|doomed| (folder.clone(), doomed))
                        })
                        .collect::<Vec<_>>()
                }
            }
        };
        let (finished_cycles, doomed_rows) =
            spare_rows_back_on_disk(&local_index, finished_cycles, reloaded_folders.clone(), recheck_lists).await;
        let authoritative = authoritative_folders(&reloaded_folders, &discovery_incomplete);
        let (removed_fresh_hashes, placeholders_before_pass) = {
            let mut index = local_index.write().await;
            let placeholders_before_pass = unhashed_placeholders_under(&index, &reloaded_folders);
            let before = (!authoritative.is_empty() || !settling.is_empty() || !finished_cycles.is_empty()).then(|| {
                index
                    .all_files()
                    .iter()
                    .filter(|file| file_in_shared_folders(&file.path, &reloaded_folders))
                    .cloned()
                    .collect::<Vec<_>>()
            });
            index.reconcile_files_for_folders(&authoritative, discovered, !authoritative.is_empty());
            for (folder, doomed) in &finished_cycles {
                let removed = index.remove_files_where(|file| {
                    let print = crate::sharing::paged_cycle::fingerprint(&file.path);
                    crate::security::path_within_dir(&file.path, folder)
                        && doomed.contains(&print)
                        && doomed_rows.contains(&(print, file.size, file.modified_at))
                });
                if removed > 0 {
                    info!("Removed {removed} missing file(s) from {folder} at the end of its paged scan");
                }
            }
            let removed = before
                .as_deref()
                .map(|before| {
                    fresh_part_hashes_removed_by_reload(
                        before,
                        index.all_files(),
                        &reloaded_folders,
                    )
                })
                .unwrap_or_default();
            (removed, placeholders_before_pass)
        };
        discard_fresh_part_hashes(&fresh_part_hashes, &removed_fresh_hashes).await;
        refresh_file_cache(&local_index, &file_cache).await;

        let _ = app.emit(
            "shared-files-changed",
            serde_json::json!({
                "phase": "discovered",
                "count": total_files,
            }),
        );

        let total_to_hash = files_to_hash.len();
        let mut hashed_count: usize = 0;
        let mut last_cache_refresh = std::time::Instant::now();
        let mut hash_progress = HashProgressEmitter::new(&files_to_hash);
        let mut was_cancelled = false;

        // One read at a time per device, more only where that device reported
        // no seek penalty; see `sharing::disk`.
        let mut pipeline = HashLookahead::new(&files_to_hash, cancel_flag.clone());
        pipeline.log_plan("Reload hashing", total_to_hash);
        loop {
            let started = match pipeline.next_started() {
                NextHash::Ready(started) => started,
                // See the folder-add loop: busy is not finished.
                NextHash::Busy => {
                    if cancel_flag.load(Ordering::Relaxed) {
                        was_cancelled = true;
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    continue;
                }
                NextHash::Done => break,
            };
            if cancel_flag.load(Ordering::Relaxed) {
                info!("Reload hashing cancelled at {hashed_count}/{total_to_hash}");
                was_cancelled = true;
                // Already claimed and running — hand it back to the drain, or
                // its claim outlives the scan. See the folder-add loop.
                pipeline.drain_started(started);
                break;
            }

            let file = &files_to_hash[started.index];
            let file_temp_id = file.id.clone();
            let hash_claim = started.claim;
            let mut hash_task = started.task;

            debug!(
                "Reload hashing {}/{}: {}",
                hashed_count + 1,
                total_to_hash,
                file.name
            );

            hash_progress.emit(&app, hashed_count + 1, total_to_hash, &file.name);

            let hash_result =
                await_hash(&mut hash_task, &started.progress, &file.path, hash_claim).await;

            match hash_result {
                Ok(Ok(Ok((
                    ed2k_hash,
                    aich_hash,
                    part_hashes,
                    ember_file_hash,
                    hashed_size,
                    hashed_modified_at,
                )))) => {
                    debug!(
                        "Reload hash complete: {} -> {}",
                        file.name,
                        &ed2k_hash[..ed2k_hash.len().min(8)]
                    );
                    let mut updated_file = file.clone();
                    updated_file.id = ed2k_hash.clone();
                    updated_file.hash = ed2k_hash;
                    updated_file.aich_hash = aich_hash;
                    updated_file.ember_file_hash = ember_file_hash;
                    updated_file.size = hashed_size;
                    updated_file.modified_at = hashed_modified_at;
                    restore_known_hash_flags(&mut updated_file, &known_list);

                    let still_shared = {
                        let cfg = config.read().await;
                        file_in_shared_folders(&updated_file.path, &cfg.settings.shared_folders)
                    };
                    // Keep the computed hashes only if this scan commits the
                    // completed row. Cancellation removes the pending row, so
                    // an earlier cache insert would be orphaned.
                    let fresh_handoff = still_shared
                        .then(|| fresh_part_hash_handoff(&updated_file.hash, part_hashes))
                        .flatten();
                    let finalized = {
                        let mut index = local_index.write().await;
                        if !cancel_flag.load(Ordering::Relaxed) && still_shared {
                            // The current pending row is authoritative for
                            // user-controlled share state and priority.
                            index
                                .finalize_pending_hash(&file_temp_id, updated_file.clone())
                                .is_some()
                        } else if still_shared {
                            // Cancelled. A re-hash row is already servable and
                            // keeps its place; only an unhashed row is dropped.
                            index.abandon_hash_placeholder(&file_temp_id);
                            false
                        } else {
                            index.remove_file_by_id(&file_temp_id);
                            false
                        }
                    };
                    cache_fresh_part_hash_handoff(&fresh_part_hashes, finalized, fresh_handoff)
                        .await;

                    if !cancel_flag.load(Ordering::Relaxed) && still_shared {
                        hashed_count += 1;
                    }
                    if !cancel_flag.load(Ordering::Relaxed)
                        && still_shared
                        && last_cache_refresh.elapsed() >= std::time::Duration::from_secs(5)
                    {
                        refresh_file_cache(&local_index, &file_cache).await;
                        let _ = app.emit(
                            "shared-files-changed",
                            serde_json::json!({ "phase": "hash-progress" }),
                        );
                        last_cache_refresh = std::time::Instant::now();
                    }
                    release_in_flight_hash(&file.path, hash_claim);
                }
                Ok(Ok(Err(e))) => {
                    let msg = e.to_string();
                    if msg.contains("cancelled") {
                        info!("Reload hashing cancelled mid-file");
                        was_cancelled = true;
                        let mut index = local_index.write().await;
                        index.abandon_hash_placeholder(&file_temp_id);
                        release_in_flight_hash(&file.path, hash_claim);
                        break;
                    }
                    warn!("Failed to hash {}: {e}", file.name);
                    let mut index = local_index.write().await;
                    index.abandon_hash_placeholder(&file_temp_id);
                    release_in_flight_hash(&file.path, hash_claim);
                }
                Ok(Err(e)) => {
                    tracing::error!("Hash task panicked for {}: {e}", file.name);
                    let mut index = local_index.write().await;
                    index.abandon_hash_placeholder(&file_temp_id);
                    release_in_flight_hash(&file.path, hash_claim);
                }
                Err(HashStalled) => {
                    // One stuck file must not end the reload. Cancelling the whole
                    // pass and dropping the reloaded folders' pending rows left
                    // every file after this one un-indexed, and it recurred on
                    // every retry because the queue is walked in a stable order.
                    // Leave the row pending and move on to the next file.
                    warn!(
                        "Hash of {} read nothing for {} min (file may be on cloud storage or locked); leaving pending for retry",
                        file.name,
                        HASH_STALL_TIMEOUT.as_secs() / 60
                    );
                    // Drain the abandoned blocking hash for its log line only,
                    // holding no lease. The read may be stuck in the kernel where
                    // the cancel flag cannot reach it, and handing the reload /
                    // coordination / scan guards to that wait would block every
                    // later reload and stall shutdown for the rest of the session.
                    let timed_out_name = file.name.clone();
                    let timed_out_path = file.path.clone();
                    // See the folder-add loop: the drive stays accounted for
                    // until the abandoned read actually finishes.
                    let orphan_device = crate::sharing::disk::note_external_read_for_key(
                        pipeline.device_key(started.device),
                    );
                    tokio::spawn(async move {
                        let _orphan_device = orphan_device;
                        let result = hash_task.await;
                        release_in_flight_hash(&timed_out_path, hash_claim);
                        if let Err(error) = result {
                            tracing::warn!(
                                "Timed-out reload hash task for {timed_out_name} failed while draining: {error}"
                            );
                        }
                    });
                    continue;
                }
            }
        }
        // Cancelling leaves the look-ahead window full of claimed, still-running
        // hashes; hand them off to drain rather than stranding their claims.
        pipeline.abandon();
        // A file another pass still held leaves this page unfinished, so the
        // resume cursor must not move past it. One that failed or stalled does
        // not: it fails the same way on every reload, and holding the cursor
        // for it kept a large folder on this page for good. The next walk of
        // the page retries it.
        let page_complete = pipeline.skipped() == 0;

        {
            let mut index = local_index.write().await;
            if was_cancelled {
                // Scope the pending cleanup to the folders this reload owns so a
                // concurrent folder-add scan keeps its in-progress entries —
                // and keep every placeholder that predates this pass or is one
                // of its own settling files. Those are the only holders of a
                // settling file's share state and restriction: a full pass
                // would otherwise wipe an earlier scoped pass's placeholders,
                // including ones on pages it never reached, and the recheck
                // would find those files new and public.
                let keep = placeholders_before_pass
                    .iter()
                    .cloned()
                    .chain(
                        settling
                            .iter()
                            .map(|file| crate::search::index::normalize_path_key(&file.path)),
                    )
                    .collect::<HashSet<_>>();
                remove_pending_rows_except(&mut index, &reloaded_folders, &keep);
            }
            index.rebuild();
        }

        // Gates the chained continuation below. A chained page re-reads the
        // cursor from config, so it can only make progress if this page's
        // cursor both moved and reached disk; otherwise it would rescan exactly
        // what just ran.
        let mut resume_point_advanced = false;
        if !was_cancelled && page_complete && !scoped {
            let cursor_updates = discovery_cursor_updates
                .into_iter()
                .filter(|(folder, _)| {
                    reloaded_folders
                        .iter()
                        .any(|active| paths_equal_ignore_case(active, folder))
                })
                .collect::<std::collections::HashMap<_, _>>();
            let advanced = cursor_updates.iter().any(|(folder, next)| {
                let key = crate::search::index::normalize_path_key(folder);
                next.as_deref() != cursors_before_scan.get(&key).map(String::as_str)
            });
            let app_state = app.state::<AppState>();
            match persist_scan_cursors(&app_state, &cursor_updates, false).await {
                Ok(()) => resume_point_advanced = advanced,
                Err(error) => warn!(
                    "Shared-folder scan page was indexed but its resume cursor was not saved: {error}"
                ),
            }
        }
        refresh_file_cache(&local_index, &file_cache).await;

        if !was_cancelled {
            // Announcing only adds to the publish set, so a scoped pass need
            // only offer what it examined.
            let all_files = {
                let index = local_index.read().await;
                index
                    .all_files()
                    .iter()
                    .filter(|f| {
                        !f.hash.is_empty()
                            && (!scoped || file_in_shared_folders(&f.path, &reloaded_folders))
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            };
            if !all_files.is_empty() {
                if let Err(e) =
                    network_tx.try_send(NetworkCommand::AnnounceFiles { files: all_files })
                {
                    warn!("Failed to queue AnnounceFiles on reload: {e}");
                }
            }
        }

        reconcile_shared_files_best_effort(&network_tx).await;
        if !was_cancelled {
            // Same post-pass intent sweep as the folder-add scan above.
            let app_state = app.state::<AppState>();
            prune_pending_intents_for_hashed(&app_state).await;
            // Only now, with every file that could not be served already
            // hashed, hand the optional repairs to the background. Cancelling
            // the reload skips this too: Stop means leave the disks alone.
            queue_hash_top_up(app.clone(), &needs_top_up).await;
        }
        // Even after a cancel: the placeholders stay, and a recheck that
        // arrives during Stop or shutdown declines on its own.
        if !settling.is_empty() {
            schedule_settle_recheck(&app, &settling, settle_now);
        }
        remove_cancel_flag_if_current(&cancel_flags, &reload_key, &cancel_flag).await;

        let from_known = total_files.saturating_sub(total_to_hash);
        info!(
            "Reload complete: {hashed_count}/{total_to_hash} hashed, {from_known} from known.met{}",
            if was_cancelled { " (cancelled)" } else { "" }
        );

        let _ = app.emit(
            "file-hash-progress",
            serde_json::json!({
                "current": total_to_hash,
                "total": total_to_hash,
                "file_name": "",
                "done": true,
            }),
        );

        // This page stopped at the cap, so the folder has more files that only
        // a later page can reach. Queue that page ourselves — nothing else
        // advances the cursor without the user pressing Reload again.
        if discovery_truncated && resume_point_advanced && chained_pages_left > 0 {
            info!(
                "Shared-folder scan page hit the file cap; queueing the next page in {}s ({} left this pass)",
                CHAINED_SCAN_PAGE_DELAY.as_secs(),
                chained_pages_left,
            );
            schedule_chained_scan_page(app.clone(), chained_pages_left - 1).await;
        }
        drop(scan_guard);
    });

    // Track the reload scan so shutdown can wait for / abort it before the
    // on-exit known.met / local_index flush (see add_shared_folder).
    state.register_background_scan(scan_handle).await;

    Ok(())
}

#[tauri::command]
pub fn get_scan_status(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    Ok(state.scanning_count.load(Ordering::Relaxed) > 0)
}

#[tauri::command]
pub fn get_library_scan_truncated(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    Ok(state.library_scan_truncated.load(Ordering::Relaxed))
}

/// Shared folders that would actually lose files if hashing stopped right now.
///
/// A folder qualifies only when it holds a row with **no hash yet** — something
/// this scan discovered and has not finished hashing. The one-time digest
/// top-up rows deliberately do not count: they already carry their ed2k hash,
/// their share state and their counters, `abandon_hash_placeholder` keeps them
/// on cancel, and the digests computed so far are already in `known.met`. So
/// stopping a migration pass costs nothing and must not be described as if it
/// did.
///
/// That distinction is the whole point of this function existing separately
/// from [`stop_hashing`]. The confirmation dialog used to warn unconditionally,
/// before anything had worked out whether there was anything to warn about — and
/// the case where there is nothing is the common one, because upgrading a large
/// library queues every file for a digest top-up and not one of them is at risk.
/// A user with a 46,000-file library was told they would lose folders for
/// stopping a pass that could not lose them anything, and so did not stop it.
async fn folders_losing_files_on_stop(state: &AppState) -> Vec<String> {
    let shared_folders = {
        let config = state.config.read().await;
        config.settings.shared_folders.clone()
    };
    // One pass over the index rather than a full clone of it. This now runs
    // twice per stop — once for the dialog's preview and once for the stop
    // itself — and `all_files().to_vec()` on a large library is tens of
    // thousands of `FileInfo` clones each time. Most rows carry a hash and are
    // rejected on the first test, so the folder loop only runs for the few that
    // are actually still waiting.
    let mut at_risk: HashSet<String> = HashSet::new();
    {
        let index = state.local_index.read().await;
        for file in index.all_files() {
            if !file.hash.is_empty() {
                continue;
            }
            for folder in &shared_folders {
                if crate::security::path_within_dir(&file.path, folder) {
                    at_risk.insert(folder.clone());
                }
            }
        }
    }

    // A per-folder scan still in flight may be about to add unhashed rows, so
    // its folder counts even if nothing unhashed is indexed yet. The special
    // `__reload__` / `__startup__` keys are whole-library passes and are named
    // by the rows above instead.
    let flags = state.hash_cancel_flags.read().await;
    for key in flags.keys() {
        if !key.starts_with("__") {
            at_risk.insert(key.clone());
        }
    }
    drop(flags);

    let mut result = at_risk.into_iter().collect::<Vec<_>>();
    result.sort();
    result
}

/// What [`stop_hashing`] would cost, without stopping anything.
///
/// Read-only, so the confirmation dialog can say what will actually happen
/// rather than warning by default.
#[tauri::command]
pub async fn preview_stop_hashing(state: tauri::State<'_, AppState>) -> Result<Vec<String>, String> {
    Ok(folders_losing_files_on_stop(&state).await)
}

#[tauri::command]
pub async fn stop_hashing(state: tauri::State<'_, AppState>) -> Result<Vec<String>, String> {
    // Latch pause before signalling cancel so a concurrent FS-watcher tick
    // cannot start a new reload that races past the cancel flags.
    state.hashing_paused.store(true, Ordering::Relaxed);

    let result = folders_losing_files_on_stop(&state).await;

    let flags = state.hash_cancel_flags.read().await;
    let count = flags.len();
    for flag in flags.values() {
        flag.store(true, Ordering::Relaxed);
    }
    drop(flags);
    // Stop means stop reading from the drives, and the background digest pass
    // is reading from them too. It is not represented in `hash_cancel_flags`
    // because it deliberately outlives the scan that queued it.
    cancel_hash_top_up().await;
    info!("Stop hashing requested, cancelled {count} active tasks");
    Ok(result)
}

/// How far along the background hash top-up is, or `None` when it is not
/// running.
///
/// Polled rather than pushed: it is a quiet, hours-long background pass, and an
/// event per file would be thousands of webview wakeups to move a number the
/// user is not watching.
#[tauri::command]
pub async fn hash_top_up_status() -> Result<Option<(usize, usize)>, String> {
    Ok(hash_top_up_progress().await)
}

#[tauri::command]
pub async fn resume_hashing(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    reload_shared_files(app, state).await
}

#[tauri::command]
pub async fn unshare_file(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    file_path: String,
    file_hash: Option<String>,
) -> Result<(), String> {
    let mutation = {
        let mut index = state.local_index.write().await;
        if index.get_by_path(&file_path).is_none() {
            // Surface a desync instead of silently reporting success: the UI
            // asked to unshare a path the backend index doesn't know about.
            return Err(coded(
                "sharing_file_not_in_index",
                "File not found in shared index",
            ));
        }
        index.set_file_shared_by_path(&file_path, false)
    };
    if mutation.changed_paths > 0 {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        persist_share_mutation(&state, &mutation, false).await?;
        let _ = app.emit(
            "shared-files-changed",
            serde_json::json!({ "unshared": mutation.changed_paths }),
        );
        info!(
            "Unshared {} file path(s) from {}{}",
            mutation.changed_paths,
            file_path,
            file_hash
                .filter(|hash| !hash.is_empty())
                .map(|hash| format!(" ({hash})"))
                .unwrap_or_default()
        );
    }
    // A partial share's allowlist is what the next scan offers. Leaving this
    // file on it would put it back on the network, and the picker would treat
    // it as already shared. Every path the mutation touched, not just the one
    // that was asked for: unsharing by hash also unshares the other copies,
    // which may sit in allowlists of their own.
    let mut cleared = mutation.hashed_paths;
    cleared.extend(mutation.pending_paths);
    if !cleared.iter().any(|path| path == &file_path) {
        cleared.push(file_path);
    }
    drop_from_allowlists(&state, &cleared).await?;
    Ok(())
}

/// Drop `paths` from every folder allowlist that names them. An empty list is
/// kept rather than removed: the folder stays shared, and nothing in it is
/// offered until the user shares the folder again.
pub(crate) async fn drop_from_allowlists(
    state: &AppState,
    paths: &[String],
) -> Result<(), String> {
    if paths.is_empty() {
        return Ok(());
    }
    let keys = paths
        .iter()
        .map(|path| crate::search::index::normalize_path_key(path))
        .collect::<HashSet<_>>();
    edit_folder_lists(state, |allowlists, withheld| withhold_keys(allowlists, withheld, &keys)).await
}

/// Take `keys` off the allowlists, and record the ones a partly shared folder
/// no longer offers as withheld, so discovery keeps walking them and the
/// Library keeps showing them, unshared, as it would in a folder shared whole.
fn withhold_keys(
    allowlists: &mut std::collections::HashMap<String, Vec<String>>,
    withheld: &mut std::collections::HashMap<String, Vec<String>>,
    keys: &HashSet<String>,
) -> bool {
    let mut changed = false;
    for (folder, files) in allowlists.iter_mut() {
        let before = files.len();
        files.retain(|item| !keys.contains(item));
        changed |= files.len() != before;
        let allowed = files.iter().cloned().collect::<HashSet<_>>();
        let mut newly = keys
            .iter()
            .filter(|key| {
                crate::security::path_within_dir(key, folder) && !allowlist_permits(&allowed, key)
            })
            .peekable();
        if newly.peek().is_none() {
            continue;
        }
        let list = withheld.entry(folder.clone()).or_default();
        let mut listed = list.iter().cloned().collect::<HashSet<_>>();
        for key in newly {
            if listed.insert(key.clone()) {
                list.push(key.clone());
                changed = true;
            }
        }
    }
    changed
}

/// Put `paths` back on the allowlist of each partly shared folder they sit in.
/// Discovery walks only what an allowlist names, so a file shared again from
/// the Library but left off its folder's list would fall out of the index on
/// the next scan.
async fn readmit_to_allowlists(state: &AppState, paths: &[String]) -> Result<(), String> {
    let keys = paths
        .iter()
        .map(|path| crate::search::index::normalize_path_key(path))
        .collect::<Vec<_>>();
    edit_folder_allowlists(state, |lists| readmit_keys(lists, &keys)).await
}

fn readmit_keys(lists: &mut std::collections::HashMap<String, Vec<String>>, keys: &[String]) -> bool {
    let mut changed = false;
    for (folder, entries) in lists.iter_mut() {
        let mut allowed = entries.iter().cloned().collect::<HashSet<_>>();
        for key in keys {
            if crate::security::path_within_dir(key, folder) && !allowlist_permits(&allowed, key) {
                allowed.insert(key.clone());
                entries.push(key.clone());
                changed = true;
            }
        }
    }
    changed
}

/// Forget the allowlists of `folder` and anything nested under it, and any
/// entry in an enclosing share's allowlist that offers something inside it.
/// Used when the whole folder stops being offered, so nothing is left to
/// re-share its files the next time they are scanned.
async fn clear_allowlists_under(state: &AppState, folder: &str) -> Result<(), String> {
    edit_folder_allowlists(state, |lists| {
        let before = lists.len();
        lists.retain(|listed, _| !crate::security::path_within_dir(listed, folder));
        let mut changed = lists.len() != before;
        for entries in lists.values_mut() {
            let before = entries.len();
            entries.retain(|entry| !crate::security::path_within_dir(entry, folder));
            changed |= entries.len() != before;
        }
        changed
    })
    .await
}

/// Stop the allowlists offering anything under `folder`, for a folder being
/// unshared while it stays shared. Entries inside it go, and a partly shared
/// folder at or under it keeps an empty list rather than none: a folder with
/// no list is shared whole, and discovery never walked the rest of its files,
/// so no known.met record would stop the next scan offering them. `indexed`
/// are the Library's paths under `folder`; the ones a partly shared folder no
/// longer offers are withheld, so they stay listed as unshared.
async fn withhold_allowlists_under(
    state: &AppState,
    folder: &str,
    indexed: &[String],
) -> Result<(), String> {
    let keys = indexed
        .iter()
        .map(|path| crate::search::index::normalize_path_key(path))
        .collect::<HashSet<_>>();
    edit_folder_lists(state, |allowlists, withheld| {
        withhold_under(allowlists, withheld, folder, &keys)
    })
    .await
}

fn withhold_under(
    allowlists: &mut std::collections::HashMap<String, Vec<String>>,
    withheld: &mut std::collections::HashMap<String, Vec<String>>,
    folder: &str,
    keys: &HashSet<String>,
) -> bool {
    let mut changed = false;
    for (listed, entries) in allowlists.iter_mut() {
        let before = entries.len();
        if crate::security::path_within_dir(listed, folder) {
            entries.clear();
        } else {
            entries.retain(|entry| !crate::security::path_within_dir(entry, folder));
        }
        changed |= entries.len() != before;
    }
    withhold_keys(allowlists, withheld, keys) || changed
}

#[tauri::command]
pub async fn share_file(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<(), String> {
    let mutation = {
        let mut index = state.local_index.write().await;
        if index.get_by_path(&file_path).is_none() {
            // Surface a desync instead of silently reporting success: the UI
            // asked to share a path the backend index doesn't know about.
            return Err(coded(
                "sharing_file_not_in_index",
                "File not found in shared index",
            ));
        }
        if index
            .get_by_path(&file_path)
            .is_some_and(|file| file.hash.is_empty())
        {
            return Err(coded(
                "sharing_file_hash_pending",
                "File is still hashing and cannot be shared individually",
            ));
        }
        index.set_file_shared_by_path(&file_path, true)
    };
    if mutation.changed_paths > 0 {
        let mut readmitted = mutation.hashed_paths.clone();
        if !readmitted.iter().any(|path| path == &file_path) {
            readmitted.push(file_path.clone());
        }
        readmit_to_allowlists(&state, &readmitted).await?;
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        persist_share_mutation(&state, &mutation, true).await?;
        let _ = app.emit(
            "shared-files-changed",
            serde_json::json!({ "shared": mutation.changed_paths }),
        );
        info!(
            "Shared {} file path(s) from {}",
            mutation.changed_paths, file_path
        );
    }
    Ok(())
}

#[tauri::command]
pub async fn unshare_folder(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<(), String> {
    // The allowlist and row changes below are drive-aware, so a request naming
    // a drive that is not shared would otherwise lift every allowlist on it.
    {
        let config = state.config.read().await;
        if !unshare_target_is_shared(&config.settings.shared_folders, &path) {
            return Err(coded_ctx(
                "sharing_folder_not_shared",
                "Folder is not in a shared folder",
                &path,
            ));
        }
    }
    // Before the index write, so a failure here cannot leave an allowlist
    // that re-offers the folder's files on the next scan.
    let indexed = {
        let index = state.local_index.read().await;
        index
            .all_files()
            .iter()
            .filter(|file| crate::security::path_within_dir(&file.path, &path))
            .map(|file| file.path.clone())
            .collect::<Vec<_>>()
    };
    withhold_allowlists_under(&state, &path, &indexed).await?;
    let mutation = state.local_index.write().await.set_shared_by_path_prefix(&path, false);
    if mutation.changed_paths > 0 {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        persist_share_mutation(&state, &mutation, false).await?;
        let _ = app.emit(
            "shared-files-changed",
            serde_json::json!({
                "folder": path,
                "unshared": mutation.changed_paths,
            }),
        );
    }
    Ok(())
}

#[tauri::command]
pub async fn delete_shared_file(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    file_path: String,
    file_hash: Option<String>,
) -> Result<(), String> {
    if file_path.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "sharing_file_path_too_long",
            format!("File path exceeds {MAX_PATH_LEN} bytes"),
            MAX_PATH_LEN,
        ));
    }
    // This command is the Library's destructive action. Do not let its broad
    // shared/download containment scope become a generic delete primitive for
    // active `.part` files or any other unindexed download.
    let indexed_path = {
        let index = state.local_index.read().await;
        index
            .get_by_path(&file_path)
            .map(|file| file.path.clone())
            .ok_or_else(|| {
                coded(
                    "sharing_file_not_in_index",
                    "File is not in the shared-file index",
                )
            })?
    };
    let allowed_dirs = {
        let config = state.config.read().await;
        shared_access_dirs(&config)
    };

    let (canonical, expected_identity) = tokio::task::spawn_blocking({
        let file_path = file_path.clone();
        let indexed_path = indexed_path.clone();
        let allowed_dirs = allowed_dirs.clone();
        move || -> Result<
            (
                std::path::PathBuf,
                crate::security::filesystem::ObjectIdentity,
            ),
            String,
        > {
            let path = std::path::Path::new(&file_path);
            let (canonical, opened) =
                crate::security::filesystem::open_existing_approved(path, &allowed_dirs, false)
                    .map_err(|e| {
                        coded_ctx("sharing_invalid_path", "Invalid or changed path", e)
                    })?;
            let indexed_canonical = crate::security::filesystem::verify_existing_path(
                std::path::Path::new(&indexed_path),
                &allowed_dirs,
            )
            .map_err(|e| {
                coded_ctx(
                    "sharing_file_not_in_index",
                    "Indexed file can no longer be resolved",
                    e,
                )
            })?;
            if canonical != indexed_canonical {
                return Err(coded(
                    "sharing_file_not_in_index",
                    "File is not the indexed Library entry",
                ));
            }
            let identity = crate::security::filesystem::opened_file_identity(&opened)
                .map_err(|e| coded_ctx("sharing_invalid_path", "Invalid or changed path", e))?;
            Ok((canonical, identity))
        }
    })
    .await
    .map_err(|e| coded_ctx("sharing_task_failed", "Task failed", e))??;

    delete_file_with_retry(&canonical, &allowed_dirs, &expected_identity, 6, 250).await?;

    let canonical_str = canonical.to_string_lossy().to_string();
    let (removed, removed_hashes, unpublish) = {
        let mut index = state.local_index.write().await;
        let removed = index
            .remove_file_by_path(&canonical_str)
            .or_else(|| index.remove_file_by_path(&file_path));
        let hashes = removed
            .as_ref()
            .and_then(|file| fresh_part_hash_key(&file.hash))
            .into_iter()
            .collect::<HashSet<_>>();
        let hashes = unreferenced_fresh_part_hashes(index.all_files(), &hashes);
        let gone: Vec<String> = removed.as_ref().map(|file| file.hash.clone()).into_iter().collect();
        let unpublish = hashes_no_longer_offered(&index, &gone);
        (removed, hashes, unpublish)
    };
    discard_fresh_part_hashes(&state.fresh_part_hashes, &removed_hashes).await;
    refresh_file_cache(&state.local_index, &state.cached_shared_files).await;

    // The reconcile cannot infer this one. Deleting a file leaves its known.met
    // record standing and says `is_shared` all the same, so the hash has to be
    // named here or its Ember records live out their TTL and light the badge
    // again on the next launch.
    unpublish_ember_files(&state.network_tx, unpublish).await;
    reconcile_shared_files_best_effort(&state.network_tx).await;
    let _ = app.emit(
        "shared-files-changed",
        serde_json::json!({ "file_deleted": true }),
    );

    info!(
        "Deleted shared file {}{}{}",
        canonical.display(),
        if removed.is_none() {
            " (index race)"
        } else {
            ""
        },
        file_hash
            .filter(|hash| !hash.is_empty())
            .map(|hash| format!(" ({hash})"))
            .unwrap_or_default()
    );
    Ok(())
}

/// Check the filesystem for every file being offered and return the list of
/// paths that no longer exist. This is cheap (a single metadata lookup per
/// file); typical libraries finish in well under a second even with tens of
/// thousands of files. Callers can then display the count and offer a bulk
/// "remove missing" action via `remove_missing_files`.
///
/// `paths` is capped at [`MAX_SCAN_MISSING_RESULTS`]; when the cap is hit,
/// `truncated` is true and `total_missing` still reflects the full count so
/// the UI can warn instead of silently under-counting.
#[tauri::command]
pub async fn scan_missing_files(
    state: tauri::State<'_, AppState>,
) -> Result<MissingScanResult, String> {
    // Offered files only. The Library lists what peers can download, so a
    // count that also included files the user has taken off the network
    // would not match the rows the "Missing" filter can show — and a file
    // nobody is being offered going missing is not a problem to report.
    let paths: Vec<String> = {
        let index = state.local_index.read().await;
        index
            .all_files()
            .iter()
            .filter(|file| file.shared)
            .map(|file| file.path.clone())
            .collect()
    };
    let result = tokio::task::spawn_blocking(move || {
        let mut missing = Vec::new();
        let mut total_missing: u32 = 0;
        for p in paths {
            if !std::path::Path::new(&p).exists() {
                total_missing = total_missing.saturating_add(1);
                if missing.len() < MAX_SCAN_MISSING_RESULTS {
                    missing.push(p);
                }
            }
        }
        MissingScanResult {
            truncated: (total_missing as usize) > missing.len(),
            total_missing,
            paths: missing,
        }
    })
    .await
    .map_err(|e| coded_ctx("sharing_scan_task_failed", "Scan task failed", e))?;
    Ok(result)
}

/// Remove the given paths from the shared-file index if — and only if —
/// they no longer exist on disk. This double-check protects against races
/// where a file reappears (e.g. an external drive mounts back) between the
/// missing-scan and the user's confirmation click.
#[tauri::command]
pub async fn remove_missing_files(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    paths: Vec<String>,
) -> Result<u32, String> {
    if paths.is_empty() {
        return Ok(0);
    }
    check_path_batch(&paths, MAX_REMOVE_MISSING_PATHS)?;
    // Drop empty / over-long entries up front: they can't name a real shared
    // file and we don't want to spend a stat() syscall on an attacker-sized path.
    let to_check: Vec<String> = paths
        .into_iter()
        .filter(|p| !p.is_empty() && p.len() <= MAX_PATH_LEN)
        .collect();
    if to_check.is_empty() {
        return Ok(0);
    }
    let really_missing = tokio::task::spawn_blocking(move || {
        to_check
            .into_iter()
            .filter(|p| !std::path::Path::new(p).exists())
            .collect::<Vec<_>>()
    })
    .await
    .map_err(|e| coded_ctx("sharing_scan_task_failed", "Scan task failed", e))?;

    let (removed, removed_hashes, unpublish) = {
        let mut removed = 0u32;
        let mut removed_hashes = HashSet::new();
        let mut gone = Vec::new();
        let mut index = state.local_index.write().await;
        for path in &really_missing {
            if let Some(file) = index.remove_file_by_path(path) {
                removed += 1;
                if let Some(hash) = fresh_part_hash_key(&file.hash) {
                    removed_hashes.insert(hash);
                }
                gone.push(file.hash);
            }
        }
        let removed_hashes = unreferenced_fresh_part_hashes(index.all_files(), &removed_hashes);
        let unpublish = hashes_no_longer_offered(&index, &gone);
        (removed, removed_hashes, unpublish)
    };
    if removed > 0 {
        discard_fresh_part_hashes(&state.fresh_part_hashes, &removed_hashes).await;
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        unpublish_ember_files(&state.network_tx, unpublish).await;
        reconcile_shared_files_best_effort(&state.network_tx).await;
        let _ = app.emit(
            "shared-files-changed",
            serde_json::json!({ "missing_removed": removed }),
        );
        info!("Removed {} missing files from shared index", removed);
    }
    Ok(removed)
}

#[tauri::command]
pub async fn republish_file(
    state: tauri::State<'_, AppState>,
    file_hash: String,
) -> Result<(), String> {
    let cleaned = file_hash.trim().to_lowercase();
    if cleaned.len() != 32 || hex::decode(&cleaned).is_err() {
        return Err(coded(
            "sharing_invalid_file_hash",
            "Invalid file hash (expected 32-char hex MD4)",
        ));
    }
    let file_exists = {
        let index = state.local_index.read().await;
        index
            .all_files()
            .iter()
            .any(|f| !f.hash.is_empty() && f.hash.eq_ignore_ascii_case(&cleaned))
    };
    if !file_exists {
        return Err(coded(
            "sharing_file_not_in_index",
            "File not found in shared index",
        ));
    }
    state
        .network_tx
        .try_send(NetworkCommand::RepublishFile {
            file_hash_hex: cleaned,
        })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    Ok(())
}

#[tauri::command]
pub async fn open_shared_file(
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<(), String> {
    if file_path.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "sharing_file_path_too_long",
            format!("File path exceeds {MAX_PATH_LEN} bytes"),
            MAX_PATH_LEN,
        ));
    }
    let allowed_dirs = {
        let config = state.config.read().await;
        shared_access_dirs(&config)
    };
    let (declared_name, indexed_path) = {
        let index = state.local_index.read().await;
        let file = index.get_by_path(&file_path).ok_or_else(|| {
            coded(
                "sharing_file_not_in_index",
                "File is not in the shared-file index",
            )
        })?;
        (file.name.clone(), file.path.clone())
    };

    tokio::task::spawn_blocking(move || {
        let path = std::path::Path::new(&file_path);
        if !path.exists() {
            return Err(coded("sharing_file_not_exist", "File does not exist"));
        }
        let canonical = crate::security::filesystem::verify_existing_path(path, &allowed_dirs)
            .map_err(|e| coded_ctx("sharing_invalid_path", "Invalid or changed path", e))?;
        let indexed_canonical = crate::security::filesystem::verify_existing_path(
            std::path::Path::new(&indexed_path),
            &allowed_dirs,
        )
        .map_err(|e| coded_ctx("sharing_file_not_in_index", "Indexed path changed", e))?;
        if canonical != indexed_canonical {
            return Err(coded(
                "sharing_file_not_in_index",
                "File is not the indexed Library entry",
            ));
        }
        if crate::security::filesystem::passive_type_agrees(&declared_name, &canonical) {
            crate::security::filesystem::open_with_default_app(&canonical)
                .map_err(|e| coded_ctx("sharing_open_file_failed", "Failed to open file", e))?;
        } else {
            crate::security::filesystem::reveal_in_file_manager(&canonical).map_err(|e| {
                coded_ctx(
                    "sharing_reveal_unsafe_file_failed",
                    "This file type was revealed instead of opened",
                    e,
                )
            })?;
        }
        Ok(())
    })
    .await
    .map_err(|e| coded_ctx("sharing_task_failed", "Task failed", e))?
}

/// Validate that `file_path` is a real file inside a shared/download folder and
/// return its canonical path for `convertFileSrc` / in-app media playback.
#[tauri::command]
pub async fn resolve_media_asset_path(
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<String, String> {
    if file_path.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "sharing_file_path_too_long",
            format!("File path exceeds {MAX_PATH_LEN} bytes"),
            MAX_PATH_LEN,
        ));
    }
    let allowed_dirs = {
        let config = state.config.read().await;
        shared_access_dirs(&config)
    };

    tokio::task::spawn_blocking(move || {
        // Containment first, and one error code for every way it can fail.
        // Unlike `open_shared_file`, nothing here requires the path to be in
        // the index, so the earlier `exists()` / `is_file()` pre-checks
        // answered "does this path exist?" about *any* path a compromised
        // renderer cared to name — the distinct codes were the oracle. Mirrors
        // `get_file_media_metadata`, which already checks containment first.
        let path = std::path::Path::new(&file_path);
        let canonical = crate::security::filesystem::verify_existing_path(path, &allowed_dirs)
            .map_err(|e| coded_ctx("sharing_invalid_path", "Invalid or changed path", e))?;
        // Safe to distinguish now: the path is already known to live inside an
        // approved root, so this tells the caller nothing it could not see.
        if !canonical.is_file() {
            return Err(coded("sharing_not_a_file", "Path is not a file"));
        }
        if !crate::security::filesystem::passive_type_agrees(&file_path, &canonical) {
            return Err(coded(
                "sharing_dangerous_file",
                "File type is not approved for in-app media",
            ));
        }
        Ok(canonical.to_string_lossy().into_owned())
    })
    .await
    .map_err(|e| coded_ctx("sharing_task_failed", "Task failed", e))?
}

#[tauri::command]
pub async fn open_shared_folder(
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<(), String> {
    if file_path.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "sharing_file_path_too_long",
            format!("File path exceeds {MAX_PATH_LEN} bytes"),
            MAX_PATH_LEN,
        ));
    }
    let allowed_dirs = {
        let config = state.config.read().await;
        shared_access_dirs(&config)
    };

    tokio::task::spawn_blocking(move || {
        let path = std::path::Path::new(&file_path);
        let folder = path.parent().unwrap_or(path);
        // Containment first, one code for every failure — see
        // `resolve_media_asset_path`. The `exists()` pre-check here reported
        // whether the *parent* of any renderer-supplied path existed, under a
        // different code than the containment failure.
        let canonical = crate::security::filesystem::verify_existing_path(folder, &allowed_dirs)
            .map_err(|e| coded_ctx("sharing_invalid_path", "Invalid or changed path", e))?;
        // `verify_existing_path` accepts regular files too, and a renderer
        // path of `<file>\_` has that file as its parent. Handing a file to
        // the default-app launcher executes it, so only a directory may pass.
        if !canonical.is_dir() {
            return Err(coded("sharing_invalid_path", "Invalid or changed path"));
        }
        // Opened, not revealed. `reveal_in_file_manager` selects its argument
        // *inside the argument's own parent*, so handing it the containing
        // folder opened the grandparent with the folder merely highlighted —
        // on Windows via `explorer /select,`, and on Linux via
        // `ShowItems`. This action names the folder it is meant to show.
        crate::security::filesystem::open_with_default_app(&canonical)
            .map_err(|e| coded_ctx("sharing_open_folder_failed", "Failed to open folder", e))?;
        Ok(())
    })
    .await
    .map_err(|e| coded_ctx("sharing_task_failed", "Task failed", e))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_in_library_matches_case_insensitively_and_skips_unhashed_rows() {
        let wanted = vec![
            "AABBCCDDEEFF00112233445566778899".to_string(),
            "0000000000000000000000000000abcd".to_string(),
            String::new(),
            "abc".to_string(),
        ];
        let library = [
            "",
            "abc",
            "aabbccddeeff00112233445566778899",
            "aabbccddeeff00112233445566778899",
            "ffffffffffffffffffffffffffffffff",
        ];
        assert_eq!(
            hashes_in_library(&wanted, library),
            vec!["aabbccddeeff00112233445566778899".to_string()],
        );

        let upper_library = ["0000000000000000000000000000ABCD"];
        assert_eq!(
            hashes_in_library(&wanted, upper_library),
            vec!["0000000000000000000000000000abcd".to_string()],
        );
    }

    fn indexed_file(path: &str, hash: &str) -> FileInfo {
        FileInfo {
            id: hash.to_string(),
            name: "file.bin".to_string(),
            path: path.to_string(),
            size: 1,
            hash: hash.to_string(),
            aich_hash: String::new(),
            ember_file_hash: String::new(),
            extension: "bin".to_string(),
            modified_at: 0,
            priority: "normal".to_string(),
            requests: 0,
            accepted: 0,
            bytes_transferred: 0,
            alltime_requests: 0,
            alltime_accepted: 0,
            alltime_transferred: 0,
            complete_sources: 0,
            folder: String::new(),
            shared: true,
            friends_only: false,
            shared_kad: false,
            shared_ed2k: false,
            shared_ember: false,
        }
    }

    /// The narrow queue row has to reach the same verdict as the full row it
    /// was built from, for every combination of what is already stored.
    ///
    /// It exists to keep a whole `FileInfo` per queued file out of memory, and
    /// the way that goes wrong is silently: a row that `wants_hash_top_up`
    /// accepts but `TopUpRow` declines is a repair that never happens, with
    /// nothing to show for it. Both sides answer through `wanted_digests` for
    /// exactly this reason — this pins that they still do.
    #[test]
    fn the_narrow_queue_row_decides_what_the_full_row_would() {
        let multi_part = crate::network::ed2k::hash::PARTSIZE;
        for (aich, ember, size) in [
            ("", "", multi_part),          // both wanted
            ("", "", 1),                   // single part: ember only
            ("aich", "", multi_part),      // ember only
            ("", "ember", multi_part),     // aich only
            ("aich", "ember", multi_part), // nothing wanted
            ("aich", "ember", 1),
        ] {
            let mut file = indexed_file("C:/s/f.bin", "ab".repeat(16).as_str());
            file.aich_hash = aich.to_string();
            file.ember_file_hash = ember.to_string();
            file.size = size;

            let row = TopUpRow::from_file(&file);
            assert_eq!(
                row.is_some(),
                wants_hash_top_up(&file),
                "queued-or-not disagreed for aich={aich:?} ember={ember:?} size={size}"
            );
            if let Some(row) = row {
                assert_eq!(
                    row.top_up().map(|(_, _, _, want)| want),
                    top_up_inputs(&file).map(|(_, _, _, want)| want),
                    "asked for different digests for aich={aich:?} ember={ember:?} size={size}"
                );
            }
        }

        // A row that was never hashed belongs to the scan, not here, whichever
        // side is asked.
        let mut unhashed = indexed_file("C:/s/new.bin", "");
        unhashed.hash = String::new();
        assert!(TopUpRow::from_file(&unhashed).is_none());
        assert!(!wants_hash_top_up(&unhashed));
    }

    fn known_record(
        path: &str,
        hash: [u8; 16],
        ember: &str,
    ) -> crate::storage::known_files::KnownFileRecord {
        crate::storage::known_files::KnownFileRecord {
            file_hash: hash,
            part_hashes: Vec::new(),
            file_name: "file.bin".to_string(),
            file_size: 1,
            file_path: path.to_string(),
            aich_hash: "cd".repeat(20),
            ember_file_hash: ember.to_string(),
            modified_at: 0,
            all_time_transferred: 0,
            all_time_requested: 0,
            all_time_accepted: 0,
            upload_priority: 0,
            last_publish_src: 0,
            last_shared: 0,
            is_shared: true,
            friends_only: false,
            complete_sources: 0,
            last_ember_source_publish: 0,
            last_ember_keyword_publish: 0,
            media: None,
            media_scanned: false,
        }
    }

    /// The change the reporter's library needed: a file that `known.met`
    /// already fully describes, and that lacks only the Ember digest, must not
    /// go into the scan's hash queue. It is servable exactly as it is, and
    /// queueing it there is what turned a Reload into a multi-day re-read of
    /// every byte on four external drives — for a check that aMule, which has
    /// no such digest, never performs at all.
    #[test]
    fn a_file_missing_only_its_digest_does_not_hold_up_the_scan() {
        let mut known = KnownFileList::new();
        known.add_or_update(known_record("C:/L/file.bin", [0x11; 16], ""));

        let mut discovered = vec![indexed_file("C:/L/file.bin", "")];
        discovered[0].size = 1;
        discovered[0].modified_at = 0;
        let work = resolve_from_known(&mut discovered, &known);

        assert!(
            work.needs_hashing.is_empty(),
            "nothing here blocks the Library from being complete"
        );
        assert_eq!(work.needs_top_up.len(), 1, "the digest is still wanted");
        // And the row itself stays a first-class, servable entry: no placeholder
        // id, and the real ed2k hash in place.
        assert_eq!(discovered[0].hash, hex::encode([0x11; 16]));
        assert_eq!(discovered[0].id, hex::encode([0x11; 16]));
        assert!(
            !discovered[0]
                .id
                .starts_with(crate::search::index::REHASH_ID_PREFIX),
            "a background top-up must not put the row into a placeholder state"
        );
    }

    /// The other side of the split, which must not regress: a file with no
    /// usable record cannot be served at all until it is hashed, so the scan
    /// still waits for it.
    #[test]
    fn a_file_with_no_record_still_blocks_the_scan() {
        let known = KnownFileList::new();
        let mut discovered = vec![indexed_file("C:/L/new.bin", "")];
        let work = resolve_from_known(&mut discovered, &known);
        assert_eq!(work.needs_hashing.len(), 1);
        assert!(work.needs_top_up.is_empty());
    }

    #[test]
    fn sharing_a_file_again_puts_it_back_on_its_folders_allowlist() {
        let sep = std::path::MAIN_SEPARATOR;
        let folder = crate::search::index::normalize_path_key(&format!("C:{sep}music"));
        let kept = format!("{folder}{sep}a.mp3");
        let back = format!("{folder}{sep}b.mp3");
        let elsewhere = crate::search::index::normalize_path_key(&format!("D:{sep}films{sep}c.mkv"));
        let mut lists = std::collections::HashMap::new();
        lists.insert(folder.clone(), vec![kept.clone()]);

        assert!(readmit_keys(&mut lists, &[back.clone(), back.clone(), elsewhere]));
        assert_eq!(lists[&folder], vec![kept.clone(), back.clone()]);
        assert!(!readmit_keys(&mut lists, &[kept]), "an entry already on the list is left alone");
    }

    #[test]
    fn a_file_unshared_from_a_partial_share_stays_walked_until_shared_again() {
        let sep = std::path::MAIN_SEPARATOR;
        let folder = crate::search::index::normalize_path_key(&format!("C:{sep}music"));
        let a = format!("{folder}{sep}a.mp3");
        let b = format!("{folder}{sep}b.mp3");
        let sub = format!("{folder}{sep}live");
        let in_sub = format!("{sub}{sep}c.mp3");
        let elsewhere = crate::search::index::normalize_path_key(&format!("D:{sep}films{sep}d.mkv"));
        let mut lists = std::collections::HashMap::from([(folder.clone(), vec![a.clone(), b.clone(), sub.clone()])]);
        let mut withheld = std::collections::HashMap::new();

        let keys = HashSet::from([a.clone(), in_sub.clone(), elsewhere]);
        assert!(withhold_keys(&mut lists, &mut withheld, &keys));
        assert_eq!(lists[&folder], vec![b.clone(), sub.clone()], "no longer offered");
        // A file inside an offered folder entry is still offered by the list,
        // so it is not withheld; one outside every partial share has nothing
        // to be withheld from.
        assert_eq!(withheld, std::collections::HashMap::from([(folder.clone(), vec![a.clone()])]));
        let walked = crate::sharing::indexer::discovery_lists(&lists, &withheld);
        assert!(walked[&folder].contains(&a), "discovery still walks it");

        // Shared again: back on the list, and no longer withheld.
        assert!(readmit_keys(&mut lists, std::slice::from_ref(&a)));
        assert!(tidy_withheld(&lists, &mut withheld));
        assert!(withheld.is_empty());

        // A folder that lost its allowlist is shared whole; nothing is withheld.
        withhold_keys(&mut lists, &mut withheld, &HashSet::from([b.clone()]));
        assert!(!withheld.is_empty());
        lists.clear();
        assert!(tidy_withheld(&lists, &mut withheld));
        assert!(withheld.is_empty());
    }

    /// Unsharing a partly shared folder must leave it limited, to nothing: with
    /// no list it would be shared whole, and the next scan would hash and offer
    /// every file discovery had never walked.
    #[test]
    fn unsharing_a_partial_share_keeps_it_limited_and_its_files_listed() {
        let sep = std::path::MAIN_SEPARATOR;
        let folder = crate::search::index::normalize_path_key(&format!("C:{sep}music"));
        let a = format!("{folder}{sep}a.mp3");
        let sub = format!("{folder}{sep}live");
        let in_sub = format!("{sub}{sep}c.mp3");
        let other = crate::search::index::normalize_path_key(&format!("D:{sep}films"));
        let film = format!("{other}{sep}d.mkv");
        let mut lists = std::collections::HashMap::from([
            (folder.clone(), vec![a.clone(), sub.clone()]),
            (other.clone(), vec![film.clone()]),
        ]);
        let mut withheld = std::collections::HashMap::new();

        let indexed = HashSet::from([in_sub.clone()]);
        assert!(withhold_under(&mut lists, &mut withheld, &sub, &indexed));
        assert_eq!(lists[&folder], vec![a.clone()], "a subfolder leaves the rest of the list");
        assert_eq!(withheld[&folder], vec![in_sub.clone()]);

        let indexed = HashSet::from([a.clone(), in_sub.clone()]);
        assert!(withhold_under(&mut lists, &mut withheld, &folder, &indexed));
        assert!(lists[&folder].is_empty(), "the folder keeps an empty list, not none");
        let mut listed = withheld[&folder].clone();
        listed.sort();
        assert_eq!(listed, vec![a.clone(), in_sub.clone()]);
        assert_eq!(lists[&other], vec![film], "another share is untouched");
        let scope = crate::sharing::indexer::DiscoveryScope::for_root(&folder, &lists);
        assert!(scope.is_some(), "discovery still walks only what is listed");
    }

    #[test]
    fn withholding_a_file_twice_lists_it_once() {
        let sep = std::path::MAIN_SEPARATOR;
        let folder = crate::search::index::normalize_path_key(&format!("C:{sep}music"));
        let a = format!("{folder}{sep}a.mp3");
        let b = format!("{folder}{sep}b.mp3");
        let mut lists = std::collections::HashMap::from([(folder.clone(), vec![a.clone(), b.clone()])]);
        let mut withheld = std::collections::HashMap::new();
        assert!(withhold_keys(&mut lists, &mut withheld, &HashSet::from([a.clone()])));
        assert!(!withhold_keys(&mut lists, &mut withheld, &HashSet::from([a.clone()])));
        assert!(withhold_keys(&mut lists, &mut withheld, &HashSet::from([a.clone(), b.clone()])));
        let mut listed = withheld[&folder].clone();
        listed.sort();
        assert_eq!(listed, vec![a, b]);
    }

    /// One folder past the page cap must not keep every other folder's deleted
    /// files in the index: each folder whose own page is complete reconciles.
    #[test]
    fn a_complete_folder_reconciles_while_another_folder_pages() {
        let sep = std::path::MAIN_SEPARATOR;
        let big = format!("C:{sep}big");
        let small = format!("C:{sep}small");
        let nested = format!("{big}{sep}inner");
        let reloaded = vec![big.clone(), small.clone(), nested.clone()];
        let incomplete = vec![big.clone()];
        assert_eq!(
            authoritative_folders(&reloaded, &incomplete),
            vec![small.clone()],
            "a share inside a partial one may owe rows to its page"
        );
        assert_eq!(authoritative_folders(&reloaded, &[]), reloaded);

        let path = |folder: &str, name: &str| format!("{folder}{sep}{name}");
        let mut index = LocalIndex::new();
        index.add_files(vec![
            indexed_file(&path(&big, "kept.bin"), &"a1".repeat(16)),
            indexed_file(&path(&big, "not-on-this-page.bin"), &"a2".repeat(16)),
            indexed_file(&path(&small, "kept.bin"), &"b1".repeat(16)),
            indexed_file(&path(&small, "deleted.bin"), &"b2".repeat(16)),
        ]);
        let discovered = vec![
            indexed_file(&path(&big, "kept.bin"), &"a1".repeat(16)),
            indexed_file(&path(&small, "kept.bin"), &"b1".repeat(16)),
        ];
        let authoritative = authoritative_folders(&[big.clone(), small.clone()], &incomplete);
        index.reconcile_files_for_folders(&authoritative, discovered, !authoritative.is_empty());
        assert!(index.get_by_path(&path(&big, "not-on-this-page.bin")).is_some());
        assert!(index.get_by_path(&path(&small, "deleted.bin")).is_none());
        assert!(index.get_by_path(&path(&small, "kept.bin")).is_some());
    }

    /// A subfolder that could not be listed this pass (antivirus, a NAS
    /// hiccup) keeps its rows, while the rest of its folder still reconciles.
    #[test]
    fn a_subfolder_that_could_not_be_listed_keeps_its_rows() {
        let sep = std::path::MAIN_SEPARATOR;
        let media = format!("C:{sep}media");
        let concerts = format!("{media}{sep}concerts");
        let other = format!("D:{sep}other");
        let path = |folder: &str, name: &str| format!("{folder}{sep}{name}");
        let mut index = LocalIndex::new();
        index.add_files(vec![
            indexed_file(&path(&concerts, "live.mkv"), &"a1".repeat(16)),
            indexed_file(&path(&media, "deleted.mkv"), &"a2".repeat(16)),
            indexed_file(&path(&other, "x.mkv"), &"a3".repeat(16)),
        ]);
        let unreadable = vec![concerts.clone(), path(&other, "sub")];
        let carried = rows_under_unreadable(&index, &unreadable, std::slice::from_ref(&media));
        assert_eq!(carried.len(), 1, "only rows under an unreadable folder of a reloaded root");

        index.reconcile_files_for_folders(std::slice::from_ref(&media), carried, true);
        assert!(index.get_by_path(&path(&concerts, "live.mkv")).is_some());
        assert!(index.get_by_path(&path(&media, "deleted.mkv")).is_none());
    }

    /// A 1.7.0 install unshared in known.met every file a partial share left
    /// off its list. Widening the list must bring those up shared, and nothing
    /// the user unshared themselves.
    #[test]
    fn widening_a_partial_share_admits_only_what_it_newly_offers() {
        let sep = std::path::MAIN_SEPARATOR;
        let folder = crate::search::index::normalize_path_key(&format!("C:{sep}music"));
        let file = |name: &str| format!("{folder}{sep}{name}");
        let live = file("live");
        let unshared = |name: &str, byte: u8| {
            let mut record = known_record(&file(name), [byte; 16], "");
            record.is_shared = false;
            record
        };
        let records = [
            unshared("stale.mp3", 1),
            unshared("withheld.mp3", 2),
            unshared(&format!("live{sep}by-hand.mp3"), 3),
            unshared("still-off.mp3", 4),
            unshared("intent.mp3", 5),
            known_record(&file("shared.mp3"), [6; 16], ""),
            unshared("outside.mp3", 7),
        ];
        let before = std::collections::HashMap::from([(folder.clone(), vec![live.clone()])]);
        let after = std::collections::HashMap::from([(
            folder.clone(),
            vec![
                live.clone(),
                file("stale.mp3"),
                file("withheld.mp3"),
                file("intent.mp3"),
                file("shared.mp3"),
                file("outside.mp3"),
            ],
        )]);
        let kept = HashSet::from([file("withheld.mp3"), file("intent.mp3")]);
        let under = vec![
            file("stale.mp3"),
            file("withheld.mp3"),
            live.clone(),
            file("still-off.mp3"),
            file("intent.mp3"),
            file("shared.mp3"),
        ];
        let admitted = newly_admitted_unshared(
            records.iter(),
            &under,
            &crate::sharing::indexer::AllowlistOffers::new(&before),
            &crate::sharing::indexer::AllowlistOffers::new(&after),
            &kept,
        );
        assert_eq!(admitted, vec![(file("stale.mp3"), hex::encode([1u8; 16]))]);

        // Lifting the list admits the whole folder, a drive root included.
        let drive = crate::search::index::normalize_path_key(&format!("D:{sep}"));
        let on_drive = unshared("x", 8);
        let on_drive = crate::storage::known_files::KnownFileRecord {
            file_path: format!("{drive}films{sep}x.mkv"),
            ..on_drive
        };
        let before = std::collections::HashMap::from([(drive.clone(), Vec::new())]);
        let admitted = newly_admitted_unshared(
            std::iter::once(&on_drive),
            std::slice::from_ref(&drive),
            &crate::sharing::indexer::AllowlistOffers::new(&before),
            &crate::sharing::indexer::AllowlistOffers::default(),
            &HashSet::new(),
        );
        assert_eq!(admitted.len(), 1);
    }

    #[test]
    fn folder_allowlists_unshare_new_files_not_in_the_drop() {
        let keep = "C:/share/keep.bin";
        let skip = "C:/share/skip.bin";
        let other = "C:/other/file.bin";
        let mut discovered = vec![
            indexed_file(keep, ""),
            indexed_file(skip, ""),
            indexed_file(other, ""),
        ];
        let mut files_to_hash = discovered.clone();
        let allowlists = std::collections::HashMap::from([(
            crate::search::index::normalize_path_key("C:/share"),
            vec![crate::search::index::normalize_path_key(keep)],
        )]);
        apply_folder_allowlists(&mut discovered, &mut files_to_hash, &allowlists);
        assert!(discovered[0].shared);
        assert!(!discovered[1].shared);
        assert!(
            discovered[2].shared,
            "files outside an allowlisted folder keep the discovery default"
        );
        assert_eq!(files_to_hash[0].shared, discovered[0].shared);
        assert_eq!(files_to_hash[1].shared, discovered[1].shared);

        let pending =
            std::collections::HashMap::from([(crate::search::index::normalize_path_key(skip), true)]);
        apply_pending_intents(
            &mut discovered,
            &mut files_to_hash,
            &pending,
            &std::collections::HashMap::new(),
        );
        assert!(
            discovered[1].shared,
            "an explicit share intent must still win over the allowlist"
        );
    }

    #[test]
    fn a_folder_on_an_allowlist_offers_everything_under_it() {
        let inside = "C:/share/album/live/a.bin";
        let beside = "C:/share/album2/b.bin";
        let mut discovered = vec![indexed_file(inside, ""), indexed_file(beside, "")];
        let mut files_to_hash = discovered.clone();
        let allowlists = std::collections::HashMap::from([(
            crate::search::index::normalize_path_key("C:/share"),
            vec![crate::search::index::normalize_path_key("C:/share/album")],
        )]);
        apply_folder_allowlists(&mut discovered, &mut files_to_hash, &allowlists);
        assert!(discovered[0].shared);
        assert!(
            !discovered[1].shared,
            "a sibling whose name merely starts the same is not inside it"
        );
    }

    #[test]
    fn a_limited_add_withholds_known_files_off_its_allowlist() {
        let hash_keep = "11111111111111111111111111111111";
        let hash_skip = "22222222222222222222222222222222";
        let mut discovered = vec![
            indexed_file("C:/music/keep.mp3", hash_keep),
            indexed_file("C:/music/skip.mp3", hash_skip),
            // Pending rows belong to `apply_folder_allowlists`.
            indexed_file("C:/music/new.mp3", ""),
        ];
        let key = crate::search::index::normalize_path_key;
        let allowlists =
            std::collections::HashMap::from([(key("C:/music"), vec![key("C:/music/keep.mp3")])]);
        let withheld =
            withhold_known_files_outside_allowlist(&mut discovered, "C:/music", &allowlists);
        assert_eq!(withheld, vec![hash_skip.to_string()]);
        assert!(discovered[0].shared);
        assert!(!discovered[1].shared);
        assert!(discovered[2].shared);

        let untouched =
            withhold_known_files_outside_allowlist(&mut discovered, "C:/other", &allowlists);
        assert!(
            untouched.is_empty(),
            "a folder without an allowlist is a full share"
        );
    }

    /// Sharing a file flips every copy of its content, but a copy its own
    /// partly shared folder withholds stays unshared, now and when it is
    /// rediscovered with known.met's per-hash flag saying shared.
    #[test]
    fn sharing_a_file_leaves_a_withheld_copy_unshared() {
        let hash = "ab".repeat(16);
        let key = crate::search::index::normalize_path_key;
        let allowlists = std::collections::HashMap::from([(key("C:/music"), vec![key("C:/music/listed.mp3")])]);
        let offers = crate::sharing::indexer::AllowlistOffers::new(&allowlists);
        let mut index = LocalIndex::new();
        let mut withheld = indexed_file("C:/music/withheld.mp3", &hash);
        withheld.shared = false;
        let mut picked = indexed_file("D:/films/picked.mp3", &hash);
        picked.shared = false;
        index.add_files(vec![withheld.clone(), picked]);

        let mut mutation = index.set_shared_by_paths(&["D:/films/picked.mp3".to_string()], true);
        assert_eq!(mutation.changed_paths, 2, "the flip is per content hash");
        keep_unlisted_copies_unshared(&mut index, &mut mutation, &offers);
        assert_eq!(mutation.changed_paths, 1);
        assert_eq!(mutation.hashes, vec![hash.clone()]);
        assert!(index.get_by_path("D:/films/picked.mp3").unwrap().shared);
        assert!(!index.get_by_path("C:/music/withheld.mp3").unwrap().shared);

        withheld.shared = true;
        let mut rediscovered = vec![withheld, indexed_file("C:/music/listed.mp3", &hash)];
        withhold_unlisted_known_files(&mut rediscovered, &allowlists);
        assert!(!rediscovered[0].shared);
        assert!(rediscovered[1].shared);
    }

    /// known.met keeps one flag per content hash: a limited add must not
    /// unshare there a copy another folder still offers, whichever path the
    /// add takes.
    #[test]
    fn a_limited_add_leaves_known_met_alone_for_content_offered_elsewhere() {
        let elsewhere = "aa".repeat(16);
        let unshared_elsewhere = "bb".repeat(16);
        let only_here = "cc".repeat(16);
        let mut off = indexed_file("D:/films/off.mkv", &unshared_elsewhere);
        off.shared = false;
        let mut index = LocalIndex::new();
        index.add_files(vec![indexed_file("D:/films/copy.mkv", &elsewhere.to_ascii_uppercase()), off]);
        assert_eq!(
            not_offered_by_the_library(&index, vec![elsewhere, unshared_elsewhere.clone(), only_here.clone()]),
            vec![unshared_elsewhere, only_here]
        );
    }

    #[test]
    fn a_fresh_add_replaces_any_allowlist_left_on_the_folder() {
        let key = crate::search::index::normalize_path_key;
        let mut lists = std::collections::HashMap::from([
            (key("C:/music"), vec![key("C:/music/old.mp3")]),
            (key("C:/music/album"), vec![key("C:/music/album/x.mp3")]),
            (key("C:/other"), vec![key("C:/other/y.mp3")]),
        ]);
        set_added_folder_allowlist(&mut lists, "C:/music", None);
        assert_eq!(
            lists.len(),
            1,
            "a whole-folder add leaves nothing limiting it"
        );
        assert!(lists.contains_key(&key("C:/other")));

        let limit = (
            vec!["C:/music/a.mp3".to_string()],
            vec!["C:/music/live".to_string()],
        );
        set_added_folder_allowlist(&mut lists, "C:/music", Some(&limit));
        assert_eq!(
            lists.get(&key("C:/music")),
            Some(&vec![key("C:/music/a.mp3"), key("C:/music/live")])
        );
    }

    #[test]
    fn scoped_paths_collapse_onto_the_outermost() {
        use std::path::PathBuf;
        let paths = vec![
            PathBuf::from("/s/album/a.mp3"),
            PathBuf::from("/s/album"),
            PathBuf::from("/s/album2/b.mp3"),
            PathBuf::from("/s/album"),
        ];
        assert_eq!(
            outermost_paths(paths),
            vec![PathBuf::from("/s/album"), PathBuf::from("/s/album2/b.mp3")]
        );
    }

    /// The growing-file case: an external writer's file is neither hashed nor
    /// sent to `known.met` while it is still changing, an unchanged indexed row
    /// is reused as-is, and only genuinely new settled files go on to be
    /// resolved.
    #[test]
    fn a_scoped_rescan_reuses_unchanged_rows_and_defers_files_still_being_written() {
        let now = 1_000_000;
        let mut unchanged = indexed_file("C:/s/done.mkv", "11111111111111111111111111111111");
        unchanged.modified_at = now - 5;
        let mut index = LocalIndex::new();
        index.add_files(vec![unchanged.clone()]);

        let mut seen_again = unchanged.clone();
        seen_again.id = "pending:C:/s/done.mkv".into();
        seen_again.hash.clear();
        let mut growing = indexed_file("C:/s/growing.mkv", "");
        growing.modified_at = now - 2;
        let mut settled = indexed_file("C:/s/new.mkv", "");
        settled.modified_at = now - 600;

        let (reused, settling, rest) =
            split_scoped_discoveries(vec![seen_again, growing, settled], &index, now);
        assert_eq!(reused.len(), 1);
        assert_eq!(reused[0].hash, unchanged.hash, "the indexed row is reused");
        assert_eq!(settling.len(), 1);
        assert_eq!(settling[0].path, "C:/s/growing.mkv");
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].path, "C:/s/new.mkv");
    }

    #[test]
    fn a_full_reload_leaves_young_files_to_settle_unless_already_indexed_as_is() {
        let now = 1_000_000;
        let mut completed = indexed_file("C:/s/completed.mkv", "22222222222222222222222222222222");
        completed.modified_at = now - 3;
        let mut index = LocalIndex::new();
        index.add_files(vec![completed.clone()]);

        let mut completed_pending = completed.clone();
        completed_pending.hash.clear();
        let mut growing = indexed_file("C:/s/growing.mkv", "");
        growing.modified_at = now - 1;
        let mut old = indexed_file("C:/s/old.mkv", "");
        old.modified_at = now - 3600;

        let mut files_to_hash = vec![completed_pending.clone(), growing.clone(), old.clone()];
        let settling = take_settling_files(&mut files_to_hash, &index, now);
        assert_eq!(settling.len(), 1);
        assert_eq!(settling[0].path, growing.path);
        assert_eq!(files_to_hash.len(), 2, "settled and already-indexed files still hash");
    }

    /// Cancelling a full pass must not wipe placeholders it did not create: an
    /// earlier scoped pass's settle placeholder (whose file this pass then
    /// queued as settled), and one on a page this pass never reached. Each is
    /// the only holder of its file's restriction; only this pass's own new
    /// pending rows go.
    #[test]
    fn cancelling_a_pass_keeps_the_placeholders_it_did_not_create() {
        let root = "C:/s".to_string();
        let placeholder = |path: &str| {
            let mut file = indexed_file(path, "");
            file.id = format!("{}{path}", crate::search::index::PENDING_ID_PREFIX);
            file
        };
        let mut earlier = placeholder("C:/s/edited.mp3");
        earlier.friends_only = true;
        earlier.shared = false;
        let mut unreached = placeholder("C:/s/zz/later.mp3");
        unreached.friends_only = true;
        let mut index = LocalIndex::new();
        index.add_files(vec![
            earlier,
            unreached,
            indexed_file("C:/s/hashed.mp3", "55555555555555555555555555555555"),
        ]);

        let before = unhashed_placeholders_under(&index, std::slice::from_ref(&root));
        assert_eq!(before.len(), 2);
        // This (partial) page rediscovers the edited file, now settled and
        // queued, plus one brand-new file.
        index.reconcile_files_for_folders(
            std::slice::from_ref(&root),
            vec![placeholder("C:/s/edited.mp3"), placeholder("C:/s/new.mp3")],
            false,
        );

        remove_pending_rows_except(&mut index, std::slice::from_ref(&root), &before);
        index.rebuild();
        let edited = index.get_by_path("C:/s/edited.mp3").expect("earlier placeholder kept");
        assert!(edited.friends_only && !edited.shared, "its restriction survives the cancel");
        assert!(index.get_by_path("C:/s/zz/later.mp3").expect("unreached kept").friends_only);
        assert!(index.get_by_path("C:/s/new.mp3").is_none(), "this pass's own row goes");
        assert!(index.get_by_path("C:/s/hashed.mp3").is_some());
    }

    /// A restart mid-settle rebuilds the index from discovery, and nothing
    /// keyed by the old hash matches the edited file any more. The path-keyed
    /// intent recorded when the placeholder took over is what the startup
    /// scan applies, so the file comes back unshared rather than public.
    #[test]
    fn a_restart_mid_settle_does_not_bring_a_restricted_file_back_public() {
        let path = "C:/s/song.mp3";
        let mut hashed = indexed_file(path, "66666666666666666666666666666666");
        hashed.friends_only = true;
        hashed.priority = "high".to_string();
        let mut index = LocalIndex::new();
        index.add_files(vec![hashed]);
        let settling = vec![indexed_file(path, "")];

        let (shares, priorities) = settle_carry_over_intents(
            &settling,
            &index,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
        );
        assert_eq!(shares, vec![(path.to_string(), false)]);
        assert_eq!(priorities, vec![(path.to_string(), "high".to_string())]);

        // An intent already recorded — the user's own, or an earlier pass's —
        // is left as it is.
        let key = crate::search::index::normalize_path_key(path);
        let (again, _) = settle_carry_over_intents(
            &settling,
            &index,
            &std::collections::HashMap::from([(key.clone(), true)]),
            &std::collections::HashMap::new(),
        );
        assert!(again.is_empty());

        // After the restart: a fresh row, as the startup scan would build it.
        let share_intents = std::collections::HashMap::from([(key.clone(), false)]);
        let priority_intents = std::collections::HashMap::from([(key, "high".to_string())]);
        let mut discovered = vec![indexed_file(path, "")];
        let mut files_to_hash = discovered.clone();
        apply_pending_intents(
            &mut discovered,
            &mut files_to_hash,
            &share_intents,
            &priority_intents,
        );
        assert!(!discovered[0].shared, "fails closed instead of coming back public");
        assert_eq!(discovered[0].priority, "high");

        // An unrestricted file at the default priority records nothing.
        let mut plain_index = LocalIndex::new();
        plain_index.add_files(vec![indexed_file(path, "77777777777777777777777777777777")]);
        let (none, no_priority) = settle_carry_over_intents(
            &settling,
            &plain_index,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
        );
        assert!(none.is_empty() && no_priority.is_empty());
    }

    /// The reported regression. A friends-only, unshared, high-priority file
    /// edited in place by another program (a tag editor, say) was dropped from
    /// the index while it settled, then came back as a brand-new row: shared,
    /// public, normal priority — and ~47 s later was hashed and announced to
    /// the open network. Its new size, mtime and hash match nothing that
    /// remembers the old choices, so the placeholder row is what has to carry
    /// them, through the settle pass, the recheck, and the hash completion.
    #[test]
    fn a_restricted_file_edited_externally_keeps_its_restrictions_through_settle_and_rehash() {
        let now = 1_000_000;
        let folder = "C:/s".to_string();
        let path = "C:/s/song.mp3";
        let mut original = indexed_file(path, "33333333333333333333333333333333");
        original.modified_at = now - 86_400;
        original.shared = false;
        original.friends_only = true;
        original.priority = "high".to_string();
        original.alltime_requests = 7;
        let mut index = LocalIndex::new();
        index.add_files(vec![original]);

        // What discovery produces for the edited file: a fresh pending row.
        let rediscovered = |modified_at: i64, size: u64| {
            let mut file = indexed_file(path, "");
            file.id = format!("{}{path}", crate::search::index::PENDING_ID_PREFIX);
            file.modified_at = modified_at;
            file.size = size;
            file
        };

        // Settle pass (scoped): the file is still being written.
        let (unchanged, early_settling, rest) =
            split_scoped_discoveries(vec![rediscovered(now - 2, 2)], &index, now);
        assert!(unchanged.is_empty() && rest.is_empty());
        let mut discovered = early_settling.clone();
        let mut files_to_hash = early_settling;
        let settling = take_settling_files(&mut files_to_hash, &index, now);
        assert_eq!(settling.len(), 1);
        assert!(files_to_hash.is_empty(), "nothing is hashed while it settles");
        index.reconcile_files_for_folders(std::slice::from_ref(&folder), discovered, true);
        let placeholder = index.get_by_path(path).expect("the row stays indexed").clone();
        assert!(placeholder.hash.is_empty(), "a changing file is not served meanwhile");
        assert!(!placeholder.shared && placeholder.friends_only);
        assert_eq!(placeholder.priority, "high");
        assert_eq!(placeholder.alltime_requests, 7);

        // Recheck once it has settled: hashed now, over the placeholder.
        let later = now + 60;
        let (unchanged, early_settling, rest) =
            split_scoped_discoveries(vec![rediscovered(now - 2, 2)], &index, later);
        assert!(unchanged.is_empty() && early_settling.is_empty());
        discovered = rest.clone();
        files_to_hash = rest;
        assert!(take_settling_files(&mut files_to_hash, &index, later).is_empty());
        assert_eq!(files_to_hash.len(), 1);
        index.reconcile_files_for_folders(std::slice::from_ref(&folder), discovered, true);
        let mut completed = files_to_hash[0].clone();
        completed.hash = "44444444444444444444444444444444".to_string();
        completed.id = completed.hash.clone();
        index
            .finalize_pending_hash(&files_to_hash[0].id, completed)
            .expect("the placeholder is finalized");

        let row = index.get_by_path(path).expect("hashed row");
        assert_eq!(row.hash, "44444444444444444444444444444444");
        assert!(!row.shared, "an unshared file stays unshared");
        assert!(row.friends_only, "a friends-only file must not come back public");
        assert_eq!(row.priority, "high");
        assert_eq!(row.alltime_requests, 7);
    }

    /// A whole data drive, shared after the native confirmation, has to index
    /// the files on it, survive a root reconcile, and have its rows cleared
    /// when it is unshared. `path_matches_dir` refuses a bare drive, so every
    /// one of these steps used to treat the drive as containing nothing: the
    /// scan dropped its files and a reconcile would have deleted any it had.
    #[cfg(windows)]
    #[test]
    fn a_shared_drive_root_indexes_its_files_and_unsharing_clears_them() {
        let drive = r"\\?\D:\".to_string();
        let shared = vec![drive.clone(), r"\\?\E:\Music".to_string()];
        let on_drive = [r"\\?\D:\Films\a.mkv", r"\\?\D:\b.iso"];
        let elsewhere = r"\\?\E:\Music\c.mp3";

        // Reload: discovery's rows survive the shared-folder filter and are
        // reconciled under the drive.
        let mut discovered: Vec<FileInfo> = on_drive
            .iter()
            .chain(std::iter::once(&elsewhere))
            .enumerate()
            .map(|(i, path)| indexed_file(path, &format!("{:032x}", i + 1)))
            .collect();
        discovered.retain(|file| file_in_shared_folders(&file.path, &shared));
        assert_eq!(discovered.len(), 3, "files on a shared drive are in a shared folder");
        let mut index = LocalIndex::new();
        index.reconcile_files_for_folders(&shared, discovered, true);
        assert_eq!(index.file_count(), 3);
        assert!(
            index.remove_files_outside_folders(&shared).is_empty(),
            "a root reconcile keeps the drive's rows"
        );

        // Unshare the drive: the request resolves to the stored share, and
        // then clears exactly the rows on it.
        let target = stored_shared_folder(&shared, Some(r"\\?\D:\"), r"D:\")
            .expect("the drive is a stored share");
        assert_eq!(target, drive);
        assert!(unshare_target_is_shared(&shared, r"D:\"));
        let mutation = index.set_shared_by_path_prefix(&target, false);
        assert_eq!(mutation.changed_paths, 2);
        index.remove_files_by_path_prefix(&target);
        assert_eq!(index.file_count(), 1);
        assert_eq!(index.all_files()[0].path, elsewhere);
    }

    /// The drive-aware operations only ever run on a stored share. A request
    /// naming a drive that is not itself shared — only a folder on it is —
    /// is refused before anything touches that folder's rows or allowlists.
    #[test]
    fn a_request_for_an_unshared_drive_root_is_refused() {
        let drive_request = if cfg!(windows) { r"D:\" } else { "/" };
        let folder_on_it = if cfg!(windows) {
            r"\\?\D:\Films".to_string()
        } else {
            "/mnt/films".to_string()
        };
        let shared = vec![folder_on_it.clone()];
        assert_eq!(stored_shared_folder(&shared, Some(drive_request), drive_request), None);
        assert!(!unshare_target_is_shared(&shared, drive_request));
        let inside = if cfg!(windows) { r"D:\Films\Extras" } else { "/mnt/films/extras" };
        assert!(
            unshare_target_is_shared(&shared, inside),
            "a folder inside a share can still be unshared"
        );
        let escaping = if cfg!(windows) { r"D:\Films\..\Other" } else { "/mnt/films/../other" };
        assert!(!unshare_target_is_shared(&shared, escaping));
    }

    /// A drive shared for only a few of its files keeps that limit: the
    /// allowlist is keyed by the drive root, which `path_matches_dir` refuses
    /// to treat as containing anything.
    #[cfg(windows)]
    #[test]
    fn a_drive_root_allowlist_limits_and_clears_like_any_folder() {
        let key = crate::search::index::normalize_path_key;
        let drive = r"\\?\D:\";
        let keep = r"D:\Films\keep.mkv";
        let skip = r"D:\Films\skip.mkv";
        let mut lists = std::collections::HashMap::new();
        set_added_folder_allowlist(
            &mut lists,
            drive,
            Some(&(vec![keep.to_string()], Vec::new())),
        );
        assert_eq!(lists.get(&key(drive)), Some(&vec![key(keep)]));

        let mut discovered = vec![indexed_file(keep, ""), indexed_file(skip, "")];
        let mut files_to_hash = discovered.clone();
        apply_folder_allowlists(&mut discovered, &mut files_to_hash, &lists);
        assert!(discovered[0].shared);
        assert!(
            !discovered[1].shared,
            "a file on the drive but off its allowlist must not be offered"
        );

        lists.insert(key(r"D:\Films"), vec![key(keep)]);
        set_added_folder_allowlist(&mut lists, drive, None);
        assert!(
            lists.is_empty(),
            "sharing the whole drive lifts every limit at or under it"
        );
    }

    #[test]
    fn nested_dropped_folders_collapse_onto_the_outer_one() {
        let folders = vec![
            "C:/a/b".to_string(),
            "C:/a".to_string(),
            "C:/ab".to_string(),
            "c:/A".to_string(),
        ];
        assert_eq!(
            outermost_folders(folders),
            if cfg!(windows) {
                vec!["C:/a".to_string(), "C:/ab".to_string()]
            } else {
                vec!["C:/a".to_string(), "C:/ab".to_string(), "c:/A".to_string()]
            }
        );
    }

    #[test]
    fn a_pick_fails_only_when_nothing_landed() {
        let failed_only = SharedFolderPick {
            failed: vec!["first".to_string(), "second".to_string()],
            ..Default::default()
        };
        assert_eq!(finish_pick(failed_only).unwrap_err(), "first");

        let partial = SharedFolderPick {
            added: vec!["C:/music".to_string()],
            failed: vec!["overlap".to_string()],
            ..Default::default()
        };
        let partial = finish_pick(partial).unwrap();
        assert_eq!(partial.failed, vec!["overlap".to_string()]);

        assert!(finish_pick(SharedFolderPick::default()).is_ok());
    }

    #[test]
    fn a_dropped_file_resolves_under_its_folders_canonical_path() {
        let dir = std::env::temp_dir().join(format!(
            "ember-discovery-form-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let sub = dir.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let file = sub.join("a.bin");
        std::fs::write(&file, b"x").unwrap();
        // Spelled with a `..` detour, as a drop from an odd shell might be.
        let detour = dir.join("sub").join("..").join("sub").join("a.bin");

        let canonical_sub =
            crate::commands::share_browser::display_fs_path(&sub.canonicalize().unwrap());
        let (resolved, is_dir) = discovery_form(&detour).unwrap();
        assert!(!is_dir);
        assert!(crate::security::path_matches_dir(&resolved, &canonical_sub));
        assert_eq!(
            crate::search::index::normalize_path_key(&resolved),
            crate::search::index::normalize_path_key(
                &crate::commands::share_browser::display_fs_path(&file.canonicalize().unwrap())
            )
        );
        let (resolved_dir, is_dir) = discovery_form(&sub).unwrap();
        assert!(is_dir);
        assert_eq!(resolved_dir, canonical_sub);
        assert!(discovery_form(&dir.join("missing").join("b.bin")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A multi-part file with no AICH root is a one-time repair like the
    /// digest, and goes to the same background pass.
    ///
    /// It used to block the scan, on the grounds that AICH is eD2k recovery
    /// data rather than an Ember extra. That is a statement about its value and
    /// not about its urgency: the row already has its ed2k id and part hashes,
    /// so it serves, searches and publishes throughout, and what a missing root
    /// costs is a downloader re-fetching a whole part instead of one block —
    /// and only once something is actually corrupt. Against that, blocking
    /// meant a library whose previous scan never finished re-read its entire
    /// share in the foreground at the three-algorithm rate, and the digest pass
    /// then read every byte a second time because it waits on `scanning_count`.
    #[test]
    fn a_multi_part_file_missing_its_aich_root_goes_to_the_background() {
        let mut known = KnownFileList::new();
        let mut record = known_record("C:/L/big.bin", [0x33; 16], &"ab".repeat(32));
        record.aich_hash = String::new();
        record.file_size = crate::network::ed2k::hash::PARTSIZE * 2;
        known.add_or_update(record);

        let mut discovered = vec![indexed_file("C:/L/big.bin", "")];
        discovered[0].size = crate::network::ed2k::hash::PARTSIZE * 2;
        discovered[0].modified_at = 0;
        let work = resolve_from_known(&mut discovered, &known);

        assert!(
            work.needs_hashing.is_empty(),
            "a servable file must not hold up the Library"
        );
        assert_eq!(work.needs_top_up.len(), 1, "the root is still wanted");
        // The digest is already present here, so this row proves the pass is
        // reached for AICH alone rather than riding on a missing digest.
        assert_eq!(
            wanted_top_up(&work.needs_top_up[0]),
            crate::network::ed2k::hash::WantedDigests {
                aich: true,
                ember: false
            }
        );
        // And it stays a first-class entry rather than a placeholder, so Stop
        // cannot take it out of the Library.
        assert_eq!(discovered[0].id, hex::encode([0x33; 16]));
        assert!(!discovered[0]
            .id
            .starts_with(crate::search::index::REHASH_ID_PREFIX));
    }

    /// A single-part file has no AICH root by design, so an empty one there is
    /// the stored answer and not a gap. Getting this wrong queues every small
    /// file in the library for a whole-file read that can never satisfy it.
    #[test]
    fn a_single_part_file_is_not_asked_for_an_aich_root() {
        let mut known = KnownFileList::new();
        let mut record = known_record("C:/L/small.bin", [0x44; 16], &"ab".repeat(32));
        record.aich_hash = String::new();
        record.file_size = crate::network::ed2k::hash::PARTSIZE - 1;
        known.add_or_update(record);

        let mut discovered = vec![indexed_file("C:/L/small.bin", "")];
        discovered[0].size = crate::network::ed2k::hash::PARTSIZE - 1;
        discovered[0].modified_at = 0;
        let work = resolve_from_known(&mut discovered, &known);

        assert!(work.needs_hashing.is_empty());
        assert!(
            work.needs_top_up.is_empty(),
            "a single-part file is complete without a root"
        );
    }

    /// Both repairs outstanding on one file must be one read, not two passes
    /// over the same bytes — which is the whole reason they were merged.
    #[test]
    fn a_file_missing_both_repairs_asks_for_them_together() {
        let mut known = KnownFileList::new();
        let mut record = known_record("C:/L/both.bin", [0x55; 16], "");
        record.aich_hash = String::new();
        record.file_size = crate::network::ed2k::hash::PARTSIZE * 3;
        known.add_or_update(record);

        let mut discovered = vec![indexed_file("C:/L/both.bin", "")];
        discovered[0].size = crate::network::ed2k::hash::PARTSIZE * 3;
        discovered[0].modified_at = 0;
        let work = resolve_from_known(&mut discovered, &known);

        assert_eq!(work.needs_top_up.len(), 1);
        assert_eq!(
            wanted_top_up(&work.needs_top_up[0]),
            crate::network::ed2k::hash::WantedDigests {
                aich: true,
                ember: true
            },
            "one pass has to be asked for both, or the file is read twice"
        );
        let (ed2k, _, _, want) =
            top_up_inputs(&work.needs_top_up[0]).expect("a matched row takes the top-up route");
        assert_eq!(ed2k, hex::encode([0x55; 16]), "the stored ed2k is reused");
        assert!(want.aich && want.ember);
    }

    /// A record that already carries its digest wants nothing at all — the
    /// ordinary case on every launch after the migration has finished, and the
    /// one that must stay free.
    #[test]
    fn a_complete_record_asks_for_no_work() {
        let mut known = KnownFileList::new();
        known.add_or_update(known_record("C:/L/done.bin", [0x22; 16], &"ab".repeat(32)));

        let mut discovered = vec![indexed_file("C:/L/done.bin", "")];
        discovered[0].size = 1;
        discovered[0].modified_at = 0;
        let work = resolve_from_known(&mut discovered, &known);

        assert!(work.needs_hashing.is_empty());
        assert!(work.needs_top_up.is_empty());
    }

    /// No device may ever have more reads outstanding than its own limit,
    /// because for a mechanical drive that limit of 1 *is* the seek safeguard.
    /// The row handed to the caller counts: the caller has not awaited it yet,
    /// so as far as the drive is concerned it is still running. Refilling the
    /// window after handing one out rather than before left two reads in flight
    /// on a disk that had asked for one.
    #[tokio::test]
    async fn no_device_ever_exceeds_its_own_limit() {
        let files: Vec<FileInfo> = (0..6)
            .map(|i| {
                indexed_file(
                    &format!("C:/ember-lookahead-{}-{i}.bin", std::process::id()),
                    &"ab".repeat(16),
                )
            })
            .collect();
        // Pre-cancelled: every spawned hash bails at once, so this measures the
        // window rather than waiting on real reads.
        let cancel = Arc::new(AtomicBool::new(true));
        let mut pipeline = HashLookahead::new(&files, cancel);
        let limits: Vec<usize> = pipeline.devices.iter().map(|d| d.limit).collect();

        let mut handed_out = 0usize;
        while let NextHash::Ready(started) = pipeline.next_started() {
            handed_out += 1;
            for (device, limit) in limits.iter().enumerate() {
                assert!(
                    pipeline.device_inflight(device) <= *limit,
                    "device {device}: {} reads in flight exceeds its limit of {limit}",
                    pipeline.device_inflight(device)
                );
            }
            assert!(pipeline.total_inflight() <= crate::sharing::disk::MAX_TOTAL_HASH_CONCURRENCY);
            release_in_flight_hash(&files[started.index].path, started.claim);
        }
        assert_eq!(
            handed_out,
            files.len(),
            "every file must be handed out once"
        );
        assert_eq!(pipeline.skipped(), 0);
    }

    /// The whole point of the per-device split: files on separate drives are
    /// read at the same time. The previous version answered once for the entire
    /// library and took the most cautious answer, so a library on four external
    /// drives used one of them and left three idle for a pass that takes days.
    #[tokio::test]
    async fn separate_devices_are_read_at_the_same_time() {
        let files: Vec<FileInfo> = (0..4)
            .map(|i| indexed_file(&format!("C:/d{i}/f.bin"), &"ab".repeat(16)))
            .collect();
        let cancel = Arc::new(AtomicBool::new(true));
        let mut pipeline = HashLookahead::new(&files, cancel);
        // Stand in for four drives, each tolerating one read — the reporter's
        // hardware. Built by hand because the test machine has one disk.
        pipeline.devices = (0..4)
            .map(|i| DeviceQueue {
                key: Some(format!("disk:test-{i}")),
                limit: 1,
                pending: std::collections::VecDeque::from(vec![i]),
            })
            .collect();

        let NextHash::Ready(first) = pipeline.next_started() else {
            panic!("a file to start");
        };
        assert_eq!(
            pipeline.total_inflight(),
            4,
            "one read should be running on each of the four drives, not one in total"
        );
        release_in_flight_hash(&files[first.index].path, first.claim);
        pipeline.abandon();
    }

    /// A read the scheduler did not start still occupies the drive. A download
    /// finishing mid-scan verifies itself by reading the whole file, and if the
    /// pass cannot see that, it puts its own read alongside — two heads on one
    /// spindle, which is the thing the per-device limit exists to prevent. The
    /// transfer never waits; the scan is the side that stands down.
    #[tokio::test]
    async fn a_read_the_scheduler_did_not_start_still_holds_the_drive() {
        let files: Vec<FileInfo> = (0..3)
            .map(|i| indexed_file(&format!("C:/busy/f{i}.bin"), &"ab".repeat(16)))
            .collect();
        let cancel = Arc::new(AtomicBool::new(true));
        let mut pipeline = HashLookahead::new(&files, cancel);
        // A real device key, so `external_reads` can be keyed to match.
        let key = format!("disk:busy-{}", std::process::id());
        pipeline.devices = vec![DeviceQueue {
            key: Some(key.clone()),
            limit: 1,
            pending: (0..files.len()).collect(),
        }];

        // Stand in for a download verifying itself on this drive. Registered
        // through the same path the transfer uses, via a path we can key.
        {
            let _busy = ExternalReadForTest::new(&key);
            assert_eq!(
                pipeline.device_inflight(0),
                1,
                "the drive is busy even though the pass has started nothing"
            );
            // Busy, emphatically *not* Done. Reporting "nothing to hand out"
            // here would end the scan with every file still queued, and let the
            // resume cursor move past files nothing ever hashed.
            assert!(
                matches!(pipeline.next_started(), NextHash::Busy),
                "a full device must make the pass wait, not make it think it finished"
            );
        }

        // Released, so the pass may proceed.
        assert_eq!(pipeline.device_inflight(0), 0);
        let NextHash::Ready(started) = pipeline.next_started() else {
            panic!("the drive is free again");
        };
        release_in_flight_hash(&files[started.index].path, started.claim);
        pipeline.abandon();
    }

    /// Deferring to another reader must not become a way to hang. A
    /// `spawn_blocking` read cannot be aborted, so one wedged on a drive that
    /// stopped answering holds its guard forever — and without a deadline the
    /// library would never hash anything again for the rest of the session.
    #[tokio::test]
    async fn the_pass_stops_deferring_to_a_read_that_never_ends() {
        let files: Vec<FileInfo> = vec![indexed_file("C:/stuck/f.bin", &"ab".repeat(16))];
        let cancel = Arc::new(AtomicBool::new(true));
        let mut pipeline = HashLookahead::new(&files, cancel);
        let key = format!("disk:stuck-{}", std::process::id());
        pipeline.devices = vec![DeviceQueue {
            key: Some(key.clone()),
            limit: 1,
            pending: (0..files.len()).collect(),
        }];

        let _never_finishes = ExternalReadForTest::new(&key);
        assert!(matches!(pipeline.next_started(), NextHash::Busy));

        // Pretend the wait started longer ago than the grace period.
        pipeline.busy_since = Some(
            std::time::Instant::now() - EXTERNAL_READ_GRACE - std::time::Duration::from_secs(1),
        );
        assert_eq!(
            pipeline.device_inflight(0),
            0,
            "past the grace period the stuck read stops being counted"
        );
        let NextHash::Ready(started) = pipeline.next_started() else {
            panic!("the pass must go ahead rather than wait forever");
        };
        release_in_flight_hash(&files[started.index].path, started.claim);
        pipeline.abandon();
    }

    /// Waiting out a stuck read has to stay waited out. `busy_since` is
    /// cleared by every hand-out, so deriving the decision from it afresh each
    /// time bought exactly one file per grace period: against a read that
    /// never returns the pass crawled at one file every two minutes, which on
    /// a real library is the same hang the grace was added to break. The
    /// single-iteration test above cannot see this — it takes a second file.
    #[tokio::test]
    async fn waiting_out_a_stuck_read_stays_waited_out() {
        let files: Vec<FileInfo> = vec![
            indexed_file("C:/stuck/a.bin", &"ab".repeat(16)),
            indexed_file("C:/stuck/b.bin", &"cd".repeat(16)),
        ];
        let cancel = Arc::new(AtomicBool::new(true));
        let mut pipeline = HashLookahead::new(&files, cancel);
        let key = format!("disk:latched-{}", std::process::id());
        pipeline.devices = vec![DeviceQueue {
            key: Some(key.clone()),
            limit: 1,
            pending: (0..files.len()).collect(),
        }];

        let _never_finishes = ExternalReadForTest::new(&key);
        assert!(matches!(pipeline.next_started(), NextHash::Busy));
        pipeline.busy_since = Some(
            std::time::Instant::now() - EXTERNAL_READ_GRACE - std::time::Duration::from_secs(1),
        );

        // First file: the grace has elapsed, so the wedged read is ignored.
        let NextHash::Ready(first) = pipeline.next_started() else {
            panic!("the pass must go ahead once the grace has elapsed");
        };
        release_in_flight_hash(&files[first.index].path, first.claim);

        // Second file, with the read still wedged and `busy_since` cleared by
        // that hand-out. This is the call that used to return `Busy` and start
        // the two-minute wait over.
        let NextHash::Ready(second) = pipeline.next_started() else {
            panic!("the pass must keep going, not re-defer to the same stuck read");
        };
        release_in_flight_hash(&files[second.index].path, second.claim);
        pipeline.abandon();
    }

    /// Registers an external read directly against a device key, which is what
    /// `disk::note_external_read` does once it has resolved a path to one.
    struct ExternalReadForTest(String);
    impl ExternalReadForTest {
        fn new(key: &str) -> Self {
            crate::sharing::disk::note_external_read_by_key(key);
            Self(key.to_string())
        }
    }
    impl Drop for ExternalReadForTest {
        fn drop(&mut self) {
            crate::sharing::disk::release_external_read_by_key(&self.0);
        }
    }

    /// The flip side, and the safeguard that must survive all of this: a
    /// library that lives on one mechanical drive still reads one file at a
    /// time, however many files are queued behind it.
    #[tokio::test]
    async fn one_mechanical_drive_still_reads_one_file_at_a_time() {
        let files: Vec<FileInfo> = (0..5)
            .map(|i| indexed_file(&format!("C:/one/f{i}.bin"), &"ab".repeat(16)))
            .collect();
        let cancel = Arc::new(AtomicBool::new(true));
        let mut pipeline = HashLookahead::new(&files, cancel);
        pipeline.devices = vec![DeviceQueue {
            key: Some("disk:test-single".to_string()),
            limit: 1,
            pending: (0..files.len()).collect(),
        }];

        while let NextHash::Ready(started) = pipeline.next_started() {
            assert_eq!(
                pipeline.total_inflight(),
                1,
                "a spinning disk must never be asked for two files at once"
            );
            release_in_flight_hash(&files[started.index].path, started.claim);
        }
    }

    /// The reporter's library: archives large enough that a USB drive takes
    /// longer than the stall window to read them. Timing those out threw the
    /// finished hash away, so they were read again on every launch.
    #[tokio::test]
    async fn a_read_that_keeps_moving_is_waited_for_past_the_stall_window() {
        let stall = std::time::Duration::from_millis(250);
        let progress = Arc::new(AtomicU64::new(0));
        let reader = progress.clone();
        let mut task = tokio::spawn(async move {
            for _ in 0..60 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                reader.fetch_add(1 << 20, Ordering::Relaxed);
            }
            Ok((String::new(), String::new(), Vec::new(), String::new(), 0, 0))
        });
        let began = tokio::time::Instant::now();
        let mut renewed = 0usize;

        let outcome = await_hash_within(&mut task, &progress, stall, || renewed += 1).await;

        assert!(
            matches!(outcome, Ok(Ok(Ok(_)))),
            "a read still making progress must be allowed to finish"
        );
        assert!(began.elapsed() > stall, "the read outlasted the stall window");
        assert!(renewed > 0, "progress has to keep the claim's lease alive");
    }

    #[tokio::test]
    async fn a_read_that_stops_is_given_up_on() {
        let progress = AtomicU64::new(0);
        let mut task = tokio::spawn(std::future::pending::<HashPassResult>());

        let outcome = await_hash_within(
            &mut task,
            &progress,
            std::time::Duration::from_millis(50),
            || panic!("nothing was read, so nothing may renew the claim"),
        )
        .await;

        assert!(matches!(outcome, Err(HashStalled)));
        task.abort();
    }

    /// A top-up may skip only what `known.met` really supplied, and must ask
    /// for exactly what is missing. Getting this wrong in the permissive
    /// direction writes a made-up ed2k hash into the index; in the restrictive
    /// direction it just costs the speed-up. Asking for too little is the one
    /// that reads a file and records nothing.
    #[test]
    fn a_top_up_asks_for_what_is_missing_and_carries_the_rest_forward() {
        let hash = "ab".repeat(16);
        let aich = "cd".repeat(20);
        let digest_only = crate::network::ed2k::hash::WantedDigests {
            aich: false,
            ember: true,
        };

        let mut migration = indexed_file("C:/A/file.bin", &hash);
        migration.aich_hash = aich.clone();
        migration.size = crate::network::ed2k::hash::PARTSIZE * 2;
        assert_eq!(
            top_up_inputs(&migration),
            Some((hash.clone(), aich.clone(), String::new(), digest_only)),
            "an otherwise complete record needs only its BLAKE3"
        );

        // The background pass hands rows over under their real content-hash id
        // rather than a `rehash:` placeholder. Requiring the prefix here made
        // every one of them take the full three-algorithm pass.
        let mut backfilled = migration.clone();
        backfilled.id = hash.clone();
        assert_eq!(
            top_up_inputs(&backfilled),
            Some((hash.clone(), aich.clone(), String::new(), digest_only)),
            "how the row was queued must not decide how much of it is hashed"
        );

        // Single-part files never had an AICH root, so an empty one is the
        // answer rather than a gap — still only the digest to compute.
        let mut single_part = migration.clone();
        single_part.aich_hash = String::new();
        single_part.size = 1;
        assert_eq!(
            top_up_inputs(&single_part),
            Some((hash.clone(), String::new(), String::new(), digest_only)),
        );

        // Old enough to predate AICH as well. This used to fall through to the
        // full three-algorithm pass in the foreground; it is now a top-up that
        // asks for both and still carries the stored ed2k forward.
        let mut no_aich = migration.clone();
        no_aich.aich_hash = String::new();
        assert_eq!(
            top_up_inputs(&no_aich),
            Some((
                hash.clone(),
                String::new(),
                String::new(),
                crate::network::ed2k::hash::WantedDigests {
                    aich: true,
                    ember: true
                }
            )),
        );

        // A row wanting only its root still carries the digest it already has,
        // because the caller assigns the whole tuple onto the index row and a
        // blank field there reads as an erasure rather than as "not asked for".
        let mut has_digest_wants_root = migration.clone();
        has_digest_wants_root.aich_hash = String::new();
        has_digest_wants_root.ember_file_hash = "ef".repeat(32);
        assert_eq!(
            top_up_inputs(&has_digest_wants_root),
            Some((
                hash.clone(),
                String::new(),
                "ef".repeat(32),
                crate::network::ed2k::hash::WantedDigests {
                    aich: true,
                    ember: false
                }
            )),
        );

        // A genuinely new file has no hash to carry forward, so there is
        // nothing to top up and it takes the full pass.
        let mut fresh = indexed_file("C:/A/new.bin", "");
        fresh.id = format!("{}C:/A/new.bin", crate::search::index::PENDING_ID_PREFIX);
        fresh.aich_hash = aich;
        assert_eq!(top_up_inputs(&fresh), None);

        // A row with both repairs already present must not be handed a
        // whole-file read that would compute nothing.
        let mut complete = indexed_file("C:/A/file.bin", &hash);
        complete.ember_file_hash = "ef".repeat(32);
        assert_eq!(top_up_inputs(&complete), None);
        assert!(!wants_hash_top_up(&complete));
    }

    #[test]
    fn a_hash_another_row_still_offers_is_not_retracted() {
        let hash = "ab".repeat(16);
        let mut index = LocalIndex::new();
        // Same content shared from two folders; only one copy is being removed.
        index.add_file(indexed_file("C:/A/file.bin", &hash));
        index.add_file(indexed_file("C:/B/file.bin", &hash));
        index.remove_file_by_path("C:/A/file.bin");

        assert!(
            hashes_no_longer_offered(&index, std::slice::from_ref(&hash)).is_empty(),
            "the surviving row keeps the file listable, so its records must stay"
        );

        index.remove_file_by_path("C:/B/file.bin");
        assert_eq!(
            hashes_no_longer_offered(&index, std::slice::from_ref(&hash)),
            vec![hash]
        );
    }

    #[test]
    fn a_survivor_that_is_not_publicly_listable_does_not_block_retraction() {
        let unshared = "12".repeat(16);
        let restricted = "34".repeat(16);
        let mut index = LocalIndex::new();

        let mut row = indexed_file("C:/A/unshared.bin", &unshared);
        row.shared = false;
        index.add_file(row);
        let mut row = indexed_file("C:/A/restricted.bin", &restricted);
        row.friends_only = true;
        index.add_file(row);

        // Neither survivor is on the open network, so neither should be holding
        // the other copy's Ember records alive.
        let mut candidates =
            hashes_no_longer_offered(&index, &[unshared.clone(), restricted.clone()]);
        candidates.sort();
        assert_eq!(candidates, vec![unshared, restricted]);
    }

    #[test]
    fn retraction_candidates_are_deduplicated_and_case_folded() {
        let kept = "cd".repeat(16);
        let gone = "EF".repeat(16);
        let mut index = LocalIndex::new();
        index.add_file(indexed_file("C:/A/kept.bin", &kept));

        // Two rows of the same removed content, and an empty hash from a row
        // that never finished hashing.
        let removed = vec![
            gone.clone(),
            gone.to_ascii_lowercase(),
            kept.clone(),
            String::new(),
        ];
        assert_eq!(
            hashes_no_longer_offered(&index, &removed),
            vec![gone.to_ascii_lowercase()]
        );
    }

    #[tokio::test]
    async fn cancelled_finalization_does_not_cache_fresh_handoff() {
        let fresh_part_hashes = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let hash = "11".repeat(16);
        let handoff = fresh_part_hash_handoff(&hash, vec![[0xA1; 16]]);

        cache_fresh_part_hash_handoff(&fresh_part_hashes, false, handoff).await;

        assert!(fresh_part_hashes.read().await.is_empty());
    }

    #[tokio::test]
    async fn folder_removal_discards_fresh_part_hash_handoffs() {
        let removed_hash = [0x11; 16];
        let retained_hash = [0x22; 16];
        let fresh_part_hashes = Arc::new(RwLock::new(std::collections::HashMap::from([
            (removed_hash, vec![[0xA1; 16]]),
            (retained_hash, vec![[0xB2; 16]]),
        ])));
        let removed = HashSet::from([removed_hash]);

        discard_fresh_part_hashes(&fresh_part_hashes, &removed).await;

        let fresh = fresh_part_hashes.read().await;
        assert!(!fresh.contains_key(&removed_hash));
        assert_eq!(fresh.get(&retained_hash), Some(&vec![[0xB2; 16]]));
    }

    #[test]
    fn folder_removal_keeps_handoff_still_referenced_by_another_root() {
        let duplicate_hash = "11".repeat(16);
        let removed_only_hash = "22".repeat(16);
        let files = vec![
            indexed_file("/shares/removed/duplicate.bin", &duplicate_hash),
            indexed_file("/shares/retained/duplicate.bin", &duplicate_hash),
            indexed_file("/shares/removed/only.bin", &removed_only_hash),
        ];
        let roots = vec!["/shares/removed".to_string()];

        let discard = fresh_part_hashes_exclusively_under_roots(&files, &roots);

        assert!(!discard.contains(&fresh_part_hash_key(&duplicate_hash).unwrap()));
        assert!(discard.contains(&fresh_part_hash_key(&removed_only_hash).unwrap()));
    }

    #[test]
    fn file_removal_keeps_handoff_still_referenced_by_duplicate() {
        let duplicate_hash = "11".repeat(16);
        let removed_only_hash = "22".repeat(16);
        let candidates = HashSet::from([
            fresh_part_hash_key(&duplicate_hash).unwrap(),
            fresh_part_hash_key(&removed_only_hash).unwrap(),
        ]);
        let remaining = vec![indexed_file(
            "/shares/retained/duplicate.bin",
            &duplicate_hash,
        )];

        let discard = unreferenced_fresh_part_hashes(&remaining, &candidates);

        assert!(!discard.contains(&fresh_part_hash_key(&duplicate_hash).unwrap()));
        assert!(discard.contains(&fresh_part_hash_key(&removed_only_hash).unwrap()));
    }

    #[test]
    fn reload_pruning_discards_only_hashes_no_longer_indexed() {
        let duplicate_hash = "11".repeat(16);
        let removed_only_hash = "22".repeat(16);
        let before = vec![
            indexed_file("/shares/reload/duplicate.bin", &duplicate_hash),
            indexed_file("/shares/reload/gone.bin", &removed_only_hash),
        ];
        let after = vec![indexed_file("/shares/other/duplicate.bin", &duplicate_hash)];
        let folders = vec!["/shares/reload".to_string()];

        let discard = fresh_part_hashes_removed_by_reload(&before, &after, &folders);

        assert!(!discard.contains(&fresh_part_hash_key(&duplicate_hash).unwrap()));
        assert!(discard.contains(&fresh_part_hash_key(&removed_only_hash).unwrap()));
    }

    #[test]
    fn delayed_root_reconciliation_keeps_root_readded_by_newer_save() {
        let removed = vec!["/shares/readded".to_string()];
        let added = Vec::new();
        let active = vec!["/shares/readded".to_string()];

        let (effective_removed, effective_added) =
            effective_shared_root_changes(&removed, &added, &active);

        assert!(effective_removed.is_empty());
        assert!(effective_added.is_empty());
    }

    #[test]
    fn zero_length_suffix_media_range_is_rejected() {
        assert_eq!(parse_single_range(Some("bytes=-0"), 1024), Err(()));
        assert_eq!(
            parse_single_range(Some("bytes=-1"), 1024),
            Ok(Some((1023, 1023)))
        );
    }

    #[test]
    fn path_batches_enforce_count_item_and_aggregate_byte_caps() {
        assert!(check_path_batch(&["a".into(), "b".into()], 2).is_ok());
        assert!(check_path_batch(&["a".into(), "b".into()], 1).is_err());
        assert!(check_path_batch(&["x".repeat(MAX_PATH_LEN + 1)], 1).is_err());
        let many = vec!["x".repeat(MAX_PATH_LEN); MAX_BATCH_PATH_BYTES / MAX_PATH_LEN + 1];
        assert!(check_path_batch(&many, many.len()).is_err());
    }
}
