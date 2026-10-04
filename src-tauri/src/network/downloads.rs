//! Download bookkeeping: pending-download retries, status writes, disk
//! checks, and starting a download from already-known sources.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

pub(super) fn pending_download_retry_interval(search_count: u32) -> i64 {
    match search_count {
        0 => 0,
        1 => 5,
        2 => 10,
        3..=5 => 20,
        6..=10 => 60,
        11..=20 => 180,
        _ => 300,
    }
}

/// Install a fresh [`TransferControl`] for `transfer_id`, cancelling whatever
/// control was registered before it.
///
/// The cancel is load-bearing, not hygiene. A worker's per-source tasks are
/// detached `tokio::spawn`s that stop only when their control is cancelled, so
/// aborting the worker's own `JoinHandle` never reaches them. Overwriting the
/// registration without cancelling left the previous generation's children
/// running against an orphaned control that no later Stop, Pause or disconnect
/// could reach, still holding their sockets and part-writer reservations. The
/// IPC path has done this since `start_promoted_downloads`; these network-loop
/// respawn sites had not, and a following `StartDownload` cannot compensate —
/// its guard compares `get_control` against the control it was handed with
/// `Arc::ptr_eq`, which now matches, so it skips the cancel itself.
pub(super) async fn reregister_transfer_control(
    transfer_manager: &Arc<RwLock<TransferManager>>,
    transfer_id: &str,
) -> Arc<TransferControl> {
    let control = TransferControl::new();
    let mut mgr = transfer_manager.write().await;
    if let Some(old) = mgr.get_control(transfer_id) {
        old.cancel();
    }
    mgr.register_control(transfer_id, control.clone());
    control
}

pub(super) fn insert_pending_download_bounded(
    pending: &mut HashMap<String, PendingDownload>,
    transfer_id: String,
    download: PendingDownload,
) -> bool {
    if pending.contains_key(&transfer_id)
        || pending.len() < crate::commands::transfers::MAX_PENDING_DOWNLOADS
    {
        pending.insert(transfer_id, download);
        true
    } else {
        warn!(
            "Refusing pending-download map insertion at cap {}",
            crate::commands::transfers::MAX_PENDING_DOWNLOADS
        );
        false
    }
}

pub(super) fn shutdown_phase_deadline(
    global: tokio::time::Instant,
    phase_max: std::time::Duration,
) -> tokio::time::Instant {
    std::cmp::min(global, tokio::time::Instant::now() + phase_max)
}

/// KAD re-search interval for active downloads that already have sources.
/// More relaxed than `pending_download_retry_interval` since these downloads
/// are already transferring — we're just looking for additional sources.
/// eMule uses KADEMLIAREASKTIME (1 hour) * m_TotalSearchesKad (up to 7).
pub(super) fn active_download_kad_interval(search_count: u32) -> i64 {
    match search_count {
        0 => 15,
        1 => 30,
        2 => 60,
        3..=5 => 300,
        6..=10 => 900,
        _ => 3600,
    }
}

pub(super) fn expected_aich_bytes(value: Option<&str>) -> Option<[u8; 20]> {
    let bytes = hex::decode(value?).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&bytes);
    Some(hash)
}

/// Availability bitmap for the OP_REASKFILEPING we send while downloading.
///
/// Advertises only parts we will actually serve (complete AND MD4-verified),
/// like every other outgoing bitmap: `is_range_safe_to_serve` also requires
/// `is_part_verified`, so a bitmap built from bare `completed_parts()` told the
/// peer we hold parts whose block requests we then silently refuse, freezing
/// its download on a part it keeps re-requesting.
///
/// The read is bounded because this runs inline in the `select!` UDP branch,
/// which drains up to 20 datagrams per turn. A source worker holds the tracker
/// *write* guard across `PartFileWriter::write`, whose ack is an mpsc round trip
/// to one per-file writer thread whose FIFO also carries other workers'
/// `sync_data` and `hash_part_md4` — so an unbounded wait here lets a peer's
/// routine OP_REASKFILEPING head-of-line block UDP recv, IPC and every timer for
/// the length of an unrelated fsync or 9.28 MB MD4.
///
/// Timing out yields `None`, which every caller already handles: the UDP path
/// rebuilds from the `.part.met` sidecar on the blocking pool, off the event
/// loop. That sidecar lags the live tracker, so it can only under-report what we
/// hold — never advertise a part we would then refuse to serve.
pub(super) async fn udp_reask_serveable_parts(state: &NetworkState, transfer_id: &str) -> Option<Vec<bool>> {
    /// Short enough that 20 contended datagrams cost well under a second, long
    /// enough that the uncontended case (the overwhelming majority, where the
    /// lock is free and the read returns immediately) never falls back.
    const TRACKER_READ_BUDGET: std::time::Duration = std::time::Duration::from_millis(20);

    let tracker = state.tracker_registry.lock().get(transfer_id).cloned()?;
    // Bound to a `let` rather than returned directly: as a tail expression the
    // read guard's temporary would outlive `tracker` itself.
    let parts = match tokio::time::timeout(TRACKER_READ_BUDGET, tracker.read()).await {
        Ok(guard) => Some(guard.serveable_parts()),
        Err(_) => {
            debug!(
                "Tracker busy for {transfer_id}; falling back to the .part.met sidecar for the reask bitmap"
            );
            None
        }
    };
    parts
}

/// How many queued OP_CALLBACKREQUESTs the event loop sends per
/// [`LOWID_CALLBACK_INTERVAL`]: 20 per five seconds, eMule's default
/// `MaxConPerFive`, the budget its callbacks are paced by
/// (`TooManySockets`, DownloadClient.cpp:183-187). The loop turns many times a
/// second, so a per-turn cap alone let a 255-source OP_FOUNDSOURCES or the
/// post-login flush reach the server — and bring the connect-backs — within
/// about a second.
pub(super) const MAX_LOWID_CALLBACKS_PER_TURN: usize = 4;
pub(super) const LOWID_CALLBACK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Ceiling on `pending_lowid_callback_queue`. Its drain only runs while we are
/// logged in with a HighID, so a LowID (or disconnected) session drains nothing
/// while the producers keep offering the same sources every source-retry tick —
/// unbounded growth without this.
pub(super) const MAX_PENDING_LOWID_CALLBACKS: usize = 1024;

/// Queue OP_CALLBACKREQUEST work for the rate-limited drain in the event loop.
///
/// Sending inline is what this exists to avoid: a `request_callback` write is
/// bounded only by `SERVER_WRITE_TIMEOUT_SECS`, and the event loop is a single
/// task, so one stalled server would otherwise freeze KAD UDP, every timer,
/// transfer events and IPC for that long per source in the batch.
///
/// Pairs already queued are skipped — every producer re-offers the same
/// `(file_hash, client_id)` until the source manager sees the callback go out,
/// so without this the retry tick alone grows the queue without bound. The scan
/// is linear, which is why the cap is kept small enough for that to stay cheap.
pub(super) fn queue_lowid_callbacks(
    queue: &mut std::collections::VecDeque<([u8; 16], u32)>,
    entries: impl IntoIterator<Item = ([u8; 16], u32)>,
) -> usize {
    let mut queued = 0usize;
    for entry in entries {
        if queue.len() >= MAX_PENDING_LOWID_CALLBACKS {
            debug!(
                "LowID callback queue at capacity ({MAX_PENDING_LOWID_CALLBACKS}); dropping the rest of this batch"
            );
            break;
        }
        if queue.contains(&entry) {
            continue;
        }
        queue.push_back(entry);
        queued += 1;
    }
    queued
}

pub(super) fn priority_str_to_u32(s: &str) -> u32 {
    match s {
        "release" => 3,
        "high" => 2,
        "low" | "verylow" => 0,
        _ => 1, // "normal", "auto", or unknown default to normal
    }
}

pub(crate) const DISK_SPACE_BUFFER: u64 = 50 * 1024 * 1024; // 50 MB safety margin

/// Bytes still needed on disk for a download (full size minus already written).
pub(super) fn remaining_download_bytes(file_size: u64, completed: u64) -> u64 {
    file_size.saturating_sub(completed)
}

/// One reading of the download volume's free space. Every download that
/// shares the folder is compared against the same reading, so a tick pays for
/// one filesystem query rather than one per pending download.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DiskSpaceProbe {
    Available(u64),
    /// The query failed on a folder that is presumed usable, or there is no
    /// fresh reading yet. Admitted: ENOSPC on write still fails the transfer
    /// safely.
    Unknown,
    /// The download folder does not exist.
    Missing,
}

/// A reading older than this is not trusted. The refresh behind it has been
/// stuck on the volume for several ticks, so the space it reported says
/// nothing about now.
pub(super) const DISK_SPACE_READING_MAX_AGE: std::time::Duration =
    std::time::Duration::from_secs(30);

/// Blocking: `fs2::available_space`, plus `Path::exists` when that fails.
fn probe_disk_space(download_dir: &std::path::Path) -> DiskSpaceProbe {
    match fs2::available_space(download_dir) {
        Ok(available) => DiskSpaceProbe::Available(available),
        Err(e) => {
            // Fail closed only when the download folder is missing/unusable.
            // Some cloud/mapped volumes reject available_space while still
            // accepting writes — treating those as Insufficient blocked all
            // downloads (R1). Admit with a warning when the path exists;
            // ENOSPC on write still fails the transfer safely.
            if download_dir.exists() {
                warn!(
                    "Could not check disk space on {}: {e}; allowing start (volume exists)",
                    download_dir.display()
                );
                DiskSpaceProbe::Unknown
            } else {
                warn!(
                    "Could not check disk space on {}: {e}; treating as insufficient (path missing)",
                    download_dir.display()
                );
                DiskSpaceProbe::Missing
            }
        }
    }
}

#[derive(Default)]
struct DiskSpaceCache {
    readings: HashMap<std::path::PathBuf, (DiskSpaceProbe, std::time::Instant)>,
    refreshing: HashSet<std::path::PathBuf>,
}

impl DiskSpaceCache {
    fn reading(&self, download_dir: &std::path::Path, now: std::time::Instant) -> DiskSpaceProbe {
        match self.readings.get(download_dir) {
            Some((probe, at))
                if now.saturating_duration_since(*at) <= DISK_SPACE_READING_MAX_AGE =>
            {
                *probe
            }
            _ => DiskSpaceProbe::Unknown,
        }
    }
}

/// Free space of each download folder, queried on the blocking pool and
/// cached, so the event loop never waits on `GetDiskFreeSpaceExW` — which
/// takes seconds on a slow or dropped SMB share.
///
/// At most one query per folder is outstanding: while one is stuck on a hung
/// volume, later ticks reuse the cached reading instead of parking another
/// blocking-pool thread behind it.
#[derive(Clone, Default)]
pub(super) struct DiskSpaceMonitor {
    cache: Arc<parking_lot::Mutex<DiskSpaceCache>>,
}

impl DiskSpaceMonitor {
    pub(super) fn global() -> &'static DiskSpaceMonitor {
        static MONITOR: std::sync::OnceLock<DiskSpaceMonitor> = std::sync::OnceLock::new();
        MONITOR.get_or_init(DiskSpaceMonitor::default)
    }

    /// The last reading for `download_dir`, or `Unknown` when there is none
    /// yet or it is older than [`DISK_SPACE_READING_MAX_AGE`]. Starts a
    /// background refresh unless one is already running for the folder, so
    /// the answer trails the volume by up to one call. Never blocks on the
    /// filesystem.
    pub(super) fn reading_and_refresh(&self, download_dir: &std::path::Path) -> DiskSpaceProbe {
        let mut cache = self.cache.lock();
        let reading = cache.reading(download_dir, std::time::Instant::now());
        if cache.refreshing.insert(download_dir.to_path_buf()) {
            drop(cache);
            self.spawn_refresh(download_dir.to_path_buf());
        }
        reading
    }

    fn spawn_refresh(&self, download_dir: std::path::PathBuf) {
        // Moved into the task so `refreshing` is cleared even if the probe
        // panics or the task is dropped unrun at runtime shutdown.
        struct RefreshGuard(Arc<parking_lot::Mutex<DiskSpaceCache>>, std::path::PathBuf);
        impl Drop for RefreshGuard {
            fn drop(&mut self) {
                self.0.lock().refreshing.remove(&self.1);
            }
        }
        let guard = RefreshGuard(self.cache.clone(), download_dir.clone());
        tokio::task::spawn_blocking(move || {
            let probe = probe_disk_space(&download_dir);
            guard
                .0
                .lock()
                .readings
                .insert(download_dir, (probe, std::time::Instant::now()));
            drop(guard);
        });
    }
}

/// The free space a pending download needs, judged on the volume that holds
/// its `.part`: an unfinished download stays in the download folder it
/// started in, which need not share a volume with the current one. One
/// reading per folder serves a whole tick.
pub(super) struct PartVolumes<'a> {
    monitor: &'a DiskSpaceMonitor,
    current: std::path::PathBuf,
    readings: HashMap<std::path::PathBuf, DiskSpaceProbe>,
}

impl<'a> PartVolumes<'a> {
    pub(super) fn new(monitor: &'a DiskSpaceMonitor, current: std::path::PathBuf) -> Self {
        Self {
            monitor,
            current,
            readings: HashMap::new(),
        }
    }

    /// Whether the volume holding `transfer_id`'s `.part` has room for
    /// `needed_bytes`. An earlier folder that is not there does not count as
    /// full: the worker holds such a download until its drive is back, which
    /// marking it Insufficient would turn into a manual resume.
    pub(super) fn suffices(&mut self, transfer_id: &str, needed_bytes: u64) -> bool {
        let folder = crate::storage::part_folders::located_folder(transfer_id)
            .unwrap_or_else(|| self.current.clone());
        let monitor = self.monitor;
        let probe = *self
            .readings
            .entry(folder.clone())
            .or_insert_with(|| monitor.reading_and_refresh(&folder));
        if probe == DiskSpaceProbe::Missing && folder != self.current {
            return true;
        }
        disk_space_suffices(probe, &folder, needed_bytes)
    }
}

/// Whether `probe` leaves room for `needed_bytes` plus [`DISK_SPACE_BUFFER`].
pub(super) fn disk_space_suffices(
    probe: DiskSpaceProbe,
    download_dir: &std::path::Path,
    needed_bytes: u64,
) -> bool {
    match probe {
        DiskSpaceProbe::Available(available) => {
            if available < needed_bytes.saturating_add(DISK_SPACE_BUFFER) {
                warn!(
                    "Insufficient disk space: need {} bytes (+ {} buffer), only {} available in {}",
                    needed_bytes,
                    DISK_SPACE_BUFFER,
                    available,
                    download_dir.display()
                );
                false
            } else {
                true
            }
        }
        DiskSpaceProbe::Unknown => true,
        DiskSpaceProbe::Missing => false,
    }
}

pub(super) async fn save_part_tracker_snapshot(
    tracker: Arc<RwLock<ed2k::part_tracker::PartTracker>>,
    transfer_id: &str,
    reason: &str,
) {
    let read_result = tokio::time::timeout(std::time::Duration::from_secs(2), tracker.read()).await;
    let snapshot = match read_result {
        Ok(guard) => guard.clone(),
        Err(_) => {
            warn!("Timed out acquiring tracker lock for {transfer_id}; .part.met not saved during {reason}");
            return;
        }
    };

    let save_result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::task::spawn_blocking(move || snapshot.save()),
    )
    .await;

    match save_result {
        Ok(Ok(())) => {
            debug!("Saved .part.met for {transfer_id} during {reason}");
        }
        Ok(Err(e)) => {
            warn!("Failed to join .part.met save for {transfer_id} during {reason}: {e}");
        }
        Err(_) => {
            warn!("Timed out writing .part.met for {transfer_id} during {reason}");
        }
    }
}

/// Serializes fire-and-forget transfer status writes so a later live state
/// cannot be overwritten by an earlier `spawn_blocking` that lost the race.
pub(crate) struct TransferStatusWriteClock {
    pub(super) seq: std::sync::atomic::AtomicU64,
    pub(super) last: std::sync::Mutex<HashMap<String, u64>>,
}

impl TransferStatusWriteClock {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            seq: std::sync::atomic::AtomicU64::new(1),
            last: std::sync::Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn next_seq(&self) -> u64 {
        self.seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Drop a transfer's entry once its row is gone.
    ///
    /// The map is otherwise insert-only, so it retained one `String` + `u64` per
    /// transfer id that ever received a status write for the life of the
    /// process. Stale entries were inert — a re-added transfer gets a fresh
    /// UUID and sequence numbers are monotonic — but this is the same per-id
    /// map leak the teardown paths clean up for every other map.
    pub(crate) fn forget(&self, transfer_id: &str) {
        let mut last = match self.last.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        last.remove(transfer_id);
    }
}

/// The one clock every transfer-status writer must order against.
///
/// Process-wide because there is exactly one `transfers` table and two
/// independent writers — the network task's fire-and-forget
/// `spawn_transfer_status_write` and the IPC handlers in
/// `commands::transfers` — and a clock only orders writes that go *through*
/// it. Threading one instance through both `NetworkDeps` and `AppState` would
/// give the same guarantee, but it would also make "two clocks" a reachable
/// mistake, and two clocks is precisely the bug this exists to prevent: an
/// unsequenced command write could land after a newer one and leave the
/// persisted status disagreeing with live state, which restore then acts on.
pub(crate) fn transfer_status_write_clock() -> &'static Arc<TransferStatusWriteClock> {
    static CLOCK: std::sync::OnceLock<Arc<TransferStatusWriteClock>> = std::sync::OnceLock::new();
    CLOCK.get_or_init(TransferStatusWriteClock::new)
}

pub(super) fn transfer_status_write_is_stale(applied: Option<u64>, seq: u64) -> bool {
    applied.is_some_and(|a| seq <= a)
}

pub(crate) fn apply_transfer_status_write(
    clock: &TransferStatusWriteClock,
    db: &Database,
    transfer_id: &str,
    status: &str,
    seq: u64,
) {
    let mut last = match clock.last.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if transfer_status_write_is_stale(last.get(transfer_id).copied(), seq) {
        return;
    }
    // Record seq even when SQLite fails so a slower older write cannot
    // land after a newer attempt. The next user-visible transition gets a
    // fresh seq.
    last.insert(transfer_id.to_string(), seq);
    if let Err(e) = db.update_transfer_status(transfer_id, status) {
        warn!("DB update_transfer_status('{status}') failed for {transfer_id}: {e}");
    }
}

impl TransferStatusWriteClock {
    /// [`apply_transfer_status_write`] for many `(id, status, seq)` rows: the
    /// same per-id stale check, but every fresh row lands in one transaction.
    /// Holds the clock for the whole write, as the single-row path does, so no
    /// other sequenced write can interleave with the batch.
    pub(crate) fn apply_status_writes(&self, db: &Database, writes: &[(String, String, u64)]) {
        let mut last = match self.last.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let mut fresh: Vec<(&str, &str)> = Vec::with_capacity(writes.len());
        for (transfer_id, status, seq) in writes {
            if transfer_status_write_is_stale(last.get(transfer_id.as_str()).copied(), *seq) {
                continue;
            }
            last.insert(transfer_id.clone(), *seq);
            fresh.push((transfer_id.as_str(), status.as_str()));
        }
        if let Err(e) = db.update_transfer_statuses(&fresh) {
            warn!("DB update_transfer_statuses failed for {} transfer(s): {e}", fresh.len());
        }
    }
}

/// The completion counterpart of [`apply_transfer_status_write`].
///
/// Ordered against the same clock — a completion that lost a race to a newer
/// status must not resurrect the row — but commits the final progress, the
/// status, the history row and the optional delete in one transaction instead
/// of four independent statements.
pub(crate) fn apply_transfer_completion_write(
    clock: &TransferStatusWriteClock,
    db: &Database,
    transfer_id: &str,
    final_total: Option<u64>,
    history: Option<(String, String, u64)>,
    remove_row: bool,
    seq: u64,
) {
    let mut last = match clock.last.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if transfer_status_write_is_stale(last.get(transfer_id).copied(), seq) {
        return;
    }
    last.insert(transfer_id.to_string(), seq);
    let history = history
        .as_ref()
        .map(|(hash, name, size)| (hash.as_str(), name.as_str(), *size));
    if let Err(e) = db.complete_transfer(transfer_id, final_total, history, remove_row) {
        warn!("DB complete_transfer failed for {transfer_id}: {e}");
    }
}

pub(super) fn spawn_transfer_status_write(
    clock: &Arc<TransferStatusWriteClock>,
    db: Arc<Database>,
    transfer_id: String,
    status: &'static str,
) {
    let seq = clock.next_seq();
    let clock = Arc::clone(clock);
    tokio::task::spawn_blocking(move || {
        apply_transfer_status_write(&clock, &db, &transfer_id, status, seq);
    });
}

pub(super) async fn mark_download_insufficient(
    transfer_manager: &Arc<RwLock<TransferManager>>,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    transfer_id: &str,
    file_name: &str,
    status_writes: &Arc<TransferStatusWriteClock>,
) -> Vec<Transfer> {
    let promoted = {
        let mut mgr = transfer_manager.write().await;
        // Stop any still-running workers so they do not keep retrying
        // writes against a full volume.
        if let Some(control) = mgr.get_control(transfer_id) {
            control.cancel();
        }
        mgr.update_status(transfer_id, TransferStatus::Insufficient);
        mgr.set_failure_context(
            transfer_id,
            Some(ed2k::transfer::TransferFailureCode::InsufficientDisk),
            Some("insufficient_disk".to_string()),
            Some("disk_space".to_string()),
        );
        // Free the concurrent slot and promote the next queued download (T2).
        mgr.promote_available()
    };
    spawn_transfer_status_write(
        status_writes,
        db.clone(),
        transfer_id.to_string(),
        "insufficient",
    );
    let _ = app_handle.emit(
        "transfer-status",
        serde_json::json!({
            "id": transfer_id,
            "status": "insufficient",
            "error": ed2k::transfer::TransferFailureCode::InsufficientDisk.message(),
            "failure_code": ed2k::transfer::TransferFailureCode::InsufficientDisk.as_code(),
            "failure_kind": "insufficient_disk",
            "failure_stage": "disk_space",
            "file_name": file_name,
        }),
    );
    promoted
}

pub(super) fn emit_transfer_health(app_handle: &tauri::AppHandle, update: &TransferHealthUpdate) {
    let _ = app_handle.emit(
        "transfer-health",
        serde_json::json!({
            "id": update.id,
            "health": update.health,
            "health_reason": update.health_reason,
            "health_code": update.health_code,
            "stalled_since": update.stalled_since,
            "failure_reason": update.failure_reason,
            "failure_code": update.failure_code,
            "failure_kind": update.failure_kind,
            "failure_stage": update.failure_stage,
        }),
    );
}

/// Whether a pending download may get a dial worker now.
///
/// Only rows actively waiting for sources or slots: in the active map
/// (promoted). Queued-in-queue rows sit in `pending_downloads` for discovery
/// and wait for `promote_next`; starting one runs it past Max concurrent
/// downloads while the UI still reads Queued. Paused / Stopped / Insufficient /
/// terminal must never dial from a stale pending. Queued-in-active is a
/// promoted row that still needs a worker (T2 promote-after-insufficient).
pub(super) fn may_start_download_worker(mgr: &TransferManager, transfer_id: &str) -> bool {
    mgr.active.get(transfer_id).is_some_and(|t| {
        matches!(
            t.status,
            TransferStatus::Searching
                | TransferStatus::Active
                | TransferStatus::Hashing
                | TransferStatus::Queued
        )
    })
}

pub(super) async fn try_start_pending_download_from_known_sources(
    state: &mut NetworkState,
    transfer_id: &str,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    credit_manager: &Arc<RwLock<CreditManager>>,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
    dl_event_tx: &mpsc::Sender<DownloadEvent>,
    app_handle: &tauri::AppHandle,
    settings: &AppSettings,
    shared_ember_payload: &ember::SharedEmberPayload,
    ember_payload_generation: &ember::EmberPayloadGeneration,
    shared_banned_ips: &ed2k::upload::SharedBannedIps,
    geoip: &crate::geoip::GeoIpReader,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    ember_hash: [u8; 16],
    ed25519_pubkey: [u8; 32],
    ed25519_secret_key: [u8; 32],
    sx_overhead: &crate::storage::statistics::SharedSxOverheadCounters,
    file_req_overhead: &crate::storage::statistics::SharedFileReqOverheadCounters,
    epx_overhead: &crate::storage::statistics::SharedSxOverheadCounters,
) -> bool {
    // The user asked activity to stop. Disconnect re-queues every active
    // download as pending so it resumes on reconnect, but the Ember overlay
    // keeps running and its source lookups call straight back into here — so
    // without this gate a transfer the user just stopped could restart itself
    // from an Ember source while the UI still read Disconnected. Checked here
    // rather than at the five call sites so no future one can miss it.
    if state
        .user_offline
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        debug!("Not starting {transfer_id}: the user is offline");
        return false;
    }

    if let Some(pd) = state.pending_downloads.get(transfer_id) {
        if pd.control.is_paused() || pd.control.is_cancelled() {
            return false;
        }
    }

    if !may_start_download_worker(&*transfer_manager.read().await, transfer_id) {
        return false;
    }

    let Some(pending) = state.pending_downloads.remove(transfer_id) else {
        return false;
    };

    let hash_bytes = match hex::decode(&pending.file_hash) {
        Ok(b) if b.len() == 16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            // Do not re-queue a permanently invalid hash — it would sit in
            // Searching forever. Fail the transfer so the UI can clear it.
            warn!(
                "Pending download {transfer_id} has invalid file hash {:?}; failing transfer",
                pending.file_hash
            );
            let _ = dl_event_tx
                .send(DownloadEvent::Failed {
                    transfer_id: pending.transfer_id,
                    error: "Invalid file hash in pending download".to_string(),
                    failure_kind: SourceFailureKind::Permanent,
                })
                .await;
            return false;
        }
    };

    let sm_sources = {
        let sm = source_manager.read().await;
        sm.get_sources(&hash_bytes)
    };
    let live_sources: Vec<(String, u16)> = sm_sources
        .into_iter()
        .filter(|(ip, port)| {
            !state
                .dead_sources
                .is_dead_source_for_file(&hash_bytes, u32::from(*ip), *port)
                && is_source_admissible(state, *ip, *port, None)
        })
        .map(|(ip, port)| (ip.to_string(), port))
        .collect();

    if live_sources.is_empty() {
        if !pending_download_has_parked_ember_sources(state, transfer_id) {
            state
                .pending_downloads
                .insert(transfer_id.to_string(), pending);
            return false;
        }
    }

    let source_count = live_sources
        .len()
        .max(
            state
                .per_file_sources
                .get(transfer_id)
                .map(|pfs| pfs.sources.len())
                .unwrap_or(0),
        ) as u32;
    {
        let mut mgr = transfer_manager.write().await;
        // Re-check under the same write lock that flips the row to Active.
        // Every step since the gate at the top of this function awaited, and
        // Pause/Stop lands from another task: `pause_transfers_batch` pauses and
        // cancels the control and writes Paused *before* the network task even
        // sees `PauseDownload`. A pause that arrived during those awaits used to
        // be overwritten right here, and the worker below then started on an
        // already-cancelled control, exited immediately, and left the row Active
        // with nothing behind it — while `PauseDownload` only aborted a handle
        // and never restored Paused. Checking the control and the status
        // together, holding the lock, is what makes the two arrival orders
        // equivalent.
        if pending.control.is_paused() || pending.control.is_cancelled() {
            debug!("Not starting {transfer_id}: paused or cancelled while collecting sources");
            drop(mgr);
            state
                .pending_downloads
                .insert(transfer_id.to_string(), pending);
            return false;
        }
        let still_startable = mgr.active.get(transfer_id).is_some_and(|t| {
            matches!(
                t.status,
                TransferStatus::Searching
                    | TransferStatus::Active
                    | TransferStatus::Hashing
                    | TransferStatus::Queued
            )
        });
        if !still_startable {
            debug!("Not starting {transfer_id}: no longer in a startable state");
            drop(mgr);
            state
                .pending_downloads
                .insert(transfer_id.to_string(), pending);
            return false;
        }
        mgr.update_status(transfer_id, TransferStatus::Active);
        mgr.update_sources(transfer_id, source_count, 0, 0);
    }
    let _ = app_handle.emit(
        "transfer-status",
        serde_json::json!({
            "id": transfer_id,
            "status": "active",
            "sources": source_count,
            "active_sources": 0,
            "queued_sources": 0,
        }),
    );

    {
        let pfs = state
            .per_file_sources
            .entry(transfer_id.to_string())
            .or_insert_with(|| {
                ed2k::sources::PerFileSourceList::new(hash_bytes, state.max_sources_per_file)
            });
        let udp_sources = {
            let sm = source_manager.read().await;
            sm.get_udp_sources(&hash_bytes)
        };
        for (ip_s, port) in &live_sources {
            if let Ok(v4) = ip_s.parse::<Ipv4Addr>() {
                let udp_port = udp_sources
                    .iter()
                    .find(|(ip, tcp_port, _)| ip == &v4 && tcp_port == port)
                    .map(|(_, _, udp)| *udp)
                    .unwrap_or(0);
                if pfs.add_source_full(v4, *port, udp_port) {
                    state.ember_payload_dirty = true;
                }
            }
        }
    }

    {
        let mut sm = source_manager.write().await;
        for (ip, port) in &live_sources {
            if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                sm.register_source(hash_bytes, v4, *port, None);
            }
        }
    }
    // D9: dedup by (ip, port) before handing sources to the downloader so
    // we don't spawn two concurrent handshakes to the same peer (common
    // when a source is discovered via both the server list and SX/KAD).
    let download_sources: Vec<DownloadSource> = {
        let sm = source_manager.read().await;
        let mut seen: HashSet<(String, u16)> = HashSet::new();
        let mut out: Vec<DownloadSource> = Vec::with_capacity(live_sources.len());
        for (ip, port) in &live_sources {
            if !seen.insert((ip.clone(), *port)) {
                continue;
            }
            let uh = ip
                .parse::<Ipv4Addr>()
                .ok()
                .and_then(|v4| sm.get_user_hash(&hash_bytes, v4, *port));
            let co = ip
                .parse::<Ipv4Addr>()
                .ok()
                .and_then(|v4| sm.get_connect_options(&hash_bytes, v4, *port));
            out.push(DownloadSource {
                peer_ip: ip.clone(),
                peer_port: *port,
                available_parts: Vec::new(),
                peer_user_hash: uh,
                peer_connect_options: co,
            });
        }
        out
    };
    let (src_inject_tx, src_inject_rx) = mpsc::channel::<DownloadSource>(32);
    // Parallel channel for pre-handshaked peer streams. Sized small —
    // it only sees inbound LowID callbacks for files we're actively
    // downloading, which is naturally rate-limited by NAT-traversal
    // round-trips.
    let (est_inject_tx, est_inject_rx) =
        mpsc::channel::<ed2k::multi_source::EstablishedSource>(ESTABLISHED_SOURCE_CHANNEL_CAP);
    let expected_aich_master = expected_aich_bytes(pending.expected_aich.as_deref());
    let ms_download = MultiSourceDownload {
        transfer_id: pending.transfer_id,
        file_hash: hash_bytes,
        file_name: pending.file_name,
        file_size: pending.file_size,
        sources: download_sources,
        download_folders: state.download_folders.clone(),
        user_hash: state.user_hash,
        nickname: settings.nickname.clone(),
        tcp_port: advertised_tcp_port(state),
        udp_port: advertised_udp_port(state),
        bandwidth_limiter: bandwidth_limiter.clone(),
        control: pending.control,
        source_manager: Some(source_manager.clone()),
        comment_manager: Some(state.comment_manager.clone()),
        credit_manager: Some(credit_manager.clone()),
        shared_buddy_info: Some(state.shared_buddy_info.clone()),
        obfuscation_enabled: state.obfuscation_enabled,
        server_addr: state.server_addr,
        new_source_rx: Some(src_inject_rx),
        new_established_rx: Some(est_inject_rx),
        ed2k_limits: settings.ed2k_download_limits(),
        ember_hash,
        ed25519_public_key: ed25519_pubkey,
        ed25519_secret_key,
        friend_hashes: Some(friend_hashes.clone()),
        ember_payload: shared_ember_payload.clone(),
        ember_payload_generation: ember_payload_generation.clone(),
        ip_filter: Some(state.shared_ip_filter.clone()),
        banned_ips: Some(shared_banned_ips.clone()),
        external_ip: state.external_ip,
        aich_pending: Some(state.aich_recovery_pending.clone()),
        trusted_aich_master: expected_aich_master
            .or_else(|| state.aich_root_map.get(&hash_bytes).copied()),
        expected_aich_master,
        ember_file_hash: state
            .ember_content_hashes
            .get(&hash_bytes)
            .map(|pin| pin.digest)
            .unwrap_or([0u8; 32]),
        geoip: geoip.clone(),
        tracker_registry: Some(state.tracker_registry.clone()),
        sx_overhead: sx_overhead.clone(),
        epx_overhead: epx_overhead.clone(),
        file_req_overhead: file_req_overhead.clone(),
    };
    let dl_tid = ms_download.transfer_id.clone();
    let dl_tid2 = dl_tid.clone();
    info!(
        "Starting download {} ({}) with {} live source(s){} [try_start_from_known]",
        dl_tid,
        hex::encode(hash_bytes),
        live_sources.len(),
        if live_sources.is_empty() {
            " — parked peers only, worker waits for a firewalled connect-back"
        } else {
            ""
        }
    );
    state
        .active_source_senders
        .insert(dl_tid.clone(), src_inject_tx);
    state
        .active_established_senders
        .insert(dl_tid.clone(), est_inject_tx);
    let tx = dl_event_tx.clone();
    let tx2 = tx.clone();
    let old_tracker = state.tracker_registry.lock().get(&dl_tid2).cloned();
    if let Some(old_handle) = state.download_handles.remove(&dl_tid2) {
        debug!(
            "Aborting existing download task for {dl_tid2} before starting multi-source download"
        );
        // Same teardown the `StartDownload` path does. It used to be
        // defensible to skip it here because a worker reaching this point had
        // almost certainly already exited — but a transfer whose only peers are
        // parked now starts a worker that deliberately stays alive waiting for
        // a connect-back, so this can genuinely abort a live one.
        //
        // The waits run off the network task, matching `CancelDownload` and
        // `PauseDownload`: `abort()` cannot pre-empt a worker parked in
        // `spawn_blocking` (final verify, MD4, fsync), so joining it inline held
        // UDP receive, every timer and every IPC snapshot for up to 7 s. The
        // `.part` hand-off does not rely on this wait — `PART_WRITER_GATES` in
        // the write coordinator holds the new `PartFileWriter` until the old
        // writer thread has closed its handle, whichever start path spawned it.
        old_handle.abort();
        let teardown_tid = dl_tid2.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), old_handle).await;
            if let Some(tracker) = old_tracker {
                let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                    loop {
                        let idle = {
                            let t = tracker.read().await;
                            t.in_progress_part_count() == 0 && t.write_reservation_count() == 0
                        };
                        if idle {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                })
                .await;
            }
            debug!("Previous download worker for {teardown_tid} finished teardown");
        });
    }
    let handle = tokio::spawn(async move {
        if let Err(e) = ms_download.run(tx).await {
            error!("Multi-source download failed: {e}");
            let kind = classify_error(&e.to_string());
            let _ = tx2
                .send(DownloadEvent::Failed {
                    transfer_id: dl_tid,
                    error: e.to_string(),
                    failure_kind: kind,
                })
                .await;
        }
    });
    state.download_handles.insert(dl_tid2, handle);

    true
}

#[cfg(test)]
mod disk_space_probe_tests {
    use super::*;

    #[test]
    fn available_space_is_compared_with_the_buffer_included() {
        let dir = std::path::Path::new("downloads");
        let needed = 10 * 1024 * 1024;
        let exact = needed + DISK_SPACE_BUFFER;
        assert!(disk_space_suffices(DiskSpaceProbe::Available(exact), dir, needed));
        assert!(!disk_space_suffices(DiskSpaceProbe::Available(exact - 1), dir, needed));
        assert!(!disk_space_suffices(DiskSpaceProbe::Available(0), dir, u64::MAX));
    }

    #[test]
    fn unknown_admits_and_missing_refuses() {
        let dir = std::path::Path::new("downloads");
        assert!(disk_space_suffices(DiskSpaceProbe::Unknown, dir, u64::MAX));
        assert!(!disk_space_suffices(DiskSpaceProbe::Missing, dir, 0));
    }

    #[test]
    fn cached_reading_is_ignored_when_stale_or_for_another_folder() {
        let dir = std::path::PathBuf::from("downloads");
        let taken = std::time::Instant::now();
        let mut cache = DiskSpaceCache::default();
        assert_eq!(cache.reading(&dir, taken), DiskSpaceProbe::Unknown);

        cache
            .readings
            .insert(dir.clone(), (DiskSpaceProbe::Available(123), taken));
        assert_eq!(cache.reading(&dir, taken), DiskSpaceProbe::Available(123));
        assert_eq!(
            cache.reading(&dir, taken + DISK_SPACE_READING_MAX_AGE),
            DiskSpaceProbe::Available(123)
        );
        assert_eq!(
            cache.reading(&dir, taken + DISK_SPACE_READING_MAX_AGE + std::time::Duration::from_secs(1)),
            DiskSpaceProbe::Unknown
        );
        assert_eq!(
            cache.reading(std::path::Path::new("elsewhere"), taken),
            DiskSpaceProbe::Unknown
        );

        cache
            .readings
            .insert(dir.clone(), (DiskSpaceProbe::Missing, taken));
        assert_eq!(cache.reading(&dir, taken), DiskSpaceProbe::Missing);
    }

    #[test]
    fn each_download_is_judged_on_the_volume_holding_its_part() {
        let current = std::path::PathBuf::from("current-folder");
        let earlier = std::path::PathBuf::from("earlier-folder");
        let offline = std::path::PathBuf::from("offline-folder");
        let now = std::time::Instant::now();
        let monitor = DiskSpaceMonitor::default();
        {
            let mut cache = monitor.cache.lock();
            cache
                .readings
                .insert(current.clone(), (DiskSpaceProbe::Available(u64::MAX / 2), now));
            cache
                .readings
                .insert(earlier.clone(), (DiskSpaceProbe::Available(0), now));
            cache
                .readings
                .insert(offline.clone(), (DiskSpaceProbe::Missing, now));
            cache.refreshing.extend([current.clone(), earlier.clone(), offline.clone()]);
        }
        let in_earlier = uuid::Uuid::new_v4().to_string();
        crate::storage::part_folders::note_located(&in_earlier, &earlier);
        let in_offline = uuid::Uuid::new_v4().to_string();
        crate::storage::part_folders::note_located(&in_offline, &offline);
        let unplaced = uuid::Uuid::new_v4().to_string();

        let mut volumes = PartVolumes::new(&monitor, current.clone());
        assert!(volumes.suffices(&unplaced, 1 << 30), "judged on the current folder");
        assert!(
            !volumes.suffices(&in_earlier, 1),
            "the full volume is the earlier folder's, where this `.part` grows"
        );
        assert!(
            volumes.suffices(&in_offline, 1),
            "an earlier folder that is offline holds the download, it does not fill it"
        );

        monitor
            .cache
            .lock()
            .readings
            .insert(current.clone(), (DiskSpaceProbe::Missing, now));
        let mut volumes = PartVolumes::new(&monitor, current);
        assert!(!volumes.suffices(&unplaced, 0), "a missing current folder still refuses");
    }

    async fn wait_for_refresh(monitor: &DiskSpaceMonitor) {
        for _ in 0..500 {
            if monitor.cache.lock().refreshing.is_empty() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("background disk-space refresh never finished");
    }

    #[tokio::test]
    async fn monitor_answers_from_the_last_background_reading() {
        let monitor = DiskSpaceMonitor::default();
        let dir = std::env::temp_dir();

        assert_eq!(monitor.reading_and_refresh(&dir), DiskSpaceProbe::Unknown);
        assert!(monitor.cache.lock().refreshing.contains(&dir));
        wait_for_refresh(&monitor).await;

        assert!(matches!(
            monitor.reading_and_refresh(&dir),
            DiskSpaceProbe::Available(_)
        ));
        wait_for_refresh(&monitor).await;
    }

    #[tokio::test]
    async fn monitor_never_starts_a_second_refresh_while_one_is_running() {
        let monitor = DiskSpaceMonitor::default();
        let dir = std::env::temp_dir();
        monitor.cache.lock().refreshing.insert(dir.clone());

        assert_eq!(monitor.reading_and_refresh(&dir), DiskSpaceProbe::Unknown);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let cache = monitor.cache.lock();
        assert!(cache.refreshing.contains(&dir));
        assert!(cache.readings.is_empty());
    }
}
