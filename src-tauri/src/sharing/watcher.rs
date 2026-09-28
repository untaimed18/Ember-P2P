use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use notify::event::{AccessKind, AccessMode, MetadataKind, ModifyKind, RenameMode};
use notify::{recommended_watcher, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::Mutex;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::app_state::AppState;

/// Keeps a filesystem watcher in sync with the currently shared folders and
/// triggers a background re-scan + `shared-files-changed` event whenever a
/// file is added, removed, or modified underneath any shared folder.
///
/// Behaviour summary:
/// - A single `notify` watcher watches every shared folder recursively.
/// - Events that are side-effects of reading a folder (Linux inotify `OPEN`,
///   close-after-read, atime `ATTRIB`) are ignored. Without that filter a
///   scan's own `read_dir` retriggers the watcher, which rescans, which opens
///   the directory again — a loop every debounce window, which is what a
///   first Linux run produced on an empty Incoming folder.
/// - Each accepted event records the paths it names and sends one ping on an
///   internal channel; the handler task coalesces pings and rescans only
///   those paths (see [`crate::commands::sharing::rescan_shared_paths`]).
///   An event that names no path — the backend saying events were dropped —
///   or more paths than a scoped pass is worth falls back to the full
///   `reload_shared_files`.
/// - Folders added via `add_shared_folder` are added with `sync_paths`;
///   folders removed via `remove_shared_folder` are unwatched the same way.
pub struct SharedFoldersWatcher {
    watched: Mutex<HashSet<PathBuf>>,
    watcher: Mutex<Option<RecommendedWatcher>>,
    /// The last full set of folders we were asked to watch, including any that
    /// were offline at the time. `watched` holds only those actually
    /// registered, so this is what lets the retry loop tell "not requested"
    /// apart from "requested but unavailable".
    desired: Mutex<Vec<String>>,
    pending: Arc<Mutex<PendingRescan>>,
    reload_tx: mpsc::Sender<()>,
}

/// Distinct paths one scoped rescan takes on before a full reload is cheaper
/// than probing each of them.
const MAX_SCOPED_RESCAN_PATHS: usize = 512;

/// What the next rescan has to cover.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RescanScope {
    Full,
    Paths(Vec<PathBuf>),
}

/// Paths accepted events have named since the driver last took them.
#[derive(Debug, Default)]
pub(crate) struct PendingRescan {
    full: bool,
    paths: HashSet<PathBuf>,
    /// Departures under a name discovery never shares (see
    /// [`rescan_paths_for_event`]), rescanned only if the index turns out to
    /// hold rows at or under them.
    unconfirmed: HashSet<PathBuf>,
}

impl PendingRescan {
    pub(crate) fn note_paths(&mut self, paths: impl IntoIterator<Item = PathBuf>) {
        if self.full {
            return;
        }
        self.paths.extend(paths);
        if self.paths.len() > MAX_SCOPED_RESCAN_PATHS {
            self.note_full();
        }
    }

    pub(crate) fn note_unconfirmed(&mut self, paths: impl IntoIterator<Item = PathBuf>) {
        if self.full {
            return;
        }
        for path in paths {
            // Past the cap these are dropped rather than escalated: a file
            // under such a name is never indexed, so only a folder could hold
            // rows, and hundreds of those vanishing at once is not a real case.
            if self.unconfirmed.len() >= MAX_SCOPED_RESCAN_PATHS {
                break;
            }
            self.unconfirmed.insert(path);
        }
    }

    pub(crate) fn take_unconfirmed(&mut self) -> Vec<PathBuf> {
        self.unconfirmed.drain().collect()
    }

    pub(crate) fn note_full(&mut self) {
        self.full = true;
        self.paths.clear();
        self.unconfirmed.clear();
    }

    pub(crate) fn take(&mut self) -> Option<RescanScope> {
        if std::mem::take(&mut self.full) {
            return Some(RescanScope::Full);
        }
        if self.paths.is_empty() {
            return None;
        }
        Some(RescanScope::Paths(self.paths.drain().collect()))
    }

    /// Put back a scope whose rescan could not start, merged with anything
    /// noted since.
    pub(crate) fn restore(&mut self, scope: RescanScope) {
        match scope {
            RescanScope::Full => self.note_full(),
            RescanScope::Paths(paths) => self.note_paths(paths),
        }
    }
}

/// How often to retry shared folders that could not be watched — an external
/// or network drive that was disconnected at launch, or a directory that
/// disappeared mid-session and took its OS watch with it.
const WATCH_RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// The paths of an event that could name a file the Library would ever show —
/// what a scoped rescan of this event has to look at. Empty means the event
/// cannot change the shared set.
///
/// [`event_should_rescan`] answers "did something change"; this answers "could
/// the thing that changed ever be shared". Discovery refuses `.part`,
/// `.part.met`, `.met.tmp` and the rest of
/// [`is_excluded_share_file_name`](crate::sharing::indexer::is_excluded_share_file_name)
/// outright, so a write to one cannot alter the shared set however many of them
/// arrive — and an active download writes to nothing else. Without this check a
/// user whose incomplete-download folder sits inside a shared folder had every
/// block scheduling a full walk of the library, on a fixed cadence for as long
/// as anything was downloading: the coalescing loop below only stops waiting at
/// `MAX_COALESCE_WINDOW`, and a steady write stream never lets it time out
/// early, so the interval is that constant rather than anything about the
/// files. One reporter's log held 7,688 of them in a day, against 46,599 files
/// on external drives, every one guaranteed to find nothing.
///
/// A single shareable path is enough. A finishing download renames its `.part`
/// to the real name, and that event carries both, so the file still reaches the
/// Library on the next rescan exactly as before.
///
/// An event with no paths is not handled here: `notify` emits those for
/// backend-level notices such as an inotify queue overflow, which means events
/// were dropped — the one case where sitting still is worst — so the callback
/// sends them to a full reload.
///
/// Returns `(paths, unconfirmed)`. The name rule is only decisive for a path
/// something arrived at. A path something *left* — a delete, or the old name of
/// a rename — may have been a folder, and discovery walks folders whatever
/// they are called, so rows can sit under a name the rule refuses. Those go
/// back as `unconfirmed` for the driver to check against the index, instead of
/// being dropped (a stale row) or rescanned outright: every `.met.tmp` →
/// `.part.met` save an active download makes is such a departure.
pub(crate) fn rescan_paths_for_event(
    kind: EventKind,
    paths: &[PathBuf],
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut rescan = Vec::new();
    let mut unconfirmed = Vec::new();
    for (position, path) in paths.iter().enumerate() {
        // Names first: the name rules are pure string work while
        // `is_excluded_share_location` canonicalizes. For the case this exists
        // for — a download writing `.part` blocks — the name rule answers and
        // the syscall is never reached.
        let shareable_name = !crate::sharing::indexer::is_excluded_share_file_name(path);
        if !shareable_name && !is_departure(kind, position) {
            continue;
        }
        if crate::sharing::indexer::is_excluded_share_location(path) {
            continue;
        }
        if shareable_name {
            rescan.push(path.clone());
        } else {
            unconfirmed.push(path.clone());
        }
    }
    (rescan, unconfirmed)
}

/// Whether the event's path at `position` names where something used to be.
/// A rename reported as one event carries the old name first.
fn is_departure(kind: EventKind, position: usize) -> bool {
    match kind {
        EventKind::Remove(_) => true,
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => position == 0,
        EventKind::Modify(ModifyKind::Name(RenameMode::To)) => false,
        EventKind::Modify(ModifyKind::Name(_)) => true,
        _ => false,
    }
}

/// Whether the index holds a row at `path` or anywhere under it.
fn index_has_rows_at_or_under(index: &crate::search::index::LocalIndex, path: &Path) -> bool {
    index.has_rows_at_or_under(&path.to_string_lossy())
}

/// True when this event means a shareable file may have appeared, vanished, or
/// changed content. `notify` 8's Linux backend includes `OPEN` and `ATTRIB` in
/// the default inotify mask; those fire when we walk a folder to index it, so
/// they must not schedule a reload. `CLOSE_WRITE` is reported as
/// `Access(Close(Write))` and *does* mean a copy finished.
pub(crate) fn event_should_rescan(kind: EventKind) -> bool {
    match kind {
        EventKind::Create(_) | EventKind::Remove(_) => true,
        EventKind::Modify(ModifyKind::Data(_)) => true,
        EventKind::Modify(ModifyKind::Name(_)) => true,
        EventKind::Modify(ModifyKind::Any) => true,
        // Poll-watcher mtime (and `touch`) — not Linux inotify ATTRIB.
        EventKind::Modify(ModifyKind::Metadata(MetadataKind::WriteTime)) => true,
        EventKind::Modify(ModifyKind::Metadata(_)) => false,
        EventKind::Modify(ModifyKind::Other) => false,
        EventKind::Access(AccessKind::Close(AccessMode::Write)) => true,
        EventKind::Access(_) => false,
        EventKind::Any | EventKind::Other => true,
    }
}

impl SharedFoldersWatcher {
    /// Create and start the watcher. Returns `None` if the OS-level watcher
    /// cannot be initialised (in which case live folder tracking is simply
    /// disabled — the app still functions, the user just needs to reload
    /// manually).
    pub fn start(app: AppHandle, initial_paths: Vec<String>) -> Option<Arc<Self>> {
        // Bounded ping channel — the coalescing loop only needs to know that
        // *some* event arrived, so a small capacity plus `try_send` drops
        // extras. This caps memory under a bulk copy that fires thousands of
        // notifications before the reload driver catches up.
        let (reload_tx, mut reload_rx) = mpsc::channel::<()>(8);
        let pending = Arc::new(Mutex::new(PendingRescan::default()));
        let pending_for_driver = pending.clone();

        // Reload driver task: coalesces pings, emits the UI event, and runs
        // either a scoped rescan of the paths the events named or the full
        // reload_shared_files, so the heavy lifting (discover, hash, publish)
        // is shared with the manual-reload path.
        let app_for_handler = app.clone();
        // Lets the driver re-arm itself when a reload is rejected because one
        // is already in flight.
        let reload_tx_for_retry = reload_tx.clone();
        // NOTE: must use `tauri::async_runtime::spawn` (not `tokio::spawn`)
        // because `SharedFoldersWatcher::start` is called from Tauri's
        // synchronous `setup` hook, which is not itself running inside a
        // Tokio reactor context.
        tauri::async_runtime::spawn(async move {
            /// How long to wait before retrying a rescan that collided with a
            /// scan already in progress. Long enough not to spin, short enough
            /// that files land in the Library promptly once the scan ends.
            const RELOAD_RETRY_DELAY: Duration = Duration::from_secs(5);
            // Upper bound on total time we'll defer a rescan while new events
            // keep arriving. Without this, a long-running bulk copy that emits
            // a steady trickle of events could starve the reload indefinitely.
            const MAX_COALESCE_WINDOW: Duration = Duration::from_secs(15);
            // Quiet window after the first ping. Replaces notify-debouncer-mini's
            // 2s debounce now that we filter events ourselves.
            const COALESCE_COOLDOWN: Duration = Duration::from_secs(2);

            while reload_rx.recv().await.is_some() {
                let first_event = std::time::Instant::now();
                while reload_rx.try_recv().is_ok() {}
                tokio::time::sleep(COALESCE_COOLDOWN).await;
                while reload_rx.try_recv().is_ok() {}

                // If more events arrived during the cooldown, coalesce them
                // but stop deferring once we've been holding the rescan for
                // longer than MAX_COALESCE_WINDOW.
                loop {
                    let elapsed = first_event.elapsed();
                    if elapsed >= MAX_COALESCE_WINDOW {
                        break;
                    }
                    match tokio::time::timeout(COALESCE_COOLDOWN, reload_rx.recv()).await {
                        Ok(Some(_)) => while reload_rx.try_recv().is_ok() {},
                        _ => break,
                    }
                }

                let state_ref = app_for_handler.state::<AppState>();
                let unconfirmed = pending_for_driver.lock().take_unconfirmed();
                if !unconfirmed.is_empty() {
                    let confirmed = {
                        let index = state_ref.local_index.read().await;
                        unconfirmed
                            .into_iter()
                            .filter(|path| index_has_rows_at_or_under(&index, path))
                            .collect::<Vec<_>>()
                    };
                    pending_for_driver.lock().note_paths(confirmed);
                }

                // Nothing noted: a re-arm whose paths an earlier pass took, or
                // departures the index held nothing for.
                let Some(scope) = pending_for_driver.lock().take() else {
                    continue;
                };

                // An FS event during exit must not start a reload: shutdown has
                // already joined the scans it tracks, so a rescan queued now
                // would mutate `known_files` behind the authoritative flush and
                // be aborted mid-write. Leave the loop rather than `continue` —
                // the flag is never cleared, so every later ping is dead work,
                // and dropping the receiver lets the watcher's `try_send` learn
                // the driver is gone instead of filling a queue nobody drains.
                if state_ref
                    .bw_shutdown
                    .load(std::sync::atomic::Ordering::Acquire)
                {
                    info!("FS watcher: shutting down; rescan driver stopping");
                    break;
                }
                // Honour an explicit Stop: reloading here would cancel the
                // pause latch and start hashing again without user consent.
                if state_ref
                    .hashing_paused
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    // Latch dirty so a later pause-clear that does not run a
                    // full reload (e.g. add_shared_folder) still rescans.
                    state_ref
                        .hashing_fs_dirty
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    info!("FS watcher: hashing paused; deferring rescan until resume");
                    let _ = app_for_handler.emit(
                        "shared-files-changed",
                        serde_json::json!({ "phase": "fs-changed-deferred" }),
                    );
                    continue;
                }

                let _ = app_for_handler.emit(
                    "shared-files-changed",
                    serde_json::json!({ "phase": "fs-changed" }),
                );

                let result = match &scope {
                    RescanScope::Full => {
                        info!("FS watcher: triggering full shared-folder rescan");
                        crate::commands::sharing::reload_shared_files(
                            app_for_handler.clone(),
                            state_ref,
                        )
                        .await
                    }
                    RescanScope::Paths(paths) => {
                        info!("FS watcher: rescanning {} changed path(s)", paths.len());
                        crate::commands::sharing::rescan_shared_paths(
                            app_for_handler.clone(),
                            &state_ref,
                            paths.clone(),
                        )
                        .await
                    }
                };
                if let Err(e) = result {
                    // A reload already running rejects this one outright, and
                    // the coalescing loop above has already drained every
                    // queued ping — so without a re-arm the notification was
                    // simply lost. That is the common case, not a rare one:
                    // the first files copied into a shared folder start the
                    // scan, and everything copied while it runs raises exactly
                    // this rejection and never gets indexed.
                    if e.contains("sharing_reload_in_flight") {
                        pending_for_driver.lock().restore(scope);
                        let retry_tx = reload_tx_for_retry.clone();
                        tauri::async_runtime::spawn(async move {
                            tokio::time::sleep(RELOAD_RETRY_DELAY).await;
                            let _ = retry_tx.send(()).await;
                        });
                        debug!("FS watcher: a scan is already running; re-arming the rescan");
                    } else {
                        warn!("FS watcher: reload_shared_files failed: {e}");
                    }
                }
            }
        });

        let tx_for_watcher = reload_tx.clone();
        let pending_for_watcher = pending.clone();
        let watcher = match recommended_watcher(move |res: notify::Result<Event>| match res {
            Ok(event) => {
                if !event_should_rescan(event.kind) {
                    return;
                }
                if event.paths.is_empty() || event.need_rescan() {
                    pending_for_watcher.lock().note_full();
                } else {
                    // Kind alone is not enough: a download writing its `.part`
                    // file produces a genuine `Modify(Data)` on a path the scan
                    // is required to ignore, so every block scheduled a walk
                    // that could not find anything.
                    let (paths, unconfirmed) = rescan_paths_for_event(event.kind, &event.paths);
                    if paths.is_empty() && unconfirmed.is_empty() {
                        return;
                    }
                    let mut pending = pending_for_watcher.lock();
                    pending.note_paths(paths);
                    pending.note_unconfirmed(unconfirmed);
                }
                debug!("FS watcher: reload-worthy event ({:?})", event.kind);
                match tx_for_watcher.try_send(()) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        debug!("FS watcher: reload queue full, ping coalesced");
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        warn!("FS watcher: reload driver task has exited");
                    }
                }
            }
            Err(e) => warn!("FS watcher error: {e:?}"),
        }) {
            Ok(watcher) => watcher,
            Err(e) => {
                warn!("FS watcher: failed to initialise ({e}); live folder tracking disabled");
                return None;
            }
        };

        let watcher = Arc::new(Self {
            watched: Mutex::new(HashSet::new()),
            watcher: Mutex::new(Some(watcher)),
            desired: Mutex::new(initial_paths),
            pending,
            reload_tx,
        });
        // `start` runs in Tauri's synchronous `setup` hook on the main thread,
        // so registering here would put an `exists()` per shared folder — each
        // able to stall for the OS timeout on an offline network share — and,
        // on Linux, the recursive inotify walk of every tree in front of the
        // first window.
        let initial_watcher = Arc::downgrade(&watcher);
        tauri::async_runtime::spawn_blocking(move || {
            if let Some(watcher) = initial_watcher.upgrade() {
                let desired = watcher.desired.lock().clone();
                watcher.apply_watches(&desired);
                // The startup scan runs alongside this and may already have
                // walked past a folder before its watch existed, so a file
                // created in that gap would reach nothing. One scoped pass per
                // watched root finds it; it queues behind the startup scan and
                // reuses every row that scan indexed unchanged.
                let roots = watcher.watched.lock().iter().cloned().collect::<Vec<_>>();
                if !roots.is_empty() {
                    watcher.pending.lock().note_paths(roots);
                    let _ = watcher.reload_tx.try_send(());
                }
            }
        });

        // Retry folders we could not watch. `sync_paths` runs only at startup
        // and on folder add/remove, so a shared folder on an external or
        // network drive that was disconnected at launch was skipped and never
        // reconsidered: live change tracking stayed off for that folder for
        // the rest of the session even after the drive came back, and files
        // added there went unindexed until a manual reload. The same applies
        // to a watched directory that disappears mid-session, which kills its
        // OS watch with nothing to re-establish it.
        let retry_watcher = Arc::downgrade(&watcher);
        tauri::async_runtime::spawn(async move {
            loop {
                tokio::time::sleep(WATCH_RETRY_INTERVAL).await;
                let Some(watcher) = retry_watcher.upgrade() else {
                    return;
                };
                // `Path::exists` is a blocking syscall, and on the very case
                // this retry exists for — an unreachable network share — it
                // can sit for tens of seconds. Running it on a runtime worker
                // stalled that worker, and doing it under the `watched` lock
                // stalled a second one whenever an add/remove command tried to
                // take the same lock.
                let _ = tokio::task::spawn_blocking(move || watcher.resync_unwatched()).await;
            }
        });
        Some(watcher)
    }

    /// Re-watch any desired folder that is not currently being watched, and
    /// forget watches whose directory has gone away so they are re-established
    /// if it returns.
    fn resync_unwatched(&self) {
        let desired = self.desired.lock().clone();
        if desired.is_empty() {
            return;
        }
        // Probe the filesystem first and take the lock afterwards. Every
        // `exists()` here can block for as long as the OS takes to give up on
        // an unreachable share, and holding `watched` across that blocks
        // `sync_paths` — which the add/remove folder commands call — for the
        // same stretch.
        let watched_now: HashSet<PathBuf> = self.watched.lock().iter().cloned().collect();
        let vanished: Vec<PathBuf> = watched_now
            .iter()
            .filter(|path| !path.exists())
            .cloned()
            .collect();
        // Test membership against the snapshot, not a fresh `lock()`: the guard
        // temporary lived until the end of the closure body, so the lock was
        // still held across `exists()` — and `&&` short-circuits, so `exists()`
        // was reached exactly for the not-yet-watched paths this retry exists
        // for, i.e. the disconnected shares that block longest.
        let reappeared = desired
            .iter()
            .map(PathBuf::from)
            .any(|path| !watched_now.contains(&path) && path.exists());

        if !vanished.is_empty() {
            // Release the OS watch before forgetting the path. Dropping it
            // from `watched` alone left the registration in place — nothing
            // else ever unwatches it, because `sync_paths` derives its removal
            // set from `watched` — so a directory that flickered accumulated a
            // fresh watch (and handle) on the backend every time it came back.
            let mut current = self.watched.lock();
            let mut watcher_guard = self.watcher.lock();
            if let Some(watcher) = watcher_guard.as_mut() {
                for path in &vanished {
                    if let Err(e) = watcher.unwatch(path) {
                        debug!(
                            "FS watcher: could not unwatch the vanished {}: {e}",
                            path.display()
                        );
                    }
                }
            }
            for path in &vanished {
                current.remove(path);
            }
        }

        if reappeared {
            // Straight to `apply_watches`: we are already on a blocking thread,
            // and re-publishing our own `desired` snapshot through `sync_paths`
            // would overwrite a newer list an add/remove command may have
            // installed while we were probing. `apply_watches` re-reads the
            // list itself once its probes are done.
            self.apply_watches(&desired);
        }
    }

    /// Rescan `paths` once `delay` has passed, through the same driver (and
    /// in-flight re-arm) that filesystem events use.
    pub fn queue_rescan_after(&self, paths: Vec<PathBuf>, delay: Duration) {
        if paths.is_empty() {
            return;
        }
        let pending = self.pending.clone();
        let reload_tx = self.reload_tx.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(delay).await;
            pending.lock().note_paths(paths);
            let _ = reload_tx.send(()).await;
        });
    }

    /// Make the watched set exactly match `desired`. Paths that don't exist
    /// on disk are skipped (logged once). Errors from the underlying
    /// watcher are logged but non-fatal.
    pub fn sync_paths(&self, desired: &[String]) {
        // Remember the full request, including paths that are offline right
        // now, so `resync_unwatched` can pick them up when they reappear.
        *self.desired.lock() = desired.to_vec();
        // Everything below is blocking syscalls: `exists()` on an offline
        // SMB/NFS share sits for as long as the OS takes to give up, and so can
        // `watch()`. Every call site is an async Tauri command running on a
        // Tokio worker, so doing that inline parked a worker for the duration.
        // `block_in_place` hands this worker's remaining tasks to another thread
        // instead, so a stalled probe costs the caller and nothing else.
        // Outside a multi-threaded runtime apply directly, since
        // `block_in_place` is only valid on the multi-threaded scheduler.
        let on_multi_thread_worker = tokio::runtime::Handle::try_current().is_ok_and(|handle| {
            handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
        });
        if on_multi_thread_worker {
            tokio::task::block_in_place(|| self.apply_watches(desired));
        } else {
            self.apply_watches(desired);
        }
    }

    /// The blocking half of [`SharedFoldersWatcher::sync_paths`]: probe every
    /// path in `snapshot` and add/remove the OS watches to match the desired
    /// list as it stands once the probes are done.
    fn apply_watches(&self, snapshot: &[String]) {
        let probed: HashMap<PathBuf, bool> = snapshot
            .iter()
            .map(|p| {
                let pb = PathBuf::from(p);
                let exists = pb.exists();
                if !exists {
                    debug!(
                        "FS watcher: {} is not available yet; will retry",
                        pb.display()
                    );
                }
                (pb, exists)
            })
            .collect();

        let mut current = self.watched.lock();
        let mut watcher_guard = self.watcher.lock();
        let Some(watcher) = watcher_guard.as_mut() else {
            return;
        };
        // The probes above can take as long as an offline share makes them,
        // and an add/remove may have replaced the list meanwhile. Applying the
        // snapshot as-is unwatched folders added since and revived removed ones.
        let desired_now: HashSet<PathBuf> =
            self.desired.lock().iter().map(PathBuf::from).collect();
        let desired_set = watch_targets(&desired_now, &probed, &current);

        let to_remove: Vec<PathBuf> = current.difference(&desired_set).cloned().collect();
        let to_add: Vec<PathBuf> = desired_set.difference(&current).cloned().collect();

        for path in &to_remove {
            if let Err(e) = watcher.unwatch(path) {
                warn!("FS watcher: failed to unwatch {}: {e}", path.display());
            }
            current.remove(path);
        }
        for path in &to_add {
            match watcher.watch(path, RecursiveMode::Recursive) {
                Ok(()) => {
                    current.insert(path.clone());
                    debug!("FS watcher: watching {}", path.display());
                }
                Err(e) => warn!("FS watcher: failed to watch {}: {e}", path.display()),
            }
        }

        if !to_add.is_empty() || !to_remove.is_empty() {
            info!(
                "FS watcher: now tracking {} folder(s) (+{}, -{})",
                current.len(),
                to_add.len(),
                to_remove.len()
            );
        }
    }
}

/// Which folders should be watched: those desired now whose probe found them.
/// A folder desired now but not probed — added after the probing snapshot was
/// taken — keeps whatever state it has; the `sync_paths` that added it applies
/// it with its own probe.
fn watch_targets(
    desired_now: &HashSet<PathBuf>,
    probed: &HashMap<PathBuf, bool>,
    current: &HashSet<PathBuf>,
) -> HashSet<PathBuf> {
    desired_now
        .iter()
        .filter(|path| match probed.get(*path) {
            Some(&exists) => exists,
            None => current.contains(*path),
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        event_should_rescan, index_has_rows_at_or_under, rescan_paths_for_event, watch_targets,
        PendingRescan, RescanScope, MAX_SCOPED_RESCAN_PATHS,
    };
    use std::collections::{HashMap, HashSet};

    const WRITE: EventKind = EventKind::Modify(ModifyKind::Data(DataChange::Any));

    /// Whether the watcher callback schedules a rescan for a write naming these
    /// paths.
    fn event_paths_can_change_the_share(paths: &[PathBuf]) -> bool {
        paths.is_empty() || !rescan_paths_for_event(WRITE, paths).0.is_empty()
    }

    /// A write to a name discovery refuses is noise, but the same name
    /// *leaving* may have been a folder full of indexed files. Those departures
    /// are held for an index check rather than dropped or rescanned outright.
    #[test]
    fn departures_under_refused_names_are_held_for_an_index_check() {
        let temp_folder = PathBuf::from("/home/u/Shared/Backup.tmp");
        let film = PathBuf::from("/home/u/Shared/film.mkv");
        let part = PathBuf::from("/home/u/Shared/Incomplete/a1b2c3.part");

        assert_eq!(
            rescan_paths_for_event(WRITE, std::slice::from_ref(&part)),
            (Vec::new(), Vec::new()),
            "a download writing its .part schedules nothing"
        );
        assert_eq!(
            rescan_paths_for_event(
                EventKind::Remove(RemoveKind::Any),
                &[temp_folder.clone(), film.clone()]
            ),
            (vec![film.clone()], vec![temp_folder.clone()])
        );
        assert_eq!(
            rescan_paths_for_event(
                EventKind::Modify(ModifyKind::Name(RenameMode::From)),
                std::slice::from_ref(&part)
            ),
            (Vec::new(), vec![part.clone()])
        );
        assert_eq!(
            rescan_paths_for_event(
                EventKind::Modify(ModifyKind::Name(RenameMode::To)),
                std::slice::from_ref(&part)
            ),
            (Vec::new(), Vec::new()),
            "arriving at a refused name is still noise"
        );
    }

    #[test]
    fn a_held_departure_is_rescanned_only_if_the_index_has_rows_there() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("ember-watcher-rows-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let sample = dir.join("a.mkv");
        std::fs::write(&sample, b"x").unwrap();
        let mut row = crate::sharing::indexer::FileIndexer::discover_file(&sample).unwrap();
        let folder = PathBuf::from("/home/u/Shared/Backup.tmp");
        row.path = folder.join("a.mkv").to_string_lossy().into_owned();
        let mut index = crate::search::index::LocalIndex::new();
        index.add_files(vec![row]);

        assert!(index_has_rows_at_or_under(&index, &folder));
        assert!(!index_has_rows_at_or_under(
            &index,
            &PathBuf::from("/home/u/Shared/Incomplete/a1b2c3.part")
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unconfirmed_departures_are_taken_separately_and_absorbed_by_full() {
        let mut pending = PendingRescan::default();
        pending.note_unconfirmed([PathBuf::from("/a/x.part")]);
        assert_eq!(pending.take(), None, "unconfirmed alone schedules no pass");
        assert_eq!(pending.take_unconfirmed(), vec![PathBuf::from("/a/x.part")]);
        pending.note_unconfirmed([PathBuf::from("/a/y.part")]);
        pending.note_full();
        assert!(pending.take_unconfirmed().is_empty());
        assert_eq!(pending.take(), Some(RescanScope::Full));
    }

    /// A resync probes from a snapshot, and the probes can take as long as an
    /// offline share makes them. Folders removed meanwhile must not be revived
    /// and folders added meanwhile must not be unwatched.
    #[test]
    fn watch_targets_follow_the_list_as_it_stands_after_probing() {
        let kept = PathBuf::from("/shares/kept");
        let removed = PathBuf::from("/shares/removed");
        let added = PathBuf::from("/shares/added");
        let offline = PathBuf::from("/shares/offline");
        let probed = HashMap::from([
            (kept.clone(), true),
            (removed.clone(), true),
            (offline.clone(), false),
        ]);
        let current = HashSet::from([kept.clone(), added.clone(), offline.clone()]);
        let desired_now = HashSet::from([kept.clone(), added.clone(), offline.clone()]);
        let targets = watch_targets(&desired_now, &probed, &current);
        assert_eq!(targets, HashSet::from([kept, added]));
        assert!(!targets.contains(&removed), "a removed folder is not revived");
    }

    #[test]
    fn pending_rescan_merges_paths_and_falls_back_to_full() {
        let mut pending = PendingRescan::default();
        assert_eq!(pending.take(), None);
        pending.note_paths([PathBuf::from("/a/x.mkv"), PathBuf::from("/a/x.mkv")]);
        assert_eq!(
            pending.take(),
            Some(RescanScope::Paths(vec![PathBuf::from("/a/x.mkv")]))
        );
        assert_eq!(pending.take(), None);

        pending.restore(RescanScope::Paths(vec![PathBuf::from("/a/y.mkv")]));
        pending.note_paths([PathBuf::from("/a/z.mkv")]);
        match pending.take() {
            Some(RescanScope::Paths(mut paths)) => {
                paths.sort();
                assert_eq!(
                    paths,
                    vec![PathBuf::from("/a/y.mkv"), PathBuf::from("/a/z.mkv")],
                    "a rescan that could not start keeps its paths"
                );
            }
            other => panic!("expected paths, got {other:?}"),
        }

        pending.note_paths((0..=MAX_SCOPED_RESCAN_PATHS).map(|i| PathBuf::from(format!("/b/{i}"))));
        assert_eq!(pending.take(), Some(RescanScope::Full));
        pending.note_full();
        pending.note_paths([PathBuf::from("/a/x.mkv")]);
        assert_eq!(pending.take(), Some(RescanScope::Full), "full absorbs paths");
        assert_eq!(pending.take(), None);
    }

    /// Another program's in-progress download writes to its temp name the whole
    /// time; only the final rename may schedule work.
    #[test]
    fn external_writers_temp_names_do_not_rescan() {
        for name in [
            "movie.mkv.crdownload",
            "Movie.MKV.CRDOWNLOAD",
            "linux.iso.!qB",
            "report.docx.tmp",
            "~$report.docx",
        ] {
            let path = PathBuf::from(format!("/home/u/Shared/{name}"));
            assert!(
                !event_paths_can_change_the_share(std::slice::from_ref(&path)),
                "{name} must not schedule a rescan"
            );
        }
        let finished = [
            PathBuf::from("/home/u/Shared/movie.mkv.crdownload"),
            PathBuf::from("/home/u/Shared/movie.mkv"),
        ];
        assert_eq!(
            rescan_paths_for_event(EventKind::Modify(ModifyKind::Name(RenameMode::Both)), &finished),
            (
                vec![PathBuf::from("/home/u/Shared/movie.mkv")],
                vec![PathBuf::from("/home/u/Shared/movie.mkv.crdownload")],
            ),
            "the rename to the real name is what gets rescanned"
        );
        assert!(event_paths_can_change_the_share(&[PathBuf::from("/x/template.docx")]));
    }
    use notify::event::{
        AccessKind, AccessMode, CreateKind, DataChange, MetadataKind, ModifyKind, RemoveKind,
        RenameMode,
    };
    use notify::EventKind;
    use std::path::PathBuf;

    /// The reported case. A download writes its `.part` and `.part.met` for as
    /// long as it runs, and if the incomplete folder is inside a shared folder
    /// every one of those writes used to schedule a full rescan of the library
    /// — a walk that cannot find anything, because discovery refuses these
    /// names. The kind is a real `Modify(Data)`, so only the path can tell
    /// them apart.
    #[test]
    fn an_active_download_writing_its_part_file_does_not_rescan() {
        for name in [
            "a1b2c3.part",
            "a1b2c3.part.met",
            "known.met.tmp",
            "library.emberbackup",
            "archive.partial",
        ] {
            let path = PathBuf::from(format!("/home/u/Shared/Incomplete/{name}"));
            assert!(
                !event_paths_can_change_the_share(std::slice::from_ref(&path)),
                "{name} can never be shared, so it must not schedule a rescan"
            );
        }
    }

    /// The other half: the pass must not go quiet on anything that really does
    /// change what the Library holds, or files stop appearing until a manual
    /// reload. A finishing download is the one that matters — it renames the
    /// `.part` to the real name, and that event carries both paths.
    #[test]
    fn a_real_file_still_rescans_including_the_rename_off_a_part() {
        let ordinary = PathBuf::from("/home/u/Shared/Movies/film.mkv");
        assert!(event_paths_can_change_the_share(std::slice::from_ref(
            &ordinary
        )));

        let completed = [
            PathBuf::from("/home/u/Shared/Incomplete/a1b2c3.part"),
            PathBuf::from("/home/u/Shared/Movies/film.mkv"),
        ];
        assert!(
            event_paths_can_change_the_share(&completed),
            "a download finishing must still reach the Library"
        );
    }

    /// `notify` emits a pathless event for backend notices such as an inotify
    /// queue overflow, which means events were dropped. That is the worst
    /// possible moment to decide nothing happened.
    #[test]
    fn an_event_with_no_paths_is_assumed_to_matter() {
        assert!(event_paths_can_change_the_share(&[]));
    }

    #[test]
    fn linux_scan_side_effects_do_not_rescan() {
        assert!(!event_should_rescan(EventKind::Access(AccessKind::Open(
            AccessMode::Any
        ))));
        assert!(!event_should_rescan(EventKind::Access(AccessKind::Close(
            AccessMode::Read
        ))));
        assert!(!event_should_rescan(EventKind::Modify(
            ModifyKind::Metadata(MetadataKind::Any)
        )));
        assert!(!event_should_rescan(EventKind::Modify(
            ModifyKind::Metadata(MetadataKind::AccessTime)
        )));
    }

    #[test]
    fn real_share_changes_do_rescan() {
        assert!(event_should_rescan(EventKind::Create(CreateKind::File)));
        assert!(event_should_rescan(EventKind::Create(CreateKind::Folder)));
        assert!(event_should_rescan(EventKind::Remove(RemoveKind::File)));
        assert!(event_should_rescan(EventKind::Modify(ModifyKind::Data(
            DataChange::Any
        ))));
        assert!(event_should_rescan(EventKind::Modify(ModifyKind::Name(
            RenameMode::Both
        ))));
        assert!(event_should_rescan(EventKind::Modify(ModifyKind::Any)));
        assert!(event_should_rescan(EventKind::Access(AccessKind::Close(
            AccessMode::Write
        ))));
        assert!(event_should_rescan(EventKind::Modify(
            ModifyKind::Metadata(MetadataKind::WriteTime)
        )));
        assert!(event_should_rescan(EventKind::Any));
    }
}
