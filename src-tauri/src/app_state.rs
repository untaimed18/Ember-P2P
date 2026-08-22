use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

use crate::bandwidth::limiter::BandwidthLimiter;
use crate::network::NetworkCommand;
use crate::search::index::LocalIndex;
use crate::search::spam::SpamFilter;
use crate::sharing::manager::TransferManager;
use crate::sharing::watcher::SharedFoldersWatcher;
use crate::storage::config::AppConfig;
use crate::storage::database::Database;
use crate::storage::identity::NodeIdentity;
use crate::storage::statistics::TransferStats;
use crate::types::FileInfo;

/// A deep link remains durable until the frontend acknowledges successful
/// handling. The opaque id lets repeated identical links be acknowledged
/// independently.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingDeepLink {
    pub id: String,
    pub payload: String,
}

/// Folders captured from an OS drag-drop that need an answer before they are
/// shared — currently only the "you dropped files, share the folder holding
/// them?" case.
///
/// The paths live here rather than travelling to the frontend because of where
/// they came from: the OS delivered them to the native window, which is what
/// makes them authorization at all, and the equal of what the folder picker
/// returns. A confirmation therefore echoes back `token`, never a path, so the
/// renderer can approve the drop the user actually made and nothing else.
pub struct PendingFolderDrop {
    pub token: u64,
    pub folders: Vec<String>,
}

/// Live shared-folder list visible to the upload server's security check.
pub type SharedFolderList = Arc<RwLock<Vec<String>>>;

/// Live friend-hash set visible to the upload server for friend-slot boost.
pub type SharedFriendHashes = Arc<RwLock<std::collections::HashSet<[u8; 16]>>>;

pub struct AppState {
    pub network_tx: mpsc::Sender<NetworkCommand>,
    pub db: Arc<Database>,
    /// Handle-bound approved filesystem roots used by every destructive or
    /// executable filesystem action.
    pub approved_roots: Arc<crate::security::filesystem::ApprovedRootRegistry>,
    /// Awaiting the user's answer to a dropped-file share prompt. Single-slot:
    /// a second drop before the first is answered supersedes it, which is what
    /// the user means by dropping again.
    pub pending_folder_drop: Arc<tokio::sync::Mutex<Option<PendingFolderDrop>>>,
    /// Network/upload startup remains closed while security policy recovery
    /// requires explicit user acknowledgement.
    pub security_policy: Arc<crate::security::policy::SecurityPolicyGate>,
    /// Process-wide persistent identity loaded exactly once during setup.
    pub identity: Arc<NodeIdentity>,
    pub config: Arc<RwLock<AppConfig>>,
    /// Serializes each read/modify/persist/commit settings transaction so
    /// concurrent commands cannot overwrite one another with stale clones.
    pub settings_save_lock: Arc<tokio::sync::Mutex<()>>,
    /// Serializes staging and deletion of a pending profile restore. The
    /// staging directory is intentionally stable so startup can find it, so
    /// overlapping imports must never write into it concurrently.
    pub restore_import_lock: Arc<tokio::sync::Mutex<()>>,
    /// Canonical path of a backup the user picked in a native open dialog.
    /// Preview and import consume this rather than a renderer-supplied path.
    pub picked_backup: Arc<tokio::sync::Mutex<Option<std::path::PathBuf>>>,
    pub local_index: Arc<RwLock<LocalIndex>>,
    pub bandwidth_limiter: Arc<BandwidthLimiter>,
    pub transfer_manager: Arc<RwLock<TransferManager>>,
    /// Serializes every pending-download admission transaction (direct IPC,
    /// collection batches, deep links, and startup migration) so count and
    /// remaining-byte checks cannot race at N+1.
    pub download_admission: Arc<tokio::sync::Mutex<()>>,
    /// Signaled by the network task after it finishes saving nodes.dat on shutdown.
    pub shutdown_complete: Arc<std::sync::atomic::AtomicBool>,
    pub bw_shutdown: Arc<std::sync::atomic::AtomicBool>,
    /// Number of folder scans currently running in the background.
    pub scanning_count: Arc<AtomicUsize>,
    /// Set when discovery reaches the per-folder file cap. This survives the
    /// startup interval before the webview attaches its event listeners.
    pub library_scan_truncated: Arc<AtomicBool>,
    /// Single-flight guard shared by startup, per-folder, and watcher reload
    /// scans. Index mutations from different scan generations must not overlap.
    pub scan_coordination: Arc<tokio::sync::Mutex<()>>,
    /// Set when the user explicitly stops hashing. While true, the FS watcher
    /// must not call `reload_shared_files` (that would resume hashing behind
    /// the user's back). Cleared by resume, manual reload, and add-folder.
    pub hashing_paused: Arc<AtomicBool>,
    /// Set by the FS watcher when disk changes arrive while [`Self::hashing_paused`]
    /// is true. Cleared on a full `reload_shared_files`. Without this, clearing
    /// the pause latch via `add_shared_folder` (which only scans the new folder)
    /// would permanently miss changes that happened under other shares during
    /// the pause.
    pub hashing_fs_dirty: Arc<AtomicBool>,
    /// Per-folder cancellation flags for background hashing tasks.
    /// Key = folder path (or "__reload__" / "__startup__" for special tasks).
    pub hash_cancel_flags: Arc<RwLock<HashMap<String, Arc<AtomicBool>>>>,
    /// Transient handoff buffer: ed2k part-hashes computed as a byproduct of
    /// the initial combined ED2K+AICH hash pass (`hash_file_combined_cancellable`),
    /// keyed by the 16-byte ed2k file hash. Populated by the hashing tasks
    /// (startup indexing, `add_shared_folder`, `reload_shared_files`) and
    /// drained by the network task's `SharedFilesChanged` handler, which
    /// otherwise has to re-read the whole file from disk to recompute the
    /// same part hashes for `known.met`. That redundant re-read used to run
    /// sequentially on the single network event loop task for every newly
    /// shared file, starving KAD UDP/timers/IPC snapshots (contacts, search
    /// activity) for the whole duration of a large hash pass — this cache
    /// lets the common case skip it entirely. Entries are removed as soon as
    /// they're consumed, so this stays small/transient rather than growing
    /// unbounded.
    pub fresh_part_hashes: Arc<RwLock<HashMap<[u8; 16], Vec<[u8; 16]>>>>,
    /// Cached transfer statistics — updated by the network loop.
    pub cached_transfer_stats: Arc<RwLock<TransferStats>>,
    /// Cached shared files list — updated by sharing commands and the network
    /// loop's background task so `get_shared_files` never contends with
    /// `local_index` writers (hashing, scanning, stats merge).
    pub cached_shared_files: Arc<RwLock<Vec<FileInfo>>>,
    /// Search spam filter for scoring and marking spam results.
    pub spam_filter: Arc<RwLock<SpamFilter>>,
    /// Peer/KAD file comments used for community "fake" votes during search enrich.
    pub comment_manager: Arc<RwLock<crate::network::ed2k::comments::CommentManager>>,
    /// Live shared-folder list shared with the upload server so runtime
    /// add/remove folder changes are immediately reflected in the security check.
    pub upload_shared_folders: SharedFolderList,
    /// Live friend user-hash set shared with the upload server for friend-slot priority.
    pub friend_hashes: SharedFriendHashes,
    /// Subset of `friend_hashes` that also added us back. Gates everything that
    /// exposes private content — friend browse answers and friends-only file
    /// serving — so a one-sided add grants upload priority but never access.
    pub mutual_friend_hashes: SharedFriendHashes,
    /// Filesystem watcher over the currently shared folders. `None` if the
    /// OS-level watcher could not be initialised at startup; in that case
    /// the app still works but users must reload manually after changes.
    pub shared_folder_watcher: Option<Arc<SharedFoldersWatcher>>,
    /// JoinHandles for long-running background scan tasks (directory discovery
    /// and hashing). Tracked so `await_background_scans` can wait for them on
    /// shutdown or `reload_shared_files`, preventing races where a still-running
    /// scan writes into `local_index`/`known_files` after we've started tearing
    /// down. Tasks self-remove from this map on completion.
    pub background_scans: Arc<RwLock<HashMap<u64, tokio::task::JoinHandle<()>>>>,
    /// Monotonic counter for assigning unique ids in `background_scans`.
    pub background_scan_seq: Arc<AtomicUsize>,
    /// Set to `true` when the user has explicitly chosen "Exit Ember" (via the
    /// close-confirmation dialog or the tray-menu Quit entry). Read inside the
    /// `WindowEvent::CloseRequested` handler so a confirmed quit bypasses the
    /// "hide to tray / show dialog" branches and lets the window destroy
    /// proceed normally. Without this flag, picking Exit from a custom dialog
    /// would still get intercepted by the close-to-tray policy and the window
    /// would just hide instead of quitting.
    pub quit_confirmed: Arc<AtomicBool>,
    /// Set by the native close handler before it emits `close-requested`.
    /// The layout consumes this latch after registering its listener, closing
    /// the startup race where the event arrives before the webview can hear
    /// it and would otherwise leave a prevented native close with no dialog.
    pub pending_close_request: Arc<AtomicBool>,
    /// Set when startup turned the Ember overlay on for a profile that had it
    /// off, and consumed by the layout after its listeners are registered.
    ///
    /// A latch rather than a fire-and-forget event, for the same reason as
    /// `pending_close_request`: Tauri does not buffer events, so a notice
    /// emitted before the webview has resolved `listen()` is simply lost. The
    /// migration has already been written to disk by then and is one-shot, so
    /// the user would never be told their node had joined a network that
    /// publishes their address and their shared-file keywords.
    pub pending_ember_default_on_notice: Arc<AtomicBool>,
    /// Set when startup failed to apply a staged profile restore, or left
    /// `restore-pending/` in place (schema too new, mid-apply abort). The
    /// layout consumes this latch and shows a sticky warning; Settings >
    /// Backup can retry or discard.
    pub pending_restore_failed_notice: Arc<AtomicBool>,
    /// Mirror of `config.settings.close_to_tray_behavior` behind a synchronous
    /// `parking_lot::RwLock` so the `WindowEvent::CloseRequested` handler can
    /// read it from the main UI thread without blocking on the async tokio
    /// `RwLock` that wraps `AppConfig`. Updated alongside the canonical config
    /// in `update_settings` and `set_close_behavior`. Holds one of the
    /// validated strings: `"ask"`, `"tray"`, or `"exit"`.
    pub close_behavior: Arc<parking_lot::RwLock<String>>,
    /// Deep-link payloads (ed2k:// URIs or `.emulecollection` file paths)
    /// captured from the launch arguments or a second instance's argv before
    /// the webview was ready to handle them. The frontend drains this buffer
    /// via `take_pending_deep_links` on mount and whenever a
    /// `deep-link-received` event wakes it. A synchronous `parking_lot::Mutex`
    /// is used because the single-instance callback runs on the OS event
    /// thread (no async context) and pushes into it directly.
    pub pending_deep_links: Arc<parking_lot::Mutex<Vec<PendingDeepLink>>>,
}

impl AppState {
    /// Register a background scan task so it can be awaited on shutdown.
    /// The caller spawns with `tokio::spawn` and passes the returned handle.
    pub async fn register_background_scan(&self, handle: tokio::task::JoinHandle<()>) -> u64 {
        let id = self
            .background_scan_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u64;
        let mut map = self.background_scans.write().await;
        // Reap already-finished scans so the map can't grow unbounded across a
        // long session of folder adds / reloads (each spawns one task and we
        // don't otherwise remove completed entries until shutdown).
        map.retain(|_, h| !h.is_finished());
        map.insert(id, handle);
        id
    }

    /// Remove a background scan entry once it finishes; does not await.
    #[allow(dead_code)]
    pub async fn deregister_background_scan(&self, id: u64) {
        self.background_scans.write().await.remove(&id);
    }

    /// Await all currently-tracked background scans. Aborts any still running
    /// after a grace period so shutdown can't hang on a frozen hasher.
    ///
    /// Earlier this just dropped the `JoinHandle`s when the grace timer
    /// fired and "continued shutdown" — which technically lets the
    /// shutdown sequence proceed but leaves the task running and still
    /// touching shared state (`local_index`, `known_files`, the
    /// in-flight `KnownFileList` we're about to flush). The on-disk
    /// flush could then race against a writer that's still alive in a
    /// detached task, producing a half-written `known.met`. Snapshotting
    /// `abort_handle()` for every scan up front and calling `.abort()`
    /// on each one when the grace window elapses guarantees no further
    /// writes after this method returns.
    pub async fn await_background_scans(&self, grace: std::time::Duration) {
        let handles: Vec<_> = {
            let mut map = self.background_scans.write().await;
            map.drain().map(|(_, h)| h).collect()
        };
        if handles.is_empty() {
            return;
        }
        let abort_handles: Vec<_> = handles.iter().map(|h| h.abort_handle()).collect();
        let count = handles.len();
        let fut = async move {
            for h in handles {
                // A panicking scan can leave the in-memory index disagreeing
                // with what is about to be flushed, so it must not pass
                // silently. A cancelled one is an expected outcome of the
                // abort path below and stays quiet.
                if let Err(error) = h.await {
                    if error.is_panic() {
                        tracing::error!("Background scan task panicked: {error}");
                    }
                }
            }
        };
        if tokio::time::timeout(grace, fut).await.is_err() {
            tracing::warn!(
                "background scans still running after {:?}; aborting {} task(s)",
                grace,
                count,
            );
            for ah in abort_handles {
                ah.abort();
            }
        }
    }

    /// Wait until `scanning_count` reaches zero or `grace` elapses. Used on
    /// shutdown paths that don't own JoinHandles directly (e.g. the startup
    /// scan spawned from `tauri::setup`).
    #[allow(dead_code)]
    pub async fn wait_scans_idle(&self, grace: std::time::Duration) {
        let deadline = std::time::Instant::now() + grace;
        while self
            .scanning_count
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
        {
            if std::time::Instant::now() >= deadline {
                tracing::warn!(
                    "scan workers still active after {:?}; continuing shutdown",
                    grace
                );
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
}
