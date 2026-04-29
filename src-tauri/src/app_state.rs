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
use crate::storage::known_files::KnownFileList;
use crate::storage::statistics::TransferStats;
use crate::types::{FileInfo, KadContactInfo};

/// Live shared-folder list visible to the upload server's security check.
pub type SharedFolderList = Arc<RwLock<Vec<String>>>;

/// Live friend-hash set visible to the upload server for friend-slot boost.
pub type SharedFriendHashes = Arc<RwLock<std::collections::HashSet<[u8; 16]>>>;

pub struct AppState {
    pub network_tx: mpsc::Sender<NetworkCommand>,
    pub db: Arc<Database>,
    pub config: Arc<RwLock<AppConfig>>,
    pub local_index: Arc<RwLock<LocalIndex>>,
    pub bandwidth_limiter: Arc<BandwidthLimiter>,
    pub transfer_manager: Arc<RwLock<TransferManager>>,
    /// Signaled by the network task after it finishes saving nodes.dat on shutdown.
    pub shutdown_complete: Arc<std::sync::atomic::AtomicBool>,
    pub bw_shutdown: Arc<std::sync::atomic::AtomicBool>,
    /// Number of folder scans currently running in the background.
    pub scanning_count: Arc<AtomicUsize>,
    /// Per-folder cancellation flags for background hashing tasks.
    /// Key = folder path (or "__reload__" / "__startup__" for special tasks).
    pub hash_cancel_flags: Arc<RwLock<HashMap<String, Arc<AtomicBool>>>>,
    /// Cached KAD contacts updated by the network loop — avoids blocking the event loop.
    pub cached_contacts: Arc<RwLock<Vec<KadContactInfo>>>,
    /// Cached transfer statistics — updated by the network loop.
    pub cached_transfer_stats: Arc<RwLock<TransferStats>>,
    /// Cached shared files list — updated by sharing commands and the network
    /// loop's background task so `get_shared_files` never contends with
    /// `local_index` writers (hashing, scanning, stats merge).
    pub cached_shared_files: Arc<RwLock<Vec<FileInfo>>>,
    /// Search spam filter for scoring and marking spam results.
    pub spam_filter: Arc<RwLock<SpamFilter>>,
    /// Live shared-folder list shared with the upload server so runtime
    /// add/remove folder changes are immediately reflected in the security check.
    pub upload_shared_folders: SharedFolderList,
    /// Live friend user-hash set shared with the upload server for friend-slot priority.
    pub friend_hashes: SharedFriendHashes,
    /// Shared known-file list (eMule known.met) so sharing commands and the
    /// network loop both work from memory instead of re-reading from disk.
    /// ember-V2's network task doesn't currently read through AppState for
    /// this list (it loads its own copy), but the field is kept so
    /// sharing-side code can grow into it without a schema change.
    #[allow(dead_code)]
    pub known_files: Arc<RwLock<KnownFileList>>,
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
    #[allow(dead_code)]
    pub background_scan_seq: Arc<AtomicUsize>,
    /// Set to `true` when the user has explicitly chosen "Exit Ember" (via the
    /// close-confirmation dialog or the tray-menu Quit entry). Read inside the
    /// `WindowEvent::CloseRequested` handler so a confirmed quit bypasses the
    /// "hide to tray / show dialog" branches and lets the window destroy
    /// proceed normally. Without this flag, picking Exit from a custom dialog
    /// would still get intercepted by the close-to-tray policy and the window
    /// would just hide instead of quitting.
    pub quit_confirmed: Arc<AtomicBool>,
    /// Mirror of `config.settings.close_to_tray_behavior` behind a synchronous
    /// `parking_lot::RwLock` so the `WindowEvent::CloseRequested` handler can
    /// read it from the main UI thread without blocking on the async tokio
    /// `RwLock` that wraps `AppConfig`. Updated alongside the canonical config
    /// in `update_settings` and `set_close_behavior`. Holds one of the
    /// validated strings: `"ask"`, `"tray"`, or `"exit"`.
    pub close_behavior: Arc<parking_lot::RwLock<String>>,
}

impl AppState {
    /// Register a background scan task so it can be awaited on shutdown.
    /// The caller spawns with `tokio::spawn` and passes the returned handle.
    #[allow(dead_code)]
    pub async fn register_background_scan(&self, handle: tokio::task::JoinHandle<()>) -> u64 {
        let id = self.background_scan_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u64;
        self.background_scans.write().await.insert(id, handle);
        id
    }

    /// Remove a background scan entry once it finishes; does not await.
    #[allow(dead_code)]
    pub async fn deregister_background_scan(&self, id: u64) {
        self.background_scans.write().await.remove(&id);
    }

    /// Await all currently-tracked background scans. Aborts any still running
    /// after a grace period so shutdown can't hang on a frozen hasher.
    #[allow(dead_code)]
    pub async fn await_background_scans(&self, grace: std::time::Duration) {
        let handles: Vec<_> = {
            let mut map = self.background_scans.write().await;
            map.drain().map(|(_, h)| h).collect()
        };
        if handles.is_empty() {
            return;
        }
        let fut = async {
            for h in handles {
                let _ = h.await;
            }
        };
        if tokio::time::timeout(grace, fut).await.is_err() {
            tracing::warn!("background scans still running after grace window; continuing shutdown");
        }
    }

    /// Wait until `scanning_count` reaches zero or `grace` elapses. Used on
    /// shutdown paths that don't own JoinHandles directly (e.g. the startup
    /// scan spawned from `tauri::setup`).
    #[allow(dead_code)]
    pub async fn wait_scans_idle(&self, grace: std::time::Duration) {
        let deadline = std::time::Instant::now() + grace;
        while self.scanning_count.load(std::sync::atomic::Ordering::Relaxed) > 0 {
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
