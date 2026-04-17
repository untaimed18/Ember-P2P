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
}
