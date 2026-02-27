use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

use crate::bandwidth::limiter::BandwidthLimiter;
use crate::network::NetworkCommand;
use crate::search::index::LocalIndex;
use crate::sharing::manager::TransferManager;
use crate::storage::config::AppConfig;
use crate::storage::database::Database;
use crate::types::{KadContactInfo, KadSearchInfo, NetworkStats, PeerInfo};

pub struct AppState {
    pub network_tx: mpsc::Sender<NetworkCommand>,
    pub db: Arc<Database>,
    pub config: Arc<RwLock<AppConfig>>,
    pub local_index: Arc<RwLock<LocalIndex>>,
    pub bandwidth_limiter: Arc<BandwidthLimiter>,
    pub transfer_manager: Arc<RwLock<TransferManager>>,
    /// Signaled by the network task after it finishes saving nodes.dat on shutdown.
    pub shutdown_complete: Arc<std::sync::atomic::AtomicBool>,
    /// Cached peer list updated by the network loop — read directly by Tauri commands.
    pub cached_peers: Arc<RwLock<Vec<PeerInfo>>>,
    /// Cached network stats updated by the network loop — read directly by Tauri commands.
    pub cached_stats: Arc<RwLock<NetworkStats>>,
    /// Cached KAD contacts updated by the network loop — avoids blocking the event loop.
    pub cached_contacts: Arc<RwLock<Vec<KadContactInfo>>>,
    /// Cached KAD searches updated by the network loop — avoids blocking the event loop.
    pub cached_searches: Arc<RwLock<Vec<KadSearchInfo>>>,
}
