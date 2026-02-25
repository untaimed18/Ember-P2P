use serde::{Deserialize, Serialize};
use crate::network::kad::types::{DEFAULT_TCP_PORT, DEFAULT_UDP_PORT};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub id: String,
    pub name: String,
    pub path: String,
    pub size: u64,
    pub hash: String,
    pub extension: String,
    pub modified_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: String,
    pub addresses: Vec<String>,
    pub nickname: String,
    pub last_seen: i64,
    pub files_shared: u32,
    pub banned: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transfer {
    pub id: String,
    pub file_name: String,
    pub file_hash: String,
    pub peer_id: String,
    pub peer_name: String,
    pub direction: TransferDirection,
    pub status: TransferStatus,
    pub progress: f64,
    pub speed: u64,
    pub total_size: u64,
    pub transferred: u64,
    pub started_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TransferDirection {
    Upload,
    Download,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TransferStatus {
    Searching,
    Queued,
    Active,
    Paused,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub file: FileInfo,
    pub peer_id: String,
    pub peer_name: String,
    pub availability: u32,
    pub file_type: String,
    pub source_addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub connected_peers: u32,
    pub upload_speed: u64,
    pub download_speed: u64,
    pub total_uploaded: u64,
    pub total_downloaded: u64,
    pub status: NetworkStatus,
    pub external_ip: String,
    pub firewalled: bool,
    pub buddy_status: String,
    pub upnp_mapped: bool,
}

impl Default for NetworkStats {
    fn default() -> Self {
        Self {
            connected_peers: 0,
            upload_speed: 0,
            download_speed: 0,
            total_uploaded: 0,
            total_downloaded: 0,
            status: NetworkStatus::Disconnected,
            external_ip: String::new(),
            firewalled: true,
            buddy_status: String::from("none"),
            upnp_mapped: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkStatus {
    Connected,
    Connecting,
    Disconnected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub nickname: String,
    pub shared_folders: Vec<String>,
    pub download_folder: String,
    pub max_upload_speed: u64,
    pub max_download_speed: u64,
    pub max_concurrent_downloads: u32,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub nodes_dat_path: String,
    pub nat_traversal_enabled: bool,
    pub upnp_enabled: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        let download_dir = directories::UserDirs::new()
            .and_then(|d| d.download_dir().map(|p| p.to_string_lossy().to_string()))
            .unwrap_or_else(|| ".".into());

        Self {
            nickname: format!("Nexus-{}", &uuid::Uuid::new_v4().to_string()[..8]),
            shared_folders: Vec::new(),
            download_folder: download_dir,
            max_upload_speed: 0,
            max_download_speed: 0,
            max_concurrent_downloads: 5,
            tcp_port: DEFAULT_TCP_PORT,
            udp_port: DEFAULT_UDP_PORT,
            nodes_dat_path: String::new(),
            nat_traversal_enabled: true,
            upnp_enabled: true,
        }
    }
}
