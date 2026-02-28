use serde::{Deserialize, Serialize};
use crate::network::kad::types::{DEFAULT_TCP_PORT, DEFAULT_UDP_PORT};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub id: String,
    pub name: String,
    pub path: String,
    pub size: u64,
    pub hash: String,
    /// AICH root hash (SHA-1 Merkle tree over 180KB blocks), hex-encoded
    #[serde(default)]
    pub aich_hash: String,
    pub extension: String,
    pub modified_at: i64,
    /// Upload priority: "verylow", "low", "normal", "high", "release", "auto"
    #[serde(default = "default_file_priority")]
    pub priority: String,
    /// Requests received this session
    #[serde(default)]
    pub requests: u32,
    /// Requests accepted this session
    #[serde(default)]
    pub accepted: u32,
    /// Bytes uploaded for this file this session
    #[serde(default)]
    pub bytes_transferred: u64,
    /// All-time requests (from known.met)
    #[serde(default)]
    pub alltime_requests: u32,
    /// All-time accepted requests (from known.met)
    #[serde(default)]
    pub alltime_accepted: u32,
    /// All-time bytes uploaded for this file (from known.met)
    #[serde(default)]
    pub alltime_transferred: u64,
    /// Number of known complete sources
    #[serde(default)]
    pub complete_sources: u32,
    /// Folder path (directory containing the file)
    #[serde(default)]
    pub folder: String,
    /// Whether this file is shared on KAD
    #[serde(default)]
    pub shared_kad: bool,
}

fn default_file_priority() -> String {
    "normal".to_string()
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
    /// Session transferred bytes (eMule: GetTransferred)
    pub transferred: u64,
    /// Total completed size including resumed data (eMule: GetCompletedSize)
    #[serde(default)]
    pub completed_size: u64,
    pub started_at: i64,
    #[serde(default)]
    pub failure_reason: Option<String>,
    #[serde(default = "default_priority")]
    pub priority: String,
    #[serde(default)]
    pub sources: u32,
    #[serde(default)]
    pub active_sources: u32,
    #[serde(default)]
    pub queued_sources: u32,
    /// Best queue rank across active sources (eMule QR display)
    #[serde(default)]
    pub queue_rank: Option<u32>,
    /// Timestamp when a complete source was last seen (eMule: lastseencomplete)
    #[serde(default)]
    pub last_seen_complete: Option<i64>,
    /// Timestamp of last data reception (eMule: GetLastReceptionDate)
    #[serde(default)]
    pub last_received: Option<i64>,
    /// Category name (eMule: category tabs)
    #[serde(default)]
    pub category: String,
    /// Upload: how long client waited in queue (ms) (eMule: GetWaitTime)
    #[serde(default)]
    pub wait_time: u64,
    /// Upload: how long the upload has been active (ms) (eMule: GetUpStartTimeDelay)
    #[serde(default)]
    pub upload_time: u64,
    /// A4AF (Asked For Another File) source count
    #[serde(default)]
    pub a4af_sources: u32,
    /// Max source limit for this file
    #[serde(default)]
    pub max_sources: u32,
}

fn default_priority() -> String {
    "normal".to_string()
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
    /// eMule "Stopped": removed from active download but not deleted (different from Paused)
    Stopped,
    Verifying,
    Completing,
    Completed,
    Failed,
    /// Waiting for hash verification after loading
    Hashing,
    /// Insufficient disk space
    Insufficient,
    /// No needed parts available from any source
    NoneNeeded,
}

/// Per-source detail for a download (eMule-style source list)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceInfo {
    pub ip: String,
    pub port: u16,
    pub status: SourceStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_rank: Option<u32>,
    pub speed: u64,
    pub transferred: u64,
    #[serde(default)]
    pub client_software: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SourceStatus {
    Connecting,
    Queued,
    Transferring,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rating: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
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
    pub stores_acknowledged: u32,
}

/// Serializable KAD contact info for the frontend (mirrors eMule KadContactListCtrl columns)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KadContactInfo {
    pub id: String,
    #[serde(rename = "type")]
    pub contact_type: u8,
    pub version: u8,
    pub distance: String,
    pub ip_verified: bool,
    pub bootstrap: bool,
}

/// Serializable KAD search entry for the frontend (mirrors eMule KadSearchListCtrl columns)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KadSearchInfo {
    pub id: u64,
    pub target: String,
    #[serde(rename = "type")]
    pub search_type: String,
    pub name: String,
    pub status: String,
    pub load: u32,
    pub load_response: u32,
    pub load_total: u32,
    pub packets_sent: u32,
    pub request_answer: u32,
    pub responses: u32,
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
            stores_acknowledged: 0,
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
    #[serde(default = "default_max_uploads")]
    pub max_concurrent_uploads: u32,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub nodes_dat_path: String,
    pub upnp_enabled: bool,
    /// Prefer obfuscated (encrypted) KAD communication when the peer supports it
    #[serde(default = "default_true")]
    pub obfuscation_enabled: bool,
    /// Enable IP filter to block known-bad IP ranges (loads ipfilter.dat)
    #[serde(default = "default_true")]
    pub ip_filter_enabled: bool,
    /// Block private/reserved IPs from being added to the routing table
    #[serde(default = "default_true")]
    pub block_private_ips: bool,
    /// Also apply IP filter to ed2k servers (eMule: "Filter servers by IP")
    #[serde(default = "default_true")]
    pub filter_servers_by_ip: bool,
    /// Accept new servers from connected server's OP_SERVERLIST (eMule: "Update server list when connecting")
    #[serde(default = "default_true")]
    pub add_servers_from_server: bool,
    /// Accept new servers from ed2k clients (eMule: "Update server list from clients")
    #[serde(default)]
    pub add_servers_from_clients: bool,
    /// Path to server.met file for ed2k server list
    #[serde(default)]
    pub server_list_path: String,
    /// Automatically connect to KAD on startup (eMule: "Autoconnect" for Kad)
    #[serde(default)]
    pub auto_connect_kad: bool,
    /// Automatically connect to an ed2k server on startup (eMule: "Autoconnect" for server)
    #[serde(default)]
    pub auto_connect_server: bool,
    /// Maximum sources tracked per file (eMule: maxsourceperfile, default 400)
    #[serde(default = "default_max_sources_per_file")]
    pub max_sources_per_file: u32,
    /// Maximum total TCP connections (eMule: maxconnections, default 500)
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// Add new downloads in paused state (eMule: addnewfilespaused)
    #[serde(default)]
    pub add_downloads_paused: bool,
    /// Automatically remove completed downloads from the list
    #[serde(default)]
    pub remove_finished_downloads: bool,
    /// Skip compressing video files during upload (eMule: dontcompressavi)
    #[serde(default)]
    pub skip_compress_video: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub ip: String,
    pub port: u16,
    pub name: String,
    pub description: String,
    pub user_count: u32,
    pub file_count: u32,
    pub max_users: u32,
    pub soft_files: u32,
    pub hard_files: u32,
    pub is_static: bool,
    pub fail_count: u32,
    #[serde(default)]
    pub client_id: u32,
    #[serde(default)]
    pub is_low_id: bool,
}

fn default_true() -> bool {
    true
}

fn default_max_uploads() -> u32 {
    5
}

fn default_max_sources_per_file() -> u32 {
    400
}

fn default_max_connections() -> u32 {
    500
}

impl Default for AppSettings {
    fn default() -> Self {
        let download_dir = directories::UserDirs::new()
            .and_then(|d| d.download_dir().map(|p| p.join("Nexus").to_string_lossy().to_string()))
            .unwrap_or_else(|| {
                std::path::PathBuf::from(std::env::temp_dir())
                    .join("Nexus")
                    .to_string_lossy()
                    .to_string()
            });

        Self {
            nickname: format!("Nexus-{}", &uuid::Uuid::new_v4().to_string()[..8]),
            shared_folders: Vec::new(),
            download_folder: download_dir,
            max_upload_speed: 0,
            max_download_speed: 0,
            max_concurrent_downloads: 5,
            max_concurrent_uploads: 5,
            tcp_port: DEFAULT_TCP_PORT,
            udp_port: DEFAULT_UDP_PORT,
            nodes_dat_path: String::new(),
            upnp_enabled: true,
            obfuscation_enabled: true,
            ip_filter_enabled: true,
            block_private_ips: true,
            filter_servers_by_ip: true,
            add_servers_from_server: true,
            add_servers_from_clients: false,
            server_list_path: String::new(),
            auto_connect_kad: false,
            auto_connect_server: false,
            max_sources_per_file: 400,
            max_connections: 500,
            add_downloads_paused: false,
            remove_finished_downloads: false,
            skip_compress_video: false,
        }
    }
}
