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
    /// Whether this file is actively shared (user can toggle off to stop publishing)
    #[serde(default = "default_true")]
    pub shared: bool,
    /// Whether this file is currently published on KAD (runtime status)
    #[serde(default)]
    pub shared_kad: bool,
    /// Whether this file is currently offered to an ed2k server (runtime status)
    #[serde(default)]
    pub shared_ed2k: bool,
}

fn default_true() -> bool {
    true
}

fn default_filename_cleanups() -> String {
    crate::search::cleanup::DEFAULT_CLEANUP_STRINGS.to_string()
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
    #[serde(default)]
    pub failure_kind: Option<String>,
    #[serde(default)]
    pub failure_stage: Option<String>,
    /// Priority for this transfer, using eMule's full ladder:
    /// "verylow" | "low" | "normal" | "high" | "release" | "auto".
    ///
    /// Interpreted differently depending on [`direction`](TransferDirection):
    /// - For downloads: relative source-slot allocation across our own
    ///   transfers (higher = more in-flight source requests).
    /// - For uploads: remote slot ranking when a peer is in our upload queue
    ///   (higher = earlier slot grant).
    ///
    /// The shared upload-priority stored on a [`FileInfo`] is copied into the
    /// upload-direction [`Transfer::priority`] when a peer connects, so both
    /// fields share a single domain to simplify IPC and keep eMule
    /// compatibility.
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
    #[serde(default = "default_transfer_health")]
    pub health: TransferHealth,
    #[serde(default)]
    pub health_reason: Option<String>,
    #[serde(default)]
    pub stalled_since: Option<i64>,
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
    /// eMule-style preview priority: download first and last parts first
    #[serde(default)]
    pub preview_priority: bool,
    /// Sources discovered via Ember Peer Exchange
    #[serde(default)]
    pub ember_sources: u32,
    /// Client software name (uploads only, e.g. "eMule 0.50")
    #[serde(default)]
    pub client_software: String,
    /// ISO country code of the peer (uploads only, e.g. "DE")
    #[serde(default)]
    pub country_code: Option<String>,
    /// ED2K user hash of the peer (uploads only, 32 hex chars)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_hash: Option<String>,
}

fn default_priority() -> String {
    "normal".to_string()
}

fn default_transfer_health() -> TransferHealth {
    TransferHealth::Healthy
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransferHealth {
    Healthy,
    Degraded,
    Stalled,
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
    #[serde(default)]
    pub peer_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available_parts: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_parts: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_origin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    Connecting,
    Queued,
    QueueFull,
    NoNeededParts,
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
    #[serde(default)]
    pub spam_rating: u32,
    #[serde(default)]
    pub is_spam: bool,
    #[serde(default)]
    pub clean_name: String,
    /// Where the hit came from: `KAD`, `Server`, `UDP`, `Local`, `Notes`, or combined (e.g. `KAD · Server`).
    #[serde(default)]
    pub result_origin: String,
}

/// Response from [`crate::commands::transfers::start_download`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartDownloadResponse {
    pub transfer_id: String,
    /// True when this file was already in the active download queue (same ed2k hash).
    pub already_queued: bool,
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
    pub kad_users_estimate: u32,
    #[serde(default)]
    pub tcp_status: String,
    #[serde(default)]
    pub udp_status: String,
    /// Ember Peer Exchange: total unique Ember peers encountered this session
    #[serde(default)]
    pub ember_peers: u32,
    /// Ember Peer Exchange: total sources received via EPX this session
    #[serde(default)]
    pub epx_sources_received: u32,
    /// Current eD2K server connection status: "connected", "connecting", or "disconnected"
    #[serde(default)]
    pub server_status: String,
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
    /// K30: unix timestamp (seconds) when the search was created. The
    /// UI derives an "age" column from this so users can see if a
    /// search is fresh or stuck.
    pub started_at: i64,
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
            firewalled: false,
            buddy_status: String::from("none"),
            upnp_mapped: false,
            stores_acknowledged: 0,
            kad_users_estimate: 0,
            tcp_status: String::from("Unknown"),
            udp_status: String::from("Unknown"),
            ember_peers: 0,
            epx_sources_received: 0,
            server_status: String::from("disconnected"),
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
#[serde(deny_unknown_fields)]
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
    /// Apply IP filter to incoming peer connections (upload server).
    /// Off by default: VPN IPs commonly appear in ipfilter.dat "hosting" ranges,
    /// silently breaking connectivity for a large portion of users. Outbound
    /// filtering still applies, and the abuse tracker / ban list protect against
    /// misbehaving inbound peers.
    #[serde(default)]
    pub filter_incoming_connections: bool,
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
    #[serde(default = "default_true")]
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
    /// Upload Speed Sense: dynamically adjust upload limit based on network latency
    #[serde(default)]
    pub uss_enabled: bool,
    /// Pipe-separated substrings to remove from filenames for display cleanup
    #[serde(default = "default_filename_cleanups")]
    pub filename_cleanups: String,
    /// Enable the search spam filter (eMule-compatible multi-signal scoring)
    #[serde(default = "default_true")]
    pub spam_filter_enabled: bool,
    /// Search spam profile: `balanced` (default) or `aggressive`
    #[serde(default = "default_spam_filter_profile")]
    pub spam_filter_profile: String,
    /// Max time (seconds) to wait in remote upload queue before giving up (eMule-style; default 1800)
    #[serde(default = "default_download_queue_wait_secs")]
    pub download_queue_wait_secs: u64,
    /// Extra multi-source retry rounds after initial source tasks (default 3)
    #[serde(default = "default_multisource_retry_rounds")]
    pub multisource_retry_rounds: u32,
    /// Per-source part hash failure retry rounds during data transfer (default 3)
    #[serde(default = "default_download_part_retry_rounds")]
    pub download_part_retry_rounds: u32,
    /// Maximum download file size in GiB (default 4096 ≈ 4 TiB; large-file paths use 64-bit offsets)
    #[serde(default = "default_max_download_file_size_gib")]
    pub max_download_file_size_gib: u32,
    /// Max seconds to wait for a keyword/global search to finish (30–600; default 120).
    #[serde(default = "default_search_timeout_secs")]
    pub search_timeout_secs: u64,
    /// Whether the first-time setup wizard has been completed
    #[serde(default)]
    pub setup_complete: bool,

    /// Require approval before granting friend-slot priority to new friend requests
    #[serde(default)]
    pub friend_require_approval: bool,
    /// Disable incoming chat messages from friends
    #[serde(default)]
    pub friend_chat_disabled: bool,
    /// Disable browse-shares responses to friends
    #[serde(default)]
    pub friend_browse_disabled: bool,
    /// Show a notification when a friend comes online
    #[serde(default = "default_true")]
    pub friend_online_notifications: bool,
    /// Maximum number of friends allowed (1–500, default 200)
    #[serde(default = "default_max_friends")]
    pub max_friends: u32,
    /// Encrypt friend sessions with RC4 obfuscation (default true)
    #[serde(default = "default_true")]
    pub friend_session_encryption: bool,
    /// Rendezvous server URL for friend discovery
    #[serde(default = "default_rendezvous_url")]
    pub rendezvous_url: String,
}

/// Sanitized ed2k download limits derived from [`AppSettings`] (clamped for safety).
#[derive(Clone, Copy, Debug)]
pub struct Ed2kDownloadLimits {
    pub queue_wait_secs: u64,
    pub multisource_retry_rounds: u32,
    pub part_retry_rounds: u32,
    pub max_download_bytes: u64,
}

impl AppSettings {
    pub fn ed2k_download_limits(&self) -> Ed2kDownloadLimits {
        let gib = self.max_download_file_size_gib.clamp(1, 16_384) as u128;
        let max_download_bytes = (gib.saturating_mul(1024 * 1024 * 1024)).min(u64::MAX as u128) as u64;
        Ed2kDownloadLimits {
            queue_wait_secs: self.download_queue_wait_secs.clamp(60, 14400),
            multisource_retry_rounds: self.multisource_retry_rounds.clamp(1, 20),
            part_retry_rounds: self.download_part_retry_rounds.clamp(1, 20),
            max_download_bytes,
        }
    }
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

/// One row in the upload-pane "Queued" tab — a peer that has joined our
/// upload queue but doesn't currently hold a slot. Snapshot taken on
/// demand from `UploadQueueRef`; `wait_seconds` is computed at snapshot
/// time so the UI doesn't need access to monotonic `Instant`s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadQueueClient {
    /// 32-char hex ed2k user hash, or empty when the peer didn't
    /// advertise one (queue identity falls back to IP in that case).
    pub user_hash: String,
    pub peer_ip: String,
    pub peer_port: u16,
    pub file_hash: String,
    pub file_name: String,
    pub wait_seconds: u64,
    /// 1-based queue rank computed via the eMule scoring rules
    /// (`compute_queue_rank` in the upload module). `None` when the
    /// peer is currently disconnected and only `m_bAddNextConnect` is
    /// keeping their slot warm.
    pub queue_rank: Option<u32>,
    /// SecIdent credit ratio (1.0–10.0). 1.0 for first-time peers.
    pub credit_ratio: f64,
    /// Lifetime bytes we have uploaded TO this peer across all sessions.
    pub uploaded: u64,
    /// Lifetime bytes we have downloaded FROM this peer across all sessions.
    pub downloaded: u64,
    /// "Verified" | "Failed" | "Unknown" | "BadGuy" | "Needed"
    pub ident_state: String,
    /// ISO 3166-1 alpha-2 country code, geoip-resolved from `peer_ip`.
    pub country_code: Option<String>,
    pub is_friend: bool,
    /// Raw eMule version byte (Hello CT_EMULE_VERSION). Surfaces in the UI
    /// as a tooltip / column for diagnosing legacy-client penalties.
    pub emule_version: u8,
}

/// One row in the upload-pane "Known Clients" tab — a SecIdent credit
/// record. These are persistent across sessions (clients.met) so the
/// list is the lifetime view of every peer we've ever traded credit
/// with, not just currently-connected peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownClient {
    /// 32-char hex ed2k user hash.
    pub user_hash: String,
    /// Bytes WE downloaded from them across all sessions (eMule's
    /// `m_nDownloaded`). This is the value that buys us upload-queue
    /// priority on their side.
    pub downloaded: u64,
    /// Bytes WE uploaded to them across all sessions (`m_nUploaded`).
    pub uploaded: u64,
    /// Cached `get_score_ratio` for the IP we last identified them at.
    pub credit_ratio: f64,
    /// Unix epoch seconds; the freshest of the per-session timestamps.
    pub last_seen: i64,
    /// "Verified" | "Failed" | "Unknown" | "BadGuy" | "Needed"
    pub ident_state: String,
    /// Last IPv4 we successfully verified the peer at, or `None` for
    /// records that exist only because of pre-SecIdent traffic.
    pub last_known_ip: Option<String>,
    /// ISO 3166-1 alpha-2, geoip-resolved from `last_known_ip`.
    pub country_code: Option<String>,
    /// True iff we have their RSA public key cached (a prerequisite for
    /// Verified state — useful for diagnosing why a record is stuck at
    /// Unknown after several connections).
    pub has_public_key: bool,
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

fn default_download_queue_wait_secs() -> u64 {
    1800
}

fn default_multisource_retry_rounds() -> u32 {
    3
}

fn default_download_part_retry_rounds() -> u32 {
    3
}

fn default_max_download_file_size_gib() -> u32 {
    4096
}

fn default_search_timeout_secs() -> u64 {
    120
}

fn default_max_friends() -> u32 {
    200
}

fn default_rendezvous_url() -> String {
    "https://ember-rendezvous.fly.dev".to_string()
}

fn default_spam_filter_profile() -> String {
    "balanced".to_string()
}

impl Default for AppSettings {
    fn default() -> Self {
        let download_dir = directories::UserDirs::new()
            .and_then(|d| d.download_dir().map(|p| p.join("Ember").to_string_lossy().to_string()))
            .unwrap_or_else(|| {
                std::path::PathBuf::from(std::env::temp_dir())
                    .join("Ember")
                    .to_string_lossy()
                    .to_string()
            });

        let completed_dir = std::path::PathBuf::from(&download_dir)
            .join("Downloads")
            .to_string_lossy()
            .to_string();

        Self {
            nickname: format!("Ember-{}", &uuid::Uuid::new_v4().to_string()[..8]),
            shared_folders: vec![completed_dir],
            download_folder: download_dir,
            max_upload_speed: 0,
            max_download_speed: 0,
            max_concurrent_downloads: 5,
            max_concurrent_uploads: 5,
            tcp_port: DEFAULT_TCP_PORT,
            udp_port: DEFAULT_UDP_PORT,
            nodes_dat_path: String::new(),
            upnp_enabled: false,
            obfuscation_enabled: true,
            ip_filter_enabled: true,
            filter_incoming_connections: false,
            block_private_ips: true,
            filter_servers_by_ip: true,
            add_servers_from_server: true,
            add_servers_from_clients: true,
            server_list_path: String::new(),
            auto_connect_kad: false,
            auto_connect_server: true,
            max_sources_per_file: 400,
            max_connections: 500,
            add_downloads_paused: false,
            remove_finished_downloads: false,
            skip_compress_video: false,
            uss_enabled: false,
            filename_cleanups: default_filename_cleanups(),
            spam_filter_enabled: true,
            spam_filter_profile: default_spam_filter_profile(),
            download_queue_wait_secs: default_download_queue_wait_secs(),
            multisource_retry_rounds: default_multisource_retry_rounds(),
            download_part_retry_rounds: default_download_part_retry_rounds(),
            max_download_file_size_gib: default_max_download_file_size_gib(),
            search_timeout_secs: default_search_timeout_secs(),
            setup_complete: false,
            friend_require_approval: true,
            friend_chat_disabled: false,
            friend_browse_disabled: false,
            friend_online_notifications: true,
            friend_session_encryption: true,
            max_friends: default_max_friends(),
            rendezvous_url: default_rendezvous_url(),
        }
    }
}

// -------------------------------------------------------------------------
// Typed event payloads
//
// These mirror the shapes previously built ad-hoc with `serde_json::json!`
// for the very highest-frequency `app_handle.emit(...)` sites — per-block
// download and upload progress. `serde_json::json!` builds a tagged
// `serde_json::Value` tree (one Box/HashMap allocation per field, plus the
// string keys) which Tauri then re-serialises to JSON for the webview.
// With typed structs the JSON is emitted in a single serde pass and field
// keys are known statically, so these events allocate much less under load.
//
// Field names use `camelCase`-free snake_case to match the existing JSON
// keys on the frontend (see `src/lib/stores/transfers.ts`); renaming would
// be a behavioural change.
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct TransferProgressPayload<'a> {
    pub id: &'a str,
    pub downloaded: u64,
    pub total: u64,
    pub progress: f64,
    pub speed: u64,
    /// Only populated for upload-direction events so existing frontend
    /// consumers (`payload.uploaded ?? payload.downloaded`) keep working.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uploaded: Option<u64>,
    /// `"upload"` for upload progress events; omitted for downloads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_time: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferSourcesPayload<'a> {
    pub id: &'a str,
    pub sources: u32,
    pub active_sources: u32,
    pub queued_sources: u32,
}
