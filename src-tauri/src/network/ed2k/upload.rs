use std::io::{self, Read as _, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::collections::HashMap;

use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use futures::FutureExt;
use tracing::{debug, info, warn, error};

use crate::bandwidth::limiter::BandwidthLimiter;
use crate::network::ed2k::a4af::A4AFManager;
use crate::network::ed2k::comments::CommentManager;
use crate::network::ed2k::credits::CreditManager;
use crate::network::ed2k::sources::SourceManager;
use crate::network::ed2k::tcp_obfuscation::{self, NegotiationResult, Rc4Reader, Rc4Writer};
use crate::search::index::LocalIndex;
use crate::sharing::manager::TransferManager;
use crate::types::TransferDirection;

pub type EmberSessionMap = Arc<RwLock<HashMap<[u8; 16], tokio::sync::mpsc::Sender<Vec<u8>>>>>;

use super::messages::*;
use crate::network::kad::buddy::PendingBuddySet;
use crate::network::kad::ip_filter::SharedIpFilter;

struct UploadSlotGuard {
    active_count: Arc<std::sync::atomic::AtomicUsize>,
    slot_notify: Arc<tokio::sync::Notify>,
    armed: bool,
}

impl UploadSlotGuard {
    fn new(active_count: Arc<std::sync::atomic::AtomicUsize>, slot_notify: Arc<tokio::sync::Notify>) -> Self {
        Self { active_count, slot_notify, armed: false }
    }

    fn activate(&mut self) {
        if !self.armed {
            self.active_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.armed = true;
        }
    }

    fn is_active(&self) -> bool {
        self.armed
    }

    fn deactivate(&mut self) {
        if self.armed {
            self.active_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            self.armed = false;
            self.slot_notify.notify_waiters();
        }
    }
}

impl Drop for UploadSlotGuard {
    fn drop(&mut self) {
        if self.armed {
            self.active_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            self.slot_notify.notify_waiters();
        }
    }
}

/// Shared set of banned peer IPs (updated by network task on Ban/Unban commands)
pub type SharedBannedIps = Arc<std::sync::RwLock<std::collections::HashSet<std::net::Ipv4Addr>>>;

/// Shared buddy info for including in Hello tags (updated by network task)
pub type SharedBuddyInfo = Arc<RwLock<Option<BuddyInfo>>>;

/// IPs we've sent KADEMLIA_FIREWALLED_REQ to; a TCP connect-back from one of
/// these proves our TCP port is reachable (not firewalled).
pub type FirewallProbeSet = Arc<std::sync::Mutex<std::collections::HashSet<std::net::Ipv4Addr>>>;

/// Per-slot smoothed upload rate registry: peer address -> bytes/sec (EWMA).
/// Updated by each upload task; read by `compute_dynamic_slot_count`.
pub(crate) type SlotRateRegistry = Arc<std::sync::Mutex<HashMap<SocketAddr, u64>>>;

/// Recognized incoming buddy connection: (user_hash, reader, writer)
pub type BuddyConnectionParts = (
    [u8; 16],
    crate::network::kad::types::KadId,
    Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    Box<dyn tokio::io::AsyncWrite + Unpin + Send + Sync>,
);

/// Callback connection from a firewalled source connecting back to us
/// (KAD buddy relay or server LowID callback).
pub struct KadCallbackParts {
    pub peer_ip: std::net::Ipv4Addr,
    pub peer_port: u16,
    pub peer_user_hash: [u8; 16],
    pub file_hash: [u8; 16],
    pub reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    pub writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    /// True if EmuleInfo exchange was already done (obfuscated connections).
    pub emule_info_done: bool,
}

/// Shared set of IPs we're expecting KAD callback connections from.
/// Maps source IP -> pending callback expectations. The upload handler checks
/// connecting peers against this to detect KAD callback responses.
/// Server LowID callbacks are detected separately via the source manager.
pub type PendingKadCallbacks = Arc<tokio::sync::Mutex<HashMap<std::net::Ipv4Addr, Vec<([u8; 16], Option<[u8; 16]>, i64)>>>>;

pub struct UdpFirewallCheckRequest {
    pub peer_ip: Ipv4Addr,
    pub internal_udp_port: u16,
    pub external_udp_port: u16,
    pub receiver_udp_key: u32,
}

const CLIENT_TIMEOUT_SECS: u64 = 120;
/// Maximum concurrent TCP connections from a single IP address
const MAX_CONNECTIONS_PER_IP: usize = 3;
/// Maximum total concurrent TCP connections to the upload server
const MAX_TOTAL_CONNECTIONS: usize = 100;
/// Maximum number of peers waiting in the upload queue
const MAX_UPLOAD_QUEUE_SIZE: usize = 500;
/// eMule SESSIONMAXTRANS: max bytes uploaded per session before rotating slots (opcodes.h:97).
const SESSIONMAXTRANS: u64 = PARTSIZE + 20 * 1024;
/// eMule SESSIONMAXTIME: max duration of a single upload session (1 hour).
const SESSIONMAXTIME_SECS: u64 = 3600;
/// eMule MIN_UP_CLIENTS_ALLOWED: minimum upload slots regardless of bandwidth
const MIN_UP_CLIENTS_ALLOWED: usize = 2;
/// eMule MAX_UP_CLIENTS_ALLOWED: maximum upload slots
const MAX_UP_CLIENTS_ALLOWED: usize = 100;
/// m7: Hard queue limit = soft + max(soft, 800) / 4.  Between soft and hard,
/// only clients with above-average score are admitted; above hard, all rejected.
const HARD_UPLOAD_QUEUE_SIZE: usize = MAX_UPLOAD_QUEUE_SIZE
    + (if MAX_UPLOAD_QUEUE_SIZE > 800 { MAX_UPLOAD_QUEUE_SIZE } else { 800 }) / 4;
/// m6: Score multiplier for peers we are simultaneously downloading from.
const DOWNLOAD_BONUS_MULTIPLIER: f64 = 1.5;

/// eMule-style per-file request frequency tracker for detecting aggressive leechers.
/// MIN_REQUESTTIME (eMule) is 590 seconds. After BADCLIENTBAN infractions, ban the client.
const MIN_REQUESTTIME_SECS: u64 = 590;
const BADCLIENTBAN: u32 = 2;

struct FileRequestTracker {
    /// Maps (peer_ip, file_hash) -> (last_request_time, bad_request_count)
    entries: HashMap<(Ipv4Addr, [u8; 16]), (std::time::Instant, u32)>,
}

impl FileRequestTracker {
    fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    /// Returns true if the client should be banned.
    fn record_request(&mut self, ip: Ipv4Addr, file_hash: [u8; 16]) -> bool {
        let now = std::time::Instant::now();
        let key = (ip, file_hash);
        if let Some((last_time, bad_count)) = self.entries.get_mut(&key) {
            if last_time.elapsed().as_secs() < MIN_REQUESTTIME_SECS {
                *bad_count += 1;
                *last_time = now;
                return *bad_count >= BADCLIENTBAN;
            }
            *last_time = now;
            false
        } else {
            self.entries.insert(key, (now, 0));
            false
        }
    }

    fn cleanup_stale(&mut self) {
        self.entries.retain(|_, (t, _)| t.elapsed().as_secs() < 3600);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum QueueIdentity {
    UserHash([u8; 16]),
    Ip(IpAddr),
}

impl QueueIdentity {
    fn from_peer(peer_user_hash: [u8; 16], peer_addr: SocketAddr) -> Self {
        if peer_user_hash != [0u8; 16] {
            Self::UserHash(peer_user_hash)
        } else {
            Self::Ip(peer_addr.ip())
        }
    }
}

#[derive(Debug, Clone)]
struct QueueEntry {
    identity: QueueIdentity,
    current_addr: Option<SocketAddr>,
    user_hash: [u8; 16],
    file_hash: [u8; 16],
    join_time: std::time::Instant,
    /// eMule m_bAddNextConnect: Low-ID client that scored highest while
    /// disconnected; gets priority slot on reconnect.
    add_next_connect: bool,
    /// eMule m_byEmuleVersion from Hello, for legacy client penalty.
    emule_version: u8,
    /// True if this peer is a friend with an active friend slot.
    is_friend_slot: bool,
}

#[derive(Debug, Clone)]
struct ResolvedUploadFile {
    name: String,
    path: PathBuf,
    size: u64,
    aich_hash_hex: String,
    is_partial: bool,
}

pub struct UploadEvent {
    pub transfer_id: String,
    pub kind: UploadEventKind,
}

pub enum UploadEventKind {
    Started {
        file_name: String,
        file_hash: String,
        total_size: u64,
        peer_addr: String,
        peer_name: String,
        client_software: String,
        country_code: Option<String>,
    },
    Progress {
        uploaded: u64,
        total: u64,
    },
    Completed,
    Failed {
        error: String,
    },
    /// Per-file upload discovery stats (Library requests / accepted columns, known.met).
    ShareInterest {
        file_hash: String,
        inc_requests: u32,
        inc_accepted: u32,
    },
    /// Sources discovered via Ember Peer Exchange from an incoming Ember peer.
    EmberSources {
        entries: Vec<([u8; 16], Vec<(std::net::Ipv4Addr, u16, u16, u8)>)>,
        aich_roots: Vec<([u8; 16], [u8; 20])>,
        ember_peers: Vec<(std::net::Ipv4Addr, u16)>,
    },
    /// An Ember peer was detected (for peer discovery mesh bootstrap).
    EmberPeerDiscovered {
        ip: std::net::Ipv4Addr,
        tcp_port: u16,
    },
    /// Incoming friend request from an Ember peer.
    EmberFriendRequest {
        ember_hash: [u8; 16],
        nickname: String,
        peer_ip: String,
        peer_port: u16,
    },
    /// An Ember friend was seen on an incoming connection (EmuleInfo exchange completed).
    FriendSeen {
        ember_hash: [u8; 16],
        ip: std::net::IpAddr,
        port: u16,
    },
    /// Incoming Ember chat message from a peer.
    EmberChatMessage {
        ember_hash: [u8; 16],
        message: String,
    },
    /// Incoming Ember browse request from a friend.
    EmberBrowseRequest {
        ember_hash: [u8; 16],
    },
    /// Incoming Ember browse response from a friend (outbound session).
    EmberBrowseResponse {
        ember_hash: [u8; 16],
        entries: Vec<(String, u64, String)>,
    },
    EmberFriendDisconnected {
        ember_hash: [u8; 16],
    },
}

/// Handles incoming TCP connections from other peers requesting file uploads.
/// This is the peer-to-peer upload listener, NOT an eMule server connection.
struct UploadHandler {
    local_index: Arc<RwLock<LocalIndex>>,
    transfer_manager: Arc<RwLock<TransferManager>>,
    bandwidth_limiter: Arc<BandwidthLimiter>,
    shared_folders: Arc<RwLock<Vec<String>>>,
    download_folder: PathBuf,
    user_hash: [u8; 16],
    nickname: String,
    obfuscation_enabled: bool,
    tcp_port: u16,
    udp_port: u16,
    active_count: Arc<std::sync::atomic::AtomicUsize>,
    max_concurrent_uploads: Arc<std::sync::atomic::AtomicUsize>,
    upload_event_tx: tokio::sync::mpsc::Sender<UploadEvent>,
    upload_queue: Arc<tokio::sync::Mutex<Vec<QueueEntry>>>,
    ip_connection_counts: Arc<tokio::sync::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>>,
    total_connections: Arc<std::sync::atomic::AtomicUsize>,
    source_manager: Arc<RwLock<SourceManager>>,
    comment_manager: Arc<RwLock<CommentManager>>,
    credit_manager: Arc<RwLock<CreditManager>>,
    a4af_manager: Arc<RwLock<A4AFManager>>,
    /// File hashes we're currently downloading (for A4AF registration)
    pending_download_hashes: Arc<RwLock<Vec<[u8; 16]>>>,
    /// Active port test waiters (IP -> Sender)
    active_port_tests: Arc<tokio::sync::Mutex<HashMap<IpAddr, tokio::sync::mpsc::Sender<()>>>>,
    /// User hashes expected as incoming buddy connections
    pending_buddy_hashes: PendingBuddySet,
    /// Channel to send recognized buddy connections back to the network task
    buddy_conn_tx: tokio::sync::mpsc::Sender<BuddyConnectionParts>,
    /// Shared buddy info for Hello tags
    shared_buddy_info: SharedBuddyInfo,
    /// GeoIP reader for country lookups
    geoip: crate::geoip::GeoIpReader,
    /// Current ed2k server for Hello callback metadata
    shared_server_addr: Arc<RwLock<Option<SocketAddr>>>,
    /// Shared IP filter snapshot for blocking incoming connections
    shared_ip_filter: SharedIpFilter,
    /// Shared banned IPs set for rejecting banned peers on TCP
    banned_ips: SharedBannedIps,
    /// eMule: dontcompressavi — skip compression for video files
    skip_compress_video: bool,
    /// Apply IP filter to incoming TCP connections (when false, only outbound is filtered)
    filter_incoming_connections: bool,
    /// IPs we probed with FirewalledReq -- connect-back proves TCP is open
    firewall_probe_ips: FirewallProbeSet,
    /// Shared atomic: set to false when TCP is proven open
    firewalled_shared: Arc<std::sync::atomic::AtomicBool>,
    /// IPs expected as incoming KAD callback connections (source -> file_hash)
    pending_kad_callbacks: PendingKadCallbacks,
    /// Channel to forward recognized KAD callback connections to network task
    kad_callback_tx: tokio::sync::mpsc::Sender<KadCallbackParts>,
    /// Channel to request a KADEMLIA2_FIREWALLUDP response via the main UDP socket
    udp_fw_check_tx: tokio::sync::mpsc::Sender<UdpFirewallCheckRequest>,
    /// eMule-style abuse tracking: per-IP request counts for auto-ban
    abuse_tracker: Arc<tokio::sync::Mutex<AbuseTracker>>,
    /// In-memory AICH hash cache: file_hash_hex -> (AICHRecoveryHashSet, last_access)
    aich_cache: Arc<tokio::sync::Mutex<AichCache>>,
    /// Our Ember identity hash, sent in EmuleInfo for friend identification
    ember_hash: [u8; 16],
    /// Live friend user-hash set for friend-slot priority boost
    friend_hashes: Arc<RwLock<std::collections::HashSet<[u8; 16]>>>,
    /// Pre-built Ember Peer Exchange payload (shared, read-only).
    ember_payload: crate::network::ember::SharedEmberPayload,
    /// eMule-style per-file request frequency tracker (AddRequestCount)
    file_request_tracker: Arc<tokio::sync::Mutex<FileRequestTracker>>,
    /// Notify queued clients when a slot becomes available (fired by UploadSlotGuard
    /// on deactivate/drop, and by the proactive slot opener timer).
    slot_notify: Arc<tokio::sync::Notify>,
    /// Per-slot smoothed upload rates for dynamic slot decisions.
    slot_rates: SlotRateRegistry,
    /// Active Ember friend sessions: ember_hash -> outbound packet sender
    ember_sessions: EmberSessionMap,
    /// Set to true when the network is disconnected; upload handlers check
    /// this to reject new file requests and terminate active sessions (eMule
    /// behavior: all upload activity stops on disconnect).
    network_disconnected: Arc<std::sync::atomic::AtomicBool>,
}

const MAX_AICH_CACHE_ENTRIES: usize = 50;

struct AichCache {
    entries: HashMap<String, (crate::network::ed2k::aich::AICHRecoveryHashSet, std::time::Instant)>,
}

impl AichCache {
    fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    fn get(&mut self, key: &str) -> Option<crate::network::ed2k::aich::AICHRecoveryHashSet> {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.1 = std::time::Instant::now();
            Some(entry.0.clone())
        } else {
            None
        }
    }

    fn insert(&mut self, key: String, value: crate::network::ed2k::aich::AICHRecoveryHashSet) {
        if self.entries.len() >= MAX_AICH_CACHE_ENTRIES {
            if let Some(oldest_key) = self.entries.iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest_key);
            }
        }
        self.entries.insert(key, (value, std::time::Instant::now()));
    }
}

/// EWMA-based per-session upload rate tracker.
/// α = 0.3 gives roughly a 3-sample half-life, balancing responsiveness
/// and smoothness for the dynamic slot opener.
struct SessionRateTracker {
    last_send: std::time::Instant,
    smoothed_bps: f64,
    has_sample: bool,
}

impl SessionRateTracker {
    fn new() -> Self {
        Self {
            last_send: std::time::Instant::now(),
            smoothed_bps: 0.0,
            has_sample: false,
        }
    }

    fn record_send(&mut self, bytes: u64) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_send).as_secs_f64();
        self.last_send = now;
        if elapsed > 0.001 {
            let instant_bps = bytes as f64 / elapsed;
            if self.has_sample {
                self.smoothed_bps = 0.3 * instant_bps + 0.7 * self.smoothed_bps;
            } else {
                self.smoothed_bps = instant_bps;
                self.has_sample = true;
            }
        }
    }

    fn smoothed_rate(&self) -> u64 {
        self.smoothed_bps as u64
    }
}

/// eMule-style automatic abusive-client detection (CBanList equivalent).
/// Tracks per-IP request rates and auto-bans IPs that exceed thresholds.
struct AbuseTracker {
    /// (request_count, first_request_time, last_request_time, banned_until)
    entries: HashMap<std::net::IpAddr, AbuseEntry>,
    last_cleanup: std::time::Instant,
}

struct AbuseEntry {
    request_count: u32,
    window_start: std::time::Instant,
    file_not_found_count: u32,
    banned_until: Option<std::time::Instant>,
}

/// eMule: BAN_TIMEOUT = 2 hours
const BAN_DURATION_SECS: u64 = 7200;
/// Max requests per 5-minute window before auto-ban
const MAX_REQUESTS_PER_WINDOW: u32 = 40;
/// Window size for tracking request rate
const ABUSE_WINDOW_SECS: u64 = 300;
/// Max "file not found" hits before ban (prevents hash-probing)
const MAX_FILE_NOT_FOUND: u32 = 10;

impl AbuseTracker {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            last_cleanup: std::time::Instant::now(),
        }
    }

    /// Check if an IP is currently banned. Returns true if banned.
    fn is_banned(&self, ip: &std::net::IpAddr) -> bool {
        if let Some(entry) = self.entries.get(ip) {
            if let Some(until) = entry.banned_until {
                return std::time::Instant::now() < until;
            }
        }
        false
    }

    /// Record a request from this IP. Returns true if the IP should be banned.
    fn record_request(&mut self, ip: std::net::IpAddr) -> bool {
        let now = std::time::Instant::now();

        // Periodic cleanup of expired entries
        if now.duration_since(self.last_cleanup).as_secs() > 600 {
            self.entries.retain(|_, e| match e.banned_until {
                Some(u) if now >= u => false,
                Some(_) => true,
                None => now.duration_since(e.window_start).as_secs() < ABUSE_WINDOW_SECS * 2,
            });
            self.last_cleanup = now;
        }

        let entry = self.entries.entry(ip).or_insert_with(|| AbuseEntry {
            request_count: 0,
            window_start: now,
            file_not_found_count: 0,
            banned_until: None,
        });

        if let Some(until) = entry.banned_until {
            return now < until;
        }

        // Reset window if expired
        if now.duration_since(entry.window_start).as_secs() > ABUSE_WINDOW_SECS {
            entry.request_count = 0;
            entry.window_start = now;
        }

        entry.request_count += 1;

        if entry.request_count > MAX_REQUESTS_PER_WINDOW {
            entry.banned_until = Some(now + std::time::Duration::from_secs(BAN_DURATION_SECS));
            tracing::warn!("Auto-banned {ip}: {} requests in {}s window", entry.request_count, ABUSE_WINDOW_SECS);
            return true;
        }

        false
    }

    /// Record a "file not found" response to this IP. Returns true if should ban.
    fn record_file_not_found(&mut self, ip: std::net::IpAddr) -> bool {
        let now = std::time::Instant::now();
        let entry = self.entries.entry(ip).or_insert_with(|| AbuseEntry {
            request_count: 0,
            window_start: now,
            file_not_found_count: 0,
            banned_until: None,
        });

        entry.file_not_found_count += 1;

        if entry.file_not_found_count > MAX_FILE_NOT_FOUND {
            entry.banned_until = Some(now + std::time::Duration::from_secs(BAN_DURATION_SECS));
            tracing::warn!("Auto-banned {ip}: {} file-not-found requests (hash probing)", entry.file_not_found_count);
            return true;
        }

        false
    }
}

/// eMule file priority to score multiplier, matching GetFilePrioAsNumber()/10.
fn priority_weight(priority: &str) -> f64 {
    match priority {
        "release" => 1.8,   // maps to eMule VeryHigh (18/10)
        "high" => 0.9,      // maps to eMule High (9/10)
        "normal" => 0.7,    // maps to eMule Normal (7/10)
        "low" => 0.6,       // maps to eMule Low (6/10)
        "verylow" => 0.2,   // maps to eMule VeryLow (2/10)
        _ => 0.7,
    }
}

/// Consistent eMule-style queue score for a single entry.
/// All code paths that compare or rank queue entries MUST use this function
/// to avoid scoring asymmetry (eMule version penalty, friend slot, download
/// bonus).  `cm` provides credit ratio; `idx` provides file priority.
fn score_queue_entry(
    cm: &CreditManager,
    idx: &LocalIndex,
    user_hash: &[u8; 16],
    file_hash: [u8; 16],
    wait_secs: u64,
    current_addr: Option<SocketAddr>,
    emule_version: u8,
    is_friend_slot: bool,
) -> f64 {
    let file_prio = idx
        .get_by_hash(&hex::encode(file_hash))
        .map(|f| priority_weight(&f.priority))
        .unwrap_or(0.7);
    let peer_ip = current_addr
        .map(|a| match a.ip() {
            IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
            _ => 0,
        })
        .unwrap_or(0);
    let mut score = cm.get_queue_score(user_hash, wait_secs, file_prio, peer_ip);
    if cm.has_download_bonus(user_hash) {
        score *= DOWNLOAD_BONUS_MULTIPLIER;
    }
    if emule_version > 0 && emule_version <= 0x19 {
        score *= 0.5;
    }
    if is_friend_slot {
        score = 268_435_455.0;
    }
    score
}

/// Compute score-based queue rank: 1 + count of entries with strictly higher
/// score.  Ties are broken by earlier join_time (lower = better rank).
fn compute_queue_rank(
    cm: &CreditManager,
    idx: &LocalIndex,
    queue: &[QueueEntry],
    my_identity: &QueueIdentity,
    my_score: f64,
    my_join_time: std::time::Instant,
) -> u16 {
    let mut rank: u16 = 1;
    for entry in queue.iter() {
        if entry.identity == *my_identity {
            continue;
        }
        let es = score_queue_entry(
            cm,
            idx,
            &entry.user_hash,
            entry.file_hash,
            entry.join_time.elapsed().as_secs(),
            entry.current_addr,
            entry.emule_version,
            entry.is_friend_slot,
        );
        if es > my_score || (es == my_score && entry.join_time < my_join_time) {
            rank += 1;
        }
    }
    rank
}

/// eMule MAX_PURGEQUEUETIME: 1 hour in seconds
const MAX_PURGEQUEUETIME_SECS: u64 = 3600;

pub async fn start_upload_server(
    tcp_port: u16,
    user_hash: [u8; 16],
    nickname: String,
    udp_port: u16,
    shared_folders: Arc<RwLock<Vec<String>>>,
    download_folder: PathBuf,
    local_index: Arc<RwLock<LocalIndex>>,
    transfer_manager: Arc<RwLock<TransferManager>>,
    bandwidth_limiter: Arc<BandwidthLimiter>,
    upload_event_tx: tokio::sync::mpsc::Sender<UploadEvent>,
    max_concurrent_uploads: Arc<std::sync::atomic::AtomicUsize>,
    source_manager: Arc<RwLock<SourceManager>>,
    comment_manager: Arc<RwLock<CommentManager>>,
    credit_manager: Arc<RwLock<CreditManager>>,
    a4af_manager: Arc<RwLock<A4AFManager>>,
    pending_download_hashes: Arc<RwLock<Vec<[u8; 16]>>>,
    active_port_tests: Arc<tokio::sync::Mutex<HashMap<std::net::IpAddr, tokio::sync::mpsc::Sender<()>>>>,
    pending_buddy_hashes: PendingBuddySet,
    buddy_conn_tx: tokio::sync::mpsc::Sender<BuddyConnectionParts>,
    shared_buddy_info: SharedBuddyInfo,
    shared_ip_filter: SharedIpFilter,
    banned_ips: SharedBannedIps,
    skip_compress_video: bool,
    filter_incoming_connections: bool,
    firewall_probe_ips: FirewallProbeSet,
    firewalled_shared: Arc<std::sync::atomic::AtomicBool>,
    pending_kad_callbacks: PendingKadCallbacks,
    kad_callback_tx: tokio::sync::mpsc::Sender<KadCallbackParts>,
    udp_fw_check_tx: tokio::sync::mpsc::Sender<UdpFirewallCheckRequest>,
    obfuscation_enabled: bool,
    shared_server_addr: Arc<RwLock<Option<SocketAddr>>>,
    friend_hashes: Arc<RwLock<std::collections::HashSet<[u8; 16]>>>,
    ember_payload: crate::network::ember::SharedEmberPayload,
    geoip: crate::geoip::GeoIpReader,
    ember_sessions: EmberSessionMap,
    ember_hash: [u8; 16],
    network_disconnected: Arc<std::sync::atomic::AtomicBool>,
) -> anyhow::Result<()> {
    let addr: SocketAddr = format!("0.0.0.0:{tcp_port}").parse()?;
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("TCP port {tcp_port} is already in use: {e}. Peer-to-peer uploads will not work.");
            anyhow::bail!("TCP port {tcp_port} already in use: {e}");
        }
    };
    let current_max = max_concurrent_uploads.load(std::sync::atomic::Ordering::Relaxed);
    info!("Peer-to-peer upload listener started on TCP port {tcp_port} (max {current_max} uploads)");

    let active_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let upload_queue = Arc::new(tokio::sync::Mutex::new(Vec::<QueueEntry>::new()));
    let slot_notify = Arc::new(tokio::sync::Notify::new());
    let slot_rates: SlotRateRegistry = Arc::new(std::sync::Mutex::new(HashMap::new()));

    let server = Arc::new(UploadHandler {
        local_index,
        transfer_manager,
        bandwidth_limiter,
        shared_folders,
        download_folder,
        user_hash,
        nickname,
        obfuscation_enabled,
        tcp_port,
        udp_port,
        active_count,
        max_concurrent_uploads,
        upload_event_tx,
        upload_queue,
        ip_connection_counts: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        total_connections: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        source_manager,
        comment_manager,
        credit_manager,
        a4af_manager,
        pending_download_hashes,
        active_port_tests,
        pending_buddy_hashes,
        buddy_conn_tx,
        shared_buddy_info,
        shared_server_addr,
        shared_ip_filter,
        banned_ips,
        skip_compress_video,
        filter_incoming_connections,
        firewall_probe_ips,
        firewalled_shared,
        pending_kad_callbacks,
        kad_callback_tx,
        udp_fw_check_tx,
        abuse_tracker: Arc::new(tokio::sync::Mutex::new(AbuseTracker::new())),
        aich_cache: Arc::new(tokio::sync::Mutex::new(AichCache::new())),
        ember_hash,
        friend_hashes,
        ember_payload,
        geoip,
        file_request_tracker: Arc::new(tokio::sync::Mutex::new(FileRequestTracker::new())),
        slot_notify,
        slot_rates,
        ember_sessions,
        network_disconnected,
    });

    let mut slot_check_interval = tokio::time::interval(std::time::Duration::from_secs(1));
    slot_check_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer_addr)) => {
                        let server = server.clone();

                        // Extract IPv4 from both native V4 and V6-mapped-V4 (::ffff:x.x.x.x).
                        // Reject pure IPv6 peers — ed2k is IPv4-only and we cannot
                        // filter/ban addresses we can't represent as Ipv4Addr.
                        let peer_ipv4 = match peer_addr.ip() {
                            std::net::IpAddr::V4(v4) => v4,
                            std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                                Some(v4) => v4,
                                None => {
                                    debug!("Rejecting non-v4-mapped IPv6 connection from {peer_addr}");
                                    drop(stream);
                                    continue;
                                }
                            },
                        };

                        if server.filter_incoming_connections {
                            if let Ok(snap) = server.shared_ip_filter.read() {
                                if snap.is_blocked(peer_ipv4) {
                                    info!("IP filter blocked incoming TCP from {peer_addr}");
                                    drop(stream);
                                    continue;
                                }
                            }
                        }

                        // Ban check: reject connections from banned IPs or auto-banned abusers
                        if let Ok(banned) = server.banned_ips.read() {
                            if banned.contains(&peer_ipv4) {
                                debug!("Rejecting TCP connection from banned IP {peer_addr}");
                                drop(stream);
                                continue;
                            }
                        }
                        {
                            let tracker = server.abuse_tracker.lock().await;
                            if tracker.is_banned(&peer_addr.ip()) {
                                debug!("Rejecting TCP connection from auto-banned IP {peer_addr}");
                                drop(stream);
                                continue;
                            }
                        }

                        // KAD firewall check: if this IP is one we probed, the TCP
                        // connect-back proves our port is reachable.
                        if let std::net::IpAddr::V4(ipv4) = peer_addr.ip() {
                            let is_probe = {
                                match server.firewall_probe_ips.lock() {
                                    Ok(mut probes) => probes.remove(&ipv4),
                                    Err(e) => {
                                        tracing::warn!("firewall_probe_ips mutex poisoned: {e}");
                                        false
                                    }
                                }
                            };
                            if is_probe {
                                info!("TCP connect-back from {peer_addr} confirms port is open (firewall check passed)");
                                server.firewalled_shared.store(false, std::sync::atomic::Ordering::Relaxed);
                                drop(stream);
                                continue;
                            }
                        }

                        // eMule: reject new upload connections while network is disconnected.
                        // Firewall probes (handled above) still pass through.
                        if server.network_disconnected.load(std::sync::atomic::Ordering::Relaxed) {
                            debug!("Rejecting connection from {peer_addr}: network disconnected");
                            drop(stream);
                            continue;
                        }

                        // Enforce global connection limit
                        let current_total = server.total_connections.load(std::sync::atomic::Ordering::Relaxed);
                        if current_total >= MAX_TOTAL_CONNECTIONS {
                            debug!("Rejecting connection from {peer_addr}: global connection limit reached ({current_total})");
                            drop(stream);
                            continue;
                        }

                        // Enforce per-IP connection limit
                        {
                            let mut counts = server.ip_connection_counts.lock().await;
                            let count = counts.entry(peer_addr.ip()).or_insert(0);
                            if *count >= MAX_CONNECTIONS_PER_IP {
                                debug!("Rejecting connection from {peer_addr}: per-IP limit reached");
                                drop(stream);
                                continue;
                            }
                            *count += 1;
                        }

                        server.total_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let _ = stream.set_nodelay(true);
                        debug!("Incoming ED2K connection from {peer_addr}");
                        tokio::spawn(async move {
                            let result = std::panic::AssertUnwindSafe(
                                server.handle_connection(stream, peer_addr)
                            ).catch_unwind().await;
                            match result {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => {
                                    let msg = e.to_string();
                                    if msg.contains("end of file") || msg.contains("Connection reset")
                                        || msg.contains("connection reset") || msg.contains("broken pipe")
                                    {
                                        debug!("Probe/short-lived connection from {peer_addr}: {msg}");
                                    } else {
                                        warn!("Connection from {peer_addr} ended: {e}");
                                    }
                                }
                                Err(_panic) => {
                                    error!("Connection handler panicked for {peer_addr}");
                                }
                            }
                            server.total_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                            let mut counts = server.ip_connection_counts.lock().await;
                            if let Some(count) = counts.get_mut(&peer_addr.ip()) {
                                *count = count.saturating_sub(1);
                                if *count == 0 {
                                    counts.remove(&peer_addr.ip());
                                }
                            }
                        });
                    }
                    Err(e) => {
                        warn!("TCP accept error: {e}");
                    }
                }
            }
            _ = slot_check_interval.tick() => {
                let active = server.active_count.load(std::sync::atomic::Ordering::Relaxed);
                let dynamic_slots = server.compute_dynamic_slot_count();
                if active < dynamic_slots {
                    let queue = server.upload_queue.lock().await;
                    let has_waiters = queue.iter().any(|e| e.current_addr.is_some());
                    drop(queue);
                    if has_waiters {
                        debug!(
                            "Proactive slot opener: {active}/{dynamic_slots} active, signalling queued clients"
                        );
                        server.slot_notify.notify_waiters();
                    }
                }
            }
        }
    }
}

impl UploadHandler {
    async fn resolve_upload_file(&self, file_hash: &[u8; 16]) -> Option<ResolvedUploadFile> {
        let hash_hex = hex::encode(file_hash);
        if let Some(file) = {
            let index = self.local_index.read().await;
            index.get_by_hash(&hash_hex).cloned()
        } {
            let path = PathBuf::from(&file.path);
            let is_partial = path.extension().map(|e| e == "part").unwrap_or(false);
            if !is_partial {
                let folders = self.shared_folders.read().await;
                if !folders.is_empty() {
                    let in_shared = std::fs::canonicalize(&path)
                        .map(|canon| {
                            crate::security::is_path_within_dirs(&canon, &folders)
                                || crate::security::is_path_within_dirs(&canon, &[
                                    self.download_folder.to_string_lossy().to_string(),
                                    self.download_folder.join("Downloads").to_string_lossy().to_string(),
                                ])
                        })
                        .unwrap_or(false);
                    if !in_shared {
                        tracing::debug!("Rejecting resolve for file not in shared folders: {}", hash_hex);
                        return None;
                    }
                }
            }
            return Some(ResolvedUploadFile {
                name: file.name,
                path: path.clone(),
                size: file.size,
                aich_hash_hex: file.aich_hash,
                is_partial,
            });
        }

        let transfer = {
            let mgr = self.transfer_manager.read().await;
            mgr.active
                .values()
                .find(|t| t.direction == TransferDirection::Download && t.file_hash == hash_hex)
                .cloned()
                .or_else(|| {
                    mgr.queue
                        .iter()
                        .find(|t| t.direction == TransferDirection::Download && t.file_hash == hash_hex)
                        .cloned()
                })
        }?;

        let part_path = self
            .download_folder
            .join("Temp")
            .join(format!("{}.part", transfer.id));
        if !part_path.exists() {
            return None;
        }

        Some(ResolvedUploadFile {
            name: transfer.file_name,
            path: part_path,
            size: transfer.total_size,
            aich_hash_hex: String::new(),
            is_partial: true,
        })
    }

    /// One "request" per file per incoming connection (eMule-style asked count).
    async fn record_share_request_once(
        &self,
        hash: &[u8; 16],
        recorded: &mut Option<[u8; 16]>,
    ) {
        if recorded.as_ref() == Some(hash) {
            return;
        }
        *recorded = Some(*hash);
        let _ = self
            .upload_event_tx
            .send(UploadEvent {
                transfer_id: String::new(),
                kind: UploadEventKind::ShareInterest {
                    file_hash: hex::encode(hash),
                    inc_requests: 1,
                    inc_accepted: 0,
                },
            })
            .await;
    }

    async fn record_share_accepted(&self, hash: &[u8; 16]) {
        let _ = self
            .upload_event_tx
            .send(UploadEvent {
                transfer_id: String::new(),
                kind: UploadEventKind::ShareInterest {
                    file_hash: hex::encode(hash),
                    inc_requests: 0,
                    inc_accepted: 1,
                },
            })
            .await;
    }

    /// eMule ForceNewClient/AcceptNewClient dynamic slot computation.
    /// Uses observed (smoothed) upload bandwidth to decide how many concurrent
    /// upload slots the server should maintain, scaling per-slot target rate
    /// as the number of active slots grows.
    ///
    /// When per-slot rate data is available from `slot_rates`, the median
    /// per-slot rate is compared against the target: if existing slots are
    /// already starved (median < target * 0.5), we avoid opening more even
    /// if the formula would allow it.
    fn compute_dynamic_slot_count(&self) -> usize {
        let active = self.active_count.load(std::sync::atomic::Ordering::Relaxed);
        let max_configured = self.max_concurrent_uploads.load(std::sync::atomic::Ordering::Relaxed);

        let observed_rate = self.bandwidth_limiter.smoothed_upload_speed();
        let effective_rate = if observed_rate > 0 || active > 0 {
            observed_rate
        } else {
            self.bandwidth_limiter.effective_upload_rate()
        };

        if effective_rate == 0 {
            return MIN_UP_CLIENTS_ALLOWED.min(max_configured);
        }

        let target_per_slot = if active <= 3 {
            3u64 * 1024
        } else {
            (3u64 * 1024 + (active as u64 - 3) * 1024).min(10 * 1024)
        };

        let computed = (effective_rate / target_per_slot).max(MIN_UP_CLIENTS_ALLOWED as u64);
        let computed = (computed as usize).min(MAX_UP_CLIENTS_ALLOWED).min(max_configured);

        if active >= 2 {
            let rates = self.slot_rates.lock().unwrap_or_else(|e| e.into_inner());
            if rates.len() >= 2 {
                let mut sorted: Vec<u64> = rates.values().copied().collect();
                sorted.sort_unstable();
                let median = sorted[sorted.len() / 2];
                drop(rates);
                if median < target_per_slot / 2 && computed > active {
                    return active;
                }
            }
        }

        computed
    }

    async fn hello_options(&self) -> HelloOptions {
        let server = *self.shared_server_addr.read().await;
        let server_ip = server
            .and_then(|addr| match addr.ip() {
                IpAddr::V4(v4) => Some(u32::from_le_bytes(v4.octets())),
                _ => None,
            })
            .unwrap_or(0);
        let server_port = server.map(|addr| addr.port()).unwrap_or(0);
        HelloOptions {
            udp_port: self.udp_port,
            kad_port: self.udp_port,
            supports_crypt_layer: self.obfuscation_enabled,
            requests_crypt_layer: self.obfuscation_enabled,
            requires_crypt_layer: false,
            supports_direct_udp_callback: false,
            supports_captcha: false,
            server_ip,
            server_port,
            kad_version: 0x09,
        }
    }

    async fn send_comment_info<W: AsyncWriteExt + Unpin + ?Sized>(
        &self,
        writer: &mut W,
        file_hash: &[u8; 16],
    ) -> anyhow::Result<()> {
        let hash_hex = hex::encode(file_hash);
        let (rating, comment) = {
            let cm = self.comment_manager.read().await;
            let (rating, comment) = cm.get_our_comment(&hash_hex);
            (rating, comment.to_string())
        };
        if rating == 0 && comment.is_empty() {
            return Ok(());
        }
        let comment_bytes = comment.as_bytes();
        let mut payload = Vec::with_capacity(5 + comment_bytes.len());
        payload.push(rating);
        payload.extend_from_slice(&(comment_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(comment_bytes);
        write_packet_async(writer, OP_EMULEPROT, OP_FILEDESC, &payload).await?;
        Ok(())
    }

    async fn handle_connection(
        &self,
        stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        // Check if already banned (fast path), but don't count yet --
        // buddy/KAD callback connections are legitimate and shouldn't
        // inflate the request counter.
        {
            let tracker = self.abuse_tracker.lock().await;
            if tracker.is_banned(&peer_addr.ip()) {
                anyhow::bail!("auto-banned for excessive requests");
            }
        }

        let (reader, writer) = stream.into_split();
        let mut raw_reader = tokio::io::BufReader::new(reader);
        let mut raw_writer = tokio::io::BufWriter::new(writer);

        // Negotiate obfuscation with full handshake response.
        let negotiation = match tokio::time::timeout(
            std::time::Duration::from_secs(CLIENT_TIMEOUT_SECS),
            tcp_obfuscation::negotiate_incoming(&mut raw_reader, &mut raw_writer, &self.user_hash, true),
        ).await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) if is_connection_closed(&e) => {
                info!("Probe connection from {peer_addr} (closed immediately)");
                return Ok(());
            }
            Ok(Err(e)) => {
                info!("Obfuscation negotiation failed from {peer_addr}: {e}");
                return Ok(());
            }
            Err(_) => {
                info!("Timeout during negotiation from {peer_addr}");
                return Ok(());
            }
        };

        // After negotiation, wrap streams based on result.
        // We use an enum to avoid dyn dispatch issues with AsyncReadExt.
        enum StreamReader {
            Plain(tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>),
            Obfuscated(tokio::io::BufReader<Rc4Reader<tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>>>),
        }
        enum StreamWriter {
            Plain(tokio::io::BufWriter<tokio::net::tcp::OwnedWriteHalf>),
            Obfuscated(tokio::io::BufWriter<Rc4Writer<tokio::io::BufWriter<tokio::net::tcp::OwnedWriteHalf>>>),
        }

        impl AsyncRead for StreamReader {
            fn poll_read(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<io::Result<()>> {
                match self.get_mut() {
                    StreamReader::Plain(r) => Pin::new(r).poll_read(cx, buf),
                    StreamReader::Obfuscated(r) => Pin::new(r).poll_read(cx, buf),
                }
            }
        }

        impl AsyncWrite for StreamWriter {
            fn poll_write(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<io::Result<usize>> {
                match self.get_mut() {
                    StreamWriter::Plain(w) => Pin::new(w).poll_write(cx, buf),
                    StreamWriter::Obfuscated(w) => Pin::new(w).poll_write(cx, buf),
                }
            }
            fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
                match self.get_mut() {
                    StreamWriter::Plain(w) => Pin::new(w).poll_flush(cx),
                    StreamWriter::Obfuscated(w) => Pin::new(w).poll_flush(cx),
                }
            }
            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
                match self.get_mut() {
                    StreamWriter::Plain(w) => Pin::new(w).poll_shutdown(cx),
                    StreamWriter::Obfuscated(w) => Pin::new(w).poll_shutdown(cx),
                }
            }
        }

        // Server port test detection: if this IP matches our connected/pending server,
        // the server is verifying our TCP port is reachable for HighID assignment.
        // Use a short timeout so we respond quickly without blocking the main login.
        let is_server_port_test = {
            let server_addr = self.shared_server_addr.read().await;
            server_addr.map(|a| a.ip() == peer_addr.ip()).unwrap_or(false)
        };

        let mut obf_ember_hash: Option<[u8; 16]> = None;
        let mut obf_emule_caps: Option<PeerCapabilities> = None;
        let (mut reader, mut writer, hello_data, peer_user_hash) = match negotiation {
            NegotiationResult::Obfuscated { recv_key, mut send_key } => {
                info!("Obfuscated connection from {peer_addr}");
                let mut obf_reader = tokio::io::BufReader::new(Rc4Reader::new(raw_reader, recv_key));

                let probe_timeout = if is_server_port_test {
                    info!("Server port test detected from {peer_addr}");
                    std::time::Duration::from_secs(3)
                } else {
                    std::time::Duration::from_secs(15)
                };
                let first_pkt = tokio::time::timeout(probe_timeout, read_packet_async_inner(&mut obf_reader)).await;

                match first_pkt {
                    Ok(Ok((proto, opcode, payload))) if proto == OP_EDONKEYHEADER && opcode == OP_HELLO => {
                        let mut puh = [0u8; 16];
                        if payload.len() >= 17 { puh.copy_from_slice(&payload[1..17]); }

                        let buddy = self.shared_buddy_info.read().await.clone();
                        let hello_options = self.hello_options().await;
                        let hello_payload = build_hello_answer_with_buddy_opts(
                            &self.user_hash,
                            0,
                            self.tcp_port,
                            &self.nickname,
                            buddy,
                            &hello_options,
                        );
                        let mut pkt = Vec::with_capacity(6 + hello_payload.len());
                        pkt.push(OP_EDONKEYHEADER);
                        pkt.extend_from_slice(&((1 + hello_payload.len()) as u32).to_le_bytes());
                        pkt.push(OP_HELLOANSWER);
                        pkt.extend_from_slice(&hello_payload);
                        let mut enc = vec![0u8; pkt.len()];
                        send_key.process(&pkt, &mut enc);
                        raw_writer.write_all(&enc).await?;
                        raw_writer.flush().await?;

                        let emule_payload = build_emule_info(self.udp_port, self.obfuscation_enabled, Some(&self.ember_hash));
                        let mut epkt = Vec::with_capacity(6 + emule_payload.len());
                        epkt.push(OP_EMULEPROT);
                        epkt.extend_from_slice(&((1 + emule_payload.len()) as u32).to_le_bytes());
                        epkt.push(OP_EMULEINFOANSWER);
                        epkt.extend_from_slice(&emule_payload);
                        let mut eenc = vec![0u8; epkt.len()];
                        send_key.process(&epkt, &mut eenc);
                        raw_writer.write_all(&eenc).await?;
                        raw_writer.flush().await?;

                        if is_server_port_test {
                            info!("Server port test from {peer_addr}: replied to Hello+EmuleInfo, port verified");
                            let mut discard = [0u8; 4096];
                            let _ = tokio::time::timeout(
                                std::time::Duration::from_secs(5),
                                async {
                                    loop {
                                        match obf_reader.read(&mut discard).await {
                                            Ok(0) | Err(_) => break,
                                            Ok(_) => continue,
                                        }
                                    }
                                }
                            ).await;
                            return Ok(());
                        }

                        // Consume peer's EmuleInfo/SecIdent packets
                        let mut obf_peer_ember_hash: Option<[u8; 16]> = None;
                        let mut obf_peer_caps: Option<PeerCapabilities> = None;
                        for _ in 0..5 {
                            match tokio::time::timeout(std::time::Duration::from_secs(5), read_packet_async_inner(&mut obf_reader)).await {
                                Ok(Ok((p, o, ref data))) => {
                                    if p == OP_EMULEPROT && (o == OP_EMULEINFOANSWER || o == OP_EMULEINFO) {
                                        let ic = parse_emule_info(data);
                                        if ic.ember_hash.is_some() {
                                            obf_peer_ember_hash = ic.ember_hash;
                                        }
                                        obf_peer_caps = Some(ic);
                                        break;
                                    }
                                }
                                _ => break,
                            }
                        }

                        let obf_writer = tokio::io::BufWriter::new(Rc4Writer::new(raw_writer, send_key));
                        obf_ember_hash = obf_peer_ember_hash;
                        obf_emule_caps = obf_peer_caps;
                        (StreamReader::Obfuscated(obf_reader), StreamWriter::Obfuscated(obf_writer), payload, puh)
                    }
                    Ok(Ok((proto, opcode, _))) if proto == OP_EMULEPROT && opcode == OP_PORTTEST => {
                        let mut pkt = Vec::with_capacity(8);
                        pkt.push(OP_EMULEPROT);
                        pkt.extend_from_slice(&2u32.to_le_bytes());
                        pkt.push(OP_PORTTEST);
                        pkt.push(0x12);
                        let mut enc = vec![0u8; pkt.len()];
                        send_key.process(&pkt, &mut enc);
                        raw_writer.write_all(&enc).await?;
                        raw_writer.flush().await?;
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        return Ok(());
                    }
                    _ => {
                        if is_server_port_test {
                            info!("Server port test from {peer_addr}: no Hello received, keeping alive briefly");
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        }
                        return Ok(());
                    }
                }
            }
            NegotiationResult::Plain { first_byte } => {
                let mut rd = StreamReader::Plain(raw_reader);
                let mut wr = StreamWriter::Plain(raw_writer);
                let (proto, opcode, hd) = read_packet_with_first_byte(&mut rd, first_byte).await?;

                if (proto == OP_EDONKEYHEADER || proto == OP_EMULEPROT) && opcode == OP_PORTTEST {
                    debug!("Received TCP Port Test from {peer_addr}");
                    let reply = [0x12u8];
                    write_packet_async(&mut wr, proto, OP_PORTTEST, &reply).await?;
                    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
                    { let mut waiters = self.active_port_tests.lock().await; waiters.insert(peer_addr.ip(), tx); }
                    let signal = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv()).await;
                    { let mut waiters = self.active_port_tests.lock().await; waiters.remove(&peer_addr.ip()); }
                    if let Ok(Some(_)) = signal {
                        write_packet_async(&mut wr, proto, OP_PORTTEST, &reply).await?;
                    }
                    return Ok(());
                }

                if proto != OP_EDONKEYHEADER || opcode != OP_HELLO {
                    info!("Non-Hello packet from {peer_addr}: proto=0x{proto:02X} op=0x{opcode:02X}");
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    return Ok(());
                }

                let mut puh = [0u8; 16];
                if hd.len() >= 17 { puh.copy_from_slice(&hd[1..17]); }
                debug!("Got Hello from {peer_addr}");

                let buddy = self.shared_buddy_info.read().await.clone();
                let hello_options = self.hello_options().await;
                let hello_payload = build_hello_answer_with_buddy_opts(
                    &self.user_hash,
                    0,
                    self.tcp_port,
                    &self.nickname,
                    buddy,
                    &hello_options,
                );
                write_packet_async(&mut wr, OP_EDONKEYHEADER, OP_HELLOANSWER, &hello_payload).await?;
                (rd, wr, hd, puh)
            }
        };

        let (_, mut hello_caps) =
            parse_hello_packet(&hello_data).unwrap_or_else(|_| ([0u8; 16], PeerCapabilities::default()));
        if let Some(obf_caps) = obf_emule_caps.take() {
            merge_caps(&mut hello_caps, obf_caps);
        }
        let peer_source_exchange_ver = hello_caps.source_exchange_ver.max(1);
        let peer_secure_ident_level = hello_caps.secure_ident_level;
        let peer_compression_ver = hello_caps.compression_ver;
        let mut ul_peer_name = if hello_caps.peer_name.is_empty() { peer_addr.to_string() } else { hello_caps.peer_name.clone() };
        let mut ul_client_software = client_software_from_caps(&hello_caps);
        let ul_country_code = crate::geoip::lookup_country(&self.geoip, peer_addr.ip());

        // Check if this is an incoming buddy connection
        {
            let mut pending = self.pending_buddy_hashes.lock().await;
            if let Some((callback_check, _)) = pending.remove(&peer_user_hash) {
                info!("Recognized incoming buddy connection from {peer_addr}");
                let (tcp_reader, tcp_writer): (
                    Box<dyn tokio::io::AsyncRead + Unpin + Send>,
                    Box<dyn tokio::io::AsyncWrite + Unpin + Send + Sync>,
                ) = match (reader, writer) {
                    (StreamReader::Plain(r), StreamWriter::Plain(w)) => (Box::new(r), Box::new(w)),
                    (StreamReader::Obfuscated(r), StreamWriter::Obfuscated(w)) => {
                        (Box::new(r), Box::new(w))
                    }
                    _ => {
                        return Ok(());
                    }
                };
                let _ = self.buddy_conn_tx.send((peer_user_hash, callback_check, tcp_reader, tcp_writer)).await;
                return Ok(());
            }
        }

        // Check if this is a KAD callback connection (firewalled source connecting back)
        if let std::net::IpAddr::V4(peer_v4) = peer_addr.ip() {
            let callback_file = {
                let mut cbs = self.pending_kad_callbacks.lock().await;
                let now = chrono::Utc::now().timestamp();
                cbs.retain(|_, entries| {
                    entries.retain(|(_, _, ts)| now - *ts < 120);
                    !entries.is_empty()
                });
                if let Some(entries) = cbs.get_mut(&peer_v4) {
                    let match_idx = entries.iter().position(|(_, user_hash, _)| {
                        user_hash.map(|h| h == peer_user_hash).unwrap_or(false)
                    }).or_else(|| (entries.len() == 1).then_some(0));
                    if let Some(idx) = match_idx {
                        let (file_hash, _user_hash, ts) = entries.remove(idx);
                        if entries.is_empty() {
                            cbs.remove(&peer_v4);
                        }
                        Some((file_hash, ts))
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            if let Some((file_hash, _ts)) = callback_file {
                info!("Recognized KAD callback connection from {peer_addr} for file {}", hex::encode(file_hash));
                let (dyn_reader, dyn_writer, emule_done): (Box<dyn tokio::io::AsyncRead + Unpin + Send>, Box<dyn tokio::io::AsyncWrite + Unpin + Send>, bool) = match (reader, writer) {
                    (StreamReader::Plain(r), StreamWriter::Plain(w)) => (Box::new(r), Box::new(w), false),
                    (StreamReader::Obfuscated(r), StreamWriter::Obfuscated(w)) => (Box::new(r), Box::new(w), true),
                    _ => {
                        warn!("Mismatched reader/writer types for KAD callback");
                        return Ok(());
                    }
                };
                let parts = KadCallbackParts {
                    peer_ip: peer_v4,
                    peer_port: peer_addr.port(),
                    peer_user_hash,
                    file_hash,
                    reader: dyn_reader,
                    writer: dyn_writer,
                    emule_info_done: emule_done,
                };
                let _ = self.kad_callback_tx.send(parts).await;
                return Ok(());
            }
        }

        // Check if this is a server callback connection (LowID source connecting
        // back after we sent OP_CALLBACKREQUEST). We match by the TCP port the
        // peer reports in its Hello packet against registered LowID sources for
        // our currently-connected server.
        if let std::net::IpAddr::V4(peer_v4) = peer_addr.ip() {
            let peer_hello_port = if hello_data.len() >= 23 {
                u16::from_le_bytes([hello_data[21], hello_data[22]])
            } else {
                0
            };
            if peer_hello_port > 0 {
                let server_callback_file = {
                    let server_addr = self.shared_server_addr.read().await;
                    if let Some(addr) = *server_addr {
                        if let std::net::IpAddr::V4(v4) = addr.ip() {
                            let sm = self.source_manager.read().await;
                            let matches = sm.find_lowid_files_by_port(
                                u32::from_le_bytes(v4.octets()),
                                addr.port(),
                                peer_hello_port,
                                Some(peer_user_hash),
                            );
                            matches.into_iter().next()
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                };
                if let Some(file_hash) = server_callback_file {
                    info!(
                        "Recognized server callback connection from {peer_addr} (port {peer_hello_port}) for file {}",
                        hex::encode(file_hash)
                    );
                    let (dyn_reader, dyn_writer, emule_done) = match (reader, writer) {
                        (StreamReader::Plain(r), StreamWriter::Plain(w)) => {
                            (
                                Box::new(r) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
                                Box::new(w) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
                                false,
                            )
                        }
                        (StreamReader::Obfuscated(r), StreamWriter::Obfuscated(w)) => {
                            (
                                Box::new(r) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
                                Box::new(w) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
                                true,
                            )
                        }
                        _ => {
                            warn!("Mismatched reader/writer types for server callback");
                            return Ok(());
                        }
                    };
                    let parts = KadCallbackParts {
                        peer_ip: peer_v4,
                        peer_port: peer_addr.port(),
                        peer_user_hash,
                        file_hash,
                        reader: dyn_reader,
                        writer: dyn_writer,
                        emule_info_done: emule_done,
                    };
                    let _ = self.kad_callback_tx.send(parts).await;
                    return Ok(());
                }
            }
        }

        // Now that buddy/KAD/server callback connections have been dispatched,
        // count this as a real upload request for abuse tracking.
        {
            let mut tracker = self.abuse_tracker.lock().await;
            if tracker.record_request(peer_addr.ip()) {
                anyhow::bail!("auto-banned for excessive requests");
            }
        }

        // Handle EmuleInfo exchange (or the peer may skip straight to file requests)
        let (proto2, opcode2, payload2) = read_packet_timeout(&mut reader).await?;
        let mut deferred_packet: Option<(u8, u8, Vec<u8>)> = None;
        let mut peer_ember_hash: Option<[u8; 16]> = hello_caps.ember_hash.or(obf_ember_hash);
        if proto2 == OP_EMULEPROT && opcode2 == OP_EMULEINFO {
            let incoming_caps = parse_emule_info(&payload2);
            merge_caps(&mut hello_caps, incoming_caps);
            peer_ember_hash = hello_caps.ember_hash;
            ul_client_software = client_software_from_caps(&hello_caps);
            if !hello_caps.peer_name.is_empty() {
                ul_peer_name = hello_caps.peer_name.clone();
            }
            let emule_payload = build_emule_info(self.udp_port, self.obfuscation_enabled, Some(&self.ember_hash));
            write_packet_async(&mut writer, OP_EMULEPROT, OP_EMULEINFOANSWER, &emule_payload).await?;
        } else {
            deferred_packet = Some((proto2, opcode2, payload2));
        }

        // Ember Peer Exchange: send our source list to Ember peers
        info!("Peer {peer_addr}: is_ember={}, mod_version='{}', ember_hash={}, client='{}'",
            hello_caps.is_ember, hello_caps.mod_version,
            peer_ember_hash.map(|h| hex::encode(h)).unwrap_or_else(|| "none".to_string()),
            ul_client_software);
        if hello_caps.is_ember {
            let epx_data = self.ember_payload.read().await.clone();
            if !epx_data.is_empty() {
                info!("Sending EPX to Ember peer {peer_addr} ({} bytes)", epx_data.len());
                let _ = write_packet_async(&mut writer, OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE, &*epx_data).await;
            } else {
                info!("EPX payload empty, skipping EPX send to {peer_addr}");
            }
            if let std::net::IpAddr::V4(v4) = peer_addr.ip() {
                if hello_caps.tcp_port > 0 && !v4.is_private() && !v4.is_loopback() && !v4.is_link_local() {
                    let _ = self.upload_event_tx.send(UploadEvent {
                        transfer_id: String::new(),
                        kind: UploadEventKind::EmberPeerDiscovered {
                            ip: v4,
                            tcp_port: hello_caps.tcp_port,
                        },
                    }).await;
                }
            }
        }

        let is_friend = if let Some(eh) = peer_ember_hash {
            self.friend_hashes.read().await.contains(&eh)
        } else {
            false
        };

        if let (true, Some(eh)) = (is_friend, peer_ember_hash) {
            let _ = self.upload_event_tx.send(UploadEvent {
                transfer_id: String::new(),
                kind: UploadEventKind::FriendSeen {
                    ember_hash: eh,
                    ip: peer_addr.ip(),
                    port: peer_addr.port(),
                },
            }).await;
        }

        if is_friend && hello_caps.is_ember {
            info!("Sending friend request to Ember peer {peer_addr}");
            let nick_bytes = self.nickname.as_bytes();
            let _ = write_packet_async(&mut writer, OP_EMULEPROT, OP_EMBER_FRIEND_REQ, nick_bytes).await;
        } else if is_friend {
            info!("Peer {peer_addr} is a friend but is_ember=false, skipping friend request");
        }

        let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        let is_ember_friend = is_friend && hello_caps.is_ember;
        let owns_ember_slot = if let (true, Some(eh)) = (is_ember_friend, peer_ember_hash) {
            let mut sessions = self.ember_sessions.write().await;
            if sessions.contains_key(&eh) {
                false
            } else {
                sessions.insert(eh, outbound_tx);
                true
            }
        } else {
            false
        };

        // Now handle file requests in a loop
        let mut current_file_hash: Option<[u8; 16]> = None;
        let mut uploaded: u64 = 0;
        let mut transfer_id: Option<String> = None;
        let mut total_size: u64 = 0;
        let mut slot_guard = UploadSlotGuard::new(self.active_count.clone(), self.slot_notify.clone());
        let mut session_start: Option<std::time::Instant> = None;
        let mut rate_tracker = SessionRateTracker::new();
        let mut pending_secident_challenge: Option<u32> = None;
        let queue_identity = QueueIdentity::from_peer(peer_user_hash, peer_addr);
        let mut queued_identity: Option<QueueIdentity> = None;
        let queue_join_time: std::time::Instant = std::time::Instant::now();
        let mut queue_wait_at_grant: u64 = 0;
        let mut last_rank_sent: Option<u16> = None;
        let mut last_rank_resend = std::time::Instant::now();
        // Deduplicate ShareInterest "request" per file hash on this TCP session.
        let mut recorded_share_request: Option<[u8; 16]> = None;
        let mut last_preempt_check: std::time::Instant = std::time::Instant::now();
        let mut epx_packets_received: u8 = 0;

        loop {
            // eMule: terminate upload sessions when the network is disconnected.
            if self.network_disconnected.load(std::sync::atomic::Ordering::Relaxed) {
                debug!("Terminating upload session with {peer_addr}: network disconnected");
                break;
            }

            let (proto, opcode, payload) = if let Some(pkt) = deferred_packet.take() {
                pkt
            } else {
                let wait_secs = if queued_identity.is_some() { 1 } else if owns_ember_slot { 90 } else { CLIENT_TIMEOUT_SECS };
                let timeout_dur = std::time::Duration::from_secs(wait_secs);
                let read_result = tokio::select! {
                    r = tokio::time::timeout(timeout_dur, read_packet_async_inner(&mut reader)) => r,
                    Some(outbound_data) = outbound_rx.recv() => {
                        if writer.write_all(&outbound_data).await.is_ok() {
                            let _ = writer.flush().await;
                        }
                        continue;
                    }
                };

                match read_result {
                    Ok(Ok(p)) => p,
                    Ok(Err(e)) => {
                        debug!("Client disconnected: {e}");
                        break;
                    }
                    Err(_) => {
                        if let Some(ref queued_key) = queued_identity {
                            let current_active = self
                                .active_count
                                .load(std::sync::atomic::Ordering::Relaxed);
                            let dynamic_slots = self.compute_dynamic_slot_count();

                            if current_active < dynamic_slots {
                                // Snapshot queue entries and release lock before acquiring RwLocks
                                let queue_snapshot: Vec<_> = {
                                    let queue = self.upload_queue.lock().await;
                                    queue.iter().enumerate().map(|(i, e)| {
                                        (i, e.identity.clone(), e.current_addr, e.join_time, e.file_hash, e.user_hash, e.emule_version, e.is_friend_slot)
                                    }).collect()
                                };
                                let cm = self.credit_manager.read().await;
                                let idx_snap = self.local_index.read().await;
                                let mut best_idx: Option<usize> = None;
                                let mut best_identity = None;
                                let mut best_score = f64::MIN;
                                for &(i, ref identity, current_addr, join_time, file_hash, ref user_hash, emule_version, is_friend_slot) in &queue_snapshot {
                                    if current_addr.is_none() {
                                        continue;
                                    }
                                    let score = score_queue_entry(
                                        &cm, &idx_snap, user_hash, file_hash,
                                        join_time.elapsed().as_secs(), current_addr,
                                        emule_version, is_friend_slot,
                                    );
                                    if score > best_score {
                                        best_score = score;
                                        best_idx = Some(i);
                                        best_identity = Some(identity.clone());
                                    }
                                }
                                drop(idx_snap);
                                drop(cm);

                                if let Some(best_idx) = best_idx {
                                    if best_identity.as_ref() == Some(queued_key) {
                                        let mut queue = self.upload_queue.lock().await;
                                        if best_idx < queue.len() && queue[best_idx].identity == *queued_key {
                                            queue.remove(best_idx);
                                        }
                                        drop(queue);

                                        write_packet_async(
                                            &mut writer,
                                            OP_EDONKEYHEADER,
                                            OP_ACCEPTUPLOADREQ,
                                            &[],
                                        )
                                        .await?;

                                        if let Some(h) = current_file_hash {
                                            self.record_share_accepted(&h).await;
                                        }

                                        slot_guard.activate();
                                        queued_identity = None;
                                        uploaded = 0;
                                        queue_wait_at_grant = queue_join_time.elapsed().as_secs();
                                        session_start = Some(std::time::Instant::now());
                                        rate_tracker = SessionRateTracker::new();

                                        if let Some(hash) = current_file_hash {
                                            let tid = uuid::Uuid::new_v4().to_string();
                                            transfer_id = Some(tid.clone());

                                            let hash_hex = hex::encode(hash);
                                            let file_name = {
                                                let index = self.local_index.read().await;
                                                index.get_by_hash(&hash_hex).map(|f| f.name.clone())
                                            };

                                            let _ = self
                                                .upload_event_tx
                                                .send(UploadEvent {
                                                    transfer_id: tid,
                                                    kind: UploadEventKind::Started {
                                                        file_name: file_name.unwrap_or_default(),
                                                        file_hash: hash_hex,
                                                        total_size,
                                                        peer_addr: peer_addr.to_string(),
                                                        peer_name: ul_peer_name.clone(),
                                                        client_software: ul_client_software.clone(),
                                                        country_code: ul_country_code.clone(),
                                                    },
                                                })
                                                .await;
                                        }
                                        continue;
                                    }
                                }
                            }

                            // Re-send OP_QUEUERANKING if rank changed, rate-limited to once per 5 min
                            if last_rank_resend.elapsed().as_secs() >= 300 {
                                last_rank_resend = std::time::Instant::now();
                                let cm = self.credit_manager.read().await;
                                let idx_snap = self.local_index.read().await;
                                let queue = self.upload_queue.lock().await;
                                let my_score = score_queue_entry(
                                    &cm, &idx_snap, &peer_user_hash,
                                    current_file_hash.unwrap_or([0u8; 16]),
                                    queue_join_time.elapsed().as_secs(),
                                    Some(peer_addr), hello_caps.emule_version_min,
                                    is_friend,
                                );
                                let rank = compute_queue_rank(
                                    &cm, &idx_snap, &queue,
                                    &queue_identity, my_score, queue_join_time,
                                );
                                drop(queue);
                                drop(idx_snap);
                                drop(cm);
                                if last_rank_sent != Some(rank) {
                                    last_rank_sent = Some(rank);
                                    let mut qr_payload = Vec::with_capacity(12);
                                    qr_payload.extend_from_slice(&rank.to_le_bytes());
                                    qr_payload.resize(12, 0);
                                    let _ = write_packet_async(
                                        &mut writer, OP_EMULEPROT, OP_QUEUERANKING, &qr_payload,
                                    ).await;
                                }
                            }
                            continue;
                        }
                        if owns_ember_slot {
                            if write_packet_async(&mut writer, OP_EMULEPROT, OP_EMBER_KEEPALIVE, &[]).await.is_err() {
                                debug!("Friend keepalive failed, closing session");
                                break;
                            }
                            continue;
                        }
                        debug!("Client timed out");
                        break;
                    }
                }
            };

            match (proto, opcode) {
                (OP_EMULEPROT, OP_PUBLICKEY) if payload.len() >= 2 => {
                    let key_len = payload[0] as usize;
                    if key_len > 0 && payload.len() >= 1 + key_len {
                        let mut cm = self.credit_manager.write().await;
                        cm.set_public_key(peer_user_hash, payload[1..1 + key_len].to_vec());
                        cm.set_ident_state(peer_user_hash, super::credits::IdentState::Needed);
                        drop(cm);

                        pending_secident_challenge = super::transfer::maybe_send_secident_challenge(
                            &mut writer,
                            Some(&self.credit_manager),
                            peer_user_hash,
                            peer_addr,
                            peer_secure_ident_level,
                        ).await?;
                        debug!("Received public key and sent SecIdent challenge to {peer_addr}");
                    }
                }

                (OP_EMULEPROT, OP_SECIDENTSTATE) if payload.len() >= 5 => {
                    super::transfer::respond_to_secident_challenge(
                        &mut writer,
                        Some(&self.credit_manager),
                        payload[0],
                        u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]),
                        peer_addr,
                        peer_user_hash,
                        peer_secure_ident_level,
                        0u32,
                    ).await?;
                    debug!("Responded to SecIdent challenge from {peer_addr}");
                }

                (OP_EMULEPROT, OP_SIGNATURE) if payload.len() >= 2 => {
                    let sig_len = payload[0] as usize;
                    if sig_len > 0 && payload.len() >= 1 + sig_len {
                        if let Some(challenge) = pending_secident_challenge.take() {
                            let sig_bytes = &payload[1..1 + sig_len];
                            let peer_ip_u32 = match peer_addr.ip() {
                                std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
                                _ => 0,
                            };
                            let mode = if payload.len() == 1 + sig_len {
                                None
                            } else if payload.len() == 2 + sig_len {
                                Some(payload[1 + sig_len])
                            } else {
                                continue;
                            };
                            let cm = self.credit_manager.read().await;
                            let verified = cm.verify_signature(
                                &peer_user_hash,
                                challenge,
                                mode,
                                peer_ip_u32,
                                0,
                                sig_bytes,
                            );
                            drop(cm);
                            let mut cm = self.credit_manager.write().await;
                            if verified {
                                cm.set_ident_state(peer_user_hash, super::credits::IdentState::Verified);
                                cm.check_identity_ip(peer_user_hash, peer_ip_u32);
                                debug!("SecIdent verified for {peer_addr}");
                            } else {
                                cm.set_ident_state(peer_user_hash, super::credits::IdentState::Failed);
                                debug!("SecIdent verification failed for {peer_addr}");
                            }
                        }
                    }
                }

                (OP_EDONKEYHEADER, OP_SETREQFILEID) => {
                    if payload.len() >= 16 {
                        let mut hash = [0u8; 16];
                        hash.copy_from_slice(&payload[..16]);
                        current_file_hash = Some(hash);

                        if let Some(file) = self.resolve_upload_file(&hash).await {
                            self.record_share_request_once(&hash, &mut recorded_share_request)
                                .await;
                            let ed2k_part_count = ed2k_wire_part_count(file.size) as u16;
                            let bitmap_bytes = ((ed2k_part_count as usize) + 7) / 8;
                            let mut status_payload = Vec::with_capacity(18 + bitmap_bytes);
                            status_payload.extend_from_slice(&hash);
                            status_payload.extend_from_slice(
                                &(if file.is_partial { ed2k_part_count } else { 0u16 }).to_le_bytes()
                            );

                            // Check if this is a partial download (.part file)
                            // and build an accurate bitmap from PartTracker
                            if file.is_partial && file.size > 0 {
                                let tracker = super::part_tracker::PartTracker::new(file.size, &file.path);
                                for byte_idx in 0..bitmap_bytes {
                                    let mut byte = 0u8;
                                    for bit in 0..8 {
                                        let part_idx = byte_idx * 8 + bit;
                                        if part_idx < ed2k_part_count as usize && tracker.is_part_complete(part_idx) {
                                            byte |= 1 << bit;
                                        }
                                    }
                                    status_payload.push(byte);
                                }
                            } else if file.is_partial {
                                for i in 0..bitmap_bytes {
                                    let remaining_bits = ed2k_part_count as usize - i * 8;
                                    if remaining_bits >= 8 {
                                        status_payload.push(0xFF);
                                    } else {
                                        status_payload.push((1u8 << remaining_bits) - 1);
                                    }
                                }
                            }
                            write_packet_async(
                                &mut writer,
                                OP_EDONKEYHEADER,
                                OP_FILESTATUS,
                                &status_payload,
                            )
                            .await?;
                            let _ = self.send_comment_info(&mut writer, &hash).await;

                            total_size = file.size;

                            // Register this peer as potential A4AF source for our pending downloads
                            let download_hashes = self.pending_download_hashes.read().await;
                            if !download_hashes.is_empty() {
                                let mut a4af = self.a4af_manager.write().await;
                                for &dl_hash in download_hashes.iter() {
                                    if dl_hash != hash {
                                        a4af.add_a4af_source(dl_hash, peer_addr, hash);
                                    }
                                }
                            }
                        } else {
                            write_packet_async(
                                &mut writer,
                                OP_EDONKEYHEADER,
                                OP_FILEREQANSNOFIL,
                                &hash,
                            )
                            .await?;
                            {
                                let mut tracker = self.abuse_tracker.lock().await;
                                tracker.record_file_not_found(peer_addr.ip());
                            }
                            current_file_hash = None;
                            total_size = 0;
                        }
                    }
                }

                (OP_EDONKEYHEADER, OP_REQUESTFILENAME) => {
                    if current_file_hash.is_none() && payload.len() >= 16 {
                        let mut hash = [0u8; 16];
                        hash.copy_from_slice(&payload[..16]);
                        current_file_hash = Some(hash);
                    }
                    if let Some(hash) = current_file_hash {
                        if let Some(file) = self.resolve_upload_file(&hash).await {
                            let name_bytes = file.name.as_bytes();
                            let mut resp = Vec::with_capacity(16 + 2 + name_bytes.len());
                            resp.extend_from_slice(&hash);
                            resp.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
                            resp.extend_from_slice(name_bytes);
                            write_packet_async(
                                &mut writer,
                                OP_EDONKEYHEADER,
                                OP_REQFILENAMEANSWER,
                                &resp,
                            )
                            .await?;
                        } else {
                            write_packet_async(
                                &mut writer,
                                OP_EDONKEYHEADER,
                                OP_FILEREQANSNOFIL,
                                &hash,
                            )
                            .await?;
                            {
                                let mut tracker = self.abuse_tracker.lock().await;
                                tracker.record_file_not_found(peer_addr.ip());
                            }
                            current_file_hash = None;
                            total_size = 0;
                        }
                    }
                }

                (OP_EDONKEYHEADER, OP_STARTUPLOADREQ) => {
                    if current_file_hash.is_none() && payload.len() >= 16 {
                        let mut hash = [0u8; 16];
                        hash.copy_from_slice(&payload[..16]);
                        current_file_hash = Some(hash);
                    }

                    if let Some(h) = current_file_hash {
                        if self.resolve_upload_file(&h).await.is_some() {
                            self.record_share_request_once(&h, &mut recorded_share_request)
                                .await;
                        }
                    }

                    // eMule AddRequestCount: check per-file request frequency before admitting
                    if let Some(h) = current_file_hash {
                        if let std::net::IpAddr::V4(peer_v4) = peer_addr.ip() {
                            let should_ban = {
                                let mut tracker = self.file_request_tracker.lock().await;
                                tracker.cleanup_stale();
                                tracker.record_request(peer_v4, h)
                            };
                            if should_ban {
                                warn!("Banning {} for excessive file request frequency (AddRequestCount)", peer_addr);
                                if let Ok(mut banned) = self.banned_ips.write() {
                                    banned.insert(peer_v4);
                                }
                                write_packet_async(&mut writer, OP_EMULEPROT, OP_QUEUEFULL, &[]).await?;
                                break;
                            }
                        }
                    }

                    let current_active = self
                        .active_count
                        .load(std::sync::atomic::Ordering::Relaxed);

                    let dynamic_slots = self.compute_dynamic_slot_count();
                    let should_accept = if current_active >= dynamic_slots {
                        false
                    } else {
                        // Snapshot queue, purging stale entries first, then release lock
                        let (queue_empty, queue_snapshot) = {
                            let mut queue = self.upload_queue.lock().await;
                            queue.retain(|e| e.join_time.elapsed().as_secs() < MAX_PURGEQUEUETIME_SECS);
                            let empty = queue.is_empty();
                            let snap: Vec<_> = queue.iter().enumerate().map(|(i, e)| {
                                (i, e.identity.clone(), e.current_addr, e.join_time, e.file_hash,
                                 e.user_hash, e.emule_version, e.is_friend_slot, e.add_next_connect)
                            }).collect();
                            (empty, snap)
                        };
                        if queue_empty {
                            true
                        } else {
                            let cm = self.credit_manager.read().await;
                            let idx_snap = self.local_index.read().await;
                            let mut best_idx: Option<usize> = None;
                            let mut best_score = f64::MIN;
                            let mut best_low_idx: Option<usize> = None;
                            let mut best_low_score = f64::MIN;
                            for &(i, ref _identity, current_addr, join_time, file_hash, ref user_hash, emule_version, is_friend_slot, add_next_connect) in &queue_snapshot {
                                let score = score_queue_entry(
                                    &cm, &idx_snap, user_hash, file_hash,
                                    join_time.elapsed().as_secs(), current_addr,
                                    emule_version, is_friend_slot,
                                );
                                if current_addr.is_some() {
                                    if score > best_score {
                                        best_score = score;
                                        best_idx = Some(i);
                                    }
                                } else if !add_next_connect {
                                    if score > best_low_score {
                                        best_low_score = score;
                                        best_low_idx = Some(i);
                                    }
                                }
                            }
                            // H4: If disconnected Low-ID would have won, flag it
                            if let Some(li) = best_low_idx {
                                if best_low_score > best_score {
                                    let mut queue = self.upload_queue.lock().await;
                                    if li < queue.len() {
                                        queue[li].add_next_connect = true;
                                    }
                                }
                            }
                            drop(cm);
                            if let Some(best_idx) = best_idx {
                                let mut queue = self.upload_queue.lock().await;
                                if best_idx < queue.len() && queue[best_idx].identity == queue_identity {
                                    queue.remove(best_idx);
                                    true
                                } else {
                                    false
                                }
                            } else {
                                true
                            }
                        }
                    };

                    if !should_accept {
                        let mut queue = self.upload_queue.lock().await;
                        let rank = if let Some(pos) =
                            queue.iter().position(|e| e.identity == queue_identity)
                        {
                            queue[pos].current_addr = Some(peer_addr);
                            queue[pos].user_hash = peer_user_hash;
                            queue[pos].file_hash = current_file_hash.unwrap_or([0u8; 16]);
                            let cm = self.credit_manager.read().await;
                            let idx_snap = self.local_index.read().await;
                            let my_score = score_queue_entry(
                                &cm, &idx_snap, &peer_user_hash,
                                current_file_hash.unwrap_or([0u8; 16]),
                                queue[pos].join_time.elapsed().as_secs(),
                                Some(peer_addr), hello_caps.emule_version_min,
                                is_friend,
                            );
                            let rank_val = compute_queue_rank(
                                &cm, &idx_snap, &queue,
                                &queue_identity, my_score, queue[pos].join_time,
                            );
                            drop(cm);
                            drop(idx_snap);
                            rank_val
                        } else if queue.len() >= HARD_UPLOAD_QUEUE_SIZE {
                            debug!("Upload queue at hard limit ({HARD_UPLOAD_QUEUE_SIZE}), sending OP_QUEUEFULL to {peer_addr}");
                            drop(queue);
                            write_packet_async(&mut writer, OP_EMULEPROT, OP_QUEUEFULL, &[]).await?;
                            break;
                        } else if queue.len() >= MAX_UPLOAD_QUEUE_SIZE {
                            // m7: Soft-to-hard zone – only admit if above-average score
                            let cm = self.credit_manager.read().await;
                            let idx_snap = self.local_index.read().await;
                            let new_fh = current_file_hash.unwrap_or([0u8; 16]);
                            let new_score = score_queue_entry(
                                &cm, &idx_snap, &peer_user_hash, new_fh,
                                0, Some(peer_addr), hello_caps.emule_version_min,
                                is_friend,
                            );
                            let avg_score = if queue.is_empty() { 0.0 } else {
                                let total: f64 = queue.iter().map(|e| {
                                    score_queue_entry(
                                        &cm, &idx_snap, &e.user_hash, e.file_hash,
                                        e.join_time.elapsed().as_secs(), e.current_addr,
                                        e.emule_version, e.is_friend_slot,
                                    )
                                }).sum();
                                total / queue.len() as f64
                            };
                            if new_score >= avg_score {
                                let join_time = std::time::Instant::now();
                                queue.push(QueueEntry {
                                    identity: queue_identity.clone(),
                                    current_addr: Some(peer_addr),
                                    user_hash: peer_user_hash,
                                    file_hash: new_fh,
                                    join_time,
                                    add_next_connect: false,
                                    emule_version: hello_caps.emule_version_min,
                                    is_friend_slot: is_friend,
                                });
                                let rank_val = compute_queue_rank(
                                    &cm, &idx_snap, &queue,
                                    &queue_identity, new_score, join_time,
                                );
                                drop(cm);
                                drop(idx_snap);
                                rank_val
                            } else {
                                debug!("Upload queue in soft-hard zone, peer score {new_score:.1} below avg {avg_score:.1}, rejecting {peer_addr}");
                                drop(cm);
                                drop(idx_snap);
                                drop(queue);
                                write_packet_async(&mut writer, OP_EMULEPROT, OP_QUEUEFULL, &[]).await?;
                                break;
                            }
                        } else {
                            let cm = self.credit_manager.read().await;
                            let idx_snap = self.local_index.read().await;
                            let new_fh = current_file_hash.unwrap_or([0u8; 16]);
                            let join_time = std::time::Instant::now();
                            queue.push(QueueEntry {
                                identity: queue_identity.clone(),
                                current_addr: Some(peer_addr),
                                user_hash: peer_user_hash,
                                file_hash: new_fh,
                                join_time,
                                add_next_connect: false,
                                emule_version: hello_caps.emule_version_min,
                                is_friend_slot: is_friend,
                            });
                            let my_score = score_queue_entry(
                                &cm, &idx_snap, &peer_user_hash, new_fh,
                                0, Some(peer_addr), hello_caps.emule_version_min,
                                is_friend,
                            );
                            let rank_val = compute_queue_rank(
                                &cm, &idx_snap, &queue,
                                &queue_identity, my_score, join_time,
                            );
                            drop(cm);
                            drop(idx_snap);
                            rank_val
                        };
                        drop(queue);
                        // eMule OP_QUEUERANKING (UploadClient.cpp:633): 12 bytes = rank(u16) + 10 zeros
                        let mut qr_payload = Vec::with_capacity(12);
                        qr_payload.extend_from_slice(&rank.to_le_bytes());
                        qr_payload.resize(12, 0);
                        write_packet_async(
                            &mut writer,
                            OP_EMULEPROT,
                            OP_QUEUERANKING,
                            &qr_payload,
                        )
                        .await?;
                        last_rank_sent = Some(rank);
                        queued_identity = Some(queue_identity.clone());
                        continue;
                    }

                    // Accept the upload (guard against duplicate OP_STARTUPLOADREQ)
                    write_packet_async(
                        &mut writer,
                        OP_EDONKEYHEADER,
                        OP_ACCEPTUPLOADREQ,
                        &[],
                    )
                    .await?;

                    if let Some(h) = current_file_hash {
                        self.record_share_accepted(&h).await;
                    }

                    slot_guard.activate();
                    queued_identity = None;
                    uploaded = 0;
                    queue_wait_at_grant = queue_join_time.elapsed().as_secs();
                    session_start = Some(std::time::Instant::now());
                    rate_tracker = SessionRateTracker::new();

                    if let Some(hash) = current_file_hash {
                        let tid = uuid::Uuid::new_v4().to_string();
                        transfer_id = Some(tid.clone());

                        let hash_hex = hex::encode(hash);
                        let file_name = {
                            let index = self.local_index.read().await;
                            index.get_by_hash(&hash_hex).map(|f| f.name.clone())
                        };

                        let _ = self.upload_event_tx.send(UploadEvent {
                            transfer_id: tid,
                            kind: UploadEventKind::Started {
                                file_name: file_name.unwrap_or_default(),
                                file_hash: hash_hex,
                                total_size,
                                peer_addr: peer_addr.to_string(),
                                peer_name: ul_peer_name.clone(),
                                client_software: ul_client_software.clone(),
                                country_code: ul_country_code.clone(),
                            },
                        }).await;
                    }
                }

                (OP_EMULEPROT, OP_REQUESTPARTS_I64) | (OP_EDONKEYHEADER, OP_REQUESTPARTS) => {
                    let hash = if let Some(h) = current_file_hash {
                        h
                    } else {
                        continue;
                    };
                    if !slot_guard.is_active() {
                        write_packet_async(
                            &mut writer,
                            OP_EDONKEYHEADER,
                            OP_OUTOFPARTREQS,
                            &[],
                        )
                        .await?;
                        continue;
                    }

                    let offsets = if opcode == OP_REQUESTPARTS_I64 {
                        parse_request_parts_i64(&payload)?
                    } else {
                        parse_request_parts_32(&payload)?
                    };

                    let offsets: Vec<(u64, u64)> = offsets
                        .into_iter()
                        .filter(|&(start, end)| {
                            if end > total_size {
                                warn!("Peer requested range past file end: {end} > {total_size}");
                                false
                            } else if start >= end {
                                false
                            } else {
                                true
                            }
                        })
                        .collect();

                    let resolved = match self.resolve_upload_file(&hash).await {
                        Some(file) => file,
                        None => {
                            write_packet_async(
                                &mut writer,
                                OP_EDONKEYHEADER,
                                OP_FILEREQANSNOFIL,
                                &hash,
                            )
                            .await?;
                            continue;
                        }
                    };
                    let file_path = resolved.path.clone();

                    let part_tracker = if file_path.extension().map(|e| e == "part").unwrap_or(false)
                        && total_size > 0
                    {
                        Some(super::part_tracker::PartTracker::new(total_size, &file_path))
                    } else {
                        None
                    };

                    for (start, end) in offsets {
                        if start >= end {
                            continue;
                        }

                        if let Some(tracker) = part_tracker.as_ref() {
                            let overlaps_gap = tracker
                                .gap_list()
                                .iter()
                                .any(|&(gs, ge)| gs < end && ge > start);
                            if overlaps_gap {
                                warn!(
                                    "Rejected upload of incomplete part-file range {}-{} for {}",
                                    start,
                                    end,
                                    file_path.display()
                                );
                                continue;
                            }
                        }

                        // Check if the upload was cancelled by the user
                        if let Some(tid) = &transfer_id {
                            let mgr = self.transfer_manager.read().await;
                            let cancelled = !mgr.active.contains_key(tid);
                            drop(mgr);
                            if cancelled {
                                info!("Upload {tid} cancelled by user, aborting");
                                return Ok(());
                            }
                        }

                        let len = ((end - start) as usize).min(PARTSIZE as usize);

                        let read_result = {
                            let fp = file_path.clone();
                            tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
                                let mut f = std::fs::File::open(&fp)?;
                                f.seek(SeekFrom::Start(start))?;
                                let mut buf = vec![0u8; len];
                                f.read_exact(&mut buf)?;
                                Ok(buf)
                            })
                            .await?
                        };

                        let data = match read_result {
                            Ok(d) => d,
                            Err(e) => {
                                warn!("Failed to read file chunk: {e}");
                                break;
                            }
                        };

                        // Skip compression for video files when configured (eMule: dontcompressavi)
                        let is_video_ext = file_path.extension()
                            .and_then(|e| e.to_str())
                            .map(|e| {
                                let e = e.to_lowercase();
                                matches!(e.as_str(), "avi" | "mp4" | "mkv" | "wmv" | "mpg" |
                                    "mpeg" | "mov" | "flv" | "webm" | "m4v" | "divx" | "ts" | "vob")
                            })
                            .unwrap_or(false);
                        let use_compression = peer_compression_ver > 0 && data.len() > 1024 && !(is_video_ext && self.skip_compress_video);
                        if use_compression {
                            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                            if encoder.write_all(&data).is_ok() {
                                if let Ok(compressed) = encoder.finish() {
                                    // Only use compression if it actually saves space
                                    if compressed.len() < data.len() {
                                        let use_i64 = end > u32::MAX as u64;
                                        let packed_size = compressed.len() as u32;
                                        let mut part_payload = Vec::with_capacity(
                                            if use_i64 { 28 } else { 24 } + compressed.len(),
                                        );
                                        part_payload.extend_from_slice(&hash);
                                        if use_i64 {
                                            part_payload.extend_from_slice(&start.to_le_bytes());
                                        } else {
                                            part_payload.extend_from_slice(&(start as u32).to_le_bytes());
                                        }
                                        part_payload.extend_from_slice(&packed_size.to_le_bytes());
                                        part_payload.extend_from_slice(&compressed);

                                        self.acquire_upload_bandwidth(compressed.len() as u64).await;
                                        write_packet_async(
                                            &mut writer,
                                            OP_EMULEPROT,
                                            if use_i64 { OP_COMPRESSEDPART_I64 } else { OP_COMPRESSEDPART },
                                            &part_payload,
                                        )
                                        .await?;

                                        uploaded += data.len() as u64;
                                        rate_tracker.record_send(data.len() as u64);
                                        self.slot_rates.lock().unwrap_or_else(|e| e.into_inner()).insert(peer_addr, rate_tracker.smoothed_rate());
                                        {
                                            let mut cm = self.credit_manager.write().await;
                                            cm.add_uploaded(peer_user_hash, data.len() as u64);
                                        }

                                        if let Some(tid) = &transfer_id {
                                            let _ = self.upload_event_tx.send(UploadEvent {
                                                transfer_id: tid.clone(),
                                                kind: UploadEventKind::Progress {
                                                    uploaded,
                                                    total: total_size,
                                                },
                                            }).await;
                                        }
                                        continue;
                                    }
                                }
                            }
                        }

                        let use_i64 = end > u32::MAX as u64;
                        let mut part_payload =
                            Vec::with_capacity(if use_i64 { 32 } else { 24 } + data.len());
                        part_payload.extend_from_slice(&hash);
                        if use_i64 {
                            part_payload.extend_from_slice(&start.to_le_bytes());
                            part_payload.extend_from_slice(&end.to_le_bytes());
                        } else {
                            part_payload.extend_from_slice(&(start as u32).to_le_bytes());
                            part_payload.extend_from_slice(&(end as u32).to_le_bytes());
                        }
                        part_payload.extend_from_slice(&data);

                        self.acquire_upload_bandwidth(data.len() as u64).await;
                        write_packet_async(
                            &mut writer,
                            if use_i64 { OP_EMULEPROT } else { OP_EDONKEYHEADER },
                            if use_i64 { OP_SENDINGPART_I64 } else { OP_SENDINGPART },
                            &part_payload,
                        )
                        .await?;

                        uploaded += data.len() as u64;
                        rate_tracker.record_send(data.len() as u64);
                        self.slot_rates.lock().unwrap_or_else(|e| e.into_inner()).insert(peer_addr, rate_tracker.smoothed_rate());
                        {
                            let mut cm = self.credit_manager.write().await;
                            cm.add_uploaded(peer_user_hash, data.len() as u64);
                        }

                        if let Some(tid) = &transfer_id {
                            let _ = self.upload_event_tx.send(UploadEvent {
                                transfer_id: tid.clone(),
                                kind: UploadEventKind::Progress {
                                    uploaded,
                                    total: total_size,
                                },
                            }).await;
                        }
                    }

                    // Enforce eMule session limits + score-based preemption.
                    // eMule CheckForTimeOver: don't rotate if nobody is waiting.
                    let queue_has_waiters = {
                        let q = self.upload_queue.lock().await;
                        !q.is_empty()
                    };
                    let session_expired = queue_has_waiters
                        && (uploaded >= SESSIONMAXTRANS
                            || session_start
                                .map(|t| t.elapsed().as_secs() >= SESSIONMAXTIME_SECS)
                                .unwrap_or(false));

                    // eMule-style score-based preemption: every ~10 seconds, check
                    // if a queued peer has a significantly higher score than us.
                    let preempted = if !session_expired
                        && slot_guard.is_active()
                        && last_preempt_check.elapsed().as_secs() >= 10
                    {
                        last_preempt_check = std::time::Instant::now();
                        let queue = self.upload_queue.lock().await;
                        if queue.is_empty() {
                            false
                        } else {
                            let cm = self.credit_manager.read().await;
                            let idx_snap = self.local_index.read().await;
                            let my_fh = current_file_hash.unwrap_or([0u8; 16]);
                            let my_score = score_queue_entry(
                                &cm, &idx_snap, &peer_user_hash, my_fh,
                                queue_wait_at_grant, Some(peer_addr),
                                hello_caps.emule_version_min, is_friend,
                            );

                            let mut best_queued_score = f64::MIN;
                            for entry in queue.iter() {
                                if entry.current_addr.is_none() {
                                    continue;
                                }
                                let score = score_queue_entry(
                                    &cm, &idx_snap, &entry.user_hash, entry.file_hash,
                                    entry.join_time.elapsed().as_secs(), entry.current_addr,
                                    entry.emule_version, entry.is_friend_slot,
                                );
                                if score > best_queued_score {
                                    best_queued_score = score;
                                }
                            }
                            best_queued_score > my_score * 2.0
                        }
                    } else {
                        false
                    };

                    let session_expired = session_expired || preempted;

                    if session_expired && slot_guard.is_active() {
                        let reason = if preempted { "score preempted" } else { "session limit" };
                        debug!(
                            "Upload {reason} for {peer_addr} ({}B / {}s, ~{} B/s), sending OutOfPartReqs",
                            uploaded,
                            session_start.map(|t| t.elapsed().as_secs()).unwrap_or(0),
                            rate_tracker.smoothed_rate(),
                        );
                        write_packet_async(
                            &mut writer,
                            OP_EDONKEYHEADER,
                            OP_OUTOFPARTREQS,
                            &[],
                        )
                        .await?;

                        if let Some(tid) = &transfer_id {
                            let _ = self.upload_event_tx.send(UploadEvent {
                                transfer_id: tid.clone(),
                                kind: UploadEventKind::Completed,
                            }).await;
                        }
                        transfer_id = None;

                        slot_guard.deactivate();
                        session_start = None;
                        self.slot_rates.lock().unwrap_or_else(|e| e.into_inner()).remove(&peer_addr);
                        rate_tracker = SessionRateTracker::new();

                        // Re-add to upload queue so they can get another turn
                        {
                            let mut queue = self.upload_queue.lock().await;
                            if let Some(entry) =
                                queue.iter_mut().find(|e| e.identity == queue_identity)
                            {
                                entry.current_addr = Some(peer_addr);
                                entry.user_hash = peer_user_hash;
                                entry.file_hash = current_file_hash.unwrap_or([0u8; 16]);
                            } else if queue.len() < MAX_UPLOAD_QUEUE_SIZE {
                                queue.push(QueueEntry {
                                    identity: queue_identity.clone(),
                                    current_addr: Some(peer_addr),
                                    user_hash: peer_user_hash,
                                    file_hash: current_file_hash.unwrap_or([0u8; 16]),
                                    join_time: queue_join_time,
                                    add_next_connect: false,
                                    emule_version: hello_caps.emule_version_min,
                                    is_friend_slot: is_friend,
                                });
                            } else if queue.len() < HARD_UPLOAD_QUEUE_SIZE {
                                // m7: Soft-to-hard zone – re-admit after session with score check
                                let cm = self.credit_manager.read().await;
                                let idx_snap = self.local_index.read().await;
                                let new_fh = current_file_hash.unwrap_or([0u8; 16]);
                                let new_score = score_queue_entry(
                                    &cm, &idx_snap, &peer_user_hash, new_fh,
                                    0, Some(peer_addr), hello_caps.emule_version_min,
                                    is_friend,
                                );
                                let avg_score = if queue.is_empty() { 0.0 } else {
                                    let total: f64 = queue.iter().map(|e| {
                                        score_queue_entry(
                                            &cm, &idx_snap, &e.user_hash, e.file_hash,
                                            e.join_time.elapsed().as_secs(), e.current_addr,
                                            e.emule_version, e.is_friend_slot,
                                        )
                                    }).sum();
                                    total / queue.len() as f64
                                };
                                drop(cm);
                                drop(idx_snap);
                                if new_score >= avg_score {
                                    queue.push(QueueEntry {
                                        identity: queue_identity.clone(),
                                        current_addr: Some(peer_addr),
                                        user_hash: peer_user_hash,
                                        file_hash: new_fh,
                                        join_time: queue_join_time,
                                        add_next_connect: false,
                                        emule_version: hello_caps.emule_version_min,
                                        is_friend_slot: is_friend,
                                    });
                                }
                            }
                        }
                    }
                }

                (OP_EDONKEYHEADER, OP_CANCELTRANSFER) | (OP_EDONKEYHEADER, OP_END_OF_DOWNLOAD) => {
                    debug!("Peer {peer_addr} cancelled/ended transfer");
                    if let Some(tid) = &transfer_id {
                        let _ = self.upload_event_tx.send(UploadEvent {
                            transfer_id: tid.clone(),
                            kind: UploadEventKind::Completed,
                        }).await;
                    }
                    slot_guard.deactivate();
                    transfer_id = None;
                    uploaded = 0;
                    session_start = None;
                    self.slot_rates.lock().unwrap_or_else(|e| e.into_inner()).remove(&peer_addr);
                    rate_tracker = SessionRateTracker::new();
                    current_file_hash = None;
                    total_size = 0;
                }

                (OP_EDONKEYHEADER, OP_HASHSETREQ) if payload.len() >= 16 => {
                    let mut req_hash = [0u8; 16];
                    req_hash.copy_from_slice(&payload[..16]);
                    if let Some(file) = self.resolve_upload_file(&req_hash).await {
                        let path = file.path.clone();
                        let file_size = file.size;
                        let is_partial = file.is_partial;
                        let hashset_result = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Vec<[u8; 16]>>> {
                            if is_partial && file_size > 0 {
                                let tracker = super::part_tracker::PartTracker::new(file_size, &path);
                                let cached = tracker.part_hashes();
                                if !cached.is_empty() {
                                    tracing::debug!("Using {} cached part hashes from tracker", cached.len());
                                    return Ok(Some(cached.to_vec()));
                                }
                                return Ok(None);
                            }
                            Ok(Some(compute_part_hashes(&path)?))
                        })
                        .await?;

                        match hashset_result {
                            Ok(Some(hashes)) => {
                                let mut resp = Vec::with_capacity(16 + 2 + hashes.len() * 16);
                                resp.extend_from_slice(&req_hash);
                                resp.extend_from_slice(&(hashes.len() as u16).to_le_bytes());
                                for h in &hashes {
                                    resp.extend_from_slice(h);
                                }
                                write_packet_async(
                                    &mut writer,
                                    OP_EDONKEYHEADER,
                                    OP_HASHSETANSWER,
                                    &resp,
                                )
                                .await?;
                            }
                            Ok(None) => {
                                debug!("Skipping legacy hashset response for partial file without cached hashes");
                            }
                            Err(e) => {
                                warn!("Failed to compute hashset: {e}");
                            }
                        }
                    }
                }

                (OP_EMULEPROT, OP_HASHSETREQUEST2) => {
                    let mut cursor = std::io::Cursor::new(&payload[..]);
                    if let Ok(file_ident) = FileIdentifier::read_identifier(&mut cursor) {
                        let options = byteorder::ReadBytesExt::read_u8(&mut cursor).unwrap_or(0);
                        if let Some(file) = self.resolve_upload_file(&file_ident.md4_hash).await {
                            let local_ident = FileIdentifier {
                                md4_hash: file_ident.md4_hash,
                                file_size: Some(file.size),
                                aich_hash: parse_aich_root_hash(&file.aich_hash_hex),
                            };
                            if !local_ident.compare_relaxed(&file_ident) {
                                write_packet_async(
                                    &mut writer,
                                    OP_EDONKEYHEADER,
                                    OP_FILEREQANSNOFIL,
                                    &file_ident.md4_hash,
                                )
                                .await?;
                                continue;
                            }
                            let request_md4 = (options & 0x01) != 0;
                            let request_aich = (options & 0x02) != 0;
                            if request_md4 || request_aich {
                                let path = file.path.clone();
                                let aich_root = local_ident.aich_hash;
                                let is_partial = file.is_partial;
                                let (md4_hashes, aich_hashes) = tokio::task::spawn_blocking(move || {
                                    let md4 = if request_md4 {
                                        if is_partial {
                                            let tracker = super::part_tracker::PartTracker::new(file.size, &path);
                                            let cached = tracker.part_hashes();
                                            if cached.is_empty() {
                                                None
                                            } else {
                                                Some(cached.to_vec())
                                            }
                                        } else {
                                            Some(compute_part_hashes(&path)?)
                                        }
                                    } else {
                                        None
                                    };
                                    let aich = if request_aich {
                                        if is_partial {
                                            None
                                        } else {
                                            Some(compute_aich_part_hashes(&path)?)
                                        }
                                    } else {
                                        None
                                    };
                                    Ok::<_, anyhow::Error>((md4, aich))
                                }).await??;

                                let mut resp = Vec::new();
                                local_ident.write_identifier(&mut resp);
                                let mut resp_options = 0u8;
                                if let Some(ref hashes) = md4_hashes {
                                    if !hashes.is_empty() {
                                        resp_options |= 0x01;
                                    }
                                }
                                if let (Some(_root), Some(ref hashes)) = (aich_root, aich_hashes.as_ref()) {
                                    if !hashes.is_empty() {
                                        resp_options |= 0x02;
                                    }
                                }
                                resp.push(resp_options);
                                if let Some(hashes) = md4_hashes {
                                    resp.extend_from_slice(&file_ident.md4_hash);
                                    resp.extend_from_slice(&(hashes.len() as u16).to_le_bytes());
                                    for h in &hashes {
                                        resp.extend_from_slice(h);
                                    }
                                }
                                if let (Some(root), Some(hashes)) = (aich_root, aich_hashes) {
                                    resp.extend_from_slice(&root);
                                    resp.extend_from_slice(&(hashes.len() as u16).to_le_bytes());
                                    for h in &hashes {
                                        resp.extend_from_slice(h);
                                    }
                                }
                                write_packet_async(
                                    &mut writer,
                                    OP_EMULEPROT,
                                    OP_HASHSETANSWER2,
                                    &resp,
                                )
                                .await?;
                            }
                        }
                    }
                }

                (OP_EMULEPROT, OP_MULTIPACKET)
                | (OP_EMULEPROT, OP_MULTIPACKET_EXT)
                | (OP_EMULEPROT, OP_MULTIPACKET_EXT2) => {
                    match parse_multipacket(&payload, opcode) {
                        Ok(mpreq) => {
                            let hash_hex = hex::encode(mpreq.file_hash);
                            if let Some(file) = self.resolve_upload_file(&mpreq.file_hash).await {
                            let local_ident = FileIdentifier {
                                md4_hash: mpreq.file_hash,
                                file_size: Some(file.size),
                                aich_hash: parse_aich_root_hash(&file.aich_hash_hex),
                            };
                            if let Some(ref req_ident) = mpreq.file_identifier {
                                if !local_ident.compare_relaxed(req_ident) {
                                    debug!("MultiPacket EXT2 identifier mismatch for {hash_hex}, sending FNF");
                                    write_packet_async(
                                        &mut writer,
                                        OP_EDONKEYHEADER,
                                        OP_FILEREQANSNOFIL,
                                        &mpreq.file_hash,
                                    )
                                    .await?;
                                    continue;
                                }
                            } else if let Some(req_size) = mpreq.file_size {
                                if req_size != 0 && req_size != file.size {
                                    debug!("MultiPacket size mismatch for {hash_hex}, sending FNF");
                                    write_packet_async(
                                        &mut writer,
                                        OP_EDONKEYHEADER,
                                        OP_FILEREQANSNOFIL,
                                        &mpreq.file_hash,
                                    )
                                    .await?;
                                    continue;
                                }
                                }
                            current_file_hash = Some(mpreq.file_hash);
                            total_size = file.size;

                                let partial_bitmap = if file.is_partial && file.size > 0 {
                                    let tracker = super::part_tracker::PartTracker::new(file.size, &file.path);
                                    Some(tracker.completed_parts())
                                } else {
                                    None
                                };

                                let answer = build_multipacket_answer(
                                    &mpreq.file_hash,
                                    &file.name,
                                    file.size,
                                    !file.is_partial,
                                    partial_bitmap.as_deref(),
                                    parse_aich_root_hash(&file.aich_hash_hex),
                                    mpreq.is_ext2,
                                    &mpreq.sub_opcodes,
                                );

                                let resp_opcode = if mpreq.is_ext2 {
                                    OP_MULTIPACKETANSWER_EXT2
                                } else {
                                    OP_MULTIPACKETANSWER
                                };
                                write_packet_async(
                                    &mut writer,
                                    OP_EMULEPROT,
                                    resp_opcode,
                                    &answer,
                                )
                                .await?;
                                let _ = self.send_comment_info(&mut writer, &mpreq.file_hash).await;
                                self.record_share_request_once(
                                    &mpreq.file_hash,
                                    &mut recorded_share_request,
                                )
                                .await;
                                debug!("Sent MultiPacketAnswer for {hash_hex} to {peer_addr}");

                                for sub in &mpreq.sub_opcodes {
                                    match sub {
                                        MultiPacketSubReq::RequestSources => {
                                            let exclude_ip = match peer_addr.ip() {
                                                std::net::IpAddr::V4(v4) => v4,
                                                _ => std::net::Ipv4Addr::UNSPECIFIED,
                                            };
                                            let resp = {
                                                let sm = self.source_manager.read().await;
                                                sm.build_answer_sources1_versioned(
                                                    &mpreq.file_hash,
                                                    exclude_ip,
                                                    peer_source_exchange_ver,
                                                )
                                            };
                                            write_packet_async(
                                                &mut writer,
                                                OP_EMULEPROT,
                                                OP_ANSWERSOURCES,
                                                &resp,
                                            )
                                            .await?;
                                        }
                                        MultiPacketSubReq::RequestSources2 { version, .. } => {
                                            let exclude_ip = match peer_addr.ip() {
                                                std::net::IpAddr::V4(v4) => v4,
                                                _ => std::net::Ipv4Addr::UNSPECIFIED,
                                            };
                                            let resp = {
                                                let sm = self.source_manager.read().await;
                                                sm.build_answer_sources2_versioned(&mpreq.file_hash, exclude_ip, *version)
                                            };
                                            write_packet_async(
                                                &mut writer,
                                                OP_EMULEPROT,
                                                OP_ANSWERSOURCES2,
                                                &resp,
                                            )
                                            .await?;
                                        }
                                        MultiPacketSubReq::AichFileHashReq => {}
                                        _ => {}
                                    }
                                }
                            } else {
                                write_packet_async(
                                    &mut writer,
                                    OP_EDONKEYHEADER,
                                    OP_FILEREQANSNOFIL,
                                    &mpreq.file_hash,
                                )
                                .await?;
                            }
                        }
                        Err(e) => {
                            debug!("Failed to parse MultiPacket from {peer_addr}: {e}");
                        }
                    }
                }

                (OP_EMULEPROT, OP_REQUESTSOURCES) => {
                    // SX v1: respond with OP_ANSWERSOURCES (legacy v1 format)
                    if let Some(hash) = current_file_hash {
                        let exclude_ip = match peer_addr.ip() {
                            std::net::IpAddr::V4(v4) => v4,
                            _ => std::net::Ipv4Addr::UNSPECIFIED,
                        };
                        let resp = {
                            let sm = self.source_manager.read().await;
                            sm.build_answer_sources1_versioned(
                                &hash,
                                exclude_ip,
                                peer_source_exchange_ver,
                            )
                        };
                        write_packet_async(
                            &mut writer,
                            OP_EMULEPROT,
                            OP_ANSWERSOURCES,
                            &resp,
                        )
                        .await?;
                    }
                }

                (OP_EMULEPROT, OP_REQUESTSOURCES2) => {
                    // SX v2+: format is Version(1) + Options(2) + Hash(16) = 19 bytes
                    if payload.len() >= 19 {
                        let requested_version = payload[0];
                        let mut hash = [0u8; 16];
                        hash.copy_from_slice(&payload[3..19]);
                        let exclude_ip = match peer_addr.ip() {
                            std::net::IpAddr::V4(v4) => v4,
                            _ => std::net::Ipv4Addr::UNSPECIFIED,
                        };
                        let resp = {
                            let sm = self.source_manager.read().await;
                            sm.build_answer_sources2_versioned(&hash, exclude_ip, requested_version)
                        };
                        write_packet_async(
                            &mut writer,
                            OP_EMULEPROT,
                            OP_ANSWERSOURCES2,
                            &resp,
                        )
                        .await?;
                    }
                }

                (OP_EMULEPROT, OP_FWCHECKUDPREQ) if payload.len() >= 8 => {
                    let internal_udp_port = u16::from_le_bytes([payload[0], payload[1]]);
                    let external_udp_port = u16::from_le_bytes([payload[2], payload[3]]);
                    let receiver_udp_key = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                    if let std::net::IpAddr::V4(peer_ip) = peer_addr.ip() {
                        let _ = self.udp_fw_check_tx.send(UdpFirewallCheckRequest {
                            peer_ip,
                            internal_udp_port,
                            external_udp_port,
                            receiver_udp_key,
                        }).await;
                    }
                }

                (OP_EMULEPROT, OP_AICHREQUEST) => {
                    if payload.len() >= 18 {
                        let mut req_hash = [0u8; 16];
                        req_hash.copy_from_slice(&payload[..16]);
                        let part_idx = u16::from_le_bytes([payload[16], payload[17]]) as usize;
                        let requested_root = if payload.len() >= 38 {
                            let mut root = [0u8; 20];
                            root.copy_from_slice(&payload[18..38]);
                            Some(root)
                        } else {
                            None
                        };
                        
                        let hash_hex = hex::encode(req_hash);
                        if let Some(file) = self.resolve_upload_file(&req_hash).await {
                            let cached = {
                                let mut cache = self.aich_cache.lock().await;
                                cache.get(&hash_hex)
                            };
                            let aich_result = if let Some(hs) = cached {
                                Ok(hs)
                            } else if file.is_partial {
                                Err(anyhow::anyhow!("AICH unavailable for partial file"))
                            } else {
                                let path = file.path.clone();
                                let res = tokio::task::spawn_blocking(move || {
                                    crate::network::ed2k::aich::AICHRecoveryHashSet::build_from_file(&path)
                                }).await?;
                                if let Ok(ref hs) = res {
                                    let mut cache = self.aich_cache.lock().await;
                                    cache.insert(hash_hex.clone(), hs.clone());
                                }
                                res
                            };

                            match aich_result {
                                Ok(hs) => {
                                    if let Some(requested_root) = requested_root {
                                        if hs.root_hash != requested_root {
                                            debug!(
                                                "Ignoring AICH request for {}: requested root {} does not match local {}",
                                                hash_hex,
                                                hex::encode(requested_root),
                                                hex::encode(hs.root_hash)
                                            );
                                            continue;
                                        }
                                    }
                                    // Create recovery data for the requested part
                                    // PARTSIZE is constant 9.28MB
                                    let recovery_data = hs.create_part_recovery_data(part_idx, PARTSIZE as usize);
                                    
                                    let mut resp = Vec::with_capacity(16 + 2 + 20 + recovery_data.len());
                                    resp.extend_from_slice(&req_hash);
                                    resp.extend_from_slice(&(part_idx as u16).to_le_bytes());
                                    resp.extend_from_slice(&hs.root_hash);
                                    resp.extend_from_slice(&recovery_data);

                                    write_packet_async(
                                        &mut writer,
                                        OP_EMULEPROT,
                                        OP_AICHANSWER,
                                        &resp,
                                    )
                                    .await?;
                                }
                                Err(e) => {
                                    warn!("Failed to build AICH for request: {e}");
                                }
                            }
                        }
                    }
                }

                (OP_EMULEPROT, OP_AICHFILEHASHREQ) if payload.len() >= 16 => {
                    let mut req_hash = [0u8; 16];
                    req_hash.copy_from_slice(&payload[..16]);
                    if let Some(file) = self.resolve_upload_file(&req_hash).await {
                        if let Some(aich_hash) = parse_aich_root_hash(&file.aich_hash_hex) {
                            let mut resp = Vec::with_capacity(16 + 20);
                            resp.extend_from_slice(&req_hash);
                            resp.extend_from_slice(&aich_hash);
                            write_packet_async(
                                &mut writer,
                                OP_EMULEPROT,
                                OP_AICHFILEHASHANS,
                                &resp,
                            )
                            .await?;
                        }
                    }
                }

                // eMule Public IP exchange: respond with the peer's IP
                (OP_EMULEPROT, OP_PUBLICIP_REQ) => {
                    let ip_bytes = match peer_addr.ip() {
                        IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
                        _ => 0,
                    };
                    write_packet_async(
                        &mut writer,
                        OP_EMULEPROT,
                        OP_PUBLICIP_ANSWER,
                        &ip_bytes.to_le_bytes(),
                    ).await?;
                    debug!("Sent OP_PUBLICIP_ANSWER ({}) to {peer_addr}", peer_addr.ip());
                }

                // eMule Buddy keepalive: respond to ping with pong
                (OP_EMULEPROT, OP_BUDDYPING) => {
                    write_packet_async(&mut writer, OP_EMULEPROT, OP_BUDDYPONG, &[]).await?;
                    debug!("Received OP_BUDDYPING, sent pong to {peer_addr}");
                }

                (OP_EMULEPROT, OP_BUDDYPONG) => {
                    debug!("Received OP_BUDDYPONG from {peer_addr}");
                }

                (OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE) => {
                    if epx_packets_received >= crate::network::ember::MAX_EPX_PACKETS_PER_CONNECTION {
                        debug!("Ignoring excess EPX packet from uploading peer {peer_addr}");
                    } else {
                        epx_packets_received += 1;
                        match crate::network::ember::parse_exchange_payload(&payload) {
                            Ok(result) if !result.files.is_empty() || !result.peers.is_empty() => {
                                info!("Received Ember Peer Exchange from uploading peer {peer_addr} ({} files, {} peers)", result.files.len(), result.peers.len());
                                let (epx_entries, aich_roots) = super::transfer::epx_result_to_entries(&result);
                                let ember_peers = result.peers.into_iter().map(|p| (p.ip, p.tcp_port)).collect();
                                let _ = self.upload_event_tx.send(UploadEvent {
                                    transfer_id: transfer_id.clone().unwrap_or_default(),
                                    kind: UploadEventKind::EmberSources { entries: epx_entries, aich_roots, ember_peers },
                                }).await;
                            }
                            Ok(_) => {}
                            Err(e) => debug!("Failed to parse Ember exchange from {peer_addr}: {e}"),
                        }
                    }
                }

                (OP_EMULEPROT, OP_EMBER_FRIEND_REQ) if hello_caps.is_ember => {
                    if let Some(eh) = peer_ember_hash {
                        let nick = std::str::from_utf8(&payload).unwrap_or("").to_string();
                        info!("Received friend request from {peer_addr} (nick='{}', hash={})", nick, hex::encode(eh));
                        let _ = self.upload_event_tx.send(UploadEvent {
                            transfer_id: String::new(),
                            kind: UploadEventKind::EmberFriendRequest {
                                ember_hash: eh,
                                nickname: nick,
                                peer_ip: peer_addr.ip().to_string(),
                                peer_port: peer_addr.port(),
                            },
                        }).await;
                    }
                }

                (OP_EMULEPROT, OP_EMBER_CHAT_MSG) if is_ember_friend => {
                    if let Some(eh) = peer_ember_hash {
                        if payload.len() <= 4096 {
                            if let Ok(msg) = std::str::from_utf8(&payload) {
                                let _ = self.upload_event_tx.send(UploadEvent {
                                    transfer_id: String::new(),
                                    kind: UploadEventKind::EmberChatMessage {
                                        ember_hash: eh,
                                        message: msg.to_string(),
                                    },
                                }).await;
                            }
                        }
                    }
                }

                (OP_EMULEPROT, OP_EMBER_BROWSE_REQ) if is_ember_friend => {
                    if let Some(eh) = peer_ember_hash {
                        let _ = self.upload_event_tx.send(UploadEvent {
                            transfer_id: String::new(),
                            kind: UploadEventKind::EmberBrowseRequest {
                                ember_hash: eh,
                            },
                        }).await;
                    }
                }

                (OP_EMULEPROT, OP_EMBER_BROWSE_RES) if is_ember_friend => {
                    if let Some(eh) = peer_ember_hash {
                        let entries = super::multi_source::parse_browse_response(&payload);
                        let _ = self.upload_event_tx.send(UploadEvent {
                            transfer_id: String::new(),
                            kind: UploadEventKind::EmberBrowseResponse {
                                ember_hash: eh,
                                entries,
                            },
                        }).await;
                    }
                }

                (OP_EMULEPROT, OP_EMBER_KEEPALIVE) if is_ember_friend => {}

                _ => {
                    debug!(
                        "Upload handler ignoring proto=0x{proto:02X} op=0x{opcode:02X} from {peer_addr}"
                    );
                }
            }
        }

        if let (true, Some(eh)) = (owns_ember_slot, peer_ember_hash) {
            self.ember_sessions.write().await.remove(&eh);
            let _ = self.upload_event_tx.send(UploadEvent {
                transfer_id: String::new(),
                kind: UploadEventKind::EmberFriendDisconnected { ember_hash: eh },
            }).await;
        }

        // Remove from upload queue on disconnect
        {
            let mut queue = self.upload_queue.lock().await;
            queue.retain(|e| e.identity != queue_identity);
        }

        self.slot_rates.lock().unwrap_or_else(|e| e.into_inner()).remove(&peer_addr);

        // slot_guard Drop handles upload slot release automatically

        // Emit completion/failure for any tracked upload
        if let Some(tid) = &transfer_id {
            let _ = self.upload_event_tx.send(UploadEvent {
                transfer_id: tid.clone(),
                kind: if uploaded > 0 {
                    UploadEventKind::Completed
                } else {
                    UploadEventKind::Failed {
                        error: "Peer disconnected before any data transferred".to_string(),
                    }
                },
            }).await;
        }

        Ok(())
    }

    async fn acquire_upload_bandwidth(&self, bytes: u64) {
        self.bandwidth_limiter.acquire_upload(bytes).await;
    }
}

fn parse_request_parts_i64(payload: &[u8]) -> anyhow::Result<Vec<(u64, u64)>> {
    if payload.len() < 16 + 48 {
        anyhow::bail!("RequestParts_I64 too short");
    }
    // Skip 16-byte file hash
    let mut offsets = Vec::new();
    let starts_offset = 16;
    let ends_offset = 16 + 24; // 3 * 8 bytes

    for i in 0..3 {
        let start = u64::from_le_bytes(
            payload[starts_offset + i * 8..starts_offset + i * 8 + 8]
                .try_into()?,
        );
        let end = u64::from_le_bytes(
            payload[ends_offset + i * 8..ends_offset + i * 8 + 8]
                .try_into()?,
        );
        if start > 0 || end > 0 {
            offsets.push((start, end));
        }
    }
    Ok(offsets)
}

fn parse_aich_root_hash(hex_str: &str) -> Option<[u8; 20]> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn compute_aich_part_hashes(path: &std::path::Path) -> anyhow::Result<Vec<[u8; 20]>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let file_size = file.metadata()?.len();
    if file_size == 0 {
        return Ok(Vec::new());
    }
    let mut hashes = Vec::new();
    let mut remaining = file_size;
    let mut buf = vec![0u8; PARTSIZE as usize];
    while remaining > 0 {
        let part_len = remaining.min(PARTSIZE) as usize;
        let part_buf = &mut buf[..part_len];
        file.read_exact(part_buf)?;
        hashes.push(crate::network::ed2k::aich::compute_aich_part(part_buf));
        remaining -= part_len as u64;
    }
    Ok(hashes)
}

fn parse_request_parts_32(payload: &[u8]) -> anyhow::Result<Vec<(u64, u64)>> {
    if payload.len() < 16 + 24 {
        anyhow::bail!("RequestParts too short");
    }
    let mut offsets = Vec::new();
    let starts_offset = 16;
    let ends_offset = 16 + 12; // 3 * 4 bytes

    for i in 0..3 {
        let start = u32::from_le_bytes(
            payload[starts_offset + i * 4..starts_offset + i * 4 + 4]
                .try_into()?,
        ) as u64;
        let end = u32::from_le_bytes(
            payload[ends_offset + i * 4..ends_offset + i * 4 + 4]
                .try_into()?,
        ) as u64;
        if start > 0 || end > 0 {
            offsets.push((start, end));
        }
    }
    Ok(offsets)
}

fn compute_part_hashes(path: &std::path::Path) -> anyhow::Result<Vec<[u8; 16]>> {
    use digest::Digest;
    use md4::Md4;

    let mut file = std::fs::File::open(path)?;
    let file_size = file.metadata()?.len();
    let num_parts = ((file_size + PARTSIZE - 1) / PARTSIZE) as usize;

    let mut hashes = Vec::with_capacity(num_parts + 1);
    let mut buf = vec![0u8; 64 * 1024];
    let mut remaining = file_size;

    for _ in 0..num_parts {
        let part_size = remaining.min(PARTSIZE);
        let mut hasher = Md4::new();
        let mut part_remaining = part_size;

        while part_remaining > 0 {
            let to_read = (part_remaining as usize).min(buf.len());
            let n = file.read(&mut buf[..to_read])?;
            if n == 0 {
                anyhow::bail!(
                    "unexpected EOF while hashing part (expected {} more bytes)",
                    part_remaining
                );
            }
            hasher.update(&buf[..n]);
            part_remaining -= n as u64;
        }

        let hash = hasher.finalize();
        let mut h = [0u8; 16];
        h.copy_from_slice(&hash);
        hashes.push(h);
        remaining -= part_size;
    }

    // NOTE: do NOT append trailing MD4("") here. The trailing empty hash is
    // a computation artifact used only when deriving the overall file hash from
    // part hashes (see ed2k_hash_from_parts). eMule's hashset answer also omits
    // it — the receiver's verify_hashset adds it during verification.

    Ok(hashes)
}

async fn read_packet_timeout<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    tokio::time::timeout(
        std::time::Duration::from_secs(CLIENT_TIMEOUT_SECS),
        read_packet_async_inner(reader),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timed out"))?
}

async fn read_packet_async_inner<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    use std::io::Read as StdRead;
    const OP_PACKEDPROT: u8 = 0xD4;
    let protocol = reader.read_u8().await?;
    let length = reader.read_u32_le().await? as usize;
    if length == 0 || length > 10 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid packet length",
        ));
    }
    let opcode = reader.read_u8().await?;
    let payload_len = length - 1;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    if protocol == OP_PACKEDPROT {
        let mut decoder = flate2::read::ZlibDecoder::new(&payload[..]);
        let mut unpacked = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = decoder.read(&mut buf)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("packed decode failed: {e}")))?;
            if n == 0 { break; }
            unpacked.extend_from_slice(&buf[..n]);
            if unpacked.len() > 10 * 1024 * 1024 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "packed packet decompressed size exceeds limit"));
            }
        }
        return Ok((OP_EMULEPROT, opcode, unpacked));
    }
    Ok((protocol, opcode, payload))
}

async fn write_packet_async<W: AsyncWriteExt + Unpin + ?Sized>(
    writer: &mut W,
    protocol: u8,
    opcode: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    writer.write_u8(protocol).await?;
    writer.write_u32_le((1 + payload.len()) as u32).await?;
    writer.write_u8(opcode).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_packet_with_first_byte<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    first_byte: u8,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    let protocol = first_byte;
    let length = reader.read_u32_le().await? as usize;
    if length == 0 || length > 10 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid packet length",
        ));
    }
    let opcode = reader.read_u8().await?;
    let payload_len = length - 1;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    Ok((protocol, opcode, payload))
}

fn is_connection_closed(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
    )
}
