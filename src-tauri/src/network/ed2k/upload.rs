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

/// Shared set of banned user hashes for upload-only enforcement.
/// Checked after Hello handshake reveals the peer's identity.
pub type SharedBannedHashes = Arc<std::sync::RwLock<std::collections::HashSet<[u8; 16]>>>;

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
/// Minimum wall time between `UploadEventKind::Progress` events for a
/// single upload session. The OP_REQUESTPARTS handler naturally fires one
/// Progress per 180 KiB block sent; at 2 MiB/s that's ~11 events/sec per
/// slot, and with several active slots we can flood both the shared
/// mpsc channel (capacity 128) and the Tauri IPC pipe to the webview.
/// 200 ms gives an upper bound of 5 events/sec per session with no
/// perceptible UI stutter (ProgressBar already smooths via `transition:
/// width 0.3s`) while leaving plenty of headroom for the event consumer
/// even at full saturation.
const PROGRESS_EMIT_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);
/// How long we'll hold a granted upload slot for a peer that has gone
/// silent (no `OP_REQUESTPARTS` and no other activity) before closing
/// the session and rotating the slot to the next queued peer.
///
/// Tighter than `CLIENT_TIMEOUT_SECS` because an actively downloading
/// eMule client sends `OP_REQUESTPARTS` back-to-back — typically one
/// per completed ~540 KB batch, so at any sane rate there's something
/// on the wire every second or two. 60 s of total silence means the
/// peer has paused, crashed, or walked away; sitting on their slot
/// starves our queue. The full 120 s timeout is kept for pre-grant
/// (discovery / secident / handshake) states where long silences are
/// normal.
const SLOT_IDLE_TIMEOUT_SECS: u64 = 60;

/// Diagnostic: cadence of the per-session "heartbeat" log emitted at the
/// top of the outer packet loop. Keeps log volume bounded (≤ 1 line per
/// session per interval) while still surfacing enough state to answer
/// "did the idle-rotation branch ever run?" in a field trace. Only
/// emitted when the session has moved at least one byte OR holds an
/// active slot — pre-grant sessions would otherwise spam the log.
const UPLOAD_HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(20);

/// Diagnostic: wall-clock threshold beyond which a single `write_packet_async`
/// call is logged at info. Intended to catch TCP back-pressure stalls (peer
/// shrinking its RWND or refusing to read) that would otherwise go
/// invisible — we already have a 60 s hard stop inside `write_packet_async`,
/// but anything over a second for a ≤10 KiB packet means the peer is
/// nearly non-draining and explains why a session can appear stuck in
/// "Transferring" while we're in fact stranded inside an OP_REQUESTPARTS
/// serving loop.
const UPLOAD_SLOW_WRITE_THRESHOLD: std::time::Duration = std::time::Duration::from_millis(1000);

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
pub(crate) enum QueueIdentity {
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

/// Shared handle to the upload queue so non-upload subsystems (e.g. the UDP
/// OP_REASKFILEPING handler in `network/mod.rs`) can report an accurate
/// queue rank for their peers instead of a placeholder 0.
pub(crate) type UploadQueueRef = Arc<tokio::sync::Mutex<Vec<QueueEntry>>>;

#[derive(Debug, Clone)]
pub(crate) struct QueueEntry {
    pub(crate) identity: QueueIdentity,
    pub(crate) current_addr: Option<SocketAddr>,
    pub(crate) user_hash: [u8; 16],
    pub(crate) file_hash: [u8; 16],
    pub(crate) join_time: std::time::Instant,
    /// eMule m_bAddNextConnect: Low-ID client that scored highest while
    /// disconnected; gets priority slot on reconnect.
    #[allow(dead_code)]
    pub(crate) add_next_connect: bool,
    /// eMule m_byEmuleVersion from Hello, for legacy client penalty.
    pub(crate) emule_version: u8,
    /// True if this peer is a friend with an active friend slot.
    pub(crate) is_friend_slot: bool,
    /// Peer's advertised Ed25519 public key from `OP_EMBER_HELLO`.
    /// Snapshotted at queue-insertion time so `score_queue_entry`
    /// can route verified Ember peers through the enhanced
    /// decayed-ratio + reliability + speed scoring path (Phase 3).
    pub(crate) ember_pubkey: Option<[u8; 32]>,
    /// True iff the peer completed full Ed25519 proof-of-possession
    /// on the session that produced this queue entry. A spoofer who
    /// merely claims a pubkey on the wire lands here as `false` and
    /// falls back to the legacy eMule credit-ratio scoring, so they
    /// can't ride a friend's Ember reputation into the queue.
    /// Snapshot of `ember_auth_state.is_verified()` at
    /// insertion/update time — re-evaluated each time the peer
    /// re-enters the queue (session-expired, queue-full rotation).
    pub(crate) ember_verified: bool,
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
        user_hash: Option<String>,
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
    /// Incoming friend request from an Ember peer. `verified` carries
    /// the same semantics as the download-side variant in
    /// `super::transfer::DownloadEvent::EmberFriendRequest`: true iff
    /// the peer advertised an Ed25519 pubkey that BLAKE3-binds to
    /// their advertised `ember_hash`, plus (on friend-connect paths)
    /// signature proof-of-possession.
    EmberFriendRequest {
        ember_hash: [u8; 16],
        nickname: String,
        peer_ip: String,
        peer_port: u16,
        verified: bool,
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
    /// Outbound friend-search lookup failed *before* a session was
    /// ever established (rendezvous returned None / Err, or the
    /// initial dial failed). Used purely as an internal signal from
    /// `spawn_rendezvous_friend_lookup` and the chat / browse
    /// auto-connect spawns back into the network task so the
    /// `outbound_session_tasks` slot can be cleared without the
    /// side-effects of `EmberFriendDisconnected` — that variant
    /// fires `ember:friend-offline` + `ember:browse-error` and
    /// schedules a backoff-gated reconnect, all of which would be
    /// wrong for a peer that was never online from our point of
    /// view in the first place. The user-facing
    /// `ember:friend-search-failed` event is emitted by the spawn
    /// itself (with a finer-grained reason); this kind is
    /// state-mutation only and never reaches the UI.
    EmberFriendSearchFailed {
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
    /// Live-toggleable obfuscation preference. The Settings page can
    /// flip this at runtime; we read it on every Hello / EmuleInfo
    /// build so inbound and outbound advertise the same value as the
    /// rest of the network stack — without this the listener would be
    /// stuck on whatever value was active at process start.
    obfuscation_enabled: Arc<std::sync::atomic::AtomicBool>,
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
    /// Shared banned user hashes for upload-only enforcement after Hello
    banned_hashes: SharedBannedHashes,
    /// Anti-leech client-software pattern filter. Checked once per session
    /// after Hello/EmuleInfo, before any slot is granted or queue position
    /// is held. Hot-reloadable from disk via the Settings UI.
    antileech: crate::security::antileech::SharedAntiLeechFilter,
    /// eMule: dontcompressavi — skip compression for video files. Live-
    /// toggleable from the Settings page; read on every send loop iter.
    skip_compress_video: Arc<std::sync::atomic::AtomicBool>,
    /// Apply IP filter to incoming TCP connections (when false, only
    /// outbound is filtered). Live-toggleable; checked once per accept.
    filter_incoming_connections: Arc<std::sync::atomic::AtomicBool>,
    /// IPs we probed with FirewalledReq -- connect-back proves TCP is open
    firewall_probe_ips: FirewallProbeSet,
    /// Shared atomic: set to false when TCP is proven open
    firewalled_shared: Arc<std::sync::atomic::AtomicBool>,
    /// Our current external IPv4 as a HighID-format little-endian u32, or
    /// `0` when we don't yet have a trusted public IP. Read on every
    /// incoming Hello so the `OP_HELLOANSWER` we send advertises our real
    /// client_id — strict eMule forks and older clients rely on this value
    /// for HighID/LowID classification, queue scoring, and callback-routing
    /// decisions. When this is 0 we fall through to sending client_id=0,
    /// which stock eMule (BaseClient.cpp:608) auto-heals to the connect IP
    /// but other clients may interpret as LowID. Kept in sync with
    /// `NetworkState::external_ip` via `set_external_ip`.
    external_ip_shared: Arc<std::sync::atomic::AtomicU32>,
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
    /// Our Ed25519 public key, advertised in `OP_EMBER_HELLO` so peers can
    /// verify our `ember_hash` is cryptographically bound to a key we
    /// actually control (`verify_ember_hash_binding`) and use it as the
    /// verifier in `perform_ember_auth`. Always the raw 32-byte little-
    /// endian public-key encoding, derived deterministically from
    /// `ed25519_secret_key` at identity-load time.
    ed25519_public_key: [u8; 32],
    /// Our Ed25519 secret key. Used by the reactive Ember auth
    /// state machine (`super::ember_auth`) to sign the peer's
    /// random nonce when they initiate a challenge-response from
    /// the download side. Never serialized to the wire or to disk
    /// from here.
    ed25519_secret_key: [u8; 32],
    /// Live friend user-hash set for friend-slot priority boost
    friend_hashes: Arc<RwLock<std::collections::HashSet<[u8; 16]>>>,
    /// Pre-built Ember Peer Exchange payload (shared, read-only).
    ember_payload: crate::network::ember::SharedEmberPayload,
    /// Generation counter for `ember_payload`; bumped each time the
    /// background timer rebuilds the shared payload. The per-connection
    /// resend logic compares its last-sent value against this so we only
    /// ship updated EPX over an open upload session when there's
    /// actually new data, not on every periodic check.
    ember_payload_generation: crate::network::ember::EmberPayloadGeneration,
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
    /// Lock-free counter the per-connection upload tasks bump on every
    /// inbound `OP_REQUESTSOURCES` and outbound `OP_ANSWERSOURCES` /
    /// `OP_EMBER_SOURCEEXCHANGE` packet. Drained on the network
    /// loop's stats tick into `OverheadCategory::SourceExchange`.
    sx_overhead: crate::storage::statistics::SharedSxOverheadCounters,
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

    /// Normalize IPv4-mapped IPv6 (::ffff:a.b.c.d) to plain V4 for consistent keying.
    fn normalize_ip(ip: &std::net::IpAddr) -> std::net::IpAddr {
        match ip {
            std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => std::net::IpAddr::V4(v4),
                None => *ip,
            },
            other => *other,
        }
    }

    /// Check if an IP is currently banned. Returns true if banned.
    fn is_banned(&self, ip: &std::net::IpAddr) -> bool {
        let key = Self::normalize_ip(ip);
        if let Some(entry) = self.entries.get(&key) {
            if let Some(until) = entry.banned_until {
                return std::time::Instant::now() < until;
            }
        }
        false
    }

    /// Record a request from this IP. Returns true if the IP should be banned.
    fn record_request(&mut self, ip: std::net::IpAddr) -> bool {
        let ip = Self::normalize_ip(&ip);
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
        let ip = Self::normalize_ip(&ip);
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
pub(crate) fn priority_weight(priority: &str) -> f64 {
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
///
/// Phase 3 routing: when the peer has advertised an Ed25519 pubkey AND
/// completed full proof-of-possession on the session (`ember_verified`),
/// the base score is drawn from the Ember ledger
/// (`CreditManager::get_ember_queue_score`) which layers decayed credit
/// ratio, session-reliability, and upload-speed fairness on top of the
/// baseline eMule formula. Peers without PoP — vanilla eMule clients,
/// hash-only Ember peers, and Ember peers that haven't yet completed
/// the challenge-response — continue using the legacy
/// `CreditManager::get_queue_score`, keeping the network-wide credit
/// compatibility story intact.
pub(crate) fn score_queue_entry(
    cm: &CreditManager,
    idx: &LocalIndex,
    user_hash: &[u8; 16],
    file_hash: [u8; 16],
    wait_secs: u64,
    current_addr: Option<SocketAddr>,
    emule_version: u8,
    is_friend_slot: bool,
    ember_pubkey: Option<&[u8; 32]>,
    ember_verified: bool,
) -> f64 {
    let file_prio = idx
        .get_by_hash(&hex::encode(file_hash))
        .map(|f| priority_weight(&f.priority))
        .unwrap_or(0.7);
    // Normalize IPv4-mapped IPv6 (::ffff:x.x.x.x) so queue scoring and
    // BadGuy IP checks work for peers connecting over dual-stack sockets.
    // Previously these peers got peer_ip=0, which defeated the credit
    // IP-pinning used by `get_current_ident_state` to detect identity
    // spoofing via IP switches.
    let peer_ip = current_addr
        .map(|a| match a.ip() {
            IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(|v4| u32::from_be_bytes(v4.octets()))
                .unwrap_or(0),
        })
        .unwrap_or(0);

    // Verified Ember peers get the enhanced-scoring path. Two guards
    // on the same branch (pubkey present AND PoP verified) so
    // binding-only peers fall through to eMule scoring — the Ember
    // ledger only starts accruing bytes after PoP per
    // `add_ember_uploaded`, so routing an unverified peer through
    // `get_ember_queue_score` would always score at MIN until they
    // verified. The eMule fallback is strictly kinder to
    // already-known binding-only peers.
    //
    // BadGuy IP check still runs via the eMule ratio for safety:
    // `get_current_ident_state` is the only place we detect identity
    // IP swaps, and it's keyed on the user_hash ledger. If the eMule
    // side returns 0.0 (BadGuy), we propagate that — a verified
    // Ember pubkey cannot override the BadGuy decision since BadGuy
    // means "this peer's user_hash was seen on a different IP",
    // which is still suspicious regardless of Ember identity.
    let emule_score = cm.get_queue_score(user_hash, wait_secs, file_prio, peer_ip);
    let use_ember = ember_verified && ember_pubkey.is_some();
    let mut score = if use_ember {
        let pk = ember_pubkey.expect("guarded by use_ember");
        // Short-circuit the BadGuy zero so a spoofer who compromised
        // one peer's user_hash but verified their own Ember pubkey
        // can't reach the queue via the Ember scoring path.
        if emule_score == 0.0 {
            0.0
        } else {
            cm.get_ember_queue_score(pk, wait_secs, file_prio)
        }
    } else {
        emule_score
    };
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
pub(crate) fn compute_queue_rank(
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
            entry.ember_pubkey.as_ref(),
            entry.ember_verified,
        );
        if es > my_score || (es == my_score && entry.join_time < my_join_time) {
            rank += 1;
        }
    }
    rank
}

/// eMule MAX_PURGEQUEUETIME: 1 hour in seconds
const MAX_PURGEQUEUETIME_SECS: u64 = 3600;

/// Compute the rank of a queued peer reached over UDP (OP_REASKFILEPING).
///
/// Matches on either a known `user_hash` or the UDP source IP — we don't
/// have the user hash from UDP alone, so IP+file is the normal fallback.
/// If multiple candidate entries match (e.g., two peers NATted behind the
/// same address) we pick the earliest join time so the rank we report is
/// stable and non-inflationary.
///
/// Returns `Some(rank)` where rank is 1-based (matching TCP `OP_QUEUERANKING`
/// semantics) or `None` if no matching entry exists (caller should treat as
/// "not queued — freshly granted or dropped").
pub(crate) async fn udp_queue_rank_for_peer(
    upload_queue: &UploadQueueRef,
    credit_manager: &Arc<tokio::sync::RwLock<CreditManager>>,
    local_index: &Arc<tokio::sync::RwLock<LocalIndex>>,
    from_ip: IpAddr,
    file_hash: &[u8; 16],
) -> Option<u16> {
    let queue = upload_queue.lock().await;
    let cm = credit_manager.read().await;
    let idx = local_index.read().await;
    let mut best: Option<&QueueEntry> = None;
    for entry in queue.iter() {
        if entry.file_hash != *file_hash {
            continue;
        }
        let matches = matches!(&entry.identity, QueueIdentity::Ip(ip) if *ip == from_ip)
            || entry
                .current_addr
                .map(|a| a.ip() == from_ip)
                .unwrap_or(false);
        if matches {
            match best {
                Some(prev) if prev.join_time <= entry.join_time => {}
                _ => best = Some(entry),
            }
        }
    }
    let target = best?;
    let my_score = score_queue_entry(
        &cm,
        &idx,
        &target.user_hash,
        target.file_hash,
        target.join_time.elapsed().as_secs(),
        target.current_addr,
        target.emule_version,
        target.is_friend_slot,
        target.ember_pubkey.as_ref(),
        target.ember_verified,
    );
    Some(compute_queue_rank(
        &cm,
        &idx,
        &queue,
        &target.identity,
        my_score,
        target.join_time,
    ))
}

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
    banned_hashes: SharedBannedHashes,
    antileech: crate::security::antileech::SharedAntiLeechFilter,
    skip_compress_video: Arc<std::sync::atomic::AtomicBool>,
    filter_incoming_connections: Arc<std::sync::atomic::AtomicBool>,
    firewall_probe_ips: FirewallProbeSet,
    firewalled_shared: Arc<std::sync::atomic::AtomicBool>,
    // Our current external IPv4 in ed2k HighID encoding (little-endian u32
    // of the four IP octets), or 0 when we don't yet have a trusted public
    // IP to advertise. Kept in sync with `NetworkState::external_ip` by
    // `set_external_ip` in network/mod.rs so this listener always reads the
    // freshest value without taking a lock.
    external_ip_shared: Arc<std::sync::atomic::AtomicU32>,
    pending_kad_callbacks: PendingKadCallbacks,
    kad_callback_tx: tokio::sync::mpsc::Sender<KadCallbackParts>,
    udp_fw_check_tx: tokio::sync::mpsc::Sender<UdpFirewallCheckRequest>,
    obfuscation_enabled: Arc<std::sync::atomic::AtomicBool>,
    shared_server_addr: Arc<RwLock<Option<SocketAddr>>>,
    friend_hashes: Arc<RwLock<std::collections::HashSet<[u8; 16]>>>,
    ember_payload: crate::network::ember::SharedEmberPayload,
    ember_payload_generation: crate::network::ember::EmberPayloadGeneration,
    geoip: crate::geoip::GeoIpReader,
    ember_sessions: EmberSessionMap,
    ember_hash: [u8; 16],
    ed25519_public_key: [u8; 32],
    ed25519_secret_key: [u8; 32],
    network_disconnected: Arc<std::sync::atomic::AtomicBool>,
    // Queue handle created by the caller so other subsystems (UDP REASKACK
    // rank, diagnostics) can read the same shared queue state.
    upload_queue: UploadQueueRef,
    // Shared atomic counters for peer-to-peer Source Exchange overhead.
    // Each upload-side connection bumps these on inbound REQUESTSOURCES
    // and outbound ANSWERSOURCES / EMBER_SOURCEEXCHANGE bytes; the
    // network-loop drains them into the SourceExchange overhead row.
    sx_overhead: crate::storage::statistics::SharedSxOverheadCounters,
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
        banned_hashes,
        antileech,
        skip_compress_video,
        filter_incoming_connections,
        firewall_probe_ips,
        firewalled_shared,
        external_ip_shared,
        pending_kad_callbacks,
        kad_callback_tx,
        udp_fw_check_tx,
        abuse_tracker: Arc::new(tokio::sync::Mutex::new(AbuseTracker::new())),
        aich_cache: Arc::new(tokio::sync::Mutex::new(AichCache::new())),
        ember_hash,
        ed25519_public_key,
        ed25519_secret_key,
        friend_hashes,
        ember_payload,
        ember_payload_generation,
        geoip,
        file_request_tracker: Arc::new(tokio::sync::Mutex::new(FileRequestTracker::new())),
        slot_notify,
        slot_rates,
        ember_sessions,
        network_disconnected,
        sx_overhead,
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

                        if server.filter_incoming_connections.load(std::sync::atomic::Ordering::Relaxed) {
                            // Fail closed on poisoned lock: if we can't read
                            // the filter snapshot we refuse the connection
                            // rather than silently letting potentially-blocked
                            // peers through.
                            let blocked = match server.shared_ip_filter.read() {
                                Ok(snap) => snap.is_blocked(peer_ipv4),
                                Err(_poisoned) => {
                                    tracing::warn!(
                                        "IP filter lock poisoned while checking {peer_addr}; rejecting connection"
                                    );
                                    true
                                }
                            };
                            if blocked {
                                info!("IP filter blocked incoming TCP from {peer_addr}");
                                drop(stream);
                                continue;
                            }
                        }

                        // Ban check: reject connections from banned IPs or auto-banned abusers.
                        // Same fail-closed policy: a poisoned lock rejects.
                        let banned_check = match server.banned_ips.read() {
                            Ok(banned) => banned.contains(&peer_ipv4),
                            Err(_poisoned) => {
                                tracing::warn!(
                                    "Banned-IP lock poisoned while checking {peer_addr}; rejecting connection"
                                );
                                true
                            }
                        };
                        if banned_check {
                            debug!("Rejecting TCP connection from banned IP {peer_addr}");
                            drop(stream);
                            continue;
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
                        {
                            let is_probe = {
                                match server.firewall_probe_ips.lock() {
                                    Ok(mut probes) => probes.remove(&peer_ipv4),
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
                        // Cap the kernel TCP send buffer so our sender-side
                        // `uploaded` counter (which advances when bytes are
                        // handed to the OS, not when they hit the wire)
                        // stays within a bounded window of what the peer has
                        // actually received. Without this, Windows TCP
                        // autotuning can grow SO_SNDBUF to several MB under
                        // a fast uplink — uploads then appear "complete" on
                        // our end while the peer is still draining the
                        // kernel buffer. 256 KiB is big enough that a
                        // 10 KiB packet write (see packet-splitting below)
                        // never meaningfully back-pressures on a healthy
                        // link, while keeping the queued-vs-wire gap
                        // bounded to ~25 ms at 10 MB/s.
                        {
                            let sref = socket2::SockRef::from(&stream);
                            let _ = sref.set_send_buffer_size(256 * 1024);
                        }
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
                path,
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
            supports_crypt_layer: self.obfuscation_enabled.load(std::sync::atomic::Ordering::Relaxed),
            requests_crypt_layer: self.obfuscation_enabled.load(std::sync::atomic::Ordering::Relaxed),
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
                        // Advertise our real HighID client_id when we have a
                        // trusted public IP. Falls back to `0` pre-handshake,
                        // which stock eMule auto-heals from the connect IP
                        // (BaseClient.cpp:608) but strict/older clients may
                        // interpret as LowID. See the
                        // `external_ip_shared` field docs.
                        let our_client_id = self
                            .external_ip_shared
                            .load(std::sync::atomic::Ordering::Relaxed);
                        let hello_payload = build_hello_answer_with_buddy_opts(
                            &self.user_hash,
                            our_client_id,
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

                        let emule_payload = build_emule_info(
                            self.udp_port,
                            self.obfuscation_enabled.load(std::sync::atomic::Ordering::Relaxed),
                            Some(&self.ember_hash),
                            None,
                        );
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
                // Advertise our real HighID client_id when known (see the
                // matching block in the obfuscated path above for rationale).
                let our_client_id = self
                    .external_ip_shared
                    .load(std::sync::atomic::Ordering::Relaxed);
                let hello_payload = build_hello_answer_with_buddy_opts(
                    &self.user_hash,
                    our_client_id,
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

        if peer_user_hash != [0u8; 16] {
            if let Ok(set) = self.banned_hashes.read() {
                if set.contains(&peer_user_hash) {
                    info!("Rejecting upload session from banned user {} ({})", hex::encode(peer_user_hash), peer_addr);
                    return Ok(());
                }
            }
        }

        // Check if this is an incoming buddy connection.
        // Release the pending-buddy mutex before awaiting on the bounded
        // `buddy_conn_tx` channel: if the channel is at capacity, `.send().await`
        // parks until a receiver drains it, and anything in the network loop
        // that wanted to `lock().await` this mutex would deadlock.
        let buddy_callback = {
            let mut pending = self.pending_buddy_hashes.lock().await;
            pending.remove(&peer_user_hash)
        };
        if let Some((callback_check, _)) = buddy_callback {
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

        // SecureIdent per-session state.
        //
        // `pending_peer_challenge` = an incoming OP_SECIDENTSTATE from the
        // peer that arrived before we had their RSA public key. eMule
        // doesn't volunteer its public key — it ships OP_PUBLICKEY only
        // in response to our own OP_SECIDENTSTATE (see eMule's
        // ListenSocket.cpp OP_SECIDENTSTATE branch). If the peer's
        // challenge arrives before our challenge elicits their key, we
        // can't sign theirs yet (CreateSignature in eMule's
        // ClientCredits.cpp needs the verifier's pub key). Park the
        // `(challenge, state)` here and replay it from the OP_PUBLICKEY
        // handler once their key lands — mirrors eMule's own deferred
        // sign in CUpDownClient::ProcessPublicKeyPacket
        // (BaseClient.cpp:1907+), and is the standard way two peers
        // that have never seen each other complete the chicken-and-egg
        // handshake without deadlock. Without this, eMule's client
        // details dialog shows "Identification: Invalid" for our
        // session.
        //
        // `pending_secident_challenge` is declared AFTER the EmuleInfo
        // exchange below (it's initialised from our proactive
        // OP_SECIDENTSTATE kick-off, so declaring it later avoids a
        // dead-store warning for the initial `None`).
        let mut pending_peer_challenge: Option<(u32, u8)> = None;

        // Handle EmuleInfo exchange (or the peer may skip straight to file requests)
        let (proto2, opcode2, payload2) = read_packet_timeout(&mut reader).await?;
        let mut deferred_packet: Option<(u8, u8, Vec<u8>)> = None;
        let mut peer_ember_hash: Option<[u8; 16]> = hello_caps.ember_hash.or(obf_ember_hash);
        let mut peer_secure_ident_level = peer_secure_ident_level;
        if proto2 == OP_EMULEPROT && opcode2 == OP_EMULEINFO {
            let incoming_caps = parse_emule_info(&payload2);
            merge_caps(&mut hello_caps, incoming_caps);
            peer_ember_hash = hello_caps.ember_hash;
            peer_secure_ident_level = hello_caps.secure_ident_level;
            ul_client_software = client_software_from_caps(&hello_caps);
            if !hello_caps.peer_name.is_empty() {
                ul_peer_name = hello_caps.peer_name.clone();
            }
            let emule_payload = build_emule_info(
                self.udp_port,
                self.obfuscation_enabled.load(std::sync::atomic::Ordering::Relaxed),
                Some(&self.ember_hash),
                None,
            );
            write_packet_async(&mut writer, OP_EMULEPROT, OP_EMULEINFOANSWER, &emule_payload).await?;
        } else {
            deferred_packet = Some((proto2, opcode2, payload2));
        }

        // Send `OP_EMBER_HELLO` so other Ember peers can detect us out-of-
        // band from the public Hello / EmuleInfo (which we deliberately
        // keep byte-identical to vanilla eMule to avoid anti-leecher queue
        // bans). Vanilla eMule peers ignore unknown OP_EMULEPROT opcodes
        // (`ListenSocket.cpp` ProcessExtPacket default branch), so sending
        // it unconditionally is safe — it's invisible to non-Ember peers.
        // The peer's reply (`OP_EMBER_HELLOANSWER`) is handled in the
        // main packet-processing loop further down, where we'll also
        // recognise it as authoritative proof of Ember-ness and learn the
        // peer's mod_version / ember_hash / ember_pubkey.
        let mut ul_sent_ember_hello = false;
        // Session-scoped Ember identity-binding flag. Set when the
        // peer advertises an Ed25519 pubkey whose BLAKE3 prefix
        // matches their claimed `ember_hash`
        // (`verify_ember_hash_binding`). This is the OFFLINE binding
        // check; on its own it does NOT imply proof of possession
        // (a peer who has merely observed the victim's pubkey on
        // the wire could replay it). The reactive auth state
        // machine below (`ember_auth_state`) provides the full PoP
        // signal; we prefer that when available and fall back to
        // this binding flag only if auth never completes.
        let mut ember_hash_binding_verified = false;
        // Reactive Ember Ed25519 challenge-response state machine.
        // Driven by inbound `OP_EMBER_AUTH_CHALLENGE` /
        // `OP_EMBER_AUTH_RESPONSE` packets dispatched from the
        // reader task; transitions to `Verified` only after we've
        // seen a sig over our random nonce that decodes against the
        // peer's advertised pubkey AND the pubkey BLAKE3-binds to
        // their `ember_hash`. See `super::ember_auth` for the full
        // state diagram and tests.
        let mut ember_auth_state = super::ember_auth::EmberAuthState::default();
        {
            // Advertise our Ed25519 pubkey alongside the ember_hash so
            // the peer can run `verify_ember_hash_binding` on our side
            // of the handshake (confirms our hash is bound to a key we
            // actually own) and so `friend_connect::perform_ember_auth`
            // has a verifier to challenge us with. Previously this
            // site passed `None`, which silently disabled Ember
            // identity verification on every upload session.
            let payload = build_ember_hello(&self.ember_hash, &self.nickname, Some(&self.ed25519_public_key));
            if write_packet_async(&mut writer, OP_EMULEPROT, OP_EMBER_HELLO, &payload).await.is_ok() {
                ul_sent_ember_hello = true;
            }
        }

        // Anti-leech client-software filter. eMule's `AntiLeech.dat`
        // equivalent — match the rendered software label against the
        // user's pattern list and close the connection at handshake
        // time if anything matches. Done HERE (after the optional
        // EmuleInfo round-trip) so we have the most complete `mod_version`
        // string possible; the fast-path branch above leaves
        // `mod_version` empty and would let some patterns fail to match
        // a peer that's actually identifiable. Closing pre-slot-grant
        // means a leech mod can't briefly claim a slot, can't move
        // bytes, and can't sit in the queue holding rank.
        let leech_match = self.antileech.read().check(&ul_client_software);
        if let Some(m) = leech_match {
            info!(
                "AntiLeech: rejecting upload session with {peer_addr} — \
                 client software {ul_client_software:?} matched pattern {:?}",
                m.pattern,
            );
            // Best-effort soft-close: send OP_QUEUEFULL so well-behaved
            // peers stop trying immediately rather than retrying with a
            // backoff. Ignore any write error — we're disconnecting
            // either way.
            let _ = write_packet_async(&mut writer, OP_EMULEPROT, OP_QUEUEFULL, &[]).await;
            return Ok(());
        }

        // Proactively challenge the peer's identity — fire this AFTER the
        // Hello+EmuleInfo exchange regardless of which branch ran above.
        //
        // A modern eMule connector treats our CT_EMULE_VERSION tag inside
        // the Hello payload as enough to set IP_EMULEPROTPACK directly in
        // `ProcessHelloTypePacket` (see BaseClient.cpp:659-664). That means
        // as soon as it processes our OP_HELLOANSWER, it flips
        // `m_byInfopacketsReceived == IP_BOTH`, invokes
        // `InfoPacketsReceived()` (BaseClient.cpp:2030-2039), and sends us
        // `OP_SECIDENTSTATE` **without** ever sending an `OP_EMULEINFO` —
        // the "fast path" new-eMule handshake. So in that case `proto2`
        // above is `OP_SECIDENTSTATE` and we hit the `else { defer }`
        // branch, previously skipping our own proactive challenge.
        //
        // That was the bug behind "Identification: Not supported or
        // disabled" on the peer side: without our OP_SECIDENTSTATE,
        // eMule never sends us their OP_PUBLICKEY (which is only ever
        // sent in response to our challenge, per ListenSocket.cpp:1138),
        // our OP_SECIDENTSTATE handler parks their challenge in
        // `pending_peer_challenge` waiting for a key that never arrives,
        // and our OP_PUBLICKEY + OP_SIGNATURE never go out — so eMule's
        // `CClientCredits::IdentState` stays at the default
        // `IS_NOTAVAILABLE` for our user hash.
        //
        // `maybe_send_secident_challenge` already guards against sending
        // when the peer doesn't advertise SecIdent (`peer_level == 0`)
        // or when we have no local RSA keypair, so it's safe to call
        // unconditionally here. `peer_secure_ident_level` is populated
        // from the Hello's MISCOPTIONS1 bits 16-19 (both Hello and
        // EmuleInfo advertise the same level on a stock eMule, and the
        // EMULEINFO branch above refreshes it if the peer chose to send
        // one).
        let mut pending_secident_challenge: Option<u32> = super::transfer::maybe_send_secident_challenge(
            &mut writer,
            Some(&self.credit_manager),
            peer_user_hash,
            peer_addr,
            peer_secure_ident_level,
        ).await?;

        // Ember Peer Exchange: send our source list to Ember peers.
        // Snapshot the generation we sent so the periodic resend loop
        // below only re-ships when the shared payload has actually been
        // rebuilt with new sources/peers, not on every timer tick.
        info!("Peer {peer_addr}: is_ember={}, mod_version='{}', ember_hash={}, client='{}'",
            hello_caps.is_ember, hello_caps.mod_version,
            peer_ember_hash.map(|h| hex::encode(h)).unwrap_or_else(|| "none".to_string()),
            ul_client_software);
        let mut last_epx_generation: u64 = self
            .ember_payload_generation
            .load(std::sync::atomic::Ordering::Relaxed);
        let mut last_epx_resend = std::time::Instant::now();
        if hello_caps.is_ember {
            let epx_data = self.ember_payload.read().await.clone();
            if !epx_data.is_empty() {
                info!("Sending EPX to Ember peer {peer_addr} ({} bytes, gen {})", epx_data.len(), last_epx_generation);
                let _ = write_packet_async(&mut writer, OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE, &*epx_data).await;
                self.sx_overhead.record_upload((6 + epx_data.len()) as u64);
            } else {
                info!("EPX payload empty, skipping EPX send to {peer_addr}");
            }
            if let std::net::IpAddr::V4(v4) = peer_addr.ip() {
                if hello_caps.tcp_port > 0 && !crate::security::is_special_use_v4(v4) {
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

        // "Claimed friend": the peer's advertised ember_hash is in our
        // friend set. This is NOT sufficient to grant friend-slot
        // priority on its own — a spoofer who learned a friend's hash
        // on the wire can claim it. Privilege-granting sites below
        // (queue insertion, score_queue_entry) additionally gate on
        // `ember_auth_state.is_verified()` via `is_verified_friend`,
        // which only transitions to `true` after the peer completes
        // the Ed25519 challenge-response on THIS TCP session (see
        // `super::ember_auth`).
        //
        // Mutable because Ember identity is exchanged out-of-band
        // from the public Hello/EmuleInfo (in `OP_EMBER_HELLO`, kept
        // private so anti-leecher mods don't queue-ban us). At this
        // point in the session `peer_ember_hash` is almost always
        // still `None` — the peer's `OP_EMBER_HELLO` is processed by
        // the dispatcher loop further down, where we re-evaluate
        // these flags and ship the deferred `OP_EMBER_FRIEND_REQ`.
        // Without that re-evaluation, a friend who initiates a
        // download from us would never receive our reciprocal
        // friend request: their upload session here sees `is_friend
        // = false` at this early gate and silently skips the send,
        // even though we know seconds later they're actually our
        // friend. (The downloader-side checks in `transfer.rs` /
        // `multi_source.rs` don't have this asymmetry because they
        // pre-block-read for OP_EMBER_HELLO before their friend
        // check.) The previously-`let`-only binding made every
        // `is_ember_friend`-gated arm below (CHAT_MSG, BROWSE_REQ,
        // BROWSE_RES, KEEPALIVE) and the `owns_ember_slot`
        // reservation permanently dead for these sessions too.
        let mut is_friend = if let Some(eh) = peer_ember_hash {
            self.friend_hashes.read().await.contains(&eh)
        } else {
            false
        };

        // FriendSeen is deliberately NOT emitted here. The dispatcher
        // promotes FriendSeen to `update_friend_address` (overwriting
        // the friend's last known IP in the DB) and an
        // `ember:friend-online` UI event; both are user-facing facts
        // about *that friend*, so they must require Ed25519 PoP on
        // this session. Emission is moved to the OK arm of
        // `OP_EMBER_AUTH_RESPONSE` below.

        // Tracks whether we've already shipped our outbound
        // `OP_EMBER_FRIEND_REQ` on this session. Both the early gate
        // here and the deferred re-check in the `OP_EMBER_HELLO` arm
        // gate on it so a peer who beat us to it (sent us their
        // `OP_EMBER_HELLO` *and* a FRIEND_REQ before we got around to
        // ours) doesn't get a duplicate from us.
        let mut friend_request_sent = false;
        if is_friend && hello_caps.is_ember {
            info!("Sending friend request to Ember peer {peer_addr}");
            let nick_bytes = self.nickname.as_bytes();
            if write_packet_async(&mut writer, OP_EMULEPROT, OP_EMBER_FRIEND_REQ, nick_bytes).await.is_ok() {
                friend_request_sent = true;
            }
        } else if is_friend {
            info!("Peer {peer_addr} is a friend but is_ember=false, skipping friend request");
        }

        let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        // Mutable for the same reason as `is_friend` above: the
        // OP_EMBER_HELLO arm below re-evaluates this once peer
        // identity is known so the `is_ember_friend`-gated chat /
        // browse / keepalive arms and the `owns_ember_slot` claim
        // in the AUTH_RESPONSE arm all see the up-to-date answer.
        let mut is_ember_friend = is_friend && hello_caps.is_ember;
        // Inbound `ember_sessions` slot reservation is deferred until the
        // peer completes Ed25519 proof-of-possession on this TCP session
        // (see `OP_EMBER_AUTH_RESPONSE` arm below). Reserving the slot
        // earlier — based on the unauthenticated `is_friend &&
        // hello_caps.is_ember` claim — let a spoofer who knew a friend's
        // ember_hash grab the map entry that `SendChatMessage` /
        // `BrowseFriend` look up by hash. Outbound chat/browse the local
        // user composed for that friend would then be written to the
        // spoofer's TCP socket. Keeping `owns_ember_slot = false` until
        // the responder side of `ember_auth` flips to `Verified` closes
        // that confidentiality gap; legitimate Ember friends always
        // complete PoP, so the only sessions denied a slot are the ones
        // we cannot prove are the friend.
        let mut owns_ember_slot = false;

        // Now handle file requests in a loop
        let mut current_file_hash: Option<[u8; 16]> = None;
        let mut uploaded: u64 = 0;
        let mut transfer_id: Option<String> = None;
        let mut total_size: u64 = 0;
        // Rate-limit `UploadEventKind::Progress` emission to the shared
        // `ul_event_tx` channel. The hot path in `OP_REQUESTPARTS` fires one
        // Progress per ~180 KiB block (often 3 per request), which at
        // saturation across several slots can easily produce hundreds of
        // events per second funneling through a 128-slot mpsc channel and
        // then through Tauri's IPC to the webview. Under load that back-
        // pressures the session (the `.send().await` blocks on a full
        // channel) AND flooded the UI with redundant frames. Coalesce to
        // at most one emit per `PROGRESS_EMIT_MIN_INTERVAL`, always
        // emitting the first Progress (so the UI snaps out of "just
        // started") and the final byte-count at session end.
        let mut last_progress_emit: Option<std::time::Instant> = None;
        let mut last_progress_uploaded: u64 = 0;
        // Set when the transfer is cancelled mid-send via UI; the inner
        // parts-send loop breaks, then the outer session loop sees this
        // flag and terminates the connection, letting all the normal
        // cleanup (slot guard drop, queue retain, completion event) run.
        let mut user_cancelled = false;
        let mut slot_guard = UploadSlotGuard::new(self.active_count.clone(), self.slot_notify.clone());
        let mut session_start: Option<std::time::Instant> = None;
        let mut rate_tracker = SessionRateTracker::new();
        // (SecureIdent state `pending_secident_challenge` / `pending_peer_challenge`
        // declared above the EmuleInfo exchange block so the proactive
        // challenge there can populate `pending_secident_challenge`.)
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

        // Time-of-last-useful-peer-activity gauge. The read-side
        // `tokio::time::timeout(SLOT_IDLE_TIMEOUT_SECS, pkt_rx.recv())`
        // resets on every packet, so a peer that holds a slot but
        // sends only chatter (mod-specific keepalives, OP_REASKFILEPING,
        // unknown opcodes) was able to pin the slot indefinitely while
        // never actually requesting more parts. This gauge is bumped
        // ONLY when the peer requests data (`OP_REQUESTPARTS` /
        // `_I64`); the per-loop gate below rotates the slot when no
        // such request has arrived in `SLOT_IDLE_TIMEOUT_SECS`,
        // independent of how chatty the peer is otherwise. Visible
        // symptom before this fix: an upload row that sat at a few
        // hundred KB transferred with status "Transferring" for many
        // minutes and only cleared when the app closed.
        let mut last_part_request: std::time::Instant = std::time::Instant::now();

        // Diagnostic: when the last per-session heartbeat log was emitted,
        // and how many outer-loop iterations have run since the session
        // began. If a field trace shows the row stuck in "Transferring"
        // but the iteration counter is frozen at the same value across
        // multiple heartbeats, we're stranded inside an inner serving
        // loop (e.g. OP_REQUESTPARTS backpressure on a peer that barely
        // reads) rather than idling at the outer `tokio::time::timeout`.
        // Conversely, an iteration counter that climbs while
        // `last_part_request` ages past SLOT_IDLE_TIMEOUT_SECS points at
        // a gate logic bug. Either reading is decisive.
        let mut last_heartbeat_log: Option<std::time::Instant> = None;
        let mut outer_loop_iterations: u64 = 0;
        let session_open_at: std::time::Instant = std::time::Instant::now();

        // Session-local caches populated lazily on OP_REQUESTPARTS and reused
        // across batches / blocks so we don't re-open the serve file, re-read
        // the `.part.met`, or re-compute the video-extension flag for every
        // 180 KiB block.
        //
        // - `cached_serve_file`: persistent `std::fs::File` handle keyed on
        //   file path, moved in/out of `spawn_blocking` per read (tokio tasks
        //   need `'static` owned values). Under steady state this replaces
        //   `File::open + seek + read_exact + close` per block with just
        //   `seek + read_exact` per block, saving one open/close syscall and
        //   one FD allocation per ~180 KiB.
        // - `cached_part_tracker`: reused across batches on the same file.
        //   Rebuilt every `PART_TRACKER_REFRESH` so that newly-completed
        //   parts of a partial file (when we are both uploading and
        //   downloading it) become advertisable within a bounded delay.
        // - `cached_is_video_ext`: cheap bool, hoisted out of the per-block
        //   loop in OP_REQUESTPARTS.
        //
        // All three are keyed on `PathBuf` rather than `file_hash` so they
        // survive the `current_file_hash = Some(same_hash)` reassigns that
        // happen after every handshake opcode; they invalidate when the peer
        // switches to a different file path mid-session.
        let mut cached_serve_file: Option<(PathBuf, std::fs::File)> = None;
        let mut cached_part_tracker: Option<(PathBuf, super::part_tracker::PartTracker, std::time::Instant)>
            = None;
        let mut cached_is_video_ext: Option<(PathBuf, bool)> = None;
        const PART_TRACKER_REFRESH: std::time::Duration = std::time::Duration::from_secs(2);

        // Dedicated reader task: ed2k framing requires four sequential awaits
        // (proto, length, opcode, payload). The main loop uses tokio::select!
        // to race the next packet against outbound writes, and select! cancels
        // the losing future. If it cancelled read_packet_async_inner mid-packet
        // we'd resume on the next iteration with the stream positioned in the
        // middle of a frame, causing desync and connection loss. Moving the
        // read into its own task keeps frame state private; the select! site
        // consumes whole packets from a channel and is trivially cancel-safe.
        let (pkt_tx, mut pkt_rx) = tokio::sync::mpsc::channel::<std::io::Result<(u8, u8, Vec<u8>)>>(4);
        let reader_task = tokio::spawn(async move {
            loop {
                let res = read_packet_async_inner(&mut reader).await;
                let was_err = res.is_err();
                if pkt_tx.send(res).await.is_err() {
                    break;
                }
                if was_err {
                    break;
                }
            }
        });

        // Periodic EPX resend cadence inside the upload session. eMule peers
        // that download from us may stay connected for hours seeding/queueing,
        // and during that time our shared payload typically rebuilds many
        // times as we discover new sources/Ember peers. Without this loop,
        // the only EPX they ever see is the one snapshot at handshake. 5 min
        // matches the cadence used by `multi_source.rs` and `transfer.rs`
        // for the symmetric "we're downloading" direction.
        const EPX_RESEND_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

        // Wrap the outer packet loop in an `async { ... }.await` so that any
        // `.await?` inside propagates into `session_result` instead of
        // straight out of `handle_connection`. The cleanup block below
        // (slot_rates removal, Ember session record, terminal
        // `UploadEventKind::Completed`/`Failed` emit) used to be bypassed
        // whenever a nested `?` fired — leaving the row pinned in the UI
        // "Transferring" pane until the app restarted. The concrete
        // repro was aMule 2.3.3 peers that stop reading mid-transfer:
        // `write_packet_async` hits its 60 s `WRITE_PACKET_TIMEOUT`, the
        // `?` aborts the handler, and the frontend never gets the
        // `transfer-complete` event it needs to drop the row. With this
        // wrap the cleanup always runs; `session_result` is returned at
        // the end of the function so the accept-loop's
        // `warn!("Connection from ... ended: {e}")` still surfaces the
        // underlying cause.
        let session_result: anyhow::Result<()> = async {
        loop {
            // eMule: terminate upload sessions when the network is disconnected.
            if self.network_disconnected.load(std::sync::atomic::Ordering::Relaxed) {
                debug!("Terminating upload session with {peer_addr}: network disconnected");
                break;
            }
            // User cancelled this transfer via the UI. The inner parts-send
            // loop flips `user_cancelled` and breaks; this check makes sure
            // we also leave the outer packet loop so the connection closes
            // and all shared cleanup at function exit runs.
            if user_cancelled {
                break;
            }

            // No-useful-activity rotation gate. The read-side timeout
            // resets on every packet — even ones we ignore (mod-
            // specific opcodes, unrecognised keepalives, etc.). A
            // peer that holds a slot but never sends OP_REQUESTPARTS
            // would sit "Transferring" forever as long as it kept any
            // packet trickle alive.
            //
            // Two independent triggers:
            //
            //   * `slot_guard.is_active()` — peer holds a slot. We
            //     want to rotate after SLOT_IDLE_TIMEOUT_SECS of no
            //     useful activity even if the read side keeps getting
            //     bumped by chatter.
            //
            //   * `uploaded > 0` — we already moved bytes for this
            //     peer this session, so they exist in the UI's
            //     "Transferring" pane. If the slot deactivated for
            //     any reason (session preemption, score rotation)
            //     but the connection is still up because the peer
            //     keeps sending chatter, the row would otherwise
            //     stay pinned at its last `transferred` value
            //     until the much-coarser `CLIENT_TIMEOUT_SECS`
            //     expired. The eMule Plus 1.2.5 case in the field
            //     hit exactly this combination — slot dropped
            //     after a couple of blocks but the peer kept the
            //     socket alive with non-REQUESTPARTS traffic.
            if (slot_guard.is_active() || uploaded > 0)
                && last_part_request.elapsed().as_secs() >= SLOT_IDLE_TIMEOUT_SECS
            {
                info!(
                    "Upload to {peer_addr} idle >{SLOT_IDLE_TIMEOUT_SECS}s with no useful \
                     activity (slot_active={}, uploaded={uploaded}B, \
                     last_part_request={}s ago, iterations={outer_loop_iterations}) — closing",
                    slot_guard.is_active(),
                    last_part_request.elapsed().as_secs(),
                );
                break;
            }

            // Diagnostic heartbeat. Fires at most once per
            // UPLOAD_HEARTBEAT_INTERVAL per session, and only for
            // sessions that have either a granted slot or non-zero
            // uploaded bytes (i.e. the ones that could plausibly
            // appear in the UI as "Transferring"). The tuple logged
            // here is exactly the information needed to distinguish
            // "outer loop frozen inside an inner serving routine"
            // (iterations stop climbing) from "outer loop iterating
            // but gate logic failing to fire" (iterations climb but
            // last_part_request keeps aging past the threshold).
            outer_loop_iterations = outer_loop_iterations.saturating_add(1);
            if (slot_guard.is_active() || uploaded > 0)
                && last_heartbeat_log
                    .map(|t| t.elapsed() >= UPLOAD_HEARTBEAT_INTERVAL)
                    .unwrap_or(true)
            {
                last_heartbeat_log = Some(std::time::Instant::now());
                info!(
                    target: "ember::upload_diag",
                    "heartbeat {peer_addr} slot_active={} uploaded={uploaded}B \
                     last_part_req={}s session_age={}s iters={outer_loop_iterations} \
                     tid={}",
                    slot_guard.is_active(),
                    last_part_request.elapsed().as_secs(),
                    session_open_at.elapsed().as_secs(),
                    transfer_id.as_deref().unwrap_or("-"),
                );
            }

            // Re-share EPX with Ember peers when our shared payload has
            // been rebuilt since we last sent. The check is two atomic
            // loads + a compare; cheap enough to do every loop iteration
            // (worst case: a 1s queued tick). We deliberately gate on
            // `is_ember` so non-Ember peers never see the OP_EMBER_*
            // opcode.
            if hello_caps.is_ember && last_epx_resend.elapsed() >= EPX_RESEND_INTERVAL {
                let current_gen = self
                    .ember_payload_generation
                    .load(std::sync::atomic::Ordering::Relaxed);
                if current_gen != last_epx_generation {
                    let epx_data = self.ember_payload.read().await.clone();
                    if !epx_data.is_empty() {
                        debug!(
                            "Re-sending EPX to {peer_addr} (gen {}->{}, {} bytes)",
                            last_epx_generation, current_gen, epx_data.len()
                        );
                        if write_packet_async(
                            &mut writer,
                            OP_EMULEPROT,
                            OP_EMBER_SOURCEEXCHANGE,
                            &*epx_data,
                        )
                        .await
                        .is_ok()
                        {
                            last_epx_generation = current_gen;
                            self.sx_overhead.record_upload((6 + epx_data.len()) as u64);
                        }
                    }
                }
                last_epx_resend = std::time::Instant::now();
            }

            let (proto, opcode, payload) = if let Some(pkt) = deferred_packet.take() {
                pkt
            } else {
                // Shorter timeout once a slot is actively granted — a
                // peer that stops requesting parts is almost certainly
                // gone, and holding their slot blocks the queue. See
                // `SLOT_IDLE_TIMEOUT_SECS` for the rationale; the full
                // `CLIENT_TIMEOUT_SECS` is still used during the
                // discovery / secident / hello phase where long silences
                // are normal, and for plain queued peers we poll every
                // 1s to re-evaluate promotion / rank updates.
                let wait_secs = if queued_identity.is_some() {
                    1
                } else if owns_ember_slot {
                    90
                } else if slot_guard.is_active() {
                    SLOT_IDLE_TIMEOUT_SECS
                } else {
                    CLIENT_TIMEOUT_SECS
                };
                let timeout_dur = std::time::Duration::from_secs(wait_secs);
                let read_result = tokio::select! {
                    r = tokio::time::timeout(timeout_dur, pkt_rx.recv()) => r,
                    Some(outbound_data) = outbound_rx.recv() => {
                        if writer.write_all(&outbound_data).await.is_ok() {
                            let _ = writer.flush().await;
                        }
                        continue;
                    }
                };

                match read_result {
                    Ok(Some(Ok(p))) => p,
                    Ok(Some(Err(e))) => {
                        info!(
                            target: "ember::upload_diag",
                            "session_end {peer_addr} reason=peer_disconnected err={e} \
                             uploaded={uploaded}B last_part_req={}s \
                             session_age={}s iters={outer_loop_iterations}",
                            last_part_request.elapsed().as_secs(),
                            session_open_at.elapsed().as_secs(),
                        );
                        break;
                    }
                    Ok(None) => {
                        info!(
                            target: "ember::upload_diag",
                            "session_end {peer_addr} reason=reader_task_ended \
                             uploaded={uploaded}B last_part_req={}s \
                             session_age={}s iters={outer_loop_iterations}",
                            last_part_request.elapsed().as_secs(),
                            session_open_at.elapsed().as_secs(),
                        );
                        break;
                    }
                    Err(_) => {
                        if let Some(ref queued_key) = queued_identity {
                            let current_active = self
                                .active_count
                                .load(std::sync::atomic::Ordering::Relaxed);
                            let dynamic_slots = self.compute_dynamic_slot_count();

                            if current_active < dynamic_slots {
                                // Snapshot queue entries and release lock before acquiring RwLocks.
                                // Purge stale entries (eMule MAX_PURGEQUEUETIME) first so
                                // this periodic rank/grant path respects the same TTL as
                                // STARTUPLOADREQ; otherwise a peer that only holds the TCP
                                // session open can live in the queue past the 1-hour cap.
                                let queue_snapshot: Vec<_> = {
                                    let mut queue = self.upload_queue.lock().await;
                                    queue.retain(|e| {
                                        e.join_time.elapsed().as_secs() < MAX_PURGEQUEUETIME_SECS
                                    });
                                    queue.iter().enumerate().map(|(i, e)| {
                                        (i, e.identity.clone(), e.current_addr, e.join_time, e.file_hash, e.user_hash, e.emule_version, e.is_friend_slot, e.ember_pubkey, e.ember_verified)
                                    }).collect()
                                };
                                let cm = self.credit_manager.read().await;
                                let idx_snap = self.local_index.read().await;
                                let mut best_idx: Option<usize> = None;
                                let mut best_identity = None;
                                let mut best_score = f64::MIN;
                                for &(i, ref identity, current_addr, join_time, file_hash, ref user_hash, emule_version, is_friend_slot, ref ember_pubkey, ember_verified) in &queue_snapshot {
                                    if current_addr.is_none() {
                                        continue;
                                    }
                                    let score = score_queue_entry(
                                        &cm, &idx_snap, user_hash, file_hash,
                                        join_time.elapsed().as_secs(), current_addr,
                                        emule_version, is_friend_slot,
                                        ember_pubkey.as_ref(), ember_verified,
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
                                        // Reset the useful-activity gauge on slot grant
                                        // so a freshly-promoted peer gets the full
                                        // SLOT_IDLE_TIMEOUT_SECS window to send their
                                        // first OP_REQUESTPARTS.
                                        last_part_request = std::time::Instant::now();

                                        if let Some(hash) = current_file_hash {
                                            let tid = uuid::Uuid::new_v4().to_string();
                                            transfer_id = Some(tid.clone());
                                            // Reset the Progress throttle for this new
                                            // session so the first chunk we send always
                                            // produces an immediate UI update instead
                                            // of waiting for the 200 ms coalesce window
                                            // to elapse.
                                            last_progress_emit = None;
                                            last_progress_uploaded = 0;

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
                                                        user_hash: if peer_user_hash != [0u8; 16] { Some(hex::encode(peer_user_hash)) } else { None },
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
                                // Gate friend-slot priority on verified PoP:
                                // `is_friend` alone only means the peer claims
                                // a hash we know; `is_verified` means they
                                // signed a nonce on THIS session with the
                                // matching Ed25519 key. Re-evaluate here
                                // rather than capturing once because
                                // `ember_auth_state` can advance from
                                // `NotStarted` → `Verified` mid-session as
                                // the peer's CHALLENGE/RESPONSE arrives.
                                let is_verified_friend = is_friend && ember_auth_state.is_verified();
                                let ember_verified = ember_auth_state.is_verified();
                                let my_score = score_queue_entry(
                                    &cm, &idx_snap, &peer_user_hash,
                                    current_file_hash.unwrap_or([0u8; 16]),
                                    queue_join_time.elapsed().as_secs(),
                                    Some(peer_addr), hello_caps.emule_version_min,
                                    is_verified_friend,
                                    hello_caps.ember_pubkey.as_ref(), ember_verified,
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
                        // Distinguish the two cases for operators: an
                        // active-slot idle timeout means the peer stopped
                        // requesting blocks while holding a slot (we'll
                        // rotate to the next queued peer), while a
                        // pre-grant timeout means the peer never
                        // progressed through the handshake. Either way,
                        // the function-exit cleanup at the end of
                        // `handle_connection` emits the appropriate
                        // `Completed` / `Failed` UploadEvent.
                        if slot_guard.is_active() {
                            info!(
                                target: "ember::upload_diag",
                                "session_end {peer_addr} reason=slot_idle_timeout \
                                 uploaded={uploaded}B last_part_req={}s \
                                 session_age={}s iters={outer_loop_iterations}",
                                last_part_request.elapsed().as_secs(),
                                session_open_at.elapsed().as_secs(),
                            );
                        } else {
                            info!(
                                target: "ember::upload_diag",
                                "session_end {peer_addr} reason=pre_grant_timeout \
                                 uploaded={uploaded}B session_age={}s \
                                 iters={outer_loop_iterations}",
                                session_open_at.elapsed().as_secs(),
                            );
                        }
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

                        // Replay any SECIDENTSTATE the peer sent us before
                        // we had their key. Now that their key is stored,
                        // `respond_to_secident_challenge` can sign the
                        // challenge over `peer_pub_key || challenge` and
                        // ship the OP_SIGNATURE they've been waiting on —
                        // the piece that, when missing, leaves eMule
                        // stuck in IS_IDNEEDED / IS_IDFAILED and renders
                        // "Identification: Invalid".
                        if let Some((challenge, state)) = pending_peer_challenge.take() {
                            // Pass our actual public IPv4 (from
                            // `external_ip_shared`) so the signed
                            // response selects CRYPT_CIP_LOCALCLIENT
                            // consistently with our HighID Hello
                            // advertisement. Hardcoding 0 here was a
                            // leftover from when this handler didn't
                            // know our external IP and forced every
                            // signed response into REMOTECLIENT mode —
                            // which verifies fine but advertises us as
                            // LowID for SecIdent purposes, blocking
                            // peers from caching our credit record
                            // under our public IP.
                            let our_client_id = self
                                .external_ip_shared
                                .load(std::sync::atomic::Ordering::Relaxed);
                            super::transfer::respond_to_secident_challenge(
                                &mut writer,
                                Some(&self.credit_manager),
                                state,
                                challenge,
                                peer_addr,
                                peer_user_hash,
                                peer_secure_ident_level,
                                our_client_id,
                            ).await?;
                            debug!("Replayed deferred SecIdent challenge response to {peer_addr}");
                        }

                        // Only challenge them for our own identity if we
                        // haven't already sent one (the proactive kick-off
                        // after EmuleInfoAnswer normally covers this) —
                        // otherwise a second OP_SECIDENTSTATE confuses the
                        // peer's state machine (eMule only tracks one
                        // outstanding `m_dwCryptRndChallengeFor`).
                        if pending_secident_challenge.is_none() {
                            pending_secident_challenge = super::transfer::maybe_send_secident_challenge(
                                &mut writer,
                                Some(&self.credit_manager),
                                peer_user_hash,
                                peer_addr,
                                peer_secure_ident_level,
                            ).await?;
                        }
                        debug!("Received public key from {peer_addr}");
                    }
                }

                (OP_EMULEPROT, OP_SECIDENTSTATE) if payload.len() >= 5 => {
                    let state = payload[0];
                    let challenge =
                        u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);

                    // We can only sign the peer's challenge if we already
                    // have their RSA public key cached — our signature is
                    // over `peer_pub_key || challenge`, same as eMule's
                    // CClientCreditsList::CreateSignature. On a first-time
                    // connection we won't have their key yet (eMule ships
                    // OP_PUBLICKEY only in response to our own
                    // OP_SECIDENTSTATE). Park the challenge in
                    // `pending_peer_challenge` and let the OP_PUBLICKEY
                    // handler replay the whole OP_PUBLICKEY + OP_SIGNATURE
                    // response once their key lands. Matching transfer.rs
                    // we skip the immediate send entirely on defer —
                    // eMule's SendSignaturePacket won't fire for our
                    // outgoing SECIDENTSTATE challenge until it sees our
                    // OP_PUBLICKEY anyway (BaseClient.cpp:1851), so there's
                    // no timing benefit to sending ours twice.
                    let missing_peer_key = if state >= 2 {
                        let cm = self.credit_manager.read().await;
                        !cm.has_public_key(&peer_user_hash)
                    } else {
                        false
                    };
                    if missing_peer_key {
                        pending_peer_challenge = Some((challenge, state));
                        debug!(
                            "Deferred SecIdent challenge from {peer_addr} — awaiting their public key"
                        );
                    } else {
                        // See the OP_PUBLICKEY handler above — pass our
                        // public IP so the signed response uses
                        // CRYPT_CIP_LOCALCLIENT when we're HighID
                        // instead of always REMOTECLIENT.
                        let our_client_id = self
                            .external_ip_shared
                            .load(std::sync::atomic::Ordering::Relaxed);
                        super::transfer::respond_to_secident_challenge(
                            &mut writer,
                            Some(&self.credit_manager),
                            state,
                            challenge,
                            peer_addr,
                            peer_user_hash,
                            peer_secure_ident_level,
                            our_client_id,
                        ).await?;
                        debug!("Responded to SecIdent challenge from {peer_addr}");
                    }
                }

                (OP_EMULEPROT, OP_SIGNATURE) if payload.len() >= 2 => {
                    // Reuse the shared verification helper instead of an
                    // inline copy. The previous inline path passed `0`
                    // as `local_ip_for_remoteclient`, which silently
                    // broke verification for any LowID peer that signed
                    // in CRYPT_CIP_REMOTECLIENT mode (their signature
                    // includes our public IP). Failed verification
                    // flips them to `IdentState::Failed`, which then
                    // blocks upload-credit accrual for the rest of the
                    // session even though the peer's signature was
                    // actually valid. The helper computes `local_ip`
                    // from `our_client_id` the same way transfer.rs
                    // does for downloads.
                    let our_client_id = self
                        .external_ip_shared
                        .load(std::sync::atomic::Ordering::Relaxed);
                    super::transfer::handle_secident_signature(
                        Some(&self.credit_manager),
                        peer_user_hash,
                        &mut pending_secident_challenge,
                        peer_addr,
                        peer_secure_ident_level,
                        &payload,
                        our_client_id,
                    ).await;
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
                            // and build an accurate bitmap from PartTracker.
                            //
                            // IMPORTANT: the bitmap must match our serving policy,
                            // not our download progress. We only serve bytes
                            // that pass `is_range_safe_to_serve`, which requires
                            // each part to be BOTH complete AND MD4-verified
                            // (see `part_tracker.rs:181`). Advertising a part
                            // that's complete-but-unverified creates a "dead
                            // upload" condition: the peer sees the bit set,
                            // requests blocks from that part, and every
                            // OP_REQUESTPARTS gets silently rejected at the
                            // serve gate. The UI row shows "Started" with no
                            // progress and the session sits open until the
                            // peer eventually disconnects — exactly the
                            // "uploads freeze in the UI" symptom. Gate the
                            // advertised bitmap on the same condition the
                            // serve path uses so the peer only ever asks for
                            // ranges we're willing to send.
                            if file.is_partial && file.size > 0 {
                                let tracker = super::part_tracker::PartTracker::new(file.size, &file.path);
                                for byte_idx in 0..bitmap_bytes {
                                    let mut byte = 0u8;
                                    for bit in 0..8 {
                                        let part_idx = byte_idx * 8 + bit;
                                        if part_idx < ed2k_part_count as usize
                                            && tracker.is_part_complete(part_idx)
                                            && tracker.is_part_verified(part_idx)
                                        {
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

                    // Duplicate OP_STARTUPLOADREQ on an already-granted session.
                    // eMule/Ember peers occasionally re-send STARTUPLOADREQ after
                    // they've already received OP_ACCEPTUPLOADREQ — e.g. in
                    // response to an unexpected QUEUERANKING, or as a soft
                    // retry during an early handshake race. The handler below
                    // unconditionally runs `slot_guard.activate()`, resets
                    // `uploaded = 0`, mints a fresh `transfer_id`, and fires a
                    // new `Started` event. That orphans the original
                    // transfer_id (the UI row never receives a terminal
                    // event), doubles up the row in the transfers window,
                    // and — combined with the OP_CANCELTRANSFER /
                    // OP_END_OF_DOWNLOAD path below — makes the stranded
                    // first row snap to "Complete" with the full file size
                    // even though zero bytes went out on it. Re-ack and keep
                    // the existing session intact instead.
                    if slot_guard.is_active() && transfer_id.is_some() {
                        write_packet_async(
                            &mut writer,
                            OP_EDONKEYHEADER,
                            OP_ACCEPTUPLOADREQ,
                            &[],
                        )
                        .await?;
                        continue;
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
                                 e.user_hash, e.emule_version, e.is_friend_slot, e.add_next_connect,
                                 e.ember_pubkey, e.ember_verified)
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
                            for &(i, ref _identity, current_addr, join_time, file_hash, ref user_hash, emule_version, is_friend_slot, add_next_connect, ref ember_pubkey, ember_verified) in &queue_snapshot {
                                let score = score_queue_entry(
                                    &cm, &idx_snap, user_hash, file_hash,
                                    join_time.elapsed().as_secs(), current_addr,
                                    emule_version, is_friend_slot,
                                    ember_pubkey.as_ref(), ember_verified,
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
                        // Friend-slot priority requires proof-of-possession
                        // on THIS TCP session (`ember_auth_state.is_verified()`).
                        // Merely claiming a friend's hash (`is_friend`) is
                        // not enough — otherwise a spoofer who observed
                        // the hash on the wire could ride friend priority.
                        // We evaluate this fresh at every queue-insertion /
                        // scoring site because `ember_auth_state` can
                        // advance mid-session as the peer's auth packets
                        // arrive.
                        let is_verified_friend = is_friend && ember_auth_state.is_verified();
                        let mut queue = self.upload_queue.lock().await;
                        let rank = if let Some(pos) =
                            queue.iter().position(|e| e.identity == queue_identity)
                        {
                            queue[pos].current_addr = Some(peer_addr);
                            queue[pos].user_hash = peer_user_hash;
                            queue[pos].file_hash = current_file_hash.unwrap_or([0u8; 16]);
                            // If the peer has since completed PoP, upgrade
                            // an existing queue entry's friend-slot flag
                            // (it may have been added while auth was still
                            // pending). Never downgrade: if the entry is
                            // already marked is_friend_slot from a prior
                            // verified state on the same session, leave it.
                            if is_verified_friend {
                                queue[pos].is_friend_slot = true;
                            }
                            let cm = self.credit_manager.read().await;
                            let idx_snap = self.local_index.read().await;
                            let ember_verified = ember_auth_state.is_verified();
                            let my_score = score_queue_entry(
                                &cm, &idx_snap, &peer_user_hash,
                                current_file_hash.unwrap_or([0u8; 16]),
                                queue[pos].join_time.elapsed().as_secs(),
                                Some(peer_addr), hello_caps.emule_version_min,
                                is_verified_friend,
                                hello_caps.ember_pubkey.as_ref(), ember_verified,
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
                            let ember_verified = ember_auth_state.is_verified();
                            let new_score = score_queue_entry(
                                &cm, &idx_snap, &peer_user_hash, new_fh,
                                0, Some(peer_addr), hello_caps.emule_version_min,
                                is_verified_friend,
                                hello_caps.ember_pubkey.as_ref(), ember_verified,
                            );
                            let avg_score = if queue.is_empty() { 0.0 } else {
                                let total: f64 = queue.iter().map(|e| {
                                    score_queue_entry(
                                        &cm, &idx_snap, &e.user_hash, e.file_hash,
                                        e.join_time.elapsed().as_secs(), e.current_addr,
                                        e.emule_version, e.is_friend_slot,
                                        e.ember_pubkey.as_ref(), e.ember_verified,
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
                                    is_friend_slot: is_verified_friend,
                                    ember_pubkey: hello_caps.ember_pubkey,
                                    ember_verified,
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
                            let ember_verified = ember_auth_state.is_verified();
                            queue.push(QueueEntry {
                                identity: queue_identity.clone(),
                                current_addr: Some(peer_addr),
                                user_hash: peer_user_hash,
                                file_hash: new_fh,
                                join_time,
                                add_next_connect: false,
                                emule_version: hello_caps.emule_version_min,
                                is_friend_slot: is_verified_friend,
                                ember_pubkey: hello_caps.ember_pubkey,
                                ember_verified,
                            });
                            let my_score = score_queue_entry(
                                &cm, &idx_snap, &peer_user_hash, new_fh,
                                0, Some(peer_addr), hello_caps.emule_version_min,
                                is_verified_friend,
                                hello_caps.ember_pubkey.as_ref(), ember_verified,
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
                    // Reset the useful-activity gauge on slot grant — see
                    // sibling activate() above for rationale.
                    last_part_request = std::time::Instant::now();

                    if let Some(hash) = current_file_hash {
                        let tid = uuid::Uuid::new_v4().to_string();
                        transfer_id = Some(tid.clone());
                        // Reset the Progress throttle for this new session
                        // so the first chunk's Progress event is emitted
                        // immediately rather than coalesced.
                        last_progress_emit = None;
                        last_progress_uploaded = 0;

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
                                user_hash: if peer_user_hash != [0u8; 16] { Some(hex::encode(peer_user_hash)) } else { None },
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
                        debug!(
                            target: "ember::upload_diag",
                            "reqparts_rejected {peer_addr} slot_inactive uploaded={uploaded}B \
                             last_part_req={}s",
                            last_part_request.elapsed().as_secs(),
                        );
                        write_packet_async(
                            &mut writer,
                            OP_EDONKEYHEADER,
                            OP_OUTOFPARTREQS,
                            &[],
                        )
                        .await?;
                        continue;
                    }

                    // Diagnostic: time the whole batch so we can correlate
                    // "peer sent REQUESTPARTS but we never responded in
                    // reasonable time" with the slow-write log below.
                    let req_batch_start = std::time::Instant::now();

                    let offsets = if opcode == OP_REQUESTPARTS_I64 {
                        parse_request_parts_i64(&payload)?
                    } else {
                        parse_request_parts_32(&payload)?
                    };
                    let raw_offset_count = offsets.len();

                    let mut offsets: Vec<(u64, u64)> = offsets
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

                    // Merge *overlapping* ranges before sending (not merely
                    // adjacent ones). eMule-family peers normally send 3
                    // disjoint EMBLOCKSIZE-sized block requests per
                    // OP_REQUESTPARTS, and those blocks are contiguous —
                    // e.g. (0, 180K) (180K, 360K) (360K, 540K). A buggy or
                    // malicious peer can re-request the same offset twice;
                    // without deduping we'd double-count bytes in the
                    // upload progress counter and the credit ledger,
                    // inflating the peer's credit ratio and the UI
                    // "transferred" stat. Use strict `<` so contiguous
                    // ranges stay as separate entries: fusing them lets a
                    // single OP_SENDINGPART cover all three blocks, and
                    // the downloader counts block responses per packet
                    // (see `multi_source.rs` `blocks_received_in_current_req`).
                    // With the old `<=` the downloader's refill logic
                    // stalled after the first 540 KB and the outer
                    // per-part loop ran out of work, so the peer sent
                    // OP_END_OF_DOWNLOAD after ~one batch and the session
                    // ended far short of the file.
                    if offsets.len() > 1 {
                        offsets.sort_by_key(|&(s, _)| s);
                        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(offsets.len());
                        for (s, e) in offsets {
                            if let Some(last) = merged.last_mut() {
                                if s < last.1 {
                                    if e > last.1 { last.1 = e; }
                                    continue;
                                }
                            }
                            merged.push((s, e));
                        }
                        offsets = merged;
                    }

                    // Belt-and-suspenders: split any range larger than
                    // EMBLOCKSIZE back into per-block pieces before we
                    // serve it. Under normal peer behaviour the merge
                    // above is a no-op on a sorted list of EMBLOCKSIZE
                    // requests, but a peer that *does* legitimately ask
                    // for more than one block in a single range entry
                    // (or an attacker that sends overlapping ranges we
                    // had to collapse into one big range) would still
                    // go out as a single OP_SENDINGPART — and the
                    // downloader's block counter is per-packet, not
                    // per-byte. Emitting one packet per EMBLOCKSIZE
                    // keeps the downloader's pipeline-refill logic
                    // happy no matter what shape the request came in.
                    if offsets.iter().any(|&(s, e)| e - s > EMBLOCKSIZE) {
                        let mut split: Vec<(u64, u64)> = Vec::with_capacity(offsets.len() * 3);
                        for (s, e) in offsets {
                            let mut cur = s;
                            while cur < e {
                                let next = (cur + EMBLOCKSIZE).min(e);
                                split.push((cur, next));
                                cur = next;
                            }
                        }
                        offsets = split;
                    }

                    // Diagnostic: summarise the batch shape for this REQUESTPARTS
                    // before we touch the disk. A peer sending REQUESTPARTS with
                    // all ranges filtered away (past EOF, zero-length, etc.) lands
                    // here with `offsets.is_empty()` and no bytes will move — the
                    // `last_part_request` gauge below won't be bumped, so the
                    // session will eventually time out via SLOT_IDLE_TIMEOUT. If
                    // the field log shows these repeatedly followed by silence,
                    // it's diagnosis-useful to see the raw count / ranges that
                    // arrived from the peer.
                    let total_bytes_requested: u64 =
                        offsets.iter().map(|&(s, e)| e.saturating_sub(s)).sum();
                    debug!(
                        target: "ember::upload_diag",
                        "reqparts_in {peer_addr} raw_offsets={raw_offset_count} \
                         after_filter_merge_split={} total_bytes={total_bytes_requested} \
                         uploaded={uploaded}B last_part_req={}s",
                        offsets.len(),
                        last_part_request.elapsed().as_secs(),
                    );

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
                    let file_path = resolved.path;

                    // Refresh-or-reuse the cached `PartTracker` for the
                    // current file. Rebuilt after PART_TRACKER_REFRESH so
                    // newly-completed parts of a partial file we're
                    // simultaneously downloading become advertisable within
                    // a bounded delay. Outside of that window we reuse the
                    // parsed tracker across batches and blocks — the old
                    // code re-read `.part.met` on every OP_REQUESTPARTS.
                    let is_partial_serve =
                        file_path.extension().map(|e| e == "part").unwrap_or(false)
                        && total_size > 0;
                    if !is_partial_serve {
                        cached_part_tracker = None;
                    } else {
                        let need_rebuild = match cached_part_tracker.as_ref() {
                            Some((p, _, at)) => {
                                p != &file_path || at.elapsed() >= PART_TRACKER_REFRESH
                            }
                            None => true,
                        };
                        if need_rebuild {
                            cached_part_tracker = Some((
                                file_path.clone(),
                                super::part_tracker::PartTracker::new(total_size, &file_path),
                                std::time::Instant::now(),
                            ));
                        }
                    }
                    let part_tracker_ref = cached_part_tracker.as_ref().map(|(_, t, _)| t);

                    // Hoist video-ext computation out of the per-block loop:
                    // it's a property of the file, not the block, and
                    // `to_lowercase()` allocates a fresh String per call.
                    if cached_is_video_ext.as_ref().map(|(p, _)| p != &file_path).unwrap_or(true) {
                        let is_video = file_path.extension()
                            .and_then(|e| e.to_str())
                            .map(|e| {
                                let e = e.to_lowercase();
                                matches!(e.as_str(), "avi" | "mp4" | "mkv" | "wmv" | "mpg" |
                                    "mpeg" | "mov" | "flv" | "webm" | "m4v" | "divx" | "ts" | "vob")
                            })
                            .unwrap_or(false);
                        cached_is_video_ext = Some((file_path.clone(), is_video));
                    }
                    let is_video_ext = cached_is_video_ext.as_ref().map(|(_, v)| *v).unwrap_or(false);

                    // Drop a stale cached File handle if the peer switched to
                    // a different file within this TCP session. We also
                    // DO NOT cache the handle for `.part` files: on Windows,
                    // holding a read handle open across a long-lived upload
                    // session would block the concurrent download side's
                    // `std::fs::rename(.part -> final)` when the file
                    // completes (see `ed2k::transfer::move_part_to_final`).
                    // Opening per block for partial-file seeds only loses a
                    // few microseconds on the hot path and keeps the classic
                    // race window (microseconds between close and the
                    // download's rename) unchanged.
                    if is_partial_serve {
                        cached_serve_file = None;
                    } else if cached_serve_file
                        .as_ref()
                        .map(|(p, _)| p != &file_path)
                        .unwrap_or(false)
                    {
                        cached_serve_file = None;
                    }

                    // Batch credit and slot-rate accumulators. The old code
                    // took `credit_manager.write().await` (an async RwLock)
                    // and `slot_rates.lock()` (a std Mutex) per block — with
                    // K concurrent slots that's K lock acquires per block
                    // wire-time. One per OP_REQUESTPARTS batch is equivalent
                    // for scoring purposes (credits are a cumulative u64;
                    // slot_rate is a smoothed EWMA that doesn't need
                    // block-granular updates).
                    let mut batch_credited_bytes: u64 = 0;

                    // Diagnostic: per-batch back-pressure counters.
                    // Each individual OP_SENDINGPART / OP_COMPRESSEDPART
                    // packet has its own elapsed timer so we can
                    // distinguish "kernel SO_SNDBUF is backing up
                    // because peer stopped reading" (large `slowest_write`)
                    // from "we're CPU-bound compressing" (many packets,
                    // all fast). `write_packet_async` already has a
                    // 60 s hard stop — anything shorter but above
                    // UPLOAD_SLOW_WRITE_THRESHOLD is an early warning
                    // that the session is stalling even though bytes
                    // are technically still moving.
                    let mut slowest_write: std::time::Duration =
                        std::time::Duration::ZERO;
                    let mut slow_writes_this_batch: u32 = 0;
                    let mut packets_this_batch: u32 = 0;

                    for (start, end) in offsets {
                        if start >= end {
                            continue;
                        }

                        if let Some(tracker) = part_tracker_ref {
                            // Only serve bytes that are BOTH complete AND
                            // MD4-verified. Serving unverified-but-complete
                            // bytes would let corrupt blocks (hashset not yet
                            // received, or bytes that happened to land on
                            // disk before their part's hash check) propagate
                            // back to peers. is_range_safe_to_serve covers
                            // both checks; the old gap-only check missed
                            // the verified-but-unchecked case.
                            if !tracker.is_range_safe_to_serve(start, end) {
                                warn!(
                                    "Rejected upload of incomplete or unverified range {}-{} for {}",
                                    start,
                                    end,
                                    file_path.display()
                                );
                                continue;
                            }
                        }

                        // Check if the upload was cancelled by the user.
                        // Fall out of the entire session loop so the normal
                        // cleanup at function exit still runs: UploadSlotGuard
                        // drop decrements active_count, the queue entry is
                        // removed, Ember session state is cleaned up, and a
                        // final transfer-complete event fires. The prior
                        // `return Ok(())` leaked all of that and left zombie
                        // rows in the UI queue.
                        if let Some(tid) = &transfer_id {
                            let mgr = self.transfer_manager.read().await;
                            let cancelled = !mgr.active.contains_key(tid);
                            drop(mgr);
                            if cancelled {
                                info!("Upload {tid} cancelled by user, ending session");
                                user_cancelled = true;
                                break;
                            }
                        }

                        let len = ((end - start) as usize).min(PARTSIZE as usize);

                        // Move the session-cached `File` into `spawn_blocking`
                        // (a `&mut File` isn't `'static`, so we take-and-put
                        // it back via the task return value). This reuses a
                        // single open handle across every block in the
                        // session instead of `File::open` per block — saves
                        // one open + one close syscall + one FD cycle per
                        // ~180 KiB on the hot path.
                        let taken_file = cached_serve_file.take().map(|(_, f)| f);
                        let fp_for_task = file_path.clone();
                        let read_result = tokio::task::spawn_blocking(
                            move || -> anyhow::Result<(std::fs::File, Vec<u8>)> {
                                let mut f = match taken_file {
                                    Some(f) => f,
                                    None => std::fs::File::open(&fp_for_task)?,
                                };
                                f.seek(SeekFrom::Start(start))?;
                                let mut buf = vec![0u8; len];
                                f.read_exact(&mut buf)?;
                                Ok((f, buf))
                            },
                        )
                        .await?;

                        let data = match read_result {
                            Ok((f, d)) => {
                                // Only reuse the handle across blocks for
                                // complete (non-.part) files — see the
                                // comment where `cached_serve_file` is
                                // cleared above for the Windows rename-race
                                // rationale. For partial files we drop `f`
                                // here so the next block re-opens.
                                if !is_partial_serve {
                                    cached_serve_file = Some((file_path.clone(), f));
                                }
                                d
                            }
                            Err(e) => {
                                warn!("Failed to read file chunk: {e}");
                                // Handle is gone; next iteration will re-open.
                                break;
                            }
                        };

                        // Match eMule's wire convention for block delivery:
                        // a single OP_REQUESTPARTS block (up to EMBLOCKSIZE,
                        // ~180 KiB) is split into ~10 KiB on-wire packets in
                        // both the compressed and uncompressed paths. See
                        // UploadDiskIOThread::CreateStandardPackets and
                        // CreatePackedPackets in emulesource/. Splitting:
                        //   * keeps downloaders that count "blocks received"
                        //     per-packet (rather than per-byte) happy,
                        //   * lets `acquire_upload_bandwidth` throttle at
                        //     packet granularity instead of bursting a full
                        //     block then idling,
                        //   * makes the sender-side `uploaded` counter track
                        //     bytes-on-wire within ~10 KiB instead of
                        //     ~180 KiB, which combined with the 256 KiB
                        //     SO_SNDBUF cap on the listening socket keeps
                        //     our progress close to what the peer actually
                        //     sees,
                        //   * is required for OP_COMPRESSEDPART compatibility
                        //     with older downloaders that enforce a max
                        //     packet size — eMule's format is a stream where
                        //     each packet carries the SAME start offset and
                        //     SAME total compressed size (`newsize`) and the
                        //     downloader accumulates `newsize` compressed
                        //     bytes across packets before decompressing.
                        //
                        // eMule's sizing rule (from CreateStandardPackets):
                        //   nPacketSize = (togo < 13000) ? togo : 10240
                        // i.e. if the remainder is < 13000 bytes, send it
                        // all in one packet; otherwise send exactly 10240.
                        const MAX_PACKET_DATA: usize = 10240;
                        const SMALL_PACKET_THRESHOLD: usize = 13000;

                        // Skip compression for video files when configured (eMule: dontcompressavi)
                        let use_compression = peer_compression_ver > 0
                            && data.len() > 1024
                            && !(is_video_ext
                                && self
                                    .skip_compress_video
                                    .load(std::sync::atomic::Ordering::Relaxed));
                        let mut sent_compressed = false;
                        if use_compression {
                            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                            if encoder.write_all(&data).is_ok() {
                                if let Ok(compressed) = encoder.finish() {
                                    // Only use compression if it actually saves space
                                    if compressed.len() < data.len() {
                                        let use_i64 = end > u32::MAX as u64;
                                        let newsize = compressed.len() as u32;
                                        let header_len = if use_i64 { 28 } else { 24 };
                                        let total_uncompressed = data.len() as u64;
                                        let total_compressed = compressed.len() as u64;

                                        let mut cursor = 0usize;
                                        let mut uncompressed_accounted: u64 = 0;
                                        while cursor < compressed.len() {
                                            let remaining = compressed.len() - cursor;
                                            let chunk_len = if remaining < SMALL_PACKET_THRESHOLD {
                                                remaining
                                            } else {
                                                MAX_PACKET_DATA
                                            };
                                            let chunk = &compressed[cursor..cursor + chunk_len];

                                            let mut part_payload =
                                                Vec::with_capacity(header_len + chunk_len);
                                            part_payload.extend_from_slice(&hash);
                                            if use_i64 {
                                                part_payload.extend_from_slice(&start.to_le_bytes());
                                            } else {
                                                part_payload.extend_from_slice(&(start as u32).to_le_bytes());
                                            }
                                            // Every packet in the stream repeats the
                                            // total compressed size — that's how the
                                            // downloader knows when the block ends.
                                            part_payload.extend_from_slice(&newsize.to_le_bytes());
                                            part_payload.extend_from_slice(chunk);

                                            self.acquire_upload_bandwidth(chunk_len as u64).await;
                                            let write_start = std::time::Instant::now();
                                            write_packet_async(
                                                &mut writer,
                                                OP_EMULEPROT,
                                                if use_i64 { OP_COMPRESSEDPART_I64 } else { OP_COMPRESSEDPART },
                                                &part_payload,
                                            )
                                            .await?;
                                            let write_elapsed = write_start.elapsed();
                                            packets_this_batch = packets_this_batch.saturating_add(1);
                                            if write_elapsed > slowest_write {
                                                slowest_write = write_elapsed;
                                            }
                                            if write_elapsed >= UPLOAD_SLOW_WRITE_THRESHOLD {
                                                slow_writes_this_batch =
                                                    slow_writes_this_batch.saturating_add(1);
                                                info!(
                                                    target: "ember::upload_diag",
                                                    "slow_write {peer_addr} kind=compressed \
                                                     chunk_len={chunk_len} elapsed_ms={} \
                                                     uploaded={uploaded}B — TCP back-pressure",
                                                    write_elapsed.as_millis(),
                                                );
                                            }

                                            cursor += chunk_len;

                                            // Attribute uncompressed-byte progress
                                            // proportionally to this packet's share
                                            // of the compressed stream. eMule does
                                            // the same thing for its own payload
                                            // accounting (see CreatePackedPackets:
                                            //   payloadSize = togo ? nPacketSize*oldSize/newsize
                                            //               : oldSize - totalPayloadSize).
                                            // The final packet gets the remainder so
                                            // the sum over the block equals exactly
                                            // data.len() with no rounding drift.
                                            let share = if cursor < compressed.len() {
                                                (chunk_len as u64)
                                                    .saturating_mul(total_uncompressed)
                                                    / total_compressed
                                            } else {
                                                total_uncompressed
                                                    .saturating_sub(uncompressed_accounted)
                                            };
                                            uncompressed_accounted += share;
                                            uploaded += share;
                                            rate_tracker.record_send(share);
                                            batch_credited_bytes =
                                                batch_credited_bytes.saturating_add(share);

                                            if let Some(tid) = &transfer_id {
                                                let should_emit = match last_progress_emit {
                                                    None => true,
                                                    Some(last) => {
                                                        last.elapsed() >= PROGRESS_EMIT_MIN_INTERVAL
                                                    }
                                                };
                                                if should_emit {
                                                    last_progress_emit =
                                                        Some(std::time::Instant::now());
                                                    last_progress_uploaded = uploaded;
                                                    let _ = self.upload_event_tx.send(UploadEvent {
                                                        transfer_id: tid.clone(),
                                                        kind: UploadEventKind::Progress {
                                                            uploaded,
                                                            total: total_size,
                                                        },
                                                    }).await;
                                                }
                                            }
                                        }
                                        sent_compressed = true;
                                    }
                                }
                            }
                        }
                        if sent_compressed {
                            continue;
                        }

                        // Uncompressed OP_SENDINGPART path: split into 10 KiB
                        // packets, each with its own start/end offset for the
                        // sub-range it carries. (eMule's
                        // CreateStandardPackets.)
                        let use_i64 = end > u32::MAX as u64;
                        let header_len = if use_i64 { 32 } else { 24 };
                        let proto =
                            if use_i64 { OP_EMULEPROT } else { OP_EDONKEYHEADER };
                        let op =
                            if use_i64 { OP_SENDINGPART_I64 } else { OP_SENDINGPART };

                        let mut cursor = 0usize;
                        while cursor < data.len() {
                            let remaining = data.len() - cursor;
                            let chunk_len = if remaining < SMALL_PACKET_THRESHOLD {
                                remaining
                            } else {
                                MAX_PACKET_DATA
                            };
                            let chunk = &data[cursor..cursor + chunk_len];
                            let chunk_start = start + cursor as u64;
                            let chunk_end = chunk_start + chunk_len as u64;

                            let mut part_payload =
                                Vec::with_capacity(header_len + chunk_len);
                            part_payload.extend_from_slice(&hash);
                            if use_i64 {
                                part_payload.extend_from_slice(&chunk_start.to_le_bytes());
                                part_payload.extend_from_slice(&chunk_end.to_le_bytes());
                            } else {
                                part_payload.extend_from_slice(&(chunk_start as u32).to_le_bytes());
                                part_payload.extend_from_slice(&(chunk_end as u32).to_le_bytes());
                            }
                            part_payload.extend_from_slice(chunk);

                            self.acquire_upload_bandwidth(chunk_len as u64).await;
                            let write_start = std::time::Instant::now();
                            write_packet_async(&mut writer, proto, op, &part_payload).await?;
                            let write_elapsed = write_start.elapsed();
                            packets_this_batch = packets_this_batch.saturating_add(1);
                            if write_elapsed > slowest_write {
                                slowest_write = write_elapsed;
                            }
                            if write_elapsed >= UPLOAD_SLOW_WRITE_THRESHOLD {
                                slow_writes_this_batch =
                                    slow_writes_this_batch.saturating_add(1);
                                info!(
                                    target: "ember::upload_diag",
                                    "slow_write {peer_addr} kind=uncompressed \
                                     chunk_len={chunk_len} elapsed_ms={} \
                                     uploaded={uploaded}B — TCP back-pressure",
                                    write_elapsed.as_millis(),
                                );
                            }

                            uploaded += chunk_len as u64;
                            rate_tracker.record_send(chunk_len as u64);
                            batch_credited_bytes =
                                batch_credited_bytes.saturating_add(chunk_len as u64);

                            if let Some(tid) = &transfer_id {
                                let should_emit = match last_progress_emit {
                                    None => true,
                                    Some(last) => last.elapsed() >= PROGRESS_EMIT_MIN_INTERVAL,
                                };
                                if should_emit {
                                    last_progress_emit = Some(std::time::Instant::now());
                                    last_progress_uploaded = uploaded;
                                    let _ = self.upload_event_tx.send(UploadEvent {
                                        transfer_id: tid.clone(),
                                        kind: UploadEventKind::Progress {
                                            uploaded,
                                            total: total_size,
                                        },
                                    }).await;
                                }
                            }

                            cursor += chunk_len;
                        }
                    }

                    // Diagnostic: batch-level summary. `credited_bytes == 0`
                    // means the peer's REQUESTPARTS produced no outgoing
                    // bytes — every range was filtered (past EOF, zero-length,
                    // or rejected by the part tracker) and `last_part_request`
                    // will NOT be bumped, so the outer idle gate is still
                    // ticking. That's the shape we need to see to distinguish
                    // "peer sent garbage REQUESTPARTS and we correctly
                    // ignored them, timeout imminent" from "we served bytes
                    // normally, peer got them, timeout reset".
                    debug!(
                        target: "ember::upload_diag",
                        "reqparts_out {peer_addr} credited={batch_credited_bytes}B \
                         packets={packets_this_batch} slow_writes={slow_writes_this_batch} \
                         slowest_ms={} batch_elapsed_ms={} uploaded_total={uploaded}B",
                        slowest_write.as_millis(),
                        req_batch_start.elapsed().as_millis(),
                    );

                    // Flush the batched credit + slot-rate updates once per
                    // OP_REQUESTPARTS batch. These used to be taken per block
                    // (see inside the loop above) and showed up as real
                    // contention under multi-slot uploads.
                    if batch_credited_bytes > 0 {
                        {
                            let mut cm = self.credit_manager.write().await;
                            cm.add_uploaded(peer_user_hash, batch_credited_bytes);
                            // Ember credit ledger: mirrors the eMule
                            // credit write for peers that have
                            // advertised an Ed25519 pubkey AND
                            // completed PoP on THIS session. Without
                            // PoP the write is rejected inside
                            // `add_ember_uploaded` — a spoofer
                            // riding a friend's hash cannot farm
                            // real reputation here. The helper also
                            // bumps `last_upload_time` so decay
                            // starts from the last real upload, not
                            // from the last handshake.
                            if let Some(pk) = hello_caps.ember_pubkey {
                                let verified = ember_auth_state.is_verified();
                                cm.add_ember_uploaded(pk, batch_credited_bytes, verified);
                            }
                        }
                        self.slot_rates
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert(peer_addr, rate_tracker.smoothed_rate());
                        // Bump the useful-activity gauge ONLY after bytes
                        // actually flowed. The earlier "bump on REQUESTPARTS
                        // arrival" approach was defeated by clients that
                        // ship REQUESTPARTS for ranges we filter out (past
                        // EOF, zero-length, parts we won't serve, parts
                        // already-served-this-batch deduplicated, etc.) —
                        // those still bumped the gauge even though nothing
                        // moved on the wire, leaving the slot pinned
                        // forever (eMule Plus 1.2.5 was the canonical
                        // repro). Tying the bump to `batch_credited_bytes`
                        // means only real progress resets the timer.
                        last_part_request = std::time::Instant::now();
                    }

                    // OP_REQUESTPARTS is the hot path. After the inner
                    // offset loop, flush a final Progress event if the
                    // throttle coalesced away the last update for this
                    // batch — otherwise the UI can sit on a stale
                    // `uploaded` value for up to `PROGRESS_EMIT_MIN_INTERVAL`
                    // after a burst of blocks, which is exactly the
                    // "row frozen while data is clearly moving" symptom
                    // for short bursty sessions.
                    if let Some(tid) = &transfer_id {
                        if uploaded != last_progress_uploaded {
                            last_progress_emit = Some(std::time::Instant::now());
                            last_progress_uploaded = uploaded;
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
                            // See queue-insertion site above: friend
                            // priority only counts when PoP has landed
                            // on this session.
                            let is_verified_friend = is_friend && ember_auth_state.is_verified();
                            let ember_verified = ember_auth_state.is_verified();
                            let my_score = score_queue_entry(
                                &cm, &idx_snap, &peer_user_hash, my_fh,
                                queue_wait_at_grant, Some(peer_addr),
                                hello_caps.emule_version_min, is_verified_friend,
                                hello_caps.ember_pubkey.as_ref(), ember_verified,
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
                                    entry.ember_pubkey.as_ref(), entry.ember_verified,
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
                        let session_secs = session_start
                            .map(|t| t.elapsed().as_secs())
                            .unwrap_or(0);
                        info!(
                            target: "ember::upload_diag",
                            "session_end {peer_addr} reason={reason} uploaded={uploaded}B \
                             session_secs={session_secs} smoothed_bps={} \
                             sending OP_OUTOFPARTREQS",
                            rate_tracker.smoothed_rate(),
                        );
                        // Record the Ember session-reliability +
                        // speed outcome. `session_limit` is treated
                        // as a clean completion (we served them the
                        // max allowed per session) while `score
                        // preempted` is not — we kicked them out
                        // because a higher-scoring peer showed up,
                        // which from the reliability perspective is
                        // still "they didn't voluntarily bail". We
                        // follow the plan spec and count only the
                        // natural session-limit case as completed so
                        // the reliability multiplier can actually
                        // differentiate peers that walk away
                        // mid-transfer from peers we rotate out.
                        if let Some(pk) = hello_caps.ember_pubkey {
                            let verified = ember_auth_state.is_verified();
                            let completed = !preempted;
                            let mut cm = self.credit_manager.write().await;
                            cm.record_ember_session(pk, uploaded, session_secs, completed, verified);
                        }
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
                            // Same PoP gate as the initial queue-insertion
                            // site: re-admitting after session-expire
                            // uses the CURRENT verification state. If the
                            // peer authenticated earlier on this session
                            // and the flag is still true, they re-enter
                            // with friend priority; if auth never
                            // completed, they re-enter as a regular peer.
                            let is_verified_friend = is_friend && ember_auth_state.is_verified();
                            let mut queue = self.upload_queue.lock().await;
                            if let Some(entry) =
                                queue.iter_mut().find(|e| e.identity == queue_identity)
                            {
                                entry.current_addr = Some(peer_addr);
                                entry.user_hash = peer_user_hash;
                                entry.file_hash = current_file_hash.unwrap_or([0u8; 16]);
                                if is_verified_friend {
                                    entry.is_friend_slot = true;
                                }
                                // Re-entry after session end: refresh
                                // the Ember verification snapshot. As
                                // with `is_friend_slot` we only
                                // upgrade (NotStarted → Verified)
                                // here, never downgrade — once a
                                // peer has completed PoP on a
                                // session the queue entry keeps
                                // that fact through re-admission.
                                if ember_auth_state.is_verified() {
                                    entry.ember_verified = true;
                                }
                                if entry.ember_pubkey.is_none() {
                                    entry.ember_pubkey = hello_caps.ember_pubkey;
                                }
                            } else if queue.len() < MAX_UPLOAD_QUEUE_SIZE {
                                queue.push(QueueEntry {
                                    identity: queue_identity.clone(),
                                    current_addr: Some(peer_addr),
                                    user_hash: peer_user_hash,
                                    file_hash: current_file_hash.unwrap_or([0u8; 16]),
                                    join_time: queue_join_time,
                                    add_next_connect: false,
                                    emule_version: hello_caps.emule_version_min,
                                    is_friend_slot: is_verified_friend,
                                    ember_pubkey: hello_caps.ember_pubkey,
                                    ember_verified: ember_auth_state.is_verified(),
                                });
                            } else if queue.len() < HARD_UPLOAD_QUEUE_SIZE {
                                // m7: Soft-to-hard zone – re-admit after session with score check
                                let cm = self.credit_manager.read().await;
                                let idx_snap = self.local_index.read().await;
                                let new_fh = current_file_hash.unwrap_or([0u8; 16]);
                                let ember_verified = ember_auth_state.is_verified();
                                let new_score = score_queue_entry(
                                    &cm, &idx_snap, &peer_user_hash, new_fh,
                                    0, Some(peer_addr), hello_caps.emule_version_min,
                                    is_verified_friend,
                                    hello_caps.ember_pubkey.as_ref(), ember_verified,
                                );
                                let avg_score = if queue.is_empty() { 0.0 } else {
                                    let total: f64 = queue.iter().map(|e| {
                                        score_queue_entry(
                                            &cm, &idx_snap, &e.user_hash, e.file_hash,
                                            e.join_time.elapsed().as_secs(), e.current_addr,
                                            e.emule_version, e.is_friend_slot,
                                            e.ember_pubkey.as_ref(), e.ember_verified,
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
                                        is_friend_slot: is_verified_friend,
                                        ember_pubkey: hello_caps.ember_pubkey,
                                        ember_verified,
                                    });
                                }
                            }
                        }
                    }
                }

                (OP_EDONKEYHEADER, OP_CANCELTRANSFER) | (OP_EDONKEYHEADER, OP_END_OF_DOWNLOAD) => {
                    let cancel_kind = if opcode == OP_CANCELTRANSFER {
                        "peer_cancel"
                    } else {
                        "peer_end_of_download"
                    };
                    info!(
                        target: "ember::upload_diag",
                        "session_end {peer_addr} reason={cancel_kind} \
                         uploaded={uploaded}B last_part_req={}s \
                         session_age={}s iters={outer_loop_iterations}",
                        last_part_request.elapsed().as_secs(),
                        session_open_at.elapsed().as_secs(),
                    );
                    // Same reliability rule as the session-expired
                    // branch: "completed" iff the peer actually
                    // received at least one byte from this session.
                    // A peer that cancels a freshly-granted slot
                    // without any data transferred is counted as an
                    // aborted session so the reliability multiplier
                    // reflects the churn.
                    if let Some(pk) = hello_caps.ember_pubkey {
                        let verified = ember_auth_state.is_verified();
                        let session_secs = session_start
                            .map(|t| t.elapsed().as_secs())
                            .unwrap_or(0);
                        let completed = uploaded > 0;
                        let mut cm = self.credit_manager.write().await;
                        cm.record_ember_session(pk, uploaded, session_secs, completed, verified);
                    }
                    if let Some(tid) = &transfer_id {
                        // Mirror the connection-exit cleanup at the bottom of
                        // this function: only report a session as Completed
                        // when at least one byte actually went out. A peer
                        // that tears down a freshly-granted slot before we
                        // got a chance to serve anything (e.g. they saw an
                        // unexpected OP_QUEUERANKING echo and decided to
                        // bail, or their downloader's initial part_queue
                        // was empty so it went straight to
                        // OP_END_OF_DOWNLOAD) previously surfaced in the
                        // UI as "Complete, 586 MB transferred" because the
                        // front-end snaps `transferred` to `total_size` on
                        // every `transfer-complete`. Emit Failed instead so
                        // the zero-byte row is visibly distinguishable from
                        // a real upload.
                        let kind = if uploaded > 0 {
                            UploadEventKind::Completed
                        } else {
                            UploadEventKind::Failed {
                                error: "Peer ended transfer before any data was sent".to_string(),
                            }
                        };
                        let _ = self.upload_event_tx.send(UploadEvent {
                            transfer_id: tid.clone(),
                            kind,
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
                                            self.sx_overhead.record_upload((6 + resp.len()) as u64);
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
                                            self.sx_overhead.record_upload((6 + resp.len()) as u64);
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
                    // Inbound peer-to-peer Source Exchange request: count
                    // the wire bytes (6-byte ed2k header + payload) so the
                    // Statistics page sees real SX activity, not just the
                    // server-side source asking that the original SX
                    // overhead category covered. The obfuscation layer
                    // adds a few bytes when enabled; the unobfuscated
                    // size is a reasonable lower bound.
                    self.sx_overhead.record_download((6 + payload.len()) as u64);
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
                        self.sx_overhead.record_upload((6 + resp.len()) as u64);
                    }
                }

                (OP_EMULEPROT, OP_REQUESTSOURCES2) => {
                    self.sx_overhead.record_download((6 + payload.len()) as u64);
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
                        self.sx_overhead.record_upload((6 + resp.len()) as u64);
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

                // Authoritative Ember peer detection from the uploader side.
                // Mirrors the downloader path in `multi_source.rs` — a
                // peer that sends a parseable `OP_EMBER_HELLO` /
                // `OP_EMBER_HELLOANSWER` is, by construction, an Ember
                // client (vanilla eMule never emits these opcodes; they
                // sit in our private 0xF8/0xF9 range). We learn their
                // mod_version, ember_hash, and (optionally) ember_pubkey
                // here — all the fields we used to harvest from the
                // public Hello / EmuleInfo before the anti-leecher fix.
                // If the peer beat us to it, also send our HELLOANSWER
                // back so they learn our identity in the same round trip.
                (OP_EMULEPROT, OP_EMBER_HELLO) | (OP_EMULEPROT, OP_EMBER_HELLOANSWER) => {
                    if let Some(ident) = parse_ember_hello(&payload) {
                        // Identity lock: once PoP succeeds the peer's
                        // `(ember_pubkey, ember_hash)` pair is fixed
                        // for this TCP session. If they try to swap
                        // identity in a follow-up Ember-Hello (the
                        // pubkey or hash differs), refuse the change
                        // and log it. Without this, an attacker who
                        // PoPs as themselves could re-issue an
                        // Ember-Hello carrying a victim's
                        // (pubkey, hash) and then have credit
                        // accounting / queue scoring attribute uploads
                        // to the victim. Mod_version/nickname keep
                        // updating because they're cosmetic.
                        let identity_changed = ember_auth_state.is_verified()
                            && (
                                (ident.ed25519_pubkey.is_some()
                                    && hello_caps.ember_pubkey.is_some()
                                    && ident.ed25519_pubkey != hello_caps.ember_pubkey)
                                || (ident.ember_hash != [0u8; 16]
                                    && hello_caps.ember_hash.is_some()
                                    && Some(ident.ember_hash) != hello_caps.ember_hash)
                            );
                        if identity_changed {
                            tracing::warn!(
                                "Ember identity-swap rejected from {peer_addr}: peer already PoP-verified, ignoring re-keyed OP_EMBER_HELLO (old_hash={:?}, new_hash={})",
                                hello_caps.ember_hash.as_ref().map(hex::encode),
                                hex::encode(ident.ember_hash),
                            );
                        }
                        hello_caps.is_ember = true;
                        if !ident.mod_version.is_empty() {
                            hello_caps.mod_version = ident.mod_version.clone();
                        }
                        if !ident.nickname.is_empty() {
                            hello_caps.peer_name = ident.nickname.clone();
                            ul_peer_name = ident.nickname.clone();
                        }
                        if ident.ember_hash != [0u8; 16] && !identity_changed {
                            hello_caps.ember_hash = Some(ident.ember_hash);
                            peer_ember_hash = Some(ident.ember_hash);
                        }
                        if let Some(pk) = ident.ed25519_pubkey {
                            if !identity_changed {
                                hello_caps.ember_pubkey = Some(pk);
                            }
                        }
                        ul_client_software = client_software_from_caps(&hello_caps);
                        info!(
                            "Peer {peer_addr} identified as Ember via OP_EMBER_HELLO (mod='{}', nick='{}')",
                            ident.mod_version, ident.nickname,
                        );
                        if opcode == OP_EMBER_HELLO && !ul_sent_ember_hello {
                            // See above for why we advertise our pubkey here.
                            let payload = build_ember_hello(&self.ember_hash, &self.nickname, Some(&self.ed25519_public_key));
                            let _ = write_packet_async(&mut writer, OP_EMULEPROT, OP_EMBER_HELLOANSWER, &payload).await;
                            ul_sent_ember_hello = true;
                        }

                        // Offline identity-binding verification. Since
                        // the upload reader runs in a dedicated task
                        // (not reachable from this dispatcher site),
                        // we can't run the full challenge-response
                        // here; we use the cheaper binding check
                        // instead. Attackers who don't have the
                        // victim's pubkey fail this check; attackers
                        // who do (e.g. via passive wire-sniffing)
                        // still get caught when the user accepts the
                        // request and `friend_connect::open_friend_session`
                        // runs a fresh challenge-response over a
                        // dedicated TCP session.
                        if !ember_hash_binding_verified {
                            if let (Some(ref peer_pk), Some(ref peer_eh)) = (hello_caps.ember_pubkey, hello_caps.ember_hash) {
                                if crate::network::ember::crypto::verify_ember_hash_binding(peer_pk, peer_eh) {
                                    ember_hash_binding_verified = true;
                                    info!("Ember binding: peer {peer_addr} pubkey matches advertised hash");
                                } else {
                                    tracing::warn!(
                                        "Ember binding: peer {peer_addr} advertised pubkey does not BLAKE3-bind to ember_hash={} (possible spoof)",
                                        hex::encode(peer_eh)
                                    );
                                }
                            }
                        }

                        // Deferred friend-request emit. The early
                        // gate above the dispatcher fires before any
                        // `OP_EMBER_HELLO` has been processed and so
                        // sees `peer_ember_hash = None` /
                        // `is_friend = false` for every Ember peer
                        // that hasn't pre-loaded an obfuscation-layer
                        // ember_hash — which is the common case
                        // because we deliberately stripped Ember
                        // identity from the public Hello/EmuleInfo
                        // (anti-leecher-mod queue-ban avoidance). On
                        // those sessions the original code would
                        // never send `OP_EMBER_FRIEND_REQ`, so a
                        // friend who already has us in their list
                        // could initiate a download from us, see our
                        // upload's friend request flow silently no-op,
                        // and never get the reciprocal acceptance
                        // prompt — exactly the asymmetric "they see
                        // me but I never see them" bug users hit.
                        //
                        // Re-evaluating `is_friend` /
                        // `is_ember_friend` here also keeps the
                        // `is_ember_friend`-gated CHAT_MSG /
                        // BROWSE_REQ / BROWSE_RES / KEEPALIVE arms
                        // honest and lets the AUTH_RESPONSE arm
                        // actually claim `owns_ember_slot` for this
                        // friend — both of which were previously
                        // dead code on the same Ember sessions.
                        //
                        // `friend_request_sent` ensures we only ever
                        // emit one request per session; OP_EMBER_HELLO
                        // arrives at most twice (HELLO + HELLOANSWER)
                        // so the guard is what stops the duplicate.
                        if !is_friend {
                            if let Some(eh) = peer_ember_hash {
                                if self.friend_hashes.read().await.contains(&eh) {
                                    is_friend = true;
                                    is_ember_friend = is_friend && hello_caps.is_ember;
                                }
                            }
                        }
                        if is_friend && hello_caps.is_ember && !friend_request_sent {
                            info!(
                                "Sending deferred friend request to Ember peer {peer_addr} after OP_EMBER_HELLO",
                            );
                            let nick_bytes = self.nickname.as_bytes();
                            if write_packet_async(
                                &mut writer,
                                OP_EMULEPROT,
                                OP_EMBER_FRIEND_REQ,
                                nick_bytes,
                            )
                            .await
                            .is_ok()
                            {
                                friend_request_sent = true;
                            }
                        }
                    }
                }

                // Gated on `hello_caps.is_ember`. EPX is an
                // Ember-only extension; vanilla eMule peers should
                // never send `OP_EMBER_SOURCEEXCHANGE`. Without this
                // guard a non-Ember (or attacker) peer could ship
                // crafted EPX that gets parsed and ends up steering
                // `known_ember_peers` and broker relay candidates,
                // polluting our peer-mesh hints. Symmetric with the
                // pubkey/binding/PoP gating on the other Ember opcodes.
                (OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE) if hello_caps.is_ember => {
                    self.sx_overhead.record_download((6 + payload.len()) as u64);
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
                    // L21: refuse a friend request whose claimed
                    // sender hash matches our own. PoP from a remote
                    // peer can never succeed for our own identity, so
                    // the row would always be unverified, but it
                    // would still flicker into the requests panel
                    // before being sanitised on refresh — confusing
                    // and unnecessary. We also reject any spoofer
                    // that pivots its hash to ours after seeing our
                    // pubkey on the wire.
                    if peer_ember_hash == Some(self.ember_hash) {
                        tracing::debug!(
                            "Ignoring self-addressed OP_EMBER_FRIEND_REQ from {peer_addr}"
                        );
                    } else if let Some(eh) = peer_ember_hash {
                        let nick = std::str::from_utf8(&payload).unwrap_or("").to_string();
                        // `verified` requires the strong PoP signal
                        // from the reactive challenge-response state
                        // machine. The earlier code also accepted
                        // `ember_hash_binding_verified` (the offline
                        // BLAKE3 hash check), but a peer can replay a
                        // friend's public (pubkey, ember_hash) pair
                        // and pass binding without holding the
                        // private key — which would let a spoofer
                        // re-issue an outgoing peer's request as
                        // "Verified" in the recipient's UI/DB.
                        // Binding is still tracked separately for the
                        // log line below.
                        let verified = ember_auth_state.is_verified();
                        info!(
                            "Received friend request from {peer_addr} (nick='{}', hash={}, verified={verified}, pop={}, binding={ember_hash_binding_verified})",
                            nick, hex::encode(eh), verified,
                        );
                        let _ = self.upload_event_tx.send(UploadEvent {
                            transfer_id: String::new(),
                            kind: UploadEventKind::EmberFriendRequest {
                                ember_hash: eh,
                                nickname: nick,
                                peer_ip: peer_addr.ip().to_string(),
                                peer_port: peer_addr.port(),
                                verified,
                            },
                        }).await;
                    }
                }

                // Ember Ed25519 challenge-response — responder side.
                // The download peer drives a synchronous round-trip
                // via `friend_connect::perform_ember_auth`; we react
                // here from the dispatcher because our reader is
                // owned by `reader_task` and we can't drive a
                // synchronous read from this site. See
                // `super::ember_auth` for the state-machine details.
                //
                // Both arms write outbound packets directly via
                // `write_packet_async` rather than rerouting through
                // the reader task, which is safe because the
                // dispatcher is the sole writer on this session.
                (OP_EMULEPROT, OP_EMBER_AUTH_CHALLENGE) => {
                    match super::ember_auth::handle_challenge(
                        &mut ember_auth_state,
                        &payload,
                        &self.ed25519_public_key,
                        &self.ed25519_secret_key,
                    ) {
                        Ok(out) => {
                            if let Some(challenge_payload) = out.our_challenge_payload {
                                let _ = write_packet_async(
                                    &mut writer,
                                    OP_EMULEPROT,
                                    OP_EMBER_AUTH_CHALLENGE,
                                    &challenge_payload,
                                ).await;
                            }
                            if let Some(response_payload) = out.our_response_payload {
                                let _ = write_packet_async(
                                    &mut writer,
                                    OP_EMULEPROT,
                                    OP_EMBER_AUTH_RESPONSE,
                                    &response_payload,
                                ).await;
                            }
                            debug!("Ember auth (responder): replied to {peer_addr}'s CHALLENGE; awaiting RESPONSE");
                        }
                        Err(e) => {
                            tracing::warn!("Ember auth (responder): rejected CHALLENGE from {peer_addr}: {e:?}");
                        }
                    }
                }

                (OP_EMULEPROT, OP_EMBER_AUTH_RESPONSE) => {
                    let outcome = match (hello_caps.ember_pubkey.as_ref(), peer_ember_hash.as_ref()) {
                        (Some(pk), Some(eh)) => super::ember_auth::handle_response(
                            &mut ember_auth_state,
                            &payload,
                            pk,
                            eh,
                        ),
                        // Theoretical race: peer sent RESPONSE before
                        // we finished parsing their OP_EMBER_HELLO.
                        // TCP guarantees ordering of their writes so
                        // this should not happen with a
                        // well-behaved initiator (it always sends
                        // OP_EMBER_HELLO before CHALLENGE before
                        // RESPONSE) — but if it does, refuse to
                        // verify rather than guess.
                        _ => Err(super::ember_auth::AuthError::PeerPubkeyUnknown),
                    };
                    match outcome {
                        Ok(()) => {
                            info!("Ember auth (responder): peer {peer_addr} verified (proof of possession)");
                            // PoP succeeded — claim the inbound friend
                            // session slot now. We deliberately defer
                            // this until verification completes so that
                            // a peer who merely knows our friend's
                            // public ember_hash cannot grab the slot
                            // and intercept outbound chat/browse
                            // routed via `ember_sessions` (see
                            // session-open comment for the full
                            // rationale).
                            if !owns_ember_slot && is_ember_friend {
                                if let Some(eh) = peer_ember_hash {
                                    let mut sessions = self.ember_sessions.write().await;
                                    if !sessions.contains_key(&eh) {
                                        sessions.insert(eh, outbound_tx.clone());
                                        owns_ember_slot = true;
                                    }
                                }
                            }
                            // Emit FriendSeen only after PoP — the
                            // dispatcher uses this to overwrite the
                            // friend's last known IP and to mark them
                            // online in the UI; an unverified peer
                            // claiming the friend's `ember_hash` would
                            // otherwise be able to poison both.
                            if is_friend {
                                if let Some(eh) = peer_ember_hash {
                                    let _ = self.upload_event_tx.send(UploadEvent {
                                        transfer_id: String::new(),
                                        kind: UploadEventKind::FriendSeen {
                                            ember_hash: eh,
                                            ip: peer_addr.ip(),
                                            port: peer_addr.port(),
                                        },
                                    }).await;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Ember auth (responder): rejected RESPONSE from {peer_addr}: {e:?}");
                        }
                    }
                }

                // The four privilege-bearing Ember friend opcodes below
                // (CHAT, BROWSE_REQ, BROWSE_RES, KEEPALIVE) are gated on
                // the composite `is_verified_ember_friend` flag: the
                // peer must claim our friend's hash (`is_ember_friend`)
                // AND have completed the Ed25519 proof-of-possession on
                // THIS TCP session (`ember_auth_state.is_verified()`).
                //
                // Without the PoP clause a peer who has learned our
                // friend's `ember_hash` on the wire (KAD publishes,
                // EPX exchanges, public trackers, etc.) could ride the
                // friend's identity on any upload session: inject chat
                // that shows up in our Friends UI as from the friend,
                // trigger browse events, silently hold the friend's
                // ember slot via keepalives. Requiring fresh-nonce
                // signature verification per session closes that
                // window — a spoofer cannot produce a valid signature
                // for a random nonce we issued here without also
                // holding the friend's Ed25519 secret key.
                //
                // Check is re-evaluated per packet (not snapshotted at
                // session open) because `ember_auth_state` advances
                // asynchronously as the peer responds to our CHALLENGE
                // — it's typically `NotStarted` when chat/browse
                // requests first arrive and only flips to `Verified`
                // a packet or two later.
                (OP_EMULEPROT, OP_EMBER_CHAT_MSG) if is_ember_friend && ember_auth_state.is_verified() => {
                    if let Some(eh) = peer_ember_hash {
                        if !self.friend_hashes.read().await.contains(&eh) {
                            debug!("Ignoring chat from removed friend {}", hex::encode(eh));
                        } else if payload.len() <= 4096 {
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

                (OP_EMULEPROT, OP_EMBER_BROWSE_REQ) if is_ember_friend && ember_auth_state.is_verified() => {
                    if let Some(eh) = peer_ember_hash {
                        if !self.friend_hashes.read().await.contains(&eh) {
                            debug!("Ignoring browse request from removed friend {}", hex::encode(eh));
                        } else {
                            let _ = self.upload_event_tx.send(UploadEvent {
                                transfer_id: String::new(),
                                kind: UploadEventKind::EmberBrowseRequest {
                                    ember_hash: eh,
                                },
                            }).await;
                        }
                    }
                }

                (OP_EMULEPROT, OP_EMBER_BROWSE_RES) if is_ember_friend && ember_auth_state.is_verified() => {
                    if let Some(eh) = peer_ember_hash {
                        if !self.friend_hashes.read().await.contains(&eh) {
                            debug!("Ignoring browse response from removed friend {}", hex::encode(eh));
                        } else {
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
                }

                (OP_EMULEPROT, OP_EMBER_KEEPALIVE) if is_ember_friend && ember_auth_state.is_verified() => {}

                _ => {
                    debug!(
                        "Upload handler ignoring proto=0x{proto:02X} op=0x{opcode:02X} from {peer_addr}"
                    );
                }
            }
        }
        // Every `break` path above lands here with an implicit `()`;
        // return it as `Ok(())` so the async block's result type matches
        // the propagated `?` errors.
        Ok::<(), anyhow::Error>(())
        }.await;

        reader_task.abort();
        let _ = reader_task.await;

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

        // Ember session reliability/speed bookkeeping for the
        // disconnect path: `session_start.is_some()` iff we were
        // mid-session when the connection dropped. Same "completed
        // iff bytes flowed" rule as the explicit cancel branch.
        // Doing this before the transfer-event emit keeps the
        // credit-manager write adjacent to the other end-of-session
        // work, and guarantees the record lands even if the event
        // channel is full (the send after this point drops on
        // `let _`).
        if let (Some(pk), Some(start)) = (hello_caps.ember_pubkey, session_start) {
            let verified = ember_auth_state.is_verified();
            let session_secs = start.elapsed().as_secs();
            let completed = uploaded > 0;
            let mut cm = self.credit_manager.write().await;
            cm.record_ember_session(pk, uploaded, session_secs, completed, verified);
        }

        // Emit completion/failure for any tracked upload. This is the
        // single bottleneck through which every upload session
        // terminates — the `transfer-complete` / `transfer-failed`
        // event emitted here is what drops the row from the frontend
        // uploads pane. If a field trace shows a "Transferring" row
        // persisting without a matching `session_final` log line,
        // the connection handler hasn't actually returned yet, which
        // is the only way a row could sit beyond
        // CLIENT_TIMEOUT_SECS. Emitting this as `info!` (not debug)
        // makes every session termination visible by default.
        let session_age = session_open_at.elapsed().as_secs();
        if let Some(tid) = &transfer_id {
            // Hybrid terminal-event semantics:
            //   * uploaded > 0  → Completed. The row vanishes quietly,
            //     matching eMule's "session ended, cumulative totals live
            //     in stats" UX. This holds even if the session ended via
            //     an error path (e.g. 60 s write stall): we still served
            //     real bytes to the peer, so from the user's POV this
            //     was a successful session that happened to end.
            //   * uploaded == 0 AND session_result is Err → surface the
            //     real error. The old hardcoded
            //     "Peer disconnected before any data transferred" hid
            //     genuinely useful diagnostics (write timeouts, TLS
            //     errors, malformed handshakes) behind a generic
            //     message, which made zero-byte failures in the
            //     Completed/Failed pane indistinguishable.
            //   * uploaded == 0 AND Ok(()) → clean handshake-only exit,
            //     keep the legacy message.
            let kind_label = if uploaded > 0 {
                "completed"
            } else if session_result.is_err() {
                "failed_with_error"
            } else {
                "failed_zero_bytes"
            };
            let err_label = session_result
                .as_ref()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "none".to_string());
            info!(
                target: "ember::upload_diag",
                "session_final {peer_addr} kind={kind_label} uploaded={uploaded}B \
                 last_part_req={}s session_age={session_age}s \
                 iters={outer_loop_iterations} tid={tid} err=\"{err_label}\"",
                last_part_request.elapsed().as_secs(),
            );
            let kind = if uploaded > 0 {
                UploadEventKind::Completed
            } else if let Err(e) = &session_result {
                UploadEventKind::Failed {
                    error: format!("Session ended: {e}"),
                }
            } else {
                UploadEventKind::Failed {
                    error: "Peer disconnected before any data transferred".to_string(),
                }
            };
            let _ = self.upload_event_tx.send(UploadEvent {
                transfer_id: tid.clone(),
                kind,
            }).await;
        } else {
            let err_label = session_result
                .as_ref()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "none".to_string());
            info!(
                target: "ember::upload_diag",
                "session_final {peer_addr} kind=no_transfer_id uploaded={uploaded}B \
                 session_age={session_age}s iters={outer_loop_iterations} \
                 err=\"{err_label}\"",
            );
        }

        session_result
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
    if length == 0 || length > 512 * 1024 {
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
            if unpacked.len() > 1024 * 1024 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "packed packet decompressed size exceeds limit"));
            }
        }
        return Ok((OP_EMULEPROT, opcode, unpacked));
    }
    Ok((protocol, opcode, payload))
}

/// Maximum wall time we allow a single packet write (including flush) to
/// take before giving up. A slow-reading peer can otherwise wedge the
/// writer side on a TCP send buffer that never drains and permanently
/// occupy an upload slot. 60s is generous even on a saturated uplink
/// for our largest single-chunk packet (~180 KiB).
const WRITE_PACKET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

async fn write_packet_async<W: AsyncWriteExt + Unpin + ?Sized>(
    writer: &mut W,
    protocol: u8,
    opcode: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let fut = async {
        writer.write_u8(protocol).await?;
        writer.write_u32_le((1 + payload.len()) as u32).await?;
        writer.write_u8(opcode).await?;
        writer.write_all(payload).await?;
        writer.flush().await?;
        Ok::<_, std::io::Error>(())
    };
    match tokio::time::timeout(WRITE_PACKET_TIMEOUT, fut).await {
        Ok(res) => res,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "peer is not reading — write stalled > 60s (slow-loris protection)",
        )),
    }
}

async fn read_packet_with_first_byte<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    first_byte: u8,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    let protocol = first_byte;
    let length = reader.read_u32_le().await? as usize;
    if length == 0 || length > 512 * 1024 {
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

#[cfg(test)]
mod scoring_tests {
    //! Phase 3: verify `score_queue_entry` routes verified Ember peers
    //! through `get_ember_queue_score` while everyone else stays on the
    //! legacy eMule credit-ratio path. The underlying scoring formulas
    //! are covered by the unit tests in `credits.rs`; this module is
    //! specifically about the routing gate — `ember_verified && pubkey.is_some()`
    //! — and its interaction with the friend-slot override, version
    //! penalty, and BadGuy short-circuit.
    use super::*;
    use crate::search::index::LocalIndex;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use chrono::Utc;
    use crate::network::ed2k::credits::{
        CreditManager, EMBER_RELIABILITY_MAX, EMBER_RELIABILITY_MIN, EMBER_SPEED_BASELINE_BPS,
        IdentState,
    };

    fn addr() -> Option<SocketAddr> {
        Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4662))
    }

    /// Seed an eMule credit record so `get_queue_score` returns a
    /// meaningful non-MIN ratio for the test user_hash. Without this
    /// the eMule path scores at MIN (1.0) and our comparisons get
    /// noisy.
    fn seed_emule_credits(cm: &mut CreditManager, user_hash: [u8; 16]) {
        let record = cm.get_or_create(user_hash);
        record.uploaded = 1_000_000;
        record.downloaded = 5_000_000;
        record.ident_state = IdentState::Verified;
        record.ident_ip = 0;
    }

    /// Seed an Ember credit record matching the fixture above so the
    /// enhanced path has real numbers to multiply against.
    fn seed_ember_credits(cm: &mut CreditManager, pubkey: [u8; 32]) {
        let now = Utc::now().timestamp();
        let record = cm.get_or_create_ember(pubkey);
        record.uploaded = 1_000_000;
        record.downloaded = 5_000_000;
        record.last_download_time = now;
        record.last_upload_time = now;
        record.total_sessions = 10;
        record.completed_sessions = 10; // 100% reliability → 1.5×
        record.avg_upload_speed = (2.0 * EMBER_SPEED_BASELINE_BPS) as u64; // → 1.2×
        record.ident_verified = true;
    }

    #[test]
    fn verified_ember_peer_routes_through_enhanced_scoring() {
        let mut cm = CreditManager::new();
        let idx = LocalIndex::new();
        let user_hash = [0xEEu8; 16];
        let pubkey = [0xEBu8; 32];
        seed_emule_credits(&mut cm, user_hash);
        seed_ember_credits(&mut cm, pubkey);

        let emule_score = score_queue_entry(
            &cm, &idx, &user_hash, [0u8; 16], 300, addr(),
            /* emule_version */ 0x42, /* is_friend_slot */ false,
            /* ember_pubkey */ None, /* ember_verified */ false,
        );
        let ember_score = score_queue_entry(
            &cm, &idx, &user_hash, [0u8; 16], 300, addr(),
            0x42, false,
            Some(&pubkey), true,
        );

        // With 100% reliability (×1.5) and 2× baseline speed (×1.2),
        // the multiplicative headroom over the eMule path is 1.8× at
        // minimum (ignoring decay, which is ~1.0 for a just-now
        // download). Assert at least 1.5× so the test doesn't flake
        // on small ratio-formula differences between the two paths.
        assert!(
            ember_score >= emule_score * 1.5,
            "verified Ember routing must score meaningfully higher (got ember={ember_score} emule={emule_score})",
        );
    }

    #[test]
    fn unverified_ember_peer_falls_back_to_emule_scoring() {
        let mut cm = CreditManager::new();
        let idx = LocalIndex::new();
        let user_hash = [0xEEu8; 16];
        let pubkey = [0xEBu8; 32];
        seed_emule_credits(&mut cm, user_hash);
        seed_ember_credits(&mut cm, pubkey);

        // Same pubkey advertised but `ember_verified = false`:
        // hash-spoofer who hasn't proven possession. Must NOT pick
        // up the Ember ledger's multipliers.
        let scored_without_verification = score_queue_entry(
            &cm, &idx, &user_hash, [0u8; 16], 300, addr(),
            0x42, false,
            Some(&pubkey), false,
        );
        let emule_only = score_queue_entry(
            &cm, &idx, &user_hash, [0u8; 16], 300, addr(),
            0x42, false,
            None, false,
        );
        assert_eq!(
            scored_without_verification, emule_only,
            "unverified Ember peer must score identically to a vanilla eMule peer",
        );
    }

    #[test]
    fn missing_pubkey_falls_back_to_emule_scoring() {
        // Peer is "verified" in some abstract sense (PoP flag = true)
        // but has no advertised pubkey: defensive path, shouldn't
        // crash, should silently fall back. Covers the impossible-in-
        // practice but still-compilable-API shape where the caller
        // passes verified=true with pubkey=None.
        let mut cm = CreditManager::new();
        let idx = LocalIndex::new();
        let user_hash = [0xEEu8; 16];
        seed_emule_credits(&mut cm, user_hash);

        let with_none = score_queue_entry(
            &cm, &idx, &user_hash, [0u8; 16], 300, addr(),
            0x42, false,
            None, true,
        );
        let baseline = score_queue_entry(
            &cm, &idx, &user_hash, [0u8; 16], 300, addr(),
            0x42, false,
            None, false,
        );
        assert_eq!(with_none, baseline, "None pubkey must take eMule path regardless of verified flag");
    }

    #[test]
    fn friend_slot_override_still_wins_for_verified_ember_peer() {
        // The friend-slot constant is meant to dwarf any credit-ratio
        // differential so friends never lose their slot. Verify the
        // Ember routing path doesn't accidentally bypass the override
        // — i.e. `is_friend_slot = true` forces the high constant
        // regardless of whether the base score came from eMule or
        // Ember scoring.
        let mut cm = CreditManager::new();
        let idx = LocalIndex::new();
        let user_hash = [0xEEu8; 16];
        let pubkey = [0xEBu8; 32];
        seed_emule_credits(&mut cm, user_hash);
        seed_ember_credits(&mut cm, pubkey);

        let ember_friend_score = score_queue_entry(
            &cm, &idx, &user_hash, [0u8; 16], 300, addr(),
            0x42, /* is_friend_slot */ true,
            Some(&pubkey), true,
        );
        let emule_friend_score = score_queue_entry(
            &cm, &idx, &user_hash, [0u8; 16], 300, addr(),
            0x42, true,
            None, false,
        );
        assert_eq!(
            ember_friend_score, emule_friend_score,
            "friend-slot override constant must dominate both routing paths",
        );
        assert!(
            ember_friend_score > 1_000_000.0,
            "friend slot should map to the multi-million priority constant",
        );
    }

    #[test]
    fn badguy_ip_short_circuit_blocks_both_paths() {
        // A peer whose user_hash is verified to a different IP must
        // score 0.0 via the eMule path; the Ember routing path must
        // inherit that zero so a verified Ember pubkey can't be used
        // to smuggle a BadGuy around the IP-pinning check.
        let mut cm = CreditManager::new();
        let idx = LocalIndex::new();
        let user_hash = [0xEEu8; 16];
        let pubkey = [0xEBu8; 32];
        seed_emule_credits(&mut cm, user_hash);
        seed_ember_credits(&mut cm, pubkey);

        // Pin the peer's verified ident to a fixed IP, then call
        // scoring from a different IP → BadGuy → eMule score 0.0.
        let bad_addr = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 4662));
        cm.check_identity_ip(user_hash, 0x0A000001); // 10.0.0.1 pinned

        let score = score_queue_entry(
            &cm, &idx, &user_hash, [0u8; 16], 300, bad_addr,
            /* emule_version */ 0, false,
            Some(&pubkey), true,
        );
        assert_eq!(score, 0.0, "BadGuy short-circuit must zero both routing paths");
    }

    #[test]
    fn reliability_penalty_actually_shows_up_in_score() {
        // Two otherwise-identical verified Ember peers — one with
        // 100% reliability, one with 0%. The 100% peer's score
        // should be `MAX / MIN ≈ 1.875×` the 0% peer's, give or
        // take the speed multiplier (which we hold constant).
        let mut cm = CreditManager::new();
        let idx = LocalIndex::new();
        let good_user = [0x01u8; 16];
        let bad_user = [0x02u8; 16];
        let good_pk = [0x11u8; 32];
        let bad_pk = [0x22u8; 32];
        let good_addr = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4662));
        let bad_addr = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 4662));

        seed_emule_credits(&mut cm, good_user);
        seed_emule_credits(&mut cm, bad_user);
        let now = Utc::now().timestamp();
        for (pk, completed) in [(good_pk, 10u32), (bad_pk, 0u32)] {
            let r = cm.get_or_create_ember(pk);
            r.uploaded = 1_000_000;
            r.downloaded = 5_000_000;
            r.last_download_time = now;
            r.total_sessions = 10;
            r.completed_sessions = completed;
            r.avg_upload_speed = EMBER_SPEED_BASELINE_BPS as u64; // neutral speed
            r.ident_verified = true;
        }

        let good = score_queue_entry(
            &cm, &idx, &good_user, [0u8; 16], 300, good_addr,
            0, false, Some(&good_pk), true,
        );
        let bad = score_queue_entry(
            &cm, &idx, &bad_user, [0u8; 16], 300, bad_addr,
            0, false, Some(&bad_pk), true,
        );
        // Reliability multiplier differential only. Expected:
        // MAX / MIN = 1.5 / 0.8 ≈ 1.875. Assert at least 1.6× to
        // leave a little slack for ratio clamping.
        let observed_ratio = good / bad;
        let expected_ratio = EMBER_RELIABILITY_MAX / EMBER_RELIABILITY_MIN;
        assert!(
            observed_ratio > expected_ratio * 0.85,
            "reliability differential should produce ≳{expected_ratio:.2}× score gap, got {observed_ratio:.3}×",
        );
    }
}
