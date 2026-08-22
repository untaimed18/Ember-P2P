use std::collections::{HashMap, HashSet};
use std::io::{self, Read as _, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use flate2::write::ZlibEncoder;
use flate2::Compression;
use futures::FutureExt;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::bandwidth::limiter::BandwidthLimiter;
use crate::network::ed2k::a4af::A4AFManager;
use crate::network::ed2k::comments::CommentManager;
use crate::network::ed2k::credits::CreditManager;
use crate::network::ed2k::sources::SourceManager;
use crate::network::ed2k::tcp_obfuscation::{self, NegotiationResult, Rc4Reader, Rc4Writer};
use crate::search::index::LocalIndex;
use crate::sharing::manager::TransferManager;
use crate::types::{TransferDirection, TransferStatus};

/// A live friend session's outbound packet sender, plus a liveness
/// timestamp (unix seconds of last confirmed inbound activity from the
/// peer) refreshed by whichever reader loop owns the session — inbound
/// (this file's `UploadHandler` connection handler) or outbound
/// (`friend_connect::run_friend_session_over_transport`).
///
/// The wire protocol has no ack on application packets, so a session
/// whose peer has gone silently unreachable (NAT mapping expired, box
/// powered off, etc.) can sit with its reader/writer tasks still
/// technically running — and its `mpsc::Sender` still open and willing to
/// accept sends — for several minutes before the session's own passive
/// stall-detector notices and tears it down (see `STALL_TIMEOUT` in
/// `friend_connect.rs`). Every call site that treats "an entry exists in
/// `EmberSessionMap`" as "this friend is reachable right now" must check
/// [`Self::is_fresh`] instead of just presence, and evict+ignore a stale
/// entry rather than trusting it — otherwise a single dead connection can
/// silently blackhole chat/browse sends, and block explicit user retries
/// and the periodic auto-retry sweep, for the entire stall-detector
/// window.
#[derive(Clone)]
pub struct EmberSessionHandle {
    pub tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    session_id: u64,
    last_activity: Arc<std::sync::atomic::AtomicI64>,
    shutdown: tokio::sync::watch::Sender<bool>,
    /// The peer's Ed25519 identity public key, as proven by the Ed25519
    /// proof-of-possession challenge-response that gates creation of
    /// every `EmberSessionHandle` (see the inbound `OP_EMBER_AUTH_RESPONSE`
    /// handler and `friend_connect::run_friend_session_over_transport`,
    /// the two call sites that construct one). Chat encryption
    /// (`ember::crypto::{encrypt,decrypt}_chat_*`) derives its AEAD key
    /// from this — reusing the same identity key already bound to
    /// `ember_hash` rather than negotiating or persisting a separate one.
    peer_ember_pubkey: [u8; 32],
    /// Registration in the process-wide v2 revocation index.  Every secure
    /// connection gets one, including authenticated duplicate connections
    /// that do not win the canonical outbound-routing slot.
    secure_registration: Option<Arc<SecureSessionRegistration>>,
}

static NEXT_EMBER_SESSION_ID: AtomicU64 = AtomicU64::new(1);
type SecureRevocationIndex =
    std::sync::Mutex<HashMap<[u8; 16], HashMap<u64, tokio::sync::watch::Sender<bool>>>>;
static SECURE_REVOCATION_INDEX: std::sync::OnceLock<SecureRevocationIndex> =
    std::sync::OnceLock::new();

struct SecureSessionRegistration {
    ember_hash: [u8; 16],
    session_id: u64,
}

impl Drop for SecureSessionRegistration {
    fn drop(&mut self) {
        let Some(index) = SECURE_REVOCATION_INDEX.get() else {
            return;
        };
        let mut index = index
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(sessions) = index.get_mut(&self.ember_hash) {
            sessions.remove(&self.session_id);
            if sessions.is_empty() {
                index.remove(&self.ember_hash);
            }
        }
    }
}

/// Close every authenticated v2 stream for a removed friend, including
/// non-canonical duplicates that were intentionally excluded from
/// [`EmberSessionMap`].  Returns the number of sessions signalled.
pub fn revoke_all_secure_sessions(ember_hash: [u8; 16]) -> usize {
    let Some(index) = SECURE_REVOCATION_INDEX.get() else {
        return 0;
    };
    let senders: Vec<_> = {
        let index = index
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        index
            .get(&ember_hash)
            .map(|sessions| sessions.values().cloned().collect())
            .unwrap_or_default()
    };
    for sender in &senders {
        let _ = sender.send(true);
    }
    senders.len()
}

/// How stale a session's last confirmed inbound activity may be before
/// [`EmberSessionHandle::is_fresh`] stops trusting it. Deliberately well
/// under the ~4.5 min `STALL_TIMEOUT` a session's own reader loop uses to
/// detect and tear itself down (3x the 90s `KEEPALIVE_INTERVAL`): that
/// timeout has to tolerate a lost keepalive in each direction without
/// flapping a healthy connection, but a caller deciding whether to *trust
/// an existing session* for a fresh action (send a chat message, honor a
/// user's "retry" click, auto-retry an offline friend) can afford to be
/// more impatient — allowing one missed keepalive is enough margin
/// (2x `KEEPALIVE_INTERVAL` = 180s) without being trigger-happy.
const EMBER_SESSION_FRESH_SECS: i64 = 180;

impl EmberSessionHandle {
    pub fn new(tx: tokio::sync::mpsc::Sender<Vec<u8>>, peer_ember_pubkey: [u8; 32]) -> Self {
        let (shutdown, _) = tokio::sync::watch::channel(false);
        let session_id = NEXT_EMBER_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            tx,
            session_id,
            last_activity: Arc::new(std::sync::atomic::AtomicI64::new(
                chrono::Utc::now().timestamp(),
            )),
            shutdown,
            peer_ember_pubkey,
            secure_registration: None,
        }
    }

    pub fn new_secure(
        tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        peer_ember_pubkey: [u8; 32],
        ember_hash: [u8; 16],
    ) -> Self {
        let mut handle = Self::new(tx, peer_ember_pubkey);
        let index = SECURE_REVOCATION_INDEX.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
        index
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(ember_hash)
            .or_default()
            .insert(handle.session_id, handle.shutdown.clone());
        handle.secure_registration = Some(Arc::new(SecureSessionRegistration {
            ember_hash,
            session_id: handle.session_id,
        }));
        handle
    }

    pub fn is_secure_v2(&self) -> bool {
        self.secure_registration.is_some()
    }

    /// The peer's PoP-verified Ed25519 identity public key for this
    /// session. See the field doc for why this is trustworthy.
    pub fn peer_ember_pubkey(&self) -> [u8; 32] {
        self.peer_ember_pubkey
    }

    /// Opaque generation for binding request/response correlation to this
    /// exact TCP session. It is never sent over the wire.
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Tell the session owner to stop its reader/writer loop and drop the
    /// underlying socket. Removing this handle from `EmberSessionMap` alone
    /// is insufficient because the owner task retains its own sender clone.
    pub fn close(&self) {
        let _ = self.shutdown.send(true);
    }

    pub fn subscribe_shutdown(&self) -> tokio::sync::watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    /// Record confirmed inbound activity from the peer. Call this on
    /// *any* successfully received packet while this handle is the
    /// live Ember session for that peer — including ordinary eD2K
    /// file-serve traffic such as `OP_REQUESTPARTS`, not only Ember
    /// CHAT/BROWSE/KEEPALIVE. Without that, a friend who is only
    /// downloading from us looks stale after `EMBER_SESSION_FRESH_SECS`
    /// and the periodic sweep / chat reconnect path will `close()` the
    /// socket mid-upload.
    pub fn touch(&self) {
        self.last_activity.store(
            chrono::Utc::now().timestamp(),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// True if the peer has been heard from recently enough to trust this
    /// session for a new send/reuse decision. See `EMBER_SESSION_FRESH_SECS`.
    pub fn is_fresh(&self) -> bool {
        let last = self
            .last_activity
            .load(std::sync::atomic::Ordering::Relaxed);
        chrono::Utc::now().timestamp().saturating_sub(last) < EMBER_SESSION_FRESH_SECS
    }

    /// Test-only: force this handle's liveness timestamp into the past so
    /// `is_fresh()` reports `false`, simulating a session whose peer went
    /// silently unreachable without the reader loop's own stall-detector
    /// having torn it down yet.
    #[cfg(test)]
    pub fn backdate_for_test(&self, secs_ago: i64) {
        self.last_activity.store(
            chrono::Utc::now().timestamp() - secs_ago,
            std::sync::atomic::Ordering::Relaxed,
        );
    }
}

pub type EmberSessionMap = Arc<RwLock<HashMap<[u8; 16], EmberSessionHandle>>>;

/// Friend chat/browse authorization on a live secure-v2 stream.
///
/// Deliberately **does not** require owning the canonical `ember_sessions`
/// outbound-routing slot: simultaneous mutual dials leave one connection as
/// the map winner and the other as a non-canonical inbound, and both must
/// still accept chat/browse.  Slot ownership only controls which `tx` Send
/// paths reuse for outbound packets.
///
/// Friend **upload-queue priority** uses [`live_secure_friend_member`] and is
/// likewise restricted to secure-v2 sessions — stock eMule file sockets cannot
/// be authenticated without restoring the retired legacy PoP signing oracle.
fn friend_privileges_allowed(secure_v2_authenticated: bool, live_friend_member: bool) -> bool {
    secure_v2_authenticated && live_friend_member
}

/// True when this peer may receive friend-slot upload priority / verified
/// Ember scoring on **this** TCP session.
///
/// Requires secure friend-stream v2 on the session. Ordinary eMule download
/// connections from a known friend hash intentionally return `false`: there is
/// no cryptographically bound live proof on those sockets without re-enabling
/// legacy PoP, and an outbound file dial to an *anonymous* source learns the
/// peer Ember hash only after the TCP discriminator (too late for Noise IK).
/// A friend-transfer dial answering `OP_EMBER_XFER_REQ` is the one exception:
/// it knows which friend it is calling before connecting, so it negotiates
/// Noise IK up front (see [`ConnectServeRequest::secure_friend_ember_hash`])
/// and does qualify. UI copy documents that priority applies only to
/// authenticated Ember secure friend sessions.
async fn live_secure_friend_member(
    friend_hashes: &Arc<RwLock<std::collections::HashSet<[u8; 16]>>>,
    peer_ember_hash: Option<[u8; 16]>,
    secure_v2_authenticated: bool,
) -> bool {
    if !secure_v2_authenticated {
        return false;
    }
    match peer_ember_hash {
        Some(hash) => friend_hashes.read().await.contains(&hash),
        None => false,
    }
}

/// The requesting peer's authenticated identity on a single upload session,
/// as far as [`UploadHandler::resolve_upload_file`] needs it.
///
/// Passing this rather than a precomputed boolean keeps the mutual-friend
/// lookup lazy: it happens only when the resolved file is actually restricted,
/// so ordinary public serving takes no extra lock.
#[derive(Clone, Copy, Default)]
pub(crate) struct PeerFileAccess {
    /// Peer Ember hash, once proven. `None` until `OP_EMBER_HELLO` lands, and
    /// forever on plain eMule sockets.
    pub ember_hash: Option<[u8; 16]>,
    /// Whether this session completed the Noise IK secure friend handshake.
    pub secure_v2_authenticated: bool,
}

/// True when this peer may reach **private** content on this session: friends
/// -only files and friend browse answers.
///
/// Stricter than [`live_secure_friend_member`] on purpose. Slot priority is a
/// courtesy we extend to anyone we listed, so a one-sided add earning it is
/// harmless. Private content is the opposite: honouring a one-sided add there
/// would let anyone who learns our Ember hash add us and read our friends-only
/// library. So this additionally requires that the peer added us back.
async fn mutual_friend_access(
    mutual_friend_hashes: &Arc<RwLock<std::collections::HashSet<[u8; 16]>>>,
    peer_ember_hash: Option<[u8; 16]>,
    secure_v2_authenticated: bool,
) -> bool {
    if !secure_v2_authenticated {
        return false;
    }
    match peer_ember_hash {
        Some(hash) => mutual_friend_hashes.read().await.contains(&hash),
        None => false,
    }
}

/// Configured-server IPs may use reserved admission slots **only** for the
/// short HighID port-test protocol.  Long-lived upload/friend sessions that
/// entered via that reserve must be rejected once ordinary capacity is full.
fn allow_long_lived_session_under_admission(
    from_configured_server_ip: bool,
    total_connections: usize,
) -> bool {
    !from_configured_server_ip || total_connections <= MAX_TOTAL_CONNECTIONS
}

/// Remove `hash`'s entry from `sessions` if present but stale (see
/// [`EmberSessionHandle::is_fresh`]), returning `true` if it was evicted.
/// Centralizes the "is this friend actually reachable, not just
/// present-in-the-map" check for every site that gates a dial/send
/// decision on `EmberSessionMap` — see [`EmberSessionHandle`]'s doc
/// comment for why presence alone isn't enough. Takes a write lock
/// unconditionally (simpler than upgrading a read lock, and this is only
/// called from cold paths: explicit user actions and periodic sweeps, not
/// per-packet hot loops).
pub async fn evict_stale_ember_session(sessions: &EmberSessionMap, hash: &[u8; 16]) -> bool {
    let mut sessions = sessions.write().await;
    if let Some(handle) = sessions.get(hash) {
        if !handle.is_fresh() {
            handle.close();
            sessions.remove(hash);
            return true;
        }
    }
    false
}

use super::dead_sources::PENDING_KAD_CALLBACK_SECS;
use super::messages::*;
use crate::network::kad::buddy::PendingBuddySet;
use crate::network::kad::ip_filter::SharedIpFilter;
use crate::network::kad::types::cuint128_swap;

// Post-negotiation stream wrappers. Defined at module scope (rather than inline
// in `run_session`) so the outbound connect-and-serve path can build the same
// concrete reader/writer the inbound path uses and hand them to the shared
// session logic. An enum avoids dyn dispatch on the hot upload read/write path.
enum StreamReader {
    Plain(tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>),
    Obfuscated(
        tokio::io::BufReader<Rc4Reader<tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>>>,
    ),
    /// A pre-established, already-encrypted-at-the-transport-layer stream
    /// (QUIC hole-punch / peer-relay / server-relay) handed to us via
    /// [`ConnInit::InboundStream`]. Never obfuscation-negotiated: the far
    /// end sends plain eD2k framing directly, matching how the download
    /// side treats these same transports in `ember::broker` /
    /// `friend_connect::run_friend_session_over_transport`.
    Boxed(Box<dyn tokio::io::AsyncRead + Unpin + Send>),
}
enum StreamWriter {
    Plain(tokio::io::BufWriter<tokio::net::tcp::OwnedWriteHalf>),
    Obfuscated(
        tokio::io::BufWriter<Rc4Writer<tokio::io::BufWriter<tokio::net::tcp::OwnedWriteHalf>>>,
    ),
    Boxed(Box<dyn tokio::io::AsyncWrite + Unpin + Send>),
}

impl AsyncRead for StreamReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            StreamReader::Plain(r) => Pin::new(r).poll_read(cx, buf),
            StreamReader::Obfuscated(r) => Pin::new(r).poll_read(cx, buf),
            StreamReader::Boxed(r) => Pin::new(&mut **r).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for StreamWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            StreamWriter::Plain(w) => Pin::new(w).poll_write(cx, buf),
            StreamWriter::Obfuscated(w) => Pin::new(w).poll_write(cx, buf),
            StreamWriter::Boxed(w) => Pin::new(&mut **w).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            StreamWriter::Plain(w) => Pin::new(w).poll_flush(cx),
            StreamWriter::Obfuscated(w) => Pin::new(w).poll_flush(cx),
            StreamWriter::Boxed(w) => Pin::new(&mut **w).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            StreamWriter::Plain(w) => Pin::new(w).poll_shutdown(cx),
            StreamWriter::Obfuscated(w) => Pin::new(w).poll_shutdown(cx),
            StreamWriter::Boxed(w) => Pin::new(&mut **w).poll_shutdown(cx),
        }
    }
}

/// How an upload session was initiated.
///
/// `Inbound` is a peer that dialed our listener (the classic path). `OutboundServe`
/// is a connection *we* dialed in response to a server/KAD callback so a
/// firewalled (LowID) node can still upload — mirroring eMule's
/// `OP_CALLBACKREQUESTED` → `TryToConnect` → unified-client-serve behaviour.
/// Both variants share the entire post-handshake serve loop in `run_session`;
/// only the handshake preamble differs (who sends `OP_HELLO` first, and
/// `negotiate_incoming` vs `negotiate_outgoing`).
enum ConnInit {
    Inbound(TcpStream),
    OutboundServe(Box<OutboundServeState>),
    /// A pre-established bidirectional stream from Ember NAT traversal
    /// (QUIC hole-punch, peer relay, or rendezvous server relay) where we
    /// are the source/upload side despite not being a literal `TcpListener`
    /// acceptor. The far end still sends `OP_HELLO` first exactly like a
    /// normal inbound TCP dial, so this converges into the same
    /// server-role handshake as [`ConnInit::Inbound`] minus the TCP accept
    /// and obfuscation-negotiation steps (the transport is already secured
    /// end-to-end by QUIC/TLS, so no RC4 layer is negotiated on top).
    InboundStream {
        reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
        secure_peer: Option<super::secure_stream::SecurePeerIdentity>,
    },
}

/// Request handed from the network task to the upload listener for a
/// pre-established stream (Ember QUIC hole-punch, peer relay, or
/// rendezvous server relay) that should be served as an upload session.
/// Flows network → upload, alongside [`ConnectServeRequest`] (which dials
/// out) and opposite [`KadCallbackParts`] (which flows upload → network for
/// the download-adoption path this is deliberately *not* used for — see
/// [`ConnInit::InboundStream`]).
pub struct InboundStreamRequest {
    pub peer_addr: SocketAddr,
    pub reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    pub writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    /// When set, this stream came from a coordinated friend-transfer punch and
    /// we are the *uploader*: negotiate Noise IK as initiator against this
    /// Ember hash and take the eD2K serve role instead of the default inbound
    /// role. See [`UploadServer::serve_punched_friend`].
    ///
    /// `None` — every other punch, relay, and broker stream — keeps the
    /// historical inbound behaviour.
    pub serve_friend_ember_hash: Option<[u8; 16]>,
}

/// A fully handshaked outbound connection produced by `connect_and_serve`, handed
/// to `run_session` so it converges straight into the shared serve loop without
/// re-running any inbound-only handshake steps.
struct OutboundServeState {
    reader: StreamReader,
    writer: StreamWriter,
    /// The peer's `OP_HELLOANSWER` payload. Parsed once into `hello_caps` before
    /// entering the serve loop; the inbound-only diversions that also read
    /// `hello_data` are skipped for outbound so its exact bytes don't matter
    /// past that parse.
    hello_data: Vec<u8>,
    peer_user_hash: [u8; 16],
    hello_caps: PeerCapabilities,
    /// A packet the peer sent *instead of* `OP_EMULEINFOANSWER` during the
    /// outbound handshake (e.g. it jumped straight to a file request). Rare —
    /// eMule answers EmuleInfo first — but when present it is fed to the serve
    /// loop as its first `deferred_packet` so nothing is dropped.
    first_packet: Option<(u8, u8, Vec<u8>)>,
    /// HighID push-grant file (AddUpNextClient). When set, the serve loop
    /// starts with this file and has already sent `OP_ACCEPTUPLOADREQ`.
    push_grant_file_hash: Option<[u8; 16]>,
    /// See [`ConnectServeRequest::push_grant_accepted`].
    push_grant_accepted: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Set when this dial negotiated Noise IK for
    /// [`ConnectServeRequest::secure_friend_ember_hash`]. Unlike every other
    /// outbound dial — which learns the peer's Ember hash only from an
    /// in-stream `OP_EMBER_HELLO`, far too late to be privilege-bearing — a
    /// secure friend dial proves the peer's identity before any eD2K byte, so
    /// the serve loop may treat it as authenticated and grant friend-slot
    /// upload priority.
    secure_peer: Option<super::secure_stream::SecurePeerIdentity>,
}

/// Request from the network task asking the upload listener to dial `peer_addr`
/// and serve it — the LowID callback-upload path. Flows network → upload,
/// opposite to [`KadCallbackParts`] (which flows upload → network for the
/// download-adoption path).
#[derive(Debug, Clone)]
pub struct ConnectServeRequest {
    pub peer_addr: SocketAddr,
    /// Peer crypt options from the callback (bit0 = supports, bit1 = requests,
    /// bit2 = requires). Drives whether we dial obfuscated, matching eMule's
    /// `SetConnectOptions` + `Connect` encryption decision.
    pub crypt_options: u8,
    /// Peer ED2K user hash from the callback when known. Required to seed the
    /// RC4 key for an obfuscated dial (eMule derives obfuscation from the user
    /// hash); `None`/zero forces a plain dial.
    pub user_hash: Option<[u8; 16]>,
    /// When `Some`, this is an eMule `AddUpNextClient` HighID push-grant: after
    /// handshake we send `OP_ACCEPTUPLOADREQ` and seed the file hash so the
    /// peer can start `OP_REQUESTPARTS` without another `STARTUPLOADREQ`.
    pub push_grant_file_hash: Option<[u8; 16]>,
    /// Set to `true` once `OP_ACCEPTUPLOADREQ` is sent for a push-grant so the
    /// caller can distinguish pre-grant dial failures (restore seniority) from
    /// post-grant session errors (do not restore).
    pub push_grant_accepted: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// When `Some(ember_hash)`, this dial answers a friend's
    /// `OP_EMBER_XFER_REQ`: negotiate a Noise IK secure stream against that
    /// expected identity instead of RC4 obfuscation, so the friend can route
    /// our connection into the right download by *proven* identity (see
    /// [`PendingKadCallbackKey::FriendEmber`]) and the transfer is encrypted
    /// end to end. There is deliberately no plain-TCP fallback: a friend
    /// transfer that silently downgraded would lose exactly the identity
    /// binding the routing depends on.
    pub secure_friend_ember_hash: Option<[u8; 16]>,
}

struct UploadSlotGuard {
    active_count: Arc<std::sync::atomic::AtomicUsize>,
    slot_notify: Arc<tokio::sync::Notify>,
    armed: bool,
}

struct ConnectionAdmissionGuard {
    total: Arc<std::sync::atomic::AtomicUsize>,
    per_ip: Arc<parking_lot::Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl ConnectionAdmissionGuard {
    fn new(
        total: Arc<std::sync::atomic::AtomicUsize>,
        per_ip: Arc<parking_lot::Mutex<HashMap<IpAddr, usize>>>,
        ip: IpAddr,
    ) -> Self {
        Self { total, per_ip, ip }
    }
}

impl Drop for ConnectionAdmissionGuard {
    fn drop(&mut self) {
        self.total
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        let mut counts = self.per_ip.lock();
        if let Some(count) = counts.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

impl UploadSlotGuard {
    fn new(
        active_count: Arc<std::sync::atomic::AtomicUsize>,
        slot_notify: Arc<tokio::sync::Notify>,
    ) -> Self {
        Self {
            active_count,
            slot_notify,
            armed: false,
        }
    }

    /// Atomically reserve a slot iff the live count is still below `limit`.
    /// Returns `true` if this guard now owns a slot. Unlike `activate()` (an
    /// unconditional `fetch_add`), this closes the check-then-activate race
    /// where several connection tasks each observe an open slot across their
    /// `.await` points and all increment past `limit`. Already-armed guards
    /// return `true` without double-counting.
    fn try_activate(&mut self, limit: usize) -> bool {
        if self.armed {
            return true;
        }
        let mut current = self.active_count.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            if current >= limit {
                return false;
            }
            match self.active_count.compare_exchange_weak(
                current,
                current + 1,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.armed = true;
                    return true;
                }
                Err(actual) => current = actual,
            }
        }
    }

    fn is_active(&self) -> bool {
        self.armed
    }

    fn deactivate(&mut self) {
        if self.armed {
            self.active_count
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            self.armed = false;
            self.slot_notify.notify_waiters();
        }
    }
}

impl Drop for UploadSlotGuard {
    fn drop(&mut self) {
        if self.armed {
            self.active_count
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            self.slot_notify.notify_waiters();
        }
    }
}

/// Shared set of banned peer IPs (updated by network task on Ban/Unban commands)
pub type SharedBannedIps = Arc<std::sync::RwLock<std::collections::HashSet<std::net::Ipv4Addr>>>;

/// Shared set of banned user hashes for upload-only enforcement.
/// Checked after Hello handshake reveals the peer's identity.
pub type SharedBannedHashes = Arc<std::sync::RwLock<std::collections::HashSet<[u8; 16]>>>;

/// known.met `friends_only` hashes, snapshotted for the upload listener.
///
/// [`UploadHandler`] cannot read `KnownFileList` (it lives on the network
/// task). The share index already covers library rows, but a friends-only
/// flag that exists **only** in known.met — an in-progress download of a
/// previously restricted hash, or an unshared completed copy that fell
/// through to `.part` — is invisible there. This set is the missing half.
///
/// `ready` is false until known.met has been absorbed. An empty hash set
/// with `ready == false` must not be read as "nothing is restricted".
#[derive(Default)]
pub struct FriendsOnlySnapshot {
    ready: bool,
    hashes: std::collections::HashSet<[u8; 16]>,
}

pub type SharedFriendsOnlyHashes = Arc<std::sync::RwLock<FriendsOnlySnapshot>>;

pub fn replace_friends_only_hashes(
    dest: &SharedFriendsOnlyHashes,
    hashes: impl IntoIterator<Item = [u8; 16]>,
) {
    let next: std::collections::HashSet<[u8; 16]> = hashes.into_iter().collect();
    match dest.write() {
        Ok(mut snap) => snap.hashes = next,
        Err(poisoned) => poisoned.into_inner().hashes = next,
    }
}

pub fn mark_friends_only_snapshot_ready(dest: &SharedFriendsOnlyHashes) {
    match dest.write() {
        Ok(mut snap) => snap.ready = true,
        Err(poisoned) => poisoned.into_inner().ready = true,
    }
}

pub(crate) fn friends_only_snapshot_contains(set: &SharedFriendsOnlyHashes, hash: &[u8; 16]) -> bool {
    match set.read() {
        Ok(s) => s.hashes.contains(hash),
        Err(poisoned) => poisoned.into_inner().hashes.contains(hash),
    }
}

pub(crate) fn friends_only_snapshot_ready(set: &SharedFriendsOnlyHashes) -> bool {
    match set.read() {
        Ok(s) => s.ready,
        Err(poisoned) => poisoned.into_inner().ready,
    }
}

/// Snapshot hit is always restricted. Until known.met has been absorbed,
/// fail closed even when the live index says public — hashing starts rows
/// with `friends_only: false`, and restoring that flag from known.met can
/// lag the first serve. After the snapshot is ready, the index row wins
/// when present and a miss is public.
fn friends_only_from_sources(
    snapshot_hit: bool,
    snapshot_ready: bool,
    index_friends_only: Option<bool>,
) -> bool {
    if snapshot_hit {
        return true;
    }
    if !snapshot_ready {
        return true;
    }
    index_friends_only.unwrap_or(false)
}

/// Shared buddy info for including in Hello tags (updated by network task)
pub type SharedBuddyInfo = Arc<RwLock<Option<BuddyInfo>>>;

/// IPs we've sent KADEMLIA_FIREWALLED_REQ to; a TCP connect-back from one of
/// these proves our TCP port is reachable (not firewalled).
pub type FirewallProbeSet = Arc<std::sync::Mutex<std::collections::HashSet<std::net::Ipv4Addr>>>;

/// Per-slot smoothed upload rate registry: peer address -> bytes/sec (EWMA).
/// Updated by each upload task; read by `compute_dynamic_slot_count`.
pub(crate) type SlotRateRegistry = Arc<parking_lot::Mutex<HashMap<SocketAddr, u64>>>;

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
    /// The peer's *advertised listening* TCP port, parsed from its Hello
    /// (bytes 21-22). Distinct from `peer_port`, which is the ephemeral source
    /// port of this inbound connection. Used to link a server-LowID callback
    /// back to the LowID source row we stored at that listening port (keyed by
    /// `(server, listening_port)`), so the peer isn't double-counted. `0` when
    /// the Hello was too short to carry it.
    pub peer_hello_port: u16,
    pub peer_user_hash: [u8; 16],
    pub file_hash: [u8; 16],
    pub reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    pub writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    /// True if EmuleInfo exchange was already done (obfuscated connections).
    pub emule_info_done: bool,
    /// Capabilities parsed from the peer's Hello so the adopting downloader
    /// formats its file request the way the peer expects (notably the
    /// extended-requests version that gates the OP_REQUESTFILENAME part
    /// bitmap — omitting it makes the peer short-read and FIN).
    pub peer_caps: PeerCapabilities,
    /// Set only when this connection answered our `OP_EMBER_XFER_REQ`, to the
    /// Ember hash the Noise IK handshake proved. Lets the adoption path retire
    /// exactly that friend request, instead of assuming any adopted callback
    /// for the same file was the friend connect-back it was waiting on (a
    /// genuine server/KAD LowID callback can arrive for the same download).
    pub friend_ember_hash: Option<[u8; 16]>,
}

/// Path B (eMule queued-source model) inbound reconnect index.
///
/// Maps a queued-source peer's IPv4 → the set of `(file_hash, optional user
/// hash)` an *active download* is currently queued on that peer for. The
/// network loop rebuilds it every few seconds from `per_file_sources` (sources
/// in the `OnQueue` state of live downloads); the inbound `handle_connection`
/// reads it so an uploader that *connects back to us* to grant a slot (a HighID
/// push-grant — eMule reconnects to deep-queued HighID downloaders from
/// `CUploadQueue::AddUpNextClient` instead of waiting for the next re-ask) is
/// recognised and its freshly-handshaked stream is diverted straight into the
/// waiting download, via the same adoption channel a LowID/KAD callback uses,
/// rather than being mishandled as an upload request.
///
/// The map is empty whenever no download has queued sources, so the inbound
/// path is a no-op for ordinary peers. It is rebuilt wholesale (not mutated
/// incrementally) so stale entries self-heal: a source no longer `OnQueue`, or
/// a finished download, simply vanishes on the next rebuild, bounding a
/// mismatched divert to one rebuild interval (and even then the adoption side
/// safely drops a stream that has no matching active download).
pub type ReconnectIndex =
    std::collections::HashMap<std::net::Ipv4Addr, Vec<([u8; 16], Option<[u8; 16]>)>>;

/// Normalize a source user hash for Path B indexing: all-zero is treated as
/// unknown (`None`) so it never equality-matches a Hello of `[0;16]`.
pub fn reconnect_user_hash(uh: Option<[u8; 16]>) -> Option<[u8; 16]> {
    uh.filter(|h| *h != [0u8; 16])
}

/// Pick a file hash for Path B diversion from the reconnect index entries at
/// `peer_v4`. Prefers an exact non-zero user-hash match; falls back to
/// unknown-hash entries only when the peer hash is also unknown or there is
/// no conflicting known-hash entry for a different user at this IP.
pub(crate) fn path_b_divert_file(
    entries: &[([u8; 16], Option<[u8; 16]>)],
    peer_user_hash: [u8; 16],
) -> Option<[u8; 16]> {
    let peer_uh = reconnect_user_hash(Some(peer_user_hash));
    if let Some(puh) = peer_uh {
        if let Some((fh, _)) = entries.iter().find(|(_, uh)| *uh == Some(puh)) {
            return Some(*fh);
        }
        // Known peer identity but no matching entry — do not steal another
        // user's unknown-hash OnQueue row at the same NAT IP.
        let has_other_known = entries
            .iter()
            .any(|(_, uh)| matches!(uh, Some(h) if *h != puh));
        if has_other_known {
            return None;
        }
        return entries
            .iter()
            .find(|(_, uh)| uh.is_none())
            .map(|(fh, _)| *fh);
    }
    // Peer Hello hash unknown: only match unknown-hash entries.
    entries
        .iter()
        .find(|(_, uh)| uh.is_none())
        .map(|(fh, _)| *fh)
}

static RECONNECT_INDEX: std::sync::OnceLock<std::sync::Arc<std::sync::RwLock<ReconnectIndex>>> =
    std::sync::OnceLock::new();

/// Shared handle to the Path B reconnect index (lazily created on first use).
/// The network loop holds one clone and overwrites its contents each rebuild;
/// `handle_connection` reads it per inbound connection. The guard is cheap and
/// is never held across an `.await`.
pub fn reconnect_index() -> std::sync::Arc<std::sync::RwLock<ReconnectIndex>> {
    RECONNECT_INDEX
        .get_or_init(|| std::sync::Arc::new(std::sync::RwLock::new(ReconnectIndex::new())))
        .clone()
}

/// How eMule keys a firewalled KAD callback source before the peer connects.
/// Type 3/5 publishes buddy IP in `TAG_SERVERIP` but usually omits
/// `TAG_SOURCEIP`, so the publisher's ED2K user hash is the stable identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PendingKadCallbackKey {
    SourceIp(std::net::Ipv4Addr),
    SourceUserHash([u8; 16]),
    /// A friend we asked to connect back via `OP_EMBER_XFER_REQ`, keyed by
    /// the Ember hash the inbound Noise IK handshake *proves* they own.
    ///
    /// Unlike the two keys above — which match on self-reported or
    /// server-reported metadata and can collide with an unrelated peer — this
    /// key cannot be spoofed, so its diversion runs even for connections that
    /// otherwise `skip_diversions` (see `run_session`).
    FriendEmber([u8; 16]),
}

#[derive(Debug, Clone)]
pub struct PendingKadCallbackEntry {
    pub file_hash: [u8; 16],
    /// `TAG_SOURCEPORT` from the KAD publish (used for disambiguation).
    pub expected_tcp_port: u16,
    pub registered_at: i64,
}

/// Pending inbound KAD callbacks. Type 3/5 sources are keyed by user hash;
/// type 6 / direct-callback sources with a real `TAG_SOURCEIP` use IP.
pub type PendingKadCallbacks =
    Arc<tokio::sync::Mutex<HashMap<PendingKadCallbackKey, Vec<PendingKadCallbackEntry>>>>;

/// UI / placeholder row key for a KAD callback source before connect-back.
pub fn kad_callback_display_key(ip: std::net::Ipv4Addr, user_hash: Option<[u8; 16]>) -> String {
    if ip.is_unspecified() {
        user_hash
            .filter(|h| *h != [0u8; 16])
            .map(|h| format!("uh:{}", hex::encode(h)))
            .unwrap_or_else(|| "0.0.0.0".to_string())
    } else {
        ip.to_string()
    }
}

pub struct UdpFirewallCheckRequest {
    pub peer_ip: Ipv4Addr,
    pub internal_udp_port: u16,
    pub external_udp_port: u16,
    pub receiver_udp_key: u32,
}

const CLIENT_TIMEOUT_SECS: u64 = 120;
/// One wall-clock budget covers transport discrimination, optional
/// obfuscation/secure-stream negotiation, and receipt of the first complete
/// eD2K frame.
const INBOUND_PREAUTH_DEADLINE_SECS: u64 = 15;
/// Per-step timeout for the *outbound* callback-serve handshake (TCP connect,
/// Hello/EmuleInfo round-trips). Much tighter than [`CLIENT_TIMEOUT_SECS`]:
/// a callback peer that doesn't answer promptly isn't worth a long stall on a
/// task we spawned proactively. Matches the peer-connect timeout the download
/// side uses.
const OUTBOUND_SERVE_HANDSHAKE_SECS: u64 = 15;
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

/// How long after the last credited byte an `OP_REQUESTPARTS` naming only
/// already-delivered ranges still counts as activity.
///
/// Generous enough that a genuinely pipelined peer is never rotated for it —
/// padding accompanies a stream of real blocks, so the gap is milliseconds —
/// while bounding a peer that only re-asks to roughly this window rather than
/// to the hour-long `SESSIONMAXTIME_SECS`.
const PADDING_KEEPALIVE_WINDOW: std::time::Duration =
    std::time::Duration::from_secs(SLOT_IDLE_TIMEOUT_SECS * 2);

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

/// Max concurrent outbound HighID push-grant dials (AddUpNextClient).
const MAX_PUSH_GRANT_DIALS: usize = 3;
/// Backoff after a failed HighID push dial before retrying the same peer.
const PUSH_GRANT_BACKOFF_SECS: u64 = 30;

/// Maximum concurrent TCP connections from a single IP address
const MAX_CONNECTIONS_PER_IP: usize = 3;
/// Maximum waiting-list entries permitted from a single IP address
/// (eMule `cSameIP` cap in `CUploadQueue::AddClientToQueue`). Unlike
/// [`MAX_CONNECTIONS_PER_IP`] this also counts disconnected but
/// still-queued entries (via [`QueueEntry::last_ip`]), so a peer cannot
/// churn connections with rotating user-hashes to dilute the queue.
const MAX_QUEUE_ENTRIES_PER_IP: usize = 3;
/// Maximum total concurrent TCP connections to the upload server
const MAX_TOTAL_CONNECTIONS: usize = 100;
/// Extra accept slots reserved so the configured eD2K server can still complete
/// its short HighID port-test while ordinary capacity is saturated.  Long-lived
/// sessions from that IP that only fit because of this reserve are rejected in
/// [`allow_long_lived_session_under_admission`].
const RESERVED_PORT_TEST_CONNECTIONS: usize = 4;
/// Maximum number of peers waiting in the upload queue
const MAX_UPLOAD_QUEUE_SIZE: usize = 500;
/// eMule SESSIONMAXTRANS: max bytes uploaded per session before rotating slots (opcodes.h:97).
const SESSIONMAXTRANS: u64 = PARTSIZE + 20 * 1024;
/// eMule SESSIONMAXTIME: max duration of a single upload session (1 hour).
const SESSIONMAXTIME_SECS: u64 = 3600;
/// Most bytes a single `OP_REQUESTPARTS` may commit us to serving.
///
/// The block loop that serves a request runs to completion before any
/// rotation control is evaluated, so this is what bounds how long one peer can
/// hold a slot uninterrupted. Set to the session quantum: an eMule-family peer
/// asks for three `EMBLOCKSIZE` blocks per request, so nothing legitimate
/// comes close.
const MAX_REQUESTPARTS_BYTES: u64 = SESSIONMAXTRANS;
/// eMule MIN_UP_CLIENTS_ALLOWED: minimum upload slots regardless of bandwidth
const MIN_UP_CLIENTS_ALLOWED: usize = 2;
/// Slots admitted before bandwidth is allowed to veto a new one.
///
/// eMule's `CUploadQueue::AcceptNewClient` waives its datarate veto below
/// `max(MIN_UP_CLIENTS_ALLOWED, 4)` (UploadQueue.cpp), so the constant alone is
/// not the floor — flooring at 2 served half as many peers as eMule would in
/// every regime where observed upload sits under the per-slot target, and it is
/// self-reinforcing because the slot count is derived from observed throughput.
const ADMISSION_FLOOR_SLOTS: usize = {
    if MIN_UP_CLIENTS_ALLOWED > 4 {
        MIN_UP_CLIENTS_ALLOWED
    } else {
        4
    }
};
/// eMule MAX_UP_CLIENTS_ALLOWED: maximum upload slots
const MAX_UP_CLIENTS_ALLOWED: usize = 100;
/// eMule UPLOAD_CLIENT_MAXDATARATE (opcodes.h:109): the assumed per-slot target
/// upload rate caps at 25 KiB/s. As the active slot count grows the per-slot
/// target grows by 1 KiB/s per slot up to this cap, which limits how many extra
/// slots the dynamic calculation opens. Matches CUploadQueue::GetTargetClientDataRate.
const UPLOAD_CLIENT_MAXDATARATE: u64 = 25 * 1024;
/// m7: Hard queue limit = soft + max(soft, 800) / 4.  Between soft and hard,
/// only clients with above-average score are admitted; above hard, all rejected.
const HARD_UPLOAD_QUEUE_SIZE: usize = MAX_UPLOAD_QUEUE_SIZE
    + (if MAX_UPLOAD_QUEUE_SIZE > 800 {
        MAX_UPLOAD_QUEUE_SIZE
    } else {
        800
    }) / 4;
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
        Self {
            entries: HashMap::new(),
        }
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
        self.entries
            .retain(|_, (t, _)| t.elapsed().as_secs() < 3600);
        // Hard cap: a peer rotating through millions of distinct file
        // hashes within the 1h window could otherwise grow this map
        // without bound (cleanup_stale only drops entries older than 1h).
        // When over the cap, keep the most-recently-active entries (those
        // closest to a ban decision) and drop the oldest — dropping an old
        // entry only resets a stale, near-expiry counter.
        const MAX_FILE_REQUEST_ENTRIES: usize = 50_000;
        if self.entries.len() > MAX_FILE_REQUEST_ENTRIES {
            let mut by_age: Vec<((Ipv4Addr, [u8; 16]), std::time::Instant)> =
                self.entries.iter().map(|(k, (t, _))| (*k, *t)).collect();
            by_age.sort_by(|a, b| b.1.cmp(&a.1));
            let keep: std::collections::HashSet<(Ipv4Addr, [u8; 16])> = by_age
                .into_iter()
                .take(MAX_FILE_REQUEST_ENTRIES)
                .map(|(k, _)| k)
                .collect();
            self.entries.retain(|k, _| keep.contains(k));
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

/// True when a queue row may be mutated, taken over, or removed by this session.
/// Unbound (`current_addr` is `None`) is a reconnect. A live bind is the same
/// client when the IP and Hello-advertised TCP port match — eMule
/// `AttachToAlreadyKnown` keys on `GetUserPort()`, not the ephemeral source
/// port — so a NAT rebind adopts the row. A different IP (or advertised port)
/// must not steal or delete a bound row.
fn queue_row_owned_by_session(
    current_addr: Option<SocketAddr>,
    row_tcp_port: u16,
    peer_addr: SocketAddr,
    session_tcp_port: u16,
) -> bool {
    match current_addr {
        None => true,
        Some(bound) => {
            bound == peer_addr
                || (bound.ip() == peer_addr.ip() && row_tcp_port == session_tcp_port)
        }
    }
}

/// After this identity has been granted a slot, keep its waiting-list row
/// only when a *different IP* still owns the bind (hash collision / spoof).
/// Same IP with a mismatched advertised port is a NAT rebind of the peer
/// that just got the slot — seniority must not sit beside the grant.
fn keep_queue_row_after_slot_grant(
    grant_identity: &QueueIdentity,
    grant_ip: IpAddr,
    entry: &QueueEntry,
) -> bool {
    entry.identity != *grant_identity
        || entry
            .current_addr
            .is_some_and(|bound| bound.ip() != grant_ip)
}

/// Shared handle to the upload queue so non-upload subsystems (e.g. the UDP
/// OP_REASKFILEPING handler in `network/mod.rs`) can report an accurate
/// queue rank for their peers instead of a placeholder 0.
pub(crate) type UploadQueueRef = Arc<tokio::sync::Mutex<Vec<QueueEntry>>>;

/// eMule-style upload parts tracking. Records how many bytes of each
/// ED2K part (`PARTSIZE`, 9.28 MB) we have actually delivered to the
/// peer during the current session, so the UI can paint a per-chunk
/// "Up Status" bar — the analog of the green `m_DoneBlocks_list` fill in
/// eMule's `CUploadListCtrl::DrawUpStatusBar`. `offset`/`len` describe a
/// fully-delivered on-wire range; each part's tally is capped at
/// `PARTSIZE` so a peer re-requesting blocks can't push a part past
/// "complete".
fn mark_served_parts(served: &mut [u64], offset: u64, len: u64) {
    if served.is_empty() || len == 0 {
        return;
    }
    let mut pos = offset;
    let mut remaining = len;
    while remaining > 0 {
        let part = (pos / PARTSIZE) as usize;
        if part >= served.len() {
            break;
        }
        let part_end = (part as u64 + 1).saturating_mul(PARTSIZE);
        let in_this = part_end.saturating_sub(pos).min(remaining);
        if in_this == 0 {
            break;
        }
        served[part] = served[part].saturating_add(in_this).min(PARTSIZE);
        pos = pos.saturating_add(in_this);
        remaining -= in_this;
    }
}

/// Build the IPC representation of the served-parts tally: a hex bitmap
/// (byte index = `part / 8`, bit = `part % 8`, LSB-first within each
/// byte) where a set bit means that whole part has been delivered this
/// session, paired with the file's total part count. Returns
/// `(None, None)` only when the total size is unknown; otherwise the
/// bitmap is always emitted (all-zero early on) so the UI can render a
/// full-width grey bar immediately and fill it in as parts complete.
fn build_up_part_status(served: &[u64], total_size: u64) -> (Option<String>, Option<u32>) {
    use std::fmt::Write as _;
    if total_size == 0 {
        return (None, None);
    }
    let part_count = total_size.div_ceil(PARTSIZE).max(1) as usize;
    let mut bytes = vec![0u8; part_count.div_ceil(8)];
    // Only trust the tally when it matches the current file's part count.
    // During a mid-session file switch it can briefly still be sized for the
    // previous file; rather than paint stale parts we emit an all-grey bar
    // until the new file's blocks land and re-size the tally.
    if served.len() == part_count {
        for (i, &s) in served.iter().enumerate() {
            let part_size = if i + 1 < part_count {
                PARTSIZE
            } else {
                total_size.saturating_sub((part_count as u64 - 1) * PARTSIZE)
            };
            if part_size > 0 && s >= part_size {
                bytes[i / 8] |= 1u8 << (i % 8);
            }
        }
    }
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in &bytes {
        let _ = write!(hex, "{b:02x}");
    }
    (Some(hex), Some(part_count as u32))
}

/// Decode a downloader's advertised ED2K part bitmap (from the
/// `OP_REQUESTFILENAME` extended-info block — see
/// [`MultiPacketRequest::req_part_status`]) into the IPC hex bitmap used by the
/// upload parts bar, the analog of eMule's `m_abyUpPartStatus`
/// (`CUpDownClient::ProcessExtendedInfo`). `advertised` is the peer's
/// `GetED2KPartCount()`-convention count and `bitmap` its raw LSB-first bytes
/// (bit `i` = part `i`).
///
/// Returns `None` — i.e. no dark "peer already has" shading, the graceful
/// fallback — when the size is unknown, the advertised count does not match
/// this file's wire part count, the bitmap is too short, or the peer has no
/// parts. This refuse-on-mismatch posture means a malformed or stale
/// advertisement from an untrusted peer can never paint garbage parts; a
/// matching peer's output is re-packed to the file's real part count so it
/// lines up bit-for-bit with the served bitmap from [`build_up_part_status`].
fn peer_part_status_hex(advertised: u16, bitmap: &[u8], total_size: u64) -> Option<String> {
    use std::fmt::Write as _;
    if total_size == 0 || advertised == 0 {
        return None;
    }
    let real_parts = ed2k_part_count_for_size(total_size);
    if real_parts == 0 || Some(advertised) != ed2k_wire_part_count_u16(total_size) {
        return None;
    }
    let need = (advertised as usize).div_ceil(8);
    if bitmap.len() < need {
        return None;
    }
    let mut out = vec![0u8; real_parts.div_ceil(8)];
    let mut any = false;
    for i in 0..real_parts {
        if (bitmap[i / 8] >> (i % 8)) & 1 != 0 {
            out[i / 8] |= 1u8 << (i % 8);
            any = true;
        }
    }
    if !any {
        return None;
    }
    let mut hex = String::with_capacity(out.len() * 2);
    for b in &out {
        let _ = write!(hex, "{b:02x}");
    }
    Some(hex)
}

#[derive(Debug, Clone)]
pub(crate) struct QueueEntry {
    pub(crate) identity: QueueIdentity,
    pub(crate) current_addr: Option<SocketAddr>,
    /// Last IP this entry was seen connecting from. Unlike
    /// `current_addr` (cleared to `None` only when the bound socket
    /// disconnects) this survives disconnects, so the per-IP queue cap
    /// (eMule `cSameIP`) still counts lingering waiting-list entries
    /// from a churning peer.
    pub(crate) last_ip: Option<std::net::IpAddr>,
    pub(crate) udp_port: u16,
    /// Peer's advertised TCP listen port from Hello — required to dial
    /// HighID push-grants (`AddUpNextClient`).
    pub(crate) tcp_port: u16,
    /// Crypt options byte (supports/requests/requires) for obfuscated dial.
    pub(crate) crypt_options: u8,
    /// True when the peer's Hello client_id is HighID (dialable when
    /// disconnected). LowID disconnected peers use `add_next_connect` instead.
    pub(crate) is_high_id: bool,
    pub(crate) user_hash: [u8; 16],
    pub(crate) file_hash: [u8; 16],
    pub(crate) join_time: std::time::Instant,
    /// eMule m_bAddNextConnect: Low-ID client that scored highest while
    /// disconnected; gets priority slot on reconnect.
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

/// Classify a peer as HighID for upload-queue dialability (`AddUpNextClient`).
///
/// When Hello reports a real client_id, trust HighID/LowID from that alone —
/// LowIDs almost always advertise a listen `tcp_port` that is not reachable,
/// so a port-based OR would incorrectly mark them dialable. The port heuristic
/// is only used when `client_id == 0` (omitted / unknown).
fn peer_is_high_id_for_queue(hello_caps: &PeerCapabilities, peer_addr: SocketAddr) -> bool {
    if hello_caps.client_id != 0 {
        return hello_caps.is_high_id();
    }
    hello_caps.tcp_port > 0
        && match peer_addr.ip() {
            IpAddr::V4(v4) => !crate::security::is_special_use_v4(v4),
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(|v4| !crate::security::is_special_use_v4(v4))
                .unwrap_or(false),
        }
}

/// Build a queue entry snapshot from the current session Hello capabilities.
fn queue_entry_from_hello(
    identity: QueueIdentity,
    peer_addr: SocketAddr,
    peer_user_hash: [u8; 16],
    file_hash: [u8; 16],
    join_time: std::time::Instant,
    hello_caps: &PeerCapabilities,
    is_friend_slot: bool,
    ember_verified: bool,
) -> QueueEntry {
    let is_high_id = peer_is_high_id_for_queue(hello_caps, peer_addr);
    QueueEntry {
        identity,
        current_addr: Some(peer_addr),
        last_ip: Some(peer_addr.ip()),
        udp_port: hello_caps.udp_port,
        tcp_port: hello_caps.tcp_port,
        crypt_options: hello_caps.crypt_options_byte(),
        is_high_id,
        user_hash: peer_user_hash,
        file_hash,
        join_time,
        add_next_connect: false,
        emule_version: hello_caps.emule_version_min,
        is_friend_slot,
        ember_pubkey: hello_caps.ember_pubkey,
        ember_verified,
    }
}

#[derive(Debug)]
struct ResolvedUploadFile {
    name: String,
    path: PathBuf,
    opened: std::fs::File,
    allowed_roots: Vec<String>,
    size: u64,
    aich_hash_hex: String,
    is_partial: bool,
}

pub struct UploadEvent {
    pub transfer_id: String,
    pub kind: UploadEventKind,
}

/// Drop block ranges already delivered this session (exact start/end match).
///
/// eMule `CUpDownClient::AddReqBlock` refuses a request already on
/// `m_BlockRequests_queue` or `m_DoneBlocks_list`. aMule and other
/// non-eMule clients pad every `OP_REQUESTPARTS` with still-queued
/// in-flight blocks so the packet always names three ranges. Without
/// this filter we re-send those blocks and Transferred climbs to 2–3×
/// unique coverage while the parts bar barely moves.
fn filter_already_sent_ranges(
    offsets: Vec<(u64, u64)>,
    sent: &HashSet<(u64, u64)>,
) -> Vec<(u64, u64)> {
    if sent.is_empty() {
        return offsets;
    }
    offsets.into_iter().filter(|r| !sent.contains(r)).collect()
}

/// Whether this `OP_REQUESTPARTS` should reset `SLOT_IDLE_TIMEOUT`.
///
/// Bytes on the wire are always activity. Ranges we skipped because they
/// were already delivered this session (aMule padding in-flight blocks so
/// every packet names three ranges) also count: the peer is still in the
/// session. EOF / zero-length / unservable garbage must not (eMule Plus
/// 1.2.5 used to pin the slot forever by re-asking ranges we filter out).
///
/// Padding only counts while real bytes are still recent. A peer that pads a
/// full pipeline is by definition being served continuously, so
/// `since_last_credit` stays near zero; one that has stopped taking data and
/// only re-asks for ranges it already has looks identical to the pin-forever
/// case, and used to hold the slot until `SESSIONMAXTIME_SECS` — an hour, and
/// only then if anyone was queued behind it.
fn requestparts_resets_idle(
    credited_bytes: u64,
    skipped_already_sent: usize,
    since_last_credit: std::time::Duration,
) -> bool {
    credited_bytes > 0
        || (skipped_already_sent > 0 && since_last_credit < PADDING_KEEPALIVE_WINDOW)
}

/// Unique bytes delivered this session from the per-part served tally
/// (re-requests do not inflate past each part's size).
fn unique_served_bytes(served: &[u64], total_size: u64) -> u64 {
    if total_size == 0 || served.is_empty() {
        return 0;
    }
    let part_count = total_size.div_ceil(PARTSIZE).max(1) as usize;
    let mut sum = 0u64;
    for (i, &s) in served.iter().take(part_count).enumerate() {
        let part_size = if i + 1 < part_count {
            PARTSIZE
        } else {
            total_size.saturating_sub((part_count as u64 - 1) * PARTSIZE)
        };
        sum = sum.saturating_add(s.min(part_size));
    }
    sum
}

/// Progress tick for the upload row: session wire bytes (`uploaded`) plus
/// unique per-part coverage so the UI percentage tracks how much of the
/// file this peer has uniquely received, not re-requested wire bytes.
fn upload_progress_kind(
    uploaded: u64,
    total_size: u64,
    served: &[u64],
    peer_part_status: Option<String>,
) -> UploadEventKind {
    let (part_status, part_count) = build_up_part_status(served, total_size);
    UploadEventKind::Progress {
        uploaded,
        unique_uploaded: unique_served_bytes(served, total_size),
        total: total_size,
        part_status,
        part_count,
        peer_part_status,
    }
}

/// Terminal upload kind for a session that moved at least one byte.
/// Statistics "Completed Uploads" only increments when unique coverage
/// reached the full file (not cumulative wire bytes, which re-requests inflate).
fn upload_session_completed(unique_uploaded: u64, total_size: u64) -> UploadEventKind {
    UploadEventKind::Completed {
        full_file: total_size > 0 && unique_uploaded >= total_size,
    }
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
        /// Seconds this peer spent in the upload queue before the slot was
        /// granted (eMule "Waited" column). Surfaced as `Transfer.wait_time`.
        wait_seconds: u64,
        /// Ember identity when this peer completed `OP_EMBER_HELLO`. Friends
        /// are keyed by this, not the eD2K `user_hash`.
        ember_hash: Option<String>,
    },
    /// Fills Ember identity on an upload row that started before
    /// `OP_EMBER_HELLO`. Classic Ember file sockets learn the hash in the
    /// dispatcher, after [`Started`] may already have been emitted.
    Identity {
        ember_hash: Option<String>,
        client_software: String,
        peer_name: String,
    },
    Progress {
        uploaded: u64,
        /// Unique per-part coverage this session (`unique_served_bytes`).
        /// Drives the row's progress % and `completed_size`; `uploaded` is
        /// cumulative wire bytes and can exceed `total`.
        unique_uploaded: u64,
        total: u64,
        /// eMule-style served-parts bitmap and total part count, driving
        /// the chunked "Up Status" bar. See
        /// [`crate::types::Transfer::up_part_status`].
        part_status: Option<String>,
        part_count: Option<u32>,
        /// Hex bitmap of parts the downloader advertised it already has at
        /// request time (eMule `m_abyUpPartStatus`), shading the parts bar
        /// dark. Shares [`part_count`]. See
        /// [`crate::types::Transfer::up_peer_part_status`].
        peer_part_status: Option<String>,
    },
    /// Session ended after sending data (or after a full-file serve).
    /// `full_file` is true only when this peer received the entire file from
    /// us in this session — that alone increments Statistics "Completed
    /// Uploads", matching hash-verified download completion. Partial
    /// sessions still dismiss the transfer row and credit byte totals.
    Completed {
        full_file: bool,
    },
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
        relay_attestations: Vec<crate::network::ember::RelayAttestation>,
        /// Ember identity of the peer that sent this exchange, when its HELLO
        /// bound one. See the matching field on `DownloadEvent::EmberSources`.
        from_ember_hash: Option<[u8; 16]>,
    },
    /// An Ember peer was detected (for peer discovery mesh bootstrap).
    ///
    /// `udp_port` is the peer's advertised eMule UDP port, or 0 when it never
    /// advertised one. Ember's Noise transport rides the UDP socket, so that —
    /// not `tcp_port` — is the address the DHT bridge can dial.
    EmberPeerDiscovered {
        ip: std::net::Ipv4Addr,
        tcp_port: u16,
        udp_port: u16,
    },
    /// Incoming friend request from an Ember peer. `verified` carries
    /// the same semantics as the download-side variant in
    /// `super::transfer::DownloadEvent::EmberFriendRequest`: true iff
    /// the peer advertised an Ed25519 pubkey that BLAKE3-binds to
    /// their advertised `ember_hash`, plus (on friend-connect paths)
    /// signature proof-of-possession.
    EmberFriendRequest {
        ember_hash: [u8; 16],
        pubkey: Option<[u8; 32]>,
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
        session_id: u64,
        reply_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        supports_ebr1: bool,
    },
    /// Incoming Ember browse response from a friend (outbound session).
    /// Each entry is `(ed2k_hash_hex, size, name, optional_aich_hash_hex, optional_ember_hex)`.
    EmberBrowseResponse {
        ember_hash: [u8; 16],
        session_id: u64,
        entries: Vec<(String, u64, String, Option<String>, Option<String>)>,
    },
    /// An on-demand browse dial established a new friend session. The network
    /// loop binds the opaque session ID to the queued request before sending
    /// the wire packet, so a reply from a retired session can never complete
    /// this request.
    EmberBrowseSessionReady {
        ember_hash: [u8; 16],
        request_id: String,
        session_id: u64,
        tx: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    /// The matching on-demand browse dial failed. Routed through the network
    /// loop to remove its placeholder request atomically with replying.
    EmberBrowseSessionFailed {
        ember_hash: [u8; 16],
        request_id: String,
        error: String,
        tx: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    /// A friend asked us to connect back so they can download `request.file_hash`
    /// from us (`OP_EMBER_XFER_REQ`). The friend-layer analogue of an inbound
    /// eD2K `OP_CALLBACKREQUESTED`, except the ask arrives over the
    /// already-authenticated friend session instead of via a server.
    EmberTransferRequest {
        ember_hash: [u8; 16],
        request: super::messages::EmberXferRequest,
        /// The friend session this arrived on, for the `OP_EMBER_XFER_ACK`.
        reply_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        /// The address the friend session is actually connected to. The
        /// connect-back dials *this* IP with the requested port, never an IP
        /// from the request payload — otherwise a friend could aim our dialer
        /// at an arbitrary third-party host.
        peer_addr: SocketAddr,
    },
    /// A friend answered our `OP_EMBER_XFER_REQ`. `nonce` is matched against
    /// the outstanding request before `status` is acted on.
    EmberTransferAck {
        ember_hash: [u8; 16],
        status: u8,
        nonce: [u8; 16],
    },
    /// A friend forwarded the relay attestations it knows about. Lets a pair
    /// with no swarm in common populate their brokers, which is otherwise
    /// impossible: attestations only ever arrive on EPX exchanges for files
    /// you are already trading, so an isolated pair starves.
    EmberRelayOffer {
        ember_hash: [u8; 16],
        attestations: Vec<crate::network::ember::RelayAttestation>,
    },
    /// A friend is offering to send us a file. Surfaced to the UI for an
    /// explicit accept — we never start a download because a peer asked us to.
    EmberFileOffer {
        ember_hash: [u8; 16],
        offer: super::messages::EmberFileOffer,
        /// The friend session this arrived on, for the offer ack.
        reply_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    },
    /// A friend answered a file offer we sent them.
    EmberFileOfferAck {
        ember_hash: [u8; 16],
        status: u8,
        file_hash: [u8; 16],
    },
    EmberFriendDisconnected {
        ember_hash: [u8; 16],
        session_id: u64,
    },
    /// A friend session was just established from the *outbound* dial side
    /// (`friend_connect::run_friend_session_over_transport`, the single
    /// choke point every `connect_friend_with_fallback` /
    /// `open_and_run_friend_session` caller funnels through). Inbound
    /// sessions and message/request activity already flip a friend online
    /// via `FriendSeen` / `EmberChatMessage` / `EmberBrowseResponse` /
    /// `EmberFriendRequest` — but a purely outbound session that hasn't
    /// exchanged any application traffic yet had no event that updated
    /// `state.online_friends`, only a UI-only `ember:friend-online` emit at
    /// each call site. That left the backend's own bookkeeping (which
    /// `GetOnlineFriends` and the auto-retry/dedup skip-checks read)
    /// silently stale for outbound-only sessions until *something* else
    /// happened to touch `online_friends` for that friend.
    EmberFriendConnected {
        ember_hash: [u8; 16],
        /// Peer's eD2K user hash from the session Hello (may be zero if
        /// unavailable). Used to bind Ember identity → download sources.
        peer_user_hash: [u8; 16],
        /// Dialable IPv4 for file-transfer reconnect (Hello listen port
        /// preferred over the ephemeral connection port).
        ip: std::net::Ipv4Addr,
        port: u16,
    },
    /// Fresh friend endpoint from rendezvous (before/without a full
    /// session). Used to relocate download sources when we already know
    /// the peer's eD2K user_hash from a prior HELLO binding.
    FriendEndpointDiscovered {
        ember_hash: [u8; 16],
        ip: std::net::Ipv4Addr,
        port: u16,
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
    /// The upload listener auto-banned an IP (eMule-style
    /// AddRequestCount: a peer re-requesting the same file far too
    /// frequently). Routed back to the network task so the ban lands in
    /// the canonical `state.banned_ips` set — which is enforced on the
    /// UDP and download paths and is the set every `*shared =
    /// state.banned_ips.clone()` resync rebuilds from. Writing only to
    /// the shared upload set (as this path used to) left the ban
    /// invisible to those paths and made it vulnerable to being clobbered
    /// by the next resync. The network task also persists it.
    PeerAutoBanned {
        ip: std::net::Ipv4Addr,
        reason: String,
        /// When set, the IP is also recorded against this peer's DB record
        /// so a later manual `unban_peer` clears it (ban/unban symmetry).
        /// `None` for anonymous abuse auto-bans (AddRequestCount etc.),
        /// whose 7-day TTL self-heals and which have no manual unban path.
        user_hash: Option<[u8; 16]>,
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
    /// Live nickname — Settings can change it without restarting the
    /// upload listener. Read on every Hello / EmuleInfo build.
    nickname: Arc<tokio::sync::RwLock<String>>,
    /// Live-toggleable obfuscation preference. The Settings page can
    /// flip this at runtime; we read it on every Hello / EmuleInfo
    /// build so inbound and outbound advertise the same value as the
    /// rest of the network stack — without this the listener would be
    /// stuck on whatever value was active at process start.
    obfuscation_enabled: Arc<std::sync::atomic::AtomicBool>,
    /// Local bind port (process-lifetime).
    tcp_port: u16,
    /// Port advertised in Hello / shared-files answers. May differ from
    /// `tcp_port` when STUN discovers a remapped public TCP port.
    advertise_tcp_port: Arc<std::sync::atomic::AtomicU16>,
    udp_port: u16,
    advertise_udp_port: Arc<std::sync::atomic::AtomicU16>,
    active_count: Arc<std::sync::atomic::AtomicUsize>,
    max_concurrent_uploads: Arc<std::sync::atomic::AtomicUsize>,
    upload_event_tx: tokio::sync::mpsc::Sender<UploadEvent>,
    upload_queue: Arc<tokio::sync::Mutex<Vec<QueueEntry>>>,
    ip_connection_counts:
        Arc<parking_lot::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>>,
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
    /// known.met friends-only hashes (see [`SharedFriendsOnlyHashes`]).
    friends_only_hashes: SharedFriendsOnlyHashes,
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
    /// Answer vanilla `OP_ASKSHAREDFILES` ("View Files") requests from any
    /// ed2k-compatible peer with our real shared-file list. Live-toggleable
    /// from the Settings page; read on every inbound request rather than
    /// snapshotted at session start, so a mid-session toggle takes effect
    /// immediately. Off by default — see `AppSettings::allow_shared_files_browse`.
    share_browsing_enabled: Arc<std::sync::atomic::AtomicBool>,
    /// IPs we probed with FirewalledReq -- connect-back proves TCP is open
    firewall_probe_ips: FirewallProbeSet,
    /// Shared atomic: set to false when TCP is proven open
    firewalled_shared: Arc<std::sync::atomic::AtomicBool>,
    /// Set true on a KAD firewall-probe connect-back so the network loop can
    /// promote `tcp_status` without treating UPnP clears as proof.
    tcp_connect_back_shared: Arc<std::sync::atomic::AtomicBool>,
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
    /// In-memory MD4 part-hash cache for `OP_HASHSETREQ`: file_hash_hex ->
    /// (part hashes, last_access). See [`PartHashCache`].
    part_hash_cache: Arc<tokio::sync::Mutex<PartHashCache>>,
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
    /// Subset of `friend_hashes` that added us back. Gates access to private
    /// content: friend browse answers and serving friends-only files. A
    /// one-sided add still earns slot priority but never reaches these.
    mutual_friend_hashes: Arc<RwLock<std::collections::HashSet<[u8; 16]>>>,
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
    /// Identities currently being dialed for HighID AddUpNextClient push-grants.
    push_grant_in_flight: Arc<tokio::sync::Mutex<std::collections::HashSet<QueueIdentity>>>,
    /// Per-identity backoff after a failed HighID push dial.
    push_grant_backoff: Arc<tokio::sync::Mutex<HashMap<QueueIdentity, std::time::Instant>>>,
    /// Count of concurrent outbound HighID push-grant dials.
    push_grant_dials: Arc<std::sync::atomic::AtomicUsize>,
    /// Per-slot smoothed upload rates for dynamic slot decisions.
    slot_rates: SlotRateRegistry,
    /// Active Ember friend sessions: ember_hash -> outbound packet sender
    ember_sessions: EmberSessionMap,
    /// Set to true when the network is disconnected; upload handlers check
    /// this to reject new file requests and terminate active sessions (eMule
    /// behavior: all upload activity stops on disconnect).
    network_disconnected: Arc<std::sync::atomic::AtomicBool>,
    /// Lock-free counter the per-connection upload tasks bump on every
    /// inbound `OP_REQUESTSOURCES` and outbound `OP_ANSWERSOURCES`
    /// packet. Ember `OP_EMBER_SOURCEEXCHANGE` is counted on
    /// `epx_overhead`. Drained on the network loop's stats tick into
    /// `OverheadCategory::SourceExchange`.
    sx_overhead: crate::storage::statistics::SharedSxOverheadCounters,
    /// Ember Peer Exchange (`OP_EMBER_SOURCEEXCHANGE`) wire bytes.
    epx_overhead: crate::storage::statistics::SharedSxOverheadCounters,
}

const MAX_AICH_CACHE_ENTRIES: usize = 50;
const MAX_PART_HASH_CACHE_ENTRIES: usize = 50;

/// MD4 part hashes for complete shared files, keyed by ed2k hash hex.
///
/// `OP_HASHSETREQ` / `OP_HASHSETREQUEST2` answer a ~22-byte request by reading
/// the whole file. Uncached, that meant every new downloader of a share cost a
/// full re-read — a popular 20 GB file re-hashed per downloader — and a peer
/// looping the request could pin a CPU core and the disk for as long as it
/// liked, because the handler needs no upload slot, no queue position and no
/// identity, and the abuse tracker only counts connections rather than
/// packets. The AICH computation one opcode away was already memoized exactly
/// like this.
struct PartHashCache {
    entries: HashMap<String, (Vec<[u8; 16]>, std::time::Instant)>,
}

impl PartHashCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn get(&mut self, key: &str) -> Option<Vec<[u8; 16]>> {
        let entry = self.entries.get_mut(key)?;
        entry.1 = std::time::Instant::now();
        Some(entry.0.clone())
    }

    fn insert(&mut self, key: String, value: Vec<[u8; 16]>) {
        if self.entries.len() >= MAX_PART_HASH_CACHE_ENTRIES {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(key, (value, std::time::Instant::now()));
    }
}

struct AichCache {
    entries: HashMap<
        String,
        (
            crate::network::ed2k::aich::AICHRecoveryHashSet,
            std::time::Instant,
        ),
    >,
}

impl AichCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
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
            if let Some(oldest_key) = self
                .entries
                .iter()
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
    /// Independent window for hash-probe (file-not-found) counting so
    /// occasional missing-file asks over hours do not accumulate forever
    /// while `record_request` keeps `window_start` fresh.
    fnf_window_start: std::time::Instant,
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

    /// Evict expired / lapsed entries at most once per 10 min. Shared by every
    /// entry-inserting path so the map stays bounded regardless of which one
    /// dominates — a firewalled LowID node that only ever dials out via
    /// callback-serve exercises `record_file_not_found` (a served peer asking
    /// for a file we don't have) without the inbound `record_request` that
    /// used to own cleanup, so eviction has to run from both.
    fn maybe_cleanup(&mut self, now: std::time::Instant) {
        if now.duration_since(self.last_cleanup).as_secs() > 600 {
            self.entries.retain(|_, e| match e.banned_until {
                Some(u) if now >= u => false,
                Some(_) => true,
                None => now.duration_since(e.window_start).as_secs() < ABUSE_WINDOW_SECS * 2,
            });
            self.last_cleanup = now;
        }
    }

    /// Record a request from this IP. Returns true if the IP should be banned.
    fn record_request(&mut self, ip: std::net::IpAddr) -> bool {
        let ip = Self::normalize_ip(&ip);
        let now = std::time::Instant::now();
        self.maybe_cleanup(now);

        let entry = self.entries.entry(ip).or_insert_with(|| AbuseEntry {
            request_count: 0,
            window_start: now,
            file_not_found_count: 0,
            fnf_window_start: now,
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
            tracing::warn!(
                "Auto-banned {ip}: {} requests in {}s window",
                entry.request_count,
                ABUSE_WINDOW_SECS
            );
            return true;
        }

        false
    }

    /// Record a "file not found" response to this IP. Returns true if should ban.
    fn record_file_not_found(&mut self, ip: std::net::IpAddr) -> bool {
        let ip = Self::normalize_ip(&ip);
        let now = std::time::Instant::now();
        self.maybe_cleanup(now);
        let entry = self.entries.entry(ip).or_insert_with(|| AbuseEntry {
            request_count: 0,
            window_start: now,
            file_not_found_count: 0,
            fnf_window_start: now,
            banned_until: None,
        });

        if let Some(until) = entry.banned_until {
            return now < until;
        }

        // Window FNF the same way as request-rate so rare missing-file
        // asks over a long session cannot trip the probe ban.
        if now.duration_since(entry.fnf_window_start).as_secs() > ABUSE_WINDOW_SECS {
            entry.file_not_found_count = 0;
            entry.fnf_window_start = now;
        }

        entry.file_not_found_count += 1;

        if entry.file_not_found_count > MAX_FILE_NOT_FOUND {
            entry.banned_until = Some(now + std::time::Duration::from_secs(BAN_DURATION_SECS));
            tracing::warn!(
                "Auto-banned {ip}: {} file-not-found requests (hash probing)",
                entry.file_not_found_count
            );
            return true;
        }

        false
    }
}

/// eMule file priority to score multiplier, matching GetFilePrioAsNumber()/10.
pub(crate) fn priority_weight(priority: &str) -> f64 {
    match priority {
        "release" => 1.8, // maps to eMule VeryHigh (18/10)
        "high" => 0.9,    // maps to eMule High (9/10)
        "normal" => 0.7,  // maps to eMule Normal (7/10)
        "low" => 0.6,     // maps to eMule Low (6/10)
        "verylow" => 0.2, // maps to eMule VeryLow (2/10)
        _ => 0.7,
    }
}

/// eMule `CUpDownClient::GetFilePrioAsNumber` integer (used by soft-zone admission).
pub(crate) fn file_prio_as_number(priority: &str) -> i32 {
    match priority {
        "release" => 18,
        "high" => 9,
        "normal" => 7,
        "low" => 6,
        "verylow" => 2,
        _ => 7,
    }
}

/// Normalize a socket address to the IPv4 u32 used by credit scoring.
fn peer_ip_u32(current_addr: Option<SocketAddr>) -> u32 {
    current_addr
        .map(|a| match a.ip() {
            IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(|v4| u32::from_be_bytes(v4.octets()))
                .unwrap_or(0),
        })
        .unwrap_or(0)
}

/// eMule `GetCombinedFilePrioAndCredit` — wait-independent soft-zone ranking:
/// `10 * credit_ratio * GetFilePrioAsNumber()`. Friends with a verified friend
/// slot bypass soft-zone checks entirely (caller responsibility).
pub(crate) fn combined_file_prio_and_credit(
    cm: &CreditManager,
    idx: &LocalIndex,
    user_hash: &[u8; 16],
    file_hash: [u8; 16],
    peer_ip: u32,
    ember_pubkey: Option<&[u8; 32]>,
    ember_verified: bool,
) -> f64 {
    let prio_num = idx
        .get_by_hash(&hex::encode(file_hash))
        .map(|f| file_prio_as_number(&f.priority))
        .unwrap_or(7) as f64;
    // BadGuy short-circuit via eMule path (same as score_queue_entry).
    if matches!(
        cm.get_current_ident_state(user_hash, peer_ip),
        crate::network::ed2k::credits::IdentState::BadGuy
    ) {
        return 0.0;
    }
    let ratio = if ember_verified && ember_pubkey.is_some() {
        cm.get_ember_score_ratio(ember_pubkey.expect("guarded"))
    } else {
        cm.get_score_ratio(user_hash, peer_ip)
    };
    10.0 * ratio * prio_num
}

/// Soft-zone admit decision matching eMule `AddClientToQueue` soft→hard gate.
pub(crate) fn soft_zone_should_admit(
    is_verified_friend: bool,
    new_combined: f64,
    avg_combined: f64,
) -> bool {
    is_verified_friend || new_combined >= avg_combined
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
    let peer_ip = peer_ip_u32(current_addr);

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
    let has_download_bonus = cm.has_download_bonus(user_hash, peer_ip)
        || (use_ember && cm.has_ember_download_bonus(ember_pubkey.expect("guarded by use_ember")));
    if has_download_bonus {
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
            rank = rank.saturating_add(1);
        }
    }
    rank
}

/// eMule MAX_PURGEQUEUETIME: 1 hour in seconds
pub(crate) const MAX_PURGEQUEUETIME_SECS: u64 = 3600;

/// Pure decision core of `UploadHandler::purge_unshared_queue_entries`, split
/// out so the eviction rule can be unit-tested without constructing a full
/// `UploadHandler` (which needs channels, sockets, a GeoIP reader, etc.).
///
/// Returns the set of queued file hashes to evict: those that are NOT the
/// all-zero placeholder (peer queued before naming a file), NOT still present
/// in the shared index, and NOT still backed by a download (so partial-file
/// seeding of a file we're actively downloading is never purged).
fn unshared_purge_hashes<'a>(
    queued_hashes: impl IntoIterator<Item = &'a [u8; 16]>,
    is_shared: impl Fn(&[u8; 16]) -> bool,
    is_downloading: impl Fn(&[u8; 16]) -> bool,
) -> std::collections::HashSet<[u8; 16]> {
    let mut out = std::collections::HashSet::new();
    for h in queued_hashes {
        if *h == [0u8; 16] || is_shared(h) || is_downloading(h) {
            continue;
        }
        out.insert(*h);
    }
    out
}

/// Encode the `OP_ASKSHAREDFILESANSWER` payload for a set of shared files:
/// `<count 4>(<HASH 16><ID 4><PORT 2><1 Tag_set>)[count]`. Pure function
/// (no I/O, no `&self`) so it's directly unit-testable; the async
/// `UploadHandler::build_shared_files_answer` just gathers `(hash_hex, name,
/// size, extension)` tuples from the live index and hands them here.
///
/// Entries whose hash doesn't decode to at least 16 bytes are skipped rather
/// than aborting the whole answer — a single corrupt index row shouldn't
/// hide the rest of the user's shares from a legitimate browse request.
fn encode_shared_files_answer(
    files: &[(String, String, u64, String)],
    client_id: u32,
    tcp_port: u16,
) -> Vec<u8> {
    // Independent of the caller's `MAX_BROWSE_ANSWER_FILES` entry-count cap
    // (which alone still allows a multi-MB payload for a large library),
    // also bound total encoded bytes: `write_packet_async` has no outbound
    // size limit of its own, and our own inbound frame reader
    // (`read_packet_with_first_byte`) rejects anything over 512 KiB
    // outright, so sending an answer this same client couldn't itself
    // receive back is never useful. A truncated-but-delivered answer is
    // strictly better than one that's fully built, sent, and then dropped
    // whole by the receiver's frame-size check.
    //
    // Sized to use the full headroom under that 512 KiB frame limit rather
    // than an arbitrarily low value, so large libraries browse as completely
    // as the single-packet eD2k `OP_ASKSHAREDFILESANSWER` format allows (it
    // has no pagination). 500 KiB of entries + the 4-byte count + framing
    // stays safely under 512 KiB (~12 KiB margin). This is the compatibility
    // ceiling: eMule sends the full list, but going past the receiver's frame
    // cap would lose the *entire* answer, not just the overflow.
    const MAX_ANSWER_BYTES: usize = 500 * 1024;

    let mut entries = Vec::with_capacity(files.len().saturating_mul(64).min(MAX_ANSWER_BYTES));
    let mut count: u32 = 0;
    for (hash_hex, name, size, extension) in files {
        if entries.len() >= MAX_ANSWER_BYTES {
            break;
        }
        let hash_bytes = match hex::decode(hash_hex) {
            Ok(b) if b.len() >= 16 => b,
            _ => continue,
        };
        entries.extend_from_slice(&hash_bytes[..16]);
        entries.extend_from_slice(&client_id.to_le_bytes());
        entries.extend_from_slice(&tcp_port.to_le_bytes());

        let mut tag_count: u32 = 0;
        let mut tags = Vec::new();
        write_ed2k_tag(&mut tags, 0x01, &Ed2kTagValue::String(name.clone())); // FT_FILENAME
        tag_count += 1;
        // Same OLD_MAX_EMULE_FILE_SIZE boundary as offer_files_chunk: files
        // above it also carry FT_FILESIZE_HI (0x3A) with the high 32 bits
        // so large-file sizes round-trip correctly.
        write_ed2k_tag(&mut tags, 0x02, &Ed2kTagValue::Uint32(*size as u32)); // FT_FILESIZE
        tag_count += 1;
        if *size > OLD_MAX_EMULE_FILE_SIZE {
            write_ed2k_tag(&mut tags, 0x3A, &Ed2kTagValue::Uint32((*size >> 32) as u32));
            tag_count += 1;
        }
        let file_type = crate::search::index::infer_file_type(extension);
        if !file_type.is_empty() {
            write_ed2k_tag(&mut tags, 0x03, &Ed2kTagValue::String(file_type)); // FT_FILETYPE
            tag_count += 1;
        }
        entries.extend_from_slice(&tag_count.to_le_bytes());
        entries.extend_from_slice(&tags);
        count += 1;
    }

    let mut payload = Vec::with_capacity(4 + entries.len());
    payload.extend_from_slice(&count.to_le_bytes());
    payload.extend_from_slice(&entries);
    payload
}

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
    from_udp_port: u16,
    file_hash: &[u8; 16],
) -> Option<u16> {
    // Snapshot the queue and release its lock BEFORE acquiring the credit /
    // index read locks, so `upload_queue` is never held across an `.await`
    // (and no two of these locks are ever held simultaneously — this sidesteps
    // both contention and any lock-ordering hazard). The reported rank is
    // advisory, so scoring a snapshot taken microseconds earlier is fine.
    let queue: Vec<QueueEntry> = {
        let guard = upload_queue.lock().await;
        guard.clone()
    };
    let cm = credit_manager.read().await;
    let idx = local_index.read().await;
    let mut best: Option<&QueueEntry> = None;
    for entry in queue.iter() {
        if entry.file_hash != *file_hash {
            continue;
        }
        if entry.udp_port != 0 && entry.udp_port != from_udp_port {
            continue;
        }
        let matches = matches!(&entry.identity, QueueIdentity::Ip(ip) if *ip == from_ip)
            || entry
                .current_addr
                .map(|a| a.ip() == from_ip)
                .unwrap_or(false)
            // Port-only fallback for entries with no known address yet.
            // Requires a real (non-zero) stored UDP port so multiple
            // queued peers that both still have `udp_port == 0` can't
            // spuriously match each other via `0 == 0`, and so this
            // branch never substitutes for the IP checks above by
            // coincidence when the port happens to still be unset.
            || (entry.current_addr.is_none()
                && entry.udp_port != 0
                && entry.udp_port == from_udp_port);
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

#[allow(clippy::too_many_arguments)]
pub async fn start_upload_server(
    tcp_port: u16,
    advertise_tcp_port: Arc<std::sync::atomic::AtomicU16>,
    user_hash: [u8; 16],
    nickname: Arc<tokio::sync::RwLock<String>>,
    udp_port: u16,
    advertise_udp_port: Arc<std::sync::atomic::AtomicU16>,
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
    active_port_tests: Arc<
        tokio::sync::Mutex<HashMap<std::net::IpAddr, tokio::sync::mpsc::Sender<()>>>,
    >,
    pending_buddy_hashes: PendingBuddySet,
    buddy_conn_tx: tokio::sync::mpsc::Sender<BuddyConnectionParts>,
    shared_buddy_info: SharedBuddyInfo,
    shared_ip_filter: SharedIpFilter,
    banned_ips: SharedBannedIps,
    banned_hashes: SharedBannedHashes,
    friends_only_hashes: SharedFriendsOnlyHashes,
    antileech: crate::security::antileech::SharedAntiLeechFilter,
    skip_compress_video: Arc<std::sync::atomic::AtomicBool>,
    filter_incoming_connections: Arc<std::sync::atomic::AtomicBool>,
    share_browsing_enabled: Arc<std::sync::atomic::AtomicBool>,
    firewall_probe_ips: FirewallProbeSet,
    firewalled_shared: Arc<std::sync::atomic::AtomicBool>,
    // Set true when a firewall-probe IP connects back; network loop consumes it.
    tcp_connect_back_shared: Arc<std::sync::atomic::AtomicBool>,
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
    // Subset of `friend_hashes` that added us back. Required for anything
    // that exposes private content: friend browse answers and serving a
    // friends-only file.
    mutual_friend_hashes: Arc<RwLock<std::collections::HashSet<[u8; 16]>>>,
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
    // and outbound ANSWERSOURCES bytes; the network-loop drains them
    // into the SourceExchange overhead row. Ember EPX uses `epx_overhead`.
    sx_overhead: crate::storage::statistics::SharedSxOverheadCounters,
    epx_overhead: crate::storage::statistics::SharedSxOverheadCounters,
    // Callback-serve requests from the network task (server `OP_CALLBACKREQUESTED`
    // and KAD buddy `OP_CALLBACK`): each asks us to dial a peer and serve it so a
    // firewalled LowID node can still upload. Drained in the accept `select!`.
    mut connect_serve_rx: tokio::sync::mpsc::Receiver<ConnectServeRequest>,
    // Pre-established, transport-encrypted streams from the network task: a
    // punch-responder's outbound QUIC dial to an initiator, or a relay-invite
    // websocket adopted for a download-broker `StartRelay` session. Both
    // arrive with no matching download (we're the source/upload side), so
    // they're served here rather than through `kad_callback_tx`. Drained in
    // the same accept `select!`.
    mut inbound_stream_rx: tokio::sync::mpsc::Receiver<InboundStreamRequest>,
) -> anyhow::Result<()> {
    let addr: SocketAddr = format!("0.0.0.0:{tcp_port}").parse()?;
    // SO_REUSEADDR so the NATMAP-style TCP mapping hold can bind the same
    // local port for outbound keep-alive connects without conflicting.
    let listener = {
        let sock = tokio::net::TcpSocket::new_v4()
            .map_err(|e| anyhow::anyhow!("TCP socket create failed: {e}"))?;
        sock.set_reuseaddr(true)
            .map_err(|e| anyhow::anyhow!("TCP SO_REUSEADDR failed: {e}"))?;
        sock.bind(addr)
            .map_err(|e| anyhow::anyhow!("TCP bind {tcp_port} failed: {e}"))?;
        match sock.listen(1024) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(
                    "TCP port {tcp_port} is already in use: {e}. Peer-to-peer uploads will not work."
                );
                anyhow::bail!("TCP port {tcp_port} is already in use: {e}");
            }
        }
    };
    let current_max = max_concurrent_uploads.load(std::sync::atomic::Ordering::Relaxed);
    info!(
        "Peer-to-peer upload listener started on TCP port {tcp_port} (max {current_max} uploads)"
    );

    let active_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let slot_notify = Arc::new(tokio::sync::Notify::new());
    let slot_rates: SlotRateRegistry = Arc::new(parking_lot::Mutex::new(HashMap::new()));

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
        advertise_tcp_port,
        udp_port,
        advertise_udp_port,
        active_count,
        max_concurrent_uploads,
        upload_event_tx,
        upload_queue,
        ip_connection_counts: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
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
        friends_only_hashes,
        antileech,
        skip_compress_video,
        filter_incoming_connections,
        share_browsing_enabled,
        firewall_probe_ips,
        firewalled_shared,
        tcp_connect_back_shared,
        external_ip_shared,
        pending_kad_callbacks,
        kad_callback_tx,
        udp_fw_check_tx,
        abuse_tracker: Arc::new(tokio::sync::Mutex::new(AbuseTracker::new())),
        aich_cache: Arc::new(tokio::sync::Mutex::new(AichCache::new())),
        part_hash_cache: Arc::new(tokio::sync::Mutex::new(PartHashCache::new())),
        ember_hash,
        ed25519_public_key,
        ed25519_secret_key,
        friend_hashes,
        mutual_friend_hashes,
        ember_payload,
        ember_payload_generation,
        geoip,
        file_request_tracker: Arc::new(tokio::sync::Mutex::new(FileRequestTracker::new())),
        slot_notify,
        push_grant_in_flight: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
        push_grant_backoff: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        push_grant_dials: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        slot_rates,
        ember_sessions,
        network_disconnected,
        sx_overhead,
        epx_overhead,
    });

    let mut slot_check_interval = tokio::time::interval(std::time::Duration::from_secs(1));
    slot_check_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Counts 1 s slot-check ticks so the heavier "file no longer offered" queue
    // purge runs on a coarser (~30 s) cadence than the proactive slot opener.
    let mut slot_check_ticks: u64 = 0;
    // Latches when the callback-serve sender is dropped so we stop polling that
    // `select!` branch (a closed channel's `recv()` returns `None` immediately
    // and would otherwise busy-spin the loop).
    let mut connect_serve_closed = false;
    // Same latch pattern for the punch/relay inbound-stream channel below.
    let mut inbound_stream_closed = false;

    loop {
        tokio::select! {
            // Fair (unbiased) polling across the three arms. A `biased;` order
            // here polled `accept()` first every iteration, so under sustained
            // inbound-connection pressure the slot-maintenance tick and the
            // LowID callback-serve arm could starve indefinitely — the tick
            // drives queue upkeep and the callback-serve arm is a firewalled
            // node's ONLY upload route. Random-order polling lets every ready
            // arm make progress; the OS backlog still buffers pending accepts.
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

                        // Always reject truly-unroutable bogus IPs (loopback,
                        // multicast, documentation, class-E, …) even when
                        // "filter incoming" is off. That toggle only skips
                        // `ipfilter.dat` ranges and optional private/LAN
                        // blocking — VPN hosting ranges are never classified
                        // as bogus, so this does not reopen the VPN breakage
                        // that motivated the default-off policy.
                        if crate::security::is_bogus_v4(peer_ipv4) {
                            debug!("Rejecting incoming TCP from bogus IP {peer_addr}");
                            drop(stream);
                            continue;
                        }

                        // eD2K server HighID port-test: the connected/pending
                        // server dials our TCP port during login. Identified
                        // before the IP filter so a fail-closed empty-range
                        // window at startup cannot reject Sunrise and force
                        // LowID. Match by peer IP against `shared_server_addr`
                        // (preset at connect).
                        let is_server_port_test_ip = {
                            let server_addr = server.shared_server_addr.read().await;
                            server_addr
                                .map(|a| a.ip() == peer_addr.ip())
                                .unwrap_or(false)
                        };

                        if server.filter_incoming_connections.load(std::sync::atomic::Ordering::Relaxed) {
                            // Fail closed on poisoned lock: if we can't read
                            // the filter snapshot we refuse the connection
                            // rather than silently letting potentially-blocked
                            // peers through.
                            let (blocked, ranges_ready) = match server.shared_ip_filter.read() {
                                Ok(snap) => (snap.is_blocked(peer_ipv4), snap.ranges_ready),
                                Err(_poisoned) => {
                                    tracing::warn!(
                                        "IP filter lock poisoned while checking {peer_addr}; rejecting connection"
                                    );
                                    (true, true)
                                }
                            };
                            // While ranges are still loading, fail-closed
                            // blocks every public IP — including the eD2K
                            // server's HighID port-test. Exempt that peer.
                            if blocked && !(is_server_port_test_ip && !ranges_ready) {
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
                                server.tcp_connect_back_shared.store(true, std::sync::atomic::Ordering::Relaxed);
                                server.firewalled_shared.store(false, std::sync::atomic::Ordering::Relaxed);
                                crate::network::kad::firewall::note_local_tcp_firewalled(false);
                                drop(stream);
                                continue;
                            }
                        }

                        // eMule: reject new upload connections while network is disconnected.
                        // Firewall probes and the eD2K server's HighID port-test still pass.
                        if server.network_disconnected.load(std::sync::atomic::Ordering::Relaxed)
                            && !is_server_port_test_ip
                        {
                            debug!("Rejecting connection from {peer_addr}: network disconnected");
                            drop(stream);
                            continue;
                        }

                        // Enforce global connection limit. Reserve the slot with
                        // an atomic compare-exchange rather than a separate
                        // load-check-then-`fetch_add`: under a burst of
                        // simultaneous accepts the old check-then-act let
                        // multiple handlers each observe `< MAX` and increment
                        // past MAX_TOTAL_CONNECTIONS.
                        let reserved = {
                            let connection_limit = if is_server_port_test_ip {
                                MAX_TOTAL_CONNECTIONS + RESERVED_PORT_TEST_CONNECTIONS
                            } else {
                                MAX_TOTAL_CONNECTIONS
                            };
                            let mut cur = server
                                .total_connections
                                .load(std::sync::atomic::Ordering::Relaxed);
                            loop {
                                if cur >= connection_limit {
                                    break false;
                                }
                                match server.total_connections.compare_exchange_weak(
                                    cur,
                                    cur + 1,
                                    std::sync::atomic::Ordering::Relaxed,
                                    std::sync::atomic::Ordering::Relaxed,
                                ) {
                                    Ok(_) => break true,
                                    Err(actual) => cur = actual,
                                }
                            }
                        };
                        if !reserved {
                            debug!("Rejecting connection from {peer_addr}: global connection limit reached");
                            drop(stream);
                            continue;
                        }

                        // Enforce per-IP connection limit. If we reject here,
                        // release the global slot reserved just above so the
                        // reservation isn't leaked.
                        {
                            let mut counts = server.ip_connection_counts.lock();
                            let count = counts.entry(peer_addr.ip()).or_insert(0);
                            let per_ip_limit = if is_server_port_test_ip {
                                MAX_CONNECTIONS_PER_IP + RESERVED_PORT_TEST_CONNECTIONS
                            } else {
                                MAX_CONNECTIONS_PER_IP
                            };
                            if *count >= per_ip_limit {
                                debug!("Rejecting connection from {peer_addr}: per-IP limit reached");
                                drop(counts);
                                server
                                    .total_connections
                                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                                drop(stream);
                                continue;
                            }
                            *count += 1;
                        }
                        let admission_guard = ConnectionAdmissionGuard::new(
                            server.total_connections.clone(),
                            server.ip_connection_counts.clone(),
                            peer_addr.ip(),
                        );
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
                            let _admission_guard = admission_guard;
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
                    let has_dialable_highid = queue.iter().any(|e| {
                        e.current_addr.is_none()
                            && e.is_high_id
                            && e.tcp_port > 0
                            && e.last_ip.is_some()
                    });
                    drop(queue);
                    if has_waiters {
                        debug!(
                            "Proactive slot opener: {active}/{dynamic_slots} active, signalling queued clients"
                        );
                        server.slot_notify.notify_waiters();
                    }
                    // eMule AddUpNextClient: dial disconnected HighID winners.
                    if has_dialable_highid {
                        let server = server.clone();
                        tokio::spawn(async move {
                            server.try_add_up_next_client().await;
                        });
                    }
                }

                // eMule Process()-loop maintenance: evict waiting peers whose
                // requested file we no longer share or download. Throttled to
                // ~30 s so the index / transfer-manager scan stays off the
                // per-connection admission path (which only does the cheap
                // age-based purge).
                slot_check_ticks = slot_check_ticks.wrapping_add(1);
                if slot_check_ticks.is_multiple_of(30) {
                    server.purge_unshared_queue_entries().await;
                }
            }
            // LowID callback-serve: the network task asks us to dial a peer and
            // serve it (server `OP_CALLBACKREQUESTED` / KAD buddy `OP_CALLBACK`).
            // Polled fairly with the accept/tick arms (no `biased;` above).
            maybe_req = connect_serve_rx.recv(), if !connect_serve_closed => {
                let req = match maybe_req {
                    Some(r) => r,
                    None => {
                        // Sender dropped (shutdown): stop polling this branch so
                        // the select! doesn't busy-spin on an always-ready None.
                        connect_serve_closed = true;
                        continue;
                    }
                };
                let peer_ip = req.peer_addr.ip();

                // Reserve a global slot with the same cap + atomic CAS the
                // inbound accept path uses, so outbound callback serves can't
                // push the process past MAX_TOTAL_CONNECTIONS.
                let reserved = {
                    let mut cur = server
                        .total_connections
                        .load(std::sync::atomic::Ordering::Relaxed);
                    loop {
                        if cur >= MAX_TOTAL_CONNECTIONS {
                            break false;
                        }
                        match server.total_connections.compare_exchange_weak(
                            cur,
                            cur + 1,
                            std::sync::atomic::Ordering::Relaxed,
                            std::sync::atomic::Ordering::Relaxed,
                        ) {
                            Ok(_) => break true,
                            Err(actual) => cur = actual,
                        }
                    }
                };
                if !reserved {
                    debug!(
                        "Dropping callback-serve to {}: global connection limit reached",
                        req.peer_addr
                    );
                    continue;
                }
                {
                    let mut counts = server.ip_connection_counts.lock();
                    let count = counts.entry(peer_ip).or_insert(0);
                    if *count >= MAX_CONNECTIONS_PER_IP {
                        debug!(
                            "Dropping callback-serve to {}: per-IP limit reached",
                            req.peer_addr
                        );
                        drop(counts);
                        server
                            .total_connections
                            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        continue;
                    }
                    *count += 1;
                }
                let admission_guard = ConnectionAdmissionGuard::new(
                    server.total_connections.clone(),
                    server.ip_connection_counts.clone(),
                    peer_ip,
                );

                let server = server.clone();
                tokio::spawn(async move {
                    let _admission_guard = admission_guard;
                    let result = std::panic::AssertUnwindSafe(server.connect_and_serve(req))
                        .catch_unwind()
                        .await;
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            let msg = e.to_string();
                            if msg.contains("end of file")
                                || msg.contains("Connection reset")
                                || msg.contains("connection reset")
                                || msg.contains("broken pipe")
                                || msg.contains("timed out")
                                || msg.contains("timeout")
                                || msg.contains("tcp connect")
                            {
                                debug!("Callback-serve to {peer_ip} ended: {msg}");
                            } else {
                                warn!("Callback-serve to {peer_ip} ended: {e}");
                            }
                        }
                        Err(_panic) => {
                            error!("Callback-serve handler panicked for {peer_ip}");
                        }
                    }
                });
            }
            // Punch/relay-adopted streams: the network task already completed
            // a QUIC hole-punch or relay-invite websocket connect on our
            // behalf. Same admission checks as a plain inbound accept —
            // including IP filter / ban when `peer_addr` is a real IPv4
            // (not an unspecified relay placeholder). Bogus addresses are
            // always rejected; `ipfilter.dat` / private blocks honor the
            // live `filter_incoming_connections` toggle like TCP accept.
            maybe_stream = inbound_stream_rx.recv(), if !inbound_stream_closed => {
                let req = match maybe_stream {
                    Some(r) => r,
                    None => {
                        inbound_stream_closed = true;
                        continue;
                    }
                };
                let peer_addr = req.peer_addr;
                let peer_ip = peer_addr.ip();

                // Same gate as inbound TCP accept: reject new upload sessions
                // while the network is disconnected (eMule behavior).
                if server.network_disconnected.load(std::sync::atomic::Ordering::Relaxed) {
                    debug!(
                        "Rejecting punch/relay-adopted stream from {peer_addr}: network disconnected"
                    );
                    continue;
                }

                if let std::net::IpAddr::V4(peer_ipv4) = peer_ip {
                    // Unspecified (0.0.0.0) is the relay-placeholder case —
                    // skip filter/ban because the true peer IP is hidden.
                    if !peer_ipv4.is_unspecified() {
                        if crate::security::is_bogus_v4(peer_ipv4) {
                            debug!(
                                "Rejecting punch/relay-adopted stream from bogus IP {peer_addr}"
                            );
                            continue;
                        }
                        if server
                            .filter_incoming_connections
                            .load(std::sync::atomic::Ordering::Relaxed)
                        {
                            let blocked = match server.shared_ip_filter.read() {
                                Ok(snap) => snap.is_blocked(peer_ipv4),
                                Err(_poisoned) => {
                                    tracing::warn!(
                                        "IP filter lock poisoned while checking punch/relay {peer_addr}; rejecting"
                                    );
                                    true
                                }
                            };
                            if blocked {
                                info!(
                                    "IP filter blocked punch/relay-adopted stream from {peer_addr}"
                                );
                                continue;
                            }
                        }
                        let banned_check = match server.banned_ips.read() {
                            Ok(banned) => banned.contains(&peer_ipv4),
                            Err(_poisoned) => {
                                tracing::warn!(
                                    "Banned-IP lock poisoned while checking punch/relay {peer_addr}; rejecting"
                                );
                                true
                            }
                        };
                        if banned_check {
                            debug!(
                                "Rejecting punch/relay-adopted stream from banned IP {peer_addr}"
                            );
                            continue;
                        }
                        {
                            let tracker = server.abuse_tracker.lock().await;
                            if tracker.is_banned(&peer_ip) {
                                debug!(
                                    "Rejecting punch/relay-adopted stream from auto-banned IP {peer_addr}"
                                );
                                continue;
                            }
                        }
                    }
                }

                let reserved = {
                    let mut cur = server
                        .total_connections
                        .load(std::sync::atomic::Ordering::Relaxed);
                    loop {
                        if cur >= MAX_TOTAL_CONNECTIONS {
                            break false;
                        }
                        match server.total_connections.compare_exchange_weak(
                            cur,
                            cur + 1,
                            std::sync::atomic::Ordering::Relaxed,
                            std::sync::atomic::Ordering::Relaxed,
                        ) {
                            Ok(_) => break true,
                            Err(actual) => cur = actual,
                        }
                    }
                };
                if !reserved {
                    debug!(
                        "Dropping punch/relay-adopted stream from {peer_addr}: global connection limit reached"
                    );
                    continue;
                }
                {
                    let mut counts = server.ip_connection_counts.lock();
                    let count = counts.entry(peer_ip).or_insert(0);
                    if *count >= MAX_CONNECTIONS_PER_IP {
                        debug!(
                            "Dropping punch/relay-adopted stream from {peer_addr}: per-IP limit reached"
                        );
                        drop(counts);
                        server
                            .total_connections
                            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        continue;
                    }
                    *count += 1;
                }
                let admission_guard = ConnectionAdmissionGuard::new(
                    server.total_connections.clone(),
                    server.ip_connection_counts.clone(),
                    peer_ip,
                );

                let server = server.clone();
                tokio::spawn(async move {
                    let _admission_guard = admission_guard;
                    // A coordinated friend-transfer punch makes us the eD2K
                    // initiator; every other adopted stream keeps the inbound
                    // role. Deciding here, rather than inside `run_session`,
                    // keeps the two roles' handshake preambles separate.
                    let result = match req.serve_friend_ember_hash {
                        Some(friend) => std::panic::AssertUnwindSafe(
                            server.serve_punched_friend(
                                peer_addr,
                                req.reader,
                                req.writer,
                                friend,
                            ),
                        )
                        .catch_unwind()
                        .await,
                        None => std::panic::AssertUnwindSafe(
                            server.handle_inbound_stream(peer_addr, req.reader, req.writer),
                        )
                        .catch_unwind()
                        .await,
                    };
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            let msg = e.to_string();
                            if msg.contains("end of file") || msg.contains("Connection reset")
                                || msg.contains("connection reset") || msg.contains("broken pipe")
                            {
                                debug!("Punch/relay-adopted stream from {peer_addr}: {msg}");
                            } else {
                                warn!("Punch/relay-adopted stream from {peer_addr} ended: {e}");
                            }
                        }
                        Err(_panic) => {
                            error!("Punch/relay-adopted stream handler panicked for {peer_addr}");
                        }
                    }
                });
            }
        }
    }
}

impl UploadHandler {
    fn advertised_tcp_port(&self) -> u16 {
        let p = self
            .advertise_tcp_port
            .load(std::sync::atomic::Ordering::Relaxed);
        if p == 0 {
            self.tcp_port
        } else {
            p
        }
    }

    fn advertised_udp_port(&self) -> u16 {
        let p = self
            .advertise_udp_port
            .load(std::sync::atomic::Ordering::Relaxed);
        if p == 0 {
            self.udp_port
        } else {
            p
        }
    }

    async fn nickname_snapshot(&self) -> String {
        self.nickname.read().await.clone()
    }

    /// Keep the waiting-list entry's file hash in sync when a peer mid-slot
    /// switches files (`OP_SETREQFILEID` / `OP_REQUESTPARTS` / MultiPacket).
    /// Queue scoring and file-priority bonuses key off `QueueEntry::file_hash`.
    async fn sync_queue_file_hash(
        &self,
        identity: &QueueIdentity,
        file_hash: [u8; 16],
        peer_addr: SocketAddr,
        session_tcp_port: u16,
    ) {
        let mut queue = self.upload_queue.lock().await;
        if let Some(entry) = queue.iter_mut().find(|e| e.identity == *identity) {
            if queue_row_owned_by_session(
                entry.current_addr,
                entry.tcp_port,
                peer_addr,
                session_tcp_port,
            ) {
                entry.file_hash = file_hash;
            }
        }
    }

    /// True when the share index **or** the known.met snapshot marks this
    /// hash friends-only. Index covers live library rows; the snapshot covers
    /// flags that exist only in known.met (see [`SharedFriendsOnlyHashes`]).
    async fn hash_is_friends_only(&self, file_hash: &[u8; 16]) -> bool {
        let snapshot_hit = friends_only_snapshot_contains(&self.friends_only_hashes, file_hash);
        let snapshot_ready = friends_only_snapshot_ready(&self.friends_only_hashes);
        let index_friends_only = {
            let index = self.local_index.read().await;
            index
                .get_by_hash(&hex::encode(file_hash))
                .map(|f| f.friends_only)
        };
        friends_only_from_sources(snapshot_hit, snapshot_ready, index_friends_only)
    }

    /// True when `file_hash` is restricted to mutual friends and this peer is
    /// not one — so queueing them could only ever end in a refusal.
    ///
    /// [`Self::resolve_upload_file`] is still the authority on whether bytes
    /// go out; this exists purely so a peer who cannot be served does not sit
    /// in the waiting list occupying a slot another peer could use.
    async fn friends_only_and_barred(&self, file_hash: &[u8; 16], peer: PeerFileAccess) -> bool {
        if !self.hash_is_friends_only(file_hash).await {
            return false;
        }
        !mutual_friend_access(
            &self.mutual_friend_hashes,
            peer.ember_hash,
            peer.secure_v2_authenticated,
        )
        .await
    }

    /// Resolve a requested hash to a servable file.
    ///
    /// `peer` carries the requester's authenticated identity on *this*
    /// session and is the sole key to friends-only files. Callers that have
    /// no cryptographic identity for the peer — plain eMule sockets, the UDP
    /// reask path, server-driven serves — pass [`PeerFileAccess::ANONYMOUS`]
    /// and can never reach restricted content.
    async fn resolve_upload_file(
        &self,
        file_hash: &[u8; 16],
        peer: PeerFileAccess,
    ) -> Option<ResolvedUploadFile> {
        let hash_hex = hex::encode(file_hash);
        if let Some(file) = {
            let index = self.local_index.read().await;
            index.get_by_hash(&hash_hex).cloned()
        } {
            'shared: {
                // Respect the user's "shared" toggle: unsharing a completed file
                // stops it from being offered/published (see
                // `build_shared_files_answer`'s `is_public_listable` filter),
                // but a peer that already learned the hash before the toggle (KAD
                // publish, source exchange, a friend's known-sources cache, …)
                // could otherwise still pull it straight from the index forever.
                // Break out (instead of returning) so an in-progress download of
                // the same hash can still fall through to the transfer-manager
                // branch below — `shared` only governs completed, indexed files.
                if !file.shared {
                    tracing::debug!("Rejecting resolve for unshared file: {}", hash_hex);
                    break 'shared;
                }
                // A friends-only file is served only to an authenticated mutual
                // friend. Unlike the `shared` check above this returns outright
                // instead of breaking: `shared` governs whether the library
                // offers a completed file, so falling through to an in-progress
                // download of the same hash is reasonable, but friends-only is a
                // restriction on the *content*. Breaking here handed the bytes
                // to the transfer-manager branch below, which has no membership
                // check, so any anonymous peer holding the hash could pull a
                // restricted file for as long as a download of it was live.
                //
                // The membership lookup is deliberately inside this branch so
                // the overwhelmingly common public-file path never pays for
                // the lock.
                if self.hash_is_friends_only(file_hash).await
                    && !mutual_friend_access(
                        &self.mutual_friend_hashes,
                        peer.ember_hash,
                        peer.secure_v2_authenticated,
                    )
                    .await
                {
                    tracing::debug!(
                        "Rejecting resolve for friends-only file from non-friend: {}",
                        hash_hex
                    );
                    return None;
                }
                let path = PathBuf::from(&file.path);
                let is_partial = path.extension().map(|e| e == "part").unwrap_or(false);
                // Always enforce containment, including for `.part` entries: the
                // served file must canonicalize to a location inside a shared
                // folder or a download root. Previously this check was skipped
                // when `shared_folders` was empty, which meant a stale index entry
                // could still be served after the user cleared all shares; it was
                // also skipped entirely for `.part` index entries, so a stale or
                // tampered index row pointing at an out-of-root partial could be
                // served. The indexer never indexes `*.part`, so a legitimate
                // partial inside a shared/download root still passes this check —
                // enforcing it for partials is pure hardening with no impact on
                // serving real in-root partials. Download partials served from the
                // transfer manager use the `Temp/{id}.part` path below.
                // Build the allowed-roots snapshot under the lock, then drop the
                // read guard *before* the blocking canonicalize below so the
                // `shared_folders` lock is never held across an `.await`.
                let allowed: Vec<String> = {
                    let folders = self.shared_folders.read().await;
                    let mut allowed: Vec<String> = folders.clone();
                    allowed.push(self.download_folder.to_string_lossy().to_string());
                    allowed.push(
                        self.download_folder
                            .join("Downloads")
                            .to_string_lossy()
                            .to_string(),
                    );
                    allowed
                };
                // `canonicalize` is a blocking filesystem syscall; run it (and the
                // pure containment check that consumes its result) on the blocking
                // pool so it never stalls a Tokio worker. Fail closed (reject) on a
                // join error.
                let path_for_check = path.clone();
                let allowed_for_open = allowed.clone();
                let (verified_path, opened) = tokio::task::spawn_blocking(move || {
                    crate::security::filesystem::open_existing_approved(
                        &path_for_check,
                        &allowed_for_open,
                        false,
                    )
                })
                .await
                .ok()
                .and_then(Result::ok)?;
                return Some(ResolvedUploadFile {
                    name: file.name,
                    path: verified_path,
                    opened,
                    allowed_roots: allowed,
                    size: file.size,
                    aich_hash_hex: file.aich_hash,
                    is_partial,
                });
            }
        }

        // Unshared index rows `break` into this `.part` branch, and hashes
        // that exist only in known.met never enter the index branch at all.
        // Either way, friends-only content must not leave for a stranger.
        if self.hash_is_friends_only(file_hash).await
            && !mutual_friend_access(
                &self.mutual_friend_hashes,
                peer.ember_hash,
                peer.secure_v2_authenticated,
            )
            .await
        {
            tracing::debug!(
                "Rejecting resolve for friends-only partial from non-friend: {}",
                hash_hex
            );
            return None;
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
                        .find(|t| {
                            t.direction == TransferDirection::Download && t.file_hash == hash_hex
                        })
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
        let allowed = vec![self.download_folder.to_string_lossy().into_owned()];
        let allowed_for_open = allowed.clone();
        let (verified_part, opened) = tokio::task::spawn_blocking(move || {
            crate::security::filesystem::open_existing_approved(
                &part_path,
                &allowed_for_open,
                false,
            )
        })
        .await
        .ok()
        .and_then(Result::ok)?;

        Some(ResolvedUploadFile {
            name: transfer.file_name,
            path: verified_part,
            opened,
            allowed_roots: allowed,
            size: transfer.total_size,
            aich_hash_hex: String::new(),
            is_partial: true,
        })
    }

    /// Whether this peer may learn our source list for `file_hash`.
    ///
    /// Public-listable shares and in-progress public downloads: yes.
    /// Friends-only hashes: only an authenticated mutual friend.
    /// Arbitrary hashes we happen to have in SourceManager: no.
    ///
    /// Does not use [`Self::resolve_upload_file`]: an unshared friends-only
    /// index row `break`s into the in-progress `.part` branch there, which
    /// would treat "we are downloading it" as a public SX yes. known.met-only
    /// flags are read from [`Self::friends_only_hashes`], not the index.
    async fn may_answer_source_exchange(
        &self,
        file_hash: &[u8; 16],
        peer: PeerFileAccess,
    ) -> bool {
        let hash_hex = hex::encode(file_hash);
        let public_share = {
            let index = self.local_index.read().await;
            index
                .get_by_hash(&hash_hex)
                .is_some_and(|f| f.is_public_listable())
        };
        if self.hash_is_friends_only(file_hash).await {
            return mutual_friend_access(
                &self.mutual_friend_hashes,
                peer.ember_hash,
                peer.secure_v2_authenticated,
            )
            .await;
        }
        if public_share {
            return true;
        }
        let mgr = self.transfer_manager.read().await;
        mgr.active
            .values()
            .chain(mgr.queue.iter())
            .any(|t| {
                t.direction == TransferDirection::Download
                    && t.file_hash == hash_hex
                    && !matches!(
                        t.status,
                        TransferStatus::Completed | TransferStatus::Failed
                    )
            })
    }

    /// Build the `OP_ASKSHAREDFILESANSWER` payload: `<count 4>(<HASH
    /// 16><ID 4><PORT 2><1 Tag_set>)[count]` — the same per-file shape
    /// eMule's `SharedFileList.cpp` uses for `OP_OFFERFILES` (see
    /// `server::offer_files_chunk`), reusing the shared `write_ed2k_tag`
    /// encoder rather than a third copy of the tag-writing logic.
    ///
    /// Only files the user actively shares (`FileInfo::shared`) are
    /// included — this mirrors what the Settings/Library UI calls "shared",
    /// not in-progress downloads. `client_id`/`self.tcp_port` are our real
    /// identity (not the server's magic compression IDs): this answer goes
    /// straight to the peer that already has our real address, so there's
    /// nothing to obscure.
    async fn build_shared_files_answer(&self, client_id: u32) -> Vec<u8> {
        // Real libraries rarely exceed a few hundred thousand files; this
        // bounds the worst case (huge or pathological index) so a single
        // browse request can't force us to build and hold an unbounded
        // buffer in memory before it's flushed to a peer's socket.
        const MAX_BROWSE_ANSWER_FILES: usize = 50_000;

        let files: Vec<(String, String, u64, String)> = {
            let index = self.local_index.read().await;
            index
                .all_files()
                .iter()
                .filter(|f| f.is_public_listable())
                .take(MAX_BROWSE_ANSWER_FILES)
                .map(|f| (f.hash.clone(), f.name.clone(), f.size, f.extension.clone()))
                .collect()
        };

        encode_shared_files_answer(&files, client_id, self.advertised_tcp_port())
    }

    /// Periodic eMule-style queue maintenance: evict waiting peers whose
    /// requested file we no longer offer.
    ///
    /// eMule's `FindBestClientInQueue` / `CheckForTimeOver` drop a queued client
    /// when `theApp.sharedfiles->GetFileByID(uploadfileid)` returns null (the
    /// file was un-shared or removed). We mirror that with a cheap, in-memory
    /// predicate — present in the shared index OR backed by a download (active
    /// or queued) in the transfer manager — deliberately avoiding the per-file
    /// `canonicalize`/`exists` work that `resolve_upload_file` does, so this can
    /// run on the slow maintenance timer instead of the hot admission path
    /// (which keeps doing only the cheap `MAX_PURGEQUEUETIME` age sweep). The
    /// test errs toward KEEPING an entry (membership only, no filesystem probe),
    /// so a file we're still sharing or downloading is never purged out from
    /// under a waiting peer; the serve path still does the authoritative
    /// resolution.
    ///
    /// Entries with the all-zero placeholder hash (peer queued before naming a
    /// file) are skipped — they have no file to compare against yet and are
    /// reaped by the age sweep instead.
    ///
    /// Lock discipline: holds at most ONE of `upload_queue`, `local_index`,
    /// `transfer_manager` at any moment (never nested), so it cannot deadlock
    /// against paths that take those locks in any order.
    async fn purge_unshared_queue_entries(&self) {
        // 1. Distinct, named file hashes currently in the queue.
        let hashes: Vec<[u8; 16]> = {
            let queue = self.upload_queue.lock().await;
            if queue.is_empty() {
                return;
            }
            let mut set: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
            for e in queue.iter() {
                if e.file_hash != [0u8; 16] {
                    set.insert(e.file_hash);
                }
            }
            set.into_iter().collect()
        };
        if hashes.is_empty() {
            return;
        }

        // 2. Snapshot membership under each lock SEPARATELY (never nested, per
        //    the lock discipline noted above): which queued hashes are still in
        //    the shared index, then which are still backed by a download.
        let shared: std::collections::HashSet<[u8; 16]> = {
            let index = self.local_index.read().await;
            hashes
                .iter()
                .copied()
                .filter(|h| index.get_by_hash(&hex::encode(h)).is_some())
                .collect()
        };
        // Short-circuit: if every queued file is still shared there is nothing
        // to purge, and we can skip taking the transfer-manager lock entirely.
        if shared.len() == hashes.len() {
            return;
        }
        let downloading: std::collections::HashSet<[u8; 16]> = {
            let mgr = self.transfer_manager.read().await;
            hashes
                .iter()
                .copied()
                .filter(|h| {
                    let hex_h = hex::encode(h);
                    mgr.active
                        .values()
                        .any(|t| t.direction == TransferDirection::Download && t.file_hash == hex_h)
                        || mgr.queue.iter().any(|t| {
                            t.direction == TransferDirection::Download && t.file_hash == hex_h
                        })
                })
                .collect()
        };

        let unserveable =
            unshared_purge_hashes(&hashes, |h| shared.contains(h), |h| downloading.contains(h));
        if unserveable.is_empty() {
            return;
        }

        // 3. Evict the orphaned waiters.
        let removed = {
            let mut queue = self.upload_queue.lock().await;
            let before = queue.len();
            queue.retain(|e| !unserveable.contains(&e.file_hash));
            before - queue.len()
        };
        if removed > 0 {
            debug!(
                "Upload queue: purged {removed} waiting peer(s) for {} file(s) no longer shared or downloading (eMule file-gone queue purge)",
                unserveable.len()
            );
        }
    }

    /// One "request" per file per incoming connection (eMule-style asked count).
    async fn record_share_request_once(&self, hash: &[u8; 16], recorded: &mut Option<[u8; 16]>) {
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
        let max_configured = self
            .max_concurrent_uploads
            .load(std::sync::atomic::Ordering::Relaxed);

        let observed_rate = self.bandwidth_limiter.smoothed_upload_speed();
        let effective_rate = if observed_rate > 0 || active > 0 {
            observed_rate
        } else {
            self.bandwidth_limiter.effective_upload_rate()
        };

        if effective_rate == 0 {
            return ADMISSION_FLOOR_SLOTS.min(max_configured);
        }

        let target_per_slot = if active <= 3 {
            3u64 * 1024
        } else {
            (3u64 * 1024 + (active as u64 - 3) * 1024).min(UPLOAD_CLIENT_MAXDATARATE)
        };

        let computed = (effective_rate / target_per_slot).max(ADMISSION_FLOOR_SLOTS as u64);
        let computed = (computed as usize)
            .min(MAX_UP_CLIENTS_ALLOWED)
            .min(max_configured);

        if active >= 2 {
            let rates = self.slot_rates.lock();
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
            udp_port: self.advertised_udp_port(),
            kad_port: self.advertised_udp_port(),
            supports_crypt_layer: self
                .obfuscation_enabled
                .load(std::sync::atomic::Ordering::Relaxed),
            requests_crypt_layer: self
                .obfuscation_enabled
                .load(std::sync::atomic::Ordering::Relaxed),
            requires_crypt_layer: false,
            supports_direct_udp_callback: crate::network::kad::firewall::advertised_direct_udp_callback(),
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

    /// Route an upload-listener auto-ban (abuse tracker: request
    /// flooding / hash probing) back to the network task so it lands in
    /// the canonical `state.banned_ips` set (UDP + download enforcement)
    /// and is persisted — mirroring the AddRequestCount path. ed2k is
    /// IPv4-only, so a pure-IPv6 peer (which can't be ban-set keyed) is
    /// dropped here; the abuse tracker's own per-connection enforcement
    /// still applies in that case.
    async fn emit_auto_ban(&self, ip: std::net::IpAddr, reason: &str) {
        let v4 = match ip {
            std::net::IpAddr::V4(v4) => Some(v4),
            std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
        };
        if let Some(v4) = v4 {
            let _ = self
                .upload_event_tx
                .send(UploadEvent {
                    transfer_id: String::new(),
                    kind: UploadEventKind::PeerAutoBanned {
                        ip: v4,
                        reason: reason.to_string(),
                        user_hash: None,
                    },
                })
                .await;
        }
    }

    /// Whether the peer in this session has been banned since it connected.
    ///
    /// The accept-loop ban check (banned IP) and the post-Hello check
    /// (`banned_hashes`) both run exactly once, so a peer that is banned
    /// *while actively downloading* would otherwise keep its in-progress
    /// upload until it completed or idled out. The session loop calls this
    /// each iteration, and the inner parts-send loop calls it per block, so a
    /// ban now tears the live transfer down promptly. Matches the accept
    /// loop's fail-closed policy: a poisoned lock is treated as "banned".
    fn peer_is_banned(&self, user_hash: &[u8; 16], peer_addr: &SocketAddr) -> bool {
        if *user_hash != [0u8; 16] {
            match self.banned_hashes.read() {
                Ok(set) => {
                    if set.contains(user_hash) {
                        return true;
                    }
                }
                Err(_poisoned) => return true,
            }
        }
        let ipv4 = match peer_addr.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
        };
        if let Some(ipv4) = ipv4 {
            match self.banned_ips.read() {
                Ok(set) => {
                    if set.contains(&ipv4) {
                        return true;
                    }
                }
                Err(_poisoned) => return true,
            }
        }
        false
    }

    async fn handle_connection(
        &self,
        stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        self.run_session(
            peer_addr,
            ConnInit::Inbound(stream),
            Some(
                tokio::time::Instant::now()
                    + std::time::Duration::from_secs(INBOUND_PREAUTH_DEADLINE_SECS),
            ),
        )
        .await
    }

    /// Serve an already-established, transport-encrypted stream handed to us
    /// by the network task — a punch-responder QUIC dial-out or a friend/
    /// download-broker relay-invite websocket that succeeded. Neither case
    /// has a `TcpStream` to hand to `ConnInit::Inbound` (QUIC and the relay
    /// websocket are already end-to-end encrypted at the transport layer,
    /// so there's also no eMule obfuscation negotiation to perform), so this
    /// skips straight to the Hello/EmuleInfo exchange inside `run_session`.
    async fn handle_inbound_stream(
        &self,
        peer_addr: SocketAddr,
        reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    ) -> anyhow::Result<()> {
        self.run_session(
            peer_addr,
            ConnInit::InboundStream {
                reader,
                writer,
                secure_peer: None,
            },
            Some(
                tokio::time::Instant::now()
                    + std::time::Duration::from_secs(INBOUND_PREAUTH_DEADLINE_SECS),
            ),
        )
        .await
    }

    /// eMule `AddUpNextClient` for disconnected HighID winners: dial the peer,
    /// handshake, send `OP_ACCEPTUPLOADREQ`, and serve. Called from the
    /// proactive slot opener when `active < dynamic_slots`.
    async fn try_add_up_next_client(self: &Arc<Self>) {
        let active = self.active_count.load(std::sync::atomic::Ordering::Relaxed);
        let dynamic_slots = self.compute_dynamic_slot_count();
        if active >= dynamic_slots {
            return;
        }
        let in_flight_n = self
            .push_grant_dials
            .load(std::sync::atomic::Ordering::Relaxed);
        if in_flight_n >= MAX_PUSH_GRANT_DIALS {
            return;
        }

        let now = std::time::Instant::now();
        {
            let mut backoff = self.push_grant_backoff.lock().await;
            backoff.retain(|_, until| *until > now);
        }

        let candidate = {
            let cm = self.credit_manager.read().await;
            let idx = self.local_index.read().await;
            let in_flight = self.push_grant_in_flight.lock().await;
            let backoff = self.push_grant_backoff.lock().await;
            let queue = self.upload_queue.lock().await;

            let mut best_connected_score = f64::MIN;
            let mut best_dial: Option<(QueueEntry, f64)> = None;

            for e in queue.iter() {
                if e.join_time.elapsed().as_secs() >= MAX_PURGEQUEUETIME_SECS {
                    continue;
                }
                let score = score_queue_entry(
                    &cm,
                    &idx,
                    &e.user_hash,
                    e.file_hash,
                    e.join_time.elapsed().as_secs(),
                    e.current_addr,
                    e.emule_version,
                    e.is_friend_slot,
                    e.ember_pubkey.as_ref(),
                    e.ember_verified,
                );
                if e.current_addr.is_some() {
                    if score > best_connected_score {
                        best_connected_score = score;
                    }
                    continue;
                }
                if !e.is_high_id || e.tcp_port == 0 || e.last_ip.is_none() {
                    continue;
                }
                if e.file_hash == [0u8; 16] {
                    continue;
                }
                if in_flight.contains(&e.identity) || backoff.contains_key(&e.identity) {
                    continue;
                }
                let better = match &best_dial {
                    None => true,
                    Some((_, bs)) => {
                        score > *bs
                            || (score == *bs
                                && best_dial
                                    .as_ref()
                                    .map(|(be, _)| e.join_time < be.join_time)
                                    .unwrap_or(true))
                    }
                };
                if better {
                    best_dial = Some((e.clone(), score));
                }
            }
            drop(queue);
            drop(backoff);
            drop(in_flight);
            drop(idx);
            drop(cm);

            // Only dial when this HighID outscores every connected waiter
            // (or there are no connected waiters) — same priority as
            // FindBestClientInQueue returning a disconnected HighID.
            best_dial.and_then(|(entry, score)| {
                if score > best_connected_score || best_connected_score == f64::MIN {
                    Some(entry)
                } else {
                    None
                }
            })
        };

        let Some(entry) = candidate else {
            return;
        };
        let Some(ip) = entry.last_ip else {
            return;
        };
        let grant_tcp_port = entry.tcp_port;
        let peer_addr = SocketAddr::new(ip, grant_tcp_port);
        if peer_addr.port() == 0 {
            return;
        }
        if let IpAddr::V4(v4) = ip {
            if crate::security::is_special_use_v4(v4) {
                return;
            }
        }

        // Keep the waiting-list entry until grant succeeds so a concurrent
        // re-ask cannot replace it with a fresh join_time. in_flight blocks
        // a second dial of the same identity.
        {
            let mut in_flight = self.push_grant_in_flight.lock().await;
            if !in_flight.insert(entry.identity.clone()) {
                return;
            }
        }
        self.push_grant_dials
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let identity = entry.identity.clone();
        let grant_accepted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let req = ConnectServeRequest {
            peer_addr,
            crypt_options: entry.crypt_options,
            user_hash: (entry.user_hash != [0u8; 16]).then_some(entry.user_hash),
            push_grant_file_hash: Some(entry.file_hash),
            push_grant_accepted: Some(grant_accepted.clone()),
            secure_friend_ember_hash: None,
        };

        info!(
            "AddUpNextClient: dialing HighID push-grant to {peer_addr} for file {}",
            hex::encode(entry.file_hash)
        );

        // Reserve global + per-IP connection slots like the callback-serve arm.
        let reserved = {
            let mut cur = self
                .total_connections
                .load(std::sync::atomic::Ordering::Relaxed);
            loop {
                if cur >= MAX_TOTAL_CONNECTIONS {
                    break false;
                }
                match self.total_connections.compare_exchange_weak(
                    cur,
                    cur + 1,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Relaxed,
                ) {
                    Ok(_) => break true,
                    Err(c) => cur = c,
                }
            }
        };
        if !reserved {
            self.push_grant_dials
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            self.push_grant_in_flight.lock().await.remove(&identity);
            return;
        }
        let per_ip_reserved = {
            let mut counts = self.ip_connection_counts.lock();
            let count = counts.entry(ip).or_insert(0);
            if *count >= MAX_CONNECTIONS_PER_IP {
                false
            } else {
                *count += 1;
                true
            }
        };
        if !per_ip_reserved {
            self.total_connections
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            self.push_grant_dials
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            self.push_grant_in_flight.lock().await.remove(&identity);
            debug!("AddUpNextClient: dropping dial to {peer_addr}: per-IP limit reached");
            return;
        }
        let _admission_guard = ConnectionAdmissionGuard::new(
            self.total_connections.clone(),
            self.ip_connection_counts.clone(),
            ip,
        );

        let result = self.connect_and_serve(req).await;
        self.push_grant_dials
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        self.push_grant_in_flight.lock().await.remove(&identity);

        let accepted = grant_accepted.load(std::sync::atomic::Ordering::Relaxed);
        if accepted {
            // Granted: drop waiting-list seniority unless a different IP
            // still owns the bind. Same-IP advertised-port mismatch is a
            // NAT rebind of the peer that just got the slot.
            let mut queue = self.upload_queue.lock().await;
            queue.retain(|e| keep_queue_row_after_slot_grant(&identity, peer_addr.ip(), e));
        } else if let Err(e) = result {
            // Pre-grant failure: leave the queue entry (seniority intact) and backoff.
            debug!("AddUpNextClient dial to {peer_addr} failed before grant: {e}");
            self.push_grant_backoff.lock().await.insert(
                identity,
                std::time::Instant::now() + std::time::Duration::from_secs(PUSH_GRANT_BACKOFF_SECS),
            );
        }
        // Soft Ok(()) before grant (ban / AntiLeech / etc.) keeps seniority.
    }

    /// Dial `peer_addr` and serve it as an upload peer — the LowID callback
    /// upload path. This mirrors eMule's `OP_CALLBACKREQUESTED` → `TryToConnect`
    /// → unified-client-serve behaviour: a firewalled node that a peer can only
    /// reach via a server/KAD callback can still upload by connecting *out* and
    /// then serving over that connection.
    ///
    /// We are the connection initiator, so (opposite of the inbound listener) we
    /// send `OP_HELLO` / `OP_EMULEINFO` first and read the peer's answers, then
    /// hand the fully-handshaked stream to [`run_session`], which converges into
    /// the exact same serve loop an inbound upload uses. Obfuscation follows
    /// eMule's `Connect()` encryption decision: dial obfuscated only when the
    /// peer's callback crypt options ask for it, we hold the peer's user hash to
    /// seed RC4, and our own obfuscation layer is enabled. A crypt-*required*
    /// peer that fails obfuscation is abandoned; otherwise we retry once plain.
    ///
    /// When `push_grant_file_hash` is set, this is also the HighID
    /// `AddUpNextClient` path: after handshake we send `OP_ACCEPTUPLOADREQ`.
    async fn connect_and_serve(&self, req: ConnectServeRequest) -> anyhow::Result<()> {
        let peer_addr = req.peer_addr;
        let push_grant_file_hash = req.push_grant_file_hash;
        let push_grant_accepted = req.push_grant_accepted;
        let peer_hash = req.user_hash.filter(|h| *h != [0u8; 16]);
        let obf_enabled = self
            .obfuscation_enabled
            .load(std::sync::atomic::Ordering::Relaxed);
        let peer_requires_crypt = (req.crypt_options & 0x04) != 0;
        // eMule: obfuscate when we have a hash to key RC4, our layer is enabled,
        // and the peer supports (bit0) or requests (bit1) crypt. A secure friend
        // dial supersedes this entirely — Noise IK already encrypts the stream,
        // so layering RC4 underneath would only cost CPU.
        let want_obf = req.secure_friend_ember_hash.is_none()
            && peer_hash.is_some()
            && obf_enabled
            && (req.crypt_options & 0x03) != 0;

        let mut try_obf = want_obf;
        let mut fallback_used = false;
        loop {
            let stream = match tokio::time::timeout(
                std::time::Duration::from_secs(OUTBOUND_SERVE_HANDSHAKE_SECS),
                TcpStream::connect(peer_addr),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => anyhow::bail!("connect_and_serve {peer_addr}: tcp connect: {e}"),
                Err(_) => anyhow::bail!("connect_and_serve {peer_addr}: tcp connect timeout"),
            };
            super::multi_source::tune_peer_stream(&stream);

            let (raw_r, raw_w) = stream.into_split();
            let mut buf_r = tokio::io::BufReader::new(raw_r);
            let mut buf_w = tokio::io::BufWriter::new(raw_w);

            let mut secure_peer: Option<super::secure_stream::SecurePeerIdentity> = None;
            let (reader, writer): (StreamReader, StreamWriter) = if let Some(expected_ember_hash) =
                req.secure_friend_ember_hash
            {
                let secure = super::secure_stream::initiate(
                    Box::new(buf_r),
                    Box::new(buf_w),
                    self.ember_hash,
                    expected_ember_hash,
                    self.ed25519_public_key,
                    self.ed25519_secret_key,
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!("connect_and_serve {peer_addr}: secure friend dial: {e}")
                })?;
                secure_peer = Some(secure.peer);
                (
                    StreamReader::Boxed(secure.reader),
                    StreamWriter::Boxed(secure.writer),
                )
            } else if try_obf {
                let hash = peer_hash.unwrap();
                match tcp_obfuscation::negotiate_outgoing(&mut buf_r, &mut buf_w, &hash).await {
                    Ok((recv_key, send_key)) => (
                        StreamReader::Obfuscated(tokio::io::BufReader::new(Rc4Reader::new(
                            buf_r, recv_key,
                        ))),
                        StreamWriter::Obfuscated(tokio::io::BufWriter::new(Rc4Writer::new(
                            buf_w, send_key,
                        ))),
                    ),
                    Err(e) => {
                        if peer_requires_crypt {
                            anyhow::bail!(
                                "connect_and_serve {peer_addr}: peer requires crypt but obfuscation failed: {e}"
                            );
                        }
                        if fallback_used {
                            anyhow::bail!("connect_and_serve {peer_addr}: obfuscation failed: {e}");
                        }
                        debug!(
                            "connect_and_serve {peer_addr}: obfuscation failed ({e}); retrying plain"
                        );
                        try_obf = false;
                        fallback_used = true;
                        continue;
                    }
                }
            } else {
                (StreamReader::Plain(buf_r), StreamWriter::Plain(buf_w))
            };

            return self
                .serve_after_transport(
                    peer_addr,
                    reader,
                    writer,
                    secure_peer,
                    obf_enabled,
                    push_grant_file_hash,
                    push_grant_accepted,
                )
                .await;
        }
    }

    /// Drive the outbound-serve handshake over an already-connected transport
    /// and hand the result to [`run_session`].
    ///
    /// Split out of [`connect_and_serve`] so the same handshake can run over a
    /// stream we did not dial: a coordinated friend-transfer hole-punch produces
    /// QUIC streams rather than a `TcpStream`, but the eD2K choreography from
    /// `OP_HELLO` onward is identical. We are the initiator either way, so we
    /// send Hello/EmuleInfo first and read the peer's answers.
    #[allow(clippy::too_many_arguments)]
    async fn serve_after_transport(
        &self,
        peer_addr: SocketAddr,
        mut reader: StreamReader,
        mut writer: StreamWriter,
        secure_peer: Option<super::secure_stream::SecurePeerIdentity>,
        obf_enabled: bool,
        push_grant_file_hash: Option<[u8; 16]>,
        push_grant_accepted: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) -> anyhow::Result<()> {
        {
            // Outbound Hello (we initiate: send OP_HELLO, expect OP_HELLOANSWER).
            let our_client_id = self
                .external_ip_shared
                .load(std::sync::atomic::Ordering::Relaxed);
            let buddy = self.shared_buddy_info.read().await.clone();
            let hello_options = self.hello_options().await;
            let nickname = self.nickname_snapshot().await;
            let hello_payload = build_hello_with_buddy_opts(
                &self.user_hash,
                our_client_id,
                self.advertised_tcp_port(),
                &nickname,
                buddy,
                &hello_options,
            );
            if let Err(e) =
                write_packet_async(&mut writer, OP_EDONKEYHEADER, OP_HELLO, &hello_payload).await
            {
                anyhow::bail!("connect_and_serve {peer_addr}: send Hello: {e}");
            }

            let (hproto, hopcode, hello_data) = match tokio::time::timeout(
                std::time::Duration::from_secs(OUTBOUND_SERVE_HANDSHAKE_SECS),
                read_packet_async_inner(&mut reader),
            )
            .await
            {
                Ok(Ok(pkt)) => pkt,
                Ok(Err(e)) => {
                    anyhow::bail!("connect_and_serve {peer_addr}: read HelloAnswer: {e}")
                }
                Err(_) => anyhow::bail!("connect_and_serve {peer_addr}: HelloAnswer timed out"),
            };
            if hproto != OP_EDONKEYHEADER || hopcode != OP_HELLOANSWER {
                anyhow::bail!(
                    "connect_and_serve {peer_addr}: expected HelloAnswer, got proto=0x{hproto:02X} op=0x{hopcode:02X}"
                );
            }
            let (peer_user_hash, mut hello_caps) =
                parse_hello_answer(&hello_data).unwrap_or_else(|_| {
                    let mut puh = [0u8; 16];
                    if hello_data.len() >= 16 {
                        puh.copy_from_slice(&hello_data[..16]);
                    }
                    (puh, PeerCapabilities::default())
                });

            // Outbound EmuleInfo: send ours, then read the peer's answer. A
            // non-EmuleInfo packet here (peer jumped straight to a file request)
            // is captured as `first_packet` and replayed by the serve loop.
            let emule_payload = build_emule_info(
                self.advertised_udp_port(),
                obf_enabled,
                Some(&self.ember_hash),
                None,
            );
            write_packet_async(&mut writer, OP_EMULEPROT, OP_EMULEINFO, &emule_payload).await?;
            let mut first_packet: Option<(u8, u8, Vec<u8>)> = None;
            if let Ok(Ok((eproto, eopcode, epayload))) = tokio::time::timeout(
                std::time::Duration::from_secs(OUTBOUND_SERVE_HANDSHAKE_SECS),
                read_packet_async_inner(&mut reader),
            )
            .await
            {
                if eproto == OP_EMULEPROT
                    && (eopcode == OP_EMULEINFOANSWER || eopcode == OP_EMULEINFO)
                {
                    merge_caps(&mut hello_caps, parse_emule_info(&epayload));
                    if eopcode == OP_EMULEINFO {
                        let answer = build_emule_info(
                            self.advertised_udp_port(),
                            obf_enabled,
                            Some(&self.ember_hash),
                            None,
                        );
                        let _ = write_packet_async(
                            &mut writer,
                            OP_EMULEPROT,
                            OP_EMULEINFOANSWER,
                            &answer,
                        )
                        .await;
                    }
                } else {
                    first_packet = Some((eproto, eopcode, epayload));
                }
            }

            let is_obf = matches!(reader, StreamReader::Obfuscated(_));
            info!(
                "Established outbound upload session to {peer_addr} (obf={is_obf}, secure_v2={}, user={})",
                secure_peer.is_some(),
                crate::security::short_hash(&peer_user_hash),
            );

            let state = OutboundServeState {
                reader,
                writer,
                hello_data,
                peer_user_hash,
                hello_caps,
                first_packet,
                push_grant_file_hash,
                push_grant_accepted,
                secure_peer,
            };
            self.run_session(peer_addr, ConnInit::OutboundServe(Box::new(state)), None)
                .await
        }
    }

    /// Serve a friend over a transport we did not dial — the responder half of a
    /// coordinated friend-transfer hole-punch.
    ///
    /// The friend asked us (over their friend session) to reach them via
    /// `OP_EMBER_XFER_REQ` with [`EmberXferMethod::Punch`], and the punch has
    /// now produced a bidirectional stream. We negotiate Noise IK as the
    /// *initiator* against their expected identity — which both encrypts the
    /// transfer and lets them route our stream into the right download by proven
    /// identity — and then take the eD2K serve role.
    ///
    /// Taking the serve role explicitly is the whole point: every other punched
    /// stream is handed to the inbound path, and if both peers did that for a
    /// transfer they would each sit waiting for the other's `OP_HELLO`.
    async fn serve_punched_friend(
        &self,
        peer_addr: SocketAddr,
        reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
        expected_ember_hash: [u8; 16],
    ) -> anyhow::Result<()> {
        let secure = super::secure_stream::initiate(
            reader,
            writer,
            self.ember_hash,
            expected_ember_hash,
            self.ed25519_public_key,
            self.ed25519_secret_key,
        )
        .await
        .map_err(|e| anyhow::anyhow!("punched friend serve {peer_addr}: secure handshake: {e}"))?;

        let obf_enabled = self
            .obfuscation_enabled
            .load(std::sync::atomic::Ordering::Relaxed);
        self.serve_after_transport(
            peer_addr,
            StreamReader::Boxed(secure.reader),
            StreamWriter::Boxed(secure.writer),
            Some(secure.peer),
            obf_enabled,
            None,
            None,
        )
        .await
    }

    /// Shared upload-session driver for both inbound connections (a peer dialed
    /// our listener) and outbound connect-and-serve connections (we dialed a
    /// peer in response to a server/KAD callback so a firewalled LowID node can
    /// still upload — eMule's `OP_CALLBACKREQUESTED` → `TryToConnect` behaviour).
    /// The handshake preamble differs by direction; everything from the EmuleInfo
    /// exchange through the serve loop and teardown is byte-for-byte identical,
    /// so both paths converge into the same code below.
    async fn run_session(
        &self,
        peer_addr: SocketAddr,
        init: ConnInit,
        preauth_deadline: Option<tokio::time::Instant>,
    ) -> anyhow::Result<()> {
        // Outbound callbacks are dialed by us for a known peer, so they skip the
        // inbound-only steps: the ban precheck, the buddy/KAD/server/Path-B
        // stream diversions, the abuse-request counter, and the inbound EmuleInfo
        // read (we complete EmuleInfo during the outbound handshake instead).
        let outbound = matches!(init, ConnInit::OutboundServe(_));
        // A punch/relay-adopted stream is inbound-like for banning/counting
        // purposes, but MUST skip the buddy/KAD-callback/server-callback/Path-B
        // diversions below: those match on `(peer_addr.ip(), peer_user_hash,
        // hello_port)` against pending *download*-side bookkeeping, and this
        // peer's identity can coincidentally collide with an unrelated pending
        // entry (e.g. we're also trying to download something else from them).
        // `StreamReader`/`StreamWriter::Boxed` have no TCP-typed counterpart,
        // so those diversions' exhaustive matches would otherwise silently
        // drop the connection via their `_ => return Ok(())` fallback instead
        // of continuing into the upload serve loop.
        let inbound_stream = matches!(init, ConnInit::InboundStream { .. });
        let skip_diversions = outbound || inbound_stream;

        // Check if already banned (fast path), but don't count yet --
        // buddy/KAD callback connections are legitimate and shouldn't
        // inflate the request counter.
        if !outbound {
            let tracker = self.abuse_tracker.lock().await;
            if tracker.is_banned(&peer_addr.ip()) {
                anyhow::bail!("auto-banned for excessive requests");
            }
        }

        // Produce the post-Hello session state via whichever path initiated this
        // connection. `obf_ember_hash` / `obf_emule_caps` are only set by the
        // inbound obfuscated branch; outbound leaves them `None` (its EmuleInfo
        // caps are already merged into `hello_caps` by `connect_and_serve`).
        let mut obf_ember_hash: Option<[u8; 16]> = None;
        let mut obf_emule_caps: Option<PeerCapabilities> = None;
        // A packet handed over by the outbound handshake to replay as the serve
        // loop's first packet (see `OutboundServeState::first_packet`). Always
        // `None` for inbound.
        let mut outbound_first_packet: Option<(u8, u8, Vec<u8>)> = None;
        let mut push_grant_file_hash: Option<[u8; 16]> = None;
        let mut push_grant_accepted: Option<std::sync::Arc<std::sync::atomic::AtomicBool>> = None;
        let mut secure_v2_peer: Option<super::secure_stream::SecurePeerIdentity> = None;
        let (mut reader, mut writer, hello_data, peer_user_hash, mut hello_caps) = match init {
            ConnInit::OutboundServe(state) => {
                let OutboundServeState {
                    reader,
                    writer,
                    hello_data,
                    peer_user_hash,
                    hello_caps,
                    first_packet,
                    push_grant_file_hash: pg,
                    push_grant_accepted: pga,
                    secure_peer,
                } = *state;
                secure_v2_peer = secure_peer;
                outbound_first_packet = first_packet;
                push_grant_file_hash = pg;
                push_grant_accepted = pga;
                (reader, writer, hello_data, peer_user_hash, hello_caps)
            }
            ConnInit::InboundStream {
                reader: mut boxed_reader,
                writer: boxed_writer,
                secure_peer: preauthenticated_peer,
            } => {
                let (mut rd, mut wr, first_inner_byte) = if let Some(peer) = preauthenticated_peer {
                    secure_v2_peer = Some(peer);
                    (
                        StreamReader::Boxed(boxed_reader),
                        StreamWriter::Boxed(boxed_writer),
                        None,
                    )
                } else {
                    let first = match tokio::time::timeout_at(
                        preauth_deadline.expect("inbound streams have a pre-auth deadline"),
                        boxed_reader.read_u8(),
                    )
                    .await
                    {
                        Ok(Ok(byte)) => byte,
                        Ok(Err(e)) if is_connection_closed(&e) => {
                            info!("Punch/relay-adopted connection from {peer_addr} closed immediately");
                            return Ok(());
                        }
                        Ok(Err(e)) => {
                            info!(
                                "Punch/relay-adopted connection read failed from {peer_addr}: {e}"
                            );
                            return Ok(());
                        }
                        Err(_) => {
                            info!("Timeout waiting for stream preamble from punch/relay peer {peer_addr}");
                            return Ok(());
                        }
                    };
                    if super::secure_stream::is_preamble_first_byte(first) {
                        let secure = tokio::time::timeout_at(
                            preauth_deadline.expect("inbound streams have a pre-auth deadline"),
                            super::secure_stream::accept_after_first(
                                boxed_reader,
                                boxed_writer,
                                first,
                                self.ember_hash,
                                self.ed25519_public_key,
                                self.ed25519_secret_key,
                            ),
                        )
                        .await
                        .map_err(|_| anyhow::anyhow!("secure-stream negotiation timed out"))??;
                        secure_v2_peer = Some(secure.peer);
                        (
                            StreamReader::Boxed(secure.reader),
                            StreamWriter::Boxed(secure.writer),
                            None,
                        )
                    } else {
                        (
                            StreamReader::Boxed(boxed_reader),
                            StreamWriter::Boxed(boxed_writer),
                            Some(first),
                        )
                    }
                };

                let (proto, opcode, hd) = match tokio::time::timeout_at(
                    preauth_deadline.expect("inbound streams have a pre-auth deadline"),
                    async {
                        if let Some(first) = first_inner_byte {
                            read_packet_with_first_byte(&mut rd, first).await
                        } else {
                            read_packet_async_inner(&mut rd).await
                        }
                    },
                )
                .await
                {
                    Ok(Ok(pkt)) => pkt,
                    Ok(Err(e)) if is_connection_closed(&e) => {
                        info!("Punch/relay-adopted connection from {peer_addr} closed immediately");
                        return Ok(());
                    }
                    Ok(Err(e)) => {
                        info!("Punch/relay-adopted connection read failed from {peer_addr}: {e}");
                        return Ok(());
                    }
                    Err(_) => {
                        info!("Timeout waiting for Hello on punch/relay-adopted connection from {peer_addr}");
                        return Ok(());
                    }
                };

                if proto != OP_EDONKEYHEADER || opcode != OP_HELLO {
                    info!(
                        "Non-Hello packet on punch/relay-adopted connection from {peer_addr}: proto=0x{proto:02X} op=0x{opcode:02X}"
                    );
                    return Ok(());
                }

                let mut puh = [0u8; 16];
                if hd.len() >= 17 {
                    puh.copy_from_slice(&hd[1..17]);
                }
                debug!("Got Hello from punch/relay-adopted peer {peer_addr}");

                let buddy = self.shared_buddy_info.read().await.clone();
                let hello_options = self.hello_options().await;
                let our_client_id = self
                    .external_ip_shared
                    .load(std::sync::atomic::Ordering::Relaxed);
                let nickname = self.nickname_snapshot().await;
                let hello_payload = build_hello_answer_with_buddy_opts(
                    &self.user_hash,
                    our_client_id,
                    self.advertised_tcp_port(),
                    &nickname,
                    buddy,
                    &hello_options,
                );
                write_packet_async(&mut wr, OP_EDONKEYHEADER, OP_HELLOANSWER, &hello_payload)
                    .await?;

                // Same rationale as the plain-TCP inbound branch below: send our
                // EmuleInfoAnswer unconditionally so the peer's client completes
                // a full eMule handshake (many mods/clients otherwise treat a
                // Hello-only reply as half-baked and silently FIN on the first
                // file request).
                let emule_payload = build_emule_info(
                    self.advertised_udp_port(),
                    self.obfuscation_enabled
                        .load(std::sync::atomic::Ordering::Relaxed),
                    Some(&self.ember_hash),
                    None,
                );
                write_packet_async(&mut wr, OP_EMULEPROT, OP_EMULEINFOANSWER, &emule_payload)
                    .await?;

                let (_, hello_caps) = parse_hello_packet(&hd)
                    .unwrap_or_else(|_| ([0u8; 16], PeerCapabilities::default()));
                (rd, wr, hd, puh, hello_caps)
            }
            ConnInit::Inbound(stream) => {
                let (reader, writer) = stream.into_split();
                let mut raw_reader = tokio::io::BufReader::new(reader);
                let mut raw_writer = tokio::io::BufWriter::new(writer);

                let first_byte = match tokio::time::timeout_at(
                    preauth_deadline.expect("inbound TCP has a pre-auth deadline"),
                    raw_reader.read_u8(),
                )
                .await
                {
                    Ok(Ok(byte)) => byte,
                    Ok(Err(e)) if is_connection_closed(&e) => {
                        info!("Probe connection from {peer_addr} (closed immediately)");
                        return Ok(());
                    }
                    Ok(Err(e)) => return Err(e.into()),
                    Err(_) => {
                        info!("Timeout waiting for TCP stream discriminator from {peer_addr}");
                        return Ok(());
                    }
                };
                // `0x00` is a legal eMule obfuscation discriminator, so the
                // discriminator alone cannot tell a friend preamble from an
                // ordinary obfuscated dial. Peek the buffered magic before
                // committing; a mismatch falls through to the negotiator below
                // with the stream untouched.
                // The peek stays behind the cheap first-byte test so an ordinary
                // obfuscated dial never waits on it, and is bounded like every
                // other pre-auth read here: `read_u8` above emptied the buffer,
                // so it issues a socket read, and a peer that sends one `0x00`
                // and then nothing would otherwise park this task forever
                // holding an admission slot. A timeout falls through to the
                // eMule negotiator, which is bounded by the same deadline.
                let is_ember_preamble = super::secure_stream::is_preamble_first_byte(first_byte)
                    && matches!(
                        tokio::time::timeout_at(
                            preauth_deadline.expect("inbound TCP has a pre-auth deadline"),
                            super::secure_stream::buffered_magic_matches(&mut raw_reader),
                        )
                        .await,
                        Ok(true)
                    );
                if is_ember_preamble {
                    let secure = tokio::time::timeout_at(
                        preauth_deadline.expect("inbound TCP has a pre-auth deadline"),
                        super::secure_stream::accept_after_first(
                            Box::new(raw_reader),
                            Box::new(raw_writer),
                            first_byte,
                            self.ember_hash,
                            self.ed25519_public_key,
                            self.ed25519_secret_key,
                        ),
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!("secure-stream negotiation timed out"))??;
                    return Box::pin(self.run_session(
                        peer_addr,
                        ConnInit::InboundStream {
                            reader: secure.reader,
                            writer: secure.writer,
                            secure_peer: Some(secure.peer),
                        },
                        preauth_deadline,
                    ))
                    .await;
                }

                // Negotiate obfuscation with full handshake response.
                let negotiation = match tokio::time::timeout_at(
                    preauth_deadline.expect("inbound TCP has a pre-auth deadline"),
                    tcp_obfuscation::negotiate_incoming_with_first_byte(
                        &mut raw_reader,
                        &mut raw_writer,
                        &self.user_hash,
                        true,
                        first_byte,
                    ),
                )
                .await
                {
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

                // Server port test detection: if this IP matches our connected/pending server,
                // the server is verifying our TCP port is reachable for HighID assignment.
                // Use a short timeout so we respond quickly without blocking the main login.
                let is_server_port_test = {
                    let server_addr = self.shared_server_addr.read().await;
                    server_addr
                        .map(|a| a.ip() == peer_addr.ip())
                        .unwrap_or(false)
                };

                let (reader, writer, hello_data, peer_user_hash) = match negotiation {
                    NegotiationResult::Obfuscated {
                        recv_key,
                        mut send_key,
                    } => {
                        info!("Obfuscated connection from {peer_addr}");
                        let mut obf_reader =
                            tokio::io::BufReader::new(Rc4Reader::new(raw_reader, recv_key));

                        let probe_timeout = if is_server_port_test {
                            info!("Server port test detected from {peer_addr}");
                            std::time::Duration::from_secs(3)
                        } else {
                            std::time::Duration::from_secs(15)
                        };
                        let first_frame_deadline = preauth_deadline
                            .expect("inbound TCP has a pre-auth deadline")
                            .min(tokio::time::Instant::now() + probe_timeout);
                        let first_pkt = tokio::time::timeout_at(
                            first_frame_deadline,
                            read_packet_async_inner(&mut obf_reader),
                        )
                        .await;

                        match first_pkt {
                            Ok(Ok((proto, opcode, payload)))
                                if proto == OP_EDONKEYHEADER && opcode == OP_HELLO =>
                            {
                                let mut puh = [0u8; 16];
                                if payload.len() >= 17 {
                                    puh.copy_from_slice(&payload[1..17]);
                                }

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
                                let nickname = self.nickname_snapshot().await;
                                let hello_payload = build_hello_answer_with_buddy_opts(
                                    &self.user_hash,
                                    our_client_id,
                                    self.advertised_tcp_port(),
                                    &nickname,
                                    buddy,
                                    &hello_options,
                                );
                                let mut pkt = Vec::with_capacity(6 + hello_payload.len());
                                pkt.push(OP_EDONKEYHEADER);
                                pkt.extend_from_slice(
                                    &((1 + hello_payload.len()) as u32).to_le_bytes(),
                                );
                                pkt.push(OP_HELLOANSWER);
                                pkt.extend_from_slice(&hello_payload);
                                let mut enc = vec![0u8; pkt.len()];
                                send_key.process(&pkt, &mut enc);
                                raw_writer.write_all(&enc).await?;
                                raw_writer.flush().await?;

                                let emule_payload = build_emule_info(
                                    self.advertised_udp_port(),
                                    self.obfuscation_enabled
                                        .load(std::sync::atomic::Ordering::Relaxed),
                                    Some(&self.ember_hash),
                                    None,
                                );
                                let mut epkt = Vec::with_capacity(6 + emule_payload.len());
                                epkt.push(OP_EMULEPROT);
                                epkt.extend_from_slice(
                                    &((1 + emule_payload.len()) as u32).to_le_bytes(),
                                );
                                epkt.push(OP_EMULEINFOANSWER);
                                epkt.extend_from_slice(&emule_payload);
                                let mut eenc = vec![0u8; epkt.len()];
                                send_key.process(&epkt, &mut eenc);
                                raw_writer.write_all(&eenc).await?;
                                raw_writer.flush().await?;

                                if is_server_port_test {
                                    info!("Server port test from {peer_addr}: replied to Hello+EmuleInfo, port verified");
                                    // Same proof as a KAD TCP connect-back: inbound
                                    // reachability from a trusted endpoint.
                                    self.tcp_connect_back_shared
                                        .store(true, std::sync::atomic::Ordering::Relaxed);
                                    self.firewalled_shared
                                        .store(false, std::sync::atomic::Ordering::Relaxed);
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
                                        },
                                    )
                                    .await;
                                    return Ok(());
                                }

                                // Consume peer's EmuleInfo/SecIdent packets
                                let mut obf_peer_ember_hash: Option<[u8; 16]> = None;
                                let mut obf_peer_caps: Option<PeerCapabilities> = None;
                                for _ in 0..5 {
                                    match tokio::time::timeout(
                                        std::time::Duration::from_secs(5),
                                        read_packet_async_inner(&mut obf_reader),
                                    )
                                    .await
                                    {
                                        Ok(Ok((p, o, ref data))) => {
                                            if p == OP_EMULEPROT
                                                && (o == OP_EMULEINFOANSWER || o == OP_EMULEINFO)
                                            {
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

                                let obf_writer =
                                    tokio::io::BufWriter::new(Rc4Writer::new(raw_writer, send_key));
                                obf_ember_hash = obf_peer_ember_hash;
                                obf_emule_caps = obf_peer_caps;
                                (
                                    StreamReader::Obfuscated(obf_reader),
                                    StreamWriter::Obfuscated(obf_writer),
                                    payload,
                                    puh,
                                )
                            }
                            Ok(Ok((proto, opcode, _)))
                                if proto == OP_EMULEPROT && opcode == OP_PORTTEST =>
                            {
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
                        let (proto, opcode, hd) = tokio::time::timeout_at(
                            preauth_deadline.expect("inbound TCP has a pre-auth deadline"),
                            read_packet_with_first_byte(&mut rd, first_byte),
                        )
                        .await
                        .map_err(|_| anyhow::anyhow!("first eD2K frame timed out"))??;

                        if (proto == OP_EDONKEYHEADER || proto == OP_EMULEPROT)
                            && opcode == OP_PORTTEST
                        {
                            debug!("Received TCP Port Test from {peer_addr}");
                            let reply = [0x12u8];
                            write_packet_async(&mut wr, proto, OP_PORTTEST, &reply).await?;
                            let (tx, mut rx) = tokio::sync::mpsc::channel(1);
                            {
                                let mut waiters = self.active_port_tests.lock().await;
                                waiters.insert(peer_addr.ip(), tx);
                            }
                            let signal =
                                tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
                                    .await;
                            {
                                let mut waiters = self.active_port_tests.lock().await;
                                waiters.remove(&peer_addr.ip());
                            }
                            if let Ok(Some(_)) = signal {
                                write_packet_async(&mut wr, proto, OP_PORTTEST, &reply).await?;
                            }
                            return Ok(());
                        }

                        if proto != OP_EDONKEYHEADER || opcode != OP_HELLO {
                            info!(
                        "Non-Hello packet from {peer_addr}: proto=0x{proto:02X} op=0x{opcode:02X}"
                    );
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                            return Ok(());
                        }

                        let mut puh = [0u8; 16];
                        if hd.len() >= 17 {
                            puh.copy_from_slice(&hd[1..17]);
                        }
                        debug!("Got Hello from {peer_addr}");

                        let buddy = self.shared_buddy_info.read().await.clone();
                        let hello_options = self.hello_options().await;
                        // Advertise our real HighID client_id when known (see the
                        // matching block in the obfuscated path above for rationale).
                        let our_client_id = self
                            .external_ip_shared
                            .load(std::sync::atomic::Ordering::Relaxed);
                        let nickname = self.nickname_snapshot().await;
                        let hello_payload = build_hello_answer_with_buddy_opts(
                            &self.user_hash,
                            our_client_id,
                            self.advertised_tcp_port(),
                            &nickname,
                            buddy,
                            &hello_options,
                        );
                        write_packet_async(
                            &mut wr,
                            OP_EDONKEYHEADER,
                            OP_HELLOANSWER,
                            &hello_payload,
                        )
                        .await?;

                        // Mirror eMule's ListenSocket::ProcessPacket OP_HELLO path
                        // (ListenSocket.cpp:273): after responding with OP_HELLOANSWER,
                        // send our OP_EMULEINFOANSWER so the peer gets a complete
                        // eMule handshake before we hand off to multi_source.
                        //
                        // Without this packet, the peer's CUpDownClient sees only
                        // OP_HELLOANSWER from us — its `m_byInfopacketsReceived`
                        // still flips to IP_BOTH via the eMule tags embedded in
                        // our HelloAnswer (`ProcessHelloTypePacket` bIsMule
                        // branch, BaseClient.cpp:661-664), so the SecIdent state
                        // machine *does* start — but many eMule mods and a
                        // surprising number of legitimate clients (anti-leecher
                        // heuristics in NeoMule/MorphXT/etc., plus older aMule
                        // 2.3.x builds that the log shows are common on this
                        // network) treat the absence of an explicit
                        // OP_EMULEINFO/OP_EMULEINFOANSWER round trip as a
                        // half-baked handshake. They accept the TCP connection,
                        // ACK our HelloAnswer, then silently FIN as soon as we
                        // send OP_REQUESTFILENAME — the exact symptom we hit in
                        // production for every KAD-callback source:
                        //
                        //   `stage:file_status_wait (round 0, got_filename=false,
                        //    early_accept=false): unexpected end of file`
                        //
                        // The obfuscated path above (line ~1602) already sends
                        // OP_EMULEINFOANSWER unconditionally for the same
                        // reason. KAD-callback sources connect back in
                        // plaintext by default (the firewalled peer doesn't
                        // know our user hash until they parse our HelloAnswer,
                        // so eMule's `Connect()` falls through to
                        // `SetConnectionEncryption(false, NULL, false)`), which
                        // is why this regression only ever bit callback flows.
                        let emule_payload = build_emule_info(
                            self.advertised_udp_port(),
                            self.obfuscation_enabled
                                .load(std::sync::atomic::Ordering::Relaxed),
                            Some(&self.ember_hash),
                            None,
                        );
                        write_packet_async(
                            &mut wr,
                            OP_EMULEPROT,
                            OP_EMULEINFOANSWER,
                            &emule_payload,
                        )
                        .await?;

                        if is_server_port_test {
                            info!("Server port test from {peer_addr}: replied to Hello+EmuleInfo, port verified");
                            self.tcp_connect_back_shared
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                            self.firewalled_shared
                                .store(false, std::sync::atomic::Ordering::Relaxed);
                            return Ok(());
                        }

                        (rd, wr, hd, puh)
                    }
                };

                let (_, mut hello_caps) = parse_hello_packet(&hello_data)
                    .unwrap_or_else(|_| ([0u8; 16], PeerCapabilities::default()));
                if let Some(obf_caps) = obf_emule_caps.take() {
                    merge_caps(&mut hello_caps, obf_caps);
                }
                (reader, writer, hello_data, peer_user_hash, hello_caps)
            }
        };

        let secure_v2_authenticated = secure_v2_peer.is_some();
        if let Some(peer) = secure_v2_peer {
            // Noise IK plus the v2 prologue is authoritative.  Inner eD2K
            // Hello/EmuleInfo fields remain byte-compatible metadata and may
            // not replace the authenticated Ember identity.
            hello_caps.is_ember = true;
            hello_caps.ember_hash = Some(peer.ember_hash);
            hello_caps.ember_pubkey = Some(peer.ed25519_public_key);
        }

        // Reserved admission for the configured eD2K server IP exists only so
        // the short HighID port-test can enter while ordinary capacity is full.
        // Any long-lived session (this point is past the port-test early return)
        // that only fit because of that reserve must be rejected.
        {
            let from_configured_server_ip = {
                let server_addr = self.shared_server_addr.read().await;
                server_addr
                    .map(|a| a.ip() == peer_addr.ip())
                    .unwrap_or(false)
            };
            let total = self
                .total_connections
                .load(std::sync::atomic::Ordering::Relaxed);
            if !allow_long_lived_session_under_admission(from_configured_server_ip, total) {
                info!(
                    "Rejecting long-lived connection from configured server IP {peer_addr}: \
                     reserved capacity is only for the short HighID port-test protocol \
                     (connections={total}, ordinary_max={MAX_TOTAL_CONNECTIONS})"
                );
                return Ok(());
            }
        }

        let peer_source_exchange_ver = hello_caps.source_exchange_ver.max(1);
        let peer_secure_ident_level = hello_caps.secure_ident_level;
        let peer_compression_ver = hello_caps.compression_ver;
        let mut ul_peer_name = if hello_caps.peer_name.is_empty() {
            peer_addr.to_string()
        } else {
            hello_caps.peer_name.clone()
        };
        let mut ul_client_software = client_software_from_caps(&hello_caps);
        let ul_country_code = crate::geoip::lookup_country(&self.geoip, peer_addr.ip());

        if peer_user_hash != [0u8; 16] {
            if let Ok(set) = self.banned_hashes.read() {
                if set.contains(&peer_user_hash) {
                    info!(
                        "Rejecting upload session from banned user {} ({})",
                        crate::security::short_hash(&peer_user_hash),
                        peer_addr
                    );
                    return Ok(());
                }
            }
        }

        // Check if this is an incoming buddy connection.
        // Release the pending-buddy mutex before awaiting on the bounded
        // `buddy_conn_tx` channel: if the channel is at capacity, `.send().await`
        // parks until a receiver drains it, and anything in the network loop
        // that wanted to `lock().await` this mutex would deadlock.
        let buddy_callback = if skip_diversions {
            None
        } else {
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
            let _ = self
                .buddy_conn_tx
                .send((peer_user_hash, callback_check, tcp_reader, tcp_writer))
                .await;
            return Ok(());
        }

        // Friend-transfer connect-back diversion: a friend we sent
        // `OP_EMBER_XFER_REQ` to has dialed us so we can download from them
        // (the friend-layer analogue of an eD2K LowID callback, with no server
        // or KAD buddy involved).
        //
        // This deliberately runs even for connections `skip_diversions`
        // excludes from the metadata-keyed diversions below. Those match on
        // self-reported `(ip, user_hash, hello_port)` and can collide with an
        // unrelated pending entry; this one keys on the Ember hash Noise IK
        // *proved* the peer owns, which no other peer can claim. It also only
        // ever fires when we asked this specific friend for this specific
        // file, so there is no window for an unsolicited adoption.
        if !outbound {
            if let Some(peer) = secure_v2_peer {
                let key = PendingKadCallbackKey::FriendEmber(peer.ember_hash);
                // Membership is checked *before* consuming the expectation: a
                // friend removed between our request and their dial must leave
                // the entry for the sweep to expire, not silently burn it.
                let expecting_friend =
                    {
                        let cbs = self.pending_kad_callbacks.lock().await;
                        cbs.contains_key(&key)
                    } && self.friend_hashes.read().await.contains(&peer.ember_hash);
                let friend_callback_file = if expecting_friend {
                    let now = chrono::Utc::now().timestamp();
                    let mut cbs = self.pending_kad_callbacks.lock().await;
                    let mut matched = None;
                    if let Some(entries) = cbs.get_mut(&key) {
                        entries.retain(|e| now - e.registered_at < PENDING_KAD_CALLBACK_SECS);
                        // The requester allows only one outstanding
                        // `OP_EMBER_XFER_REQ` per friend at a time (see
                        // `request_friend_transfer`), so there is at most one
                        // entry here and no guessing about which file this
                        // connection was opened for. Were that invariant ever
                        // relaxed, this would need the request nonce echoed on
                        // the data connection to stay unambiguous.
                        matched = entries.pop().map(|e| e.file_hash);
                        if entries.is_empty() {
                            cbs.remove(&key);
                        }
                    }
                    matched
                } else {
                    None
                };
                if let Some(file_hash) = friend_callback_file {
                    let (dyn_reader, dyn_writer): (
                        Box<dyn tokio::io::AsyncRead + Unpin + Send>,
                        Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
                    ) = match (reader, writer) {
                        (StreamReader::Boxed(r), StreamWriter::Boxed(w)) => (r, w),
                        // Unreachable: a secure-v2 session is always Boxed on
                        // both halves. Bail rather than panic so a future
                        // transport that breaks the invariant degrades to a
                        // dropped connection and a retry.
                        _ => {
                            warn!(
                                "Friend transfer connect-back from {peer_addr} was not a boxed secure stream; dropping"
                            );
                            return Ok(());
                        }
                    };
                    info!(
                        "Recognized friend transfer connect-back from {} ({peer_addr}) for file {}",
                        hex::encode(peer.ember_hash),
                        hex::encode(file_hash)
                    );
                    let peer_v4 = match peer_addr.ip() {
                        std::net::IpAddr::V4(v4) => v4,
                        _ => std::net::Ipv4Addr::UNSPECIFIED,
                    };
                    let _ = self
                        .kad_callback_tx
                        .send(KadCallbackParts {
                            peer_ip: peer_v4,
                            peer_port: peer_addr.port(),
                            peer_hello_port: hello_caps.tcp_port,
                            peer_user_hash,
                            file_hash,
                            reader: dyn_reader,
                            writer: dyn_writer,
                            // The secure inbound branch already answered with
                            // our EmuleInfoAnswer, so the adopting downloader
                            // must not run the exchange again. A trailing
                            // `OP_EMULEINFO` from the friend's own outbound
                            // handshake is merged by the download loop's
                            // delayed-EmuleInfo arm.
                            emule_info_done: true,
                            peer_caps: hello_caps.clone(),
                            friend_ember_hash: Some(peer.ember_hash),
                        })
                        .await;
                    return Ok(());
                }
            }
        }

        // Inbound-only stream diversions (buddy handled above): match this
        // connection against pending KAD/server callbacks and Path-B queued
        // sources. None of these apply to an outbound dial we initiated, so a
        // `None` here (whenever `outbound`) cleanly skips all three blocks below
        // without re-indenting them.
        let diversion_ip: Option<std::net::Ipv4Addr> = if skip_diversions {
            None
        } else {
            match peer_addr.ip() {
                std::net::IpAddr::V4(v4) => Some(v4),
                _ => None,
            }
        };

        // Check if this is a KAD callback connection (firewalled source connecting back)
        if let Some(peer_v4) = diversion_ip {
            let peer_hello_port = if hello_data.len() >= 23 {
                u16::from_le_bytes([hello_data[21], hello_data[22]])
            } else {
                0
            };
            let callback_file = {
                let mut cbs = self.pending_kad_callbacks.lock().await;
                let now = chrono::Utc::now().timestamp();
                for entries in cbs.values_mut() {
                    entries.retain(|e| now - e.registered_at < PENDING_KAD_CALLBACK_SECS);
                }
                cbs.retain(|_, v| !v.is_empty());

                let mut lookup_keys: Vec<PendingKadCallbackKey> = Vec::new();
                if peer_user_hash != [0u8; 16] {
                    lookup_keys.push(PendingKadCallbackKey::SourceUserHash(peer_user_hash));
                    let swapped = cuint128_swap(&peer_user_hash);
                    if swapped != peer_user_hash {
                        lookup_keys.push(PendingKadCallbackKey::SourceUserHash(swapped));
                    }
                }
                if !peer_v4.is_unspecified() {
                    lookup_keys.push(PendingKadCallbackKey::SourceIp(peer_v4));
                }

                let mut matched: Option<[u8; 16]> = None;
                'outer: for key in lookup_keys {
                    let Some(entries) = cbs.get_mut(&key) else {
                        continue;
                    };
                    let match_idx = if matches!(key, PendingKadCallbackKey::SourceUserHash(_)) {
                        if entries.len() == 1 {
                            Some(0)
                        } else {
                            // One firewalled source can serve several files.
                            // Prefer a matching advertised TCP port when present;
                            // otherwise attach the callback to the most recently
                            // registered request rather than arbitrary Vec[0].
                            let by_port = (peer_hello_port > 0).then(|| {
                                entries
                                    .iter()
                                    .enumerate()
                                    .filter(|(_, entry)| {
                                        entry.expected_tcp_port == 0
                                            || entry.expected_tcp_port == peer_hello_port
                                    })
                                    .max_by_key(|(_, entry)| entry.registered_at)
                                    .map(|(idx, _)| idx)
                            });
                            by_port.flatten().or_else(|| {
                                entries
                                    .iter()
                                    .enumerate()
                                    .max_by_key(|(_, entry)| entry.registered_at)
                                    .map(|(idx, _)| idx)
                            })
                        }
                    } else {
                        entries.iter().position(|e| {
                            peer_hello_port == 0
                                || e.expected_tcp_port == 0
                                || e.expected_tcp_port == peer_hello_port
                        })
                    };
                    if let Some(idx) = match_idx {
                        let entry = entries.remove(idx);
                        if entries.is_empty() {
                            cbs.remove(&key);
                        }
                        matched = Some(entry.file_hash);
                        break 'outer;
                    }
                }

                if matched.is_none() && !cbs.is_empty() {
                    // Diagnostic: an inbound connection arrived while we were
                    // expecting callbacks but it matched none of them. Dump
                    // the peer identity next to the pending keys so we can see
                    // whether a firewalled source actually connected back and
                    // we simply failed to recognise it (hash/port mismatch)
                    // vs. the buddy never relaying at all.
                    let pending_summary: Vec<String> = cbs
                        .keys()
                        .map(|k| match k {
                            PendingKadCallbackKey::SourceIp(ip) => format!("ip={ip}"),
                            PendingKadCallbackKey::SourceUserHash(h) => {
                                format!("uh={}", crate::security::short_hash(h))
                            }
                            PendingKadCallbackKey::FriendEmber(h) => {
                                format!("friend={}", crate::security::short_hash(h))
                            }
                        })
                        .collect();
                    info!(
                        "Inbound conn from {peer_addr} (user={}, hello_port={peer_hello_port}) \
                         did NOT match any of {} pending KAD callback(s): [{}]",
                        crate::security::short_hash(&peer_user_hash),
                        cbs.len(),
                        pending_summary.join(", "),
                    );
                }
                matched
            };
            if let Some(file_hash) = callback_file {
                info!(
                    "Recognized KAD callback connection from {peer_addr} for file {}",
                    hex::encode(file_hash)
                );
                let (dyn_reader, dyn_writer, emule_done): (
                    Box<dyn tokio::io::AsyncRead + Unpin + Send>,
                    Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
                    bool,
                ) = match (reader, writer) {
                    (StreamReader::Plain(r), StreamWriter::Plain(w)) => {
                        (Box::new(r), Box::new(w), false)
                    }
                    (StreamReader::Obfuscated(r), StreamWriter::Obfuscated(w)) => {
                        (Box::new(r), Box::new(w), true)
                    }
                    _ => {
                        warn!("Mismatched reader/writer types for KAD callback");
                        return Ok(());
                    }
                };
                let parts = KadCallbackParts {
                    peer_ip: peer_v4,
                    peer_port: peer_addr.port(),
                    peer_hello_port,
                    peer_user_hash,
                    file_hash,
                    reader: dyn_reader,
                    writer: dyn_writer,
                    emule_info_done: emule_done,
                    peer_caps: hello_caps.clone(),
                    friend_ember_hash: None,
                };
                let _ = self.kad_callback_tx.send(parts).await;
                return Ok(());
            }
        }

        // Check if this is a server callback connection (LowID source connecting
        // back after we sent OP_CALLBACKREQUEST). We match by the TCP port the
        // peer reports in its Hello packet against registered LowID sources for
        // our currently-connected server.
        if let Some(peer_v4) = diversion_ip {
            let peer_hello_port = if hello_data.len() >= 23 {
                u16::from_le_bytes([hello_data[21], hello_data[22]])
            } else {
                0
            };
            {
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
                        (StreamReader::Plain(r), StreamWriter::Plain(w)) => (
                            Box::new(r) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
                            Box::new(w) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
                            false,
                        ),
                        (StreamReader::Obfuscated(r), StreamWriter::Obfuscated(w)) => (
                            Box::new(r) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
                            Box::new(w) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
                            true,
                        ),
                        _ => {
                            warn!("Mismatched reader/writer types for server callback");
                            return Ok(());
                        }
                    };
                    let parts = KadCallbackParts {
                        peer_ip: peer_v4,
                        peer_port: peer_addr.port(),
                        peer_hello_port,
                        peer_user_hash,
                        file_hash,
                        reader: dyn_reader,
                        writer: dyn_writer,
                        emule_info_done: emule_done,
                        peer_caps: hello_caps.clone(),
                        friend_ember_hash: None,
                    };
                    let _ = self.kad_callback_tx.send(parts).await;
                    return Ok(());
                }
            }
        }

        // Path B (eMule queued-source model): if this inbound connection comes
        // from a peer we are currently *queued on* for an active download, it
        // is the uploader connecting back to grant us a slot (a HighID
        // push-grant — eMule reconnects to deep-queued HighID downloaders from
        // `CUploadQueue::AddUpNextClient` rather than waiting for them to
        // re-ask). Divert the freshly-handshaked stream straight into the
        // waiting download via the same adoption channel the KAD/server
        // callbacks use above, instead of treating it as an upload request.
        //
        // Gated strictly on (peer IP [+ user hash when we know it]) matching a
        // source in our `OnQueue` set, so it is a no-op for ordinary
        // downloaders (the index is empty unless a download has queued
        // sources). Done BEFORE recording an upload request for abuse tracking
        // so a legitimate reconnect is never counted against the peer.
        if let Some(peer_v4) = diversion_ip {
            let divert_file: Option<[u8; 16]> = {
                let idx = reconnect_index();
                let guard = idx.read().unwrap_or_else(|e| e.into_inner());
                guard
                    .get(&peer_v4)
                    .and_then(|entries| path_b_divert_file(entries, peer_user_hash))
            };
            if let Some(file_hash) = divert_file {
                info!(
                    "Inbound reconnect from {peer_addr} (user={}) matches a queued source for file {} — diverting to active download (Path B push-grant)",
                    crate::security::short_hash(&peer_user_hash),
                    hex::encode(file_hash),
                );
                crate::network::ed2k::multi_source::note_push_grant_diversion();
                let (dyn_reader, dyn_writer, emule_done): (
                    Box<dyn tokio::io::AsyncRead + Unpin + Send>,
                    Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
                    bool,
                ) = match (reader, writer) {
                    (StreamReader::Plain(r), StreamWriter::Plain(w)) => {
                        (Box::new(r), Box::new(w), false)
                    }
                    (StreamReader::Obfuscated(r), StreamWriter::Obfuscated(w)) => {
                        (Box::new(r), Box::new(w), true)
                    }
                    _ => {
                        warn!("Mismatched reader/writer types for Path B reconnect diversion");
                        return Ok(());
                    }
                };
                // Path-B peers are HighID push-grants, not server-LowID
                // callbacks, so this listening port won't match a LowID row; we
                // still carry it to keep the struct consistently populated.
                let peer_hello_port = if hello_data.len() >= 23 {
                    u16::from_le_bytes([hello_data[21], hello_data[22]])
                } else {
                    0
                };
                let parts = KadCallbackParts {
                    peer_ip: peer_v4,
                    peer_port: peer_addr.port(),
                    peer_hello_port,
                    peer_user_hash,
                    file_hash,
                    reader: dyn_reader,
                    writer: dyn_writer,
                    emule_info_done: emule_done,
                    peer_caps: hello_caps.clone(),
                    friend_ember_hash: None,
                };
                let _ = self.kad_callback_tx.send(parts).await;
                return Ok(());
            }
        }

        // Now that buddy/KAD/server callback connections have been dispatched,
        // count this as a real upload request for abuse tracking. Skipped for
        // outbound callback serves: we dialed this peer, so it never made an
        // inbound request that should count against a rate limit.
        if !outbound {
            let mut tracker = self.abuse_tracker.lock().await;
            let banned = tracker.record_request(peer_addr.ip());
            drop(tracker);
            if banned {
                self.emit_auto_ban(peer_addr.ip(), "excessive upload requests (rate limit)")
                    .await;
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

        // Handle EmuleInfo exchange. Inbound: the peer sends its OP_EMULEINFO
        // here (or skips straight to file requests). Outbound callback serves
        // already completed the EmuleInfo round-trip inside `connect_and_serve`,
        // so we don't read again — `deferred_packet` stays `None` and the main
        // loop reads the peer's first real packet fresh.
        let mut deferred_packet: Option<(u8, u8, Vec<u8>)> = outbound_first_packet.take();
        let mut peer_ember_hash: Option<[u8; 16]> = hello_caps.ember_hash.or(obf_ember_hash);
        let mut peer_secure_ident_level = peer_secure_ident_level;
        if !outbound {
            let (proto2, opcode2, payload2) = read_packet_timeout(&mut reader).await?;
            if proto2 == OP_EMULEPROT && opcode2 == OP_EMULEINFO {
                let incoming_caps = parse_emule_info(&payload2);
                merge_caps(&mut hello_caps, incoming_caps);
                if let Some(peer) = secure_v2_peer {
                    hello_caps.is_ember = true;
                    hello_caps.ember_hash = Some(peer.ember_hash);
                    hello_caps.ember_pubkey = Some(peer.ed25519_public_key);
                }
                peer_ember_hash = hello_caps.ember_hash;
                peer_secure_ident_level = hello_caps.secure_ident_level;
                ul_client_software = client_software_from_caps(&hello_caps);
                if !hello_caps.peer_name.is_empty() {
                    ul_peer_name = hello_caps.peer_name.clone();
                }
                let emule_payload = build_emule_info(
                    self.advertised_udp_port(),
                    self.obfuscation_enabled
                        .load(std::sync::atomic::Ordering::Relaxed),
                    Some(&self.ember_hash),
                    None,
                );
                write_packet_async(
                    &mut writer,
                    OP_EMULEPROT,
                    OP_EMULEINFOANSWER,
                    &emule_payload,
                )
                .await?;
            } else {
                deferred_packet = Some((proto2, opcode2, payload2));
            }
        }

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
        let mut ember_hash_binding_verified = secure_v2_authenticated;
        // Reactive Ember Ed25519 challenge-response state machine.
        // Driven by inbound `OP_EMBER_AUTH_CHALLENGE` /
        // `OP_EMBER_AUTH_RESPONSE` packets dispatched from the
        // reader task; transitions to `Verified` only after we've
        // seen a sig over our random nonce that decodes against the
        // peer's advertised pubkey AND the pubkey BLAKE3-binds to
        // their `ember_hash`. See `super::ember_auth` for the full
        // state diagram and tests.
        let mut ember_auth_state = super::ember_auth::EmberAuthState::default();
        let mut ul_sent_ember_hello = secure_v2_authenticated;
        if !secure_v2_authenticated {
            // Preserve the existing generic eMule byte stream exactly:
            // legacy Ember Hello remains an ignorable extension packet.
            // Its auth challenge/response opcodes are parsed and dropped
            // below, never signed and never consulted for privileges.
            let nickname = self.nickname_snapshot().await;
            let payload =
                build_ember_hello(&self.ember_hash, &nickname, Some(&self.ed25519_public_key));
            if write_packet_async(&mut writer, OP_EMULEPROT, OP_EMBER_HELLO, &payload)
                .await
                .is_ok()
            {
                ul_sent_ember_hello = true;
            }
        }

        // Anti-leech client-software filter. eMule's `AntiLeech.dat`
        // equivalent — match the rendered software label plus the
        // CT_MODVERSION / ET_MOD_VERSION tag against the user's pattern
        // list and close the connection at handshake time if anything
        // matches. Done HERE (after the optional EmuleInfo round-trip)
        // so we have the most complete `mod_version` string possible.
        // The eMule fast path (OP_SECIDENTSTATE instead of OP_EMULEINFO)
        // still leaves `mod_version` empty when the brand lives only in
        // EmuleInfo; the serve loop re-checks when that packet arrives.
        // Closing pre-slot-grant means a leech mod can't briefly claim a
        // slot, can't move bytes, and can't sit in the queue holding rank.
        let leech_haystack = crate::security::antileech::match_haystack(
            &ul_client_software,
            &hello_caps.mod_version,
        );
        let leech_match = self.antileech.read().check(&leech_haystack);
        if let Some(m) = leech_match {
            info!(
                "AntiLeech: rejecting upload session with {peer_addr} — \
                 client software {ul_client_software:?} mod {:?} matched pattern {:?}",
                hello_caps.mod_version, m.pattern,
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
        let mut pending_secident_challenge: Option<u32> =
            super::transfer::maybe_send_secident_challenge(
                &mut writer,
                Some(&self.credit_manager),
                peer_user_hash,
                peer_addr,
                peer_secure_ident_level,
            )
            .await?;

        // Ember Peer Exchange: send our source list to Ember peers.
        // Snapshot the generation we sent so the periodic resend loop
        // below only re-ships when the shared payload has actually been
        // rebuilt with new sources/peers, not on every timer tick.
        info!(
            "Peer {peer_addr}: is_ember={}, mod_version='{}', ember_hash={}, client='{}'",
            hello_caps.is_ember,
            hello_caps.mod_version,
            peer_ember_hash
                .map(hex::encode)
                .unwrap_or_else(|| "none".to_string()),
            ul_client_software
        );
        let mut last_epx_generation: u64 = self
            .ember_payload_generation
            .load(std::sync::atomic::Ordering::Relaxed);
        let mut last_epx_resend = std::time::Instant::now();
        // EPX/mesh identity unlocks after Ember HELLO binding. Friend
        // privileges still require secure_v2. HELLO usually arrives later
        // in the dispatcher; emission happens when binding flips true.
        let mut epx_sent_after_binding = false;
        let mut mesh_discovered_emitted = secure_v2_authenticated;
        if hello_caps.is_ember && secure_v2_authenticated {
            if let std::net::IpAddr::V4(v4) = peer_addr.ip() {
                if hello_caps.tcp_port > 0 && !crate::security::is_bogus_v4(v4) {
                    let _ = self
                        .upload_event_tx
                        .send(UploadEvent {
                            transfer_id: String::new(),
                            kind: UploadEventKind::EmberPeerDiscovered {
                                ip: v4,
                                tcp_port: hello_caps.tcp_port,
                                udp_port: hello_caps.udp_port,
                            },
                        })
                        .await;
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
        // `OP_EMBER_FRIEND_REQ` on this session. Noise-authenticated
        // sessions send immediately below; classic Ember file sockets
        // send after HELLO (or when the user adds the peer mid-session).
        let mut friend_request_sent = false;
        let mut identity_emitted = false;
        if is_friend && !hello_caps.is_ember {
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
        // Set alongside `owns_ember_slot` when we claim the `ember_sessions`
        // slot below. Touched on *every* subsequent inbound packet (including
        // OP_REQUESTPARTS / ordinary eD2K file-serve traffic, not just Ember
        // CHAT/BROWSE/KEEPALIVE) so `EmberSessionHandle::is_fresh()` stays
        // true for as long as this TCP session is actually receiving traffic.
        // Without that, a friend who is only downloading from us would look
        // "stale" after `EMBER_SESSION_FRESH_SECS` and the periodic sweep /
        // SendChatMessage reconnect would `close()` the socket mid-upload.
        let mut ember_session_handle: Option<EmberSessionHandle> = None;
        // Becomes active only after this connection has proven ownership of a
        // friend slot. A caller that retires the slot (for example, cancelling
        // an in-flight browse) wakes the select below so this socket closes
        // immediately instead of waiting for the passive timeout.
        let mut ember_shutdown_rx: Option<tokio::sync::watch::Receiver<bool>> = None;

        if secure_v2_authenticated {
            if let (Some(eh), Some(pk)) = (peer_ember_hash, hello_caps.ember_pubkey) {
                // Register every authenticated v2 connection for immediate
                // revocation, even when another connection already owns the
                // canonical outbound-routing slot.  Chat/browse authorization
                // on this socket does not require owns_ember_slot.
                let handle = EmberSessionHandle::new_secure(outbound_tx.clone(), pk, eh);
                ember_shutdown_rx = Some(handle.subscribe_shutdown());
                ember_session_handle = Some(handle.clone());

                if is_friend {
                    let mut sessions = self.ember_sessions.write().await;
                    match sessions.get(&eh) {
                        Some(existing)
                            if existing.is_fresh()
                                && existing.is_secure_v2()
                                && existing.peer_ember_pubkey() == pk =>
                        {
                            // Keep the existing canonical outbound router;
                            // this inbound remains authorized for chat/browse.
                            owns_ember_slot = false;
                        }
                        Some(stale_or_mismatched) => {
                            stale_or_mismatched.close();
                            sessions.insert(eh, handle);
                            owns_ember_slot = true;
                        }
                        None => {
                            sessions.insert(eh, handle);
                            owns_ember_slot = true;
                        }
                    }
                    drop(sessions);

                    // Prefer the Hello listen port over the ephemeral inbound
                    // socket port so this gets recorded as a dialable
                    // download-source endpoint (see the outbound-side
                    // counterpart in `friend_connect.rs`).
                    let friend_port = if hello_caps.tcp_port > 0 {
                        hello_caps.tcp_port
                    } else {
                        peer_addr.port()
                    };
                    let _ = self
                        .upload_event_tx
                        .send(UploadEvent {
                            transfer_id: String::new(),
                            kind: UploadEventKind::FriendSeen {
                                ember_hash: eh,
                                ip: peer_addr.ip(),
                                port: friend_port,
                            },
                        })
                        .await;
                    let nickname = self.nickname_snapshot().await;
                    if write_packet_async(
                        &mut writer,
                        OP_EMULEPROT,
                        OP_EMBER_FRIEND_REQ,
                        nickname.as_bytes(),
                    )
                    .await
                    .is_ok()
                    {
                        friend_request_sent = true;
                    }
                }
            }
        }

        // Now handle file requests in a loop
        let mut current_file_hash: Option<[u8; 16]> = None;
        let mut uploaded: u64 = 0;
        let mut transfer_id: Option<String> = None;
        let mut total_size: u64 = 0;
        // eMule-style served-parts tally backing the chunked "Up Status"
        // bar: per ED2K part, the number of bytes we've actually
        // delivered to this peer this session. Sized lazily the first
        // time we serve a block (once `total_size` is known).
        // `mark_served_parts` records each delivered range and
        // `build_up_part_status` packs the completed-part bitmap for IPC.
        let mut served_bytes_per_part: Vec<u64> = Vec::new();
        // eMule `m_DoneBlocks_list` / `m_BlockRequests_queue`: exact
        // (start, end) ranges already served this session. Cleared on
        // slot grant, file switch, and session end along with the
        // served-parts tally.
        let mut sent_blocks: HashSet<(u64, u64)> = HashSet::new();
        // eMule `m_abyUpPartStatus`: the parts the downloader told us it
        // already has, captured from the `OP_REQUESTFILENAME` extended-info
        // block and shaded dark on the parts bar. Keyed by file hash so a
        // mid-session file switch (A4AF) can never paint the previous file's
        // possession — at emit time we only use it when the hash still matches
        // `current_file_hash`, otherwise it falls back to no shading.
        let mut peer_part_status: Option<([u8; 16], String)> = None;
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
        let mut slot_guard =
            UploadSlotGuard::new(self.active_count.clone(), self.slot_notify.clone());
        let mut session_start: Option<std::time::Instant> = None;
        let mut rate_tracker = SessionRateTracker::new();
        // (SecureIdent state `pending_secident_challenge` / `pending_peer_challenge`
        // declared above the EmuleInfo exchange block so the proactive
        // challenge there can populate `pending_secident_challenge`.)
        let queue_identity = QueueIdentity::from_peer(peer_user_hash, peer_addr);
        let mut queued_identity: Option<QueueIdentity> = None;
        let mut queue_join_time: std::time::Instant = std::time::Instant::now();
        let mut queue_wait_at_grant: u64 = 0;
        let mut last_rank_sent: Option<u16> = None;
        let mut last_rank_resend = std::time::Instant::now();
        // Deduplicate ShareInterest "request" per file hash on this TCP session.
        let mut recorded_share_request: Option<[u8; 16]> = None;
        let mut last_preempt_check: std::time::Instant = std::time::Instant::now();
        let mut epx_packets_received: u8 = 0;
        let mut last_part_request: std::time::Instant = std::time::Instant::now();
        // Last time this session actually credited bytes, so padding can be
        // told apart from a peer that has stopped taking data — see
        // `requestparts_resets_idle`.
        let mut last_credited_at: std::time::Instant = std::time::Instant::now();

        // HighID AddUpNextClient push-grant: we dialed this peer, so seed the
        // file hash, reserve a slot, and send OP_ACCEPTUPLOADREQ before the
        // packet loop (peer will follow with OP_REQUESTPARTS).
        if let Some(fh) = push_grant_file_hash {
            let dynamic_slots = self.compute_dynamic_slot_count();
            if !slot_guard.try_activate(dynamic_slots) {
                anyhow::bail!("push-grant session {peer_addr}: no free upload slot after dial");
            }
            current_file_hash = Some(fh);
            write_packet_async(&mut writer, OP_EDONKEYHEADER, OP_ACCEPTUPLOADREQ, &[]).await?;
            if let Some(flag) = push_grant_accepted.as_ref() {
                flag.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            // Drop waiting-list entry now that the slot is granted (eMule
            // RemoveFromWaitingQueue before/at AcceptUploadReq). A different
            // IP still bound to this identity keeps its row; a same-IP
            // advertised-port mismatch is this peer's NAT rebind.
            {
                let mut queue = self.upload_queue.lock().await;
                queue.retain(|e| {
                    keep_queue_row_after_slot_grant(&queue_identity, peer_addr.ip(), e)
                });
            }
            self.record_share_accepted(&fh).await;
            queue_wait_at_grant = 0;
            session_start = Some(std::time::Instant::now());
            last_part_request = std::time::Instant::now();
            let tid = uuid::Uuid::new_v4().to_string();
            transfer_id = Some(tid.clone());
            if let Some(resolved) = self
                .resolve_upload_file(
                    &fh,
                    PeerFileAccess {
                        ember_hash: peer_ember_hash,
                        secure_v2_authenticated,
                    },
                )
                .await
            {
                total_size = resolved.size;
                let _ = self
                    .upload_event_tx
                    .send(UploadEvent {
                        transfer_id: tid,
                        kind: UploadEventKind::Started {
                            file_name: resolved.name,
                            file_hash: hex::encode(fh),
                            total_size: resolved.size,
                            peer_addr: peer_addr.to_string(),
                            peer_name: ul_peer_name.clone(),
                            client_software: ul_client_software.clone(),
                            country_code: ul_country_code.clone(),
                            user_hash: if peer_user_hash != [0u8; 16] {
                                Some(hex::encode(peer_user_hash))
                            } else {
                                None
                            },
                            wait_seconds: 0,
                            ember_hash: peer_ember_hash.map(hex::encode),
                        },
                    })
                    .await;
            }
            info!(
                "AddUpNextClient: push-grant session ready for {peer_addr} file {}",
                hex::encode(fh)
            );
        }

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
        let mut cached_part_tracker: Option<(
            PathBuf,
            super::part_tracker::PartTracker,
            std::time::Instant,
        )> = None;
        let mut cached_is_video_ext: Option<(PathBuf, bool)> = None;
        // Keep the disk-backed cache short-lived so a just-verified part can
        // be seeded promptly. The unchanged is_range_safe_to_serve gate below
        // still requires both completeness and MD4 verification.
        const PART_TRACKER_REFRESH: std::time::Duration = std::time::Duration::from_millis(500);
        // One-shot INFO log per session the first time we serve verified bytes
        // out of a `.part` file (eMule-style partial-file sharing). Makes it
        // observable that we're seeding a file we're still downloading, without
        // spamming a line per block.
        let mut logged_partial_seed = false;

        // Dedicated reader task: ed2k framing requires four sequential awaits
        // (proto, length, opcode, payload). The main loop uses tokio::select!
        // to race the next packet against outbound writes, and select! cancels
        // the losing future. If it cancelled read_packet_async_inner mid-packet
        // we'd resume on the next iteration with the stream positioned in the
        // middle of a frame, causing desync and connection loss. Moving the
        // read into its own task keeps frame state private; the select! site
        // consumes whole packets from a channel and is trivially cancel-safe.
        let (pkt_tx, mut pkt_rx) =
            tokio::sync::mpsc::channel::<std::io::Result<(u8, u8, Vec<u8>)>>(4);
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
            if let Some(eh) = peer_ember_hash {
                let live_member = self.friend_hashes.read().await.contains(&eh);
                if is_friend && !live_member {
                    is_friend = false;
                    is_ember_friend = false;
                    if secure_v2_authenticated {
                        // Membership is the live authorization source.  Do not
                        // let a session-local flag or queued priority snapshot
                        // survive friend removal.
                        info!("Friend {} removed; closing secure v2 stream", hex::encode(eh));
                        break;
                    }
                }
                if !is_friend && live_member {
                    // Add Friend from the uploads pane (or Friends page) can
                    // land while this downloader's socket is still open.
                    // Promote membership, then ship `OP_EMBER_FRIEND_REQ` on
                    // this live connection — FindFriendAndConnect cannot
                    // carry the request when the peer is firewalled, and
                    // classic Ember file sockets are not in `ember_sessions`
                    // until they are already friends.
                    is_friend = true;
                    is_ember_friend = hello_caps.is_ember;
                    if secure_v2_authenticated && !owns_ember_slot {
                        if let Some(handle) = ember_session_handle.as_ref().cloned() {
                            let mut sessions = self.ember_sessions.write().await;
                            match sessions.get(&eh) {
                                Some(existing)
                                    if existing.is_fresh()
                                        && existing.is_secure_v2()
                                        && existing.peer_ember_pubkey()
                                            == handle.peer_ember_pubkey() =>
                                {
                                    owns_ember_slot = false;
                                }
                                Some(other) => {
                                    other.close();
                                    sessions.insert(eh, handle);
                                    owns_ember_slot = true;
                                }
                                None => {
                                    sessions.insert(eh, handle);
                                    owns_ember_slot = true;
                                }
                            }
                        }
                    }
                    if hello_caps.is_ember && !friend_request_sent {
                        info!(
                            "Sending friend request to Ember peer {peer_addr} (mid-session add)"
                        );
                        let nickname = self.nickname_snapshot().await;
                        if write_packet_async(
                            &mut writer,
                            OP_EMULEPROT,
                            OP_EMBER_FRIEND_REQ,
                            nickname.as_bytes(),
                        )
                        .await
                        .is_ok()
                        {
                            friend_request_sent = true;
                        }
                    }
                }
            }
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

            // Peer banned mid-session. The accept-loop / post-Hello ban
            // checks run only once, so without re-checking here a peer
            // banned while actively downloading would keep its upload until
            // completion. Breaking here closes the connection and runs the
            // normal cleanup at function exit (slot release, queue removal,
            // terminal transfer event).
            if self.peer_is_banned(&peer_user_hash, &peer_addr) {
                info!("Terminating upload session with {peer_addr}: peer banned");
                // Capture this live session's IP into the ban list. A peer
                // banned by user-hash while actively downloading may have an
                // IP that wasn't in the routing table or peer DB at ban time
                // (so `BanPeer` never learned it) — the hash check above is
                // then the *only* thing that caught them, and a reconnect
                // from the same IP would sail through the cheap accept-loop
                // IP gate. Route the IP through the same canonical + durable
                // path as the auto-ban (PeerAutoBanned -> apply_persistent_
                // ip_ban) so the UDP / download / accept-loop paths cover it
                // too and it survives a restart. Emit at most once (we break
                // immediately after, and only when the IP isn't already set).
                let peer_v4 = match peer_addr.ip() {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
                };
                if let Some(peer_v4) = peer_v4 {
                    let already = self
                        .banned_ips
                        .read()
                        .map(|s| s.contains(&peer_v4))
                        .unwrap_or(true);
                    if !already {
                        if let Ok(mut banned) = self.banned_ips.write() {
                            banned.insert(peer_v4);
                        }
                        let _ = self
                            .upload_event_tx
                            .send(UploadEvent {
                                transfer_id: String::new(),
                                kind: UploadEventKind::PeerAutoBanned {
                                    ip: peer_v4,
                                    reason: "manual peer ban (captured from live upload session)"
                                        .to_string(),
                                    // Associate with the banned peer so a later
                                    // unban_peer (which walks the peer's known
                                    // addresses) also clears this captured IP.
                                    user_hash: (peer_user_hash != [0u8; 16])
                                        .then_some(peer_user_hash),
                                },
                            })
                            .await;
                    }
                }
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
            // been rebuilt since we last sent. Gated on HELLO binding.
            if hello_caps.is_ember
                && ember_hash_binding_verified
                && last_epx_resend.elapsed() >= EPX_RESEND_INTERVAL
            {
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
                            &epx_data,
                        )
                        .await
                        .is_ok()
                        {
                            last_epx_generation = current_gen;
                            self.epx_overhead.record_upload((6 + epx_data.len()) as u64);
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
                    _ = async {
                        match ember_shutdown_rx.as_mut() {
                            Some(rx) => {
                                if !*rx.borrow() {
                                    let _ = rx.changed().await;
                                }
                            }
                            None => std::future::pending::<()>().await,
                        }
                    } => {
                        info!("Closing retired Ember friend session from {peer_addr}");
                        break;
                    }
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
                            let still_ours = {
                                let queue = self.upload_queue.lock().await;
                                queue.iter().any(|e| {
                                    e.identity == *queued_key
                                        && queue_row_owned_by_session(
                                            e.current_addr,
                                            e.tcp_port,
                                            peer_addr,
                                            hello_caps.tcp_port,
                                        )
                                })
                            };
                            if !still_ours {
                                queued_identity = None;
                                let _ = write_packet_async(
                                    &mut writer,
                                    OP_EMULEPROT,
                                    OP_QUEUEFULL,
                                    &[],
                                )
                                .await;
                                break;
                            }
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
                                let mut best_identity = None;
                                let mut best_join: Option<std::time::Instant> = None;
                                let mut best_score = f64::MIN;
                                for &(_i, ref identity, current_addr, join_time, file_hash, ref user_hash, emule_version, is_friend_slot, ref ember_pubkey, ember_verified) in &queue_snapshot {
                                    if current_addr.is_none() {
                                        continue;
                                    }
                                    let score = score_queue_entry(
                                        &cm, &idx_snap, user_hash, file_hash,
                                        join_time.elapsed().as_secs(), current_addr,
                                        emule_version, is_friend_slot,
                                        ember_pubkey.as_ref(), ember_verified,
                                    );
                                    // Tie-break by earlier join_time to agree with
                                    // compute_queue_rank's FIFO tie ordering.
                                    if score > best_score
                                        || (score == best_score && best_join.is_none_or(|bj| join_time < bj))
                                    {
                                        best_score = score;
                                        best_identity = Some(identity.clone());
                                        best_join = Some(join_time);
                                    }
                                }
                                drop(idx_snap);
                                drop(cm);

                                if best_identity.is_some() {
                                    // Reserve the slot atomically BEFORE removing the
                                    // queue entry or sending OP_ACCEPTUPLOADREQ. The
                                    // `current_active < dynamic_slots` check above is
                                    // separated from the grant by `.await` points, so a
                                    // concurrent connection could have taken the slot.
                                    // `try_activate` only runs when we are the winner
                                    // (short-circuit) and only commits if a slot is free;
                                    // on a lost race we keep the queue entry and retry on
                                    // the next poll instead of over-granting.
                                    if best_identity.as_ref() == Some(queued_key)
                                        && slot_guard.try_activate(dynamic_slots)
                                    {
                                        let mut queue = self.upload_queue.lock().await;
                                        // Remove by IDENTITY, not the snapshot index:
                                        // other connections may have purged/removed
                                        // entries since the snapshot, shifting indices.
                                        // An index-only removal could leave this peer's
                                        // entry as a ghost (slot granted, still queued)
                                        // or remove the wrong peer. Ownership is
                                        // re-checked here: a NAT rebind may have
                                        // rebound the row since the snapshot.
                                        let owned_pos = queue.iter().position(|e| {
                                            e.identity == *queued_key
                                                && queue_row_owned_by_session(
                                                    e.current_addr,
                                                    e.tcp_port,
                                                    peer_addr,
                                                    hello_caps.tcp_port,
                                                )
                                        });
                                        match owned_pos {
                                            Some(pos) => {
                                                queue.remove(pos);
                                            }
                                            None => {
                                                drop(queue);
                                                slot_guard.deactivate();
                                                queued_identity = None;
                                                let _ = write_packet_async(
                                                    &mut writer,
                                                    OP_EMULEPROT,
                                                    OP_QUEUEFULL,
                                                    &[],
                                                )
                                                .await;
                                                break;
                                            }
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

                                        // Slot already reserved atomically above.
                                        queued_identity = None;
                                        uploaded = 0;
                                        served_bytes_per_part.clear();
                                        sent_blocks.clear();
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
                                            // Resolve the name through `resolve_upload_file` rather
                                            // than the shared index alone: files we serve from an
                                            // in-progress download live as a `.part` under Temp and
                                            // are NOT in the shared index, so an index-only lookup
                                            // returned None and the Uploading list showed a blank
                                            // File column for partial-file seeds.
                                            let file_name = self
                                                .resolve_upload_file(&hash, PeerFileAccess { ember_hash: peer_ember_hash, secure_v2_authenticated })
                                                .await
                                                .map(|rf| rf.name);

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
                                                        wait_seconds: queue_wait_at_grant,
                                                        ember_hash: peer_ember_hash.map(hex::encode),
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
                                let is_verified_friend = live_secure_friend_member(
                                    &self.friend_hashes,
                                    peer_ember_hash,
                                    secure_v2_authenticated,
                                )
                                .await;
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
                                let ember_verified = secure_v2_authenticated;
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

            // Refresh friend-session liveness on any inbound packet while we
            // own the Ember slot. File-serve traffic (OP_REQUESTPARTS, etc.)
            // is the common case for a friend who is downloading from us and
            // must keep the handle fresh — see the `ember_session_handle`
            // comment above.
            if let Some(h) = &ember_session_handle {
                h.touch();
            }

            match (proto, opcode) {
                (OP_EMULEPROT, OP_PUBLICKEY) if payload.len() >= 2 => {
                    let key_len = payload[0] as usize;
                    if key_len > 0 && payload.len() > key_len {
                        let mut cm = self.credit_manager.write().await;
                        // Only move the identity forward if the key was
                        // actually bound. A refused key must not reset a
                        // verified peer's state to `Needed` — that alone
                        // would let a stranger knock an established identity
                        // out of `Verified` on demand.
                        let key_bound = cm
                            .set_public_key(peer_user_hash, payload[1..1 + key_len].to_vec());
                        if key_bound {
                            cm.set_ident_state(peer_user_hash, super::credits::IdentState::Needed);
                        }
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
                        // Mid-slot file switch: a peer that already holds an active
                        // transfer (transfer_id is Some) just asked us to serve a
                        // *different* file. The progress/UI row is keyed by the old
                        // transfer_id and file, so reporting the new file's bytes
                        // under that row mislabels it (wrong name/size) and, on
                        // session end, snaps the stale row to the OLD file's full
                        // size. Finalize the old row now; the next serve mints a
                        // fresh transfer_id for the new file. (Same-file re-queries
                        // and handshake-time SETREQFILEID — when transfer_id is None
                        // — are unaffected.)
                        if let Some(prev) = current_file_hash {
                            if prev != hash {
                                if let Some(tid) = transfer_id.take() {
                                    let kind = if uploaded > 0 {
                                        upload_session_completed(
                                            unique_served_bytes(&served_bytes_per_part, total_size),
                                            total_size,
                                        )
                                    } else {
                                        UploadEventKind::Failed {
                                            error: "Peer switched files before any data was sent".to_string(),
                                        }
                                    };
                                    let _ = self.upload_event_tx.send(UploadEvent {
                                        transfer_id: tid,
                                        kind,
                                    }).await;
                                }
                                // Coverage is per-file. Clear even when no UI row
                                // existed yet — otherwise a later REQUESTPARTS for
                                // the new hash reuses the old file's sent_blocks.
                                uploaded = 0;
                                served_bytes_per_part.clear();
                                sent_blocks.clear();
                                cached_part_tracker = None;
                            }
                        }
                        current_file_hash = Some(hash);
                        self.sync_queue_file_hash(
                            &queue_identity,
                            hash,
                            peer_addr,
                            hello_caps.tcp_port,
                        )
                        .await;

                        if let Some(file) = self.resolve_upload_file(&hash, PeerFileAccess { ember_hash: peer_ember_hash, secure_v2_authenticated }).await {
                            self.record_share_request_once(&hash, &mut recorded_share_request)
                                .await;
                            let Some(ed2k_part_count) = ed2k_wire_part_count_u16(file.size) else {
                                warn!(
                                    "Refusing OP_FILESTATUS for {}: file exceeds standard ED2K wire part-count limit",
                                    file.name
                                );
                                continue;
                            };
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
                                let file_size = file.size;
                                let part_path = file.path.clone();
                                let fallback_path = part_path.clone();
                                let tracker = tokio::task::spawn_blocking(move || {
                                    super::part_tracker::PartTracker::new(file_size, &part_path)
                                })
                                .await
                                .unwrap_or_else(|e| {
                                    tracing::warn!(
                                        "PartTracker load task failed for OP_FILESTATUS bitmap: {e}"
                                    );
                                    super::part_tracker::PartTracker::new_empty(
                                        file_size,
                                        &fallback_path,
                                    )
                                });
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
                                let banned = tracker.record_file_not_found(peer_addr.ip());
                                drop(tracker);
                                if banned {
                                    self.emit_auto_ban(peer_addr.ip(), "excessive file-not-found requests (hash probing)").await;
                                }
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
                        if let Some(file) = self.resolve_upload_file(&hash, PeerFileAccess { ember_hash: peer_ember_hash, secure_v2_authenticated }).await {
                            // eMule ProcessExtendedInfo: bytes after the 16-byte
                            // hash carry the downloader's advertised part status
                            // (ExtendedRequests v1+ — partcount u16 + bitmap).
                            // Capture it for the dark "peer already has" shading;
                            // a non-extended request is exactly 16 bytes so the
                            // length check naturally gates v0 peers out.
                            if payload.len() >= 18 {
                                let ext = &payload[16..];
                                let advertised = u16::from_le_bytes([ext[0], ext[1]]);
                                if let Some(hex) =
                                    peer_part_status_hex(advertised, &ext[2..], file.size)
                                {
                                    peer_part_status = Some((hash, hex));
                                }
                            }
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
                                let banned = tracker.record_file_not_found(peer_addr.ip());
                                drop(tracker);
                                if banned {
                                    self.emit_auto_ban(peer_addr.ip(), "excessive file-not-found requests (hash probing)").await;
                                }
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

                    // Turn a friends-only request away at the door rather than
                    // letting it wait for a slot it can never be granted.
                    // Answering QUEUEFULL reuses the refusal the soft-limit
                    // path already sends, so the peer backs off and looks
                    // elsewhere without learning why.
                    if let Some(h) = current_file_hash {
                        if self
                            .friends_only_and_barred(
                                &h,
                                PeerFileAccess {
                                    ember_hash: peer_ember_hash,
                                    secure_v2_authenticated,
                                },
                            )
                            .await
                        {
                            debug!(
                                "Refusing queue admission for friends-only file {} from {peer_addr}",
                                hex::encode(h)
                            );
                            write_packet_async(&mut writer, OP_EMULEPROT, OP_QUEUEFULL, &[])
                                .await?;
                            break;
                        }
                    }

                    // Duplicate OP_STARTUPLOADREQ on an already-granted session.
                    // eMule/Ember peers occasionally re-send STARTUPLOADREQ after
                    // they've already received OP_ACCEPTUPLOADREQ — e.g. in
                    // response to an unexpected QUEUERANKING, or as a soft
                    // retry during an early handshake race. The handler below
                    // reserves a slot, resets
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
                        if self.resolve_upload_file(&h, PeerFileAccess { ember_hash: peer_ember_hash, secure_v2_authenticated }).await.is_some() {
                            self.record_share_request_once(&h, &mut recorded_share_request)
                                .await;
                        }
                    }

                    // eMule AddRequestCount: check per-file request frequency before admitting
                    if let Some(h) = current_file_hash {
                        let peer_v4 = match peer_addr.ip() {
                            std::net::IpAddr::V4(v4) => Some(v4),
                            std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
                        };
                        if let Some(peer_v4) = peer_v4 {
                            let should_ban = {
                                let mut tracker = self.file_request_tracker.lock().await;
                                tracker.cleanup_stale();
                                tracker.record_request(peer_v4, h)
                            };
                            if should_ban {
                                warn!("Banning {} for excessive file request frequency (AddRequestCount)", peer_addr);
                                // Immediate local effect for the shared upload set so
                                // any in-flight connection from this IP is rejected
                                // right away...
                                if let Ok(mut banned) = self.banned_ips.write() {
                                    banned.insert(peer_v4);
                                }
                                // ...and route it to the network task so it becomes
                                // canonical (state.banned_ips, UDP + download
                                // enforcement) and gets persisted. Without this the
                                // direct write above is dropped by the next
                                // `*shared = state.banned_ips.clone()` resync.
                                let _ = self.upload_event_tx.send(UploadEvent {
                                    transfer_id: String::new(),
                                    kind: UploadEventKind::PeerAutoBanned {
                                        ip: peer_v4,
                                        reason: "excessive file request frequency (AddRequestCount)".to_string(),
                                        user_hash: None,
                                    },
                                }).await;
                                write_packet_async(&mut writer, OP_EMULEPROT, OP_QUEUEFULL, &[]).await?;
                                break;
                            }
                        }
                    }

                    let current_active = self
                        .active_count
                        .load(std::sync::atomic::Ordering::Relaxed);

                    let dynamic_slots = self.compute_dynamic_slot_count();
                    let mut removed_queue_entry: Option<QueueEntry> = None;
                    let should_accept = if current_active >= dynamic_slots {
                        false
                    } else {
                        // Snapshot queue, purging stale entries first, then release lock
                        let (queue_empty, queue_snapshot) = {
                            let mut queue = self.upload_queue.lock().await;
                            queue.retain(|e| e.join_time.elapsed().as_secs() < MAX_PURGEQUEUETIME_SECS);
                            let empty = queue.is_empty();
                            let snap: Vec<_> = queue
                                .iter()
                                .enumerate()
                                .map(|(i, e)| {
                                    (
                                        i,
                                        e.identity.clone(),
                                        e.current_addr,
                                        e.join_time,
                                        e.file_hash,
                                        e.user_hash,
                                        e.emule_version,
                                        e.is_friend_slot,
                                        e.add_next_connect,
                                        e.ember_pubkey,
                                        e.ember_verified,
                                        e.is_high_id,
                                        e.tcp_port,
                                        e.last_ip,
                                    )
                                })
                                .collect();
                            (empty, snap)
                        };
                        if queue_empty {
                            true
                        } else if queue_snapshot.iter().any(|t| t.1 == queue_identity && t.8) {
                            // eMule m_bAddNextConnect: this reconnecting peer was flagged
                            // (it would have won while disconnected), so grant it the next
                            // slot ahead of normal scoring and drop its queue entry. The
                            // shared `slot_guard.try_activate` below still gates on a free
                            // slot, so this cannot over-grant. A live waiter bound to a
                            // different socket still owns the row — don't let a hash
                            // replay collect the flag and delete them.
                            let mut queue = self.upload_queue.lock().await;
                            if let Some(pos) = queue.iter().position(|e| e.identity == queue_identity)
                            {
                                if queue_row_owned_by_session(
                                    queue[pos].current_addr,
                                    queue[pos].tcp_port,
                                    peer_addr,
                                    hello_caps.tcp_port,
                                ) {
                                    let removed = queue.remove(pos);
                                    removed_queue_entry = Some(removed);
                                    true
                                } else {
                                    false
                                }
                            } else {
                                true
                            }
                        } else {
                            let cm = self.credit_manager.read().await;
                            let idx_snap = self.local_index.read().await;
                            // eMule FindBestClientInQueue: connected peers OR dialable
                            // HighIDs compete for the slot; disconnected LowIDs only
                            // get m_bAddNextConnect.
                            let mut best_ready_identity: Option<QueueIdentity> = None;
                            let mut best_ready_join: Option<std::time::Instant> = None;
                            let mut best_ready_score = f64::MIN;
                            let mut best_ready_needs_dial = false;
                            let mut best_low_identity: Option<QueueIdentity> = None;
                            let mut best_low_score = f64::MIN;
                            for &(
                                _i,
                                ref identity,
                                current_addr,
                                join_time,
                                file_hash,
                                ref user_hash,
                                emule_version,
                                is_friend_slot,
                                add_next_connect,
                                ref ember_pubkey,
                                ember_verified,
                                is_high_id,
                                tcp_port,
                                last_ip,
                            ) in &queue_snapshot
                            {
                                let score = score_queue_entry(
                                    &cm,
                                    &idx_snap,
                                    user_hash,
                                    file_hash,
                                    join_time.elapsed().as_secs(),
                                    current_addr,
                                    emule_version,
                                    is_friend_slot,
                                    ember_pubkey.as_ref(),
                                    ember_verified,
                                );
                                let connected = current_addr.is_some();
                                let dialable = !connected
                                    && is_high_id
                                    && tcp_port > 0
                                    && last_ip.is_some();
                                if connected || dialable {
                                    if score > best_ready_score
                                        || (score == best_ready_score
                                            && best_ready_join.is_none_or(|bj| join_time < bj))
                                    {
                                        best_ready_score = score;
                                        best_ready_identity = Some(identity.clone());
                                        best_ready_join = Some(join_time);
                                        best_ready_needs_dial = dialable;
                                    }
                                } else if !add_next_connect && score > best_low_score {
                                    best_low_score = score;
                                    best_low_identity = Some(identity.clone());
                                }
                            }
                            if let Some(low_id) = best_low_identity {
                                if best_low_score > best_ready_score {
                                    let mut queue = self.upload_queue.lock().await;
                                    if let Some(e) = queue.iter_mut().find(|e| e.identity == low_id)
                                    {
                                        e.add_next_connect = true;
                                    }
                                }
                            }
                            drop(idx_snap);
                            drop(cm);
                            // Grant iff THIS peer is the best ready *connected* peer.
                            // A disconnected HighID that outscores everyone is left for
                            // the proactive AddUpNextClient dial (slot opener), matching
                            // eMule FindBestClient → TryToConnect rather than granting
                            // a lower-scoring connected peer.
                            match best_ready_identity {
                                Some(bi) if bi == queue_identity && !best_ready_needs_dial => {
                                    let mut queue = self.upload_queue.lock().await;
                                    if let Some(pos) =
                                        queue.iter().position(|e| e.identity == queue_identity)
                                    {
                                        if queue_row_owned_by_session(
                                            queue[pos].current_addr,
                                            queue[pos].tcp_port,
                                            peer_addr,
                                            hello_caps.tcp_port,
                                        ) {
                                            let removed = queue.remove(pos);
                                            removed_queue_entry = Some(removed);
                                            true
                                        } else {
                                            false
                                        }
                                    } else {
                                        true
                                    }
                                }
                                Some(_) => false,
                                None => true,
                            }
                        }
                    };

                    // Atomically reserve the slot to close the check-then-activate
                    // race: the slot-count check and the queue scoring above both
                    // contain `.await` points, so a concurrent connection could
                    // have taken the last slot in between. `try_activate` only
                    // succeeds while we are still under `dynamic_slots`; on a lost
                    // race we fall through to the queue path (which re-inserts the
                    // entry that the `should_accept` scoring may have removed).
                    let should_accept = should_accept && slot_guard.try_activate(dynamic_slots);
                    if let Some(removed) = removed_queue_entry {
                        queue_join_time = removed.join_time;
                        if !should_accept {
                            let mut queue = self.upload_queue.lock().await;
                            if !queue.iter().any(|entry| entry.identity == removed.identity) {
                                queue.push(removed);
                            }
                        }
                    }

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
                        let is_verified_friend = live_secure_friend_member(
                            &self.friend_hashes,
                            peer_ember_hash,
                            secure_v2_authenticated,
                        )
                        .await;
                        // Global scoring lock order: credit manager → local
                        // index → upload queue. Every scoring path follows this
                        // order so concurrent rank/admission work cannot form an
                        // AB-BA deadlock.
                        let cm = self.credit_manager.read().await;
                        let idx_snap = self.local_index.read().await;
                        let mut queue = self.upload_queue.lock().await;
                        let rank = if let Some(pos) =
                            queue.iter().position(|e| e.identity == queue_identity)
                        {
                            // `queue_identity` is keyed on the peer's bare,
                            // wire-visible `user_hash` (unauthenticated —
                            // no cryptographic binding). If the row is
                            // already bound to a different IP or advertised
                            // TCP port, refuse the reclaim: overwriting
                            // `current_addr` would zero the victim's
                            // promotion score until they re-ask, and
                            // resetting session flags would strip
                            // friend-slot / Ember verification from the
                            // live waiter. Same IP + Hello-advertised port
                            // is the same client (eMule GetUserPort) and
                            // takes the row over. Preserve `join_time`
                            // (seniority) only for a genuine reconnect,
                            // when `current_addr` is `None`.
                            let bound_addr = queue[pos].current_addr;
                            if !queue_row_owned_by_session(
                                bound_addr,
                                queue[pos].tcp_port,
                                peer_addr,
                                hello_caps.tcp_port,
                            ) {
                                drop(queue);
                                drop(idx_snap);
                                drop(cm);
                                write_packet_async(&mut writer, OP_EMULEPROT, OP_QUEUEFULL, &[])
                                    .await?;
                                break;
                            }
                            let same_session = bound_addr == Some(peer_addr);
                            if !same_session {
                                queue[pos].is_friend_slot = false;
                                queue[pos].ember_verified = false;
                            }
                            queue[pos].current_addr = Some(peer_addr);
                            queue[pos].last_ip = Some(peer_addr.ip());
                            queue[pos].udp_port = hello_caps.udp_port;
                            queue[pos].tcp_port = hello_caps.tcp_port;
                            queue[pos].crypt_options = hello_caps.crypt_options_byte();
                            queue[pos].is_high_id =
                                peer_is_high_id_for_queue(&hello_caps, peer_addr);
                            queue[pos].user_hash = peer_user_hash;
                            queue[pos].file_hash = current_file_hash.unwrap_or([0u8; 16]);
                            // If the peer has since completed PoP, upgrade
                            // an existing queue entry's friend-slot flag
                            // (it may have been added while auth was still
                            // pending). Never downgrade within the same
                            // session: if the entry is already marked
                            // is_friend_slot from a prior verified state on
                            // the same session, leave it — but a session
                            // change already reset it to `false` above, so
                            // this can only re-arm from this session's own
                            // live verification state.
                            if is_verified_friend {
                                queue[pos].is_friend_slot = true;
                            }
                            let ember_verified = secure_v2_authenticated;
                            queue[pos].ember_verified |= ember_verified;
                            if !same_session {
                                queue[pos].ember_pubkey = hello_caps.ember_pubkey;
                            } else if queue[pos].ember_pubkey.is_none() {
                                queue[pos].ember_pubkey = hello_caps.ember_pubkey;
                            }
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
                            rank_val
                        } else if queue
                            .iter()
                            .filter(|e| {
                                e.identity != queue_identity
                                    && e.last_ip == Some(peer_addr.ip())
                            })
                            .count()
                            >= MAX_QUEUE_ENTRIES_PER_IP
                        {
                            // eMule cSameIP cap (CUploadQueue::AddClientToQueue):
                            // never let one IP occupy more than a few
                            // waiting-list slots. `current_addr` is cleared on
                            // disconnect but `last_ip` is not, so this also
                            // bounds a peer that churns connections with
                            // rotating user-hashes to pile up lingering entries
                            // — which the concurrent MAX_CONNECTIONS_PER_IP cap
                            // alone does not prevent.
                            debug!(
                                "Per-IP upload-queue cap reached for {} (>= {} entries), rejecting {peer_addr}",
                                peer_addr.ip(),
                                MAX_QUEUE_ENTRIES_PER_IP,
                            );
                            drop(queue);
                            drop(idx_snap);
                            drop(cm);
                            write_packet_async(&mut writer, OP_EMULEPROT, OP_QUEUEFULL, &[]).await?;
                            break;
                        } else if queue.len() >= HARD_UPLOAD_QUEUE_SIZE {
                            debug!("Upload queue at hard limit ({HARD_UPLOAD_QUEUE_SIZE}), sending OP_QUEUEFULL to {peer_addr}");
                            drop(queue);
                            drop(idx_snap);
                            drop(cm);
                            write_packet_async(&mut writer, OP_EMULEPROT, OP_QUEUEFULL, &[]).await?;
                            break;
                        } else if queue.len() >= MAX_UPLOAD_QUEUE_SIZE {
                            // eMule soft→hard zone: admit when CombinedFilePrioAndCredit
                            // is at/above the queue average (wait-independent), or the
                            // peer holds a verified friend slot. Scoring newcomers with
                            // wait=0 made almost everyone get OP_QUEUEFULL.
                            let new_fh = current_file_hash.unwrap_or([0u8; 16]);
                            let ember_verified = secure_v2_authenticated;
                            let peer_ip = peer_ip_u32(Some(peer_addr));
                            let new_combined = combined_file_prio_and_credit(
                                &cm,
                                &idx_snap,
                                &peer_user_hash,
                                new_fh,
                                peer_ip,
                                hello_caps.ember_pubkey.as_ref(),
                                ember_verified,
                            );
                            let avg_combined = if queue.is_empty() {
                                0.0
                            } else {
                                let total: f64 = queue
                                    .iter()
                                    .map(|e| {
                                        combined_file_prio_and_credit(
                                            &cm,
                                            &idx_snap,
                                            &e.user_hash,
                                            e.file_hash,
                                            peer_ip_u32(e.current_addr.or_else(|| {
                                                e.last_ip.map(|ip| SocketAddr::new(ip, 0))
                                            })),
                                            e.ember_pubkey.as_ref(),
                                            e.ember_verified,
                                        )
                                    })
                                    .sum();
                                total / queue.len() as f64
                            };
                            if soft_zone_should_admit(is_verified_friend, new_combined, avg_combined)
                            {
                                let join_time = queue_join_time;
                                let new_score = score_queue_entry(
                                    &cm,
                                    &idx_snap,
                                    &peer_user_hash,
                                    new_fh,
                                    0,
                                    Some(peer_addr),
                                    hello_caps.emule_version_min,
                                    is_verified_friend,
                                    hello_caps.ember_pubkey.as_ref(),
                                    ember_verified,
                                );
                                let mut rank_val: u16 = 1;
                                for e in queue.iter() {
                                    if e.identity == queue_identity {
                                        continue;
                                    }
                                    let es = score_queue_entry(
                                        &cm,
                                        &idx_snap,
                                        &e.user_hash,
                                        e.file_hash,
                                        e.join_time.elapsed().as_secs(),
                                        e.current_addr,
                                        e.emule_version,
                                        e.is_friend_slot,
                                        e.ember_pubkey.as_ref(),
                                        e.ember_verified,
                                    );
                                    if es > new_score
                                        || (es == new_score && e.join_time < join_time)
                                    {
                                        rank_val = rank_val.saturating_add(1);
                                    }
                                }
                                queue.push(queue_entry_from_hello(
                                    queue_identity.clone(),
                                    peer_addr,
                                    peer_user_hash,
                                    new_fh,
                                    join_time,
                                    &hello_caps,
                                    is_verified_friend,
                                    ember_verified,
                                ));
                                rank_val
                            } else {
                                debug!(
                                    "Upload queue in soft-hard zone, peer combined {new_combined:.1} below avg {avg_combined:.1}, rejecting {peer_addr}"
                                );
                                drop(queue);
                                drop(idx_snap);
                                drop(cm);
                                write_packet_async(&mut writer, OP_EMULEPROT, OP_QUEUEFULL, &[])
                                    .await?;
                                break;
                            }
                        } else {
                            let new_fh = current_file_hash.unwrap_or([0u8; 16]);
                            let join_time = queue_join_time;
                            let ember_verified = secure_v2_authenticated;
                            queue.push(queue_entry_from_hello(
                                queue_identity.clone(),
                                peer_addr,
                                peer_user_hash,
                                new_fh,
                                join_time,
                                &hello_caps,
                                is_verified_friend,
                                ember_verified,
                            ));
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
                            rank_val
                        };
                        drop(queue);
                        drop(idx_snap);
                        drop(cm);
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

                    // Slot already reserved atomically via `try_activate` above.
                    queued_identity = None;
                    uploaded = 0;
                    served_bytes_per_part.clear();
                    sent_blocks.clear();
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
                        // Resolve via `resolve_upload_file` (not the shared index alone) so
                        // files served from an in-progress download (a `.part` under Temp,
                        // absent from the shared index) report their name instead of a blank
                        // File column in the Uploading list.
                        let file_name = self
                            .resolve_upload_file(&hash, PeerFileAccess { ember_hash: peer_ember_hash, secure_v2_authenticated })
                            .await
                            .map(|rf| rf.name);

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
                                wait_seconds: queue_wait_at_grant,
                                ember_hash: peer_ember_hash.map(hex::encode),
                            },
                        }).await;
                    }
                }

                (OP_EMULEPROT, OP_REQUESTPARTS_I64) | (OP_EDONKEYHEADER, OP_REQUESTPARTS) => {
                    // The first 16 bytes of an OP_REQUESTPARTS payload are the
                    // requested file's ED2K hash. Honor it as authoritative for
                    // what to serve rather than blindly serving whatever
                    // `current_file_hash` happens to be: a peer that pipelines a
                    // request for a different file than the one negotiated on this
                    // slot must not receive the wrong file's bytes (which would
                    // corrupt their download under the other file's hash). On a
                    // genuine switch we finalize the previous UI row (mirroring the
                    // OP_SETREQFILEID path) and force a size re-resolve below.
                    if payload.len() >= 16 {
                        let mut requested = [0u8; 16];
                        requested.copy_from_slice(&payload[..16]);
                        if current_file_hash != Some(requested) {
                            if let Some(prev) = current_file_hash {
                                if prev != requested {
                                    if let Some(tid) = transfer_id.take() {
                                        let kind = if uploaded > 0 {
                                            upload_session_completed(
                                                unique_served_bytes(&served_bytes_per_part, total_size),
                                                total_size,
                                            )
                                        } else {
                                            UploadEventKind::Failed {
                                                error: "Peer switched files before any data was sent".to_string(),
                                            }
                                        };
                                        let _ = self.upload_event_tx.send(UploadEvent {
                                            transfer_id: tid,
                                            kind,
                                        }).await;
                                    }
                                    uploaded = 0;
                                    served_bytes_per_part.clear();
                                    sent_blocks.clear();
                                    cached_part_tracker = None;
                                }
                            }
                            current_file_hash = Some(requested);
                            // Force the size backstop below to re-resolve for the
                            // newly-targeted file.
                            total_size = 0;
                            self.sync_queue_file_hash(
                                &queue_identity,
                                requested,
                                peer_addr,
                                hello_caps.tcp_port,
                            )
                            .await;
                        }
                    }
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

                    // Backstop / UI-row (re)establishment. `total_size` is only
                    // set by OP_SETREQFILEID and the size-bearing MultiPacket, and
                    // `transfer_id` is minted at grant time. A peer can reach
                    // OP_REQUESTPARTS with either still unset:
                    //   * single-part (< PARTSIZE) files where our own downloader
                    //     omits OP_SETREQFILEID (multi_source.rs) leave total_size
                    //     == 0; without a resolved size the range filter below
                    //     drops every request and we serve nothing.
                    //   * a mid-slot file switch (handled in OP_SETREQFILEID /
                    //     MultiPacket / the hash check above) finalizes the prior
                    //     row and nulls transfer_id, so the newly-targeted file has
                    //     no UI row yet — Progress events are gated on a live
                    //     transfer_id and would be silently dropped.
                    // Resolve once and repair both. Only runs on these off-nominal
                    // paths, so there's no cost on the steady-state serve loop.
                    if total_size == 0 || transfer_id.is_none() {
                        if let Some(file) = self.resolve_upload_file(&hash, PeerFileAccess { ember_hash: peer_ember_hash, secure_v2_authenticated }).await {
                            if total_size == 0 {
                                total_size = file.size;
                            }
                            if transfer_id.is_none() {
                                let tid = uuid::Uuid::new_v4().to_string();
                                transfer_id = Some(tid.clone());
                                // Fresh row: emit the first Progress immediately
                                // rather than coalescing against the prior file's.
                                last_progress_emit = None;
                                last_progress_uploaded = 0;
                                let _ = self.upload_event_tx.send(UploadEvent {
                                    transfer_id: tid,
                                    kind: UploadEventKind::Started {
                                        file_name: file.name.clone(),
                                        file_hash: hex::encode(hash),
                                        total_size,
                                        peer_addr: peer_addr.to_string(),
                                        peer_name: ul_peer_name.clone(),
                                        client_software: ul_client_software.clone(),
                                        country_code: ul_country_code.clone(),
                                        user_hash: if peer_user_hash != [0u8; 16] { Some(hex::encode(peer_user_hash)) } else { None },
                                        wait_seconds: queue_wait_at_grant,
                                        ember_hash: peer_ember_hash.map(hex::encode),
                                    },
                                }).await;
                            }
                        }
                    }

                    let mut offsets: Vec<(u64, u64)> = offsets
                        .into_iter()
                        .filter(|&(start, end)| {
                            if end > total_size {
                                debug!("Peer requested range past file end: {end} > {total_size}");
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
                    // the downloader counts completed requested ranges
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

                    // Cap what one request can commit us to serving, *before*
                    // the per-block split below. Every rotation control —
                    // SESSIONMAXTRANS, SESSIONMAXTIME, the score-based
                    // preemption check and the outer idle gate — lives after
                    // the block loop, so a single range covering the whole
                    // file (nothing rejected it: it is within EOF and
                    // correctly ordered) held one of the user's upload slots
                    // for the entire transfer while everyone else waited.
                    //
                    // Trimming after the split was too late to stop the other
                    // half of the problem: the split expands a range into one
                    // tuple per EMBLOCKSIZE first, so a 22-byte request naming
                    // one whole-file range on a 50 GB share allocated roughly
                    // 290k tuples — several megabytes — before anything looked
                    // at the budget, and the peer could repeat that at line
                    // rate. Capping the merged ranges bounds the split's output
                    // to `MAX_REQUESTPARTS_BYTES / EMBLOCKSIZE` pieces.
                    //
                    // Ranges are truncated rather than dropped so an oversized
                    // request still gets served up to the cap; the remainder is
                    // re-requested on the peer's next turn. eMule-family peers
                    // ask for three EMBLOCKSIZE blocks at a time, so nothing
                    // legitimate reaches this.
                    {
                        let before = offsets.len();
                        let mut budget = MAX_REQUESTPARTS_BYTES;
                        let mut capped: Vec<(u64, u64)> = Vec::with_capacity(offsets.len());
                        for (s, e) in offsets {
                            if budget == 0 {
                                break;
                            }
                            let take = e.saturating_sub(s).min(budget);
                            if take == 0 {
                                continue;
                            }
                            capped.push((s, s + take));
                            budget -= take;
                        }
                        let trimmed = capped.len() != before
                            || capped.iter().map(|&(s, e)| e - s).sum::<u64>()
                                == MAX_REQUESTPARTS_BYTES;
                        if trimmed {
                            debug!(
                                "Trimmed OP_REQUESTPARTS from {peer_addr}: {before} range(s) \
                                 exceeded the {MAX_REQUESTPARTS_BYTES}-byte per-request cap"
                            );
                        }
                        offsets = capped;
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

                    // eMule AddReqBlock: drop ranges already queued or already
                    // delivered this session. aMule and other non-eMule clients
                    // pad each OP_REQUESTPARTS with still-in-flight blocks so
                    // the packet always names three ranges; serving those again
                    // is what made Transferred climb to 2–3× unique coverage.
                    let after_split = offsets.len();
                    offsets = filter_already_sent_ranges(offsets, &sent_blocks);
                    let skipped_already_sent = after_split - offsets.len();
                    if skipped_already_sent > 0 {
                        debug!(
                            target: "ember::upload_diag",
                            "reqparts_skip_dup {peer_addr} skipped={skipped_already_sent} kept={}",
                            offsets.len(),
                        );
                    }

                    // Diagnostic: summarise the batch shape for this REQUESTPARTS
                    // before we touch the disk. A peer sending REQUESTPARTS with
                    // all ranges filtered away as garbage (past EOF, zero-length)
                    // lands here with `offsets.is_empty()` and no idle bump, so
                    // SLOT_IDLE_TIMEOUT will eventually fire. aMule padding that
                    // we skip as already-sent still resets the gauge below even
                    // when nothing new is served.
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

                    let resolved = match self.resolve_upload_file(&hash, PeerFileAccess { ember_hash: peer_ember_hash, secure_v2_authenticated }).await {
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
                    let resolved_allowed_roots = resolved.allowed_roots;
                    let mut resolved_opened = Some(resolved.opened);

                    // Refresh-or-reuse the cached `PartTracker` for the
                    // current file. Rebuilt after PART_TRACKER_REFRESH so
                    // newly-completed parts of a partial file we're
                    // simultaneously downloading become advertisable within
                    // a bounded delay. Outside of that window we reuse the
                    // parsed tracker across batches and blocks — the old
                    // code re-read `.part.met` on every OP_REQUESTPARTS.
                    let is_partial_serve = resolved.is_partial && total_size > 0;
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
                            // `PartTracker::new` synchronously reads the
                            // `.part.met` from disk; run it on the blocking pool
                            // so it never stalls a Tokio worker on the serve hot
                            // path. (It's infallible — IO errors yield an empty
                            // tracker — so the only failure here is a join panic,
                            // in which case we fall back to the direct call.)
                            let fp = file_path.clone();
                            let ts = total_size;
                            let tracker = tokio::task::spawn_blocking(move || {
                                super::part_tracker::PartTracker::new(ts, &fp)
                            })
                            .await
                            .unwrap_or_else(|_| {
                                super::part_tracker::PartTracker::new(total_size, &file_path)
                            });
                            cached_part_tracker =
                                Some((file_path.clone(), tracker, std::time::Instant::now()));
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
                    } else {
                        // Every request batch receives a newly policy-validated
                        // handle. Replace any older cached handle so a pathname
                        // replacement cannot keep an obsolete object serving
                        // after the next authorization check.
                        cached_serve_file =
                            resolved_opened.take().map(|file| (file_path.clone(), file));
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
                                debug!(
                                    "Rejected upload of incomplete or unverified range {}-{} for {}",
                                    start,
                                    end,
                                    file_path.display()
                                );
                                continue;
                            }
                            // First verified range we serve out of this `.part`
                            // file on this session: announce the partial-file
                            // seed once so it's visible that swarming is working.
                            if !logged_partial_seed {
                                logged_partial_seed = true;
                                info!(
                                    "Seeding partial file \"{}\" to {} — serving already-verified parts while still downloading it",
                                    file_path
                                        .file_name()
                                        .and_then(|n| n.to_str())
                                        .unwrap_or("<unknown>"),
                                    peer_addr
                                );
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

                        // Terminate promptly when the network is disconnected,
                        // mid-batch. The outer session loop also checks this, but
                        // only between OP_REQUESTPARTS batches, so without this a
                        // large in-flight batch keeps streaming to the peer for
                        // several seconds after the user clicked Disconnect.
                        // Breaking returns to the outer loop, whose own
                        // network-disconnected check ends the session and runs
                        // the normal cleanup.
                        if self.network_disconnected.load(std::sync::atomic::Ordering::Relaxed) {
                            info!("Upload to {peer_addr} ending: network disconnected mid-batch");
                            break;
                        }

                        // Stop serving blocks the moment the peer is banned so
                        // an in-flight transfer can't keep streaming through a
                        // multi-block OP_REQUESTPARTS. Breaking the block loop
                        // returns to the outer loop, whose ban check then ends
                        // the session (and runs the normal cleanup).
                        if self.peer_is_banned(&peer_user_hash, &peer_addr) {
                            info!("Upload to {peer_addr} aborted: peer banned mid-transfer");
                            break;
                        }

                        // `start < end` is already enforced upstream (range filter
                        // + per-offset skip), but use saturating_sub so a future
                        // refactor that drops a guard can't underflow on this
                        // peer-supplied range.
                        let len = (end.saturating_sub(start) as usize).min(PARTSIZE as usize);

                        // Move the session-cached `File` into `spawn_blocking`
                        // (a `&mut File` isn't `'static`, so we take-and-put
                        // it back via the task return value). This reuses a
                        // single open handle across every block in the
                        // session instead of `File::open` per block — saves
                        // one open + one close syscall + one FD cycle per
                        // ~180 KiB on the hot path.
                        let taken_file = if is_partial_serve {
                            resolved_opened.take()
                        } else {
                            cached_serve_file.take().map(|(_, f)| f)
                        };
                        let fp_for_task = file_path.clone();
                        let allowed_for_task = resolved_allowed_roots.clone();
                        let read_result = tokio::task::spawn_blocking(
                            move || -> anyhow::Result<(std::fs::File, Vec<u8>)> {
                                let f = match taken_file {
                                    Some(f) => f,
                                    None => {
                                        crate::security::filesystem::open_existing_approved(
                                            &fp_for_task,
                                            &allowed_for_task,
                                            false,
                                        )?
                                        .1
                                    }
                                };
                                read_upload_block(f, start, len)
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
                        // Run the zlib pass off the async runtime: compressing a
                        // ~180 KiB block is CPU-bound and would otherwise pin a
                        // Tokio worker for the whole pass, competing with the
                        // reactor that also drives downloads, accepts, and KAD.
                        // The file read above is already offloaded the same way.
                        // `data` is moved into the blocking task and handed back
                        // so the uncompressed fallback below can reuse it with no
                        // extra copy.
                        let (data, compressed_opt): (Vec<u8>, Option<Vec<u8>>) =
                            if use_compression {
                                tokio::task::spawn_blocking(move || {
                                    let mut encoder =
                                        ZlibEncoder::new(Vec::new(), Compression::default());
                                    let compressed = match encoder.write_all(&data) {
                                        // Only keep the compressed copy if it
                                        // actually saves space.
                                        Ok(()) => {
                                            encoder.finish().ok().filter(|c| c.len() < data.len())
                                        }
                                        Err(_) => None,
                                    };
                                    (data, compressed)
                                })
                                .await?
                            } else {
                                (data, None)
                            };

                        let mut sent_compressed = false;
                        if let Some(compressed) = compressed_opt {
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

                                self.acquire_upload_bandwidth(chunk_len as u64).await?;
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
                                        let peer_part = peer_part_status
                                            .as_ref()
                                            .filter(|(h, _)| Some(*h) == current_file_hash)
                                            .map(|(_, s)| s.clone());
                                        let _ = self.upload_event_tx.send(UploadEvent {
                                            transfer_id: tid.clone(),
                                            kind: upload_progress_kind(
                                                uploaded,
                                                total_size,
                                                &served_bytes_per_part,
                                                peer_part,
                                            ),
                                        }).await;
                                    }
                                }
                            }
                            // Size (or re-size, after a mid-session file
                            // switch where `total_size` changed) the tally to
                            // the current file's part count before recording.
                            let want_parts =
                                total_size.div_ceil(PARTSIZE).max(1) as usize;
                            if total_size > 0 && served_bytes_per_part.len() != want_parts {
                                served_bytes_per_part = vec![0u64; want_parts];
                            }
                            mark_served_parts(
                                &mut served_bytes_per_part,
                                start,
                                data.len() as u64,
                            );
                            sent_blocks.insert((start, end));
                            sent_compressed = true;
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

                            self.acquire_upload_bandwidth(chunk_len as u64).await?;
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
                                    let peer_part = peer_part_status
                                        .as_ref()
                                        .filter(|(h, _)| Some(*h) == current_file_hash)
                                        .map(|(_, s)| s.clone());
                                    let _ = self.upload_event_tx.send(UploadEvent {
                                        transfer_id: tid.clone(),
                                        kind: upload_progress_kind(
                                            uploaded,
                                            total_size,
                                            &served_bytes_per_part,
                                            peer_part,
                                        ),
                                    }).await;
                                }
                            }

                            cursor += chunk_len;
                        }
                        // Size (or re-size, after a mid-session file switch
                        // where `total_size` changed) the tally to the current
                        // file's part count before recording.
                        let want_parts = total_size.div_ceil(PARTSIZE).max(1) as usize;
                        if total_size > 0 && served_bytes_per_part.len() != want_parts {
                            served_bytes_per_part = vec![0u64; want_parts];
                        }
                        mark_served_parts(&mut served_bytes_per_part, start, data.len() as u64);
                        sent_blocks.insert((start, end));
                    }

                    // Diagnostic: batch-level summary. `credited_bytes == 0`
                    // with no already-sent skips means every range was garbage
                    // (past EOF, zero-length, or rejected by the part tracker)
                    // and `last_part_request` will NOT be bumped. Already-sent
                    // padding (aMule) still resets the idle gauge below.
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
                                let verified = secure_v2_authenticated;
                                cm.add_ember_uploaded(pk, batch_credited_bytes, verified);
                            }
                        }
                        self.slot_rates
                            .lock()
                            .insert(peer_addr, rate_tracker.smoothed_rate());
                    }
                    // Idle gauge: bytes on the wire always count. aMule
                    // padding (ranges we already delivered this session)
                    // also counts so a pipeline-full re-ask does not lose
                    // the slot. EOF / zero-length / unservable garbage
                    // still does not — that is the eMule Plus 1.2.5
                    // pin-forever case this timer exists to break.
                    if requestparts_resets_idle(
                        batch_credited_bytes,
                        skipped_already_sent,
                        last_credited_at.elapsed(),
                    ) {
                        last_part_request = std::time::Instant::now();
                    }
                    if batch_credited_bytes > 0 {
                        last_credited_at = std::time::Instant::now();
                    }

                    // OP_REQUESTPARTS is the hot path. After the inner
                    // offset loop, `mark_served_parts` has run, so unique
                    // coverage and the parts bitmap finally include this
                    // batch. Mid-loop Progress ticks fire *before* that
                    // tally update (so speed/`uploaded` stay live) and set
                    // `last_progress_uploaded`, which used to skip this
                    // flush — leaving the UI on the previous batch's unique
                    // bytes (0% for a file sent in a single REQUESTPARTS).
                    // Emit whenever this batch credited bytes, even if the
                    // wire counter was already reported.
                    if let Some(tid) = &transfer_id {
                        if batch_credited_bytes > 0 {
                            last_progress_emit = Some(std::time::Instant::now());
                            last_progress_uploaded = uploaded;
                            let peer_part = peer_part_status
                                .as_ref()
                                .filter(|(h, _)| Some(*h) == current_file_hash)
                                .map(|(_, s)| s.clone());
                            let _ = self.upload_event_tx.send(UploadEvent {
                                transfer_id: tid.clone(),
                                kind: upload_progress_kind(
                                    uploaded,
                                    total_size,
                                    &served_bytes_per_part,
                                    peer_part,
                                ),
                            }).await;
                        }
                    }

                    // eMule's upload list has no terminal "Complete" row: a
                    // client occupies a slot only while it is actively being
                    // served and the row disappears the instant the session
                    // ends (CUploadQueue::RemoveFromUploadQueue). Once a peer
                    // has received the entire file from us this session there
                    // are no more parts it can legitimately request, so we
                    // finalize the transfer now and close the connection
                    // rather than letting the row linger at "Complete 100%"
                    // until the 60 s idle gate or an eventual peer disconnect
                    // fires. Cumulative upload totals live in StatsManager, so
                    // dropping the per-session row loses no history; a peer
                    // that wants another file just reconnects (cheap, and
                    // exactly how eMule clients pipeline multiple files).
                    // Use unique per-part coverage — cumulative `uploaded`
                    // counts re-requests after hash/AICH and would end the
                    // session early while the peer still needs bytes.
                    let unique_uploaded =
                        unique_served_bytes(&served_bytes_per_part, total_size);
                    if total_size > 0 && unique_uploaded >= total_size {
                        info!(
                            target: "ember::upload_diag",
                            "session_end {peer_addr} reason=file_complete \
                             uploaded={uploaded}B unique={unique_uploaded}B \
                             total={total_size}B \
                             session_age={}s iters={outer_loop_iterations} — \
                             dropping completed upload row",
                            session_open_at.elapsed().as_secs(),
                        );
                        if let Some(tid) = &transfer_id {
                            let _ = self
                                .upload_event_tx
                                .send(UploadEvent {
                                    transfer_id: tid.clone(),
                                    kind: UploadEventKind::Completed { full_file: true },
                                })
                                .await;
                        }
                        // Cleared so the shared teardown below does not emit a
                        // second terminal event for this transfer. The Ember
                        // session record still fires there (session_start is
                        // left intact) with completed = true.
                        transfer_id = None;
                        break;
                    }

                    // Enforce eMule session limits + score-based preemption.
                    // eMule CheckForTimeOver: don't rotate if nobody is waiting.
                    let queue_has_waiters = {
                        let q = self.upload_queue.lock().await;
                        !q.is_empty()
                    };
                    // eMule CheckForTimeOver (UploadQueue.cpp:773) returns false
                    // for a friend slot: a verified friend is NEVER rotated out,
                    // neither by the per-session byte cap (SESSIONMAXTRANS) nor the
                    // max session time (SESSIONMAXTIME). Friend priority requires
                    // proof-of-possession on THIS session (merely claiming a
                    // friend's hash is not enough), matching the queue-insertion
                    // and preemption sites. Without this exemption a friend's
                    // transfer was interrupted with OP_OUTOFPARTREQS every ~9.5 MB
                    // (re-queued, then immediately re-granted via their score, but
                    // with a needless stall) — eMule keeps the friend uploading
                    // continuously.
                    let is_verified_friend = live_secure_friend_member(
                        &self.friend_hashes,
                        peer_ember_hash,
                        secure_v2_authenticated,
                    )
                    .await;
                    let session_expired = queue_has_waiters
                        && !is_verified_friend
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
                        let cm = self.credit_manager.read().await;
                        let idx_snap = self.local_index.read().await;
                        let queue = self.upload_queue.lock().await;
                        if queue.is_empty() {
                            false
                        } else {
                            let my_fh = current_file_hash.unwrap_or([0u8; 16]);
                            // See queue-insertion site above: friend
                            // priority only counts when PoP has landed
                            // on this session.
                            let ember_verified = secure_v2_authenticated;
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
                            let verified = secure_v2_authenticated;
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
                            // Terminal event for the rotated-out session. Use
                            // Completed only if we actually moved bytes; a slot
                            // that was granted then immediately rotated (e.g. score
                            // preemption) without sending any data emits Failed so
                            // the UI row is distinguishable from a real transfer.
                            // Statistics only count full-file serves as completed.
                            let kind = if uploaded > 0 {
                                upload_session_completed(
                                    unique_served_bytes(&served_bytes_per_part, total_size),
                                    total_size,
                                )
                            } else {
                                UploadEventKind::Failed {
                                    error: "Slot rotated before any data was sent".to_string(),
                                }
                            };
                            let _ = self.upload_event_tx.send(UploadEvent {
                                transfer_id: tid.clone(),
                                kind,
                            }).await;
                        }
                        transfer_id = None;

                        slot_guard.deactivate();
                        session_start = None;
                        // Reset the session byte counters, exactly as the
                        // cancel / end-of-download teardown below does. Left
                        // set, the outer idle gate (`slot_guard.is_active() ||
                        // uploaded > 0`) tripped 60 seconds later and closed
                        // the connection on a peer that was correctly waiting
                        // its next turn. That trigger exists to unpin a stale
                        // UI row, and `transfer_id` was just cleared, so there
                        // was no row left to unpin — it only cost the
                        // connection, and a firewalled peer could not be
                        // re-promoted until it dialled back in.
                        uploaded = 0;
                        served_bytes_per_part.clear();
                        sent_blocks.clear();
                        self.slot_rates.lock().remove(&peer_addr);
                        rate_tracker = SessionRateTracker::new();

                        // Re-add to upload queue so they can get another turn.
                        // `queued_identity` is only armed once we've confirmed a
                        // queue entry actually exists for this peer (`re_queued`
                        // below) — the periodic promotion poll uses a 1s timeout
                        // while `queued_identity.is_some()`, so arming it
                        // unconditionally here used to leave a peer stuck
                        // spinning that poll forever once the queue was full or
                        // their re-admission score lost the soft-hard-zone
                        // check: no queue entry existed for them, so the poll
                        // could never find and promote them, yet nothing ever
                        // told the peer to give up and reconnect later.
                        let re_queued = {
                            // Same PoP gate as the initial queue-insertion
                            // site: re-admitting after session-expire
                            // uses the CURRENT verification state. If the
                            // peer authenticated earlier on this session
                            // and the flag is still true, they re-enter
                            // with friend priority; if auth never
                            // completed, they re-enter as a regular peer.
                            let is_verified_friend = live_secure_friend_member(
                                &self.friend_hashes,
                                peer_ember_hash,
                                secure_v2_authenticated,
                            )
                            .await;
                            let cm = self.credit_manager.read().await;
                            let idx_snap = self.local_index.read().await;
                            let mut queue = self.upload_queue.lock().await;
                            if let Some(entry) =
                                queue.iter_mut().find(|e| e.identity == queue_identity)
                            {
                                // Same live-session bind as the initial
                                // queue-insertion site: while this session
                                // was uploading its row was removed, so
                                // another connection claiming this
                                // `user_hash` may have inserted a fresh
                                // row. Do not hijack a waiter's row bound
                                // to a different IP or advertised port;
                                // refuse and let the caller send OP_QUEUEFULL.
                                // Same IP + Hello-advertised port takes
                                // the row over. Preserve seniority only
                                // when `current_addr` is `None` (reconnect).
                                let bound_addr = entry.current_addr;
                                if !queue_row_owned_by_session(
                                    bound_addr,
                                    entry.tcp_port,
                                    peer_addr,
                                    hello_caps.tcp_port,
                                ) {
                                    false
                                } else {
                                let same_session = bound_addr == Some(peer_addr);
                                if !same_session {
                                    entry.is_friend_slot = false;
                                    entry.ember_verified = false;
                                }
                                entry.current_addr = Some(peer_addr);
                                entry.last_ip = Some(peer_addr.ip());
                                entry.udp_port = hello_caps.udp_port;
                                entry.tcp_port = hello_caps.tcp_port;
                                entry.crypt_options = hello_caps.crypt_options_byte();
                                entry.is_high_id =
                                    peer_is_high_id_for_queue(&hello_caps, peer_addr);
                                entry.user_hash = peer_user_hash;
                                entry.file_hash = current_file_hash.unwrap_or([0u8; 16]);
                                if is_verified_friend {
                                    entry.is_friend_slot = true;
                                }
                                // Re-entry after session end: refresh
                                // the Ember verification snapshot. As
                                // with `is_friend_slot` we only
                                // upgrade (NotStarted → Verified)
                                // here, never downgrade within the
                                // same session — once a peer has
                                // completed PoP on a session the
                                // queue entry keeps that fact through
                                // re-admission (a session change
                                // already reset it to `false` above).
                                if secure_v2_authenticated {
                                    entry.ember_verified = true;
                                }
                                if !same_session {
                                    entry.ember_pubkey = hello_caps.ember_pubkey;
                                } else if entry.ember_pubkey.is_none() {
                                    entry.ember_pubkey = hello_caps.ember_pubkey;
                                }
                                true
                                }
                            } else if queue.len() < MAX_UPLOAD_QUEUE_SIZE {
                                queue.push(queue_entry_from_hello(
                                    queue_identity.clone(),
                                    peer_addr,
                                    peer_user_hash,
                                    current_file_hash.unwrap_or([0u8; 16]),
                                    queue_join_time,
                                    &hello_caps,
                                    is_verified_friend,
                                    secure_v2_authenticated,
                                ));
                                true
                            } else if queue.len() < HARD_UPLOAD_QUEUE_SIZE {
                                // eMule soft→hard: CombinedFilePrioAndCredit (no wait)
                                let new_fh = current_file_hash.unwrap_or([0u8; 16]);
                                let ember_verified = secure_v2_authenticated;
                                let peer_ip = peer_ip_u32(Some(peer_addr));
                                let new_combined = combined_file_prio_and_credit(
                                    &cm,
                                    &idx_snap,
                                    &peer_user_hash,
                                    new_fh,
                                    peer_ip,
                                    hello_caps.ember_pubkey.as_ref(),
                                    ember_verified,
                                );
                                let avg_combined = if queue.is_empty() {
                                    0.0
                                } else {
                                    let total: f64 = queue
                                        .iter()
                                        .map(|e| {
                                            combined_file_prio_and_credit(
                                                &cm,
                                                &idx_snap,
                                                &e.user_hash,
                                                e.file_hash,
                                                peer_ip_u32(e.current_addr.or_else(|| {
                                                    e.last_ip.map(|ip| SocketAddr::new(ip, 0))
                                                })),
                                                e.ember_pubkey.as_ref(),
                                                e.ember_verified,
                                            )
                                        })
                                        .sum();
                                    total / queue.len() as f64
                                };
                                if soft_zone_should_admit(
                                    is_verified_friend,
                                    new_combined,
                                    avg_combined,
                                ) {
                                    queue.push(queue_entry_from_hello(
                                        queue_identity.clone(),
                                        peer_addr,
                                        peer_user_hash,
                                        new_fh,
                                        queue_join_time,
                                        &hello_caps,
                                        is_verified_friend,
                                        ember_verified,
                                    ));
                                    true
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        };

                        if re_queued {
                            // Re-arm the promotion poller now that we've confirmed
                            // a queue entry exists to promote it from.
                            queued_identity = Some(queue_identity.clone());
                        } else {
                            debug!(
                                "Upload queue full on session-rotation re-admit, sending OP_QUEUEFULL to {peer_addr}"
                            );
                            write_packet_async(&mut writer, OP_EMULEPROT, OP_QUEUEFULL, &[])
                                .await?;
                            break;
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
                        let verified = secure_v2_authenticated;
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
                            upload_session_completed(
                                unique_served_bytes(&served_bytes_per_part, total_size),
                                total_size,
                            )
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
                    served_bytes_per_part.clear();
                    sent_blocks.clear();
                    session_start = None;
                    self.slot_rates.lock().remove(&peer_addr);
                    rate_tracker = SessionRateTracker::new();
                    current_file_hash = None;
                    total_size = 0;
                }

                // Vanilla eDonkey/eMule "View Files" — works with any
                // ed2k-compatible client (eMule, aMule, MLDonkey, ...), not
                // just other instances of this app. Gated on a plain
                // Settings toggle rather than friendship/auth, matching
                // real eMule's "Show shared files to everybody" behavior.
                // When disabled we still answer — with an explicit denial
                // — rather than silently dropping the request, so the
                // asker's client shows "access denied" instead of hanging.
                (OP_EDONKEYHEADER, OP_ASKSHAREDFILES) => {
                    if self
                        .share_browsing_enabled
                        .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        let client_id = self
                            .external_ip_shared
                            .load(std::sync::atomic::Ordering::Relaxed);
                        let resp = self.build_shared_files_answer(client_id).await;
                        write_packet_async(
                            &mut writer,
                            OP_EDONKEYHEADER,
                            OP_ASKSHAREDFILESANSWER,
                            &resp,
                        )
                        .await?;
                        debug!("Answered OP_ASKSHAREDFILES from {peer_addr}");
                    } else {
                        write_packet_async(
                            &mut writer,
                            OP_EDONKEYHEADER,
                            OP_ASKSHAREDDENIEDANS,
                            &[],
                        )
                        .await?;
                        debug!("Denied OP_ASKSHAREDFILES from {peer_addr} (browsing disabled)");
                    }
                }

                (OP_EDONKEYHEADER, OP_HASHSETREQ) if payload.len() >= 16 => {
                    let mut req_hash = [0u8; 16];
                    req_hash.copy_from_slice(&payload[..16]);
                    if let Some(file) = self.resolve_upload_file(&req_hash, PeerFileAccess { ember_hash: peer_ember_hash, secure_v2_authenticated }).await {
                        let path = file.path.clone();
                        let file_name = file.name.clone();
                        let file_size = file.size;
                        let is_partial = file.is_partial;
                        let mut opened = file.opened;
                        // Complete files answer from the memo when we have it:
                        // this handler is otherwise a whole-file read for the
                        // price of a 22-byte packet, and every downloader of a
                        // share sends one.
                        let cache_key = hex::encode(req_hash);
                        let memoized = if is_partial {
                            None
                        } else {
                            self.part_hash_cache.lock().await.get(&cache_key)
                        };
                        let hashset_result = match memoized {
                            Some(hashes) => Ok(Some(hashes)),
                            None => {
                                let computed = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Vec<[u8; 16]>>> {
                                    if is_partial && file_size > 0 {
                                        let tracker = super::part_tracker::PartTracker::new(file_size, &path);
                                        let cached = tracker.part_hashes();
                                        if !cached.is_empty() {
                                            tracing::debug!("Using {} cached part hashes from tracker", cached.len());
                                            return Ok(Some(cached.to_vec()));
                                        }
                                        return Ok(None);
                                    }
                                    Ok(Some(compute_part_hashes(&mut opened)?))
                                })
                                .await?;
                                if let Ok(Some(ref hashes)) = computed {
                                    if !is_partial {
                                        self.part_hash_cache
                                            .lock()
                                            .await
                                            .insert(cache_key.clone(), hashes.clone());
                                    }
                                }
                                computed
                            }
                        };

                        match hashset_result {
                            Ok(Some(hashes)) => {
                                let Some(resp) =
                                    encode_legacy_hashset_response(&req_hash, &hashes)
                                else {
                                    warn!(
                                        "Refusing legacy HashSet for {}: {} hashes exceed u16 wire count",
                                        file_name,
                                        hashes.len()
                                    );
                                    continue;
                                };
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
                        if let Some(file) = self.resolve_upload_file(&file_ident.md4_hash, PeerFileAccess { ember_hash: peer_ember_hash, secure_v2_authenticated }).await {
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
                                let file_name = file.name.clone();
                                let file_size = file.size;
                                let aich_root = local_ident.aich_hash;
                                let is_partial = file.is_partial;
                                let mut opened = file.opened;
                                // Same memo as `OP_HASHSETREQ` above: without
                                // it this re-reads the whole file per request.
                                let cache_key = hex::encode(file_ident.md4_hash);
                                let memoized_md4 = if is_partial || !request_md4 {
                                    None
                                } else {
                                    self.part_hash_cache.lock().await.get(&cache_key)
                                };
                                let compute_md4 = request_md4 && memoized_md4.is_none();
                                // The AICH branch needs the same memo, and for the
                                // same reason: it reads the whole file and builds a
                                // SHA-1 tree over every 180 KiB block, on a request
                                // that needs no slot, no queue position and no
                                // identity, and the abuse tracker counts connections
                                // rather than packets. Uncached, one looped 20-byte
                                // packet pinned a core and the disk indefinitely.
                                // Shares `aich_cache` with `OP_AICHREQUEST` — that
                                // handler stores the same hash set, so warming
                                // either opcode now serves both.
                                let memoized_aich = if is_partial || !request_aich {
                                    None
                                } else {
                                    self.aich_cache.lock().await.get(&cache_key)
                                };
                                let compute_aich = request_aich && memoized_aich.is_none();
                                let (computed_md4, computed_aich) = tokio::task::spawn_blocking(move || {
                                    let md4 = if compute_md4 {
                                        if is_partial {
                                            let tracker = super::part_tracker::PartTracker::new(file_size, &path);
                                            let cached = tracker.part_hashes();
                                            if cached.is_empty() {
                                                None
                                            } else {
                                                Some(cached.to_vec())
                                            }
                                        } else {
                                            Some(compute_part_hashes(&mut opened)?)
                                        }
                                    } else {
                                        None
                                    };
                                    let aich = if compute_aich {
                                        if is_partial {
                                            None
                                        } else {
                                            Some(crate::network::ed2k::aich::AICHRecoveryHashSet::build_from_open_file(
                                                &mut opened,
                                            )?)
                                        }
                                    } else {
                                        None
                                    };
                                    Ok::<_, anyhow::Error>((md4, aich))
                                }).await??;
                                if let Some(ref hashes) = computed_md4 {
                                    if !is_partial {
                                        self.part_hash_cache
                                            .lock()
                                            .await
                                            .insert(cache_key.clone(), hashes.clone());
                                    }
                                }
                                if let Some(ref hs) = computed_aich {
                                    if !is_partial {
                                        self.aich_cache
                                            .lock()
                                            .await
                                            .insert(cache_key.clone(), hs.clone());
                                    }
                                }
                                let md4_hashes = memoized_md4.or(computed_md4);
                                let aich_hashes = memoized_aich
                                    .or(computed_aich)
                                    .map(|hs| hs.part_hashes());

                                let md4_section = md4_hashes
                                    .as_ref()
                                    .filter(|h| !h.is_empty());
                                let aich_section = match (aich_root, aich_hashes.as_ref()) {
                                    (Some(root), Some(hashes)) if !hashes.is_empty() => {
                                        Some((root, hashes))
                                    }
                                    _ => None,
                                };
                                let Some(resp) = encode_hashset2_response(
                                    &local_ident,
                                    md4_section.map(Vec::as_slice),
                                    aich_section.map(|(root, hashes)| (root, hashes.as_slice())),
                                ) else {
                                    warn!(
                                        "Refusing HashSet2 for {}: a requested hash section exceeds u16 wire count",
                                        file_name
                                    );
                                    continue;
                                };
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
                    match parse_multipacket(
                        &payload,
                        opcode,
                        hello_caps.extended_requests_ver,
                    ) {
                        Ok(mpreq) => {
                            let hash_hex = hex::encode(mpreq.file_hash);
                            if let Some(file) = self.resolve_upload_file(&mpreq.file_hash, PeerFileAccess { ember_hash: peer_ember_hash, secure_v2_authenticated }).await {
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
                            // Mid-slot file switch (see OP_SETREQFILEID): if this
                            // MultiPacket targets a different file than the one we're
                            // actively serving, finalize the old UI row so the new
                            // file's bytes aren't reported under the stale transfer.
                            if let Some(prev) = current_file_hash {
                                if prev != mpreq.file_hash {
                                    if let Some(tid) = transfer_id.take() {
                                        let kind = if uploaded > 0 {
                                            upload_session_completed(
                                                unique_served_bytes(&served_bytes_per_part, total_size),
                                                total_size,
                                            )
                                        } else {
                                            UploadEventKind::Failed {
                                                error: "Peer switched files before any data was sent".to_string(),
                                            }
                                        };
                                        let _ = self.upload_event_tx.send(UploadEvent {
                                            transfer_id: tid,
                                            kind,
                                        }).await;
                                    }
                                    uploaded = 0;
                                    served_bytes_per_part.clear();
                                    sent_blocks.clear();
                                    cached_part_tracker = None;
                                }
                            }
                            current_file_hash = Some(mpreq.file_hash);
                            total_size = file.size;
                            self.sync_queue_file_hash(
                                &queue_identity,
                                mpreq.file_hash,
                                peer_addr,
                                hello_caps.tcp_port,
                            )
                            .await;

                                // eMule ProcessExtendedInfo over MultiPacket: the
                                // OP_REQUESTFILENAME sub-block carries the peer's
                                // advertised part status. `parse_multipacket`
                                // captured the raw bitmap; decode it for the dark
                                // "peer already has" shading.
                                if let Some((advertised, ref bitmap)) = mpreq.req_part_status {
                                    if let Some(hex) =
                                        peer_part_status_hex(advertised, bitmap, file.size)
                                    {
                                        peer_part_status = Some((mpreq.file_hash, hex));
                                    }
                                }

                                let partial_bitmap = if file.is_partial && file.size > 0 {
                                    let file_size = file.size;
                                    let part_path = file.path.clone();
                                    let fallback_path = part_path.clone();
                                    let tracker = tokio::task::spawn_blocking(move || {
                                        super::part_tracker::PartTracker::new(file_size, &part_path)
                                    })
                                    .await
                                    .unwrap_or_else(|e| {
                                        tracing::warn!(
                                            "PartTracker load task failed for MultiPacket bitmap: {e}"
                                        );
                                        super::part_tracker::PartTracker::new_empty(
                                            file_size,
                                            &fallback_path,
                                        )
                                    });
                                    // Advertise only parts we will actually serve
                                    // (complete AND MD4-verified). Using bare
                                    // `completed_parts()` here advertised unverified
                                    // parts that the serve gate then rejected,
                                    // freezing partial-file seeds over MultiPacket.
                                    Some(tracker.serveable_parts())
                                } else {
                                    None
                                };

                                let Some(answer) = build_multipacket_answer(
                                    &mpreq.file_hash,
                                    &file.name,
                                    file.size,
                                    !file.is_partial,
                                    partial_bitmap.as_deref(),
                                    parse_aich_root_hash(&file.aich_hash_hex),
                                    mpreq.is_ext2,
                                    &mpreq.sub_opcodes,
                                ) else {
                                    debug!(
                                        "Refusing MultiPacket response for {hash_hex}: file exceeds standard ED2K wire part-count limit"
                                    );
                                    write_packet_async(
                                        &mut writer,
                                        OP_EDONKEYHEADER,
                                        OP_FILEREQANSNOFIL,
                                        &mpreq.file_hash,
                                    )
                                    .await?;
                                    continue;
                                };

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
                        let peer = PeerFileAccess {
                            ember_hash: peer_ember_hash,
                            secure_v2_authenticated,
                        };
                        if !self.may_answer_source_exchange(&hash, peer).await {
                            continue;
                        }
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
                        let peer = PeerFileAccess {
                            ember_hash: peer_ember_hash,
                            secure_v2_authenticated,
                        };
                        if !self.may_answer_source_exchange(&hash, peer).await {
                            continue;
                        }
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
                        if let Some(file) = self.resolve_upload_file(&req_hash, PeerFileAccess { ember_hash: peer_ember_hash, secure_v2_authenticated }).await {
                            let cached = {
                                let mut cache = self.aich_cache.lock().await;
                                cache.get(&hash_hex)
                            };
                            let aich_result = if let Some(hs) = cached {
                                Ok(hs)
                            } else if file.is_partial {
                                Err(anyhow::anyhow!("AICH unavailable for partial file"))
                            } else {
                                // Hash the already-pinned upload handle. Reopening
                                // by path would allow a post-resolve symlink swap
                                // to poison the AICH cache under this MD4 key.
                                let mut opened = file.opened;
                                let res = tokio::task::spawn_blocking(move || {
                                    crate::network::ed2k::aich::AICHRecoveryHashSet::build_from_open_file(
                                        &mut opened,
                                    )
                                })
                                .await?;
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
                    if let Some(file) = self.resolve_upload_file(&req_hash, PeerFileAccess { ember_hash: peer_ember_hash, secure_v2_authenticated }).await {
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

                // Late OP_EMULEINFO: the inbound handshake only waits for the
                // *next* packet after Hello. Modern eMule often sends
                // OP_SECIDENTSTATE first (fast path), so ET_MOD_VERSION lands
                // here. Re-merge caps and re-run the anti-leech haystack so
                // VeryCD / easyMule are still caught if they skipped Hello's
                // CT_MODVERSION tag.
                (OP_EMULEPROT, OP_EMULEINFO) | (OP_EMULEPROT, OP_EMULEINFOANSWER) => {
                    merge_caps(&mut hello_caps, parse_emule_info(&payload));
                    ul_client_software = client_software_from_caps(&hello_caps);
                    if opcode == OP_EMULEINFO {
                        let emule_payload = build_emule_info(
                            self.advertised_udp_port(),
                            self.obfuscation_enabled
                                .load(std::sync::atomic::Ordering::Relaxed),
                            Some(&self.ember_hash),
                            None,
                        );
                        let _ = write_packet_async(
                            &mut writer,
                            OP_EMULEPROT,
                            OP_EMULEINFOANSWER,
                            &emule_payload,
                        )
                        .await;
                    }
                    let leech_haystack = crate::security::antileech::match_haystack(
                        &ul_client_software,
                        &hello_caps.mod_version,
                    );
                    let leech_match = self.antileech.read().check(&leech_haystack);
                    if let Some(m) = leech_match {
                        info!(
                            "AntiLeech: rejecting upload session with {peer_addr} after EmuleInfo — \
                             client software {ul_client_software:?} mod {:?} matched pattern {:?}",
                            hello_caps.mod_version,
                            m.pattern,
                        );
                        let _ = write_packet_async(
                            &mut writer,
                            OP_EMULEPROT,
                            OP_QUEUEFULL,
                            &[],
                        )
                        .await;
                        {
                            let mut queue = self.upload_queue.lock().await;
                            queue.retain(|e| {
                                e.identity != queue_identity
                                    || !queue_row_owned_by_session(
                                        e.current_addr,
                                        e.tcp_port,
                                        peer_addr,
                                        hello_caps.tcp_port,
                                    )
                            });
                        }
                        break;
                    }
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
                        let identity_changed = secure_v2_authenticated
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
                            let nickname = self.nickname_snapshot().await;
                            let payload = build_ember_hello(&self.ember_hash, &nickname, Some(&self.ed25519_public_key));
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
                                    if peer_user_hash != [0u8; 16] {
                                        let mut cm = self.credit_manager.write().await;
                                        cm.set_ember_hash(peer_user_hash, *peer_eh);
                                    }
                                    // Unlock mesh + first EPX once HELLO
                                    // binding succeeds (friend privileges
                                    // remain on secure_v2 / PoP).
                                    if hello_caps.is_ember && !mesh_discovered_emitted {
                                        if let std::net::IpAddr::V4(v4) = peer_addr.ip() {
                                            if hello_caps.tcp_port > 0
                                                && !crate::security::is_bogus_v4(v4)
                                            {
                                                let _ = self
                                                    .upload_event_tx
                                                    .send(UploadEvent {
                                                        transfer_id: String::new(),
                                                        kind: UploadEventKind::EmberPeerDiscovered {
                                                            ip: v4,
                                                            tcp_port: hello_caps.tcp_port,
                                                            udp_port: hello_caps.udp_port,
                                                        },
                                                    })
                                                    .await;
                                                mesh_discovered_emitted = true;
                                            }
                                        }
                                    }
                                    if hello_caps.is_ember && !epx_sent_after_binding {
                                        let epx_data = self.ember_payload.read().await.clone();
                                        if !epx_data.is_empty() {
                                            let gen = self
                                                .ember_payload_generation
                                                .load(std::sync::atomic::Ordering::Relaxed);
                                            info!(
                                                "Sending EPX to bound Ember peer {peer_addr} ({} bytes, gen {gen})",
                                                epx_data.len()
                                            );
                                            if write_packet_async(
                                                &mut writer,
                                                OP_EMULEPROT,
                                                OP_EMBER_SOURCEEXCHANGE,
                                                &epx_data,
                                            )
                                            .await
                                            .is_ok()
                                            {
                                                last_epx_generation = gen;
                                                last_epx_resend = std::time::Instant::now();
                                                epx_sent_after_binding = true;
                                                self.epx_overhead
                                                    .record_upload((6 + epx_data.len()) as u64);
                                            }
                                        } else {
                                            epx_sent_after_binding = true;
                                            info!("EPX payload empty, skipping EPX send to {peer_addr}");
                                        }
                                    }
                                } else {
                                    tracing::warn!(
                                        "Ember binding: peer {peer_addr} advertised pubkey does not BLAKE3-bind to ember_hash={} (possible spoof)",
                                        hex::encode(peer_eh)
                                    );
                                }
                            }
                        }

                        // Classic Ember file sockets learn identity here,
                        // after `Started` may already have been emitted
                        // (AddUpNextClient push-grant). Patch the upload
                        // row so the UI's Add Friend action can use the
                        // Ember hash rather than the eD2K user hash.
                        if !identity_emitted {
                            if let (Some(tid), Some(eh)) =
                                (transfer_id.as_ref(), peer_ember_hash)
                            {
                                let _ = self
                                    .upload_event_tx
                                    .send(UploadEvent {
                                        transfer_id: tid.clone(),
                                        kind: UploadEventKind::Identity {
                                            ember_hash: Some(hex::encode(eh)),
                                            client_software: ul_client_software.clone(),
                                            peer_name: ul_peer_name.clone(),
                                        },
                                    })
                                    .await;
                                identity_emitted = true;
                            }
                        }

                        // The early gate above the dispatcher fires before
                        // `OP_EMBER_HELLO`, so classic sessions see
                        // `peer_ember_hash = None` / `is_friend = false`
                        // there. Re-evaluate membership now that the hash
                        // is known. `LEGACY_FRIEND_AUTH_ENABLED` is off, so
                        // AUTH_RESPONSE will never send the request —
                        // ship it here (and on mid-session promotion in
                        // the outer loop). `friend_request_sent` stops the
                        // HELLO + HELLOANSWER duplicate.
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
                                "Sending friend request to Ember peer {peer_addr}"
                            );
                            let nickname = self.nickname_snapshot().await;
                            if write_packet_async(
                                &mut writer,
                                OP_EMULEPROT,
                                OP_EMBER_FRIEND_REQ,
                                nickname.as_bytes(),
                            )
                            .await
                            .is_ok()
                            {
                                friend_request_sent = true;
                            }
                        }
                    }
                }

                // Gated on HELLO + hash↔pubkey binding. Friend/chat still
                // require secure_v2; EPX is mesh/source identity only.
                (OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE)
                    if hello_caps.is_ember && ember_hash_binding_verified =>
                {
                    self.epx_overhead.record_download((6 + payload.len()) as u64);
                    if epx_packets_received >= crate::network::ember::MAX_EPX_PACKETS_PER_CONNECTION {
                        debug!("Ignoring excess EPX packet from uploading peer {peer_addr}");
                    } else {
                        epx_packets_received += 1;
                        match crate::network::ember::parse_exchange_payload(&payload) {
                            Ok(result)
                                if !result.files.is_empty()
                                    || !result.peers.is_empty()
                                    || !result.relay_attestations.is_empty() =>
                            {
                                info!("Received Ember Peer Exchange from uploading peer {peer_addr} ({} files, {} peers, {} relay attestations)", result.files.len(), result.peers.len(), result.relay_attestations.len());
                                let (epx_entries, aich_roots) = super::transfer::epx_result_to_entries(&result);
                                let relay_attestations = result.relay_attestations.clone();
                                let ember_peers = result.peers.into_iter().map(|p| (p.ip, p.tcp_port)).collect();
                                let _ = self.upload_event_tx.send(UploadEvent {
                                    transfer_id: transfer_id.clone().unwrap_or_default(),
                                    kind: UploadEventKind::EmberSources { entries: epx_entries, aich_roots, ember_peers, relay_attestations, from_ember_hash: peer_ember_hash },
                                }).await;
                            }
                            Ok(_) => {}
                            Err(e) => debug!("Failed to parse Ember exchange from {peer_addr}: {e}"),
                        }
                    }
                }

                (OP_EMULEPROT, OP_EMBER_FRIEND_REQ)
                    if hello_caps.is_ember || secure_v2_authenticated =>
                {
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
                        let nick = crate::security::normalize_inbound_friend_nickname(&payload);
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
                        let verified = secure_v2_authenticated;
                        debug!(
                            "Received friend request from {peer_addr} (nickname_chars={}, hash={}, verified={verified}, pop={}, binding={ember_hash_binding_verified})",
                            nick.chars().count(), hex::encode(eh), verified,
                        );
                        let _ = self.upload_event_tx.send(UploadEvent {
                            transfer_id: String::new(),
                            kind: UploadEventKind::EmberFriendRequest {
                                ember_hash: eh,
                                pubkey: hello_caps.ember_pubkey,
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
                    // V1 signed attacker-selected nonces and was usable as a
                    // live cross-session signing oracle.  Parsing remains for
                    // wire compatibility, but no network path signs or
                    // authorizes this opcode in secure-stream v2.
                    debug!("Ignoring retired Ember v1 auth challenge from {peer_addr}");
                }

                (OP_EMULEPROT, OP_EMBER_AUTH_RESPONSE)
                    if super::LEGACY_FRIEND_AUTH_ENABLED =>
                {
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
                            // Feed the mesh now that PoP has verified this
                            // peer (see the gate comment above the
                            // now-dead-at-connect-time `is_ember`-only
                            // emit near the top of this function).
                            if hello_caps.is_ember {
                                if let std::net::IpAddr::V4(v4) = peer_addr.ip() {
                                    if hello_caps.tcp_port > 0
                                        && !crate::security::is_bogus_v4(v4)
                                    {
                                        let _ = self
                                            .upload_event_tx
                                            .send(UploadEvent {
                                                transfer_id: String::new(),
                                                kind: UploadEventKind::EmberPeerDiscovered {
                                                    ip: v4,
                                                    tcp_port: hello_caps.tcp_port,
                                                    udp_port: hello_caps.udp_port,
                                                },
                                            })
                                            .await;
                                        mesh_discovered_emitted = true;
                                    }
                                }
                            }
                            // First EPX push after binding — mirrors download
                            // paths that only share sources once the peer's
                            // advertised key binds to its Ember hash.
                            if hello_caps.is_ember && !epx_sent_after_binding {
                                let epx_data = self.ember_payload.read().await.clone();
                                if !epx_data.is_empty() {
                                    let gen = self
                                        .ember_payload_generation
                                        .load(std::sync::atomic::Ordering::Relaxed);
                                    info!(
                                        "Sending EPX to verified Ember peer {peer_addr} ({} bytes, gen {gen})",
                                        epx_data.len()
                                    );
                                    if write_packet_async(
                                        &mut writer,
                                        OP_EMULEPROT,
                                        OP_EMBER_SOURCEEXCHANGE,
                                        &epx_data,
                                    )
                                    .await
                                    .is_ok()
                                    {
                                        last_epx_generation = gen;
                                        last_epx_resend = std::time::Instant::now();
                                        epx_sent_after_binding = true;
                                        self.epx_overhead
                                            .record_upload((6 + epx_data.len()) as u64);
                                    }
                                } else {
                                    epx_sent_after_binding = true;
                                    info!("EPX payload empty, skipping EPX send to {peer_addr}");
                                }
                            }
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
                                // `hello_caps.ember_pubkey` is guaranteed
                                // `Some` here: PoP just succeeded above,
                                // which requires a pubkey to verify the
                                // peer's signature against.
                                if let (Some(eh), Some(pk)) =
                                    (peer_ember_hash, hello_caps.ember_pubkey)
                                {
                                    let mut sessions = self.ember_sessions.write().await;
                                    // A pre-existing entry might just be a
                                    // stale leftover from a connection that
                                    // died without a clean teardown (see
                                    // `EmberSessionHandle`) — evict it so a
                                    // fresh, actually-verified inbound
                                    // session isn't blocked from claiming
                                    // the slot.
                                    if let Some(stale) =
                                        sessions.get(&eh).filter(|handle| !handle.is_fresh())
                                    {
                                        stale.close();
                                        sessions.remove(&eh);
                                    }
                                    if !sessions.contains_key(&eh) {
                                        let handle =
                                            EmberSessionHandle::new(outbound_tx.clone(), pk);
                                        ember_shutdown_rx = Some(handle.subscribe_shutdown());
                                        ember_session_handle = Some(handle.clone());
                                        sessions.insert(eh, handle);
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
                                    // See the comment on the other `FriendSeen`
                                    // emission in this file for why we prefer the
                                    // Hello listen port here.
                                    let friend_port = if hello_caps.tcp_port > 0 {
                                        hello_caps.tcp_port
                                    } else {
                                        peer_addr.port()
                                    };
                                    let _ = self.upload_event_tx.send(UploadEvent {
                                        transfer_id: String::new(),
                                        kind: UploadEventKind::FriendSeen {
                                            ember_hash: eh,
                                            ip: peer_addr.ip(),
                                            port: friend_port,
                                        },
                                    }).await;
                                }
                            }
                            // Reciprocal friend request only after PoP —
                            // same bar as FriendSeen / EPX / chat.
                            if is_friend && hello_caps.is_ember && !friend_request_sent {
                                info!(
                                    "Sending friend request to verified Ember peer {peer_addr}"
                                );
                                let nickname = self.nickname_snapshot().await;
                                let nick_bytes = nickname.as_bytes();
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
                        Err(e) => {
                            tracing::warn!("Ember auth (responder): rejected RESPONSE from {peer_addr}: {e:?}");
                        }
                    }
                }

                (OP_EMULEPROT, OP_EMBER_AUTH_RESPONSE) => {
                    debug!("Ignoring retired Ember v1 auth response from {peer_addr}");
                }

                // Privilege-bearing Ember friend opcodes (CHAT, BROWSE_*) are
                // gated on secure-v2 + live friend membership only.  Owning
                // the canonical ember_sessions outbound slot is intentionally
                // *not* required: simultaneous mutual dials leave one TCP
                // connection as the map winner and the peer's messages arrive
                // on the non-canonical inbound, which must still process them.
                //
                // `owns_ember_slot` remains meaningful for outbound routing
                // (which `tx` SendChatMessage / BrowseFriend reuse) and for
                // avoiding duplicate map insertions — not for decrypt/auth.
                (OP_EMULEPROT, OP_EMBER_CHAT_MSG)
                    if friend_privileges_allowed(secure_v2_authenticated, is_ember_friend) =>
                {
                    if let Some(eh) = peer_ember_hash {
                        if !self.friend_hashes.read().await.contains(&eh) {
                            debug!("Ignoring chat from removed friend {}", hex::encode(eh));
                        } else if payload.len() > crate::network::ember::crypto::MAX_CHAT_WIRE_LEN {
                            // No ciphertext in logs.  A dedicated UploadEvent +
                            // UI toast requires a network/mod.rs match arm.
                            warn!(
                                "Friend {} chat payload oversized ({} bytes); dropping",
                                hex::encode(eh),
                                payload.len()
                            );
                        } else if let Some(pk) = hello_caps.ember_pubkey {
                            if let Some(msg) = crate::network::ember::crypto::decrypt_chat_payload(
                                &self.ed25519_secret_key,
                                &pk,
                                &payload,
                            ) {
                                let _ = self
                                    .upload_event_tx
                                    .send(UploadEvent {
                                        transfer_id: String::new(),
                                        kind: UploadEventKind::EmberChatMessage {
                                            ember_hash: eh,
                                            message: msg,
                                        },
                                    })
                                    .await;
                            } else {
                                warn!(
                                    "Friend {} chat decrypt failed (len={}); dropping ciphertext",
                                    hex::encode(eh),
                                    payload.len()
                                );
                            }
                        }
                    }
                }

                (OP_EMULEPROT, OP_EMBER_BROWSE_REQ)
                    if friend_privileges_allowed(secure_v2_authenticated, is_ember_friend) =>
                {
                    if let (Some(eh), Some(session)) =
                        (peer_ember_hash, ember_session_handle.as_ref())
                    {
                        if !self.friend_hashes.read().await.contains(&eh) {
                            debug!("Ignoring browse request from removed friend {}", hex::encode(eh));
                        } else {
                            let _ = self.upload_event_tx.send(UploadEvent {
                                transfer_id: String::new(),
                                kind: UploadEventKind::EmberBrowseRequest {
                                    ember_hash: eh,
                                    session_id: session.session_id(),
                                    reply_tx: outbound_tx.clone(),
                                    supports_ebr1:
                                        super::multi_source::browse_request_supports_v1(&payload),
                                },
                            }).await;
                        }
                    }
                }

                (OP_EMULEPROT, OP_EMBER_BROWSE_RES)
                    if friend_privileges_allowed(secure_v2_authenticated, is_ember_friend) =>
                {
                    if let (Some(eh), Some(session)) = (peer_ember_hash, ember_session_handle.as_ref()) {
                        if !self.friend_hashes.read().await.contains(&eh) {
                            debug!("Ignoring browse response from removed friend {}", hex::encode(eh));
                        } else {
                            let entries = super::multi_source::parse_browse_response(&payload);
                            let _ = self.upload_event_tx.send(UploadEvent {
                                transfer_id: String::new(),
                                kind: UploadEventKind::EmberBrowseResponse {
                                    ember_hash: eh,
                                    session_id: session.session_id(),
                                    entries,
                                },
                            }).await;
                        }
                    }
                }

                (OP_EMULEPROT, OP_EMBER_XFER_REQ)
                    if friend_privileges_allowed(secure_v2_authenticated, is_ember_friend) =>
                {
                    if let Some(eh) = peer_ember_hash {
                        if !self.friend_hashes.read().await.contains(&eh) {
                            debug!(
                                "Ignoring transfer request from removed friend {}",
                                hex::encode(eh)
                            );
                        } else if let Some(request) = parse_ember_xfer_req(&payload) {
                            let _ = self
                                .upload_event_tx
                                .send(UploadEvent {
                                    transfer_id: String::new(),
                                    kind: UploadEventKind::EmberTransferRequest {
                                        ember_hash: eh,
                                        request,
                                        reply_tx: outbound_tx.clone(),
                                        peer_addr,
                                    },
                                })
                                .await;
                        } else {
                            // Malformed, or a method this build predates. We
                            // cannot echo a nonce we failed to parse, so the
                            // requester falls back to its own attempt timeout.
                            debug!(
                                "Friend {} sent an unparseable OP_EMBER_XFER_REQ ({} bytes)",
                                hex::encode(eh),
                                payload.len()
                            );
                        }
                    }
                }

                (OP_EMULEPROT, OP_EMBER_XFER_ACK)
                    if friend_privileges_allowed(secure_v2_authenticated, is_ember_friend) =>
                {
                    if let Some(eh) = peer_ember_hash {
                        if let Some((status, nonce)) = parse_ember_xfer_ack(&payload) {
                            let _ = self
                                .upload_event_tx
                                .send(UploadEvent {
                                    transfer_id: String::new(),
                                    kind: UploadEventKind::EmberTransferAck {
                                        ember_hash: eh,
                                        status,
                                        nonce,
                                    },
                                })
                                .await;
                        }
                    }
                }

                (OP_EMULEPROT, super::messages::OP_EMBER_EXT)
                    if friend_privileges_allowed(secure_v2_authenticated, is_ember_friend) =>
                {
                    if let Some(eh) = peer_ember_hash {
                        match super::messages::parse_ember_ext(&payload) {
                            Some((super::messages::EMBER_EXT_RELAY_OFFER, body)) => {
                                // Parsed here but verified in the network loop,
                                // which owns the broker. Nothing is trusted at
                                // this point: a forwarded attestation is just
                                // bytes until its own signature checks out.
                                let attestations =
                                    crate::network::ember::parse_relay_attestation_block(body);
                                if !attestations.is_empty() {
                                    let _ = self
                                        .upload_event_tx
                                        .send(UploadEvent {
                                            transfer_id: String::new(),
                                            kind: UploadEventKind::EmberRelayOffer {
                                                ember_hash: eh,
                                                attestations,
                                            },
                                        })
                                        .await;
                                }
                            }
                            // A sub-type this build predates. Ignoring it is
                            // the whole point of the envelope.
                            Some((other, _)) => debug!(
                                "Friend {} sent unknown OP_EMBER_EXT sub-type {other:#04x}",
                                hex::encode(eh)
                            ),
                            None => debug!(
                                "Friend {} sent an empty OP_EMBER_EXT payload",
                                hex::encode(eh)
                            ),
                        }
                    }
                }

                (OP_EMULEPROT, OP_EMBER_FILE_OFFER)
                    if friend_privileges_allowed(secure_v2_authenticated, is_ember_friend) =>
                {
                    if let (Some(eh), Some(reply_tx)) =
                        (peer_ember_hash, ember_session_handle.as_ref().map(|h| h.tx.clone()))
                    {
                        if let Some(offer) =
                            super::messages::parse_ember_file_offer(&payload)
                        {
                            let _ = self
                                .upload_event_tx
                                .send(UploadEvent {
                                    transfer_id: String::new(),
                                    kind: UploadEventKind::EmberFileOffer {
                                        ember_hash: eh,
                                        offer,
                                        reply_tx,
                                    },
                                })
                                .await;
                        }
                    }
                }

                (OP_EMULEPROT, OP_EMBER_FILE_OFFER_ACK)
                    if friend_privileges_allowed(secure_v2_authenticated, is_ember_friend) =>
                {
                    if let Some(eh) = peer_ember_hash {
                        if let Some((status, file_hash)) =
                            super::messages::parse_ember_file_offer_ack(&payload)
                        {
                            let _ = self
                                .upload_event_tx
                                .send(UploadEvent {
                                    transfer_id: String::new(),
                                    kind: UploadEventKind::EmberFileOfferAck {
                                        ember_hash: eh,
                                        status,
                                        file_hash,
                                    },
                                })
                                .await;
                        }
                    }
                }

                (OP_EMULEPROT, OP_EMBER_KEEPALIVE) if is_ember_friend && secure_v2_authenticated => {}

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

        if let (true, Some(eh), Some(session)) = (
            owns_ember_slot,
            peer_ember_hash,
            ember_session_handle.as_ref(),
        ) {
            let session_id = session.session_id();
            let mut sessions = self.ember_sessions.write().await;
            let remove_current = sessions
                .get(&eh)
                .is_some_and(|current| current.tx.same_channel(&session.tx));
            if remove_current {
                sessions.remove(&eh);
            }
            drop(sessions);
            let _ = self
                .upload_event_tx
                .send(UploadEvent {
                    transfer_id: String::new(),
                    kind: UploadEventKind::EmberFriendDisconnected {
                        ember_hash: eh,
                        session_id,
                    },
                })
                .await;
        }

        // Keep queued peers on disconnect, but mark them disconnected
        // only when this socket is the one bound to the row. Matching on
        // identity alone would let a hash-spoofer connect and hang up,
        // clearing a still-connected victim's `current_addr`. eMule
        // preserves LowID/disconnected queue entries until the normal
        // purge window; immediate removal destroys seniority and makes
        // the `add_next_connect` fast path unreachable. The queue's
        // 1-hour purge cap bounds stale entries.
        {
            let mut queue = self.upload_queue.lock().await;
            queue.retain_mut(|e| {
                if e.identity != queue_identity {
                    return true;
                }
                if e.current_addr == Some(peer_addr) {
                    e.current_addr = None;
                }
                true
            });
        }

        self.slot_rates.lock().remove(&peer_addr);

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
            let verified = secure_v2_authenticated;
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
                upload_session_completed(
                    unique_served_bytes(&served_bytes_per_part, total_size),
                    total_size,
                )
            } else if let Err(e) = &session_result {
                UploadEventKind::Failed {
                    error: format!("Session ended: {e}"),
                }
            } else {
                UploadEventKind::Failed {
                    error: "Peer disconnected before any data transferred".to_string(),
                }
            };
            let _ = self
                .upload_event_tx
                .send(UploadEvent {
                    transfer_id: tid.clone(),
                    kind,
                })
                .await;
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

    /// Acquire upload tokens, aborting promptly if the network disconnects
    /// while parked in the token bucket (tight limits can otherwise stall
    /// teardown for many seconds after Disconnect).
    async fn acquire_upload_bandwidth(&self, bytes: u64) -> anyhow::Result<()> {
        if self
            .network_disconnected
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            anyhow::bail!("network disconnected");
        }
        tokio::select! {
            ok = self.bandwidth_limiter.acquire_upload(bytes) => {
                if ok {
                    Ok(())
                } else {
                    anyhow::bail!("bandwidth limiter stopped")
                }
            }
            _ = async {
                loop {
                    if self.network_disconnected.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            } => {
                anyhow::bail!("network disconnected");
            }
        }
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
            payload[starts_offset + i * 8..starts_offset + i * 8 + 8].try_into()?,
        );
        let end =
            u64::from_le_bytes(payload[ends_offset + i * 8..ends_offset + i * 8 + 8].try_into()?);
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

fn encode_legacy_hashset_response(file_hash: &[u8; 16], hashes: &[[u8; 16]]) -> Option<Vec<u8>> {
    let count = u16::try_from(hashes.len()).ok()?;
    let mut response = Vec::with_capacity(16 + 2 + hashes.len() * 16);
    response.extend_from_slice(file_hash);
    response.extend_from_slice(&count.to_le_bytes());
    for hash in hashes {
        response.extend_from_slice(hash);
    }
    Some(response)
}

fn encode_hashset2_response(
    identifier: &FileIdentifier,
    md4_hashes: Option<&[[u8; 16]]>,
    aich_section: Option<([u8; 20], &[[u8; 20]])>,
) -> Option<Vec<u8>> {
    // Reject the full answer when a requested section cannot be represented:
    // omitting it silently would make a peer treat the reply as complete,
    // while serializing `as u16` would wrap the count and corrupt framing.
    let md4_count = match md4_hashes {
        Some(hashes) => Some(u16::try_from(hashes.len()).ok()?),
        None => None,
    };
    let aich_count = match aich_section.as_ref() {
        Some((_, hashes)) => Some(u16::try_from(hashes.len()).ok()?),
        None => None,
    };

    let mut response = Vec::new();
    identifier.write_identifier(&mut response);
    let mut options = 0u8;
    if md4_count.is_some() {
        options |= 0x01;
    }
    if aich_count.is_some() {
        options |= 0x02;
    }
    response.push(options);
    if let (Some(hashes), Some(count)) = (md4_hashes, md4_count) {
        response.extend_from_slice(&identifier.md4_hash);
        response.extend_from_slice(&count.to_le_bytes());
        for hash in hashes {
            response.extend_from_slice(hash);
        }
    }
    if let (Some((root, hashes)), Some(count)) = (aich_section, aich_count) {
        response.extend_from_slice(&root);
        response.extend_from_slice(&count.to_le_bytes());
        for hash in hashes {
            response.extend_from_slice(hash);
        }
    }
    Some(response)
}

fn read_upload_block(
    mut file: std::fs::File,
    start: u64,
    len: usize,
) -> anyhow::Result<(std::fs::File, Vec<u8>)> {
    file.seek(SeekFrom::Start(start))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    Ok((file, buf))
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
            payload[starts_offset + i * 4..starts_offset + i * 4 + 4].try_into()?,
        ) as u64;
        let end =
            u32::from_le_bytes(payload[ends_offset + i * 4..ends_offset + i * 4 + 4].try_into()?)
                as u64;
        if start > 0 || end > 0 {
            offsets.push((start, end));
        }
    }
    Ok(offsets)
}

fn compute_part_hashes(file: &mut std::fs::File) -> anyhow::Result<Vec<[u8; 16]>> {
    use digest::Digest;
    use md4::Md4;

    file.seek(SeekFrom::Start(0))?;
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
    let mut payload = Vec::new();
    if payload_len > 0 {
        // Grow as bytes arrive instead of eagerly allocating the full declared
        // length (up to 512 KiB) so a slow/hostile peer can't pin that memory
        // per upload slot before sending anything.
        payload.reserve(payload_len.min(64 * 1024));
        let mut remaining = payload_len;
        let mut chunk = [0u8; 32 * 1024];
        while remaining > 0 {
            let want = remaining.min(chunk.len());
            reader.read_exact(&mut chunk[..want]).await?;
            payload.extend_from_slice(&chunk[..want]);
            remaining -= want;
        }
    }
    if protocol == OP_PACKEDPROT {
        let mut decoder = flate2::read::ZlibDecoder::new(&payload[..]);
        let mut unpacked = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = decoder.read(&mut buf).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("packed decode failed: {e}"),
                )
            })?;
            if n == 0 {
                break;
            }
            unpacked.extend_from_slice(&buf[..n]);
            if unpacked.len() > 1024 * 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "packed packet decompressed size exceeds limit",
                ));
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
    let mut payload = Vec::new();
    if payload_len > 0 {
        // Grow as bytes arrive instead of eagerly allocating the full declared
        // length (up to 512 KiB) so a slow/hostile peer can't pin that memory
        // per upload slot before sending anything.
        payload.reserve(payload_len.min(64 * 1024));
        let mut remaining = payload_len;
        let mut chunk = [0u8; 32 * 1024];
        while remaining > 0 {
            let want = remaining.min(chunk.len());
            reader.read_exact(&mut chunk[..want]).await?;
            payload.extend_from_slice(&chunk[..want]);
            remaining -= want;
        }
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
mod unique_served_tests {
    use super::*;

    #[test]
    fn unique_served_bytes_caps_each_part_so_rerequests_do_not_fill_the_file() {
        let total = PARTSIZE + 1_000;
        // First part served twice; last part only half-done.
        let served = vec![PARTSIZE.saturating_mul(2), 500u64];
        assert_eq!(unique_served_bytes(&served, total), PARTSIZE + 500);
        assert!(
            unique_served_bytes(&served, total) < total,
            "re-requests must not make unique coverage look complete"
        );
    }

    #[test]
    fn unique_served_bytes_empty_or_unknown_size_is_zero() {
        assert_eq!(unique_served_bytes(&[PARTSIZE], 0), 0);
        assert_eq!(unique_served_bytes(&[], PARTSIZE), 0);
    }

    #[test]
    fn already_sent_ranges_are_dropped_on_exact_match_only() {
        let sent = HashSet::from([(0, EMBLOCKSIZE), (EMBLOCKSIZE, EMBLOCKSIZE * 2)]);
        let offsets = vec![
            (0, EMBLOCKSIZE),
            (EMBLOCKSIZE * 2, EMBLOCKSIZE * 3),
            (EMBLOCKSIZE, EMBLOCKSIZE * 2),
            (0, EMBLOCKSIZE + 1),
        ];
        assert_eq!(
            filter_already_sent_ranges(offsets, &sent),
            vec![(EMBLOCKSIZE * 2, EMBLOCKSIZE * 3), (0, EMBLOCKSIZE + 1)]
        );
    }

    #[test]
    fn already_sent_filter_is_noop_when_nothing_has_been_sent() {
        let sent = HashSet::new();
        let offsets = vec![(0, 100), (100, 200)];
        assert_eq!(filter_already_sent_ranges(offsets.clone(), &sent), offsets);
    }

    #[test]
    fn padding_only_requestparts_still_reset_idle_but_garbage_does_not() {
        let fresh = std::time::Duration::from_secs(1);
        assert!(requestparts_resets_idle(1, 0, fresh));
        assert!(requestparts_resets_idle(0, 3, fresh));
        assert!(requestparts_resets_idle(180 * 1024, 2, fresh));
        assert!(!requestparts_resets_idle(0, 0, fresh));
    }

    /// Padding keeps a pipelined peer's slot, but must not keep the slot of a
    /// peer that stopped taking data: re-asking for ranges it already has was
    /// enough to defeat `SLOT_IDLE_TIMEOUT_SECS` entirely, leaving the hour-long
    /// session cap as the only limit — and that only applies with a queue.
    #[test]
    fn padding_stops_holding_the_slot_once_real_bytes_go_stale() {
        let stale = PADDING_KEEPALIVE_WINDOW + std::time::Duration::from_secs(1);
        assert!(
            !requestparts_resets_idle(0, 3, stale),
            "padding alone must not renew a slot that has moved no bytes for the whole window"
        );
        // Real bytes in the same batch still count, however old the last ones were.
        assert!(requestparts_resets_idle(180 * 1024, 3, stale));
        // And a peer being served continuously is never affected.
        assert!(requestparts_resets_idle(
            0,
            3,
            PADDING_KEEPALIVE_WINDOW - std::time::Duration::from_secs(1)
        ));
    }
}

#[cfg(test)]
mod friends_only_snapshot_tests {
    use super::*;

    #[test]
    fn known_met_hash_is_visible_after_replace_and_gone_after_clear() {
        let set: SharedFriendsOnlyHashes = Arc::new(std::sync::RwLock::new(Default::default()));
        let hash = [0xABu8; 16];
        assert!(
            !friends_only_snapshot_contains(&set, &hash),
            "empty snapshot must not restrict a hash"
        );
        assert!(
            !friends_only_snapshot_ready(&set),
            "snapshot must stay unread until known.met is absorbed"
        );
        replace_friends_only_hashes(&set, [hash]);
        assert!(
            friends_only_snapshot_contains(&set, &hash),
            "upload listener must see a known.met friends-only hash"
        );
        assert!(
            !friends_only_snapshot_ready(&set),
            "replacing hashes must not imply the catalog has been absorbed"
        );
        assert!(
            !friends_only_snapshot_contains(&set, &[0xCD; 16]),
            "unrelated hashes stay unrestricted"
        );
        mark_friends_only_snapshot_ready(&set);
        assert!(friends_only_snapshot_ready(&set));
        replace_friends_only_hashes(&set, std::iter::empty());
        assert!(
            !friends_only_snapshot_contains(&set, &hash),
            "clearing friends-only must lift the upload restriction"
        );
        assert!(
            friends_only_snapshot_ready(&set),
            "clearing hashes must not un-ready the snapshot"
        );
    }

    #[test]
    fn index_miss_is_restricted_until_snapshot_is_ready() {
        assert!(
            friends_only_from_sources(false, false, None),
            "known.met-only hashes must not be treated as public before absorb"
        );
        assert!(
            !friends_only_from_sources(false, true, None),
            "after absorb, an index miss that is not in the snapshot is public"
        );
        assert!(friends_only_from_sources(true, false, Some(false)));
        assert!(
            friends_only_from_sources(false, false, Some(false)),
            "index false is not trusted until the snapshot is ready"
        );
        assert!(friends_only_from_sources(false, true, Some(true)));
        assert!(
            !friends_only_from_sources(false, true, Some(false)),
            "after absorb, a public index row is public"
        );
    }
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
    use crate::network::ed2k::credits::{
        CreditManager, IdentState, EMBER_RELIABILITY_MAX, EMBER_RELIABILITY_MIN,
        EMBER_SPEED_BASELINE_BPS,
    };
    use crate::search::index::LocalIndex;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn addr() -> Option<SocketAddr> {
        Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            4662,
        ))
    }

    #[test]
    fn hashset_encoders_refuse_counts_that_do_not_fit_u16() {
        let md4_hashes = vec![[0x11; 16]; u16::MAX as usize + 1];
        let aich_hashes = vec![[0x22; 20]; u16::MAX as usize + 1];
        let file_hash = [0x33; 16];
        let identifier = FileIdentifier {
            md4_hash: file_hash,
            file_size: Some(1),
            aich_hash: None,
        };

        assert!(encode_legacy_hashset_response(&file_hash, &md4_hashes).is_none());
        assert!(
            encode_hashset2_response(&identifier, Some(&md4_hashes), None).is_none(),
            "HashSet2 MD4 section must not wrap its count"
        );
        assert!(
            encode_hashset2_response(&identifier, None, Some(([0x44; 20], &aich_hashes))).is_none(),
            "HashSet2 AICH section must not wrap its count"
        );
    }

    /// `unshared_purge_hashes` is the decision core of the periodic
    /// "file no longer offered" queue sweep (eMule's file-gone purge). It must
    /// evict a waiting peer only when the requested file is gone from BOTH the
    /// shared index and the download set — never while we're still sharing it
    /// or partial-seeding it mid-download — and must always leave the all-zero
    /// placeholder hash (peer queued before naming a file) alone.
    #[test]
    fn unshared_purge_keeps_shared_and_downloading_drops_orphans() {
        let shared_hash = [0x11u8; 16];
        let downloading_hash = [0x22u8; 16];
        let orphan_hash = [0x33u8; 16];
        let placeholder = [0u8; 16];

        let queued = [shared_hash, downloading_hash, orphan_hash, placeholder];
        let shared: std::collections::HashSet<[u8; 16]> = [shared_hash].into_iter().collect();
        let downloading: std::collections::HashSet<[u8; 16]> =
            [downloading_hash].into_iter().collect();

        let evict = unshared_purge_hashes(
            queued.iter(),
            |h| shared.contains(h),
            |h| downloading.contains(h),
        );

        assert_eq!(evict.len(), 1, "only the orphan should be evicted");
        assert!(evict.contains(&orphan_hash), "orphaned file must be purged");
        assert!(!evict.contains(&shared_hash), "shared file must be kept");
        assert!(
            !evict.contains(&downloading_hash),
            "partial-seeded download must be kept"
        );
        assert!(
            !evict.contains(&placeholder),
            "all-zero placeholder hash must never be purged"
        );
    }

    /// When every queued file is still accounted for (shared or downloading)
    /// the sweep evicts nothing.
    #[test]
    fn unshared_purge_empty_when_all_accounted_for() {
        let a = [0xAAu8; 16];
        let b = [0xBBu8; 16];
        let queued = [a, b];
        let shared: std::collections::HashSet<[u8; 16]> = [a].into_iter().collect();
        let downloading: std::collections::HashSet<[u8; 16]> = [b].into_iter().collect();

        let evict = unshared_purge_hashes(
            queued.iter(),
            |h| shared.contains(h),
            |h| downloading.contains(h),
        );

        assert!(evict.is_empty(), "nothing orphaned -> nothing purged");
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
            &cm,
            &idx,
            &user_hash,
            [0u8; 16],
            300,
            addr(),
            /* emule_version */ 0x42,
            /* is_friend_slot */ false,
            /* ember_pubkey */ None,
            /* ember_verified */ false,
        );
        let ember_score = score_queue_entry(
            &cm,
            &idx,
            &user_hash,
            [0u8; 16],
            300,
            addr(),
            0x42,
            false,
            Some(&pubkey),
            true,
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
            &cm,
            &idx,
            &user_hash,
            [0u8; 16],
            300,
            addr(),
            0x42,
            false,
            Some(&pubkey),
            false,
        );
        let emule_only = score_queue_entry(
            &cm,
            &idx,
            &user_hash,
            [0u8; 16],
            300,
            addr(),
            0x42,
            false,
            None,
            false,
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
            &cm,
            &idx,
            &user_hash,
            [0u8; 16],
            300,
            addr(),
            0x42,
            false,
            None,
            true,
        );
        let baseline = score_queue_entry(
            &cm,
            &idx,
            &user_hash,
            [0u8; 16],
            300,
            addr(),
            0x42,
            false,
            None,
            false,
        );
        assert_eq!(
            with_none, baseline,
            "None pubkey must take eMule path regardless of verified flag"
        );
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
            &cm,
            &idx,
            &user_hash,
            [0u8; 16],
            300,
            addr(),
            0x42,
            /* is_friend_slot */ true,
            Some(&pubkey),
            true,
        );
        let emule_friend_score = score_queue_entry(
            &cm,
            &idx,
            &user_hash,
            [0u8; 16],
            300,
            addr(),
            0x42,
            true,
            None,
            false,
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
        let bad_addr = Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            4662,
        ));
        cm.check_identity_ip(user_hash, 0x0A000001); // 10.0.0.1 pinned

        let score = score_queue_entry(
            &cm,
            &idx,
            &user_hash,
            [0u8; 16],
            300,
            bad_addr,
            /* emule_version */ 0,
            false,
            Some(&pubkey),
            true,
        );
        assert_eq!(
            score, 0.0,
            "BadGuy short-circuit must zero both routing paths"
        );
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
        let good_addr = Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            4662,
        ));
        let bad_addr = Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            4662,
        ));

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
            &cm,
            &idx,
            &good_user,
            [0u8; 16],
            300,
            good_addr,
            0,
            false,
            Some(&good_pk),
            true,
        );
        let bad = score_queue_entry(
            &cm,
            &idx,
            &bad_user,
            [0u8; 16],
            300,
            bad_addr,
            0,
            false,
            Some(&bad_pk),
            true,
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

    #[test]
    fn soft_zone_admits_high_combined_without_wait() {
        // Newcomers scored with wait=0 must still enter soft-zone when their
        // CombinedFilePrioAndCredit beats the average (eMule AddClientToQueue).
        assert!(soft_zone_should_admit(false, 100.0, 50.0));
        assert!(!soft_zone_should_admit(false, 10.0, 50.0));
        assert!(
            soft_zone_should_admit(true, 0.0, 999.0),
            "verified friend bypasses soft zone"
        );
        assert!(
            soft_zone_should_admit(false, 50.0, 50.0),
            "equal combined is admitted"
        );
    }

    #[test]
    fn combined_prio_ignores_wait_and_scales_with_ratio() {
        let mut cm = CreditManager::new();
        let idx = LocalIndex::new();
        let user = [0xABu8; 16];
        seed_emule_credits(&mut cm, user);
        let peer_ip = u32::from_be_bytes([10, 0, 0, 1]);
        let low = combined_file_prio_and_credit(&cm, &idx, &user, [0u8; 16], peer_ip, None, false);
        // Unknown file → prio 7 → combined = 10 * ratio * 7
        assert!(
            low > 0.0,
            "combined must be wait-independent and non-zero for credited peers"
        );
        let ratio = cm.get_score_ratio(&user, peer_ip);
        let expected = 10.0 * ratio * 7.0;
        assert!(
            (low - expected).abs() < 0.01,
            "got {low}, expected ~{expected}"
        );
    }

    #[test]
    fn path_b_divert_prefers_exact_hash_and_rejects_zero_hash_collision() {
        let file_a = [0x11u8; 16];
        let file_b = [0x22u8; 16];
        let user_a = [0xAAu8; 16];
        let user_b = [0xBBu8; 16];
        // Index rebuild stores zero hashes as None via reconnect_user_hash.
        let normalized = vec![
            (file_a, reconnect_user_hash(Some(user_a))),
            (file_b, reconnect_user_hash(Some([0u8; 16]))),
        ];
        assert_eq!(normalized[1].1, None);
        assert_eq!(path_b_divert_file(&normalized, user_a), Some(file_a));
        // Unknown peer Hello may match unknown-hash OnQueue rows only.
        assert_eq!(path_b_divert_file(&normalized, [0u8; 16]), Some(file_b));
        // Different known user must not steal via the unknown-hash fallback
        // while another known-hash entry exists at this IP.
        assert_eq!(path_b_divert_file(&normalized, user_b), None);
        let unknown_only = vec![(file_b, None)];
        assert_eq!(path_b_divert_file(&unknown_only, [0u8; 16]), Some(file_b));
    }

    #[test]
    fn peer_high_id_classification_trusts_client_id() {
        let addr: SocketAddr = "8.8.8.8:4662".parse().unwrap();
        let mut caps = PeerCapabilities::default();
        caps.tcp_port = 4662;

        // Real LowID must NOT become dialable just because tcp_port is set.
        caps.client_id = 12345; // < LOWID_THRESHOLD
        assert!(!peer_is_high_id_for_queue(&caps, addr));

        caps.client_id = crate::network::ed2k::server::LOWID_THRESHOLD;
        assert!(peer_is_high_id_for_queue(&caps, addr));

        // Omitted client_id: port + public IP heuristic.
        caps.client_id = 0;
        assert!(peer_is_high_id_for_queue(&caps, addr));

        let lan: SocketAddr = "192.168.1.2:4662".parse().unwrap();
        assert!(!peer_is_high_id_for_queue(&caps, lan));
    }
}

#[cfg(test)]
mod browse_answer_tests {
    //! Wire-format tests for `OP_ASKSHAREDFILESANSWER` (native eMule/ed2k
    //! "View Files" browse). These lock down the exact byte layout so a
    //! future refactor can't silently break interop with real eMule/aMule
    //! clients without a failing test.
    use super::*;

    /// One small file must produce exactly: count=1, then
    /// `<hash 16><id 4><port 2>`, then `tag_count=2` covering FT_FILENAME
    /// (string) and FT_FILESIZE (uint32) — no FT_FILESIZE_HI since the file
    /// is well under the large-file boundary, and no FT_FILETYPE since the
    /// extension is unrecognized.
    #[test]
    fn encodes_single_small_file_with_expected_tags() {
        let hash_hex = "00112233445566778899aabbccddeeff".to_string(); // 16 bytes
        let files = vec![(
            hash_hex.clone(),
            "movie.unknownext".to_string(),
            12345u64,
            "unknownext".to_string(),
        )];

        let payload =
            encode_shared_files_answer(&files, 0x0100A8C0 /* 192.168.0.1 LE */, 4662);

        let mut pos = 0usize;
        let count = u32::from_le_bytes(payload[pos..pos + 4].try_into().unwrap());
        pos += 4;
        assert_eq!(count, 1, "one shared file should yield count=1");

        let hash_bytes = hex::decode(&hash_hex).unwrap();
        assert_eq!(
            &payload[pos..pos + 16],
            &hash_bytes[..16],
            "hash must round-trip byte-for-byte"
        );
        pos += 16;

        let id = u32::from_le_bytes(payload[pos..pos + 4].try_into().unwrap());
        assert_eq!(
            id, 0x0100A8C0,
            "client id must be our real id, not a magic compression id"
        );
        pos += 4;

        let port = u16::from_le_bytes(payload[pos..pos + 2].try_into().unwrap());
        assert_eq!(port, 4662);
        pos += 2;

        let tag_count = u32::from_le_bytes(payload[pos..pos + 4].try_into().unwrap());
        assert_eq!(tag_count, 2, "expected FT_FILENAME + FT_FILESIZE only");
        pos += 4;

        // FT_FILENAME: type=0x02 (string), name_len=1, name_id=0x01, then u16 len + bytes.
        assert_eq!(payload[pos], 0x02);
        pos += 1;
        assert_eq!(
            u16::from_le_bytes(payload[pos..pos + 2].try_into().unwrap()),
            1
        );
        pos += 2;
        assert_eq!(payload[pos], 0x01);
        pos += 1;
        let name_len = u16::from_le_bytes(payload[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        assert_eq!(&payload[pos..pos + name_len], b"movie.unknownext");
        pos += name_len;

        // FT_FILESIZE: type=0x03 (uint32), name_len=1, name_id=0x02, u32 value.
        assert_eq!(payload[pos], 0x03);
        pos += 1;
        assert_eq!(
            u16::from_le_bytes(payload[pos..pos + 2].try_into().unwrap()),
            1
        );
        pos += 2;
        assert_eq!(payload[pos], 0x02);
        pos += 1;
        let size = u32::from_le_bytes(payload[pos..pos + 4].try_into().unwrap());
        assert_eq!(size, 12345);
        pos += 4;

        assert_eq!(pos, payload.len(), "no trailing/missing bytes");
    }

    /// Files above `OLD_MAX_EMULE_FILE_SIZE` must carry an extra
    /// FT_FILESIZE_HI (0x3A) tag with the high 32 bits, matching
    /// `offer_files_chunk`'s large-file handling exactly.
    #[test]
    fn large_file_gets_filesize_hi_tag() {
        let hash_hex = "11".repeat(16);
        let big_size = OLD_MAX_EMULE_FILE_SIZE + (5u64 << 32) + 42;
        let files = vec![(hash_hex, "big.iso".to_string(), big_size, "iso".to_string())];

        let payload = encode_shared_files_answer(&files, 0, 4662);

        // count(4) + hash(16) + id(4) + port(2) + tag_count(4)
        let tag_count = u32::from_le_bytes(payload[26..30].try_into().unwrap());
        // FT_FILENAME + FT_FILESIZE + FT_FILESIZE_HI + FT_FILETYPE (iso -> "Iso")
        assert_eq!(tag_count, 4);

        // FT_FILESIZE_HI tag header: type=0x03 (uint32), name_len=1 (LE u16:
        // 0x01, 0x00), name_id=0x3A — scan for that exact 4-byte header
        // followed by the expected high-32-bits value (5).
        let hi_value = 5u32.to_le_bytes();
        let hi_tag_present = payload
            .windows(8)
            .any(|w| w[0..4] == [0x03, 0x01, 0x00, 0x3A] && w[4..8] == hi_value);
        assert!(
            hi_tag_present,
            "expected an FT_FILESIZE_HI (0x3A) uint32 tag with value 5 for a >4GB file"
        );
    }

    /// An unshared / non-decodable hash must be skipped without aborting
    /// the whole answer — one bad index row shouldn't hide every other
    /// legitimately shared file from the requester.
    #[test]
    fn skips_entries_with_invalid_hash() {
        let good_hash = "aa".repeat(16);
        let files = vec![
            (
                "not-hex".to_string(),
                "bad.txt".to_string(),
                10,
                "txt".to_string(),
            ),
            (
                good_hash.clone(),
                "good.txt".to_string(),
                10,
                "txt".to_string(),
            ),
        ];

        let payload = encode_shared_files_answer(&files, 0, 4662);
        let count = u32::from_le_bytes(payload[0..4].try_into().unwrap());
        assert_eq!(
            count, 1,
            "the invalid-hash entry must be skipped, not counted"
        );
        assert_eq!(
            &payload[4..20],
            &hex::decode(good_hash).unwrap()[..],
            "surviving entry must be the good one"
        );
    }

    /// No shared files -> a well-formed empty answer (count=0), matching
    /// real eMule's behavior of answering with an empty list rather than
    /// treating "nothing shared" as a denial.
    #[test]
    fn empty_share_list_encodes_zero_count() {
        let payload = encode_shared_files_answer(&[], 0, 4662);
        assert_eq!(payload.len(), 4);
        assert_eq!(u32::from_le_bytes(payload[..4].try_into().unwrap()), 0);
    }

    /// A pathologically large shared library must not produce a payload
    /// that can never be delivered: our own inbound frame reader
    /// (`read_packet_with_first_byte`) rejects any packet over 512 KiB
    /// outright, so `encode_shared_files_answer`'s internal byte budget
    /// must keep the *encoded* payload comfortably under that regardless
    /// of how many files are passed in — and it must still emit a
    /// well-formed, fully-decodable prefix (truncated count matches the
    /// number of entries actually written) rather than a partial/corrupt
    /// tail.
    #[test]
    fn huge_share_list_is_truncated_under_frame_size_limit() {
        let files: Vec<_> = (0..50_000u32)
            .map(|i| {
                (
                    format!("{i:032x}"),
                    format!("a-reasonably-long-file-name-{i}.mkv"),
                    123_456_789u64,
                    "mkv".to_string(),
                )
            })
            .collect();

        let payload = encode_shared_files_answer(&files, 0, 4662);

        assert!(
            payload.len() < 512 * 1024,
            "encoded answer must stay under the 512 KiB inbound frame cap, got {} bytes",
            payload.len()
        );

        let count = u32::from_le_bytes(payload[0..4].try_into().unwrap());
        assert!(
            (count as usize) < files.len(),
            "50,000 files with long names must be truncated, not all included"
        );
        assert!(count > 0, "truncation must still leave at least one entry");

        // The declared count must match how many entries are actually
        // decodable from the payload — i.e. truncation happened at an
        // entry boundary, not mid-entry. Tag layout per `write_ed2k_tag`:
        // type(1) + name_len(2, always 1) + name_id(1) + value, where
        // value is a u16-prefixed string for type 0x02 or a raw u32 for
        // type 0x03 (the only two tag types this encoder emits).
        let mut pos = 4usize;
        let mut decoded = 0u32;
        while pos < payload.len() {
            pos += 16 + 4 + 2; // hash + client_id + port
            let tag_count = u32::from_le_bytes(payload[pos..pos + 4].try_into().unwrap());
            pos += 4;
            for _ in 0..tag_count {
                let tag_type = payload[pos];
                pos += 3; // type(1) + name_len(2, unused: always 1)
                pos += 1; // name_id(1)
                match tag_type {
                    0x02 => {
                        let str_len =
                            u16::from_le_bytes(payload[pos..pos + 2].try_into().unwrap()) as usize;
                        pos += 2 + str_len;
                    }
                    0x03 => pos += 4,
                    other => panic!("unexpected tag type {other} in test payload"),
                }
            }
            decoded += 1;
        }
        assert_eq!(
            decoded, count,
            "declared count must match the number of fully-decodable entries"
        );
    }
}

#[cfg(test)]
mod ember_session_handle_tests {
    //! Regression coverage for `med-ember-sessions-stale`: a session whose
    //! peer went silently unreachable must stop being trusted by
    //! `is_fresh()` well before the ~4.5 min `STALL_TIMEOUT` in
    //! `friend_connect.rs` finally tears it down, and `evict_stale_ember_session`
    //! must reclaim exactly (and only) such entries.
    use super::*;

    #[tokio::test]
    async fn fresh_handle_reports_fresh_until_backdated() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let handle = EmberSessionHandle::new(tx, [0u8; 32]);
        assert!(handle.is_fresh(), "a just-created handle must be fresh");

        handle.backdate_for_test(EMBER_SESSION_FRESH_SECS + 1);
        assert!(
            !handle.is_fresh(),
            "a handle with no activity in > EMBER_SESSION_FRESH_SECS must be stale"
        );
    }

    #[tokio::test]
    async fn touch_refreshes_a_backdated_handle() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let handle = EmberSessionHandle::new(tx, [0u8; 32]);
        handle.backdate_for_test(EMBER_SESSION_FRESH_SECS + 1);
        assert!(!handle.is_fresh());

        handle.touch();
        assert!(handle.is_fresh(), "touch() must reset staleness");
    }

    /// Regression for friend uploads lasting longer than
    /// `EMBER_SESSION_FRESH_SECS`: if `touch()` is only called on Ember
    /// chat/browse/keepalive (and never on OP_REQUESTPARTS), the periodic
    /// stale sweep would `close()` an otherwise healthy upload session.
    /// The upload reader now touches on every inbound packet; this test
    /// locks in that repeated file-serve-style activity keeps the handle
    /// fresh indefinitely.
    #[tokio::test]
    async fn repeated_touches_keep_handle_fresh_across_freshness_window() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let handle = EmberSessionHandle::new(tx, [0u8; 32]);

        // Simulate several "OP_REQUESTPARTS arrived" events spaced just
        // under the freshness window — the same pattern a sustained
        // friend download produces on our upload socket.
        for _ in 0..3 {
            handle.backdate_for_test(EMBER_SESSION_FRESH_SECS - 1);
            assert!(
                handle.is_fresh(),
                "activity just inside the freshness window must still count"
            );
            handle.touch();
        }
        assert!(
            handle.is_fresh(),
            "sustained inbound file-serve traffic must keep the Ember session fresh"
        );
    }

    #[tokio::test]
    async fn close_notifies_the_session_owner() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let handle = EmberSessionHandle::new(tx, [0u8; 32]);
        let mut shutdown = handle.subscribe_shutdown();

        handle.close();
        shutdown
            .changed()
            .await
            .expect("shutdown sender stays alive");
        assert!(*shutdown.borrow());
    }

    #[tokio::test]
    async fn evict_stale_ember_session_removes_only_stale_entries() {
        let sessions: EmberSessionMap = Arc::new(RwLock::new(HashMap::new()));
        let stale_hash = [0xAA; 16];
        let fresh_hash = [0xBB; 16];

        let (stale_tx, _stale_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let stale_handle = EmberSessionHandle::new(stale_tx, [0u8; 32]);
        stale_handle.backdate_for_test(EMBER_SESSION_FRESH_SECS + 1);

        let (fresh_tx, _fresh_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let fresh_handle = EmberSessionHandle::new(fresh_tx, [0u8; 32]);

        {
            let mut map = sessions.write().await;
            map.insert(stale_hash, stale_handle);
            map.insert(fresh_hash, fresh_handle);
        }

        let evicted_stale = evict_stale_ember_session(&sessions, &stale_hash).await;
        let evicted_fresh = evict_stale_ember_session(&sessions, &fresh_hash).await;

        assert!(evicted_stale, "stale entry must be evicted");
        assert!(!evicted_fresh, "fresh entry must be left alone");

        let map = sessions.read().await;
        assert!(
            !map.contains_key(&stale_hash),
            "stale hash must no longer be present after eviction"
        );
        assert!(
            map.contains_key(&fresh_hash),
            "fresh hash must still be present"
        );
    }

    #[tokio::test]
    async fn evict_stale_ember_session_is_noop_when_absent() {
        let sessions: EmberSessionMap = Arc::new(RwLock::new(HashMap::new()));
        let evicted = evict_stale_ember_session(&sessions, &[0xCC; 16]).await;
        assert!(
            !evicted,
            "evicting an absent hash must report false, not panic"
        );
    }

    #[test]
    fn two_v1_sessions_or_nonmembers_never_gain_friend_privileges() {
        // Even if two legacy sessions independently complete/replay their old
        // PoP transcript, neither supplies the v2-authenticated bit consumed
        // by authorization.
        assert!(!crate::network::ed2k::LEGACY_FRIEND_AUTH_ENABLED);
        assert!(!friend_privileges_allowed(false, true));
        assert!(!friend_privileges_allowed(true, false));
        // Canonical outbound-slot ownership is not part of chat/browse auth.
        assert!(friend_privileges_allowed(true, true));
    }

    #[test]
    fn friend_priority_requires_secure_v2_not_hash_claim_alone() {
        // Document the intentional architecture: stock eMule file sockets
        // never set secure_v2_authenticated, so live_secure_friend_member
        // (and thus friend-slot priority) stays false without restoring
        // legacy PoP.
        assert!(
            !friend_privileges_allowed(false, true),
            "hash membership without secure-v2 must not authorize friend privileges"
        );
    }

    #[test]
    fn reserved_port_test_admission_rejects_long_lived_over_capacity() {
        assert!(allow_long_lived_session_under_admission(
            false,
            MAX_TOTAL_CONNECTIONS + RESERVED_PORT_TEST_CONNECTIONS
        ));
        assert!(allow_long_lived_session_under_admission(
            true,
            MAX_TOTAL_CONNECTIONS
        ));
        assert!(!allow_long_lived_session_under_admission(
            true,
            MAX_TOTAL_CONNECTIONS + 1
        ));
    }

    #[tokio::test]
    async fn friend_removal_revokes_every_matching_secure_session() {
        let hash = [0xD7; 16];
        let (tx_a, _rx_a) = tokio::sync::mpsc::channel(1);
        let (tx_b, _rx_b) = tokio::sync::mpsc::channel(1);
        let a = EmberSessionHandle::new_secure(tx_a, [1; 32], hash);
        let b = EmberSessionHandle::new_secure(tx_b, [1; 32], hash);
        let mut shutdown_a = a.subscribe_shutdown();
        let mut shutdown_b = b.subscribe_shutdown();

        assert!(revoke_all_secure_sessions(hash) >= 2);
        shutdown_a.changed().await.unwrap();
        shutdown_b.changed().await.unwrap();
        assert!(*shutdown_a.borrow());
        assert!(*shutdown_b.borrow());
    }

    #[test]
    fn connection_admission_guard_releases_all_counters() {
        let total = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        let per_ip = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let ip: IpAddr = "203.0.113.20".parse().unwrap();
        per_ip.lock().insert(ip, 1);
        {
            let _guard = ConnectionAdmissionGuard::new(total.clone(), per_ip.clone(), ip);
            assert_eq!(total.load(std::sync::atomic::Ordering::Relaxed), 1);
        }
        assert_eq!(total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert!(!per_ip.lock().contains_key(&ip));
    }

    #[test]
    fn port_test_reserve_does_not_expand_ordinary_capacity() {
        assert_eq!(MAX_TOTAL_CONNECTIONS, 100);
        assert!(RESERVED_PORT_TEST_CONNECTIONS > 0);
        assert!(INBOUND_PREAUTH_DEADLINE_SECS < CLIENT_TIMEOUT_SECS);
    }

    #[tokio::test]
    async fn emule_port_test_frame_remains_wire_compatible() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(&[OP_EMULEPROT]).await.unwrap();
        writer.write_all(&2u32.to_le_bytes()).await.unwrap();
        writer.write_all(&[OP_PORTTEST, 0x12]).await.unwrap();
        let (protocol, opcode, payload) = read_packet_async_inner(&mut reader).await.unwrap();
        assert_eq!(protocol, OP_EMULEPROT);
        assert_eq!(opcode, OP_PORTTEST);
        assert_eq!(payload, [0x12]);
    }

    #[test]
    fn upload_read_uses_pinned_handle_after_name_replacement() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-upload-pinned-read-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let root = base.join("root");
        let data = base.join("data");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let shared = root.join("shared.bin");
        let moved = root.join("shared-original.bin");
        std::fs::write(&shared, b"verified").unwrap();
        let root_string = root.to_string_lossy().into_owned();
        crate::security::filesystem::initialize_approved_roots(
            &data,
            std::slice::from_ref(&root_string),
        )
        .unwrap();
        let (_, opened) = crate::security::filesystem::open_existing_approved(
            &shared,
            std::slice::from_ref(&root_string),
            false,
        )
        .unwrap();
        std::fs::rename(&shared, &moved).unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(&base.join("private.bin"), &shared).unwrap();
        #[cfg(not(unix))]
        std::fs::write(&shared, b"attacker").unwrap();

        let (_, bytes) = read_upload_block(opened, 0, 8).unwrap();
        assert_eq!(bytes, b"verified");
        let _ = std::fs::remove_dir_all(base);
    }
}
