//! Process-wide bookkeeping for how Ember looks to each eD2K peer.
//!
//! eMule keeps one `CUpDownClient` per remote user, found by user hash or by
//! IP and listen port, and gives it at most one socket
//! (`CClientList::AttachToAlreadyKnown`, `ClientList.cpp:196-240`). A second
//! connection from us is attached to that client and the socket it already
//! had is deleted, taking down whatever was running on it. If the two
//! connections carry different listen ports in our Hello while the first one
//! is identified, the newcomer is banned as "Userhash invalid". The uploader
//! also remembers, per client and file, when we last sent `OP_STARTUPLOADREQ`
//! (`CUpDownClient::AddRequestCount`, `UploadClient.cpp:597-620`).
//!
//! Download sources for different files, upload sessions and callbacks all
//! run as separate tasks, so this state has to live outside any one of them.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use super::dead_sources::MIN_REQUESTTIME_SECS;
use super::messages::{
    PeerCapabilities, OP_AICHFILEHASHREQ, OP_AICHREQUEST, OP_ASKSHAREDDIRS, OP_ASKSHAREDFILES,
    OP_ASKSHAREDFILESDIR, OP_EDONKEYHEADER, OP_EMULEPROT, OP_HASHSETREQ, OP_HASHSETREQUEST2,
    OP_MULTIPACKET, OP_MULTIPACKET_EXT, OP_MULTIPACKET_EXT2, OP_REQUESTFILENAME,
    OP_REQUESTPARTS, OP_REQUESTPARTS_I64, OP_REQUESTSOURCES, OP_REQUESTSOURCES2,
    OP_SETREQFILEID, OP_STARTUPLOADREQ,
};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn known_hash(user_hash: Option<[u8; 16]>) -> Option<[u8; 16]> {
    user_hash.filter(|h| *h != [0u8; 16])
}

// ---------------------------------------------------------------------------
// Live sessions

#[derive(Clone, Copy)]
struct SessionEntry {
    user_hash: Option<[u8; 16]>,
    ip: Ipv4Addr,
    listen_port: u16,
    /// Cleared once the peer turns out to be Ember, which keeps parallel
    /// sockets to one peer apart instead of closing the older one.
    exclusive: bool,
}

impl SessionEntry {
    /// Whether this live session occupies the peer's one socket to us. The
    /// user hash only counts from the same address: an unauthenticated Hello
    /// from elsewhere must not be able to hold another peer's slot.
    fn blocks(&self, user_hash: Option<[u8; 16]>, ip: Ipv4Addr, listen_port: u16) -> bool {
        if !self.exclusive || self.ip != ip {
            return false;
        }
        let same_port = listen_port != 0 && self.listen_port == listen_port;
        let same_user = matches!((self.user_hash, user_hash), (Some(a), Some(b)) if a == b);
        same_port || same_user
    }
}

#[derive(Default)]
struct Sessions {
    next_id: u64,
    live: HashMap<u64, SessionEntry>,
}

fn sessions() -> MutexGuard<'static, Sessions> {
    static SESSIONS: OnceLock<Mutex<Sessions>> = OnceLock::new();
    lock(SESSIONS.get_or_init(Mutex::default))
}

/// One live connection to a peer, registered until dropped.
#[must_use = "the session is only registered while this guard is alive"]
pub struct PeerSession {
    id: u64,
}

impl PeerSession {
    fn insert(entry: SessionEntry, sessions: &mut Sessions) -> Self {
        sessions.next_id += 1;
        let id = sessions.next_id;
        sessions.live.insert(id, entry);
        Self { id }
    }

    /// Records the user hash from the peer's Hello, for a session reserved
    /// before we knew it.
    pub fn identify(&self, user_hash: [u8; 16]) {
        let Some(hash) = known_hash(Some(user_hash)) else {
            return;
        };
        if let Some(entry) = sessions().live.get_mut(&self.id) {
            entry.user_hash = Some(hash);
        }
    }

    /// The peer identified itself as Ember, so this session no longer keeps
    /// other connections to it from being opened.
    pub fn mark_ember(&self) {
        if let Some(entry) = sessions().live.get_mut(&self.id) {
            entry.exclusive = false;
        }
    }
}

impl Drop for PeerSession {
    fn drop(&mut self) {
        sessions().live.remove(&self.id);
    }
}

/// Whether a session with this peer is open in either direction, so that
/// dialing it would make the peer drop that one.
pub fn is_busy(user_hash: Option<[u8; 16]>, ip: Ipv4Addr, listen_port: u16) -> bool {
    let user_hash = known_hash(user_hash);
    sessions()
        .live
        .values()
        .any(|e| e.blocks(user_hash, ip, listen_port))
}

/// Reserves a peer for a connection we are about to open, or `None` when
/// [`is_busy`].
pub fn try_reserve(
    user_hash: Option<[u8; 16]>,
    ip: Ipv4Addr,
    listen_port: u16,
) -> Option<PeerSession> {
    let user_hash = known_hash(user_hash);
    let mut sessions = sessions();
    if sessions
        .live
        .values()
        .any(|e| e.blocks(user_hash, ip, listen_port))
    {
        return None;
    }
    let entry = SessionEntry {
        user_hash,
        ip,
        listen_port,
        exclusive: true,
    };
    Some(PeerSession::insert(entry, &mut sessions))
}

/// Records a connection that already exists, such as one the peer opened.
pub fn register(user_hash: Option<[u8; 16]>, ip: Ipv4Addr, listen_port: u16) -> PeerSession {
    let entry = SessionEntry {
        user_hash: known_hash(user_hash),
        ip,
        listen_port,
        exclusive: true,
    };
    PeerSession::insert(entry, &mut sessions())
}

// ---------------------------------------------------------------------------
// Advertised TCP port

static ADVERTISED_TCP_PORT: AtomicU16 = AtomicU16::new(0);

/// Publishes the TCP port our Hello carries. eMule compares it across our
/// connections, so every Hello reads this rather than a copy taken when its
/// task started.
pub fn set_advertised_tcp_port(port: u16) {
    ADVERTISED_TCP_PORT.store(port, Ordering::Relaxed);
}

/// The TCP port to put in a Hello, or `fallback` before one is published.
pub fn advertised_tcp_port_or(fallback: u16) -> u16 {
    match ADVERTISED_TCP_PORT.load(Ordering::Relaxed) {
        0 => fallback,
        port => port,
    }
}

// ---------------------------------------------------------------------------
// Upload requests we sent

/// Gap we leave between two `OP_STARTUPLOADREQ` for one file to one peer.
/// eMule strikes a re-ask inside `MIN_REQUESTTIME` unless it is downloading
/// from us at the time, and bans at the fourth. We cannot see that exemption,
/// so every re-ask waits; the margin covers our send and its receipt being
/// timed on different clocks.
pub const UPLOAD_REQUEST_INTERVAL: Duration =
    Duration::from_secs(MIN_REQUESTTIME_SECS as u64 + 15);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum PeerKey {
    Endpoint(Ipv4Addr, u16),
    User([u8; 16]),
}

type UploadRequests = HashMap<(PeerKey, [u8; 16]), Instant>;

fn upload_requests() -> MutexGuard<'static, UploadRequests> {
    static ASKED: OnceLock<Mutex<UploadRequests>> = OnceLock::new();
    lock(ASKED.get_or_init(Mutex::default))
}

fn peer_keys(user_hash: Option<[u8; 16]>, ip: Ipv4Addr, ports: &[u16]) -> Vec<PeerKey> {
    let mut keys: Vec<PeerKey> = ports
        .iter()
        .filter(|&&port| port != 0)
        .map(|&port| PeerKey::Endpoint(ip, port))
        .collect();
    keys.extend(known_hash(user_hash).map(PeerKey::User));
    keys
}

/// Records that we just sent `OP_STARTUPLOADREQ` for `file_hash`. `ports`
/// lists every port the peer is known by (dialed, advertised in its Hello,
/// or on its source row) so a later check under any of them finds it.
pub fn note_upload_request(
    user_hash: Option<[u8; 16]>,
    ip: Ipv4Addr,
    ports: &[u16],
    file_hash: [u8; 16],
) {
    let now = Instant::now();
    let mut asked = upload_requests();
    asked.retain(|_, at| now.duration_since(*at) < UPLOAD_REQUEST_INTERVAL);
    for key in peer_keys(user_hash, ip, ports) {
        asked.insert((key, file_hash), now);
    }
}

/// How long until we may send this peer another `OP_STARTUPLOADREQ` for
/// `file_hash`, or `None` if we may now.
pub fn upload_request_wait(
    user_hash: Option<[u8; 16]>,
    ip: Ipv4Addr,
    ports: &[u16],
    file_hash: &[u8; 16],
) -> Option<Duration> {
    let asked = upload_requests();
    peer_keys(user_hash, ip, ports)
        .into_iter()
        .filter_map(|key| asked.get(&(key, *file_hash)))
        .filter_map(|at| UPLOAD_REQUEST_INTERVAL.checked_sub(at.elapsed()))
        .filter(|wait| !wait.is_zero())
        .max()
}

const UPLOAD_REQUESTS_FILE: &str = "recent_upload_requests.json";

#[derive(serde::Serialize, serde::Deserialize)]
struct SavedUploadRequest {
    peer: String,
    file: String,
    asked_at: u64,
}

impl PeerKey {
    fn encode(&self) -> String {
        match self {
            PeerKey::Endpoint(ip, port) => format!("{ip}:{port}"),
            PeerKey::User(hash) => hex::encode(hash),
        }
    }

    fn decode(text: &str) -> Option<Self> {
        if let Ok(addr) = text.parse::<std::net::SocketAddrV4>() {
            return Some(PeerKey::Endpoint(*addr.ip(), addr.port()));
        }
        let hash: [u8; 16] = hex::decode(text).ok()?.try_into().ok()?;
        Some(PeerKey::User(hash))
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Writes the asks still inside [`UPLOAD_REQUEST_INTERVAL`]. The uploader
/// keeps counting them across our restart, so without this every restart
/// re-asked every uploader at once.
pub fn save_upload_requests(data_dir: &std::path::Path) {
    let now = Instant::now();
    let unix = unix_now();
    let saved: Vec<SavedUploadRequest> = upload_requests()
        .iter()
        .filter_map(|((key, file), at)| {
            let age = now.duration_since(*at);
            (age < UPLOAD_REQUEST_INTERVAL).then(|| SavedUploadRequest {
                peer: key.encode(),
                file: hex::encode(file),
                asked_at: unix.saturating_sub(age.as_secs()),
            })
        })
        .collect();
    let path = data_dir.join(UPLOAD_REQUESTS_FILE);
    if saved.is_empty() {
        let _ = std::fs::remove_file(&path);
        return;
    }
    let result = serde_json::to_vec(&saved)
        .map_err(io::Error::other)
        .and_then(|bytes| crate::security::atomic_write(&path, &bytes, true));
    if let Err(e) = result {
        tracing::warn!("Could not save recent upload requests: {e}");
    }
}

/// Restores what [`save_upload_requests`] wrote, dropping asks whose
/// interval has run out since.
pub fn load_upload_requests(data_dir: &std::path::Path) {
    let Ok(bytes) = std::fs::read(data_dir.join(UPLOAD_REQUESTS_FILE)) else {
        return;
    };
    let saved: Vec<SavedUploadRequest> = match serde_json::from_slice(&bytes) {
        Ok(saved) => saved,
        Err(e) => {
            tracing::warn!("Ignoring unreadable recent upload requests: {e}");
            return;
        }
    };
    let unix = unix_now();
    let now = Instant::now();
    let mut asked = upload_requests();
    for entry in saved {
        let age = Duration::from_secs(unix.saturating_sub(entry.asked_at));
        if age >= UPLOAD_REQUEST_INTERVAL {
            continue;
        }
        let Some(key) = PeerKey::decode(&entry.peer) else {
            continue;
        };
        let Some(file) = hex::decode(&entry.file)
            .ok()
            .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
        else {
            continue;
        };
        asked.insert((key, file), now.checked_sub(age).unwrap_or(now));
    }
}

// ---------------------------------------------------------------------------
// Requests arriving on a download connection

const OP_PACKEDPROT: u8 = 0xD4;
const HEADER_LEN: usize = 6;
const MAX_HELD_FRAME: usize = 64 * 1024;
const MAX_HELD_BYTES: usize = 256 * 1024;

/// Whether a frame from the peer is it asking *us* for something: the upload
/// half of the conversation, which the download side has no answer for.
fn is_request_to_us(proto: u8, opcode: u8) -> bool {
    match proto {
        OP_EDONKEYHEADER => matches!(
            opcode,
            OP_REQUESTFILENAME
                | OP_SETREQFILEID
                | OP_HASHSETREQ
                | OP_STARTUPLOADREQ
                | OP_REQUESTPARTS
                | OP_ASKSHAREDFILES
                | OP_ASKSHAREDDIRS
                | OP_ASKSHAREDFILESDIR
        ),
        OP_EMULEPROT | OP_PACKEDPROT => matches!(
            opcode,
            OP_MULTIPACKET
                | OP_MULTIPACKET_EXT
                | OP_MULTIPACKET_EXT2
                | OP_HASHSETREQUEST2
                | OP_REQUESTSOURCES
                | OP_REQUESTSOURCES2
                | OP_AICHREQUEST
                | OP_AICHFILEHASHREQ
                | OP_REQUESTPARTS_I64
        ),
        _ => false,
    }
}

/// Requests a peer sent over a connection our download side owns.
///
/// eMule uses its one socket to us for both directions, so when it also wants
/// something we have, it asks on the connection we opened to download from
/// it. The download side cannot answer, and a request left unanswered until
/// the socket closes makes eMule drop us as a source. [`HoldingReader`] keeps
/// those frames here, and the connection goes to the upload server with them
/// once the download is done with it (see [`hand_over`]).
#[derive(Default)]
pub struct HeldRequests {
    frames: Mutex<Vec<u8>>,
    held: AtomicBool,
    released: AtomicBool,
    reader_mid_frame: AtomicBool,
    writer_mid_frame: AtomicBool,
    broken: AtomicBool,
    awaiting_grant: AtomicBool,
}

impl HeldRequests {
    /// The peer is waiting on a request, the download side is not waiting on
    /// the peer, and neither direction stopped partway through a frame, so the
    /// upload server can pick the stream up.
    pub fn ready_for_handover(&self) -> bool {
        self.held.load(Ordering::Acquire)
            && !self.awaiting_grant.load(Ordering::Acquire)
            && !self.broken.load(Ordering::Acquire)
            && !self.reader_mid_frame.load(Ordering::Acquire)
            && !self.writer_mid_frame.load(Ordering::Acquire)
    }

    /// Whether the download side is on the peer's queue. The slot grant then
    /// arrives on this socket (`UploadQueue.cpp:206-217`), and the upload
    /// server has no use for it, so the connection is closed rather than
    /// handed over and the peer grants through a new one.
    pub fn set_awaiting_grant(&self, waiting: bool) {
        self.awaiting_grant.store(waiting, Ordering::Release);
    }

    /// Stops holding: the reader replays the held frames, then passes the
    /// stream through untouched.
    pub fn release(&self) {
        self.released.store(true, Ordering::Release);
    }
}

enum ReadState {
    Header,
    Forward { header_sent: usize, remaining: usize },
    Hold { frame: Vec<u8>, remaining: usize },
    Transparent,
}

/// Reader for a download connection that sets aside the peer's own requests
/// (see [`HeldRequests`]) and passes every other frame through unchanged.
pub struct HoldingReader<R> {
    inner: R,
    held: Arc<HeldRequests>,
    header: [u8; HEADER_LEN],
    header_len: usize,
    state: ReadState,
    held_bytes: usize,
    replay: Vec<u8>,
    replay_pos: usize,
}

impl<R> HoldingReader<R> {
    pub fn new(inner: R, held: Arc<HeldRequests>) -> Self {
        Self {
            inner,
            held,
            header: [0; HEADER_LEN],
            header_len: 0,
            state: ReadState::Header,
            held_bytes: 0,
            replay: Vec::new(),
            replay_pos: 0,
        }
    }

    fn begin_frame(&mut self) {
        self.header_len = 0;
        let proto = self.header[0];
        let len = u32::from_le_bytes([self.header[1], self.header[2], self.header[3], self.header[4]])
            as usize;
        let opcode = self.header[5];
        if !matches!(proto, OP_EDONKEYHEADER | OP_EMULEPROT | OP_PACKEDPROT) || len == 0 {
            // Not framing we can follow. The download side sees the bytes and
            // fails exactly as it would have without us.
            self.held.broken.store(true, Ordering::Release);
            self.replay = self.header.to_vec();
            self.replay_pos = 0;
            self.state = ReadState::Transparent;
            return;
        }
        let body = len - 1;
        let fits = body <= MAX_HELD_FRAME && self.held_bytes + HEADER_LEN + body <= MAX_HELD_BYTES;
        if fits && is_request_to_us(proto, opcode) {
            let mut frame = Vec::with_capacity(HEADER_LEN + body);
            frame.extend_from_slice(&self.header);
            if body == 0 {
                self.commit_held(frame);
            } else {
                self.state = ReadState::Hold {
                    frame,
                    remaining: body,
                };
            }
        } else {
            self.held.reader_mid_frame.store(true, Ordering::Release);
            self.state = ReadState::Forward {
                header_sent: 0,
                remaining: body,
            };
        }
    }

    fn commit_held(&mut self, frame: Vec<u8>) {
        self.held_bytes += frame.len();
        lock(&self.held.frames).extend_from_slice(&frame);
        self.held.held.store(true, Ordering::Release);
        self.state = ReadState::Header;
    }

    fn end_forward(&mut self) {
        self.held.reader_mid_frame.store(false, Ordering::Release);
        self.state = ReadState::Header;
    }

    fn release(&mut self) {
        let mut replay = std::mem::take(&mut *lock(&self.held.frames));
        match std::mem::replace(&mut self.state, ReadState::Transparent) {
            ReadState::Header => replay.extend_from_slice(&self.header[..self.header_len]),
            ReadState::Hold { frame, .. } => replay.extend_from_slice(&frame),
            ReadState::Forward { header_sent, .. } => {
                replay.extend_from_slice(&self.header[header_sent..]);
            }
            ReadState::Transparent => {}
        }
        self.header_len = 0;
        self.replay = replay;
        self.replay_pos = 0;
    }

    fn fail(&self) {
        self.held.broken.store(true, Ordering::Release);
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for HoldingReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.replay_pos < this.replay.len() {
                let n = (this.replay.len() - this.replay_pos).min(buf.remaining());
                buf.put_slice(&this.replay[this.replay_pos..this.replay_pos + n]);
                this.replay_pos += n;
                return Poll::Ready(Ok(()));
            }
            if !matches!(this.state, ReadState::Transparent)
                && this.held.released.load(Ordering::Acquire)
            {
                this.release();
                continue;
            }
            match &mut this.state {
                ReadState::Transparent => return Pin::new(&mut this.inner).poll_read(cx, buf),
                ReadState::Header => {
                    let mut rb = ReadBuf::new(&mut this.header[this.header_len..]);
                    if let Err(e) = ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb)) {
                        this.fail();
                        return Poll::Ready(Err(e));
                    }
                    let n = rb.filled().len();
                    if n == 0 {
                        // End of stream. A partial header still reaches the
                        // download side, which reports the short frame.
                        this.fail();
                        this.replay = this.header[..this.header_len].to_vec();
                        this.replay_pos = 0;
                        this.header_len = 0;
                        this.state = ReadState::Transparent;
                        if this.replay.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        continue;
                    }
                    this.header_len += n;
                    if this.header_len == HEADER_LEN {
                        this.begin_frame();
                    }
                }
                ReadState::Forward {
                    header_sent,
                    remaining,
                } => {
                    if *header_sent < HEADER_LEN {
                        let n = (HEADER_LEN - *header_sent).min(buf.remaining());
                        buf.put_slice(&this.header[*header_sent..*header_sent + n]);
                        *header_sent += n;
                        if *header_sent == HEADER_LEN && *remaining == 0 {
                            this.end_forward();
                        }
                        return Poll::Ready(Ok(()));
                    }
                    let want = (*remaining).min(buf.remaining());
                    let mut rb = ReadBuf::new(buf.initialize_unfilled_to(want));
                    if let Err(e) = ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb)) {
                        this.fail();
                        return Poll::Ready(Err(e));
                    }
                    let n = rb.filled().len();
                    buf.advance(n);
                    if n == 0 {
                        this.fail();
                        return Poll::Ready(Ok(()));
                    }
                    *remaining -= n;
                    if *remaining == 0 {
                        this.end_forward();
                    }
                    return Poll::Ready(Ok(()));
                }
                ReadState::Hold { frame, remaining } => {
                    let mut chunk = [0u8; 4096];
                    let want = (*remaining).min(chunk.len());
                    let mut rb = ReadBuf::new(&mut chunk[..want]);
                    if let Err(e) = ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb)) {
                        this.fail();
                        return Poll::Ready(Err(e));
                    }
                    let n = rb.filled().len();
                    if n == 0 {
                        this.fail();
                        return Poll::Ready(Ok(()));
                    }
                    frame.extend_from_slice(&chunk[..n]);
                    *remaining -= n;
                    if *remaining == 0 {
                        let frame = std::mem::take(frame);
                        this.commit_held(frame);
                    }
                }
            }
        }
    }
}

/// Writer for a download connection that notes whether the last frame went
/// out whole, so a connection is never handed on with half a packet written.
pub struct FrameTrackingWriter<W> {
    inner: W,
    held: Arc<HeldRequests>,
    header: [u8; 5],
    header_len: usize,
    remaining: usize,
}

impl<W> FrameTrackingWriter<W> {
    pub fn new(inner: W, held: Arc<HeldRequests>) -> Self {
        Self {
            inner,
            held,
            header: [0; 5],
            header_len: 0,
            remaining: 0,
        }
    }

    fn track(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            if self.remaining > 0 {
                let n = self.remaining.min(bytes.len());
                self.remaining -= n;
                bytes = &bytes[n..];
                continue;
            }
            let n = (self.header.len() - self.header_len).min(bytes.len());
            self.header[self.header_len..self.header_len + n].copy_from_slice(&bytes[..n]);
            self.header_len += n;
            bytes = &bytes[n..];
            if self.header_len == self.header.len() {
                self.remaining = u32::from_le_bytes([
                    self.header[1],
                    self.header[2],
                    self.header[3],
                    self.header[4],
                ]) as usize;
                self.header_len = 0;
            }
        }
        let mid_frame = self.header_len != 0 || self.remaining != 0;
        self.held.writer_mid_frame.store(mid_frame, Ordering::Release);
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for FrameTrackingWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let n = ready!(Pin::new(&mut this.inner).poll_write(cx, buf))?;
        this.track(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Handing a download connection to the upload server

/// A download connection whose peer is waiting on requests it made to us.
/// The reader has already been released, so it replays those requests first.
pub struct DownloadHandover {
    pub peer_addr: SocketAddr,
    pub reader: Box<dyn AsyncRead + Unpin + Send>,
    pub writer: Box<dyn AsyncWrite + Unpin + Send>,
    pub peer_user_hash: [u8; 16],
    pub hello_caps: PeerCapabilities,
    /// Keeps the peer marked busy until the upload session registers itself.
    pub session: Option<PeerSession>,
}

fn handover_sender() -> MutexGuard<'static, Option<mpsc::Sender<DownloadHandover>>> {
    static SENDER: OnceLock<Mutex<Option<mpsc::Sender<DownloadHandover>>>> = OnceLock::new();
    lock(SENDER.get_or_init(Mutex::default))
}

/// Called by the upload server as it starts; hand-overs arrive on the
/// returned channel until the next call replaces it.
pub fn accept_download_handovers() -> mpsc::Receiver<DownloadHandover> {
    let (tx, rx) = mpsc::channel(32);
    *handover_sender() = Some(tx);
    rx
}

/// Gives the upload server a connection the download side is finished with.
/// When no upload server is taking them the connection is simply dropped,
/// which is what would have happened to it anyway.
pub fn hand_over(handover: DownloadHandover) -> bool {
    let sender = handover_sender().clone();
    sender.is_some_and(|tx| tx.try_send(handover).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn frame(proto: u8, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![proto];
        out.extend_from_slice(&((payload.len() + 1) as u32).to_le_bytes());
        out.push(opcode);
        out.extend_from_slice(payload);
        out
    }

    fn peer(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, last)
    }

    #[test]
    fn a_live_session_blocks_a_second_dial_until_dropped() {
        let ip = peer(1);
        let first = try_reserve(None, ip, 4662).expect("first dial");
        assert!(try_reserve(None, ip, 4662).is_none());
        assert!(try_reserve(None, ip, 4663).is_some(), "another port is another client");
        drop(first);
        assert!(try_reserve(None, ip, 4662).is_some());
    }

    #[test]
    fn a_session_the_peer_opened_blocks_our_dial_by_user_hash() {
        let hash = [7u8; 16];
        let _inbound = register(Some(hash), peer(2), 0);
        assert!(is_busy(Some(hash), peer(2), 4662));
        assert!(try_reserve(Some(hash), peer(2), 4662).is_none());
        assert!(try_reserve(None, peer(2), 4662).is_some(), "hash unknown and no port to match");
    }

    #[test]
    fn a_user_hash_claimed_from_another_address_holds_nothing() {
        let hash = [8u8; 16];
        let _spoofed = register(Some(hash), peer(40), 0);
        assert!(!is_busy(Some(hash), peer(41), 4662));
    }

    #[test]
    fn identify_lets_a_reserved_dial_block_by_hash() {
        let hash = [9u8; 16];
        let dial = try_reserve(None, peer(3), 4662).expect("dial");
        assert!(!is_busy(Some(hash), peer(3), 5000));
        dial.identify(hash);
        assert!(is_busy(Some(hash), peer(3), 5000));
    }

    #[test]
    fn an_ember_session_leaves_other_connections_free() {
        let session = register(Some([0x66u8; 16]), peer(30), 4662);
        assert!(is_busy(None, peer(30), 4662));
        session.mark_ember();
        assert!(try_reserve(None, peer(30), 4662).is_some());
    }

    #[test]
    fn zero_user_hash_matches_nothing() {
        let _a = register(Some([0u8; 16]), peer(5), 0);
        assert!(try_reserve(Some([0u8; 16]), peer(6), 4662).is_some());
    }

    #[test]
    fn upload_request_wait_covers_every_known_key() {
        let file = [0x11u8; 16];
        let hash = [0x22u8; 16];
        assert!(upload_request_wait(Some(hash), peer(10), &[4662], &file).is_none());
        note_upload_request(Some(hash), peer(10), &[4662, 51000], file);
        let wait = upload_request_wait(None, peer(10), &[51000], &file).expect("by port");
        assert!(wait > Duration::from_secs(MIN_REQUESTTIME_SECS as u64));
        assert!(upload_request_wait(Some(hash), peer(11), &[1], &file).is_some(), "by hash");
        assert!(upload_request_wait(Some(hash), peer(10), &[4662], &[0x33; 16]).is_none());
    }

    #[test]
    fn upload_requests_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!(
            "ember-upload-requests-{:016x}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = [0x44u8; 16];
        let hash = [0x55u8; 16];
        note_upload_request(Some(hash), peer(20), &[4662], file);
        save_upload_requests(&dir);
        upload_requests().retain(|(_, f), _| *f != file);
        assert!(upload_request_wait(Some(hash), peer(20), &[4662], &file).is_none());

        load_upload_requests(&dir);
        assert!(upload_request_wait(None, peer(20), &[4662], &file).is_some());
        assert!(upload_request_wait(Some(hash), peer(21), &[], &file).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn holding_reader_passes_download_frames_and_holds_requests() {
        let held = Arc::new(HeldRequests::default());
        let status = frame(OP_EDONKEYHEADER, 0x50, &[1, 2, 3]);
        let request = frame(OP_EDONKEYHEADER, OP_REQUESTFILENAME, &[0xAA; 16]);
        let multi = frame(OP_EMULEPROT, OP_MULTIPACKET, &[0xBB; 17]);
        let part = frame(OP_EDONKEYHEADER, 0x46, &[0xCC; 40]);
        let mut wire = Vec::new();
        for f in [&status, &request, &multi, &part] {
            wire.extend_from_slice(f);
        }
        let mut reader = HoldingReader::new(std::io::Cursor::new(wire), held.clone());

        let mut got = vec![0u8; status.len() + part.len()];
        reader.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..status.len()], &status[..]);
        assert_eq!(&got[status.len()..], &part[..]);
        assert!(held.ready_for_handover());

        held.release();
        let mut replayed = Vec::new();
        reader.read_to_end(&mut replayed).await.unwrap();
        let mut expected = request.clone();
        expected.extend_from_slice(&multi);
        assert_eq!(replayed, expected);
    }

    #[tokio::test]
    async fn holding_reader_is_not_ready_mid_frame_or_without_requests() {
        let held = Arc::new(HeldRequests::default());
        let part = frame(OP_EDONKEYHEADER, 0x46, &[0xCC; 40]);
        let mut wire = frame(OP_EDONKEYHEADER, OP_STARTUPLOADREQ, &[0xAA; 16]);
        wire.extend_from_slice(&part);
        let mut reader = HoldingReader::new(std::io::Cursor::new(wire), held.clone());
        let mut first = [0u8; 10];
        reader.read_exact(&mut first).await.unwrap();
        assert!(!held.ready_for_handover(), "download side is inside a frame");
        let mut rest = vec![0u8; part.len() - first.len()];
        reader.read_exact(&mut rest).await.unwrap();
        assert!(held.ready_for_handover());

        let quiet = Arc::new(HeldRequests::default());
        let mut reader =
            HoldingReader::new(std::io::Cursor::new(part.clone()), quiet.clone());
        let mut all = vec![0u8; part.len()];
        reader.read_exact(&mut all).await.unwrap();
        assert!(!quiet.ready_for_handover());
    }

    #[tokio::test]
    async fn holding_reader_steps_aside_on_unknown_framing() {
        let held = Arc::new(HeldRequests::default());
        let wire = vec![0x42, 1, 0, 0, 0, 0x58, 9, 9];
        let mut reader = HoldingReader::new(std::io::Cursor::new(wire.clone()), held.clone());
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, wire);
        assert!(!held.ready_for_handover());
    }

    #[tokio::test]
    async fn frame_tracking_writer_notices_a_partial_frame() {
        let held = Arc::new(HeldRequests::default());
        held.held.store(true, Ordering::Release);
        let mut writer = FrameTrackingWriter::new(Vec::new(), held.clone());
        let f = frame(OP_EDONKEYHEADER, OP_REQUESTPARTS, &[0u8; 40]);
        writer.write_all(&f[..7]).await.unwrap();
        assert!(!held.ready_for_handover());
        writer.write_all(&f[7..]).await.unwrap();
        assert!(held.ready_for_handover());

        held.set_awaiting_grant(true);
        assert!(!held.ready_for_handover(), "a grant is due on this socket");
        held.set_awaiting_grant(false);
        assert!(held.ready_for_handover());
    }
}
