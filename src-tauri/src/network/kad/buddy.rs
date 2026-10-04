use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info};

use super::firewall::FirewallStatus;
use super::types::KadId;
use crate::network::ed2k::tcp_obfuscation::{self, Rc4Reader, Rc4Writer};

use crate::network::ed2k::messages::{
    OP_BUDDYPING, OP_BUDDYPONG, OP_CALLBACK, OP_REASKCALLBACKTCP,
};

const OP_EDONKEYHEADER: u8 = 0xE3;
const OP_EMULEPROT: u8 = 0xC5;
const OP_HELLO: u8 = 0x01;
const OP_HELLOANSWER: u8 = 0x4C;
const OP_EMULEINFO: u8 = 0x01;
const OP_EMULEINFOANSWER: u8 = 0x02;

const BUDDY_EVENT_CHANNEL_SIZE: usize = 32;
const REASK_CALLBACK_BUDGET_PER_SESSION: u32 = 16;
const MAX_PENDING_BUDDY_HASHES: usize = 512;
/// Only the firewalled side pings. eMule does so every 10 minutes
/// (`SetLastBuddyPingPongTime`, `UpdownClient.h`), and answers a ping only
/// 13 minutes or more after its previous pong, ignoring the rest.
const BUDDY_PING_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// A buddy that answered our last ping is pinged again on the next 60 s
/// buddy tick. eMule never answers that soon, so only Ember buddies get this
/// cadence, and Ember up to 1.7.1 drops a served client after 180 s
/// without a packet.
const BUDDY_ANSWERED_PING_INTERVAL: Duration = Duration::from_secs(50);
/// Max time to wait for the *next* packet from the client we serve before
/// treating the connection as dead. eMule clients ping every 10 minutes, so
/// this outlasts one lost ping.
///
/// Without a read-side timeout a firewalled client that crashes or
/// black-holes mid-session — without ever sending a TCP FIN/RST — would
/// occupy the single `serving_buddy_for` slot forever, since
/// `read_ed2k_packet` blocks indefinitely.
const BUDDY_SERVING_IDLE_TIMEOUT: Duration = Duration::from_secs(25 * 60);
/// Same for the connection to our own buddy. At our 10-minute cadence an
/// eMule buddy answers every other ping, so its pongs arrive about 21
/// minutes apart. `send_buddy_ping` only notices a dead buddy on a write
/// failure, not on a connection that accepts writes but never replies.
const BUDDY_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Packets queued for the dedicated buddy writer task. Keep this small: a
/// stalled firewalled client must not pin unbounded callback/reask payloads
/// in memory, and `try_send` failing with Full is the signal to drop the
/// extra relay rather than park the network event loop on TCP.
const BUDDY_WRITE_CHANNEL_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuddyState {
    NoBuddy,
    FindingBuddy,
    Connected,
}

#[derive(Debug)]
pub enum BuddyEvent {
    PingReceived,
    PongReceived,
    /// OP_CALLBACK: full Kad callback -- firewalled client should connect out to the requester
    Callback {
        file_hash: [u8; 16],
        dest_ip: Ipv4Addr,
        dest_port: u16,
    },
    /// OP_REASKCALLBACKTCP: UDP reask relay -- firewalled client should send UDP queue response
    ReaskCallback {
        dest_ip: Ipv4Addr,
        dest_port: u16,
        file_hash: [u8; 16],
    },
    Disconnected,
}

pub type PendingBuddySet = Arc<Mutex<std::collections::HashMap<[u8; 16], (KadId, i64)>>>;
type BuddyReadStream = Box<dyn AsyncRead + Unpin + Send>;
pub type BuddyWriteStream = Box<dyn AsyncWrite + Unpin + Send + Sync>;

/// A completed outgoing buddy handshake, handed from the spawned connect task
/// to the real [`BuddyManager`] on the network loop.
///
/// The connect/handshake runs on a throwaway clone of the manager, so
/// everything the live manager needs has to travel back here.
pub struct OutgoingBuddyConnection {
    pub buddy_id: KadId,
    pub buddy_ip: Ipv4Addr,
    pub buddy_tcp_port: u16,
    /// Source port of the `FindBuddyRes`. Nothing later in the handshake
    /// carries it, and firewalled source records must advertise it for
    /// callbacks, so it is captured at the datagram and passed through.
    pub buddy_udp_port: u16,
    pub events: mpsc::Receiver<BuddyEvent>,
    /// Clone of the reader's event sender, so the writer task can report its
    /// own failures instead of waiting to be noticed on the next ping tick.
    pub disconnect_tx: mpsc::Sender<BuddyEvent>,
    pub writer: BuddyWriteStream,
    pub reader_handle: tokio::task::JoinHandle<()>,
}

enum Enqueue {
    Queued,
    Busy,
    Dead,
}

/// Owns the TCP write half of a buddy connection on a dedicated task so the
/// network event loop never `.await`s a stalled firewalled peer. USS samples
/// KAD RTT from that same loop; a 10s `write_all` there used to look like
/// congestion and slash the upload cap for every other peer.
struct BuddyWriteQueue {
    tx: mpsc::Sender<Vec<u8>>,
    handle: tokio::task::JoinHandle<()>,
}

impl BuddyWriteQueue {
    fn spawn(
        mut writer: BuddyWriteStream,
        disconnect_tx: Option<mpsc::Sender<BuddyEvent>>,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(BUDDY_WRITE_CHANNEL_SIZE);
        let handle = tokio::spawn(async move {
            while let Some(pkt) = rx.recv().await {
                let ok = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    writer.write_all(&pkt).await?;
                    writer.flush().await
                })
                .await;
                if !matches!(ok, Ok(Ok(()))) {
                    debug!("Buddy writer failed or timed out");
                    if let Some(tx) = disconnect_tx {
                        let _ = tx.try_send(BuddyEvent::Disconnected);
                    }
                    break;
                }
            }
        });
        Self { tx, handle }
    }

    fn try_enqueue(&self, pkt: Vec<u8>) -> Enqueue {
        match self.tx.try_send(pkt) {
            Ok(()) => Enqueue::Queued,
            Err(mpsc::error::TrySendError::Full(_)) => Enqueue::Busy,
            Err(mpsc::error::TrySendError::Closed(_)) => Enqueue::Dead,
        }
    }

    fn abort(&self) {
        self.handle.abort();
    }
}

impl Drop for BuddyWriteQueue {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

pub struct BuddyManager {
    local_id: KadId,
    user_hash: [u8; 16],
    nickname: String,
    tcp_port: u16,
    udp_port: u16,
    state: BuddyState,
    buddy_id: Option<KadId>,
    buddy_addr: Option<SocketAddr>,
    /// The buddy's Kad UDP port, learned from the source address of its
    /// `FindBuddyRes`. `buddy_addr` holds the *TCP* port we dial for the relay
    /// connection; a callback request has to reach the buddy's UDP socket
    /// instead, and the two are not related by any fixed offset.
    buddy_udp_port: Option<u16>,
    last_find_attempt: i64,
    find_attempt_count: u32,

    buddy_writer: Option<BuddyWriteQueue>,
    buddy_reader_handle: Option<tokio::task::JoinHandle<()>>,
    last_buddy_ping: Option<Instant>,
    buddy_ponged_since_ping: bool,

    serving_buddy_for: Option<KadId>,
    serving_callback_check: Option<KadId>,
    serving_callback_budget: u32,
    serving_writer: Option<BuddyWriteQueue>,
    serving_reader_handle: Option<tokio::task::JoinHandle<()>>,

    pending_buddy_hashes: PendingBuddySet,
}

impl BuddyManager {
    pub fn new(
        local_id: KadId,
        user_hash: [u8; 16],
        nickname: String,
        tcp_port: u16,
        udp_port: u16,
        pending_buddy_hashes: PendingBuddySet,
    ) -> Self {
        BuddyManager {
            local_id,
            user_hash,
            nickname,
            tcp_port,
            udp_port,
            state: BuddyState::NoBuddy,
            buddy_id: None,
            buddy_addr: None,
            buddy_udp_port: None,
            last_find_attempt: 0,
            find_attempt_count: 0,
            buddy_writer: None,
            buddy_reader_handle: None,
            last_buddy_ping: None,
            buddy_ponged_since_ping: false,
            serving_buddy_for: None,
            serving_callback_check: None,
            serving_callback_budget: 0,
            serving_writer: None,
            serving_reader_handle: None,
            pending_buddy_hashes,
        }
    }

    pub async fn reset(&mut self) {
        self.state = BuddyState::NoBuddy;
        self.buddy_id = None;
        self.buddy_addr = None;
        self.buddy_udp_port = None;
        self.last_find_attempt = 0;
        self.find_attempt_count = 0;
        if let Some(h) = self.buddy_reader_handle.take() {
            h.abort();
        }
        if let Some(w) = self.buddy_writer.take() {
            w.abort();
        }
        self.last_buddy_ping = None;
        self.buddy_ponged_since_ping = false;
        if let Some(h) = self.serving_reader_handle.take() {
            h.abort();
        }
        if let Some(w) = self.serving_writer.take() {
            w.abort();
        }
        self.serving_buddy_for = None;
        self.serving_callback_check = None;
        self.serving_callback_budget = 0;
        // See `disconnect_buddy` — `.await` the real lock instead of a
        // best-effort `try_lock()` so this can never skip clearing stale
        // pending-buddy entries under lock contention.
        self.pending_buddy_hashes.lock().await.clear();
    }

    pub fn state(&self) -> BuddyState {
        self.state
    }

    pub fn local_id(&self) -> &KadId {
        &self.local_id
    }

    pub fn tcp_port(&self) -> u16 {
        self.tcp_port
    }

    /// Keep the port we advertise to our buddy in sync with STUN keep-alive
    /// remaps discovered after construction — without this, a mid-session
    /// remap would never reach the buddy Hello handshake / `OP_CALLBACK`
    /// payloads, which bake in whatever `tcp_port` was at startup.
    pub fn set_tcp_port(&mut self, tcp_port: u16) {
        self.tcp_port = tcp_port;
    }

    /// Same as `set_tcp_port` but for the UDP/Kad port advertised in the
    /// buddy Hello handshake (`HelloOptions::udp_port`/`kad_port`).
    pub fn set_udp_port(&mut self, udp_port: u16) {
        self.udp_port = udp_port;
    }

    pub fn buddy_id(&self) -> Option<&KadId> {
        self.buddy_id.as_ref()
    }

    pub fn buddy_addr(&self) -> Option<(std::net::Ipv4Addr, u16)> {
        self.buddy_addr.as_ref().and_then(|addr| {
            if let std::net::IpAddr::V4(v4) = addr.ip() {
                Some((v4, addr.port()))
            } else {
                None
            }
        })
    }

    /// The buddy's Kad UDP port, for the `TAG_SERVERPORT` we publish on
    /// firewalled source records. A searcher sends `KADEMLIA_CALLBACK_REQ`
    /// there, so publishing anything else strands every callback.
    pub fn buddy_udp_port(&self) -> Option<u16> {
        self.buddy_udp_port.filter(|port| *port != 0)
    }

    pub fn find_buddy_target(&self) -> KadId {
        let mut target = self.local_id.0;
        for byte in &mut target {
            *byte ^= 0xFF;
        }
        KadId(target)
    }

    /// Only search for a buddy when we are firewalled on BOTH TCP and UDP.
    ///
    /// eMule seeks a buddy only when both ports are firewalled
    /// (`ClientList.cpp`: `IsFirewalled() && IsFirewalledUDP(true)`, with the
    /// comment "we only need a buddy if direct callback is not available"). A
    /// TCP-firewalled but UDP-open client is still reachable via direct UDP
    /// callback (`can_advertise_direct_udp_callback`), so a buddy — a scarce
    /// relay that serves only one client at a time — would be wasted and would
    /// deny a slot to a peer that is firewalled on both ports.
    ///
    /// Both statuses must be the explicitly-confirmed `Firewalled` value; the
    /// initial `Unknown` (open assumed, matching eMule's `IsFirewalledUDP`)
    /// does not trigger a search, so we don't produce false buddy searches for
    /// users who are actually open or not yet checked.
    ///
    /// Uses escalating backoff: 60s → 120s → 240s → 480s → 600s (max).
    pub fn should_find_buddy(
        &self,
        tcp_status: FirewallStatus,
        udp_status: FirewallStatus,
    ) -> bool {
        if tcp_status != FirewallStatus::Firewalled {
            return false;
        }
        // UDP Open/Unknown ⇒ direct UDP callback may apply; do not consume a
        // buddy slot. Equivalent to `udp_status != Firewalled` once TCP is
        // confirmed firewalled.
        if super::firewall::can_advertise_direct_udp_callback(tcp_status, udp_status) {
            return false;
        }
        if self.state == BuddyState::Connected {
            return false;
        }
        if self.state == BuddyState::FindingBuddy {
            return false;
        }
        let cooldown = match self.find_attempt_count {
            0 => 0,
            1 => 60,
            2 => 120,
            3 => 240,
            4 => 480,
            _ => 600,
        };
        let now = chrono::Utc::now().timestamp();
        now - self.last_find_attempt > cooldown
    }

    pub fn start_finding(&mut self) {
        self.state = BuddyState::FindingBuddy;
        self.last_find_attempt = chrono::Utc::now().timestamp();
        self.find_attempt_count += 1;
        info!(
            "Starting buddy search (attempt #{})",
            self.find_attempt_count
        );
    }

    pub fn find_failed(&mut self) {
        self.state = BuddyState::NoBuddy;
        let elapsed = chrono::Utc::now().timestamp() - self.last_find_attempt;
        info!(
            "Buddy search attempt #{} failed after {}s, next retry cooldown={}s",
            self.find_attempt_count,
            elapsed,
            match self.find_attempt_count {
                0 => 0,
                1 => 60,
                2 => 120,
                3 => 240,
                4 => 480,
                _ => 600,
            }
        );
    }

    /// True when FindingBuddy state has been active longer than the search
    /// lifetime + a grace window for FindBuddyRes responses (180s total).
    pub fn finding_timed_out(&self) -> bool {
        if self.state != BuddyState::FindingBuddy {
            return false;
        }
        let now = chrono::Utc::now().timestamp();
        now - self.last_find_attempt > 180
    }

    /// Handle FindBuddyRes: connect to buddy, do Hello handshake, start read loop.
    /// We are the firewalled client connecting to a non-firewalled buddy.
    /// Returns everything the real `BuddyManager` needs to adopt the
    /// connection via [`Self::install_buddy_connection`], because this method
    /// may run on a temporary clone whose state is discarded.
    pub async fn handle_findbuddy_response(
        &mut self,
        buddy_id: KadId,
        buddy_ip: Ipv4Addr,
        tcp_port: u16,
        buddy_udp_port: u16,
        peer_user_hash: [u8; 16],
        connect_options: u8,
        allow_obfuscation: bool,
    ) -> Option<OutgoingBuddyConnection> {
        let addr = SocketAddr::new(buddy_ip.into(), tcp_port);
        info!("Connecting to buddy {} at {}", buddy_id, addr);

        let stream = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                debug!("Failed to connect to buddy {}: {}", buddy_id, e);
                self.find_failed();
                return None;
            }
            Err(_) => {
                debug!("Timeout connecting to buddy {}", buddy_id);
                self.find_failed();
                return None;
            }
        };

        let requires_crypt = (connect_options & 0x04) != 0;
        let supports_crypt = (connect_options & 0x01) != 0;
        let use_obf = allow_obfuscation && supports_crypt && peer_user_hash != [0u8; 16];
        if requires_crypt && !use_obf {
            debug!(
                "Buddy {} requires obfuscation but it is unavailable",
                buddy_id
            );
            self.find_failed();
            return None;
        }

        let (reader, writer) = stream.into_split();
        let mut raw_writer = BufWriter::new(writer);
        let mut raw_reader = BufReader::new(reader);

        let (mut reader, mut writer): (BuddyReadStream, BuddyWriteStream) = if use_obf {
            match tcp_obfuscation::negotiate_outgoing(
                &mut raw_reader,
                &mut raw_writer,
                &peer_user_hash,
            )
            .await
            {
                Ok((recv_key, send_key)) => (
                    Box::new(BufReader::new(Rc4Reader::new(raw_reader, recv_key))),
                    Box::new(BufWriter::new(Rc4Writer::new(raw_writer, send_key))),
                ),
                Err(e) => {
                    if requires_crypt {
                        debug!("Obfuscated buddy connect failed and peer requires crypt: {e}");
                        self.find_failed();
                        return None;
                    }
                    debug!("Obfuscated buddy connect failed, reconnecting plain: {e}");
                    drop(raw_reader);
                    drop(raw_writer);
                    let plain_stream = match tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        tokio::net::TcpStream::connect(addr),
                    )
                    .await
                    {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            debug!("Plain reconnect to buddy failed: {e}");
                            self.find_failed();
                            return None;
                        }
                        Err(_) => {
                            debug!("Plain reconnect to buddy timed out");
                            self.find_failed();
                            return None;
                        }
                    };
                    let (r, w) = plain_stream.into_split();
                    (
                        Box::new(BufReader::new(r)) as BuddyReadStream,
                        Box::new(BufWriter::new(w)) as BuddyWriteStream,
                    )
                }
            }
        } else {
            (Box::new(raw_reader), Box::new(raw_writer))
        };

        // Outgoing buddy: we send Hello first, read HelloAnswer
        if let Err(e) = buddy_hello_handshake_outgoing(
            &mut reader,
            &mut writer,
            &self.user_hash,
            &self.nickname,
            self.tcp_port,
            self.udp_port,
            allow_obfuscation,
        )
        .await
        {
            debug!("Buddy Hello handshake failed: {e}");
            self.find_failed();
            return None;
        }

        info!("Buddy connected: {} at {}", buddy_id, addr);
        let (events, disconnect_tx, reader_handle) =
            event_rx_from_reader(reader, self.find_buddy_target());
        Some(OutgoingBuddyConnection {
            buddy_id,
            buddy_ip,
            buddy_tcp_port: tcp_port,
            buddy_udp_port,
            events,
            disconnect_tx,
            writer,
            reader_handle,
        })
    }

    /// Adopt an externally-completed buddy connection (from the spawned
    /// connect task). Returns the event receiver for the caller to store in
    /// `NetworkState::buddy_event_rx`.
    pub fn install_buddy_connection(
        &mut self,
        conn: OutgoingBuddyConnection,
    ) -> mpsc::Receiver<BuddyEvent> {
        if let Some(h) = self.buddy_reader_handle.take() {
            h.abort();
        }
        self.buddy_id = Some(conn.buddy_id);
        self.buddy_addr = Some(SocketAddr::new(
            conn.buddy_ip.into(),
            conn.buddy_tcp_port,
        ));
        self.buddy_udp_port = Some(conn.buddy_udp_port);
        self.buddy_writer = Some(BuddyWriteQueue::spawn(
            conn.writer,
            Some(conn.disconnect_tx),
        ));
        self.buddy_reader_handle = Some(conn.reader_handle);
        self.last_buddy_ping = None;
        self.buddy_ponged_since_ping = false;
        self.state = BuddyState::Connected;
        self.find_attempt_count = 0;
        conn.events
    }

    /// Accept an incoming buddy connection (we are the non-firewalled buddy).
    /// The firewalled client already sent Hello; we already sent HelloAnswer.
    /// `stream` is the already-handshaked TCP connection.
    pub fn accept_buddy_connection(
        &mut self,
        requester_id: KadId,
        callback_check: KadId,
        reader: BuddyReadStream,
        writer: BuddyWriteStream,
    ) -> Option<mpsc::Receiver<BuddyEvent>> {
        if self.serving_buddy_for.is_some() {
            debug!(
                "Already serving as buddy, rejecting request from {}",
                requester_id
            );
            return None;
        }
        let (event_tx, event_rx) = mpsc::channel(BUDDY_EVENT_CHANNEL_SIZE);
        let handle = tokio::spawn(run_buddy_reader(
            reader,
            event_tx.clone(),
            None,
            BUDDY_SERVING_IDLE_TIMEOUT,
        ));

        self.serving_buddy_for = Some(requester_id);
        self.serving_callback_check = Some(callback_check);
        self.serving_callback_budget = 32;
        self.serving_writer = Some(BuddyWriteQueue::spawn(writer, Some(event_tx)));
        self.serving_reader_handle = Some(handle);
        info!("Now serving as buddy for {}", requester_id);
        Some(event_rx)
    }

    /// Register a user hash as a pending buddy (upload listener will check this).
    /// Entries expire after 2 minutes to prevent unbounded growth.
    pub async fn register_pending_buddy(&self, user_hash: [u8; 16], callback_check: KadId) {
        let now = chrono::Utc::now().timestamp();
        let mut map = self.pending_buddy_hashes.lock().await;
        map.retain(|_, (_, ts)| now - *ts < 120);
        if !map.contains_key(&user_hash) && map.len() >= MAX_PENDING_BUDDY_HASHES {
            if let Some(oldest) = map
                .iter()
                .min_by_key(|(_, (_, timestamp))| *timestamp)
                .map(|(hash, _)| *hash)
            {
                map.remove(&oldest);
            }
        }
        map.insert(user_hash, (callback_check, now));
    }

    /// Whether our buddy is due an `OP_BUDDYPING` at `now`. The first ping
    /// goes out on the first tick after connecting.
    pub fn buddy_ping_due(&self, now: Instant) -> bool {
        if self.state != BuddyState::Connected {
            return false;
        }
        let Some(sent) = self.last_buddy_ping else {
            return true;
        };
        let interval = if self.buddy_ponged_since_ping {
            BUDDY_ANSWERED_PING_INTERVAL
        } else {
            BUDDY_PING_INTERVAL
        };
        now.saturating_duration_since(sent) >= interval
    }

    fn record_buddy_ping(&mut self, now: Instant) {
        self.last_buddy_ping = Some(now);
        self.buddy_ponged_since_ping = false;
    }

    pub fn note_buddy_pong(&mut self) {
        self.buddy_ponged_since_ping = true;
    }

    /// Send OP_BUDDYPING to our buddy (we are firewalled).
    pub async fn send_buddy_ping(&mut self) -> bool {
        self.record_buddy_ping(Instant::now());
        let pkt = build_emule_packet(OP_BUDDYPING, &[]);
        match self.enqueue_buddy(pkt) {
            Enqueue::Queued | Enqueue::Busy => true,
            Enqueue::Dead => {
                debug!("Buddy ping failed, connection lost");
                self.disconnect_buddy().await;
                false
            }
        }
    }

    /// Send OP_BUDDYPONG reply on a writer.
    pub async fn send_pong_to_buddy(&mut self) -> bool {
        match self.enqueue_buddy(build_emule_packet(OP_BUDDYPONG, &[])) {
            Enqueue::Queued | Enqueue::Busy => true,
            Enqueue::Dead => {
                self.disconnect_buddy().await;
                false
            }
        }
    }

    /// Send OP_BUDDYPONG reply to our serving client.
    pub fn send_pong_to_serving(&mut self) -> bool {
        match self.enqueue_serving(build_emule_packet(OP_BUDDYPONG, &[])) {
            Enqueue::Queued | Enqueue::Busy => true,
            Enqueue::Dead => {
                self.disconnect_serving();
                false
            }
        }
    }

    /// Send OP_CALLBACK (0x99) to our serving buddy client (Kad callback relay).
    /// Format: [check_hash:16][file_id:16][client_ip:4][client_tcp_port:2]
    /// check_hash = buddy's KadID XOR'd with 0xFF..FF mask (eMule verification)
    ///
    /// Queues the packet on the dedicated writer task. Never `.await`s TCP:
    /// a stalled firewalled client must not block the network event loop
    /// (USS samples KAD RTT there, and a 10s write used to slash every
    /// other peer's upload cap).
    pub fn send_callback_relay(
        &mut self,
        buddy_kad_id: &KadId,
        client_ip: Ipv4Addr,
        client_port: u16,
        file_hash: [u8; 16],
    ) -> bool {
        let Some(check_id) = self.serving_callback_check else {
            return false;
        };
        if *buddy_kad_id != check_id {
            debug!(
                "Rejecting CallbackReq relay: request check {} does not match served buddy check {}",
                buddy_kad_id, check_id
            );
            return false;
        }
        if self.serving_callback_budget == 0 {
            debug!("Rejecting CallbackReq relay: per-session budget exhausted");
            return false;
        }

        let mut payload = Vec::with_capacity(38);
        payload.extend_from_slice(&check_id.0);
        payload.extend_from_slice(&file_hash);
        payload.extend_from_slice(&u32::from(client_ip).to_le_bytes());
        payload.extend_from_slice(&client_port.to_le_bytes());
        let pkt = build_emule_packet(OP_CALLBACK, &payload);
        match self.enqueue_serving(pkt) {
            Enqueue::Queued => {
                self.serving_callback_budget -= 1;
                true
            }
            Enqueue::Busy => {
                debug!("Dropping CallbackReq relay: serving writer is backed up");
                false
            }
            Enqueue::Dead => {
                self.disconnect_serving();
                false
            }
        }
    }

    /// Forward a buddy-relayed UDP reask callback to our own TCP buddy.
    ///
    /// This is the Low-ID-recipient half of the eMule buddy-relay-reask
    /// flow (matches `CClientUDPSocket::ProcessPacket` case
    /// `OP_REASKCALLBACKUDP` in the reference eMule client): another
    /// peer's buddy just sent us an `OP_REASKCALLBACKUDP` over UDP
    /// targeting our `buddy_id`, and we need to turn around and relay
    /// it to our buddy as `OP_REASKCALLBACKTCP` so our buddy can send
    /// the actual UDP reask to the original requester's destination.
    ///
    /// `sender_ip` / `sender_port` identify the upstream relay buddy
    /// (i.e. the other Low-ID peer's buddy) and are placed at the
    /// head of the forwarded payload so the receiving (our own) buddy
    /// knows where to direct its outbound UDP reask. `trailing` is
    /// the tail of the original `OP_REASKCALLBACKUDP` payload after
    /// the 16-byte `buddy_id` header (typically a 16-byte file hash;
    /// any extended tail is forwarded as-is).
    ///
    /// Returns `false` (and drops the buddy connection) when the writer
    /// is gone. A full queue drops this reask without tearing the
    /// session down — the peer will re-ask.
    pub async fn forward_reask_callback(
        &mut self,
        sender_ip: Ipv4Addr,
        sender_port: u16,
        trailing: &[u8],
    ) -> bool {
        let mut payload = Vec::with_capacity(6 + trailing.len());
        payload.extend_from_slice(&u32::from(sender_ip).to_le_bytes());
        payload.extend_from_slice(&sender_port.to_le_bytes());
        payload.extend_from_slice(trailing);
        let pkt = build_emule_packet(OP_REASKCALLBACKTCP, &payload);
        match self.enqueue_buddy(pkt) {
            Enqueue::Queued | Enqueue::Busy => true,
            Enqueue::Dead => {
                debug!("Failed to forward OP_REASKCALLBACKUDP: buddy writer is gone");
                self.disconnect_buddy().await;
                false
            }
        }
    }

    fn enqueue_buddy(&self, pkt: Vec<u8>) -> Enqueue {
        match self.buddy_writer.as_ref() {
            Some(w) => w.try_enqueue(pkt),
            None => Enqueue::Dead,
        }
    }

    fn enqueue_serving(&self, pkt: Vec<u8>) -> Enqueue {
        match self.serving_writer.as_ref() {
            Some(w) => w.try_enqueue(pkt),
            None => Enqueue::Dead,
        }
    }

    pub async fn disconnect_buddy(&mut self) {
        if let Some(h) = self.buddy_reader_handle.take() {
            h.abort();
        }
        if let Some(w) = self.buddy_writer.take() {
            w.abort();
        }
        self.last_buddy_ping = None;
        self.buddy_ponged_since_ping = false;
        self.buddy_id = None;
        self.buddy_addr = None;
        self.buddy_udp_port = None;
        self.state = BuddyState::NoBuddy;
        // `.await` the real lock rather than `try_lock()`: the previous
        // best-effort skip meant that if the upload listener's
        // `register_pending_buddy` happened to hold the lock at this exact
        // moment, `pending_buddy_hashes` was left uncleared and stale
        // entries could linger up to their own 2-minute TTL, causing brief
        // false-positive buddy matching after a disconnect/reconnect.
        self.pending_buddy_hashes.lock().await.clear();
        info!("Buddy disconnected");
    }

    pub fn disconnect_serving(&mut self) {
        if let Some(h) = self.serving_reader_handle.take() {
            h.abort();
        }
        if let Some(w) = self.serving_writer.take() {
            w.abort();
        }
        self.serving_buddy_for = None;
        // Clear the callback-check token too (mirrors `reset()`); leaving a
        // stale token behind would let a later relay path validate against a
        // peer we are no longer serving.
        self.serving_callback_check = None;
        self.serving_callback_budget = 0;
        info!("Stopped serving as buddy");
    }

    pub fn is_serving(&self) -> bool {
        self.serving_buddy_for.is_some()
    }

    pub fn serving_for(&self) -> Option<&KadId> {
        self.serving_buddy_for.as_ref()
    }
}

/// Outgoing buddy handshake: we send Hello, read HelloAnswer, then exchange EmuleInfo.
async fn buddy_hello_handshake_outgoing(
    reader: &mut (dyn AsyncRead + Unpin + Send),
    writer: &mut (dyn AsyncWrite + Unpin + Send),
    user_hash: &[u8; 16],
    nickname: &str,
    tcp_port: u16,
    udp_port: u16,
    obfuscation_enabled: bool,
) -> anyhow::Result<()> {
    let hello_options = crate::network::ed2k::messages::HelloOptions {
        udp_port,
        kad_port: udp_port,
        supports_crypt_layer: obfuscation_enabled,
        requests_crypt_layer: obfuscation_enabled,
        requires_crypt_layer: false,
        supports_direct_udp_callback: crate::network::kad::firewall::advertised_direct_udp_callback(),
        supports_captcha: false,
        server_ip: 0,
        server_port: 0,
        kad_version: 0x09,
    };
    let hello = crate::network::ed2k::messages::build_hello_with_buddy_opts(
        user_hash,
        0,
        tcp_port,
        nickname,
        None,
        &hello_options,
    );
    write_ed2k_packet(writer, OP_EDONKEYHEADER, OP_HELLO, &hello).await?;

    let (proto, opcode, hello_answer) =
        tokio::time::timeout(std::time::Duration::from_secs(15), read_ed2k_packet(reader))
            .await
            .map_err(|_| anyhow::anyhow!("Hello handshake timeout"))??;

    if proto != OP_EDONKEYHEADER || opcode != OP_HELLOANSWER {
        anyhow::bail!("Expected HelloAnswer, got proto=0x{proto:02X} op=0x{opcode:02X}");
    }

    let needs_mule_info = crate::network::ed2k::messages::parse_hello_answer(&hello_answer)
        .is_ok_and(|(hash, caps)| {
            crate::network::ed2k::messages::dialer_needs_mule_info(&hash, &caps)
        });
    if needs_mule_info {
        let emule_info = crate::network::ed2k::messages::build_emule_info(
            udp_port,
            obfuscation_enabled,
            None,
            None,
        );
        write_ed2k_packet(writer, OP_EMULEPROT, OP_EMULEINFO, &emule_info).await?;

        let (proto2, opcode2, _) =
            tokio::time::timeout(std::time::Duration::from_secs(10), read_ed2k_packet(reader))
                .await
                .map_err(|_| anyhow::anyhow!("EmuleInfo timeout"))??;

        if proto2 == OP_EMULEPROT && opcode2 == OP_EMULEINFOANSWER {
            debug!("Buddy EmuleInfo exchange complete");
        } else {
            debug!("Buddy peer did not send EmuleInfoAnswer (proto=0x{proto2:02X} op=0x{opcode2:02X}), continuing");
        }
    }

    debug!("Buddy handshake complete (outgoing)");
    Ok(())
}

/// Spawn a buddy reader task and return the event receiver and task handle.
/// Spawn the reader task and hand back its receiver plus a spare sender, so
/// the buddy write queue can announce its own failures on the same channel.
fn event_rx_from_reader(
    reader: BuddyReadStream,
    buddy_id: KadId,
) -> (
    mpsc::Receiver<BuddyEvent>,
    mpsc::Sender<BuddyEvent>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = mpsc::channel(BUDDY_EVENT_CHANNEL_SIZE);
    let handle = tokio::spawn(run_buddy_reader(
        reader,
        tx.clone(),
        Some(buddy_id),
        BUDDY_IDLE_TIMEOUT,
    ));
    (rx, tx, handle)
}

/// Long-running reader task for a buddy TCP connection.
/// Reads ed2k packets and sends events back via channel.
///
/// `idle_timeout` is a parameter purely so tests can exercise the timeout
/// path in milliseconds instead of real minutes; production passes
/// `BUDDY_IDLE_TIMEOUT` or `BUDDY_SERVING_IDLE_TIMEOUT`.
async fn run_buddy_reader(
    reader: BuddyReadStream,
    event_tx: mpsc::Sender<BuddyEvent>,
    expected_callback_check: Option<KadId>,
    idle_timeout: std::time::Duration,
) {
    let mut reader = reader;
    // K9: per-session OP_REASKCALLBACKTCP budget. A legit buddy using
    // queue reasks for our downloads should need only a handful of these; a
    // malicious buddy trying to reflect UDP traffic runs out quickly. Keep this
    // lower than the authenticated OP_CALLBACK budget because this eMule wire
    // opcode has no check token.
    //
    // OP_CALLBACK carries a cryptographic check token, so only our current
    // buddy should be able to send it successfully, but the destination IP is
    // still buddy-provided. Keep a separate generous budget and apply the same
    // destination safety gate used for reask callbacks so a compromised buddy
    // cannot steer us at loopback/private/reserved hosts.
    let mut callback_budget: u32 = 64;
    let mut reask_callback_budget: u32 = REASK_CALLBACK_BUDGET_PER_SESSION;
    loop {
        let read_result =
            match tokio::time::timeout(idle_timeout, read_ed2k_packet(&mut reader)).await {
                Ok(result) => result,
                Err(_) => {
                    debug!("Buddy reader idle for {idle_timeout:?} with no traffic, disconnecting");
                    let _ = event_tx.send(BuddyEvent::Disconnected).await;
                    break;
                }
            };
        match read_result {
            Ok((proto, opcode, payload)) => {
                let event = match (proto, opcode) {
                    (OP_EMULEPROT, OP_BUDDYPING) => {
                        debug!("Received OP_BUDDYPING");
                        Some(BuddyEvent::PingReceived)
                    }
                    (OP_EMULEPROT, OP_BUDDYPONG) => {
                        debug!("Received OP_BUDDYPONG");
                        Some(BuddyEvent::PongReceived)
                    }
                    (OP_EMULEPROT, OP_CALLBACK) => {
                        // OP_CALLBACK: [check_hash:16][file_id:16][ip:4][tcp_port:2] = 38 bytes
                        if payload.len() >= 38 {
                            if let Some(expected) = expected_callback_check {
                                let mut check = [0u8; 16];
                                check.copy_from_slice(&payload[..16]);
                                if check != expected.0 {
                                    debug!("Ignoring OP_CALLBACK with unexpected check token");
                                    None
                                } else {
                                    let mut file_hash = [0u8; 16];
                                    file_hash.copy_from_slice(&payload[16..32]);
                                    let ip_bytes =
                                        [payload[32], payload[33], payload[34], payload[35]];
                                    let dest_ip = Ipv4Addr::from(u32::from_le_bytes(ip_bytes));
                                    let dest_port = u16::from_le_bytes([payload[36], payload[37]]);
                                    if dest_port == 0 || crate::security::is_special_use_v4(dest_ip)
                                    {
                                        debug!(
                                            "Rejecting OP_CALLBACK: bad dest {}:{}",
                                            dest_ip, dest_port
                                        );
                                        None
                                    } else if callback_budget == 0 {
                                        debug!(
                                            "Rejecting OP_CALLBACK: per-session budget exhausted"
                                        );
                                        None
                                    } else {
                                        callback_budget -= 1;
                                        debug!(
                                            "Received OP_CALLBACK: {}:{} file={} (budget remaining {})",
                                            dest_ip,
                                            dest_port,
                                            hex::encode(file_hash),
                                            callback_budget
                                        );
                                        Some(BuddyEvent::Callback {
                                            file_hash,
                                            dest_ip,
                                            dest_port,
                                        })
                                    }
                                }
                            } else {
                                debug!("Rejecting OP_CALLBACK: no expected check token set");
                                None
                            }
                        } else {
                            debug!("OP_CALLBACK too short ({} bytes)", payload.len());
                            None
                        }
                    }
                    (OP_EMULEPROT, OP_REASKCALLBACKTCP) => {
                        // OP_REASKCALLBACKTCP: [ip:4][port:2][file_hash:16] = 22 bytes.
                        //
                        // K9: this opcode tells us to direct a UDP reask at
                        // `dest_ip:dest_port` on our buddy's behalf. Unlike
                        // OP_CALLBACK it has no cryptographic check token
                        // in the wire format. A malicious buddy could use it
                        // to reflect UDP traffic at arbitrary hosts. Three
                        // layered mitigations here:
                        //   1. Require `dest_port != 0`.
                        //   2. Refuse special-use / loopback / private IPs
                        //      as destination (matches the rest of the
                        //      codebase's `is_special_use_v4` policy).
                        //   3. Rate-limit per buddy session via
                        //      `reask_callback_budget` so a flood of these
                        //      can't amplify our egress.
                        if payload.len() >= 22 {
                            let ip_bytes = [payload[0], payload[1], payload[2], payload[3]];
                            let dest_ip = Ipv4Addr::from(u32::from_le_bytes(ip_bytes));
                            let dest_port = u16::from_le_bytes([payload[4], payload[5]]);
                            let mut file_hash = [0u8; 16];
                            file_hash.copy_from_slice(&payload[6..22]);
                            if dest_port == 0 || crate::security::is_special_use_v4(dest_ip) {
                                debug!(
                                    "Rejecting OP_REASKCALLBACKTCP: bad dest {}:{}",
                                    dest_ip, dest_port
                                );
                                None
                            } else if reask_callback_budget == 0 {
                                debug!(
                                    "Rejecting OP_REASKCALLBACKTCP: per-session budget exhausted"
                                );
                                None
                            } else {
                                reask_callback_budget -= 1;
                                debug!(
                                    "Received OP_REASKCALLBACKTCP: {}:{} hash={} (budget remaining {})",
                                    dest_ip, dest_port, hex::encode(file_hash), reask_callback_budget
                                );
                                Some(BuddyEvent::ReaskCallback {
                                    dest_ip,
                                    dest_port,
                                    file_hash,
                                })
                            }
                        } else {
                            debug!("OP_REASKCALLBACKTCP too short ({} bytes)", payload.len());
                            None
                        }
                    }
                    (OP_EMULEPROT, OP_EMULEINFO) => {
                        debug!("Received OP_EMULEINFO from buddy, ignoring (already handshaked)");
                        None
                    }
                    _ => {
                        debug!("Buddy reader: ignoring proto=0x{proto:02X} op=0x{opcode:02X}");
                        None
                    }
                };
                if let Some(ev) = event {
                    if event_tx.send(ev).await.is_err() {
                        break;
                    }
                }
            }
            Err(e) => {
                debug!("Buddy reader disconnected: {e}");
                let _ = event_tx.send(BuddyEvent::Disconnected).await;
                break;
            }
        }
    }
}

async fn read_ed2k_packet(
    reader: &mut (dyn AsyncRead + Unpin + Send),
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    let protocol = reader.read_u8().await?;
    let length = reader.read_u32_le().await? as usize;
    if length == 0 || length > 65_536 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid packet length: {length}"),
        ));
    }
    let opcode = reader.read_u8().await?;
    let payload_len = length.saturating_sub(1);
    let mut payload = Vec::new();
    if payload_len > 0 {
        // Grow as bytes arrive rather than eagerly allocating the full declared
        // length so a slow/hostile peer can't pin it before sending anything.
        payload.reserve(payload_len.min(16 * 1024));
        let mut remaining = payload_len;
        let mut chunk = [0u8; 16 * 1024];
        while remaining > 0 {
            let want = remaining.min(chunk.len());
            reader.read_exact(&mut chunk[..want]).await?;
            payload.extend_from_slice(&chunk[..want]);
            remaining -= want;
        }
    }
    Ok((protocol, opcode, payload))
}

async fn write_ed2k_packet(
    writer: &mut (dyn AsyncWrite + Unpin + Send),
    protocol: u8,
    opcode: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    // The ed2k header length field is u32. In practice every packet we
    // emit is well under that, but a `len as u32` silent truncation would
    // produce a malformed packet that's ambiguous to the peer, so be explicit.
    let length = u32::try_from(1usize.saturating_add(payload.len())).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "ed2k packet payload too large: {} bytes (max {})",
                payload.len(),
                u32::MAX - 1
            ),
        )
    })?;
    writer.write_u8(protocol).await?;
    writer.write_u32_le(length).await?;
    writer.write_u8(opcode).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

fn build_emule_packet(opcode: u8, payload: &[u8]) -> Vec<u8> {
    // u32::try_from only fails on 64-bit platforms if payload.len() > 4 GiB,
    // which the rest of the stack never builds. saturate to u32::MAX on the
    // off chance to avoid a hidden truncation bug.
    let len = u32::try_from(1usize.saturating_add(payload.len())).unwrap_or(u32::MAX);
    let mut pkt = Vec::with_capacity(6 + payload.len());
    pkt.push(OP_EMULEPROT);
    pkt.extend_from_slice(&len.to_le_bytes());
    pkt.push(opcode);
    pkt.extend_from_slice(payload);
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    fn test_manager() -> BuddyManager {
        let pending: PendingBuddySet = Arc::new(Mutex::new(HashMap::new()));
        BuddyManager::new(
            KadId([1u8; 16]),
            [2u8; 16],
            "test".to_string(),
            4662,
            4672,
            pending,
        )
    }

    #[test]
    fn should_find_buddy_requires_both_ports_firewalled() {
        let mgr = test_manager();
        // eMule (ClientList.cpp): a buddy is needed only while firewalled on
        // BOTH TCP and UDP. A fresh manager has no cooldown, so the only gate
        // under test here is the firewall-status pair.
        assert!(mgr.should_find_buddy(FirewallStatus::Firewalled, FirewallStatus::Firewalled));
        // TCP firewalled but UDP open => reachable via direct UDP callback, so
        // no relay is needed.
        assert!(!mgr.should_find_buddy(FirewallStatus::Firewalled, FirewallStatus::Open));
        // UDP not yet determined => assume open (matches eMule's
        // IsFirewalledUDP) => don't search.
        assert!(!mgr.should_find_buddy(FirewallStatus::Firewalled, FirewallStatus::Unknown));
        // TCP reachable => not firewalled at all => never need a buddy.
        assert!(!mgr.should_find_buddy(FirewallStatus::Open, FirewallStatus::Firewalled));
        assert!(!mgr.should_find_buddy(FirewallStatus::Unknown, FirewallStatus::Firewalled));
        assert!(!mgr.should_find_buddy(FirewallStatus::Open, FirewallStatus::Open));
    }

    #[test]
    fn should_find_buddy_false_while_finding() {
        let mut mgr = test_manager();
        mgr.start_finding();
        // A search is already in flight; don't start another even though both
        // ports are firewalled.
        assert!(!mgr.should_find_buddy(FirewallStatus::Firewalled, FirewallStatus::Firewalled));
    }

    #[tokio::test]
    async fn pending_buddy_hashes_are_capacity_bounded() {
        let manager = test_manager();
        let now = chrono::Utc::now().timestamp();
        {
            let mut pending = manager.pending_buddy_hashes.lock().await;
            for index in 0..MAX_PENDING_BUDDY_HASHES {
                let mut hash = [0u8; 16];
                hash[..8].copy_from_slice(&(index as u64).to_le_bytes());
                pending.insert(hash, (KadId(hash), now));
            }
        }
        let newest = [0xFFu8; 16];
        manager
            .register_pending_buddy(newest, KadId([0xEE; 16]))
            .await;
        let pending = manager.pending_buddy_hashes.lock().await;
        assert_eq!(pending.len(), MAX_PENDING_BUDDY_HASHES);
        assert!(pending.contains_key(&newest));
    }

    /// Regression guard for the "dead firewalled client occupies the single
    /// serving slot forever" bug: with no traffic at all on the reader side
    /// (the peer neither sends anything nor closes the TCP connection —
    /// e.g. it crashed or the network black-holed without a FIN/RST),
    /// `run_buddy_reader` must still emit `BuddyEvent::Disconnected` once
    /// `idle_timeout` elapses, rather than blocking on `read_ed2k_packet`
    /// indefinitely.
    #[tokio::test]
    async fn run_buddy_reader_emits_disconnected_after_idle_timeout() {
        let (client, server) = tokio::io::duplex(64);
        // `server` is never written to and never closed here — it stays
        // open exactly like a black-holed but not-yet-torn-down TCP peer.
        let reader: BuddyReadStream = Box::new(server);
        let (event_tx, mut event_rx) = mpsc::channel(BUDDY_EVENT_CHANNEL_SIZE);
        let handle = tokio::spawn(run_buddy_reader(
            reader,
            event_tx,
            None,
            std::time::Duration::from_millis(50),
        ));

        let event = tokio::time::timeout(std::time::Duration::from_secs(5), event_rx.recv())
            .await
            .expect("run_buddy_reader must emit an event within 5s of the 50ms idle timeout, not hang forever");
        assert!(
            matches!(event, Some(BuddyEvent::Disconnected)),
            "expected Disconnected after idle timeout, got {event:?}"
        );

        drop(client);
        let _ = handle.await;
    }

    /// Runs the real ping schedule on the 60 s buddy tick for four hours
    /// against a buddy that answers a ping when `answers(at)` says so.
    /// Returns the longest gap between packets from the buddy and the
    /// longest gap between our pings.
    fn simulate_buddy_link(mut answers: impl FnMut(Duration) -> bool) -> (Duration, Duration) {
        let mut mgr = test_manager();
        mgr.state = BuddyState::Connected;
        let start = Instant::now();
        let tick = Duration::from_secs(60);
        let (mut last_in, mut last_out) = (Duration::ZERO, Duration::ZERO);
        let (mut longest_in, mut longest_out) = (Duration::ZERO, Duration::ZERO);
        let mut at = tick;
        while at < Duration::from_secs(4 * 3600) {
            if mgr.buddy_ping_due(start + at) {
                mgr.record_buddy_ping(start + at);
                longest_out = longest_out.max(at - last_out);
                last_out = at;
                if answers(at) {
                    mgr.note_buddy_pong();
                    longest_in = longest_in.max(at - last_in);
                    last_in = at;
                }
            }
            at += tick;
        }
        (longest_in, longest_out)
    }

    /// eMule pongs only 13 minutes or more after the client object was made
    /// or its last pong (`AllowIncomingBuddyPingPong`), and drops the socket
    /// after 40 s + 15 min without traffic either way.
    #[test]
    fn emule_buddy_link_outlives_both_idle_timeouts() {
        let thirteen_minutes = Duration::from_secs(13 * 60);
        let mut allowed_from = thirteen_minutes;
        let (longest_in, longest_out) = simulate_buddy_link(|at| {
            if at < allowed_from {
                return false;
            }
            allowed_from = at + thirteen_minutes;
            true
        });
        assert!(
            longest_in + Duration::from_secs(5 * 60) <= BUDDY_IDLE_TIMEOUT,
            "eMule pongs {longest_in:?} apart against a {BUDDY_IDLE_TIMEOUT:?} timeout"
        );
        assert!(longest_out < Duration::from_secs(15 * 60 + 40));
        assert!(longest_out <= BUDDY_PING_INTERVAL + Duration::from_secs(60));
        assert!(BUDDY_SERVING_IDLE_TIMEOUT > 2 * BUDDY_PING_INTERVAL);
    }

    /// Ember up to 1.7.1 answers every ping but drops a served client after
    /// 180 s without a packet, so it must keep getting pinged every tick.
    #[test]
    fn released_ember_buddy_that_answers_every_ping_is_pinged_within_its_timeout() {
        let (longest_in, longest_out) = simulate_buddy_link(|_| true);
        assert!(longest_out < Duration::from_secs(180), "pinged {longest_out:?} apart");
        assert!(longest_in < Duration::from_secs(180));
    }

    #[test]
    fn unanswered_buddy_ping_waits_the_emule_interval() {
        let mut mgr = test_manager();
        let now = Instant::now();
        assert!(!mgr.buddy_ping_due(now), "no buddy, nothing to ping");
        mgr.state = BuddyState::Connected;
        assert!(mgr.buddy_ping_due(now), "first ping goes out right away");

        mgr.record_buddy_ping(now);
        assert!(!mgr.buddy_ping_due(now + Duration::from_secs(60)));
        assert!(!mgr.buddy_ping_due(now + BUDDY_PING_INTERVAL - Duration::from_secs(1)));
        assert!(mgr.buddy_ping_due(now + BUDDY_PING_INTERVAL));

        mgr.note_buddy_pong();
        assert!(mgr.buddy_ping_due(now + Duration::from_secs(60)));
    }

    /// Serving as a buddy used to `.await` `OP_CALLBACK` on the network
    /// event loop. A firewalled client that stopped reading filled the TCP
    /// window and parked every other upload for up to 10s per callback (USS
    /// then slashed the cap). Relays must enqueue without waiting on I/O.
    #[tokio::test]
    async fn send_callback_relay_does_not_block_on_stalled_peer() {
        let mut mgr = test_manager();
        let (client, server) = tokio::io::duplex(32);
        let (reader, writer) = tokio::io::split(server);
        let _client = client;
        let check = KadId([0x11; 16]);
        assert!(mgr
            .accept_buddy_connection(
                KadId([0x22; 16]),
                check,
                Box::new(reader),
                Box::new(writer),
            )
            .is_some());

        let start = std::time::Instant::now();
        for _ in 0..BUDDY_WRITE_CHANNEL_SIZE + 4 {
            let _ = mgr.send_callback_relay(
                &check,
                Ipv4Addr::new(203, 0, 113, 1),
                4662,
                [0xAB; 16],
            );
        }
        assert!(
            start.elapsed() < std::time::Duration::from_millis(200),
            "callback relay must not wait on TCP, took {:?}",
            start.elapsed()
        );
        mgr.disconnect_serving();
    }
}
