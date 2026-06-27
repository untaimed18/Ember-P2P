use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

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

pub struct BuddyManager {
    local_id: KadId,
    user_hash: [u8; 16],
    nickname: String,
    tcp_port: u16,
    udp_port: u16,
    state: BuddyState,
    buddy_id: Option<KadId>,
    buddy_addr: Option<SocketAddr>,
    last_find_attempt: i64,
    find_attempt_count: u32,

    buddy_writer: Option<BuddyWriteStream>,
    buddy_reader_handle: Option<tokio::task::JoinHandle<()>>,

    serving_buddy_for: Option<KadId>,
    serving_callback_check: Option<KadId>,
    serving_callback_budget: u32,
    serving_writer: Option<BuddyWriteStream>,
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
            last_find_attempt: 0,
            find_attempt_count: 0,
            buddy_writer: None,
            buddy_reader_handle: None,
            serving_buddy_for: None,
            serving_callback_check: None,
            serving_callback_budget: 0,
            serving_writer: None,
            serving_reader_handle: None,
            pending_buddy_hashes,
        }
    }

    pub fn reset(&mut self) {
        self.state = BuddyState::NoBuddy;
        self.buddy_id = None;
        self.buddy_addr = None;
        self.last_find_attempt = 0;
        self.find_attempt_count = 0;
        if let Some(h) = self.buddy_reader_handle.take() {
            h.abort();
        }
        self.buddy_writer = None;
        if let Some(h) = self.serving_reader_handle.take() {
            h.abort();
        }
        self.serving_writer = None;
        self.serving_buddy_for = None;
        self.serving_callback_check = None;
        self.serving_callback_budget = 0;
        if let Ok(mut guard) = self.pending_buddy_hashes.try_lock() {
            guard.clear();
        }
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
    pub fn should_find_buddy(&self, tcp_status: FirewallStatus, udp_status: FirewallStatus) -> bool {
        if tcp_status != FirewallStatus::Firewalled {
            return false;
        }
        if udp_status != FirewallStatus::Firewalled {
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
    /// Returns (event_receiver, writer) so the caller can install the writer
    /// on the real BuddyManager (this method may run on a temporary clone).
    pub async fn handle_findbuddy_response(
        &mut self,
        buddy_id: KadId,
        buddy_ip: Ipv4Addr,
        tcp_port: u16,
        peer_user_hash: [u8; 16],
        connect_options: u8,
        allow_obfuscation: bool,
    ) -> Option<(
        mpsc::Receiver<BuddyEvent>,
        BuddyWriteStream,
        tokio::task::JoinHandle<()>,
    )> {
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
                warn!("Failed to connect to buddy {}: {}", buddy_id, e);
                self.find_failed();
                return None;
            }
            Err(_) => {
                warn!("Timeout connecting to buddy {}", buddy_id);
                self.find_failed();
                return None;
            }
        };

        let requires_crypt = (connect_options & 0x04) != 0;
        let supports_crypt = (connect_options & 0x01) != 0;
        let use_obf = allow_obfuscation && supports_crypt && peer_user_hash != [0u8; 16];
        if requires_crypt && !use_obf {
            warn!(
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
                        warn!("Obfuscated buddy connect failed and peer requires crypt: {e}");
                        self.find_failed();
                        return None;
                    }
                    warn!("Obfuscated buddy connect failed, reconnecting plain: {e}");
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
                            warn!("Plain reconnect to buddy failed: {e}");
                            self.find_failed();
                            return None;
                        }
                        Err(_) => {
                            warn!("Plain reconnect to buddy timed out");
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
            warn!("Buddy Hello handshake failed: {e}");
            self.find_failed();
            return None;
        }

        info!("Buddy connected: {} at {}", buddy_id, addr);
        let (rx, reader_handle) = event_rx_from_reader(reader, self.find_buddy_target());
        Some((rx, writer, reader_handle))
    }

    /// Install an externally-completed buddy connection (writer from spawned task).
    /// Called on the real BuddyManager after a spawned connect task succeeds.
    /// The event receiver is stored separately in NetworkState.buddy_event_rx.
    pub fn install_buddy_connection(
        &mut self,
        buddy_id: KadId,
        buddy_ip: Ipv4Addr,
        buddy_port: u16,
        writer: BuddyWriteStream,
        reader_handle: tokio::task::JoinHandle<()>,
    ) {
        if let Some(h) = self.buddy_reader_handle.take() {
            h.abort();
        }
        self.buddy_id = Some(buddy_id);
        self.buddy_addr = Some(SocketAddr::new(buddy_ip.into(), buddy_port));
        self.buddy_writer = Some(writer);
        self.buddy_reader_handle = Some(reader_handle);
        self.state = BuddyState::Connected;
        self.find_attempt_count = 0;
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
        let handle = tokio::spawn(run_buddy_reader(reader, event_tx, None));

        self.serving_buddy_for = Some(requester_id);
        self.serving_callback_check = Some(callback_check);
        self.serving_callback_budget = 64;
        self.serving_writer = Some(Box::new(writer));
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
        map.insert(user_hash, (callback_check, now));
    }

    /// Send OP_BUDDYPING to our buddy (we are firewalled).
    pub async fn send_buddy_ping(&mut self) -> bool {
        if let Some(ref mut w) = self.buddy_writer {
            let pkt = build_emule_packet(OP_BUDDYPING, &[]);
            match tokio::time::timeout(std::time::Duration::from_secs(10), async {
                w.write_all(&pkt).await?;
                w.flush().await
            })
            .await
            {
                Ok(Ok(())) => true,
                _ => {
                    warn!("Buddy ping failed, connection lost");
                    self.disconnect_buddy();
                    false
                }
            }
        } else {
            false
        }
    }

    /// Send OP_BUDDYPONG reply on a writer.
    pub async fn send_pong_to_buddy(&mut self) -> bool {
        if let Some(ref mut w) = self.buddy_writer {
            send_pong(w).await
        } else {
            false
        }
    }

    /// Send OP_BUDDYPONG reply to our serving client.
    pub async fn send_pong_to_serving(&mut self) -> bool {
        if let Some(ref mut w) = self.serving_writer {
            send_pong(w).await
        } else {
            false
        }
    }

    /// Send OP_CALLBACK (0x99) to our serving buddy client (Kad callback relay).
    /// Format: [check_hash:16][file_id:16][client_ip:4][client_tcp_port:2]
    /// check_hash = buddy's KadID XOR'd with 0xFF..FF mask (eMule verification)
    pub async fn send_callback_relay(
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
        self.serving_callback_budget -= 1;

        if let Some(ref mut w) = self.serving_writer {
            let mut payload = Vec::with_capacity(38);
            payload.extend_from_slice(&check_id.0);
            payload.extend_from_slice(&file_hash);
            payload.extend_from_slice(&u32::from(client_ip).to_le_bytes());
            payload.extend_from_slice(&client_port.to_le_bytes());
            let pkt = build_emule_packet(OP_CALLBACK, &payload);
            match tokio::time::timeout(std::time::Duration::from_secs(10), async {
                w.write_all(&pkt).await?;
                w.flush().await
            })
            .await
            {
                Ok(Ok(())) => true,
                Ok(Err(e)) => {
                    warn!("Failed to relay callback: {e}");
                    self.disconnect_serving();
                    false
                }
                Err(_) => {
                    warn!("Callback relay write timed out");
                    self.disconnect_serving();
                    false
                }
            }
        } else {
            false
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
    /// Returns `false` (and drops the buddy connection) on write
    /// failure / timeout, matching the semantics of the sibling
    /// ping / callback relay helpers. No-ops if we don't currently
    /// have an outbound buddy TCP writer open.
    pub async fn forward_reask_callback(
        &mut self,
        sender_ip: Ipv4Addr,
        sender_port: u16,
        trailing: &[u8],
    ) -> bool {
        let Some(ref mut w) = self.buddy_writer else {
            return false;
        };
        let mut payload = Vec::with_capacity(6 + trailing.len());
        payload.extend_from_slice(&u32::from(sender_ip).to_le_bytes());
        payload.extend_from_slice(&sender_port.to_le_bytes());
        payload.extend_from_slice(trailing);
        let pkt = build_emule_packet(OP_REASKCALLBACKTCP, &payload);
        match tokio::time::timeout(std::time::Duration::from_secs(10), async {
            w.write_all(&pkt).await?;
            w.flush().await
        })
        .await
        {
            Ok(Ok(())) => true,
            Ok(Err(e)) => {
                warn!("Failed to forward OP_REASKCALLBACKUDP to buddy over TCP: {e}");
                self.disconnect_buddy();
                false
            }
            Err(_) => {
                warn!("OP_REASKCALLBACKUDP forward to buddy TCP timed out");
                self.disconnect_buddy();
                false
            }
        }
    }

    pub fn disconnect_buddy(&mut self) {
        if let Some(h) = self.buddy_reader_handle.take() {
            h.abort();
        }
        self.buddy_writer = None;
        self.buddy_id = None;
        self.buddy_addr = None;
        self.state = BuddyState::NoBuddy;
        if let Ok(mut guard) = self.pending_buddy_hashes.try_lock() {
            guard.clear();
        }
        info!("Buddy disconnected");
    }

    pub fn disconnect_serving(&mut self) {
        if let Some(h) = self.serving_reader_handle.take() {
            h.abort();
        }
        self.serving_writer = None;
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

async fn send_pong<W: AsyncWriteExt + Unpin + ?Sized>(w: &mut W) -> bool {
    let pkt = build_emule_packet(OP_BUDDYPONG, &[]);
    matches!(
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            w.write_all(&pkt).await?;
            w.flush().await
        })
        .await,
        Ok(Ok(()))
    )
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
        supports_direct_udp_callback: false,
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

    let (proto, opcode, _payload) =
        tokio::time::timeout(std::time::Duration::from_secs(15), read_ed2k_packet(reader))
            .await
            .map_err(|_| anyhow::anyhow!("Hello handshake timeout"))??;

    if proto != OP_EDONKEYHEADER || opcode != OP_HELLOANSWER {
        anyhow::bail!("Expected HelloAnswer, got proto=0x{proto:02X} op=0x{opcode:02X}");
    }

    let emule_info =
        crate::network::ed2k::messages::build_emule_info(udp_port, obfuscation_enabled, None, None);
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

    debug!("Buddy handshake complete (outgoing)");
    Ok(())
}

/// Spawn a buddy reader task and return the event receiver and task handle.
fn event_rx_from_reader(
    reader: BuddyReadStream,
    buddy_id: KadId,
) -> (mpsc::Receiver<BuddyEvent>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(BUDDY_EVENT_CHANNEL_SIZE);
    let handle = tokio::spawn(run_buddy_reader(reader, tx, Some(buddy_id)));
    (rx, handle)
}

/// Long-running reader task for a buddy TCP connection.
/// Reads ed2k packets and sends events back via channel.
async fn run_buddy_reader(
    reader: BuddyReadStream,
    event_tx: mpsc::Sender<BuddyEvent>,
    expected_callback_check: Option<KadId>,
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
        match read_ed2k_packet(&mut reader).await {
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

    fn test_manager() -> BuddyManager {
        let pending: PendingBuddySet = Arc::new(Mutex::new(HashMap::new()));
        BuddyManager::new(KadId([1u8; 16]), [2u8; 16], "test".to_string(), 4662, 4672, pending)
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
}
