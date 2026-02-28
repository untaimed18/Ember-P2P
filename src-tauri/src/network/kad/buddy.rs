use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

use super::types::KadId;

const OP_EDONKEYHEADER: u8 = 0xE3;
const OP_EMULEPROT: u8 = 0xC5;
const OP_HELLO: u8 = 0x01;
const OP_HELLOANSWER: u8 = 0x4C;
const OP_BUDDYPING: u8 = 0x9F;
const OP_BUDDYPONG: u8 = 0xA0;
const OP_REASKCALLBACKTCP: u8 = 0x9A;
const OP_CALLBACK: u8 = 0x99;
const OP_EMULEINFO: u8 = 0x01;
const OP_EMULEINFOANSWER: u8 = 0x02;

const BUDDY_EVENT_CHANNEL_SIZE: usize = 32;

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

pub type PendingBuddySet = Arc<Mutex<std::collections::HashMap<[u8; 16], i64>>>;

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

    buddy_writer: Option<BufWriter<OwnedWriteHalf>>,
    buddy_reader_handle: Option<tokio::task::JoinHandle<()>>,

    serving_buddy_for: Option<KadId>,
    serving_writer: Option<BufWriter<OwnedWriteHalf>>,
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
            buddy_writer: None,
            buddy_reader_handle: None,
            serving_buddy_for: None,
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
        if let Some(h) = self.buddy_reader_handle.take() {
            h.abort();
        }
        self.buddy_writer = None;
        if let Some(h) = self.serving_reader_handle.take() {
            h.abort();
        }
        self.serving_writer = None;
        self.serving_buddy_for = None;
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

    pub fn buddy_addr(&self) -> Option<SocketAddr> {
        self.buddy_addr
    }

    pub fn find_buddy_target(&self) -> KadId {
        let mut target = self.local_id.0;
        target[0] ^= 0xFF;
        target[1] ^= 0xFF;
        KadId(target)
    }

    pub fn should_find_buddy(&self, firewalled: bool) -> bool {
        if !firewalled {
            return false;
        }
        if self.state == BuddyState::Connected {
            return false;
        }
        if self.state == BuddyState::FindingBuddy {
            return false;
        }
        let now = chrono::Utc::now().timestamp();
        now - self.last_find_attempt > 1200
    }

    pub fn start_finding(&mut self) {
        self.state = BuddyState::FindingBuddy;
        self.last_find_attempt = chrono::Utc::now().timestamp();
        info!("Starting buddy search");
    }

    pub fn find_failed(&mut self) {
        self.state = BuddyState::NoBuddy;
        debug!("Buddy search failed, will retry later");
    }

    /// Handle FindBuddyRes: connect to buddy, do Hello handshake, start read loop.
    /// We are the firewalled client connecting to a non-firewalled buddy.
    pub async fn handle_findbuddy_response(
        &mut self,
        buddy_id: KadId,
        buddy_ip: Ipv4Addr,
        tcp_port: u16,
    ) -> Option<mpsc::Receiver<BuddyEvent>> {
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

        let (reader, writer) = stream.into_split();
        let mut writer = BufWriter::new(writer);
        let mut reader = BufReader::new(reader);

        // Outgoing buddy: we send Hello first, read HelloAnswer
        if let Err(e) = buddy_hello_handshake_outgoing(
            &mut reader,
            &mut writer,
            &self.user_hash,
            &self.nickname,
            self.tcp_port,
            self.udp_port,
        )
        .await
        {
            warn!("Buddy Hello handshake failed: {e}");
            self.find_failed();
            return None;
        }

        let (event_tx, event_rx) = mpsc::channel(BUDDY_EVENT_CHANNEL_SIZE);
        let handle = tokio::spawn(run_buddy_reader(reader, event_tx));

        self.buddy_id = Some(buddy_id);
        self.buddy_addr = Some(addr);
        self.buddy_writer = Some(writer);
        self.buddy_reader_handle = Some(handle);
        self.state = BuddyState::Connected;
        info!("Buddy connected: {} at {}", buddy_id, addr);
        Some(event_rx)
    }

    /// Accept an incoming buddy connection (we are the non-firewalled buddy).
    /// The firewalled client already sent Hello; we already sent HelloAnswer.
    /// `stream` is the already-handshaked TCP connection.
    pub fn accept_buddy_connection(
        &mut self,
        requester_id: KadId,
        reader: BufReader<OwnedReadHalf>,
        writer: BufWriter<OwnedWriteHalf>,
    ) -> Option<mpsc::Receiver<BuddyEvent>> {
        if self.serving_buddy_for.is_some() {
            debug!(
                "Already serving as buddy, rejecting request from {}",
                requester_id
            );
            return None;
        }
        let (event_tx, event_rx) = mpsc::channel(BUDDY_EVENT_CHANNEL_SIZE);
        let handle = tokio::spawn(run_buddy_reader(reader, event_tx));

        self.serving_buddy_for = Some(requester_id);
        self.serving_writer = Some(writer);
        self.serving_reader_handle = Some(handle);
        info!("Now serving as buddy for {}", requester_id);
        Some(event_rx)
    }

    /// Register a user hash as a pending buddy (upload listener will check this).
    /// Entries expire after 2 minutes to prevent unbounded growth.
    pub async fn register_pending_buddy(&self, user_hash: [u8; 16]) {
        let now = chrono::Utc::now().timestamp();
        let mut map = self.pending_buddy_hashes.lock().await;
        map.retain(|_, &mut ts| now - ts < 120);
        map.insert(user_hash, now);
    }

    /// Send OP_BUDDYPING to our buddy (we are firewalled).
    pub async fn send_buddy_ping(&mut self) -> bool {
        if let Some(ref mut w) = self.buddy_writer {
            let pkt = build_emule_packet(OP_BUDDYPING, &[]);
            match tokio::time::timeout(std::time::Duration::from_secs(10), w.write_all(&pkt)).await
            {
                Ok(Ok(())) => {
                    let _ = w.flush().await;
                    true
                }
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
        if let Some(ref mut w) = self.serving_writer {
            let mut check_hash = buddy_kad_id.0;
            for b in &mut check_hash { *b ^= 0xFF; }
            let mut payload = Vec::with_capacity(38);
            payload.extend_from_slice(&check_hash);
            payload.extend_from_slice(&file_hash);
            payload.extend_from_slice(&u32::from(client_ip).to_le_bytes());
            payload.extend_from_slice(&client_port.to_le_bytes());
            let pkt = build_emule_packet(OP_CALLBACK, &payload);
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                w.write_all(&pkt),
            ).await {
                Ok(Ok(())) => {
                    let _ = w.flush().await;
                    true
                }
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

    pub fn disconnect_buddy(&mut self) {
        if let Some(h) = self.buddy_reader_handle.take() {
            h.abort();
        }
        self.buddy_writer = None;
        self.buddy_id = None;
        self.buddy_addr = None;
        self.state = BuddyState::NoBuddy;
        info!("Buddy disconnected");
    }

    pub fn disconnect_serving(&mut self) {
        if let Some(h) = self.serving_reader_handle.take() {
            h.abort();
        }
        self.serving_writer = None;
        self.serving_buddy_for = None;
        info!("Stopped serving as buddy");
    }

    pub fn is_serving(&self) -> bool {
        self.serving_buddy_for.is_some()
    }

    pub fn serving_for(&self) -> Option<&KadId> {
        self.serving_buddy_for.as_ref()
    }
}

async fn send_pong(w: &mut BufWriter<OwnedWriteHalf>) -> bool {
    let pkt = build_emule_packet(OP_BUDDYPONG, &[]);
    match w.write_all(&pkt).await {
        Ok(()) => {
            let _ = w.flush().await;
            true
        }
        Err(_) => false,
    }
}

/// Outgoing buddy handshake: we send Hello, read HelloAnswer, then exchange EmuleInfo.
async fn buddy_hello_handshake_outgoing(
    reader: &mut BufReader<OwnedReadHalf>,
    writer: &mut BufWriter<OwnedWriteHalf>,
    user_hash: &[u8; 16],
    nickname: &str,
    tcp_port: u16,
    udp_port: u16,
) -> anyhow::Result<()> {
    let hello = crate::network::ed2k::messages::build_hello(user_hash, 0, tcp_port, nickname);
    write_ed2k_packet(writer, OP_EDONKEYHEADER, OP_HELLO, &hello).await?;

    let (proto, opcode, _payload) =
        tokio::time::timeout(std::time::Duration::from_secs(15), read_ed2k_packet(reader))
            .await
            .map_err(|_| anyhow::anyhow!("Hello handshake timeout"))??;

    if proto != OP_EDONKEYHEADER || opcode != OP_HELLOANSWER {
        anyhow::bail!(
            "Expected HelloAnswer, got proto=0x{proto:02X} op=0x{opcode:02X}"
        );
    }

    let emule_info = crate::network::ed2k::messages::build_emule_info(udp_port);
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

/// Incoming buddy handshake: read Hello, send HelloAnswer.
/// Returns the peer's user_hash extracted from the Hello payload.
pub async fn buddy_hello_handshake_incoming(
    reader: &mut BufReader<OwnedReadHalf>,
    writer: &mut BufWriter<OwnedWriteHalf>,
    user_hash: &[u8; 16],
    nickname: &str,
    tcp_port: u16,
) -> anyhow::Result<[u8; 16]> {
    let (proto, opcode, payload) =
        tokio::time::timeout(std::time::Duration::from_secs(15), read_ed2k_packet(reader))
            .await
            .map_err(|_| anyhow::anyhow!("Hello handshake timeout"))??;

    if proto != OP_EDONKEYHEADER || opcode != OP_HELLO {
        anyhow::bail!(
            "Expected Hello, got proto=0x{proto:02X} op=0x{opcode:02X}"
        );
    }

    let mut peer_user_hash = [0u8; 16];
    if payload.len() >= 17 {
        peer_user_hash.copy_from_slice(&payload[1..17]);
    }

    let hello_ans =
        crate::network::ed2k::messages::build_hello_answer(user_hash, 0, tcp_port, nickname);
    write_ed2k_packet(writer, OP_EDONKEYHEADER, OP_HELLOANSWER, &hello_ans).await?;

    debug!("Buddy Hello handshake complete (incoming)");
    Ok(peer_user_hash)
}

/// Long-running reader task for a buddy TCP connection.
/// Reads ed2k packets and sends events back via channel.
async fn run_buddy_reader(
    reader: BufReader<OwnedReadHalf>,
    event_tx: mpsc::Sender<BuddyEvent>,
) {
    let mut reader = reader;
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
                            let mut file_hash = [0u8; 16];
                            file_hash.copy_from_slice(&payload[16..32]);
                            let ip_bytes = [payload[32], payload[33], payload[34], payload[35]];
                            let dest_ip = Ipv4Addr::from(u32::from_le_bytes(ip_bytes));
                            let dest_port = u16::from_le_bytes([payload[36], payload[37]]);
                            debug!(
                                "Received OP_CALLBACK: {}:{} file={}",
                                dest_ip, dest_port, hex::encode(file_hash)
                            );
                            Some(BuddyEvent::Callback {
                                file_hash,
                                dest_ip,
                                dest_port,
                            })
                        } else {
                            debug!("OP_CALLBACK too short ({} bytes)", payload.len());
                            None
                        }
                    }
                    (OP_EMULEPROT, OP_REASKCALLBACKTCP) => {
                        // OP_REASKCALLBACKTCP: [ip:4][port:2][file_hash:16] = 22 bytes
                        if payload.len() >= 22 {
                            let ip_bytes = [payload[0], payload[1], payload[2], payload[3]];
                            let dest_ip = Ipv4Addr::from(u32::from_le_bytes(ip_bytes));
                            let dest_port = u16::from_le_bytes([payload[4], payload[5]]);
                            let mut file_hash = [0u8; 16];
                            file_hash.copy_from_slice(&payload[6..22]);
                            debug!(
                                "Received OP_REASKCALLBACKTCP: {}:{} hash={}",
                                dest_ip, dest_port, hex::encode(file_hash)
                            );
                            Some(BuddyEvent::ReaskCallback {
                                dest_ip,
                                dest_port,
                                file_hash,
                            })
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
                        debug!(
                            "Buddy reader: ignoring proto=0x{proto:02X} op=0x{opcode:02X}"
                        );
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
    reader: &mut BufReader<OwnedReadHalf>,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    let protocol = reader.read_u8().await?;
    let length = reader.read_u32_le().await? as usize;
    if length == 0 || length > 5_000_000 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid packet length: {length}"),
        ));
    }
    let opcode = reader.read_u8().await?;
    let payload_len = length.saturating_sub(1);
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    Ok((protocol, opcode, payload))
}

async fn write_ed2k_packet(
    writer: &mut BufWriter<OwnedWriteHalf>,
    protocol: u8,
    opcode: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let length = (1 + payload.len()) as u32;
    writer.write_u8(protocol).await?;
    writer.write_u32_le(length).await?;
    writer.write_u8(opcode).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

fn build_emule_packet(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let len = (1 + payload.len()) as u32;
    let mut pkt = Vec::with_capacity(6 + payload.len());
    pkt.push(OP_EMULEPROT);
    pkt.extend_from_slice(&len.to_le_bytes());
    pkt.push(opcode);
    pkt.extend_from_slice(payload);
    pkt
}
