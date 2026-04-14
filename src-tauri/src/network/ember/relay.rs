use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, info};

const MSG_RELAY_REQUEST: u8 = 0x01;
const MSG_RELAY_ACCEPT: u8 = 0x02;
const MSG_RELAY_CONNECT: u8 = 0x03;
#[allow(dead_code)]
const MSG_RELAY_DATA: u8 = 0x04;
const MSG_RELAY_CLOSE: u8 = 0x05;
const MSG_RELAY_REJECT: u8 = 0x06;

const MAX_RELAY_DATA_SIZE: usize = 16384;
#[allow(dead_code)]
const RELAY_BANDWIDTH_LIMIT: usize = 512 * 1024;
const MAX_CONCURRENT_RELAY_SESSIONS: usize = 4;
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
const RELAY_MAX_DURATION: Duration = Duration::from_secs(7200);

/// A relay session between two LowID peers through an intermediary.
#[derive(Debug)]
#[allow(dead_code)]
pub struct RelaySession {
    pub session_id: u32,
    pub initiator_ip: Ipv4Addr,
    pub initiator_port: u16,
    pub target_ip: Ipv4Addr,
    pub target_port: u16,
    pub file_hash: [u8; 16],
    pub state: RelaySessionState,
    pub created: Instant,
    pub last_activity: Instant,
    pub bytes_relayed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum RelaySessionState {
    /// Waiting for target peer to connect to the relay.
    WaitingForTarget,
    /// Both peers connected; actively relaying data.
    Active,
    /// Session is closing down.
    Closing,
}

impl RelaySession {
    pub fn new(
        session_id: u32,
        initiator_ip: Ipv4Addr,
        initiator_port: u16,
        target_ip: Ipv4Addr,
        target_port: u16,
        file_hash: [u8; 16],
    ) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            initiator_ip,
            initiator_port,
            target_ip,
            target_port,
            file_hash,
            state: RelaySessionState::WaitingForTarget,
            created: now,
            last_activity: now,
            bytes_relayed: 0,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > RELAY_IDLE_TIMEOUT
            || self.created.elapsed() > RELAY_MAX_DURATION
    }

    pub fn mark_active(&mut self) {
        self.state = RelaySessionState::Active;
        self.last_activity = Instant::now();
    }

    #[allow(dead_code)]
    pub fn add_relayed_bytes(&mut self, count: usize) {
        self.bytes_relayed += count as u64;
        self.last_activity = Instant::now();
    }
}

/// Manages relay sessions when this node acts as a relay for others.
pub struct RelayManager {
    sessions: HashMap<u32, RelaySession>,
    next_session_id: u32,
    total_bytes_relayed: u64,
}

impl RelayManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_session_id: 1,
            total_bytes_relayed: 0,
        }
    }

    /// Create a new relay session if capacity allows.
    pub fn create_session(
        &mut self,
        initiator_ip: Ipv4Addr,
        initiator_port: u16,
        target_ip: Ipv4Addr,
        target_port: u16,
        file_hash: [u8; 16],
    ) -> Option<u32> {
        if self.sessions.len() >= MAX_CONCURRENT_RELAY_SESSIONS {
            debug!("RelayManager: at capacity ({} sessions)", self.sessions.len());
            return None;
        }

        let id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);

        self.sessions.insert(id, RelaySession::new(
            id, initiator_ip, initiator_port, target_ip, target_port, file_hash,
        ));
        info!("RelayManager: created session {} ({} -> {}:{})", id, initiator_ip, target_ip, target_port);
        Some(id)
    }

    #[allow(dead_code)]
    pub fn get_session(&self, id: u32) -> Option<&RelaySession> {
        self.sessions.get(&id)
    }

    pub fn get_session_mut(&mut self, id: u32) -> Option<&mut RelaySession> {
        self.sessions.get_mut(&id)
    }

    pub fn remove_session(&mut self, id: u32) -> Option<RelaySession> {
        self.sessions.remove(&id)
    }

    /// Clean up expired sessions.
    pub fn cleanup(&mut self) -> Vec<u32> {
        let expired: Vec<u32> = self.sessions.iter()
            .filter(|(_, s)| s.is_expired())
            .map(|(id, _)| *id)
            .collect();

        for id in &expired {
            if let Some(session) = self.sessions.remove(id) {
                info!("RelayManager: expired session {} ({} bytes relayed)", id, session.bytes_relayed);
                self.total_bytes_relayed += session.bytes_relayed;
            }
        }
        expired
    }

    #[allow(dead_code)]
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    #[allow(dead_code)]
    pub fn total_bytes_relayed(&self) -> u64 {
        self.total_bytes_relayed + self.sessions.values().map(|s| s.bytes_relayed).sum::<u64>()
    }
}

/// Encode a relay protocol message.
pub fn encode_relay_message(msg_type: u8, session_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u16;
    let mut buf = Vec::with_capacity(7 + payload.len());
    buf.push(msg_type);
    buf.extend_from_slice(&session_id.to_le_bytes());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Decode a relay protocol message header. Returns (msg_type, session_id, payload).
pub fn decode_relay_message(data: &[u8]) -> Option<(u8, u32, &[u8])> {
    if data.len() < 7 {
        return None;
    }
    let msg_type = data[0];
    let session_id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let payload_len = u16::from_le_bytes([data[5], data[6]]) as usize;
    if data.len() < 7 + payload_len {
        return None;
    }
    Some((msg_type, session_id, &data[7..7 + payload_len]))
}

/// Build a RELAY_REQUEST message.
pub fn build_relay_request(session_id: u32, target_ip: Ipv4Addr, target_port: u16, file_hash: &[u8; 16]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(22);
    payload.extend_from_slice(&target_ip.octets());
    payload.extend_from_slice(&target_port.to_le_bytes());
    payload.extend_from_slice(file_hash);
    encode_relay_message(MSG_RELAY_REQUEST, session_id, &payload)
}

/// Build a RELAY_ACCEPT message.
pub fn build_relay_accept(session_id: u32) -> Vec<u8> {
    encode_relay_message(MSG_RELAY_ACCEPT, session_id, &[])
}

/// Build a RELAY_REJECT message.
pub fn build_relay_reject(session_id: u32, reason: u8) -> Vec<u8> {
    encode_relay_message(MSG_RELAY_REJECT, session_id, &[reason])
}

/// Build a RELAY_CONNECT message sent to the target peer,
/// carrying the file_hash so the target knows what to serve.
pub fn build_relay_connect(session_id: u32, file_hash: &[u8; 16]) -> Vec<u8> {
    encode_relay_message(MSG_RELAY_CONNECT, session_id, file_hash)
}

/// Build a RELAY_DATA message.
#[allow(dead_code)]
pub fn build_relay_data(session_id: u32, data: &[u8]) -> Vec<u8> {
    let chunk = &data[..data.len().min(MAX_RELAY_DATA_SIZE)];
    encode_relay_message(MSG_RELAY_DATA, session_id, chunk)
}

/// Build a RELAY_CLOSE message.
pub fn build_relay_close(session_id: u32) -> Vec<u8> {
    encode_relay_message(MSG_RELAY_CLOSE, session_id, &[])
}

/// Parse a RELAY_REQUEST payload.
pub fn parse_relay_request(payload: &[u8]) -> Option<(Ipv4Addr, u16, [u8; 16])> {
    if payload.len() < 22 {
        return None;
    }
    let ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
    let port = u16::from_le_bytes([payload[4], payload[5]]);
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[6..22]);
    Some((ip, port, hash))
}

/// Client-side helper: register a hole-punch coordination request.
pub async fn register_punch(
    rendezvous_url: &str,
    from_id: &str,
    target_id: &str,
    port: u16,
    nat_type: u8,
) -> Result<(), String> {
    let url = format!("{}/punch", rendezvous_url);
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "from_id": from_id,
            "target_id": target_id,
            "port": port,
            "nat_type": nat_type,
        }))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("punch register: {e}"))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("punch register: status {}", resp.status()))
    }
}

/// Client-side helper: poll for incoming punch requests.
pub async fn poll_punch(
    rendezvous_url: &str,
    our_id: &str,
) -> Result<Option<PunchInfo>, String> {
    let url = format!("{}/punch/{}", rendezvous_url, our_id);
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("punch poll: {e}"))?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!("punch poll: status {}", resp.status()));
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| format!("punch poll parse: {e}"))?;
    Ok(Some(PunchInfo {
        from_id: body["from_id"].as_str().unwrap_or("").to_string(),
        ip: body["ip"].as_str().unwrap_or("").to_string(),
        port: body["port"].as_u64().unwrap_or(0) as u16,
        nat_type: body["nat_type"].as_u64().unwrap_or(5) as u8,
    }))
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PunchInfo {
    pub from_id: String,
    pub ip: String,
    pub port: u16,
    pub nat_type: u8,
}

/// Connect to a relay-capable peer over QUIC and negotiate a relay session.
/// Returns the QUIC streams on success.
pub async fn connect_to_peer_relay(
    endpoint: &quinn::Endpoint,
    relay_addr: SocketAddr,
    target_ip: Ipv4Addr,
    target_port: u16,
    file_hash: &[u8; 16],
) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
    info!("Relay: connecting to peer relay at {relay_addr}");

    let conn = endpoint
        .connect(relay_addr, "ember-relay")
        .map_err(|e| format!("relay connect error: {e}"))?
        .await
        .map_err(|e| format!("relay QUIC handshake failed: {e}"))?;

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("relay open_bi failed: {e}"))?;

    let session_id = rand::random::<u32>();
    let request = build_relay_request(session_id, target_ip, target_port, file_hash);

    send.write_all(&request)
        .await
        .map_err(|e| format!("relay write request: {e}"))?;

    let mut resp_buf = [0u8; 7];
    recv.read_exact(&mut resp_buf)
        .await
        .map_err(|e| format!("relay read response: {e}"))?;

    let (msg_type, returned_sid, _payload) = decode_relay_message(&resp_buf)
        .ok_or_else(|| "invalid relay response".to_string())?;

    if msg_type == MSG_RELAY_REJECT {
        return Err("relay peer rejected request".to_string());
    }
    if msg_type != MSG_RELAY_ACCEPT {
        return Err(format!("unexpected relay response type: {msg_type}"));
    }

    info!("Relay: peer relay accepted at {relay_addr}, session {session_id} (relay echoed {returned_sid})");
    Ok((send, recv))
}

/// WebSocket adapter that implements AsyncRead + AsyncWrite over a
/// tokio-tungstenite WebSocket stream.
pub struct WsStream {
    inner: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl WsStream {
    pub fn new(
        ws: tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> Self {
        Self {
            inner: ws,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

impl AsyncRead for WsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        match Stream::poll_next(Pin::new(&mut self.inner), cx) {
            Poll::Ready(Some(Ok(msg))) => {
                use tokio_tungstenite::tungstenite::Message;
                match msg {
                    Message::Binary(data) => {
                        let to_copy = data.len().min(buf.remaining());
                        buf.put_slice(&data[..to_copy]);
                        if to_copy < data.len() {
                            self.read_buf = data[to_copy..].to_vec();
                            self.read_pos = 0;
                        }
                        Poll::Ready(Ok(()))
                    }
                    Message::Close(_) => Poll::Ready(Ok(())),
                    _ => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        use tokio_tungstenite::tungstenite::Message;

        let msg = Message::Binary(buf.to_vec().into());
        match Sink::poll_ready(Pin::new(&mut self.inner), cx) {
            Poll::Ready(Ok(())) => {
                match Sink::start_send(Pin::new(&mut self.inner), msg) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(e) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e))),
                }
            }
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match Sink::<tokio_tungstenite::tungstenite::Message>::poll_flush(Pin::new(&mut self.inner), cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match Sink::<tokio_tungstenite::tungstenite::Message>::poll_close(Pin::new(&mut self.inner), cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Timeout for the relay node to connect to the target peer.
const RELAY_TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Run the QUIC relay accept loop. Accepts incoming connections from peers
/// that want us to relay their LowID-to-LowID transfers.
///
/// Each incoming connection is handled in a separate task:
///   1. Read RELAY_REQUEST from initiator → create session, respond RELAY_ACCEPT
///   2. Open a QUIC connection to the target peer (we are HighID, so outbound works)
///   3. Bridge both QUIC stream pairs bidirectionally until close or timeout
pub async fn run_relay_accept_loop(
    endpoint: std::sync::Arc<quinn::Endpoint>,
    relay_manager: std::sync::Arc<tokio::sync::Mutex<RelayManager>>,
) {
    info!("Relay accept loop started on {:?}", endpoint.local_addr());
    loop {
        let incoming = match endpoint.accept().await {
            Some(inc) => inc,
            None => {
                info!("Relay accept loop: endpoint closed");
                break;
            }
        };

        let mgr = relay_manager.clone();
        let ep = endpoint.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    debug!("Relay accept: handshake failed: {e}");
                    return;
                }
            };

            let remote = conn.remote_address();
            debug!("Relay accept: new QUIC connection from {remote}");

            let (mut init_send, mut init_recv) = match conn.accept_bi().await {
                Ok(s) => s,
                Err(e) => {
                    debug!("Relay accept: accept_bi failed from {remote}: {e}");
                    return;
                }
            };

            // Read the relay request header (7 bytes)
            let mut header = [0u8; 7];
            if let Err(e) = init_recv.read_exact(&mut header).await {
                debug!("Relay accept: failed to read header from {remote}: {e}");
                return;
            }

            let (msg_type, peer_session_id, _payload_len_slice) =
                match decode_relay_message(&header) {
                    Some((t, sid, p)) => (t, sid, p),
                    None => {
                        debug!("Relay accept: invalid header from {remote}");
                        return;
                    }
                };

            if msg_type != MSG_RELAY_REQUEST {
                debug!("Relay accept: expected RELAY_REQUEST, got {msg_type} from {remote}");
                return;
            }

            // Read the relay request payload (22 bytes: 4 ip + 2 port + 16 hash)
            let mut payload_buf = [0u8; 22];
            if let Err(e) = init_recv.read_exact(&mut payload_buf).await {
                debug!("Relay accept: failed to read request payload from {remote}: {e}");
                return;
            }

            let (target_ip, target_port, file_hash) = match parse_relay_request(&payload_buf) {
                Some(parsed) => parsed,
                None => {
                    debug!("Relay accept: invalid relay request payload from {remote}");
                    return;
                }
            };

            let initiator_ip = match remote.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => {
                    debug!("Relay accept: non-IPv4 remote {remote}");
                    return;
                }
            };
            let initiator_port = remote.port();

            // Create session in the manager
            let session_id = {
                let mut mgr_lock = mgr.lock().await;
                match mgr_lock.create_session(
                    initiator_ip,
                    initiator_port,
                    target_ip,
                    target_port,
                    file_hash,
                ) {
                    Some(sid) => sid,
                    None => {
                        let reject = build_relay_reject(peer_session_id, 0x01);
                        let _ = init_send.write_all(&reject).await;
                        debug!("Relay accept: at capacity, rejected request from {remote}");
                        return;
                    }
                }
            };

            // Send RELAY_ACCEPT back using the peer's session_id so both sides agree
            let accept_msg = build_relay_accept(peer_session_id);
            if let Err(e) = init_send.write_all(&accept_msg).await {
                debug!("Relay accept: failed to send ACCEPT to {remote}: {e}");
                mgr.lock().await.remove_session(session_id);
                return;
            }

            info!(
                "Relay session {session_id}: accepted from {initiator_ip}:{initiator_port}, connecting to target {target_ip}:{target_port}"
            );

            // Connect to the target peer via QUIC (we are HighID so outbound succeeds)
            let target_addr = SocketAddr::new(
                std::net::IpAddr::V4(target_ip),
                target_port,
            );

            let target_result = tokio::time::timeout(
                RELAY_TARGET_CONNECT_TIMEOUT,
                connect_relay_target(&ep, target_addr, session_id, &file_hash),
            )
            .await;

            let (mut tgt_send, mut tgt_recv) = match target_result {
                Ok(Ok(streams)) => streams,
                Ok(Err(e)) => {
                    info!("Relay session {session_id}: target connect failed: {e}");
                    let close = build_relay_close(peer_session_id);
                    let _ = init_send.write_all(&close).await;
                    mgr.lock().await.remove_session(session_id);
                    return;
                }
                Err(_) => {
                    info!("Relay session {session_id}: target connect timed out");
                    let close = build_relay_close(peer_session_id);
                    let _ = init_send.write_all(&close).await;
                    mgr.lock().await.remove_session(session_id);
                    return;
                }
            };

            // Mark session active
            {
                let mut mgr_lock = mgr.lock().await;
                if let Some(session) = mgr_lock.get_session_mut(session_id) {
                    session.mark_active();
                }
            }

            info!("Relay session {session_id}: both sides connected, starting bidirectional relay");

            // Bridge both QUIC stream pairs bidirectionally with a max duration.
            // init_recv → tgt_send (initiator's data goes to target)
            // tgt_recv → init_send (target's data goes to initiator)
            let relay_result = tokio::time::timeout(RELAY_MAX_DURATION, async {
                let i2t = tokio::io::copy(&mut init_recv, &mut tgt_send);
                let t2i = tokio::io::copy(&mut tgt_recv, &mut init_send);

                match tokio::try_join!(i2t, t2i) {
                    Ok((i2t_bytes, t2i_bytes)) => {
                        info!(
                            "Relay session {session_id}: completed (initiator→target: {i2t_bytes}B, target→initiator: {t2i_bytes}B)"
                        );
                        i2t_bytes + t2i_bytes
                    }
                    Err(e) => {
                        debug!("Relay session {session_id}: IO error during relay: {e}");
                        0
                    }
                }
            })
            .await;

            let total_bytes = match relay_result {
                Ok(bytes) => bytes,
                Err(_) => {
                    debug!("Relay session {session_id}: max duration reached");
                    0
                }
            };

            // Clean up
            let _ = init_send.finish();
            let _ = tgt_send.finish();

            if let Some(session) = mgr.lock().await.remove_session(session_id) {
                info!(
                    "Relay session {session_id} ended: {} bytes tracked ({total_bytes} bytes bridged)",
                    session.bytes_relayed
                );
            }
        });
    }
}

/// Connect to a target peer for relay bridging. Sends RELAY_CONNECT to
/// inform the target that this is a relayed connection.
async fn connect_relay_target(
    endpoint: &quinn::Endpoint,
    target_addr: SocketAddr,
    session_id: u32,
    file_hash: &[u8; 16],
) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
    let conn = endpoint
        .connect(target_addr, "ember-relay")
        .map_err(|e| format!("target connect error: {e}"))?
        .await
        .map_err(|e| format!("target QUIC handshake failed with {target_addr}: {e}"))?;

    let (mut send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("target open_bi failed: {e}"))?;

    let connect_msg = build_relay_connect(session_id, file_hash);
    send.write_all(&connect_msg)
        .await
        .map_err(|e| format!("target write RELAY_CONNECT: {e}"))?;

    debug!("Relay: connected to target {target_addr} for session {session_id}");
    Ok((send, recv))
}

/// Connect to the rendezvous server's WebSocket relay endpoint.
/// Returns a WsStream that implements AsyncRead + AsyncWrite.
pub async fn connect_server_relay(
    rendezvous_url: &str,
    session_id: &str,
) -> Result<WsStream, String> {
    let ws_url = format!(
        "{}/relay/{}",
        rendezvous_url
            .replace("https://", "wss://")
            .replace("http://", "ws://"),
        session_id
    );

    info!("Relay: connecting to server relay at {ws_url}");

    let (ws_stream, _response) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .map_err(|e| format!("WS relay connect failed: {e}"))?;

    info!("Relay: server relay connected for session {session_id}");
    Ok(WsStream::new(ws_stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_message_round_trip() {
        let original = encode_relay_message(MSG_RELAY_DATA, 42, b"hello world");
        let (msg_type, session_id, payload) = decode_relay_message(&original).unwrap();
        assert_eq!(msg_type, MSG_RELAY_DATA);
        assert_eq!(session_id, 42);
        assert_eq!(payload, b"hello world");
    }

    #[test]
    fn relay_request_round_trip() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let port = 4662u16;
        let hash = [0xAA; 16];
        let msg = build_relay_request(1, ip, port, &hash);
        let (msg_type, sid, payload) = decode_relay_message(&msg).unwrap();
        assert_eq!(msg_type, MSG_RELAY_REQUEST);
        assert_eq!(sid, 1);
        let (parsed_ip, parsed_port, parsed_hash) = parse_relay_request(payload).unwrap();
        assert_eq!(parsed_ip, ip);
        assert_eq!(parsed_port, port);
        assert_eq!(parsed_hash, hash);
    }

    #[test]
    fn relay_accept_decode() {
        let msg = build_relay_accept(99);
        let (t, sid, payload) = decode_relay_message(&msg).unwrap();
        assert_eq!(t, MSG_RELAY_ACCEPT);
        assert_eq!(sid, 99);
        assert!(payload.is_empty());
    }

    #[test]
    fn relay_manager_session_lifecycle() {
        let mut mgr = RelayManager::new();
        assert_eq!(mgr.active_count(), 0);

        let sid = mgr.create_session(
            Ipv4Addr::new(1, 2, 3, 4), 4662,
            Ipv4Addr::new(5, 6, 7, 8), 4663,
            [1u8; 16],
        ).unwrap();

        assert_eq!(mgr.active_count(), 1);
        assert!(mgr.get_session(sid).is_some());

        mgr.get_session_mut(sid).unwrap().mark_active();
        mgr.get_session_mut(sid).unwrap().add_relayed_bytes(1000);
        assert_eq!(mgr.get_session(sid).unwrap().bytes_relayed, 1000);

        mgr.remove_session(sid);
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn relay_manager_capacity_limit() {
        let mut mgr = RelayManager::new();
        for i in 0..MAX_CONCURRENT_RELAY_SESSIONS {
            let mut ip_bytes = [0u8; 4];
            ip_bytes[3] = (i + 1) as u8;
            assert!(mgr.create_session(
                Ipv4Addr::from(ip_bytes), 4662,
                Ipv4Addr::new(10, 10, 10, 10), 4663,
                [i as u8; 16],
            ).is_some());
        }
        // Next one should fail
        assert!(mgr.create_session(
            Ipv4Addr::new(99, 99, 99, 99), 4662,
            Ipv4Addr::new(10, 10, 10, 10), 4663,
            [0xFF; 16],
        ).is_none());
    }

    #[test]
    fn relay_data_capped() {
        let big = vec![0u8; MAX_RELAY_DATA_SIZE + 100];
        let msg = build_relay_data(1, &big);
        let (_, _, payload) = decode_relay_message(&msg).unwrap();
        assert_eq!(payload.len(), MAX_RELAY_DATA_SIZE);
    }
}
