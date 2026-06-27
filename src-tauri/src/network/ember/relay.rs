use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tracing::{debug, info};

const MSG_RELAY_REQUEST: u8 = 0x01;
const MSG_RELAY_ACCEPT: u8 = 0x02;
const MSG_RELAY_CONNECT: u8 = 0x03;
const MSG_RELAY_CLOSE: u8 = 0x05;
const MSG_RELAY_REJECT: u8 = 0x06;

/// Build a hardened reqwest client for relay/punch HTTP calls.
///
/// M8: previously each helper called `reqwest::Client::new()`,
/// which omitted `https_only`, `no_proxy`, and any body-size
/// guard — strictly weaker than the rendezvous client built in
/// `network/rendezvous.rs::client()`. The relay/punch endpoints
/// hit the same rendezvous server, so they should be subject to
/// the same defense-in-depth posture: refuse to follow a redirect
/// onto plain HTTP, never route through an environment proxy, and
/// hard-cap the request timeout. The body size is bounded
/// indirectly by reqwest's default response cap and the very small
/// JSON shapes these endpoints accept; if a future endpoint needs
/// larger bodies, add an explicit `bytes_per_response` cap here.
fn relay_http_client() -> reqwest::Client {
    match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .no_proxy()
        .https_only(true)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            // Fall back rather than panicking, but keep the proxy-bypass and
            // timeout (only the TLS-backend-dependent `https_only` is at risk
            // of failing). The HTTPS requirement itself is still enforced
            // independently by `require_https` at every call site, so even
            // this degraded client can't be used against a plain-HTTP URL.
            tracing::warn!(
                "relay http client builder failed ({e}); falling back to a no-proxy timeout client"
            );
            reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .no_proxy()
                .build()
                .unwrap_or_else(|_| reqwest::Client::new())
        }
    }
}

/// Defense-in-depth: refuse to contact a non-HTTPS rendezvous/relay URL.
/// `relay_http_client()` already sets `https_only(true)`, but this makes the
/// requirement explicit at each call site and also covers the (near-
/// impossible) builder-failure fallback client.
fn require_https(url: &str) -> Result<(), String> {
    if url.starts_with("https://") {
        Ok(())
    } else {
        Err(format!("refusing non-HTTPS rendezvous/relay URL: {url}"))
    }
}

/// Rendezvous/relay endpoints return tiny JSON shapes; 64 KiB is generous.
const MAX_RENDEZVOUS_JSON_BYTES: usize = 64 * 1024;

/// Read a response body into memory with a hard cap, then deserialize it.
/// `reqwest::Response::json()` buffers the whole body with no size limit, so
/// a malicious or compromised rendezvous server could OOM us by streaming an
/// unbounded body. Stream chunks and bail once the cap is exceeded.
async fn read_json_capped<T: serde::de::DeserializeOwned>(
    mut resp: reqwest::Response,
    max_bytes: usize,
    ctx: &str,
) -> Result<T, String> {
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| format!("{ctx}: {e}"))? {
        if buf.len() + chunk.len() > max_bytes {
            return Err(format!("{ctx}: response exceeds {max_bytes} byte cap"));
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&buf).map_err(|e| format!("{ctx} parse: {e}"))
}
/// Per-direction byte ceiling for a single relay session. Picked to be
/// large enough that real file transfers (eD2K parts are ~9.5 MiB,
/// whole files commonly hundreds of MiB to several GiB) complete
/// without bumping into this cap, while still bounding the worst-case
/// uplink that a misbehaving peer can extract from a relay node — in
/// combination with `MAX_CONCURRENT_RELAY_SESSIONS = 4` and
/// `RELAY_MAX_DURATION = 2h`, the relay's effective uplink ceiling is
/// `4 sessions * 2 dirs * 8 GiB = 64 GiB per 2h window`. The previous
/// constant (`512 KiB`) was misleadingly named "bandwidth limit" but
/// applied as a total-bytes cap via `AsyncRead::take`, which silently
/// stalled every LowID-to-LowID transfer past ~512 KiB per direction.
const RELAY_MAX_BYTES_PER_DIRECTION: u64 = 8 * 1024 * 1024 * 1024;
const MAX_CONCURRENT_RELAY_SESSIONS: usize = 4;
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
const RELAY_MAX_DURATION: Duration = Duration::from_secs(7200);

/// A relay session between two LowID peers through an intermediary.
#[derive(Debug)]
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
pub enum RelaySessionState {
    /// Waiting for target peer to connect to the relay.
    WaitingForTarget,
    /// Both peers connected; actively relaying data.
    Active,
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

    pub fn add_relayed_bytes(&mut self, count: usize) {
        self.bytes_relayed += count as u64;
        self.last_activity = Instant::now();
    }

    /// One-line routing description used in relay lifecycle logs. Reading the
    /// endpoint/file metadata here is also what keeps these fields live — they
    /// are the relay's audit trail of which peers a session bridged and for
    /// which file hash.
    pub fn describe(&self) -> String {
        format!(
            "session {} {}:{} -> {}:{} file {}",
            self.session_id,
            self.initiator_ip,
            self.initiator_port,
            self.target_ip,
            self.target_port,
            hex::encode(self.file_hash),
        )
    }
}

/// Manages relay sessions when this node acts as a relay for others.
pub struct RelayManager {
    sessions: HashMap<u32, RelaySession>,
    attestation_hashes: HashMap<[u8; 32], u64>,
    next_session_id: u32,
    total_bytes_relayed: u64,
}

impl RelayManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            attestation_hashes: HashMap::new(),
            next_session_id: 1,
            total_bytes_relayed: 0,
        }
    }

    pub fn set_current_attestation_hash(&mut self, hash: [u8; 32], expires_at_unix: u64) {
        self.attestation_hashes.clear();
        self.attestation_hashes.insert(hash, expires_at_unix);
    }

    fn accepts_attestation_hash(&mut self, hash: &[u8; 32]) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.attestation_hashes.retain(|_, exp| *exp > now);
        self.attestation_hashes.contains_key(hash)
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
            debug!(
                "RelayManager: at capacity ({} sessions)",
                self.sessions.len()
            );
            return None;
        }

        let id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);

        let session = RelaySession::new(
            id,
            initiator_ip,
            initiator_port,
            target_ip,
            target_port,
            file_hash,
        );
        info!("RelayManager: created {}", session.describe());
        self.sessions.insert(id, session);
        Some(id)
    }

    pub fn get_session_mut(&mut self, id: u32) -> Option<&mut RelaySession> {
        self.sessions.get_mut(&id)
    }

    pub fn remove_session(&mut self, id: u32) -> Option<RelaySession> {
        self.sessions.remove(&id)
    }

    /// Clean up expired sessions.
    pub fn cleanup(&mut self) -> Vec<u32> {
        let expired: Vec<u32> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.is_expired())
            .map(|(id, _)| *id)
            .collect();

        for id in &expired {
            if let Some(session) = self.sessions.remove(id) {
                info!(
                    "RelayManager: expired {} ({} bytes relayed)",
                    session.describe(),
                    session.bytes_relayed
                );
                self.total_bytes_relayed += session.bytes_relayed;
            }
        }
        expired
    }

    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn total_bytes_relayed(&self) -> u64 {
        self.total_bytes_relayed + self.sessions.values().map(|s| s.bytes_relayed).sum::<u64>()
    }
}

/// Encode a relay protocol message.
pub fn encode_relay_message(msg_type: u8, session_id: u32, payload: &[u8]) -> Vec<u8> {
    // The wire framing uses a u16 length prefix. Every relay control message
    // (REQUEST/ACCEPT/CONNECT/CLOSE/REJECT) stays well under that — a few
    // bytes plus an optional 16-byte file hash and 32-byte attestation hash —
    // but assert it so a future caller that overflows the prefix (which would
    // silently corrupt the framing) is caught in debug builds rather than
    // producing undecodable messages.
    debug_assert!(
        payload.len() <= u16::MAX as usize,
        "relay message payload {} exceeds u16 length prefix",
        payload.len()
    );
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

/// Decode just the 7-byte relay header. Used by the QUIC accept loop
/// where we have only read the fixed-size header and still need to
/// know how much body to `read_exact` next; calling
/// [`decode_relay_message`] on the bare header would always fail for
/// any message with a non-zero `payload_len` (e.g. `RELAY_REQUEST`),
/// which previously broke peer-relay accept entirely.
///
/// Returns `(msg_type, session_id, payload_len)`. Always succeeds when
/// `data.len() >= 7`.
pub fn decode_relay_header(data: &[u8]) -> Option<(u8, u32, u16)> {
    if data.len() < 7 {
        return None;
    }
    let msg_type = data[0];
    let session_id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let payload_len = u16::from_le_bytes([data[5], data[6]]);
    Some((msg_type, session_id, payload_len))
}

/// Build a RELAY_REQUEST message.
pub fn build_relay_request_with_attestation_hash(
    session_id: u32,
    target_ip: Ipv4Addr,
    target_port: u16,
    file_hash: &[u8; 16],
    attestation_hash: Option<[u8; 32]>,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(22);
    payload.extend_from_slice(&target_ip.octets());
    payload.extend_from_slice(&target_port.to_le_bytes());
    payload.extend_from_slice(file_hash);
    if let Some(hash) = attestation_hash {
        payload.extend_from_slice(&hash);
    }
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

/// Build a RELAY_CLOSE message.
pub fn build_relay_close(session_id: u32) -> Vec<u8> {
    encode_relay_message(MSG_RELAY_CLOSE, session_id, &[])
}

/// Parse a RELAY_REQUEST payload.
pub fn parse_relay_request_with_attestation_hash(
    payload: &[u8],
) -> Option<(Ipv4Addr, u16, [u8; 16], Option<[u8; 32]>)> {
    if payload.len() < 22 {
        return None;
    }
    let ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
    let port = u16::from_le_bytes([payload[4], payload[5]]);
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[6..22]);
    let attestation_hash = if payload.len() >= 54 {
        let mut h = [0u8; 32];
        h.copy_from_slice(&payload[22..54]);
        Some(h)
    } else {
        None
    };
    Some((ip, port, hash, attestation_hash))
}

/// Client-side helper: register a hole-punch coordination request.
pub async fn register_punch(
    rendezvous_url: &str,
    from_id: &str,
    target_id: &str,
    port: u16,
    nat_type: u8,
) -> Result<(), String> {
    require_https(rendezvous_url)?;
    let url = format!("{}/punch", rendezvous_url);
    let client = relay_http_client();
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

    let status = resp.status();
    if status.is_success() {
        Ok(())
    } else if status == reqwest::StatusCode::NOT_FOUND {
        // The deployed rendezvous server is older than this client and
        // doesn't have the `/punch` route registered. Calling it out
        // explicitly so a `WARN` line is enough to diagnose without
        // having to grep through the source — the same 404 is
        // otherwise indistinguishable from a network blip.
        Err(format!(
            "punch register: status 404 Not Found ({} — deployed rendezvous is missing the /punch route; redeploy the server)",
            url,
        ))
    } else {
        Err(format!("punch register: status {status}"))
    }
}

/// Client-side helper: poll for incoming punch requests.
pub async fn poll_punch(rendezvous_url: &str, our_id: &str) -> Result<Option<PunchInfo>, String> {
    require_https(rendezvous_url)?;
    let url = format!("{}/punch/{}", rendezvous_url, our_id);
    let client = relay_http_client();
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

    let body: serde_json::Value =
        read_json_capped(resp, MAX_RENDEZVOUS_JSON_BYTES, "punch poll").await?;
    Ok(Some(PunchInfo {
        from_id: body["from_id"].as_str().unwrap_or("").to_string(),
        ip: body["ip"].as_str().unwrap_or("").to_string(),
        port: body["port"].as_u64().unwrap_or(0) as u16,
        nat_type: body["nat_type"].as_u64().unwrap_or(5) as u8,
    }))
}

#[derive(Debug, Clone)]
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
    attestation_hash: Option<[u8; 32]>,
    pin: Option<(&[u8], &[u8], [u8; 16])>,
) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
    info!("Relay: connecting to peer relay at {relay_addr}");

    let conn = super::quic::connect_pinned(endpoint, relay_addr, "ember-relay", pin)
        .await
        .map_err(|e| format!("relay QUIC handshake failed: {e}"))?;

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("relay open_bi failed: {e}"))?;

    let session_id = rand::random::<u32>();
    let request = build_relay_request_with_attestation_hash(
        session_id,
        target_ip,
        target_port,
        file_hash,
        attestation_hash,
    );

    send.write_all(&request)
        .await
        .map_err(|e| format!("relay write request: {e}"))?;

    // Read header first (always 7 bytes: msg_type | session_id | payload_len),
    // then drain the payload by length so we don't desynchronize the
    // stream if a future protocol revision (or non-conforming relay)
    // ever sends a non-empty accept/reject body. Cap payload to 64 KiB
    // to avoid reading an attacker-chosen huge `payload_len` into
    // memory.
    let mut resp_header = [0u8; 7];
    recv.read_exact(&mut resp_header)
        .await
        .map_err(|e| format!("relay read response: {e}"))?;
    let payload_len = u16::from_le_bytes([resp_header[5], resp_header[6]]) as usize;
    if payload_len > 64 * 1024 {
        return Err(format!(
            "relay response payload_len {payload_len} exceeds 64 KiB cap"
        ));
    }
    let mut payload_buf = vec![0u8; payload_len];
    if payload_len > 0 {
        recv.read_exact(&mut payload_buf)
            .await
            .map_err(|e| format!("relay read response payload: {e}"))?;
    }
    let mut full = Vec::with_capacity(7 + payload_len);
    full.extend_from_slice(&resp_header);
    full.extend_from_slice(&payload_buf);

    let (msg_type, returned_sid, _payload) =
        decode_relay_message(&full).ok_or_else(|| "invalid relay response".to_string())?;

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

        // Drain non-data WebSocket frames (Ping/Pong/Text/etc.) in a
        // single poll without waking ourselves up — the old code called
        // `wake_by_ref()` and returned `Poll::Pending`, which makes the
        // runtime re-poll immediately and pegs a core at 100% whenever
        // the peer sends frames we don't care about. `tokio-tungstenite`
        // handles ping/pong internally by default, but a buggy or
        // hostile peer could still emit Text frames and we'd spin.
        // Looping here also means we only return `Poll::Pending` when
        // the underlying socket really is out of data.
        loop {
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
                            return Poll::Ready(Ok(()));
                        }
                        // Close and stream-end both surface as EOF
                        // (zero bytes filled). Subsequent polls will
                        // return EOF again via `Poll::Ready(None)`.
                        Message::Close(_) => return Poll::Ready(Ok(())),
                        // Text, Ping, Pong, Frame: not data we should
                        // propagate through an AsyncRead. Drop and
                        // read the next frame in the same poll call.
                        _ => continue,
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
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

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        const MAX_WS_WRITE_FRAME: usize = 16 * 1024;
        let write_len = buf.len().min(MAX_WS_WRITE_FRAME);
        let msg = Message::Binary(buf[..write_len].to_vec().into());
        match Sink::poll_ready(Pin::new(&mut self.inner), cx) {
            Poll::Ready(Ok(())) => match Sink::start_send(Pin::new(&mut self.inner), msg) {
                Ok(()) => Poll::Ready(Ok(write_len)),
                Err(e) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e))),
            },
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Sink::<tokio_tungstenite::tungstenite::Message>::poll_flush(
            Pin::new(&mut self.inner),
            cx,
        ) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Sink::<tokio_tungstenite::tungstenite::Message>::poll_close(
            Pin::new(&mut self.inner),
            cx,
        ) {
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

/// A relay target must be a globally-routable IPv4 unicast address.
///
/// The relay dials whatever `target_ip:target_port` the initiator puts in the
/// RELAY_REQUEST. Without this filter a malicious initiator could point the
/// relay at loopback, RFC1918, link-local or other reserved ranges and use the
/// operator's node as an SSRF / internal-port-scan proxy into its own LAN.
/// Only public unicast targets are dialable.
fn is_public_relay_target(ip: Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        // 0.0.0.0/8 ("this network") — not covered by the helpers above.
        || ip.octets()[0] == 0)
}

/// Maximum number of in-flight QUIC accept tasks. The semaphore is
/// taken **before** spawning to bound pre-auth work — without this,
/// a peer flooding QUIC connections could exhaust scheduler/memory
/// regardless of `RelayManager::MAX_CONCURRENT_RELAY_SESSIONS`
/// (which only kicks in *after* the spawned task has read and
/// parsed the first message).
///
/// The permit is held for the **lifetime of the accept task**, which
/// for relay sessions runs for the duration of the relayed transfer
/// (potentially minutes), so the cap also bounds concurrent relay
/// sessions plus hole-punched direct connections plus in-progress
/// handshakes. Sized at 64 to leave room for normal traffic spikes
/// while still being orders of magnitude below a real
/// scheduler/memory exhaustion threshold.
const QUIC_ACCEPT_INFLIGHT_CAP: usize = 64;

/// Run the QUIC accept loop. Handles three kinds of inbound QUIC connections:
///   1. **RELAY_REQUEST** — peer wants us to relay a LowID transfer (existing relay logic)
///   2. **RELAY_CONNECT** — a relay node is forwarding a client to us (relay target)
///   3. **Raw eMule bytes** — hole-punched direct connection
pub async fn run_quic_accept_loop(
    endpoint: std::sync::Arc<quinn::Endpoint>,
    relay_manager: std::sync::Arc<tokio::sync::Mutex<RelayManager>>,
    kad_callback_tx: tokio::sync::mpsc::Sender<crate::network::ed2k::upload::KadCallbackParts>,
) {
    info!("QUIC accept loop started on {:?}", endpoint.local_addr());
    let accept_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(QUIC_ACCEPT_INFLIGHT_CAP));
    loop {
        let incoming = match endpoint.accept().await {
            Some(inc) => inc,
            None => {
                info!("QUIC accept loop: endpoint closed");
                break;
            }
        };

        // Pre-spawn admission gate. `try_acquire_owned` is non-blocking
        // and lets us drop excess inbound connections fast (refusing
        // the QUIC handshake) instead of queueing work that would
        // accumulate during a flood.
        let permit = match accept_sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                debug!(
                    "QUIC accept: at concurrency cap ({}), refusing inbound from {:?}",
                    QUIC_ACCEPT_INFLIGHT_CAP,
                    incoming.remote_address(),
                );
                incoming.refuse();
                continue;
            }
        };

        let mgr = relay_manager.clone();
        let ep = endpoint.clone();
        let cb_tx = kad_callback_tx.clone();
        tokio::spawn(async move {
            // Hold the permit for the lifetime of the accept task so
            // long-running relay sessions count against the cap; they
            // already have their own per-session timeouts.
            let _permit = permit;
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

            // Read the first 7 bytes to determine connection type.
            // Relay framing: [msg_type(1) | session_id(4 LE) | payload_len(2 LE)]
            // eMule protocol: first byte >= 0xC5 (0xE3=ED2K, 0xC5=eMule, 0xD4=packed)
            let mut header = [0u8; 7];
            if let Err(e) = init_recv.read_exact(&mut header).await {
                debug!("QUIC accept: failed to read header from {remote}: {e}");
                return;
            }

            let msg_type = header[0];

            if msg_type == MSG_RELAY_REQUEST {
                // === Peer relay request: initiator wants us to relay ===
                // We have only read the 7-byte header, so call the
                // header-only decoder rather than `decode_relay_message`,
                // which requires the full body (payload_len = 22 for
                // RELAY_REQUEST) to be present and would otherwise reject
                // every spec-compliant initiator.
                let (_mt, peer_session_id, payload_len) = match decode_relay_header(&header) {
                    Some(decoded) => decoded,
                    None => {
                        debug!("QUIC accept: invalid RELAY_REQUEST header from {remote}");
                        return;
                    }
                };
                if !matches!(payload_len as usize, 22 | 54) {
                    debug!(
                        "QUIC accept: RELAY_REQUEST from {remote} has unexpected payload_len {payload_len} (want 22 or 54)"
                    );
                    return;
                }

                let mut payload_buf = vec![0u8; payload_len as usize];
                if let Err(e) = init_recv.read_exact(&mut payload_buf).await {
                    debug!("QUIC accept: failed to read request payload from {remote}: {e}");
                    return;
                }

                let (target_ip, target_port, file_hash, attestation_hash) =
                    match parse_relay_request_with_attestation_hash(&payload_buf) {
                        Some(parsed) => parsed,
                        None => {
                            debug!("QUIC accept: invalid relay request payload from {remote}");
                            return;
                        }
                    };

                // Refuse to relay to non-public destinations (SSRF/scan guard).
                if target_port == 0 || !is_public_relay_target(target_ip) {
                    debug!(
                        "QUIC accept: refusing relay to non-public target {target_ip}:{target_port} from {remote}"
                    );
                    let reject = build_relay_reject(peer_session_id, 0x02);
                    let _ = init_send.write_all(&reject).await;
                    return;
                }

                let Some(attestation_hash) = attestation_hash else {
                    debug!(
                        "QUIC accept: refusing unauthenticated peer relay request from {remote}"
                    );
                    let reject = build_relay_reject(peer_session_id, 0x03);
                    let _ = init_send.write_all(&reject).await;
                    return;
                };
                {
                    let mut mgr_lock = mgr.lock().await;
                    if !mgr_lock.accepts_attestation_hash(&attestation_hash) {
                        debug!("QUIC accept: refusing relay request from {remote}: unknown or expired attestation hash");
                        let reject = build_relay_reject(peer_session_id, 0x03);
                        let _ = init_send.write_all(&reject).await;
                        return;
                    }
                }

                let initiator_ip = match remote.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => {
                        debug!("QUIC accept: non-IPv4 remote {remote}");
                        return;
                    }
                };
                let initiator_port = remote.port();

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
                            debug!("QUIC accept: at capacity, rejected relay from {remote}");
                            return;
                        }
                    }
                };

                let accept_msg = build_relay_accept(peer_session_id);
                if let Err(e) = init_send.write_all(&accept_msg).await {
                    debug!("QUIC accept: failed to send ACCEPT to {remote}: {e}");
                    mgr.lock().await.remove_session(session_id);
                    return;
                }

                info!(
                    "Relay session {session_id}: accepted from {initiator_ip}:{initiator_port}, connecting to target {target_ip}:{target_port}"
                );

                let target_addr = SocketAddr::new(std::net::IpAddr::V4(target_ip), target_port);

                let target_result = tokio::time::timeout(
                    RELAY_TARGET_CONNECT_TIMEOUT,
                    connect_relay_target(&ep, target_addr, session_id, &file_hash),
                )
                .await;

                let (mut tgt_send, tgt_recv) = match target_result {
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

                {
                    let mut mgr_lock = mgr.lock().await;
                    if let Some(session) = mgr_lock.get_session_mut(session_id) {
                        session.mark_active();
                    }
                    info!(
                        "Relay session {session_id}: bridging ({} active sessions)",
                        mgr_lock.active_count()
                    );
                }

                let bw_limit = RELAY_MAX_BYTES_PER_DIRECTION;
                let relay_result = tokio::time::timeout(RELAY_MAX_DURATION, async {
                    let mut i2t_limited = init_recv.take(bw_limit);
                    let mut t2i_limited = tgt_recv.take(bw_limit);
                    let i2t = tokio::io::copy(&mut i2t_limited, &mut tgt_send);
                    let t2i = tokio::io::copy(&mut t2i_limited, &mut init_send);

                    match tokio::try_join!(i2t, t2i) {
                        Ok((i2t_bytes, t2i_bytes)) => {
                            let total = i2t_bytes + t2i_bytes;
                            if i2t_bytes >= bw_limit || t2i_bytes >= bw_limit {
                                info!(
                                    "Relay session {session_id}: per-direction byte ceiling reached (i→t: {i2t_bytes}B, t→i: {t2i_bytes}B)"
                                );
                            } else {
                                info!(
                                    "Relay session {session_id}: completed (i→t: {i2t_bytes}B, t→i: {t2i_bytes}B)"
                                );
                            }
                            total
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

                let _ = init_send.finish();
                let _ = tgt_send.finish();

                {
                    let mut mgr_lock = mgr.lock().await;
                    if let Some(mut session) = mgr_lock.remove_session(session_id) {
                        session.add_relayed_bytes(total_bytes as usize);
                        info!(
                            "Relay session {session_id} ended: {} bytes relayed ({} active, {} total relayed)",
                            session.bytes_relayed,
                            mgr_lock.active_count(),
                            mgr_lock.total_bytes_relayed() + session.bytes_relayed,
                        );
                    }
                }
            } else if msg_type == MSG_RELAY_CONNECT {
                // === Relay target: a relay node is forwarding a client to us ===
                let payload_len = u16::from_le_bytes([header[5], header[6]]) as usize;
                if payload_len != 16 {
                    debug!(
                        "QUIC accept: RELAY_CONNECT payload length {payload_len} from {remote} (expected 16)"
                    );
                    return;
                }
                let mut file_hash = [0u8; 16];
                if let Err(e) = init_recv.read_exact(&mut file_hash).await {
                    debug!(
                        "QUIC accept: failed to read RELAY_CONNECT file hash from {remote}: {e}"
                    );
                    return;
                }

                let peer_ip = match remote.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => {
                        debug!("QUIC accept: non-IPv4 RELAY_CONNECT from {remote}");
                        return;
                    }
                };

                info!(
                    "QUIC accept: relay-target connection from {remote}, file {}",
                    hex::encode(file_hash)
                );

                let parts = crate::network::ed2k::upload::KadCallbackParts {
                    peer_ip,
                    peer_port: remote.port(),
                    peer_user_hash: [0u8; 16],
                    file_hash,
                    reader: Box::new(init_recv),
                    writer: Box::new(init_send),
                    emule_info_done: false,
                    peer_caps: Default::default(),
                };
                if let Err(e) = cb_tx.try_send(parts) {
                    debug!("QUIC accept: dropping relay-target callback from {remote}: {e}");
                }
            } else {
                // === Hole-punch or other direct connection ===
                let peer_ip = match remote.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => {
                        debug!("QUIC accept: non-IPv4 direct connection from {remote}");
                        return;
                    }
                };

                info!(
                    "QUIC accept: direct connection from {remote} (first byte 0x{:02X})",
                    header[0]
                );

                let chained = std::io::Cursor::new(header.to_vec()).chain(init_recv);
                let parts = crate::network::ed2k::upload::KadCallbackParts {
                    peer_ip,
                    peer_port: remote.port(),
                    peer_user_hash: [0u8; 16],
                    file_hash: [0u8; 16],
                    reader: Box::new(chained),
                    writer: Box::new(init_send),
                    emule_info_done: false,
                    peer_caps: Default::default(),
                };
                if let Err(e) = cb_tx.try_send(parts) {
                    debug!("QUIC accept: dropping direct callback from {remote}: {e}");
                }
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
    // L11: refuse to downgrade ws upgrades to plaintext. The
    // previous implementation rewrote `https://`→`wss://` and also
    // `http://`→`ws://`, which would cheerfully open a plain
    // websocket if the rendezvous URL was misconfigured to use
    // `http://` (e.g. a stale env var). The rest of the system
    // requires HTTPS for the rendezvous control plane, so we should
    // refuse to ride the relay over plaintext too — a
    // network-position attacker can otherwise observe and inject
    // relayed bytes verbatim. If the URL doesn't already use
    // `https://`, return a hard error rather than silently downgrading.
    let trimmed = rendezvous_url.trim();
    if !trimmed.starts_with("https://") {
        return Err(format!(
            "rendezvous URL must use https:// for relay connections, got {trimmed}"
        ));
    }
    let ws_url = format!(
        "{}/relay/{}",
        trimmed.replacen("https://", "wss://", 1),
        session_id
    );

    info!("Relay: connecting to server relay at {ws_url}");

    let (ws_stream, _response) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .map_err(|e| {
            // tokio-tungstenite surfaces an HTTP 404 from the upgrade
            // handshake as `Http(Response { status: 404, ... })`. The
            // raw `Display` is noisy but does contain "404", so we
            // pattern-match on the rendered string. Same intent as the
            // explicit branch in `register_punch`: make a missing
            // route on the deployed rendezvous obvious.
            let rendered = format!("{e}");
            if rendered.contains("404") {
                format!(
                    "WS relay connect failed: 404 Not Found ({ws_url} — deployed rendezvous is missing the /relay route; redeploy the server)"
                )
            } else {
                format!("WS relay connect failed: {rendered}")
            }
        })?;

    info!("Relay: server relay connected for session {session_id}");
    Ok(WsStream::new(ws_stream))
}

/// Post a relay invitation to the rendezvous server, telling the target
/// to connect to the given server-relay session.
pub async fn post_relay_invite(
    rendezvous_url: &str,
    target_id: &str,
    session_id: &str,
) -> Result<(), String> {
    require_https(rendezvous_url)?;
    let url = format!("{}/relay-invite", rendezvous_url.trim_end_matches('/'));
    let client = relay_http_client();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "target_id": target_id,
            "session_id": session_id,
        }))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("relay invite post: {e}"))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("relay invite post: status {}", resp.status()))
    }
}

/// Poll the rendezvous server for pending relay invitations targeting us.
/// Returns a list of session_ids we should connect to via server relay.
pub async fn poll_relay_invites(rendezvous_url: &str, our_id: &str) -> Result<Vec<String>, String> {
    require_https(rendezvous_url)?;
    let url = format!(
        "{}/relay-invites/{}",
        rendezvous_url.trim_end_matches('/'),
        our_id
    );
    let client = relay_http_client();
    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("relay invite poll: {e}"))?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(Vec::new());
    }
    if !resp.status().is_success() {
        return Err(format!("relay invite poll: status {}", resp.status()));
    }

    let body: Vec<serde_json::Value> =
        read_json_capped(resp, MAX_RENDEZVOUS_JSON_BYTES, "relay invite poll").await?;
    Ok(body
        .iter()
        .filter_map(|v| v["session_id"].as_str().map(|s| s.to_string()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_message_round_trip() {
        let original = encode_relay_message(MSG_RELAY_CONNECT, 42, b"hello world");
        let (msg_type, session_id, payload) = decode_relay_message(&original).unwrap();
        assert_eq!(msg_type, MSG_RELAY_CONNECT);
        assert_eq!(session_id, 42);
        assert_eq!(payload, b"hello world");
    }

    #[test]
    fn relay_request_with_attestation_hash_round_trip() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let port = 4662u16;
        let file_hash = [0xAA; 16];
        let attestation_hash = [0xBB; 32];
        let msg = build_relay_request_with_attestation_hash(
            1,
            ip,
            port,
            &file_hash,
            Some(attestation_hash),
        );
        let (msg_type, sid, payload) = decode_relay_message(&msg).unwrap();
        assert_eq!(msg_type, MSG_RELAY_REQUEST);
        assert_eq!(sid, 1);
        let (parsed_ip, parsed_port, parsed_file_hash, parsed_attestation_hash) =
            parse_relay_request_with_attestation_hash(payload).unwrap();
        assert_eq!(parsed_ip, ip);
        assert_eq!(parsed_port, port);
        assert_eq!(parsed_file_hash, file_hash);
        assert_eq!(parsed_attestation_hash, Some(attestation_hash));
    }

    #[test]
    fn relay_manager_accepts_only_current_attestation_hash() {
        let mut mgr = RelayManager::new();
        let current = [1u8; 32];
        let other = [2u8; 32];
        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;
        mgr.set_current_attestation_hash(current, expires);
        assert!(mgr.accepts_attestation_hash(&current));
        assert!(!mgr.accepts_attestation_hash(&other));
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

        let sid = mgr
            .create_session(
                Ipv4Addr::new(1, 2, 3, 4),
                4662,
                Ipv4Addr::new(5, 6, 7, 8),
                4663,
                [1u8; 16],
            )
            .unwrap();

        assert_eq!(mgr.active_count(), 1);
        assert!(mgr.get_session_mut(sid).is_some());

        mgr.get_session_mut(sid).unwrap().mark_active();
        mgr.get_session_mut(sid).unwrap().add_relayed_bytes(1000);
        assert_eq!(mgr.get_session_mut(sid).unwrap().bytes_relayed, 1000);

        mgr.remove_session(sid);
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn relay_manager_capacity_limit() {
        let mut mgr = RelayManager::new();
        for i in 0..MAX_CONCURRENT_RELAY_SESSIONS {
            let mut ip_bytes = [0u8; 4];
            ip_bytes[3] = (i + 1) as u8;
            assert!(mgr
                .create_session(
                    Ipv4Addr::from(ip_bytes),
                    4662,
                    Ipv4Addr::new(10, 10, 10, 10),
                    4663,
                    [i as u8; 16],
                )
                .is_some());
        }
        // Next one should fail
        assert!(mgr
            .create_session(
                Ipv4Addr::new(99, 99, 99, 99),
                4662,
                Ipv4Addr::new(10, 10, 10, 10),
                4663,
                [0xFF; 16],
            )
            .is_none());
    }
}
