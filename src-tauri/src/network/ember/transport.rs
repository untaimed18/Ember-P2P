use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tracing::{debug, trace, warn};

/// Magic bytes that distinguish Ember-encrypted UDP from KAD/ED2K traffic.
pub const EMBER_MAGIC: [u8; 2] = [0xEB, 0x3E];

const PKT_IK_INIT: u8 = 0x01;
const PKT_IK_RESP: u8 = 0x02;
const PKT_XX_MSG1: u8 = 0x03;
const PKT_XX_MSG2: u8 = 0x04;
const PKT_XX_MSG3: u8 = 0x05;
const PKT_TRANSPORT: u8 = 0x10;

const NOISE_PATTERN_IK: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const NOISE_PATTERN_XX: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Overhead per packet: 2 (magic) + 1 (type) = 3 bytes header
const HEADER_LEN: usize = 3;

/// Version byte for small Ember-native control payloads carried inside Noise.
const CONTROL_VERSION: u8 = 1;
const CONTROL_KIND_PING: u8 = 1;
const CONTROL_KIND_PONG: u8 = 2;

/// Sessions idle longer than this are evicted.
const SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum concurrent sessions before we start evicting oldest.
const MAX_SESSIONS: usize = 4096;

/// Maximum concurrent pending handshakes.
const MAX_PENDING: usize = 512;

/// An established encrypted session with a remote peer.
struct NoiseSession {
    transport: snow::TransportState,
    remote_noise_pub: [u8; 32],
    last_activity: Instant,
}

/// In-progress handshake awaiting a response.
enum PendingHandshake {
    /// Noise_IK: we sent message 1, waiting for message 2.
    IkInitiator {
        state: snow::HandshakeState,
        queued: Vec<Vec<u8>>,
        created: Instant,
    },
    /// Noise_XX: we sent message 1, waiting for message 2.
    XxInitiatorMsg1 {
        state: snow::HandshakeState,
        queued: Vec<Vec<u8>>,
        created: Instant,
    },
    /// Noise_XX: responder read message 1, sent message 2, waiting for message 3.
    XxResponderMsg2 {
        state: snow::HandshakeState,
        created: Instant,
    },
}

/// Result of processing an incoming Ember packet.
pub enum IncomingResult {
    /// A decrypted DHT message from a peer with an established session.
    Message {
        from: SocketAddr,
        remote_noise_pub: [u8; 32],
        payload: Vec<u8>,
    },
    /// Handshake progressed; one or more response packets need to be sent.
    HandshakeResponse {
        to: SocketAddr,
        packets: Vec<Vec<u8>>,
    },
    /// Handshake completed; response packets to send, plus any buffered messages
    /// the peer embedded in the handshake.
    HandshakeComplete {
        peer: SocketAddr,
        remote_noise_pub: [u8; 32],
        packets_to_send: Vec<Vec<u8>>,
        decrypted_payload: Option<Vec<u8>>,
    },
    /// Packet was malformed or from an unknown handshake context.
    Rejected,
}

/// Result of preparing an outgoing message.
pub enum OutgoingResult {
    /// Message encrypted and ready to send.
    Ready { packet: Vec<u8> },
    /// No session exists; handshake initiated. The message is queued.
    HandshakeStarted { packet: Vec<u8> },
    /// Message queued behind an in-progress handshake.
    Queued,
    /// Error during encryption or handshake creation.
    Error(String),
}

/// Minimal Ember-native control payload used to prove the Noise transport
/// before routing DHT or file-transfer messages through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmberControlMessage {
    Ping { nonce: u64 },
    Pong { nonce: u64 },
}

impl EmberControlMessage {
    pub fn encode(self) -> [u8; 10] {
        let (kind, nonce) = match self {
            EmberControlMessage::Ping { nonce } => (CONTROL_KIND_PING, nonce),
            EmberControlMessage::Pong { nonce } => (CONTROL_KIND_PONG, nonce),
        };
        let mut out = [0u8; 10];
        out[0] = CONTROL_VERSION;
        out[1] = kind;
        out[2..].copy_from_slice(&nonce.to_le_bytes());
        out
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() != 10 || data[0] != CONTROL_VERSION {
            return None;
        }

        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&data[2..]);
        let nonce = u64::from_le_bytes(nonce);

        match data[1] {
            CONTROL_KIND_PING => Some(EmberControlMessage::Ping { nonce }),
            CONTROL_KIND_PONG => Some(EmberControlMessage::Pong { nonce }),
            _ => None,
        }
    }
}

pub struct EmberTransport {
    local_noise_key: [u8; 32],
    local_noise_pub: [u8; 32],
    sessions: HashMap<SocketAddr, NoiseSession>,
    pending: HashMap<SocketAddr, PendingHandshake>,
}

impl EmberTransport {
    pub fn new(local_noise_key: [u8; 32], local_noise_pub: [u8; 32]) -> Self {
        Self {
            local_noise_key,
            local_noise_pub,
            sessions: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Check if a raw UDP packet is an Ember-encrypted packet.
    pub fn is_ember_packet(data: &[u8]) -> bool {
        data.len() >= HEADER_LEN && data[0] == EMBER_MAGIC[0] && data[1] == EMBER_MAGIC[1]
    }

    /// Our Noise static public key (X25519).
    pub fn local_noise_public_key(&self) -> &[u8; 32] {
        &self.local_noise_pub
    }

    /// Number of active encrypted sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Check if we have an established session with a peer.
    pub fn has_session(&self, addr: &SocketAddr) -> bool {
        self.sessions.contains_key(addr)
    }

    /// Process an incoming Ember-encrypted UDP packet.
    pub fn process_incoming(&mut self, data: &[u8], from: SocketAddr) -> IncomingResult {
        if data.len() < HEADER_LEN {
            return IncomingResult::Rejected;
        }
        if data[0] != EMBER_MAGIC[0] || data[1] != EMBER_MAGIC[1] {
            return IncomingResult::Rejected;
        }

        let pkt_type = data[2];
        let payload = &data[HEADER_LEN..];

        match pkt_type {
            PKT_IK_INIT => self.handle_ik_init(from, payload),
            PKT_IK_RESP => self.handle_ik_resp(from, payload),
            PKT_XX_MSG1 => self.handle_xx_msg1(from, payload),
            PKT_XX_MSG2 => self.handle_xx_msg2(from, payload),
            PKT_XX_MSG3 => self.handle_xx_msg3(from, payload),
            PKT_TRANSPORT => self.handle_transport(from, payload),
            _ => {
                debug!("Unknown Ember packet type 0x{pkt_type:02x} from {from}");
                IncomingResult::Rejected
            }
        }
    }

    /// Encrypt and frame a DHT message for a peer.
    ///
    /// If `remote_noise_pub` is `Some`, we initiate Noise_IK (1-RTT) when
    /// there is no existing session. If `None`, we fall back to Noise_XX (2-RTT).
    pub fn prepare_outgoing(
        &mut self,
        peer: SocketAddr,
        remote_noise_pub: Option<&[u8; 32]>,
        message: &[u8],
    ) -> OutgoingResult {
        // Fast path: established session
        if let Some(session) = self.sessions.get_mut(&peer) {
            session.last_activity = Instant::now();
            let mut buf = vec![0u8; HEADER_LEN + message.len() + 64]; // AEAD tag overhead
            buf[0] = EMBER_MAGIC[0];
            buf[1] = EMBER_MAGIC[1];
            buf[2] = PKT_TRANSPORT;
            match session.transport.write_message(message, &mut buf[HEADER_LEN..]) {
                Ok(len) => {
                    buf.truncate(HEADER_LEN + len);
                    return OutgoingResult::Ready { packet: buf };
                }
                Err(e) => {
                    warn!("Ember transport encrypt error for {peer}: {e}");
                    self.sessions.remove(&peer);
                    return OutgoingResult::Error(format!("encrypt failed: {e}"));
                }
            }
        }

        // Queue behind in-progress handshake
        if let Some(pending) = self.pending.get_mut(&peer) {
            match pending {
                PendingHandshake::IkInitiator { queued, .. }
                | PendingHandshake::XxInitiatorMsg1 { queued, .. } => {
                    queued.push(message.to_vec());
                    return OutgoingResult::Queued;
                }
                PendingHandshake::XxResponderMsg2 { .. } => {
                    return OutgoingResult::Queued;
                }
            }
        }

        // Start new handshake
        if self.pending.len() >= MAX_PENDING {
            self.evict_oldest_pending();
        }

        if let Some(remote_pub) = remote_noise_pub {
            self.start_ik_handshake(peer, remote_pub, message)
        } else {
            self.start_xx_handshake(peer, message)
        }
    }

    /// Remove expired sessions and pending handshakes.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.sessions
            .retain(|_, s| now.duration_since(s.last_activity) < SESSION_TIMEOUT);
        self.pending.retain(|_, p| {
            let created = match p {
                PendingHandshake::IkInitiator { created, .. } => *created,
                PendingHandshake::XxInitiatorMsg1 { created, .. } => *created,
                PendingHandshake::XxResponderMsg2 { created, .. } => *created,
            };
            now.duration_since(created) < Duration::from_secs(30)
        });
    }

    /// Remove an existing session for a peer (e.g., on disconnect).
    pub fn remove_session(&mut self, addr: &SocketAddr) {
        self.sessions.remove(addr);
        self.pending.remove(addr);
    }

    // ── Noise_IK handshake (1-RTT, we know the peer's static key) ──

    fn start_ik_handshake(
        &mut self,
        peer: SocketAddr,
        remote_pub: &[u8; 32],
        first_message: &[u8],
    ) -> OutgoingResult {
        let params = match NOISE_PATTERN_IK.parse::<snow::params::NoiseParams>() {
            Ok(p) => p,
            Err(e) => return OutgoingResult::Error(format!("noise params: {e}")),
        };
        let mut initiator = match snow::Builder::new(params)
            .local_private_key(&self.local_noise_key)
            .remote_public_key(remote_pub)
            .build_initiator()
        {
            Ok(s) => s,
            Err(e) => return OutgoingResult::Error(format!("noise init: {e}")),
        };

        // IK message 1 can carry a payload (our DHT request)
        let mut buf = vec![0u8; HEADER_LEN + first_message.len() + 256];
        buf[0] = EMBER_MAGIC[0];
        buf[1] = EMBER_MAGIC[1];
        buf[2] = PKT_IK_INIT;
        match initiator.write_message(first_message, &mut buf[HEADER_LEN..]) {
            Ok(len) => {
                buf.truncate(HEADER_LEN + len);
                self.pending.insert(
                    peer,
                    PendingHandshake::IkInitiator {
                        state: initiator,
                        queued: Vec::new(),
                        created: Instant::now(),
                    },
                );
                trace!("Started IK handshake with {peer}");
                OutgoingResult::HandshakeStarted { packet: buf }
            }
            Err(e) => OutgoingResult::Error(format!("noise write: {e}")),
        }
    }

    fn handle_ik_init(&mut self, from: SocketAddr, data: &[u8]) -> IncomingResult {
        let params = match NOISE_PATTERN_IK.parse::<snow::params::NoiseParams>() {
            Ok(p) => p,
            Err(_) => return IncomingResult::Rejected,
        };
        let mut responder = match snow::Builder::new(params)
            .local_private_key(&self.local_noise_key)
            .build_responder()
        {
            Ok(s) => s,
            Err(e) => {
                debug!("IK responder build failed for {from}: {e}");
                return IncomingResult::Rejected;
            }
        };

        // Read message 1 (may contain a DHT request payload)
        let mut payload_buf = vec![0u8; data.len()];
        let payload_len = match responder.read_message(data, &mut payload_buf) {
            Ok(len) => len,
            Err(e) => {
                debug!("IK read_message failed from {from}: {e}");
                return IncomingResult::Rejected;
            }
        };

        // Write message 2 (empty payload for now; DHT response comes via transport)
        let mut resp_buf = vec![0u8; HEADER_LEN + 256];
        resp_buf[0] = EMBER_MAGIC[0];
        resp_buf[1] = EMBER_MAGIC[1];
        resp_buf[2] = PKT_IK_RESP;
        let resp_len = match responder.write_message(&[], &mut resp_buf[HEADER_LEN..]) {
            Ok(len) => len,
            Err(e) => {
                debug!("IK write_message failed for {from}: {e}");
                return IncomingResult::Rejected;
            }
        };
        resp_buf.truncate(HEADER_LEN + resp_len);

        let remote_noise_pub = match extract_remote_static(&responder) {
            Some(k) => k,
            None => {
                debug!("IK responder: handshake completed without remote static key from {from}");
                return IncomingResult::Rejected;
            }
        };
        let transport = match responder.into_transport_mode() {
            Ok(t) => t,
            Err(e) => {
                debug!("IK into_transport failed for {from}: {e}");
                return IncomingResult::Rejected;
            }
        };

        if self.sessions.len() >= MAX_SESSIONS {
            self.evict_oldest_session();
        }
        self.sessions.insert(
            from,
            NoiseSession {
                transport,
                remote_noise_pub,
                last_activity: Instant::now(),
            },
        );
        trace!("IK handshake completed (responder) with {from}");

        let decrypted = if payload_len > 0 {
            Some(payload_buf[..payload_len].to_vec())
        } else {
            None
        };

        IncomingResult::HandshakeComplete {
            peer: from,
            remote_noise_pub,
            packets_to_send: vec![resp_buf],
            decrypted_payload: decrypted,
        }
    }

    fn handle_ik_resp(&mut self, from: SocketAddr, data: &[u8]) -> IncomingResult {
        let pending = match self.pending.remove(&from) {
            Some(PendingHandshake::IkInitiator { state, queued, .. }) => (state, queued),
            Some(other) => {
                self.pending.insert(from, other);
                debug!("Unexpected IK response from {from} (wrong handshake type)");
                return IncomingResult::Rejected;
            }
            None => {
                debug!("IK response from {from} but no pending handshake");
                return IncomingResult::Rejected;
            }
        };

        let (mut state, queued) = pending;
        let mut payload_buf = vec![0u8; data.len()];
        let _payload_len = match state.read_message(data, &mut payload_buf) {
            Ok(len) => len,
            Err(e) => {
                debug!("IK resp read_message failed from {from}: {e}");
                return IncomingResult::Rejected;
            }
        };

        let remote_noise_pub = match extract_remote_static(&state) {
            Some(k) => k,
            None => {
                debug!("IK initiator: handshake completed without remote static key from {from}");
                return IncomingResult::Rejected;
            }
        };
        let mut transport = match state.into_transport_mode() {
            Ok(t) => t,
            Err(e) => {
                debug!("IK into_transport failed for {from}: {e}");
                return IncomingResult::Rejected;
            }
        };

        // Send queued messages
        let mut packets = Vec::new();
        for msg in &queued {
            let mut buf = vec![0u8; HEADER_LEN + msg.len() + 64];
            buf[0] = EMBER_MAGIC[0];
            buf[1] = EMBER_MAGIC[1];
            buf[2] = PKT_TRANSPORT;
            if let Ok(len) = transport.write_message(msg, &mut buf[HEADER_LEN..]) {
                buf.truncate(HEADER_LEN + len);
                packets.push(buf);
            }
        }

        if self.sessions.len() >= MAX_SESSIONS {
            self.evict_oldest_session();
        }
        self.sessions.insert(
            from,
            NoiseSession {
                transport,
                remote_noise_pub,
                last_activity: Instant::now(),
            },
        );
        trace!("IK handshake completed (initiator) with {from}");

        IncomingResult::HandshakeComplete {
            peer: from,
            remote_noise_pub,
            packets_to_send: packets,
            decrypted_payload: None,
        }
    }

    // ── Noise_XX handshake (2-RTT, we don't know the peer's static key) ──

    fn start_xx_handshake(
        &mut self,
        peer: SocketAddr,
        first_message: &[u8],
    ) -> OutgoingResult {
        let params = match NOISE_PATTERN_XX.parse::<snow::params::NoiseParams>() {
            Ok(p) => p,
            Err(e) => return OutgoingResult::Error(format!("noise params: {e}")),
        };
        let mut initiator = match snow::Builder::new(params)
            .local_private_key(&self.local_noise_key)
            .build_initiator()
        {
            Ok(s) => s,
            Err(e) => return OutgoingResult::Error(format!("noise init: {e}")),
        };

        // XX message 1: only ephemeral key, no payload
        let mut buf = vec![0u8; HEADER_LEN + 256];
        buf[0] = EMBER_MAGIC[0];
        buf[1] = EMBER_MAGIC[1];
        buf[2] = PKT_XX_MSG1;
        match initiator.write_message(&[], &mut buf[HEADER_LEN..]) {
            Ok(len) => {
                buf.truncate(HEADER_LEN + len);
                self.pending.insert(
                    peer,
                    PendingHandshake::XxInitiatorMsg1 {
                        state: initiator,
                        queued: vec![first_message.to_vec()],
                        created: Instant::now(),
                    },
                );
                trace!("Started XX handshake with {peer}");
                OutgoingResult::HandshakeStarted { packet: buf }
            }
            Err(e) => OutgoingResult::Error(format!("noise write: {e}")),
        }
    }

    fn handle_xx_msg1(&mut self, from: SocketAddr, data: &[u8]) -> IncomingResult {
        let params = match NOISE_PATTERN_XX.parse::<snow::params::NoiseParams>() {
            Ok(p) => p,
            Err(_) => return IncomingResult::Rejected,
        };
        let mut responder = match snow::Builder::new(params)
            .local_private_key(&self.local_noise_key)
            .build_responder()
        {
            Ok(s) => s,
            Err(e) => {
                debug!("XX responder build failed for {from}: {e}");
                return IncomingResult::Rejected;
            }
        };

        let mut buf = vec![0u8; data.len() + 64];
        if let Err(e) = responder.read_message(data, &mut buf) {
            debug!("XX msg1 read failed from {from}: {e}");
            return IncomingResult::Rejected;
        }

        // Write message 2 (includes responder's static key)
        let mut resp_buf = vec![0u8; HEADER_LEN + 256];
        resp_buf[0] = EMBER_MAGIC[0];
        resp_buf[1] = EMBER_MAGIC[1];
        resp_buf[2] = PKT_XX_MSG2;
        let resp_len = match responder.write_message(&[], &mut resp_buf[HEADER_LEN..]) {
            Ok(len) => len,
            Err(e) => {
                debug!("XX msg2 write failed for {from}: {e}");
                return IncomingResult::Rejected;
            }
        };
        resp_buf.truncate(HEADER_LEN + resp_len);

        if self.pending.len() >= MAX_PENDING {
            self.evict_oldest_pending();
        }
        self.pending.insert(
            from,
            PendingHandshake::XxResponderMsg2 {
                state: responder,
                created: Instant::now(),
            },
        );
        trace!("XX handshake msg2 sent to {from}");

        IncomingResult::HandshakeResponse {
            to: from,
            packets: vec![resp_buf],
        }
    }

    fn handle_xx_msg2(&mut self, from: SocketAddr, data: &[u8]) -> IncomingResult {
        let pending = match self.pending.remove(&from) {
            Some(PendingHandshake::XxInitiatorMsg1 {
                state, queued, ..
            }) => (state, queued),
            Some(other) => {
                self.pending.insert(from, other);
                debug!("Unexpected XX msg2 from {from}");
                return IncomingResult::Rejected;
            }
            None => {
                debug!("XX msg2 from {from} but no pending handshake");
                return IncomingResult::Rejected;
            }
        };

        let (mut state, queued) = pending;
        let mut buf = vec![0u8; data.len() + 64];
        if let Err(e) = state.read_message(data, &mut buf) {
            debug!("XX msg2 read failed from {from}: {e}");
            return IncomingResult::Rejected;
        }

        // Write message 3 (includes initiator's static key + first queued message as payload)
        let payload = queued.first().map(|v| v.as_slice()).unwrap_or(&[]);
        let mut resp_buf = vec![0u8; HEADER_LEN + payload.len() + 256];
        resp_buf[0] = EMBER_MAGIC[0];
        resp_buf[1] = EMBER_MAGIC[1];
        resp_buf[2] = PKT_XX_MSG3;
        let resp_len = match state.write_message(payload, &mut resp_buf[HEADER_LEN..]) {
            Ok(len) => len,
            Err(e) => {
                debug!("XX msg3 write failed for {from}: {e}");
                return IncomingResult::Rejected;
            }
        };
        resp_buf.truncate(HEADER_LEN + resp_len);

        let remote_noise_pub = match extract_remote_static(&state) {
            Some(k) => k,
            None => {
                debug!("XX initiator: handshake completed without remote static key from {from}");
                return IncomingResult::Rejected;
            }
        };
        let mut transport = match state.into_transport_mode() {
            Ok(t) => t,
            Err(e) => {
                debug!("XX into_transport failed for {from}: {e}");
                return IncomingResult::Rejected;
            }
        };

        // Send remaining queued messages (skip first, it was in msg3 payload)
        let mut packets = vec![resp_buf];
        for msg in queued.iter().skip(1) {
            let mut pkt = vec![0u8; HEADER_LEN + msg.len() + 64];
            pkt[0] = EMBER_MAGIC[0];
            pkt[1] = EMBER_MAGIC[1];
            pkt[2] = PKT_TRANSPORT;
            if let Ok(len) = transport.write_message(msg, &mut pkt[HEADER_LEN..]) {
                pkt.truncate(HEADER_LEN + len);
                packets.push(pkt);
            }
        }

        if self.sessions.len() >= MAX_SESSIONS {
            self.evict_oldest_session();
        }
        self.sessions.insert(
            from,
            NoiseSession {
                transport,
                remote_noise_pub,
                last_activity: Instant::now(),
            },
        );
        trace!("XX handshake completed (initiator) with {from}");

        IncomingResult::HandshakeComplete {
            peer: from,
            remote_noise_pub,
            packets_to_send: packets,
            decrypted_payload: None,
        }
    }

    fn handle_xx_msg3(&mut self, from: SocketAddr, data: &[u8]) -> IncomingResult {
        let pending = match self.pending.remove(&from) {
            Some(PendingHandshake::XxResponderMsg2 { state, .. }) => state,
            Some(other) => {
                self.pending.insert(from, other);
                debug!("Unexpected XX msg3 from {from}");
                return IncomingResult::Rejected;
            }
            None => {
                debug!("XX msg3 from {from} but no pending handshake");
                return IncomingResult::Rejected;
            }
        };

        let mut state = pending;
        let mut payload_buf = vec![0u8; data.len()];
        let payload_len = match state.read_message(data, &mut payload_buf) {
            Ok(len) => len,
            Err(e) => {
                debug!("XX msg3 read failed from {from}: {e}");
                return IncomingResult::Rejected;
            }
        };

        let remote_noise_pub = match extract_remote_static(&state) {
            Some(k) => k,
            None => {
                debug!("XX msg3 responder: handshake completed without remote static key from {from}");
                return IncomingResult::Rejected;
            }
        };
        let transport = match state.into_transport_mode() {
            Ok(t) => t,
            Err(e) => {
                debug!("XX into_transport failed for {from}: {e}");
                return IncomingResult::Rejected;
            }
        };

        if self.sessions.len() >= MAX_SESSIONS {
            self.evict_oldest_session();
        }
        self.sessions.insert(
            from,
            NoiseSession {
                transport,
                remote_noise_pub,
                last_activity: Instant::now(),
            },
        );
        trace!("XX handshake completed (responder) with {from}");

        let decrypted = if payload_len > 0 {
            Some(payload_buf[..payload_len].to_vec())
        } else {
            None
        };

        IncomingResult::HandshakeComplete {
            peer: from,
            remote_noise_pub,
            packets_to_send: vec![],
            decrypted_payload: decrypted,
        }
    }

    // ── Transport (post-handshake encrypted messages) ──

    fn handle_transport(&mut self, from: SocketAddr, data: &[u8]) -> IncomingResult {
        let session = match self.sessions.get_mut(&from) {
            Some(s) => s,
            None => {
                debug!("Ember transport packet from {from} with no session");
                return IncomingResult::Rejected;
            }
        };

        let mut payload_buf = vec![0u8; data.len()];
        match session.transport.read_message(data, &mut payload_buf) {
            Ok(len) => {
                session.last_activity = Instant::now();
                IncomingResult::Message {
                    from,
                    remote_noise_pub: session.remote_noise_pub,
                    payload: payload_buf[..len].to_vec(),
                }
            }
            Err(e) => {
                debug!("Ember transport decrypt failed from {from}: {e}");
                self.sessions.remove(&from);
                IncomingResult::Rejected
            }
        }
    }

    // ── Eviction helpers ──

    fn evict_oldest_session(&mut self) {
        if let Some(oldest) = self
            .sessions
            .iter()
            .min_by_key(|(_, s)| s.last_activity)
            .map(|(k, _)| *k)
        {
            self.sessions.remove(&oldest);
        }
    }

    fn evict_oldest_pending(&mut self) {
        if let Some(oldest) = self
            .pending
            .iter()
            .min_by_key(|(_, p)| match p {
                PendingHandshake::IkInitiator { created, .. } => *created,
                PendingHandshake::XxInitiatorMsg1 { created, .. } => *created,
                PendingHandshake::XxResponderMsg2 { created, .. } => *created,
            })
            .map(|(k, _)| *k)
        {
            self.pending.remove(&oldest);
        }
    }
}

/// Extract the remote peer's static public key from a Noise handshake state.
///
/// Returns `None` if the handshake state doesn't carry a 32-byte static
/// public key. After a *successful* IK/XX handshake this should never
/// happen with the snow patterns we use, but treating it as `None`
/// (and rejecting the session at the caller) is safer than the
/// previous fallback to an all-zero key — that fallback would have
/// silently bound the session to the well-known zero pubkey, letting
/// every "successful but malformed" peer collide on that identity in
/// reputation/friend lookups.
fn extract_remote_static(state: &snow::HandshakeState) -> Option<[u8; 32]> {
    let rs = state.get_remote_static()?;
    if rs.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(rs);
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_keypair() -> ([u8; 32], [u8; 32]) {
        let params: snow::params::NoiseParams = NOISE_PATTERN_XX.parse().unwrap();
        let kp = snow::Builder::new(params).generate_keypair().unwrap();
        let mut priv_key = [0u8; 32];
        let mut pub_key = [0u8; 32];
        priv_key.copy_from_slice(&kp.private);
        pub_key.copy_from_slice(&kp.public);
        (priv_key, pub_key)
    }

    #[test]
    fn is_ember_packet_detects_magic() {
        assert!(EmberTransport::is_ember_packet(&[0xEB, 0x3E, 0x01]));
        assert!(!EmberTransport::is_ember_packet(&[0xEB, 0x3F, 0x01]));
        assert!(!EmberTransport::is_ember_packet(&[0xEB]));
        assert!(!EmberTransport::is_ember_packet(&[]));
    }

    #[test]
    fn ik_handshake_round_trip() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();

        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);

        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        let msg = b"hello from alice";
        let result = alice.prepare_outgoing(bob_addr, Some(&bob_pub), msg);
        let init_packet = match result {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got: {}", variant_name(&other)),
        };

        let result = bob.process_incoming(&init_packet, alice_addr);
        let (resp_packets, decrypted) = match result {
            IncomingResult::HandshakeComplete {
                packets_to_send,
                decrypted_payload,
                ..
            } => (packets_to_send, decrypted_payload),
            _ => panic!("expected HandshakeComplete"),
        };
        assert_eq!(decrypted.as_deref(), Some(msg.as_slice()));
        assert_eq!(resp_packets.len(), 1);

        let result = alice.process_incoming(&resp_packets[0], bob_addr);
        match result {
            IncomingResult::HandshakeComplete {
                packets_to_send, ..
            } => {
                assert!(packets_to_send.is_empty());
            }
            _ => panic!("expected HandshakeComplete"),
        }

        assert!(alice.has_session(&bob_addr));
        assert!(bob.has_session(&alice_addr));

        let msg2 = b"subsequent message";
        let packet = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), msg2) {
            OutgoingResult::Ready { packet } => packet,
            other => panic!("expected Ready, got: {}", variant_name(&other)),
        };
        match bob.process_incoming(&packet, alice_addr) {
            IncomingResult::Message { payload, .. } => {
                assert_eq!(&payload, msg2);
            }
            _ => panic!("expected Message"),
        }
    }

    #[test]
    fn xx_handshake_round_trip() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();

        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);

        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        let msg = b"hello via XX";

        // Alice → Bob: XX msg1
        let init_packet = match alice.prepare_outgoing(bob_addr, None, msg) {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got: {}", variant_name(&other)),
        };

        // Bob receives msg1, sends msg2
        let msg2_packets = match bob.process_incoming(&init_packet, alice_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => packets,
            _ => panic!("expected HandshakeResponse"),
        };
        assert_eq!(msg2_packets.len(), 1);

        // Alice receives msg2, sends msg3 (with queued DHT message as payload)
        let result = alice.process_incoming(&msg2_packets[0], bob_addr);
        let msg3_packets = match result {
            IncomingResult::HandshakeComplete {
                packets_to_send, ..
            } => packets_to_send,
            _ => panic!("expected HandshakeComplete"),
        };
        assert!(!msg3_packets.is_empty());

        // Bob receives msg3 (handshake completes, receives payload)
        let result = bob.process_incoming(&msg3_packets[0], alice_addr);
        match result {
            IncomingResult::HandshakeComplete {
                decrypted_payload, ..
            } => {
                assert_eq!(decrypted_payload.as_deref(), Some(msg.as_slice()));
            }
            _ => panic!("expected HandshakeComplete"),
        }

        assert!(alice.has_session(&bob_addr));
        assert!(bob.has_session(&alice_addr));
    }

    #[test]
    fn control_message_crosses_established_noise_session() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();

        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);

        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        let bootstrap = EmberControlMessage::Ping { nonce: 1 }.encode();
        let init_packet = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), &bootstrap) {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got: {}", variant_name(&other)),
        };

        let resp_packets = match bob.process_incoming(&init_packet, alice_addr) {
            IncomingResult::HandshakeComplete {
                packets_to_send,
                decrypted_payload,
                ..
            } => {
                assert_eq!(
                    decrypted_payload.as_deref().and_then(EmberControlMessage::decode),
                    Some(EmberControlMessage::Ping { nonce: 1 }),
                );
                packets_to_send
            }
            _ => panic!("expected HandshakeComplete"),
        };
        assert_eq!(resp_packets.len(), 1);

        match alice.process_incoming(&resp_packets[0], bob_addr) {
            IncomingResult::HandshakeComplete { .. } => {}
            _ => panic!("expected HandshakeComplete"),
        }

        let pong = EmberControlMessage::Pong { nonce: 1 }.encode();
        let packet = match bob.prepare_outgoing(alice_addr, Some(&alice_pub), &pong) {
            OutgoingResult::Ready { packet } => packet,
            other => panic!("expected Ready, got: {}", variant_name(&other)),
        };

        match alice.process_incoming(&packet, bob_addr) {
            IncomingResult::Message { payload, .. } => {
                assert_eq!(
                    EmberControlMessage::decode(&payload),
                    Some(EmberControlMessage::Pong { nonce: 1 }),
                );
            }
            _ => panic!("expected Message"),
        }
    }

    #[test]
    fn session_cleanup() {
        let (priv_key, pub_key) = make_keypair();
        let mut transport = EmberTransport::new(priv_key, pub_key);
        assert_eq!(transport.session_count(), 0);
        transport.cleanup(); // should not panic on empty
    }

    fn variant_name(r: &OutgoingResult) -> &'static str {
        match r {
            OutgoingResult::Ready { .. } => "Ready",
            OutgoingResult::HandshakeStarted { .. } => "HandshakeStarted",
            OutgoingResult::Queued => "Queued",
            OutgoingResult::Error(_) => "Error",
        }
    }
}
