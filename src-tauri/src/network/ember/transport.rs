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
/// Ask the peer to send its current EPX source/peer payload back over
/// this encrypted session. Body is empty.
const CONTROL_KIND_EXCHANGE_REQUEST: u8 = 3;
/// Carries an EPX payload (variable length); body is the exact wire
/// format produced by `ember::build_exchange_payload*`.
const CONTROL_KIND_EXCHANGE_DATA: u8 = 4;

/// Sessions idle longer than this are evicted.
const SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum concurrent sessions before we start evicting oldest.
const MAX_SESSIONS: usize = 4096;

/// Maximum concurrent pending handshakes.
const MAX_PENDING: usize = 512;

/// How long a processed handshake-initiation packet's digest is remembered
/// for verbatim-replay rejection.
const HANDSHAKE_REPLAY_TTL: Duration = Duration::from_secs(30);

/// Cap on the verbatim-replay digest cache so a flood of distinct
/// initiations can't grow it without bound.
const MAX_REPLAY_DIGESTS: usize = 8192;

/// Size of the anti-replay sliding window (in nonces) for inbound transport
/// packets.
const REPLAY_WINDOW_BITS: u64 = 64;

/// Largest Ember UDP datagram we will parse. Valid Noise handshake and
/// transport packets are far smaller than this; the cap prevents an oversized
/// UDP datagram from driving proportional allocation during handshake parsing.
const MAX_EMBER_DATAGRAM_BYTES: usize = 4096;

/// An established encrypted session with a remote peer.
///
/// Ember runs Noise transport over UDP, which can lose, reorder, and duplicate
/// datagrams. A *stateful* `snow::TransportState` derives the nonce implicitly
/// from a strictly-increasing counter, so a single lost/reordered packet
/// desynchronises the counter and every subsequent packet fails to
/// authenticate. We instead use [`snow::StatelessTransportState`] with an
/// explicit per-packet nonce on the wire plus our own sliding replay window,
/// the same approach WireGuard/IPsec use. This makes the session tolerant of
/// loss and reordering and means a single forged/corrupt datagram is simply
/// dropped rather than tearing the session down.
struct NoiseSession {
    transport: snow::StatelessTransportState,
    remote_noise_pub: [u8; 32],
    last_activity: Instant,
    /// Next nonce to stamp on an outbound transport packet (monotonic).
    send_nonce: u64,
    /// Highest accepted inbound nonce.
    recv_high: u64,
    /// Bitmap of accepted nonces in `[recv_high - 63, recv_high]`; bit `i`
    /// represents `recv_high - i`.
    recv_window: u64,
}

impl NoiseSession {
    fn new(transport: snow::StatelessTransportState, remote_noise_pub: [u8; 32]) -> Self {
        Self {
            transport,
            remote_noise_pub,
            last_activity: Instant::now(),
            send_nonce: 0,
            recv_high: 0,
            recv_window: 0,
        }
    }

    /// Frame + encrypt `message` as a transport packet, advancing the send
    /// nonce. Returns the wire bytes (`magic | type | nonce(8 LE) | ciphertext`)
    /// or `None` on an (unexpected) encrypt error.
    fn seal(&mut self, message: &[u8]) -> Option<Vec<u8>> {
        let nonce = self.send_nonce;
        let mut buf = vec![0u8; HEADER_LEN + 8 + message.len() + 16];
        buf[0] = EMBER_MAGIC[0];
        buf[1] = EMBER_MAGIC[1];
        buf[2] = PKT_TRANSPORT;
        buf[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(&nonce.to_le_bytes());
        match self
            .transport
            .write_message(nonce, message, &mut buf[HEADER_LEN + 8..])
        {
            Ok(len) => {
                self.send_nonce = self.send_nonce.wrapping_add(1);
                buf.truncate(HEADER_LEN + 8 + len);
                Some(buf)
            }
            Err(e) => {
                warn!("Ember transport encrypt error: {e}");
                None
            }
        }
    }

    /// Whether `nonce` is acceptable (not already seen, not older than the
    /// window). Does **not** mutate state — the window is only advanced on a
    /// successful decrypt via [`Self::replay_commit`] so a forged nonce that
    /// fails AEAD verification can't block the genuine packet that bears it.
    fn replay_precheck(&self, nonce: u64) -> bool {
        if nonce > self.recv_high {
            return true;
        }
        let diff = self.recv_high - nonce;
        if diff >= REPLAY_WINDOW_BITS {
            return false;
        }
        (self.recv_window & (1u64 << diff)) == 0
    }

    /// Record `nonce` as accepted, sliding the window forward if needed.
    fn replay_commit(&mut self, nonce: u64) {
        if nonce > self.recv_high {
            let shift = nonce - self.recv_high;
            if shift >= REPLAY_WINDOW_BITS {
                self.recv_window = 0;
            } else {
                self.recv_window <<= shift;
            }
            self.recv_window |= 1;
            self.recv_high = nonce;
        } else {
            let diff = self.recv_high - nonce;
            if diff < REPLAY_WINDOW_BITS {
                self.recv_window |= 1u64 << diff;
            }
        }
    }
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
    /// Application payloads enqueued here while we wait for the initiator's
    /// final handshake message are flushed as transport-mode packets in
    /// `handle_xx_msg3` once the session is established. Without this
    /// queue, calls to `prepare_outgoing` during the brief msg2→msg3
    /// window would silently drop the payload.
    XxResponderMsg2 {
        state: snow::HandshakeState,
        queued: Vec<Vec<u8>>,
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

/// Outcome of [`EmberTransport::dispatch_incoming`]: every side
/// effect needed to handle one inbound Ember-native UDP packet,
/// returned as data so the caller decides when to perform IO and so
/// the dispatch logic can be unit-tested without spinning up a
/// `NetworkState`.
#[derive(Debug, Default)]
pub struct DispatchOutcome {
    /// Raw packets to send back to the source address. May contain
    /// handshake responses, an encoded Pong reply, or both.
    pub responses: Vec<Vec<u8>>,
    /// Decoded control message embedded in the packet. `None` for
    /// pure handshake-progress packets and rejected packets.
    pub control: Option<EmberControlMessage>,
    /// Decrypted application payload that was *not* a 10-byte control
    /// frame — i.e. an Ember DHT message (or a future Ember-native
    /// frame) the caller is expected to route. Control frames are
    /// exactly 10 bytes (`version`+`kind`+`nonce`); every DHT frame is
    /// far larger (its Ed25519 signature alone is 64 bytes), so frame
    /// length disambiguates the two without a dedicated channel byte.
    pub app_payload: Option<Vec<u8>>,
    /// The peer's Noise static public key, present whenever the packet
    /// carried a decrypted payload (control or app) or completed a
    /// handshake. Lets the caller dial the peer back over the
    /// established session and bind the DHT identity to the transport.
    pub remote_noise_pub: Option<[u8; 32]>,
    /// `true` when the transport rejected the packet (bad magic,
    /// unknown handshake state). The caller should drop it.
    pub rejected: bool,
}

/// Ember-native control payload carried inside the Noise transport.
///
/// Wire framing is `version(1) + kind(1) + body(..)`. `Ping`/`Pong`
/// keep their original fixed 10-byte shape (body is the 8-byte LE
/// nonce); the exchange variants carry a variable-length body, so this
/// type is no longer `Copy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmberControlMessage {
    Ping { nonce: u64 },
    Pong { nonce: u64 },
    /// Ask the peer to reply with its current EPX source/peer payload.
    /// No body — the request itself is the whole message.
    ExchangeRequest,
    /// An EPX exchange payload (same wire format as the eD2K TCP EPX
    /// path: `ember::build_exchange_payload*` /
    /// `ember::parse_exchange_payload`). Lets two Ember peers trade
    /// source and peer hints over the encrypted Noise channel.
    ExchangeData { payload: Vec<u8> },
}

impl EmberControlMessage {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            EmberControlMessage::Ping { nonce } => {
                let mut out = Vec::with_capacity(10);
                out.push(CONTROL_VERSION);
                out.push(CONTROL_KIND_PING);
                out.extend_from_slice(&nonce.to_le_bytes());
                out
            }
            EmberControlMessage::Pong { nonce } => {
                let mut out = Vec::with_capacity(10);
                out.push(CONTROL_VERSION);
                out.push(CONTROL_KIND_PONG);
                out.extend_from_slice(&nonce.to_le_bytes());
                out
            }
            EmberControlMessage::ExchangeRequest => {
                vec![CONTROL_VERSION, CONTROL_KIND_EXCHANGE_REQUEST]
            }
            EmberControlMessage::ExchangeData { payload } => {
                let mut out = Vec::with_capacity(2 + payload.len());
                out.push(CONTROL_VERSION);
                out.push(CONTROL_KIND_EXCHANGE_DATA);
                out.extend_from_slice(payload);
                out
            }
        }
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 2 || data[0] != CONTROL_VERSION {
            return None;
        }

        match data[1] {
            CONTROL_KIND_PING | CONTROL_KIND_PONG => {
                // Fixed 10-byte shape: version + kind + 8-byte nonce.
                if data.len() != 10 {
                    return None;
                }
                let mut nonce = [0u8; 8];
                nonce.copy_from_slice(&data[2..10]);
                let nonce = u64::from_le_bytes(nonce);
                if data[1] == CONTROL_KIND_PING {
                    Some(EmberControlMessage::Ping { nonce })
                } else {
                    Some(EmberControlMessage::Pong { nonce })
                }
            }
            CONTROL_KIND_EXCHANGE_REQUEST => {
                // The request carries no body; reject trailing bytes so a
                // malformed/forged frame can't masquerade as a request.
                if data.len() != 2 {
                    return None;
                }
                Some(EmberControlMessage::ExchangeRequest)
            }
            CONTROL_KIND_EXCHANGE_DATA => {
                // Body is the EPX payload (possibly empty). The datagram
                // cap in `dispatch_incoming` and `parse_exchange_payload`'s
                // own length check bound the size; copy the body out here.
                Some(EmberControlMessage::ExchangeData {
                    payload: data[2..].to_vec(),
                })
            }
            _ => None,
        }
    }
}

pub struct EmberTransport {
    local_noise_key: [u8; 32],
    local_noise_pub: [u8; 32],
    sessions: HashMap<SocketAddr, NoiseSession>,
    pending: HashMap<SocketAddr, PendingHandshake>,
    /// BLAKE3 digests of recently-processed handshake-initiation packets
    /// (`IK_INIT`, `XX_MSG1`) with the time we first saw them. An attacker can
    /// only replay handshake bytes verbatim (they lack the keys to forge a
    /// *different* valid handshake), so rejecting exact duplicates closes the
    /// "replayed init re-runs the handshake, re-emits its embedded payload, and
    /// resets the live session" vector. Pruned in [`Self::cleanup`].
    recent_handshakes: HashMap<[u8; 32], Instant>,
}

impl EmberTransport {
    pub fn new(local_noise_key: [u8; 32], local_noise_pub: [u8; 32]) -> Self {
        Self {
            local_noise_key,
            local_noise_pub,
            sessions: HashMap::new(),
            pending: HashMap::new(),
            recent_handshakes: HashMap::new(),
        }
    }

    /// Returns `true` if this exact handshake-initiation packet was processed
    /// recently (a verbatim replay) and records its digest otherwise. See
    /// [`Self::recent_handshakes`] for why a digest cache fully addresses the
    /// replay threat for these packet types.
    fn is_replayed_handshake(&mut self, data: &[u8]) -> bool {
        let digest = *blake3::hash(data).as_bytes();
        let now = Instant::now();
        if let Some(seen) = self.recent_handshakes.get(&digest) {
            if now.duration_since(*seen) < HANDSHAKE_REPLAY_TTL {
                return true;
            }
        }
        if self.recent_handshakes.len() >= MAX_REPLAY_DIGESTS {
            if let Some(oldest) = self
                .recent_handshakes
                .iter()
                .min_by_key(|(_, t)| **t)
                .map(|(k, _)| *k)
            {
                self.recent_handshakes.remove(&oldest);
            }
        }
        self.recent_handshakes.insert(digest, now);
        false
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
        if self.sessions.contains_key(&peer) {
            let sealed = {
                let session = self
                    .sessions
                    .get_mut(&peer)
                    .expect("checked contains_key above");
                session.last_activity = Instant::now();
                session.seal(message)
            };
            return match sealed {
                Some(packet) => OutgoingResult::Ready { packet },
                None => {
                    self.sessions.remove(&peer);
                    OutgoingResult::Error("encrypt failed".to_string())
                }
            };
        }

        // Queue behind in-progress handshake
        if let Some(pending) = self.pending.get_mut(&peer) {
            match pending {
                PendingHandshake::IkInitiator { queued, .. }
                | PendingHandshake::XxInitiatorMsg1 { queued, .. }
                | PendingHandshake::XxResponderMsg2 { queued, .. } => {
                    // Bound per-peer queue: if the handshake stalls (the
                    // peer never completes it), drop the oldest queued
                    // payload instead of growing without limit. These are
                    // best-effort outgoing app messages, so shedding the
                    // stalest one is acceptable back-pressure.
                    const MAX_QUEUED_PER_HANDSHAKE: usize = 64;
                    if queued.len() >= MAX_QUEUED_PER_HANDSHAKE {
                        queued.remove(0);
                    }
                    queued.push(message.to_vec());
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
        self.recent_handshakes
            .retain(|_, t| now.duration_since(*t) < HANDSHAKE_REPLAY_TTL);
    }

    /// Remove an existing session for a peer (e.g., on disconnect).
    pub fn remove_session(&mut self, addr: &SocketAddr) {
        self.sessions.remove(addr);
        self.pending.remove(addr);
    }

    /// Drop every session and pending handshake. Used when the
    /// `ember_native_enabled` feature flag flips off so a session
    /// established during an "on" period cannot decrypt later traffic
    /// when the user re-enables it (different harness session,
    /// different intent, possibly different peer trust).
    pub fn cleanup_all(&mut self) {
        self.sessions.clear();
        self.pending.clear();
        self.recent_handshakes.clear();
    }

    /// Drive the Noise state machine for an inbound UDP packet and
    /// produce every side effect as data: response packets to send
    /// back, plus the decoded control message if the packet carried
    /// a payload.
    ///
    /// When the decoded payload is a `Ping`, the matching `Pong` is
    /// encoded on the same session and appended to `responses`, so
    /// the caller only has to drain the response list and update its
    /// counters / pending-ping registry. Pure handshake-progress
    /// packets (no embedded payload) yield `control: None`. Garbled
    /// or malformed packets yield `rejected: true` and an empty
    /// `responses` vector.
    ///
    /// Pulled out of the network task's `handle_ember_native_udp` so
    /// the same code path can be exercised by `cargo test` over real
    /// loopback UDP without constructing a full `NetworkState`.
    pub fn dispatch_incoming(&mut self, data: &[u8], from: SocketAddr) -> DispatchOutcome {
        let mut outcome = DispatchOutcome::default();
        if data.len() > MAX_EMBER_DATAGRAM_BYTES {
            debug!(
                "dropping oversized Ember UDP datagram from {from}: {} bytes",
                data.len()
            );
            outcome.rejected = true;
            return outcome;
        }
        let result = self.process_incoming(data, from);

        let payload = match result {
            IncomingResult::Message {
                payload,
                remote_noise_pub,
                ..
            } => {
                outcome.remote_noise_pub = Some(remote_noise_pub);
                Some(payload)
            }
            IncomingResult::HandshakeResponse { packets, .. } => {
                outcome.responses = packets;
                None
            }
            IncomingResult::HandshakeComplete {
                packets_to_send,
                decrypted_payload,
                remote_noise_pub,
                ..
            } => {
                outcome.responses = packets_to_send;
                outcome.remote_noise_pub = Some(remote_noise_pub);
                decrypted_payload
            }
            IncomingResult::Rejected => {
                outcome.rejected = true;
                return outcome;
            }
        };

        let Some(payload) = payload else {
            return outcome;
        };

        let Some(message) = EmberControlMessage::decode(&payload) else {
            // Not a 10-byte control frame — hand the raw decrypted
            // bytes back as an application payload (DHT message, future
            // Ember-native frame). The caller routes it; the handshake
            // responses (if any) still ride along in `responses`.
            outcome.app_payload = Some(payload);
            return outcome;
        };

        // Auto-answer `Ping` here: it needs no application state, and
        // the session is established by definition (we just decrypted a
        // payload from it), so `prepare_outgoing` should hit the fast
        // Ready path. `Pong` / `ExchangeRequest` / `ExchangeData` are
        // surfaced to the caller, which owns the EPX payload and the
        // source/transfer managers required to act on them.
        if let EmberControlMessage::Ping { nonce } = &message {
            let pong = EmberControlMessage::Pong { nonce: *nonce }.encode();
            if let OutgoingResult::Ready { packet } = self.prepare_outgoing(from, None, &pong) {
                outcome.responses.push(packet);
            }
        }

        outcome.control = Some(message);
        outcome
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
        // Reject verbatim replays before doing any crypto or, crucially, before
        // re-emitting the embedded payload or replacing a live session.
        if self.is_replayed_handshake(data) {
            debug!("Dropping replayed IK_INIT from {from}");
            return IncomingResult::Rejected;
        }
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

        // Don't let a NEW handshake from the same socket address silently
        // replace a live session that belongs to a DIFFERENT Noise identity.
        // A legitimate peer always re-handshakes with the same static key, so
        // matching-key re-handshakes are still allowed (session refresh); only
        // a mismatched static key (potential takeover via a shared NAT mapping
        // or on-path attacker) is rejected.
        if let Some(existing) = self.sessions.get(&from) {
            if existing.remote_noise_pub != remote_noise_pub {
                debug!(
                    "IK init from {from} carries a different static key than the live session; \
                     rejecting to prevent session takeover"
                );
                return IncomingResult::Rejected;
            }
        }

        let transport = match responder.into_stateless_transport_mode() {
            Ok(t) => t,
            Err(e) => {
                debug!("IK into_transport failed for {from}: {e}");
                return IncomingResult::Rejected;
            }
        };

        if self.sessions.len() >= MAX_SESSIONS {
            self.evict_oldest_session();
        }
        self.sessions
            .insert(from, NoiseSession::new(transport, remote_noise_pub));
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

        // Mirror the responder guard: never let a completing handshake replace a
        // live session that belongs to a DIFFERENT Noise identity at the same
        // address (session-takeover defense). Same-key completion is a refresh
        // and allowed.
        if let Some(existing) = self.sessions.get(&from) {
            if existing.remote_noise_pub != remote_noise_pub {
                debug!(
                    "IK resp from {from} would replace a live session with a different static key; \
                     rejecting to prevent session takeover"
                );
                return IncomingResult::Rejected;
            }
        }

        let transport = match state.into_stateless_transport_mode() {
            Ok(t) => t,
            Err(e) => {
                debug!("IK into_transport failed for {from}: {e}");
                return IncomingResult::Rejected;
            }
        };
        let mut session = NoiseSession::new(transport, remote_noise_pub);

        // Send queued messages
        let mut packets = Vec::new();
        for msg in &queued {
            if let Some(pkt) = session.seal(msg) {
                packets.push(pkt);
            }
        }

        if self.sessions.len() >= MAX_SESSIONS {
            self.evict_oldest_session();
        }
        self.sessions.insert(from, session);
        trace!("IK handshake completed (initiator) with {from}");

        IncomingResult::HandshakeComplete {
            peer: from,
            remote_noise_pub,
            packets_to_send: packets,
            decrypted_payload: None,
        }
    }

    // ── Noise_XX handshake (2-RTT, we don't know the peer's static key) ──

    fn start_xx_handshake(&mut self, peer: SocketAddr, first_message: &[u8]) -> OutgoingResult {
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
        // Don't let an inbound XX msg1 clobber a handshake *we* initiated to the
        // same address: an attacker spoofing the peer's source address could
        // otherwise strand our in-flight connect attempts. A peer legitimately
        // retransmitting msg1 (after a lost msg2) only ever has a responder-side
        // pending here, which we still refresh below.
        if matches!(
            self.pending.get(&from),
            Some(PendingHandshake::IkInitiator { .. } | PendingHandshake::XxInitiatorMsg1 { .. })
        ) {
            debug!("Ignoring XX msg1 from {from}: an initiator handshake is in flight");
            return IncomingResult::Rejected;
        }
        // Reject verbatim replays (prevents repeated msg2 reflection from a
        // single captured msg1).
        if self.is_replayed_handshake(data) {
            debug!("Dropping replayed XX msg1 from {from}");
            return IncomingResult::Rejected;
        }
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
                queued: Vec::new(),
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
            Some(PendingHandshake::XxInitiatorMsg1 { state, queued, .. }) => (state, queued),
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

        // Mirror the responder guard: a completing handshake must not replace a
        // live session belonging to a DIFFERENT Noise identity at the same
        // address (session-takeover defense).
        if let Some(existing) = self.sessions.get(&from) {
            if existing.remote_noise_pub != remote_noise_pub {
                debug!(
                    "XX msg2 from {from} would replace a live session with a different static key; \
                     rejecting to prevent session takeover"
                );
                return IncomingResult::Rejected;
            }
        }

        let transport = match state.into_stateless_transport_mode() {
            Ok(t) => t,
            Err(e) => {
                debug!("XX into_transport failed for {from}: {e}");
                return IncomingResult::Rejected;
            }
        };
        let mut session = NoiseSession::new(transport, remote_noise_pub);

        // Send remaining queued messages (skip first, it was in msg3 payload)
        let mut packets = vec![resp_buf];
        for msg in queued.iter().skip(1) {
            if let Some(pkt) = session.seal(msg) {
                packets.push(pkt);
            }
        }

        if self.sessions.len() >= MAX_SESSIONS {
            self.evict_oldest_session();
        }
        self.sessions.insert(from, session);
        trace!("XX handshake completed (initiator) with {from}");

        IncomingResult::HandshakeComplete {
            peer: from,
            remote_noise_pub,
            packets_to_send: packets,
            decrypted_payload: None,
        }
    }

    fn handle_xx_msg3(&mut self, from: SocketAddr, data: &[u8]) -> IncomingResult {
        let (mut state, queued) = match self.pending.remove(&from) {
            Some(PendingHandshake::XxResponderMsg2 { state, queued, .. }) => (state, queued),
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
                debug!(
                    "XX msg3 responder: handshake completed without remote static key from {from}"
                );
                return IncomingResult::Rejected;
            }
        };

        // Mirror the IK responder guard: a completed XX handshake from the same
        // socket address must not silently replace a live session belonging to
        // a DIFFERENT Noise identity. A legitimate peer re-handshakes with its
        // own static key (allowed — session refresh); a mismatched key is a
        // potential takeover via a shared NAT mapping or on-path attacker.
        if let Some(existing) = self.sessions.get(&from) {
            if existing.remote_noise_pub != remote_noise_pub {
                debug!(
                    "XX msg3 from {from} carries a different static key than the live session; \
                     rejecting to prevent session takeover"
                );
                return IncomingResult::Rejected;
            }
        }

        let transport = match state.into_stateless_transport_mode() {
            Ok(t) => t,
            Err(e) => {
                debug!("XX into_transport failed for {from}: {e}");
                return IncomingResult::Rejected;
            }
        };
        let mut session = NoiseSession::new(transport, remote_noise_pub);

        // Drain any application payloads that the local app tried to
        // send while we were still in the msg2→msg3 window. Each one
        // becomes a transport-mode packet that the caller will emit on
        // the wire; without this loop those payloads were silently
        // dropped by `prepare_outgoing`'s queue case.
        let mut packets_to_send: Vec<Vec<u8>> = Vec::with_capacity(queued.len());
        for msg in &queued {
            if let Some(pkt) = session.seal(msg) {
                packets_to_send.push(pkt);
            } else {
                warn!("XX msg3: failed to encrypt queued message for {from}");
            }
        }

        if self.sessions.len() >= MAX_SESSIONS {
            self.evict_oldest_session();
        }
        self.sessions.insert(from, session);
        trace!(
            "XX handshake completed (responder) with {from}; flushed {} queued message(s)",
            queued.len()
        );

        let decrypted = if payload_len > 0 {
            Some(payload_buf[..payload_len].to_vec())
        } else {
            None
        };

        IncomingResult::HandshakeComplete {
            peer: from,
            remote_noise_pub,
            packets_to_send,
            decrypted_payload: decrypted,
        }
    }

    // ── Transport (post-handshake encrypted messages) ──

    fn handle_transport(&mut self, from: SocketAddr, data: &[u8]) -> IncomingResult {
        // Wire layout: nonce(8 LE) || ciphertext.
        if data.len() < 8 {
            debug!("Ember transport packet from {from} too short for nonce");
            return IncomingResult::Rejected;
        }
        let nonce = u64::from_le_bytes(data[..8].try_into().expect("8 bytes"));
        let ciphertext = &data[8..];

        let session = match self.sessions.get_mut(&from) {
            Some(s) => s,
            None => {
                debug!("Ember transport packet from {from} with no session");
                return IncomingResult::Rejected;
            }
        };

        // Reject stale/duplicate nonces before spending a decrypt on them.
        if !session.replay_precheck(nonce) {
            trace!("Ember transport replayed/stale nonce {nonce} from {from}");
            return IncomingResult::Rejected;
        }

        let mut payload_buf = vec![0u8; ciphertext.len()];
        match session
            .transport
            .read_message(nonce, ciphertext, &mut payload_buf)
        {
            Ok(len) => {
                // Commit the nonce to the replay window only now that AEAD has
                // authenticated it.
                session.replay_commit(nonce);
                session.last_activity = Instant::now();
                IncomingResult::Message {
                    from,
                    remote_noise_pub: session.remote_noise_pub,
                    payload: payload_buf[..len].to_vec(),
                }
            }
            Err(e) => {
                // Crucially, do NOT tear the session down: over UDP a single
                // spoofed, corrupt, or stray datagram would otherwise kill a
                // perfectly healthy session. Drop just this packet.
                debug!("Ember transport decrypt failed from {from} (nonce {nonce}): {e}");
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

    /// Establish a live IK session between two transports and return them
    /// with each side's view of the peer address.
    fn established_pair() -> (EmberTransport, EmberTransport, SocketAddr, SocketAddr) {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        let init = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), b"hi") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            _ => panic!("expected HandshakeStarted"),
        };
        let resp = match bob.process_incoming(&init, alice_addr) {
            IncomingResult::HandshakeComplete {
                packets_to_send, ..
            } => packets_to_send,
            _ => panic!("expected HandshakeComplete (responder)"),
        };
        match alice.process_incoming(&resp[0], bob_addr) {
            IncomingResult::HandshakeComplete { .. } => {}
            _ => panic!("expected HandshakeComplete (initiator)"),
        }
        (alice, bob, alice_addr, bob_addr)
    }

    fn seal_ready(t: &mut EmberTransport, peer: SocketAddr, msg: &[u8]) -> Vec<u8> {
        match t.prepare_outgoing(peer, None, msg) {
            OutgoingResult::Ready { packet } => packet,
            _ => panic!("expected Ready on established session"),
        }
    }

    #[test]
    fn transport_tolerates_reorder_and_rejects_replay() {
        let (mut alice, mut bob, alice_addr, bob_addr) = established_pair();
        let p1 = seal_ready(&mut alice, bob_addr, b"one");
        let p2 = seal_ready(&mut alice, bob_addr, b"two");
        let p3 = seal_ready(&mut alice, bob_addr, b"three");

        // Deliver out of order: p3, p1, p2 — the sliding window accepts all.
        for (pkt, expect) in [(&p3, &b"three"[..]), (&p1, &b"one"[..]), (&p2, &b"two"[..])] {
            match bob.process_incoming(pkt, alice_addr) {
                IncomingResult::Message { payload, .. } => assert_eq!(payload, expect),
                _ => panic!("expected Message for reordered packet"),
            }
        }

        // A verbatim replay of an already-accepted packet is rejected…
        assert!(matches!(
            bob.process_incoming(&p1, alice_addr),
            IncomingResult::Rejected
        ));
        // …yet the session stays healthy and a fresh packet still decrypts.
        let p4 = seal_ready(&mut alice, bob_addr, b"four");
        assert!(matches!(
            bob.process_incoming(&p4, alice_addr),
            IncomingResult::Message { .. }
        ));
    }

    #[test]
    fn forged_transport_packet_does_not_tear_down_session() {
        let (mut alice, mut bob, alice_addr, bob_addr) = established_pair();
        let good = seal_ready(&mut alice, bob_addr, b"legit");

        // Corrupt the AEAD tag of a copy and deliver it first.
        let mut forged = good.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0xFF;
        assert!(matches!(
            bob.process_incoming(&forged, alice_addr),
            IncomingResult::Rejected
        ));
        assert!(
            bob.has_session(&alice_addr),
            "a single forged/corrupt datagram must not tear down the session"
        );

        // The genuine packet (same nonce, untampered) still decrypts because the
        // forged one never committed its nonce to the replay window.
        match bob.process_incoming(&good, alice_addr) {
            IncomingResult::Message { payload, .. } => assert_eq!(payload, b"legit"),
            _ => panic!("expected Message after a forged packet was dropped"),
        }
    }

    #[test]
    fn replayed_ik_init_is_dropped() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        let init = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), b"req") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            _ => panic!("expected HandshakeStarted"),
        };
        // First copy completes the handshake and surfaces the embedded payload.
        match bob.process_incoming(&init, alice_addr) {
            IncomingResult::HandshakeComplete {
                decrypted_payload, ..
            } => assert_eq!(decrypted_payload.as_deref(), Some(&b"req"[..])),
            _ => panic!("expected HandshakeComplete"),
        }
        // A verbatim replay must be dropped — it must NOT re-emit the payload or
        // reset the freshly-established session.
        assert!(matches!(
            bob.process_incoming(&init, alice_addr),
            IncomingResult::Rejected
        ));
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
                    decrypted_payload
                        .as_deref()
                        .and_then(EmberControlMessage::decode),
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

    /// A decrypted payload that is *not* a 10-byte control frame (e.g. a
    /// signed DHT message) must surface via `app_payload` with the
    /// peer's Noise key attached, so the caller can route it and reply
    /// over the established session. The control path stays `None`.
    #[test]
    fn dispatch_surfaces_non_control_payload_as_app_payload() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        // DHT frames are always larger than the 10-byte control frame
        // (the Ed25519 signature alone is 64 bytes); 90 bytes stands in
        // for one here.
        let dht_like = vec![0x01u8; 90];

        let init = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), &dht_like) {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };

        let outcome = bob.dispatch_incoming(&init, alice_addr);
        assert!(!outcome.rejected);
        assert_eq!(outcome.control, None, "payload is not a control frame");
        assert_eq!(outcome.app_payload.as_deref(), Some(dht_like.as_slice()));
        assert_eq!(
            outcome.remote_noise_pub,
            Some(alice_pub),
            "app payload must carry the peer's Noise key for the reply path"
        );
        // The IK responder still emits message 2.
        assert_eq!(outcome.responses.len(), 1);
    }

    #[test]
    fn control_message_encode_decode_round_trip_all_variants() {
        let cases = [
            EmberControlMessage::Ping {
                nonce: 0x0102_0304_0506_0708,
            },
            EmberControlMessage::Pong { nonce: 0 },
            EmberControlMessage::ExchangeRequest,
            EmberControlMessage::ExchangeData {
                payload: vec![1, 2, 3, 4, 5],
            },
            // Empty exchange payload must still round-trip (a peer with
            // nothing to share replies with an empty EPX body).
            EmberControlMessage::ExchangeData { payload: vec![] },
        ];
        for msg in cases {
            let encoded = msg.encode();
            assert_eq!(
                EmberControlMessage::decode(&encoded),
                Some(msg.clone()),
                "round trip failed for {msg:?}",
            );
        }

        // Ping/Pong keep their original fixed 10-byte wire shape.
        assert_eq!(EmberControlMessage::Ping { nonce: 7 }.encode().len(), 10);
        assert_eq!(EmberControlMessage::Pong { nonce: 7 }.encode().len(), 10);
        // A request is exactly version + kind.
        assert_eq!(EmberControlMessage::ExchangeRequest.encode(), vec![1, 3]);
    }

    #[test]
    fn control_message_decode_rejects_malformed() {
        // Wrong version.
        assert_eq!(EmberControlMessage::decode(&[0, 1, 0, 0, 0, 0, 0, 0, 0, 0]), None);
        // Ping/Pong with wrong length.
        assert_eq!(EmberControlMessage::decode(&[1, 1, 0, 0]), None);
        // ExchangeRequest must have no trailing bytes.
        assert_eq!(EmberControlMessage::decode(&[1, 3, 0xFF]), None);
        // Unknown kind.
        assert_eq!(EmberControlMessage::decode(&[1, 0x7F]), None);
        // Too short to carry version + kind.
        assert_eq!(EmberControlMessage::decode(&[1]), None);
    }

    /// `ExchangeRequest` and `ExchangeData` cross an established Noise
    /// session intact, and `dispatch_incoming` surfaces them as
    /// `control` (without auto-answering — the caller owns the EPX
    /// payload needed to respond).
    #[test]
    fn exchange_messages_cross_established_session() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();

        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);

        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        // Alice opens the session by sending an ExchangeRequest in the
        // IK handshake's first message.
        let req = EmberControlMessage::ExchangeRequest.encode();
        let init = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), &req) {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };

        // Bob decodes the request; dispatch must NOT auto-respond.
        let bob_outcome = bob.dispatch_incoming(&init, alice_addr);
        assert!(!bob_outcome.rejected);
        assert_eq!(
            bob_outcome.control,
            Some(EmberControlMessage::ExchangeRequest)
        );
        assert_eq!(
            bob_outcome.responses.len(),
            1,
            "only the IK handshake response, no auto-answer to the exchange request"
        );

        // Alice completes the handshake.
        for pkt in &bob_outcome.responses {
            let _ = alice.dispatch_incoming(pkt, bob_addr);
        }
        assert!(alice.has_session(&bob_addr));
        assert!(bob.has_session(&alice_addr));

        // Bob answers with an ExchangeData payload over the session.
        let payload = vec![4u8, 0, 0, 0, 0]; // a tiny v4 EPX-shaped body
        let data = EmberControlMessage::ExchangeData {
            payload: payload.clone(),
        }
        .encode();
        let pkt = match bob.prepare_outgoing(alice_addr, None, &data) {
            OutgoingResult::Ready { packet } => packet,
            other => panic!("expected Ready, got {}", variant_name(&other)),
        };
        let alice_outcome = alice.dispatch_incoming(&pkt, bob_addr);
        assert_eq!(
            alice_outcome.control,
            Some(EmberControlMessage::ExchangeData { payload })
        );
    }

    /// Regression: Bob (XX responder) calls `prepare_outgoing` while
    /// still in `XxResponderMsg2` (waiting for Alice's msg3). The
    /// payload must be queued and flushed as a transport packet once
    /// the handshake completes — not silently dropped (the previous
    /// behavior, which made dev-panel pings hang during this race).
    #[test]
    fn xx_responder_flushes_payload_queued_during_msg2_window() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();

        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);

        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        // Alice → Bob: XX msg1 (no remote pubkey known yet)
        let init_packet = match alice.prepare_outgoing(bob_addr, None, b"first msg from alice") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };

        // Bob receives msg1 → emits msg2, parks state in XxResponderMsg2.
        let msg2_packets = match bob.process_incoming(&init_packet, alice_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => packets,
            other => panic!(
                "expected HandshakeResponse after Bob sees msg1, got {:?}",
                std::mem::discriminant(&other)
            ),
        };
        assert_eq!(msg2_packets.len(), 1);

        // Bob immediately tries to send a control message back to Alice
        // (e.g. unsolicited ping). With the bug, this returned Queued
        // and dropped the payload. Now it must Queue it for flush.
        let bob_msg = b"queued by bob during msg2 window";
        match bob.prepare_outgoing(alice_addr, Some(&alice_pub), bob_msg) {
            OutgoingResult::Queued => {}
            other => panic!(
                "expected Queued during XxResponderMsg2 window, got {}",
                variant_name(&other)
            ),
        }

        // Alice receives msg2 → emits msg3 (and her own queued payload).
        let msg3_packets = match alice.process_incoming(&msg2_packets[0], bob_addr) {
            IncomingResult::HandshakeComplete {
                packets_to_send, ..
            } => packets_to_send,
            _ => panic!("expected HandshakeComplete on alice after msg2"),
        };
        assert!(!msg3_packets.is_empty());

        // Bob receives msg3 → handshake completes AND must flush the
        // previously-queued application payload as a transport packet.
        let bob_emitted = match bob.process_incoming(&msg3_packets[0], alice_addr) {
            IncomingResult::HandshakeComplete {
                packets_to_send, ..
            } => packets_to_send,
            _ => panic!("expected HandshakeComplete on bob after msg3"),
        };
        assert_eq!(
            bob_emitted.len(),
            1,
            "responder must emit exactly the one queued message it deferred"
        );

        // Alice decrypts the flushed packet and recovers Bob's payload.
        match alice.process_incoming(&bob_emitted[0], bob_addr) {
            IncomingResult::Message { payload, .. } => {
                assert_eq!(payload, bob_msg.to_vec());
            }
            other => panic!(
                "expected decrypted Message, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn session_cleanup() {
        let (priv_key, pub_key) = make_keypair();
        let mut transport = EmberTransport::new(priv_key, pub_key);
        assert_eq!(transport.session_count(), 0);
        transport.cleanup(); // should not panic on empty
    }

    #[test]
    fn cleanup_all_drops_active_sessions() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();

        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);

        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        // Establish a session via Noise IK so cleanup_all has something
        // to drop.
        let init = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), b"hello") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        let resp = match bob.process_incoming(&init, alice_addr) {
            IncomingResult::HandshakeComplete {
                packets_to_send, ..
            } => packets_to_send,
            _ => panic!("expected HandshakeComplete on responder side"),
        };
        assert_eq!(resp.len(), 1);
        match alice.process_incoming(&resp[0], bob_addr) {
            IncomingResult::HandshakeComplete { .. } => {}
            _ => panic!("expected HandshakeComplete on initiator side"),
        }

        assert!(alice.has_session(&bob_addr));
        assert!(bob.has_session(&alice_addr));
        assert_eq!(alice.session_count(), 1);

        alice.cleanup_all();
        bob.cleanup_all();

        assert_eq!(alice.session_count(), 0);
        assert_eq!(bob.session_count(), 0);
        assert!(!alice.has_session(&bob_addr));
        assert!(!bob.has_session(&alice_addr));
    }

    /// End-to-end integration test that drives the same code path
    /// `handle_ember_native_udp` uses, but over **real loopback UDP
    /// sockets**: two `EmberTransport`s, two `tokio::net::UdpSocket`s
    /// on `127.0.0.1`, and `dispatch_incoming` on each side.
    ///
    /// This is the verification that used to require the GUI harness
    /// (build a release `ember.exe`, launch two windows, copy pubkeys,
    /// invoke `ember_ping_peer` from devtools). It now runs in
    /// `cargo test` in well under a second and asserts:
    ///
    /// 1. The Noise IK handshake succeeds with the Ping payload
    ///    embedded in message 1.
    /// 2. The responder's `dispatch_incoming` extracts the Ping AND
    ///    encodes the matching Pong on the freshly-established
    ///    session.
    /// 3. The initiator's `dispatch_incoming` decodes the Pong on
    ///    arrival, with no further responses to send.
    ///
    /// Together those steps cover what `handle_ember_native_udp`
    /// would observe in production, minus the IO and the diagnostics
    /// counters (which are owned by `NetworkState`).
    #[tokio::test]
    async fn ember_native_round_trip_over_real_loopback_udp() {
        use tokio::net::UdpSocket;

        let (a_priv, a_pub) = make_keypair();
        let (b_priv, b_pub) = make_keypair();

        let mut transport_a = EmberTransport::new(a_priv, a_pub);
        let mut transport_b = EmberTransport::new(b_priv, b_pub);

        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        // ── Step 1: A initiates Ping → B over Noise IK ──
        let nonce: u64 = 0xDEAD_BEEF_CAFE_F00D;
        let ping = EmberControlMessage::Ping { nonce }.encode();

        let init_packet = match transport_a.prepare_outgoing(addr_b, Some(&b_pub), &ping) {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        sock_a.send_to(&init_packet, addr_b).await.unwrap();

        // ── Step 2: B receives, dispatch_incoming should yield ──
        //   - Ping as the decoded control
        //   - Two responses: Noise IK msg 2 + the encoded Pong reply
        let mut buf = vec![0u8; 65535];
        let (len, from) = sock_b.recv_from(&mut buf).await.unwrap();
        assert_eq!(from, addr_a);

        let outcome_b = transport_b.dispatch_incoming(&buf[..len], from);
        assert!(!outcome_b.rejected, "B rejected the init packet");
        assert_eq!(
            outcome_b.control,
            Some(EmberControlMessage::Ping { nonce }),
            "B should decode the Ping payload",
        );
        assert_eq!(
            outcome_b.responses.len(),
            2,
            "B should send back IK msg 2 + the Pong reply, got {} packet(s)",
            outcome_b.responses.len()
        );

        for pkt in &outcome_b.responses {
            sock_b.send_to(pkt, from).await.unwrap();
        }

        // ── Step 3: A receives Noise IK msg 2 (handshake completes,
        //           no payload, no further responses). ──
        let (len, _) = sock_a.recv_from(&mut buf).await.unwrap();
        let outcome_a_handshake = transport_a.dispatch_incoming(&buf[..len], addr_b);
        assert!(!outcome_a_handshake.rejected);
        assert_eq!(outcome_a_handshake.control, None);
        assert!(
            outcome_a_handshake.responses.is_empty(),
            "A should not send anything in response to msg 2"
        );

        // ── Step 4: A receives the Pong on the now-established session. ──
        let (len, _) = sock_a.recv_from(&mut buf).await.unwrap();
        let outcome_a_pong = transport_a.dispatch_incoming(&buf[..len], addr_b);
        assert!(!outcome_a_pong.rejected);
        assert_eq!(
            outcome_a_pong.control,
            Some(EmberControlMessage::Pong { nonce }),
            "A should decode the matching Pong"
        );
        assert!(
            outcome_a_pong.responses.is_empty(),
            "A should not send anything in response to a Pong"
        );

        // Both ends should now report exactly one established session.
        assert_eq!(transport_a.session_count(), 1);
        assert_eq!(transport_b.session_count(), 1);
    }

    #[test]
    fn ember_magic_is_distinct_from_kad_and_emule_headers() {
        // Sanity-check the dispatch decision in `handle_udp_packet`: KAD
        // packets begin with `OP_EDONKEYHEADER = 0xE3` or
        // `OP_EMULEPROT = 0xC5`, never `0xEB`. Without this property,
        // gating on the magic prefix could divert a real KAD packet
        // into the Noise transport.
        const OP_EDONKEYHEADER: u8 = 0xE3;
        const OP_EMULEPROT: u8 = 0xC5;
        assert_ne!(EMBER_MAGIC[0], OP_EDONKEYHEADER);
        assert_ne!(EMBER_MAGIC[0], OP_EMULEPROT);

        // And the magic-detector itself rejects KAD-style packets.
        assert!(!EmberTransport::is_ember_packet(&[
            OP_EDONKEYHEADER,
            0x00,
            0x00
        ]));
        assert!(!EmberTransport::is_ember_packet(&[
            OP_EMULEPROT,
            0x00,
            0x00
        ]));
        // Ember packets need at least header_len bytes too.
        assert!(!EmberTransport::is_ember_packet(&[EMBER_MAGIC[0]]));
        assert!(!EmberTransport::is_ember_packet(&[]));
        // Real Ember-shaped prefix is detected.
        assert!(EmberTransport::is_ember_packet(&[
            EMBER_MAGIC[0],
            EMBER_MAGIC[1],
            0x10,
        ]));
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
