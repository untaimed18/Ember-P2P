use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::RngCore;
use tracing::{debug, trace, warn};

/// Magic bytes that distinguish Ember-encrypted UDP from KAD/ED2K traffic.
pub const EMBER_MAGIC: [u8; 2] = [0xEB, 0x3E];

const PKT_IK_INIT: u8 = 0x01;
const PKT_IK_RESP: u8 = 0x02;
const PKT_XX_MSG1: u8 = 0x03;
const PKT_XX_MSG2: u8 = 0x04;
const PKT_XX_MSG3: u8 = 0x05;
/// Stateless retry cookie handed back to an XX initiator whose source address
/// is not yet proven return-routable. Only sent once the unvalidated-msg2
/// budget is spent, so a peer that does not know this packet type still
/// completes first contact whenever we are not under a flood. See
/// [`EmberTransport::handle_xx_msg1`].
const PKT_XX_COOKIE: u8 = 0x06;
const PKT_TRANSPORT: u8 = 0x10;

const NOISE_PATTERN_IK: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const NOISE_PATTERN_XX: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Overhead per packet: 2 (magic) + 1 (type) = 3 bytes header
const HEADER_LEN: usize = 3;

/// Version byte for small Ember-native control payloads carried inside Noise.
///
/// Control frames and DHT frames share one decrypted byte stream, and a
/// payload is offered to the control decoder first, so the two leading bytes
/// form a single namespace. This value must therefore never collide with
/// [`EMBER_DHT_VERSION`](super::dht::EMBER_DHT_VERSION), which counts up from
/// 1: a control version of 1 made `CONTROL_KIND_EXCHANGE_DATA` (4) alias
/// `MSG_FOUND_NODE` (4), and since the exchange body has no fixed length every
/// FOUND_NODE was decoded as an EPX payload and never reached the DHT, which
/// silently stalled every iterative lookup after its first hop. 0xC1 sits far
/// outside the range a DHT version will plausibly reach.
/// `control_frames_never_alias_dht_frames` pins this.
const CONTROL_VERSION: u8 = 0xC1;
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

/// Caps on sessions displaced by another claimant at the same address and kept
/// until their own frame proves them. See
/// [`EmberTransport::trim_shadow_sessions`] for why the per-address bound is the
/// one that carries the security property and the global one is only a memory
/// backstop.
const MAX_SHADOW_SESSIONS_PER_ADDR: usize = 3;
const MAX_SHADOW_SESSIONS: usize = 1024;

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

/// Cap on payloads held back from IK initiations whose source address is not
/// yet proven return-routable, and how long one is held. See
/// [`EmberTransport::handle_ik_init`]. Bounded like every other cache here so a
/// flood of spoofed initiations cannot grow it.
///
/// Sized to match `MAX_SESSIONS` so the deferral is not the weaker link: at 256
/// it took only ~1,300 spoofed initiations per second to evict an honest peer's
/// entry before its handshake completed, an order of magnitude cheaper than
/// evicting the session the payload rides on.
///
/// An evicted entry is not always recoverable, which an earlier version of this
/// comment claimed: a DHT search retries (`MAX_QUERY_ATTEMPTS`), but a one-shot
/// `STORE_RECORD` or `ExchangeRequest` sent as a first message has no retry
/// layer and is simply lost — see the note in `dispatch_incoming`.
///
/// Bounded per address as well as globally, on the rule
/// [`EmberTransport::trim_deferred_ik`] explains: without it a spoofer churning
/// static keys at one address could push a genuine peer's request out.
const MAX_DEFERRED_IK_PAYLOADS_PER_ADDR: usize = 3;
const MAX_DEFERRED_IK_PAYLOADS: usize = 4096;
const DEFERRED_IK_PAYLOAD_TTL: Duration = Duration::from_secs(30);

/// Bytes of a Noise XX message 1 that precede its payload: the 32-byte
/// ephemeral public key. `-> e` establishes no key, so snow appends the
/// payload in the clear — which is what lets us read the retry cookie off
/// the wire before spending a Diffie-Hellman on the packet.
const XX_MSG1_EPHEMERAL_LEN: usize = 32;

/// Length of the XX retry cookie on the wire: the leading 16 bytes of a
/// keyed BLAKE3 tag. Forging one is a 2^-128 guess, and the whole reply
/// (3-byte header plus tag) is 19 bytes against the 35-byte msg1 that
/// triggers it, so the retry cannot itself be turned into an amplifier.
const XX_COOKIE_LEN: usize = 16;

/// Domain separator, so an XX retry cookie can never collide with another
/// keyed-BLAKE3 value computed elsewhere from the same kind of input.
const XX_COOKIE_DOMAIN: &[u8] = b"ember-xx-retry-cookie-v1";

/// How often the cookie secret rotates. A cookie stays valid while the secret
/// that produced it is still one of the two we hold. Rotation is lazy, so a
/// cookie minted just after one rotation survives until the second rotation
/// after it: the real window is one to three intervals (15-45s), not two.
/// Long enough for a slow RTT plus a retransmit, short enough that a captured
/// cookie is worthless within a minute — and it is address-bound regardless,
/// so a longer window only ever lets an address prove itself for itself.
const XX_COOKIE_ROTATION: Duration = Duration::from_secs(15);

/// Sustained ceiling on Noise XX message 2 answers to sources that have not
/// proven return-routability, in packets per second, plus the burst allowed
/// above it.
///
/// msg2 carries our encrypted static key: 99 bytes for the 35-byte msg1 that
/// triggers it, 2.83x, aimed at whatever source address the sender wrote
/// down — and nothing dedupes a flood, because every distinct ephemeral
/// hashes to a fresh replay digest.
///
/// Demanding a cookie unconditionally would fix the ratio and break the
/// network: deployed peers do not know [`PKT_XX_COOKIE`] and will never echo
/// one, so their XX first contact would fail outright. So spend the ratio up
/// to a budget and no further, the way a SYN-cookie deployment does. What
/// this bounds is the *amplifying* volume, not reflection as such: past the
/// budget each 35-byte msg1 still draws a 19-byte cookie, so total reflected
/// bytes are `XX_UNVALIDATED_MSG2_PER_SEC * 99` per second plus 0.54x of the
/// attacker's own rate. The second term is de-amplifying (0.75x once IP and
/// UDP headers are counted), so it is useless as an amplifier — the channel
/// stays open, exactly as it does with QUIC Retry, but paying for it costs
/// the attacker more than it delivers. Before, the whole thing scaled at
/// 2.83x of whatever the attacker could push.
///
/// Rate-based rather than keyed on `pending` occupancy on purpose: occupancy
/// can be held just below a threshold indefinitely at no cost, so it buys an
/// attacker the full ratio for free. The only way to exhaust this budget is
/// to actually make us emit the packets it counts.
///
/// XX is the fallback path — we take it only when the peer's static key is
/// unknown — so 16/s sustained with a 64-packet burst sits far above what
/// honest first contact needs and far below anything useful as a reflector.
const XX_UNVALIDATED_MSG2_PER_SEC: u32 = 16;
const XX_UNVALIDATED_MSG2_BURST: u32 = 64;

/// Largest Ember UDP datagram we will parse. Valid Noise handshake and
/// transport packets are far smaller than this; the cap prevents an oversized
/// UDP datagram from driving proportional allocation during handshake parsing.
///
/// `pub(crate)` so send-side callers (the EPX `ExchangeData` reply in
/// `network/mod.rs`) can size-check a plaintext payload against the same
/// cap this module enforces on receive, instead of duplicating the magic
/// number and risking drift.
pub(crate) const MAX_EMBER_DATAGRAM_BYTES: usize = 4096;

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
    ik_authenticated: bool,
    /// Whether the peer has proven it can *receive* at this socket address.
    ///
    /// Authentication and return-routability are different questions: a
    /// Noise_IK message 1 proves who signed it but says nothing about where
    /// the sender actually is, because the pattern is 1-RTT and every node
    /// publishes its static key in `FOUND_NODE` contact lists. Set when the
    /// peer does something only reachability makes possible — answers a
    /// handshake message we sent to this address, or decrypts under keys it
    /// could only derive from our handshake reply. Sessions default to
    /// `false` so a new code path has to opt in deliberately.
    addr_validated: bool,
    /// Nonce of the return-routability probe we sealed onto this session,
    /// until its `Pong` comes back. The probe is ours, not the caller's, so
    /// its answer is swallowed rather than surfaced — otherwise it looks
    /// like an unsolicited reply to the caller's pending-ping registry.
    /// Lives here rather than on the deferred payload because the payload
    /// can be released by an earlier frame (see `dispatch_incoming`), and
    /// the probe still has an answer in flight after that.
    probe_nonce: Option<u64>,
    /// Next nonce to stamp on an outbound transport packet (monotonic).
    send_nonce: u64,
    /// Highest accepted inbound nonce.
    recv_high: u64,
    /// Bitmap of accepted nonces in `[recv_high - 63, recv_high]`; bit `i`
    /// represents `recv_high - i`.
    recv_window: u64,
}

impl NoiseSession {
    fn new(
        transport: snow::StatelessTransportState,
        remote_noise_pub: [u8; 32],
        ik_authenticated: bool,
    ) -> Self {
        Self {
            transport,
            remote_noise_pub,
            last_activity: Instant::now(),
            ik_authenticated,
            addr_validated: false,
            probe_nonce: None,
            send_nonce: 0,
            recv_high: 0,
            recv_window: 0,
        }
    }

    /// Mark a session whose peer has already proven return-routability: we
    /// started the handshake and it answered, or it completed a leg that
    /// required reading a message we sent to this address. See
    /// [`Self::addr_validated`].
    fn validated(mut self) -> Self {
        self.addr_validated = true;
        self
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
        /// The handshake a cookie retry replaced, kept so the responder's real
        /// message 2 can still be read against it.
        ///
        /// A cookie packet cannot be authenticated — nothing is keyed at msg1 —
        /// so a spoofed one must not be able to throw away the handshake we
        /// actually sent. Keeping it here means the worst a forged cookie costs
        /// is one extra msg1 on the wire, instead of the whole attempt.
        prior: Option<Box<snow::HandshakeState>>,
        queued: Vec<Vec<u8>>,
        created: Instant,
        /// Whether this handshake was already re-sent carrying a retry
        /// cookie. Nothing is keyed yet at msg1, so the cookie packet is
        /// unauthenticated: without a one-shot limit, anyone able to spoof
        /// the responder's address could answer every msg1 with another
        /// cookie and keep us minting ephemerals forever.
        cookie_retried: bool,
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
    ///
    /// `from` / `remote_noise_pub` go unread today: the only wired-up
    /// caller (`dispatch_incoming`) already has the peer address from its
    /// own argument and has no need yet for the pubkey. Kept for a future
    /// direct caller of the lower-level `process_incoming` (see its doc
    /// comment above its definition).
    #[allow(dead_code)]
    Message {
        from: SocketAddr,
        remote_noise_pub: [u8; 32],
        payload: Vec<u8>,
    },
    /// Handshake progressed; one or more response packets need to be sent.
    ///
    /// `to` goes unread for the same reason as `Message::from` above.
    #[allow(dead_code)]
    HandshakeResponse {
        to: SocketAddr,
        packets: Vec<Vec<u8>>,
    },
    /// Handshake completed; response packets to send, plus any buffered messages
    /// the peer embedded in the handshake.
    ///
    /// `peer` / `remote_noise_pub` go unread for the same reason as
    /// `Message`'s fields above.
    #[allow(dead_code)]
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
    /// Decoded control messages carried by the packet, in the order the
    /// peer sent them. Empty for pure handshake-progress packets and
    /// rejected packets.
    ///
    /// A vector rather than a single slot because one packet can deliver
    /// two payloads: a frame that proves return-routability also releases
    /// whatever the peer's IK_INIT was holding (see `dispatch_incoming`).
    /// Callers must drain this, not peek at its first element.
    pub controls: Vec<EmberControlMessage>,
    /// Decrypted application payloads that were *not* 10-byte control
    /// frames — i.e. Ember DHT messages (or future Ember-native frames)
    /// the caller is expected to route, in the order the peer sent them.
    /// Control frames are exactly 10 bytes (`version`+`kind`+`nonce`);
    /// every DHT frame is far larger (its Ed25519 signature alone is 64
    /// bytes), so frame length disambiguates the two without a dedicated
    /// channel byte. Plural for the same reason as `controls`.
    pub app_payloads: Vec<Vec<u8>>,
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
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    /// Ask the peer to reply with its current EPX source/peer payload.
    /// No body — the request itself is the whole message.
    ExchangeRequest,
    /// An EPX exchange payload (same wire format as the eD2K TCP EPX
    /// path: `ember::build_exchange_payload*` /
    /// `ember::parse_exchange_payload`). Lets two Ember peers trade
    /// source and peer hints over the encrypted Noise channel.
    ExchangeData {
        payload: Vec<u8>,
    },
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
    recent_handshakes: HashMap<[u8; 32], RecentHandshake>,
    /// Payloads carried inside an inbound IK initiation, held until the
    /// source address proves it can receive. See [`Self::handle_ik_init`].
    /// Pruned in [`Self::cleanup`].
    /// Keyed per claimant, not per address: a spoofed initiation at the same
    /// address must not be able to drop the request a real peer embedded in its
    /// own. `take_deferred_ik` already refused an entry whose static key did not
    /// match, so this only stops one claimant evicting another's.
    deferred_ik: HashMap<(SocketAddr, [u8; 32]), DeferredIkPayload>,
    /// Sessions a different-key claimant displaced at the same address, held
    /// until one of their own frames proves which claimant really holds it.
    /// See [`Self::install_session`]. Pruned in [`Self::cleanup`].
    shadow_sessions: HashMap<(SocketAddr, [u8; 32]), NoiseSession>,
    /// Secret keying the XX retry cookie, and the one it replaced. Two, not
    /// one, so a cookie minted a moment before a rotation is still honoured
    /// a moment after it. This is the *only* state an unvalidated XX msg1
    /// touches, and it is global rather than per-source — a per-source
    /// entry would trade the amplification vector for a memory-exhaustion
    /// one, which is no bargain.
    cookie_secret: [u8; 32],
    prev_cookie_secret: [u8; 32],
    cookie_rotated_at: Instant,
    /// Token bucket governing msg2 answers to sources that have not proven
    /// return-routability. Two integers rather than a per-source table:
    /// a per-source budget would be exactly the state an attacker with a
    /// spoofable source address gets to allocate for free, which is the
    /// vector the cookie exists to avoid. A single global bucket also bounds
    /// what any one victim can receive, since aiming every packet at one
    /// address spends the same tokens.
    xx_msg2_tokens: u32,
    xx_msg2_refilled_at: Instant,
}

/// An application payload that arrived inside a Noise_IK message 1 from an
/// address we have not yet proven return-routable.
struct DeferredIkPayload {
    payload: Vec<u8>,
    /// The identity that sent it. An address can change hands (NAT rebind,
    /// or an unvalidated squatter displaced by the address's real owner), and
    /// surfacing one peer's payload under another's Noise key would let a
    /// forged initiation borrow a genuine peer's identity binding.
    remote_noise_pub: [u8; 32],
    stored: Instant,
}

/// A handshake initiation we have already processed.
struct RecentHandshake {
    seen_at: Instant,
    /// Who sent it. A cached answer is only re-sent to the same address: an
    /// honest retransmit always comes from there, while replaying to a
    /// different address would turn us into a free reflector for a packet an
    /// attacker captured.
    from: SocketAddr,
    /// The answer we produced, if the handshake got that far.
    response: Option<Vec<u8>>,
}

/// Whether a handshake initiation is new, and if not, what we answered last
/// time.
enum HandshakeReplay {
    Fresh { digest: [u8; 32] },
    Seen { response: Option<Vec<u8>> },
}

impl EmberTransport {
    pub fn new(local_noise_key: [u8; 32], local_noise_pub: [u8; 32]) -> Self {
        Self {
            local_noise_key,
            local_noise_pub,
            sessions: HashMap::new(),
            pending: HashMap::new(),
            recent_handshakes: HashMap::new(),
            deferred_ik: HashMap::new(),
            shadow_sessions: HashMap::new(),
            cookie_secret: fresh_cookie_secret(),
            prev_cookie_secret: fresh_cookie_secret(),
            cookie_rotated_at: Instant::now(),
            xx_msg2_tokens: XX_UNVALIDATED_MSG2_BURST,
            xx_msg2_refilled_at: Instant::now(),
        }
    }

    /// Accrue msg2 budget for the time since the last refill.
    fn refill_xx_msg2_budget(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.xx_msg2_refilled_at);
        let earned = (elapsed.as_millis() as u64 * u64::from(XX_UNVALIDATED_MSG2_PER_SEC)) / 1000;
        // Below a whole token, leave the clock where it is so the remainder
        // carries: advancing it here would round every sub-token interval away
        // and a steady trickle of arrivals would never refill at all.
        if earned == 0 {
            return;
        }
        let refilled = u64::from(self.xx_msg2_tokens).saturating_add(earned);
        self.xx_msg2_tokens = refilled.min(u64::from(XX_UNVALIDATED_MSG2_BURST)) as u32;
        self.xx_msg2_refilled_at = now;
    }

    /// Whether we may still answer an unproven source with msg2.
    ///
    /// Checked here and charged only when a msg2 actually goes on the wire:
    /// a malformed msg1 emits nothing, and charging it would let a stream of
    /// junk push every honest peer onto the cookie path — an extra round trip
    /// for the whole network — without the attacker ever reflecting a byte.
    fn xx_msg2_budget_available(&mut self) -> bool {
        self.refill_xx_msg2_budget();
        self.xx_msg2_tokens > 0
    }

    /// Charge one msg2 put on the wire to a source that has not proven itself.
    fn spend_xx_msg2_budget(&mut self) {
        self.xx_msg2_tokens = self.xx_msg2_tokens.saturating_sub(1);
    }

    /// Age out the cookie secret pair if the rotation interval has passed.
    ///
    /// Lazy rather than timer-driven: the only thing a stale secret can do
    /// is honour a cookie for longer than intended, and every code path that
    /// mints or checks one comes through here first.
    fn rotate_cookie_secret_if_due(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.cookie_rotated_at);
        if elapsed < XX_COOKIE_ROTATION {
            return;
        }
        // Two quiet intervals mean even the outgoing secret is past its
        // window, so retire both rather than promoting a stale one — an idle
        // node must not end up honouring a cookie minted an hour ago.
        self.prev_cookie_secret = if elapsed < XX_COOKIE_ROTATION * 2 {
            self.cookie_secret
        } else {
            fresh_cookie_secret()
        };
        self.cookie_secret = fresh_cookie_secret();
        self.cookie_rotated_at = now;
    }

    /// The cookie packet answering an XX msg1 from an unproven address:
    /// `magic | type | tag(16)`, 19 bytes against msg1's 35.
    fn xx_cookie_packet(&mut self, from: SocketAddr) -> Vec<u8> {
        self.rotate_cookie_secret_if_due();
        let mut buf = Vec::with_capacity(HEADER_LEN + XX_COOKIE_LEN);
        buf.extend_from_slice(&[EMBER_MAGIC[0], EMBER_MAGIC[1], PKT_XX_COOKIE]);
        buf.extend_from_slice(&xx_cookie_for(&self.cookie_secret, from));
        buf
    }

    /// Whether `cookie` is one we issued to `from` and have not yet rotated
    /// out. Recomputing the tag is two BLAKE3 compressions over ~30 bytes —
    /// far cheaper than the X25519 the packet used to buy unconditionally,
    /// so gating msg2 on this lowers the CPU an unproven source can spend.
    fn xx_cookie_is_valid(&mut self, from: SocketAddr, cookie: &[u8]) -> bool {
        if cookie.len() != XX_COOKIE_LEN {
            return false;
        }
        self.rotate_cookie_secret_if_due();
        // `|=`, not `||`: both candidates are always checked, so the time
        // this takes leaks neither which secret matched nor whether one did.
        let mut matched = false;
        for secret in [&self.cookie_secret, &self.prev_cookie_secret] {
            matched |= cookie_tags_match(&xx_cookie_for(secret, from), cookie);
        }
        matched
    }

    /// Classify a handshake-initiation packet against the replay cache.
    ///
    /// A verbatim repeat is either an attacker replaying a captured packet or
    /// a peer that never received our answer and is retransmitting. Both look
    /// identical on the wire, so rather than choosing, we re-send the answer
    /// we already computed. That is safe — it is the same bytes the peer
    /// should have received, and it re-runs no crypto and disturbs no live
    /// session — and it unblocks the honest case, which previously stalled
    /// for the full replay TTL before it could try again.
    fn check_handshake_replay(
        &mut self,
        pkt_type: u8,
        from: SocketAddr,
        data: &[u8],
    ) -> HandshakeReplay {
        // The packet type is part of the identity. `process_incoming` strips
        // the header before dispatching, so hashing the body alone puts
        // IK_INIT and XX_MSG1 in one namespace — and snow accepts an
        // over-long XX msg1, so an on-path attacker could re-send a captured
        // IK_INIT tagged as XX_MSG1, seeding the entry with an XX msg2. The
        // genuine initiator would then be answered with the wrong message
        // type and stall for the whole replay window.
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[pkt_type]);
        hasher.update(data);
        let digest = *hasher.finalize().as_bytes();

        let now = Instant::now();
        if let Some(entry) = self.recent_handshakes.get(&digest) {
            if now.duration_since(entry.seen_at) < HANDSHAKE_REPLAY_TTL {
                return HandshakeReplay::Seen {
                    // Only the original sender gets the answer back. Anyone
                    // else replaying this packet gets silence, exactly as
                    // before this cache learned to re-send.
                    response: if entry.from == from {
                        entry.response.clone()
                    } else {
                        None
                    },
                };
            }
        }
        if self.recent_handshakes.len() >= MAX_REPLAY_DIGESTS {
            if let Some(oldest) = self
                .recent_handshakes
                .iter()
                .min_by_key(|(_, e)| e.seen_at)
                .map(|(k, _)| *k)
            {
                self.recent_handshakes.remove(&oldest);
            }
        }
        self.recent_handshakes.insert(
            digest,
            RecentHandshake {
                seen_at: now,
                from,
                response: None,
            },
        );
        HandshakeReplay::Fresh { digest }
    }

    /// Remember the answer we produced, so a retransmission of the same
    /// initiation gets the same answer instead of silence.
    fn remember_handshake_response(&mut self, digest: [u8; 32], response: Vec<u8>) {
        if let Some(entry) = self.recent_handshakes.get_mut(&digest) {
            entry.response = Some(response);
        }
    }

    /// Check if a raw UDP packet is an Ember-encrypted packet.
    ///
    /// The packet-type byte is part of the test, not just the two magic
    /// bytes. Obfuscated eD2K client-to-client datagrams begin with a byte
    /// whose low bit is forced set followed by a random byte, so they collide
    /// with the magic pair roughly once in 32k packets — and a collision here
    /// means the packet is claimed by the Ember branch and dropped instead of
    /// reaching the eD2K parser. Only seven of the 256 type values are valid,
    /// so requiring one makes that some thirty-six times rarer at no cost,
    /// since every genuine Ember packet carries one.
    pub fn is_ember_packet(data: &[u8]) -> bool {
        data.len() >= HEADER_LEN
            && data[0] == EMBER_MAGIC[0]
            && data[1] == EMBER_MAGIC[1]
            && matches!(
                data[2],
                PKT_IK_INIT
                    | PKT_IK_RESP
                    | PKT_XX_MSG1
                    | PKT_XX_MSG2
                    | PKT_XX_MSG3
                    | PKT_XX_COOKIE
                    | PKT_TRANSPORT
            )
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
    #[allow(dead_code)]
    pub fn has_session(&self, addr: &SocketAddr) -> bool {
        self.sessions.contains_key(addr)
    }

    pub fn peer_is_ik_authenticated(&self, addr: &SocketAddr) -> bool {
        self.sessions
            .get(addr)
            .is_some_and(|session| session.ik_authenticated)
    }

    /// Process an incoming Ember-encrypted UDP packet.
    pub fn process_incoming(&mut self, data: &[u8], from: SocketAddr) -> IncomingResult {
        // `dispatch_incoming` is the only wired-up caller today and already
        // enforces this cap, but `process_incoming` is `pub` and documented
        // as the lower-level entry point — enforce it here too so any
        // future direct caller can't drive proportional-to-datagram-size
        // allocation in the handshake parsers below via an oversized
        // packet.
        if data.len() > MAX_EMBER_DATAGRAM_BYTES {
            debug!(
                "process_incoming: dropping oversized Ember UDP datagram from {from}: {} bytes",
                data.len()
            );
            return IncomingResult::Rejected;
        }
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
            PKT_XX_COOKIE => self.handle_xx_cookie(from, payload),
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
        // An unvalidated session was installed by whoever sent an IK_INIT
        // claiming this address, which an off-path attacker can forge. When
        // we mean to reach a *different* identity, sealing to the squatter's
        // static key hands it our traffic and leaves the peer we asked for
        // deaf — the other half of the lockout the takeover guard used to
        // cause. Nothing is lost by dropping an unproven session, so start a
        // fresh handshake to the identity the caller named.
        let squatted = match (remote_noise_pub, self.sessions.get(&peer)) {
            (Some(want), Some(existing)) => {
                !existing.addr_validated && existing.remote_noise_pub != *want
            }
            _ => false,
        };
        if squatted {
            debug!(
                "Discarding unvalidated session for {peer}: it holds a different static key \
                 than the peer we are dialling"
            );
            // Only the squatter's own state: its deferred payload is keyed on its
            // static key, and another claimant's must not be collateral.
            if let Some(displaced) = self.sessions.remove(&peer) {
                self.deferred_ik
                    .remove(&(peer, displaced.remote_noise_pub));
            }
        }

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

    /// Install `session` as the live one for `addr`, keeping a different-key
    /// session it displaces as a shadow.
    ///
    /// A session is keyed on an address an off-path attacker can forge, so
    /// "newest unproven claimant wins" is what stops a spoofed session locking
    /// the address owner out. On its own that also let a spoofer replace a real
    /// peer's session every few tens of milliseconds, so the peer's own probe
    /// answer never had a session to decrypt against and its first contact never
    /// completed. Retaining the displaced one makes an address hold effectively
    /// one session per static key: the wrong claimant is never the one that opens
    /// a frame, so neither has to outrank the other.
    fn install_session(&mut self, addr: SocketAddr, session: NoiseSession) {
        let arriving_key = session.remote_noise_pub;
        // Enforced here, not only at the handshake call sites: promoting a proven
        // shadow can install a session at an address that has none — its live
        // entry having been evicted or discarded — and that path had no cap check,
        // so `sessions` could grow past `MAX_SESSIONS` by as many promotions as
        // there were shadows.
        if !self.sessions.contains_key(&addr) && self.sessions.len() >= MAX_SESSIONS {
            self.evict_oldest_session();
        }
        // This handshake supersedes any shadow for the same key: leaving an older
        // one there would let frames from the earlier handshake promote it back
        // over the session that just replaced it.
        self.shadow_sessions.remove(&(addr, arriving_key));
        if let Some(displaced) = self.sessions.insert(addr, session) {
            if displaced.remote_noise_pub == arriving_key {
                return;
            }
            self.shadow_sessions
                .insert((addr, displaced.remote_noise_pub), displaced);
            self.trim_shadow_sessions(addr);
        }
    }

    /// Keep [`Self::shadow_sessions`] bounded, per address first.
    ///
    /// Only an *unvalidated* session is ever displaced — the takeover guards
    /// refuse a different key while the incumbent is validated — so every shadow
    /// at an address arrived in the order its claimant did. That is what decides
    /// the rule: a spoofer churning static keys mints the newest shadows at that
    /// address, so shedding the newest keeps the genuine peer's, which arrived
    /// first and is the one with a probe answer still in flight.
    ///
    /// The per-address cap has to come first. Applying the newest-first rule to a
    /// global cap inverts it: a map left full by an earlier burst elsewhere would
    /// evict each freshly displaced session the moment it was stored — precisely
    /// the one being protected. The global cap is a memory backstop only, and
    /// sheds the oldest, which is nearest its `SESSION_TIMEOUT` anyway.
    fn trim_shadow_sessions(&mut self, addr: SocketAddr) {
        while self
            .shadow_sessions
            .keys()
            .filter(|(shadow_addr, _)| *shadow_addr == addr)
            .count()
            > MAX_SHADOW_SESSIONS_PER_ADDR
        {
            let Some(newest) = self
                .shadow_sessions
                .iter()
                .filter(|((shadow_addr, _), _)| *shadow_addr == addr)
                .max_by_key(|(_, session)| session.last_activity)
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.shadow_sessions.remove(&newest);
        }
        while self.shadow_sessions.len() > MAX_SHADOW_SESSIONS {
            let Some(oldest) = self
                .shadow_sessions
                .iter()
                .min_by_key(|(_, session)| session.last_activity)
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.shadow_sessions.remove(&oldest);
        }
    }

    /// Remove expired sessions and pending handshakes.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.sessions
            .retain(|_, s| now.duration_since(s.last_activity) < SESSION_TIMEOUT);
        self.shadow_sessions
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
            .retain(|_, e| now.duration_since(e.seen_at) < HANDSHAKE_REPLAY_TTL);
        self.deferred_ik
            .retain(|_, d| now.duration_since(d.stored) < DEFERRED_IK_PAYLOAD_TTL);
    }

    /// Remove an existing session for a peer (e.g., on disconnect).
    #[allow(dead_code)]
    pub fn remove_session(&mut self, addr: &SocketAddr) {
        self.sessions.remove(addr);
        self.shadow_sessions.retain(|(shadow, _), _| shadow != addr);
        self.pending.remove(addr);
        self.deferred_ik.retain(|(deferred, _), _| deferred != addr);
    }

    /// Drop every session and pending handshake. Used when the
    /// `ember_native_enabled` feature flag flips off so a session
    /// established during an "on" period cannot decrypt later traffic
    /// when the user re-enables it (different harness session,
    /// different intent, possibly different peer trust).
    pub fn cleanup_all(&mut self) {
        self.sessions.clear();
        self.shadow_sessions.clear();
        self.pending.clear();
        self.recent_handshakes.clear();
        self.deferred_ik.clear();
    }

    /// Drive the Noise state machine for an inbound UDP packet and
    /// produce every side effect as data: response packets to send
    /// back, plus the decoded control message if the packet carried
    /// a payload.
    ///
    /// When a decoded payload is a `Ping`, the matching `Pong` is
    /// encoded on the same session and appended to `responses`, so
    /// the caller only has to drain the response list and update its
    /// counters / pending-ping registry. Pure handshake-progress
    /// packets (no embedded payload) yield empty `controls` and
    /// `app_payloads`. Garbled or malformed packets yield
    /// `rejected: true` and an empty `responses` vector.
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

        // A transport frame that authenticates is the proof of
        // return-routability an inbound IK handshake could not give us, so
        // whatever that handshake carried can be acted on now. Callers of the
        // lower-level `process_incoming` do not get this release; they see the
        // deferral only as a payload that arrives one round trip late.
        let released = match &result {
            IncomingResult::Message {
                remote_noise_pub, ..
            } => self.take_deferred_ik(from, remote_noise_pub),
            _ => None,
        };

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

        // One dispatch can therefore surface two payloads, in the order the
        // peer sent them: the request we held back, then the frame that
        // released it. Both must come out, because the releasing frame is
        // routinely *not* the probe answer — a peer that calls
        // `prepare_outgoing` twice before our probe reaches it has its second
        // request flushed by `handle_ik_resp` the instant IK_RESP is read, so
        // we see that request first and it, not the `Pong`, is what proves
        // the address. Surfacing only one of the two silently dropped the
        // request embedded in IK_INIT, which a search retries once and a
        // one-shot `STORE_RECORD` or `ExchangeRequest` never recovers.
        // Releasing on a non-probe frame weakens nothing: `take_deferred_ik`
        // only fires on a frame that authenticated under keys derived from
        // our IK_RESP, which is the same proof the `Pong` carried.
        //
        // The probe answer itself is ours to swallow — surfacing it would
        // look like an unsolicited reply to the caller's pending-ping
        // registry — whether or not a deferred payload is still waiting.
        let probe_answered = self.consume_probe_answer(from, &payload);
        let mut payloads = Vec::with_capacity(2);
        if let Some(deferred) = released {
            payloads.push(deferred.payload);
        }
        if !probe_answered {
            payloads.push(payload);
        }

        for payload in payloads {
            let Some(message) = EmberControlMessage::decode(&payload) else {
                // Not a 10-byte control frame — hand the raw decrypted
                // bytes back as an application payload (DHT message, future
                // Ember-native frame). The caller routes it; the handshake
                // responses (if any) still ride along in `responses`.
                outcome.app_payloads.push(payload);
                continue;
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

            outcome.controls.push(message);
        }

        outcome
    }

    /// Whether `payload` is the `Pong` answering the return-routability probe
    /// we sealed onto this peer's session, consuming the expectation if so.
    ///
    /// Kept on the session rather than on the deferred payload because the
    /// two now come apart: an earlier frame can release the payload while the
    /// probe's answer is still in flight, and that answer must still be
    /// swallowed when it lands.
    fn consume_probe_answer(&mut self, from: SocketAddr, payload: &[u8]) -> bool {
        let Some(session) = self.sessions.get_mut(&from) else {
            return false;
        };
        let Some(nonce) = session.probe_nonce else {
            return false;
        };
        if EmberControlMessage::decode(payload) != Some(EmberControlMessage::Pong { nonce }) {
            return false;
        }
        session.probe_nonce = None;
        true
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
        // Same rule `handle_xx_msg1` applies: never let an inbound init
        // destroy a handshake *we* started to the same address.
        //
        // Without it, two peers that dialled each other inside one RTT each
        // completed as responder to the other's msg1 and dropped their own
        // initiator state — so each side's msg2 then arrived to "no pending
        // handshake" and was refused, leaving both ends holding a live
        // session from a *different* handshake. Every transport packet
        // between them failed AEAD after that, and nothing recovered it:
        // decrypt failures deliberately do not tear a session down,
        // `prepare_outgoing` keeps refreshing `last_activity` so the idle
        // timeout never fires, and the collision itself marked the contact
        // fresh enough to skip liveness pings for ten minutes.
        if matches!(
            self.pending.get(&from),
            Some(PendingHandshake::IkInitiator { .. } | PendingHandshake::XxInitiatorMsg1 { .. })
        ) {
            debug!("Ignoring IK init from {from}: an initiator handshake is in flight");
            return IncomingResult::Rejected;
        }
        // Do no crypto, re-emit no embedded payload, and replace no live
        // session for a repeat. Answering with the response we already
        // computed serves a peer whose copy was lost without giving a
        // replaying attacker anything it did not already see on the wire.
        let handshake_digest = match self.check_handshake_replay(PKT_IK_INIT, from, data) {
            HandshakeReplay::Fresh { digest } => digest,
            HandshakeReplay::Seen { response } => {
                return match response {
                    Some(packet) => {
                        debug!("Re-sending cached IK response to {from}");
                        IncomingResult::HandshakeResponse {
                            to: from,
                            packets: vec![packet],
                        }
                    }
                    None => {
                        debug!("Dropping replayed IK_INIT from {from}");
                        IncomingResult::Rejected
                    }
                };
            }
        };
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
        //
        // Only a *validated* incumbent earns that protection. An unvalidated
        // session proves nothing about who is at the address — anyone able to
        // forge a source address can install one — so preferring it over a
        // newcomer inverted the guard into a lockout: one spoofed IK_INIT
        // claiming a victim's address kept the victim itself from ever
        // handshaking with us, refreshable with a packet per session lifetime
        // and unrecoverable because decrypt failures never tear a session
        // down. Between two unproven claimants, let the newest one try.
        // KNOWN RESIDUAL: "newest unproven claimant wins" is what keeps a
        // spoofed session from locking the address owner out (see
        // `an_unvalidated_session_never_locks_out_the_address_owner`), but it
        // also means a spoofer sending one init every few tens of milliseconds
        // can replace a real peer's session before its `Pong` lands, so a
        // targeted peer never completes inbound first contact. The two are in
        // direct tension here and a grace window only moves the loss around:
        // protecting the incumbent for one round trip reinstates a bounded
        // version of the lockout, and one-shot payloads (`STORE_RECORD`,
        // `ExchangeRequest`) have no retry to survive it. Keying sessions by
        // `(addr, static_key)` so both claimants coexist — and the wrong one is
        // simply never selected — removes the need to rank them at all, which is
        // the actual fix and is deliberately not attempted here.
        if let Some(existing) = self.sessions.get(&from) {
            if existing.remote_noise_pub != remote_noise_pub && existing.addr_validated {
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
        let mut session = NoiseSession::new(transport, remote_noise_pub, true);
        // Clear any stale pending handshake for this address (e.g. an
        // earlier XX attempt we initiated before this IK init arrived).
        // Left in place, it lingers until the 30s pending-cleanup sweep
        // and can confuse a late, stray XX packet into being processed
        // against a handshake state that's no longer relevant now that a
        // session exists.
        self.pending.remove(&from);
        trace!("IK handshake completed (responder) with {from}");

        self.remember_handshake_response(handshake_digest, resp_buf.clone());
        let mut packets_to_send = vec![resp_buf];

        // Nothing in message 1 proves the sender can *receive* where it says
        // it is. IK is 1-RTT and every node's static key is published in
        // FOUND_NODE contact lists, so an off-path attacker can drive this
        // whole handshake from a forged source address — and acting on the
        // embedded payload right here is what turned that into an attack:
        // an embedded FIND_NODE reflected a ~1.4 KB FOUND_NODE at the forged
        // address for a ~235-byte packet, an embedded EXCHANGE_REQUEST
        // reflected a multi-kilobyte EPX payload, and an embedded
        // STORE_RECORD satisfied the DHT's `from.ip() == source.ip`
        // anti-reflection bind (`dht/engine.rs`) for free, aiming a swarm of
        // downloaders at whatever host the attacker named.
        //
        // So hold the payload until the address is proven, and prompt the
        // peer to prove it immediately with a control `Ping`: only someone
        // who actually received our IK_RESP can derive the keys to answer,
        // and answering a `Ping` on an established session is something
        // every Ember client already does, so this costs one round trip and
        // no wire-format change. Until the proof arrives the only bytes an
        // initiation earns are this 51-byte IK_RESP and the 37-byte probe —
        // together smaller than the 99-byte minimum IK_INIT that triggered
        // them, so there is nothing left to amplify.
        self.deferred_ik.remove(&(from, remote_noise_pub));
        if payload_len > 0 {
            let probe_nonce = rand::random::<u64>();
            self.deferred_ik.insert(
                (from, remote_noise_pub),
                DeferredIkPayload {
                    payload: payload_buf[..payload_len].to_vec(),
                    remote_noise_pub,
                    stored: Instant::now(),
                },
            );
            let probe = EmberControlMessage::Ping { nonce: probe_nonce }.encode();
            match session.seal(&probe) {
                Some(packet) => {
                    session.probe_nonce = Some(probe_nonce);
                    packets_to_send.push(packet);
                }
                // The payload stays deferred and is not lost: any
                // authenticated frame from this peer releases it, so without
                // a probe it simply waits for the peer's own next frame
                // instead of a prompt reply.
                None => warn!("IK responder: failed to seal return-routability probe for {from}"),
            }
            // Trimmed after the insert, not before, so the bound is applied with
            // this claimant's entry among the candidates rather than to a map it
            // has not joined yet.
            self.trim_deferred_ik(from);
        }

        self.install_session(from, session);

        IncomingResult::HandshakeComplete {
            peer: from,
            remote_noise_pub,
            packets_to_send,
            decrypted_payload: None,
        }
    }

    /// Release the payload deferred for `from`, if the peer that just proved
    /// return-routability is the one that left it there.
    fn take_deferred_ik(
        &mut self,
        from: SocketAddr,
        remote_noise_pub: &[u8; 32],
    ) -> Option<DeferredIkPayload> {
        // Logged rather than silently returning `None`: a dropped deferral means
        // a peer's first-contact request is gone, and for a one-shot publish or
        // exchange there is no retry to make it look like anything but a peer
        // that never asked.
        let Some(entry) = self.deferred_ik.remove(&(from, *remote_noise_pub)) else {
            trace!("No deferred IK payload for {from}: evicted, expired, or never held one");
            return None;
        };
        // The key already pins the claimant, so this only drops one that has sat
        // here past its TTL. The static-key comparison stays as a belt-and-braces
        // check against a future caller keying it differently.
        if &entry.remote_noise_pub != remote_noise_pub
            || Instant::now().duration_since(entry.stored) >= DEFERRED_IK_PAYLOAD_TTL
        {
            return None;
        }
        Some(entry)
    }

    /// Keep [`Self::deferred_ik`] bounded, on the same rule as
    /// [`Self::trim_shadow_sessions`] and for the same reason: entries at one
    /// address arrived in the order their claimants did, so a spoofer churning
    /// static keys mints the newest and shedding those keeps the genuine peer's
    /// request. The global cap is a memory backstop and sheds the oldest, which is
    /// nearest its TTL.
    fn trim_deferred_ik(&mut self, addr: SocketAddr) {
        while self
            .deferred_ik
            .keys()
            .filter(|(deferred_addr, _)| *deferred_addr == addr)
            .count()
            > MAX_DEFERRED_IK_PAYLOADS_PER_ADDR
        {
            let Some(newest) = self
                .deferred_ik
                .iter()
                .filter(|((deferred_addr, _), _)| *deferred_addr == addr)
                .max_by_key(|(_, payload)| payload.stored)
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.deferred_ik.remove(&newest);
        }
        while self.deferred_ik.len() > MAX_DEFERRED_IK_PAYLOADS {
            let Some(oldest) = self
                .deferred_ik
                .iter()
                .min_by_key(|(_, payload)| payload.stored)
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.deferred_ik.remove(&oldest);
        }
    }

    #[allow(dead_code)]
    fn evict_oldest_deferred_ik(&mut self) {
        if let Some(oldest) = self
            .deferred_ik
            .iter()
            .min_by_key(|(_, d)| d.stored)
            .map(|(k, _)| *k)
        {
            self.deferred_ik.remove(&oldest);
        }
    }

    fn handle_ik_resp(&mut self, from: SocketAddr, data: &[u8]) -> IncomingResult {
        // Authenticate before consuming the pending entry, for the reason
        // spelled out in `handle_xx_msg2`. This is the more damaging of the
        // two: IK is the path we take whenever the peer's static key is
        // already known, so it carries nearly all first contact, and one
        // unauthenticated packet used to end any handshake in flight.
        let mut payload_buf = vec![0u8; data.len()];
        match self.pending.get_mut(&from) {
            Some(PendingHandshake::IkInitiator { state, .. }) => {
                if let Err(e) = state.read_message(data, &mut payload_buf) {
                    debug!("IK resp read_message failed from {from}: {e}");
                    return IncomingResult::Rejected;
                }
            }
            Some(_) => {
                debug!("Unexpected IK response from {from} (wrong handshake type)");
                return IncomingResult::Rejected;
            }
            None => {
                debug!("IK response from {from} but no pending handshake");
                return IncomingResult::Rejected;
            }
        }

        let Some(PendingHandshake::IkInitiator { state, queued, .. }) = self.pending.remove(&from)
        else {
            debug!("IK resp from {from}: pending handshake changed shape mid-dispatch");
            return IncomingResult::Rejected;
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
        // and allowed, and an unvalidated incumbent — which anyone spoofing
        // this address could have installed — never outranks a handshake we
        // started ourselves.
        if let Some(existing) = self.sessions.get(&from) {
            if existing.remote_noise_pub != remote_noise_pub && existing.addr_validated {
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
        // We started this handshake: message 2 could only be produced by a
        // peer that read the message 1 we sent to this address, so the
        // address is proven.
        let mut session = NoiseSession::new(transport, remote_noise_pub, true).validated();

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
        self.install_session(from, session);
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
        match self.write_xx_msg1(peer, vec![first_message.to_vec()], &[], false, None) {
            Ok(packet) => {
                trace!("Started XX handshake with {peer}");
                OutgoingResult::HandshakeStarted { packet }
            }
            Err(e) => OutgoingResult::Error(e),
        }
    }

    /// Build XX message 1 and park the initiator state for `peer`.
    ///
    /// `cookie` rides in the message's payload, which `-> e` leaves in the
    /// clear — it is a return-routability token, not a secret, and carrying
    /// it there keeps the retry an ordinary msg1 that the replay cache still
    /// dedupes verbatim, rather than a second packet type on the request
    /// side. An empty `cookie` produces exactly the 35-byte msg1 this
    /// function has always produced.
    fn write_xx_msg1(
        &mut self,
        peer: SocketAddr,
        queued: Vec<Vec<u8>>,
        cookie: &[u8],
        cookie_retried: bool,
        prior: Option<Box<snow::HandshakeState>>,
    ) -> Result<Vec<u8>, String> {
        let (initiator, buf) = self.build_xx_msg1(cookie)?;
        self.pending.insert(
            peer,
            PendingHandshake::XxInitiatorMsg1 {
                state: initiator,
                prior,
                queued,
                created: Instant::now(),
                cookie_retried,
            },
        );
        Ok(buf)
    }

    /// Build a message 1 without touching any state, so a caller holding state it
    /// would have to put back can do the fallible part first.
    fn build_xx_msg1(&self, cookie: &[u8]) -> Result<(snow::HandshakeState, Vec<u8>), String> {
        let params = NOISE_PATTERN_XX
            .parse::<snow::params::NoiseParams>()
            .map_err(|e| format!("noise params: {e}"))?;
        let mut initiator = snow::Builder::new(params)
            .local_private_key(&self.local_noise_key)
            .build_initiator()
            .map_err(|e| format!("noise init: {e}"))?;

        let mut buf = vec![0u8; HEADER_LEN + cookie.len() + 256];
        buf[0] = EMBER_MAGIC[0];
        buf[1] = EMBER_MAGIC[1];
        buf[2] = PKT_XX_MSG1;
        let len = initiator
            .write_message(cookie, &mut buf[HEADER_LEN..])
            .map_err(|e| format!("noise write: {e}"))?;
        buf.truncate(HEADER_LEN + len);
        Ok((initiator, buf))
    }

    /// Re-send message 1 carrying the retry cookie the responder asked for.
    ///
    /// Nothing is keyed at msg1, so this packet cannot be authenticated and a
    /// spoofed one used to destroy the handshake we had already sent — the only
    /// reader where an unauthenticated packet consumed pending state. It no
    /// longer does: the parked handshake moves into `prior` and
    /// [`Self::handle_xx_msg2`] accepts a message 2 that verifies against either,
    /// so a forged cookie costs one extra msg1 and nothing else. `cookie_retried`
    /// still bounds that to once per attempt.
    fn handle_xx_cookie(&mut self, from: SocketAddr, data: &[u8]) -> IncomingResult {
        if data.len() != XX_COOKIE_LEN {
            debug!("XX cookie from {from} has wrong length {}", data.len());
            return IncomingResult::Rejected;
        }
        match self.pending.get(&from) {
            Some(PendingHandshake::XxInitiatorMsg1 {
                cookie_retried: false,
                ..
            }) => {}
            Some(PendingHandshake::XxInitiatorMsg1 { .. }) => {
                debug!("Ignoring XX cookie from {from}: this handshake already spent its retry");
                return IncomingResult::Rejected;
            }
            _ => {
                debug!("XX cookie from {from} but no XX handshake of ours is in flight");
                return IncomingResult::Rejected;
            }
        }

        // A fresh initiator, not the parked one: msg1's payload is mixed into the
        // Noise transcript hash, so the cookie has to be present when the message
        // is written, and snow cannot rewrite one it has already produced.
        //
        // Built before the parked handshake is taken, so a failure here leaves the
        // in-flight attempt exactly as it was — the responder may still answer the
        // message 1 we already sent.
        let (initiator, packet) = match self.build_xx_msg1(data) {
            Ok(built) => built,
            Err(e) => {
                debug!("XX cookie retry for {from} failed: {e}");
                return IncomingResult::Rejected;
            }
        };

        // The queued payloads move across so nothing the caller handed us during
        // the cookie round trip is dropped.
        let Some(PendingHandshake::XxInitiatorMsg1 { state, prior, queued, .. }) =
            self.pending.remove(&from)
        else {
            debug!("XX cookie from {from}: the pending handshake changed shape mid-dispatch");
            return IncomingResult::Rejected;
        };
        self.pending.insert(
            from,
            PendingHandshake::XxInitiatorMsg1 {
                state: initiator,
                // Keep the handshake this retry replaces. Prefer the original when
                // a retry is itself retried: it is the one the responder saw first,
                // and holding more than one spare would let a cookie flood grow
                // this entry.
                prior: Some(prior.unwrap_or_else(|| Box::new(state))),
                queued,
                created: Instant::now(),
                cookie_retried: true,
            },
        );
        trace!("Re-sending XX msg1 to {from} with the retry cookie");
        IncomingResult::HandshakeResponse {
            to: from,
            packets: vec![packet],
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
        // Below the ephemeral key there is no msg1 to speak of, and answering
        // a runt with a 19-byte cookie would be the very amplification the
        // cookie exists to prevent.
        if data.len() < XX_MSG1_EPHEMERAL_LEN {
            debug!(
                "XX msg1 from {from} is too short to carry an ephemeral key ({} bytes)",
                data.len()
            );
            return IncomingResult::Rejected;
        }
        // Noise XX message 1 is 32 bytes of ephemeral key and nothing else:
        // no signature, no state, no proof of anything. Answering it with
        // msg2 — which carries our encrypted static key — is 99 bytes for
        // 35, a 2.83x reflector aimed at whatever source address the sender
        // wrote down, and nothing dedupes the flood because every distinct
        // ephemeral is a fresh replay digest.
        //
        // The standard answer is a stateless retry cookie the sender has to
        // echo, as QUIC Retry and DTLS HelloVerifyRequest do and as the QUIC
        // path in `relay.rs` already does one layer down. Demanding one
        // unconditionally, though, would break every deployed peer: they do
        // not know `PKT_XX_COOKIE` and would never echo it, so their XX first
        // contact would fail outright. So engage it only under pressure. Below
        // the budget an unproven source is answered exactly as before, at no
        // extra round trip; once the budget is gone — the flood case and
        // nothing else — every further msg1 earns a 19-byte cookie instead of
        // a 99-byte msg2, which is 0.54x and cannot be amplified in turn.
        //
        // A valid cookie skips the budget entirely: that address is proven, so
        // its msg2 is not a reflection, and an honest peer that completes the
        // round trip during an attack never competes with the flood for
        // tokens. Note this whole check runs before the replay cache and
        // before any Noise work, so a cookie-less msg1 we decline costs one
        // BLAKE3 and leaves no state behind.
        let cookie_ok = self.xx_cookie_is_valid(from, &data[XX_MSG1_EPHEMERAL_LEN..]);
        if !cookie_ok && !self.xx_msg2_budget_available() {
            trace!("XX msg1 from {from} is over the unvalidated msg2 budget; sending a cookie");
            return IncomingResult::HandshakeResponse {
                to: from,
                packets: vec![self.xx_cookie_packet(from)],
            };
        }
        // A repeat is either a replay or a peer that never got our msg2.
        // Re-sending the msg2 we already produced serves the honest case and
        // gives a replaying attacker nothing new, whereas dropping it stalled
        // a legitimate retransmit for the whole replay TTL.
        let handshake_digest = match self.check_handshake_replay(PKT_XX_MSG1, from, data) {
            HandshakeReplay::Fresh { digest } => digest,
            HandshakeReplay::Seen { response } => {
                return match response {
                    Some(packet) => {
                        debug!("Re-sending cached XX msg2 to {from}");
                        // The cached answer is another 99 bytes to the same
                        // unproven address, so it is charged like a fresh one.
                        // Without this, one msg1 replayed inside the cache TTL
                        // re-emitted msg2 without limit — the cheapest form of
                        // the flood, since the attacker does no crypto at all.
                        if !cookie_ok {
                            self.spend_xx_msg2_budget();
                        }
                        IncomingResult::HandshakeResponse {
                            to: from,
                            packets: vec![packet],
                        }
                    }
                    None => {
                        debug!("Dropping replayed XX msg1 from {from}");
                        IncomingResult::Rejected
                    }
                };
            }
        };
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

        self.remember_handshake_response(handshake_digest, resp_buf.clone());
        if !cookie_ok {
            self.spend_xx_msg2_budget();
        }

        IncomingResult::HandshakeResponse {
            to: from,
            packets: vec![resp_buf],
        }
    }

    fn handle_xx_msg2(&mut self, from: SocketAddr, data: &[u8]) -> IncomingResult {
        // Read against the parked handshake *in place* and take it out of
        // `pending` only once the message authenticates. Taking it out first
        // meant a single unauthenticated msg2 — anything of the right packet
        // type from an address we happen to have a handshake in flight to —
        // permanently stranded that handshake: the genuine msg2 then arrived
        // to "no pending handshake" and XX first contact simply never
        // completed. An attacker does not need to guess anything to do it,
        // only to spray spoofed msg2s from known peer addresses.
        //
        // Retrying against the same state is sound here, but read why before
        // copying this pattern elsewhere. snow does roll back on a failed
        // read, and does not advance `pattern_position`, `my_turn`, or the
        // cipherstate nonce (`handshakestate.rs`, `cipherstate.rs`) — but its
        // checkpoint is only `{h, ck, has_key}` and does *not* cover the
        // CipherState's key. What actually makes this safe is the message
        // pattern: XX msg2 is `<- e, ee, s, es`, so the first cipherstate
        // touch is `Dh(ee) -> mix_key`, which re-keys and zeroes the nonce at
        // the start of every attempt, before anything can fail destructively.
        // A pattern whose first token decrypts against the *existing* key —
        // XX msg3's `s` — has no such reset and is not safe to retry this way.
        // The only other residue is the remote-ephemeral buffer, which the
        // next read overwrites from its own `e` token before anything consumes
        // it. So the genuine msg2 still verifies afterwards.
        let mut buf = vec![0u8; data.len() + 64];
        // Try the live handshake, then the one a cookie retry displaced. Only the
        // responder can produce a message 2 that verifies, so whichever it answers
        // is the real one — which is what makes an unauthenticated cookie packet
        // harmless: it can add a candidate, never remove one. Each state is a
        // separate object, so a failed read on one cannot disturb the other.
        let verified_prior = match self.pending.get_mut(&from) {
            Some(PendingHandshake::XxInitiatorMsg1 { state, prior, .. }) => {
                if state.read_message(data, &mut buf).is_ok() {
                    false
                } else {
                    match prior.as_mut().map(|prior| prior.read_message(data, &mut buf)) {
                        Some(Ok(_)) => true,
                        _ => {
                            debug!(
                                "XX msg2 from {from} verified against neither the retry nor the \
                                 handshake it replaced"
                            );
                            return IncomingResult::Rejected;
                        }
                    }
                }
            }
            Some(_) => {
                debug!("Unexpected XX msg2 from {from}");
                return IncomingResult::Rejected;
            }
            None => {
                debug!("XX msg2 from {from} but no pending handshake");
                return IncomingResult::Rejected;
            }
        };

        // Authenticated, so the handshake is ours to consume. The variant is
        // the one matched above — nothing can have run in between under
        // `&mut self` — and the arm exists only so a future refactor cannot
        // turn a mismatch into a panic.
        let Some(PendingHandshake::XxInitiatorMsg1 {
            state,
            prior,
            queued,
            ..
        }) = self.pending.remove(&from)
        else {
            debug!("XX msg2 from {from}: pending handshake changed shape mid-dispatch");
            return IncomingResult::Rejected;
        };
        // Carry on with whichever state read the message; the other is dropped.
        let mut state = if verified_prior {
            match prior {
                Some(prior) => *prior,
                None => {
                    debug!("XX msg2 from {from}: the verified handshake vanished mid-dispatch");
                    return IncomingResult::Rejected;
                }
            }
        } else {
            state
        };

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
        // address (session-takeover defense). An unvalidated incumbent has
        // proven nothing and does not outrank a handshake we started.
        if let Some(existing) = self.sessions.get(&from) {
            if existing.remote_noise_pub != remote_noise_pub && existing.addr_validated {
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
        // We started this handshake and the peer answered, so the address is
        // proven (see `handle_ik_resp`).
        let mut session = NoiseSession::new(transport, remote_noise_pub, false).validated();

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
        self.install_session(from, session);
        trace!("XX handshake completed (initiator) with {from}");

        IncomingResult::HandshakeComplete {
            peer: from,
            remote_noise_pub,
            packets_to_send: packets,
            decrypted_payload: None,
        }
    }

    fn handle_xx_msg3(&mut self, from: SocketAddr, data: &[u8]) -> IncomingResult {
        // Authenticate before consuming the pending entry, for the reason
        // spelled out in `handle_xx_msg2`. Here it strands the responder half:
        // we have already sent msg2 and a forged msg3 used to discard the
        // state the real one needs.
        //
        // This closes the off-path case, which is the one that matters: msg3 is
        // `-> s, se`, and a forged `s` block fails `decrypt_ad` before the
        // nonce advances and before `Dh(se)` re-keys, so the state is untouched
        // and the genuine msg3 still verifies. It does *not* close the on-path
        // case — see the pattern note in `handle_xx_msg2`. Replaying the real
        // `s` block with a corrupted payload lets `Dh(se)` re-key before the
        // failure, and snow's rollback does not restore the CipherState, so the
        // genuine msg3 can no longer decrypt and the handshake waits out the
        // pending sweep. Not a regression (the old order stranded this case
        // too), and an attacker holding that position can strand us just by
        // dropping msg3. Closing it means snapshotting the responder state
        // around the read, which costs a clone on every inbound msg3.
        let mut payload_buf = vec![0u8; data.len()];
        let payload_len = match self.pending.get_mut(&from) {
            Some(PendingHandshake::XxResponderMsg2 { state, .. }) => {
                match state.read_message(data, &mut payload_buf) {
                    Ok(len) => len,
                    Err(e) => {
                        debug!("XX msg3 read failed from {from}: {e}");
                        return IncomingResult::Rejected;
                    }
                }
            }
            Some(_) => {
                debug!("Unexpected XX msg3 from {from}");
                return IncomingResult::Rejected;
            }
            None => {
                debug!("XX msg3 from {from} but no pending handshake");
                return IncomingResult::Rejected;
            }
        };

        let Some(PendingHandshake::XxResponderMsg2 { state, queued, .. }) =
            self.pending.remove(&from)
        else {
            debug!("XX msg3 from {from}: pending handshake changed shape mid-dispatch");
            return IncomingResult::Rejected;
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
        // Message 3 is itself proof of return-routability, so it outranks an
        // unvalidated incumbent that only ever claimed this address.
        if let Some(existing) = self.sessions.get(&from) {
            if existing.remote_noise_pub != remote_noise_pub && existing.addr_validated {
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
        // Message 3 can only be produced by a peer that read the message 2 we
        // sent to this address, so the address is proven.
        let mut session = NoiseSession::new(transport, remote_noise_pub, false).validated();

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
        self.install_session(from, session);
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

        // Every way the live session can fail to account for this frame falls
        // through to the sessions displaced at this address, because a displaced
        // one lives *only* in `shadow_sessions`. Missing outright: eviction, the
        // squatter discard in `prepare_outgoing`, or an encrypt failure dropped it.
        // Refused by the replay window: a squatter holding the live slot can
        // advance its own receive window with frames it encrypts itself, which
        // would otherwise make the genuine peer's low-nonce probe answer look
        // stale. Failed to decrypt: the ordinary case of two claimants.
        let live_outcome = match self.sessions.get_mut(&from) {
            Some(session) if session.replay_precheck(nonce) => {
                let mut payload_buf = vec![0u8; ciphertext.len()];
                match session
                    .transport
                    .read_message(nonce, ciphertext, &mut payload_buf)
                {
                    Ok(len) => {
                        // Commit the nonce to the replay window only now that AEAD
                        // has authenticated it.
                        session.replay_commit(nonce);
                        session.last_activity = Instant::now();
                        // Deriving these keys required reading the handshake reply
                        // we sent to this address, so this frame is the
                        // return-routability proof an IK responder session starts
                        // out without. From here the session can be trusted with
                        // the address it is keyed on (see `handle_ik_init`).
                        session.addr_validated = true;
                        Some(IncomingResult::Message {
                            from,
                            remote_noise_pub: session.remote_noise_pub,
                            payload: payload_buf[..len].to_vec(),
                        })
                    }
                    Err(e) => {
                        // Crucially, do NOT tear the session down: over UDP a
                        // single spoofed, corrupt, or stray datagram would
                        // otherwise kill a perfectly healthy session.
                        debug!("Ember transport decrypt failed from {from} (nonce {nonce}): {e}");
                        None
                    }
                }
            }
            Some(_) => {
                trace!("Ember transport replayed/stale nonce {nonce} from {from} on the live session");
                None
            }
            None => {
                debug!("Ember transport packet from {from} with no live session");
                None
            }
        };
        match live_outcome {
            Some(result) => result,
            None => self.open_with_shadow_session(from, nonce, ciphertext),
        }
    }

    /// Try the sessions displaced at `from`, promoting one that opens the frame.
    fn open_with_shadow_session(
        &mut self,
        from: SocketAddr,
        nonce: u64,
        ciphertext: &[u8],
    ) -> IncomingResult {
        let candidates: Vec<[u8; 32]> = self
            .shadow_sessions
            .keys()
            .filter(|(addr, _)| *addr == from)
            .map(|(_, key)| *key)
            .collect();
        for key in candidates {
            let Some(shadow) = self.shadow_sessions.get_mut(&(from, key)) else {
                continue;
            };
            if !shadow.replay_precheck(nonce) {
                continue;
            }
            let mut payload_buf = vec![0u8; ciphertext.len()];
            let Ok(len) = shadow
                .transport
                .read_message(nonce, ciphertext, &mut payload_buf)
            else {
                continue;
            };
            shadow.replay_commit(nonce);
            shadow.last_activity = Instant::now();
            // Opening this frame required keys derived from the handshake reply we
            // sent to this address, so it is the same return-routability proof a
            // live session earns above.
            shadow.addr_validated = true;
            let remote_noise_pub = shadow.remote_noise_pub;
            let payload = payload_buf[..len].to_vec();
            let Some(proven) = self.shadow_sessions.remove(&(from, key)) else {
                continue;
            };
            // Proven, so it takes the live slot back — and whatever it displaces
            // becomes a shadow in turn, by the same rule.
            self.install_session(from, proven);
            debug!("Ember transport frame from {from} proved a displaced session; promoting it");
            return IncomingResult::Message {
                from,
                remote_noise_pub,
                payload,
            };
        }
        IncomingResult::Rejected
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

fn fresh_cookie_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    secret
}

/// The retry cookie for `addr` under `secret`.
///
/// Binding the tag to the full source address — not just the IP — is what
/// makes a captured cookie useless anywhere else: echoing it from a
/// different address recomputes a different tag. The address is encoded
/// with a leading version byte so a v4-mapped v6 address cannot be framed
/// to collide with the v4 address it maps.
fn xx_cookie_for(secret: &[u8; 32], addr: SocketAddr) -> [u8; XX_COOKIE_LEN] {
    let mut input = Vec::with_capacity(XX_COOKIE_DOMAIN.len() + 19);
    input.extend_from_slice(XX_COOKIE_DOMAIN);
    match addr.ip() {
        std::net::IpAddr::V4(v4) => {
            input.push(4);
            input.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            input.push(6);
            input.extend_from_slice(&v6.octets());
        }
    }
    input.extend_from_slice(&addr.port().to_be_bytes());

    let tag = blake3::keyed_hash(secret, &input);
    let mut cookie = [0u8; XX_COOKIE_LEN];
    cookie.copy_from_slice(&tag.as_bytes()[..XX_COOKIE_LEN]);
    cookie
}

/// Constant-time comparison of a cookie tag against the bytes a peer echoed.
///
/// A plain `==` on slices returns at the first differing byte. An attacker
/// that can time our reply could walk that timing to recover a tag for an
/// address it cannot receive at, turning a 2^-128 forgery into a 16x256
/// search — which is precisely the return-routability property the cookie
/// exists to enforce.
fn cookie_tags_match(expected: &[u8; XX_COOKIE_LEN], got: &[u8]) -> bool {
    if got.len() != XX_COOKIE_LEN {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(got.iter()) {
        diff |= a ^ b;
    }
    diff == 0
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
        // The embedded payload waits for the address to prove itself; the
        // responder answers with IK message 2 plus the routability probe.
        assert_eq!(decrypted, None);
        assert_eq!(resp_packets.len(), 2);

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

        // Answering the probe proves the address and releases the payload.
        let probe_answer = alice.dispatch_incoming(&resp_packets[1], bob_addr);
        assert_eq!(probe_answer.responses.len(), 1);
        let released = bob.dispatch_incoming(&probe_answer.responses[0], alice_addr);
        assert_eq!(released.app_payloads, vec![msg.to_vec()]);

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

    /// Put `t` in the state a flood puts it in: no budget left to answer an
    /// unproven source with msg2, which is the only condition under which it
    /// asks for a cookie. Set directly rather than by sending 64 real msg1s
    /// so the cookie tests are deterministic and do not race the refill.
    fn exhaust_xx_msg2_budget(t: &mut EmberTransport) {
        t.xx_msg2_tokens = 0;
        t.xx_msg2_refilled_at = Instant::now();
    }

    /// Drive `msg1` through the responder's retry cookie and return the msg1
    /// the responder will actually answer with a handshake. Exhausts the
    /// budget first, since the cookie is not otherwise demanded.
    fn xx_cookie_round_trip(
        initiator: &mut EmberTransport,
        responder: &mut EmberTransport,
        initiator_addr: SocketAddr,
        responder_addr: SocketAddr,
        msg1: &[u8],
    ) -> Vec<u8> {
        exhaust_xx_msg2_budget(responder);
        let cookie = match responder.process_incoming(msg1, initiator_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => packets,
            _ => panic!("expected a retry cookie for an unproven XX msg1"),
        };
        assert_eq!(cookie.len(), 1);
        assert_eq!(cookie[0][2], PKT_XX_COOKIE, "expected a cookie packet");

        match initiator.process_incoming(&cookie[0], responder_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => {
                assert_eq!(packets.len(), 1);
                packets.into_iter().next().expect("retried msg1")
            }
            _ => panic!("expected the initiator to re-send msg1 with the cookie"),
        }
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

    /// A repeated initiation is either a replay or a peer whose copy of our
    /// answer was lost. We cannot tell them apart, so we re-send the answer
    /// we already produced: that unblocks the honest retransmit while giving
    /// a replaying attacker only bytes it already saw. What must not happen
    /// is re-emitting the embedded payload or disturbing the live session.
    #[test]
    fn a_replayed_ik_init_gets_the_cached_answer_and_nothing_else() {
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
        // First copy completes the handshake and defers the embedded payload
        // until the source address proves it can receive.
        let original_response = match bob.process_incoming(&init, alice_addr) {
            IncomingResult::HandshakeComplete {
                decrypted_payload,
                packets_to_send,
                ..
            } => {
                assert_eq!(decrypted_payload, None);
                packets_to_send
            }
            _ => panic!("expected HandshakeComplete"),
        };

        match bob.process_incoming(&init, alice_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => {
                assert_eq!(
                    packets,
                    original_response[..1].to_vec(),
                    "the repeat must get exactly the handshake answer we already sent"
                );
            }
            _ => panic!("expected the cached answer to be re-sent"),
        }

        // The session Bob established on the first copy is untouched, so he
        // can still encrypt to Alice on the fast path.
        assert!(
            matches!(
                bob.prepare_outgoing(alice_addr, Some(&alice_pub), b"after"),
                OutgoingResult::Ready { .. }
            ),
            "the replay must not have disturbed the live session"
        );
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

        // Alice → Bob: XX msg1. Under the msg2 budget, which is where an
        // unattacked node lives, this is answered straight away.
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
                // Deferred until the address proves it can receive; see
                // `an_unvalidated_ik_init_is_never_amplified`.
                assert_eq!(decrypted_payload, None);
                packets_to_send
            }
            _ => panic!("expected HandshakeComplete"),
        };
        assert_eq!(resp_packets.len(), 2);

        match alice.process_incoming(&resp_packets[0], bob_addr) {
            IncomingResult::HandshakeComplete { .. } => {}
            _ => panic!("expected HandshakeComplete"),
        }
        let probe_answer = alice.dispatch_incoming(&resp_packets[1], bob_addr);
        assert_eq!(
            bob.dispatch_incoming(&probe_answer.responses[0], alice_addr)
                .controls,
            vec![EmberControlMessage::Ping { nonce: 1 }],
        );

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

        // The IK responder emits message 2 and the routability probe, and
        // holds the payload back until the probe is answered.
        let handshake = bob.dispatch_incoming(&init, alice_addr);
        assert!(!handshake.rejected);
        assert!(handshake.app_payloads.is_empty());
        assert_eq!(handshake.responses.len(), 2);

        assert!(
            !alice
                .dispatch_incoming(&handshake.responses[0], bob_addr)
                .rejected
        );
        let probe_answer = alice.dispatch_incoming(&handshake.responses[1], bob_addr);
        assert_eq!(probe_answer.responses.len(), 1, "the probe must be answered");

        let outcome = bob.dispatch_incoming(&probe_answer.responses[0], alice_addr);
        assert!(!outcome.rejected);
        assert!(
            outcome.controls.is_empty(),
            "payload is not a control frame"
        );
        assert_eq!(outcome.app_payloads, vec![dht_like]);
        assert_eq!(
            outcome.remote_noise_pub,
            Some(alice_pub),
            "app payload must carry the peer's Noise key for the reply path"
        );
    }

    /// The cached answer belongs to the peer that asked for it. Replaying a
    /// captured initiation from somewhere else must not turn us into a free
    /// reflector aimed at whatever address the attacker spoofed.
    #[test]
    fn a_cached_handshake_answer_only_goes_back_to_its_sender() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let victim_addr: SocketAddr = "9.9.9.9:9999".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        let init = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), b"req") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            _ => panic!("expected HandshakeStarted"),
        };
        assert!(matches!(
            bob.process_incoming(&init, alice_addr),
            IncomingResult::HandshakeComplete { .. }
        ));

        // Same bytes, spoofed source: no answer, so nothing is reflected.
        assert!(matches!(
            bob.process_incoming(&init, victim_addr),
            IncomingResult::Rejected
        ));

        // The genuine sender still gets its answer re-sent.
        assert!(matches!(
            bob.process_incoming(&init, alice_addr),
            IncomingResult::HandshakeResponse { .. }
        ));
    }

    /// Noise_IK message 1 proves who signed it, never where they are: the
    /// pattern is 1-RTT and every node publishes its static key in FOUND_NODE
    /// contact lists, so an off-path attacker can drive a whole handshake
    /// from a forged source address. Acting on the embedded payload is what
    /// made that profitable — an embedded FIND_NODE reflected ~1.4 KB at the
    /// forged address for a ~235-byte packet, and an embedded STORE_RECORD
    /// walked through the DHT's `from.ip()` anti-reflection bind unchallenged.
    #[test]
    fn an_unvalidated_ik_init_is_never_amplified() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        // The address the attacker forged. Nothing proves anyone listens here.
        let victim_addr: SocketAddr = "9.9.9.9:9999".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        // A DHT-shaped request embedded in message 1, as a FIND_NODE would be.
        let query = vec![0x01u8; 136];
        let init = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), &query) {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };

        let outcome = bob.dispatch_incoming(&init, victim_addr);
        assert!(!outcome.rejected);
        assert!(
            outcome.app_payloads.is_empty(),
            "the embedded request must not reach the DHT until the address is proven"
        );
        assert!(outcome.controls.is_empty());
        let sent: usize = outcome.responses.iter().map(|p| p.len()).sum();
        assert!(
            sent <= init.len(),
            "forging a source address must never buy more bytes than it costs: \
             {sent} sent for {} received",
            init.len()
        );
    }

    /// Build `count` XX msg1 packets that are distinct on the wire, the way a
    /// flood is: each aimed at a different address so it carries its own
    /// ephemeral, so none of them collide in the handshake replay cache.
    fn distinct_xx_msg1s(initiator: &mut EmberTransport, count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|i| {
                let target: SocketAddr = format!("5.6.7.8:{}", 2000 + i).parse().unwrap();
                match initiator.prepare_outgoing(target, None, b"find node") {
                    OutgoingResult::HandshakeStarted { packet } => packet,
                    other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
                }
            })
            .collect()
    }

    /// The steady state, and the interop guarantee behind making the cookie
    /// adaptive: a node that is not being flooded answers XX msg1 with msg2
    /// exactly as it always has. Deployed peers do not know `PKT_XX_COOKIE`
    /// and would never echo one, so first contact has to keep working with no
    /// extra round trip and no new packet type on the wire.
    #[test]
    fn an_xx_msg1_is_answered_directly_in_the_steady_state() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        let msg1 = match alice.prepare_outgoing(bob_addr, None, b"hi") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        match bob.process_incoming(&msg1, alice_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => {
                assert_eq!(packets.len(), 1);
                assert_eq!(
                    packets[0][2], PKT_XX_MSG2,
                    "an unattacked responder must not cost an existing peer a round trip"
                );
            }
            _ => panic!("expected msg2"),
        }
    }

    /// Noise XX message 1 is 32 bytes of ephemeral key with no state and no
    /// proof of anything behind it, and msg2 answers it with our encrypted
    /// static key: 99 bytes out for 35 in, a 2.83x reflector pointed at
    /// whatever source address the sender wrote down. Nothing dedupes the
    /// flood, since every distinct ephemeral hashes to a fresh digest.
    ///
    /// What bounds it is the budget rather than the ratio: honest peers keep
    /// the cheap path, and once a flood has spent the budget every further
    /// msg1 earns a cookie instead — so the reflected volume stops growing no
    /// matter how hard the attacker pushes.
    #[test]
    fn an_xx_msg1_flood_falls_back_to_cookies_once_the_budget_is_spent() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        // The address the attacker forged. Nothing proves anyone listens here.
        let victim_addr: SocketAddr = "9.9.9.9:9999".parse().unwrap();

        // A small budget stands in for the real one so the test cannot race
        // the refill; the behaviour under test is the same at any size.
        const BUDGET: usize = 2;
        bob.xx_msg2_tokens = BUDGET as u32;
        bob.xx_msg2_refilled_at = Instant::now();

        let flood = distinct_xx_msg1s(&mut alice, BUDGET + 3);
        let mut answers = Vec::new();
        let mut state_at_budget = None;
        for (i, msg1) in flood.iter().enumerate() {
            let outcome = bob.dispatch_incoming(msg1, victim_addr);
            assert!(!outcome.rejected);
            assert_eq!(outcome.responses.len(), 1);
            answers.push(outcome.responses[0].clone());
            if i + 1 == BUDGET {
                state_at_budget = Some((bob.pending.len(), bob.recent_handshakes.len()));
            }
        }

        // The budget buys msg2 and nothing past it does.
        for (i, (msg1, answer)) in flood.iter().zip(&answers).enumerate() {
            if i < BUDGET {
                assert_eq!(answer[2], PKT_XX_MSG2, "packet {i} is inside the budget");
                assert_eq!((msg1.len(), answer.len()), (35, 99), "the 2.83x we cap");
            } else {
                assert_eq!(answer[2], PKT_XX_COOKIE, "packet {i} is past the budget");
                // 19 bytes against 35, 0.54x: the retry cannot be turned into
                // an amplifier of its own, so the flood has nothing to escalate
                // to and is strictly worse off than attacking the victim direct.
                assert_eq!((msg1.len(), answer.len()), (35, HEADER_LEN + XX_COOKIE_LEN));
                assert!(answer.len() <= msg1.len());
            }
        }

        // The cookie is stateless, so the flood cannot be traded from an
        // amplification vector into a memory-exhaustion one: nothing past the
        // budget took a handshake slot or reached the replay cache, so it can
        // neither be grown without bound nor crowd out a genuine handshake.
        assert_eq!(
            (bob.pending.len(), bob.recent_handshakes.len()),
            state_at_budget.expect("budget boundary observed"),
            "a msg1 answered with a cookie must leave nothing behind"
        );
        assert!(bob.sessions.is_empty());
    }

    /// The cached msg2 is charged like a fresh one. It is the same 99 bytes to
    /// the same unproven address, and it is the cheapest form of the flood
    /// because replaying one captured msg1 costs the attacker no crypto at
    /// all — so leaving it uncharged would have let a single packet re-emit
    /// msg2 without limit for the whole replay TTL.
    #[test]
    fn a_replayed_xx_msg1_cannot_re_emit_the_cached_msg2_for_free() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let victim_addr: SocketAddr = "9.9.9.9:9999".parse().unwrap();

        bob.xx_msg2_tokens = 2;
        bob.xx_msg2_refilled_at = Instant::now();
        let msg1 = distinct_xx_msg1s(&mut alice, 1).remove(0);

        // Fresh: the handshake path answers and caches the msg2.
        let first = bob.dispatch_incoming(&msg1, victim_addr);
        assert_eq!(first.responses[0][2], PKT_XX_MSG2);

        // Replayed: the cache answers, and that spends the last token.
        let second = bob.dispatch_incoming(&msg1, victim_addr);
        assert_eq!(second.responses[0][2], PKT_XX_MSG2);
        assert_eq!(second.responses[0], first.responses[0]);

        // Replayed again with the budget gone: a cookie, not another msg2.
        let third = bob.dispatch_incoming(&msg1, victim_addr);
        assert_eq!(
            third.responses[0][2], PKT_XX_COOKIE,
            "the cached msg2 must not outlive the budget"
        );
    }

    /// One unauthenticated packet must not be able to end a handshake that is
    /// in flight. `handle_xx_msg2` used to take the pending state out of the
    /// map before reading the message, so a forged msg2 — anything of the
    /// right type from an address we happen to be dialling — discarded the
    /// state the genuine msg2 needed, and XX first contact simply never
    /// completed. Spraying spoofed msg2s from known peer addresses needs no
    /// secret and no guess, so with a deployed population it is a live denial
    /// of service on first contact, not a theoretical one.
    #[test]
    fn a_spoofed_xx_msg2_does_not_strand_the_handshake() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        let msg1 = match alice.prepare_outgoing(bob_addr, None, b"hi") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        let msg2 = match bob.process_incoming(&msg1, alice_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => {
                packets.into_iter().next().expect("msg2")
            }
            _ => panic!("expected msg2"),
        };

        // The attacker cannot forge a msg2 that verifies — that needs the
        // ephemeral shared secret — so all it can do is send a well-formed
        // packet of the right type and hope the failure is destructive. Break
        // it at both points it can fail: inside the encrypted static key,
        // which is where a real off-path forgery dies, and on the trailing
        // payload tag, which fails only after snow has mixed three tokens'
        // worth of state and so is the harder thing to recover from.
        for corrupt in [HEADER_LEN + 36, msg2.len() - 1] {
            let mut forged = msg2.clone();
            forged[corrupt] ^= 0xff;
            assert!(
                matches!(
                    alice.process_incoming(&forged, bob_addr),
                    IncomingResult::Rejected
                ),
                "a msg2 that does not authenticate must be rejected"
            );
            assert!(
                alice.pending.contains_key(&bob_addr),
                "the in-flight handshake must survive a packet that proved nothing \
                 (corrupted at byte {corrupt})"
            );
        }

        // And the genuine msg2 still completes: snow rolls its symmetric state
        // back on a failed read, so the forgery left no residue.
        let msg3 = match alice.process_incoming(&msg2, bob_addr) {
            IncomingResult::HandshakeComplete {
                packets_to_send, ..
            } => packets_to_send,
            _ => panic!("the genuine msg2 must still complete the handshake"),
        };
        assert!(!msg3.is_empty());
        match bob.process_incoming(&msg3[0], alice_addr) {
            IncomingResult::HandshakeComplete { .. } => {}
            _ => panic!("expected the responder to complete on msg3"),
        }
    }

    /// "Newest unproven claimant wins" is what keeps a spoofed session from
    /// locking the address owner out, but on its own it also let a spoofer
    /// *repeatedly* displace a real peer's session: one initiation every few tens
    /// of milliseconds — inside the per-IP packet cap — meant the peer's own probe
    /// answer never had a session to decrypt against, so its first contact never
    /// completed and nothing tore the squatter down. The displaced session is now
    /// kept until one of its own frames proves it.
    #[test]
    fn a_sustained_spoof_cannot_keep_the_address_owner_from_completing() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        // Alice reaches Bob for the first time. Bob installs an unvalidated
        // session and probes her address.
        let alice_init = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), b"genuine") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        let to_alice = match bob.process_incoming(&alice_init, alice_addr) {
            IncomingResult::HandshakeComplete {
                packets_to_send, ..
            } => packets_to_send,
            _ => panic!("expected Bob to complete the IK handshake"),
        };

        // A spoofer now claims Alice's address repeatedly, minting a fresh static
        // key each time — free, and the churn is what made a single displaced slot
        // insufficient. Each initiation takes the live slot, which is what stops
        // *it* from being locked out in turn, so Alice's session has to survive
        // somewhere.
        //
        // Deliberately far past `MAX_SHADOW_SESSIONS_PER_ADDR` and
        // `MAX_DEFERRED_IK_PAYLOADS_PER_ADDR`: the point is that the bound sheds
        // the *newest* claimant at this address, so no amount of churn pushes out
        // the session and the deferred request Alice arrived with first. Each of
        // these initiations carries a payload of its own, so both caches are under
        // pressure.
        for _ in 0..(MAX_SHADOW_SESSIONS_PER_ADDR.max(MAX_DEFERRED_IK_PAYLOADS_PER_ADDR) * 4) {
            let (squatter_priv, squatter_pub) = make_keypair();
            let mut squatter = EmberTransport::new(squatter_priv, squatter_pub);
            let squat = match squatter.prepare_outgoing(bob_addr, Some(&bob_pub), b"squat") {
                OutgoingResult::HandshakeStarted { packet } => packet,
                other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
            };
            assert!(matches!(
                bob.process_incoming(&squat, alice_addr),
                IncomingResult::HandshakeComplete { .. }
            ));
        }

        // Alice answers Bob's probe. It has to reach Bob even though the live slot
        // now belongs to Mallory, and answering is what proves Alice holds the
        // address.
        let mut probe_answer = None;
        for packet in &to_alice {
            let out = alice.dispatch_incoming(packet, bob_addr);
            assert!(!out.rejected, "Alice must accept Bob's own handshake reply");
            if let Some(response) = out.responses.into_iter().next() {
                probe_answer = Some(response);
            }
        }
        let probe_answer = probe_answer.expect("Alice answers the return-routability probe");

        let released = bob.dispatch_incoming(&probe_answer, alice_addr);
        assert!(
            !released.rejected,
            "a spoof flood must not stop the address owner completing first contact"
        );
        assert_eq!(
            released.app_payloads,
            vec![b"genuine".to_vec()],
            "and her queued request must be released"
        );
    }

    /// A cookie packet cannot be authenticated — nothing is keyed at msg1 — so
    /// acting on one must not be able to throw away the handshake we already
    /// sent. It used to: the retry overwrote the parked state, so a single forged
    /// 19-byte packet from an address we were dialling stranded the attempt, and
    /// the genuine msg2 then verified against nothing. The retry now keeps the
    /// handshake it replaces, and either may complete.
    #[test]
    fn a_spoofed_xx_cookie_does_not_strand_the_handshake() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        let msg1 = match alice.prepare_outgoing(bob_addr, None, b"hi") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        // Bob answers msg1 directly: he is nowhere near his budget, so no cookie
        // is legitimately in play at all.
        let msg2 = match bob.process_incoming(&msg1, alice_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => {
                packets.into_iter().next().expect("msg2")
            }
            _ => panic!("expected msg2"),
        };

        // A forged cookie needs no secret: the right packet type and length from
        // an address we are dialling. It buys the attacker one retry msg1 and
        // must cost us nothing.
        let mut forged = Vec::with_capacity(HEADER_LEN + XX_COOKIE_LEN);
        forged.extend_from_slice(&[EMBER_MAGIC[0], EMBER_MAGIC[1], PKT_XX_COOKIE]);
        forged.extend_from_slice(&[0xAB; XX_COOKIE_LEN]);
        match alice.process_incoming(&forged, bob_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => {
                assert_eq!(packets[0][2], PKT_XX_MSG1, "the retry is an ordinary msg1");
            }
            _ => panic!("expected the cookie retry"),
        }
        assert!(
            alice.pending.contains_key(&bob_addr),
            "the handshake must still be in flight"
        );

        // Bob's real msg2 answers the *original* msg1, which the retry replaced.
        // It has to complete anyway.
        let msg3 = match alice.process_incoming(&msg2, bob_addr) {
            IncomingResult::HandshakeComplete {
                packets_to_send, ..
            } => packets_to_send,
            _ => panic!("the genuine msg2 must still complete the handshake"),
        };
        assert!(!msg3.is_empty());
        match bob.process_incoming(&msg3[0], alice_addr) {
            IncomingResult::HandshakeComplete { .. } => {}
            _ => panic!("expected the responder to complete on msg3"),
        }

        // And the retry is still one-shot: a second forged cookie earns nothing.
        let mut alice2 = EmberTransport::new(make_keypair().0, alice_pub);
        let _ = alice2.prepare_outgoing(bob_addr, None, b"hi");
        assert!(matches!(
            alice2.process_incoming(&forged, bob_addr),
            IncomingResult::HandshakeResponse { .. }
        ));
        assert!(
            matches!(
                alice2.process_incoming(&forged, bob_addr),
                IncomingResult::Rejected
            ),
            "a handshake gets one cookie retry, not one per forged packet"
        );
    }

    /// The cookie is a keyed tag over the source address, so capturing one
    /// off the wire buys nothing anywhere else — which is the whole point:
    /// echoing it is the proof that the sender receives where it claims to.
    #[test]
    fn an_xx_cookie_is_bound_to_the_address_it_was_issued_to() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let victim_addr: SocketAddr = "9.9.9.9:9999".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        let msg1 = match alice.prepare_outgoing(bob_addr, None, b"hi") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        let retried = xx_cookie_round_trip(&mut alice, &mut bob, alice_addr, bob_addr, &msg1);

        // Replayed from anywhere else, the tag simply does not verify, so the
        // forged address earns another 19-byte cookie rather than a 99-byte
        // msg2. Checked before the honest case so the replay cache cannot be
        // what answers.
        match bob.process_incoming(&retried, victim_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => {
                assert_eq!(packets.len(), 1);
                assert_eq!(
                    packets[0][2], PKT_XX_COOKIE,
                    "a captured cookie must not buy a handshake from another address"
                );
            }
            _ => panic!("expected a fresh cookie"),
        }

        // The address it was issued to is served normally.
        match bob.process_incoming(&retried, alice_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => {
                assert_eq!(packets[0][2], PKT_XX_MSG2);
            }
            _ => panic!("the address the cookie was issued to must be served"),
        }
    }

    /// The secret rotates, so a cookie has a lifetime: one rotation of grace
    /// (a cookie in flight across a boundary must not strand an honest peer),
    /// and nothing beyond that — by then the address may have changed hands.
    #[test]
    fn an_xx_cookie_expires_with_its_secret() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        let msg1 = match alice.prepare_outgoing(bob_addr, None, b"hi") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        let retried = xx_cookie_round_trip(&mut alice, &mut bob, alice_addr, bob_addr, &msg1);

        // One interval on: the next packet demotes the minting secret to
        // `prev`, where it still verifies.
        bob.cookie_rotated_at = Instant::now()
            .checked_sub(XX_COOKIE_ROTATION)
            .expect("test clock");
        match bob.process_incoming(&retried, alice_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => {
                assert_eq!(packets[0][2], PKT_XX_MSG2, "one rotation of grace");
            }
            _ => panic!("a cookie one rotation old must still be honoured"),
        }

        // Past both secrets, it buys a fresh cookie and nothing more. The
        // cookie check runs ahead of the replay cache, so the msg2 cached
        // above is not what answers here.
        bob.cookie_rotated_at = Instant::now()
            .checked_sub(XX_COOKIE_ROTATION * 3)
            .expect("test clock");
        // An expired cookie is no cookie, so this only demands one while the
        // budget is still spent; the msg2 served above refunded nothing but
        // real time has passed since.
        exhaust_xx_msg2_budget(&mut bob);
        match bob.process_incoming(&retried, alice_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => {
                assert_eq!(
                    packets[0][2], PKT_XX_COOKIE,
                    "an expired cookie must earn a fresh one, not a handshake"
                );
            }
            _ => panic!("expected a fresh cookie"),
        }
    }

    /// Alice sends a second request before our return-routability probe can
    /// reach her: `handle_ik_resp` flushes it the instant IK_RESP is read, so
    /// that request — not the probe's `Pong` — is the first frame proving her
    /// address. Releasing the deferred payload only on the `Pong` therefore
    /// dropped the request embedded in IK_INIT. A DHT search retries once and
    /// papers over it; a one-shot `STORE_RECORD`, `ANNOUNCE_PEER` or
    /// `ExchangeRequest` sent as a first message has no retry layer at all
    /// and was simply lost. This is deterministic, not a race.
    #[test]
    fn two_requests_inside_one_round_trip_are_both_delivered() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        // DHT-shaped, so both surface as app payloads rather than control.
        let first = vec![0xA1u8; 96];
        let second = vec![0xB2u8; 96];

        let init = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), &first) {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        assert!(
            matches!(
                alice.prepare_outgoing(bob_addr, Some(&bob_pub), &second),
                OutgoingResult::Queued
            ),
            "the second request rides behind the in-flight handshake"
        );

        let handshake = bob.dispatch_incoming(&init, alice_addr);
        assert_eq!(handshake.responses.len(), 2, "IK_RESP plus the probe");

        // Alice reads IK_RESP and flushes the queued request at once —
        // before she has so much as seen the probe.
        let flushed = alice.dispatch_incoming(&handshake.responses[0], bob_addr);
        assert_eq!(
            flushed.responses.len(),
            1,
            "the queued request goes out now"
        );

        let delivered = bob.dispatch_incoming(&flushed.responses[0], alice_addr);
        assert_eq!(
            delivered.app_payloads,
            vec![first, second],
            "both requests must arrive, in the order Alice sent them"
        );
        assert_eq!(delivered.remote_noise_pub, Some(alice_pub));

        // The probe's answer still lands afterwards, and is still ours to
        // swallow rather than hand back as an unsolicited reply.
        let probe_answer = alice.dispatch_incoming(&handshake.responses[1], bob_addr);
        assert_eq!(probe_answer.responses.len(), 1);
        let after_probe = bob.dispatch_incoming(&probe_answer.responses[0], alice_addr);
        assert!(after_probe.controls.is_empty());
        assert!(after_probe.app_payloads.is_empty());

        // Released exactly once: no later frame resurrects it.
        let third = seal_ready(&mut alice, bob_addr, &[0xC3u8; 96]);
        assert_eq!(
            bob.dispatch_incoming(&third, alice_addr).app_payloads.len(),
            1
        );
    }

    /// A session installed from a forged source address has proven nothing,
    /// so it must not outrank the address's real owner. It used to: the
    /// takeover guard rejected every later IK_INIT whose static key differed,
    /// locking the victim out for the whole session lifetime — refreshable by
    /// the attacker with one packet, and unrecoverable because decrypt
    /// failures deliberately never tear a session down.
    #[test]
    fn an_unvalidated_session_never_locks_out_the_address_owner() {
        let (alice_priv, alice_pub) = make_keypair();
        let (mallory_priv, mallory_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut mallory = EmberTransport::new(mallory_priv, mallory_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        // Mallory completes an IK handshake with Bob while claiming Alice's
        // address. Bob installs the session; nothing has validated it.
        let squat = match mallory.prepare_outgoing(bob_addr, Some(&bob_pub), b"squat") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        assert!(matches!(
            bob.process_incoming(&squat, alice_addr),
            IncomingResult::HandshakeComplete { .. }
        ));

        // Alice, who actually holds the address, must still get in.
        let genuine = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), b"genuine") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        let responses = match bob.process_incoming(&genuine, alice_addr) {
            IncomingResult::HandshakeComplete {
                packets_to_send, ..
            } => packets_to_send,
            _ => panic!("an unproven squatter must not lock the address owner out"),
        };

        // Answering the probe proves the address and releases Alice's request
        // — Mallory's deferred payload is discarded with her session.
        assert!(!alice.dispatch_incoming(&responses[0], bob_addr).rejected);
        let probe_answer = alice.dispatch_incoming(&responses[1], bob_addr);
        let released = bob.dispatch_incoming(&probe_answer.responses[0], alice_addr);
        assert_eq!(released.app_payloads, vec![b"genuine".to_vec()]);

        // Now that the session is proven, the takeover guard does its job.
        mallory.remove_session(&bob_addr);
        let squat_again = match mallory.prepare_outgoing(bob_addr, Some(&bob_pub), b"squat again") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        assert!(
            matches!(
                bob.process_incoming(&squat_again, alice_addr),
                IncomingResult::Rejected
            ),
            "a validated session is exactly what the takeover guard exists to protect"
        );
    }

    /// The other half of the lockout: an unproven session squatting a peer's
    /// address must not capture the traffic we send to that peer, or the real
    /// peer receives frames it cannot decrypt and we never notice.
    #[test]
    fn dialling_a_peer_discards_an_unvalidated_session_for_another_identity() {
        let (_alice_priv, alice_pub) = make_keypair();
        let (mallory_priv, mallory_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let mut mallory = EmberTransport::new(mallory_priv, mallory_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        let squat = match mallory.prepare_outgoing(bob_addr, Some(&bob_pub), b"squat") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        assert!(matches!(
            bob.process_incoming(&squat, alice_addr),
            IncomingResult::HandshakeComplete { .. }
        ));

        // Talking to the identity the session actually belongs to is fine.
        assert!(matches!(
            bob.prepare_outgoing(alice_addr, Some(&mallory_pub), b"for mallory"),
            OutgoingResult::Ready { .. }
        ));
        // Talking to a different identity at that address is not.
        assert!(
            matches!(
                bob.prepare_outgoing(alice_addr, Some(&alice_pub), b"for alice"),
                OutgoingResult::HandshakeStarted { .. }
            ),
            "an unproven session must not intercept traffic meant for another peer"
        );
    }

    /// The header is stripped before dispatch, so hashing the body alone put
    /// IK and XX initiations in one namespace — and snow accepts an over-long
    /// XX msg1, so a captured IK init could be re-sent tagged as XX to seed
    /// the entry with the wrong answer and stall the real handshake.
    #[test]
    fn handshake_replay_entries_are_scoped_to_their_packet_type() {
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

        // The same body re-tagged as an XX msg1, as an on-path attacker would
        // send it, seeding an entry whose cached answer is the wrong type.
        let mut masquerade = init.clone();
        masquerade[2] = PKT_XX_MSG1;
        let _ = bob.process_incoming(&masquerade, alice_addr);

        // The genuine IK init must still be processed on its own terms.
        assert!(
            matches!(
                bob.process_incoming(&init, alice_addr),
                IncomingResult::HandshakeComplete { .. }
            ),
            "an XX-tagged copy must not poison the IK entry"
        );
    }

    /// Control frames and DHT frames share the decrypted byte stream, and the
    /// control decoder gets first refusal, so no signed DHT frame may ever
    /// parse as a control message. When it did, the aliased message type was
    /// swallowed whole and its lookups stalled with no error anywhere.
    #[test]
    fn control_frames_never_alias_dht_frames() {
        use crate::network::ember::dht::messages;

        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let node_id = crate::network::ember::dht::EmberNodeId([0x11; 16]);

        let observed: SocketAddr = "9.9.9.9:4672".parse().unwrap();
        let frames = vec![
            messages::build_ping(node_id, 1),
            messages::build_pong(node_id, 2, observed),
            messages::build_find_node(node_id, 3, node_id),
            messages::build_found_node(node_id, 4, vec![]),
            messages::build_find_value(node_id, 5, vec![[0x22; 16]]),
            messages::build_store_record(node_id, 6, [0x33; 16], vec![0u8; 32], [0u8; 64]),
            messages::build_store_ack(node_id, 7, [0x44; 16]),
            messages::build_found_value(node_id, 8, [0x55; 16], vec![vec![0u8; 32]]),
            messages::build_announce_peer(node_id, 9, vec![]),
            messages::build_peer_list(node_id, 10, vec![]),
            messages::build_proxy_store(node_id, 11, [0x66; 16], vec![0u8; 32], [0u8; 64]),
            messages::build_proxy_store_ack(node_id, 12, [0x77; 16]),
            messages::build_store_batch(
                node_id,
                13,
                vec![messages::BatchedRecord {
                    key: [0x88; 16],
                    record: vec![0u8; 32],
                    record_signature: [0u8; 64],
                }],
            ),
            messages::build_store_batch_ack(node_id, 14, 0b1),
        ];

        for msg in frames {
            let msg_type = msg.msg_type;
            let encoded = messages::encode_message(&msg, &signing, true);
            assert!(
                EmberControlMessage::decode(&encoded).is_none(),
                "DHT message type {msg_type:#04x} must not decode as a control frame"
            );
        }
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
        assert_eq!(
            EmberControlMessage::ExchangeRequest.encode(),
            vec![CONTROL_VERSION, CONTROL_KIND_EXCHANGE_REQUEST]
        );
    }

    #[test]
    fn control_message_decode_rejects_malformed() {
        const V: u8 = CONTROL_VERSION;
        // Wrong version.
        assert_eq!(
            EmberControlMessage::decode(&[V ^ 0xFF, 1, 0, 0, 0, 0, 0, 0, 0, 0]),
            None
        );
        // Ping/Pong with wrong length.
        assert_eq!(EmberControlMessage::decode(&[V, 1, 0, 0]), None);
        // ExchangeRequest must have no trailing bytes.
        assert_eq!(EmberControlMessage::decode(&[V, 3, 0xFF]), None);
        // Unknown kind.
        assert_eq!(EmberControlMessage::decode(&[V, 0x7F]), None);
        // Too short to carry version + kind.
        assert_eq!(EmberControlMessage::decode(&[V]), None);
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

        // Alice completes the handshake and answers the routability probe;
        // only then does Bob act on the request, and even then dispatch must
        // NOT auto-respond to it.
        let bob_outcome = bob.dispatch_incoming(&init, alice_addr);
        assert!(!bob_outcome.rejected);
        assert!(bob_outcome.controls.is_empty(), "the request is deferred");
        assert_eq!(
            bob_outcome.responses.len(),
            2,
            "the IK handshake response and the routability probe, nothing else"
        );

        let _ = alice.dispatch_incoming(&bob_outcome.responses[0], bob_addr);
        let probe_answer = alice.dispatch_incoming(&bob_outcome.responses[1], bob_addr);
        let bob_outcome = bob.dispatch_incoming(&probe_answer.responses[0], alice_addr);
        assert_eq!(
            bob_outcome.controls,
            vec![EmberControlMessage::ExchangeRequest]
        );
        assert!(
            bob_outcome.responses.is_empty(),
            "no auto-answer to the exchange request"
        );
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
            alice_outcome.controls,
            vec![EmberControlMessage::ExchangeData { payload }]
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

        // Alice → Bob: XX msg1 (no remote pubkey known yet).
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
        assert_eq!(resp.len(), 2, "IK message 2 plus the routability probe");
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
    /// 2. The responder defers that payload and probes the source
    ///    address, and once the initiator answers the probe, extracts
    ///    the Ping AND encodes the matching Pong on the established
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
        //   - no control yet: the payload waits on return-routability
        //   - two responses: Noise IK msg 2 + the routability probe
        let mut buf = vec![0u8; 65535];
        let (len, from) = sock_b.recv_from(&mut buf).await.unwrap();
        assert_eq!(from, addr_a);

        let outcome_b = transport_b.dispatch_incoming(&buf[..len], from);
        assert!(!outcome_b.rejected, "B rejected the init packet");
        assert!(
            outcome_b.controls.is_empty(),
            "B should hold the Ping until A proves it receives at this address",
        );
        assert_eq!(
            outcome_b.responses.len(),
            2,
            "B should send back IK msg 2 + the routability probe, got {} packet(s)",
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
        assert!(outcome_a_handshake.controls.is_empty());
        assert!(
            outcome_a_handshake.responses.is_empty(),
            "A should not send anything in response to msg 2"
        );

        // ── Step 4: A answers B's probe, which is what proves the
        //           address and releases A's own Ping on B's side. ──
        let (len, _) = sock_a.recv_from(&mut buf).await.unwrap();
        let outcome_a_probe = transport_a.dispatch_incoming(&buf[..len], addr_b);
        assert!(!outcome_a_probe.rejected);
        assert_eq!(
            outcome_a_probe.responses.len(),
            1,
            "A auto-answers the probe Ping"
        );
        sock_a
            .send_to(&outcome_a_probe.responses[0], addr_b)
            .await
            .unwrap();

        let (len, from) = sock_b.recv_from(&mut buf).await.unwrap();
        let outcome_b_released = transport_b.dispatch_incoming(&buf[..len], from);
        assert_eq!(
            outcome_b_released.controls,
            vec![EmberControlMessage::Ping { nonce }],
            "B should now decode the Ping payload it deferred",
        );
        assert_eq!(
            outcome_b_released.responses.len(),
            1,
            "B answers the released Ping with a Pong"
        );
        sock_b
            .send_to(&outcome_b_released.responses[0], from)
            .await
            .unwrap();

        // ── Step 5: A receives the Pong on the established session. ──
        let (len, _) = sock_a.recv_from(&mut buf).await.unwrap();
        let outcome_a_pong = transport_a.dispatch_incoming(&buf[..len], addr_b);
        assert!(!outcome_a_pong.rejected);
        assert_eq!(
            outcome_a_pong.controls,
            vec![EmberControlMessage::Pong { nonce }],
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
