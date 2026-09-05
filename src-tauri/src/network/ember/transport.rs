use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::RngCore;
use tracing::{debug, trace, warn};
use zeroize::Zeroize;

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
///
/// Has to outlive the DHT's liveness-ping interval (`CONTACT_TIMEOUT_SECS`, 600 s),
/// and did not: at 300 s every scheduled ping was *guaranteed* to find its session
/// already evicted and pay a fresh handshake. That is two round trips and five
/// datagrams where one and two would do, and it lands on far more than pings —
/// every hop past the first in any lookup is a first contact, so the same tax was
/// on the critical path of essentially every search.
///
/// 900 s leaves the ping comfortably inside the window with room for a late tick.
/// Erring long is cheap: an idle session costs a little memory against a bounded
/// `MAX_SESSIONS` with LRU eviction, and if the peer's NAT mapping has lapsed the
/// cost is one timed-out query before we re-handshake — while the ping that keeps
/// the session alive refreshes that mapping anyway.
const SESSION_TIMEOUT: Duration = Duration::from_secs(900);

// Enforced rather than merely documented: the ordering is the whole point, and
// the two constants live in different modules where nothing would otherwise
// notice one of them moving.
const _: () = assert!(
    SESSION_TIMEOUT.as_secs() > super::dht::CONTACT_TIMEOUT_SECS as u64,
    "a session must outlive the liveness ping interval, or every ping re-handshakes"
);

/// Maximum concurrent sessions before we start evicting oldest.
const MAX_SESSIONS: usize = 4096;
/// Ceiling on handshakes held aside pending proof they can decrypt.
///
/// Reaching this needs a completed handshake per entry against a slot that
/// already holds a validated session, so it is not a spoofed-source surface —
/// but it is driven by remote input, so it gets a bound and a TTL like every
/// other table here. Far smaller than [`MAX_SESSIONS`] because a staged entry
/// is transient by construction.
const MAX_STAGED_SESSIONS: usize = 256;

/// How long an inbound XX handshake may hold our outbound traffic for a peer we
/// can name before we stop waiting and dial that identity ourselves.
///
/// A responder-side pending is created by an XX msg1, which is unauthenticated,
/// so an off-path attacker can mint one by forging a peer's source address.
/// Queuing behind it indefinitely is what made that worth doing: every caller
/// treats `Queued` as sent, so one forged packet per pending sweep silently
/// swallowed everything we sent that peer until its contact was faulted out of
/// the routing table.
///
/// A grace window rather than superseding immediately, because the honest race
/// is real: a peer opening XX with us exactly as we go to dial it completes one
/// round trip after our msg2, well inside this, and queuing is the behaviour
/// that delivers both sides' first message. Past it the handshake is not
/// progressing, and dialling costs the attacker its hold — once our own
/// `IkInitiator` is pending, `handle_xx_msg1` refuses further inbound msg1s from
/// that address, so the stall cannot be renewed.
const XX_RESPONDER_QUEUE_GRACE: Duration = Duration::from_secs(3);

/// Outgoing payloads one address may park behind an in-progress handshake.
///
/// If the handshake stalls, the oldest is dropped rather than letting the queue
/// grow without bound — these are best-effort app messages, so shedding the
/// stalest is acceptable back-pressure. Module-scope because a handshake that
/// supersedes another inherits its queue and has to apply the same ceiling.
const MAX_QUEUED_PER_HANDSHAKE: usize = 64;

/// How many concurrent sessions one source address may hold. Each is keyed
/// on `(address, static key)`, so claimants coexist instead of ranking for a
/// single live slot. Four matches the old 1-live-plus-3-shadow budget.
const MAX_SESSIONS_PER_ADDR: usize = 4;

/// Retry cookies one XX attempt will act on. See
/// `PendingHandshake::XxInitiatorMsg1::cookie_retries` for why this is two.
const MAX_XX_COOKIE_RETRIES: u8 = 2;

/// How long after sending to an address a reply from it might still be arriving
/// through the NAT mapping that send opened.
///
/// Comfortably past the usual UDP mapping lifetime of 30 s to a few minutes, since
/// erring long only makes the reachability rule more cautious.
const DIAL_MEMORY: Duration = Duration::from_secs(600);
/// Cap on remembered addresses, evicting the oldest. Ten minutes of Ember dialling
/// is far below this; it exists so the map cannot grow without bound.
const MAX_DIALLED_ADDRS: usize = 4096;

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

/// Sustained ceiling on inbound IK initiations we will run Noise for, in
/// packets per second, plus the burst allowed above it.
///
/// IK answers are already de-amplifying and withhold the embedded payload
/// until the address proves routable, so what is rationed here is not
/// reflected bytes but our own CPU: every initiation with a fresh ephemeral
/// costs a responder build and an X25519 exchange, and none of it is deduped,
/// because a new ephemeral is a new replay digest. An IK init needs no
/// return-routability, so the source address can be spoofed and the work
/// bought for the price of a datagram.
///
/// Far looser than the XX budget above, because this is the *primary* path —
/// every peer that knows our static key arrives on it — where XX is the
/// fallback taken only when the key is unknown. Sixty-four a second is orders
/// of magnitude above real first-contact rates (a few dozen a *minute* on a
/// busy node, mostly sessions re-forming after an idle timeout) and still
/// bounds the flood case to a few milliseconds of CPU per second. The burst
/// covers the one legitimate spike there is: coming online and being dialled
/// by everyone who already held our contact.
///
/// Unlike the XX budget, a token is spent on every initiation we look at,
/// including one that turns out to be malformed. That is deliberate but it is
/// not free: the work being rationed *is* the read that decides whether the
/// packet was genuine, so there is no point at which we know it was junk and
/// have not already paid. The cost is that a flood of garbage can empty the
/// bucket and leave honest first contact to retry — the usual bargain, and
/// the better half of it, since the alternative is spending the CPU and
/// degrading every established session along with it.
const IK_HANDSHAKE_PER_SEC: u32 = 64;
const IK_HANDSHAKE_BURST: u32 = 256;

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
    /// The last time this peer proved it was still there: a frame of theirs we
    /// decrypted, or — until one arrives — the handshake that built the session.
    ///
    /// Separate from `last_activity`, which our own sends refresh and which is
    /// therefore useless as an expiry clock. A peer that restarts or forgets
    /// its half leaves us sealing to keys nobody can read, and every such send
    /// pushed `last_activity` forward, so [`SESSION_TIMEOUT`] never fired and
    /// the dead slot outlived the process. `has_live_session` reported it as
    /// live throughout, which is what channel fan-out consults before choosing
    /// direct delivery over the relay. Only the peer can advance this.
    last_inbound: Instant,
    /// When this session's handshake completed, and unlike `last_activity` never
    /// touched again. Being able to order sessions by *arrival* rather than by use
    /// is what makes [`EmberTransport::trim_sessions_at`] correct — see there.
    established: Instant,
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
        let now = Instant::now();
        Self {
            transport,
            remote_noise_pub,
            last_activity: now,
            last_inbound: now,
            established: now,
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

/// An application payload parked behind an in-progress handshake, together
/// with the peer identity the caller addressed it to.
///
/// `pending` holds one slot per address while `sessions` are keyed by
/// `(address, static key)`, so a queued payload is only safe to seal once the
/// handshake has proven *which* identity answered. Carrying `to` is what lets
/// the flush sites tell a payload meant for this peer from one meant for a
/// different peer that happens to share the address.
struct QueuedPayload {
    /// The static key the caller named, or `None` if it named none.
    ///
    /// `None` is not a wildcard by accident: an unkeyed `prepare_outgoing` is
    /// precisely how an XX handshake gets started (the KAD bridge and the
    /// channel-neighbour probe both dial addresses whose Noise key we have not
    /// learned yet), and such a caller has already accepted whoever answers.
    to: Option<[u8; 32]>,
    bytes: Vec<u8>,
}

impl QueuedPayload {
    /// Whether this payload may be sealed to a session with `remote_noise_pub`.
    fn addressed_to(&self, remote_noise_pub: &[u8; 32]) -> bool {
        self.to.is_none_or(|want| &want == remote_noise_pub)
    }
}

/// Drop the payloads a completed handshake must not deliver, keeping only the
/// ones addressed to the identity that actually answered.
///
/// An XX handshake learns the peer's static key only at the end, so anything
/// queued behind one was queued before the recipient was known. Delivering the
/// remainder anyway would seal a caller's bytes to a peer it never named — the
/// same mistake [`EmberTransport::prepare_outgoing`] refuses outright for IK,
/// where the target *is* known up front. Dropping is safe in the way that
/// matters: every caller here is sending a best-effort datagram that a lost
/// packet would have cost anyway, and the DHT re-drives it on the next tick
/// against a session for the right identity.
fn retain_addressed_to(queued: Vec<QueuedPayload>, remote_noise_pub: &[u8; 32]) -> Vec<Vec<u8>> {
    let total = queued.len();
    let kept: Vec<Vec<u8>> = queued
        .into_iter()
        .filter(|q| q.addressed_to(remote_noise_pub))
        .map(|q| q.bytes)
        .collect();
    if kept.len() != total {
        debug!(
            "Dropped {} queued payload(s) addressed to another identity",
            total - kept.len()
        );
    }
    kept
}

/// In-progress handshake awaiting a response.
enum PendingHandshake {
    /// Noise_IK: we sent message 1, waiting for message 2.
    IkInitiator {
        state: snow::HandshakeState,
        queued: Vec<QueuedPayload>,
        created: Instant,
        /// Static key this handshake was started for. `pending` is keyed by
        /// address alone while `sessions` is keyed by `(address, static key)`,
        /// so this is what tells a later `prepare_outgoing` whether the
        /// handshake in flight will actually reach the identity it was asked
        /// for.
        remote_noise_pub: [u8; 32],
    },
    /// Noise_XX: we sent message 1, waiting for message 2.
    XxInitiatorMsg1 {
        state: snow::HandshakeState,
        queued: Vec<QueuedPayload>,
        created: Instant,
        /// Retry cookies this attempt has already acted on. Nothing is keyed yet
        /// at msg1, so a cookie packet is unauthenticated: without a hard limit,
        /// anyone able to spoof the responder's address could answer every msg1
        /// with another cookie and keep us minting ephemerals forever.
        ///
        /// The limit is [`MAX_XX_COOKIE_RETRIES`] rather than one because a forged
        /// cookie and a real one can both be in play. A forged one spends the
        /// first retry; if the responder is meanwhile over its own msg2 budget it
        /// answers that retry with a *genuine* cookie, and with only one retry
        /// allowed we refused it and the attempt died — under load, which is
        /// exactly when the cookie mechanism is engaged. Two lets the real cookie
        /// through while still bounding what a spoofer can extract to one extra
        /// message 1.
        cookie_retries: u8,
    },
    /// Noise_XX: responder read message 1, sent message 2, waiting for message 3.
    /// Application payloads enqueued here while we wait for the initiator's
    /// final handshake message are flushed as transport-mode packets in
    /// `handle_xx_msg3` once the session is established. Without this
    /// queue, calls to `prepare_outgoing` during the brief msg2→msg3
    /// window would silently drop the payload.
    XxResponderMsg2 {
        state: snow::HandshakeState,
        queued: Vec<QueuedPayload>,
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
    sessions: HashMap<(SocketAddr, [u8; 32]), NoiseSession>,
    /// Completed handshakes waiting to replace a slot that already holds a
    /// *proven* session. Consulted only after every live session at the address
    /// has failed AEAD, and promoted the moment one of these decrypts a frame.
    /// See [`EmberTransport::install_session`] for why a proven session is
    /// never displaced on the strength of a handshake alone.
    staged_sessions: HashMap<(SocketAddr, [u8; 32]), NoiseSession>,
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
    /// Per-process salt for [`Self::salted_addr_rank`], so eviction tie-breaks
    /// cannot be aimed by an attacker choosing its source addresses.
    trim_salt: [u8; 32],
    /// Addresses we have sent to, and when. Written by [`Self::note_dialled`] and
    /// read by [`Self::recently_dialled`], which is how the caller tells a peer
    /// that reached us unsolicited from one answering through a NAT mapping we
    /// opened ourselves. Keyed on address only: a peer's source port rotates, and
    /// the mapping question is about the host.
    dialled: HashMap<IpAddr, Instant>,
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
    /// The same, for the Noise work an inbound IK initiation costs. A separate
    /// bucket rather than a shared one: the two ration different things — XX
    /// rations bytes we reflect, IK rations CPU we spend — and sharing would
    /// let a flood on either path close the other, which is the whole network
    /// for a peer that only knows one of them.
    ik_tokens: u32,
    ik_refilled_at: Instant,
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

/// Wipe the long-lived secrets rather than leaving them in freed heap.
///
/// `local_noise_key` is the node's static X25519 private key and lives for the
/// whole process; the two cookie secrets are what make an XX retry cookie
/// unforgeable. This is defence in depth against a later heap disclosure — a
/// core dump, a swapped page, an allocator reusing the block — not against an
/// attacker who can already read this process's memory live.
///
/// What it cannot reach is the per-session traffic keys inside snow's
/// `StatelessTransportState`, which owns them and exposes no way to clear
/// them. Those go when a session is evicted, uncleared.
impl Drop for EmberTransport {
    fn drop(&mut self) {
        self.local_noise_key.zeroize();
        self.cookie_secret.zeroize();
        self.prev_cookie_secret.zeroize();
    }
}

impl EmberTransport {
    pub fn new(local_noise_key: [u8; 32], local_noise_pub: [u8; 32]) -> Self {
        Self {
            local_noise_key,
            local_noise_pub,
            sessions: HashMap::new(),
            staged_sessions: HashMap::new(),
            pending: HashMap::new(),
            recent_handshakes: HashMap::new(),
            deferred_ik: HashMap::new(),
            trim_salt: fresh_cookie_secret(),
            dialled: HashMap::new(),
            cookie_secret: fresh_cookie_secret(),
            prev_cookie_secret: fresh_cookie_secret(),
            cookie_rotated_at: Instant::now(),
            xx_msg2_tokens: XX_UNVALIDATED_MSG2_BURST,
            xx_msg2_refilled_at: Instant::now(),
            ik_tokens: IK_HANDSHAKE_BURST,
            ik_refilled_at: Instant::now(),
        }
    }

    /// Whether we may run the Noise responder for one fresh IK initiation,
    /// charging it if so.
    ///
    /// Charged on take, unlike [`Self::xx_msg2_budget_available`] and its
    /// separate spend: there the token pays for a packet that may still not be
    /// sent, here it pays for the crypto we are about to do either way.
    fn take_ik_handshake_token(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.ik_refilled_at);
        let earned = (elapsed.as_millis() as u64 * u64::from(IK_HANDSHAKE_PER_SEC)) / 1000;
        // Sub-token intervals leave the clock alone so the remainder carries;
        // see `refill_xx_msg2_budget`.
        if earned > 0 {
            let refilled = u64::from(self.ik_tokens).saturating_add(earned);
            self.ik_tokens = refilled.min(u64::from(IK_HANDSHAKE_BURST)) as u32;
            self.ik_refilled_at = now;
        }
        if self.ik_tokens == 0 {
            return false;
        }
        self.ik_tokens -= 1;
        true
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

    /// Drop the digest [`Self::check_handshake_replay`] recorded for an
    /// initiation we then declined to process at all.
    ///
    /// The cache exists to answer a retransmit with whatever we sent the first
    /// time, and an entry with no response answers it with silence — right for
    /// an initiation that genuinely produced nothing, wrong for one we refused
    /// on a budget, which would turn a single dropped packet into a whole
    /// replay window of them for a peer that is only retrying.
    fn forget_handshake(&mut self, digest: &[u8; 32]) {
        self.recent_handshakes.remove(digest);
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

    /// An ordering over addresses that an attacker cannot compute or steer,
    /// for breaking ties where the natural order would be attacker-chosen.
    fn salted_addr_rank(&self, addr: &SocketAddr) -> u64 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.trim_salt);
        match addr.ip() {
            IpAddr::V4(v4) => hasher.update(&v4.octets()),
            IpAddr::V6(v6) => hasher.update(&v6.octets()),
        };
        hasher.update(&addr.port().to_le_bytes());
        let digest = hasher.finalize();
        u64::from_le_bytes(digest.as_bytes()[..8].try_into().unwrap_or([0u8; 8]))
    }

    /// Remember that we sent something to this address.
    ///
    /// Called from [`Self::prepare_outgoing`] because that is the one place every
    /// outbound Ember packet passes through — searches, both bootstrap bridges,
    /// publishes, buddy forwards, liveness pings and replies alike. The callers
    /// each pair it with their own `send_to`, so trying to record dials at the call
    /// sites means enumerating them, and the enumeration is what went wrong before:
    /// the reachability rule consulted a map only the two bridges wrote to, and
    /// missed the iterative search — which dials whatever its shortlist holds,
    /// including gossip contacts the routing table refused, and so is the *common*
    /// way to open a mapping to a peer we have no contact for.
    fn note_dialled(&mut self, ip: IpAddr) {
        // Canonicalised on the way in as well as the way out. The socket is IPv4
        // today so the two forms cannot both occur, but storing `::ffff:a.b.c.d`
        // under one key and querying `a.b.c.d` under another would silently never
        // match, and nothing about that failure would be visible.
        let ip = ip.to_canonical();
        let now = Instant::now();
        if self.dialled.len() >= MAX_DIALLED_ADDRS && !self.dialled.contains_key(&ip) {
            if let Some(oldest) = self
                .dialled
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(ip, _)| *ip)
            {
                self.dialled.remove(&oldest);
            }
        }
        self.dialled.insert(ip, now);
    }

    /// Whether we have sent anything to this address recently enough that a NAT
    /// mapping we opened could still be carrying its reply.
    ///
    /// Compared on the canonical address so an IPv4-mapped IPv6 source matches the
    /// v4 entry it belongs to, rather than silently missing.
    pub fn recently_dialled(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.dialled
            .get(&ip)
            .is_some_and(|at| at.elapsed() < DIAL_MEMORY)
    }

    /// Check if we have an established session with a peer.
    #[allow(dead_code)]
    pub fn has_session(&self, addr: &SocketAddr) -> bool {
        self.sessions
            .keys()
            .any(|(session_addr, _)| session_addr == addr)
    }

    /// Whether a completed Noise session exists for this identity at `addr`.
    ///
    /// Distinct from [`Self::has_session`]: sessions are keyed by
    /// `(addr, static key)`, so an XX squatter at the same address must not
    /// count as a live path to `remote_noise_pub`. Channel relay and transfer
    /// delivery use this so they never call `prepare_outgoing` in a way that
    /// starts a handshake and then claim the frame was sent.
    pub fn has_live_session(&self, addr: &SocketAddr, remote_noise_pub: &[u8; 32]) -> bool {
        self.sessions.contains_key(&(*addr, *remote_noise_pub))
    }

    /// Whether the one session identified by `remote_noise_pub` completed
    /// Noise_IK.
    ///
    /// Scoped to a session rather than an address: sessions are keyed by
    /// `(addr, static key)` and up to [`MAX_SESSIONS_PER_ADDR`] identities can
    /// hold slots at the same address, so asking "does *anyone* here hold IK"
    /// would let an unauthenticated XX peer borrow a neighbour's
    /// authentication. Callers acting on a frame they just decrypted should ask
    /// about the key that decrypted it.
    pub fn session_is_ik_authenticated(
        &self,
        addr: &SocketAddr,
        remote_noise_pub: &[u8; 32],
    ) -> bool {
        self.sessions
            .get(&(*addr, *remote_noise_pub))
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
        self.note_dialled(peer.ip());

        // Fast path: an established session for the identity we were asked to
        // reach. Different keys at this address coexist, so a squatter holding
        // another slot must not capture (or force us to discard) this one.
        if let Some(session) = self.outgoing_session_mut(peer, remote_noise_pub) {
            session.last_activity = Instant::now();
            let key = session.remote_noise_pub;
            let sealed = session.seal(message);
            if let Some(packet) = sealed {
                return OutgoingResult::Ready { packet };
            }
            self.sessions.remove(&(peer, key));
            return OutgoingResult::Error("encrypt failed".to_string());
        }

        // A responder-side pending is not ours — see `XX_RESPONDER_QUEUE_GRACE`.
        // Once it has sat unfinished past the grace window, stop queuing behind
        // it and dial the identity the caller named instead. This is the
        // priority rule the module already applies in the other direction:
        // `handle_xx_msg1` refuses an inbound msg1 that would clobber a
        // handshake *we* started. Nothing better can be done for a caller that
        // named no key, so those still queue.
        let stalled_inbound_handshake = remote_noise_pub.is_some()
            && matches!(
                self.pending.get(&peer),
                Some(PendingHandshake::XxResponderMsg2 { created, .. })
                    if created.elapsed() >= XX_RESPONDER_QUEUE_GRACE
            );
        // Carried across rather than dropped. The payloads parked behind that
        // stalled handshake were accepted from callers who were told `Queued`
        // and treat it as sent, so discarding them here loses them silently —
        // `handle_xx_cookie` already moves its queue across for the same
        // reason. This matters more now that `handle_xx_msg1` no longer
        // restamps `created`: an XX exchange that takes longer than the grace
        // window is superseded here, and a single lost msg2 plus a retransmit
        // is enough to reach it.
        let mut carried_from_stalled: Vec<QueuedPayload> = Vec::new();
        if stalled_inbound_handshake {
            debug!(
                "Inbound XX handshake for {peer} has not completed in {:?}; dialling \
                 the identity we were asked for instead of queuing behind it",
                XX_RESPONDER_QUEUE_GRACE
            );
            if let Some(PendingHandshake::XxResponderMsg2 { queued, .. }) =
                self.pending.remove(&peer)
            {
                carried_from_stalled = queued;
            }
        }

        // Never queue behind a handshake that is reaching for a different
        // identity. `pending` holds one slot per address while `sessions` are
        // keyed by `(address, static key)`, so a payload parked here would be
        // sealed to whichever peer that handshake completes with — not the one
        // the caller named. Failing is recoverable (the caller retries, and
        // `cleanup` frees the slot after 30s); encrypting to the wrong identity
        // is not.
        if let (
            Some(PendingHandshake::IkInitiator {
                remote_noise_pub: target,
                ..
            }),
            Some(want),
        ) = (self.pending.get(&peer), remote_noise_pub)
        {
            if target != want {
                debug!(
                    "Not queuing for {peer}: an IK handshake to a different identity \
                     at this address is still in flight"
                );
                return OutgoingResult::Error(
                    "handshake in flight for another identity at this address".to_string(),
                );
            }
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
                    if queued.len() >= MAX_QUEUED_PER_HANDSHAKE {
                        queued.remove(0);
                    }
                    // Tagged with the identity the caller named. An IK
                    // handshake is already known to be reaching for that
                    // identity (refused just above otherwise), but an XX one
                    // does not learn who answered until it completes, so the
                    // flush sites need this to avoid sealing these bytes to a
                    // peer the caller never asked for.
                    queued.push(QueuedPayload {
                        to: remote_noise_pub.copied(),
                        bytes: message.to_vec(),
                    });
                    return OutgoingResult::Queued;
                }
            }
        }

        // Start new handshake
        if self.pending.len() >= MAX_PENDING {
            self.evict_oldest_pending();
        }

        if let Some(remote_pub) = remote_noise_pub {
            self.start_ik_handshake(peer, remote_pub, message, carried_from_stalled)
        } else {
            self.start_xx_handshake(peer, message)
        }
    }

    /// Whether a payload just parked by [`Self::prepare_outgoing`] for
    /// `remote_noise_pub` is certain to reach that identity.
    ///
    /// `false` when the queue it joined belongs to an XX handshake. XX does not
    /// learn who answered until it completes, so if a different identity turns
    /// up at that address the flush sites drop the payload
    /// (`retain_addressed_to`) and it never reaches the wire. A caller that
    /// books a timeout against a `Queued` result needs the difference: the
    /// keyed liveness pings the DHT parks behind an unkeyed KAD-bridge or
    /// channel-neighbour dial to the same address were being counted as sent,
    /// and the contact then took the strike for a probe discarded in here.
    pub fn queued_delivery_is_certain(
        &self,
        peer: SocketAddr,
        remote_noise_pub: &[u8; 32],
    ) -> bool {
        match self.pending.get(&peer) {
            Some(PendingHandshake::IkInitiator {
                remote_noise_pub: target,
                ..
            }) => target == remote_noise_pub,
            // XX in either role: identity unknown until completion.
            Some(_) => false,
            None => true,
        }
    }

    /// The session `prepare_outgoing` should seal to.
    ///
    /// A named static key selects only that session. No key — a ping auto-reply
    /// that just decrypted a frame — prefers a unique session at the address,
    /// then a validated one, then the most recently active.
    fn outgoing_session_mut(
        &mut self,
        peer: SocketAddr,
        remote_noise_pub: Option<&[u8; 32]>,
    ) -> Option<&mut NoiseSession> {
        if let Some(want) = remote_noise_pub {
            return self.sessions.get_mut(&(peer, *want));
        }
        let mut unique: Option<(SocketAddr, [u8; 32])> = None;
        let mut best: Option<((SocketAddr, [u8; 32]), bool, Instant)> = None;
        let mut count = 0usize;
        for (slot, session) in &self.sessions {
            if slot.0 != peer {
                continue;
            }
            count += 1;
            unique = Some(*slot);
            let rank = (session.addr_validated, session.last_activity);
            if best.is_none_or(|(_, validated, activity)| rank > (validated, activity)) {
                best = Some((*slot, rank.0, rank.1));
            }
        }
        let slot = if count == 1 {
            unique?
        } else {
            best.map(|(slot, _, _)| slot)?
        };
        self.sessions.get_mut(&slot)
    }

    /// Install `session` at `(addr, static key)`, replacing a previous handshake
    /// for the same key and sitting alongside any other keys at the address.
    /// Returns whether the session is still reachable afterwards — live in
    /// `sessions`, or staged awaiting the frame that promotes it.
    ///
    /// `false` means the per-address cap refused this claimant and its slot is
    /// gone, which only ever happens to an *unvalidated* arrival:
    /// `trim_sessions_at` will not shed a proven one. A caller that installs a
    /// `.validated()` session can ignore the result; the IK responder cannot,
    /// because it would otherwise answer a peer whose session it no longer has.
    #[must_use]
    fn install_session(&mut self, addr: SocketAddr, session: NoiseSession) -> bool {
        let arriving_key = session.remote_noise_pub;
        let slot = (addr, arriving_key);

        // A completed handshake for a slot that already holds a *proven*
        // session does not get to evict it. Stage it instead, and promote only
        // once it decrypts something.
        //
        // This used to overwrite unconditionally, and past
        // `HANDSHAKE_REPLAY_TTL` a captured `IK_INIT` replayed at a spoofed
        // source classifies as fresh: we run the responder again with a new
        // ephemeral, derive keys the genuine peer never sees (its own pending
        // entry expired long ago, so it rejects our `IK_RESP`), and install
        // them over the working session. Every frame in both directions then
        // failed AEAD, and nothing recovered — decrypt failures deliberately do
        // not tear a session down, and our own sends kept refreshing
        // `last_activity` so `SESSION_TIMEOUT` never fired. One captured packet
        // per liveness-ping cycle held the link down indefinitely.
        //
        // Staging closes it without breaking a legitimate re-handshake. Forging
        // a *new* `IK_INIT` needs the peer's static private key, so any init we
        // can read is genuinely from that peer; the only thing an attacker can
        // do is replay old bytes, and a replayer cannot derive the new
        // transport keys (they come from our fresh ephemeral against the peer's
        // static) so it can never produce the frame that promotes. A peer that
        // really did restart sends its next frame under the new keys and
        // promotes immediately.
        //
        // `trim_sessions_at` and `evict_one_session` already refuse to shed a
        // validated session for an unproven one; this closes the same-slot hole
        // in that reasoning.
        let incumbent_is_proven = self
            .sessions
            .get(&slot)
            .is_some_and(|existing| existing.addr_validated);
        if incumbent_is_proven {
            if self.staged_sessions.len() >= MAX_STAGED_SESSIONS
                && !self.staged_sessions.contains_key(&slot)
            {
                if let Some(oldest) = self
                    .staged_sessions
                    .iter()
                    .min_by_key(|(_, staged)| staged.established)
                    .map(|(key, _)| *key)
                {
                    self.staged_sessions.remove(&oldest);
                }
            }
            self.staged_sessions.insert(slot, session);
            return true;
        }

        self.staged_sessions.remove(&slot);
        if !self.sessions.contains_key(&slot) && self.sessions.len() >= MAX_SESSIONS {
            self.evict_one_session();
        }
        self.sessions.insert(slot, session);
        self.trim_sessions_at(addr, arriving_key);
        self.sessions.contains_key(&slot)
    }

    /// Keep one address from holding more than [`MAX_SESSIONS_PER_ADDR`] sessions.
    ///
    /// Shedding the newest *unvalidated* claimant (never the arrival, never a
    /// validated peer to admit an unproven one) is what lets a genuine first
    /// contact complete at an address whose slots are already full of spoofs:
    /// she is the arrival, so the oldest spoof stays and a newer one is dropped
    /// instead of her.
    fn trim_sessions_at(&mut self, addr: SocketAddr, arriving: [u8; 32]) {
        while self
            .sessions
            .keys()
            .filter(|(session_addr, _)| *session_addr == addr)
            .count()
            > MAX_SESSIONS_PER_ADDR
        {
            let arriving_validated = self
                .sessions
                .get(&(addr, arriving))
                .is_some_and(|session| session.addr_validated);
            let newest_unvalidated = self
                .sessions
                .iter()
                .filter(|((session_addr, key), session)| {
                    *session_addr == addr && *key != arriving && !session.addr_validated
                })
                .max_by_key(|(_, session)| session.established)
                .map(|(slot, _)| *slot);
            if let Some(victim) = newest_unvalidated {
                self.sessions.remove(&victim);
                continue;
            }
            if !arriving_validated {
                // Never shed a validated peer to admit an unproven newcomer.
                self.sessions.remove(&(addr, arriving));
                break;
            }
            let lru = self
                .sessions
                .iter()
                .filter(|((session_addr, key), _)| *session_addr == addr && *key != arriving)
                .min_by_key(|(_, session)| session.last_activity)
                .map(|(slot, _)| *slot);
            if let Some(victim) = lru {
                self.sessions.remove(&victim);
            } else {
                break;
            }
        }
    }

    /// Remove expired sessions and pending handshakes.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        // Age every session from the last time the *peer* proved it was there,
        // never from when we last used it.
        //
        // `last_activity` is refreshed by our own sends, so any session that can
        // only ever fail survived as long as we kept transmitting — and the DHT
        // keeps transmitting, because a contact stays in the table until its
        // pings time out. Two ways in: an on-path attacker replaying a captured
        // `IK_INIT` past `HANDSHAKE_REPLAY_TTL` (keys the real peer cannot read,
        // held at their address), and the ordinary case of a peer restarting or
        // forgetting its half. `fault_ember_contact` drops the session for a
        // routing-table contact on its first missed ping, but a peer we hold no
        // contact for — a channel member reached over its own session — is never
        // liveness-pinged, so nothing faulted it and the dead slot outlived the
        // process while `has_live_session` kept calling it live.
        //
        // `last_inbound` starts at the handshake and only the peer can advance
        // it, so this subsumes the old rule rather than loosening it: our sends
        // push `last_activity` forward but never this, so `last_activity` is
        // always at or ahead of it. The cost is that a strictly one-way flow
        // re-handshakes every `SESSION_TIMEOUT` — one 1-RTT IK exchange against
        // a peer whose static key we already hold, which is the trade this
        // constant's own documentation already accepts.
        self.sessions
            .retain(|_, s| now.duration_since(s.last_inbound) < SESSION_TIMEOUT);
        // A staged session that never decrypted anything is a handshake the
        // peer never followed up on — or a replay that never could. Drop it on
        // the pending-handshake timescale rather than the session one: the
        // genuine case promotes on the peer's very next frame.
        self.staged_sessions
            .retain(|_, s| now.duration_since(s.established) < Duration::from_secs(30));
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
        self.dialled
            .retain(|_, at| now.duration_since(*at) < DIAL_MEMORY);
    }

    /// Drop the session, staged re-handshake and deferred payload held for one
    /// peer *identity* (e.g. when the DHT concludes that peer is unreachable).
    ///
    /// Keyed by `(addr, static key)` rather than by address alone. Sessions
    /// coexist per identity precisely so that distinct peers behind one NAT or
    /// CGNAT do not compete for a slot, and [`Self::trim_sessions_at`] goes to
    /// real trouble never to shed a validated session to admit an unproven one.
    /// An address-wide sweep discarded all of that: one unresponsive peer's
    /// ping timeout tore down a co-located peer's working session, its
    /// in-flight handshake, and the first-contact payload deferred behind its
    /// return-routability probe — none of which that peer did anything to earn.
    ///
    /// A pending handshake is dropped only when it is one of ours aimed at this
    /// identity. `pending` holds a single slot per address, and an XX leg
    /// carries no target key at all, so anything else in it belongs to a
    /// different peer or a different question; it ages out on the 30-second
    /// sweep in [`Self::cleanup`].
    pub fn remove_session_for(&mut self, addr: &SocketAddr, remote_noise_pub: &[u8; 32]) {
        let slot = (*addr, *remote_noise_pub);
        self.sessions.remove(&slot);
        self.staged_sessions.remove(&slot);
        self.deferred_ik.remove(&slot);
        if matches!(
            self.pending.get(addr),
            Some(PendingHandshake::IkInitiator {
                remote_noise_pub: target,
                ..
            }) if target == remote_noise_pub
        ) {
            self.pending.remove(addr);
        }
    }

    /// Drop every session and pending handshake. Used when the
    /// `ember_native_enabled` feature flag flips off so a session
    /// established during an "on" period cannot decrypt later traffic
    /// when the user re-enables it (different harness session,
    /// different intent, possibly different peer trust).
    pub fn cleanup_all(&mut self) {
        self.sessions.clear();
        self.staged_sessions.clear();
        self.pending.clear();
        self.recent_handshakes.clear();
        self.deferred_ik.clear();
        // `dialled` deliberately survives. Clearing it alongside the session state
        // looked tidy and was wrong: the caller does reset its reachability
        // conclusion here, but the NAT mappings these dials opened outlive the
        // toggle, which is the whole reason `DIAL_MEMORY` is ten minutes. A user who
        // turns Ember off and straight back on would otherwise have a peer we
        // dialled — one the routing table does not hold, which is exactly the
        // population this map exists for — ping back and be read as a stranger. It
        // holds no session or cryptographic state, and is TTL-pruned anyway.
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
        let probe_answered = match outcome.remote_noise_pub {
            Some(key) => self.consume_probe_answer(from, &key, &payload),
            None => false,
        };
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
                if let OutgoingResult::Ready { packet } =
                    self.prepare_outgoing(from, outcome.remote_noise_pub.as_ref(), &pong)
                {
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
    fn consume_probe_answer(
        &mut self,
        from: SocketAddr,
        remote_noise_pub: &[u8; 32],
        payload: &[u8],
    ) -> bool {
        let Some(session) = self.sessions.get_mut(&(from, *remote_noise_pub)) else {
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

    /// `carried` is anything already queued for this address by a handshake
    /// this one supersedes. It rides out with the rest when the session comes
    /// up; dropping it instead loses payloads the caller was told were sent,
    /// because every caller treats `Queued` as success.
    fn start_ik_handshake(
        &mut self,
        peer: SocketAddr,
        remote_pub: &[u8; 32],
        first_message: &[u8],
        carried: Vec<QueuedPayload>,
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
                let mut queued = carried;
                // Same ceiling the queuing path enforces, applied here because
                // a superseded handshake's queue arrives all at once.
                if queued.len() > MAX_QUEUED_PER_HANDSHAKE {
                    let excess = queued.len() - MAX_QUEUED_PER_HANDSHAKE;
                    queued.drain(0..excess);
                }
                self.pending.insert(
                    peer,
                    PendingHandshake::IkInitiator {
                        state: initiator,
                        queued,
                        created: Instant::now(),
                        remote_noise_pub: *remote_pub,
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
        // Everything above this point is a hash and a map lookup; everything
        // below is a responder build and an X25519 exchange. See
        // [`IK_HANDSHAKE_PER_SEC`] for why that asymmetry needs a ceiling and
        // why this one sits so far above honest traffic. A retransmit was
        // already answered from the replay cache without reaching here, so a
        // drop costs a peer one attempt, not a handshake.
        if !self.take_ik_handshake_token() {
            trace!("Dropping IK init from {from}: over the handshake budget");
            self.forget_handshake(&handshake_digest);
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

        let remote_noise_pub = match extract_remote_static(&responder, &self.local_noise_key) {
            Some(k) => k,
            None => {
                debug!("IK responder: handshake completed without remote static key from {from}");
                return IncomingResult::Rejected;
            }
        };

        // Sessions are keyed on `(addr, static key)`, so a different identity
        // at this address installs alongside the incumbent instead of taking
        // it over. Same-key completion is a refresh of that slot.

        let transport = match responder.into_stateless_transport_mode() {
            Ok(t) => t,
            Err(e) => {
                debug!("IK into_transport failed for {from}: {e}");
                return IncomingResult::Rejected;
            }
        };

        let mut session = NoiseSession::new(transport, remote_noise_pub, true);
        // Clear any stale pending handshake for this address (e.g. an
        // earlier XX attempt we initiated before this IK init arrived).
        // Left in place, it lingers until the 30s pending-cleanup sweep
        // and can confuse a late, stray XX packet into being processed
        // against a handshake state that's no longer relevant now that a
        // session exists.
        //
        // But not a responder-side XX handshake still inside its grace window.
        // That state belongs to whoever sent us msg1, not to this handshake,
        // and anyone can mint a valid `IK_INIT` — it only needs our static key,
        // which every `FOUND_NODE` contact list publishes — from any source
        // address they care to write down. Removing it unconditionally meant
        // one forged packet destroyed a genuine inbound handshake: the peer's
        // `XX_MSG3` then arrived to "no pending handshake" and the first-contact
        // payload riding in it was lost.
        //
        // Sessions are keyed by `(addr, static key)`, so the session this
        // handshake just produced coexists with that pending rather than
        // competing for it, and nothing is confused by leaving it alone. The
        // grace bound keeps the original cleanup intent for genuinely stale
        // state. Refusing the `IK_INIT` outright instead would only invert the
        // problem — an unauthenticated forged `XX_MSG1` would then block real IK
        // handshakes, which is the worse trade, since msg1 proves nothing at all
        // while a completed IK is authenticated.
        let hold_inbound_xx = matches!(
            self.pending.get(&from),
            Some(PendingHandshake::XxResponderMsg2 { created, .. })
                if created.elapsed() < XX_RESPONDER_QUEUE_GRACE
        );
        if !hold_inbound_xx {
            self.pending.remove(&from);
        }
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
            // Trimmed after the insert, so the bound is applied to the map this
            // claimant has actually joined — and with its own entry excluded, or the
            // trim would simply undo the insert. See `trim_deferred_ik`.
            self.trim_deferred_ik(from, remote_noise_pub);
        }

        if !self.install_session(from, session) {
            // The per-address cap refused this claimant, and the session this
            // handshake produced no longer exists. Answering anyway is worse
            // than not answering: the peer installs its half on receiving
            // IK_RESP and believes the link is up, while every frame it sends
            // arrives here to no session, and the probe above would be
            // soliciting a Pong nothing can decrypt. That state does not heal
            // — the peer has no reason to re-handshake a session it thinks is
            // working — so an address already holding `MAX_SESSIONS_PER_ADDR`
            // proven peers, whether a busy NAT or an attacker who arranged it,
            // would leave every further identity behind it permanently
            // half-connected. Dropping the response instead leaves the peer to
            // time out and retry, which is recoverable.
            //
            // The deferred payload goes with it: releasing it needs an
            // authenticated frame, and without a session none can ever arrive,
            // so it would otherwise sit until the TTL sweep. `remove_session_for`
            // clears the same entry for the same reason.
            self.deferred_ik.remove(&(from, remote_noise_pub));
            // And forget the digest, or the replay cache would answer the
            // peer's retransmit with the IK_RESP we just decided not to send —
            // handing it the working half of a session we do not have, which is
            // the exact state this branch exists to avoid. Forgetting makes a
            // retransmit re-run the handshake, so the peer gets in as soon as a
            // slot at this address frees up.
            self.forget_handshake(&handshake_digest);
            debug!("IK responder: per-address session cap refused {from}; not answering");
            return IncomingResult::Rejected;
        }

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
    /// [`Self::trim_sessions_at`] and for the same reason: entries at one
    /// address arrived in the order their claimants did, so a spoofer churning
    /// static keys mints the newest and shedding those keeps the genuine peer's
    /// request. The global cap sheds from whichever address holds the most, for the
    /// same reason [`Self::trim_sessions_at`] does: shedding the map-wide oldest
    /// picks the peer that has been waiting longest for its probe answer, which is
    /// the one worth keeping. Exploiting that here would take roughly twenty
    /// thousand forged initiations a second against this map's larger bound, so it
    /// was a backstop in practice — but there is no reason to leave the wrong rule
    /// in place next to the right one.
    ///
    /// `arriving` is the entry this call was made to admit, and it is never a
    /// candidate. Without that the rule inverted itself deterministically: the
    /// caller inserts and then trims, so at a saturated address the newest entry is
    /// always the arrival, and every genuine first-contact payload was discarded
    /// the instant it was stored — for exactly the one-shot requests
    /// (`STORE_RECORD`, `ExchangeRequest`) that have no retry to survive it.
    fn trim_deferred_ik(&mut self, addr: SocketAddr, arriving: [u8; 32]) {
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
                .filter(|((deferred_addr, key), _)| *deferred_addr == addr && *key != arriving)
                .max_by_key(|(_, payload)| payload.stored)
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.deferred_ik.remove(&newest);
        }
        while self.deferred_ik.len() > MAX_DEFERRED_IK_PAYLOADS {
            let mut held: HashMap<SocketAddr, usize> = HashMap::new();
            for (deferred_addr, _) in self.deferred_ik.keys() {
                *held.entry(*deferred_addr).or_insert(0) += 1;
            }
            let Some(heaviest) = held
                .into_iter()
                .max_by_key(|(deferred_addr, count)| (*count, self.salted_addr_rank(deferred_addr)))
                .map(|(deferred_addr, _)| deferred_addr)
            else {
                break;
            };
            let Some(newest) = self
                .deferred_ik
                .iter()
                .filter(|((deferred_addr, _), _)| *deferred_addr == heaviest)
                .max_by_key(|(_, payload)| payload.stored)
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.deferred_ik.remove(&newest);
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

        let remote_noise_pub = match extract_remote_static(&state, &self.local_noise_key) {
            Some(k) => k,
            None => {
                debug!("IK initiator: handshake completed without remote static key from {from}");
                return IncomingResult::Rejected;
            }
        };

        // Sessions coexist per static key, so completing this handshake cannot
        // displace a different identity already at `from`.

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

        // Send queued messages. `prepare_outgoing` already refuses to park a
        // payload behind an IK handshake aimed elsewhere, so this filter is
        // expected to keep everything; it earns its place on the payloads
        // *carried in* from a superseded XX handshake, which were queued
        // before any identity was known.
        let mut packets = Vec::new();
        for msg in retain_addressed_to(queued, &remote_noise_pub) {
            if let Some(pkt) = session.seal(&msg) {
                packets.push(pkt);
            }
        }

        // Validated, so the per-address cap cannot shed it.
        let _ = self.install_session(from, session);
        trace!("IK handshake completed (initiator) with {from}");

        IncomingResult::HandshakeComplete {
            peer: from,
            remote_noise_pub,
            packets_to_send: packets,
            decrypted_payload: None,
        }
    }

    // ── Noise_XX handshake (2-RTT, we don't know the peer's static key) ──

    /// Only reached when the caller named no static key — that is what makes
    /// XX the right pattern — so the queued first message is addressed to
    /// whoever answers.
    fn start_xx_handshake(&mut self, peer: SocketAddr, first_message: &[u8]) -> OutgoingResult {
        let first = QueuedPayload {
            to: None,
            bytes: first_message.to_vec(),
        };
        match self.write_xx_msg1(peer, vec![first], &[], 0) {
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
        queued: Vec<QueuedPayload>,
        cookie: &[u8],
        cookie_retries: u8,
    ) -> Result<Vec<u8>, String> {
        let (initiator, buf) = self.build_xx_msg1(cookie)?;
        self.pending.insert(
            peer,
            PendingHandshake::XxInitiatorMsg1 {
                state: initiator,
                queued,
                created: Instant::now(),
                cookie_retries,
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
    /// Nothing is keyed at msg1, so this packet cannot be authenticated: a
    /// spoofed one makes us start the handshake over. That is survivable because a
    /// second message 1 replaces the responder's half-finished state and earns
    /// either a fresh message 2 or, if it is over its own unvalidated-msg2 budget,
    /// a genuine cookie — which is why [`MAX_XX_COOKIE_RETRIES`] is two rather than
    /// one. A forged cookie therefore costs a round trip, not the attempt — one
    /// forged cookie. Two delivered back to back still spend both retries, and if
    /// the responder is over budget by then its genuine cookie is refused and the
    /// attempt dies; any finite cap has that shape. The price of the second retry is
    /// that a source-address spoofer draws two ~51-byte message 1s toward the peer
    /// in `from` for its 19-byte packets rather than one.
    ///
    /// An earlier version tried to do better by keeping the replaced handshake
    /// and accepting a message 2 that verified against either. That looked
    /// strictly safer and was not: the responder keeps only its latest state, so
    /// completing against the *replaced* transcript left it unable to read our
    /// message 3, and we installed a session it would never use — a connection
    /// that looks established and silently carries nothing. Failing the stale
    /// message 2 and completing on the retry's keeps both sides on one transcript.
    fn handle_xx_cookie(&mut self, from: SocketAddr, data: &[u8]) -> IncomingResult {
        if data.len() != XX_COOKIE_LEN {
            debug!("XX cookie from {from} has wrong length {}", data.len());
            return IncomingResult::Rejected;
        }
        let spent = match self.pending.get(&from) {
            Some(PendingHandshake::XxInitiatorMsg1 { cookie_retries, .. })
                if *cookie_retries < MAX_XX_COOKIE_RETRIES =>
            {
                *cookie_retries
            }
            Some(PendingHandshake::XxInitiatorMsg1 { .. }) => {
                debug!("Ignoring XX cookie from {from}: this handshake spent its retries");
                return IncomingResult::Rejected;
            }
            _ => {
                debug!("XX cookie from {from} but no XX handshake of ours is in flight");
                return IncomingResult::Rejected;
            }
        };

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
        let Some(PendingHandshake::XxInitiatorMsg1 { queued, .. }) = self.pending.remove(&from)
        else {
            debug!("XX cookie from {from}: the pending handshake changed shape mid-dispatch");
            return IncomingResult::Rejected;
        };
        self.pending.insert(
            from,
            PendingHandshake::XxInitiatorMsg1 {
                state: initiator,
                queued,
                // `created` is refreshed, which is deliberate but bounded: the
                // retry is a new message 1 and deserves its own answer window, and
                // the retry count is what stops that being extended indefinitely.
                created: Instant::now(),
                cookie_retries: spent.saturating_add(1),
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
        // Carry the age and the queued payloads of the attempt this replaces.
        //
        // Stamping a fresh `created` on every inbound msg1 handed the sender
        // control of the timer that exists to protect us from them:
        // `prepare_outgoing` only stops queuing behind a responder-side pending
        // once it has sat unfinished past `XX_RESPONDER_QUEUE_GRACE`, so
        // re-forging a msg1 every couple of seconds kept it perpetually young.
        // We would then never dial, our own `IkInitiator` would never take the
        // slot, and the documented mitigation — "once our own `IkInitiator` is
        // pending, `handle_xx_msg1` refuses further inbound msg1s" — could never
        // engage. Every `prepare_outgoing` to that address returned `Queued`,
        // which callers treat as sent, and the fresh `Vec::new()` then destroyed
        // the payloads. One spoofed packet per victim per three seconds.
        //
        // Measuring from the oldest unfinished attempt instead means a genuine
        // retransmit still refreshes the crypto state while the clock — and the
        // queue — survive.
        let (created, queued) = match self.pending.remove(&from) {
            Some(PendingHandshake::XxResponderMsg2 { created, queued, .. }) => (created, queued),
            _ => (Instant::now(), Vec::new()),
        };
        self.pending.insert(
            from,
            PendingHandshake::XxResponderMsg2 {
                state: responder,
                queued,
                created,
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
        // Read against the handshake we currently hold and nothing else. After a
        // cookie retry that means a message 2 answering the message 1 the retry
        // replaced is refused — deliberately, since the responder has moved to the
        // retry's transcript and would not be able to read a message 3 built on
        // the old one. See [`Self::handle_xx_cookie`].
        match self.pending.get_mut(&from) {
            Some(PendingHandshake::XxInitiatorMsg1 { state, .. }) => {
                if state.read_message(data, &mut buf).is_err() {
                    debug!("XX msg2 from {from} did not verify against our handshake");
                    return IncomingResult::Rejected;
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
            mut state, queued, ..
        }) = self.pending.remove(&from)
        else {
            debug!("XX msg2 from {from}: pending handshake changed shape mid-dispatch");
            return IncomingResult::Rejected;
        };

        // Read out who answered before deciding what to send them. Message 2
        // carried the responder's static key, so the identity is known here —
        // and it has to be, because the msg3 payload below is the first thing
        // we would seal to it. Choosing that payload from the queue without
        // checking would hand a caller's bytes to whatever identity happens to
        // sit at this address: an XX handshake is only ever started by an
        // unkeyed `prepare_outgoing`, so the peer here was never named by the
        // caller whose payload is at the head of the queue.
        let remote_noise_pub = match extract_remote_static(&state, &self.local_noise_key) {
            Some(k) => k,
            None => {
                debug!("XX initiator: handshake completed without remote static key from {from}");
                return IncomingResult::Rejected;
            }
        };
        let deliverable = retain_addressed_to(queued, &remote_noise_pub);

        // Write message 3 (includes initiator's static key + first deliverable
        // queued message as payload)
        let payload = deliverable.first().map(|v| v.as_slice()).unwrap_or(&[]);
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

        // Sessions coexist per static key, so completing this handshake cannot
        // displace a different identity already at `from`.

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
        for msg in deliverable.iter().skip(1) {
            if let Some(pkt) = session.seal(msg) {
                packets.push(pkt);
            }
        }

        // Validated, so the per-address cap cannot shed it.
        let _ = self.install_session(from, session);
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

        let remote_noise_pub = match extract_remote_static(&state, &self.local_noise_key) {
            Some(k) => k,
            None => {
                debug!(
                    "XX msg3 responder: handshake completed without remote static key from {from}"
                );
                return IncomingResult::Rejected;
            }
        };

        // Sessions coexist per static key, so completing this handshake cannot
        // displace a different identity already at `from`.

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
        //
        // Only the ones addressed to the peer that actually completed the
        // handshake. This is the window the grace period in
        // `XX_RESPONDER_QUEUE_GRACE` deliberately keeps open, and in the
        // honest race the caller named exactly this peer — but a second
        // identity at the same address would otherwise have been handed
        // whatever was parked here for the first.
        let deliverable = retain_addressed_to(queued, &remote_noise_pub);
        let mut packets_to_send: Vec<Vec<u8>> = Vec::with_capacity(deliverable.len());
        for msg in &deliverable {
            if let Some(pkt) = session.seal(msg) {
                packets_to_send.push(pkt);
            } else {
                warn!("XX msg3: failed to encrypt queued message for {from}");
            }
        }

        // Validated, so the per-address cap cannot shed it.
        let _ = self.install_session(from, session);
        trace!(
            "XX handshake completed (responder) with {from}; flushed {} queued message(s)",
            deliverable.len()
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

        // Try every session at this address until AEAD succeeds. A squatter's
        // replay window or decrypt failure must not hide the real peer's frame.
        let candidates: Vec<[u8; 32]> = self
            .sessions
            .keys()
            .filter(|(addr, _)| *addr == from)
            .map(|(_, key)| *key)
            .collect();
        let staged: Vec<[u8; 32]> = self
            .staged_sessions
            .keys()
            .filter(|(addr, _)| *addr == from)
            .map(|(_, key)| *key)
            .collect();
        if candidates.is_empty() && staged.is_empty() {
            debug!("Ember transport packet from {from} with no session");
            return IncomingResult::Rejected;
        }
        for key in candidates {
            let Some(session) = self.sessions.get_mut(&(from, key)) else {
                continue;
            };
            if !session.replay_precheck(nonce) {
                continue;
            }
            let mut payload_buf = vec![0u8; ciphertext.len()];
            match session
                .transport
                .read_message(nonce, ciphertext, &mut payload_buf)
            {
                Ok(len) => {
                    session.replay_commit(nonce);
                    let now = Instant::now();
                    session.last_activity = now;
                    session.last_inbound = now;
                    session.addr_validated = true;
                    return IncomingResult::Message {
                        from,
                        remote_noise_pub: session.remote_noise_pub,
                        payload: payload_buf[..len].to_vec(),
                    };
                }
                Err(_) => continue,
            }
        }

        // Nothing live could read it. A staged handshake for this address is
        // the remaining possibility, and decrypting under its keys is exactly
        // the proof `install_session` withheld promotion for: a replayer cannot
        // derive them, so only the genuine peer reaches here. Promote it over
        // the stale incumbent and serve the frame.
        for key in staged {
            let slot = (from, key);
            let Some(session) = self.staged_sessions.get_mut(&slot) else {
                continue;
            };
            if !session.replay_precheck(nonce) {
                continue;
            }
            let mut payload_buf = vec![0u8; ciphertext.len()];
            match session
                .transport
                .read_message(nonce, ciphertext, &mut payload_buf)
            {
                Ok(len) => {
                    let Some(mut promoted) = self.staged_sessions.remove(&slot) else {
                        continue;
                    };
                    promoted.replay_commit(nonce);
                    let now = Instant::now();
                    promoted.last_activity = now;
                    promoted.last_inbound = now;
                    promoted.addr_validated = true;
                    let remote_noise_pub = promoted.remote_noise_pub;
                    debug!(
                        "Ember transport: promoting re-handshaked session for {from} after it decrypted a frame"
                    );
                    if !self.sessions.contains_key(&slot) && self.sessions.len() >= MAX_SESSIONS {
                        self.evict_one_session();
                    }
                    self.sessions.insert(slot, promoted);
                    self.trim_sessions_at(from, key);
                    return IncomingResult::Message {
                        from,
                        remote_noise_pub,
                        payload: payload_buf[..len].to_vec(),
                    };
                }
                Err(_) => continue,
            }
        }
        IncomingResult::Rejected
    }

    // ── Eviction helpers ──

    /// Free one session slot when the table is full.
    ///
    /// Newest unvalidated first, so a flood of forged initiations cannibalises
    /// itself rather than established peers. Validated sessions are LRU only
    /// when nothing unproven remains. Ties break on a per-process salted hash
    /// of the address, so the order cannot be aimed by choosing source addresses.
    fn evict_one_session(&mut self) {
        let victim = self
            .sessions
            .iter()
            .filter(|(_, s)| !s.addr_validated)
            .max_by_key(|(slot, s)| (s.established, self.salted_addr_rank(&slot.0)))
            .map(|(k, _)| *k)
            .or_else(|| {
                self.sessions
                    .iter()
                    .min_by_key(|(slot, s)| (s.last_activity, self.salted_addr_rank(&slot.0)))
                    .map(|(k, _)| *k)
            });
        if let Some(victim) = victim {
            self.sessions.remove(&victim);
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
fn extract_remote_static(
    state: &snow::HandshakeState,
    local_noise_key: &[u8; 32],
) -> Option<[u8; 32]> {
    let rs = state.get_remote_static()?;
    if rs.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(rs);
    // snow's default resolver performs no contributory check, so a peer can
    // present the all-zero point — or any other low-order point — as its
    // static key and complete the handshake while holding no private key at
    // all: every DH against such a point is the identity, so the attacker can
    // substitute the known constant wherever the pattern calls for a DH
    // against its claimed static. Repeat the `ss` exchange here and refuse a
    // non-contributory result, which is exactly the test `crypto.rs` applies
    // on the chat and capability paths.
    //
    // This is what keeps "the session carries a static key" equivalent to "the
    // peer holds the matching private key" — an invariant `dht/engine.rs`
    // depends on when it adopts the session's static key as a contact's
    // `noise_pub`. All-zero is also the sentinel the rest of the codebase
    // reads as "no key", so admitting it let every malformed peer collide on
    // one identity.
    let ours = x25519_dalek::StaticSecret::from(*local_noise_key);
    if !ours
        .diffie_hellman(&x25519_dalek::PublicKey::from(key))
        .was_contributory()
    {
        return None;
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    /// Stand-in for a node's own Noise static key, which v4 binds every frame
    /// signature to. Encode and decode must agree on it; a test that needs them
    /// to disagree passes a different key explicitly.
    const TEST_NOISE_PUB: [u8; 32] = [0xAB; 32];

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

    /// A captured `IK_INIT` replayed once the replay cache has aged out used to
    /// overwrite the live session with keys the genuine peer never derived — its
    /// own pending entry had long expired, so it ignored our `IK_RESP` and kept
    /// the originals. Every frame in both directions then failed AEAD, and
    /// nothing recovered: decrypt failures do not tear a session down, and our
    /// own sends kept `last_activity` fresh so the timeout never fired.
    ///
    /// The replay cache is swept by `cleanup`, so clearing `recent_handshakes`
    /// here is exactly what the passage of `HANDSHAKE_REPLAY_TTL` does.
    #[test]
    fn a_replayed_init_past_the_replay_window_cannot_wedge_a_live_session() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        // Establish, and prove the address so Bob's session is validated.
        let init = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), b"hi") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        let resp = match bob.process_incoming(&init, alice_addr) {
            IncomingResult::HandshakeComplete {
                packets_to_send, ..
            } => packets_to_send,
            _ => panic!("expected HandshakeComplete"),
        };
        let _ = alice.process_incoming(&resp[0], bob_addr);
        let probe_answer = alice.dispatch_incoming(&resp[1], bob_addr);
        let _ = bob.dispatch_incoming(&probe_answer.responses[0], alice_addr);

        // Alice can be heard.
        let good = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), b"before") {
            OutgoingResult::Ready { packet } => packet,
            other => panic!("expected Ready, got {}", variant_name(&other)),
        };
        assert_eq!(
            bob.dispatch_incoming(&good, alice_addr).app_payloads,
            vec![b"before".to_vec()],
            "the established session works"
        );

        // The replay window lapses, then the attacker replays the captured init
        // from Alice's address.
        bob.recent_handshakes.clear();
        let _ = bob.process_incoming(&init, alice_addr);

        // Alice's next frame, under the ORIGINAL keys, must still be readable.
        let after = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), b"after") {
            OutgoingResult::Ready { packet } => packet,
            other => panic!("expected Ready, got {}", variant_name(&other)),
        };
        // Delivered, therefore the incumbent session survived. Asserting on the
        // exact payload list would be wrong: the replayed init re-armed its own
        // embedded payload as a deferred one, and any authenticated frame
        // releases that, so Alice's original first message rides along a second
        // time. Duplicate delivery of an already-authenticated payload is
        // harmless here (the DHT's own replay collapse covers it) and is not
        // what this test is about.
        let delivered = bob.dispatch_incoming(&after, alice_addr).app_payloads;
        assert!(
            delivered.contains(&b"after".to_vec()),
            "a replayed init must not wedge the live session; got {delivered:?}"
        );
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
        assert_eq!(
            probe_answer.responses.len(),
            1,
            "the probe must be answered"
        );

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

    /// Every IK initiation with an unseen ephemeral costs a responder build
    /// and an X25519 exchange, nothing dedupes a flood of them, and the source
    /// address needs to prove nothing first. The budget is what keeps that
    /// from being unbounded remote CPU.
    #[test]
    fn an_ik_flood_is_capped_by_the_handshake_budget() {
        let (bob_priv, bob_pub) = make_keypair();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();
        let peer_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();

        let (peer_priv, peer_pub) = make_keypair();
        let mut peer = EmberTransport::new(peer_priv, peer_pub);
        let init = match peer.prepare_outgoing(bob_addr, Some(&bob_pub), b"request") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };

        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        // Drained directly rather than by sending a burst's worth of real
        // initiations: that loop takes long enough to earn tokens back while
        // it runs, so where it landed would be a matter of how fast the
        // machine is.
        while bob.take_ik_handshake_token() {}

        assert!(
            matches!(
                bob.process_incoming(&init, peer_addr),
                IncomingResult::Rejected
            ),
            "an initiation over the budget must be dropped before any Noise work"
        );
        assert!(
            bob.recent_handshakes.is_empty(),
            "a refused initiation must leave no replay-cache entry, or the peer's \
             retransmit is answered with silence for the whole replay window"
        );

        // The control: the same packet, delivered to the same identity with a
        // full bucket, is an ordinary first contact. So it was the budget that
        // refused it above and nothing about the packet.
        let mut rested = EmberTransport::new(bob_priv, bob_pub);
        assert!(
            !matches!(
                rested.process_incoming(&init, peer_addr),
                IncomingResult::Rejected
            ),
            "the initiation itself is well-formed"
        );
    }

    /// Sessions coexist per static key, so a spoofer churning identities at
    /// Alice's address cannot displace her session or her deferred first-contact
    /// request. The per-address cap sheds the newest unvalidated claimant except
    /// the arrival, which is what keeps the oldest (Alice) through any amount of
    /// churn.
    #[test]
    fn a_sustained_spoof_cannot_keep_the_address_owner_from_completing() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

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

        for _ in 0..(MAX_SESSIONS_PER_ADDR.max(MAX_DEFERRED_IK_PAYLOADS_PER_ADDR) * 4) {
            let (squatter_priv, _squatter_pub) = make_keypair();
            let mut squatter = EmberTransport::new(squatter_priv, _squatter_pub);
            let squat = match squatter.prepare_outgoing(bob_addr, Some(&bob_pub), b"squat") {
                OutgoingResult::HandshakeStarted { packet } => packet,
                other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
            };
            assert!(matches!(
                bob.process_incoming(&squat, alice_addr),
                IncomingResult::HandshakeComplete { .. }
            ));
        }

        assert!(
            bob.sessions.contains_key(&(alice_addr, alice_pub)),
            "Alice's session must survive the spoof flood"
        );

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

    /// Ranking by last-activity used to drop a genuine session that was busy
    /// when a newer spoof arrived. Sessions now coexist, and the trim still
    /// sheds the newest unvalidated handshake — never the busiest one.
    #[test]
    fn a_busy_session_is_not_mistaken_for_the_newest_shadow() {
        let (bob_priv, bob_pub) = make_keypair();
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        let (alice_priv, alice_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let init = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), b"genuine") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        let _ = bob.process_incoming(&init, alice_addr);
        assert_eq!(
            bob.sessions
                .get(&(alice_addr, alice_pub))
                .map(|s| s.remote_noise_pub),
            Some(alice_pub),
            "her unvalidated session is installed under her static key"
        );

        let spoof = |bob: &mut EmberTransport| {
            let (priv_key, _pub_key) = make_keypair();
            let mut attacker = EmberTransport::new(priv_key, _pub_key);
            let packet = match attacker.prepare_outgoing(bob_addr, Some(&bob_pub), b"spoof") {
                OutgoingResult::HandshakeStarted { packet } => packet,
                other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
            };
            let _ = bob.process_incoming(&packet, alice_addr);
        };
        for _ in 0..(MAX_SESSIONS_PER_ADDR - 1) {
            spoof(&mut bob);
        }
        assert!(
            bob.sessions.contains_key(&(alice_addr, alice_pub)),
            "she must still be held before the trim is even reached"
        );

        bob.sessions
            .get_mut(&(alice_addr, alice_pub))
            .expect("her session")
            .last_activity = Instant::now();

        spoof(&mut bob);
        assert!(
            bob.sessions.contains_key(&(alice_addr, alice_pub)),
            "the trim must shed the newest handshake, not the busiest session"
        );
    }

    /// The hole the shadow map could not close: Alice's first contact arrives
    /// at an address already full of older spoof sessions. She is the newest,
    /// so the old trim shed her at once. Keying by static key and never shedding
    /// the arrival to make room for older unvalidated claimants keeps her.
    #[test]
    fn first_contact_at_a_full_address_of_spoofs_still_completes() {
        let (bob_priv, bob_pub) = make_keypair();
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        for _ in 0..MAX_SESSIONS_PER_ADDR {
            let (priv_key, _pub_key) = make_keypair();
            let mut attacker = EmberTransport::new(priv_key, _pub_key);
            let packet = match attacker.prepare_outgoing(bob_addr, Some(&bob_pub), b"spoof") {
                OutgoingResult::HandshakeStarted { packet } => packet,
                other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
            };
            assert!(matches!(
                bob.process_incoming(&packet, alice_addr),
                IncomingResult::HandshakeComplete { .. }
            ));
        }
        assert_eq!(
            bob.sessions
                .keys()
                .filter(|(addr, _)| *addr == alice_addr)
                .count(),
            MAX_SESSIONS_PER_ADDR
        );

        let (alice_priv, alice_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let init = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), b"genuine") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        let to_alice = match bob.process_incoming(&init, alice_addr) {
            IncomingResult::HandshakeComplete {
                packets_to_send, ..
            } => packets_to_send,
            other => panic!(
                "first contact at a full address must complete, got {}",
                incoming_variant_name(&other)
            ),
        };
        assert!(
            bob.sessions.contains_key(&(alice_addr, alice_pub)),
            "Alice's session must be kept even though she was the newest claimant"
        );

        let mut probe_answer = None;
        for packet in &to_alice {
            let out = alice.dispatch_incoming(packet, bob_addr);
            assert!(!out.rejected);
            if let Some(response) = out.responses.into_iter().next() {
                probe_answer = Some(response);
            }
        }
        let probe_answer = probe_answer.expect("Alice answers the probe");
        let released = bob.dispatch_incoming(&probe_answer, alice_addr);
        assert_eq!(released.app_payloads, vec![b"genuine".to_vec()]);
    }

    /// A cookie packet cannot be authenticated — nothing is keyed at msg1 — so a
    /// forged one from an address we are dialling makes us start over. First
    /// contact still has to complete, because the responder answers the retry too.
    ///
    /// This is also the test that pinned the wrong fix. It used to keep the
    /// replaced handshake and let the responder's *earlier* message 2 complete
    /// against it, which passed only because the test never delivered the retry to
    /// the responder. On a real network it does arrive, the responder keeps only
    /// its latest state, and completing against the replaced transcript left us
    /// holding a session it could not read — established-looking and silently
    /// carrying nothing. So the retry is delivered here, and the stale message 2
    /// is expected to be refused.
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
        let retry = match alice.process_incoming(&forged, bob_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => {
                assert_eq!(packets[0][2], PKT_XX_MSG1, "the retry is an ordinary msg1");
                packets.into_iter().next().expect("the retry msg1")
            }
            _ => panic!("expected the cookie retry"),
        };
        assert!(
            alice.pending.contains_key(&bob_addr),
            "the handshake must still be in flight"
        );

        // The retry reaches Bob, as it would on any network that delivered the
        // forged cookie. He moves to its transcript and answers it.
        let msg2_retry = match bob.process_incoming(&retry, alice_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => {
                packets.into_iter().next().expect("msg2 for the retry")
            }
            other => panic!(
                "the responder must answer the retry, got {}",
                incoming_variant_name(&other)
            ),
        };

        // Bob's first msg2 answers the message 1 the retry replaced. Completing on
        // it would build a message 3 he cannot read, so it is refused — and
        // refusing it must not cost us the handshake.
        assert!(
            matches!(
                alice.process_incoming(&msg2, bob_addr),
                IncomingResult::Rejected
            ),
            "a message 2 for a transcript the responder has left must not complete"
        );
        assert!(
            alice.pending.contains_key(&bob_addr),
            "and rejecting it must not strand the attempt"
        );

        // The retry's own msg2 completes, and both sides agree on the transcript.
        let msg3 = match alice.process_incoming(&msg2_retry, bob_addr) {
            IncomingResult::HandshakeComplete {
                packets_to_send, ..
            } => packets_to_send,
            other => panic!(
                "the retry's msg2 must complete the handshake, got {}",
                incoming_variant_name(&other)
            ),
        };
        assert!(!msg3.is_empty());
        match bob.process_incoming(&msg3[0], alice_addr) {
            IncomingResult::HandshakeComplete { .. } => {}
            other => panic!(
                "expected the responder to complete on msg3, got {}",
                incoming_variant_name(&other)
            ),
        }

        // And the retries are hard-capped, so a cookie flood cannot keep us minting
        // ephemerals: MAX_XX_COOKIE_RETRIES and then nothing, however many arrive.
        let mut alice2 = EmberTransport::new(make_keypair().0, alice_pub);
        let _ = alice2.prepare_outgoing(bob_addr, None, b"hi");
        for attempt in 0..MAX_XX_COOKIE_RETRIES {
            assert!(
                matches!(
                    alice2.process_incoming(&forged, bob_addr),
                    IncomingResult::HandshakeResponse { .. }
                ),
                "retry {attempt} should still be allowed"
            );
        }
        assert!(
            matches!(
                alice2.process_incoming(&forged, bob_addr),
                IncomingResult::Rejected
            ),
            "an attempt gets a fixed number of cookie retries, not one per forged packet"
        );
    }

    /// The reason the cap is two rather than one. A forged cookie spends the first
    /// retry; the responder, over its own unvalidated-msg2 budget by then, answers
    /// that retry with a *genuine* cookie. With a single retry allowed we refused it
    /// and the attempt died — under load, which is when the cookie mechanism exists
    /// to be used.
    #[test]
    fn a_forged_cookie_does_not_use_up_the_response_to_a_real_one() {
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
        let _ = bob.process_incoming(&msg1, alice_addr);

        // A forged cookie spends retry one.
        let mut forged = Vec::with_capacity(HEADER_LEN + XX_COOKIE_LEN);
        forged.extend_from_slice(&[EMBER_MAGIC[0], EMBER_MAGIC[1], PKT_XX_COOKIE]);
        forged.extend_from_slice(&[0xAB; XX_COOKIE_LEN]);
        let retry = match alice.process_incoming(&forged, bob_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => {
                packets.into_iter().next().expect("the retry msg1")
            }
            other => panic!("expected the retry, got {}", incoming_variant_name(&other)),
        };

        // Bob is now under pressure and answers the retry with a real cookie
        // instead of a message 2. Through the helper, which also resets the refill
        // clock — zeroing the tokens alone lets a slow moment earn one back and the
        // assertion below then races the refill.
        exhaust_xx_msg2_budget(&mut bob);
        let real_cookie = match bob.process_incoming(&retry, alice_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => {
                let packet = packets.into_iter().next().expect("a cookie");
                assert_eq!(packet[2], PKT_XX_COOKIE, "the responder is over its budget");
                packet
            }
            other => panic!("expected a cookie, got {}", incoming_variant_name(&other)),
        };

        // The real cookie has to be usable, and the msg1 carrying it has to be the
        // one that finally earns a message 2.
        let proven = match alice.process_incoming(&real_cookie, bob_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => {
                packets.into_iter().next().expect("the proven msg1")
            }
            other => panic!(
                "a genuine cookie must still be actionable, got {}",
                incoming_variant_name(&other)
            ),
        };
        let msg2 = match bob.process_incoming(&proven, alice_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => {
                let packet = packets.into_iter().next().expect("msg2");
                assert_eq!(
                    packet[2], PKT_XX_MSG2,
                    "a valid cookie skips the budget entirely"
                );
                packet
            }
            other => panic!("expected msg2, got {}", incoming_variant_name(&other)),
        };
        let msg3 = match alice.process_incoming(&msg2, bob_addr) {
            IncomingResult::HandshakeComplete {
                packets_to_send, ..
            } => packets_to_send,
            other => panic!(
                "first contact must complete, got {}",
                incoming_variant_name(&other)
            ),
        };
        assert!(matches!(
            bob.process_incoming(&msg3[0], alice_addr),
            IncomingResult::HandshakeComplete { .. }
        ));
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

    /// Two identities can hold slots at one address, because `sessions` is
    /// keyed by `(addr, static key)` — but `pending` still has one slot per
    /// address. A payload aimed at the second identity used to be queued onto
    /// the first one's handshake and then sealed to it on completion,
    /// delivering it to a peer it was never addressed to. Refusing is
    /// recoverable (the caller retries, and `cleanup` frees the slot);
    /// misdirecting is not.
    #[test]
    fn a_payload_is_not_queued_onto_a_handshake_for_another_identity() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let (_other_priv, other_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        let for_bob = vec![0xA1u8; 96];
        let for_other = vec![0xB2u8; 96];

        let init = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), &for_bob) {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };

        match alice.prepare_outgoing(bob_addr, Some(&other_pub), &for_other) {
            OutgoingResult::Error(_) => {}
            other => panic!(
                "a payload for another identity must not ride Bob's handshake, got {}",
                variant_name(&other)
            ),
        }

        // A retry for the identity the handshake *is* for still queues.
        assert!(
            matches!(
                alice.prepare_outgoing(bob_addr, Some(&bob_pub), b"also for bob"),
                OutgoingResult::Queued
            ),
            "the same identity must still ride its own handshake"
        );

        let handshake = bob.dispatch_incoming(&init, alice_addr);
        let flushed = alice.dispatch_incoming(&handshake.responses[0], bob_addr);
        let delivered = bob.dispatch_incoming(&flushed.responses[0], alice_addr);
        assert!(
            !delivered.app_payloads.contains(&for_other),
            "the other identity's payload must never reach Bob"
        );
        assert_eq!(delivered.app_payloads.first(), Some(&for_bob));
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

        // Answering the probe proves Alice's address and releases her request.
        // Mallory's session sits alongside; it is not discarded.
        assert!(!alice.dispatch_incoming(&responses[0], bob_addr).rejected);
        let probe_answer = alice.dispatch_incoming(&responses[1], bob_addr);
        let released = bob.dispatch_incoming(&probe_answer.responses[0], alice_addr);
        assert_eq!(released.app_payloads, vec![b"genuine".to_vec()]);
        assert!(bob.sessions.contains_key(&(alice_addr, alice_pub)));
        assert!(bob.sessions.contains_key(&(alice_addr, mallory_pub)));

        // A later initiation from Mallory installs (or refreshes) her own slot
        // rather than being rejected by a takeover guard, and cannot evict Alice.
        mallory.remove_session_for(&bob_addr, &bob_pub);
        let squat_again = match mallory.prepare_outgoing(bob_addr, Some(&bob_pub), b"squat again") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        assert!(
            matches!(
                bob.process_incoming(&squat_again, alice_addr),
                IncomingResult::HandshakeComplete { .. }
            ),
            "a different static key installs alongside a validated peer"
        );
        assert!(
            bob.sessions.contains_key(&(alice_addr, alice_pub)),
            "Alice's validated session must survive Mallory's later handshake"
        );
    }

    /// An unproven session squatting a peer's address must not capture the
    /// traffic we send to a *different* identity at that address, and dialling
    /// the named identity must not discard the squatter's own session.
    #[test]
    fn dialling_a_peer_does_not_discard_another_identitys_session() {
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

        assert!(matches!(
            bob.prepare_outgoing(alice_addr, Some(&mallory_pub), b"for mallory"),
            OutgoingResult::Ready { .. }
        ));
        assert!(
            matches!(
                bob.prepare_outgoing(alice_addr, Some(&alice_pub), b"for alice"),
                OutgoingResult::HandshakeStarted { .. }
            ),
            "a named identity with no session must start its own handshake"
        );
        assert!(
            bob.sessions.contains_key(&(alice_addr, mallory_pub)),
            "dialling Alice must not discard Mallory's session"
        );
    }

    /// The header is stripped before dispatch, so hashing the body alone put
    /// `XX_RESPONDER_QUEUE_GRACE` only lets `prepare_outgoing` give up on a
    /// responder-side pending once it has sat unfinished past the window. If a
    /// fresh msg1 restamps `created`, the sender controls that clock: re-forging
    /// every couple of seconds keeps it perpetually young, so we never dial, our
    /// own initiator never takes the slot, and every send returns `Queued` —
    /// which callers treat as sent — while the requeue destroys the payloads.
    #[test]
    fn a_repeated_xx_msg1_cannot_hold_the_queue_grace_open() {
        let (bob_priv, bob_pub) = make_keypair();
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let attacker: SocketAddr = "9.9.9.9:5000".parse().unwrap();

        let (a_priv, _a_pub) = make_keypair();
        let mut msg1 = vec![0u8; HEADER_LEN + 128];
        msg1[0] = EMBER_MAGIC[0];
        msg1[1] = EMBER_MAGIC[1];
        msg1[2] = PKT_XX_MSG1;
        let params: snow::params::NoiseParams = NOISE_PATTERN_XX.parse().unwrap();
        let mut initiator = snow::Builder::new(params)
            .local_private_key(&a_priv)
            .build_initiator()
            .unwrap();
        let n = initiator.write_message(&[], &mut msg1[HEADER_LEN..]).unwrap();
        msg1.truncate(HEADER_LEN + n);

        let _ = bob.process_incoming(&msg1, attacker);
        let first_created = match bob.pending.get(&attacker) {
            Some(PendingHandshake::XxResponderMsg2 { created, .. }) => *created,
            other => panic!("expected a responder pending, got {}", other.is_some()),
        };

        // A second msg1 from the same address, as the renewal attack sends it.
        // The crypto state may be rebuilt, but the clock must not restart.
        let mut msg1b = msg1.clone();
        msg1b[HEADER_LEN] ^= 0x01;
        let _ = bob.process_incoming(&msg1b, attacker);
        match bob.pending.get(&attacker) {
            Some(PendingHandshake::XxResponderMsg2 { created, .. }) => assert_eq!(
                *created, first_created,
                "the grace window must age from the oldest unfinished attempt"
            ),
            _ => panic!("expected the responder pending to survive"),
        }
    }

    /// Anyone can mint a valid `IK_INIT` — it needs only our static key, which
    /// every `FOUND_NODE` contact list publishes — from any source address they
    /// write down. It must not be able to destroy a genuine inbound handshake
    /// belonging to whoever really is at that address.
    #[test]
    fn a_forged_ik_init_does_not_destroy_an_inbound_xx_handshake() {
        let (bob_priv, bob_pub) = make_keypair();
        let (victim_priv, _victim_pub) = make_keypair();
        let (mallory_priv, _mallory_pub) = make_keypair();
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let victim: SocketAddr = "4.4.4.4:4000".parse().unwrap();

        // The victim opens an XX handshake with Bob.
        let params: snow::params::NoiseParams = NOISE_PATTERN_XX.parse().unwrap();
        let mut initiator = snow::Builder::new(params)
            .local_private_key(&victim_priv)
            .build_initiator()
            .unwrap();
        let mut msg1 = vec![0u8; HEADER_LEN + 128];
        msg1[0] = EMBER_MAGIC[0];
        msg1[1] = EMBER_MAGIC[1];
        msg1[2] = PKT_XX_MSG1;
        let n = initiator.write_message(&[], &mut msg1[HEADER_LEN..]).unwrap();
        msg1.truncate(HEADER_LEN + n);
        assert!(matches!(
            bob.process_incoming(&msg1, victim),
            IncomingResult::HandshakeResponse { .. }
        ));
        assert!(bob.pending.contains_key(&victim));

        // Mallory forges an IK init from the victim's address.
        let mut mallory = EmberTransport::new(mallory_priv, _mallory_pub);
        let forged = match mallory.prepare_outgoing(
            "5.5.5.5:5000".parse().unwrap(),
            Some(&bob_pub),
            b"x",
        ) {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        let _ = bob.process_incoming(&forged, victim);

        assert!(
            matches!(
                bob.pending.get(&victim),
                Some(PendingHandshake::XxResponderMsg2 { .. })
            ),
            "the victim's inbound handshake must survive a forged IK init"
        );
        // The forged handshake still completes into its own session slot —
        // refusing it outright would only invert the attack, since an
        // unauthenticated XX msg1 would then block real IK dials. Coexistence
        // is what makes leaving the pending alone safe, so assert it.
        assert!(
            bob.sessions.keys().any(|(addr, _)| *addr == victim),
            "the IK handshake installs its own session rather than being refused"
        );

        // And the victim's genuine exchange still finishes, into a *second*
        // slot. Bob answers a replayed msg1 from its handshake cache, which is
        // the same msg2 the victim would have received.
        let msg2 = match bob.process_incoming(&msg1, victim) {
            IncomingResult::HandshakeResponse { packets, .. } => packets[0].clone(),
            _ => panic!("expected the cached msg2 for the victim's handshake"),
        };
        let mut scratch = [0u8; 256];
        initiator
            .read_message(&msg2[HEADER_LEN..], &mut scratch)
            .expect("the victim reads msg2");
        let mut msg3 = vec![0u8; HEADER_LEN + 256];
        msg3[0] = EMBER_MAGIC[0];
        msg3[1] = EMBER_MAGIC[1];
        msg3[2] = PKT_XX_MSG3;
        let n = initiator.write_message(&[], &mut msg3[HEADER_LEN..]).unwrap();
        msg3.truncate(HEADER_LEN + n);
        let _ = bob.process_incoming(&msg3, victim);

        assert!(
            bob.sessions
                .keys()
                .filter(|(addr, _)| *addr == victim)
                .count()
                >= 2,
            "the victim's own handshake completes alongside the forged one — \
             coexistence is what makes leaving the pending in place safe"
        );
    }

    /// A session that has never decrypted anything cannot be kept alive by our
    /// own sends. An on-path replay of a captured IK init installs exactly that
    /// — keys the real peer cannot read — and it used to be immortal.
    #[test]
    fn a_session_that_never_receives_anything_is_aged_out() {
        let (bob_priv, bob_pub) = make_keypair();
        let (alice_priv, alice_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        let init = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), b"hi") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        assert!(matches!(
            bob.process_incoming(&init, alice_addr),
            IncomingResult::HandshakeComplete { .. }
        ));
        let slot = *bob
            .sessions
            .keys()
            .find(|(addr, _)| *addr == alice_addr)
            .expect("bob installed a session");
        assert!(
            !bob.sessions[&slot].addr_validated,
            "a responder session starts unproven"
        );

        // Keep sending, as the DHT's liveness pings would.
        for _ in 0..3 {
            let _ = bob.prepare_outgoing(alice_addr, Some(&slot.1), b"ping");
        }
        // Backdate only what a send cannot touch. `checked_sub` because
        // `Instant` subtraction panics on a machine that has been up for less
        // than the timeout.
        if let Some(session) = bob.sessions.get_mut(&slot) {
            session.last_inbound = Instant::now()
                .checked_sub(SESSION_TIMEOUT + Duration::from_secs(1))
                .unwrap_or_else(Instant::now);
        }
        bob.cleanup();

        assert!(
            !bob.sessions.contains_key(&slot),
            "our own traffic must not keep an unproven session alive forever"
        );
    }

    /// The same rule has to hold for a session that *was* proven and then went
    /// dead, which is the ordinary case: the peer restarts or forgets its half,
    /// every frame we seal is unreadable, and our own sends kept the idle timer
    /// fresh. `fault_ember_contact` clears this for a routing-table contact on
    /// its first missed liveness ping, but a peer we hold no contact for is
    /// never pinged, so nothing else would ever reap it — and `has_live_session`
    /// reports it live meanwhile, which is what channel fan-out consults before
    /// choosing direct delivery over the relay.
    #[test]
    fn a_proven_session_that_goes_silent_is_aged_out_despite_our_own_sends() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        // A full exchange, so Alice's session is proven rather than merely
        // installed: she started it and read Bob's reply.
        let init = match alice.prepare_outgoing(bob_addr, Some(&bob_pub), b"hi") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        let resp = match bob.process_incoming(&init, alice_addr) {
            IncomingResult::HandshakeComplete {
                packets_to_send, ..
            } => packets_to_send,
            _ => panic!("expected HandshakeComplete"),
        };
        for packet in &resp {
            let _ = alice.dispatch_incoming(packet, bob_addr);
        }
        assert!(
            alice.has_live_session(&bob_addr, &bob_pub),
            "the session must be established before it can go stale"
        );

        // Bob vanishes. Alice keeps sending, as the DHT and channel fan-out do.
        for _ in 0..5 {
            let _ = alice.prepare_outgoing(bob_addr, Some(&bob_pub), b"still here?");
        }
        // Age past the timeout. Only `last_inbound` is backdated, because that
        // is the whole point: `last_activity` is whatever our last send set.
        if let Some(session) = alice.sessions.get_mut(&(bob_addr, bob_pub)) {
            session.last_inbound = Instant::now()
                .checked_sub(SESSION_TIMEOUT + Duration::from_secs(1))
                .unwrap_or_else(Instant::now);
        }
        alice.cleanup();

        assert!(
            !alice.has_live_session(&bob_addr, &bob_pub),
            "a peer we have not heard from in longer than SESSION_TIMEOUT must \
             not keep reporting as live just because we kept talking at it"
        );
    }

    /// Sessions are keyed per identity so peers sharing a NAT coexist. Tearing
    /// one down on its own ping timeout must not take the neighbours with it —
    /// the address-wide sweep this replaced dropped a working session, an
    /// in-flight handshake and a deferred first-contact payload belonging to a
    /// peer that had done nothing wrong.
    #[test]
    fn dropping_one_identity_spares_a_co_located_peer() {
        let (bob_priv, bob_pub) = make_keypair();
        let (alice_priv, alice_pub) = make_keypair();
        let (carol_priv, carol_pub) = make_keypair();
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut carol = EmberTransport::new(carol_priv, carol_pub);
        // One address, two identities — a CGNAT or a shared host.
        let shared: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        for peer in [&mut alice, &mut carol] {
            let init = match peer.prepare_outgoing(bob_addr, Some(&bob_pub), b"hi") {
                OutgoingResult::HandshakeStarted { packet } => packet,
                other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
            };
            assert!(matches!(
                bob.process_incoming(&init, shared),
                IncomingResult::HandshakeComplete { .. }
            ));
        }
        assert!(bob.sessions.contains_key(&(shared, alice_pub)));
        assert!(bob.sessions.contains_key(&(shared, carol_pub)));

        bob.remove_session_for(&shared, &alice_pub);

        assert!(
            !bob.sessions.contains_key(&(shared, alice_pub)),
            "the identity we gave up on must be gone"
        );
        assert!(
            bob.sessions.contains_key(&(shared, carol_pub)),
            "the peer that merely shares an address must keep its session"
        );
    }

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
            messages::build_find_value(node_id, 5, vec![[0x22; 16]], 0),
            messages::build_store_record(node_id, 6, [0x33; 16], vec![0u8; 32], [0u8; 64]),
            messages::build_store_ack(node_id, 7, [0x44; 16]),
            messages::build_found_value(node_id, 8, [0x55; 16], vec![vec![0u8; 32]], 1, 1),
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
            let encoded = messages::encode_message(&msg, &signing, true, &TEST_NOISE_PUB);
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

    /// An inbound XX handshake is created by an unauthenticated msg1, so an
    /// off-path attacker can mint one at a victim's address by forging the
    /// source. Left holding our outbound traffic it is a blackhole rather than a
    /// delay: every caller treats `Queued` as sent, so the frames die with the
    /// pending and the peer is faulted for never answering. Past the grace
    /// window we dial the identity we were asked for instead, which also takes
    /// the slot back — `handle_xx_msg1` refuses an inbound msg1 once one of our
    /// own handshakes is pending, so the stall cannot be renewed.
    #[test]
    fn a_stalled_inbound_xx_handshake_does_not_hold_our_traffic() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();

        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);

        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        let init_packet = match alice.prepare_outgoing(bob_addr, None, b"first msg from alice") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        match bob.process_incoming(&init_packet, alice_addr) {
            IncomingResult::HandshakeResponse { .. } => {}
            other => panic!(
                "expected HandshakeResponse after Bob sees msg1, got {:?}",
                std::mem::discriminant(&other)
            ),
        }

        // Alice's msg3 never arrives — the msg1 was forged and the real Alice
        // has no handshake in flight to finish.
        match bob.pending.get_mut(&alice_addr) {
            Some(PendingHandshake::XxResponderMsg2 { created, .. }) => {
                *created = Instant::now() - XX_RESPONDER_QUEUE_GRACE - Duration::from_secs(1);
            }
            _ => panic!("Bob should be holding a responder-side pending"),
        }

        match bob.prepare_outgoing(alice_addr, Some(&alice_pub), b"a query bob needs answered") {
            OutgoingResult::HandshakeStarted { .. } => {}
            other => panic!(
                "a stalled inbound handshake must not swallow our traffic, got {}",
                variant_name(&other)
            ),
        }
        assert!(
            matches!(
                bob.pending.get(&alice_addr),
                Some(PendingHandshake::IkInitiator { .. })
            ),
            "our own dial must own the slot afterwards, so the stall cannot be renewed"
        );
    }

    /// Regression: Bob (XX responder) calls `prepare_outgoing` while
    /// still in `XxResponderMsg2` (waiting for Alice's msg3). The
    /// payload must be queued and flushed as a transport packet once
    /// the handshake completes — not silently dropped (the previous
    /// behavior, which made dev-panel pings hang during this race).
    ///
    /// The grace window in `XX_RESPONDER_QUEUE_GRACE` exists to keep this case
    /// working: the honest race completes one round trip after msg2, and queuing
    /// is what delivers both sides' first message.
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

    /// An XX handshake does not learn who answered until it completes, so
    /// anything queued behind one was queued before its recipient was known.
    /// Those payloads used to be sealed to whoever turned up — starting with
    /// the msg3 payload, the very first thing written to the new session.
    ///
    /// `prepare_outgoing` refuses this outright for IK, where the target is
    /// known up front (see
    /// `a_payload_is_not_queued_onto_a_handshake_for_another_identity`). XX had
    /// no equivalent, and XX is exactly what an unkeyed `prepare_outgoing`
    /// starts — which is how the KAD bridge and the channel-neighbour probe
    /// dial every address whose Noise key we have not learned yet. A keyed
    /// caller reaching the same address in that window (a liveness ping to a
    /// contact we do have keys for) parked its frame behind the XX attempt.
    #[test]
    fn an_xx_handshake_does_not_deliver_a_payload_meant_for_another_identity() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let (_other_priv, other_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        let for_whoever = vec![0xC3u8; 96];
        let for_other = vec![0xD4u8; 96];

        // No key for the address, so this is an XX dial and the caller has
        // accepted whoever answers.
        let msg1 = match alice.prepare_outgoing(bob_addr, None, &for_whoever) {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };

        // A second caller does name an identity, and it is not the one that is
        // about to answer. Queuing is still the right answer to give it — the
        // honest case is that the address holds the peer it named — but the
        // handshake has to be the one that decides.
        assert!(
            matches!(
                alice.prepare_outgoing(bob_addr, Some(&other_pub), &for_other),
                OutgoingResult::Queued
            ),
            "a keyed caller behind an XX dial still queues"
        );

        let msg2 = match bob.process_incoming(&msg1, alice_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => packets,
            other => panic!("expected msg2, got {:?}", std::mem::discriminant(&other)),
        };
        let msg3 = match alice.process_incoming(&msg2[0], bob_addr) {
            IncomingResult::HandshakeComplete {
                packets_to_send,
                remote_noise_pub,
                ..
            } => {
                assert_eq!(remote_noise_pub, bob_pub, "Bob is who answered");
                packets_to_send
            }
            other => panic!(
                "expected HandshakeComplete, got {:?}",
                std::mem::discriminant(&other)
            ),
        };
        assert_eq!(
            msg3.len(),
            1,
            "only msg3 goes out: the payload for another identity is not Bob's to receive"
        );

        match bob.process_incoming(&msg3[0], alice_addr) {
            IncomingResult::HandshakeComplete {
                decrypted_payload, ..
            } => {
                assert_eq!(
                    decrypted_payload,
                    Some(for_whoever),
                    "the unkeyed caller's payload is the one addressed to whoever answered"
                );
            }
            other => panic!(
                "expected HandshakeComplete, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    /// The responder half of the same rule. The msg2→msg3 window is held open
    /// deliberately by `XX_RESPONDER_QUEUE_GRACE` so the honest race delivers
    /// both sides' first message, and in that race the queued payload really is
    /// for the peer completing the handshake. It is only when it is not that
    /// the queue must hold it back.
    #[test]
    fn an_xx_responder_does_not_flush_a_payload_meant_for_another_identity() {
        let (alice_priv, alice_pub) = make_keypair();
        let (bob_priv, bob_pub) = make_keypair();
        let (_other_priv, other_pub) = make_keypair();
        let mut alice = EmberTransport::new(alice_priv, alice_pub);
        let mut bob = EmberTransport::new(bob_priv, bob_pub);
        let alice_addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let bob_addr: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        let msg1 = match alice.prepare_outgoing(bob_addr, None, b"hi") {
            OutgoingResult::HandshakeStarted { packet } => packet,
            other => panic!("expected HandshakeStarted, got {}", variant_name(&other)),
        };
        let msg2 = match bob.process_incoming(&msg1, alice_addr) {
            IncomingResult::HandshakeResponse { packets, .. } => packets,
            other => panic!("expected msg2, got {:?}", std::mem::discriminant(&other)),
        };

        // Bob has an inbound XX in flight and no session yet, so this queues —
        // but it names a third identity, not the Alice who is completing.
        let for_other = b"not for the peer completing this handshake";
        assert!(
            matches!(
                bob.prepare_outgoing(alice_addr, Some(&other_pub), for_other),
                OutgoingResult::Queued
            ),
            "the msg2 window queues, as the grace period intends"
        );
        assert_ne!(other_pub, alice_pub);

        let msg3 = match alice.process_incoming(&msg2[0], bob_addr) {
            IncomingResult::HandshakeComplete {
                packets_to_send, ..
            } => packets_to_send,
            other => panic!(
                "expected HandshakeComplete, got {:?}",
                std::mem::discriminant(&other)
            ),
        };
        match bob.process_incoming(&msg3[0], alice_addr) {
            IncomingResult::HandshakeComplete {
                packets_to_send, ..
            } => {
                assert!(
                    packets_to_send.is_empty(),
                    "nothing queued here was addressed to Alice, so nothing is flushed to her"
                );
            }
            other => panic!(
                "expected HandshakeComplete, got {:?}",
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

    fn incoming_variant_name(r: &IncomingResult) -> &'static str {
        match r {
            IncomingResult::Message { .. } => "Message",
            IncomingResult::HandshakeResponse { .. } => "HandshakeResponse",
            IncomingResult::HandshakeComplete { .. } => "HandshakeComplete",
            IncomingResult::Rejected => "Rejected",
        }
    }
}
