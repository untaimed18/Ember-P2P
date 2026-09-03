use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};

use super::{
    EmberContact, EmberNodeId, EMBER_DHT_MIN_VERSION, EMBER_DHT_VERSION, MAX_CONTACTS_PER_RESPONSE,
};
use crate::network::ember::crypto;

// ── Message types ──

pub const MSG_PING: u8 = 0x01;
pub const MSG_PONG: u8 = 0x02;
pub const MSG_FIND_NODE: u8 = 0x03;
pub const MSG_FOUND_NODE: u8 = 0x04;
pub const MSG_STORE_RECORD: u8 = 0x05;
pub const MSG_STORE_ACK: u8 = 0x06;
pub const MSG_FIND_VALUE: u8 = 0x07;
pub const MSG_FOUND_VALUE: u8 = 0x08;
pub const MSG_ANNOUNCE_PEER: u8 = 0x09;
pub const MSG_PEER_LIST: u8 = 0x0A;
/// Firewalled peer → HighID buddy: please fan out this publisher-signed
/// source `STORE_RECORD` payload on our behalf.
pub const MSG_PROXY_STORE: u8 = 0x0B;
/// Buddy → firewalled peer: accepted the proxy request (not a DHT STORE_ACK).
pub const MSG_PROXY_STORE_ACK: u8 = 0x0C;
/// Several records for one destination in a single frame.
pub const MSG_STORE_BATCH: u8 = 0x0D;
/// Answer to `STORE_BATCH`, reporting how many of its records were stored.
pub const MSG_STORE_BATCH_ACK: u8 = 0x0E;
/// Searcher → HighID buddy: please tell `publisher_id` to connect back to us.
///
/// Additive: a v2 peer that does not speak this type decodes it as
/// [`DhtPayload::Unknown`] and ignores it. The DHT header layout is unchanged,
/// so this is not a version bump.
pub const MSG_CALLBACK_REQ: u8 = 0x0F;
/// Buddy → firewalled publisher: connect to this searcher for `file_hash`.
pub const MSG_CALLBACK: u8 = 0x10;
/// Channel gossip body. `0x0F`/`0x10` are Ember callback; these are next.
pub const MSG_CHANNEL_MSG: u8 = 0x11;
/// Ask a HighID overlay contact to forward a `CHANNEL_MSG` to a LowID target.
/// Capability-bound rooms use this instead of the friend WebSocket broker.
pub const MSG_CHANNEL_RELAY: u8 = 0x12;
// The endorse pair sits after the channel types deliberately. Message
// numbering is global to the overlay, not to a branch: a `BUDDY_ENDORSE_REQ`
// carries no payload and its decoder ignores the body, so sharing a number with
// `CHANNEL_MSG` would have a channel frame decode cleanly on that arm and draw
// a signed endorsement in reply.
/// Firewalled publisher → candidate buddy: sign your own endpoint for me, so
/// I can name you in a source trailer and searchers can verify it offline.
///
/// Empty payload — the requester is the authenticated frame `sender_id`, and
/// that is what the endorsement is bound to.
///
/// Additive like `CALLBACK_REQ`: a peer that does not speak this type decodes
/// it as [`DhtPayload::Unknown`] and ignores it, which reads to the requester
/// as a buddy that cannot be named. Not a version bump.
pub const MSG_BUDDY_ENDORSE_REQ: u8 = 0x13;
/// Buddy → firewalled publisher: my endpoint, signed by my identity key and
/// bound to you and an expiry.
pub const MSG_BUDDY_ENDORSE: u8 = 0x14;

/// `CALLBACK_REQ` body: publisher node id, file hash, searcher TCP port,
/// crypt options, searcher eD2K user hash, callback token. The searcher's
/// IP is the UDP source the buddy observed — it is not in the payload.
pub const CALLBACK_REQ_WIRE_LEN: usize = 16 + 16 + 2 + 1 + 16 + 16;
/// `CALLBACK` body: file hash, searcher IPv4, TCP port, crypt options,
/// searcher user hash, callback token.
pub const CALLBACK_WIRE_LEN: usize = 16 + 4 + 2 + 1 + 16 + 16;
/// `BUDDY_ENDORSE` body: the endpoint the buddy asserts is its own (ipv4(4) +
/// udp_port(2) + noise_pub(32)), the expiry, and the buddy's signature over
/// all of it. The signing key is the frame's sender key, which `decode_message`
/// has already bound to `sender_id`, so it is not repeated here.
pub const BUDDY_ENDORSE_WIRE_LEN: usize = 4 + 2 + 32 + 8 + 64;

/// Records one `STORE_BATCH` may carry.
///
/// This bounds the decode-side allocation and the width of the ack bitmap
/// (one `u64`). It is not the binding limit in practice: the datagram budget
/// caps a real batch at roughly twenty minimum-size records, so do not size
/// anything against 64 expecting it to be reachable.
pub const MAX_STORE_BATCH_RECORDS: usize = 64;
// The ack is a `u64` bitmap indexed by record position, so `1u64 << i` for the
// last record has to be representable. Raising the constant without widening
// the bitmap would turn an attacker-controlled count into a shift overflow.
const _: () = assert!(MAX_STORE_BATCH_RECORDS <= u64::BITS as usize);

/// Maximum keys in a FIND_VALUE request.
pub const MAX_FIND_VALUE_KEYS: usize = 8;
/// Maximum records in a FOUND_VALUE response.
pub const MAX_FOUND_VALUE_RECORDS: usize = 300;

/// Bytes a signed frame adds around its payload: the 22-byte header, the
/// 32-byte sender public key, the 2-byte payload length, and the 64-byte
/// signature.
pub(crate) const FRAME_OVERHEAD: usize = HEADER_MIN_SIZE + 32 + 2 + 64;
/// Bytes the Noise transport adds around a frame: 3-byte header, 8-byte
/// nonce, 16-byte AEAD tag.
pub(crate) const TRANSPORT_OVERHEAD: usize = 3 + 8 + 16;

/// Largest payload that still yields a deliverable datagram.
///
/// A receiver drops anything over `MAX_EMBER_DATAGRAM_BYTES` before it is
/// decrypted, so an oversized reply is built, encrypted, and sent looking
/// entirely successful while the peer never sees it — the sender observes
/// only a timeout. This is also the decode bound, so the limits on the two
/// sides cannot drift apart. `a_full_found_value_frame_fits_a_datagram` pins
/// the arithmetic.
pub const MAX_DELIVERABLE_PAYLOAD: usize =
    crate::network::ember::transport::MAX_EMBER_DATAGRAM_BYTES
        - TRANSPORT_OVERHEAD
        - FRAME_OVERHEAD;

/// Maximum DHT payload bytes accepted on decode. Anything larger could not
/// have reached us intact, since the transport drops oversized datagrams
/// before decryption.
pub const MAX_DHT_PAYLOAD: usize = MAX_DELIVERABLE_PAYLOAD;

/// A UDP payload this size will not be IP-fragmented on ordinary paths.
///
/// Fragmented UDP is dropped outright by a fair number of consumer NATs and
/// some ISPs, and a reply that never arrives is worse than a shorter one that
/// does. The legacy KAD stack holds the same line with
/// `UDP_KAD_MAXFRAGMENT` (1420); this is the Ember equivalent, applied to the
/// responses whose size we actually choose.
pub const MAX_UNFRAGMENTED_DATAGRAM: usize = 1400;

/// Payload budget that keeps a signed frame inside
/// [`MAX_UNFRAGMENTED_DATAGRAM`].
pub const MAX_UNFRAGMENTED_PAYLOAD: usize =
    MAX_UNFRAGMENTED_DATAGRAM - TRANSPORT_OVERHEAD - FRAME_OVERHEAD;

/// Bytes a `FOUND_VALUE` spends before its first blob: `key(16) ||
/// next_position(2) || total_available(2) || record_count(2)`.
const FOUND_VALUE_HEADER_LEN: usize = 16 + 2 + 2 + 2;

/// Byte budget for the record blobs in a `FOUND_VALUE`, after
/// [`FOUND_VALUE_HEADER_LEN`]. Each blob also costs a 2-byte length prefix.
///
/// Budgeted against the unfragmented limit like every other response whose
/// size we choose (FOUND_NODE, PEER_LIST, STORE_BATCH). Using the 4 KB decode
/// cap here produced ~4 KB datagrams that fragment on any normal MTU — and
/// the node holding the most records for a popular keyword is exactly the one
/// whose answers were then most likely to be dropped in transit. The searcher
/// read that as a timeout and charged the responder a failure, so after three
/// of them a healthy, well-stocked storer was evicted from the routing table.
pub const MAX_FOUND_VALUE_RECORD_BYTES: usize =
    MAX_UNFRAGMENTED_PAYLOAD - FOUND_VALUE_HEADER_LEN;

/// Length prefix each `FOUND_VALUE` blob carries on the wire.
const FOUND_VALUE_BLOB_LEN_PREFIX: usize = 2;
/// Publisher Ed25519 signature appended to a record body in a `FOUND_VALUE` blob.
const FOUND_VALUE_BLOB_SIGNATURE_LEN: usize = 64;

/// Maximum STORE / PROXY_STORE / STORE_BATCH record body size.
///
/// Bounded by what a `FOUND_VALUE` can pack even as the only blob in the
/// reply (`2` length prefix + body + `64` signature). The deliverable (~4 KiB)
/// cap used to admit bodies the unfragmented packer then skipped, so a huge
/// filename could store-but-hide: live under the key, invisible to searchers,
/// and if every live record was oversized the peer answered `FOUND_NODE` as
/// if the key were empty.
pub const MAX_STORE_RECORD_BYTES: usize = MAX_FOUND_VALUE_RECORD_BYTES
    .saturating_sub(FOUND_VALUE_BLOB_LEN_PREFIX)
    .saturating_sub(FOUND_VALUE_BLOB_SIGNATURE_LEN);

/// Minimum STORE / PROXY_STORE / STORE_BATCH record body size: the fixed
/// header every record carries ahead of its (possibly empty) file name.
///
/// `SignedRecord::from_wire` reads that header at fixed offsets and refuses
/// anything shorter, so a shorter body could never be parsed, verified against
/// its own key, or served — only held, counted, and rejected again by every
/// reader. `DhtStore::store_attributed` enforces it at acceptance, which is
/// what allows [`MIN_FOUND_VALUE_RECORD_BYTES`] to be a real record's floor
/// rather than the wire format's.
pub const MIN_STORE_RECORD_BYTES: usize = super::publish::RECORD_HEADER_LEN;

/// Maximum `FOUND_VALUE` blob (`record_body || signature`). Distinct from
/// [`MAX_STORE_RECORD_BYTES`], which is the body alone.
pub const MAX_FOUND_VALUE_BLOB_BYTES: usize =
    MAX_STORE_RECORD_BYTES + FOUND_VALUE_BLOB_SIGNATURE_LEN;

/// Fewest bytes a record can possibly cost a `FOUND_VALUE` page: the length
/// prefix, the shortest body the store will hold, and the signature.
///
/// The packer stops scanning a key once less than this is left, which bounds
/// the tail walk on a key holding a thousand records instead of touching every
/// one of them to learn that none of them fits. The floor may only be as high
/// as what [`MIN_STORE_RECORD_BYTES`] guarantees at acceptance — assume more
/// and the packer skips a record it is holding rather than merely stopping
/// early. It was once the *format's* floor (a prefix and a signature around an
/// empty body) for want of that guarantee, and at 66 bytes the stop fired only
/// when the budget was all but spent, so on a hot key of similarly sized
/// records it usually never fired at all.
pub const MIN_FOUND_VALUE_RECORD_BYTES: usize =
    FOUND_VALUE_BLOB_LEN_PREFIX + MIN_STORE_RECORD_BYTES + FOUND_VALUE_BLOB_SIGNATURE_LEN;

const _: () = assert!(
    FOUND_VALUE_BLOB_LEN_PREFIX + MAX_STORE_RECORD_BYTES + FOUND_VALUE_BLOB_SIGNATURE_LEN
        <= MAX_FOUND_VALUE_RECORD_BYTES
);
// Forward progress in the `FOUND_VALUE` packer, which is what makes paging
// terminate: the record at the requested start faces an untouched budget, so
// the early stop must not fire there or a page could serve nothing and the
// searcher would be handed a `next_position` it has already asked for. Implied
// today by the assert above plus `MIN_STORE_RECORD_BYTES <=
// MAX_STORE_RECORD_BYTES`, and spelled out because those two are free to move
// independently of each other.
const _: () = assert!(MIN_FOUND_VALUE_RECORD_BYTES <= MAX_FOUND_VALUE_RECORD_BYTES);
// A single-blob `FOUND_VALUE` payload is the header plus `blob_len(2) || body ||
// signature(64)` — see the `DhtPayload::FoundValue` encoder. This used to spell
// the header out as `16 + 2` and drifted the moment paging widened it, which is
// why it now shares [`FOUND_VALUE_HEADER_LEN`] with both the encoder's budget
// and the decoder's offset. With current constants both sides are exactly equal.
const _: () = assert!(
    FOUND_VALUE_HEADER_LEN
        + FOUND_VALUE_BLOB_LEN_PREFIX
        + MAX_STORE_RECORD_BYTES
        + FOUND_VALUE_BLOB_SIGNATURE_LEN
        <= MAX_UNFRAGMENTED_PAYLOAD
);

// Address type flags
const ADDR_IPV4: u8 = 0x04;
const ADDR_IPV6: u8 = 0x06;

/// Wire size of one IPv4 contact in a contact list: `addr_type(1) + ip(4) +
/// port(2) + noise_pub(32) + ed25519_pub(32)`.
///
/// v2 spent another 16 bytes per contact restating the node ID, which is
/// `BLAKE3(ed25519_pub)[..16]` and was re-derived by every decoder rather than
/// trusted — so the only thing those bytes could do was disagree with the key
/// beside them. Dropping them took a contact from 87 to 71 and a `FOUND_NODE`
/// from 14 contacts to 17, which is most of a hop on a sparse table.
/// `a_found_node_carries_more_contacts_than_v2_could` pins the count.
pub const CONTACT_WIRE_LEN_IPV4: usize = 1 + 4 + 2 + 32 + 32;

/// The most a contact list can legitimately occupy: the declared count cap at
/// the IPv6 contact size, plus the count byte.
///
/// [`decode_contact_list`] already refuses a count above
/// [`MAX_CONTACTS_PER_RESPONSE`] and bounds every read, so this is not needed
/// to parse safely. It is here for the friend-session path, where the list
/// arrives over TCP with no datagram ceiling in front of it: a body far larger
/// than this cannot be a contact list whatever it decodes to, and is cheaper to
/// refuse by length than to carry through a channel first.
pub const MAX_CONTACT_LIST_BYTES: usize = 1 + MAX_CONTACTS_PER_RESPONSE * (1 + 16 + 2 + 32 + 32);

/// Header size without public key (used after encrypted session established):
/// version(1) + msg_type(1) + request_id(4) + sender_node_id(16) = 22 bytes
const HEADER_MIN_SIZE: usize = 22;

/// Parsed Ember DHT message.
#[derive(Debug, Clone)]
pub struct DhtMessage {
    pub version: u8,
    pub msg_type: u8,
    pub request_id: u32,
    pub sender_id: EmberNodeId,
    /// Sender's Ed25519 public key (only present in cleartext/handshake messages,
    /// omitted in encrypted sessions where we already know it).
    pub sender_pub_key: Option<[u8; 32]>,
    pub payload: DhtPayload,
    /// Per-frame Ed25519 signature over every preceding byte.
    ///
    /// Never read after construction, and deliberately so: [`decode_message`]
    /// verifies it (and the `sender_id == BLAKE3(pubkey)[..16]` binding)
    /// against the raw wire bytes *before* building this struct, bailing on
    /// failure. A `DhtMessage` therefore only ever exists in verified form,
    /// and re-checking here would invite a caller to treat verification as
    /// its own responsibility. The builders leave it zeroed for
    /// [`encode_message`] to fill.
    #[allow(dead_code)]
    pub signature: [u8; 64],
}

/// One record inside a [`DhtPayload::StoreBatch`], carrying exactly what a
/// single `STORE_RECORD` would.
#[derive(Debug, Clone)]
pub struct BatchedRecord {
    pub key: [u8; 16],
    pub record: Vec<u8>,
    pub record_signature: [u8; 64],
}

/// Payload variants for each message type.
#[derive(Debug, Clone)]
pub enum DhtPayload {
    Ping,
    /// Optional observed address of the ping sender (slice 19). Empty
    /// payload decodes as `None` for backward compatibility.
    Pong {
        observed: Option<SocketAddr>,
    },
    FindNode {
        target: EmberNodeId,
    },
    FoundNode {
        contacts: Vec<EmberContact>,
    },
    StoreRecord {
        key: [u8; 16],
        record: Vec<u8>,
        record_signature: [u8; 64],
    },
    StoreAck {
        key: [u8; 16],
    },
    /// Same body as [`DhtPayload::StoreRecord`]; asks the receiver to
    /// re-`STORE` a firewalled source record on the publisher's behalf.
    ProxyStore {
        key: [u8; 16],
        record: Vec<u8>,
        record_signature: [u8; 64],
    },
    ProxyStoreAck {
        key: [u8; 16],
    },
    /// Several records bound for the same node in one frame.
    ///
    /// Publishing a large library one datagram per (record, target) puts the
    /// frame count in proportion to records, which both saturates the link
    /// and trips the receiver's per-peer rate limit. Records destined for the
    /// same peer travel together instead, so frame count scales with the
    /// number of peers.
    StoreBatch {
        records: Vec<BatchedRecord>,
    },
    /// Which records of the matching `STORE_BATCH` were accepted, as a
    /// bitmap over the batch's record positions (bit `i` = record `i`).
    ///
    /// A count alone is not enough. Acceptance is per record — the storer
    /// re-evaluates proximity against its own table and applies its own
    /// capacity limits — so a batch is routinely accepted in part. Reporting
    /// only a total forced the publisher to treat "some landed" as "all
    /// landed" and retire every file in the batch, including ones that were
    /// never stored. [`MAX_STORE_BATCH_RECORDS`] is 64 so one `u64` covers a
    /// full batch.
    StoreBatchAck {
        accepted: u64,
    },
    FindValue {
        keys: Vec<[u8; 16]>,
        /// Index into the responder's live record list for `keys[0]` at which
        /// this answer should begin.
        ///
        /// A datagram fits roughly five keyword records, so a popular key holds
        /// far more than one reply can carry. Without an offset the only records
        /// a node would ever serve were the first that fit, and the rest were
        /// held but unreachable — visible in `get_live` and the diagnostics,
        /// invisible to every searcher.
        ///
        /// Positions are advisory: the responder's list shifts as records expire
        /// and are evicted, so paging is best-effort and may repeat or skip an
        /// entry across pages. That is the same guarantee a Kademlia walk gives
        /// for contacts, and the searcher dedups by blob hash regardless.
        start_position: u16,
    },
    FoundValue {
        key: [u8; 16],
        records: Vec<Vec<u8>>,
        /// Where the searcher should resume to continue past this page.
        ///
        /// The responder reports this rather than letting the searcher add
        /// `records.len()` to what it asked, because the packer skips records
        /// too large for the remaining budget and keeps scanning — so the
        /// records served are not always a contiguous run. Adding the count
        /// would step over the skipped positions and hide them permanently.
        next_position: u16,
        /// Live records matching the query, whether or not this page carries
        /// them. `next_position >= total_available` means the key is exhausted.
        total_available: u16,
    },
    AnnouncePeer {
        contacts: Vec<EmberContact>,
    },
    PeerList {
        contacts: Vec<EmberContact>,
    },
    /// Authenticated channel gossip. The DHT frame already binds the sender;
    /// the body is AEAD under the channel content key (see `ember::channel`).
    ChannelMsg {
        body: Vec<u8>,
    },
    /// Opaque `CHANNEL_MSG` body plus channel/target ids. Relays cannot
    /// decrypt the gossip; they only forward to a UDP session they already have.
    ChannelRelay {
        body: Vec<u8>,
    },
    /// Searcher → buddy. `searcher_tcp_port` is claimed (UDP cannot observe
    /// TCP); the buddy fills the publisher-facing `CALLBACK` from the
    /// datagram's source address, not from anything here.
    CallbackReq {
        publisher_id: EmberNodeId,
        file_hash: [u8; 16],
        searcher_tcp_port: u16,
        crypt_options: u8,
        searcher_user_hash: [u8; 16],
        callback_token: [u8; 16],
    },
    /// Buddy → firewalled publisher. `searcher_ip` is the address the buddy
    /// received `CALLBACK_REQ` from. `callback_token` is copied from the
    /// request so the publisher can bind connect-back to a file it asked
    /// this buddy to proxy.
    Callback {
        file_hash: [u8; 16],
        searcher_ip: Ipv4Addr,
        searcher_tcp_port: u16,
        crypt_options: u8,
        searcher_user_hash: [u8; 16],
        callback_token: [u8; 16],
    },
    /// Publisher → candidate buddy. No body: the endorsement is bound to the
    /// authenticated `sender_id`, so there is nothing here for a requester to
    /// influence — in particular it cannot ask for an endpoint of its choosing.
    BuddyEndorseReq,
    /// Buddy → publisher. The buddy's own endpoint plus its signature over it.
    ///
    /// The publisher copies this verbatim into the source trailer, so the
    /// endpoint a searcher dials is authored entirely by the node that will
    /// receive the `CALLBACK_REQ` — never by the publisher's observation of it.
    BuddyEndorse {
        ip: Ipv4Addr,
        udp_port: u16,
        noise_pub: [u8; 32],
        expires_at: i64,
        signature: [u8; 64],
    },
    Unknown(Vec<u8>),
}

/// Encode a DHT message into wire format, signing with the sender's Ed25519 key.
///
/// If `include_pub_key` is true, the sender's 32-byte Ed25519 public key is
/// included in the header (used for initial messages before encryption is established).
///
/// `sender_noise_pub` is our own Noise static public key. It is appended to the
/// signed bytes but never written to the wire: the peer learned it from the
/// handshake, so restating it would waste 32 bytes per frame. Signing over it is
/// what stops the frame being a bearer token — see [`EMBER_DHT_VERSION`]. Our
/// *own* key rather than the recipient's, deliberately: we always know it (an
/// XX handshake has not yet revealed the responder's), and one frame can still
/// be addressed to many peers.
pub fn encode_message(
    msg: &DhtMessage,
    signing_key: &ed25519_dalek::SigningKey,
    include_pub_key: bool,
    sender_noise_pub: &[u8; 32],
) -> Vec<u8> {
    let mut payload_bytes = encode_payload(&msg.payload);
    // The length prefix is a u16 and the peer drops anything over the
    // datagram cap, so an oversized payload used to be written with a
    // truncated length and signed over the mismatch — a frame that is
    // self-consistently wrong. Every encoder is bounded, so reaching this is
    // a bug; clamp so the frame stays coherent and say so loudly.
    if payload_bytes.len() > MAX_DELIVERABLE_PAYLOAD {
        debug_assert!(
            false,
            "DHT payload of {} bytes exceeds the deliverable maximum {}",
            payload_bytes.len(),
            MAX_DELIVERABLE_PAYLOAD
        );
        tracing::error!(
            "Ember DHT: truncating oversized {} payload ({} > {})",
            msg.msg_type,
            payload_bytes.len(),
            MAX_DELIVERABLE_PAYLOAD
        );
        payload_bytes.truncate(MAX_DELIVERABLE_PAYLOAD);
    }
    let payload_len = payload_bytes.len();

    let pub_key_bytes = if include_pub_key { 32 } else { 0 };
    let total = HEADER_MIN_SIZE + pub_key_bytes + 2 + payload_len + 64;

    let mut buf = Vec::with_capacity(total);
    buf.write_u8(msg.version).unwrap();
    buf.write_u8(msg.msg_type).unwrap();
    buf.write_u32::<LittleEndian>(msg.request_id).unwrap();
    buf.write_all(&msg.sender_id.0).unwrap();

    if include_pub_key {
        buf.write_all(&signing_key.verifying_key().to_bytes())
            .unwrap();
    }

    buf.write_u16::<LittleEndian>(payload_len as u16).unwrap();
    buf.write_all(&payload_bytes).unwrap();

    // Sign everything so far, plus the domain tag and our Noise static key.
    // Appended and then cut back rather than signed over a copy, so binding the
    // session costs no allocation on a path that runs per outbound frame.
    let suffix_len = frame_signing_suffix(&mut buf, sender_noise_pub);
    let sig = crypto::sign(signing_key, &buf);
    buf.truncate(buf.len() - suffix_len);
    buf.write_all(&sig).unwrap();

    buf
}

/// Domain tag mixed into every DHT frame signature.
///
/// The identity key also signs stored records (`SignedRecord`), and neither
/// preimage carried a context string — the only thing keeping a signature over
/// one from being read as the other was that both formats happen to require the
/// signer's own key at a fixed offset, which is an accident that any future
/// field addition would quietly spend. Everything else in the tree that signs
/// with this key is already separated (`BUDDY_ENDORSE_DOMAIN`, `RDV_DOMAIN`,
/// `ember_auth`), so this brings frames in line.
///
/// Appended rather than prepended, unlike those. They build a preimage from
/// scratch; this one signs a buffer that is already the frame, and appending is
/// what lets the suffix be cut back off without copying it. Separation does not
/// care which end it sits at, only that no other context can produce the same
/// bytes — and no record body ends with this tag followed by a static key.
///
/// The version is inside the tag deliberately: changing the wire format changes
/// the domain, so a v4 signature can never be replayed as a v5 one. It has to
/// be edited by hand alongside [`EMBER_DHT_VERSION`], which the test below
/// pins.
const DHT_FRAME_DOMAIN: &[u8] = b"ember-dht-frame-v4";

/// Append the bytes a frame signature covers beyond the frame itself, returning
/// how many were added so the caller can cut them back off.
///
/// Kept in one place because the encoder and the verifier have to agree byte
/// for byte, and they are three hundred lines apart.
fn frame_signing_suffix(buf: &mut Vec<u8>, noise_pub: &[u8; 32]) -> usize {
    buf.extend_from_slice(DHT_FRAME_DOMAIN);
    buf.extend_from_slice(noise_pub);
    DHT_FRAME_DOMAIN.len() + 32
}

/// The version byte of a DHT frame, if it is outside the range this build
/// can parse.
///
/// Version 0 is not a peer we could upgrade — it is garbage — so it is left
/// to the ordinary malformed path. A non-zero byte outside
/// [`EMBER_DHT_MIN_VERSION`]..=[`EMBER_DHT_VERSION`] is a peer speaking a
/// layout we refused at the version byte rather than misparsed.
pub fn unsupported_dht_version(data: &[u8]) -> Option<u8> {
    let version = *data.first()?;
    if version == 0 {
        return None;
    }
    if version < EMBER_DHT_MIN_VERSION || version > EMBER_DHT_VERSION {
        Some(version)
    } else {
        None
    }
}

/// Whether an unsupported version byte means the sender is ahead of this build.
///
/// [`unsupported_dht_version`] only returns `Some` for a non-zero byte outside
/// [`EMBER_DHT_MIN_VERSION`]..=[`EMBER_DHT_VERSION`]. Above that range we are
/// the one who cannot speak the overlay; below it, they are. The Ember page
/// uses this split so "check for an update" is not shown when the far end is
/// the one that needs to upgrade. A high byte is only a hint: anyone who
/// completed a Noise handshake can send one, so the install path is still the
/// signed updater, never a URL from the peer.
pub fn dht_version_is_newer_than_us(version: u8) -> bool {
    version > EMBER_DHT_VERSION
}

/// Decode a DHT message from wire format.
///
/// `has_pub_key`: whether the sender's public key is present in the header
/// (should be true for messages received outside encrypted sessions).
///
/// `session_noise_pub` is the peer static key the Noise handshake proved for
/// the session this frame arrived on. The signature is checked over the frame
/// *plus* that key, so a frame signed for one session cannot verify on another
/// — which is what makes a captured frame useless to a replayer. See
/// [`EMBER_DHT_VERSION`].
pub fn decode_message(
    data: &[u8],
    has_pub_key: bool,
    session_noise_pub: &[u8; 32],
) -> anyhow::Result<DhtMessage> {
    let pub_key_size = if has_pub_key { 32 } else { 0 };
    let min_size = HEADER_MIN_SIZE + pub_key_size + 2 + 64; // header + payload_len + signature
    if data.len() < min_size {
        anyhow::bail!(
            "DHT message too short ({} bytes, need at least {min_size})",
            data.len()
        );
    }

    let mut cursor = Cursor::new(data);
    let version = cursor.read_u8()?;
    if version == 0 {
        anyhow::bail!("Invalid DHT version 0");
    }
    // Both ends of the range, not just the upper one. Refusing only *newer*
    // versions meant an older peer's frames were accepted and then misparsed,
    // because the version byte was never raised when the layout changed. A peer
    // we cannot parse has to be refused here, where it reads as a version
    // mismatch, rather than deeper in as a malformed payload.
    if version < EMBER_DHT_MIN_VERSION || version > EMBER_DHT_VERSION {
        anyhow::bail!(
            "Unsupported DHT version {version} (this build speaks \
             {EMBER_DHT_MIN_VERSION}..={EMBER_DHT_VERSION})"
        );
    }
    let msg_type = cursor.read_u8()?;
    let request_id = cursor.read_u32::<LittleEndian>()?;

    let mut sender_id_bytes = [0u8; 16];
    cursor.read_exact(&mut sender_id_bytes)?;
    let sender_id = EmberNodeId(sender_id_bytes);

    let sender_pub_key = if has_pub_key {
        let mut key = [0u8; 32];
        cursor.read_exact(&mut key)?;
        Some(key)
    } else {
        None
    };

    let payload_len = cursor.read_u16::<LittleEndian>()? as usize;
    if payload_len > MAX_DHT_PAYLOAD {
        anyhow::bail!("DHT payload_len {payload_len} exceeds max {MAX_DHT_PAYLOAD}");
    }
    let pos = cursor.position() as usize;
    if pos + payload_len + 64 > data.len() {
        anyhow::bail!(
            "DHT message truncated: payload_len={payload_len}, remaining={}",
            data.len() - pos
        );
    }

    let payload_data = &data[pos..pos + payload_len];
    let sig_offset = pos + payload_len;
    if data.len() != sig_offset + 64 {
        anyhow::bail!(
            "DHT message has trailing bytes after signature (len={}, expected {})",
            data.len(),
            sig_offset + 64
        );
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[sig_offset..sig_offset + 64]);

    // Verify the signature and the identity binding. Both live behind the
    // public key being present, so a `has_pub_key = false` call would return a
    // fully-formed but entirely unauthenticated `DhtMessage`. Every encoder in
    // the tree sets `include_pub_key: true` and the only production caller
    // decodes with `true`, so refusing the other case costs nothing and stops
    // a future caller from silently opting out of authentication.
    let Some(ref pk_bytes) = sender_pub_key else {
        anyhow::bail!("DHT message carries no public key, so it cannot be authenticated");
    };
    let Some(pk) = crypto::verifying_key_from_bytes(pk_bytes) else {
        anyhow::bail!("Invalid Ed25519 public key in DHT message");
    };
    // The sender signed the frame with its own Noise static key appended. We
    // check against the key the handshake proved for *this* session, so a frame
    // captured from another session fails here rather than being accepted as
    // proof that its sender_id lives at the address that delivered it.
    let mut signed_data = Vec::with_capacity(sig_offset + DHT_FRAME_DOMAIN.len() + 32);
    signed_data.extend_from_slice(&data[..sig_offset]);
    frame_signing_suffix(&mut signed_data, session_noise_pub);
    if !crypto::verify(&pk, &signed_data, &signature) {
        anyhow::bail!("DHT message signature verification failed");
    }
    // Bind sender_id to the public key. The signature only proves the
    // sender holds *some* key; without this check a peer could sign with
    // their own key while claiming a victim's sender_id (routing-table
    // poisoning / impersonation in FOUND_NODE, STORE_RECORD, etc.).
    // `node_id == BLAKE3(pubkey)[..16]` everywhere else in Ember.
    if !crypto::verify_ember_hash_binding(pk_bytes, &sender_id.0) {
        anyhow::bail!("DHT message sender_id does not match its public key");
    }

    let payload = decode_payload(msg_type, payload_data)?;

    Ok(DhtMessage {
        version,
        msg_type,
        request_id,
        sender_id,
        sender_pub_key,
        payload,
        signature,
    })
}

/// Build a PING message.
pub fn build_ping(sender_id: EmberNodeId, request_id: u32) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_PING,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::Ping,
        signature: [0u8; 64], // filled by encode_message
    }
}

/// Build a PONG response carrying the sender's observed address.
pub fn build_pong(sender_id: EmberNodeId, request_id: u32, observed: SocketAddr) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_PONG,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::Pong {
            observed: Some(observed),
        },
        signature: [0u8; 64],
    }
}

/// Build a FIND_NODE request.
pub fn build_find_node(sender_id: EmberNodeId, request_id: u32, target: EmberNodeId) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_FIND_NODE,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::FindNode { target },
        signature: [0u8; 64],
    }
}

/// Build a FOUND_NODE response.
pub fn build_found_node(
    sender_id: EmberNodeId,
    request_id: u32,
    contacts: Vec<EmberContact>,
) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_FOUND_NODE,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::FoundNode { contacts },
        signature: [0u8; 64],
    }
}

/// Build an ANNOUNCE_PEER request carrying a contact-list gossip dump.
/// Peers reply with [`build_peer_list`].
pub fn build_announce_peer(
    sender_id: EmberNodeId,
    request_id: u32,
    contacts: Vec<EmberContact>,
) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_ANNOUNCE_PEER,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::AnnouncePeer { contacts },
        signature: [0u8; 64],
    }
}

/// Build a PEER_LIST response (answer to [`build_announce_peer`]).
pub fn build_peer_list(
    sender_id: EmberNodeId,
    request_id: u32,
    contacts: Vec<EmberContact>,
) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_PEER_LIST,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::PeerList { contacts },
        signature: [0u8; 64],
    }
}

/// Build a STORE_RECORD request. `record` is the publisher-signed record
/// bytes ([`super::publish::SignedRecord::data`]) and `record_signature`
/// is that publisher's Ed25519 signature over it — distinct from the
/// per-frame signature `encode_message` adds with the sender's key.
pub fn build_store_record(
    sender_id: EmberNodeId,
    request_id: u32,
    key: [u8; 16],
    record: Vec<u8>,
    record_signature: [u8; 64],
) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_STORE_RECORD,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::StoreRecord {
            key,
            record,
            record_signature,
        },
        signature: [0u8; 64],
    }
}

/// Build a STORE_ACK response (echoes the stored key).
pub fn build_store_ack(sender_id: EmberNodeId, request_id: u32, key: [u8; 16]) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_STORE_ACK,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::StoreAck { key },
        signature: [0u8; 64],
    }
}

/// Build a PROXY_STORE (buddy fan-out request); body matches STORE_RECORD.
pub fn build_proxy_store(
    sender_id: EmberNodeId,
    request_id: u32,
    key: [u8; 16],
    record: Vec<u8>,
    record_signature: [u8; 64],
) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_PROXY_STORE,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::ProxyStore {
            key,
            record,
            record_signature,
        },
        signature: [0u8; 64],
    }
}

/// Build a PROXY_STORE_ACK (buddy accepted the proxy request).
pub fn build_proxy_store_ack(sender_id: EmberNodeId, request_id: u32, key: [u8; 16]) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_PROXY_STORE_ACK,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::ProxyStoreAck { key },
        signature: [0u8; 64],
    }
}

/// Build a STORE_BATCH carrying several records for one destination.
pub fn build_store_batch(
    sender_id: EmberNodeId,
    request_id: u32,
    records: Vec<BatchedRecord>,
) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_STORE_BATCH,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::StoreBatch { records },
        signature: [0u8; 64],
    }
}

/// Build the reply to a STORE_BATCH, reporting which records were accepted.
pub fn build_store_batch_ack(sender_id: EmberNodeId, request_id: u32, accepted: u64) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_STORE_BATCH_ACK,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::StoreBatchAck { accepted },
        signature: [0u8; 64],
    }
}

/// Gossip a channel message to a neighbor. `body` is the encoded
/// [`crate::network::ember::channel::ChannelGossip`].
pub fn build_channel_msg(sender_id: EmberNodeId, request_id: u32, body: Vec<u8>) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_CHANNEL_MSG,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::ChannelMsg { body },
        signature: [0u8; 64],
    }
}

/// Ask `target` to be reached via this HighID hop. `body` is a relay envelope
/// (`channel::encode_channel_relay_envelope`).
pub fn build_channel_relay(sender_id: EmberNodeId, request_id: u32, body: Vec<u8>) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_CHANNEL_RELAY,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::ChannelRelay { body },
        signature: [0u8; 64],
    }
}

/// Searcher → buddy: ask `publisher_id` to connect back for `file_hash`.
pub fn build_callback_req(
    sender_id: EmberNodeId,
    request_id: u32,
    publisher_id: EmberNodeId,
    file_hash: [u8; 16],
    searcher_tcp_port: u16,
    crypt_options: u8,
    searcher_user_hash: [u8; 16],
    callback_token: [u8; 16],
) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_CALLBACK_REQ,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::CallbackReq {
            publisher_id,
            file_hash,
            searcher_tcp_port,
            crypt_options,
            searcher_user_hash,
            callback_token,
        },
        signature: [0u8; 64],
    }
}

/// Publisher → candidate buddy: sign your own endpoint for me.
pub fn build_buddy_endorse_req(sender_id: EmberNodeId, request_id: u32) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_BUDDY_ENDORSE_REQ,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::BuddyEndorseReq,
        signature: [0u8; 64],
    }
}

/// Buddy → publisher: my endpoint, signed and bound to that publisher.
pub fn build_buddy_endorse(
    sender_id: EmberNodeId,
    request_id: u32,
    ip: Ipv4Addr,
    udp_port: u16,
    noise_pub: [u8; 32],
    expires_at: i64,
    signature: [u8; 64],
) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_BUDDY_ENDORSE,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::BuddyEndorse {
            ip,
            udp_port,
            noise_pub,
            expires_at,
            signature,
        },
        signature: [0u8; 64],
    }
}

/// Buddy → firewalled publisher: connect to this searcher.
pub fn build_callback(
    sender_id: EmberNodeId,
    request_id: u32,
    file_hash: [u8; 16],
    searcher_ip: Ipv4Addr,
    searcher_tcp_port: u16,
    crypt_options: u8,
    searcher_user_hash: [u8; 16],
    callback_token: [u8; 16],
) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_CALLBACK,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::Callback {
            file_hash,
            searcher_ip,
            searcher_tcp_port,
            crypt_options,
            searcher_user_hash,
            callback_token,
        },
        signature: [0u8; 64],
    }
}

/// How many bytes `record` costs inside a `STORE_BATCH`: the 16-byte key, the
/// 2-byte length prefix, the body, and the 64-byte record signature.
pub fn batched_record_wire_len(record_len: usize) -> usize {
    16 + 2 + record_len + 64
}

/// Read a `STORE_BATCH` frame's declared record count without decoding it.
///
/// Lets the rate limiter charge for the work a frame implies before paying
/// for the signature verifications that decoding it would cost. The value is
/// unverified — `decode_payload` re-checks it against the actual body — so
/// treat it only as an upper bound the sender is claiming.
pub fn peek_store_batch_count(frame: &[u8]) -> Option<u32> {
    // version(1) + msg_type(1) + request_id(4) + sender_id(16) + pubkey(32)
    // + payload_len(2), then the payload's own leading count byte.
    let len_at = HEADER_MIN_SIZE + 32;
    let offset = len_at + 2;
    // The declared payload length has to be read first. Indexing straight to the
    // count byte meant that on a frame claiming an empty payload the byte at that
    // offset is the first byte of the *signature*, so the store budget was
    // charged from signature material instead of a record count.
    let payload_len = u16::from_le_bytes([*frame.get(len_at)?, *frame.get(len_at + 1)?]);
    if payload_len == 0 {
        return None;
    }
    frame
        .get(offset)
        .map(|count| (*count as u32).min(MAX_STORE_BATCH_RECORDS as u32))
}

/// Build a FIND_VALUE request for one or more keys, starting at
/// `start_position` in the responder's live list for `keys[0]`.
pub fn build_find_value(
    sender_id: EmberNodeId,
    request_id: u32,
    keys: Vec<[u8; 16]>,
    start_position: u16,
) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_FIND_VALUE,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::FindValue {
            keys,
            start_position,
        },
        signature: [0u8; 64],
    }
}

/// Build a FOUND_VALUE response carrying one page of the records held for
/// `key`. See [`DhtPayload::FoundValue`] for what the two positions mean.
pub fn build_found_value(
    sender_id: EmberNodeId,
    request_id: u32,
    key: [u8; 16],
    records: Vec<Vec<u8>>,
    next_position: u16,
    total_available: u16,
) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_FOUND_VALUE,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::FoundValue {
            key,
            records,
            next_position,
            total_available,
        },
        signature: [0u8; 64],
    }
}

// ── Payload encoding ──

fn encode_payload(payload: &DhtPayload) -> Vec<u8> {
    match payload {
        DhtPayload::Ping => Vec::new(),
        DhtPayload::Pong { observed } => match observed {
            Some(addr) => {
                let mut buf = Vec::with_capacity(19);
                encode_socket_addr(addr, &mut buf);
                buf
            }
            None => Vec::new(),
        },
        DhtPayload::FindNode { target } => target.0.to_vec(),
        DhtPayload::FoundNode { contacts }
        | DhtPayload::AnnouncePeer { contacts }
        | DhtPayload::PeerList { contacts } => encode_contact_list(contacts),
        DhtPayload::StoreRecord {
            key,
            record,
            record_signature,
        }
        | DhtPayload::ProxyStore {
            key,
            record,
            record_signature,
        } => {
            let mut buf = Vec::with_capacity(16 + 2 + record.len() + 64);
            buf.extend_from_slice(key);
            buf.write_u16::<LittleEndian>(record.len() as u16).unwrap();
            buf.extend_from_slice(record);
            buf.extend_from_slice(record_signature);
            buf
        }
        DhtPayload::StoreAck { key } | DhtPayload::ProxyStoreAck { key } => key.to_vec(),
        DhtPayload::StoreBatch { records } => {
            let total: usize = records
                .iter()
                .map(|r| batched_record_wire_len(r.record.len()))
                .sum();
            let mut buf = Vec::with_capacity(1 + total);
            // Both bounds below silently discard data if a caller exceeds
            // them, and a caller has no way to notice. `EmberDht` respects
            // both, so tripping either is a bug in a future caller.
            debug_assert!(
                records.len() <= MAX_STORE_BATCH_RECORDS,
                "STORE_BATCH of {} records exceeds the {MAX_STORE_BATCH_RECORDS} maximum",
                records.len()
            );
            debug_assert!(
                records.iter().all(|r| r.record.len() <= u16::MAX as usize),
                "a batched record body exceeds what its u16 length prefix can express"
            );
            let count = records.len().min(MAX_STORE_BATCH_RECORDS);
            buf.write_u8(count as u8).unwrap();
            for rec in records.iter().take(count) {
                buf.extend_from_slice(&rec.key);
                buf.write_u16::<LittleEndian>(rec.record.len() as u16)
                    .unwrap();
                buf.extend_from_slice(&rec.record);
                buf.extend_from_slice(&rec.record_signature);
            }
            buf
        }
        DhtPayload::StoreBatchAck { accepted } => accepted.to_le_bytes().to_vec(),
        DhtPayload::FindValue {
            keys,
            start_position,
        } => {
            let mut buf = Vec::with_capacity(1 + keys.len() * 16 + 2);
            // Same reasoning as `StoreBatch` above: a bare `as u8` truncates the
            // count while the loop still writes every key, so an over-long
            // caller would emit a signed frame whose declared count disagrees
            // with its body. Every current caller truncates first, so clamping
            // here only makes that a local guarantee rather than a remote one.
            debug_assert!(
                keys.len() <= MAX_FIND_VALUE_KEYS,
                "FIND_VALUE of {} keys exceeds the {MAX_FIND_VALUE_KEYS} maximum",
                keys.len()
            );
            let count = keys.len().min(MAX_FIND_VALUE_KEYS);
            buf.write_u8(count as u8).unwrap();
            for key in keys.iter().take(count) {
                buf.extend_from_slice(key);
            }
            // Trails the keys so the fixed-size prefix a decoder needs to size
            // the key run stays first.
            buf.write_u16::<LittleEndian>(*start_position).unwrap();
            buf
        }
        DhtPayload::FoundValue {
            key,
            records,
            next_position,
            total_available,
        } => {
            let mut buf =
                Vec::with_capacity(FOUND_VALUE_HEADER_LEN + records.len() * 128);
            buf.extend_from_slice(key);
            buf.write_u16::<LittleEndian>(*next_position).unwrap();
            buf.write_u16::<LittleEndian>(*total_available).unwrap();
            debug_assert!(
                records.len() <= MAX_FOUND_VALUE_RECORDS,
                "FOUND_VALUE of {} records exceeds the {MAX_FOUND_VALUE_RECORDS} maximum",
                records.len()
            );
            debug_assert!(
                records.iter().all(|r| r.len() <= u16::MAX as usize),
                "a FOUND_VALUE blob exceeds what its u16 length prefix can express"
            );
            let count = records.len().min(MAX_FOUND_VALUE_RECORDS);
            buf.write_u16::<LittleEndian>(count as u16).unwrap();
            for rec in records.iter().take(count) {
                buf.write_u16::<LittleEndian>(rec.len() as u16).unwrap();
                buf.extend_from_slice(rec);
            }
            buf
        }
        DhtPayload::ChannelMsg { body } => body.clone(),
        DhtPayload::ChannelRelay { body } => body.clone(),
        DhtPayload::CallbackReq {
            publisher_id,
            file_hash,
            searcher_tcp_port,
            crypt_options,
            searcher_user_hash,
            callback_token,
        } => {
            let mut buf = Vec::with_capacity(CALLBACK_REQ_WIRE_LEN);
            buf.extend_from_slice(&publisher_id.0);
            buf.extend_from_slice(file_hash);
            buf.write_u16::<LittleEndian>(*searcher_tcp_port).unwrap();
            buf.push(*crypt_options);
            buf.extend_from_slice(searcher_user_hash);
            buf.extend_from_slice(callback_token);
            buf
        }
        DhtPayload::Callback {
            file_hash,
            searcher_ip,
            searcher_tcp_port,
            crypt_options,
            searcher_user_hash,
            callback_token,
        } => {
            let mut buf = Vec::with_capacity(CALLBACK_WIRE_LEN);
            buf.extend_from_slice(file_hash);
            buf.extend_from_slice(&searcher_ip.octets());
            buf.write_u16::<LittleEndian>(*searcher_tcp_port).unwrap();
            buf.push(*crypt_options);
            buf.extend_from_slice(searcher_user_hash);
            buf.extend_from_slice(callback_token);
            buf
        }
        DhtPayload::BuddyEndorseReq => Vec::new(),
        DhtPayload::BuddyEndorse {
            ip,
            udp_port,
            noise_pub,
            expires_at,
            signature,
        } => {
            let mut buf = Vec::with_capacity(BUDDY_ENDORSE_WIRE_LEN);
            buf.extend_from_slice(&ip.octets());
            buf.write_u16::<LittleEndian>(*udp_port).unwrap();
            buf.extend_from_slice(noise_pub);
            buf.write_i64::<LittleEndian>(*expires_at).unwrap();
            buf.extend_from_slice(signature);
            buf
        }
        DhtPayload::Unknown(data) => data.clone(),
    }
}

/// Encode a contact list, bounded by both the declared count limit and a byte
/// budget that keeps the resulting datagram from fragmenting.
///
/// A count limit alone is not enough: 20 IPv4 contacts encode to roughly 1420
/// bytes, which fragments, and an IPv6 list is larger still. Contacts are
/// already ordered closest-first, so trimming the tail drops the least useful
/// entries.
///
/// No `node_id` is written — see [`CONTACT_WIRE_LEN_IPV4`]. The receiver derives
/// it from `ed25519_pub`, which is the only value that could ever have been
/// authoritative.
///
/// Also used off the DHT wire, by the friend-session contact exchange
/// ([`crate::network::ed2k::messages::EMBER_EXT_DHT_CONTACTS`]). The
/// unfragmented budget is meaningless over TCP and simply caps that answer at
/// 17 contacts, which is most of a k-bucket and far more than a join needs —
/// worth strictly less than having one encoder whose identity binding is
/// already pinned by tests.
pub(crate) fn encode_contact_list(contacts: &[EmberContact]) -> Vec<u8> {
    // Exact for an IPv4 list, which is all we currently dial; an IPv6 entry is
    // 12 bytes wider and costs one realloc. The byte cap below is what actually
    // bounds the result either way.
    let mut buf = Vec::with_capacity(1 + MAX_CONTACTS_PER_RESPONSE * CONTACT_WIRE_LEN_IPV4);
    buf.write_u8(0).unwrap(); // placeholder, rewritten once the count is known

    let mut count = 0usize;
    for contact in contacts.iter().take(MAX_CONTACTS_PER_RESPONSE) {
        let before = buf.len();
        encode_socket_addr(&contact.addr, &mut buf);
        buf.extend_from_slice(&contact.noise_pub);
        buf.extend_from_slice(&contact.ed25519_pub);
        if buf.len() > MAX_UNFRAGMENTED_PAYLOAD {
            buf.truncate(before);
            break;
        }
        count += 1;
    }

    buf[0] = count as u8;
    buf
}

fn encode_socket_addr(addr: &SocketAddr, buf: &mut Vec<u8>) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            buf.write_u8(ADDR_IPV4).unwrap();
            buf.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.write_u8(ADDR_IPV6).unwrap();
            buf.extend_from_slice(&ip.octets());
        }
    }
    buf.write_u16::<BigEndian>(addr.port()).unwrap();
}

fn decode_socket_addr(data: &[u8]) -> anyhow::Result<(SocketAddr, usize)> {
    if data.is_empty() {
        anyhow::bail!("socket addr empty");
    }
    let addr_type = data[0];
    let (ip, ip_len) = match addr_type {
        ADDR_IPV4 => {
            if data.len() < 1 + 4 + 2 {
                anyhow::bail!("socket addr truncated (ipv4)");
            }
            let ip = IpAddr::V4(Ipv4Addr::new(data[1], data[2], data[3], data[4]));
            (ip, 4)
        }
        ADDR_IPV6 => {
            if data.len() < 1 + 16 + 2 {
                anyhow::bail!("socket addr truncated (ipv6)");
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = IpAddr::V6(Ipv6Addr::from(octets));
            (ip, 16)
        }
        _ => anyhow::bail!("Unknown address type 0x{addr_type:02x}"),
    };
    let port_off = 1 + ip_len;
    let port = u16::from_be_bytes([data[port_off], data[port_off + 1]]);
    Ok((SocketAddr::new(ip, port), port_off + 2))
}

// ── Payload decoding ──

fn decode_payload(msg_type: u8, data: &[u8]) -> anyhow::Result<DhtPayload> {
    match msg_type {
        MSG_PING => Ok(DhtPayload::Ping),
        MSG_PONG => {
            if data.is_empty() {
                Ok(DhtPayload::Pong { observed: None })
            } else {
                let (addr, _) = decode_socket_addr(data)?;
                Ok(DhtPayload::Pong {
                    observed: Some(addr),
                })
            }
        }
        MSG_FIND_NODE => {
            if data.len() < 16 {
                anyhow::bail!("FIND_NODE payload too short");
            }
            let mut target = [0u8; 16];
            target.copy_from_slice(&data[..16]);
            Ok(DhtPayload::FindNode {
                target: EmberNodeId(target),
            })
        }
        MSG_FOUND_NODE | MSG_ANNOUNCE_PEER | MSG_PEER_LIST => {
            let contacts = decode_contact_list(data)?;
            match msg_type {
                MSG_FOUND_NODE => Ok(DhtPayload::FoundNode { contacts }),
                MSG_ANNOUNCE_PEER => Ok(DhtPayload::AnnouncePeer { contacts }),
                _ => Ok(DhtPayload::PeerList { contacts }),
            }
        }
        MSG_STORE_RECORD | MSG_PROXY_STORE => {
            if data.len() < 16 + 2 + 64 {
                anyhow::bail!("STORE/PROXY_STORE too short");
            }
            let mut key = [0u8; 16];
            key.copy_from_slice(&data[..16]);
            let mut cursor = Cursor::new(&data[16..]);
            let record_len = cursor.read_u16::<LittleEndian>()? as usize;
            if record_len > MAX_STORE_RECORD_BYTES {
                anyhow::bail!(
                    "STORE/PROXY_STORE record_len {record_len} exceeds max {MAX_STORE_RECORD_BYTES}"
                );
            }
            let offset = 18;
            if offset + record_len + 64 > data.len() {
                anyhow::bail!("STORE/PROXY_STORE truncated");
            }
            let record = data[offset..offset + record_len].to_vec();
            let mut record_signature = [0u8; 64];
            record_signature.copy_from_slice(&data[offset + record_len..offset + record_len + 64]);
            if msg_type == MSG_PROXY_STORE {
                Ok(DhtPayload::ProxyStore {
                    key,
                    record,
                    record_signature,
                })
            } else {
                Ok(DhtPayload::StoreRecord {
                    key,
                    record,
                    record_signature,
                })
            }
        }
        MSG_STORE_BATCH => {
            if data.is_empty() {
                anyhow::bail!("STORE_BATCH empty");
            }
            let count = data[0] as usize;
            if count > MAX_STORE_BATCH_RECORDS {
                anyhow::bail!("STORE_BATCH count {count} exceeds max {MAX_STORE_BATCH_RECORDS}");
            }
            let mut records = Vec::with_capacity(count);
            let mut offset = 1usize;
            for _ in 0..count {
                if offset + 16 + 2 > data.len() {
                    anyhow::bail!("STORE_BATCH truncated in header");
                }
                let mut key = [0u8; 16];
                key.copy_from_slice(&data[offset..offset + 16]);
                offset += 16;
                let record_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
                offset += 2;
                if record_len > MAX_STORE_RECORD_BYTES {
                    anyhow::bail!(
                        "STORE_BATCH record_len {record_len} exceeds max {MAX_STORE_RECORD_BYTES}"
                    );
                }
                if offset + record_len + 64 > data.len() {
                    anyhow::bail!("STORE_BATCH truncated in record body");
                }
                let record = data[offset..offset + record_len].to_vec();
                offset += record_len;
                let mut record_signature = [0u8; 64];
                record_signature.copy_from_slice(&data[offset..offset + 64]);
                offset += 64;
                records.push(BatchedRecord {
                    key,
                    record,
                    record_signature,
                });
            }
            // Trailing bytes mean the frame is not what it claims to be.
            if offset != data.len() {
                anyhow::bail!("STORE_BATCH has {} trailing byte(s)", data.len() - offset);
            }
            Ok(DhtPayload::StoreBatch { records })
        }
        MSG_STORE_BATCH_ACK => {
            if data.len() < 8 {
                anyhow::bail!("STORE_BATCH_ACK too short");
            }
            let mut bits = [0u8; 8];
            bits.copy_from_slice(&data[..8]);
            Ok(DhtPayload::StoreBatchAck {
                accepted: u64::from_le_bytes(bits),
            })
        }
        MSG_STORE_ACK | MSG_PROXY_STORE_ACK => {
            if data.len() < 16 {
                anyhow::bail!("STORE/PROXY_STORE_ACK too short");
            }
            let mut key = [0u8; 16];
            key.copy_from_slice(&data[..16]);
            if msg_type == MSG_PROXY_STORE_ACK {
                Ok(DhtPayload::ProxyStoreAck { key })
            } else {
                Ok(DhtPayload::StoreAck { key })
            }
        }
        MSG_FIND_VALUE => {
            if data.is_empty() {
                anyhow::bail!("FIND_VALUE empty");
            }
            let count = data[0] as usize;
            if count == 0 {
                // A lookup for nothing. The engine reads `keys[0]` as the key to
                // serve and had no target to fall back on but its own id, so an
                // empty request was answered with our closest contacts to
                // ourselves — a `FIND_NODE` under another name, and one no
                // builder here can produce. Malformed at the decoder is where
                // that belongs.
                anyhow::bail!("FIND_VALUE carries no keys");
            }
            if count > MAX_FIND_VALUE_KEYS {
                anyhow::bail!("FIND_VALUE keys count {count} exceeds max {MAX_FIND_VALUE_KEYS}");
            }
            if data.len() < 1 + count * 16 + 2 {
                anyhow::bail!("FIND_VALUE truncated");
            }
            let mut keys = Vec::with_capacity(count);
            for i in 0..count {
                let mut key = [0u8; 16];
                key.copy_from_slice(&data[1 + i * 16..1 + (i + 1) * 16]);
                keys.push(key);
            }
            let pos_at = 1 + count * 16;
            let start_position = u16::from_le_bytes([data[pos_at], data[pos_at + 1]]);
            Ok(DhtPayload::FindValue {
                keys,
                start_position,
            })
        }
        MSG_FOUND_VALUE => {
            if data.len() < FOUND_VALUE_HEADER_LEN {
                anyhow::bail!("FOUND_VALUE too short");
            }
            let mut key = [0u8; 16];
            key.copy_from_slice(&data[..16]);
            let mut cursor = Cursor::new(&data[16..]);
            let next_position = cursor.read_u16::<LittleEndian>()?;
            let total_available = cursor.read_u16::<LittleEndian>()?;
            let record_count = cursor.read_u16::<LittleEndian>()? as usize;
            if record_count > MAX_FOUND_VALUE_RECORDS {
                anyhow::bail!(
                    "FOUND_VALUE record_count {record_count} exceeds max {MAX_FOUND_VALUE_RECORDS}"
                );
            }
            // A peer can claim up to MAX_FOUND_VALUE_RECORDS records in a
            // packet that can't physically hold them. The loop below is
            // bounded by the actual data length (each record needs >= 2
            // bytes), so only reserve what the remaining bytes could contain
            // to avoid a large eager alloc.
            let mut records = Vec::with_capacity(record_count.min(data.len() / 2 + 1));
            let mut offset = FOUND_VALUE_HEADER_LEN;
            for _ in 0..record_count {
                // A declared record count that the buffer can't satisfy is a
                // framing error, not a partial list to be silently accepted —
                // reject the whole frame so a peer can't smuggle a truncated
                // payload that we'd misinterpret.
                if offset + 2 > data.len() {
                    anyhow::bail!("FOUND_VALUE truncated (declared {record_count} records)");
                }
                let rlen = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
                if rlen > MAX_FOUND_VALUE_BLOB_BYTES {
                    anyhow::bail!(
                        "FOUND_VALUE record length {rlen} exceeds max {MAX_FOUND_VALUE_BLOB_BYTES}"
                    );
                }
                offset += 2;
                if offset + rlen > data.len() {
                    anyhow::bail!("FOUND_VALUE record length {rlen} exceeds buffer");
                }
                records.push(data[offset..offset + rlen].to_vec());
                offset += rlen;
            }
            Ok(DhtPayload::FoundValue {
                key,
                records,
                next_position,
                total_available,
            })
        }
        MSG_CHANNEL_MSG => {
            if data.len() > MAX_DHT_PAYLOAD {
                anyhow::bail!("CHANNEL_MSG body exceeds max {MAX_DHT_PAYLOAD}");
            }
            Ok(DhtPayload::ChannelMsg {
                body: data.to_vec(),
            })
        }
        MSG_CHANNEL_RELAY => {
            if data.len() > MAX_DHT_PAYLOAD {
                anyhow::bail!("CHANNEL_RELAY body exceeds max {MAX_DHT_PAYLOAD}");
            }
            Ok(DhtPayload::ChannelRelay {
                body: data.to_vec(),
            })
        }
        MSG_CALLBACK_REQ => {
            if data.len() != CALLBACK_REQ_WIRE_LEN {
                anyhow::bail!(
                    "CALLBACK_REQ length {} (expected {CALLBACK_REQ_WIRE_LEN})",
                    data.len()
                );
            }
            let mut publisher = [0u8; 16];
            publisher.copy_from_slice(&data[..16]);
            let mut file_hash = [0u8; 16];
            file_hash.copy_from_slice(&data[16..32]);
            let searcher_tcp_port = u16::from_le_bytes([data[32], data[33]]);
            let crypt_options = data[34];
            let mut searcher_user_hash = [0u8; 16];
            searcher_user_hash.copy_from_slice(&data[35..51]);
            let mut callback_token = [0u8; 16];
            callback_token.copy_from_slice(&data[51..67]);
            Ok(DhtPayload::CallbackReq {
                publisher_id: EmberNodeId(publisher),
                file_hash,
                searcher_tcp_port,
                crypt_options,
                searcher_user_hash,
                callback_token,
            })
        }
        MSG_CALLBACK => {
            if data.len() != CALLBACK_WIRE_LEN {
                anyhow::bail!(
                    "CALLBACK length {} (expected {CALLBACK_WIRE_LEN})",
                    data.len()
                );
            }
            let mut file_hash = [0u8; 16];
            file_hash.copy_from_slice(&data[..16]);
            let searcher_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
            let searcher_tcp_port = u16::from_le_bytes([data[20], data[21]]);
            let crypt_options = data[22];
            let mut searcher_user_hash = [0u8; 16];
            searcher_user_hash.copy_from_slice(&data[23..39]);
            let mut callback_token = [0u8; 16];
            callback_token.copy_from_slice(&data[39..55]);
            Ok(DhtPayload::Callback {
                file_hash,
                searcher_ip,
                searcher_tcp_port,
                crypt_options,
                searcher_user_hash,
                callback_token,
            })
        }
        MSG_BUDDY_ENDORSE_REQ => Ok(DhtPayload::BuddyEndorseReq),
        MSG_BUDDY_ENDORSE => {
            if data.len() != BUDDY_ENDORSE_WIRE_LEN {
                anyhow::bail!(
                    "BUDDY_ENDORSE length {} (expected {BUDDY_ENDORSE_WIRE_LEN})",
                    data.len()
                );
            }
            let ip = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
            let udp_port = u16::from_le_bytes([data[4], data[5]]);
            let mut noise_pub = [0u8; 32];
            noise_pub.copy_from_slice(&data[6..38]);
            let expires_at = i64::from_le_bytes(data[38..46].try_into()?);
            let mut signature = [0u8; 64];
            signature.copy_from_slice(&data[46..110]);
            Ok(DhtPayload::BuddyEndorse {
                ip,
                udp_port,
                noise_pub,
                expires_at,
                signature,
            })
        }
        _ => Ok(DhtPayload::Unknown(data.to_vec())),
    }
}

pub(crate) fn decode_contact_list(data: &[u8]) -> anyhow::Result<Vec<EmberContact>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let count = data[0] as usize;
    if count > MAX_CONTACTS_PER_RESPONSE {
        anyhow::bail!("Contact list count {count} exceeds max {MAX_CONTACTS_PER_RESPONSE}");
    }

    let mut contacts = Vec::with_capacity(count);
    let mut offset = 1usize;

    for _ in 0..count {
        // addr_type (1) + ip (4 or 16) + port (2) + noise_pub (32) + ed25519_pub (32).
        // A declared count the buffer can't satisfy is a framing error: reject
        // the whole frame instead of returning a silently-truncated prefix.
        if offset + 1 > data.len() {
            anyhow::bail!("contact list truncated (declared {count} contacts)");
        }

        let addr_type = data[offset];
        offset += 1;

        let (ip, ip_len) = match addr_type {
            ADDR_IPV4 => {
                if offset + 4 > data.len() {
                    anyhow::bail!("contact list truncated (ipv4 address)");
                }
                let ip = IpAddr::V4(Ipv4Addr::new(
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ));
                (ip, 4)
            }
            ADDR_IPV6 => {
                if offset + 16 > data.len() {
                    anyhow::bail!("contact list truncated (ipv6 address)");
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[offset..offset + 16]);
                let ip = IpAddr::V6(Ipv6Addr::from(octets));
                (ip, 16)
            }
            _ => {
                anyhow::bail!("Unknown address type 0x{addr_type:02x}");
            }
        };
        offset += ip_len;

        if offset + 2 + 32 + 32 > data.len() {
            anyhow::bail!("contact list truncated (port/keys)");
        }
        let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let mut noise_pub = [0u8; 32];
        noise_pub.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut ed25519_pub = [0u8; 32];
        ed25519_pub.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // The node ID is derived here because the key is the only place it can
        // come from — v3 does not carry one. This mirrors the identity binding
        // `decode_message` enforces for direct senders and
        // `BootstrapNode::to_contact` applies to rendezvous peers: an
        // indirectly-learned contact cannot be injected under an ID it doesn't
        // control. A contact whose key isn't a valid Ed25519 point can never be
        // dialed or verified, so drop it silently (one bad entry must not void
        // the rest of an otherwise honest list).
        let Some(derived_id) = crypto::node_id_from_ed25519_bytes(&ed25519_pub) else {
            continue;
        };

        contacts.push(EmberContact {
            node_id: EmberNodeId(derived_id),
            addr: SocketAddr::new(ip, port),
            noise_pub,
            ed25519_pub,
            last_seen: 0,
            failed_queries: 0,
        });
    }

    Ok(contacts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::ember::crypto;
    use ed25519_dalek::SigningKey;
    /// Stand-in for a node's own Noise static key, which v4 binds every frame
    /// signature to. Encode and decode must agree on it; a test that needs them
    /// to disagree passes a different key explicitly.
    const TEST_NOISE_PUB: [u8; 32] = [0xAB; 32];


    /// A signing key paired with the node ID it actually binds to
    /// (`node_id == BLAKE3(pubkey)[..16]`). `decode_message` enforces
    /// that binding, so tests must use a consistent (key, id) pair
    /// rather than an arbitrary placeholder id.
    fn test_keypair() -> (SigningKey, EmberNodeId) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let id = EmberNodeId(crypto::node_id_from_public_key(&sk.verifying_key()));
        (sk, id)
    }

    /// Build a contact whose `node_id` is correctly derived from a real
    /// Ed25519 key. `decode_contact_list` re-derives the ID from the key and
    /// drops contacts with non-curve-valid keys, so tests must use genuine
    /// keypairs rather than placeholder bytes.
    fn test_contact(seed: u8, addr: &str, noise: u8) -> EmberContact {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let vk = sk.verifying_key();
        EmberContact {
            node_id: EmberNodeId(crypto::node_id_from_public_key(&vk)),
            addr: addr.parse().unwrap(),
            noise_pub: [noise; 32],
            ed25519_pub: vk.to_bytes(),
            last_seen: 0,
            failed_queries: 0,
        }
    }

    #[test]
    fn ping_pong_round_trip() {
        let (sk, id) = test_keypair();

        let ping = build_ping(id, 42);
        let encoded = encode_message(&ping, &sk, true, &TEST_NOISE_PUB);
        let decoded = decode_message(&encoded, true, &TEST_NOISE_PUB).unwrap();

        assert_eq!(decoded.version, EMBER_DHT_VERSION);
        assert_eq!(decoded.msg_type, MSG_PING);
        assert_eq!(decoded.request_id, 42);
        assert_eq!(decoded.sender_id, id);
        assert!(matches!(decoded.payload, DhtPayload::Ping));

        let pong = build_pong(id, 42, "203.0.113.50:4672".parse().unwrap());
        let encoded = encode_message(&pong, &sk, true, &TEST_NOISE_PUB);
        let decoded = decode_message(&encoded, true, &TEST_NOISE_PUB).unwrap();
        match decoded.payload {
            DhtPayload::Pong { observed } => {
                assert_eq!(observed, Some("203.0.113.50:4672".parse().unwrap()));
            }
            _ => panic!("expected Pong"),
        }
    }

    #[test]
    fn channel_msg_round_trip() {
        let (sk, id) = test_keypair();
        let body = b"gossip-body".to_vec();
        let msg = build_channel_msg(id, 7, body.clone());
        let encoded = encode_message(&msg, &sk, true, &TEST_NOISE_PUB);
        let decoded = decode_message(&encoded, true, &TEST_NOISE_PUB).unwrap();
        assert_eq!(decoded.msg_type, MSG_CHANNEL_MSG);
        match decoded.payload {
            DhtPayload::ChannelMsg { body: got } => assert_eq!(got, body),
            other => panic!("expected ChannelMsg, got {other:?}"),
        }
    }

    #[test]
    fn channel_relay_round_trip() {
        let (sk, id) = test_keypair();
        let body = b"relay-envelope".to_vec();
        let msg = build_channel_relay(id, 8, body.clone());
        let encoded = encode_message(&msg, &sk, true, &TEST_NOISE_PUB);
        let decoded = decode_message(&encoded, true, &TEST_NOISE_PUB).unwrap();
        assert_eq!(decoded.msg_type, MSG_CHANNEL_RELAY);
        match decoded.payload {
            DhtPayload::ChannelRelay { body: got } => assert_eq!(got, body),
            other => panic!("expected ChannelRelay, got {other:?}"),
        }
    }

    /// Signature verification and the `sender_id == BLAKE3(pubkey)[..16]`
    /// binding both live behind the public key being present, so decoding
    /// without one yielded a fully-formed but entirely unauthenticated
    /// message. Nothing in the tree encodes that way and the only production
    /// caller passes `true`, so the shape is refused rather than left as a
    /// trap for a future caller.
    #[test]
    fn a_frame_without_a_public_key_cannot_be_authenticated_and_is_refused() {
        let (sk, id) = test_keypair();
        let pong = build_pong(id, 42, "203.0.113.50:4672".parse().unwrap());
        let encoded = encode_message(&pong, &sk, false, &TEST_NOISE_PUB);
        let err = decode_message(&encoded, false, &TEST_NOISE_PUB).expect_err("must not decode unauthenticated");
        assert!(
            err.to_string().contains("cannot be authenticated"),
            "unexpected reason: {err}"
        );
    }

    /// A version we cannot parse has to be refused as a version mismatch. The
    /// check used to reject only *newer* versions, so when the v1 layout changed
    /// without the byte being raised, two peers announced the same version and
    /// then misparsed each other into malformed-frame counters that looked like
    /// packet loss.
    #[test]
    fn decode_refuses_versions_outside_the_supported_range() {
        let (sk, id) = test_keypair();
        let encoded = encode_message(&build_ping(id, 1), &sk, true, &TEST_NOISE_PUB);

        // The version byte leads the frame, so the range check runs before the
        // signature is even looked at.
        for bogus in [0u8, EMBER_DHT_MIN_VERSION - 1, EMBER_DHT_VERSION + 1, 0xFF] {
            let mut framed = encoded.clone();
            framed[0] = bogus;
            assert!(
                decode_message(&framed, true, &TEST_NOISE_PUB).is_err(),
                "version {bogus} must be refused"
            );
        }

        // Our own frames still decode, and the range is coherent.
        assert!(decode_message(&encoded, true, &TEST_NOISE_PUB).is_ok());
        const _: () = assert!(EMBER_DHT_MIN_VERSION >= 1);
        const _: () = assert!(EMBER_DHT_MIN_VERSION <= EMBER_DHT_VERSION);
        assert_eq!(unsupported_dht_version(&encoded), None);
        let mut newer = encoded.clone();
        newer[0] = EMBER_DHT_VERSION + 1;
        assert_eq!(unsupported_dht_version(&newer), Some(EMBER_DHT_VERSION + 1));
        let mut zero = encoded;
        zero[0] = 0;
        assert_eq!(
            unsupported_dht_version(&zero),
            None,
            "version 0 is garbage, not a peer we could upgrade"
        );
        assert!(
            dht_version_is_newer_than_us(EMBER_DHT_VERSION + 1),
            "a byte above this build is a peer we should update to meet"
        );
        assert!(
            !dht_version_is_newer_than_us(EMBER_DHT_MIN_VERSION.saturating_sub(1)),
            "a byte below this build is a peer that should update to meet us"
        );
    }

    #[test]
    fn version_zero_rejected() {
        let (sk, id) = test_keypair();
        let ping = build_ping(id, 1);
        let mut encoded = encode_message(&ping, &sk, true, &TEST_NOISE_PUB);
        encoded[0] = 0;
        assert!(decode_message(&encoded, true, &TEST_NOISE_PUB).is_err());
    }

    #[test]
    fn trailing_bytes_rejected() {
        let (sk, id) = test_keypair();
        let ping = build_ping(id, 1);
        let mut encoded = encode_message(&ping, &sk, true, &TEST_NOISE_PUB);
        encoded.push(0xAB);
        assert!(decode_message(&encoded, true, &TEST_NOISE_PUB).is_err());
    }

    /// A reply that fragments is a reply many peers never receive, so the
    /// contact list is bounded by bytes and not only by count.
    #[test]
    fn contact_lists_stay_inside_one_unfragmented_datagram() {
        let (sk, id) = test_keypair();

        for (label, make_addr) in [
            (
                "ipv4",
                (|i: u8| SocketAddr::from(([80, 1, i, 1], 4672))) as fn(u8) -> SocketAddr,
            ),
            ("ipv6", |i: u8| {
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i as u16 + 1)),
                    4672,
                )
            }),
        ] {
            let contacts: Vec<EmberContact> = (0..MAX_CONTACTS_PER_RESPONSE as u8)
                .map(|i| EmberContact {
                    node_id: EmberNodeId([i; 16]),
                    addr: make_addr(i),
                    noise_pub: [i; 32],
                    ed25519_pub: [i; 32],
                    last_seen: 1,
                    failed_queries: 0,
                })
                .collect();

            let msg = build_found_node(id, 1, contacts);
            let frame = encode_message(&msg, &sk, true, &TEST_NOISE_PUB);
            let datagram = frame.len() + TRANSPORT_OVERHEAD;
            assert!(
                datagram <= MAX_UNFRAGMENTED_DATAGRAM,
                "{label} FOUND_NODE datagram is {datagram} bytes and would fragment"
            );

            // Trimming must still leave a useful answer, and it must decode.
            let decoded = decode_message(&frame, true, &TEST_NOISE_PUB).expect("frame decodes");
            match decoded.payload {
                DhtPayload::FoundNode { contacts } => {
                    assert!(!contacts.is_empty(), "{label} reply must carry contacts");
                }
                other => panic!("expected FoundNode, got {other:?}"),
            }
        }
    }

    #[test]
    fn oversized_payload_rejected() {
        let (sk, id) = test_keypair();
        let ping = build_ping(id, 1);
        let mut encoded = encode_message(&ping, &sk, true, &TEST_NOISE_PUB);
        // payload_len is a u16 LE right after the pub key (header min + 32).
        let payload_len_off = HEADER_MIN_SIZE + 32;
        let oversized = (MAX_DHT_PAYLOAD as u16).saturating_add(1);
        encoded[payload_len_off..payload_len_off + 2].copy_from_slice(&oversized.to_le_bytes());
        // Truncate/extend so length checks past payload_len still run;
        // we only care that the max-payload gate fires first.
        assert!(decode_message(&encoded, true, &TEST_NOISE_PUB).is_err());
    }

    #[test]
    fn pong_observed_round_trip() {
        let (sk, id) = test_keypair();
        let observed: SocketAddr = "198.51.100.7:4662".parse().unwrap();
        let pong = build_pong(id, 7, observed);
        let encoded = encode_message(&pong, &sk, true, &TEST_NOISE_PUB);
        let decoded = decode_message(&encoded, true, &TEST_NOISE_PUB).unwrap();
        match decoded.payload {
            DhtPayload::Pong {
                observed: Some(addr),
            } => assert_eq!(addr, observed),
            _ => panic!("expected Pong with observed"),
        }
    }

    /// The domain tag carries the wire version, so a signature made under one
    /// format can never verify under another. That only holds while the two are
    /// edited together, and nothing but this test makes them.
    #[test]
    fn the_frame_domain_names_the_wire_version() {
        let tag = std::str::from_utf8(DHT_FRAME_DOMAIN).expect("the tag is ASCII");
        assert!(
            tag.ends_with(&format!("-v{EMBER_DHT_VERSION}")),
            "DHT_FRAME_DOMAIN is {tag:?} but the wire version is {EMBER_DHT_VERSION}; \
             bump the tag with it or a v{EMBER_DHT_VERSION} signature inherits the old domain"
        );
    }

    #[test]
    fn decode_message_fuzz_never_panics() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xE19E_19E1);
        // Header-level soak: truncated frames, bad versions, random trailing
        // junk. Deliberately does *not* reach `decode_payload` — random bytes
        // cannot pass an Ed25519 check — which is what
        // `decode_payload_fuzz_never_panics` below exists to cover.
        for _ in 0..2_000 {
            let len = rng.gen_range(0..=2_048);
            let mut buf = vec![0u8; len];
            rng.fill(&mut buf[..]);
            let _ = decode_message(&buf, true, &TEST_NOISE_PUB);
            let _ = decode_message(&buf, false, &TEST_NOISE_PUB);
        }
    }

    /// Fuzz the payload decoders, which is where every length prefix, slice
    /// and capacity hint actually lives.
    ///
    /// Random bytes never get there: a buffer has to carry the right version,
    /// an exactly-consistent payload length *and* a valid signature over
    /// itself, so the header-level soak above rejects essentially every
    /// iteration at the signature and the decoders were never executed once.
    /// Signing a well-formed frame around a randomised body puts the fuzz
    /// where the parsing is.
    #[test]
    fn decode_payload_fuzz_never_panics() {
        use rand::{Rng, SeedableRng};
        let (sk, id) = test_keypair();
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x0EC0_DEC0);
        let types = [
            MSG_PING,
            MSG_PONG,
            MSG_FIND_NODE,
            MSG_FOUND_NODE,
            MSG_STORE_RECORD,
            MSG_STORE_ACK,
            MSG_FIND_VALUE,
            MSG_FOUND_VALUE,
            MSG_ANNOUNCE_PEER,
            MSG_PEER_LIST,
            MSG_PROXY_STORE,
            MSG_PROXY_STORE_ACK,
            MSG_STORE_BATCH,
            MSG_STORE_BATCH_ACK,
            MSG_CALLBACK_REQ,
            MSG_CALLBACK,
            MSG_CHANNEL_MSG,
            MSG_CHANNEL_RELAY,
            // The two newest types, and the ones this list silently omitted.
            MSG_BUDDY_ENDORSE_REQ,
            MSG_BUDDY_ENDORSE,
            0x00,
            0xFF,
        ];

        // Only the randomised iterations count. A deterministic well-formed
        // frame used to be mixed in "so a future change that stops the fuzz
        // reaching the decoders fails loudly" — but it was an empty `PING`, so
        // it satisfied the assertion by itself and the guard could only ever
        // prove that `PING` decodes. Counting the random ones separately is
        // what makes the claim real.
        let mut random_decoded_ok = 0usize;
        for _ in 0..2_000 {
            let msg_type = types[rng.gen_range(0..types.len())];
            // Up to the wire ceiling, not 600: every length prefix above that
            // — `FOUND_VALUE` pages, `STORE_BATCH` bodies, the source-contact
            // trailer — was outside the range the fuzz could ever produce.
            let len = rng.gen_range(0..=MAX_DELIVERABLE_PAYLOAD);
            let mut payload = vec![0u8; len];
            rng.fill(&mut payload[..]);

            let mut buf = Vec::with_capacity(payload.len() + 120);
            buf.push(EMBER_DHT_VERSION);
            buf.push(msg_type);
            buf.extend_from_slice(&rng.gen::<u32>().to_le_bytes());
            buf.extend_from_slice(&id.0);
            buf.extend_from_slice(&sk.verifying_key().to_bytes());
            buf.extend_from_slice(&(payload.len() as u16).to_le_bytes());
            buf.extend_from_slice(&payload);
            // Same domain tag and session binding `encode_message` applies.
            // Without them nothing here clears signature verification and the
            // fuzz never reaches the payload decoders it exists to exercise.
            let suffix = frame_signing_suffix(&mut buf, &TEST_NOISE_PUB);
            let sig = crypto::sign(&sk, &buf);
            buf.truncate(buf.len() - suffix);
            buf.extend_from_slice(&sig);

            if decode_message(&buf, true, &TEST_NOISE_PUB).is_ok() {
                random_decoded_ok += 1;
            }
        }
        assert!(
            random_decoded_ok > 0,
            "the fuzz never produced a frame that reached the payload decoders"
        );
    }

    #[test]
    fn announce_peer_peer_list_round_trip() {
        let (sk, id) = test_keypair();
        let contacts = vec![
            test_contact(21, "203.0.113.1:4662", 0x11),
            test_contact(22, "203.0.113.2:4663", 0x22),
        ];
        let announce = build_announce_peer(id, 55, contacts.clone());
        let encoded = encode_message(&announce, &sk, true, &TEST_NOISE_PUB);
        let decoded = decode_message(&encoded, true, &TEST_NOISE_PUB).unwrap();
        match decoded.payload {
            DhtPayload::AnnouncePeer { contacts: got } => {
                assert_eq!(got.len(), 2);
                assert_eq!(got[0].node_id, contacts[0].node_id);
                assert_eq!(got[1].addr, contacts[1].addr);
            }
            _ => panic!("expected AnnouncePeer"),
        }

        let list = build_peer_list(id, 55, contacts.clone());
        let encoded = encode_message(&list, &sk, true, &TEST_NOISE_PUB);
        let decoded = decode_message(&encoded, true, &TEST_NOISE_PUB).unwrap();
        match decoded.payload {
            DhtPayload::PeerList { contacts: got } => {
                assert_eq!(got.len(), 2);
                assert_eq!(got[1].node_id, contacts[1].node_id);
            }
            _ => panic!("expected PeerList"),
        }
    }

    #[test]
    fn find_node_round_trip() {
        let (sk, id) = test_keypair();
        let target = EmberNodeId([0xAA; 16]);

        let msg = build_find_node(id, 99, target);
        let encoded = encode_message(&msg, &sk, true, &TEST_NOISE_PUB);
        let decoded = decode_message(&encoded, true, &TEST_NOISE_PUB).unwrap();

        match decoded.payload {
            DhtPayload::FindNode { target: t } => {
                assert_eq!(t, target);
            }
            _ => panic!("expected FindNode"),
        }
    }

    #[test]
    fn found_node_with_contacts_round_trip() {
        let (sk, id) = test_keypair();

        let contacts = vec![
            test_contact(11, "1.2.3.4:4662", 0xAA),
            test_contact(12, "[::1]:4663", 0xCC),
        ];

        let msg = build_found_node(id, 100, contacts.clone());
        let encoded = encode_message(&msg, &sk, true, &TEST_NOISE_PUB);
        let decoded = decode_message(&encoded, true, &TEST_NOISE_PUB).unwrap();

        match decoded.payload {
            DhtPayload::FoundNode {
                contacts: decoded_contacts,
            } => {
                assert_eq!(decoded_contacts.len(), 2);
                // node_id is re-derived from the Ed25519 key on decode and
                // must match the (correctly derived) id we encoded.
                assert_eq!(decoded_contacts[0].node_id, contacts[0].node_id);
                assert_eq!(decoded_contacts[0].addr, contacts[0].addr);
                assert_eq!(decoded_contacts[0].noise_pub, contacts[0].noise_pub);
                assert_eq!(decoded_contacts[0].ed25519_pub, contacts[0].ed25519_pub);
                assert_eq!(decoded_contacts[1].node_id, contacts[1].node_id);
                assert_eq!(decoded_contacts[1].addr, contacts[1].addr);
            }
            _ => panic!("expected FoundNode"),
        }
    }

    #[test]
    fn contact_list_drops_invalid_ed25519_keys() {
        use ed25519_dalek::VerifyingKey;
        // Find a 32-byte value that is NOT a valid Ed25519 point encoding
        // (roughly half of all y-coordinates fail to decompress).
        let bad_ed = (1u8..=255)
            .map(|i| [i; 32])
            .find(|c| VerifyingKey::from_bytes(c).is_err())
            .expect("an invalid Ed25519 encoding should exist");

        // A contact whose Ed25519 key isn't a valid curve point can't be
        // verified or dialed; decode must drop it rather than admit a contact
        // under an unverifiable identity.
        let good = test_contact(21, "9.9.9.9:1111", 0x01);
        let mut encoded = encode_contact_list(std::slice::from_ref(&good));
        // Append a second hand-rolled contact with the invalid key.
        encoded[0] = 2; // bump declared count
        encoded.push(ADDR_IPV4);
        encoded.extend_from_slice(&[8, 8, 8, 8]);
        encoded.extend_from_slice(&2000u16.to_be_bytes());
        encoded.extend_from_slice(&[0x02; 32]); // noise_pub
        encoded.extend_from_slice(&bad_ed); // invalid ed25519_pub

        let decoded = decode_contact_list(&encoded).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].node_id, good.node_id);
    }

    /// v3 dropped the `node_id` from each wire contact, which buys three more
    /// contacts per response — most of a hop on a sparse table.
    ///
    /// Pinned because the gain is purely a function of the byte budget: any
    /// field a future version adds to a contact spends it silently, and the
    /// symptom (shorter contact lists, so slower lookups) is not one anybody
    /// would trace back to an encoder change.
    #[test]
    fn a_found_node_carries_more_contacts_than_v2_could() {
        let contacts: Vec<EmberContact> = (1u8..=MAX_CONTACTS_PER_RESPONSE as u8)
            .map(|i| test_contact(i, &format!("10.0.0.{i}:{}", 1000 + i as u16), i))
            .collect();
        let encoded = encode_contact_list(&contacts);
        let carried = encoded[0] as usize;

        assert_eq!(
            encoded.len(),
            1 + carried * CONTACT_WIRE_LEN_IPV4,
            "an IPv4 contact must cost exactly CONTACT_WIRE_LEN_IPV4"
        );
        assert!(
            encoded.len() <= MAX_UNFRAGMENTED_PAYLOAD,
            "a contact list must not fragment"
        );
        assert_eq!(carried, 17, "the byte budget fits 17 contacts at 71 bytes");

        // What the same budget bought while every contact restated its ID.
        const V2_CONTACT_WIRE_LEN_IPV4: usize = CONTACT_WIRE_LEN_IPV4 + 16;
        assert_eq!((MAX_UNFRAGMENTED_PAYLOAD - 1) / V2_CONTACT_WIRE_LEN_IPV4, 14);

        // And the trimmed list still decodes, with every ID derived from its key.
        let decoded = decode_contact_list(&encoded).expect("a trimmed list decodes");
        assert_eq!(decoded.len(), carried);
        for contact in &decoded {
            assert_eq!(
                contact.node_id.0,
                crypto::node_id_from_ed25519_bytes(&contact.ed25519_pub).unwrap()
            );
        }
    }

    /// The friend-session contact exchange refuses a body over
    /// [`MAX_CONTACT_LIST_BYTES`] before decoding it, so that cap has to be
    /// above anything the encoder can emit — otherwise the guard would drop
    /// honest answers, and the symptom (a friend's contacts never arriving)
    /// looks exactly like the friend running an older build.
    #[test]
    fn the_contact_list_size_cap_cannot_refuse_an_honest_list() {
        let ipv4: Vec<EmberContact> = (1u8..=MAX_CONTACTS_PER_RESPONSE as u8)
            .map(|i| test_contact(i, &format!("10.0.0.{i}:{}", 1000 + i as u16), i))
            .collect();
        assert!(encode_contact_list(&ipv4).len() <= MAX_CONTACT_LIST_BYTES);

        // The wider case the cap is actually sized for. The encoder's own byte
        // budget stops it well short, which is the point: the cap bounds the
        // format, not the datagram, so it stays correct if the budget changes.
        let ipv6: Vec<EmberContact> = (1u8..=MAX_CONTACTS_PER_RESPONSE as u8)
            .map(|i| test_contact(i, &format!("[2001:db8::{i:x}]:{}", 1000 + i as u16), i))
            .collect();
        let encoded = encode_contact_list(&ipv6);
        assert!(
            encoded.len() <= MAX_CONTACT_LIST_BYTES,
            "an IPv6 list encodes to {} bytes, over the {MAX_CONTACT_LIST_BYTES} the \
             friend path accepts",
            encoded.len()
        );
        assert_eq!(
            MAX_CONTACT_LIST_BYTES,
            1 + MAX_CONTACTS_PER_RESPONSE * (CONTACT_WIRE_LEN_IPV4 + 12),
            "an IPv6 contact is twelve bytes wider than an IPv4 one"
        );
    }

    #[test]
    fn contact_list_rejects_truncation() {
        let good = test_contact(22, "9.9.9.9:1111", 0x01);
        let mut encoded = encode_contact_list(&[good]);
        // Claim two contacts but provide bytes for only one.
        encoded[0] = 2;
        assert!(decode_contact_list(&encoded).is_err());
    }

    #[test]
    fn signature_verification_fails_on_tamper() {
        let (sk, id) = test_keypair();
        let msg = build_ping(id, 1);
        let mut encoded = encode_message(&msg, &sk, true, &TEST_NOISE_PUB);

        // Tamper with the request_id
        encoded[3] ^= 0xFF;

        let result = decode_message(&encoded, true, &TEST_NOISE_PUB);
        assert!(result.is_err());
    }

    #[test]
    fn contact_list_ipv4_and_ipv6() {
        let contacts = vec![
            test_contact(31, "10.0.0.1:1000", 0x10),
            test_contact(32, "[2001:db8::1]:2000", 0x20),
        ];

        let encoded = encode_contact_list(&contacts);
        let decoded = decode_contact_list(&encoded).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(
            decoded[0].addr,
            "10.0.0.1:1000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(decoded[0].node_id, contacts[0].node_id);
        assert_eq!(
            decoded[1].addr,
            "[2001:db8::1]:2000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(decoded[1].node_id, contacts[1].node_id);
    }

    /// A STORE body that cannot pack into a FOUND_VALUE even as the only blob
    /// must be refused at decode, or it stores-but-hides.
    #[test]
    fn a_store_body_over_the_found_value_budget_is_refused() {
        let (sk, id) = test_keypair();
        let too_big = vec![0u8; MAX_STORE_RECORD_BYTES + 1];
        let msg = build_store_record(id, 1, [0xAB; 16], too_big, [0u8; 64]);
        let encoded = encode_message(&msg, &sk, true, &TEST_NOISE_PUB);
        assert!(decode_message(&encoded, true, &TEST_NOISE_PUB).is_err());

        let fits = vec![0u8; MAX_STORE_RECORD_BYTES];
        let msg = build_store_record(id, 2, [0xAB; 16], fits, [0u8; 64]);
        let encoded = encode_message(&msg, &sk, true, &TEST_NOISE_PUB);
        let decoded = decode_message(&encoded, true, &TEST_NOISE_PUB).expect("max-size body still decodes");
        match decoded.payload {
            DhtPayload::StoreRecord { record, .. } => {
                assert_eq!(record.len(), MAX_STORE_RECORD_BYTES);
            }
            other => panic!("expected StoreRecord, got {other:?}"),
        }
    }

    /// FOUND_VALUE blobs are body||signature, so the length prefix is 64
    /// larger than the STORE body cap. Using MAX_STORE_RECORD_BYTES here
    /// would reject a perfectly packable singleton.
    #[test]
    fn a_found_value_blob_at_the_store_body_cap_still_decodes() {
        let (sk, id) = test_keypair();
        let blob = vec![0u8; MAX_FOUND_VALUE_BLOB_BYTES];
        let msg = DhtMessage {
            version: EMBER_DHT_VERSION,
            msg_type: MSG_FOUND_VALUE,
            request_id: 1,
            sender_id: id,
            sender_pub_key: None,
            payload: DhtPayload::FoundValue {
                key: [0xCD; 16],
                records: vec![blob],
                next_position: 1,
                total_available: 1,
            },
            signature: [0u8; 64],
        };
        let encoded = encode_message(&msg, &sk, true, &TEST_NOISE_PUB);
        let decoded = decode_message(&encoded, true, &TEST_NOISE_PUB).expect("max blob decodes");
        match decoded.payload {
            DhtPayload::FoundValue { records, .. } => {
                assert_eq!(records[0].len(), MAX_FOUND_VALUE_BLOB_BYTES);
            }
            other => panic!("expected FoundValue, got {other:?}"),
        }

        let too_big = vec![0u8; MAX_FOUND_VALUE_BLOB_BYTES + 1];
        let msg = DhtMessage {
            version: EMBER_DHT_VERSION,
            msg_type: MSG_FOUND_VALUE,
            request_id: 2,
            sender_id: id,
            sender_pub_key: None,
            payload: DhtPayload::FoundValue {
                key: [0xCD; 16],
                records: vec![too_big],
                next_position: 1,
                total_available: 1,
            },
            signature: [0u8; 64],
        };
        let encoded = encode_message(&msg, &sk, true, &TEST_NOISE_PUB);
        assert!(decode_message(&encoded, true, &TEST_NOISE_PUB).is_err());
    }

    /// Both paging positions have to survive the wire, and the `start_position`
    /// has to survive sitting *after* a variable-length key run.
    #[test]
    fn find_value_paging_positions_round_trip() {
        let (sk, id) = test_keypair();

        let ask = build_find_value(id, 1, vec![[0xA1; 16], [0xA2; 16]], 4321);
        let decoded = decode_message(&encode_message(&ask, &sk, true, &TEST_NOISE_PUB), true, &TEST_NOISE_PUB).unwrap();
        match decoded.payload {
            DhtPayload::FindValue {
                keys,
                start_position,
            } => {
                assert_eq!(keys, vec![[0xA1; 16], [0xA2; 16]]);
                assert_eq!(start_position, 4321);
            }
            other => panic!("expected FindValue, got {other:?}"),
        }

        let answer = build_found_value(id, 2, [0xB0; 16], vec![vec![7u8; 40]], 9, 900);
        let decoded = decode_message(&encode_message(&answer, &sk, true, &TEST_NOISE_PUB), true, &TEST_NOISE_PUB).unwrap();
        match decoded.payload {
            DhtPayload::FoundValue {
                key,
                records,
                next_position,
                total_available,
            } => {
                assert_eq!(key, [0xB0; 16]);
                assert_eq!(records, vec![vec![7u8; 40]]);
                assert_eq!(next_position, 9);
                assert_eq!(total_available, 900);
            }
            other => panic!("expected FoundValue, got {other:?}"),
        }
    }

    /// A `FIND_VALUE` whose `start_position` is missing must be refused, not
    /// read as position zero. Silently defaulting would make a truncated frame
    /// look like a first-page request and re-serve records the searcher already
    /// had, for as many pages as it asked for.
    #[test]
    fn a_find_value_without_its_start_position_is_refused() {
        let (_, id) = test_keypair();
        let ask = build_find_value(id, 1, vec![[0xA1; 16]], 7);
        let full = encode_payload(&ask.payload);
        assert!(decode_payload(MSG_FIND_VALUE, &full).is_ok());
        assert!(
            decode_payload(MSG_FIND_VALUE, &full[..full.len() - 1]).is_err(),
            "a half-written position must not decode"
        );
        assert!(
            decode_payload(MSG_FIND_VALUE, &full[..full.len() - 2]).is_err(),
            "an absent position must not decode as zero"
        );
    }

    /// A lookup for nothing. No builder here can produce one, and the engine
    /// reads `keys[0]` as the key to serve — with nothing to fall back on but
    /// its own id, so an empty request was answered with our closest contacts
    /// to ourselves. That is a `FIND_NODE` wearing another opcode, and it
    /// belongs in the decoder's refusals with every other malformed frame.
    #[test]
    fn a_find_value_with_no_keys_is_refused() {
        let (_, id) = test_keypair();
        let one_key = encode_payload(&build_find_value(id, 1, vec![[0xA1; 16]], 0).payload);
        assert!(decode_payload(MSG_FIND_VALUE, &one_key).is_ok());

        // The same frame with its key run removed: count 0, then the position.
        let empty = [0u8, 0u8, 0u8];
        assert!(
            decode_payload(MSG_FIND_VALUE, &empty).is_err(),
            "a keyless FIND_VALUE must not decode"
        );
    }

    #[test]
    fn callback_req_and_callback_round_trip() {
        let (sk, id) = test_keypair();
        let publisher = EmberNodeId([0x11; 16]);
        let file_hash = [0x22u8; 16];
        let user_hash = [0x33u8; 16];
        let token = [0x44u8; 16];
        let req = build_callback_req(id, 7, publisher, file_hash, 4662, 0x03, user_hash, token);
        let encoded = encode_message(&req, &sk, true, &TEST_NOISE_PUB);
        let decoded = decode_message(&encoded, true, &TEST_NOISE_PUB).unwrap();
        match decoded.payload {
            DhtPayload::CallbackReq {
                publisher_id,
                file_hash: fh,
                searcher_tcp_port,
                crypt_options,
                searcher_user_hash,
                callback_token,
            } => {
                assert_eq!(publisher_id, publisher);
                assert_eq!(fh, file_hash);
                assert_eq!(searcher_tcp_port, 4662);
                assert_eq!(crypt_options, 0x03);
                assert_eq!(searcher_user_hash, user_hash);
                assert_eq!(callback_token, token);
            }
            other => panic!("expected CallbackReq, got {other:?}"),
        }

        let ip = Ipv4Addr::new(8, 8, 4, 4);
        let cb = build_callback(id, 8, file_hash, ip, 4662, 0x03, user_hash, token);
        let encoded = encode_message(&cb, &sk, true, &TEST_NOISE_PUB);
        let decoded = decode_message(&encoded, true, &TEST_NOISE_PUB).unwrap();
        match decoded.payload {
            DhtPayload::Callback {
                file_hash: fh,
                searcher_ip,
                searcher_tcp_port,
                crypt_options,
                searcher_user_hash,
                callback_token,
            } => {
                assert_eq!(fh, file_hash);
                assert_eq!(searcher_ip, ip);
                assert_eq!(searcher_tcp_port, 4662);
                assert_eq!(crypt_options, 0x03);
                assert_eq!(searcher_user_hash, user_hash);
                assert_eq!(callback_token, token);
            }
            other => panic!("expected Callback, got {other:?}"),
        }
    }

    #[test]
    fn buddy_endorse_round_trip() {
        let (sk, id) = test_keypair();
        let req = build_buddy_endorse_req(id, 9);
        let encoded = encode_message(&req, &sk, true, &TEST_NOISE_PUB);
        let decoded = decode_message(&encoded, true, &TEST_NOISE_PUB).unwrap();
        assert!(matches!(decoded.payload, DhtPayload::BuddyEndorseReq));
        assert_eq!(decoded.request_id, 9, "the answer has to match the ask");

        let ip = Ipv4Addr::new(8, 8, 4, 4);
        let noise = [0x5Au8; 32];
        let sig = [0x6Bu8; 64];
        let msg = build_buddy_endorse(id, 9, ip, 4672, noise, 1_700_000_000, sig);
        let encoded = encode_message(&msg, &sk, true, &TEST_NOISE_PUB);
        let decoded = decode_message(&encoded, true, &TEST_NOISE_PUB).unwrap();
        match decoded.payload {
            DhtPayload::BuddyEndorse {
                ip: got_ip,
                udp_port,
                noise_pub,
                expires_at,
                signature,
            } => {
                assert_eq!(got_ip, ip);
                assert_eq!(udp_port, 4672);
                assert_eq!(noise_pub, noise);
                assert_eq!(expires_at, 1_700_000_000);
                assert_eq!(signature, sig);
            }
            other => panic!("expected BuddyEndorse, got {other:?}"),
        }

        // The verifier reads the key off the frame, so the endorsement is only
        // ever attributable to the sender the signature check bound it to.
        assert_eq!(decoded.sender_pub_key, Some(sk.verifying_key().to_bytes()));

        // A short or long body is a framing error, not a partial endorsement.
        let mut truncated = build_buddy_endorse(id, 9, ip, 4672, noise, 1, sig);
        truncated.payload = DhtPayload::Unknown(vec![0u8; BUDDY_ENDORSE_WIRE_LEN - 1]);
        let encoded = encode_message(&truncated, &sk, true, &TEST_NOISE_PUB);
        assert!(decode_message(&encoded, true, &TEST_NOISE_PUB).is_err());
    }
}
