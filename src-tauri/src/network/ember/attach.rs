//! Chat attachments: one friend hands one file to one other friend.
//!
//! This is the friend-scoped sibling of [`super::xfer`], and it exists because
//! that one cannot be reused as it stands. Room transfers ride channel gossip,
//! so their key derivation, their transport and their authorization are all
//! bound to a `channel_id`, and their blocks are 1008 bytes at 192/sec — a
//! ceiling of roughly 190 KB/s, which is the wrong order of magnitude for
//! "send my friend this file". `channel.rs` says as much: the framing was
//! written so "a later QUIC or multi-source implementation can carry the same
//! offers without a new handshake".
//!
//! So the shape is kept and the two halves are split across the transports
//! that suit them:
//!
//! * **Signalling** — the offer, the answer, and a cancellation — goes over the
//!   authenticated friend session, which is a Noise IK stream already carrying
//!   chat. These are tens of bytes and want the session's reliability and its
//!   existing reachability story (direct TCP, hole-punched QUIC, or relay).
//! * **Bytes** go over their own QUIC stream, dialled with the recipient's
//!   Ember identity pinned into the TLS verifier. QUIC brings congestion
//!   control, which is the actual difference between this and the room path,
//!   and [`super::quic`] is already tuned for throughput (8 MiB stream window).
//!
//! Nothing here touches the shared library index, KAD, the eD2K servers, or
//! `resolve_upload_file`. A chat attachment is never published and never
//! becomes a library file: the sender authorizes exactly one peer to read
//! exactly one path for as long as the grant lives. That is deliberate. The
//! eD2K route would have had to widen the one gate that decides whether a
//! stranger may read a local file, and an attachment mid-download would have
//! been served from the `.part` fallback to anyone who asked.
//!
//! # What authorizes a transfer
//!
//! Two independent things, and the weaker one is not load-bearing:
//!
//! 1. **The QUIC certificate.** The recipient dials with the sender's node id
//!    pinned, and the sender reads the dialer's node id back out of the
//!    certificate the TLS handshake proved possession of
//!    ([`super::quic::connection_node_id`]). An Ember node id *is*
//!    `BLAKE3(ed25519_pub)[..16]`, the same 16 bytes a friend is known by, so
//!    this is the friend's real identity rather than a claim.
//! 2. **The capability tag**, below. It proves the dialer actually received the
//!    offer, because it cannot be computed without one of the two private keys.
//!    A `xfer_id` is 16 random bytes, so this is not what stops guessing — it
//!    stops a *friend* from probing for transfers meant for someone else.

use super::crypto;
use super::transfer::{root_from_chunk_hashes, CHUNK_SIZE};

/// Payload bytes per chunk. The stream is reliable and ordered, so this is a
/// read/verify granularity rather than a datagram budget — hence 256 KiB here
/// against the room path's 1008 bytes.
pub const ATTACH_CHUNK_SIZE: usize = CHUNK_SIZE;

/// Largest file one friend may send another in a chat.
///
/// The chunk-hash list the receiver checks the root against costs 32 bytes per
/// chunk, so this is also what bounds that list: 2 GiB is 8192 chunks and a
/// 256 KiB list, which is 0.012% of the transfer.
pub const ATTACH_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Longest attachment file name carried on the wire, in bytes.
pub const ATTACH_NAME_MAX: usize = 160;

/// How long an offer waits for an answer before it lapses on both sides.
pub const ATTACH_OFFER_TTL_SECS: i64 = 300;

/// How long a sender keeps a grant readable after the offer was answered.
///
/// A transfer that is progressing refreshes this; the cap is what stops a
/// declined-then-forgotten offer leaving a path readable for the session.
pub const ATTACH_GRANT_TTL_SECS: i64 = 24 * 60 * 60;

/// Default ceiling under which an inbound attachment is taken without asking.
///
/// Messaging apps fetch small files silently and prompt for large ones, which
/// is the behaviour people expect; the setting exists because "small" is a
/// judgement about someone's disk and connection, not a constant.
pub const ATTACH_AUTO_ACCEPT_DEFAULT_MB: u64 = 25;

/// First byte of an attachment data stream.
///
/// The QUIC accept loop in [`super::relay`] owns `endpoint.accept()` and
/// discriminates connections on the first byte of their first stream. Relay
/// control messages use 0x01–0x06 and a tunnelled eMule stream starts at 0xC5
/// or above, so this claims a byte in the gap between them.
pub const ATTACH_STREAM_MSG_TYPE: u8 = 0x07;

/// First byte of a room transfer's data stream.
///
/// Same request, header and verified chunks as an attachment; its own byte
/// because the accept loop authorizes the two differently — a friend against
/// the grant table, a room member against the transfer offered to them.
pub const ROOM_XFER_STREAM_MSG_TYPE: u8 = 0x08;

/// Wire version of the stream request and of the signalling payloads.
pub const ATTACH_VERSION: u8 = 1;

/// Bytes in a stream request: type, version, 4 reserved, xfer id, tag, cursor.
pub const ATTACH_REQUEST_LEN: usize = 1 + 1 + 4 + 16 + 16 + 4;

/// Bytes of a stream request the accept loop has not already consumed.
///
/// The dispatcher reads a 7-byte prefix to decide what a connection is, so an
/// attachment handler is handed those 7 and reads this many more.
pub const ATTACH_REQUEST_TAIL_LEN: usize = ATTACH_REQUEST_LEN - 7;

/// QUIC close reason a recipient gives once every chunk arrived and verified.
///
/// The sender counts this as delivery alongside the stream's own
/// acknowledgement, because the recipient closes the moment it has the last
/// byte and the ACK for it can be lost behind the close. Earlier builds sent
/// it after every fetch, so it is also what they send on success.
pub const ATTACH_CLOSE_RECEIVED: &[u8] = b"attach done";

/// QUIC close reason a recipient gives when a fetch attempt did not finish.
pub const ATTACH_CLOSE_ABANDONED: &[u8] = b"attach abandoned";

/// Keyed-hash domain for the capability tag on a stream request.
const ATTACH_TAG_DOMAIN: &[u8] = b"ember-attach-stream-tag-v1";

/// Purpose string binding a pairwise capability to attachments.
const ATTACH_CAPABILITY_PURPOSE: &[u8] = b"friend-attach-v1";

/// Length of the capability tag on the wire.
pub const ATTACH_TAG_LEN: usize = 16;

/// Answer to an attachment offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachReply {
    /// The recipient wants the file and will dial for it.
    Accept,
    /// The recipient said no.
    Decline,
    /// Over [`ATTACH_MAX_BYTES`], or over what this recipient will take.
    TooLarge,
    /// The recipient already has as many attachments running as it will take.
    Busy,
    /// The recipient's settings refuse attachments from this sender.
    NotAllowed,
}

impl AttachReply {
    pub fn to_byte(self) -> u8 {
        match self {
            AttachReply::Accept => 0,
            AttachReply::Decline => 1,
            AttachReply::TooLarge => 2,
            AttachReply::Busy => 3,
            AttachReply::NotAllowed => 4,
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => AttachReply::Accept,
            1 => AttachReply::Decline,
            2 => AttachReply::TooLarge,
            3 => AttachReply::Busy,
            4 => AttachReply::NotAllowed,
            _ => return None,
        })
    }

    /// Whether this answer is one the sender should treat as "keep the grant".
    pub fn is_accept(self) -> bool {
        matches!(self, AttachReply::Accept)
    }
}

/// Why a transfer was given up on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachCancel {
    /// Someone pressed cancel.
    User,
    /// The sender can no longer read the file it offered.
    SourceGone,
    /// Nothing arrived for long enough that the transfer was abandoned.
    Stalled,
    /// The bytes did not match the hashes they were offered under.
    Corrupt,
    /// The recipient never got a direct connection to the sender: the friend
    /// session runs through a relay, or every dial failed to connect at all.
    Unreachable,
}

impl AttachCancel {
    pub fn to_byte(self) -> u8 {
        match self {
            AttachCancel::User => 0,
            AttachCancel::SourceGone => 1,
            AttachCancel::Stalled => 2,
            AttachCancel::Corrupt => 3,
            AttachCancel::Unreachable => 4,
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => AttachCancel::User,
            1 => AttachCancel::SourceGone,
            2 => AttachCancel::Stalled,
            3 => AttachCancel::Corrupt,
            4 => AttachCancel::Unreachable,
            _ => return None,
        })
    }
}

/// An offer as it travels over the friend session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachOffer {
    pub xfer_id: [u8; 16],
    pub size: u64,
    /// BLAKE3 root over the file's 256 KiB chunk hashes — the commitment the
    /// chunk-hash list is later checked against.
    pub root: [u8; 32],
    /// Public UDP port of the sender's QUIC endpoint. The address is the one
    /// the friend session came from; only the port has to be carried, because
    /// QUIC and the session are different sockets.
    pub quic_port: u16,
    pub name: String,
}

/// Derive the pairwise capability an attachment's stream tag is keyed with.
///
/// Symmetric by construction — [`crypto::derive_pairwise_capability`] sorts the
/// two public keys — so both ends compute the same value without either having
/// to say which of them is which. Epoch 0 pins it: a transfer may outlive a
/// rotating capability epoch, and a resumed stream has to verify under the same
/// key the offer was made with.
pub fn derive_attach_capability(
    our_ed25519_seed: &[u8; 32],
    peer_ed25519_pubkey: &[u8; 32],
    xfer_id: &[u8; 16],
) -> Option<[u8; 32]> {
    let mut purpose = Vec::with_capacity(ATTACH_CAPABILITY_PURPOSE.len() + 16);
    purpose.extend_from_slice(ATTACH_CAPABILITY_PURPOSE);
    purpose.extend_from_slice(xfer_id);
    crypto::derive_pairwise_capability(our_ed25519_seed, peer_ed25519_pubkey, &purpose, 0)
}

/// The tag a requester puts on a stream request to show it holds the offer.
pub fn attach_stream_tag(capability: &[u8; 32], xfer_id: &[u8; 16]) -> [u8; ATTACH_TAG_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(capability);
    hasher.update(ATTACH_TAG_DOMAIN);
    hasher.update(xfer_id);
    let digest = hasher.finalize();
    let mut tag = [0u8; ATTACH_TAG_LEN];
    tag.copy_from_slice(&digest.as_bytes()[..ATTACH_TAG_LEN]);
    tag
}

/// Compare two stream tags without leaking where they first differ.
///
/// The derived `PartialEq` on `[u8; 16]` returns at the first differing byte. A
/// peer that can time our refusal could walk that timing to recover the tag one
/// byte at a time — 16×256 probes rather than 2^128 — and the tag is the proof
/// that the dialer was actually offered this transfer. Same shape, and the same
/// reason, as `engine::callback_tokens_match`.
pub fn attach_tags_match(expected: &[u8; ATTACH_TAG_LEN], got: &[u8; ATTACH_TAG_LEN]) -> bool {
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(got.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// A request to open the data stream for one attachment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachRequest {
    pub xfer_id: [u8; 16],
    pub tag: [u8; ATTACH_TAG_LEN],
    /// Chunk index to start at, so an interrupted transfer resumes rather than
    /// starting over. The receiver only ever asks from a chunk it has verified
    /// every predecessor of.
    pub start_chunk: u32,
}

#[cfg(test)]
pub fn encode_attach_request(req: &AttachRequest) -> Vec<u8> {
    encode_stream_request(ATTACH_STREAM_MSG_TYPE, req)
}

#[cfg(test)]
pub fn decode_attach_request(bytes: &[u8]) -> Option<AttachRequest> {
    decode_stream_request(ATTACH_STREAM_MSG_TYPE, bytes)
}

/// A stream request under `stream_type`: [`ATTACH_STREAM_MSG_TYPE`] for a chat
/// attachment, [`ROOM_XFER_STREAM_MSG_TYPE`] for a room transfer. The layout
/// is shared; only the first byte, and so who the accept loop asks to
/// authorize it, differs.
pub fn encode_stream_request(stream_type: u8, req: &AttachRequest) -> Vec<u8> {
    let mut out = Vec::with_capacity(ATTACH_REQUEST_LEN);
    out.push(stream_type);
    out.push(ATTACH_VERSION);
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&req.xfer_id);
    out.extend_from_slice(&req.tag);
    out.extend_from_slice(&req.start_chunk.to_le_bytes());
    debug_assert_eq!(out.len(), ATTACH_REQUEST_LEN);
    out
}

pub fn decode_stream_request(stream_type: u8, bytes: &[u8]) -> Option<AttachRequest> {
    if bytes.len() != ATTACH_REQUEST_LEN {
        return None;
    }
    if bytes[0] != stream_type || bytes[1] != ATTACH_VERSION {
        return None;
    }
    let mut xfer_id = [0u8; 16];
    xfer_id.copy_from_slice(&bytes[6..22]);
    let mut tag = [0u8; ATTACH_TAG_LEN];
    tag.copy_from_slice(&bytes[22..22 + ATTACH_TAG_LEN]);
    let start = 22 + ATTACH_TAG_LEN;
    let start_chunk = u32::from_le_bytes(bytes[start..start + 4].try_into().ok()?);
    Some(AttachRequest {
        xfer_id,
        tag,
        start_chunk,
    })
}

/// Status byte a sender answers a stream request with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachStreamStatus {
    Ok,
    /// No live grant for this `xfer_id` and this peer.
    Unknown,
    /// The grant exists but the tag did not verify.
    Unauthorized,
    /// The file named by the grant can no longer be read.
    SourceGone,
    /// The requester asked to resume past the end of the file.
    BadCursor,
}

impl AttachStreamStatus {
    pub fn to_byte(self) -> u8 {
        match self {
            AttachStreamStatus::Ok => 0,
            AttachStreamStatus::Unknown => 1,
            AttachStreamStatus::Unauthorized => 2,
            AttachStreamStatus::SourceGone => 3,
            AttachStreamStatus::BadCursor => 4,
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => AttachStreamStatus::Ok,
            1 => AttachStreamStatus::Unknown,
            2 => AttachStreamStatus::Unauthorized,
            3 => AttachStreamStatus::SourceGone,
            4 => AttachStreamStatus::BadCursor,
            _ => return None,
        })
    }
}

/// Header the sender writes before any file bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachFileInfo {
    pub size: u64,
    /// BLAKE3 of each 256 KiB chunk, in order. Checked against the offered root
    /// before a single byte of the file is trusted.
    pub chunk_hashes: Vec<[u8; 32]>,
}

impl AttachFileInfo {
    /// Whether this list is the one the offer's root committed to.
    ///
    /// Must be called before any chunk is written to disk. Without it the
    /// per-chunk hashes are just whatever the sender said, and a sender that
    /// sends a consistent lie about both the chunks and the list would only be
    /// caught by re-reading the finished file.
    pub fn matches_root(&self, root: &[u8; 32]) -> bool {
        root_from_chunk_hashes(&self.chunk_hashes) == *root
    }

    /// Chunks a file of this size is cut into.
    pub fn chunk_count(&self) -> usize {
        self.chunk_hashes.len()
    }

    /// Length of the chunk at `index`, which is short for the last one.
    pub fn chunk_len(&self, index: usize) -> Option<usize> {
        let count = self.chunk_count();
        if index >= count {
            return None;
        }
        let full = ATTACH_CHUNK_SIZE as u64;
        let start = index as u64 * full;
        Some((self.size - start).min(full) as usize)
    }
}

pub fn encode_attach_file_info(info: &AttachFileInfo) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + 4 + info.chunk_hashes.len() * 32);
    out.push(AttachStreamStatus::Ok.to_byte());
    out.extend_from_slice(&info.size.to_le_bytes());
    out.extend_from_slice(&(info.chunk_hashes.len() as u32).to_le_bytes());
    for hash in &info.chunk_hashes {
        out.extend_from_slice(hash);
    }
    out
}

/// Chunks a file of `size` bytes is cut into, or `None` if it is not a size an
/// attachment may have.
pub fn attach_chunk_count(size: u64) -> Option<u32> {
    if size == 0 || size > ATTACH_MAX_BYTES {
        return None;
    }
    u32::try_from(size.div_ceil(ATTACH_CHUNK_SIZE as u64)).ok()
}

/// Read the header a sender answered with, given the declared chunk count.
///
/// Split from the body read because the count decides how many bytes the list
/// is, and a receiver must not allocate from a number a peer chose without
/// bounding it first — which [`attach_chunk_count`] does against the size.
pub fn decode_attach_file_info(bytes: &[u8]) -> Result<AttachFileInfo, AttachStreamStatus> {
    let status = bytes
        .first()
        .and_then(|b| AttachStreamStatus::from_byte(*b))
        .ok_or(AttachStreamStatus::Unknown)?;
    if status != AttachStreamStatus::Ok {
        return Err(status);
    }
    if bytes.len() < 1 + 8 + 4 {
        return Err(AttachStreamStatus::Unknown);
    }
    let size = u64::from_le_bytes(bytes[1..9].try_into().map_err(|_| AttachStreamStatus::Unknown)?);
    let declared = u32::from_le_bytes(
        bytes[9..13]
            .try_into()
            .map_err(|_| AttachStreamStatus::Unknown)?,
    );
    // The size decides the count, so a count that disagrees with it is a
    // malformed header rather than something to trust and allocate from.
    if attach_chunk_count(size) != Some(declared) {
        return Err(AttachStreamStatus::Unknown);
    }
    let want = 13 + declared as usize * 32;
    if bytes.len() != want {
        return Err(AttachStreamStatus::Unknown);
    }
    let mut chunk_hashes = Vec::with_capacity(declared as usize);
    for i in 0..declared as usize {
        let at = 13 + i * 32;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[at..at + 32]);
        chunk_hashes.push(hash);
    }
    Ok(AttachFileInfo { size, chunk_hashes })
}

/// Bytes of the chunk-hash list for a file of `size`, for sizing a read.
pub fn attach_file_info_len(size: u64) -> Option<usize> {
    let count = attach_chunk_count(size)?;
    Some(13 + count as usize * 32)
}

// --- Signalling payloads, carried over the friend session -------------------

pub fn encode_attach_offer(offer: &AttachOffer) -> Option<Vec<u8>> {
    let name = offer.name.as_bytes();
    if name.is_empty() || name.len() > ATTACH_NAME_MAX {
        return None;
    }
    attach_chunk_count(offer.size)?;
    let mut out = Vec::with_capacity(1 + 16 + 8 + 32 + 2 + 1 + name.len());
    out.push(ATTACH_VERSION);
    out.extend_from_slice(&offer.xfer_id);
    out.extend_from_slice(&offer.size.to_le_bytes());
    out.extend_from_slice(&offer.root);
    out.extend_from_slice(&offer.quic_port.to_le_bytes());
    out.push(name.len() as u8);
    out.extend_from_slice(name);
    Some(out)
}

pub fn decode_attach_offer(bytes: &[u8]) -> Option<AttachOffer> {
    if bytes.first().copied()? != ATTACH_VERSION {
        return None;
    }
    if bytes.len() < 1 + 16 + 8 + 32 + 2 + 1 {
        return None;
    }
    let mut xfer_id = [0u8; 16];
    xfer_id.copy_from_slice(&bytes[1..17]);
    let size = u64::from_le_bytes(bytes[17..25].try_into().ok()?);
    // Refused here rather than by the caller: a size of zero or one past the
    // ceiling has no chunk count, so nothing downstream could act on it.
    attach_chunk_count(size)?;
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes[25..57]);
    let quic_port = u16::from_le_bytes(bytes[57..59].try_into().ok()?);
    let name_len = bytes[59] as usize;
    if name_len == 0 || name_len > ATTACH_NAME_MAX || bytes.len() != 60 + name_len {
        return None;
    }
    // Lossy on purpose: a name is a display hint from a peer, and the caller
    // sanitizes it into a filename separately. Refusing the whole offer over a
    // stray byte would lose the file for a cosmetic reason.
    let name = String::from_utf8_lossy(&bytes[60..60 + name_len]).into_owned();
    Some(AttachOffer {
        xfer_id,
        size,
        root,
        quic_port,
        name,
    })
}

/// Encode an answer to an offer.
///
/// An accept carries the recipient's own public QUIC port, and nothing else
/// does. The recipient is the one that dials, but a sender behind a
/// port-restricted NAT drops that dial unless its NAT has already seen traffic
/// go out to the recipient. With the port, the sender can fire a short-lived
/// dial of its own at the same moment — simultaneous open — which is what opens
/// the mapping the recipient's dial then lands in. A refusal needs no port,
/// because nothing is coming.
pub fn encode_attach_reply(
    xfer_id: &[u8; 16],
    reply: AttachReply,
    quic_port: Option<u16>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 16 + 1 + 2);
    out.push(ATTACH_VERSION);
    out.extend_from_slice(xfer_id);
    out.push(reply.to_byte());
    if let (true, Some(port)) = (reply.is_accept(), quic_port.filter(|p| *p != 0)) {
        out.extend_from_slice(&port.to_le_bytes());
    }
    out
}

/// Decode an answer; the port is present only on an accept that sent one.
pub fn decode_attach_reply(bytes: &[u8]) -> Option<([u8; 16], AttachReply, Option<u16>)> {
    if !(bytes.len() == 1 + 16 + 1 || bytes.len() == 1 + 16 + 1 + 2) || bytes[0] != ATTACH_VERSION
    {
        return None;
    }
    let mut xfer_id = [0u8; 16];
    xfer_id.copy_from_slice(&bytes[1..17]);
    let reply = AttachReply::from_byte(bytes[17])?;
    let port = if bytes.len() == 20 {
        // A port on a refusal is a malformed answer, not a hint to act on.
        if !reply.is_accept() {
            return None;
        }
        Some(u16::from_le_bytes([bytes[18], bytes[19]])).filter(|p| *p != 0)
    } else {
        None
    };
    Some((xfer_id, reply, port))
}

pub fn encode_attach_cancel(xfer_id: &[u8; 16], reason: AttachCancel) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 16 + 1);
    out.push(ATTACH_VERSION);
    out.extend_from_slice(xfer_id);
    out.push(reason.to_byte());
    out
}

pub fn decode_attach_cancel(bytes: &[u8]) -> Option<([u8; 16], AttachCancel)> {
    if bytes.len() != 1 + 16 + 1 || bytes[0] != ATTACH_VERSION {
        return None;
    }
    let mut xfer_id = [0u8; 16];
    xfer_id.copy_from_slice(&bytes[1..17]);
    Some((xfer_id, AttachCancel::from_byte(bytes[17])?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        (sk.to_bytes(), sk.verifying_key().to_bytes())
    }

    fn sample_offer() -> AttachOffer {
        AttachOffer {
            xfer_id: [7u8; 16],
            size: 3 * ATTACH_CHUNK_SIZE as u64 + 11,
            root: *blake3::hash(b"root").as_bytes(),
            quic_port: 41330,
            name: "holiday.zip".into(),
        }
    }

    #[test]
    fn an_offer_round_trips() {
        let offer = sample_offer();
        let bytes = encode_attach_offer(&offer).expect("encodes");
        assert_eq!(decode_attach_offer(&bytes), Some(offer));
    }

    /// A size of zero or past the ceiling has no chunk count, so there is
    /// nothing a receiver could do with it but allocate from a peer's number.
    #[test]
    fn an_offer_outside_the_size_range_is_refused_both_ways() {
        for size in [0, ATTACH_MAX_BYTES + 1] {
            let offer = AttachOffer {
                size,
                ..sample_offer()
            };
            assert!(encode_attach_offer(&offer).is_none(), "size {size} encoded");
        }

        // And on the way in, where the bytes did not come from us.
        let mut bytes = encode_attach_offer(&sample_offer()).expect("encodes");
        bytes[17..25].copy_from_slice(&(ATTACH_MAX_BYTES + 1).to_le_bytes());
        assert!(decode_attach_offer(&bytes).is_none());
    }

    #[test]
    fn an_offer_with_no_name_or_an_overlong_one_is_refused() {
        let empty = AttachOffer {
            name: String::new(),
            ..sample_offer()
        };
        assert!(encode_attach_offer(&empty).is_none());

        let long = AttachOffer {
            name: "x".repeat(ATTACH_NAME_MAX + 1),
            ..sample_offer()
        };
        assert!(encode_attach_offer(&long).is_none());
    }

    #[test]
    fn a_truncated_offer_does_not_decode() {
        let bytes = encode_attach_offer(&sample_offer()).expect("encodes");
        for cut in 0..bytes.len() {
            assert!(
                decode_attach_offer(&bytes[..cut]).is_none(),
                "{cut} bytes decoded"
            );
        }
    }

    #[test]
    fn replies_and_cancels_round_trip_every_variant() {
        let id = [3u8; 16];
        for reply in [
            AttachReply::Accept,
            AttachReply::Decline,
            AttachReply::TooLarge,
            AttachReply::Busy,
            AttachReply::NotAllowed,
        ] {
            let bytes = encode_attach_reply(&id, reply, None);
            assert_eq!(decode_attach_reply(&bytes), Some((id, reply, None)));
        }
        // Only an accept carries the recipient's port, and a refusal that
        // claims one is malformed rather than a hint to dial somewhere.
        let accept = encode_attach_reply(&id, AttachReply::Accept, Some(41330));
        assert_eq!(
            decode_attach_reply(&accept),
            Some((id, AttachReply::Accept, Some(41330)))
        );
        let decline = encode_attach_reply(&id, AttachReply::Decline, Some(41330));
        assert_eq!(decline.len(), 18, "a refusal never carries a port");
        let mut forged = encode_attach_reply(&id, AttachReply::Decline, None);
        forged.extend_from_slice(&41330u16.to_le_bytes());
        assert!(decode_attach_reply(&forged).is_none());
        for reason in [
            AttachCancel::User,
            AttachCancel::SourceGone,
            AttachCancel::Stalled,
            AttachCancel::Corrupt,
            AttachCancel::Unreachable,
        ] {
            let bytes = encode_attach_cancel(&id, reason);
            assert_eq!(decode_attach_cancel(&bytes), Some((id, reason)));
        }
        assert!(decode_attach_reply(&[ATTACH_VERSION, 0, 0]).is_none());
    }

    /// Both ends derive the same capability without agreeing who is which —
    /// `derive_pairwise_capability` sorts the two public keys.
    #[test]
    fn the_capability_is_the_same_from_either_side() {
        let (a_seed, a_pub) = keypair(1);
        let (b_seed, b_pub) = keypair(2);
        let id = [9u8; 16];

        let from_a = derive_attach_capability(&a_seed, &b_pub, &id).expect("a derives");
        let from_b = derive_attach_capability(&b_seed, &a_pub, &id).expect("b derives");
        assert_eq!(from_a, from_b);
    }

    /// The tag is what stops a friend fishing for a transfer meant for someone
    /// else, so it has to be bound to the transfer and to the pair.
    #[test]
    fn a_tag_is_bound_to_its_transfer_and_its_pair() {
        let (a_seed, _) = keypair(1);
        let (b_seed, b_pub) = keypair(2);
        let (_, c_pub) = keypair(3);
        let id = [9u8; 16];
        let other_id = [10u8; 16];

        let cap = derive_attach_capability(&a_seed, &b_pub, &id).expect("derives");
        let tag = attach_stream_tag(&cap, &id);

        // Same pair, different transfer.
        let other_cap = derive_attach_capability(&a_seed, &b_pub, &other_id).expect("derives");
        assert_ne!(attach_stream_tag(&other_cap, &other_id), tag);

        // Same transfer, a third party who is not in the pair.
        let outsider = derive_attach_capability(&b_seed, &c_pub, &id).expect("derives");
        assert_ne!(attach_stream_tag(&outsider, &id), tag);

        assert!(attach_tags_match(&tag, &tag));
        let mut flipped = tag;
        flipped[0] ^= 0xFF;
        assert!(!attach_tags_match(&tag, &flipped));
    }

    #[test]
    fn a_stream_request_round_trips() {
        let req = AttachRequest {
            xfer_id: [5u8; 16],
            tag: [6u8; ATTACH_TAG_LEN],
            start_chunk: 12,
        };
        let bytes = encode_attach_request(&req);
        assert_eq!(bytes.len(), ATTACH_REQUEST_LEN);
        assert_eq!(bytes[0], ATTACH_STREAM_MSG_TYPE);
        assert_eq!(decode_attach_request(&bytes), Some(req));
    }

    /// The accept loop reads seven bytes to decide what a connection is, then
    /// hands the handler the rest. If those two numbers disagree the handler
    /// reads into the next frame.
    #[test]
    fn the_request_tail_is_what_the_dispatcher_leaves_behind() {
        assert_eq!(ATTACH_REQUEST_TAIL_LEN + 7, ATTACH_REQUEST_LEN);
    }

    #[test]
    fn a_request_of_the_wrong_shape_does_not_decode() {
        let req = AttachRequest {
            xfer_id: [5u8; 16],
            tag: [6u8; ATTACH_TAG_LEN],
            start_chunk: 0,
        };
        let good = encode_attach_request(&req);

        let mut wrong_type = good.clone();
        wrong_type[0] = ATTACH_STREAM_MSG_TYPE + 1;
        assert!(decode_attach_request(&wrong_type).is_none());

        let mut wrong_version = good.clone();
        wrong_version[1] = ATTACH_VERSION + 1;
        assert!(decode_attach_request(&wrong_version).is_none());

        assert!(decode_attach_request(&good[..good.len() - 1]).is_none());
        let mut too_long = good;
        too_long.push(0);
        assert!(decode_attach_request(&too_long).is_none());
    }

    fn info_for(data: &[u8]) -> AttachFileInfo {
        let tree = super::super::transfer::HashTree::from_data(data);
        AttachFileInfo {
            size: data.len() as u64,
            chunk_hashes: tree.chunk_hashes,
        }
    }

    #[test]
    fn file_info_round_trips_and_commits_to_the_offered_root() {
        let data = vec![0xABu8; ATTACH_CHUNK_SIZE * 2 + 7];
        let tree = super::super::transfer::HashTree::from_data(&data);
        let info = info_for(&data);

        let bytes = encode_attach_file_info(&info);
        assert_eq!(bytes.len(), attach_file_info_len(info.size).expect("len"));
        let decoded = decode_attach_file_info(&bytes).expect("decodes");
        assert_eq!(decoded, info);
        assert!(decoded.matches_root(&tree.root_hash));
    }

    /// The whole point of sending the list: a sender that alters one chunk hash
    /// no longer matches the root it offered, and is caught before any byte of
    /// the file is written rather than after the last one.
    #[test]
    fn a_tampered_chunk_list_fails_the_root_it_was_offered_under() {
        let data = vec![1u8; ATTACH_CHUNK_SIZE + 1];
        let tree = super::super::transfer::HashTree::from_data(&data);
        let mut info = info_for(&data);
        info.chunk_hashes[0][0] ^= 0xFF;

        assert!(!info.matches_root(&tree.root_hash));
    }

    /// A count that does not follow from the size is a malformed header, and
    /// must be refused before it is used to size an allocation.
    #[test]
    fn a_chunk_count_that_disagrees_with_the_size_is_refused() {
        let data = vec![2u8; ATTACH_CHUNK_SIZE];
        let info = info_for(&data);
        let mut bytes = encode_attach_file_info(&info);
        // Claim a thousand chunks for a one-chunk file.
        bytes[9..13].copy_from_slice(&1000u32.to_le_bytes());
        assert_eq!(
            decode_attach_file_info(&bytes),
            Err(AttachStreamStatus::Unknown)
        );
    }

    #[test]
    fn a_refusal_status_comes_back_as_that_status() {
        for status in [
            AttachStreamStatus::Unknown,
            AttachStreamStatus::Unauthorized,
            AttachStreamStatus::SourceGone,
            AttachStreamStatus::BadCursor,
        ] {
            assert_eq!(decode_attach_file_info(&[status.to_byte()]), Err(status));
        }
    }

    #[test]
    fn chunk_lengths_cover_the_short_tail() {
        let data = vec![3u8; ATTACH_CHUNK_SIZE * 2 + 5];
        let info = info_for(&data);
        assert_eq!(info.chunk_count(), 3);
        assert_eq!(info.chunk_len(0), Some(ATTACH_CHUNK_SIZE));
        assert_eq!(info.chunk_len(1), Some(ATTACH_CHUNK_SIZE));
        assert_eq!(info.chunk_len(2), Some(5));
        assert_eq!(info.chunk_len(3), None);
    }

    #[test]
    fn chunk_counts_bound_the_size_range() {
        assert_eq!(attach_chunk_count(0), None);
        assert_eq!(attach_chunk_count(1), Some(1));
        assert_eq!(attach_chunk_count(ATTACH_CHUNK_SIZE as u64), Some(1));
        assert_eq!(attach_chunk_count(ATTACH_CHUNK_SIZE as u64 + 1), Some(2));
        assert_eq!(attach_chunk_count(ATTACH_MAX_BYTES + 1), None);
        assert!(attach_chunk_count(ATTACH_MAX_BYTES).is_some());
    }
}
