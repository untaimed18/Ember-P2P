//! Private messages between two members of a room: the body of extension
//! frame [`EXT_KIND_PRIVATE_MESSAGE`], sealed so only the recipient can tell
//! it is theirs, let alone read it.
//!
//! The frame travels through the room like chat: every member it passes
//! checks the sender's signature, ban and chat rate, and passes it on. What
//! they cannot learn is to whom it goes or what it says. The body is
//!
//! `version(1) || tag(16) || nonce(24) || ciphertext`
//!
//! - **The key** comes from the two members' identities and the room
//!   (`derive_pairwise_capability`, purpose `ch-dm-v1 || channel_id`), never
//!   from `derive_chat_key`: friend chat's key depends on the two identities
//!   alone, and sharing it would make a room message open as friend chat and
//!   the other way round.
//! - **The tag** is keyed by that pairwise secret and bound to the envelope's
//!   id, so it differs on every frame: the members relaying two messages to
//!   one person cannot tell. The recipient derives the secret once per sender
//!   and room ([`PairwiseBase`]) and one keyed hash per frame.
//! - **The ciphertext** is XChaCha20-Poly1305 over a padded plaintext, with
//!   the room, the envelope's id and time, the sender and the tag as
//!   associated data, so a body cannot be lifted into another envelope.
//! - **The plaintext** is `type(1) || len(2) || fields`, zero-padded to one of
//!   [`DM_BUCKETS`]. Every kind of message is one kind of frame, so relays
//!   cannot tell a message from a receipt, and the buckets say little about
//!   its length.
//!
//! [`EXT_KIND_PRIVATE_MESSAGE`]: super::channel::EXT_KIND_PRIVATE_MESSAGE

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key as ChaChaKey, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use super::channel::EXT_BODY_MAX_BYTES;
use super::crypto;

/// The body's own version, ahead of everything else in it.
pub const DM_BODY_VERSION: u8 = 1;
const DM_PURPOSE: &[u8] = b"ch-dm-v1";
const TAG_CONTEXT: &str = "ember room private message tag v1";
const KEY_CONTEXT: &str = "ember room private message key v1";
const AAD_DOMAIN: &[u8] = b"ember-room-dm-v1\0";
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const AEAD_TAG_LEN: usize = 16;
/// `version || tag || nonce`, then the AEAD tag after the ciphertext.
const BODY_OVERHEAD: usize = 1 + TAG_LEN + NONCE_LEN + AEAD_TAG_LEN;
/// `type(1) || len(2)` ahead of the fields.
const PLAIN_HEADER_LEN: usize = 3;
/// The largest padded plaintext: whatever one datagram has left once the
/// gossip envelope, the extension frame and this body's own overhead are
/// counted.
pub const DM_TOP_BUCKET: usize = EXT_BODY_MAX_BYTES - BODY_OVERHEAD;
/// What a plaintext is padded to, smallest first. The middle one keeps a
/// frame, relay envelope and all, under `MAX_UNFRAGMENTED_PAYLOAD`: many
/// consumer NATs drop a fragmented datagram.
pub const DM_BUCKETS: [usize; 3] = [256, 960, DM_TOP_BUCKET];
/// The longest text one message carries, in UTF-8 bytes.
pub const DM_TEXT_MAX_BYTES: usize = DM_TOP_BUCKET - PLAIN_HEADER_LEN - 16;

const TYPE_MESSAGE: u8 = 1;
const TYPE_RECEIPT: u8 = 2;
const TYPE_ACCEPT: u8 = 3;
const TYPE_DECLINE: u8 = 4;

/// What one private-message frame says. Its `Debug` leaves the text out, so a
/// logged command never carries a message.
#[derive(Clone, PartialEq, Eq)]
pub enum DmPayload {
    /// A message, under an id of the sender's that stays the same across
    /// resends, so the recipient keeps it once and answers each copy.
    Message { id: [u8; 16], text: String },
    /// The message with this id arrived.
    Receipt { id: [u8; 16] },
    /// The recipient takes messages from the sender.
    Accept,
    /// The recipient does not.
    Decline,
}

impl std::fmt::Debug for DmPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DmPayload::Message { id, text } => {
                write!(f, "Message {{ id: {}, text: {} bytes }}", hex::encode(id), text.len())
            }
            DmPayload::Receipt { id } => write!(f, "Receipt {{ id: {} }}", hex::encode(id)),
            DmPayload::Accept => f.write_str("Accept"),
            DmPayload::Decline => f.write_str("Decline"),
        }
    }
}

impl DmPayload {
    fn encode(&self) -> Option<Vec<u8>> {
        let (kind, fields): (u8, Zeroizing<Vec<u8>>) = match self {
            DmPayload::Message { id, text } => {
                if text.len() > DM_TEXT_MAX_BYTES {
                    return None;
                }
                let mut fields = Zeroizing::new(Vec::with_capacity(16 + text.len()));
                fields.extend_from_slice(id);
                fields.extend_from_slice(text.as_bytes());
                (TYPE_MESSAGE, fields)
            }
            DmPayload::Receipt { id } => (TYPE_RECEIPT, Zeroizing::new(id.to_vec())),
            DmPayload::Accept => (TYPE_ACCEPT, Zeroizing::new(Vec::new())),
            DmPayload::Decline => (TYPE_DECLINE, Zeroizing::new(Vec::new())),
        };
        let used = PLAIN_HEADER_LEN + fields.len();
        let bucket = *DM_BUCKETS.iter().find(|&&size| size >= used)?;
        let mut out = Vec::with_capacity(bucket);
        out.push(kind);
        out.extend_from_slice(&(fields.len() as u16).to_le_bytes());
        out.extend_from_slice(&fields);
        out.resize(bucket, 0);
        Some(out)
    }

    fn decode(plain: &[u8]) -> Option<Self> {
        if !DM_BUCKETS.contains(&plain.len()) {
            return None;
        }
        let len = u16::from_le_bytes([plain[1], plain[2]]) as usize;
        let fields = plain.get(PLAIN_HEADER_LEN..PLAIN_HEADER_LEN + len)?;
        // Padding is zeros, and nothing else: a writer that put anything
        // there has a reason this build does not know.
        if plain[PLAIN_HEADER_LEN + len..].iter().any(|&b| b != 0) {
            return None;
        }
        let id = || -> Option<[u8; 16]> { fields.get(..16)?.try_into().ok() };
        match plain[0] {
            TYPE_MESSAGE => Some(DmPayload::Message {
                id: id()?,
                text: String::from_utf8(fields.get(16..)?.to_vec()).ok()?,
            }),
            TYPE_RECEIPT if fields.len() == 16 => Some(DmPayload::Receipt { id: id()? }),
            TYPE_ACCEPT if fields.is_empty() => Some(DmPayload::Accept),
            TYPE_DECLINE if fields.is_empty() => Some(DmPayload::Decline),
            _ => None,
        }
    }
}

/// The secret two members share in one room, from which every tag and key of
/// their private messages there is derived. Either side computes the same
/// one, so a receiver keeps one per sender and room rather than paying an
/// X25519 exchange per frame.
pub struct PairwiseBase {
    tag_key: Zeroizing<[u8; 32]>,
    seal_key: Zeroizing<[u8; 32]>,
}

impl PairwiseBase {
    /// `None` when `peer` is not a usable key.
    pub fn derive(our_seed: &[u8; 32], peer: &[u8; 32], channel_id: &[u8; 16]) -> Option<Self> {
        let mut purpose = Vec::with_capacity(DM_PURPOSE.len() + 16);
        purpose.extend_from_slice(DM_PURPOSE);
        purpose.extend_from_slice(channel_id);
        let base = Zeroizing::new(crypto::derive_pairwise_capability(our_seed, peer, &purpose, 0)?);
        Some(Self {
            tag_key: Zeroizing::new(blake3::derive_key(TAG_CONTEXT, base.as_slice())),
            seal_key: Zeroizing::new(blake3::derive_key(KEY_CONTEXT, base.as_slice())),
        })
    }

    fn tag(&self, msg_id: &[u8; 16]) -> [u8; TAG_LEN] {
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&blake3::keyed_hash(&self.tag_key, msg_id).as_bytes()[..TAG_LEN]);
        tag
    }

    /// Whether `body`, in the envelope with id `msg_id`, is between the two
    /// members this secret belongs to.
    pub fn recognises(&self, msg_id: &[u8; 16], body: &[u8]) -> bool {
        let Some(tag) = body_tag(body) else {
            return false;
        };
        let expected = self.tag(msg_id);
        expected.iter().zip(tag.iter()).fold(0u8, |diff, (a, b)| diff | (a ^ b)) == 0
    }

    /// A body saying `payload`, from `sender`, for the envelope it goes in.
    /// `None` for a message too long for one frame.
    pub fn seal(
        &self,
        channel_id: &[u8; 16],
        msg_id: &[u8; 16],
        timestamp: i64,
        sender: &[u8; 32],
        payload: &DmPayload,
    ) -> Option<Vec<u8>> {
        let plain = Zeroizing::new(payload.encode()?);
        let tag = self.tag(msg_id);
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let aad = associated_data(channel_id, msg_id, timestamp, sender, &tag);
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(self.seal_key.as_slice()));
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plain, aad: &aad })
            .ok()?;
        let mut out = Vec::with_capacity(1 + TAG_LEN + NONCE_LEN + ciphertext.len());
        out.push(DM_BODY_VERSION);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Some(out)
    }

    /// What `body` says, or `None` if it is not ours, was moved from another
    /// envelope, room or sender, or is malformed.
    pub fn open(
        &self,
        channel_id: &[u8; 16],
        msg_id: &[u8; 16],
        timestamp: i64,
        sender: &[u8; 32],
        body: &[u8],
    ) -> Option<DmPayload> {
        if !self.recognises(msg_id, body) {
            return None;
        }
        let tag: [u8; TAG_LEN] = body[1..1 + TAG_LEN].try_into().ok()?;
        let nonce = &body[1 + TAG_LEN..1 + TAG_LEN + NONCE_LEN];
        let aad = associated_data(channel_id, msg_id, timestamp, sender, &tag);
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(self.seal_key.as_slice()));
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload { msg: &body[1 + TAG_LEN + NONCE_LEN..], aad: &aad },
                )
                .ok()?,
        );
        DmPayload::decode(&plain)
    }
}

/// The tag a body carries, if it is shaped like a body this build reads.
fn body_tag(body: &[u8]) -> Option<&[u8]> {
    if body.len() < BODY_OVERHEAD + DM_BUCKETS[0] || body[0] != DM_BODY_VERSION {
        return None;
    }
    body.get(1..1 + TAG_LEN)
}

fn associated_data(
    channel_id: &[u8; 16],
    msg_id: &[u8; 16],
    timestamp: i64,
    sender: &[u8; 32],
    tag: &[u8; TAG_LEN],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 16 + 16 + 8 + 32 + TAG_LEN);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(channel_id);
    aad.extend_from_slice(msg_id);
    aad.extend_from_slice(&timestamp.to_le_bytes());
    aad.extend_from_slice(sender);
    aad.extend_from_slice(tag);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::ember::channel::{
        decode_channel_ext_frame, encode_channel_ext_frame, ChannelGossip, EXT_KIND_PRIVATE_MESSAGE,
    };
    use crate::network::ember::crypto::signing_key_from_bytes;

    struct Member {
        seed: [u8; 32],
        pubkey: [u8; 32],
    }

    fn member(byte: u8) -> Member {
        let seed = [byte; 32];
        Member { seed, pubkey: signing_key_from_bytes(&seed).verifying_key().to_bytes() }
    }

    const ROOM: [u8; 16] = [0x41; 16];

    #[test]
    fn only_the_recipient_recognises_its_tag_and_no_two_frames_share_one() {
        let (ann, bob, cat) = (member(1), member(2), member(3));
        let ann_to_bob = PairwiseBase::derive(&ann.seed, &bob.pubkey, &ROOM).unwrap();
        let bob_from_ann = PairwiseBase::derive(&bob.seed, &ann.pubkey, &ROOM).unwrap();
        let cat_from_ann = PairwiseBase::derive(&cat.seed, &ann.pubkey, &ROOM).unwrap();
        let (first, second) = ([1u8; 16], [2u8; 16]);
        let message = DmPayload::Message { id: [9; 16], text: "hello".into() };
        let one = ann_to_bob.seal(&ROOM, &first, 100, &ann.pubkey, &message).unwrap();
        let two = ann_to_bob.seal(&ROOM, &second, 101, &ann.pubkey, &message).unwrap();

        assert!(bob_from_ann.recognises(&first, &one));
        assert!(!cat_from_ann.recognises(&first, &one), "another member cannot tell it is theirs");
        assert_ne!(body_tag(&one), body_tag(&two), "relays cannot group frames by recipient");
        assert!(!bob_from_ann.recognises(&first, &two), "a tag is bound to its envelope");
        let other_room = PairwiseBase::derive(&bob.seed, &ann.pubkey, &[0x42; 16]).unwrap();
        assert!(!other_room.recognises(&first, &one), "nor good in another room");
    }

    #[test]
    fn a_body_opens_only_in_its_own_envelope_room_and_sender() {
        let (ann, bob) = (member(1), member(2));
        let seal = PairwiseBase::derive(&ann.seed, &bob.pubkey, &ROOM).unwrap();
        let open = PairwiseBase::derive(&bob.seed, &ann.pubkey, &ROOM).unwrap();
        let msg_id = [7u8; 16];
        let message = DmPayload::Message { id: [3; 16], text: "just us".into() };
        let body = seal.seal(&ROOM, &msg_id, 500, &ann.pubkey, &message).unwrap();

        assert_eq!(open.open(&ROOM, &msg_id, 500, &ann.pubkey, &body), Some(message));
        assert_eq!(open.open(&ROOM, &msg_id, 501, &ann.pubkey, &body), None, "another time");
        assert_eq!(open.open(&[0x42; 16], &msg_id, 500, &ann.pubkey, &body), None, "another room");
        assert_eq!(open.open(&ROOM, &msg_id, 500, &bob.pubkey, &body), None, "another sender");
        let mut tampered = body.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(open.open(&ROOM, &msg_id, 500, &ann.pubkey, &tampered), None);
    }

    /// Friend chat's key depends on the two identities alone; this one on the
    /// room too, under a purpose of its own, so neither opens as the other.
    #[test]
    fn a_room_message_key_is_never_the_friend_chat_key() {
        let (ann, bob) = (member(1), member(2));
        let chat = crypto::derive_chat_key(&ann.seed, &bob.pubkey).unwrap();
        let base = PairwiseBase::derive(&ann.seed, &bob.pubkey, &ROOM).unwrap();
        assert_ne!(*base.seal_key, chat);
        assert_ne!(*base.tag_key, chat);
        // A friend-chat-keyed body is not a room message.
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(&chat));
        let plain = DmPayload::Accept.encode().unwrap();
        let ct = cipher.encrypt(XNonce::from_slice(&[0u8; 24]), plain.as_slice()).unwrap();
        let mut forged = vec![DM_BODY_VERSION];
        forged.extend_from_slice(&base.tag(&[5; 16]));
        forged.extend_from_slice(&[0u8; 24]);
        forged.extend_from_slice(&ct);
        let open = PairwiseBase::derive(&bob.seed, &ann.pubkey, &ROOM).unwrap();
        assert_eq!(open.open(&ROOM, &[5; 16], 1, &ann.pubkey, &forged), None);
    }

    #[test]
    fn every_kind_pads_to_a_bucket_and_reads_back() {
        let base = PairwiseBase::derive(&member(1).seed, &member(2).pubkey, &ROOM).unwrap();
        let open = PairwiseBase::derive(&member(2).seed, &member(1).pubkey, &ROOM).unwrap();
        let sender = member(1).pubkey;
        let cases = [
            DmPayload::Message { id: [1; 16], text: "hi".into() },
            DmPayload::Message { id: [1; 16], text: "x".repeat(600) },
            DmPayload::Message { id: [1; 16], text: "y".repeat(DM_TEXT_MAX_BYTES) },
            DmPayload::Receipt { id: [2; 16] },
            DmPayload::Accept,
            DmPayload::Decline,
        ];
        let mut sizes = Vec::new();
        for payload in cases {
            let body = base.seal(&ROOM, &[4; 16], 9, &sender, &payload).unwrap();
            sizes.push(body.len());
            assert_eq!(open.open(&ROOM, &[4; 16], 9, &sender, &body), Some(payload));
        }
        let small = BODY_OVERHEAD + DM_BUCKETS[0];
        assert_eq!(sizes, vec![small, BODY_OVERHEAD + DM_BUCKETS[1], BODY_OVERHEAD + DM_TOP_BUCKET, small, small, small]);
        let too_long = DmPayload::Message { id: [1; 16], text: "z".repeat(DM_TEXT_MAX_BYTES + 1) };
        assert!(base.seal(&ROOM, &[4; 16], 9, &sender, &too_long).is_none());
    }

    /// The largest message still goes out in one datagram, as an extension
    /// frame in a gossip envelope, and reads back through the frame decoder.
    #[test]
    fn the_longest_message_fits_one_datagram() {
        let ann = member(1);
        let signing = signing_key_from_bytes(&ann.seed);
        let base = PairwiseBase::derive(&ann.seed, &member(2).pubkey, &ROOM).unwrap();
        let msg_id = [8u8; 16];
        let payload = DmPayload::Message { id: [1; 16], text: "w".repeat(DM_TEXT_MAX_BYTES) };
        let body = base.seal(&ROOM, &msg_id, 77, &ann.pubkey, &payload).unwrap();
        let frame = encode_channel_ext_frame(&signing, &ROOM, &msg_id, 77, EXT_KIND_PRIVATE_MESSAGE, 0, &body).unwrap();
        let gossip = ChannelGossip::sealed(ROOM, msg_id, &[0x11; 32], 1, &frame, 8, 77).encode();
        // Wrapped for an overlay hop, as a firewalled member is reached.
        let relayed = crate::network::ember::channel::encode_channel_relay_envelope(&ROOM, &[0x22; 16], &gossip);
        assert!(relayed.len() <= crate::network::ember::dht::messages::MAX_DELIVERABLE_PAYLOAD, "{}", relayed.len());
        let decoded = decode_channel_ext_frame(&frame, &ROOM, &msg_id, 77).unwrap();
        assert!(!decoded.displayable());
        assert_eq!(decoded.body, body);
    }

    /// A middle-sized message, relay envelope and all, stays under what goes
    /// out unfragmented.
    #[test]
    fn a_middle_sized_message_is_not_fragmented() {
        let ann = member(1);
        let signing = signing_key_from_bytes(&ann.seed);
        let base = PairwiseBase::derive(&ann.seed, &member(2).pubkey, &ROOM).unwrap();
        let text = "m".repeat(DM_BUCKETS[1] - PLAIN_HEADER_LEN - 16);
        let body = base.seal(&ROOM, &[3; 16], 5, &ann.pubkey, &DmPayload::Message { id: [1; 16], text }).unwrap();
        assert_eq!(body.len(), BODY_OVERHEAD + DM_BUCKETS[1]);
        let frame = encode_channel_ext_frame(&signing, &ROOM, &[3; 16], 5, EXT_KIND_PRIVATE_MESSAGE, 0, &body).unwrap();
        let gossip = ChannelGossip::sealed(ROOM, [3; 16], &[0x11; 32], 1, &frame, 8, 5).encode();
        let relayed = crate::network::ember::channel::encode_channel_relay_envelope(&ROOM, &[0x22; 16], &gossip);
        assert!(relayed.len() <= crate::network::ember::dht::messages::MAX_UNFRAGMENTED_PAYLOAD, "{}", relayed.len());
    }
}
