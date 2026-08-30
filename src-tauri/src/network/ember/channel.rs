//! Ember Channels: identities, DHT keys, invite URIs, and gossip bodies.
//!
//! A channel is an Ed25519 keypair minted at creation. Its stable address is
//! `channel_id = BLAKE3(channel_pubkey)[..16]`, the same derivation used for
//! Ember node IDs. Display names are a Rendezvous directory property
//! (unique handles); the DHT identity remains the channel keypair.
//!
//! Index / presence / moderation records are published as
//! [`super::dht::publish::RECORD_TYPE_CHANNEL`] signed records. Member IPs
//! never appear in those records; two members resolve each other only when
//! they become gossip neighbors, via a pairwise rendezvous capability.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key as ChaChaKey, XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use super::crypto;
use super::dht::EmberNodeId;

/// BLAKE3 `derive_key` context for the channel content key. Must stay at or
/// under 64 bytes; changing it would rotate every channel's message key.
const CONTENT_KEY_CONTEXT: &str = "ember-channel-content-v1";
const INDEX_KEY_PREFIX: &[u8] = b"ember:channels:index:v1:";
const PRESENCE_KEY_PREFIX: &[u8] = b"ember:channel:presence:v1";
const MODERATION_KEY_PREFIX: &[u8] = b"ember:channel:mod:v1";
const HANDOFF_KEY_PREFIX: &[u8] = b"ember:channel:handoff:v1";
const EPOCH_KEY_PREFIX: &[u8] = b"ember:channel:epoch:v1";
const CLAIM_KEY_PREFIX: &[u8] = b"ember:channel:claim:v1";
const EPOCH_AAD_DOMAIN: &[u8] = b"ember-channel-key-epoch-v1\0";
const EPOCH_ENVELOPE_VERSION: u8 = 1;
/// `version(1) + nonce + key(32) + tag`.
pub const EPOCH_ENVELOPE_LEN: usize = 1 + GOSSIP_NONCE_LEN + 32 + GOSSIP_TAG_LEN;
const HANDOFF_OFFER_DOMAIN: &[u8] = b"ember-channel-handoff-offer-v1\0";
const GOSSIP_AAD_DOMAIN: &[u8] = b"ember-channel-gossip-v1\0";
const CHAT_SIG_DOMAIN: &[u8] = b"ember-channel-chat-author-v1\0";

/// How many public-index shards Gather walks. Sized so each shard stays under
/// the 300-records-per-key FIND_VALUE cap for longer.
pub const INDEX_SHARD_COUNT: u8 = 16;
/// Presence DHT keys rotate on this interval so departed members age out.
pub const PRESENCE_EPOCH_SECS: i64 = 15 * 60;
/// Members re-announce presence this often (inside one epoch).
pub const PRESENCE_REPUBLISH_SECS: i64 = 10 * 60;
/// How soon to try presence again after a publish that stored nowhere.
///
/// The republish stamp used to be written when the publish *started*, so a pass
/// that placed the record on no node still bought ten minutes of silence.
/// [`PRESENCE_FRESH_SECS`] is two intervals, so two such passes were enough to
/// age a member out of every roster they were sitting in — they went on
/// chatting while everyone else stopped seeing them and stopped picking them as
/// a gossip neighbor.
pub const PRESENCE_RETRY_SECS: i64 = 60;

/// Whether a wall-clock schedule is due.
///
/// Every periodic channel task compares `i64` wall-clock seconds, and
/// `saturating_sub` on `i64` saturates toward `i64::MIN` rather than zero — so
/// a stamp *ahead* of the clock yielded a negative age, which is below every
/// interval, and the task simply stopped running until real time caught up. An
/// NTP correction on a fast clock, a VM resume, or someone editing the system
/// date could stall presence republish for as long as the skew lasted, which is
/// the same ghost-member failure by a different route.
///
/// A stamp in the future is not information, so it is treated as due: at worst
/// that costs one extra run, and the stamp written afterwards uses the
/// corrected clock.
pub fn schedule_due(stamp: i64, now: i64, interval_secs: i64) -> bool {
    stamp > now || now.saturating_sub(stamp) >= interval_secs
}
/// How often a member walks the presence DHT keys for rooms they have joined.
pub const PRESENCE_FETCH_SECS: i64 = 5 * 60;
/// The same walk for a room we are alone in.
///
/// Five minutes keeps a roster we already have fresh, but it is the wrong
/// number for the case the user is actually watching: a room with nobody else
/// in it yet is either one they have just joined or one somebody is about to
/// arrive in, and until presence names a second member there is no one to
/// gossip to, so chat cannot move either. Costs one extra walk every twenty
/// seconds per empty room, and stops as soon as the room has anyone in it.
pub const PRESENCE_FETCH_EMPTY_SECS: i64 = 20;
/// A member is treated as present — and eligible as a gossip neighbor —
/// if their last announcement is this recent. Two republish intervals so one
/// missed announce does not drop them, matching the roster presence dot.
pub const PRESENCE_FRESH_SECS: i64 = PRESENCE_REPUBLISH_SECS * 2;
/// Hard cap on `channel_members` rows per room. Public rooms used to grow
/// without bound from chat ingest; gossip neighbors are the XOR-closest of
/// that table, so an unbounded roster is an eclipse. Past this we only drop
/// stale rows (`last_seen` older than [`PRESENCE_FRESH_SECS`]), never the
/// local user, and never a still-fresh peer — a flood of newcomers is
/// refused rather than admitted as identity 257.
pub const CHANNEL_MEMBERS_MAX: usize = 256;
/// How often members re-fetch the owner-signed moderation record.
pub const MODERATION_FETCH_SECS: i64 = 5 * 60;
/// Owners re-publish moderation so the 24h record TTL cannot age out.
pub const MODERATION_REPUBLISH_SECS: i64 = 6 * 60 * 60;
/// How often an in-room member re-claims their username so Rendezvous
/// does not free it after a year of silence.
pub const USERNAME_REFRESH_SECS: i64 = 24 * 60 * 60;
/// Cap on rooms whose XOR-neighbors we register at rendezvous per heartbeat.
pub const CHANNEL_RENDEZVOUS_MAX_CHANNELS: usize = 4;
/// Deterministic gossip degree: XOR-closest members to self.
pub const CHANNEL_NEIGHBOR_COUNT: usize = 8;
/// Default hop budget for a gossip flood.
pub const CHANNEL_MSG_TTL_DEFAULT: u8 = 8;
/// In-session cap on distinct gossip ids remembered for flood dedup.
pub const CHANNEL_GOSSIP_SEEN_CAP: usize = 4096;
/// `CHANNEL_MSG` frames we will relay for the mesh per second.
pub const CHANNEL_GOSSIP_OUT_PER_SEC: usize = 16;
/// `CHANNEL_MSG` frames this user may originate per second.
///
/// Held apart from the relay allowance above. Sharing one budget meant a room
/// busy enough to fill it dropped the sender's own next line. Origination is
/// retried for a few minutes, but a shared budget would still starve the
/// queue whenever the mesh was busy. Well above any human typing rate, and
/// still a ceiling, so a send loop cannot become an unbounded flood.
pub const CHANNEL_GOSSIP_LOCAL_PER_SEC: usize = 32;
/// Inbound `CHANNEL_MSG` frames admitted from one DHT hop per second, before
/// anything here knows what they are.
///
/// A work bound rather than a policy. All this can do is cap how much
/// decryption one hop makes us attempt; the limits that actually govern a room
/// sit past the decrypt and are keyed on the *signed author* instead —
/// [`author_gossip_allow`] for chat, moderator actions and transfer offers,
/// [`history_sync_allow`] for catch-up. A hop is not an identity, and a real
/// flood arrives spread across every neighbor at once, so a tight per-hop
/// number buys the room nothing and costs it the honest traffic.
///
/// Derived from what one well-behaved peer can legitimately have in flight
/// toward us: everything they will relay for the mesh, plus a full catch-up
/// reply landing in the same second. Sized below that, this limit punished the
/// protocol's own behaviour — half of every history-sync reply was refused,
/// and the neighbor that answered was scored for it.
pub const CHANNEL_GOSSIP_IN_PER_PEER_PER_SEC: usize =
    CHANNEL_GOSSIP_OUT_PER_SEC + CHANNEL_HISTORY_SYNC_MAX;
/// Extra inbound allowance for a hop we have an Ember Transfer running with,
/// on top of [`CHANNEL_GOSSIP_IN_PER_PEER_PER_SEC`].
///
/// Granted only while a transfer with that peer is actually live, so a hop
/// that has not been invited to send us anything bulky keeps the tight budget.
/// It has to cover what the far end is allowed to emit: the receiver leaves a
/// whole [`XFER_WINDOW_BLOCKS`] window outstanding and the sender answers the
/// lot in one pass at [`XFER_BLOCKS_OUT_PER_SEC`], so a smaller number here
/// refuses blocks this node asked for by name.
pub const CHANNEL_XFER_IN_PER_PEER_PER_SEC: usize = XFER_BLOCKS_OUT_PER_SEC;

// The receiver's window, the sender's rate, and this admission bucket are
// three halves of one agreement, and they were not in agreement: the inbound
// cap sat at 8/sec while a single window is 64 blocks answered at 192/sec, so
// the opening burst of every transfer was ~87% refused — and each refusal was
// scored against the sender as a protocol violation, which banned them for a
// day before the file had moved a hundred kilobytes.
const _: () = assert!(
    CHANNEL_XFER_IN_PER_PEER_PER_SEC >= XFER_WINDOW_BLOCKS,
    "a transfer peer must be admitted at least a full outstanding window"
);
const _: () = assert!(
    CHANNEL_GOSSIP_IN_PER_PEER_PER_SEC >= CHANNEL_HISTORY_SYNC_MAX,
    "a catch-up reply must fit the inbound allowance without being shed"
);

/// Cap on distinct hops tracked in the inbound gossip rate map.
pub const CHANNEL_GOSSIP_IN_PEER_CAP: usize = 512;
/// Chat messages accepted from one room member per second, counted against the
/// signed author rather than the hop that handed them over.
///
/// The per-hop limit above bounds what any single neighbor can push at us, but
/// a flood spreads across the mesh and arrives via many hops at once, so it
/// buys the room nothing on its own: one member could saturate every peer and
/// each would dutifully relay. Four a second is far above human typing and far
/// below what makes a room unreadable.
pub const CHANNEL_GOSSIP_PER_AUTHOR_PER_SEC: usize = 4;

// Refusing to send what the far end would have accepted is the one way these
// two can be wrong together: our own ceiling has to sit above what a receiving
// peer allows one author, or a burst is lost here rather than there, where at
// least it is a deliberate flood defence.
const _: () = assert!(
    CHANNEL_GOSSIP_LOCAL_PER_SEC > CHANNEL_GOSSIP_PER_AUTHOR_PER_SEC,
    "originating must not be capped below what a peer accepts from one author"
);

/// Cap on distinct (room, author) pairs tracked for the limit above.
pub const CHANNEL_GOSSIP_AUTHOR_CAP: usize = 1024;
/// Recent local messages offered to a neighbor that asks for catch-up.
/// Frames one catch-up reply may send, across lines and reactions together.
///
/// Under [`CHANNEL_GOSSIP_IN_PER_PEER_PER_SEC`] so a reply is not partly shed by
/// its own recipient, with room left for the ordinary relay traffic sharing that
/// hop's allowance. Lines are served first and reactions take what is left, so a
/// room becomes readable before it becomes fully annotated.
pub const CHANNEL_HISTORY_SYNC_FRAME_MAX: usize = 40;

pub const CHANNEL_HISTORY_SYNC_MAX: usize = 32;

// A reply arrives from one peer, so the whole thing is charged to that hop's
// bucket. Exceeding it sheds the tail — recoverable, since the requester's
// watermark does not advance past what it stored, but it costs a round trip and
// looks to the reader like history arriving in pieces. Compile-time rather than a
// test: raising either number past the other is a mistake that should not build.
const _: () = assert!(
    CHANNEL_HISTORY_SYNC_FRAME_MAX < CHANNEL_GOSSIP_IN_PER_PEER_PER_SEC,
    "a catch-up reply must fit inside what one hop may send us in a second"
);
// And lines alone must not be able to spend the whole budget, or a busy room
// would never carry its reactions across.
const _: () = assert!(
    CHANNEL_HISTORY_SYNC_MAX < CHANNEL_HISTORY_SYNC_FRAME_MAX,
    "the frame budget must leave room for reactions after the lines"
);
/// Catch-up requests answered for one member of one room per minute.
///
/// Far tighter than the chat budget because a sync request is the one frame
/// that costs the receiver more than the sender: a single 105-byte request is
/// answered with up to [`CHANNEL_HISTORY_SYNC_MAX`] separately sealed unicast
/// frames, so at the chat allowance one peer could turn four packets a second
/// into a hundred and twenty-eight. A member asks once per
/// [`CHANNEL_HISTORY_SYNC_SECS`] (five minutes), so two a minute is already
/// far more headroom than the honest path uses.
pub const CHANNEL_HISTORY_SYNC_PER_MIN: usize = 2;
/// How often we ask one neighbor for missed history.
pub const CHANNEL_HISTORY_SYNC_SECS: u64 = 5 * 60;
/// Catch-up asks for messages in this window behind our newest timestamp so a
/// hole behind the frontier can still be filled. Combined with
/// `ORDER BY timestamp DESC`, a new joiner (watermark 0) receives the newest
/// [`CHANNEL_HISTORY_SYNC_MAX`] lines rather than the oldest.
pub const CHANNEL_HISTORY_SYNC_LOOKBACK_SECS: i64 = 6 * 60 * 60;
/// Gossip timestamps further ahead of local time than this are refused.
///
/// The envelope timestamp is authenticated under the room key, so a member
/// (or anyone who can compute a public room's key) can still *choose* it.
/// Without a ceiling, `i64::MAX` poisons `last_active`, the history-sync
/// watermark, and `ban_revised_at` — an owner snapshot can never catch up.
pub const CHANNEL_GOSSIP_MAX_FUTURE_SKEW_SECS: i64 = 5 * 60;
/// Originated frames waiting for a neighbor to appear, or for the local
/// send budget to roll over. Sized to a couple of bursts, not a send loop.
pub const CHANNEL_ORIGIN_RETRY_CAP: usize = 64;
/// Give up retrying an origination that has sat this long.
pub const CHANNEL_ORIGIN_RETRY_SECS: u64 = 10 * 60;
/// Retry rendezvous lookup sooner when a neighbor still has no UDP session.
pub const CHANNEL_NEIGHBOR_LOOKUP_RETRY_SECS: u64 = 30;
/// How often members walk the owner-signed handoff key.
pub const HANDOFF_FETCH_SECS: i64 = 5 * 60;
/// How long an unanswered ownership offer blocks a different one.
///
/// The offer is a single gossip flood, retried for at most
/// [`CHANNEL_ORIGIN_RETRY_SECS`], so a nominee who never comes online in that
/// window will not answer at all. Nothing cleared the pending mark, and no
/// command exposed a way to: an owner who offered the room to someone offline
/// was told "a transfer to another member is already waiting to be accepted"
/// for every later attempt, forever, with deleting the room as the only way
/// out. Comfortably past the retry window so a live handoff is never cut
/// short, and short enough that a lapsed one stops being a life sentence.
/// Re-offering to the *same* member stays allowed at any age.
pub const HANDOFF_PENDING_TTL_SECS: i64 = 60 * 60;
// --- Ember Transfer -------------------------------------------------------
//
// One member hands a file to one other member. Nothing is broadcast: the
// offer, the reply, and every block are addressed to a single peer, and the
// recipient has to accept before any bytes move.
//
// This is the first version of the Ember transfer system, so it deliberately
// runs on what the room already has — the authenticated Noise/UDP session
// between members, with the channel relay as a fallback. The framing keeps
// the file identified by its BLAKE3 root, so a later QUIC or multi-source
// implementation can carry the same offers without a new handshake.

/// Largest file one member may offer another.
pub const XFER_MAX_BYTES: u64 = 100 * 1024 * 1024;
/// Payload bytes per block. Chosen so a data frame plus its plaintext header,
/// authenticator, gossip envelope, and a relay wrapper still fit one
/// unfragmented datagram. `xfer_block_frame_fits_one_unfragmented_datagram`
/// pins the arithmetic; a fragmented block is one plenty of consumer NATs
/// simply drop, which would show up as a transfer that never finishes.
pub const XFER_BLOCK_SIZE: usize = 1008;
/// Truncated BLAKE3 authenticator on every transfer frame. See
/// [`derive_xfer_key`].
pub const XFER_MAC_LEN: usize = 16;
/// Longest file name carried on the wire.
pub const XFER_NAME_MAX: usize = 160;
/// Blocks the receiver leaves outstanding at once. This is the flow control:
/// the sender only ever answers requests, so it cannot outrun the receiver.
pub const XFER_WINDOW_BLOCKS: usize = 64;
/// Re-request a block that has not landed within this long.
pub const XFER_BLOCK_TIMEOUT_MS: u64 = 4_000;
/// Abandon a transfer that has made no progress at all for this long.
pub const XFER_STALL_SECS: u64 = 90;
/// Data frames one node emits per second.
///
/// Deliberately its own budget rather than the chat one. Sharing
/// `CHANNEL_GOSSIP_OUT_PER_SEC` is what made the old attachment path stall a
/// few kilobytes in: a transfer would spend the room's entire gossip
/// allowance and then abandon itself.
pub const XFER_BLOCKS_OUT_PER_SEC: usize = 192;
/// Concurrent transfers, counted per direction.
pub const XFER_MAX_ACTIVE: usize = 4;
/// How long an offer waits for an answer before it lapses.
pub const XFER_OFFER_TTL_SECS: i64 = 300;
/// Private rooms keep the existing join secret across ownership transfer.
pub const HANDOFF_FLAG_KEEP_JOIN_SECRET: u8 = 0x01;
pub const CHANNEL_MSG_VERSION: u8 = 1;
const GOSSIP_NONCE_LEN: usize = 24;
const GOSSIP_TAG_LEN: usize = 16;
/// `version(1) + nonce + tag` around the plaintext.
pub const GOSSIP_ENVELOPE_OVERHEAD: usize = 1 + GOSSIP_NONCE_LEN + GOSSIP_TAG_LEN;
/// Fixed prefix of a gossip body before the ciphertext:
/// version(1) + channel_id(16) + msg_id(16) + ttl(1) + timestamp(8) + counter(8).
pub const GOSSIP_HEADER_LEN: usize = 1 + 16 + 16 + 1 + 8 + 8;

pub const CHANNEL_KIND_PUBLIC: &str = "public";
pub const CHANNEL_KIND_PRIVATE: &str = "private";

const URI_SCHEME: &str = "ember-channel:";

/// A newly minted channel identity.
#[derive(Clone)]
pub struct ChannelIdentity {
    pub signing_key: SigningKey,
    pub pubkey: [u8; 32],
    pub channel_id: [u8; 16],
}

impl ChannelIdentity {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self::from_signing_key(signing_key)
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self::from_signing_key(SigningKey::from_bytes(seed))
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let pubkey = signing_key.verifying_key().to_bytes();
        let channel_id = channel_id_from_pubkey(&pubkey);
        Self {
            signing_key,
            pubkey,
            channel_id,
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

/// `channel_id = BLAKE3(channel_pubkey)[..16]`.
pub fn channel_id_from_pubkey(pubkey: &[u8; 32]) -> [u8; 16] {
    crypto::node_id_from_ed25519_bytes(pubkey).unwrap_or_else(|| {
        // A 32-byte value that is not a valid Ed25519 point cannot be a
        // channel pubkey we would ever mint or accept on the wire. The
        // fallback keeps the function total for hashing already-checked keys.
        let hash = blake3::hash(pubkey);
        let mut id = [0u8; 16];
        id.copy_from_slice(&hash.as_bytes()[..16]);
        id
    })
}

/// Public channels use the channel pubkey as the join secret. Private
/// channels carry an extra 32-byte secret in the invite.
pub fn public_join_secret(channel_pubkey: &[u8; 32]) -> [u8; 32] {
    *channel_pubkey
}

pub fn generate_private_join_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    secret
}

/// Symmetric key for channel message bodies and private metadata.
pub fn content_key(join_secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(CONTENT_KEY_CONTEXT, join_secret)
}

pub fn index_shard(channel_id: &[u8; 16]) -> u8 {
    channel_id[0] % INDEX_SHARD_COUNT
}

/// DHT key for one public-index shard.
pub fn index_key(shard: u8) -> [u8; 16] {
    let shard = shard % INDEX_SHARD_COUNT;
    let mut hasher = blake3::Hasher::new();
    hasher.update(INDEX_KEY_PREFIX);
    hasher.update(&[shard]);
    let hash = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash.as_bytes()[..16]);
    key
}

pub fn index_key_for_channel(channel_id: &[u8; 16]) -> [u8; 16] {
    index_key(index_shard(channel_id))
}

/// All 16 public-index keys, in shard order, for Gather.
pub fn all_index_keys() -> [[u8; 16]; INDEX_SHARD_COUNT as usize] {
    let mut keys = [[0u8; 16]; INDEX_SHARD_COUNT as usize];
    for (i, key) in keys.iter_mut().enumerate() {
        *key = index_key(i as u8);
    }
    keys
}

pub fn presence_epoch(unix_seconds: i64) -> i64 {
    unix_seconds.div_euclid(PRESENCE_EPOCH_SECS)
}

/// Presence DHT key. Private channels fold `join_secret` in so non-members
/// cannot enumerate the room.
pub fn presence_key(channel_id: &[u8; 16], join_secret: &[u8; 32], epoch: i64) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PRESENCE_KEY_PREFIX);
    hasher.update(channel_id);
    hasher.update(join_secret);
    hasher.update(&epoch.to_le_bytes());
    let hash = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash.as_bytes()[..16]);
    key
}

pub fn moderation_key(channel_id: &[u8; 16]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MODERATION_KEY_PREFIX);
    hasher.update(channel_id);
    let hash = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash.as_bytes()[..16]);
    key
}

/// DHT key for an owner-signed successor record. `file_hash` on that record
/// is the **old** `channel_id`, so it never shares a STORE slot with
/// moderation (same publisher + file_hash would replace).
pub fn handoff_key(channel_id: &[u8; 16]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(HANDOFF_KEY_PREFIX);
    hasher.update(channel_id);
    let hash = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash.as_bytes()[..16]);
    key
}

/// DHT key holding one member's copy of one content-key epoch.
///
/// Per member rather than one record listing everybody: a room of 32 would not
/// fit a single record, and this way each member fetches only their own slot.
/// An evicted member can still fetch someone else's blob — they simply cannot
/// open it, which is the whole point.
pub fn epoch_key(channel_id: &[u8; 16], member_pubkey: &[u8; 32], epoch: i64) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EPOCH_KEY_PREFIX);
    hasher.update(channel_id);
    hasher.update(member_pubkey);
    hasher.update(&epoch.to_le_bytes());
    let hash = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash.as_bytes()[..16]);
    key
}

/// Whether a room's owner-silence is something we have observed rather than
/// assumed.
///
/// `moderation_checked_at` is when a search for the owner's record last came
/// back. Without this, a client that had been offline past the claim window
/// would treat its own stale snapshot as proof the owner had gone — the two are
/// indistinguishable locally. Both the member honouring a claim and the nominee
/// making one ask this, so neither can act on an unverified silence.
///
/// Three fetch intervals tolerates a couple of missed passes.
pub fn owner_silence_is_confirmed(moderation_checked_at: i64) -> bool {
    if moderation_checked_at <= 0 {
        return false;
    }
    let age = chrono::Utc::now()
        .timestamp()
        .saturating_sub(moderation_checked_at);
    age <= MODERATION_FETCH_SECS * 3
}

/// Default silence before an owner's nomination may be claimed.
pub const CLAIM_AFTER_DAYS_DEFAULT: u16 = 14;
/// Bounds on that window. A room whose owner is merely on holiday must not
/// change hands, and one nobody can ever inherit is the problem being solved.
pub const CLAIM_AFTER_DAYS_MIN: u16 = 7;
pub const CLAIM_AFTER_DAYS_MAX: u16 = 365;

/// DHT key for a nominee's succession claim.
///
/// Separate from [`handoff_key`] because the two are signed by different keys:
/// a handoff is the owner acting, a claim is a nominee acting in their absence.
/// Sharing a slot would let one overwrite the other.
pub fn claim_key(channel_id: &[u8; 16]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CLAIM_KEY_PREFIX);
    hasher.update(channel_id);
    let hash = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash.as_bytes()[..16]);
    key
}

/// `successor_pubkey(32) || witnessed_moderation_ts(8)`.
///
/// The timestamp is the newest owner-signed moderation record the claimant
/// could find. Members check it against their own copy, so a claimant cannot
/// pretend the owner has been quiet longer than they have.
pub fn encode_claim_extra(successor_pubkey: &[u8; 32], witnessed_moderation_ts: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(successor_pubkey);
    out.extend_from_slice(&witnessed_moderation_ts.to_le_bytes());
    out
}

pub fn decode_claim_extra(extra: &[u8]) -> Option<([u8; 32], [u8; 16], i64)> {
    if extra.len() != 40 {
        return None;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&extra[..32]);
    // Must be a real point, or the successor id derived from it is meaningless.
    crypto::verifying_key_from_bytes(&pk)?;
    let ts = i64::from_le_bytes(extra[32..].try_into().ok()?);
    Some((pk, channel_id_from_pubkey(&pk), ts))
}

/// Wrapping key for one member's copy of one epoch.
///
/// Symmetric static DH, so the owner computes it from their own seed plus the
/// member's identity and the member computes the identical value from their
/// seed plus the owner's — which they know because the owner signs it into the
/// moderation record. Nobody else can derive it, so nobody else can read the
/// room key out of the DHT.
pub fn derive_channel_epoch_secret(
    our_ed25519_seed: &[u8; 32],
    peer_ed25519_pubkey: &[u8; 32],
    channel_id: &[u8; 16],
    epoch: i64,
) -> Option<[u8; 32]> {
    // Pairwise purpose is capped at 64 bytes; this is 26.
    let mut purpose = Vec::with_capacity(10 + 16);
    purpose.extend_from_slice(b"ch-epoch-v1");
    purpose.extend_from_slice(channel_id);
    crypto::derive_pairwise_capability(our_ed25519_seed, peer_ed25519_pubkey, &purpose, epoch)
}

/// Seal a rotated content key for one member.
///
/// The epoch and room are bound as AAD, so a blob lifted from one room or one
/// epoch cannot be replayed into another even by a member who legitimately
/// holds the wrapping key for both.
pub fn seal_channel_key_epoch(
    wrap_key: &[u8; 32],
    channel_id: &[u8; 16],
    epoch: i64,
    room_key: &[u8; 32],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(wrap_key));
    let mut nonce = [0u8; GOSSIP_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let encrypted = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: room_key,
                aad: &epoch_aad(channel_id, epoch),
            },
        )
        .expect("XChaCha20-Poly1305 encryption cannot fail for a 32-byte key");
    let mut out = Vec::with_capacity(1 + GOSSIP_NONCE_LEN + encrypted.len());
    out.push(EPOCH_ENVELOPE_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&encrypted);
    out
}

pub fn open_channel_key_epoch(
    wrap_key: &[u8; 32],
    channel_id: &[u8; 16],
    epoch: i64,
    envelope: &[u8],
) -> Option<[u8; 32]> {
    if envelope.len() != EPOCH_ENVELOPE_LEN || envelope[0] != EPOCH_ENVELOPE_VERSION {
        return None;
    }
    let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(wrap_key));
    let plain = cipher
        .decrypt(
            XNonce::from_slice(&envelope[1..1 + GOSSIP_NONCE_LEN]),
            Payload {
                msg: &envelope[1 + GOSSIP_NONCE_LEN..],
                aad: &epoch_aad(channel_id, epoch),
            },
        )
        .ok()?;
    <[u8; 32]>::try_from(plain).ok()
}

fn epoch_aad(channel_id: &[u8; 16], epoch: i64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(EPOCH_AAD_DOMAIN.len() + 16 + 8);
    aad.extend_from_slice(EPOCH_AAD_DOMAIN);
    aad.extend_from_slice(channel_id);
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad
}

/// Storers cannot open an epoch blob, so they check only that it is the right
/// shape — a truncated or padded one is dropped rather than stored to mislead.
pub fn epoch_envelope_store_ok(extra: &[u8]) -> bool {
    extra.len() == EPOCH_ENVELOPE_LEN && extra[0] == EPOCH_ENVELOPE_VERSION
}

/// Rendezvous capability two channel members compute for each other.
///
/// Distinct from friend presence: the purpose binds the channel and the
/// presence-slot owner, so a channel neighbor cannot reuse the capability
/// to look up a friend slot, and Alice's entry cannot overwrite Bob's.
pub fn derive_channel_presence_capability(
    our_ed25519_seed: &[u8; 32],
    peer_ed25519_pubkey: &[u8; 32],
    owner_ed25519_pubkey: &[u8; 32],
    channel_id: &[u8; 16],
    epoch: i64,
) -> Option<[u8; 32]> {
    // Pairwise purpose is capped at 64 bytes. Truncate the owner to the
    // same 16-byte ID used everywhere else so the tuple still fits.
    let owner_id = channel_id_from_pubkey(owner_ed25519_pubkey);
    let mut purpose = Vec::with_capacity(10 + 16 + 16);
    purpose.extend_from_slice(b"ch-pres-v1");
    purpose.extend_from_slice(channel_id);
    purpose.extend_from_slice(&owner_id);
    crypto::derive_pairwise_capability(our_ed25519_seed, peer_ed25519_pubkey, &purpose, epoch)
}

/// Whether a signature-valid chat line may insert its author into the
/// gossip roster.
///
/// Presence is the voucher for a public room: anyone who can compute the
/// public content key can mint a chat line, so treating every author as a
/// mesh neighbor is how a public room gets eclipsed. Private rooms fold a
/// secret into the content key, so a chat line is already evidence of
/// membership. Chat display can still show the author either way.
pub fn chat_author_joins_gossip_roster(private: bool) -> bool {
    private
}

/// Presence timestamps more than this far ahead of wall clock are dropped.
/// Same bound DHT store uses for `created_at` (`CLOCK_SKEW_TOLERANCE_SECS`
/// = 3600): a record that sat in the store can still carry a lying
/// `last_seen`, and that is what roster eviction sorts on.
pub const PRESENCE_MAX_FUTURE_SKEW_SECS: i64 = 3600;

/// Drop a signed presence timestamp that is unusable as `last_seen`, and
/// clamp a slightly-ahead clock so it cannot sort past honest peers.
pub fn clamp_presence_timestamp(timestamp: i64, now: i64) -> Option<i64> {
    if timestamp <= 0 || timestamp > now.saturating_add(PRESENCE_MAX_FUTURE_SKEW_SECS) {
        return None;
    }
    Some(timestamp.min(now))
}

/// A leave tombstone for our own key is ignored while we are still in
/// the room: the previous epoch's departure would otherwise delete us
/// after we re-announced under the current one.
pub fn presence_departure_applies(
    publisher: &[u8; 32],
    our_pubkey: &[u8; 32],
    in_room: bool,
) -> bool {
    !(publisher == our_pubkey && in_room)
}

/// Direct DHT unicast only with a live Noise session. A routing-table
/// contact (including HandshakeStarted / replacement cache) is not
/// delivery; those neighbors still go through overlay and the WebSocket
/// outbox.
pub fn channel_fanout_uses_direct_session(has_live_session: bool) -> bool {
    has_live_session
}

/// Inbound `CHANNEL_RELAY` may be forwarded only when this node is in the
/// named room, a live Noise session already exists for the target (never a
/// replacement-cache lead we would handshake to), and — when we have a
/// roster — the target is on it.
///
/// The previous hop is a DHT overlay contact, not necessarily a member, so
/// it is not roster-checked. Relays stay off the handshake-initiating path:
/// `has_live_session` is what makes `prepare_outgoing` take the established
/// fast path instead of starting Noise_IK and re-sealing the attacker's body
/// under our identity.
pub fn inbound_channel_relay_may_forward(
    in_room: bool,
    target_on_roster: Option<bool>,
    has_live_session: bool,
) -> bool {
    if !in_room || !has_live_session {
        return false;
    }
    target_on_roster.unwrap_or(true)
}

/// XOR-closest `k` member pubkeys to `self_pub`, excluding self.
///
/// Distance is on the 16-byte IDs (`BLAKE3(pubkey)[..16]`), matching DHT
/// node IDs, so both sides independently compute the same pairing.
pub fn xor_closest_neighbors(self_pub: &[u8; 32], members: &[[u8; 32]], k: usize) -> Vec<[u8; 32]> {
    let self_id = EmberNodeId(channel_id_from_pubkey(self_pub));
    let mut ranked: Vec<([u8; 32], EmberNodeId)> = members
        .iter()
        .filter(|pk| *pk != self_pub)
        .map(|pk| {
            let id = EmberNodeId(channel_id_from_pubkey(pk));
            (*pk, self_id.distance(&id))
        })
        .collect();
    ranked.sort_by_key(|a| a.1 .0);
    ranked.truncate(k);
    ranked.into_iter().map(|(pk, _)| pk).collect()
}

/// Members either side of us in ring order that always get a gossip slot.
///
/// Two each way rather than one: a single successor and predecessor is enough
/// for connectivity on paper, but it makes the cycle depend on both of those
/// two being reachable, and it spends fewer slots on the long-range links than
/// the rest of the budget can afford. Three each way starts costing reach —
/// at 256 members it leaves too few buckets covered to cross the id space
/// inside [`CHANNEL_MSG_TTL_DEFAULT`].
pub const RING_NEIGHBORS_EACH_WAY: usize = 2;

/// Length of the common prefix of two ids, i.e. the index of the first bit
/// where they differ. 128 when they are equal.
fn xor_bucket(distance: &[u8; 16]) -> u32 {
    for (i, byte) in distance.iter().enumerate() {
        if *byte != 0 {
            return i as u32 * 8 + byte.leading_zeros();
        }
    }
    128
}

fn xor_distance(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (slot, (x, y)) in out.iter_mut().zip(a.iter().zip(b.iter())) {
        *slot = x ^ y;
    }
    out
}

/// Deterministic gossip neighbors: ring links for connectivity, long-range
/// links for reach.
///
/// [`xor_closest_neighbors`] cannot do this job alone, and the reason is
/// structural rather than a matter of tuning. XOR-closest-`k` is
/// *prefix-closed*: for any set of members sharing an id prefix, every member
/// of that set is nearer to each other than to any outsider, so once such a
/// set holds more than `k` members every one of their slots is spent inside it
/// and no edge ever leaves. Rooms therefore split at the top bits of the id
/// space — a 256-member room settled into roughly eighteen islands that never
/// exchanged a line — and nothing repaired it, because the fanout retry only
/// widens when fewer than `k` neighbors resolve and catch-up draws its
/// partners from the same closed set.
///
/// Two link types fix it, and both are needed:
///
/// * **Ring** — the [`RING_NEIGHBORS_EACH_WAY`] members either side of us in
///   id order, wrapping at the ends. These form a cycle through the whole
///   roster, so the graph is connected however the ids cluster. They are also
///   the only links guaranteed to be mutual — our successor's predecessor is
///   us — which matters because the rendezvous presence capability is
///   pairwise: an edge the far end does not also choose has nobody publishing
///   an address under the capability we would look up.
/// * **Long-range** — the nearest member in each XOR distance bucket,
///   shallowest bucket (furthest half of the space) first, so every slot past
///   the ring reaches a different scale. A ring on its own is connected but
///   has diameter `N / 2r`, which at 256 members is several times
///   [`CHANNEL_MSG_TTL_DEFAULT`]; these collapse it to a few hops.
///
/// Any slots still spare fall back to XOR-closest, which is what small rooms
/// use for most of their degree.
///
/// Derived only from the roster, so a member computes the same set for
/// themselves that their neighbors compute for them —
/// [`rendezvous_neighbor_targets`] relies on that to register the capability
/// the other end will look up.
pub fn gossip_neighbors(self_pub: &[u8; 32], members: &[[u8; 32]], k: usize) -> Vec<[u8; 32]> {
    if k == 0 {
        return Vec::new();
    }
    let self_id = channel_id_from_pubkey(self_pub);
    // Sorted by id, which is the ring order. Deduped so a roster that lists a
    // member twice cannot hand the same peer two slots.
    let mut ring: Vec<([u8; 16], [u8; 32])> = members
        .iter()
        .filter(|pk| *pk != self_pub)
        .map(|pk| (channel_id_from_pubkey(pk), *pk))
        .collect();
    ring.sort_unstable();
    ring.dedup();
    let n = ring.len();
    if n == 0 {
        return Vec::new();
    }

    let mut out: Vec<[u8; 32]> = Vec::with_capacity(k);
    // Where our own id would sit: everything from here on is a successor,
    // everything before it a predecessor, both wrapping.
    let pos = ring.partition_point(|(id, _)| *id < self_id);
    for step in 0..RING_NEIGHBORS_EACH_WAY {
        for index in [(pos + step) % n, (pos + n - 1 - (step % n)) % n] {
            let pk = ring[index].1;
            if out.len() < k && !out.contains(&pk) {
                out.push(pk);
            }
        }
    }

    // One per bucket, furthest scale first, so the slots left after the ring
    // are spent crossing the id space rather than crowding around us.
    if out.len() < k {
        let mut spread: Vec<(u32, [u8; 16], [u8; 32])> = ring
            .iter()
            .map(|(id, pk)| {
                let distance = xor_distance(&self_id, id);
                (xor_bucket(&distance), distance, *pk)
            })
            .collect();
        spread.sort_unstable();
        let mut last_bucket = None;
        for (bucket, _, pk) in spread {
            if last_bucket == Some(bucket) {
                continue;
            }
            last_bucket = Some(bucket);
            if !out.contains(&pk) {
                out.push(pk);
                if out.len() == k {
                    break;
                }
            }
        }
    }

    if out.len() < k {
        for pk in xor_closest_neighbors(self_pub, members, k) {
            if !out.contains(&pk) {
                out.push(pk);
                if out.len() == k {
                    break;
                }
            }
        }
    }
    out
}

/// Gossip neighbors across joined rooms, for rendezvous capability
/// registration. Caps both the number of rooms and the degree so a large join
/// list cannot explode the heartbeat HTTP fan-out.
pub fn rendezvous_neighbor_targets(
    our_pubkey: &[u8; 32],
    members_by_channel: &[([u8; 16], Vec<[u8; 32]>)],
    max_channels: usize,
    neighbor_count: usize,
) -> Vec<([u8; 16], [u8; 32])> {
    let mut out = Vec::new();
    for (channel_id, members) in members_by_channel.iter().take(max_channels) {
        for pk in gossip_neighbors(our_pubkey, members, neighbor_count) {
            out.push((*channel_id, pk));
        }
    }
    out
}

/// Parsed `ember-channel:` invite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelInvite {
    pub channel_id: [u8; 16],
    pub pubkey: [u8; 32],
    pub name: String,
    pub join_secret: [u8; 32],
    pub private: bool,
    /// Which content-key epoch `join_secret` belongs to. 0 means the invite does
    /// not say, which is true of a room that never rotated and of any invite
    /// minted before this field existed.
    ///
    /// Without it a joiner cannot tell a working invite from a stale one: their
    /// secret is current, but the room reports an epoch they have no record of,
    /// so they would be told their invite was out of date and would chase a key
    /// that was never minted for them.
    pub key_epoch: u64,
}

impl ChannelInvite {
    pub fn format(&self) -> String {
        let mut uri = format!(
            "{URI_SCHEME}{}?pk={}",
            hex::encode(self.channel_id),
            hex::encode(self.pubkey)
        );
        if !self.name.is_empty() {
            uri.push_str("&name=");
            uri.push_str(&percent_encode(&self.name));
        }
        if self.private {
            uri.push_str("&k=");
            uri.push_str(&hex::encode(self.join_secret));
            // Omitted at epoch 0 so an unrotated room's invite is unchanged.
            if self.key_epoch > 0 {
                uri.push_str("&e=");
                uri.push_str(&self.key_epoch.to_string());
            }
        }
        uri
    }

    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        let rest = trimmed.strip_prefix(URI_SCHEME)?;
        let (id_hex, query) = rest.split_once('?').unwrap_or((rest, ""));
        if id_hex.len() != 32 {
            return None;
        }
        let channel_id = hex_16(id_hex)?;
        let mut pubkey = None;
        let mut name = String::new();
        let mut join_secret = None;
        let mut key_epoch = 0u64;
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            match key {
                "pk" => pubkey = hex_32(value),
                "name" => name = percent_decode(value)?,
                "k" => join_secret = hex_32(value),
                // Unparseable is the same as absent: an invite is user-pasted,
                // so a mangled epoch must not throw the whole thing away when
                // the secret itself is intact.
                "e" => key_epoch = value.parse().unwrap_or(0),
                _ => {}
            }
        }
        let pubkey = pubkey?;
        if channel_id_from_pubkey(&pubkey) != channel_id {
            return None;
        }
        let private = join_secret.is_some();
        let join_secret = join_secret.unwrap_or_else(|| public_join_secret(&pubkey));
        // A public room's key is derived, never rotated, so an epoch on one is
        // meaningless and is dropped rather than recorded.
        let key_epoch = if private { key_epoch } else { 0 };
        Some(Self {
            channel_id,
            pubkey,
            name,
            join_secret,
            private,
            key_epoch,
        })
    }
}

fn hex_16(s: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(s).ok()?;
    <[u8; 16]>::try_from(bytes).ok()
}

fn hex_32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    <[u8; 32]>::try_from(bytes).ok()
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let hi = from_hex_digit(bytes[i + 1])?;
                let lo = from_hex_digit(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn from_hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Authenticated gossip payload carried inside [`super::dht::messages::MSG_CHANNEL_MSG`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelGossip {
    pub channel_id: [u8; 16],
    pub msg_id: [u8; 16],
    pub ttl: u8,
    pub timestamp: i64,
    pub sender_counter: u64,
    pub ciphertext: Vec<u8>,
}

// 1 was chat before it carried the author's signature. A peer still sending it
// cannot prove who wrote the line, which is exactly what the new frame exists
// to establish, so the number is retired rather than accepted alongside: were
// it still read, an impersonator would just send the old frame and the
// signature would buy nothing.
const CHAT_PLAIN_VERSION: u8 = 15;
// 2 was unsigned moderator gossip. Same hole chat closed: the content key
// proves membership, not who sent the frame. Retired rather than accepted
// alongside, or an impersonator would just send the old frame.
const MOD_ACTION_PLAIN_VERSION: u8 = 16;
// 3 was an unsigned sync request. Retired for the same reason: a banned
// member could name someone else and be answered under an old epoch key.
const SYNC_REQUEST_PLAIN_VERSION: u8 = 18;
// 4, 5, and 8 belonged to the withdrawn broadcast-attachment path. Builds
// still running it are on the network, so the numbers stay retired rather
// than being recycled into something a stale peer would misread.
const HANDOFF_OFFER_PLAIN_VERSION: u8 = 6;
// 7 was unsigned handoff-ready. The offer is signed by the channel key; Ready
// was not, so any content-key holder who saw the flooded offer could race the
// nominee and point the DHT handoff at a successor they own.
const HANDOFF_READY_PLAIN_VERSION: u8 = 17;
const MOD_SIG_DOMAIN: &[u8] = b"ember-channel-mod-author-v1\0";
const SYNC_SIG_DOMAIN: &[u8] = b"ember-channel-sync-author-v1\0";
const HANDOFF_READY_DOMAIN: &[u8] = b"ember-channel-handoff-ready-v1\0";
/// Revision of a line the author already sent. Signed by the same key the
/// original was, so "only the author may edit" is something every receiver
/// checks rather than something the sending client is trusted about.
const CHAT_EDIT_PLAIN_VERSION: u8 = 19;
/// One or more reactions to lines in this room. Always a batch — a live
/// reaction is a batch of one — so catch-up can carry a room's worth of
/// reactions in a frame or two instead of one datagram each.
const REACTION_PLAIN_VERSION: u8 = 20;
const EDIT_SIG_DOMAIN: &[u8] = b"ember-channel-edit-author-v1\0";
const REACTION_SIG_DOMAIN: &[u8] = b"ember-channel-reaction-author-v1\0";
const XFER_OFFER_PLAIN_VERSION: u8 = 9;
const XFER_REPLY_PLAIN_VERSION: u8 = 10;
const XFER_BLOCK_REQUEST_PLAIN_VERSION: u8 = 11;
// 12 was a block whose payload travelled in the clear, authenticated pairwise
// but encrypted only by the gossip envelope around it -- which is sealed with
// the *room's* content key. Retired rather than reused: a build still sending
// them must be refused, not misread.
const XFER_CANCEL_PLAIN_VERSION: u8 = 13;
const XFER_DONE_PLAIN_VERSION: u8 = 14;
/// A block whose payload is encrypted to the recipient alone.
const XFER_BLOCK_DATA_SEALED_VERSION: u8 = 21;
const MOD_ACTION_BAN: u8 = 1;
const MOD_ACTION_UNBAN: u8 = 0;
const PRESENCE_EXTRA_ENC_VERSION: u8 = 1;
const PRESENCE_NICK_PAD: usize = 64;
const PRESENCE_EXTRA_AAD: &[u8] = b"ember-channel-presence-extra-v1\0";
/// Encrypted private extra: version + nonce + tag + noise + nick_len + pad.
pub const PRESENCE_EXTRA_ENC_LEN: usize =
    1 + GOSSIP_NONCE_LEN + GOSSIP_TAG_LEN + 32 + 1 + PRESENCE_NICK_PAD;

/// What the author's signature covers.
///
/// The room binding is the point. Every member holds the content key, so the
/// AEAD proves only that a line came from *somebody* in the room, and the
/// `sender` beside it was until now an unauthenticated claim any member could
/// fill in with another member's key. Signing the text alone would fix the
/// author and leave the context forgeable: the same signed line could be
/// replayed into a different room, or re-dated, or re-wrapped under a fresh
/// `msg_id` to slip past the duplicate filter and repeat somebody's words back
/// at the room. All four are therefore inside the preimage.
fn chat_sig_preimage(
    channel_id: &[u8; 16],
    msg_id: &[u8; 16],
    timestamp: i64,
    sender_pubkey: &[u8; 32],
    text: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(CHAT_SIG_DOMAIN.len() + 16 + 16 + 8 + 32 + text.len());
    out.extend_from_slice(CHAT_SIG_DOMAIN);
    out.extend_from_slice(channel_id);
    out.extend_from_slice(msg_id);
    out.extend_from_slice(&timestamp.to_le_bytes());
    out.extend_from_slice(sender_pubkey);
    out.extend_from_slice(text.as_bytes());
    out
}

/// The author's signature over a chat line.
///
/// A signature rather than the pairwise MAC transfers use, because chat is
/// one-to-many and every member has to verify the same bytes. The 64 bytes are
/// affordable here for the reason they were not on a transfer block: a chat
/// line is nowhere near the unfragmented datagram budget.
///
/// Produced separately from the frame so a sender can keep it with its stored
/// copy of the message and put byte-identical bytes on the wire, which is what
/// lets the row be re-served on a catch-up later.
pub fn chat_author_signature(
    signing_key: &SigningKey,
    sender_pubkey: &[u8; 32],
    channel_id: &[u8; 16],
    msg_id: &[u8; 16],
    timestamp: i64,
    text: &str,
) -> [u8; 64] {
    crypto::sign(
        signing_key,
        &chat_sig_preimage(channel_id, msg_id, timestamp, sender_pubkey, text),
    )
}

/// Rebuild a chat frame around a signature its author already made.
///
/// History catch-up re-serves lines somebody else wrote, and only they could
/// have signed one. Replaying the original is what makes a re-serve worth
/// trusting; minting a fresh signature here would be precisely the
/// impersonation the frame exists to rule out.
pub fn encode_channel_chat_plain_presigned(
    sender_pubkey: &[u8; 32],
    signature: &[u8; 64],
    text: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 64 + text.len());
    out.push(CHAT_PLAIN_VERSION);
    out.extend_from_slice(sender_pubkey);
    out.extend_from_slice(signature);
    out.extend_from_slice(text.as_bytes());
    out
}

/// Recover the author of a chat line, or nothing if it cannot be proved.
///
/// Returns `None` for an unsigned line as well as a badly signed one. Accepting
/// unsigned chat would leave the forgery it exists to close wide open, since an
/// impersonator would simply send the older frame; the version byte moved for
/// the same reason, so a build that cannot sign is not silently trusted.
///
/// The signature comes back with the text so a receiver can keep it and re-serve
/// the line later without being able to author one.
pub fn decode_channel_chat_plain(
    bytes: &[u8],
    channel_id: &[u8; 16],
    msg_id: &[u8; 16],
    timestamp: i64,
) -> Option<([u8; 32], String, [u8; 64])> {
    if bytes.len() < 1 + 32 + 64 || bytes[0] != CHAT_PLAIN_VERSION {
        return None;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&bytes[1..33]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes[33..97]);
    let text = std::str::from_utf8(&bytes[97..]).ok()?.to_string();
    let author = crypto::verifying_key_from_bytes(&pk)?;
    if !crypto::verify(
        &author,
        &chat_sig_preimage(channel_id, msg_id, timestamp, &pk, &text),
        &sig,
    ) {
        return None;
    }
    Some((pk, text, sig))
}

/// Whether a gossip envelope timestamp is usable as wall-clock state.
///
/// Old timestamps are allowed: history catch-up replays them, and a delayed
/// flood can be minutes behind. Far-future values are not — they are how a
/// member used to stick a ban or freeze catch-up for everyone who stored it.
pub fn gossip_timestamp_ok(timestamp: i64, now: i64) -> bool {
    timestamp > 0 && timestamp <= now.saturating_add(CHANNEL_GOSSIP_MAX_FUTURE_SKEW_SECS)
}

/// How long after sending a line its author may still revise it.
///
/// Long enough to catch the typo you notice a moment after pressing Enter,
/// short enough that nobody rewrites what a conversation was replying to. Both
/// ends of a room enforce it: see [`edit_within_window`] for why the check needs
/// two clocks rather than one.
pub const CHANNEL_EDIT_WINDOW_SECS: i64 = 15 * 60;

/// Whether an edit may still be applied to the line it names.
///
/// Two clocks, because neither alone is sufficient. `original_timestamp` and
/// `edited_at` are both author-supplied, so on their own a member could date a
/// line now, wait a day, and send an "edit" dated a minute after it —
/// [`gossip_timestamp_ok`] deliberately allows old timestamps, because history
/// catch-up replays them. `first_seen_at` is this device's own clock when it
/// first stored the original, which the author cannot influence at all.
///
/// Requiring both means a late rewrite fails even when the author lies about
/// when it happened. The cost is that members can legitimately disagree: one who
/// was offline and receives the line and its edit together accepts the edit,
/// while one who has had the line on screen for an hour refuses it. That is
/// inherent to a room with no arbiter of time, and refusing is the safe side to
/// err on — a member who rejects an edit keeps showing exactly the words that
/// were signed to them.
///
/// `first_seen_at` of 0 means the row predates the column, so only the
/// author-claimed gap is checked; a pre-existing row is not worth refusing an
/// otherwise valid edit over.
pub fn edit_within_window(
    original_timestamp: i64,
    edited_at: i64,
    first_seen_at: i64,
    now: i64,
) -> bool {
    if edited_at < original_timestamp {
        return false;
    }
    if edited_at.saturating_sub(original_timestamp) > CHANNEL_EDIT_WINDOW_SECS {
        return false;
    }
    if first_seen_at > 0 && now.saturating_sub(first_seen_at) > CHANNEL_EDIT_WINDOW_SECS {
        return false;
    }
    true
}

/// What an edit's signature covers.
///
/// Same reasoning as [`chat_sig_preimage`], with the target in place of the
/// line's own id: the room stops the edit being replayed into another room, the
/// target stops it being pointed at another line, the two timestamps stop it
/// being re-dated past the window, and the author key stops anyone else
/// claiming it.
///
/// `original_timestamp` is carried so the frame stands on its own. A member who
/// was away can be handed one edit frame instead of the original line followed
/// by its revision, which halves what a catch-up costs — and, more importantly,
/// means an edited line does not have to keep its pre-edit text on every
/// member's disk just so it can be replayed. Editing out something you regret
/// would be worth very little if the first version were archived everywhere.
///
/// Deliberately *not* bound to the edit frame's own envelope `msg_id`, unlike
/// chat. A re-serve on catch-up has to mint a fresh envelope id for the
/// receiver's duplicate filter, and binding one would make the stored signature
/// unusable for that — while buying nothing, because the only replay this
/// permits is a byte-identical edit, and applying the same revision twice is a
/// no-op under the newer-wins rule.
fn edit_sig_preimage(
    channel_id: &[u8; 16],
    target_msg_id: &[u8; 16],
    original_timestamp: i64,
    edited_at: i64,
    sender_pubkey: &[u8; 32],
    text: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(EDIT_SIG_DOMAIN.len() + 16 + 16 + 8 + 8 + 32 + text.len());
    out.extend_from_slice(EDIT_SIG_DOMAIN);
    out.extend_from_slice(channel_id);
    out.extend_from_slice(target_msg_id);
    out.extend_from_slice(&original_timestamp.to_le_bytes());
    out.extend_from_slice(&edited_at.to_le_bytes());
    out.extend_from_slice(sender_pubkey);
    out.extend_from_slice(text.as_bytes());
    out
}

/// The author's signature over a revision of their own line.
///
/// Kept beside the stored row for the same reason [`chat_author_signature`] is:
/// a catch-up has to put byte-identical bytes back on the wire, and only the
/// author could have produced them.
pub fn edit_author_signature(
    signing_key: &SigningKey,
    sender_pubkey: &[u8; 32],
    channel_id: &[u8; 16],
    target_msg_id: &[u8; 16],
    original_timestamp: i64,
    edited_at: i64,
    text: &str,
) -> [u8; 64] {
    crypto::sign(
        signing_key,
        &edit_sig_preimage(
            channel_id,
            target_msg_id,
            original_timestamp,
            edited_at,
            sender_pubkey,
            text,
        ),
    )
}

/// `version || sender(32) || target(16) || original_ts(8) || edited_at(8) || signature(64) || text`.
///
/// Both timestamps ride in the payload rather than being read from the envelope,
/// so a catch-up can replay the revision under a fresh envelope timestamp
/// without invalidating the signature — the same reason the signature does not
/// bind the envelope id.
pub fn encode_channel_chat_edit_presigned(
    sender_pubkey: &[u8; 32],
    target_msg_id: &[u8; 16],
    original_timestamp: i64,
    edited_at: i64,
    signature: &[u8; 64],
    text: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 16 + 8 + 8 + 64 + text.len());
    out.push(CHAT_EDIT_PLAIN_VERSION);
    out.extend_from_slice(sender_pubkey);
    out.extend_from_slice(target_msg_id);
    out.extend_from_slice(&original_timestamp.to_le_bytes());
    out.extend_from_slice(&edited_at.to_le_bytes());
    out.extend_from_slice(signature);
    out.extend_from_slice(text.as_bytes());
    out
}

/// A revision and who signed it, or nothing if the signature does not hold.
///
/// The caller still has to check that the author matches the *original* line's
/// author and that the window has not closed — this proves only that whoever
/// holds `sender_pubkey` asked for this text on this line at this time.
pub fn decode_channel_chat_edit(bytes: &[u8], channel_id: &[u8; 16]) -> Option<ChannelChatEdit> {
    const HEAD: usize = 1 + 32 + 16 + 8 + 8 + 64;
    if bytes.len() < HEAD || bytes[0] != CHAT_EDIT_PLAIN_VERSION {
        return None;
    }
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&bytes[1..33]);
    let mut target = [0u8; 16];
    target.copy_from_slice(&bytes[33..49]);
    let original_timestamp = i64::from_le_bytes(bytes[49..57].try_into().ok()?);
    let edited_at = i64::from_le_bytes(bytes[57..65].try_into().ok()?);
    let sig: [u8; 64] = bytes[65..HEAD].try_into().ok()?;
    let text = std::str::from_utf8(&bytes[HEAD..]).ok()?.to_string();
    let author = crypto::verifying_key_from_bytes(&sender)?;
    if !crypto::verify(
        &author,
        &edit_sig_preimage(
            channel_id,
            &target,
            original_timestamp,
            edited_at,
            &sender,
            &text,
        ),
        &sig,
    ) {
        return None;
    }
    Some(ChannelChatEdit {
        sender,
        target_msg_id: target,
        original_timestamp,
        edited_at,
        text,
        signature: sig,
    })
}

/// A verified revision of a chat line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelChatEdit {
    pub sender: [u8; 32],
    pub target_msg_id: [u8; 16],
    /// When the line being revised was originally sent. Carried so the frame can
    /// stand in for a line the receiver never saw.
    pub original_timestamp: i64,
    pub edited_at: i64,
    pub text: String,
    pub signature: [u8; 64],
}

/// Reaction values carried on the wire.
///
/// A number rather than a flag pair so a later build can add reactions without
/// another frame version. An unrecognised value is stored and re-served rather
/// than dropped, so a room running a newer build does not lose its reactions
/// every time they pass through this one — this build simply does not draw them.
pub const REACTION_NONE: u8 = 0;
pub const REACTION_UP: u8 = 1;
pub const REACTION_DOWN: u8 = 2;
pub const REACTION_HEART: u8 = 3;

/// Reactions one frame may carry. 121 bytes each, so a full batch is under 4 KiB
/// and stays inside the budget a chat line already occupies.
pub const CHANNEL_REACTION_MAX_PER_FRAME: usize = 32;

/// One member's reaction to one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelReaction {
    pub target_msg_id: [u8; 16],
    pub member: [u8; 32],
    pub reaction: u8,
    pub reacted_at: i64,
    pub signature: [u8; 64],
}

/// What a reaction's signature covers.
///
/// `reacted_at` is in the preimage and in each entry rather than being taken
/// from the envelope, because a batch carries reactions made at different times
/// under one envelope timestamp. It is also what orders competing reactions from
/// the same member, so it has to be something they signed.
fn reaction_sig_preimage(
    channel_id: &[u8; 16],
    target_msg_id: &[u8; 16],
    reacted_at: i64,
    member: &[u8; 32],
    reaction: u8,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(REACTION_SIG_DOMAIN.len() + 16 + 16 + 8 + 32 + 1);
    out.extend_from_slice(REACTION_SIG_DOMAIN);
    out.extend_from_slice(channel_id);
    out.extend_from_slice(target_msg_id);
    out.extend_from_slice(&reacted_at.to_le_bytes());
    out.extend_from_slice(member);
    out.push(reaction);
    out
}

pub fn reaction_signature(
    signing_key: &SigningKey,
    member: &[u8; 32],
    channel_id: &[u8; 16],
    target_msg_id: &[u8; 16],
    reacted_at: i64,
    reaction: u8,
) -> [u8; 64] {
    crypto::sign(
        signing_key,
        &reaction_sig_preimage(channel_id, target_msg_id, reacted_at, member, reaction),
    )
}

/// `version || count(1) || [target(16) || member(32) || reaction(1) || reacted_at(8) || sig(64)]*`.
///
/// Entries past [`CHANNEL_REACTION_MAX_PER_FRAME`] are dropped rather than
/// splitting here: the caller decides how to page a large room's backlog, and a
/// silently oversized frame would be refused by every receiver.
pub fn encode_channel_reactions(entries: &[ChannelReaction]) -> Vec<u8> {
    let take = entries.len().min(CHANNEL_REACTION_MAX_PER_FRAME);
    let mut out = Vec::with_capacity(2 + take * REACTION_ENTRY_LEN);
    out.push(REACTION_PLAIN_VERSION);
    out.push(take as u8);
    for entry in &entries[..take] {
        out.extend_from_slice(&entry.target_msg_id);
        out.extend_from_slice(&entry.member);
        out.push(entry.reaction);
        out.extend_from_slice(&entry.reacted_at.to_le_bytes());
        out.extend_from_slice(&entry.signature);
    }
    out
}

const REACTION_ENTRY_LEN: usize = 16 + 32 + 1 + 8 + 64;

/// Every entry in a reaction frame whose signature holds.
///
/// Entries are verified one at a time and a bad one is skipped rather than
/// failing the frame: a batch is an aggregate of independent claims by different
/// members, so one member's forged entry must not discard everyone else's real
/// ones. Returns `None` only when the frame itself is malformed.
pub fn decode_channel_reactions(
    bytes: &[u8],
    channel_id: &[u8; 16],
) -> Option<Vec<ChannelReaction>> {
    if bytes.len() < 2 || bytes[0] != REACTION_PLAIN_VERSION {
        return None;
    }
    let count = bytes[1] as usize;
    if count == 0 || count > CHANNEL_REACTION_MAX_PER_FRAME {
        return None;
    }
    if bytes.len() != 2 + count * REACTION_ENTRY_LEN {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let at = 2 + i * REACTION_ENTRY_LEN;
        let mut target = [0u8; 16];
        target.copy_from_slice(&bytes[at..at + 16]);
        let mut member = [0u8; 32];
        member.copy_from_slice(&bytes[at + 16..at + 48]);
        let reaction = bytes[at + 48];
        let Ok(ts_bytes) = bytes[at + 49..at + 57].try_into() else {
            continue;
        };
        let reacted_at = i64::from_le_bytes(ts_bytes);
        let Ok(sig) = <[u8; 64]>::try_from(&bytes[at + 57..at + REACTION_ENTRY_LEN]) else {
            continue;
        };
        let Some(author) = crypto::verifying_key_from_bytes(&member) else {
            continue;
        };
        if !crypto::verify(
            &author,
            &reaction_sig_preimage(channel_id, &target, reacted_at, &member, reaction),
            &sig,
        ) {
            continue;
        }
        out.push(ChannelReaction {
            target_msg_id: target,
            member,
            reaction,
            reacted_at,
            signature: sig,
        });
    }
    Some(out)
}

fn mod_action_preimage(
    channel_id: &[u8; 16],
    msg_id: &[u8; 16],
    timestamp: i64,
    sender_pubkey: &[u8; 32],
    target_pubkey: &[u8; 32],
    banned: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(MOD_SIG_DOMAIN.len() + 16 + 16 + 8 + 32 + 1 + 32);
    out.extend_from_slice(MOD_SIG_DOMAIN);
    out.extend_from_slice(channel_id);
    out.extend_from_slice(msg_id);
    out.extend_from_slice(&timestamp.to_le_bytes());
    out.extend_from_slice(sender_pubkey);
    out.push(if banned {
        MOD_ACTION_BAN
    } else {
        MOD_ACTION_UNBAN
    });
    out.extend_from_slice(target_pubkey);
    out
}

/// Moderator gossip: `version || sender || action || target || signature`.
///
/// Signed by the sender's user key and bound to the room, id, and time, for
/// the same reason chat is: every member holds the content key.
pub fn encode_channel_mod_action(
    signing_key: &SigningKey,
    sender_pubkey: &[u8; 32],
    target_pubkey: &[u8; 32],
    banned: bool,
    channel_id: &[u8; 16],
    msg_id: &[u8; 16],
    timestamp: i64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 1 + 32 + 64);
    out.push(MOD_ACTION_PLAIN_VERSION);
    out.extend_from_slice(sender_pubkey);
    out.push(if banned {
        MOD_ACTION_BAN
    } else {
        MOD_ACTION_UNBAN
    });
    out.extend_from_slice(target_pubkey);
    let sig = crypto::sign(
        signing_key,
        &mod_action_preimage(
            channel_id,
            msg_id,
            timestamp,
            sender_pubkey,
            target_pubkey,
            banned,
        ),
    );
    out.extend_from_slice(&sig);
    out
}

pub fn decode_channel_mod_action(
    bytes: &[u8],
    channel_id: &[u8; 16],
    msg_id: &[u8; 16],
    timestamp: i64,
) -> Option<([u8; 32], [u8; 32], bool)> {
    if bytes.len() != 130 || bytes[0] != MOD_ACTION_PLAIN_VERSION {
        return None;
    }
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&bytes[1..33]);
    let banned = match bytes[33] {
        MOD_ACTION_BAN => true,
        MOD_ACTION_UNBAN => false,
        _ => return None,
    };
    let mut target = [0u8; 32];
    target.copy_from_slice(&bytes[34..66]);
    let sig: [u8; 64] = bytes[66..130].try_into().ok()?;
    let author = crypto::verifying_key_from_bytes(&sender)?;
    if !crypto::verify(
        &author,
        &mod_action_preimage(channel_id, msg_id, timestamp, &sender, &target, banned),
        &sig,
    ) {
        return None;
    }
    Some((sender, target, banned))
}

fn sync_request_preimage(
    channel_id: &[u8; 16],
    msg_id: &[u8; 16],
    timestamp: i64,
    sender_pubkey: &[u8; 32],
    since_ts: i64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SYNC_SIG_DOMAIN.len() + 16 + 16 + 8 + 32 + 8);
    out.extend_from_slice(SYNC_SIG_DOMAIN);
    out.extend_from_slice(channel_id);
    out.extend_from_slice(msg_id);
    out.extend_from_slice(&timestamp.to_le_bytes());
    out.extend_from_slice(sender_pubkey);
    out.extend_from_slice(&since_ts.to_le_bytes());
    out
}

pub fn encode_channel_sync_request(
    signing_key: &SigningKey,
    sender_pubkey: &[u8; 32],
    channel_id: &[u8; 16],
    msg_id: &[u8; 16],
    timestamp: i64,
    since_ts: i64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 8 + 64);
    out.push(SYNC_REQUEST_PLAIN_VERSION);
    out.extend_from_slice(sender_pubkey);
    out.extend_from_slice(&since_ts.to_le_bytes());
    let sig = crypto::sign(
        signing_key,
        &sync_request_preimage(channel_id, msg_id, timestamp, sender_pubkey, since_ts),
    );
    out.extend_from_slice(&sig);
    out
}

pub fn decode_channel_sync_request(
    bytes: &[u8],
    channel_id: &[u8; 16],
    msg_id: &[u8; 16],
    timestamp: i64,
) -> Option<([u8; 32], i64)> {
    if bytes.len() != 105 || bytes[0] != SYNC_REQUEST_PLAIN_VERSION {
        return None;
    }
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&bytes[1..33]);
    let since_ts = i64::from_le_bytes(bytes[33..41].try_into().ok()?);
    let sig: [u8; 64] = bytes[41..105].try_into().ok()?;
    let author = crypto::verifying_key_from_bytes(&sender)?;
    if !crypto::verify(
        &author,
        &sync_request_preimage(channel_id, msg_id, timestamp, &sender, since_ts),
        &sig,
    ) {
        return None;
    }
    Some((sender, since_ts))
}

/// Why a transfer offer was refused, or that it was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XferReply {
    Accept,
    Decline,
    /// The recipient already has as many transfers running as it will take.
    Busy,
    /// Over [`XFER_MAX_BYTES`], or over whatever the recipient will accept.
    TooLarge,
    /// Refused by the recipient's "who may offer me files" setting.
    NotAllowed,
}

impl XferReply {
    fn code(self) -> u8 {
        match self {
            Self::Accept => 0,
            Self::Decline => 1,
            Self::Busy => 2,
            Self::TooLarge => 3,
            Self::NotAllowed => 4,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Accept,
            1 => Self::Decline,
            2 => Self::Busy,
            3 => Self::TooLarge,
            4 => Self::NotAllowed,
            _ => return None,
        })
    }

    /// The status the UI shows for this answer. Kept in step with the
    /// `ChannelTransferStatus` union in `src/lib/api/channels.ts`; a value
    /// that has no case there renders as a bare "failed".
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accepted",
            Self::Decline => "declined",
            Self::Busy => "busy",
            Self::TooLarge => "too_large",
            Self::NotAllowed => "not_allowed",
        }
    }
}

/// Why a transfer stopped early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XferCancel {
    /// Either side pressed cancel.
    User,
    /// The sender can no longer read the file it offered.
    SourceGone,
    /// No progress for [`XFER_STALL_SECS`].
    Stalled,
}

impl XferCancel {
    fn code(self) -> u8 {
        match self {
            Self::User => 0,
            Self::SourceGone => 1,
            Self::Stalled => 2,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::User,
            1 => Self::SourceGone,
            2 => Self::Stalled,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "cancelled",
            Self::SourceGone => "source_gone",
            Self::Stalled => "stalled",
        }
    }
}

/// Every transfer frame names both ends: `sender(32) || target(32) ||
/// xfer_id(16)` after the version byte.
///
/// The target is on the wire even though these are unicast, because the
/// channel relay can hand a frame to a member it merely forwards for. A
/// member that is not the target drops the frame instead of acting on it.
///
/// `sender` is backed by the authenticator every frame carries — see
/// [`derive_xfer_key`]. A room member cannot put another member's name on a
/// transfer frame, which is a stronger guarantee than the chat sharing the
/// room gets.
const XFER_HEADER_LEN: usize = 1 + 32 + 32 + 16;

/// Key authenticating every transfer frame between one pair of members.
///
/// The room's content key is held by *every* member, so on its own it proves
/// only that a frame came from someone in the room — any of them could put
/// another member's key in the `sender` field, exactly as they can forge the
/// author of a chat line. That is tolerable for chat and not for transfers: a
/// forged offer would put a trusted member's name on a prompt for a file they
/// never sent.
///
/// So each frame also carries a tag under a key only the two ends can compute:
/// static X25519 Diffie-Hellman between their Ed25519 identities, which the
/// room's presence records already publish. `derive_pairwise_capability` sorts
/// the two public keys, so both sides arrive at the same value without any
/// handshake, and the purpose binds the room and the transfer so a frame
/// cannot be lifted into a different one. The `target` field is inside the
/// authenticated bytes, so a frame cannot be reflected back at its sender
/// either.
///
/// Symmetric rather than a signature because it is a quarter the size, and
/// the 64 bytes an Ed25519 signature costs would push a block frame past the
/// unfragmented datagram budget. Nothing here needs to be provable to a third
/// party — only unforgeable by one.
pub fn derive_xfer_key(
    our_ed25519_seed: &[u8; 32],
    peer_ed25519_pubkey: &[u8; 32],
    channel_id: &[u8; 16],
    xfer_id: &[u8; 16],
) -> Option<[u8; 32]> {
    // Pairwise purpose is capped at 64 bytes; this is 42.
    let mut purpose = Vec::with_capacity(10 + 16 + 16);
    purpose.extend_from_slice(b"ch-xfer-v1");
    purpose.extend_from_slice(channel_id);
    purpose.extend_from_slice(xfer_id);
    // Epoch 0: a transfer is short-lived and already bound to its own id, so
    // it wants a key stable for its lifetime rather than one that rotates
    // underneath it mid-file.
    crypto::derive_pairwise_capability(our_ed25519_seed, peer_ed25519_pubkey, &purpose, 0)
}

const XFER_BLOCK_STREAM_DOMAIN: &[u8] = b"ember-channel-xfer-block-v1\0";

/// XOR a block's payload with a keystream only the two ends can produce.
///
/// Symmetric, so one function both seals and opens. Keyed BLAKE3 in XOF mode is
/// a PRF, so `(xfer_id, offset)` selects an independent stream per block with no
/// nonce on the wire — which is what lets a sealed frame be exactly the size the
/// cleartext one was, and keeps the unfragmented-datagram budget as it was.
///
/// A retransmitted block reuses its stream, which is harmless: it carries the
/// same file bytes. The case that is not harmless is a file edited underneath a
/// transfer already in flight, where the same offset would carry two different
/// plaintexts under one stream and an observer holding both frames learns their
/// XOR. Such a transfer already fails the root hash it was offered under, and
/// the alternative — a per-block nonce — costs headroom this frame does not
/// have.
fn xfer_block_stream_xor(key: &[u8; 32], xfer_id: &[u8; 16], offset: u64, data: &mut [u8]) {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(XFER_BLOCK_STREAM_DOMAIN);
    hasher.update(xfer_id);
    hasher.update(&offset.to_le_bytes());
    let mut stream = [0u8; XFER_BLOCK_SIZE];
    let stream = &mut stream[..data.len().min(XFER_BLOCK_SIZE)];
    hasher.finalize_xof().fill(stream);
    for (byte, pad) in data.iter_mut().zip(stream.iter()) {
        *byte ^= *pad;
    }
}

fn xfer_tag(key: &[u8; 32], body: &[u8]) -> [u8; XFER_MAC_LEN] {
    let full = blake3::keyed_hash(key, body);
    let mut tag = [0u8; XFER_MAC_LEN];
    tag.copy_from_slice(&full.as_bytes()[..XFER_MAC_LEN]);
    tag
}

fn append_xfer_tag(key: &[u8; 32], out: &mut Vec<u8>) {
    let tag = xfer_tag(key, out);
    out.extend_from_slice(&tag);
}

/// Read a transfer frame's header without checking it.
///
/// Deliberately unauthenticated: the key needed to verify the frame is derived
/// from the very fields this returns. Callers use it to work out *which* key
/// to derive and must then call [`xfer_verify`] before believing any of it.
pub fn xfer_frame_peek(bytes: &[u8]) -> Option<([u8; 32], [u8; 32], [u8; 16])> {
    if bytes.len() < XFER_HEADER_LEN + XFER_MAC_LEN {
        return None;
    }
    if !matches!(
        bytes[0],
        XFER_OFFER_PLAIN_VERSION
            | XFER_REPLY_PLAIN_VERSION
            | XFER_BLOCK_REQUEST_PLAIN_VERSION
            | XFER_BLOCK_DATA_SEALED_VERSION
            | XFER_CANCEL_PLAIN_VERSION
            | XFER_DONE_PLAIN_VERSION
    ) {
        return None;
    }
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&bytes[1..33]);
    let mut target = [0u8; 32];
    target.copy_from_slice(&bytes[33..65]);
    let mut xfer_id = [0u8; 16];
    xfer_id.copy_from_slice(&bytes[65..81]);
    Some((sender, target, xfer_id))
}

/// Check the authenticator and hand back the frame body without it.
pub fn xfer_verify<'a>(key: &[u8; 32], bytes: &'a [u8]) -> Option<&'a [u8]> {
    if bytes.len() < XFER_HEADER_LEN + XFER_MAC_LEN {
        return None;
    }
    let (body, tag) = bytes.split_at(bytes.len() - XFER_MAC_LEN);
    let expected = xfer_tag(key, body);
    // Constant-time: a byte-at-a-time compare would leak how much of a guess
    // was right, which is the one thing that turns forging a 128-bit tag from
    // hopeless into merely expensive.
    let mut diff = 0u8;
    for (a, b) in tag.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    if diff == 0 {
        Some(body)
    } else {
        None
    }
}

fn put_xfer_header(out: &mut Vec<u8>, version: u8, sender: &[u8; 32], target: &[u8; 32], xfer_id: &[u8; 16]) {
    out.push(version);
    out.extend_from_slice(sender);
    out.extend_from_slice(target);
    out.extend_from_slice(xfer_id);
}

fn take_xfer_header(bytes: &[u8], version: u8) -> Option<([u8; 32], [u8; 32], [u8; 16])> {
    if bytes.len() < XFER_HEADER_LEN || bytes[0] != version {
        return None;
    }
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&bytes[1..33]);
    let mut target = [0u8; 32];
    target.copy_from_slice(&bytes[33..65]);
    let mut xfer_id = [0u8; 16];
    xfer_id.copy_from_slice(&bytes[65..81]);
    Some((sender, target, xfer_id))
}

/// What one member proposes to send another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XferOffer {
    pub sender: [u8; 32],
    pub target: [u8; 32],
    pub xfer_id: [u8; 16],
    pub size: u64,
    /// `HashTree` root over the file, which is also the Ember file hash.
    pub root: [u8; 32],
    pub name: String,
}

/// `hdr || size(8) || root(32) || name || tag(16)`.
pub fn encode_xfer_offer(key: &[u8; 32], offer: &XferOffer) -> Vec<u8> {
    let name = truncate_utf8_owned(&offer.name, XFER_NAME_MAX);
    let mut out = Vec::with_capacity(XFER_HEADER_LEN + 8 + 32 + name.len() + XFER_MAC_LEN);
    put_xfer_header(
        &mut out,
        XFER_OFFER_PLAIN_VERSION,
        &offer.sender,
        &offer.target,
        &offer.xfer_id,
    );
    out.extend_from_slice(&offer.size.to_le_bytes());
    out.extend_from_slice(&offer.root);
    out.extend_from_slice(name.as_bytes());
    append_xfer_tag(key, &mut out);
    out
}

pub fn decode_xfer_offer(bytes: &[u8]) -> Option<XferOffer> {
    let (sender, target, xfer_id) = take_xfer_header(bytes, XFER_OFFER_PLAIN_VERSION)?;
    let rest = bytes.get(XFER_HEADER_LEN..)?;
    if rest.len() < 8 + 32 {
        return None;
    }
    let size = u64::from_le_bytes(rest[..8].try_into().ok()?);
    if size == 0 || size > XFER_MAX_BYTES {
        return None;
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&rest[8..40]);
    let name_bytes = &rest[40..];
    if name_bytes.is_empty() || name_bytes.len() > XFER_NAME_MAX {
        return None;
    }
    let name = std::str::from_utf8(name_bytes).ok()?.to_string();
    Some(XferOffer {
        sender,
        target,
        xfer_id,
        size,
        root,
        name,
    })
}

/// `hdr || status(1) || tag(16)`.
pub fn encode_xfer_reply(
    key: &[u8; 32],
    sender: &[u8; 32],
    target: &[u8; 32],
    xfer_id: &[u8; 16],
    reply: XferReply,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(XFER_HEADER_LEN + 1 + XFER_MAC_LEN);
    put_xfer_header(&mut out, XFER_REPLY_PLAIN_VERSION, sender, target, xfer_id);
    out.push(reply.code());
    append_xfer_tag(key, &mut out);
    out
}

pub fn decode_xfer_reply(bytes: &[u8]) -> Option<([u8; 32], [u8; 32], [u8; 16], XferReply)> {
    let (sender, target, xfer_id) = take_xfer_header(bytes, XFER_REPLY_PLAIN_VERSION)?;
    if bytes.len() != XFER_HEADER_LEN + 1 {
        return None;
    }
    let reply = XferReply::from_code(bytes[XFER_HEADER_LEN])?;
    Some((sender, target, xfer_id, reply))
}

/// `hdr || offset(8) || count(2)` — `count` consecutive blocks from `offset`.
///
/// Receiver-driven on purpose. The sender only ever answers a request, so it
/// cannot run ahead of what the other side can absorb, and a block that goes
/// missing is simply asked for again rather than lost for good.
pub fn encode_xfer_block_request(
    key: &[u8; 32],
    sender: &[u8; 32],
    target: &[u8; 32],
    xfer_id: &[u8; 16],
    offset: u64,
    count: u16,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(XFER_HEADER_LEN + 8 + 2 + XFER_MAC_LEN);
    put_xfer_header(
        &mut out,
        XFER_BLOCK_REQUEST_PLAIN_VERSION,
        sender,
        target,
        xfer_id,
    );
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    append_xfer_tag(key, &mut out);
    out
}

pub fn decode_xfer_block_request(
    bytes: &[u8],
) -> Option<([u8; 32], [u8; 32], [u8; 16], u64, u16)> {
    let (sender, target, xfer_id) =
        take_xfer_header(bytes, XFER_BLOCK_REQUEST_PLAIN_VERSION)?;
    if bytes.len() != XFER_HEADER_LEN + 8 + 2 {
        return None;
    }
    let offset = u64::from_le_bytes(bytes[XFER_HEADER_LEN..XFER_HEADER_LEN + 8].try_into().ok()?);
    let count = u16::from_le_bytes(
        bytes[XFER_HEADER_LEN + 8..XFER_HEADER_LEN + 10]
            .try_into()
            .ok()?,
    );
    if count == 0 || count as usize > XFER_WINDOW_BLOCKS {
        return None;
    }
    Some((sender, target, xfer_id, offset, count))
}

/// `hdr || offset(8) || sealed(data) || tag(16)`.
///
/// The payload is encrypted to the recipient, not merely authenticated to them.
/// The gossip envelope carrying it is sealed with the *room's* content key,
/// which every member holds — and which, for a public room, is derived straight
/// from the channel pubkey that sits in the public index and in every invite. So
/// a block "sent to one member" was readable by every member of a private room,
/// and by any stranger who could find a public one, while the UI presented it as
/// a file going to one person.
///
/// Same length on the wire as the cleartext frame it replaces, so the
/// unfragmented-datagram budget is unchanged.
///
/// Block data is authenticated like everything else rather than leaning on
/// the whole-file hash at the end. That check would catch injected bytes, but
/// only after the last block, and the answer would be to discard the entire
/// file — so an unauthenticated stream hands any room member a cheap way to
/// make every transfer fail.
pub fn encode_xfer_block_data(
    key: &[u8; 32],
    sender: &[u8; 32],
    target: &[u8; 32],
    xfer_id: &[u8; 16],
    offset: u64,
    data: &[u8],
) -> Option<Vec<u8>> {
    if data.is_empty() || data.len() > XFER_BLOCK_SIZE {
        return None;
    }
    let mut out = Vec::with_capacity(XFER_HEADER_LEN + 8 + data.len() + XFER_MAC_LEN);
    put_xfer_header(
        &mut out,
        XFER_BLOCK_DATA_SEALED_VERSION,
        sender,
        target,
        xfer_id,
    );
    out.extend_from_slice(&offset.to_le_bytes());
    let payload = out.len();
    out.extend_from_slice(data);
    xfer_block_stream_xor(key, xfer_id, offset, &mut out[payload..]);
    // Encrypt then MAC: the tag still covers the header, the offset and now the
    // ciphertext, so sender, target, transfer and position stay bound exactly as
    // they were.
    append_xfer_tag(key, &mut out);
    Some(out)
}

/// Open a block. Call only on a frame [`xfer_verify`] has already accepted —
/// decrypting first would be decrypting whatever a stranger sent.
pub fn decode_xfer_block_data(
    key: &[u8; 32],
    bytes: &[u8],
) -> Option<([u8; 32], [u8; 32], [u8; 16], u64, Vec<u8>)> {
    let (sender, target, xfer_id) = take_xfer_header(bytes, XFER_BLOCK_DATA_SEALED_VERSION)?;
    let rest = bytes.get(XFER_HEADER_LEN..)?;
    if rest.len() < 8 + 1 {
        return None;
    }
    let offset = u64::from_le_bytes(rest[..8].try_into().ok()?);
    if rest.len() - 8 > XFER_BLOCK_SIZE {
        return None;
    }
    let mut data = rest[8..].to_vec();
    xfer_block_stream_xor(key, &xfer_id, offset, &mut data);
    Some((sender, target, xfer_id, offset, data))
}

/// `hdr || reason(1) || tag(16)`.
pub fn encode_xfer_cancel(
    key: &[u8; 32],
    sender: &[u8; 32],
    target: &[u8; 32],
    xfer_id: &[u8; 16],
    reason: XferCancel,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(XFER_HEADER_LEN + 1 + XFER_MAC_LEN);
    put_xfer_header(&mut out, XFER_CANCEL_PLAIN_VERSION, sender, target, xfer_id);
    out.push(reason.code());
    append_xfer_tag(key, &mut out);
    out
}

pub fn decode_xfer_cancel(bytes: &[u8]) -> Option<([u8; 32], [u8; 32], [u8; 16], XferCancel)> {
    let (sender, target, xfer_id) = take_xfer_header(bytes, XFER_CANCEL_PLAIN_VERSION)?;
    if bytes.len() != XFER_HEADER_LEN + 1 {
        return None;
    }
    let reason = XferCancel::from_code(bytes[XFER_HEADER_LEN])?;
    Some((sender, target, xfer_id, reason))
}

/// `hdr` only — "I have the whole file, and it matched."
///
/// Without this the sender has no way to learn it is finished: it answers
/// requests and never hears anything again, so its own stall timer would
/// eventually fire and report a successful transfer as a failure.
pub fn encode_xfer_done(
    key: &[u8; 32],
    sender: &[u8; 32],
    target: &[u8; 32],
    xfer_id: &[u8; 16],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(XFER_HEADER_LEN + XFER_MAC_LEN);
    put_xfer_header(&mut out, XFER_DONE_PLAIN_VERSION, sender, target, xfer_id);
    append_xfer_tag(key, &mut out);
    out
}

pub fn decode_xfer_done(bytes: &[u8]) -> Option<([u8; 32], [u8; 32], [u8; 16])> {
    let parsed = take_xfer_header(bytes, XFER_DONE_PLAIN_VERSION)?;
    if bytes.len() != XFER_HEADER_LEN {
        return None;
    }
    Some(parsed)
}

/// Total blocks a file of `size` bytes is cut into.
pub fn xfer_block_count(size: u64) -> u64 {
    size.div_ceil(XFER_BLOCK_SIZE as u64)
}

/// Offer signed by the **old channel key**, not the owner's user key.
/// Members share the content key, so an unsigned inner sender field is not
/// proof of ownership.
pub fn encode_channel_handoff_offer(
    channel_id: &[u8; 16],
    signing_key: &SigningKey,
    sender_pubkey: &[u8; 32],
    target_pubkey: &[u8; 32],
    version: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 32 + 8 + 64);
    out.push(HANDOFF_OFFER_PLAIN_VERSION);
    out.extend_from_slice(sender_pubkey);
    out.extend_from_slice(target_pubkey);
    out.extend_from_slice(&version.to_le_bytes());
    let sig = crypto::sign(
        signing_key,
        &handoff_offer_preimage(channel_id, sender_pubkey, target_pubkey, version),
    );
    out.extend_from_slice(&sig);
    out
}

pub fn decode_channel_handoff_offer(
    bytes: &[u8],
    channel_id: &[u8; 16],
    channel_pubkey: &[u8; 32],
) -> Option<([u8; 32], [u8; 32], u64)> {
    if bytes.len() != 137 || bytes[0] != HANDOFF_OFFER_PLAIN_VERSION {
        return None;
    }
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&bytes[1..33]);
    let mut target = [0u8; 32];
    target.copy_from_slice(&bytes[33..65]);
    let version = u64::from_le_bytes(bytes[65..73].try_into().ok()?);
    let sig: [u8; 64] = bytes[73..137].try_into().ok()?;
    let vk = crypto::verifying_key_from_bytes(channel_pubkey)?;
    if !crypto::verify(
        &vk,
        &handoff_offer_preimage(channel_id, &sender, &target, version),
        &sig,
    ) {
        return None;
    }
    Some((sender, target, version))
}

fn handoff_offer_preimage(
    channel_id: &[u8; 16],
    sender_pubkey: &[u8; 32],
    target_pubkey: &[u8; 32],
    version: u64,
) -> Vec<u8> {
    let mut pre = Vec::with_capacity(HANDOFF_OFFER_DOMAIN.len() + 16 + 32 + 32 + 8);
    pre.extend_from_slice(HANDOFF_OFFER_DOMAIN);
    pre.extend_from_slice(channel_id);
    pre.extend_from_slice(sender_pubkey);
    pre.extend_from_slice(target_pubkey);
    pre.extend_from_slice(&version.to_le_bytes());
    pre
}

fn handoff_ready_preimage(
    channel_id: &[u8; 16],
    sender_pubkey: &[u8; 32],
    successor_pubkey: &[u8; 32],
    version: u64,
) -> Vec<u8> {
    let mut pre = Vec::with_capacity(HANDOFF_READY_DOMAIN.len() + 16 + 32 + 32 + 8);
    pre.extend_from_slice(HANDOFF_READY_DOMAIN);
    pre.extend_from_slice(channel_id);
    pre.extend_from_slice(sender_pubkey);
    pre.extend_from_slice(successor_pubkey);
    pre.extend_from_slice(&version.to_le_bytes());
    pre
}

/// Ready signed by the **nominee's user key**, bound to this room and version.
///
/// The matching offer is signed by the channel key. Ready was unsigned, so
/// anyone who saw the flooded offer could impersonate the nominee and name
/// their own successor. The owner checks this signature against the pending
/// target before publishing a DHT handoff.
pub fn encode_channel_handoff_ready(
    signing_key: &SigningKey,
    channel_id: &[u8; 16],
    sender_pubkey: &[u8; 32],
    successor_pubkey: &[u8; 32],
    version: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 32 + 8 + 64);
    out.push(HANDOFF_READY_PLAIN_VERSION);
    out.extend_from_slice(sender_pubkey);
    out.extend_from_slice(successor_pubkey);
    out.extend_from_slice(&version.to_le_bytes());
    let sig = crypto::sign(
        signing_key,
        &handoff_ready_preimage(channel_id, sender_pubkey, successor_pubkey, version),
    );
    out.extend_from_slice(&sig);
    out
}

pub fn decode_channel_handoff_ready(
    bytes: &[u8],
    channel_id: &[u8; 16],
) -> Option<([u8; 32], [u8; 32], u64)> {
    if bytes.len() != 137 || bytes[0] != HANDOFF_READY_PLAIN_VERSION {
        return None;
    }
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&bytes[1..33]);
    let mut successor = [0u8; 32];
    successor.copy_from_slice(&bytes[33..65]);
    let version = u64::from_le_bytes(bytes[65..73].try_into().ok()?);
    let sig: [u8; 64] = bytes[73..137].try_into().ok()?;
    let vk = crypto::verifying_key_from_bytes(&sender)?;
    if !crypto::verify(
        &vk,
        &handoff_ready_preimage(channel_id, &sender, &successor, version),
        &sig,
    ) {
        return None;
    }
    Some((sender, successor, version))
}

/// Extra blob for a DHT handoff record: version, successor pubkey/id, flags.
pub fn encode_handoff_extra(
    version: u64,
    successor_pubkey: &[u8; 32],
    flags: u8,
) -> Vec<u8> {
    let successor_id = channel_id_from_pubkey(successor_pubkey);
    let mut extra = Vec::with_capacity(8 + 32 + 16 + 1);
    extra.extend_from_slice(&version.to_le_bytes());
    extra.extend_from_slice(successor_pubkey);
    extra.extend_from_slice(&successor_id);
    extra.push(flags);
    extra
}

pub fn decode_handoff_extra(extra: &[u8]) -> Option<(u64, [u8; 32], [u8; 16], u8)> {
    if extra.len() != 8 + 32 + 16 + 1 {
        return None;
    }
    let version = u64::from_le_bytes(extra[0..8].try_into().ok()?);
    let mut successor_pubkey = [0u8; 32];
    successor_pubkey.copy_from_slice(&extra[8..40]);
    let mut successor_id = [0u8; 16];
    successor_id.copy_from_slice(&extra[40..56]);
    if channel_id_from_pubkey(&successor_pubkey) != successor_id {
        return None;
    }
    Some((version, successor_pubkey, successor_id, extra[56]))
}

fn truncate_utf8_owned(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

const CHANNEL_RELAY_ENVELOPE_VERSION: u8 = 1;
/// `version(1) + channel_id(16) + target_id(16)` before the inner gossip body.
pub const CHANNEL_RELAY_ENVELOPE_HEADER: usize = 1 + 16 + 16;

/// Overlay-buddy relay envelope. The hop cannot decrypt `inner` (AEAD).
pub fn encode_channel_relay_envelope(
    channel_id: &[u8; 16],
    target_id: &[u8; 16],
    inner: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(CHANNEL_RELAY_ENVELOPE_HEADER + inner.len());
    out.push(CHANNEL_RELAY_ENVELOPE_VERSION);
    out.extend_from_slice(channel_id);
    out.extend_from_slice(target_id);
    out.extend_from_slice(inner);
    out
}

pub fn decode_channel_relay_envelope(bytes: &[u8]) -> Option<([u8; 16], [u8; 16], &[u8])> {
    if bytes.len() <= CHANNEL_RELAY_ENVELOPE_HEADER || bytes[0] != CHANNEL_RELAY_ENVELOPE_VERSION {
        return None;
    }
    let mut channel_id = [0u8; 16];
    channel_id.copy_from_slice(&bytes[1..17]);
    let mut target_id = [0u8; 16];
    target_id.copy_from_slice(&bytes[17..33]);
    Some((channel_id, target_id, &bytes[33..]))
}

/// Sliding-window admit: true if `now` can be recorded without exceeding
/// `limit` events in `window`.
pub fn rate_window_allow(
    times: &mut VecDeque<Instant>,
    now: Instant,
    window: Duration,
    limit: usize,
) -> bool {
    while times
        .front()
        .is_some_and(|t| now.saturating_duration_since(*t) > window)
    {
        times.pop_front();
    }
    if times.len() >= limit {
        return false;
    }
    times.push_back(now);
    true
}

/// Admit one chat message from `author` in `channel_id`, or refuse it as a
/// flood. Keyed on the room as well as the author so a member who is noisy in
/// one room is not throttled in another.
///
/// Refuses outright once `CHANNEL_GOSSIP_AUTHOR_CAP` other pairs are tracked:
/// the map is the only thing standing between a stream of invented authors and
/// unbounded growth, and an admitted-but-untracked message would let exactly
/// that stream past.
pub fn author_gossip_allow(
    seen: &mut HashMap<([u8; 16], [u8; 32]), VecDeque<Instant>>,
    channel_id: [u8; 16],
    author: &[u8; 32],
    now: Instant,
) -> bool {
    let key = (channel_id, *author);
    if seen.len() >= CHANNEL_GOSSIP_AUTHOR_CAP && !seen.contains_key(&key) {
        return false;
    }
    let times = seen.entry(key).or_default();
    rate_window_allow(
        times,
        now,
        Duration::from_secs(1),
        CHANNEL_GOSSIP_PER_AUTHOR_PER_SEC,
    )
}

/// Admit one history-sync request from `author` in `channel_id`, or refuse it.
///
/// Deliberately its own budget rather than sharing the chat one. Answering a
/// catch-up is the most expensive thing an unproven peer can ask us to do, and
/// the honest rate is one request per room every few minutes, so the two are
/// nowhere near each other. Shares the cap and the refuse-when-full rule with
/// [`author_gossip_allow`] for the same reason: an untracked requester waved
/// through is exactly the stream of invented identities the cap exists to stop.
pub fn history_sync_allow(
    seen: &mut HashMap<([u8; 16], [u8; 32]), VecDeque<Instant>>,
    channel_id: [u8; 16],
    author: &[u8; 32],
    now: Instant,
) -> bool {
    let key = (channel_id, *author);
    if seen.len() >= CHANNEL_GOSSIP_AUTHOR_CAP && !seen.contains_key(&key) {
        return false;
    }
    let times = seen.entry(key).or_default();
    rate_window_allow(
        times,
        now,
        Duration::from_secs(60),
        CHANNEL_HISTORY_SYNC_PER_MIN,
    )
}

/// Drop rate-window tracking for keys with no activity inside `window`, so a
/// long session does not hold a slot for everyone who ever spoke.
///
/// Generic over the key because all three inbound budgets need it and each is
/// keyed differently — chat and catch-up by `(room, author)`, hop admission by
/// node id. The hop map is the one that most needs sweeping: it refuses any
/// newcomer once [`CHANNEL_GOSSIP_IN_PEER_CAP`] slots are taken, so without a
/// sweep a long session eventually stops accepting channel traffic from anyone
/// it has not already spoken to.
pub fn prune_rate_windows<K: Eq + std::hash::Hash>(
    seen: &mut HashMap<K, VecDeque<Instant>>,
    now: Instant,
    window: Duration,
) {
    seen.retain(|_, times| {
        times
            .back()
            .is_some_and(|t| now.saturating_duration_since(*t) <= window)
    });
}

/// Storers cannot decrypt a private extra; they only check the length so a
/// truncated or obviously-junk blob is dropped.
pub fn presence_extra_store_ok(extra: &[u8]) -> bool {
    extra.len() == 32
        || (extra.first() == Some(&PRESENCE_EXTRA_ENC_VERSION)
            && extra.len() == PRESENCE_EXTRA_ENC_LEN)
}

/// Public rooms keep nickname in `file_name` and Noise pub as 32 raw extra
/// bytes (legacy). Private rooms leave `file_name` empty and seal both under
/// the content key so a storer cannot read membership metadata.
pub fn encode_presence_extra(
    private: bool,
    content_key: &[u8; 32],
    channel_id: &[u8; 16],
    noise_pub: &[u8; 32],
    nickname: &str,
) -> (String, Vec<u8>) {
    let nick = truncate_nickname(nickname);
    if !private {
        return (nick, noise_pub.to_vec());
    }
    let mut plain = vec![0u8; 32 + 1 + PRESENCE_NICK_PAD];
    plain[..32].copy_from_slice(noise_pub);
    let nick_bytes = nick.as_bytes();
    plain[32] = nick_bytes.len() as u8;
    plain[33..33 + nick_bytes.len()].copy_from_slice(nick_bytes);
    (
        String::new(),
        seal_presence_extra(content_key, channel_id, &plain),
    )
}

pub fn decode_presence_extra(
    content_key: Option<&[u8; 32]>,
    channel_id: &[u8; 16],
    extra: &[u8],
    file_name: &str,
) -> Option<([u8; 32], String)> {
    if extra.len() == 32 {
        let mut noise = [0u8; 32];
        noise.copy_from_slice(extra);
        return Some((noise, file_name.to_string()));
    }
    let key = content_key?;
    let plain = open_presence_extra(key, channel_id, extra)?;
    if plain.len() != 32 + 1 + PRESENCE_NICK_PAD {
        return None;
    }
    let mut noise = [0u8; 32];
    noise.copy_from_slice(&plain[..32]);
    let nick_len = plain[32] as usize;
    if nick_len > PRESENCE_NICK_PAD {
        return None;
    }
    let nick = std::str::from_utf8(&plain[33..33 + nick_len])
        .ok()?
        .to_string();
    Some((noise, nick))
}

fn truncate_nickname(s: &str) -> String {
    if s.len() <= PRESENCE_NICK_PAD {
        return s.to_string();
    }
    let mut end = PRESENCE_NICK_PAD;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn presence_extra_aad(channel_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(PRESENCE_EXTRA_AAD.len() + 16);
    aad.extend_from_slice(PRESENCE_EXTRA_AAD);
    aad.extend_from_slice(channel_id);
    aad
}

fn seal_presence_extra(key: &[u8; 32], channel_id: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
    let mut nonce = [0u8; GOSSIP_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let encrypted = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &presence_extra_aad(channel_id),
            },
        )
        .expect("XChaCha20-Poly1305 encryption cannot fail for presence extra");
    let mut out = Vec::with_capacity(1 + GOSSIP_NONCE_LEN + encrypted.len());
    out.push(PRESENCE_EXTRA_ENC_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&encrypted);
    out
}

fn open_presence_extra(key: &[u8; 32], channel_id: &[u8; 16], extra: &[u8]) -> Option<Vec<u8>> {
    if extra.len() != PRESENCE_EXTRA_ENC_LEN || extra[0] != PRESENCE_EXTRA_ENC_VERSION {
        return None;
    }
    let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(&extra[1..1 + GOSSIP_NONCE_LEN]),
            Payload {
                msg: &extra[1 + GOSSIP_NONCE_LEN..],
                aad: &presence_extra_aad(channel_id),
            },
        )
        .ok()
}

/// Record `msg_id` in the flood seen-set. Returns `true` the first time
/// this id is observed; later copies are dropped so a cycle cannot loop.
pub fn remember_gossip_id(
    seen: &mut HashMap<[u8; 16], Instant>,
    order: &mut VecDeque<[u8; 16]>,
    cap: usize,
    msg_id: [u8; 16],
    now: Instant,
) -> bool {
    if seen.contains_key(&msg_id) {
        return false;
    }
    while order.len() >= cap {
        if let Some(old) = order.pop_front() {
            seen.remove(&old);
        } else {
            break;
        }
    }
    seen.insert(msg_id, now);
    order.push_back(msg_id);
    true
}

/// Undo a [`remember_gossip_id`] for a message refused on grounds that may not
/// hold next time — a rate limit rather than a validity failure.
///
/// Dedup runs before the body can even be decrypted, so a message refused
/// later in the pipeline has already spent its id. Left spent, every retransmit
/// is mistaken for a flood cycle and the message is lost on this node for good;
/// a legitimate burst is exactly the case that produces one.
pub fn forget_gossip_id(
    seen: &mut HashMap<[u8; 16], Instant>,
    order: &mut VecDeque<[u8; 16]>,
    msg_id: &[u8; 16],
) {
    if seen.remove(msg_id).is_none() {
        return;
    }
    if let Some(pos) = order.iter().rposition(|id| id == msg_id) {
        order.remove(pos);
    }
}

impl ChannelGossip {
    pub fn new_plaintext(
        channel_id: [u8; 16],
        content_key: &[u8; 32],
        sender_counter: u64,
        plaintext: &[u8],
        ttl: u8,
    ) -> Self {
        let mut msg_id = [0u8; 16];
        OsRng.fill_bytes(&mut msg_id);
        Self::sealed(
            channel_id,
            msg_id,
            content_key,
            sender_counter,
            plaintext,
            ttl,
            chrono::Utc::now().timestamp(),
        )
    }

    pub fn sealed(
        channel_id: [u8; 16],
        msg_id: [u8; 16],
        content_key: &[u8; 32],
        sender_counter: u64,
        plaintext: &[u8],
        ttl: u8,
        timestamp: i64,
    ) -> Self {
        let ciphertext = encrypt_gossip_body(
            content_key,
            &channel_id,
            &msg_id,
            sender_counter,
            timestamp,
            plaintext,
        );
        Self {
            channel_id,
            msg_id,
            ttl,
            timestamp,
            sender_counter,
            ciphertext,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(GOSSIP_HEADER_LEN + self.ciphertext.len());
        buf.push(CHANNEL_MSG_VERSION);
        buf.extend_from_slice(&self.channel_id);
        buf.extend_from_slice(&self.msg_id);
        buf.push(self.ttl);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.sender_counter.to_le_bytes());
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < GOSSIP_HEADER_LEN + GOSSIP_TAG_LEN {
            return None;
        }
        if bytes[0] != CHANNEL_MSG_VERSION {
            return None;
        }
        let mut channel_id = [0u8; 16];
        channel_id.copy_from_slice(&bytes[1..17]);
        let mut msg_id = [0u8; 16];
        msg_id.copy_from_slice(&bytes[17..33]);
        // Clamped, not trusted. The hop count has to mutate as a frame travels,
        // so it cannot live under the AEAD like the rest of the header — which
        // leaves the originator free to write 255 and have the mesh carry the
        // frame two hundred hops instead of eight. Dedup still stops loops and
        // holds each node to one relay, so the cost is reach rather than
        // runaway, but reach is the whole point of a hop budget.
        let ttl = bytes[33].min(CHANNEL_MSG_TTL_DEFAULT);
        let timestamp = i64::from_le_bytes(bytes[34..42].try_into().ok()?);
        let sender_counter = u64::from_le_bytes(bytes[42..50].try_into().ok()?);
        Some(Self {
            channel_id,
            msg_id,
            ttl,
            timestamp,
            sender_counter,
            ciphertext: bytes[50..].to_vec(),
        })
    }

    pub fn decrypt(&self, content_key: &[u8; 32]) -> Option<Vec<u8>> {
        decrypt_gossip_body(
            content_key,
            &self.channel_id,
            &self.msg_id,
            self.sender_counter,
            self.timestamp,
            &self.ciphertext,
        )
    }

    pub fn decremented_ttl(&self) -> Option<Self> {
        let ttl = self.ttl.checked_sub(1)?;
        if ttl == 0 {
            return None;
        }
        let mut next = self.clone();
        next.ttl = ttl;
        Some(next)
    }
}

fn gossip_aad(
    channel_id: &[u8; 16],
    msg_id: &[u8; 16],
    sender_counter: u64,
    timestamp: i64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(GOSSIP_AAD_DOMAIN.len() + 16 + 16 + 8 + 8);
    aad.extend_from_slice(GOSSIP_AAD_DOMAIN);
    aad.extend_from_slice(channel_id);
    aad.extend_from_slice(msg_id);
    aad.extend_from_slice(&sender_counter.to_le_bytes());
    aad.extend_from_slice(&timestamp.to_le_bytes());
    aad
}

fn encrypt_gossip_body(
    key: &[u8; 32],
    channel_id: &[u8; 16],
    msg_id: &[u8; 16],
    sender_counter: u64,
    timestamp: i64,
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
    let mut nonce = [0u8; GOSSIP_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let aad = gossip_aad(channel_id, msg_id, sender_counter, timestamp);
    let encrypted = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption cannot fail for channel-sized plaintext");
    let mut out = Vec::with_capacity(1 + GOSSIP_NONCE_LEN + encrypted.len());
    out.push(CHANNEL_MSG_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&encrypted);
    out
}

fn decrypt_gossip_body(
    key: &[u8; 32],
    channel_id: &[u8; 16],
    msg_id: &[u8; 16],
    sender_counter: u64,
    timestamp: i64,
    envelope: &[u8],
) -> Option<Vec<u8>> {
    if envelope.len() < GOSSIP_ENVELOPE_OVERHEAD || envelope[0] != CHANNEL_MSG_VERSION {
        return None;
    }
    let aad = gossip_aad(channel_id, msg_id, sender_counter, timestamp);
    let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(&envelope[1..1 + GOSSIP_NONCE_LEN]),
            Payload {
                msg: &envelope[1 + GOSSIP_NONCE_LEN..],
                aad: &aad,
            },
        )
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // One fixed room / message / time for the chat frames below. A signature
    // only verifies against the context it was made for, so both ends of a
    // test have to name the same one.
    const CHAT_CHANNEL: [u8; 16] = [3u8; 16];
    const CHAT_MSG_ID: [u8; 16] = [4u8; 16];
    const CHAT_TS: i64 = 1_700_000_000;

    /// A chat line signed by `sk` and bound to the fixed context above.
    fn chat_frame(sk: &SigningKey, text: &str) -> Vec<u8> {
        let pk = sk.verifying_key().to_bytes();
        let sig = chat_author_signature(sk, &pk, &CHAT_CHANNEL, &CHAT_MSG_ID, CHAT_TS, text);
        encode_channel_chat_plain_presigned(&pk, &sig, text)
    }

    /// A revision of `CHAT_MSG_ID` signed by `sk`, dated `edited_at`.
    fn edit_frame(sk: &SigningKey, text: &str, edited_at: i64) -> Vec<u8> {
        let pk = sk.verifying_key().to_bytes();
        let sig = edit_author_signature(
            sk,
            &pk,
            &CHAT_CHANNEL,
            &CHAT_MSG_ID,
            CHAT_TS,
            edited_at,
            text,
        );
        encode_channel_chat_edit_presigned(&pk, &CHAT_MSG_ID, CHAT_TS, edited_at, &sig, text)
    }

    fn reaction_entry(sk: &SigningKey, target: [u8; 16], reaction: u8, at: i64) -> ChannelReaction {
        let pk = sk.verifying_key().to_bytes();
        let signature = reaction_signature(sk, &pk, &CHAT_CHANNEL, &target, at, reaction);
        ChannelReaction {
            target_msg_id: target,
            member: pk,
            reaction,
            reacted_at: at,
            signature,
        }
    }

    #[test]
    fn an_edit_round_trips_and_is_bound_to_its_author_room_and_target() {
        let alice = SigningKey::generate(&mut rand::rngs::OsRng);
        let bob = SigningKey::generate(&mut rand::rngs::OsRng);
        let alice_pk = alice.verifying_key().to_bytes();

        let frame = edit_frame(&alice, "fixed the typo", CHAT_TS + 30);
        let edit = decode_channel_chat_edit(&frame, &CHAT_CHANNEL).unwrap();
        assert_eq!(edit.sender, alice_pk);
        assert_eq!(edit.target_msg_id, CHAT_MSG_ID);
        assert_eq!(edit.original_timestamp, CHAT_TS);
        assert_eq!(edit.edited_at, CHAT_TS + 30);
        assert_eq!(edit.text, "fixed the typo");

        // Re-serving on a catch-up rebuilds the same bytes from the stored
        // parts, so a member can pass on somebody else's revision without being
        // able to author one.
        let replayed = encode_channel_chat_edit_presigned(
            &edit.sender,
            &edit.target_msg_id,
            edit.original_timestamp,
            edit.edited_at,
            &edit.signature,
            &edit.text,
        );
        assert_eq!(replayed, frame);

        // Wrong room, and a body claiming an author who did not sign it.
        assert!(decode_channel_chat_edit(&frame, &[9u8; 16]).is_none());
        let mut forged = frame.clone();
        forged[1..33].copy_from_slice(&bob.verifying_key().to_bytes());
        assert!(
            decode_channel_chat_edit(&forged, &CHAT_CHANNEL).is_none(),
            "an edit naming another member must not be attributed to them"
        );

        // Every signed field is load-bearing: flipping the target, either
        // timestamp, or the text must all invalidate it.
        for byte in [33usize, 49, 57, frame.len() - 1] {
            let mut tampered = frame.clone();
            tampered[byte] ^= 0xFF;
            assert!(
                decode_channel_chat_edit(&tampered, &CHAT_CHANNEL).is_none(),
                "byte {byte} is inside the signed preimage and must not be malleable"
            );
        }
    }

    #[test]
    fn the_edit_window_needs_both_the_authors_clock_and_our_own() {
        let sent = 1_000_000i64;
        let seen = 2_000_000i64;

        // Inside the window on both clocks.
        assert!(edit_within_window(sent, sent + 60, seen, seen + 60));
        // The author claims a gap wider than the window.
        assert!(!edit_within_window(
            sent,
            sent + CHANNEL_EDIT_WINDOW_SECS + 1,
            seen,
            seen + 60
        ));
        // The author claims a tight gap, but we have held the line for a day —
        // this is the backdating case the second clock exists to refuse.
        assert!(!edit_within_window(sent, sent + 60, seen, seen + 86_400));
        // An edit dated before the line it revises is nonsense.
        assert!(!edit_within_window(sent, sent - 1, seen, seen + 60));
        // A row from before `first_seen_at` existed is judged on the author's
        // clock alone rather than refused outright.
        assert!(edit_within_window(sent, sent + 60, 0, seen + 86_400));
    }

    #[test]
    fn a_reaction_batch_verifies_each_entry_independently() {
        let alice = SigningKey::generate(&mut rand::rngs::OsRng);
        let bob = SigningKey::generate(&mut rand::rngs::OsRng);
        let other_target = [7u8; 16];

        let entries = vec![
            reaction_entry(&alice, CHAT_MSG_ID, REACTION_UP, CHAT_TS + 1),
            reaction_entry(&bob, CHAT_MSG_ID, REACTION_DOWN, CHAT_TS + 2),
            // One batch may span several lines, which is what makes a catch-up
            // affordable.
            reaction_entry(&alice, other_target, REACTION_UP, CHAT_TS + 3),
        ];
        let frame = encode_channel_reactions(&entries);
        let decoded = decode_channel_reactions(&frame, &CHAT_CHANNEL).unwrap();
        assert_eq!(decoded, entries);

        // A forged entry is dropped on its own; the genuine ones beside it
        // survive, because a batch is a bundle of independent claims.
        let mut tampered = frame.clone();
        let second = 2 + REACTION_ENTRY_LEN;
        tampered[second + 48] = REACTION_UP;
        let decoded = decode_channel_reactions(&tampered, &CHAT_CHANNEL).unwrap();
        assert_eq!(decoded.len(), 2, "only the edited entry should be discarded");
        assert!(decoded.iter().all(|e| e.member != bob.verifying_key().to_bytes()));

        // Wrong room invalidates the whole batch, entry by entry.
        assert!(decode_channel_reactions(&frame, &[9u8; 16])
            .unwrap()
            .is_empty());

        // A malformed frame is refused rather than partially read.
        assert!(decode_channel_reactions(&frame[..frame.len() - 1], &CHAT_CHANNEL).is_none());
        assert!(decode_channel_reactions(&[REACTION_PLAIN_VERSION, 0], &CHAT_CHANNEL).is_none());
    }

    #[test]
    fn a_reaction_value_this_build_does_not_draw_still_survives_a_round_trip() {
        // Forward compatibility: a newer build's reaction has to reach the rest
        // of the room through this one, or a mixed-version room loses reactions
        // every time one passes through an older peer.
        let alice = SigningKey::generate(&mut rand::rngs::OsRng);
        let future = reaction_entry(&alice, CHAT_MSG_ID, 200, CHAT_TS + 1);
        let frame = encode_channel_reactions(std::slice::from_ref(&future));
        let decoded = decode_channel_reactions(&frame, &CHAT_CHANNEL).unwrap();
        assert_eq!(decoded, vec![future]);
    }

    #[test]
    fn a_reaction_batch_refuses_more_than_one_frame_holds() {
        let alice = SigningKey::generate(&mut rand::rngs::OsRng);
        let entries: Vec<ChannelReaction> = (0..CHANNEL_REACTION_MAX_PER_FRAME + 5)
            .map(|i| {
                let mut target = [0u8; 16];
                target[0] = i as u8;
                reaction_entry(&alice, target, REACTION_UP, CHAT_TS + i as i64)
            })
            .collect();
        let frame = encode_channel_reactions(&entries);
        let decoded = decode_channel_reactions(&frame, &CHAT_CHANNEL).unwrap();
        assert_eq!(
            decoded.len(),
            CHANNEL_REACTION_MAX_PER_FRAME,
            "the encoder must clamp rather than emit a frame no receiver accepts"
        );
    }

    #[test]
    fn channel_id_matches_ember_node_id_derivation() {
        let ident = ChannelIdentity::generate();
        let vk = crypto::verifying_key_from_bytes(&ident.pubkey).unwrap();
        assert_eq!(ident.channel_id, crypto::node_id_from_public_key(&vk));
        assert_eq!(ident.channel_id, channel_id_from_pubkey(&ident.pubkey));
    }

    #[test]
    fn public_and_private_content_keys_differ() {
        let ident = ChannelIdentity::generate();
        let public = content_key(&public_join_secret(&ident.pubkey));
        let private = content_key(&generate_private_join_secret());
        assert_ne!(public, private);
        assert_eq!(
            content_key(&public_join_secret(&ident.pubkey)),
            public,
            "content key must be deterministic"
        );
    }

    #[test]
    fn index_keys_are_sharded_and_stable() {
        let keys = all_index_keys();
        let unique: std::collections::HashSet<_> = keys.iter().copied().collect();
        assert_eq!(unique.len(), INDEX_SHARD_COUNT as usize);
        assert_eq!(index_key(0), index_key(INDEX_SHARD_COUNT));
        let id = [0x11u8; 16];
        assert_eq!(index_key_for_channel(&id), index_key(index_shard(&id)));
    }

    #[test]
    fn presence_key_rotates_with_epoch_and_secret() {
        let id = [0xAAu8; 16];
        let secret = [0xBBu8; 32];
        let e0 = presence_key(&id, &secret, 0);
        let e1 = presence_key(&id, &secret, 1);
        let other = presence_key(&id, &[0xCCu8; 32], 0);
        assert_ne!(e0, e1);
        assert_ne!(e0, other);
        assert_eq!(presence_epoch(PRESENCE_EPOCH_SECS - 1), 0);
        assert_eq!(presence_epoch(PRESENCE_EPOCH_SECS), 1);
    }

    #[test]
    fn public_invite_round_trip_binds_id_to_pubkey() {
        let ident = ChannelIdentity::generate();
        let invite = ChannelInvite {
            channel_id: ident.channel_id,
            pubkey: ident.pubkey,
            name: "General chat".into(),
            join_secret: public_join_secret(&ident.pubkey),
            private: false,
            key_epoch: 0,
        };
        let parsed = ChannelInvite::parse(&invite.format()).unwrap();
        assert_eq!(parsed, invite);
        assert!(!parsed.format().contains("&k="));
    }

    #[test]
    fn private_invite_carries_join_secret() {
        let ident = ChannelIdentity::generate();
        let secret = generate_private_join_secret();
        let invite = ChannelInvite {
            channel_id: ident.channel_id,
            pubkey: ident.pubkey,
            name: "café ☕".into(),
            join_secret: secret,
            private: true,
            key_epoch: 5,
        };
        let parsed = ChannelInvite::parse(&invite.format()).unwrap();
        assert_eq!(parsed.join_secret, secret);
        assert!(parsed.private);
        assert_eq!(parsed.name, "café ☕");
        assert_eq!(parsed.key_epoch, 5, "the invite states which epoch it is for");

        // An invite from before this field existed, or from a room that never
        // rotated, reads as epoch 0 rather than failing to parse — the secret is
        // what matters and it is still intact.
        let older = invite.format().replace("&e=5", "");
        let parsed = ChannelInvite::parse(&older).expect("older invites still parse");
        assert_eq!(parsed.join_secret, secret);
        assert_eq!(parsed.key_epoch, 0);

        // A mangled epoch is treated the same way, for the same reason: these
        // are pasted by hand.
        let mangled = invite.format().replace("&e=5", "&e=notanumber");
        let parsed = ChannelInvite::parse(&mangled).expect("a bad epoch is not fatal");
        assert_eq!(parsed.join_secret, secret);
        assert_eq!(parsed.key_epoch, 0);

        // A public invite never carries one: its key is derived, not rotated.
        let public = ChannelInvite {
            channel_id: ident.channel_id,
            pubkey: ident.pubkey,
            name: String::new(),
            join_secret: public_join_secret(&ident.pubkey),
            private: false,
            key_epoch: 9,
        };
        assert!(!public.format().contains("&e="));
        assert_eq!(ChannelInvite::parse(&public.format()).unwrap().key_epoch, 0);
    }

    #[test]
    fn invite_with_mismatched_id_is_rejected() {
        let ident = ChannelIdentity::generate();
        let mut uri = format!(
            "{URI_SCHEME}{}?pk={}",
            hex::encode([0u8; 16]),
            hex::encode(ident.pubkey)
        );
        assert!(ChannelInvite::parse(&uri).is_none());
        uri = format!(
            "{URI_SCHEME}{}?pk={}",
            hex::encode(ident.channel_id),
            hex::encode([1u8; 32])
        );
        assert!(ChannelInvite::parse(&uri).is_none());
    }

    #[test]
    fn xor_neighbors_are_deterministic_and_exclude_self() {
        let self_pk = [1u8; 32];
        let mut members = vec![self_pk];
        for i in 2u8..=20 {
            members.push([i; 32]);
        }
        let a = xor_closest_neighbors(&self_pk, &members, CHANNEL_NEIGHBOR_COUNT);
        let b = xor_closest_neighbors(&self_pk, &members, CHANNEL_NEIGHBOR_COUNT);
        assert_eq!(a, b);
        assert_eq!(a.len(), CHANNEL_NEIGHBOR_COUNT);
        assert!(!a.contains(&self_pk));
    }

    #[test]
    fn presence_departure_is_skipped_for_us_while_in_the_room() {
        let us = [1u8; 32];
        let them = [2u8; 32];
        assert!(
            !presence_departure_applies(&us, &us, true),
            "our own leave tombstone must not drop us while we are still in the room"
        );
        assert!(presence_departure_applies(&them, &us, true));
        assert!(
            presence_departure_applies(&us, &us, false),
            "after we walk out, a tombstone for us is still applied"
        );
    }

    #[test]
    fn clamp_presence_timestamp_rejects_far_future_and_pins_to_now() {
        let now = 1_700_000_000;
        assert_eq!(clamp_presence_timestamp(now, now), Some(now));
        assert_eq!(clamp_presence_timestamp(now - 60, now), Some(now - 60));
        assert_eq!(
            clamp_presence_timestamp(now + 30, now),
            Some(now),
            "a slightly-ahead clock must not sort past honest last_seen"
        );
        assert!(clamp_presence_timestamp(now + PRESENCE_MAX_FUTURE_SKEW_SECS + 1, now).is_none());
        assert!(clamp_presence_timestamp(0, now).is_none());
    }

    #[test]
    fn chat_fanout_direct_rung_requires_a_live_session() {
        assert!(channel_fanout_uses_direct_session(true));
        assert!(
            !channel_fanout_uses_direct_session(false),
            "a routing-table hit is not delivery — overlay and WS must still run"
        );
    }

    #[test]
    fn a_public_chat_line_does_not_insert_a_stranger_into_the_neighbor_set() {
        assert!(
            !chat_author_joins_gossip_roster(false),
            "public rooms take neighbors from presence, not from chat authors"
        );
        assert!(
            chat_author_joins_gossip_roster(true),
            "a private chat line is already evidence of membership"
        );

        let self_pk = [1u8; 32];
        let stranger = [9u8; 32];
        // The gossip roster is presence-vouched members. A chat line must not
        // have added `stranger`, so XOR-closest of the real roster does not
        // include them.
        let neighbors = xor_closest_neighbors(&self_pk, &[self_pk], CHANNEL_NEIGHBOR_COUNT);
        assert!(
            !neighbors.contains(&stranger),
            "a stranger who only spoke must not become a mesh neighbor"
        );
        assert!(neighbors.is_empty());
    }

    #[test]
    fn inbound_relay_forwards_only_with_a_live_session_in_a_room_we_are_in() {
        assert!(inbound_channel_relay_may_forward(true, Some(true), true));
        assert!(
            inbound_channel_relay_may_forward(true, None, true),
            "no roster yet is not a hard refuse"
        );
        assert!(!inbound_channel_relay_may_forward(false, Some(true), true));
        assert!(!inbound_channel_relay_may_forward(true, Some(true), false));
        assert!(!inbound_channel_relay_may_forward(true, Some(false), true));
    }

    #[test]
    fn gossip_round_trip_and_aad_bind() {
        let key = content_key(&[7u8; 32]);
        let channel_id = [3u8; 16];
        let msg = ChannelGossip::new_plaintext(channel_id, &key, 42, b"hello room", 4);
        let decoded = ChannelGossip::decode(&msg.encode()).unwrap();
        assert_eq!(
            decoded.decrypt(&key).as_deref(),
            Some(b"hello room".as_slice())
        );
        let author = SigningKey::generate(&mut OsRng);
        let (pk, text, _sig) = decode_channel_chat_plain(
            &chat_frame(&author, "hi"),
            &CHAT_CHANNEL,
            &CHAT_MSG_ID,
            CHAT_TS,
        )
        .unwrap();
        assert_eq!(pk, author.verifying_key().to_bytes());
        assert_eq!(text, "hi");
        assert!(decoded.decrypt(&[8u8; 32]).is_none());
        let mut tampered = decoded.clone();
        tampered.sender_counter = 43;
        assert!(tampered.decrypt(&key).is_none());
        assert_eq!(decoded.decremented_ttl().unwrap().ttl, 3);
        assert!(ChannelGossip { ttl: 1, ..decoded }
            .decremented_ttl()
            .is_none());
        let author = SigningKey::generate(&mut OsRng);
        let author_pk = author.verifying_key().to_bytes();
        let target = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let (sender, decoded_target, banned) = decode_channel_mod_action(
            &encode_channel_mod_action(
                &author,
                &author_pk,
                &target,
                true,
                &CHAT_CHANNEL,
                &CHAT_MSG_ID,
                CHAT_TS,
            ),
            &CHAT_CHANNEL,
            &CHAT_MSG_ID,
            CHAT_TS,
        )
        .unwrap();
        assert_eq!(sender, author_pk);
        assert_eq!(decoded_target, target);
        assert!(banned);
        assert!(decode_channel_mod_action(
            &chat_frame(&author, "x"),
            &CHAT_CHANNEL,
            &CHAT_MSG_ID,
            CHAT_TS
        )
        .is_none());
    }

    /// The forgery the signature exists to stop, and the three replays that
    /// signing the text alone would have left open.
    ///
    /// Every member holds the room's content key, so Mallory can seal a line
    /// that names Alice in its sender field and it will decrypt for everyone.
    /// What she cannot do is produce Alice's signature over it.
    #[test]
    fn a_member_cannot_put_another_members_name_on_a_chat_line() {
        let alice = SigningKey::generate(&mut OsRng);
        let mallory = SigningKey::generate(&mut OsRng);
        let alice_pk = alice.verifying_key().to_bytes();

        // Mallory signs with her own key and writes Alice's into the sender
        // field — everything an impersonating member can actually do.
        let mallory_sig = chat_author_signature(
            &mallory,
            &alice_pk,
            &CHAT_CHANNEL,
            &CHAT_MSG_ID,
            CHAT_TS,
            "I vouch for this download",
        );
        let forged = encode_channel_chat_plain_presigned(
            &alice_pk,
            &mallory_sig,
            "I vouch for this download",
        );
        assert!(
            decode_channel_chat_plain(&forged, &CHAT_CHANNEL, &CHAT_MSG_ID, CHAT_TS).is_none(),
            "a line signed by one member but naming another must not be attributed"
        );

        let genuine = chat_frame(&alice, "I vouch for this download");
        let (pk, text, sig) =
            decode_channel_chat_plain(&genuine, &CHAT_CHANNEL, &CHAT_MSG_ID, CHAT_TS).unwrap();
        assert_eq!(pk, alice_pk);
        assert_eq!(text, "I vouch for this download");

        // The signature comes back out so a receiver can re-serve the line on a
        // catch-up. Rebuilt from those parts alone it still verifies, which is
        // what makes history sync possible without anyone signing for Alice.
        let reserved = encode_channel_chat_plain_presigned(&pk, &sig, &text);
        assert_eq!(reserved, genuine);

        // The context is inside the preimage, so a genuine line cannot be
        // lifted into another room, re-wrapped under a fresh id to get past the
        // duplicate filter, or re-dated.
        assert!(decode_channel_chat_plain(&genuine, &[9u8; 16], &CHAT_MSG_ID, CHAT_TS).is_none());
        assert!(decode_channel_chat_plain(&genuine, &CHAT_CHANNEL, &[9u8; 16], CHAT_TS).is_none());
        assert!(
            decode_channel_chat_plain(&genuine, &CHAT_CHANNEL, &CHAT_MSG_ID, CHAT_TS + 1).is_none()
        );

        let mut tampered = genuine.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert!(
            decode_channel_chat_plain(&tampered, &CHAT_CHANNEL, &CHAT_MSG_ID, CHAT_TS).is_none()
        );

        // The unsigned frame this replaced is refused outright. Reading it would
        // hand an impersonator the whole forgery back for the cost of one byte.
        let mut legacy = vec![1u8];
        legacy.extend_from_slice(&alice_pk);
        legacy.extend_from_slice(b"I vouch for this download");
        assert!(
            decode_channel_chat_plain(&legacy, &CHAT_CHANNEL, &CHAT_MSG_ID, CHAT_TS).is_none(),
            "the retired unsigned chat frame must not be trusted"
        );
    }

    #[test]
    fn channel_presence_capability_is_pairwise_and_channel_bound() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let channel_id = [0x11u8; 16];
        let epoch = 9;
        let alice_to_bob = derive_channel_presence_capability(
            &alice.to_bytes(),
            &bob.verifying_key().to_bytes(),
            &bob.verifying_key().to_bytes(),
            &channel_id,
            epoch,
        )
        .unwrap();
        let bob_to_alice = derive_channel_presence_capability(
            &bob.to_bytes(),
            &alice.verifying_key().to_bytes(),
            &bob.verifying_key().to_bytes(),
            &channel_id,
            epoch,
        )
        .unwrap();
        assert_eq!(alice_to_bob, bob_to_alice);
        let other_channel = derive_channel_presence_capability(
            &alice.to_bytes(),
            &bob.verifying_key().to_bytes(),
            &bob.verifying_key().to_bytes(),
            &[0x22u8; 16],
            epoch,
        )
        .unwrap();
        assert_ne!(alice_to_bob, other_channel);
        let friend_cap = crypto::derive_pairwise_presence_capability(
            &alice.to_bytes(),
            &bob.verifying_key().to_bytes(),
            &bob.verifying_key().to_bytes(),
            epoch,
        )
        .unwrap();
        assert_ne!(
            alice_to_bob, friend_cap,
            "channel capability must not collide with friend presence"
        );
    }

    #[test]
    /// Registration has to name exactly the peers the fanout will dial, or we
    /// publish an address under a capability nobody looks up and look up one
    /// nobody published under.
    fn rendezvous_neighbor_targets_match_the_gossip_set_and_skip_self() {
        let self_pk = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let a = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let b = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let channel_id = [0xab; 16];
        let roster = vec![self_pk, a, b];
        let picked = gossip_neighbors(&self_pk, &roster, 1);
        assert_eq!(picked.len(), 1);
        assert_ne!(picked[0], self_pk);
        let targets = rendezvous_neighbor_targets(
            &self_pk,
            &[(channel_id, roster)],
            CHANNEL_RENDEZVOUS_MAX_CHANNELS,
            1,
        );
        assert_eq!(targets, vec![(channel_id, picked[0])]);
    }

    #[test]
    fn gossip_seen_set_dedups_and_evicts_oldest() {
        let mut seen = HashMap::new();
        let mut order = VecDeque::new();
        let now = Instant::now();
        let cap = 4;
        let ids: Vec<[u8; 16]> = (0u8..6)
            .map(|i| {
                let mut id = [0u8; 16];
                id[0] = i;
                id
            })
            .collect();
        for id in &ids[..4] {
            assert!(remember_gossip_id(&mut seen, &mut order, cap, *id, now));
        }
        assert!(!remember_gossip_id(&mut seen, &mut order, cap, ids[0], now));
        assert!(remember_gossip_id(&mut seen, &mut order, cap, ids[4], now));
        assert!(!seen.contains_key(&ids[0]));
        assert!(remember_gossip_id(&mut seen, &mut order, cap, ids[5], now));
        assert!(!seen.contains_key(&ids[1]));
        assert_eq!(seen.len(), cap);
        assert_eq!(order.len(), cap);
        assert!(seen.contains_key(&ids[2]));
        assert!(seen.contains_key(&ids[5]));
    }

    #[test]
    fn gossip_seen_set_respects_session_cap() {
        let mut seen = HashMap::new();
        let mut order = VecDeque::new();
        let now = Instant::now();
        let cap = CHANNEL_GOSSIP_SEEN_CAP;
        for i in 0..(cap + 10) {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            assert!(remember_gossip_id(&mut seen, &mut order, cap, id, now));
        }
        assert_eq!(seen.len(), cap);
        assert_eq!(order.len(), cap);
        let mut evicted = [0u8; 16];
        evicted[..8].copy_from_slice(&0u64.to_le_bytes());
        assert!(!seen.contains_key(&evicted));
        let mut kept = [0u8; 16];
        kept[..8].copy_from_slice(&10u64.to_le_bytes());
        assert!(seen.contains_key(&kept));
        assert!(!remember_gossip_id(&mut seen, &mut order, cap, kept, now));
    }

    #[test]
    fn gossip_decode_fuzz_never_panics() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xC8A1_7E11);
        let key = content_key(&[7u8; 32]);
        let channel_id = CHAT_CHANNEL;
        let author = SigningKey::generate(&mut OsRng);
        let chat_plain = chat_frame(&author, "fuzz");
        // Sealed rather than `new_plaintext` so the envelope carries the same
        // room, id and time the signature inside it was made over.
        let well_chat =
            ChannelGossip::sealed(channel_id, CHAT_MSG_ID, &key, 1, &chat_plain, 4, CHAT_TS)
                .encode();
        let mod_plain = encode_channel_mod_action(
            &author,
            &author.verifying_key().to_bytes(),
            &SigningKey::generate(&mut OsRng).verifying_key().to_bytes(),
            true,
            &channel_id,
            &CHAT_MSG_ID,
            CHAT_TS,
        );
        let well_mod =
            ChannelGossip::sealed(channel_id, CHAT_MSG_ID, &key, 2, &mod_plain, 4, CHAT_TS)
                .encode();
        let mut decoded_ok = 0usize;
        for i in 0..2_000 {
            let buf = match i {
                0 => well_chat.clone(),
                1 => well_mod.clone(),
                _ => {
                    let len = rng.gen_range(0..=512);
                    let mut buf = vec![0u8; len];
                    rng.fill(&mut buf[..]);
                    if i % 17 == 0 {
                        buf = well_chat.clone();
                        let at = rng.gen_range(0..buf.len());
                        buf[at] ^= rng.gen_range(1u8..=255);
                    }
                    buf
                }
            };
            if let Some(decoded) = ChannelGossip::decode(&buf) {
                decoded_ok += 1;
                let _ = decoded.decremented_ttl();
                if let Some(plain) = decoded.decrypt(&key) {
                    let _ = decode_channel_chat_plain(
                        &plain,
                        &decoded.channel_id,
                        &decoded.msg_id,
                        decoded.timestamp,
                    );
                    let _ = decode_channel_mod_action(
                        &plain,
                        &decoded.channel_id,
                        &decoded.msg_id,
                        decoded.timestamp,
                    );
                }
            }
            let _ = decode_channel_chat_plain(&buf, &channel_id, &CHAT_MSG_ID, CHAT_TS);
            let _ = decode_channel_mod_action(&buf, &channel_id, &CHAT_MSG_ID, CHAT_TS);
            let _ = decode_channel_sync_request(&buf, &channel_id, &CHAT_MSG_ID, CHAT_TS);
            let _ = decode_presence_extra(Some(&key), &channel_id, &buf, "");
        }
        let chat = ChannelGossip::decode(&well_chat).unwrap();
        let (pk, text, _sig) = decode_channel_chat_plain(
            &chat.decrypt(&key).unwrap(),
            &chat.channel_id,
            &chat.msg_id,
            chat.timestamp,
        )
        .unwrap();
        assert_eq!(pk, author.verifying_key().to_bytes());
        assert_eq!(text, "fuzz");
        let mod_g = ChannelGossip::decode(&well_mod).unwrap();
        let (sender, target, banned) = decode_channel_mod_action(
            &mod_g.decrypt(&key).unwrap(),
            &mod_g.channel_id,
            &mod_g.msg_id,
            mod_g.timestamp,
        )
        .unwrap();
        assert_eq!(sender, author.verifying_key().to_bytes());
        assert_eq!(target.len(), 32);
        assert!(banned);
        assert!(
            decoded_ok > 0,
            "the fuzz never produced a buffer that reached ChannelGossip::decode"
        );
    }

    /// Deliberately past the size where XOR-closest alone comes apart. At 12 —
    /// what this used to run — a prefix-closed cluster cannot yet reach the
    /// `CHANNEL_NEIGHBOR_COUNT + 1` members it takes to seal itself off, so the
    /// old graph passed and the partition went unnoticed until a real room grew.
    #[test]
    fn gossip_mesh_soak_delivers_once_within_ttl() {
        const N: usize = 64;
        let members: Vec<[u8; 32]> = (0..N)
            .map(|i| {
                let mut pk = [0u8; 32];
                pk[0] = i as u8;
                pk[1] = 0xC8;
                pk[2] = 0xA1;
                pk
            })
            .collect();
        let neighbors: Vec<Vec<usize>> = members
            .iter()
            .map(|self_pk| {
                gossip_neighbors(self_pk, &members, CHANNEL_NEIGHBOR_COUNT)
                    .into_iter()
                    .filter_map(|pk| members.iter().position(|m| *m == pk))
                    .collect()
            })
            .collect();
        let key = content_key(&[9u8; 32]);
        let channel_id = [0x42u8; 16];
        let now = Instant::now();
        let mut seen: Vec<(HashMap<[u8; 16], Instant>, VecDeque<[u8; 16]>)> =
            (0..N).map(|_| (HashMap::new(), VecDeque::new())).collect();

        for origin in 0..N {
            let reachable = directed_reach(&neighbors, origin, CHANNEL_MSG_TTL_DEFAULT);
            assert_eq!(
                reachable.len(),
                N,
                "degree-{CHANNEL_NEIGHBOR_COUNT} gossip graph on {N} members should be fully \
                 reachable from {origin} within TTL"
            );
            let expected = format!("soak-{origin}");
            let gossip = ChannelGossip::new_plaintext(
                channel_id,
                &key,
                origin as u64 + 1,
                expected.as_bytes(),
                CHANNEL_MSG_TTL_DEFAULT,
            );
            let mut delivered = [0u8; N];
            let mut q = VecDeque::new();
            {
                let (map, order) = &mut seen[origin];
                assert!(remember_gossip_id(
                    map,
                    order,
                    CHANNEL_GOSSIP_SEEN_CAP,
                    gossip.msg_id,
                    now,
                ));
            }
            delivered[origin] = 1;
            for &nbr in &neighbors[origin] {
                q.push_back((nbr, gossip.clone()));
            }
            while let Some((node, pkt)) = q.pop_front() {
                let first_seen = {
                    let (map, order) = &mut seen[node];
                    remember_gossip_id(map, order, CHANNEL_GOSSIP_SEEN_CAP, pkt.msg_id, now)
                };
                if !first_seen {
                    continue;
                }
                assert_eq!(pkt.decrypt(&key).as_deref(), Some(expected.as_bytes()));
                delivered[node] += 1;
                let Some(next) = pkt.decremented_ttl() else {
                    continue;
                };
                for &nbr in &neighbors[node] {
                    q.push_back((nbr, next.clone()));
                }
            }
            for node in 0..N {
                assert_eq!(
                    delivered[node], 1,
                    "node {node} should receive origin {origin}'s message exactly once"
                );
                let (map, order) = &mut seen[node];
                assert!(!remember_gossip_id(
                    map,
                    order,
                    CHANNEL_GOSSIP_SEEN_CAP,
                    gossip.msg_id,
                    now,
                ));
            }
        }
        for (map, order) in &seen {
            assert_eq!(map.len(), N);
            assert_eq!(order.len(), N);
            assert!(map.len() <= CHANNEL_GOSSIP_SEEN_CAP);
        }
    }

    #[test]
    fn presence_extra_private_hides_nickname_and_noise() {
        let key = content_key(&[3u8; 32]);
        let channel_id = [0x11u8; 16];
        let noise = [0x42u8; 32];
        let (public_name, public_extra) =
            encode_presence_extra(false, &key, &channel_id, &noise, "Ada");
        assert_eq!(public_name, "Ada");
        assert_eq!(public_extra, noise);
        assert!(presence_extra_store_ok(&public_extra));
        let (n, nick) = decode_presence_extra(None, &channel_id, &public_extra, "Ada").unwrap();
        assert_eq!(n, noise);
        assert_eq!(nick, "Ada");

        let (private_name, private_extra) =
            encode_presence_extra(true, &key, &channel_id, &noise, "Ada");
        assert!(private_name.is_empty());
        assert_ne!(private_extra, noise);
        assert!(presence_extra_store_ok(&private_extra));
        assert!(decode_presence_extra(None, &channel_id, &private_extra, "").is_none());
        let (n, nick) = decode_presence_extra(Some(&key), &channel_id, &private_extra, "").unwrap();
        assert_eq!(n, noise);
        assert_eq!(nick, "Ada");
        assert!(
            decode_presence_extra(Some(&key), &[0x22u8; 16], &private_extra, "").is_none(),
            "presence extra must bind the channel id"
        );
    }

    #[test]
    fn sync_request_round_trip_and_rate_window() {
        let author = SigningKey::generate(&mut OsRng);
        let pk = author.verifying_key().to_bytes();
        let plain = encode_channel_sync_request(
            &author,
            &pk,
            &CHAT_CHANNEL,
            &CHAT_MSG_ID,
            CHAT_TS,
            1_700_000_000,
        );
        let (decoded_pk, since) =
            decode_channel_sync_request(&plain, &CHAT_CHANNEL, &CHAT_MSG_ID, CHAT_TS).unwrap();
        assert_eq!(decoded_pk, pk);
        assert_eq!(since, 1_700_000_000);
        assert!(decode_channel_sync_request(
            &chat_frame(&author, "x"),
            &CHAT_CHANNEL,
            &CHAT_MSG_ID,
            CHAT_TS
        )
        .is_none());

        let mut times = VecDeque::new();
        let t0 = Instant::now();
        let window = Duration::from_secs(1);
        for _ in 0..3 {
            assert!(rate_window_allow(&mut times, t0, window, 3));
        }
        assert!(!rate_window_allow(&mut times, t0, window, 3));
        assert!(rate_window_allow(
            &mut times,
            t0 + Duration::from_millis(1_001),
            window,
            3
        ));
    }

    /// The per-hop limit cannot bound a flood that arrives spread across the
    /// mesh, so the author limit is what actually protects a room — and it has
    /// to stay per-room, refuse unknown authors once full, and free slots again
    /// as members go quiet.
    #[test]
    fn author_flood_control_is_per_room_and_reclaims_quiet_slots() {
        let mut seen = HashMap::new();
        let room = [0x01u8; 16];
        let other_room = [0x02u8; 16];
        let alice = [0xAAu8; 32];
        let bob = [0xBBu8; 32];
        let start = Instant::now();

        for i in 0..CHANNEL_GOSSIP_PER_AUTHOR_PER_SEC {
            assert!(
                author_gossip_allow(&mut seen, room, &alice, start),
                "message {i} is inside the per-second budget"
            );
        }
        assert!(
            !author_gossip_allow(&mut seen, room, &alice, start),
            "one past the budget is a flood"
        );
        assert!(
            author_gossip_allow(&mut seen, room, &bob, start),
            "another member is unaffected by Alice's budget"
        );
        assert!(
            author_gossip_allow(&mut seen, other_room, &alice, start),
            "and Alice still has a full budget in a different room"
        );

        // A second later her window has rolled off.
        let later = start + Duration::from_secs(2);
        assert!(author_gossip_allow(&mut seen, room, &alice, later));

        // Slots are only reclaimed for authors who have actually gone quiet.
        prune_rate_windows(&mut seen, later, Duration::from_secs(1));
        assert!(
            seen.contains_key(&(room, alice)),
            "Alice just spoke, so she keeps her slot"
        );
        assert!(
            !seen.contains_key(&(room, bob)),
            "Bob has been silent past the window"
        );
    }

    /// Answering a catch-up is the one exchange that costs the receiver more
    /// than the sender, so it gets a budget of its own rather than sharing the
    /// chat one — and that budget has to be far below what chat allows.
    #[test]
    fn history_sync_has_a_tighter_budget_than_chat_and_is_per_room() {
        const {
            assert!(
                CHANNEL_HISTORY_SYNC_PER_MIN < CHANNEL_GOSSIP_PER_AUTHOR_PER_SEC,
                "a request answered with CHANNEL_HISTORY_SYNC_MAX sealed frames must not be \
                 admitted at the per-second rate plain chat is"
            );
        }

        let mut seen = HashMap::new();
        let room = [0x01u8; 16];
        let other_room = [0x02u8; 16];
        let alice = [0xAAu8; 32];
        let bob = [0xBBu8; 32];
        let start = Instant::now();

        for i in 0..CHANNEL_HISTORY_SYNC_PER_MIN {
            assert!(
                history_sync_allow(&mut seen, room, &alice, start),
                "request {i} is inside the budget"
            );
        }
        assert!(
            !history_sync_allow(&mut seen, room, &alice, start),
            "one past the budget is refused"
        );
        assert!(
            history_sync_allow(&mut seen, room, &bob, start),
            "another member has their own allowance"
        );
        assert!(
            history_sync_allow(&mut seen, other_room, &alice, start),
            "and Alice still has a full one in a different room"
        );
        // A minute on, the window has rolled off and the honest five-minute
        // catch-up is admitted again.
        assert!(history_sync_allow(
            &mut seen,
            room,
            &alice,
            start + Duration::from_secs(61)
        ));
    }

    /// The hop count cannot travel under the AEAD, because every relay has to
    /// change it. Clamping on the way in is what stops an originator writing
    /// 255 and having the mesh carry one frame two hundred hops.
    #[test]
    fn an_inflated_hop_budget_is_clamped_on_ingest() {
        let key = [0x33u8; 32];
        let channel_id = [0x44u8; 16];
        let mut wire = ChannelGossip::new_plaintext(channel_id, &key, 1, b"hello", 255).encode();
        assert_eq!(wire[33], 255, "the sender put an inflated hop count on it");

        let decoded = ChannelGossip::decode(&wire).expect("still a well-formed frame");
        assert_eq!(decoded.ttl, CHANNEL_MSG_TTL_DEFAULT);
        assert_eq!(
            decoded.decrypt(&key).as_deref(),
            Some(b"hello".as_slice()),
            "clamping the hop count must not disturb the sealed body"
        );

        // A budget under the ceiling is honoured as sent, not raised to it.
        wire[33] = 3;
        assert_eq!(ChannelGossip::decode(&wire).unwrap().ttl, 3);
    }

    /// Dedup spends a message's id before the body can be decrypted, so a
    /// rate-limited message must hand its id back or every retransmit reads as
    /// a flood cycle and the message is lost on this node permanently.
    #[test]
    fn a_forgotten_gossip_id_can_be_admitted_again() {
        let mut seen = HashMap::new();
        let mut order = VecDeque::new();
        let msg = [0x5Au8; 16];
        let other = [0x11u8; 16];
        let now = Instant::now();

        assert!(remember_gossip_id(&mut seen, &mut order, 8, msg, now));
        assert!(remember_gossip_id(&mut seen, &mut order, 8, other, now));
        assert!(
            !remember_gossip_id(&mut seen, &mut order, 8, msg, now),
            "a second copy is a cycle while the id is still held"
        );

        forget_gossip_id(&mut seen, &mut order, &msg);
        assert_eq!(order.len(), 1, "only the forgotten id leaves the order queue");
        assert!(
            remember_gossip_id(&mut seen, &mut order, 8, msg, now),
            "and the retransmit is admitted"
        );
        assert!(
            !remember_gossip_id(&mut seen, &mut order, 8, other, now),
            "unrelated ids are untouched"
        );

        // Forgetting something never remembered is a no-op, not a corruption.
        let before = order.len();
        forget_gossip_id(&mut seen, &mut order, &[0xEEu8; 16]);
        assert_eq!(order.len(), before);
    }

    /// Once the map is full an unknown author must be refused, not admitted
    /// untracked — otherwise a stream of invented authors walks straight past
    /// the limit that is meant to stop it.
    #[test]
    fn a_full_author_map_refuses_newcomers_rather_than_forgetting_them() {
        let mut seen = HashMap::new();
        let room = [0x07u8; 16];
        for i in 0..CHANNEL_GOSSIP_AUTHOR_CAP {
            let mut author = [0u8; 32];
            author[..8].copy_from_slice(&(i as u64).to_le_bytes());
            assert!(author_gossip_allow(&mut seen, room, &author, Instant::now()));
        }
        assert_eq!(seen.len(), CHANNEL_GOSSIP_AUTHOR_CAP);
        assert!(
            !author_gossip_allow(&mut seen, room, &[0xFFu8; 32], Instant::now()),
            "the map is full, so an untracked author is refused"
        );
        assert_eq!(
            seen.len(),
            CHANNEL_GOSSIP_AUTHOR_CAP,
            "and refusing does not grow the map"
        );
    }

    /// The per-hop budget has to sit above what our own protocol tells the far
    /// end to send, or it punishes the traffic it asked for. It used to sit at
    /// 8/sec while a receiver leaves a 64-block window outstanding and the
    /// sender answers the lot at `XFER_BLOCKS_OUT_PER_SEC`, so the opening
    /// burst of every transfer was mostly refused — and each refusal was
    /// scored as a protocol violation, banning the sender for a day well
    /// before the file had moved.
    #[test]
    fn a_transfer_window_fits_the_inbound_allowance_for_that_hop() {
        let limit = CHANNEL_GOSSIP_IN_PER_PEER_PER_SEC + CHANNEL_XFER_IN_PER_PEER_PER_SEC;
        assert!(
            limit >= XFER_BLOCKS_OUT_PER_SEC,
            "a hop mid-transfer must be admitted at the rate it is allowed to send"
        );
        let mut times = VecDeque::new();
        let now = Instant::now();
        for i in 0..XFER_WINDOW_BLOCKS {
            assert!(
                rate_window_allow(&mut times, now, Duration::from_secs(1), limit),
                "block {i} of one outstanding window must be admitted"
            );
        }
    }

    /// A neighbor answering a catch-up sends up to `CHANNEL_HISTORY_SYNC_MAX`
    /// sealed frames back to back, and does so without any transfer running.
    /// Shedding part of that reply is what left a new joiner with a
    /// hole-ridden scrollback and a five-minute wait before the next attempt.
    #[test]
    fn a_full_catch_up_reply_fits_the_base_inbound_allowance() {
        let mut times = VecDeque::new();
        let now = Instant::now();
        for i in 0..CHANNEL_HISTORY_SYNC_MAX {
            assert!(
                rate_window_allow(
                    &mut times,
                    now,
                    Duration::from_secs(1),
                    CHANNEL_GOSSIP_IN_PER_PEER_PER_SEC,
                ),
                "line {i} of one catch-up reply must land without a transfer running"
            );
        }
    }

    /// A full room has to stay one mesh. This is the property XOR-closest
    /// could not hold: it is prefix-closed, so any cluster of more than
    /// `CHANNEL_NEIGHBOR_COUNT` members spends every slot inside itself and
    /// seals off. The second half of the assertion is the reason
    /// [`gossip_neighbors`] exists at all — if someone ever simplifies it back
    /// to plain XOR-closest, this fails rather than shipping a room where two
    /// members cannot hear each other.
    #[test]
    fn a_full_room_stays_one_mesh_where_xor_closest_alone_shatters() {
        const N: usize = CHANNEL_MEMBERS_MAX;
        let members: Vec<[u8; 32]> = (0..N)
            .map(|i| {
                let mut pk = [0u8; 32];
                pk[..2].copy_from_slice(&(i as u16).to_le_bytes());
                pk[2] = 0x5E;
                pk
            })
            .collect();

        let index_of = |graph: &mut Vec<Vec<usize>>, picks: Vec<[u8; 32]>| {
            graph.push(
                picks
                    .into_iter()
                    .filter_map(|pk| members.iter().position(|m| *m == pk))
                    .collect(),
            );
        };
        let mut mesh: Vec<Vec<usize>> = Vec::with_capacity(N);
        let mut closest_only: Vec<Vec<usize>> = Vec::with_capacity(N);
        for pk in &members {
            index_of(
                &mut mesh,
                gossip_neighbors(pk, &members, CHANNEL_NEIGHBOR_COUNT),
            );
            index_of(
                &mut closest_only,
                xor_closest_neighbors(pk, &members, CHANNEL_NEIGHBOR_COUNT),
            );
        }

        for origin in 0..N {
            assert_eq!(
                directed_reach(&mesh, origin, CHANNEL_MSG_TTL_DEFAULT).len(),
                N,
                "member {origin} must reach the whole room within TTL"
            );
        }
        let stranded = directed_reach(&closest_only, 0, CHANNEL_MSG_TTL_DEFAULT).len();
        assert!(
            stranded < N,
            "XOR-closest alone is expected to strand most of a {N}-member room \
             (reached {stranded}); if that is no longer true the ring links can be revisited"
        );
    }

    /// Ring links are the half of the degree that has to be mutual: the
    /// rendezvous presence capability is pairwise, so an edge the far end does
    /// not also choose has nobody publishing an address under it.
    #[test]
    fn ring_links_are_mutual_and_survive_a_duplicated_roster() {
        let members: Vec<[u8; 32]> = (0..40u8)
            .map(|i| {
                let mut pk = [0u8; 32];
                pk[0] = i;
                pk[1] = 0x7C;
                pk
            })
            .collect();
        let mut mutual = 0usize;
        for pk in &members {
            for peer in gossip_neighbors(pk, &members, CHANNEL_NEIGHBOR_COUNT) {
                if gossip_neighbors(&peer, &members, CHANNEL_NEIGHBOR_COUNT).contains(pk) {
                    mutual += 1;
                }
            }
        }
        // Every node contributes at least its two ring links back.
        assert!(
            mutual >= members.len() * 2 * RING_NEIGHBORS_EACH_WAY,
            "ring links should always pair up, saw {mutual} mutual edges"
        );

        // A roster that names someone twice must not hand them two slots.
        let mut doubled = members.clone();
        doubled.extend_from_slice(&members);
        let picks = gossip_neighbors(&members[0], &doubled, CHANNEL_NEIGHBOR_COUNT);
        let mut unique = picks.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(picks.len(), unique.len(), "a duplicated roster duplicated a slot");
        assert!(!picks.contains(&members[0]), "never picks self");
        assert_eq!(
            picks,
            gossip_neighbors(&members[0], &members, CHANNEL_NEIGHBOR_COUNT),
            "selection must not depend on how many times the roster lists someone"
        );
    }

    /// Rooms below the degree still have to work, including the two- and
    /// three-member cases where the ring wraps onto itself.
    #[test]
    fn tiny_rooms_pick_everyone_exactly_once() {
        for size in 1..=CHANNEL_NEIGHBOR_COUNT {
            let members: Vec<[u8; 32]> = (0..size as u8)
                .map(|i| {
                    let mut pk = [0u8; 32];
                    pk[0] = i;
                    pk[1] = 0x3B;
                    pk
                })
                .collect();
            let picks = gossip_neighbors(&members[0], &members, CHANNEL_NEIGHBOR_COUNT);
            let mut unique = picks.clone();
            unique.sort_unstable();
            unique.dedup();
            assert_eq!(picks.len(), unique.len(), "size {size} repeated a member");
            assert_eq!(
                picks.len(),
                size - 1,
                "size {size} should pick every other member and no more"
            );
            assert!(!picks.contains(&members[0]), "size {size} picked self");
        }
    }

    /// Every periodic channel task compares wall-clock seconds, and a stamp
    /// ahead of the clock used to read as a negative age — below every
    /// interval, so the task stopped running until real time caught up. On the
    /// presence republish that meant a member sitting in the room aged out of
    /// everyone else's roster for the length of the skew.
    #[test]
    fn a_backwards_clock_jump_does_not_wedge_a_schedule() {
        let now = 1_700_000_000i64;
        let interval = 600i64;

        assert!(!schedule_due(now, now, interval), "just ran");
        assert!(!schedule_due(now - interval + 1, now, interval), "not yet");
        assert!(schedule_due(now - interval, now, interval), "exactly due");
        assert!(schedule_due(0, now, interval), "never run is due");
        assert!(
            schedule_due(now + 1, now, interval),
            "a stamp one second ahead is a clock correction, not a recent run"
        );
        assert!(
            schedule_due(now + 86_400, now, interval),
            "and a day ahead must not stall the task for a day"
        );
    }

    /// The hop map refuses unseen hops once full, so it is the budget that
    /// most needs sweeping. Leaving it out of the sweep turned a long session
    /// deaf to every peer it had not already spoken to, until a restart.
    #[test]
    fn pruning_reclaims_hop_slots_so_a_full_map_admits_newcomers_again() {
        let mut hops: HashMap<[u8; 16], VecDeque<Instant>> = HashMap::new();
        let start = Instant::now();
        for i in 0..CHANNEL_GOSSIP_IN_PEER_CAP {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            hops.entry(id).or_default().push_back(start);
        }
        assert_eq!(
            hops.len(),
            CHANNEL_GOSSIP_IN_PEER_CAP,
            "the map is full, which is where an unseen hop starts being refused"
        );

        // One hop is still talking to us; the rest went quiet two minutes ago.
        let later = start + Duration::from_secs(120);
        let mut busy = [0u8; 16];
        busy[..8].copy_from_slice(&0u64.to_le_bytes());
        hops.entry(busy).or_default().push_back(later);

        prune_rate_windows(&mut hops, later, Duration::from_secs(60));
        assert_eq!(hops.len(), 1, "only the hop still sending keeps its slot");
        assert!(hops.contains_key(&busy));
    }

    /// Rotation is only an eviction if the member who was removed cannot open
    /// the new key. That rests entirely on the wrapping key being pairwise, so
    /// this pins both directions: the two parties agree, and nobody else can
    /// reach it.
    #[test]
    fn an_epoch_key_is_readable_by_its_recipient_and_nobody_else() {
        let owner = SigningKey::generate(&mut OsRng);
        let member = SigningKey::generate(&mut OsRng);
        let evicted = SigningKey::generate(&mut OsRng);
        let owner_pub = owner.verifying_key().to_bytes();
        let member_pub = member.verifying_key().to_bytes();
        let channel_id = [0x31u8; 16];
        let room_key = [0x5Eu8; 32];
        let epoch = 7i64;

        // Owner seals to the member; the member derives the same wrapping key
        // from their own seed and the owner's identity.
        let owner_side =
            derive_channel_epoch_secret(&owner.to_bytes(), &member_pub, &channel_id, epoch)
                .expect("owner derives");
        let member_side =
            derive_channel_epoch_secret(&member.to_bytes(), &owner_pub, &channel_id, epoch)
                .expect("member derives");
        assert_eq!(owner_side, member_side, "static DH has to be symmetric");

        let sealed = seal_channel_key_epoch(&owner_side, &channel_id, epoch, &room_key);
        assert!(epoch_envelope_store_ok(&sealed));
        assert_eq!(
            open_channel_key_epoch(&member_side, &channel_id, epoch, &sealed),
            Some(room_key)
        );

        // The evicted member holds the room's old key and every pubkey in it,
        // and still cannot derive this wrapping key.
        let evicted_side =
            derive_channel_epoch_secret(&evicted.to_bytes(), &owner_pub, &channel_id, epoch)
                .expect("derives, just not the right one");
        assert_ne!(evicted_side, owner_side);
        assert_eq!(
            open_channel_key_epoch(&evicted_side, &channel_id, epoch, &sealed),
            None,
            "an evicted member must not be able to open the epoch that removed them"
        );

        // Room and epoch are bound, so a blob cannot be replayed across either.
        assert_eq!(
            open_channel_key_epoch(&member_side, &[0x32u8; 16], epoch, &sealed),
            None
        );
        assert_eq!(
            open_channel_key_epoch(&member_side, &channel_id, epoch + 1, &sealed),
            None
        );

        // And the DHT slot is per member, per epoch, per room.
        assert_ne!(
            epoch_key(&channel_id, &member_pub, epoch),
            epoch_key(&channel_id, &member_pub, epoch + 1)
        );
        assert_ne!(
            epoch_key(&channel_id, &member_pub, epoch),
            epoch_key(&channel_id, &owner_pub, epoch)
        );
        assert_ne!(
            epoch_key(&channel_id, &member_pub, epoch),
            epoch_key(&[0x32u8; 16], &member_pub, epoch)
        );

        // Malformed envelopes are refused rather than mistaken for a key.
        let mut truncated = sealed.clone();
        truncated.pop();
        assert!(!epoch_envelope_store_ok(&truncated));
        assert_eq!(
            open_channel_key_epoch(&member_side, &channel_id, epoch, &truncated),
            None
        );
        let mut tampered = sealed.clone();
        tampered[EPOCH_ENVELOPE_LEN - 1] ^= 0xFF;
        assert_eq!(
            open_channel_key_epoch(&member_side, &channel_id, epoch, &tampered),
            None
        );
    }

    #[test]
    fn handoff_key_differs_from_moderation_and_binds_id() {
        let a = [0x11u8; 16];
        let b = [0x22u8; 16];
        assert_ne!(handoff_key(&a), moderation_key(&a));
        assert_ne!(handoff_key(&a), handoff_key(&b));
        assert_eq!(handoff_key(&a), handoff_key(&a));
    }

    #[test]
    fn handoff_offer_requires_old_channel_key() {
        let channel = ChannelIdentity::generate();
        let sender = [0x11u8; 32];
        let target = [0x22u8; 32];
        let bytes = encode_channel_handoff_offer(
            &channel.channel_id,
            &channel.signing_key,
            &sender,
            &target,
            9,
        );
        assert_eq!(
            decode_channel_handoff_offer(&bytes, &channel.channel_id, &channel.pubkey),
            Some((sender, target, 9))
        );
        let other = ChannelIdentity::generate();
        assert!(decode_channel_handoff_offer(&bytes, &channel.channel_id, &other.pubkey).is_none());
        assert!(decode_channel_handoff_offer(&bytes, &[0u8; 16], &channel.pubkey).is_none());
    }

    #[test]
    fn handoff_ready_requires_the_nominees_user_key() {
        let nominee = SigningKey::generate(&mut OsRng);
        let nominee_pk = nominee.verifying_key().to_bytes();
        let successor = ChannelIdentity::generate();
        let room = [0x11u8; 16];
        let bytes = encode_channel_handoff_ready(
            &nominee,
            &room,
            &nominee_pk,
            &successor.pubkey,
            9,
        );
        assert_eq!(
            decode_channel_handoff_ready(&bytes, &room),
            Some((nominee_pk, successor.pubkey, 9))
        );
        let mallory = SigningKey::generate(&mut OsRng);
        let forged = encode_channel_handoff_ready(
            &mallory,
            &room,
            &nominee_pk,
            &successor.pubkey,
            9,
        );
        assert!(
            decode_channel_handoff_ready(&forged, &room).is_none(),
            "a Ready naming the nominee must be signed by the nominee"
        );
        assert!(decode_channel_handoff_ready(&bytes, &[0u8; 16]).is_none());
        let mut legacy = bytes[..73].to_vec();
        legacy[0] = 7;
        assert!(
            decode_channel_handoff_ready(&legacy, &room).is_none(),
            "unsigned Ready frames are refused"
        );
    }

    #[test]
    fn a_member_cannot_put_a_moderators_name_on_a_ban() {
        let moderator = SigningKey::generate(&mut OsRng);
        let mallory = SigningKey::generate(&mut OsRng);
        let moderator_pk = moderator.verifying_key().to_bytes();
        let target = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let mallory_frame = encode_channel_mod_action(
            &mallory,
            &moderator_pk,
            &target,
            true,
            &CHAT_CHANNEL,
            &CHAT_MSG_ID,
            CHAT_TS,
        );
        assert!(
            decode_channel_mod_action(&mallory_frame, &CHAT_CHANNEL, &CHAT_MSG_ID, CHAT_TS)
                .is_none()
        );
        let genuine = encode_channel_mod_action(
            &moderator,
            &moderator_pk,
            &target,
            true,
            &CHAT_CHANNEL,
            &CHAT_MSG_ID,
            CHAT_TS,
        );
        assert!(
            decode_channel_mod_action(&genuine, &[9u8; 16], &CHAT_MSG_ID, CHAT_TS).is_none()
        );
        let mut unsigned = vec![2u8];
        unsigned.extend_from_slice(&moderator_pk);
        unsigned.push(1);
        unsigned.extend_from_slice(&target);
        assert!(
            decode_channel_mod_action(&unsigned, &CHAT_CHANNEL, &CHAT_MSG_ID, CHAT_TS).is_none(),
            "unsigned mod frames are refused"
        );
    }

    #[test]
    fn gossip_timestamp_rejects_the_far_future() {
        let now = 1_700_000_000;
        assert!(gossip_timestamp_ok(now, now));
        assert!(gossip_timestamp_ok(now + CHANNEL_GOSSIP_MAX_FUTURE_SKEW_SECS, now));
        assert!(!gossip_timestamp_ok(
            now + CHANNEL_GOSSIP_MAX_FUTURE_SKEW_SECS + 1,
            now
        ));
        assert!(!gossip_timestamp_ok(0, now));
        assert!(!gossip_timestamp_ok(i64::MAX, now));
        assert!(gossip_timestamp_ok(1, now), "old timestamps stay admissible for catch-up");
    }

    #[test]
    fn handoff_extra_round_trip_binds_successor_id() {
        let successor = ChannelIdentity::generate();
        let extra = encode_handoff_extra(7, &successor.pubkey, HANDOFF_FLAG_KEEP_JOIN_SECRET);
        let (version, pk, id, flags) = decode_handoff_extra(&extra).unwrap();
        assert_eq!(version, 7);
        assert_eq!(pk, successor.pubkey);
        assert_eq!(id, successor.channel_id);
        assert_eq!(flags, HANDOFF_FLAG_KEEP_JOIN_SECRET);
        let mut broken = extra;
        broken[40] ^= 0xFF;
        assert!(decode_handoff_extra(&broken).is_none());
    }

    const K: [u8; 32] = [0x5Au8; 32];

    /// Verify with `K` and hand back the body, as the dispatcher does.
    fn opened(bytes: &[u8]) -> Vec<u8> {
        xfer_verify(&K, bytes).expect("frame must verify under its own key").to_vec()
    }

    fn sample_offer() -> XferOffer {
        XferOffer {
            sender: [0xAAu8; 32],
            target: [0xBBu8; 32],
            xfer_id: [7u8; 16],
            size: 5,
            root: *blake3::hash(b"hello").as_bytes(),
            name: "note.txt".into(),
        }
    }

    #[test]
    fn xfer_offer_round_trip_and_bounds() {
        let offer = sample_offer();
        assert_eq!(
            decode_xfer_offer(&opened(&encode_xfer_offer(&K, &offer))),
            Some(offer.clone())
        );

        let too_big = XferOffer {
            size: XFER_MAX_BYTES + 1,
            ..offer.clone()
        };
        assert!(decode_xfer_offer(&opened(&encode_xfer_offer(&K, &too_big))).is_none());

        let empty = XferOffer {
            size: 0,
            ..offer.clone()
        };
        assert!(decode_xfer_offer(&opened(&encode_xfer_offer(&K, &empty))).is_none());

        // A long name is truncated on a char boundary rather than refused.
        let long = XferOffer {
            name: "é".repeat(XFER_NAME_MAX),
            ..offer
        };
        let decoded = decode_xfer_offer(&opened(&encode_xfer_offer(&K, &long))).unwrap();
        assert!(decoded.name.len() <= XFER_NAME_MAX);
        assert!(long.name.starts_with(&decoded.name));
    }

    #[test]
    fn xfer_reply_and_cancel_round_trip() {
        let (s, t, id) = ([1u8; 32], [2u8; 32], [3u8; 16]);
        for reply in [
            XferReply::Accept,
            XferReply::Decline,
            XferReply::Busy,
            XferReply::TooLarge,
            XferReply::NotAllowed,
        ] {
            let bytes = encode_xfer_reply(&K, &s, &t, &id, reply);
            assert_eq!(decode_xfer_reply(&opened(&bytes)), Some((s, t, id, reply)));
        }
        for reason in [XferCancel::User, XferCancel::SourceGone, XferCancel::Stalled] {
            let bytes = encode_xfer_cancel(&K, &s, &t, &id, reason);
            assert_eq!(decode_xfer_cancel(&opened(&bytes)), Some((s, t, id, reason)));
        }
    }

    #[test]
    fn xfer_block_frames_round_trip() {
        let (s, t, id) = ([1u8; 32], [2u8; 32], [3u8; 16]);
        let req = encode_xfer_block_request(&K, &s, &t, &id, 4096, 8);
        assert_eq!(
            decode_xfer_block_request(&opened(&req)),
            Some((s, t, id, 4096, 8))
        );

        // A window-busting or empty run is refused rather than clamped: it can
        // only come from a peer that is not playing by the same rules.
        let greedy = encode_xfer_block_request(&K, &s, &t, &id, 0, XFER_WINDOW_BLOCKS as u16 + 1);
        assert!(decode_xfer_block_request(&opened(&greedy)).is_none());
        assert!(decode_xfer_block_request(&opened(&encode_xfer_block_request(
            &K, &s, &t, &id, 0, 0
        )))
        .is_none());

        let data = vec![9u8; XFER_BLOCK_SIZE];
        let frame = encode_xfer_block_data(&K, &s, &t, &id, 1024, &data).unwrap();
        let body = opened(&frame);
        let (gs, gt, gid, offset, got) = decode_xfer_block_data(&K, &body).unwrap();
        assert_eq!((gs, gt, gid, offset), (s, t, id, 1024));
        assert_eq!(got, data);

        // The payload has to be unreadable to anyone but the recipient. Only the
        // gossip envelope used to cover it, and that is sealed with the room's
        // content key -- which every member holds, and which a public room
        // derives from a pubkey anyone can look up.
        let on_wire = &body[XFER_HEADER_LEN + 8..body.len()];
        assert_ne!(
            on_wire, &data[..],
            "a block's bytes must not travel in the clear inside the room envelope"
        );
        assert_eq!(
            frame.len(),
            XFER_HEADER_LEN + 8 + data.len() + XFER_MAC_LEN,
            "sealing must not grow the frame, or the unfragmented budget moves"
        );

        // Somebody else's pairwise key opens nothing, even though the room key
        // got them this far.
        let (_, _, _, _, wrong) = decode_xfer_block_data(&[0xAAu8; 32], &body).unwrap();
        assert_ne!(wrong, data);

        // Per offset, so two blocks of identical bytes do not share a keystream.
        let other = encode_xfer_block_data(&K, &s, &t, &id, 2048, &data).unwrap();
        assert_ne!(opened(&other), body);

        assert!(encode_xfer_block_data(&K, &s, &t, &id, 0, &[]).is_none());
        assert!(
            encode_xfer_block_data(&K, &s, &t, &id, 0, &vec![0u8; XFER_BLOCK_SIZE + 1]).is_none()
        );
    }

    #[test]
    fn xfer_done_round_trips() {
        let (s, t, id) = ([1u8; 32], [2u8; 32], [3u8; 16]);
        let bytes = encode_xfer_done(&K, &s, &t, &id);
        assert_eq!(decode_xfer_done(&opened(&bytes)), Some((s, t, id)));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(xfer_verify(&K, &trailing).is_none());
    }

    /// The property the whole authenticator exists for: a room member holding
    /// the shared content key still cannot put another member's name on a
    /// transfer frame, because it cannot compute their pairwise key.
    #[test]
    fn a_frame_forged_under_another_key_does_not_verify() {
        let (s, t, id) = ([1u8; 32], [2u8; 32], [3u8; 16]);
        let forger = [0x99u8; 32];
        let frame = encode_xfer_reply(&forger, &s, &t, &id, XferReply::Accept);
        // The header still reads as a well-formed frame naming `s`...
        assert_eq!(xfer_frame_peek(&frame), Some((s, t, id)));
        // ...and that is exactly as far as it gets.
        assert!(xfer_verify(&K, &frame).is_none());
    }

    #[test]
    fn tampering_with_any_authenticated_byte_is_caught() {
        let offer = sample_offer();
        let frame = encode_xfer_offer(&K, &offer);
        for i in 0..frame.len() {
            let mut broken = frame.clone();
            broken[i] ^= 0x01;
            assert!(
                xfer_verify(&K, &broken).is_none(),
                "flipping byte {i} went unnoticed"
            );
        }
    }

    /// The key binds the room and the transfer, so a frame cannot be lifted
    /// out of one and replayed into another.
    #[test]
    fn the_transfer_key_binds_the_room_and_the_transfer() {
        let a = ChannelIdentity::generate();
        let b = ChannelIdentity::generate();
        let room = [0x31u8; 16];
        let other_room = [0x32u8; 16];
        let xfer = [7u8; 16];
        let other_xfer = [8u8; 16];

        let a_seed = a.signing_key.to_bytes();
        let b_seed = b.signing_key.to_bytes();

        // Both ends derive the same key without exchanging anything.
        let from_a = derive_xfer_key(&a_seed, &b.pubkey, &room, &xfer).unwrap();
        let from_b = derive_xfer_key(&b_seed, &a.pubkey, &room, &xfer).unwrap();
        assert_eq!(from_a, from_b);

        assert_ne!(
            from_a,
            derive_xfer_key(&a_seed, &b.pubkey, &other_room, &xfer).unwrap()
        );
        assert_ne!(
            from_a,
            derive_xfer_key(&a_seed, &b.pubkey, &room, &other_xfer).unwrap()
        );

        // A third member of the same room derives something else entirely.
        let c = ChannelIdentity::generate();
        assert_ne!(
            from_a,
            derive_xfer_key(&c.signing_key.to_bytes(), &b.pubkey, &room, &xfer).unwrap()
        );
    }

    /// Every answer has to name a status the UI knows, or a peer declining
    /// shows up as a bare "failed". These strings are the contract with
    /// `ChannelTransferStatus` on the TypeScript side.
    #[test]
    fn xfer_reply_statuses_are_the_ones_the_ui_renders() {
        assert_eq!(XferReply::Accept.as_str(), "accepted");
        assert_eq!(XferReply::Decline.as_str(), "declined");
        assert_eq!(XferReply::Busy.as_str(), "busy");
        assert_eq!(XferReply::TooLarge.as_str(), "too_large");
        assert_eq!(XferReply::NotAllowed.as_str(), "not_allowed");
        assert_eq!(XferCancel::User.as_str(), "cancelled");
        assert_eq!(XferCancel::SourceGone.as_str(), "source_gone");
        assert_eq!(XferCancel::Stalled.as_str(), "stalled");
    }

    #[test]
    fn xfer_frames_do_not_decode_as_each_other() {
        let (s, t, id) = ([1u8; 32], [2u8; 32], [3u8; 16]);
        let body = opened(&encode_xfer_reply(&K, &s, &t, &id, XferReply::Accept));
        assert!(decode_xfer_cancel(&body).is_none());
        assert!(decode_xfer_offer(&body).is_none());
        assert!(decode_xfer_block_request(&body).is_none());
        assert!(decode_xfer_block_data(&K, &body).is_none());
        assert!(decode_xfer_done(&body).is_none());
        // And the retired attachment versions are not mistaken for transfers,
        // nor picked up by the dispatcher's peek.
        for retired in [4u8, 5, 8] {
            let mut bytes = body.clone();
            bytes[0] = retired;
            assert!(decode_xfer_reply(&bytes).is_none());
            assert!(xfer_frame_peek(&bytes).is_none());
        }
        // Chat and handoff frames are not mistaken for transfer frames either.
        let author = SigningKey::generate(&mut OsRng);
        assert!(xfer_frame_peek(&chat_frame(&author, "hello there")).is_none());
        let sync = encode_channel_sync_request(
            &author,
            &author.verifying_key().to_bytes(),
            &CHAT_CHANNEL,
            &CHAT_MSG_ID,
            CHAT_TS,
            1,
        );
        assert!(xfer_frame_peek(&sync).is_none());
    }

    #[test]
    fn xfer_block_count_covers_the_tail() {
        assert_eq!(xfer_block_count(0), 0);
        assert_eq!(xfer_block_count(1), 1);
        assert_eq!(xfer_block_count(XFER_BLOCK_SIZE as u64), 1);
        assert_eq!(xfer_block_count(XFER_BLOCK_SIZE as u64 + 1), 2);
    }

    /// A block plus every wrapper has to fit one unfragmented datagram.
    ///
    /// Fragmented UDP is dropped outright by plenty of consumer NATs, so an
    /// oversized block would not be slow — it would never arrive, and the
    /// receiver would re-request it forever. The relay header is included
    /// because the firewalled path is the one that needs this most.
    #[test]
    fn xfer_block_frame_fits_one_unfragmented_datagram() {
        let budget = crate::network::ember::dht::messages::MAX_UNFRAGMENTED_PAYLOAD;
        let framed = XFER_HEADER_LEN
            + 8
            + XFER_BLOCK_SIZE
            + XFER_MAC_LEN
            + GOSSIP_HEADER_LEN
            + GOSSIP_ENVELOPE_OVERHEAD
            + CHANNEL_RELAY_ENVELOPE_HEADER;
        assert!(
            framed <= budget,
            "a block frame is {framed} bytes, over the {budget}-byte unfragmented budget — \
             lower XFER_BLOCK_SIZE rather than letting blocks fragment"
        );
    }

    fn directed_reach(neighbors: &[Vec<usize>], origin: usize, ttl: u8) -> HashSet<usize> {
        let mut reach = HashSet::from([origin]);
        let mut q = VecDeque::from([(origin, 0u8)]);
        while let Some((node, depth)) = q.pop_front() {
            if depth >= ttl {
                continue;
            }
            for &nbr in &neighbors[node] {
                if reach.insert(nbr) {
                    q.push_back((nbr, depth + 1));
                }
            }
        }
        reach
    }
}
