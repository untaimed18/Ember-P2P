use parking_lot::Mutex;

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key as ChaChaKey, XChaCha20Poly1305, XNonce};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, ErrorCode, OptionalExtension};
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::network::ed2k::transfer::TransferFailureCode;
use crate::network::ember::channel::{CHANNEL_MEMBERS_MAX, PRESENCE_FRESH_SECS};
use crate::network::ember::crypto::chat_body_hash;
use crate::storage::paths;
use crate::types::*;

const MAX_PEERS_ROWS: i64 = 10_000;
const MAX_DOWNLOAD_HISTORY_ROWS: i64 = 5_000;
/// Rooms kept in the Discover cache. Far more than a browse can usefully show,
/// and small enough that the table stays a rounding error on disk.
const MAX_CHANNEL_CACHE_ROWS: i64 = 500;
/// A cached listing this old has been absent from the DHT for many times the
/// index record's own lifetime, so offering it would only send the user at a
/// room that no longer answers.
const CHANNEL_CACHE_MAX_AGE_SECS: i64 = 30 * 24 * 3600;
/// Highest `schema_version` this build knows how to open. Opening a newer
/// database, or restoring a backup taken from one, would invite subtle
/// corruption (missing columns, renamed tables, changed semantics), so both
/// paths refuse instead. Bump this when introducing a new migration.
pub const MAX_SUPPORTED_SCHEMA_VERSION: i64 = 62;

/// Longest room name kept from a moderation snapshot. Keep in step with
/// `MAX_CHANNEL_NAME_CHARS` in `commands/channels.rs`, the cap an owner names
/// a room under.
const ROOM_NAME_MAX_CHARS: usize = 32;

/// [`StoredChannel::roster_count`] for the `channels` row aliased `c`.
///
/// A lifted ban leaves its row behind at `last_seen = 0`, naming someone this
/// device may never have seen in the room, so a never-seen row counts only
/// when it is a moderator — the owner's own record vouching for them.
const CHANNEL_ROSTER_COUNT_SQL: &str = "(SELECT COUNT(*) FROM channel_members r
                     WHERE r.channel_id = c.channel_id
                       AND r.banned = 0
                       AND (r.last_seen > 0 OR r.moderator = 1))";

/// A friend row with no public key bound to its hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashOnlyFriend {
    pub hash: [u8; 16],
    pub mutual: bool,
    /// Unix seconds of the last contact, or of the add if never seen.
    pub last_contact: i64,
}

/// One friend-chat row as the UI needs it.
#[derive(Debug, Clone)]
pub struct FriendChatRow {
    pub id: i64,
    pub direction: String,
    pub message: String,
    pub timestamp: i64,
    pub read: bool,
    pub delivery: i64,
    /// The friend has opened our sent message. Received rows stay false.
    pub seen: bool,
}

/// One chat attachment, as either side of it needs to see it.
#[derive(Debug, Clone)]
pub struct ChatAttachmentRow {
    /// Hex of the 16-byte transfer id.
    pub xfer_id: String,
    pub friend_hash: String,
    /// `"sent"` or `"received"`.
    pub direction: String,
    pub file_name: String,
    pub file_size: u64,
    /// Where a completed inbound file was written. `None` until it finishes,
    /// and always `None` on the sending side — the sender's own path is
    /// deliberately not exposed to anything that renders.
    pub dest_path: Option<String>,
    pub status: String,
    pub transferred: u64,
    pub created_at: i64,
}

/// One row of a room's history as the UI needs it.
///
/// A struct rather than the tuple this used to be: it had six fields and was
/// about to gain two more, and a positional `(i64, String, String, String, i64,
/// bool, i64, String)` at three call sites is a silent mismatch waiting to
/// happen.
#[derive(Debug, Clone)]
pub struct ChannelMessageRow {
    pub id: i64,
    pub sender_pubkey: String,
    pub direction: String,
    pub message: String,
    pub timestamp: i64,
    pub read: bool,
    /// 0 when the line has never been revised.
    pub edited_at: i64,
    /// Wire identity, needed to address reactions and revisions across devices.
    pub msg_id: String,
    /// [`CHAT_DELIVERED`] / [`CHAT_QUEUED`] / [`CHAT_FAILED`], reusing the
    /// friend-chat vocabulary because it means the same three things. Received
    /// rows are always delivered — we have it, which is the whole claim.
    pub delivery: i64,
    /// Hex wire id of the line this one replies to. `message` is the body alone;
    /// the signed trailer carrying this id is stripped on the way out.
    pub reply_to: Option<String>,
    /// That line as this device holds it now, or `None` when it is not here.
    pub reply_parent: Option<ChannelReplyParent>,
    /// The parent is missing because the user removed it from this device, as
    /// opposed to never having received it.
    pub reply_parent_deleted: bool,
}

/// What a reply's quote needs of the line it answers.
///
/// Read at the time the reply is read, so a parent revised since shows its
/// current words, and carried with the reply so the quote can be drawn — and
/// jumped to by row id — without the parent being among the loaded pages.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ChannelReplyParent {
    /// Local row id, which is what the transcript pages by.
    pub id: i64,
    pub sender_pubkey: String,
    /// The start of the parent's body, trailer removed. Bounded by
    /// [`Database::REPLY_EXCERPT_CHARS`]; the UI cuts it to one line.
    pub excerpt: String,
}

/// A reply's parent as this device knows it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChannelReplyLookup {
    pub parent: Option<ChannelReplyParent>,
    /// Absent because it was removed here; see [`ChannelMessageRow::reply_parent_deleted`].
    pub deleted: bool,
}

/// One line as it goes back on the wire for a member catching up.
///
/// An edited row is re-served as the *revision*, not as the original followed by
/// it: the edit frame carries the original's timestamp so it stands alone, which
/// halves the frames a catch-up costs and means the pre-edit text does not have
/// to be kept anywhere.
#[derive(Debug, Clone)]
pub struct ChannelSyncRow {
    pub msg_id: String,
    pub sender_pubkey: String,
    pub message: String,
    pub timestamp: i64,
    /// The author's signature over the line as first sent. Empty for a row this
    /// device only ever saw as a revision.
    pub author_sig: String,
    pub edited_at: i64,
    /// The author's signature over the revision. Empty if never revised.
    pub edit_sig: String,
}

/// What a caller needs to know before revising or reacting to a stored line.
#[derive(Debug, Clone)]
pub struct ChannelEditTarget {
    pub msg_id: String,
    pub sender_pubkey: String,
    pub direction: String,
    pub timestamp: i64,
    pub first_seen_at: i64,
    /// The parent this line replies to, so a revision can carry the same signed
    /// reference forward rather than silently turning the reply into a plain
    /// line.
    pub reply_to: Option<String>,
}

/// What a verified edit frame did to our copy of the line it names.
///
/// The refusals are values rather than errors because none of them is a fault:
/// they are the ordinary outcomes of a room with no arbiter of time or order,
/// and the caller logs them at debug and moves on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelEditOutcome {
    /// Applied to a line we already held. Carries the local row id so the UI can
    /// be told which bubble changed.
    Applied(i64),
    /// The line was not here, so the frame's own copy of it was stored. This is
    /// the catch-up path: a member who was away is handed the revision instead of
    /// the original followed by it.
    Created(i64),
    /// Signed by somebody other than the line's author — or, for a line we do
    /// not hold, by somebody the line's id does not prove to be its author.
    NotAuthor,
    /// The 15-minute window had closed on at least one of the two clocks.
    OutsideWindow,
    /// We already hold this revision or a later one.
    NotNewer,
    /// This device deleted the line, so its revision is not stored either.
    Forgotten,
}

/// One row of the eD2K `credits` table, in `load_credits` order. The
/// `bool` is the durable "has ever been cryptographically verified" anchor;
/// the two strings after it are the peer's Hello nickname and client
/// software (v47), and the last `u32` is the address of our latest session
/// with it (v52).
pub type CreditRow = (
    [u8; 16],
    u64,
    u64,
    i64,
    Vec<u8>,
    u32,
    u8,
    Option<[u8; 16]>,
    bool,
    String,
    String,
    u32,
);

/// Borrowed form of [`CreditRow`] used by the save path.
pub type CreditRowRef<'a> = (
    &'a [u8; 16],
    u64,
    u64,
    i64,
    &'a [u8],
    u32,
    u8,
    Option<&'a [u8; 16]>,
    bool,
    &'a str,
    &'a str,
    u32,
);

/// Borrowed `ember_credits` row, in `load_ember_credits` column order.
pub type EmberCreditRowRef<'a> = (&'a [u8; 32], u64, u64, i64, i64, u32, u32, u64, i64, bool);

/// One public room remembered from an earlier Discover walk.
///
/// A hint for what to draw while the DHT is being asked again, never an
/// assertion that the room is still there. The `last_seen` column behind this
/// orders and expires the cache in SQL; nothing in Rust needs to read it.
#[derive(Debug, Clone)]
pub struct CachedChannel {
    pub channel_id: String,
    pub pubkey: String,
    pub name: String,
    /// Default language code from the listing, empty for none.
    pub language: String,
}

/// The `channels.pinned_msg_ids` column: comma-separated hex wire ids. Anything
/// that is not one is skipped rather than failing the whole row.
fn parse_pinned_msg_ids(stored: &str) -> Vec<String> {
    stored
        .split(',')
        .map(str::trim)
        .filter(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_ascii_lowercase)
        .collect()
}

/// One joined channel, as listed in the Channels page.
#[derive(Debug, Clone)]
pub struct StoredChannel {
    pub channel_id: String,
    pub pubkey: String,
    pub name: String,
    pub visibility: String,
    pub is_owner: bool,
    pub topic: String,
    pub welcome: String,
    pub joined_at: i64,
    pub last_active: i64,
    pub member_count: i64,
    /// Everyone this device knows to be in the room, present or not: roster
    /// rows that are neither banned nor a placeholder left by a lifted ban.
    /// Unlike `member_count` it does not move as people come and go, which is
    /// what makes it usable as a sort key. 0 from the lite queries.
    pub roster_count: i64,
    pub unread: i64,
    /// Empty unless this room's owner published a successor mapping.
    pub successor_id: String,
    /// Empty unless we joined this room by following a handoff.
    pub predecessor_id: String,
    /// The owner's user pubkey (64-char hex) as published in their signed
    /// moderation record, or empty when we have not learned it. Load-bearing:
    /// it is the only thing that lets a member refuse a moderator's ban aimed
    /// at the owner.
    pub owner_pubkey: String,
    /// Current content-key epoch for a private room. 0 means the room has
    /// never rotated and still uses `join_secret` as minted.
    pub key_epoch: i64,
    /// Owner-nominated successor (64-char hex), empty when unset.
    pub successor_nominee: String,
    /// Days of owner silence before that nomination may be claimed. 0 disables
    /// succession, which leaves the room frozen if the owner never returns.
    pub claim_after_days: i64,
    /// Epoch the owner last announced. Ahead of `key_epoch` means we are behind
    /// and have an epoch record to go and fetch.
    pub key_epoch_wanted: i64,
    /// Timestamp of the newest owner-signed moderation record applied here.
    /// Doubles as the owner's liveness signal: they republish on a timer, so
    /// silence past `claim_after_days` is what lets a nomination be claimed.
    pub moderation_updated_at: i64,
    /// When we last got an answer back from a search for that record. Silence is
    /// only evidence of an absent owner if we have been asking.
    pub moderation_checked_at: i64,
    /// Whether this device is currently inside the room. Leave walks out
    /// without deleting the local row, so Join can reopen the same door.
    pub in_room: bool,
    /// Owner has permanently deleted this room. The row stays so the owner
    /// cannot recreate the same name by accident on this device.
    pub deleted: bool,
    /// The owner has asked that only they hand out invites. Carried on their
    /// signed moderation record; false for rooms whose owner never set it.
    pub invites_owner_only: bool,
    /// Seconds a member must wait between messages, 0 when the owner has not
    /// turned slow mode on. Carried on the signed moderation record.
    pub slow_mode_secs: i64,
    /// Only the owner and moderators may post. Carried on the signed
    /// moderation record; false for rooms whose owner never set it.
    pub announce_only: bool,
    /// Hex wire ids of the owner's pinned messages, oldest pin first.
    pub pinned_msg_ids: Vec<String>,
    /// Unix seconds of this device's last rename of a room it owns, 0 if never.
    /// Non-zero is what puts the name on the owner's moderation snapshot.
    pub renamed_at: i64,
    /// The room's default language code, empty for none. Carried on the
    /// signed moderation record; see `ModerationTail::language`.
    pub language: String,
}

impl StoredChannel {
    /// [`Self::pinned_msg_ids`] as the wire ids a moderation snapshot carries.
    pub fn pinned_msg_id_bytes(&self) -> Vec<[u8; 16]> {
        self.pinned_msg_ids
            .iter()
            .filter_map(|id| {
                let mut out = [0u8; 16];
                hex::decode_to_slice(id, &mut out).ok()?;
                Some(out)
            })
            .collect()
    }

    /// Presence, send, and gossip: only while we are actually in the room
    /// and it has not been tombstoned.
    pub fn in_room_now(&self) -> bool {
        self.in_room && !self.deleted
    }
}

/// The contents of one owner moderation snapshot, as
/// [`Database::apply_channel_moderation`] stores them. The trailing facts are
/// `None` when the record does not carry them.
#[derive(Debug, Clone, Copy)]
pub struct ModerationSnapshot<'a> {
    pub topic: &'a str,
    pub welcome: &'a str,
    pub banned_pubkeys: &'a [[u8; 32]],
    pub moderator_pubkeys: &'a [[u8; 32]],
    pub owner_pubkey: Option<&'a [u8; 32]>,
    pub successor_nominee: Option<&'a [u8; 32]>,
    pub claim_after_days: Option<u16>,
    pub key_epoch: Option<u64>,
    pub invites_owner_only: Option<bool>,
    pub slow_mode_secs: Option<u16>,
}

/// The room policy an owner snapshot carries beside the moderation fields.
/// See [`Database::apply_owner_room_policy`].
#[derive(Debug, Clone, Copy)]
pub struct OwnerRoomPolicy<'a> {
    pub announce_only: bool,
    pub pinned_msg_ids: &'a [[u8; 16]],
    pub language: Option<&'a str>,
}

/// How a moderation snapshot is weighed against the one this device holds.
#[derive(Debug, Clone, Copy)]
enum ModerationOrder<'a> {
    /// Applied by this device itself: by stamp alone, the way every snapshot
    /// was ordered before signatures were kept.
    Local,
    /// Fetched from the network: by stamp, then by this signature, and on a
    /// room this device owns only when stamped after all it has signed.
    Fetched(&'a [u8; 64]),
    /// The owner making an edit, which always applies.
    OwnerEdit,
}

/// Furthest ahead of now a stored owner stamp is still counted on from. See
/// [`Database::stamp_owner_snapshot`].
const OWNER_STAMP_MAX_LEAD_SECS: i64 = 10 * 60;

/// One member of a joined channel. `member_pubkey` is 64-char hex.
#[derive(Debug, Clone)]
pub struct StoredChannelMember {
    pub member_pubkey: String,
    pub nickname: String,
    pub last_seen: i64,
    pub banned: bool,
    pub moderator: bool,
}

/// What [`Database::upsert_channel_member`] did to the roster row.
///
/// Callers that drive the UI or XOR-neighbor registration need to tell a
/// no-op republish apart from a join or a last_seen/nick change: treating
/// every successful write as "someone new" re-registers rendezvous on every
/// presence walk, and treating none of them as a change leaves the roster
/// showing whoever was there when the list was last fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelMemberWrite {
    /// Row already had this last_seen (or newer) and this nickname.
    Unchanged,
    /// A new roster row. XOR-neighbors may have changed.
    Inserted,
    /// Only `last_seen` advanced — the same member, seen again.
    ///
    /// Split from [`ChannelMemberWrite::Updated`] because it is by far the
    /// commonest write and the cheapest to report: nothing about the row has
    /// changed except when it was last heard from, which is one number the UI
    /// can be handed directly. Reporting it as a general update made every
    /// presence walk that found a routine republish rebuild the whole member
    /// list, which in a full room is 256 rows serialised to answer "one of
    /// these is still here".
    Touched,
    /// The nickname changed, so anything displaying the row has to re-read it.
    Updated,
    /// A newcomer the roster cap turned away: the room is full of members who
    /// are neither stale nor exempt, so nothing was evicted and no row was kept.
    ///
    /// Distinct from [`ChannelMemberWrite::Unchanged`] because callers hold
    /// state beside the table — relay caches, key caches — that is meant to be
    /// bounded by the roster. Reporting a refusal as a no-op let those admit
    /// exactly the identities the roster had just refused.
    Refused,
}

/// Moved by every write to `channel_members` that a cached roster could
/// observe — a row added, removed, banned, unbanned or made moderator, or a
/// `last_seen` carried to fresh from stale or from nearly stale (see
/// [`channel_presence_revived`]) — so a caller holding a copy of a room's
/// roster can tell whether it is still what the table says. A `last_seen` that
/// moves well inside the fresh window does not count: nothing a snapshot
/// answers changes before it expires, and those writes are the commonest
/// there are.
///
/// Per room, hashed into a fixed set of slots: rooms sharing a slot only cost
/// each other an extra re-read. Process-wide rather than per `Database`, since
/// there is one store in production and a second (tests) is harmless here.
static CHANNEL_ROSTER_GENERATIONS: [std::sync::atomic::AtomicU64; 64] =
    [const { std::sync::atomic::AtomicU64::new(0) }; 64];

fn channel_roster_slot(channel_id: &str) -> &'static std::sync::atomic::AtomicU64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in channel_id.bytes() {
        hash ^= u64::from(byte.to_ascii_lowercase());
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    &CHANNEL_ROSTER_GENERATIONS[(hash % CHANNEL_ROSTER_GENERATIONS.len() as u64) as usize]
}

/// Must run *after* the write has committed. A reader samples the generation
/// before it reads the rows, so a bump that lands first lets it cache
/// pre-write rows under the post-write generation, where nothing would ever
/// notice they are stale.
fn bump_channel_roster_generation(channel_id: &str) {
    channel_roster_slot(channel_id).fetch_add(1, std::sync::atomic::Ordering::AcqRel);
}

/// The longest a cached roster may be served before it is read again, whatever
/// the generation says.
pub(crate) const CHANNEL_ROSTER_SNAPSHOT_TTL_SECS: i64 = 30;

/// Whether moving a roster row's `last_seen` from `before` to `after` changes
/// whether it counts as present at any time a snapshot taken now could still
/// be answering: now, or up to [`CHANNEL_ROSTER_SNAPSHOT_TTL_SECS`] later. A
/// row about to go stale that is touched without a bump would otherwise read
/// as absent from a still-valid snapshot until it expired, since the touch
/// buffer that covered it has been drained by the flush that wrote it.
fn channel_presence_revived(before: i64, after: i64, now: i64) -> bool {
    let cutoff = now.saturating_sub(PRESENCE_FRESH_SECS);
    before < cutoff.saturating_add(CHANNEL_ROSTER_SNAPSHOT_TTL_SECS) && after >= cutoff
}

/// What the transactional half of a handoff did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelHandoffTransition {
    Refused,
    AlreadyApplied,
    Applied,
}

/// A room we own that is spoken for by a handoff record we have begun
/// publishing. See [`Database::commit_channel_handoff`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelHandoffCommit {
    /// The member whose ready this answers, lowercase hex. Empty when the
    /// commitment was adopted from a record found in the DHT.
    pub nominee: String,
    pub version: u64,
    /// The successor room's pubkey, lowercase hex.
    pub successor_pubkey: String,
    /// When publishing began, or was last re-driven.
    pub committed_at: i64,
    /// Some node is known to hold the record.
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelHandoffCommitOutcome {
    /// Newly committed.
    Committed(ChannelHandoffCommit),
    /// Already committed to exactly this successor and version.
    Held(ChannelHandoffCommit),
    /// Committed to a different successor or version; this one is refused.
    Conflict,
    /// Not our room, already moved, or not the offer that is pending.
    NotPending,
}
const CHAT_KEY_FILE: &str = "chat-history.key";
const CHAT_CIPHERTEXT_PREFIX: &str = "EMBRCHAT1:";
const CHAT_UNAVAILABLE_TEXT: &str = "[Message unavailable]";
/// `chat_messages.delivery` states. Added in schema v24; every pre-existing
/// row defaults to `CHAT_DELIVERED` because it was only ever written after a
/// successful handoff.
pub const CHAT_DELIVERED: i64 = 0;
/// Stored locally, still waiting for a session to the friend.
pub const CHAT_QUEUED: i64 = 1;
/// Abandoned after exhausting retries; the user can resend explicitly.
pub const CHAT_FAILED: i64 = 2;
/// How long an outbound message may sit queued before it is abandoned.
///
/// A friend who is merely offline for a while should still receive what was
/// typed to them, so this is generous — but it has to be finite, or a message
/// to someone who never returns is retried on every reconnect forever and
/// counted as unsent for the life of the database.
const CHAT_QUEUE_MAX_AGE_SECS: i64 = 7 * 24 * 60 * 60;
/// How long a settled `chat_attachments` row (finished, refused, expired,
/// failed) stays in the transcript before it is deleted.
const CHAT_ATTACHMENT_RETENTION_SECS: i64 = 30 * 24 * 60 * 60;
/// How long an undelivered friend-request withdrawal keeps being retried. Same
/// ceiling as the chat outbox, for the same reason: the row holds the address of
/// someone the user has removed, so it must not be kept indefinitely on the
/// chance that they eventually reappear.
const RETRACTION_QUEUE_MAX_AGE_SECS: i64 = 7 * 24 * 60 * 60;
/// New friend requests one room may bring in an hour. A room carries a request
/// from any key it will carry at all, which in a public room is anyone's.
pub const ROOM_FRIEND_REQUESTS_PER_ROOM_HOUR: i64 = 5;
/// How long a refusal is remembered against a room request: past the oldest
/// envelope a room request is still acted on in, plus the clock skew allowed.
const FRIEND_REQUEST_REFUSAL_MEMORY_SECS: i64 =
    crate::network::ember::channel::ROOM_FRIEND_REQUEST_MAX_AGE_SECS
        + crate::network::ember::channel::CHANNEL_GOSSIP_MAX_FUTURE_SKEW_SECS;
const CHAT_NONCE_LEN: usize = 24;
const CHAT_AAD_DOMAIN: &[u8] = b"ember-chat-db-row-v1\0";
const CHANNEL_MSG_AAD_DOMAIN: &[u8] = b"ember-channel-db-row-v1\0";
const CHANNEL_SECRET_AAD_DOMAIN: &[u8] = b"ember-channel-secret-v1\0";
const CHANNEL_SECRET_PREFIX: &str = "EMBRCSEC1:";
const CHAT_ATTACH_AAD_DOMAIN: &[u8] = b"ember-chat-attachment-db-v1\0";
/// Marks a sealed `chat_attachments` name or path. A value without it is one
/// written before v60 that has not been sealed yet, and is read as it stands.
const CHAT_ATTACH_PREFIX: &str = "EMBRCATT1:";
/// Shown for an attachment whose name is sealed under a key this device no
/// longer holds.
const CHAT_ATTACH_UNAVAILABLE_NAME: &str = "[File name unavailable]";

pub struct Database {
    conn: Mutex<Connection>,
    /// Where `conn` was opened from, so a long read like
    /// [`Self::snapshot_to`] can open its own connection instead of holding
    /// the shared one.
    path: std::path::PathBuf,
    /// Dedicated random key for chat-history encryption. It is stored beside
    /// the database through `secret_store` (DPAPI on Windows) and zeroized
    /// when the last Database handle is dropped.
    /// `None` when chat is locked — the key could not be recovered, so history
    /// stays sealed and nothing new is stored, while the rest of the database
    /// works normally. See [`Self::load_or_create_chat_key`].
    chat_key: Option<Zeroizing<[u8; 32]>>,
    /// Set when `ember.db` was corrupt at open time and replaced after backup.
    /// Startup surfaces a non-silent notice (same pattern as config recovery).
    pub corrupt_backup: Option<std::path::PathBuf>,
}

#[derive(Debug)]
struct CorruptDatabase(String);

impl std::fmt::Display for CorruptDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "database integrity check failed: {}", self.0)
    }
}

impl std::error::Error for CorruptDatabase {}

impl Database {
    pub fn new(app_handle: &tauri::AppHandle) -> anyhow::Result<Self> {
        let app_dir = paths::ensure_data_dir_with_app(app_handle)
            .map_err(|e| anyhow::anyhow!("Failed to prepare data dir: {e}"))?;

        Self::open_for_session(&app_dir.join("ember.db"))
    }

    /// [`Self::new`] at an explicit path: open for a whole app session,
    /// replacing a corrupt database and recording the session marker.
    fn open_for_session(db_path: &std::path::Path) -> anyhow::Result<Self> {
        let db_path = db_path.to_path_buf();
        // `PRAGMA quick_check` reads every page of the database, on the main
        // thread, before the first window exists. What it guards against —
        // pages torn by a power cut or an OS crash — can only have happened if
        // the last session never reached its shutdown, so only then is it run.
        let marker = Self::session_marker_path(&db_path);
        let unclean = marker.exists();
        if unclean {
            tracing::warn!(
                "The previous session did not shut down cleanly; checking ember.db integrity"
            );
        }
        let opened = match Self::open_with(&db_path, unclean) {
            Ok(db) => Ok(db),
            Err(e) if db_path.exists() && Self::is_corruption_error(&e) => {
                let backup = Self::backup_corrupt_database(&db_path)?;
                tracing::warn!(
                    "ember.db was corrupt and has been preserved at {}; creating a fresh database",
                    backup.display()
                );
                let mut db = Self::open_at(&db_path).map_err(|retry| {
                    anyhow::anyhow!(
                        "Failed to initialize a fresh database after preserving the corrupt one at {}: {retry}",
                        backup.display()
                    )
                })?;
                db.corrupt_backup = Some(backup);
                Ok(db)
            }
            Err(e) => Err(e),
        }?;
        if let Err(error) = std::fs::write(&marker, b"") {
            tracing::debug!(
                "Could not record the session marker at {}: {error}",
                marker.display()
            );
        }
        Ok(opened)
    }

    /// Present from a successful open until [`Self::mark_clean_shutdown`].
    /// Named as an `ember.db` variant so the share denylist already covers it.
    fn session_marker_path(db_path: &std::path::Path) -> std::path::PathBuf {
        let mut marker = db_path.as_os_str().to_os_string();
        marker.push(".session");
        std::path::PathBuf::from(marker)
    }

    /// Record that this session reached its shutdown, so the next launch can
    /// skip the full integrity check.
    pub fn mark_clean_shutdown(&self) {
        let marker = Self::session_marker_path(&self.path);
        match std::fs::remove_file(&marker) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                "Could not clear the session marker at {}: {error}",
                marker.display()
            ),
        }
    }

    /// Open (or create) a database at an explicit path, running migrations and
    /// a full integrity check.
    ///
    /// `pub(crate)` so callers that already know the path can use it without a
    /// Tauri handle, notably the backup round-trip test.
    pub(crate) fn open_at(db_path: &std::path::Path) -> anyhow::Result<Self> {
        Self::open_with(db_path, true)
    }

    fn open_with(db_path: &std::path::Path, integrity_check: bool) -> anyhow::Result<Self> {
        // Repair ACLs before SQLite touches the main file or its WAL/SHM
        // sidecars. A prior ACL-hardening bug could leave those sidecars with
        // an empty DACL, in which case `Connection::open` fails before the
        // post-open permission pass has a chance to repair them.
        #[cfg(target_os = "windows")]
        {
            for path in std::iter::once(db_path.to_path_buf()).chain(
                ["-wal", "-shm"].into_iter().map(|suffix| {
                    let mut sidecar = db_path.as_os_str().to_os_string();
                    sidecar.push(suffix);
                    std::path::PathBuf::from(sidecar)
                }),
            ) {
                match std::fs::symlink_metadata(&path) {
                    Ok(_) => crate::security::restrict_file_permissions_checked(&path)?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    // An empty DACL makes metadata itself fail. Attempt ACL
                    // repair by pathname; the file owner still has WRITE_DAC.
                    Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                        crate::security::restrict_file_permissions_checked(&path)?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }

        let conn = Connection::open(db_path)?;
        crate::security::restrict_file_permissions_checked(db_path)?;
        let chat_key = Self::load_or_create_chat_key(db_path, &conn)?;

        if integrity_check {
            let quick_check: String =
                conn.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
            if !quick_check.eq_ignore_ascii_case("ok") {
                return Err(CorruptDatabase(quick_check).into());
            }
        }

        conn.execute_batch(
            // auto_vacuum must be set before journal_mode writes the DB
            // header. After WAL is enabled (or any table exists), changing
            // auto_vacuum requires an explicit VACUUM — see v21 migration.
            "PRAGMA auto_vacuum=INCREMENTAL;\
             PRAGMA journal_mode=WAL;\
             PRAGMA synchronous=FULL;\
             PRAGMA foreign_keys=ON;\
             PRAGMA secure_delete=ON;\
             PRAGMA busy_timeout=5000;",
        )?;
        // SQLite may create WAL/SHM sidecars as soon as journal_mode changes.
        // They contain the same sensitive rows as the main database.
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = db_path.as_os_str().to_os_string();
            sidecar.push(suffix);
            let sidecar = std::path::PathBuf::from(sidecar);
            if sidecar.exists() {
                crate::security::restrict_file_permissions_checked(&sidecar)?;
            }
        }

        let db = Self {
            conn: Mutex::new(conn),
            path: db_path.to_path_buf(),
            chat_key,
            corrupt_backup: None,
        };
        db.run_migrations()?;

        info!("Database initialized");
        Ok(db)
    }

    /// `Ok(None)` means chat is *locked*: the key could not be recovered, so
    /// history stays sealed and no new messages can be stored — but the rest of
    /// the database opens normally.
    ///
    /// This used to abort startup. Refusing to rotate the key or drop history is
    /// right, but taking the whole application down with it was not: downloads,
    /// the library and every setting became unreachable because chat history
    /// could not be read, and the explanation went only to the log. The key file
    /// is deliberately never overwritten here, so restoring it from backup still
    /// recovers the history afterwards.
    fn load_or_create_chat_key(
        db_path: &std::path::Path,
        conn: &Connection,
    ) -> anyhow::Result<Option<Zeroizing<[u8; 32]>>> {
        let key_path = db_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join(CHAT_KEY_FILE);
        // Wrapping a legacy plaintext key rewrites this file, so an interrupted
        // replace can park it. Reading that as missing seals the history behind
        // the "restore it from backup" path below while the key is sitting right
        // next to the database under its backup name.
        crate::security::recover_interrupted_replace(&key_path);
        match std::fs::read(&key_path) {
            Ok(stored) => {
                let was_protected = crate::storage::secret_store::is_protected(&stored);
                let plaintext = match crate::storage::secret_store::unprotect(&stored) {
                    Ok(plaintext) => plaintext,
                    Err(e) => {
                        warn!(
                            "Chat history is locked: the key at {} could not be recovered \
                             ({e}). Restore it under the original Windows account, unlock \
                             the login keyring on Linux, or restore from backup. Nothing has \
                             been rotated or deleted.",
                            key_path.display()
                        );
                        return Ok(None);
                    }
                };
                if plaintext.len() != 32 {
                    warn!(
                        "Chat history is locked: the key at {} has invalid length {} \
                         (expected 32). Nothing has been rotated or deleted.",
                        key_path.display(),
                        plaintext.len()
                    );
                    return Ok(None);
                }
                // `Zeroizing` from the moment the key exists, not once it
                // reaches the struct field: a bare `[u8; 32]` local is copied
                // out by value on every return and never wiped, so the key
                // stays readable in the freed stack frames of `Database::new`.
                let mut key = Zeroizing::new([0u8; 32]);
                key.copy_from_slice(&plaintext);
                // Transparently wrap a legacy restricted plaintext key, and
                // likewise one sealed under a superseded scheme — a Unix
                // `EMBRSEC2`/`EMBRSEC3` blob is keyed by `$USER`, which a
                // launcher need not export, so it only stops depending on that
                // variable once rewritten. Never rewrite a key that failed
                // unprotect/validation: this is reached only after a successful
                // one.
                if !was_protected || crate::storage::secret_store::needs_rewrap(&stored) {
                    let protected = crate::storage::secret_store::protect(key.as_slice())?;
                    crate::security::atomic_write(&key_path, &protected, true)?;
                }
                Ok(Some(key))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Losing this file must never silently rotate the key while
                // encrypted rows still exist. That would make valid history
                // look corrupt and could encourage destructive recovery.
                let has_encrypted_rows = match Self::database_holds_chat_ciphertext(conn) {
                    Ok(found) => found,
                    Err(e) => {
                        // A query that cannot answer is not evidence of absence.
                        // Rotating on a failed probe is the one outcome that
                        // cannot be undone, so an unanswerable database seals.
                        warn!(
                            "Chat history is locked: the key is missing at {} and whether \
                             encrypted rows exist could not be established ({e}). Nothing \
                             has been rotated or deleted.",
                            key_path.display()
                        );
                        return Ok(None);
                    }
                };
                if has_encrypted_rows {
                    // Lock rather than rotate. Writing a new key here would make
                    // the existing history permanently unreadable even if the
                    // original key were restored later, so the file is left
                    // untouched and chat stays sealed until it comes back.
                    warn!(
                        "Chat history is locked: the key is missing at {} while encrypted \
                         history exists. Restore it from backup to read it again. Nothing \
                         has been rotated or deleted.",
                        key_path.display()
                    );
                    return Ok(None);
                }
                let mut key = Zeroizing::new([0u8; 32]);
                OsRng.fill_bytes(key.as_mut_slice());
                let protected = crate::storage::secret_store::protect(key.as_slice())?;
                crate::security::atomic_write(&key_path, &protected, true)?;
                Ok(Some(key))
            }
            Err(error) => {
                // Unreadable for some other reason (permissions, I/O). Same
                // treatment: seal chat, leave the file alone, open everything
                // else.
                warn!(
                    "Chat history is locked: failed to read the key at {}: {error}",
                    key_path.display()
                );
                Ok(None)
            }
        }
    }

    /// Every column sealed with the chat key, as `(table, ciphertext predicate)`.
    ///
    /// Direct messages are only one of them. A profile that never opened a DM
    /// still has room history, join secrets, epoch keys and a parked handoff
    /// seed under this key, and treating `chat_messages` as the whole story
    /// rotates all of that away.
    ///
    /// Both prefixes are matched with case-sensitive GLOB, matching
    /// `starts_with` elsewhere: under LIKE a plaintext body beginning
    /// `embrchat1:` would count as ciphertext and seal chat permanently instead
    /// of minting a fresh key.
    const CHAT_KEYED_COLUMNS: [(&'static str, &'static str); 6] = [
        ("chat_messages", "message GLOB 'EMBRCHAT1:*'"),
        ("channel_messages", "message GLOB 'EMBRCHAT1:*'"),
        (
            "channels",
            "join_secret GLOB 'EMBRCSEC1:*' OR owner_seed GLOB 'EMBRCSEC1:*'",
        ),
        ("channel_key_epochs", "secret_enc GLOB 'EMBRCSEC1:*'"),
        ("channel_handoff_pending", "owner_seed GLOB 'EMBRCSEC1:*'"),
        (
            "chat_attachments",
            "file_name GLOB 'EMBRCATT1:*' OR source_path GLOB 'EMBRCATT1:*' \
             OR dest_path GLOB 'EMBRCATT1:*'",
        ),
    ];

    /// Whether anything in the database is still sealed under the chat key.
    ///
    /// Errors propagate rather than reading as `false`: the caller may only mint
    /// a replacement key once absence has actually been established.
    fn database_holds_chat_ciphertext(conn: &Connection) -> rusqlite::Result<bool> {
        for (table, predicate) in Self::CHAT_KEYED_COLUMNS {
            // A table missing from an older schema cannot hold ciphertext, and
            // naming it in a prepared statement would fail before the predicate
            // ever ran.
            let table_exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master \
                 WHERE type='table' AND name=?1)",
                [table],
                |row| row.get(0),
            )?;
            if !table_exists {
                continue;
            }
            // Interpolated from `CHAT_KEYED_COLUMNS` only: compile-time literals,
            // never anything a caller or peer supplied.
            let found: bool = conn.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {predicate} LIMIT 1)"),
                [],
                |row| row.get(0),
            )?;
            if found {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether chat history is sealed because its key could not be recovered.
    ///
    /// Everything else in the database works; this exists so the UI can say why
    /// chat is empty and unusable instead of leaving the user guessing.
    pub fn chat_locked(&self) -> bool {
        self.chat_key.is_none()
    }

    fn require_chat_key(&self) -> anyhow::Result<&[u8; 32]> {
        self.chat_key.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "Chat history is locked: its encryption key could not be recovered. \
                 Restore the key file from backup to read or send messages."
            )
        })
    }

    fn chat_row_aad(id: i64, friend_hash: &str, direction: &str, timestamp: i64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            CHAT_AAD_DOMAIN.len() + 8 + 8 + 4 + friend_hash.len() + 4 + direction.len(),
        );
        aad.extend_from_slice(CHAT_AAD_DOMAIN);
        aad.extend_from_slice(&id.to_le_bytes());
        aad.extend_from_slice(&timestamp.to_le_bytes());
        aad.extend_from_slice(&(friend_hash.len() as u32).to_le_bytes());
        aad.extend_from_slice(friend_hash.as_bytes());
        aad.extend_from_slice(&(direction.len() as u32).to_le_bytes());
        aad.extend_from_slice(direction.as_bytes());
        aad
    }

    fn encrypt_chat_body(
        key: &[u8; 32],
        id: i64,
        friend_hash: &str,
        direction: &str,
        timestamp: i64,
        plaintext: &str,
    ) -> anyhow::Result<String> {
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
        let mut nonce = [0u8; CHAT_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let aad = Self::chat_row_aad(id, friend_hash, direction, timestamp);
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("Failed to encrypt chat history row"))?;
        let mut envelope = Vec::with_capacity(CHAT_NONCE_LEN + encrypted.len());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&encrypted);
        Ok(format!(
            "{CHAT_CIPHERTEXT_PREFIX}{}",
            STANDARD_NO_PAD.encode(envelope)
        ))
    }

    fn decrypt_chat_body(
        key: &[u8; 32],
        id: i64,
        friend_hash: &str,
        direction: &str,
        timestamp: i64,
        stored: &str,
    ) -> anyhow::Result<String> {
        let encoded = stored.strip_prefix(CHAT_CIPHERTEXT_PREFIX).ok_or_else(|| {
            anyhow::anyhow!("Chat history row {id} is not encrypted; refusing plaintext fallback")
        })?;
        let envelope = STANDARD_NO_PAD
            .decode(encoded)
            .map_err(|_| anyhow::anyhow!("Chat history row {id} has an invalid ciphertext"))?;
        if envelope.len() < CHAT_NONCE_LEN + 16 {
            anyhow::bail!("Chat history row {id} has a truncated ciphertext");
        }
        let aad = Self::chat_row_aad(id, friend_hash, direction, timestamp);
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&envelope[..CHAT_NONCE_LEN]),
                Payload {
                    msg: &envelope[CHAT_NONCE_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "Chat history authentication failed for row {id}; the database or key may \
                     be damaged. Restore both from the same backup."
                )
            })?;
        String::from_utf8(plaintext)
            .map_err(|_| anyhow::anyhow!("Chat history row {id} decrypted to invalid UTF-8"))
    }

    fn friend_chat_body_hash_hex(message: &str) -> String {
        hex::encode(chat_body_hash(message))
    }

    /// Fill `body_hash` on rows written before schema v45, so a later receipt
    /// can still name them. Failures leave the hash empty rather than aborting
    /// the migration: those lines simply never show as seen.
    fn backfill_chat_body_hashes(tx: &Connection, key: &[u8; 32]) -> anyhow::Result<u32> {
        let rows: Vec<(i64, String, String, i64, String)> = {
            let mut stmt = tx.prepare(
                "SELECT id, friend_hash, direction, timestamp, message \
                 FROM chat_messages WHERE body_hash = ''",
            )?;
            let mapped = stmt.query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };
        let mut filled = 0u32;
        for (id, friend_hash, direction, timestamp, stored) in rows {
            let Ok(plain) =
                Self::decrypt_chat_body(key, id, &friend_hash, &direction, timestamp, &stored)
            else {
                continue;
            };
            tx.execute(
                "UPDATE chat_messages SET body_hash = ?1 WHERE id = ?2",
                params![Self::friend_chat_body_hash_hex(&plain), id],
            )?;
            filled += 1;
        }
        Ok(filled)
    }

    fn channel_secret_aad(channel_id: &str, label: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            CHANNEL_SECRET_AAD_DOMAIN.len() + 4 + channel_id.len() + 4 + label.len(),
        );
        aad.extend_from_slice(CHANNEL_SECRET_AAD_DOMAIN);
        aad.extend_from_slice(&(channel_id.len() as u32).to_le_bytes());
        aad.extend_from_slice(channel_id.as_bytes());
        aad.extend_from_slice(&(label.len() as u32).to_le_bytes());
        aad.extend_from_slice(label.as_bytes());
        aad
    }

    fn encrypt_channel_secret(
        key: &[u8; 32],
        channel_id: &str,
        label: &str,
        plaintext: &[u8; 32],
    ) -> anyhow::Result<String> {
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
        let mut nonce = [0u8; CHAT_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let aad = Self::channel_secret_aad(channel_id, label);
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("Failed to encrypt channel secret"))?;
        let mut envelope = Vec::with_capacity(CHAT_NONCE_LEN + encrypted.len());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&encrypted);
        Ok(format!(
            "{CHANNEL_SECRET_PREFIX}{}",
            STANDARD_NO_PAD.encode(envelope)
        ))
    }

    fn decrypt_channel_secret(
        key: &[u8; 32],
        channel_id: &str,
        label: &str,
        stored: &str,
    ) -> anyhow::Result<[u8; 32]> {
        let encoded = stored
            .strip_prefix(CHANNEL_SECRET_PREFIX)
            .ok_or_else(|| anyhow::anyhow!("Channel secret for {channel_id} is not encrypted"))?;
        let envelope = STANDARD_NO_PAD.decode(encoded).map_err(|_| {
            anyhow::anyhow!("Channel secret for {channel_id} has invalid ciphertext")
        })?;
        if envelope.len() < CHAT_NONCE_LEN + 16 {
            anyhow::bail!("Channel secret for {channel_id} is truncated");
        }
        let aad = Self::channel_secret_aad(channel_id, label);
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&envelope[..CHAT_NONCE_LEN]),
                Payload {
                    msg: &envelope[CHAT_NONCE_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| {
                anyhow::anyhow!("Channel secret authentication failed for {channel_id}")
            })?;
        <[u8; 32]>::try_from(plaintext)
            .map_err(|_| anyhow::anyhow!("Channel secret for {channel_id} has invalid length"))
    }

    fn channel_row_aad(id: i64, channel_id: &str, direction: &str, timestamp: i64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            CHANNEL_MSG_AAD_DOMAIN.len() + 8 + 8 + 4 + channel_id.len() + 4 + direction.len(),
        );
        aad.extend_from_slice(CHANNEL_MSG_AAD_DOMAIN);
        aad.extend_from_slice(&id.to_le_bytes());
        aad.extend_from_slice(&timestamp.to_le_bytes());
        aad.extend_from_slice(&(channel_id.len() as u32).to_le_bytes());
        aad.extend_from_slice(channel_id.as_bytes());
        aad.extend_from_slice(&(direction.len() as u32).to_le_bytes());
        aad.extend_from_slice(direction.as_bytes());
        aad
    }

    fn encrypt_channel_message_body(
        key: &[u8; 32],
        id: i64,
        channel_id: &str,
        direction: &str,
        timestamp: i64,
        plaintext: &str,
    ) -> anyhow::Result<String> {
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
        let mut nonce = [0u8; CHAT_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let aad = Self::channel_row_aad(id, channel_id, direction, timestamp);
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("Failed to encrypt channel message"))?;
        let mut envelope = Vec::with_capacity(CHAT_NONCE_LEN + encrypted.len());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&encrypted);
        Ok(format!(
            "{CHAT_CIPHERTEXT_PREFIX}{}",
            STANDARD_NO_PAD.encode(envelope)
        ))
    }

    fn decrypt_channel_message_body(
        key: &[u8; 32],
        id: i64,
        channel_id: &str,
        direction: &str,
        timestamp: i64,
        stored: &str,
    ) -> anyhow::Result<String> {
        let encoded = stored
            .strip_prefix(CHAT_CIPHERTEXT_PREFIX)
            .ok_or_else(|| anyhow::anyhow!("Channel message {id} is not encrypted"))?;
        let envelope = STANDARD_NO_PAD
            .decode(encoded)
            .map_err(|_| anyhow::anyhow!("Channel message {id} has invalid ciphertext"))?;
        if envelope.len() < CHAT_NONCE_LEN + 16 {
            anyhow::bail!("Channel message {id} is truncated");
        }
        let aad = Self::channel_row_aad(id, channel_id, direction, timestamp);
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&envelope[..CHAT_NONCE_LEN]),
                Payload {
                    msg: &envelope[CHAT_NONCE_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("Channel message {id} failed authentication"))?;
        String::from_utf8(plaintext)
            .map_err(|_| anyhow::anyhow!("Channel message {id} decrypted to invalid UTF-8"))
    }

    /// Binds a sealed attachment field to its row and column, so one cannot be
    /// moved onto another attachment or read back as a different field.
    fn chat_attach_aad(xfer_id: &str, column: &str) -> Vec<u8> {
        let mut aad =
            Vec::with_capacity(CHAT_ATTACH_AAD_DOMAIN.len() + 4 + xfer_id.len() + 4 + column.len());
        aad.extend_from_slice(CHAT_ATTACH_AAD_DOMAIN);
        aad.extend_from_slice(&(xfer_id.len() as u32).to_le_bytes());
        aad.extend_from_slice(xfer_id.as_bytes());
        aad.extend_from_slice(&(column.len() as u32).to_le_bytes());
        aad.extend_from_slice(column.as_bytes());
        aad
    }

    fn seal_attachment_field(
        key: &[u8; 32],
        xfer_id: &str,
        column: &str,
        plaintext: &str,
    ) -> anyhow::Result<String> {
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
        let mut nonce = [0u8; CHAT_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let aad = Self::chat_attach_aad(xfer_id, column);
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("Failed to seal a chat attachment field"))?;
        let mut envelope = Vec::with_capacity(CHAT_NONCE_LEN + encrypted.len());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&encrypted);
        Ok(format!("{CHAT_ATTACH_PREFIX}{}", STANDARD_NO_PAD.encode(envelope)))
    }

    /// Read a stored attachment field. `None` when it is sealed and cannot be
    /// opened here — the chat key is unavailable, or the value is damaged.
    fn open_attachment_field(
        key: Option<&[u8; 32]>,
        xfer_id: &str,
        column: &str,
        stored: &str,
    ) -> Option<String> {
        let Some(encoded) = stored.strip_prefix(CHAT_ATTACH_PREFIX) else {
            return Some(stored.to_string());
        };
        let envelope = STANDARD_NO_PAD.decode(encoded).ok()?;
        if envelope.len() < CHAT_NONCE_LEN + 16 {
            return None;
        }
        let aad = Self::chat_attach_aad(xfer_id, column);
        let plaintext = XChaCha20Poly1305::new(ChaChaKey::from_slice(key?))
            .decrypt(
                XNonce::from_slice(&envelope[..CHAT_NONCE_LEN]),
                Payload {
                    msg: &envelope[CHAT_NONCE_LEN..],
                    aad: &aad,
                },
            )
            .ok()?;
        String::from_utf8(plaintext).ok()
    }

    /// [`Self::seal_attachment_field`] under this database's chat key. Refused
    /// while chat is locked, which stores nothing new rather than storing it
    /// readable.
    fn seal_attachment_value(
        &self,
        xfer_id: &str,
        column: &str,
        plaintext: &str,
    ) -> anyhow::Result<String> {
        Self::seal_attachment_field(self.require_chat_key()?, xfer_id, column, plaintext)
    }

    fn is_corruption_error(error: &anyhow::Error) -> bool {
        error.chain().any(|cause| {
            if cause.downcast_ref::<CorruptDatabase>().is_some() {
                return true;
            }
            matches!(
                cause.downcast_ref::<rusqlite::Error>(),
                Some(rusqlite::Error::SqliteFailure(sqlite, _))
                    if matches!(
                        sqlite.code,
                        ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase
                    )
            )
        })
    }

    fn backup_corrupt_database(db_path: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
        let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
        let mut backup = db_path.with_extension(format!("db.{timestamp}.corrupt"));
        let mut suffix = 1u32;
        while backup.exists() && suffix < 1000 {
            backup = db_path.with_extension(format!("db.{timestamp}.{suffix}.corrupt"));
            suffix += 1;
        }

        Self::move_database_file(db_path, &backup)?;
        crate::security::restrict_file_permissions_checked(&backup)?;

        // Preserve WAL sidecars under matching backup names. Leaving a stale
        // sidecar beside the new database could make SQLite associate old
        // pages with the replacement file.
        for sidecar in ["-wal", "-shm"] {
            let mut source_name = db_path.as_os_str().to_os_string();
            source_name.push(sidecar);
            let source = std::path::PathBuf::from(source_name);
            if !source.exists() {
                continue;
            }
            let mut destination_name = backup.as_os_str().to_os_string();
            destination_name.push(sidecar);
            let destination = std::path::PathBuf::from(destination_name);
            Self::move_database_file(&source, &destination)?;
            crate::security::restrict_file_permissions_checked(&destination)?;
        }

        Ok(backup)
    }

    fn move_database_file(
        source: &std::path::Path,
        destination: &std::path::Path,
    ) -> anyhow::Result<()> {
        if std::fs::rename(source, destination).is_ok() {
            return Ok(());
        }
        std::fs::copy(source, destination).map_err(|e| {
            anyhow::anyhow!(
                "Failed to preserve corrupt database file {} at {}: {e}",
                source.display(),
                destination.display()
            )
        })?;
        std::fs::remove_file(source).map_err(|e| {
            anyhow::anyhow!(
                "Copied corrupt database file {} to {}, but could not remove the original: {e}",
                source.display(),
                destination.display()
            )
        })
    }

    /// Encrypt every chat body that is still stored as plaintext, through
    /// `conn` so the caller owns the transaction. Returns how many rows were
    /// rewritten.
    ///
    /// `authenticate_existing` also decrypts the rows that already carry the
    /// ciphertext marker, which the v23 migration requires: a partially
    /// prepared or hand-made database must prove those rows open, not merely
    /// carry the prefix. The deferred pass leaves them untouched and asks
    /// SQLite for the plaintext rows only, so it stays cheap enough to run on
    /// every open and cannot turn a damaged ciphertext row into a failed open.
    fn encrypt_chat_history_rows(
        &self,
        conn: &Connection,
        authenticate_existing: bool,
    ) -> anyhow::Result<usize> {
        let key = self.require_chat_key()?;
        let rows = {
            // GLOB rather than LIKE: SQLite's LIKE is ASCII case-insensitive, so
            // a plaintext body starting with e.g. `embrchat1:` would be filtered
            // out of the deferred pass, never encrypted (v23 has already run, so
            // it never runs again), and then fail the case-sensitive
            // `starts_with` on every read — [Message unavailable] forever.
            let mut stmt = conn.prepare(if authenticate_existing {
                "SELECT id, friend_hash, direction, message, timestamp \
                 FROM chat_messages ORDER BY id"
            } else {
                "SELECT id, friend_hash, direction, message, timestamp \
                 FROM chat_messages WHERE message NOT GLOB 'EMBRCHAT1:*' ORDER BY id"
            })?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut rewritten = 0usize;
        for (id, friend_hash, direction, stored, timestamp) in rows {
            if stored.starts_with(CHAT_CIPHERTEXT_PREFIX) {
                // A partially prepared/manual database must authenticate, not
                // merely carry the marker, before migration completes.
                //
                // A failure here does not fail the migration, because in a
                // pre-v23 database these bodies are plaintext straight off the
                // wire: a friend who opened a message with the marker text
                // produces a row that cannot decrypt, and propagating that error
                // aborted `run_migrations` — and with it every future database
                // open, deterministically, with no corruption path to recover
                // through. Treat it as the plaintext it is and encrypt it.
                if authenticate_existing
                    && Self::decrypt_chat_body(
                        key,
                        id,
                        &friend_hash,
                        &direction,
                        timestamp,
                        &stored,
                    )
                    .is_ok()
                {
                    continue;
                }
                if !authenticate_existing {
                    continue;
                }
                warn!(
                    "Chat message {id} carries the ciphertext marker but does not authenticate; \
                     treating it as plaintext that happened to start with it."
                );
            }
            let encrypted =
                Self::encrypt_chat_body(key, id, &friend_hash, &direction, timestamp, &stored)?;
            conn.execute(
                "UPDATE chat_messages SET message = ?1 WHERE id = ?2",
                params![encrypted, id],
            )?;
            rewritten += 1;
        }
        Ok(rewritten)
    }

    fn run_migrations(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock();

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL DEFAULT 0);",
        )?;
        let version: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        // Refuse to run against a database that was last opened by a newer
        // Ember build.
        if version > MAX_SUPPORTED_SCHEMA_VERSION {
            anyhow::bail!(
                "Database schema version {version} is newer than this Ember build supports \
                 (max {MAX_SUPPORTED_SCHEMA_VERSION}). The database was likely written by a \
                 more recent version of Ember. Install that version to access this data; \
                 refusing to start to avoid corruption."
            );
        }

        let set_version = |tx: &Connection, v: i64| -> anyhow::Result<()> {
            tx.execute("DELETE FROM schema_version", [])?;
            tx.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                params![v],
            )?;
            Ok(())
        };

        if version < 1 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "
                CREATE TABLE IF NOT EXISTS shared_files (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    path TEXT NOT NULL UNIQUE,
                    size INTEGER NOT NULL,
                    hash TEXT NOT NULL,
                    aich_hash TEXT NOT NULL DEFAULT '',
                    extension TEXT NOT NULL DEFAULT '',
                    modified_at INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS peers (
                    id TEXT PRIMARY KEY,
                    addresses TEXT NOT NULL DEFAULT '[]',
                    nickname TEXT NOT NULL DEFAULT '',
                    last_seen INTEGER NOT NULL DEFAULT 0,
                    files_shared INTEGER NOT NULL DEFAULT 0,
                    banned INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS transfers (
                    id TEXT PRIMARY KEY,
                    file_name TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    peer_id TEXT NOT NULL,
                    peer_name TEXT NOT NULL DEFAULT '',
                    direction TEXT NOT NULL,
                    status TEXT NOT NULL,
                    progress REAL NOT NULL DEFAULT 0.0,
                    speed INTEGER NOT NULL DEFAULT 0,
                    total_size INTEGER NOT NULL DEFAULT 0,
                    transferred INTEGER NOT NULL DEFAULT 0,
                    started_at INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_shared_files_hash ON shared_files(hash);
                CREATE INDEX IF NOT EXISTS idx_transfers_status ON transfers(status);
                ",
            )?;
            Self::add_column_if_missing(
                &tx,
                "shared_files",
                "aich_hash",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            set_version(&tx, 1)?;
            tx.commit()?;
        }

        if version < 2 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS credits (
                    user_hash BLOB PRIMARY KEY,
                    uploaded INTEGER NOT NULL DEFAULT 0,
                    downloaded INTEGER NOT NULL DEFAULT 0,
                    last_seen INTEGER NOT NULL DEFAULT 0,
                    public_key BLOB NOT NULL DEFAULT x''
                );",
            )?;
            set_version(&tx, 2)?;
            tx.commit()?;
        }

        if version < 3 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS statistics (
                    key TEXT PRIMARY KEY,
                    value INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS file_comments (
                    file_hash TEXT PRIMARY KEY,
                    rating INTEGER NOT NULL DEFAULT 0,
                    comment TEXT NOT NULL DEFAULT ''
                );",
            )?;
            set_version(&tx, 3)?;
            tx.commit()?;
        }

        if version < 4 {
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "shared_files",
                "shared",
                "INTEGER NOT NULL DEFAULT 1",
            )?;
            set_version(&tx, 4)?;
            tx.commit()?;
        }

        if version < 5 {
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "transfers",
                "priority",
                "TEXT NOT NULL DEFAULT 'normal'",
            )?;
            Self::add_column_if_missing(&tx, "transfers", "category", "TEXT NOT NULL DEFAULT ''")?;
            set_version(&tx, 5)?;
            tx.commit()?;
        }

        if version < 6 {
            // Back up the rows we're about to mass-UPDATE. If the TRIM
            // accidentally matches an unusual-but-valid value the original
            // rows can be recovered from `transfers_v5_backup`.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "DROP TABLE IF EXISTS transfers_v5_backup;
                 CREATE TABLE transfers_v5_backup AS
                     SELECT id, status, direction FROM transfers
                     WHERE status LIKE '\"%\"' OR direction LIKE '\"%\"';
                 UPDATE transfers SET status = TRIM(status, '\"') WHERE status LIKE '\"%\"';
                 UPDATE transfers SET direction = TRIM(direction, '\"') WHERE direction LIKE '\"%\"';",
            )?;
            set_version(&tx, 6)?;
            tx.commit()?;
        }

        if version < 7 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS friends (
                    user_hash TEXT PRIMARY KEY,
                    nickname TEXT NOT NULL DEFAULT '',
                    added_at INTEGER NOT NULL DEFAULT 0
                );",
            )?;
            set_version(&tx, 7)?;
            tx.commit()?;
        }

        if version < 8 {
            // v8 replaces shared_files/settings with file-based storage
            // (known.met + config.json). Preserve the legacy rows in
            // _backup tables instead of dropping outright so users upgrading
            // from v<8 aren't silently wiped — a subsequent admin/dev can
            // recover or export them if needed. These back-up tables are
            // never queried by the live app.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "DROP TABLE IF EXISTS shared_files_v7_backup;
                 DROP TABLE IF EXISTS settings_v7_backup;
                 DROP INDEX IF EXISTS idx_shared_files_hash;",
            )?;
            let has_shared: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='shared_files'",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            if has_shared > 0 {
                tx.execute_batch("ALTER TABLE shared_files RENAME TO shared_files_v7_backup;")?;
            }
            let has_settings: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='settings'",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            if has_settings > 0 {
                tx.execute_batch("ALTER TABLE settings RENAME TO settings_v7_backup;")?;
            }
            set_version(&tx, 8)?;
            tx.commit()?;
        }

        if version < 9 {
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "friends", "last_ip", "TEXT DEFAULT ''")?;
            Self::add_column_if_missing(&tx, "friends", "last_port", "INTEGER DEFAULT 0")?;
            Self::add_column_if_missing(&tx, "friends", "last_seen", "INTEGER DEFAULT 0")?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS chat_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    friend_hash TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    read INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_chat_messages_friend ON chat_messages(friend_hash, timestamp);",
            )?;
            set_version(&tx, 9)?;
            tx.commit()?;
        }

        if version < 10 {
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "friends", "mutual", "INTEGER NOT NULL DEFAULT 0")?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS friend_requests (
                    sender_hash TEXT PRIMARY KEY,
                    sender_nickname TEXT NOT NULL DEFAULT '',
                    received_at INTEGER NOT NULL DEFAULT 0
                );",
            )?;
            set_version(&tx, 10)?;
            tx.commit()?;
        }

        if version < 11 {
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "friend_requests", "sender_ip", "TEXT DEFAULT ''")?;
            Self::add_column_if_missing(
                &tx,
                "friend_requests",
                "sender_port",
                "INTEGER DEFAULT 0",
            )?;
            set_version(&tx, 11)?;
            tx.commit()?;
        }

        if version < 12 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS download_history (
                    file_hash TEXT NOT NULL PRIMARY KEY,
                    file_name TEXT NOT NULL DEFAULT '',
                    file_size INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    timestamp INTEGER NOT NULL
                );",
            )?;
            set_version(&tx, 12)?;
            tx.commit()?;
        }

        if version < 13 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE INDEX IF NOT EXISTS idx_chat_messages_read ON chat_messages(read);
                 CREATE INDEX IF NOT EXISTS idx_download_history_status ON download_history(status);",
            )?;
            set_version(&tx, 13)?;
            tx.commit()?;
        }

        if version < 14 {
            // Record whether each incoming friend request arrived on a
            // TCP channel where the peer's advertised Ed25519 pubkey
            // BLAKE3-bound to their claimed `ember_hash` (the offline
            // identity-binding check in
            // `crate::network::ember::crypto::verify_ember_hash_binding`).
            // Surfaces in the Friends UI as a "Verified" badge and is
            // taken into account by any future server-side checks that
            // gate friend-only features on a positive binding.
            //
            // Default `0` (unverified) for rows migrated from v13: we
            // have no record of the binding state of historical
            // requests, so the safest assumption is that they were
            // unverified. Re-sending a friend request will refresh the
            // flag per the latest exchange.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "friend_requests",
                "verified",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 14)?;
            tx.commit()?;
        }

        if version < 15 {
            // Phase 2 of the Ember Credit System: an enhanced credit
            // ledger keyed on the peer's 32-byte Ed25519 public key.
            // Sits alongside the existing eMule `credits` table rather
            // than replacing it — wire-compatible eMule peers continue
            // using the `credits` table via user_hash, and Ember peers
            // that completed PoP get a second higher-fidelity record
            // here that feeds decayed-ratio + reliability + speed
            // scoring.
            //
            // The pubkey column is `BLOB` (32 bytes) and acts as the
            // identity anchor — unlike user_hash it's cryptographically
            // bound to the peer's secret key, so this row can't be
            // farmed by spoofing the on-wire hash.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS ember_credits (
                    pub_key BLOB PRIMARY KEY,
                    uploaded INTEGER NOT NULL DEFAULT 0,
                    downloaded INTEGER NOT NULL DEFAULT 0,
                    last_upload_time INTEGER NOT NULL DEFAULT 0,
                    last_download_time INTEGER NOT NULL DEFAULT 0,
                    completed_sessions INTEGER NOT NULL DEFAULT 0,
                    total_sessions INTEGER NOT NULL DEFAULT 0,
                    avg_upload_speed INTEGER NOT NULL DEFAULT 0,
                    last_seen INTEGER NOT NULL DEFAULT 0,
                    ident_verified INTEGER NOT NULL DEFAULT 0
                );",
            )?;
            set_version(&tx, 15)?;
            tx.commit()?;
        }

        if version < 16 {
            // Notes (comments/ratings) we have explicitly published to the
            // KAD DHT. DHT note entries expire after ~24h, so we re-publish
            // them periodically; persisting the set here means republishing
            // survives restarts. `last_publish` is a Unix timestamp of the
            // most recent (re)publish. Distinct from `file_comments`, which
            // holds local comments on our *own* shared files exchanged over
            // ed2k and intentionally NOT broadcast to the DHT.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS published_notes (
                    file_hash TEXT PRIMARY KEY,
                    rating INTEGER NOT NULL DEFAULT 0,
                    comment TEXT NOT NULL DEFAULT '',
                    last_publish INTEGER NOT NULL DEFAULT 0
                );",
            )?;
            set_version(&tx, 16)?;
            tx.commit()?;
        }

        if version < 17 {
            // SecureIdent state for eMule credit records. Previously only
            // uploaded/downloaded/last_seen/public_key were persisted, so on
            // every restart `ident_ip` reset to 0 and `ident_state` to
            // Unknown. Because the Known Clients tab derives the last-known
            // IP *and* the country flag purely from `ident_ip`, both vanished
            // after a relaunch until the peer was seen again. Persisting them
            // makes those columns survive restarts. Defaults (0 / Unknown)
            // are correct for rows migrated from v16.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "credits", "ident_ip", "INTEGER NOT NULL DEFAULT 0")?;
            Self::add_column_if_missing(
                &tx,
                "credits",
                "ident_state",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 17)?;
            tx.commit()?;
        }

        if version < 18 {
            // Persistent store for *automatic* IP bans (corruption
            // blackbox, eMule-style AddRequestCount request-flooding).
            // Kept deliberately separate from the `peers` table so
            // machine-generated bans don't pollute the user-facing peer
            // list (and so the manual ban/unban UI, which is keyed on a
            // 32-hex user hash, never has to reason about bare IPs).
            //
            // `expires_at` is a Unix timestamp; 0 means "permanent".
            // Auto-bans set a finite expiry so the list is self-healing
            // and can't grow without bound the way the in-memory
            // `banned_ips` cache could before this existed. The startup
            // loader and the runtime `banned_ips` cap-reset both union
            // the non-expired rows back into the live ban set, so these
            // bans now survive both a restart and the 10k-entry cap
            // reset that previously discarded them.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS banned_ips (
                    ip TEXT PRIMARY KEY,
                    reason TEXT NOT NULL DEFAULT '',
                    banned_at INTEGER NOT NULL DEFAULT 0,
                    expires_at INTEGER NOT NULL DEFAULT 0
                );",
            )?;
            set_version(&tx, 18)?;
            tx.commit()?;
        }

        if version < 19 {
            // Preserve the file metadata that KAD note publishes need when
            // republishing after a restart and the file is not in our library.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "published_notes", "file_name", "TEXT")?;
            Self::add_column_if_missing(&tx, "published_notes", "file_size", "INTEGER")?;
            set_version(&tx, 19)?;
            tx.commit()?;
        }

        if version < 20 {
            // Link eD2K SecIdent credit rows to Ember node ids so the Known
            // Clients tab can mark friends (friends are keyed by ember hash).
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "credits", "ember_hash", "BLOB")?;
            set_version(&tx, 20)?;
            tx.commit()?;
        }

        if version < 21 {
            // Existing installs were created with `journal_mode=WAL` before
            // `auto_vacuum=INCREMENTAL`, which left auto_vacuum stuck at NONE
            // forever — `PRAGMA incremental_vacuum` then silently no-ops and
            // freed pages never return to the OS. Enable incremental vacuum
            // and drop unused legacy migration backup tables.
            //
            // VACUUM cannot run inside a transaction, so we set the version
            // after the maintenance steps (same pattern as other one-shot
            // maintenance migrations).
            let auto_vacuum: i64 = conn
                .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
                .unwrap_or(0);
            if auto_vacuum == 0 {
                // Must set the pragma, then VACUUM, for the file header to change.
                conn.execute_batch("PRAGMA auto_vacuum=INCREMENTAL; VACUUM;")?;
                info!("Enabled incremental auto_vacuum on existing database (v21)");
            }
            // Only drop a legacy snapshot this database already carried when
            // it was opened.
            //
            // `version` is read once, before any block runs, so a database
            // upgrading from below v6 or v8 in one jump executes the block
            // that *creates* these tables and this one that removes them
            // inside the same call. Dropping unconditionally therefore
            // destroyed the snapshot in the very upgrade that made it, which
            // is the opposite of what v6 and v8 promise: v8 says outright that
            // it preserves the rows "so users upgrading from v<8 aren't
            // silently wiped". Gating on the entry version means a snapshot is
            // only reclaimed once the user has had a session in which it could
            // have been recovered.
            let mut reclaim = String::new();
            if version >= 6 {
                reclaim.push_str("DROP TABLE IF EXISTS transfers_v5_backup;");
            }
            if version >= 8 {
                reclaim.push_str(
                    "DROP TABLE IF EXISTS shared_files_v7_backup;
                     DROP TABLE IF EXISTS settings_v7_backup;",
                );
            }
            if !reclaim.is_empty() {
                conn.execute_batch(&reclaim)?;
            }
            let tx = conn.unchecked_transaction()?;
            set_version(&tx, 21)?;
            tx.commit()?;
        }

        if version < 22 {
            // Optional trusted AICH master supplied by an ed2k link or
            // collection. Keeping it on the transfer row carries the pin
            // through pause/restart without changing any eMule wire format.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "transfers", "expected_aich", "TEXT")?;
            set_version(&tx, 22)?;
            tx.commit()?;
        }

        if version < 23 {
            // Encrypt all historical chat bodies atomically. The version is
            // advanced in the same transaction, so a crash leaves either the
            // complete plaintext v22 database (which retries migration) or a
            // complete encrypted v23 database—never a mixed committed state.
            let tx = conn.unchecked_transaction()?;
            // A few valid legacy/test databases carry only schema metadata
            // (for example, after an interrupted old migration or a targeted
            // auto-vacuum repair). Recreate the prerequisite tables before
            // adding v23 columns so migration remains idempotent instead of
            // failing with "no such table".
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS friends (
                    user_hash TEXT PRIMARY KEY,
                    nickname TEXT NOT NULL DEFAULT '',
                    added_at INTEGER NOT NULL DEFAULT 0,
                    last_ip TEXT DEFAULT '',
                    last_port INTEGER DEFAULT 0,
                    last_seen INTEGER DEFAULT 0,
                    mutual INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS friend_requests (
                    sender_hash TEXT PRIMARY KEY,
                    sender_nickname TEXT NOT NULL DEFAULT '',
                    received_at INTEGER NOT NULL DEFAULT 0,
                    sender_ip TEXT DEFAULT '',
                    sender_port INTEGER DEFAULT 0,
                    verified INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS chat_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    friend_hash TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    read INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_chat_messages_friend
                    ON chat_messages(friend_hash, timestamp);",
            )?;
            Self::add_column_if_missing(&tx, "friends", "ed25519_pubkey", "BLOB")?;
            Self::add_column_if_missing(&tx, "friend_requests", "sender_pubkey", "BLOB")?;
            // Encrypting the bodies needs the chat key, which may be
            // unrecoverable: `load_or_create_chat_key` then returns `None`, the
            // deliberate "chat is locked, everything else still works" state.
            // Failing here failed the whole open, so a locked key stopped the
            // application from launching at all. The schema work above must
            // still land — friends and friend requests depend on it — so v23
            // completes and the row pass is deferred to the first open that can
            // recover the key. Nothing is rotated, rewritten or dropped in the
            // meantime; the rows read as unavailable exactly like sealed
            // ciphertext does.
            let encrypted_now = if self.chat_key.is_some() {
                self.encrypt_chat_history_rows(&tx, true)?;
                true
            } else {
                warn!(
                    "Chat history is locked, so the v23 encryption pass is deferred: existing \
                     messages are left exactly as they are and will be encrypted on the first \
                     launch that recovers the key."
                );
                false
            };
            set_version(&tx, 23)?;
            tx.commit()?;

            if encrypted_now {
                // Remove plaintext remnants from WAL/free pages after the
                // transactional rewrite. `secure_delete=ON` protects released
                // cells; checkpoint+VACUUM also rewrites the main file so a raw
                // database scan cannot recover old message canaries.
                conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")?;
                info!("Encrypted local chat history (database v23)");
            }
        }

        if version < 24 {
            // Outbound chat used to be persisted only after a successful
            // handoff to a live session, so a message typed while a friend
            // was unreachable was simply lost. `delivery` lets a send be
            // stored up front and reconciled later.
            //
            // 0 = delivered to the peer's session (and every historical row,
            //     which is why the default matters), 1 = queued for the next
            //     time we reach them, 2 = gave up.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "chat_messages",
                "delivery",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            // Flushing scans by (friend, delivery) and expects oldest-first.
            tx.execute(
                "CREATE INDEX IF NOT EXISTS idx_chat_messages_delivery \
                 ON chat_messages (friend_hash, delivery, id)",
                [],
            )?;
            set_version(&tx, 24)?;
            tx.commit()?;
        }

        if version < 25 {
            // Removing a friend deletes the row, so it cannot also record that
            // the user wants nothing further from that identity: the same peer
            // can send another request straight away and, with approval
            // disabled, be promoted back to mutual without the user ever being
            // asked. Blocks therefore live in their own table, which outlives
            // the friendship it ended.
            //
            // The nickname is denormalised on purpose. Once the `friends` row
            // is gone there is nothing left to join against, and a list of
            // bare 32-character hashes gives the user no way to tell who they
            // blocked or who to unblock.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS friend_blocks (
                    user_hash TEXT PRIMARY KEY,
                    nickname TEXT NOT NULL DEFAULT '',
                    blocked_at INTEGER NOT NULL DEFAULT 0
                );",
            )?;
            set_version(&tx, 25)?;
            tx.commit()?;
        }

        if version < 26 {
            // The anti-credit-theft reset fires unless a record has ever been
            // cryptographically verified by us. That anchor has to be durable
            // and monotonic (eMule persists the equivalent `nKeySize` and only
            // ever writes it inside `Verified()`), because `ident_state` is
            // not: a stranger claiming a peer's user_hash can fail one
            // challenge and knock an established record out of `Verified`.
            // Deriving the anchor from `ident_state` at load would then wipe
            // that peer's accumulated credits on their next verification.
            let tx = conn.unchecked_transaction()?;
            // Guarded on the table existing so a partially-formed database
            // cannot turn this into a failed open, which would stop the app
            // launching entirely.
            let has_credits: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master \
                     WHERE type='table' AND name='credits')",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(false);
            if has_credits {
                Self::add_column_if_missing(
                    &tx,
                    "credits",
                    "crypto_verified_once",
                    "INTEGER NOT NULL DEFAULT 0",
                )?;
                // Existing rows get the one-time benefit of the doubt: a
                // persisted `Verified` (1) can only have been reached through a
                // real challenge, so treat it as the anchor rather than
                // resetting every peer the first time they reconnect after
                // this upgrade.
                tx.execute(
                    "UPDATE credits SET crypto_verified_once = 1 WHERE ident_state = 1",
                    [],
                )?;
            }
            set_version(&tx, 26)?;
            tx.commit()?;
        }

        if version < 27 {
            // Optional Ember content BLAKE3 supplied by an ed2k `eh=` link,
            // friend browse/offer, or collection. Keeping it on the transfer
            // row carries the pin through pause/restart the same way
            // `expected_aich` does.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "transfers", "ember_file_hash", "TEXT")?;
            set_version(&tx, 27)?;
            tx.commit()?;
        }

        if version < 28 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS channels (
                    channel_id TEXT PRIMARY KEY,
                    pubkey TEXT NOT NULL,
                    name TEXT NOT NULL,
                    visibility TEXT NOT NULL,
                    is_owner INTEGER NOT NULL DEFAULT 0,
                    owner_seed TEXT,
                    join_secret TEXT,
                    topic TEXT NOT NULL DEFAULT '',
                    welcome TEXT NOT NULL DEFAULT '',
                    joined_at INTEGER NOT NULL,
                    last_active INTEGER NOT NULL DEFAULT 0,
                    presence_published_at INTEGER NOT NULL DEFAULT 0,
                    moderation_updated_at INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS channel_members (
                    channel_id TEXT NOT NULL,
                    member_pubkey TEXT NOT NULL,
                    nickname TEXT NOT NULL DEFAULT '',
                    last_seen INTEGER NOT NULL DEFAULT 0,
                    banned INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (channel_id, member_pubkey)
                );
                CREATE TABLE IF NOT EXISTS channel_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    channel_id TEXT NOT NULL,
                    sender_pubkey TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    read INTEGER NOT NULL DEFAULT 0,
                    msg_id TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_channel_messages_dedup
                    ON channel_messages(channel_id, msg_id);
                CREATE INDEX IF NOT EXISTS idx_channel_messages_chan
                    ON channel_messages(channel_id, id);
                CREATE INDEX IF NOT EXISTS idx_channel_members_chan
                    ON channel_members(channel_id);",
            )?;
            set_version(&tx, 28)?;
            tx.commit()?;
        }

        if version < 29 {
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "moderation_updated_at",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 29)?;
            tx.commit()?;
        }

        if version < 30 {
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channel_members",
                "moderator",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            Self::add_column_if_missing(
                &tx,
                "channel_members",
                "ban_revised_at",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 30)?;
            tx.commit()?;
        }

        if version < 31 {
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "successor_id",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "predecessor_id",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "pending_successor",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "pending_handoff_version",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS channel_handoff_pending (
                    old_channel_id TEXT PRIMARY KEY,
                    version INTEGER NOT NULL,
                    successor_pubkey TEXT NOT NULL,
                    owner_seed TEXT,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS channel_attachments (
                    channel_id TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    sender_pubkey TEXT NOT NULL,
                    complete INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (channel_id, digest)
                );",
            )?;
            set_version(&tx, 31)?;
            tx.commit()?;
        }

        if version < 32 {
            // The owner's own user identity, learned from their signed
            // moderation record. Members need it to refuse a moderator's ban
            // gossip that names the owner: nothing else on the wire says which
            // pubkey owns a room, so before this every member applied such a
            // ban and silently dropped the owner's messages. Empty means "not
            // learned yet" — no record seen, or one predating the field.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "owner_pubkey",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            set_version(&tx, 32)?;
            tx.commit()?;
        }

        if version < 33 {
            // Private rooms rotate their content key so a ban can actually
            // evict: the join secret used to be minted once and baked into
            // every invite, which meant anyone who ever held one could read
            // the room forever. Each epoch's secret is stored under the chat
            // key like the others; `channels.key_epoch` names the current one,
            // and epoch 0 is the pre-rotation `join_secret` still in place.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "key_epoch",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS channel_key_epochs (
                    channel_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    secret_enc TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (channel_id, epoch)
                );",
            )?;
            // Succession: who may take a room over once its owner has gone
            // quiet, and for how long they must have been quiet. Both come
            // from the owner-signed moderation record. Either one empty or
            // zero means the owner has not set it up, and the room simply
            // freezes if they vanish — the status quo.
            Self::add_column_if_missing(
                &tx,
                "channels",
                "successor_nominee",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "claim_after_days",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            // The epoch the owner says is current, against `key_epoch` which is
            // the newest we actually hold a key for. Wanted ahead of held is
            // what sends a member looking for the record sealed to them.
            Self::add_column_if_missing(
                &tx,
                "channels",
                "key_epoch_wanted",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            // When a search for this room's owner record last came back, as
            // against `moderation_updated_at` which is how new that record was.
            // Succession needs both: an owner-silence window is only meaningful
            // if we have actually been asking, and locally "they have gone
            // quiet" is otherwise indistinguishable from "we have not looked".
            // Persisted rather than kept in memory so a restart cannot make a
            // month-old snapshot look freshly confirmed.
            Self::add_column_if_missing(
                &tx,
                "channels",
                "moderation_checked_at",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 33)?;
            tx.commit()?;
        }

        if version < 34 {
            // Room attachments are gone. They broadcast a file to everyone in
            // the room whether or not anybody asked for it, capped at 256 KB,
            // with no acknowledgement and no way to resume — so in practice a
            // transfer died a few kilobytes in and could not recover. Ember
            // Transfer replaces it: one member offers a file to one member,
            // who has to accept before any bytes move.
            //
            // The sealed blobs these rows pointed at live outside the database,
            // so startup removes the `channel-files` directory separately.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch("DROP TABLE IF EXISTS channel_attachments;")?;
            set_version(&tx, 34)?;
            tx.commit()?;
        }

        if version < 35 {
            // Discover began from nothing on every open: a cold DHT walk across
            // sixteen index shards with an empty list on screen until the
            // slowest of them answered, which on a table that had just started
            // warming meant the better part of a minute showing nothing. This
            // remembers what the last walk turned up so the browse can open on
            // it and replace the rows as fresh records land. Cache only — the
            // DHT stays the authority, and a listing here is never treated as
            // proof the room is still alive.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS channel_index_cache (
                    channel_id TEXT PRIMARY KEY,
                    pubkey TEXT NOT NULL,
                    name TEXT NOT NULL,
                    last_seen INTEGER NOT NULL DEFAULT 0
                );",
            )?;
            set_version(&tx, 35)?;
            tx.commit()?;
        }

        if version < 36 {
            // The author's own signature over a chat line, hex, empty when we
            // do not have one.
            //
            // History sync used to re-encode a stored message under whatever
            // `sender_pubkey` the row carried, which meant any member answering
            // a catch-up request could invent a conversation and attribute it to
            // anyone. Chat lines now carry an Ed25519 signature from their
            // author, and a re-serve has to replay that original rather than
            // mint a new one, so the signature has to survive in the row.
            //
            // Rows written before this are left empty and simply are not
            // re-served; their text is still readable locally.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channel_messages",
                "author_sig",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            set_version(&tx, 36)?;
            tx.commit()?;
        }

        if version < 37 {
            // Membership is presence: Leave walks out without wiping the row,
            // so Join can reopen the same door. Existing rows are rooms this
            // device already joined, so they start inside.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "in_room",
                "INTEGER NOT NULL DEFAULT 1",
            )?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "deleted",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 37)?;
            tx.commit()?;
        }

        if version < 38 {
            // Owner-only invites. Defaults off, which is the behaviour every
            // room had before the flag existed, so an upgraded database keeps
            // letting members invite until an owner says otherwise.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "invites_owner_only",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 38)?;
            tx.commit()?;
        }

        if version < 39 {
            // Owner slow mode. Zero is off, which is how every room behaved
            // before the field existed, so an upgraded database throttles
            // nobody until an owner asks for it.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "slow_mode_secs",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 39)?;
            tx.commit()?;
        }

        if version < 40 {
            // The slow-mode clock, moved off the message history.
            //
            // It used to be `MAX(timestamp)` over our own sent rows, which the
            // per-message delete button could remove: send, delete your own
            // line, send again, with no wait at all. Slow mode is documented as
            // a guard against a flood of *ordinary* clients, so a bypass
            // available from the stock UI defeated the whole point of it.
            //
            // Seeded from the history that is still there, so an upgrade does
            // not hand everyone one free message.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "last_sent_at",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            tx.execute(
                "UPDATE channels SET last_sent_at = COALESCE((
                     SELECT MAX(timestamp) FROM channel_messages m
                     WHERE m.channel_id = channels.channel_id AND m.direction = 'sent'
                 ), 0)",
                [],
            )?;
            set_version(&tx, 40)?;
            tx.commit()?;
        }

        if version < 41 {
            // Message revisions and reactions.
            //
            // `edited_at` of 0 means never revised, which is every row an
            // upgrade inherits. `edit_sig` keeps the author's signature over the
            // revision so a catch-up can replay it without this device being
            // able to author one, exactly as `author_sig` does for the original.
            //
            // `first_seen_at` is this device's own clock when the row first
            // landed, and is the half of the edit window an author cannot lie
            // about. Existing rows get 0, which
            // `channel::edit_within_window` reads as "judge this on the author's
            // clock alone" rather than refusing every edit to a line that
            // predates the upgrade.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channel_messages",
                "edited_at",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            Self::add_column_if_missing(
                &tx,
                "channel_messages",
                "edit_sig",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            Self::add_column_if_missing(
                &tx,
                "channel_messages",
                "first_seen_at",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            // One row per (line, member): a member holds one reaction at a time,
            // and changing it replaces rather than accumulates. `reacted_at`
            // orders competing claims the way `ban_revised_at` does for
            // moderation, so a stale frame arriving late cannot undo a newer
            // one. `sig` is kept so the entry can be re-served on a catch-up.
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS channel_message_reactions (
                    channel_id TEXT NOT NULL,
                    msg_id TEXT NOT NULL,
                    member_pubkey TEXT NOT NULL,
                    reaction INTEGER NOT NULL,
                    reacted_at INTEGER NOT NULL,
                    sig TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (channel_id, msg_id, member_pubkey)
                );
                CREATE INDEX IF NOT EXISTS idx_channel_reactions_msg
                    ON channel_message_reactions(channel_id, msg_id);",
            )?;
            set_version(&tx, 41)?;
            tx.commit()?;
        }

        if version < 42 {
            // Room work that has to outlive the process that decided to do it.
            //
            // Both of these were in-memory intentions, and both were lost by
            // closing the app in the wrong second. `rotate_pending` is set when a
            // delegated moderator's ban lands in a private room we own: only the
            // owner can mint an epoch record, so their ban is a label until we
            // rotate for them, and dropping the request meant it stayed one until
            // the next ban. `departure_due_at` is the presence tombstone that
            // says we left, which was published once and never retried — a
            // failed STORE left us on every other roster until we aged out.
            //
            // Both live on `channels` rather than in a work queue: they are
            // per-room facts with no ordering between them, and the loop that
            // acts on each already walks that table.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "rotate_pending",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "departure_due_at",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 42)?;
            tx.commit()?;
        }

        if version < 43 {
            // Lines this device has been told to forget.
            //
            // Deleting a message only removed the row, and the dedup gate on the
            // ingest path is "do we hold this msg_id" — so the next gossip
            // replay or catch-up that carried the line inserted it again and it
            // reappeared. Remembering the id is what makes "remove on this
            // device" survive the room still holding a copy.
            //
            // Deliberately not gossiped: the protocol has no redaction, and
            // publishing an id we want gone would only tell the room what to
            // look at.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS channel_message_tombstones (
                    channel_id TEXT NOT NULL,
                    msg_id TEXT NOT NULL,
                    deleted_at INTEGER NOT NULL,
                    PRIMARY KEY (channel_id, msg_id)
                );",
            )?;
            set_version(&tx, 43)?;
            tx.commit()?;
        }

        if version < 44 {
            // Friend requests we have withdrawn but not yet told the recipient
            // about.
            //
            // Cancelling was purely local: the request kept sitting on their
            // Friends page with no way to take it back. Telling them needs an
            // address, and removing a friend deletes the row that holds it, so
            // the address is copied here at the moment of removal.
            //
            // Only the hash and last address: the Noise handshake learns the
            // peer's key and checks it against the hash, so storing the key
            // would keep more about someone the user just removed than the
            // delivery actually needs.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS friend_request_retractions (
                    user_hash TEXT PRIMARY KEY,
                    last_ip TEXT NOT NULL DEFAULT '',
                    last_port INTEGER NOT NULL DEFAULT 0,
                    queued_at INTEGER NOT NULL DEFAULT 0
                );",
            )?;
            set_version(&tx, 44)?;
            tx.commit()?;
        }

        if version < 45 {
            // Friend-chat read receipts: `seen` is "they opened this sent
            // line", and `body_hash` is the truncated BLAKE3 of the plaintext
            // so a receipt can name a line without a shared row id or clock.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "chat_messages",
                "seen",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            Self::add_column_if_missing(
                &tx,
                "chat_messages",
                "body_hash",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            if let Some(key) = self.chat_key.as_deref() {
                Self::backfill_chat_body_hashes(&tx, key)?;
            }
            set_version(&tx, 45)?;
            tx.commit()?;
        }

        if version < 46 {
            // The unread tally in `get_channel`/`list_channels` filters
            // `read = 0 AND direction = 'received'`, and until now neither
            // column was indexed: SQLite seeked `channel_id` and then read
            // every message row for the room out of the table to test the two
            // predicates. At `MAX_MESSAGES_PER_CHANNEL` that is a 5,000-row
            // scan per room per call, which the once-a-second network tick
            // paid for every joined room. `chat_messages` has had
            // `idx_chat_messages_read` since v14; the channel table never got
            // the equivalent.
            //
            // Column order is `(channel_id, read, direction)` rather than
            // `(channel_id, direction, read)` so the `(channel_id, read)`
            // prefix also covers `mark_channel_messages_read`'s UPDATE. Both
            // shapes serve the COUNT equally (all three terms are equalities);
            // only this one serves both callers.
            //
            // The second index serves `channel_member_flags`, which answers
            // "am I banned / a moderator" for every room in one statement.
            // `channel_members` is keyed `(channel_id, member_pubkey)`, so
            // asking by member alone had no index to use and would scan the
            // whole roster table. `last_seen` is not in either index, so the
            // per-beacon presence touches do not pay to maintain them.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE INDEX IF NOT EXISTS idx_channel_messages_unread
                    ON channel_messages(channel_id, read, direction);
                 CREATE INDEX IF NOT EXISTS idx_channel_members_member
                    ON channel_members(member_pubkey);",
            )?;
            set_version(&tx, 46)?;
            tx.commit()?;
        }

        if version < 47 {
            // Who a known peer says it is: its Hello nickname and its client
            // software string.
            //
            // The credit ledger only ever stored accounting, so the Known
            // eD2K Peers tab could identify a row by 32 hex characters and
            // nothing else. These are the two things a person actually
            // recognises, and they have to be persisted rather than read from
            // a live session, because the tab is a *lifetime* view — almost
            // none of its rows have a session open.
            //
            // Columns on `credits` rather than a side table: they are keyed by
            // the same `user_hash`, they are written and pruned on exactly the
            // same schedule, and `save_all_credits` replaces the table
            // wholesale, so a separate table would only add a second thing to
            // keep in step with that replacement.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "credits", "peer_name", "TEXT NOT NULL DEFAULT ''")?;
            Self::add_column_if_missing(
                &tx,
                "credits",
                "client_software",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            set_version(&tx, 47)?;
            tx.commit()?;
        }

        if version < 48 {
            // Refusals owed to somebody whose request the user rejected.
            //
            // Its own table rather than a `kind` column on
            // `friend_request_retractions`: that one is keyed by `user_hash`
            // alone, and the two can both be owed to the same identity — they
            // are opposite directions of the same pair — so sharing it would
            // need the primary key rebuilt to hold both. A second table with
            // the same four columns costs one sweep and no migration risk to
            // the queue that already works.
            //
            // Only the hash and last address, for the reason the retraction
            // queue gives: the handshake learns the peer's key and checks it
            // against the hash, so storing the key would keep more about
            // somebody the user has just declined than delivery needs.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS friend_request_declines (
                    user_hash TEXT PRIMARY KEY,
                    last_ip TEXT NOT NULL DEFAULT '',
                    last_port INTEGER NOT NULL DEFAULT 0,
                    queued_at INTEGER NOT NULL DEFAULT 0
                );",
            )?;
            set_version(&tx, 48)?;
            tx.commit()?;
        }

        if version < 49 {
            // Whether an originated room line actually reached anybody.
            //
            // The network task has always known — a flood that found no
            // neighbour, no overlay hop and no relay is retried for ten
            // minutes and then dropped — but that lived only in memory, so a
            // line nobody received sat in the sender's own history looking
            // delivered, and a restart forgot even that. Same three values as
            // `chat_messages.delivery` because they mean the same things.
            //
            // Defaults to 0 (delivered), which is right for every row already
            // on disk: received lines are delivered by definition, and a sent
            // line old enough to be here has long since had whatever fate it
            // was going to have.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channel_messages",
                "delivery",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 49)?;
            tx.commit()?;
        }

        if version < 50 {
            // Three sweeps that had no index to stand on.
            //
            // `idx_chat_messages_delivery` is `(friend_hash, delivery, id)`,
            // which serves the per-friend flush. But `pending_chat_counts` and
            // `expire_stale_queued_chat` are deliberately *global* — one asks
            // "how many unsent, for every conversation", the other "which rows
            // have waited too long, anywhere" — so neither supplies the leading
            // `friend_hash` and neither could use that index. Both fell back to
            // scanning `chat_messages`, which is capped per friend rather than
            // in total and so grows with the friend list.
            //
            // `(delivery, direction, timestamp)`: the two equalities first, then
            // the range the expiry sweep tests and the column it would otherwise
            // sort. `pending_chat_counts` uses the `(delivery, direction)`
            // prefix and reads `friend_hash` out of the table for its GROUP BY.
            //
            // The third is the channel-side equivalent, for the sync catch-up
            // read: it filters one room with a `timestamp >=` range and orders by
            // timestamp, while `idx_channel_messages_chan` is `(channel_id, id)`
            // — so the room seek was indexed and the range and the sort were not.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE INDEX IF NOT EXISTS idx_chat_messages_queue
                    ON chat_messages(delivery, direction, timestamp);
                 CREATE INDEX IF NOT EXISTS idx_channel_messages_time
                    ON channel_messages(channel_id, timestamp);",
            )?;
            set_version(&tx, 50)?;
            tx.commit()?;
        }

        if version < 51 {
            // Chat attachments. One row is both halves of the same fact: on the
            // sending side it is the *grant* — the only thing that authorizes
            // one friend to read one path — and on the receiving side it is the
            // transfer's state. Persisted rather than held in memory because
            // both halves have to survive a restart: a grant so an interrupted
            // transfer can resume instead of the sender having to re-pick the
            // file, and the receiving state so a half-written `.part` is either
            // continued or cleaned up rather than orphaned.
            //
            // `source_path` is only ever set on the sending side and is never
            // sent anywhere. It is what makes an attachment servable without
            // being in the shared library, and it is the reason `expires_at`
            // exists: a grant nobody ever answered must stop being readable.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS chat_attachments (
                    xfer_id TEXT PRIMARY KEY,
                    friend_hash TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    root_hash TEXT NOT NULL,
                    source_path TEXT,
                    dest_path TEXT,
                    status TEXT NOT NULL,
                    transferred INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                 CREATE INDEX IF NOT EXISTS idx_chat_attachments_friend
                    ON chat_attachments(friend_hash, created_at);
                 CREATE INDEX IF NOT EXISTS idx_chat_attachments_status
                    ON chat_attachments(status, expires_at);",
            )?;
            set_version(&tx, 51)?;
            tx.commit()?;
        }

        if version < 52 {
            // Where we last saw a known peer, separate from `ident_ip`.
            //
            // `ident_ip` is only written once a SecIdent signature verifies,
            // because it is the address BadGuy detection compares against. The
            // Known Clients tab also took its IP and country flag from it, so
            // every peer that never finished a challenge with us — no SecIdent,
            // an abandoned exchange, or our own key unavailable — had neither.
            // Defaults to 0, which is what those rows effectively had.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "credits", "seen_ip", "INTEGER NOT NULL DEFAULT 0")?;
            set_version(&tx, 52)?;
            tx.commit()?;
        }

        if version < 53 {
            // A download from a friend who restricts the file to friends. The
            // flag has to outlive a restart: a resumed partial that forgot it
            // would be offered to servers and KAD the moment it came back.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "transfers",
                "friends_only",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 53)?;
            tx.commit()?;
        }

        if version < 54 {
            // The intro secret from a friend's `ember3:` code. Until they add
            // us back it is the only way to find them on the rendezvous
            // server, so a one-sided add must keep working across restarts.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "friends", "intro_secret", "BLOB")?;
            set_version(&tx, 54)?;
            tx.commit()?;
        }

        if version < 55 {
            // When the owner last renamed a room they own, or 0. Enforces the
            // registry's once-a-day rule before asking it, and tells the
            // moderation snapshot to carry the name to members.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "renamed_at",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 55)?;
            tx.commit()?;
        }

        if version < 56 {
            // The line a room message replies to, as its hex wire id, or NULL.
            //
            // Derived from the stored text rather than taken as a separate
            // input: the reference travels inside the signed text (see
            // `channel::with_reply_trailer`), and the text column keeps exactly
            // what was signed so a catch-up can re-serve it. The column exists
            // so reads can find the parent without re-parsing every body, and it
            // is fixed when the row is written — an edit cannot move a quote
            // after people have answered it. No backfill: no build before this
            // one wrote a trailer.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "channel_messages", "reply_to", "TEXT")?;
            set_version(&tx, 56)?;
            tx.commit()?;
        }

        if version < 57 {
            // Announcement-only rooms and pinned messages, both carried on the
            // owner's moderation snapshot. Off and none are how every room
            // behaved before, so an upgrade changes nothing until an owner
            // sets them. Pins are comma-separated hex wire ids, oldest first —
            // at most three, so a side table would buy nothing.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "announce_only",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "pinned_msg_ids",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            set_version(&tx, 57)?;
            tx.commit()?;
        }

        if version < 58 {
            // A room's default language, carried on the owner's moderation
            // snapshot. Empty is "none", which is every room until its owner
            // picks one.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "channels", "language", "TEXT NOT NULL DEFAULT ''")?;
            set_version(&tx, 58)?;
            tx.commit()?;
        }

        if version < 59 {
            // The language a room's public listing carries, cached with the
            // rest of the listing so Discover shows it before its walk returns.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channel_index_cache",
                "language",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            set_version(&tx, 59)?;
            tx.commit()?;
        }

        if version < 60 {
            // Attachment names and paths were the one part of a conversation
            // left readable on disk: which files a friend sent, and where on
            // this machine they and ours live. Sealed under the chat key like
            // the bodies beside them. With the key unavailable the rows are
            // left as they are and sealed on the first open that has it, the
            // same deferral v23 makes.
            let tx = conn.unchecked_transaction()?;
            let sealed = match self.chat_key.as_deref() {
                Some(key) => Self::seal_chat_attachment_rows(&tx, key)?,
                None => 0,
            };
            set_version(&tx, 60)?;
            tx.commit()?;
            if sealed > 0 {
                conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")?;
                info!("Sealed {sealed} chat attachment row(s) (database v60)");
            }
        }

        if version < 61 {
            // What orders two owner snapshots stamped in the same second, and
            // the newest stamp this device has signed for a room it owns. See
            // `apply_channel_moderation_locked` and `stamp_owner_snapshot`.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "channels", "moderation_sig", "BLOB")?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "owner_snapshot_at",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 61)?;
            tx.commit()?;
        }

        if version < 62 {
            // Friend requests that came through a room. `via_room` names the
            // room one arrived through, empty for one from a session, so room
            // requests can be capped per room and never push a session's out;
            // refusals are remembered past the window a room request is
            // accepted in, so a replay cannot put one back; and a friend asked
            // through rooms is asked less and less often, then not at all.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "friend_requests",
                "via_room",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS friend_request_refusals (
                    user_hash TEXT PRIMARY KEY,
                    refused_at INTEGER NOT NULL DEFAULT 0
                );",
            )?;
            Self::add_column_if_missing(&tx, "friends", "room_asks", "INTEGER NOT NULL DEFAULT 0")?;
            Self::add_column_if_missing(
                &tx,
                "friends",
                "room_asked_at",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 62)?;
            tx.commit()?;
        }

        // Finish a v23 encryption pass that was deferred because chat was
        // locked at the time. The version is already 23 or later, so the
        // migration itself will never run again — without this the history
        // would stay in plaintext on disk and unreadable forever, even once the
        // key came back. A database that migrated normally has no plaintext
        // bodies left, so this finds nothing and writes nothing.
        if self.chat_key.is_some() {
            let has_chat_table: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master \
                     WHERE type='table' AND name='chat_messages')",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(false);
            if has_chat_table {
                let tx = conn.unchecked_transaction()?;
                let encrypted = self.encrypt_chat_history_rows(&tx, false)?;
                let hashed = if let Some(key) = self.chat_key.as_deref() {
                    Self::backfill_chat_body_hashes(&tx, key)?
                } else {
                    0
                };
                if encrypted > 0 || hashed > 0 {
                    tx.commit()?;
                    if encrypted > 0 {
                        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")?;
                        info!(
                            "Encrypted {encrypted} chat history row(s) left in plaintext by a \
                             migration that ran while the chat key was unavailable"
                        );
                    }
                }
            }
            // The v60 pass, when it was deferred. Finds nothing once done.
            if let Some(key) = self.chat_key.as_deref() {
                let tx = conn.unchecked_transaction()?;
                let sealed = Self::seal_chat_attachment_rows(&tx, key)?;
                if sealed > 0 {
                    tx.commit()?;
                    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")?;
                    info!(
                        "Sealed {sealed} chat attachment row(s) left readable by a migration \
                         that ran while the chat key was unavailable"
                    );
                }
            }
        }

        Ok(())
    }

    /// Seal every attachment name and path still stored readable. Returns how
    /// many rows it rewrote.
    fn seal_chat_attachment_rows(tx: &Connection, key: &[u8; 32]) -> anyhow::Result<usize> {
        let has_table: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master \
             WHERE type='table' AND name='chat_attachments')",
            [],
            |row| row.get(0),
        )?;
        if !has_table {
            return Ok(0);
        }
        let rows: Vec<(String, String, Option<String>, Option<String>)> = {
            let mut stmt = tx.prepare(
                "SELECT xfer_id, file_name, source_path, dest_path FROM chat_attachments
                 WHERE file_name NOT GLOB 'EMBRCATT1:*'
                    OR (source_path IS NOT NULL AND source_path NOT GLOB 'EMBRCATT1:*')
                    OR (dest_path IS NOT NULL AND dest_path NOT GLOB 'EMBRCATT1:*')",
            )?;
            let mapped = stmt.query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };
        let reseal = |xfer_id: &str, column: &str, stored: &str| -> anyhow::Result<String> {
            if stored.starts_with(CHAT_ATTACH_PREFIX) {
                return Ok(stored.to_string());
            }
            Self::seal_attachment_field(key, xfer_id, column, stored)
        };
        for (xfer_id, file_name, source_path, dest_path) in &rows {
            let file_name = reseal(xfer_id, "file_name", file_name)?;
            let source_path = source_path
                .as_deref()
                .map(|path| reseal(xfer_id, "source_path", path))
                .transpose()?;
            let dest_path = dest_path
                .as_deref()
                .map(|path| reseal(xfer_id, "dest_path", path))
                .transpose()?;
            tx.execute(
                "UPDATE chat_attachments SET file_name = ?2, source_path = ?3, dest_path = ?4
                 WHERE xfer_id = ?1",
                params![xfer_id, file_name, source_path, dest_path],
            )?;
        }
        Ok(rows.len())
    }

    /// `schema_version` recorded in the open database.
    pub fn schema_version(&self) -> i64 {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0)
    }

    /// Record one chat attachment, on either side of it.
    ///
    /// `source_path` is set only by the sender and is what the grant lookup
    /// resolves to; the receiver passes `None` and fills `dest_path` when the
    /// file lands. Replaces any row with the same `xfer_id` so a re-offer of the
    /// same transfer cannot accumulate rows.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_chat_attachment(
        &self,
        xfer_id: &str,
        friend_hash: &str,
        direction: &str,
        file_name: &str,
        file_size: u64,
        root_hash: &str,
        source_path: Option<&str>,
        status: &str,
        created_at: i64,
        expires_at: i64,
    ) -> anyhow::Result<()> {
        let file_name = self.seal_attachment_value(xfer_id, "file_name", file_name)?;
        let source_path = source_path
            .map(|path| self.seal_attachment_value(xfer_id, "source_path", path))
            .transpose()?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO chat_attachments (
                xfer_id, friend_hash, direction, file_name, file_size, root_hash,
                source_path, dest_path, status, transferred, created_at, expires_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, 0, ?9, ?10)
             ON CONFLICT(xfer_id) DO UPDATE SET
                friend_hash = excluded.friend_hash,
                direction = excluded.direction,
                file_name = excluded.file_name,
                file_size = excluded.file_size,
                root_hash = excluded.root_hash,
                source_path = excluded.source_path,
                status = excluded.status,
                expires_at = excluded.expires_at",
            rusqlite::params![
                xfer_id,
                friend_hash,
                direction,
                file_name,
                file_size as i64,
                root_hash,
                source_path,
                status,
                created_at,
                expires_at,
            ],
        )?;
        Ok(())
    }

    /// The live grant for `xfer_id`, if `friend_hash` is who it was granted to.
    ///
    /// The friend is part of the lookup rather than something the caller checks
    /// afterwards, so a grant cannot be resolved for the wrong peer by a caller
    /// that forgets to compare. Returns `(source_path, file_size, root_hash)`.
    ///
    /// Expiry is applied here too: a grant past `expires_at` is not a grant, and
    /// leaving that to the caller would make every call site a place the
    /// check could be missed.
    pub fn chat_attachment_grant(
        &self,
        xfer_id: &str,
        friend_hash: &str,
        now: i64,
    ) -> Option<(String, u64, String)> {
        let conn = self.conn.lock();
        let (stored, size, root) = conn
            .query_row(
                // An allow-list, not a deny-list: a status added later is not a
                // grant until someone decides it should be. `offered` has to be on
                // it because the recipient dials straight after sending its accept,
                // and the accept can still be in flight when the stream arrives.
                "SELECT source_path, file_size, root_hash FROM chat_attachments
                 WHERE xfer_id = ?1 AND friend_hash = ?2 AND direction = 'sent'
                   AND source_path IS NOT NULL AND expires_at > ?3
                   AND status IN ('offered', 'accepted', 'active', 'complete')",
                rusqlite::params![xfer_id, friend_hash, now],
                |row| {
                    let path: String = row.get(0)?;
                    let size: i64 = row.get(1)?;
                    let root: String = row.get(2)?;
                    Ok((path, size.max(0) as u64, root))
                },
            )
            .ok()?;
        drop(conn);
        let path =
            Self::open_attachment_field(self.chat_key.as_deref(), xfer_id, "source_path", &stored)?;
        Some((path, size, root))
    }

    /// Move an attachment to a new status, optionally recording progress and
    /// where the finished file went.
    pub fn set_chat_attachment_status(
        &self,
        xfer_id: &str,
        status: &str,
        transferred: Option<u64>,
        dest_path: Option<&str>,
    ) -> anyhow::Result<()> {
        let dest_path = dest_path
            .map(|path| self.seal_attachment_value(xfer_id, "dest_path", path))
            .transpose()?;
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE chat_attachments SET
                status = ?2,
                transferred = COALESCE(?3, transferred),
                dest_path = COALESCE(?4, dest_path)
             WHERE xfer_id = ?1",
            rusqlite::params![xfer_id, status, transferred.map(|t| t as i64), dest_path],
        )?;
        Ok(())
    }

    /// [`Self::set_chat_attachment_status`], but only while the row is still
    /// live. Returns whether it moved.
    ///
    /// The status check and the write are one statement, so two parties
    /// settling the same transfer at once — a cancel and the task finishing
    /// the file — cannot both believe they won.
    pub fn advance_chat_attachment(
        &self,
        xfer_id: &str,
        status: &str,
        transferred: Option<u64>,
        dest_path: Option<&str>,
    ) -> anyhow::Result<bool> {
        let dest_path = dest_path
            .map(|path| self.seal_attachment_value(xfer_id, "dest_path", path))
            .transpose()?;
        let conn = self.conn.lock();
        let moved = conn.execute(
            "UPDATE chat_attachments SET
                status = ?2,
                transferred = COALESCE(?3, transferred),
                dest_path = COALESCE(?4, dest_path)
             WHERE xfer_id = ?1 AND status IN ('offered', 'awaiting', 'accepted', 'active')",
            rusqlite::params![xfer_id, status, transferred.map(|t| t as i64), dest_path],
        )?;
        Ok(moved > 0)
    }

    /// When an attachment's row stops being live on its own.
    pub fn chat_attachment_expiry(&self, xfer_id: &str) -> Option<i64> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT expires_at FROM chat_attachments WHERE xfer_id = ?1",
            rusqlite::params![xfer_id],
            |row| row.get(0),
        )
        .ok()
    }

    /// Move an attachment's expiry, which on the sending side is how long the
    /// grant stays readable. Extended when the recipient accepts, because an
    /// offer's short lifetime is for "nobody answered", not for the transfer.
    pub fn set_chat_attachment_expiry(&self, xfer_id: &str, expires_at: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE chat_attachments SET expires_at = ?2 WHERE xfer_id = ?1",
            rusqlite::params![xfer_id, expires_at],
        )?;
        Ok(())
    }

    /// Every received attachment that was waiting or moving when the process
    /// last stopped. The offer an `awaiting` row needs lives only in memory and
    /// a receive does not survive a restart, so both are stale on startup.
    pub fn interrupted_inbound_chat_attachments(&self) -> anyhow::Result<Vec<(String, String)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT xfer_id, status FROM chat_attachments
             WHERE direction = 'received' AND status IN ('awaiting', 'active')",
        )?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Put files we were sending when the process last stopped back to
    /// `accepted`. The friend's receive resumes from its last verified chunk
    /// if it dials again while the grant lasts, and if it never does the grant
    /// lapses like any other accepted offer — either way nothing is left
    /// claiming to be mid-send.
    pub fn requeue_interrupted_outbound_chat_attachments(&self) -> anyhow::Result<usize> {
        let conn = self.conn.lock();
        let moved = conn.execute(
            "UPDATE chat_attachments SET status = 'accepted'
             WHERE direction = 'sent' AND status = 'active'",
            [],
        )?;
        Ok(moved)
    }

    /// Every attachment for one friend, newest first, for drawing the transcript.
    pub fn chat_attachments_for_friend(
        &self,
        friend_hash: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<ChatAttachmentRow>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT xfer_id, friend_hash, direction, file_name, file_size,
                    dest_path, status, transferred, created_at
             FROM chat_attachments WHERE friend_hash = ?1
             ORDER BY created_at DESC, rowid DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(
                rusqlite::params![friend_hash, limit.max(0)],
                Self::chat_attachment_from_row,
            )?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        drop(conn);
        Ok(rows.into_iter().map(|row| self.open_chat_attachment_row(row)).collect())
    }

    /// Column order shared by every attachment read: xfer_id, friend_hash,
    /// direction, file_name, file_size, dest_path, status, transferred,
    /// created_at. Name and path come back as stored; see
    /// [`Self::open_chat_attachment_row`].
    fn chat_attachment_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChatAttachmentRow> {
        Ok(ChatAttachmentRow {
            xfer_id: row.get(0)?,
            friend_hash: row.get(1)?,
            direction: row.get(2)?,
            file_name: row.get(3)?,
            file_size: row.get::<_, i64>(4)?.max(0) as u64,
            dest_path: row.get(5)?,
            status: row.get(6)?,
            transferred: row.get::<_, i64>(7)?.max(0) as u64,
            created_at: row.get(8)?,
        })
    }

    /// Open the sealed name and path of a row read by
    /// [`Self::chat_attachment_from_row`]. One that cannot be opened reads as
    /// unavailable rather than as its ciphertext.
    fn open_chat_attachment_row(&self, mut row: ChatAttachmentRow) -> ChatAttachmentRow {
        let key = self.chat_key.as_deref();
        row.file_name = Self::open_attachment_field(key, &row.xfer_id, "file_name", &row.file_name)
            .unwrap_or_else(|| CHAT_ATTACH_UNAVAILABLE_NAME.to_string());
        row.dest_path = row
            .dest_path
            .as_deref()
            .and_then(|path| Self::open_attachment_field(key, &row.xfer_id, "dest_path", path));
        row
    }

    /// One attachment by id, whichever side of it this node is on.
    pub fn chat_attachment(&self, xfer_id: &str) -> Option<ChatAttachmentRow> {
        let conn = self.conn.lock();
        let row = conn
            .query_row(
                "SELECT xfer_id, friend_hash, direction, file_name, file_size,
                        dest_path, status, transferred, created_at
                 FROM chat_attachments WHERE xfer_id = ?1",
                rusqlite::params![xfer_id],
                Self::chat_attachment_from_row,
            )
            .ok()?;
        drop(conn);
        Some(self.open_chat_attachment_row(row))
    }

    /// Retire attachments nobody answered, and stop their grants being readable.
    ///
    /// Returns how many rows moved. Offers that lapsed are marked rather than
    /// deleted so the transcript can still say what happened to them; the grant
    /// stops resolving either way, because `chat_attachment_grant` refuses an
    /// expired row and refuses this status.
    ///
    /// A receive that is running is not swept: its expiry is only the offer's,
    /// and the task moving the bytes is what settles it.
    ///
    /// Settled rows older than [`CHAT_ATTACHMENT_RETENTION_SECS`] are deleted
    /// on the same pass; nothing else ever removes a row.
    /// Settle rows whose time ran out, returning the ids that moved so a caller
    /// can tell an open conversation.
    pub fn expire_chat_attachments(&self, now: i64) -> anyhow::Result<Vec<String>> {
        let conn = self.conn.lock();
        let moved: Vec<String> = conn
            .prepare(
                "UPDATE chat_attachments SET status = 'expired'
                 WHERE expires_at <= ?1
                   AND ((direction = 'sent' AND status IN ('offered', 'accepted', 'active'))
                     OR (direction = 'received' AND status = 'awaiting'))
                 RETURNING xfer_id",
            )?
            .query_map(rusqlite::params![now], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        Self::prune_settled_chat_attachments_locked(&conn, now)?;
        Ok(moved)
    }

    /// Delete settled attachment rows whose last date is past the retention
    /// window. A row that is still live — an open grant, a receive in flight —
    /// is never a candidate, whatever its age.
    fn prune_settled_chat_attachments_locked(conn: &Connection, now: i64) -> anyhow::Result<usize> {
        let cutoff = now.saturating_sub(CHAT_ATTACHMENT_RETENTION_SECS);
        Ok(conn.execute(
            "DELETE FROM chat_attachments
             WHERE status NOT IN ('offered', 'awaiting', 'accepted', 'active')
               AND expires_at < ?1 AND created_at < ?1",
            rusqlite::params![cutoff],
        )?)
    }

    /// Write a consistent, self-contained copy of the live database to `dest`.
    ///
    /// `VACUUM INTO` runs inside a read transaction and produces a single file
    /// with no WAL sidecar, which is what a backup needs: copying `ember.db`
    /// by hand while the app is running captures a file whose newest
    /// committed rows are still only in `ember.db-wal`.
    ///
    /// Runs on its own connection rather than the shared one. `VACUUM INTO`
    /// copies the entire database, which on a large one is seconds — and
    /// `conn` is a plain Rust `Mutex` that every other caller in the process
    /// blocks on, the network task included, so holding it for the duration
    /// stalled the overlay and dropped peers for as long as the backup ran.
    /// WAL gives the second connection a consistent snapshot without excluding
    /// writers, which is the same guarantee the shared one offered here.
    pub fn snapshot_to(&self, dest: &std::path::Path) -> anyhow::Result<()> {
        // SQLite refuses to overwrite an existing target.
        if dest.exists() {
            std::fs::remove_file(dest)?;
        }
        let dest_str = dest
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Snapshot path is not valid UTF-8"))?;
        {
            let conn = Connection::open_with_flags(
                &self.path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            // A reader that arrives mid-checkpoint would otherwise fail
            // outright instead of waiting the moment out.
            conn.busy_timeout(std::time::Duration::from_secs(30))?;
            conn.execute("VACUUM INTO ?1", params![dest_str])?;
        }
        crate::security::restrict_file_permissions(dest);
        Ok(())
    }

    fn add_column_if_missing(
        conn: &Connection,
        table: &str,
        column: &str,
        col_type: &str,
    ) -> anyhow::Result<()> {
        let valid_ident =
            |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        let valid_col_type = |s: &str| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '\'')
        };
        if !valid_ident(table) || !valid_ident(column) || !valid_col_type(col_type) {
            anyhow::bail!("Invalid SQL identifier in migration: {table}.{column} {col_type}");
        }
        // The base tables are only created by the `version < 1` arm, so a
        // database opened at a later version that is missing one never gets it
        // back. Aborting the migration chain over it would still be the wrong
        // trade: that fails every future open of an otherwise usable database,
        // where skipping degrades only the feature backed by that table. Warn
        // rather than `debug!` so the cause is in the log when it does happen,
        // and let a genuine query failure propagate instead of reading as
        // "absent" — that would mark the migration done and never retry it.
        let has_table: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            params![table],
            |row| row.get(0),
        )?;
        if !has_table {
            warn!("Skipping column {table}.{column}: table {table} does not exist");
            return Ok(());
        }
        let has_column = conn
            .prepare(&format!("SELECT {column} FROM {table} LIMIT 0"))
            .is_ok();
        if !has_column {
            let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {col_type}");
            conn.execute(&sql, [])
                .map_err(|e| anyhow::anyhow!("Failed to add column {table}.{column}: {e}"))?;
            info!("Added column {table}.{column}");
        }
        Ok(())
    }

    pub fn save_peer(&self, peer: &PeerInfo) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let addresses = serde_json::to_string(&peer.addresses)?;
        conn.execute(
            "INSERT INTO peers (id, addresses, nickname, last_seen, files_shared, banned)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
               addresses = excluded.addresses,
               nickname = excluded.nickname,
               last_seen = excluded.last_seen,
               files_shared = excluded.files_shared,
               banned = excluded.banned",
            params![
                peer.id,
                addresses,
                peer.nickname,
                peer.last_seen,
                peer.files_shared,
                peer.banned as i32,
            ],
        )?;
        // Banned rows are exempt. A ban is a user decision with no natural
        // refresh — nothing contacts the peer again, so `last_seen` freezes
        // and the row drifts to the bottom of this ordering (a ban placed on
        // a hash we had never met starts at 0 and is evicted immediately).
        // The ban list is rebuilt from `banned = 1` at startup, so eviction
        // silently un-banned peers within days on an active node.
        conn.execute(
            "DELETE FROM peers WHERE id IN (
                SELECT id FROM peers
                WHERE banned = 0
                ORDER BY last_seen DESC
                LIMIT -1 OFFSET ?1
            )",
            params![MAX_PEERS_ROWS],
        )?;
        Ok(())
    }

    /// Every address recorded for one peer id.
    ///
    /// The ban and unban paths used to reach this through `get_peers`, which
    /// reads the whole table *and* deserializes every row's address list to
    /// answer a question about a single id — synchronously on the network task.
    /// It is also `LIMIT MAX_PEERS_ROWS`, so a peer whose row had fallen outside
    /// that window contributed no IPs at all and the ban silently covered only
    /// the user-hash paths.
    pub fn get_peer_addresses(&self, peer_id: &str) -> anyhow::Result<Vec<String>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT addresses FROM peers WHERE id = ?1")?;
        let mut rows = stmt.query(params![peer_id])?;
        let Some(row) = rows.next()? else {
            return Ok(Vec::new());
        };
        let addresses_str: String = row.get(0)?;
        Ok(serde_json::from_str(&addresses_str)?)
    }

    pub fn get_peers(&self) -> anyhow::Result<Vec<PeerInfo>> {
        let conn = self.conn.lock();
        // Banned rows first, then by recency. Exempting them from eviction
        // only kept them in the table; every consumer reads them through
        // here, and a ban's `last_seen` is frozen at the moment it was placed
        // (nothing contacts the peer again), so on an active node they sorted
        // below `MAX_PEERS_ROWS` fresher rows and fell outside this window.
        // The enforcement sets rebuilt at startup and by the periodic resync
        // are both built from this result, so the ban stopped being applied
        // while the row sat in the database looking correct.
        let mut stmt = conn.prepare(
            "SELECT id, addresses, nickname, last_seen, files_shared, banned
             FROM peers
             ORDER BY banned DESC, last_seen DESC
             LIMIT ?1",
        )?;

        let peers = stmt
            .query_map(params![MAX_PEERS_ROWS], |row| {
                let addresses_str: String = row.get(1)?;
                let addresses: Vec<String> = serde_json::from_str(&addresses_str).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;
                Ok(PeerInfo {
                    id: row.get(0)?,
                    addresses,
                    nickname: row.get(2)?,
                    last_seen: row.get(3)?,
                    files_shared: row.get(4)?,
                    banned: row.get::<_, i32>(5)? != 0,
                })
            })?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!("Failed to read DB row: {e}");
                    None
                }
            })
            .collect();

        Ok(peers)
    }

    pub fn ban_peer(&self, peer_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO peers (id, banned) VALUES (?1, 1)
             ON CONFLICT(id) DO UPDATE SET banned = 1",
            params![peer_id],
        )?;
        Ok(())
    }

    pub fn unban_peer(&self, peer_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE peers SET banned = 0 WHERE id = ?1",
            params![peer_id],
        )?;
        Ok(())
    }

    /// Record `ip` as one of the addresses belonging to a (banned) peer.
    ///
    /// Used when a live upload session is torn down because its peer was
    /// banned by user-hash: the connecting IP may not have been in the
    /// routing table or peer DB at ban time, so without this it would not
    /// be cleared by `unban_peer` (which reverses a ban by walking the
    /// peer's known addresses). Storing it here makes ban/unban symmetric.
    /// The port is recorded as 0 (placeholder) — only the IP is ever used
    /// by the ban/unban paths, and boot-contact loading skips banned peers
    /// so the placeholder never produces a junk KAD contact. The row is
    /// upserted with `banned = 1` so a peer we only ever saw as an inbound
    /// uploader still exists for `unban_peer` to flip. Idempotent: an IP
    /// already present (under any port) is not duplicated.
    pub fn add_banned_peer_address(
        &self,
        peer_id: &str,
        ip: std::net::Ipv4Addr,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let existing: Option<String> = conn
            .query_row(
                "SELECT addresses FROM peers WHERE id = ?1",
                params![peer_id],
                |row| row.get(0),
            )
            .optional()?;
        let mut addresses: Vec<String> = existing
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();
        let ip_str = ip.to_string();
        let already_present = addresses.iter().any(|addr| {
            addr.rsplit_once(':')
                .map(|(host, _)| host == ip_str)
                .unwrap_or(addr.as_str() == ip_str)
        });
        if !already_present {
            addresses.push(format!("{ip_str}:0"));
        }
        let addresses_json = serde_json::to_string(&addresses)?;
        conn.execute(
            "INSERT INTO peers (id, addresses, banned) VALUES (?1, ?2, 1)
             ON CONFLICT(id) DO UPDATE SET addresses = excluded.addresses, banned = 1",
            params![peer_id, addresses_json],
        )?;
        Ok(())
    }

    /// Persist an automatic IP ban. `expires_at` is a Unix timestamp
    /// (0 = permanent). Re-banning an already-listed IP refreshes the
    /// reason and extends the expiry, never shortening an existing
    /// permanent ban down to a finite one.
    pub fn ban_ip(
        &self,
        ip: std::net::Ipv4Addr,
        reason: &str,
        expires_at: u64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        conn.execute(
            "INSERT INTO banned_ips (ip, reason, banned_at, expires_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(ip) DO UPDATE SET
               reason = excluded.reason,
               expires_at = CASE
                 WHEN banned_ips.expires_at = 0 OR excluded.expires_at = 0 THEN 0
                 ELSE MAX(banned_ips.expires_at, excluded.expires_at)
               END",
            params![
                ip.to_string(),
                reason,
                now as i64,
                expires_at.min(i64::MAX as u64) as i64
            ],
        )?;
        Ok(())
    }

    /// Remove an automatic IP ban.
    pub fn unban_ip(&self, ip: std::net::Ipv4Addr) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM banned_ips WHERE ip = ?1",
            params![ip.to_string()],
        )?;
        Ok(())
    }

    /// Load all auto-banned IPs that have not yet expired. Expired rows
    /// are pruned as a side effect so the table stays bounded.
    pub fn get_banned_ips(&self) -> anyhow::Result<Vec<std::net::Ipv4Addr>> {
        let conn = self.conn.lock();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0) as i64;
        conn.execute(
            "DELETE FROM banned_ips WHERE expires_at != 0 AND expires_at <= ?1",
            params![now],
        )?;
        let mut stmt = conn.prepare("SELECT ip FROM banned_ips")?;
        let mut ips = Vec::new();
        for row in stmt.query_map([], |row| row.get::<_, String>(0))? {
            let value = row?;
            let parsed = value.parse::<std::net::Ipv4Addr>().map_err(|error| {
                anyhow::anyhow!("invalid persisted banned IP {value:?}: {error}")
            })?;
            ips.push(parsed);
        }
        Ok(ips)
    }

    /// Strict startup validation for policy-bearing database rows. Runtime UI
    /// loaders may skip malformed non-security rows, but bans must never become
    /// an empty set because one row failed JSON/IP parsing.
    pub fn validate_security_policy(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let mut peers = conn.prepare("SELECT id, addresses FROM peers WHERE banned = 1")?;
        for row in peers.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })? {
            let (peer_id, addresses_json) = row?;
            let addresses: Vec<String> =
                serde_json::from_str(&addresses_json).map_err(|error| {
                    anyhow::anyhow!("invalid addresses for banned peer {peer_id}: {error}")
                })?;
            for address in addresses {
                let host = address
                    .rsplit_once(':')
                    .map(|(host, _)| host)
                    .unwrap_or(address.as_str());
                host.parse::<std::net::Ipv4Addr>().map_err(|error| {
                    anyhow::anyhow!(
                        "invalid address {address:?} for banned peer {peer_id}: {error}"
                    )
                })?;
            }
        }
        let mut banned_ips = conn.prepare("SELECT ip FROM banned_ips")?;
        for row in banned_ips.query_map([], |row| row.get::<_, String>(0))? {
            let value = row?;
            value.parse::<std::net::Ipv4Addr>().map_err(|error| {
                anyhow::anyhow!("invalid persisted banned IP {value:?}: {error}")
            })?;
        }
        Ok(())
    }

    /// Explicit user-authorized reset for policy rows that failed startup
    /// validation. This is never called automatically.
    pub fn reset_security_policy(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        tx.execute("UPDATE peers SET banned = 0", [])?;
        tx.execute("DELETE FROM banned_ips", [])?;
        tx.commit()?;
        Ok(())
    }

    pub fn save_transfer(&self, transfer: &Transfer) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let direction: &str = match transfer.direction {
            TransferDirection::Upload => "upload",
            TransferDirection::Download => "download",
        };
        let status: &str = match transfer.status {
            TransferStatus::Searching => "searching",
            TransferStatus::Queued => "queued",
            TransferStatus::Active => "active",
            TransferStatus::Paused => "paused",
            TransferStatus::Stopped => "stopped",
            TransferStatus::Verifying => "verifying",
            TransferStatus::Completing => "completing",
            TransferStatus::Completed => "completed",
            TransferStatus::Failed => "failed",
            TransferStatus::Hashing => "hashing",
            TransferStatus::Insufficient => "insufficient",
            TransferStatus::NoneNeeded => "noneneeded",
        };
        conn.execute(
            "INSERT INTO transfers (id, file_name, file_hash, peer_id, peer_name, direction, status, progress, speed, total_size, transferred, started_at, priority, category, expected_aich, ember_file_hash, friends_only)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
             ON CONFLICT(id) DO UPDATE SET
               file_name = excluded.file_name,
               file_hash = excluded.file_hash,
               peer_id = excluded.peer_id,
               peer_name = excluded.peer_name,
               direction = excluded.direction,
               status = excluded.status,
               progress = excluded.progress,
               speed = excluded.speed,
               total_size = excluded.total_size,
               transferred = excluded.transferred,
               started_at = excluded.started_at,
               priority = excluded.priority,
               category = excluded.category,
               expected_aich = excluded.expected_aich,
               ember_file_hash = excluded.ember_file_hash,
               friends_only = MAX(friends_only, excluded.friends_only)",
            params![
                transfer.id,
                transfer.file_name,
                transfer.file_hash,
                transfer.peer_id,
                transfer.peer_name,
                direction,
                status,
                transfer.progress,
                i64::try_from(transfer.speed).unwrap_or(i64::MAX),
                i64::try_from(transfer.total_size).unwrap_or(i64::MAX),
                // The `transferred` column stores resume progress, so it takes the
                // on-disk figure — the same thing `update_transfer_progress` writes
                // and `load_transfers` reads back into `completed_size`. The
                // cumulative wire total is kept in `.part.met`'s `FT_TRANSFERRED`,
                // as eMule keeps it, and must not land here: the queue-overflow
                // query computes `total_size - transferred`, which would underflow
                // to zero for any download that re-fetched a part.
                i64::try_from(transfer.completed_size).unwrap_or(i64::MAX),
                transfer.started_at,
                transfer.priority,
                transfer.category,
                transfer.expected_aich,
                transfer.ember_file_hash,
                transfer.friends_only,
            ],
        )?;
        Ok(())
    }

    /// Mark a download as coming from a friend who restricts the file. Never
    /// cleared: `save_transfer` keeps the stored flag when a stale snapshot
    /// without it is written back.
    pub fn mark_transfer_friends_only(&self, id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE transfers SET friends_only = 1 WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn get_incomplete_downloads(&self) -> anyhow::Result<Vec<Transfer>> {
        self.get_incomplete_downloads_page(usize::MAX, 0)
    }

    pub fn get_incomplete_downloads_page(
        &self,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Vec<Transfer>> {
        let conn = self.conn.lock();
        // Include `failed` so Temp `.part` files for hash-failed downloads are
        // still owned by a known transfer id and survive orphan sweep. They are
        // restored into the manager as Failed (not auto-started).
        let mut stmt = conn.prepare(
            "SELECT id, file_name, file_hash, peer_id, peer_name, direction, status, progress, speed, total_size, transferred, started_at, priority, category, expected_aich, ember_file_hash, friends_only
             FROM transfers
             WHERE status NOT IN ('completed', 'noneneeded')
               AND status NOT LIKE 'queue_overflow%'
               AND direction = 'download'
             ORDER BY started_at ASC, id ASC
             LIMIT ?1 OFFSET ?2"
        )?;

        let transfers = stmt
            .query_map(
                params![
                    i64::try_from(limit).unwrap_or(i64::MAX),
                    i64::try_from(offset).unwrap_or(i64::MAX)
                ],
                |row| {
                    let direction_str: String = row.get(5)?;
                    let status_str: String = row.get(6)?;
                    let transferred_val = row.get::<_, i64>(10)?.max(0) as u64;
                    let raw_aich: Option<String> = row.get(14)?;
                    // SQL NULL is the only persisted representation of "no
                    // pin". Empty/whitespace strings can be accepted as absent
                    // at an IPC boundary, but they are never written by Ember;
                    // seeing one in the database is corruption and must not
                    // silently resume an AICH-required transfer unpinned.
                    let (expected_aich, aich_corrupt) = match raw_aich.as_deref() {
                        None => (None, false),
                        Some(value) => match crate::security::parse_expected_aich(Some(value)) {
                            Ok(Some(value)) => (Some(value), false),
                            Ok(None) | Err(_) => (None, true),
                        },
                    };
                    let raw_ember: Option<String> = row.get(15)?;
                    let (ember_file_hash, ember_corrupt) = match raw_ember.as_deref() {
                        None => (None, false),
                        Some(value) => match crate::security::parse_ember_file_hash(Some(value)) {
                            Ok(Some(value)) => (Some(value), false),
                            Ok(None) | Err(_) => (None, true),
                        },
                    };
                    let pin_corrupt = aich_corrupt || ember_corrupt;
                    // Ember first: a row can be corrupt on both pins, and the
                    // Ember digest is the one the user must re-add an `eh=`
                    // link to fix.
                    let pin_failure = if ember_corrupt {
                        Some(TransferFailureCode::EmberPinCorrupt)
                    } else if aich_corrupt {
                        Some(TransferFailureCode::AichPinCorrupt)
                    } else {
                        None
                    };
                    let mut status = match status_str.trim_matches('"') {
                        "searching" => TransferStatus::Searching,
                        "queued" => TransferStatus::Queued,
                        "active" => TransferStatus::Active,
                        "paused" => TransferStatus::Paused,
                        "stopped" => TransferStatus::Stopped,
                        "verifying" => TransferStatus::Verifying,
                        "completing" => TransferStatus::Completing,
                        "completed" => TransferStatus::Completed,
                        "failed" => TransferStatus::Failed,
                        "hashing" => TransferStatus::Hashing,
                        "insufficient" => TransferStatus::Insufficient,
                        "noneneeded" => TransferStatus::NoneNeeded,
                        // A corrupted or future-version status string must
                        // not silently resume as an active "searching"
                        // transfer (which would kick off network activity on
                        // load). Fall back to the inert Stopped state.
                        _ => TransferStatus::Stopped,
                    };
                    if pin_corrupt {
                        status = TransferStatus::Failed;
                    }
                    Ok(Transfer {
                        id: row.get(0)?,
                        // Defense-in-depth: re-sanitize the persisted name on
                        // restore so a tampered DB row can't reintroduce path
                        // separators/traversal/reserved names into the path that
                        // gets built from it at finalize. Idempotent for names
                        // that were already sanitized when first written.
                        file_name: crate::security::sanitize_filename(&row.get::<_, String>(1)?),
                        file_hash: row.get(2)?,
                        peer_id: row.get(3)?,
                        peer_name: row.get(4)?,
                        direction: match direction_str.trim_matches('"') {
                            "upload" => TransferDirection::Upload,
                            _ => TransferDirection::Download,
                        },
                        status,
                        progress: row.get(7)?,
                        speed: row.get::<_, i64>(8)?.max(0) as u64,
                        total_size: row.get::<_, i64>(9)?.max(0) as u64,
                        // The persisted column is the on-disk figure, so it restores
                        // `completed_size` directly. `transferred` starts from it as
                        // a floor: the real cumulative wire total lives in
                        // `.part.met`'s `FT_TRANSFERRED` (as it does for eMule) and
                        // replaces this the first time the resumed download reports
                        // progress.
                        transferred: transferred_val,
                        completed_size: transferred_val,
                        started_at: row.get(11)?,
                        failure_reason: pin_failure.map(|f| f.message().to_string()),
                        failure_code: pin_failure.map(|f| f.as_code().to_string()),
                        failure_kind: pin_corrupt.then(|| "permanent".to_string()),
                        failure_stage: None,
                        priority: row
                            .get::<_, String>(12)
                            .unwrap_or_else(|_| "normal".to_string()),
                        sources: 0,
                        active_sources: 0,
                        queued_sources: 0,
                        queue_rank: None,
                        last_seen_complete: None,
                        last_received: None,
                        health: TransferHealth::Healthy,
                        health_reason: None,
                        health_code: None,
                        stalled_since: None,
                        category: row.get::<_, String>(13).unwrap_or_default(),
                        wait_time: 0,
                        upload_time: 0,
                        a4af_sources: 0,
                        max_sources: 0,
                        preview_priority: false,
                        preview_ready: false,
                        ember_sources: 0,
                        client_software: String::new(),
                        country_code: None,
                        user_hash: None,
                        ember_hash: None,
                        expected_aich,
                        ember_file_hash,
                        completed_path: None,
                        up_part_status: None,
                        up_part_count: None,
                        up_peer_part_status: None,
                        // Not persisted (see the `ember_verified` field doc):
                        // completed transfers never come back through this
                        // loader, and an incomplete one hasn't been checked
                        // yet either way.
                        ember_verified: false,
                        friends_only: row.get::<_, i64>(16).unwrap_or(0) != 0,
                    })
                },
            )?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!("Skipping malformed transfer row: {e}");
                    None
                }
            })
            .collect();

        Ok(transfers)
    }

    /// Deterministically quarantine legacy pending rows beyond the one global
    /// count/remaining-byte budget. Rows are retained (never deleted) and stay
    /// tagged until the frontend acknowledges the migration notice.
    pub fn quarantine_excess_pending_downloads(
        &self,
        max_count: usize,
        max_remaining_bytes: u64,
    ) -> anyhow::Result<usize> {
        let conn = self.conn.lock();
        conn.execute(
            "WITH ranked AS (
                 SELECT id,
                        ROW_NUMBER() OVER (ORDER BY started_at ASC, id ASC) AS row_num,
                        MAX(total_size - transferred, 0) AS remaining
                 FROM transfers
                 WHERE status NOT IN ('completed', 'noneneeded')
                   AND status NOT LIKE 'queue_overflow%'
                   AND direction = 'download'
             ),
             ordered AS (
                 SELECT id,
                        row_num,
                        SUM(
                            CASE
                                WHEN row_num <= ?1 THEN MIN(remaining, ?2 + 1)
                                ELSE 0
                            END
                        ) OVER (ORDER BY row_num ASC) AS remaining_sum
                 FROM ranked
             )
             UPDATE transfers
                SET status = 'queue_overflow'
              WHERE id IN (
                  SELECT id FROM ordered
                   WHERE row_num > ?1 OR remaining_sum > ?2
              )",
            params![
                i64::try_from(max_count).unwrap_or(i64::MAX),
                i64::try_from(max_remaining_bytes).unwrap_or(i64::MAX)
            ],
        )?;
        Ok(conn.changes() as usize)
    }

    /// Mark an overflow migration notice as seen and return its row count.
    pub fn acknowledge_pending_download_overflow(&self) -> anyhow::Result<usize> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM transfers WHERE status = 'queue_overflow'",
            [],
            |row| row.get(0),
        )?;
        if count > 0 {
            tx.execute(
                "UPDATE transfers
                    SET status = 'queue_overflow_acknowledged'
                  WHERE status = 'queue_overflow'",
                [],
            )?;
        }
        tx.commit()?;
        Ok(count.max(0) as usize)
    }

    pub fn transfer_exists(&self, transfer_id: &str) -> bool {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT 1 FROM transfers WHERE id = ?1",
            params![transfer_id],
            |_| Ok(()),
        )
        .is_ok()
    }

    /// Ids of durable, non-terminal download rows that still own their `.part`
    /// files, even where the row was quarantined rather than restored in memory.
    ///
    /// The orphan sweep tests one id per file in the Temp directory. Asking
    /// per file meant a query, and a turn on the shared connection mutex, for
    /// every stale `.part` a crash had left behind — thousands of them on a
    /// long-lived install, all of it before the network loop reached its first
    /// `select`. The whole set is one scan of the same index.
    pub fn incomplete_downloads_owning_partials(
        &self,
    ) -> anyhow::Result<std::collections::HashSet<String>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id FROM transfers
              WHERE direction = 'download'
                AND status NOT IN ('completed', 'noneneeded')",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn remove_transfer(&self, transfer_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM transfers WHERE id = ?1", params![transfer_id])?;
        Ok(())
    }

    /// Delete many transfers in one transaction.
    ///
    /// [`Database::remove_transfer`] autocommits, so a caller deleting a
    /// selection paid one transaction — and under `synchronous=FULL` one fsync
    /// — per row, each of them re-taking the single connection mutex that every
    /// other database user in the process shares, the network task included.
    /// Clearing a few thousand completed rows that way froze the app for tens
    /// of seconds. One transaction is one fsync regardless of the count.
    pub fn remove_transfers(&self, transfer_ids: &[String]) -> anyhow::Result<()> {
        if transfer_ids.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare("DELETE FROM transfers WHERE id = ?1")?;
            for id in transfer_ids {
                stmt.execute(params![id])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Record many cancelled/finished downloads in one transaction.
    ///
    /// Same reasoning as [`Database::remove_transfers`]: the per-row
    /// [`Database::record_download_history`] opens its own transaction, so a
    /// batch cancel paid one fsync per row before it even reached the deletes.
    /// Rows are `(file_hash, file_name, file_size, status)`.
    pub fn record_download_history_batch(
        &self,
        rows: &[(String, String, u64, &str)],
    ) -> anyhow::Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        for (file_hash, file_name, file_size, status) in rows {
            Self::record_download_history_in(&tx, file_hash, file_name, *file_size, status)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn update_transfer_status(&self, transfer_id: &str, status: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE transfers SET status = ?1 WHERE id = ?2",
            params![status, transfer_id],
        )?;
        Ok(())
    }

    /// [`Self::update_transfer_status`] for many rows in one transaction.
    ///
    /// Pause/Resume All touch up to `MAX_PENDING_DOWNLOADS` rows; one
    /// autocommit UPDATE each meant one WAL fsync each under
    /// `synchronous=FULL`. Rows are `(transfer_id, status)`, applied in order.
    pub fn update_transfer_statuses(&self, updates: &[(&str, &str)]) -> anyhow::Result<()> {
        if updates.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare("UPDATE transfers SET status = ?1 WHERE id = ?2")?;
            for (transfer_id, status) in updates {
                stmt.execute(params![status, transfer_id])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn update_transfer_progress(
        &self,
        transfer_id: &str,
        transferred: u64,
        progress: f64,
        speed: u64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE transfers
             SET transferred = ?1, progress = ?2, speed = ?3
             WHERE id = ?4",
            params![
                i64::try_from(transferred).unwrap_or(i64::MAX),
                progress,
                i64::try_from(speed).unwrap_or(i64::MAX),
                transfer_id
            ],
        )?;
        Ok(())
    }

    /// Progress update that refuses to reopen a row that has already reached a
    /// terminal state.
    ///
    /// The periodic progress flush is fire-and-forget on the blocking pool and
    /// carries no sequence number, so it can be executed *after* the
    /// completion write it was queued before. Without the predicate that
    /// persists `completed` at 95%, which is what the UI and a restart then
    /// show — and the `.part.met` is gone by then, so nothing can repair it.
    /// Terminal states are only left via a deliberate re-queue, which writes
    /// its own progress.
    pub fn update_transfer_progress_if_active(
        &self,
        transfer_id: &str,
        transferred: u64,
        progress: f64,
        speed: u64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE transfers
             SET transferred = ?1, progress = ?2, speed = ?3
             WHERE id = ?4 AND status NOT IN ('completed', 'cancelled')",
            params![
                i64::try_from(transferred).unwrap_or(i64::MAX),
                progress,
                i64::try_from(speed).unwrap_or(i64::MAX),
                transfer_id
            ],
        )?;
        Ok(())
    }

    /// Commit a finished download's terminal state in one transaction.
    ///
    /// Final progress, status, history and the optional row delete used to be
    /// four independent statements, so a crash between them could persist
    /// `completed` at 95%, or a history row for a transfer that was still
    /// listed. Writing the final progress together with the status also closes
    /// the window where a late periodic tick landed between the two and left a
    /// completed row showing a short bar.
    pub fn complete_transfer(
        &self,
        transfer_id: &str,
        final_total: Option<u64>,
        history: Option<(&str, &str, u64)>,
        remove_row: bool,
    ) -> anyhow::Result<()> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        match final_total {
            Some(total) => {
                tx.execute(
                    "UPDATE transfers
                     SET transferred = ?1, progress = 100.0, speed = 0, status = 'completed'
                     WHERE id = ?2",
                    params![i64::try_from(total).unwrap_or(i64::MAX), transfer_id],
                )?;
            }
            None => {
                tx.execute(
                    "UPDATE transfers SET speed = 0, status = 'completed' WHERE id = ?1",
                    params![transfer_id],
                )?;
            }
        }
        if let Some((file_hash, file_name, file_size)) = history {
            Self::record_download_history_in(&tx, file_hash, file_name, file_size, "completed")?;
        }
        if remove_row {
            tx.execute("DELETE FROM transfers WHERE id = ?1", params![transfer_id])?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn update_transfer_priority(
        &self,
        transfer_id: &str,
        priority: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE transfers SET priority = ?1 WHERE id = ?2",
            params![priority, transfer_id],
        )?;
        Ok(())
    }

    pub fn update_transfer_category(
        &self,
        transfer_id: &str,
        category: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE transfers SET category = ?1 WHERE id = ?2",
            params![category, transfer_id],
        )?;
        Ok(())
    }

    pub fn update_transfer_file_name(
        &self,
        transfer_id: &str,
        file_name: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE transfers SET file_name = ?1 WHERE id = ?2",
            params![file_name, transfer_id],
        )?;
        Ok(())
    }

    pub fn load_credits(&self) -> anyhow::Result<Vec<CreditRow>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT user_hash, uploaded, downloaded, last_seen, public_key, ident_ip, ident_state, ember_hash, crypto_verified_once, peer_name, client_software, seen_ip FROM credits",
        )?;
        let records = stmt
            .query_map([], |row| {
                let hash_blob: Vec<u8> = row.get(0)?;
                // Exactly 16, not "at least 16", for the reason `load_ember_credits`
                // spells out for its 32-byte key: a longer blob silently truncated
                // to the first 16 bytes would alias two distinct user hashes onto a
                // single credit account. Short blobs were already refused; long ones
                // are now refused too, so the row is skipped rather than merged into
                // the wrong account.
                if hash_blob.len() != 16 {
                    return Err(rusqlite::Error::InvalidColumnType(
                        0,
                        format!("user_hash must be 16 bytes, got {}", hash_blob.len()),
                        rusqlite::types::Type::Blob,
                    ));
                }
                let mut hash = [0u8; 16];
                hash.copy_from_slice(&hash_blob[..16]);
                let ember_blob: Option<Vec<u8>> = row.get(7)?;
                let ember_hash = ember_blob.and_then(|b| {
                    if b.len() == 16 {
                        let mut eh = [0u8; 16];
                        eh.copy_from_slice(&b);
                        Some(eh)
                    } else {
                        None
                    }
                });
                Ok((
                    hash,
                    row.get::<_, i64>(1)?.max(0) as u64,
                    row.get::<_, i64>(2)?.max(0) as u64,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    // ident_ip is a 32-bit IPv4 stored as INTEGER; clamp to the
                    // u32 range defensively in case of a malformed row.
                    row.get::<_, i64>(5)?.clamp(0, u32::MAX as i64) as u32,
                    row.get::<_, i64>(6)?.clamp(0, u8::MAX as i64) as u8,
                    ember_hash,
                    row.get::<_, i64>(8)? != 0,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, i64>(11)?.clamp(0, u32::MAX as i64) as u32,
                ))
            })?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!("Skipping malformed credit row: {e}");
                    None
                }
            })
            .collect();
        Ok(records)
    }

    pub fn load_statistics(&self) -> anyhow::Result<Vec<(String, i64)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT key, value FROM statistics")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!("Skipping malformed statistics row: {e}");
                    None
                }
            })
            .collect();
        Ok(rows)
    }

    pub fn save_statistics(&self, pairs: &[(&str, i64)]) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        {
            // Cumulative counters must never shrink: a delayed periodic save
            // started with an older snapshot can otherwise race a newer save
            // (including the shutdown write) and roll totals backwards.
            let mut read_stmt = tx.prepare("SELECT value FROM statistics WHERE key = ?1")?;
            let mut write_stmt =
                tx.prepare("INSERT OR REPLACE INTO statistics (key, value) VALUES (?1, ?2)")?;
            for (key, value) in pairs {
                let to_write = if key.starts_with("cum_") {
                    let existing: i64 = read_stmt
                        .query_row(params![key], |row| row.get(0))
                        .unwrap_or(0);
                    (*value).max(existing)
                } else {
                    *value
                };
                write_stmt.execute(params![key, to_write])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_file_comments(&self) -> anyhow::Result<Vec<(String, u8, String)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT file_hash, rating, comment FROM file_comments")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    (row.get::<_, i32>(1)?).clamp(0, 5) as u8,
                    row.get::<_, String>(2)?,
                ))
            })?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!("Skipping malformed file comment row: {e}");
                    None
                }
            })
            .collect();
        Ok(rows)
    }

    pub fn save_file_comment(
        &self,
        file_hash: &str,
        rating: u8,
        comment: &str,
    ) -> anyhow::Result<()> {
        // Defense-in-depth cap matching the IPC layer
        // (`commands/comments.rs::set_file_comment`). The IPC entry point
        // already rejects > 4096-byte comments, but enforcing it again
        // here protects against future internal callers that might skip
        // the validation step. 4096 matches eMule's on-wire limit so we
        // don't write something the protocol couldn't carry.
        const MAX_COMMENT_BYTES: usize = 4096;
        if comment.len() > MAX_COMMENT_BYTES {
            return Err(anyhow::anyhow!(
                "comment too long ({} bytes > {} max)",
                comment.len(),
                MAX_COMMENT_BYTES
            ));
        }
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO file_comments (file_hash, rating, comment) VALUES (?1, ?2, ?3)",
            params![file_hash, rating as i32, comment],
        )?;
        Ok(())
    }

    /// Load every note we have published to the KAD DHT, along with the
    /// timestamp of its last (re)publish. Used at startup to seed the
    /// periodic notes-republish loop so our comments/ratings keep refreshing
    /// after a restart instead of silently expiring from the network.
    pub fn load_published_notes(
        &self,
    ) -> anyhow::Result<Vec<(String, u8, String, i64, Option<String>, Option<u64>)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT file_hash, rating, comment, last_publish, file_name, file_size FROM published_notes",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    (row.get::<_, i32>(1)?).clamp(0, 5) as u8,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<i64>>(5)?.map(|v| v.max(0) as u64),
                ))
            })?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!("Skipping malformed published note row: {e}");
                    None
                }
            })
            .collect();
        Ok(rows)
    }

    /// Record (or refresh) a note we have published to the DHT. `last_publish`
    /// is the Unix timestamp of this publish so the republish loop can tell
    /// when the entry is due to be pushed again.
    pub fn save_published_note(
        &self,
        file_hash: &str,
        rating: u8,
        comment: &str,
        last_publish: i64,
        file_name: Option<&str>,
        file_size: Option<u64>,
    ) -> anyhow::Result<()> {
        const MAX_COMMENT_BYTES: usize = 4096;
        if comment.len() > MAX_COMMENT_BYTES {
            return Err(anyhow::anyhow!(
                "comment too long ({} bytes > {} max)",
                comment.len(),
                MAX_COMMENT_BYTES
            ));
        }
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO published_notes \
             (file_hash, rating, comment, last_publish, file_name, file_size) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                file_hash,
                rating as i32,
                comment,
                last_publish,
                file_name,
                file_size.map(|v| v.min(i64::MAX as u64) as i64)
            ],
        )?;
        Ok(())
    }

    /// Persist the full credit ledger as a single atomic replacement.
    /// The previous implementation only ran `INSERT OR REPLACE` per row,
    /// which meant rows pruned in memory by `CreditManager::cleanup_stale`
    /// were left behind in the database. On the next launch the loader
    /// would resurrect those stale rows and the in-memory eviction
    /// would have to run again — visible as a Known Clients tab that
    /// kept showing months-old "Unknown" peers across restarts even
    /// after the periodic pruner had supposedly cleaned them up.
    ///
    /// `DELETE FROM credits` followed by the INSERTs inside one
    /// transaction guarantees the table mirrors the in-memory snapshot
    /// exactly. SQLite's transaction guarantees that either the whole
    /// replacement lands or nothing changes, so a crash mid-flush won't
    /// leave the table empty.
    // Retained as a focused, unit-tested building block (full-replacement
    // semantics); production flushes go through `save_credit_changes` and
    // `sync_all_credits_with_ember`.
    #[allow(dead_code)]
    pub fn save_all_credits(&self, credits: &[CreditRowRef<'_>]) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM credits", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO credits (user_hash, uploaded, downloaded, last_seen, public_key, ident_ip, ident_state, ember_hash, crypto_verified_once, peer_name, client_software, seen_ip) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"
            )?;
            for (
                hash,
                uploaded,
                downloaded,
                last_seen,
                public_key,
                ident_ip,
                ident_state,
                ember_hash,
                crypto_verified_once,
                peer_name,
                client_software,
                seen_ip,
            ) in credits
            {
                stmt.execute(params![
                    &hash[..],
                    i64::try_from(*uploaded).unwrap_or(i64::MAX),
                    i64::try_from(*downloaded).unwrap_or(i64::MAX),
                    *last_seen,
                    *public_key,
                    i64::from(*ident_ip),
                    i64::from(*ident_state),
                    ember_hash.map(|eh| eh.as_slice()),
                    i64::from(*crypto_verified_once),
                    *peer_name,
                    *client_software,
                    i64::from(*seen_ip),
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Load persisted Ember credit records. Returns raw field tuples so
    /// the caller can rehydrate `EmberCreditRecord` without this layer
    /// depending on the credit types — same pattern as
    /// `load_credits`.
    ///
    /// Field order matches the v15 schema and the
    /// `save_all_ember_credits` INSERT statement: pubkey, uploaded,
    /// downloaded, last_upload_time, last_download_time,
    /// completed_sessions, total_sessions, avg_upload_speed, last_seen,
    /// ident_verified.
    #[allow(clippy::type_complexity)]
    pub fn load_ember_credits(
        &self,
    ) -> anyhow::Result<Vec<([u8; 32], u64, u64, i64, i64, u32, u32, u64, i64, bool)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT pub_key, uploaded, downloaded, last_upload_time, last_download_time, \
                    completed_sessions, total_sessions, avg_upload_speed, last_seen, ident_verified \
             FROM ember_credits",
        )?;
        let records = stmt
            .query_map([], |row| {
                let pk_blob: Vec<u8> = row.get(0)?;
                // M10: strict 32-byte pub_key. Previously a row with
                // a >32 byte blob silently truncated to the first 32
                // bytes, which would alias two distinct Ed25519 keys
                // onto a single credit account if any non-conformant
                // row ever appeared. We now reject anything that
                // isn't exactly 32 bytes; the row is logged + skipped
                // by the `filter_map` below rather than being merged
                // into the wrong account.
                if pk_blob.len() != 32 {
                    return Err(rusqlite::Error::InvalidColumnType(
                        0,
                        format!("pub_key must be 32 bytes, got {}", pk_blob.len()),
                        rusqlite::types::Type::Blob,
                    ));
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&pk_blob);
                Ok((
                    pk,
                    row.get::<_, i64>(1)?.max(0) as u64,
                    row.get::<_, i64>(2)?.max(0) as u64,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?.clamp(0, i64::from(u32::MAX)) as u32,
                    row.get::<_, i64>(6)?.clamp(0, i64::from(u32::MAX)) as u32,
                    row.get::<_, i64>(7)?.max(0) as u64,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)? != 0,
                ))
            })?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!("Skipping malformed ember_credits row: {e}");
                    None
                }
            })
            .collect();
        Ok(records)
    }

    /// Full-replacement save for the Ember credit table — same
    /// contract as `save_all_credits`: DELETE followed by INSERT
    /// inside one transaction so on-disk state matches the
    /// in-memory `CreditManager.ember_credits` snapshot exactly. A
    /// crash mid-flush leaves the pre-save rows intact thanks to
    /// SQLite's all-or-nothing transaction guarantee.
    #[allow(clippy::type_complexity, dead_code)]
    pub fn save_all_ember_credits(
        &self,
        credits: &[(&[u8; 32], u64, u64, i64, i64, u32, u32, u64, i64, bool)],
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM ember_credits", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO ember_credits (\
                    pub_key, uploaded, downloaded, last_upload_time, last_download_time, \
                    completed_sessions, total_sessions, avg_upload_speed, last_seen, ident_verified\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            for (
                pk,
                up,
                down,
                last_up,
                last_down,
                completed,
                total,
                avg_speed,
                last_seen,
                verified,
            ) in credits
            {
                stmt.execute(params![
                    &pk[..],
                    i64::try_from(*up).unwrap_or(i64::MAX),
                    i64::try_from(*down).unwrap_or(i64::MAX),
                    *last_up,
                    *last_down,
                    i64::from(*completed),
                    i64::from(*total),
                    i64::try_from(*avg_speed).unwrap_or(i64::MAX),
                    *last_seen,
                    i64::from(*verified),
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Full-replacement save of BOTH credit tables inside a SINGLE
    /// transaction, so the `credits` and `ember_credits` tables can never
    /// diverge across a crash or a partial failure. The previous code ran
    /// `save_all_credits` and `save_all_ember_credits` as two independent
    /// committed transactions back-to-back; if the second failed (or the
    /// process died between them) the two tables ended up inconsistent
    /// despite a comment claiming "either both land or neither". Both
    /// DELETE+INSERT pairs now share one `tx`, restoring that guarantee.
    #[allow(clippy::type_complexity)]
    pub fn save_all_credits_with_ember(
        &self,
        credits: &[CreditRowRef<'_>],
        ember_credits: &[(&[u8; 32], u64, u64, i64, i64, u32, u32, u64, i64, bool)],
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM credits", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO credits (user_hash, uploaded, downloaded, last_seen, public_key, ident_ip, ident_state, ember_hash, crypto_verified_once, peer_name, client_software, seen_ip) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"
            )?;
            for (
                hash,
                uploaded,
                downloaded,
                last_seen,
                public_key,
                ident_ip,
                ident_state,
                ember_hash,
                crypto_verified_once,
                peer_name,
                client_software,
                seen_ip,
            ) in credits
            {
                stmt.execute(params![
                    &hash[..],
                    i64::try_from(*uploaded).unwrap_or(i64::MAX),
                    i64::try_from(*downloaded).unwrap_or(i64::MAX),
                    *last_seen,
                    *public_key,
                    i64::from(*ident_ip),
                    i64::from(*ident_state),
                    ember_hash.map(|eh| eh.as_slice()),
                    i64::from(*crypto_verified_once),
                    *peer_name,
                    *client_software,
                    i64::from(*seen_ip),
                ])?;
            }
        }
        tx.execute("DELETE FROM ember_credits", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO ember_credits (\
                    pub_key, uploaded, downloaded, last_upload_time, last_download_time, \
                    completed_sessions, total_sessions, avg_upload_speed, last_seen, ident_verified\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            for (
                pk,
                up,
                down,
                last_up,
                last_down,
                completed,
                total,
                avg_speed,
                last_seen,
                verified,
            ) in ember_credits
            {
                stmt.execute(params![
                    &pk[..],
                    i64::try_from(*up).unwrap_or(i64::MAX),
                    i64::try_from(*down).unwrap_or(i64::MAX),
                    *last_up,
                    *last_down,
                    i64::from(*completed),
                    i64::from(*total),
                    i64::try_from(*avg_speed).unwrap_or(i64::MAX),
                    *last_seen,
                    i64::from(*verified),
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    const CREDIT_COLUMNS: &'static str = "user_hash, uploaded, downloaded, last_seen, public_key, \
         ident_ip, ident_state, ember_hash, crypto_verified_once, peer_name, client_software, seen_ip";
    const CREDIT_UPSERT_SQL: &'static str = "INSERT INTO credits (user_hash, uploaded, downloaded, \
         last_seen, public_key, ident_ip, ident_state, ember_hash, crypto_verified_once, peer_name, \
         client_software, seen_ip) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
         ON CONFLICT(user_hash) DO UPDATE SET uploaded = excluded.uploaded, \
         downloaded = excluded.downloaded, last_seen = excluded.last_seen, \
         public_key = excluded.public_key, ident_ip = excluded.ident_ip, \
         ident_state = excluded.ident_state, ember_hash = excluded.ember_hash, \
         crypto_verified_once = excluded.crypto_verified_once, peer_name = excluded.peer_name, \
         client_software = excluded.client_software, seen_ip = excluded.seen_ip";
    const EMBER_CREDIT_COLUMNS: &'static str = "pub_key, uploaded, downloaded, last_upload_time, \
         last_download_time, completed_sessions, total_sessions, avg_upload_speed, last_seen, \
         ident_verified";
    const EMBER_CREDIT_UPSERT_SQL: &'static str = "INSERT INTO ember_credits (pub_key, uploaded, \
         downloaded, last_upload_time, last_download_time, completed_sessions, total_sessions, \
         avg_upload_speed, last_seen, ident_verified) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
         ON CONFLICT(pub_key) DO UPDATE SET uploaded = excluded.uploaded, \
         downloaded = excluded.downloaded, last_upload_time = excluded.last_upload_time, \
         last_download_time = excluded.last_download_time, \
         completed_sessions = excluded.completed_sessions, total_sessions = excluded.total_sessions, \
         avg_upload_speed = excluded.avg_upload_speed, last_seen = excluded.last_seen, \
         ident_verified = excluded.ident_verified";

    /// Column values exactly as the credit saves store them, in
    /// `CREDIT_COLUMNS` order, so a stored row can be compared for equality.
    fn credit_row_values(row: &CreditRowRef<'_>) -> [rusqlite::types::Value; 12] {
        use rusqlite::types::Value;
        let (
            hash,
            uploaded,
            downloaded,
            last_seen,
            public_key,
            ident_ip,
            ident_state,
            ember_hash,
            crypto_verified_once,
            peer_name,
            client_software,
            seen_ip,
        ) = *row;
        [
            Value::Blob(hash.to_vec()),
            Value::Integer(i64::try_from(uploaded).unwrap_or(i64::MAX)),
            Value::Integer(i64::try_from(downloaded).unwrap_or(i64::MAX)),
            Value::Integer(last_seen),
            Value::Blob(public_key.to_vec()),
            Value::Integer(i64::from(ident_ip)),
            Value::Integer(i64::from(ident_state)),
            ember_hash.map_or(Value::Null, |eh| Value::Blob(eh.to_vec())),
            Value::Integer(i64::from(crypto_verified_once)),
            Value::Text(peer_name.to_owned()),
            Value::Text(client_software.to_owned()),
            Value::Integer(i64::from(seen_ip)),
        ]
    }

    fn ember_credit_row_values(row: &EmberCreditRowRef<'_>) -> [rusqlite::types::Value; 10] {
        use rusqlite::types::Value;
        let (pk, up, down, last_up, last_down, completed, total, avg_speed, last_seen, verified) =
            *row;
        [
            Value::Blob(pk.to_vec()),
            Value::Integer(i64::try_from(up).unwrap_or(i64::MAX)),
            Value::Integer(i64::try_from(down).unwrap_or(i64::MAX)),
            Value::Integer(last_up),
            Value::Integer(last_down),
            Value::Integer(i64::from(completed)),
            Value::Integer(i64::from(total)),
            Value::Integer(i64::try_from(avg_speed).unwrap_or(i64::MAX)),
            Value::Integer(last_seen),
            Value::Integer(i64::from(verified)),
        ]
    }

    fn credit_row_key<'r>(row: &'r CreditRowRef<'_>) -> &'r [u8] {
        &row.0[..]
    }

    fn ember_credit_row_key<'r>(row: &'r EmberCreditRowRef<'_>) -> &'r [u8] {
        &row.0[..]
    }

    /// Persist only the credit rows a flush found changed: an upsert for each
    /// live record and a delete for each evicted key, both tables in one
    /// transaction.
    ///
    /// The full-replacement saves rewrite every row, and with `secure_delete`
    /// and `synchronous=FULL` that pushed the whole ledger (up to 50k rows per
    /// table) through the WAL under the connection mutex every minute.
    pub fn save_credit_changes(
        &self,
        credits: &[CreditRowRef<'_>],
        removed_credits: &[[u8; 16]],
        ember_credits: &[EmberCreditRowRef<'_>],
        removed_ember_credits: &[[u8; 32]],
    ) -> anyhow::Result<()> {
        if credits.is_empty()
            && removed_credits.is_empty()
            && ember_credits.is_empty()
            && removed_ember_credits.is_empty()
        {
            return Ok(());
        }
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        {
            let mut upsert = tx.prepare(Self::CREDIT_UPSERT_SQL)?;
            for row in credits {
                upsert.execute(rusqlite::params_from_iter(Self::credit_row_values(row)))?;
            }
            let mut delete = tx.prepare("DELETE FROM credits WHERE user_hash = ?1")?;
            for hash in removed_credits {
                delete.execute(params![&hash[..]])?;
            }
        }
        {
            let mut upsert = tx.prepare(Self::EMBER_CREDIT_UPSERT_SQL)?;
            for row in ember_credits {
                upsert.execute(rusqlite::params_from_iter(Self::ember_credit_row_values(row)))?;
            }
            let mut delete = tx.prepare("DELETE FROM ember_credits WHERE pub_key = ?1")?;
            for pk in removed_ember_credits {
                delete.execute(params![&pk[..]])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Make both credit tables equal a full snapshot while writing only the
    /// rows that differ, in one transaction. Same end state as
    /// [`Self::save_all_credits_with_ember`], including dropping rows the
    /// snapshot lacks or that `load_credits` would skip as malformed.
    ///
    /// For a session's first flush: startup loads every record through the
    /// mutating accessor, so all of them are marked even though nearly all
    /// already match disk. Reading the table is far cheaper than rewriting it.
    pub fn sync_all_credits_with_ember(
        &self,
        credits: &[CreditRowRef<'_>],
        ember_credits: &[EmberCreditRowRef<'_>],
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        Self::reconcile_rows(
            &tx,
            "credits",
            Self::CREDIT_COLUMNS,
            Self::CREDIT_UPSERT_SQL,
            credits,
            Self::credit_row_key,
            Self::credit_row_values,
        )?;
        Self::reconcile_rows(
            &tx,
            "ember_credits",
            Self::EMBER_CREDIT_COLUMNS,
            Self::EMBER_CREDIT_UPSERT_SQL,
            ember_credits,
            Self::ember_credit_row_key,
            Self::ember_credit_row_values,
        )?;
        tx.commit()?;
        Ok(())
    }

    /// `columns` must list the key column first and match `encode`'s order.
    fn reconcile_rows<R, const N: usize>(
        conn: &Connection,
        table: &str,
        columns: &str,
        upsert_sql: &str,
        rows: &[R],
        key: fn(&R) -> &[u8],
        encode: fn(&R) -> [rusqlite::types::Value; N],
    ) -> rusqlite::Result<()> {
        use rusqlite::types::{Value, ValueRef};
        let wanted: std::collections::HashMap<&[u8], &R> =
            rows.iter().map(|row| (key(row), row)).collect();
        let mut unchanged: std::collections::HashSet<&[u8]> =
            std::collections::HashSet::with_capacity(rows.len());
        let mut stale_rowids: Vec<i64> = Vec::new();
        {
            let mut stmt = conn.prepare(&format!("SELECT rowid, {columns} FROM {table}"))?;
            let mut stored = stmt.query([])?;
            while let Some(stored_row) = stored.next()? {
                let rowid: i64 = stored_row.get(0)?;
                let found = match stored_row.get_ref(1)? {
                    ValueRef::Blob(k) => wanted.get_key_value(k).map(|(k, row)| (*k, *row)),
                    _ => None,
                };
                let Some((k, row)) = found else {
                    stale_rowids.push(rowid);
                    continue;
                };
                let same = encode(row).iter().enumerate().all(|(i, expected)| {
                    stored_row
                        .get::<_, Value>(i + 1)
                        .is_ok_and(|actual| actual == *expected)
                });
                if same {
                    unchanged.insert(k);
                }
            }
        }
        let mut delete = conn.prepare(&format!("DELETE FROM {table} WHERE rowid = ?1"))?;
        for rowid in stale_rowids {
            delete.execute(params![rowid])?;
        }
        let mut upsert = conn.prepare(upsert_sql)?;
        for row in rows {
            if !unchanged.contains(key(row)) {
                upsert.execute(rusqlite::params_from_iter(encode(row)))?;
            }
        }
        Ok(())
    }

    /// Persist a friend the user added by code.
    ///
    /// `Ok(None)` — blocked, nothing written.
    /// `Ok(Some(mutual))` — row written. `mutual` is true when a matching
    /// `friend_requests` row existed and was consumed (same grant as
    /// `accept_friend_request`), so pasting someone's code after they already
    /// asked is not left as a one-sided friend plus a leftover request.
    pub fn add_friend(
        &self,
        user_hash: &str,
        nickname: &str,
        ed25519_pubkey: Option<&[u8; 32]>,
    ) -> anyhow::Result<Option<bool>> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let now = chrono::Utc::now().timestamp();
        // The command checks first so it can report this properly; repeating
        // it here closes the window where a block commits in between and
        // leaves the identity listed as a friend and blocked at once.
        //
        // `Ok(None)` rather than an error, matching `add_friend_request`: the
        // caller needs to tell "blocked" from a genuine save failure so it can
        // name the right reason. Bailing here surfaced the race as "Failed to
        // save friend: identity is blocked".
        if Self::blocked_in(&tx, user_hash)? {
            return Ok(None);
        }

        let pending: Option<(String, String, u16, Option<Vec<u8>>)> = {
            let mut stmt = tx.prepare(
                "SELECT sender_nickname, COALESCE(sender_ip, ''), COALESCE(sender_port, 0), sender_pubkey \
                 FROM friend_requests WHERE sender_hash = ?1",
            )?;
            // Only "no such request" may fall through to a one-sided add. A
            // real query failure has to propagate: swallowing it would silently
            // downgrade the add to non-mutual *and* leave the request row in
            // place, so the user gets a friend they cannot browse plus a
            // pending request they already answered.
            match stmt.query_row(params![user_hash], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?.clamp(0, u16::MAX as i64) as u16,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                ))
            }) {
                Ok(row) => Some(row),
                Err(rusqlite::Error::QueryReturnedNoRows) => None,
                Err(e) => return Err(e.into()),
            }
        };

        let (stored_nick, mutual, pending_pubkey, pending_ip, pending_port) =
            if let Some((req_nick, ip, port, pk)) = pending {
                let nick = if nickname.is_empty() {
                    req_nick
                } else {
                    nickname.to_string()
                };
                (nick, true, pk, ip, port)
            } else {
                (
                    nickname.to_string(),
                    false,
                    None,
                    String::new(),
                    0u16,
                )
            };
        let pubkey = ed25519_pubkey
            .map(|key| key.as_slice())
            .or(pending_pubkey.as_deref());

        tx.execute(
            "INSERT INTO friends (user_hash, nickname, added_at, mutual, ed25519_pubkey) \
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(user_hash) DO UPDATE SET \
                 nickname = CASE WHEN excluded.nickname != '' \
                     THEN excluded.nickname ELSE friends.nickname END, \
                 mutual = MAX(friends.mutual, excluded.mutual), \
                 ed25519_pubkey = COALESCE(excluded.ed25519_pubkey, friends.ed25519_pubkey)",
            params![user_hash, stored_nick, now, if mutual { 1i64 } else { 0 }, pubkey],
        )?;
        if mutual && !pending_ip.is_empty() && pending_port > 0 {
            tx.execute(
                "UPDATE friends SET last_ip = ?2, last_port = ?3, last_seen = ?4 WHERE user_hash = ?1",
                params![user_hash, pending_ip, pending_port as i64, now],
            )?;
        }
        if mutual {
            tx.execute(
                "DELETE FROM friend_requests WHERE sender_hash = ?1",
                params![user_hash],
            )?;
        }
        // Adding them again countermands an undelivered withdrawal. Leaving it
        // queued would let the courier retract the request this add just sent.
        tx.execute(
            "DELETE FROM friend_request_retractions WHERE user_hash = ?1",
            params![user_hash],
        )?;
        // And an undelivered refusal of *their* request: adding them is the
        // opposite answer, so telling them no afterwards would contradict the
        // request this add is sending.
        tx.execute(
            "DELETE FROM friend_request_declines WHERE user_hash = ?1",
            params![user_hash],
        )?;
        tx.commit()?;
        Ok(Some(mutual))
    }

    /// Record the intro secret from a friend's `ember3:` code. `false` when no
    /// friend row matches (removed in between), so nothing was written.
    pub fn set_friend_intro_secret(
        &self,
        user_hash: &str,
        intro_secret: &[u8; crate::network::ember::crypto::INTRO_SECRET_LEN],
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let updated = conn.execute(
            "UPDATE friends SET intro_secret = ?2 WHERE user_hash = ?1",
            params![user_hash, intro_secret.as_slice()],
        )?;
        Ok(updated > 0)
    }

    /// Friends whose row has no usable public key — absent, malformed, or not
    /// bound to their hash — so no pairwise presence can be registered for
    /// them.
    pub fn get_hash_only_friends(&self) -> anyhow::Result<Vec<HashOnlyFriend>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT user_hash, ed25519_pubkey, mutual, \
             MAX(COALESCE(last_seen, 0), COALESCE(added_at, 0)) FROM friends",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, i64>(2)? != 0,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            .filter_map(|(hash_hex, pubkey, mutual, last_contact)| {
                let hash = <[u8; 16]>::try_from(hex::decode(&hash_hex).ok()?).ok()?;
                let keyed = pubkey
                    .and_then(|key| <[u8; 32]>::try_from(key).ok())
                    .is_some_and(|key| {
                        crate::network::ember::crypto::verify_ember_hash_binding(&key, &hash)
                    });
                (!keyed).then_some(HashOnlyFriend {
                    hash,
                    mutual,
                    last_contact,
                })
            })
            .collect())
    }

    /// Store a public key learned for an existing friend. The caller has
    /// checked it binds to the hash, which also makes it the only key the row
    /// could legitimately hold.
    pub fn set_friend_public_key(
        &self,
        user_hash: &str,
        ed25519_pubkey: &[u8; 32],
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let updated = conn.execute(
            "UPDATE friends SET ed25519_pubkey = ?2 WHERE user_hash = ?1",
            params![user_hash, ed25519_pubkey.as_slice()],
        )?;
        Ok(updated > 0)
    }

    /// Clear intro secrets that pairwise presence has made redundant: the
    /// friend is mutual and we hold a key bound to their hash. Returns the
    /// hashes cleared so the in-memory copies can go too.
    pub fn clear_keyed_mutual_friend_intro_secrets(&self) -> anyhow::Result<Vec<[u8; 16]>> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let rows = {
            let mut stmt = tx.prepare(
                "SELECT user_hash, ed25519_pubkey FROM friends \
                 WHERE mutual = 1 AND intro_secret IS NOT NULL AND ed25519_pubkey IS NOT NULL",
            )?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        let mut cleared = Vec::new();
        for (hash_hex, pubkey) in rows {
            let Some(hash) = hex::decode(&hash_hex)
                .ok()
                .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
            else {
                continue;
            };
            let keyed = <[u8; 32]>::try_from(pubkey).is_ok_and(|key| {
                crate::network::ember::crypto::verify_ember_hash_binding(&key, &hash)
            });
            if keyed {
                tx.execute(
                    "UPDATE friends SET intro_secret = NULL WHERE user_hash = ?1",
                    params![hash_hex],
                )?;
                cleared.push(hash);
            }
        }
        tx.commit()?;
        Ok(cleared)
    }

    /// Every stored friend intro secret, skipping rows that do not decode.
    pub fn get_friend_intro_secrets(
        &self,
    ) -> anyhow::Result<Vec<([u8; 16], [u8; crate::network::ember::crypto::INTRO_SECRET_LEN])>>
    {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT user_hash, intro_secret FROM friends WHERE intro_secret IS NOT NULL",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            .filter_map(|(hash_hex, secret)| {
                let hash = <[u8; 16]>::try_from(hex::decode(&hash_hex).ok()?).ok()?;
                let secret = <[u8; crate::network::ember::crypto::INTRO_SECRET_LEN]>::try_from(
                    secret,
                )
                .ok()?;
                Some((hash, secret))
            })
            .collect())
    }

    pub fn get_friend_public_keys(&self) -> anyhow::Result<Vec<([u8; 16], [u8; 32])>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT user_hash, ed25519_pubkey FROM friends \
             WHERE ed25519_pubkey IS NOT NULL",
        )?;
        let rows = stmt
            .query_map([], |row| {
                let hash_hex: String = row.get(0)?;
                let pubkey: Vec<u8> = row.get(1)?;
                Ok((hash_hex, pubkey))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        // One unusable row must not take the list down with it. A friend request
        // can be accepted while carrying a public key that does not bind to the
        // sender's hash, and returning `Err` here left the only caller — which
        // recovers with `unwrap_or_default` — advertising presence for nobody.
        // A key we cannot trust is a friend we cannot advertise to, not a reason
        // to stop advertising to the rest.
        let mut keys = Vec::with_capacity(rows.len());
        for (hash_hex, pubkey) in rows {
            let hash = hex::decode(&hash_hex)
                .ok()
                .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok());
            let Some(hash) = hash else {
                warn!("Skipping friend with an unusable stored hash: {hash_hex}");
                continue;
            };
            let Ok(pubkey) = <[u8; 32]>::try_from(pubkey) else {
                warn!("Skipping friend {hash_hex} with an unusable stored public key");
                continue;
            };
            if !crate::network::ember::crypto::verify_ember_hash_binding(&pubkey, &hash) {
                warn!(
                    "Skipping friend {hash_hex}: the stored public key does not match the \
                     friend hash, so presence advertised under it would be unreachable"
                );
                continue;
            }
            keys.push((hash, pubkey));
        }
        Ok(keys)
    }

    /// Remove a friend. Returns true when the removal left a friend request to
    /// withdraw, so the caller can try to tell the peer.
    ///
    /// A one-sided friend is a request the peer has not answered yet, and
    /// cancelling used to be purely local — their prompt stayed on screen with
    /// no way to take it back. The address is copied into the retraction queue
    /// here because the `friends` row that holds it is about to be deleted, and
    /// nothing else remembers where that peer lives.
    pub fn remove_friend(&self, user_hash: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        // A mutual friend consumed their request when they accepted it, so
        // there is nothing queued on their side to withdraw.
        let pending: Option<(String, i64)> = tx
            .query_row(
                "SELECT COALESCE(last_ip, ''), COALESCE(last_port, 0) FROM friends \
                 WHERE user_hash = ?1 AND mutual = 0",
                params![user_hash],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((last_ip, last_port)) = pending.as_ref() {
            tx.execute(
                "INSERT INTO friend_request_retractions (user_hash, last_ip, last_port, queued_at) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(user_hash) DO UPDATE SET last_ip = excluded.last_ip, \
                     last_port = excluded.last_port",
                params![
                    user_hash,
                    last_ip,
                    last_port,
                    chrono::Utc::now().timestamp()
                ],
            )?;
        }
        tx.execute(
            "DELETE FROM chat_messages WHERE friend_hash = ?1",
            params![user_hash],
        )?;
        // Takes the friend's grants with it: a `sent` row is what makes its
        // `source_path` readable to them.
        tx.execute(
            "DELETE FROM chat_attachments WHERE friend_hash = ?1",
            params![user_hash],
        )?;
        tx.execute(
            "DELETE FROM friends WHERE user_hash = ?1",
            params![user_hash],
        )?;
        tx.execute(
            "DELETE FROM friend_requests WHERE sender_hash = ?1",
            params![user_hash],
        )?;
        tx.commit()?;
        Ok(pending.is_some())
    }

    /// Record what became of an originated room line, by its wire identity.
    ///
    /// Keyed by `(channel_id, msg_id)` rather than the row id because the
    /// network task works in gossip frames and never learns the row id — and
    /// that pair is the dedup index, so the lookup is already paid for.
    ///
    /// Only ever moves a `sent` row: a received line is delivered by
    /// definition, and a replayed frame naming somebody else's message must
    /// not be able to mark their history failed. Returns the row id when a row
    /// actually moved, so the caller can name it in an event and stay quiet
    /// when nothing changed.
    pub fn set_channel_delivery(
        &self,
        channel_id: &str,
        msg_id: &str,
        delivery: i64,
    ) -> anyhow::Result<Option<i64>> {
        let conn = self.conn.lock();
        // One transaction, so the row the id names is the row that moved. Read
        // and write apart, a concurrent verdict for the same line could settle
        // between them and this would report a change it did not make.
        let tx = conn.unchecked_transaction()?;
        let row: Option<i64> = tx
            .query_row(
                "SELECT id FROM channel_messages \
                 WHERE channel_id = ?1 AND msg_id = ?2 AND direction = 'sent' AND delivery != ?3",
                params![channel_id, msg_id, delivery],
                |row| row.get(0),
            )
            .optional()?;
        let Some(id) = row else {
            tx.commit()?;
            return Ok(None);
        };
        tx.execute(
            "UPDATE channel_messages SET delivery = ?2 WHERE id = ?1",
            params![id, delivery],
        )?;
        tx.commit()?;
        Ok(Some(id))
    }

    /// How the UI names a stored `delivery` value.
    ///
    /// Here rather than beside either caller because both the load path and
    /// the live event have to agree on the word, and two matches on the same
    /// three constants is exactly the pair that drifts.
    pub fn delivery_label(delivery: i64) -> &'static str {
        match delivery {
            CHAT_QUEUED => "queued",
            CHAT_FAILED => "failed",
            _ => "delivered",
        }
    }

    /// Sent room lines still marked queued at startup.
    ///
    /// The retry queue that would have resolved them lives in memory, so a
    /// restart mid-flight would otherwise leave a bubble reading "sending"
    /// for the life of the database with nothing left to move it.
    ///
    /// Only lines written at or before `cutoff` — the second this run started.
    /// Anything later belongs to this run, still in its command queue or retry
    /// queue, and will be settled by that.
    pub fn fail_stale_queued_channel_messages(&self, cutoff: i64) -> anyhow::Result<usize> {
        let conn = self.conn.lock();
        let changed = conn.execute(
            "UPDATE channel_messages SET delivery = ?1 \
             WHERE direction = 'sent' AND delivery = ?2 AND timestamp <= ?3",
            params![CHAT_FAILED, CHAT_QUEUED, cutoff],
        )?;
        Ok(changed)
    }

    /// Act on a peer's refusal of a request we sent them.
    ///
    /// Deletes only a `friends` row they have never accepted. `mutual = 0` is
    /// the whole of the guard: once a friendship is established their refusal
    /// of a request that no longer exists must not be able to end it, and the
    /// wire message carries nothing but an identity, so the row's own state is
    /// the only thing that can decide whether it is still refusable.
    ///
    /// `Ok(false)` when there was nothing pending — they accepted first, or we
    /// removed them in the meantime.
    pub fn decline_friend_request(&self, user_hash: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let removed = tx.execute(
            "DELETE FROM friends WHERE user_hash = ?1 AND mutual = 0",
            params![user_hash],
        )?;
        if removed == 0 {
            tx.commit()?;
            return Ok(false);
        }
        // Our own outbound queue for this identity is moot now: a withdrawal
        // of the request they have just refused would dial them to take back
        // something already gone.
        tx.execute(
            "DELETE FROM friend_request_retractions WHERE user_hash = ?1",
            params![user_hash],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Queue a refusal of `user_hash`'s request for delivery.
    ///
    /// Written in the transaction that deletes the request, for the reason the
    /// retraction queue exists: the request row holds the only address we have
    /// for somebody who is not a friend, so the address has to be copied out
    /// at the moment of removal or the courier has nowhere to dial.
    ///
    /// `Ok(false)` when there was no request to refuse, or nowhere to send the
    /// refusal.
    pub fn reject_and_queue_friend_decline(&self, user_hash: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let pending: Option<(String, i64, bool)> = tx
            .query_row(
                "SELECT COALESCE(sender_ip, ''), COALESCE(sender_port, 0),
                        sender_pubkey IS NOT NULL AND COALESCE(verified, 0) != 0
                 FROM friend_requests WHERE sender_hash = ?1",
                params![user_hash],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((last_ip, last_port, keyed)) = pending else {
            tx.commit()?;
            return Ok(false);
        };
        tx.execute(
            "DELETE FROM friend_requests WHERE sender_hash = ?1",
            params![user_hash],
        )?;
        // Remembered past the decline's delivery, which clears its queue row:
        // a member replaying the room envelope the request came in, before it
        // ages out, must not put the question back.
        let now = chrono::Utc::now().timestamp();
        tx.execute(
            "DELETE FROM friend_request_refusals WHERE refused_at < ?1",
            params![now.saturating_sub(FRIEND_REQUEST_REFUSAL_MEMORY_SECS)],
        )?;
        tx.execute(
            "INSERT INTO friend_request_refusals (user_hash, refused_at) VALUES (?1, ?2)
             ON CONFLICT(user_hash) DO UPDATE SET refused_at = excluded.refused_at",
            params![user_hash, now],
        )?;
        // Only worth a courier if it can reach them: at the address the request
        // came from, or through the rendezvous, which finds a sender that
        // proved its key because a sender who has our key publishes pairwise
        // presence for us. A request that came through a room has only the
        // second. Anything else is still rejected locally — the queue is about
        // delivery, not about the decision.
        let addressed = !last_ip.is_empty() && last_port > 0;
        if addressed || keyed {
            tx.execute(
                "INSERT INTO friend_request_declines (user_hash, last_ip, last_port, queued_at) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(user_hash) DO UPDATE SET last_ip = excluded.last_ip, \
                     last_port = excluded.last_port, queued_at = excluded.queued_at",
                params![
                    user_hash,
                    last_ip,
                    last_port,
                    chrono::Utc::now().timestamp()
                ],
            )?;
        }
        tx.commit()?;
        Ok(addressed || keyed)
    }

    /// Refusals not yet delivered, as `(user_hash, last_ip, last_port)`.
    pub fn pending_friend_request_declines(&self) -> anyhow::Result<Vec<(String, String, u16)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT user_hash, last_ip, last_port FROM friend_request_declines \
             ORDER BY queued_at ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?.clamp(0, u16::MAX as i64) as u16,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Forget a queued refusal — delivered, or no longer wanted because the
    /// user added or blocked that identity in the meantime.
    pub fn clear_friend_request_decline(&self, user_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM friend_request_declines WHERE user_hash = ?1",
            params![user_hash],
        )?;
        Ok(())
    }

    /// Drop refusals we have failed to deliver for
    /// [`RETRACTION_QUEUE_MAX_AGE_SECS`] — the same ceiling and the same
    /// reason as the withdrawal queue, since the row likewise holds the
    /// address of somebody the user has declined to know.
    pub fn expire_stale_friend_request_declines(&self) -> anyhow::Result<usize> {
        let conn = self.conn.lock();
        let cutoff = chrono::Utc::now().timestamp() - RETRACTION_QUEUE_MAX_AGE_SECS;
        let removed = conn.execute(
            "DELETE FROM friend_request_declines WHERE queued_at < ?1",
            params![cutoff],
        )?;
        Ok(removed)
    }

    /// Friend requests withdrawn but not yet delivered, as
    /// `(user_hash, last_ip, last_port)`.
    pub fn pending_friend_request_retractions(
        &self,
    ) -> anyhow::Result<Vec<(String, String, u16)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT user_hash, last_ip, last_port FROM friend_request_retractions \
             ORDER BY queued_at ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?.clamp(0, u16::MAX as i64) as u16,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Forget a queued retraction — delivered, or no longer wanted because the
    /// user added or blocked that identity in the meantime.
    pub fn clear_friend_request_retraction(&self, user_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM friend_request_retractions WHERE user_hash = ?1",
            params![user_hash],
        )?;
        Ok(())
    }

    /// Drop retractions we have failed to deliver for
    /// [`RETRACTION_QUEUE_MAX_AGE_SECS`]. Matches the chat outbox rather than
    /// retrying forever: a peer absent this long has most likely abandoned the
    /// identity, and the queue is the last thing holding their address.
    pub fn expire_stale_friend_request_retractions(&self) -> anyhow::Result<usize> {
        let conn = self.conn.lock();
        let cutoff = chrono::Utc::now().timestamp() - RETRACTION_QUEUE_MAX_AGE_SECS;
        let removed = conn.execute(
            "DELETE FROM friend_request_retractions WHERE queued_at < ?1",
            params![cutoff],
        )?;
        Ok(removed)
    }

    /// End a friendship and record that the user wants no further contact.
    ///
    /// Both halves happen in one transaction because either alone is worse
    /// than neither: a removal whose block was lost invites the peer straight
    /// back, and a block whose removal failed leaves them listed as a friend.
    pub fn block_friend(&self, user_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        // Read the name before deleting the rows that hold it — this is the
        // user's only handle on the entry afterwards.
        let nickname: String = tx
            .query_row(
                "SELECT nickname FROM friends WHERE user_hash = ?1",
                params![user_hash],
                |row| row.get(0),
            )
            .or_else(|_| {
                tx.query_row(
                    "SELECT sender_nickname FROM friend_requests WHERE sender_hash = ?1",
                    params![user_hash],
                    |row| row.get(0),
                )
            })
            .unwrap_or_default();
        tx.execute(
            // Re-blocking must not erase what we already knew. By the second
            // call the friend and request rows are long gone, so the lookup
            // above finds nothing and would otherwise overwrite a good name
            // with an empty one. `blocked_at` likewise keeps the date of the
            // original decision rather than the retry.
            "INSERT INTO friend_blocks (user_hash, nickname, blocked_at) \
             VALUES (?1, ?2, ?3) \
             ON CONFLICT(user_hash) DO UPDATE SET \
                 nickname = CASE WHEN excluded.nickname != '' \
                     THEN excluded.nickname ELSE friend_blocks.nickname END",
            params![user_hash, nickname, chrono::Utc::now().timestamp()],
        )?;
        tx.execute(
            "DELETE FROM chat_messages WHERE friend_hash = ?1",
            params![user_hash],
        )?;
        tx.execute(
            "DELETE FROM chat_attachments WHERE friend_hash = ?1",
            params![user_hash],
        )?;
        tx.execute(
            "DELETE FROM friends WHERE user_hash = ?1",
            params![user_hash],
        )?;
        tx.execute(
            "DELETE FROM friend_requests WHERE sender_hash = ?1",
            params![user_hash],
        )?;
        // Blocking means no further contact in either direction, so neither
        // queue may keep dialling them. Their copy of the request becomes moot
        // anyway: accepting it cannot reach us through the block.
        tx.execute(
            "DELETE FROM friend_request_retractions WHERE user_hash = ?1",
            params![user_hash],
        )?;
        tx.execute(
            "DELETE FROM friend_request_declines WHERE user_hash = ?1",
            params![user_hash],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Lift a block. Deliberately does not restore the friendship: the rows
    /// were deleted when it was applied, so the two have to add each other
    /// again, which is the same handshake any other pair goes through.
    pub fn unblock_friend(&self, user_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM friend_blocks WHERE user_hash = ?1",
            params![user_hash],
        )?;
        Ok(())
    }

    pub fn is_friend_blocked(&self, user_hash: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Ok(Self::blocked_in(&conn, user_hash)?)
    }

    /// The block test as run *inside* an open transaction.
    ///
    /// Every path that can grant an identity access has to consult this
    /// within the same transaction that does the writing. Checking
    /// beforehand only proves they were not blocked at the time of the
    /// check: blocking commits from the UI thread, so it can land in the
    /// window between a caller's test and its insert, and the request or
    /// friendship would then be written over the top of a live block.
    fn blocked_in(conn: &Connection, user_hash: &str) -> rusqlite::Result<bool> {
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM friend_blocks WHERE user_hash = ?1",
            params![user_hash],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// How often a friend has been asked through rooms, and when last, as
    /// `(asks, asked_at)`. `None` when they are not on the list.
    pub fn room_friend_request_asks(&self, user_hash: &str) -> anyhow::Result<Option<(i64, i64)>> {
        let conn = self.conn.lock();
        Ok(conn
            .query_row(
                "SELECT room_asks, room_asked_at FROM friends WHERE user_hash = ?1",
                params![user_hash],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    pub fn set_room_friend_request_asks(
        &self,
        user_hash: &str,
        asks: i64,
        asked_at: i64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE friends SET room_asks = ?2, room_asked_at = ?3 WHERE user_hash = ?1",
            params![user_hash, asks, asked_at],
        )?;
        Ok(())
    }

    /// `(user_hash, nickname, blocked_at)`, most recently blocked first.
    pub fn get_blocked_friends(&self) -> anyhow::Result<Vec<(String, String, i64)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT user_hash, nickname, blocked_at FROM friend_blocks \
             ORDER BY blocked_at DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn get_friends(&self) -> anyhow::Result<Vec<(String, String, i64)>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT user_hash, nickname, added_at FROM friends ORDER BY added_at DESC")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Update the nickname for an existing friend. Returns `Ok(true)`
    /// if the row existed and was updated, `Ok(false)` if no friend
    /// matches `user_hash` (so the caller can surface a real error
    /// instead of silently succeeding).
    pub fn update_friend_nickname(&self, user_hash: &str, nickname: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let updated = conn.execute(
            "UPDATE friends SET nickname = ?2 WHERE user_hash = ?1",
            params![user_hash, nickname],
        )?;
        Ok(updated > 0)
    }

    pub fn update_friend_address(
        &self,
        user_hash: &str,
        ip: &str,
        port: u16,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "UPDATE friends SET last_ip = ?2, last_port = ?3, last_seen = ?4 WHERE user_hash = ?1",
            params![user_hash, ip, port as i64, now],
        )?;
        Ok(())
    }

    pub fn clear_friend_address(&self, user_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE friends SET last_ip = '', last_port = 0 WHERE user_hash = ?1",
            params![user_hash],
        )?;
        Ok(())
    }

    pub fn get_friend_address(&self, user_hash: &str) -> anyhow::Result<Option<(String, u16)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT COALESCE(last_ip, ''), COALESCE(last_port, 0) FROM friends WHERE user_hash = ?1"
        )?;
        let result = stmt.query_row(params![user_hash], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?.clamp(0, u16::MAX as i64) as u16,
            ))
        });
        match result {
            Ok((ip, port)) if !ip.is_empty() && port > 0 => Ok(Some((ip, port))),
            Ok(_) => Ok(None),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_friends_full(
        &self,
    ) -> anyhow::Result<Vec<(String, String, i64, String, u16, i64, bool)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT user_hash, nickname, added_at, COALESCE(last_ip, ''), COALESCE(last_port, 0), COALESCE(last_seen, 0), COALESCE(mutual, 0) FROM friends ORDER BY added_at DESC"
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?.clamp(0, u16::MAX as i64) as u16,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)? != 0,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn add_friend_request(
        &self,
        sender_hash: &str,
        sender_pubkey: Option<&[u8; 32]>,
        nickname: &str,
        sender_ip: &str,
        sender_port: u16,
        verified: bool,
    ) -> anyhow::Result<bool> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let queued = Self::add_friend_request_in(
            &tx,
            sender_hash,
            sender_pubkey,
            nickname,
            sender_ip,
            sender_port,
            verified,
            "",
            chrono::Utc::now().timestamp(),
        )?;
        if queued {
            tx.commit()?;
        }
        Ok(queued)
    }

    /// Queue a friend request that reached us through room `channel_id`, in an
    /// envelope dated `sent_at`. `Ok(false)` when it is not queued.
    ///
    /// Held to more than a request from a session, because any key a room will
    /// carry can send one and nobody but the recipient sees it: it must not
    /// come from someone already on our list or asked to go away, the room may
    /// only bring [`ROOM_FRIEND_REQUESTS_PER_ROOM_HOUR`] new ones an hour, and
    /// a full table makes room for it only at the expense of other room or
    /// unverified requests, never one a session proved.
    pub fn add_room_friend_request(
        &self,
        sender_hash: &str,
        sender_pubkey: &[u8; 32],
        nickname: &str,
        channel_id: &str,
        sent_at: i64,
        now: i64,
    ) -> anyhow::Result<bool> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let listed: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM friends WHERE user_hash = ?1)
                 OR EXISTS(SELECT 1 FROM friend_request_declines WHERE user_hash = ?1)
                 OR EXISTS(SELECT 1 FROM friend_request_refusals
                           WHERE user_hash = ?1 AND refused_at + ?3 >= ?2)",
            params![
                sender_hash,
                sent_at,
                crate::network::ember::channel::CHANNEL_GOSSIP_MAX_FUTURE_SKEW_SECS
            ],
            |row| row.get(0),
        )?;
        if listed {
            return Ok(false);
        }
        let present: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM friend_requests WHERE sender_hash = ?1)",
            params![sender_hash],
            |row| row.get(0),
        )?;
        if !present {
            let recent: i64 = tx.query_row(
                "SELECT COUNT(*) FROM friend_requests WHERE via_room = ?1 AND received_at > ?2",
                params![channel_id, now.saturating_sub(3600)],
                |row| row.get(0),
            )?;
            if recent >= ROOM_FRIEND_REQUESTS_PER_ROOM_HOUR {
                return Ok(false);
            }
        }
        let queued = Self::add_friend_request_in(
            &tx,
            sender_hash,
            Some(sender_pubkey),
            nickname,
            "",
            0,
            true,
            channel_id,
            now,
        )?;
        if queued {
            tx.commit()?;
        }
        Ok(queued)
    }

    /// Everything [`Self::add_friend_request`] writes, inside the caller's
    /// transaction. `via_room` is the room a request came through, empty for
    /// one from a session.
    #[allow(clippy::too_many_arguments)]
    fn add_friend_request_in(
        tx: &Connection,
        sender_hash: &str,
        sender_pubkey: Option<&[u8; 32]>,
        nickname: &str,
        sender_ip: &str,
        sender_port: u16,
        verified: bool,
        via_room: &str,
        now: i64,
    ) -> anyhow::Result<bool> {
        // The network ingress normalizes this already, but keep the storage
        // boundary bounded for future callers and migrations that bypass the
        // live event path.
        let nickname = crate::security::sanitize_inbound_friend_nickname(nickname);

        // Authoritative block test. Callers check first to avoid the work of
        // queueing and notifying, but this is the one that decides, because
        // it cannot be raced by a block committing mid-flight.
        if Self::blocked_in(tx, sender_hash)? {
            return Ok(false);
        }

        // M2: cap total inbound `friend_requests` rows. Per-sender
        // UPSERT below already prevents same-hash flooding, but an
        // attacker that iterates random ember_hashes from EPX
        // dumps could otherwise grow this table without bound and
        // (a) consume disk, (b) hide legitimate requests under a
        // sea of spoofed ones in the UI list. We pick 100 unique
        // pending requests as a generous practical ceiling. When
        // overflowing, evict the oldest **unverified** rows first,
        // then the oldest that came through a room, and only then
        // — and only for a request from a session — the oldest
        // verified one. A request through a room is proven by a key
        // anyone can mint, so it may displace noise and its own kind
        // but never a request a session proved; with nothing it may
        // displace, it is refused. A repeat request from a sender
        // already present is exempt from the cap — it just refreshes
        // the existing row via the UPSERT.
        const MAX_FRIEND_REQUESTS: i64 = 100;
        let already_present: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM friend_requests WHERE sender_hash = ?1",
                params![sender_hash],
                |row| row.get(0),
            )
            .unwrap_or(0);
        if already_present == 0 {
            let total: i64 = tx
                .query_row("SELECT COUNT(*) FROM friend_requests", [], |row| row.get(0))
                .unwrap_or(0);
            if total >= MAX_FRIEND_REQUESTS {
                let mut remaining = (total - MAX_FRIEND_REQUESTS + 1).max(1);
                let mut tiers = vec![
                    "COALESCE(verified, 0) = 0",
                    "COALESCE(verified, 0) != 0 AND via_room != ''",
                ];
                if via_room.is_empty() {
                    tiers.push("1");
                }
                for tier in tiers {
                    if remaining <= 0 {
                        break;
                    }
                    // `tier` is one of the literals above, never input.
                    remaining -= tx.execute(
                        &format!(
                            "DELETE FROM friend_requests WHERE sender_hash IN (
                                SELECT sender_hash FROM friend_requests
                                WHERE {tier}
                                ORDER BY received_at ASC
                                LIMIT ?1
                            )"
                        ),
                        params![remaining],
                    )? as i64;
                }
                if remaining > 0 {
                    return Ok(false);
                }
            }
        }

        // Refresh behaviour: a repeat request from the same peer
        // can legitimately change any of the fields on the row,
        // including the verification flag (e.g. an older request
        // arrived on an unverified path, a later one on a verified
        // path). We preserve the "verified once, always verified"
        // monotonicity across refreshes so a spoofer can't silently
        // *downgrade* an existing verified request by flooding
        // unverified requests from another channel — a legitimate
        // re-request from the real user always raises the flag or
        // leaves it unchanged, never lowers it.
        //
        // The same goes for the fields an accept acts on: an unverified
        // request must not repoint a verified one's nickname or address,
        // since accepting it would dial whatever the spoofer supplied.
        //
        // A request that carries no address — one through a room — leaves a
        // verified address where it is, and does not rename a verified request
        // a session made: the nickname a session carried is the one they
        // chose, the room's is only what that room calls them. Which kind a row
        // counts as follows whatever verified it, so the eviction order above
        // cannot be climbed by pairing a room request with an unproven one.
        tx.execute(
            "INSERT INTO friend_requests (sender_hash, sender_nickname, received_at, sender_ip, sender_port, verified, sender_pubkey, via_room)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(sender_hash) DO UPDATE SET
             sender_nickname = CASE
                WHEN COALESCE(friend_requests.verified, 0) != 0
                     AND (excluded.verified = 0
                          OR (excluded.via_room != '' AND friend_requests.via_room = ''))
                    THEN friend_requests.sender_nickname
                ELSE excluded.sender_nickname END,
             sender_ip = CASE
                WHEN COALESCE(friend_requests.verified, 0) != 0
                     AND (excluded.verified = 0 OR COALESCE(excluded.sender_ip, '') = '')
                    THEN friend_requests.sender_ip
                ELSE excluded.sender_ip END,
             sender_port = CASE
                WHEN COALESCE(friend_requests.verified, 0) != 0
                     AND (excluded.verified = 0 OR COALESCE(excluded.sender_ip, '') = '')
                    THEN friend_requests.sender_port
                ELSE excluded.sender_port END,
             verified = MAX(COALESCE(friend_requests.verified, 0), excluded.verified),
             sender_pubkey = CASE WHEN excluded.verified != 0
                THEN COALESCE(excluded.sender_pubkey, friend_requests.sender_pubkey)
                ELSE friend_requests.sender_pubkey END,
             via_room = CASE
                WHEN excluded.verified != 0 AND excluded.via_room = '' THEN ''
                WHEN excluded.verified != 0 AND COALESCE(friend_requests.verified, 0) = 0
                    THEN excluded.via_room
                ELSE friend_requests.via_room END",
            params![
                sender_hash,
                nickname,
                now,
                sender_ip,
                sender_port as i64,
                verified as i64,
                sender_pubkey.map(|key| key.as_slice()),
                via_room
            ],
        )?;
        Ok(true)
    }

    pub fn get_friend_requests(
        &self,
    ) -> anyhow::Result<Vec<(String, String, i64, String, u16, bool)>> {
        let conn = self.conn.lock();
        // Clear leftovers from the old path, which queued a reciprocal accept
        // even though the user had already added that peer. Best-effort: the
        // SELECT below filters them out either way, so a failed write here
        // must not take down the whole list.
        if let Err(e) = conn.execute(
            "DELETE FROM friend_requests WHERE EXISTS (
                SELECT 1 FROM friends WHERE friends.user_hash = friend_requests.sender_hash
            )",
            [],
        ) {
            warn!("Could not clear friend requests from already-added peers: {e}");
        }
        // Adding someone is the approval, so their request is never something
        // to ask about again — filtered here rather than trusting the DELETE.
        let mut stmt = conn.prepare(
            "SELECT sender_hash, sender_nickname, received_at, COALESCE(sender_ip, ''), COALESCE(sender_port, 0), COALESCE(verified, 0) \
             FROM friend_requests \
             WHERE NOT EXISTS (SELECT 1 FROM friends WHERE friends.user_hash = friend_requests.sender_hash) \
             ORDER BY received_at DESC"
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?.clamp(0, u16::MAX as i64) as u16,
                    row.get::<_, i64>(5)? != 0,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn remove_friend_request(&self, sender_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM friend_requests WHERE sender_hash = ?1",
            params![sender_hash],
        )?;
        Ok(())
    }

    /// Atomic "accept friend request" path used by the
    /// `accept_friend_request` Tauri command.
    ///
    /// In a single transaction:
    ///   1. Read the matching `friend_requests` row (if any) so we can
    ///      seed the new friend's nickname and last-known address from
    ///      what the peer sent at request time.
    ///   2. Insert / update the `friends` row with `mutual = 1`,
    ///      preserving the inserted `added_at` for first-time rows.
    ///   3. If the request carried a usable IP / port, write them onto
    ///      the friend so the auto-connect path in `SendChatMessage` /
    ///      `BrowseFriend` can dial directly without paying for a
    ///      rendezvous round trip.
    ///   4. Delete the originating `friend_requests` row.
    ///
    /// Returns the (nickname, ip, port) tuple that was on the request,
    /// or `None` if no matching request existed (e.g. user accepted via
    /// stale UI state). The caller can use the returned address as a
    /// hint for an immediate friend-session dial.
    ///
    /// Doing this transactionally fixes a subtle inconsistency where
    /// the previous implementation issued three independent
    /// `conn.execute` calls; if `set_friend_mutual` failed mid-way the
    /// row would persist with `mutual = 0` while the in-memory
    /// `friend_hashes` set was rolled back, leaving `get_friends()`
    /// reporting an orphan friend that the upload path's
    /// `friend_hashes.contains(&eh)` gate would silently reject.
    pub fn accept_friend_request(
        &self,
        sender_hash: &str,
    ) -> anyhow::Result<Option<(String, String, u16)>> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;

        let request_data: Option<(String, String, u16, Option<Vec<u8>>)> = {
            let mut stmt = tx.prepare(
                "SELECT sender_nickname, COALESCE(sender_ip, ''), COALESCE(sender_port, 0), sender_pubkey \
                 FROM friend_requests WHERE sender_hash = ?1",
            )?;
            // `optional()` rather than `.ok()`: only "no such row" means the
            // request is gone. Swallowing every error turned an I/O failure or a
            // corrupt page into "friend request not found", which the caller
            // reports as a stale row and the UI answers by dropping the card —
            // so a storage fault presented as the user's own request vanishing,
            // and the retry that would have surfaced it never happened.
            stmt.query_row(params![sender_hash], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?.clamp(0, u16::MAX as i64) as u16,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                ))
            })
            .optional()?
        };

        // Refuse to "accept" a request that no longer exists. Without this a
        // stale accept (the row was withdrawn, rejected in another window, or
        // aged out of the 100-row cap) would still INSERT a `mutual = 1`
        // friend with an empty nickname and no address — a "ghost" friend the
        // user never knowingly added. The caller surfaces this as a "request
        // no longer exists" error and drops the row from the UI.
        let request_data = match request_data {
            Some(data) => data,
            None => anyhow::bail!("friend request not found"),
        };

        // A blocked identity should have no request row to accept, but the
        // two can cross: the row may already have been on screen when the
        // block was applied, and the click arrives afterwards. Accepting
        // writes `mutual = 1`, which would hand back chat and browse while
        // the block sat there looking effective.
        if Self::blocked_in(&tx, sender_hash)? {
            anyhow::bail!("identity is blocked");
        }

        let nickname = request_data.0.clone();
        let now = chrono::Utc::now().timestamp();

        // Insert the friend with `mutual = 1` directly (matches the
        // previous `add_friend` + `set_friend_mutual` semantics). On
        // conflict we refresh the nickname and re-assert mutual so a
        // re-accept after a previous demotion still flips the flag.
        // `added_at` is intentionally NOT overwritten on conflict so
        // long-standing friends keep their original add timestamp.
        tx.execute(
            "INSERT INTO friends (user_hash, nickname, added_at, mutual, ed25519_pubkey) \
             VALUES (?1, ?2, ?3, 1, ?4) \
             ON CONFLICT(user_hash) DO UPDATE SET nickname = excluded.nickname, mutual = 1,
             ed25519_pubkey = COALESCE(excluded.ed25519_pubkey, friends.ed25519_pubkey)",
            params![sender_hash, nickname, now, request_data.3.as_deref()],
        )?;

        {
            let (_, ref ip, port, _) = request_data;
            if !ip.is_empty() && port > 0 {
                tx.execute(
                    "UPDATE friends SET last_ip = ?2, last_port = ?3, last_seen = ?4 WHERE user_hash = ?1",
                    params![sender_hash, ip, port as i64, now],
                )?;
            }
        }

        tx.execute(
            "DELETE FROM friend_requests WHERE sender_hash = ?1",
            params![sender_hash],
        )?;
        tx.commit()?;
        Ok(Some((request_data.0, request_data.1, request_data.2)))
    }

    /// Promote an existing friend to mutual and refresh their last-known
    /// address. Used by the auto-confirm path: an inbound friend request from
    /// a peer we already added (that add was the approval). Also consumes any
    /// leftover `friend_requests` row for that hash (the old double-approval
    /// path queued those). Returns the number of friend rows updated — 0
    /// means the peer wasn't actually in the friend list, so the caller
    /// should fall back to queuing.
    pub fn set_friend_mutual(
        &self,
        user_hash: &str,
        ip: &str,
        port: u16,
        ed25519_pubkey: Option<&[u8; 32]>,
    ) -> anyhow::Result<usize> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let now = chrono::Utc::now().timestamp();
        // Promotion to mutual is the widest grant there is — it opens browse
        // and friends-only serving — so the block test rides along in the
        // UPDATE itself. A blocked identity matches no row, and the caller's
        // "nothing was updated" path already declines to grant anything.
        let updated = if !ip.is_empty() && port > 0 {
            tx.execute(
                "UPDATE friends SET mutual = 1, last_ip = ?2, last_port = ?3, last_seen = ?4,
                 ed25519_pubkey = COALESCE(?5, ed25519_pubkey) WHERE user_hash = ?1
                 AND NOT EXISTS (SELECT 1 FROM friend_blocks WHERE user_hash = ?1)",
                params![
                    user_hash,
                    ip,
                    port as i64,
                    now,
                    ed25519_pubkey.map(|key| key.as_slice())
                ],
            )?
        } else {
            tx.execute(
                "UPDATE friends SET mutual = 1,
                 ed25519_pubkey = COALESCE(?2, ed25519_pubkey) WHERE user_hash = ?1
                 AND NOT EXISTS (SELECT 1 FROM friend_blocks WHERE user_hash = ?1)",
                params![user_hash, ed25519_pubkey.map(|key| key.as_slice())],
            )?
        };
        if updated > 0 {
            tx.execute(
                "DELETE FROM friend_requests WHERE sender_hash = ?1",
                params![user_hash],
            )?;
        }
        tx.commit()?;
        Ok(updated)
    }

    /// Delivery state of an outbound chat message. Received messages are
    /// always [`ChatDelivery::Delivered`].
    pub fn insert_chat_message(
        &self,
        friend_hash: &str,
        direction: &str,
        message: &str,
    ) -> anyhow::Result<i64> {
        self.insert_chat_message_with_delivery(friend_hash, direction, message, CHAT_DELIVERED)
    }

    /// Store an outbound message that could not be handed to a live session,
    /// so it can be flushed the next time the friend is reachable.
    pub fn insert_pending_chat_message(
        &self,
        friend_hash: &str,
        message: &str,
    ) -> anyhow::Result<i64> {
        self.insert_chat_message_with_delivery(friend_hash, "sent", message, CHAT_QUEUED)
    }

    pub fn insert_chat_message_with_delivery(
        &self,
        friend_hash: &str,
        direction: &str,
        message: &str,
        delivery: i64,
    ) -> anyhow::Result<i64> {
        // Cap stored message length. Incoming chat text comes straight off
        // the wire from a peer, so bound it here (on a char boundary, so we
        // never split a multi-byte sequence) to stop a hostile friend from
        // bloating the DB with a single huge message. 4 KiB matches the
        // comment-length ceiling used elsewhere.
        const MAX_CHAT_MESSAGE_LEN: usize = 4096;
        let message: &str = if message.len() > MAX_CHAT_MESSAGE_LEN {
            let mut end = MAX_CHAT_MESSAGE_LEN;
            while end > 0 && !message.is_char_boundary(end) {
                end -= 1;
            }
            &message[..end]
        } else {
            message
        };
        // Per-friend retention cap. The frontend chat sidebar paginates
        // the most-recent messages, so storing more than this provides
        // no UX benefit while letting `chat_messages` grow without
        // bound across long-lived friendships. 5000 messages per friend
        // covers months-to-years of normal conversation; beyond that we
        // age out the oldest entries on insert so the DB stays compact.
        const MAX_MESSAGES_PER_FRIEND: i64 = 5_000;
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let now = chrono::Utc::now().timestamp();
        let body_hash = Self::friend_chat_body_hash_hex(message);
        tx.execute(
            "INSERT INTO chat_messages (friend_hash, direction, message, timestamp, read, delivery, seen, body_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)",
            params![friend_hash, direction, CHAT_CIPHERTEXT_PREFIX, now, if direction == "sent" { 1 } else { 0 }, delivery, body_hash],
        )?;
        let new_id = tx.last_insert_rowid();
        let encrypted = Self::encrypt_chat_body(
            self.require_chat_key()?,
            new_id,
            friend_hash,
            direction,
            now,
            message,
        )?;
        tx.execute(
            "UPDATE chat_messages SET message = ?1 WHERE id = ?2",
            params![encrypted, new_id],
        )?;
        // Trim oldest messages above the cap. SQLite's `LIMIT -1 OFFSET ?`
        // means "everything past the first ? newest rows"; we delete
        // those. Friend hash is already validated upstream so we can
        // pass it directly into the parameterised SQL.
        tx.execute(
            "DELETE FROM chat_messages WHERE id IN (
                 SELECT id FROM chat_messages
                 WHERE friend_hash = ?1
                 ORDER BY id DESC
                 LIMIT -1 OFFSET ?2
             )",
            params![friend_hash, MAX_MESSAGES_PER_FRIEND],
        )?;
        tx.commit()?;
        Ok(new_id)
    }

    /// Outbound messages still waiting on a session, oldest first, so a flush
    /// replays them in the order the user typed them.
    pub fn pending_chat_messages(
        &self,
        friend_hash: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<(i64, String, i64)>> {
        // Nothing can be sent while chat is locked, and these rows must not be
        // marked failed either: the key may yet be restored, and abandoning
        // them would throw away messages that are still perfectly recoverable.
        if self.chat_key.is_none() {
            return Ok(Vec::new());
        }
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, message, timestamp FROM chat_messages \
             WHERE friend_hash = ?1 AND delivery = ?2 AND direction = 'sent' \
             ORDER BY id ASC LIMIT ?3",
        )?;
        let rows: Vec<(i64, String, i64)> = stmt
            .query_map(params![friend_hash, CHAT_QUEUED, limit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        drop(conn);
        // Decrypt outside the statement borrow, mirroring `get_chat_messages`.
        let mut out = Vec::with_capacity(rows.len());
        let mut undecryptable = Vec::new();
        for (id, body, ts) in rows {
            match Self::decrypt_chat_body(
                self.require_chat_key()?,
                id,
                friend_hash,
                "sent",
                ts,
                &body,
            ) {
                Ok(plain) => out.push((id, plain, ts)),
                // Cannot be sent and never will be, so record that rather than
                // skipping it. Skipping left the row queued while
                // `pending_chat_counts` went on counting it, so the unsent
                // total never reached zero and nothing could clear it.
                Err(_) => undecryptable.push(id),
            }
        }
        if !undecryptable.is_empty() {
            tracing::warn!(
                "Marking {} undecryptable queued chat message(s) for {friend_hash} as failed",
                undecryptable.len()
            );
            let conn = self.conn.lock();
            for id in undecryptable {
                let _ = conn.execute(
                    "UPDATE chat_messages SET delivery = ?1 WHERE id = ?2",
                    params![CHAT_FAILED, id],
                );
            }
        }
        Ok(out)
    }

    /// Move a stored outbound message between delivery states.
    pub fn set_chat_delivery(&self, id: i64, delivery: i64) -> anyhow::Result<usize> {
        let conn = self.conn.lock();
        Ok(conn.execute(
            "UPDATE chat_messages SET delivery = ?1 WHERE id = ?2",
            params![delivery, id],
        )?)
    }

    /// [`Self::set_chat_delivery`] for many rows in one transaction. Returns,
    /// per id in order, whether a row matched.
    pub fn set_chat_delivery_many(&self, ids: &[i64], delivery: i64) -> anyhow::Result<Vec<bool>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let mut matched = Vec::with_capacity(ids.len());
        {
            let mut stmt = tx.prepare("UPDATE chat_messages SET delivery = ?1 WHERE id = ?2")?;
            for id in ids {
                matched.push(stmt.execute(params![delivery, id])? > 0);
            }
        }
        tx.commit()?;
        Ok(matched)
    }

    /// Count of outbound messages still queued, per friend. Drives the
    /// "unsent" affordance in the chat dock.
    pub fn pending_chat_counts(&self) -> anyhow::Result<Vec<(String, i64)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT friend_hash, COUNT(*) FROM chat_messages \
             WHERE delivery = ?1 AND direction = 'sent' GROUP BY friend_hash",
        )?;
        let rows = stmt
            .query_map(params![CHAT_QUEUED], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Abandon outbound messages that have been queued too long, across every
    /// conversation.
    ///
    /// Deliberately global and eager rather than filtered at each read. Nothing
    /// used to assign [`CHAT_FAILED`] at all, so a message to a friend who never
    /// returned stayed queued for the life of the database. Expiring it lazily
    /// on flush only moved the problem: the flush runs per friend and only when
    /// one reconnects, so the conversation, the unsent badge and the queue
    /// itself could each hold a different view of the same row. One writer that
    /// every reader observes keeps them agreeing.
    /// Returns the `(id, friend_hash)` of every row it abandoned, so the caller
    /// can tell the UI which live bubbles to flip. Without that, an open
    /// conversation keeps rendering an abandoned message as "queued" until it
    /// is reloaded, even though the row on disk already says failed.
    pub fn expire_stale_queued_chat(&self) -> anyhow::Result<Vec<(i64, String)>> {
        // Never while chat is locked. `pending_chat_messages` deliberately
        // refuses to flush *or* fail queued sends in that state, because a
        // restored key can still deliver them; abandoning them here would take
        // that back and mark as failed the very rows that recovery would have
        // rescued. The ceiling resumes applying once the key is back.
        if self.chat_key.is_none() {
            return Ok(Vec::new());
        }
        let cutoff = chrono::Utc::now().timestamp() - CHAT_QUEUE_MAX_AGE_SECS;
        let conn = self.conn.lock();
        // Read the victims and update them in one transaction, so the ids
        // reported are exactly the rows this sweep changed. The mutex alone was
        // not enough: it serialises callers of this type, but the SELECT and the
        // UPDATE were still two statements, and anything that reached the same
        // file between them — another connection, or a crash — could leave the
        // returned list describing rows that were never marked, which is a
        // conversation rendering "failed" over a row on disk that still says
        // queued.
        let tx = conn.unchecked_transaction()?;
        let expired: Vec<(i64, String)> = {
            let mut stmt = tx.prepare(
                "SELECT id, friend_hash FROM chat_messages \
                 WHERE delivery = ?1 AND direction = 'sent' AND timestamp < ?2",
            )?;
            let rows = stmt
                .query_map(params![CHAT_QUEUED, cutoff], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        if expired.is_empty() {
            return Ok(expired);
        }
        tx.execute(
            "UPDATE chat_messages SET delivery = ?1 \
             WHERE delivery = ?2 AND direction = 'sent' AND timestamp < ?3",
            params![CHAT_FAILED, CHAT_QUEUED, cutoff],
        )?;
        tx.commit()?;
        tracing::info!(
            "Gave up on {} chat message(s) queued longer than {} days",
            expired.len(),
            CHAT_QUEUE_MAX_AGE_SECS / 86_400
        );
        Ok(expired)
    }

    pub fn get_chat_messages(
        &self,
        friend_hash: &str,
        limit: i64,
        before_id: Option<i64>,
    ) -> anyhow::Result<Vec<FriendChatRow>> {
        let conn = self.conn.lock();
        let rows: Vec<(i64, String, String, i64, bool, i64, bool)> = if let Some(bid) = before_id {
            let mut stmt = conn.prepare(
                "SELECT id, direction, message, timestamp, read, delivery, seen \
                 FROM chat_messages WHERE friend_hash = ?1 AND id < ?2 ORDER BY id DESC LIMIT ?3"
            )?;
            let mapped = stmt.query_map(params![friend_hash, bid, limit], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get::<_, i64>(4)? != 0,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)? != 0,
                ))
            })?;
            mapped.collect::<Result<Vec<_>, _>>()?
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, direction, message, timestamp, read, delivery, seen \
                 FROM chat_messages WHERE friend_hash = ?1 ORDER BY id DESC LIMIT ?2"
            )?;
            let mapped = stmt.query_map(params![friend_hash, limit], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get::<_, i64>(4)? != 0,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)? != 0,
                ))
            })?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };
        let to_row = |id, direction, message, timestamp, read, delivery, seen| FriendChatRow {
            id,
            direction,
            message,
            timestamp,
            read,
            delivery,
            seen,
        };
        // Locked: every row is sealed, so report them all as unavailable in one
        // go rather than warning once per row for a condition that is a property
        // of the database, not of any individual message.
        let Some(chat_key) = self.chat_key.as_deref() else {
            return Ok(rows
                .into_iter()
                .map(|(id, direction, _stored, timestamp, read, delivery, seen)| {
                    to_row(
                        id,
                        direction,
                        CHAT_UNAVAILABLE_TEXT.to_string(),
                        timestamp,
                        read,
                        delivery,
                        seen,
                    )
                })
                .collect());
        };
        let mut messages = Vec::with_capacity(rows.len());
        for (id, direction, stored, timestamp, read, delivery, seen) in rows {
            match Self::decrypt_chat_body(chat_key, id, friend_hash, &direction, timestamp, &stored)
            {
                Ok(message) => {
                    messages.push(to_row(id, direction, message, timestamp, read, delivery, seen))
                }
                Err(error) => {
                    tracing::warn!(
                        "Chat row {id} for friend {friend_hash} is unavailable; preserving its ciphertext for later recovery: {error}"
                    );
                    messages.push(to_row(
                        id,
                        direction,
                        CHAT_UNAVAILABLE_TEXT.to_string(),
                        timestamp,
                        read,
                        delivery,
                        seen,
                    ));
                }
            }
        }
        Ok(messages)
    }

    pub fn mark_messages_read(&self, friend_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE chat_messages SET read = 1 WHERE friend_hash = ?1 AND read = 0",
            params![friend_hash],
        )?;
        Ok(())
    }

    /// Body hash of the newest received message this device has already read,
    /// for a read-receipt watermark. `None` if there is nothing to acknowledge.
    pub fn latest_read_received_hash(&self, friend_hash: &str) -> anyhow::Result<Option<String>> {
        let conn = self.conn.lock();
        let hash: Option<String> = conn
            .query_row(
                "SELECT body_hash FROM chat_messages \
                 WHERE friend_hash = ?1 AND direction = 'received' AND read = 1 AND body_hash != '' \
                 ORDER BY id DESC LIMIT 1",
                params![friend_hash],
                |row| row.get(0),
            )
            .optional()?;
        Ok(hash.filter(|h| !h.is_empty()))
    }

    /// Mark our sent messages up through the one named by `body_hash` as seen.
    /// Returns that row's id so the UI can apply the watermark without a reload.
    ///
    /// Only delivered rows can match or be covered. A receipt names a line by
    /// its body alone, and short replies repeat — "ok" sent twice, the second
    /// still queued, would otherwise resolve to the queued copy and flag it and
    /// everything before it as read by someone who has not received it yet.
    pub fn mark_sent_seen_by_hash(
        &self,
        friend_hash: &str,
        body_hash: &str,
    ) -> anyhow::Result<Option<i64>> {
        if body_hash.is_empty() {
            return Ok(None);
        }
        let conn = self.conn.lock();
        let id: Option<i64> = conn
            .query_row(
                "SELECT id FROM chat_messages \
                 WHERE friend_hash = ?1 AND direction = 'sent' AND body_hash = ?2 \
                   AND delivery = ?3 \
                 ORDER BY id DESC LIMIT 1",
                params![friend_hash, body_hash, CHAT_DELIVERED],
                |row| row.get(0),
            )
            .optional()?;
        let Some(id) = id else {
            return Ok(None);
        };
        conn.execute(
            "UPDATE chat_messages SET seen = 1 \
             WHERE friend_hash = ?1 AND direction = 'sent' AND id <= ?2 AND seen = 0 \
               AND delivery = ?3",
            params![friend_hash, id, CHAT_DELIVERED],
        )?;
        Ok(Some(id))
    }

    pub fn unread_message_counts(&self) -> anyhow::Result<Vec<(String, i64)>> {
        let conn = self.conn.lock();
        // `direction = 'received'` for the same reason the channel tally in
        // `list_channels` carries it: unread means "they said something I have
        // not read", and a sent row has no business in that count. The insert
        // path writes `read = 1` on outbound so this changes nothing today —
        // which is precisely why it was worth stating, because the one thing
        // that would surface the omission is a row written by some future path
        // that forgets, and it would surface as a badge the user cannot clear.
        let mut stmt = conn.prepare(
            "SELECT friend_hash, COUNT(*) FROM chat_messages \
             WHERE read = 0 AND direction = 'received' GROUP BY friend_hash",
        )?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn list_channels(&self) -> anyhow::Result<Vec<StoredChannel>> {
        let conn = self.conn.lock();
        let sql = format!(
            "SELECT c.channel_id, c.pubkey, c.name, c.visibility, c.is_owner, c.topic, c.welcome,
                    c.joined_at, c.last_active,
                    (SELECT COUNT(*) FROM channel_members m
                     WHERE m.channel_id = c.channel_id
                       AND m.banned = 0
                       AND m.last_seen >= unixepoch() - {PRESENCE_FRESH_SECS}),
                    (SELECT COUNT(*) FROM channel_messages msg
                     WHERE msg.channel_id = c.channel_id AND msg.read = 0 AND msg.direction = 'received'),
                    c.successor_id, c.predecessor_id, c.owner_pubkey, c.key_epoch,
                    c.successor_nominee, c.claim_after_days, c.key_epoch_wanted,
                    c.moderation_updated_at, c.moderation_checked_at,
                    c.in_room, c.deleted, c.invites_owner_only, c.slow_mode_secs,
                    c.announce_only, c.pinned_msg_ids, {CHANNEL_ROSTER_COUNT_SQL}, c.renamed_at, c.language
             FROM channels c
             ORDER BY c.last_active DESC, c.joined_at DESC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map([], Self::stored_channel_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Joined-room rows without the two COUNT(*) subqueries. The network loop
    /// ticks this once a second; unread and historical member totals are UI
    /// figures it does not read.
    pub fn list_channels_lite(&self) -> anyhow::Result<Vec<StoredChannel>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT c.channel_id, c.pubkey, c.name, c.visibility, c.is_owner, c.topic, c.welcome,
                    c.joined_at, c.last_active, 0, 0,
                    c.successor_id, c.predecessor_id, c.owner_pubkey, c.key_epoch,
                    c.successor_nominee, c.claim_after_days, c.key_epoch_wanted,
                    c.moderation_updated_at, c.moderation_checked_at,
                    c.in_room, c.deleted, c.invites_owner_only, c.slow_mode_secs,
                    c.announce_only, c.pinned_msg_ids, 0, c.renamed_at, c.language
             FROM channels c
             ORDER BY c.last_active DESC, c.joined_at DESC",
        )?;
        let rows = stmt
            .query_map([], Self::stored_channel_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Presence-fresh members, including us if we are not banned. `1`
    /// means nobody else has announced recently — the empty-room poll case.
    pub fn count_fresh_channel_members(
        &self,
        channel_id: &str,
        now: i64,
        fresh_secs: i64,
    ) -> anyhow::Result<i64> {
        let cutoff = now.saturating_sub(fresh_secs);
        let conn = self.conn.lock();
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM channel_members
             WHERE channel_id = ?1 AND banned = 0 AND last_seen >= ?2",
            params![channel_id, cutoff],
            |row| row.get(0),
        )?;
        Ok(n)
    }

    /// Remember what a Discover walk turned up.
    ///
    /// Upsert rather than replace-all, because a walk that lost a shard to a
    /// timeout still knows everything the previous one did about the other
    /// fifteen. Clearing the table each time would empty the cache precisely
    /// when the network is least able to refill it.
    pub fn cache_channel_listings(&self, rows: &[CachedChannel]) -> anyhow::Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let now = chrono::Utc::now().timestamp();
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO channel_index_cache (channel_id, pubkey, name, language, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(channel_id) DO UPDATE SET
                    pubkey = excluded.pubkey,
                    name = excluded.name,
                    language = excluded.language,
                    last_seen = excluded.last_seen",
            )?;
            for row in rows {
                stmt.execute(params![row.channel_id, row.pubkey, row.name, row.language, now])?;
            }
        }
        tx.execute(
            "DELETE FROM channel_index_cache WHERE last_seen < ?1",
            params![now - CHANNEL_CACHE_MAX_AGE_SECS],
        )?;
        tx.execute(
            "DELETE FROM channel_index_cache WHERE channel_id NOT IN (
                 SELECT channel_id FROM channel_index_cache
                 ORDER BY last_seen DESC LIMIT ?1
             )",
            params![MAX_CHANNEL_CACHE_ROWS],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Rooms an earlier Discover walk found, most recently seen first.
    pub fn list_cached_channels(&self) -> anyhow::Result<Vec<CachedChannel>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT channel_id, pubkey, name, language FROM channel_index_cache
             ORDER BY last_seen DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(CachedChannel {
                    channel_id: row.get(0)?,
                    pubkey: row.get(1)?,
                    name: row.get(2)?,
                    language: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_channel(&self, channel_id: &str) -> anyhow::Result<Option<StoredChannel>> {
        let conn = self.conn.lock();
        Self::get_channel_locked(&conn, channel_id)
    }

    /// One channel row without the two `COUNT(*)` subqueries, for the same
    /// reason [`Self::list_channels_lite`] exists: the packet paths need the
    /// room's identity, keys and in-room flag, and never read `member_count`
    /// or `unread`. Both are reported as `0`.
    pub fn get_channel_lite(&self, channel_id: &str) -> anyhow::Result<Option<StoredChannel>> {
        let conn = self.conn.lock();
        let row = conn
            .query_row(
                "SELECT c.channel_id, c.pubkey, c.name, c.visibility, c.is_owner, c.topic, c.welcome,
                        c.joined_at, c.last_active, 0, 0,
                        c.successor_id, c.predecessor_id, c.owner_pubkey, c.key_epoch,
                        c.successor_nominee, c.claim_after_days, c.key_epoch_wanted,
                        c.moderation_updated_at, c.moderation_checked_at,
                        c.in_room, c.deleted, c.invites_owner_only, c.slow_mode_secs,
                    c.announce_only, c.pinned_msg_ids, 0, c.renamed_at, c.language
                 FROM channels c WHERE c.channel_id = ?1",
                params![channel_id],
                Self::stored_channel_from_row,
            )
            .optional()?;
        Ok(row)
    }

    fn get_channel_locked(
        conn: &Connection,
        channel_id: &str,
    ) -> anyhow::Result<Option<StoredChannel>> {
        let row = conn
            .query_row(
                &format!(
                    "SELECT c.channel_id, c.pubkey, c.name, c.visibility, c.is_owner, c.topic, c.welcome,
                        c.joined_at, c.last_active,
                        (SELECT COUNT(*) FROM channel_members m
                         WHERE m.channel_id = c.channel_id
                           AND m.banned = 0
                           AND m.last_seen >= unixepoch() - {PRESENCE_FRESH_SECS}),
                        (SELECT COUNT(*) FROM channel_messages msg
                         WHERE msg.channel_id = c.channel_id AND msg.read = 0 AND msg.direction = 'received'),
                        c.successor_id, c.predecessor_id, c.owner_pubkey, c.key_epoch,
                        c.successor_nominee, c.claim_after_days, c.key_epoch_wanted,
                        c.moderation_updated_at, c.moderation_checked_at,
                        c.in_room, c.deleted, c.invites_owner_only, c.slow_mode_secs,
                    c.announce_only, c.pinned_msg_ids, {CHANNEL_ROSTER_COUNT_SQL}, c.renamed_at, c.language
                 FROM channels c WHERE c.channel_id = ?1"
                ),
                params![channel_id],
                Self::stored_channel_from_row,
            )
            .optional()?;
        Ok(row)
    }

    fn stored_channel_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredChannel> {
        Ok(StoredChannel {
            channel_id: row.get(0)?,
            pubkey: row.get(1)?,
            name: row.get(2)?,
            visibility: row.get(3)?,
            is_owner: row.get::<_, i64>(4)? != 0,
            topic: row.get(5)?,
            welcome: row.get(6)?,
            joined_at: row.get(7)?,
            last_active: row.get(8)?,
            member_count: row.get(9)?,
            unread: row.get(10)?,
            successor_id: row.get::<_, String>(11).unwrap_or_default(),
            predecessor_id: row.get::<_, String>(12).unwrap_or_default(),
            owner_pubkey: row.get::<_, String>(13).unwrap_or_default(),
            key_epoch: row.get::<_, i64>(14).unwrap_or(0),
            successor_nominee: row.get::<_, String>(15).unwrap_or_default(),
            claim_after_days: row.get::<_, i64>(16).unwrap_or(0),
            key_epoch_wanted: row.get::<_, i64>(17).unwrap_or(0),
            moderation_updated_at: row.get::<_, i64>(18).unwrap_or(0),
            moderation_checked_at: row.get::<_, i64>(19).unwrap_or(0),
            in_room: row.get::<_, i64>(20).unwrap_or(1) != 0,
            deleted: row.get::<_, i64>(21).unwrap_or(0) != 0,
            invites_owner_only: row.get::<_, i64>(22).unwrap_or(0) != 0,
            slow_mode_secs: row.get::<_, i64>(23).unwrap_or(0),
            announce_only: row.get::<_, i64>(24).unwrap_or(0) != 0,
            pinned_msg_ids: row
                .get::<_, String>(25)
                .map(|s| parse_pinned_msg_ids(&s))
                .unwrap_or_default(),
            roster_count: row.get(26)?,
            renamed_at: row.get::<_, i64>(27).unwrap_or(0),
            language: row.get::<_, String>(28).unwrap_or_default(),
        })
    }

    pub fn insert_channel(
        &self,
        channel_id: &str,
        pubkey: &str,
        name: &str,
        visibility: &str,
        is_owner: bool,
        owner_seed: Option<&[u8; 32]>,
        join_secret: Option<&[u8; 32]>,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        self.insert_channel_locked(
            &conn,
            channel_id,
            pubkey,
            name,
            visibility,
            is_owner,
            owner_seed,
            join_secret,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_channel_locked(
        &self,
        conn: &Connection,
        channel_id: &str,
        pubkey: &str,
        name: &str,
        visibility: &str,
        is_owner: bool,
        owner_seed: Option<&[u8; 32]>,
        join_secret: Option<&[u8; 32]>,
    ) -> anyhow::Result<()> {
        let owner_enc = match owner_seed {
            Some(seed) => Some(Self::encrypt_channel_secret(
                self.require_chat_key()?,
                channel_id,
                "owner",
                seed,
            )?),
            None => None,
        };
        let join_enc = match join_secret {
            Some(secret) => Some(Self::encrypt_channel_secret(
                self.require_chat_key()?,
                channel_id,
                "join",
                secret,
            )?),
            None => None,
        };
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO channels (channel_id, pubkey, name, visibility, is_owner, owner_seed,
                 join_secret, topic, welcome, joined_at, last_active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '', '', ?8, ?8)",
            params![
                channel_id,
                pubkey,
                name,
                visibility,
                if is_owner { 1 } else { 0 },
                owner_enc,
                join_enc,
                now
            ],
        )?;
        Ok(())
    }

    /// Walk in or out without dropping secrets or history.
    pub fn set_channel_in_room(&self, channel_id: &str, in_room: bool) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        // Walking back in cancels any leave tombstone still waiting to publish.
        // Sending one afterwards would tell the room to drop the roster row we
        // had just re-earned.
        let n = conn.execute(
            "UPDATE channels SET in_room = ?2,
                departure_due_at = CASE WHEN ?2 = 1 THEN 0 ELSE departure_due_at END
             WHERE channel_id = ?1 AND deleted = 0",
            params![channel_id, if in_room { 1 } else { 0 }],
        )?;
        Ok(n > 0)
    }

    /// Owner-only permanent delete on this device: leave the door and keep the
    /// row so the same name is not minted again locally.
    /// Owner delete: tombstone the row, and purge everything it held.
    ///
    /// The `channels` row itself stays, because `deleted` is what
    /// `refuse_deleted_channel` reads to keep this device from walking back
    /// into a room it destroyed. Everything else used to stay with it — every
    /// message, the whole roster, and the retained content keys — with no path
    /// that could ever remove them, since [`Self::delete_channel`] is only
    /// reachable through `forget_channel` and that refuses to run on a row we
    /// own. "Permanently delete this room" left the entire history on disk.
    pub fn tombstone_channel(&self, channel_id: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let n = tx.execute(
            "UPDATE channels SET in_room = 0, deleted = 1 WHERE channel_id = ?1",
            params![channel_id],
        )?;
        if n > 0 {
            tx.execute(
                "DELETE FROM channel_messages WHERE channel_id = ?1",
                params![channel_id],
            )?;
            tx.execute(
                "DELETE FROM channel_message_reactions WHERE channel_id = ?1",
                params![channel_id],
            )?;
            tx.execute(
                "DELETE FROM channel_members WHERE channel_id = ?1",
                params![channel_id],
            )?;
            tx.execute(
                "DELETE FROM channel_key_epochs WHERE channel_id = ?1",
                params![channel_id],
            )?;
            // The forget-list goes too. It exists to stop a deleted line being
            // re-inserted by the next gossip replay, and with the room itself
            // destroyed there is no ingest path left to refuse — so every row
            // here is unreachable, up to `CHANNEL_TOMBSTONES_PER_CHANNEL` of them,
            // and nothing else would ever remove them.
            tx.execute(
                "DELETE FROM channel_message_tombstones WHERE channel_id = ?1",
                params![channel_id],
            )?;
            tx.execute(
                "DELETE FROM channel_handoff_pending WHERE old_channel_id = ?1",
                params![channel_id],
            )?;
        }
        tx.commit()?;
        if n > 0 {
            bump_channel_roster_generation(channel_id);
        }
        Ok(n > 0)
    }

    /// Walk this device out of rooms the directory lists as deleted.
    ///
    /// Deliberately *not* a tombstone. The directory is an unsigned hint —
    /// nothing in the response proves the room's owner asked for this — and
    /// `deleted` is one-way: it hides the room, refuses re-entry, and there is
    /// no way back from the UI. A directory bug or a compromised server could
    /// therefore erase every room a user belongs to, private ones included,
    /// whose ids the server has no authority over in the first place.
    ///
    /// Walking out is the recoverable half of the same action: the row, its
    /// history and its join secret stay, the room reappears as a Join, and
    /// re-entry is local so it works even while the directory still lies.
    /// Owners are skipped — an owner's own delete goes through
    /// [`Self::tombstone_channel`], so a row saying we own it and a directory
    /// saying it is gone means the directory is the one that is wrong.
    pub fn walk_out_deleted_channels(&self, deleted_ids: &[String]) -> anyhow::Result<Vec<String>> {
        if deleted_ids.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn.lock();
        let mut walked = Vec::new();
        for id in deleted_ids {
            let n = conn.execute(
                "UPDATE channels SET in_room = 0 \
                 WHERE channel_id = ?1 AND deleted = 0 AND is_owner = 0 AND in_room = 1",
                params![id],
            )?;
            if n > 0 {
                walked.push(id.clone());
            }
        }
        Ok(walked)
    }

    /// Forget a channel. A ban recorded against `keep_banned_member` survives,
    /// because a ban belongs to the room rather than to the membership: wiping
    /// it made leaving and rejoining a client-side ban reset, and the local
    /// flag is what stops the composer accepting sends that every remaining
    /// member will discard. Pass `None` when there is nothing to preserve
    /// (rolling back a room that was never published).
    pub fn delete_channel(
        &self,
        channel_id: &str,
        keep_banned_member: Option<&str>,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM channel_messages WHERE channel_id = ?1",
            params![channel_id],
        )?;
        tx.execute(
            "DELETE FROM channel_message_reactions WHERE channel_id = ?1",
            params![channel_id],
        )?;
        // Any half-finished handoff goes with the room. Left behind it is an
        // unreachable row keyed to a channel that no longer exists.
        tx.execute(
            "DELETE FROM channel_handoff_pending WHERE old_channel_id = ?1",
            params![channel_id],
        )?;
        tx.execute(
            "DELETE FROM channel_key_epochs WHERE channel_id = ?1",
            params![channel_id],
        )?;
        // Same reasoning as `tombstone_channel`: no messages means no ingest to
        // refuse, so the forget-list has no reader left.
        tx.execute(
            "DELETE FROM channel_message_tombstones WHERE channel_id = ?1",
            params![channel_id],
        )?;
        match keep_banned_member {
            Some(pk) => tx.execute(
                "DELETE FROM channel_members
                 WHERE channel_id = ?1
                   AND NOT (banned = 1 AND lower(member_pubkey) = lower(?2))",
                params![channel_id, pk],
            )?,
            None => tx.execute(
                "DELETE FROM channel_members WHERE channel_id = ?1",
                params![channel_id],
            )?,
        };
        let n = tx.execute(
            "DELETE FROM channels WHERE channel_id = ?1",
            params![channel_id],
        )?;
        tx.commit()?;
        bump_channel_roster_generation(channel_id);
        Ok(n > 0)
    }

    pub fn load_channel_owner_seed(&self, channel_id: &str) -> anyhow::Result<Option<[u8; 32]>> {
        let conn = self.conn.lock();
        self.load_channel_secret_locked(&conn, channel_id, "owner_seed", "owner")
    }

    pub fn load_channel_join_secret(&self, channel_id: &str) -> anyhow::Result<Option<[u8; 32]>> {
        let conn = self.conn.lock();
        self.load_channel_secret_locked(&conn, channel_id, "join_secret", "join")
    }

    /// The secret a room is *currently* sealing with: its newest epoch, or the
    /// original `join_secret` if it has never rotated.
    ///
    /// A handoff that carries a secret forward has to carry this one. Rotation
    /// writes new keys to `channel_key_epochs` and never touches `join_secret`,
    /// so inheriting that column would hand the successor room the key the last
    /// ban rotated away from — letting an evicted member who kept their original
    /// invite read the new room, and quietly undoing the eviction.
    fn load_current_channel_secret_locked(
        &self,
        conn: &Connection,
        channel_id: &str,
    ) -> anyhow::Result<Option<[u8; 32]>> {
        let newest: Option<(i64, String)> = conn
            .query_row(
                "SELECT epoch, secret_enc FROM channel_key_epochs
                 WHERE channel_id = ?1 ORDER BY epoch DESC LIMIT 1",
                params![channel_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((epoch, enc)) = newest {
            return Ok(Some(Self::decrypt_channel_secret(
                self.require_chat_key()?,
                channel_id,
                &format!("epoch{epoch}"),
                &enc,
            )?));
        }
        self.load_channel_secret_locked(conn, channel_id, "join_secret", "join")
    }

    /// Shared body for the two secret loaders, callable while the connection
    /// lock is already held — the handoff needs to read and write in one
    /// transaction, and taking the lock again inside it would deadlock.
    fn load_channel_secret_locked(
        &self,
        conn: &Connection,
        channel_id: &str,
        column: &str,
        label: &str,
    ) -> anyhow::Result<Option<[u8; 32]>> {
        let stored: Option<String> = conn
            .query_row(
                &format!("SELECT {column} FROM channels WHERE channel_id = ?1"),
                params![channel_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        match stored {
            Some(enc) => Ok(Some(Self::decrypt_channel_secret(
                self.require_chat_key()?,
                channel_id,
                label,
                &enc,
            )?)),
            None => Ok(None),
        }
    }

    /// How many content-key epochs a room keeps.
    ///
    /// A member who was offline across a rotation still has to read what
    /// arrived in the gap, and history sync replays messages sealed under
    /// whichever epoch was current when they were sent. Four is the margin;
    /// past that a member needs a fresh invite, which is the same position an
    /// evicted member is in and the point of rotating at all.
    pub const CHANNEL_KEY_EPOCHS_KEPT: usize = 4;

    /// Record a rotated content key and make it current, dropping epochs past
    /// the retention window.
    pub fn insert_channel_key_epoch(
        &self,
        channel_id: &str,
        epoch: i64,
        secret: &[u8; 32],
    ) -> anyhow::Result<()> {
        let enc = Self::encrypt_channel_secret(
            self.require_chat_key()?,
            channel_id,
            &format!("epoch{epoch}"),
            secret,
        )?;
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO channel_key_epochs (channel_id, epoch, secret_enc, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(channel_id, epoch) DO UPDATE SET secret_enc = excluded.secret_enc",
            params![channel_id, epoch, enc, chrono::Utc::now().timestamp()],
        )?;
        // Never walk the epoch backwards: an out-of-order record must not
        // demote the room to an older key for everything it sends next.
        tx.execute(
            "UPDATE channels SET key_epoch = ?2 WHERE channel_id = ?1 AND key_epoch < ?2",
            params![channel_id, epoch],
        )?;
        tx.execute(
            "DELETE FROM channel_key_epochs WHERE channel_id = ?1 AND epoch NOT IN (
                 SELECT epoch FROM channel_key_epochs WHERE channel_id = ?1
                 ORDER BY epoch DESC LIMIT ?2
             )",
            params![channel_id, Self::CHANNEL_KEY_EPOCHS_KEPT as i64],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The newest content-key epoch in `floor..=wanted` this device does not
    /// hold, if any.
    ///
    /// Chasing only the epoch the owner currently advertises left a hole. A
    /// member offline across two rotations learns about the newest one and
    /// never the one in between, so the window of history sealed under the
    /// intermediate epoch stayed unreadable for good — even while its record
    /// was still in the DHT and `channel_content_keys` would happily have used
    /// it. Newest first, because holding the current epoch is what lets the
    /// member send again; the older ones only restore readability.
    ///
    /// Bounded to the retention window, since [`Self::insert_channel_key_epoch`]
    /// drops anything past it on arrival anyway.
    pub fn newest_missing_channel_key_epoch(
        &self,
        channel_id: &str,
        floor: i64,
        wanted: i64,
    ) -> anyhow::Result<Option<i64>> {
        if wanted < floor {
            return Ok(None);
        }
        let conn = self.conn.lock();
        let held: Vec<i64> = {
            let mut stmt = conn.prepare(
                "SELECT epoch FROM channel_key_epochs
                 WHERE channel_id = ?1 AND epoch >= ?2 AND epoch <= ?3",
            )?;
            let rows = stmt.query_map(params![channel_id, floor, wanted], |row| row.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        Ok((floor..=wanted).rev().find(|epoch| !held.contains(epoch)))
    }

    /// Undo a rotation whose moderation snapshot never got committed.
    ///
    /// The epoch and the snapshot announcing it have to land together: the owner
    /// seals new traffic with whatever `key_epoch` says, and members only go
    /// looking for a key the snapshot names. Keeping a rotation whose snapshot
    /// failed would leave the owner talking under a key nobody knows to fetch.
    pub fn rollback_channel_key_epoch(&self, channel_id: &str, epoch: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM channel_key_epochs WHERE channel_id = ?1 AND epoch = ?2",
            params![channel_id, epoch],
        )?;
        tx.execute(
            "UPDATE channels SET key_epoch = (
                 SELECT COALESCE(MAX(epoch), 0) FROM channel_key_epochs WHERE channel_id = ?1
             ) WHERE channel_id = ?1",
            params![channel_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Retained content-key secrets for a room, newest epoch first.
    ///
    /// Callers try these in order, so the current epoch is attempted before
    /// any older one. Empty when the room has never rotated — the caller then
    /// falls back to `load_channel_join_secret`, which is epoch 0.
    pub fn load_channel_key_epochs(
        &self,
        channel_id: &str,
    ) -> anyhow::Result<Vec<(i64, [u8; 32])>> {
        let stored: Vec<(i64, String)> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare(
                "SELECT epoch, secret_enc FROM channel_key_epochs
                 WHERE channel_id = ?1 ORDER BY epoch DESC",
            )?;
            let mapped = stmt.query_map(params![channel_id], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };
        if stored.is_empty() {
            return Ok(Vec::new());
        }
        let chat_key = self.require_chat_key()?;
        let mut out = Vec::with_capacity(stored.len());
        for (epoch, enc) in stored {
            match Self::decrypt_channel_secret(
                chat_key,
                channel_id,
                &format!("epoch{epoch}"),
                &enc,
            ) {
                Ok(secret) => out.push((epoch, secret)),
                // One unreadable epoch must not hide the others: the current
                // key may well be fine and the room still usable.
                Err(error) => {
                    tracing::warn!(
                        "Channel {channel_id} epoch {epoch} secret is unreadable: {error}"
                    );
                }
            }
        }
        Ok(out)
    }

    /// Note that a search for this room's owner-signed record came back.
    ///
    /// Recorded when results are drained rather than when the search starts:
    /// asking and getting no answer means we could not reach anyone, which is
    /// not evidence that the owner has stopped publishing.
    pub fn touch_channel_moderation_checked(
        &self,
        channel_id: &str,
        checked_at: i64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE channels SET moderation_checked_at = ?2
             WHERE channel_id = ?1 AND moderation_checked_at < ?2",
            params![channel_id, checked_at],
        )?;
        Ok(())
    }

    // No `set_channel_succession`. The nominee and the claim window are part of
    // the owner-signed moderation snapshot, so `apply_channel_moderation` is the
    // only thing that writes them — which is what makes setting one atomic with
    // publishing it. A second writer is how the two came apart: the column was
    // written first and the publish could then refuse, leaving this device
    // honouring a successor the room had never been told about.

    /// Set or withdraw the room's pending ownership offer.
    ///
    /// Refused while a handoff is committed (see
    /// [`Self::commit_channel_handoff`]): a new offer would lead to a second
    /// record beside one that may already be stored. Withdrawing drops an
    /// unconfirmed commitment with it, and is refused for a confirmed one —
    /// that record is out, and the members are following it.
    pub fn set_channel_pending_handoff(
        &self,
        channel_id: &str,
        successor_member: &str,
        version: u64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        if let Some(held) = Self::load_channel_handoff_commit_locked(&tx, channel_id)? {
            if !successor_member.is_empty() || held.confirmed {
                anyhow::bail!("an ownership transfer of this room is already being published");
            }
            Self::delete_channel_handoff_commit_locked(&tx, channel_id)?;
        }
        tx.execute(
            "UPDATE channels SET pending_successor = ?2, pending_handoff_version = ?3
             WHERE channel_id = ?1",
            params![channel_id, successor_member, version as i64],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn channel_pending_handoff(
        &self,
        channel_id: &str,
    ) -> anyhow::Result<Option<(String, u64)>> {
        let conn = self.conn.lock();
        let row: Option<(String, i64)> = conn
            .query_row(
                "SELECT pending_successor, pending_handoff_version FROM channels WHERE channel_id = ?1",
                params![channel_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.and_then(|(pk, ver)| {
            if pk.is_empty() || ver <= 0 {
                None
            } else {
                Some((pk, ver as u64))
            }
        }))
    }

    /// Hold the successor seed a nominee minted for an ownership offer.
    ///
    /// Returns whether it was stored. Only a strictly newer version replaces a
    /// held row: the seed is the successor room's identity, and the owner may
    /// already have published a handoff naming its pubkey, so a replayed or
    /// reordered older offer — or a repeat of the same one — overwriting it
    /// would leave this device unable to sign for the room it was handed.
    pub fn store_handoff_pending_seed(
        &self,
        old_channel_id: &str,
        version: u64,
        successor_pubkey: &str,
        owner_seed: &[u8; 32],
    ) -> anyhow::Result<bool> {
        let enc = Self::encrypt_channel_secret(
            self.require_chat_key()?,
            old_channel_id,
            "handoff",
            owner_seed,
        )?;
        let now = chrono::Utc::now().timestamp();
        let conn = self.conn.lock();
        let n = conn.execute(
            "INSERT INTO channel_handoff_pending (old_channel_id, version, successor_pubkey, owner_seed, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(old_channel_id) DO UPDATE SET
                version = excluded.version,
                successor_pubkey = excluded.successor_pubkey,
                owner_seed = excluded.owner_seed,
                created_at = excluded.created_at
             WHERE excluded.version > channel_handoff_pending.version",
            params![old_channel_id, version as i64, successor_pubkey, enc, now],
        )?;
        Ok(n > 0)
    }

    pub fn load_handoff_pending_row(
        &self,
        old_channel_id: &str,
    ) -> anyhow::Result<Option<(String, u64, [u8; 32])>> {
        let stored: Option<(String, i64, String)> = {
            let conn = self.conn.lock();
            conn.query_row(
                "SELECT successor_pubkey, version, owner_seed FROM channel_handoff_pending
                 WHERE old_channel_id = ?1",
                params![old_channel_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
        };
        let Some((pk, ver, enc)) = stored else {
            return Ok(None);
        };
        let seed = Self::decrypt_channel_secret(
            self.require_chat_key()?,
            old_channel_id,
            "handoff",
            &enc,
        )?;
        Ok(Some((pk, ver as u64, seed)))
    }

    pub fn load_handoff_pending_seed(
        &self,
        old_channel_id: &str,
        successor_pubkey: &str,
        version: u64,
    ) -> anyhow::Result<Option<[u8; 32]>> {
        let Some((pk, ver, seed)) = self.load_handoff_pending_row(old_channel_id)? else {
            return Ok(None);
        };
        if pk != successor_pubkey || ver != version {
            return Ok(None);
        }
        Ok(Some(seed))
    }

    pub fn clear_handoff_pending(&self, old_channel_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM channel_handoff_pending WHERE old_channel_id = ?1",
            params![old_channel_id],
        )?;
        Ok(())
    }

    /// Follow an owner-signed handoff: create the successor room, copy local
    /// history, and mark the old id as superseded. Never copies `owner_seed`
    /// from the old row.
    pub fn apply_channel_handoff(
        &self,
        old_channel_id: &str,
        successor_pubkey: &str,
        successor_channel_id: &str,
        _version: u64,
        keep_join_secret: bool,
        successor_owner_seed: Option<&[u8; 32]>,
    ) -> anyhow::Result<bool> {
        // The identity-critical part runs as one transaction. Each step used to
        // take the connection lock on its own, so a crash between them could
        // leave a successor room with no seed, or an old room pointed at a
        // successor that was never created — states nothing later repairs.
        //
        // What happens next is decided inside the transaction but acted on after
        // the lock is released — `clear_handoff_pending` and the replay both
        // take the lock themselves, and this mutex is not reentrant.
        {
            let conn = self.conn.lock();
            let tx = conn.unchecked_transaction()?;
            if self.channel_handoff_transition_locked(
                &tx,
                old_channel_id,
                successor_pubkey,
                successor_channel_id,
                keep_join_secret,
                successor_owner_seed,
            )? == ChannelHandoffTransition::Refused
            {
                return Ok(false);
            }
            tx.commit()?;
            bump_channel_roster_generation(old_channel_id);
            bump_channel_roster_generation(successor_channel_id);
        }
        self.finish_channel_handoff(old_channel_id, successor_channel_id)?;
        Ok(true)
    }

    /// The transactional half of a handoff, on a connection the caller holds
    /// inside a transaction it commits.
    fn channel_handoff_transition_locked(
        &self,
        tx: &Connection,
        old_channel_id: &str,
        successor_pubkey: &str,
        successor_channel_id: &str,
        keep_join_secret: bool,
        successor_owner_seed: Option<&[u8; 32]>,
    ) -> anyhow::Result<ChannelHandoffTransition> {
        let old = match Self::get_channel_locked(tx, old_channel_id)? {
            Some(ch) => ch,
            None => return Ok(ChannelHandoffTransition::Refused),
        };
        if !old.successor_id.is_empty() {
            if old.successor_id != successor_channel_id {
                return Ok(ChannelHandoffTransition::Refused);
            }
            // Already applied. Still worth a pass: the nominee may be
            // installing the seed for a successor row a previous run
            // created without it.
            if let Some(seed) = successor_owner_seed {
                if self
                    .load_channel_secret_locked(tx, successor_channel_id, "owner_seed", "owner")?
                    .is_none()
                {
                    let enc = Self::encrypt_channel_secret(
                        self.require_chat_key()?,
                        successor_channel_id,
                        "owner",
                        seed,
                    )?;
                    tx.execute(
                        "UPDATE channels SET is_owner = 1, owner_seed = ?2
                         WHERE channel_id = ?1",
                        params![successor_channel_id, enc],
                    )?;
                }
            }
            return Ok(ChannelHandoffTransition::AlreadyApplied);
        }
        let successor_exists = Self::get_channel_locked(tx, successor_channel_id)?.is_some();
        if successor_exists {
            // The owner may have created the successor row first,
            // without the new seed. The named successor installs it
            // here — never by copying the old `owner_seed`.
            if let Some(seed) = successor_owner_seed {
                let enc = Self::encrypt_channel_secret(
                    self.require_chat_key()?,
                    successor_channel_id,
                    "owner",
                    seed,
                )?;
                tx.execute(
                    "UPDATE channels SET is_owner = 1, owner_seed = ?2
                     WHERE channel_id = ?1",
                    params![successor_channel_id, enc],
                )?;
            }
        } else {
            let join_secret = if keep_join_secret {
                self.load_current_channel_secret_locked(tx, old_channel_id)?
            } else {
                hex::decode(successor_pubkey)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .map(|p| crate::network::ember::channel::public_join_secret(&p))
            };
            self.insert_channel_locked(
                tx,
                successor_channel_id,
                successor_pubkey,
                &old.name,
                &old.visibility,
                successor_owner_seed.is_some(),
                successor_owner_seed,
                join_secret.as_ref(),
            )?;
            // Announce-only travels: it is how the room is run, and a successor
            // that quietly reopened the floor to everyone is not the room its
            // members followed. Pins deliberately do not. They name messages
            // by wire id, and `finish_channel_handoff` copies history under
            // fresh local ids that nothing else holds, so a carried pin would
            // name a line the successor room does not have.
            tx.execute(
                "UPDATE channels SET predecessor_id = ?2, topic = ?3, welcome = ?4,
                     announce_only = ?5, language = ?6
                 WHERE channel_id = ?1",
                params![
                    successor_channel_id,
                    old_channel_id,
                    old.topic,
                    old.welcome,
                    i64::from(old.announce_only),
                    old.language
                ],
            )?;
            // `ban_revised_at` travels with the row. It is the watermark
            // that orders competing ban gossip, so dropping it reset
            // every member to "never revised" and let a stale ban or
            // unban frame re-decide a question the room had settled.
            tx.execute(
                "INSERT OR IGNORE INTO channel_members
                    (channel_id, member_pubkey, nickname, last_seen, banned, moderator,
                     ban_revised_at)
                 SELECT ?2, member_pubkey, nickname, last_seen, banned, moderator,
                     ban_revised_at
                 FROM channel_members WHERE channel_id = ?1",
                params![old_channel_id, successor_channel_id],
            )?;
        }
        tx.execute(
            "UPDATE channels SET successor_id = ?2, is_owner = 0, owner_seed = NULL,
                 pending_successor = '', pending_handoff_version = 0
             WHERE channel_id = ?1",
            params![old_channel_id, successor_channel_id],
        )?;
        Self::delete_channel_handoff_commit_locked(tx, old_channel_id)?;
        Ok(ChannelHandoffTransition::Applied)
    }

    /// Copy history into the successor and drop the nominee-side seed row.
    ///
    /// Outside the handoff transaction: 5,000 inserts is too long to hold the
    /// write lock for, and it is safe to resume because `predecessor_id` is
    /// already recorded and the message IDs are deterministic.
    fn finish_channel_handoff(
        &self,
        old_channel_id: &str,
        successor_channel_id: &str,
    ) -> anyhow::Result<()> {
        let history = self.get_channel_messages(old_channel_id, 5_000, None)?;
        for row in history.into_iter().rev() {
            let msg_id = format!("handoff-{old_channel_id}-{}", row.id);
            // No signature travels with a handoff copy. The author signed the
            // line against the *old* room's id, so the original does not verify
            // under the successor's, and re-signing here is the forgery the
            // signature exists to prevent. The copy stays readable locally and
            // is not re-served to anyone else.
            let copied = self.insert_channel_message(
                successor_channel_id,
                &row.sender_pubkey,
                &row.direction,
                &row.message,
                &msg_id,
                row.timestamp,
                "",
                row.read,
            );
            // `row.message` is the body without its signed trailer, which could
            // not verify here anyway, so the quote is carried by pointing the
            // copy at its parent's copy. Oldest first, so that copy is already
            // written; local-only like the rest of a handoff copy.
            if let (Ok(copy_id), Some(parent)) = (copied, row.reply_parent.as_ref()) {
                let _ = self.conn.lock().execute(
                    "UPDATE channel_messages SET reply_to = ?1 WHERE id = ?2",
                    params![format!("handoff-{old_channel_id}-{}", parent.id), copy_id],
                );
            }
        }
        let _ = self.clear_handoff_pending(old_channel_id);
        Ok(())
    }

    /// Created on first use by the handoff-commit helpers rather than by a
    /// numbered migration: it holds nothing any other table refers to, and a
    /// build that predates it has nothing to read from it.
    fn ensure_channel_handoff_commits_locked(conn: &Connection) -> anyhow::Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS channel_handoff_commits (
                channel_id TEXT PRIMARY KEY,
                nominee TEXT NOT NULL,
                version INTEGER NOT NULL,
                successor_pubkey TEXT NOT NULL,
                committed_at INTEGER NOT NULL,
                confirmed INTEGER NOT NULL DEFAULT 0
            );",
        )?;
        Ok(())
    }

    fn channel_handoff_commit_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChannelHandoffCommit> {
        Ok(ChannelHandoffCommit {
            nominee: row.get(0)?,
            version: row.get::<_, i64>(1)?.max(0) as u64,
            successor_pubkey: row.get(2)?,
            committed_at: row.get(3)?,
            confirmed: row.get::<_, i64>(4)? != 0,
        })
    }

    fn load_channel_handoff_commit_locked(
        conn: &Connection,
        channel_id: &str,
    ) -> anyhow::Result<Option<ChannelHandoffCommit>> {
        Self::ensure_channel_handoff_commits_locked(conn)?;
        Ok(conn
            .query_row(
                "SELECT nominee, version, successor_pubkey, committed_at, confirmed
                 FROM channel_handoff_commits WHERE channel_id = ?1",
                params![channel_id],
                Self::channel_handoff_commit_from_row,
            )
            .optional()?)
    }

    fn store_channel_handoff_commit_locked(
        conn: &Connection,
        channel_id: &str,
        commit: &ChannelHandoffCommit,
    ) -> anyhow::Result<()> {
        Self::ensure_channel_handoff_commits_locked(conn)?;
        conn.execute(
            "INSERT INTO channel_handoff_commits
                (channel_id, nominee, version, successor_pubkey, committed_at, confirmed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(channel_id) DO UPDATE SET
                nominee = excluded.nominee,
                version = excluded.version,
                successor_pubkey = excluded.successor_pubkey,
                committed_at = excluded.committed_at,
                confirmed = excluded.confirmed",
            params![
                channel_id,
                commit.nominee,
                commit.version as i64,
                commit.successor_pubkey,
                commit.committed_at,
                i64::from(commit.confirmed)
            ],
        )?;
        Ok(())
    }

    fn delete_channel_handoff_commit_locked(conn: &Connection, channel_id: &str) -> anyhow::Result<()> {
        Self::ensure_channel_handoff_commits_locked(conn)?;
        conn.execute(
            "DELETE FROM channel_handoff_commits WHERE channel_id = ?1",
            params![channel_id],
        )?;
        Ok(())
    }

    /// The pending ownership offer of a room we own, if any.
    fn channel_pending_handoff_locked(
        conn: &Connection,
        channel_id: &str,
    ) -> anyhow::Result<Option<(String, u64)>> {
        let row: Option<(String, i64)> = conn
            .query_row(
                "SELECT pending_successor, pending_handoff_version FROM channels WHERE channel_id = ?1",
                params![channel_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.and_then(|(pk, ver)| (!pk.is_empty() && ver > 0).then_some((pk, ver as u64))))
    }

    /// Commit a room we own to the successor its nominee answered with.
    ///
    /// Taken the moment the owner starts publishing the handoff record, and
    /// held until the handoff is applied. A record may be stored even when no
    /// storer's acknowledgement comes back, so from here on the room is spoken
    /// for: a second, different handoff published beside it would split the
    /// membership between two successors. On disk, so the commitment survives
    /// a restart.
    pub fn commit_channel_handoff(
        &self,
        channel_id: &str,
        nominee: &str,
        version: u64,
        successor_pubkey: &str,
        now: i64,
    ) -> anyhow::Result<ChannelHandoffCommitOutcome> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let Some(row) = Self::get_channel_locked(&tx, channel_id)? else {
            return Ok(ChannelHandoffCommitOutcome::NotPending);
        };
        if !row.is_owner || !row.successor_id.is_empty() {
            return Ok(ChannelHandoffCommitOutcome::NotPending);
        }
        match Self::channel_pending_handoff_locked(&tx, channel_id)? {
            Some((pending, ver)) if pending.eq_ignore_ascii_case(nominee) && ver == version => {}
            _ => return Ok(ChannelHandoffCommitOutcome::NotPending),
        }
        if let Some(held) = Self::load_channel_handoff_commit_locked(&tx, channel_id)? {
            return Ok(
                if held.version == version
                    && held.successor_pubkey.eq_ignore_ascii_case(successor_pubkey)
                {
                    ChannelHandoffCommitOutcome::Held(held)
                } else {
                    ChannelHandoffCommitOutcome::Conflict
                },
            );
        }
        let commit = ChannelHandoffCommit {
            nominee: nominee.to_ascii_lowercase(),
            version,
            successor_pubkey: successor_pubkey.to_ascii_lowercase(),
            committed_at: now,
            confirmed: false,
        };
        Self::store_channel_handoff_commit_locked(&tx, channel_id, &commit)?;
        tx.commit()?;
        Ok(ChannelHandoffCommitOutcome::Committed(commit))
    }

    pub fn channel_handoff_commit(
        &self,
        channel_id: &str,
    ) -> anyhow::Result<Option<ChannelHandoffCommit>> {
        let conn = self.conn.lock();
        Self::load_channel_handoff_commit_locked(&conn, channel_id)
    }

    /// Every committed handoff, keyed by the room it moves.
    pub fn list_channel_handoff_commits(
        &self,
    ) -> anyhow::Result<Vec<(String, ChannelHandoffCommit)>> {
        let conn = self.conn.lock();
        Self::ensure_channel_handoff_commits_locked(&conn)?;
        let mut stmt = conn.prepare(
            "SELECT channel_id, nominee, version, successor_pubkey, committed_at, confirmed
             FROM channel_handoff_commits",
        )?;
        let rows = stmt
            .query_map([], |row| {
                let channel_id: String = row.get(0)?;
                let commit = ChannelHandoffCommit {
                    nominee: row.get(1)?,
                    version: row.get::<_, i64>(2)?.max(0) as u64,
                    successor_pubkey: row.get(3)?,
                    committed_at: row.get(4)?,
                    confirmed: row.get::<_, i64>(5)? != 0,
                };
                Ok((channel_id, commit))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Record that a handoff record for a room we own is stored somewhere.
    ///
    /// A publish's own acknowledgement confirms only the commitment it was
    /// made for. With `adopt`, a record our handoff fetch *found* is taken on
    /// even when it is not the one we were publishing: whatever the DHT holds
    /// under our room's key is what the members follow, so the commitment
    /// moves to it rather than competing with it. A found record carries no
    /// nominee; see [`Self::apply_owned_channel_handoff`].
    pub fn confirm_channel_handoff(
        &self,
        channel_id: &str,
        version: u64,
        successor_pubkey: &str,
        now: i64,
        adopt: bool,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let Some(row) = Self::get_channel_locked(&tx, channel_id)? else {
            return Ok(false);
        };
        if !row.is_owner || !row.successor_id.is_empty() {
            return Ok(false);
        }
        let commit = match Self::load_channel_handoff_commit_locked(&tx, channel_id)? {
            Some(held)
                if held.version == version
                    && held.successor_pubkey.eq_ignore_ascii_case(successor_pubkey) =>
            {
                ChannelHandoffCommit {
                    confirmed: true,
                    ..held
                }
            }
            _ if !adopt => return Ok(false),
            _ => ChannelHandoffCommit {
                nominee: String::new(),
                version,
                successor_pubkey: successor_pubkey.to_ascii_lowercase(),
                committed_at: now,
                confirmed: true,
            },
        };
        Self::store_channel_handoff_commit_locked(&tx, channel_id, &commit)?;
        tx.commit()?;
        Ok(true)
    }

    /// Start a committed-but-unconfirmed handoff's publish window over.
    pub fn restart_channel_handoff_commit(&self, channel_id: &str, now: i64) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let Some(held) = Self::load_channel_handoff_commit_locked(&tx, channel_id)? else {
            return Ok(false);
        };
        if held.confirmed {
            return Ok(false);
        }
        Self::store_channel_handoff_commit_locked(
            &tx,
            channel_id,
            &ChannelHandoffCommit {
                committed_at: now,
                ..held
            },
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Forget a commitment for a room that is gone, moved, or no longer ours.
    pub fn drop_channel_handoff_commit(&self, channel_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::delete_channel_handoff_commit_locked(&conn, channel_id)
    }

    /// Created on first use rather than by a numbered migration, like
    /// `channel_handoff_commits`: nothing refers to it, and a numbered one
    /// would stop 1.7.0 from opening the database after a downgrade.
    fn ensure_sealed_offer_readers_locked(conn: &Connection) -> anyhow::Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sealed_offer_readers (
                member_pubkey TEXT PRIMARY KEY,
                last_seen INTEGER NOT NULL
            );",
        )?;
        Ok(())
    }

    /// Record that the room member with Ed25519 key `member_pubkey` (hex)
    /// proved at `now` that it reads sealed transfer offers. Forget every
    /// member last proven before `forget_before` or too far after `now` (a
    /// proof written while our clock was wrong), and all but the
    /// `keep_at_most` most recently proven.
    pub fn note_sealed_offer_reader(
        &self,
        member_pubkey: &str,
        now: i64,
        forget_before: i64,
        keep_at_most: usize,
    ) -> anyhow::Result<()> {
        let future_after = now.saturating_add(
            crate::network::ember::xfer::SEALED_OFFER_READER_MAX_FUTURE_SECS,
        );
        let conn = self.conn.lock();
        Self::ensure_sealed_offer_readers_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO sealed_offer_readers (member_pubkey, last_seen) VALUES (?1, ?2)
             ON CONFLICT(member_pubkey) DO UPDATE SET last_seen =
                CASE WHEN last_seen > ?3 THEN excluded.last_seen
                     ELSE MAX(last_seen, excluded.last_seen) END",
            params![member_pubkey.to_ascii_lowercase(), now, future_after],
        )?;
        tx.execute(
            "DELETE FROM sealed_offer_readers WHERE last_seen < ?1 OR last_seen > ?2",
            params![forget_before, future_after],
        )?;
        tx.execute(
            "DELETE FROM sealed_offer_readers WHERE member_pubkey IN (
                SELECT member_pubkey FROM sealed_offer_readers
                 ORDER BY last_seen DESC, member_pubkey ASC
                 LIMIT -1 OFFSET ?1
             )",
            params![keep_at_most as i64],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// When the member with Ed25519 key `member_pubkey` (hex) last proved it
    /// reads sealed transfer offers, if it ever did.
    pub fn sealed_offer_reader_seen_at(&self, member_pubkey: &str) -> anyhow::Result<Option<i64>> {
        let conn = self.conn.lock();
        Self::ensure_sealed_offer_readers_locked(&conn)?;
        Ok(conn
            .query_row(
                "SELECT last_seen FROM sealed_offer_readers WHERE member_pubkey = ?1",
                params![member_pubkey.to_ascii_lowercase()],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Hand a room we own to its confirmed successor, if that is still the
    /// handoff this device is committed to.
    ///
    /// Returns whether this call performed the transition. The check and the
    /// write share one transaction, so of two callers racing to finish the same
    /// handoff exactly one sees `true` and does the side effects that follow.
    /// A commitment made from a nominee's ready also requires that offer to
    /// still be the pending one; one adopted from the DHT has no nominee and
    /// is authoritative on its own.
    pub fn apply_owned_channel_handoff(&self, channel_id: &str) -> anyhow::Result<bool> {
        let successor_id = {
            let conn = self.conn.lock();
            let tx = conn.unchecked_transaction()?;
            let Some(row) = Self::get_channel_locked(&tx, channel_id)? else {
                return Ok(false);
            };
            if !row.is_owner || !row.successor_id.is_empty() {
                return Ok(false);
            }
            let Some(commit) = Self::load_channel_handoff_commit_locked(&tx, channel_id)? else {
                return Ok(false);
            };
            if !commit.confirmed {
                return Ok(false);
            }
            if !commit.nominee.is_empty() {
                match Self::channel_pending_handoff_locked(&tx, channel_id)? {
                    Some((pending, ver))
                        if pending.eq_ignore_ascii_case(&commit.nominee)
                            && ver == commit.version => {}
                    _ => return Ok(false),
                }
            }
            let Some(successor_pk) = hex::decode(&commit.successor_pubkey)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
            else {
                return Ok(false);
            };
            let successor_id =
                hex::encode(crate::network::ember::channel::channel_id_from_pubkey(&successor_pk));
            let keep = row.visibility == crate::network::ember::channel::CHANNEL_KIND_PRIVATE;
            if self.channel_handoff_transition_locked(
                &tx,
                channel_id,
                &commit.successor_pubkey,
                &successor_id,
                keep,
                None,
            )? != ChannelHandoffTransition::Applied
            {
                return Ok(false);
            }
            tx.commit()?;
            bump_channel_roster_generation(channel_id);
            bump_channel_roster_generation(&successor_id);
            successor_id
        };
        self.finish_channel_handoff(channel_id, &successor_id)?;
        Ok(true)
    }

    pub fn upsert_channel_member(
        &self,
        channel_id: &str,
        member_pubkey: &str,
        nickname: &str,
        last_seen: i64,
        local_pubkey: Option<&str>,
    ) -> anyhow::Result<ChannelMemberWrite> {
        let now = chrono::Utc::now().timestamp();
        // Signed records can claim a last_seen up to an hour ahead of us
        // (DHT store CLOCK_SKEW). Eviction sorts by last_seen, so an
        // unclamped future value would sit at the end of the list while
        // honest (and our own) rows are dropped first.
        let last_seen = last_seen.min(now);
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let prior: Option<(String, i64)> = tx
            .query_row(
                "SELECT nickname, last_seen FROM channel_members
                 WHERE channel_id = ?1 AND member_pubkey = ?2",
                params![channel_id, member_pubkey],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let existed = prior.is_some();
        tx.execute(
            "INSERT INTO channel_members (channel_id, member_pubkey, nickname, last_seen, banned, moderator)
             VALUES (?1, ?2, ?3, ?4, 0, 0)
             ON CONFLICT(channel_id, member_pubkey) DO UPDATE SET
                nickname = CASE WHEN excluded.nickname = '' THEN channel_members.nickname ELSE excluded.nickname END,
                last_seen = MAX(channel_members.last_seen, excluded.last_seen)",
            params![channel_id, member_pubkey, nickname, last_seen],
        )?;
        // Presence ingest and private-room chat can still grow the table.
        // Banned rows stay: a ban has to survive eviction or it can be
        // laundered by flooding new identities. Moderator rows stay for the
        // same reason and were the hole in it: the owner's snapshot writes them
        // with `last_seen = 0`, which is not a stale peer but a row that has
        // never carried a presence time, and sorting by `last_seen ASC` put
        // them first in the queue. A flood could evict the people holding the
        // mop, and this device would stop honouring their ban gossip until the
        // next snapshot arrived. Both lists are bounded by the record that
        // carries them, so exempting them cannot stop eviction from working.
        // Past the cap we only drop stale rows that are neither, never the
        // local user, and never a still-fresh honest peer — a flood of
        // newcomers is refused instead.
        let live: i64 = tx.query_row(
            "SELECT COUNT(*) FROM channel_members
             WHERE channel_id = ?1 AND banned = 0",
            params![channel_id],
            |row| row.get(0),
        )?;
        let mut evicted = 0usize;
        if live > CHANNEL_MEMBERS_MAX as i64 {
            let extra = live - CHANNEL_MEMBERS_MAX as i64;
            let cutoff = now.saturating_sub(PRESENCE_FRESH_SECS);
            evicted = tx.execute(
                "DELETE FROM channel_members WHERE rowid IN (
                    SELECT rowid FROM channel_members
                     WHERE channel_id = ?1 AND banned = 0 AND moderator = 0
                       AND member_pubkey != ?2
                       AND (?3 IS NULL OR member_pubkey != ?3)
                       AND last_seen < ?4
                     ORDER BY last_seen ASC, member_pubkey ASC
                     LIMIT ?5
                 )",
                params![channel_id, member_pubkey, local_pubkey, cutoff, extra],
            )?;
            let live: i64 = tx.query_row(
                "SELECT COUNT(*) FROM channel_members
                 WHERE channel_id = ?1 AND banned = 0",
                params![channel_id],
                |row| row.get(0),
            )?;
            if live > CHANNEL_MEMBERS_MAX as i64
                && !existed
                && local_pubkey != Some(member_pubkey)
            {
                tx.execute(
                    "DELETE FROM channel_members
                     WHERE channel_id = ?1 AND member_pubkey = ?2 AND banned = 0",
                    params![channel_id, member_pubkey],
                )?;
                tx.commit()?;
                if evicted > 0 {
                    bump_channel_roster_generation(channel_id);
                }
                return Ok(ChannelMemberWrite::Refused);
            }
        }
        tx.commit()?;
        let visible = evicted > 0
            || prior
                .as_ref()
                .is_none_or(|(_, old_seen)| channel_presence_revived(*old_seen, last_seen, now));
        if visible {
            bump_channel_roster_generation(channel_id);
        }
        Ok(match prior {
            None => ChannelMemberWrite::Inserted,
            Some((old_nick, old_seen)) => {
                let nick_changed = !nickname.is_empty() && nickname != old_nick;
                if nick_changed {
                    ChannelMemberWrite::Updated
                } else if last_seen > old_seen {
                    ChannelMemberWrite::Touched
                } else {
                    ChannelMemberWrite::Unchanged
                }
            }
        })
    }

    /// Refresh `last_seen` for a pubkey that already has a row. No INSERT:
    /// public-room chat must not admit strangers onto the gossip roster.
    ///
    /// Returns whether the row actually moved forward, which is a different
    /// question from whether one was found. Callers that push presence to the
    /// UI need the former: a member talking in a busy room is touched many
    /// times a second with a stamp the row already has, and reporting each of
    /// those as a change turned a quiet roster into a stream of no-op updates.
    /// The monotonic guarantee now lives in the `WHERE` rather than in `MAX`,
    /// so a late frame still cannot walk a row backwards.
    /// Apply many `last_seen` touches in one transaction.
    ///
    /// Returns, for each input row in order, whether it moved a roster row —
    /// the same answer [`Database::touch_channel_member_last_seen`] gives, and
    /// the thing the caller needs to know which rows to push to the UI.
    ///
    /// Rows are `(channel_id, member_pubkey, last_seen)`. The per-row method
    /// autocommits, and its caller ran once per received channel datagram, so a
    /// user in a few busy rooms was charging the shared connection mutex tens
    /// of fsyncs a second from inside the network task.
    pub fn touch_channel_members_last_seen(
        &self,
        rows: &[(String, String, i64)],
    ) -> anyhow::Result<Vec<bool>> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let now = chrono::Utc::now().timestamp();
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let mut updated = Vec::with_capacity(rows.len());
        let mut revived: Vec<&str> = Vec::new();
        {
            let mut stmt = tx.prepare(
                "UPDATE channel_members
                 SET last_seen = ?3
                 WHERE channel_id = ?1 AND member_pubkey = ?2 AND last_seen < ?3",
            )?;
            let mut prior = tx.prepare(
                "SELECT last_seen FROM channel_members WHERE channel_id = ?1 AND member_pubkey = ?2",
            )?;
            for (channel_id, member_pubkey, last_seen) in rows {
                let last_seen = (*last_seen).min(now);
                let before: Option<i64> = prior
                    .query_row(params![channel_id, member_pubkey], |row| row.get(0))
                    .optional()?;
                let moved = stmt.execute(params![channel_id, member_pubkey, last_seen])? > 0;
                if moved && before.is_some_and(|before| channel_presence_revived(before, last_seen, now)) {
                    revived.push(channel_id.as_str());
                }
                updated.push(moved);
            }
        }
        tx.commit()?;
        for channel_id in revived {
            bump_channel_roster_generation(channel_id);
        }
        Ok(updated)
    }

    pub fn touch_channel_member_last_seen(
        &self,
        channel_id: &str,
        member_pubkey: &str,
        last_seen: i64,
    ) -> anyhow::Result<bool> {
        let now = chrono::Utc::now().timestamp();
        let last_seen = last_seen.min(now);
        let conn = self.conn.lock();
        let before: Option<i64> = conn
            .query_row(
                "SELECT last_seen FROM channel_members WHERE channel_id = ?1 AND member_pubkey = ?2",
                params![channel_id, member_pubkey],
                |row| row.get(0),
            )
            .optional()?;
        let n = conn.execute(
            "UPDATE channel_members
             SET last_seen = ?3
             WHERE channel_id = ?1 AND member_pubkey = ?2 AND last_seen < ?3",
            params![channel_id, member_pubkey, last_seen],
        )?;
        drop(conn);
        if n > 0 && before.is_some_and(|before| channel_presence_revived(before, last_seen, now)) {
            bump_channel_roster_generation(channel_id);
        }
        Ok(n > 0)
    }

    pub fn remove_channel_member(
        &self,
        channel_id: &str,
        member_pubkey: &str,
        last_seen: i64,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let n = conn.execute(
            "DELETE FROM channel_members
             WHERE channel_id = ?1 AND member_pubkey = ?2 AND banned = 0
               AND last_seen <= ?3",
            params![channel_id, member_pubkey, last_seen],
        )?;
        drop(conn);
        if n > 0 {
            bump_channel_roster_generation(channel_id);
        }
        Ok(n > 0)
    }

    /// See [`bump_channel_roster_generation`] for the ordering a caller relies
    /// on: read this, then the rows, and the copy is current for as long as
    /// this value has not moved.
    pub fn channel_roster_generation(&self, channel_id: &str) -> u64 {
        channel_roster_slot(channel_id).load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn list_channel_members(
        &self,
        channel_id: &str,
    ) -> anyhow::Result<Vec<StoredChannelMember>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT member_pubkey, nickname, last_seen, banned, moderator
             FROM channel_members WHERE channel_id = ?1
             ORDER BY nickname COLLATE NOCASE, member_pubkey",
        )?;
        let rows = stmt
            .query_map(params![channel_id], |row| {
                Ok(StoredChannelMember {
                    member_pubkey: row.get(0)?,
                    nickname: row.get(1)?,
                    last_seen: row.get(2)?,
                    banned: row.get::<_, i64>(3)? != 0,
                    moderator: row.get::<_, i64>(4)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Rooms this device is in with `member_pubkey`, where neither of us is
    /// banned and they have been seen, most recently seen there first.
    pub fn rooms_shared_with(
        &self,
        member_pubkey: &str,
        our_pubkey: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<String>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT c.channel_id FROM channel_members m
             JOIN channels c ON c.channel_id = m.channel_id
             WHERE lower(m.member_pubkey) = lower(?1) AND m.banned = 0 AND m.last_seen > 0
               AND c.in_room = 1 AND c.deleted = 0
               AND NOT EXISTS (
                   SELECT 1 FROM channel_members us
                   WHERE us.channel_id = c.channel_id
                     AND lower(us.member_pubkey) = lower(?2) AND us.banned = 1)
             ORDER BY m.last_seen DESC LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![member_pubkey, our_pubkey, limit as i64], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        Ok(rows)
    }

    pub fn channel_member_is_banned(
        &self,
        channel_id: &str,
        member_pubkey: &str,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let banned: Option<i64> = conn
            .query_row(
                "SELECT banned FROM channel_members WHERE channel_id = ?1 AND member_pubkey = ?2",
                params![channel_id, member_pubkey],
                |row| row.get(0),
            )
            .optional()?;
        Ok(banned.unwrap_or(0) != 0)
    }

    /// Whether a pubkey has a roster row at all, and whether it is banned.
    ///
    /// `None` for no row, `Some(banned)` otherwise. One query rather than two,
    /// because presence ingest asks both questions about every beacon in every
    /// digest and rooms beat on a timer.
    pub fn channel_member_status(
        &self,
        channel_id: &str,
        member_pubkey: &str,
    ) -> anyhow::Result<Option<bool>> {
        let conn = self.conn.lock();
        let banned: Option<i64> = conn
            .query_row(
                "SELECT banned FROM channel_members WHERE channel_id = ?1 AND member_pubkey = ?2",
                params![channel_id, member_pubkey],
                |row| row.get(0),
            )
            .optional()?;
        Ok(banned.map(|flag| flag != 0))
    }

    /// `(banned, moderator)` per room for one member, keyed by `channel_id`.
    ///
    /// The room list needs both flags for every row, and asking per row cost
    /// two statements per room — each retaking the single connection lock the
    /// network loop is also contending for. Both flags live in the same
    /// roster row, and a member has at most one row per room, so the whole
    /// answer is one indexed scan. A room with no roster row for this member
    /// is simply absent; callers read that as "neither flag set".
    pub fn channel_member_flags(
        &self,
        member_pubkey: &str,
    ) -> anyhow::Result<std::collections::HashMap<String, (bool, bool)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT channel_id, banned, moderator FROM channel_members WHERE member_pubkey = ?1",
        )?;
        let rows = stmt.query_map(params![member_pubkey], |row| {
            Ok((
                row.get::<_, String>(0)?,
                (
                    row.get::<_, i64>(1)? != 0,
                    row.get::<_, i64>(2)? != 0,
                ),
            ))
        })?;
        let mut out = std::collections::HashMap::new();
        for row in rows {
            let (channel_id, flags) = row?;
            out.insert(channel_id, flags);
        }
        Ok(out)
    }

    pub fn channel_member_is_moderator(
        &self,
        channel_id: &str,
        member_pubkey: &str,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let flag: Option<i64> = conn
            .query_row(
                "SELECT moderator FROM channel_members WHERE channel_id = ?1 AND member_pubkey = ?2",
                params![channel_id, member_pubkey],
                |row| row.get(0),
            )
            .optional()?;
        Ok(flag.unwrap_or(0) != 0)
    }

    fn hex_pubkeys_from_query(
        conn: &Connection,
        sql: &str,
        channel_id: &str,
    ) -> anyhow::Result<Vec<[u8; 32]>> {
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map(params![channel_id], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for pk_hex in rows {
            let Ok(pk_hex) = pk_hex else {
                continue;
            };
            let Ok(bytes) = hex::decode(pk_hex) else {
                continue;
            };
            if let Ok(pk) = <[u8; 32]>::try_from(bytes) {
                out.push(pk);
            }
        }
        Ok(out)
    }

    /// Bans a moderation record can actually carry, newest first.
    ///
    /// Capped and ordered here rather than at the encoder because both readers
    /// publish what they get: [`crate::network::ember::dht::publish::encode_moderation_extra`]
    /// truncates silently past `CHANNEL_BAN_LIST_MAX`, and every recipient
    /// applies a moderation record as a *full snapshot* — so a room holding
    /// more bans than the record can carry had the owner's six-hourly
    /// republish lift the surplus room-wide, while the owner's own commands
    /// refused to run because their snapshot no longer fit.
    ///
    /// `ban_revised_at DESC` so the entries that survive are the most recent
    /// decisions, tie-broken by pubkey so every device trims identically.
    pub fn list_banned_channel_pubkeys(&self, channel_id: &str) -> anyhow::Result<Vec<[u8; 32]>> {
        let conn = self.conn.lock();
        Self::hex_pubkeys_from_query(
            &conn,
            &format!(
                "SELECT member_pubkey FROM channel_members
                 WHERE channel_id = ?1 AND banned = 1
                 ORDER BY ban_revised_at DESC, member_pubkey
                 LIMIT {}",
                crate::network::ember::dht::publish::CHANNEL_BAN_LIST_MAX
            ),
            channel_id,
        )
    }

    pub fn list_moderator_channel_pubkeys(
        &self,
        channel_id: &str,
    ) -> anyhow::Result<Vec<[u8; 32]>> {
        let conn = self.conn.lock();
        Self::hex_pubkeys_from_query(
            &conn,
            "SELECT member_pubkey FROM channel_members
             WHERE channel_id = ?1 AND moderator = 1
             ORDER BY member_pubkey",
            channel_id,
        )
    }

    /// Apply a gossip ban/unban from a delegated moderator. Wins only if newer
    /// than the last owner snapshot *and* any previous revision on that row.
    pub fn apply_channel_ban_action(
        &self,
        channel_id: &str,
        member_pubkey: &str,
        banned: bool,
        timestamp: i64,
    ) -> anyhow::Result<bool> {
        let now = chrono::Utc::now().timestamp();
        if !crate::network::ember::channel::gossip_timestamp_ok(timestamp, now) {
            return Ok(false);
        }
        let timestamp = timestamp.min(now);
        let conn = self.conn.lock();
        let snapshot: i64 = conn
            .query_row(
                "SELECT moderation_updated_at FROM channels WHERE channel_id = ?1",
                params![channel_id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        if timestamp < snapshot {
            return Ok(false);
        }
        // A ban that cannot be published is not a ban, and this is the one path
        // that could mint them without a ceiling: a delegated moderator's
        // gossip inserts a row for any pubkey it names, member or not. Past
        // `CHANNEL_BAN_LIST_MAX` the owner's next republish would lift the
        // surplus for the whole room, and the rows themselves are exempt from
        // roster eviction — deliberately, so a ban cannot be laundered by
        // flooding new identities, but that exemption needs a ceiling to go
        // with it or one compromised moderator grows every member's database
        // without bound.
        //
        // The target is excluded from the count so re-stating an existing ban
        // still refreshes `ban_revised_at` at exactly the cap. Unbans are never
        // refused: they only ever clear a row.
        if banned {
            let held: i64 = conn.query_row(
                "SELECT COUNT(*) FROM channel_members
                 WHERE channel_id = ?1 AND banned = 1
                   AND lower(member_pubkey) <> lower(?2)",
                params![channel_id, member_pubkey],
                |row| row.get(0),
            )?;
            if held >= crate::network::ember::dht::publish::CHANNEL_BAN_LIST_MAX as i64 {
                return Ok(false);
            }
        }
        let n = conn.execute(
            "INSERT INTO channel_members
                (channel_id, member_pubkey, nickname, last_seen, banned, moderator, ban_revised_at)
             VALUES (?1, ?2, '', 0, ?3, 0, ?4)
             ON CONFLICT(channel_id, member_pubkey) DO UPDATE SET
                banned = excluded.banned,
                ban_revised_at = excluded.ban_revised_at
             WHERE channel_members.ban_revised_at <= excluded.ban_revised_at",
            params![
                channel_id,
                member_pubkey,
                if banned { 1 } else { 0 },
                timestamp
            ],
        )?;
        if n > 0 {
            bump_channel_roster_generation(channel_id);
        }
        Ok(n > 0)
    }

    /// Apply an owner-signed moderation snapshot if it is newer than what we hold.
    /// Replaces bans and the moderator list; a later gossip action can still
    /// override an individual ban via `ban_revised_at`.
    /// Apply an owner-signed snapshot.
    ///
    /// Each of the trailing facts is only written when the record actually
    /// carries it, so a record predating a field cannot erase what a newer one
    /// already told us. The owner is never added to the ban list even if the
    /// snapshot names them — the owner is the authority a ban derives from, so
    /// a record banning them is corrupt or hostile either way.
    pub fn apply_channel_moderation(
        &self,
        channel_id: &str,
        topic: &str,
        welcome: &str,
        timestamp: i64,
        banned_pubkeys: &[[u8; 32]],
        moderator_pubkeys: &[[u8; 32]],
        owner_pubkey: Option<&[u8; 32]>,
        successor_nominee: Option<&[u8; 32]>,
        claim_after_days: Option<u16>,
        key_epoch: Option<u64>,
        invites_owner_only: Option<bool>,
        slow_mode_secs: Option<u16>,
    ) -> anyhow::Result<bool> {
        let snapshot = ModerationSnapshot {
            topic,
            welcome,
            banned_pubkeys,
            moderator_pubkeys,
            owner_pubkey,
            successor_nominee,
            claim_after_days,
            key_epoch,
            invites_owner_only,
            slow_mode_secs,
        };
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let applied = Self::apply_channel_moderation_locked(
            &tx,
            channel_id,
            &snapshot,
            timestamp,
            ModerationOrder::Local,
        )?;
        if applied {
            tx.commit()?;
            bump_channel_roster_generation(channel_id);
        }
        Ok(applied)
    }

    /// [`Self::apply_channel_moderation`] for a snapshot fetched from the
    /// network, which is ordered by its signature as well as its stamp.
    ///
    /// On a room this device owns, only a snapshot stamped after everything it
    /// has signed or applied itself is taken. Anything else is its own earlier
    /// work coming back, and applying it would roll back whatever the owner
    /// changed since.
    pub fn ingest_channel_moderation(
        &self,
        channel_id: &str,
        snapshot: &ModerationSnapshot<'_>,
        timestamp: i64,
        signature: &[u8; 64],
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let applied = Self::apply_channel_moderation_locked(
            &tx,
            channel_id,
            snapshot,
            timestamp,
            ModerationOrder::Fetched(signature),
        )?;
        if applied {
            tx.commit()?;
            bump_channel_roster_generation(channel_id);
        }
        Ok(applied)
    }

    /// Stamp and apply an owner's edit to a room it owns in one step, with the
    /// room policy that rides the same record, and return the stamp its record
    /// must be signed with. `None` when the room is not on this device.
    ///
    /// One step so the owner's republish, which stamps and then reads, either
    /// reads this edit or is stamped before it: a republish of the state before
    /// the edit can never carry the later stamp and undo it for the room.
    ///
    /// Applied whatever this device already holds. The owner is the authority,
    /// and after a stamp from a clock that ran fast (see
    /// [`Self::stamp_owner_snapshot`]) its own last snapshot can be dated after
    /// the edit it is making now.
    pub fn commit_owner_channel_moderation(
        &self,
        channel_id: &str,
        snapshot: &ModerationSnapshot<'_>,
        policy: &OwnerRoomPolicy<'_>,
        now: i64,
    ) -> anyhow::Result<Option<i64>> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let Some(stamp) = Self::stamp_owner_snapshot_locked(&tx, channel_id, now)? else {
            return Ok(None);
        };
        if !Self::apply_channel_moderation_locked(
            &tx,
            channel_id,
            snapshot,
            stamp,
            ModerationOrder::OwnerEdit,
        )? {
            return Ok(None);
        }
        Self::apply_owner_room_policy_locked(&tx, channel_id, policy)?;
        tx.commit()?;
        bump_channel_roster_generation(channel_id);
        Ok(Some(stamp))
    }

    /// The stamp for the next moderation snapshot this device signs for a room
    /// it owns: `now`, or one past the newest it has signed or applied when that
    /// is not already behind. Stored, so neither a restart nor a republish in
    /// the same second as an edit can repeat one. `None` when the room is not on
    /// this device.
    ///
    /// A stored stamp more than [`OWNER_STAMP_MAX_LEAD_SECS`] ahead of now was
    /// taken while this clock ran fast. Counting on from it would date every
    /// later snapshot that far ahead, which storers refuse past an hour, so the
    /// room's bans and topic would stop reaching anyone until real time caught
    /// up. Such a stamp is dropped and counting restarts from now.
    pub fn stamp_owner_snapshot(&self, channel_id: &str, now: i64) -> anyhow::Result<Option<i64>> {
        let conn = self.conn.lock();
        Self::stamp_owner_snapshot_locked(&conn, channel_id, now)
    }

    fn stamp_owner_snapshot_locked(
        conn: &Connection,
        channel_id: &str,
        now: i64,
    ) -> anyhow::Result<Option<i64>> {
        Ok(conn
            .query_row(
                "UPDATE channels SET owner_snapshot_at = MAX(?2, 1 + MAX(
                    CASE WHEN owner_snapshot_at <= ?2 + ?3 THEN owner_snapshot_at ELSE 0 END,
                    CASE WHEN moderation_updated_at <= ?2 + ?3 THEN moderation_updated_at ELSE 0 END))
                 WHERE channel_id = ?1
                 RETURNING owner_snapshot_at",
                params![channel_id, now, OWNER_STAMP_MAX_LEAD_SECS],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Everything [`Self::apply_channel_moderation`] writes, inside the
    /// caller's transaction. The caller commits and bumps the roster.
    fn apply_channel_moderation_locked(
        tx: &Connection,
        channel_id: &str,
        snapshot: &ModerationSnapshot<'_>,
        timestamp: i64,
        order: ModerationOrder<'_>,
    ) -> anyhow::Result<bool> {
        let ModerationSnapshot {
            topic,
            welcome,
            banned_pubkeys,
            moderator_pubkeys,
            owner_pubkey,
            successor_nominee,
            claim_after_days,
            key_epoch,
            invites_owner_only,
            slow_mode_secs,
        } = *snapshot;
        let held: Option<(i64, Option<Vec<u8>>, i64, bool)> = tx
            .query_row(
                "SELECT moderation_updated_at, moderation_sig, owner_snapshot_at, is_owner
                 FROM channels WHERE channel_id = ?1",
                params![channel_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get::<_, i64>(3)? != 0)),
            )
            .optional()?;
        let Some((current, held_sig, owner_signed_at, is_owner)) = held else {
            return Ok(false);
        };
        let held_sig = held_sig.and_then(|sig| <[u8; 64]>::try_from(sig).ok());
        let (takes, signature) = match order {
            ModerationOrder::Local => (timestamp >= current, None),
            ModerationOrder::Fetched(sig) => (
                crate::network::ember::dht::publish::moderation_supersedes(
                    timestamp,
                    sig,
                    current,
                    held_sig.as_ref(),
                ) && !(is_owner && timestamp <= current.max(owner_signed_at)),
                Some(sig),
            ),
            ModerationOrder::OwnerEdit => (true, None),
        };
        if !takes {
            return Ok(false);
        }
        let topic = crate::security::sanitize_remote_text(topic, 64);
        let welcome = crate::security::sanitize_remote_text(welcome, 512);
        let n = tx.execute(
            "UPDATE channels SET topic = ?2, welcome = ?3, moderation_updated_at = ?4,
                moderation_sig = ?5
             WHERE channel_id = ?1",
            params![channel_id, topic, welcome, timestamp, signature.map(|s| s.as_slice())],
        )?;
        if n == 0 {
            return Ok(false);
        }
        tx.execute(
            "UPDATE channel_members SET banned = 0
             WHERE channel_id = ?1 AND ban_revised_at <= ?2",
            params![channel_id, timestamp],
        )?;
        tx.execute(
            "UPDATE channel_members SET moderator = 0 WHERE channel_id = ?1",
            params![channel_id],
        )?;
        let owner_hex = owner_pubkey.map(hex::encode);
        for pk in banned_pubkeys.iter().take(32) {
            let hex_pk = hex::encode(pk);
            // The owner is the authority a ban derives from, so a snapshot
            // naming them is corrupt or hostile either way. Skipping is enough:
            // the sweep above has already cleared their row.
            if owner_hex.as_deref() == Some(hex_pk.as_str()) {
                continue;
            }
            tx.execute(
                "INSERT INTO channel_members
                    (channel_id, member_pubkey, nickname, last_seen, banned, moderator, ban_revised_at)
                 VALUES (?1, ?2, '', 0, 1, 0, ?3)
                 ON CONFLICT(channel_id, member_pubkey) DO UPDATE SET
                    banned = 1,
                    ban_revised_at = excluded.ban_revised_at
                 WHERE channel_members.ban_revised_at <= excluded.ban_revised_at",
                params![channel_id, hex_pk, timestamp],
            )?;
        }
        for pk in moderator_pubkeys.iter().take(16) {
            let hex_pk = hex::encode(pk);
            tx.execute(
                "INSERT INTO channel_members
                    (channel_id, member_pubkey, nickname, last_seen, banned, moderator, ban_revised_at)
                 VALUES (?1, ?2, '', 0, 0, 1, 0)
                 ON CONFLICT(channel_id, member_pubkey) DO UPDATE SET moderator = 1",
                params![channel_id, hex_pk],
            )?;
        }
        // Only overwrite when this record actually carries an owner: a record
        // predating the field must not erase what a newer one already told us.
        if let Some(hex_owner) = owner_hex.as_deref() {
            tx.execute(
                "UPDATE channels SET owner_pubkey = ?2 WHERE channel_id = ?1",
                params![channel_id, hex_owner],
            )?;
            // A ban recorded against the owner before we knew who they were is
            // exactly the state this whole change exists to undo.
            tx.execute(
                "UPDATE channel_members SET banned = 0
                 WHERE channel_id = ?1 AND lower(member_pubkey) = lower(?2)",
                params![channel_id, hex_owner],
            )?;
        }
        if let Some(nominee) = successor_nominee {
            // All zeros is the owner withdrawing the nomination, not a member
            // whose key happens to be zero. Absent (`None`) is a record that
            // does not say, which must leave what we already know alone.
            let hex_nominee = if nominee.iter().all(|b| *b == 0) {
                String::new()
            } else {
                hex::encode(nominee)
            };
            tx.execute(
                "UPDATE channels SET successor_nominee = ?2 WHERE channel_id = ?1",
                params![channel_id, hex_nominee],
            )?;
        }
        if let Some(days) = claim_after_days {
            tx.execute(
                "UPDATE channels SET claim_after_days = ?2 WHERE channel_id = ?1",
                params![channel_id, days as i64],
            )?;
        }
        // Never walk it backwards: an out-of-order record must not send a
        // member hunting for an epoch that has already been superseded.
        if let Some(epoch) = key_epoch {
            tx.execute(
                "UPDATE channels SET key_epoch_wanted = ?2
                 WHERE channel_id = ?1 AND key_epoch_wanted < ?2",
                params![channel_id, epoch as i64],
            )?;
        }
        // Absent means the record predates the field, which must leave the
        // stored policy alone rather than reading as "anyone may invite".
        if let Some(owner_only) = invites_owner_only {
            tx.execute(
                "UPDATE channels SET invites_owner_only = ?2 WHERE channel_id = ?1",
                params![channel_id, i64::from(owner_only)],
            )?;
        }
        // Unlike the fields above, absent here means off rather than "the
        // record does not say". The writer leaves it out when there is no
        // limit, so treating absence as unknown would leave a room throttled
        // after its owner turned slow mode back off.
        tx.execute(
            "UPDATE channels SET slow_mode_secs = ?2 WHERE channel_id = ?1",
            params![channel_id, i64::from(slow_mode_secs.unwrap_or(0))],
        )?;
        Ok(true)
    }

    /// Take the room name from an owner snapshot that
    /// [`Self::apply_channel_moderation`] has just accepted — which is what
    /// makes it the newest the owner has signed. Trimmed the way a Discover or
    /// invite name is, since it reaches us the same way. Returns whether the
    /// stored name changed.
    pub fn apply_owner_room_name(&self, channel_id: &str, name: &str) -> anyhow::Result<bool> {
        let name = crate::security::sanitize_remote_text(name, ROOM_NAME_MAX_CHARS);
        if name.is_empty() {
            return Ok(false);
        }
        let conn = self.conn.lock();
        let changed = conn.execute(
            "UPDATE channels SET name = ?2 WHERE channel_id = ?1 AND name <> ?2",
            params![channel_id, name],
        )?;
        drop(conn);
        if changed > 0 {
            bump_channel_roster_generation(channel_id);
        }
        Ok(changed > 0)
    }

    /// Take the announce flag, the pins and the language from an owner snapshot that
    /// [`Self::apply_channel_moderation`] has just accepted, the same way
    /// [`Self::apply_owner_room_name`] takes the name — so an older record
    /// replayed from a slow storer cannot unpin or reopen the room.
    ///
    /// Written whatever the record says, absence included: the writer leaves
    /// all three out when unset, so absent means "off", "none" and "no
    /// language", as for slow mode. Returns whether any changed.
    pub fn apply_owner_room_policy(
        &self,
        channel_id: &str,
        announce_only: bool,
        pinned_msg_ids: &[[u8; 16]],
        language: Option<&str>,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let changed = Self::apply_owner_room_policy_locked(
            &conn,
            channel_id,
            &OwnerRoomPolicy {
                announce_only,
                pinned_msg_ids,
                language,
            },
        )?;
        drop(conn);
        if changed {
            bump_channel_roster_generation(channel_id);
        }
        Ok(changed)
    }

    fn apply_owner_room_policy_locked(
        conn: &Connection,
        channel_id: &str,
        policy: &OwnerRoomPolicy<'_>,
    ) -> anyhow::Result<bool> {
        let pins = policy
            .pinned_msg_ids
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>()
            .join(",");
        let language = policy.language.unwrap_or("");
        let changed = conn.execute(
            "UPDATE channels SET announce_only = ?2, pinned_msg_ids = ?3, language = ?4
             WHERE channel_id = ?1
               AND (announce_only <> ?2 OR pinned_msg_ids <> ?3 OR language <> ?4)",
            params![channel_id, i64::from(policy.announce_only), pins, language],
        )?;
        Ok(changed > 0)
    }

    /// [`Self::insert_channel`] for a room we are creating with a default
    /// language, both under one lock. A roster read landing between two
    /// separate writes would cache the row without its language, and the owner
    /// loop's first republish — due at once for a new room — would sign that.
    /// Later changes ride [`Self::apply_owner_room_policy`].
    #[allow(clippy::too_many_arguments)]
    pub fn insert_channel_with_language(
        &self,
        channel_id: &str,
        pubkey: &str,
        name: &str,
        visibility: &str,
        is_owner: bool,
        owner_seed: Option<&[u8; 32]>,
        join_secret: Option<&[u8; 32]>,
        language: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        self.insert_channel_locked(
            &tx,
            channel_id,
            pubkey,
            name,
            visibility,
            is_owner,
            owner_seed,
            join_secret,
        )?;
        tx.execute(
            "UPDATE channels SET language = ?2 WHERE channel_id = ?1",
            params![channel_id, language],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Which of `msg_ids` this device has been told to forget in this room.
    ///
    /// An owner's commit drops those from the pins it publishes. A pin merely
    /// not held here is kept: history is trimmed per room, and the oldest pin
    /// in a busy room is exactly the one that would fall out of it.
    ///
    /// Runs on the owner republish pass, on the network task, once per owned
    /// room: an existence check and a tombstone lookup per pin, with no body
    /// decrypted, and nothing at all for a room without pins.
    pub fn channel_messages_removed(
        &self,
        channel_id: &str,
        msg_ids: &[String],
    ) -> anyhow::Result<Vec<String>> {
        if msg_ids.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn.lock();
        let mut removed = Vec::new();
        for id in msg_ids {
            let held: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM channel_messages WHERE channel_id = ?1 AND msg_id = ?2)",
                params![channel_id, id],
                |row| row.get(0),
            )?;
            if !held && Self::channel_msg_tombstoned_locked(&conn, channel_id, id)? {
                removed.push(id.clone());
            }
        }
        Ok(removed)
    }

    /// Record an owner's rename of their room, once the registry has granted
    /// the name.
    pub fn rename_owned_channel(
        &self,
        channel_id: &str,
        name: &str,
        renamed_at: i64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE channels SET name = ?2, renamed_at = ?3 WHERE channel_id = ?1",
            params![channel_id, name, renamed_at],
        )?;
        drop(conn);
        bump_channel_roster_generation(channel_id);
        Ok(())
    }

    /// Rooms this device owns and has not deleted, which is what the creation
    /// cap counts. Leaving a room you own does not give the slot back: the name
    /// is still claimed and the room is still yours to delete.
    pub fn count_owned_channels(&self) -> anyhow::Result<i64> {
        let conn = self.conn.lock();
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM channels WHERE is_owner = 1 AND deleted = 0",
            [],
            |row| row.get(0),
        )?;
        Ok(n)
    }

    /// Timestamp of the newest message we sent to this room, or 0 if we never
    /// have. Read on the send path to apply the room's slow mode across
    /// restarts, which an in-memory timer would forget.
    ///
    /// Held on the room rather than derived from the message history, which the
    /// per-message delete button can edit — see the v40 migration.
    pub fn last_sent_channel_message_at(&self, channel_id: &str) -> anyhow::Result<i64> {
        let conn = self.conn.lock();
        let ts: Option<i64> = conn
            .query_row(
                "SELECT last_sent_at FROM channels WHERE channel_id = ?1",
                params![channel_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(ts.unwrap_or(0))
    }

    pub fn touch_channel_presence(&self, channel_id: &str, when: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE channels SET presence_published_at = ?2 WHERE channel_id = ?1",
            params![channel_id, when],
        )?;
        Ok(())
    }

    pub fn channels_due_for_presence(
        &self,
        now: i64,
        interval_secs: i64,
    ) -> anyhow::Result<Vec<String>> {
        let conn = self.conn.lock();
        // `presence_published_at > ?2` catches a stamp written by a clock that
        // has since been corrected backwards. Without it such a row is never
        // `<= cutoff` again until real time passes it, and a member who is
        // sitting in the room ages out of everyone else's roster meanwhile.
        let mut stmt = conn.prepare(
            "SELECT channel_id FROM channels
             WHERE (presence_published_at <= ?1 OR presence_published_at > ?2)
               AND successor_id = '' AND in_room = 1 AND deleted = 0
             ORDER BY presence_published_at ASC",
        )?;
        let cutoff = now.saturating_sub(interval_secs);
        let rows = stmt
            .query_map(params![cutoff, now], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Hand a presence slot back when the publish stored on nobody.
    ///
    /// Conditional on the stamp still being the one this publish wrote, so a
    /// late failure from an earlier attempt cannot undo a later success.
    pub fn retry_channel_presence(
        &self,
        channel_id: &str,
        expected: i64,
        retry_at: i64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE channels SET presence_published_at = ?3
             WHERE channel_id = ?1 AND presence_published_at = ?2",
            params![channel_id, expected, retry_at],
        )?;
        Ok(())
    }

    /// Make every joined room's presence due on the next scan.
    ///
    /// Used when the Channel username changes, so the new handle is announced
    /// immediately rather than waiting out a republish interval that still
    /// names the old one.
    pub fn due_channel_presence_now(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE channels SET presence_published_at = 0
             WHERE in_room = 1 AND deleted = 0 AND successor_id = ''",
            [],
        )?;
        Ok(())
    }

    /// Record that a private room we own owes a key rotation.
    ///
    /// Written when a delegated moderator's ban lands. Only the owner can mint an
    /// epoch record, so until this is acted on their ban is a label the evicted
    /// member reads straight through — and holding the intention in memory meant
    /// closing the app in the wrong second turned it into one permanently.
    pub fn mark_channel_rotate_pending(&self, channel_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE channels SET rotate_pending = 1
             WHERE channel_id = ?1 AND is_owner = 1 AND visibility = 'private'",
            params![channel_id],
        )?;
        Ok(())
    }

    /// Clear it, once the snapshot announcing the new epoch is on its way.
    pub fn clear_channel_rotate_pending(&self, channel_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE channels SET rotate_pending = 0 WHERE channel_id = ?1",
            params![channel_id],
        )?;
        Ok(())
    }

    /// Rooms still owing the presence tombstone that says we left.
    ///
    /// `departure_due_at` is when to try next, not when we left: a tombstone has
    /// to be *newer* than the live announcement it replaces, so each attempt
    /// mints its own timestamp. What makes that safe is the `in_room = 0` test
    /// here plus the clear on rejoining — publishing a departure after walking
    /// back in would delete the row we had just re-earned.
    ///
    /// Retried until it lands. A tombstone that never published leaves us on
    /// every other roster until we age out, and one publish attempt per room per
    /// presence interval is nothing next to that; the set is only rooms left
    /// while the network was unreachable, and it empties as soon as one is.
    pub fn channels_due_for_departure(&self, now: i64) -> anyhow::Result<Vec<String>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT channel_id FROM channels
             WHERE departure_due_at > 0 AND in_room = 0 AND deleted = 0
               AND departure_due_at <= ?1
             ORDER BY departure_due_at",
        )?;
        let rows = stmt
            .query_map(params![now], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Owe a leave tombstone for this room, next attempted at `at`.
    ///
    /// Only while we are actually out of the room, so nothing can arm this
    /// against a room we are sitting in.
    pub fn mark_channel_departure_due(&self, channel_id: &str, at: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE channels SET departure_due_at = ?2
             WHERE channel_id = ?1 AND in_room = 0",
            params![channel_id, at.max(1)],
        )?;
        Ok(())
    }

    /// Take the next attempt at a room's leave tombstone, reserving it.
    ///
    /// One statement, because the check and the reservation cannot be allowed to
    /// come apart. The publisher works from a list it gathered earlier and yields
    /// to the runtime between rooms, so a rejoin can land in the middle of a pass
    /// — and publishing a departure after walking back in tells every member to
    /// drop the roster row we just re-earned. `in_room = 0` is part of the write
    /// rather than something read beforehand.
    ///
    /// Returns whether this caller now owns the attempt. The stamp moves to
    /// `next_attempt` either way, so a publish that fails to start is retried on
    /// the ordinary interval instead of spinning.
    pub fn claim_channel_departure(
        &self,
        channel_id: &str,
        next_attempt: i64,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let n = conn.execute(
            "UPDATE channels SET departure_due_at = ?2
             WHERE channel_id = ?1 AND in_room = 0 AND deleted = 0
               AND departure_due_at > 0",
            params![channel_id, next_attempt.max(1)],
        )?;
        Ok(n > 0)
    }

    /// Stop owing it — the STORE landed, or we are back in the room.
    pub fn clear_channel_departure(&self, channel_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE channels SET departure_due_at = 0 WHERE channel_id = ?1",
            params![channel_id],
        )?;
        Ok(())
    }

    /// Whether a room we own owes a rotation for a moderator's ban.
    pub fn channel_rotate_is_pending(&self, channel_id: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let pending: Option<i64> = conn
            .query_row(
                "SELECT rotate_pending FROM channels WHERE channel_id = ?1",
                params![channel_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(pending.unwrap_or(0) != 0)
    }

    /// Rename our own roster rows across every room we sit in.
    pub fn rename_self_channel_member(
        &self,
        member_pubkey: &str,
        nickname: &str,
    ) -> anyhow::Result<usize> {
        let conn = self.conn.lock();
        let n = conn.execute(
            "UPDATE channel_members SET nickname = ?2 WHERE member_pubkey = ?1",
            params![member_pubkey, nickname],
        )?;
        Ok(n)
    }

    /// `author_sig` is the author's hex Ed25519 signature over the line, or
    /// empty when we hold none — a locally copied handoff, or a row written
    /// before signatures existed. Only a row that has one can be re-served to
    /// another member, since a re-serve replays the original rather than
    /// signing afresh.
    ///
    /// `message` is the text exactly as signed, reply trailer included; the
    /// `reply_to` column is read out of it here.
    pub fn insert_channel_message(
        &self,
        channel_id: &str,
        sender_pubkey: &str,
        direction: &str,
        message: &str,
        msg_id: &str,
        timestamp: i64,
        author_sig: &str,
        read: bool,
    ) -> anyhow::Result<i64> {
        const MAX_CHANNEL_MESSAGE_LEN: usize = 4096;
        const MAX_MESSAGES_PER_CHANNEL: i64 = Database::CHANNEL_MESSAGES_PER_CHANNEL;
        let message: &str = if message.len() > MAX_CHANNEL_MESSAGE_LEN {
            let mut end = MAX_CHANNEL_MESSAGE_LEN;
            while end > 0 && !message.is_char_boundary(end) {
                end -= 1;
            }
            &message[..end]
        } else {
            message
        };
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let now = if timestamp > 0 {
            timestamp
        } else {
            chrono::Utc::now().timestamp()
        };
        if let Some((held_id, true)) =
            Self::channel_line_supersedes_locked(&tx, channel_id, msg_id, sender_pubkey, now)?
        {
            tx.execute(
                "DELETE FROM channel_messages WHERE id = ?1",
                params![held_id],
            )?;
        }
        // From the text as stored, so the column can never disagree with the
        // signed trailer a catch-up re-serves.
        let reply_to = crate::network::ember::channel::chat_reply_parent_hex(message, msg_id);
        tx.execute(
            "INSERT OR IGNORE INTO channel_messages (channel_id, sender_pubkey, direction, message, timestamp, read, msg_id, author_sig, first_seen_at, reply_to)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                channel_id,
                sender_pubkey,
                direction,
                CHAT_CIPHERTEXT_PREFIX,
                now,
                if read { 1 } else { 0 },
                msg_id,
                author_sig,
                // Our clock, not the author's: this is what closes the edit
                // window against a backdated revision, so it must not be
                // something the sender can choose.
                chrono::Utc::now().timestamp(),
                reply_to
            ],
        )?;
        if tx.changes() == 0 {
            let existing: i64 = tx.query_row(
                "SELECT id FROM channel_messages WHERE channel_id = ?1 AND msg_id = ?2",
                params![channel_id, msg_id],
                |row| row.get(0),
            )?;
            tx.commit()?;
            return Ok(existing);
        }
        let new_id = tx.last_insert_rowid();
        let encrypted = Self::encrypt_channel_message_body(
            self.require_chat_key()?,
            new_id,
            channel_id,
            direction,
            now,
            message,
        )?;
        tx.execute(
            "UPDATE channel_messages SET message = ?1 WHERE id = ?2",
            params![encrypted, new_id],
        )?;
        // `now` here is the message's own timestamp, which a member chooses and
        // which catch-up delivers newest-first — so the *oldest* backfilled
        // line was processed last and won, sinking an active room to the bottom
        // of a list ordered by `last_active` right after a successful sync. One
        // member with a wrong clock could park it in 1970.
        tx.execute(
            "UPDATE channels SET last_active = MAX(last_active, ?2) WHERE channel_id = ?1",
            params![channel_id, now],
        )?;
        if direction == "sent" {
            // The slow-mode clock, stamped in the same transaction as the line
            // it belongs to and out of reach of `delete_channel_message`.
            // Monotonic so a handoff copy carrying an older timestamp cannot
            // rewind it into letting a message straight through.
            tx.execute(
                "UPDATE channels SET last_sent_at = MAX(last_sent_at, ?2) WHERE channel_id = ?1",
                params![channel_id, now],
            )?;
        }
        tx.execute(
            "DELETE FROM channel_messages WHERE id IN (
                 SELECT id FROM channel_messages
                 WHERE channel_id = ?1
                 ORDER BY id DESC
                 LIMIT -1 OFFSET ?2
             )",
            params![channel_id, MAX_MESSAGES_PER_CHANNEL],
        )?;
        // Reactions belong to a line, and nothing else deletes them — so without
        // this they outlive the history they annotate and grow without bound in a
        // busy room. Only swept when the prune above actually removed something,
        // because this runs on every insert.
        if tx.changes() > 0 {
            tx.execute(
                "DELETE FROM channel_message_reactions
                 WHERE channel_id = ?1 AND msg_id NOT IN (
                     SELECT msg_id FROM channel_messages WHERE channel_id = ?1
                 )",
                params![channel_id],
            )?;
        }
        tx.commit()?;
        Ok(new_id)
    }

    /// Substring match over a room's history, newest first.
    ///
    /// Cannot be a SQL `LIKE`: `encrypt_channel_message_body` binds each body
    /// to its own row id, room, direction and timestamp, so the stored column
    /// is ciphertext and every candidate has to be decrypted here. Bounded by
    /// the per-room retention cap above, and stops as soon as `limit` matches
    /// are found so the common case walks only the recent tail.
    pub fn search_channel_messages(
        &self,
        channel_id: &str,
        needle: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<ChannelMessageRow>> {
        let needle = needle.trim().to_lowercase();
        if needle.is_empty() || limit <= 0 {
            return Ok(Vec::new());
        }
        let rows: Vec<(i64, String, String, String, i64, bool, i64, String)> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare(
                "SELECT id, sender_pubkey, direction, message, timestamp, read, edited_at, msg_id
                 FROM channel_messages WHERE channel_id = ?1
                 ORDER BY id DESC",
            )?;
            let mapped = stmt.query_map(params![channel_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get::<_, i64>(5)? != 0,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };
        // No key means no plaintext to match against; report nothing rather
        // than a page of "unavailable" placeholders that all "match".
        let Some(chat_key) = self.chat_key.as_deref() else {
            return Ok(Vec::new());
        };
        let mut hits = Vec::new();
        for (id, sender, direction, stored, timestamp, read, edited_at, msg_id) in rows {
            if hits.len() as i64 >= limit {
                break;
            }
            let Ok(stored_text) = Self::decrypt_channel_message_body(
                chat_key, id, channel_id, &direction, timestamp, &stored,
            ) else {
                continue;
            };
            let message = crate::network::ember::channel::chat_display_text(&stored_text);
            if message.to_lowercase().contains(&needle) {
                hits.push(ChannelMessageRow {
                    id,
                    sender_pubkey: sender,
                    direction,
                    message: message.to_string(),
                    timestamp,
                    read,
                    edited_at,
                    msg_id,
                    // Search results are a jump target, not a transcript, so
                    // they carry no bubble status of their own — nor a quote.
                    delivery: CHAT_DELIVERED,
                    reply_to: None,
                    reply_parent: None,
                    reply_parent_deleted: false,
                });
            }
        }
        Ok(hits)
    }

    /// Longest parent excerpt a reply carries: more than any quote shows, so
    /// the UI cuts it rather than the backend, and small enough that a page of
    /// replies stays cheap to send.
    pub const REPLY_EXCERPT_CHARS: usize = 280;

    /// The line `parent_msg_id` names, as a reply's quote needs it.
    ///
    /// Read now rather than when the reply arrived, so a parent revised since
    /// is quoted as it reads today.
    fn channel_reply_lookup_locked(
        conn: &Connection,
        chat_key: Option<&[u8; 32]>,
        channel_id: &str,
        parent_msg_id: &str,
    ) -> anyhow::Result<ChannelReplyLookup> {
        let held: Option<(i64, String, String, String, i64)> = conn
            .query_row(
                "SELECT id, sender_pubkey, direction, message, timestamp
                 FROM channel_messages WHERE channel_id = ?1 AND msg_id = ?2",
                params![channel_id, parent_msg_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?;
        if let Some((id, sender_pubkey, direction, stored, timestamp)) = held {
            let excerpt = match chat_key.map(|key| {
                Self::decrypt_channel_message_body(key, id, channel_id, &direction, timestamp, &stored)
            }) {
                Some(Ok(text)) => crate::network::ember::channel::chat_display_text(&text)
                    .chars()
                    .take(Self::REPLY_EXCERPT_CHARS)
                    .collect(),
                _ => CHAT_UNAVAILABLE_TEXT.to_string(),
            };
            return Ok(ChannelReplyLookup {
                parent: Some(ChannelReplyParent {
                    id,
                    sender_pubkey,
                    excerpt,
                }),
                deleted: false,
            });
        }
        Ok(ChannelReplyLookup {
            parent: None,
            deleted: Self::channel_msg_tombstoned_locked(conn, channel_id, parent_msg_id)?,
        })
    }

    /// Whether `msg_id` has been deleted in this room, in either tombstone
    /// form: the bare id, or `id/sender` for a row that could not prove the id
    /// was its own (`channel_tombstone_key`).
    fn channel_msg_tombstoned_locked(
        conn: &Connection,
        channel_id: &str,
        msg_id: &str,
    ) -> anyhow::Result<bool> {
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM channel_message_tombstones
                 WHERE channel_id = ?1 AND (msg_id = ?2 OR substr(msg_id, 1, ?3) = ?4))",
            params![channel_id, msg_id, msg_id.len() as i64 + 1, format!("{msg_id}/")],
            |row| row.get(0),
        )?)
    }

    /// [`Self::channel_reply_lookup_locked`] for one parent, for a reply that
    /// has just been sent or received.
    pub fn channel_reply_lookup(
        &self,
        channel_id: &str,
        parent_msg_id: &str,
    ) -> anyhow::Result<ChannelReplyLookup> {
        let conn = self.conn.lock();
        Self::channel_reply_lookup_locked(
            &conn,
            self.chat_key.as_deref(),
            channel_id,
            parent_msg_id,
        )
    }

    /// Lines kept per room; older ones are pruned on insert.
    const CHANNEL_MESSAGES_PER_CHANNEL: i64 = 5_000;

    /// Tombstoned `msg_id`s kept per room.
    ///
    /// Bounded for the same reason history is: an unbounded local table is a
    /// slow leak. Past this the oldest deletions are forgotten, and a line that
    /// old is no longer being replayed by anyone.
    const CHANNEL_TOMBSTONES_PER_CHANNEL: i64 = 5_000;

    /// Whether this device has been told to forget `msg_id` as sent by
    /// `sender_pubkey`.
    ///
    /// The ingest dedup gate asks "do we hold this line", which a deletion
    /// answers no to, so without this the next replay puts it straight back.
    #[cfg(test)]
    pub fn channel_message_forgotten(
        &self,
        channel_id: &str,
        msg_id: &str,
        sender_pubkey: &str,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::channel_message_forgotten_locked(&conn, channel_id, msg_id, sender_pubkey)
    }

    /// Tombstone key for a deleted row.
    ///
    /// The bare id when the id binds the row's sender. Otherwise the row cannot
    /// show the id is its own — it may be a squatter on somebody else's line —
    /// so the tombstone names the sender too, or deleting the squatter would
    /// bury the genuine line that has yet to arrive. Kept in the existing
    /// `msg_id` column; `/` never occurs in an id.
    fn channel_tombstone_key(
        channel_id: &str,
        msg_id: &str,
        sender_pubkey: &str,
        timestamp: i64,
    ) -> String {
        if crate::network::ember::channel::chat_msg_id_binds_hex(
            channel_id,
            msg_id,
            sender_pubkey,
            timestamp,
        ) {
            msg_id.to_string()
        } else {
            format!("{msg_id}/{}", sender_pubkey.to_ascii_lowercase())
        }
    }

    fn channel_message_forgotten_locked(
        conn: &Connection,
        channel_id: &str,
        msg_id: &str,
        sender_pubkey: &str,
    ) -> anyhow::Result<bool> {
        let scoped = format!("{msg_id}/{}", sender_pubkey.to_ascii_lowercase());
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM channel_message_tombstones \
             WHERE channel_id = ?1 AND (msg_id = ?2 OR msg_id = ?3)",
            params![channel_id, msg_id, scoped],
            |row| row.get(0),
        )?;
        Ok(n > 0)
    }

    /// Forget one message on this device. Local only: the copy every other
    /// member holds is untouched, and nothing is gossiped.
    pub fn delete_channel_message(&self, channel_id: &str, id: i64) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        // Before the row goes, while its `msg_id` is still readable. Without the
        // tombstone the delete is undone by the next gossip replay or catch-up
        // that carries the line.
        let held: Option<(String, String, i64)> = tx
            .query_row(
                "SELECT msg_id, sender_pubkey, timestamp FROM channel_messages
                 WHERE channel_id = ?1 AND id = ?2",
                params![channel_id, id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((msg_id, sender, timestamp)) =
            held.filter(|(msg_id, _, _)| !msg_id.is_empty())
        {
            tx.execute(
                "INSERT OR IGNORE INTO channel_message_tombstones
                    (channel_id, msg_id, deleted_at)
                 VALUES (?1, ?2, ?3)",
                params![
                    channel_id,
                    Self::channel_tombstone_key(channel_id, &msg_id, &sender, timestamp),
                    chrono::Utc::now().timestamp()
                ],
            )?;
            tx.execute(
                "DELETE FROM channel_message_tombstones
                 WHERE channel_id = ?1 AND msg_id NOT IN (
                     SELECT msg_id FROM channel_message_tombstones
                     WHERE channel_id = ?1
                     ORDER BY deleted_at DESC, rowid DESC LIMIT ?2
                 )",
                params![channel_id, Self::CHANNEL_TOMBSTONES_PER_CHANNEL],
            )?;
        }
        // Ahead of the message, while its `msg_id` is still resolvable. Forgetting
        // a line on this device forgets what was voted on it too — leaving the
        // reactions behind would keep a count alive for a bubble that is gone.
        tx.execute(
            "DELETE FROM channel_message_reactions
             WHERE channel_id = ?1
               AND msg_id = (SELECT msg_id FROM channel_messages
                             WHERE channel_id = ?1 AND id = ?2)",
            params![channel_id, id],
        )?;
        let n = tx.execute(
            "DELETE FROM channel_messages WHERE channel_id = ?1 AND id = ?2",
            params![channel_id, id],
        )?;
        tx.commit()?;
        Ok(n > 0)
    }

    pub fn get_channel_messages(
        &self,
        channel_id: &str,
        limit: i64,
        before_id: Option<i64>,
    ) -> anyhow::Result<Vec<ChannelMessageRow>> {
        type PageRow = (i64, String, String, String, i64, bool, i64, String, i64, Option<String>);
        let (rows, parents) = {
            let conn = self.conn.lock();
            let read_row = |row: &rusqlite::Row<'_>| -> rusqlite::Result<PageRow> {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get::<_, i64>(5)? != 0,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            };
            let rows: Vec<PageRow> = if let Some(bid) = before_id {
                let mut stmt = conn.prepare(
                    "SELECT id, sender_pubkey, direction, message, timestamp, read, edited_at, msg_id, delivery, reply_to
                     FROM channel_messages WHERE channel_id = ?1 AND id < ?2
                     ORDER BY id DESC LIMIT ?3",
                )?;
                let mapped = stmt.query_map(params![channel_id, bid, limit], read_row)?;
                mapped.collect::<Result<Vec<_>, _>>()?
            } else {
                let mut stmt = conn.prepare(
                    "SELECT id, sender_pubkey, direction, message, timestamp, read, edited_at, msg_id, delivery, reply_to
                     FROM channel_messages WHERE channel_id = ?1
                     ORDER BY id DESC LIMIT ?2",
                )?;
                let mapped = stmt.query_map(params![channel_id, limit], read_row)?;
                mapped.collect::<Result<Vec<_>, _>>()?
            };
            // One lookup per distinct parent, under the same lock as the page,
            // so a quote and the page it sits in describe one moment. A page is
            // at most a couple of hundred rows and each lookup is a unique-index
            // seek.
            let mut parents: std::collections::HashMap<String, ChannelReplyLookup> =
                std::collections::HashMap::new();
            for (.., reply_to) in &rows {
                if let Some(parent) = reply_to {
                    if !parents.contains_key(parent) {
                        let lookup = Self::channel_reply_lookup_locked(
                            &conn,
                            self.chat_key.as_deref(),
                            channel_id,
                            parent,
                        )?;
                        parents.insert(parent.clone(), lookup);
                    }
                }
            }
            (rows, parents)
        };
        let reply_fields = |reply_to: Option<String>| {
            let lookup = reply_to
                .as_ref()
                .and_then(|parent| parents.get(parent))
                .cloned()
                .unwrap_or_default();
            (reply_to, lookup.parent, lookup.deleted)
        };
        let Some(chat_key) = self.chat_key.as_deref() else {
            return Ok(rows
                .into_iter()
                .map(
                    |(id, sender, direction, _, timestamp, read, edited_at, msg_id, delivery, reply_to)| {
                        let (reply_to, reply_parent, reply_parent_deleted) = reply_fields(reply_to);
                        ChannelMessageRow {
                            id,
                            sender_pubkey: sender,
                            direction,
                            message: CHAT_UNAVAILABLE_TEXT.to_string(),
                            timestamp,
                            read,
                            edited_at,
                            msg_id,
                            delivery,
                            reply_to,
                            reply_parent,
                            reply_parent_deleted,
                        }
                    },
                )
                .collect());
        };
        let mut messages = Vec::with_capacity(rows.len());
        for (id, sender, direction, stored, timestamp, read, edited_at, msg_id, delivery, reply_to) in
            rows
        {
            let message = match Self::decrypt_channel_message_body(
                chat_key, id, channel_id, &direction, timestamp, &stored,
            ) {
                // The body the member sees. The stored text keeps the signed
                // trailer for re-serving; `reply_to` already says what it held.
                Ok(message) => {
                    crate::network::ember::channel::chat_display_text(&message).to_string()
                }
                Err(error) => {
                    tracing::warn!("Channel message {id} in {channel_id} is unavailable: {error}");
                    CHAT_UNAVAILABLE_TEXT.to_string()
                }
            };
            let (reply_to, reply_parent, reply_parent_deleted) = reply_fields(reply_to);
            messages.push(ChannelMessageRow {
                id,
                sender_pubkey: sender,
                direction,
                message,
                timestamp,
                read,
                edited_at,
                msg_id,
                delivery,
                reply_to,
                reply_parent,
                reply_parent_deleted,
            });
        }
        Ok(messages)
    }

    pub fn mark_channel_messages_read(&self, channel_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE channel_messages SET read = 1 WHERE channel_id = ?1 AND read = 0",
            params![channel_id],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn channel_message_exists(&self, channel_id: &str, msg_id: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM channel_messages WHERE channel_id = ?1 AND msg_id = ?2",
            params![channel_id, msg_id],
            |row| row.get(0),
        )?;
        Ok(n > 0)
    }

    /// The ingest dedup gate for a verified chat line: whether we hold a row
    /// under its `msg_id` that it would *not* displace.
    ///
    /// Not [`Self::channel_message_exists`], because holding the id is not the
    /// same as holding the line. A row somebody else put there without proving
    /// the id is theirs must not be what turns the genuine line away as a repeat
    /// — see [`Self::channel_line_supersedes_locked`].
    #[cfg(test)]
    pub fn channel_message_held(
        &self,
        channel_id: &str,
        msg_id: &str,
        sender_pubkey: &str,
        timestamp: i64,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Ok(matches!(
            Self::channel_line_supersedes_locked(&conn, channel_id, msg_id, sender_pubkey, timestamp)?,
            Some((_, false))
        ))
    }

    /// Whether ingest should decline to store this line: a row we hold that
    /// it would not displace, or a tombstone telling us to forget it. Both
    /// questions under one lock, since ingest asks both of every line.
    pub fn channel_message_known(
        &self,
        channel_id: &str,
        msg_id: &str,
        sender_pubkey: &str,
        timestamp: i64,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        if matches!(
            Self::channel_line_supersedes_locked(&conn, channel_id, msg_id, sender_pubkey, timestamp)?,
            Some((_, false))
        ) {
            return Ok(true);
        }
        Self::channel_message_forgotten_locked(&conn, channel_id, msg_id, sender_pubkey)
    }

    /// The row held under `msg_id`, and whether a line signed by `sender_pubkey`
    /// at `timestamp` should replace it.
    ///
    /// `msg_id`s are chosen by whoever sends first, so the first row to land
    /// under one is not evidence it belongs there. A held row from somebody else
    /// gives way only when it cannot show the id is its author's and the
    /// incoming line can ([`crate::network::ember::channel::chat_msg_id_binds`]).
    /// Nothing weaker will do: an unbound row may be a genuine line or edit an
    /// older build stored, and letting any signed line displace it would hand
    /// it to whoever sent one first. From the same author, an edit-only row on
    /// an unbound id is re-judged against the original's real timestamp: the
    /// one the revision claimed was the author's word alone.
    ///
    /// Our own sent lines never give way.
    fn channel_line_supersedes_locked(
        conn: &Connection,
        channel_id: &str,
        msg_id: &str,
        sender_pubkey: &str,
        timestamp: i64,
    ) -> anyhow::Result<Option<(i64, bool)>> {
        use crate::network::ember::channel::{chat_msg_id_binds_hex, edit_within_window};
        let held: Option<(i64, String, String, String, String, i64, i64)> = conn
            .query_row(
                "SELECT id, sender_pubkey, direction, author_sig, edit_sig, timestamp, edited_at
                 FROM channel_messages WHERE channel_id = ?1 AND msg_id = ?2",
                params![channel_id, msg_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((id, held_sender, direction, author_sig, edit_sig, held_ts, edited_at)) = held
        else {
            return Ok(None);
        };
        if direction == "sent" {
            return Ok(Some((id, false)));
        }
        let held_bound = chat_msg_id_binds_hex(channel_id, msg_id, &held_sender, held_ts);
        let edit_only = author_sig.is_empty() && !edit_sig.is_empty();
        let supersedes = if held_sender.eq_ignore_ascii_case(sender_pubkey) {
            edit_only
                && !held_bound
                && (held_ts != timestamp
                    || !edit_within_window(timestamp, edited_at, 0, timestamp))
        } else {
            !held_bound && chat_msg_id_binds_hex(channel_id, msg_id, sender_pubkey, timestamp)
        };
        Ok(Some((id, supersedes)))
    }

    /// Decrypted messages for neighbor history catch-up.
    ///
    /// Ordered by [`channel_sync_serves_oldest_first`]: oldest-first above the
    /// requester's watermark so their gap walks forward, newest-first for a cold
    /// room that has no gap to walk.
    ///
    /// [`channel_sync_serves_oldest_first`]:
    ///     crate::network::ember::channel::channel_sync_serves_oldest_first
    ///
    /// Rows with no stored signature are skipped: a re-serve has to replay the
    /// author's own signature, and this node cannot produce one on their behalf.
    /// That is the point rather than a shortcoming — it is what stops a member
    /// answering a catch-up with a conversation nobody had.
    pub fn list_channel_messages_for_sync(
        &self,
        channel_id: &str,
        since_ts: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<ChannelSyncRow>> {
        let limit = limit.clamp(1, 64);
        let oldest_first =
            crate::network::ember::channel::channel_sync_serves_oldest_first(since_ts);
        let Some(chat_key) = self.chat_key.as_ref() else {
            return Ok(Vec::new());
        };
        let conn = self.conn.lock();
        {
            // A watermark is a timestamp, so a whole page sitting on the
            // watermark's own second is a page the requester cannot advance
            // past: it already holds that second, and the next round would ask
            // the same question and get the same rows back. Step over the second
            // instead. It costs the same-second lines the requester has not got
            // — the ones it is most likely to hold already, since its watermark
            // is that second — and it is what guarantees the walk terminates.
            let since_ts = if oldest_first {
                let saturated: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM channel_messages
                     WHERE channel_id = ?1 AND timestamp = ?2
                       AND (author_sig <> '' OR edit_sig <> '')",
                    params![channel_id, since_ts],
                    |row| row.get(0),
                )?;
                if saturated >= limit {
                    since_ts.saturating_add(1)
                } else {
                    since_ts
                }
            } else {
                since_ts
            };
            // Either signature makes a row re-servable: the author's over the
            // line as first sent, or theirs over the revision that replaced it. A
            // row carrying neither predates signed chat, or is a handoff copy
            // signed against a room that no longer exists, and cannot be proved
            // to anyone.
            let order = if oldest_first {
                "ORDER BY timestamp ASC, id ASC"
            } else {
                "ORDER BY timestamp DESC, id DESC"
            };
            let mut stmt = conn.prepare(&format!(
                "SELECT id, msg_id, sender_pubkey, direction, message, timestamp, author_sig,
                        edited_at, edit_sig
                 FROM channel_messages
                 WHERE channel_id = ?1 AND timestamp >= ?2
                   AND (author_sig <> '' OR edit_sig <> '')
                 {order}
                 LIMIT ?3 OFFSET ?4"
            ))?;
            // Rows are filtered below, after the LIMIT, so one page can come back
            // empty; an empty reply leaves the requester's watermark where it
            // was and it asks the same question forever. Keep reading until the
            // page fills or the room runs out — bounded by retention, so the
            // worst case is one pass over the room.
            let max_pages = Self::CHANNEL_MESSAGES_PER_CHANNEL / limit + 2;
            let mut out = Vec::with_capacity(limit as usize);
            for page in 0..max_pages {
                #[allow(clippy::type_complexity)]
                let rows: Vec<(i64, String, String, String, String, i64, String, i64, String)> =
                    stmt.query_map(
                        params![channel_id, since_ts, limit, page * limit],
                        |row| {
                            Ok((
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                                row.get(4)?,
                                row.get(5)?,
                                row.get(6)?,
                                row.get(7)?,
                                row.get(8)?,
                            ))
                        },
                    )?
                    .collect::<Result<Vec<_>, _>>()?;
                let exhausted = (rows.len() as i64) < limit;
                for (id, msg_id, sender, direction, stored, timestamp, author_sig, edited_at, edit_sig) in
                    rows
                {
                    if out.len() as i64 >= limit {
                        break;
                    }
                    // Without the author's signature over the line itself, only an
                    // id bound to them shows this row belongs under it. Anything
                    // else is a revision taken on trust — an older build stored
                    // those — and re-serving it would plant the same claim on
                    // every requester.
                    if author_sig.is_empty()
                        && !crate::network::ember::channel::chat_msg_id_binds_hex(
                            channel_id, &msg_id, &sender, timestamp,
                        )
                    {
                        continue;
                    }
                    if let Ok(message) = Self::decrypt_channel_message_body(
                        chat_key, id, channel_id, &direction, timestamp, &stored,
                    ) {
                        out.push(ChannelSyncRow {
                            msg_id,
                            sender_pubkey: sender,
                            message,
                            timestamp,
                            author_sig,
                            edited_at,
                            edit_sig,
                        });
                    }
                }
                if exhausted || out.len() as i64 >= limit {
                    break;
                }
            }
            Ok(out)
        }
    }

    /// The few fields deciding whether a local edit or reaction is allowed.
    ///
    /// Kept separate from [`Self::get_channel_messages`] so the command path does
    /// not decrypt and page a whole room to answer a question about one line.
    pub fn channel_message_edit_target(
        &self,
        channel_id: &str,
        id: i64,
    ) -> anyhow::Result<Option<ChannelEditTarget>> {
        let conn = self.conn.lock();
        let row = conn
            .query_row(
                "SELECT msg_id, sender_pubkey, direction, timestamp, first_seen_at, reply_to
                 FROM channel_messages WHERE channel_id = ?1 AND id = ?2",
                params![channel_id, id],
                |row| {
                    Ok(ChannelEditTarget {
                        msg_id: row.get(0)?,
                        sender_pubkey: row.get(1)?,
                        direction: row.get(2)?,
                        timestamp: row.get(3)?,
                        first_seen_at: row.get(4)?,
                        reply_to: row.get(5)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Apply an author's revision of one of their own lines.
    ///
    /// Every check that decides whether a revision is legitimate lives here
    /// rather than in the caller, so the network path and a catch-up cannot
    /// diverge on it:
    ///
    /// * the editor must be the key that authored the line — a signature proves
    ///   who asked, not that they were entitled to. For a line we do not hold
    ///   that means the id itself must bind the editor
    ///   ([`crate::network::ember::channel::chat_msg_id_binds`]); a revision of
    ///   an unbound id is refused rather than stored under the editor's name;
    /// * the window must still be open on both clocks
    ///   ([`crate::network::ember::channel::edit_within_window`]);
    /// * and a revision must be newer than the one we already applied, so a
    ///   frame that arrives late over a slower path cannot undo a newer one.
    ///
    /// The pre-edit text is overwritten, not archived. Editing out something you
    /// regret would be worth little if the first version stayed on every
    /// member's disk.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_channel_message_edit(
        &self,
        channel_id: &str,
        msg_id: &str,
        editor_pubkey: &str,
        original_timestamp: i64,
        edited_at: i64,
        text: &str,
        edit_sig: &str,
        now: i64,
    ) -> anyhow::Result<ChannelEditOutcome> {
        // A future-dated revision would win every later newer-wins comparison.
        if edited_at
            > now.saturating_add(crate::network::ember::channel::CHANNEL_GOSSIP_MAX_FUTURE_SKEW_SECS)
        {
            return Ok(ChannelEditOutcome::OutsideWindow);
        }
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let existing: Option<(i64, String, String, i64, i64, i64)> = tx
            .query_row(
                "SELECT id, sender_pubkey, direction, timestamp, edited_at, first_seen_at
                 FROM channel_messages WHERE channel_id = ?1 AND msg_id = ?2",
                params![channel_id, msg_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        use crate::network::ember::channel::chat_msg_id_binds_hex;
        let editor_owns_id =
            chat_msg_id_binds_hex(channel_id, msg_id, editor_pubkey, original_timestamp);
        // The held row cannot show the id is its sender's and the revision can,
        // so it was squatting on somebody else's line. Rolled back with the rest
        // of the transaction if the revision is refused below.
        let existing = match existing {
            Some((id, sender, direction, timestamp, ..))
                if editor_owns_id
                    && direction != "sent"
                    && !sender.eq_ignore_ascii_case(editor_pubkey)
                    && !chat_msg_id_binds_hex(channel_id, msg_id, &sender, timestamp) =>
            {
                tx.execute("DELETE FROM channel_messages WHERE id = ?1", params![id])?;
                None
            }
            other => other,
        };

        let (id, direction, row_timestamp, created) = match existing {
            Some((id, sender, direction, timestamp, prior_edit, first_seen_at)) => {
                if !sender.eq_ignore_ascii_case(editor_pubkey) {
                    return Ok(ChannelEditOutcome::NotAuthor);
                }
                if edited_at <= prior_edit {
                    return Ok(ChannelEditOutcome::NotNewer);
                }
                if !crate::network::ember::channel::edit_within_window(
                    timestamp,
                    edited_at,
                    first_seen_at,
                    now,
                ) {
                    return Ok(ChannelEditOutcome::OutsideWindow);
                }
                (id, direction, timestamp, false)
            }
            None => {
                // Absent because this device deleted it, not because it was
                // never here. Storing the revision would put the line back under
                // the very id the user asked to forget.
                if Self::channel_message_forgotten_locked(&tx, channel_id, msg_id, editor_pubkey)? {
                    return Ok(ChannelEditOutcome::Forgotten);
                }
                // Stored under the editor's name, so the editor has to be shown to
                // own the id: a signature proves who sent the revision, not whose
                // line it names. Refused rather than parked, because a revision
                // from the real author cannot be told apart from anyone else's
                // here, and the genuine line arriving later still lands.
                if !editor_owns_id {
                    return Ok(ChannelEditOutcome::NotAuthor);
                }
                // Catch-up: judged on the author's clock alone, because a line we
                // never held has no first-seen time to check against. The id binds
                // `original_timestamp`, so that clock cannot be re-dated. Stored as
                // `received`, since a revision only reaches us from elsewhere.
                //
                // The row takes `original_timestamp` as its own, so it is held to
                // the envelope rule too: a far-future row would sit above every
                // history-sync watermark.
                if !crate::network::ember::channel::gossip_timestamp_ok(original_timestamp, now)
                    || !crate::network::ember::channel::edit_within_window(
                        original_timestamp,
                        edited_at,
                        0,
                        now,
                    )
                {
                    return Ok(ChannelEditOutcome::OutsideWindow);
                }
                // The revision stands in for a line we never held, so its trailer
                // is the only word on what that line replied to. A revision of a
                // row we do hold leaves `reply_to` as the original set it.
                tx.execute(
                    "INSERT INTO channel_messages
                        (channel_id, sender_pubkey, direction, message, timestamp, read, msg_id, author_sig, first_seen_at, reply_to)
                     VALUES (?1, ?2, 'received', ?3, ?4, 0, ?5, '', ?6, ?7)",
                    params![
                        channel_id,
                        editor_pubkey,
                        CHAT_CIPHERTEXT_PREFIX,
                        original_timestamp,
                        msg_id,
                        now,
                        crate::network::ember::channel::chat_reply_parent_hex(text, msg_id)
                    ],
                )?;
                let id = tx.last_insert_rowid();
                (id, "received".to_string(), original_timestamp, true)
            }
        };

        let encrypted = Self::encrypt_channel_message_body(
            self.require_chat_key()?,
            id,
            channel_id,
            &direction,
            row_timestamp,
            text,
        )?;
        tx.execute(
            "UPDATE channel_messages SET message = ?1, edited_at = ?2, edit_sig = ?3 WHERE id = ?4",
            params![encrypted, edited_at, edit_sig, id],
        )?;
        tx.commit()?;
        Ok(if created {
            ChannelEditOutcome::Created(id)
        } else {
            ChannelEditOutcome::Applied(id)
        })
    }

    /// Record one member's reaction to one line, newest claim winning.
    ///
    /// Returns whether anything changed, so a caller can skip telling the UI
    /// about a frame that only repeated what we already had — reactions arrive
    /// several times over in a gossip mesh.
    ///
    /// Deliberately does not require the line to be present. A reaction can
    /// legitimately arrive before the message it points at (different paths,
    /// different hop counts), and dropping it would lose it for good; kept this
    /// way the count is simply right the moment the line lands.
    #[allow(clippy::too_many_arguments)]
    pub fn set_channel_message_reaction(
        &self,
        channel_id: &str,
        msg_id: &str,
        member_pubkey: &str,
        reaction: u8,
        reacted_at: i64,
        sig: &str,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let changed = tx.execute(
            "INSERT INTO channel_message_reactions
                 (channel_id, msg_id, member_pubkey, reaction, reacted_at, sig)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(channel_id, msg_id, member_pubkey) DO UPDATE SET
                 reaction = excluded.reaction,
                 reacted_at = excluded.reacted_at,
                 sig = excluded.sig
             WHERE channel_message_reactions.reacted_at < excluded.reacted_at",
            params![
                channel_id,
                msg_id,
                member_pubkey.to_ascii_lowercase(),
                reaction as i64,
                reacted_at,
                sig
            ],
        )?;
        // Accepting a reaction for a line we do not hold is what makes an early
        // one work, but it is also the one insert with no bound on it. A row
        // whose message never arrives is swept by nothing: the message prune and
        // the local delete both key off a line that exists, and only destroying
        // the whole room clears the rest. So a mesh that reacts to ids it never
        // publishes grows this table for as long as we stay in the room.
        //
        // Only checked when the target is genuinely absent, which is the rare
        // case — the sweep itself has to test every reaction in the room against
        // the message table, and that is not work to do on an ordinary reaction
        // to a line that is sitting right there.
        let target_present: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM channel_messages \
             WHERE channel_id = ?1 AND msg_id = ?2)",
            params![channel_id, msg_id],
            |row| row.get(0),
        )?;
        if !target_present {
            // Newest kept, oldest dropped: a reaction that has waited longest
            // for its line is the one least likely to ever be matched.
            tx.execute(
                "DELETE FROM channel_message_reactions
                 WHERE rowid IN (
                     SELECT r.rowid FROM channel_message_reactions r
                     WHERE r.channel_id = ?1
                       AND NOT EXISTS (
                           SELECT 1 FROM channel_messages m
                           WHERE m.channel_id = r.channel_id AND m.msg_id = r.msg_id
                       )
                     ORDER BY r.reacted_at DESC
                     LIMIT -1 OFFSET ?2
                 )",
                params![channel_id, Self::CHANNEL_ORPHAN_REACTIONS_PER_CHANNEL],
            )?;
        }
        tx.commit()?;
        Ok(changed > 0)
    }

    /// Reactions for lines this device does not hold, per room.
    ///
    /// Generous next to any real burst — a room sees one reaction per member per
    /// line — and small enough that a peer inventing ids cannot spend our disk.
    const CHANNEL_ORPHAN_REACTIONS_PER_CHANNEL: i64 = 256;

    /// Every live reaction in a room, keyed by the line it belongs to.
    ///
    /// `REACTION_NONE` rows are dropped here rather than deleted on receipt: a
    /// cleared reaction has to stay on disk to carry its `reacted_at`, or a stale
    /// frame reasserting the old one would win the newer-wins comparison against
    /// a missing row.
    ///
    /// Ordered by when each member reacted, which is the order the UI names
    /// them in; the key breaks ties so the same rows always read back the same.
    pub fn channel_message_reactions(
        &self,
        channel_id: &str,
    ) -> anyhow::Result<Vec<(String, String, u8)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT msg_id, member_pubkey, reaction FROM channel_message_reactions
             WHERE channel_id = ?1 AND reaction <> 0
             ORDER BY reacted_at, member_pubkey",
        )?;
        let mapped = stmt.query_map(params![channel_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? as u8,
            ))
        })?;
        Ok(mapped.collect::<Result<Vec<_>, _>>()?)
    }

    /// Reactions worth handing to a member catching up, newest first.
    ///
    /// Cleared reactions are included, unlike [`Self::channel_message_reactions`]:
    /// a member who missed both the reaction and its removal needs the removal
    /// too, or they would show a reaction its owner has taken back.
    /// Reactions on the exact lines a catch-up reply just served.
    ///
    /// Scoped to those ids, not to the requester's watermark. The watermark
    /// picks a window, but one reply only ever serves the oldest
    /// `CHANNEL_HISTORY_SYNC_MAX` lines inside it — so on a room with a real
    /// backlog the reactions went out for the *newest* messages, which the peer
    /// had not been given, while the lines it did get arrived bare. Nothing
    /// retried them either: the watermark advances with the messages, putting
    /// those reactions outside the next window as well.
    pub fn list_channel_reactions_for_sync(
        &self,
        channel_id: &str,
        msg_ids: &[String],
        limit: i64,
    ) -> anyhow::Result<Vec<(String, String, u8, i64, String)>> {
        if msg_ids.is_empty() {
            return Ok(Vec::new());
        }
        let limit = limit.clamp(1, 256);
        // One reply is capped at `CHANNEL_HISTORY_SYNC_MAX` lines, so this list
        // is short and needs no chunking.
        let placeholders: Vec<String> = (3..3 + msg_ids.len()).map(|i| format!("?{i}")).collect();
        let sql = format!(
            "SELECT msg_id, member_pubkey, reaction, reacted_at, sig
             FROM channel_message_reactions
             WHERE channel_id = ?1 AND sig <> '' AND msg_id IN ({})
             ORDER BY reacted_at DESC, msg_id, member_pubkey
             LIMIT ?2",
            placeholders.join(",")
        );
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(&sql)?;
        let mut bound: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(msg_ids.len() + 2);
        bound.push(&channel_id);
        bound.push(&limit);
        for id in msg_ids {
            bound.push(id as &dyn rusqlite::ToSql);
        }
        let mapped = stmt.query_map(bound.as_slice(), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? as u8,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        Ok(mapped.collect::<Result<Vec<_>, _>>()?)
    }

    /// The history-sync watermark. Rows dated past the gossip skew are left out:
    /// one of those as the maximum would put the watermark above everything
    /// still missing, and an older build could store one from a revision.
    pub fn latest_channel_message_timestamp(&self, channel_id: &str) -> anyhow::Result<i64> {
        let ceiling = chrono::Utc::now()
            .timestamp()
            .saturating_add(crate::network::ember::channel::CHANNEL_GOSSIP_MAX_FUTURE_SKEW_SECS);
        let conn = self.conn.lock();
        let ts: i64 = conn.query_row(
            "SELECT COALESCE(MAX(timestamp), 0) FROM channel_messages
             WHERE channel_id = ?1 AND timestamp <= ?2",
            params![channel_id, ceiling],
            |row| row.get(0),
        )?;
        Ok(ts)
    }

    /// Reclaim unused pages freed by DELETE operations.
    /// Should be called periodically (e.g. alongside credit flush).
    pub fn incremental_vacuum(&self) {
        let conn = self.conn.lock();
        let auto_vacuum: i64 = conn
            .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
            .unwrap_or(0);
        if auto_vacuum == 0 {
            // Should be impossible after v21, but keep the signal if a
            // future regression re-introduces the pragma-order bug.
            tracing::warn!(
                "incremental_vacuum skipped: auto_vacuum is NONE (expected INCREMENTAL)"
            );
            return;
        }
        if let Err(e) = conn.execute_batch("PRAGMA incremental_vacuum(64);") {
            tracing::debug!("incremental_vacuum failed: {e}");
        }
    }

    /// Record a completed or cancelled download in history.
    pub fn record_download_history(
        &self,
        file_hash: &str,
        file_name: &str,
        file_size: u64,
        status: &str,
    ) -> anyhow::Result<()> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        Self::record_download_history_in(&tx, file_hash, file_name, file_size, status)?;
        tx.commit()?;
        Ok(())
    }

    /// The history insert itself, so a caller that is already inside a
    /// transaction (see [`Database::complete_transfer`]) can include it rather
    /// than opening a second one.
    fn record_download_history_in(
        conn: &rusqlite::Connection,
        file_hash: &str,
        file_name: &str,
        file_size: u64,
        status: &str,
    ) -> anyhow::Result<()> {
        // Bound the stored file name (on a char boundary). Names originate
        // from peer-supplied metadata, so a hostile source could otherwise
        // persist an oversized string. eD2K names don't exceed ~255 bytes in
        // practice; 1 KiB is generous headroom.
        const MAX_HISTORY_NAME_LEN: usize = 1024;
        let file_name: &str = if file_name.len() > MAX_HISTORY_NAME_LEN {
            let mut end = MAX_HISTORY_NAME_LEN;
            while end > 0 && !file_name.is_char_boundary(end) {
                end -= 1;
            }
            &file_name[..end]
        } else {
            file_name
        };
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO download_history (file_hash, file_name, file_size, status, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(file_hash) DO UPDATE SET
               file_name = excluded.file_name,
               file_size = excluded.file_size,
               status = excluded.status,
               timestamp = excluded.timestamp",
            params![
                file_hash,
                file_name,
                i64::try_from(file_size).unwrap_or(i64::MAX),
                status,
                now
            ],
        )?;
        conn.execute(
            "DELETE FROM download_history WHERE file_hash IN (
                SELECT file_hash FROM download_history
                ORDER BY timestamp DESC
                LIMIT -1 OFFSET ?1
            )",
            params![MAX_DOWNLOAD_HISTORY_ROWS],
        )?;
        Ok(())
    }

    /// Look up download history for a batch of file hashes.
    /// Returns a map of hash → status ("completed" or "cancelled").
    pub fn get_download_history_batch(
        &self,
        hashes: &[String],
    ) -> anyhow::Result<std::collections::HashMap<String, String>> {
        if hashes.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let conn = self.conn.lock();
        let mut result = std::collections::HashMap::new();
        const CHUNK_SIZE: usize = 900;
        for chunk in hashes.chunks(CHUNK_SIZE) {
            let placeholders: Vec<String> = (1..=chunk.len()).map(|i| format!("?{i}")).collect();
            let sql = format!(
                "SELECT file_hash, status FROM download_history WHERE file_hash IN ({})",
                placeholders.join(",")
            );
            let mut stmt = conn.prepare(&sql)?;
            let params: Vec<&dyn rusqlite::ToSql> =
                chunk.iter().map(|h| h as &dyn rusqlite::ToSql).collect();
            let rows = stmt
                .query_map(params.as_slice(), |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .filter_map(|r| r.ok());
            for (hash, status) in rows {
                result.insert(hash, status);
            }
        }
        Ok(result)
    }

    /// Remove a specific file from download history (per-row user override).
    pub fn remove_download_history(&self, file_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM download_history WHERE file_hash = ?1",
            params![file_hash],
        )?;
        Ok(())
    }

    /// Clear all download history entries of a given status.
    pub fn clear_download_history(&self, status: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM download_history WHERE status = ?1",
            params![status],
        )?;
        Ok(())
    }

    /// Count download-history rows by status for the settings summary.
    pub fn get_download_history_counts(&self) -> anyhow::Result<(i64, i64)> {
        let conn = self.conn.lock();
        let completed: i64 = conn.query_row(
            "SELECT COUNT(*) FROM download_history WHERE status = 'completed'",
            [],
            |row| row.get(0),
        )?;
        let cancelled: i64 = conn.query_row(
            "SELECT COUNT(*) FROM download_history WHERE status = 'cancelled'",
            [],
            |row| row.get(0),
        )?;
        Ok((completed, cancelled))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `Database` backed by an in-memory SQLite connection plus
    /// just the `credits` table, so we can exercise the credit save /
    /// load round-trip without needing a `tauri::AppHandle`.
    fn credits_only_db() -> Database {
        let conn = Connection::open_in_memory().expect("open in-memory");
        conn.execute_batch(
            "CREATE TABLE credits (
                user_hash BLOB PRIMARY KEY,
                uploaded INTEGER NOT NULL DEFAULT 0,
                downloaded INTEGER NOT NULL DEFAULT 0,
                last_seen INTEGER NOT NULL DEFAULT 0,
                public_key BLOB NOT NULL DEFAULT x'',
                ident_ip INTEGER NOT NULL DEFAULT 0,
                ident_state INTEGER NOT NULL DEFAULT 0,
                ember_hash BLOB,
                crypto_verified_once INTEGER NOT NULL DEFAULT 0,
                peer_name TEXT NOT NULL DEFAULT '',
                client_software TEXT NOT NULL DEFAULT '',
                seen_ip INTEGER NOT NULL DEFAULT 0
            );",
        )
        .expect("create schema");
        Database {
            conn: Mutex::new(conn),
            path: std::path::PathBuf::from(":memory:"),
            chat_key: Some(Zeroizing::new([0xA5; 32])),
            corrupt_backup: None,
        }
    }

    /// Minimal schema for testing the defensive SQLite-to-memory conversion
    /// used by `load_ember_credits`.
    fn ember_credits_only_db() -> Database {
        let conn = Connection::open_in_memory().expect("open in-memory");
        conn.execute_batch(
            "CREATE TABLE ember_credits (
                pub_key BLOB PRIMARY KEY,
                uploaded INTEGER NOT NULL DEFAULT 0,
                downloaded INTEGER NOT NULL DEFAULT 0,
                last_upload_time INTEGER NOT NULL DEFAULT 0,
                last_download_time INTEGER NOT NULL DEFAULT 0,
                completed_sessions INTEGER NOT NULL DEFAULT 0,
                total_sessions INTEGER NOT NULL DEFAULT 0,
                avg_upload_speed INTEGER NOT NULL DEFAULT 0,
                last_seen INTEGER NOT NULL DEFAULT 0,
                ident_verified INTEGER NOT NULL DEFAULT 0
            );",
        )
        .expect("create schema");
        Database {
            conn: Mutex::new(conn),
            path: std::path::PathBuf::from(":memory:"),
            chat_key: Some(Zeroizing::new([0xA5; 32])),
            corrupt_backup: None,
        }
    }

    /// Build a `Database` with just the friends-related tables, enough to
    /// exercise blocking without a `tauri::AppHandle`.
    fn friends_only_db() -> Database {
        let conn = Connection::open_in_memory().expect("open in-memory");
        conn.execute_batch(
            "CREATE TABLE friends (
                user_hash TEXT PRIMARY KEY,
                nickname TEXT NOT NULL DEFAULT '',
                added_at INTEGER NOT NULL DEFAULT 0,
                last_ip TEXT DEFAULT '',
                last_port INTEGER DEFAULT 0,
                last_seen INTEGER DEFAULT 0,
                mutual INTEGER NOT NULL DEFAULT 0,
                ed25519_pubkey BLOB,
                room_asks INTEGER NOT NULL DEFAULT 0,
                room_asked_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE friend_requests (
                sender_hash TEXT PRIMARY KEY,
                sender_nickname TEXT NOT NULL DEFAULT '',
                received_at INTEGER NOT NULL DEFAULT 0,
                sender_ip TEXT DEFAULT '',
                sender_port INTEGER DEFAULT 0,
                verified INTEGER NOT NULL DEFAULT 0,
                sender_pubkey BLOB,
                via_room TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE friend_request_refusals (
                user_hash TEXT PRIMARY KEY,
                refused_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                friend_hash TEXT NOT NULL,
                direction TEXT NOT NULL DEFAULT 'sent',
                message TEXT NOT NULL,
                timestamp INTEGER NOT NULL DEFAULT 0,
                read INTEGER NOT NULL DEFAULT 0,
                delivery INTEGER NOT NULL DEFAULT 0,
                seen INTEGER NOT NULL DEFAULT 0,
                body_hash TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE friend_blocks (
                user_hash TEXT PRIMARY KEY,
                nickname TEXT NOT NULL DEFAULT '',
                blocked_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE friend_request_retractions (
                user_hash TEXT PRIMARY KEY,
                last_ip TEXT NOT NULL DEFAULT '',
                last_port INTEGER NOT NULL DEFAULT 0,
                queued_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE friend_request_declines (
                user_hash TEXT PRIMARY KEY,
                last_ip TEXT NOT NULL DEFAULT '',
                last_port INTEGER NOT NULL DEFAULT 0,
                queued_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE chat_attachments (
                xfer_id TEXT PRIMARY KEY,
                friend_hash TEXT NOT NULL,
                direction TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                root_hash TEXT NOT NULL,
                source_path TEXT,
                dest_path TEXT,
                status TEXT NOT NULL,
                transferred INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );",
        )
        .expect("create schema");
        Database {
            conn: Mutex::new(conn),
            path: std::path::PathBuf::from(":memory:"),
            chat_key: Some(Zeroizing::new([0xA5; 32])),
            corrupt_backup: None,
        }
    }

    fn row_count(db: &Database, sql: &str) -> i64 {
        db.conn
            .lock()
            .query_row(sql, [], |r| r.get(0))
            .expect("count")
    }

    #[test]
    fn load_ember_credits_clamps_corrupt_session_counters() {
        let db = ember_credits_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO ember_credits (
                    pub_key, uploaded, downloaded, last_upload_time, last_download_time,
                    completed_sessions, total_sessions, avg_upload_speed, last_seen, ident_verified
                ) VALUES (?1, 0, 0, 0, 0, ?2, ?3, 0, 0, 0)",
                params![vec![0xA5u8; 32], 5_000_000_000i64, -1i64],
            )
            .expect("insert corrupt counters");

        let records = db.load_ember_credits().expect("load credits");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].5, u32::MAX);
        assert_eq!(records[0].6, 0);
    }

    /// The point of a block is that it outlives the friendship it ended.
    /// Removal alone deletes the row and with it any record of the decision,
    /// which is what let a blocked peer re-request their way back in.
    #[test]
    fn blocking_ends_the_friendship_and_outlives_it() {
        let db = friends_only_db();
        {
            let conn = db.conn.lock();
            conn.execute(
                "INSERT INTO friends (user_hash, nickname, mutual) VALUES ('aa', 'Mallory', 1)",
                [],
            )
            .expect("seed friend");
            conn.execute(
                "INSERT INTO chat_messages (friend_hash, message) VALUES ('aa', 'hi')",
                [],
            )
            .expect("seed chat");
        }

        db.block_friend("aa").expect("block");

        assert_eq!(row_count(&db, "SELECT COUNT(*) FROM friends"), 0);
        assert_eq!(row_count(&db, "SELECT COUNT(*) FROM chat_messages"), 0);
        assert!(db.is_friend_blocked("aa").expect("lookup"));

        let blocked = db.get_blocked_friends().expect("list");
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].0, "aa");
        // Carried across from the deleted friend row: without it the user is
        // left staring at a bare hash with no way to tell who it was.
        assert_eq!(blocked[0].1, "Mallory");
    }

    /// A stranger can be blocked straight from the approval queue, before
    /// they were ever a friend, so the name has to come from the request.
    #[test]
    fn blocking_a_pending_requester_keeps_their_name() {
        let db = friends_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO friend_requests (sender_hash, sender_nickname) \
                 VALUES ('bb', 'Stranger')",
                [],
            )
            .expect("seed request");

        db.block_friend("bb").expect("block");

        assert_eq!(row_count(&db, "SELECT COUNT(*) FROM friend_requests"), 0);
        let blocked = db.get_blocked_friends().expect("list");
        assert_eq!(blocked[0].1, "Stranger");
    }

    /// Unblocking clears the block and nothing else. The friendship rows were
    /// deleted when it was applied, so the pair have to add each other again
    /// rather than silently resuming.
    #[test]
    fn unblocking_does_not_restore_the_friendship() {
        let db = friends_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO friends (user_hash, nickname) VALUES ('cc', 'Gone')",
                [],
            )
            .expect("seed friend");

        db.block_friend("cc").expect("block");
        db.unblock_friend("cc").expect("unblock");

        assert!(!db.is_friend_blocked("cc").expect("lookup"));
        assert!(db.get_blocked_friends().expect("list").is_empty());
        assert_eq!(row_count(&db, "SELECT COUNT(*) FROM friends"), 0);
    }

    /// A database whose chat key cannot be recovered must still be usable. It
    /// previously refused to open at all, so an unreadable key file took
    /// downloads, the library and every setting with it — and said so only in a
    /// log. History is sealed instead: rows read as unavailable, sends are
    /// refused, and the ciphertext is left intact so restoring the key recovers
    /// it.
    #[test]
    fn a_locked_chat_key_seals_history_instead_of_failing() {
        let conn = Connection::open_in_memory().expect("open in-memory");
        conn.execute_batch(
            "CREATE TABLE chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                friend_hash TEXT NOT NULL,
                direction TEXT NOT NULL DEFAULT 'sent',
                message TEXT NOT NULL,
                timestamp INTEGER NOT NULL DEFAULT 0,
                read INTEGER NOT NULL DEFAULT 0,
                delivery INTEGER NOT NULL DEFAULT 0,
                seen INTEGER NOT NULL DEFAULT 0,
                body_hash TEXT NOT NULL DEFAULT ''
            );",
        )
        .expect("create schema");
        let locked = Database {
            conn: Mutex::new(conn),
            path: std::path::PathBuf::from(":memory:"),
            chat_key: None,
            corrupt_backup: None,
        };
        assert!(locked.chat_locked());

        // Seed a row that only the real key could open.
        let ciphertext = format!("{CHAT_CIPHERTEXT_PREFIX}bm90LXJlYWxseS1jaXBoZXJ0ZXh0");
        locked
            .conn
            .lock()
            .execute(
                "INSERT INTO chat_messages (friend_hash, direction, message, timestamp) \
                 VALUES ('aa', 'received', ?1, 1)",
                params![ciphertext],
            )
            .expect("seed row");

        // Reads succeed, reporting the row as unavailable rather than erroring.
        let messages = locked.get_chat_messages("aa", 50, None).expect("read");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message, CHAT_UNAVAILABLE_TEXT);

        // Writes are refused, so nothing is stored under a key we do not have.
        assert!(locked.insert_chat_message("aa", "sent", "hello").is_err());

        // The queue reports nothing, and crucially does not abandon rows that a
        // restored key could still send.
        assert!(locked
            .pending_chat_messages("aa", 10)
            .expect("pending")
            .is_empty());

        // The ciphertext is untouched, so restoring the key recovers it.
        let stored: String = locked
            .conn
            .lock()
            .query_row("SELECT message FROM chat_messages", [], |r| r.get(0))
            .expect("read raw");
        assert_eq!(stored, ciphertext);

        // And the age sweep leaves queued sends alone while locked, or it would
        // abandon exactly the rows a restored key could still deliver.
        locked
            .conn
            .lock()
            .execute(
                "INSERT INTO chat_messages (friend_hash, direction, message, timestamp, delivery) \
                 VALUES ('aa', 'sent', 'x', ?1, ?2)",
                params![
                    chrono::Utc::now().timestamp() - CHAT_QUEUE_MAX_AGE_SECS - 60,
                    CHAT_QUEUED
                ],
            )
            .expect("seed stale queued");
        assert!(locked.expire_stale_queued_chat().expect("sweep").is_empty());
        assert_eq!(
            row_count(
                &locked,
                &format!("SELECT COUNT(*) FROM chat_messages WHERE delivery = {CHAT_QUEUED}")
            ),
            1,
            "a locked database must not abandon queued sends"
        );
    }

    /// Nothing used to assign `CHAT_FAILED`, so a message to a friend who never
    /// came back was queued forever, counted as unsent forever, and retried on
    /// every reconnect. The sweep has to be global: expiring only on flush left
    /// the conversation, the badge and the queue each holding a different view
    /// of the same row, because a flush runs per friend and only on reconnect.
    #[test]
    fn chat_queued_past_the_age_limit_is_given_up_on() {
        let db = friends_only_db();
        let now = chrono::Utc::now().timestamp();
        {
            let conn = db.conn.lock();
            // One well past the ceiling, one comfortably inside it.
            conn.execute(
                "INSERT INTO chat_messages (friend_hash, direction, message, timestamp, delivery) \
                 VALUES ('aa', 'sent', 'x', ?1, ?2)",
                params![now - CHAT_QUEUE_MAX_AGE_SECS - 60, CHAT_QUEUED],
            )
            .expect("seed stale");
            conn.execute(
                "INSERT INTO chat_messages (friend_hash, direction, message, timestamp, delivery) \
                 VALUES ('aa', 'sent', 'y', ?1, ?2)",
                params![now - 60, CHAT_QUEUED],
            )
            .expect("seed fresh");
        }

        // The abandoned rows come back so the caller can flip the live bubbles.
        let expired = db.expire_stale_queued_chat().expect("sweep");
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].1, "aa");

        // Both views agree afterwards: one row still queued, one abandoned.
        assert_eq!(
            row_count(
                &db,
                &format!("SELECT COUNT(*) FROM chat_messages WHERE delivery = {CHAT_QUEUED}")
            ),
            1
        );
        assert_eq!(
            row_count(
                &db,
                &format!("SELECT COUNT(*) FROM chat_messages WHERE delivery = {CHAT_FAILED}")
            ),
            1
        );
        let counts = db.pending_chat_counts().expect("counts");
        assert_eq!(counts, vec![("aa".to_string(), 1)]);

        // Idempotent: a second sweep finds nothing left to abandon.
        assert!(db
            .expire_stale_queued_chat()
            .expect("sweep again")
            .is_empty());
    }

    /// The check the network loop runs before queueing is only an early-out.
    /// Blocking commits from the UI thread, so it can land after that check
    /// and before the insert; the transaction has to refuse on its own.
    #[test]
    fn a_block_committed_mid_flight_still_stops_the_request() {
        let db = friends_only_db();
        db.block_friend("dd").expect("block");

        let queued = db
            .add_friend_request("dd", None, "Mallory", "1.2.3.4", 4662, true)
            .expect("insert");

        assert!(!queued, "blocked identity must not be queued");
        assert_eq!(row_count(&db, "SELECT COUNT(*) FROM friend_requests"), 0);
    }

    /// The request row may already be on screen when the block is applied, so
    /// the accept can arrive afterwards. Letting it through would write
    /// `mutual = 1` and hand back chat and browse under a live block.
    #[test]
    fn accepting_a_request_from_a_blocked_identity_is_refused() {
        let db = friends_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO friend_requests (sender_hash, sender_nickname) \
                 VALUES ('ee', 'Mallory')",
                [],
            )
            .expect("seed request");
        // Block without going through `block_friend`, which would delete the
        // row: this is the racing order, where the row outlives the block.
        db.conn
            .lock()
            .execute(
                "INSERT INTO friend_blocks (user_hash, nickname) VALUES ('ee', 'Mallory')",
                [],
            )
            .expect("seed block");

        assert!(db.accept_friend_request("ee").is_err());
        assert_eq!(row_count(&db, "SELECT COUNT(*) FROM friends"), 0);
    }

    /// The command checks before calling, so this covers the race: a block
    /// that commits in between must not leave the identity both listed as a
    /// friend and blocked.
    #[test]
    fn adding_a_blocked_identity_is_refused_by_the_transaction() {
        let db = friends_only_db();
        db.block_friend("11").expect("block");

        // `Ok(None)`, not an error: the caller has to tell a block from a
        // genuine save failure so it can name the reason the user must act on.
        assert!(
            db.add_friend("11", "Mallory", None)
                .expect("no db error")
                .is_none(),
            "a blocked identity must be refused, not written"
        );
        assert_eq!(row_count(&db, "SELECT COUNT(*) FROM friends"), 0);
        assert_eq!(
            db.add_friend("22", "Friend", None).expect("no db error"),
            Some(false),
            "an unblocked identity must still be added"
        );
    }

    /// Pasting a friend code after that peer already queued a request must
    /// consume the request and grant mutual — otherwise the UI shows a
    /// one-sided friend plus a leftover request, and rejecting the request
    /// leaves chat/browse locked.
    #[test]
    fn adding_a_friend_who_already_requested_becomes_mutual() {
        let db = friends_only_db();
        db.add_friend_request("aa", None, "Alice", "1.2.3.4", 4662, true)
            .expect("queue request");

        assert_eq!(
            db.add_friend("aa", "Ally", None).expect("add"),
            Some(true),
            "a pending request must promote the new friend to mutual"
        );
        assert_eq!(
            row_count(&db, "SELECT COUNT(*) FROM friend_requests"),
            0,
            "the request row must be consumed"
        );
        let friends = db.get_friends_full().expect("list");
        assert_eq!(friends.len(), 1);
        assert_eq!(friends[0].1, "Ally");
        assert_eq!(friends[0].3, "1.2.3.4");
        assert_eq!(friends[0].4, 4662);
        assert!(friends[0].6, "mutual flag");
    }

    #[test]
    fn adding_without_a_nickname_keeps_the_request_name() {
        let db = friends_only_db();
        db.add_friend_request("bb", None, "Bob", "5.6.7.8", 4662, false)
            .expect("queue request");
        assert_eq!(db.add_friend("bb", "", None).expect("add"), Some(true));
        let friends = db.get_friends_full().expect("list");
        assert_eq!(friends[0].1, "Bob");
    }

    #[test]
    fn friend_request_unverified_refresh_keeps_verified_contact_details() {
        let db = friends_only_db();
        db.add_friend_request("cc", None, "Carol", "1.2.3.4", 4662, true)
            .expect("verified request");
        db.add_friend_request("cc", None, "Mallory", "6.6.6.6", 6666, false)
            .expect("spoofed refresh");

        let requests = db.get_friend_requests().expect("list");
        assert_eq!(requests.len(), 1);
        let (_, nickname, _, ip, port, verified) = &requests[0];
        assert_eq!(nickname, "Carol");
        assert_eq!(ip, "1.2.3.4");
        assert_eq!(*port, 4662);
        assert!(*verified);

        db.add_friend_request("cc", None, "Carol2", "5.5.5.5", 4663, true)
            .expect("verified refresh");
        let requests = db.get_friend_requests().expect("list");
        let (_, nickname, _, ip, port, _) = &requests[0];
        assert_eq!(nickname, "Carol2");
        assert_eq!(ip, "5.5.5.5");
        assert_eq!(*port, 4663);
    }

    #[test]
    fn friend_request_unverified_refresh_updates_unverified_row() {
        let db = friends_only_db();
        db.add_friend_request("dd", None, "Dave", "1.2.3.4", 4662, false)
            .expect("first request");
        db.add_friend_request("dd", None, "Dave2", "5.6.7.8", 4663, false)
            .expect("refresh");
        let requests = db.get_friend_requests().expect("list");
        let (_, nickname, _, ip, port, verified) = &requests[0];
        assert_eq!(nickname, "Dave2");
        assert_eq!(ip, "5.6.7.8");
        assert_eq!(*port, 4663);
        assert!(!*verified);
    }

    /// Auto-confirm promotes a one-sided friend to mutual without prompting,
    /// which grants browse and friends-only serving. A block has to stop it
    /// even though the `friends` row is still there.
    #[test]
    fn promotion_to_mutual_skips_a_blocked_identity() {
        let db = friends_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO friends (user_hash, nickname, mutual) VALUES ('22', 'Mallory', 0)",
                [],
            )
            .expect("seed friend");
        db.conn
            .lock()
            .execute("INSERT INTO friend_blocks (user_hash) VALUES ('22')", [])
            .expect("seed block");

        let updated = db
            .set_friend_mutual("22", "1.2.3.4", 4662, None)
            .expect("promote");

        assert_eq!(updated, 0, "blocked identity must not be promoted");
        assert_eq!(
            row_count(&db, "SELECT COUNT(*) FROM friends WHERE mutual = 1"),
            0
        );
    }

    /// Auto-confirm used to leave the queued request in place, so the
    /// initiator still saw an Accept prompt after the friendship completed.
    #[test]
    fn promoting_a_friend_consumes_a_leftover_request() {
        let db = friends_only_db();
        db.add_friend("22", "Friend", None).expect("add");
        db.add_friend_request("22", None, "Friend", "1.2.3.4", 4662, true)
            .expect("queue leftover");

        let updated = db
            .set_friend_mutual("22", "1.2.3.4", 4662, None)
            .expect("promote");

        assert_eq!(updated, 1);
        assert_eq!(
            row_count(&db, "SELECT COUNT(*) FROM friend_requests"),
            0,
            "leftover request must be consumed"
        );
        assert_eq!(
            row_count(&db, "SELECT COUNT(*) FROM friends WHERE mutual = 1"),
            1
        );
    }

    /// Requests already queued by the old double-approval path must not
    /// reappear the next time the Friends page loads.
    #[test]
    fn listing_requests_drops_rows_from_people_already_added() {
        let db = friends_only_db();
        db.add_friend("22", "Friend", None).expect("add");
        db.add_friend_request("22", None, "Friend", "1.2.3.4", 4662, true)
            .expect("leftover");
        db.add_friend_request("aa", None, "Alice", "5.6.7.8", 4662, true)
            .expect("stranger");

        let rows = db.get_friend_requests().expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "aa");
        assert_eq!(
            row_count(&db, "SELECT COUNT(*) FROM friend_requests"),
            1,
            "known-friend leftover must be deleted, stranger kept"
        );
    }

    /// Cancelling used to be purely local, leaving the request on the
    /// recipient's screen. The address has to be captured here because the row
    /// holding it is deleted in the same transaction.
    #[test]
    fn removing_a_friend_who_never_accepted_queues_a_withdrawal() {
        let db = friends_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO friends (user_hash, nickname, last_ip, last_port, mutual) \
                 VALUES ('22', 'Pending', '1.2.3.4', 4662, 0)",
                [],
            )
            .expect("seed one-sided friend");

        assert!(db.remove_friend("22").expect("remove"), "a withdrawal is owed");
        let queued = db.pending_friend_request_retractions().expect("list");
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].0, "22");
        assert_eq!(
            (queued[0].1.as_str(), queued[0].2),
            ("1.2.3.4", 4662),
            "the address must survive the friend row it came from"
        );
    }

    /// The network task names a line by its wire identity, which is something
    /// every member of the room can choose. Letting that reach a received row
    /// would let anyone mark somebody else's history failed.
    #[test]
    fn a_delivery_verdict_only_ever_moves_our_own_sent_line() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-delivery-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let channel_id = "ab".repeat(16);
        let me = "cd".repeat(32);
        let them = "ef".repeat(32);
        db.insert_channel(&channel_id, &me, "Lobby", "public", true, None, None)
            .expect("insert channel");
        db.insert_channel_message(&channel_id, &me, "sent", "mine", "s1", 100, "", true)
            .expect("sent row");
        db.insert_channel_message(&channel_id, &them, "received", "theirs", "r1", 200, "", true)
            .expect("received row");

        assert!(db
            .set_channel_delivery(&channel_id, "s1", CHAT_FAILED)
            .expect("mark ours")
            .is_some());
        assert!(
            db.set_channel_delivery(&channel_id, "r1", CHAT_FAILED)
                .expect("mark theirs")
                .is_none(),
            "a received line is delivered by definition and must not be movable"
        );

        // Idempotent: the same verdict twice reports no second change, so the
        // tick cannot emit an event for a row that did not move.
        assert!(db
            .set_channel_delivery(&channel_id, "s1", CHAT_FAILED)
            .expect("same verdict")
            .is_none());

        let rows = db.get_channel_messages(&channel_id, 10, None).expect("read");
        let ours = rows.iter().find(|r| r.msg_id == "s1").expect("ours");
        let theirs = rows.iter().find(|r| r.msg_id == "r1").expect("theirs");
        assert_eq!(ours.delivery, CHAT_FAILED);
        assert_eq!(theirs.delivery, CHAT_DELIVERED);

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// The retry that settles a queued line lives in memory, so a restart
    /// leaves the row with nothing left to move it off "sending".
    #[test]
    fn a_restart_settles_room_lines_left_sending() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-restart-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let channel_id = "ab".repeat(16);
        let me = "cd".repeat(32);
        db.insert_channel(&channel_id, &me, "Lobby", "public", true, None, None)
            .expect("insert channel");
        db.insert_channel_message(&channel_id, &me, "sent", "mid-flight", "s1", 100, "", true)
            .expect("sent row");
        db.set_channel_delivery(&channel_id, "s1", CHAT_QUEUED)
            .expect("queue it");

        assert_eq!(
            db.fail_stale_queued_channel_messages(99).expect("this run's"),
            0,
            "a line written after the run started is its retry queue's to settle"
        );
        assert_eq!(db.fail_stale_queued_channel_messages(100).expect("sweep"), 1);
        let rows = db.get_channel_messages(&channel_id, 10, None).expect("read");
        assert_eq!(rows[0].delivery, CHAT_FAILED);
        // Idempotent, so the once-per-run guard is a cost saving rather than a
        // correctness requirement.
        assert_eq!(db.fail_stale_queued_channel_messages(100).expect("again"), 0);

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// The decline arrives as an identity and nothing else, so the row's own
    /// state is the only thing that can decide whether it is still refusable.
    /// If it could reach a mutual row, anyone could unfriend themselves from
    /// someone else's list by declining a request that no longer exists.
    #[test]
    fn a_decline_clears_a_pending_row_and_never_a_friendship() {
        let db = friends_only_db();
        db.conn
            .lock()
            .execute_batch(
                "INSERT INTO friends (user_hash, nickname, mutual) VALUES ('11', 'Pending', 0);
                 INSERT INTO friends (user_hash, nickname, mutual) VALUES ('22', 'Established', 1);",
            )
            .expect("seed");

        assert!(db.decline_friend_request("11").expect("decline pending"));
        assert_eq!(
            row_count(&db, "SELECT COUNT(*) FROM friends WHERE user_hash = '11'"),
            0
        );

        assert!(
            !db.decline_friend_request("22").expect("decline mutual"),
            "a mutual friendship must not be endable by a decline"
        );
        assert_eq!(
            row_count(&db, "SELECT COUNT(*) FROM friends WHERE user_hash = '22'"),
            1
        );

        // Nothing on file at all is the accepted-first case, and is not an error.
        assert!(!db.decline_friend_request("33").expect("decline unknown"));
    }

    /// The request row holds the only address we have for somebody who is not
    /// a friend, so rejecting has to copy it out in the same transaction that
    /// deletes it or the courier has nowhere to dial.
    #[test]
    fn rejecting_a_request_queues_the_decline_with_its_address() {
        let db = friends_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO friend_requests (sender_hash, sender_nickname, sender_ip, sender_port) \
                 VALUES ('44', 'Asker', '203.0.113.9', 4662)",
                [],
            )
            .expect("seed request");

        assert!(db.reject_and_queue_friend_decline("44").expect("reject"));
        assert_eq!(
            row_count(&db, "SELECT COUNT(*) FROM friend_requests WHERE sender_hash = '44'"),
            0,
            "the request is gone whether or not we can reach them"
        );
        let queued = db.pending_friend_request_declines().expect("list");
        assert_eq!(queued.len(), 1);
        assert_eq!((queued[0].1.as_str(), queued[0].2), ("203.0.113.9", 4662));
    }

    /// A request that arrived without a usable address is still rejected — the
    /// queue is about delivery, not about the decision — but queuing a dial to
    /// nowhere would hold a row until it expired for no possible gain.
    #[test]
    fn rejecting_an_addressless_request_still_removes_it() {
        let db = friends_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO friend_requests (sender_hash, sender_nickname) VALUES ('55', 'Ghost')",
                [],
            )
            .expect("seed request");

        assert!(!db.reject_and_queue_friend_decline("55").expect("reject"));
        assert_eq!(
            row_count(&db, "SELECT COUNT(*) FROM friend_requests WHERE sender_hash = '55'"),
            0
        );
        assert!(db.pending_friend_request_declines().expect("list").is_empty());
        // And a request that was never there is not an error either.
        assert!(!db.reject_and_queue_friend_decline("66").expect("reject none"));
    }

    /// A request that came through a room has no address but a proven key, and
    /// the rendezvous finds a sender like that, so its refusal is still owed.
    #[test]
    fn rejecting_a_keyed_request_without_an_address_still_owes_a_decline() {
        let db = friends_only_db();
        db.add_friend_request("99", Some(&[7u8; 32]), "Roomie", "", 0, true)
            .expect("seed request");
        assert!(db.reject_and_queue_friend_decline("99").expect("reject"));
        let queued = db.pending_friend_request_declines().expect("list");
        assert_eq!(queued.len(), 1);
        assert_eq!((queued[0].0.as_str(), queued[0].1.as_str(), queued[0].2), ("99", "", 0));

        // Unproven, the key is only a claim, and nothing is owed.
        db.add_friend_request("98", Some(&[8u8; 32]), "Claim", "", 0, false)
            .expect("seed unverified request");
        assert!(!db.reject_and_queue_friend_decline("98").expect("reject"));
        assert_eq!(db.pending_friend_request_declines().expect("list").len(), 1);
    }

    fn room_request(db: &Database, hash: &str, room: &str, now: i64) -> bool {
        db.add_room_friend_request(hash, &[3u8; 32], "Roomie", room, now, now)
            .expect("room request")
    }

    fn via_room_of(db: &Database, hash: &str) -> String {
        db.conn
            .lock()
            .query_row(
                "SELECT via_room FROM friend_requests WHERE sender_hash = ?1",
                params![hash],
                |row| row.get(0),
            )
            .expect("row")
    }

    /// Room requests can be minted by any key, so a full table takes one only
    /// at the expense of other room or unproven requests, never a session's
    /// verified one; a session's request makes room the other way.
    #[test]
    fn room_requests_never_displace_a_sessions_verified_one() {
        let db = friends_only_db();
        let now = 1_700_000_000;
        for i in 0..100 {
            db.add_friend_request(&format!("s{i:02}"), None, "Real", "1.2.3.4", 4662, true)
                .expect("session request");
        }
        let held = |hash: &str| {
            row_count(
                &db,
                &format!("SELECT COUNT(*) FROM friend_requests WHERE sender_hash = '{hash}'"),
            )
        };
        assert!(!room_request(&db, "r0", "room-a", now), "nothing it may displace");
        assert_eq!(row_count(&db, "SELECT COUNT(*) FROM friend_requests"), 100);
        assert_eq!(held("r0"), 0);

        db.conn
            .lock()
            .execute("DELETE FROM friend_requests WHERE sender_hash = 's00'", [])
            .unwrap();
        assert!(room_request(&db, "r1", "room-a", now));
        assert!(room_request(&db, "r2", "room-b", now), "another room request may go");
        assert_eq!(held("r1"), 0);
        assert!(db
            .add_friend_request("s00", None, "Real", "1.2.3.4", 4662, true)
            .expect("session request"));
        assert_eq!(
            row_count(&db, "SELECT COUNT(*) FROM friend_requests WHERE via_room != ''"),
            0,
            "a session's request makes room by displacing a room one"
        );
    }

    #[test]
    fn a_room_brings_only_its_hourly_share_of_new_requests() {
        let db = friends_only_db();
        let now = 1_700_000_000;
        for i in 0..ROOM_FRIEND_REQUESTS_PER_ROOM_HOUR {
            assert!(room_request(&db, &format!("a{i}"), "room-a", now));
        }
        assert!(!room_request(&db, "late", "room-a", now));
        assert!(room_request(&db, "a0", "room-a", now + 10), "a repeat only refreshes");
        assert!(room_request(&db, "b0", "room-b", now), "another room has its own share");
        assert!(room_request(&db, "late", "room-a", now + 3601), "and it comes back each hour");
    }

    /// A room request carries no address and only the room's name for them, so
    /// it leaves what a session's verified request recorded — and on top of an
    /// unproven one, it is what proved the row, so the row counts as a room's.
    #[test]
    fn a_room_request_keeps_what_a_session_proved() {
        let db = friends_only_db();
        let now = 1_700_000_000;
        db.add_friend_request("cc", Some(&[3u8; 32]), "Carol", "1.2.3.4", 4662, true)
            .expect("session request");
        assert!(room_request(&db, "cc", "room-a", now));
        let rows = db.get_friend_requests().expect("list");
        let (_, nick, _, ip, port, verified) = rows.iter().find(|r| r.0 == "cc").unwrap();
        assert_eq!(
            (nick.as_str(), ip.as_str(), *port, *verified),
            ("Carol", "1.2.3.4", 4662, true)
        );
        assert_eq!(via_room_of(&db, "cc"), "");

        db.add_friend_request("dd", None, "Dave?", "6.6.6.6", 6666, false)
            .expect("unproven request");
        assert!(room_request(&db, "dd", "room-a", now));
        let rows = db.get_friend_requests().expect("list");
        let (_, nick, _, ip, _, verified) = rows.iter().find(|r| r.0 == "dd").unwrap();
        assert_eq!((nick.as_str(), ip.as_str(), *verified), ("Roomie", "", true));
        assert_eq!(via_room_of(&db, "dd"), "room-a");
        db.add_friend_request("dd", None, "Dave?", "6.6.6.6", 6666, false)
            .expect("unproven again");
        assert_eq!(via_room_of(&db, "dd"), "room-a", "an unproven request cannot promote it");
        db.add_friend_request("dd", Some(&[3u8; 32]), "Dave", "5.6.7.8", 4662, true)
            .expect("verified session");
        assert_eq!(via_room_of(&db, "dd"), "", "a verified session does");
    }

    /// A refused sender's envelopes from before the refusal stay refused after
    /// the decline is delivered, for as long as a room would still accept
    /// them; one sent afterwards is a new question.
    #[test]
    fn a_refused_room_request_cannot_be_replayed_back() {
        let db = friends_only_db();
        let sent = chrono::Utc::now().timestamp();
        assert!(room_request(&db, "ee", "room-a", sent));
        assert!(db.reject_and_queue_friend_decline("ee").expect("reject"));
        assert!(!room_request(&db, "ee", "room-a", sent), "while the decline is owed");
        db.clear_friend_request_decline("ee").expect("delivered");
        assert!(!room_request(&db, "ee", "room-a", sent), "a replay after delivery");
        let later = sent + crate::network::ember::channel::CHANNEL_GOSSIP_MAX_FUTURE_SKEW_SECS + 10;
        assert!(db
            .add_room_friend_request("ee", &[3u8; 32], "Roomie", "room-a", later, later)
            .expect("new request"));

        db.add_friend("ff", "Listed", None).expect("add");
        assert!(!room_request(&db, "ff", "room-a", sent), "someone already on the list");
    }

    /// A second refusal is a new delivery with its own lifetime, not the tail
    /// end of the first one's.
    #[test]
    fn rejecting_again_restarts_the_decline_clock() {
        let db = friends_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO friend_request_declines (user_hash, last_ip, last_port, queued_at) \
                 VALUES ('88', '203.0.113.9', 4662, 0)",
                [],
            )
            .expect("seed decline");
        db.conn
            .lock()
            .execute(
                "INSERT INTO friend_requests (sender_hash, sender_nickname, sender_ip, sender_port) \
                 VALUES ('88', 'Persistent', '203.0.113.10', 4663)",
                [],
            )
            .expect("seed request");

        assert!(db.reject_and_queue_friend_decline("88").expect("reject"));
        assert_eq!(
            db.expire_stale_friend_request_declines().expect("expire"),
            0,
            "the fresh refusal must not inherit the old one's age"
        );
        let queued = db.pending_friend_request_declines().expect("list");
        assert_eq!((queued[0].1.as_str(), queued[0].2), ("203.0.113.10", 4663));
    }

    /// Adding somebody is the opposite answer to declining them, so an
    /// undelivered refusal must not survive it and contradict the request the
    /// add has just sent.
    #[test]
    fn adding_someone_countermands_an_undelivered_decline() {
        let db = friends_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO friend_request_declines (user_hash, last_ip, last_port, queued_at) \
                 VALUES ('77', '203.0.113.9', 4662, 0)",
                [],
            )
            .expect("seed decline");

        db.add_friend("77", "Reconsidered", None).expect("add");
        assert!(
            db.pending_friend_request_declines().expect("list").is_empty(),
            "the queued refusal must go when the user changes their mind"
        );
    }

    /// A mutual friend consumed their request when they accepted it, so there
    /// is nothing queued on their side to take back. Dialling them to withdraw
    /// a request that no longer exists would be pure noise.
    #[test]
    fn removing_a_mutual_friend_queues_no_withdrawal() {
        let db = friends_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO friends (user_hash, nickname, last_ip, last_port, mutual) \
                 VALUES ('33', 'Friend', '1.2.3.4', 4662, 1)",
                [],
            )
            .expect("seed mutual friend");

        assert!(!db.remove_friend("33").expect("remove"));
        assert!(db
            .pending_friend_request_retractions()
            .expect("list")
            .is_empty());
    }

    /// Adding them again countermands the withdrawal. Left queued, the courier
    /// would retract the request the new add just sent.
    #[test]
    fn re_adding_cancels_an_undelivered_withdrawal() {
        let db = friends_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO friends (user_hash, last_ip, last_port, mutual) \
                 VALUES ('44', '1.2.3.4', 4662, 0)",
                [],
            )
            .expect("seed");
        assert!(db.remove_friend("44").expect("remove"));

        db.add_friend("44", "Second Thoughts", None).expect("re-add");

        assert!(
            db.pending_friend_request_retractions()
                .expect("list")
                .is_empty(),
            "the queued withdrawal must not outlive the re-add"
        );
    }

    /// Blocking ends contact in both directions, so a queued withdrawal must
    /// stop dialling them.
    #[test]
    fn blocking_cancels_an_undelivered_withdrawal() {
        let db = friends_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO friends (user_hash, last_ip, last_port, mutual) \
                 VALUES ('55', '1.2.3.4', 4662, 0)",
                [],
            )
            .expect("seed");
        assert!(db.remove_friend("55").expect("remove"));

        db.block_friend("55").expect("block");

        assert!(db
            .pending_friend_request_retractions()
            .expect("list")
            .is_empty());
    }

    /// The queue is the last thing holding the address of someone the user
    /// removed, so it has to stop retrying eventually.
    #[test]
    fn an_undeliverable_withdrawal_is_given_up_on() {
        let db = friends_only_db();
        let stale = chrono::Utc::now().timestamp() - (RETRACTION_QUEUE_MAX_AGE_SECS + 60);
        db.conn
            .lock()
            .execute(
                "INSERT INTO friend_request_retractions (user_hash, last_ip, last_port, queued_at) \
                 VALUES ('66', '1.2.3.4', 4662, ?1)",
                params![stale],
            )
            .expect("seed stale");
        db.conn
            .lock()
            .execute(
                "INSERT INTO friend_request_retractions (user_hash, last_ip, last_port, queued_at) \
                 VALUES ('77', '5.6.7.8', 4662, ?1)",
                params![chrono::Utc::now().timestamp()],
            )
            .expect("seed fresh");

        assert_eq!(db.expire_stale_friend_request_retractions().expect("sweep"), 1);
        let left = db.pending_friend_request_retractions().expect("list");
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].0, "77", "only the over-age row goes");
    }

    /// Acting on a withdrawal may only ever clear a queued request. If it
    /// reached `friends` it would be a way to remove yourself from someone
    /// else's friend list, and an accept that arrived first would be undone.
    #[test]
    fn a_withdrawal_cannot_undo_a_friendship() {
        let db = friends_only_db();
        db.add_friend_request("88", None, "Alice", "1.2.3.4", 4662, true)
            .expect("queue request");
        db.accept_friend_request("88").expect("accept");

        // What the inbound withdrawal handler does, arriving too late.
        db.remove_friend_request("88").expect("withdraw");

        let friends = db.get_friends_full().expect("list");
        assert_eq!(friends.len(), 1, "the friendship must survive");
        assert!(friends[0].6, "and stay mutual");
    }

    /// Blocking twice must not erase the name. By the second call the friend
    /// and request rows are gone, so the lookup finds nothing — easy to hit
    /// when the first attempt persisted the block but reported an error and
    /// the user simply tried again.
    #[test]
    fn re_blocking_keeps_the_name_from_the_first_time() {
        let db = friends_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO friends (user_hash, nickname) VALUES ('ff', 'Mallory')",
                [],
            )
            .expect("seed friend");

        db.block_friend("ff").expect("first block");
        db.block_friend("ff").expect("second block");

        let blocked = db.get_blocked_friends().expect("list");
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].1, "Mallory");
    }

    /// Regression: `save_all_credits` MUST act as a full replacement so
    /// records pruned in memory by `CreditManager::cleanup_stale` are
    /// also dropped from the persisted table. Before this was a bare
    /// `INSERT OR REPLACE`, the database accumulated stale rows
    /// indefinitely — visible as a Known Clients tab that kept showing
    /// months-old peers across restarts even though the in-memory
    /// pruner was running on the periodic timer.
    #[test]
    fn save_all_credits_is_a_full_replacement() {
        let db = credits_only_db();
        let h1 = [0x01u8; 16];
        let h2 = [0x02u8; 16];
        let h3 = [0x03u8; 16];
        let pk: &[u8] = &[0xAA; 4];

        // Seed three records.
        db.save_all_credits(&[
            (&h1, 100, 200, 1_700_000_000, pk, 0, 0, None, false, "", "", 0),
            (&h2, 300, 400, 1_700_000_001, pk, 0x0102_0304, 1, None, true, "", "", 0),
            (&h3, 500, 600, 1_700_000_002, pk, 0, 0, None, false, "", "", 0),
        ])
        .expect("seed");
        let loaded = db.load_credits().expect("reload after seed");
        assert_eq!(loaded.len(), 3, "seed must persist three records");

        // Re-save with only one of the three. The other two represent
        // stale records the in-memory pruner has just dropped — they
        // must NOT survive in the database.
        db.save_all_credits(&[(&h2, 999, 888, 1_700_000_999, pk, 0x0102_0304, 1, None, true, "Nia", "eMule 0.60a", 0x0506_0708)])
            .expect("replace");
        let after = db.load_credits().expect("reload after replace");
        assert_eq!(after.len(), 1, "stale records must not persist");
        assert_eq!(after[0].0, h2);
        // And the surviving row must reflect the latest values, not a
        // mix of the original seed and the new save.
        assert_eq!(after[0].1, 999);
        assert_eq!(after[0].2, 888);
        assert_eq!(after[0].3, 1_700_000_999);
        // ident_ip / ident_state must round-trip so the Known Clients tab
        // keeps the peer's last IP + country flag across restarts.
        assert_eq!(after[0].5, 0x0102_0304, "ident_ip must persist");
        assert_eq!(after[0].6, 1, "ident_state must persist");
        // Same reasoning for the peer's name and client software: the Known
        // eD2K Peers tab is a lifetime view, so a row it draws almost never
        // has a live session to re-learn them from.
        assert_eq!(after[0].9, "Nia", "peer_name must persist");
        assert_eq!(
            after[0].10, "eMule 0.60a",
            "client_software must persist"
        );
        assert_eq!(after[0].11, 0x0506_0708, "seen_ip must persist");
    }

    /// Saving an empty slice must clear every existing row — the only
    /// way to "wipe credits" is to flush an empty `CreditManager`, and
    /// that has to actually empty the table.
    #[test]
    fn save_all_credits_with_empty_input_clears_table() {
        let db = credits_only_db();
        let h1 = [0x01u8; 16];
        db.save_all_credits(&[(&h1, 1, 1, 0, &[], 0, 0, None, false, "", "", 0)])
            .expect("seed");
        assert_eq!(db.load_credits().expect("reload").len(), 1);

        db.save_all_credits(&[]).expect("empty save");
        assert!(db.load_credits().expect("reload empty").is_empty());
    }

    /// Opened through the real migrations, so the `ON CONFLICT` targets are
    /// checked against the production schema rather than a test copy.
    fn migrated_credits_db(tag: &str) -> (Database, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "ember-credits-{tag}-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        (Database::open_at(&path).expect("open migrated db"), path)
    }

    fn remove_db_files(db: Database, path: &std::path::Path) {
        drop(db);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn save_credit_changes_upserts_touched_rows_and_deletes_evicted_ones() {
        let (db, path) = migrated_credits_db("changes");
        let (h1, h2, h3) = ([0x01u8; 16], [0x02u8; 16], [0x03u8; 16]);
        let (pk1, pk2) = ([0x11u8; 32], [0x12u8; 32]);
        let key: &[u8] = &[0xAA; 4];
        db.save_all_credits_with_ember(
            &[
                (&h1, 1, 1, 100, key, 0, 0, None, false, "", "", 0),
                (&h2, 2, 2, 200, key, 0, 0, None, false, "", "", 0),
            ],
            &[
                (&pk1, 1, 1, 0, 0, 0, 0, 0, 100, false),
                (&pk2, 2, 2, 0, 0, 0, 0, 0, 200, false),
            ],
        )
        .expect("seed");

        db.save_credit_changes(
            &[
                (&h1, 50, 60, 300, key, 7, 1, Some(&h3), true, "Nia", "eMule", 9),
                (&h3, 3, 3, 300, &[], 0, 0, None, false, "", "", 0),
            ],
            &[h2],
            &[(&pk1, 5, 6, 7, 8, 1, 2, 3, 300, true)],
            &[pk2],
        )
        .expect("incremental save");

        let mut credits = db.load_credits().expect("reload credits");
        credits.sort_by_key(|row| row.0);
        assert_eq!(credits.len(), 2, "the evicted row must be deleted");
        assert_eq!(
            credits[0],
            (h1, 50, 60, 300, key.to_vec(), 7, 1, Some(h3), true, "Nia".to_string(), "eMule".to_string(), 9),
            "an existing row must take every new column value"
        );
        assert_eq!(credits[1].0, h3, "a new record must be inserted");
        assert_eq!(
            db.load_ember_credits().expect("reload ember"),
            vec![(pk1, 5, 6, 7, 8, 1, 2, 3, 300, true)]
        );
        remove_db_files(db, &path);
    }

    /// The first-flush reconcile must end where a full replacement would,
    /// and on a table that already matches it must write nothing at all.
    #[test]
    fn sync_all_credits_writes_only_differences_and_drops_unknown_rows() {
        let (db, path) = migrated_credits_db("sync");
        let (h1, h2, h3) = ([0x01u8; 16], [0x02u8; 16], [0x03u8; 16]);
        let (pk1, pk2) = ([0x11u8; 32], [0x12u8; 32]);
        let key: &[u8] = &[0xAA; 4];
        db.save_all_credits_with_ember(
            &[
                (&h1, 1, 1, 100, key, 0, 0, None, false, "a", "b", 0),
                (&h2, 2, 2, 200, key, 0, 0, None, false, "", "", 0),
            ],
            &[
                (&pk1, 1, 1, 0, 0, 0, 0, 0, 100, false),
                (&pk2, 2, 2, 0, 0, 0, 0, 0, 200, false),
            ],
        )
        .expect("seed");
        db.conn
            .lock()
            .execute(
                "INSERT INTO credits (user_hash) VALUES (?1)",
                params![vec![0x09u8; 17]],
            )
            .expect("malformed row");

        let snapshot: [CreditRowRef<'_>; 2] = [
            (&h1, 1, 1, 100, key, 0, 0, None, false, "a", "b", 0),
            (&h3, 3, 3, 300, key, 0, 0, None, false, "", "", 0),
        ];
        let ember_snapshot: [EmberCreditRowRef<'_>; 1] = [(&pk1, 9, 9, 0, 0, 0, 0, 0, 100, true)];
        db.sync_all_credits_with_ember(&snapshot, &ember_snapshot)
            .expect("sync");

        let raw_rows: i64 = db
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM credits", [], |r| r.get(0))
            .unwrap();
        assert_eq!(raw_rows, 2, "rows absent from the snapshot, malformed ones included, must go");
        let mut credits = db.load_credits().expect("reload");
        credits.sort_by_key(|row| row.0);
        assert_eq!(credits.iter().map(|r| r.0).collect::<Vec<_>>(), vec![h1, h3]);
        assert_eq!(
            db.load_ember_credits().expect("reload ember"),
            vec![(pk1, 9, 9, 0, 0, 0, 0, 0, 100, true)]
        );

        db.conn
            .lock()
            .execute_batch(
                "CREATE TEMP TABLE credit_writes (n INTEGER);
                 CREATE TEMP TRIGGER cw_ins AFTER INSERT ON main.credits BEGIN INSERT INTO credit_writes VALUES (1); END;
                 CREATE TEMP TRIGGER cw_upd AFTER UPDATE ON main.credits BEGIN INSERT INTO credit_writes VALUES (1); END;
                 CREATE TEMP TRIGGER cw_del AFTER DELETE ON main.credits BEGIN INSERT INTO credit_writes VALUES (1); END;
                 CREATE TEMP TRIGGER ew_ins AFTER INSERT ON main.ember_credits BEGIN INSERT INTO credit_writes VALUES (1); END;
                 CREATE TEMP TRIGGER ew_upd AFTER UPDATE ON main.ember_credits BEGIN INSERT INTO credit_writes VALUES (1); END;
                 CREATE TEMP TRIGGER ew_del AFTER DELETE ON main.ember_credits BEGIN INSERT INTO credit_writes VALUES (1); END;",
            )
            .expect("write counters");
        db.sync_all_credits_with_ember(&snapshot, &ember_snapshot)
            .expect("second sync");
        let writes: i64 = db
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM credit_writes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(writes, 0, "a table that already matches must not be rewritten");
        remove_db_files(db, &path);
    }

    /// The batched status write keeps the per-transfer sequence rule: a row
    /// whose sequence is older than one already applied is skipped, the rest
    /// land, and a later entry for the same id wins.
    #[test]
    fn batched_status_writes_skip_stale_sequences_per_transfer() {
        let (db, path) = migrated_credits_db("status-batch");
        let nonce = rand::random::<u64>();
        let (a, b) = (format!("batch-a-{nonce}"), format!("batch-b-{nonce}"));
        for id in [&a, &b] {
            db.conn
                .lock()
                .execute(
                    "INSERT INTO transfers (
                        id, file_name, file_hash, peer_id, peer_name, direction, status,
                        progress, speed, total_size, transferred, started_at, priority, category
                     ) VALUES (?1, 'f.bin', ?2, '', '', 'download', 'active', 0, 0, 4, 0, 1, 'normal', '')",
                    params![id, "11".repeat(16)],
                )
                .expect("seed transfer");
        }
        let status_of = |id: &str| -> String {
            db.conn
                .lock()
                .query_row("SELECT status FROM transfers WHERE id = ?1", params![id], |r| r.get(0))
                .expect("status")
        };

        let clock = crate::network::transfer_status_write_clock();
        let older = clock.next_seq();
        let newer = clock.next_seq();
        crate::network::apply_transfer_status_write(clock, &db, &a, "paused", newer);
        clock.apply_status_writes(
            &db,
            &[
                (a.clone(), "active".to_string(), older),
                (b.clone(), "queued".to_string(), clock.next_seq()),
                (b.clone(), "paused".to_string(), clock.next_seq()),
            ],
        );
        assert_eq!(status_of(&a), "paused", "an older sequence must not overwrite a newer write");
        assert_eq!(status_of(&b), "paused", "the later entry for the same transfer wins");

        clock.forget(&a);
        clock.forget(&b);
        remove_db_files(db, &path);
    }

    /// The "has ever been cryptographically verified" anchor must survive the
    /// database round-trip. It gates the anti-credit-theft reset, and the DB is
    /// the primary credit store, so an anchor that did not persist would let
    /// every peer's accumulated totals be reset on their first verification
    /// after any restart.
    #[test]
    fn crypto_verified_anchor_round_trips() {
        let db = credits_only_db();
        let anchored = [0x11u8; 16];
        let fresh = [0x22u8; 16];
        let pk: &[u8] = &[0xAA; 4];

        db.save_all_credits(&[
            (&anchored, 10, 20, 1_700_000_000, pk, 0, 1, None, true, "", "", 0),
            // Persisted `Failed` (2) with no anchor: exactly the state a
            // stranger can force by failing one challenge under this hash.
            (&fresh, 30, 40, 1_700_000_001, pk, 0, 2, None, false, "", "", 0),
        ])
        .expect("seed");

        let loaded = db.load_credits().expect("reload");
        let anchor_of = |hash: [u8; 16]| {
            loaded
                .iter()
                .find(|row| row.0 == hash)
                .map(|row| row.8)
                .expect("row present")
        };
        assert!(anchor_of(anchored), "a verified anchor must persist");
        assert!(
            !anchor_of(fresh),
            "an unanchored record must not gain an anchor from its ident_state"
        );
    }

    /// In-memory `Database` with just the `banned_ips` table for
    /// exercising the auto-ban persistence round-trip.
    fn banned_ips_db() -> Database {
        let conn = Connection::open_in_memory().expect("open in-memory");
        conn.execute_batch(
            "CREATE TABLE banned_ips (
                ip TEXT PRIMARY KEY,
                reason TEXT NOT NULL DEFAULT '',
                banned_at INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER NOT NULL DEFAULT 0
            );",
        )
        .expect("create schema");
        Database {
            conn: Mutex::new(conn),
            path: std::path::PathBuf::from(":memory:"),
            chat_key: Some(Zeroizing::new([0xA5; 32])),
            corrupt_backup: None,
        }
    }

    #[test]
    fn banned_ip_roundtrip_and_unban() {
        let db = banned_ips_db();
        let ip: std::net::Ipv4Addr = "203.0.113.7".parse().unwrap();
        db.ban_ip(ip, "test", 0).expect("ban");
        assert_eq!(db.get_banned_ips().expect("load"), vec![ip]);
        db.unban_ip(ip).expect("unban");
        assert!(db.get_banned_ips().expect("load after unban").is_empty());
    }

    #[test]
    fn expired_bans_are_pruned_on_load() {
        let db = banned_ips_db();
        let live: std::net::Ipv4Addr = "203.0.113.1".parse().unwrap();
        let expired: std::net::Ipv4Addr = "203.0.113.2".parse().unwrap();
        let permanent: std::net::Ipv4Addr = "203.0.113.3".parse().unwrap();
        db.ban_ip(live, "live", u64::MAX).expect("ban live");
        db.ban_ip(expired, "expired", 1).expect("ban expired"); // expired far in the past
        db.ban_ip(permanent, "permanent", 0).expect("ban permanent");
        let mut loaded = db.get_banned_ips().expect("load");
        loaded.sort();
        assert_eq!(loaded, vec![live, permanent], "expired ban must be pruned");
    }

    #[test]
    fn malformed_ban_row_fails_closed() {
        let db = banned_ips_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO banned_ips (ip, reason, banned_at, expires_at) VALUES ('not-an-ip', '', 0, 0)",
                [],
            )
            .unwrap();
        assert!(db.get_banned_ips().is_err());
        assert!(db.validate_security_policy().is_err());
    }

    #[test]
    fn expected_aich_survives_transfer_restart_load() {
        let path = std::env::temp_dir().join(format!(
            "ember-aich-transfer-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let db = Database::open_at(&path).unwrap();
        let expected = "ab".repeat(20);
        db.conn
            .lock()
            .execute(
                "INSERT INTO transfers (
                    id, file_name, file_hash, peer_id, peer_name, direction, status,
                    progress, speed, total_size, transferred, started_at, priority,
                    category, expected_aich
                 ) VALUES (?1, ?2, ?3, '', '', 'download', 'paused', 0, 0, 4, 0, 1, 'normal', '', ?4)",
                params!["transfer-aich", "file.bin", "11".repeat(16), expected],
            )
            .unwrap();
        let loaded = db.get_incomplete_downloads().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].expected_aich.as_deref(),
            Some("abababababababababababababababababababab")
        );
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn corrupt_expected_aich_restores_as_failed_without_pin() {
        let path = std::env::temp_dir().join(format!(
            "ember-aich-corrupt-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let db = Database::open_at(&path).unwrap();
        {
            let conn = db.conn.lock();
            for (id, value) in [
                ("transfer-empty-aich", ""),
                ("transfer-space-aich", "   "),
                ("transfer-bad-aich", "not-a-valid-aich"),
            ] {
                conn.execute(
                    "INSERT INTO transfers (
                        id, file_name, file_hash, peer_id, peer_name, direction, status,
                        progress, speed, total_size, transferred, started_at, priority,
                        category, expected_aich
                     ) VALUES (?1, ?2, ?3, '', '', 'download', 'paused', 0, 0, 4, 0, 1, 'normal', '', ?4)",
                    params![id, "file.bin", "11".repeat(16), value],
                )
                .unwrap();
            }
        }
        let loaded = db.get_incomplete_downloads().unwrap();
        assert_eq!(loaded.len(), 3);
        for transfer in loaded {
            assert!(transfer.expected_aich.is_none());
            assert_eq!(transfer.status, TransferStatus::Failed);
            assert!(transfer
                .failure_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("AICH")));
        }
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn ember_file_hash_survives_transfer_restart_load() {
        let path = std::env::temp_dir().join(format!(
            "ember-digest-transfer-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let db = Database::open_at(&path).unwrap();
        let expected = "cd".repeat(32);
        db.conn
            .lock()
            .execute(
                "INSERT INTO transfers (
                    id, file_name, file_hash, peer_id, peer_name, direction, status,
                    progress, speed, total_size, transferred, started_at, priority,
                    category, expected_aich, ember_file_hash
                 ) VALUES (?1, ?2, ?3, '', '', 'download', 'paused', 0, 0, 4, 0, 1, 'normal', '', NULL, ?4)",
                params!["transfer-ember", "file.bin", "11".repeat(16), expected],
            )
            .unwrap();
        let loaded = db.get_incomplete_downloads().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].ember_file_hash.as_deref(),
            Some(expected.as_str())
        );
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn transfer_friends_only_survives_restart_and_stale_saves() {
        let path = std::env::temp_dir().join(format!(
            "ember-friends-only-transfer-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let db = Database::open_at(&path).unwrap();
        db.conn
            .lock()
            .execute(
                "INSERT INTO transfers (
                    id, file_name, file_hash, peer_id, peer_name, direction, status,
                    progress, speed, total_size, transferred, started_at, priority,
                    category, expected_aich, ember_file_hash
                 ) VALUES (?1, 'file.bin', ?2, '', '', 'download', 'paused', 0, 0, 4, 0, 1, 'normal', '', NULL, NULL)",
                params!["transfer-restricted", "22".repeat(16)],
            )
            .unwrap();
        let loaded = db.get_incomplete_downloads().unwrap();
        assert!(!loaded[0].friends_only, "rows from before the column read as unrestricted");

        db.mark_transfer_friends_only("transfer-restricted").unwrap();
        let mut restricted = db.get_incomplete_downloads().unwrap().remove(0);
        assert!(restricted.friends_only);

        // A snapshot taken before the flag was set must not clear it.
        restricted.friends_only = false;
        db.save_transfer(&restricted).unwrap();
        assert!(db.get_incomplete_downloads().unwrap()[0].friends_only);

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn pending_restore_is_paginated_and_overflow_is_quarantined_without_deletion() {
        let path = std::env::temp_dir().join(format!(
            "ember-pending-budget-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let db = Database::open_at(&path).unwrap();
        {
            let conn = db.conn.lock();
            for (id, started_at) in [("oldest", 1i64), ("middle", 2), ("newest", 3)] {
                conn.execute(
                    "INSERT INTO transfers (
                        id, file_name, file_hash, peer_id, peer_name, direction, status,
                        progress, speed, total_size, transferred, started_at, priority,
                        category, expected_aich
                     ) VALUES (?1, ?2, ?3, '', '', 'download', 'paused', 0, 0, 10, 0, ?4, 'normal', '', NULL)",
                    params![id, format!("{id}.bin"), "11".repeat(16), started_at],
                )
                .unwrap();
            }
        }

        assert_eq!(db.quarantine_excess_pending_downloads(2, 20).unwrap(), 1);
        let first = db.get_incomplete_downloads_page(1, 0).unwrap();
        let second = db.get_incomplete_downloads_page(1, 1).unwrap();
        assert_eq!(first[0].id, "oldest");
        assert_eq!(second[0].id, "middle");
        assert!(db.get_incomplete_downloads_page(1, 2).unwrap().is_empty());
        assert!(
            db.incomplete_downloads_owning_partials()
                .unwrap()
                .contains("newest"),
            "quarantined rows must keep ownership of user .part data"
        );

        let total_rows: i64 = db
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM transfers", [], |row| row.get(0))
            .unwrap();
        assert_eq!(total_rows, 3, "migration must not delete user rows");
        assert_eq!(db.acknowledge_pending_download_overflow().unwrap(), 1);
        assert_eq!(db.acknowledge_pending_download_overflow().unwrap(), 0);

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// Re-banning never shortens a permanent ban into a finite one, and
    /// extends a finite ban to the later expiry.
    #[test]
    fn reban_expiry_merge_rules() {
        let db = banned_ips_db();
        let ip: std::net::Ipv4Addr = "203.0.113.9".parse().unwrap();
        db.ban_ip(ip, "perm", 0).expect("perm");
        db.ban_ip(ip, "finite", 100).expect("finite");
        // Still permanent (present despite the finite re-ban being in the past).
        assert_eq!(db.get_banned_ips().expect("load"), vec![ip]);
    }

    #[test]
    fn fresh_database_uses_incremental_auto_vacuum() {
        let path = std::env::temp_dir().join(format!(
            "ember-av-fresh-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open fresh db");
        let auto_vacuum: i64 = db
            .conn
            .lock()
            .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
            .expect("auto_vacuum");
        assert_eq!(
            auto_vacuum, 2,
            "INCREMENTAL auto_vacuum expected on fresh DB"
        );
        let version: i64 = db
            .conn
            .lock()
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |r| r.get(0),
            )
            .expect("version");
        assert_eq!(version, MAX_SUPPORTED_SCHEMA_VERSION);
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn friend_intro_secret_is_stored_and_listed_per_friend() {
        let path = std::env::temp_dir().join(format!(
            "ember-friend-intro-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let hash = "0123456789abcdef0123456789abcdef";
        let secret = [0x5Cu8; crate::network::ember::crypto::INTRO_SECRET_LEN];

        assert!(!db.set_friend_intro_secret(hash, &secret).expect("no row"));
        db.add_friend(hash, "Code", None).expect("add");
        db.add_friend("fedcba9876543210fedcba9876543210", "Legacy", None)
            .expect("add legacy");
        assert!(db.set_friend_intro_secret(hash, &secret).expect("set"));

        let listed = db.get_friend_intro_secrets().expect("list");
        let mut expected_hash = [0u8; 16];
        hex::decode_to_slice(hash, &mut expected_hash).unwrap();
        assert_eq!(listed, vec![(expected_hash, secret)]);

        db.remove_friend(hash).expect("remove");
        assert!(db.get_friend_intro_secrets().expect("list").is_empty());
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    /// A friend with no usable key is hash-only until one is stored; the
    /// intro secret goes only once the friend is both mutual and keyed.
    #[test]
    fn hash_only_friends_are_backfilled_and_redundant_secrets_cleared() {
        let path = std::env::temp_dir().join(format!(
            "ember-friend-backfill-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let key = crate::network::ember::crypto::signing_key_from_bytes(&[5u8; 32])
            .verifying_key()
            .to_bytes();
        let hash = crate::network::ember::crypto::node_id_from_ed25519_bytes(&key).unwrap();
        let hash_hex = hex::encode(hash);
        let other = crate::network::ember::crypto::signing_key_from_bytes(&[6u8; 32])
            .verifying_key()
            .to_bytes();
        let secret = [0x5Cu8; crate::network::ember::crypto::INTRO_SECRET_LEN];

        db.add_friend(&hash_hex, "HashOnly", None).expect("add");
        // A key that does not bind to the hash leaves the row hash-only.
        db.set_friend_public_key(&hash_hex, &other).expect("store unbound key");
        let listed = db.get_hash_only_friends().expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].hash, hash);
        assert!(!listed[0].mutual, "an outgoing request is not mutual");
        assert!(listed[0].last_contact > 0, "never seen falls back to the add time");

        db.set_friend_intro_secret(&hash_hex, &secret).expect("set secret");
        db.set_friend_mutual(&hash_hex, "", 0, None).expect("promote");
        assert!(db.get_hash_only_friends().expect("list")[0].mutual);
        assert!(
            db.clear_keyed_mutual_friend_intro_secrets().expect("sweep").is_empty(),
            "mutual but unkeyed keeps its secret"
        );

        assert!(db.set_friend_public_key(&hash_hex, &key).expect("store key"));
        assert!(db.get_hash_only_friends().expect("list").is_empty());
        assert_eq!(
            db.clear_keyed_mutual_friend_intro_secrets().expect("sweep"),
            vec![hash]
        );
        assert!(db.get_friend_intro_secrets().expect("list").is_empty());
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn one_sided_keyed_friends_keep_their_intro_secret() {
        let path = std::env::temp_dir().join(format!(
            "ember-friend-oneside-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let key = crate::network::ember::crypto::signing_key_from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes();
        let hash_hex =
            hex::encode(crate::network::ember::crypto::node_id_from_ed25519_bytes(&key).unwrap());
        db.add_friend(&hash_hex, "Pending", Some(&key)).expect("add");
        db.set_friend_intro_secret(&hash_hex, &[1u8; 16]).expect("set");
        assert!(db.clear_keyed_mutual_friend_intro_secrets().expect("sweep").is_empty());
        assert_eq!(db.get_friend_intro_secrets().expect("list").len(), 1);
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    /// v6 and v8 snapshot the rows they are about to rewrite or replace, and
    /// v8 says outright it does so "so users upgrading from v<8 aren't
    /// silently wiped". Because `version` is read once and every block then
    /// runs in ascending order in the same call, a database entering below v6
    /// or v8 creates those snapshots and reaches v21's reclaim in the same
    /// upgrade — so v21 has to leave them alone.
    #[test]
    fn a_one_jump_upgrade_keeps_the_legacy_snapshots_v8_promises() {
        let path = std::env::temp_dir().join(format!(
            "ember-legacy-snapshot-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);

        // A pre-v6 profile: the three legacy tables, each carrying a row the
        // snapshot is supposed to preserve, and a version that predates them.
        {
            let conn = Connection::open(&path).expect("open raw");
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL DEFAULT 0);
                 INSERT INTO schema_version (version) VALUES (5);
                 CREATE TABLE transfers (id TEXT, status TEXT, direction TEXT);
                 INSERT INTO transfers VALUES ('t1', '\"done\"', '\"down\"');
                 CREATE TABLE shared_files (path TEXT, size INTEGER);
                 INSERT INTO shared_files VALUES ('C:\\x.bin', 7);
                 CREATE TABLE settings (key TEXT, value TEXT);
                 INSERT INTO settings VALUES ('nick', 'Ada');",
            )
            .expect("seed a pre-v6 profile");
        }

        let db = Database::open_at(&path).expect("migrate from v5");
        assert_eq!(db.schema_version(), MAX_SUPPORTED_SCHEMA_VERSION);

        let rows_in = |table: &str| -> Option<i64> {
            db.conn
                .lock()
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .ok()
        };
        assert_eq!(
            rows_in("shared_files_v7_backup"),
            Some(1),
            "the v8 shared-file snapshot must survive a v5 -> latest upgrade"
        );
        assert_eq!(
            rows_in("settings_v7_backup"),
            Some(1),
            "the v8 settings snapshot must survive a v5 -> latest upgrade"
        );
        assert_eq!(
            rows_in("transfers_v5_backup"),
            Some(1),
            "the v6 transfers snapshot must survive a v5 -> latest upgrade"
        );

        // A profile that already carried the snapshots on entry is past the
        // window they exist for, so the reclaim still runs for it.
        {
            let conn = db.conn.lock();
            conn.execute_batch(
                "DELETE FROM schema_version; INSERT INTO schema_version (version) VALUES (20);",
            )
            .expect("roll back to v20");
        }
        drop(db);
        let reopened = Database::open_at(&path).expect("migrate from v20");
        let gone = |table: &str| -> bool {
            reopened
                .conn
                .lock()
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| {
                    r.get::<_, i64>(0)
                })
                .is_err()
        };
        assert!(gone("shared_files_v7_backup"), "reclaimed at v20 -> latest");
        assert!(gone("settings_v7_backup"), "reclaimed at v20 -> latest");
        assert!(gone("transfers_v5_backup"), "reclaimed at v20 -> latest");

        drop(reopened);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// A fresh database runs every migration block, so it proves the v46 block
    /// works on an empty schema but not that it works on an *existing* one.
    /// Rolling the version back and dropping what it created reproduces the
    /// upgrade a user actually performs, including re-running a block whose
    /// work is already partly present.
    #[test]
    fn the_v46_indexes_are_created_on_an_existing_database() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-upgrade-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);

        let index_count = |db: &Database| -> i64 {
            db.conn
                .lock()
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' \
                     AND name IN ('idx_channel_messages_unread', 'idx_channel_members_member')",
                    [],
                    |r| r.get(0),
                )
                .expect("index count")
        };

        let db = Database::open_at(&path).expect("open db");
        // The current version, not 46: this test is about the two indexes
        // surviving the v45→v46 step, and pinning the number here only made
        // it fail on the next unrelated migration.
        assert_eq!(db.schema_version(), MAX_SUPPORTED_SCHEMA_VERSION);
        assert_eq!(index_count(&db), 2, "fresh database gets both indexes");

        // Back to a v45 profile: version rolled back and the indexes gone.
        {
            let conn = db.conn.lock();
            conn.execute_batch(
                "DROP INDEX idx_channel_messages_unread;
                 DROP INDEX idx_channel_members_member;
                 DELETE FROM schema_version;
                 INSERT INTO schema_version (version) VALUES (45);",
            )
            .expect("roll back to v45");
        }
        drop(db);

        let upgraded = Database::open_at(&path).expect("reopen and migrate");
        assert_eq!(upgraded.schema_version(), MAX_SUPPORTED_SCHEMA_VERSION);
        assert_eq!(index_count(&upgraded), 2, "upgrade recreates both indexes");

        // Idempotent: opening again must not fail on indexes that now exist.
        drop(upgraded);
        let again = Database::open_at(&path).expect("reopen at the current version");
        assert_eq!(again.schema_version(), MAX_SUPPORTED_SCHEMA_VERSION);
        assert_eq!(index_count(&again), 2);

        drop(again);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// An index only helps if the planner picks it, and the unread tally is
    /// the one that used to fall back to reading every message row for a room
    /// out of the table. Asserting the plan is the only way to know the v46
    /// migration did what it was added for.
    #[test]
    fn the_unread_tally_and_member_flags_are_index_driven() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-plan-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let plan_for = |sql: &str| -> String {
            let conn = db.conn.lock();
            let mut stmt = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .expect("prepare plan");
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(3))
                .expect("plan rows")
                .collect::<Result<Vec<_>, _>>()
                .expect("plan text");
            rows.join(" | ")
        };

        let unread = plan_for(
            "SELECT COUNT(*) FROM channel_messages msg \
             WHERE msg.channel_id = 'x' AND msg.read = 0 AND msg.direction = 'received'",
        );
        assert!(
            unread.contains("idx_channel_messages_unread"),
            "unread tally is not using its index: {unread}"
        );
        assert!(
            !unread.contains("SCAN channel_messages"),
            "unread tally still scans the table: {unread}"
        );

        // The mark-as-read UPDATE is why the index is ordered
        // `(channel_id, read, direction)` rather than the other way round.
        let mark_read =
            plan_for("SELECT id FROM channel_messages WHERE channel_id = 'x' AND read = 0");
        assert!(
            mark_read.contains("idx_channel_messages_unread"),
            "mark-read predicate is not using the index prefix: {mark_read}"
        );

        let flags =
            plan_for("SELECT channel_id, banned, moderator FROM channel_members WHERE member_pubkey = 'x'");
        assert!(
            flags.contains("idx_channel_members_member"),
            "batched member flags are not using their index: {flags}"
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// The v48 indexes exist for three queries that could not use the ones
    /// already there: two global queued-chat sweeps that omit `friend_hash`, and
    /// the channel sync read that ranges over `timestamp` while the only room
    /// index is keyed on `id`. As with v46, asserting the plan is the only way to
    /// know the migration did what it was added for.
    #[test]
    fn the_queued_chat_and_sync_sweeps_are_index_driven() {
        let path = std::env::temp_dir().join(format!(
            "ember-queue-plan-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let plan_for = |sql: &str| -> String {
            let conn = db.conn.lock();
            let mut stmt = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .expect("prepare plan");
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(3))
                .expect("plan rows")
                .collect::<Result<Vec<_>, _>>()
                .expect("plan text");
            rows.join(" | ")
        };

        // `pending_chat_counts`: no `friend_hash`, so the per-friend delivery
        // index cannot serve it.
        let counts = plan_for(
            "SELECT friend_hash, COUNT(*) FROM chat_messages \
             WHERE delivery = 1 AND direction = 'sent' GROUP BY friend_hash",
        );
        assert!(
            counts.contains("idx_chat_messages_queue"),
            "unsent tally is not using its index: {counts}"
        );
        assert!(
            !counts.contains("SCAN chat_messages"),
            "unsent tally still scans the table: {counts}"
        );

        // `expire_stale_queued_chat`: same two equalities plus the age range.
        let expire = plan_for(
            "SELECT id, friend_hash FROM chat_messages \
             WHERE delivery = 1 AND direction = 'sent' AND timestamp < 99",
        );
        assert!(
            expire.contains("idx_chat_messages_queue"),
            "queue expiry is not using its index: {expire}"
        );
        assert!(
            !expire.contains("SCAN chat_messages"),
            "queue expiry still scans the table: {expire}"
        );

        // The sync catch-up read, which ranges and sorts on `timestamp`.
        let sync = plan_for(
            "SELECT id FROM channel_messages \
             WHERE channel_id = 'x' AND timestamp >= 5 ORDER BY timestamp ASC, id ASC",
        );
        assert!(
            sync.contains("idx_channel_messages_time"),
            "channel sync read is not using its index: {sync}"
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// A fresh database runs every migration block, so the plan test above proves
    /// v50 works on an empty schema but not on an *existing* one — and the
    /// existing one that matters is a database already at 49, which is what a
    /// device that ran the decline-queue work is sitting on. Rolling the version
    /// back and dropping what the block creates reproduces that upgrade.
    #[test]
    fn the_v50_indexes_are_created_on_a_v49_database() {
        let path = std::env::temp_dir().join(format!(
            "ember-v50-upgrade-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);

        let index_count = |db: &Database| -> i64 {
            db.conn
                .lock()
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' \
                     AND name IN ('idx_chat_messages_queue', 'idx_channel_messages_time')",
                    [],
                    |r| r.get(0),
                )
                .expect("index count")
        };

        let db = Database::open_at(&path).expect("open db");
        assert_eq!(db.schema_version(), MAX_SUPPORTED_SCHEMA_VERSION);
        assert_eq!(index_count(&db), 2, "fresh database gets both indexes");

        // Back to a v49 profile: the version rolled back and the indexes gone,
        // with everything v48 and v49 added left in place.
        {
            let conn = db.conn.lock();
            conn.execute_batch(
                "DROP INDEX idx_chat_messages_queue;
                 DROP INDEX idx_channel_messages_time;
                 DELETE FROM schema_version;
                 INSERT INTO schema_version (version) VALUES (49);",
            )
            .expect("roll back to v49");
        }
        drop(db);

        let upgraded = Database::open_at(&path).expect("a v49 database must still open");
        assert_eq!(upgraded.schema_version(), MAX_SUPPORTED_SCHEMA_VERSION);
        assert_eq!(index_count(&upgraded), 2, "upgrade recreates both indexes");
        // The earlier blocks must not have been re-run backwards over it.
        assert!(
            upgraded
                .conn
                .lock()
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('channel_messages') \
                     WHERE name = 'delivery'",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .expect("column count")
                == 1,
            "v49's column survives the v50 step"
        );

        // Idempotent: opening again must not fail on indexes that now exist.
        drop(upgraded);
        let again = Database::open_at(&path).expect("reopen at the current version");
        assert_eq!(again.schema_version(), MAX_SUPPORTED_SCHEMA_VERSION);
        assert_eq!(index_count(&again), 2);

        drop(again);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// A chat attachment's grant is the only thing that lets a friend read a
    /// file that is not in the shared library, so every way it can stop being a
    /// grant matters as much as the way it starts being one.
    #[test]
    fn a_chat_attachment_grant_resolves_only_for_its_friend_while_it_lives() {
        let path = std::env::temp_dir().join(format!(
            "ember-attach-grant-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        assert_eq!(db.schema_version(), MAX_SUPPORTED_SCHEMA_VERSION);

        let xfer = "ab".repeat(8);
        let friend = "cd".repeat(8);
        let stranger = "ef".repeat(8);
        let now = 1_000_000i64;
        db.upsert_chat_attachment(
            &xfer,
            &friend,
            "sent",
            "holiday.zip",
            4096,
            &"11".repeat(32),
            Some("C:\\private\\holiday.zip"),
            "offered",
            now,
            now + 600,
        )
        .expect("insert grant");

        let granted = db
            .chat_attachment_grant(&xfer, &friend, now)
            .expect("the friend it was granted to");
        assert_eq!(granted.0, "C:\\private\\holiday.zip");
        assert_eq!(granted.1, 4096);

        // Another friend holding the same id gets nothing. The friend is part of
        // the lookup so a caller cannot forget to compare it.
        assert!(db.chat_attachment_grant(&xfer, &stranger, now).is_none());

        // Past its expiry it is not a grant, without anything having to sweep.
        assert!(db.chat_attachment_grant(&xfer, &friend, now + 601).is_none());

        // And a transfer that was refused or abandoned stops resolving —
        // including the refusals no deny-list ever named, because the query is
        // an allow-list.
        for status in [
            "declined",
            "too_large",
            "busy",
            "not_allowed",
            "cancelled",
            "failed",
            "expired",
        ] {
            db.set_chat_attachment_status(&xfer, status, None, None)
                .expect("set status");
            assert!(
                db.chat_attachment_grant(&xfer, &friend, now).is_none(),
                "a {status} attachment must not still be readable"
            );
        }

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    fn raw_attachment_fields(
        db: &Database,
        xfer: &str,
    ) -> (String, Option<String>, Option<String>) {
        db.conn
            .lock()
            .query_row(
                "SELECT file_name, source_path, dest_path FROM chat_attachments WHERE xfer_id = ?1",
                params![xfer],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("raw row")
    }

    /// Names and paths are sealed on disk like message bodies, and read back as
    /// written. Under a key that cannot open them they read as unavailable,
    /// never as their ciphertext and never as a grant.
    #[test]
    fn attachment_names_and_paths_are_sealed_at_rest() {
        let path = std::env::temp_dir().join(format!(
            "ember-attach-sealed-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let (sent, received) = ("a1".repeat(16), "b2".repeat(16));
        let friend = "cd".repeat(8);
        let now = 1_500_000i64;
        db.upsert_chat_attachment(
            &sent, &friend, "sent", "tax-return.pdf", 10, &"11".repeat(32),
            Some("C:\\Users\\me\\Private\\tax-return.pdf"), "offered", now, now + 600,
        )
        .expect("insert sent");
        db.upsert_chat_attachment(
            &received, &friend, "received", "photo.jpg", 10, &"22".repeat(32), None, "awaiting",
            now, now + 600,
        )
        .expect("insert received");
        let landed = Some("D:\\Chat Files\\photo.jpg");
        assert!(db
            .advance_chat_attachment(&received, "complete", Some(10), landed)
            .expect("complete"));

        for xfer in [&sent, &received] {
            let (name, source, dest) = raw_attachment_fields(&db, xfer);
            for stored in std::iter::once(name).chain(source).chain(dest) {
                assert!(stored.starts_with(CHAT_ATTACH_PREFIX), "stored readable: {stored}");
                for plain in ["tax-return", "Private", "photo", "Chat Files"] {
                    assert!(!stored.contains(plain));
                }
            }
        }
        assert_eq!(db.chat_attachment(&sent).unwrap().file_name, "tax-return.pdf");
        assert_eq!(
            db.chat_attachment_grant(&sent, &friend, now).unwrap().0,
            "C:\\Users\\me\\Private\\tax-return.pdf"
        );
        let row = db.chat_attachment(&received).unwrap();
        assert_eq!(row.file_name, "photo.jpg");
        assert_eq!(row.dest_path.as_deref(), Some("D:\\Chat Files\\photo.jpg"));
        assert_eq!(db.chat_attachments_for_friend(&friend, 10).unwrap().len(), 2);

        let wrong_key = Database {
            conn: Mutex::new(Connection::open(&path).expect("second connection")),
            path: path.clone(),
            chat_key: Some(Zeroizing::new([0x5A; 32])),
            corrupt_backup: None,
        };
        let row = wrong_key.chat_attachment(&received).unwrap();
        assert_eq!(row.file_name, CHAT_ATTACH_UNAVAILABLE_NAME);
        assert_eq!(row.dest_path, None);
        assert!(wrong_key.chat_attachment_grant(&sent, &friend, now).is_none());

        drop(wrong_key);
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// v60 seals the rows an older build left readable, and until it has run a
    /// readable row still reads.
    #[test]
    fn v60_seals_attachment_rows_written_before_it() {
        let path = std::env::temp_dir().join(format!(
            "ember-attach-v60-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let xfer = "c3".repeat(16);
        let friend = "de".repeat(8);
        db.conn
            .lock()
            .execute_batch(&format!(
                "INSERT INTO chat_attachments (
                    xfer_id, friend_hash, direction, file_name, file_size, root_hash,
                    source_path, dest_path, status, transferred, created_at, expires_at
                 ) VALUES ('{xfer}', '{friend}', 'sent', 'old.txt', 3, '{root}',
                    'C:\\old\\old.txt', 'C:\\dl\\old.txt', 'offered', 0, 10, 99999999999);
                 DELETE FROM schema_version; INSERT INTO schema_version (version) VALUES (59);",
                root = "33".repeat(32),
            ))
            .expect("plant a v59 row");
        let row = db.chat_attachment(&xfer).expect("a readable row still reads");
        assert_eq!(row.file_name, "old.txt");
        assert_eq!(row.dest_path.as_deref(), Some("C:\\dl\\old.txt"));
        drop(db);

        let db = Database::open_at(&path).expect("reopen and migrate");
        assert_eq!(db.schema_version(), MAX_SUPPORTED_SCHEMA_VERSION);
        let (name, source, dest) = raw_attachment_fields(&db, &xfer);
        assert!(name.starts_with(CHAT_ATTACH_PREFIX));
        assert!(source.unwrap().starts_with(CHAT_ATTACH_PREFIX));
        assert!(dest.unwrap().starts_with(CHAT_ATTACH_PREFIX));
        let row = db.chat_attachment(&xfer).unwrap();
        assert_eq!(row.file_name, "old.txt");
        assert_eq!(row.dest_path.as_deref(), Some("C:\\dl\\old.txt"));
        assert_eq!(db.chat_attachment_grant(&xfer, &friend, 20).unwrap().0, "C:\\old\\old.txt");
        {
            let conn = db.conn.lock();
            assert!(Database::database_holds_chat_ciphertext(&conn).unwrap());
        }

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    fn owned_room_db(tag: &str, is_owner: bool) -> (Database, std::path::PathBuf, String) {
        let path = std::env::temp_dir().join(format!(
            "ember-moderation-{tag}-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let channel_id = "ab".repeat(16);
        db.insert_channel(&channel_id, &"cd".repeat(32), "Lobby", "public", is_owner, None, None)
            .expect("insert channel");
        (db, path, channel_id)
    }

    fn drop_db(db: Database, path: &std::path::Path) {
        drop(db);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    fn topic_only(topic: &str) -> ModerationSnapshot<'_> {
        ModerationSnapshot {
            topic,
            welcome: "",
            banned_pubkeys: &[],
            moderator_pubkeys: &[],
            owner_pubkey: None,
            successor_nominee: None,
            claim_after_days: None,
            key_epoch: None,
            invites_owner_only: None,
            slow_mode_secs: None,
        }
    }

    const NO_POLICY: OwnerRoomPolicy<'static> = OwnerRoomPolicy {
        announce_only: false,
        pinned_msg_ids: &[],
        language: None,
    };

    /// Every snapshot an owner signs gets a stamp of its own, however many land
    /// in one second, and never one at or behind what it already holds.
    #[test]
    fn owner_snapshot_stamps_never_repeat() {
        let (db, path, id) = owned_room_db("stamps", true);
        let now = 1_700_000_000i64;
        let first = db.stamp_owner_snapshot(&id, now).unwrap().unwrap();
        assert_eq!(first, now);
        let edit = db
            .commit_owner_channel_moderation(&id, &topic_only("edit"), &NO_POLICY, now)
            .unwrap()
            .unwrap();
        assert_eq!(edit, now + 1);
        let republish = db.stamp_owner_snapshot(&id, now).unwrap().unwrap();
        assert_eq!(republish, now + 2);
        assert_eq!(db.stamp_owner_snapshot(&id, now + 60).unwrap(), Some(now + 60));
        assert_eq!(db.stamp_owner_snapshot(&"ee".repeat(16), now).unwrap(), None);
        assert_eq!(db.get_channel(&id).unwrap().unwrap().topic, "edit");
        drop_db(db, &path);
    }

    /// A stamp taken while the clock ran hours fast is not counted on from once
    /// it is corrected — storers would refuse everything after it — and the
    /// owner can still edit, although its last snapshot is dated after now.
    #[test]
    fn a_stamp_from_a_fast_clock_is_not_counted_on_from() {
        let (db, path, id) = owned_room_db("fast-clock", true);
        let now = 1_700_000_000i64;
        let fast = now + 5 * 3600;
        let ahead = db
            .commit_owner_channel_moderation(&id, &topic_only("while fast"), &NO_POLICY, fast)
            .unwrap()
            .unwrap();
        assert_eq!(ahead, fast);
        assert_eq!(db.stamp_owner_snapshot(&id, now).unwrap(), Some(now));
        assert_eq!(db.stamp_owner_snapshot(&id, now).unwrap(), Some(now + 1), "and counts on");
        let edit = db
            .commit_owner_channel_moderation(&id, &topic_only("corrected"), &NO_POLICY, now)
            .unwrap()
            .unwrap();
        assert_eq!(edit, now + 2);
        assert_eq!(db.get_channel(&id).unwrap().unwrap().topic, "corrected");
        // A stamp only a little ahead is still counted on from.
        assert_eq!(db.stamp_owner_snapshot(&id, now - 60).unwrap(), Some(now + 3));
        drop_db(db, &path);
    }

    /// The pins, posting rule and language an edit carries are stored with it,
    /// so a republish can never read the moderation fields without them.
    #[test]
    fn an_owner_edit_stores_its_room_policy_in_the_same_write() {
        let (db, path, id) = owned_room_db("policy", true);
        let pins = [[0xA1u8; 16]];
        let policy = OwnerRoomPolicy {
            announce_only: true,
            pinned_msg_ids: &pins,
            language: Some("fr"),
        };
        db.commit_owner_channel_moderation(&id, &topic_only("rules"), &policy, 1_700_000_000)
            .unwrap()
            .unwrap();
        let row = db.get_channel(&id).unwrap().unwrap();
        assert!(row.announce_only);
        assert_eq!(row.pinned_msg_ids, vec!["a1".repeat(16)]);
        assert_eq!(row.language, "fr");
        assert!(db
            .commit_owner_channel_moderation(&"ee".repeat(16), &topic_only("x"), &policy, 1)
            .unwrap()
            .is_none());
        drop_db(db, &path);
    }

    /// Two snapshots from one second leave every member holding the same one,
    /// whichever arrived first.
    #[test]
    fn same_second_snapshots_settle_on_the_larger_signature() {
        let (low, high) = ([0x10u8; 64], [0x20u8; 64]);
        let at = 1_700_000_000i64;
        let orders = [(("low", &low), ("high", &high)), (("high", &high), ("low", &low))];
        for (first, second) in orders {
            let (db, path, id) = owned_room_db("tie", false);
            assert!(db.ingest_channel_moderation(&id, &topic_only(first.0), at, first.1).unwrap());
            let replaced = db
                .ingest_channel_moderation(&id, &topic_only(second.0), at, second.1)
                .unwrap();
            assert_eq!(replaced, second.0 == "high");
            assert_eq!(db.get_channel(&id).unwrap().unwrap().topic, "high");
            assert!(
                !db.ingest_channel_moderation(&id, &topic_only("older"), at - 1, &[0xFF; 64])
                    .unwrap(),
                "an older stamp never wins on signature"
            );
            drop_db(db, &path);
        }
    }

    /// The owner's device never lets one of its own snapshots coming back from
    /// the network roll back what it has changed since.
    #[test]
    fn an_owner_does_not_reapply_its_own_snapshot() {
        let (db, path, id) = owned_room_db("owner", true);
        let now = 1_700_000_000i64;
        let stamp = db
            .commit_owner_channel_moderation(&id, &topic_only("current"), &NO_POLICY, now)
            .unwrap()
            .unwrap();
        for (at, sig) in [(stamp, [0xFFu8; 64]), (stamp - 1, [0xFF; 64])] {
            assert!(!db.ingest_channel_moderation(&id, &topic_only("stale"), at, &sig).unwrap());
        }
        let republished = db.stamp_owner_snapshot(&id, now).unwrap().unwrap();
        assert!(
            !db.ingest_channel_moderation(&id, &topic_only("stale"), republished, &[0xFF; 64])
                .unwrap(),
            "a republish it signed is its own work too"
        );
        assert_eq!(db.get_channel(&id).unwrap().unwrap().topic, "current");
        drop_db(db, &path);
    }

    /// The receiving side has no source path, so it must never look like a
    /// grant — otherwise receiving a file would authorize serving one.
    #[test]
    fn a_received_attachment_is_never_a_grant() {
        let path = std::env::temp_dir().join(format!(
            "ember-attach-inbound-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let xfer = "12".repeat(8);
        let friend = "34".repeat(8);
        let now = 2_000_000i64;
        db.upsert_chat_attachment(
            &xfer,
            &friend,
            "received",
            "inbound.bin",
            10,
            &"22".repeat(32),
            None,
            "awaiting",
            now,
            now + 600,
        )
        .expect("insert inbound");

        assert!(db.chat_attachment_grant(&xfer, &friend, now).is_none());

        // It is still readable as a transcript row, and completing it records
        // where the bytes landed.
        db.set_chat_attachment_status(&xfer, "complete", Some(10), Some("C:\\dl\\Chat Files\\inbound.bin"))
            .expect("complete it");
        let row = db.chat_attachment(&xfer).expect("row");
        assert_eq!(row.status, "complete");
        assert_eq!(row.transferred, 10);
        assert_eq!(
            row.dest_path.as_deref(),
            Some("C:\\dl\\Chat Files\\inbound.bin")
        );
        assert_eq!(db.chat_attachments_for_friend(&friend, 10).unwrap().len(), 1);

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// The full-file check only runs when the last session never reached its
    /// shutdown — and then it still finds and preserves a damaged database.
    #[test]
    fn open_checks_integrity_only_after_an_unclean_shutdown() {
        use std::io::{Seek, SeekFrom, Write};
        let dir = std::env::temp_dir().join(format!(
            "ember-session-marker-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ember.db");
        let marker = Database::session_marker_path(&path);

        let db = Database::open_for_session(&path).expect("first open");
        assert!(marker.exists(), "an open session is marked");
        let (root, page_size) = {
            let conn = db.conn.lock();
            conn.execute_batch("CREATE TABLE filler(x BLOB);").unwrap();
            for _ in 0..20 {
                conn.execute("INSERT INTO filler VALUES (randomblob(2000))", [])
                    .unwrap();
            }
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
            let root: i64 = conn
                .query_row("SELECT rootpage FROM sqlite_master WHERE name = 'filler'", [], |r| {
                    r.get(0)
                })
                .unwrap();
            let page_size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap();
            (root, page_size)
        };
        db.mark_clean_shutdown();
        assert!(!marker.exists());
        drop(db);

        // Damage a page nothing on the open path reads.
        {
            let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            file.seek(SeekFrom::Start(((root - 1) * page_size) as u64)).unwrap();
            file.write_all(&[0xFF; 16]).unwrap();
        }

        let after_clean = Database::open_for_session(&path).expect("open after a clean exit");
        assert!(
            after_clean.corrupt_backup.is_none(),
            "a clean shutdown skips the full check"
        );
        drop(after_clean);
        assert!(marker.exists(), "that session never reached its shutdown");

        let after_crash = Database::open_for_session(&path).expect("open after a crash");
        assert!(
            after_crash.corrupt_backup.is_some(),
            "after an unclean shutdown the check runs and preserves the damaged file"
        );
        drop(after_crash);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn scratch_db(tag: &str) -> (Database, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "ember-{tag}-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let _ = std::fs::remove_file(&path);
        (Database::open_at(&path).expect("open db"), path)
    }

    fn drop_scratch_db(db: Database, path: std::path::PathBuf) {
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// Removing or blocking a friend has to take their attachment rows too: a
    /// `sent` row is a grant that keeps a local path readable to them.
    #[test]
    fn removing_or_blocking_a_friend_deletes_their_attachments() {
        let (db, path) = scratch_db("attach-friend-removal");
        let now = chrono::Utc::now().timestamp();
        let removed = "a1".repeat(8);
        let blocked = "b2".repeat(8);
        let kept = "c3".repeat(8);
        for (i, friend) in [&removed, &blocked, &kept].iter().enumerate() {
            db.upsert_chat_attachment(
                &format!("{:02x}", 0x40 + i).repeat(8),
                friend,
                "sent",
                "f.bin",
                1,
                &"11".repeat(32),
                Some("C:\\f.bin"),
                "accepted",
                now,
                now + 600,
            )
            .expect("insert");
        }
        db.remove_friend(&removed).expect("remove");
        db.block_friend(&blocked).expect("block");
        assert!(db.chat_attachments_for_friend(&removed, 10).unwrap().is_empty());
        assert!(db.chat_attachments_for_friend(&blocked, 10).unwrap().is_empty());
        assert_eq!(db.chat_attachments_for_friend(&kept, 10).unwrap().len(), 1);
        drop_scratch_db(db, path);
    }

    /// Settled rows go once they are past retention; live ones stay whatever
    /// their age, and so do settled ones still inside the window.
    #[test]
    fn settled_attachments_are_pruned_after_the_retention_window() {
        let (db, path) = scratch_db("attach-prune");
        let friend = "d4".repeat(8);
        let now = 50_000_000i64;
        let old = now - CHAT_ATTACHMENT_RETENTION_SECS - 3_600;
        let recent = now - 60;
        let rows = [
            ("old-complete", "received", "complete", old),
            ("old-declined", "sent", "declined", old),
            ("old-active", "received", "active", old),
            ("new-complete", "received", "complete", recent),
        ];
        for (i, (_, direction, status, at)) in rows.iter().enumerate() {
            db.upsert_chat_attachment(
                &format!("{:02x}", 0x50 + i).repeat(8),
                &friend,
                direction,
                "f.bin",
                1,
                &"11".repeat(32),
                None,
                status,
                *at,
                *at + 600,
            )
            .expect("insert");
        }
        db.expire_chat_attachments(now).expect("sweep");
        let mut left: Vec<String> = db
            .chat_attachments_for_friend(&friend, 10)
            .unwrap()
            .into_iter()
            .map(|row| row.status)
            .collect();
        left.sort();
        assert_eq!(left, vec!["active".to_string(), "complete".to_string()]);
        drop_scratch_db(db, path);
    }

    #[test]
    fn chat_delivery_is_marked_for_a_batch_in_one_call() {
        let (db, path) = scratch_db("chat-delivery-many");
        let friend = "e5".repeat(8);
        let a = db.insert_pending_chat_message(&friend, "one").expect("queue");
        let b = db.insert_pending_chat_message(&friend, "two").expect("queue");
        let matched = db
            .set_chat_delivery_many(&[a, b, i64::MAX], CHAT_DELIVERED)
            .expect("mark");
        assert_eq!(matched, vec![true, true, false]);
        assert!(db.pending_chat_messages(&friend, 10).unwrap().is_empty());
        assert!(db.set_chat_delivery_many(&[], CHAT_DELIVERED).unwrap().is_empty());
        drop_scratch_db(db, path);
    }

    /// A roster copy is only as good as the generation it was read under, so
    /// every write that can change who is on it, or whether they are fresh or
    /// banned, has to move it. Only increases are asserted: the counter is
    /// shared by slot with whatever other tests are writing rosters.
    #[test]
    fn every_channel_roster_write_moves_the_roster_generation() {
        let (db, path) = scratch_db("roster-generation");
        let channel = "f6".repeat(16);
        let member = "a7".repeat(32);
        db.insert_channel(&channel, &"b8".repeat(32), "Room", "public", false, None, None)
            .expect("channel");
        let generation = || db.channel_roster_generation(&channel);

        let before = generation();
        db.upsert_channel_member(&channel, &member, "", 100, None).unwrap();
        let after_insert = generation();
        assert!(after_insert > before, "an insert");

        let now = chrono::Utc::now().timestamp();
        db.touch_channel_members_last_seen(&[(channel.clone(), member.clone(), now)])
            .unwrap();
        let after_touch = generation();
        assert!(after_touch > after_insert, "a touch that brought the row back to fresh");

        assert!(db.apply_channel_ban_action(&channel, &member, true, now).unwrap());
        let after_ban = generation();
        assert!(after_ban > after_touch, "a ban");

        assert!(db.apply_channel_ban_action(&channel, &member, false, now).unwrap());
        assert!(db.remove_channel_member(&channel, &member, i64::MAX).unwrap());
        assert!(generation() > after_ban, "a removal");
        drop_scratch_db(db, path);
    }

    /// The writes that do not move the generation are the ones no snapshot can
    /// see before it expires: `last_seen` moving while it was comfortably
    /// fresh, or while it stays stale. Those are nearly all of them.
    #[test]
    fn only_a_presence_move_a_snapshot_could_see_counts_as_a_channel_roster_change() {
        let now = 10_000_000;
        let fresh = now - 10;
        let stale = now - PRESENCE_FRESH_SECS - 10;
        assert!(channel_presence_revived(stale, fresh, now));
        assert!(!channel_presence_revived(fresh, now, now), "fresh to fresher");
        assert!(!channel_presence_revived(stale - 100, stale, now), "stale to less stale");
        // Fresh now, but stale before a snapshot taken now would expire: a
        // touch that is flushed without a bump would leave the member reading
        // as absent for the rest of that snapshot's life.
        let nearly_stale = now - PRESENCE_FRESH_SECS + CHANNEL_ROSTER_SNAPSHOT_TTL_SECS - 1;
        assert!(channel_presence_revived(nearly_stale, now, now));
        let safely_fresh = now - PRESENCE_FRESH_SECS + CHANNEL_ROSTER_SNAPSHOT_TTL_SECS;
        assert!(!channel_presence_revived(safely_fresh, now, now));
    }

    #[test]
    fn channel_roster_generations_are_per_room() {
        let a = "0a".repeat(16);
        let b = (0u8..=255)
            .map(|i| format!("{i:02x}").repeat(16))
            .find(|b| !std::ptr::eq(channel_roster_slot(&a), channel_roster_slot(b)))
            .expect("another slot");
        assert!(!std::ptr::eq(channel_roster_slot(&a), channel_roster_slot(&b)));
        // Case-insensitive, since ids arrive in either case.
        assert!(std::ptr::eq(
            channel_roster_slot(&a),
            channel_roster_slot(&a.to_ascii_uppercase())
        ));
    }

    /// An offer nobody answered has to stop being readable on its own, or a
    /// forgotten one leaves a path open to a friend for the life of the profile.
    #[test]
    fn unanswered_attachments_expire_and_stop_granting() {
        let path = std::env::temp_dir().join(format!(
            "ember-attach-expire-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let friend = "56".repeat(8);
        let now = 3_000_000i64;
        for (i, status) in ["offered", "active", "complete"].iter().enumerate() {
            db.upsert_chat_attachment(
                &format!("{:02x}", i).repeat(8),
                &friend,
                "sent",
                "f.bin",
                10,
                &"33".repeat(32),
                Some("C:\\private\\f.bin"),
                status,
                now,
                now + 60,
            )
            .expect("insert");
        }

        // Only the two that were still in flight move; a finished transfer is
        // not "expired" and is left saying what it did.
        assert_eq!(db.expire_chat_attachments(now + 61).expect("sweep").len(), 2);
        assert_eq!(
            db.chat_attachment(&"00".repeat(8)).expect("row").status,
            "expired"
        );
        assert_eq!(
            db.chat_attachment(&"02".repeat(8)).expect("row").status,
            "complete"
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    fn attach_test_db(tag: &str) -> (Database, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "ember-attach-{tag}-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let _ = std::fs::remove_file(&path);
        (Database::open_at(&path).expect("open db"), path)
    }

    fn drop_attach_test_db(db: Database, path: std::path::PathBuf) {
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// A receive carries only the offer's short expiry. The sweep that runs
    /// every time the transcript is listed must not end one that is still
    /// moving bytes, while an offer that was never answered still lapses.
    #[test]
    fn a_running_receive_outlives_its_offer_expiry() {
        let (db, path) = attach_test_db("expire-recv");
        let friend = "57".repeat(8);
        let now = 3_000_000i64;
        for (id, status) in [("aa", "active"), ("bb", "awaiting")] {
            db.upsert_chat_attachment(
                &id.repeat(16),
                &friend,
                "received",
                "f.bin",
                10,
                &"33".repeat(32),
                None,
                status,
                now,
                now + 60,
            )
            .expect("insert");
        }

        assert_eq!(db.expire_chat_attachments(now + 61).expect("sweep").len(), 1);
        assert_eq!(db.chat_attachment(&"aa".repeat(16)).expect("row").status, "active");
        assert_eq!(db.chat_attachment(&"bb".repeat(16)).expect("row").status, "expired");
        drop_attach_test_db(db, path);
    }

    /// The conditional write is what settles a race between a cancel and a
    /// finishing receive: whichever lands first holds.
    #[test]
    fn only_a_live_attachment_can_be_advanced() {
        let (db, path) = attach_test_db("advance");
        let xfer = "cc".repeat(16);
        db.upsert_chat_attachment(
            &xfer,
            &"58".repeat(8),
            "received",
            "f.bin",
            10,
            &"33".repeat(32),
            None,
            "active",
            1,
            2,
        )
        .expect("insert");

        assert!(db.advance_chat_attachment(&xfer, "cancelled", None, None).expect("cancel"));
        assert!(!db
            .advance_chat_attachment(&xfer, "complete", Some(10), Some("C:\\dl\\f.bin"))
            .expect("late completion"));
        let row = db.chat_attachment(&xfer).expect("row");
        assert_eq!(row.status, "cancelled");
        assert_eq!(row.dest_path, None);
        assert_eq!(db.chat_attachment_expiry(&xfer), Some(2));
        drop_attach_test_db(db, path);
    }

    /// A send cut off by a restart goes back to waiting for the friend's dial,
    /// and a receive is left for the inbound sweep.
    #[test]
    fn an_interrupted_send_is_requeued_not_left_sending() {
        let (db, path) = attach_test_db("requeue");
        let friend = "59".repeat(8);
        for (id, direction) in [("dd", "sent"), ("ee", "received")] {
            db.upsert_chat_attachment(
                &id.repeat(16),
                &friend,
                direction,
                "f.bin",
                10,
                &"33".repeat(32),
                (direction == "sent").then_some("C:\\private\\f.bin"),
                "active",
                1,
                i64::MAX,
            )
            .expect("insert");
        }

        assert_eq!(db.requeue_interrupted_outbound_chat_attachments().expect("requeue"), 1);
        assert_eq!(db.chat_attachment(&"dd".repeat(16)).expect("row").status, "accepted");
        assert_eq!(db.chat_attachment(&"ee".repeat(16)).expect("row").status, "active");
        drop_attach_test_db(db, path);
    }

    /// Unread means "they said something I have not read". A sent row that
    /// somehow carries `read = 0` must not put a number on the badge, because
    /// nothing in the UI can ever clear it.
    #[test]
    fn the_friend_unread_tally_ignores_outbound_rows() {
        let path = std::env::temp_dir().join(format!(
            "ember-unread-dir-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let friend = "ab".repeat(8);
        db.insert_chat_message(&friend, "received", "hello")
            .expect("inbound");
        db.insert_chat_message(&friend, "sent", "mine")
            .expect("outbound");
        // The flag the insert path never sets on an outbound row, which is exactly
        // the row the direction filter exists to ignore. Forced here because the
        // point is what the tally does when something else has already gone wrong.
        {
            let conn = db.conn.lock();
            conn.execute(
                "UPDATE chat_messages SET read = 0 WHERE direction = 'sent'",
                [],
            )
            .expect("clear read on the sent row");
        }

        let counts = db.unread_message_counts().expect("counts");
        assert_eq!(
            counts,
            vec![(friend.clone(), 1)],
            "only the inbound line is unread"
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// Destroying a room has to take its forget-list with it. The list only ever
    /// serves the ingest path for that room, so once the room is gone every row
    /// is unreachable and nothing else would remove them.
    #[test]
    fn removing_a_room_clears_its_message_tombstones() {
        let path = std::env::temp_dir().join(format!(
            "ember-tombstone-sweep-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let tombstones = |db: &Database, id: &str| -> i64 {
            db.conn
                .lock()
                .query_row(
                    "SELECT COUNT(*) FROM channel_message_tombstones WHERE channel_id = ?1",
                    params![id],
                    |r| r.get(0),
                )
                .expect("tombstone count")
        };

        // One room we own and tombstone, one we merely forget.
        let owned = "aa".repeat(16);
        let joined = "bb".repeat(16);
        for (id, is_owner) in [(&owned, true), (&joined, false)] {
            db.insert_channel(
                id,
                &"cd".repeat(32),
                "Lobby",
                "public",
                is_owner,
                if is_owner { Some(&[0x11u8; 32]) } else { None },
                Some(&[0x22u8; 32]),
            )
            .expect("insert channel");
            {
                let conn = db.conn.lock();
                conn.execute(
                    "INSERT INTO channel_message_tombstones (channel_id, msg_id, deleted_at) \
                     VALUES (?1, ?2, 1)",
                    params![id, "ff".repeat(8)],
                )
                .expect("record a forgotten line");
            }
            assert_eq!(tombstones(&db, id), 1, "the forget-list row is there");
        }

        db.tombstone_channel(&owned).expect("owner delete");
        assert_eq!(
            tombstones(&db, &owned),
            0,
            "an owner delete leaves no forget-list behind"
        );

        db.delete_channel(&joined, None).expect("forget");
        assert_eq!(
            tombstones(&db, &joined),
            0,
            "forgetting a room leaves no forget-list behind"
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// A reaction for a line we do not hold is kept on purpose — it may arrive
    /// before its message — but it cannot be kept without limit, or a peer
    /// reacting to ids it never publishes spends our disk.
    #[test]
    fn reactions_for_absent_lines_are_bounded() {
        let path = std::env::temp_dir().join(format!(
            "ember-orphan-reactions-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel = "aa".repeat(16);
        db.insert_channel(
            &channel,
            &"cd".repeat(32),
            "Lobby",
            "public",
            false,
            None,
            Some(&[0x22u8; 32]),
        )
        .expect("insert channel");

        let cap = Database::CHANNEL_ORPHAN_REACTIONS_PER_CHANNEL;
        let member = "ef".repeat(32);
        // Comfortably past the cap, each against a line that will never arrive.
        for n in 0..(cap + 64) {
            let msg_id = format!("{:032x}", n);
            db.set_channel_message_reaction(&channel, &msg_id, &member, 1, 1_000 + n, "sig")
                .expect("record reaction");
        }

        let total: i64 = db
            .conn
            .lock()
            .query_row(
                "SELECT COUNT(*) FROM channel_message_reactions WHERE channel_id = ?1",
                params![&channel],
                |r| r.get(0),
            )
            .expect("reaction count");
        assert!(
            total <= cap,
            "orphan reactions grew past the cap: {total} > {cap}"
        );

        // A reaction whose line is present is never touched by the sweep, however
        // many orphans surround it.
        let real_msg = "ab".repeat(8);
        db.insert_channel_message(
            &channel, &member, "received", "hello", &real_msg, 2_000, "", true,
        )
        .expect("insert message");
        db.set_channel_message_reaction(&channel, &real_msg, &member, 1, 2_001, "sig")
            .expect("react to a real line");
        for n in 0..32 {
            let msg_id = format!("{:032x}", 100_000 + n);
            db.set_channel_message_reaction(&channel, &msg_id, &member, 1, 3_000 + n, "sig")
                .expect("more orphans");
        }
        let kept: i64 = db
            .conn
            .lock()
            .query_row(
                "SELECT COUNT(*) FROM channel_message_reactions \
                 WHERE channel_id = ?1 AND msg_id = ?2",
                params![&channel, &real_msg],
                |r| r.get(0),
            )
            .expect("real reaction count");
        assert_eq!(kept, 1, "the reaction on a line we hold survives the sweep");

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// `get_channel_lite` is what the packet paths read, and `list_channels`
    /// reads both membership flags for every room in one statement. Neither
    /// may disagree with the per-row queries they replaced.
    #[test]
    fn lite_channel_reads_agree_with_the_per_row_queries() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-lite-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let room_a = "aa".repeat(16);
        let room_b = "bb".repeat(16);
        let me = "cd".repeat(32);
        let other = "ef".repeat(32);
        for (id, pk) in [(&room_a, &me), (&room_b, &me)] {
            db.insert_channel(id, pk, "Lobby", "private", true, None, Some(&[0x22u8; 32]))
                .expect("insert channel");
        }
        db.upsert_channel_member(&room_a, &me, "Ada", 100, None)
            .unwrap();
        db.upsert_channel_member(&room_a, &other, "Bob", 100, None)
            .unwrap();
        // Banned in one room, a moderator in neither, absent from the other.
        db.apply_channel_moderation(
            &room_a,
            "topic",
            "welcome",
            50,
            &[hex::decode(&me).unwrap().try_into().unwrap()],
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        // Every field the packet paths read must match, counts aside.
        let full = db.get_channel(&room_a).unwrap().unwrap();
        let lite = db.get_channel_lite(&room_a).unwrap().unwrap();
        assert_eq!(lite.channel_id, full.channel_id);
        assert_eq!(lite.pubkey, full.pubkey);
        assert_eq!(lite.visibility, full.visibility);
        assert_eq!(lite.key_epoch, full.key_epoch);
        assert_eq!(lite.in_room, full.in_room);
        assert_eq!(lite.deleted, full.deleted);
        assert_eq!(lite.in_room_now(), full.in_room_now());
        assert_eq!(lite.member_count, 0, "counts are deliberately not read");
        assert_eq!(lite.unread, 0);
        assert!(db.get_channel_lite(&"99".repeat(16)).unwrap().is_none());

        // The batched flags must equal what the two per-row queries answer,
        // including for a room this member has no roster row in.
        let flags = db.channel_member_flags(&me).unwrap();
        for room in [&room_a, &room_b] {
            let (banned, moderator) = flags.get(room).copied().unwrap_or((false, false));
            assert_eq!(banned, db.channel_member_is_banned(room, &me).unwrap());
            assert_eq!(
                moderator,
                db.channel_member_is_moderator(room, &me).unwrap()
            );
        }
        assert!(flags.get(&room_a).copied().unwrap().0, "banned in room A");
        assert!(!flags.contains_key(&room_b), "no roster row in room B");

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn a_room_rename_reaches_a_member_and_the_owner_remembers_when() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-rename-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let channel_id = "ab".repeat(16);
        db.insert_channel(&channel_id, &"cd".repeat(32), "Lobby", "public", false, None, None)
            .expect("insert channel");

        // A member: the name arrives with an owner snapshot.
        assert!(db.apply_owner_room_name(&channel_id, "Lounge").unwrap());
        assert_eq!(db.get_channel(&channel_id).unwrap().unwrap().name, "Lounge");
        assert!(
            !db.apply_owner_room_name(&channel_id, "Lounge").unwrap(),
            "the same name again is not a change"
        );
        // Trimmed like any name that comes off the network, and nothing left
        // to show is not a name.
        assert!(db
            .apply_owner_room_name(&channel_id, &format!("Lo\u{200B}bby {}", "x".repeat(100)))
            .unwrap());
        let trimmed = db.get_channel(&channel_id).unwrap().unwrap().name;
        assert!(!trimmed.contains('\u{200B}'));
        assert_eq!(trimmed.chars().count(), ROOM_NAME_MAX_CHARS);
        assert!(!db.apply_owner_room_name(&channel_id, "\u{200B}\u{FEFF}").unwrap());

        // An owner: the rename is stamped so the next one can be rationed.
        assert_eq!(db.get_channel(&channel_id).unwrap().unwrap().renamed_at, 0);
        db.rename_owned_channel(&channel_id, "Den", 1_234).unwrap();
        let renamed = db.get_channel(&channel_id).unwrap().unwrap();
        assert_eq!(renamed.name, "Den");
        assert_eq!(renamed.renamed_at, 1_234);
        assert_eq!(
            db.list_channels_lite().unwrap()[0].renamed_at,
            1_234,
            "the owner loop reads it from the roster query it already runs"
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// v57 adds the announce flag and the pin list to an existing profile,
    /// both starting off, and the policy write stores and clears them.
    #[test]
    fn announce_only_and_pins_migrate_and_apply() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-v57-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let channel_id = "ab".repeat(16);
        db.insert_channel(&channel_id, &"cd".repeat(32), "Lobby", "public", false, None, None)
            .expect("insert channel");
        // Back to a v56 profile, with the room already in it.
        {
            let conn = db.conn.lock();
            conn.execute_batch(
                "ALTER TABLE channels DROP COLUMN announce_only;
                 ALTER TABLE channels DROP COLUMN pinned_msg_ids;
                 DELETE FROM schema_version;
                 INSERT INTO schema_version (version) VALUES (56);",
            )
            .expect("roll back to v56");
        }
        drop(db);

        let db = Database::open_at(&path).expect("reopen and migrate");
        assert_eq!(db.schema_version(), MAX_SUPPORTED_SCHEMA_VERSION);
        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert!(!row.announce_only, "an upgraded room is open to everyone");
        assert!(row.pinned_msg_ids.is_empty());

        let pins = [[0xA1u8; 16], [0xB2u8; 16]];
        assert!(db.apply_owner_room_policy(&channel_id, true, &pins, None).unwrap());
        assert!(
            !db.apply_owner_room_policy(&channel_id, true, &pins, None).unwrap(),
            "the same policy again is not a change"
        );
        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert!(row.announce_only);
        assert_eq!(row.pinned_msg_ids, vec!["a1".repeat(16), "b2".repeat(16)]);
        assert_eq!(row.pinned_msg_id_bytes(), pins.to_vec());
        // The lite read the network loop republishes from carries them too.
        let lite = db.get_channel_lite(&channel_id).unwrap().unwrap();
        assert!(lite.announce_only);
        assert_eq!(lite.pinned_msg_ids.len(), 2);

        assert!(db.apply_owner_room_policy(&channel_id, false, &[], None).unwrap());
        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert!(!row.announce_only);
        assert!(row.pinned_msg_ids.is_empty());

        // Idempotent: opening again does not fail on columns that exist.
        drop(db);
        let again = Database::open_at(&path).expect("reopen at the current version");
        assert_eq!(again.schema_version(), MAX_SUPPORTED_SCHEMA_VERSION);

        drop(again);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// v58 adds the default language to an existing profile, starting at
    /// none; the policy write stores and clears it, and the create path sets it.
    /// v59 does the same for the Discover cache.
    #[test]
    fn channel_language_migrates_and_applies() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-v58-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let channel_id = "ab".repeat(16);
        db.insert_channel(&channel_id, &"cd".repeat(32), "Lobby", "public", false, None, None)
            .expect("insert channel");
        {
            let conn = db.conn.lock();
            conn.execute_batch(
                "ALTER TABLE channels DROP COLUMN language;
                 ALTER TABLE channel_index_cache DROP COLUMN language;
                 DELETE FROM schema_version;
                 INSERT INTO schema_version (version) VALUES (57);",
            )
            .expect("roll back to v57");
        }
        drop(db);

        let db = Database::open_at(&path).expect("reopen and migrate");
        assert_eq!(db.schema_version(), MAX_SUPPORTED_SCHEMA_VERSION);
        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert_eq!(row.language, "", "an upgraded room has no default language");

        assert!(db.apply_owner_room_policy(&channel_id, false, &[], Some("de")).unwrap());
        assert!(
            !db.apply_owner_room_policy(&channel_id, false, &[], Some("de")).unwrap(),
            "the same language again is not a change"
        );
        assert_eq!(db.get_channel(&channel_id).unwrap().unwrap().language, "de");
        assert_eq!(db.get_channel_lite(&channel_id).unwrap().unwrap().language, "de");
        assert_eq!(db.list_channels().unwrap()[0].language, "de");

        assert!(db.apply_owner_room_policy(&channel_id, false, &[], None).unwrap());
        assert_eq!(db.get_channel(&channel_id).unwrap().unwrap().language, "");

        let created = "ef".repeat(16);
        db.insert_channel_with_language(&created, &"01".repeat(32), "Tokyo", "public", false, None, None, "ja")
            .unwrap();
        assert_eq!(db.get_channel(&created).unwrap().unwrap().language, "ja");

        // v59: Discover's cache keeps the listing's language.
        let cached = |language: &str| CachedChannel {
            channel_id: created.clone(),
            pubkey: "01".repeat(32),
            name: "Tokyo".to_string(),
            language: language.to_string(),
        };
        db.cache_channel_listings(&[cached("ja")]).unwrap();
        assert_eq!(db.list_cached_channels().unwrap()[0].language, "ja");
        db.cache_channel_listings(&[cached("")]).unwrap();
        assert_eq!(db.list_cached_channels().unwrap()[0].language, "", "a cleared language clears");

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// A pin the owner removed from this device is reported for pruning; one
    /// merely not held — never synced, or trimmed from history — is not.
    #[test]
    fn only_removed_pins_are_reported_for_pruning() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-pin-prune-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let channel_id = "ab".repeat(16);
        db.insert_channel(&channel_id, &"cd".repeat(32), "Lobby", "public", true, None, None)
            .expect("insert channel");
        let kept = "11".repeat(16);
        let removed = "22".repeat(16);
        let never_held = "33".repeat(16);
        let author = "ee".repeat(32);
        db.insert_channel_message(&channel_id, &author, "received", "kept", &kept, 100, "", true)
            .expect("insert kept");
        let gone = db
            .insert_channel_message(&channel_id, &author, "received", "gone", &removed, 101, "", true)
            .expect("insert removed");
        assert!(db.delete_channel_message(&channel_id, gone).unwrap());

        let pins = vec![kept.clone(), removed.clone(), never_held.clone()];
        assert_eq!(db.channel_messages_removed(&channel_id, &pins).unwrap(), vec![removed]);

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn stored_pin_lists_skip_what_is_not_a_wire_id() {
        assert_eq!(
            parse_pinned_msg_ids(&format!("{},zz,, {} ,{}", "AB".repeat(16), "cd".repeat(16), "1".repeat(31))),
            vec!["ab".repeat(16), "cd".repeat(16)]
        );
        assert!(parse_pinned_msg_ids("").is_empty());
    }

    #[test]
    fn channels_round_trip_secrets_and_messages() {
        let path = std::env::temp_dir().join(format!(
            "ember-channels-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        assert_eq!(db.schema_version(), MAX_SUPPORTED_SCHEMA_VERSION);

        let channel_id = "ab".repeat(16);
        let pubkey = "cd".repeat(32);
        let seed = [0x11u8; 32];
        let join = [0x22u8; 32];
        db.insert_channel(
            &channel_id,
            &pubkey,
            "Lobby",
            "private",
            true,
            Some(&seed),
            Some(&join),
        )
        .expect("insert channel");
        assert_eq!(db.load_channel_owner_seed(&channel_id).unwrap(), Some(seed));
        assert_eq!(
            db.load_channel_join_secret(&channel_id).unwrap(),
            Some(join)
        );

        db.upsert_channel_member(&channel_id, &pubkey, "Ada", 100, None)
            .unwrap();
        let members = db.list_channel_members(&channel_id).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].nickname, "Ada");

        let banned = [0x33u8; 32];
        let banned_hex = hex::encode(banned);
        assert!(db
            .apply_channel_moderation(&channel_id, "topic", "welcome", 50, &[banned], &[], None, None, None, None, None, None)
            .unwrap());
        let ch = db.get_channel(&channel_id).unwrap().unwrap();
        assert_eq!(ch.topic, "topic");
        assert_eq!(ch.welcome, "welcome");
        assert!(db
            .channel_member_is_banned(&channel_id, &banned_hex)
            .unwrap());
        assert!(!db.channel_member_is_banned(&channel_id, &pubkey).unwrap());
        assert!(!db
            .apply_channel_moderation(&channel_id, "older", "stale", 10, &[], &[], None, None, None, None, None, None)
            .unwrap());
        let ch = db.get_channel(&channel_id).unwrap().unwrap();
        assert_eq!(ch.topic, "topic");
        assert!(db
            .apply_channel_moderation(&channel_id, "topic", "welcome", 60, &[], &[], None, None, None, None, None, None)
            .unwrap());
        assert!(!db
            .channel_member_is_banned(&channel_id, &banned_hex)
            .unwrap());

        let moderator = [0x44u8; 32];
        let mod_hex = hex::encode(moderator);
        assert!(db
            .apply_channel_moderation(&channel_id, "topic", "welcome", 70, &[], &[moderator], None, None, None, None, None, None)
            .unwrap());
        assert!(db
            .channel_member_is_moderator(&channel_id, &mod_hex)
            .unwrap());
        assert!(!db
            .channel_member_is_moderator(&channel_id, &pubkey)
            .unwrap());
        assert!(db
            .apply_channel_ban_action(&channel_id, &banned_hex, true, 80)
            .unwrap());
        assert!(
            !db.apply_channel_ban_action(&channel_id, &banned_hex, true, i64::MAX)
                .unwrap(),
            "a far-future gossip timestamp must not stick a ban past every owner snapshot"
        );
        assert!(db
            .channel_member_is_banned(&channel_id, &banned_hex)
            .unwrap());
        assert!(db
            .apply_channel_moderation(&channel_id, "topic", "welcome", 75, &[], &[moderator], None, None, None, None, None, None)
            .unwrap());
        assert!(
            db.channel_member_is_banned(&channel_id, &banned_hex)
                .unwrap(),
            "newer gossip ban must survive an older owner snapshot"
        );

        let msg_id = "aa".repeat(16);
        let id = db
            .insert_channel_message(
                &channel_id,
                &pubkey,
                "sent",
                "hello room",
                &msg_id,
                1_700_000_000,
                &"cd".repeat(64),
                true,
            )
            .unwrap();
        let msgs = db.get_channel_messages(&channel_id, 50, None).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].id, id);
        assert_eq!(msgs[0].message, "hello room");
        assert_eq!(msgs[0].timestamp, 1_700_000_000);
        let newer_id = "bb".repeat(16);
        db.insert_channel_message(
            &channel_id,
            &pubkey,
            "sent",
            "later line",
            &newer_id,
            1_700_000_100,
            &"ce".repeat(64),
            true,
        )
        .unwrap();
        let sync = db
            .list_channel_messages_for_sync(&channel_id, 0, 32)
            .unwrap();
        assert_eq!(sync.len(), 2);
        assert_eq!(
            sync[0].msg_id, newer_id,
            "catch-up with since=0 must offer newest first, not oldest"
        );

        let listed = db.list_channels().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "Lobby");
        assert!(listed[0].is_owner);

        assert!(db.delete_channel(&channel_id, None).unwrap());
        assert!(db.list_channels().unwrap().is_empty());
        assert!(
            db.list_channel_members(&channel_id).unwrap().is_empty(),
            "no member is preserved when the caller keeps nobody"
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn a_channel_edit_needs_the_author_the_window_and_a_newer_revision() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-edit-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "ab".repeat(16);
        let author = "cd".repeat(32);
        let other = "ef".repeat(32);
        db.insert_channel(&channel_id, &author, "Lobby", "public", true, None, None)
            .unwrap();
        let msg_id = "aa".repeat(16);
        let sent = chrono::Utc::now().timestamp();
        let id = db
            .insert_channel_message(
                &channel_id,
                &author,
                "sent",
                "orignal typo",
                &msg_id,
                sent,
                &"11".repeat(64),
                true,
            )
            .unwrap();

        // Somebody else's signature over the same line is not authority to change
        // it, however valid the signature itself was.
        assert_eq!(
            db.apply_channel_message_edit(
                &channel_id, &msg_id, &other, sent, sent + 5, "hijacked", "22", sent + 5
            )
            .unwrap(),
            ChannelEditOutcome::NotAuthor
        );

        assert_eq!(
            db.apply_channel_message_edit(
                &channel_id, &msg_id, &author, sent, sent + 30, "original typo", "33", sent + 30
            )
            .unwrap(),
            ChannelEditOutcome::Applied(id)
        );
        let rows = db.get_channel_messages(&channel_id, 10, None).unwrap();
        assert_eq!(rows[0].message, "original typo");
        assert_eq!(rows[0].edited_at, sent + 30);

        // A revision we already have, or an older one arriving late over a slower
        // path, must not undo the newer text.
        assert_eq!(
            db.apply_channel_message_edit(
                &channel_id, &msg_id, &author, sent, sent + 10, "stale", "44", sent + 40
            )
            .unwrap(),
            ChannelEditOutcome::NotNewer
        );
        assert_eq!(
            db.get_channel_messages(&channel_id, 10, None).unwrap()[0].message,
            "original typo"
        );

        // Past the window on our own clock, which is the half the author cannot
        // lie about: `first_seen_at` was stamped when the row landed.
        assert_eq!(
            db.apply_channel_message_edit(
                &channel_id,
                &msg_id,
                &author,
                sent,
                sent + 60,
                "too late",
                "55",
                sent + 86_400,
            )
            .unwrap(),
            ChannelEditOutcome::OutsideWindow
        );

        // A revision for a line this device never held stands on its own, which is
        // how a member who was away receives it — provided the id is its signer's.
        let unseen = hex::encode(crate::network::ember::channel::new_chat_msg_id(
            &hex::decode(&channel_id).unwrap().try_into().unwrap(),
            &hex::decode(&other).unwrap().try_into().unwrap(),
            sent,
        ));
        let created = db
            .apply_channel_message_edit(
                &channel_id, &unseen, &other, sent, sent + 20, "caught up", "66", sent + 20,
            )
            .unwrap();
        assert!(matches!(created, ChannelEditOutcome::Created(_)));
        let sync = db.list_channel_messages_for_sync(&channel_id, 0, 32).unwrap();
        assert!(
            sync.iter().any(|row| row.msg_id == unseen && !row.edit_sig.is_empty()),
            "a row known only as a revision must still be re-servable"
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    fn temp_db_path(tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ember-{tag}-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn remove_temp_db(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// A member proven to read sealed offers is remembered across a restart
    /// under its newest proof, and forgotten once that proof is too old.
    #[test]
    fn sealed_offer_readers_survive_a_restart_and_age_out() {
        let path = temp_db_path("sealed-readers");
        let (alice, bob) = ("A1".repeat(32), "b0".repeat(32));
        {
            let db = Database::open_at(&path).expect("open db");
            assert_eq!(db.sealed_offer_reader_seen_at(&alice).unwrap(), None);
            db.note_sealed_offer_reader(&alice, 1_000, 0, 16).unwrap();
            db.note_sealed_offer_reader(&alice, 900, 0, 16).unwrap();
            db.note_sealed_offer_reader(&bob, 500, 0, 16).unwrap();
            assert_eq!(
                db.sealed_offer_reader_seen_at(&alice.to_ascii_lowercase()).unwrap(),
                Some(1_000),
                "an older proof does not move it back, and case does not matter"
            );
        }
        let db = Database::open_at(&path).expect("reopen db");
        assert_eq!(db.sealed_offer_reader_seen_at(&alice).unwrap(), Some(1_000));
        assert_eq!(db.sealed_offer_reader_seen_at(&bob).unwrap(), Some(500));
        db.note_sealed_offer_reader(&alice, 2_000, 600, 16).unwrap();
        assert_eq!(db.sealed_offer_reader_seen_at(&bob).unwrap(), None, "aged out");
        assert_eq!(db.sealed_offer_reader_seen_at(&alice).unwrap(), Some(2_000));
        drop(db);
        remove_temp_db(&path);
    }

    /// A proof written while the clock ran far ahead gives way to the next
    /// proof, and one nobody renews is forgotten, rather than either counting
    /// until that date plus the keep time. A little ahead still wins.
    #[test]
    fn a_sealed_offer_reader_proven_under_a_fast_clock_is_not_kept() {
        use crate::network::ember::xfer::SEALED_OFFER_READER_MAX_FUTURE_SECS as AHEAD;
        let path = temp_db_path("sealed-readers-future");
        let db = Database::open_at(&path).expect("open db");
        let (alice, bob, carol) = ("a1".repeat(32), "b0".repeat(32), "c2".repeat(32));
        let now = 1_000_000;
        db.note_sealed_offer_reader(&alice, now + AHEAD + 1, 0, 16).unwrap();
        db.note_sealed_offer_reader(&bob, now + AHEAD + 1, 0, 16).unwrap();
        db.note_sealed_offer_reader(&carol, now + 60, 0, 16).unwrap();

        db.note_sealed_offer_reader(&alice, now, 0, 16).unwrap();
        assert_eq!(db.sealed_offer_reader_seen_at(&alice).unwrap(), Some(now), "overwritten");
        assert_eq!(db.sealed_offer_reader_seen_at(&bob).unwrap(), None, "forgotten");
        db.note_sealed_offer_reader(&carol, now, 0, 16).unwrap();
        assert_eq!(db.sealed_offer_reader_seen_at(&carol).unwrap(), Some(now + 60));
        drop(db);
        remove_temp_db(&path);
    }

    /// However many identities prove themselves, only the most recently
    /// proven are kept.
    #[test]
    fn sealed_offer_readers_are_capped_newest_first() {
        let path = temp_db_path("sealed-readers-cap");
        let db = Database::open_at(&path).expect("open db");
        let member = |i: u8| format!("{i:02x}").repeat(32);
        for i in 0..6u8 {
            db.note_sealed_offer_reader(&member(i), 1_000 + i as i64, 0, 4).unwrap();
        }
        for i in 0..2u8 {
            assert_eq!(db.sealed_offer_reader_seen_at(&member(i)).unwrap(), None, "oldest {i} made way");
        }
        for i in 2..6u8 {
            assert_eq!(db.sealed_offer_reader_seen_at(&member(i)).unwrap(), Some(1_000 + i as i64));
        }
        db.note_sealed_offer_reader(&member(2), 2_000, 0, 4).unwrap();
        db.note_sealed_offer_reader(&member(9), 2_001, 0, 4).unwrap();
        assert_eq!(db.sealed_offer_reader_seen_at(&member(2)).unwrap(), Some(2_000), "renewed, so kept");
        assert_eq!(db.sealed_offer_reader_seen_at(&member(3)).unwrap(), None);
        drop(db);
        remove_temp_db(&path);
    }

    #[test]
    fn a_reply_is_stored_as_signed_and_read_back_as_body_and_quote() {
        use crate::network::ember::channel::with_reply_trailer;
        let path = temp_db_path("channel-reply");
        let db = Database::open_at(&path).expect("open db");
        let channel_id = "ab".repeat(16);
        let alice = "a1".repeat(32);
        let bob = "b0".repeat(32);
        db.insert_channel(&channel_id, &bob, "Lobby", "public", false, None, None)
            .unwrap();
        let now = chrono::Utc::now().timestamp();

        let parent_id = bound_chat_msg_id(&channel_id, &alice, now);
        let parent_bytes: [u8; 16] = hex::decode(&parent_id).unwrap().try_into().unwrap();
        let parent_row = db
            .insert_channel_message(
                &channel_id, &alice, "received", "the plan **is** set", &parent_id, now,
                &"11".repeat(64), false,
            )
            .unwrap();
        let reply_wire = with_reply_trailer("agreed", Some(&parent_bytes));
        let reply_id = bound_chat_msg_id(&channel_id, &bob, now + 1);
        let reply_row = db
            .insert_channel_message(
                &channel_id, &bob, "sent", &reply_wire, &reply_id, now + 1, &"22".repeat(64),
                true,
            )
            .unwrap();

        let rows = db.get_channel_messages(&channel_id, 10, None).unwrap();
        let reply = rows.iter().find(|row| row.id == reply_row).unwrap();
        assert_eq!(reply.message, "agreed", "the member sees the body, not the trailer");
        assert_eq!(reply.reply_to.as_deref(), Some(parent_id.as_str()));
        assert_eq!(
            reply.reply_parent,
            Some(ChannelReplyParent {
                id: parent_row,
                sender_pubkey: alice.clone(),
                excerpt: "the plan **is** set".into(),
            })
        );
        assert!(!reply.reply_parent_deleted);
        let parent = rows.iter().find(|row| row.id == parent_row).unwrap();
        assert_eq!(parent.reply_to, None);

        // What goes back on the wire is exactly what the author signed.
        let sync = db.list_channel_messages_for_sync(&channel_id, 0, 32).unwrap();
        let served = sync.iter().find(|row| row.msg_id == reply_id).unwrap();
        assert_eq!(served.message, reply_wire);

        let hits = db.search_channel_messages(&channel_id, "agreed", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].message, "agreed");

        // The quote follows the parent: revised, then removed from this device.
        assert!(matches!(
            db.apply_channel_message_edit(
                &channel_id, &parent_id, &alice, now, now + 30, "the plan changed", "33", now + 30,
            )
            .unwrap(),
            ChannelEditOutcome::Applied(_)
        ));
        let revised = db.channel_reply_lookup(&channel_id, &parent_id).unwrap();
        assert_eq!(revised.parent.unwrap().excerpt, "the plan changed");
        assert!(db.delete_channel_message(&channel_id, parent_row).unwrap());
        let rows = db.get_channel_messages(&channel_id, 10, None).unwrap();
        let reply = rows.iter().find(|row| row.id == reply_row).unwrap();
        assert_eq!(reply.reply_to.as_deref(), Some(parent_id.as_str()));
        assert_eq!(reply.reply_parent, None);
        assert!(reply.reply_parent_deleted, "removed here, as opposed to never received");

        // A parent this device never held is simply missing.
        let unheld = db.channel_reply_lookup(&channel_id, &"cc".repeat(16)).unwrap();
        assert_eq!(unheld, ChannelReplyLookup::default());

        // A line naming itself is not a reply.
        let own_id = bound_chat_msg_id(&channel_id, &alice, now + 2);
        let own_bytes: [u8; 16] = hex::decode(&own_id).unwrap().try_into().unwrap();
        let selfish = db
            .insert_channel_message(
                &channel_id,
                &alice,
                "received",
                &with_reply_trailer("me again", Some(&own_bytes)),
                &own_id,
                now + 2,
                &"44".repeat(64),
                false,
            )
            .unwrap();
        let rows = db.get_channel_messages(&channel_id, 10, None).unwrap();
        let selfish = rows.iter().find(|row| row.id == selfish).unwrap();
        assert_eq!(selfish.reply_to, None);
        assert_eq!(selfish.message, "me again");

        drop(db);
        remove_temp_db(&path);
    }

    #[test]
    fn an_edit_of_a_reply_keeps_the_reference_it_was_sent_with() {
        use crate::network::ember::channel::with_reply_trailer;
        let path = temp_db_path("channel-reply-edit");
        let db = Database::open_at(&path).expect("open db");
        let channel_id = "ab".repeat(16);
        let author = "cd".repeat(32);
        db.insert_channel(&channel_id, &author, "Lobby", "public", true, None, None)
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        let parent = [0x5Au8; 16];
        let parent_hex = hex::encode(parent);

        let msg_id = bound_chat_msg_id(&channel_id, &author, now);
        let id = db
            .insert_channel_message(
                &channel_id,
                &author,
                "sent",
                &with_reply_trailer("fist draft", Some(&parent)),
                &msg_id,
                now,
                &"11".repeat(64),
                true,
            )
            .unwrap();
        let target = db.channel_message_edit_target(&channel_id, id).unwrap().unwrap();
        assert_eq!(target.reply_to.as_deref(), Some(parent_hex.as_str()));

        let revised = with_reply_trailer("first draft", Some(&parent));
        assert_eq!(
            db.apply_channel_message_edit(
                &channel_id, &msg_id, &author, now, now + 10, &revised, "22", now + 10,
            )
            .unwrap(),
            ChannelEditOutcome::Applied(id)
        );
        let row = &db.get_channel_messages(&channel_id, 10, None).unwrap()[0];
        assert_eq!(row.message, "first draft");
        assert_eq!(row.reply_to.as_deref(), Some(parent_hex.as_str()));
        let sync = db.list_channel_messages_for_sync(&channel_id, 0, 32).unwrap();
        assert_eq!(sync[0].message, revised, "the revision is re-served as signed");

        // A revision cannot move or drop the quote once people may have answered
        // it: the column is fixed when the row is written.
        db.apply_channel_message_edit(
            &channel_id, &msg_id, &author, now, now + 20, "no trailer", "33", now + 20,
        )
        .unwrap();
        let row = &db.get_channel_messages(&channel_id, 10, None).unwrap()[0];
        assert_eq!(row.message, "no trailer");
        assert_eq!(row.reply_to.as_deref(), Some(parent_hex.as_str()));

        // A revision standing in for a line never held brings its reference.
        let other = "ef".repeat(32);
        let unseen = bound_chat_msg_id(&channel_id, &other, now);
        let created = db
            .apply_channel_message_edit(
                &channel_id,
                &unseen,
                &other,
                now,
                now + 5,
                &with_reply_trailer("caught up", Some(&parent)),
                "44",
                now + 5,
            )
            .unwrap();
        let ChannelEditOutcome::Created(created) = created else {
            panic!("expected the revision to create the line, got {created:?}");
        };
        let rows = db.get_channel_messages(&channel_id, 10, None).unwrap();
        let row = rows.iter().find(|row| row.id == created).unwrap();
        assert_eq!(row.message, "caught up");
        assert_eq!(row.reply_to.as_deref(), Some(parent_hex.as_str()));

        drop(db);
        remove_temp_db(&path);
    }

    #[test]
    fn migration_56_adds_reply_to_beside_an_existing_history() {
        use crate::network::ember::channel::with_reply_trailer;
        let path = temp_db_path("channel-reply-migration");
        let channel_id = "ab".repeat(16);
        let author = "cd".repeat(32);
        let now = chrono::Utc::now().timestamp();
        {
            let db = Database::open_at(&path).expect("open db");
            db.insert_channel(&channel_id, &author, "Lobby", "public", true, None, None)
                .unwrap();
            db.insert_channel_message(
                &channel_id, &author, "sent", "from before", "m1", now, "", true,
            )
            .unwrap();
            // Back to a v55 profile: same history, no column.
            let conn = db.conn.lock();
            conn.execute_batch(
                "ALTER TABLE channel_messages DROP COLUMN reply_to;
                 DELETE FROM schema_version; INSERT INTO schema_version (version) VALUES (55);",
            )
            .expect("roll back to v55");
        }
        let db = Database::open_at(&path).expect("migrate from v55");
        assert_eq!(db.schema_version(), MAX_SUPPORTED_SCHEMA_VERSION);
        let rows = db.get_channel_messages(&channel_id, 10, None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].message, "from before");
        assert_eq!(rows[0].reply_to, None);

        let parent = [0x11u8; 16];
        db.insert_channel_message(
            &channel_id,
            &author,
            "sent",
            &with_reply_trailer("after", Some(&parent)),
            "m2",
            now + 1,
            "",
            true,
        )
        .unwrap();
        let rows = db.get_channel_messages(&channel_id, 10, None).unwrap();
        assert_eq!(rows[0].message, "after");
        assert_eq!(rows[0].reply_to, Some(hex::encode(parent)));

        drop(db);
        remove_temp_db(&path);
    }

    fn bound_chat_msg_id(channel_id: &str, author: &str, timestamp: i64) -> String {
        hex::encode(crate::network::ember::channel::new_chat_msg_id(
            &hex::decode(channel_id).unwrap().try_into().unwrap(),
            &hex::decode(author).unwrap().try_into().unwrap(),
            timestamp,
        ))
    }

    fn open_channel_test_db(tag: &str) -> (Database, std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "ember-{tag}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ember.db");
        let db = Database::open_at(&path).unwrap();
        (db, path, dir)
    }

    /// Stands in for a row an older build stored from a revision it took on
    /// trust: sender and id rewritten after the fact, which the body's
    /// encryption does not bind.
    fn plant_edit_only_row(
        db: &Database,
        channel_id: &str,
        sender: &str,
        msg_id: &str,
        original_ts: i64,
        edited_at: i64,
        text: &str,
    ) -> i64 {
        let scratch = bound_chat_msg_id(channel_id, sender, original_ts);
        let ChannelEditOutcome::Created(id) = db
            .apply_channel_message_edit(
                channel_id, &scratch, sender, original_ts, edited_at, text, &"77".repeat(64),
                edited_at,
            )
            .unwrap()
        else {
            panic!("scratch revision should create its row");
        };
        db.conn
            .lock()
            .execute(
                "UPDATE channel_messages SET sender_pubkey = ?1, msg_id = ?2 WHERE id = ?3",
                params![sender, msg_id, id],
            )
            .unwrap();
        id
    }

    #[test]
    fn a_forged_channel_edit_cannot_claim_another_members_line_before_it_arrives() {
        let (db, path, dir) = open_channel_test_db("channel-forged-edit");
        let channel_id = "ab".repeat(16);
        let victim = "cd".repeat(32);
        let mallory = "ef".repeat(32);
        db.insert_channel(&channel_id, &victim, "Lobby", "public", false, None, None)
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        let sent = now - 60;

        // A new id bound to the victim, and one minted before ids were bound.
        for msg_id in [bound_chat_msg_id(&channel_id, &victim, sent), "aa".repeat(16)] {
            assert_eq!(
                db.apply_channel_message_edit(
                    &channel_id, &msg_id, &mallory, sent, sent + 5, "hijacked", "22", now,
                )
                .unwrap(),
                ChannelEditOutcome::NotAuthor,
            );
            assert!(!db.channel_message_exists(&channel_id, &msg_id).unwrap());
            assert!(!db
                .channel_message_held(&channel_id, &msg_id, &victim, sent)
                .unwrap());

            let id = db
                .insert_channel_message(
                    &channel_id, &victim, "received", "genuine words", &msg_id, sent,
                    &"11".repeat(64), false,
                )
                .unwrap();
            let rows = db.get_channel_messages(&channel_id, 50, None).unwrap();
            let row = rows.iter().find(|r| r.msg_id == msg_id).unwrap();
            assert_eq!(row.id, id);
            assert_eq!(row.sender_pubkey, victim);
            assert_eq!(row.message, "genuine words");
            assert_eq!(row.edited_at, 0);
        }
        let sync = db.list_channel_messages_for_sync(&channel_id, 0, 32).unwrap();
        assert_eq!(sync.len(), 2);
        assert!(sync.iter().all(|r| r.sender_pubkey == victim));

        drop(db);
        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_channel_authors_edit_before_the_line_stands_in_for_it_and_cannot_be_re_dated() {
        let (db, path, dir) = open_channel_test_db("channel-early-edit");
        let channel_id = "ab".repeat(16);
        let author = "cd".repeat(32);
        db.insert_channel(&channel_id, &author, "Lobby", "public", false, None, None)
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        let sent = now - 60;
        let msg_id = bound_chat_msg_id(&channel_id, &author, sent);

        // Claiming a later original to stretch the window breaks the binding.
        assert_eq!(
            db.apply_channel_message_edit(
                &channel_id, &msg_id, &author, sent + 50, sent + 55, "late", "33", now,
            )
            .unwrap(),
            ChannelEditOutcome::NotAuthor,
        );
        assert_eq!(
            db.apply_channel_message_edit(
                &channel_id, &msg_id, &author, sent, sent + 3_000, "late", "33", now,
            )
            .unwrap(),
            ChannelEditOutcome::OutsideWindow,
        );

        let ChannelEditOutcome::Created(id) = db
            .apply_channel_message_edit(
                &channel_id, &msg_id, &author, sent, sent + 30, "fixed", "44", now,
            )
            .unwrap()
        else {
            panic!("the author's own revision must stand in for the line");
        };
        // The original arriving afterwards is a repeat, not a replacement.
        assert!(db
            .channel_message_held(&channel_id, &msg_id, &author, sent)
            .unwrap());
        assert_eq!(
            db.insert_channel_message(
                &channel_id, &author, "received", "fxied", &msg_id, sent, &"11".repeat(64), false,
            )
            .unwrap(),
            id
        );
        let rows = db.get_channel_messages(&channel_id, 50, None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].sender_pubkey, author);
        assert_eq!(rows[0].message, "fixed");
        assert_eq!(rows[0].edited_at, sent + 30);
        let sync = db.list_channel_messages_for_sync(&channel_id, 0, 32).unwrap();
        assert_eq!(sync.len(), 1);
        assert_eq!(sync[0].sender_pubkey, author);
        assert!(!sync[0].edit_sig.is_empty());

        drop(db);
        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_channel_row_planted_under_someone_elses_id_is_never_served_or_taken_over() {
        let (db, path, dir) = open_channel_test_db("channel-planted-row");
        let channel_id = "ab".repeat(16);
        let victim = "cd".repeat(32);
        let mallory = "ef".repeat(32);
        db.insert_channel(&channel_id, &victim, "Lobby", "public", false, None, None)
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        let sent = now - 60;
        let bound = bound_chat_msg_id(&channel_id, &victim, sent);
        let legacy = "aa".repeat(16);
        for msg_id in [&bound, &legacy] {
            plant_edit_only_row(&db, &channel_id, &mallory, msg_id, sent, sent + 5, "hijacked");
        }

        let sync = db.list_channel_messages_for_sync(&channel_id, 0, 32).unwrap();
        assert!(
            sync.iter().all(|r| r.sender_pubkey != mallory),
            "a revision taken on trust must not be re-served under the id it claimed"
        );
        assert!(sync.is_empty());

        // Under an id bound to the victim, their genuine line displaces it.
        assert!(!db
            .channel_message_held(&channel_id, &bound, &victim, sent)
            .unwrap());
        db.insert_channel_message(
            &channel_id, &victim, "received", "genuine words", &bound, sent, &"11".repeat(64),
            false,
        )
        .unwrap();

        // Under an unbound id nobody can prove ownership, and the row may be a
        // genuine revision an older build stored: no signed line — the
        // victim's or a third member's — may take it over.
        let third = "0f".repeat(32);
        for sender in [&victim, &third] {
            assert!(db
                .channel_message_held(&channel_id, &legacy, sender, sent)
                .unwrap());
            db.insert_channel_message(
                &channel_id, sender, "received", "takeover", &legacy, sent, &"11".repeat(64),
                false,
            )
            .unwrap();
        }

        let rows = db.get_channel_messages(&channel_id, 50, None).unwrap();
        assert_eq!(rows.len(), 2);
        let row = |id: &str| rows.iter().find(|r| r.msg_id == id).unwrap().clone();
        assert_eq!(row(&bound).sender_pubkey, victim);
        assert_eq!(row(&bound).message, "genuine words");
        assert_eq!(row(&legacy).sender_pubkey, mallory);
        assert_eq!(row(&legacy).message, "hijacked");
        let sync = db.list_channel_messages_for_sync(&channel_id, 0, 32).unwrap();
        assert_eq!(sync.len(), 1);
        assert_eq!(sync[0].msg_id, bound);
        assert_eq!(sync[0].sender_pubkey, victim);

        drop(db);
        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_channel_line_squatting_on_a_bound_id_gives_way_to_its_author() {
        let (db, path, dir) = open_channel_test_db("channel-squat");
        let channel_id = "ab".repeat(16);
        let victim = "cd".repeat(32);
        let mallory = "ef".repeat(32);
        db.insert_channel(&channel_id, &victim, "Lobby", "public", false, None, None)
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        let sent = now - 60;

        // Mallory's own signed line, first to arrive under the victim's id.
        let first = bound_chat_msg_id(&channel_id, &victim, sent);
        db.insert_channel_message(
            &channel_id, &mallory, "received", "squat", &first, sent, &"22".repeat(64), false,
        )
        .unwrap();
        assert!(!db
            .channel_message_held(&channel_id, &first, &victim, sent)
            .unwrap());
        db.insert_channel_message(
            &channel_id, &victim, "received", "genuine", &first, sent, &"11".repeat(64), false,
        )
        .unwrap();
        // And once the author holds it, a later squat is just a repeat.
        assert!(db
            .channel_message_held(&channel_id, &first, &mallory, sent)
            .unwrap());
        db.insert_channel_message(
            &channel_id, &mallory, "received", "squat", &first, sent, &"22".repeat(64), false,
        )
        .unwrap();

        // The author's revision displaces a squatter the same way.
        let second = bound_chat_msg_id(&channel_id, &victim, sent);
        db.insert_channel_message(
            &channel_id, &mallory, "received", "squat", &second, sent, &"22".repeat(64), false,
        )
        .unwrap();
        assert!(matches!(
            db.apply_channel_message_edit(
                &channel_id, &second, &victim, sent, sent + 10, "genuine, edited", "33", now,
            )
            .unwrap(),
            ChannelEditOutcome::Created(_)
        ));

        let rows = db.get_channel_messages(&channel_id, 50, None).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.sender_pubkey == victim));
        let sync = db.list_channel_messages_for_sync(&channel_id, 0, 32).unwrap();
        assert_eq!(sync.len(), 2);
        assert!(sync.iter().all(|r| r.sender_pubkey == victim));

        drop(db);
        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_unbound_early_channel_edit_is_re_judged_on_the_originals_real_timestamp() {
        let (db, path, dir) = open_channel_test_db("channel-rejudge");
        let channel_id = "ab".repeat(16);
        let author = "cd".repeat(32);
        db.insert_channel(&channel_id, &author, "Lobby", "public", false, None, None)
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        let sent = now - 7_200;
        let legacy = "aa".repeat(16);
        let honest = "bb".repeat(16);
        // An older build took both revisions on trust. One claimed an original
        // an hour later than the line really was, to stay inside the window.
        plant_edit_only_row(&db, &channel_id, &author, &legacy, sent + 3_600, sent + 3_630, "rewritten");
        plant_edit_only_row(&db, &channel_id, &author, &honest, sent, sent + 30, "fixed");

        for msg_id in [&legacy, &honest] {
            db.insert_channel_message(
                &channel_id, &author, "received", "as sent", msg_id, sent, &"11".repeat(64), false,
            )
            .unwrap();
        }
        let rows = db.get_channel_messages(&channel_id, 50, None).unwrap();
        let by_id = |id: &str| rows.iter().find(|r| r.msg_id == id).unwrap().clone();
        assert_eq!(by_id(&legacy).message, "as sent");
        assert_eq!(by_id(&legacy).edited_at, 0);
        assert_eq!(by_id(&honest).message, "fixed");

        drop(db);
        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_future_dated_channel_edit_neither_lands_nor_lifts_the_sync_watermark() {
        let (db, path, dir) = open_channel_test_db("channel-future-edit");
        let channel_id = "ab".repeat(16);
        let author = "cd".repeat(32);
        db.insert_channel(&channel_id, &author, "Lobby", "public", false, None, None)
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        let skew = crate::network::ember::channel::CHANNEL_GOSSIP_MAX_FUTURE_SKEW_SECS;

        let far = now + 10 * 365 * 86_400;
        let far_id = bound_chat_msg_id(&channel_id, &author, far);
        assert_eq!(
            db.apply_channel_message_edit(&channel_id, &far_id, &author, far, far + 5, "x", "22", now)
                .unwrap(),
            ChannelEditOutcome::OutsideWindow,
        );
        let zero_id = bound_chat_msg_id(&channel_id, &author, 0);
        assert_eq!(
            db.apply_channel_message_edit(&channel_id, &zero_id, &author, 0, 5, "x", "22", now)
                .unwrap(),
            ChannelEditOutcome::OutsideWindow,
        );
        assert!(!db.channel_message_exists(&channel_id, &far_id).unwrap());

        // A held line cannot be pinned by a revision dated past the skew either.
        let sent = now - 60;
        let held = bound_chat_msg_id(&channel_id, &author, sent);
        db.insert_channel_message(
            &channel_id, &author, "received", "hi", &held, sent, &"11".repeat(64), false,
        )
        .unwrap();
        assert_eq!(
            db.apply_channel_message_edit(
                &channel_id, &held, &author, sent, now + skew + 60, "pinned", "33", now,
            )
            .unwrap(),
            ChannelEditOutcome::OutsideWindow,
        );

        // A far-future row an older build stored must not become the watermark.
        db.insert_channel_message(
            &channel_id, &author, "received", "from the future", &"aa".repeat(16), far,
            &"11".repeat(64), false,
        )
        .unwrap();
        assert_eq!(db.latest_channel_message_timestamp(&channel_id).unwrap(), sent);

        drop(db);
        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_channel_sync_page_reads_past_rows_it_cannot_serve() {
        let (db, path, dir) = open_channel_test_db("channel-sync-paging");
        let channel_id = "ab".repeat(16);
        let victim = "cd".repeat(32);
        let mallory = "ef".repeat(32);
        db.insert_channel(&channel_id, &victim, "Lobby", "public", false, None, None)
            .unwrap();
        // More unservable rows than one page, all ahead of the servable ones.
        for n in 0..40 {
            let ts = 1_000 + n;
            let id = bound_chat_msg_id(&channel_id, &victim, ts);
            plant_edit_only_row(&db, &channel_id, &mallory, &id, ts, ts + 5, "hijacked");
        }
        for n in 0..3 {
            let ts = 2_000 + n;
            db.insert_channel_message(
                &channel_id, &victim, "received", "servable",
                &bound_chat_msg_id(&channel_id, &victim, ts), ts, &"11".repeat(64), false,
            )
            .unwrap();
        }
        let sync = db.list_channel_messages_for_sync(&channel_id, 1, 32).unwrap();
        assert_eq!(sync.len(), 3, "a page of filtered rows must not stall the walk");
        assert!(sync.iter().all(|r| r.sender_pubkey == victim));

        drop(db);
        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn deleting_a_channel_squatter_does_not_bury_the_genuine_line() {
        let (db, path, dir) = open_channel_test_db("channel-squat-tombstone");
        let channel_id = "ab".repeat(16);
        let victim = "cd".repeat(32);
        let mallory = "ef".repeat(32);
        db.insert_channel(&channel_id, &victim, "Lobby", "public", false, None, None)
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        let sent = now - 60;

        let first = bound_chat_msg_id(&channel_id, &victim, sent);
        let squat = db
            .insert_channel_message(
                &channel_id, &mallory, "received", "squat", &first, sent, &"22".repeat(64), false,
            )
            .unwrap();
        assert!(db.delete_channel_message(&channel_id, squat).unwrap());
        assert!(db
            .channel_message_forgotten(&channel_id, &first, &mallory)
            .unwrap());
        assert!(!db
            .channel_message_forgotten(&channel_id, &first, &victim.to_ascii_uppercase())
            .unwrap());
        db.insert_channel_message(
            &channel_id, &victim, "received", "genuine", &first, sent, &"11".repeat(64), false,
        )
        .unwrap();

        // The author's revision is not refused as forgotten either.
        let second = bound_chat_msg_id(&channel_id, &victim, sent);
        let squat = db
            .insert_channel_message(
                &channel_id, &mallory, "received", "squat", &second, sent, &"22".repeat(64), false,
            )
            .unwrap();
        assert!(db.delete_channel_message(&channel_id, squat).unwrap());
        assert!(matches!(
            db.apply_channel_message_edit(
                &channel_id, &second, &victim, sent, sent + 10, "genuine, edited", "33", now,
            )
            .unwrap(),
            ChannelEditOutcome::Created(_)
        ));

        // Deleting the author's own line under their id forgets it for everyone.
        let genuine = db
            .get_channel_messages(&channel_id, 50, None)
            .unwrap()
            .into_iter()
            .find(|r| r.msg_id == first)
            .unwrap();
        assert_eq!(genuine.sender_pubkey, victim);
        assert!(db.delete_channel_message(&channel_id, genuine.id).unwrap());
        assert!(db.channel_message_forgotten(&channel_id, &first, &victim).unwrap());
        assert!(db.channel_message_forgotten(&channel_id, &first, &mallory).unwrap());

        drop(db);
        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn channel_reactions_are_newest_wins_and_do_not_outlive_their_message() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-reactions-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "ab".repeat(16);
        let me = "cd".repeat(32);
        let them = "ef".repeat(32);
        db.insert_channel(&channel_id, &me, "Lobby", "public", true, None, None)
            .unwrap();
        let msg_id = "aa".repeat(16);
        let id = db
            .insert_channel_message(
                &channel_id,
                &me,
                "sent",
                "worth a vote",
                &msg_id,
                1_700_000_000,
                &"11".repeat(64),
                true,
            )
            .unwrap();

        assert!(db
            .set_channel_message_reaction(&channel_id, &msg_id, &me, 1, 10, "aa")
            .unwrap());
        assert!(db
            .set_channel_message_reaction(&channel_id, &msg_id, &them, 2, 11, "bb")
            .unwrap());
        let tally = db.channel_message_reactions(&channel_id).unwrap();
        assert_eq!(tally.len(), 2);

        // One row per member: changing your mind replaces rather than accumulates.
        assert!(db
            .set_channel_message_reaction(&channel_id, &msg_id, &me, 2, 20, "cc")
            .unwrap());
        let tally = db.channel_message_reactions(&channel_id).unwrap();
        assert_eq!(tally.len(), 2);
        assert!(tally.iter().all(|(_, _, reaction)| *reaction == 2));

        // A stale frame arriving late must not undo the newer claim.
        assert!(!db
            .set_channel_message_reaction(&channel_id, &msg_id, &me, 1, 15, "dd")
            .unwrap());
        assert!(db
            .channel_message_reactions(&channel_id)
            .unwrap()
            .iter()
            .all(|(_, _, reaction)| *reaction == 2));

        // Withdrawn reactions stay on disk to carry their timestamp, but stop
        // being counted.
        assert!(db
            .set_channel_message_reaction(&channel_id, &msg_id, &them, 0, 30, "ee")
            .unwrap());
        assert_eq!(db.channel_message_reactions(&channel_id).unwrap().len(), 1);
        assert!(
            !db.set_channel_message_reaction(&channel_id, &msg_id, &them, 2, 25, "ff")
                .unwrap(),
            "a withdrawal must not be undone by an older frame reasserting the reaction"
        );

        // Forgetting the line forgets what was voted on it, or the rows outlive
        // every bubble that could show them.
        assert!(db.delete_channel_message(&channel_id, id).unwrap());
        assert!(
            db.channel_message_reactions(&channel_id).unwrap().is_empty(),
            "reactions must not survive the message they belong to"
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn channel_reactions_keep_codes_this_build_does_not_draw_and_read_back_in_order() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-reaction-codes-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "ab".repeat(16);
        let me = "cd".repeat(32);
        let ada = "a1".repeat(32);
        let bo = "b2".repeat(32);
        let later = "c3".repeat(32);
        db.insert_channel(&channel_id, &me, "Lobby", "public", true, None, None)
            .unwrap();
        let msg_id = "aa".repeat(16);
        db.insert_channel_message(
            &channel_id,
            &me,
            "sent",
            "party time",
            &msg_id,
            1_700_000_000,
            &"11".repeat(64),
            true,
        )
        .unwrap();

        // Inserted out of time order, so the read has to be what orders them.
        db.set_channel_message_reaction(&channel_id, &msg_id, &bo, 8, 30, "bb")
            .unwrap();
        db.set_channel_message_reaction(&channel_id, &msg_id, &ada, 17, 20, "aa")
            .unwrap();
        // A code a newer build drew: stored like any other so it is re-served
        // to the rest of the room rather than lost at this hop.
        db.set_channel_message_reaction(&channel_id, &msg_id, &later, 250, 40, "cc")
            .unwrap();

        let rows = db.channel_message_reactions(&channel_id).unwrap();
        assert_eq!(
            rows,
            vec![
                (msg_id.clone(), ada.clone(), 17),
                (msg_id.clone(), bo.clone(), 8),
                (msg_id.clone(), later.clone(), 250),
            ]
        );
        let served = db
            .list_channel_reactions_for_sync(&channel_id, std::slice::from_ref(&msg_id), 32)
            .unwrap();
        assert!(served
            .iter()
            .any(|(_, member, reaction, at, sig)| member == &later
                && *reaction == 250
                && *at == 40
                && sig == "cc"));

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn channel_member_upsert_keeps_nickname_and_last_seen_monotonic() {
        let path = std::env::temp_dir().join(format!(
            "ember-member-upsert-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let channel_id = "ab".repeat(16);
        db.insert_channel(
            &channel_id,
            &"cd".repeat(32),
            "Lobby",
            "public",
            true,
            None,
            None,
        )
        .unwrap();
        let pk = "ee".repeat(32);
        assert_eq!(
            db.upsert_channel_member(&channel_id, &pk, "Ada", 200, None)
                .unwrap(),
            ChannelMemberWrite::Inserted
        );
        assert_eq!(
            db.upsert_channel_member(&channel_id, &pk, "", 50, None)
                .unwrap(),
            ChannelMemberWrite::Unchanged,
            "an older chat timestamp and an empty nick must not count as a change"
        );
        let members = db.list_channel_members(&channel_id).unwrap();
        assert_eq!(members[0].nickname, "Ada");
        assert_eq!(
            members[0].last_seen, 200,
            "an older chat timestamp must not rewind presence last_seen"
        );
        assert_eq!(
            db.upsert_channel_member(&channel_id, &pk, "Ada2", 250, None)
                .unwrap(),
            ChannelMemberWrite::Updated
        );
        let members = db.list_channel_members(&channel_id).unwrap();
        assert_eq!(members[0].nickname, "Ada2");
        assert_eq!(members[0].last_seen, 250);
        assert_eq!(
            db.upsert_channel_member(&channel_id, &pk, "Ada2", 250, None)
                .unwrap(),
            ChannelMemberWrite::Unchanged
        );
        // The same member, seen again. Reported apart from a nickname change
        // because it is the commonest write there is — every presence walk of
        // a settled room is a table of these — and the only thing a reader has
        // to be told is the new number.
        assert_eq!(
            db.upsert_channel_member(&channel_id, &pk, "Ada2", 300, None)
                .unwrap(),
            ChannelMemberWrite::Touched
        );
        assert_eq!(
            db.upsert_channel_member(&channel_id, &pk, "", 350, None)
                .unwrap(),
            ChannelMemberWrite::Touched,
            "a presence record carrying no nickname still moves last_seen"
        );
        assert_eq!(db.list_channel_members(&channel_id).unwrap()[0].last_seen, 350);
        db.rename_self_channel_member(&pk, "AdaRenamed").unwrap();
        assert_eq!(
            db.list_channel_members(&channel_id).unwrap()[0].nickname,
            "AdaRenamed"
        );
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn list_channels_member_count_counts_only_presence_fresh_rows() {
        let path = std::env::temp_dir().join(format!(
            "ember-member-fresh-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let channel_id = "ab".repeat(16);
        db.insert_channel(
            &channel_id,
            &"cd".repeat(32),
            "Lobby",
            "public",
            true,
            None,
            None,
        )
        .unwrap();
        let now = chrono::Utc::now().timestamp();
        db.upsert_channel_member(&channel_id, &"11".repeat(32), "Us", now, None)
            .unwrap();
        db.upsert_channel_member(
            &channel_id,
            &"22".repeat(32),
            "Gone",
            now - PRESENCE_FRESH_SECS - 30,
            None,
        )
        .unwrap();
        let listed = db.list_channels().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].member_count, 1,
            "a stale last_seen must not keep the empty-room poll from firing"
        );
        assert_eq!(
            db.count_fresh_channel_members(&channel_id, now, PRESENCE_FRESH_SECS)
                .unwrap(),
            1
        );
        let banned_pk = "33".repeat(32);
        db.upsert_channel_member(&channel_id, &banned_pk, "Banned", now, None)
            .unwrap();
        assert!(db
            .apply_channel_ban_action(&channel_id, &banned_pk, true, now)
            .unwrap());
        assert_eq!(
            db.list_channels().unwrap()[0].member_count,
            1,
            "a banned member must not keep the empty-room poll from firing"
        );
        assert_eq!(
            db.count_fresh_channel_members(&channel_id, now, PRESENCE_FRESH_SECS)
                .unwrap(),
            1
        );
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn roster_count_keeps_absent_members_and_drops_banned_ones() {
        let path = std::env::temp_dir().join(format!(
            "ember-roster-count-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let channel_id = "ab".repeat(16);
        db.insert_channel(
            &channel_id,
            &"cd".repeat(32),
            "Lobby",
            "public",
            true,
            None,
            None,
        )
        .unwrap();
        let now = chrono::Utc::now().timestamp();
        db.upsert_channel_member(&channel_id, &"11".repeat(32), "Us", now, None)
            .unwrap();
        db.upsert_channel_member(
            &channel_id,
            &"22".repeat(32),
            "Away",
            now - PRESENCE_FRESH_SECS - 30,
            None,
        )
        .unwrap();
        let listed = db.list_channels().unwrap();
        assert_eq!(listed[0].member_count, 1, "only one is present");
        assert_eq!(
            listed[0].roster_count, 2,
            "someone who stepped out is still a member"
        );

        let banned_pk = "33".repeat(32);
        db.upsert_channel_member(&channel_id, &banned_pk, "Banned", now, None)
            .unwrap();
        assert!(db
            .apply_channel_ban_action(&channel_id, &banned_pk, true, now)
            .unwrap());
        // A ban on someone never seen here leaves a row once it is lifted.
        let stranger = "44".repeat(32);
        assert!(db
            .apply_channel_ban_action(&channel_id, &stranger, true, now)
            .unwrap());
        assert!(db
            .apply_channel_ban_action(&channel_id, &stranger, false, now + 1)
            .unwrap());
        assert_eq!(
            db.list_channels().unwrap()[0].roster_count,
            2,
            "neither a banned member nor a lifted ban on a stranger is a member"
        );
        assert_eq!(
            db.get_channel(&channel_id).unwrap().unwrap().roster_count,
            2,
            "the single-row read reports the same figure the list does"
        );
        assert_eq!(
            db.get_channel_lite(&channel_id).unwrap().unwrap().roster_count,
            0,
            "the lite read skips the count"
        );
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn an_older_tombstone_does_not_delete_a_newer_live_row() {
        let path = std::env::temp_dir().join(format!(
            "ember-presence-tombstone-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let channel_id = "ab".repeat(16);
        db.insert_channel(
            &channel_id,
            &"cd".repeat(32),
            "Lobby",
            "public",
            true,
            None,
            None,
        )
        .unwrap();
        let pk = "ee".repeat(32);
        db.upsert_channel_member(&channel_id, &pk, "Ada", 200, None)
            .unwrap();
        assert!(
            !db.remove_channel_member(&channel_id, &pk, 100).unwrap(),
            "an older tombstone must not delete a newer live last_seen"
        );
        assert_eq!(db.list_channel_members(&channel_id).unwrap().len(), 1);
        assert!(
            db.remove_channel_member(&channel_id, &pk, 200).unwrap(),
            "equal timestamps prefer the tombstone"
        );
        assert!(db.list_channel_members(&channel_id).unwrap().is_empty());
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn a_flood_of_newcomers_does_not_evict_a_still_fresh_local_or_honest_row() {
        let path = std::env::temp_dir().join(format!(
            "ember-member-cap-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let channel_id = "ab".repeat(16);
        db.insert_channel(
            &channel_id,
            &"cd".repeat(32),
            "Lobby",
            "public",
            true,
            None,
            None,
        )
        .unwrap();
        let now = chrono::Utc::now().timestamp();
        let local = "11".repeat(32);
        let honest = "22".repeat(32);
        db.upsert_channel_member(&channel_id, &local, "Us", now, Some(&local))
            .unwrap();
        db.upsert_channel_member(&channel_id, &honest, "Ada", now, Some(&local))
            .unwrap();
        for i in 0..CHANNEL_MEMBERS_MAX.saturating_sub(2) {
            let pk = format!("{i:064x}");
            db.upsert_channel_member(&channel_id, &pk, "Flood", now, Some(&local))
                .unwrap();
        }
        assert_eq!(
            db.list_channel_members(&channel_id)
                .unwrap()
                .iter()
                .filter(|m| !m.banned)
                .count(),
            CHANNEL_MEMBERS_MAX
        );
        for i in 0..16 {
            let pk = format!("{:064x}", 10_000 + i);
            assert_eq!(
                db.upsert_channel_member(&channel_id, &pk, "New", now, Some(&local))
                    .unwrap(),
                ChannelMemberWrite::Refused,
                "a newcomer the cap turns away is reported as refused, not as a no-op, \
                 so caches sized to the roster do not admit what the roster would not"
            );
        }
        let members = db.list_channel_members(&channel_id).unwrap();
        let live: Vec<_> = members.iter().filter(|m| !m.banned).collect();
        assert!(
            live.iter().any(|m| m.member_pubkey == local),
            "the local user's row must survive a newcomer flood"
        );
        assert!(
            live.iter().any(|m| m.member_pubkey == honest),
            "a still-fresh honest peer must not be dropped to admit identity 257"
        );
        assert!(
            live.len() <= CHANNEL_MEMBERS_MAX,
            "refusing newcomers must not grow the table past the cap"
        );
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn leave_keeps_the_row_and_skips_presence() {
        let path = std::env::temp_dir().join(format!(
            "ember-in-room-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let channel_id = "ab".repeat(16);
        db.insert_channel(
            &channel_id,
            &"cd".repeat(32),
            "Lobby",
            "public",
            true,
            Some(&[0x11u8; 32]),
            None,
        )
        .expect("insert");
        let listed = db.list_channels().unwrap();
        assert!(listed[0].in_room);
        assert!(!listed[0].deleted);
        let due = db.channels_due_for_presence(i64::MAX, 1).unwrap();
        assert_eq!(due, vec![channel_id.clone()]);

        let now = 1_000_000i64;
        db.touch_channel_presence(&channel_id, now - 10).unwrap();
        assert!(
            db.channels_due_for_presence(now, 60).unwrap().is_empty(),
            "a stamp inside the republish interval must not look due"
        );
        db.due_channel_presence_now().unwrap();
        assert_eq!(
            db.channels_due_for_presence(now, 60).unwrap(),
            vec![channel_id.clone()],
            "clearing the stamp must make presence due without waiting out the interval"
        );

        assert!(db.set_channel_in_room(&channel_id, false).unwrap());
        let left = db.get_channel(&channel_id).unwrap().unwrap();
        assert!(!left.in_room);
        assert!(db.load_channel_owner_seed(&channel_id).unwrap().is_some());
        assert!(
            db.channels_due_for_presence(i64::MAX, 1)
                .unwrap()
                .is_empty(),
            "a device that walked out must not republish presence"
        );

        assert!(db.set_channel_in_room(&channel_id, true).unwrap());
        assert!(db.get_channel(&channel_id).unwrap().unwrap().in_room);

        assert!(db.tombstone_channel(&channel_id).unwrap());
        let gone = db.get_channel(&channel_id).unwrap().unwrap();
        assert!(!gone.in_room);
        assert!(gone.deleted);
        assert!(
            !db.set_channel_in_room(&channel_id, true).unwrap(),
            "a tombstoned room cannot be re-entered on this device"
        );

        let other_id = "ef".repeat(16);
        db.insert_channel(
            &other_id,
            &"12".repeat(32),
            "Elsewhere",
            "public",
            false,
            None,
            None,
        )
        .expect("insert other");
        let walked = db
            .walk_out_deleted_channels(std::slice::from_ref(&other_id))
            .unwrap();
        assert_eq!(walked, vec![other_id.clone()]);
        let hidden = db.get_channel(&other_id).unwrap().unwrap();
        assert!(!hidden.in_room);
        assert!(
            !hidden.deleted,
            "the directory is an unsigned hint: it walks a device out, it does \
             not tombstone a room beyond recovery"
        );
        assert!(
            db.set_channel_in_room(&other_id, true).unwrap(),
            "a room the directory was wrong about must be re-enterable"
        );

        // A room of its own, not the tombstoned one above: reusing that id made
        // this a duplicate insert, so the owner case below was never reached.
        let owned_id = "99".repeat(16);
        db.insert_channel(&owned_id, &"34".repeat(32), "Mine", "public", true, None, None)
            .expect("insert owned");
        let owned_walk = db
            .walk_out_deleted_channels(std::slice::from_ref(&owned_id))
            .unwrap();
        assert!(
            owned_walk.is_empty(),
            "a room we own is not walked out on the directory's say-so"
        );
        assert!(db.get_channel(&owned_id).unwrap().unwrap().in_room);

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// A moderator could name the room owner in ban gossip and every member
    /// applied it, silently dropping the owner's messages — nothing on the wire
    /// said who the owner was, so no recipient had grounds to refuse. The owner
    /// now signs their own identity into the moderation record; this covers the
    /// storage half of that: the key is remembered, a snapshot naming the owner
    /// cannot ban them, and learning who the owner is undoes a ban recorded
    /// before we knew.
    #[test]
    fn a_moderation_snapshot_can_never_ban_the_room_owner() {
        let path = std::env::temp_dir().join(format!(
            "ember-owner-ban-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "3c".repeat(16);
        let channel_pubkey = "4d".repeat(32);
        let owner = [0x0Au8; 32];
        let owner_hex = hex::encode(owner);
        let nuisance = [0x0Bu8; 32];
        let nuisance_hex = hex::encode(nuisance);

        db.insert_channel(
            &channel_id,
            &channel_pubkey,
            "Lobby",
            "public",
            false,
            None,
            None,
        )
        .expect("insert channel");

        // Stand in for the hole: a moderator's gossip ban on the owner, applied
        // before this device had ever seen an owner-signed record.
        assert!(db
            .apply_channel_ban_action(&channel_id, &owner_hex, true, 40)
            .unwrap());
        assert!(db.channel_member_is_banned(&channel_id, &owner_hex).unwrap());
        assert_eq!(db.get_channel(&channel_id).unwrap().unwrap().owner_pubkey, "");

        // The owner's own snapshot arrives. It names them, so the stale ban goes
        // and the identity is remembered for the gossip path to check against.
        assert!(db
            .apply_channel_moderation(
                &channel_id,
                "topic",
                "",
                50,
                &[nuisance],
                &[],
                Some(&owner),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap());
        assert!(
            !db.channel_member_is_banned(&channel_id, &owner_hex).unwrap(),
            "learning who the owner is must undo a ban recorded before we knew"
        );
        assert!(
            db.channel_member_is_banned(&channel_id, &nuisance_hex).unwrap(),
            "everyone else in the snapshot is still banned"
        );
        assert_eq!(
            db.get_channel(&channel_id).unwrap().unwrap().owner_pubkey,
            owner_hex
        );

        // And a snapshot that names the owner in its own ban list is refused
        // that one entry rather than being applied wholesale.
        assert!(db
            .apply_channel_moderation(
                &channel_id,
                "topic",
                "",
                60,
                &[owner, nuisance],
                &[],
                Some(&owner),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap());
        assert!(
            !db.channel_member_is_banned(&channel_id, &owner_hex).unwrap(),
            "a record banning its own owner is corrupt or hostile either way"
        );
        assert!(db.channel_member_is_banned(&channel_id, &nuisance_hex).unwrap());

        // A later record that predates the field must not erase what we know.
        assert!(db
            .apply_channel_moderation(&channel_id, "topic", "", 70, &[], &[], None, None, None, None, None, None)
            .unwrap());
        assert_eq!(
            db.get_channel(&channel_id).unwrap().unwrap().owner_pubkey,
            owner_hex,
            "a record that says nothing about the owner is not a record saying nobody"
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// Slow mode is documented as a guard against a flood of *ordinary*
    /// clients, so a bypass reachable from the stock UI defeats it. The clock
    /// used to be `MAX(timestamp)` over our own sent rows, and the transcript
    /// has a delete button on every one of them.
    #[test]
    fn the_slow_mode_clock_survives_deleting_your_own_last_message() {
        let path = std::env::temp_dir().join(format!(
            "ember-slowclock-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "9e".repeat(16);
        let me = "1f".repeat(32);
        db.insert_channel(
            &channel_id,
            &"8d".repeat(32),
            "Lobby",
            "public",
            false,
            None,
            None,
        )
        .expect("insert channel");
        assert_eq!(
            db.last_sent_channel_message_at(&channel_id).unwrap(),
            0,
            "a room we have never spoken in throttles nobody"
        );

        let id = db
            .insert_channel_message(&channel_id, &me, "sent", "first", "s1", 5_000, "", true)
            .unwrap();
        assert_eq!(db.last_sent_channel_message_at(&channel_id).unwrap(), 5_000);

        db.delete_channel_message(&channel_id, id).unwrap();
        assert_eq!(
            db.last_sent_channel_message_at(&channel_id).unwrap(),
            5_000,
            "deleting the line must not hand back the slow-mode slot"
        );

        // A received line is somebody else's and must not move our clock.
        db.insert_channel_message(&channel_id, &"2a".repeat(32), "received", "hi", "r1", 9_000, "", true)
            .unwrap();
        assert_eq!(db.last_sent_channel_message_at(&channel_id).unwrap(), 5_000);

        // Monotonic: a handoff copy carrying an older timestamp cannot rewind it.
        db.insert_channel_message(&channel_id, &me, "sent", "older", "s0", 1_000, "", true)
            .unwrap();
        assert_eq!(db.last_sent_channel_message_at(&channel_id).unwrap(), 5_000);

        db.insert_channel_message(&channel_id, &me, "sent", "newer", "s2", 7_000, "", true)
            .unwrap();
        assert_eq!(db.last_sent_channel_message_at(&channel_id).unwrap(), 7_000);

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// Chasing only the epoch the owner advertises left the one in between
    /// unfetchable, so a member who slept through two rotations kept a window
    /// of history they could never read.
    #[test]
    fn epoch_backfill_finds_the_gap_a_double_rotation_leaves() {
        let path = std::env::temp_dir().join(format!(
            "ember-epochgap-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "6c".repeat(16);
        db.insert_channel(
            &channel_id,
            &"5b".repeat(32),
            "Private",
            "private",
            false,
            None,
            None,
        )
        .expect("insert channel");

        // Held 4, slept through 5, woke up and took 6.
        db.insert_channel_key_epoch(&channel_id, 4, &[4u8; 32]).unwrap();
        db.insert_channel_key_epoch(&channel_id, 6, &[6u8; 32]).unwrap();
        assert_eq!(
            db.newest_missing_channel_key_epoch(&channel_id, 3, 6).unwrap(),
            Some(5),
            "the gap has to be visible even though the newest epoch is held"
        );

        db.insert_channel_key_epoch(&channel_id, 5, &[5u8; 32]).unwrap();
        assert_eq!(
            db.newest_missing_channel_key_epoch(&channel_id, 3, 6).unwrap(),
            Some(3),
            "and then the next one down"
        );
        db.insert_channel_key_epoch(&channel_id, 3, &[3u8; 32]).unwrap();
        assert_eq!(
            db.newest_missing_channel_key_epoch(&channel_id, 3, 6).unwrap(),
            None,
            "nothing left to chase"
        );
        // Newest first, because holding the current epoch is what unblocks sending.
        assert_eq!(
            db.newest_missing_channel_key_epoch(&channel_id, 3, 8).unwrap(),
            Some(8)
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// "Permanently delete this room" has to actually remove what the room
    /// held. Only the tombstone row survives, because `refuse_deleted_channel`
    /// reads it to keep this device from walking back in — everything else used
    /// to survive with it, unreachably, since `forget_channel` refuses to run
    /// on a row we own.
    #[test]
    fn deleting_an_owned_room_purges_its_contents_and_keeps_the_tombstone() {
        let path = std::env::temp_dir().join(format!(
            "ember-tombstone-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "5f".repeat(16);
        let member = "2e".repeat(32);
        let join = [0x71u8; 32];
        db.insert_channel(
            &channel_id,
            &"4d".repeat(32),
            "Lobby",
            "private",
            true,
            Some(&[0x33u8; 32]),
            Some(&join),
        )
        .expect("insert channel");
        db.upsert_channel_member(&channel_id, &member, "Them", 100, None)
            .unwrap();
        db.insert_channel_message(&channel_id, &member, "received", "private words", "m1", 100, "", true)
            .unwrap();
        db.insert_channel_key_epoch(&channel_id, 1, &join).unwrap();
        assert_eq!(db.get_channel_messages(&channel_id, 10, None).unwrap().len(), 1);

        assert!(db.tombstone_channel(&channel_id).unwrap());

        let row = db.get_channel(&channel_id).unwrap().expect("tombstone row");
        assert!(row.deleted, "the row has to stay, as the re-entry guard");
        assert!(!row.in_room_now());
        assert!(
            db.get_channel_messages(&channel_id, 10, None)
                .unwrap()
                .is_empty(),
            "every message in a deleted room must be gone"
        );
        assert!(
            db.list_channel_members(&channel_id).unwrap().is_empty(),
            "the roster of a deleted room must be gone"
        );
        assert!(
            db.load_channel_key_epochs(&channel_id).unwrap().is_empty(),
            "retained content keys must go with the room they opened"
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// A delegated moderator's gossip ban is the one path that can mint ban
    /// rows without the owner in the loop, and it had no ceiling. Past
    /// `CHANNEL_BAN_LIST_MAX` the moderation record cannot carry them: the
    /// encoder truncates, every recipient applies the record as a full
    /// snapshot, and so the owner's six-hourly republish lifted every ban past
    /// the cap for the whole room. The rows also survive roster eviction by
    /// design, so without a ceiling they accumulated on every member's disk.
    #[test]
    fn gossip_bans_stop_at_the_cap_a_moderation_record_can_carry() {
        let path = std::env::temp_dir().join(format!(
            "ember-ban-cap-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "7a".repeat(16);
        db.insert_channel(
            &channel_id,
            &"6b".repeat(32),
            "Lobby",
            "public",
            false,
            None,
            None,
        )
        .expect("insert channel");

        let cap = crate::network::ember::dht::publish::CHANNEL_BAN_LIST_MAX;
        let now = chrono::Utc::now().timestamp();
        let member = |i: usize| hex::encode([i as u8 + 1; 32]);

        // Fill to the cap, oldest decision first.
        for i in 0..cap {
            assert!(
                db.apply_channel_ban_action(&channel_id, &member(i), true, now - (cap - i) as i64)
                    .unwrap(),
                "ban {i} is inside the cap"
            );
        }
        let held = db.list_banned_channel_pubkeys(&channel_id).unwrap();
        assert_eq!(held.len(), cap);

        // Newest first, so a trim keeps the most recent decisions and every
        // device trims to the same list.
        assert_eq!(
            held.first().copied(),
            Some([cap as u8; 32]),
            "the most recently revised ban must sort first"
        );

        // One past the cap is refused outright rather than stored and then
        // silently dropped by the encoder.
        assert!(!db
            .apply_channel_ban_action(&channel_id, &member(cap), true, now)
            .unwrap());
        assert!(!db
            .channel_member_is_banned(&channel_id, &member(cap))
            .unwrap());

        // Re-stating a ban already held still refreshes it at exactly the cap.
        assert!(db
            .apply_channel_ban_action(&channel_id, &member(0), true, now)
            .unwrap());
        assert_eq!(
            db.list_banned_channel_pubkeys(&channel_id).unwrap().len(),
            cap
        );

        // An unban is never refused, and frees the slot for someone else.
        assert!(db
            .apply_channel_ban_action(&channel_id, &member(1), false, now)
            .unwrap());
        assert!(db
            .apply_channel_ban_action(&channel_id, &member(cap), true, now)
            .unwrap());
        assert_eq!(
            db.list_banned_channel_pubkeys(&channel_id).unwrap().len(),
            cap
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// The handoff writes a successor room, moves the seed, and points the old
    /// room at it. Those used to be separate lock acquisitions, so a crash
    /// between them could strand a successor with no seed or an old room
    /// pointing at a room that was never created. Re-running it has to be safe
    /// and has to converge, because that is what recovery depends on.
    #[test]
    fn applying_a_handoff_twice_converges_on_the_same_state() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-handoff-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let old_id = "7a".repeat(16);
        let successor_id = "8b".repeat(16);
        let successor_pk = "9c".repeat(32);
        db.insert_channel(&old_id, &"a1".repeat(32), "Room", "private", true, None, None)
            .expect("insert channel");
        db.upsert_channel_member(&old_id, &"b2".repeat(32), "Them", 100, None)
            .unwrap();
        db.insert_channel_message(&old_id, &"b2".repeat(32), "received", "hello", "m1", 100, "", true)
            .unwrap();
        db.apply_owner_room_policy(&old_id, true, &[[0x0Fu8; 16]], Some("it")).unwrap();

        let seed = [0x44u8; 32];
        assert!(db
            .apply_channel_handoff(&old_id, &successor_pk, &successor_id, 1, true, Some(&seed))
            .expect("apply handoff"));

        let successor = db.get_channel(&successor_id).unwrap().expect("successor row");
        assert!(successor.is_owner, "the claimant owns the successor");
        assert_eq!(successor.predecessor_id, old_id);
        assert_eq!(successor.name, "Room");
        assert!(successor.announce_only, "the room stays announce-only");
        assert_eq!(successor.language, "it", "and keeps its language");
        assert!(
            successor.pinned_msg_ids.is_empty(),
            "pins name ids the successor's copied history does not carry"
        );
        assert_eq!(
            db.load_channel_owner_seed(&successor_id).unwrap(),
            Some(seed),
            "the seed lands with the room, not after it"
        );
        let old = db.get_channel(&old_id).unwrap().expect("old row");
        assert_eq!(old.successor_id, successor_id);
        assert!(!old.is_owner, "the old room hands ownership over");
        assert!(
            db.load_channel_owner_seed(&old_id).unwrap().is_none(),
            "the old seed is dropped, never copied forward"
        );
        // Members and history come across.
        assert_eq!(db.list_channel_members(&successor_id).unwrap().len(), 1);
        assert_eq!(
            db.get_channel_messages(&successor_id, 10, None).unwrap().len(),
            1
        );
        let copied = db.get_channel_messages(&successor_id, 10, None).unwrap();
        assert!(
            copied[0].read,
            "a read received line must stay read on the successor"
        );
        assert_eq!(
            db.get_channel(&successor_id).unwrap().unwrap().unread,
            0,
            "handoff must not turn copied history into unread"
        );

        db.insert_channel_message(
            &old_id,
            &"b2".repeat(32),
            "received",
            "after crash",
            "m2",
            101,
            "",
            false,
        )
        .unwrap();
        assert!(db
            .apply_channel_handoff(&old_id, &successor_pk, &successor_id, 1, true, Some(&seed))
            .expect("resume handoff"));
        assert_eq!(
            db.get_channel_messages(&successor_id, 10, None).unwrap().len(),
            2,
            "a second apply must copy lines missed by a crash mid-replay"
        );

        // Replaying is idempotent: same successor, no duplicated history.
        assert!(db
            .apply_channel_handoff(&old_id, &successor_pk, &successor_id, 1, true, Some(&seed))
            .expect("replay handoff"));
        assert_eq!(
            db.get_channel_messages(&successor_id, 10, None).unwrap().len(),
            2,
            "a replay must not duplicate history"
        );

        // And a second, different successor cannot hijack a room already moved.
        assert!(!db
            .apply_channel_handoff(&old_id, &"d4".repeat(32), &"c3".repeat(16), 2, true, None)
            .expect("rival handoff"));
        assert_eq!(
            db.get_channel(&old_id).unwrap().unwrap().successor_id,
            successor_id
        );
    }

    /// An owner that has started publishing a handoff is committed to it: a
    /// second offer would put a rival record beside one that may be stored,
    /// and only one of two racing finishers may perform the handoff.
    #[test]
    fn an_owned_handoff_is_committed_before_publish_and_applied_exactly_once() {
        let path = std::env::temp_dir().join(format!(
            "ember-handoff-commit-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let room = "6f".repeat(16);
        let nominee = "a1".repeat(32);
        let rival = "b2".repeat(32);
        let successor_pk = "9c".repeat(32);
        let successor_id = hex::encode(crate::network::ember::channel::channel_id_from_pubkey(
            &[0x9c; 32],
        ));
        db.insert_channel(&room, &"d4".repeat(32), "Room", "private", true, None, None)
            .expect("insert channel");

        assert_eq!(
            db.commit_channel_handoff(&room, &nominee, 100, &successor_pk, 10).unwrap(),
            ChannelHandoffCommitOutcome::NotPending,
            "no offer is pending, so no ready can commit the room"
        );
        db.set_channel_pending_handoff(&room, &nominee, 100).unwrap();
        let ChannelHandoffCommitOutcome::Committed(commit) =
            db.commit_channel_handoff(&room, &nominee, 100, &successor_pk, 10).unwrap()
        else {
            panic!("the pending nominee's ready commits the room");
        };
        assert!(!commit.confirmed);
        assert!(matches!(
            db.commit_channel_handoff(&room, &nominee, 100, &successor_pk, 11).unwrap(),
            ChannelHandoffCommitOutcome::Held(_)
        ));
        assert_eq!(
            db.commit_channel_handoff(&room, &nominee, 100, &"e5".repeat(32), 11).unwrap(),
            ChannelHandoffCommitOutcome::Conflict,
            "a second successor for the same room is refused"
        );
        assert!(
            db.set_channel_pending_handoff(&room, &rival, 101).is_err(),
            "a new offer is refused while a handoff record may already be out"
        );
        assert_eq!(db.channel_pending_handoff(&room).unwrap(), Some((nominee.clone(), 100)));

        assert!(!db.apply_owned_channel_handoff(&room).unwrap(), "unconfirmed never applies");
        assert!(
            !db.confirm_channel_handoff(&room, 99, &successor_pk, 12, false).unwrap(),
            "an acknowledgement confirms only the commitment it was made for"
        );
        assert!(db.confirm_channel_handoff(&room, 100, &successor_pk, 12, false).unwrap());
        assert!(
            db.set_channel_pending_handoff(&room, "", 0).is_err(),
            "a stored record cannot be withdrawn by clearing the offer"
        );
        assert_eq!(db.list_channel_handoff_commits().unwrap().len(), 1);

        assert!(db.apply_owned_channel_handoff(&room).unwrap());
        assert!(
            !db.apply_owned_channel_handoff(&room).unwrap(),
            "only one finisher performs the handoff"
        );
        let old = db.get_channel(&room).unwrap().unwrap();
        assert_eq!(old.successor_id, successor_id);
        assert!(!old.is_owner);
        assert!(db.channel_handoff_commit(&room).unwrap().is_none());
        assert!(db.list_channel_handoff_commits().unwrap().is_empty());
        assert!(db.get_channel(&successor_id).unwrap().is_some());

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// A record found stored under our own room's key is what the members are
    /// following, whatever this device was publishing. Withdrawing an offer
    /// before anything is confirmed, by contrast, gives the room back.
    #[test]
    fn an_owner_adopts_its_own_stored_handoff_and_can_withdraw_an_unconfirmed_one() {
        let path = std::env::temp_dir().join(format!(
            "ember-handoff-adopt-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let room = "7e".repeat(16);
        let nominee = "a1".repeat(32);
        db.insert_channel(&room, &"d4".repeat(32), "Room", "public", true, None, None)
            .expect("insert channel");

        db.set_channel_pending_handoff(&room, &nominee, 200).unwrap();
        assert!(matches!(
            db.commit_channel_handoff(&room, &nominee, 200, &"9c".repeat(32), 10).unwrap(),
            ChannelHandoffCommitOutcome::Committed(_)
        ));
        db.set_channel_pending_handoff(&room, "", 0).unwrap();
        assert!(db.channel_handoff_commit(&room).unwrap().is_none());
        assert!(db.channel_pending_handoff(&room).unwrap().is_none());

        assert!(db.confirm_channel_handoff(&room, 150, &"8d".repeat(32), 20, true).unwrap());
        let adopted = db.channel_handoff_commit(&room).unwrap().expect("adopted");
        assert!(adopted.confirmed && adopted.nominee.is_empty());
        assert!(
            db.apply_owned_channel_handoff(&room).unwrap(),
            "an adopted record needs no pending offer to match"
        );
        assert_eq!(
            db.get_channel(&room).unwrap().unwrap().successor_id,
            hex::encode(crate::network::ember::channel::channel_id_from_pubkey(&[0x8d; 32]))
        );
        assert!(
            !db.confirm_channel_handoff(&room, 150, &"8d".repeat(32), 30, true).unwrap(),
            "a room already moved has nothing left to confirm"
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// The nominee's pending seed is the successor room's identity, and the
    /// owner may already have published a handoff naming its pubkey. A replayed
    /// or reordered offer overwriting it would leave the nominee handed a room
    /// it can no longer sign for.
    #[test]
    fn a_pending_handoff_seed_is_only_replaced_by_a_newer_offer() {
        let path = std::env::temp_dir().join(format!(
            "ember-handoff-pending-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let old_id = "5e".repeat(16);

        assert!(db
            .store_handoff_pending_seed(&old_id, 100, &"a1".repeat(32), &[0x11; 32])
            .unwrap());
        assert!(
            !db.store_handoff_pending_seed(&old_id, 100, &"b2".repeat(32), &[0x22; 32])
                .unwrap(),
            "a repeat of the same offer must reuse the held seed, not mint over it"
        );
        assert!(
            !db.store_handoff_pending_seed(&old_id, 99, &"c3".repeat(32), &[0x33; 32])
                .unwrap(),
            "an older offer replayed late must not displace a newer one"
        );
        assert_eq!(
            db.load_handoff_pending_row(&old_id).unwrap(),
            Some(("a1".repeat(32), 100, [0x11; 32]))
        );

        assert!(db
            .store_handoff_pending_seed(&old_id, 101, &"d4".repeat(32), &[0x44; 32])
            .unwrap());
        assert_eq!(
            db.load_handoff_pending_row(&old_id).unwrap(),
            Some(("d4".repeat(32), 101, [0x44; 32]))
        );

        db.clear_handoff_pending(&old_id).unwrap();
        assert!(
            db.store_handoff_pending_seed(&old_id, 50, &"e5".repeat(32), &[0x55; 32])
                .unwrap(),
            "with nothing held, any offer may be stored"
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// Rotation is only useful if the keys survive in a readable window and the
    /// window is actually bounded: too few and a member offline across a ban
    /// cannot read the gap, unbounded and every key a room ever used stays on
    /// disk forever.
    #[test]
    fn rotating_a_room_key_keeps_a_bounded_window_of_readable_epochs() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-epochs-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "3c".repeat(16);
        db.insert_channel(
            &channel_id,
            &"4d".repeat(32),
            "Private",
            "private",
            true,
            None,
            None,
        )
        .expect("insert channel");

        // Rotate well past the retention window.
        let kept = Database::CHANNEL_KEY_EPOCHS_KEPT as i64;
        let total = kept + 3;
        for epoch in 1..=total {
            db.insert_channel_key_epoch(&channel_id, epoch, &[epoch as u8; 32])
                .expect("insert epoch");
        }

        let epochs = db.load_channel_key_epochs(&channel_id).expect("load");
        assert_eq!(epochs.len(), kept as usize, "retention window is bounded");
        // Newest first, because readers try the current key before older ones.
        assert_eq!(epochs[0].0, total);
        assert_eq!(epochs[0].1, [total as u8; 32]);
        assert!(
            epochs.windows(2).all(|w| w[0].0 > w[1].0),
            "candidates must be newest-first"
        );
        assert_eq!(
            epochs.last().map(|(e, _)| *e),
            Some(total - kept + 1),
            "the oldest retained epoch is exactly one window back"
        );

        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert_eq!(row.key_epoch, total, "the newest epoch becomes current");

        // An out-of-order record must not demote the room: everything we send
        // next would be sealed under a key half the members have dropped.
        db.insert_channel_key_epoch(&channel_id, total - 2, &[0xEEu8; 32])
            .expect("insert stale epoch");
        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert_eq!(row.key_epoch, total, "a late arrival cannot walk it back");

        // Dropping the room drops its keys with it.
        db.delete_channel(&channel_id, None).expect("delete");
        assert!(db
            .load_channel_key_epochs(&channel_id)
            .expect("load")
            .is_empty());
    }

    /// A handoff that carries a secret forward has to carry the *current* one.
    /// Rotation writes to `channel_key_epochs` and never touches `join_secret`,
    /// so inheriting that column handed the successor room the key the last ban
    /// rotated away from — which an evicted member still holds, letting them
    /// read the new room and undoing the eviction.
    #[test]
    fn a_successor_room_inherits_the_rotated_key_not_the_original_invite() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-succ-key-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let old_id = "1f".repeat(16);
        let successor_id = "2e".repeat(16);
        let original_invite = [0x01u8; 32];
        db.insert_channel(
            &old_id,
            &"3d".repeat(32),
            "Private",
            "private",
            true,
            None,
            Some(&original_invite),
        )
        .expect("insert channel");

        // Two bans' worth of rotation.
        let rotated = [0x02u8; 32];
        db.insert_channel_key_epoch(&old_id, 1, &[0x09u8; 32]).unwrap();
        db.insert_channel_key_epoch(&old_id, 2, &rotated).unwrap();

        assert!(db
            .apply_channel_handoff(&old_id, &"4c".repeat(32), &successor_id, 1, true, None)
            .expect("apply handoff"));

        let inherited = db
            .load_channel_join_secret(&successor_id)
            .expect("load")
            .expect("successor has a secret");
        assert_eq!(
            inherited, rotated,
            "the successor must start from the newest epoch"
        );
        assert_ne!(
            inherited, original_invite,
            "an evicted member's original invite must not open the successor room"
        );
    }

    /// Succession has to be opt-in and driven only by owner-signed facts: the
    /// nomination and the window both come from the moderation record, and a
    /// record that predates those fields must not silently erase them.
    #[test]
    fn succession_settings_come_only_from_owner_signed_records() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-succession-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "5e".repeat(16);
        db.insert_channel(
            &channel_id,
            &"6f".repeat(32),
            "Room",
            "private",
            false,
            None,
            None,
        )
        .expect("insert channel");

        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert!(row.successor_nominee.is_empty(), "off by default");
        assert_eq!(row.claim_after_days, 0);
        assert_eq!(row.key_epoch_wanted, 0);

        let owner = [0x11u8; 32];
        let nominee = [0x22u8; 32];
        assert!(db
            .apply_channel_moderation(
                &channel_id,
                "Topic",
                "Welcome",
                1_000,
                &[],
                &[],
                Some(&owner),
                Some(&nominee),
                Some(30),
                Some(4),
                None,
                None,
            )
            .unwrap());
        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert_eq!(row.successor_nominee, hex::encode(nominee));
        assert_eq!(row.claim_after_days, 30);
        assert_eq!(row.key_epoch_wanted, 4);
        assert_eq!(row.moderation_updated_at, 1_000);

        // A newer record carrying none of the trailing fields — an older build,
        // say — leaves what we already learned intact rather than wiping it.
        assert!(db
            .apply_channel_moderation(
                &channel_id, "Topic 2", "Welcome", 2_000, &[], &[], None, None, None, None, None,
                None,
            )
            .unwrap());
        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert_eq!(row.successor_nominee, hex::encode(nominee));
        assert_eq!(row.claim_after_days, 30);
        assert_eq!(row.key_epoch_wanted, 4);

        // And a stale epoch cannot send members hunting for a superseded key.
        assert!(db
            .apply_channel_moderation(
                &channel_id,
                "Topic 3",
                "Welcome",
                3_000,
                &[],
                &[],
                None,
                None,
                None,
                Some(2),
                None,
                None,
            )
            .unwrap());
        assert_eq!(
            db.get_channel(&channel_id).unwrap().unwrap().key_epoch_wanted,
            4
        );

        // Clearing a nomination locally used to have its own setter, and this is
        // where it was exercised. It has none now: the nominee is part of the
        // signed snapshot, so withdrawing one travels the same path as setting
        // one and the all-zero case below is the whole of it.

        // A withdrawal has to reach members. An all-zero nominee is the
        // owner saying "nobody" — distinct from a record that simply omits the
        // field, which must leave what we already know alone. Without this an
        // owner could never call a nomination back.
        assert!(db
            .apply_channel_moderation(
                &channel_id,
                "Topic 4",
                "Welcome",
                4_000,
                &[],
                &[],
                Some(&owner),
                Some(&nominee),
                Some(21),
                None,
                None,
                None,
            )
            .unwrap());
        assert_eq!(
            db.get_channel(&channel_id).unwrap().unwrap().successor_nominee,
            hex::encode(nominee)
        );
        assert!(db
            .apply_channel_moderation(
                &channel_id,
                "Topic 5",
                "Welcome",
                5_000,
                &[],
                &[],
                Some(&owner),
                Some(&[0u8; 32]),
                Some(0),
                None,
                None,
                None,
            )
            .unwrap());
        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert!(
            row.successor_nominee.is_empty(),
            "an all-zero nominee withdraws the nomination"
        );
        assert_eq!(row.claim_after_days, 0);
    }

    /// Succession is the one feature that acts on *absence*, so the record of
    /// having looked must never move backwards — a late-arriving older
    /// confirmation could otherwise make a freshly-checked room look unverified,
    /// or worse, be replayed to make a stale check look current.
    #[test]
    fn the_record_of_having_checked_for_an_owner_only_moves_forward() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-checked-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "9d".repeat(16);
        db.insert_channel(&channel_id, &"ae".repeat(32), "Room", "private", false, None, None)
            .expect("insert channel");
        assert_eq!(
            db.get_channel(&channel_id).unwrap().unwrap().moderation_checked_at,
            0,
            "a room we have never polled has not been checked"
        );

        db.touch_channel_moderation_checked(&channel_id, 5_000).unwrap();
        assert_eq!(
            db.get_channel(&channel_id).unwrap().unwrap().moderation_checked_at,
            5_000
        );

        db.touch_channel_moderation_checked(&channel_id, 4_000).unwrap();
        assert_eq!(
            db.get_channel(&channel_id).unwrap().unwrap().moderation_checked_at,
            5_000,
            "an older confirmation cannot un-verify a room"
        );

        db.touch_channel_moderation_checked(&channel_id, 9_000).unwrap();
        assert_eq!(
            db.get_channel(&channel_id).unwrap().unwrap().moderation_checked_at,
            9_000
        );

        // It belongs to the room, so a fresh successor starts unverified rather
        // than inheriting our confidence about the room it replaced.
        let successor_id = "bf".repeat(16);
        assert!(db
            .apply_channel_handoff(&channel_id, &"c0".repeat(32), &successor_id, 1, false, None)
            .expect("apply handoff"));
        assert_eq!(
            db.get_channel(&successor_id).unwrap().unwrap().moderation_checked_at,
            0,
            "a successor room has its own owner to verify"
        );
    }

    /// A rotation and the snapshot announcing it have to land together. The
    /// owner seals under whatever `key_epoch` says, and members only fetch a key
    /// the snapshot names — so a rotation whose commit failed has to come back
    /// off, or the owner talks under a key nobody knows to look for.
    #[test]
    fn rolling_back_a_rotation_restores_the_previous_epoch() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-rollback-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "6a".repeat(16);
        db.insert_channel(
            &channel_id,
            &"7b".repeat(32),
            "Private",
            "private",
            true,
            None,
            Some(&[0xAAu8; 32]),
        )
        .expect("insert channel");

        db.insert_channel_key_epoch(&channel_id, 1, &[0x01u8; 32]).unwrap();
        db.insert_channel_key_epoch(&channel_id, 2, &[0x02u8; 32]).unwrap();
        assert_eq!(db.get_channel(&channel_id).unwrap().unwrap().key_epoch, 2);

        db.rollback_channel_key_epoch(&channel_id, 2).unwrap();
        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert_eq!(row.key_epoch, 1, "the epoch falls back to the previous one");
        let epochs = db.load_channel_key_epochs(&channel_id).unwrap();
        assert_eq!(epochs.len(), 1);
        assert_eq!(epochs[0], (1, [0x01u8; 32]));

        // Rolling back the only epoch leaves the room on its original invite
        // secret rather than on nothing at all.
        db.rollback_channel_key_epoch(&channel_id, 1).unwrap();
        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert_eq!(row.key_epoch, 0);
        assert!(db.load_channel_key_epochs(&channel_id).unwrap().is_empty());
        assert_eq!(
            db.load_channel_join_secret(&channel_id).unwrap(),
            Some([0xAAu8; 32])
        );
    }

    /// Leaving used to wipe `channel_members`, so rejoining re-inserted the
    /// member with `banned = 0` and the client offered a composer whose sends
    /// every remaining member discards. A ban belongs to the room, not to the
    /// membership, so it has to outlive an explicit leave.
    #[test]
    fn leaving_keeps_our_own_ban_but_forgets_everything_else() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-leave-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "1a".repeat(16);
        let channel_pubkey = "2b".repeat(32);
        let us = [0x55u8; 32];
        let us_hex = hex::encode(us);
        let other = [0x66u8; 32];
        let other_hex = hex::encode(other);

        db.insert_channel(
            &channel_id,
            &channel_pubkey,
            "Lobby",
            "public",
            false,
            None,
            None,
        )
        .expect("insert channel");
        db.upsert_channel_member(&channel_id, &us_hex, "Us", 100, None)
            .unwrap();
        db.upsert_channel_member(&channel_id, &other_hex, "Them", 100, None)
            .unwrap();
        assert!(db
            .apply_channel_moderation(&channel_id, "", "", 50, &[us, other], &[], None, None, None, None, None, None)
            .unwrap());

        assert!(db.delete_channel(&channel_id, Some(&us_hex)).unwrap());
        assert!(db.get_channel(&channel_id).unwrap().is_none());
        assert!(
            db.channel_member_is_banned(&channel_id, &us_hex).unwrap(),
            "our ban must outlive leaving the room"
        );
        assert!(
            !db.channel_member_is_banned(&channel_id, &other_hex).unwrap(),
            "another member's ban is not ours to keep once we have left"
        );

        // Rejoining must not launder the ban: `upsert_channel_member` refreshes
        // the nickname and last-seen but leaves `banned` alone.
        db.insert_channel(
            &channel_id,
            &channel_pubkey,
            "Lobby",
            "public",
            false,
            None,
            None,
        )
        .expect("rejoin channel");
        db.upsert_channel_member(&channel_id, &us_hex, "Us", 200, None)
            .unwrap();
        assert!(
            db.channel_member_is_banned(&channel_id, &us_hex).unwrap(),
            "rejoining must not clear the ban"
        );

        // The owner lifting it still does, on the next moderation snapshot.
        assert!(db
            .apply_channel_moderation(&channel_id, "", "", 60, &[], &[], None, None, None, None, None, None)
            .unwrap());
        assert!(!db.channel_member_is_banned(&channel_id, &us_hex).unwrap());

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn channel_handoff_installs_successor_seed_without_copying_old() {
        use crate::network::ember::channel::ChannelIdentity;

        let path = std::env::temp_dir().join(format!(
            "ember-handoff-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let old = ChannelIdentity::generate();
        let successor = ChannelIdentity::generate();
        let old_id = hex::encode(old.channel_id);
        let new_id = hex::encode(successor.channel_id);
        let old_pk = hex::encode(old.pubkey);
        let new_pk = hex::encode(successor.pubkey);
        let old_seed = old.seed();
        let new_seed = successor.seed();
        let join = [0x55u8; 32];

        db.insert_channel(&old_id, &old_pk, "Lobby", "private", true, Some(&old_seed), Some(&join))
            .unwrap();
        let keep_id = "aa".repeat(16);
        db.insert_channel_message(&old_id, &old_pk, "sent", "keep me", &keep_id, 10, "", true)
            .unwrap();

        assert!(db
            .apply_channel_handoff(&old_id, &new_pk, &new_id, 1, true, None)
            .unwrap());
        let old_row = db.get_channel(&old_id).unwrap().unwrap();
        assert!(!old_row.is_owner);
        assert_eq!(old_row.successor_id, new_id);
        assert!(db.load_channel_owner_seed(&old_id).unwrap().is_none());
        assert!(db.load_channel_owner_seed(&new_id).unwrap().is_none());
        assert_eq!(db.load_channel_join_secret(&new_id).unwrap(), Some(join));

        assert!(db
            .apply_channel_handoff(&old_id, &new_pk, &new_id, 1, true, Some(&new_seed))
            .unwrap());
        assert_eq!(db.load_channel_owner_seed(&new_id).unwrap(), Some(new_seed));
        assert_ne!(db.load_channel_owner_seed(&new_id).unwrap(), Some(old_seed));
        let new_row = db.get_channel(&new_id).unwrap().unwrap();
        assert!(new_row.is_owner);
        assert_eq!(new_row.predecessor_id, old_id);
        let history = db.get_channel_messages(&new_id, 50, None).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].message, "keep me");

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// Walking back into a room cancels the tombstone that said we left.
    ///
    /// The publisher gathers a list and yields between rooms, so a rejoin can
    /// land mid-pass. Publishing the departure anyway would tell every member to
    /// drop the roster row we had just re-earned, which is why the claim tests
    /// `in_room` as part of its own write rather than trusting the list.
    #[test]
    fn a_rejoin_cancels_the_leave_tombstone_even_mid_pass() {
        let path = std::env::temp_dir().join(format!(
            "ember-departure-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "7d".repeat(16);
        db.insert_channel(&channel_id, &"1f".repeat(32), "Lobby", "public", false, None, None)
            .unwrap();
        assert!(db.set_channel_in_room(&channel_id, false).unwrap());
        db.mark_channel_departure_due(&channel_id, 100).unwrap();
        assert_eq!(db.channels_due_for_departure(200).unwrap(), vec![channel_id.clone()]);

        // Not yet due is not the same as not owed.
        assert!(db.channels_due_for_departure(50).unwrap().is_empty());

        // The claim reserves it and pushes the next attempt out, so a second
        // pass cannot start a duplicate publish while the first is in flight.
        assert!(db.claim_channel_departure(&channel_id, 900).unwrap());
        assert!(db.channels_due_for_departure(200).unwrap().is_empty());
        assert_eq!(db.channels_due_for_departure(900).unwrap(), vec![channel_id.clone()]);

        // Rejoining drops the marker, and the claim then refuses -- which is the
        // race: the publisher already had this room on its list.
        assert!(db.set_channel_in_room(&channel_id, true).unwrap());
        assert!(db.channels_due_for_departure(i64::MAX).unwrap().is_empty());
        assert!(
            !db.claim_channel_departure(&channel_id, 1_000).unwrap(),
            "a departure must not be publishable for a room we are back inside"
        );
        db.mark_channel_departure_due(&channel_id, 100).unwrap();
        assert!(
            db.channels_due_for_departure(i64::MAX).unwrap().is_empty(),
            "nor arm-able while we are in the room"
        );

        // Leaving again owes a fresh one, and a stored record clears it.
        assert!(db.set_channel_in_room(&channel_id, false).unwrap());
        db.mark_channel_departure_due(&channel_id, 100).unwrap();
        assert!(db.claim_channel_departure(&channel_id, 900).unwrap());
        db.clear_channel_departure(&channel_id).unwrap();
        assert!(db.channels_due_for_departure(i64::MAX).unwrap().is_empty());
        assert!(!db.claim_channel_departure(&channel_id, 1_000).unwrap());

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// A handoff carries the roster's ban watermarks, not just its ban flags.
    ///
    /// `ban_revised_at` is what orders competing ban gossip. Copying the rows
    /// without it reset every member to "never revised", so the first stale
    /// frame to arrive in the successor room could re-decide a question the
    /// predecessor had already settled.
    #[test]
    fn channel_handoff_carries_the_ban_watermark() {
        use crate::network::ember::channel::ChannelIdentity;

        let path = std::env::temp_dir().join(format!(
            "ember-handoff-bans-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let old = ChannelIdentity::generate();
        let successor = ChannelIdentity::generate();
        let old_id = hex::encode(old.channel_id);
        let new_id = hex::encode(successor.channel_id);
        let old_pk = hex::encode(old.pubkey);
        let new_pk = hex::encode(successor.pubkey);
        let old_seed = old.seed();
        let villain = "b9".repeat(32);

        db.insert_channel(
            &old_id,
            &old_pk,
            "Lobby",
            "private",
            true,
            Some(&old_seed),
            Some(&[0x55u8; 32]),
        )
        .unwrap();
        assert!(db
            .apply_channel_ban_action(&old_id, &villain, true, 500)
            .unwrap());

        assert!(db
            .apply_channel_handoff(&old_id, &new_pk, &new_id, 1, true, Some(&successor.seed()))
            .unwrap());
        assert!(
            db.channel_member_is_banned(&new_id, &villain).unwrap(),
            "the ban itself has to survive the move"
        );
        assert!(
            !db.apply_channel_ban_action(&new_id, &villain, false, 400)
                .unwrap(),
            "an unban older than the ban must still be refused in the successor room"
        );
        assert!(db.channel_member_is_banned(&new_id, &villain).unwrap());
        assert!(
            db.apply_channel_ban_action(&new_id, &villain, false, 600)
                .unwrap(),
            "a genuinely newer unban still applies"
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// A catch-up reply annotates the lines it served and nothing else.
    ///
    /// Scoped by message id rather than by the requester's watermark: a reply
    /// serves the oldest lines in that window, so selecting reactions by
    /// timestamp sent them for messages the peer had not been given while the
    /// ones it did get arrived bare.
    #[test]
    fn channel_reaction_sync_only_covers_the_lines_it_is_given() {
        let path = std::env::temp_dir().join(format!(
            "ember-reaction-sync-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "3c".repeat(16);
        let me = "1a".repeat(32);
        let them = "2b".repeat(32);
        db.insert_channel(&channel_id, &me, "Lobby", "public", true, None, None)
            .unwrap();

        let older = "aa".repeat(16);
        let newer = "bb".repeat(16);
        db.insert_channel_message(
            &channel_id, &me, "sent", "first", &older, 1_700_000_000, &"11".repeat(64), true,
        )
        .unwrap();
        db.insert_channel_message(
            &channel_id, &me, "sent", "second", &newer, 1_700_000_900, &"22".repeat(64), true,
        )
        .unwrap();
        assert!(db
            .set_channel_message_reaction(&channel_id, &older, &them, 1, 1_700_000_100, "aa")
            .unwrap());
        assert!(db
            .set_channel_message_reaction(&channel_id, &newer, &them, 2, 1_700_001_000, "bb")
            .unwrap());

        let served = db
            .list_channel_reactions_for_sync(&channel_id, std::slice::from_ref(&older), 32)
            .unwrap();
        assert_eq!(served.len(), 1, "only the line named may be annotated");
        assert_eq!(served[0].0, older);
        assert_eq!(
            served[0].2, 1,
            "and it has to be that line's reaction, not the newest in the room"
        );

        let both = db
            .list_channel_reactions_for_sync(&channel_id, &[older, newer], 32)
            .unwrap();
        assert_eq!(both.len(), 2);

        assert!(
            db.list_channel_reactions_for_sync(&channel_id, &[], 32)
                .unwrap()
                .is_empty(),
            "a reply that served no lines has nothing to annotate"
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// Queued outbound chat has to survive a restart, otherwise the queue is
    /// no better than the in-memory send it replaced.
    #[test]
    fn queued_chat_survives_restart_and_flush_marks_it_delivered() {
        let path = std::env::temp_dir().join(format!(
            "ember-chat-queue-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let friend = "aa".repeat(16);

        let id = {
            let db = Database::open_at(&path).expect("open db");
            let id = db
                .insert_pending_chat_message(&friend, "held for later")
                .expect("queue message");
            // A delivered message must not be picked up by the flush scan.
            db.insert_chat_message(&friend, "sent", "already gone")
                .expect("insert delivered");
            id
        };

        let db = Database::open_at(&path).expect("reopen db");
        let pending = db.pending_chat_messages(&friend, 100).expect("pending");
        assert_eq!(pending.len(), 1, "only the queued row should be pending");
        assert_eq!(pending[0].0, id);
        assert_eq!(pending[0].1, "held for later");
        assert_eq!(
            db.pending_chat_counts().expect("counts"),
            vec![(friend.clone(), 1)]
        );

        db.set_chat_delivery(id, CHAT_DELIVERED).expect("mark sent");
        assert!(
            db.pending_chat_messages(&friend, 100)
                .expect("pending after")
                .is_empty(),
            "a delivered message must leave the queue"
        );
        // History still shows both, and the flushed one now reads as delivered.
        let history = db.get_chat_messages(&friend, 50, None).expect("history");
        assert_eq!(history.len(), 2);
        assert!(history.iter().all(|row| row.delivery == CHAT_DELIVERED));

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn v21_enables_auto_vacuum_on_legacy_none_db() {
        let path = std::env::temp_dir().join(format!(
            "ember-av-legacy-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        {
            // Build a minimal pre-v21 DB with auto_vacuum stuck at NONE
            // (the historical pragma-order bug + existing tables).
            let conn = Connection::open(&path).expect("create legacy");
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE schema_version (version INTEGER NOT NULL DEFAULT 0);
                 INSERT INTO schema_version (version) VALUES (20);
                 CREATE TABLE statistics (key TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0);
                 CREATE TABLE transfers (id TEXT PRIMARY KEY);
                 CREATE TABLE transfers_v5_backup (id TEXT);
                 CREATE TABLE shared_files_v7_backup (id TEXT);
                 CREATE TABLE settings_v7_backup (key TEXT);",
            )
            .expect("seed legacy schema");
            let av: i64 = conn
                .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
                .unwrap();
            assert_eq!(av, 0, "fixture must start with auto_vacuum=NONE");
        }
        let db = Database::open_at(&path).expect("migrate legacy");
        let auto_vacuum: i64 = db
            .conn
            .lock()
            .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
            .expect("auto_vacuum");
        assert_eq!(auto_vacuum, 2, "v21 must enable INCREMENTAL auto_vacuum");
        let backups: i64 = db
            .conn
            .lock()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE '%_backup'",
                [],
                |r| r.get(0),
            )
            .expect("backup count");
        assert_eq!(backups, 0, "v21 must drop legacy backup tables");
        let expected_aich_column: i64 = db
            .conn
            .lock()
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('transfers') WHERE name = 'expected_aich'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            expected_aich_column, 1,
            "v22 must persist optional AICH pins"
        );
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    fn remove_test_database(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_file(parent.join(CHAT_KEY_FILE));
        }
    }

    #[test]
    fn chat_rows_are_encrypted_and_survive_restart_and_pagination() {
        let dir = std::env::temp_dir().join(format!(
            "ember-chat-encrypted-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ember.db");
        let canary = "plaintext-canary-chat-7c61";
        {
            let db = Database::open_at(&path).expect("open");
            let first = db
                .insert_chat_message(&"11".repeat(16), "sent", canary)
                .unwrap();
            let second = db
                .insert_chat_message(&"11".repeat(16), "received", "second")
                .unwrap();
            let raw: String = db
                .conn
                .lock()
                .query_row(
                    "SELECT message FROM chat_messages WHERE id = ?1",
                    params![first],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(raw.starts_with(CHAT_CIPHERTEXT_PREFIX));
            assert!(!raw.contains(canary));

            let newest = db.get_chat_messages(&"11".repeat(16), 1, None).unwrap();
            assert_eq!(newest[0].id, second);
            assert_eq!(newest[0].message, "second");
            let older = db
                .get_chat_messages(&"11".repeat(16), 5, Some(second))
                .unwrap();
            assert_eq!(older[0].id, first);
            assert_eq!(older[0].message, canary);
        }
        {
            let db = Database::open_at(&path).expect("restart");
            let rows = db.get_chat_messages(&"11".repeat(16), 5, None).unwrap();
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[1].message, canary);
        }
        let raw_db = std::fs::read(&path).unwrap();
        assert!(
            !raw_db
                .windows(canary.len())
                .any(|window| window == canary.as_bytes()),
            "database file must not contain the plaintext canary"
        );
        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn chat_ciphertext_tampering_and_wrong_key_fail_closed() {
        let key = [0x44; 32];
        let row =
            Database::encrypt_chat_body(&key, 9, &"22".repeat(16), "sent", 123, "secret").unwrap();
        let mut envelope = STANDARD_NO_PAD
            .decode(row.strip_prefix(CHAT_CIPHERTEXT_PREFIX).unwrap())
            .unwrap();
        *envelope.last_mut().unwrap() ^= 0x80;
        let tampered = format!(
            "{CHAT_CIPHERTEXT_PREFIX}{}",
            STANDARD_NO_PAD.encode(envelope)
        );
        assert!(
            Database::decrypt_chat_body(&key, 9, &"22".repeat(16), "sent", 123, &tampered).is_err()
        );
        assert!(
            Database::decrypt_chat_body(&[0x45; 32], 9, &"22".repeat(16), "sent", 123, &row)
                .is_err()
        );
        assert!(Database::decrypt_chat_body(
            &key,
            9,
            &"22".repeat(16),
            "sent",
            123,
            "legacy plaintext"
        )
        .is_err());
    }

    #[test]
    fn plaintext_chat_migration_is_transactional_and_authenticated() {
        let dir = std::env::temp_dir().join(format!(
            "ember-chat-migrate-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ember.db");
        let canary = "legacy-plaintext-canary-f143";
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL DEFAULT 0);
                 INSERT INTO schema_version(version) VALUES (22);
                 CREATE TABLE friends (
                    user_hash TEXT PRIMARY KEY, nickname TEXT NOT NULL DEFAULT '',
                    added_at INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE friend_requests (
                    sender_hash TEXT PRIMARY KEY, sender_nickname TEXT NOT NULL DEFAULT '',
                    received_at INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE chat_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    friend_hash TEXT NOT NULL, direction TEXT NOT NULL,
                    message TEXT NOT NULL, timestamp INTEGER NOT NULL,
                    read INTEGER NOT NULL DEFAULT 0
                 );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO chat_messages(friend_hash,direction,message,timestamp,read) \
                 VALUES (?1,'received',?2,77,0)",
                params!["33".repeat(16), canary],
            )
            .unwrap();
        }
        let db = Database::open_at(&path).expect("migrate");
        let rows = db.get_chat_messages(&"33".repeat(16), 10, None).unwrap();
        assert_eq!(rows[0].message, canary);
        let stored: String = db
            .conn
            .lock()
            .query_row("SELECT message FROM chat_messages", [], |row| row.get(0))
            .unwrap();
        assert!(stored.starts_with(CHAT_CIPHERTEXT_PREFIX));
        drop(db);
        let raw_db = std::fs::read(&path).unwrap();
        assert!(!raw_db.windows(canary.len()).any(|w| w == canary.as_bytes()));
        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A locked chat key must not turn a pre-v23 database into a failed open.
    /// The migration completes its schema work, leaves the message rows exactly
    /// as it found them, and encrypts them on the first launch that recovers
    /// the key — nothing is rotated, rewritten or lost in between.
    #[test]
    fn locked_chat_key_defers_v23_encryption_instead_of_failing_the_open() {
        let dir = std::env::temp_dir().join(format!(
            "ember-chat-locked-migrate-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ember.db");
        let friend = "55".repeat(16);
        let canary = "locked-migration-canary-90ab";
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL DEFAULT 0);
                 INSERT INTO schema_version(version) VALUES (22);
                 CREATE TABLE friends (
                    user_hash TEXT PRIMARY KEY, nickname TEXT NOT NULL DEFAULT '',
                    added_at INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE friend_requests (
                    sender_hash TEXT PRIMARY KEY, sender_nickname TEXT NOT NULL DEFAULT '',
                    received_at INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE chat_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    friend_hash TEXT NOT NULL, direction TEXT NOT NULL,
                    message TEXT NOT NULL, timestamp INTEGER NOT NULL,
                    read INTEGER NOT NULL DEFAULT 0
                 );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO chat_messages(friend_hash,direction,message,timestamp,read) \
                 VALUES (?1,'received',?2,77,0)",
                params![friend, canary],
            )
            .unwrap();
        }
        // An unrecoverable key file: not DPAPI-wrapped and not 32 bytes, so it
        // is rejected without being rewritten, exactly like a blob protected
        // under another Windows account.
        let key_path = dir.join(CHAT_KEY_FILE);
        std::fs::write(&key_path, b"unrecoverable").unwrap();

        let locked = Database::open_at(&path).expect("a locked chat key must not fail the open");
        assert!(locked.chat_locked());
        assert_eq!(locked.schema_version(), MAX_SUPPORTED_SCHEMA_VERSION);
        let stored: String = locked
            .conn
            .lock()
            .query_row("SELECT message FROM chat_messages", [], |row| row.get(0))
            .unwrap();
        assert_eq!(stored, canary, "the row must be left exactly as it was");
        let sealed = locked.get_chat_messages(&friend, 10, None).unwrap();
        assert_eq!(sealed.len(), 1);
        assert_eq!(sealed[0].message, CHAT_UNAVAILABLE_TEXT);
        drop(locked);

        // With the key recoverable again the deferred pass finishes the job.
        std::fs::remove_file(&key_path).unwrap();
        let recovered = Database::open_at(&path).expect("reopen");
        assert!(!recovered.chat_locked());
        let stored: String = recovered
            .conn
            .lock()
            .query_row("SELECT message FROM chat_messages", [], |row| row.get(0))
            .unwrap();
        assert!(stored.starts_with(CHAT_CIPHERTEXT_PREFIX));
        let messages = recovered.get_chat_messages(&friend, 10, None).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message, canary);
        drop(recovered);

        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn wrong_chat_key_returns_placeholder_without_destroying_recoverable_ciphertext() {
        let dir = std::env::temp_dir().join(format!(
            "ember-chat-preserve-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ember.db");
        let friend = "44".repeat(16);
        let db = Database::open_at(&path).unwrap();
        let good = db
            .insert_chat_message(&friend, "received", "keep-me")
            .unwrap();
        let correct_key = **db.chat_key.as_ref().expect("test db has a chat key");
        let stored_before: String = db
            .conn
            .lock()
            .query_row(
                "SELECT message FROM chat_messages WHERE id = ?1",
                params![good],
                |row| row.get(0),
            )
            .unwrap();
        assert!(stored_before.starts_with(CHAT_CIPHERTEXT_PREFIX));
        drop(db);

        let wrong_key_db = Database {
            conn: Mutex::new(Connection::open(&path).unwrap()),
            path: path.clone(),
            chat_key: Some(Zeroizing::new([0x5A; 32])),
            corrupt_backup: None,
        };
        let unavailable = wrong_key_db.get_chat_messages(&friend, 10, None).unwrap();
        assert_eq!(unavailable.len(), 1);
        assert_eq!(unavailable[0].message, CHAT_UNAVAILABLE_TEXT);
        assert!(!unavailable[0].message.contains(&stored_before));
        let stored_after: String = wrong_key_db
            .conn
            .lock()
            .query_row(
                "SELECT message FROM chat_messages WHERE id = ?1",
                params![good],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_after.as_bytes(), stored_before.as_bytes());
        drop(wrong_key_db);

        let recovered_db = Database {
            conn: Mutex::new(Connection::open(&path).unwrap()),
            path: path.clone(),
            chat_key: Some(Zeroizing::new(correct_key)),
            corrupt_backup: None,
        };
        let recovered = recovered_db.get_chat_messages(&friend, 10, None).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].message, "keep-me");
        drop(recovered_db);

        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn read_receipt_marks_sent_messages_up_through_the_named_body() {
        let dir = std::env::temp_dir().join(format!(
            "ember-chat-seen-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ember.db");
        let friend = "aa".repeat(16);
        let db = Database::open_at(&path).unwrap();
        let first = db.insert_chat_message(&friend, "sent", "one").unwrap();
        let second = db.insert_chat_message(&friend, "sent", "two").unwrap();
        let third = db.insert_chat_message(&friend, "sent", "three").unwrap();
        db.insert_chat_message(&friend, "received", "two").unwrap();
        db.mark_messages_read(&friend).unwrap();
        let hash = db.latest_read_received_hash(&friend).unwrap().expect("hash");
        let until = db
            .mark_sent_seen_by_hash(&friend, &hash)
            .unwrap()
            .expect("matched our sent copy of the same body");
        assert_eq!(until, second);
        let rows = db.get_chat_messages(&friend, 10, None).unwrap();
        let by_id: std::collections::HashMap<_, _> =
            rows.into_iter().map(|row| (row.id, row.seen)).collect();
        assert!(by_id[&first], "earlier sent lines are covered by the watermark");
        assert!(by_id[&second]);
        assert!(!by_id[&third], "later unsent-to-them lines stay unseen");
        drop(db);
        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A receipt names a body, and bodies repeat. When the newest copy of that
    /// body is still in the outbox, the receipt is for the delivered copy before
    /// it — the friend cannot have read a line that never reached them — and a
    /// queued or failed row between the two must not be swept up either.
    #[test]
    fn read_receipt_resolves_to_the_delivered_copy_of_a_repeated_body() {
        let dir = std::env::temp_dir().join(format!(
            "ember-chat-seen-repeat-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ember.db");
        let friend = "ab".repeat(16);
        let db = Database::open_at(&path).unwrap();
        let delivered_ok = db.insert_chat_message(&friend, "sent", "ok").unwrap();
        let failed = db
            .insert_pending_chat_message(&friend, "did you get that?")
            .unwrap();
        db.set_chat_delivery(failed, CHAT_FAILED).unwrap();
        let queued_ok = db.insert_pending_chat_message(&friend, "ok").unwrap();
        let hash = Database::friend_chat_body_hash_hex("ok");

        let until = db
            .mark_sent_seen_by_hash(&friend, &hash)
            .unwrap()
            .expect("the delivered copy matches");
        assert_eq!(until, delivered_ok, "the queued copy is not a candidate");

        let rows = db.get_chat_messages(&friend, 10, None).unwrap();
        let by_id: std::collections::HashMap<_, _> =
            rows.into_iter().map(|row| (row.id, row.seen)).collect();
        assert!(by_id[&delivered_ok]);
        assert!(!by_id[&failed], "an abandoned line was never read");
        assert!(
            !by_id[&queued_ok],
            "a line still in the outbox was never read"
        );

        // Nothing but outbox copies of a body: no watermark at all.
        let only_queued = Database::friend_chat_body_hash_hex("did you get that?");
        assert_eq!(
            db.mark_sent_seen_by_hash(&friend, &only_queued).unwrap(),
            None
        );
        drop(db);
        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The rotation guard used to look only at `chat_messages`, so a profile
    /// that had only ever used rooms — no direct messages at all — read as
    /// "nothing encrypted here" and had its key replaced. That is unrecoverable:
    /// room history, join secrets and epoch keys are sealed under the same key,
    /// and the replacement is written to disk.
    #[test]
    fn a_channels_only_profile_locks_rather_than_rotating_a_missing_chat_key() {
        let dir = std::env::temp_dir().join(format!(
            "ember-chat-channels-only-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ember.db");
        let channel_id = "ab".repeat(16);
        let pubkey = "cd".repeat(32);

        let db = Database::open_at(&path).unwrap();
        db.insert_channel(
            &channel_id,
            &pubkey,
            "room",
            crate::network::ember::channel::CHANNEL_KIND_PRIVATE,
            true,
            Some(&[0x11u8; 32]),
            Some(&[0x22u8; 32]),
        )
        .unwrap();
        let row_id = db
            .insert_channel_message(
                &channel_id,
                &pubkey,
                "received",
                "room-history",
                &"ef".repeat(16),
                4242,
                "",
                false,
            )
            .unwrap();
        let key_before = **db.chat_key.as_ref().expect("test db has a chat key");
        // Nothing in the direct-message table: the case the old guard missed.
        let dm_rows: i64 = db
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM chat_messages", [], |row| row.get(0))
            .unwrap();
        assert_eq!(dm_rows, 0);
        drop(db);

        let key_path = dir.join(CHAT_KEY_FILE);
        let stored_key = std::fs::read(&key_path).unwrap();
        std::fs::remove_file(&key_path).unwrap();

        let locked = Database::open_at(&path).expect("a missing chat key must not fail the open");
        assert!(
            locked.chat_locked(),
            "a room-only profile must seal, not mint a replacement key"
        );
        assert!(
            !key_path.exists(),
            "no key may be written while ciphertext is still on disk"
        );
        drop(locked);

        // Restoring the original key still recovers everything, which is the
        // whole point of refusing to rotate.
        std::fs::write(&key_path, &stored_key).unwrap();
        let recovered = Database::open_at(&path).expect("reopen");
        assert!(!recovered.chat_locked());
        assert_eq!(
            **recovered.chat_key.as_ref().expect("key"),
            key_before,
            "the original key must be the one in use again"
        );
        let history = recovered.get_channel_messages(&channel_id, 10, None).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].id, row_id);
        assert_eq!(history[0].message, "room-history");
        drop(recovered);

        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// "Remove from this device" was undone by the next gossip replay or
    /// catch-up that carried the line, because the ingest gate only asked
    /// whether the row was present.
    #[test]
    fn a_deleted_channel_message_stays_deleted_when_it_is_offered_again() {
        let dir = std::env::temp_dir().join(format!(
            "ember-channel-tombstone-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ember.db");
        let channel_id = "ab".repeat(16);
        let pubkey = "cd".repeat(32);
        let msg_id = "ef".repeat(16);

        let db = Database::open_at(&path).unwrap();
        db.insert_channel(
            &channel_id,
            &pubkey,
            "room",
            crate::network::ember::channel::CHANNEL_KIND_PUBLIC,
            false,
            None,
            None,
        )
        .unwrap();
        let row_id = db
            .insert_channel_message(
                &channel_id,
                &pubkey,
                "received",
                "forget me",
                &msg_id,
                4242,
                "",
                false,
            )
            .unwrap();
        assert!(!db
            .channel_message_forgotten(&channel_id, &msg_id, &pubkey)
            .unwrap());

        assert!(db.delete_channel_message(&channel_id, row_id).unwrap());
        assert!(
            db.channel_message_forgotten(&channel_id, &msg_id, &pubkey).unwrap(),
            "the id has to be remembered or the line comes back"
        );
        assert!(!db.channel_message_exists(&channel_id, &msg_id).unwrap());

        // A revision arriving for a line we deleted must not recreate it either.
        let now = chrono::Utc::now().timestamp();
        let outcome = db
            .apply_channel_message_edit(
                &channel_id,
                &msg_id,
                &pubkey,
                now,
                now,
                "revised",
                &"11".repeat(64),
                now,
            )
            .unwrap();
        assert_eq!(outcome, ChannelEditOutcome::Forgotten);
        assert!(!db.channel_message_exists(&channel_id, &msg_id).unwrap());
        drop(db);

        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A watermark is the newest timestamp held, so a reply served newest-first
    /// advances it past everything still missing underneath: the same batch came
    /// back every round and a gap wider than one batch never closed. Above a
    /// watermark the reply has to walk forward; a cold room still wants the
    /// newest lines, because it has no gap to walk.
    #[test]
    fn catch_up_walks_forward_above_a_watermark_and_serves_newest_to_a_cold_room() {
        let dir = std::env::temp_dir().join(format!(
            "ember-channel-syncorder-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ember.db");
        let channel_id = "ab".repeat(16);
        let pubkey = "cd".repeat(32);

        let db = Database::open_at(&path).unwrap();
        db.insert_channel(
            &channel_id,
            &pubkey,
            "room",
            crate::network::ember::channel::CHANNEL_KIND_PUBLIC,
            false,
            None,
            None,
        )
        .unwrap();
        for (index, ts) in [1_000i64, 2_000, 3_000].into_iter().enumerate() {
            db.insert_channel_message(
                &channel_id,
                &pubkey,
                "received",
                &format!("line {ts}"),
                &format!("{:02x}", index).repeat(16),
                ts,
                &"11".repeat(64),
                false,
            )
            .unwrap();
        }

        let cold = db.list_channel_messages_for_sync(&channel_id, 0, 2).unwrap();
        assert_eq!(
            cold.iter().map(|row| row.timestamp).collect::<Vec<_>>(),
            vec![3_000, 2_000],
            "a cold room is answered with the newest lines"
        );

        let gap = db
            .list_channel_messages_for_sync(&channel_id, 1_000, 2)
            .unwrap();
        assert_eq!(
            gap.iter().map(|row| row.timestamp).collect::<Vec<_>>(),
            vec![1_000, 2_000],
            "above a watermark the reply must start at the watermark and walk forward"
        );

        // A whole page on the watermark's own second cannot move the requester,
        // so the walk has to step over it or it never terminates.
        for extra in 0..3 {
            db.insert_channel_message(
                &channel_id,
                &pubkey,
                "received",
                "same second",
                &format!("{:02x}", 0x40 + extra).repeat(16),
                1_000,
                &"11".repeat(64),
                false,
            )
            .unwrap();
        }
        let stepped = db
            .list_channel_messages_for_sync(&channel_id, 1_000, 2)
            .unwrap();
        assert!(
            stepped.iter().all(|row| row.timestamp > 1_000),
            "a saturated watermark second must be stepped over, not served again"
        );
        drop(db);

        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }
}
