//! Ember Channels: create, join, list, and local chat.
//!
//! DHT publish/search is forwarded to the network task. Channel peers are
//! never added to `friend_hashes`.

use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::RngCore;
use tauri::Emitter;

use crate::app_state::AppState;
use crate::commands::errors::{await_reply, coded, coded_ctx, CMD_SEND_TIMEOUT};
use crate::network::ember::channel::{
    self, ChannelIdentity, ChannelInvite, CHANNEL_KIND_PRIVATE, CHANNEL_KIND_PUBLIC,
};
use crate::network::ember::dht::publish::{
    ModerationTail, SignedRecord, CHANNEL_BAN_LIST_MAX, CHANNEL_MOD_LIST_MAX, CHANNEL_NAME_MAX,
    CHANNEL_PIN_MAX, CHANNEL_WELCOME_MAX,
};
use crate::network::ember::crypto;
use crate::network::{EmberPublishPending, EmberPublishResult, NetworkCommand};
use crate::storage::database::{
    CachedChannel, ChannelEditOutcome, ChannelReplyLookup, ChannelReplyParent, Database,
    StoredChannel, StoredChannelMember,
};
use tauri_plugin_dialog::DialogExt;

/// Room names are bounded in characters, not only by the record's bytes: a
/// byte cap alone would give an English name 64 characters and a CJK one 21.
/// Thirty-two is as far as the characters can go before [`MAX_CHANNEL_NAME`]
/// is what decides for most scripts anyway; the list shows some 26 whole and
/// ellipsises the rest.
///
/// Builds from before this was raised trim a longer name to their own twenty
/// characters when it arrives (see [`discovered_room_name`] and the invite
/// path), so a long name reads cut short there rather than failing to join.
const MAX_CHANNEL_NAME_CHARS: usize = 32;

/// Rooms one device may own at once, counting every room it has created and
/// not deleted.
///
/// Aimed at scripted name-grabbing rather than at people: a room reserves its
/// name on Rendezvous, so hundreds of throwaway rooms squat hundreds of words
/// and crowd Discover. Ten is well past what anyone runs by hand, and deleting
/// a room gives the slot straight back. Joining rooms is not capped — that
/// costs the namespace nothing, and the gossip layer already tapers off past a
/// handful (`CHANNEL_RENDEZVOUS_MAX_CHANNELS`).
///
/// A local count, so a patched build can ignore it. That is the right split:
/// this stops the accident and the casual script, and the per-IP ceiling on
/// name claims at Rendezvous is what answers a determined one.
const MAX_OWNED_CHANNELS: i64 = 10;

/// Slow-mode delays an owner may choose, in seconds. 0 is off.
///
/// A closed set rather than a free number so every member reads the same
/// wait off the same record, and so the UI cannot offer something the
/// backend would clamp to a different value behind the user's back.
pub(crate) const SLOW_MODE_CHOICES: [u16; 6] = [0, 5, 10, 30, 60, 300];

/// Messages this device will originate into one room per minute.
///
/// Sits above [`channel::CHANNEL_GOSSIP_PER_AUTHOR_PER_SEC`], which bounds a
/// burst, and below any rate a person sustains: twenty a minute is a fast
/// conversation, and a hundred is a script. Per room, because being talkative
/// in two rooms is not spam in either.
///
/// Deliberately enforced when *sending* rather than when receiving. A receiver
/// that dropped what it judged excessive would leave members holding different
/// halves of the same conversation with no way to tell; refusing our own send
/// tells the one person who can do something about it.
const LOCAL_SEND_PER_MINUTE: usize = 20;

/// Byte ceiling the published record imposes whatever the character count
/// says, and the one Rendezvous reserves names under. Twenty-two CJK
/// characters satisfy the character cap and still overrun this. Not raised
/// with the character cap: an invite carrying a longer name is one older
/// builds refuse to parse.
const MAX_CHANNEL_NAME: usize = 64;
const MAX_CHANNEL_MESSAGE: usize = 4096;
const DEFAULT_FIND_TIMEOUT_MS: u64 = 30_000;
/// Tombstone directory is a hint, not membership. The HTTP client can sit
/// on a 60s request timeout; join must not.
const DELETED_DIRECTORY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// Public listings are a hint too. Discover must still walk DHT shards when
/// Rendezvous is slow; five seconds is enough for a healthy directory and
/// short enough that a hung one cannot sit on the HTTP client's 60s budget.
const DIRECTORY_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Same reasoning for every other Rendezvous round-trip a command awaits:
/// worth asking, not worth the HTTP client's full 60s budget with the user
/// watching. Applied through [`registry_call`].
const REGISTRY_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(serde::Serialize)]
pub struct ChannelInfo {
    pub channel_id: String,
    pub pubkey: String,
    pub name: String,
    pub visibility: String,
    pub is_owner: bool,
    pub topic: String,
    pub welcome: String,
    pub joined_at: i64,
    pub last_active: i64,
    /// Members seen inside the presence window, including us.
    pub member_count: i64,
    /// Everyone on this device's roster for the room, present or not; see
    /// `StoredChannel::roster_count`. Stable enough to rank rooms by.
    pub roster_count: i64,
    pub unread: i64,
    pub you_are_banned: bool,
    pub you_are_moderator: bool,
    pub successor_id: String,
    pub predecessor_id: String,
    /// Owner-nominated successor (64-char hex), empty when unset.
    pub successor_nominee: String,
    /// Days of owner silence before that nomination may be claimed; 0 disables.
    pub claim_after_days: i64,
    /// When the owner last republished. The UI counts the claim window from it.
    pub moderation_updated_at: i64,
    /// Whether this device may claim the room right now: it is the nominee and
    /// the owner has been silent past the window.
    pub can_claim: bool,
    /// A private room whose content key has rotated past what we hold, so we
    /// cannot read new traffic until the epoch record sealed to us arrives. Also
    /// what a stale invite looks like from the inside.
    pub key_behind: bool,
    /// Owner's user pubkey (64-char hex), empty until a signed moderation
    /// record naming them has been applied. Used so the roster can hide Ban
    /// on the owner rather than only refusing it on the wire.
    pub owner_pubkey: String,
    /// This device is currently inside the room.
    pub in_room: bool,
    /// Owner has permanently deleted this room.
    pub deleted: bool,
    /// Only the owner may hand out invites for this room.
    pub invites_owner_only: bool,
    /// Seconds a member must wait between messages; 0 when slow mode is off.
    pub slow_mode_secs: i64,
    /// Only the owner and moderators may post.
    pub announce_only: bool,
    /// Hex wire ids of the owner's pinned messages, oldest pin first.
    pub pinned_msg_ids: Vec<String>,
    /// The room's default language code, empty for none.
    pub language: String,
}

impl ChannelInfo {
    fn from_stored(row: StoredChannel, you_are_banned: bool, you_are_moderator: bool) -> Self {
        let key_behind =
            row.visibility == CHANNEL_KIND_PRIVATE && row.key_epoch_wanted > row.key_epoch;
        Self {
            channel_id: row.channel_id,
            pubkey: row.pubkey,
            name: row.name,
            visibility: row.visibility,
            is_owner: row.is_owner,
            topic: row.topic,
            welcome: row.welcome,
            joined_at: row.joined_at,
            last_active: row.last_active,
            member_count: row.member_count,
            roster_count: row.roster_count,
            unread: row.unread,
            you_are_banned,
            you_are_moderator,
            key_behind,
            can_claim: false,
            moderation_updated_at: row.moderation_updated_at,
            successor_nominee: row.successor_nominee,
            claim_after_days: row.claim_after_days,
            successor_id: row.successor_id,
            predecessor_id: row.predecessor_id,
            owner_pubkey: row.owner_pubkey,
            in_room: row.in_room,
            deleted: row.deleted,
            invites_owner_only: row.invites_owner_only,
            slow_mode_secs: row.slow_mode_secs,
            announce_only: row.announce_only,
            pinned_msg_ids: row.pinned_msg_ids,
            language: row.language,
        }
    }

    /// Fill in the two facts that depend on who we are and what time it is.
    ///
    /// Mirrors the checks in `claim_channel_ownership`, including the confirmed
    /// silence one, so the button is not offered for an action that would be
    /// refused — or worse, accepted locally and refused by everyone else.
    fn with_viewer(
        mut self,
        our_pubkey_hex: &str,
        moderation_updated_at: i64,
        moderation_checked_at: i64,
    ) -> Self {
        self.can_claim = !self.is_owner
            && !self.you_are_banned
            && self.successor_id.is_empty()
            && self.claim_after_days > 0
            && moderation_updated_at > 0
            && channel::owner_silence_is_confirmed(moderation_checked_at)
            && self.successor_nominee.eq_ignore_ascii_case(our_pubkey_hex)
            && chrono::Utc::now().timestamp().saturating_sub(moderation_updated_at)
                >= self.claim_after_days.saturating_mul(86_400);
        self
    }
}

#[derive(serde::Serialize)]
pub struct ChannelMemberInfo {
    pub member_pubkey: String,
    pub nickname: String,
    pub last_seen: i64,
    pub banned: bool,
    pub is_self: bool,
    pub moderator: bool,
    /// `BLAKE3(pubkey)[..16]` hex — the Friend ID for this member. Empty when
    /// the stored key is not a valid Ed25519 point.
    pub ember_hash: String,
}

fn ember_hash_for_member_pubkey(hex_pk: &str) -> String {
    let Ok(bytes) = hex::decode(hex_pk) else {
        return String::new();
    };
    let Ok(pk) = <[u8; 32]>::try_from(bytes) else {
        return String::new();
    };
    crypto::node_id_from_ed25519_bytes(&pk)
        .map(hex::encode)
        .unwrap_or_default()
}

impl ChannelMemberInfo {
    fn from_stored(row: StoredChannelMember, is_self: bool) -> Self {
        let ember_hash = ember_hash_for_member_pubkey(&row.member_pubkey);
        Self {
            member_pubkey: row.member_pubkey,
            nickname: row.nickname,
            last_seen: row.last_seen,
            banned: row.banned,
            is_self,
            moderator: row.moderator,
            ember_hash,
        }
    }
}

#[derive(serde::Serialize)]
pub struct ChannelMessageInfo {
    pub id: i64,
    pub sender_pubkey: String,
    pub direction: String,
    pub message: String,
    pub timestamp: i64,
    pub read: bool,
    /// When the author last revised this line, or 0 if they never did.
    pub edited_at: i64,
    /// Wire identity of the line. Exposed because a reaction arriving live names
    /// the message this way, and the local row id means nothing to the peer that
    /// sent it — so the UI needs it to match the two up.
    pub msg_id: String,
    /// `delivered` / `queued` / `failed`, the same vocabulary friend chat uses.
    /// Received lines are always delivered. A sent line is queued until the
    /// flood reaches somebody, and failed once the retry gives up.
    pub delivery: String,
    /// Wire id of the line this one replies to, or `None` for a plain line.
    /// Signed by the author as part of the text (see
    /// [`channel::with_reply_trailer`]); `message` is the body without it.
    pub reply_to: Option<String>,
    /// The parent was written by this device's identity, so the reply is
    /// addressed to us the way a mention is. False whenever the parent is not
    /// held here, since nothing else says who wrote it.
    pub reply_to_me: bool,
    /// The parent as this device holds it, for drawing the quote.
    pub reply_parent: Option<ChannelReplyParent>,
    /// The parent was removed from this device rather than never received.
    pub reply_parent_deleted: bool,
}

/// The stored `delivery` integer as the UI names it.
fn channel_delivery_label(delivery: i64) -> String {
    crate::storage::database::Database::delivery_label(delivery).to_string()
}

/// Whether a reply's parent was written by `mine`, our own identity in hex.
fn reply_parent_is_mine(parent: Option<&ChannelReplyParent>, mine: &str) -> bool {
    parent.is_some_and(|parent| parent.sender_pubkey.eq_ignore_ascii_case(mine))
}

impl ChannelMessageInfo {
    fn from_row(row: crate::storage::database::ChannelMessageRow, mine: &str) -> Self {
        Self {
            id: row.id,
            sender_pubkey: row.sender_pubkey,
            direction: row.direction,
            message: row.message,
            timestamp: row.timestamp,
            read: row.read,
            edited_at: row.edited_at,
            msg_id: row.msg_id,
            delivery: channel_delivery_label(row.delivery),
            reply_to_me: reply_parent_is_mine(row.reply_parent.as_ref(), mine),
            reply_to: row.reply_to,
            reply_parent: row.reply_parent,
            reply_parent_deleted: row.reply_parent_deleted,
        }
    }
}

/// Reaction tally for one line, as the UI draws it.
#[derive(Debug, serde::Serialize, PartialEq, Eq)]
pub struct ChannelReactionInfo {
    pub msg_id: String,
    /// One entry per curated reaction somebody holds, in code order so chips do
    /// not trade places as counts change.
    pub reactions: Vec<ChannelReactionTally>,
    /// This device's own reaction, so the button can show as pressed. 0 is none.
    pub mine: u8,
}

/// How many members hold one reaction on one line, and a few of who they are.
#[derive(Debug, serde::Serialize, PartialEq, Eq)]
pub struct ChannelReactionTally {
    pub reaction: u8,
    pub count: u32,
    /// Member keys, this device's first when it is among them and the rest in
    /// the order they reacted. Capped at [`REACTION_MEMBERS_SHOWN`]: the label
    /// names a handful and says "and N others" for the remainder, and a busy
    /// room should not ship its whole roster per chip on every refresh.
    pub members: Vec<String>,
}

/// Member keys carried per chip. More than any label names.
const REACTION_MEMBERS_SHOWN: usize = 8;

#[derive(serde::Serialize)]
pub struct ChannelInviteInfo {
    pub uri: String,
    pub channel_id: String,
    pub name: String,
    pub private: bool,
}

#[derive(Clone, serde::Serialize)]
pub struct GatheredChannelInfo {
    pub channel_id: String,
    pub pubkey: String,
    pub name: String,
    pub private: bool,
    pub joined: bool,
    /// Members announcing themselves in the room right now, or `None` when we
    /// could not find out. A confirmed 0 and an unanswered probe have to stay
    /// distinguishable, or a card can never drop a count it has outlived.
    pub member_count: Option<i64>,
    /// Default language code from the room's signed listing, empty for none.
    pub language: String,
}

async fn require_ember(state: &AppState) -> Result<(), String> {
    if !state.config.read().await.settings.ember_native_enabled {
        return Err(coded(
            "channels_ember_disabled",
            "Channels require the Ember Network to be on",
        ));
    }
    Ok(())
}

fn sanitize_channel_name(name: &str) -> Result<String, String> {
    let cleaned = crate::security::sanitize_display_name(name);
    if cleaned.is_empty() || cleaned == "Anonymous" && name.trim().is_empty() {
        return Err(coded(
            "channels_name_invalid",
            "Channel name must not be empty",
        ));
    }
    if cleaned.chars().count() > MAX_CHANNEL_NAME_CHARS {
        return Err(coded_ctx(
            "channels_name_too_long",
            format!("Room name too long (max {MAX_CHANNEL_NAME_CHARS} characters)"),
            MAX_CHANNEL_NAME_CHARS,
        ));
    }
    // Only reachable from a caller that is not the compose form, which stops
    // at the character cap. Reported the same way: both mean "shorten it".
    if cleaned.len() > MAX_CHANNEL_NAME {
        return Err(coded_ctx(
            "channels_name_too_long",
            format!("Room name too long (max {MAX_CHANNEL_NAME} bytes)"),
            MAX_CHANNEL_NAME_CHARS,
        ));
    }
    Ok(cleaned)
}

const CHANNEL_USERNAME_MIN: usize = 2;
pub(crate) const CHANNEL_USERNAME_MAX: usize = 12;

/// Letters and numbers only, 2–12 characters, never Anonymous. Returns the
/// display form (original case); the claim key is the lowercase of that.
pub(crate) fn sanitize_channel_username(name: &str) -> Result<String, String> {
    let cleaned: String = name
        .chars()
        .filter(|c| {
            !c.is_control() && *c != '\0' && !crate::security::is_invisible_or_bidi_control_pub(*c)
        })
        .collect::<String>()
        .trim()
        .to_string();
    let valid = cleaned.len() >= CHANNEL_USERNAME_MIN
        && cleaned.len() <= CHANNEL_USERNAME_MAX
        && cleaned.chars().all(|c| c.is_ascii_alphanumeric())
        && !cleaned.eq_ignore_ascii_case("anonymous");
    if !valid {
        return Err(coded(
            "channels_username_invalid",
            "Channel username must be 2–12 letters or numbers",
        ));
    }
    Ok(cleaned)
}

fn username_claim_key(display: &str) -> String {
    display.to_lowercase()
}

fn registry_fail(err: crate::network::rendezvous::ChannelRegistryError, taken: &'static str) -> String {
    match err {
        crate::network::rendezvous::ChannelRegistryError::Taken => coded(
            taken,
            "That name is already taken",
        ),
        crate::network::rendezvous::ChannelRegistryError::Forbidden => coded(
            "channels_delete_forbidden",
            "Only the channel owner can delete this room",
        ),
        crate::network::rendezvous::ChannelRegistryError::Invalid => coded(
            "channels_name_invalid",
            "Channel name must not be empty",
        ),
        crate::network::rendezvous::ChannelRegistryError::Unavailable => coded(
            "channels_registry_unavailable",
            "The name registry is unreachable; try again when online",
        ),
        crate::network::rendezvous::ChannelRegistryError::TooSoon => coded(
            "channels_rename_too_soon",
            "A room can be renamed once a day",
        ),
        crate::network::rendezvous::ChannelRegistryError::Unsupported => coded(
            "channels_rename_unsupported",
            "Renaming rooms isn't available on this server yet",
        ),
    }
}

async fn rendezvous_url(state: &AppState) -> String {
    state.config.read().await.settings.rendezvous_url.clone()
}

/// Bound a Rendezvous call.
///
/// The pinned HTTP client waits up to 60s for a response, which is a sane
/// ceiling for a background task and far too long for anything a user is
/// sitting in front of. A timeout reports `Unavailable` — indistinguishable,
/// from the caller's point of view, from the unreachable registry it probably
/// is, and already mapped to a message telling them to try again when online.
async fn registry_call<T>(
    fut: impl std::future::Future<
        Output = Result<T, crate::network::rendezvous::ChannelRegistryError>,
    >,
) -> Result<T, crate::network::rendezvous::ChannelRegistryError> {
    tokio::time::timeout(REGISTRY_CALL_TIMEOUT, fut)
        .await
        .unwrap_or(Err(
            crate::network::rendezvous::ChannelRegistryError::Unavailable,
        ))
}

async fn require_channel_username(state: &AppState) -> Result<String, String> {
    let name = state.config.read().await.settings.channel_username.clone();
    if name.trim().is_empty() {
        return Err(coded(
            "channels_username_required",
            "Choose a Channel username before creating or joining a room",
        ));
    }
    sanitize_channel_username(&name)
}

async fn persist_channel_username(state: &AppState, username: &str) -> Result<(), String> {
    let _guard = state.settings_save_lock.lock().await;
    let (new_settings, save_data) = {
        let config = state.config.read().await;
        let mut new_settings = config.settings.clone();
        new_settings.channel_username = username.to_string();
        new_settings.settings_revision = config.settings.settings_revision.saturating_add(1);
        let data = config.prepare_save_settings(&new_settings).map_err(|e| {
            coded_ctx(
                "settings_serialize_failed",
                "Failed to serialize settings",
                e,
            )
        })?;
        (new_settings, data)
    };
    tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(&save_data.0, &save_data.1, &save_data.2)
    })
    .await
    .map_err(|e| coded_ctx("settings_transaction_task_failed", "Save failed", e))?
    .map_err(|e| coded_ctx("settings_save_failed", "Save failed", e))?;
    state.config.write().await.settings = new_settings.clone();
    // The network loop keeps its own copy of settings. Without this it keeps
    // publishing (or skipping) presence under the old handle until the next
    // Settings save or restart — and an empty handle makes the republish
    // path return without scanning any room.
    let _ = state
        .network_tx
        .try_send(NetworkCommand::UpdateSettings {
            settings: Box::new(new_settings),
        });
    apply_channel_username_locally(state, username);
    Ok(())
}

/// Rename our own roster rows to match a newly chosen Channel username.
///
/// Presence republish is *not* kicked from here. Clearing the stamps before
/// the network loop has swapped its settings copy lets it publish the old
/// handle into the newly-due slots. The loop does that work when it applies
/// `UpdateSettings`.
pub(crate) fn apply_channel_username_locally(state: &AppState, username: &str) {
    let pk = hex::encode(state.identity.ed25519_public_key);
    let _ = state.db.rename_self_channel_member(&pk, username);
}

/// Claim `username` on Rendezvous and return the stored display form.
pub(crate) async fn claim_username_on_registry(
    state: &AppState,
    username: &str,
) -> Result<String, String> {
    let display = sanitize_channel_username(username)?;
    let key = username_claim_key(&display);
    let url = rendezvous_url(state).await;
    registry_call(crate::network::rendezvous::claim_channel_username(
        &url,
        &state.identity.ed25519_public_key,
        &state.identity.ed25519_secret_key,
        &key,
    ))
    .await
    .map_err(|e| registry_fail(e, "channels_username_taken"))?;
    Ok(display)
}

fn coded_has_code(err: &str, code: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(err)
        .ok()
        .and_then(|value| value.get("code")?.as_str().map(|found| found == code))
        .unwrap_or(false)
}

/// Re-assert this device's claim on its Channel username before publishing
/// presence under it.
///
/// A refusal fails the caller: presence carries this handle to everyone in the
/// room, so going ahead with one the registry has since given to somebody else
/// is how a member ends up wearing another's name. An unreachable or slow
/// registry is not a refusal — the local handle stands and the daily refresh in
/// `maybe_publish_channel_presence` tries again.
async fn reassert_channel_username(state: &AppState, username: &str) -> Result<String, String> {
    match claim_username_on_registry(state, username).await {
        Ok(display) => Ok(display),
        // `registry_call` reports a timeout as unavailable, so this one arm
        // covers both "the registry said nothing" cases.
        Err(e) if coded_has_code(&e, "channels_registry_unavailable") => Ok(username.to_string()),
        Err(e) => Err(e),
    }
}

fn sanitize_topic(topic: &str) -> Result<String, String> {
    let cleaned = crate::security::sanitize_remote_text(topic, CHANNEL_NAME_MAX);
    Ok(truncate_bytes(cleaned, CHANNEL_NAME_MAX))
}

fn sanitize_welcome(welcome: &str) -> Result<String, String> {
    let cleaned = crate::security::sanitize_remote_text(welcome, CHANNEL_WELCOME_MAX);
    Ok(truncate_bytes(cleaned, CHANNEL_WELCOME_MAX))
}

fn truncate_bytes(s: String, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn parse_member_pubkey(hex_str: &str) -> Result<[u8; 32], String> {
    let canonical = hex_str.trim().to_ascii_lowercase();
    let bytes = hex::decode(&canonical).map_err(|_| {
        coded(
            "channels_member_invalid",
            "Invalid member key",
        )
    })?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        coded(
            "channels_member_invalid",
            "Invalid member key",
        )
    })
}

fn parse_channel_id(hex_str: &str) -> Result<String, String> {
    let canonical = hex_str.trim().to_ascii_lowercase();
    if canonical.len() != 32 || hex::decode(&canonical).map(|b| b.len()).unwrap_or(0) != 16 {
        return Err(coded(
            "channels_invite_invalid",
            "Invalid channel id",
        ));
    }
    Ok(canonical)
}

/// The 16 raw bytes of an already-canonical channel id, for the signing and
/// framing calls that want them rather than the hex.
fn channel_id_bytes(canonical: &str) -> Result<[u8; 16], String> {
    let mut out = [0u8; 16];
    hex::decode_to_slice(canonical, &mut out)
        .map_err(|_| coded("channels_not_found", "Channel not found"))?;
    Ok(out)
}

/// The 16 raw bytes of a stored message's wire id.
///
/// A row copied across a handoff carries a synthetic id (`handoff-<room>-<n>`)
/// rather than 16 hex bytes, because the original was signed against the old
/// room and cannot be re-served under the new one. Those lines are therefore not
/// addressable on the wire, which is exactly why editing or reacting to one has
/// to fail here rather than flood a frame nobody can match.
fn parse_msg_id(msg_id: &str) -> Result<[u8; 16], String> {
    let mut out = [0u8; 16];
    hex::decode_to_slice(msg_id, &mut out).map_err(|_| {
        coded(
            "channels_message_not_addressable",
            "This message cannot be edited or reacted to",
        )
    })?;
    Ok(out)
}

/// Write our own row into `channel_members`. Not optional: gossip fanout picks
/// neighbors out of that table and bails when it is empty, so a room without
/// this row is joined in name only. `fail_code` lets the caller keep its own
/// translated framing (create vs join).
async fn record_self_member(
    state: &AppState,
    channel_id: &str,
    nickname: &str,
    fail_code: &'static str,
) -> Result<(), String> {
    let db = state.db.clone();
    let id = channel_id.to_string();
    let pk = hex::encode(state.identity.ed25519_public_key);
    let nick = nickname.to_string();
    tokio::task::spawn_blocking(move || {
        db.upsert_channel_member(&id, &pk, &nick, chrono::Utc::now().timestamp(), Some(&pk))
            .map(|_| ())
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx(fail_code, "Could not record your membership", e))
}

/// Drop a room whose member row could not be written. Nothing has been
/// published at that point, so leaving no trace lets the user simply retry
/// instead of owning a room that can never mesh.
async fn discard_partial_channel(state: &AppState, channel_id: &str) {
    let db = state.db.clone();
    let id = channel_id.to_string();
    let outcome = tokio::task::spawn_blocking(move || db.delete_channel(&id, None)).await;
    let failure = match outcome {
        Ok(Ok(_)) => return,
        Ok(Err(e)) => e.to_string(),
        Err(e) => e.to_string(),
    };
    tracing::warn!(
        channel_id = %channel_id,
        error = %failure,
        "could not roll back a channel whose member row failed to write"
    );
}

#[tauri::command]
pub async fn list_channels(state: tauri::State<'_, AppState>) -> Result<Vec<ChannelInfo>, String> {
    require_ember(&state).await?;
    let our_pk = hex::encode(state.identity.ed25519_public_key);
    let db = state.db.clone();
    let rows = tokio::task::spawn_blocking(move || {
        let rows = db.list_channels()?;
        // Both flags for every room in one statement. Asking per row made the
        // command `1 + 2N` statements, and while it runs on the blocking pool
        // rather than the reactor, each one still takes the single SQLite
        // connection the network loop needs — and the page calls this on every
        // channel event.
        //
        // Propagated rather than defaulted, as the per-row reads were: showing
        // a banned member an unbanned composer hands them a box whose sends
        // every peer will drop, so a failed read must not read as "not banned".
        let flags = db.channel_member_flags(&our_pk)?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            // No roster row in a room means neither flag is set there. That is
            // the absent entry, not a failure — the query above already spoke
            // for the whole table.
            let (banned, moderator) = flags
                .get(&row.channel_id)
                .copied()
                .unwrap_or((false, false));
            // Owners are exempt from their own room's bans, for the reasons in
            // `self_banned_from`.
            let you_are_banned = !row.is_owner && banned;
            let you_are_moderator = moderator;
            let moderation_updated_at = row.moderation_updated_at;
            let moderation_checked_at = row.moderation_checked_at;
            out.push(
                ChannelInfo::from_stored(row, you_are_banned, you_are_moderator).with_viewer(
                    &our_pk,
                    moderation_updated_at,
                    moderation_checked_at,
                ),
            );
        }
        Ok::<_, anyhow::Error>(out)
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_list_failed", "Failed to list channels", e))?;
    Ok(rows)
}

#[tauri::command]
pub async fn create_channel(
    state: tauri::State<'_, AppState>,
    name: String,
    private: bool,
    language: Option<String>,
) -> Result<ChannelInviteInfo, String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to create a channel",
        ));
    }
    let name = sanitize_channel_name(&name)?;
    let language = parse_channel_language(language.as_deref())?;
    // Counted before the name is claimed, so a refusal costs the namespace
    // nothing and the user is not told a room exists that does not.
    let db_count = state.db.clone();
    let owned_now = tokio::task::spawn_blocking(move || db_count.count_owned_channels())
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_create_failed", "Failed to create channel", e))?;
    if owned_now >= MAX_OWNED_CHANNELS {
        return Err(coded(
            "channels_owned_limit",
            "You already own the most rooms one device can hold. Delete a room to make space.",
        ));
    }
    let username = require_channel_username(&state).await?;
    let username = reassert_channel_username(&state, &username).await?;
    let ident = ChannelIdentity::generate();
    let join_secret = if private {
        channel::generate_private_join_secret()
    } else {
        channel::public_join_secret(&ident.pubkey)
    };
    let visibility = if private {
        CHANNEL_KIND_PRIVATE
    } else {
        CHANNEL_KIND_PUBLIC
    };
    let channel_id_hex = hex::encode(ident.channel_id);
    let pubkey_hex = hex::encode(ident.pubkey);
    let url = rendezvous_url(&state).await;
    let channel_seed = ident.seed();
    let seed = channel_seed;
    let db = state.db.clone();
    let db_id = channel_id_hex.clone();
    let db_pk = pubkey_hex.clone();
    let db_name = name.clone();
    tokio::task::spawn_blocking(move || {
        db.insert_channel_with_language(
            &db_id,
            &db_pk,
            &db_name,
            visibility,
            true,
            Some(&seed),
            if private { Some(&join_secret) } else { None },
            language.unwrap_or(""),
        )
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_create_failed", "Failed to create channel", e))?;

    // Bounded and fatal, unlike the username re-claim above: this call is what
    // makes the name ours, so proceeding without an answer would publish a room
    // under a name the registry never granted. `discard_partial_channel` leaves
    // no trace, so a timeout is simply a retry.
    if let Err(e) = registry_call(crate::network::rendezvous::claim_channel_name(
        &url,
        &ident.channel_id,
        &ident.pubkey,
        &channel_seed,
        &name,
        private,
    ))
    .await
    {
        discard_partial_channel(&state, &channel_id_hex).await;
        return Err(registry_fail(e, "channels_name_taken"));
    }

    let nickname = username;
    if let Err(e) =
        record_self_member(&state, &channel_id_hex, &nickname, "channels_create_failed").await
    {
        let _ = registry_call(crate::network::rendezvous::delete_channel_registry(
            &url,
            &ident.channel_id,
            &ident.pubkey,
            &channel_seed,
        ))
        .await;
        discard_partial_channel(&state, &channel_id_hex).await;
        return Err(e);
    }

    if !private {
        let record = SignedRecord::channel_index(
            &name,
            ident.channel_id,
            ident.pubkey,
            false,
            language,
            &ident.signing_key,
        );
        // Not fatal — the room exists locally and the owner maintenance loop
        // republishes the listing within the hour. Until it does the room is
        // undiscoverable, and a discarded error made that indistinguishable
        // from a room nobody happened to browse for.
        if let Err(e) = queue_signed_record(&state, record).await {
            tracing::warn!(
                channel_id = %channel_id_hex,
                error = %e,
                "public room created but its index record did not publish"
            );
        }
    }
    let presence = SignedRecord::channel_presence(
        &nickname,
        ident.channel_id,
        ident.pubkey,
        &join_secret,
        private,
        channel::presence_epoch(chrono::Utc::now().timestamp()),
        &state.identity.noise_public_key,
        &crypto::signing_key_from_bytes(&state.identity.ed25519_secret_key),
    );
    if let Err(e) = queue_signed_record(&state, presence).await {
        tracing::warn!(
            channel_id = %channel_id_hex,
            error = %e,
            "room created but its presence record did not publish"
        );
    }
    // From the same stamp sequence as every later snapshot, so an edit made in
    // the room's first second still outranks this one.
    let now = chrono::Utc::now().timestamp();
    let opening_at = {
        let db = state.db.clone();
        let id = channel_id_hex.clone();
        tokio::task::spawn_blocking(move || db.stamp_owner_snapshot(&id, now))
            .await
            .ok()
            .and_then(Result::ok)
            .flatten()
            .unwrap_or(now)
    };
    let moderation = SignedRecord::channel_moderation_at(
        "",
        "",
        &[],
        &[],
        // Names us as owner from the very first record, so a member who joins
        // before any moderation edit already knows who cannot be banned. The
        // language too, or a member would read the room as having none.
        &ModerationTail {
            owner_pubkey: Some(state.identity.ed25519_public_key),
            key_epoch: Some(0),
            language,
            ..Default::default()
        },
        ident.channel_id,
        ident.pubkey,
        private,
        &ident.signing_key,
        opening_at,
    );
    // An empty topic, welcome and lists cannot overrun the record budget, so
    // this only fires if those limits are ever changed out from under it.
    if let Some(moderation) = moderation {
        if let Err(e) = queue_signed_record(&state, moderation).await {
            tracing::warn!(
                channel_id = %channel_id_hex,
                error = %e,
                "room created but its moderation record did not publish"
            );
        }
    } else {
        tracing::error!("Ember: the opening channel moderation record does not fit a STORE");
    }
    // Remember it locally too, so this device's roster can hide Ban on us
    // without waiting for our own DHT record to be fetched back.
    let db_owner = state.db.clone();
    let id_owner = channel_id_hex.clone();
    let owner_pk = state.identity.ed25519_public_key;
    match tokio::task::spawn_blocking(move || {
        db_owner.apply_channel_moderation(
            &id_owner,
            "",
            "",
            // Older than any snapshot this device signs, so it never outranks one.
            1,
            &[],
            &[],
            Some(&owner_pk),
            None,
            None,
            Some(0),
            // A new room starts open; the owner can close it afterwards.
            Some(false),
            // And unthrottled, for the same reason.
            None,
        )
    })
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            tracing::error!(
                channel_id = %channel_id_hex,
                error = %e,
                "could not apply the opening moderation snapshot locally"
            );
        }
        Err(e) => {
            tracing::error!(
                channel_id = %channel_id_hex,
                error = %e,
                "opening moderation snapshot task failed"
            );
        }
    }

    // Same kick join uses: an empty room otherwise waits the idle presence
    // cadence (~20s) before this device even looks for anyone else.
    let _ = state
        .network_tx
        .try_send(NetworkCommand::RefreshChannelMembers {
            channel_id: ident.channel_id,
        });
    let _ = state
        .network_tx
        .try_send(NetworkCommand::AnnounceChannelPresence {
            channel_id: ident.channel_id,
            departed: false,
        });

    let invite = ChannelInvite {
        channel_id: ident.channel_id,
        pubkey: ident.pubkey,
        name: name.clone(),
        join_secret,
        private,
        // A room that has just been created has never rotated.
        key_epoch: 0,
    };
    Ok(ChannelInviteInfo {
        uri: invite.format(),
        channel_id: channel_id_hex,
        name,
        private,
    })
}

#[tauri::command]
pub async fn join_channel(
    state: tauri::State<'_, AppState>,
    uri: String,
) -> Result<ChannelInfo, String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to join a channel",
        ));
    }
    let username = require_channel_username(&state).await?;
    let invite = ChannelInvite::parse(&uri).ok_or_else(|| {
        coded(
            "channels_invite_invalid",
            "That is not a valid ember-channel invite",
        )
    })?;
    let name = if invite.name.is_empty() {
        let id_hex = hex::encode(invite.channel_id);
        id_hex[..8].to_string()
    } else {
        // A room named before this cap existed, or by a peer that never had it,
        // is trimmed to the same length rather than refused — the name is
        // theirs to choose, ours only to draw.
        sanitize_channel_name(&invite.name).unwrap_or_else(|_| {
            crate::security::sanitize_remote_text(&invite.name, MAX_CHANNEL_NAME_CHARS)
        })
    };
    let channel_id_hex = hex::encode(invite.channel_id);

    let db = state.db.clone();
    let existing = tokio::task::spawn_blocking({
        let db = db.clone();
        let id = channel_id_hex.clone();
        move || db.get_channel(&id)
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_join_failed", "Failed to join channel", e))?;
    if let Some(row) = existing {
        if row.deleted {
            return Err(coded(
                "channels_deleted",
                "This channel has been deleted",
            ));
        }
        // Local rows already know `deleted`. A directory round-trip here made
        // re-entry wait on Rendezvous even though membership is local.
        return enter_stored_channel(&state, &channel_id_hex, &username).await;
    }

    refuse_deleted_channel(&state, &channel_id_hex).await?;

    // Only a first join reaches here — re-entry returned above — so this costs
    // a bounded round-trip once per room rather than on every walk back in.
    let username = reassert_channel_username(&state, &username).await?;

    let pubkey_hex = hex::encode(invite.pubkey);
    let visibility = if invite.private {
        CHANNEL_KIND_PRIVATE
    } else {
        CHANNEL_KIND_PUBLIC
    };
    let join_secret = invite.join_secret;
    let private = invite.private;
    let db_id = channel_id_hex.clone();
    tokio::task::spawn_blocking({
        let db = db.clone();
        let id = db_id.clone();
        let pk = pubkey_hex.clone();
        let nm = name.clone();
        move || {
            db.insert_channel(
                &id,
                &pk,
                &nm,
                visibility,
                false,
                None,
                if private { Some(&join_secret) } else { None },
            )
        }
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_join_failed", "Failed to join channel", e))?;

    if private && invite.key_epoch > 0 {
        let db = db.clone();
        let id = db_id.clone();
        let epoch = invite.key_epoch.min(i64::MAX as u64) as i64;
        if let Err(e) =
            tokio::task::spawn_blocking(move || db.insert_channel_key_epoch(&id, epoch, &join_secret))
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))
                .and_then(|r| r)
        {
            tracing::warn!(channel_id = %db_id, error = %e, "could not record the invite's epoch");
        }
    }

    if let Err(e) = record_self_member(&state, &db_id, &username, "channels_join_failed").await {
        discard_partial_channel(&state, &db_id).await;
        return Err(e);
    }

    publish_join_presence(&state, &invite, &username).await;
    let our_pk = hex::encode(state.identity.ed25519_public_key);
    let db = state.db.clone();
    let ours = our_pk.clone();
    // Read the flags rather than assuming a fresh row cannot carry them.
    // `forget_channel` goes out of its way to keep a ban on us alive across the
    // delete — precisely so a ban survives forget-and-rejoin — so this row can
    // and does arrive already banned. Hardcoding `false` handed the user an
    // enabled composer that refused the first thing they typed, and stayed
    // wrong until the next `list_channels`.
    let (row, you_are_banned, you_are_moderator) = tokio::task::spawn_blocking(move || {
        let row = db.get_channel(&db_id)?;
        let banned = db.channel_member_is_banned(&db_id, &ours)?;
        let moderator = db.channel_member_is_moderator(&db_id, &ours)?;
        Ok::<_, anyhow::Error>((row, banned, moderator))
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_join_failed", "Failed to join channel", e))?;
    let row = row.ok_or_else(|| coded("channels_not_found", "Channel not found"))?;
    let updated_at = row.moderation_updated_at;
    let checked_at = row.moderation_checked_at;
    Ok(
        ChannelInfo::from_stored(row, you_are_banned, you_are_moderator)
            .with_viewer(&our_pk, updated_at, checked_at),
    )
}

/// Re-enter a room this device already has a row for, without an invite URI.
#[tauri::command]
pub async fn enter_channel(
    state: tauri::State<'_, AppState>,
    channel_id: String,
) -> Result<ChannelInfo, String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to join a channel",
        ));
    }
    let username = require_channel_username(&state).await?;
    let channel_id = parse_channel_id(&channel_id)?;
    enter_stored_channel(&state, &channel_id, &username).await
}

async fn refuse_deleted_channel(
    state: &AppState,
    channel_id: &str,
) -> Result<(), String> {
    let url = rendezvous_url(state).await;
    let fetch = crate::network::rendezvous::fetch_deleted_channel_ids(&url);
    match tokio::time::timeout(DELETED_DIRECTORY_TIMEOUT, fetch).await {
        Ok(Ok(ids)) if ids.iter().any(|id| id.eq_ignore_ascii_case(channel_id)) => {
            Err(coded(
                "channels_deleted",
                "This channel has been deleted",
            ))
        }
        Ok(Ok(_)) => Ok(()),
        // Tombstones are a directory hint, not uniqueness. A private invite
        // must still work when Rendezvous is unreachable or slow.
        Ok(Err(_)) | Err(_) => Ok(()),
    }
}

async fn enter_stored_channel(
    state: &AppState,
    channel_id: &str,
    username: &str,
) -> Result<ChannelInfo, String> {
    let db = state.db.clone();
    let id = channel_id.to_string();
    let row = tokio::task::spawn_blocking({
        let db = db.clone();
        let id = id.clone();
        move || {
            let row = db.get_channel(&id)?;
            if let Some(ref row) = row {
                if row.deleted {
                    return Err(anyhow::anyhow!("deleted"));
                }
                db.set_channel_in_room(&id, true)?;
            }
            Ok::<_, anyhow::Error>(row)
        }
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| {
        if e.to_string().contains("deleted") {
            coded("channels_deleted", "This channel has been deleted")
        } else {
            coded_ctx("channels_join_failed", "Failed to join channel", e)
        }
    })?
    .ok_or_else(|| coded("channels_not_found", "Channel not found"))?;

    if let Err(e) = record_self_member(state, channel_id, username, "channels_join_failed").await {
        let db = state.db.clone();
        let id = channel_id.to_string();
        // A rollback that itself fails leaves `in_room = true` for a join this
        // call is about to report as failed, so the room reappears in
        // `list_channels` as one the user never joined. Nothing here can undo
        // that, but it must not be invisible.
        match tokio::task::spawn_blocking(move || db.set_channel_in_room(&id, false)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => tracing::error!(
                channel_id = %channel_id,
                %error,
                "failed join left in_room set: rollback update failed"
            ),
            Err(error) => tracing::error!(
                channel_id = %channel_id,
                %error,
                "failed join left in_room set: rollback task did not run"
            ),
        }
        return Err(e);
    }
    let Ok(id_bytes) = hex::decode(&row.channel_id) else {
        return Err(coded("channels_not_found", "Channel not found"));
    };
    let Ok(channel_id_bytes) = <[u8; 16]>::try_from(id_bytes) else {
        return Err(coded("channels_not_found", "Channel not found"));
    };
    let Ok(pk_bytes) = hex::decode(&row.pubkey) else {
        return Err(coded("channels_invite_invalid", "Stored channel pubkey is invalid"));
    };
    let Ok(pubkey) = <[u8; 32]>::try_from(pk_bytes) else {
        return Err(coded("channels_invite_invalid", "Stored channel pubkey is invalid"));
    };
    let private = row.visibility == CHANNEL_KIND_PRIVATE;
    let join_secret = join_secret_for_channel(state, &row).await.unwrap_or_else(|| {
        if private {
            [0u8; 32]
        } else {
            channel::public_join_secret(&pubkey)
        }
    });
    if private && join_secret == [0u8; 32] {
        return Err(coded(
            "channels_join_failed",
            "This private channel has no join secret on this device",
        ));
    }
    let invite = ChannelInvite {
        channel_id: channel_id_bytes,
        pubkey,
        name: row.name.clone(),
        join_secret,
        private,
        key_epoch: row.key_epoch.max(0) as u64,
    };
    publish_join_presence(state, &invite, username).await;
    let db = state.db.clone();
    let id = channel_id.to_string();
    let our_pk = hex::encode(state.identity.ed25519_public_key);
    let refreshed = tokio::task::spawn_blocking(move || {
        let row = db.get_channel(&id)?.ok_or_else(|| anyhow::anyhow!("missing"))?;
        let banned = !row.is_owner && db.channel_member_is_banned(&row.channel_id, &our_pk)?;
        let moderator = db.channel_member_is_moderator(&row.channel_id, &our_pk)?;
        let updated_at = row.moderation_updated_at;
        let checked_at = row.moderation_checked_at;
        Ok::<_, anyhow::Error>(
            ChannelInfo::from_stored(row, banned, moderator)
                .with_viewer(&our_pk, updated_at, checked_at),
        )
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_join_failed", "Failed to join channel", e))?;
    Ok(refreshed)
}

async fn publish_join_presence(state: &AppState, invite: &ChannelInvite, username: &str) {
    let presence = SignedRecord::channel_presence(
        username,
        invite.channel_id,
        invite.pubkey,
        &invite.join_secret,
        invite.private,
        channel::presence_epoch(chrono::Utc::now().timestamp()),
        &state.identity.noise_public_key,
        &crypto::signing_key_from_bytes(&state.identity.ed25519_secret_key),
    );
    if let Err(e) = queue_signed_record(state, presence).await {
        tracing::warn!(
            channel_id = %hex::encode(invite.channel_id),
            error = %e,
            "join presence did not publish"
        );
    }
    let _ = state
        .network_tx
        .try_send(NetworkCommand::RefreshChannelMembers {
            channel_id: invite.channel_id,
        });
    // The DHT record above is the durable copy and the slow one: it has to be
    // stored, then found by a walk somebody else runs on their own timer, so on
    // its own it can be minutes before the room knows anyone arrived. This is
    // the same signed fact taking the path chat takes.
    let _ = state
        .network_tx
        .try_send(NetworkCommand::AnnounceChannelPresence {
            channel_id: invite.channel_id,
            departed: false,
        });
}

#[tauri::command]
pub async fn leave_channel(
    state: tauri::State<'_, AppState>,
    channel_id: String,
) -> Result<(), String> {
    require_ember(&state).await?;
    let channel_id = parse_channel_id(&channel_id)?;
    // Straight to the write. The room used to be read first for the key and the
    // visibility the tombstone was built from, and `set_channel_in_room` reports
    // a missing row on its own, so the read is only a second chance to race.
    let db = state.db.clone();
    let leave_id = channel_id.clone();
    let left = tokio::task::spawn_blocking(move || db.set_channel_in_room(&leave_id, false))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_leave_failed", "Failed to leave channel", e))?;
    if !left {
        return Err(coded("channels_not_found", "Channel not found"));
    }
    if let Ok(bytes) = hex::decode(&channel_id) {
        if let Ok(id) = <[u8; 16]>::try_from(bytes.as_slice()) {
            let _ = state
                .network_tx
                .try_send(NetworkCommand::DropChannelTransfers {
                    channel_id: id,
                    member: None,
                });
            // Tell the room now, on the mesh, rather than leaving everyone to
            // notice we stopped beating. The DHT tombstone below is the copy
            // that reaches members who are offline at this moment; this is the
            // one that reaches the people currently looking at the roster.
            let _ = state
                .network_tx
                .try_send(NetworkCommand::AnnounceChannelPresence {
                    channel_id: id,
                    departed: true,
                });
        }
    }
    // Same presence key, newer timestamp, CHANNEL_FLAG_DEPARTED. Ingest on
    // this build drops the member; the store TTL is short. Not a new wire
    // type — flags already lived in file_size — so older peers treat this as
    // a last announce until it expires.
    //
    // Recorded as owed rather than published here. This was one fire-and-forget
    // STORE, so a leave attempted with no route to the storing nodes left us on
    // every other roster until we aged out twenty minutes later — with nothing
    // that could notice or try again. The network loop owns the retry, exactly
    // as it does for a live announcement, and clears the marker once one lands.
    let _ = state
        .db
        .mark_channel_departure_due(&channel_id, chrono::Utc::now().timestamp());
    Ok(())
}

/// Drop a room this device has left and does not own.
///
/// Leaving only clears `in_room`, and the list is built from every row, so a
/// room joined once stayed in it forever with nothing that could clear it.
///
/// The row is deleted rather than flagged `deleted`: that flag is what
/// `refuse_deleted_channel` reads, so setting it here would quietly turn "take
/// this off my list" into "never let me back in". Removing the row leaves the
/// room reachable through Discover or a fresh invite, which is what a member
/// who changes their mind expects.
#[tauri::command]
pub async fn forget_channel(
    state: tauri::State<'_, AppState>,
    channel_id: String,
) -> Result<(), String> {
    let channel_id = parse_channel_id(&channel_id)?;
    let db = state.db.clone();
    let row_id = channel_id.clone();
    let row = tokio::task::spawn_blocking(move || db.get_channel(&row_id))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_forget_failed", "Failed to remove the room", e))?;
    let Some(row) = row else {
        return Err(coded("channels_not_found", "Channel not found"));
    };
    if row.in_room {
        return Err(coded(
            "channels_forget_joined",
            "Leave the room before removing it from your list",
        ));
    }
    // An owner's row carries the room's key and, once deleted, the tombstone
    // that stops this device rejoining something it destroyed. Neither is ours
    // to discard behind a list-tidying button.
    if row.is_owner {
        return Err(coded(
            "channels_forget_owned",
            "Delete the room instead of removing it from your list",
        ));
    }
    let db = state.db.clone();
    let forget_id = channel_id.clone();
    // Keep a ban standing against us. Removing a room is a rejoinable act, and
    // the member row is keyed by channel id rather than by the room row, so it
    // is waiting when we walk back in. Dropping it would hand a banned member a
    // working composer until the next moderation fetch, with every peer
    // discarding what they typed. `delete_channel` preserves the row only when
    // it is actually a ban, so passing our key unconditionally is free.
    let our_pubkey = hex::encode(state.identity.ed25519_public_key);
    tokio::task::spawn_blocking(move || db.delete_channel(&forget_id, Some(&our_pubkey)))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_forget_failed", "Failed to remove the room", e))?;
    Ok(())
}

#[tauri::command]
pub async fn claim_channel_username(
    state: tauri::State<'_, AppState>,
    name: String,
) -> Result<String, String> {
    let display = claim_username_on_registry(&state, &name).await?;
    persist_channel_username(&state, &display).await?;
    Ok(display)
}

/// Owner-only permanent delete: tombstone the name on Rendezvous and walk
/// this device out. Moderators cannot call this.
#[tauri::command]
pub async fn delete_owned_channel(
    state: tauri::State<'_, AppState>,
    channel_id: String,
) -> Result<(), String> {
    require_ember(&state).await?;
    let channel_id = parse_channel_id(&channel_id)?;
    let owned = load_owned_channel(&state, &channel_id).await?;
    let url = rendezvous_url(&state).await;
    let channel_seed = owned.ident.seed();
    registry_call(crate::network::rendezvous::delete_channel_registry(
        &url,
        &owned.ident.channel_id,
        &owned.ident.pubkey,
        &channel_seed,
    ))
    .await
    .map_err(|e| registry_fail(e, "channels_name_taken"))?;
    let db = state.db.clone();
    let id = channel_id.clone();
    tokio::task::spawn_blocking(move || db.tombstone_channel(&id))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_leave_failed", "Failed to leave channel", e))?;
    if let Ok(bytes) = hex::decode(&channel_id) {
        if let Ok(id) = <[u8; 16]>::try_from(bytes.as_slice()) {
            let _ = state
                .network_tx
                .try_send(NetworkCommand::DropChannelTransfers {
                    channel_id: id,
                    member: None,
                });
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn get_channel_invite(
    state: tauri::State<'_, AppState>,
    channel_id: String,
) -> Result<ChannelInviteInfo, String> {
    require_ember(&state).await?;
    let channel_id = parse_channel_id(&channel_id)?;
    let db = state.db.clone();
    let id = channel_id.clone();
    let row = tokio::task::spawn_blocking(move || db.get_channel(&id))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_invite_failed", "Failed to load invite", e))?
        .ok_or_else(|| coded("channels_not_found", "Channel not found"))?;
    // Same gate as sending and attaching. A banned member still holds retired
    // epoch secrets, so without this they could keep handing out invites that
    // read nothing and look to the recipient like a broken room.
    if self_banned_from(&state, &row, "channels_invite_failed").await? {
        return Err(coded(
            "channels_banned",
            "You are banned from this channel",
        ));
    }
    // A guardrail, not a control: every member holds the key already, so this
    // stops a careless re-share rather than a determined one. That is the
    // failure it is aimed at.
    if row.invites_owner_only && !row.is_owner {
        return Err(coded(
            "channels_invites_owner_only",
            "Only this room's owner can hand out invites",
        ));
    }
    let mut pubkey = [0u8; 32];
    let pk_bytes = hex::decode(&row.pubkey)
        .map_err(|_| coded("channels_invite_invalid", "Stored channel pubkey is invalid"))?;
    if pk_bytes.len() != 32 {
        return Err(coded(
            "channels_invite_invalid",
            "Stored channel pubkey is invalid",
        ));
    }
    pubkey.copy_from_slice(&pk_bytes);
    let mut cid = [0u8; 16];
    let id_bytes = hex::decode(&row.channel_id)
        .map_err(|_| coded("channels_invite_invalid", "Stored channel id is invalid"))?;
    if id_bytes.len() != 16 {
        return Err(coded(
            "channels_invite_invalid",
            "Stored channel id is invalid",
        ));
    }
    cid.copy_from_slice(&id_bytes);
    let private = row.visibility == CHANNEL_KIND_PRIVATE;
    // Minted from the *current* epoch, so every invite handed out before the
    // last rotation is already dead. That is the point of rotating.
    let join_secret = join_secret_for_channel(&state, &row).await.ok_or_else(|| {
        if private {
            coded(
                "channels_invite_invalid",
                "This private channel has no join secret on this device",
            )
        } else {
            coded("channels_invite_invalid", "Stored channel pubkey is invalid")
        }
    })?;
    let invite = ChannelInvite {
        channel_id: cid,
        pubkey,
        name: row.name.clone(),
        join_secret,
        private,
        // Names the epoch the secret above belongs to, so the joiner records it
        // rather than looking behind and hunting a key never minted for them.
        key_epoch: row.key_epoch.max(0) as u64,
    };
    Ok(ChannelInviteInfo {
        uri: invite.format(),
        channel_id: row.channel_id,
        name: row.name,
        private,
    })
}

#[tauri::command]
pub async fn list_channel_members(
    state: tauri::State<'_, AppState>,
    channel_id: String,
) -> Result<Vec<ChannelMemberInfo>, String> {
    require_ember(&state).await?;
    let channel_id = parse_channel_id(&channel_id)?;
    let our_pk = hex::encode(state.identity.ed25519_public_key);
    let db = state.db.clone();
    let rows = tokio::task::spawn_blocking(move || db.list_channel_members(&channel_id))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_members_failed", "Failed to list members", e))?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let is_self = row.member_pubkey.eq_ignore_ascii_case(&our_pk);
            ChannelMemberInfo::from_stored(row, is_self)
        })
        .collect())
}

/// The presence windows the roster is drawn with.
///
/// Served from the backend rather than mirrored in the UI. These numbers decide
/// which members a device gossips to as well as which ones it draws a dot
/// beside, and a copy in the frontend is a copy that can drift from the one the
/// protocol actually runs on — the roster would then disagree with the mesh
/// about who is in the room, which is the class of bug this whole change is
/// about.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChannelPresenceConfig {
    /// Seen within this many seconds on the live mesh: online.
    pub mesh_fresh_secs: i64,
    /// Seen within this many seconds by any means: recently here, not online.
    pub dht_fresh_secs: i64,
    /// How often a member announces itself, so the UI can pick a sane redraw.
    pub beat_secs: i64,
}

#[tauri::command]
pub async fn channel_presence_config() -> Result<ChannelPresenceConfig, String> {
    Ok(ChannelPresenceConfig {
        mesh_fresh_secs: channel::PRESENCE_MESH_FRESH_SECS,
        dht_fresh_secs: channel::PRESENCE_FRESH_SECS,
        beat_secs: channel::PRESENCE_BEAT_SECS,
    })
}

/// Tell the network loop which room is on screen, or `None` when none is.
///
/// Presence costs are per room and a user who has joined thirty is reading one.
/// Naming it is what lets that one be walked at the rate somebody watching it
/// would expect without paying the same for the other twenty-nine.
#[tauri::command]
pub async fn set_channel_focus(
    state: tauri::State<'_, AppState>,
    channel_id: Option<String>,
) -> Result<(), String> {
    let parsed = match channel_id {
        Some(id) => Some(channel_id_bytes(&parse_channel_id(&id)?)?),
        None => None,
    };
    let _ = state
        .network_tx
        .try_send(NetworkCommand::SetChannelFocus {
            channel_id: parsed,
        });
    Ok(())
}

#[tauri::command]
pub async fn get_channel_messages(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    limit: Option<i64>,
    before_id: Option<i64>,
) -> Result<Vec<ChannelMessageInfo>, String> {
    require_ember(&state).await?;
    let channel_id = parse_channel_id(&channel_id)?;
    let db = state.db.clone();
    let lim = limit.unwrap_or(50).clamp(1, 200);
    let rows = tokio::task::spawn_blocking(move || {
        db.get_channel_messages(&channel_id, lim, before_id)
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_messages_failed", "Failed to load messages", e))?;
    let mine = hex::encode(state.identity.ed25519_public_key);
    Ok(rows
        .into_iter()
        .map(|row| ChannelMessageInfo::from_row(row, &mine))
        .collect())
}

/// Substring search over one room's stored history. Local only — nothing is
/// asked of the network, so this finds what this device has kept.
#[tauri::command]
pub async fn search_channel_messages(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    query: String,
    limit: Option<i64>,
) -> Result<Vec<ChannelMessageInfo>, String> {
    require_ember(&state).await?;
    let channel_id = parse_channel_id(&channel_id)?;
    let needle = crate::security::sanitize_chat_text(&query);
    if needle.trim().is_empty() {
        return Ok(Vec::new());
    }
    let db = state.db.clone();
    let lim = limit.unwrap_or(50).clamp(1, 200);
    let rows = tokio::task::spawn_blocking(move || {
        db.search_channel_messages(&channel_id, &needle, lim)
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_messages_failed", "Failed to search messages", e))?;
    let mine = hex::encode(state.identity.ed25519_public_key);
    Ok(rows
        .into_iter()
        .map(|row| ChannelMessageInfo::from_row(row, &mine))
        .collect())
}

/// Revise one of your own lines, within [`channel::CHANNEL_EDIT_WINDOW_SECS`].
///
/// The revision is signed and flooded exactly as the original was, so every
/// member re-checks for themselves that it came from the line's author and
/// arrived in time — this side's checks are there to give the user a clear
/// refusal, not because anyone downstream takes our word for it.
///
/// The room's slow mode deliberately does not apply. It exists to bound how fast
/// *new* lines arrive, and a revision replaces one that has already been counted.
#[tauri::command]
pub async fn edit_channel_message(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    channel_id: String,
    message_id: i64,
    message: String,
) -> Result<ChannelMessageInfo, String> {
    require_ember(&state).await?;
    let channel_id = parse_channel_id(&channel_id)?;
    let channel_id_bytes = channel_id_bytes(&channel_id)?;
    let sanitized = crate::security::sanitize_chat_text(&message);
    // The reply reference is re-attached below from the stored line, never taken
    // from what was typed.
    let cleaned = channel::strip_reply_trailers(&sanitized).to_string();
    if cleaned.is_empty() || cleaned.len() > MAX_CHANNEL_MESSAGE {
        return Err(coded(
            "channels_message_size_invalid",
            "Message must be between 1 and 4096 bytes",
        ));
    }
    let row = load_joined_channel(&state, &channel_id).await?;
    // A banned member's revision is dropped by every receiver anyway, so applying
    // it locally would only show them a room state nobody else has.
    if self_banned_from(&state, &row, "channels_edit_failed").await? {
        return Err(coded(
            "channels_banned",
            "You are banned from this channel",
        ));
    }
    if row.visibility == CHANNEL_KIND_PRIVATE && row.key_epoch_wanted > row.key_epoch {
        return Err(coded(
            "channels_key_behind",
            "New messages are locked until this device has the current room key",
        ));
    }
    let sender_pk = state.identity.ed25519_public_key;
    let sender = hex::encode(sender_pk);

    // Read the line first: only its author may revise it, and the window is
    // measured from when it was sent.
    let db = state.db.clone();
    let id_for_read = channel_id.clone();
    let target = tokio::task::spawn_blocking(move || {
        db.channel_message_edit_target(&id_for_read, message_id)
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_edit_failed", "Failed to load message", e))?
    .ok_or_else(|| coded("channels_not_found", "Message not found"))?;

    if !target.sender_pubkey.eq_ignore_ascii_case(&sender) {
        return Err(coded(
            "channels_edit_not_author",
            "Only the author can edit a message",
        ));
    }
    let edited_at = chrono::Utc::now().timestamp();
    if !channel::edit_within_window(
        target.timestamp,
        edited_at,
        target.first_seen_at,
        edited_at,
    ) {
        return Err(coded(
            "channels_edit_window_closed",
            "This message is too old to edit",
        ));
    }

    let join_secret = join_secret_for_channel(&state, &row)
        .await
        .ok_or_else(|| {
            coded(
                "channels_edit_failed",
                "This device has no key for this channel",
            )
        })?;
    let msg_id_bytes = parse_msg_id(&target.msg_id)?;
    // A revision of a reply is still a reply. The edit frame can stand in for
    // the original on a catch-up, so it has to carry the same signed reference
    // or a member who only ever receives the revision loses the quote — and
    // receivers keep the original's `reply_to` regardless, so dropping it here
    // would only make this device disagree with everyone else.
    let reply_parent = target
        .reply_to
        .as_deref()
        .and_then(|parent| <[u8; 16]>::try_from(hex::decode(parent).ok()?).ok());
    let wire_text = channel::with_reply_trailer(&cleaned, reply_parent.as_ref());
    if wire_text.len() > MAX_CHANNEL_MESSAGE {
        return Err(coded(
            "channels_message_size_invalid",
            "Message must be between 1 and 4096 bytes",
        ));
    }
    let edit_sig = channel::edit_author_signature(
        &crypto::signing_key_from_bytes(&state.identity.ed25519_secret_key),
        &sender_pk,
        &channel_id_bytes,
        &msg_id_bytes,
        target.timestamp,
        edited_at,
        &wire_text,
    );

    // The queue slot is claimed before the row is written, because the write
    // cannot be undone: `apply_channel_message_edit` overwrites the pre-edit
    // text rather than archiving it, so an enqueue that failed afterwards left
    // the author holding a revision no other member has, with nothing to
    // restore it from and no resend to reconcile it. Deciding the flood first
    // turns a busy network task into a plain refusal, with the text the user
    // typed still in the composer.
    let permit = reserve_network_slot(&state).await?;
    // Local first, now that the flood behind it can no longer be refused: a
    // revision the user can see is worth more than one that only left the host.
    let db = state.db.clone();
    let id_for_edit = channel_id.clone();
    let msg_id_for_edit = target.msg_id.clone();
    let sender_for_edit = sender.clone();
    let text_for_edit = wire_text.clone();
    let sig_hex = hex::encode(edit_sig);
    let original_ts = target.timestamp;
    let outcome = tokio::task::spawn_blocking(move || {
        db.apply_channel_message_edit(
            &id_for_edit,
            &msg_id_for_edit,
            &sender_for_edit,
            original_ts,
            edited_at,
            &text_for_edit,
            &sig_hex,
            edited_at,
        )
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_edit_failed", "Failed to save edit", e))?;

    // The storage layer refuses on its own terms, and it is the one holding the
    // row. Its checks re-run the two clocks and the authorship against what is
    // actually stored, which is not always what the checks above read: an
    // inbound revision of the same line can land between them, and two edits in
    // one second leave the second with nothing newer to say. Treating a refusal
    // as a save flooded a revision this device never kept, told the room it had
    // happened, and handed the composer back text that reverted on next read.
    match outcome {
        ChannelEditOutcome::Applied(_) | ChannelEditOutcome::Created(_) => {}
        ChannelEditOutcome::OutsideWindow => {
            return Err(coded(
                "channels_edit_window_closed",
                "This message is too old to edit",
            ));
        }
        ChannelEditOutcome::NotAuthor => {
            return Err(coded(
                "channels_edit_not_author",
                "Only the author can edit a message",
            ));
        }
        ChannelEditOutcome::NotNewer => {
            return Err(coded(
                "channels_edit_failed",
                "A newer version of this message is already stored",
            ));
        }
        // Only reachable if the line was removed from this device between the
        // lookup above and the write. Storing the revision would bring it back.
        ChannelEditOutcome::Forgotten => {
            return Err(coded(
                "channels_edit_failed",
                "This message is no longer on this device",
            ));
        }
    }

    let plain = channel::encode_channel_chat_edit_presigned(
        &sender_pk,
        &msg_id_bytes,
        target.timestamp,
        edited_at,
        &edit_sig,
        &wire_text,
    );
    let mut envelope_id = [0u8; 16];
    OsRng.fill_bytes(&mut envelope_id);
    let gossip = channel::ChannelGossip::sealed(
        channel_id_bytes,
        envelope_id,
        &channel::content_key(&join_secret),
        edited_at.max(0) as u64,
        &plain,
        channel::CHANNEL_MSG_TTL_DEFAULT,
        edited_at,
    );
    // Spends the slot claimed before the write. Nothing between the two can
    // refuse it, so the revision on disk and the frame on the mesh are one
    // outcome rather than two.
    permit.send(NetworkCommand::FanoutChannelGossip {
        body: gossip.encode(),
    });
    let _ = app.emit(
        "ember:channel-message-edited",
        serde_json::json!({
            "channel_id": channel_id,
            "id": message_id,
            "msg_id": target.msg_id,
            "message": cleaned,
            "edited_at": edited_at,
        }),
    );

    let reply = reply_lookup_for(&state, &channel_id, target.reply_to.as_deref()).await;
    Ok(ChannelMessageInfo {
        id: message_id,
        reply_to_me: reply_parent_is_mine(reply.parent.as_ref(), &sender),
        sender_pubkey: sender,
        direction: target.direction,
        message: cleaned,
        timestamp: target.timestamp,
        read: true,
        edited_at,
        // A revision only reaches this point for a line already on the wire,
        // and the bubble it replaces carries that line's own state. Reporting
        // an edit as anything but delivered would re-open a question the
        // original already answered.
        delivery: channel_delivery_label(crate::storage::database::CHAT_DELIVERED),
        msg_id: target.msg_id,
        reply_to: target.reply_to,
        reply_parent: reply.parent,
        reply_parent_deleted: reply.deleted,
    })
}

/// The quote for a line this device has just written, or nothing.
///
/// Best-effort: the line itself is already stored and sent by the time this
/// runs, so a failed read costs the returned bubble its quote until the room
/// is next read from disk, and is not worth failing the command over.
async fn reply_lookup_for(
    state: &AppState,
    channel_id: &str,
    reply_to: Option<&str>,
) -> ChannelReplyLookup {
    let Some(parent) = reply_to else {
        return ChannelReplyLookup::default();
    };
    let db = state.db.clone();
    let channel_id = channel_id.to_string();
    let parent = parent.to_string();
    tokio::task::spawn_blocking(move || db.channel_reply_lookup(&channel_id, &parent))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default()
}

/// Set or clear this device's reaction to one line.
///
/// `reaction` is [`channel::REACTION_NONE`] to take a reaction back, or one of
/// the curated codes up to [`channel::REACTION_CURATED_MAX`]. A member holds one
/// reaction per line and picking another replaces it — the row is keyed that
/// way on every build since reactions shipped, so a second concurrent reaction
/// would silently displace the first on any v1.6.x peer and in what it
/// re-serves. Clearing is stored rather than deleted, because the row carries
/// the timestamp that stops a stale frame reasserting what was withdrawn.
#[tauri::command]
pub async fn set_channel_message_reaction(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    message_id: i64,
    reaction: u8,
) -> Result<(), String> {
    require_ember(&state).await?;
    let channel_id = parse_channel_id(&channel_id)?;
    let channel_id_bytes = channel_id_bytes(&channel_id)?;
    // Only codes this build draws. Anything past them is stored when a newer
    // build sends it, but minting one here would put a reaction on the wire
    // that nobody running this version can see or take back from the UI.
    if reaction > channel::REACTION_CURATED_MAX {
        return Err(coded(
            "channels_reaction_invalid",
            "Unsupported reaction",
        ));
    }
    let row = load_joined_channel(&state, &channel_id).await?;
    if self_banned_from(&state, &row, "channels_reaction_failed").await? {
        return Err(coded(
            "channels_banned",
            "You are banned from this channel",
        ));
    }
    let db = state.db.clone();
    let id_for_read = channel_id.clone();
    let target = tokio::task::spawn_blocking(move || {
        db.channel_message_edit_target(&id_for_read, message_id)
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_reaction_failed", "Failed to load message", e))?
    .ok_or_else(|| coded("channels_not_found", "Message not found"))?;

    let join_secret = join_secret_for_channel(&state, &row)
        .await
        .ok_or_else(|| {
            coded(
                "channels_reaction_failed",
                "This device has no key for this channel",
            )
        })?;
    let member_pk = state.identity.ed25519_public_key;
    if reaction != channel::REACTION_NONE
        && target
            .sender_pubkey
            .eq_ignore_ascii_case(&hex::encode(member_pk))
    {
        return Err(coded(
            "channels_reaction_own",
            "You cannot react to your own message",
        ));
    }
    let msg_id_bytes = parse_msg_id(&target.msg_id)?;
    let reacted_at = chrono::Utc::now().timestamp();
    let sig = channel::reaction_signature(
        &crypto::signing_key_from_bytes(&state.identity.ed25519_secret_key),
        &member_pk,
        &channel_id_bytes,
        &msg_id_bytes,
        reacted_at,
        reaction,
    );

    // Same order as the edit path, for the same reason: the upsert below
    // replaces this member's previous reaction along with its `reacted_at` and
    // signature, and nothing reads that pair back, so a flood that failed after
    // the write left a tally only this device holds and no way to restore the
    // one it overwrote. Claiming the slot first makes a busy network task a
    // refusal the caller can act on instead.
    let permit = reserve_network_slot(&state).await?;
    let db = state.db.clone();
    let id_for_write = channel_id.clone();
    let msg_id_for_write = target.msg_id.clone();
    let member_hex = hex::encode(member_pk);
    let sig_hex = hex::encode(sig);
    tokio::task::spawn_blocking(move || {
        db.set_channel_message_reaction(
            &id_for_write,
            &msg_id_for_write,
            &member_hex,
            reaction,
            reacted_at,
            &sig_hex,
        )
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_reaction_failed", "Failed to save reaction", e))?;

    let plain = channel::encode_channel_reactions(&[channel::ChannelReaction {
        target_msg_id: msg_id_bytes,
        member: member_pk,
        reaction,
        reacted_at,
        signature: sig,
    }]);
    let mut envelope_id = [0u8; 16];
    OsRng.fill_bytes(&mut envelope_id);
    let gossip = channel::ChannelGossip::sealed(
        channel_id_bytes,
        envelope_id,
        &channel::content_key(&join_secret),
        reacted_at.max(0) as u64,
        &plain,
        channel::CHANNEL_MSG_TTL_DEFAULT,
        reacted_at,
    );
    permit.send(NetworkCommand::FanoutChannelGossip {
        body: gossip.encode(),
    });
    Ok(())
}

/// Tell the room we are (or have stopped) composing.
///
/// Best effort from end to end. Every check that matters — joined, not banned,
/// chat unlocked, room small enough — runs on the network task against its
/// cached view, so this costs no database read per keystroke; and a full
/// command queue drops the signal rather than waiting, since the next
/// keystroke sends a fresh one and a late one would be wrong.
#[tauri::command]
pub async fn send_channel_typing(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    typing: bool,
) -> Result<(), String> {
    let channel_id = channel_id_bytes(&parse_channel_id(&channel_id)?)?;
    let _ = state
        .network_tx
        .try_send(NetworkCommand::SendChannelTyping { channel_id, typing });
    Ok(())
}

/// Every live reaction tally in a room, so the UI can draw counts in one read
/// rather than a query per bubble.
#[tauri::command]
pub async fn get_channel_reactions(
    state: tauri::State<'_, AppState>,
    channel_id: String,
) -> Result<Vec<ChannelReactionInfo>, String> {
    let channel_id = parse_channel_id(&channel_id)?;
    let mine = hex::encode(state.identity.ed25519_public_key);
    let db = state.db.clone();
    let rows = tokio::task::spawn_blocking(move || db.channel_message_reactions(&channel_id))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_reaction_failed", "Failed to load reactions", e))?;
    Ok(tally_channel_reactions(rows, &mine))
}

/// Fold a room's live reaction rows into one tally per line.
///
/// `rows` are `(msg_id, member, reaction)` in the order members reacted, which
/// is the order names are listed in. A code past the curated set belongs to a
/// newer build: it is counted nowhere rather than lumped in with a mark it is
/// not, and a line holding only such reactions gets no tally at all, so it draws
/// exactly as it would with none.
fn tally_channel_reactions(rows: Vec<(String, String, u8)>, mine: &str) -> Vec<ChannelReactionInfo> {
    use std::collections::BTreeMap;
    // Per line, per code: (count, members). BTreeMaps give code order within a
    // line and a stable line order for callers that compare results.
    let mut lines: BTreeMap<String, (u8, BTreeMap<u8, (u32, Vec<String>)>)> = BTreeMap::new();
    for (msg_id, member, reaction) in rows {
        let line = lines
            .entry(msg_id)
            .or_insert_with(|| (channel::REACTION_NONE, BTreeMap::new()));
        let is_mine = member.eq_ignore_ascii_case(mine);
        if is_mine {
            line.0 = reaction;
        }
        if !channel::reaction_is_curated(reaction) {
            continue;
        }
        let (count, members) = line.1.entry(reaction).or_insert_with(|| (0, Vec::new()));
        *count = count.saturating_add(1);
        if is_mine {
            members.insert(0, member);
            members.truncate(REACTION_MEMBERS_SHOWN);
        } else if members.len() < REACTION_MEMBERS_SHOWN {
            members.push(member);
        }
    }
    lines
        .into_iter()
        .filter(|(_, (_, codes))| !codes.is_empty())
        .map(|(msg_id, (mine, codes))| ChannelReactionInfo {
            msg_id,
            reactions: codes
                .into_iter()
                .map(|(reaction, (count, members))| ChannelReactionTally {
                    reaction,
                    count,
                    members,
                })
                .collect(),
            mine,
        })
        .collect()
}

/// Remove one message from this device. Deliberately does not propagate: the
/// protocol has no redaction, so pretending otherwise would be a lie about
/// what every other member still holds.
#[tauri::command]
pub async fn delete_channel_message(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    message_id: i64,
) -> Result<(), String> {
    require_ember(&state).await?;
    let channel_id = parse_channel_id(&channel_id)?;
    let db = state.db.clone();
    let removed = tokio::task::spawn_blocking(move || {
        db.delete_channel_message(&channel_id, message_id)
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_messages_failed", "Could not remove the message", e))?;
    if !removed {
        return Err(coded("channels_not_found", "Message not found"));
    }
    Ok(())
}

/// Send a line to a room, optionally as a reply to one already in it.
///
/// `reply_to` is the parent's wire id. It must name a line this device holds
/// in this room: the reference is signed into the text and every member will
/// show it, so it is checked against something real rather than passed through
/// — and a line the sender cannot see is not one they can meaningfully answer.
/// Receivers are not held to this, since a reply can outrun its parent.
#[tauri::command]
pub async fn send_channel_message(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    message: String,
    reply_to: Option<String>,
) -> Result<ChannelMessageInfo, String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to send",
        ));
    }
    let sanitized = crate::security::sanitize_chat_text(&message);
    // A trailer pasted in with copied text would otherwise make this a reply to
    // whatever the copied line answered.
    let cleaned = channel::strip_reply_trailers(&sanitized).to_string();
    let reply_parent = match reply_to.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(parent) => {
            let mut id = [0u8; 16];
            hex::decode_to_slice(parent, &mut id).map_err(|_| {
                coded(
                    "channels_reply_target_invalid",
                    "The message you are replying to is not in this room",
                )
            })?;
            Some(id)
        }
    };
    let wire_text = channel::with_reply_trailer(&cleaned, reply_parent.as_ref());
    // The cap is on what goes on the wire, which a reply's trailer is part of:
    // every receiver, old builds included, refuses a line over 4096 bytes.
    if cleaned.is_empty() || wire_text.len() > MAX_CHANNEL_MESSAGE {
        return Err(coded(
            "channels_message_size_invalid",
            "Message must be between 1 and 4096 bytes",
        ));
    }
    let channel_id = parse_channel_id(&channel_id)?;
    // `parse_channel_id` has already established this is 16 hex-decodable
    // bytes; the signature below binds the room, so it needs them as bytes.
    let channel_id_bytes: [u8; 16] = hex::decode(&channel_id)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
        .ok_or_else(|| coded("channels_invite_invalid", "Invalid channel id"))?;
    let db = state.db.clone();
    let id_check = channel_id.clone();
    let row = tokio::task::spawn_blocking(move || db.get_channel(&id_check))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_send_failed", "Failed to send", e))?
        .ok_or_else(|| coded("channels_not_found", "Channel not found"))?;
    if !row.in_room_now() {
        return Err(coded(
            "channels_not_in_room",
            "Join this channel before sending",
        ));
    }
    let sender = hex::encode(state.identity.ed25519_public_key);
    if self_banned_from(&state, &row, "channels_send_failed").await? {
        return Err(coded(
            "channels_banned",
            "You are banned from this channel",
        ));
    }
    if row.visibility == CHANNEL_KIND_PRIVATE && row.key_epoch_wanted > row.key_epoch {
        return Err(coded(
            "channels_key_behind",
            "New messages are locked until this device has the current room key",
        ));
    }
    // Before slow mode: in a room nobody but its staff may post in, a wait is
    // not the reason this line cannot go out.
    let refuses = {
        let db = state.db.clone();
        let row = row.clone();
        let our = sender.clone();
        tokio::task::spawn_blocking(move || announce_only_refuses(&db, &row, &our))
            .await
            .unwrap_or(true)
    };
    if refuses {
        return Err(coded(
            "channels_announce_only",
            "Only the owner and moderators can post in this room",
        ));
    }
    // The room's own rule, set by its owner and carried on the signed
    // moderation record. Whoever runs the room is exempt: they are the ones
    // answering questions and posting the notice that made it necessary.
    let slow_secs = row.slow_mode_secs.clamp(0, u16::MAX as i64);
    if slow_secs > 0 && !row.is_owner && !you_are_moderator(&state, &row.channel_id).await {
        let db_last = state.db.clone();
        let id_last = channel_id.clone();
        let last_sent =
            tokio::task::spawn_blocking(move || db_last.last_sent_channel_message_at(&id_last))
                .await
                .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
                .map_err(|e| coded_ctx("channels_send_failed", "Failed to send", e))?;
        // A stamp ahead of the clock is not evidence of a recent send, it is a
        // clock that has moved backwards under us — an NTP correction, or a
        // device that booted with a bad RTC. Clamping it to now reads that as
        // "long enough ago"; the previous floor only fixed the number shown in
        // the error, so the send itself stayed refused for as long as the skew
        // lasted, which could be days.
        let now_ts = chrono::Utc::now().timestamp();
        let last_sent = last_sent.min(now_ts);
        let waited = now_ts.saturating_sub(last_sent).max(0);
        if last_sent > 0 && waited < slow_secs {
            // The remaining wait rather than the room's setting, carried as
            // context so the translated framing can interpolate it: what the
            // sender needs is how long until they can post, and a bare "30
            // seconds" one second after a send reads as a full reset.
            let remaining = slow_secs - waited;
            return Err(coded_ctx(
                "channels_slow_mode",
                format!("Slow mode is on in this room. Try again in {remaining}s."),
                remaining,
            ));
        }
    }
    // Ahead of the rate budget below, like every other refusal. Looked up by
    // this room's id, so a line from another room — even one this device holds
    // — is refused too.
    let reply_to_hex = reply_parent.map(hex::encode);
    let reply = reply_lookup_for(&state, &channel_id, reply_to_hex.as_deref()).await;
    if reply_to_hex.is_some() && reply.parent.is_none() {
        return Err(coded(
            "channels_reply_target_invalid",
            "The message you are replying to is not in this room",
        ));
    }
    // Our own ceiling, which no room turns off. Checked last so a message
    // refused for any reason above does not spend budget.
    if !local_send_allowed(&channel_id) {
        return Err(coded(
            "channels_send_too_fast",
            "You are sending faster than this room accepts. Wait a moment and try again.",
        ));
    }
    let join_secret = join_secret_for_channel(&state, &row).await.ok_or_else(|| {
        refund_local_send(&channel_id);
        coded(
            "channels_send_failed",
            "This device has no key for this channel",
        )
    })?;
    let sender_pk = state.identity.ed25519_public_key;
    let sent_at = chrono::Utc::now().timestamp();
    let msg_id = channel::new_chat_msg_id(&channel_id_bytes, &sender_pk, sent_at);
    let author_sig = channel::chat_author_signature(
        &crypto::signing_key_from_bytes(&state.identity.ed25519_secret_key),
        &sender_pk,
        &channel_id_bytes,
        &msg_id,
        sent_at,
        &wire_text,
    );
    let key = channel::content_key(&join_secret);
    let plain = channel::encode_channel_chat_plain_presigned(&sender_pk, &author_sig, &wire_text);
    let gossip = channel::ChannelGossip::sealed(
        channel_id_bytes,
        msg_id,
        &key,
        sent_at.max(0) as u64,
        &plain,
        channel::CHANNEL_MSG_TTL_DEFAULT,
        sent_at,
    );
    // Stored before it is flooded, which is the order the edit path already
    // uses. The other way round, a failed insert left the line on every peer's
    // disk and on none of ours: the user was told the send failed, and the retry
    // minted a fresh `msg_id` — so the room saw the same sentence twice, with no
    // duplicate filter able to tell. Refusing to send something we could not
    // keep makes "failed" mean what it says, and leaves the retry clean.
    let db = state.db.clone();
    let id = channel_id.clone();
    let sender2 = sender.clone();
    // Stored as signed, trailer and all, so a catch-up re-serves the same bytes.
    let text = wire_text.clone();
    let msg_id_hex = hex::encode(msg_id);
    let author_sig_hex = hex::encode(author_sig);
    let row_id = tokio::task::spawn_blocking(move || {
        let row_id = db.insert_channel_message(
            &id,
            &sender2,
            "sent",
            &text,
            &msg_id_hex,
            sent_at,
            &author_sig_hex,
            true,
        )?;
        // Queued until the flood finds somebody. The network task flips it to
        // delivered on the same tick in the ordinary case, and to failed when
        // the ten-minute retry gives up — which is the state that used to be
        // invisible, leaving a line nobody received looking sent.
        let _ = db.set_channel_delivery(&id, &msg_id_hex, crate::storage::database::CHAT_QUEUED);
        // We are present: keep our own last_seen in step with the line, so
        // gossip-neighbor freshness and the empty-room poll do not treat a
        // talking member as gone until the next DHT announce.
        let _ = db.touch_channel_member_last_seen(&id, &sender2, sent_at);
        Ok::<_, anyhow::Error>(row_id)
    })
    .await
    .map_err(|e| {
        refund_local_send(&channel_id);
        coded_ctx("channels_task_error", "Task error", e)
    })?
    .map_err(|e| {
        refund_local_send(&channel_id);
        coded_ctx("channels_send_failed", "Failed to send", e)
    })?;

    if let Err(e) = state
        .network_tx
        .try_send(NetworkCommand::FanoutChannelGossip {
            body: gossip.encode(),
        })
    {
        // Take the row back out. A line nobody was sent is not history, and
        // leaving it would show the sender a transcript the room does not have —
        // with no resend, because a channel send never leaves a row to retry.
        let db = state.db.clone();
        let id = channel_id.clone();
        // If the take-back itself fails the sender keeps a line the room never
        // received, and there is no resend to reconcile it — worth a log even
        // though the send is already being reported as failed.
        match tokio::task::spawn_blocking(move || db.delete_channel_message(&id, row_id)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => tracing::error!(
                channel_id = %channel_id,
                %error,
                "undelivered channel message left in the local transcript"
            ),
            Err(error) => tracing::error!(
                channel_id = %channel_id,
                %error,
                "undelivered channel message left in the local transcript: task did not run"
            ),
        }
        refund_local_send(&channel_id);
        return Err(coded_ctx("network_busy", "Network busy", e));
    }

    Ok(ChannelMessageInfo {
        id: row_id,
        reply_to_me: reply_parent_is_mine(reply.parent.as_ref(), &sender),
        sender_pubkey: sender,
        direction: "sent".into(),
        message: cleaned,
        timestamp: sent_at,
        read: true,
        edited_at: 0,
        msg_id: hex::encode(msg_id),
        delivery: channel_delivery_label(crate::storage::database::CHAT_QUEUED),
        reply_to: reply_to_hex,
        reply_parent: reply.parent,
        reply_parent_deleted: reply.deleted,
    })
}

#[tauri::command]
pub async fn mark_channel_messages_read(
    state: tauri::State<'_, AppState>,
    channel_id: String,
) -> Result<(), String> {
    require_ember(&state).await?;
    let channel_id = parse_channel_id(&channel_id)?;
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || db.mark_channel_messages_read(&channel_id))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_read_failed", "Failed to mark read", e))?;
    Ok(())
}

struct OwnedChannel {
    row: StoredChannel,
    ident: ChannelIdentity,
    channel_id: [u8; 16],
}

async fn load_owned_channel(
    state: &AppState,
    channel_id: &str,
) -> Result<OwnedChannel, String> {
    let db = state.db.clone();
    let id = channel_id.to_string();
    let (row, seed) = tokio::task::spawn_blocking(move || {
        let row = db.get_channel(&id)?;
        let seed = db.load_channel_owner_seed(&id)?;
        Ok::<_, anyhow::Error>((row, seed))
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_moderation_failed", "Failed to load channel", e))?;
    let row = row.ok_or_else(|| coded("channels_not_found", "Channel not found"))?;
    // Deliberately no ban check: everything below requires ownership, and
    // `self_banned_from` exempts an owner, so a ban here could only ever be a
    // moderator's gossip or a stale row locking the owner out of the very
    // tools needed to undo it.
    if !row.is_owner {
        return Err(coded(
            "channels_not_owner",
            "Only the channel owner can do that",
        ));
    }
    let seed = seed.ok_or_else(|| {
        coded(
            "channels_not_owner",
            "Only the channel owner can do that",
        )
    })?;
    let ident = ChannelIdentity::from_seed(&seed);
    let Ok(id_bytes) = hex::decode(&row.channel_id) else {
        return Err(coded("channels_not_found", "Channel not found"));
    };
    let Ok(channel_id) = <[u8; 16]>::try_from(id_bytes) else {
        return Err(coded("channels_not_found", "Channel not found"));
    };
    if ident.channel_id != channel_id {
        return Err(coded(
            "channels_moderation_failed",
            "Stored channel key does not match this room",
        ));
    }
    Ok(OwnedChannel {
        row,
        ident,
        channel_id,
    })
}

/// Serialises the whole read-modify-write behind every owner moderation
/// command.
///
/// `load_banned_pubkeys` / `load_moderator_pubkeys` read the current lists, the
/// caller mutates them in memory, and `commit_channel_moderation` writes a
/// fresh signed snapshot of the result. Two of those interleaved both build
/// from the same base and the later one silently discards the earlier's change,
/// so the whole sequence has to be exclusive — a lock inside the commit alone
/// would be too late.
///
/// One global gate rather than one per room: these are human-paced actions, and
/// the bookkeeping for per-channel locks buys nothing at this rate. It is held
/// across the DHT publish too, which is bounded by that call's own timeout.
static MODERATION_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

/// Our own outbound chat times, per room, for [`LOCAL_SEND_PER_MINUTE`].
///
/// Session-scoped on purpose. A restart is not a loophole that matters here:
/// the point is to stop a runaway loop or a wall of pasted lines, and both
/// happen inside one session. Slow mode reads its last-send time from the
/// database instead, because that one is a rule the room agreed to and has to
/// survive a relaunch.
type SendTimes = std::collections::HashMap<String, std::collections::VecDeque<Instant>>;
static LOCAL_SEND_TIMES: std::sync::OnceLock<std::sync::Mutex<SendTimes>> =
    std::sync::OnceLock::new();

/// Whether this room has room left in its per-minute budget. Records the send
/// when it does.
fn local_send_allowed(channel_id: &str) -> bool {
    let cell = LOCAL_SEND_TIMES.get_or_init(|| std::sync::Mutex::new(SendTimes::new()));
    // A poisoned lock means an earlier caller panicked mid-update. The window
    // is a throttle, not a ledger, so recovering and carrying on is better than
    // making every later send panic too.
    let mut map = cell.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    let window = Duration::from_secs(60);
    // Rooms nobody has spoken in for a minute keep no state, so this holds the
    // few being talked in rather than every room ever opened.
    map.retain(|_, times| {
        times
            .back()
            .is_some_and(|t| now.saturating_duration_since(*t) <= window)
    });
    let times = map.entry(channel_id.to_string()).or_default();
    channel::rate_window_allow(times, now, window, LOCAL_SEND_PER_MINUTE)
}

/// Hand back the slot a send took when the send did not happen.
///
/// The budget exists to bound what we put on the mesh, so a message that never
/// reached it should not count against the next one. Without this a run of
/// failures — a busy network queue, a write error — spends the whole minute's
/// allowance and then locks the user out of a room they have said nothing in.
fn refund_local_send(channel_id: &str) {
    let Some(cell) = LOCAL_SEND_TIMES.get() else {
        return;
    };
    let mut map = cell.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(times) = map.get_mut(channel_id) {
        times.pop_back();
    }
}

fn moderation_lock() -> &'static tokio::sync::Mutex<()> {
    MODERATION_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

async fn commit_channel_moderation(
    state: &AppState,
    owned: &OwnedChannel,
    topic: &str,
    welcome: &str,
    bans: &[[u8; 32]],
    mods: &[[u8; 32]],
) -> Result<(), String> {
    commit_channel_moderation_with(state, owned, topic, welcome, bans, mods, PinFit::Shed).await
}

/// What a commit does with pins the record has no room for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PinFit {
    /// Drop the oldest. Every edit but a pin: a ban or a welcome must never be
    /// refused because of a pin, which is the least of what the snapshot holds.
    Shed,
    /// Refuse the commit. The owner pinning a message asked for exactly that
    /// pin, and shedding it — or an older one they did not choose — would
    /// report success for something other than what they did.
    Require,
}

/// The tail an owner commit of `owned` publishes, before any pin is shed.
///
/// Everything comes from `owned.row` except what another path may have moved
/// under it, so a caller that commits a change in memory — a rename, a policy
/// flag — publishes exactly that change.
async fn owner_moderation_tail(state: &AppState, owned: &OwnedChannel) -> ModerationTail {
    // We are the owner on this path, so our identity is what every member needs
    // in order to refuse a moderator's ban aimed at us, and our epoch is how
    // they tell they are behind and go looking for the key sealed to them.
    let our_pk = state.identity.ed25519_public_key;
    // Re-read rather than trusting `owned.row`: a ban rotates the key before
    // committing, so the snapshot in hand is one epoch stale and members would
    // never learn to go looking for the new one.
    let (live_epoch, removed_pins) = {
        let db = state.db.clone();
        let id = owned.row.channel_id.clone();
        let pins = owned.row.pinned_msg_ids.clone();
        let fallback = (owned.row.key_epoch, Vec::new());
        tokio::task::spawn_blocking(move || {
            let row = db.get_channel_lite(&id).ok().flatten()?;
            // A pin this device has removed is pruned here, which is the
            // owner's next commit of any kind.
            let removed = db.channel_messages_removed(&id, &pins).unwrap_or_default();
            Some((row.key_epoch, removed))
        })
        .await
        .ok()
        .flatten()
        .unwrap_or(fallback)
    };
    let pinned_msg_ids = owned
        .row
        .pinned_msg_id_bytes()
        .into_iter()
        .filter(|id| !removed_pins.contains(&hex::encode(id)))
        .collect::<Vec<_>>();
    ModerationTail {
        owner_pubkey: Some(our_pk),
        key_epoch: Some(live_epoch.max(0) as u64),
        // Always written, zeros when there is no nominee: that is what lets an
        // owner withdraw one. Leaving it absent would truncate the field, which
        // members read as "no opinion" and would go on honouring the old name.
        successor_nominee: Some(
            hex::decode(&owned.row.successor_nominee)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .unwrap_or([0u8; 32]),
        ),
        claim_after_days: Some(owned.row.claim_after_days.clamp(0, u16::MAX as i64) as u16),
        // Always written for the same reason as the nominee: the snapshot is a
        // whole replacement, so an absent field would read as "no opinion" and
        // let members go on inviting after the owner turned it off.
        invites_owner_only: Some(owned.row.invites_owner_only),
        // Absent rather than zero when off, so a room that never uses slow mode
        // publishes a tail byte-identical to the one builds without the field
        // expect. See `ModerationTail::slow_mode_secs`.
        slow_mode_secs: match owned.row.slow_mode_secs.clamp(0, u16::MAX as i64) as u16 {
            0 => None,
            secs => Some(secs),
        },
        // Only once the room has been renamed; see `ModerationTail::room_name`.
        // Taken from the row in hand, which the rename path fills with the new
        // name before committing, rather than re-read from the database.
        room_name: (owned.row.renamed_at > 0).then(|| owned.row.name.clone()),
        // Absent when off, like slow mode, so a room that never uses either
        // keeps publishing the tail it always has.
        announce_only: owned.row.announce_only.then_some(true),
        pinned_msg_ids,
        language: crate::network::ember::dht::publish::channel_language(&owned.row.language),
    }
}

/// Whether `tail`'s pins all fit a record for this snapshot.
fn owner_pins_fit(
    topic: &str,
    welcome: &str,
    bans: &[[u8; 32]],
    mods: &[[u8; 32]],
    tail: &ModerationTail,
) -> bool {
    crate::network::ember::dht::publish::moderation_pin_capacity(topic, welcome, bans, mods, tail)
        >= tail.pinned_msg_ids.len()
}

async fn commit_channel_moderation_with(
    state: &AppState,
    owned: &OwnedChannel,
    topic: &str,
    welcome: &str,
    bans: &[[u8; 32]],
    mods: &[[u8; 32]],
    pin_fit: PinFit,
) -> Result<(), String> {
    let private = owned.row.visibility == CHANNEL_KIND_PRIVATE;
    let our_pk = state.identity.ed25519_public_key;
    let tail = owner_moderation_tail(state, owned).await;
    if pin_fit == PinFit::Require && !owner_pins_fit(topic, welcome, bans, mods, &tail) {
        return Err(coded(
            "channels_pins_no_room",
            "This room's published settings have no space for another pin. Unpin a \
             message, shorten the welcome message, or remove a ban.",
        ));
    }
    // What the record will carry, and so what this device stores: the owner's
    // pin bar should show what members will see, not a pin that was shed.
    let tail = crate::network::ember::dht::publish::fit_moderation_pins(
        topic, welcome, bans, mods, &tail,
    );
    let record = SignedRecord::channel_moderation(
        topic,
        welcome,
        bans,
        mods,
        &tail,
        owned.channel_id,
        owned.ident.pubkey,
        private,
        &owned.ident.signing_key,
    );
    // Refuse before touching the database. A moderation record is a full
    // snapshot, so one the network will not accept does not leave the previous
    // state standing — the last good copy simply expires, taking the topic,
    // welcome, both lists, the owner key, the key epoch and any successor
    // nomination with it. Reporting the edit as applied while that happens is
    // the worst of both.
    //
    // The `fits` check catches the commoner case, where the record would
    // publish but the encoder would quietly drop entries past the cap, so the
    // room would go on believing it had banned someone it had not.
    if !crate::network::ember::dht::publish::moderation_snapshot_fits(
        topic, welcome, bans, mods, &tail,
    ) {
        return Err(coded(
            "channels_moderation_too_large",
            "This change does not fit in one published record. Shorten the welcome \
             message, or remove some bans or moderators.",
        ));
    }
    if record.is_none() {
        return Err(coded(
            "channels_moderation_too_large",
            "This change does not fit in one published record. Shorten the welcome \
             message, or remove some bans or moderators.",
        ));
    }
    let tail_nominee = tail.successor_nominee;
    let tail_days = tail.claim_after_days;
    let tail_epoch = tail.key_epoch;
    let tail_owner_only = tail.invites_owner_only;
    let tail_slow_mode = tail.slow_mode_secs;
    let tail_announce = tail.announce_only == Some(true);
    let tail_pins = tail.pinned_msg_ids.clone();
    let tail_language = tail.language;
    let db = state.db.clone();
    let id = owned.row.channel_id.clone();
    let topic_s = topic.to_string();
    let welcome_s = welcome.to_string();
    let bans_v = bans.to_vec();
    let mods_v = mods.to_vec();
    let stamped = tokio::task::spawn_blocking(move || {
        db.commit_owner_channel_moderation(
            &id,
            &crate::storage::database::ModerationSnapshot {
                topic: &topic_s,
                welcome: &welcome_s,
                banned_pubkeys: &bans_v,
                moderator_pubkeys: &mods_v,
                owner_pubkey: Some(&our_pk),
                successor_nominee: tail_nominee.as_ref(),
                claim_after_days: tail_days,
                key_epoch: tail_epoch,
                invites_owner_only: tail_owner_only,
                slow_mode_secs: tail_slow_mode,
            },
            // In the same write, and before the record is queued, like the
            // rest of the snapshot: a failed write is an edit that did not
            // happen rather than one that reaches the room while this device
            // forgets it.
            &crate::storage::database::OwnerRoomPolicy {
                announce_only: tail_announce,
                pinned_msg_ids: &tail_pins,
                language: tail_language,
            },
            chrono::Utc::now().timestamp(),
        )
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_moderation_failed", "Failed to save room info", e))?;
    let Some(stamp) = stamped else {
        return Err(coded("channels_not_found", "Channel not found"));
    };
    // Signed again at the stamp the edit was stored under. Nothing about the
    // size depends on it, so this fits exactly as the check above found.
    let Some(record) = SignedRecord::channel_moderation_at(
        topic,
        welcome,
        bans,
        mods,
        &tail,
        owned.channel_id,
        owned.ident.pubkey,
        private,
        &owned.ident.signing_key,
        stamp,
    ) else {
        return Ok(());
    };
    // Queued, not awaited. The rows above are already committed and the owner's
    // periodic republish (`maybe_republish_channel_moderation`) rebuilds this
    // record from them, so the STORE result was never acted on — only logged.
    // Waiting for it cost up to DEFAULT_FIND_TIMEOUT_MS while holding
    // MODERATION_LOCK, which stalls owner actions in every other room too.
    if let Err(e) = queue_signed_record(state, record).await {
        tracing::warn!(
            channel_id = %owned.row.channel_id,
            error = %e,
            "channel moderation saved locally but not published; other members \
             keep the previous record until the next owner republish"
        );
    }
    Ok(())
}

async fn load_banned_pubkeys(
    state: &AppState,
    channel_id: &str,
) -> Result<Vec<[u8; 32]>, String> {
    let db = state.db.clone();
    let id = channel_id.to_string();
    let ours = state.identity.ed25519_public_key;
    let mut bans = tokio::task::spawn_blocking(move || db.list_banned_channel_pubkeys(&id))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_moderation_failed", "Failed to load bans", e))?;
    // Every caller is an owner-only path, so a row banning us can only be
    // moderator gossip or a stale snapshot. Signing it into the record we
    // publish would promote that to an owner-signed ban the whole room honours,
    // and would keep re-signing it forever. Dropping it here also clears the
    // stale row, since `commit_channel_moderation` applies this same list
    // locally.
    bans.retain(|pk| pk != &ours);
    Ok(bans)
}

async fn load_moderator_pubkeys(
    state: &AppState,
    channel_id: &str,
) -> Result<Vec<[u8; 32]>, String> {
    let db = state.db.clone();
    let id = channel_id.to_string();
    tokio::task::spawn_blocking(move || db.list_moderator_channel_pubkeys(&id))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_moderation_failed", "Failed to load moderators", e))
}

async fn channel_info_from_id(state: &AppState, channel_id: &str) -> Result<ChannelInfo, String> {
    let our_pk = hex::encode(state.identity.ed25519_public_key);
    let db = state.db.clone();
    let id = channel_id.to_string();
    let our = our_pk.clone();
    let (row, you_are_banned, you_are_moderator) = tokio::task::spawn_blocking(move || {
        let row = db.get_channel(&id)?;
        let owned = row.as_ref().is_some_and(|r| r.is_owner);
        let banned = !owned && db.channel_member_is_banned(&id, &our)?;
        let moderator = db.channel_member_is_moderator(&id, &our)?;
        Ok::<_, anyhow::Error>((row, banned, moderator))
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_moderation_failed", "Failed to load channel", e))?;
    let row = row.ok_or_else(|| coded("channels_not_found", "Channel not found"))?;
    let moderation_updated_at = row.moderation_updated_at;
    let moderation_checked_at = row.moderation_checked_at;
    Ok(
        ChannelInfo::from_stored(row, you_are_banned, you_are_moderator).with_viewer(
            &our_pk,
            moderation_updated_at,
            moderation_checked_at,
        ),
    )
}

async fn load_joined_channel(
    state: &AppState,
    channel_id: &str,
) -> Result<StoredChannel, String> {
    let db = state.db.clone();
    let id = channel_id.to_string();
    let row = tokio::task::spawn_blocking(move || db.get_channel(&id))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_moderation_failed", "Failed to load channel", e))?
        .ok_or_else(|| coded("channels_not_found", "Channel not found"))?;
    if !row.in_room_now() {
        return Err(coded(
            "channels_not_in_room",
            "Join this channel first",
        ));
    }
    Ok(row)
}

/// Whether an announcement-only room stops this device starting a new line.
///
/// The owner and the moderators the owner's snapshot names may post; nobody
/// else. Enforced here, by the sender, and nowhere on receipt — see
/// `ModerationTail::announce_only` for why a receiver cannot judge it without
/// splitting the room. Edits and reactions are not new lines and stay open.
/// A moderator lookup that fails reads as "not one", like slow mode's.
fn announce_only_refuses(db: &Database, row: &StoredChannel, our_pubkey_hex: &str) -> bool {
    if !row.announce_only || row.is_owner {
        return false;
    }
    !db.channel_member_is_moderator(&row.channel_id, our_pubkey_hex)
        .unwrap_or(false)
}

/// Whether this device holds moderator rights in a room. Used to exempt the
/// people running it from slow mode; a lookup failure reads as "not one", so
/// the limit applies rather than being skipped on an error.
async fn you_are_moderator(state: &AppState, channel_id: &str) -> bool {
    let db = state.db.clone();
    let id = channel_id.to_string();
    let our_pk = hex::encode(state.identity.ed25519_public_key);
    tokio::task::spawn_blocking(move || db.channel_member_is_moderator(&id, &our_pk))
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or(false)
}

/// Whether *we* are barred from taking part in this room.
///
/// Ownership wins over the ban list, always. A ban is only legitimate because
/// the owner's signed moderation record says so, and moderator ban gossip
/// cannot exclude the owner because nothing on the wire identifies which pubkey
/// owns a room — only our own `is_owner` flag does. Honouring a ban against
/// ourselves in a room we own therefore let a moderator we appointed silence us
/// and strip the moderation tools needed to undo it.
///
/// `fail_code` lets the caller keep its own translated framing.
async fn self_banned_from(
    state: &AppState,
    row: &StoredChannel,
    fail_code: &'static str,
) -> Result<bool, String> {
    if row.is_owner {
        return Ok(false);
    }
    let db = state.db.clone();
    let id = row.channel_id.clone();
    let our_pk = hex::encode(state.identity.ed25519_public_key);
    tokio::task::spawn_blocking(move || db.channel_member_is_banned(&id, &our_pk))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx(fail_code, "Could not check your membership", e))
}

/// Whether this room's owner looks reachable right now.
///
/// Presence is the only owner-liveness signal a member holds that moves on a
/// useful timescale: `moderation_updated_at` only advances every
/// `MODERATION_REPUBLISH_SECS`, which is six hours, so it answers "has an owner
/// at all" rather than "is the owner here". [`channel::PRESENCE_FRESH_SECS`] is
/// two republish intervals — the same window the roster's presence dot and
/// `member_count` are drawn from, so a decision made here agrees with what the
/// user is already looking at instead of inventing a second notion of online.
///
/// A proxy, not proof: a present owner can still miss a gossip frame if no path
/// of Noise sessions carries it to them. That direction is the safe one — the
/// ban is recorded, and `mark_channel_rotate_pending` is on disk, so the work
/// is late rather than lost. The unsafe direction is the one this rules out.
///
/// False when no owner-signed moderation record has ever been applied here
/// (`owner_pubkey` empty) or the owner has no roster row at all: both mean this
/// device has no evidence the owner is present, and absence of evidence has to
/// read as absent for the caller's refusal to be worth anything.
async fn owner_is_present(state: &AppState, row: &StoredChannel) -> bool {
    if row.owner_pubkey.is_empty() {
        return false;
    }
    let db = state.db.clone();
    let id = row.channel_id.clone();
    let Ok(Ok(members)) = tokio::task::spawn_blocking(move || db.list_channel_members(&id)).await
    else {
        return false;
    };
    let cutoff = chrono::Utc::now()
        .timestamp()
        .saturating_sub(channel::PRESENCE_FRESH_SECS);
    members.iter().any(|member| {
        member.member_pubkey.eq_ignore_ascii_case(&row.owner_pubkey) && member.last_seen >= cutoff
    })
}

async fn moderation_power(
    state: &AppState,
    channel_id: &str,
) -> Result<(StoredChannel, bool, bool), String> {
    let row = load_joined_channel(state, channel_id).await?;
    if self_banned_from(state, &row, "channels_moderation_failed").await? {
        return Err(coded(
            "channels_banned",
            "You are banned from this channel",
        ));
    }
    let our_pk = hex::encode(state.identity.ed25519_public_key);
    let db = state.db.clone();
    let id = channel_id.to_string();
    let moderator = tokio::task::spawn_blocking(move || {
        db.channel_member_is_moderator(&id, &our_pk)
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_moderation_failed", "Failed to load channel", e))?;
    let is_owner = row.is_owner;
    Ok((row, is_owner, moderator))
}

/// Claim one slot on the network task's command queue, to be spent later.
///
/// For the paths that have to write to disk *and* flood, and whose write cannot
/// be undone. `try_send` after the write can fail with the row already
/// committed, and both callers here have nothing to restore: an edit overwrites
/// the pre-edit text rather than archiving it, and a reaction overwrites the
/// previous `reacted_at` and signature with no read-back. A failed flood there
/// left the author reading a transcript no other member holds, with no resend
/// and no way back — so the decision has to be made before anything is written,
/// and [`tokio::sync::mpsc::Permit::send`] is infallible.
///
/// Waited on rather than polled, to the same [`CMD_SEND_TIMEOUT`] ceiling
/// [`crate::commands::errors::bounded_send`] uses: the queue fills when the
/// event loop is momentarily busy, and refusing a keystroke's worth of work for
/// that is a worse answer than a pause. Bounded because these are IPC calls — a
/// wedged network task has to surface as an error, not a permanent spinner.
async fn reserve_network_slot<'a>(
    state: &'a AppState,
) -> Result<tokio::sync::mpsc::Permit<'a, NetworkCommand>, String> {
    match tokio::time::timeout(CMD_SEND_TIMEOUT, state.network_tx.reserve()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(e)) => Err(coded_ctx("network_busy", "Network busy", e)),
        Err(_) => Err(coded("network_timeout", "The network is not responding")),
    }
}

fn enqueue_channel_gossip(
    state: &AppState,
    channel_id: &str,
    join_secret: [u8; 32],
    plain: Vec<u8>,
) -> Result<(), String> {
    let mut channel_id_bytes = [0u8; 16];
    let Ok(id_bytes) = hex::decode(channel_id) else {
        return Err(coded("channels_not_found", "Channel not found"));
    };
    if id_bytes.len() != 16 {
        return Err(coded("channels_not_found", "Channel not found"));
    }
    channel_id_bytes.copy_from_slice(&id_bytes);
    let mut msg_id = [0u8; 16];
    OsRng.fill_bytes(&mut msg_id);
    let key = channel::content_key(&join_secret);
    let ts = chrono::Utc::now().timestamp();
    let gossip = channel::ChannelGossip::sealed(
        channel_id_bytes,
        msg_id,
        &key,
        ts.max(0) as u64,
        &plain,
        channel::CHANNEL_MSG_TTL_DEFAULT,
        ts,
    );
    state
        .network_tx
        .try_send(NetworkCommand::FanoutChannelGossip {
            body: gossip.encode(),
        })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    Ok(())
}

/// Secrets this room can be read with, newest epoch first.
///
/// A private room rotates on a ban, so anything sealed before the rotation — an
/// attachment already on disk, a message being replayed by history sync — is
/// under an older epoch. Public rooms have exactly one, derived from a pubkey
/// anyone can compute.
async fn join_secrets_for_channel(state: &AppState, row: &StoredChannel) -> Vec<[u8; 32]> {
    if row.visibility != CHANNEL_KIND_PRIVATE {
        return hex::decode(&row.pubkey)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(|pk| vec![channel::public_join_secret(&pk)])
            .unwrap_or_default();
    }
    let db = state.db.clone();
    let id = row.channel_id.clone();
    tokio::task::spawn_blocking(move || {
        let mut out: Vec<[u8; 32]> = db
            .load_channel_key_epochs(&id)
            .unwrap_or_default()
            .into_iter()
            .map(|(_, secret)| secret)
            .collect();
        // Epoch 0 is the secret the invite was minted with, still in
        // `join_secret` for a room that has never rotated.
        if let Ok(Some(secret)) = db.load_channel_join_secret(&id) {
            if !out.contains(&secret) {
                out.push(secret);
            }
        }
        out
    })
    .await
    .unwrap_or_default()
}

/// The secret this room seals *new* traffic with, and mints invites from.
async fn join_secret_for_channel(
    state: &AppState,
    row: &StoredChannel,
) -> Option<[u8; 32]> {
    join_secrets_for_channel(state, row).await.into_iter().next()
}

/// Mint the next content key for a private room and hand it to every member
/// who is still in it.
///
/// This is what makes a ban an eviction. Until it runs, a removed member still
/// holds a key that reads everything, and so does anyone they ever passed the
/// invite to. Each remaining member gets the key sealed under a secret only
/// they and the owner can derive, so the banned member can fetch the records
/// and still learn nothing.
///
/// Public rooms are skipped: their key comes from the channel pubkey, which
/// anyone can compute, so there is nothing to rotate away from.
/// `excluded` is the ban list about to be committed, not what the database says.
/// The `banned` flag is written by `commit_channel_moderation`, which runs
/// *after* this — reading it from `channel_members` here would still show the
/// member as present and seal the new key straight to the person being evicted.
async fn rotate_channel_key(
    state: &AppState,
    owned: &OwnedChannel,
    excluded: &[[u8; 32]],
) -> Result<Option<i64>, String> {
    if owned.row.visibility != CHANNEL_KIND_PRIVATE {
        return Ok(None);
    }
    let next_epoch = owned.row.key_epoch.saturating_add(1);
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);

    let db = state.db.clone();
    let id = owned.row.channel_id.clone();
    let stored_secret = secret;
    tokio::task::spawn_blocking(move || {
        db.insert_channel_key_epoch(&id, next_epoch, &stored_secret)
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_moderation_failed", "Could not rotate the room key", e))?;

    let db = state.db.clone();
    let id = owned.row.channel_id.clone();
    let members = tokio::task::spawn_blocking(move || db.list_channel_members(&id))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_moderation_failed", "Could not load members", e))?;

    let our_seed = state.identity.ed25519_secret_key;
    let our_hex = hex::encode(state.identity.ed25519_public_key);
    for member in members {
        // Banned members are the point of rotating, and we already hold the key
        // we just minted.
        if member.banned || member.member_pubkey.eq_ignore_ascii_case(&our_hex) {
            continue;
        }
        let Some(member_pk) = hex::decode(&member.member_pubkey)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            continue;
        };
        if excluded.contains(&member_pk) {
            continue;
        }
        let Some(wrap) = channel::derive_channel_epoch_secret(
            &our_seed,
            &member_pk,
            &owned.channel_id,
            next_epoch,
        ) else {
            continue;
        };
        let sealed =
            channel::seal_channel_key_epoch(&wrap, &owned.channel_id, next_epoch, &secret);
        let record = SignedRecord::channel_key_epoch(
            owned.channel_id,
            owned.ident.pubkey,
            &member_pk,
            next_epoch,
            &sealed,
            &owned.ident.signing_key,
        );
        // Queued rather than awaited. The STORE result was only ever logged, so
        // waiting on it bought nothing and cost up to DEFAULT_FIND_TIMEOUT_MS
        // per member — serially, while holding MODERATION_LOCK. On a sparse DHT
        // where those lookups time out, one ban in a room of a dozen froze
        // moderation everywhere for minutes. The walk still starts; a member who
        // cannot find their record re-asks every minute, and the owner
        // republishes moderation on a timer.
        if let Err(e) = queue_signed_record(state, record).await {
            tracing::warn!(
                channel_id = %owned.row.channel_id,
                member = %member.member_pubkey,
                error = %e,
                "could not queue a rotated channel key for a member"
            );
        }
    }
    Ok(Some(next_epoch))
}

/// Mint a new content key and publish the snapshot that announces it.
///
/// The two halves cannot be separated. The snapshot is the only thing that
/// tells members a new epoch exists, so a rotation whose commit fails has to
/// come back off — otherwise everything sent afterwards is sealed under a key
/// nobody will ever go looking for.
async fn rotate_and_commit(
    state: &AppState,
    owned: &OwnedChannel,
    bans: &[[u8; 32]],
    mods: &[[u8; 32]],
) -> Result<(), String> {
    let rotated = rotate_channel_key(state, owned, bans).await?;
    let Err(error) = commit_channel_moderation(
        state,
        owned,
        &owned.row.topic,
        &owned.row.welcome,
        bans,
        mods,
    )
    .await
    else {
        return Ok(());
    };
    undo_rotation(state, owned, rotated).await;
    Err(error)
}

/// Take a rotation back off after the snapshot that would have announced it
/// failed to publish. No-op when nothing was rotated.
async fn undo_rotation(state: &AppState, owned: &OwnedChannel, rotated: Option<i64>) {
    let Some(epoch) = rotated else {
        return;
    };
    let db = state.db.clone();
    let id = owned.row.channel_id.clone();
    if let Err(e) = tokio::task::spawn_blocking(move || db.rollback_channel_key_epoch(&id, epoch))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .and_then(|r| r)
    {
        tracing::error!(
            channel_id = %owned.row.channel_id,
            error = %e,
            "could not roll back epoch {epoch} after a failed moderation commit"
        );
    }
}

/// Hand one member the private room's current content key, sealed to them alone.
///
/// Both places that mint an epoch record skip banned members, which is the skip
/// that makes a ban in a private room an eviction rather than a label: rotation
/// omits them, and so does the owner's periodic re-seal. Lifting the ban is
/// therefore social only until one of those runs again — the snapshot published
/// here carries the epoch *number*, not the key. That left the member in a room
/// that looked joined and refused every send behind `key_behind` for up to
/// `MODERATION_REPUBLISH_SECS`, which is six hours.
async fn reseal_current_epoch_to_member(
    state: &AppState,
    owned: &OwnedChannel,
    member_pk: [u8; 32],
) -> Result<(), String> {
    // Epoch 0 is the secret the invite carried, which this member already has.
    if owned.row.visibility != CHANNEL_KIND_PRIVATE || owned.row.key_epoch <= 0 {
        return Ok(());
    }
    if member_pk == state.identity.ed25519_public_key {
        return Ok(());
    }
    let epoch = owned.row.key_epoch;
    let db = state.db.clone();
    let id = owned.row.channel_id.clone();
    let secret = tokio::task::spawn_blocking(move || db.load_channel_key_epochs(&id))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_moderation_failed", "Could not load the room key", e))?
        .into_iter()
        .find(|(held, _)| *held == epoch)
        .map(|(_, secret)| secret);
    // Retention drops the oldest epochs, so the one the snapshot advertises can
    // be gone on a device that has rotated many times. Saying nothing is right:
    // the next rotation reseals to everyone unbanned, this member included.
    let Some(secret) = secret else {
        tracing::warn!(
            channel_id = %owned.row.channel_id,
            "no stored secret for epoch {epoch}; the unbanned member waits for the next rotation"
        );
        return Ok(());
    };
    let Some(wrap) = channel::derive_channel_epoch_secret(
        &state.identity.ed25519_secret_key,
        &member_pk,
        &owned.channel_id,
        epoch,
    ) else {
        return Ok(());
    };
    let sealed = channel::seal_channel_key_epoch(&wrap, &owned.channel_id, epoch, &secret);
    let record = SignedRecord::channel_key_epoch(
        owned.channel_id,
        owned.ident.pubkey,
        &member_pk,
        epoch,
        &sealed,
        &owned.ident.signing_key,
    );
    // Queued rather than awaited, exactly as rotation does: the member re-asks
    // every minute until they find it, so a slow walk costs nothing but time.
    if let Err(e) = queue_signed_record(state, record).await {
        tracing::warn!(
            channel_id = %owned.row.channel_id,
            member = %hex::encode(member_pk),
            error = %e,
            "could not queue the current room key for an unbanned member"
        );
    }
    Ok(())
}

/// Mint a fresh content key for a private room without evicting anyone.
///
/// Rotation otherwise only happens on a ban, so an owner whose invite link had
/// leaked had no remedy but to ban somebody who had done nothing wrong. Every
/// invite handed out before this stops working, which is the point.
#[tauri::command]
pub async fn rotate_channel_room_key(
    state: tauri::State<'_, AppState>,
    channel_id: String,
) -> Result<ChannelInfo, String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to rotate this room's key",
        ));
    }
    let channel_id = parse_channel_id(&channel_id)?;
    let _snapshot = moderation_lock().lock().await;
    let owned = load_owned_channel(&state, &channel_id).await?;
    if owned.row.visibility != CHANNEL_KIND_PRIVATE {
        return Err(coded(
            "channels_rotate_public",
            "A public room's key comes from its address, so there is nothing to rotate",
        ));
    }
    let bans = load_banned_pubkeys(&state, &channel_id).await?;
    let mods = load_moderator_pubkeys(&state, &channel_id).await?;
    rotate_and_commit(&state, &owned, &bans, &mods).await?;
    channel_info_from_id(&state, &channel_id).await
}

/// Choose whether members other than the owner may hand out invites.
///
/// Rides the owner-signed moderation snapshot, so members learn it the same
/// way they learn bans. Enforcement is each client refusing to mint, which
/// makes this a guard against carelessness rather than against a member who
/// patches their build — they already hold the key either way.
#[tauri::command]
pub async fn set_channel_invite_policy(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    owner_only: bool,
) -> Result<ChannelInfo, String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to edit this channel",
        ));
    }
    let channel_id = parse_channel_id(&channel_id)?;
    let _snapshot = moderation_lock().lock().await;
    let owned = load_owned_channel(&state, &channel_id).await?;
    // Carried in memory rather than written first. `commit_channel_moderation`
    // builds the published tail from this row *and* applies the same snapshot
    // locally, so passing the requested value makes the edit atomic: either it
    // publishes and is stored, or neither happens. Writing the column up front
    // meant a failed commit returned an error for a change that had in fact
    // applied — throttling nobody, but queued to reach the whole room hours
    // later on the next republish, long after the owner concluded it had not
    // taken and possibly set something else.
    let owned = OwnedChannel {
        row: StoredChannel {
            invites_owner_only: owner_only,
            ..owned.row.clone()
        },
        ..owned
    };
    let bans = load_banned_pubkeys(&state, &channel_id).await?;
    let mods = load_moderator_pubkeys(&state, &channel_id).await?;
    commit_channel_moderation(
        &state,
        &owned,
        &owned.row.topic,
        &owned.row.welcome,
        &bans,
        &mods,
    )
    .await?;
    channel_info_from_id(&state, &channel_id).await
}

/// Owner-set: how long a member must wait between messages in this room.
///
/// Opt-in and visible to everyone, which is the point. An automatic throttle
/// has to guess, and it guesses worst about the person who just joined and is
/// answering a question; a human turning this on has already decided the room
/// needs it. Rides the owner-signed moderation snapshot, so members learn it
/// the same way they learn bans, and like the invite policy it is enforced by
/// each client declining to send — a guard against a flood of ordinary clients
/// rather than against a patched one.
#[tauri::command]
pub async fn set_channel_slow_mode(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    secs: u16,
) -> Result<ChannelInfo, String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to edit this channel",
        ));
    }
    if !SLOW_MODE_CHOICES.contains(&secs) {
        return Err(coded(
            "channels_slow_mode_invalid",
            "That is not one of the slow-mode delays this room can publish",
        ));
    }
    let channel_id = parse_channel_id(&channel_id)?;
    let _snapshot = moderation_lock().lock().await;
    let owned = load_owned_channel(&state, &channel_id).await?;
    // In memory, not written first — see `set_channel_invite_policy`. The local
    // apply inside the commit writes `slow_mode_secs` unconditionally (an absent
    // tail field means off, not "no opinion"), so turning slow mode back off
    // travels the same atomic path as turning it on.
    let owned = OwnedChannel {
        row: StoredChannel {
            slow_mode_secs: i64::from(secs),
            ..owned.row.clone()
        },
        ..owned
    };
    let bans = load_banned_pubkeys(&state, &channel_id).await?;
    let mods = load_moderator_pubkeys(&state, &channel_id).await?;
    commit_channel_moderation(
        &state,
        &owned,
        &owned.row.topic,
        &owned.row.welcome,
        &bans,
        &mods,
    )
    .await?;
    channel_info_from_id(&state, &channel_id).await
}

/// Owner-set: only the owner and moderators may post in this room.
///
/// For a room that exists to carry notices — releases, a club's schedule —
/// where replies belong somewhere else. Rides the owner-signed moderation
/// snapshot like slow mode, and like slow mode it is each member's client that
/// declines to send; nothing is dropped on receipt (see
/// `ModerationTail::announce_only`). Reactions stay open.
#[tauri::command]
pub async fn set_channel_announce_only(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    announce_only: bool,
) -> Result<ChannelInfo, String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to edit this channel",
        ));
    }
    let channel_id = parse_channel_id(&channel_id)?;
    let _snapshot = moderation_lock().lock().await;
    let owned = load_owned_channel(&state, &channel_id).await?;
    // In memory, not written first — see `set_channel_invite_policy`.
    let owned = OwnedChannel {
        row: StoredChannel {
            announce_only,
            ..owned.row.clone()
        },
        ..owned
    };
    let bans = load_banned_pubkeys(&state, &channel_id).await?;
    let mods = load_moderator_pubkeys(&state, &channel_id).await?;
    commit_channel_moderation(
        &state,
        &owned,
        &owned.row.topic,
        &owned.row.welcome,
        &bans,
        &mods,
    )
    .await?;
    channel_info_from_id(&state, &channel_id).await
}

/// A room language from the UI: absent or empty is "none", anything else has
/// to be a code a moderation record can carry.
fn parse_channel_language(code: Option<&str>) -> Result<Option<&'static str>, String> {
    match code.map(str::trim).filter(|c| !c.is_empty()) {
        None => Ok(None),
        Some(code) => crate::network::ember::dht::publish::channel_language(code)
            .map(Some)
            .ok_or_else(|| {
                coded(
                    "channels_language_invalid",
                    "That is not one of the languages a room can be marked with",
                )
            }),
    }
}

/// Owner-set: the language the room is meant to be held in, or none.
///
/// Shown to members as a flag beside the room's name, and nothing more — it
/// filters nothing and stops no one writing in another language. Rides the
/// owner-signed moderation snapshot like the posting rule.
#[tauri::command]
pub async fn set_channel_language(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    language: Option<String>,
) -> Result<ChannelInfo, String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to edit this channel",
        ));
    }
    let language = parse_channel_language(language.as_deref())?;
    let channel_id = parse_channel_id(&channel_id)?;
    let _snapshot = moderation_lock().lock().await;
    let owned = load_owned_channel(&state, &channel_id).await?;
    // In memory, not written first — see `set_channel_invite_policy`.
    let owned = OwnedChannel {
        row: StoredChannel {
            language: language.unwrap_or("").to_string(),
            ..owned.row.clone()
        },
        ..owned
    };
    let bans = load_banned_pubkeys(&state, &channel_id).await?;
    let mods = load_moderator_pubkeys(&state, &channel_id).await?;
    commit_channel_moderation(
        &state,
        &owned,
        &owned.row.topic,
        &owned.row.welcome,
        &bans,
        &mods,
    )
    .await?;
    // The listing is what Discover shows before anyone joins, so it has to
    // change with the snapshot rather than wait for the owner loop's renewal.
    if owned.row.visibility != CHANNEL_KIND_PRIVATE {
        let record = SignedRecord::channel_index(
            &owned.row.name,
            owned.ident.channel_id,
            owned.ident.pubkey,
            false,
            language,
            &owned.ident.signing_key,
        );
        if let Err(e) = queue_signed_record(&state, record).await {
            tracing::warn!(
                channel_id = %channel_id,
                error = %e,
                "room's index record did not publish its new language"
            );
        }
    }
    channel_info_from_id(&state, &channel_id).await
}

/// The pin list after pinning or unpinning `msg_id`, oldest pin first.
///
/// `Ok(None)` is "nothing to change" — pinning what is already pinned, or
/// unpinning what is not — so a double click is not an error. Pinning past
/// [`CHANNEL_PIN_MAX`] is refused rather than silently replacing the oldest:
/// the owner chose those pins, and which one to give up is theirs to say.
fn next_pins(current: &[String], msg_id: &str, pinned: bool) -> Result<Option<Vec<String>>, String> {
    let held = current.iter().any(|id| id == msg_id);
    if pinned == held {
        return Ok(None);
    }
    if !pinned {
        return Ok(Some(current.iter().filter(|id| *id != msg_id).cloned().collect()));
    }
    if current.len() >= CHANNEL_PIN_MAX {
        return Err(coded(
            "channels_pins_full",
            format!("A room can have {CHANNEL_PIN_MAX} pinned messages. Unpin one first."),
        ));
    }
    let mut next = current.to_vec();
    next.push(msg_id.to_string());
    Ok(Some(next))
}

/// Owner-only: pin a message to the top of the room, or take a pin down.
///
/// Pins ride the owner-signed moderation snapshot, so members see them within
/// a refresh and a patched client cannot forge one. The pin commit refuses
/// rather than sheds when the record is full ([`PinFit::Require`]); every other
/// commit sheds the oldest pin first.
#[tauri::command]
pub async fn set_channel_message_pinned(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    msg_id: String,
    pinned: bool,
) -> Result<ChannelInfo, String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to edit this channel",
        ));
    }
    let channel_id = parse_channel_id(&channel_id)?;
    let msg_id = msg_id.trim().to_ascii_lowercase();
    if msg_id.len() != 32 || !msg_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(coded(
            "channels_pin_target_invalid",
            "That message is not in this room",
        ));
    }
    let _snapshot = moderation_lock().lock().await;
    let owned = load_owned_channel(&state, &channel_id).await?;
    if pinned {
        // Looked up by this room's id, so a line from another room is refused
        // too, exactly as a reply's parent is.
        let lookup = reply_lookup_for(&state, &channel_id, Some(&msg_id)).await;
        if lookup.parent.is_none() {
            return Err(coded(
                "channels_pin_target_invalid",
                "That message is not in this room",
            ));
        }
    }
    let Some(pins) = next_pins(&owned.row.pinned_msg_ids, &msg_id, pinned)? else {
        return channel_info_from_id(&state, &channel_id).await;
    };
    let owned = OwnedChannel {
        row: StoredChannel {
            pinned_msg_ids: pins,
            ..owned.row.clone()
        },
        ..owned
    };
    let bans = load_banned_pubkeys(&state, &channel_id).await?;
    let mods = load_moderator_pubkeys(&state, &channel_id).await?;
    commit_channel_moderation_with(
        &state,
        &owned,
        &owned.row.topic,
        &owned.row.welcome,
        &bans,
        &mods,
        if pinned { PinFit::Require } else { PinFit::Shed },
    )
    .await?;
    channel_info_from_id(&state, &channel_id).await
}

/// One pinned message as the room's pin bar draws it.
#[derive(serde::Serialize)]
pub struct ChannelPinInfo {
    pub msg_id: String,
    /// The line as this device holds it now, or `None` when it is not here —
    /// not yet synced, or trimmed from history.
    pub message: Option<ChannelReplyParent>,
    /// Absent because it was removed here, which the bar hides rather than
    /// calling "not available yet".
    pub deleted: bool,
}

/// The room's pins, oldest first, each resolved against local history the way
/// a reply's quote is.
#[tauri::command]
pub async fn get_channel_pins(
    state: tauri::State<'_, AppState>,
    channel_id: String,
) -> Result<Vec<ChannelPinInfo>, String> {
    require_ember(&state).await?;
    let channel_id = parse_channel_id(&channel_id)?;
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || {
        let row = db
            .get_channel_lite(&channel_id)?
            .ok_or_else(|| anyhow::anyhow!("channel not found"))?;
        row.pinned_msg_ids
            .into_iter()
            .map(|msg_id| {
                let lookup = db.channel_reply_lookup(&channel_id, &msg_id)?;
                Ok(ChannelPinInfo {
                    msg_id,
                    message: lookup.parent,
                    deleted: lookup.deleted,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_pins_failed", "Failed to load pinned messages", e))
}

async fn apply_local_mod_ban(
    state: &AppState,
    row: &StoredChannel,
    target: [u8; 32],
    banned: bool,
) -> Result<(), String> {
    let ts = chrono::Utc::now().timestamp();
    let db = state.db.clone();
    let id = row.channel_id.clone();
    let target_hex = hex::encode(target);
    let applied = tokio::task::spawn_blocking(move || {
        db.apply_channel_ban_action(&id, &target_hex, banned, ts)
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_ban_failed", "Failed to update the ban list", e))?;
    if !applied {
        return Err(coded(
            "channels_ban_failed",
            "The ban list was not updated",
        ));
    }

    async fn rollback(
        state: &AppState,
        row: &StoredChannel,
        target: [u8; 32],
        banned: bool,
        ts: i64,
    ) -> Result<(), String> {
        let db = state.db.clone();
        let id = row.channel_id.clone();
        let target_hex = hex::encode(target);
        let rollback_banned = !banned;
        let rollback_ts = ts.saturating_add(1);
        let outcome = tokio::task::spawn_blocking(move || {
            db.apply_channel_ban_action(&id, &target_hex, rollback_banned, rollback_ts)
        })
        .await;
        match outcome {
            Ok(Ok(true)) => Ok(()),
            Ok(Ok(false)) => {
                tracing::error!(
                    channel_id = %row.channel_id,
                    member = %hex::encode(target),
                    "ban was saved locally but rolling it back did not take"
                );
                Err(coded(
                    "channels_ban_stuck",
                    "The ban was saved but could not be announced, and rolling it back failed",
                ))
            }
            Ok(Err(e)) => {
                tracing::error!(
                    channel_id = %row.channel_id,
                    member = %hex::encode(target),
                    error = %e,
                    "ban was saved locally but rolling it back failed"
                );
                Err(coded_ctx(
                    "channels_ban_stuck",
                    "The ban was saved but could not be announced, and rolling it back failed",
                    e,
                ))
            }
            Err(e) => {
                tracing::error!(
                    channel_id = %row.channel_id,
                    member = %hex::encode(target),
                    error = %e,
                    "ban was saved locally but rolling it back failed"
                );
                Err(coded_ctx(
                    "channels_ban_stuck",
                    "The ban was saved but could not be announced, and rolling it back failed",
                    e,
                ))
            }
        }
    }

    let Some(join_secret) = join_secret_for_channel(state, row).await else {
        rollback(state, row, target, banned, ts).await?;
        return Err(coded(
            "channels_ban_failed",
            "Could not announce the ban",
        ));
    };
    let mut channel_id_bytes = [0u8; 16];
    let Ok(id_bytes) = hex::decode(&row.channel_id) else {
        rollback(state, row, target, banned, ts).await?;
        return Err(coded(
            "channels_ban_failed",
            "Could not announce the ban",
        ));
    };
    if id_bytes.len() != 16 {
        rollback(state, row, target, banned, ts).await?;
        return Err(coded(
            "channels_ban_failed",
            "Could not announce the ban",
        ));
    }
    channel_id_bytes.copy_from_slice(&id_bytes);
    let mut msg_id = [0u8; 16];
    OsRng.fill_bytes(&mut msg_id);
    let plain = channel::encode_channel_mod_action(
        &crypto::signing_key_from_bytes(&state.identity.ed25519_secret_key),
        &state.identity.ed25519_public_key,
        &target,
        banned,
        &channel_id_bytes,
        &msg_id,
        ts,
    );
    let key = channel::content_key(&join_secret);
    let gossip = channel::ChannelGossip::sealed(
        channel_id_bytes,
        msg_id,
        &key,
        ts.max(0) as u64,
        &plain,
        channel::CHANNEL_MSG_TTL_DEFAULT,
        ts,
    );
    if let Err(e) = state
        .network_tx
        .try_send(NetworkCommand::FanoutChannelGossip {
            body: gossip.encode(),
        })
    {
        rollback(state, row, target, banned, ts).await?;
        return Err(coded_ctx("network_busy", "Network busy", e));
    }
    // Only once the ban is both saved and announced. The gossip path tears these
    // down on the receiving side, but the device that issued the ban never sees
    // its own frame — so without this the moderator who evicted somebody was the
    // one member still uploading to them.
    if banned {
        let _ = state
            .network_tx
            .try_send(NetworkCommand::DropChannelTransfers {
                channel_id: channel_id_bytes,
                member: Some(target),
            });
    }
    Ok(())
}

#[tauri::command]
pub async fn update_channel_moderation(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    topic: String,
    welcome: String,
) -> Result<ChannelInfo, String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to edit this channel",
        ));
    }
    let channel_id = parse_channel_id(&channel_id)?;
    let topic = sanitize_topic(&topic)?;
    let welcome = sanitize_welcome(&welcome)?;
    let _snapshot = moderation_lock().lock().await;
    let owned = load_owned_channel(&state, &channel_id).await?;
    let bans = load_banned_pubkeys(&state, &channel_id).await?;
    let mods = load_moderator_pubkeys(&state, &channel_id).await?;
    commit_channel_moderation(&state, &owned, &topic, &welcome, &bans, &mods).await?;
    channel_info_from_id(&state, &channel_id).await
}

/// Least time between two renames of one room. The registry holds the same
/// line (`RENAME_INTERVAL_SECS` in the rendezvous server) and is what enforces
/// it; this copy only lets the owner hear so without a round trip.
const RENAME_INTERVAL_SECS: i64 = 24 * 60 * 60;

/// Rename a room this device owns.
///
/// The registry decides whether the name is free, so nothing changes here
/// until it has granted it; the name it gives up stays reserved to this room
/// for a while, so nobody can take it and be mistaken for the room. Members
/// learn the new name from the owner's moderation snapshot, the record that
/// already carries the topic, which they fetch every few minutes while in the
/// room — so one who is offline picks it up when they are back.
#[tauri::command]
pub async fn rename_channel(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    name: String,
) -> Result<ChannelInfo, String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to edit this channel",
        ));
    }
    let channel_id = parse_channel_id(&channel_id)?;
    let name = sanitize_channel_name(&name)?;
    let _snapshot = moderation_lock().lock().await;
    let owned = load_owned_channel(&state, &channel_id).await?;
    if !owned.row.successor_id.is_empty() {
        return Err(coded(
            "channels_handoff_failed",
            "This room has already been transferred",
        ));
    }
    let bans = load_banned_pubkeys(&state, &channel_id).await?;
    let mods = load_moderator_pubkeys(&state, &channel_id).await?;
    let topic = owned.row.topic.clone();
    let welcome = owned.row.welcome.clone();
    let renamed_at = owned.row.renamed_at;
    if owned.row.name == name {
        // Already this device's name. If a rename recorded it, the snapshot
        // carrying it may be what failed last time — the registry and this
        // database had already moved — so commit it again rather than leave
        // members on the old name with nothing left to retry. Idempotent: the
        // same snapshot again, under a newer timestamp.
        if renamed_at > 0 {
            commit_channel_moderation(&state, &owned, &topic, &welcome, &bans, &mods).await?;
        }
        return channel_info_from_id(&state, &channel_id).await;
    }
    // Two names with one registry key are one name there, so a change between
    // them is a re-casing — a refresh, not rationed — rather than a rename.
    let renames_key = crate::network::rendezvous::channel_name_registry_key(&owned.row.name)
        != crate::network::rendezvous::channel_name_registry_key(&name);
    let now = chrono::Utc::now().timestamp();
    if renames_key && renamed_at > 0 && now.saturating_sub(renamed_at) < RENAME_INTERVAL_SECS {
        return Err(coded(
            "channels_rename_too_soon",
            "A room can be renamed once a day",
        ));
    }
    // A re-casing marks the room renamed without starting the once-a-day
    // clock, which the registry does not start either: the name still has to
    // ride the snapshot or members would never see the new casing.
    let stamp = if renames_key { now } else { renamed_at.max(1) };
    // The room as it will be, in memory, so the snapshot committed below
    // carries exactly the name granted, whatever the database reads by then.
    let owned = OwnedChannel {
        row: StoredChannel {
            name: name.clone(),
            renamed_at: stamp,
            ..owned.row.clone()
        },
        ..owned
    };
    // Checked before the registry is asked. The name rides the snapshot with
    // the pins, and past this point the commit would have to shed pins to fit
    // it — or, the registry having granted the name, leave members on the old
    // one. Neither is what the owner asked for.
    if !owner_pins_fit(
        &topic,
        &welcome,
        &bans,
        &mods,
        &owner_moderation_tail(&state, &owned).await,
    ) {
        return Err(coded(
            "channels_rename_pins_no_room",
            "The new name doesn't fit alongside this room's pins. Choose a shorter name \
             or unpin a message.",
        ));
    }

    let private = owned.row.visibility == CHANNEL_KIND_PRIVATE;
    let url = rendezvous_url(&state).await;
    let seed = owned.ident.signing_key.to_bytes();
    // A claim for a different name is refused by the registry, so only an
    // actual rename goes through the rename operation. A re-casing is still
    // a claim, which also keeps it working against a server without renames.
    let granted = if renames_key {
        registry_call(crate::network::rendezvous::rename_channel_name(
            &url,
            &owned.ident.channel_id,
            &owned.ident.pubkey,
            &seed,
            &name,
            private,
        ))
        .await
    } else {
        registry_call(crate::network::rendezvous::claim_channel_name(
            &url,
            &owned.ident.channel_id,
            &owned.ident.pubkey,
            &seed,
            &name,
            private,
        ))
        .await
    };
    granted.map_err(|e| registry_fail(e, "channels_name_taken"))?;

    {
        let db = state.db.clone();
        let id = channel_id.clone();
        let new_name = name.clone();
        tokio::task::spawn_blocking(move || db.rename_owned_channel(&id, &new_name, stamp))
            .await
            .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
            .map_err(|e| coded_ctx("channels_moderation_failed", "Failed to save room info", e))?;
    }

    if !private {
        let record = SignedRecord::channel_index(
            &name,
            owned.ident.channel_id,
            owned.ident.pubkey,
            false,
            Some(owned.row.language.as_str()).filter(|l| !l.is_empty()),
            &owned.ident.signing_key,
        );
        // Not fatal: the owner loop republishes the listing, and Discover also
        // reads the registry, which already has the new name.
        if let Err(e) = queue_signed_record(&state, record).await {
            tracing::warn!(
                channel_id = %channel_id,
                error = %e,
                "renamed room's index record did not publish"
            );
        }
    }

    // Past the registry and the local save the room is renamed, whatever this
    // says: sizes were checked before the registry was asked, and the owner's
    // periodic republish reads the new name back from the database. Failing
    // here would tell the owner the rename did not happen and spend their one
    // rename a day on it.
    if let Err(e) = commit_channel_moderation(&state, &owned, &topic, &welcome, &bans, &mods).await {
        tracing::warn!(
            channel_id = %channel_id,
            error = %e,
            "renamed room's snapshot did not commit; the next republish carries the name"
        );
    }
    channel_info_from_id(&state, &channel_id).await
}

#[tauri::command]
pub async fn ban_channel_member(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    member_pubkey: String,
) -> Result<(), String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to moderate this channel",
        ));
    }
    let channel_id = parse_channel_id(&channel_id)?;
    let pk = parse_member_pubkey(&member_pubkey)?;
    if pk == state.identity.ed25519_public_key {
        return Err(coded(
            "channels_ban_self",
            "You cannot ban yourself",
        ));
    }
    let _snapshot = moderation_lock().lock().await;
    let (row, is_owner, is_mod) = moderation_power(&state, &channel_id).await?;
    if !is_owner && !is_mod {
        return Err(coded(
            "channels_not_moderator",
            "Only the owner or a moderator can do that",
        ));
    }
    if !is_owner
        && !row.owner_pubkey.is_empty()
        && row.owner_pubkey.eq_ignore_ascii_case(&hex::encode(pk))
    {
        return Err(coded(
            "channels_ban_owner",
            "You cannot ban the channel owner",
        ));
    }
    if is_owner {
        // From the first publish of a handoff record naming them it may be
        // stored, whether or not anyone said so, and once it is the members
        // follow it to the room they now own; nothing this device signs can
        // call it back, and our own fetch adopts it when it turns up. Banning
        // them here would only ban them from a room nobody is left in.
        //
        // Except a claim of theirs we are following that is not known to be
        // stored yet: the ban stops it being published, and it is given up
        // once our fetch shows it never landed.
        let db = state.db.clone();
        let id = channel_id.clone();
        let commit = tokio::task::spawn_blocking(move || db.channel_handoff_commit(&id))
            .await
            .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
            .map_err(|e| coded_ctx("channels_moderation_failed", "Failed to load channel", e))?;
        if commit.is_some_and(|commit| {
            commit.nominee.eq_ignore_ascii_case(&hex::encode(pk)) && (commit.confirmed || !commit.claimed)
        }) {
            return Err(coded(
                "channels_ban_transfer_nominee",
                "This member is already taking over the room and can no longer be banned from it",
            ));
        }
        let owned = load_owned_channel(&state, &channel_id).await?;
        let mut bans = load_banned_pubkeys(&state, &channel_id).await?;
        let mut mods = load_moderator_pubkeys(&state, &channel_id).await?;
        mods.retain(|existing| existing != &pk);
        if !bans.contains(&pk) {
            if bans.len() >= CHANNEL_BAN_LIST_MAX {
                return Err(coded_ctx(
                    "channels_ban_list_full",
                    format!("Ban list is full (max {CHANNEL_BAN_LIST_MAX})"),
                    CHANNEL_BAN_LIST_MAX,
                ));
            }
            bans.push(pk);
        }
        // Banning the nominee withdraws the nomination. Leaving it standing
        // would let the person we just evicted inherit the room once we went
        // quiet, which is the opposite of what a ban means.
        //
        // Cleared in memory, not written first. `commit_channel_moderation`
        // builds the published tail from this row and applies the same snapshot
        // locally, so the withdrawal travels with the ban: either both land or
        // neither does. Writing the column up front and re-reading it meant a
        // `rotate_and_commit` that then failed — a record that no longer fits, a
        // rotation the key store refused — left the nomination already gone, with
        // the ban not applied and nothing to put it back. The owner saw a failed
        // ban and had no way to know their successor had been wiped too.
        let withdraws_nominee = owned
            .row
            .successor_nominee
            .eq_ignore_ascii_case(&hex::encode(pk));
        let owned = if withdraws_nominee {
            OwnedChannel {
                row: StoredChannel {
                    successor_nominee: String::new(),
                    claim_after_days: 0,
                    ..owned.row.clone()
                },
                ..owned
            }
        } else {
            owned
        };
        // Rotate before committing: a ban that leaves the old key in place is
        // not an eviction, since the removed member — and anyone they gave the
        // invite to — can still read everything sent afterwards. Ordering
        // matters twice over, because the snapshot carries the new epoch number
        // and that is how the remaining members learn to fetch it.
        rotate_and_commit(&state, &owned, &bans, &mods).await?;
        if withdraws_nominee {
            register_nominee_with_registry(&state, &owned, None, 0).await;
        }
        // An offer still waiting on them would otherwise complete the moment
        // their ready reply arrived, handing the room to the person just
        // evicted from it.
        let db = state.db.clone();
        let id = channel_id.clone();
        let pending = tokio::task::spawn_blocking(move || db.channel_pending_handoff(&id))
            .await
            .ok()
            .and_then(|r| r.ok())
            .flatten();
        if pending.is_some_and(|(waiting_on, _)| waiting_on.eq_ignore_ascii_case(&hex::encode(pk)))
        {
            if let Err(e) = clear_channel_pending_handoff(&state, &channel_id).await {
                tracing::warn!(
                    channel_id = %channel_id,
                    error = %e,
                    "banned the pending successor but could not withdraw the transfer offer"
                );
            }
        }
        // The rotation locks them out of what the room sends next, but a
        // transfer already under way runs on a key pair of its own and would
        // have carried on delivering.
        if let Ok(id) = hex::decode(&channel_id)
            .map_err(|_| ())
            .and_then(|b| <[u8; 16]>::try_from(b).map_err(|_| ()))
        {
            let _ = state
                .network_tx
                .try_send(NetworkCommand::DropChannelTransfers {
                    channel_id: id,
                    member: Some(pk),
                });
        }
    } else {
        // The same ceiling the owner path enforces, reported the same way. A
        // moderator's ban travels as gossip and lands in the owner's next
        // snapshot, so one that does not fit would be lifted room-wide at the
        // next republish — and without this the storage layer would simply
        // decline the write and the moderator would be told only that "the ban
        // list was not updated".
        let bans = load_banned_pubkeys(&state, &channel_id).await?;
        if !bans.contains(&pk) && bans.len() >= CHANNEL_BAN_LIST_MAX {
            return Err(coded_ctx(
                "channels_ban_list_full",
                format!("Ban list is full (max {CHANNEL_BAN_LIST_MAX})"),
                CHANNEL_BAN_LIST_MAX,
            ));
        }
        // In a private room a ban is only an eviction once the content key
        // rotates, and an epoch record is signed by the room identity whose
        // seed the owner alone holds — `load_owned_channel` is the only way to
        // reach it, and it refuses anyone else. So a moderator's ban becomes an
        // eviction by exactly one route: the owner ingests the gossip, sets
        // `rotate_pending`, and their next moderation pass mints the epoch and
        // reseals it to everyone still in the room. With the owner away that
        // route does not exist, and the ban went through as an eviction anyway:
        // the roster drew the member as removed while they went on decrypting
        // every message the room sent afterwards, holding a key that is still
        // current. Refusing is the honest answer, because nothing this device
        // can sign would make the eviction real, and the moderator can see for
        // themselves — same presence window as the roster dot — that the owner
        // is the person to wait for.
        //
        // Public rooms are exempt: their key is derived from a pubkey anyone
        // who found the room already has, so a ban there never claimed to take
        // reading rights away in the first place.
        if row.visibility == CHANNEL_KIND_PRIVATE && !owner_is_present(&state, &row).await {
            return Err(coded(
                "channels_ban_owner_offline",
                "Removing someone from a private room needs the room's owner online: \
                 only they can change the room key, and without that the person \
                 would keep reading everything sent afterwards.",
            ));
        }
        apply_local_mod_ban(&state, &row, pk, true).await?;
    }
    Ok(())
}

#[tauri::command]
pub async fn unban_channel_member(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    member_pubkey: String,
) -> Result<(), String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to moderate this channel",
        ));
    }
    let channel_id = parse_channel_id(&channel_id)?;
    let pk = parse_member_pubkey(&member_pubkey)?;
    let _snapshot = moderation_lock().lock().await;
    let (row, is_owner, is_mod) = moderation_power(&state, &channel_id).await?;
    if !is_owner && !is_mod {
        return Err(coded(
            "channels_not_moderator",
            "Only the owner or a moderator can do that",
        ));
    }
    if is_owner {
        let owned = load_owned_channel(&state, &channel_id).await?;
        let mut bans = load_banned_pubkeys(&state, &channel_id).await?;
        let mods = load_moderator_pubkeys(&state, &channel_id).await?;
        bans.retain(|existing| existing != &pk);
        commit_channel_moderation(
            &state,
            &owned,
            &owned.row.topic,
            &owned.row.welcome,
            &bans,
            &mods,
        )
        .await?;
        // Only after the snapshot that drops them from the ban list. The other
        // order would put the room's key on the wire for somebody every other
        // member still holds a signed record saying is banned.
        reseal_current_epoch_to_member(&state, &owned, pk).await?;
    } else {
        apply_local_mod_ban(&state, &row, pk, false).await?;
    }
    Ok(())
}

#[tauri::command]
pub async fn add_channel_moderator(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    member_pubkey: String,
) -> Result<(), String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to moderate this channel",
        ));
    }
    let channel_id = parse_channel_id(&channel_id)?;
    let pk = parse_member_pubkey(&member_pubkey)?;
    if pk == state.identity.ed25519_public_key {
        return Err(coded(
            "channels_mod_self",
            "You cannot appoint yourself as a moderator",
        ));
    }
    let _snapshot = moderation_lock().lock().await;
    let owned = load_owned_channel(&state, &channel_id).await?;
    let mut bans = load_banned_pubkeys(&state, &channel_id).await?;
    let mut mods = load_moderator_pubkeys(&state, &channel_id).await?;
    bans.retain(|existing| existing != &pk);
    if !mods.contains(&pk) {
        if mods.len() >= CHANNEL_MOD_LIST_MAX {
            return Err(coded_ctx(
                "channels_mod_list_full",
                format!("Moderator list is full (max {CHANNEL_MOD_LIST_MAX})"),
                CHANNEL_MOD_LIST_MAX,
            ));
        }
        mods.push(pk);
    }
    commit_channel_moderation(
        &state,
        &owned,
        &owned.row.topic,
        &owned.row.welcome,
        &bans,
        &mods,
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn remove_channel_moderator(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    member_pubkey: String,
) -> Result<(), String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to moderate this channel",
        ));
    }
    let channel_id = parse_channel_id(&channel_id)?;
    let pk = parse_member_pubkey(&member_pubkey)?;
    let _snapshot = moderation_lock().lock().await;
    let owned = load_owned_channel(&state, &channel_id).await?;
    let bans = load_banned_pubkeys(&state, &channel_id).await?;
    let mut mods = load_moderator_pubkeys(&state, &channel_id).await?;
    mods.retain(|existing| existing != &pk);
    commit_channel_moderation(
        &state,
        &owned,
        &owned.row.topic,
        &owned.row.welcome,
        &bans,
        &mods,
    )
    .await?;
    Ok(())
}

/// Nominate who may take the room over if the owner stops republishing, and
/// after how long. Both facts ride the owner-signed moderation record, so every
/// member can check a later claim against them.
#[tauri::command]
pub async fn set_channel_successor_nominee(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    member_pubkey: Option<String>,
    claim_after_days: Option<u16>,
) -> Result<ChannelInfo, String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to edit this channel",
        ));
    }
    let channel_id = parse_channel_id(&channel_id)?;
    let nominee = match member_pubkey.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(raw) => {
            let pk = parse_member_pubkey(raw)?;
            if pk == state.identity.ed25519_public_key {
                return Err(coded(
                    "channels_mod_self",
                    "You cannot nominate yourself as successor",
                ));
            }
            Some(pk)
        }
    };
    // No nominee means no succession, whatever window was asked for.
    let days = if nominee.is_none() {
        0
    } else {
        claim_after_days
            .unwrap_or(channel::CLAIM_AFTER_DAYS_DEFAULT)
            .clamp(channel::CLAIM_AFTER_DAYS_MIN, channel::CLAIM_AFTER_DAYS_MAX)
    };
    let _snapshot = moderation_lock().lock().await;
    let owned = load_owned_channel(&state, &channel_id).await?;
    if nominee.is_some() {
        // Nominating somebody who is not in the room, or is banned from it,
        // would hand it to nobody.
        let member_hex = nominee.map(hex::encode).unwrap_or_default();
        let db = state.db.clone();
        let id = channel_id.clone();
        let ok = tokio::task::spawn_blocking(move || {
            let members = db.list_channel_members(&id)?;
            Ok::<_, anyhow::Error>(members.into_iter().any(|m| {
                m.member_pubkey.eq_ignore_ascii_case(&member_hex) && !m.banned
            }))
        })
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_moderation_failed", "Could not load members", e))?;
        if !ok {
            return Err(coded(
                "channels_member_invalid",
                "That member is not in this room",
            ));
        }
    }
    // Carried in memory rather than written first, exactly as
    // `set_channel_invite_policy` does it. `commit_channel_moderation` builds the
    // published tail from this row *and* applies the same snapshot locally, so
    // passing the requested value makes the change atomic: either it publishes
    // and is stored, or neither happens. Writing the column up front meant a
    // commit that refused — a record that no longer fits, a stale timestamp —
    // returned an error for a nomination the database had in fact accepted, so
    // this device honoured a successor the room had never been told about.
    let nominee_hex = nominee.map(hex::encode).unwrap_or_default();
    let owned = OwnedChannel {
        row: StoredChannel {
            successor_nominee: nominee_hex,
            claim_after_days: i64::from(days),
            ..owned.row.clone()
        },
        ..owned
    };

    // Publishes the nomination and stores it, in that order and as one step.
    let bans = load_banned_pubkeys(&state, &channel_id).await?;
    let mods = load_moderator_pubkeys(&state, &channel_id).await?;
    commit_channel_moderation(
        &state,
        &owned,
        &owned.row.topic,
        &owned.row.welcome,
        &bans,
        &mods,
    )
    .await?;
    // Only once the commit has landed: a registry told first would hold a
    // nominee the room never had whenever the commit then refused.
    register_nominee_with_registry(&state, &owned, nominee.as_ref(), u32::from(days)).await;
    channel_info_from_id(&state, &channel_id).await
}

/// Tell the name registry who may inherit the room's name.
///
/// Members learn the nomination from the moderation record, but the registry
/// cannot read that. Without this a nominee could take the room and still not
/// move its name — or, once withdrawn, still move it after being banned.
/// Not fatal on failure: the owner's periodic republish re-sends the current
/// nominee, so an unreachable registry only delays it catching up.
async fn register_nominee_with_registry(
    state: &AppState,
    owned: &OwnedChannel,
    nominee: Option<&[u8; 32]>,
    claim_after_days: u32,
) {
    let url = rendezvous_url(state).await;
    if url.is_empty() {
        return;
    }
    if let Err(e) = registry_call(crate::network::rendezvous::register_channel_nominee(
        &url,
        &owned.ident.channel_id,
        &owned.ident.pubkey,
        &owned.ident.seed(),
        nominee,
        claim_after_days,
    ))
    .await
    {
        tracing::warn!(
            channel_id = %owned.row.channel_id,
            error = ?e,
            "saved the nominee but could not update the name registry"
        );
    }
}

/// Take over a room whose owner has gone silent, as the member they nominated.
///
/// Mints a fresh room key — the old owner's seed is never copied — and publishes
/// a claim every member checks against the nomination in the owner's last signed
/// record before following it.
#[tauri::command]
pub async fn claim_channel_ownership(
    state: tauri::State<'_, AppState>,
    channel_id: String,
) -> Result<ChannelInfo, String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to claim this channel",
        ));
    }
    let channel_id = parse_channel_id(&channel_id)?;
    let snapshot = moderation_lock().lock().await;
    let row = load_joined_channel(&state, &channel_id).await?;
    if row.is_owner || !row.successor_id.is_empty() {
        return Err(coded(
            "channels_handoff_failed",
            "This room does not need claiming",
        ));
    }
    let our_hex = hex::encode(state.identity.ed25519_public_key);
    if !row.successor_nominee.eq_ignore_ascii_case(&our_hex) {
        return Err(coded(
            "channels_not_nominee",
            "The owner nominated somebody else",
        ));
    }
    // No point minting a room every other member will refuse to follow.
    if self_banned_from(&state, &row, "channels_handoff_failed").await? {
        return Err(coded(
            "channels_banned",
            "You are banned from this channel",
        ));
    }
    if row.claim_after_days <= 0 || row.moderation_updated_at <= 0 {
        return Err(coded(
            "channels_claim_too_early",
            "This room has no succession window set",
        ));
    }
    // Our snapshot only means the owner is gone if we have actually been asking.
    // Otherwise a nominee who had been offline past the window would, on
    // startup, claim a room whose owner never stopped publishing — and every
    // other member would rightly refuse it, leaving the nominee alone on a
    // successor room while the real one carried on without them.
    if !channel::owner_silence_is_confirmed(row.moderation_checked_at) {
        return Err(coded(
            "channels_claim_unverified",
            "Still checking whether the owner is active; try again shortly",
        ));
    }
    let now = chrono::Utc::now().timestamp();
    if now.saturating_sub(row.moderation_updated_at)
        < row.claim_after_days.saturating_mul(86_400)
    {
        return Err(coded(
            "channels_claim_too_early",
            "The owner has not been silent long enough yet",
        ));
    }

    let successor = ChannelIdentity::generate();
    let private = row.visibility == CHANNEL_KIND_PRIVATE;
    let seed = successor.seed();
    let old_pubkey = hex::decode(&row.pubkey)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| coded("channels_not_found", "Channel not found"))?;
    let mut old_id = [0u8; 16];
    hex::decode_to_slice(&channel_id, &mut old_id)
        .map_err(|_| coded("channels_not_found", "Channel not found"))?;

    // Install locally first: if the publish fails we are still the owner of a
    // successor room our own members can be pointed at on the next republish,
    // rather than having announced a room we do not hold the key to.
    let db = state.db.clone();
    let old = channel_id.clone();
    let successor_pk_hex = hex::encode(successor.pubkey);
    let successor_id_hex = hex::encode(successor.channel_id);
    let applied = tokio::task::spawn_blocking(move || {
        db.apply_claimed_channel_handoff(&old, &successor_pk_hex, &successor_id_hex, private, Some(&seed))
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_handoff_failed", "Could not claim the room", e))?;
    // Refused: the room moved or was deleted since it was loaded. Publishing
    // the claim anyway would send the members to a successor nobody holds.
    if !applied {
        return Err(coded(
            "channels_handoff_failed",
            "This room does not need claiming",
        ));
    }

    // Everything that needed serialising is now in the database, and the room
    // reads as claimed, so a second attempt is refused by the guard above
    // rather than by this lock. Released before the network work because
    // `MODERATION_LOCK` is a single mutex across every room and the two calls
    // below wait on the DHT and then on Rendezvous — holding it across them
    // froze bans, topic edits and key rotation in every *other* room for the
    // best part of a minute. `commit_channel_moderation` was changed to
    // queue-rather-than-await for the same reason; this path was missed.
    drop(snapshot);

    let claim = SignedRecord::channel_succession_claim(
        old_id,
        old_pubkey,
        &successor.pubkey,
        row.moderation_updated_at,
        private,
        &crypto::signing_key_from_bytes(&state.identity.ed25519_secret_key),
    );
    if let Err(e) = publish_signed_record(&state, claim).await {
        tracing::warn!(
            channel_id = %channel_id,
            error = %e,
            "claimed a room locally but could not publish the claim yet"
        );
    }
    // Kept for republishing, which is also what covers a publish that failed
    // just now: a member away for the day the claim lived on older storers, and
    // the silent owner when they come back, have no other way to find it.
    {
        let db = state.db.clone();
        let old = channel_id.clone();
        let old_pubkey_hex = row.pubkey.clone();
        let successor_pk_hex = hex::encode(successor.pubkey);
        let witnessed = row.moderation_updated_at;
        if let Err(e) = tokio::task::spawn_blocking(move || {
            db.retire_channel_claim(
                &old,
                &old_pubkey_hex,
                witnessed,
                &successor_pk_hex,
                private,
                chrono::Utc::now().timestamp(),
            )
        })
        .await
        .map_err(anyhow::Error::from)
        .and_then(|r| r)
        {
            tracing::warn!(channel_id = %channel_id, error = %e, "could not keep the claim for republishing");
        }
    }

    // Take the name with us. Signed with our *user* key: the owner registered
    // us as their nominee, and the registry checks their claim has been stale
    // for the window they published — the same silence we just proved against
    // their moderation record.
    let url = rendezvous_url(&state).await;
    if !url.is_empty() {
        if let Err(e) = registry_call(crate::network::rendezvous::handover_channel_name(
            &url,
            &old_id,
            &successor.channel_id,
            &successor.pubkey,
            &state.identity.ed25519_public_key,
            &state.identity.ed25519_secret_key,
        ))
        .await
        {
            // The room is ours either way; only its directory name is behind,
            // and the periodic refresh retries the claim.
            tracing::warn!(
                channel_id = %channel_id,
                error = ?e,
                "claimed the room but could not move its registry name yet"
            );
        }
    }

    // Rotate the successor room straight away, and let that be what every
    // member converges on.
    //
    // The room inherits the predecessor's *current* content key, and each member
    // computes that from whichever epoch they had reached — so a member who
    // never caught up would inherit a different secret and be unable to talk to
    // anyone. Rotating fixes it for good, because the new key reaches each
    // member sealed pairwise against our identity: that needs only our pubkey,
    // which we sign into the moderation record below, and their own seed. No
    // shared secret has to have survived the handoff for this to work.
    let successor_id_hex = hex::encode(successor.channel_id);
    // Retaken for the successor room's own moderation write, which is a commit
    // like any other and has to serialise with the rest.
    let _snapshot = moderation_lock().lock().await;
    match load_owned_channel(&state, &successor_id_hex).await {
        Ok(owned) => {
            let bans = load_banned_pubkeys(&state, &successor_id_hex)
                .await
                .unwrap_or_default();
            let mods = load_moderator_pubkeys(&state, &successor_id_hex)
                .await
                .unwrap_or_default();
            // Not `rotate_and_commit`, because the two halves are not equally
            // optional here: the commit is also the first record naming us as
            // owner, which is what lets members derive the pairwise key at all.
            // A room that failed to rotate still works — everyone inherited a
            // key — so the snapshot goes out either way. What must not survive
            // is the reverse: a rotation the snapshot never announced leaves us
            // sealing traffic under an epoch nobody has been told to fetch.
            let rotated = match rotate_channel_key(&state, &owned, &bans).await {
                Ok(rotated) => rotated,
                Err(e) => {
                    tracing::warn!(channel_id = %successor_id_hex, error = %e, "could not rotate the claimed room");
                    None
                }
            };
            match commit_channel_moderation(
                &state,
                &owned,
                &owned.row.topic,
                &owned.row.welcome,
                &bans,
                &mods,
            )
            .await
            {
                Ok(_) if rotated.is_some() || !private => {}
                // The one rotation this room is owed, and nothing else is going
                // to mint it: the claim left no mark for the owned-room pass,
                // whose rotation would have raced this one for the same epoch.
                // Marked now that ours did not land, and that pass retries it.
                outcome => {
                    if let Err(e) = outcome {
                        tracing::warn!(channel_id = %successor_id_hex, error = %e, "could not publish the claimed room's first record");
                        undo_rotation(&state, &owned, rotated).await;
                    }
                    let db = state.db.clone();
                    let id = successor_id_hex.clone();
                    let _ = tokio::task::spawn_blocking(move || db.mark_channel_rotate_pending(&id)).await;
                }
            }
        }
        Err(e) => {
            tracing::warn!(channel_id = %successor_id_hex, error = %e, "claimed room is not loadable as owned");
        }
    }
    channel_info_from_id(&state, &successor_id_hex).await
}

/// How many rooms one Discover pass will ask the network to size. Each costs a
/// FIND_VALUE, so this is the ceiling on what browsing adds to a walk.
const MAX_PRESENCE_PROBE_ROOMS: usize = 24;

/// Probe FIND_VALUEs started at once. The search manager holds 64 slots and
/// a walk lasts 60s unless cancelled; 24 in parallel plus shard walks used
/// to fill the table so new searches were silently rejected.
const PRESENCE_PROBE_CONCURRENCY: usize = 6;

/// How long to wait for those counts. Far shorter than a shard walk's budget:
/// the size is a decoration on a listing the browse has already produced, so a
/// slow answer should be dropped rather than hold the whole result back.
const PRESENCE_PROBE_TIMEOUT_MS: u64 = 6_000;

/// How recently a member must have announced themselves to be counted. Two
/// republish intervals, so one missed announcement does not drop somebody, and
/// the same rule the roster's presence dot uses.
const PRESENCE_FRESH_SECS: i64 = channel::PRESENCE_FRESH_SECS;

/// Count who is announcing themselves in public rooms we have not joined.
///
/// A public room's presence key folds in `public_join_secret`, which *is* the
/// channel pubkey, and its presence extra is unsealed — so a directory listing
/// alone is enough to read the room's size. Private rooms fold in a real secret
/// and stay uncountable on purpose, which is why they never reach here.
///
/// Only the current epoch is asked for. A member who last announced under the
/// previous key is missed for up to one republish interval. Rooms that time
/// out or never answer stay `None`; a completed walk with no fresh live
/// records is stamped 0.
async fn probe_public_member_counts(
    state: &AppState,
    rooms: &[(String, String)],
) -> Option<std::collections::HashMap<String, i64>> {
    use std::collections::{HashMap, HashSet};

    let now = chrono::Utc::now().timestamp();
    let epoch = channel::presence_epoch(now);
    let mut wanted: HashMap<[u8; 16], String> = HashMap::new();
    for (id_hex, pk_hex) in rooms.iter().take(MAX_PRESENCE_PROBE_ROOMS) {
        let Some(id) = hex::decode(id_hex)
            .ok()
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
        else {
            continue;
        };
        let Some(pk) = hex::decode(pk_hex)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            continue;
        };
        let key = channel::presence_key(&id, &channel::public_join_secret(&pk), epoch);
        wanted.insert(key, id_hex.clone());
    }
    if wanted.is_empty() {
        return None;
    }
    // One FIND_VALUE per presence key, the same pattern as the public-index
    // shard walks. Batching independent rooms into extras AND-filters by
    // file_hash, and MAX_FIND_VALUE_KEYS would truncate the rest to a
    // confirmed 0 the UI treated as authoritative. Run in small batches so
    // the 64-slot search table is not filled by one Discover pass.
    let keys: Vec<[u8; 16]> = wanted.keys().copied().collect();
    let mut walks = Vec::with_capacity(keys.len());
    for chunk in keys.chunks(PRESENCE_PROBE_CONCURRENCY) {
        let batch = futures::future::join_all(
            chunk
                .iter()
                .map(|key| find_raw_keys_within(state, vec![*key], PRESENCE_PROBE_TIMEOUT_MS)),
        )
        .await;
        walks.extend(batch);
    }
    let mut members: HashMap<String, HashMap<[u8; 32], (i64, bool)>> = HashMap::new();
    let mut answered: HashSet<String> = HashSet::new();
    let mut any_answer = false;
    for (key, walk) in keys.into_iter().zip(walks) {
        let Some(blobs) = walk.unwrap_or(None) else {
            continue;
        };
        any_answer = true;
        let Some(id_hex) = wanted.get(&key) else {
            continue;
        };
        answered.insert(id_hex.clone());
        let Some(channel_id) = hex::decode(id_hex)
            .ok()
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
        else {
            continue;
        };
        let per_room = members.entry(id_hex.clone()).or_default();
        for blob in blobs {
            if let Some(member) =
                SignedRecord::parse_channel_presence_member(&blob, &channel_id, None)
            {
                match per_room.get(&member.publisher_key) {
                    Some((ts, departed))
                        if *ts > member.timestamp
                            || (*ts == member.timestamp && *departed && !member.departed) => {}
                    _ => {
                        per_room.insert(
                            member.publisher_key,
                            (member.timestamp, member.departed),
                        );
                    }
                }
            }
        }
    }
    // Hearing nothing at all cannot be told apart from not being able to ask.
    if !any_answer {
        return None;
    }
    // A walked key that completed — including tombstone-only or empty —
    // reports 0 rather than leaving the previous count on screen forever.
    // Timeouts stay absent so the UI does not treat 0 as authoritative.
    let mut out = HashMap::new();
    for id in answered {
        let count = members.get(&id).map(|seen| {
            seen.values()
                .filter(|(ts, departed)| {
                    !*departed && now.saturating_sub(*ts) <= PRESENCE_FRESH_SECS
                })
                .count() as i64
        }).unwrap_or(0);
        out.insert(id, count);
    }
    Some(out)
}

/// Turn one shard's raw `FOUND_VALUE` blobs into public room listings, each
/// with the signed timestamp of the record it came from.
///
/// Several storers can hold different generations of one room's record, so
/// the same room can appear more than once; [`merge_signed_listing`] keeps the
/// newest. Private rooms publish an index record too and are dropped here:
/// theirs exists so a holder of the invite can confirm the room, not so a
/// browse can find it.
fn listings_from_blobs(
    blobs: Vec<Vec<u8>>,
    joined_ids: &std::collections::HashSet<String>,
) -> Vec<(GatheredChannelInfo, i64)> {
    let mut out = Vec::new();
    for blob in blobs {
        let Some(rec) = SignedRecord::from_value_blob(&blob) else {
            continue;
        };
        if rec.record_type != crate::network::ember::dht::publish::RECORD_TYPE_CHANNEL {
            continue;
        }
        if !rec.channel_store_ok() {
            continue;
        }
        // Only an index record is signed by the room's own key. A storer
        // accepts a presence record under any key, from anyone, so one filed
        // in a shard would otherwise pass as the room's listing and put a
        // stranger's name and language on it.
        let Some(meta) = rec
            .channel
            .as_ref()
            .filter(|m| m.kind == crate::network::ember::dht::publish::CHANNEL_KIND_INDEX)
        else {
            continue;
        };
        let private = meta.is_private();
        if private {
            continue;
        }
        let id_hex = hex::encode(rec.file_hash);
        out.push((
            GatheredChannelInfo {
                channel_id: id_hex.clone(),
                pubkey: hex::encode(rec.ember_file_hash),
                name: discovered_room_name(&rec.file_name, &id_hex),
                private,
                joined: joined_ids.contains(&id_hex),
                member_count: None,
                language: crate::network::ember::dht::publish::channel_language_from_file_size(
                    rec.file_size,
                )
                .unwrap_or("")
                .to_string(),
            },
            rec.timestamp,
        ));
    }
    out
}

/// Fold one signed listing into the rows gathered so far. Returns the row to
/// re-emit when it adds a room or changes one.
///
/// Where a gathered row came from: its index in the output, the timestamp of
/// the newest signed listing folded into it, and whether the Rendezvous
/// directory supplied it.
type ListingOrigin = (usize, Option<i64>, bool);

/// `signed_at` tracks each row's [`ListingOrigin`]. The directory is unsigned
/// and knows nothing of the room's language, so signed listings for one of
/// its rooms bring the language in and leave the registry's name standing
/// whatever order storers answer in. Between signed listings the newest wins
/// outright, so a storer still holding a stale generation cannot put back a
/// name or language the owner has since changed.
fn merge_signed_listing(
    out: &mut Vec<GatheredChannelInfo>,
    signed_at: &mut std::collections::HashMap<String, ListingOrigin>,
    listing: GatheredChannelInfo,
    timestamp: i64,
) -> Option<GatheredChannelInfo> {
    match signed_at.get_mut(&listing.channel_id) {
        None => {
            signed_at.insert(listing.channel_id.clone(), (out.len(), Some(timestamp), false));
            out.push(listing.clone());
            Some(listing)
        }
        Some((i, seen, from_directory)) => {
            if seen.is_some_and(|prev| prev >= timestamp) {
                return None;
            }
            let row = &mut out[*i];
            if !*from_directory {
                row.name = listing.name;
            }
            *seen = Some(timestamp);
            row.language = listing.language;
            Some(row.clone())
        }
    }
}

/// Display name for a room nobody here has joined, from a name its publisher
/// chose.
///
/// Discover is the one route into the room list that does not pass through
/// `accept_invite`, so it has to do the same trimming that path does. The
/// record's own cap is a kilobyte and says nothing about characters, which
/// leaves an unfiltered name free to run past every column the page has and
/// to carry zero-width and bidi controls — a listing that reads as a
/// well-known room while pointing somewhere else. The identity underneath is
/// verified (`channel_id == BLAKE3(pubkey)`), so only the label is at stake,
/// but the label is what the user clicks.
///
/// A name that sanitizes away to nothing falls back to the short id, which is
/// what a room that never had a name already shows.
fn discovered_room_name(raw: &str, channel_id_hex: &str) -> String {
    let cleaned = crate::security::sanitize_remote_text(raw, MAX_CHANNEL_NAME_CHARS);
    if !cleaned.is_empty() {
        return cleaned;
    }
    channel_id_hex
        .get(..8)
        .unwrap_or(channel_id_hex)
        .to_string()
}

fn inside_ids(rows: &[StoredChannel]) -> std::collections::HashSet<String> {
    rows.iter()
        .filter(|c| c.in_room_now())
        .map(|c| c.channel_id.clone())
        .collect()
}

/// One shard's worth of listings, tagged with the walk that asked for them.
#[derive(Clone, serde::Serialize)]
struct GatheredChannelBatch<'a> {
    /// Echoed straight back from the caller.
    ///
    /// Shards from a finished walk can still be in the air when the next one
    /// starts, and the page had no way to tell them apart — it merged them into
    /// the new walk's results as though they had just been found. The caller
    /// names its own walk because the events begin arriving before this command
    /// returns, so nothing the return value carries could identify them in time.
    walk: &'a str,
    channels: &'a [GatheredChannelInfo],
}

/// Longest walk token echoed back. Local IPC, so this is hygiene rather than a
/// boundary: a token is a generated id, and a long one is a mistake either way.
const GATHER_WALK_MAX: usize = 64;

/// Walk the 16 public-index shards and return unique channel listings.
///
/// Each shard is emitted on `ember:channels-found` the moment it lands, so a
/// browse fills in as answers arrive instead of showing nothing until the
/// slowest walk gives up, and the merged result is cached for the next open.
/// The return value is still the complete set: a caller that ignores the
/// events behaves exactly as before.
#[tauri::command]
pub async fn gather_channels(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    walk: String,
) -> Result<Vec<GatheredChannelInfo>, String> {
    use futures::StreamExt;

    let walk: String = walk.chars().take(GATHER_WALK_MAX).collect();
    let emit = |channels: &[GatheredChannelInfo]| {
        let _ = app.emit(
            "ember:channels-found",
            GatheredChannelBatch {
                walk: &walk,
                channels,
            },
        );
    };

    require_ember(&state).await?;
    let db = state.db.clone();
    let local = tokio::task::spawn_blocking(move || db.list_channels())
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default();
    let joined_ids = inside_ids(&local);

    let url = rendezvous_url(&state).await;
    let (directory, deleted) = tokio::join!(
        crate::network::rendezvous::fetch_channel_directory(&url, DIRECTORY_FETCH_TIMEOUT),
        tokio::time::timeout(
            DIRECTORY_FETCH_TIMEOUT,
            crate::network::rendezvous::fetch_deleted_channel_ids(&url),
        ),
    );
    // A rendezvous that is down or slow degrades Discover to whatever the DHT
    // walks below turn up, which is the right behaviour — but it used to be
    // indistinguishable from "the network has no rooms". Log it so an empty
    // Discover can be told apart from an unreachable directory.
    let directory = match directory {
        Ok(list) => list,
        Err(error) => {
            tracing::warn!(?error, "channel directory fetch failed; showing DHT results only");
            Vec::new()
        }
    };
    let deleted: std::collections::HashSet<String> = match deleted {
        Ok(Ok(ids)) => ids,
        Ok(Err(error)) => {
            tracing::warn!(?error, "deleted-channel list fetch failed; tombstoned rooms may still be listed");
            Vec::new()
        }
        Err(_) => {
            tracing::warn!("deleted-channel list fetch timed out; tombstoned rooms may still be listed");
            Vec::new()
        }
    }
    .into_iter()
    .map(|id| id.to_ascii_lowercase())
    .collect();
    if !deleted.is_empty() {
        let db = state.db.clone();
        let ids: Vec<String> = deleted.iter().cloned().collect();
        let _ = tokio::task::spawn_blocking(move || db.walk_out_deleted_channels(&ids)).await;
    }

    let mut walks: futures::stream::FuturesUnordered<_> = channel::all_index_keys()
        .into_iter()
        .map(|key| find_raw_keys(&state, vec![key]))
        .collect();

    let mut signed_at: std::collections::HashMap<String, ListingOrigin> =
        std::collections::HashMap::new();
    let mut out: Vec<GatheredChannelInfo> = Vec::new();
    for listing in directory {
        let id = listing.channel_id.to_ascii_lowercase();
        if deleted.contains(&id) {
            continue;
        }
        // Directory rows are the one channel listing that arrives unsigned, so
        // this is the only place the id has to be checked against the key it
        // claims. A room's id *is* BLAKE3 of its pubkey, so a row that
        // disagrees with itself was forged or corrupted in transit.
        // `ChannelInvite::parse` already refuses the pair, but finding out at
        // Join reads as "this app is broken" rather than "that listing was".
        let pubkey_hex = listing.pubkey.to_ascii_lowercase();
        let Some(pubkey) = hex::decode(&pubkey_hex)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
        else {
            continue;
        };
        if hex::encode(channel::channel_id_from_pubkey(&pubkey)) != id {
            continue;
        }
        if signed_at.contains_key(&id) {
            continue;
        }
        signed_at.insert(id.clone(), (out.len(), None, true));
        let name = discovered_room_name(&listing.name, &id);
        out.push(GatheredChannelInfo {
            joined: joined_ids.contains(&id),
            channel_id: id,
            pubkey: pubkey_hex,
            name,
            private: false,
            member_count: None,
            language: String::new(),
        });
    }
    if !out.is_empty() {
        emit(&out);
    }

    while let Some(shard) = walks.next().await {
        let mut changed = Vec::new();
        for (listing, timestamp) in listings_from_blobs(shard.unwrap_or_default(), &joined_ids) {
            if deleted.contains(&listing.channel_id) {
                continue;
            }
            if let Some(row) = merge_signed_listing(&mut out, &mut signed_at, listing, timestamp) {
                changed.retain(|c: &GatheredChannelInfo| c.channel_id != row.channel_id);
                changed.push(row);
            }
        }
        if !changed.is_empty() {
            emit(&changed);
        }
    }

    // A room the user has not joined shows no roster, so the directory is the
    // only place its size can come from. Rooms we are already in are skipped:
    // their own member table is both cheaper and more accurate.
    let probe: Vec<(String, String)> = out
        .iter()
        .filter(|c| !c.private && !c.joined)
        .map(|c| (c.channel_id.clone(), c.pubkey.clone()))
        .collect();
    if !probe.is_empty() {
        if let Some(counts) = probe_public_member_counts(&state, &probe).await {
            for item in out.iter_mut() {
                if let Some(count) = counts.get(&item.channel_id) {
                    item.member_count = Some(*count);
                }
            }
            emit(&out);
        }
    }

    let listings: Vec<CachedChannel> = out
        .iter()
        .map(|c| CachedChannel {
            channel_id: c.channel_id.clone(),
            pubkey: c.pubkey.clone(),
            name: c.name.clone(),
            language: c.language.clone(),
        })
        .collect();
    if !listings.is_empty() {
        let db = state.db.clone();
        let _ = tokio::task::spawn_blocking(move || db.cache_channel_listings(&listings)).await;
    }

    Ok(out)
}

/// Rooms the last Discover walk found, straight from the local cache.
///
/// Answers without touching the network so the browse has something on screen
/// while [`gather_channels`] is still walking. These are hints and may name a
/// room that has since gone; the walk that follows is what confirms them.
#[tauri::command]
pub async fn cached_channels(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<GatheredChannelInfo>, String> {
    let db = state.db.clone();
    let (cached, joined) = tokio::task::spawn_blocking(move || {
        (
            db.list_cached_channels().unwrap_or_default(),
            db.list_channels().unwrap_or_default(),
        )
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?;

    let joined_ids = inside_ids(&joined);
    let hidden: std::collections::HashSet<String> = joined
        .iter()
        .filter(|c| c.deleted)
        .map(|c| c.channel_id.clone())
        .collect();
    Ok(cached
        .into_iter()
        .filter(|c| !hidden.contains(&c.channel_id))
        .map(|c| GatheredChannelInfo {
            joined: joined_ids.contains(&c.channel_id),
            channel_id: c.channel_id,
            pubkey: c.pubkey,
            name: c.name,
            private: false,
            // Nobody's presence is cached, so the size stays unknown until the
            // walk this cache is standing in for comes back.
            member_count: None,
            language: c.language,
        })
        .collect())
}

/// Queue a signed record on the Ember DHT without waiting for STORE (or even
/// for the network task to pick the command up). Presence join/leave must not
/// hold the UI for that lookup (up to [`DEFAULT_FIND_TIMEOUT_MS`]). The
/// oneshot is dropped: `PublishEmberRecord` still starts the walk, and
/// `maybe_finish_ember_publish` ignores a gone waiter.
async fn queue_signed_record(state: &AppState, record: SignedRecord) -> Result<(), String> {
    let (tx, _rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::PublishEmberRecord {
            record: Box::new(record),
            tx,
        })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    Ok(())
}

async fn start_signed_record(
    state: &AppState,
    record: SignedRecord,
) -> Result<EmberPublishPending, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::PublishEmberRecord {
            record: Box::new(record),
            tx,
        })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    await_reply(rx, "channels_publish_failed", "No response from network").await?
}

async fn publish_signed_record(
    state: &AppState,
    record: SignedRecord,
) -> Result<EmberPublishResult, String> {
    let pending = start_signed_record(state, record).await?;
    match tokio::time::timeout(
        std::time::Duration::from_millis(DEFAULT_FIND_TIMEOUT_MS),
        pending.result_rx,
    )
    .await
    {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(_)) => Err(coded(
            "channels_publish_failed",
            "Publish was dropped",
        )),
        Err(_) => Err(coded(
            "channels_publish_failed",
            "Publish timed out",
        )),
    }
}

async fn find_raw_keys(state: &AppState, keys: Vec<[u8; 16]>) -> Result<Vec<Vec<u8>>, String> {
    Ok(find_raw_keys_within(state, keys, DEFAULT_FIND_TIMEOUT_MS)
        .await?
        .unwrap_or_default())
}

/// `None` means the caller timed out (or the waiter was dropped) before the
/// search completed. `Some(blobs)` — including empty — means the walk finished.
async fn find_raw_keys_within(
    state: &AppState,
    keys: Vec<[u8; 16]>,
    timeout_ms: u64,
) -> Result<Option<Vec<Vec<u8>>>, String> {
    if keys.is_empty() {
        return Ok(Some(Vec::new()));
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::FindEmberKeys { keys, tx })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    let pending = await_reply(rx, "channels_gather_failed", "No response from network").await??;
    match tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        pending.records_rx,
    )
    .await
    {
        Ok(Ok(records)) => Ok(Some(records)),
        Ok(Err(_)) => Ok(None),
        Err(_) => {
            let _ = state
                .network_tx
                .try_send(NetworkCommand::CancelEmberSearch {
                    search_id: pending.search_id,
                });
            Ok(None)
        }
    }
}

/// Owner starts a transfer: the named member mints a new channel key; the
/// old key then signs a DHT handoff. The seed is never copied.
#[tauri::command]
pub async fn transfer_channel_ownership(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    member_pubkey: String,
) -> Result<(), String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to transfer this channel",
        ));
    }
    let channel_id = parse_channel_id(&channel_id)?;
    let pk = parse_member_pubkey(&member_pubkey)?;
    if pk == state.identity.ed25519_public_key {
        return Err(coded(
            "channels_mod_self",
            "You cannot transfer the room to yourself",
        ));
    }
    // Held across the check-then-write below, like every other owner mutation.
    // Without it this was a plain read-modify-write: two transfers started
    // close together — a double click, or two windows — both read "nothing
    // pending", both wrote, and both gossiped a validly signed offer to
    // different members, which is exactly the ambiguous ownership the check
    // exists to prevent.
    let _snapshot = moderation_lock().lock().await;
    let owned = load_owned_channel(&state, &channel_id).await?;
    if !owned.row.successor_id.is_empty() {
        return Err(coded(
            "channels_handoff_failed",
            "This room has already been transferred",
        ));
    }
    // Once the nominee has answered and a handoff record has gone out, the room
    // is spoken for: that record may be stored even though no acknowledgement
    // said so, and a second offer would put a rival record beside it and split
    // the members between two successors. Transferring to the same member
    // again re-drives the publish instead. Only once the offer it answered has
    // lapsed — long enough for our own handoff fetch to have found a record
    // that did land — may an unconfirmed commitment be given up.
    let db = state.db.clone();
    let commit_id = channel_id.clone();
    let commit = tokio::task::spawn_blocking(move || db.channel_handoff_commit(&commit_id))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_handoff_failed", "Could not start transfer", e))?;
    if let Some(commit) = commit {
        let now = chrono::Utc::now().timestamp();
        let publishing = || {
            coded(
                "channels_handoff_publishing",
                "This room's ownership transfer is still being published",
            )
        };
        // A claim we are following has no offer to lapse: the members who
        // honoured it have already left for its successor.
        if commit.confirmed || commit.claimed {
            return Err(publishing());
        }
        if channel::handoff_offer_live(commit.version, now) {
            if !commit.nominee.eq_ignore_ascii_case(&hex::encode(pk)) {
                return Err(publishing());
            }
            let db = state.db.clone();
            let id = channel_id.clone();
            tokio::task::spawn_blocking(move || db.restart_channel_handoff_commit(&id, now))
                .await
                .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
                .map_err(|e| coded_ctx("channels_handoff_failed", "Could not start transfer", e))?;
            return Ok(());
        }
        clear_channel_pending_handoff(&state, &channel_id).await?;
    }
    // `set_channel_pending_handoff` overwrites, so a second offer to a
    // different member would orphan the first and leave the room in an
    // ambiguous handoff. Re-offering to the same member stays allowed, since a
    // dropped gossip offer otherwise has no retry.
    let db = state.db.clone();
    let pending_id = channel_id.clone();
    let pending = tokio::task::spawn_blocking(move || db.channel_pending_handoff(&pending_id))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_handoff_failed", "Could not start transfer", e))?;
    if let Some((waiting_on, offered_at)) = pending {
        let lapsed = !channel::handoff_offer_live(offered_at, chrono::Utc::now().timestamp());
        if !lapsed && !waiting_on.eq_ignore_ascii_case(&hex::encode(pk)) {
            return Err(coded(
                "channels_handoff_pending",
                "A transfer to another member is already waiting to be accepted",
            ));
        }
    }
    let member_hex = hex::encode(pk);
    let db = state.db.clone();
    let id = channel_id.clone();
    let member_ok = tokio::task::spawn_blocking(move || {
        let members = db.list_channel_members(&id)?;
        Ok::<_, anyhow::Error>(members.into_iter().any(|m| {
            m.member_pubkey.eq_ignore_ascii_case(&member_hex) && !m.banned
        }))
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_handoff_failed", "Could not start transfer", e))?;
    if !member_ok {
        return Err(coded(
            "channels_member_invalid",
            "That member is not in this room",
        ));
    }
    let version = chrono::Utc::now().timestamp().max(1) as u64;
    let db = state.db.clone();
    let id = channel_id.clone();
    let member_hex = hex::encode(pk);
    tokio::task::spawn_blocking(move || {
        db.set_channel_pending_handoff(&id, &member_hex, version)
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_handoff_failed", "Could not start transfer", e))?;
    let Some(join_secret) = join_secret_for_channel(&state, &owned.row).await else {
        clear_channel_pending_handoff(&state, &channel_id).await?;
        return Err(coded(
            "channels_handoff_failed",
            "Could not start transfer",
        ));
    };
    let plain = channel::encode_channel_handoff_offer(
        &owned.ident.channel_id,
        &owned.ident.signing_key,
        &state.identity.ed25519_public_key,
        &pk,
        version,
    );
    if let Err(e) = enqueue_channel_gossip(&state, &channel_id, join_secret, plain) {
        clear_channel_pending_handoff(&state, &channel_id).await?;
        return Err(e);
    }
    Ok(())
}

async fn clear_channel_pending_handoff(
    state: &AppState,
    channel_id: &str,
) -> Result<(), String> {
    let db = state.db.clone();
    let id = channel_id.to_string();
    tokio::task::spawn_blocking(move || db.set_channel_pending_handoff(&id, "", 0))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| {
            coded_ctx(
                "channels_handoff_stuck",
                "A transfer is still marked pending on this room",
                e,
            )
        })?;
    Ok(())
}

/// The v2 friend code for a room member, so they can be added as a friend.
///
/// Channel members and friends are the same identity keyed two ways: a
/// friend's Ember hash is BLAKE3 of the Ed25519 key the room already shows us.
/// Deriving it here rather than in the UI keeps one implementation of that
/// binding, and hands `add_friend` a code whose pubkey it can verify instead
/// of a bare hash it would have to learn the key for later.
#[tauri::command]
pub async fn channel_member_friend_code(
    _state: tauri::State<'_, AppState>,
    member_pubkey: String,
) -> Result<String, String> {
    let pk = parse_member_pubkey(&member_pubkey)?;
    let hash = crypto::node_id_from_ed25519_bytes(&pk).ok_or_else(|| {
        coded("channels_member_invalid", "Invalid member key")
    })?;
    Ok(format!("ember2:{}:{}", hex::encode(hash), hex::encode(pk)))
}

/// Rooms one friend request is sent across when it goes through rooms.
const ROOM_FRIEND_REQUEST_ROOMS: usize = 2;

/// How long after the first ask through rooms the second waits. Each later one
/// waits twice as long as the one before: the friend retry sweep that repeats
/// them runs every few minutes, and each ask floods every room it goes through.
const ROOM_FRIEND_REQUEST_FIRST_GAP_SECS: i64 = 30 * 60;

/// Asks through rooms before that route is given up, some two and a half days
/// of them. A member who has not answered by then is not going to — and one
/// added from an older code may run a build that never reads the frame.
const ROOM_FRIEND_REQUEST_ATTEMPTS: i64 = 8;

/// Whether a friend asked through rooms `asks` times, the last at `asked_at`,
/// is due another ask at `now`.
fn room_friend_request_due(asks: i64, asked_at: i64, now: i64) -> bool {
    if asks <= 0 {
        return true;
    }
    if asks >= ROOM_FRIEND_REQUEST_ATTEMPTS {
        return false;
    }
    let gap = ROOM_FRIEND_REQUEST_FIRST_GAP_SECS.saturating_mul(1i64 << (asks - 1).min(30));
    now.saturating_sub(asked_at) >= gap
}

/// Ask `member` to be friends through the rooms we share with them. Returns
/// how many rooms the request went out through.
///
/// The friend rendezvous cannot find a member added from a room: a current
/// build publishes its presence only to its friends and to holders of its v3
/// code, and what a room shows is neither. The request travels as a room
/// frame instead (see `channel::encode_room_friend_request`), addressed so
/// that only the member can tell it is theirs and older builds ignore it. Once
/// they accept, both sides are keyed friends and pairwise presence connects
/// them as usual.
///
/// `asked_now` is the user adding them just now, which is never held back by
/// earlier attempts and starts their count again. Otherwise asks back off as
/// [`room_friend_request_due`] says, counted on the friend's row so a restart
/// does not start them over.
pub(crate) async fn send_room_friend_request(
    state: &AppState,
    member: [u8; 32],
    asked_now: bool,
) -> usize {
    let Some(hash) = crypto::node_id_from_ed25519_bytes(&member) else {
        return 0;
    };
    if member == state.identity.ed25519_public_key
        || state.db.chat_locked()
        || require_ember(state).await.is_err()
    {
        return 0;
    }
    let now = chrono::Utc::now().timestamp();
    let hash_hex = hex::encode(hash);
    let db = state.db.clone();
    let lookup_hash = hash_hex.clone();
    let member_hex = hex::encode(member);
    let our_hex = hex::encode(state.identity.ed25519_public_key);
    let due = tokio::task::spawn_blocking(move || {
        let asks = if asked_now {
            0
        } else {
            match db.room_friend_request_asks(&lookup_hash) {
                Ok(Some((asks, asked_at))) if room_friend_request_due(asks, asked_at, now) => asks,
                _ => return None,
            }
        };
        let rooms = db
            .rooms_shared_with(&member_hex, &our_hex, ROOM_FRIEND_REQUEST_ROOMS)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|id| db.get_channel_lite(&id).ok().flatten())
            .collect::<Vec<_>>();
        Some((asks, rooms))
    })
    .await
    .ok()
    .flatten();
    let Some((asks, rooms)) = due else {
        return 0;
    };
    let seed = state.identity.ed25519_secret_key;
    let our_pk = state.identity.ed25519_public_key;
    let signing = crypto::signing_key_from_bytes(&seed);
    let mut sent = 0;
    for row in rooms {
        let Ok(channel_id) = channel_id_bytes(&row.channel_id) else {
            continue;
        };
        let Some(join_secret) = join_secret_for_channel(state, &row).await else {
            continue;
        };
        let mut msg_id = [0u8; 16];
        OsRng.fill_bytes(&mut msg_id);
        let Some(tag) = channel::room_friend_request_tag(&seed, &member, &channel_id, &msg_id)
        else {
            continue;
        };
        let ts = chrono::Utc::now().timestamp();
        let plain =
            channel::encode_room_friend_request(&signing, &our_pk, &tag, &channel_id, &msg_id, ts);
        let gossip = channel::ChannelGossip::sealed(
            channel_id,
            msg_id,
            &channel::content_key(&join_secret),
            ts.max(0) as u64,
            &plain,
            channel::CHANNEL_MSG_TTL_DEFAULT,
            ts,
        );
        if state
            .network_tx
            .try_send(NetworkCommand::FanoutChannelGossip {
                body: gossip.encode(),
            })
            .is_ok()
        {
            sent += 1;
        }
    }
    // Only an ask that went somewhere counts, so a friend we share no room with
    // yet is asked as soon as we do.
    if sent > 0 {
        let db = state.db.clone();
        let recorded = tokio::task::spawn_blocking(move || {
            db.set_room_friend_request_asks(&hash_hex, asks + 1, now)
        })
        .await;
        if let Ok(Err(e)) = recorded {
            tracing::debug!("Could not record a friend request sent through rooms: {e}");
        }
    }
    sent
}

#[cfg(test)]
mod room_friend_request_backoff_tests {
    use super::{
        room_friend_request_due, ROOM_FRIEND_REQUEST_ATTEMPTS, ROOM_FRIEND_REQUEST_FIRST_GAP_SECS,
    };

    /// Each ask through rooms waits twice as long as the last, and after the
    /// last attempt none follows.
    #[test]
    fn asks_through_rooms_back_off_and_then_stop() {
        let at = 1_700_000_000;
        let gap = ROOM_FRIEND_REQUEST_FIRST_GAP_SECS;
        assert!(room_friend_request_due(0, 0, at));
        assert!(!room_friend_request_due(1, at, at + gap - 1));
        assert!(room_friend_request_due(1, at, at + gap));
        assert!(!room_friend_request_due(2, at, at + gap));
        assert!(room_friend_request_due(2, at, at + 2 * gap));
        assert!(room_friend_request_due(3, at, at + 4 * gap));
        assert!(!room_friend_request_due(ROOM_FRIEND_REQUEST_ATTEMPTS, at, i64::MAX));
    }
}

// --- Ember Transfer -------------------------------------------------------

/// Offer a file to one member of a room.
///
/// Nothing leaves this machine until they accept. The file is hashed here
/// rather than in the network task so a 2 GiB read never stalls the loop
/// that is also carrying everyone's chat.
///
/// The file is chosen in a native dialog *here* rather than accepted as a path
/// from the renderer, for the same reason as `pick_and_load_collection` and
/// `pick_and_import_ipfilter_file`: picking a file in the OS dialog is the
/// user's authorization, a path arriving over IPC is not. This command reads
/// whatever it is handed and sends it to another person, and it is not scoped
/// to the shared roots — so a renderer-supplied path meant any readable file
/// (identity material, documents) could be exfiltrated to a room member, and
/// on Windows a UNC path would additionally have been dialled by
/// `canonicalize`.
///
/// `Ok(None)` means the user dismissed the picker.
#[tauri::command]
pub async fn pick_and_offer_channel_transfer(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    channel_id: String,
    member_pubkey: String,
    title: Option<String>,
) -> Result<Option<String>, String> {
    let dialog_title = super::picker_title(title, "Choose a file to send");
    require_ember(&state).await?;
    let channel_id = parse_channel_id(&channel_id)?;
    let peer = parse_member_pubkey(&member_pubkey)?;
    if peer == state.identity.ed25519_public_key {
        return Err(coded(
            "channels_xfer_self",
            "You cannot send a file to yourself",
        ));
    }

    let row = load_joined_channel(&state, &channel_id).await?;
    if self_banned_from(&state, &row, "channels_xfer_failed").await? {
        return Err(coded(
            "channels_banned",
            "You are banned from this channel",
        ));
    }
    // The recipient has to be someone the room can currently see, or the
    // offer has nowhere to go and would sit "offered" until it lapsed.
    let db = state.db.clone();
    let id = channel_id.clone();
    let peer_hex = hex::encode(peer);
    let known = tokio::task::spawn_blocking(move || db.list_channel_members(&id))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_xfer_failed", "Could not check the member list", e))?
        .into_iter()
        .any(|m| m.member_pubkey.eq_ignore_ascii_case(&peer_hex) && !m.banned);
    if !known {
        return Err(coded(
            "channels_xfer_no_member",
            "That member is not in this channel",
        ));
    }

    // Only prompt once the offer is known to have somewhere to go, so a
    // dismissed dialog is the only reason this returns `Ok(None)`.
    let picker = app.clone();
    let picked = tokio::task::spawn_blocking(move || {
        picker
            .dialog()
            .file()
            .set_title(dialog_title)
            .blocking_pick_file()
            .map(|file| {
                file.into_path()
                    .map_err(|e| coded_ctx("channels_xfer_failed", "Invalid file path", e))
            })
            .transpose()
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))??;
    let Some(picked) = picked else {
        return Ok(None);
    };

    let prepared = tokio::task::spawn_blocking(move || {
        let canonical = picked
            .canonicalize()
            .map_err(|e| coded_ctx("channels_xfer_failed", "Cannot open that file", e))?;
        if !canonical.is_file() {
            return Err(coded("channels_xfer_failed", "That is not a file"));
        }
        crate::security::filesystem::ensure_not_reparse(&canonical)
            .map_err(|e| coded_ctx("channels_xfer_failed", "Cannot open that file", e))?;
        let meta = std::fs::metadata(&canonical)
            .map_err(|e| coded_ctx("channels_xfer_failed", "Cannot open that file", e))?;
        if meta.len() == 0 || meta.len() > channel::XFER_MAX_BYTES {
            return Err(coded_ctx(
                "channels_xfer_too_large",
                "Files must be between 1 byte and 2 GB",
                channel::XFER_MAX_BYTES,
            ));
        }
        // Clamped here, keeping the extension, rather than cut from the end by
        // the wire encoder, so the recipient saves the same name the sender's
        // UI shows.
        let name = super::chat_attachments::clamp_file_name_keep_extension(
            &crate::security::sanitize_filename(
                canonical
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("file"),
            ),
            channel::XFER_NAME_MAX,
        );
        if name.is_empty() {
            return Err(coded(
                "channels_xfer_failed",
                "That file name is not allowed",
            ));
        }
        // Cached for the QUIC stream that will serve it, so a 2 GiB file is
        // read once here rather than again when the recipient connects.
        let tree = crate::network::ember::attach_stream::hash_for_serving(&canonical)
            .map_err(|e| coded_ctx("channels_xfer_failed", "Could not read that file", e))?;
        if tree.file_size != meta.len() {
            return Err(coded(
                "channels_xfer_failed",
                "That file changed while it was being prepared",
            ));
        }
        Ok((canonical, name, meta.len(), tree))
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))??;
    let (canonical, name, size, tree) = prepared;

    let mut channel_id_bytes = [0u8; 16];
    hex::decode_to_slice(&channel_id, &mut channel_id_bytes)
        .map_err(|_| coded("channels_not_found", "Channel not found"))?;
    let mut xfer_id = [0u8; 16];
    OsRng.fill_bytes(&mut xfer_id);

    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::OfferChannelTransfer {
            channel_id: channel_id_bytes,
            peer,
            xfer_id,
            path: canonical,
            name,
            size,
            root: tree.root_hash,
            tx,
        })
        .map_err(|_| coded("channels_xfer_failed", "Network is busy"))?;
    await_reply(rx, "channels_xfer_failed", "No response from network").await??;
    Ok(Some(hex::encode(xfer_id)))
}

/// Accept or decline an offer someone made you.
#[tauri::command]
pub async fn respond_channel_transfer(
    state: tauri::State<'_, AppState>,
    xfer_id: String,
    accept: bool,
) -> Result<(), String> {
    require_ember(&state).await?;
    let xfer_id = parse_xfer_id(&xfer_id)?;
    let download_folder = {
        let config = state.config.read().await;
        std::path::PathBuf::from(&config.settings.download_folder)
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::RespondChannelTransfer {
            xfer_id,
            accept,
            download_folder,
            tx,
        })
        .map_err(|_| coded("channels_xfer_failed", "Network is busy"))?;
    await_reply(rx, "channels_xfer_failed", "No response from network").await??;
    Ok(())
}

/// Stop a transfer in either direction, and tell the other end.
#[tauri::command]
pub async fn cancel_channel_transfer(
    state: tauri::State<'_, AppState>,
    xfer_id: String,
) -> Result<(), String> {
    require_ember(&state).await?;
    let xfer_id = parse_xfer_id(&xfer_id)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::CancelChannelTransfer { xfer_id, tx })
        .map_err(|_| coded("channels_xfer_failed", "Network is busy"))?;
    await_reply(rx, "channels_xfer_failed", "No response from network").await??;
    Ok(())
}

/// Send the standard offer for a file you offered whose recipient has not
/// answered the private one. Every member it is forwarded through can read the
/// file's name and size, so this only runs when the user asks for it.
#[tauri::command]
pub async fn send_channel_transfer_standard_offer(
    state: tauri::State<'_, AppState>,
    xfer_id: String,
) -> Result<(), String> {
    require_ember(&state).await?;
    let xfer_id = parse_xfer_id(&xfer_id)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::SendChannelTransferPlainOffer { xfer_id, tx })
        .map_err(|_| coded("channels_xfer_failed", "Network is busy"))?;
    await_reply(rx, "channels_xfer_failed", "No response from network").await??;
    Ok(())
}

/// Open the Channel Files folder, creating it if nothing has landed there yet.
#[tauri::command]
pub async fn open_channel_files_folder(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let dl_folder = state.config.read().await.settings.download_folder.clone();
    tokio::task::spawn_blocking(move || {
        let allowed = vec![dl_folder.clone()];
        let dir = crate::security::filesystem::prepare_approved_subdir(
            std::path::Path::new(&dl_folder),
            crate::network::ember::xfer::CHANNEL_FILES_DIR,
            &allowed,
        )
        .map_err(|e| coded_ctx("transfers_invalid_path", "Invalid or changed download path", e))?;
        crate::security::filesystem::open_with_default_app(&dir).map_err(|e| {
            coded_ctx(
                "transfers_open_explorer_failed",
                "Failed to open the Channel Files folder",
                e,
            )
        })
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
}

/// Everything currently offered, awaiting an answer, or moving.
#[tauri::command]
pub async fn list_channel_transfers(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<crate::network::ChannelTransferSnapshot>, String> {
    if !state.config.read().await.settings.ember_native_enabled {
        return Ok(Vec::new());
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    // An empty list here used to mean two different things: "nothing is in
    // flight" and "the network task did not answer". The second one made live
    // transfers disappear from the room instead of reporting a fault, and the
    // bare `rx.await` could park this command forever. Every other channel
    // command bounds both halves; so does this one now.
    state
        .network_tx
        .try_send(NetworkCommand::ListChannelTransfers { tx })
        .map_err(|_| coded("channels_xfer_failed", "Network is busy"))?;
    await_reply(rx, "channels_xfer_failed", "No response from network").await
}

fn parse_xfer_id(hex_str: &str) -> Result<[u8; 16], String> {
    let canonical = hex_str.trim().to_ascii_lowercase();
    let bytes = hex::decode(&canonical)
        .map_err(|_| coded("channels_xfer_not_found", "Invalid transfer id"))?;
    <[u8; 16]>::try_from(bytes.as_slice())
        .map_err(|_| coded("channels_xfer_not_found", "Invalid transfer id"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In an announcement-only room the owner and the snapshot's moderators
    /// send; everyone else is refused before anything goes on the wire. A room
    /// without the flag refuses nobody.
    #[test]
    fn announce_only_rooms_refuse_everyone_but_the_owner_and_moderators() {
        let path = std::env::temp_dir().join(format!(
            "ember-announce-send-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let member_room = "ab".repeat(16);
        let owned_room = "cd".repeat(16);
        db.insert_channel(&member_room, &"01".repeat(32), "News", "public", false, None, None)
            .expect("insert member room");
        db.insert_channel(&owned_room, &"02".repeat(32), "Mine", "public", true, None, None)
            .expect("insert owned room");
        let moderator = [0x5Au8; 32];
        let member = hex::encode([0x6Bu8; 32]);
        assert!(db
            .apply_channel_moderation(
                &member_room, "", "", 1, &[], &[moderator], None, None, None, None, None, None,
            )
            .unwrap());

        let row = db.get_channel(&member_room).unwrap().unwrap();
        assert!(!announce_only_refuses(&db, &row, &member), "open room");

        db.apply_owner_room_policy(&member_room, true, &[], None).unwrap();
        let row = db.get_channel(&member_room).unwrap().unwrap();
        assert!(announce_only_refuses(&db, &row, &member), "a member is refused");
        assert!(
            !announce_only_refuses(&db, &row, &hex::encode(moderator)),
            "a moderator posts"
        );

        db.apply_owner_room_policy(&owned_room, true, &[], None).unwrap();
        let owned = db.get_channel(&owned_room).unwrap().unwrap();
        assert!(!announce_only_refuses(&db, &owned, &member), "the owner posts");

        // A moderator the next snapshot drops is refused from then on.
        assert!(db
            .apply_channel_moderation(
                &member_room, "", "", 2, &[], &[], None, None, None, None, None, None,
            )
            .unwrap());
        let row = db.get_channel(&member_room).unwrap().unwrap();
        assert!(announce_only_refuses(&db, &row, &hex::encode(moderator)));

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn pinning_adds_unpinning_removes_and_the_cap_refuses() {
        let a = "aa".repeat(16);
        let b = "bb".repeat(16);
        let c = "cc".repeat(16);
        let d = "dd".repeat(16);
        assert_eq!(next_pins(&[], &a, true).unwrap(), Some(vec![a.clone()]));
        assert_eq!(next_pins(std::slice::from_ref(&a), &a, true).unwrap(), None, "already pinned");
        assert_eq!(next_pins(std::slice::from_ref(&a), &b, false).unwrap(), None, "not pinned");
        assert_eq!(
            next_pins(&[a.clone(), b.clone()], &a, false).unwrap(),
            Some(vec![b.clone()])
        );
        let full = vec![a.clone(), b.clone(), c.clone()];
        assert_eq!(full.len(), CHANNEL_PIN_MAX);
        let err = next_pins(&full, &d, true).unwrap_err();
        assert!(err.contains("channels_pins_full"), "{err}");
        // Unpinning from a full list is always allowed.
        assert_eq!(next_pins(&full, &b, false).unwrap(), Some(vec![a, c]));
    }

    #[test]
    fn channel_username_rejects_anonymous_and_out_of_range() {
        assert!(sanitize_channel_username("A").is_err());
        assert!(sanitize_channel_username("Anonymous").is_err());
        assert!(sanitize_channel_username("Ada Lovelace").is_err());
        assert!(sanitize_channel_username("Ada_1").is_err());
        assert!(sanitize_channel_username(&"x".repeat(13)).is_err());
        assert_eq!(sanitize_channel_username("Ada").unwrap(), "Ada");
        assert_eq!(sanitize_channel_username("Ada1").unwrap(), "Ada1");
        assert_eq!(username_claim_key("Ada"), "ada");
    }

    #[test]
    fn a_room_name_may_run_to_32_characters_within_64_bytes() {
        assert!(sanitize_channel_name(&"a".repeat(32)).is_ok());
        assert!(sanitize_channel_name(&"a".repeat(33)).is_err());
        // Two bytes a character: the character cap is the one that binds.
        assert!(sanitize_channel_name(&"ж".repeat(32)).is_ok());
        // Three bytes a character: the record's byte ceiling binds first.
        assert!(sanitize_channel_name(&"房".repeat(21)).is_ok());
        assert!(sanitize_channel_name(&"房".repeat(22)).is_err());
    }

    /// Discover names come from whoever published the record, which is the one
    /// route into the room list that does not go through `accept_invite`.
    #[test]
    fn discovered_room_names_are_trimmed_like_invited_ones() {
        let id = "ab".repeat(16);

        assert_eq!(discovered_room_name("Lobby", &id), "Lobby");

        // Capped at the same length the compose form and invites enforce.
        let long = "x".repeat(200);
        assert_eq!(
            discovered_room_name(&long, &id).chars().count(),
            MAX_CHANNEL_NAME_CHARS
        );

        // Zero-width and bidi controls are what make one room's label
        // indistinguishable from another's.
        let spoof = "Lo\u{200B}bby\u{202E}";
        assert_eq!(discovered_room_name(spoof, &id), "Lobby");

        // Nothing left to draw falls back to the short id, which is what a
        // room that never had a name already shows.
        assert_eq!(discovered_room_name("\u{200B}\u{FEFF}", &id), &id[..8]);
        assert_eq!(discovered_room_name("", &id), &id[..8]);
    }

    fn listing(id: &str, name: &str, language: &str) -> GatheredChannelInfo {
        GatheredChannelInfo {
            channel_id: id.to_string(),
            pubkey: "00".repeat(32),
            name: name.to_string(),
            private: false,
            joined: false,
            member_count: None,
            language: language.to_string(),
        }
    }

    /// The directory row comes first and carries no language; the room's own
    /// signed listing fills it in, the newest generation wins, and a stale one
    /// a slow storer still holds changes nothing.
    #[test]
    fn signed_listings_bring_the_language_and_the_newest_one_wins() {
        let id = "ab".repeat(16);
        let mut out = vec![listing(&id, "Registry Name", "")];
        let mut signed_at =
            std::collections::HashMap::from([(id.clone(), (0usize, None, true))]);

        let row = merge_signed_listing(&mut out, &mut signed_at, listing(&id, "Signed", "de"), 100)
            .expect("the language is news");
        assert_eq!(row.language, "de");
        assert_eq!(row.name, "Registry Name", "the registry keeps the name");

        assert!(
            merge_signed_listing(&mut out, &mut signed_at, listing(&id, "Old", ""), 50).is_none(),
            "an older generation is ignored"
        );
        assert_eq!(out[0].language, "de");

        let row = merge_signed_listing(&mut out, &mut signed_at, listing(&id, "Renamed", "fr"), 200)
            .expect("a newer generation replaces the language");
        assert_eq!(
            (row.name.as_str(), row.language.as_str()),
            ("Registry Name", "fr"),
            "whatever order storers answer in, the registry keeps the name"
        );

        // A room only the DHT knows: the newest signed listing names it.
        let other = "cd".repeat(16);
        let row = merge_signed_listing(&mut out, &mut signed_at, listing(&other, "New", "ja"), 10)
            .expect("a room only the DHT knows is added");
        assert_eq!(row.language, "ja");
        assert_eq!(out.len(), 2);
        let row = merge_signed_listing(&mut out, &mut signed_at, listing(&other, "Newer", ""), 20)
            .expect("its newer listing replaces it");
        assert_eq!((row.name.as_str(), row.language.as_str()), ("Newer", ""));
    }

    /// Only an index record — signed by the room's own key — is a listing. A
    /// presence record anyone can sign, filed in the room's shard, must not
    /// pass as one and put its name and language on the room.
    #[test]
    fn a_planted_presence_record_is_not_a_listing() {
        let room = ChannelIdentity::generate();
        let index = SignedRecord::channel_index(
            "Lobby", room.channel_id, room.pubkey, false, Some("de"), &room.signing_key,
        );
        let stranger = crypto::signing_key_from_bytes(&[0x77u8; 32]);
        let planted = SignedRecord::channel_presence(
            "Fake", room.channel_id, room.pubkey, &[0u8; 32], false, 0, &[0u8; 32], &stranger,
        );
        assert!(planted.channel_store_ok(), "storers accept it, which is the problem");
        let blob = |r: &SignedRecord| [r.data.clone(), r.signature.to_vec()].concat();

        let found = listings_from_blobs(
            vec![blob(&planted), blob(&index)],
            &std::collections::HashSet::new(),
        );
        assert_eq!(found.len(), 1, "only the room's own listing is read");
        assert_eq!(found[0].0.name, "Lobby");
        assert_eq!(found[0].0.language, "de");
    }

    fn reaction_row(msg: &str, member: &str, reaction: u8) -> (String, String, u8) {
        (msg.to_string(), member.to_string(), reaction)
    }

    #[test]
    fn reaction_tallies_count_mixed_codes_in_code_order_with_me_named_first() {
        let me = "cd".repeat(32);
        let rows = vec![
            reaction_row("m1", "ada", 8),
            reaction_row("m1", "bo", channel::REACTION_UP),
            reaction_row("m1", "cy", 8),
            reaction_row("m1", &me.to_ascii_uppercase(), 8),
            reaction_row("m1", "di", channel::REACTION_CURATED_MAX),
            reaction_row("m2", "ada", channel::REACTION_HEART),
        ];
        let tallies = tally_channel_reactions(rows, &me);
        assert_eq!(
            tallies,
            vec![
                ChannelReactionInfo {
                    msg_id: "m1".into(),
                    reactions: vec![
                        ChannelReactionTally {
                            reaction: channel::REACTION_UP,
                            count: 1,
                            members: vec!["bo".into()],
                        },
                        ChannelReactionTally {
                            reaction: 8,
                            count: 3,
                            members: vec![me.to_ascii_uppercase(), "ada".into(), "cy".into()],
                        },
                        ChannelReactionTally {
                            reaction: channel::REACTION_CURATED_MAX,
                            count: 1,
                            members: vec!["di".into()],
                        },
                    ],
                    mine: 8,
                },
                ChannelReactionInfo {
                    msg_id: "m2".into(),
                    reactions: vec![ChannelReactionTally {
                        reaction: channel::REACTION_HEART,
                        count: 1,
                        members: vec!["ada".into()],
                    }],
                    mine: channel::REACTION_NONE,
                },
            ]
        );
    }

    #[test]
    fn reaction_tallies_skip_codes_past_the_curated_set() {
        let me = "cd".repeat(32);
        let future = channel::REACTION_CURATED_MAX + 1;
        let rows = vec![
            reaction_row("m1", "ada", future),
            reaction_row("m1", "bo", channel::REACTION_DOWN),
            reaction_row("m2", "ada", u8::MAX),
        ];
        let tallies = tally_channel_reactions(rows, &me);
        // Not folded into any drawn code, and a line holding nothing drawable
        // has no tally, so it renders as a line nobody reacted to.
        assert_eq!(tallies.len(), 1);
        assert_eq!(tallies[0].msg_id, "m1");
        assert_eq!(
            tallies[0].reactions,
            vec![ChannelReactionTally {
                reaction: channel::REACTION_DOWN,
                count: 1,
                members: vec!["bo".into()],
            }]
        );
    }

    #[test]
    fn reaction_members_are_capped_but_the_count_is_not() {
        let me = "cd".repeat(32);
        let mut rows: Vec<_> = (0..REACTION_MEMBERS_SHOWN + 4)
            .map(|i| reaction_row("m1", &format!("member{i}"), channel::REACTION_UP))
            .collect();
        // Reacted last, so without the rule it would fall past the cap.
        rows.push(reaction_row("m1", &me, channel::REACTION_UP));
        let tallies = tally_channel_reactions(rows, &me);
        let tally = &tallies[0].reactions[0];
        assert_eq!(tally.count as usize, REACTION_MEMBERS_SHOWN + 5);
        assert_eq!(tally.members.len(), REACTION_MEMBERS_SHOWN);
        assert_eq!(tally.members[0], me);
        assert_eq!(tally.members[1], "member0");
    }

    /// `get_channel_reactions`' tally exactly as v1.6.7 shipped it
    /// (`git show v1.6.7:src-tauri/src/commands/channels.rs`), so the property
    /// released builds depend on is checked against their logic rather than
    /// against a description of it.
    fn v1_6_7_tally(rows: Vec<(String, String, u8)>, mine: &str) -> Vec<(String, u32, u32, u32, u8)> {
        struct Info {
            msg_id: String,
            up: u32,
            down: u32,
            heart: u32,
            mine: u8,
        }
        let mut tallies: std::collections::HashMap<String, Info> = std::collections::HashMap::new();
        for (msg_id, member, reaction) in rows {
            let entry = tallies.entry(msg_id.clone()).or_insert_with(|| Info {
                msg_id,
                up: 0,
                down: 0,
                heart: 0,
                mine: 0,
            });
            match reaction {
                1 => entry.up = entry.up.saturating_add(1),
                2 => entry.down = entry.down.saturating_add(1),
                3 => entry.heart = entry.heart.saturating_add(1),
                _ => {}
            }
            if member.eq_ignore_ascii_case(mine) {
                entry.mine = reaction;
            }
        }
        let mut out: Vec<_> = tallies
            .into_values()
            .map(|t| (t.msg_id, t.up, t.down, t.heart, t.mine))
            .collect();
        out.sort();
        out
    }

    #[test]
    fn a_v1_6_build_ignores_every_new_code_rather_than_misreading_it() {
        use ed25519_dalek::SigningKey;

        // The reaction frame, its signature and its decoder are unchanged since
        // v1.6.7, so running the current decoder is running theirs.
        let channel_id = [7u8; 16];
        let target = [9u8; 16];
        let entries: Vec<channel::ChannelReaction> = (channel::REACTION_UP
            ..=channel::REACTION_CURATED_MAX)
            .map(|code| {
                let sk = SigningKey::from_bytes(&[code; 32]);
                let member = sk.verifying_key().to_bytes();
                let reacted_at = 1_700_000_000 + i64::from(code);
                channel::ChannelReaction {
                    target_msg_id: target,
                    member,
                    reaction: code,
                    reacted_at,
                    signature: channel::reaction_signature(
                        &sk,
                        &member,
                        &channel_id,
                        &target,
                        reacted_at,
                        code,
                    ),
                }
            })
            .collect();
        let frame = channel::encode_channel_reactions(&entries);
        let decoded = channel::decode_channel_reactions(&frame, &channel_id)
            .expect("the frame must not be dropped whole");
        assert_eq!(decoded.len(), entries.len(), "no entry may fail its signature");

        let rows: Vec<_> = decoded
            .iter()
            .map(|e| (hex::encode(e.target_msg_id), hex::encode(e.member), e.reaction))
            .collect();
        let old = v1_6_7_tally(rows.clone(), "");
        // One member each on 👍, 👎 and ❤️; the seventeen new codes add to none.
        assert_eq!(old, vec![(hex::encode(target), 1, 1, 1, 0)]);

        // And only new codes: counts all zero, which v1.6.7's `hasAny` reads as
        // a line with no reactions, drawing nothing rather than a wrong mark.
        let only_new: Vec<_> = rows.into_iter().filter(|(_, _, code)| *code > 3).collect();
        assert_eq!(v1_6_7_tally(only_new.clone(), ""), vec![(hex::encode(target), 0, 0, 0, 0)]);

        // This build counts each of them under its own code.
        let new = tally_channel_reactions(only_new, "");
        let codes: Vec<u8> = new[0].reactions.iter().map(|t| t.reaction).collect();
        assert_eq!(codes, (4..=channel::REACTION_CURATED_MAX).collect::<Vec<_>>());
    }
}

