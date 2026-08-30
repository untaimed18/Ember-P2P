//! Ember Channels: create, join, list, and local chat.
//!
//! DHT publish/search is forwarded to the network task. Channel peers are
//! never added to `friend_hashes`.

use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::RngCore;
use tauri::Emitter;

use crate::app_state::AppState;
use crate::commands::errors::{await_reply, coded, coded_ctx};
use crate::network::ember::channel::{
    self, ChannelIdentity, ChannelInvite, CHANNEL_KIND_PRIVATE, CHANNEL_KIND_PUBLIC,
};
use crate::network::ember::dht::publish::{
    ModerationTail, SignedRecord, CHANNEL_BAN_LIST_MAX, CHANNEL_MOD_LIST_MAX, CHANNEL_NAME_MAX,
    CHANNEL_WELCOME_MAX,
};
use crate::network::ember::crypto;
use crate::network::{EmberPublishPending, EmberPublishResult, NetworkCommand};
use crate::storage::database::{ChannelEditOutcome, StoredChannel, StoredChannelMember};

/// Room names are bounded by what a directory row can show rather than by what
/// the record could carry: twenty characters fit the list at every width the
/// page uses, so a name reaches other members intact instead of ellipsised.
/// Counted in characters, not bytes — a byte cap of this size would leave a
/// CJK name six characters to work with.
const MAX_CHANNEL_NAME_CHARS: usize = 20;

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
/// says. Twenty astral emoji satisfy the character cap and still overrun this.
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
    pub member_count: i64,
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
}

impl ChannelMemberInfo {
    fn from_stored(row: StoredChannelMember, is_self: bool) -> Self {
        Self {
            member_pubkey: row.member_pubkey,
            nickname: row.nickname,
            last_seen: row.last_seen,
            banned: row.banned,
            is_self,
            moderator: row.moderator,
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
}

impl From<crate::storage::database::ChannelMessageRow> for ChannelMessageInfo {
    fn from(row: crate::storage::database::ChannelMessageRow) -> Self {
        Self {
            id: row.id,
            sender_pubkey: row.sender_pubkey,
            direction: row.direction,
            message: row.message,
            timestamp: row.timestamp,
            read: row.read,
            edited_at: row.edited_at,
            msg_id: row.msg_id,
        }
    }
}

/// Reaction tally for one line, as the UI draws it.
#[derive(serde::Serialize)]
pub struct ChannelReactionInfo {
    pub msg_id: String,
    pub up: u32,
    pub down: u32,
    pub heart: u32,
    /// This device's own reaction, so the button can show as pressed. 0 is none.
    pub mine: u8,
}

#[derive(serde::Serialize)]
pub struct ChannelInviteInfo {
    pub uri: String,
    pub channel_id: String,
    pub name: String,
    pub private: bool,
}

#[derive(serde::Serialize)]
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
            settings: new_settings,
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
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            // Not `unwrap_or(false)`: reporting a banned member as unbanned
            // hands them a composer whose sends every peer will drop. Owners
            // are exempt for the reasons in `self_banned_from`.
            let you_are_banned =
                !row.is_owner && db.channel_member_is_banned(&row.channel_id, &our_pk)?;
            let you_are_moderator = db.channel_member_is_moderator(&row.channel_id, &our_pk)?;
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
) -> Result<ChannelInviteInfo, String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to create a channel",
        ));
    }
    let name = sanitize_channel_name(&name)?;
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
        db.insert_channel(
            &db_id,
            &db_pk,
            &db_name,
            visibility,
            true,
            Some(&seed),
            if private { Some(&join_secret) } else { None },
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
    let moderation = SignedRecord::channel_moderation(
        "",
        "",
        &[],
        &[],
        // Names us as owner from the very first record, so a member who joins
        // before any moderation edit already knows who cannot be banned.
        &ModerationTail {
            owner_pubkey: Some(state.identity.ed25519_public_key),
            key_epoch: Some(0),
            ..Default::default()
        },
        ident.channel_id,
        ident.pubkey,
        private,
        &ident.signing_key,
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
            // Older than any real DHT record so the first fetch still applies.
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
        let _ = tokio::task::spawn_blocking(move || db.set_channel_in_room(&id, false)).await;
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
    Ok(rows.into_iter().map(ChannelMessageInfo::from).collect())
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
    Ok(rows.into_iter().map(ChannelMessageInfo::from).collect())
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
    let cleaned = crate::security::sanitize_chat_text(&message);
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
    let edit_sig = channel::edit_author_signature(
        &crypto::signing_key_from_bytes(&state.identity.ed25519_secret_key),
        &sender_pk,
        &channel_id_bytes,
        &msg_id_bytes,
        target.timestamp,
        edited_at,
        &cleaned,
    );

    // Local first: a revision the user can see is worth more than one that only
    // left the host, and the flood below is best-effort by nature.
    let db = state.db.clone();
    let id_for_edit = channel_id.clone();
    let msg_id_for_edit = target.msg_id.clone();
    let sender_for_edit = sender.clone();
    let text_for_edit = cleaned.clone();
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
    }

    let plain = channel::encode_channel_chat_edit_presigned(
        &sender_pk,
        &msg_id_bytes,
        target.timestamp,
        edited_at,
        &edit_sig,
        &cleaned,
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
    // Best effort past this point: the edit is already on disk here, and a busy
    // network task must not make the user think it was refused.
    if let Err(e) = state
        .network_tx
        .try_send(NetworkCommand::FanoutChannelGossip {
            body: gossip.encode(),
        })
    {
        tracing::warn!("Channel edit saved locally but not flooded: {e}");
    }
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

    Ok(ChannelMessageInfo {
        id: message_id,
        sender_pubkey: sender,
        direction: target.direction,
        message: cleaned,
        timestamp: target.timestamp,
        read: true,
        edited_at,
        msg_id: target.msg_id,
    })
}

/// Set or clear this device's reaction to one line.
///
/// `reaction` is [`channel::REACTION_NONE`] to take a reaction back,
/// [`channel::REACTION_UP`], [`channel::REACTION_DOWN`], or
/// [`channel::REACTION_HEART`]. Clearing is stored rather than deleted, because
/// the row carries the timestamp that stops a stale frame reasserting what was
/// withdrawn.
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
    if reaction > channel::REACTION_HEART {
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
    if let Err(e) = state
        .network_tx
        .try_send(NetworkCommand::FanoutChannelGossip {
            body: gossip.encode(),
        })
    {
        tracing::warn!("Channel reaction saved locally but not flooded: {e}");
    }
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
    let mut tallies: std::collections::HashMap<String, ChannelReactionInfo> =
        std::collections::HashMap::new();
    for (msg_id, member, reaction) in rows {
        let entry = tallies
            .entry(msg_id.clone())
            .or_insert_with(|| ChannelReactionInfo {
                msg_id,
                up: 0,
                down: 0,
                heart: 0,
                mine: channel::REACTION_NONE,
            });
        match reaction {
            channel::REACTION_UP => entry.up = entry.up.saturating_add(1),
            channel::REACTION_DOWN => entry.down = entry.down.saturating_add(1),
            channel::REACTION_HEART => entry.heart = entry.heart.saturating_add(1),
            // A reaction a newer build drew and this one does not. Counted
            // nowhere rather than lumped in with a mark it is not.
            _ => {}
        }
        if member.eq_ignore_ascii_case(&mine) {
            entry.mine = reaction;
        }
    }
    Ok(tallies.into_values().collect())
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

#[tauri::command]
pub async fn send_channel_message(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    message: String,
) -> Result<ChannelMessageInfo, String> {
    require_ember(&state).await?;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to send",
        ));
    }
    let cleaned = crate::security::sanitize_chat_text(&message);
    if cleaned.is_empty() || cleaned.len() > MAX_CHANNEL_MESSAGE {
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
    let mut msg_id = [0u8; 16];
    OsRng.fill_bytes(&mut msg_id);
    let sender_pk = state.identity.ed25519_public_key;
    let sent_at = chrono::Utc::now().timestamp();
    let author_sig = channel::chat_author_signature(
        &crypto::signing_key_from_bytes(&state.identity.ed25519_secret_key),
        &sender_pk,
        &channel_id_bytes,
        &msg_id,
        sent_at,
        &cleaned,
    );
    let key = channel::content_key(&join_secret);
    let plain = channel::encode_channel_chat_plain_presigned(&sender_pk, &author_sig, &cleaned);
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
    let text = cleaned.clone();
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
        let _ = tokio::task::spawn_blocking(move || db.delete_channel_message(&id, row_id)).await;
        refund_local_send(&channel_id);
        return Err(coded_ctx("network_busy", "Network busy", e));
    }

    Ok(ChannelMessageInfo {
        id: row_id,
        sender_pubkey: sender,
        direction: "sent".into(),
        message: cleaned,
        timestamp: sent_at,
        read: true,
        edited_at: 0,
        msg_id: hex::encode(msg_id),
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
    let private = owned.row.visibility == CHANNEL_KIND_PRIVATE;
    // We are the owner on this path, so our identity is what every member needs
    // in order to refuse a moderator's ban aimed at us, and our epoch is how
    // they tell they are behind and go looking for the key sealed to them.
    let our_pk = state.identity.ed25519_public_key;
    // Re-read rather than trusting `owned.row`: a ban rotates the key before
    // committing, so the snapshot in hand is one epoch stale and members would
    // never learn to go looking for the new one.
    let live_epoch = {
        let db = state.db.clone();
        let id = owned.row.channel_id.clone();
        tokio::task::spawn_blocking(move || db.get_channel(&id))
            .await
            .ok()
            .and_then(|r| r.ok())
            .flatten()
            .map(|row| row.key_epoch)
            .unwrap_or(owned.row.key_epoch)
    };
    let tail = ModerationTail {
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
    };
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
    let Some(record) = record else {
        return Err(coded(
            "channels_moderation_too_large",
            "This change does not fit in one published record. Shorten the welcome \
             message, or remove some bans or moderators.",
        ));
    };
    let ts = record.timestamp;
    let tail_nominee = tail.successor_nominee;
    let tail_days = tail.claim_after_days;
    let tail_epoch = tail.key_epoch;
    let tail_owner_only = tail.invites_owner_only;
    let tail_slow_mode = tail.slow_mode_secs;
    let db = state.db.clone();
    let id = owned.row.channel_id.clone();
    let topic_s = topic.to_string();
    let welcome_s = welcome.to_string();
    let bans_v = bans.to_vec();
    let mods_v = mods.to_vec();
    let applied = tokio::task::spawn_blocking(move || {
        db.apply_channel_moderation(
            &id,
            &topic_s,
            &welcome_s,
            ts,
            &bans_v,
            &mods_v,
            Some(&our_pk),
            tail_nominee.as_ref(),
            tail_days,
            tail_epoch,
            tail_owner_only,
            tail_slow_mode,
        )
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_moderation_failed", "Failed to save room info", e))?;
    if !applied {
        return Err(coded(
            "channels_moderation_failed",
            "A newer moderation record is already stored",
        ));
    }
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
        let owned = if owned
            .row
            .successor_nominee
            .eq_ignore_ascii_case(&hex::encode(pk))
        {
            let db = state.db.clone();
            let id = channel_id.clone();
            tokio::task::spawn_blocking(move || db.set_channel_succession(&id, "", 0))
                .await
                .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
                .map_err(|e| {
                    coded_ctx("channels_moderation_failed", "Could not clear the nominee", e)
                })?;
            // Re-read, exactly as the other commands that write a column before
            // committing do. `commit_channel_moderation` builds the published
            // tail from this row, so handing it the pre-clear snapshot signed
            // the withdrawn nomination straight back into the record the whole
            // room reads — and wrote it back locally too, leaving the banned
            // member still listed as successor.
            OwnedChannel {
                row: load_owned_channel(&state, &channel_id).await?.row,
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
    let db = state.db.clone();
    let id = channel_id.clone();
    let nominee_hex = nominee.map(hex::encode).unwrap_or_default();
    tokio::task::spawn_blocking(move || db.set_channel_succession(&id, &nominee_hex, days as i64))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_moderation_failed", "Could not save the nominee", e))?;

    // The members learn the nomination from the moderation record below, but
    // the name registry cannot read that — so tell it separately. Without this
    // the nominee could take the room and still not be able to move its name,
    // because the record would stay bound to the abandoned room's key.
    let url = rendezvous_url(&state).await;
    if !url.is_empty() {
        if let Err(e) = registry_call(crate::network::rendezvous::register_channel_nominee(
            &url,
            &owned.ident.channel_id,
            &owned.ident.pubkey,
            &owned.ident.seed(),
            nominee.as_ref(),
            days as u32,
        ))
        .await
        {
            // Not fatal: the nomination itself lives in the signed record, and
            // an unreachable registry only delays the name following the room.
            tracing::warn!(
                channel_id = %channel_id,
                error = ?e,
                "saved the nominee but could not register it with the name registry"
            );
        }
    }

    // Republish so members learn the nomination; the tail is rebuilt from the
    // row we just wrote.
    let bans = load_banned_pubkeys(&state, &channel_id).await?;
    let mods = load_moderator_pubkeys(&state, &channel_id).await?;
    let refreshed = load_owned_channel(&state, &channel_id).await?;
    commit_channel_moderation(
        &state,
        &refreshed,
        &owned.row.topic,
        &owned.row.welcome,
        &bans,
        &mods,
    )
    .await?;
    channel_info_from_id(&state, &channel_id).await
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
    let version = row.moderation_updated_at.max(1) as u64;
    tokio::task::spawn_blocking(move || {
        db.apply_channel_handoff(
            &old,
            &successor_pk_hex,
            &successor_id_hex,
            version,
            private,
            Some(&seed),
        )
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_handoff_failed", "Could not claim the room", e))?;

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
            if let Err(e) = commit_channel_moderation(
                &state,
                &owned,
                &owned.row.topic,
                &owned.row.welcome,
                &bans,
                &mods,
            )
            .await
            {
                tracing::warn!(channel_id = %successor_id_hex, error = %e, "could not publish the claimed room's first record");
                undo_rotation(&state, &owned, rotated).await;
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

/// Turn one shard's raw `FOUND_VALUE` blobs into public room listings.
///
/// `seen` is threaded across shards so a record several storers hold is listed
/// once. Private rooms publish an index record too and are dropped here: theirs
/// exists so a holder of the invite can confirm the room, not so a browse can
/// find it.
fn listings_from_blobs(
    blobs: Vec<Vec<u8>>,
    joined_ids: &std::collections::HashSet<String>,
    seen: &mut std::collections::HashSet<String>,
) -> Vec<GatheredChannelInfo> {
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
        let id_hex = hex::encode(rec.file_hash);
        if !seen.insert(id_hex.clone()) {
            continue;
        }
        let private = rec
            .channel
            .as_ref()
            .map(|m| m.is_private())
            .unwrap_or(false);
        if private {
            continue;
        }
        out.push(GatheredChannelInfo {
            channel_id: id_hex.clone(),
            pubkey: hex::encode(rec.ember_file_hash),
            name: rec.file_name,
            private,
            joined: joined_ids.contains(&id_hex),
            member_count: None,
        });
    }
    out
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
        tokio::time::timeout(
            DIRECTORY_FETCH_TIMEOUT,
            crate::network::rendezvous::fetch_channel_directory(&url),
        ),
        tokio::time::timeout(
            DIRECTORY_FETCH_TIMEOUT,
            crate::network::rendezvous::fetch_deleted_channel_ids(&url),
        ),
    );
    let directory = match directory {
        Ok(Ok(list)) => list,
        Ok(Err(_)) | Err(_) => Vec::new(),
    };
    let deleted: std::collections::HashSet<String> = match deleted {
        Ok(Ok(ids)) => ids,
        Ok(Err(_)) | Err(_) => Vec::new(),
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

    let mut seen = std::collections::HashSet::new();
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
        seen.insert(id.clone());
        out.push(GatheredChannelInfo {
            joined: joined_ids.contains(&id),
            channel_id: id,
            pubkey: pubkey_hex,
            name: listing.name,
            private: false,
            member_count: None,
        });
    }
    if !out.is_empty() {
        emit(&out);
    }

    while let Some(shard) = walks.next().await {
        let found = listings_from_blobs(shard.unwrap_or_default(), &joined_ids, &mut seen);
        let found: Vec<_> = found
            .into_iter()
            .filter(|c| !deleted.contains(&c.channel_id))
            .collect();
        if found.is_empty() {
            continue;
        }
        emit(&found);
        out.extend(found);
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

    let listings: Vec<(String, String, String)> = out
        .iter()
        .map(|c| (c.channel_id.clone(), c.pubkey.clone(), c.name.clone()))
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
        .try_send(NetworkCommand::PublishEmberRecord { record, tx })
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
        .try_send(NetworkCommand::PublishEmberRecord { record, tx })
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
        // The version is the offer's own wall-clock second, so it doubles as
        // its age. A negative age means the clock moved backwards under us,
        // which must not wedge the room either.
        let age = chrono::Utc::now()
            .timestamp()
            .saturating_sub(offered_at as i64);
        let lapsed = !(0..channel::HANDOFF_PENDING_TTL_SECS).contains(&age);
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

// --- Ember Transfer -------------------------------------------------------

/// Offer a file to one member of a room.
///
/// Nothing leaves this machine until they accept. The file is hashed here
/// rather than in the network task so a 100 MB read never stalls the loop
/// that is also carrying everyone's chat.
#[tauri::command]
pub async fn offer_channel_transfer(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    member_pubkey: String,
    path: String,
) -> Result<String, String> {
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

    let path_for_hash = path.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        let canonical = std::path::PathBuf::from(&path_for_hash)
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
                "Files must be between 1 byte and 100 MB",
                channel::XFER_MAX_BYTES,
            ));
        }
        let name = crate::security::sanitize_filename(
            canonical
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file"),
        );
        if name.is_empty() {
            return Err(coded(
                "channels_xfer_failed",
                "That file name is not allowed",
            ));
        }
        let tree = std::fs::File::open(&canonical).and_then(|f| {
            crate::network::ember::transfer::HashTree::from_reader(std::io::BufReader::new(f))
        })
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
    Ok(hex::encode(xfer_id))
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

/// Everything currently offered, awaiting an answer, or moving.
#[tauri::command]
pub async fn list_channel_transfers(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<crate::network::ChannelTransferSnapshot>, String> {
    if !state.config.read().await.settings.ember_native_enabled {
        return Ok(Vec::new());
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    if state
        .network_tx
        .try_send(NetworkCommand::ListChannelTransfers { tx })
        .is_err()
    {
        return Ok(Vec::new());
    }
    Ok(rx.await.unwrap_or_default())
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
}

