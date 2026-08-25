//! Ember Channels: create, join, list, and local chat.
//!
//! DHT publish/search is forwarded to the network task. Channel peers are
//! never added to `friend_hashes`.

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
use crate::storage::database::{StoredChannel, StoredChannelMember};

const MAX_CHANNEL_NAME: usize = 64;
const MAX_CHANNEL_MESSAGE: usize = 4096;
const DEFAULT_FIND_TIMEOUT_MS: u64 = 30_000;

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
    if cleaned.len() > MAX_CHANNEL_NAME {
        return Err(coded_ctx(
            "channels_name_too_long",
            format!("Channel name too long (max {MAX_CHANNEL_NAME} bytes)"),
            MAX_CHANNEL_NAME,
        ));
    }
    Ok(cleaned)
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
        db.upsert_channel_member(&id, &pk, &nick, chrono::Utc::now().timestamp())
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
    let seed = ident.seed();
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

    let nickname = {
        let cfg = state.config.read().await;
        crate::security::sanitize_display_name(&cfg.settings.nickname)
    };
    if let Err(e) =
        record_self_member(&state, &channel_id_hex, &nickname, "channels_create_failed").await
    {
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
        if let Err(e) = publish_signed_record(&state, record).await {
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
    let _ = publish_signed_record(&state, presence).await;
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
    let _ = publish_signed_record(&state, moderation).await;

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
        sanitize_channel_name(&invite.name).unwrap_or_else(|_| {
            crate::security::sanitize_remote_text(&invite.name, MAX_CHANNEL_NAME)
        })
    };
    let channel_id_hex = hex::encode(invite.channel_id);
    let pubkey_hex = hex::encode(invite.pubkey);
    let visibility = if invite.private {
        CHANNEL_KIND_PRIVATE
    } else {
        CHANNEL_KIND_PUBLIC
    };
    let db = state.db.clone();
    let db_id = channel_id_hex.clone();
    if tokio::task::spawn_blocking({
        let db = db.clone();
        let id = db_id.clone();
        move || db.get_channel(&id)
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_join_failed", "Failed to join channel", e))?
    .is_some()
    {
        return Err(coded(
            "channels_already_joined",
            "You have already joined this channel",
        ));
    }

    let join_secret = invite.join_secret;
    let private = invite.private;
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

    // Record which epoch the invite's secret belongs to. Otherwise the room
    // reports an epoch we hold no record of, and we would both warn the user
    // their working invite is stale and poll forever for a key the owner never
    // minted for us — we were not a member when it rotated.
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
            // Not fatal: the secret is already stored as the join secret, so the
            // room is readable either way.
            tracing::warn!(channel_id = %db_id, error = %e, "could not record the invite's epoch");
        }
    }

    let nickname = {
        let cfg = state.config.read().await;
        crate::security::sanitize_display_name(&cfg.settings.nickname)
    };
    if let Err(e) = record_self_member(&state, &db_id, &nickname, "channels_join_failed").await {
        discard_partial_channel(&state, &db_id).await;
        return Err(e);
    }

    let presence = SignedRecord::channel_presence(
        &nickname,
        invite.channel_id,
        invite.pubkey,
        &invite.join_secret,
        invite.private,
        channel::presence_epoch(chrono::Utc::now().timestamp()),
        &state.identity.noise_public_key,
        &crypto::signing_key_from_bytes(&state.identity.ed25519_secret_key),
    );
    let _ = publish_signed_record(&state, presence).await;

    let db = state.db.clone();
    let row = tokio::task::spawn_blocking(move || db.get_channel(&db_id))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_join_failed", "Failed to join channel", e))?
        .ok_or_else(|| coded("channels_not_found", "Channel not found"))?;
    Ok(ChannelInfo::from_stored(row, false, false))
}

#[tauri::command]
pub async fn leave_channel(
    state: tauri::State<'_, AppState>,
    channel_id: String,
) -> Result<(), String> {
    require_ember(&state).await?;
    let channel_id = parse_channel_id(&channel_id)?;
    let db = state.db.clone();
    let our_pk = hex::encode(state.identity.ed25519_public_key);
    let delete_id = channel_id.clone();
    let removed = tokio::task::spawn_blocking(move || {
        db.delete_channel(&delete_id, Some(&our_pk))
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_leave_failed", "Failed to leave channel", e))?;
    if !removed {
        return Err(coded("channels_not_found", "Channel not found"));
    }
    // Transfers belong to the room. Leaving takes the content key with it, so
    // anything still in flight can neither continue nor be cancelled on the
    // wire — drop it now rather than leaving the UI a row that only clears
    // when it eventually times out.
    if let Ok(bytes) = hex::decode(&channel_id) {
        if let Ok(id) = <[u8; 16]>::try_from(bytes.as_slice()) {
            let _ = state
                .network_tx
                .try_send(NetworkCommand::DropChannelTransfers { channel_id: id });
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
    Ok(rows
        .into_iter()
        .map(
            |(id, sender_pubkey, direction, message, timestamp, read)| ChannelMessageInfo {
                id,
                sender_pubkey,
                direction,
                message,
                timestamp,
                read,
            },
        )
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
    Ok(rows
        .into_iter()
        .map(
            |(id, sender_pubkey, direction, message, timestamp, read)| ChannelMessageInfo {
                id,
                sender_pubkey,
                direction,
                message,
                timestamp,
                read,
            },
        )
        .collect())
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
    let sender = hex::encode(state.identity.ed25519_public_key);
    if self_banned_from(&state, &row, "channels_send_failed").await? {
        return Err(coded(
            "channels_banned",
            "You are banned from this channel",
        ));
    }
    let mut msg_id = [0u8; 16];
    OsRng.fill_bytes(&mut msg_id);
    let sender_pk = state.identity.ed25519_public_key;
    let db = state.db.clone();
    let id = channel_id.clone();
    let sender2 = sender.clone();
    let text = cleaned.clone();
    let msg_id_hex = hex::encode(msg_id);
    let sent_at = chrono::Utc::now().timestamp();
    // Signed before the row is written so the stored copy carries the same
    // authenticator the room will see, and can be re-served on a catch-up
    // without this node ever signing on somebody's behalf.
    let author_sig = channel::chat_author_signature(
        &crypto::signing_key_from_bytes(&state.identity.ed25519_secret_key),
        &sender_pk,
        &channel_id_bytes,
        &msg_id,
        sent_at,
        &cleaned,
    );
    let author_sig_hex = hex::encode(author_sig);
    let row_id = tokio::task::spawn_blocking(move || {
        db.insert_channel_message(
            &id,
            &sender2,
            "sent",
            &text,
            &msg_id_hex,
            sent_at,
            &author_sig_hex,
        )
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_send_failed", "Failed to send", e))?;

    // Must be the current epoch, not the `join_secret` column. Chat is the bulk
    // of what a room carries, so sealing it with the pre-rotation key left the
    // member a ban had just evicted able to read every new message — the one
    // thing rotating is for.
    if let Some(join_secret) = join_secret_for_channel(&state, &row).await {
        let key = channel::content_key(&join_secret);
        // The same signature the row kept, so what the room verifies and what a
        // later catch-up replays are byte-identical.
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
        let _ = state
            .network_tx
            .try_send(NetworkCommand::FanoutChannelGossip {
                body: gossip.encode(),
            });
    }

    Ok(ChannelMessageInfo {
        id: row_id,
        sender_pubkey: sender,
        direction: "sent".into(),
        message: cleaned,
        timestamp: sent_at,
        read: true,
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
    let ts = record.timestamp;
    let tail_nominee = tail.successor_nominee;
    let tail_days = tail.claim_after_days;
    let tail_epoch = tail.key_epoch;
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
    // Not fatal: the rows above are already committed, and the owner's
    // periodic republish (`maybe_republish_channel_moderation`) rebuilds this
    // record from them, so a failure here delays propagation by up to
    // MODERATION_REPUBLISH_SECS rather than losing it. A timeout also does not
    // prove the store failed, so refusing the whole command would report a
    // false failure for a change that did land.
    if let Err(e) = publish_signed_record(state, record).await {
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
    tokio::task::spawn_blocking(move || db.get_channel(&id))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_moderation_failed", "Failed to load channel", e))?
        .ok_or_else(|| coded("channels_not_found", "Channel not found"))
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

fn enqueue_channel_gossip(state: &AppState, channel_id: &str, join_secret: [u8; 32], plain: Vec<u8>) {
    let mut channel_id_bytes = [0u8; 16];
    let Ok(id_bytes) = hex::decode(channel_id) else {
        return;
    };
    if id_bytes.len() != 16 {
        return;
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
    let _ = state
        .network_tx
        .try_send(NetworkCommand::FanoutChannelGossip {
            body: gossip.encode(),
        });
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
        // Best effort per member, like every other channel publish: the owner
        // republishes moderation on a timer, and a member who cannot find
        // their record re-asks every minute until it lands.
        if let Err(e) = publish_signed_record(state, record).await {
            tracing::warn!(
                channel_id = %owned.row.channel_id,
                member = %member.member_pubkey,
                error = %e,
                "could not publish a rotated channel key to a member"
            );
        }
    }
    Ok(Some(next_epoch))
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
    tokio::task::spawn_blocking(move || {
        db.apply_channel_ban_action(&id, &target_hex, banned, ts)
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_ban_failed", "Failed to update the ban list", e))?;
    if let Some(join_secret) = join_secret_for_channel(state, row).await {
        let plain = channel::encode_channel_mod_action(
            &state.identity.ed25519_public_key,
            &target,
            banned,
        );
        enqueue_channel_gossip(state, &row.channel_id, join_secret, plain);
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
        if owned
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
        }
        // Rotate before committing: a ban that leaves the old key in place is
        // not an eviction, since the removed member — and anyone they gave the
        // invite to — can still read everything sent afterwards. Ordering
        // matters twice over, because the snapshot below carries the new epoch
        // number and that is how the remaining members learn to fetch it.
        let rotated = rotate_channel_key(&state, &owned, &bans).await?;
        if let Err(error) = commit_channel_moderation(
            &state,
            &owned,
            &owned.row.topic,
            &owned.row.welcome,
            &bans,
            &mods,
        )
        .await
        {
            // The snapshot is what tells members a new epoch exists. Without it
            // we would seal everything under a key none of them will ever go
            // looking for, so the rotation has to come back off.
            if let Some(epoch) = rotated {
                let db = state.db.clone();
                let id = channel_id.clone();
                if let Err(e) =
                    tokio::task::spawn_blocking(move || db.rollback_channel_key_epoch(&id, epoch))
                        .await
                        .map_err(|e| anyhow::anyhow!("{e}"))
                        .and_then(|r| r)
                {
                    tracing::error!(
                        channel_id = %channel_id,
                        error = %e,
                        "could not roll back epoch {epoch} after a failed moderation commit"
                    );
                }
            }
            return Err(error);
        }
    } else {
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
    let _snapshot = moderation_lock().lock().await;
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
    match load_owned_channel(&state, &successor_id_hex).await {
        Ok(owned) => {
            if let Err(e) = rotate_channel_key(&state, &owned, &[]).await {
                tracing::warn!(channel_id = %successor_id_hex, error = %e, "could not rotate the claimed room");
            }
            let bans = load_banned_pubkeys(&state, &successor_id_hex)
                .await
                .unwrap_or_default();
            let mods = load_moderator_pubkeys(&state, &successor_id_hex)
                .await
                .unwrap_or_default();
            // Also the first record naming us as owner, which is what lets
            // members derive the pairwise key at all.
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
            }
        }
        Err(e) => {
            tracing::warn!(channel_id = %successor_id_hex, error = %e, "claimed room is not loadable as owned");
        }
    }
    channel_info_from_id(&state, &successor_id_hex).await
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
        });
    }
    out
}

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
) -> Result<Vec<GatheredChannelInfo>, String> {
    use futures::StreamExt;

    require_ember(&state).await?;
    let db = state.db.clone();
    let joined = tokio::task::spawn_blocking(move || db.list_channels())
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default();
    let joined_ids: std::collections::HashSet<_> =
        joined.into_iter().map(|c| c.channel_id).collect();

    // One walk per shard, and never a batch. A `FIND_VALUE` converges on the
    // single point in the ID space named by its first key; the rest are an AND
    // filter for multi-word search, and the searcher drops any record whose
    // embedded key is not the primary. Batching the shards into requests of
    // `MAX_FIND_VALUE_KEYS` therefore walked toward shard 0 and shard 8 and
    // discarded the other fourteen, so most public rooms could never be found.
    // The walks run together because they are independent and a browse that
    // ran them in series would cost sixteen timeouts.
    let mut walks: futures::stream::FuturesUnordered<_> = channel::all_index_keys()
        .into_iter()
        .map(|key| find_raw_keys(&state, vec![key]))
        .collect();

    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<GatheredChannelInfo> = Vec::new();
    // A shard that errors or times out is skipped rather than failing the
    // browse: fifteen shards of listings beat none.
    while let Some(shard) = walks.next().await {
        let found = listings_from_blobs(shard.unwrap_or_default(), &joined_ids, &mut seen);
        if found.is_empty() {
            continue;
        }
        let _ = app.emit("ember:channels-found", &found);
        out.extend(found);
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

    let joined_ids: std::collections::HashSet<_> =
        joined.into_iter().map(|c| c.channel_id).collect();
    Ok(cached
        .into_iter()
        .map(|c| GatheredChannelInfo {
            joined: joined_ids.contains(&c.channel_id),
            channel_id: c.channel_id,
            pubkey: c.pubkey,
            name: c.name,
            private: false,
        })
        .collect())
}

async fn publish_signed_record(
    state: &AppState,
    record: SignedRecord,
) -> Result<EmberPublishResult, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::PublishEmberRecord { record, tx })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    let pending: EmberPublishPending = await_reply(
        rx,
        "channels_publish_failed",
        "No response from network",
    )
    .await??;
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
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::FindEmberKeys { keys, tx })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    let pending = await_reply(rx, "channels_gather_failed", "No response from network").await??;
    match tokio::time::timeout(
        std::time::Duration::from_millis(DEFAULT_FIND_TIMEOUT_MS),
        pending.records_rx,
    )
    .await
    {
        Ok(Ok(records)) => Ok(records),
        Ok(Err(_)) => Ok(Vec::new()),
        Err(_) => Ok(Vec::new()),
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
    if let Some((waiting_on, _)) = pending {
        if !waiting_on.eq_ignore_ascii_case(&hex::encode(pk)) {
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
    enqueue_channel_gossip(&state, &channel_id, join_secret, plain);
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

    let canonical = std::path::PathBuf::from(&path)
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

    // The same hash tree the dormant Ember transfer module defines, so the
    // identifier here is the Ember file hash rather than a one-off digest.
    let hash_path = canonical.clone();
    let tree = tokio::task::spawn_blocking(move || {
        std::fs::File::open(&hash_path).and_then(|f| {
            crate::network::ember::transfer::HashTree::from_reader(std::io::BufReader::new(f))
        })
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_xfer_failed", "Could not read that file", e))?;
    if tree.file_size != meta.len() {
        return Err(coded(
            "channels_xfer_failed",
            "That file changed while it was being prepared",
        ));
    }

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
            size: meta.len(),
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

