//! Ember Channels: create, join, list, and local chat.
//!
//! DHT publish/search is forwarded to the network task. Channel peers are
//! never added to `friend_hashes`.

use rand::rngs::OsRng;
use rand::RngCore;

use crate::app_state::AppState;
use crate::commands::errors::{await_reply, coded, coded_ctx};
use crate::network::ember::channel::{
    self, ChannelIdentity, ChannelInvite, CHANNEL_KIND_PRIVATE, CHANNEL_KIND_PUBLIC,
};
use crate::network::ember::dht::messages::MAX_FIND_VALUE_KEYS;
use crate::network::ember::dht::publish::SignedRecord;
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
}

impl From<StoredChannel> for ChannelInfo {
    fn from(row: StoredChannel) -> Self {
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
        }
    }
}

#[derive(serde::Serialize)]
pub struct ChannelMemberInfo {
    pub member_pubkey: String,
    pub nickname: String,
    pub last_seen: i64,
    pub banned: bool,
}

impl From<StoredChannelMember> for ChannelMemberInfo {
    fn from(row: StoredChannelMember) -> Self {
        Self {
            member_pubkey: row.member_pubkey,
            nickname: row.nickname,
            last_seen: row.last_seen,
            banned: row.banned,
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

#[tauri::command]
pub async fn list_channels(state: tauri::State<'_, AppState>) -> Result<Vec<ChannelInfo>, String> {
    require_ember(&state).await?;
    let db = state.db.clone();
    let rows = tokio::task::spawn_blocking(move || db.list_channels())
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_list_failed", "Failed to list channels", e))?;
    Ok(rows.into_iter().map(ChannelInfo::from).collect())
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

    let our_pk = hex::encode(state.identity.ed25519_public_key);
    let nickname = {
        let cfg = state.config.read().await;
        crate::security::sanitize_display_name(&cfg.settings.nickname)
    };
    let db = state.db.clone();
    let member_id = channel_id_hex.clone();
    let member_pk = our_pk.clone();
    let member_nick = nickname.clone();
    let _ = tokio::task::spawn_blocking(move || {
        db.upsert_channel_member(
            &member_id,
            &member_pk,
            &member_nick,
            chrono::Utc::now().timestamp(),
        )
    })
    .await;

    if !private {
        let record = SignedRecord::channel_index(
            &name,
            ident.channel_id,
            ident.pubkey,
            false,
            &ident.signing_key,
        );
        let _ = publish_signed_record(&state, record).await;
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

    let invite = ChannelInvite {
        channel_id: ident.channel_id,
        pubkey: ident.pubkey,
        name: name.clone(),
        join_secret,
        private,
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

    let our_pk = hex::encode(state.identity.ed25519_public_key);
    let nickname = {
        let cfg = state.config.read().await;
        crate::security::sanitize_display_name(&cfg.settings.nickname)
    };
    let db2 = state.db.clone();
    let member_id = db_id.clone();
    let member_pk = our_pk;
    let member_nick = nickname.clone();
    let _ = tokio::task::spawn_blocking(move || {
        db2.upsert_channel_member(
            &member_id,
            &member_pk,
            &member_nick,
            chrono::Utc::now().timestamp(),
        )
    })
    .await;

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
    Ok(row.into())
}

#[tauri::command]
pub async fn leave_channel(
    state: tauri::State<'_, AppState>,
    channel_id: String,
) -> Result<(), String> {
    require_ember(&state).await?;
    let channel_id = parse_channel_id(&channel_id)?;
    let db = state.db.clone();
    let removed = tokio::task::spawn_blocking(move || db.delete_channel(&channel_id))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_leave_failed", "Failed to leave channel", e))?;
    if !removed {
        return Err(coded("channels_not_found", "Channel not found"));
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
    let join_secret = if private {
        let db = state.db.clone();
        let id = channel_id.clone();
        tokio::task::spawn_blocking(move || db.load_channel_join_secret(&id))
            .await
            .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
            .map_err(|e| coded_ctx("channels_invite_failed", "Failed to load invite", e))?
            .ok_or_else(|| {
                coded(
                    "channels_invite_invalid",
                    "This private channel has no join secret on this device",
                )
            })?
    } else {
        channel::public_join_secret(&pubkey)
    };
    let invite = ChannelInvite {
        channel_id: cid,
        pubkey,
        name: row.name.clone(),
        join_secret,
        private,
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
    let db = state.db.clone();
    let rows = tokio::task::spawn_blocking(move || db.list_channel_members(&channel_id))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_members_failed", "Failed to list members", e))?;
    Ok(rows.into_iter().map(ChannelMemberInfo::from).collect())
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
    let db = state.db.clone();
    let id_check = channel_id.clone();
    let row = tokio::task::spawn_blocking(move || db.get_channel(&id_check))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_send_failed", "Failed to send", e))?
        .ok_or_else(|| coded("channels_not_found", "Channel not found"))?;
    let mut msg_id = [0u8; 16];
    OsRng.fill_bytes(&mut msg_id);
    let sender_pk = state.identity.ed25519_public_key;
    let sender = hex::encode(sender_pk);
    let db = state.db.clone();
    let id = channel_id.clone();
    let sender2 = sender.clone();
    let text = cleaned.clone();
    let msg_id_hex = hex::encode(msg_id);
    let row_id = tokio::task::spawn_blocking(move || {
        db.insert_channel_message(&id, &sender2, "sent", &text, &msg_id_hex)
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("channels_send_failed", "Failed to send", e))?;

    let join_secret = if row.visibility == CHANNEL_KIND_PRIVATE {
        let db = state.db.clone();
        let id = channel_id.clone();
        tokio::task::spawn_blocking(move || db.load_channel_join_secret(&id))
            .await
            .ok()
            .and_then(|r| r.ok())
            .flatten()
    } else {
        hex::decode(&row.pubkey)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(|pk| channel::public_join_secret(&pk))
    };
    if let Some(join_secret) = join_secret {
        let mut channel_id_bytes = [0u8; 16];
        if let Ok(id_bytes) = hex::decode(&channel_id) {
            if id_bytes.len() == 16 {
                channel_id_bytes.copy_from_slice(&id_bytes);
                let key = channel::content_key(&join_secret);
                let plain = channel::encode_channel_chat_plain(&sender_pk, &cleaned);
                let gossip = channel::ChannelGossip::sealed(
                    channel_id_bytes,
                    msg_id,
                    &key,
                    chrono::Utc::now().timestamp().max(0) as u64,
                    &plain,
                    channel::CHANNEL_MSG_TTL_DEFAULT,
                );
                let _ = state
                    .network_tx
                    .try_send(NetworkCommand::FanoutChannelGossip {
                        body: gossip.encode(),
                    });
            }
        }
    }

    Ok(ChannelMessageInfo {
        id: row_id,
        sender_pubkey: sender,
        direction: "sent".into(),
        message: cleaned,
        timestamp: chrono::Utc::now().timestamp(),
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

/// Walk the 16 public-index shards and return unique channel listings.
#[tauri::command]
pub async fn gather_channels(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<GatheredChannelInfo>, String> {
    require_ember(&state).await?;
    let keys = channel::all_index_keys();
    let mut records = Vec::new();
    for chunk in keys.chunks(MAX_FIND_VALUE_KEYS) {
        match find_raw_keys(&state, chunk.to_vec()).await {
            Ok(blobs) => records.extend(blobs),
            Err(_) => continue,
        }
    }
    let db = state.db.clone();
    let joined = tokio::task::spawn_blocking(move || db.list_channels())
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default();
    let joined_ids: std::collections::HashSet<_> =
        joined.into_iter().map(|c| c.channel_id).collect();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for blob in records {
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
    Ok(out)
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
