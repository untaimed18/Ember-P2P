use crate::app_state::AppState;
use crate::network::{NetworkCommand, PeerReputationInfo, ReputationStatsInfo};
use crate::storage::identity::NodeIdentity;
use crate::types::*;

/// Maximum stored friend nickname size. Same cap is enforced in
/// `update_friend_nickname`; centralizing it here keeps the two
/// command paths in sync.
const MAX_FRIEND_NICKNAME_LEN: usize = 256;

fn parse_user_hash(hex_str: &str) -> Result<[u8; 16], String> {
    if hex_str.len() != 32 || !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("User hash must be 32 hex characters (16 bytes)".into());
    }
    let bytes = hex::decode(hex_str).map_err(|_| "Invalid hex string".to_string())?;
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

#[derive(serde::Serialize)]
pub struct FriendInfo {
    pub user_hash: String,
    pub nickname: String,
    pub added_at: i64,
    pub last_ip: String,
    pub last_port: u16,
    pub last_seen: i64,
    pub mutual: bool,
}

#[derive(serde::Serialize)]
pub struct FriendRequestInfo {
    pub sender_hash: String,
    pub sender_nickname: String,
    pub received_at: i64,
}

#[tauri::command]
pub async fn add_friend(
    state: tauri::State<'_, AppState>,
    user_hash_hex: String,
    nickname: Option<String>,
) -> Result<(), String> {
    let canonical = user_hash_hex.to_lowercase();
    let hash = parse_user_hash(&canonical)?;
    let nick = nickname.unwrap_or_default();
    if nick.len() > MAX_FRIEND_NICKNAME_LEN {
        return Err(format!(
            "Nickname too long (max {MAX_FRIEND_NICKNAME_LEN} bytes)"
        ));
    }

    let our_ember_hash = {
        let data_dir = directories::ProjectDirs::from("com", "ember", "p2p")
            .map(|d| d.data_dir().to_path_buf())
            .ok_or_else(|| "Failed to determine data directory".to_string())?;
        let id = tokio::task::spawn_blocking(move || NodeIdentity::load_or_create(&data_dir))
            .await.map_err(|e| format!("Task error: {e}"))?.map_err(|e| format!("{e}"))?;
        hex::encode(id.ember_hash)
    };
    if canonical == our_ember_hash {
        return Err("You cannot add yourself as a friend".into());
    }

    let max_friends = {
        let config = state.config.read().await;
        config.settings.max_friends
    };

    {
        let mut friends = state.friend_hashes.write().await;
        if friends.len() as u32 >= max_friends && !friends.contains(&hash) {
            return Err(format!("Friend limit reached ({max_friends}). Increase the limit in Settings > Friends."));
        }
        friends.insert(hash);
    }

    let db = state.db.clone();
    let db_hash = canonical.clone();
    let db_nick = nick.clone();
    let db_result = tokio::task::spawn_blocking(move || db.add_friend(&db_hash, &db_nick)).await;
    if let Err(e) = db_result.as_ref().map_err(|e| e.to_string()).and_then(|r| r.as_ref().map_err(|e| e.to_string())) {
        state.friend_hashes.write().await.remove(&hash);
        return Err(format!("Failed to save friend: {e}"));
    }

    // Friend is already persisted to the DB above; the network task
    // only needs the hash to start the auto-connect search. If the
    // command channel is briefly saturated we'd rather log a warning
    // than fail the whole add — the friend IS added either way and
    // the next periodic friend-search cycle (or restart) will pick
    // them up. Returning Err here used to make the UI flag
    // "add friend failed" even though the DB row was successfully
    // written.
    if let Err(e) = state.network_tx.try_send(NetworkCommand::FindFriendAndConnect {
        ember_hash: hash,
    }) {
        tracing::warn!("Friend added to DB, but auto-connect search was not enqueued (channel full): {e}");
    }

    Ok(())
}

#[tauri::command]
pub async fn remove_friend(
    state: tauri::State<'_, AppState>,
    user_hash_hex: String,
) -> Result<(), String> {
    let canonical = user_hash_hex.to_lowercase();
    let hash = parse_user_hash(&canonical)?;

    let db = state.db.clone();
    let db_hash = canonical;
    tokio::task::spawn_blocking(move || db.remove_friend(&db_hash))
        .await
        .map_err(|e| format!("Task error: {e}"))?
        .map_err(|e| format!("Failed to remove friend: {e}"))?;

    let mut friends = state.friend_hashes.write().await;
    friends.remove(&hash);
    drop(friends);
    // Removal is already committed to the DB and the in-memory friend
    // set above. The network notification only matters for tearing
    // down a live session — if the channel is full a stale session may
    // linger until next restart, which is preferable to surfacing a
    // "remove friend failed" error after the row is already gone.
    if let Err(e) = state.network_tx.try_send(NetworkCommand::FriendRemoved { ember_hash: hash }) {
        tracing::warn!("Friend removed from DB, but live-session teardown was not enqueued (channel full): {e}");
    }
    Ok(())
}

#[tauri::command]
pub async fn update_friend_nickname(
    state: tauri::State<'_, AppState>,
    user_hash_hex: String,
    nickname: String,
) -> Result<(), String> {
    if nickname.len() > MAX_FRIEND_NICKNAME_LEN {
        return Err(format!(
            "Nickname too long (max {MAX_FRIEND_NICKNAME_LEN} bytes)"
        ));
    }
    let canonical = user_hash_hex.to_lowercase();
    parse_user_hash(&canonical)?;

    let db = state.db.clone();
    let db_hash = canonical;
    let db_nick = nickname;
    tokio::task::spawn_blocking(move || db.update_friend_nickname(&db_hash, &db_nick))
        .await
        .map_err(|e| format!("Task error: {e}"))?
        .map_err(|e| format!("Failed to update friend: {e}"))?;
    Ok(())
}

#[tauri::command]
pub async fn get_friends(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<FriendInfo>, String> {
    let db = state.db.clone();
    let rows = tokio::task::spawn_blocking(move || db.get_friends_full())
        .await
        .map_err(|e| format!("Task error: {e}"))?
        .map_err(|e| format!("Failed to load friends: {e}"))?;

    Ok(rows.into_iter().map(|(user_hash, nickname, added_at, last_ip, last_port, last_seen, mutual)| FriendInfo {
        user_hash,
        nickname,
        added_at,
        last_ip,
        last_port,
        last_seen,
        mutual,
    }).collect())
}

#[tauri::command]
pub async fn get_my_ember_hash(_app: tauri::AppHandle) -> Result<String, String> {
    let data_dir = directories::ProjectDirs::from("com", "ember", "p2p")
        .map(|d| d.data_dir().to_path_buf())
        .ok_or_else(|| "Failed to determine data directory".to_string())?;
    let identity = tokio::task::spawn_blocking(move || NodeIdentity::load_or_create(&data_dir))
        .await
        .map_err(|e| format!("Task error: {e}"))?
        .map_err(|e| format!("Failed to load identity: {e}"))?;
    Ok(hex::encode(identity.ember_hash))
}

#[derive(serde::Serialize)]
pub struct ChatMessageInfo {
    pub id: i64,
    pub direction: String,
    pub message: String,
    pub timestamp: i64,
    pub read: bool,
}

#[tauri::command]
pub async fn send_chat_message(
    state: tauri::State<'_, AppState>,
    user_hash_hex: String,
    message: String,
) -> Result<(), String> {
    if message.is_empty() || message.len() > 4096 {
        return Err("Message must be between 1 and 4096 bytes".into());
    }
    let canonical = user_hash_hex.to_lowercase();
    let hash = parse_user_hash(&canonical)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    state.network_tx.send(NetworkCommand::SendChatMessage {
        ember_hash: hash,
        message,
        tx,
    }).await.map_err(|_| "Network unavailable".to_string())?;
    rx.await.map_err(|_| "No response".to_string())?
}

#[tauri::command]
pub async fn get_chat_messages(
    state: tauri::State<'_, AppState>,
    friend_hash: String,
    limit: Option<i64>,
    before_id: Option<i64>,
) -> Result<Vec<ChatMessageInfo>, String> {
    let friend_hash = friend_hash.to_lowercase();
    parse_user_hash(&friend_hash)?;
    let db = state.db.clone();
    let lim = limit.unwrap_or(50).clamp(1, 200);
    let rows = tokio::task::spawn_blocking(move || db.get_chat_messages(&friend_hash, lim, before_id))
        .await
        .map_err(|e| format!("Task error: {e}"))?
        .map_err(|e| format!("Failed to load messages: {e}"))?;
    Ok(rows.into_iter().map(|(id, direction, message, timestamp, read)| ChatMessageInfo {
        id, direction, message, timestamp, read,
    }).collect())
}

#[tauri::command]
pub async fn mark_messages_read(
    state: tauri::State<'_, AppState>,
    friend_hash: String,
) -> Result<(), String> {
    let friend_hash = friend_hash.to_lowercase();
    parse_user_hash(&friend_hash)?;
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || db.mark_messages_read(&friend_hash))
        .await
        .map_err(|e| format!("Task error: {e}"))?
        .map_err(|e| format!("Failed to mark messages read: {e}"))?;
    Ok(())
}

#[tauri::command]
pub async fn get_unread_message_counts(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<(String, i64)>, String> {
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || db.unread_message_counts())
        .await
        .map_err(|e| format!("Task error: {e}"))?
        .map_err(|e| format!("Failed to get unread counts: {e}"))
}

#[tauri::command]
pub async fn get_friend_requests(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<FriendRequestInfo>, String> {
    let db = state.db.clone();
    let rows = tokio::task::spawn_blocking(move || db.get_friend_requests())
        .await
        .map_err(|e| format!("Task error: {e}"))?
        .map_err(|e| format!("Failed to load friend requests: {e}"))?;

    Ok(rows.into_iter().map(|(sender_hash, sender_nickname, received_at, _ip, _port)| FriendRequestInfo {
        sender_hash,
        sender_nickname,
        received_at,
    }).collect())
}

#[tauri::command]
pub async fn accept_friend_request(
    state: tauri::State<'_, AppState>,
    sender_hash: String,
) -> Result<(), String> {
    let canonical = sender_hash.to_lowercase();
    let hash = parse_user_hash(&canonical)?;

    let our_ember_hash = {
        let data_dir = directories::ProjectDirs::from("com", "ember", "p2p")
            .map(|d| d.data_dir().to_path_buf())
            .ok_or_else(|| "Failed to determine data directory".to_string())?;
        let id = tokio::task::spawn_blocking(move || NodeIdentity::load_or_create(&data_dir))
            .await.map_err(|e| format!("Task error: {e}"))?.map_err(|e| format!("{e}"))?;
        hex::encode(id.ember_hash)
    };
    if canonical == our_ember_hash {
        return Err("You cannot add yourself as a friend".into());
    }

    let max_friends = {
        let config = state.config.read().await;
        config.settings.max_friends
    };

    {
        let mut friends = state.friend_hashes.write().await;
        if friends.len() as u32 >= max_friends && !friends.contains(&hash) {
            return Err(format!("Friend limit reached ({max_friends}). Increase the limit in Settings > Friends."));
        }
        friends.insert(hash);
    }

    let db = state.db.clone();
    let c2 = canonical.clone();
    let db_result = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let requests = db.get_friend_requests()?;
        let nick = requests.iter()
            .find(|(h, _, _, _, _)| h == &c2)
            .map(|(_, n, _, _, _)| n.clone())
            .unwrap_or_default();
        db.add_friend(&c2, &nick)?;
        db.set_friend_mutual(&c2)?;
        db.remove_friend_request(&c2)?;
        Ok(())
    })
    .await;
    if let Err(e) = db_result.as_ref().map_err(|e| e.to_string()).and_then(|r| r.as_ref().map_err(|e| e.to_string())) {
        state.friend_hashes.write().await.remove(&hash);
        return Err(format!("Failed to accept friend request: {e}"));
    }

    // Same rationale as `add_friend`: the friend row is already
    // committed to the DB, so a full network channel just means
    // auto-connect waits for the next friend-search cycle. Don't
    // surface that as an "accept failed" error to the UI when the
    // accept itself succeeded.
    if let Err(e) = state.network_tx.try_send(NetworkCommand::FindFriendAndConnect {
        ember_hash: hash,
    }) {
        tracing::warn!("Friend request accepted in DB, but auto-connect search was not enqueued (channel full): {e}");
    }

    Ok(())
}

#[tauri::command]
pub async fn reject_friend_request(
    state: tauri::State<'_, AppState>,
    sender_hash: String,
) -> Result<(), String> {
    // Validate identically to `accept_friend_request` so a malformed
    // hash is rejected before it reaches the database. The DB path
    // uses bound parameters and is safe today, but consistency makes
    // the contract obvious and protects against future refactors.
    parse_user_hash(&sender_hash)?;
    let canonical = sender_hash.to_lowercase();
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || db.remove_friend_request(&canonical))
        .await
        .map_err(|e| format!("Task error: {e}"))?
        .map_err(|e| format!("Failed to reject friend request: {e}"))
}

#[tauri::command]
pub async fn is_friend_discoverable(
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state.network_tx.try_send(NetworkCommand::IsFriendDiscoverable { tx })
        .map_err(|e| format!("Network busy: {e}"))?;
    rx.await.map_err(|_| "No response".to_string())
}

#[tauri::command]
pub async fn retry_friend_search(
    state: tauri::State<'_, AppState>,
    user_hash_hex: String,
) -> Result<(), String> {
    let canonical = user_hash_hex.to_lowercase();
    let hash = parse_user_hash(&canonical)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    state.network_tx.send(NetworkCommand::RetryFriendSearch {
        ember_hash: hash,
        tx,
    }).await.map_err(|_| "Network unavailable".to_string())?;
    rx.await.map_err(|_| "No response".to_string())?
}

#[tauri::command]
pub async fn ensure_friend_session(
    state: tauri::State<'_, AppState>,
    user_hash_hex: String,
) -> Result<(), String> {
    let canonical = user_hash_hex.to_lowercase();
    let hash = parse_user_hash(&canonical)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    state.network_tx.send(NetworkCommand::EnsureFriendSession {
        ember_hash: hash,
        tx,
    }).await.map_err(|_| "Network unavailable".to_string())?;
    rx.await.map_err(|_| "No response".to_string())?
}

#[tauri::command]
pub async fn browse_friend(
    state: tauri::State<'_, AppState>,
    user_hash_hex: String,
) -> Result<(), String> {
    let canonical = user_hash_hex.to_lowercase();
    let hash = parse_user_hash(&canonical)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    state.network_tx.send(NetworkCommand::BrowseFriend {
        ember_hash: hash,
        tx,
    }).await.map_err(|_| "Network unavailable".to_string())?;
    rx.await.map_err(|_| "No response".to_string())?
}

async fn resolve_kad_host(input: &str, port: u16) -> Result<String, String> {
    if let Ok(ip) = input.parse::<std::net::Ipv4Addr>() {
        if crate::security::is_special_use_v4(ip) {
            return Err("Cannot connect to private/loopback addresses".into());
        }
        return Ok(input.to_string());
    }
    let addr = tokio::net::lookup_host((input, port))
        .await
        .map_err(|_| "Failed to resolve host address".to_string())?
        .find(|addr| addr.is_ipv4())
        .ok_or_else(|| format!("No IPv4 address found for {input}:{port}"))?;
    if crate::security::is_private_ip(addr.ip()) {
        return Err("Hostname resolves to a private/loopback address".into());
    }
    Ok(addr.ip().to_string())
}

#[tauri::command]
pub async fn get_peers(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<PeerInfo>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetPeersSnapshot { tx })
        .map_err(|e| format!("Network busy: {e}"))?;
    rx.await.map_err(|_| "Failed to get peers".to_string())
}

#[tauri::command]
pub async fn get_network_stats(
    state: tauri::State<'_, AppState>,
) -> Result<NetworkStats, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetNetworkStatsSnapshot { tx })
        .map_err(|e| format!("Network busy: {e}"))?;
    rx.await.map_err(|_| "Failed to get network stats".to_string())
}

#[tauri::command]
pub async fn ban_peer(
    state: tauri::State<'_, AppState>,
    peer_id: String,
) -> Result<(), String> {
    if peer_id.len() != 32 || !peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid peer ID (expected 32 hex characters)".into());
    }

    let db = state.db.clone();
    let pid = peer_id.clone();
    tokio::task::spawn_blocking(move || db.ban_peer(&pid))
        .await
        .map_err(|e| format!("Task error: {e}"))?
        .map_err(|e| format!("Failed to ban peer: {e}"))?;

    // Ban is already persisted to the DB above; the network task only
    // needs the peer ID to drop any active connections. If the channel
    // is full a current connection may linger briefly, but the ban
    // itself takes effect on next reconnect via the persistent banlist.
    if let Err(e) = state.network_tx.try_send(NetworkCommand::BanPeer {
        peer_id_hex: peer_id,
    }) {
        tracing::warn!("Peer banned in DB, but live-connection drop was not enqueued (channel full): {e}");
    }

    Ok(())
}

#[tauri::command]
pub async fn unban_peer(
    state: tauri::State<'_, AppState>,
    peer_id: String,
) -> Result<(), String> {
    if peer_id.len() != 32 || !peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid peer ID (expected 32 hex characters)".into());
    }

    let db = state.db.clone();
    let pid = peer_id.clone();
    tokio::task::spawn_blocking(move || db.unban_peer(&pid))
        .await
        .map_err(|e| format!("Task error: {e}"))?
        .map_err(|e| format!("Failed to unban peer: {e}"))?;

    // Unban is already persisted to the DB above; the network task
    // notification only refreshes the in-memory banned-IPs cache. If
    // the channel is full the cache catches up on next refresh cycle
    // — the user shouldn't see "unban failed" when the row is gone.
    if let Err(e) = state.network_tx.try_send(NetworkCommand::UnbanPeer {
        peer_id_hex: peer_id,
    }) {
        tracing::warn!("Peer unbanned in DB, but cache refresh was not enqueued (channel full): {e}");
    }

    Ok(())
}

#[tauri::command]
pub async fn kad_connect(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state
        .network_tx
        .try_send(NetworkCommand::KadConnect)
        .map_err(|e| format!("Network busy: {e}"))?;
    Ok(())
}

#[tauri::command]
pub async fn kad_disconnect(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state
        .network_tx
        .try_send(NetworkCommand::KadDisconnect)
        .map_err(|e| format!("Network busy: {e}"))?;
    Ok(())
}

#[tauri::command]
pub async fn kad_bootstrap_ip(
    state: tauri::State<'_, AppState>,
    ip: String,
    port: u16,
) -> Result<String, String> {
    if ip.is_empty() {
        return Err("IP address is required".into());
    }
    if port == 0 {
        return Err("Port must be greater than 0".into());
    }
    let resolved_ip = resolve_kad_host(&ip, port).await?;

    // K0: await the real outcome from the network task via oneshot so the UI
    // reports "sent"/"failed" based on what actually happened, not merely
    // that the command was enqueued.
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::KadBootstrapIp {
            ip: resolved_ip,
            port,
            tx,
        })
        .map_err(|e| format!("Network busy: {e}"))?;
    rx.await
        .map_err(|_| "Bootstrap worker dropped the request".to_string())?
}

#[tauri::command]
pub async fn kad_bootstrap_url(
    state: tauri::State<'_, AppState>,
    url: String,
) -> Result<String, String> {
    let (validated_url, host, resolved_addrs) = crate::security::validate_fetch_url(&url).await?;

    // K0: same oneshot pattern as kad_bootstrap_ip — this is what lets the
    // UI show "Loaded N contacts" on success and a useful error on failure
    // instead of always toasting "Fetching…" on enqueue.
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::KadBootstrapUrl {
            url: validated_url,
            host,
            resolved_addrs,
            tx,
        })
        .map_err(|e| format!("Network busy: {e}"))?;
    rx.await
        .map_err(|_| "Bootstrap worker dropped the request".to_string())?
}

#[tauri::command]
pub async fn kad_bootstrap_clients(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::KadBootstrapClients { tx })
        .map_err(|e| format!("Network busy: {e}"))?;
    rx.await
        .map_err(|_| "Failed to bootstrap from contacts".to_string())?
        .map(|_| ())
}

#[tauri::command]
pub async fn kad_recheck_firewall(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::RecheckFirewall { tx })
        .map_err(|e| format!("Network busy: {e}"))?;
    rx.await
        .map_err(|_| "Failed to start firewall recheck".to_string())?
        .map(|_| ())
}

#[tauri::command]
pub async fn get_kad_contacts(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<KadContactInfo>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetKadContactsSnapshot { tx })
        .map_err(|e| format!("Network busy: {e}"))?;
    rx.await.map_err(|_| "Failed to get KAD contacts".to_string())
}

#[tauri::command]
pub async fn get_kad_searches(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<KadSearchInfo>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetKadSearchesSnapshot { tx })
        .map_err(|e| format!("Network busy: {e}"))?;
    rx.await.map_err(|_| "Failed to get KAD searches".to_string())
}

/// User-initiated cancellation for an active KAD search. Accepts the
/// id as a string so the JS side can safely pass a u64 without the
/// 2^53-bit precision problem. Returns `()` on success; a missing/
/// invalid id or a completed search that has already been pruned both
/// surface as `Ok(())` so the UI can refresh idempotently.
#[tauri::command]
pub async fn kad_cancel_search(
    state: tauri::State<'_, AppState>,
    id: String,
) -> Result<(), String> {
    let parsed: u64 = id
        .parse()
        .map_err(|_| "Invalid search id".to_string())?;
    state
        .network_tx
        .try_send(NetworkCommand::CancelKadSearch { id: parsed })
        .map_err(|e| format!("Network busy: {e}"))?;
    Ok(())
}

#[tauri::command]
pub async fn get_peer_reputation(
    state: tauri::State<'_, AppState>,
    user_hash_hex: String,
) -> Result<Option<PeerReputationInfo>, String> {
    let hash = parse_user_hash(&user_hash_hex.to_lowercase())?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    state.network_tx.try_send(NetworkCommand::GetPeerReputation { user_hash: hash, tx })
        .map_err(|e| format!("Network busy: {e}"))?;
    rx.await.map_err(|_| "No response".to_string())
}

#[tauri::command]
pub async fn get_reputation_stats(
    state: tauri::State<'_, AppState>,
) -> Result<ReputationStatsInfo, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state.network_tx.try_send(NetworkCommand::GetReputationStats { tx })
        .map_err(|e| format!("Network busy: {e}"))?;
    rx.await.map_err(|_| "No response".to_string())
}
