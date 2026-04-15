use crate::app_state::AppState;
use crate::network::NetworkCommand;
use crate::storage::identity::NodeIdentity;
use crate::types::*;

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
        let friends = state.friend_hashes.read().await;
        if friends.len() as u32 >= max_friends {
            return Err(format!("Friend limit reached ({max_friends}). Increase the limit in Settings > Friends."));
        }
    }

    let db = state.db.clone();
    let db_hash = canonical.clone();
    let db_nick = nick.clone();
    tokio::task::spawn_blocking(move || db.add_friend(&db_hash, &db_nick))
        .await
        .map_err(|e| format!("Task error: {e}"))?
        .map_err(|e| format!("Failed to save friend: {e}"))?;

    state.friend_hashes.write().await.insert(hash);

    if state.network_tx.try_send(NetworkCommand::FindFriendAndConnect {
        ember_hash: hash,
    }).is_err() {
        tracing::warn!("Network channel full, friend {canonical} will connect on next source exchange");
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
    if let Err(_) = state.network_tx.try_send(NetworkCommand::FriendRemoved { ember_hash: hash }) {
        tracing::warn!("Network channel full when sending FriendRemoved for {}", hex::encode(hash));
    }
    Ok(())
}

#[tauri::command]
pub async fn update_friend_nickname(
    state: tauri::State<'_, AppState>,
    user_hash_hex: String,
    nickname: String,
) -> Result<(), String> {
    if nickname.len() > 256 {
        return Err("Nickname too long (max 256 bytes)".into());
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
        let friends = state.friend_hashes.read().await;
        if friends.len() as u32 >= max_friends {
            return Err(format!("Friend limit reached ({max_friends}). Increase the limit in Settings > Friends."));
        }
    }

    let db = state.db.clone();
    let c2 = canonical.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
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
    .await
    .map_err(|e| format!("Task error: {e}"))?
    .map_err(|e| format!("Failed to accept friend request: {e}"))?;

    state.friend_hashes.write().await.insert(hash);

    if state.network_tx.try_send(NetworkCommand::FindFriendAndConnect {
        ember_hash: hash,
    }).is_err() {
        tracing::warn!("Network channel full, accepted friend {canonical} will connect on next source exchange");
    }

    Ok(())
}

#[tauri::command]
pub async fn reject_friend_request(
    state: tauri::State<'_, AppState>,
    sender_hash: String,
) -> Result<(), String> {
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

    if let Err(_) = state.network_tx.try_send(NetworkCommand::BanPeer {
        peer_id_hex: peer_id,
    }) {
        tracing::warn!("Network channel full when sending BanPeer");
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

    if let Err(_) = state.network_tx.try_send(NetworkCommand::UnbanPeer {
        peer_id_hex: peer_id,
    }) {
        tracing::warn!("Network channel full when sending UnbanPeer");
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
) -> Result<(), String> {
    if ip.is_empty() {
        return Err("IP address is required".into());
    }
    if port == 0 {
        return Err("Port must be greater than 0".into());
    }
    let resolved_ip = resolve_kad_host(&ip, port).await?;

    state
        .network_tx
        .try_send(NetworkCommand::KadBootstrapIp { ip: resolved_ip, port })
        .map_err(|e| format!("Network busy: {e}"))?;
    Ok(())
}

#[tauri::command]
pub async fn kad_bootstrap_url(
    state: tauri::State<'_, AppState>,
    url: String,
) -> Result<(), String> {
    let (host, resolved_addrs) = crate::security::validate_fetch_url(&url).await?;

    state
        .network_tx
        .try_send(NetworkCommand::KadBootstrapUrl { url, host, resolved_addrs })
        .map_err(|e| format!("Network busy: {e}"))?;
    Ok(())
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
