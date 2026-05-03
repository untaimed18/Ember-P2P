use std::net::{IpAddr, SocketAddr};

use crate::app_state::AppState;
use crate::network::{NetworkCommand, PeerReputationInfo, ReputationStatsInfo};
use crate::storage::identity::NodeIdentity;
use crate::types::*;
use crate::types::EmberDiagnostics;

/// Result returned by the `ember_ping_peer` harness command — either
/// the round-trip time of the matching `Pong` or the reason the
/// transport could not deliver it.
#[derive(serde::Serialize)]
pub struct EmberPingResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Default round-trip timeout in milliseconds for `ember_ping_peer`.
/// Matches what the harness defaults the TS side to; explicit value
/// here so the backend has a sane bound even if the caller omits it.
const DEFAULT_EMBER_PING_TIMEOUT_MS: u64 = 5_000;
const MIN_EMBER_PING_TIMEOUT_MS: u64 = 100;
const MAX_EMBER_PING_TIMEOUT_MS: u64 = 60_000;

/// Maximum stored friend nickname size. L18: aligned with the
/// frontend `maxlength="64"` constraints in `+page.svelte` so a
/// peer who advertises a longer nickname (or a future rogue UI
/// surface) doesn't end up with rows that overflow the friends
/// list ellipsis breakpoints. The previous 256-byte ceiling was
/// generous-but-inconsistent: foreign nicknames truncated by the
/// backend at 256 chars couldn't be rendered cleanly anyway, and a
/// 256-char nickname pushed several columns of UI off-screen.
const MAX_FRIEND_NICKNAME_LEN: usize = 64;

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
    /// `true` iff the peer's advertised Ed25519 public key
    /// BLAKE3-bound to `sender_hash` at request-emit time. Used by
    /// the Friends UI to render a verification badge so users can
    /// distinguish requests backed by cryptographic identity from
    /// older unverified paths.
    pub verified: bool,
}

#[tauri::command]
pub async fn add_friend(
    state: tauri::State<'_, AppState>,
    user_hash_hex: String,
    nickname: Option<String>,
) -> Result<(), String> {
    let canonical = user_hash_hex.to_lowercase();
    let hash = parse_user_hash(&canonical)?;
    // L20: strip bidi/zero-width/control formatters from
    // user-supplied nicknames before they're written to the DB.
    // The friends list uses `<bdi>` to neutralise visual
    // reordering at render time (M14), but storing the override
    // character means it comes back the next time the user
    // exports the friends list, copies a name, or syncs to a
    // future sibling client.
    let nick = crate::security::sanitize_display_name(&nickname.unwrap_or_default());
    // `sanitize_display_name` substitutes "Anonymous" for empty
    // input; treat that the same as a too-short nickname so
    // adding a friend without specifying one keeps a sensible
    // default rather than the literal string "Anonymous".
    let nick = if nick == "Anonymous" { String::new() } else { nick };
    if nick.len() > MAX_FRIEND_NICKNAME_LEN {
        return Err(format!(
            "Nickname too long (max {MAX_FRIEND_NICKNAME_LEN} bytes)"
        ));
    }

    let our_ember_hash = {
        let data_dir = crate::storage::paths::resolve_data_dir();
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
    // L20: same sanitisation pass as `add_friend` so a rename to
    // an injected bidi/zero-width payload doesn't slip past.
    let cleaned = crate::security::sanitize_display_name(&nickname);
    let cleaned = if cleaned == "Anonymous" && nickname.trim().is_empty() {
        String::new()
    } else {
        cleaned
    };
    if cleaned.len() > MAX_FRIEND_NICKNAME_LEN {
        return Err(format!(
            "Nickname too long (max {MAX_FRIEND_NICKNAME_LEN} bytes)"
        ));
    }
    let canonical = user_hash_hex.to_lowercase();
    parse_user_hash(&canonical)?;

    let db = state.db.clone();
    let db_hash = canonical;
    let db_nick = cleaned;
    let updated = tokio::task::spawn_blocking(move || db.update_friend_nickname(&db_hash, &db_nick))
        .await
        .map_err(|e| format!("Task error: {e}"))?
        .map_err(|e| format!("Failed to update friend: {e}"))?;
    // Returning Err for "no matching row" rather than the previous
    // silent success: the UI used to accept the result and write the
    // typed nickname into local state, then `loadFriends()` would
    // overwrite it back to the original. The failure mode looked like
    // a UI bug ("rename didn't stick") but was really a backend
    // contract problem — the friend may have been removed from
    // another window while the user was editing.
    if !updated {
        return Err("Friend no longer exists".into());
    }
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
    let data_dir = crate::storage::paths::resolve_data_dir();
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
    // L20: strip control / bidi-override / zero-width / variation
    // selector code points from outbound chat. Inbound chat is
    // already protected from visual reordering by the `<bdi>`
    // wrapping in `ChatSidebar.svelte` (M14), but the underlying
    // text would still carry the override characters across the
    // wire and into the recipient's database. Sanitising on
    // egress means our peers see only the visible content and
    // never store the spoofing primitive.
    let cleaned = crate::security::sanitize_chat_text(&message);
    if cleaned.trim().is_empty() {
        return Err("Message is empty after sanitisation".into());
    }
    let canonical = user_hash_hex.to_lowercase();
    let hash = parse_user_hash(&canonical)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    state.network_tx.send(NetworkCommand::SendChatMessage {
        ember_hash: hash,
        message: cleaned,
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

    Ok(rows.into_iter().map(|(sender_hash, sender_nickname, received_at, _ip, _port, verified)| FriendRequestInfo {
        sender_hash,
        sender_nickname,
        received_at,
        verified,
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
        let data_dir = crate::storage::paths::resolve_data_dir();
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

    // Atomic DB write: nickname pull from the matching friend_request
    // row, INSERT/UPDATE friend with `mutual = 1` and the address
    // captured at request time, DELETE the request — all in one
    // transaction. Replaces three independent execute() calls that
    // could half-succeed and leave an orphan unmutual friend in the
    // DB while the in-memory friend_hashes set was rolled back. See
    // `Database::accept_friend_request` for details.
    let db = state.db.clone();
    let c2 = canonical.clone();
    let db_result = tokio::task::spawn_blocking(move || db.accept_friend_request(&c2)).await;
    let request_addr = match db_result {
        Ok(Ok(addr)) => addr,
        Ok(Err(e)) => {
            state.friend_hashes.write().await.remove(&hash);
            return Err(format!("Failed to accept friend request: {e}"));
        }
        Err(e) => {
            state.friend_hashes.write().await.remove(&hash);
            return Err(format!("Task error: {e}"));
        }
    };

    // Reuse the IP/port the requester left in their friend_requests
    // row (captured by `add_friend_request` at receive time). Without
    // this, every accept paid for a fresh rendezvous round trip even
    // though we already had a known-good address moments ago.
    // `request_addr` may be `None` for requests that arrived without
    // an address (legacy data migrated up); fall back to the rendezvous
    // path in that case.
    let has_seed_addr = request_addr
        .as_ref()
        .map(|(_, ip, port)| !ip.is_empty() && *port > 0)
        .unwrap_or(false);
    if has_seed_addr {
        // We've already written `last_ip` / `last_port` inside the
        // transaction above; the network task's `SendChatMessage` /
        // `BrowseFriend` paths read those columns directly when the
        // user starts a conversation, so no extra plumbing is needed
        // here. Trigger a friend-search anyway so the friend goes
        // online immediately after the first dial succeeds.
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

/// Look up the reputation record for a single peer by user-hash. The
/// backend's `ReputationTracker` runs in-memory and is consulted for
/// ban decisions; this is the only IPC surface that exposes its state
/// to the UI (trust badge / per-peer diagnostics).
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

/// Aggregate reputation-tracker stats for the security / statistics
/// UI. Same-only-path rationale as `get_peer_reputation`.
#[tauri::command]
pub async fn get_reputation_stats(
    state: tauri::State<'_, AppState>,
) -> Result<ReputationStatsInfo, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state.network_tx.try_send(NetworkCommand::GetReputationStats { tx })
        .map_err(|e| format!("Network busy: {e}"))?;
    rx.await.map_err(|_| "No response".to_string())
}

/// Developer / harness-facing diagnostic counters for the Ember mesh:
/// EPX event counts, broker punch / relay outcomes, and the size of
/// the mesh peer cache. Distinct from `get_network_stats` so the
/// hot status-bar IPC payload stays small and user-focused.
#[tauri::command]
pub async fn get_ember_diagnostics(
    state: tauri::State<'_, AppState>,
) -> Result<EmberDiagnostics, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state.network_tx.try_send(NetworkCommand::GetEmberDiagnostics { tx })
        .map_err(|e| format!("Network busy: {e}"))?;
    rx.await.map_err(|_| "No response".to_string())
}

/// Send an Ember-native `Ping` to a peer over the Noise transport and
/// wait up to `timeout_ms` for the matching `Pong`. Used by the local
/// harness (`scripts\harness.ps1`) to verify the feature-flagged
/// integration end-to-end.
///
/// `peer_pubkey_hex` is **optional**. When provided, it must be the
/// 64-char hex encoding of the peer's `local_noise_public_key` (also
/// returned by `get_ember_diagnostics`). When omitted (or empty), the
/// network task looks the pubkey up in the cache populated from KAD
/// source publishes — the production path. A cache miss is reported
/// as a clear error so the harness can distinguish "we don't know
/// this peer" from "Noise handshake failed".
///
/// `peer_ip` is parsed as an IPv4 / IPv6 literal — DNS is
/// intentionally not resolved here, since the harness deals in
/// `127.0.0.1` and explicit addresses only.
#[tauri::command]
pub async fn ember_ping_peer(
    state: tauri::State<'_, AppState>,
    peer_ip: String,
    peer_port: u16,
    peer_pubkey_hex: Option<String>,
    timeout_ms: Option<u64>,
) -> Result<EmberPingResult, String> {
    let timeout = timeout_ms
        .unwrap_or(DEFAULT_EMBER_PING_TIMEOUT_MS)
        .clamp(MIN_EMBER_PING_TIMEOUT_MS, MAX_EMBER_PING_TIMEOUT_MS);

    if peer_port == 0 {
        return Err("peer_port must be > 0".into());
    }

    let ip: IpAddr = peer_ip
        .parse()
        .map_err(|e| format!("Invalid peer_ip '{peer_ip}': {e}"))?;
    let addr = SocketAddr::new(ip, peer_port);

    // Treat both an absent field and an empty string as "look it up
    // from the KAD-fed Noise key cache". The IPC layer can't
    // distinguish those two on the JS side cleanly, so collapsing
    // them here keeps the two valid invocations
    // (`ember_ping_peer({...})` with no pubkey and
    // `ember_ping_peer({..., peerPubkeyHex: ''})`) both working.
    let peer_pubkey: Option<[u8; 32]> = match peer_pubkey_hex.as_deref() {
        Some(s) if !s.is_empty() => {
            let bytes = hex::decode(s)
                .map_err(|e| format!("peer_pubkey_hex is not valid hex: {e}"))?;
            if bytes.len() != 32 {
                return Err(format!(
                    "peer_pubkey_hex must decode to 32 bytes, got {}",
                    bytes.len()
                ));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            Some(k)
        }
        _ => None,
    };

    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::SendEmberPing {
            addr,
            peer_pubkey,
            tx,
        })
        .map_err(|e| format!("Network busy: {e}"))?;

    let scheduled = match rx.await.map_err(|_| "No response from network".to_string())? {
        Ok(p) => p,
        Err(e) => {
            return Ok(EmberPingResult {
                success: false,
                rtt_ms: None,
                error: Some(e),
            })
        }
    };

    match tokio::time::timeout(
        std::time::Duration::from_millis(timeout),
        scheduled.pong_rx,
    )
    .await
    {
        Ok(Ok(rtt)) => Ok(EmberPingResult {
            success: true,
            rtt_ms: Some(rtt.as_secs_f64() * 1_000.0),
            error: None,
        }),
        Ok(Err(_)) => Ok(EmberPingResult {
            success: false,
            rtt_ms: None,
            error: Some("Network task dropped pong oneshot".into()),
        }),
        Err(_) => Ok(EmberPingResult {
            success: false,
            rtt_ms: None,
            error: Some(format!("Timed out after {timeout} ms")),
        }),
    }
}
