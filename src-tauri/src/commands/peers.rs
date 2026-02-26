use tokio::sync::oneshot;

use crate::app_state::AppState;
use crate::network::NetworkCommand;
use crate::types::*;

#[tauri::command]
pub async fn get_peers(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<PeerInfo>, String> {
    let peers = state.cached_peers.read().await;
    Ok(peers.clone())
}

#[tauri::command]
pub async fn get_network_stats(
    state: tauri::State<'_, AppState>,
) -> Result<NetworkStats, String> {
    let stats = state.cached_stats.read().await;
    Ok(stats.clone())
}

#[tauri::command]
pub async fn ban_peer(
    state: tauri::State<'_, AppState>,
    peer_id: String,
) -> Result<(), String> {
    if peer_id.is_empty() || hex::decode(&peer_id).is_err() {
        return Err("Invalid peer ID".into());
    }

    state
        .db
        .ban_peer(&peer_id)
        .map_err(|e| format!("Failed to ban peer: {e}"))?;

    let _ = state
        .network_tx
        .try_send(NetworkCommand::BanPeer {
            peer_id_hex: peer_id,
        });

    Ok(())
}

#[tauri::command]
pub async fn unban_peer(
    state: tauri::State<'_, AppState>,
    peer_id: String,
) -> Result<(), String> {
    if peer_id.is_empty() || hex::decode(&peer_id).is_err() {
        return Err("Invalid peer ID".into());
    }

    state
        .db
        .unban_peer(&peer_id)
        .map_err(|e| format!("Failed to unban peer: {e}"))?;

    let _ = state
        .network_tx
        .try_send(NetworkCommand::UnbanPeer {
            peer_id_hex: peer_id,
        });

    Ok(())
}

#[tauri::command]
pub async fn kad_connect(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state
        .network_tx
        .send(NetworkCommand::KadConnect)
        .await
        .map_err(|e| format!("Failed to send KAD connect: {e}"))?;
    Ok(())
}

#[tauri::command]
pub async fn kad_disconnect(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state
        .network_tx
        .send(NetworkCommand::KadDisconnect)
        .await
        .map_err(|e| format!("Failed to send KAD disconnect: {e}"))?;
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

    state
        .network_tx
        .send(NetworkCommand::KadBootstrapIp { ip, port })
        .await
        .map_err(|e| format!("Failed to send bootstrap command: {e}"))?;
    Ok(())
}

#[tauri::command]
pub async fn kad_bootstrap_url(
    state: tauri::State<'_, AppState>,
    url: String,
) -> Result<(), String> {
    if url.is_empty() || !url.contains("://") {
        return Err("Invalid URL".into());
    }

    state
        .network_tx
        .send(NetworkCommand::KadBootstrapUrl { url })
        .await
        .map_err(|e| format!("Failed to send bootstrap command: {e}"))?;
    Ok(())
}

#[tauri::command]
pub async fn kad_bootstrap_clients(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state
        .network_tx
        .send(NetworkCommand::KadBootstrapClients)
        .await
        .map_err(|e| format!("Failed to send bootstrap command: {e}"))?;
    Ok(())
}

#[tauri::command]
pub async fn kad_recheck_firewall(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state
        .network_tx
        .send(NetworkCommand::RecheckFirewall)
        .await
        .map_err(|e| format!("Failed to send firewall recheck: {e}"))?;
    Ok(())
}

#[tauri::command]
pub async fn get_kad_contacts(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<KadContactInfo>, String> {
    let (tx, rx) = oneshot::channel();
    state
        .network_tx
        .send(NetworkCommand::GetKadContacts { tx })
        .await
        .map_err(|e| format!("Failed to request KAD contacts: {e}"))?;
    rx.await.map_err(|e| format!("Failed to receive KAD contacts: {e}"))
}

#[tauri::command]
pub async fn get_kad_searches(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<KadSearchInfo>, String> {
    let (tx, rx) = oneshot::channel();
    state
        .network_tx
        .send(NetworkCommand::GetKadSearches { tx })
        .await
        .map_err(|e| format!("Failed to request KAD searches: {e}"))?;
    rx.await.map_err(|e| format!("Failed to receive KAD searches: {e}"))
}
