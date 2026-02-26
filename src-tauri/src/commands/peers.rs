use tokio::sync::oneshot;

use crate::app_state::AppState;
use crate::network::NetworkCommand;
use crate::types::*;

#[tauri::command]
pub async fn get_peers(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<PeerInfo>, String> {
    let (tx, rx) = oneshot::channel();

    state
        .network_tx
        .send(NetworkCommand::GetPeers { tx })
        .await
        .map_err(|e| format!("Failed to get peers: {e}"))?;

    rx.await.map_err(|e| format!("Failed to receive peers: {e}"))
}

#[tauri::command]
pub async fn get_network_stats(
    state: tauri::State<'_, AppState>,
) -> Result<NetworkStats, String> {
    let (tx, rx) = oneshot::channel();

    state
        .network_tx
        .send(NetworkCommand::GetStats { tx })
        .await
        .map_err(|e| format!("Failed to get stats: {e}"))?;

    rx.await
        .map_err(|e| format!("Failed to receive stats: {e}"))
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
        .send(NetworkCommand::BanPeer {
            peer_id_hex: peer_id,
        })
        .await;

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
        .send(NetworkCommand::UnbanPeer {
            peer_id_hex: peer_id,
        })
        .await;

    Ok(())
}
