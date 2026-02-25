use crate::app_state::AppState;
use crate::network::NetworkCommand;
use crate::sharing::manager::TransferControl;
use crate::types::*;

#[tauri::command]
pub async fn start_download(
    state: tauri::State<'_, AppState>,
    file_hash: String,
    file_name: String,
    file_size: u64,
    peer_ip: String,
    peer_port: u16,
) -> Result<String, String> {
    let transfer_id = uuid::Uuid::new_v4().to_string();

    let has_source = !peer_ip.is_empty() && peer_ip != "0.0.0.0" && peer_port > 0;

    let control = TransferControl::new();

    let transfer = Transfer {
        id: transfer_id.clone(),
        file_name: file_name.clone(),
        file_hash: file_hash.clone(),
        peer_id: if has_source {
            format!("{peer_ip}:{peer_port}")
        } else {
            String::new()
        },
        peer_name: String::new(),
        direction: TransferDirection::Download,
        status: if has_source {
            TransferStatus::Queued
        } else {
            TransferStatus::Searching
        },
        progress: 0.0,
        speed: 0,
        total_size: file_size,
        transferred: 0,
        started_at: chrono::Utc::now().timestamp(),
    };

    {
        let mut manager = state.transfer_manager.write().await;
        manager.enqueue(transfer);
        manager.register_control(&transfer_id, control.clone());
    }

    state
        .network_tx
        .send(NetworkCommand::StartDownload {
            file_hash,
            file_name,
            file_size,
            peer_ip,
            peer_port,
            transfer_id: transfer_id.clone(),
            control,
        })
        .await
        .map_err(|e| format!("Failed to start download: {e}"))?;

    Ok(transfer_id)
}

#[tauri::command]
pub async fn pause_transfer(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let mut manager = state.transfer_manager.write().await;
    manager.pause(&transfer_id);
    Ok(())
}

#[tauri::command]
pub async fn resume_transfer(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let mut manager = state.transfer_manager.write().await;
    manager.resume(&transfer_id);
    Ok(())
}

#[tauri::command]
pub async fn cancel_transfer(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let mut manager = state.transfer_manager.write().await;
    manager.cancel(&transfer_id);
    Ok(())
}

#[tauri::command]
pub async fn get_transfers(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<Transfer>, String> {
    let manager = state.transfer_manager.read().await;
    Ok(manager.get_all())
}
