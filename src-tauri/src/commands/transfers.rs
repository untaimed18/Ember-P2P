use tauri::Emitter;

use crate::app_state::AppState;
use crate::network::NetworkCommand;
use crate::sharing::manager::TransferControl;
use crate::types::*;

#[tauri::command]
pub async fn start_download(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    file_hash: String,
    file_name: String,
    file_size: u64,
    peer_ip: String,
    peer_port: u16,
) -> Result<String, String> {
    let file_name = crate::security::sanitize_filename(&file_name);

    if file_hash.len() != 32 || hex::decode(&file_hash).is_err() {
        return Err("Invalid file hash".into());
    }

    if !peer_ip.is_empty() {
        peer_ip
            .parse::<std::net::IpAddr>()
            .map_err(|_| "Invalid peer IP")?;
    }

    if file_size == 0 {
        return Err("File size must be greater than 0".into());
    }

    let transfer_id = uuid::Uuid::new_v4().to_string();

    let has_source = !peer_ip.is_empty() && peer_ip != "0.0.0.0" && peer_port > 0;

    let add_paused = {
        let config = state.config.read().await;
        config.settings.add_downloads_paused
    };
    let control = TransferControl::new();
    if add_paused {
        control.pause();
    }

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
        status: if add_paused {
            TransferStatus::Paused
        } else if has_source {
            TransferStatus::Queued
        } else {
            TransferStatus::Searching
        },
        progress: 0.0,
        speed: 0,
        total_size: file_size,
        transferred: 0,
        completed_size: 0,
        started_at: chrono::Utc::now().timestamp(),
        failure_reason: None,
        priority: "normal".to_string(),
        sources: if has_source { 1 } else { 0 },
        active_sources: 0,
        queued_sources: 0,
        queue_rank: None,
        last_seen_complete: None,
        last_received: None,
        category: String::new(),
        wait_time: 0,
        upload_time: 0,
        a4af_sources: 0,
        max_sources: 0,
        preview_priority: false,
    };

    {
        let mut manager = state.transfer_manager.write().await;
        manager.enqueue(transfer.clone());
        manager.register_control(&transfer_id, control.clone());
    }

    let _ = app.emit("transfer-started", &transfer);

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

/// eMule "Stop": removes from active download without deleting files.
/// Different from Pause - a stopped file won't automatically resume.
#[tauri::command]
pub async fn stop_transfer(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let mut manager = state.transfer_manager.write().await;
    manager.stop(&transfer_id);
    Ok(())
}

#[tauri::command]
pub async fn open_file(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let transfer = {
        let manager = state.transfer_manager.read().await;
        manager.get_transfer(&transfer_id).cloned()
    };
    let transfer = transfer.ok_or("Transfer not found")?;
    if transfer.status != TransferStatus::Completed {
        return Err("File is not completed".into());
    }
    let config = state.config.read().await;
    let file_path = std::path::PathBuf::from(&config.settings.download_folder)
        .join("Downloads")
        .join(&transfer.file_name);
    if !file_path.exists() {
        return Err("File not found on disk".into());
    }
    let path_str = file_path.to_string_lossy().to_string();
    tokio::task::spawn_blocking(move || {
        let _ = opener::open(&path_str);
    }).await.map_err(|e| format!("Failed to open file: {e}"))?;
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
    let promoted = {
        let mut manager = state.transfer_manager.write().await;
        manager.cancel(&transfer_id)
    };

    // Clean up .part and .part.met files
    {
        let config = state.config.read().await;
        let dl_folder = config.settings.download_folder.clone();
        let tid = transfer_id.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let temp_dir = std::path::PathBuf::from(&dl_folder).join("Temp");
            let part_path = temp_dir.join(format!("{tid}.part"));
            let met_path = temp_dir.join(format!("{tid}.part.met"));
            if part_path.exists() {
                let _ = std::fs::remove_file(&part_path);
                tracing::debug!("Deleted part file: {}", part_path.display());
            }
            if met_path.exists() {
                let _ = std::fs::remove_file(&met_path);
                tracing::debug!("Deleted met file: {}", met_path.display());
            }
        }).await;
    }

    {
        let db = state.db.clone();
        let tid = transfer_id.clone();
        let _ = tokio::task::spawn_blocking(move || db.remove_transfer(&tid)).await;
    }

    for t in &promoted {
        let control = crate::sharing::manager::TransferControl::new();
        {
            let mut manager = state.transfer_manager.write().await;
            manager.register_control(&t.id, control.clone());
        }
        let _ = state
            .network_tx
            .send(NetworkCommand::StartDownload {
                file_hash: t.file_hash.clone(),
                file_name: t.file_name.clone(),
                file_size: t.total_size,
                peer_ip: t.peer_id.split(':').next().unwrap_or("").to_string(),
                peer_port: t.peer_id.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(0),
                transfer_id: t.id.clone(),
                control,
            })
            .await;
    }
    Ok(())
}

#[tauri::command]
pub async fn remove_transfer(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    {
        let mut manager = state.transfer_manager.write().await;
        manager.remove(&transfer_id);
    }
    // Clean up .part and .part.met files (if they exist from an incomplete download)
    {
        let config = state.config.read().await;
        let dl_folder = config.settings.download_folder.clone();
        let tid = transfer_id.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let temp_dir = std::path::PathBuf::from(&dl_folder).join("Temp");
            let part_path = temp_dir.join(format!("{tid}.part"));
            let met_path = temp_dir.join(format!("{tid}.part.met"));
            if part_path.exists() {
                let _ = std::fs::remove_file(&part_path);
            }
            if met_path.exists() {
                let _ = std::fs::remove_file(&met_path);
            }
        }).await;
    }
    {
        let db = state.db.clone();
        let tid = transfer_id.clone();
        let _ = tokio::task::spawn_blocking(move || db.remove_transfer(&tid)).await;
    }
    Ok(())
}

#[tauri::command]
pub async fn get_transfers(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<Transfer>, String> {
    let manager = state.transfer_manager.read().await;
    Ok(manager.get_all())
}

#[tauri::command]
pub async fn set_transfer_priority(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
    priority: String,
) -> Result<(), String> {
    let valid = ["low", "normal", "high", "auto"];
    if !valid.contains(&priority.as_str()) {
        return Err(format!("Invalid priority: {priority}. Must be one of: {valid:?}"));
    }
    let mut manager = state.transfer_manager.write().await;
    manager.set_priority(&transfer_id, &priority);
    Ok(())
}

#[tauri::command]
pub async fn set_preview_priority(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
    enabled: bool,
) -> Result<(), String> {
    let mut manager = state.transfer_manager.write().await;
    manager.set_preview_priority(&transfer_id, enabled);
    Ok(())
}

#[tauri::command]
pub async fn pause_all_transfers(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let mut manager = state.transfer_manager.write().await;
    let ids: Vec<String> = manager.active.keys().cloned().collect();
    for id in ids {
        manager.pause(&id);
    }
    Ok(())
}

#[tauri::command]
pub async fn resume_all_transfers(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let mut manager = state.transfer_manager.write().await;
    let ids: Vec<String> = manager.active.keys().cloned().collect();
    for id in ids {
        manager.resume(&id);
    }
    Ok(())
}

#[tauri::command]
pub async fn get_transfer_sources(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<Vec<crate::types::SourceInfo>, String> {
    let manager = state.transfer_manager.read().await;
    Ok(manager.get_source_details(&transfer_id))
}

#[tauri::command]
pub async fn clear_completed(
    state: tauri::State<'_, AppState>,
) -> Result<u32, String> {
    let mut manager = state.transfer_manager.write().await;
    let count = manager.completed.len() as u32;
    let ids: Vec<String> = manager.completed.iter().map(|t| t.id.clone()).collect();
    manager.completed.clear();
    drop(manager);

    let dl_folder = {
        let config = state.config.read().await;
        config.settings.download_folder.clone()
    };
    let db = state.db.clone();
    let _ = tokio::task::spawn_blocking(move || {
        let temp_dir = std::path::PathBuf::from(&dl_folder).join("Temp");
        for id in &ids {
            let _ = db.remove_transfer(id);
            let part_path = temp_dir.join(format!("{id}.part"));
            let met_path = temp_dir.join(format!("{id}.part.met"));
            if part_path.exists() {
                let _ = std::fs::remove_file(&part_path);
            }
            if met_path.exists() {
                let _ = std::fs::remove_file(&met_path);
            }
        }
    }).await;
    Ok(count)
}

#[tauri::command]
pub async fn recover_archive(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<String, String> {
    let (file_name, file_size, transfer_id_clone) = {
        let manager = state.transfer_manager.read().await;
        let transfer = manager.get_transfer(&transfer_id)
            .ok_or("Transfer not found")?;
        (transfer.file_name.clone(), transfer.total_size, transfer.id.clone())
    };

    if !crate::network::ed2k::archive_recovery::is_recoverable_archive(&file_name) {
        return Err("File is not a supported archive format (ZIP, RAR, ACE)".into());
    }

    let dl_folder = {
        let config = state.config.read().await;
        config.settings.download_folder.clone()
    };

    let part_path = std::path::PathBuf::from(&dl_folder)
        .join("Temp")
        .join(format!("{transfer_id_clone}.part"));

    if !part_path.exists() {
        return Err("Part file not found — download may not have started".into());
    }

    let filled_ranges = {
        let tracker = crate::network::ed2k::part_tracker::PartTracker::new(file_size, &part_path);
        tracker.filled_ranges()
    };

    if filled_ranges.is_empty() {
        return Err("No completed parts available for recovery".into());
    }

    let fname = file_name.clone();
    let result = tokio::task::spawn_blocking(move || {
        crate::network::ed2k::archive_recovery::recover_archive(&part_path, &fname, &filled_ranges)
    })
    .await
    .map_err(|e| format!("Recovery task failed: {e}"))?
    .map_err(|e| format!("Recovery failed: {e}"))?;

    Ok(result.to_string_lossy().to_string())
}
