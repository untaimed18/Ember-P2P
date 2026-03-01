use crate::app_state::AppState;
use crate::network::ed2k::collection::{Collection, CollectionFile};
use crate::types::{Transfer, TransferStatus, TransferDirection};

#[tauri::command]
pub async fn load_collection(
    path: String,
) -> Result<Collection, String> {
    let p = std::path::PathBuf::from(&path);
    if !p.exists() {
        return Err("File does not exist".into());
    }
    Collection::load(&p).map_err(|e| format!("Failed to load collection: {e}"))
}

#[tauri::command]
pub async fn create_collection(
    name: String,
    author: String,
    files: Vec<CollectionFile>,
    output_path: String,
    binary: bool,
) -> Result<String, String> {
    let collection = Collection {
        name: name.clone(),
        author,
        files,
    };
    let path = std::path::PathBuf::from(&output_path);
    if binary {
        collection.save_binary(&path).map_err(|e| format!("Failed to save: {e}"))?;
    } else {
        collection.save_text(&path).map_err(|e| format!("Failed to save: {e}"))?;
    }
    Ok(format!("Created collection '{name}' at {output_path}"))
}

#[tauri::command]
pub async fn download_collection_files(
    state: tauri::State<'_, AppState>,
    files: Vec<CollectionFile>,
) -> Result<String, String> {
    let count = files.len();
    for file in files {
        if file.hash.is_empty() || file.name.is_empty() {
            continue;
        }
        let transfer_id = uuid::Uuid::new_v4().to_string();
        let control = crate::sharing::manager::TransferControl::new();

        let transfer = Transfer {
            id: transfer_id.clone(),
            file_name: file.name.clone(),
            file_hash: file.hash.clone(),
            peer_id: String::new(),
            peer_name: String::new(),
            direction: TransferDirection::Download,
            status: TransferStatus::Searching,
            progress: 0.0,
            speed: 0,
            total_size: file.size,
            transferred: 0,
            completed_size: 0,
            started_at: chrono::Utc::now().timestamp(),
            failure_reason: None,
            priority: "normal".to_string(),
            sources: 0,
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
            let mut mgr = state.transfer_manager.write().await;
            mgr.enqueue(transfer);
            mgr.register_control(&transfer_id, control.clone());
        }

        let _ = state.network_tx.try_send(crate::network::NetworkCommand::StartDownload {
            file_hash: file.hash,
            file_name: file.name,
            file_size: file.size,
            peer_ip: String::new(),
            peer_port: 0,
            transfer_id,
            control,
        });
    }
    Ok(format!("Queued {count} files for download"))
}
