use crate::app_state::AppState;
use crate::network::ed2k::collection::{Collection, CollectionFile};

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
