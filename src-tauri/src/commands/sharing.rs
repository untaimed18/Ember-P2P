use crate::app_state::AppState;
use crate::network::NetworkCommand;
use crate::sharing::indexer::FileIndexer;
use crate::types::*;

#[tauri::command]
pub async fn add_shared_folder(
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<Vec<FileInfo>, String> {
    let scan_path = path.clone();
    let files =
        tokio::task::spawn_blocking(move || FileIndexer::scan_directory(&scan_path))
            .await
            .map_err(|e| format!("Scan failed: {e}"))?;

    {
        let mut index = state.local_index.write().await;
        index.add_files(files.clone());
    }

    for file in &files {
        state
            .db
            .save_shared_file(file)
            .map_err(|e| format!("DB error: {e}"))?;
    }

    state
        .network_tx
        .send(NetworkCommand::AnnounceFiles {
            files: files.clone(),
        })
        .await
        .map_err(|e| format!("Failed to announce files: {e}"))?;

    let mut config = state.config.write().await;
    if !config.settings.shared_folders.contains(&path) {
        config.settings.shared_folders.push(path);
        config.save().map_err(|e| format!("Config save error: {e}"))?;
    }

    Ok(files)
}

#[tauri::command]
pub async fn remove_shared_folder(
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<(), String> {
    // Collect hashes of files being removed so we can unannounce them
    let removed_hashes: Vec<String> = {
        let index = state.local_index.read().await;
        index
            .all_files()
            .iter()
            .filter(|f| f.path.starts_with(&path))
            .map(|f| f.hash.clone())
            .collect()
    };

    let mut config = state.config.write().await;
    config.settings.shared_folders.retain(|f| f != &path);
    config.save().map_err(|e| format!("Config save error: {e}"))?;

    let mut index = state.local_index.write().await;
    index.clear();

    state
        .db
        .clear_shared_files()
        .map_err(|e| format!("DB error: {e}"))?;

    for folder in &config.settings.shared_folders {
        let folder = folder.clone();
        let files =
            tokio::task::spawn_blocking(move || FileIndexer::scan_directory(&folder))
                .await
                .map_err(|e| format!("Scan failed: {e}"))?;
        index.add_files(files);
    }

    // Unannounce removed files from the KAD network
    if !removed_hashes.is_empty() {
        let _ = state
            .network_tx
            .send(NetworkCommand::UnannounceFiles {
                file_hashes: removed_hashes,
            })
            .await;
    }

    Ok(())
}

#[tauri::command]
pub async fn get_shared_files(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<FileInfo>, String> {
    let index = state.local_index.read().await;
    Ok(index.all_files().to_vec())
}

#[tauri::command]
pub async fn get_shared_folders(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let config = state.config.read().await;
    Ok(config.settings.shared_folders.clone())
}
