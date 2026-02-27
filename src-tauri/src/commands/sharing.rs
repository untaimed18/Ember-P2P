use crate::app_state::AppState;
use crate::network::NetworkCommand;
use crate::sharing::indexer::FileIndexer;
use crate::types::*;
use tracing::info;

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

    {
        let mut index = state.local_index.write().await;
        index.remove_files_by_path_prefix(&path);
    }

    for hash in &removed_hashes {
        let _ = state.db.remove_shared_file_by_hash(hash);
    }

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

#[tauri::command]
pub async fn set_file_priority(
    state: tauri::State<'_, AppState>,
    file_hash: String,
    priority: String,
) -> Result<(), String> {
    let valid = ["verylow", "low", "normal", "high", "release", "auto"];
    if !valid.contains(&priority.as_str()) {
        return Err(format!("Invalid priority: {priority}"));
    }
    let mut index = state.local_index.write().await;
    if index.set_file_priority(&file_hash, &priority) {
        info!("Set priority for {} to {}", file_hash, priority);
        Ok(())
    } else {
        Err("File not found".to_string())
    }
}

#[tauri::command]
pub async fn reload_shared_files(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<FileInfo>, String> {
    let folders = {
        let config = state.config.read().await;
        config.settings.shared_folders.clone()
    };

    let all_files: Vec<FileInfo> = tokio::task::spawn_blocking(move || {
        let mut files = Vec::new();
        for folder in &folders {
            files.extend(FileIndexer::scan_directory(folder));
        }
        files
    })
    .await
    .map_err(|e| format!("Scan failed: {e}"))?;

    {
        let mut index = state.local_index.write().await;
        // Clear and rebuild
        for file in &all_files {
            if index.get_by_hash(&file.hash).is_none() {
                index.add_file(file.clone());
            }
        }
    }

    let _ = state
        .network_tx
        .send(NetworkCommand::AnnounceFiles {
            files: all_files.clone(),
        })
        .await;

    let index = state.local_index.read().await;
    Ok(index.all_files().to_vec())
}

#[tauri::command]
pub async fn unshare_file(
    state: tauri::State<'_, AppState>,
    file_hash: String,
) -> Result<(), String> {
    let removed = {
        let mut index = state.local_index.write().await;
        index.remove_file_by_hash(&file_hash)
    };

    if removed.is_some() {
        let _ = state.db.remove_shared_file_by_hash(&file_hash);
        let _ = state
            .network_tx
            .send(NetworkCommand::UnannounceFiles {
                file_hashes: vec![file_hash],
            })
            .await;
    }

    Ok(())
}

#[tauri::command]
pub async fn open_shared_file(file_path: String) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/c", "start", "", &file_path])
            .spawn()
            .map_err(|e| format!("Failed to open file: {e}"))?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&file_path)
            .spawn()
            .map_err(|e| format!("Failed to open file: {e}"))?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&file_path)
            .spawn()
            .map_err(|e| format!("Failed to open file: {e}"))?;
    }
    Ok(())
}

#[tauri::command]
pub async fn open_shared_folder(file_path: String) -> Result<(), String> {
    let path = std::path::Path::new(&file_path);
    let folder = path.parent().unwrap_or(path).to_string_lossy().to_string();
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(&folder)
            .spawn()
            .map_err(|e| format!("Failed to open folder: {e}"))?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&folder)
            .spawn()
            .map_err(|e| format!("Failed to open folder: {e}"))?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&folder)
            .spawn()
            .map_err(|e| format!("Failed to open folder: {e}"))?;
    }
    Ok(())
}
