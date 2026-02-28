use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::app_state::AppState;
use crate::network::NetworkCommand;
use crate::sharing::indexer::FileIndexer;
use crate::storage::database::Database;
use crate::types::*;
use tracing::info;

#[tauri::command]
pub async fn add_shared_folder(
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<(), String> {
    {
        let mut config = state.config.write().await;
        if !config.settings.shared_folders.contains(&path) {
            config.settings.shared_folders.push(path.clone());
            config.save().map_err(|e| format!("Config save error: {e}"))?;
        }
    }

    let local_index = state.local_index.clone();
    let db = state.db.clone();
    let network_tx = state.network_tx.clone();
    let scanning = state.scanning_count.clone();

    scanning.fetch_add(1, Ordering::Relaxed);

    tokio::spawn(async move {
        let scan_path = path.clone();
        let files = match tokio::task::spawn_blocking(move || {
            FileIndexer::scan_directory(&scan_path)
        })
        .await
        {
            Ok(files) => files,
            Err(e) => {
                tracing::error!("Background scan failed for {path}: {e}");
                scanning.fetch_sub(1, Ordering::Relaxed);
                return;
            }
        };

        {
            let mut index = local_index.write().await;
            index.add_files(files.clone());
        }

        let db_files = files.clone();
        let db_ref = db.clone();
        let _ = tokio::task::spawn_blocking(move || {
            save_files_to_db(&db_ref, &db_files);
        })
        .await;

        let _ = network_tx
            .send(NetworkCommand::AnnounceFiles {
                files: files.clone(),
            })
            .await;
        let _ = network_tx.send(NetworkCommand::SharedFilesChanged).await;

        scanning.fetch_sub(1, Ordering::Relaxed);
        info!("Background scan complete: {} files from {}", files.len(), path);
    });

    Ok(())
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

    {
        let mut config = state.config.write().await;
        config.settings.shared_folders.retain(|f| f != &path);
        config.save().map_err(|e| format!("Config save error: {e}"))?;
    }

    {
        let mut index = state.local_index.write().await;
        index.remove_files_by_path_prefix(&path);
    }

    // Batch DB deletes on a blocking thread
    let db = state.db.clone();
    let hashes = removed_hashes.clone();
    tokio::task::spawn_blocking(move || {
        for hash in &hashes {
            let _ = db.remove_shared_file_by_hash(hash);
        }
    })
    .await
    .map_err(|e| format!("DB cleanup failed: {e}"))?;

    if !removed_hashes.is_empty() {
        let _ = state
            .network_tx
            .send(NetworkCommand::UnannounceFiles {
                file_hashes: removed_hashes,
            })
            .await;
        let _ = state.network_tx.send(NetworkCommand::SharedFilesChanged).await;
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
) -> Result<(), String> {
    let folders = {
        let config = state.config.read().await;
        config.settings.shared_folders.clone()
    };

    let local_index = state.local_index.clone();
    let network_tx = state.network_tx.clone();
    let scanning = state.scanning_count.clone();

    scanning.fetch_add(1, Ordering::Relaxed);

    tokio::spawn(async move {
        let all_files: Vec<FileInfo> = match tokio::task::spawn_blocking(move || {
            let mut files = Vec::new();
            for folder in &folders {
                files.extend(FileIndexer::scan_directory(folder));
            }
            files
        })
        .await
        {
            Ok(files) => files,
            Err(e) => {
                tracing::error!("Reload scan failed: {e}");
                scanning.fetch_sub(1, Ordering::Relaxed);
                return;
            }
        };

        {
            let mut index = local_index.write().await;
            for file in &all_files {
                if index.get_by_hash(&file.hash).is_none() {
                    index.add_file(file.clone());
                }
            }
        }

        let _ = network_tx
            .send(NetworkCommand::AnnounceFiles {
                files: all_files,
            })
            .await;
        let _ = network_tx.send(NetworkCommand::SharedFilesChanged).await;

        scanning.fetch_sub(1, Ordering::Relaxed);
        info!("Background reload scan complete");
    });

    Ok(())
}

#[tauri::command]
pub async fn get_scan_status(
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    Ok(state.scanning_count.load(Ordering::Relaxed) > 0)
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
        let db = state.db.clone();
        let hash = file_hash.clone();
        tokio::task::spawn_blocking(move || {
            let _ = db.remove_shared_file_by_hash(&hash);
        })
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let _ = state
            .network_tx
            .send(NetworkCommand::UnannounceFiles {
                file_hashes: vec![file_hash],
            })
            .await;
        let _ = state.network_tx.send(NetworkCommand::SharedFilesChanged).await;
    }

    Ok(())
}

#[tauri::command]
pub async fn open_shared_file(file_path: String) -> Result<(), String> {
    let path = std::path::Path::new(&file_path);
    if !path.exists() {
        return Err("File does not exist".to_string());
    }
    let canonical = path.canonicalize().map_err(|e| format!("Invalid path: {e}"))?;
    opener::open(&canonical).map_err(|e| format!("Failed to open file: {e}"))?;
    Ok(())
}

#[tauri::command]
pub async fn open_shared_folder(file_path: String) -> Result<(), String> {
    let path = std::path::Path::new(&file_path);
    let folder = path.parent().unwrap_or(path);
    if !folder.exists() {
        return Err("Folder does not exist".to_string());
    }
    let canonical = folder.canonicalize().map_err(|e| format!("Invalid path: {e}"))?;
    opener::open(&canonical).map_err(|e| format!("Failed to open folder: {e}"))?;
    Ok(())
}

/// Helper: batch-save files to DB on current (blocking) thread.
fn save_files_to_db(db: &Arc<Database>, files: &[FileInfo]) {
    for file in files {
        if let Err(e) = db.save_shared_file(file) {
            tracing::warn!("Failed to save shared file {}: {e}", file.name);
        }
    }
}
