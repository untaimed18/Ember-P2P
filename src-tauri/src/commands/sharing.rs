use std::sync::atomic::Ordering;

use tauri::Emitter;

use crate::app_state::AppState;
use crate::network::NetworkCommand;
use crate::sharing::indexer::FileIndexer;
use crate::types::*;
use tracing::info;

/// eMule-style two-phase shared folder addition:
///   Phase 1 (instant): discover files (metadata only) → show in UI immediately
///   Phase 2 (background): hash files one at a time → update UI + publish to KAD
#[tauri::command]
pub async fn add_shared_folder(
    app: tauri::AppHandle,
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

    // Phase 1: instant file discovery (no hashing)
    let discover_path = path.clone();
    let discovered = match tokio::task::spawn_blocking(move || {
        FileIndexer::discover_directory(&discover_path)
    })
    .await
    {
        Ok(files) => files,
        Err(e) => {
            tracing::error!("Discovery failed for {path}: {e}");
            scanning.fetch_sub(1, Ordering::Relaxed);
            return Err(format!("Discovery failed: {e}"));
        }
    };

    let total_files = discovered.len();
    info!("Discovered {total_files} files in {path}, starting background hashing");

    // Add discovered (unhashed) files to the index immediately so the UI shows them
    {
        let mut index = local_index.write().await;
        index.add_files(discovered.clone());
    }

    // Emit an event so the frontend knows files are available now
    let _ = app.emit("shared-files-changed", serde_json::json!({
        "folder": path,
        "count": total_files,
        "phase": "discovered",
    }));

    // Phase 2: hash files one at a time in the background (eMule style)
    let app_clone = app.clone();
    tokio::spawn(async move {
        let mut hashed_count: usize = 0;

        for file in &discovered {
            let file_path = file.path.clone();
            let file_temp_id = file.id.clone();

            let _ = app_clone.emit("file-hash-progress", serde_json::json!({
                "current": hashed_count + 1,
                "total": total_files,
                "file_name": file.name,
            }));

            let hash_result = tokio::task::spawn_blocking(move || {
                FileIndexer::hash_file(std::path::Path::new(&file_path))
            })
            .await;

            match hash_result {
                Ok(Ok((ed2k_hash, aich_hash))) => {
                    let mut updated_file = file.clone();
                    updated_file.id = ed2k_hash.clone();
                    updated_file.hash = ed2k_hash;
                    updated_file.aich_hash = aich_hash;

                    // Replace the placeholder entry with the hashed version
                    {
                        let mut index = local_index.write().await;
                        index.remove_file_by_id(&file_temp_id);
                        index.add_file(updated_file.clone());
                    }

                    // Persist to DB
                    let db_ref = db.clone();
                    let db_file = updated_file.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        let _ = db_ref.save_shared_file(&db_file);
                    })
                    .await;

                    // Publish this file to KAD immediately
                    let _ = network_tx
                        .send(NetworkCommand::AnnounceFiles {
                            files: vec![updated_file.clone()],
                        })
                        .await;

                    let _ = app_clone.emit("file-hashed", serde_json::json!({
                        "temp_id": file_temp_id,
                        "hash": updated_file.hash,
                        "aich_hash": updated_file.aich_hash,
                        "file_name": updated_file.name,
                        "current": hashed_count + 1,
                        "total": total_files,
                    }));

                    hashed_count += 1;
                }
                Ok(Err(e)) => {
                    tracing::warn!("Failed to hash {}: {e}", file.name);
                    // Remove the placeholder since we can't share this file
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
                Err(e) => {
                    tracing::error!("Hash task panicked for {}: {e}", file.name);
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
            }
        }

        let _ = network_tx.send(NetworkCommand::SharedFilesChanged).await;
        scanning.fetch_sub(1, Ordering::Relaxed);
        info!(
            "Background hashing complete: {hashed_count}/{total_files} files from {path}"
        );

        let _ = app_clone.emit("file-hash-progress", serde_json::json!({
            "current": total_files,
            "total": total_files,
            "file_name": "",
            "done": true,
        }));
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
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let folders = {
        let config = state.config.read().await;
        config.settings.shared_folders.clone()
    };

    let local_index = state.local_index.clone();
    let db = state.db.clone();
    let network_tx = state.network_tx.clone();
    let scanning = state.scanning_count.clone();

    scanning.fetch_add(1, Ordering::Relaxed);

    // Phase 1: instant discovery across all folders
    let discover_folders = folders.clone();
    let discovered: Vec<FileInfo> = match tokio::task::spawn_blocking(move || {
        let mut files = Vec::new();
        for folder in &discover_folders {
            files.extend(FileIndexer::discover_directory(folder));
        }
        files
    })
    .await
    {
        Ok(files) => files,
        Err(e) => {
            tracing::error!("Reload discovery failed: {e}");
            scanning.fetch_sub(1, Ordering::Relaxed);
            return Err(format!("Discovery failed: {e}"));
        }
    };

    let total_files = discovered.len();
    {
        let mut index = local_index.write().await;
        index.add_files(discovered.clone());
    }

    let _ = app.emit("shared-files-changed", serde_json::json!({
        "phase": "discovered",
        "count": total_files,
    }));

    // Phase 2: hash one at a time in background
    let app_clone = app.clone();
    tokio::spawn(async move {
        let mut hashed_count: usize = 0;

        for file in &discovered {
            let file_path = file.path.clone();
            let file_temp_id = file.id.clone();

            // Skip if already hashed (exists in DB with same path)
            {
                let index = local_index.read().await;
                if let Some(existing) = index.all_files().iter().find(|f| f.path == file.path && !f.hash.is_empty()) {
                    if existing.hash != file.hash {
                        hashed_count += 1;
                        continue;
                    }
                }
            }

            let _ = app_clone.emit("file-hash-progress", serde_json::json!({
                "current": hashed_count + 1,
                "total": total_files,
                "file_name": file.name,
            }));

            let hash_result = tokio::task::spawn_blocking(move || {
                FileIndexer::hash_file(std::path::Path::new(&file_path))
            })
            .await;

            match hash_result {
                Ok(Ok((ed2k_hash, aich_hash))) => {
                    let mut updated_file = file.clone();
                    updated_file.id = ed2k_hash.clone();
                    updated_file.hash = ed2k_hash;
                    updated_file.aich_hash = aich_hash;

                    {
                        let mut index = local_index.write().await;
                        index.remove_file_by_id(&file_temp_id);
                        if index.get_by_hash(&updated_file.hash).is_none() {
                            index.add_file(updated_file.clone());
                        }
                    }

                    let db_ref = db.clone();
                    let db_file = updated_file.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        let _ = db_ref.save_shared_file(&db_file);
                    })
                    .await;

                    let _ = network_tx
                        .send(NetworkCommand::AnnounceFiles {
                            files: vec![updated_file.clone()],
                        })
                        .await;

                    hashed_count += 1;
                }
                Ok(Err(e)) => {
                    tracing::warn!("Failed to hash {}: {e}", file.name);
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
                Err(e) => {
                    tracing::error!("Hash task panicked for {}: {e}", file.name);
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
            }
        }

        let _ = network_tx.send(NetworkCommand::SharedFilesChanged).await;
        scanning.fetch_sub(1, Ordering::Relaxed);
        info!("Background reload hashing complete: {hashed_count}/{total_files} files");

        let _ = app_clone.emit("file-hash-progress", serde_json::json!({
            "current": total_files,
            "total": total_files,
            "file_name": "",
            "done": true,
        }));
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

