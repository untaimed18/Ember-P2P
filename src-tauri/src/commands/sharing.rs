use std::sync::atomic::Ordering;

use tauri::Emitter;

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::app_state::AppState;
use crate::network::NetworkCommand;
use crate::search::index::LocalIndex;
use crate::sharing::indexer::FileIndexer;
use crate::storage::known_files::KnownFileList;
use crate::types::*;
use tracing::{debug, info, warn};

async fn refresh_file_cache(index: &Arc<RwLock<LocalIndex>>, cache: &Arc<RwLock<Vec<FileInfo>>>) {
    let snap = index.read().await.all_files().to_vec();
    *cache.write().await = snap;
}

fn load_known_files() -> KnownFileList {
    let data_dir = directories::ProjectDirs::from("com", "nexus", "p2p")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    KnownFileList::load(&data_dir.join("known.met"))
}

fn resolve_from_known(files: &mut Vec<FileInfo>, known: &KnownFileList) -> Vec<FileInfo> {
    let mut needs_hashing = Vec::new();
    for file in files.iter_mut() {
        if let Some(record) = known.find_by_path_and_meta(&file.path, file.size, file.modified_at) {
            let hash = hex::encode(record.file_hash);
            file.id = hash.clone();
            file.hash = hash;
            file.aich_hash = record.aich_hash.clone();
        } else {
            needs_hashing.push(file.clone());
        }
    }
    needs_hashing
}

/// eMule-style shared folder addition -- returns IMMEDIATELY.
/// All discovery and hashing runs in a background task:
///   Phase 1: discover files (metadata only) → show in UI via event
///   Phase 2: hash files one at a time → update UI + publish to KAD
#[tauri::command]
pub async fn add_shared_folder(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<(), String> {
    let save_data = {
        let mut config = state.config.write().await;
        if !config.settings.shared_folders.contains(&path) {
            config.settings.shared_folders.push(path.clone());
            Some(config.prepare_save().map_err(|e| format!("Config save error: {e}"))?)
        } else {
            None
        }
    };
    if save_data.is_none() {
        info!("Folder {path} is already shared, skipping duplicate scan");
        return Ok(());
    }
    if let Some((data, tmp, final_path)) = save_data {
        tokio::task::spawn_blocking(move || {
            crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
        }).await.map_err(|e| format!("Config save error: {e}"))?.map_err(|e| format!("Config save error: {e}"))?;
    }

    let local_index = state.local_index.clone();
    let file_cache = state.cached_shared_files.clone();
    let network_tx = state.network_tx.clone();
    let scanning = state.scanning_count.clone();

    scanning.fetch_add(1, Ordering::Relaxed);

    // Everything runs in background -- command returns immediately
    tokio::spawn(async move {
        let discover_path = path.clone();
        let mut discovered = match tokio::task::spawn_blocking(move || {
            FileIndexer::discover_directory(&discover_path)
        })
        .await
        {
            Ok(files) => files,
            Err(e) => {
                tracing::error!("Discovery failed for {path}: {e}");
                scanning.fetch_sub(1, Ordering::Relaxed);
                return;
            }
        };

        let total_files = discovered.len();
        info!("Discovered {total_files} files in {path}");

        let known_list = load_known_files();
        let files_to_hash = resolve_from_known(&mut discovered, &known_list);

        {
            let mut index = local_index.write().await;
            index.add_files(discovered.clone());
        }
        refresh_file_cache(&local_index, &file_cache).await;

        let _ = app.emit("shared-files-changed", serde_json::json!({
            "folder": path,
            "count": total_files,
            "phase": "discovered",
        }));

        let known_for_announce: Vec<_> = discovered.iter()
            .filter(|f| !f.hash.is_empty())
            .cloned()
            .collect();
        if !known_for_announce.is_empty() {
            let _ = network_tx.try_send(NetworkCommand::AnnounceFiles {
                files: known_for_announce,
            });
        }

        let total_to_hash = files_to_hash.len();
        let mut hashed_count: usize = 0;
        let mut last_cache_refresh = std::time::Instant::now();

        for file in &files_to_hash {
            let file_path = file.path.clone();
            let file_temp_id = file.id.clone();

            debug!("Hashing file {}/{}: {}", hashed_count + 1, total_to_hash, file.name);

            let _ = app.emit("file-hash-progress", serde_json::json!({
                "current": hashed_count + 1,
                "total": total_to_hash,
                "file_name": file.name,
            }));

            let hash_result = tokio::time::timeout(
                std::time::Duration::from_secs(300),
                tokio::task::spawn_blocking(move || {
                    FileIndexer::hash_file(std::path::Path::new(&file_path))
                }),
            )
            .await;

            match hash_result {
                Ok(Ok(Ok((ed2k_hash, aich_hash)))) => {
                    debug!("Hash complete: {} -> {}", file.name, &ed2k_hash[..8]);
                    let mut updated_file = file.clone();
                    updated_file.id = ed2k_hash.clone();
                    updated_file.hash = ed2k_hash;
                    updated_file.aich_hash = aich_hash;

                    {
                        let mut index = local_index.write().await;
                        index.remove_file_by_id(&file_temp_id);
                        index.add_file(updated_file.clone());
                    }

                    let _ = network_tx
                        .try_send(NetworkCommand::AnnounceFiles {
                            files: vec![updated_file.clone()],
                        });

                    hashed_count += 1;
                    if last_cache_refresh.elapsed() >= std::time::Duration::from_secs(5) {
                        refresh_file_cache(&local_index, &file_cache).await;
                        last_cache_refresh = std::time::Instant::now();
                    }
                }
                Ok(Ok(Err(e))) => {
                    warn!("Failed to hash {}: {e}", file.name);
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
                Ok(Err(e)) => {
                    tracing::error!("Hash task panicked for {}: {e}", file.name);
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
                Err(_) => {
                    warn!("Hash timed out after 5 min for {} (file may be on cloud storage or locked), skipping", file.name);
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
            }
        }

        refresh_file_cache(&local_index, &file_cache).await;
        let _ = network_tx.try_send(NetworkCommand::SharedFilesChanged);
        scanning.fetch_sub(1, Ordering::Relaxed);
        let from_known = total_files - total_to_hash;
        info!("Background hashing complete: {hashed_count}/{total_to_hash} hashed, {from_known} from known.met ({path})");

        let _ = app.emit("file-hash-progress", serde_json::json!({
            "current": total_to_hash,
            "total": total_to_hash,
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
            .filter(|f| f.path.starts_with(&path) && !f.hash.is_empty())
            .map(|f| f.hash.clone())
            .collect()
    };

    let save_data = {
        let mut config = state.config.write().await;
        config.settings.shared_folders.retain(|f| f != &path);
        config.prepare_save().map_err(|e| format!("Config save error: {e}"))?
    };
    {
        let (data, tmp, final_path) = save_data;
        tokio::task::spawn_blocking(move || {
            crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
        }).await.map_err(|e| format!("Config save error: {e}"))?.map_err(|e| format!("Config save error: {e}"))?;
    }

    {
        let mut index = state.local_index.write().await;
        index.remove_files_by_path_prefix(&path);
    }
    refresh_file_cache(&state.local_index, &state.cached_shared_files).await;

    let network_tx = state.network_tx.clone();
    tokio::spawn(async move {
        if !removed_hashes.is_empty() {
            let _ = network_tx
                .try_send(NetworkCommand::UnannounceFiles {
                    file_hashes: removed_hashes,
                });
        }
        let _ = network_tx.try_send(NetworkCommand::SharedFilesChanged);
    });

    Ok(())
}

#[tauri::command]
pub async fn get_shared_files(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<FileInfo>, String> {
    let cached = state.cached_shared_files.read().await;
    Ok(cached.clone())
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
    {
        let mut index = state.local_index.write().await;
        if !index.set_file_priority(&file_hash, &priority) {
            return Err("File not found".to_string());
        }
    }
    refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
    info!("Set priority for {} to {}", file_hash, priority);
    Ok(())
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
    let file_cache = state.cached_shared_files.clone();
    let network_tx = state.network_tx.clone();
    let scanning = state.scanning_count.clone();

    scanning.fetch_add(1, Ordering::Relaxed);

    // Everything runs in background -- command returns immediately
    tokio::spawn(async move {
        let mut discovered: Vec<FileInfo> = match tokio::task::spawn_blocking(move || {
            let mut files = Vec::new();
            for folder in &folders {
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
                return;
            }
        };

        let total_files = discovered.len();

        let known_list = load_known_files();
        let files_to_hash = resolve_from_known(&mut discovered, &known_list);

        {
            let mut index = local_index.write().await;
            index.add_files(discovered.clone());
        }
        refresh_file_cache(&local_index, &file_cache).await;

        let _ = app.emit("shared-files-changed", serde_json::json!({
            "phase": "discovered",
            "count": total_files,
        }));

        let known_for_announce: Vec<_> = discovered.iter()
            .filter(|f| !f.hash.is_empty())
            .cloned()
            .collect();
        if !known_for_announce.is_empty() {
            let _ = network_tx.try_send(NetworkCommand::AnnounceFiles {
                files: known_for_announce,
            });
        }

        let total_to_hash = files_to_hash.len();
        let mut hashed_count: usize = 0;
        let mut last_cache_refresh = std::time::Instant::now();

        for file in &files_to_hash {
            let file_path = file.path.clone();
            let file_temp_id = file.id.clone();

            debug!("Reload hashing {}/{}: {}", hashed_count + 1, total_to_hash, file.name);

            let _ = app.emit("file-hash-progress", serde_json::json!({
                "current": hashed_count + 1,
                "total": total_to_hash,
                "file_name": file.name,
            }));

            let hash_result = tokio::time::timeout(
                std::time::Duration::from_secs(300),
                tokio::task::spawn_blocking(move || {
                    FileIndexer::hash_file(std::path::Path::new(&file_path))
                }),
            )
            .await;

            match hash_result {
                Ok(Ok(Ok((ed2k_hash, aich_hash)))) => {
                    debug!("Reload hash complete: {} -> {}", file.name, &ed2k_hash[..8]);
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

                    let _ = network_tx
                        .try_send(NetworkCommand::AnnounceFiles {
                            files: vec![updated_file.clone()],
                        });

                    hashed_count += 1;
                    if last_cache_refresh.elapsed() >= std::time::Duration::from_secs(5) {
                        refresh_file_cache(&local_index, &file_cache).await;
                        last_cache_refresh = std::time::Instant::now();
                    }
                }
                Ok(Ok(Err(e))) => {
                    warn!("Failed to hash {}: {e}", file.name);
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
                Ok(Err(e)) => {
                    tracing::error!("Hash task panicked for {}: {e}", file.name);
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
                Err(_) => {
                    warn!("Hash timed out after 5 min for {} (file may be on cloud storage or locked), skipping", file.name);
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
            }
        }

        refresh_file_cache(&local_index, &file_cache).await;
        let _ = network_tx.try_send(NetworkCommand::SharedFilesChanged);
        scanning.fetch_sub(1, Ordering::Relaxed);
        let from_known = total_files - total_to_hash;
        info!("Background reload complete: {hashed_count}/{total_to_hash} hashed, {from_known} from known.met");

        let _ = app.emit("file-hash-progress", serde_json::json!({
            "current": total_to_hash,
            "total": total_to_hash,
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
    let toggled = {
        let mut index = state.local_index.write().await;
        index.set_file_shared(&file_hash, false)
    };
    if toggled {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        let _ = state.network_tx.try_send(NetworkCommand::UnannounceFiles {
            file_hashes: vec![file_hash],
        });
        let _ = state.network_tx.try_send(NetworkCommand::SharedFilesChanged);
    }
    Ok(())
}

#[tauri::command]
pub async fn share_file(
    state: tauri::State<'_, AppState>,
    file_hash: String,
) -> Result<(), String> {
    let file = {
        let mut index = state.local_index.write().await;
        index.set_file_shared(&file_hash, true);
        index.get_by_hash(&file_hash).cloned()
    };
    if let Some(f) = file {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        let _ = state.network_tx.try_send(NetworkCommand::AnnounceFiles {
            files: vec![f],
        });
        let _ = state.network_tx.try_send(NetworkCommand::SharedFilesChanged);
    }
    Ok(())
}

#[tauri::command]
pub async fn unshare_folder(
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<(), String> {
    let affected_hashes = {
        let mut index = state.local_index.write().await;
        index.set_shared_by_path_prefix(&path, false)
    };
    if !affected_hashes.is_empty() {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        let _ = state.network_tx.try_send(NetworkCommand::UnannounceFiles {
            file_hashes: affected_hashes,
        });
        let _ = state.network_tx.try_send(NetworkCommand::SharedFilesChanged);
    }
    Ok(())
}

#[tauri::command]
pub async fn open_shared_file(file_path: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let path = std::path::Path::new(&file_path);
        if !path.exists() {
            return Err("File does not exist".to_string());
        }
        let canonical = path.canonicalize().map_err(|e| format!("Invalid path: {e}"))?;
        opener::open(&canonical).map_err(|e| format!("Failed to open file: {e}"))?;
        Ok(())
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}

#[tauri::command]
pub async fn open_shared_folder(file_path: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let path = std::path::Path::new(&file_path);
        let folder = path.parent().unwrap_or(path);
        if !folder.exists() {
            return Err("Folder does not exist".to_string());
        }
        let canonical = folder.canonicalize().map_err(|e| format!("Invalid path: {e}"))?;
        opener::open(&canonical).map_err(|e| format!("Failed to open folder: {e}"))?;
        Ok(())
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}

