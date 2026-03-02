use std::sync::atomic::{AtomicBool, Ordering};

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
    let p = std::path::Path::new(&path);
    if !p.exists() || !p.is_dir() {
        return Err("Path does not exist or is not a directory".into());
    }
    let canonical = p.canonicalize().map_err(|e| format!("Invalid path: {e}"))?;
    let canonical_str = canonical.to_string_lossy().to_lowercase();
    let blocked = [
        "\\windows", "\\program files", "\\program files (x86)",
        "\\programdata", "\\.ssh", "\\.gnupg", "\\appdata\\local\\temp",
        "/etc", "/usr", "/bin", "/sbin", "/var", "/root",
    ];
    for prefix in &blocked {
        if canonical_str.contains(&prefix.to_lowercase()) {
            return Err(format!("Cannot share system directory: {}", canonical.display()));
        }
    }

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
    let cancel_flags = state.hash_cancel_flags.clone();

    scanning.fetch_add(1, Ordering::Relaxed);
    let cancel_flag = Arc::new(AtomicBool::new(false));
    cancel_flags.write().await.insert(path.clone(), cancel_flag.clone());

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
                cancel_flags.write().await.remove(&path);
                return;
            }
        };

        let total_files = discovered.len();
        info!("Discovered {total_files} files in {path}");

        if cancel_flag.load(Ordering::Relaxed) {
            info!("Hashing cancelled during discovery for {path}");
            scanning.fetch_sub(1, Ordering::Relaxed);
            cancel_flags.write().await.remove(&path);
            let _ = app.emit("file-hash-progress", serde_json::json!({ "done": true, "current": 0, "total": 0, "file_name": "" }));
            return;
        }

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

        let total_to_hash = files_to_hash.len();
        let mut hashed_count: usize = 0;
        let mut last_cache_refresh = std::time::Instant::now();
        let mut was_cancelled = false;

        for file in &files_to_hash {
            if cancel_flag.load(Ordering::Relaxed) {
                info!("Hashing cancelled for {path} at {hashed_count}/{total_to_hash}");
                was_cancelled = true;
                break;
            }

            let file_path = file.path.clone();
            let file_temp_id = file.id.clone();
            let cf = cancel_flag.clone();

            debug!("Hashing file {}/{}: {}", hashed_count + 1, total_to_hash, file.name);

            let _ = app.emit("file-hash-progress", serde_json::json!({
                "current": hashed_count + 1,
                "total": total_to_hash,
                "file_name": file.name,
            }));

            let hash_result = tokio::time::timeout(
                std::time::Duration::from_secs(300),
                tokio::task::spawn_blocking(move || {
                    FileIndexer::hash_file_cancellable(std::path::Path::new(&file_path), &cf)
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

                    hashed_count += 1;
                    if last_cache_refresh.elapsed() >= std::time::Duration::from_secs(5) {
                        refresh_file_cache(&local_index, &file_cache).await;
                        last_cache_refresh = std::time::Instant::now();
                    }
                }
                Ok(Ok(Err(e))) => {
                    let msg = e.to_string();
                    if msg.contains("cancelled") {
                        info!("Hashing cancelled mid-file for {path}");
                        was_cancelled = true;
                        let mut index = local_index.write().await;
                        index.remove_file_by_id(&file_temp_id);
                        break;
                    }
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

        if was_cancelled {
            let mut index = local_index.write().await;
            index.remove_pending_files();
        }

        refresh_file_cache(&local_index, &file_cache).await;

        if !was_cancelled {
            let all_files = {
                let index = local_index.read().await;
                index.all_files().iter()
                    .filter(|f| f.path.starts_with(&path) && !f.hash.is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
            };
            if !all_files.is_empty() {
                let _ = network_tx.try_send(NetworkCommand::AnnounceFiles { files: all_files });
            }
        }

        let _ = network_tx.try_send(NetworkCommand::SharedFilesChanged);
        scanning.fetch_sub(1, Ordering::Relaxed);
        cancel_flags.write().await.remove(&path);

        let from_known = total_files - total_to_hash;
        if was_cancelled {
            info!("Hashing stopped for {path}: {hashed_count}/{total_to_hash} hashed before cancel, {from_known} from known.met");
        } else {
            info!("Background hashing complete: {hashed_count}/{total_to_hash} hashed, {from_known} from known.met ({path})");
        }

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
    // Cancel any in-progress hashing for this folder before cleanup
    {
        let flags = state.hash_cancel_flags.read().await;
        if let Some(flag) = flags.get(&path) {
            flag.store(true, Ordering::Relaxed);
        }
        if let Some(flag) = flags.get("__reload__") {
            flag.store(true, Ordering::Relaxed);
        }
        if let Some(flag) = flags.get("__startup__") {
            flag.store(true, Ordering::Relaxed);
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

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
    let cancel_flags = state.hash_cancel_flags.clone();

    scanning.fetch_add(1, Ordering::Relaxed);
    let cancel_flag = Arc::new(AtomicBool::new(false));
    cancel_flags.write().await.insert("__reload__".to_string(), cancel_flag.clone());

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
                cancel_flags.write().await.remove("__reload__");
                return;
            }
        };

        let total_files = discovered.len();

        if cancel_flag.load(Ordering::Relaxed) {
            info!("Reload cancelled during discovery");
            scanning.fetch_sub(1, Ordering::Relaxed);
            cancel_flags.write().await.remove("__reload__");
            let _ = app.emit("file-hash-progress", serde_json::json!({ "done": true, "current": 0, "total": 0, "file_name": "" }));
            return;
        }

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

        let total_to_hash = files_to_hash.len();
        let mut hashed_count: usize = 0;
        let mut last_cache_refresh = std::time::Instant::now();
        let mut was_cancelled = false;

        for file in &files_to_hash {
            if cancel_flag.load(Ordering::Relaxed) {
                info!("Reload hashing cancelled at {hashed_count}/{total_to_hash}");
                was_cancelled = true;
                break;
            }

            let file_path = file.path.clone();
            let file_temp_id = file.id.clone();
            let cf = cancel_flag.clone();

            debug!("Reload hashing {}/{}: {}", hashed_count + 1, total_to_hash, file.name);

            let _ = app.emit("file-hash-progress", serde_json::json!({
                "current": hashed_count + 1,
                "total": total_to_hash,
                "file_name": file.name,
            }));

            let hash_result = tokio::time::timeout(
                std::time::Duration::from_secs(300),
                tokio::task::spawn_blocking(move || {
                    FileIndexer::hash_file_cancellable(std::path::Path::new(&file_path), &cf)
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

                    hashed_count += 1;
                    if last_cache_refresh.elapsed() >= std::time::Duration::from_secs(5) {
                        refresh_file_cache(&local_index, &file_cache).await;
                        last_cache_refresh = std::time::Instant::now();
                    }
                }
                Ok(Ok(Err(e))) => {
                    let msg = e.to_string();
                    if msg.contains("cancelled") {
                        info!("Reload hashing cancelled mid-file");
                        was_cancelled = true;
                        let mut index = local_index.write().await;
                        index.remove_file_by_id(&file_temp_id);
                        break;
                    }
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

        if was_cancelled {
            let mut index = local_index.write().await;
            index.remove_pending_files();
        }

        refresh_file_cache(&local_index, &file_cache).await;

        if !was_cancelled {
            let all_files = {
                let index = local_index.read().await;
                index.all_files().iter()
                    .filter(|f| !f.hash.is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
            };
            if !all_files.is_empty() {
                let _ = network_tx.try_send(NetworkCommand::AnnounceFiles { files: all_files });
            }
        }

        let _ = network_tx.try_send(NetworkCommand::SharedFilesChanged);
        scanning.fetch_sub(1, Ordering::Relaxed);
        cancel_flags.write().await.remove("__reload__");

        let from_known = total_files - total_to_hash;
        info!("Reload complete: {hashed_count}/{total_to_hash} hashed, {from_known} from known.met{}", if was_cancelled { " (cancelled)" } else { "" });

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
pub async fn stop_hashing(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let flags = state.hash_cancel_flags.read().await;
    let count = flags.len();
    for flag in flags.values() {
        flag.store(true, Ordering::Relaxed);
    }
    info!("Stop hashing requested, cancelled {count} active tasks");
    Ok(())
}

#[tauri::command]
pub async fn resume_hashing(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    reload_shared_files(app, state).await
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
pub async fn open_shared_file(
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<(), String> {
    let config = state.config.read().await;
    let mut allowed_dirs = config.settings.shared_folders.clone();
    let download_dir = std::path::PathBuf::from(&config.settings.download_folder)
        .join("Downloads")
        .to_string_lossy()
        .to_string();
    allowed_dirs.push(download_dir);
    drop(config);

    tokio::task::spawn_blocking(move || {
        let path = std::path::Path::new(&file_path);
        if !path.exists() {
            return Err("File does not exist".to_string());
        }
        let canonical = path.canonicalize().map_err(|e| format!("Invalid path: {e}"))?;
        if !crate::security::is_path_within_dirs(&canonical, &allowed_dirs) {
            return Err("File is not within a shared or download folder".to_string());
        }
        if crate::security::is_dangerous_extension(&canonical.to_string_lossy()) {
            return Err("Cannot open potentially dangerous file types".to_string());
        }
        opener::open(&canonical).map_err(|e| format!("Failed to open file: {e}"))?;
        Ok(())
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}

#[tauri::command]
pub async fn open_shared_folder(
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<(), String> {
    let config = state.config.read().await;
    let mut allowed_dirs = config.settings.shared_folders.clone();
    let download_dir = std::path::PathBuf::from(&config.settings.download_folder)
        .join("Downloads")
        .to_string_lossy()
        .to_string();
    allowed_dirs.push(download_dir);
    allowed_dirs.push(config.settings.download_folder.clone());
    drop(config);

    tokio::task::spawn_blocking(move || {
        let path = std::path::Path::new(&file_path);
        let folder = path.parent().unwrap_or(path);
        if !folder.exists() {
            return Err("Folder does not exist".to_string());
        }
        let canonical = folder.canonicalize().map_err(|e| format!("Invalid path: {e}"))?;
        if !crate::security::is_path_within_dirs(&canonical, &allowed_dirs) {
            return Err("Folder is not within a shared or download directory".to_string());
        }
        opener::open(&canonical).map_err(|e| format!("Failed to open folder: {e}"))?;
        Ok(())
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}

