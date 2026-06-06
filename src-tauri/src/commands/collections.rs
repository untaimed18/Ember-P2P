use tauri::Emitter;
use crate::app_state::AppState;
use crate::commands::errors::{coded, coded_ctx};
use crate::network::ed2k::collection::{Collection, CollectionFile};
use crate::types::{Transfer, TransferStatus, TransferDirection};

#[tauri::command]
pub async fn load_collection(
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<Collection, String> {
    let p = std::path::PathBuf::from(&path);
    if p.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(coded("collections_path_no_parent_dir", "Path must not contain '..' components"));
    }
    let ext = p.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase());
    if !matches!(ext.as_deref(), Some("emulecollection") | Some("txt")) {
        return Err(coded("collections_invalid_file_extension", "File must be a .emulecollection or .txt file"));
    }
    if !p.exists() {
        return Err(coded("collections_file_not_found", "File does not exist"));
    }

    let p2 = p.clone();
    let canonical = tokio::task::spawn_blocking(move || std::fs::canonicalize(&p2))
        .await
        .map_err(|e| coded_ctx("collections_canonicalize_task_failed", "Canonicalize task failed", e))?
        .map_err(|e| coded_ctx("collections_cannot_resolve_path", "Cannot resolve path", e))?;
    let config = state.config.read().await;
    let download_root = std::path::PathBuf::from(&config.settings.download_folder);
    let mut allowed_dirs: Vec<String> = config.settings.shared_folders.clone();
    if !config.settings.download_folder.is_empty() {
        allowed_dirs.push(download_root.to_string_lossy().into_owned());
    }
    drop(config);

    if allowed_dirs.is_empty() {
        return Err(coded("collections_no_folders_configured", "No shared or download folders configured"));
    }
    if !crate::security::is_path_within_dirs(&canonical, &allowed_dirs) {
        return Err(coded("collections_file_outside_allowed_dirs", "Collection file must be inside a shared or download folder"));
    }

    // Cap the on-disk size before `Collection::load` reads the whole file into
    // memory (`std::fs::read`). `open_collection_file` already enforces this;
    // the webview-callable `load_collection` path did not, so a multi-GiB file
    // inside an allowed folder could OOM the client.
    const MAX_COLLECTION_BYTES: u64 = 32 * 1024 * 1024;
    let meta = tokio::fs::metadata(&canonical)
        .await
        .map_err(|e| coded_ctx("collections_stat_failed", "Cannot stat collection file", e))?;
    if meta.len() > MAX_COLLECTION_BYTES {
        return Err(coded("collections_file_too_large", "Collection file too large (max 32 MiB)"));
    }

    tokio::task::spawn_blocking(move || {
        Collection::load(&canonical).map_err(|e| coded_ctx("collections_load_failed", "Failed to load collection", e))
    })
    .await
    .map_err(|e| coded_ctx("collections_load_task_failed", "Load task failed", e))?
}

#[tauri::command]
pub async fn create_collection(
    state: tauri::State<'_, AppState>,
    name: String,
    author: String,
    files: Vec<CollectionFile>,
    output_path: String,
    binary: bool,
) -> Result<String, String> {
    // Mirror the cap on the binary loader (100k entries) and the
    // download-batch cap (200 entries) — the IPC create path was
    // unbounded, so a frontend bug or malicious bundle could push a
    // multi-million-entry vector. 100k is generous; the on-disk binary
    // loader will enforce the same cap on read-back.
    const MAX_COLLECTION_FILES: usize = 100_000;
    if files.len() > MAX_COLLECTION_FILES {
        return Err(coded_ctx(
            "collections_too_large",
            format!("Collection too large (max {MAX_COLLECTION_FILES} files)"),
            MAX_COLLECTION_FILES,
        ));
    }
    let collection = Collection {
        name: name.clone(),
        author,
        files,
    };
    let path = std::path::PathBuf::from(&output_path);

    // `canonicalize` hits the filesystem and can block (network drives, AV,
    // cloud-backed paths). This command is async, so run it on the blocking
    // pool instead of stalling the Tokio worker (and with it unrelated IPC).
    let canonical = {
        let path = path.clone();
        tokio::task::spawn_blocking(move || {
            path.canonicalize().or_else(|_| {
                if let Some(parent) = path.parent() {
                    parent.canonicalize().map(|p| p.join(path.file_name().unwrap_or_default()))
                } else {
                    Err(std::io::Error::new(std::io::ErrorKind::NotFound, "invalid path"))
                }
            })
        })
        .await
        .map_err(|e| coded_ctx("collections_canonicalize_task", "Path resolution failed", e))?
        .map_err(|e| coded_ctx("collections_invalid_output_path", "Invalid output path", e))?
    };

    if canonical.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(coded("collections_output_path_no_parent_dir", "Output path must not contain '..' components"));
    }

    let config = state.config.read().await;
    let mut allowed_dirs: Vec<String> = config.settings.shared_folders.clone();
    if !config.settings.download_folder.is_empty() {
        allowed_dirs.push(std::path::PathBuf::from(&config.settings.download_folder)
            .to_string_lossy().into_owned());
    }
    drop(config);

    if allowed_dirs.is_empty() {
        return Err(coded("collections_no_folders_configured", "No shared or download folders configured"));
    }
    if !crate::security::is_path_within_dirs(&canonical, &allowed_dirs) {
        return Err(coded("collections_output_outside_allowed_dirs", "Output path must be inside a shared or download folder"));
    }

    let ext = canonical.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase());
    if !matches!(ext.as_deref(), Some("emulecollection") | Some("txt")) {
        return Err(coded("collections_output_invalid_extension", "Output file must have .emulecollection or .txt extension"));
    }
    let write_path = canonical.clone();
    tokio::task::spawn_blocking(move || {
        if binary {
            collection.save_binary(&write_path).map_err(|e| coded_ctx("collections_save_failed", "Failed to save", e))?;
        } else {
            collection.save_text(&write_path).map_err(|e| coded_ctx("collections_save_failed", "Failed to save", e))?;
        }
        Ok::<_, String>(())
    })
    .await
    .map_err(|e| coded_ctx("collections_save_task_failed", "Save task failed", e))??;
    Ok(format!("Created collection '{name}' at {}", canonical.display()))
}

#[tauri::command]
pub async fn download_collection_files(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    files: Vec<CollectionFile>,
) -> Result<String, String> {
    if files.len() > 200 {
        return Err(coded("collections_too_many_files", "Collection too large (max 200 files)"));
    }
    // Mirror `start_download` (D16): reject collection entries that
    // exceed the user's `max_download_file_size_gib` cap up front, so
    // the batch path enforces the same policy as the single-file path.
    // `validate_settings` rejects `0`, so under normal flow the cap is
    // always active; the `> 0` guard is defense for hand-edited configs
    // that bypass validation.
    let (add_paused, max_dl_bytes) = {
        let config = state.config.read().await;
        let cap_gib = config.settings.max_download_file_size_gib;
        let cap_bytes = if cap_gib > 0 {
            (cap_gib as u64).saturating_mul(1024 * 1024 * 1024)
        } else {
            0
        };
        (config.settings.add_downloads_paused, cap_bytes)
    };
    let mut queued_count = 0usize;
    let mut skipped_count = 0usize;
    let mut oversize_count = 0usize;
    for file in files {
        if file.hash.is_empty() || file.name.is_empty() {
            skipped_count += 1;
            tracing::debug!("Skipping collection entry: empty hash or name");
            continue;
        }
        if file.hash.len() != 32 || hex::decode(&file.hash).is_err() {
            skipped_count += 1;
            tracing::debug!("Skipping collection entry '{}': invalid hash", file.name);
            continue;
        }
        if max_dl_bytes > 0 && file.size > max_dl_bytes {
            oversize_count += 1;
            tracing::debug!(
                "Skipping collection entry '{}': size {} exceeds configured cap {}",
                file.name, file.size, max_dl_bytes
            );
            continue;
        }
        let safe_name = crate::security::sanitize_filename(&file.name);
        let transfer_id = uuid::Uuid::new_v4().to_string();
        let control = crate::sharing::manager::TransferControl::new();
        if add_paused {
            control.pause();
        }

        let transfer = Transfer {
            id: transfer_id.clone(),
            file_name: safe_name.clone(),
            file_hash: file.hash.clone(),
            peer_id: String::new(),
            peer_name: String::new(),
            direction: TransferDirection::Download,
            status: if add_paused { TransferStatus::Paused } else { TransferStatus::Searching },
            progress: 0.0,
            speed: 0,
            total_size: file.size,
            transferred: 0,
            completed_size: 0,
            started_at: chrono::Utc::now().timestamp(),
            failure_reason: None,
            failure_kind: None,
            failure_stage: None,
            priority: "auto".to_string(),
            sources: 0,
            active_sources: 0,
            queued_sources: 0,
            queue_rank: None,
            last_seen_complete: None,
            last_received: None,
            health: crate::types::TransferHealth::Healthy,
            health_reason: None,
            stalled_since: None,
            category: String::new(),
            wait_time: 0,
            upload_time: 0,
            a4af_sources: 0,
            max_sources: 0,
            preview_priority: false,
            ember_sources: 0,
            client_software: String::new(),
            country_code: None,
            user_hash: None,
        };

        let (active_now, persisted_transfer) = {
            let mut mgr = state.transfer_manager.write().await;
            if mgr.has_pending_for_hash(&file.hash) {
                skipped_count += 1;
                continue;
            }
            let active_now = mgr.enqueue(transfer.clone());
            mgr.register_control(&transfer_id, control.clone());
            let persisted = mgr
                .get_transfer(&transfer_id)
                .cloned()
                .unwrap_or(transfer);
            (active_now, persisted)
        };
        queued_count += 1;

        super::transfers::persist_transfer(&state, &persisted_transfer).await;
        let _ = app.emit("transfer-started", &persisted_transfer);

        if active_now && !add_paused {
            if let Err(e) = state
                .network_tx
                .send(crate::network::NetworkCommand::StartDownload {
                    file_hash: file.hash,
                    file_name: safe_name,
                    file_size: file.size,
                    peer_ip: String::new(),
                    peer_port: 0,
                    // Collection entries don't carry per-file source
                    // addresses; the network task handles full source
                    // discovery for each.
                    extra_sources: Vec::new(),
                    transfer_id: transfer_id.clone(),
                    control,
                })
                .await
            {
                tracing::warn!("Failed to send StartDownload for collection entry '{}': {e}", file.name);
                // Roll the just-enqueued (now active) transfer back to Failed
                // so it doesn't pin a download slot forever once the network
                // channel is gone. Persist + emit so the DB row and UI match
                // the in-memory state (mirrors `start_download`'s rollback).
                {
                    let mut mgr = state.transfer_manager.write().await;
                    let _ = mgr.fail(
                        &transfer_id,
                        "Network channel unavailable",
                        Some("permanent".to_string()),
                        None,
                    );
                }
                if let Some(failed) = {
                    let mgr = state.transfer_manager.read().await;
                    mgr.get_transfer(&transfer_id).cloned()
                } {
                    super::transfers::persist_transfer(&state, &failed).await;
                    let _ = app.emit("transfer-failed", &failed);
                }
            }
        }
    }
    if skipped_count > 0 {
        tracing::warn!("Collection download: skipped {skipped_count} invalid entries");
    }
    if oversize_count > 0 {
        tracing::warn!(
            "Collection download: skipped {oversize_count} entries that exceed max_download_file_size_gib"
        );
    }
    let mut msg = format!("Queued {queued_count} files for download");
    if oversize_count > 0 {
        msg.push_str(&format!(
            " ({oversize_count} skipped: exceeds Max File Size in Settings > Downloads)"
        ));
    }
    Ok(msg)
}
