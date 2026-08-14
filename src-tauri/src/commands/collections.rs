use crate::app_state::AppState;
use crate::commands::errors::{bounded_send, coded, coded_ctx};
use crate::network::ed2k::collection::{Collection, CollectionFile};
use crate::types::{Transfer, TransferDirection, TransferStatus};
use tauri::Emitter;
use tauri_plugin_dialog::DialogExt;

const MAX_COLLECTION_FIELD_LEN: usize = 1024;
const MAX_COLLECTION_ENTRY_NAME_LEN: usize = 1024;

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionDownloadResult {
    pub queued_count: usize,
    pub skipped_count: usize,
    pub oversize_count: usize,
    pub failed_count: usize,
}

#[tauri::command]
pub async fn load_collection(
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<Collection, String> {
    let p = std::path::PathBuf::from(&path);
    if p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(coded(
            "collections_path_no_parent_dir",
            "Path must not contain '..' components",
        ));
    }
    let ext = p
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase());
    if !matches!(ext.as_deref(), Some("emulecollection") | Some("txt")) {
        return Err(coded(
            "collections_invalid_file_extension",
            "File must be a .emulecollection or .txt file",
        ));
    }
    let p2 = p.clone();
    let canonical = tokio::task::spawn_blocking(move || {
        if !p2.exists() {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "file does not exist",
            ))
        } else {
            std::fs::canonicalize(&p2)
        }
    })
    .await
    .map_err(|e| {
        coded_ctx(
            "collections_canonicalize_task_failed",
            "Canonicalize task failed",
            e,
        )
    })?
    .map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            coded("collections_file_not_found", "File does not exist")
        } else {
            coded_ctx("collections_cannot_resolve_path", "Cannot resolve path", e)
        }
    })?;
    let config = state.config.read().await;
    let download_root = std::path::PathBuf::from(&config.settings.download_folder);
    let mut allowed_dirs: Vec<String> = config.settings.shared_folders.clone();
    if !config.settings.download_folder.is_empty() {
        allowed_dirs.push(download_root.to_string_lossy().into_owned());
    }
    drop(config);

    if allowed_dirs.is_empty() {
        return Err(coded(
            "collections_no_folders_configured",
            "No shared or download folders configured",
        ));
    }
    let canonical = crate::security::filesystem::verify_existing_path(&canonical, &allowed_dirs)
        .map_err(|e| {
            coded_ctx(
                "collections_file_outside_allowed_dirs",
                "Collection file must be inside an unchanged approved root",
                e,
            )
        })?;

    // Cap the on-disk size before `Collection::load` reads the whole file into
    // memory (`std::fs::read`). `open_collection_file` already enforces this;
    // the webview-callable `load_collection` path did not, so a multi-GiB file
    // inside an allowed folder could OOM the client.
    const MAX_COLLECTION_BYTES: u64 = 32 * 1024 * 1024;
    let meta = tokio::fs::metadata(&canonical)
        .await
        .map_err(|e| coded_ctx("collections_stat_failed", "Cannot stat collection file", e))?;
    if meta.len() > MAX_COLLECTION_BYTES {
        return Err(coded(
            "collections_file_too_large",
            "Collection file too large (max 32 MiB)",
        ));
    }

    tokio::task::spawn_blocking(move || {
        Collection::load(&canonical)
            .map_err(|e| coded_ctx("collections_load_failed", "Failed to load collection", e))
    })
    .await
    .map_err(|e| coded_ctx("collections_load_task_failed", "Load task failed", e))?
}

/// Native picker path for Library. Selecting a file is an explicit user
/// authorization, so use the same bounded parser as OS file-association opens
/// instead of the raw IPC command's shared/download-root policy.
#[tauri::command]
pub async fn pick_and_load_collection(app: tauri::AppHandle) -> Result<Option<Collection>, String> {
    let selected = tokio::task::spawn_blocking(move || {
        app.dialog()
            .file()
            .add_filter("eMule Collection", &["emulecollection", "txt"])
            .blocking_pick_file()
            .map(|file| {
                file.into_path().map_err(|e| {
                    coded_ctx("collections_invalid_path", "Invalid collection path", e)
                })
            })
            .transpose()
    })
    .await
    .map_err(|e| coded_ctx("collections_dialog_task_failed", "Open dialog failed", e))??;
    let Some(selected) = selected else {
        return Ok(None);
    };
    crate::commands::deeplink::open_collection_file(selected.to_string_lossy().into_owned())
        .await
        .map(Some)
}

async fn create_collection_internal(
    state: &AppState,
    name: String,
    author: String,
    files: Vec<CollectionFile>,
    output_path: String,
    binary: bool,
    enforce_output_scope: bool,
) -> Result<String, String> {
    if name.len() > MAX_COLLECTION_FIELD_LEN {
        return Err(coded_ctx(
            "collections_name_too_long",
            format!("Collection name exceeds {MAX_COLLECTION_FIELD_LEN} bytes"),
            MAX_COLLECTION_FIELD_LEN,
        ));
    }
    if author.len() > MAX_COLLECTION_FIELD_LEN {
        return Err(coded_ctx(
            "collections_author_too_long",
            format!("Collection author exceeds {MAX_COLLECTION_FIELD_LEN} bytes"),
            MAX_COLLECTION_FIELD_LEN,
        ));
    }
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
    for file in &files {
        if file.name.trim().is_empty() {
            return Err(coded(
                "collections_empty_file_name",
                "Collection entries must have non-empty names",
            ));
        }
        if file.name.len() > MAX_COLLECTION_ENTRY_NAME_LEN {
            return Err(coded_ctx(
                "collections_file_name_too_long",
                format!("Collection entry name exceeds {MAX_COLLECTION_ENTRY_NAME_LEN} bytes"),
                MAX_COLLECTION_ENTRY_NAME_LEN,
            ));
        }
        if file.hash.len() != 32 || !file.hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(coded(
                "collections_invalid_file_hash",
                "Collection entries must use 32-character ED2K file hashes",
            ));
        }
        if !file.aich_hash.is_empty()
            && (file.aich_hash.len() != 40
                || !file.aich_hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(coded(
                "collections_invalid_aich_hash",
                "Collection AICH hashes must be 40-character hexadecimal SHA-1 roots",
            ));
        }
        if !file.ember_file_hash.is_empty()
            && crate::security::parse_ember_file_hash(Some(&file.ember_file_hash))
                .ok()
                .flatten()
                .is_none()
        {
            return Err(coded(
                "collections_invalid_ember_file_hash",
                "Collection Ember hashes must be 64-character hexadecimal BLAKE3 digests",
            ));
        }
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
                    parent
                        .canonicalize()
                        .map(|p| p.join(path.file_name().unwrap_or_default()))
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "invalid path",
                    ))
                }
            })
        })
        .await
        .map_err(|e| coded_ctx("collections_canonicalize_task", "Path resolution failed", e))?
        .map_err(|e| coded_ctx("collections_invalid_output_path", "Invalid output path", e))?
    };

    if canonical
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(coded(
            "collections_output_path_no_parent_dir",
            "Output path must not contain '..' components",
        ));
    }

    let mut scoped_dirs: Option<Vec<String>> = None;
    if enforce_output_scope {
        let config = state.config.read().await;
        let mut allowed_dirs: Vec<String> = config.settings.shared_folders.clone();
        if !config.settings.download_folder.is_empty() {
            allowed_dirs.push(
                std::path::PathBuf::from(&config.settings.download_folder)
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        drop(config);

        if allowed_dirs.is_empty() {
            return Err(coded(
                "collections_no_folders_configured",
                "No shared or download folders configured",
            ));
        }
        crate::security::filesystem::verify_output_path(&canonical, &allowed_dirs).map_err(
            |e| {
                coded_ctx(
                    "collections_output_outside_allowed_dirs",
                    "Output path must be inside an unchanged approved root",
                    e,
                )
            },
        )?;
        scoped_dirs = Some(allowed_dirs);
    }

    let ext = canonical
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase());
    if !matches!(ext.as_deref(), Some("emulecollection") | Some("txt")) {
        return Err(coded(
            "collections_output_invalid_extension",
            "Output file must have .emulecollection or .txt extension",
        ));
    }
    let write_path = canonical.clone();
    tokio::task::spawn_blocking(move || {
        let bytes = if binary {
            collection
                .to_binary_bytes()
                .map_err(|e| coded_ctx("collections_save_failed", "Failed to save", e))?
        } else {
            collection.to_text_bytes().into_bytes()
        };
        match scoped_dirs {
            // Scoped export: create the file through a pinned parent-directory
            // handle rather than by pathname. `verify_output_path` above only
            // proves the location was inside an approved root *at check time*,
            // and both the write and `atomic_write`'s own temp file resolve
            // the parent by name afterwards — so a directory swapped in
            // between could redirect the export out of the approved tree.
            // `archive_recovery` and the download-completion path already
            // write through this helper for the same reason.
            Some(allowed_dirs) => {
                use std::io::Write;
                // Write a sibling temp through the pinned parent handle and
                // rename it over the target, so the export keeps the
                // crash-safety the unscoped branch has.
                //
                // Deleting the old file first and then creating the new one —
                // which is what `create_new` seemed to require — meant any
                // failure after the delete (disk full, permissions changed, a
                // crash) left the user with no collection file at all. The
                // rename is the only step that resolves by pathname, and it is
                // the same step `atomic_write` relies on.
                let tmp_path = crate::security::unique_tmp_path(&write_path);
                let (_, mut file) = crate::security::filesystem::create_new_verified_output(
                    &tmp_path,
                    &allowed_dirs,
                )
                .map_err(|e| {
                    coded_ctx(
                        "collections_output_outside_allowed_dirs",
                        "Output path must be inside an unchanged approved root",
                        e,
                    )
                })?;
                let mut written = file.write_all(&bytes).and_then(|()| file.sync_all());
                // Close before renaming: Windows will not replace a file that
                // still has an open handle on the source.
                drop(file);
                if written.is_ok() {
                    written = std::fs::rename(&tmp_path, &write_path);
                }
                if let Err(e) = written {
                    // Never leave the scratch file behind next to the user's
                    // collections; the original is still intact either way.
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err(coded_ctx("collections_save_failed", "Failed to save", e));
                }
            }
            // Unscoped export (the user picked the destination themselves):
            // no approved root applies, so keep the crash-safe atomic write.
            None => crate::security::atomic_write(&write_path, &bytes, false)
                .map_err(|e| coded_ctx("collections_save_failed", "Failed to save", e))?,
        }
        Ok::<_, String>(())
    })
    .await
    .map_err(|e| coded_ctx("collections_save_task_failed", "Save task failed", e))??;
    Ok(format!(
        "Created collection '{name}' at {}",
        canonical.display()
    ))
}

/// Legacy raw-path command. Retains the Library-root restriction so arbitrary
/// WebView IPC cannot write elsewhere; normal Library exports use the native
/// save dialog command below.
#[tauri::command]
pub async fn create_collection(
    state: tauri::State<'_, AppState>,
    name: String,
    author: String,
    files: Vec<CollectionFile>,
    output_path: String,
    binary: bool,
) -> Result<String, String> {
    create_collection_internal(&state, name, author, files, output_path, binary, true).await
}

#[tauri::command]
pub async fn create_collection_with_dialog(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    name: String,
    author: String,
    files: Vec<CollectionFile>,
    binary: bool,
) -> Result<Option<String>, String> {
    let extension = if binary { "emulecollection" } else { "txt" };
    let filter_name = if binary {
        "eMule Collection"
    } else {
        "ED2K Links"
    };
    let safe_name = crate::security::sanitize_filename(&name);
    let default_name = format!("{safe_name}.{extension}");
    let selected = tokio::task::spawn_blocking(move || {
        app.dialog()
            .file()
            .add_filter(filter_name, &[extension])
            .set_file_name(default_name)
            .blocking_save_file()
            .map(|file| {
                file.into_path().map_err(|e| {
                    coded_ctx("collections_invalid_output_path", "Invalid output path", e)
                })
            })
            .transpose()
    })
    .await
    .map_err(|e| coded_ctx("collections_dialog_task_failed", "Save dialog failed", e))??;
    let Some(selected) = selected else {
        return Ok(None);
    };
    create_collection_internal(
        &state,
        name,
        author,
        files,
        selected.to_string_lossy().into_owned(),
        binary,
        true,
    )
    .await
    .map(Some)
}

#[tauri::command]
pub async fn download_collection_files(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    files: Vec<CollectionFile>,
) -> Result<CollectionDownloadResult, String> {
    let _download_admission = state.download_admission.lock().await;
    if files.len() > 200 {
        return Err(coded(
            "collections_too_many_files",
            "Collection too large (max 200 files)",
        ));
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
    let mut failed_count = 0usize;
    for file in files {
        if file.hash.is_empty()
            || file.name.trim().is_empty()
            || file.name.len() > MAX_COLLECTION_ENTRY_NAME_LEN
            || file.size == 0
        {
            skipped_count += 1;
            tracing::debug!("Skipping collection entry: invalid name, hash, or size");
            continue;
        }
        if file.hash.len() != 32 || hex::decode(&file.hash).is_err() {
            skipped_count += 1;
            tracing::debug!("Skipping collection entry '{}': invalid hash", file.name);
            continue;
        }
        if !file.aich_hash.is_empty()
            && (file.aich_hash.len() != 40
                || !file.aich_hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            skipped_count += 1;
            tracing::debug!("Skipping collection entry '{}': invalid AICH", file.name);
            continue;
        }
        let ember_file_hash = match crate::security::parse_ember_file_hash(
            (!file.ember_file_hash.is_empty()).then_some(file.ember_file_hash.as_str()),
        ) {
            Ok(value) => value,
            Err(_) => {
                skipped_count += 1;
                tracing::debug!(
                    "Skipping collection entry '{}': invalid Ember digest",
                    file.name
                );
                continue;
            }
        };
        if max_dl_bytes > 0 && file.size > max_dl_bytes {
            oversize_count += 1;
            tracing::debug!(
                "Skipping collection entry '{}': size {} exceeds configured cap {}",
                file.name,
                file.size,
                max_dl_bytes
            );
            continue;
        }
        let safe_name = crate::security::sanitize_filename(&file.name);
        let transfer_id = uuid::Uuid::new_v4().to_string();
        let control = crate::sharing::manager::TransferControl::new();
        if add_paused {
            control.pause();
        }

        let expected_aich = match crate::security::parse_expected_aich(
            (!file.aich_hash.is_empty()).then_some(file.aich_hash.as_str()),
        ) {
            Ok(value) => value,
            Err(_) => {
                failed_count += 1;
                tracing::warn!(
                    "Skipping collection entry '{}': malformed AICH pin",
                    file.name
                );
                continue;
            }
        };

        let transfer = Transfer {
            id: transfer_id.clone(),
            file_name: safe_name.clone(),
            file_hash: file.hash.clone(),
            peer_id: String::new(),
            peer_name: String::new(),
            direction: TransferDirection::Download,
            status: if add_paused {
                TransferStatus::Paused
            } else {
                TransferStatus::Searching
            },
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
            preview_ready: false,
            ember_sources: 0,
            client_software: String::new(),
            country_code: None,
            user_hash: None,
            ember_hash: None,
            expected_aich: expected_aich.clone(),
            ember_file_hash: ember_file_hash.clone(),
            completed_path: None,
            up_part_status: None,
            up_part_count: None,
            up_peer_part_status: None,
            ember_verified: false,
        };

        let (active_now, persisted_transfer) = {
            let mut mgr = state.transfer_manager.write().await;
            if let Some(existing_id) = mgr.pending_transfer_id_for_hash(&file.hash) {
                let existing = mgr.get_transfer(&existing_id);
                let existing_pin = existing.and_then(|transfer| transfer.expected_aich.clone());
                let existing_ember = existing.and_then(|transfer| transfer.ember_file_hash.clone());
                if expected_aich.is_some() && existing_pin != expected_aich {
                    failed_count += 1;
                } else if ember_file_hash.is_some() && existing_ember != ember_file_hash {
                    failed_count += 1;
                } else {
                    skipped_count += 1;
                }
                continue;
            }
            if let Err(error) = super::transfers::ensure_pending_download_budget(&mgr, &[file.size])
            {
                tracing::warn!(
                    "Collection admission stopped at the aggregate pending-download budget: {error}"
                );
                failed_count += 1;
                continue;
            }
            let active_now = mgr.enqueue(transfer.clone());
            mgr.register_control(&transfer_id, control.clone());
            let persisted = mgr.get_transfer(&transfer_id).cloned().unwrap_or(transfer);
            (active_now, persisted)
        };
        if let Err(error) = super::transfers::persist_transfer(&state, &persisted_transfer).await {
            // The transfer has not reached the network worker yet. Remove the
            // transient manager entry so startup can never mistake a future
            // partial file for an orphan after a failed database write.
            let promoted = {
                let mut mgr = state.transfer_manager.write().await;
                mgr.remove(&transfer_id)
            };
            if !promoted.is_empty() {
                super::transfers::start_promoted_downloads(&state, &promoted).await;
            }
            tracing::warn!(
                "Skipping collection entry '{}': could not persist transfer before start: {error}",
                file.name
            );
            failed_count += 1;
            continue;
        }
        let _ = app.emit("transfer-started", &persisted_transfer);

        if active_now && !add_paused {
            if let Err(e) = bounded_send(
                &state.network_tx,
                crate::network::NetworkCommand::StartDownload {
                    file_hash: file.hash.clone(),
                    file_name: safe_name.clone(),
                    file_size: file.size,
                    peer_ip: String::new(),
                    peer_port: 0,
                    // Collection entries don't carry per-file source
                    // addresses; the network task handles full source
                    // discovery for each.
                    extra_sources: Vec::new(),
                    ember_file_hash: ember_file_hash.clone().unwrap_or_default(),
                    expected_aich: expected_aich.clone(),
                    transfer_id: transfer_id.clone(),
                    control: control.clone(),
                    friend_ember_hash: None,
                    discovery_only: false,
                },
            )
            .await
            {
                tracing::warn!(
                    "Failed to send StartDownload for collection entry '{}': {e}",
                    file.name
                );
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
                    if let Err(persist_error) =
                        super::transfers::persist_transfer(&state, &failed).await
                    {
                        tracing::error!(
                            "Failed to persist collection network-start failure for {}: {persist_error}",
                            transfer_id
                        );
                    }
                    let _ = app.emit("transfer-failed", &failed);
                }
                failed_count += 1;
            } else {
                queued_count += 1;
            }
        } else {
            // Queued / add-paused: still run KAD+TCP+UDP discovery so sources
            // are ready when the download is promoted or resumed.
            if let Err(e) = bounded_send(
                &state.network_tx,
                crate::network::NetworkCommand::StartDownload {
                    file_hash: file.hash,
                    file_name: safe_name,
                    file_size: file.size,
                    peer_ip: String::new(),
                    peer_port: 0,
                    extra_sources: Vec::new(),
                    ember_file_hash: ember_file_hash.unwrap_or_default(),
                    expected_aich: expected_aich.clone(),
                    transfer_id: transfer_id.clone(),
                    control,
                    discovery_only: true,
                    friend_ember_hash: None,
                },
            )
            .await
            {
                tracing::warn!(
                    "Failed to send discovery-only StartDownload for collection entry '{}': {e}",
                    file.name
                );
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
                    if let Err(persist_error) =
                        super::transfers::persist_transfer(&state, &failed).await
                    {
                        tracing::error!(
                            "Failed to persist collection discovery-start failure for {}: {persist_error}",
                            transfer_id
                        );
                    }
                    let _ = app.emit("transfer-failed", &failed);
                }
                failed_count += 1;
            } else {
                queued_count += 1;
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
    Ok(CollectionDownloadResult {
        queued_count,
        skipped_count,
        oversize_count,
        failed_count,
    })
}
