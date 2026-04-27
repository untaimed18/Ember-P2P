use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tauri::Emitter;

use crate::app_state::AppState;
use crate::network::NetworkCommand;
use crate::sharing::manager::TransferControl;
use crate::types::*;

async fn db_blocking<F>(f: F) where F: FnOnce() + Send + 'static {
    if let Err(e) = tokio::task::spawn_blocking(f).await {
        tracing::warn!("DB task failed: {e}");
    }
}

fn parse_peer_ip(peer_id: &str) -> String {
    if let Ok(addr) = peer_id.parse::<std::net::SocketAddr>() {
        return addr.ip().to_string();
    }
    peer_id.rsplit_once(':').map(|(ip, _)| ip.to_string()).unwrap_or_default()
}

fn parse_peer_port(peer_id: &str) -> u16 {
    if let Ok(addr) = peer_id.parse::<std::net::SocketAddr>() {
        return addr.port();
    }
    peer_id.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(0)
}

fn transfer_status_key(status: &TransferStatus) -> &'static str {
    match status {
        TransferStatus::Searching => "searching",
        TransferStatus::Queued => "queued",
        TransferStatus::Active => "active",
        TransferStatus::Paused => "paused",
        TransferStatus::Stopped => "stopped",
        TransferStatus::Verifying => "verifying",
        TransferStatus::Completing => "completing",
        TransferStatus::Completed => "completed",
        TransferStatus::Failed => "failed",
        TransferStatus::Hashing => "hashing",
        TransferStatus::Insufficient => "insufficient",
        TransferStatus::NoneNeeded => "noneneeded",
    }
}

pub(crate) async fn persist_transfer(state: &AppState, transfer: &Transfer) {
    let db = state.db.clone();
    let tid = transfer.id.clone();
    let transfer = transfer.clone();
    match tokio::task::spawn_blocking(move || db.save_transfer(&transfer)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!("Failed to persist transfer {}: {e}", transfer_id_short(&tid)),
        Err(e) => tracing::warn!("Transfer persist task panicked: {e}"),
    }
}

fn transfer_id_short(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

async fn persist_transfer_status(state: &AppState, transfer_id: &str, status: &TransferStatus) {
    let db = state.db.clone();
    let tid = transfer_id.to_string();
    let status = transfer_status_key(status).to_string();
    match tokio::task::spawn_blocking(move || db.update_transfer_status(&tid, &status)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!("Failed to persist transfer status: {e}"),
        Err(e) => tracing::warn!("Transfer status persist task panicked: {e}"),
    }
}

async fn start_promoted_downloads(state: &AppState, promoted: &[Transfer]) {
    for transfer in promoted {
        let control = {
            let mut manager = state.transfer_manager.write().await;
            let control = TransferControl::new();
            manager.register_control(&transfer.id, control.clone());
            control
        };
        if let Err(e) = state
            .network_tx
            .send(NetworkCommand::StartDownload {
                file_hash: transfer.file_hash.clone(),
                file_name: transfer.file_name.clone(),
                file_size: transfer.total_size,
                peer_ip: parse_peer_ip(&transfer.peer_id),
                peer_port: parse_peer_port(&transfer.peer_id),
                // Promoting a queued transfer from the DB doesn't carry
                // the original search-result address list — the network
                // task does its own discovery as usual.
                extra_sources: Vec::new(),
                transfer_id: transfer.id.clone(),
                control,
            })
            .await
        {
            tracing::warn!("Failed to start promoted download {}: {e}", transfer.id);
            let mut manager = state.transfer_manager.write().await;
            let _ = manager.fail(
                &transfer.id,
                "Network channel unavailable",
                Some("permanent".to_string()),
                None,
            );
        }
    }
}

/// Try to delete a file, retrying with a delay if it fails (e.g. because
/// the download task still holds the handle on Windows).
async fn delete_with_retry(path: &Path, max_attempts: u32, delay_ms: u64) {
    if !path.exists() {
        return;
    }
    for attempt in 0..max_attempts {
        match tokio::fs::remove_file(path).await {
            Ok(()) => {
                tracing::debug!("Deleted {}", path.display());
                return;
            }
            Err(e) if attempt + 1 < max_attempts => {
                tracing::debug!(
                    "Delete {} attempt {}/{} failed ({}), retrying...",
                    path.display(), attempt + 1, max_attempts, e
                );
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
            Err(e) => {
                tracing::warn!("Failed to delete {} after {} attempts: {}", path.display(), max_attempts, e);
            }
        }
    }
}

async fn cleanup_partial_files(download_folder: &str, transfer_id: &str) {
    if uuid::Uuid::parse_str(transfer_id).is_err() {
        tracing::warn!("cleanup_partial_files: invalid transfer_id, skipping");
        return;
    }
    let temp_dir = std::path::PathBuf::from(download_folder).join("Temp");
    let part_path = temp_dir.join(format!("{transfer_id}.part"));
    let met_path = temp_dir.join(format!("{transfer_id}.part.met"));
    tokio::join!(
        delete_with_retry(&part_path, 6, 500),
        delete_with_retry(&met_path, 6, 500),
    );
}

/// Walk `<download_folder>/Temp/` and remove any `.part` / `.part.met`
/// files whose `<uuid>` prefix doesn't match a transfer ID the
/// `transfer_manager` knows about. Idempotent and safe to call at
/// process startup once the DB-backed resume logic has populated the
/// manager — workers that own a known `.part` are skipped because
/// their UUID is in `known_ids`.
///
/// Catches:
///   * orphans left over from a previous crash where the cleanup path
///     didn't run,
///   * orphans from a `cleanup_partial_files` attempt that failed
///     because the upload server briefly held the .part open on Windows,
///   * orphans from a cross-device `move_part_to_final` whose source
///     remove step failed after the copy already succeeded, and
///   * .part files left behind by users who wiped or replaced their
///     transfers DB without also clearing the Temp folder.
///
/// Files whose basename isn't a valid UUID are ignored — only Ember-
/// created part files use UUID basenames, so user-managed files in the
/// same folder are never touched.
pub async fn sweep_orphan_part_files(
    download_folder: &str,
    known_ids: &std::collections::HashSet<String>,
) {
    let temp_dir = std::path::PathBuf::from(download_folder).join("Temp");
    if !temp_dir.is_dir() {
        return;
    }
    let mut entries = match tokio::fs::read_dir(&temp_dir).await {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(
                "Orphan sweep: failed to read {}: {e}",
                temp_dir.display()
            );
            return;
        }
    };
    let mut swept_part: u32 = 0;
    let mut swept_met: u32 = 0;
    let mut skipped_known: u32 = 0;
    let mut failed: u32 = 0;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Match `<uuid>.part.met` first (longer suffix) so we don't
        // accidentally treat the `.met` file as a `.part` whose UUID
        // ends in `.met`.
        let (uuid_str, is_met) = if let Some(stem) = name.strip_suffix(".part.met") {
            (stem, true)
        } else if let Some(stem) = name.strip_suffix(".part") {
            (stem, false)
        } else {
            continue;
        };
        if uuid::Uuid::parse_str(uuid_str).is_err() {
            // Not an Ember-managed file; leave it alone.
            continue;
        }
        if known_ids.contains(uuid_str) {
            skipped_known += 1;
            continue;
        }
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {
                if is_met {
                    swept_met += 1;
                } else {
                    swept_part += 1;
                }
                tracing::info!("Orphan sweep: removed {}", path.display());
            }
            Err(e) => {
                failed += 1;
                tracing::warn!(
                    "Orphan sweep: failed to remove {}: {e}",
                    path.display()
                );
            }
        }
    }
    if swept_part > 0 || swept_met > 0 || failed > 0 {
        tracing::info!(
            "Orphan sweep finished: removed {swept_part} .part and {swept_met} .part.met file(s) from {} ({skipped_known} skipped — still in use, {failed} failed to delete)",
            temp_dir.display()
        );
    }
}

#[tauri::command]
pub async fn start_download(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    file_hash: String,
    file_name: String,
    file_size: u64,
    peer_ip: String,
    peer_port: u16,
    // `extra_sources`: additional candidate sources known up-front,
    // e.g. the rest of `result.source_addresses` from a search hit
    // beyond the primary peer the frontend already passes as
    // `peer_ip`/`peer_port`. Each entry is an "ip:port" string.
    // Optional and capped server-side; a missing/empty list is
    // treated as "no extras" and the network task does its own
    // discovery (KAD + server queries) as usual. We cap the parsed
    // result here at 64 to avoid pushing pathological lists across
    // the IPC boundary; the network task applies its own stricter
    // cap (`MAX_SEED_EXTRA_SOURCES = 49`) after IP-filter / ban /
    // dedup validation.
    extra_sources: Option<Vec<String>>,
) -> Result<StartDownloadResponse, String> {
    let file_name = crate::security::sanitize_filename(&file_name);

    if file_hash.len() != 32 || hex::decode(&file_hash).is_err() {
        return Err("Invalid file hash".into());
    }

    if !peer_ip.is_empty() {
        peer_ip
            .parse::<std::net::IpAddr>()
            .map_err(|_| "Invalid peer IP")?;
    }

    // Parse + cheap-validate extra sources at the IPC boundary. Anything
    // that doesn't parse as `ip:port` with a non-zero IPv4/IPv6 host and
    // a non-zero port is dropped silently — the search-result feed
    // sometimes carries "0.0.0.0:0" placeholders for LowID rows we can't
    // dial directly. Full security validation (IP filter, banned IPs,
    // dedup against primary, special-use addresses) runs in the network
    // task where the live state is available.
    const MAX_EXTRA_SOURCES_IPC: usize = 64;
    let parsed_extras: Vec<(String, u16)> = extra_sources
        .unwrap_or_default()
        .into_iter()
        .take(MAX_EXTRA_SOURCES_IPC)
        .filter_map(|addr| {
            let addr = addr.trim();
            if addr.is_empty() {
                return None;
            }
            let (ip_part, port_part) = addr.rsplit_once(':')?;
            let port: u16 = port_part.parse().ok()?;
            if port == 0 {
                return None;
            }
            // Strip IPv6 brackets if present so the network task's
            // `Ipv4Addr::parse` path matches. IPv6 sources aren't
            // supported on the eD2K download path; drop them now.
            let ip_str = ip_part.trim_start_matches('[').trim_end_matches(']').to_string();
            ip_str.parse::<std::net::Ipv4Addr>().ok()?;
            Some((ip_str, port))
        })
        .collect();

    // Zero-byte ed2k files are valid (hash must be empty-file MD4 on the network stack).

    // D16: reject oversized files up front instead of enqueueing them and
    // failing later at network-start with a confusing "exceeds maximum"
    // error. `max_download_file_size_gib` is user-configurable; a size of
    // 0 disables the cap.
    {
        let config = state.config.read().await;
        let cap_gib = config.settings.max_download_file_size_gib;
        if cap_gib > 0 {
            let cap_bytes = (cap_gib as u64).saturating_mul(1024 * 1024 * 1024);
            if file_size > cap_bytes {
                let gib = (file_size as f64) / (1024.0 * 1024.0 * 1024.0);
                return Err(format!(
                    "File size {:.2} GiB exceeds your configured maximum of {} GiB — raise Max Download Size in Settings > Downloads to enqueue this file.",
                    gib, cap_gib
                ));
            }
        }
    }

    let transfer_id = uuid::Uuid::new_v4().to_string();

    let has_source = !peer_ip.is_empty() && peer_ip != "0.0.0.0" && peer_port > 0;

    let add_paused = {
        let config = state.config.read().await;
        config.settings.add_downloads_paused
    };
    let control = TransferControl::new();
    if add_paused {
        control.pause();
    }

    let transfer = Transfer {
        id: transfer_id.clone(),
        file_name: file_name.clone(),
        file_hash: file_hash.clone(),
        peer_id: if has_source {
            format!("{peer_ip}:{peer_port}")
        } else {
            String::new()
        },
        peer_name: String::new(),
        direction: TransferDirection::Download,
        status: if add_paused {
            TransferStatus::Paused
        } else if has_source {
            TransferStatus::Queued
        } else {
            TransferStatus::Searching
        },
        progress: 0.0,
        speed: 0,
        total_size: file_size,
        transferred: 0,
        completed_size: 0,
        started_at: chrono::Utc::now().timestamp(),
        failure_reason: None,
        failure_kind: None,
        failure_stage: None,
        priority: "auto".to_string(),
        sources: if has_source { 1 } else { 0 },
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

    let active_now = {
        let mut manager = state.transfer_manager.write().await;
        if let Some(existing_id) = manager.pending_transfer_id_for_hash(&file_hash) {
            return Ok(StartDownloadResponse {
                transfer_id: existing_id,
                already_queued: true,
            });
        }
        let active_now = manager.enqueue(transfer.clone());
        manager.register_control(&transfer_id, control.clone());
        active_now
    };

    let persisted_transfer = {
        let manager = state.transfer_manager.read().await;
        manager
            .get_transfer(&transfer_id)
            .cloned()
            .unwrap_or_else(|| transfer.clone())
    };
    persist_transfer(&state, &persisted_transfer).await;

    let _ = app.emit("transfer-started", &persisted_transfer);

    if !active_now || add_paused {
        return Ok(StartDownloadResponse {
            transfer_id,
            already_queued: false,
        });
    }

    state
        .network_tx
        .send(NetworkCommand::StartDownload {
            file_hash,
            file_name,
            file_size,
            peer_ip,
            peer_port,
            extra_sources: parsed_extras,
            transfer_id: transfer_id.clone(),
            control,
        })
        .await
        .map_err(|e| format!("Failed to start download: {e}"))?;

    Ok(StartDownloadResponse {
        transfer_id,
        already_queued: false,
    })
}

#[tauri::command]
pub async fn pause_transfers_batch(
    state: tauri::State<'_, AppState>,
    transfer_ids: Vec<String>,
) -> Result<(), String> {
    let mut promoted_by_id: HashMap<String, Transfer> = HashMap::new();
    for transfer_id in &transfer_ids {
        let (status, promoted) = {
            let mut manager = state.transfer_manager.write().await;
            if let Some(control) = manager.get_control(transfer_id) {
                control.pause();
            }
            let promoted = manager.pause_and_promote(transfer_id);
            let status = manager.get_transfer(transfer_id).map(|t| t.status.clone());
            (status, promoted)
        };
        for p in promoted {
            promoted_by_id.entry(p.id.clone()).or_insert(p);
        }
        if let Some(status) = status {
            persist_transfer_status(&state, transfer_id, &status).await;
        }
    }
    for transfer_id in &transfer_ids {
        let _ = state
            .network_tx
            .send(NetworkCommand::PauseDownload {
                transfer_id: transfer_id.clone(),
            })
            .await;
    }
    let promoted: Vec<Transfer> = promoted_by_id.into_values().collect();
    start_promoted_downloads(&state, &promoted).await;
    Ok(())
}

#[tauri::command]
pub async fn resume_transfers_batch(
    state: tauri::State<'_, AppState>,
    transfer_ids: Vec<String>,
) -> Result<(), String> {
    let mut promoted_by_id: HashMap<String, Transfer> = HashMap::new();
    let mut restart_ids: Vec<String> = Vec::new();
    for transfer_id in transfer_ids {
        let (was_paused_active, promoted) = {
            let mut manager = state.transfer_manager.write().await;
            let was_paused_active = manager
                .active
                .get(&transfer_id)
                .map(|t| t.status == TransferStatus::Paused)
                .unwrap_or(false);
            if manager.get_control(&transfer_id).is_none() {
                manager.register_control(&transfer_id, TransferControl::new());
            }
            let promoted = manager.resume(&transfer_id);
            (was_paused_active, promoted)
        };
        if was_paused_active && promoted.is_empty() {
            restart_ids.push(transfer_id.clone());
        }
        for p in promoted {
            promoted_by_id.entry(p.id.clone()).or_insert(p);
        }
        let status = {
            let manager = state.transfer_manager.read().await;
            manager.get_transfer(&transfer_id).map(|t| t.status.clone())
        };
        if let Some(status) = status {
            persist_transfer_status(&state, &transfer_id, &status).await;
        }
    }
    let mut to_start: Vec<Transfer> = promoted_by_id.into_values().collect();
    {
        let manager = state.transfer_manager.read().await;
        for id in restart_ids {
            if let Some(t) = manager.get_transfer(&id) {
                to_start.push(t.clone());
            }
        }
    }
    start_promoted_downloads(&state, &to_start).await;
    Ok(())
}

#[tauri::command]
pub async fn stop_transfers_batch(
    state: tauri::State<'_, AppState>,
    transfer_ids: Vec<String>,
) -> Result<(), String> {
    let mut promoted_by_id: HashMap<String, Transfer> = HashMap::new();
    for transfer_id in transfer_ids {
        let promoted = {
            let mut manager = state.transfer_manager.write().await;
            if let Some(control) = manager.get_control(&transfer_id) {
                control.cancel();
            }
            manager.stop(&transfer_id)
        };
        for p in promoted {
            promoted_by_id.entry(p.id.clone()).or_insert(p);
        }
        persist_transfer_status(&state, &transfer_id, &TransferStatus::Stopped).await;
        let _ = state
            .network_tx
            .send(NetworkCommand::CancelDownload {
                transfer_id: transfer_id.clone(),
                cleanup_ack: None,
            })
            .await;
    }
    let promoted: Vec<Transfer> = promoted_by_id.into_values().collect();
    start_promoted_downloads(&state, &promoted).await;
    Ok(())
}

#[tauri::command]
pub async fn cancel_transfers_batch(
    state: tauri::State<'_, AppState>,
    transfer_ids: Vec<String>,
) -> Result<(), String> {
    let mut promoted_by_id: HashMap<String, Transfer> = HashMap::new();
    for transfer_id in transfer_ids {
        let (promoted, cancelled_info) = {
            let mut manager = state.transfer_manager.write().await;
            let info = manager.get_transfer(&transfer_id).map(|t| {
                (t.file_hash.clone(), t.file_name.clone(), t.total_size)
            });
            if let Some(control) = manager.get_control(&transfer_id) {
                control.cancel();
            }
            (manager.cancel(&transfer_id), info)
        };
        if let Some((file_hash, file_name, file_size)) = cancelled_info {
            let db = state.db.clone();
            db_blocking(move || { let _ = db.record_download_history(&file_hash, &file_name, file_size, "cancelled"); }).await;
        }
        for p in promoted {
            promoted_by_id.entry(p.id.clone()).or_insert(p);
        }

        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        let _ = state
            .network_tx
            .send(NetworkCommand::CancelDownload {
                transfer_id: transfer_id.clone(),
                cleanup_ack: Some(ack_tx),
            })
            .await;
        let _ = ack_rx.await;

        let dl_folder = {
            let config = state.config.read().await;
            config.settings.download_folder.clone()
        };
        cleanup_partial_files(&dl_folder, &transfer_id).await;
        {
            let db = state.db.clone();
            let tid = transfer_id.clone();
            db_blocking(move || { let _ = db.remove_transfer(&tid); }).await;
        }
    }
    let promoted: Vec<Transfer> = promoted_by_id.into_values().collect();
    start_promoted_downloads(&state, &promoted).await;
    Ok(())
}

#[tauri::command]
pub async fn pause_transfer(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let (status, promoted) = {
        let mut manager = state.transfer_manager.write().await;
        if let Some(control) = manager.get_control(&transfer_id) {
            control.pause();
        }
        let promoted = manager.pause_and_promote(&transfer_id);
        let status = manager.get_transfer(&transfer_id).map(|t| t.status.clone());
        (status, promoted)
    };
    if let Some(status) = status {
        persist_transfer_status(&state, &transfer_id, &status).await;
    }
    let _ = state
        .network_tx
        .send(NetworkCommand::PauseDownload {
            transfer_id: transfer_id.clone(),
        })
        .await;
    start_promoted_downloads(&state, &promoted).await;
    Ok(())
}

/// eMule "Stop": removes from active download without deleting files.
/// Different from Pause - a stopped file won't automatically resume.
#[tauri::command]
pub async fn stop_transfer(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let promoted = {
        let mut manager = state.transfer_manager.write().await;
        if let Some(control) = manager.get_control(&transfer_id) {
            control.cancel();
        }
        manager.stop(&transfer_id)
    };
    persist_transfer_status(&state, &transfer_id, &TransferStatus::Stopped).await;
    let _ = state
        .network_tx
        .send(NetworkCommand::CancelDownload {
            transfer_id: transfer_id.clone(),
            cleanup_ack: None,
        })
        .await;
    start_promoted_downloads(&state, &promoted).await;
    Ok(())
}

/// Completed file in `Downloads/`, or in-progress `.part` in `Temp/`.
/// Always prefers the final file in Downloads/ over the .part in Temp/ so
/// that a stale in-memory status never misdirects the user.
fn resolve_transfer_reveal_path(transfer: &Transfer, download_folder: &str) -> Result<PathBuf, String> {
    if transfer.direction != TransferDirection::Download {
        return Err("Not a download".into());
    }
    let root = PathBuf::from(download_folder);
    let completed_dir = root.join("Downloads");
    let temp_dir = root.join("Temp");
    let safe_name = crate::security::sanitize_filename(&transfer.file_name);
    let final_path = completed_dir.join(&safe_name);
    let part_path = temp_dir.join(format!("{}.part", transfer.id));

    let (candidate, base_dir) = if final_path.is_file() {
        (final_path, completed_dir)
    } else if part_path.is_file() {
        (part_path, temp_dir)
    } else {
        return Err("File not found on disk".into());
    };

    let canonical = candidate
        .canonicalize()
        .map_err(|e| format!("Invalid path: {e}"))?;
    let canonical_base = base_dir
        .canonicalize()
        .map_err(|e| format!("Invalid base: {e}"))?;
    if !canonical.starts_with(&canonical_base) {
        return Err("File path escapes download directory".into());
    }
    Ok(canonical)
}

#[cfg(windows)]
fn reveal_in_file_manager(path: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    // NTFS paths cannot contain `"` but a crafted / non-NTFS path could.
    // Reject it outright so we never interpolate user-controlled quote
    // characters into the raw command line below.
    let path_str = path
        .to_str()
        .ok_or_else(|| "Path contains non-UTF8 characters".to_string())?;
    if path_str.contains('"') || path_str.contains('\0') {
        return Err("Path contains unsupported characters".to_string());
    }
    // explorer.exe doesn't understand \\?\-prefixed long paths — strip it so
    // the /select, argument resolves against the user-visible namespace.
    let clean = path_str.strip_prefix(r"\\?\").unwrap_or(path_str);
    let raw = format!(r#"/select,"{clean}""#);
    std::process::Command::new("explorer")
        .raw_arg(raw)
        .spawn()
        .map_err(|e| format!("Failed to open File Explorer: {e}"))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn reveal_in_file_manager(path: &Path) -> Result<(), String> {
    let path_str = path.to_str().ok_or("Invalid path encoding")?;
    std::process::Command::new("open")
        .args(["-R", path_str])
        .spawn()
        .map_err(|e| format!("Failed to reveal in Finder: {e}"))?;
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn reveal_in_file_manager(path: &Path) -> Result<(), String> {
    use std::process::Command;
    let path_str = path.to_str().ok_or("Invalid path encoding")?;
    for cmd in ["nautilus", "dolphin", "nemo"] {
        if Command::new(cmd)
            .args(["--select", path_str])
            .spawn()
            .is_ok()
        {
            return Ok(());
        }
    }
    if let Some(parent) = path.parent() {
        opener::open(parent.to_string_lossy().as_ref())
            .map_err(|e| format!("Failed to open folder: {e}"))?;
        return Ok(());
    }
    Err("Could not open file location".into())
}

#[tauri::command]
pub async fn open_transfer_file_location(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let (transfer, dl_folder) = {
        let (mgr, cfg) = tokio::join!(
            state.transfer_manager.read(),
            state.config.read(),
        );
        (mgr.get_transfer(&transfer_id).cloned(), cfg.settings.download_folder.clone())
    };
    let transfer = transfer.ok_or("Transfer not found")?;
    let path = resolve_transfer_reveal_path(&transfer, &dl_folder)?;
    tokio::task::spawn_blocking(move || reveal_in_file_manager(&path))
        .await
        .map_err(|e| format!("Reveal task failed: {e}"))??;
    Ok(())
}

#[tauri::command]
pub async fn open_file(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let (transfer, dl_folder) = {
        let (mgr, cfg) = tokio::join!(
            state.transfer_manager.read(),
            state.config.read(),
        );
        (mgr.get_transfer(&transfer_id).cloned(), cfg.settings.download_folder.clone())
    };
    let transfer = transfer.ok_or("Transfer not found")?;
    let safe_name = crate::security::sanitize_filename(&transfer.file_name);
    if crate::security::is_dangerous_extension(&safe_name) {
        return Err("Cannot open potentially dangerous file types. Please use a dedicated application.".into());
    }
    let download_dir = std::path::PathBuf::from(&dl_folder)
        .join("Downloads");
    let file_path = download_dir.join(&safe_name);
    tokio::task::spawn_blocking(move || {
        if !file_path.exists() {
            return Err("Download has not finished yet".to_string());
        }
        let canonical = file_path.canonicalize().map_err(|e| format!("Invalid path: {e}"))?;
        let canonical_base = download_dir.canonicalize().map_err(|e| format!("Invalid base: {e}"))?;
        if !canonical.starts_with(&canonical_base) {
            return Err("File path escapes download directory".to_string());
        }
        opener::open(&canonical).map_err(|e| format!("Failed to open file: {e}"))
    }).await.map_err(|e| format!("Open task failed: {e}"))??;
    Ok(())
}

#[tauri::command]
pub async fn resume_transfer(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let (was_paused_active, promoted) = {
        let mut manager = state.transfer_manager.write().await;
        let was_paused_active = manager
            .active
            .get(&transfer_id)
            .map(|t| t.status == TransferStatus::Paused)
            .unwrap_or(false);
        if manager.get_control(&transfer_id).is_none() {
            manager.register_control(&transfer_id, TransferControl::new());
        }
        let promoted = manager.resume(&transfer_id);
        (was_paused_active, promoted)
    };
    let status = {
        let manager = state.transfer_manager.read().await;
        manager.get_transfer(&transfer_id).map(|t| t.status.clone())
    };
    if let Some(status) = status {
        persist_transfer_status(&state, &transfer_id, &status).await;
    }
    if was_paused_active && promoted.is_empty() {
        let transfer = {
            let manager = state.transfer_manager.read().await;
            manager.get_transfer(&transfer_id).cloned()
        };
        if let Some(t) = transfer {
            start_promoted_downloads(&state, &[t]).await;
        }
    } else {
        start_promoted_downloads(&state, &promoted).await;
    }
    Ok(())
}

#[tauri::command]
pub async fn cancel_transfer(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let (promoted, cancelled_info) = {
        let mut manager = state.transfer_manager.write().await;
        let info = manager.get_transfer(&transfer_id).map(|t| {
            (t.file_hash.clone(), t.file_name.clone(), t.total_size)
        });
        if let Some(control) = manager.get_control(&transfer_id) {
            control.cancel();
        }
        (manager.cancel(&transfer_id), info)
    };

    if let Some((file_hash, file_name, file_size)) = cancelled_info {
        let db = state.db.clone();
        db_blocking(move || { let _ = db.record_download_history(&file_hash, &file_name, file_size, "cancelled"); }).await;
    }

    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
    let (_, dl_folder) = tokio::join!(
        async {
            let _ = state
                .network_tx
                .send(NetworkCommand::CancelDownload {
                    transfer_id: transfer_id.clone(),
                    cleanup_ack: Some(ack_tx),
                })
                .await;
        },
        async {
            let config = state.config.read().await;
            config.settings.download_folder.clone()
        },
    );
    let _ = ack_rx.await;
    cleanup_partial_files(&dl_folder, &transfer_id).await;

    {
        let db = state.db.clone();
        let tid = transfer_id.clone();
        db_blocking(move || { let _ = db.remove_transfer(&tid); }).await;
    }

    start_promoted_downloads(&state, &promoted).await;
    Ok(())
}

#[tauri::command]
pub async fn remove_transfer(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let promoted = {
        let mut manager = state.transfer_manager.write().await;
        if let Some(control) = manager.get_control(&transfer_id) {
            control.cancel();
        }
        manager.remove(&transfer_id)
    };

    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
    let (_, dl_folder) = tokio::join!(
        async {
            let _ = state
                .network_tx
                .send(NetworkCommand::CancelDownload {
                    transfer_id: transfer_id.clone(),
                    cleanup_ack: Some(ack_tx),
                })
                .await;
        },
        async {
            let config = state.config.read().await;
            config.settings.download_folder.clone()
        },
    );
    let _ = ack_rx.await;
    let db = state.db.clone();
    let tid = transfer_id.clone();
    tokio::join!(
        cleanup_partial_files(&dl_folder, &transfer_id),
        async { db_blocking(move || { let _ = db.remove_transfer(&tid); }).await; },
    );
    start_promoted_downloads(&state, &promoted).await;
    Ok(())
}

#[tauri::command]
pub async fn get_transfers(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<Transfer>, String> {
    let manager = state.transfer_manager.read().await;
    Ok(manager.get_all())
}

/// Snapshot of peers currently waiting in our upload queue. Backs the
/// "Queued" tab in the transfers/uploads pane. Each row already carries
/// resolved file name + credit info so the frontend doesn't need any
/// follow-up commands per row.
#[tauri::command]
pub async fn get_upload_queue(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<UploadQueueClient>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetUploadQueueSnapshot { tx })
        .map_err(|e| format!("Network busy: {e}"))?;
    rx.await.map_err(|_| "Failed to get upload queue".to_string())
}

/// Snapshot of every persisted SecIdent credit record. Backs the
/// "Known Clients" tab — this is the lifetime view of every peer
/// we've ever traded credit with, sorted by most-recently-seen.
#[tauri::command]
pub async fn get_known_clients(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<KnownClient>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetKnownClientsSnapshot { tx })
        .map_err(|e| format!("Network busy: {e}"))?;
    rx.await.map_err(|_| "Failed to get known clients".to_string())
}

#[tauri::command]
pub async fn set_transfer_priority(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
    priority: String,
) -> Result<(), String> {
    let valid = ["verylow", "low", "normal", "high", "release", "auto"];
    if !valid.contains(&priority.as_str()) {
        return Err(format!("Invalid priority: {priority}. Must be one of: {valid:?}"));
    }
    {
        let mut manager = state.transfer_manager.write().await;
        manager.set_priority(&transfer_id, &priority);
    }
    let db = state.db.clone();
    let tid = transfer_id.clone();
    let prio = priority.clone();
    db_blocking(move || { let _ = db.update_transfer_priority(&tid, &prio); }).await;
    Ok(())
}

#[tauri::command]
pub async fn set_transfer_category(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
    category: String,
) -> Result<(), String> {
    if category.len() > 256 {
        return Err("Category name too long (max 256 bytes)".into());
    }
    {
        let mut manager = state.transfer_manager.write().await;
        manager.set_category(&transfer_id, &category);
    }
    let db = state.db.clone();
    let tid = transfer_id.clone();
    let cat = category.clone();
    db_blocking(move || { let _ = db.update_transfer_category(&tid, &cat); }).await;
    Ok(())
}

#[tauri::command]
pub async fn set_preview_priority(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
    enabled: bool,
) -> Result<(), String> {
    let transfer = {
        let mut manager = state.transfer_manager.write().await;
        manager.set_preview_priority(&transfer_id, enabled);
        manager.get_transfer(&transfer_id).cloned()
    };
    if let Some(t) = transfer {
        persist_transfer(&state, &t).await;
    }
    Ok(())
}

/// Pause every active download.
///
/// L7 note: this operation is eventually-consistent, not atomic. It takes
/// a write lock on the transfer manager to capture the set of active IDs,
/// then fans out individual `NetworkCommand::PauseDownload` messages. If
/// the user resumes a transfer concurrently, the resume and the broadcast
/// pause may interleave; last command wins per transfer. Callers should
/// debounce in the UI rather than expect a transactional guarantee.
#[tauri::command]
pub async fn pause_all_transfers(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let (statuses, pause_ids) = {
        let mut manager = state.transfer_manager.write().await;
        let active_ids: Vec<String> = manager.active.iter()
            .filter(|(_, t)| t.direction == TransferDirection::Download)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &active_ids {
            if let Some(control) = manager.get_control(id) {
                control.pause();
            }
            manager.pause(id);
        }
        let queued_ids: Vec<String> = manager
            .queue
            .iter()
            .filter(|t| t.direction == TransferDirection::Download && t.status != TransferStatus::Paused && t.status != TransferStatus::Stopped)
            .map(|t| t.id.clone())
            .collect();
        for id in &queued_ids {
            manager.pause(id);
        }
        let all_ids: Vec<String> = active_ids.iter().chain(queued_ids.iter()).cloned().collect();
        let statuses = active_ids.into_iter()
            .chain(queued_ids)
            .filter_map(|id| manager.get_transfer(&id).map(|t| (id, t.status.clone())))
            .collect::<Vec<_>>();
        (statuses, all_ids)
    };
    for id in &pause_ids {
        let _ = state
            .network_tx
            .send(NetworkCommand::PauseDownload {
                transfer_id: id.clone(),
            })
            .await;
    }
    futures::future::join_all(
        statuses.into_iter().map(|(id, status)| {
            let state = &state;
            async move { persist_transfer_status(state, &id, &status).await; }
        })
    ).await;
    Ok(())
}

#[tauri::command]
/// Resume every paused / stopped download. See pause_all_transfers for the
/// same eventual-consistency caveat.
pub async fn resume_all_transfers(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let (promoted, restart_ids, statuses) = {
        let mut manager = state.transfer_manager.write().await;
        let active_ids: Vec<String> = manager.active.keys().cloned().collect();
        let mut promoted = Vec::new();
        let mut restart_ids: Vec<String> = Vec::new();
        for id in active_ids {
            let was_paused = manager
                .active
                .get(&id)
                .map(|t| t.status == TransferStatus::Paused)
                .unwrap_or(false);
            let p = manager.resume(&id);
            if was_paused && p.is_empty() {
                restart_ids.push(id.clone());
            }
            promoted.extend(p);
        }
        let queued_ids: Vec<String> = manager
            .queue
            .iter()
            .filter(|t| t.status == TransferStatus::Paused || t.status == TransferStatus::Insufficient)
            .map(|t| t.id.clone())
            .collect();
        for id in queued_ids {
            promoted.extend(manager.resume(&id));
        }
        let statuses = manager
            .active
            .keys()
            .cloned()
            .chain(manager.queue.iter().map(|t| t.id.clone()))
            .filter_map(|id| manager.get_transfer(&id).map(|t| (id, t.status.clone())))
            .collect::<Vec<_>>();
        (promoted, restart_ids, statuses)
    };
    futures::future::join_all(
        statuses.into_iter()
            .filter(|(_, status)| matches!(status, TransferStatus::Searching | TransferStatus::Queued | TransferStatus::Active))
            .map(|(id, status)| {
                let state = &state;
                async move { persist_transfer_status(state, &id, &status).await; }
            })
    ).await;
    let mut to_start = promoted;
    {
        let manager = state.transfer_manager.read().await;
        for id in restart_ids {
            if let Some(t) = manager.get_transfer(&id) {
                to_start.push(t.clone());
            }
        }
    }
    start_promoted_downloads(&state, &to_start).await;
    Ok(())
}

#[tauri::command]
pub async fn get_transfer_sources(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<Vec<crate::types::SourceInfo>, String> {
    let manager = state.transfer_manager.read().await;
    Ok(manager.get_source_details(&transfer_id))
}

#[tauri::command]
pub async fn clear_completed(
    state: tauri::State<'_, AppState>,
) -> Result<u32, String> {
    // L1: completed rows have no live network state (their upload/download
    // tasks already returned), so there's nothing for CancelDownload to
    // clean up. Just drop from the manager's completed bucket and delete
    // the on-disk .part file below. This avoids a pointless round-trip
    // through the network command channel for every completed row.
    let mut manager = state.transfer_manager.write().await;
    let mut ids: Vec<String> = Vec::new();
    manager.completed.retain(|t| {
        if t.status == TransferStatus::Completed {
            ids.push(t.id.clone());
            false
        } else {
            true
        }
    });
    let count = u32::try_from(ids.len()).unwrap_or(u32::MAX);
    drop(manager);

    let dl_folder = {
        let config = state.config.read().await;
        config.settings.download_folder.clone()
    };

    let db = state.db.clone();
    for id in &ids {
        let db_ref = db.clone();
        let tid = id.clone();
        db_blocking(move || { let _ = db_ref.remove_transfer(&tid); }).await;
        cleanup_partial_files(&dl_folder, id).await;
    }
    Ok(count)
}

#[tauri::command]
pub async fn recover_archive(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<String, String> {
    let (transfer_info, dl_folder) = {
        let (mgr, cfg) = tokio::join!(
            state.transfer_manager.read(),
            state.config.read(),
        );
        let t = mgr.get_transfer(&transfer_id)
            .map(|t| (t.file_name.clone(), t.total_size, t.id.clone()));
        (t, cfg.settings.download_folder.clone())
    };
    let (file_name, file_size, transfer_id_clone) = transfer_info.ok_or("Transfer not found")?;

    if !crate::network::ed2k::archive_recovery::is_recoverable_archive(&file_name) {
        return Err("File is not a supported archive format (ZIP, RAR, ACE)".into());
    }

    let part_path = std::path::PathBuf::from(&dl_folder)
        .join("Temp")
        .join(format!("{transfer_id_clone}.part"));

    if !part_path.exists() {
        return Err("Part file not found — download may not have started".into());
    }

    let pp = part_path.clone();
    let filled_ranges = tokio::task::spawn_blocking(move || {
        let tracker = crate::network::ed2k::part_tracker::PartTracker::new(file_size, &pp);
        tracker.filled_ranges()
    }).await.map_err(|e| format!("PartTracker task failed: {e}"))?;

    if filled_ranges.is_empty() {
        return Err("No completed parts available for recovery".into());
    }

    let fname = file_name.clone();
    let result = tokio::task::spawn_blocking(move || {
        crate::network::ed2k::archive_recovery::recover_archive(&part_path, &fname, &filled_ranges)
    })
    .await
    .map_err(|e| format!("Recovery task failed: {e}"))?
    .map_err(|e| format!("Recovery failed: {e}"))?;

    Ok(result.to_string_lossy().to_string())
}
