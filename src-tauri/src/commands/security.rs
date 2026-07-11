use std::io::{Cursor, Read};
use std::net::Ipv4Addr;

use tokio::sync::oneshot;
use tracing::info;
use zip::ZipArchive;

use crate::app_state::AppState;
use crate::commands::errors::{await_reply, bounded_send, coded, coded_ctx, CMD_REPLY_TIMEOUT};
use crate::network::kad::ip_filter::{count_valid_entries, IpFilterStats};
use crate::network::NetworkCommand;

const CMD_TIMEOUT: std::time::Duration = CMD_REPLY_TIMEOUT;
const DEFAULT_IPFILTER_ARCHIVE_URL: &str = "https://upd.emule-security.org/ipfilter.zip";
const MAX_RESPONSE_BYTES: usize = 50 * 1024 * 1024;

async fn persist_ip_filter_enabled(
    state: &tauri::State<'_, AppState>,
) -> Result<crate::types::AppSettings, String> {
    let _settings_save_guard = state.settings_save_lock.lock().await;
    let (previous_settings, new_settings, save_data) = {
        let config = state.config.read().await;
        let previous_settings = config.settings.clone();
        let mut new_settings = previous_settings.clone();
        new_settings.ip_filter_enabled = true;
        new_settings.settings_revision = config.settings.settings_revision.saturating_add(1);
        let data = config
            .prepare_save_settings(&new_settings)
            .map_err(|e| coded_ctx("security_failed_to_save_config", "Failed to save config", e))?;
        (previous_settings, new_settings, data)
    };
    tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(&save_data.0, &save_data.1, &save_data.2)
    })
    .await
    .map_err(|e| coded_ctx("security_save_task_failed", "Save task failed", e))?
    .map_err(|e| coded_ctx("security_failed_to_save_config", "Failed to save config", e))?;
    state.config.write().await.settings = new_settings;
    Ok(previous_settings)
}

async fn restore_settings_after_send_failure(
    state: &tauri::State<'_, AppState>,
    previous_settings: crate::types::AppSettings,
) -> Result<(), String> {
    let save_data = {
        let config = state.config.read().await;
        config
            .prepare_save_settings(&previous_settings)
            .map_err(|e| coded_ctx("security_failed_to_save_config", "Failed to save config", e))?
    };
    tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(&save_data.0, &save_data.1, &save_data.2)
    })
    .await
    .map_err(|e| coded_ctx("security_save_task_failed", "Save task failed", e))?
    .map_err(|e| coded_ctx("security_failed_to_save_config", "Failed to save config", e))?;
    state.config.write().await.settings = previous_settings;
    Ok(())
}

fn extract_ipfilter_from_zip(zip_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let cursor = Cursor::new(zip_bytes);
    let mut archive = ZipArchive::new(cursor).map_err(|e| {
        coded_ctx(
            "security_failed_to_open_ipfilter_zip",
            "Failed to open ipfilter.zip",
            e,
        )
    })?;

    let mut best_candidate: Option<(usize, i32)> = None;
    for idx in 0..archive.len() {
        let entry = archive.by_index(idx).map_err(|e| {
            coded_ctx(
                "security_failed_to_inspect_archive_entry",
                "Failed to inspect archive entry",
                format!("#{idx}: {e}"),
            )
        })?;
        if !entry.is_file() {
            continue;
        }
        let name = entry.name().to_ascii_lowercase();
        let score = if name.ends_with("ipfilter.dat") {
            100
        } else if name.ends_with("ipfilter.p2p") {
            95
        } else if name.contains("ipfilter")
            && (name.ends_with(".dat") || name.ends_with(".txt") || name.ends_with(".p2p"))
        {
            90
        } else if name.ends_with(".dat") {
            50
        } else if name.ends_with(".txt") {
            45
        } else if name.ends_with(".p2p") {
            40
        } else {
            continue;
        };

        if best_candidate
            .map(|(_, best_score)| score > best_score)
            .unwrap_or(true)
        {
            best_candidate = Some((idx, score));
        }
    }

    let selected_idx = best_candidate.map(|(idx, _)| idx).ok_or_else(|| {
        coded(
            "security_archive_no_usable_ipfilter",
            "Archive does not contain a usable ipfilter.dat/.dat/.txt/.p2p file",
        )
    })?;

    let entry = archive.by_index(selected_idx).map_err(|e| {
        coded_ctx(
            "security_failed_to_read_selected_archive_entry",
            "Failed to read selected archive entry",
            e,
        )
    })?;
    // Reject early on the declared size, but never *trust* it: `entry.size()`
    // is central-directory metadata an attacker fully controls, and the
    // deflate reader decompresses until the compressed stream ends rather
    // than stopping at the declared length. So cap the *actual* decompressed
    // stream with `take` — a zip bomb that understates its size can't grow
    // the buffer past the limit and exhaust memory.
    if entry.size() > MAX_RESPONSE_BYTES as u64 {
        return Err(coded(
            "security_extracted_ipfilter_too_large",
            "Extracted ipfilter.dat is too large",
        ));
    }

    let cap = MAX_RESPONSE_BYTES as u64;
    let mut extracted = Vec::new();
    entry
        .take(cap + 1)
        .read_to_end(&mut extracted)
        .map_err(|e| {
            coded_ctx(
                "security_failed_to_extract_ipfilter",
                "Failed to extract ipfilter.dat",
                e,
            )
        })?;
    if extracted.len() as u64 > cap {
        return Err(coded(
            "security_extracted_ipfilter_too_large",
            "Extracted ipfilter.dat is too large",
        ));
    }
    Ok(extracted)
}

#[tauri::command]
pub async fn get_ip_filter_stats(
    state: tauri::State<'_, AppState>,
) -> Result<IpFilterStats, String> {
    let (tx, rx) = oneshot::channel();

    state
        .network_tx
        .try_send(NetworkCommand::GetIpFilterStats { tx })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;

    tokio::time::timeout(CMD_TIMEOUT, rx)
        .await
        .map_err(|_| {
            coded(
                "security_network_not_responding",
                "Network not responding (timeout)",
            )
        })?
        .map_err(|e| {
            coded_ctx(
                "security_failed_to_receive_ip_filter_stats",
                "Failed to receive IP filter stats",
                e,
            )
        })
}

#[tauri::command]
pub async fn add_ip_filter_range(
    state: tauri::State<'_, AppState>,
    start_ip: String,
    end_ip: String,
    description: String,
) -> Result<(), String> {
    let start: Ipv4Addr = start_ip
        .parse()
        .map_err(|_| coded("security_invalid_start_ip", "Invalid start IP address"))?;
    let end: Ipv4Addr = end_ip
        .parse()
        .map_err(|_| coded("security_invalid_end_ip", "Invalid end IP address"))?;
    if u32::from(start) > u32::from(end) {
        return Err(coded(
            "security_start_ip_must_be_less_than_end",
            "Start IP must be less than or equal to end IP",
        ));
    }
    // Bound the persisted description so a runaway caller can't grow the
    // ip-filter config unboundedly.
    if description.len() > 256 {
        return Err(coded(
            "security_description_too_long",
            "Description too long (max 256 bytes)",
        ));
    }

    bounded_send(
        &state.network_tx,
        NetworkCommand::AddIpRange {
            start_ip,
            end_ip,
            description,
        },
    )
    .await?;

    Ok(())
}

#[tauri::command]
pub async fn remove_ip_filter_range(
    state: tauri::State<'_, AppState>,
    start_ip: String,
    end_ip: String,
) -> Result<(), String> {
    let start: Ipv4Addr = start_ip
        .parse()
        .map_err(|_| coded("security_invalid_start_ip", "Invalid start IP address"))?;
    let end: Ipv4Addr = end_ip
        .parse()
        .map_err(|_| coded("security_invalid_end_ip", "Invalid end IP address"))?;
    // Mirror add_ip_filter_range's ordering check: an inverted range can
    // never match an entry added through the add path (which rejects
    // start > end), so without this check here the remove silently no-ops
    // and the caller gets no feedback that the range they typed could never
    // have existed.
    if u32::from(start) > u32::from(end) {
        return Err(coded(
            "security_start_ip_must_be_less_than_end",
            "Start IP must be less than or equal to end IP",
        ));
    }

    let (tx, rx) = oneshot::channel();
    bounded_send(
        &state.network_tx,
        NetworkCommand::RemoveIpRange {
            start_ip,
            end_ip,
            tx,
        },
    )
    .await?;

    let removed = await_reply(
        rx,
        "security_failed_to_remove_range",
        "Failed to remove range",
    )
    .await?;
    if !removed {
        return Err(coded(
            "security_range_not_found",
            "No matching IP filter range found to remove",
        ));
    }

    Ok(())
}

#[tauri::command]
pub async fn set_ip_filter_enabled(
    state: tauri::State<'_, AppState>,
    enabled: bool,
) -> Result<(), String> {
    let _settings_save_guard = state.settings_save_lock.lock().await;
    // Persist *before* applying the runtime change (reversed from the
    // original order). `SetIpFilterEnabled` is a fire-and-forget bool flip
    // with no ack, so there's no way to roll the network task's live state
    // back if the disk write fails after the fact — the old order left the
    // running filter and `AppState.config.settings` both diverged from disk
    // (and from each other) until restart. Persisting first means a save
    // failure bails out before touching runtime state at all, so nothing
    // ever diverges; a channel-send failure after a successful save just
    // means the already-correct persisted value takes effect on next start.
    let (previous_settings, new_settings, save_data) = {
        let config = state.config.read().await;
        let previous_settings = config.settings.clone();
        let mut new_settings = previous_settings.clone();
        new_settings.ip_filter_enabled = enabled;
        new_settings.settings_revision = config.settings.settings_revision.saturating_add(1);
        let data = config
            .prepare_save_settings(&new_settings)
            .map_err(|e| coded_ctx("security_failed_to_save_config", "Failed to save config", e))?;
        (previous_settings, new_settings, data)
    };
    tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(&save_data.0, &save_data.1, &save_data.2)
    })
    .await
    .map_err(|e| coded_ctx("security_save_task_failed", "Save task failed", e))?
    .map_err(|e| coded_ctx("security_failed_to_save_config", "Failed to save config", e))?;

    if let Err(error) = bounded_send(
        &state.network_tx,
        NetworkCommand::SetIpFilterEnabled { enabled },
    )
    .await
    {
        restore_settings_after_send_failure(&state, previous_settings).await?;
        return Err(error);
    }

    {
        let mut config = state.config.write().await;
        config.settings = new_settings;
    }

    Ok(())
}

#[tauri::command]
pub async fn set_block_private_ips(
    state: tauri::State<'_, AppState>,
    block_private: bool,
) -> Result<(), String> {
    let _settings_save_guard = state.settings_save_lock.lock().await;
    // Persist before applying the runtime change — see set_ip_filter_enabled
    // for why this order avoids a config/runtime divergence window on save
    // failure.
    let (previous_settings, new_settings, save_data) = {
        let config = state.config.read().await;
        let previous_settings = config.settings.clone();
        let mut new_settings = previous_settings.clone();
        new_settings.block_private_ips = block_private;
        new_settings.settings_revision = config.settings.settings_revision.saturating_add(1);
        let data = config
            .prepare_save_settings(&new_settings)
            .map_err(|e| coded_ctx("security_failed_to_save_config", "Failed to save config", e))?;
        (previous_settings, new_settings, data)
    };
    tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(&save_data.0, &save_data.1, &save_data.2)
    })
    .await
    .map_err(|e| coded_ctx("security_save_task_failed", "Save task failed", e))?
    .map_err(|e| coded_ctx("security_failed_to_save_config", "Failed to save config", e))?;

    if let Err(error) = bounded_send(
        &state.network_tx,
        NetworkCommand::SetBlockPrivateIps { block_private },
    )
    .await
    {
        restore_settings_after_send_failure(&state, previous_settings).await?;
        return Err(error);
    }

    {
        let mut config = state.config.write().await;
        config.settings = new_settings;
    }

    Ok(())
}

#[tauri::command]
pub async fn download_and_load_ipfilter(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    info!("Downloading ipfilter.zip from {DEFAULT_IPFILTER_ARCHIVE_URL}");

    let response = crate::security::fetch_pinned_get(DEFAULT_IPFILTER_ARCHIVE_URL)
        .await
        .map_err(|e| coded_ctx("security_http_request_failed", "HTTP request failed", e))?
        .error_for_status()
        .map_err(|e| coded_ctx("security_http_error", "HTTP error", e))?;
    if let Some(cl) = response.content_length() {
        if cl > MAX_RESPONSE_BYTES as u64 {
            return Err(coded(
                "security_response_too_large_content_length",
                "Response too large (Content-Length exceeds limit)",
            ));
        }
    }
    let bytes = {
        use futures::StreamExt;
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                coded_ctx(
                    "security_failed_to_read_response",
                    "Failed to read response",
                    e,
                )
            })?;
            body.extend_from_slice(&chunk);
            if body.len() > MAX_RESPONSE_BYTES {
                return Err(coded("security_response_too_large", "Response too large"));
            }
        }
        body
    };

    let extracted = tokio::task::spawn_blocking(move || extract_ipfilter_from_zip(&bytes))
        .await
        .map_err(|e| {
            coded_ctx(
                "security_extraction_task_failed",
                "Extraction task failed",
                e,
            )
        })??;

    // Validate *before* anything on disk or in memory is touched. Without
    // this, a dead mirror serving an HTML error page (still a 200, so
    // `error_for_status` doesn't catch it) or a truncated/corrupted archive
    // would sail through straight to `atomic_write` + `ReloadIpFilter`,
    // which faithfully replaces the working filter with an empty one —
    // silently wiping out the user's protection while this command still
    // reports success. Counting real entries first means a bad response
    // can never overwrite a working ipfilter.dat.
    let (extracted, entry_count) = tokio::task::spawn_blocking(move || {
        let entry_count = count_valid_entries(&extracted, "dat");
        (extracted, entry_count)
    })
    .await
    .map_err(|e| {
        coded_ctx(
            "security_validation_task_failed",
            "Validation task failed",
            e,
        )
    })?;
    if entry_count == 0 {
        return Err(coded(
            "security_ipfilter_no_valid_entries",
            "Downloaded file does not contain any valid IP filter entries — keeping the existing filter",
        ));
    }

    let data_dir = crate::storage::paths::resolve_data_dir_with_app(&app);
    tokio::fs::create_dir_all(&data_dir).await.map_err(|e| {
        coded_ctx(
            "security_failed_to_create_data_dir",
            "Failed to create data dir",
            e,
        )
    })?;

    let filter_path = data_dir.join("ipfilter.dat");
    // Use atomic_write so a crash mid-save can't leave a partial
    // ipfilter.dat that would silently disable filtering on next
    // start. Mirrors `commands/settings.rs::download_ipfilter` which
    // already does this.
    {
        let path = filter_path.clone();
        let payload = extracted.clone();
        tokio::task::spawn_blocking(move || crate::security::atomic_write(&path, &payload, false))
            .await
            .map_err(|e| coded_ctx("security_save_task_failed", "Save task failed", e))?
            .map_err(|e| {
                coded_ctx(
                    "security_failed_to_write_ipfilter",
                    "Failed to write ipfilter.dat",
                    e,
                )
            })?;
    }

    let byte_count = extracted.len();
    let previous_settings = persist_ip_filter_enabled(&state).await?;
    let apply_result = async {
        bounded_send(
            &state.network_tx,
            NetworkCommand::ReloadIpFilter { path: filter_path },
        )
        .await?;
        bounded_send(
            &state.network_tx,
            NetworkCommand::SetIpFilterEnabled { enabled: true },
        )
        .await
    }
    .await;
    if let Err(error) = apply_result {
        restore_settings_after_send_failure(&state, previous_settings).await?;
        return Err(error);
    }

    let msg = format!(
        "Downloaded, extracted, and loaded ipfilter.dat ({byte_count} bytes, {entry_count} entries) — filter is now active"
    );
    info!("{msg}");
    Ok(msg)
}

/// Download and load an ipfilter from a user-supplied URL.
///
/// Distinct from `download_and_load_ipfilter`, which fetches from a
/// hard-coded default URL, and from `import_ipfilter_file`, which
/// reads a local path. This is the only IPC path that accepts a
/// user-provided URL — useful for corporate / third-party ipfilter
/// distributions that aren't covered by the bundled default.
///
/// The URL is validated via `security::validate_fetch_url` (DNS
/// resolved, public/private IP filtered, host pinned) before we
/// dial, and the response is capped at 50 MiB.
#[tauri::command]
pub async fn update_ipfilter_from_url(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    url: String,
) -> Result<String, String> {
    info!("Updating IP filter from a user-supplied URL");

    const MAX_RESPONSE_BYTES: usize = 50 * 1024 * 1024;
    let response = crate::security::fetch_pinned_get(&url)
        .await
        .map_err(|e| coded_ctx("security_http_request_failed", "HTTP request failed", e))?
        .error_for_status()
        .map_err(|e| coded_ctx("security_http_error", "HTTP error", e))?;
    if let Some(cl) = response.content_length() {
        if cl > MAX_RESPONSE_BYTES as u64 {
            return Err(coded(
                "security_response_too_large_content_length",
                "Response too large (Content-Length exceeds limit)",
            ));
        }
    }
    let bytes = {
        use futures::StreamExt;
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                coded_ctx(
                    "security_failed_to_read_response",
                    "Failed to read response",
                    e,
                )
            })?;
            body.extend_from_slice(&chunk);
            if body.len() > MAX_RESPONSE_BYTES {
                return Err(coded("security_response_too_large", "Response too large"));
            }
        }
        body
    };

    let is_zip = bytes.len() >= 4
        && bytes[0] == 0x50
        && bytes[1] == 0x4B
        && bytes[2] == 0x03
        && bytes[3] == 0x04;
    let filter_bytes = if is_zip {
        info!("Detected zip archive, extracting ipfilter…");
        let zb = bytes;
        tokio::task::spawn_blocking(move || extract_ipfilter_from_zip(&zb))
            .await
            .map_err(|e| {
                coded_ctx(
                    "security_extraction_task_failed",
                    "Extraction task failed",
                    e,
                )
            })??
    } else {
        bytes
    };

    // Validate before writing anything — a user-supplied URL is even less
    // trustworthy than the hard-coded default, and the same silent-wipe risk
    // applies (see the comment in `download_and_load_ipfilter`).
    let (filter_bytes, entry_count) = tokio::task::spawn_blocking(move || {
        let entry_count = count_valid_entries(&filter_bytes, "dat");
        (filter_bytes, entry_count)
    })
    .await
    .map_err(|e| {
        coded_ctx(
            "security_validation_task_failed",
            "Validation task failed",
            e,
        )
    })?;
    if entry_count == 0 {
        return Err(coded(
            "security_ipfilter_no_valid_entries",
            "Downloaded file does not contain any valid IP filter entries — keeping the existing filter",
        ));
    }

    let data_dir = crate::storage::paths::resolve_data_dir_with_app(&app);
    tokio::fs::create_dir_all(&data_dir).await.map_err(|e| {
        coded_ctx(
            "security_failed_to_create_data_dir",
            "Failed to create data dir",
            e,
        )
    })?;

    let filter_path = data_dir.join("ipfilter.dat");
    // Atomic write: crash safety as in `download_and_load_ipfilter`.
    {
        let path = filter_path.clone();
        let payload = filter_bytes.clone();
        tokio::task::spawn_blocking(move || crate::security::atomic_write(&path, &payload, false))
            .await
            .map_err(|e| coded_ctx("security_save_task_failed", "Save task failed", e))?
            .map_err(|e| {
                coded_ctx(
                    "security_failed_to_write_ipfilter",
                    "Failed to write ipfilter.dat",
                    e,
                )
            })?;
    }

    let byte_count = filter_bytes.len();
    let previous_settings = persist_ip_filter_enabled(&state).await?;
    let apply_result = async {
        bounded_send(
            &state.network_tx,
            NetworkCommand::ReloadIpFilter { path: filter_path },
        )
        .await?;
        bounded_send(
            &state.network_tx,
            NetworkCommand::SetIpFilterEnabled { enabled: true },
        )
        .await
    }
    .await;
    if let Err(error) = apply_result {
        restore_settings_after_send_failure(&state, previous_settings).await?;
        return Err(error);
    }

    let extracted_note = if is_zip { " (extracted from zip)" } else { "" };
    let msg = format!(
        "Downloaded and loaded ipfilter.dat from {url}{extracted_note} ({byte_count} bytes, {entry_count} entries) — filter is now active"
    );
    info!("{msg}");
    Ok(msg)
}

#[tauri::command]
pub async fn import_ipfilter_file(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<String, String> {
    // Match the cap used by `add_shared_folder` / `validate_settings`
    // so a degenerate frontend caller can't pass a multi-megabyte
    // string into IPC. The blocking canonicalize / read paths below
    // would still cope, but bounding here avoids ferrying a giant
    // string across thread boundaries unnecessarily.
    const MAX_PATH_LEN: usize = 4 * 1024;
    if file_path.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "security_file_path_too_long",
            "File path exceeds maximum length",
            format!("{MAX_PATH_LEN} bytes"),
        ));
    }
    let path = tokio::task::spawn_blocking(move || {
        let path = std::path::PathBuf::from(&file_path);
        if !path.exists() {
            return Err(coded("security_file_does_not_exist", "File does not exist"));
        }
        let canonical = path
            .canonicalize()
            .map_err(|e| coded_ctx("security_invalid_path", "Invalid path", e))?;
        let blocked_segments: &[&str] = &[
            "windows",
            "program files",
            "program files (x86)",
            "programdata",
            ".ssh",
            ".gnupg",
            "etc",
            "usr",
            "bin",
            "sbin",
            "var",
            "root",
        ];
        for component in canonical.components() {
            if let std::path::Component::Normal(seg) = component {
                let seg_lower = seg.to_string_lossy().to_lowercase();
                if blocked_segments.contains(&seg_lower.as_str()) {
                    return Err(coded_ctx(
                        "security_cannot_import_system_dir",
                        "Cannot import from system directory",
                        canonical.display(),
                    ));
                }
            }
        }
        if canonical
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            != Some("dat".to_string())
            && canonical
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_lowercase())
                != Some("txt".to_string())
            && canonical
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_lowercase())
                != Some("gz".to_string())
            && canonical
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_lowercase())
                != Some("zip".to_string())
            && canonical
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_lowercase())
                != Some("p2p".to_string())
        {
            return Err(coded(
                "security_invalid_ipfilter_file_type",
                "IP filter file must be a .dat, .txt, .gz, .zip, or .p2p file",
            ));
        }
        Ok(canonical)
    })
    .await
    .map_err(|e| coded_ctx("security_task_failed", "Task failed", e))??;

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    let (load_path, entry_count) = if ext == "gz" || ext == "zip" {
        let data_dir = crate::storage::paths::resolve_data_dir_with_app(&app);
        tokio::fs::create_dir_all(&data_dir).await.map_err(|e| {
            coded_ctx(
                "security_failed_to_create_data_dir",
                "Failed to create data dir",
                e,
            )
        })?;
        let dest = data_dir.join("ipfilter.dat");

        let src = path.clone();
        tokio::task::spawn_blocking(move || {
            let raw = std::fs::read(&src)
                .map_err(|e| coded_ctx("security_failed_to_read_file", "Failed to read file", e))?;
            let decompressed = if ext == "gz" {
                // Bound the decompressed output to MAX_RESPONSE_BYTES to
                // prevent a "zip bomb" — a small .gz that expands into
                // many GB. Without this cap a crafted file could exhaust
                // memory. We `take(MAX + 1)` and check against the cap so
                // we can distinguish "exactly the limit" from "overflowed".
                use flate2::read::GzDecoder;
                let decoder = GzDecoder::new(std::io::Cursor::new(&raw));
                let mut limited = decoder.take(MAX_RESPONSE_BYTES as u64 + 1);
                let mut out = Vec::new();
                limited.read_to_end(&mut out).map_err(|e| {
                    coded_ctx(
                        "security_failed_to_decompress_gz",
                        "Failed to decompress .gz file",
                        e,
                    )
                })?;
                if out.len() > MAX_RESPONSE_BYTES {
                    return Err(coded_ctx(
                        "security_decompressed_gz_too_large",
                        "Decompressed .gz file is too large",
                        format!(
                            "over {} MiB — refusing to load",
                            MAX_RESPONSE_BYTES / (1024 * 1024)
                        ),
                    ));
                }
                out
            } else {
                extract_ipfilter_from_zip(&raw)?
            };
            // Validate before this is ever written to ipfilter.dat — see
            // `download_and_load_ipfilter` for why a bad payload must never
            // reach `atomic_write` (which would otherwise faithfully
            // replace a working filter with an empty one).
            let entry_count = count_valid_entries(&decompressed, "dat");
            if entry_count == 0 {
                return Err(coded(
                    "security_ipfilter_no_valid_entries",
                    "Selected file does not contain any valid IP filter entries — keeping the existing filter",
                ));
            }
            // Atomic write: prevents partial-file corruption on crash
            // mid-decompression-write. Already inside spawn_blocking,
            // so calling the sync helper directly is fine.
            crate::security::atomic_write(&dest, &decompressed, false).map_err(|e| {
                coded_ctx(
                    "security_failed_to_write_ipfilter",
                    "Failed to write ipfilter.dat",
                    e,
                )
            })?;
            Ok::<(std::path::PathBuf, usize), String>((dest, entry_count))
        })
        .await
        .map_err(|e| coded_ctx("security_task_failed", "Task failed", e))??
    } else {
        // Unlike the .gz/.zip branch above (which decompresses into a
        // bounded buffer) and every other ipfilter-loading path in this
        // file (URL download, zip-from-URL), a plain .dat/.txt/.p2p local
        // file was passed straight through to `ReloadIpFilter` with no
        // size check at all — a user picking (or a compromised frontend
        // supplying) an arbitrarily large file would have it copied
        // wholesale into ipfilter.dat by the network-loop handler.
        // Enforce the same MAX_RESPONSE_BYTES cap here for consistency.
        let metadata = tokio::fs::metadata(&path).await.map_err(|e| {
            coded_ctx(
                "security_failed_to_stat_file",
                "Failed to read file metadata",
                e,
            )
        })?;
        if metadata.len() > MAX_RESPONSE_BYTES as u64 {
            return Err(coded_ctx(
                "security_ipfilter_file_too_large",
                "IP filter file is too large",
                format!(
                    "{} bytes exceeds the {} MiB limit",
                    metadata.len(),
                    MAX_RESPONSE_BYTES / (1024 * 1024)
                ),
            ));
        }
        // Validate before handing off to `ReloadIpFilter` — a file the user
        // picked by mistake (wrong content, empty, corrupted) must not be
        // allowed to clear the working filter. Bounded by the size check
        // above.
        let raw = tokio::fs::read(&path)
            .await
            .map_err(|e| coded_ctx("security_failed_to_read_file", "Failed to read file", e))?;
        let entry_count = tokio::task::spawn_blocking(move || count_valid_entries(&raw, &ext))
            .await
            .map_err(|e| {
                coded_ctx(
                    "security_validation_task_failed",
                    "Validation task failed",
                    e,
                )
            })?;
        if entry_count == 0 {
            return Err(coded(
                "security_ipfilter_no_valid_entries",
                "Selected file does not contain any valid IP filter entries — keeping the existing filter",
            ));
        }
        (path, entry_count)
    };
    let previous_settings = persist_ip_filter_enabled(&state).await?;
    let apply_result = async {
        bounded_send(
            &state.network_tx,
            NetworkCommand::ReloadIpFilter { path: load_path },
        )
        .await?;
        bounded_send(
            &state.network_tx,
            NetworkCommand::SetIpFilterEnabled { enabled: true },
        )
        .await
    }
    .await;
    if let Err(error) = apply_result {
        restore_settings_after_send_failure(&state, previous_settings).await?;
        return Err(error);
    }

    Ok(format!(
        "Imported and loaded IP filter ({entry_count} entries) — filter is now active"
    ))
}

// ----- Anti-leech client filter commands -----------------------------
//
// The filter logic and persistence live in `crate::security::antileech`.
// These commands form the thin Tauri layer over a NetworkCommand round
// trip so the network task remains the single owner of the runtime
// state and the on-disk file. Going through `network_tx` (rather than
// holding the filter `Arc` directly on `AppState`) keeps reload /
// pattern-edit operations serialised against everything else the
// network task is doing — no risk of a half-applied pattern set being
// observed by an in-flight upload handshake.

/// Snapshot the current pattern list for the Settings UI.
#[tauri::command]
pub async fn get_antileech_patterns(
    state: tauri::State<'_, AppState>,
) -> Result<crate::types::AntiLeechSnapshot, String> {
    let (tx, rx) = oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetAntiLeechSnapshot { tx })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    await_reply(
        rx,
        "security_failed_to_read_antileech",
        "Failed to read anti-leech filter",
    )
    .await
}

/// Replace the entire pattern list, persist to disk, and recompile.
/// Returns any per-pattern compile errors so the UI can show which
/// rows were rejected (the rest still take effect — partial-success
/// is intentional so a single typo doesn't wipe the whole list).
#[tauri::command]
pub async fn set_antileech_patterns(
    state: tauri::State<'_, AppState>,
    patterns: Vec<String>,
) -> Result<crate::types::AntiLeechReplaceResult, String> {
    // Bound the pattern set so a runaway caller can't push an unbounded list
    // (each pattern is compiled and held in memory by the network task).
    if patterns.len() > 10_000 {
        return Err(coded(
            "security_too_many_patterns",
            "Too many anti-leech patterns (max 10000)",
        ));
    }
    if patterns.iter().any(|p| p.len() > 1024) {
        return Err(coded(
            "security_pattern_too_long",
            "Anti-leech pattern too long (max 1024 bytes)",
        ));
    }
    let (tx, rx) = oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::SetAntiLeechPatterns { patterns, tx })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    await_reply(
        rx,
        "security_failed_to_update_antileech",
        "Failed to update anti-leech filter",
    )
    .await?
}

/// Toggle the filter on or off without touching the pattern list.
/// Persists the new state to AppSettings + the on-disk config so the
/// choice survives restarts.
#[tauri::command]
pub async fn set_antileech_enabled(
    state: tauri::State<'_, AppState>,
    enabled: bool,
) -> Result<(), String> {
    let _settings_save_guard = state.settings_save_lock.lock().await;
    // Persist the toggle before applying the runtime change. Unlike the older
    // one-way IP-filter command, this command has an ack, so we can avoid
    // returning an error after the live filter has already changed.
    let (new_settings, old_save_data, new_save_data) = {
        let cfg = state.config.read().await;
        let old_settings = cfg.settings.clone();
        let mut new_settings = cfg.settings.clone();
        new_settings.antileech_enabled = enabled;
        new_settings.settings_revision = cfg.settings.settings_revision.saturating_add(1);
        let old_data = cfg
            .prepare_save_settings(&old_settings)
            .map_err(|e| coded_ctx("security_failed_to_save_config", "Failed to save config", e))?;
        let new_data = cfg
            .prepare_save_settings(&new_settings)
            .map_err(|e| coded_ctx("security_failed_to_save_config", "Failed to save config", e))?;
        (new_settings, old_data, new_data)
    };
    tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(
            &new_save_data.0,
            &new_save_data.1,
            &new_save_data.2,
        )
    })
    .await
    .map_err(|e| {
        coded_ctx(
            "security_config_save_task_failed",
            "Config save task failed",
            e,
        )
    })?
    .map_err(|e| {
        coded_ctx(
            "security_failed_to_write_config",
            "Failed to write config",
            e,
        )
    })?;

    let (tx, rx) = oneshot::channel();
    if let Err(e) = state
        .network_tx
        .try_send(NetworkCommand::SetAntiLeechEnabled { enabled, tx })
    {
        let _ = tokio::task::spawn_blocking(move || {
            crate::storage::config::AppConfig::write_to_disk(
                &old_save_data.0,
                &old_save_data.1,
                &old_save_data.2,
            )
        })
        .await;
        return Err(coded_ctx("network_busy", "Network busy", e));
    }

    if let Err(e) = await_reply(
        rx,
        "security_failed_to_toggle_antileech",
        "Failed to toggle anti-leech filter",
    )
    .await?
    {
        let _ = tokio::task::spawn_blocking(move || {
            crate::storage::config::AppConfig::write_to_disk(
                &old_save_data.0,
                &old_save_data.1,
                &old_save_data.2,
            )
        })
        .await;
        return Err(e);
    }

    {
        let mut cfg = state.config.write().await;
        cfg.settings = new_settings;
    }
    Ok(())
}

/// Reset the pattern list to the built-in defaults — the small,
/// well-vetted set of "always block" leech mods. Useful as a recovery
/// path if the user edits the file manually and breaks something.
#[tauri::command]
pub async fn reset_antileech_to_defaults(
    state: tauri::State<'_, AppState>,
) -> Result<crate::types::AntiLeechSnapshot, String> {
    let (tx, rx) = oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::ResetAntiLeechToDefaults { tx })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    await_reply(
        rx,
        "security_failed_to_reset_antileech",
        "Failed to reset anti-leech filter",
    )
    .await?
}
