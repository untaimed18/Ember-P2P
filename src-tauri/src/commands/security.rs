use std::io::{Cursor, Read};
use std::net::Ipv4Addr;

use tokio::sync::oneshot;
use tracing::info;
use zip::ZipArchive;

use crate::app_state::AppState;
use crate::commands::errors::{await_reply, coded, coded_ctx};
use crate::network::kad::ip_filter::IpFilterStats;
use crate::network::NetworkCommand;

const CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const DEFAULT_IPFILTER_ARCHIVE_URL: &str = "https://upd.emule-security.org/ipfilter.zip";
const MAX_RESPONSE_BYTES: usize = 50 * 1024 * 1024;

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

    state
        .network_tx
        .send(NetworkCommand::AddIpRange {
            start_ip,
            end_ip,
            description,
        })
        .await
        .map_err(|e| coded_ctx("security_failed_to_add_range", "Failed to add range", e))?;

    Ok(())
}

#[tauri::command]
pub async fn remove_ip_filter_range(
    state: tauri::State<'_, AppState>,
    start_ip: String,
    end_ip: String,
) -> Result<(), String> {
    start_ip
        .parse::<Ipv4Addr>()
        .map_err(|_| coded("security_invalid_start_ip", "Invalid start IP address"))?;
    end_ip
        .parse::<Ipv4Addr>()
        .map_err(|_| coded("security_invalid_end_ip", "Invalid end IP address"))?;

    state
        .network_tx
        .send(NetworkCommand::RemoveIpRange { start_ip, end_ip })
        .await
        .map_err(|e| {
            coded_ctx(
                "security_failed_to_remove_range",
                "Failed to remove range",
                e,
            )
        })?;

    Ok(())
}

#[tauri::command]
pub async fn set_ip_filter_enabled(
    state: tauri::State<'_, AppState>,
    enabled: bool,
) -> Result<(), String> {
    state
        .network_tx
        .send(NetworkCommand::SetIpFilterEnabled { enabled })
        .await
        .map_err(|e| {
            coded_ctx(
                "security_failed_to_update_filter",
                "Failed to update filter",
                e,
            )
        })?;

    // Persist before committing the in-memory flag so a failed write can't
    // leave the saved config diverged from disk (the runtime filter was
    // already updated above, which is the fail-safe direction for security).
    let (new_settings, save_data) = {
        let config = state.config.read().await;
        let mut new_settings = config.settings.clone();
        new_settings.ip_filter_enabled = enabled;
        let data = config
            .prepare_save_settings(&new_settings)
            .map_err(|e| coded_ctx("security_failed_to_save_config", "Failed to save config", e))?;
        (new_settings, data)
    };
    tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(&save_data.0, &save_data.1, &save_data.2)
    })
    .await
    .map_err(|e| coded_ctx("security_save_task_failed", "Save task failed", e))?
    .map_err(|e| coded_ctx("security_failed_to_save_config", "Failed to save config", e))?;
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
    state
        .network_tx
        .send(NetworkCommand::SetBlockPrivateIps { block_private })
        .await
        .map_err(|e| {
            coded_ctx(
                "security_failed_to_update_filter",
                "Failed to update filter",
                e,
            )
        })?;

    // Persist before committing the in-memory flag (see set_ip_filter_enabled).
    let (new_settings, save_data) = {
        let config = state.config.read().await;
        let mut new_settings = config.settings.clone();
        new_settings.block_private_ips = block_private;
        let data = config
            .prepare_save_settings(&new_settings)
            .map_err(|e| coded_ctx("security_failed_to_save_config", "Failed to save config", e))?;
        (new_settings, data)
    };
    tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(&save_data.0, &save_data.1, &save_data.2)
    })
    .await
    .map_err(|e| coded_ctx("security_save_task_failed", "Save task failed", e))?
    .map_err(|e| coded_ctx("security_failed_to_save_config", "Failed to save config", e))?;
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
    let line_count = extracted.iter().filter(|&&b| b == b'\n').count();

    state
        .network_tx
        .send(NetworkCommand::ReloadIpFilter { path: filter_path })
        .await
        .map_err(|e| {
            coded_ctx(
                "security_failed_to_reload_filter",
                "Failed to reload filter",
                e,
            )
        })?;

    // Also enable the filter if it wasn't already
    state
        .network_tx
        .send(NetworkCommand::SetIpFilterEnabled { enabled: true })
        .await
        .map_err(|e| {
            coded_ctx(
                "security_failed_to_enable_filter",
                "Failed to enable filter",
                e,
            )
        })?;

    {
        // Persist before committing the in-memory flag (see
        // set_ip_filter_enabled). The runtime filter was already enabled above.
        let (new_settings, save_data) = {
            let config = state.config.read().await;
            let mut new_settings = config.settings.clone();
            new_settings.ip_filter_enabled = true;
            let data = config.prepare_save_settings(&new_settings).map_err(|e| {
                coded_ctx("security_failed_to_save_config", "Failed to save config", e)
            })?;
            (new_settings, data)
        };
        tokio::task::spawn_blocking(move || {
            crate::storage::config::AppConfig::write_to_disk(
                &save_data.0,
                &save_data.1,
                &save_data.2,
            )
        })
        .await
        .map_err(|e| coded_ctx("security_save_task_failed", "Save task failed", e))?
        .map_err(|e| coded_ctx("security_failed_to_save_config", "Failed to save config", e))?;
        {
            let mut config = state.config.write().await;
            config.settings = new_settings;
        }
    }

    let msg = format!(
        "Downloaded, extracted, and loaded ipfilter.dat ({byte_count} bytes, ~{line_count} entries) — filter is now active"
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
    let line_count = filter_bytes.iter().filter(|&&b| b == b'\n').count();

    state
        .network_tx
        .send(NetworkCommand::ReloadIpFilter { path: filter_path })
        .await
        .map_err(|e| {
            coded_ctx(
                "security_failed_to_reload_filter",
                "Failed to reload filter",
                e,
            )
        })?;

    state
        .network_tx
        .send(NetworkCommand::SetIpFilterEnabled { enabled: true })
        .await
        .map_err(|e| {
            coded_ctx(
                "security_failed_to_enable_filter",
                "Failed to enable filter",
                e,
            )
        })?;

    {
        // Persist before committing the in-memory flag (see
        // set_ip_filter_enabled). The runtime filter was already enabled above.
        let (new_settings, save_data) = {
            let config = state.config.read().await;
            let mut new_settings = config.settings.clone();
            new_settings.ip_filter_enabled = true;
            let data = config.prepare_save_settings(&new_settings).map_err(|e| {
                coded_ctx("security_failed_to_save_config", "Failed to save config", e)
            })?;
            (new_settings, data)
        };
        tokio::task::spawn_blocking(move || {
            crate::storage::config::AppConfig::write_to_disk(
                &save_data.0,
                &save_data.1,
                &save_data.2,
            )
        })
        .await
        .map_err(|e| coded_ctx("security_save_task_failed", "Save task failed", e))?
        .map_err(|e| coded_ctx("security_failed_to_save_config", "Failed to save config", e))?;
        {
            let mut config = state.config.write().await;
            config.settings = new_settings;
        }
    }

    let extracted_note = if is_zip { " (extracted from zip)" } else { "" };
    let msg = format!(
        "Downloaded and loaded ipfilter.dat from {url}{extracted_note} ({byte_count} bytes, ~{line_count} entries) — filter is now active"
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

    let load_path = if ext == "gz" || ext == "zip" {
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
            Ok::<std::path::PathBuf, String>(dest)
        })
        .await
        .map_err(|e| coded_ctx("security_task_failed", "Task failed", e))??
    } else {
        path
    };

    state
        .network_tx
        .send(NetworkCommand::ReloadIpFilter { path: load_path })
        .await
        .map_err(|e| {
            coded_ctx(
                "security_failed_to_reload_filter",
                "Failed to reload filter",
                e,
            )
        })?;

    state
        .network_tx
        .send(NetworkCommand::SetIpFilterEnabled { enabled: true })
        .await
        .map_err(|e| {
            coded_ctx(
                "security_failed_to_enable_filter",
                "Failed to enable filter",
                e,
            )
        })?;

    {
        // Persist before committing the in-memory flag (see
        // set_ip_filter_enabled). The runtime filter was already enabled above.
        let (new_settings, save_data) = {
            let config = state.config.read().await;
            let mut new_settings = config.settings.clone();
            new_settings.ip_filter_enabled = true;
            let data = config.prepare_save_settings(&new_settings).map_err(|e| {
                coded_ctx("security_failed_to_save_config", "Failed to save config", e)
            })?;
            (new_settings, data)
        };
        tokio::task::spawn_blocking(move || {
            crate::storage::config::AppConfig::write_to_disk(
                &save_data.0,
                &save_data.1,
                &save_data.2,
            )
        })
        .await
        .map_err(|e| coded_ctx("security_save_task_failed", "Save task failed", e))?
        .map_err(|e| coded_ctx("security_failed_to_save_config", "Failed to save config", e))?;
        {
            let mut config = state.config.write().await;
            config.settings = new_settings;
        }
    }

    Ok("Imported and loaded IP filter — filter is now active".into())
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
    let (tx, rx) = oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::SetAntiLeechEnabled { enabled, tx })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    await_reply(
        rx,
        "security_failed_to_toggle_antileech",
        "Failed to toggle anti-leech filter",
    )
    .await??;

    // Persist the toggle to the config file so a restart preserves it. The
    // runtime flip was already confirmed by the network task above; persist to
    // disk BEFORE committing the in-memory flag (see set_ip_filter_enabled) so
    // a failed write can't leave the saved config diverged from disk.
    let (new_settings, save_data) = {
        let cfg = state.config.read().await;
        let mut new_settings = cfg.settings.clone();
        new_settings.antileech_enabled = enabled;
        let data = cfg
            .prepare_save_settings(&new_settings)
            .map_err(|e| coded_ctx("security_failed_to_save_config", "Failed to save config", e))?;
        (new_settings, data)
    };
    tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(&save_data.0, &save_data.1, &save_data.2)
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
