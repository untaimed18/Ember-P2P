use std::net::Ipv4Addr;
use std::io::{Cursor, Read};

use tauri::Manager;
use tokio::sync::oneshot;
use tracing::info;
use zip::ZipArchive;

use crate::app_state::AppState;
use crate::network::kad::ip_filter::IpFilterStats;
use crate::network::NetworkCommand;

const CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const DEFAULT_IPFILTER_ARCHIVE_URL: &str = "https://upd.emule-security.org/ipfilter.zip";
const MAX_RESPONSE_BYTES: usize = 50 * 1024 * 1024;

fn extract_ipfilter_from_zip(zip_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let cursor = Cursor::new(zip_bytes);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|e| format!("Failed to open ipfilter.zip: {e}"))?;

    let mut best_candidate: Option<(usize, i32)> = None;
    for idx in 0..archive.len() {
        let entry = archive
            .by_index(idx)
            .map_err(|e| format!("Failed to inspect archive entry #{idx}: {e}"))?;
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

        if best_candidate.map(|(_, best_score)| score > best_score).unwrap_or(true) {
            best_candidate = Some((idx, score));
        }
    }

    let selected_idx = best_candidate.map(|(idx, _)| idx).ok_or_else(|| {
        "Archive does not contain a usable ipfilter.dat/.dat/.txt/.p2p file".to_string()
    })?;

    let mut entry = archive
        .by_index(selected_idx)
        .map_err(|e| format!("Failed to read selected archive entry: {e}"))?;
    if entry.size() > MAX_RESPONSE_BYTES as u64 {
        return Err("Extracted ipfilter.dat is too large".into());
    }

    let mut extracted = Vec::with_capacity(entry.size() as usize);
    entry
        .read_to_end(&mut extracted)
        .map_err(|e| format!("Failed to extract ipfilter.dat: {e}"))?;
    if extracted.len() > MAX_RESPONSE_BYTES {
        return Err("Extracted ipfilter.dat is too large".into());
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
        .map_err(|e| format!("Network busy: {e}"))?;

    tokio::time::timeout(CMD_TIMEOUT, rx)
        .await
        .map_err(|_| "Network not responding (timeout)".to_string())?
        .map_err(|e| format!("Failed to receive IP filter stats: {e}"))
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
        .map_err(|_| "Invalid start IP address")?;
    let end: Ipv4Addr = end_ip
        .parse()
        .map_err(|_| "Invalid end IP address")?;
    if u32::from(start) > u32::from(end) {
        return Err("Start IP must be less than or equal to end IP".into());
    }

    state
        .network_tx
        .send(NetworkCommand::AddIpRange {
            start_ip,
            end_ip,
            description,
        })
        .await
        .map_err(|e| format!("Failed to add range: {e}"))?;

    Ok(())
}

#[tauri::command]
pub async fn remove_ip_filter_range(
    state: tauri::State<'_, AppState>,
    start_ip: String,
    end_ip: String,
) -> Result<(), String> {
    start_ip.parse::<Ipv4Addr>().map_err(|_| "Invalid start IP address")?;
    end_ip.parse::<Ipv4Addr>().map_err(|_| "Invalid end IP address")?;

    state
        .network_tx
        .send(NetworkCommand::RemoveIpRange { start_ip, end_ip })
        .await
        .map_err(|e| format!("Failed to remove range: {e}"))?;

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
        .map_err(|e| format!("Failed to update filter: {e}"))?;

    let save_data = {
        let mut config = state.config.write().await;
        config.settings.ip_filter_enabled = enabled;
        config.prepare_save().map_err(|e| format!("Failed to save config: {e}"))?
    };
    tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(&save_data.0, &save_data.1, &save_data.2)
    }).await.map_err(|e| format!("Save task failed: {e}"))?.map_err(|e| format!("Failed to save config: {e}"))?;

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
        .map_err(|e| format!("Failed to update filter: {e}"))?;

    let save_data = {
        let mut config = state.config.write().await;
        config.settings.block_private_ips = block_private;
        config.prepare_save().map_err(|e| format!("Failed to save config: {e}"))?
    };
    tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(&save_data.0, &save_data.1, &save_data.2)
    }).await.map_err(|e| format!("Save task failed: {e}"))?.map_err(|e| format!("Failed to save config: {e}"))?;

    Ok(())
}

#[tauri::command]
pub async fn download_and_load_ipfilter(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    info!("Downloading ipfilter.zip from {DEFAULT_IPFILTER_ARCHIVE_URL}");

    let (host, resolved_addrs) = crate::security::validate_fetch_url(DEFAULT_IPFILTER_ARCHIVE_URL).await
        .map_err(|e| format!("URL validation failed: {e}"))?;
    let client = crate::security::build_pinned_client(&host, &resolved_addrs)
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

    let response = client.get(DEFAULT_IPFILTER_ARCHIVE_URL).send()
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("HTTP error: {e}"))?;
    if let Some(cl) = response.content_length() {
        if cl > MAX_RESPONSE_BYTES as u64 {
            return Err("Response too large (Content-Length exceeds limit)".into());
        }
    }
    let bytes = {
        use futures::StreamExt;
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| format!("Failed to read response: {e}"))?;
            body.extend_from_slice(&chunk);
            if body.len() > MAX_RESPONSE_BYTES {
                return Err("Response too large".into());
            }
        }
        body
    };

    let extracted = tokio::task::spawn_blocking(move || extract_ipfilter_from_zip(&bytes))
        .await
        .map_err(|e| format!("Extraction task failed: {e}"))??;

    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to get app data dir: {e}"))?;
    tokio::fs::create_dir_all(&data_dir)
        .await
        .map_err(|e| format!("Failed to create data dir: {e}"))?;

    let filter_path = data_dir.join("ipfilter.dat");
    tokio::fs::write(&filter_path, &extracted)
        .await
        .map_err(|e| format!("Failed to write ipfilter.dat: {e}"))?;

    let byte_count = extracted.len();
    let line_count = extracted.iter().filter(|&&b| b == b'\n').count();

    state
        .network_tx
        .send(NetworkCommand::ReloadIpFilter {
            path: filter_path,
        })
        .await
        .map_err(|e| format!("Failed to reload filter: {e}"))?;

    // Also enable the filter if it wasn't already
    state
        .network_tx
        .send(NetworkCommand::SetIpFilterEnabled { enabled: true })
        .await
        .map_err(|e| format!("Failed to enable filter: {e}"))?;

    {
        let save_data = {
            let mut config = state.config.write().await;
            config.settings.ip_filter_enabled = true;
            config.prepare_save().map_err(|e| format!("Failed to save config: {e}"))?
        };
        tokio::task::spawn_blocking(move || {
            crate::storage::config::AppConfig::write_to_disk(&save_data.0, &save_data.1, &save_data.2)
        }).await.map_err(|e| format!("Save task failed: {e}"))?.map_err(|e| format!("Failed to save config: {e}"))?;
    }

    let msg = format!(
        "Downloaded, extracted, and loaded ipfilter.dat ({byte_count} bytes, ~{line_count} entries) — filter is now active"
    );
    info!("{msg}");
    Ok(msg)
}

#[tauri::command]
pub async fn update_ipfilter_from_url(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    url: String,
) -> Result<String, String> {
    let (host, resolved_addrs) = crate::security::validate_fetch_url(&url).await?;

    info!("Updating IP filter from URL: {url}");

    let client = crate::security::build_pinned_client(&host, &resolved_addrs)
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

    const MAX_RESPONSE_BYTES: usize = 50 * 1024 * 1024;
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("HTTP error: {e}"))?;
    if let Some(cl) = response.content_length() {
        if cl > MAX_RESPONSE_BYTES as u64 {
            return Err("Response too large (Content-Length exceeds limit)".into());
        }
    }
    let bytes = {
        use futures::StreamExt;
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| format!("Failed to read response: {e}"))?;
            body.extend_from_slice(&chunk);
            if body.len() > MAX_RESPONSE_BYTES {
                return Err("Response too large".into());
            }
        }
        body
    };

    let is_zip = bytes.len() >= 4 && bytes[0] == 0x50 && bytes[1] == 0x4B && bytes[2] == 0x03 && bytes[3] == 0x04;
    let filter_bytes = if is_zip {
        info!("Detected zip archive, extracting ipfilter…");
        let zb = bytes;
        tokio::task::spawn_blocking(move || extract_ipfilter_from_zip(&zb))
            .await
            .map_err(|e| format!("Extraction task failed: {e}"))??
    } else {
        bytes
    };

    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to get app data dir: {e}"))?;
    tokio::fs::create_dir_all(&data_dir)
        .await
        .map_err(|e| format!("Failed to create data dir: {e}"))?;

    let filter_path = data_dir.join("ipfilter.dat");
    tokio::fs::write(&filter_path, &filter_bytes)
        .await
        .map_err(|e| format!("Failed to write ipfilter.dat: {e}"))?;

    let byte_count = filter_bytes.len();
    let line_count = filter_bytes.iter().filter(|&&b| b == b'\n').count();

    state
        .network_tx
        .send(NetworkCommand::ReloadIpFilter {
            path: filter_path,
        })
        .await
        .map_err(|e| format!("Failed to reload filter: {e}"))?;

    state
        .network_tx
        .send(NetworkCommand::SetIpFilterEnabled { enabled: true })
        .await
        .map_err(|e| format!("Failed to enable filter: {e}"))?;

    {
        let save_data = {
            let mut config = state.config.write().await;
            config.settings.ip_filter_enabled = true;
            config.prepare_save().map_err(|e| format!("Failed to save config: {e}"))?
        };
        tokio::task::spawn_blocking(move || {
            crate::storage::config::AppConfig::write_to_disk(&save_data.0, &save_data.1, &save_data.2)
        }).await.map_err(|e| format!("Save task failed: {e}"))?.map_err(|e| format!("Failed to save config: {e}"))?;
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
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<String, String> {
    let path = tokio::task::spawn_blocking(move || {
        let path = std::path::PathBuf::from(&file_path);
        if !path.exists() {
            return Err("File does not exist".to_string());
        }
        let canonical = path.canonicalize().map_err(|e| format!("Invalid path: {e}"))?;
        let blocked_segments: &[&str] = &[
            "windows", "program files", "program files (x86)",
            "programdata", ".ssh", ".gnupg",
            "etc", "usr", "bin", "sbin", "var", "root",
        ];
        for component in canonical.components() {
            if let std::path::Component::Normal(seg) = component {
                let seg_lower = seg.to_string_lossy().to_lowercase();
                if blocked_segments.contains(&seg_lower.as_str()) {
                    return Err(format!("Cannot import from system directory: {}", canonical.display()));
                }
            }
        }
        if canonical.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase()) != Some("dat".to_string())
            && canonical.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase()) != Some("txt".to_string())
            && canonical.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase()) != Some("gz".to_string())
            && canonical.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase()) != Some("zip".to_string())
            && canonical.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase()) != Some("p2p".to_string())
        {
            return Err("IP filter file must be a .dat, .txt, .gz, .zip, or .p2p file".to_string());
        }
        Ok(canonical)
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))??;

    state
        .network_tx
        .send(NetworkCommand::ReloadIpFilter { path })
        .await
        .map_err(|e| format!("Failed to reload filter: {e}"))?;

    state
        .network_tx
        .send(NetworkCommand::SetIpFilterEnabled { enabled: true })
        .await
        .map_err(|e| format!("Failed to enable filter: {e}"))?;

    {
        let save_data = {
            let mut config = state.config.write().await;
            config.settings.ip_filter_enabled = true;
            config.prepare_save().map_err(|e| format!("Failed to save config: {e}"))?
        };
        tokio::task::spawn_blocking(move || {
            crate::storage::config::AppConfig::write_to_disk(&save_data.0, &save_data.1, &save_data.2)
        }).await.map_err(|e| format!("Save task failed: {e}"))?.map_err(|e| format!("Failed to save config: {e}"))?;
    }

    Ok("Imported and loaded IP filter — filter is now active".into())
}
