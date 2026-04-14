use tracing::info;

use tauri::Manager;

use crate::app_state::AppState;
use crate::network::kad::bootstrap;
use crate::network::NetworkCommand;
use crate::types::AppSettings;

const NODES_DAT_URL: &str = "https://upd.emule-security.org/nodes.dat";
const IPFILTER_URL: &str = "https://emuling.gitlab.io/ipfilter.dat";

#[tauri::command]
pub async fn get_settings(
    state: tauri::State<'_, AppState>,
) -> Result<AppSettings, String> {
    let config = state.config.read().await;
    Ok(config.settings.clone())
}

fn validate_settings(settings: &AppSettings) -> Result<(), String> {
    if settings.spam_filter_profile != "relaxed" && settings.spam_filter_profile != "balanced" && settings.spam_filter_profile != "aggressive" {
        return Err("Spam filter profile must be 'relaxed', 'balanced', or 'aggressive'".into());
    }
    if settings.tcp_port == 0 {
        return Err("TCP port must be between 1 and 65535".into());
    }
    if settings.udp_port == 0 {
        return Err("UDP port must be between 1 and 65535".into());
    }
    if settings.max_concurrent_downloads == 0 || settings.max_concurrent_downloads > 50 {
        return Err("Max concurrent downloads must be between 1 and 50".into());
    }
    if settings.max_concurrent_uploads == 0 || settings.max_concurrent_uploads > 50 {
        return Err("Max concurrent uploads must be between 1 and 50".into());
    }
    if !(60..=14400).contains(&settings.download_queue_wait_secs) {
        return Err("Download queue wait must be between 60 and 14400 seconds".into());
    }
    if !(1..=2000).contains(&settings.max_sources_per_file) {
        return Err("Max sources per file must be between 1 and 2000".into());
    }
    if !(1..=2000).contains(&settings.max_connections) {
        return Err("Max connections must be between 1 and 2000".into());
    }
    if !(1..=20).contains(&settings.multisource_retry_rounds) {
        return Err("Multi-source retry rounds must be between 1 and 20".into());
    }
    if !(1..=20).contains(&settings.download_part_retry_rounds) {
        return Err("Part hash retry rounds must be between 1 and 20".into());
    }
    if !(1..=16_384).contains(&settings.max_download_file_size_gib) {
        return Err("Max download file size must be between 1 and 16384 GiB".into());
    }
    if !(30..=600).contains(&settings.search_timeout_secs) {
        return Err("Search timeout must be between 30 and 600 seconds".into());
    }
    if !(1..=500).contains(&settings.max_friends) {
        return Err("Max friends must be between 1 and 500".into());
    }
    if settings.nickname.trim().is_empty() {
        return Err("Nickname must not be empty".into());
    }
    if settings.nickname.len() > 128 {
        return Err("Nickname must be 128 bytes or fewer".into());
    }
    let blocked_segments: &[&str] = &[
        "windows", "program files", "program files (x86)",
        "programdata", ".ssh", ".gnupg",
        "etc", "usr", "bin", "sbin", "var", "root",
    ];
    if !settings.download_folder.is_empty() {
        let path = std::path::Path::new(&settings.download_folder);
        if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            return Err("Download folder must not contain '..' path components".into());
        }
        for component in path.components() {
            if let std::path::Component::Normal(seg) = component {
                let seg_lower = seg.to_string_lossy().to_lowercase();
                if blocked_segments.contains(&seg_lower.as_str()) {
                    return Err(format!("Cannot use system directory as download folder: {}", settings.download_folder));
                }
            }
        }
    }
    if !settings.rendezvous_url.is_empty() {
        let url_lower = settings.rendezvous_url.to_ascii_lowercase();
        if !url_lower.starts_with("https://") {
            return Err("Rendezvous URL must use HTTPS".into());
        }
        let after_scheme = &settings.rendezvous_url["https://".len()..];
        if after_scheme.is_empty() || after_scheme.starts_with('/') {
            return Err("Rendezvous URL must have a valid host".into());
        }
        if after_scheme.contains('@') {
            return Err("Rendezvous URL must not contain credentials".into());
        }
    }

    for folder in &settings.shared_folders {
        let path = std::path::Path::new(folder);
        if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            return Err(format!("Shared folder must not contain '..' path components: {folder}"));
        }
        for component in path.components() {
            if let std::path::Component::Normal(seg) = component {
                let seg_lower = seg.to_string_lossy().to_lowercase();
                if blocked_segments.contains(&seg_lower.as_str()) {
                    return Err(format!("Cannot share system directory: {folder}"));
                }
                if seg_lower == "appdata" {
                    let rest: String = path.components()
                        .skip_while(|c| {
                            if let std::path::Component::Normal(s) = c {
                                s.to_string_lossy().to_lowercase() != "appdata"
                            } else {
                                true
                            }
                        })
                        .skip(1)
                        .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
                        .collect::<Vec<_>>()
                        .join("/");
                    if rest.starts_with("local/temp") || rest.starts_with("local\\temp") {
                        return Err(format!("Cannot share system directory: {folder}"));
                    }
                }
            }
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn update_settings(
    state: tauri::State<'_, AppState>,
    settings: AppSettings,
) -> Result<String, String> {
    let mut settings = settings;
    settings.spam_filter_profile = settings.spam_filter_profile.trim().to_ascii_lowercase();
    validate_settings(&settings)?;

    let old_settings = {
        let config = state.config.read().await;
        config.settings.clone()
    };

    let port_changed = settings.tcp_port != old_settings.tcp_port
        || settings.udp_port != old_settings.udp_port;

    let save_data = {
        let mut config = state.config.write().await;
        config.settings = settings.clone();
        config.prepare_save().map_err(|e| format!("Failed to serialize settings: {e}"))?
    };
    {
        let (data, tmp, final_path) = save_data;
        tokio::task::spawn_blocking(move || {
            crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
        }).await.map_err(|e| format!("Save failed: {e}"))?.map_err(|e| format!("Save failed: {e}"))?;
    }

    state
        .bandwidth_limiter
        .set_configured_limits(settings.max_upload_speed, settings.max_download_speed);

    {
        let mut manager = state.transfer_manager.write().await;
        manager.max_concurrent = settings.max_concurrent_downloads;
    }

    {
        let mut live = state.upload_shared_folders.write().await;
        *live = settings.shared_folders.clone();
    }

    state.network_tx.try_send(NetworkCommand::UpdateSettings {
        settings: settings.clone(),
    }).map_err(|e| format!("Network busy: {e}"))?;

    if port_changed {
        Ok("Settings saved. Port changes require an application restart to take effect.".into())
    } else {
        Ok("Settings saved.".into())
    }
}

#[tauri::command]
pub async fn download_nodes_dat(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    info!("Downloading nodes.dat from {NODES_DAT_URL}");

    let (host, resolved_addrs) = crate::security::validate_fetch_url(NODES_DAT_URL).await
        .map_err(|e| format!("URL validation failed: {e}"))?;
    let client = crate::security::build_pinned_client(&host, &resolved_addrs)
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

    const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
    let response = client.get(NODES_DAT_URL).send()
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
            let chunk = chunk.map_err(|e| format!("Failed to read response body: {e}"))?;
            body.extend_from_slice(&chunk);
            if body.len() > MAX_RESPONSE_BYTES {
                return Err("Response too large".into());
            }
        }
        body
    };

    let data_dir = app.path().app_data_dir()
        .map_err(|e| format!("Failed to get app data dir: {e}"))?;
    tokio::fs::create_dir_all(&data_dir)
        .await
        .map_err(|e| format!("Failed to create data dir: {e}"))?;

    let nodes_path = data_dir.join("nodes.dat");
    tokio::fs::write(&nodes_path, &bytes)
        .await
        .map_err(|e| format!("Failed to write nodes.dat: {e}"))?;

    let contacts = bootstrap::load_nodes_dat(&nodes_path)
        .map_err(|e| format!("Failed to parse nodes.dat: {e}"))?;

    let contact_count = contacts.len();
    let byte_count = bytes.len();

    // Inject contacts into the running network
    state
        .network_tx
        .try_send(NetworkCommand::BootstrapContacts { contacts })
        .map_err(|e| format!("Network busy: {e}"))?;

    let msg = format!(
        "Downloaded and loaded {contact_count} contacts ({byte_count} bytes) — bootstrapping now",
    );
    info!("{msg}");
    Ok(msg)
}

#[tauri::command]
pub async fn download_ipfilter(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    info!("Downloading ipfilter.dat from {IPFILTER_URL}");

    let (host, resolved_addrs) = crate::security::validate_fetch_url(IPFILTER_URL).await
        .map_err(|e| format!("URL validation failed: {e}"))?;
    let client = crate::security::build_pinned_client(&host, &resolved_addrs)
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

    const MAX_RESPONSE_BYTES: usize = 50 * 1024 * 1024;
    let response = client.get(IPFILTER_URL).send()
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
            let chunk = chunk.map_err(|e| format!("Failed to read response body: {e}"))?;
            body.extend_from_slice(&chunk);
            if body.len() > MAX_RESPONSE_BYTES {
                return Err("Response too large".into());
            }
        }
        body
    };

    let data_dir = app.path().app_data_dir()
        .map_err(|e| format!("Failed to get app data dir: {e}"))?;
    tokio::fs::create_dir_all(&data_dir)
        .await
        .map_err(|e| format!("Failed to create data dir: {e}"))?;

    let filter_path = data_dir.join("ipfilter.dat");
    tokio::fs::write(&filter_path, &bytes)
        .await
        .map_err(|e| format!("Failed to write ipfilter.dat: {e}"))?;

    let byte_count = bytes.len();
    let line_count = bytes.iter().filter(|&&b| b == b'\n').count();

    let reload_ok = state
        .network_tx
        .try_send(NetworkCommand::ReloadIpFilter {
            path: filter_path,
        })
        .is_ok();

    let msg = if reload_ok {
        format!(
            "Downloaded ipfilter.dat ({byte_count} bytes, ~{line_count} entries) — reloading filter now"
        )
    } else {
        format!(
            "Downloaded ipfilter.dat ({byte_count} bytes, ~{line_count} entries) — network busy, filter will load on restart"
        )
    };
    info!("{msg}");
    Ok(msg)
}
