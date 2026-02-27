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
    if settings.nickname.len() > 128 {
        return Err("Nickname must be 128 characters or fewer".into());
    }
    if !settings.download_folder.is_empty() {
        let path = std::path::Path::new(&settings.download_folder);
        if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            return Err("Download folder must not contain '..' path components".into());
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn update_settings(
    state: tauri::State<'_, AppState>,
    settings: AppSettings,
) -> Result<String, String> {
    validate_settings(&settings)?;

    state
        .bandwidth_limiter
        .set_limits(settings.max_upload_speed, settings.max_download_speed);

    let old_settings = {
        let config = state.config.read().await;
        config.settings.clone()
    };

    let port_changed = settings.tcp_port != old_settings.tcp_port
        || settings.udp_port != old_settings.udp_port;

    {
        let mut manager = state.transfer_manager.write().await;
        manager.max_concurrent = settings.max_concurrent_downloads;
    }

    let mut config = state.config.write().await;
    config
        .update(settings)
        .map_err(|e| format!("Failed to save settings: {e}"))?;

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

    let bytes = reqwest::get(NODES_DAT_URL)
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response body: {e}"))?;

    let data_dir = app.path().app_data_dir()
        .map_err(|e| format!("Failed to get app data dir: {e}"))?;
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("Failed to create data dir: {e}"))?;

    let nodes_path = data_dir.join("nodes.dat");
    std::fs::write(&nodes_path, &bytes)
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

    let bytes = reqwest::get(IPFILTER_URL)
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response body: {e}"))?;

    let data_dir = app.path().app_data_dir()
        .map_err(|e| format!("Failed to get app data dir: {e}"))?;
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("Failed to create data dir: {e}"))?;

    let filter_path = data_dir.join("ipfilter.dat");
    std::fs::write(&filter_path, &bytes)
        .map_err(|e| format!("Failed to write ipfilter.dat: {e}"))?;

    let byte_count = bytes.len();
    let line_count = bytes.iter().filter(|&&b| b == b'\n').count();

    let _ = state
        .network_tx
        .try_send(NetworkCommand::ReloadIpFilter {
            path: filter_path,
        });

    let msg = format!(
        "Downloaded ipfilter.dat ({byte_count} bytes, ~{line_count} entries) — reloading filter now",
    );
    info!("{msg}");
    Ok(msg)
}
