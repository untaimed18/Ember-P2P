use std::net::Ipv4Addr;

use tauri::Manager;
use tokio::sync::oneshot;
use tracing::info;

use crate::app_state::AppState;
use crate::network::kad::ip_filter::IpFilterStats;
use crate::network::NetworkCommand;

const CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

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
    start_ip
        .parse::<Ipv4Addr>()
        .map_err(|_| "Invalid start IP address")?;
    end_ip
        .parse::<Ipv4Addr>()
        .map_err(|_| "Invalid end IP address")?;

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

    let mut config = state.config.write().await;
    config.settings.ip_filter_enabled = enabled;
    let updated = config.settings.clone();
    config
        .update(updated)
        .map_err(|e| format!("Failed to save config: {e}"))?;

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

    let mut config = state.config.write().await;
    config.settings.block_private_ips = block_private;
    let updated = config.settings.clone();
    config
        .update(updated)
        .map_err(|e| format!("Failed to save config: {e}"))?;

    Ok(())
}

#[tauri::command]
pub async fn download_and_load_ipfilter(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    const IPFILTER_URL: &str = "https://emuling.gitlab.io/ipfilter.dat";

    info!("Downloading ipfilter.dat from {IPFILTER_URL}");

    let bytes = reqwest::get(IPFILTER_URL)
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response: {e}"))?;

    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to get app data dir: {e}"))?;
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("Failed to create data dir: {e}"))?;

    let filter_path = data_dir.join("ipfilter.dat");
    std::fs::write(&filter_path, &bytes)
        .map_err(|e| format!("Failed to write ipfilter.dat: {e}"))?;

    let byte_count = bytes.len();

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
        let mut config = state.config.write().await;
        config.settings.ip_filter_enabled = true;
        let updated = config.settings.clone();
        let _ = config.update(updated);
    }

    let msg = format!("Downloaded and loaded ipfilter.dat ({byte_count} bytes) — filter is now active");
    info!("{msg}");
    Ok(msg)
}

#[tauri::command]
pub async fn import_ipfilter_file(
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<String, String> {
    let path = std::path::PathBuf::from(&file_path);
    if !path.exists() {
        return Err("File does not exist".into());
    }

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
        let mut config = state.config.write().await;
        config.settings.ip_filter_enabled = true;
        let updated = config.settings.clone();
        let _ = config.update(updated);
    }

    Ok("Imported and loaded IP filter — filter is now active".into())
}
