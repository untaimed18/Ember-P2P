use crate::app_state::AppState;
use crate::network::NetworkCommand;
use crate::types::ServerInfo;
use tracing::info;

#[tauri::command]
pub async fn connect_to_server(
    state: tauri::State<'_, AppState>,
    ip: String,
    port: u16,
) -> Result<String, String> {
    if ip.is_empty() {
        return Err("Server IP is required".into());
    }
    if port == 0 {
        return Err("Port must be greater than 0".into());
    }

    state
        .network_tx
        .try_send(NetworkCommand::ConnectToServer { ip: ip.clone(), port })
        .map_err(|e| format!("Network busy: {e}"))?;

    Ok(format!("Connecting to ed2k server {ip}:{port}..."))
}

#[tauri::command]
pub async fn disconnect_server(
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    state
        .network_tx
        .try_send(NetworkCommand::DisconnectServer)
        .map_err(|e| format!("Network busy: {e}"))?;

    Ok("Disconnected from ed2k server".into())
}

#[tauri::command]
pub async fn add_server(
    state: tauri::State<'_, AppState>,
    ip: String,
    port: u16,
    name: String,
) -> Result<String, String> {
    if ip.is_empty() {
        return Err("Server IP is required".into());
    }
    if port == 0 {
        return Err("Port must be greater than 0".into());
    }

    state
        .network_tx
        .try_send(NetworkCommand::AddServer { ip: ip.clone(), port, name: name.clone() })
        .map_err(|e| format!("Network busy: {e}"))?;

    let label = if name.is_empty() { format!("{ip}:{port}") } else { name };
    Ok(format!("Added server {label}"))
}

#[tauri::command]
pub async fn remove_server(
    state: tauri::State<'_, AppState>,
    ip: String,
    port: u16,
) -> Result<String, String> {
    if ip.is_empty() {
        return Err("Server IP is required".into());
    }

    state
        .network_tx
        .try_send(NetworkCommand::RemoveServer { ip: ip.clone(), port })
        .map_err(|e| format!("Network busy: {e}"))?;

    Ok(format!("Removed server {ip}:{port}"))
}

#[tauri::command]
pub async fn get_server_list(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<ServerInfo>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetServerList { tx })
        .map_err(|e| format!("Network busy: {e}"))?;

    rx.await.map_err(|_| "Failed to get server list".to_string())
}

#[tauri::command]
pub async fn get_connected_server(
    state: tauri::State<'_, AppState>,
) -> Result<Option<ServerInfo>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetConnectedServer { tx })
        .map_err(|e| format!("Network busy: {e}"))?;

    rx.await.map_err(|_| "Failed to get connected server".to_string())
}

#[tauri::command]
pub async fn download_server_met(
    state: tauri::State<'_, AppState>,
    url: String,
) -> Result<String, String> {
    if url.is_empty() {
        return Err("URL is required".into());
    }

    info!("Downloading server.met from {url}");

    let response = reqwest::get(&url)
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response: {e}"))?;

    let data = if bytes.starts_with(&[0x1f, 0x8b]) {
        use std::io::Read;
        let mut decoder = flate2::read::GzDecoder::new(&bytes[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)
            .map_err(|e| format!("Failed to decompress gzip: {e}"))?;
        decompressed
    } else {
        bytes.to_vec()
    };

    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::MergeServerMet { data, tx })
        .map_err(|e| format!("Network busy: {e}"))?;

    let added = rx.await.map_err(|_| "Failed to merge servers".to_string())?
        .map_err(|e| format!("Failed to parse server.met: {e}"))?;

    let msg = format!("Downloaded and merged {added} new servers from server.met");
    info!("{msg}");
    Ok(msg)
}
