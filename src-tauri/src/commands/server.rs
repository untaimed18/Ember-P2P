use crate::app_state::AppState;
use crate::network::NetworkCommand;
use crate::types::ServerInfo;

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
