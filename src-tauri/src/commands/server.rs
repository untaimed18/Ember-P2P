use crate::app_state::AppState;
use crate::network::NetworkCommand;
use crate::types::ServerInfo;
use tracing::info;

async fn resolve_server_host(input: &str, port: u16) -> Result<String, String> {
    if let Ok(ip) = input.parse::<std::net::Ipv4Addr>() {
        if crate::security::is_special_use_v4(ip) {
            return Err("Cannot connect to private/loopback addresses".into());
        }
        return Ok(input.to_string());
    }
    let addr = tokio::net::lookup_host((input, port))
        .await
        .map_err(|_| "Failed to resolve server address".to_string())?
        .find(|addr| addr.is_ipv4())
        .ok_or_else(|| "No IPv4 address found for the given hostname".to_string())?;
    if crate::security::is_private_ip(addr.ip()) {
        return Err("Server hostname resolves to a private/loopback address".into());
    }
    Ok(addr.ip().to_string())
}

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
    let resolved_ip = resolve_server_host(&ip, port).await?;

    state
        .network_tx
        .try_send(NetworkCommand::ConnectToServer { ip: resolved_ip.clone(), port })
        .map_err(|e| format!("Network busy: {e}"))?;

    Ok(format!("Connecting to ed2k server {resolved_ip}:{port}..."))
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
    let resolved_ip = resolve_server_host(&ip, port).await?;
    let label_name = if name.trim().is_empty() {
        ip.clone()
    } else {
        name.clone()
    };
    let (tx, rx) = tokio::sync::oneshot::channel();

    state
        .network_tx
        .try_send(NetworkCommand::AddServer { ip: resolved_ip, port, name: label_name, tx })
        .map_err(|e| format!("Network busy: {e}"))?;

    rx.await.map_err(|_| "Failed to add server".to_string())?
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

    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::RemoveServer { ip: ip.clone(), port, tx })
        .map_err(|e| format!("Network busy: {e}"))?;

    rx.await.map_err(|_| "Failed to remove server".to_string())?
}

#[tauri::command]
pub async fn get_server_list(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<ServerInfo>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetServerListSnapshot { tx })
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
        .try_send(NetworkCommand::GetConnectedServerSnapshot { tx })
        .map_err(|e| format!("Network busy: {e}"))?;
    rx.await.map_err(|_| "Failed to get connected server".to_string())
}

#[tauri::command]
pub async fn download_server_met(
    state: tauri::State<'_, AppState>,
    url: String,
) -> Result<String, String> {
    let (validated_url, host, resolved_addrs) = crate::security::validate_fetch_url(&url).await?;

    info!("Downloading server.met");

    let client = crate::security::build_pinned_client(&host, &resolved_addrs)
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

    const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
    let response = client.get(&validated_url).send()
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

    let data = if bytes.starts_with(&[0x1f, 0x8b]) {
        use std::io::Read;
        const MAX_DECOMPRESSED: u64 = 50 * 1024 * 1024;
        let decoder = flate2::read::GzDecoder::new(&bytes[..]);
        let mut limited = decoder.take(MAX_DECOMPRESSED);
        let mut decompressed = Vec::new();
        limited.read_to_end(&mut decompressed)
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

    let stats = rx.await.map_err(|_| "Failed to merge servers".to_string())?
        .map_err(|e| format!("Failed to parse server.met: {e}"))?;

    let msg = format!(
        "Downloaded server.met: {} added, {} updated, {} filtered",
        stats.added, stats.updated, stats.filtered
    );
    info!("{msg}");
    Ok(msg)
}
