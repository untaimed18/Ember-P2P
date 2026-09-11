use crate::app_state::AppState;
use crate::commands::errors::{await_reply, coded, coded_ctx};
use crate::network::NetworkCommand;
use crate::types::ServerInfo;
use tauri_plugin_dialog::DialogExt;
use tracing::info;

const MAX_SERVER_NAME_LEN: usize = 256;

/// Default community server.met used on first launch and as the Servers-page
/// suggested URL. Same host as nodes.dat / ipfilter bootstrap assets.
pub const DEFAULT_SERVER_MET_URL: &str = "https://upd.emule-security.org/server.met";

/// Download and optionally gunzip a server.met from `url` (HTTPS + DNS-pinned).
/// Shared by the Tauri command and network-task first-launch bootstrap.
pub async fn fetch_server_met_bytes(url: &str) -> Result<Vec<u8>, String> {
    const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
    let response = crate::security::fetch_pinned_get(url)
        .await
        .map_err(|e| coded_ctx("http_request_failed", "HTTP request failed", e))?
        .error_for_status()
        .map_err(|e| coded_ctx("http_error", "HTTP error", e))?;
    if let Some(cl) = response.content_length() {
        if cl > MAX_RESPONSE_BYTES as u64 {
            return Err(coded(
                "response_too_large",
                "Response too large (Content-Length exceeds limit)",
            ));
        }
    }

    let bytes = {
        use futures::StreamExt;
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk
                .map_err(|e| coded_ctx("response_read_failed", "Failed to read response", e))?;
            body.extend_from_slice(&chunk);
            if body.len() > MAX_RESPONSE_BYTES {
                return Err(coded("response_too_large", "Response too large"));
            }
        }
        body
    };

    if bytes.starts_with(&[0x1f, 0x8b]) {
        use std::io::Read;
        // Bound decompressed output; `take(MAX + 1)` so we can distinguish
        // "exactly the limit" from overflow (same pattern as ipfilter .gz).
        const MAX_DECOMPRESSED: u64 = 50 * 1024 * 1024;
        let decoder = flate2::read::GzDecoder::new(&bytes[..]);
        let mut limited = decoder.take(MAX_DECOMPRESSED + 1);
        let mut decompressed = Vec::new();
        limited
            .read_to_end(&mut decompressed)
            .map_err(|e| coded_ctx("gzip_decompress_failed", "Failed to decompress gzip", e))?;
        if decompressed.len() as u64 > MAX_DECOMPRESSED {
            return Err(coded(
                "gzip_decompressed_too_large",
                "Decompressed server.met is too large",
            ));
        }
        Ok(decompressed)
    } else {
        Ok(bytes)
    }
}

async fn resolve_server_host(input: &str, port: u16) -> Result<String, String> {
    if let Ok(ip) = input.parse::<std::net::Ipv4Addr>() {
        if crate::security::is_special_use_v4(ip) {
            return Err(coded(
                "server_private_addr",
                "Cannot connect to private/loopback addresses",
            ));
        }
        return Ok(input.to_string());
    }
    let addr = tokio::net::lookup_host((input, port))
        .await
        .map_err(|_| coded("server_resolve_failed", "Failed to resolve server address"))?
        .find(|addr| addr.is_ipv4())
        .ok_or_else(|| {
            coded(
                "server_no_ipv4",
                "No IPv4 address found for the given hostname",
            )
        })?;
    if crate::security::is_private_ip(addr.ip()) {
        return Err(coded(
            "server_resolves_private",
            "Server hostname resolves to a private/loopback address",
        ));
    }
    Ok(addr.ip().to_string())
}

/// Collect native consent for introducing a new eD2K server.
///
/// Connecting to a server is not a neutral act: the login sends this machine's
/// ed2k user hash, nickname and listening ports, exposes the public IP, and
/// then pushes the **entire public share list** via `OP_OFFERFILES` along with
/// every subsequent search. That is a larger disclosure than the ones this
/// application already stops to ask about — opening a link, adding a web
/// service because the site "learns which file you are looking for", replacing
/// the IP filter from a URL — all of which are gated natively on the stated
/// grounds that a request arriving from the renderer is not consent.
///
/// Asked once, on the addition, rather than on each connect, so routine
/// reconnects to a server the user already chose stay prompt-free.
async fn confirm_server_addition(app: &tauri::AppHandle, hosts: &[String]) -> bool {
    let listed = hosts
        .iter()
        .map(|host| crate::commands::settings::elide_for_dialog(host))
        .collect::<Vec<_>>()
        .join("\n");
    let prompt = format!(
        "{listed}\n\nConnecting to an eD2K server tells it your nickname, your user hash and your \
         IP address, and shares the list of files you are offering publicly. Ember asks once, \
         here, and not again each time it reconnects.\n\nAdd it only if you recognise the server."
    );
    let title = if hosts.len() == 1 {
        "Add this eD2K server?"
    } else {
        "Add these eD2K servers?"
    };
    let confirm_app = app.clone();
    // `blocking_show` pumps the dialog on the main thread, so it cannot run on
    // the command's own task. Same shape as `confirm_web_service_additions`.
    tokio::task::spawn_blocking(move || {
        confirm_app
            .dialog()
            .message(prompt)
            .title(title)
            .kind(tauri_plugin_dialog::MessageDialogKind::Warning)
            .buttons(tauri_plugin_dialog::MessageDialogButtons::OkCancelCustom(
                "Add".to_string(),
                "Cancel".to_string(),
            ))
            .blocking_show()
    })
    .await
    .unwrap_or(false)
}

#[tauri::command]
pub async fn connect_to_server(
    state: tauri::State<'_, AppState>,
    ip: String,
    port: u16,
) -> Result<String, String> {
    if ip.is_empty() {
        return Err(coded("server_ip_required", "Server IP is required"));
    }
    if port == 0 {
        return Err(coded("server_port_invalid", "Port must be greater than 0"));
    }
    let resolved_ip = resolve_server_host(&ip, port).await?;

    // Only somewhere the user has already agreed to. Without this the consent
    // collected in `add_server` is bypassable in one call: a renderer could
    // name any public endpoint here and reach a server that was never added,
    // which is the whole disclosure the prompt exists to gate.
    let known = server_list_snapshot(&state).await?;
    if !known
        .iter()
        .any(|server| server.ip == resolved_ip && server.port == port)
    {
        return Err(coded(
            "server_not_in_list",
            "That server is not in your server list. Add it first.",
        ));
    }

    state
        .network_tx
        .try_send(NetworkCommand::ConnectToServer {
            ip: resolved_ip.clone(),
            port,
        })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;

    Ok(format!("Connecting to ed2k server {resolved_ip}:{port}..."))
}

#[tauri::command]
pub async fn disconnect_server(state: tauri::State<'_, AppState>) -> Result<String, String> {
    state
        .network_tx
        .try_send(NetworkCommand::DisconnectServer)
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;

    Ok("Disconnected from ed2k server".into())
}

#[tauri::command]
pub async fn add_server(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    ip: String,
    port: u16,
    name: String,
) -> Result<String, String> {
    if ip.is_empty() {
        return Err(coded("server_ip_required", "Server IP is required"));
    }
    if port == 0 {
        return Err(coded("server_port_invalid", "Port must be greater than 0"));
    }
    if name.len() > MAX_SERVER_NAME_LEN {
        return Err(coded_ctx(
            "server_name_too_long",
            format!("Server name exceeds {MAX_SERVER_NAME_LEN} bytes"),
            MAX_SERVER_NAME_LEN,
        ));
    }
    let resolved_ip = resolve_server_host(&ip, port).await?;
    let label_name = if name.trim().is_empty() {
        ip.clone()
    } else {
        name.clone()
    };

    // Consent for the destination, collected natively — see
    // `confirm_server_addition`. The host is shown as the user typed it *and*
    // as it resolved, so a name that resolves somewhere unexpected is visible.
    let shown = if resolved_ip == ip {
        format!("{label_name} — {resolved_ip}:{port}")
    } else {
        format!("{label_name} — {ip} ({resolved_ip}):{port}")
    };
    if !confirm_server_addition(&app, std::slice::from_ref(&shown)).await {
        return Err(coded(
            "server_add_declined",
            "The server was not added.",
        ));
    }

    let (tx, rx) = tokio::sync::oneshot::channel();

    state
        .network_tx
        .try_send(NetworkCommand::AddServer {
            ip: resolved_ip,
            port,
            name: label_name,
            tx,
        })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;

    await_reply(rx, "server_add_failed", "Failed to add server").await?
}

#[tauri::command]
pub async fn remove_server(
    state: tauri::State<'_, AppState>,
    ip: String,
    port: u16,
) -> Result<String, String> {
    if ip.is_empty() {
        return Err(coded("server_ip_required", "Server IP is required"));
    }

    let resolved_ip = resolve_server_host(&ip, port).await?;

    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::RemoveServer {
            ip: resolved_ip,
            port,
            tx,
        })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;

    await_reply(rx, "server_remove_failed", "Failed to remove server").await?
}

#[tauri::command]
pub async fn get_server_list(state: tauri::State<'_, AppState>) -> Result<Vec<ServerInfo>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetServerListSnapshot { tx })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    await_reply(rx, "server_list_failed", "Failed to get server list").await
}

/// The stored server list, for callers that need to check membership rather
/// than display it. Shares the network round-trip with [`get_server_list`].
async fn server_list_snapshot(state: &AppState) -> Result<Vec<ServerInfo>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetServerListSnapshot { tx })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    await_reply(rx, "server_list_failed", "Failed to get server list").await
}

#[tauri::command]
pub async fn get_connected_server(
    state: tauri::State<'_, AppState>,
) -> Result<Option<ServerInfo>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetConnectedServerSnapshot { tx })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    await_reply(
        rx,
        "server_connected_failed",
        "Failed to get connected server",
    )
    .await
}

#[tauri::command]
pub async fn download_server_met(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    url: String,
) -> Result<String, String> {
    info!("Downloading server.met");

    // The bundled community list is exempt, by byte-exact comparison so a
    // lookalike URL cannot inherit the exemption — the same shape
    // `update_ipfilter_from_url` uses for its own default. Everything else is a
    // renderer-supplied URL introducing an unknown number of servers at once,
    // so it is gated like a single addition is.
    if url != DEFAULT_SERVER_MET_URL {
        let host = crate::webservices::service_host(&url);
        if !confirm_server_addition(&app, std::slice::from_ref(&host)).await {
            return Err(coded(
                "server_met_declined",
                "The server list was not downloaded.",
            ));
        }
    }

    let data = fetch_server_met_bytes(&url).await?;

    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::MergeServerMet { data, tx })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;

    let stats = await_reply(rx, "server_merge_failed", "Failed to merge servers")
        .await?
        .map_err(|e| coded_ctx("server_met_parse_failed", "Failed to parse server.met", e))?;

    let msg = format!(
        "Downloaded server.met: {} added, {} updated, {} filtered, {} dropped at capacity",
        stats.added, stats.updated, stats.filtered, stats.at_capacity
    );
    info!("{msg}");
    Ok(msg)
}
