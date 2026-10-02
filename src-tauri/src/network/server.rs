//! eD2K server connection: connect, disconnect, session reset, the server
//! log, and IP-filter enforcement on the connected server.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// One recorded line of eD2K server activity.
///
/// `seq` is assigned here rather than in the frontend so a replayed line and
/// the live event announcing it can be recognised as the same line.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServerLogLine {
    pub seq: u64,
    /// Epoch milliseconds at the moment the line was recorded. Carried through
    /// so replayed lines keep the time they happened rather than the time they
    /// were read back.
    pub at: i64,
    pub message: String,
}

/// Lines kept for replay. Matches `MAX_ENTRIES` in `stores/serverLog.ts`;
/// there is no point holding more here than the view will show.
pub(super) const SERVER_LOG_HISTORY: usize = 200;

/// Replay buffer behind [`get_server_log`](crate::commands::server::get_server_log).
///
/// `emit_server_log` used to only emit. That was survivable while the sole
/// consumer was a frontend store that outlived tab switches, but the store
/// does not outlive a reload of the webview — and the uploads pane was
/// offering the webview's own Reload as its context menu — so the log came
/// back empty with the connection still up and no way to get the history
/// back. Keeping the last lines here means the frontend can ask.
///
/// Process-global because `emit_server_log` is called from all over the
/// network task with nothing but an `AppHandle` to hand.
pub(super) static SERVER_LOG: std::sync::LazyLock<parking_lot::Mutex<VecDeque<ServerLogLine>>> =
    std::sync::LazyLock::new(|| parking_lot::Mutex::new(VecDeque::new()));

/// Record a line in the replay buffer and return it, ready to emit.
pub(super) fn record_server_log(message: &str) -> ServerLogLine {
    static NEXT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let line = ServerLogLine {
        seq: NEXT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        at: chrono::Utc::now().timestamp_millis(),
        message: message.to_string(),
    };
    let mut log = SERVER_LOG.lock();
    if log.len() >= SERVER_LOG_HISTORY {
        log.pop_front();
    }
    log.push_back(line.clone());
    line
}

pub(super) fn emit_server_log(app: &tauri::AppHandle, message: &str) {
    let _ = app.emit("server-log", record_server_log(message));
}

/// The retained log, oldest first.
pub fn server_log_history() -> Vec<ServerLogLine> {
    SERVER_LOG.lock().iter().cloned().collect()
}

/// Discard the retained log. `seq` deliberately keeps counting, so a line
/// recorded after a clear can still never collide with one the frontend is
/// already holding.
pub fn clear_server_log_history() {
    SERVER_LOG.lock().clear();
}

/// Extract a human-readable message from a `catch_unwind` panic payload.
pub(super) fn describe_panic(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

/// Try to connect to a server, attempting the DH-encrypted connection first (for HighID),
/// then falling back to plain text (for LowID).
///
/// Many servers use the same port for both plain and obfuscated connections (the server
/// detects the mode from the first byte). If no dedicated obfuscation port is known,
/// we try DH on the regular port first.
pub(super) async fn try_connect_server(
    ip: &str,
    port: u16,
    obf_port: u16,
    app: &tauri::AppHandle,
    force_plain: bool,
    obfuscation_enabled: bool,
) -> anyhow::Result<(Ed2kServerConnection, SocketAddr)> {
    // Decide whether/where to attempt the obfuscated (DH) server handshake.
    // eMule negotiates protocol obfuscation via a DH agreement on the server's
    // *standard* port when no separate obfuscation port is advertised (its log:
    // "Connecting to … (45.82.80.155:5687 - using Protocol Obfuscation)" /
    // "Obfuscated connection established on: … (45.82.80.155:5687)"). Crucially,
    // some servers — notably "eMule Security" — return source lists ONLY over an
    // obfuscated connection, so connecting plain there yields a working login
    // (HighID, status, welcome) but zero OP_FOUNDSOURCES. So prefer obfuscation
    // whenever it's enabled: use the dedicated obfuscation port if we learned
    // one, otherwise the standard port. Fall back to plain if the DH handshake
    // fails (e.g. a server that doesn't actually support obfuscation).
    // Gated on the setting first. Reading `obf_port` before it meant that once
    // a server's obfuscation port had been learned — which happens
    // automatically from any extended UDP status reply, so for most
    // obfuscation-capable servers — turning obfuscation off in Settings did
    // nothing. That is not cosmetic: `login()` sets
    // `SRVCAP_SUPPORTCRYPT | SRVCAP_REQUESTCRYPT` on an encrypted transport,
    // and the server relays those bits to peers as instructions for how to
    // connect back to us.
    let enc_port = if !obfuscation_enabled {
        None
    } else if obf_port != 0 {
        Some(obf_port)
    } else {
        Some(port)
    };
    if !force_plain {
        if let Some(enc_port) = enc_port {
            let enc_addr = tokio::net::lookup_host((ip, enc_port))
                .await?
                .find(|addr| addr.is_ipv4())
                .ok_or_else(|| anyhow::anyhow!("No IPv4 address found for {ip}:{enc_port}"))?;
            info!("Trying encrypted DH connection to server {ip}:{enc_port}");
            emit_server_log(
                app,
                &format!("Trying encrypted connection to {ip}:{enc_port}..."),
            );
            match Ed2kServerConnection::connect_encrypted(enc_addr).await {
                Ok(conn) => {
                    info!("Encrypted DH connection to server {ip}:{enc_port} established");
                    emit_server_log(app, "Encrypted connection established");
                    return Ok((conn, enc_addr));
                }
                Err(e) => {
                    debug!("Encrypted DH connection to server {ip}:{enc_port} failed: {e}, falling back to plain");
                    emit_server_log(
                        app,
                        &format!("Encrypted connection failed, trying plain TCP on port {port}..."),
                    );
                }
            }
        } else {
            info!("Obfuscation disabled and no obfuscation port for server {ip}:{port}, using plain TCP");
        }
    } else {
        info!("Skipping encryption (force_plain) for server {ip}:{port}");
    }
    let addr = tokio::net::lookup_host((ip, port))
        .await?
        .find(|addr| addr.is_ipv4())
        .ok_or_else(|| anyhow::anyhow!("No IPv4 address found for {ip}:{port}"))?;
    let conn = Ed2kServerConnection::connect(addr).await?;
    info!("Plain TCP connection to server {ip}:{port} established");
    emit_server_log(app, "TCP connection established");
    Ok((conn, addr))
}

/// Clear per-session eD2K identity and in-flight TCP search state. Does not
/// touch `udp_search_queue` (throttled global multi-server search) or the
/// connection fields.
pub(super) fn reset_ed2k_server_session(state: &mut NetworkState, app_handle: &tauri::AppHandle) {
    // No session means no server capabilities; leaving the mirror set would
    // have a related search keep planning around a co-share request that can no
    // longer be sent.
    ed2k::server::set_server_flags_mirror(0);
    state.server_poll_count = 0;
    state.server_search_more_due_at = None;
    state.server_search_more_requests = 0;
    // No session, no way to send it — and the flags mirror cleared above means
    // the next plan will not count on a co-share request either.
    state.server_followup_search = None;
    state.server_followup_due_at = None;
    state.low_id = false;
    state.server_client_id = 0;
    // A new connection (even to the same server) is a fresh session that
    // has no memory of any previous OP_OFFERFILES we sent — the dedup
    // signature in the `SharedFilesChanged` handler must not carry over,
    // or the first offer after reconnecting could be wrongly skipped as
    // "unchanged" when the new server session has never seen it.
    state.last_offer_files_signature = None;
    state.offered_ed2k_hashes.clear();
    // Asks for this server's sources; the next server's first sweep covers
    // every download anyway.
    state.server_tcp_srcreq_asks.clear();
    if let Some(mut pending) = state.pending_server_search.take() {
        let request_id = pending.request_id;
        if let Some(tx) = pending.tx.take() {
            let _ = tx.send(pending.results);
        }
        if let Some(active) = state.active_search_request.as_mut() {
            if active.request_id == request_id {
                active.server_pending = false;
            }
        }
        maybe_finish_active_search(state, app_handle, request_id);
    }
    if let Some(active) = state.active_search_request.as_mut() {
        let rid = active.request_id;
        let mut changed = false;
        if active.udp_pending {
            active.udp_pending = false;
            state.server_udp_search_age = 0;
            changed = true;
        }
        if active.server_pending {
            active.server_pending = false;
            changed = true;
        }
        if changed {
            maybe_finish_active_search(state, app_handle, rid);
        }
    }
}

pub(super) async fn handle_server_disconnect(
    state: &mut NetworkState,
    shared_server_addr: &Arc<RwLock<Option<SocketAddr>>>,
    app_handle: &tauri::AppHandle,
    reason: &str,
) {
    debug!("Server connection lost: {reason}");
    emit_server_log(app_handle, &format!("Server disconnected: {reason}"));
    if state.server_connected {
        let session_secs = state
            .server_logged_in_at
            .map_or(0, |at| i64::try_from(at.elapsed().as_secs()).unwrap_or(i64::MAX));
        state.server_reconnect_failures =
            reconnect_failures_after_session(state.server_reconnect_failures, session_secs);
        if session_secs < SHORT_SERVER_SESSION_SECS {
            state.server_last_connect_attempt = Some(std::time::Instant::now());
        }
    }
    if let Some(handle) = state.pending_server_connect.take() {
        handle.abort();
    }
    state.udp_search_queue.clear();
    state.server_connected = false;
    state.server_connection = None;
    state.server_addr = None;
    reset_ed2k_server_session(state, app_handle);
    *shared_server_addr.write().await = None;
    state.stats.server_status = "disconnected".to_string();
    let _ = app_handle.emit(
        "server-status-changed",
        serde_json::json!({ "status": "disconnected" }),
    );
    // Losing the server does not stop uploads, whether the user asked for it or
    // not. Serving needs the shared file and the TCP listener; a server only
    // relays callbacks for LowID peers, so a HighID node needs it for nothing at
    // all and a LowID one simply stops receiving callbacks.
    //
    // Two rules have been tried here and both stopped uploads that should have
    // kept running. Keying off `stats.status == Disconnected` meant KAD's status
    // decided the fate of eD2K uploads, so a server-only session lost every
    // upload on the first transient drop — the 120 s activity watchdog, a
    // server-side disconnect, a failed reconnect — and nothing cleared it again,
    // because only `initiate_server_connect` and `KadConnect` do. Keying off
    // `user_offline` then quietly undid the KAD-disconnect exemption instead:
    // `KadDisconnect` sets that flag and then calls this function to drop the
    // server itself, so the gate came straight back up and uploads stopped
    // anyway.
    //
    // eMule raises no such gate on any disconnect — see the note in
    // `NetworkCommand::KadDisconnect`. The upload listener now comes down for
    // shutdown alone.
}

/// Tear down an already-up eD2K session whose IP is now blocked.
///
/// First-launch merge admits servers while `!ranges_ready` so `server.met`
/// is not wiped. Auto-connect waits; a manual Connect in that window can
/// still be up when the parse finishes. `remove_filtered` drops the list
/// row — this drops the live TCP session too. No-op while fail-closed.
pub(super) async fn disconnect_connected_server_if_ip_filtered(
    state: &mut NetworkState,
    shared_server_addr: &Arc<RwLock<Option<SocketAddr>>>,
    app_handle: &tauri::AppHandle,
    filter_servers_by_ip: bool,
) {
    if !filter_servers_by_ip {
        return;
    }
    if state.ip_filter.is_enabled() && !state.ip_filter.ranges_ready() {
        return;
    }
    if !state.server_connected && state.server_connection.is_none() {
        return;
    }
    let Some(addr) = state.server_addr else {
        return;
    };
    let ipv4 = match addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4,
            None => return,
        },
    };
    if !state.ip_filter.is_blocked(ipv4) {
        return;
    }
    let ip = ipv4.to_string();
    let port = addr.port();
    warn!("Server {ip}:{port} blocked by IP filter, disconnecting");
    emit_server_log(
        app_handle,
        &format!("Server {ip}:{port} blocked by IP filter"),
    );
    handle_server_disconnect(
        state,
        shared_server_addr,
        app_handle,
        "blocked by IP filter",
    )
    .await;
    if state.server_auto_reconnect {
        abandon_server_auto_reconnect(
            state,
            app_handle,
            &format!("preferred server {ip}:{port} blocked by IP filter"),
        );
    }
}

/// Drop blocked servers from `server.met` and disconnect if the live
/// session is now in the list. Safe to call after any range load/reload.
pub(super) async fn apply_server_ip_filter(
    state: &mut NetworkState,
    shared_server_addr: &Arc<RwLock<Option<SocketAddr>>>,
    app_handle: &tauri::AppHandle,
    filter_servers_by_ip: bool,
) {
    if !filter_servers_by_ip {
        return;
    }
    let removed = state.server_list.remove_filtered(&mut state.ip_filter);
    if removed > 0 {
        let met_path = state.data_dir.join("server.met");
        spawn_save_server_met(
            &state.server_list,
            met_path,
            &state.server_met_save_generation,
            &state.server_met_save_lock,
        );
        info!("Removed {removed} IP-filtered servers from server list");
    }
    disconnect_connected_server_if_ip_filtered(
        state,
        shared_server_addr,
        app_handle,
        filter_servers_by_ip,
    )
    .await;
}

/// Max preferred-server connect failures before auto-reconnect stops and the
/// UI is told to connect manually. Covers boot auto-connect and mid-session
/// drop recovery for the same host only.
pub(super) const AUTO_CONNECT_MAX_FAILURES: u32 = 3;

/// A server session that ends sooner than this after login counts toward
/// `AUTO_CONNECT_MAX_FAILURES` (see `handle_server_disconnect`).
const SHORT_SERVER_SESSION_SECS: i64 = 120;

/// The reconnect failure count once a session of `session_secs` has ended.
///
/// A login that is dropped soon after it succeeds is another failed attempt,
/// and only a session that outlasts `SHORT_SERVER_SESSION_SECS` clears the
/// count. Login itself must not: a server that accepts us and then kicks us
/// (flood protection, a ban notice) would otherwise take the count 0→1→0
/// forever, be redialed every few seconds, and see the whole post-login burst
/// each time — the pattern servers blacklist.
fn reconnect_failures_after_session(failures: u32, session_secs: i64) -> u32 {
    if session_secs < SHORT_SERVER_SESSION_SECS {
        failures.saturating_add(1)
    } else {
        0
    }
}

/// Wait before auto-reconnecting to the preferred server after `failures`
/// consecutive failed attempts.
pub(super) fn server_reconnect_backoff_secs(failures: u32) -> u64 {
    match failures {
        0 => 0,
        1 => 3,
        2 => 5,
        3 => 10,
        4 => 20,
        _ => 30,
    }
}

pub(super) fn emit_server_auto_connect_failed(app_handle: &tauri::AppHandle, detail: &str) {
    warn!("eD2K auto-connect abandoned: {detail}");
    emit_server_log(
        app_handle,
        &format!("Auto-connect failed ({detail}). Please connect to a server manually."),
    );
    let _ = app_handle.emit(
        "server-auto-connect-failed",
        serde_json::json!({ "detail": detail }),
    );
}

pub(super) fn abandon_server_auto_reconnect(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    detail: &str,
) {
    state.server_auto_reconnect = false;
    emit_server_auto_connect_failed(app_handle, detail);
}

/// Capture the TCP port for `OP_LOGINREQUEST`, then run session teardown.
/// `reset_ed2k_server_session` clears `low_id`; the capture must happen first.
pub(super) fn capture_advertised_tcp_port_then_reset_ed2k_session(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
) -> u16 {
    let tcp_port = capture_advertised_tcp_port_then_reset_low_id(
        state.upnp_tcp_port,
        state.external_tcp_port,
        state.tcp_port,
        &mut state.low_id,
    );
    reset_ed2k_server_session(state, app_handle);
    tcp_port
}

/// Establish a new eD2K server connection to `ip`:`port`, tearing down any
/// existing connection/pending attempt first. Shared by
/// `NetworkCommand::ConnectToServer` (Servers page) and
/// `start_network`'s boot path when `settings.auto_connect_server` is set.
/// KAD Connect does **not** call this — eD2K is opt-in via the Servers page
/// (or the startup auto-connect setting).
///
/// Auto-reconnect (after drop / failed attempt) retries **only** this same
/// preferred server — it never walks the rest of the server list.
pub(super) async fn initiate_server_connect(
    state: &mut NetworkState,
    settings: &AppSettings,
    app_handle: &tauri::AppHandle,
    shared_server_addr: &Arc<RwLock<Option<SocketAddr>>>,
    ip: String,
    port: u16,
) {
    state.server_auto_reconnect = true;
    state.server_reconnect_failures = 0;
    state.preferred_ed2k_server = Some((ip.clone(), port));
    // Joining a server is a deliberate "come back online", so it lifts the
    // outbound stop the same way `KadConnect` does. The upload listener needs
    // nothing here — it was never taken down. It used to be, which is what made
    // joining a server after disconnecting KAD reject the server's own HighID
    // TCP port-test and stick the node on LowID.
    state
        .user_offline
        .store(false, std::sync::atomic::Ordering::Relaxed);
    // Explicit Connect should be allowed to retry a server that recently
    // failed auto-reconnect — keep fail counts for sort preference.
    state.server_list.clear_connect_cooldowns();
    if let Some(handle) = state.pending_server_connect.take() {
        handle.abort();
    }
    let tcp_port = if let Some(conn) = state.server_connection.take() {
        emit_server_log(app_handle, "Disconnecting from current server...");
        drop(conn);
        state.server_connected = false;
        state.server_addr = None;
        *shared_server_addr.write().await = None;
        state.stats.server_status = "disconnected".to_string();
        let tcp_port = capture_advertised_tcp_port_then_reset_ed2k_session(state, app_handle);
        let _ = app_handle.emit(
            "server-status-changed",
            serde_json::json!({ "status": "disconnected" }),
        );
        tcp_port
    } else {
        advertised_tcp_port(state)
    };
    let user_hash = state.user_hash;
    let nickname = settings.nickname.clone();
    let obf_port = state
        .server_list
        .servers()
        .iter()
        .find(|s| s.ip == ip && s.port == port)
        .map(|s| s.obfuscation_port_tcp)
        .unwrap_or(0);
    let obfuscation_enabled = state.obfuscation_enabled;
    let ip_clone = ip.clone();
    let app_for_connect = app_handle.clone();
    // Pre-set server addr so upload handler can detect HighID port test callbacks
    if let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() {
        *shared_server_addr.write().await = Some(SocketAddr::new(ip_addr, port));
    }
    info!("Connecting to ed2k server {ip}:{port} (background)...");
    emit_server_log(app_handle, &format!("Connecting to {ip}:{port}..."));
    state.stats.server_status = "connecting".to_string();
    let _ = app_handle.emit(
        "server-status-changed",
        serde_json::json!({ "status": "connecting" }),
    );
    state.pending_server_connect = Some(tokio::spawn(async move {
        // One crypt→plain cycle per server. Prefer failing fast on a dead
        // preferred host so auto-reconnect can retry with backoff, then stop
        // after AUTO_CONNECT_MAX_FAILURES instead of walking the server list.
        let result = async {
            let (mut conn, resolved_addr) = try_connect_server(
                &ip_clone,
                port,
                obf_port,
                &app_for_connect,
                false,
                obfuscation_enabled,
            )
            .await
            .map_err(|e| format!("Connect failed: {e}"))?;
            emit_server_log(
                &app_for_connect,
                &format!("Sending login request (client TCP port {tcp_port})..."),
            );
            match conn.login(&user_hash, &nickname, tcp_port).await {
                Ok(session) => Ok((conn, session, resolved_addr)),
                Err(login_err) if conn.is_encrypted() => {
                    debug!("Encrypted login to {ip_clone}:{port} failed: {login_err}, falling back to plain TCP");
                    emit_server_log(
                        &app_for_connect,
                        &format!("Encrypted login failed ({login_err}), trying plain TCP..."),
                    );
                    drop(conn);
                    let plain_addr = tokio::net::lookup_host((ip_clone.as_str(), port))
                        .await
                        .map_err(|e| format!("Plain fallback resolve failed: {e}"))?
                        .find(|addr| addr.is_ipv4())
                        .ok_or_else(|| {
                            format!("No IPv4 address for plain fallback {ip_clone}:{port}")
                        })?;
                    let mut plain_conn = Ed2kServerConnection::connect(plain_addr)
                        .await
                        .map_err(|e| format!("Plain fallback connect failed: {e}"))?;
                    emit_server_log(
                        &app_for_connect,
                        &format!("Sending login over plain TCP (port {tcp_port})..."),
                    );
                    match plain_conn.login(&user_hash, &nickname, tcp_port).await {
                        Ok(session) => Ok((plain_conn, session, plain_addr)),
                        Err(e) => Err(format!("Plain TCP login failed: {e}")),
                    }
                }
                Err(e) => Err(format!("Login failed: {e}")),
            }
        }
        .await;
        let addr = result
            .as_ref()
            .ok()
            .map(|(_, _, resolved_addr)| *resolved_addr)
            .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
        ServerConnectResult {
            addr,
            ip,
            port,
            login_tcp_port: tcp_port,
            result: result.map(|(conn, session, _)| (conn, session)),
        }
    }));
}

pub(super) fn server_entry_to_info(server: &ServerEntry) -> ServerInfo {
    ServerInfo {
        ip: server.ip.clone(),
        port: server.port,
        name: server.name.clone(),
        description: server.description.clone(),
        user_count: server.user_count,
        file_count: server.file_count,
        max_users: server.max_users,
        soft_files: server.soft_files,
        hard_files: server.hard_files,
        is_static: server.is_static,
        priority: server.priority.as_str().to_string(),
        fail_count: server.fail_count,
        client_id: 0,
        is_low_id: false,
    }
}

pub(super) fn connected_server_info(state: &NetworkState) -> Option<ServerInfo> {
    let session = &state.server_connection.as_ref()?.session;
    let addr = state.server_addr?;
    // The live session carries the user/file counts but not the capacity
    // limits — those come from `server.met` (ST_MAXUSERS / ST_SOFTFILES /
    // ST_HARDFILES) or an extended UDP status reply. Zeroing them here meant
    // the server the user is actually on was the one row that could never show
    // its limits, which is backwards. Borrow them from the list entry.
    let ip = addr.ip().to_string();
    let limits = state.server_list.find_by_addr(&ip, addr.port());
    Some(ServerInfo {
        ip,
        port: addr.port(),
        name: session.server_name.clone(),
        description: limits.map(|s| s.description.clone()).unwrap_or_default(),
        user_count: session.user_count,
        file_count: session.file_count,
        max_users: limits.map(|s| s.max_users).unwrap_or(0),
        soft_files: limits.map(|s| s.soft_files).unwrap_or(0),
        hard_files: limits.map(|s| s.hard_files).unwrap_or(0),
        is_static: limits.is_some_and(|s| s.is_static),
        priority: limits
            .map(|s| s.priority)
            .unwrap_or(crate::network::ed2k::server_list::ServerPriority::Normal)
            .as_str()
            .to_string(),
        fail_count: 0,
        client_id: state.server_client_id,
        is_low_id: state.low_id,
    })
}

#[cfg(test)]
mod reconnect_backoff_tests {
    use super::*;

    /// A server that accepts the login and kicks us 20 s later: each redial
    /// has to wait longer than the last, and auto-reconnect gives up after
    /// `AUTO_CONNECT_MAX_FAILURES` of them instead of redialing forever.
    #[test]
    fn repeated_short_sessions_back_off_and_then_stop() {
        let mut failures = 0;
        let mut last_backoff = server_reconnect_backoff_secs(failures);
        for expected in 1..=AUTO_CONNECT_MAX_FAILURES {
            failures = reconnect_failures_after_session(failures, 20);
            assert_eq!(failures, expected);
            let backoff = server_reconnect_backoff_secs(failures);
            assert!(backoff > last_backoff, "backoff must grow: {backoff} after {last_backoff}");
            last_backoff = backoff;
        }
        assert!(failures >= AUTO_CONNECT_MAX_FAILURES);
    }

    #[test]
    fn only_a_session_that_lasts_clears_the_count() {
        assert_eq!(
            reconnect_failures_after_session(2, SHORT_SERVER_SESSION_SECS - 1),
            3
        );
        assert_eq!(reconnect_failures_after_session(2, SHORT_SERVER_SESSION_SECS), 0);
    }
}
