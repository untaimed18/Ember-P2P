//! Finishing a background eD2K server connection: the IP-filter check, login
//! bookkeeping, HighID and firewall status, and the requests sent right after
//! login; or recording why the connection failed.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_server_connect_result(
    result: Result<ServerConnectResult, tokio::task::JoinError>,
    udp_socket: &Arc<UdpSocket>,
    state: &mut NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    settings: &AppSettings,
    app_handle: &tauri::AppHandle,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    known_files: &KnownFileList,
    shared_server_addr: &Arc<RwLock<Option<SocketAddr>>>,
    last_server_activity_at: &mut i64,
    nat_probe_in_flight: &mut bool,
    nat_probe_packet_tx: &mut Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>,
    nat_probe_result_tx: &mpsc::UnboundedSender<NatProbeResult>,
    nat_probe_started_at: &mut Option<tokio::time::Instant>,
    next_offer_packet_at: &mut Option<tokio::time::Instant>,
    pending_lowid_callback_queue: &mut VecDeque<([u8; 16], u32)>,
    pending_offer_files: &mut Option<Vec<ed2k::server::OfferFile>>,
    pending_offer_signature: &mut Option<(usize, u64)>,
    server_tcp_source_timer: &mut tokio::time::Interval,
) {
    state.pending_server_connect = None;
    match result {
        Ok(ServerConnectResult { addr, ip, port, login_tcp_port, result: Ok((conn, session)) }) => {
            // Check server IP against IP filter (eMule: FilterServerByIP)
            if settings.filter_servers_by_ip {
                let server_ipv4 = match addr.ip() {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
                };
                if let Some(ipv4) = server_ipv4 {
                    let skip_fail_closed = state.ip_filter.is_enabled()
                        && !state.ip_filter.ranges_ready();
                    if !skip_fail_closed && state.ip_filter.is_blocked(ipv4) {
                        warn!("Server {ip}:{port} blocked by IP filter, disconnecting");
                        emit_server_log(app_handle, &format!("Server {ip}:{port} blocked by IP filter"));
                        drop(conn);
                        state.server_list.record_failure(&ip, port);
                        let met_path = state.data_dir.join("server.met");
                        spawn_save_server_met(&state.server_list, met_path, &state.server_met_save_generation, &state.server_met_save_lock);
                        *shared_server_addr.write().await = None;
                        state.server_reconnect_failures =
                            state.server_reconnect_failures.saturating_add(1);
                        state.stats.server_status = "disconnected".to_string();
                        let _ = app_handle.emit("server-status-changed", serde_json::json!({ "status": "disconnected" }));
                        if state.server_auto_reconnect
                            && state.server_reconnect_failures >= AUTO_CONNECT_MAX_FAILURES
                        {
                            abandon_server_auto_reconnect(
                                state,
                                app_handle,
                                &format!("preferred server {ip}:{port} blocked by IP filter"),
                            );
                        }
                        return;
                    }
                }
            }

            for motd in &session.motd_messages {
                emit_server_log(app_handle, &format!("Server: {motd}"));
            }

            let mut conn = conn.into_link(session.clone());
            let is_low = conn.is_low_id();
            let our_id = conn.our_client_id();
            let id_type = if is_low { "LowID" } else { "HighID" };
            info!("Connected to ed2k server: {} ({} users, {} files, {} id={})",
                session.server_name, session.user_count, session.file_count,
                id_type, our_id);
            emit_server_log(app_handle, &format!(
                "Connected to {} ({} users, {} files, {})",
                if session.server_name.is_empty() { &ip } else { &session.server_name },
                session.user_count, session.file_count, id_type,
            ));
            state.low_id = is_low;
            state.server_client_id = session.client_id;
            state.server_login_tcp_port = Some(login_tcp_port);
            state.server_list.record_success(&ip, port);
            state.server_connected = true;
            ed2k::server::set_server_flags_mirror(session.server_flags);
            // `server_reconnect_failures` is deliberately left alone: only a
            // session that lasts clears it (`handle_server_disconnect`).
            state.preferred_ed2k_server = Some((ip.clone(), port));
            {
                let last = ed2k::server_list::LastEd2kServer {
                    ip: ip.clone(),
                    port,
                    name: session.server_name.clone(),
                };
                let last_path = state.data_dir.join("last_ed2k_server.json");
                if let Err(e) = last.save(&last_path) {
                    warn!("Failed to persist last eD2K server: {e}");
                }
            }
            *last_server_activity_at = chrono::Utc::now().timestamp();
            state.server_logged_in_at = Some(std::time::Instant::now());
            state.server_addr = Some(addr);
            *shared_server_addr.write().await = Some(addr);

            // Cap OP_OFFERFILES at this server's soft per-client file
            // limit, the way eMule's SendListToServer does. Looked up
            // from the server-list metadata (ST_SOFTFILES); 0 => the
            // 200-file default. Set before the post-login offer below.
            let server_soft_files = state.server_list.servers().iter()
                .find(|s| s.ip == ip && s.port == port)
                .map(|s| s.soft_files)
                .unwrap_or(0);
            conn.set_soft_files(server_soft_files);

            // HighID from server is the most reliable TCP firewall test:
            // the server successfully connected back to our TCP port.
            // Always update tcp_status — even when UPnP already cleared
            // `state.firewalled` — otherwise the UI stays on Unknown
            // until a later KAD probe cycle.
            if !is_low && our_id >= ed2k::server::LOWID_THRESHOLD {
                if state.firewalled {
                    info!("HighID from server confirms TCP port is open, clearing firewalled status");
                    state.firewalled = false;
                    state.firewalled_shared.store(false, std::sync::atomic::Ordering::Relaxed);
                    if state.buddy_manager.state() == BuddyState::FindingBuddy {
                        state.buddy_manager.find_failed();
                        info!("Cancelled buddy search: HighID proves TCP is open");
                    }
                } else if state.firewall_checker.tcp_status()
                    != crate::network::kad::firewall::FirewallStatus::Open
                {
                    info!("HighID from server confirms TCP port is open (updating tcp_status)");
                }
                // TCP Open must be recorded *before* we refresh the
                // publish manager. `kad_source_publish_treat_as_firewalled`
                // treats Unknown as firewalled, so an update here used
                // to leave source publishes skipped (no buddy, no type-6)
                // until a later unrelated refresh.
                state.firewall_checker.handle_tcp_connect_back();
                kad::firewall::publish_local_firewall(
                    state.firewalled,
                    state.udp_firewalled,
                );
                update_publish_manager_state(state);
                state.stats.firewalled = state.firewalled;
                state.stats.tcp_status = format!("{:?}", state.firewall_checker.tcp_status());
                state.stats.udp_status = format!("{:?}", state.firewall_checker.udp_status());
                let _ = app_handle.emit("firewall-status", serde_json::json!({
                    "firewalled": state.firewalled,
                    "external_ip": state.stats.external_ip,
                    "tcp_status": state.stats.tcp_status,
                    "udp_status": state.stats.udp_status,
                }));
                // HighID = our external IP (ed2k stores IPs as LE u32)
                let ip_bytes = our_id.to_le_bytes();
                let ext_ip = Ipv4Addr::from(ip_bytes);
                info!("Server HighID reports our IP as {}", ext_ip);
                if !crate::security::is_bogus_v4(ext_ip) {
                    let was_none = state.external_ip.is_none();
                    if state.external_ip != Some(ext_ip) {
                        info!(
                            "External IP set from server HighID: {} (was {:?})",
                            ext_ip, state.external_ip
                        );
                    }
                    set_external_ip(state, Some(ext_ip));
                    state.stats.external_ip = ext_ip.to_string();
                    // Server HighID is a single trusted report; route it
                    // through the dedicated 1-arg path rather than the
                    // KAD-peer-vote path (which requires a reporter IP
                    // for distinct-/24 sybil protection).
                    state.firewall_checker.handle_server_highid_response(ext_ip);
                    if was_none && state.nat_info.nat_type == ember::nat::NatType::Unknown {
                        if !*nat_probe_in_flight {
                            info!("External IP discovered via server HighID — scheduling initial NAT probe");
                            *nat_probe_in_flight = true;
                            *nat_probe_started_at = Some(tokio::time::Instant::now());
                            state.nat_probe_generation =
                                state.nat_probe_generation.saturating_add(1);
                            *nat_probe_packet_tx = Some(spawn_nat_probe(
                                udp_socket.clone(),
                                nat_probe_result_tx.clone(),
                                state.nat_probe_generation,
                                "server HighID",
                            ));
                        }
                    }
                }
            } else if is_low {
                // LowID: server could not connect back — TCP is firewalled.
                state.firewalled = true;
                state.firewalled_shared.store(true, std::sync::atomic::Ordering::Relaxed);
                state.firewall_checker.note_tcp_firewalled();
                // Hello's `supports_direct_udp_callback` reads a
                // process atomic, not `state`. Without this a
                // session that was HighID earlier keeps advertising
                // "no UDP callback" while LowID, so peers that
                // cannot dial our TCP port drop us instead of
                // calling back over UDP.
                kad::firewall::note_local_tcp_firewalled(true);
                update_publish_manager_state(state);
                state.stats.firewalled = true;
                state.stats.tcp_status = format!("{:?}", state.firewall_checker.tcp_status());
                state.stats.udp_status = format!("{:?}", state.firewall_checker.udp_status());
                let _ = app_handle.emit("firewall-status", serde_json::json!({
                    "firewalled": state.firewalled,
                    "external_ip": state.stats.external_ip,
                    "tcp_status": state.stats.tcp_status,
                    "udp_status": state.stats.udp_status,
                }));
                if session.server_reported_ip != 0 {
                    // eMule ServerSocket OP_IDCHANGE: for a LowID client the
                    // server reports our real public IP at offset 12 —
                    // `if (IsLowID(clientid) && dwServerReportedIP != 0)
                    // SetPublicIP(dwServerReportedIP)`. LowID keeps us
                    // firewalled, so unlike the HighID branch we do NOT touch
                    // firewalled status here beyond note_tcp_firewalled above;
                    // this only teaches us our external IP.
                    let ext_ip = Ipv4Addr::from(session.server_reported_ip.to_le_bytes());
                    if !crate::security::is_special_use_v4(ext_ip)
                        && state.external_ip.is_none()
                    {
                        set_external_ip(state, Some(ext_ip));
                        state.stats.external_ip = ext_ip.to_string();
                        info!("External IP set from server LowID report");
                        // Trusted single-reporter path, same as the HighID
                        // case above (records the confirmed external IP
                        // without the KAD distinct-/24 vote requirement).
                        state.firewall_checker.handle_server_highid_response(ext_ip);
                    }
                }
            }

            // eMule: "Update server list when connecting" —
            // process OP_SERVERLIST payload received during login handshake.
            // Some servers push it unsolicited (handled here); most modern
            // servers wait for an explicit OP_GETSERVERLIST request from
            // the client (sent below). Either way the response opcode is
            // the same OP_SERVERLIST and arrives via the regular
            // `ServerEvent::ServerList` branch in the read loop.
            if settings.add_servers_from_server {
                if let Some(ref list_data) = session.server_list_data {
                    let added = state.server_list.add_from_server_list_packet(
                        list_data,
                        settings.filter_servers_by_ip,
                        &mut state.ip_filter,
                    );
                    if added > 0 {
                        emit_server_log(app_handle, &format!("Added {added} servers from connected server"));
                        let met_path = state.data_dir.join("server.met");
                        spawn_save_server_met(&state.server_list, met_path, &state.server_met_save_generation, &state.server_met_save_lock);
                    }
                }
                // Explicitly request the server list. eMule's "Update
                // server list when connecting" sends OP_GETSERVERLIST
                // shortly after login because most public ed2k servers
                // don't push the list unsolicited — they wait for the
                // client to ask. Without this our `add_servers_from_server`
                // setting was effectively dead for the common case.
                if let Err(e) = conn.request_server_list() {
                    debug!("Failed to send OP_GETSERVERLIST: {e}");
                }
            }

            // Queue OP_OFFERFILES for chunked drain on later turns so
            // firewall/server status events and GetNetworkStats can
            // flush to the UI before a potentially large offer.
            {
                let mut seen_offer_hashes = std::collections::HashSet::new();
                let (mut offer_files, restricted) = {
                    let index = local_index.read().await;
                    let restricted = collect_friends_only_hashes(&index, known_files);
                    let offer_files: Vec<ed2k::server::OfferFile> = index
                        .all_files()
                        .iter()
                        .filter(|f| {
                            kad_may_advertise_complete(f, known_files, &restricted)
                        })
                        .filter_map(|f| {
                            let hash_bytes = hex::decode(&f.hash).ok()?;
                            if hash_bytes.len() < 16 {
                                return None;
                            }
                            if !seen_offer_hashes.insert(f.hash.clone()) {
                                return None;
                            }
                            let mut h = [0u8; 16];
                            h.copy_from_slice(&hash_bytes[..16]);
                            Some(ed2k::server::OfferFile {
                                hash: h,
                                name: f.name.clone(),
                                size: f.size,
                                is_complete: true,
                                file_type: ed2k::server::offer_file_type(&f.name),
                            })
                        })
                        .collect();
                    (offer_files, restricted)
                };
                offer_files.extend(
                    super::offer_files::partial_download_offers(
                        transfer_manager,
                        settings,
                        known_files,
                        &restricted,
                        &mut seen_offer_hashes,
                    )
                    .await,
                );
                // This TCP session has never published to this server.
                // Leftover hashes from a disconnect that skipped
                // `reset_ed2k_server_session` would make incremental skip the
                // opening dump entirely, and the last session's packet pacing,
                // which that reset cannot reach, would hold back this
                // session's first offer by up to a minute, including one that
                // comes later because the login had nothing to offer yet.
                state.offered_ed2k_hashes.clear();
                *next_offer_packet_at = None;
                if offer_files.is_empty() {
                    warn!("No files to offer to server after login — check shared folders");
                    *pending_offer_files = None;
                    *pending_offer_signature = None;
                } else {
                    let limit = conn.offer_files_chunk_limit();
                    let signature = offer_files_signature(&offer_files);
                    let incremental =
                        incremental_ed2k_offers(offer_files, &state.offered_ed2k_hashes);
                    info!(
                        "Queuing {} files to offer to server ({limit} per packet)",
                        incremental.len()
                    );
                    *pending_offer_signature = Some(signature);
                    *pending_offer_files = if incremental.is_empty() {
                        state.last_offer_files_signature = Some(signature);
                        None
                    } else {
                        Some(incremental)
                    };
                }
            }

            // eMule: request sources for incomplete downloads after
            // server login — but NOT in the same instant we receive
            // OP_IDCHANGE. The server is still streaming its welcome
            // (OP_SERVERSTATUS / message / list / ident) for the next
            // ~1-2s, and bursting OP_GETSOURCES into that window
            // (login batch + warm-start + starved re-ask all at once)
            // is both premature and trips Lugdunum flood protection,
            // which then silently drops source requests. Instead, let
            // the connection settle: fast-forward the periodic TCP
            // source timer to fire just after `SERVER_SOURCE_SETTLE_SECS`
            // so the first OP_GETSOURCES batch goes out once the server
            // is ready (it already covers every pending + active
            // download). The on-demand warm-start / starved-re-ask
            // paths below are likewise gated on `server_logged_in_at`.
            state.server_tcp_getsources_cursor = 0;
            // A new connection carries no spent credit, so the first
            // frame may go out as soon as the welcome has settled.
            state.server_tcp_srcreq_next_at = None;
            server_tcp_source_timer.reset_after(std::time::Duration::from_secs(
                SERVER_SOURCE_SETTLE_SECS as u64,
            ));

            state.server_connection = Some(conn);
            state.stats.server_status = "connected".to_string();
            let _ = app_handle.emit("server-status-changed", serde_json::json!({ "status": "connected" }));

            // Whatever is still queued was addressed to the previous
            // session: a LowID client id only means something to the server
            // that issued it, and a write-failure disconnect leaves the
            // drain's unsent tail behind.
            pending_lowid_callback_queue.clear();

            // L-2: flush LowID callback requests for any
            // sources we previously learned about via UDP
            // from this server. Without this, UDP-discovered
            // LowID sources from a server we *weren't* TCP-
            // connected to at discovery time would sit in
            // source manager unreachable forever — eMule
            // protocol requires the callback to go through
            // the source's originating server.
            if !is_low {
                let server_ip_u32 = match addr.ip() {
                    std::net::IpAddr::V4(v4) => u32::from_le_bytes(v4.octets()),
                    _ => 0,
                };
                let server_port_u16 = addr.port();
                if server_ip_u32 != 0 {
                    let pending: Vec<([u8; 16], u32)> = {
                        let sm = source_manager.read().await;
                        sm.get_lowid_sources_for_server(
                            server_ip_u32,
                            server_port_u16,
                            ed2k::dead_sources::FILEREASKTIME_SECS,
                        )
                    };
                    if !pending.is_empty() {
                        // Queue for rate-limited drain (MAX_LOWID_CALLBACKS_PER_TURN)
                        // so login cannot monopolize the loop with N sequential awaits.
                        let n = queue_lowid_callbacks(
                            pending_lowid_callback_queue,
                            pending,
                        );
                        if n > 0 {
                            info!(
                                "L-2 flush: queued {n} LowID callbacks via newly-connected server {}:{}",
                                addr.ip(), server_port_u16,
                            );
                        }
                    }
                }
            }
        }
        Ok(ServerConnectResult { ip, port, result: Err(e), .. }) => {
            info!("Failed to connect to server {ip}:{port}: {e}");
            let attempt = state.server_reconnect_failures.saturating_add(1);
            let will_retry = state.server_auto_reconnect
                && state.preferred_ed2k_server.as_ref().is_some_and(|(pip, pport)| {
                    pip == &ip && *pport == port
                })
                && attempt < AUTO_CONNECT_MAX_FAILURES;
            if will_retry {
                emit_server_log(
                    app_handle,
                    &format!(
                        "Connection failed ({e}); retrying preferred server ({attempt}/{AUTO_CONNECT_MAX_FAILURES})..."
                    ),
                );
            } else {
                emit_server_log(
                    app_handle,
                    &format!("Connection failed ({e})."),
                );
            }
            state.server_reconnect_failures = attempt;
            *shared_server_addr.write().await = None;
            state.server_list.record_failure(&ip, port);
            let met_path = state.data_dir.join("server.met");
            spawn_save_server_met(&state.server_list, met_path, &state.server_met_save_generation, &state.server_met_save_lock);
            state.stats.server_status = "disconnected".to_string();
            let _ = app_handle.emit("server-status-changed", serde_json::json!({ "status": "disconnected" }));
            if state.server_auto_reconnect && attempt >= AUTO_CONNECT_MAX_FAILURES {
                abandon_server_auto_reconnect(
                    state,
                    app_handle,
                    &format!("could not reach preferred server {ip}:{port}"),
                );
            }
            // Keep `server_last_connect_attempt` so reconnect backoff
            // still applies when retrying the same preferred host.
        }
        Err(e) => {
            warn!("Server connection task panicked: {e}");
            emit_server_log(app_handle, &format!("Connection error: {e}"));
            state.server_reconnect_failures =
                state.server_reconnect_failures.saturating_add(1);
            *shared_server_addr.write().await = None;
            state.stats.server_status = "disconnected".to_string();
            let _ = app_handle.emit("server-status-changed", serde_json::json!({ "status": "disconnected" }));
            if state.server_auto_reconnect
                && state.server_reconnect_failures >= AUTO_CONNECT_MAX_FAILURES
            {
                let detail = state
                    .preferred_ed2k_server
                    .as_ref()
                    .map(|(ip, port)| format!("could not reach preferred server {ip}:{port}"))
                    .unwrap_or_else(|| "server connection task failed".to_string());
                abandon_server_auto_reconnect(state, app_handle, &detail);
            }
        }
    }
}
