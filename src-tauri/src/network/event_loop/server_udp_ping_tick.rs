//! The server UDP tick: pings known eD2K servers in turn and handles their UDP
//! replies (status responses, found sources, and global search results).

use super::*;
use crate::network::ed2k::server_udp::ServerUdpRecv;

/// Datagrams read per 200 ms tick, so a flood cannot hold the network loop.
const MAX_SERVER_UDP_PACKETS_PER_TICK: usize = 32;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_server_udp_ping_tick(
    state: &mut NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    settings: &AppSettings,
    dl_event_tx: &mpsc::Sender<DownloadEvent>,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
    app_handle: &tauri::AppHandle,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    credit_manager: &Arc<RwLock<CreditManager>>,
    stats_manager: &mut StatsManager,
    server_udp: &mut ServerUdpSocket,
    shared_banned_ips: &upload_server::SharedBannedIps,
    shared_ember_payload: &ember::SharedEmberPayload,
    ember_payload_generation: &ember::EmberPayloadGeneration,
    geoip: &crate::geoip::GeoIpReader,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    ember_hash: [u8; 16],
    ed25519_pubkey: [u8; 32],
    ed25519_secret_key: [u8; 32],
    comment_manager: &Arc<RwLock<CommentManager>>,
    pending_lowid_callback_queue: &mut VecDeque<([u8; 16], u32)>,
    server_udp_ping_idx: &mut usize,
    spam_filter: &Arc<RwLock<crate::search::spam::SpamFilter>>,
) {
    let server_count = state.server_list.len();
    if server_count > 0 {
        let idx = *server_udp_ping_idx % server_count;
        *server_udp_ping_idx = server_udp_ping_idx.wrapping_add(1);
        let server = state.server_list.servers()[idx].clone();
        let now = crate::network::monotonic_secs();
        match server_udp.send_status_ping(&server, now).await {
            Ok(bytes) if bytes > 0 => {
                state
                    .server_list
                    .record_udp_ping_sent(&server.ip, server.port, now);
                stats_manager.add_overhead(
                    crate::storage::statistics::OverheadCategory::Server,
                    crate::storage::statistics::OverheadDirection::Upload,
                    bytes as u64,
                );
            }
            Ok(_) => {}
            Err(e) => {
                debug!(
                    "Server UDP ping to {}:{} failed: {e}",
                    server.ip, server.port
                );
            }
        }
    }
    for _ in 0..MAX_SERVER_UDP_PACKETS_PER_TICK {
        // Snapshot the server list reference so the
        // closure (called possibly multiple times by
        // `try_recv_with`) can do per-server lookups
        // without borrowing `state` mutably across the
        // await. Returns `(base_key, tcp_port)`: the
        // first lets us decrypt obfuscated replies, the
        // second lets `try_recv_with` canonicalise the
        // emitted `addr` so downstream handlers'
        // `addr.port() - 4 == tcp_port` math works
        // regardless of whether the reply came from the
        // standard UDP port or the server's
        // `obfuscation_port_udp`.
        let server_list = &state.server_list;
        let (recv_len, resp) = match server_udp.try_recv_with(move |ip, port| {
            server_list.lookup_for_udp_addr(ip, port)
        }).await {
            ServerUdpRecv::Packet(recv_len, resp) => (recv_len, resp),
            ServerUdpRecv::Skipped => continue,
            ServerUdpRecv::Drained => break,
        };
        // Attribute the actual wire bytes to the correct
        // category. Previously every response paid a flat
        // 64-byte "Server" charge AND `FoundSources`
        // additionally paid `sources*10` "SourceExchange",
        // so the same reply was double-counted under two
        // categories — and the `SourceExchange` estimate
        // missed the packet header and per-source overhead.
        let recv_bytes = recv_len as u64;
        let category = match &resp {
            ServerUdpResponse::FoundSources { .. } =>
                crate::storage::statistics::OverheadCategory::SourceExchange,
            // Status pings and global search results are
            // server-control traffic, not source-discovery.
            ServerUdpResponse::StatusResponse { .. }
            | ServerUdpResponse::SearchResult { .. } =>
                crate::storage::statistics::OverheadCategory::Server,
        };
        stats_manager.add_overhead(
            category,
            crate::storage::statistics::OverheadDirection::Download,
            recv_bytes,
        );
        // Reset the per-server UDP-failure counter on
        // any inbound reply (status, sources, or search).
        // The address is already canonicalised to the
        // standard TCP+4 port by `try_recv_with`, so the
        // server-list lookup uses `addr.port() - 4` for
        // the matching TCP port.
        {
            let resp_addr = match &resp {
                ServerUdpResponse::StatusResponse { addr, .. } => Some(*addr),
                // FoundSources is recorded only after endpoint +
                // recent-query correlation in its handler below.
                ServerUdpResponse::FoundSources { .. } => None,
                // Search replies are recorded only after the
                // sent-IP allowlist check below (eMule
                // ProcessUDPSearchAnswer).
                ServerUdpResponse::SearchResult { .. } => None,
            };
            if let Some(a) = resp_addr {
                let ip_str = a.ip().to_string();
                let tcp_port = a.port().saturating_sub(4);
                state.server_list.record_udp_reply(&ip_str, tcp_port);
            }
        }
        match resp {
            ServerUdpResponse::StatusResponse { addr, challenge, user_count, file_count, max_users, soft_files, hard_files, obfuscation_port_tcp, obfuscation_port_udp, udp_flags, server_udp_key } => {
                // eMule: verify challenge to prevent spoofed status responses
                let expected = server_udp.take_challenge(&addr);
                if expected != Some(challenge) {
                    debug!("Ignoring UDP status from {addr}: challenge mismatch or unexpected");
                } else {
                    let tcp_port = addr.port().saturating_sub(4);
                    state.server_list.update_server_stats(
                        &addr.ip().to_string(), tcp_port, user_count, file_count, obfuscation_port_tcp,
                    );
                    // Learn the server's capacity limits: the soft
                    // per-client file limit so OP_OFFERFILES gets capped
                    // like eMule on the next connect, plus the user
                    // capacity and hard file limit the Servers page shows
                    // (all persisted to server.met as ST_MAXUSERS /
                    // ST_SOFTFILES / ST_HARDFILES).
                    state.server_list.update_capacity_limits(
                        &addr.ip().to_string(), tcp_port, max_users, soft_files, hard_files,
                    );
                    // L11: Store per-server UDP flags for feature gating
                    state.server_list.update_udp_flags(
                        &addr.ip().to_string(), tcp_port, udp_flags,
                    );
                    // Persist UDP obfuscation crypto material so
                    // subsequent send / recv paths can wrap and
                    // unwrap packets for this server. Both fields
                    // come from the extended status payload —
                    // without storing them, V2 silently sends
                    // plaintext to obfuscation-only servers and
                    // they ignore us.
                    state.server_list.update_udp_obfuscation(
                        &addr.ip().to_string(), tcp_port,
                        obfuscation_port_udp, server_udp_key, state.external_ip,
                    );
                }
            }
            ServerUdpResponse::FoundSources { addr, files } => {
                let now = std::time::Instant::now();
                let files: Vec<_> = files
                    .into_iter()
                    .filter(|(file_hash, _)| {
                        is_recent_configured_server_source_reply(
                            &state.server_list,
                            &state.server_udp_source_reask_at,
                            addr,
                            file_hash,
                            now,
                        )
                    })
                    .collect();
                if files.is_empty() {
                    debug!(
                        "Ignoring unsolicited/stale UDP FoundSources from {addr}"
                    );
                    continue;
                }
                let ip_str = addr.ip().to_string();
                let tcp_port = addr.port().saturating_sub(4);
                state.server_list.record_udp_reply(&ip_str, tcp_port);
                // Bump per-reply diagnostic ONCE per packet, not
                // per file — `udp_discovery_replies` measures
                // "server answered our UDP query at all", and
                // a multi-file reply is still one packet on the
                // wire. `udp_discovery_sources_found` aggregates
                // sources across every file in the packet.
                state.udp_discovery_replies = state.udp_discovery_replies.saturating_add(1);
                let total_sources_in_packet: u64 = files.iter()
                    .map(|(_, srcs)| srcs.len() as u64)
                    .sum();
                state.udp_discovery_sources_found = state
                    .udp_discovery_sources_found
                    .saturating_add(total_sources_in_packet);
                // Distinct from `record_udp_reply` (which
                // fires above for ANY UDP reply): this
                // marks the server as actually USEFUL for
                // source discovery, not just reachable.
                // Lets the per-server health log
                // distinguish "alive" from "alive AND has
                // returned source data".
                {
                    let ip_str = addr.ip().to_string();
                    let tcp_port = addr.port().saturating_sub(4);
                    state.server_list.record_udp_source_reply(&ip_str, tcp_port);
                }
                // Now process each file's source list. eMule's
                // UDP servers can pack multiple file responses
                // in one OP_GLOBFOUNDSOURCES datagram, so iterate
                // every entry the parser returned (the previous
                // single-entry parser silently dropped every
                // entry past the first, which dramatically
                // reduced the source pool whenever we batched
                // multiple file hashes into one OP_GLOBGETSOURCES2
                // request — i.e. any session with >1 download).
              for (file_hash, sources) in files {
                {
                    let hash_hex_udp = hex::encode(file_hash);
                    let matching: Vec<String> = state.pending_downloads.iter()
                        .filter(|(_, pd)| pd.file_hash == hash_hex_udp)
                        .map(|(_, pd)| pd.transfer_id.clone())
                        .collect();
                    for tid in &matching {
                        let _ = app_handle.emit("transfer:source-search", serde_json::json!({
                            "transfer_id": tid,
                            "kind": if sources.is_empty() { "udp_empty" } else { "udp_found" },
                            "count": sources.len(),
                        }));
                    }
                    if sources.is_empty() {
                        debug!("UDP server {} returned 0 sources for file {}", addr, hash_hex_udp);
                    }
                }
                if !sources.is_empty() {
                    let hash_hex = hex::encode(file_hash);
                    info!("UDP server {} found {} sources for {}", addr, sources.len(), hash_hex);
                    // Inbound bytes already counted above against
                    // `OverheadCategory::SourceExchange` using the
                    // actual packet length from `try_recv`.
                    let udp_server_port = addr.port().saturating_sub(4);
                    let udp_server_ip = match addr.ip() {
                        std::net::IpAddr::V4(v4) => u32::from_le_bytes(v4.octets()),
                        _ => 0,
                    };
                    {
                        let mut sm = source_manager.write().await;
                        for (ip, port, client_id) in &sources {
                            if *client_id > 0 {
                                // LowID source — no peer
                                // IP yet (only known once
                                // the callback connects
                                // back). No IP-level filter
                                // we can apply here, so
                                // register and let the
                                // upload listener filter
                                // when the callback
                                // actually arrives.
                                //
                                // Unless we are LowID
                                // ourselves, in which case
                                // the callback can never
                                // work and eMule refuses
                                // the source outright
                                // (`CanAddSource`,
                                // `PartFile.cpp:2438-2442`).
                                // This path carries no user
                                // hash, so unlike the TCP
                                // poll it cannot even leave
                                // a visible dead-end row.
                                if state.low_id {
                                    continue;
                                }
                                sm.register_lowid_source(
                                    file_hash,
                                    *client_id,
                                    *port,
                                    udp_server_ip,
                                    udp_server_port,
                                    [0u8; 16],
                                    0,
                                    // UDP OP_GLOBFOUNDSOURCES.
                                    Some(crate::types::SourceOrigin::Server),
                                );
                            } else {
                                // HighID source — apply
                                // Same IP filter / ban gate
                                // as `inject_source_into_active_transfers`
                                // BEFORE registering, so
                                // banned IPs don't end up
                                // in the source manager
                                // (where they would
                                // pollute SX out and
                                // future retries).
                                if state.ip_filter.is_blocked(*ip) {
                                    continue;
                                }
                                if state.banned_ips.contains(ip) {
                                    continue;
                                }
                                // Drop undialable port 0 and our own
                                // echoed HighID (same as the TCP
                                // found-sources path) so neither is
                                // reask-dialed or SX-forwarded.
                                if *port == 0 {
                                    continue;
                                }
                                if state.external_ip == Some(*ip)
                                    && (*port == state.tcp_port
                                        || *port == advertised_tcp_port(state))
                                {
                                    continue;
                                }
                                sm.register_source_full_server(
                                    file_hash, *ip, *port, 0,
                                    udp_server_ip, udp_server_port,
                                    [0u8; 16], 0,
                                    // UDP OP_GLOBFOUNDSOURCES.
                                    Some(crate::types::SourceOrigin::Server),
                                );
                            }
                        }
                    }
                    if state.server_connected && !state.low_id {
                        let needing_callback = {
                            let sm = source_manager.read().await;
                            sm.get_lowid_sources_needing_callback(
                                &file_hash,
                                udp_server_ip,
                                udp_server_port,
                                ed2k::dead_sources::FILEREASKTIME_SECS,
                            )
                        };
                        if !needing_callback.is_empty() && state.server_connection.is_some() {
                            let current_server_matches = state.server_addr.map(|server_addr| {
                                server_addr.ip() == addr.ip() && server_addr.port() == udp_server_port
                            }).unwrap_or(false);
                            if current_server_matches {
                                // Queue instead of writing here — see the
                                // identical change on the TCP-sourced
                                // LowID-callback path above: an untimed
                                // `request_callback` write can stall on a
                                // slow/stuck server, and this runs inline in
                                // the network task's own event loop, so an
                                // uncapped batch of them freezes all of
                                // networking for as long as the writes are
                                // stuck. The drain paces the sends and does
                                // the `mark_callback_sent` bookkeeping for
                                // whatever it gets out.
                                let queued = queue_lowid_callbacks(
                                    pending_lowid_callback_queue,
                                    needing_callback.iter().map(|cid| (file_hash, *cid)),
                                );
                                if queued > 0 {
                                    debug!("Queued {queued} LowID callback requests from UDP sources");
                                }
                            }
                        }
                    }
                    // Inject HighID sources into active downloads
                    let matching_transfer_ids = {
                        let mgr = transfer_manager.read().await;
                        matching_active_transfer_ids_for_hash(state, &mgr, &hash_hex)
                    };
                    for (ip, port, client_id) in &sources {
                        if *client_id == 0 && !ip.is_unspecified() {
                            if state.dead_sources.is_dead_source_for_file(&file_hash, u32::from(*ip), *port) {
                                continue;
                            }
                            let uh = {
                                let sm = source_manager.read().await;
                                sm.get_user_hash(&file_hash, *ip, *port)
                            };
                            let co = {
                                let sm = source_manager.read().await;
                                sm.get_connect_options(&file_hash, *ip, *port)
                            };
                            let download_source = DownloadSource {
                                peer_ip: ip.to_string(),
                                peer_port: *port,
                                available_parts: Vec::new(),
                                peer_user_hash: uh,
                                peer_connect_options: co,
                            };
                            let stats = inject_source_into_active_transfers(
                                state,
                                file_hash,
                                &matching_transfer_ids,
                                &download_source,
                                0,
                            );
                            if stats.dropped_full > 0 || stats.dropped_closed > 0 {
                                debug!(
                                    "UDP sources: source {}:{} for {} matched {} active downloads, injected={}, preserved={}, full={}, overflowed={}, closed={}",
                                    ip,
                                    port,
                                    hash_hex,
                                    stats.matched_transfers,
                                    stats.injected,
                                    stats.persisted,
                                    stats.dropped_full,
                                    stats.overflowed,
                                    stats.dropped_closed,
                                );
                            }
                        }
                    }
                    // Register source details so the frontend shows ed2k origin icons
                    {
                        let matching_transfer_ids = {
                            let mgr = transfer_manager.read().await;
                            matching_active_transfer_ids_for_hash(state, &mgr, &hash_hex)
                        };
                        if !matching_transfer_ids.is_empty() {
                            let mut mgr = transfer_manager.write().await;
                            for (ip, port, client_id) in &sources {
                                if *client_id == 0 && !ip.is_unspecified() {
                                    let cc = crate::geoip::lookup_country(geoip, std::net::IpAddr::V4(*ip));
                                    for tid in &matching_transfer_ids {
                                        mgr.update_source_detail(
                                            tid,
                                            crate::types::SourceInfo {
                                                ip: ip.to_string(),
                                                port: *port,
                                                status: crate::types::SourceStatus::Connecting,
                                                queue_rank: None,
                                                speed: 0,
                                                transferred: 0,
                                                client_software: String::new(),
                                                peer_name: String::new(),
                                                available_parts: None,
                                                total_parts: None,
                                                country_code: cc.clone(),
                                                user_hash: None,
                                                // UDP global search
                                                // answer from a server.
                                                origin: Some(crate::types::SourceOrigin::Server),
                                                placeholder: false,
                                            },
                                        );
                                    }
                                }
                            }
                            for tid in &matching_transfer_ids {
                                let _ = app_handle.emit(
                                    "transfer:sources-updated",
                                    serde_json::json!({ "transfer_id": tid }),
                                );
                            }
                        }
                    }
                    for pd in state.pending_downloads.values_mut() {
                        if pd.file_hash == hash_hex {
                            pd.last_search_at = None;
                            debug!("Marked pending download {} for immediate retry (UDP sources)", pd.transfer_id);
                        }
                    }
                    let matching_tids: Vec<String> = state.pending_downloads
                        .iter()
                        .filter(|(_, pd)| pd.file_hash == hash_hex)
                        .map(|(tid, _)| tid.clone())
                        .collect();
                    for tid in matching_tids {
                        let _ = try_start_pending_download_from_known_sources(
                            state,
                            &tid,
                            transfer_manager,
                            source_manager,
                            credit_manager,
                            bandwidth_limiter,
                            dl_event_tx,
                            app_handle,
                            settings,
                            shared_ember_payload,
                            ember_payload_generation,
                            shared_banned_ips,
                            geoip,
                            friend_hashes,
                            ember_hash,
                            ed25519_pubkey,
                            ed25519_secret_key,
                            &stats_manager.sx_counters,
                            &stats_manager.file_req_counters,
                            &stats_manager.epx_counters,
                        ).await;
                    }
                }
              } // end `for (file_hash, sources) in files`
            }
            ServerUdpResponse::SearchResult { addr, results } => {
                // eMule ProcessUDPSearchAnswer: ignore replies from
                // IPs we did not successfully UDP-query this search.
                let src_ip = match addr.ip() {
                    IpAddr::V4(ip) => Some(ip),
                    _ => None,
                };
                let allowed = state.active_search_request.as_ref().is_some_and(|a| {
                    a.udp_pending
                        && src_ip.is_some_and(|ip| a.udp_search_sent_ips.contains(&ip))
                });
                if !allowed {
                    debug!(
                        "Ignoring unsolicited or late UDP search result from {addr}"
                    );
                } else if !results.is_empty() {
                    let ip_str = addr.ip().to_string();
                    let tcp_port = addr.port().saturating_sub(4);
                    state.server_list.record_udp_reply(&ip_str, tcp_port);

                    debug!("UDP search returned {} results from {addr}", results.len());
                    let search_results: Vec<SearchResult> = results.iter().map(|sr| {
                        let hash_hex = hex::encode(sr.file_hash);
                        let extension = sr.file_name
                            .rsplit_once('.')
                            .map(|(_, ext)| ext.to_string())
                            .unwrap_or_default();
                        let source_addresses = if sr.client_id >= ed2k::server::LOWID_THRESHOLD
                            && sr.client_port > 0
                        {
                            let ip = Ipv4Addr::from(sr.client_id.to_le_bytes());
                            if is_search_source_safe(state, ip) {
                                vec![format!("{}:{}", ip, sr.client_port)]
                            } else {
                                Vec::new()
                            }
                        } else {
                            Vec::new()
                        };
                        // Prefer advertised FT_SOURCES; fall back to 1
                        // so a hit without the tag still ranks as present.
                        let availability = crate::search::merge::clamp_source_count(
                            if sr.source_count > 0 {
                                sr.source_count
                            } else {
                                1
                            },
                        );
                        SearchResult {
                            file: FileInfo {
                                id: hash_hex.clone(),
                                name: sr.file_name.clone(),
                                path: String::new(),
                                size: sr.file_size,
                                hash: hash_hex,
                                aich_hash: String::new(),
                                ember_file_hash: String::new(),
                                extension: extension.clone(),
                                modified_at: 0,
                                priority: "normal".to_string(),
                                requests: 0,
                                accepted: 0,
                                bytes_transferred: 0,
                                alltime_requests: 0,
                                alltime_accepted: 0,
                                alltime_transferred: 0,
                                complete_sources: crate::search::merge::clamp_source_count(
                                    sr.complete_source_count,
                                ),
                                folder: String::new(),
                                shared: false,
                                friends_only: false,
                                shared_kad: false,
                                shared_ed2k: false,
                                shared_ember: false,
                            },
                            peer_id: format!("{}:{}", sr.client_id, sr.client_port),
                            peer_name: String::new(),
                            availability,
                            file_type: crate::search::index::infer_file_type(&extension),
                            source_addresses,
                            rating: sr.rating,
                            comment: sr.comment.clone(),
                            media: sr.media.clone().into_option(),
                            spam_rating: 0,
                            is_spam: false,
                            clean_name: String::new(),
                            result_origin: crate::search::merge::ORIGIN_SERVER_UDP.to_string(),
                            origin_server_ip: None,
                            spam_reasons: Vec::new(),
                            spam_reason_details: Vec::new(),
                        }
                    }).collect();
                    // Extracted into owned values (rather than an `as_ref()`
                    // binding kept alive across the call below) so the
                    // `dedup_streamed_batch` call can take `active_search_request`
                    // mutably afterward without fighting the borrow checker.
                    let active_ctx = state.active_search_request.as_ref().map(|a| {
                        (
                            a.request_id,
                            a.file_type_filter.clone(),
                            a.min_size,
                            a.max_size,
                            a.file_extension.clone(),
                            a.min_availability,
                            a.keywords.clone(),
                        )
                    });
                    if let Some((
                        request_id,
                        ft_filter,
                        min_size,
                        max_size,
                        file_extension,
                        min_availability,
                        kws,
                    )) = active_ctx
                    {
                        state.server_udp_search_age = 0;
                        let mut search_results = search_results;
                        let resights = dedup_streamed_batch(
                            &mut state.active_search_request,
                            request_id,
                            &mut search_results,
                        );
                        let mut batch_spam = take_search_batch_spam(state, request_id);
                        let udp_server_ip = addr.ip().to_string();
                        let emitted = enrich_and_emit_search_results(
                            app_handle,
                            spam_filter,
                            comment_manager,
                            settings,
                            request_id,
                            search_results,
                            &ft_filter,
                            min_size,
                            max_size,
                            file_extension.as_deref(),
                            min_availability,
                            &kws,
                            Some(&udp_server_ip),
                            Some(&mut batch_spam),
                        ).await;
                        store_search_batch_spam(state, request_id, batch_spam);
                        let skip_hashes = {
                            let idx = local_index.read().await;
                            let mgr = transfer_manager.read().await;
                            owned_or_downloading_search_hashes(
                                emitted
                                    .iter()
                                    .chain(resights.iter())
                                    .map(|r| r.file.hash.as_str()),
                                &idx,
                                &mgr,
                                &state.pending_downloads,
                            )
                        };
                        if let Some(active) = state.active_search_request.as_mut() {
                            if active.request_id == request_id {
                                mark_streamed_hashes(active, &emitted);
                                let _ = note_ed2k_search_results(
                                    active,
                                    &emitted,
                                    &skip_hashes,
                                );
                                emit_search_resight_updates(
                                    app_handle,
                                    request_id,
                                    resights,
                                    active,
                                    &skip_hashes,
                                );
                            }
                        }
                        stop_ed2k_udp_search_if_capped(state, app_handle);
                    }
                }
            }
        }
    }
}
