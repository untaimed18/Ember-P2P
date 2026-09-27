//! The 2 s eD2K server tick: takes what the server link's reader task has
//! decoded (server list, status, search results, sources, callback requests,
//! ID changes) and handles it, times out server searches, and reconnects to the
//! preferred server when the connection drops. Nothing here waits on the
//! server socket; see `ServerLink`.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_server_tick(
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
    shared_banned_ips: &upload_server::SharedBannedIps,
    shared_server_addr: &Arc<RwLock<Option<SocketAddr>>>,
    shared_ember_payload: &ember::SharedEmberPayload,
    ember_payload_generation: &ember::EmberPayloadGeneration,
    geoip: &crate::geoip::GeoIpReader,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    ember_hash: [u8; 16],
    ed25519_pubkey: [u8; 32],
    ed25519_secret_key: [u8; 32],
    comment_manager: &Arc<RwLock<CommentManager>>,
    connect_serve_tx: &mpsc::Sender<upload_server::ConnectServeRequest>,
    last_server_activity_at: &mut i64,
    spam_filter: &Arc<RwLock<crate::search::spam::SpamFilter>>,
    pending_lowid_callback_queue: &mut VecDeque<([u8; 16], u32)>,
) {
    if state.server_connected {
        let mut pending_lowid_callbacks: Vec<([u8; 16], u32)> = Vec::new();
        let mut finished_search_requests: Vec<u64> = Vec::new();
        let mut pending_source_start_tids: Vec<String> = Vec::new();
        let mut server_disconnect_reason: Option<String> = None;
        let mut conn_to_restore: Option<ServerLink> = None;
        if let Some(mut conn) = state.server_connection.take() {
            // Whatever the reader decoded since the last tick, in arrival
            // order, drained even when the session is about to be dropped: a
            // server that kicks us usually says why first (a ban, "too many
            // files"), and that notice is the one message worth logging. A
            // reader that has stopped (EOF, a corrupt stream, a parse panic)
            // says so after the events that preceded it.
            let (events, closed) = conn.drain_events(ed2k::server::SERVER_EVENT_QUEUE);
            // The writer task marks the link unusable when a write fails or
            // times out; later sends already fail fast, so this is where the
            // session actually gets dropped. That failure is the root cause
            // when both happened.
            server_disconnect_reason = server_write_failure_reason(&conn).or(closed);
            if !events.is_empty() {
                *last_server_activity_at = chrono::Utc::now().timestamp();
            }
            for event in events {
                match event {
                    ed2k::server::ServerEvent::ServerList { data } => {
                        if settings.add_servers_from_server {
                            let added = state.server_list.add_from_server_list_packet(
                                &data,
                                settings.filter_servers_by_ip,
                                &mut state.ip_filter,
                            );
                            if added > 0 {
                                emit_server_log(app_handle, &format!("Added {added} servers from server list update"));
                                let met_path = state.data_dir.join("server.met");
                                spawn_save_server_met(&state.server_list, met_path.clone(), &state.server_met_save_generation, &state.server_met_save_lock);
                            }
                        }
                    }
                    ed2k::server::ServerEvent::StatusUpdate { users, files } => {
                        if let Some(addr) = state.server_addr {
                            state.server_list.update_server_stats(
                                &addr.ip().to_string(), addr.port(), users, files, 0,
                            );
                        }
                        conn.session.user_count = users;
                        conn.session.file_count = files;
                    }
                    ed2k::server::ServerEvent::ServerIdent { name } => {
                        conn.session.server_name = name.clone();
                        if let Some(addr) = state.server_addr {
                            if state.server_list.update_server_name_from_ident(
                                &addr.ip().to_string(),
                                addr.port(),
                                &name,
                            ) {
                                let met_path = state.data_dir.join("server.met");
                                spawn_save_server_met(&state.server_list, met_path, &state.server_met_save_generation, &state.server_met_save_lock);
                            }
                        }
                    }
                    ed2k::server::ServerEvent::SearchResult { results, more } => {
                        let count = results.len();
                        info!("Server returned {count} search results via poll");
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
                            peer_id: String::new(),
                            peer_name: String::new(),
                            // Mirror UDP/KAD: missing/0 sources still
                            // mean the publishing peer is present.
                            availability: crate::search::merge::clamp_source_count(
                                sr.source_count.max(1),
                            ),
                            file_type: crate::search::index::infer_file_type(&extension),
                            source_addresses,
                            rating: sr.rating,
                            comment: sr.comment.clone(),
                            media: sr.media.clone().into_option(),
                            spam_rating: 0,
                            is_spam: false,
                            clean_name: String::new(),
                            result_origin: crate::search::merge::ORIGIN_SERVER_TCP.to_string(),
                            origin_server_ip: None,
                            spam_reasons: Vec::new(),
                            spam_reason_details: Vec::new(),
                            }
                        }).collect();

                        if let Some(mut pending) = state.pending_server_search.take() {
                            let request_id = pending.request_id;
                            state.server_search_age = 0;
                            if let Some(active) = state.active_search_request.as_mut() {
                                if active.request_id == request_id {
                                    active.server_result_count =
                                        active.server_result_count.saturating_add(count);
                                }
                            }
                            if let Some(tx) = pending.tx.take() {
                                // Legacy oneshot accumulate path (not used by
                                // live SearchFiles, which always sets tx: None).
                                let mut local = pending.results;
                                local.extend(search_results);
                                if server_should_ask_for_more(
                                    more,
                                    state.server_search_more_requests,
                                    local.len() < 1000,
                                ) {
                                    state.server_search_more_due_at = Some(
                                        std::time::Instant::now() + SERVER_MORE_RESULTS_DELAY,
                                    );
                                    state.pending_server_search = Some(PendingServerSearch {
                                        tx: Some(tx),
                                        results: local,
                                        request_id,
                                    });
                                } else {
                                    let _ = tx.send(local);
                                    if let Some(active) = state.active_search_request.as_mut() {
                                        if active.request_id == request_id {
                                            active.server_pending = false;
                                        }
                                    }
                                    finished_search_requests.push(request_id);
                                }
                            } else {
                                // A page we asked for is a page we use.
                                // This whole branch used to be a
                                // discard: if the shared source cap
                                // had tripped between the request
                                // leaving and the answer arriving, up
                                // to 200 parsed rows were thrown away
                                // unemitted, and any queued co-share
                                // follow-up was dropped with them. The
                                // round trip had already been spent;
                                // refusing to read the reply bought
                                // none of it back.
                                {
                                // Matched on the id for the same
                                // reason as the KAD leg above: the
                                // `None` fallback meant "no
                                // client-side filters" on a batch
                                // still emitted under this id, so a
                                // search that had already moved on
                                // would deliver rows ignoring the
                                // user's filters.
                                let filter_ctx = state
                                    .active_search_request
                                    .as_ref()
                                    .filter(|a| a.request_id == request_id)
                                    .map(|a| {
                                        (
                                            a.file_type_filter.clone(),
                                            a.min_size,
                                            a.max_size,
                                            a.file_extension.clone(),
                                            a.min_availability,
                                            a.keywords.clone(),
                                            a.server_ip.clone(),
                                        )
                                    });
                                let ctx_matches = filter_ctx.is_some();
                                let (
                                    ft_filter,
                                    min_size,
                                    max_size,
                                    file_extension,
                                    min_availability,
                                    kws,
                                    srv_ip,
                                ) = filter_ctx.unwrap_or((
                                    None, None, None, None, None, Vec::new(), None,
                                ));
                                let mut search_results = search_results;
                                if !ctx_matches {
                                    search_results.clear();
                                }
                                let resights = dedup_streamed_batch(
                                    &mut state.active_search_request,
                                    request_id,
                                    &mut search_results,
                                );
                                let mut batch_spam =
                                    take_search_batch_spam(state, request_id);
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
                                    srv_ip.as_deref(),
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
                                let under_result_cap = state
                                    .active_search_request
                                    .as_ref()
                                    .filter(|active| active.request_id == request_id)
                                    .map(|active| active.server_result_count < 1000)
                                    .unwrap_or(true);
                                // Only the server's own "more" byte
                                // says there is more to give; a full
                                // page does not. The next page is
                                // asked for on a later tick, never in
                                // this one.
                                if server_should_ask_for_more(
                                    more,
                                    state.server_search_more_requests,
                                    under_result_cap,
                                ) {
                                    state.server_search_more_due_at = Some(
                                        std::time::Instant::now() + SERVER_MORE_RESULTS_DELAY,
                                    );
                                    state.pending_server_search = Some(PendingServerSearch {
                                        tx: None,
                                        results: Vec::new(),
                                        request_id,
                                    });
                                } else {
                                    end_or_continue_server_search_leg(
                                        state,
                                        request_id,
                                        &mut finished_search_requests,
                                    );
                                }
                                } // end of the page-processing block
                            }
                        }
                    }
                    ed2k::server::ServerEvent::FoundSources { file_hash, sources } => {
                        let hash_hex_fs = hex::encode(file_hash);
                        // Count the inbound TCP source-list reply
                        // as SourceExchange overhead. The exact
                        // wire size isn't carried through the
                        // event, so we estimate from the eMule
                        // OP_FOUNDSOURCES layout: 6-byte frame +
                        // opcode + 16-byte hash + 2-byte count +
                        // 6 bytes per source (IP/client_id + port).
                        let est_bytes = (25 + sources.len() * 6) as u64;
                        stats_manager.add_overhead(
                            crate::storage::statistics::OverheadCategory::SourceExchange,
                            crate::storage::statistics::OverheadDirection::Download,
                            est_bytes,
                        );
                        {
                            let matching: Vec<String> = state.pending_downloads.iter()
                                .filter(|(_, pd)| pd.file_hash == hash_hex_fs)
                                .map(|(_, pd)| pd.transfer_id.clone())
                                .collect();
                            for tid in &matching {
                                let _ = app_handle.emit("transfer:source-search", serde_json::json!({
                                    "transfer_id": tid,
                                    "kind": if sources.is_empty() { "server_empty" } else { "server_found" },
                                    "count": sources.len(),
                                }));
                            }
                        }
                        if sources.is_empty() {
                            debug!("Server returned 0 sources for file {}", hash_hex_fs);
                        }
                        if !sources.is_empty() {
                            let highid_count = sources.iter().filter(|s| s.client_id == 0).count();
                            let lowid_count = sources.iter().filter(|s| s.client_id > 0).count();
                            info!("Server found {} sources ({} HighID, {} LowID) for file {} via poll",
                                sources.len(), highid_count, lowid_count, hex::encode(file_hash));
                            let mut sm = source_manager.write().await;
                            let (server_ip, server_port) = state.server_addr.and_then(|addr| {
                                match addr.ip() {
                                    std::net::IpAddr::V4(v4) => Some((u32::from_le_bytes(v4.octets()), addr.port())),
                                    _ => None,
                                }
                            }).unwrap_or((0, 0));
                            // LowID sources found here that we can't reach via
                            // `OP_CALLBACKREQUEST` (see the `state.low_id` gate
                            // below) because we're LowID ourselves. Collected by
                            // user hash (the only stable identity a classic
                            // ed2k-server LowID entry carries) and surfaced into
                            // matching transfers' `PerFileSourceList` after
                            // `matching_transfer_ids` is computed below.
                            let mut lowid_unreachable_hashes: Vec<[u8; 16]> = Vec::new();
                            for src in &sources {
                                if src.client_id == 0 {
                                    if let Ok(v4) = src.ip.parse::<Ipv4Addr>() {
                                        // Mirror the gate the UDP source path applies
                                        // (see `OP_FOUNDSOURCES` handler). Without
                                        // this, banned/special-use IPs reported by
                                        // the TCP-connected server would pollute
                                        // `source_manager` (and from there our
                                        // outbound Source Exchange) — the eventual
                                        // download attempt is gated by
                                        // `inject_source_into_active_transfers` so
                                        // we don't actually connect, but we'd still
                                        // forward the bad IP to other peers.
                                        // Never store ourselves (a
                                        // server that we published
                                        // this file to can echo our
                                        // own HighID back) or an
                                        // undialable port 0 — both
                                        // would otherwise be reask-
                                        // dialed and forwarded via
                                        // Source Exchange. Mirrors
                                        // `is_self_source` + the
                                        // inject gate. Checks both
                                        // the raw bind port and
                                        // the currently-advertised
                                        // (possibly STUN-remapped)
                                        // one.
                                        let is_self = (state.external_ip == Some(v4)
                                            && (src.port == state.tcp_port
                                                || src.port == advertised_tcp_port(state)))
                                            || matches!(
                                                src.user_hash,
                                                Some(uh) if uh != [0u8; 16] && uh == state.user_hash
                                            );
                                        if state.ip_filter.is_blocked(v4)
                                            || state.banned_ips.contains(&v4)
                                            || src.port == 0
                                            || is_self
                                        {
                                            continue;
                                        }
                                        sm.register_source_full_server(
                                            file_hash,
                                            v4,
                                            src.port,
                                            0,
                                            server_ip,
                                            server_port,
                                            src.user_hash.unwrap_or([0u8; 16]),
                                            src.crypt_options.unwrap_or(0),
                                            // OP_FOUNDSOURCES, from
                                            // the server we are on.
                                            Some(crate::types::SourceOrigin::Server),
                                        );
                                    }
                                } else if !state.low_id {
                                    sm.register_lowid_source(
                                        file_hash,
                                        src.client_id,
                                        src.port,
                                        server_ip,
                                        server_port,
                                        src.user_hash.unwrap_or([0u8; 16]),
                                        src.crypt_options.unwrap_or(0),
                                        // OP_FOUNDSOURCES: here the
                                        // server really is the finder.
                                        Some(crate::types::SourceOrigin::Server),
                                    );
                                } else {
                                    // We are LowID too, so this source is a dead end:
                                    // asking the server to relay OP_CALLBACKREQUEST
                                    // would only tell the peer to dial an address as
                                    // unreachable as its own. eMule declines to create
                                    // the source at all in that case — `CanAddSource`
                                    // returns false for `IsLowID(hybridID) &&
                                    // IsFirewalled()` (`PartFile.cpp:2438-2442`) — so it
                                    // never enters `srclist` and never counts.
                                    //
                                    // Keeping it out of the registry is the part that
                                    // matters: `source_count` gates every further
                                    // server, KAD and Ember lookup against
                                    // `MAX_SOURCES_FOR_UDP`, so a LowID user's popular
                                    // file used to accumulate enough undialable rows to
                                    // switch its own discovery off — while the Sources
                                    // column showed hundreds. The visible row below is
                                    // still added: the dead end is worth showing, and
                                    // it can be upgraded later — see
                                    // `set_low_to_low_by_identity`.
                                    if let Some(uh) = src.user_hash.filter(|h| *h != [0u8; 16]) {
                                        lowid_unreachable_hashes.push(uh);
                                    }
                                }
                            }
                            drop(sm);
                            // Collect LowID client IDs needing callbacks (dedup-aware)
                            if !state.low_id {
                                let sm = source_manager.read().await;
                                let needing = sm.get_lowid_sources_needing_callback(
                                    &file_hash,
                                    server_ip,
                                    server_port,
                                    ed2k::dead_sources::FILEREASKTIME_SECS,
                                );
                                for cid in needing {
                                    pending_lowid_callbacks.push((file_hash, cid));
                                }
                            }
                            let hash_hex = hex::encode(file_hash);
                            let matching_transfer_ids = {
                                let mgr = transfer_manager.read().await;
                                matching_active_transfer_ids_for_hash(state, &mgr, &hash_hex)
                            };
                            if !lowid_unreachable_hashes.is_empty() {
                                for tid in &matching_transfer_ids {
                                    let pfs = state.per_file_sources
                                        .entry(tid.clone())
                                        .or_insert_with(|| ed2k::sources::PerFileSourceList::new(file_hash));
                                    // Identity-only rows: a classic ed2k-server LowID
                                    // entry carries no routable address, so IP and port
                                    // both stay zero and the user hash is the only key
                                    // (`register_lowid_source` stores the same way).
                                    // These sources deliberately do *not* reach the
                                    // Ember broker: a relay request needs a dialable
                                    // `target_ip:target_port`, and the relay-side SSRF
                                    // guard (`relay_target_refusal`) rejects
                                    // `0.0.0.0:0` on both its port and address checks.
                                    // Brokering them would require discovering an
                                    // address first — i.e. a KAD buddy record, which is
                                    // already the path that reaches `attempt_low_to_low`.
                                    for uh in &lowid_unreachable_hashes {
                                        pfs.add_source_with_identity(Ipv4Addr::UNSPECIFIED, 0, 0, Some(*uh));
                                        pfs.set_low_to_low(Ipv4Addr::UNSPECIFIED, 0, Some(*uh));
                                    }
                                }
                            }
                            let mut server_source_ips: Vec<(String, u16)> = Vec::new();
                            for src in &sources {
                                if src.client_id == 0 && !src.ip.is_empty() {
                                    let v4_ip = src.ip.parse::<Ipv4Addr>().ok();
                                    if let Some(v4) = v4_ip {
                                        if state.dead_sources.is_dead_source_for_file(&file_hash, u32::from(v4), src.port) {
                                            continue;
                                        }
                                    }
                                    server_source_ips.push((src.ip.clone(), src.port));
                                    let (uh, co) = if let Some(v4) = v4_ip {
                                        let sm = source_manager.read().await;
                                        (sm.get_user_hash(&file_hash, v4, src.port),
                                         sm.get_connect_options(&file_hash, v4, src.port))
                                    } else {
                                        (None, None)
                                    };
                                    let download_source = DownloadSource {
                                        peer_ip: src.ip.clone(),
                                        peer_port: src.port,
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
                                            "Server sources: source {}:{} for {} matched {} active downloads, injected={}, preserved={}, full={}, overflowed={}, closed={}",
                                            src.ip,
                                            src.port,
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
                            if !server_source_ips.is_empty() {
                                let mut mgr = transfer_manager.write().await;
                                for tid in &matching_transfer_ids {
                                    for (ip_s, port) in &server_source_ips {
                                        let cc = ip_s.parse::<std::net::IpAddr>().ok()
                                            .and_then(|ip| crate::geoip::lookup_country(geoip, ip));
                                        mgr.update_source_detail(
                                            tid,
                                            crate::types::SourceInfo {
                                                ip: ip_s.clone(),
                                                port: *port,
                                                status: crate::types::SourceStatus::Connecting,
                                                queue_rank: None,
                                                speed: 0,
                                                transferred: 0,
                                                client_software: String::new(),
                                                peer_name: String::new(),
                                                available_parts: None,
                                                total_parts: None,
                                                country_code: cc,
                                                user_hash: None,
                                                // Straight from the
                                                // server's answer.
                                                origin: Some(crate::types::SourceOrigin::Server),
                                                placeholder: false,
                                            },
                                        );
                                    }
                                    let _ = app_handle.emit(
                                        "transfer:sources-updated",
                                        serde_json::json!({ "transfer_id": tid }),
                                    );
                                }
                            }
                            for pd in state.pending_downloads.values_mut() {
                                if pd.file_hash == hash_hex {
                                    pd.last_search_at = 0;
                                    debug!("Marked pending download {} for immediate retry (server sources)", pd.transfer_id);
                                }
                            }
                            let matching_tids: Vec<String> = state.pending_downloads
                                .iter()
                                .filter(|(_, pd)| pd.file_hash == hash_hex)
                                .map(|(tid, _)| tid.clone())
                                .collect();
                            for tid in matching_tids {
                                if !pending_source_start_tids.contains(&tid) {
                                    pending_source_start_tids.push(tid);
                                }
                            }
                        }
                    }
                    ed2k::server::ServerEvent::Message(msg) => {
                        info!("Server message: {msg}");
                        emit_server_log(app_handle, &format!("Server: {msg}"));
                    }
                    ed2k::server::ServerEvent::CallbackRequested { ip, port, crypt_options, user_hash } => {
                        // eMule parity (ServerSocket OP_CALLBACKREQUESTED ->
                        // TryToConnect -> unified serve): we dial the peer back and serve
                        // it via the upload listener's outbound connect-and-serve path, so
                        // a firewalled LowID node can still upload to peers that can only
                        // reach it through a server callback (connect-back is a LowID
                        // node's only upload route). We ALSO keep the download-direction
                        // handling below (register + inject the peer as a source) for the
                        // case where this same peer is a LowID *source* of a file we're
                        // downloading; eMule unifies both directions on one connection,
                        // Ember uses one connection per direction. The KAD buddy
                        // OP_CALLBACK relay path dials back the same way.
                        info!("Server callback requested: peer at {ip}:{port}");
                        if let Ok(peer_ip) = ip.parse::<std::net::Ipv4Addr>() {
                            // Same IP-filter gate as the
                            // UDP `OP_FOUNDSOURCES` path:
                            // refuse to register a callback
                            // peer whose announced IP is in
                            // a special-use range, in our
                            // ipfilter.dat blocklist, or
                            // banned at runtime. A
                            // misbehaving server could
                            // otherwise sneak banned IPs
                            // into source_manager and out
                            // via Source Exchange.
                            if state.ip_filter.is_blocked(peer_ip)
                                || state.banned_ips.contains(&peer_ip)
                                || !connect_serve_target_ok(
                                    peer_ip,
                                    port,
                                    state.external_ip,
                                    state.tcp_port,
                                    advertised_tcp_port(state),
                                    user_hash,
                                    &state.user_hash,
                                )
                            {
                                debug!("Ignoring server callback for {peer_ip}:{port}: blocked by IP filter / banned / special-use / self / port 0");
                                continue;
                            }

                            // eMule TryToConnect: dial the peer back and serve it, so a
                            // firewalled LowID node can upload over the connection it
                            // opens. Non-blocking hand-off to the upload listener; a full
                            // queue just drops the request (the peer re-asks on a timer).
                            let cb_addr = std::net::SocketAddr::from((peer_ip, port));
                            if let Err(e) = connect_serve_tx.try_send(
                                upload_server::ConnectServeRequest {
                                    peer_addr: cb_addr,
                                    crypt_options: crypt_options.unwrap_or(0),
                                    user_hash,
                                    push_grant_file_hash: None,
                                    push_grant_accepted: None,
                                    secure_friend_ember_hash: None,
                                },
                            ) {
                                debug!("Could not enqueue callback-serve for {cb_addr}: {e}");
                            }

                            let matching_hashes = if let Some(addr) = state.server_addr {
                                if let std::net::IpAddr::V4(v4) = addr.ip() {
                                    let sm = source_manager.read().await;
                                    sm.find_lowid_files_by_port(
                                        u32::from_le_bytes(v4.octets()),
                                        addr.port(),
                                        port,
                                        user_hash,
                                    )
                                } else {
                                    Vec::new()
                                }
                            } else {
                                Vec::new()
                            };

                            let (cb_server_ip, cb_server_port) = state.server_addr.and_then(|a| {
                                match a.ip() {
                                    std::net::IpAddr::V4(v4) => Some((u32::from_le_bytes(v4.octets()), a.port())),
                                    _ => None,
                                }
                            }).unwrap_or((0, 0));
                            let mut sm = source_manager.write().await;
                            for fh in &matching_hashes {
                                sm.register_source_full_server(
                                    *fh,
                                    peer_ip,
                                    port,
                                    0,
                                    cb_server_ip,
                                    cb_server_port,
                                    user_hash.unwrap_or([0u8; 16]),
                                    crypt_options.unwrap_or(0),
                                    // Reached us through the
                                    // server's callback relay.
                                    Some(crate::types::SourceOrigin::Server),
                                );
                            }
                            drop(sm);
                            let matching_hex: Vec<String> =
                                matching_hashes.iter().map(hex::encode).collect();
                            let mgr = transfer_manager.read().await;
                            for file_hash in &matching_hashes {
                                let hash_hex = hex::encode(file_hash);
                                let matching_transfer_ids =
                                    matching_active_transfer_ids_for_hash(state, &mgr, &hash_hex);
                                let download_source = DownloadSource {
                                    peer_ip: ip.clone(),
                                    peer_port: port,
                                    available_parts: Vec::new(),
                                    peer_user_hash: user_hash,
                                    peer_connect_options: crypt_options,
                                };
                                let stats = inject_source_into_active_transfers(
                                    state,
                                    *file_hash,
                                    &matching_transfer_ids,
                                    &download_source,
                                    0,
                                );
                                if stats.dropped_full > 0 || stats.dropped_closed > 0 {
                                    debug!(
                                        "Callback source: peer {}:{} for {} matched {} active downloads, injected={}, preserved={}, full={}, overflowed={}, closed={}",
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
                            for pd in state.pending_downloads.values_mut() {
                                if matching_hex.iter().any(|h| h == &pd.file_hash) {
                                    pd.last_search_at = 0;
                                }
                            }
                            for hash_hex in &matching_hex {
                                let matching_tids: Vec<String> = state.pending_downloads
                                    .iter()
                                    .filter(|(_, pd)| &pd.file_hash == hash_hex)
                                    .map(|(tid, _)| tid.clone())
                                    .collect();
                                for tid in matching_tids {
                                    if !pending_source_start_tids.contains(&tid) {
                                        pending_source_start_tids.push(tid);
                                    }
                                }
                            }
                            info!(
                                "Registered callback peer {ip}:{port} as source for {} matching downloads",
                                matching_hex.len()
                            );
                        }
                    }
                    ed2k::server::ServerEvent::CallbackFailed => {
                        debug!("Server reported callback failure");
                    }
                    ed2k::server::ServerEvent::IdChange {
                        client_id,
                        server_flags,
                        server_reported_ip,
                    } => {
                        if client_id == 0 {
                            warn!("Server sent OP_IDCHANGE with client_id=0 — disconnecting");
                            server_disconnect_reason =
                                Some("server revoked client id (OP_IDCHANGE=0)".into());
                            break;
                        }
                        let was_low = state.low_id;
                        let is_low = client_id > 0 && client_id < ed2k::server::LOWID_THRESHOLD;
                        ed2k::server::set_server_flags_mirror(server_flags);
                        conn.session.client_id = client_id;
                        conn.session.server_flags = server_flags;
                        if server_reported_ip != 0 {
                            conn.session.server_reported_ip = server_reported_ip;
                        }
                        state.server_client_id = client_id;
                        state.low_id = is_low;
                        let id_type = if is_low { "LowID" } else { "HighID" };
                        info!(
                            "Server OP_IDCHANGE: {} id={client_id} (was_low={was_low})",
                            id_type
                        );
                        emit_server_log(
                            app_handle,
                            &format!("Server reassigned {id_type} ({client_id})"),
                        );
                        if !is_low && client_id >= ed2k::server::LOWID_THRESHOLD {
                            if state.firewalled || was_low {
                                info!("Mid-session HighID confirms TCP port is open");
                                state.firewalled = false;
                                state.firewalled_shared.store(
                                    false,
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                                if state.buddy_manager.state() == BuddyState::FindingBuddy
                                {
                                    state.buddy_manager.find_failed();
                                    info!(
                                        "Cancelled buddy search: HighID proves TCP is open"
                                    );
                                }
                            }
                            state.firewall_checker.handle_tcp_connect_back();
                            kad::firewall::publish_local_firewall(
                                state.firewalled,
                                state.udp_firewalled,
                            );
                            let ip_bytes = client_id.to_le_bytes();
                            let ext_ip = Ipv4Addr::from(ip_bytes);
                            if !ext_ip.is_unspecified()
                                && !crate::security::is_bogus_v4(ext_ip)
                            {
                                // HighID is a TCP connect-back from a
                                // user-chosen server; it replaces a
                                // conflicting KAD/Ember vote.
                                set_external_ip(state, Some(ext_ip));
                                state.stats.external_ip = ext_ip.to_string();
                                state
                                    .firewall_checker
                                    .handle_server_highid_response(ext_ip);
                            }
                            update_publish_manager_state(state);
                            state.stats.firewalled = state.firewalled;
                            state.stats.tcp_status = format!(
                                "{:?}",
                                state.firewall_checker.tcp_status()
                            );
                            state.stats.udp_status = format!(
                                "{:?}",
                                state.firewall_checker.udp_status()
                            );
                            let _ = app_handle.emit(
                                "firewall-status",
                                serde_json::json!({
                                    "firewalled": state.firewalled,
                                    "external_ip": state.stats.external_ip,
                                    "tcp_status": state.stats.tcp_status,
                                    "udp_status": state.stats.udp_status,
                                }),
                            );
                        } else if is_low {
                            state.firewalled = true;
                            state.firewalled_shared.store(
                                true,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            state.firewall_checker.note_tcp_firewalled();
                            // See the login LowID branch: the Hello
                            // capability bit lives in a process
                            // atomic and would otherwise keep the
                            // stale HighID value for this session.
                            kad::firewall::note_local_tcp_firewalled(true);
                            update_publish_manager_state(state);
                            state.stats.firewalled = true;
                            state.stats.tcp_status = format!(
                                "{:?}",
                                state.firewall_checker.tcp_status()
                            );
                            state.stats.udp_status = format!(
                                "{:?}",
                                state.firewall_checker.udp_status()
                            );
                            let _ = app_handle.emit(
                                "firewall-status",
                                serde_json::json!({
                                    "firewalled": state.firewalled,
                                    "external_ip": state.stats.external_ip,
                                    "tcp_status": state.stats.tcp_status,
                                    "udp_status": state.stats.udp_status,
                                }),
                            );
                            if server_reported_ip != 0 {
                                let ext_ip = Ipv4Addr::from(
                                    server_reported_ip.to_le_bytes(),
                                );
                                if !crate::security::is_special_use_v4(ext_ip)
                                    && state.external_ip.is_none()
                                {
                                    set_external_ip(state, Some(ext_ip));
                                    state.stats.external_ip = ext_ip.to_string();
                                }
                            }
                        }
                    }
                }
            }
            if server_disconnect_reason.is_none()
                && state.pending_server_search.is_some()
                && state
                    .server_search_more_due_at
                    .is_some_and(|due| std::time::Instant::now() >= due)
                && state.server_search_more_requests < MAX_SERVER_MORE_REQUESTS
            {
                state.server_search_more_due_at = None;
                match conn.request_more_results() {
                    Ok(()) => {
                        state.server_search_more_requests += 1;
                        // The wait for the next page starts now, not when
                        // the previous one arrived.
                        state.server_search_age = 0;
                    }
                    Err(e) => debug!("OP_QUERY_MORE_RESULT not sent: {e}"),
                }
            }

            // Second half of a related search's server leg: the
            // keyword query (and any More pages behind it) has
            // finished, so put the co-share request to the same
            // server under the same `request_id`. Asking only one of
            // the two, as this leg used to, meant a related search
            // with a usable title never put that title to the one
            // leg most likely to answer it. Gated on the leg still
            // being pending, which is a flag only a first request
            // that actually reached the wire ever set, and paced like a
            // More page rather than sent in the tick that retired the
            // first search.
            let followup_ready = server_disconnect_reason.is_none()
                && state.pending_server_search.is_none()
                && state
                    .server_followup_due_at
                    .is_none_or(|due| std::time::Instant::now() >= due)
                && match (&state.server_followup_search, &state.active_search_request) {
                    (Some((rid, _)), Some(active)) => {
                        *rid == active.request_id && active.server_pending
                    }
                    _ => false,
                };
            if followup_ready {
                if let Some((followup_id, expr)) = state.server_followup_search.take() {
                    state.server_followup_due_at = None;
                    match conn.send_search_expr_bytes(&expr) {
                        Ok(()) => {
                            // Its own More budget: this is a second
                            // search, not another page of the first.
                            state.server_search_more_due_at = None;
                            state.server_search_more_requests = 0;
                            state.pending_server_search = Some(PendingServerSearch {
                                tx: None,
                                results: Vec::new(),
                                request_id: followup_id,
                            });
                            state.server_search_age = 0;
                            info!(
                                "TCP server co-share request sent for search {followup_id}"
                            );
                        }
                        Err(e) => {
                            // Nothing else will retire this leg: the
                            // first request already delivered, and
                            // only this send was holding it open.
                            debug!("TCP server co-share request failed to send: {e}");
                            if let Some(active) = state.active_search_request.as_mut() {
                                if active.request_id == followup_id {
                                    active.server_pending = false;
                                }
                            }
                            maybe_finish_active_search(
                                state,
                                app_handle,
                                followup_id,
                            );
                        }
                    }
                }
            }

            if server_disconnect_reason.is_none() && state.server_connected {
                state.server_poll_count += 1;
                if state.server_poll_count >= 30 {
                    state.server_poll_count = 0;
                    // A refusal here is a full writer queue, which the stuck
                    // write behind it resolves one way or the other, or a
                    // broken session, which the check below drops.
                    match conn.keep_alive() {
                        Ok(()) => *last_server_activity_at = chrono::Utc::now().timestamp(),
                        Err(e) => debug!("Server keep-alive not queued: {e}"),
                    }
                }
            }
            if server_disconnect_reason.is_none() {
                server_disconnect_reason = server_write_failure_reason(&conn);
            }
            // Handed to the rate-limited drain in the event loop, which sends
            // at most MAX_LOWID_CALLBACKS_PER_TURN per LOWID_CALLBACK_INTERVAL,
            // stops at the first refusal and marks only what it got out as
            // sent. One OP_FOUNDSOURCES reply can carry hundreds of LowID
            // sources, far more than the server writer's queue holds.
            if server_disconnect_reason.is_none() && state.server_connected && !pending_lowid_callbacks.is_empty() && !state.low_id {
                let queued = queue_lowid_callbacks(
                    pending_lowid_callback_queue,
                    pending_lowid_callbacks,
                );
                if queued > 0 {
                    debug!("Queued {queued} LowID callback requests from server poll");
                }
            }
            if state.server_connected {
                conn_to_restore = Some(conn);
            }
        }
        if let Some(reason) = server_disconnect_reason {
            handle_server_disconnect(
                state,
                shared_server_addr,
                app_handle,
                &reason,
            ).await;
        }
        if state.server_connected {
            state.server_connection = conn_to_restore;
        }
        for request_id in finished_search_requests {
            maybe_finish_active_search(state, app_handle, request_id);
        }
        for tid in pending_source_start_tids {
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

    // Timeout pending server search. This arm is the `server_timer`
    // tick (every 2s). The wait scales with `search_timeout_secs`
    // (a tenth, clamped 30–60s): 30s at the default 120s setting
    // (age > 14), up to 60s when the user raises the overall timeout.
    if state.pending_server_search.is_some() {
        state.server_search_age += 1;
        if state.server_search_age > server_search_age_limit(settings.search_timeout_secs) {
            if let Some(mut pending) = state.pending_server_search.take() {
                let request_id = pending.request_id;
                info!("Server search timed out, returning {} local results", pending.results.len());
                if let Some(tx) = pending.tx.take() {
                    let _ = tx.send(pending.results);
                }
                // A server that went quiet for the whole window is
                // not worth a second question — chasing it would
                // buy another full timeout of spinner.
                drop_queued_server_followup(state, request_id);
                if let Some(active) = state.active_search_request.as_mut() {
                    if active.request_id == request_id {
                        active.server_pending = false;
                    }
                }
                maybe_finish_active_search(state, app_handle, request_id);
            }
            state.server_search_age = 0;
        }
    } else {
        state.server_search_age = 0;
    }

    // An explicit Disconnect has to outlast this tick. `preferred_ed2k_server`
    // and `server_auto_reconnect` both survive going offline, so without this
    // guard the disconnect the user just asked for was undone ~2s later by
    // the drop-recovery path: the server came back on its own while
    // `uploads_halted_for_shutdown` stayed raised, leaving a session that reads
    // "server connected" in the UI and refuses every upload.
    if state.server_auto_reconnect
        && !state.user_offline.load(std::sync::atomic::Ordering::Relaxed)
        && !state.server_connected
        && state.pending_server_connect.is_none()
        && state.server_connection.is_none()
        && state.preferred_ed2k_server.is_some()
    {
        if state.server_reconnect_failures >= AUTO_CONNECT_MAX_FAILURES {
            let (ip, port) = state.preferred_ed2k_server.clone().unwrap_or_default();
            abandon_server_auto_reconnect(
                state,
                app_handle,
                &format!("could not reach preferred server {ip}:{port}"),
            );
        } else {
        let backoff_secs = server_reconnect_backoff_secs(state.server_reconnect_failures);
        let elapsed_ok = state.server_last_connect_attempt
            .map(|t| t.elapsed().as_secs() >= backoff_secs)
            .unwrap_or(true);
        if elapsed_ok {
        // Retry only the preferred server — never rotate through the list.
        let picked = state.preferred_ed2k_server.clone().map(|(ip, port)| {
            let obf_port = state
                .server_list
                .find_by_addr(&ip, port)
                .map(|s| s.obfuscation_port_tcp)
                .unwrap_or(0);
            (ip, port, obf_port)
        });
        if let Some((ip, port, obf_port)) = picked {
            let addr_str = format!("{ip}:{port}");
            let user_hash = state.user_hash;
            let nickname = settings.nickname.clone();
            let tcp_port = advertised_tcp_port(state);
            let force_plain = state.server_reconnect_failures >= 2;
            let obfuscation_enabled = state.obfuscation_enabled;
            state.server_last_connect_attempt = Some(std::time::Instant::now());
            // Pre-set server addr so upload handler can detect HighID port test callbacks
            if let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() {
                *shared_server_addr.write().await = Some(SocketAddr::new(ip_addr, port));
            }
            info!("Auto-connecting to ed2k server {addr_str} (background, attempt {}, backoff {backoff_secs}s, plain={force_plain})",
                state.server_reconnect_failures + 1);
            emit_server_log(app_handle, &format!("Connecting to {addr_str}..."));
            state.stats.server_status = "connecting".to_string();
            let _ = app_handle.emit("server-status-changed", serde_json::json!({ "status": "connecting" }));
            let app_for_auto = app_handle.clone();
            state.pending_server_connect = Some(tokio::spawn(async move {
                // One crypt→plain cycle; outer auto-reconnect retries
                // the same preferred server only (see initiate_server_connect).
                let result = async {
                    let (mut conn, resolved_addr) = try_connect_server(
                        &ip,
                        port,
                        obf_port,
                        &app_for_auto,
                        force_plain,
                        obfuscation_enabled,
                    )
                    .await
                    .map_err(|e| format!("Connect failed: {e}"))?;
                    emit_server_log(
                        &app_for_auto,
                        &format!("Sending login request (client TCP port {tcp_port})..."),
                    );
                    match conn.login(&user_hash, &nickname, tcp_port).await {
                        Ok(session) => Ok((conn, session, resolved_addr)),
                        Err(login_err) if conn.is_encrypted() => {
                            debug!("Encrypted login to {ip}:{port} failed: {login_err}, falling back to plain TCP");
                            emit_server_log(
                                &app_for_auto,
                                &format!("Encrypted login failed ({login_err}), trying plain TCP..."),
                            );
                            drop(conn);
                            let plain_addr = tokio::net::lookup_host((ip.as_str(), port))
                                .await
                                .map_err(|e| format!("Plain fallback resolve failed: {e}"))?
                                .find(|addr| addr.is_ipv4())
                                .ok_or_else(|| {
                                    format!("No IPv4 address for plain fallback {ip}:{port}")
                                })?;
                            let mut plain_conn = Ed2kServerConnection::connect(plain_addr)
                                .await
                                .map_err(|e| format!("Plain fallback connect failed: {e}"))?;
                            emit_server_log(
                                &app_for_auto,
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
        } // elapsed_ok
        } // else: failures < MAX
    }
}

fn server_write_failure_reason(conn: &ServerLink) -> Option<String> {
    conn.write_failure()
        .map(|reason| format!("server write failed, stream unusable: {reason}"))
}
