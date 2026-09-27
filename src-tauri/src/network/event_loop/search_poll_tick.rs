//! The 1 s search poll: completes the eD2K UDP search leg, drives KAD
//! searches and their eager publish sends, and finishes or reaps searches whose
//! work is done.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_search_poll_tick(
    udp_socket: &Arc<UdpSocket>,
    state: &mut NetworkState,
    settings: &AppSettings,
    dl_event_tx: &mpsc::Sender<DownloadEvent>,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    credit_manager: &Arc<RwLock<CreditManager>>,
    stats_manager: &StatsManager,
    known_files: &mut KnownFileList,
    shared_banned_ips: &upload_server::SharedBannedIps,
    shared_ember_payload: &ember::SharedEmberPayload,
    ember_payload_generation: &ember::EmberPayloadGeneration,
    geoip: &crate::geoip::GeoIpReader,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    ember_hash: [u8; 16],
    ed25519_pubkey: [u8; 32],
    ed25519_secret_key: [u8; 32],
    comment_manager: &Arc<RwLock<CommentManager>>,
    pending_kad_callbacks: &upload_server::PendingKadCallbacks,
    pending_lowid_callback_queue: &mut VecDeque<([u8; 16], u32)>,
    spam_filter: &Arc<RwLock<crate::search::spam::SpamFilter>>,
) {
    if !state.evicted_kad_sources.is_empty() {
        let evicted = std::mem::take(&mut state.evicted_kad_sources);
        let mut sm = source_manager.write().await;
        for (fh, ip, tcp_port, udp_port, user_hash, connect_options) in evicted {
            sm.register_source_full_opts(
                fh,
                ip,
                tcp_port,
                udp_port,
                user_hash,
                connect_options,
                Some(crate::types::SourceOrigin::Kad),
            );
        }
    }
    let mut udp_finished_request = None;
    if let Some(active) = state.active_search_request.as_mut() {
        if active.udp_pending {
            // Only start the timeout countdown after the throttled
            // queue is fully drained (all servers queried).
            if state.udp_search_queue.is_empty() {
                state.server_udp_search_age += 1;
            }
            // Scale the post-drain grace period from the user's
            // configured `search_timeout_secs` (a tenth of it,
            // clamped to 10-30s) instead of a hardcoded 10s that
            // ignored the setting entirely. This keeps the
            // default (120s setting -> 12s grace) close to the
            // old fixed value while giving users who raise the
            // overall timeout proportionally more time for
            // straggler UDP replies, and users who lower it a
            // floor so the leg isn't cut off unreasonably fast.
            let udp_grace_secs = (settings.search_timeout_secs / 10).clamp(10, 30);
            let now = chrono::Utc::now().timestamp();
            if udp_search_leg_should_complete(
                state.server_udp_search_age,
                udp_grace_secs,
                now,
                active.udp_search_deadline,
            ) {
                if now >= active.udp_search_deadline
                    && u64::from(state.server_udp_search_age) <= udp_grace_secs
                {
                    debug!(
                        "UDP global search for request {}: hard deadline reached while results kept arriving",
                        active.request_id
                    );
                }
                active.udp_pending = false;
                udp_finished_request = Some(active.request_id);
                state.udp_search_queue.clear();
            }
        } else {
            state.server_udp_search_age = 0;
        }
    } else {
        state.server_udp_search_age = 0;
    }
    if let Some(request_id) = udp_finished_request {
        maybe_finish_active_search(state, app_handle, request_id);
    }
    if state.stats.status == NetworkStatus::Disconnected { return; }
    let new_in_use = state.search_manager.drain_pending_in_use();
    if !new_in_use.is_empty() {
        state.routing_table.mark_contacts_in_use(&new_in_use);
    }
    // Release in-use marks for any searches still queued on
    // pending_release (legacy / non-start_search path). Search-storm
    // eviction now returns released ids from start_search and
    // finalize_removed_searches handles them immediately.
    let to_release = state.search_manager.drain_pending_release();
    if !to_release.is_empty() {
        state.routing_table.release_contacts_in_use(&to_release);
    }
    let queries = state.search_manager.poll_queries();
    for (sid, addr, msg, contact_id) in queries {
        if state.flood_protection.check_outgoing_rate(addr.ip()) {
            debug!("Throttling outgoing search {} packet to {addr}", sid.0);
            if let Some(search) = state.search_manager.get_mut(&sid) {
                search.rollback_unsent_query(contact_id, &msg);
            }
            continue;
        }
        if let Ok(packet) = messages::encode_packet(&msg) {
            let opcode = packet.get(1).copied().unwrap_or(0);
            if let Err(e) = send_kad_packet(
                udp_socket, &packet, addr, state, &contact_id,
            ).await {
                if let Some(search) = state.search_manager.get_mut(&sid) {
                    if is_kad_request_paced(&e) {
                        search.skip_paced_query(contact_id, &msg);
                    } else {
                        search.rollback_unsent_query(contact_id, &msg);
                    }
                }
                continue;
            }
            if let Some(search) = state.search_manager.get_mut(&sid) {
                search.commit_query_sent(contact_id, addr);
            }
            state.flood_protection.track_request(addr, opcode);
            // Track publish requests for ack matching. poll_queries
            // can return KadReq (routing lookup) or Publish* (store
            // phase); only the latter expect a PublishRes so only
            // those need an entry. Insert at send-time (not at
            // search completion) — peers ack within milliseconds
            // and we used to miss every single lookup-phase ack.
            let (publish_target, is_source) = match &msg {
                KadMessage::PublishSourceReq { target, .. } => (Some(*target), true),
                KadMessage::PublishKeyReq { target, .. } => (Some(*target), false),
                KadMessage::PublishNotesReq { target, .. } => (Some(*target), false),
                _ => (None, false),
            };
            if let Some(target) = publish_target {
                let file_hash = state
                    .store_source_searches
                    .get(&sid)
                    .map(|(fh, _)| *fh)
                    .unwrap_or(target);
                let now_ts = chrono::Utc::now().timestamp();
                let pending = state
                    .publish_pending
                    .entry((target, addr))
                    .or_insert((file_hash, now_ts, is_source, 0));
                pending.0 = file_hash;
                pending.1 = now_ts;
                pending.2 = is_source;
                pending.3 = pending.3.saturating_add(1);
            }
        } else if let Some(search) = state.search_manager.get_mut(&sid) {
            search.rollback_unsent_query(contact_id, &msg);
        }
    }

    // eMule StorePacket: send publish messages to within-tolerance
    // contacts DURING Lookup (not just at completion). This ensures
    // the data reaches the same live nodes that searchers discover.
    {
        let store_sids: Vec<SearchId> = state.store_source_searches.keys().copied().collect();
        for sid in store_sids {
            if let Some(search) = state.search_manager.get_mut(&sid) {
                let candidates = search.next_publish_candidates();
                if !candidates.is_empty() {
                    if let Some((file_hash, ref msg)) = state.store_source_searches.get(&sid).cloned() {
                        let opcode = kad_request_opcode(msg).unwrap_or(0);
                        // Snapshot publish target for ack tracking
                        // before the send loop (can't borrow msg
                        // across the loop otherwise).
                        let publish_target = match &msg {
                            KadMessage::PublishSourceReq { target, .. } => Some(*target),
                            KadMessage::PublishKeyReq { target, .. } => Some(*target),
                            KadMessage::PublishNotesReq { target, .. } => Some(*target),
                            _ => None,
                        };
                        for contact in &candidates {
                            let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                            if state.flood_protection.check_outgoing_rate(addr.ip()) {
                                debug!("Throttling eager source publish to {addr}");
                                continue;
                            }
                            if let Ok(packet) = messages::encode_packet(msg) {
                                let sent = send_kad_packet(
                                    udp_socket,
                                    &packet,
                                    addr,
                                    state,
                                    &contact.id,
                                )
                                .await;
                                if sent.as_ref().is_err_and(is_kad_request_paced) {
                                    if let Some(search) = state.search_manager.get_mut(&sid) {
                                        search.defer_publish(contact);
                                    }
                                }
                                if sent.is_ok() {
                                    state.flood_protection.track_request(addr, opcode);
                                    if let Some(sent_search) =
                                        state.search_manager.get_mut(&sid)
                                    {
                                        sent_search.mark_publish_sent(contact);
                                    }
                                    if let Some(target) = publish_target {
                                        let now_ts = chrono::Utc::now().timestamp();
                                        let pending = state
                                            .publish_pending
                                            .entry((target, addr))
                                            .or_insert((file_hash, now_ts, true, 0));
                                        pending.0 = file_hash;
                                        pending.1 = now_ts;
                                        pending.2 = true;
                                        pending.3 = pending.3.saturating_add(1);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // eMule StorePacket for keyword publishes: the same eager
    // per-response send as the source-publish loop above, so a
    // shared file's keywords become searchable within seconds of
    // the DHT walk finding in-tolerance nodes rather than only at
    // search completion (now held open for close to the full
    // eMule lifetime — see `check_phase_transition`). A keyword
    // batch can carry up to three 50-entry packets, so every
    // eagerly-found contact gets all of them.
    {
        let store_sids: Vec<SearchId> = state.store_keyword_searches.keys().copied().collect();
        for sid in store_sids {
            if let Some(search) = state.search_manager.get_mut(&sid) {
                let candidates = search.next_publish_candidates();
                if !candidates.is_empty() {
                    if let Some(batch) = state.store_keyword_searches.get(&sid).cloned() {
                        let Some(packets) = encode_keyword_batch(&batch) else {
                            continue;
                        };
                        for contact in &candidates {
                            let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                            if state.flood_protection.check_outgoing_rate(addr.ip()) {
                                debug!("Throttling eager keyword publish to {addr}");
                                continue;
                            }
                            // The whole batch is charged at once, so a node
                            // either gets every packet or is left for later.
                            if !kad_requests_allowed(state, addr, &packets[0], packets.len()) {
                                if let Some(search) = state.search_manager.get_mut(&sid) {
                                    search.defer_publish(contact);
                                }
                                continue;
                            }
                            let sent =
                                send_keyword_batch(udp_socket, state, &batch, &packets, addr, contact)
                                    .await;
                            // A keyword peer is complete only after
                            // every split packet reached the socket.
                            // Partial success remains retryable on
                            // the next StorePacket tick.
                            if sent == packets.len() {
                                if let Some(sent_search) =
                                    state.search_manager.get_mut(&sid)
                                {
                                    sent_search.mark_publish_sent(contact);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // StoreNotes follows the same eager StorePacket behavior as
    // source/keyword publishing. The exact payload is captured
    // when the publish search starts so lookup and completion use
    // identical tags.
    {
        let store_sids: Vec<SearchId> =
            state.pending_note_publishes.keys().copied().collect();
        for sid in store_sids {
            let candidates = state
                .search_manager
                .get_mut(&sid)
                .map(|search| search.next_publish_candidates())
                .unwrap_or_default();
            if candidates.is_empty() {
                continue;
            }
            let Some(note) = state.pending_note_publishes.get(&sid).cloned() else {
                continue;
            };
            let opcode = kad_request_opcode(&note.message).unwrap_or(0);
            for contact in &candidates {
                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                if state.flood_protection.check_outgoing_rate(addr.ip()) {
                    debug!("Throttling eager note publish to {addr}");
                    continue;
                }
                let Ok(packet) = messages::encode_packet(&note.message) else {
                    continue;
                };
                if let Err(e) = send_kad_packet(
                    udp_socket,
                    &packet,
                    addr,
                    state,
                    &contact.id,
                )
                .await
                {
                    if is_kad_request_paced(&e) {
                        if let Some(search) = state.search_manager.get_mut(&sid) {
                            search.defer_publish(contact);
                        }
                    }
                    continue;
                }
                state.flood_protection.track_request(addr, opcode);
                if let Some(search) = state.search_manager.get_mut(&sid) {
                    search.mark_publish_sent(contact);
                }
                let now_ts = chrono::Utc::now().timestamp();
                let pending = state
                    .publish_pending
                    .entry((note.file_hash, addr))
                    .or_insert((note.file_hash, now_ts, false, 0));
                pending.0 = note.file_hash;
                pending.1 = now_ts;
                pending.2 = false;
                pending.3 = pending.3.saturating_add(1);
            }
        }
    }

    // Check for completed searches
    let completed_ids: Vec<SearchId> = state.search_manager.active
        .iter()
        .filter(|(_, s)| s.completed)
        .map(|(id, _)| *id)
        .collect();

    if !state.pending_keyword_searches.is_empty() {
        let sids: Vec<SearchId> = state.pending_keyword_searches.keys().cloned().collect();
        for sid in sids {
            let Some(search) = state.search_manager.get(&sid) else { continue; };
            if search.completed { continue; }
            let Some(pending) = state.pending_keyword_searches.get(&sid) else { continue; };
            let unique_count = {
                let unique: std::collections::HashSet<&kad::types::KadId> =
                    search.results.iter().map(|r| &r.id).collect();
                unique.len()
            };
            let _ = app_handle.emit(
                "search-progress",
                SearchProgressEvent {
                    request_id: pending.request_id,
                    nodes_contacted: search.queried.len(),
                    results_so_far: unique_count,
                    phase: format!("{:?}", search.phase),
                },
            );

            let new_results = search.results.len();
            let stream_threshold = if pending.last_streamed_count == 0 { 1 } else { 20 };
            // `>=` so the first batch streams at 1 result and later
            // batches every 20 new results (strict `>` was off-by-one).
            if new_results >= pending.last_streamed_count + stream_threshold {
                let new_entries = &search.results[pending.last_streamed_count..];
                let mut batch = convert_search_results(new_entries, |ip| {
                    is_search_source_safe(state, ip)
                });
                // Pull the per-pending data out by value so we
                // don't hold an immutable borrow of
                // `state.pending_keyword_searches` across the
                // `await` below — the next statement re-borrows
                // it mutably (`get_mut`).
                let pending_request_id = pending.request_id;
                let pending_file_type_filter = pending.file_type_filter.clone();
                let pending_keywords = pending.keywords.clone();
                // Re-apply the full boolean query locally: a Kad
                // lookup only matches a single keyword hash, so
                // OR/NOT branches the responding node doesn't store
                // can slip through. Skipped for a single bare
                // keyword (already exact). `pending_keywords` still
                // seeds the spam scorer in the enrich call below.
                let pending_expr = pending.query_expr.clone();
                if !pending_expr.is_trivial() {
                    batch.retain(|r| pending_expr.matches(&r.file.name.to_lowercase()));
                }
                let resights = dedup_streamed_batch(
                    &mut state.active_search_request,
                    pending_request_id,
                    &mut batch,
                );
                // Matched on the id, like `dedup_streamed_batch` and
                // `take_search_batch_spam` beside it. Falling back to
                // `None` for a request that is no longer active meant
                // "apply no client-side filters" while still emitting
                // under this batch's own id — rows that ignore the
                // user's size, extension and Min-sources settings. An
                // empty batch is the honest answer: there is no tab
                // asking this question any more.
                let filter_ctx = state
                    .active_search_request
                    .as_ref()
                    .filter(|a| a.request_id == pending_request_id)
                    .map(|a| {
                        (a.min_size, a.max_size, a.file_extension.clone(), a.min_availability)
                    });
                if filter_ctx.is_none() {
                    batch.clear();
                }
                let (min_size, max_size, file_extension, min_availability) =
                    filter_ctx.unwrap_or((None, None, None, None));
                if !batch.is_empty() {
                    let mut batch_spam =
                        take_search_batch_spam(state, pending_request_id);
                    let mut emitted = enrich_and_emit_search_results(
                        app_handle,
                        spam_filter,
                        comment_manager,
                        settings,
                        pending_request_id,
                        batch,
                        &pending_file_type_filter,
                        min_size,
                        max_size,
                        file_extension.as_deref(),
                        min_availability,
                        &pending_keywords,
                        None,
                        Some(&mut batch_spam),
                    ).await;
                    store_search_batch_spam(
                        state,
                        pending_request_id,
                        batch_spam,
                    );
                    if let Some(active) = state.active_search_request.as_mut() {
                        if active.request_id == pending_request_id {
                            mark_streamed_hashes(active, &emitted);
                            // Seeds the running total with this
                            // slice; the re-sights below carry what
                            // it has grown to.
                            note_dht_availability(
                                active,
                                &mut emitted,
                                DhtBatchKind::Incremental,
                            );
                            let mut resights = resights;
                            note_dht_availability(
                                active,
                                &mut resights,
                                DhtBatchKind::Incremental,
                            );
                            // KAD origins never advance the ed2k stop
                            // counter; skip set is unused for these rows.
                            let no_skip = HashSet::new();
                            emit_search_resight_updates(
                                app_handle,
                                pending_request_id,
                                resights,
                                active,
                                &no_skip,
                            );
                        }
                    }
                } else if !resights.is_empty() {
                    if let Some(active) = state.active_search_request.as_mut() {
                        if active.request_id == pending_request_id {
                            let mut resights = resights;
                            note_dht_availability(
                                active,
                                &mut resights,
                                DhtBatchKind::Incremental,
                            );
                            let no_skip = HashSet::new();
                            emit_search_resight_updates(
                                app_handle,
                                pending_request_id,
                                resights,
                                active,
                                &no_skip,
                            );
                        }
                    }
                }
                if let Some(p) = state.pending_keyword_searches.get_mut(&sid) {
                    p.last_streamed_count = new_results;
                }
            }
        }
    }

    // Stream KAD source-search results into downloads as they
    // arrive, rather than waiting for the search to complete or
    // expire (up to ~60s — TIMEOUT_SOURCE 45s + 15s grace). eMule's
    // `CSearch::ProcessResult` hands each source to the partfile the
    // moment a node answers; our keyword searches already stream
    // (block above) but source searches historically only delivered
    // at completion, so a download sat visibly starved for up to a
    // minute even when KAD had answered within seconds. Here we push
    // the freshly-arrived *reachable HighID* ("direct") sources —
    // the ones that connect and transfer/queue immediately — and
    // leave the completion handler below as the authoritative
    // backstop that also drives the firewalled callback / LowID /
    // type-6 paths and the UI placeholder rows. Every delivery is
    // idempotent (per-file dedup in `inject_source_into_active_
    // transfers` and source-manager registration), so re-processing
    // the same entries at completion is a no-op.
    if !state.download_source_searches.is_empty() {
        let completed_set: std::collections::HashSet<SearchId> =
            completed_ids.iter().copied().collect();
        // Snapshot work to do while only *reading* state, so the
        // mutating pass below isn't fighting the borrow checker over
        // `state.search_manager` / `state.download_source_searches`.
        let mut to_stream: Vec<(
            SearchId,
            String,
            [u8; 16],
            usize,
            Vec<kad::messages::SearchResultEntry>,
        )> = Vec::new();
        for (sid, (tid, fh)) in &state.download_source_searches {
            if completed_set.contains(sid) {
                // The completion loop handles this sid this tick.
                continue;
            }
            let Some(search) = state.search_manager.get(sid) else {
                continue;
            };
            if !search.search_type.accepts_search_results() {
                continue;
            }
            let total = search.results.len();
            let cursor = state
                .source_search_stream_cursor
                .get(sid)
                .copied()
                .unwrap_or(0);
            if total > cursor {
                to_stream.push((
                    *sid,
                    tid.clone(),
                    *fh,
                    cursor,
                    search.results[cursor..].to_vec(),
                ));
            }
        }

        for (sid, transfer_id, fh, cursor, new_entries) in to_stream {
            let new_cursor = cursor + new_entries.len();
            let all = extract_kad_sources(&new_entries);
            // Learn Noise keys from every response, mirroring the
            // completion handler so the native-dial cache fills
            // regardless of which path (stream vs completion)
            // sees a peer first.
            let established = ember_established_addrs(state);
            harvest_ember_noise_keys(
                &mut state.ember_noise_keys,
                &all,
                &established,
                state.ember_transport.local_noise_public_key(),
            );
            let kad_sources: Vec<KadSource> = all
                .into_iter()
                .filter(|s| !is_self_source(s, state))
                .collect();

            // Direct = reachable HighID sources, same filter the
            // completion handler uses for `direct_sources`. Type-6
            // direct-callback peers are excluded (they go through the
            // UDP-punch path at completion).
            let direct_callback_present: Vec<(Ipv4Addr, u16)> = kad_sources
                .iter()
                .filter(|s| {
                    s.source_type == 6
                        && s.udp_port != 0
                        && (s.connect_options & 0x08) != 0
                })
                .map(|s| (s.ip, s.tcp_port))
                .collect();
            let direct_sources: Vec<&KadSource> = kad_sources
                .iter()
                .filter(|s| {
                    s.buddy_ip.is_none()
                        && s.tcp_port != 0
                        && !s.ip.is_unspecified()
                        && s.lowid == 0
                        && (s.source_type != 6
                            || !direct_callback_present
                                .iter()
                                .any(|(ip, p)| *ip == s.ip && *p == s.tcp_port))
                })
                .collect();

            if direct_sources.is_empty() {
                state.source_search_stream_cursor.insert(sid, new_cursor);
                continue;
            }

            // Register in the source manager first so the start /
            // inject helpers (which read sources from it) and the
            // completion backstop all observe the same set.
            {
                let mut sm = source_manager.write().await;
                for ds in &direct_sources {
                    sm.register_source_full_opts(
                        fh,
                        ds.ip,
                        ds.tcp_port,
                        ds.udp_port,
                        ds.source_user_hash.unwrap_or([0u8; 16]),
                        ds.connect_options,
                        Some(crate::types::SourceOrigin::Kad),
                    );
                }
            }

            let is_active = state.active_source_senders.contains_key(&transfer_id);
            let mut injected = 0usize;
            if is_active {
                let matching = [transfer_id.clone()];
                let dsources: Vec<(DownloadSource, u16)> = {
                    let sm = source_manager.read().await;
                    direct_sources
                        .iter()
                        .map(|ds| {
                            (
                                DownloadSource {
                                    peer_ip: ds.ip.to_string(),
                                    peer_port: ds.tcp_port,
                                    available_parts: Vec::new(),
                                    peer_user_hash: sm
                                        .get_user_hash(&fh, ds.ip, ds.tcp_port)
                                        .or(ds.source_user_hash),
                                    peer_connect_options: sm
                                        .get_connect_options(&fh, ds.ip, ds.tcp_port)
                                        .or(Some(ds.connect_options)),
                                },
                                ds.udp_port,
                            )
                        })
                        .collect()
                };
                for (ds, udp_port) in &dsources {
                    let stats = inject_source_into_active_transfers(
                        state, fh, &matching, ds, *udp_port,
                    );
                    injected += stats.injected;
                }
                if injected > 0 {
                    info!(
                        "Streamed {} KAD direct source(s) into active download {} (search {}, mid-search)",
                        injected, transfer_id, sid.0
                    );
                }
            } else if state.pending_downloads.contains_key(&transfer_id) {
                let started = try_start_pending_download_from_known_sources(
                    state,
                    &transfer_id,
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
                )
                .await;
                if started {
                    info!(
                        "Streamed {} KAD direct source(s); started download {} mid-search (search {})",
                        direct_sources.len(), transfer_id, sid.0
                    );
                }
            }

            // Refresh the visible source count + nudge any open
            // drawer without zeroing live active/queued counters the
            // multi-source worker maintains.
            if injected > 0 || !is_active {
                let sm_known = {
                    let sm = source_manager.read().await;
                    sm.source_count(&fh) as u32
                };
                let mut mgr = transfer_manager.write().await;
                mgr.update_source_total(&transfer_id, sm_known);
                if let Some((sources, active_sources, queued_sources)) =
                    mgr.source_counts(&transfer_id)
                {
                    let _ = app_handle.emit(
                        "transfer-sources",
                        &crate::types::TransferSourcesPayload {
                            id: &transfer_id,
                            sources,
                            active_sources,
                            queued_sources,
                        },
                    );
                }
            }

            state.source_search_stream_cursor.insert(sid, new_cursor);
        }

        // Prune cursors whose search has left the in-flight map
        // (completed, cancelled, or evicted) so this can't grow.
        if !state.source_search_stream_cursor.is_empty() {
            let live: std::collections::HashSet<SearchId> =
                state.download_source_searches.keys().copied().collect();
            state
                .source_search_stream_cursor
                .retain(|sid, _| live.contains(sid));
        }
    }

    for sid in completed_ids {
        if ember_rendezvous_id_reused(
            state.ember_rendezvous_search,
            sid,
            state.search_manager.get(&sid).map(|s| s.target),
        ) {
            state.ember_rendezvous_search = None;
        }
        if let Some(PendingKeywordSearch { tx, mut local_results, query_expr, request_id, file_type_filter, .. }) = state.pending_keyword_searches.remove(&sid) {
            let mut network_results = if let Some(search) = state.search_manager.get(&sid) {
                let unique: std::collections::HashSet<&kad::types::KadId> =
                    search.results.iter().map(|r| &r.id).collect();
                info!(
                    "Keyword search {} completed: {} unique files ({} raw entries from KAD), {} local results",
                    sid.0, unique.len(), search.results.len(), local_results.len()
                );
                let all_results = convert_search_results(&search.results, |ip| {
                    is_search_source_safe(state, ip)
                });
                if !query_expr.is_trivial() {
                    let before = all_results.len();
                    let filtered: Vec<SearchResult> = all_results
                        .into_iter()
                        .filter(|r| query_expr.matches(&r.file.name.to_lowercase()))
                        .collect();
                    info!(
                        "Keyword filter: {before} -> {} results (boolean query)",
                        filtered.len()
                    );
                    filtered
                } else {
                    all_results
                }
            } else {
                Vec::new()
            };
            // Already-streamed Kad hashes: push absolute availability
            // via lightweight events (no spam re-score / invoke flip).
            // Oneshot return keeps only fresh hashes + local hits.
            if let Some(active) = state.active_search_request.as_mut() {
                if active.request_id == request_id {
                    let mut resights = Vec::new();
                    network_results.retain(|r| {
                        if !r.file.hash.is_empty()
                            && active.streamed_hashes.contains(&r.file.hash)
                        {
                            resights.push(r.clone());
                            false
                        } else {
                            true
                        }
                    });
                    // A rebuild over every entry the walk gathered,
                    // so it replaces the running total rather than
                    // adding to what the slices already contributed.
                    note_dht_availability(
                        active,
                        &mut resights,
                        DhtBatchKind::Cumulative,
                    );
                    note_dht_availability(
                        active,
                        &mut network_results,
                        DhtBatchKind::Cumulative,
                    );
                    emit_search_resight_updates(
                        app_handle,
                        request_id,
                        resights,
                        active,
                        &HashSet::new(),
                    );
                }
            }
            local_results.extend(network_results);
            if let Some(active) = state.active_search_request.as_ref() {
                if active.request_id == request_id {
                    local_results = filter_results_by_client_constraints(
                        local_results,
                        active,
                    );
                } else {
                    local_results =
                        filter_results_by_type(local_results, &file_type_filter);
                }
            } else {
                local_results =
                    filter_results_by_type(local_results, &file_type_filter);
            }
            local_results
                .sort_by_key(|r| std::cmp::Reverse(r.availability));
            if local_results.len() > SEARCH_INVOKE_REPLY_MAX {
                // Not a loss of results — these are the rows that
                // were never streamed, and the ones dropped here
                // are the least-sourced of them — but it is the
                // one place a hit can leave the search without
                // ever having been shown, so it is on the record.
                debug!(
                    "search {} reply holds {} unstreamed rows; returning the {} best-sourced",
                    request_id,
                    local_results.len(),
                    SEARCH_INVOKE_REPLY_MAX,
                );
            }
            local_results.truncate(SEARCH_INVOKE_REPLY_MAX);
            // Intentional: the `search_files` IPC call returns as soon as
            // the KAD leg (normally the slowest, ~45-60s) finishes, rather
            // than blocking further for the bounded TCP-server (<=30s) and
            // UDP (<=30s) legs — those are usually already done or timed
            // out by this point, and any hits that land after this point
            // still reach the UI via streamed `search-results` events plus
            // the later `search-complete` event from
            // `maybe_finish_active_search` below. Deliberately not blocking
            // the oneshot on `active.server_pending`/`udp_pending` here
            // keeps the awaited command call latency bounded by the KAD
            // leg instead of the sum of all three.
            let _ = tx.send(local_results);
            if let Some(active) = state.active_search_request.as_mut() {
                if active.request_id == request_id {
                    active.kad_pending = false;
                }
            }
            maybe_finish_active_search(state, app_handle, request_id);
        } else if state.ember_rendezvous_search == Some(sid) {
            // Ember rendezvous lookup. Its whole purpose is the
            // Noise keys the returned sources carry — the DHT bridge
            // picks them up on the next maintenance tick — so the
            // source list itself is discarded rather than injected
            // anywhere. Not a real file, so nothing wants it.
            state.ember_rendezvous_search = None;
            let (found, peers) = if let Some(search) = state.search_manager.get(&sid) {
                let all = extract_kad_sources(&search.results);
                let found = all.len();
                // Our own advert is always in these results — we put
                // it there. Drop it before caching, or the bridge
                // spends a ping dialing this node's own address.
                let peers: Vec<KadSource> = all
                    .into_iter()
                    .filter(|s| !is_self_source(s, state))
                    .collect();
                (found, peers)
            } else {
                (0, Vec::new())
            };
            let established = ember_established_addrs(state);
            // Measured across the harvest: reporting the cache size
            // credited this lookup with every key the session had
            // already learned, so on a warm cache a lookup that
            // harvested nothing still logged a large number — the
            // opposite of what the only cold-join diagnostic needs
            // to say.
            let keys_before = state.ember_noise_keys.len();
            harvest_ember_noise_keys(
                &mut state.ember_noise_keys,
                &peers,
                &established,
                state.ember_transport.local_noise_public_key(),
            );
            let keys_learned = state.ember_noise_keys.len().saturating_sub(keys_before);
            let converted = ember_rendezvous_converted_contacts(state, &peers);
            note_ember_rendezvous_lookup(state, peers.len(), converted);
            info!(
                "Ember rendezvous lookup finished: {found} advertised peer(s), \
                 {} after dropping self, {converted} already overlay contact(s), \
                 {keys_learned} new dialable Noise key(s) \
                 ({} cached in total)",
                peers.len(),
                state.ember_noise_keys.len()
            );
        } else if let Some((transfer_id, search_file_hash)) = state.download_source_searches.remove(&sid) {
            // `transfer_id` gets moved into `pending_downloads`
            // in several of the branches below; keep an owned
            // copy so we can fire a single post-write UI refresh
            // signal at the end regardless of which branch ran.
            let refresh_transfer_id = transfer_id.clone();
            let kad_sources = if let Some(search) = state.search_manager.get(&sid) {
                let all = extract_kad_sources(&search.results);
                // Learn the peer's Noise pubkey so Ember-native
                // dialing doesn't require a separate exchange.
                // Done here rather than inside
                // `extract_kad_sources` to keep that helper a pure
                // function with no `state` dependency.
                let established = ember_established_addrs(state);
                for s in &all {
                    if !s.ip.is_unspecified() && s.tcp_port != 0 {
                        // Cache the Noise key under the peer's UDP
                        // port: Ember's Noise transport runs over
                        // UDP (the shared KAD socket), so every
                        // bridge/dial path must target udp_port,
                        // not the eMule TCP port. A peer that
                        // advertised no UDP port can't be Ember-
                        // dialed, so skip caching it.
                        if let Some(npub) = s.ember_noise_pub {
                            if s.udp_port != 0
                                && npub != *state.ember_transport.local_noise_public_key()
                            {
                                let pinned =
                                    established.contains(&(s.ip, s.udp_port));
                                if let Some(_held) = cache_bound_ember_noise_key(
                                    &mut state.ember_noise_keys,
                                    s.ip,
                                    s.udp_port,
                                    npub,
                                    pinned,
                                ) {
                                    debug!(
                                        "Ignoring conflicting KAD ember_npub for {}:{} (key of a live contact is pinned)",
                                        s.ip, s.udp_port
                                    );
                                }
                            }
                        }
                    }
                }
                let before = all.len();
                let filtered: Vec<KadSource> = all
                    .into_iter()
                    .filter(|s| !is_self_source(s, state))
                    .collect();
                if filtered.len() != before {
                    debug!(
                        "Download source search {} for {}: dropped {} self-sources",
                        sid.0,
                        transfer_id,
                        before - filtered.len()
                    );
                }
                filtered
            } else {
                Vec::new()
            };

            // Real-world compatibility: many clients mix source-type semantics.
            // Treat entries without buddy info as direct candidates and entries
            // with buddy info as callback candidates.
            // Type-6 sources that qualify for direct UDP callback go into
            // direct_callback_sources; remaining type-6 with valid TCP info
            // are treated as regular direct sources (eMule fallback).
            let direct_callback_sources: Vec<&KadSource> = kad_sources.iter()
                .filter(|s| s.source_type == 6 && s.udp_port != 0 && (s.connect_options & 0x08) != 0)
                .collect();
            let direct_sources: Vec<&KadSource> = kad_sources.iter()
                .filter(|s| {
                    s.buddy_ip.is_none()
                        && s.tcp_port != 0
                        && !s.ip.is_unspecified()
                        && s.lowid == 0
                        && (s.source_type != 6
                            || !direct_callback_sources.iter().any(|dc| dc.ip == s.ip && dc.tcp_port == s.tcp_port))
                })
                .collect();
            let callback_sources: Vec<&KadSource> = kad_sources.iter()
                .filter(|s| s.buddy_ip.is_some() && matches!(s.source_type, 3 | 5))
                .collect();
            let lowid_sources: Vec<&KadSource> = kad_sources.iter()
                .filter(|s| s.source_type == 2 && s.lowid > 0 && s.ed2k_server_ip != 0)
                .collect();
            let type6_count = direct_callback_sources.len();

            let total_kad_sources = direct_sources.len() + callback_sources.len() + type6_count + lowid_sources.len();
            info!(
                "Download source search {} completed for {}: {} direct, {} callback, {} direct-callback (type 6), {} lowid (type 2)",
                sid.0, transfer_id, direct_sources.len(), callback_sources.len(), type6_count, lowid_sources.len()
            );
            let _ = app_handle.emit("transfer:source-search", serde_json::json!({
                "transfer_id": &transfer_id,
                "kind": if total_kad_sources == 0 { "kad_empty" }
                        else if direct_sources.is_empty() { "kad_indirect" }
                        else { "kad_found" },
                "count": total_kad_sources,
            }));

            // File hash is carried in `download_source_searches`
            // alongside the transfer_id — it was captured when
            // the search was started and no longer depends on
            // `pending_downloads` (which is consumed by
            // `try_start_from_known` the moment server-side
            // sources arrive, leaving in-flight KAD searches
            // orphaned under the old design).
            let resolved_file_hash: Option<[u8; 16]> = Some(search_file_hash);

            // Send KADEMLIA_CALLBACK_REQ for buddy-backed callback sources.
            if !callback_sources.is_empty() {
                let file_hash_bytes = resolved_file_hash;

                if let Some(fh) = file_hash_bytes {
                    for cb_src in &callback_sources {
                        let Some(buddy_ip) = cb_src.buddy_ip else {
                            debug!("Skipping callback source: no buddy IP");
                            continue;
                        };
                        if kad::ip_filter::is_private_or_reserved(buddy_ip) {
                            debug!("Skipping callback source: buddy IP {} is private/unroutable", buddy_ip);
                            continue;
                        }
                        // Per eMule `Search.cpp:669`,
                        // `TAG_SERVERPORT` is declared as
                        // `theApp.clientlist->GetBuddy()->GetUDPPort()` —
                        // i.e. the buddy's eMule UDP listen
                        // port. In practice the field gets
                        // published inconsistently in the
                        // wild: some clients (modern eMule
                        // on a classic setup) publish the
                        // UDP port (e.g. 4675), others
                        // (aMule, several eMule mods, and
                        // clients whose buddy record came
                        // from KAD `IncomingBuddy` which
                        // only calls `SetKadPort` and
                        // leaves `m_nUDPPort == 0` until a
                        // subsequent Hello fills it) end up
                        // publishing a value that's really
                        // the buddy's TCP port (e.g. 4672),
                        // expecting callers to apply the
                        // `UDP = TCP + 3` convention.
                        //
                        // We can't tell which flavour a
                        // given source record uses without
                        // probing. The packet is ~40 bytes;
                        // rather than guess wrong half the
                        // time and send every
                        // `KADEMLIA_CALLBACK_REQ` to the
                        // void (the pre-fix bug shipped
                        // `port + 3` unconditionally; the
                        // post-fix bug shipped `port`
                        // unconditionally — both failed ~100%
                        // of the time against the
                        // opposite-flavour publishers),
                        // try `TAG_SERVERPORT` and
                        // `TAG_SERVERPORT + 3` on
                        // *alternating* attempts. Exactly one
                        // of the two lands on the buddy's
                        // actual UDP listener; the other is
                        // dropped by the OS as "no such
                        // socket".
                        //
                        // Sending both at once is what must
                        // not happen: it is two packets to
                        // one IP inside eMule's one-per-minute
                        // budget for this opcode, which after
                        // a couple of attempts starts dropping
                        // the *primary* packet too and ends in
                        // a two-hour ban. See
                        // `kad_callback_buddy_port`.
                        let buddy_port_raw = cb_src.buddy_port.unwrap_or(0);
                        if buddy_port_raw == 0 {
                            debug!("Skipping callback source: no buddy UDP port in TAG_SERVERPORT");
                            continue;
                        }
                        // `cb_src.buddy_hash` is the
                        // `TAG_BUDDYHASH` value published by
                        // the LowID peer, which eMule
                        // `Search.cpp:665-670` computes as
                        // `NOT(LowID_peer_kad_id)` — a
                        // verification token, NOT the
                        // buddy's actual KAD ID. The LowID
                        // peer's `OP_CALLBACK` handler
                        // (`ListenSocket.cpp:1337-1358`)
                        // accepts the callback iff
                        // `received_token XOR all_ones ==
                        // my_kad_id`. We forward this
                        // token unmodified as the first
                        // 128-bit field of
                        // `KADEMLIA_CALLBACK_REQ` so the
                        // buddy relays it to its LowID
                        // client via `OP_CALLBACK` with
                        // `uCheck` intact.
                        //
                        // Looking this hash up in our
                        // routing table to resolve the
                        // buddy's UDP port was always
                        // wrong — there's no contact with
                        // ID = NOT(LowID_peer_kad_id) in
                        // the routing table except by
                        // astronomical coincidence.
                        let buddy_hash = match &cb_src.buddy_hash {
                            Some(h) => *h,
                            None => {
                                debug!("Skipping callback source {}: no buddy hash", buddy_ip);
                                continue;
                            }
                        };

                        {
                            let pfs = state.per_file_sources
                                .entry(transfer_id.clone())
                                .or_insert_with(|| ed2k::sources::PerFileSourceList::new(fh));
                            let is_new = pfs.add_source_with_identity(
                                cb_src.ip,
                                cb_src.tcp_port,
                                0,
                                cb_src.source_user_hash,
                            );
                            if is_new {
                                state.ember_payload_dirty = true;
                            }
                            pfs.set_kad_callback_buddy(
                                cb_src.ip,
                                cb_src.tcp_port,
                                buddy_ip,
                                buddy_port_raw,
                                buddy_hash.0,
                                cb_src.source_user_hash,
                                is_new,
                            );
                            if state.firewalled || state.low_id {
                                let broker_started = if !cb_src.is_ember_capable {
                                    debug!(
                                        "Skipping LowID-to-LowID broker for {}:{} — \
                                         no Ember capability advertised in KAD record",
                                        cb_src.ip, cb_src.tcp_port,
                                    );
                                    false
                                } else if let Some(ref mut broker) = state.connection_broker {
                                    // See the matching comment at the other
                                    // `attempt_low_to_low` call site above: advertise
                                    // our QUIC bind port, not the KAD-UDP-probed one.
                                    let ext = state.nat_info.external_addr.map(|addr| {
                                        SocketAddr::new(addr.ip(), state.quic_port.unwrap_or(state.tcp_port))
                                    });
                                    broker.attempt_low_to_low(
                                        &transfer_id, fh, cb_src.ip, cb_src.tcp_port,
                                        state.nat_info.nat_type, ext,
                                    ).await
                                } else {
                                    false
                                };
                                if broker_started {
                                    pfs.set_ember_relay(cb_src.ip, cb_src.tcp_port, cb_src.source_user_hash);
                                } else {
                                    pfs.set_low_to_low(cb_src.ip, cb_src.tcp_port, cb_src.source_user_hash);
                                }
                            }
                        }

                        let (should_send, attempt) = state
                            .per_file_sources
                            .get(&transfer_id)
                            .map(|pfs| {
                                (
                                    pfs.callback_reask_due(cb_src.ip, cb_src.tcp_port, cb_src.source_user_hash),
                                    pfs.callback_attempts(cb_src.ip, cb_src.tcp_port, cb_src.source_user_hash),
                                )
                            })
                            .unwrap_or((false, 0));
                        if !should_send {
                            continue;
                        }

                        let buddy_addr_sent = SocketAddr::new(
                            buddy_ip.into(),
                            kad_callback_buddy_port(buddy_port_raw, attempt),
                        );
                        if send_kad_callback_req(
                            udp_socket,
                            state,
                            buddy_ip,
                            buddy_port_raw,
                            buddy_hash,
                            fh,
                            attempt,
                        ).await {
                            if let Some(pfs) = state.per_file_sources.get_mut(&transfer_id) {
                                pfs.mark_callback_requested(cb_src.ip, cb_src.tcp_port, cb_src.source_user_hash);
                            }
                            register_or_refresh_pending_kad_callback(
                                pending_kad_callbacks,
                                cb_src.ip,
                                cb_src.tcp_port,
                                fh,
                                cb_src.source_user_hash,
                                crate::types::SourceOrigin::Kad,
                            ).await;
                            info!(
                                "Sent KAD CallbackReq to buddy {} at {} (attempt {}) for file {}",
                                buddy_hash,
                                buddy_addr_sent,
                                attempt + 1,
                                hex::encode(fh),
                            );
                        }
                    }
                }
            }

            // Send OP_DIRECTCALLBACKREQ for direct-callback sources.
            if !direct_callback_sources.is_empty() {
                for ds in &direct_callback_sources {
                    let addr = SocketAddr::new(ds.ip.into(), ds.udp_port);
                    let mut pkt = vec![OP_EMULEPROT, ed2k::messages::OP_DIRECTCALLBACKREQ];
                    // Tell the peer the STUN-confirmed public port
                    // to connect back to, not the raw local bind
                    // port (same reasoning as CallbackReq/HelloRes).
                    pkt.extend_from_slice(&advertised_tcp_port(state).to_le_bytes());
                    pkt.extend_from_slice(&state.user_hash);
                    pkt.push(build_kad_connect_options(state) & 0x07);
                    // Match eMule: when the peer advertises crypt support and we
                    // have crypt enabled, obfuscate OP_DIRECTCALLBACKREQ with the
                    // ED2K client UDP layer keyed on the source's user hash and our
                    // public IP. Many modern clients silently drop a plain
                    // direct-callback request. Falls back to plaintext if we lack
                    // the source's user hash or our own external IP (the receiver
                    // would otherwise derive a non-matching key).
                    let obf_pkt = if state.obfuscation_enabled
                        && (ds.connect_options & 0x01) != 0
                    {
                        match (ds.source_user_hash, state.external_ip) {
                            (Some(uh), Some(eip)) => Some(
                                kad::obfuscation::encrypt_client_ed2k_packet(
                                    &pkt,
                                    &uh,
                                    eip.octets(),
                                ),
                            ),
                            _ => None,
                        }
                    } else {
                        None
                    };
                    let send_ok = match &obf_pkt {
                        Some(enc) => udp_socket.send_to(enc, addr).await.is_ok(),
                        None => udp_socket.send_to(&pkt, addr).await.is_ok(),
                    };
                    if send_ok {
                        info!(
                            "Sent OP_DIRECTCALLBACKREQ to type-6 source {}:{} (tcp_port={}, obfuscated={})",
                            ds.ip,
                            ds.udp_port,
                            ds.tcp_port,
                            obf_pkt.is_some(),
                        );
                        // Register only after a successful send — same
                        // track-after-send rule as buddy CallbackReq.
                        if let Some(fh) = resolved_file_hash {
                            register_or_refresh_pending_kad_callback(
                                pending_kad_callbacks,
                                ds.ip,
                                ds.tcp_port,
                                fh,
                                ds.source_user_hash,
                                crate::types::SourceOrigin::Kad,
                            ).await;
                        }
                    } else {
                        warn!(
                            "Failed to send OP_DIRECTCALLBACKREQ to type-6 source {}:{}",
                            ds.ip, ds.udp_port
                        );
                    }
                }
            }

            let sources: Vec<(String, u16)> = direct_sources.iter()
                .map(|s| (s.ip.to_string(), s.tcp_port))
                .collect();

            // For KAD source-search results, the entry ID carries the source's
            // ED2K user hash (eMule Search.cpp STOREFILE sender_id).
            if let Some(fh) = resolved_file_hash {
                let mut sm = source_manager.write().await;
                for ds in &direct_sources {
                    sm.register_source_full_opts(
                        fh,
                        ds.ip,
                        ds.tcp_port,
                        ds.udp_port,
                        ds.source_user_hash.unwrap_or([0u8; 16]),
                        ds.connect_options,
                        Some(crate::types::SourceOrigin::Kad),
                    );
                }
            }

            // Register Type-2 (eD2K LowID) sources in the source manager;
            // the existing server poll loop will send OP_CALLBACKREQUEST.
            // Without a server connection these sources are unreachable,
            // so skip registration and don't count them.
            let effective_lowid = if !lowid_sources.is_empty() && state.server_connected {
                if let Some(fh) = resolved_file_hash {
                    let mut sm = source_manager.write().await;
                    for ls in &lowid_sources {
                        sm.register_lowid_source(
                            fh,
                            ls.lowid,
                            ls.tcp_port,
                            ls.ed2k_server_ip,
                            ls.ed2k_server_port,
                            ls.source_user_hash.unwrap_or([0u8; 16]),
                            ls.connect_options,
                            // A KAD answer that happens to name the
                            // server the peer is registered on. KAD
                            // found it; the server is only the route.
                            Some(crate::types::SourceOrigin::Kad),
                        );
                    }
                    info!(
                        "Registered {} Type-2 LowID sources for {}, queuing server callbacks",
                        lowid_sources.len(), transfer_id
                    );
                    // Enqueue callbacks immediately when HighID on the
                    // matching server — do not wait for FoundSources.
                    if !state.low_id {
                        if let Some(addr) = state.server_addr {
                            if let std::net::IpAddr::V4(v4) = addr.ip() {
                                let srv_ip = u32::from_le_bytes(v4.octets());
                                let srv_port = addr.port();
                                queue_lowid_callbacks(
                                    pending_lowid_callback_queue,
                                    lowid_sources
                                        .iter()
                                        .filter(|ls| {
                                            ls.ed2k_server_ip == srv_ip
                                                && ls.ed2k_server_port == srv_port
                                        })
                                        .map(|ls| (fh, ls.lowid)),
                                );
                            }
                        }
                    }
                }
                lowid_sources.len()
            } else {
                if !lowid_sources.is_empty() {
                    info!(
                        "Skipping {} Type-2 LowID sources for {} (no server connected, cannot relay callback)",
                        lowid_sources.len(), transfer_id
                    );
                }
                0
            };

            let total_found = sources.len() + callback_sources.len() + effective_lowid;

            if let Some(pending) = state.pending_downloads.remove(&transfer_id) {
                if sources.is_empty() && callback_sources.is_empty() && effective_lowid == 0 {
                    info!("No sources found yet for {transfer_id}, will retry later");
                    insert_pending_download_bounded(&mut state.pending_downloads, transfer_id, pending);
                } else if sources.is_empty() {
                    // Only callback/LowID sources — keep pending; callbacks
                    // will arrive via kad_callback_rx or server poll.
                    let indirect_count = callback_sources.len() + effective_lowid + type6_count;
                    info!(
                        "Only indirect sources for {transfer_id}: {} callback, {} lowid, {} type6 — waiting for callbacks",
                        callback_sources.len(), effective_lowid, type6_count
                    );
                    {
                        let mut mgr = transfer_manager.write().await;
                        mgr.update_source_total(&transfer_id, indirect_count as u32);
                        // Skip rows when the peer IP is already
                        // represented — either by an existing
                        // placeholder from a prior search cycle
                        // or by the real `(ip, ephemeral_port)`
                        // row the callback arrived on. Without
                        // the guard each ~45s search refresh
                        // stomps the placeholder back to
                        // `Connecting`, producing duplicate
                        // rows for peers that are already
                        // queued or transferring.
                        let now_ts = chrono::Utc::now().timestamp();
                        for cb_src in &callback_sources {
                            let ip_s = upload_server::kad_callback_display_key(
                                cb_src.ip,
                                cb_src.source_user_hash,
                            );
                            if mgr.has_source_detail_for_ip(&transfer_id, &ip_s) {
                                continue;
                            }
                            mgr.update_source_detail(
                                &transfer_id,
                                crate::types::SourceInfo {
                                    ip: ip_s.clone(),
                                    port: cb_src.tcp_port,
                                    status: crate::types::SourceStatus::WaitCallback,
                                    queue_rank: None,
                                    speed: 0,
                                    transferred: 0,
                                    // Empty, not "KAD Callback":
                                    // we have not spoken to this
                                    // peer yet, so we do not know
                                    // what it runs. The two facts
                                    // that string used to stand in
                                    // for now have fields of their
                                    // own.
                                    client_software: String::new(),
                                    peer_name: String::new(),
                                    available_parts: None,
                                    total_parts: None,
                                    country_code: crate::geoip::lookup_country(geoip, std::net::IpAddr::V4(cb_src.ip)),
                                    user_hash: cb_src.source_user_hash,
                                    origin: Some(crate::types::SourceOrigin::Kad),
                                    placeholder: true,
                                },
                            );
                            // Fresh row → fresh timestamp, always.
                            // Overwrites any stale entry left over
                            // from a prior pause/resume cycle
                            // where `source_details` was cleared
                            // but we hadn't swept the timestamp
                            // map yet.
                            state.callback_row_pending_since.insert(
                                (transfer_id.clone(), ip_s, cb_src.tcp_port),
                                now_ts,
                            );
                        }
                        for dc_src in &direct_callback_sources {
                            let ip_s = dc_src.ip.to_string();
                            if mgr.has_source_detail_for_ip(&transfer_id, &ip_s) {
                                continue;
                            }
                            mgr.update_source_detail(
                                &transfer_id,
                                crate::types::SourceInfo {
                                    ip: ip_s.clone(),
                                    port: dc_src.tcp_port,
                                    status: crate::types::SourceStatus::WaitCallback,
                                    queue_rank: None,
                                    speed: 0,
                                    transferred: 0,
                                    client_software: String::new(),
                                    peer_name: String::new(),
                                    available_parts: None,
                                    total_parts: None,
                                    country_code: crate::geoip::lookup_country(geoip, std::net::IpAddr::V4(dc_src.ip)),
                                    user_hash: dc_src.source_user_hash,
                                    origin: Some(crate::types::SourceOrigin::Kad),
                                    placeholder: true,
                                },
                            );
                            state.callback_row_pending_since.insert(
                                (transfer_id.clone(), ip_s, dc_src.tcp_port),
                                now_ts,
                            );
                        }
                        for ls in &lowid_sources {
                            if state.server_connected {
                                let ip_str = Ipv4Addr::from(ls.ed2k_server_ip).to_string();
                                if mgr.has_source_detail_for_ip(&transfer_id, &ip_str) {
                                    continue;
                                }
                                mgr.update_source_detail(
                                    &transfer_id,
                                    crate::types::SourceInfo {
                                        ip: ip_str.clone(),
                                        port: ls.ed2k_server_port,
                                        status: crate::types::SourceStatus::WaitCallback,
                                        queue_rank: None,
                                        speed: 0,
                                        transferred: 0,
                                        client_software: String::new(),
                                        peer_name: String::new(),
                                        available_parts: None,
                                        total_parts: None,
                                        country_code: crate::geoip::lookup_country(geoip, std::net::IpAddr::V4(ls.ip)),
                                        user_hash: ls.source_user_hash,
                                        // A LowID peer only reachable
                                        // because a server will relay
                                        // our callback to it.
                                        origin: Some(crate::types::SourceOrigin::Server),
                                        placeholder: true,
                                    },
                                );
                                state.callback_row_pending_since.insert(
                                    (transfer_id.clone(), ip_str, ls.ed2k_server_port),
                                    now_ts,
                                );
                            }
                        }
                    }
                    let _ = app_handle.emit("transfer-status", serde_json::json!({
                        "id": &transfer_id,
                        "status": "searching",
                        "sources": indirect_count,
                    }));
                    insert_pending_download_bounded(&mut state.pending_downloads, transfer_id, pending);
                } else {
                    let hash_bytes = match hex::decode(&pending.file_hash) {
                        Ok(b) if b.len() == 16 => {
                            let mut arr = [0u8; 16];
                            arr.copy_from_slice(&b);
                            arr
                        }
                        _ => {
                            error!("Bad hash in pending download, re-queuing for retry");
                            insert_pending_download_bounded(&mut state.pending_downloads, transfer_id, pending);
                            continue;
                        }
                    };

                    let sm_known = {
                        let sm = source_manager.read().await;
                        sm.source_count(&hash_bytes) as u32
                    };
                    // Include type-6 (direct-callback) in the
                    // visible-sources count. `total_found`
                    // is derived from
                    // `sources.len() + callback_sources.len()
                    //  + effective_lowid`, which deliberately
                    // omits type-6 because direct-callback is
                    // handled via a separate code path. But
                    // from the user's perspective a type-6
                    // source is "a source for this file that
                    // we're trying to reach" and must show
                    // up in the transfer's source count —
                    // otherwise sessions with several type-6
                    // peers display a source count
                    // significantly lower than eMule's for
                    // the same file.
                    let visible_total = (total_found as u32).saturating_add(type6_count as u32);
                    let source_count = visible_total.max(sm_known);
                    // Release this transfer-manager write guard before the
                    // source_manager locks and the `live_sources.is_empty()`
                    // branch below: that branch re-acquires
                    // `transfer_manager.write()`, which is not reentrant, so
                    // holding the guard across it deadlocks the network task.
                    {
                        let mut mgr = transfer_manager.write().await;
                        mgr.update_status(&transfer_id, TransferStatus::Active);
                        mgr.update_sources(&transfer_id, source_count, 0, 0);
                        for (ip_s, port) in &sources {
                            let cc = ip_s.parse::<std::net::IpAddr>().ok()
                                .and_then(|ip| crate::geoip::lookup_country(geoip, ip));
                            mgr.update_source_detail(
                                &transfer_id,
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
                                    // `sources` here is the KAD
                                    // search's own answer list.
                                    origin: Some(crate::types::SourceOrigin::Kad),
                                    placeholder: false,
                                },
                            );
                        }
                        // Also populate the per-source detail
                        // rows for callback and type-6
                        // (direct-callback) sources. These
                        // are REAL sources we're actively
                        // trying to reach — the CallbackReq
                        // has already been sent to each
                        // buddy (see `callback_sources` loop
                        // earlier in this function) and
                        // DIRECTCALLBACKREQ to each type-6
                        // peer — so they belong in the
                        // transfer's source table just as
                        // much as HighID direct sources.
                        // The previously-existing code only
                        // registered these rows in the
                        // "indirect-only" branch (when
                        // `sources.is_empty()`); the same
                        // sources being ALSO present as
                        // direct candidates caused the
                        // branch above to be taken, which
                        // silently dropped the callback /
                        // type-6 rows from the UI. Status
                        // starts as `Connecting` for both
                        // — the callback branch transitions
                        // to `Queued` / `Transferring` once
                        // the buddy relays and the LowID
                        // peer connects back to us; the
                        // type-6 branch transitions on the
                        // UDP punch-response.
                        // Skip callback/type-6 placeholders when
                        // the peer IP is already represented.
                        // See the parallel block in the
                        // "only indirect sources" branch for
                        // the full rationale — essentially
                        // the real callback connection lands
                        // on an ephemeral port that doesn't
                        // match the listed listening port,
                        // so a refreshed placeholder would
                        // duplicate-row the same peer.
                        let now_ts = chrono::Utc::now().timestamp();
                        for cb_src in &callback_sources {
                            let ip_s = upload_server::kad_callback_display_key(
                                cb_src.ip,
                                cb_src.source_user_hash,
                            );
                            if mgr.has_source_detail_for_ip(&transfer_id, &ip_s) {
                                continue;
                            }
                            let cc = crate::geoip::lookup_country(
                                geoip, std::net::IpAddr::V4(cb_src.ip),
                            );
                            mgr.update_source_detail(
                                &transfer_id,
                                crate::types::SourceInfo {
                                    ip: ip_s.clone(),
                                    port: cb_src.tcp_port,
                                    status: crate::types::SourceStatus::WaitCallback,
                                    queue_rank: None,
                                    speed: 0,
                                    transferred: 0,
                                    client_software: String::new(),
                                    peer_name: String::new(),
                                    available_parts: None,
                                    total_parts: None,
                                    country_code: cc,
                                    user_hash: cb_src.source_user_hash,
                                    origin: Some(crate::types::SourceOrigin::Kad),
                                    placeholder: true,
                                },
                            );
                            // Fresh row → fresh timestamp, always.
                            // Overwrites any stale entry left over
                            // from a prior pause/resume cycle
                            // where `source_details` was cleared
                            // but we hadn't swept the timestamp
                            // map yet.
                            state.callback_row_pending_since.insert(
                                (transfer_id.clone(), ip_s, cb_src.tcp_port),
                                now_ts,
                            );
                        }
                        for dc_src in &direct_callback_sources {
                            let ip_s = dc_src.ip.to_string();
                            if mgr.has_source_detail_for_ip(&transfer_id, &ip_s) {
                                continue;
                            }
                            let cc = crate::geoip::lookup_country(
                                geoip, std::net::IpAddr::V4(dc_src.ip),
                            );
                            mgr.update_source_detail(
                                &transfer_id,
                                crate::types::SourceInfo {
                                    ip: ip_s.clone(),
                                    port: dc_src.tcp_port,
                                    status: crate::types::SourceStatus::WaitCallback,
                                    queue_rank: None,
                                    speed: 0,
                                    transferred: 0,
                                    client_software: String::new(),
                                    peer_name: String::new(),
                                    available_parts: None,
                                    total_parts: None,
                                    country_code: cc,
                                    user_hash: dc_src.source_user_hash,
                                    origin: Some(crate::types::SourceOrigin::Kad),
                                    placeholder: true,
                                },
                            );
                            state.callback_row_pending_since.insert(
                                (transfer_id.clone(), ip_s, dc_src.tcp_port),
                                now_ts,
                            );
                        }
                        // Parity with the indirect-only branch:
                        // populate Server-Relay ("Low ID") placeholder
                        // rows so mixed KAD results (direct HighID
                        // + Type-2 LowID via connected server) show
                        // ALL the peers we're pursuing, not just
                        // the direct ones. Without this the user
                        // sees e.g. "7 sources found" in the
                        // summary but a shorter list in the detail
                        // panel whenever a download has both
                        // reachable-direct and Low-ID candidates —
                        // same visual inconsistency that motivated
                        // the callback placeholder rows in the
                        // first place.
                        for ls in &lowid_sources {
                            if !state.server_connected {
                                continue;
                            }
                            let ip_str = Ipv4Addr::from(ls.ed2k_server_ip).to_string();
                            if mgr.has_source_detail_for_ip(&transfer_id, &ip_str) {
                                continue;
                            }
                            mgr.update_source_detail(
                                &transfer_id,
                                crate::types::SourceInfo {
                                    ip: ip_str.clone(),
                                    port: ls.ed2k_server_port,
                                    status: crate::types::SourceStatus::WaitCallback,
                                    queue_rank: None,
                                    speed: 0,
                                    transferred: 0,
                                    client_software: String::new(),
                                    peer_name: String::new(),
                                    available_parts: None,
                                    total_parts: None,
                                    country_code: crate::geoip::lookup_country(
                                        geoip, std::net::IpAddr::V4(ls.ip),
                                    ),
                                    user_hash: ls.source_user_hash,
                                    origin: Some(crate::types::SourceOrigin::Server),
                                    placeholder: true,
                                },
                            );
                            state.callback_row_pending_since.insert(
                                (transfer_id.clone(), ip_str, ls.ed2k_server_port),
                                now_ts,
                            );
                        }
                    }
                    let peer_desc = sources.iter()
                        .map(|(ip, port)| format!("{ip}:{port}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let _ = app_handle.emit("transfer-status", serde_json::json!({
                        "id": transfer_id,
                        "status": "active",
                        "peer_id": peer_desc,
                        "sources": source_count,
                        "active_sources": 0,
                        "queued_sources": 0,
                    }));

                    // Populate persistent per-file source list
                    {
                        let pfs = state.per_file_sources
                            .entry(transfer_id.clone())
                            .or_insert_with(|| ed2k::sources::PerFileSourceList::new(hash_bytes));
                        for (ip_s, port) in &sources {
                            if let Ok(v4) = ip_s.parse::<Ipv4Addr>() {
                                let udp_port = {
                                    let sm = source_manager.read().await;
                                    sm.get_udp_sources(&hash_bytes)
                                        .into_iter()
                                        .find(|(ip, tcp_port, _)| ip == &v4 && tcp_port == port)
                                        .map(|(_, _, udp)| udp)
                                        .unwrap_or(0)
                                };
                                if pfs.add_source_full(v4, *port, udp_port) {
                                    state.ember_payload_dirty = true;
                                }
                            }
                        }
                    }

                    {
                        let live_sources: Vec<&(String, u16)> = sources
                            .iter()
                            .filter(|(ip, port)| {
                                if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                                    !state.dead_sources.is_dead_source_for_file(&hash_bytes, u32::from(v4), *port)
                                        && is_source_admissible(state, v4, *port, None)
                                } else {
                                    false
                                }
                            })
                            .collect();
                        if live_sources.is_empty() {
                            debug!("All {} sources are dead for {transfer_id}, re-queuing", sources.len());
                            // Revert the just-emitted Active transition:
                            // we set status=Active + emitted the
                            // `transfer-status` event up above in the
                            // optimistic path, but now we've discovered
                            // every candidate is on the dead-source
                            // cooldown list so no worker is actually
                            // going to start. Flip back to Searching
                            // and re-emit so the UI lifecycle phase
                            // (and the priority badge, health color,
                            // context menu entries, etc.) reflects
                            // reality instead of sitting at Active
                            // with 0 peers until the next retry tick.
                            {
                                let mut mgr = transfer_manager.write().await;
                                mgr.update_status(
                                    &transfer_id,
                                    TransferStatus::Searching,
                                );
                            }
                            let _ = app_handle.emit(
                                "transfer-status",
                                serde_json::json!({
                                    "id": &transfer_id,
                                    "status": "searching",
                                }),
                            );
                            insert_pending_download_bounded(&mut state.pending_downloads, transfer_id, pending);
                            continue;
                        }
                        info!(
                            "Starting multi-source download {transfer_id} from {} sources ({} dead filtered)",
                            live_sources.len(), sources.len() - live_sources.len()
                        );
                        {
                            let mut sm = source_manager.write().await;
                            for (ip, port) in &sources {
                                if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                                    sm.register_source(hash_bytes, v4, *port, None);
                                }
                            }
                        }
                        // D9: dedup (ip, port) — see the
                        // equivalent block in the initial-start
                        // path for rationale.
                        let download_sources: Vec<DownloadSource> = {
                            let sm = source_manager.read().await;
                            let mut seen: HashSet<(String, u16)> = HashSet::new();
                            let mut out: Vec<DownloadSource> = Vec::with_capacity(live_sources.len());
                            for (ip, port) in live_sources {
                                if !seen.insert((ip.clone(), *port)) { continue; }
                                let uh = ip.parse::<Ipv4Addr>().ok()
                                    .and_then(|v4| sm.get_user_hash(&hash_bytes, v4, *port));
                                let co = ip.parse::<Ipv4Addr>().ok()
                                    .and_then(|v4| sm.get_connect_options(&hash_bytes, v4, *port));
                                out.push(DownloadSource {
                                    peer_ip: ip.clone(),
                                    peer_port: *port,
                                    available_parts: Vec::new(),
                                    peer_user_hash: uh,
                                    peer_connect_options: co,
                                });
                            }
                            out
                        };
                        let (src_inject_tx, src_inject_rx) = mpsc::channel::<DownloadSource>(32);
                        let (est_inject_tx, est_inject_rx) =
                            mpsc::channel::<ed2k::multi_source::EstablishedSource>(ESTABLISHED_SOURCE_CHANNEL_CAP);
                        let expected_aich_master =
                            expected_aich_bytes(pending.expected_aich.as_deref());
                        let ms_download = MultiSourceDownload {
                            transfer_id: pending.transfer_id,
                            file_hash: hash_bytes,
                            file_name: pending.file_name,
                            file_size: pending.file_size,
                            sources: download_sources,
                            download_dir: PathBuf::from(&settings.download_folder),
                            user_hash: state.user_hash,
                            nickname: settings.nickname.clone(),
                            tcp_port: advertised_tcp_port(state),
                            udp_port: advertised_udp_port(state),
                            bandwidth_limiter: bandwidth_limiter.clone(),
                            control: pending.control,
                            source_manager: Some(source_manager.clone()),
                            comment_manager: Some(state.comment_manager.clone()),
                            credit_manager: Some(credit_manager.clone()),
                            shared_buddy_info: Some(state.shared_buddy_info.clone()),
                            obfuscation_enabled: state.obfuscation_enabled,
                            server_addr: state.server_addr,
                            new_source_rx: Some(src_inject_rx),
                            new_established_rx: Some(est_inject_rx),
            ed2k_limits: settings.ed2k_download_limits(),
            ember_hash,
            ed25519_public_key: ed25519_pubkey,
            ed25519_secret_key,
            friend_hashes: Some(friend_hashes.clone()),
                            ember_payload: shared_ember_payload.clone(),
                            ember_payload_generation: ember_payload_generation.clone(),
                            ip_filter: Some(state.shared_ip_filter.clone()),
                            banned_ips: Some(shared_banned_ips.clone()),
                            external_ip: state.external_ip,
                            aich_pending: Some(state.aich_recovery_pending.clone()),
                            trusted_aich_master: expected_aich_master
                                .or_else(|| state.aich_root_map.get(&hash_bytes).copied()),
                            expected_aich_master,
                            ember_file_hash: state.ember_content_hashes.get(&hash_bytes).map(|pin| pin.digest).unwrap_or([0u8; 32]),
                            geoip: geoip.clone(),
                            tracker_registry: Some(state.tracker_registry.clone()),
                            sx_overhead: stats_manager.sx_counters.clone(),
                            file_req_overhead: stats_manager.file_req_counters.clone(),
                            epx_overhead: stats_manager.epx_counters.clone(),
                        };
                        let tid = ms_download.transfer_id.clone();
                        let tid2 = tid.clone();
                        state.active_source_senders.insert(tid.clone(), src_inject_tx);
                        state.active_established_senders.insert(tid.clone(), est_inject_tx);
                        let tx = dl_event_tx.clone();
                        let tx2 = tx.clone();
                        if let Some(old_handle) = state.download_handles.remove(&tid2) {
                            old_handle.abort();
                        }
                        let handle = tokio::spawn(async move {
                            if let Err(e) = ms_download.run(tx).await {
                                error!("Multi-source download failed: {e}");
                                let kind = classify_error(&e.to_string());
                                let _ = tx2.send(DownloadEvent::Failed { transfer_id: tid, error: e.to_string(), failure_kind: kind }).await;
                            }
                        });
                        state.download_handles.insert(tid2, handle);
                    }
                }
            } else if let Some(fh) = resolved_file_hash {
                // Download is already active — inject KAD sources into it
                if !sources.is_empty() {
                    let matching_ids = vec![transfer_id.clone()];
                    let sm = source_manager.read().await;
                    let udp_sources = sm.get_udp_sources(&fh);
                    let mut injected = 0usize;
                    for (ip_s, port) in &sources {
                        let v4 = ip_s.parse::<Ipv4Addr>().ok();
                        let uh = v4.and_then(|v4| sm.get_user_hash(&fh, v4, *port));
                        let co = v4.and_then(|v4| sm.get_connect_options(&fh, v4, *port));
                        let udp = v4
                            .and_then(|v4| {
                                udp_sources
                                    .iter()
                                    .find(|(ip, tcp, _)| *ip == v4 && *tcp == *port)
                                    .map(|(_, _, u)| *u)
                            })
                            .unwrap_or(0);
                        let ds = DownloadSource {
                            peer_ip: ip_s.clone(),
                            peer_port: *port,
                            available_parts: Vec::new(),
                            peer_user_hash: uh,
                            peer_connect_options: co,
                        };
                        let stats = inject_source_into_active_transfers(
                            state, fh, &matching_ids, &ds, udp,
                        );
                        injected += stats.injected;
                    }
                    drop(sm);
                    if injected > 0 {
                        info!(
                            "Injected {} KAD sources into already-active download {}",
                            injected, transfer_id
                        );
                        let sm_known = {
                            let sm2 = source_manager.read().await;
                            sm2.source_count(&fh) as u32
                        };
                        // Include type-6 in the visible total
                        // — see the parallel fix at the
                        // `sources.is_empty() == false` branch
                        // above for the full rationale.
                        let visible_total = (total_found as u32).saturating_add(type6_count as u32);
                        let source_count = visible_total.max(sm_known);
                        let mut mgr = transfer_manager.write().await;
                        mgr.update_source_total(&transfer_id, source_count);
                        // Push the new count to the UI without
                        // zeroing live active/queued counters
                        // the multi-source worker maintains.
                        if let Some((sources, active_sources, queued_sources)) =
                            mgr.source_counts(&transfer_id)
                        {
                            let _ = app_handle.emit(
                                "transfer-sources",
                                &crate::types::TransferSourcesPayload {
                                    id: &transfer_id,
                                    sources,
                                    active_sources,
                                    queued_sources,
                                },
                            );
                        }
                        // Populate UI source-detail rows for
                        // callback and type-6 sources so the
                        // transfer's Sources tab reflects
                        // what's actually being pursued. The
                        // CallbackReq / DIRECTCALLBACKREQ
                        // was already dispatched earlier in
                        // this function; these rows tell
                        // the user "we're waiting on these
                        // peers to connect back to us".
                        // Without them the user only sees
                        // the ~4-6 direct sources and
                        // thinks Ember is finding half what
                        // eMule finds for the same file.
                        // Skip placeholders when the peer IP is
                        // already represented (duplicate-row
                        // prevention — see parallel blocks
                        // in the pending / pending→active
                        // branches above).
                        let now_ts = chrono::Utc::now().timestamp();
                        for cb_src in &callback_sources {
                            let ip_s = upload_server::kad_callback_display_key(
                                cb_src.ip,
                                cb_src.source_user_hash,
                            );
                            if mgr.has_source_detail_for_ip(&transfer_id, &ip_s) {
                                continue;
                            }
                            let cc = crate::geoip::lookup_country(
                                geoip, std::net::IpAddr::V4(cb_src.ip),
                            );
                            mgr.update_source_detail(
                                &transfer_id,
                                crate::types::SourceInfo {
                                    ip: ip_s.clone(),
                                    port: cb_src.tcp_port,
                                    status: crate::types::SourceStatus::WaitCallback,
                                    queue_rank: None,
                                    speed: 0,
                                    transferred: 0,
                                    client_software: String::new(),
                                    peer_name: String::new(),
                                    available_parts: None,
                                    total_parts: None,
                                    country_code: cc,
                                    user_hash: cb_src.source_user_hash,
                                    origin: Some(crate::types::SourceOrigin::Kad),
                                    placeholder: true,
                                },
                            );
                            // Fresh row → fresh timestamp, always.
                            // Overwrites any stale entry left over
                            // from a prior pause/resume cycle
                            // where `source_details` was cleared
                            // but we hadn't swept the timestamp
                            // map yet.
                            state.callback_row_pending_since.insert(
                                (transfer_id.clone(), ip_s, cb_src.tcp_port),
                                now_ts,
                            );
                        }
                        for dc_src in &direct_callback_sources {
                            let ip_s = dc_src.ip.to_string();
                            if mgr.has_source_detail_for_ip(&transfer_id, &ip_s) {
                                continue;
                            }
                            let cc = crate::geoip::lookup_country(
                                geoip, std::net::IpAddr::V4(dc_src.ip),
                            );
                            mgr.update_source_detail(
                                &transfer_id,
                                crate::types::SourceInfo {
                                    ip: ip_s.clone(),
                                    port: dc_src.tcp_port,
                                    status: crate::types::SourceStatus::WaitCallback,
                                    queue_rank: None,
                                    speed: 0,
                                    transferred: 0,
                                    client_software: String::new(),
                                    peer_name: String::new(),
                                    available_parts: None,
                                    total_parts: None,
                                    country_code: cc,
                                    user_hash: dc_src.source_user_hash,
                                    origin: Some(crate::types::SourceOrigin::Kad),
                                    placeholder: true,
                                },
                            );
                            state.callback_row_pending_since.insert(
                                (transfer_id.clone(), ip_s, dc_src.tcp_port),
                                now_ts,
                            );
                        }
                    }
                }
            }
            // All placeholder/source rows for this transfer have
            // now been written to the TransferManager. Unlike the
            // live multi-source worker rows, these writes don't
            // each emit a `transfer-source-detail` event, so an
            // open drawer wouldn't see them until the user
            // collapsed and re-expanded it (which re-fetches via
            // `getTransferSources`). The `transfer:source-search`
            // event fires too early — before the ~1s of callback
            // sends and row writes above — so a refresh keyed off
            // it races and reads stale state. Emit a dedicated
            // post-write signal the UI can refresh on reliably.
            let _ = app_handle.emit(
                "transfer:sources-updated",
                serde_json::json!({ "transfer_id": refresh_transfer_id }),
            );
        } else if let Some((_, tx)) = state.pending_notes_searches.remove(&sid) {
            let results = if let Some(search) = state.search_manager.get(&sid) {
                info!(
                    "Notes search {} completed: {} results",
                    sid.0, search.results.len()
                );
                convert_note_search_results(&search.results, &search.target)
            } else {
                Vec::new()
            };
            let _ = tx.send(Ok(results));
        } else if let Some(batch) = state.store_keyword_searches.remove(&sid) {
            // StoreKeyword search completed - send publish messages to the closest nodes found.
            // eMule publishes by keyword, carrying all complete files
            // that reference the keyword (up to 150, split into
            // 50-entry packets), not one DHT walk per file token.
            if let Some(search) = state.search_manager.get(&sid) {
                // Publish only to nodes that actually answered during
                // the lookup AND fall within the eMule search tolerance
                // of the keyword target (mirrors the StoreSource path).
                // Publishing to never-queried / out-of-tolerance nodes
                // just gets rejected remotely and wastes publish slots.
                // Skip whatever the eager per-tick loop
                // (`next_publish_candidates`) already reached while
                // the search was walking — this is the completion
                // mop-up, not a resend of it.
                let already_published = search.store_sent.len();
                let remaining = STORE_PUBLISH_TARGET_TOTAL.saturating_sub(already_published);
                let candidates: Vec<kad::types::KadContact> = search.closest.iter()
                    .filter(|c| {
                        !search.store_sent.contains(&c.id)
                            && !state.overloaded_nodes.contains_key(&c.ip)
                            && search.responded_during_lookup.contains(&c.id)
                            && kad::search::within_search_tolerance_pub(&search.target, &c.id)
                    })
                    .take(remaining)
                    .cloned()
                    .collect();
                let mut successful_packets = 0usize;
                let mut successful_peers = 0usize;
                let packets = encode_keyword_batch(&batch).unwrap_or_default();
                for contact in candidates.iter().filter(|_| !packets.is_empty()) {
                    let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                    if state.flood_protection.check_outgoing_rate(addr.ip()) {
                        debug!("Throttling completion keyword publish to {addr}");
                        continue;
                    }
                    if !kad_requests_allowed(state, addr, &packets[0], packets.len()) {
                        continue;
                    }
                    let peer_packets =
                        send_keyword_batch(udp_socket, state, &batch, &packets, addr, contact).await;
                    successful_packets += peer_packets;
                    if peer_packets == packets.len() {
                        successful_peers += 1;
                    }
                }
                let total_published = already_published + successful_peers;
                if total_published > 0 {
                    state.publish_manager.mark_keyword_batch_published(&batch);
                    info!(
                        "StoreKeyword search {} completed: published keyword '{}' ({} file entries, {} packet send(s)) to {} fully-reached nodes ({} during lookup, {} at completion)",
                        sid.0,
                        batch.keyword,
                        batch.file_hashes.len(),
                        successful_packets,
                        total_published,
                        already_published,
                        successful_peers,
                    );
                }
            }
        } else if let Some((file_hash, msg)) = state.store_source_searches.remove(&sid) {
            // StoreSource search completed - send source publish to remaining
            // within-tolerance responded contacts not already published during Lookup.
            if let Some(search) = state.search_manager.get(&sid) {
                let now = chrono::Utc::now().timestamp();
                let mut successful_peers = 0usize;
                let already_published = &search.store_sent;
                let responded = &search.responded_during_lookup;
                let remaining = STORE_PUBLISH_TARGET_TOTAL.saturating_sub(already_published.len());
                let candidates: Vec<&kad::types::KadContact> = search.closest.iter()
                    .filter(|c| {
                        !already_published.contains(&c.id)
                            && !state.overloaded_nodes.contains_key(&c.ip)
                            && responded.contains(&c.id)
                            && kad::search::within_search_tolerance_pub(&search.target, &c.id)
                    })
                    .take(remaining)
                    .collect();
                for contact in candidates {
                    let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                    if state.flood_protection.check_outgoing_rate(addr.ip()) {
                        debug!("Throttling completion source publish to {addr}");
                        continue;
                    }
                    if let Ok(packet) = messages::encode_packet(&msg) {
                        if send_kad_packet(
                            udp_socket,
                            &packet,
                            addr,
                            state,
                            &contact.id,
                        )
                        .await
                        .is_err()
                        {
                            continue;
                        }
                        state.flood_protection.track_request(
                            addr,
                            kad_request_opcode(&msg).unwrap_or(0),
                        );
                        // Per-peer pending entry — we track the
                        // store's target rather than `file_hash` so
                        // remove-on-ack matches the target echoed
                        // in PublishRes (for source publishes these
                        // are the same value, but keyword/notes
                        // would differ).
                        let pending = state
                            .publish_pending
                            .entry((search.target, addr))
                            .or_insert((file_hash, now, true, 0));
                        pending.0 = file_hash;
                        pending.1 = now;
                        pending.2 = true;
                        pending.3 = pending.3.saturating_add(1);
                        successful_peers += 1;
                    }
                }
                let total_published = already_published.len() + successful_peers;
                if total_published > 0 {
                    let now_ts = chrono::Utc::now().timestamp();
                    state.publish_manager.mark_source_published(&file_hash);
                    let raw_hash = kad_id_to_md4_bytes(&file_hash);
                    if let Some(record) = known_files.find_by_hash_mut(&raw_hash) {
                        record.last_publish_src = (now_ts.max(0) as u64).min(u32::MAX as u64) as u32;
                        known_files.mark_dirty();
                    }
                    info!("StoreSource search {} completed: published to {} nodes ({} during lookup, {} at completion)",
                        sid.0, total_published, already_published.len(), successful_peers);
                }
                if file_hash == kad::publish::ember_rendezvous_key() {
                    // Only an ack proves a peer actually stored the
                    // advert. `total_published` counts packets we
                    // *sent*, so treating it as success left the node
                    // believing it was listed — and therefore
                    // undiscoverable for a whole republish interval —
                    // whenever the sends went unanswered.
                    // `mark_source_published` is a no-op for this key
                    // (deliberately absent from the file set), so the
                    // timestamp is managed here.
                    let acked = state
                        .source_publish_acks
                        .get(&file_hash)
                        .copied()
                        .unwrap_or(0);
                    if acked == 0 {
                        state.ember_rendezvous_published_at = chrono::Utc::now().timestamp()
                            - EMBER_RENDEZVOUS_REPUBLISH_SECS
                            + EMBER_RENDEZVOUS_UNACKED_RETRY_SECS;
                        info!("Ember rendezvous: advert unacknowledged, will retry in 10 minutes");
                    } else {
                        info!("Ember rendezvous: advert stored by {acked} peer(s)");
                    }
                }
            }
        } else if let Some(note) = state.pending_note_publishes.remove(&sid) {
            // StoreNotes search completed - send PublishNotesReq to closest nodes
            if let Some(search) = state.search_manager.get(&sid) {
                let now = chrono::Utc::now().timestamp();
                let already_published = &search.store_sent;
                let remaining =
                    STORE_PUBLISH_TARGET_TOTAL.saturating_sub(already_published.len());
                let mut successful_peers = 0usize;
                // Same targeting as StoreSource/StoreKeyword: publish only
                // to nodes that answered during the lookup and lie within
                // the search tolerance of the target, skipping overloaded
                // nodes. Publishing to never-queried / far nodes is rejected
                // remotely and weakens note availability.
                for contact in search.closest.iter()
                    .filter(|c| !already_published.contains(&c.id)
                        && !state.overloaded_nodes.contains_key(&c.ip)
                        && search.responded_during_lookup.contains(&c.id)
                        && kad::search::within_search_tolerance_pub(&search.target, &c.id))
                    .take(remaining) {
                    let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                    if state.flood_protection.check_outgoing_rate(addr.ip()) {
                        debug!("Throttling completion note publish to {addr}");
                        continue;
                    }
                    if let Ok(packet) = messages::encode_packet(&note.message) {
                        if send_kad_packet(
                            udp_socket,
                            &packet,
                            addr,
                            state,
                            &contact.id,
                        )
                        .await
                        .is_err()
                        {
                            continue;
                        }
                        state.flood_protection.track_request(
                            addr,
                            kad_request_opcode(&note.message).unwrap_or(0),
                        );
                        // Track per-peer pending entry so the
                        // PublishRes handler can match and bump
                        // `publish_confirmed`. The Source and
                        // Keyword paths already do this; the
                        // Notes path used to skip it, which made
                        // every notes ack show up as
                        // `publish_res_unmatched` in diagnostics
                        // even when the publish succeeded.
                        let pending = state
                            .publish_pending
                            .entry((note.file_hash, addr))
                            .or_insert((note.file_hash, now, false, 0));
                        pending.0 = note.file_hash;
                        pending.1 = now;
                        pending.2 = false;
                        pending.3 = pending.3.saturating_add(1);
                        successful_peers += 1;
                    }
                }
                let total_published =
                    already_published.len().saturating_add(successful_peers);
                if total_published > 0 {
                    // Only now — after PublishNotesReq packets were
                    // actually transmitted — do we record/refresh
                    // the note's `last_publish` and reset its 24h
                    // republish timer. This is a shared completion
                    // path for both the first-time publish
                    // (`NetworkCommand::PublishNote`) and every
                    // subsequent scheduled republish, neither of
                    // which insert/update `published_notes`
                    // themselves anymore — a search that timed out
                    // or found zero reachable nodes used to still
                    // reset the timer (or, for first publish,
                    // record a "published" entry) despite nothing
                    // actually being sent.
                    if note.rating > 0 || !note.comment.trim().is_empty() {
                        state.published_notes.insert(
                            note.file_hash,
                            PublishedNote {
                                rating: note.rating,
                                comment: note.comment.clone(),
                                file_name: note.file_name.clone(),
                                file_size: note.file_size,
                                last_publish: now,
                            },
                        );
                        {
                            let db = db.clone();
                            let hash_hex = note.file_hash.to_hex();
                            let rating = note.rating;
                            let comment = note.comment.clone();
                            let file_name = note.file_name.clone();
                            let file_size = note.file_size;
                            tokio::task::spawn_blocking(move || {
                                if let Err(e) = db.save_published_note(
                                    &hash_hex,
                                    rating,
                                    &comment,
                                    now,
                                    file_name.as_deref(),
                                    file_size,
                                ) {
                                    warn!(
                                        "Failed to persist note republish timestamp: {e}"
                                    );
                                }
                            });
                        }
                    }
                    info!(
                        "StoreNotes search {} completed: published note (rating={}) to {} nodes ({} during lookup, {} at completion)",
                        sid.0,
                        note.rating,
                        total_published,
                        already_published.len(),
                        successful_peers,
                    );
                }
            }
        }

        // FindBuddy convergence sweep: send FindBuddyReq to all closest
        // contacts discovered during the DHT walk. We already sent to
        // each responding node during lookup (eMule behavior), but this
        // final sweep catches any contacts that were discovered but not
        // yet directly queried.
        //
        // Only the completing *FindBuddy* search may decide the hunt's
        // outcome. Every search type shares this completion path, and a
        // publish or source lookup finishing left the locals below at
        // their defaults — which `already_sent == 0` then read as "the
        // buddy search reached nobody" and reported as a failure. With
        // the publish timer at 2s and a source search per download,
        // some unrelated search almost always completes inside a buddy
        // walk, so a firewalled node aborted its own hunt, ignored the
        // FindBuddyRes that followed (only honoured in `FindingBuddy`),
        // and escalated its retry cooldown toward ten minutes.
        let completing_is_find_buddy = state
            .search_manager
            .get(&sid)
            .is_some_and(|search| matches!(search.search_type, SearchType::FindBuddy));
        if completing_is_find_buddy
            && state.buddy_manager.state() == BuddyState::FindingBuddy
        {
            let mut already_sent = 0usize;
            let mut contacts_to_send = Vec::new();
            let mut target = KadId::zero();
            if let Some(search) = state.search_manager.get_mut(&sid) {
                target = search.target;
                already_sent = search.find_buddy_requests_sent();
                let candidates: Vec<KadContact> = search
                    .closest
                    .iter()
                    .filter(|c| !search.responded_during_lookup.contains(&c.id))
                    .cloned()
                    .collect();
                for contact in candidates {
                    if search.reserve_find_buddy_request(contact.id) {
                        contacts_to_send.push(contact);
                    }
                }
            }
            if !contacts_to_send.is_empty() {
                let user_id = KadId(cuint128_swap(&state.user_hash));
                let local_tcp = state.buddy_manager.tcp_port();
                let mut sent = 0;
                for contact in &contacts_to_send {
                    let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                    let msg = KadMessage::FindBuddyReq {
                        buddy_id: target,
                        user_id,
                        tcp_port: local_tcp,
                    };
                    match messages::encode_packet(&msg) {
                        Ok(packet) => {
                            if send_kad_packet(
                                udp_socket, &packet, addr, state, &contact.id,
                            )
                            .await
                            .is_ok()
                            {
                                // Track only after a successful send —
                                // mirrors poll_queries and avoids
                                // phantom FindBuddyRes ack slots.
                                state.flood_protection.track_request(addr, 0x51);
                                sent += 1;
                            } else if let Some(search) =
                                state.search_manager.get_mut(&sid)
                            {
                                search.release_find_buddy_request(contact.id);
                            }
                        }
                        Err(_) => {
                            if let Some(search) = state.search_manager.get_mut(&sid) {
                                search.release_find_buddy_request(contact.id);
                            }
                        }
                    }
                }
                info!(
                    "FindBuddy search {} converged: sent FindBuddyReq to {} additional contacts (already sent to {} during lookup)",
                    sid.0, sent, already_sent
                );
            } else if already_sent == 0 {
                state.buddy_manager.find_failed();
                info!("FindBuddy search {} completed without finding any reachable contacts", sid.0);
            } else {
                info!(
                    "FindBuddy search {} converged: already sent FindBuddyReq to {} nodes during lookup",
                    sid.0, already_sent
                );
            }
        }

        let store_publish_pending = state
            .search_manager
            .get(&sid)
            .map(|search| {
                matches!(
                    search.search_type,
                    kad::search::SearchType::StoreFile
                        | kad::search::SearchType::StoreKeyword
                        | kad::search::SearchType::StoreNotes
                ) && state.publish_pending.iter().any(
                    |((target, _), (file_hash, _, _, _))| {
                        *target == search.target || *file_hash == search.target
                    },
                )
            })
            .unwrap_or(false);
        if store_publish_pending {
            continue;
        }

        if let Some(removed) = state.search_manager.remove(&sid) {
            state.routing_table.release_contacts_in_use(&removed.in_use_ids);
        }
    }

    // eMule CSearchManager::JumpStart() reaps "stopping" searches
    // every second, ~15s after PrepareToStop. The loop above already
    // removes completed searches once their work is done, but
    // fire-and-forget Store* publishes stay parked on
    // `store_publish_pending` while waiting for publish acks that may
    // never arrive — so without this they sit in the UI as "STOPPING"
    // until the slow 300s cleanup() sweep. Mirror eMule and reap them
    // here on the 1s tick (the same teardown the cleanup sweep uses).
    let rendezvous_target = rendezvous_search_target(state);
    let (stopped_sids, stopped_in_use) =
        state.search_manager.prune_stopped(STOP_GRACE_SECS);
    if !stopped_sids.is_empty() {
        finalize_removed_searches(
            state,
            app_handle,
            &stopped_sids,
            &stopped_in_use,
            rendezvous_target,
        );
    }
}

/// Every packet of a keyword batch, or `None` when one cannot be encoded: a
/// node only counts as reached with the whole batch, so none is sent.
fn encode_keyword_batch(batch: &kad::publish::KeywordPublishBatch) -> Option<Vec<Vec<u8>>> {
    let packets = batch
        .messages
        .iter()
        .map(messages::encode_packet)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    (!packets.is_empty()).then_some(packets)
}

/// Send a keyword batch already charged with `kad_requests_allowed` to
/// `addr`, tracking each packet that left for ack matching. Returns how many
/// did.
async fn send_keyword_batch(
    udp_socket: &UdpSocket,
    state: &mut NetworkState,
    batch: &kad::publish::KeywordPublishBatch,
    packets: &[Vec<u8>],
    addr: SocketAddr,
    contact: &KadContact,
) -> usize {
    let mut sent = 0usize;
    for packet in packets {
        if send_prepaid_kad_packet(udp_socket, packet, addr, state, &contact.id)
            .await
            .is_err()
        {
            continue;
        }
        state
            .flood_protection
            .track_request(addr, kad::messages::KADEMLIA2_PUBLISH_KEY_REQ);
        sent += 1;
        // Per-peer pending entry so every ack counts.
        let now_ts = chrono::Utc::now().timestamp();
        let pending = state
            .publish_pending
            .entry((batch.keyword_hash, addr))
            .or_insert((batch.keyword_hash, now_ts, false, 0));
        pending.0 = batch.keyword_hash;
        pending.1 = now_ts;
        pending.2 = false;
        pending.3 = pending.3.saturating_add(1);
    }
    sent
}
