//! Frontend/IPC command dispatch for the network task.
//!
//! What belongs here: `handle_command_inner` — the single `match` over
//! [`NetworkCommand`] that every Tauri command ultimately drives — and the
//! panic-isolating `handle_command` wrapper around it.
//!
//! What does not belong here: the network event loop itself, the other
//! dispatchers it drives (`handle_udp_packet`, `handle_download_event`,
//! `handle_upload_event`), and the helpers the arms call. Those stay in the
//! parent module.
//!
//! The glob `use super::*` below is deliberate. This is a pure code-motion
//! split of a ~50k-line module: the arms reach well over a hundred
//! parent-module helpers, constants and `NetworkState` fields, so an explicit
//! import list would be enormous, would churn on every edit, and would buy no
//! real isolation while `NetworkState` is still shared by value. The boundary
//! this file draws is "command dispatch is edited here", not a dependency
//! firewall.

use super::*;

/// Panic-isolating wrapper around [`handle_command_inner`]. Frontend/IPC
/// commands drive nearly every operation; a panic in one handler must not
/// permanently freeze networking, so it is caught and the loop carries on.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_command(
    socket: &UdpSocket,
    cmd: NetworkCommand,
    state: &mut NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    fresh_part_hashes: &Arc<RwLock<HashMap<[u8; 16], Vec<[u8; 16]>>>>,
    settings: &AppSettings,
    dl_event_tx: &mpsc::Sender<DownloadEvent>,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    credit_manager: &Arc<RwLock<CreditManager>>,
    stats_manager: &mut StatsManager,
    known_files: &mut KnownFileList,
    _server_udp: &ServerUdpSocket,
    firewall_probe_ips: &upload_server::FirewallProbeSet,
    shared_banned_ips: &upload_server::SharedBannedIps,
    shared_banned_hashes: &upload_server::SharedBannedHashes,
    shared_server_addr: &Arc<RwLock<Option<SocketAddr>>>,
    shared_ember_payload: &ember::SharedEmberPayload,
    ember_payload_generation: &ember::EmberPayloadGeneration,
    geoip: &crate::geoip::GeoIpReader,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    mutual_friend_hashes: &crate::app_state::SharedFriendHashes,
    ember_hash: [u8; 16],
    ul_event_tx: &mpsc::Sender<upload_server::UploadEvent>,
    ed25519_pubkey: [u8; 32],
    ed25519_secret_key: [u8; 32],
    upload_queue: &ed2k::upload::UploadQueueRef,
) {
    if let Err(p) = std::panic::AssertUnwindSafe(handle_command_inner(
        socket,
        cmd,
        state,
        local_index,
        fresh_part_hashes,
        settings,
        dl_event_tx,
        bandwidth_limiter,
        db,
        app_handle,
        transfer_manager,
        source_manager,
        credit_manager,
        stats_manager,
        known_files,
        _server_udp,
        firewall_probe_ips,
        shared_banned_ips,
        shared_banned_hashes,
        shared_server_addr,
        shared_ember_payload,
        ember_payload_generation,
        geoip,
        friend_hashes,
        mutual_friend_hashes,
        ember_hash,
        ul_event_tx,
        ed25519_pubkey,
        ed25519_secret_key,
        upload_queue,
    ))
    .catch_unwind()
    .await
    {
        error!(
            "Network command handler panicked (recovered, network loop continues): {}",
            describe_panic(&*p)
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_command_inner(
    socket: &UdpSocket,
    cmd: NetworkCommand,
    state: &mut NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    fresh_part_hashes: &Arc<RwLock<HashMap<[u8; 16], Vec<[u8; 16]>>>>,
    settings: &AppSettings,
    dl_event_tx: &mpsc::Sender<DownloadEvent>,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    credit_manager: &Arc<RwLock<CreditManager>>,
    stats_manager: &mut StatsManager,
    known_files: &mut KnownFileList,
    _server_udp: &ServerUdpSocket,
    firewall_probe_ips: &upload_server::FirewallProbeSet,
    shared_banned_ips: &upload_server::SharedBannedIps,
    shared_banned_hashes: &upload_server::SharedBannedHashes,
    shared_server_addr: &Arc<RwLock<Option<SocketAddr>>>,
    shared_ember_payload: &ember::SharedEmberPayload,
    ember_payload_generation: &ember::EmberPayloadGeneration,
    geoip: &crate::geoip::GeoIpReader,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    mutual_friend_hashes: &crate::app_state::SharedFriendHashes,
    ember_hash: [u8; 16],
    ul_event_tx: &mpsc::Sender<upload_server::UploadEvent>,
    ed25519_pubkey: [u8; 32],
    ed25519_secret_key: [u8; 32],
    upload_queue: &ed2k::upload::UploadQueueRef,
) {
    match cmd {
        NetworkCommand::SearchFiles {
            query,
            method,
            request_id,
            tx,
            search_filters,
        } => {
            // Cancel the prior request while it is still `active_search_request`
            // so cancel can clear the UDP queue and emit `search-complete`.
            // Taking first used to skip both, leaving the old tab spinning and
            // leftover UDP packets tagged under the new request.
            if let Some(active) = state.active_search_request.as_ref() {
                let prior_id = active.request_id;
                cancel_search_request(state, app_handle, prior_id);
            }
            state.active_search_request = None;

            let mut tx = Some(tx);
            let mut local_results: Option<Vec<SearchResult>> = Some(Vec::new());
            let ui_file_type = search_filters.as_ref().and_then(|f| f.file_type.clone());
            // eMule: Arc/Iso → Pro on the wire; Program clears local filter;
            // Arc/Iso keep theirs for post-filter.
            let file_type_filter =
                crate::search::merge::client_search_file_type_filter(ui_file_type.as_deref());
            let wire_file_type =
                crate::search::merge::wire_search_file_type(ui_file_type.as_deref())
                    .map(|s| s.to_string());
            let mut active_request = ActiveSearchRequest {
                request_id,
                server_pending: false,
                kad_pending: false,
                udp_pending: false,
                ember_pending: false,
                udp_search_deadline: 0,
                udp_search_sent_ips: HashSet::new(),
                ed2k_found_sources: 0,
                ed2k_noted_availability: HashMap::new(),
                file_type_filter: file_type_filter.clone(),
                min_size: search_filters.as_ref().and_then(|f| f.min_size),
                max_size: search_filters.as_ref().and_then(|f| f.max_size),
                file_extension: search_filters
                    .as_ref()
                    .and_then(|f| f.file_extension.clone()),
                min_availability: search_filters.as_ref().and_then(|f| f.min_availability),
                keywords: Vec::new(),
                server_ip: state.server_addr.map(|a| a.ip().to_string()),
                server_result_count: 0,
                streamed_hashes: std::collections::HashSet::new(),
                batch_spam: crate::search::spam::BatchSpamContext::default(),
            };

            // Parse the raw query into a boolean keyword tree (implicit AND,
            // explicit AND/OR/NOT, `-` negation, "quoted phrases", and
            // parentheses). Operator-free queries still tokenize exactly like
            // before (byte-identical wire expression). `positive_terms`
            // (negated terms excluded) drive the Kad lookup keyword and spam
            // scoring; the full tree drives the wire expression and the local
            // Kad result filter.
            let query_expr = crate::search::query::parse(&query);
            let keywords: Vec<String> = query_expr
                .as_ref()
                .map(|e| e.positive_terms())
                .unwrap_or_default();
            // Match wire encoding: zero numerics and empty type/ext are dropped
            // by `build_search_expression_with_node`, so treat them as absent.
            let has_usable_filters = search_filters.as_ref().is_some_and(|f| {
                f.file_type.as_ref().is_some_and(|t| !t.is_empty())
                    || f.file_extension.as_ref().is_some_and(|e| !e.is_empty())
                    || f.min_size.is_some_and(|v| v > 0)
                    || f.max_size.is_some_and(|v| v > 0)
                    || f.min_availability.is_some_and(|v| v > 0)
            }) || wire_file_type.as_ref().is_some_and(|t| !t.is_empty());
            if keywords.is_empty() && !has_usable_filters {
                if let Some(tx) = tx.take() {
                    let _ = tx.send(local_results.take().unwrap_or_default());
                }
                let _ = app_handle.emit("search-complete", SearchCompleteEvent { request_id });
                return;
            }
            active_request.keywords = keywords.clone();

            // Build the search expression once, reuse for KAD + TCP + UDP.
            // Single keyword → string leaf; multiple → AND tree. Any size /
            // availability / type / extension filters are AND-combined as
            // numeric/meta-string leaves (eMule `GetSearchPacket`) so the
            // remote node filters *before* truncating to its result cap —
            // a client-side-only filter can't recover hits lost to that cap.
            // Arc/Iso are remapped to Pro on the wire (eMule ED2KFTSTR).
            let search_constraints = kad::messages::SearchConstraints {
                file_type: wire_file_type.as_deref(),
                file_extension: search_filters
                    .as_ref()
                    .and_then(|f| f.file_extension.as_deref()),
                min_size: search_filters.as_ref().and_then(|f| f.min_size),
                max_size: search_filters.as_ref().and_then(|f| f.max_size),
                min_availability: search_filters.as_ref().and_then(|f| f.min_availability),
            };
            let search_expr = kad::messages::build_search_expression_with_node(
                query_expr.as_ref().map(|expr| expr.to_wire_bytes()),
                &search_constraints,
            );

            // --- TCP server search ---
            let run_server = matches!(method, SearchMethod::Global | SearchMethod::Server);
            let run_udp = matches!(method, SearchMethod::Global);
            let run_kad =
                !keywords.is_empty() && matches!(method, SearchMethod::Global | SearchMethod::Kad);
            let run_ember = matches!(method, SearchMethod::Global | SearchMethod::Ember);

            if run_server && state.server_connected {
                if let Some(mut conn) = state.server_connection.take() {
                    match conn.send_search_expr_bytes(&search_expr).await {
                        Ok(()) => {
                            active_request.server_pending = true;
                            state.server_search_more_needed = false;
                            state.server_search_more_requests = 0;
                            state.pending_server_search = Some(PendingServerSearch {
                                tx: None,
                                results: Vec::new(),
                                request_id,
                            });
                            state.server_search_age = 0;
                            info!("TCP server search started for '{query}'");
                        }
                        Err(e) => {
                            debug!("TCP server search failed to send: {e}");
                        }
                    }
                    state.server_connection = Some(conn);
                }
            }

            // --- UDP global search ---
            if run_udp {
                let uses_64bit_search = kad::messages::search_expression_uses_64bit(&search_expr);
                let connected_addr = state.server_addr;
                let servers = state.server_list.servers().to_vec();
                let mut dropped = 0usize;
                for server in &servers {
                    if !is_eligible_udp_server(server, connected_addr) {
                        continue;
                    }
                    if let Some(pkt) = ServerUdpSocket::build_global_search_packet(
                        server,
                        &search_expr,
                        uses_64bit_search,
                    ) {
                        if state.udp_search_queue.len() >= MAX_UDP_SEARCH_QUEUE {
                            dropped = dropped.saturating_add(1);
                            continue;
                        }
                        state.udp_search_queue.push_back(pkt);
                    }
                }
                if dropped > 0 {
                    debug!(
                        "UDP global search queue at cap ({}); dropped {} additional server packet(s)",
                        MAX_UDP_SEARCH_QUEUE, dropped,
                    );
                }
                if !state.udp_search_queue.is_empty() {
                    active_request.udp_pending = true;
                    state.server_udp_search_age = 0;
                    // One second per queued packet safely exceeds the real
                    // ~750ms `udp_search_timer` send throttle (eMule
                    // UDPSEARCHSPEED), so this comfortably covers the worst
                    // case where every queued server must be drained before
                    // the post-drain grace period even starts counting.
                    active_request.udp_search_deadline = chrono::Utc::now().timestamp()
                        + state.udp_search_queue.len() as i64
                        + UDP_SEARCH_HARD_DEADLINE_BUFFER_SECS;
                    info!(
                        "UDP global search queued for {} servers",
                        state.udp_search_queue.len()
                    );
                }
            }

            // --- KAD search ---
            let kad_started = 'kad: {
                if !run_kad {
                    break 'kad false;
                }
                // KAD needs the parsed boolean expression. Positive terms being
                // present is already what gates `run_kad`, but guard here too —
                // before any side effects — so future logic drift degrades to a
                // skipped KAD search instead of panicking the whole network task.
                let Some(query_expr) = query_expr.clone() else {
                    break 'kad false;
                };
                let Some(primary_keyword) = keywords.iter().max_by_key(|k| k.len()) else {
                    break 'kad false;
                };
                let keyword_hash = kad::publish::keyword_to_kad_id(primary_keyword);
                info!(
                    "Searching KAD ({} keywords) -> hash {}",
                    keywords.len(),
                    keyword_hash
                );

                let closest = state
                    .routing_table
                    .find_closest_prefer_verified(&keyword_hash, SEARCH_INITIAL_CONTACTS);

                if closest.is_empty() {
                    info!("KAD search: no closest contacts in routing table");
                    break 'kad false;
                }

                let sid = start_kad_search(
                    state,
                    app_handle,
                    keyword_hash,
                    SearchType::FindKeyword,
                    closest,
                );

                if sid == SearchId(0) {
                    info!("KAD search: rejected (too many active searches)");
                    break 'kad false;
                }
                // eMule GetSearchPacket (Kad): for AND-only trees, strip the
                // lookup keyword from restrictive terms — the DHT target
                // already selects that word. Empty terms are valid
                // (unrestricted startPos). OR/NOT keep the full tree.
                let kad_keyword_node = if !query_expr.contains_or() && !query_expr.contains_not() {
                    query_expr
                        .without_term(primary_keyword)
                        .map(|e| e.to_wire_bytes())
                } else {
                    Some(query_expr.to_wire_bytes())
                };
                let kad_search_expr = kad::messages::build_search_expression_with_node(
                    kad_keyword_node,
                    &search_constraints,
                );
                if let Some(search) = state.search_manager.get_mut(&sid) {
                    search.search_terms_data = kad_search_expr;
                }
                active_request.kad_pending = true;
                let Some(search_tx) = tx.take() else {
                    tracing::error!("KAD search: tx already consumed");
                    break 'kad false;
                };
                state.pending_keyword_searches.insert(
                    sid,
                    PendingKeywordSearch {
                        tx: search_tx,
                        local_results: local_results.take().unwrap_or_default(),
                        keywords,
                        query_expr,
                        request_id,
                        last_streamed_count: 0,
                        file_type_filter,
                    },
                );
                true
            };

            // --- Ember DHT keyword search (slice 10 + multi-keyword wire) ---
            // Streaming-only: it never touches the invoke oneshot (`tx`); its
            // hits arrive via `search-results` events and it gates
            // `search-complete` through `ember_pending`. Uses the longest
            // (most selective) keyword as the DHT walk key; remaining
            // keyword hashes ride on FIND_VALUE for peer-side file_hash
            // intersection on AND-only queries (OR skips extras — that
            // intersection would drop the non-matching half). Filename
            // filtering remains defense-in-depth via `query_expr`.
            // Deliberately not gated on having contacts. With none the search
            // completes immediately from whatever the local store holds
            // rather than being skipped, which keeps a momentarily empty
            // table from silently dropping the Ember leg of a search.
            if run_ember && settings.ember_native_enabled {
                let query = active_request.keywords.join(" ");
                let hashed = ember::dht::search::compute_keyword_hashes(&query);
                if let Some((primary_hash, _)) = hashed.first() {
                    // AND-only: remaining keyword hashes ride on FIND_VALUE so
                    // peers that hold those keys can intersect file hashes.
                    // OR must not — that intersection is AND semantics and
                    // drops the non-matching half at any peer that stored a
                    // secondary key. Local `query_expr.matches` still applies.
                    let extras = ember::dht::search::extra_keyword_hashes(
                        &hashed,
                        !query_expr.as_ref().is_some_and(|e| e.contains_or()),
                    );
                    if let Some(search_id) = state.ember_search.start_find_value(
                        ember::dht::EmberNodeId(*primary_hash),
                        extras.clone(),
                        state.ember_dht.routing(),
                    ) {
                        seed_ember_local_records(state, search_id, primary_hash, &extras);
                        seed_ember_session_search_contacts(state, search_id);
                        state.ember_keyword_searches.insert(
                            search_id,
                            EmberKeywordSearch {
                                request_id,
                                keywords: active_request.keywords.clone(),
                                query_expr: query_expr.clone(),
                                file_type_filter: active_request.file_type_filter.clone(),
                                min_size: active_request.min_size,
                                max_size: active_request.max_size,
                                file_extension: active_request.file_extension.clone(),
                                min_availability: active_request.min_availability,
                                last_streamed_count: 0,
                            },
                        );
                        active_request.ember_pending = true;
                        drive_ember_search(socket, state, search_id).await;
                    }
                }
            }

            if !kad_started {
                if let Some(tx) = tx.take() {
                    let _ = tx.send(local_results.take().unwrap_or_default());
                }
                if !active_request.server_pending
                    && !active_request.udp_pending
                    && !active_request.ember_pending
                {
                    let _ = app_handle.emit("search-complete", SearchCompleteEvent { request_id });
                    return;
                }
            }

            state.active_search_request = Some(active_request);
        }

        NetworkCommand::CancelSearch { request_id } => {
            cancel_search_request(state, app_handle, request_id);
            info!("Cancelled search request {}", request_id);
        }

        NetworkCommand::CancelDownload {
            transfer_id,
            cleanup_ack,
        } => {
            // eMule: CPartFile::DeletePartFile -> StopFile -> PauseFile ->
            //   CSearchManager::StopSearch(GetKadFileSearchID(), true)
            // Remove from pending_downloads so no new searches are started
            let removed_pending = state.pending_downloads.remove(&transfer_id);

            // Resolve the file hash up front, before the teardown below drops
            // the state that carries it. Every caller removes the transfer
            // from `TransferManager` *before* sending this command, and a
            // started download is no longer in `pending_downloads`, so by the
            // time the old lookup ran (after `per_file_sources.remove`) both
            // sources were empty and the unpublish below was dead code for
            // every download that had actually run: we kept advertising as a
            // source for a file we had just deleted, and leaked its publish,
            // ack, blackbox and AICH-recovery entries for the session.
            let cancel_hash = removed_pending
                .as_ref()
                .map(|p| p.file_hash.clone())
                .or_else(|| {
                    transfer_manager
                        .try_read()
                        .ok()
                        .and_then(|mgr| mgr.get_transfer(&transfer_id).map(|t| t.file_hash.clone()))
                })
                .or_else(|| {
                    state
                        .per_file_sources
                        .get(&transfer_id)
                        .map(|sources| hex::encode(sources.file_hash))
                });

            // Cancel control first so detached per-source tasks bail before
            // we ACK cleanup / delete .part files (N1).
            {
                let mgr = transfer_manager.read().await;
                if let Some(control) = mgr.get_control(&transfer_id) {
                    control.cancel();
                }
            }

            // Find and stop all active KAD source searches for this transfer
            let search_ids: Vec<SearchId> = state
                .download_source_searches
                .iter()
                .filter(|(_, (tid, _))| tid == &transfer_id)
                .map(|(sid, _)| *sid)
                .collect();
            for sid in &search_ids {
                state.download_source_searches.remove(sid);
                if let Some(removed) = state.search_manager.remove(sid) {
                    state
                        .routing_table
                        .release_contacts_in_use(&removed.in_use_ids);
                }
            }

            state.active_source_senders.remove(&transfer_id);
            // Lockstep with the metadata sender (see field doc on
            // `active_established_senders`). Without this, a cancelled
            // download leaves a dead `EstablishedSource` channel
            // registered; future LowID callbacks for the same hash
            // would hit `Closed` on dispatch and waste a round.
            state.active_established_senders.remove(&transfer_id);
            state.active_source_overflow.remove(&transfer_id);
            state.active_kad_search_state.remove(&transfer_id);
            // Cancel (delete) clears known sources; Stop preserves them for resume.
            if cleanup_ack.is_some() {
                state.per_file_sources.remove(&transfer_id);
            }
            if let Some(handle) = state.download_handles.remove(&transfer_id) {
                if cleanup_ack.is_none() {
                    // Stop path: preserve .part.met for resume
                    save_registered_part_tracker(&state, &transfer_id, "cancel/stop").await;
                }
                handle.abort();
                // Bounded wait: abort() cannot interrupt a task parked in
                // spawn_blocking (fsync / hashing), so a slow unwind must not
                // freeze the entire single-threaded network task.
                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
            }
            if cleanup_ack.is_some() {
                state.tracker_registry.lock().remove(&transfer_id);
            }

            // Remove partial download from KAD source publish. `cancel_hash`
            // was resolved at the top of this handler, before teardown.
            if let Some(fh) = cancel_hash {
                if let Ok(hb) = hex::decode(&fh) {
                    if hb.len() >= 16 {
                        let kad_hash = md4_bytes_to_kad_id(&hb[..16]);
                        state.publish_manager.remove_file(&kad_hash);
                        state.source_publish_acks.remove(&kad_hash);
                        let mut fh_arr = [0u8; 16];
                        fh_arr.copy_from_slice(&hb[..16]);
                        state.corruption_blackbox.remove_file(&fh_arr);
                        if let Ok(mut map) = state.aich_recovery_pending.write() {
                            map.retain(|(file_hash, _), _| *file_hash != fh_arr);
                        }
                    }
                }
            }

            // Drop any KAD-callback placeholder timestamps for this
            // transfer so they don't linger until the 180s timeout
            // sweep catches them. The periodic sweep tolerates stale
            // keys (it returns no-op when the row is gone), but
            // clearing here keeps the map tight and avoids a race
            // where a restart-download for the same transfer_id
            // within the sweep window would inherit pre-cancel
            // timestamps. See the parallel cleanup in
            // `PauseDownload` below.
            state
                .callback_row_pending_since
                .retain(|(tid, _, _), _| tid != &transfer_id);

            if removed_pending.is_some() || !search_ids.is_empty() {
                info!(
                    "CancelDownload {}: removed pending_download={}, stopped {} KAD source search(es)",
                    transfer_id, removed_pending.is_some(), search_ids.len()
                );
            }

            if let Some(tx) = cleanup_ack {
                let _ = tx.send(());
            }
        }

        NetworkCommand::PauseDownload { transfer_id } => {
            // eMule PauseFile: tear down active network state but keep source
            // knowledge so the download can be resumed quickly.
            // Cancel the shared control BEFORE aborting the worker so detached
            // per-source tasks observe teardown cooperatively (N1 / KadDisconnect).
            {
                let mgr = transfer_manager.read().await;
                if let Some(control) = mgr.get_control(&transfer_id) {
                    control.cancel();
                }
            }
            if let Some(handle) = state.download_handles.remove(&transfer_id) {
                save_registered_part_tracker(&state, &transfer_id, "pause").await;
                handle.abort();
                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
            }
            // Drop KAD-callback placeholder timestamps: the manager
            // clears `source_details` for this transfer on pause
            // (see `TransferManager::pause`), so any pending_since
            // entries would be orphaned until the sweep. Resuming
            // the download within the 180s sweep window would let
            // the freshly-added placeholders inherit stale
            // timestamps via `.insert(...)` overwrite, which works,
            // but proactively clearing here keeps the invariant
            // "pending_since only tracks rows that exist".
            state
                .callback_row_pending_since
                .retain(|(tid, _, _), _| tid != &transfer_id);
            state.active_source_senders.remove(&transfer_id);
            // Pause = worker is gone; keep both sender maps in lockstep
            // so a callback that arrives mid-pause doesn't try to
            // dispatch to a dead established channel.
            state.active_established_senders.remove(&transfer_id);
            state.active_source_overflow.remove(&transfer_id);
            state.active_kad_search_state.remove(&transfer_id);
            if let Some(pfs) = state.per_file_sources.get_mut(&transfer_id) {
                pfs.reset_active_states();
            }

            // Keep download_source_searches mappings alive so in-flight KAD
            // searches can still register discovered sources into
            // SourceManager when they complete. The search completion
            // handler checks `pending_downloads` to decide whether to start
            // the transfer; paused downloads STAY in `pending_downloads`
            // but have their `PendingDownload::control` marked paused, so
            // `try_start_pending_download_from_known_sources` guards against
            // starting them until resumed. (L4: earlier comment wrongly
            // said paused downloads are "removed from pending_downloads".)
            let in_flight = state
                .download_source_searches
                .values()
                .filter(|(tid, _)| tid == &transfer_id)
                .count();

            info!(
                "PauseDownload {}: aborted task, removed sender, {} in-flight KAD search(es) will drain naturally",
                transfer_id, in_flight
            );
        }

        NetworkCommand::StartDownload {
            file_hash,
            file_name,
            file_size,
            peer_ip,
            peer_port,
            extra_sources,
            ember_file_hash,
            expected_aich,
            transfer_id,
            control,
            discovery_only,
            friend_ember_hash,
        } => {
            // Seed expected BLAKE3 from search/UI so verify does not depend
            // solely on having processed an Ember keyword hit this session.
            // Non-search starts (deep link, friend browse, collections) often
            // omit the digest — fall back to known.met / shared library when
            // we already hashed this file before.
            if let Ok(bytes) = hex::decode(file_hash.trim()) {
                if let Ok(ed2k) = <[u8; 16]>::try_from(bytes.as_slice()) {
                    let mut digest = parse_ember_file_hash(&ember_file_hash);
                    if digest == [0u8; 32] {
                        if let Some(rec) = known_files.find_by_hash(&ed2k) {
                            digest = parse_ember_file_hash(&rec.ember_file_hash);
                        }
                    }
                    if digest == [0u8; 32] {
                        let hash_hex = hex::encode(ed2k);
                        let idx = local_index.read().await;
                        if let Some(f) = idx.get_by_hash(&hash_hex) {
                            digest = parse_ember_file_hash(&f.ember_file_hash);
                        }
                    }
                    if digest != [0u8; 32] {
                        state.ember_content_hashes.insert(ed2k, digest);
                    }
                }
            }

            let has_source = !peer_ip.is_empty() && peer_ip != "0.0.0.0" && peer_port > 0;
            // Best-effort: a friend-browse download almost always implies an
            // active friend session, so this binding is usually already
            // known this session (see `EmberFriendConnected` /
            // `reseed_friend_endpoint`) or persisted from a prior one.
            // `None` here just means the primary seed gets registered
            // anonymously, same as before this field existed.
            //
            // Require current friend membership before trusting this
            // caller-supplied hash: `start_download` is a Tauri IPC command,
            // so a compromised/malicious renderer script could otherwise
            // pass an arbitrary `ember_hash` to bind our own choice of
            // `peer_ip`/`peer_port` into a *real* friend's (or any other
            // previously-seen peer's) `sources.met` identity — poisoning
            // future `reseed_friend_endpoint` relocations for that peer.
            let friend_peer_user_hash = match friend_ember_hash {
                Some(eh) if friend_hashes.read().await.contains(&eh) => {
                    // Same membership-checked hash also drives the
                    // `OP_EMBER_XFER_REQ` fallback when dialing this friend
                    // fails, so record it against the transfer.
                    state.transfer_friend_hint.insert(transfer_id.clone(), eh);
                    credit_manager.read().await.find_user_hash_by_ember(&eh)
                }
                _ => None,
            };

            let publish_file_name = file_name.clone();
            let publish_ext = std::path::Path::new(&file_name)
                .extension()
                .map(|e| e.to_string_lossy().to_string())
                .unwrap_or_default();

            if has_source {
                let hash_bytes = match hex::decode(&file_hash) {
                    Ok(b) if b.len() == 16 => {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(&b);
                        arr
                    }
                    _ => {
                        error!("Invalid file hash: {file_hash}");
                        return;
                    }
                };
                let source_addr: SocketAddr = match format!("{peer_ip}:{peer_port}").parse() {
                    Ok(a) => a,
                    Err(e) => {
                        error!("Invalid peer address: {e}");
                        return;
                    }
                };

                // Validate primary + extras with the shared admissibility
                // gate so we don't hand the multi-source manager addresses
                // we refuse to dial (IP filter, banlist, self, port 0).
                // The cap mirrors `MAX_SOURCE_ADDRS` from the search merge
                // path so a bug in the frontend can't push an unbounded list.
                const MAX_SEED_EXTRA_SOURCES: usize = 49;
                let mut seen_addrs: std::collections::HashSet<(Ipv4Addr, u16)> =
                    std::collections::HashSet::new();
                let primary_ok = match source_addr.ip() {
                    std::net::IpAddr::V4(primary_v4) => {
                        seen_addrs.insert((primary_v4, source_addr.port()));
                        is_source_admissible(&state, primary_v4, source_addr.port(), None)
                    }
                    _ => false,
                };
                if !primary_ok {
                    warn!(
                        "StartDownload rejecting primary source {peer_ip}:{peer_port} (filtered/banned/self/undialable)"
                    );
                    // Fall through without registering the primary; extras
                    // may still seed the download if any are admissible.
                }
                let mut validated_extras: Vec<(Ipv4Addr, u16, String)> =
                    Vec::with_capacity(extra_sources.len().min(MAX_SEED_EXTRA_SOURCES));
                for (extra_ip_str, extra_port) in extra_sources.iter().take(MAX_SEED_EXTRA_SOURCES)
                {
                    if extra_ip_str.is_empty() || *extra_port == 0 {
                        continue;
                    }
                    let parsed_ip: Ipv4Addr = match extra_ip_str.parse() {
                        Ok(ip) => ip,
                        Err(_) => continue,
                    };
                    if !is_source_admissible(&state, parsed_ip, *extra_port, None) {
                        continue;
                    }
                    if !seen_addrs.insert((parsed_ip, *extra_port)) {
                        continue;
                    }
                    validated_extras.push((parsed_ip, *extra_port, extra_ip_str.clone()));
                }

                {
                    let mut sm = source_manager.write().await;
                    if primary_ok {
                        if let std::net::IpAddr::V4(v4) = source_addr.ip() {
                            match friend_peer_user_hash {
                                // Register with identity up front so a friend
                                // download that restarts before completing even
                                // one Hello handshake still has a `sources.met`
                                // row `reseed_friend_endpoint` can relocate.
                                Some(uh) => {
                                    sm.register_source_full_opts(
                                        hash_bytes,
                                        v4,
                                        source_addr.port(),
                                        0,
                                        uh,
                                        0,
                                    );
                                }
                                None => {
                                    sm.register_source(hash_bytes, v4, source_addr.port());
                                }
                            }
                        }
                    }
                    for (parsed_ip, extra_port, _) in &validated_extras {
                        sm.register_source(hash_bytes, *parsed_ip, *extra_port);
                    }
                }

                // Queued / add-paused: keep seeds in SourceManager and run
                // full-network discovery without starting dial workers.
                if discovery_only {
                    let now = chrono::Utc::now().timestamp();
                    let pending_priority = {
                        let mgr = transfer_manager.read().await;
                        mgr.get_transfer(&transfer_id)
                            .map(|t| priority_str_to_u32(&t.priority))
                            .unwrap_or(1)
                    };
                    let kad_available = kad_ready_for_sources(state);
                    let kad_hash = md4_bytes_to_kad_id(&hash_bytes);
                    let mut closest = state
                        .routing_table
                        .find_closest_prefer_verified(&kad_hash, SEARCH_INITIAL_CONTACTS);
                    let kad_search_started = if kad_available && !closest.is_empty() {
                        closest.sort_by_key(|c| c.is_tcp_firewalled() as u8);
                        let sid = start_kad_search(
                            state,
                            app_handle,
                            kad_hash,
                            SearchType::FindSource { file_size },
                            closest,
                        );
                        if sid != SearchId(0) {
                            state
                                .download_source_searches
                                .insert(sid, (transfer_id.clone(), hash_bytes));
                            info!(
                                "Started KAD source search {} for queued/paused download {}",
                                sid.0, transfer_id
                            );
                            let _ = app_handle.emit(
                                "transfer:source-search",
                                serde_json::json!({
                                    "transfer_id": &transfer_id,
                                    "kind": "kad_search",
                                }),
                            );
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    insert_pending_download_bounded(
                        &mut state.pending_downloads,
                        transfer_id.clone(),
                        PendingDownload {
                            transfer_id: transfer_id.clone(),
                            file_hash: file_hash.clone(),
                            file_name: file_name.clone(),
                            file_size,
                            expected_aich: expected_aich.clone(),
                            control,
                            search_count: if kad_search_started { 1 } else { 0 },
                            last_search_at: if kad_search_started { now } else { 0 },
                            priority: pending_priority,
                        },
                    );
                    if server_source_settle_elapsed(state) {
                        if let Some(conn) = state.server_connection.as_mut() {
                            if let Ok(bytes) = conn.send_get_sources(&hash_bytes, file_size).await {
                                if bytes > 0 {
                                    stats_manager.add_overhead(
                                        crate::storage::statistics::OverheadCategory::SourceExchange,
                                        crate::storage::statistics::OverheadDirection::Upload,
                                        bytes,
                                    );
                                    let _ = app_handle.emit(
                                        "transfer:source-search",
                                        serde_json::json!({
                                            "transfer_id": &transfer_id,
                                            "kind": "server_query",
                                        }),
                                    );
                                }
                            }
                        }
                    }
                    if network_ready_for_sources(state) {
                        let packets = build_all_getsources_packets(state, &hash_bytes, file_size);
                        if !packets.is_empty() {
                            let room =
                                MAX_UDP_SOURCE_QUEUE.saturating_sub(state.udp_source_queue.len());
                            state
                                .udp_source_queue
                                .extend(packets.into_iter().take(room));
                        }
                    }
                    if let Ok(hb) = hex::decode(&file_hash) {
                        if hb.len() >= 16 {
                            state.publish_manager.add_file(PublishableFile {
                                file_hash: md4_bytes_to_kad_id(&hb[..16]),
                                file_name: publish_file_name,
                                file_size,
                                file_type: crate::search::index::infer_file_type(&publish_ext),
                                complete_sources: 0,
                                keyword_publishable: false,
                                last_source_publish: {
                                    let mut raw = [0u8; 16];
                                    raw.copy_from_slice(&hb[..16]);
                                    known_files
                                        .find_by_hash(&raw)
                                        .map(|r| r.last_publish_src as i64)
                                        .unwrap_or(0)
                                },
                            });
                        }
                    }
                    info!(
                        "Discovery-only StartDownload for {}: seeds registered, KAD/TCP/UDP asked",
                        transfer_id
                    );
                    return;
                }

                // Promoting / active start: drop any prior discovery-only
                // pending entry and pull SM sources into the seed list.
                state.pending_downloads.remove(&transfer_id);
                {
                    let sm = source_manager.read().await;
                    for (ip, port) in sm.get_sources(&hash_bytes) {
                        if validated_extras.len() >= MAX_SEED_EXTRA_SOURCES {
                            break;
                        }
                        if !is_source_admissible(&state, ip, port, None) {
                            continue;
                        }
                        if !seen_addrs.insert((ip, port)) {
                            continue;
                        }
                        validated_extras.push((ip, port, ip.to_string()));
                    }
                }
                // Also seed from per_file_sources (EPX / soft-kept peers that
                // may not be in SourceManager). Register into SM so later
                // rediscovery and pause→resume stay consistent.
                let pfs_dialable = state
                    .per_file_sources
                    .get(&transfer_id)
                    .map(|pfs| pfs.dialable_sources())
                    .unwrap_or_default();
                if !pfs_dialable.is_empty() {
                    let mut sm = source_manager.write().await;
                    for (ip, port, udp_port) in pfs_dialable {
                        if validated_extras.len() >= MAX_SEED_EXTRA_SOURCES {
                            break;
                        }
                        // Do not re-immortalize inbound callback/push-grant
                        // ephemeral ports as reconnectable HighID rows.
                        if sm.is_session_only_port(&hash_bytes, ip, port) {
                            continue;
                        }
                        if !is_source_admissible(&state, ip, port, None) {
                            continue;
                        }
                        if !seen_addrs.insert((ip, port)) {
                            continue;
                        }
                        sm.register_source_full(hash_bytes, ip, port, udp_port, [0u8; 16]);
                        validated_extras.push((ip, port, ip.to_string()));
                    }
                }

                let download_sources = {
                    let sm = source_manager.read().await;
                    let mut sources =
                        Vec::with_capacity(usize::from(primary_ok) + validated_extras.len());
                    if primary_ok {
                        let uh = if let std::net::IpAddr::V4(v4) = source_addr.ip() {
                            sm.get_user_hash(&hash_bytes, v4, source_addr.port())
                        } else {
                            None
                        };
                        let co = if let std::net::IpAddr::V4(v4) = source_addr.ip() {
                            sm.get_connect_options(&hash_bytes, v4, source_addr.port())
                        } else {
                            None
                        };
                        sources.push(DownloadSource {
                            peer_ip: peer_ip.clone(),
                            peer_port,
                            available_parts: Vec::new(),
                            peer_user_hash: uh,
                            peer_connect_options: co,
                        });
                    }
                    for (parsed_ip, extra_port, extra_ip_str) in &validated_extras {
                        let uh = sm.get_user_hash(&hash_bytes, *parsed_ip, *extra_port);
                        let co = sm.get_connect_options(&hash_bytes, *parsed_ip, *extra_port);
                        sources.push(DownloadSource {
                            peer_ip: extra_ip_str.clone(),
                            peer_port: *extra_port,
                            available_parts: Vec::new(),
                            peer_user_hash: uh,
                            peer_connect_options: co,
                        });
                    }
                    sources
                };
                if download_sources.is_empty() {
                    warn!(
                        "StartDownload {transfer_id}: no admissible sources after filter/ban checks — \
                         queueing pending discovery without spawning a worker"
                    );
                    let pending_priority = {
                        let mgr = transfer_manager.read().await;
                        mgr.get_transfer(&transfer_id)
                            .map(|t| priority_str_to_u32(&t.priority))
                            .unwrap_or(1)
                    };
                    {
                        let mut mgr = transfer_manager.write().await;
                        mgr.update_status(&transfer_id, TransferStatus::Searching);
                        mgr.register_control(&transfer_id, control.clone());
                    }
                    insert_pending_download_bounded(
                        &mut state.pending_downloads,
                        transfer_id.clone(),
                        PendingDownload {
                            transfer_id: transfer_id.clone(),
                            file_hash: file_hash.clone(),
                            file_name: file_name.clone(),
                            file_size,
                            expected_aich: expected_aich.clone(),
                            control,
                            search_count: 0,
                            last_search_at: 0,
                            priority: pending_priority,
                        },
                    );
                } else {
                    if !validated_extras.is_empty() {
                        info!(
                        "Seeded multi-source download {} with primary {}:{} + {} extra source(s)",
                        transfer_id,
                        peer_ip,
                        peer_port,
                        validated_extras.len()
                    );
                    }
                    let (src_inject_tx, src_inject_rx) = mpsc::channel::<DownloadSource>(32);
                    let (est_inject_tx, est_inject_rx) =
                        mpsc::channel::<ed2k::multi_source::EstablishedSource>(
                            ESTABLISHED_SOURCE_CHANNEL_CAP,
                        );
                    let expected_aich_master = expected_aich_bytes(expected_aich.as_deref());
                    let ms_download = MultiSourceDownload {
                        // Clone instead of move so the outer `transfer_id`
                        // survives for the source-discovery dispatch below.
                        transfer_id: transfer_id.clone(),
                        file_hash: hash_bytes,
                        file_name,
                        file_size,
                        sources: download_sources,
                        download_dir: PathBuf::from(&settings.download_folder),
                        user_hash: state.user_hash,
                        nickname: settings.nickname.clone(),
                        tcp_port: advertised_tcp_port(&state),
                        udp_port: advertised_udp_port(&state),
                        bandwidth_limiter: bandwidth_limiter.clone(),
                        control,
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
                        ember_file_hash: state
                            .ember_content_hashes
                            .get(&hash_bytes)
                            .copied()
                            .unwrap_or([0u8; 32]),
                        geoip: geoip.clone(),
                        tracker_registry: Some(state.tracker_registry.clone()),
                        sx_overhead: stats_manager.sx_counters.clone(),
                        file_req_overhead: stats_manager.file_req_counters.clone(),
                        epx_overhead: stats_manager.epx_counters.clone(),
                    };

                    let tx = dl_event_tx.clone();
                    let tid = ms_download.transfer_id.clone();
                    let tid2 = tid.clone();
                    state
                        .active_source_senders
                        .insert(tid.clone(), src_inject_tx);
                    state
                        .active_established_senders
                        .insert(tid.clone(), est_inject_tx);
                    let tx2 = tx.clone();
                    if let Some(old_handle) = state.download_handles.remove(&tid2) {
                        debug!(
                            "Aborting existing download task for {tid2} before starting new one"
                        );
                        old_handle.abort();
                        // Match CancelDownload: wait for the old worker (and its
                        // spawn_blocking children) to release the .part before the
                        // new multi-source task opens it.
                        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), old_handle)
                            .await;
                    }
                    let handle = tokio::spawn(async move {
                        if let Err(e) = ms_download.run(tx).await {
                            error!("Multi-source download failed: {e}");
                            let kind = classify_error(&e.to_string());
                            let _ = tx2
                                .send(DownloadEvent::Failed {
                                    transfer_id: tid,
                                    error: e.to_string(),
                                    failure_kind: kind,
                                })
                                .await;
                        }
                    });
                    state.download_handles.insert(tid2, handle);
                } // end non-empty sources spawn

                // ─── Source-discovery fan-out for new downloads ──────────────
                //
                // Without these three dispatches a download added with a
                // single seed peer (the common path: user clicks Download
                // on a search result, frontend passes the first
                // `source_addresses` entry) would only see that one peer
                // until the next periodic sweep — the source_retry_timer
                // for KAD (15s+ on `active_download_kad_interval(0)`)
                // and the 4-minute TCP `OP_GETSOURCES` batch. A search
                // result reporting "27 sources" then looked like it had
                // exactly one in the transfer view, and a single failed
                // connection left the file stuck. Match the
                // `has_source = false` branch's behavior so the moment a
                // download starts, every source-discovery channel is
                // already in flight.
                let now_ts = chrono::Utc::now().timestamp();
                let kad_available = kad_ready_for_sources(state);
                let kad_hash = md4_bytes_to_kad_id(&hash_bytes);

                let initial_kad_search_started = if kad_available {
                    let mut closest = state
                        .routing_table
                        .find_closest_prefer_verified(&kad_hash, SEARCH_INITIAL_CONTACTS);
                    if !closest.is_empty() {
                        closest.sort_by_key(|c| c.is_tcp_firewalled() as u8);
                        let sid = start_kad_search(
                            state,
                            app_handle,
                            kad_hash,
                            SearchType::FindSource { file_size },
                            closest,
                        );
                        if sid != SearchId(0) {
                            state
                                .download_source_searches
                                .insert(sid, (transfer_id.clone(), hash_bytes));
                            info!(
                                "Started KAD source search {} for new active download {}",
                                sid.0, transfer_id
                            );
                            let _ = app_handle.emit(
                                "transfer:source-search",
                                serde_json::json!({
                                    "transfer_id": &transfer_id,
                                    "kind": "kad_search",
                                }),
                            );
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                };

                // Seed `active_kad_search_state` so the periodic sweep
                // schedules the next KAD search on its normal cadence
                // (~30s after this one when count==1) instead of
                // re-firing immediately. When the initial dispatch
                // didn't run (no KAD contacts / KAD disconnected) we
                // fall back to (now, 0) which lets the sweep retry as
                // soon as KAD is available again.
                state.active_kad_search_state.insert(
                    transfer_id.clone(),
                    (now_ts, if initial_kad_search_started { 1 } else { 0 }),
                );
                // Empty-seed pending was inserted with search_count=0; stamp the
                // fan-out so the 5s retry timer does not start a duplicate FindSource.
                if initial_kad_search_started {
                    if let Some(pd) = state.pending_downloads.get_mut(&transfer_id) {
                        pd.search_count = pd.search_count.max(1);
                        pd.last_search_at = now_ts;
                    }
                }

                // Ember DHT source discovery for the new download (slice 9):
                // independent of KAD, so it fires even on a KAD-less network.
                // Mirrors the KAD seed above so the periodic source-retry sweep
                // schedules the next lookup on the normal backoff instead of
                // re-firing immediately.
                let initial_ember_search_started =
                    if settings.ember_native_enabled && ember_overlay_contact_count(state) > 0 {
                        start_ember_source_search(socket, state, &transfer_id, hash_bytes).await
                    } else {
                        false
                    };
                state.ember_source_search_state.insert(
                    transfer_id.clone(),
                    (now_ts, if initial_ember_search_started { 1 } else { 0 }),
                );

                // Immediate TCP `OP_GETSOURCES` to the connected eD2K
                // server after post-login settle (Lugdunum drops early asks).
                if server_source_settle_elapsed(state) {
                    if let Some(conn) = state.server_connection.as_mut() {
                        if let Ok(bytes) = conn.send_get_sources(&hash_bytes, file_size).await {
                            if bytes > 0 {
                                stats_manager.add_overhead(
                                    crate::storage::statistics::OverheadCategory::SourceExchange,
                                    crate::storage::statistics::OverheadDirection::Upload,
                                    bytes,
                                );
                                let _ = app_handle.emit(
                                    "transfer:source-search",
                                    serde_json::json!({
                                        "transfer_id": &transfer_id,
                                        "kind": "server_query",
                                    }),
                                );
                            }
                        }
                    }
                }

                // UDP fan-out to every eligible known server, paced via
                // `udp_source_queue` so we don't burst-send on add.
                if network_ready_for_sources(state) {
                    let packets = build_all_getsources_packets(state, &hash_bytes, file_size);
                    if !packets.is_empty() {
                        let room =
                            MAX_UDP_SOURCE_QUEUE.saturating_sub(state.udp_source_queue.len());
                        debug!(
                            "Queuing {}/{} UDP source requests for new active download {}",
                            packets.len().min(room),
                            packets.len(),
                            transfer_id
                        );
                        state
                            .udp_source_queue
                            .extend(packets.into_iter().take(room));
                    }
                }
            } else {
                info!("No source address for {file_hash}, starting KAD source search");

                let hash_bytes = match hex::decode(&file_hash) {
                    Ok(b) if b.len() == 16 => b,
                    _ => {
                        error!("Invalid file hash: {file_hash}");
                        return;
                    }
                };
                let kad_hash = md4_bytes_to_kad_id(&hash_bytes);

                let mut closest = state
                    .routing_table
                    .find_closest_prefer_verified(&kad_hash, SEARCH_INITIAL_CONTACTS);
                if closest.is_empty() {
                    debug!(
                        "No routing table contacts for source search, download will retry later"
                    );
                }

                let now = chrono::Utc::now().timestamp();

                // Persist download to database for resume across restarts.
                // Check for an existing DB row first so we don't clobber
                // progress/priority when a queued download is promoted.
                {
                    let db_ref = db.clone();
                    let tid = transfer_id.clone();
                    let fname = file_name.clone();
                    let fhash = file_hash.clone();
                    let expected_for_db = expected_aich.clone();
                    let ember_for_db =
                        crate::security::parse_ember_file_hash(Some(&ember_file_hash))
                            .ok()
                            .flatten();
                    tokio::task::spawn_blocking(move || {
                        if db_ref.transfer_exists(&tid) {
                            let _ = db_ref.update_transfer_status(&tid, "searching");
                        } else {
                            let db_transfer = Transfer {
                                id: tid,
                                file_name: fname,
                                file_hash: fhash,
                                peer_id: String::new(),
                                peer_name: String::new(),
                                direction: TransferDirection::Download,
                                status: TransferStatus::Searching,
                                progress: 0.0,
                                speed: 0,
                                total_size: file_size,
                                transferred: 0,
                                completed_size: 0,
                                started_at: now,
                                failure_reason: None,
                                failure_kind: None,
                                failure_stage: None,
                                priority: "auto".to_string(),
                                sources: 0,
                                active_sources: 0,
                                queued_sources: 0,
                                queue_rank: None,
                                last_seen_complete: None,
                                last_received: None,
                                health: TransferHealth::Healthy,
                                health_reason: None,
                                stalled_since: None,
                                category: String::new(),
                                wait_time: 0,
                                upload_time: 0,
                                a4af_sources: 0,
                                max_sources: 0,
                                preview_priority: false,
                                preview_ready: false,
                                ember_sources: 0,
                                client_software: String::new(),
                                country_code: None,
                                user_hash: None,
                                ember_hash: None,
                                expected_aich: expected_for_db,
                                ember_file_hash: ember_for_db,
                                completed_path: None,
                                up_part_status: None,
                                up_part_count: None,
                                up_peer_part_status: None,
                                ember_verified: false,
                            };
                            let _ = db_ref.save_transfer(&db_transfer);
                        }
                    });
                }

                let kad_search_started = if kad_ready_for_sources(state) && !closest.is_empty() {
                    closest.sort_by_key(|c| c.is_tcp_firewalled() as u8);
                    let sid = start_kad_search(
                        state,
                        app_handle,
                        kad_hash,
                        SearchType::FindSource { file_size },
                        closest,
                    );
                    if sid != SearchId(0) {
                        let mut fh = [0u8; 16];
                        fh.copy_from_slice(&hash_bytes[..16]);
                        state
                            .download_source_searches
                            .insert(sid, (transfer_id.clone(), fh));
                        info!(
                            "Started source search {} for download {}",
                            sid.0, transfer_id
                        );
                        let _ = app_handle.emit(
                            "transfer:source-search",
                            serde_json::json!({
                                "transfer_id": &transfer_id,
                                "kind": "kad_search",
                            }),
                        );
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };

                // Look up actual priority from the transfer manager if this
                // is a promoted/re-started download, otherwise default to normal.
                let pending_priority = {
                    let mgr = transfer_manager.read().await;
                    mgr.get_transfer(&transfer_id)
                        .map(|t| priority_str_to_u32(&t.priority))
                        .unwrap_or(1)
                };
                insert_pending_download_bounded(
                    &mut state.pending_downloads,
                    transfer_id.clone(),
                    PendingDownload {
                        transfer_id: transfer_id.clone(),
                        file_hash: file_hash.clone(),
                        file_name,
                        file_size,
                        expected_aich,
                        control,
                        search_count: if kad_search_started { 1 } else { 0 },
                        last_search_at: if kad_search_started { now } else { 0 },
                        priority: pending_priority,
                    },
                );

                // Kick an immediate Ember DHT source search too (slice 9),
                // mirroring the KAD seed above so a download started purely by
                // hash can discover sources on a KAD-less network. The periodic
                // sweep re-asks on the normal backoff afterwards.
                if settings.ember_native_enabled && ember_overlay_contact_count(state) > 0 {
                    let mut fh = [0u8; 16];
                    fh.copy_from_slice(&hash_bytes);
                    let ember_started =
                        start_ember_source_search(socket, state, &transfer_id, fh).await;
                    state.ember_source_search_state.insert(
                        transfer_id.clone(),
                        (now, if ember_started { 1 } else { 0 }),
                    );
                }

                // Request sources from the connected ed2k server (non-blocking)
                // after post-login settle so Lugdunum does not drop the ask.
                if server_source_settle_elapsed(state) {
                    if let Some(conn) = &mut state.server_connection {
                        let mut file_hash_arr = [0u8; 16];
                        file_hash_arr.copy_from_slice(&hash_bytes);
                        if let Ok(bytes) = conn.send_get_sources(&file_hash_arr, file_size).await {
                            if bytes > 0 {
                                stats_manager.add_overhead(
                                    crate::storage::statistics::OverheadCategory::SourceExchange,
                                    crate::storage::statistics::OverheadDirection::Upload,
                                    bytes,
                                );
                                let _ = app_handle.emit(
                                    "transfer:source-search",
                                    serde_json::json!({
                                        "transfer_id": &transfer_id,
                                        "kind": "server_query",
                                    }),
                                );
                            }
                        }
                    }
                }

                // Queue UDP source requests to ALL eligible servers (paced via udp_source_queue)
                if network_ready_for_sources(state) {
                    let mut file_hash_arr = [0u8; 16];
                    file_hash_arr.copy_from_slice(&hash_bytes);
                    let packets = build_all_getsources_packets(state, &file_hash_arr, file_size);
                    if !packets.is_empty() {
                        let room =
                            MAX_UDP_SOURCE_QUEUE.saturating_sub(state.udp_source_queue.len());
                        debug!(
                            "Queuing {}/{} UDP source requests for new download",
                            packets.len().min(room),
                            packets.len()
                        );
                        state
                            .udp_source_queue
                            .extend(packets.into_iter().take(room));
                    }
                }
            }

            if let Ok(hb) = hex::decode(&file_hash) {
                if hb.len() >= 16 {
                    state.publish_manager.add_file(PublishableFile {
                        file_hash: md4_bytes_to_kad_id(&hb[..16]),
                        file_name: publish_file_name,
                        file_size,
                        file_type: crate::search::index::infer_file_type(&publish_ext),
                        complete_sources: 0,
                        keyword_publishable: false,
                        last_source_publish: {
                            let mut raw = [0u8; 16];
                            raw.copy_from_slice(&hb[..16]);
                            known_files
                                .find_by_hash(&raw)
                                .map(|r| r.last_publish_src as i64)
                                .unwrap_or(0)
                        },
                    });
                    info!("Published partial download to KAD source publish");
                }
            }
        }

        NetworkCommand::AnnounceFiles { files } => {
            for file in files {
                // Friends-only files are never announced to KAD. Publishing a
                // source or keyword for one would make it discoverable by
                // search even though browse hides it.
                if !file.is_public_listable() {
                    continue;
                }
                if let Ok(raw_bytes) = hex::decode(&file.hash) {
                    if raw_bytes.len() != 16 {
                        continue;
                    }
                    let kad_hash = md4_bytes_to_kad_id(&raw_bytes);
                    let publishable = PublishableFile {
                        file_hash: kad_hash,
                        file_name: file.name.clone(),
                        file_size: file.size,
                        file_type: crate::search::index::infer_file_type(&file.extension),
                        complete_sources: file.complete_sources,
                        keyword_publishable: true,
                        last_source_publish: {
                            let mut raw = [0u8; 16];
                            raw.copy_from_slice(&raw_bytes);
                            known_files
                                .find_by_hash(&raw)
                                .map(|r| r.last_publish_src as i64)
                                .unwrap_or(0)
                        },
                    };
                    state.publish_manager.add_file(publishable);
                }
            }
            info!(
                "Registered {} files for KAD publishing",
                state.publish_manager.file_count()
            );
        }

        NetworkCommand::RepublishFile { file_hash_hex } => {
            let Ok(raw_bytes) = hex::decode(&file_hash_hex) else {
                warn!("RepublishFile: invalid hex in file hash");
                return;
            };
            if raw_bytes.len() != 16 {
                warn!(
                    "RepublishFile: expected 16-byte MD4 hash, got {}",
                    raw_bytes.len()
                );
                return;
            }
            let kad_hash = md4_bytes_to_kad_id(&raw_bytes);
            state.publish_manager.reset_source_publish(&kad_hash);
            state.publish_manager.reset_keyword_publish(&kad_hash);
            info!(
                "Scheduled immediate KAD republish for file hash {}",
                &file_hash_hex[..file_hash_hex.len().min(16)]
            );
        }

        NetworkCommand::PublishNote {
            file_hash,
            file_name,
            file_size,
            rating,
            comment,
            tx,
        } => {
            if state.stats.status == NetworkStatus::Disconnected {
                let _ = tx.send(Err("KAD is disconnected".to_string()));
                return;
            }
            let closest = state
                .routing_table
                .find_closest_prefer_verified(&file_hash, SEARCH_INITIAL_CONTACTS);

            if closest.is_empty() {
                debug!("No contacts to publish note to");
                let _ = tx.send(Err(
                    "No live KAD contacts available to publish note".to_string()
                ));
                return;
            }

            let sid = start_kad_search(
                state,
                app_handle,
                file_hash,
                SearchType::StoreNotes,
                closest,
            );
            if sid == SearchId(0) {
                debug!("Failed to start StoreNotes search: too many active searches");
                let _ = tx.send(Err(
                    "KAD publish capacity is busy; retry shortly".to_string()
                ));
            } else {
                let local_note_file = {
                    let index = local_index.read().await;
                    index.get_by_hash(&file_hash.to_hex()).cloned()
                };
                let message = build_publish_notes_message(
                    state.local_id,
                    file_hash,
                    local_note_file,
                    file_name.as_deref(),
                    file_size,
                    rating,
                    &comment,
                );
                state.pending_note_publishes.insert(
                    sid,
                    PendingNotePublish {
                        file_hash,
                        rating,
                        comment: comment.clone(),
                        file_name: file_name.clone(),
                        file_size,
                        message,
                    },
                );
                info!(
                    "Started StoreNotes search {} for file {} (rating={}, comment_len={})",
                    sid.0,
                    file_hash,
                    rating,
                    comment.len()
                );
                // Track (and persist) the note right away with a
                // `last_publish: 0` sentinel — not `now_ts` — so it survives
                // a crash/restart before this attempt finishes and, if this
                // attempt sends to zero nodes, the round-robin republish
                // scheduler's `now_ts - note.last_publish > REPUBLISH_NOTE_SECS`
                // due-check finds it immediately eligible for retry instead
                // of waiting a full 24h. `last_publish` is only bumped to a
                // real timestamp once PublishNotesReq packets actually go
                // out (the `sent > 0` branch in the StoreNotes
                // search-completion handler), so the 24h timer can't be
                // reset by a search that found no reachable nodes.
                if rating > 0 || !comment.trim().is_empty() {
                    state.published_notes.insert(
                        file_hash,
                        PublishedNote {
                            rating,
                            comment: comment.clone(),
                            file_name: file_name.clone(),
                            file_size,
                            last_publish: 0,
                        },
                    );
                    if let Err(e) = db.save_published_note(
                        &file_hash.to_hex(),
                        rating,
                        &comment,
                        0,
                        file_name.as_deref(),
                        file_size,
                    ) {
                        warn!("Failed to persist published note for republish: {e}");
                    }
                }
                let _ = tx.send(Ok(()));
            }
        }

        NetworkCommand::BanPeer { peer_id_hex } => {
            if let Some(kad_id) = KadId::from_hex(&peer_id_hex) {
                // Collect every IP we can associate with this peer so the
                // ban also covers the IP-keyed paths (accept loop, UDP,
                // download/source connect), not just the user-hash upload
                // gate. Sources:
                //   1. The KAD routing-table contact (only matches when the
                //      ban id happens to be the peer's *node* id).
                //   2. Peer DB rows whose id equals the ban id.
                //   3. Known download sources for this user hash — the UI
                //      bans by eD2K user hash, which (1) and (2) are keyed
                //      differently from, so without this a non-active peer's
                //      IP was never blocked. Mirrors the reputation-ban path.
                let mut ips_to_ban: Vec<Ipv4Addr> = Vec::new();
                let contact_ip = state.routing_table.get_contact(&kad_id).map(|c| c.ip);
                if state.routing_table.remove(&kad_id) {
                    info!("Removed banned peer {} from routing table", peer_id_hex);
                    state.stats.connected_peers = state.routing_table.len() as u32;
                }
                if let Some(ip) = contact_ip {
                    ips_to_ban.push(ip);
                }
                if let Ok(peers) = db.get_peers() {
                    for peer in &peers {
                        if peer.id == peer_id_hex {
                            for addr_str in &peer.addresses {
                                if let Some((ip_str, _)) = addr_str.rsplit_once(':') {
                                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                                        ips_to_ban.push(ip);
                                    }
                                }
                            }
                        }
                    }
                }
                {
                    let sm = source_manager.read().await;
                    for ip in sm.find_ips_by_user_hash(&kad_id.0) {
                        ips_to_ban.push(ip);
                    }
                }
                for ip in &ips_to_ban {
                    state.banned_ips.insert(*ip);
                    // Persist the IP against this peer so the ban survives a
                    // restart (boot rebuilds banned_ips from banned peers'
                    // addresses) and so unban_peer — which walks the peer's
                    // addresses — clears it again. Keeps ban/unban symmetric.
                    if let Err(e) = db.add_banned_peer_address(&peer_id_hex, *ip) {
                        warn!("Failed to persist banned IP {ip} for peer {peer_id_hex}: {e}");
                    }
                }
                if let Ok(mut shared) = shared_banned_ips.write() {
                    *shared = state.banned_ips.clone();
                }
                // Also add user hash to upload-only banned set
                if let Ok(mut set) = shared_banned_hashes.write() {
                    set.insert(kad_id.0);
                }
                // Keep ReputationManager in sync so Trust badges and
                // reputation-gated connect paths see the manual ban
                // immediately (UnbanPeer already cleared this side).
                state.reputation.apply_manual_ban(&kad_id.0);
            }
        }

        NetworkCommand::UnbanPeer { peer_id_hex } => {
            if let Some(kad_id) = KadId::from_hex(&peer_id_hex) {
                if let Some(contact) = state.routing_table.get_contact(&kad_id) {
                    state.banned_ips.remove(&contact.ip);
                    if let Err(e) = db.unban_ip(contact.ip) {
                        warn!(
                            "Failed to clear persisted IP ban for {} (peer {peer_id_hex}): {e}",
                            contact.ip
                        );
                    }
                }
            }
            if let Ok(peers) = db.get_peers() {
                for peer in &peers {
                    if peer.id == peer_id_hex {
                        for addr_str in &peer.addresses {
                            if let Some((ip_str, _)) = addr_str.rsplit_once(':') {
                                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                                    state.banned_ips.remove(&ip);
                                    // Also clear any persistent auto-ban for this IP.
                                    if let Err(e) = db.unban_ip(ip) {
                                        warn!(
                                            "Failed to clear persisted IP ban for {ip} (peer {peer_id_hex}): {e}"
                                        );
                                    }
                                    // Soften IP-reputation so the next scored
                                    // event cannot immediately re-arm an IP ban.
                                    let _ = state.reputation.clear_ip_ban(ip);
                                }
                            }
                        }
                    }
                }
            }
            if let Ok(mut shared) = shared_banned_ips.write() {
                *shared = state.banned_ips.clone();
            }
            // Also remove from upload-only banned set, and clear any
            // reputation ban for this user hash — otherwise the source /
            // callback paths (which gate on `reputation.is_banned`) would
            // keep the peer blocked despite the UI showing them unbanned.
            if let Some(kad_id) = KadId::from_hex(&peer_id_hex) {
                if let Ok(mut set) = shared_banned_hashes.write() {
                    set.remove(&kad_id.0);
                }
                if state.reputation.clear_ban(&kad_id.0) {
                    debug!("Cleared reputation ban for {peer_id_hex}");
                }
                // Routing-table contact IP may not be on the peer row.
                if let Some(contact) = state.routing_table.get_contact(&kad_id) {
                    let _ = state.reputation.clear_ip_ban(contact.ip);
                    state.banned_ips.remove(&contact.ip);
                }
                // Reputation bans mirror onto every SourceManager IP for the
                // user hash; clear those too or the next sync_enforced_banned_ips
                // tick would re-inject them from currently_banned_ips().
                {
                    let sm = source_manager.read().await;
                    for ip in sm.find_ips_by_user_hash(&kad_id.0) {
                        let _ = state.reputation.clear_ip_ban(ip);
                        state.banned_ips.remove(&ip);
                    }
                }
                if let Ok(mut shared) = shared_banned_ips.write() {
                    *shared = state.banned_ips.clone();
                }
            }
            info!("Unbanned peer {peer_id_hex}");
        }

        NetworkCommand::GetPeersSnapshot { tx } => {
            let peers = routing_peers_snapshot(state);
            let db_for_peers = db.clone();
            tokio::spawn(async move {
                let saved_peers = tokio::task::spawn_blocking(move || {
                    db_for_peers.get_peers().unwrap_or_default()
                })
                .await
                .unwrap_or_default();
                let _ = tx.send(merge_saved_peers(peers, saved_peers));
            });
        }

        NetworkCommand::GetNetworkStatsSnapshot { tx } => {
            // Always reflect the live checker — poll consumers must not see a
            // stale "Unknown" after connect-backs / HighID already proved Open.
            state.stats.tcp_status = format!("{:?}", state.firewall_checker.tcp_status());
            state.stats.udp_status = format!("{:?}", state.firewall_checker.udp_status());
            // EmberDHT status-bar gauges — same sources as GetEmberDiagnostics.
            state.stats.ember_native_enabled = settings.ember_native_enabled;
            let (ember_contacts, ember_verified) = ember_dht_ui_contact_counts(state);
            state.stats.ember_dht_contacts = ember_contacts;
            state.stats.ember_dht_verified_contacts = ember_verified;
            let _ = tx.send(state.stats.clone());
        }

        NetworkCommand::GetEmberDiagnostics { tx } => {
            let mut diag = state.ember_diagnostics.clone();
            diag.ember_peers_known = state.known_ember_peers.len() as u32;
            diag.ember_native_enabled = settings.ember_native_enabled;
            diag.ember_sessions = state.ember_transport.session_count() as u32;
            diag.local_noise_public_key =
                hex::encode(state.ember_transport.local_noise_public_key());
            diag.ember_dht_node_id = state.ember_dht.local_id().to_hex();
            diag.local_ed25519_public_key = hex::encode(state.ember_dht.ed25519_public_key());
            let (ember_contacts, ember_verified) = ember_dht_ui_contact_counts(state);
            diag.ember_dht_contacts = ember_contacts;
            diag.ember_dht_verified_contacts = ember_verified;
            if note_ember_verified_contacts(
                &mut state.ember_verified_highwater,
                diag.ember_dht_verified_contacts,
            ) {
                state.ember_verified_highwater_dirty = true;
            }
            diag.ember_dht_verified_highwater_today = state.ember_verified_highwater.daily;
            diag.ember_dht_verified_highwater = state.ember_verified_highwater.alltime;
            diag.ember_dht_estimated_nodes = state
                .ember_dht
                .routing()
                .estimated_network_size()
                .unwrap_or(0)
                .min(u32::MAX as u64) as u32;
            diag.ember_dht_republish_backlog = state
                .ember_dht
                .republish_backlog(std::time::Duration::from_secs(EMBER_RECORD_REPUBLISH_SECS))
                as u32;
            diag.ember_dht_seconds_since_inbound = state
                .ember_last_inbound
                .map(|at| {
                    chrono::Utc::now()
                        .timestamp()
                        .saturating_sub(at)
                        .clamp(0, u32::MAX as i64) as u32
                })
                .unwrap_or(0);
            diag.ember_dht_active_searches = state.ember_search.active_count() as u32;
            diag.ember_dht_published_files = state.ember_published_sources.len() as u32;
            let (store_keys, store_records) = state.ember_dht.store_stats();
            diag.ember_dht_stored_keys = store_keys as u32;
            diag.ember_dht_stored_records = store_records as u32;
            let (foreign_keys, foreign_records) = state.ember_dht.foreign_store_stats();
            diag.ember_dht_stored_for_others_keys = foreign_keys as u32;
            diag.ember_dht_stored_for_others_records = foreign_records as u32;
            // Both publish paths: single-record operations (proxy-store
            // forwarding, the manual command) plus batches awaiting an ack.
            // Reading only the former showed zero while the batch publisher
            // was doing all the work.
            diag.ember_dht_active_publishes = (state.ember_publish.active_count()
                + state.ember_batch_publish.in_flight.len())
                as u32;
            diag.ember_dht_avg_replication = if diag.ember_dht_publishes_completed > 0 {
                (diag.ember_dht_replication_sum / diag.ember_dht_publishes_completed as u64) as u32
            } else {
                0
            };
            diag.ember_dht_observed_addr = state
                .ember_observed_votes
                .confirmed()
                .map(|a| a.to_string())
                .unwrap_or_default();
            {
                let fs = state.friend_xfer_stats;
                diag.friend_xfer_connect_back_requested = fs.connect_back_requested;
                diag.friend_xfer_punch_requested = fs.punch_requested;
                diag.friend_xfer_accepted = fs.accepted;
                diag.friend_xfer_declined = fs.declined;
                diag.friend_xfer_connected = fs.connected;
                diag.friend_xfer_timed_out = fs.timed_out;
                diag.friend_xfer_inbound_accepted = fs.inbound_accepted;
                diag.friend_xfer_inbound_declined = fs.inbound_declined;
            }
            if let Some(ref broker) = state.connection_broker {
                let bs = broker.stats();
                diag.broker_relay_attempts = bs.relay_attempts;
                diag.broker_relay_successes = bs.relay_successes;
                diag.broker_relay_failures = bs.relay_failures;
                diag.broker_active_attempts = broker.active_attempts() as u32;
                diag.broker_relay_candidates = broker.relay_candidate_count() as u32;
                diag.broker_oldest_attempt_age_secs = broker.oldest_attempt_age_secs().unwrap_or(0);
            }
            {
                let rm = state.relay_manager.lock().await;
                diag.relay_sessions_active = rm.active_count() as u32;
                diag.relay_bytes_relayed = rm.total_bytes_relayed();
            }
            let _ = tx.send(diag);
        }

        NetworkCommand::SendEmberPing {
            addr,
            peer_pubkey,
            tx,
        } => {
            // Feature gate: refuse here so the harness gets a clear
            // "feature off" string instead of a silent timeout.
            if !settings.ember_native_enabled {
                let _ = tx.send(Err("Ember-native transport is disabled".to_string()));
                return;
            }

            // Resolve the peer's Noise pubkey: prefer an explicit
            // value from the caller, otherwise fall back to the cache
            // populated from KAD source publishes carrying
            // `EMBER_NOISE_PUB_TAG`. A cache miss is surfaced as a
            // clear error so the harness can distinguish "we have no
            // key for this peer" from "Noise handshake failed".
            let resolved_pubkey = match peer_pubkey {
                Some(k) => k,
                None => match (addr.ip(), addr.port()) {
                    (std::net::IpAddr::V4(v4), port) => {
                        match lookup_ember_noise_key(&state.ember_noise_keys, v4, port) {
                            Some(k) => k,
                            None => {
                                let _ = tx.send(Err(format!(
                                    "No cached Ember Noise pubkey for {addr}; \
                                     pass peer_pubkey_hex explicitly or wait for \
                                     a KAD source publish to populate the cache"
                                )));
                                return;
                            }
                        }
                    }
                    _ => {
                        let _ = tx.send(Err(
                            "Noise pubkey lookup is IPv4-only — pass peer_pubkey_hex explicitly"
                                .into(),
                        ));
                        return;
                    }
                },
            };

            // Bound the pending map. A stuck peer (no Pong reply) keeps
            // an entry around until `cleanup` reaps the session, but
            // each entry is small and the cap prevents a misbehaving
            // peer or a chatty harness from growing the map unboundedly.
            if state.ember_pending_pings.len() >= MAX_EMBER_PENDING_PINGS {
                let _ = tx.send(Err(format!(
                    "Too many in-flight Ember pings ({})",
                    state.ember_pending_pings.len()
                )));
                return;
            }

            // Cryptographically random nonce so two harness operators
            // probing the same peer do not collide on a sequential
            // counter (and so the entry cannot be predicted by a
            // third party watching the wire).
            let nonce: u64 = rand::random();

            let payload = ember::transport::EmberControlMessage::Ping { nonce }.encode();

            let mut sent_on_wire = false;
            match state
                .ember_transport
                .prepare_outgoing(addr, Some(&resolved_pubkey), &payload)
            {
                ember::transport::OutgoingResult::Ready { packet }
                | ember::transport::OutgoingResult::HandshakeStarted { packet } => {
                    if let Err(e) =
                        send_ember_udp(socket, &packet, addr, &state.ember_dht_overhead).await
                    {
                        let _ = tx.send(Err(format!("send_to({addr}) failed: {e}")));
                        return;
                    }
                    sent_on_wire = true;
                }
                ember::transport::OutgoingResult::Queued => {
                    // Message queued behind an in-progress handshake;
                    // it'll be flushed when the handshake completes,
                    // and the matching Pong will resolve the oneshot
                    // exactly the same way as the Ready path.
                }
                ember::transport::OutgoingResult::Error(err) => {
                    let _ = tx.send(Err(format!("Ember transport error: {err}")));
                    return;
                }
            }

            if sent_on_wire {
                state.ember_diagnostics.ember_pings_sent =
                    state.ember_diagnostics.ember_pings_sent.saturating_add(1);
            }

            let (pong_tx, pong_rx) = oneshot::channel();
            state
                .ember_pending_pings
                .insert(nonce, (std::time::Instant::now(), pong_tx));

            let _ = tx.send(Ok(EmberPingPending { pong_rx }));
        }

        NetworkCommand::AddEmberDhtContact {
            addr,
            ed25519_pub,
            noise_pub,
            tx,
        } => {
            // Derive the node ID from the supplied Ed25519 key so the
            // contact is self-consistent (`node_id == BLAKE3(pub)[..16]`)
            // exactly like one learned from a signed frame. A key that
            // isn't a valid curve point is rejected outright.
            let node_id = match ember::crypto::verifying_key_from_bytes(&ed25519_pub) {
                Some(vk) => ember::dht::EmberNodeId(ember::crypto::node_id_from_public_key(&vk)),
                None => {
                    let _ = tx.send(Err("Invalid Ed25519 public key".to_string()));
                    return;
                }
            };
            let contact = ember::dht::EmberContact {
                node_id,
                addr,
                noise_pub,
                ed25519_pub,
                last_seen: chrono::Utc::now().timestamp(),
                failed_queries: 0,
            };
            if state.ember_dht.add_contact(contact) {
                let _ = tx.send(Ok(()));
            } else {
                let _ = tx.send(Err(
                    "Contact not added (it is our own ID, hit a subnet-diversity limit, or its bucket is full)"
                        .to_string(),
                ));
            }
        }

        NetworkCommand::GetEmberDhtContacts { tx } => {
            let local_id = state.ember_dht.local_id();
            let mut seen: HashSet<[u8; 16]> = HashSet::new();
            let mut contacts: Vec<EmberDhtContactInfo> = Vec::new();
            for c in state.ember_dht.contacts() {
                seen.insert(c.node_id.0);
                let mut info = ember_dht_contact_info(&c, local_id);
                info.addr.clear();
                info.noise_pub.clear();
                info.ed25519_pub.clear();
                contacts.push(info);
            }
            // Firsthand session peers the public table refused (LAN while
            // `block_private_ips` is on). The gauges already count them as
            // verified; omitting them here left the contact table empty on a
            // LAN island that the status bar called connected.
            for c in state.ember_session_dht_contacts.values() {
                if !seen.insert(c.node_id.0) {
                    continue;
                }
                let mut info = ember_dht_contact_info(c, local_id);
                info.addr.clear();
                info.noise_pub.clear();
                info.ed25519_pub.clear();
                contacts.push(info);
            }
            let _ = tx.send(contacts);
        }

        NetworkCommand::GetEmberDhtSearches { tx } => {
            let searches = state
                .ember_search
                .snapshot()
                .into_iter()
                .map(|s| EmberDhtSearchInfo {
                    id: s.id,
                    search_type: s.search_type,
                    target: s.target,
                    keyword_count: s.keyword_count,
                    results: s.results,
                    queried: s.queried,
                    in_flight: s.in_flight,
                    responded: s.responded,
                    pending: s.pending,
                    complete: s.complete,
                    age_secs: s.started_at_secs,
                })
                .collect();
            let _ = tx.send(searches);
        }

        NetworkCommand::GetEmberDhtStore { tx } => {
            const MAX_STORE_ROWS: usize = 500;
            let entries = state
                .ember_dht
                .store_entries(MAX_STORE_ROWS)
                .into_iter()
                .map(|e| EmberDhtStoreInfo {
                    key: hex::encode(e.key),
                    record_count: e.record_count,
                    keyword_records: e.keyword_records,
                    source_records: e.source_records,
                })
                .collect();
            let _ = tx.send(entries);
        }

        NetworkCommand::SendEmberExchangeRequest {
            addr,
            peer_pubkey,
            tx,
        } => {
            // Feature gate: refuse here so the harness gets a clear
            // "feature off" string instead of a silent no-op.
            if !settings.ember_native_enabled {
                let _ = tx.send(Err("Ember-native transport is disabled".to_string()));
                return;
            }

            // Resolve the peer's Noise pubkey the same way SendEmberPing
            // does: explicit value wins, otherwise the KAD-fed cache.
            let resolved_pubkey = match peer_pubkey {
                Some(k) => k,
                None => match (addr.ip(), addr.port()) {
                    (std::net::IpAddr::V4(v4), port) => {
                        match lookup_ember_noise_key(&state.ember_noise_keys, v4, port) {
                            Some(k) => k,
                            None => {
                                let _ = tx.send(Err(format!(
                                    "No cached Ember Noise pubkey for {addr}; \
                                     pass peer_pubkey_hex explicitly or wait for \
                                     a KAD source publish to populate the cache"
                                )));
                                return;
                            }
                        }
                    }
                    _ => {
                        let _ = tx.send(Err(
                            "Noise pubkey lookup is IPv4-only — pass peer_pubkey_hex explicitly"
                                .into(),
                        ));
                        return;
                    }
                },
            };

            let payload = ember::transport::EmberControlMessage::ExchangeRequest.encode();

            match state
                .ember_transport
                .prepare_outgoing(addr, Some(&resolved_pubkey), &payload)
            {
                ember::transport::OutgoingResult::Ready { packet }
                | ember::transport::OutgoingResult::HandshakeStarted { packet } => {
                    if let Err(e) = send_ember_udp(socket, &packet, addr, &state.epx_overhead).await
                    {
                        let _ = tx.send(Err(format!("send_to({addr}) failed: {e}")));
                        return;
                    }
                }
                ember::transport::OutgoingResult::Queued => {
                    // Queued behind an in-progress handshake; it flushes
                    // when the handshake completes, same as the ping path.
                }
                ember::transport::OutgoingResult::Error(err) => {
                    let _ = tx.send(Err(format!("Ember transport error: {err}")));
                    return;
                }
            }

            let _ = tx.send(Ok(()));
        }

        NetworkCommand::SendEmberDhtPing {
            addr,
            peer_pubkey,
            tx,
        } => {
            // Same feature gate and Noise-key resolution as
            // SendEmberPing, but the frame is a signed DHT PING — so a
            // successful round trip also seeds both routing tables.
            if !settings.ember_native_enabled {
                let _ = tx.send(Err("Ember-native transport is disabled".to_string()));
                return;
            }

            let resolved_pubkey = match peer_pubkey {
                Some(k) => k,
                None => match (addr.ip(), addr.port()) {
                    (std::net::IpAddr::V4(v4), port) => {
                        match lookup_ember_noise_key(&state.ember_noise_keys, v4, port) {
                            Some(k) => k,
                            None => {
                                let _ = tx.send(Err(format!(
                                    "No cached Ember Noise pubkey for {addr}; \
                                     pass peer_pubkey_hex explicitly or wait for \
                                     a KAD source publish to populate the cache"
                                )));
                                return;
                            }
                        }
                    }
                    _ => {
                        let _ = tx.send(Err(
                            "Noise pubkey lookup is IPv4-only — pass peer_pubkey_hex explicitly"
                                .into(),
                        ));
                        return;
                    }
                },
            };

            if state.ember_dht_pending_pings.len() >= MAX_EMBER_PENDING_PINGS {
                let _ = tx.send(Err(format!(
                    "Too many in-flight Ember DHT pings ({})",
                    state.ember_dht_pending_pings.len()
                )));
                return;
            }

            let (request_id, frame) = state.ember_dht.build_ping();

            let mut sent_on_wire = false;
            match state
                .ember_transport
                .prepare_outgoing(addr, Some(&resolved_pubkey), &frame)
            {
                ember::transport::OutgoingResult::Ready { packet }
                | ember::transport::OutgoingResult::HandshakeStarted { packet } => {
                    if let Err(e) =
                        send_ember_udp(socket, &packet, addr, &state.ember_dht_overhead).await
                    {
                        let _ = tx.send(Err(format!("send_to({addr}) failed: {e}")));
                        return;
                    }
                    sent_on_wire = true;
                }
                ember::transport::OutgoingResult::Queued => {}
                ember::transport::OutgoingResult::Error(err) => {
                    let _ = tx.send(Err(format!("Ember transport error: {err}")));
                    return;
                }
            }

            if sent_on_wire {
                state.ember_diagnostics.ember_dht_pings_sent = state
                    .ember_diagnostics
                    .ember_dht_pings_sent
                    .saturating_add(1);
            }

            let (pong_tx, pong_rx) = oneshot::channel();
            state
                .ember_dht_pending_pings
                .insert(request_id, (std::time::Instant::now(), addr, pong_tx));

            let _ = tx.send(Ok(EmberPingPending { pong_rx }));
        }

        NetworkCommand::SendEmberDhtFindNode {
            addr,
            peer_pubkey,
            target,
            tx,
        } => {
            // Single-hop FIND_NODE: ask one peer for the k contacts it
            // knows closest to `target`, and hand the answer back to the
            // dev panel. Same feature gate and Noise-key resolution as
            // SendEmberDhtPing; the iterative multi-hop driver is a later
            // slice that loops this primitive.
            if !settings.ember_native_enabled {
                let _ = tx.send(Err("Ember-native transport is disabled".to_string()));
                return;
            }

            let resolved_pubkey = match peer_pubkey {
                Some(k) => k,
                None => match (addr.ip(), addr.port()) {
                    (std::net::IpAddr::V4(v4), port) => {
                        match lookup_ember_noise_key(&state.ember_noise_keys, v4, port) {
                            Some(k) => k,
                            None => {
                                let _ = tx.send(Err(format!(
                                    "No cached Ember Noise pubkey for {addr}; \
                                     pass peer_pubkey_hex explicitly or wait for \
                                     a KAD source publish to populate the cache"
                                )));
                                return;
                            }
                        }
                    }
                    _ => {
                        let _ = tx.send(Err(
                            "Noise pubkey lookup is IPv4-only — pass peer_pubkey_hex explicitly"
                                .into(),
                        ));
                        return;
                    }
                },
            };

            if state.ember_dht_pending_finds.len() >= MAX_EMBER_PENDING_PINGS {
                let _ = tx.send(Err(format!(
                    "Too many in-flight Ember DHT finds ({})",
                    state.ember_dht_pending_finds.len()
                )));
                return;
            }

            // A blank target means "show me whatever this peer knows" —
            // a random ID exercises the closest-set logic without caring
            // where it lands in the keyspace.
            let target = ember::dht::EmberNodeId(target.unwrap_or_else(rand::random));
            let (request_id, frame) = state.ember_dht.build_find_node(target);

            let mut sent_on_wire = false;
            match state
                .ember_transport
                .prepare_outgoing(addr, Some(&resolved_pubkey), &frame)
            {
                ember::transport::OutgoingResult::Ready { packet }
                | ember::transport::OutgoingResult::HandshakeStarted { packet } => {
                    if let Err(e) =
                        send_ember_udp(socket, &packet, addr, &state.ember_dht_overhead).await
                    {
                        let _ = tx.send(Err(format!("send_to({addr}) failed: {e}")));
                        return;
                    }
                    sent_on_wire = true;
                }
                ember::transport::OutgoingResult::Queued => {}
                ember::transport::OutgoingResult::Error(err) => {
                    let _ = tx.send(Err(format!("Ember transport error: {err}")));
                    return;
                }
            }

            if sent_on_wire {
                state.ember_diagnostics.ember_dht_find_nodes_sent = state
                    .ember_diagnostics
                    .ember_dht_find_nodes_sent
                    .saturating_add(1);
            }

            let (contacts_tx, contacts_rx) = oneshot::channel();
            state
                .ember_dht_pending_finds
                .insert(request_id, (std::time::Instant::now(), contacts_tx));

            let _ = tx.send(Ok(EmberDhtFindPending { contacts_rx }));
        }

        NetworkCommand::SendEmberDhtIterativeFindNode { target, tx } => {
            // Start a multi-hop lookup and let the driver fan out
            // FIND_NODE rounds across the closest contacts it learns.
            if !settings.ember_native_enabled {
                let _ = tx.send(Err("Ember-native transport is disabled".to_string()));
                return;
            }

            let target = ember::dht::EmberNodeId(target.unwrap_or_else(rand::random));
            let search_id = match start_ember_find_node(state, target) {
                Some(id) => id,
                None => {
                    let _ = tx.send(Err(format!(
                        "Too many active Ember DHT searches ({})",
                        state.ember_search.active_count()
                    )));
                    return;
                }
            };

            let (contacts_tx, contacts_rx) = oneshot::channel();
            state
                .ember_dht_pending_lookups
                .insert(search_id, contacts_tx);
            let _ = tx.send(Ok(EmberDhtLookupPending { contacts_rx }));

            // Kick off the first round (and resolve immediately if the
            // routing table had nothing to seed the shortlist with).
            drive_ember_search(socket, state, search_id).await;
        }

        NetworkCommand::PublishEmberKeyword {
            keyword,
            file_name,
            file_size,
            file_hash,
            tx,
        } => {
            if !settings.ember_native_enabled {
                let _ = tx.send(Err("Ember-native transport is disabled".to_string()));
                return;
            }

            // Prefer the content BLAKE3 from the shared library when this
            // file_hash is one of ours; otherwise leave zeros (dev/random hash).
            let ember_file_hash = {
                let hash_hex = hex::encode(file_hash);
                let idx = local_index.read().await;
                idx.get_by_hash(&hash_hex)
                    .map(|f| parse_ember_file_hash(&f.ember_file_hash))
                    .unwrap_or([0u8; 32])
            };
            let record = state.ember_dht.build_keyword_record(
                &keyword,
                file_hash,
                ember_file_hash,
                file_size,
                &file_name,
            );
            let key = record.keyword_hash;
            let key_hex = hex::encode(key);
            let targets = ember_overlay_publish_targets(state, key);

            let publish_id = match state.ember_publish.start_publish_to(record, targets) {
                Some(id) => id,
                None => {
                    let _ = tx.send(Err(format!(
                        "Too many active Ember DHT publishes ({})",
                        state.ember_publish.active_count()
                    )));
                    return;
                }
            };

            let (result_tx, result_rx) = oneshot::channel();
            state
                .ember_dht_pending_publishes
                .insert(publish_id, result_tx);
            let _ = tx.send(Ok(EmberPublishPending {
                key: key_hex,
                result_rx,
            }));

            // Fan out the STOREs (and resolve immediately if the routing
            // table had no targets to store on).
            drive_ember_publish(socket, state, publish_id).await;
        }

        NetworkCommand::FindEmberValue { keyword, tx } => {
            if !settings.ember_native_enabled {
                let _ = tx.send(Err("Ember-native transport is disabled".to_string()));
                return;
            }

            let hashed = ember::dht::search::compute_keyword_hashes(&keyword);
            let Some((primary_hash, _)) = hashed.first() else {
                let _ = tx.send(Err("Keyword is empty".to_string()));
                return;
            };
            let extras: Vec<[u8; 16]> = hashed.iter().skip(1).map(|(h, _)| *h).collect();
            let primary = ember::dht::EmberNodeId(*primary_hash);
            let search_id = match state.ember_search.start_find_value(
                primary,
                extras.clone(),
                state.ember_dht.routing(),
            ) {
                Some(id) => id,
                None => {
                    let _ = tx.send(Err(format!(
                        "Too many active Ember DHT searches ({})",
                        state.ember_search.active_count()
                    )));
                    return;
                }
            };

            seed_ember_local_records(state, search_id, primary_hash, &extras);
            seed_ember_session_search_contacts(state, search_id);

            let (records_tx, records_rx) = oneshot::channel();
            state
                .ember_dht_pending_value_lookups
                .insert(search_id, records_tx);
            let _ = tx.send(Ok(EmberValueLookupPending { records_rx }));

            // Kick off the first round (and resolve immediately if the
            // routing table had nothing to seed the shortlist with).
            drive_ember_search(socket, state, search_id).await;
        }

        NetworkCommand::PublishEmberRecord { record, tx } => {
            if !settings.ember_native_enabled {
                let _ = tx.send(Err("Ember-native transport is disabled".to_string()));
                return;
            }
            let key_hex = hex::encode(record.keyword_hash);
            let publish_id = match state
                .ember_publish
                .start_publish(record, state.ember_dht.routing())
            {
                Some(id) => id,
                None => {
                    let _ = tx.send(Err(format!(
                        "Too many active Ember DHT publishes ({})",
                        state.ember_publish.active_count()
                    )));
                    return;
                }
            };
            let (result_tx, result_rx) = oneshot::channel();
            state
                .ember_dht_pending_publishes
                .insert(publish_id, result_tx);
            let _ = tx.send(Ok(EmberPublishPending {
                key: key_hex,
                result_rx,
            }));
            drive_ember_publish(socket, state, publish_id).await;
        }

        NetworkCommand::FindEmberKeys { keys, tx } => {
            if !settings.ember_native_enabled {
                let _ = tx.send(Err("Ember-native transport is disabled".to_string()));
                return;
            }
            if keys.is_empty() {
                let _ = tx.send(Err("No DHT keys".to_string()));
                return;
            }
            let cap = ember::dht::messages::MAX_FIND_VALUE_KEYS;
            let keys: Vec<[u8; 16]> = keys.into_iter().take(cap).collect();
            let primary_hash = keys[0];
            let extras: Vec<[u8; 16]> = keys.iter().skip(1).copied().collect();
            let primary = ember::dht::EmberNodeId(primary_hash);
            let search_id = match state.ember_search.start_find_value(
                primary,
                extras.clone(),
                state.ember_dht.routing(),
            ) {
                Some(id) => id,
                None => {
                    let _ = tx.send(Err(format!(
                        "Too many active Ember DHT searches ({})",
                        state.ember_search.active_count()
                    )));
                    return;
                }
            };
            seed_ember_local_records(state, search_id, &primary_hash, &extras);
            let (records_tx, records_rx) = oneshot::channel();
            state
                .ember_dht_pending_value_lookups
                .insert(search_id, records_tx);
            let _ = tx.send(Ok(EmberValueLookupPending { records_rx }));
            drive_ember_search(socket, state, search_id).await;
        }

        NetworkCommand::FanoutChannelGossip { body } => {
            if !settings.ember_native_enabled {
                return;
            }
            if let Some(gossip) = ember::channel::ChannelGossip::decode(&body) {
                let _ = remember_channel_gossip(state, gossip.msg_id);
            }
            fanout_channel_gossip_body(socket, state, db, body, None).await;
        }

        NetworkCommand::RunEmberMaintenance { tx } => {
            if !settings.ember_native_enabled {
                let _ = tx.send(Err("Ember-native transport is disabled".to_string()));
                return;
            }
            // `force = true`: the on-demand command bypasses the staleness
            // gates so a refresh / ping / republish can be observed right
            // away even on a freshly-active table.
            let result = run_ember_maintenance(socket, state, true).await;
            let _ = tx.send(Ok(result));
        }

        NetworkCommand::GetUploadQueueSnapshot { tx } => {
            let snap = upload_queue_snapshot(
                upload_queue,
                credit_manager,
                local_index,
                friend_hashes,
                geoip,
            )
            .await;
            let _ = tx.send(snap);
        }

        NetworkCommand::GetKnownClientsSnapshot { tx } => {
            let snap =
                known_clients_snapshot(credit_manager, friend_hashes, upload_queue, geoip, &db)
                    .await;
            let _ = tx.send(snap);
        }

        NetworkCommand::GetAntiLeechSnapshot { tx } => {
            let _ = tx.send(antileech_snapshot(state));
        }

        NetworkCommand::SetAntiLeechPatterns { patterns, tx } => {
            let _ = tx.send(antileech_set_patterns(state, patterns));
        }

        NetworkCommand::SetAntiLeechEnabled { enabled, tx } => {
            let _ = tx.send(antileech_set_enabled(state, enabled));
        }

        NetworkCommand::ResetAntiLeechToDefaults { tx } => {
            let _ = tx.send(antileech_reset_defaults(state));
        }

        NetworkCommand::GetKadContactsSnapshot { tx } => {
            let _ = tx.send(kad_contacts_snapshot(state, state.local_id));
        }

        NetworkCommand::GetKadSearchesSnapshot { tx } => {
            let _ = tx.send(kad_searches_snapshot(state));
        }

        NetworkCommand::CancelKadSearch { id } => {
            // K30: release routing-table in-use refs first (so the
            // contacts can be cleaned up normally) then drop the search.
            let sid = crate::network::kad::search::SearchId(id);
            if let Some(removed) = state.search_manager.remove(&sid) {
                // Beyond the in-use refs, a cancelled search can still have
                // pending IPC oneshots (`pending_keyword_searches` /
                // `pending_source_searches` / `pending_notes_searches`) and
                // bookkeeping entries (`download_source_searches`,
                // `store_keyword_searches`, `store_source_searches`,
                // `pending_note_publishes`) keyed on this `sid`. Without
                // this, callers of `find_notes`/`find_sources`/global
                // search hang until their own IPC timeout instead of
                // resolving immediately, and `active_search_request.kad_pending`
                // can be left stuck set so `search-complete` never fires.
                finalize_removed_searches(state, app_handle, &[sid], &removed.in_use_ids);
                info!("KAD search {id} cancelled by user");
            } else {
                debug!("KAD search {id} not found (already completed?) — ignoring cancel");
            }
        }

        NetworkCommand::IsFriendDiscoverable { tx } => {
            let _ = tx.send(state.rendezvous_registered && !state.last_presence_blocked);
        }

        NetworkCommand::GetOnlineFriends { tx } => {
            let now = chrono::Utc::now().timestamp();
            {
                let sessions = state.ember_sessions.read().await;
                let friends = friend_hashes.read().await;
                for (eh, handle) in sessions.iter() {
                    if handle.is_fresh() && friends.contains(eh) {
                        state.online_friends.entry(*eh).or_insert(now);
                    }
                }
            }
            let online: Vec<String> = state.online_friends.keys().map(hex::encode).collect();
            let _ = tx.send(online);
        }

        NetworkCommand::FindNotes {
            file_hash,
            file_size,
            request_id,
            tx,
        } => {
            let closest = state
                .routing_table
                .find_closest_prefer_verified(&file_hash, SEARCH_INITIAL_CONTACTS);

            if closest.is_empty() {
                let _ = tx.send(Ok(Vec::new()));
                return;
            }

            let sid = start_kad_search(
                state,
                app_handle,
                file_hash,
                SearchType::FindNotes { file_size },
                closest,
            );
            if sid == SearchId(0) {
                warn!("FindNotes rejected: active search cap reached");
                let _ = tx.send(Err(
                    "Notes search busy: too many active KAD searches".to_string()
                ));
                return;
            }
            state.pending_notes_searches.insert(sid, (request_id, tx));
        }

        NetworkCommand::FindSources {
            file_hash,
            file_size,
            request_id,
            tx,
        } => {
            let closest = state
                .routing_table
                .find_closest_prefer_verified(&file_hash, SEARCH_INITIAL_CONTACTS);

            if closest.is_empty() {
                let _ = tx.send(Ok(Vec::new()));
                return;
            }

            let sid = start_kad_search(
                state,
                app_handle,
                file_hash,
                SearchType::FindSource { file_size },
                closest,
            );

            if sid == SearchId(0) {
                warn!("FindSources rejected: active search cap reached");
                let _ = tx.send(Err(
                    "Source search busy: too many active KAD searches".to_string()
                ));
                return;
            }
            state.pending_source_searches.insert(sid, (request_id, tx));
        }

        NetworkCommand::BootstrapContacts { contacts, tx } => {
            // Our own export path (`export_bootstrap_contacts`) caps at 200
            // contacts, but a hand-crafted or third-party-client nodes.dat
            // is only bounded by the download size cap (10-16MB), which
            // could still hold hundreds of thousands of small contact
            // records. Cap injection well above the normal 200-contact norm
            // (to tolerate larger legitimate lists from other clients)
            // without letting a pathological file drive an unbounded burst
            // of routing-table insert work on this single command handler.
            let declared_count = contacts.len();
            if declared_count > MAX_BOOTSTRAP_CONTACTS {
                warn!(
                    "BootstrapContacts: {declared_count} contacts exceeds cap, truncating to {MAX_BOOTSTRAP_CONTACTS}"
                );
            }
            let contacts: Vec<_> = contacts
                .into_iter()
                .take(applied_bootstrap_contact_count(declared_count))
                .collect();
            let count = count_accepted_bootstrap_contacts(contacts.iter().cloned(), |contact| {
                state.routing_table.insert(contact)
            });
            let table_size = state.routing_table.len();
            info!(
                "Injected {} bootstrap contacts, routing table now has {} entries",
                count, table_size
            );

            // eMule: GetBootstrapContacts returns at most 20 contacts.
            // Limit bootstrap requests to prevent flooding the event loop.
            let sample_size = count.min(20);
            for contact in contacts.iter().take(sample_size) {
                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                let msg = KadMessage::BootstrapReq;
                if let Ok(packet) = messages::encode_packet(&msg) {
                    state.flood_protection.track_request(addr, 0x01);
                    let _ = socket.send_to(&packet, addr).await;
                }
            }
            info!("Sent bootstrap requests to {sample_size} contacts (table has {table_size})");
            let _ = tx.send(count);
        }

        NetworkCommand::ReloadIpFilter { path, tx } => {
            // Validate imports from a private staged copy, then atomically
            // persist compatible startup bytes. This keeps startup and the
            // live filter coherent even if an external source file is
            // replaced while an import is in progress.
            //
            // IMPORTANT: leave `state.ip_filter` in place for the entire
            // await. The network `select!` still drains UDP/TCP while we
            // wait, so swapping in an empty placeholder would fail-open
            // for every packet that arrives mid-reload. Load into a
            // fresh filter on the side and only replace on success; on
            // I/O failure or task panic keep the previous ranges.
            let default_path = state.data_dir.join("ipfilter.dat");
            let enabled = state.ip_filter.is_enabled();
            let block_private = state.ip_filter.blocks_private();
            let load_path = default_path.clone();
            let loaded = tokio::task::spawn_blocking(move || -> Result<IpFilter, String> {
                const MAX_IMPORTED_IPFILTER_BYTES: u64 = 50 * 1024 * 1024;
                let mut staged_path = None;
                let mut staged_bytes = None;
                let mut imported_p2b = false;
                let parse_path = if path != load_path {
                    // Defense in depth: `pick_and_import_ipfilter_file` (the
                    // only caller that can supply an arbitrary local path,
                    // and only one the user picked in the OS dialog)
                    // enforces this same limit before sending this
                    // command, but a `path` != `default_path` can in
                    // principle reach this handler from any future
                    // caller too. Stat-and-reject here so this command
                    // can never be tricked into copying an unbounded
                    // file into ipfilter.dat regardless of caller.
                    match std::fs::metadata(&path) {
                        Ok(meta) if meta.len() > MAX_IMPORTED_IPFILTER_BYTES => {
                            warn!(
                                "Refusing to import IP filter from {:?}: {} bytes exceeds the {} MiB cap",
                                path,
                                meta.len(),
                                MAX_IMPORTED_IPFILTER_BYTES / (1024 * 1024)
                            );
                            return Err(format!(
                                "Imported IP filter exceeds the {} MiB limit",
                                MAX_IMPORTED_IPFILTER_BYTES / (1024 * 1024)
                            ));
                        }
                        Ok(_) => {}
                        Err(e) => {
                            warn!("Failed to stat IP filter import path {:?}: {}", path, e);
                            return Err(format!("Failed to read imported IP filter: {e}"));
                        }
                    }
                    let bytes = std::fs::read(&path)
                        .map_err(|error| format!("Failed to read imported IP filter: {error}"))?;
                    if bytes.len() as u64 > MAX_IMPORTED_IPFILTER_BYTES {
                        return Err(format!(
                            "Imported IP filter exceeds the {} MiB limit",
                            MAX_IMPORTED_IPFILTER_BYTES / (1024 * 1024)
                        ));
                    }
                    let extension = path
                        .extension()
                        .and_then(|extension| extension.to_str())
                        .map(|extension| extension.to_ascii_lowercase());
                    let extension = match extension.as_deref() {
                        Some("p2b") => "p2b",
                        Some("p2p") => "p2p",
                        _ => "dat",
                    };
                    imported_p2b = extension == "p2b";
                    let staged = load_path.with_file_name(format!(
                        ".ipfilter-stage-{}-{}.{}",
                        std::process::id(),
                        uuid::Uuid::new_v4(),
                        extension
                    ));
                    crate::security::atomic_write(&staged, &bytes, false).map_err(|error| {
                        format!("Failed to stage imported IP filter: {error}")
                    })?;
                    staged_path = Some(staged.clone());
                    staged_bytes = Some(bytes);
                    staged
                } else {
                    path.clone()
                };
                let mut fresh = IpFilter::new(enabled, block_private);
                let range_count = match fresh.load_from_file(&parse_path) {
                    Some(n @ 1..) => n,
                    Some(0) => {
                        if let Some(staged) = staged_path.as_ref() {
                            let _ = std::fs::remove_file(staged);
                        }
                        warn!(
                            "ReloadIpFilter: refusing zero-range filter from {:?}; keeping the previous filter",
                            path
                        );
                        return Err("IP filter contains no valid ranges".into());
                    }
                    None => {
                        if let Some(staged) = staged_path.as_ref() {
                            let _ = std::fs::remove_file(staged);
                        }
                        warn!(
                            "ReloadIpFilter: failed to read {path:?}; keeping the previous filter"
                        );
                        return Err("Failed to parse IP filter".into());
                    }
                };
                if let (Some(staged), Some(bytes)) = (staged_path, staged_bytes) {
                    // `ipfilter.dat` is always loaded as text on startup.
                    // Preserve `.p2p` text verbatim, but convert `.p2b`
                    // binary input into canonical eMule text before it
                    // replaces that stable path.
                    let persisted_bytes = if imported_p2b {
                        fresh.canonical_dat_bytes()
                    } else {
                        bytes
                    };
                    let persist_result =
                        crate::security::atomic_write(&load_path, &persisted_bytes, false);
                    let _ = std::fs::remove_file(&staged);
                    if let Err(error) = persist_result {
                        warn!("Failed to persist IP filter to {:?}: {}", load_path, error);
                        return Err(format!("Failed to persist imported IP filter: {error}"));
                    }
                    info!("Persisted imported IP filter to {:?}", load_path);
                }
                info!("ReloadIpFilter: parsed {range_count} ranges from {path:?}");
                Ok(fresh)
            })
            .await;
            let result = match loaded {
                Ok(Ok(fresh)) => {
                    state.ip_filter = fresh;
                    state.ip_filter.mark_ranges_ready();
                    state
                        .ip_filter
                        .update_shared_snapshot(&state.shared_ip_filter);
                    state.routing_table.evict_filtered_contacts();
                    state.ember_dht.evict_filtered_contacts();
                    info!(
                        "Reloaded IP filter: {} ranges",
                        state.ip_filter.range_count(),
                    );
                    if settings.filter_servers_by_ip {
                        apply_server_ip_filter(
                            state,
                            shared_server_addr,
                            app_handle,
                            true,
                        )
                        .await;
                    }
                    Ok(())
                }
                Ok(Err(error)) => {
                    // Keep previous ranges — load/copy failed closed.
                    Err(error)
                }
                Err(e) => {
                    error!(
                        "ReloadIpFilter background task panicked: {e}; keeping the previous filter"
                    );
                    Err("IP filter reload task failed".into())
                }
            };
            if let Some(tx) = tx {
                let _ = tx.send(result);
            }
        }

        NetworkCommand::GetIpFilterStats {
            query,
            sort,
            sort_asc,
            offset,
            limit,
            tx,
        } => {
            state.ip_filter.collect_shared_hits(&state.shared_ip_filter);
            let _ = tx.send(state.ip_filter.query_stats(
                &query,
                &sort,
                sort_asc,
                offset,
                limit,
            ));
        }

        NetworkCommand::AddIpRange {
            start_ip,
            end_ip,
            description,
        } => {
            if let (Ok(start), Ok(end)) = (start_ip.parse::<Ipv4Addr>(), end_ip.parse::<Ipv4Addr>())
            {
                ensure_ipfilter_loaded(state).await;
                state.ip_filter.add_range(start, end, description);
                state
                    .ip_filter
                    .update_shared_snapshot(&state.shared_ip_filter);
                state.routing_table.evict_filtered_contacts();
                state.ember_dht.evict_filtered_contacts();
                spawn_save_ipfilter_dat(&state.ip_filter, state.data_dir.join("ipfilter.dat"));
                info!(
                    "Added IP filter range {start_ip} - {end_ip}, total ranges: {}",
                    state.ip_filter.range_count()
                );
                apply_server_ip_filter(
                    state,
                    shared_server_addr,
                    app_handle,
                    settings.filter_servers_by_ip,
                )
                .await;
            }
        }

        NetworkCommand::RemoveIpRange {
            start_ip,
            end_ip,
            tx,
        } => {
            ensure_ipfilter_loaded(state).await;
            let removed = state.ip_filter.remove_range(&start_ip, &end_ip);
            if removed {
                state
                    .ip_filter
                    .update_shared_snapshot(&state.shared_ip_filter);
                spawn_save_ipfilter_dat(&state.ip_filter, state.data_dir.join("ipfilter.dat"));
                info!(
                    "Removed IP filter range {start_ip} - {end_ip}, total ranges: {}",
                    state.ip_filter.range_count()
                );
            } else {
                debug!("RemoveIpRange: no matching range {start_ip} - {end_ip}");
            }
            let _ = tx.send(removed);
        }

        NetworkCommand::SetIpFilterEnabled { enabled } => {
            state.ip_filter.set_enabled(enabled);
            // Boot only reads ipfilter.dat when the filter is already
            // enabled, so a session that started disabled has an empty
            // range set. Without loading here, toggling the filter on at
            // runtime would "enable" a filter that blocks nothing but
            // private/special IPs — the persisted ranges would only take
            // effect after a manual re-import or a restart-while-enabled.
            // Load the persisted file now (only when we have no ranges, so
            // a Reload/import that already populated them isn't re-read).
            //
            // Keep the live filter in place during the await so UDP/TCP
            // arms don't see an empty placeholder if the load task panics.
            // Keyed on "have we read the file", not "is the list empty". A
            // single manual range added while the filter was off used to make
            // the count non-zero and skip this load entirely, so enabling the
            // filter armed it with essentially nothing.
            let mut load_ready = true;
            if enabled && !state.ip_filter.has_loaded_ranges() {
                let default_path = state.data_dir.join("ipfilter.dat");
                if default_path.exists() {
                    let block_private = state.ip_filter.blocks_private();
                    let loaded = tokio::task::spawn_blocking(move || {
                        let mut fresh = IpFilter::new(true, block_private);
                        match fresh.load_from_file(&default_path) {
                            Some(n @ 1..) => {
                                info!(
                                    "SetIpFilterEnabled: parsed {n} ranges from {default_path:?}"
                                );
                                Some(fresh)
                            }
                            Some(0) => {
                                fresh.mark_ranges_not_ready();
                                warn!(
                                    "ipfilter.dat contained no valid ranges while enabling the filter; leaving fail-closed until a successful reload"
                                );
                                None
                            }
                            None => {
                                warn!(
                                    "Failed to read ipfilter.dat while enabling the filter; leaving fail-closed until a successful reload"
                                );
                                None
                            }
                        }
                    })
                    .await;
                    match loaded {
                        Ok(Some(fresh)) => {
                            state.ip_filter = fresh;
                            info!(
                                "Loaded {} IP filter entries on enable",
                                state.ip_filter.range_count()
                            );
                        }
                        Ok(None) => {
                            load_ready = false;
                        }
                        Err(e) => {
                            error!(
                                "SetIpFilterEnabled load task panicked: {e}; keeping previous filter"
                            );
                            load_ready = false;
                        }
                    }
                }
            }
            // Clear fail-closed only after a successful load or intentional empty/absent.
            if enabled && load_ready {
                state.ip_filter.mark_ranges_ready();
            }
            state
                .ip_filter
                .update_shared_snapshot(&state.shared_ip_filter);
            if enabled {
                state.routing_table.evict_filtered_contacts();
                state.ember_dht.evict_filtered_contacts();
                apply_server_ip_filter(
                    state,
                    shared_server_addr,
                    app_handle,
                    settings.filter_servers_by_ip,
                )
                .await;
            }
            info!("IP filter enabled: {enabled}");
        }

        NetworkCommand::SetBlockPrivateIps { block_private } => {
            state.ip_filter.set_block_private(block_private);
            state
                .ip_filter
                .update_shared_snapshot(&state.shared_ip_filter);
            state.routing_table.set_block_private_ips(block_private);
            state.ember_dht.set_block_private_ips(block_private);
            info!("Block private IPs: {block_private}");
        }

        NetworkCommand::KadConnect => {
            info!("KAD connect requested");
            state
                .upload_disconnected
                .store(false, std::sync::atomic::Ordering::Relaxed);
            state.stats.status = NetworkStatus::Connecting;
            state.self_lookup_done = false;
            state.last_self_lookup = 0;
            state.kad_started_at = chrono::Utc::now().timestamp();
            state
                .routing_table
                .reset_big_timer_global(chrono::Utc::now().timestamp());
            let _ = app_handle.emit("network-status", NetworkStatus::Connecting);

            // Reload routing table from saved nodes.dat (eMule recreates RoutingZone on Start).
            // Legacy contacts have no verified bit and remain unverified
            // until the normal Hello/ACK flow promotes them.
            let nodes_path = state.data_dir.join("nodes.dat");
            if state.routing_table.is_empty() {
                if nodes_path.exists() {
                    match bootstrap::load_nodes_dat_with_format(&nodes_path) {
                        Ok((saved, _fmt)) => {
                            for c in &saved {
                                state.routing_table.insert(c.clone());
                            }
                            info!("Loaded {} contacts from nodes.dat on connect", saved.len());
                        }
                        Err(e) => warn!("Failed to load nodes.dat on connect: {e}"),
                    }
                }
            }

            let contacts: Vec<KadContact> = state.routing_table.all_contacts().cloned().collect();
            if contacts.is_empty() {
                let default_contacts = bootstrap::default_bootstrap_contacts();
                for c in &default_contacts {
                    state.routing_table.insert(c.clone());
                }
                for contact in &default_contacts {
                    let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                    let msg = KadMessage::BootstrapReq;
                    if let Ok(packet) = messages::encode_packet(&msg) {
                        state.flood_protection.track_request(addr, 0x01);
                        let _ = socket.send_to(&packet, addr).await;
                    }
                }
                info!(
                    "Bootstrapped from {} default contacts",
                    default_contacts.len()
                );
            } else {
                for contact in contacts.iter().take(20) {
                    let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                    let msg = KadMessage::BootstrapReq;
                    if let Ok(packet) = messages::encode_packet(&msg) {
                        state.flood_protection.track_request(addr, 0x01);
                        let _ = socket.send_to(&packet, addr).await;
                    }
                }
                info!(
                    "Sent bootstrap requests to {} existing contacts",
                    contacts.len().min(20)
                );
            }

            // Firewall check is deferred to the periodic bootstrap_timer recheck,
            // which runs once we have verified contacts (table_size >= 10).
            // Sending checks here against stale nodes.dat contacts produces
            // false Firewalled results because those contacts may be offline.
            //
            // eD2K is intentionally not started here — use the Servers page
            // (or Settings → Auto-Connect Server) to join a server.
        }

        NetworkCommand::KadDisconnect => {
            info!("KAD disconnect requested");
            let rendezvous_was_registered = state.rendezvous_registered;

            // Save routing table before clearing (eMule saves on Stop)
            let contacts = state.routing_table.export_bootstrap_contacts(200);
            let nodes_path = state.data_dir.join("nodes.dat");
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                state.nodes_save_lock.clone().lock_owned(),
            )
            .await
            {
                Ok(ownership) => {
                    // Off the loop, exactly like the periodic nodes_save_timer
                    // arm: `save_nodes_dat` commits through `atomic_write`, which
                    // fsyncs the file *and* its parent directory inline, so
                    // running it here stalled UDP receive and every timer for the
                    // duration — long enough for a full receive buffer to drop KAD
                    // and Ember packets outright. The blocking task keeps the lock
                    // guard, so the shutdown writer still serializes behind this
                    // save instead of renaming an older snapshot over a newer one.
                    let contact_count = contacts.len();
                    tokio::task::spawn_blocking(move || {
                        let _ownership = ownership;
                        if let Err(e) = bootstrap::save_nodes_dat(&nodes_path, &contacts) {
                            error!("Failed to save nodes.dat on disconnect: {e}");
                        } else {
                            info!("Saved {contact_count} contacts to nodes.dat on disconnect");
                        }
                    });
                }
                Err(_) => warn!(
                    "Skipped disconnect nodes.dat checkpoint because the serialized periodic writer did not finish"
                ),
            }

            // Stop all searches and cancel pending oneshot channels
            state.search_manager = SearchManager::new();
            for (
                _,
                PendingKeywordSearch {
                    tx, local_results, ..
                },
            ) in state.pending_keyword_searches.drain()
            {
                let _ = tx.send(local_results);
            }
            for (_, (_, tx)) in state.pending_source_searches.drain() {
                let _ = tx.send(Ok(Vec::new()));
            }
            for (_, (_, tx)) in state.pending_notes_searches.drain() {
                let _ = tx.send(Ok(Vec::new()));
            }
            state.active_search_request = None;
            state.download_source_searches.clear();
            state.store_keyword_searches.clear();
            // A disconnect drops the rendezvous advert along with everything
            // else, so we are no longer listed and must re-advertise.
            if state
                .store_source_searches
                .values()
                .any(|(hash, _)| *hash == kad::publish::ember_rendezvous_key())
            {
                state.ember_rendezvous_published_at = 0;
            }
            state.store_source_searches.clear();
            state.pending_note_publishes.clear();
            state.publish_pending.clear();
            state.source_publish_acks.clear();
            state.pending_udp_reasks.clear();
            state.server_udp_source_reask_at.clear();

            // Reset network state (eMule resets firewall, deletes routing zone)
            state.routing_table.clear();
            set_external_ip(state, None);
            state.external_udp_port = None;
            state.firewalled = true;
            // New KAD session (possibly a different network): any STUN
            // candidate/suspend progress and remapped advertise ports from
            // before this disconnect are stale. Also resets the live
            // advertise_tcp_port/advertise_udp_port atomics the upload
            // listener reads directly, back to Settings ports. Done after
            // `firewalled` is updated so update_publish_manager_state (called
            // inside) reflects the post-disconnect state, not the pre-reset one.
            // (reset_stun_keepalive_session also bumps mapping_ka_generation,
            // invalidating any in-flight STUN/TCP-hold cycle from before this
            // disconnect — see its doc comment.)
            reset_stun_keepalive_session(state);
            state
                .firewalled_shared
                .store(true, std::sync::atomic::Ordering::Relaxed);
            state.firewall_checks_sent = 0;
            state.firewall_checker = FirewallChecker::new();
            state.self_lookup_done = false;
            state.last_self_lookup = 0;
            state.last_kad_contact = None;
            state.udp_firewalled = true;
            state.udp_fw_verified = false;
            state.overloaded_nodes.clear();
            state.buddy_manager.reset().await;
            state.buddy_event_rx = None;
            state.serving_event_rx = None;
            *state.shared_buddy_info.write().await = None;
            state.peer_nicknames.clear();
            state.publish_confirmed = 0;
            state.first_publish_done = false;
            state.kad_initial_source_burst_done = false;
            state.friend_presence_initial_done = false;
            state.last_presence_blocked = false;
            state.friend_search_initial_done = false;
            state.friend_search_started_at = None;
            state.rendezvous_register_generation =
                state.rendezvous_register_generation.saturating_add(1);
            state.nat_probe_generation = state.nat_probe_generation.saturating_add(1);
            state.rendezvous_registered = false;
            state.rendezvous_last_register = None;
            if rendezvous_was_registered {
                let rv_url = settings.rendezvous_url.clone();
                let rv_hash = ember_hash;
                let rv_secret = ed25519_secret_key;
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        rendezvous::unregister(&rv_url, &rv_hash, &rv_secret),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            debug!("Failed to unregister from rendezvous server on disconnect: {e}")
                        }
                        Err(_) => debug!("Rendezvous unregister timed out on disconnect; skipping"),
                    }
                });
            }
            // Emit offline for all previously-online friends
            for eh in state.online_friends.keys() {
                let _ = app_handle.emit(
                    "ember:friend-offline",
                    serde_json::json!({
                        "user_hash": hex::encode(eh),
                    }),
                );
            }
            state.online_friends.clear();
            state.outbound_session_tasks.clear();

            // Abort all active download tasks — they hold open TCP connections
            // to peers and will keep transferring data even though the network
            // is logically disconnected.  Re-queue each as a pending download
            // so they resume automatically when the user reconnects.
            // Save .part.met for in-progress downloads before aborting tasks.
            // Snapshot tracker handles first, then await each lock with a
            // short bound so a mid-write tracker doesn't silently miss its
            // resume metadata.
            let disconnect_trackers: Vec<_> = state
                .tracker_registry
                .lock()
                .iter()
                .map(|(tid, tracker)| (tid.clone(), tracker.clone()))
                .collect();
            let tracker_saves = futures::future::join_all(disconnect_trackers.into_iter().map(
                |(tid, tracker)| async move {
                    save_part_tracker_snapshot(tracker, &tid, "disconnect").await;
                },
            ));
            if tokio::time::timeout(std::time::Duration::from_secs(8), tracker_saves)
                .await
                .is_err()
            {
                warn!("Timed out saving some .part.met file(s) during disconnect");
            }

            // Cancel each active download's control BEFORE aborting its worker
            // handle. The per-source connection tasks are detached
            // `tokio::spawn`s; aborting the worker handle does NOT abort them,
            // so without cancelling the shared control they keep their TCP
            // connections open and keep transferring even though the network is
            // logically disconnected. Cancelling trips the cooperative
            // `check_control` at the top of each source loop so they bail and
            // drop their sockets. The re-queue below registers fresh controls
            // for the resume-on-reconnect entries, so this only affects the
            // now-dead generation.
            {
                let mgr = transfer_manager.read().await;
                for tid in state.download_handles.keys() {
                    if let Some(control) = mgr.get_control(tid) {
                        control.cancel();
                    }
                }
            }

            for (tid, handle) in state.download_handles.drain() {
                handle.abort();
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
                    debug!("Aborted download task {tid} on KAD disconnect");
                });
            }

            // Clear the registry — tasks are gone, trackers are saved.
            state.tracker_registry.lock().clear();
            state.active_source_senders.clear();
            // Lockstep cleanup — KAD disconnect tears down all
            // workers, so the established-source channel map must be
            // cleared too. Without this, on reconnect new downloads
            // would create new entries while stale closed senders
            // remain forever.
            state.active_established_senders.clear();
            state.active_source_overflow.clear();
            state.active_kad_search_state.clear();

            // Move all active downloads back to pending so they can be
            // restarted when the network is reconnected.
            {
                let mut mgr = transfer_manager.write().await;
                let active_tids: Vec<String> = mgr
                    .get_all()
                    .iter()
                    .filter(|t| {
                        t.status == TransferStatus::Active
                            && t.direction == TransferDirection::Download
                    })
                    .map(|t| t.id.clone())
                    .collect();
                for tid in &active_tids {
                    if state.pending_downloads.contains_key(tid) {
                        continue;
                    }
                    if let Some(t) = mgr.get_transfer(tid).cloned() {
                        let control = TransferControl::new();
                        mgr.register_control(tid, control.clone());
                        mgr.update_sources(tid, t.sources, 0, 0);
                        mgr.update_status(tid, TransferStatus::Searching);
                        insert_pending_download_bounded(
                            &mut state.pending_downloads,
                            tid.clone(),
                            PendingDownload {
                                transfer_id: tid.clone(),
                                file_hash: t.file_hash.clone(),
                                file_name: t.file_name.clone(),
                                file_size: t.total_size,
                                expected_aich: t.expected_aich.clone(),
                                control,
                                search_count: 0,
                                last_search_at: 0,
                                priority: priority_str_to_u32(&t.priority),
                            },
                        );
                        if let Some(pfs) = state.per_file_sources.get_mut(tid) {
                            pfs.reset_active_states();
                        }
                        let _ = app_handle.emit(
                            "transfer-status",
                            serde_json::json!({
                                "id": tid,
                                "status": "searching",
                                "sources": t.sources,
                            }),
                        );
                    }
                }
            }

            // Signal the upload listener to reject new connections and
            // terminate active upload sessions (eMule: all uploads stop on disconnect).
            state
                .upload_disconnected
                .store(true, std::sync::atomic::Ordering::Relaxed);

            state.stats.status = NetworkStatus::Disconnected;
            state.stats.connected_peers = 0;
            state.stats.external_ip = String::new();
            state.stats.firewalled = true;
            state.stats.buddy_status = "none".to_string();
            state.stats.stores_acknowledged = 0;
            let _ = app_handle.emit("network-status", NetworkStatus::Disconnected);

            // Tear down eD2K server — it should only be up while KAD is connected
            if let Some(handle) = state.pending_server_connect.take() {
                handle.abort();
            }
            if state.server_connected || state.server_connection.is_some() {
                if let Some(conn) = state.server_connection.take() {
                    conn.disconnect().await;
                }
                handle_server_disconnect(
                    state,
                    &shared_server_addr,
                    &app_handle,
                    "KAD disconnected",
                )
                .await;
            }

            info!("KAD fully disconnected — all activity stopped");
        }

        NetworkCommand::KadBootstrapIp { ip, port, tx } => {
            info!("KAD bootstrap from IP {ip}:{port}");
            let outcome: Result<String, String> = if !(11..=65535).contains(&port) {
                // eMule's convention is "tcp_port = udp_port - 10".
                // For any UDP port < 11, that produces 0 (or wraps with
                // saturating_sub) — a silently broken contact whose
                // TCP port is unusable. Reject up front with a clear
                // error rather than insert a poison record into the
                // routing table.
                Err(format!(
                    "Invalid UDP port {port} for manual bootstrap (must be ≥ 11 so the implied TCP port = UDP-10 is non-zero)",
                ))
            } else if let Ok(addr_ip) = ip.parse::<Ipv4Addr>() {
                let contact = KadContact {
                    id: KadId::zero(),
                    ip: addr_ip,
                    udp_port: port,
                    tcp_port: port - 10,
                    version: KADEMLIA_VERSION,
                    last_seen: chrono::Utc::now().timestamp(),
                    verified: false,
                    contact_type: CONTACT_TYPE_NEW,
                    udp_key: None,
                    kad_options: 0,
                    created_at: chrono::Utc::now().timestamp(),
                    expires_at: 0,
                    last_type_set: 0,
                    received_hello: false,
                };
                state.routing_table.insert(contact);

                let addr = SocketAddr::new(addr_ip.into(), port);
                let msg = KadMessage::BootstrapReq;
                match messages::encode_packet(&msg) {
                    Ok(packet) => {
                        state.flood_protection.track_request(addr, 0x01);
                        match socket.send_to(&packet, addr).await {
                            Ok(_) => {
                                info!("Sent bootstrap request to {addr}");
                                if state.stats.status == NetworkStatus::Disconnected {
                                    state.stats.status = NetworkStatus::Connecting;
                                    // Same rule as `KadConnect`: this is the
                                    // one path that actually moves us off
                                    // Disconnected, so the upload listener
                                    // must be told at the same moment.
                                    state
                                        .upload_disconnected
                                        .store(false, std::sync::atomic::Ordering::Relaxed);
                                }
                                Ok(format!(
                                    "Bootstrap request sent to {addr} — contacts will appear as they respond"
                                ))
                            }
                            Err(e) => Err(format!("Failed to send bootstrap packet: {e}")),
                        }
                    }
                    Err(e) => Err(format!("Failed to encode bootstrap packet: {e}")),
                }
            } else {
                warn!("Invalid bootstrap IP: {ip}");
                Err(format!("Invalid bootstrap IP: {ip}"))
            };
            let _ = tx.send(outcome);
        }

        NetworkCommand::KadBootstrapUrl { url, tx } => {
            info!("KAD bootstrap from URL: {url}");
            const MAX_NODES_BYTES: usize = 10 * 1024 * 1024;
            // `fetch_pinned_get` re-validates the URL and every redirect hop
            // against the private-IP rules, so a malicious redirect can't
            // pivot the bootstrap fetch onto an internal host.
            let outcome: Result<String, String> = match crate::security::fetch_pinned_get(&url)
                .await
            {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        Err(format!("HTTP {} from {}", resp.status().as_u16(), url))
                    } else {
                        let download_result: Result<Vec<u8>, String> = {
                            use futures::StreamExt;
                            let mut body = Vec::new();
                            let mut stream = resp.bytes_stream();
                            let mut err: Option<String> = None;
                            while let Some(chunk) = stream.next().await {
                                match chunk {
                                    Ok(data) => {
                                        body.extend_from_slice(&data);
                                        if body.len() > MAX_NODES_BYTES {
                                            err = Some(format!(
                                                "Response exceeded {} byte cap",
                                                MAX_NODES_BYTES
                                            ));
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        err = Some(format!("Download failed: {e}"));
                                        break;
                                    }
                                }
                            }
                            if let Some(e) = err {
                                Err(e)
                            } else {
                                Ok(body)
                            }
                        };
                        match download_result {
                            Ok(bytes) => {
                                let tmp_dir = std::env::temp_dir();
                                let tmp_path = tmp_dir.join(format!(
                                    "ember-nodes-{}.dat",
                                    chrono::Utc::now().timestamp()
                                ));
                                match tokio::fs::write(&tmp_path, &bytes).await {
                                    Err(e) => Err(format!("Failed to write temp nodes.dat: {e}")),
                                    Ok(_) => {
                                        let parse_res = bootstrap::load_nodes_dat(&tmp_path);
                                        let _ = tokio::fs::remove_file(&tmp_path).await;
                                        match parse_res {
                                                    Err(e) => Err(format!(
                                                        "Parsed {} bytes but file is not a valid nodes.dat: {e}",
                                                        bytes.len()
                                                    )),
                                                    Ok(contacts) => {
                                                        let count = contacts.len();
                                                        if count == 0 {
                                                            Err("Downloaded nodes.dat contained no contacts".into())
                                                        } else {
                                                            for c in &contacts {
                                                                state.routing_table.insert(c.clone());
                                                            }
                                                            for contact in contacts.iter().take(20) {
                                                                let addr = SocketAddr::new(
                                                                    contact.ip.into(),
                                                                    contact.udp_port,
                                                                );
                                                                let msg = KadMessage::BootstrapReq;
                                                                if let Ok(packet) =
                                                                    messages::encode_packet(&msg)
                                                                {
                                                                    state
                                                                        .flood_protection
                                                                        .track_request(addr, 0x01);
                                                                    let _ = socket
                                                                        .send_to(&packet, addr)
                                                                        .await;
                                                                }
                                                            }
                                            info!(
                                                "Loaded {count} contacts from URL, bootstrapping"
                                            );
                                            if state.stats.status
                                                == NetworkStatus::Disconnected
                                            {
                                                state.stats.status =
                                                    NetworkStatus::Connecting;
                                                // See `KadBootstrapIp`: keep
                                                // the upload gate in sync
                                                // with every path off
                                                // Disconnected.
                                                state.upload_disconnected.store(
                                                    false,
                                                    std::sync::atomic::Ordering::Relaxed,
                                                );
                                            }
                                            Ok(format!(
                                                "Loaded {count} contacts from nodes.dat"
                                            ))
                                                        }
                                                    }
                                                }
                                    }
                                }
                            }
                            Err(e) => Err(e),
                        }
                    }
                }
                Err(e) => Err(format!("KAD bootstrap fetch failed: {e}")),
            };
            if let Err(ref e) = outcome {
                warn!("KAD bootstrap from {url} failed: {e}");
            }
            let _ = tx.send(outcome);
        }

        NetworkCommand::KadBootstrapClients { tx } => {
            info!("KAD bootstrap from connected clients");
            let contacts: Vec<KadContact> = state
                .routing_table
                .all_contacts()
                .filter(|contact| contact.verified && !contact.is_dead())
                .cloned()
                .collect();
            let send_count = contacts.len().min(20);
            let mut actually_sent = 0usize;
            for contact in contacts.iter().take(send_count) {
                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                // K17: the KadBootstrapIp path tracks outgoing bootstrap
                // requests in flood_protection so we don't double-send.
                // This bulk path didn't, meaning a rapid user-triggered
                // rebootstrap could send duplicate BootstrapReqs to the
                // same contact within the flood window — we'd then reject
                // our own replies. Track every send here too.
                state.flood_protection.track_request(addr, 0x01);
                let msg = KadMessage::BootstrapReq;
                if let Ok(packet) = messages::encode_packet(&msg) {
                    if socket.send_to(&packet, addr).await.is_ok() {
                        actually_sent += 1;
                    }
                }
            }
            info!("Sent bootstrap requests to {actually_sent}/{send_count} connected contacts");
            if state.stats.status == NetworkStatus::Disconnected && actually_sent > 0 {
                state.stats.status = NetworkStatus::Connecting;
                // See `KadBootstrapIp`: keep the upload gate in sync with
                // every path off Disconnected.
                state
                    .upload_disconnected
                    .store(false, std::sync::atomic::Ordering::Relaxed);
            }
            let _ = tx.send(if actually_sent > 0 {
                Ok(actually_sent)
            } else {
                Err("No known contacts are available for bootstrap".to_string())
            });
        }

        NetworkCommand::RecheckFirewall { tx } => {
            info!("Rechecking firewall status");
            state.firewall_checks_sent = 0;

            state.firewall_checker.start_check();
            clear_external_udp_for_firewall_recheck(state);
            if let Ok(mut probes) = firewall_probe_ips.lock() {
                probes.clear();
            }

            let contacts: Vec<KadContact> = state
                .routing_table
                .all_contacts()
                .filter(|contact| contact.verified && !contact.is_dead())
                .take(4)
                .cloned()
                .collect();

            let fw_tcp_port = advertised_tcp_port(state);
            for contact in &contacts {
                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                let (msg, track_opcode) = if contact.version > KADEMLIA_VERSION6_49ABETA {
                    (
                        KadMessage::Firewalled2Req {
                            tcp_port: fw_tcp_port,
                            user_hash: state.user_hash,
                            connect_options: build_kad_connect_options(&state),
                        },
                        0x53u8,
                    )
                } else {
                    (
                        KadMessage::FirewalledReq {
                            tcp_port: fw_tcp_port,
                        },
                        0x50u8,
                    )
                };
                if let Ok(packet) = messages::encode_packet(&msg) {
                    state.flood_protection.track_request(addr, track_opcode);
                    if let Ok(mut probes) = firewall_probe_ips.lock() {
                        probes.insert(contact.ip);
                    }
                    let _ = send_kad_packet(socket, &packet, addr, &state, &contact.id).await;
                    state.firewall_checks_sent += 1;
                    state.firewall_checker.record_tcp_request_sent(contact.ip);
                }
            }

            let ping_contacts: Vec<KadContact> = state
                .routing_table
                .all_contacts()
                .filter(|contact| contact.verified && !contact.is_dead())
                .skip(4)
                .take(4)
                .cloned()
                .collect();
            for contact in &ping_contacts {
                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                let msg = KadMessage::Ping;
                if let Ok(packet) = messages::encode_packet(&msg) {
                    state.flood_protection.track_request(addr, 0x60);
                    let _ = send_kad_packet(socket, &packet, addr, &state, &contact.id).await;
                    state.firewall_checker.record_udp_port_probe_sent();
                }
            }

            // Eagerly dispatch UDP firewall probes (uses previous external port
            // or falls back to settings.udp_port). Pong handler will also retry.
            dispatch_udp_firewall_probe_requests(state, app_handle, &settings);

            info!(
                "Sent {} firewall checks and {} ping probes",
                state.firewall_checks_sent,
                ping_contacts.len()
            );
            let _ = tx.send(
                if state.firewall_checks_sent > 0 || !ping_contacts.is_empty() {
                    Ok((state.firewall_checks_sent as usize) + ping_contacts.len())
                } else {
                    Err("No verified contacts available for firewall recheck".to_string())
                },
            );
        }

        NetworkCommand::UpdateSettings { .. } => {
            // Handled inline in the command dispatch loop (start_network)
            // to allow updating the owned `settings` variable.
        }

        NetworkCommand::ConnectToServer { ip, port } => {
            initiate_server_connect(state, settings, app_handle, shared_server_addr, ip, port)
                .await;
        }

        NetworkCommand::DisconnectServer => {
            info!("Disconnecting from ed2k server");
            state.server_auto_reconnect = false;
            if let Some(handle) = state.pending_server_connect.take() {
                handle.abort();
            }
            if let Some(conn) = state.server_connection.take() {
                conn.disconnect().await;
            }
            handle_server_disconnect(state, shared_server_addr, app_handle, "User disconnected")
                .await;
        }

        NetworkCommand::AddServer { ip, port, name, tx } => {
            use crate::network::ed2k::server_list::{AddServerOutcome, ServerEntry};
            let result = match ip.parse::<std::net::Ipv4Addr>() {
                Err(_) => Err(format!("Invalid server IP: {ip}")),
                Ok(_) if port == 0 => Err("Server port must not be zero".to_string()),
                Ok(_) => {
                    let mut entry = ServerEntry::new(ip.clone(), port);
                    entry.name = name.clone();
                    // A user-added server is static (eMule semantics): it is
                    // exempt from automatic fail-count pruning.
                    entry.is_static = true;
                    match state.server_list.add_filtered(
                        entry,
                        settings.filter_servers_by_ip,
                        &mut state.ip_filter,
                    ) {
                        AddServerOutcome::Added => {
                            let met_path = state.data_dir.join("server.met");
                            spawn_save_server_met(
                                &state.server_list,
                                met_path.clone(),
                                &state.server_met_save_generation,
                                &state.server_met_save_lock,
                            );
                            Ok(format!("Added server {ip}:{port}"))
                        }
                        AddServerOutcome::Duplicate => {
                            Err(format!("Server {ip}:{port} is already in the list"))
                        }
                        AddServerOutcome::Filtered => {
                            Err(format!("Server {ip}:{port} is blocked by the IP filter"))
                        }
                        AddServerOutcome::AtCapacity => Err(format!(
                            "Server list is full; remove an entry before adding {ip}:{port}"
                        )),
                    }
                }
            };
            let _ = tx.send(result);
        }

        NetworkCommand::RemoveServer { ip, port, tx } => {
            let result = if state.server_list.remove(&ip, port) {
                let met_path = state.data_dir.join("server.met");
                spawn_save_server_met(
                    &state.server_list,
                    met_path.clone(),
                    &state.server_met_save_generation,
                    &state.server_met_save_lock,
                );
                Ok(format!("Removed server {ip}:{port}"))
            } else {
                Err(format!("Server {ip}:{port} not found in the list"))
            };
            let _ = tx.send(result);
        }

        NetworkCommand::GetServerListSnapshot { tx } => {
            let _ = tx.send(
                state
                    .server_list
                    .servers()
                    .iter()
                    .map(server_entry_to_info)
                    .collect(),
            );
        }

        NetworkCommand::GetConnectedServerSnapshot { tx } => {
            let _ = tx.send(connected_server_info(state));
        }

        NetworkCommand::SetUploadPriorities {
            file_hashes,
            priority,
            tx,
        } => {
            let mut parsed = Vec::with_capacity(file_hashes.len());
            for file_hash_hex in file_hashes {
                let hash_bytes = match hex::decode(&file_hash_hex) {
                    Ok(bytes) if bytes.len() == 16 => bytes,
                    Ok(bytes) => {
                        let _ = tx.send(Err(format!(
                            "Invalid upload-priority hash {file_hash_hex}: expected 16 bytes, got {}",
                            bytes.len()
                        )));
                        return;
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!(
                            "Invalid upload-priority hash {file_hash_hex}: {e}"
                        )));
                        return;
                    }
                };
                let mut hash = [0u8; 16];
                hash.copy_from_slice(&hash_bytes);
                if known_files.find_by_hash(&hash).is_none() {
                    let _ = tx.send(Err(format!(
                        "No known.met record for file hash {file_hash_hex}"
                    )));
                    return;
                }
                parsed.push(hash);
            }
            if !parsed.is_empty() {
                let before = known_files.clone();
                for hash in parsed {
                    if let Some(record) = known_files.find_by_hash_mut(&hash) {
                        record.upload_priority = priority;
                    }
                }
                known_files.mark_dirty();
                // A Library command must not report a priority change as
                // durable merely because it was queued for the 120s periodic
                // writer. Serialize an immediate snapshot save with that
                // writer so a restart immediately after the IPC reply keeps
                // the state the UI displayed.
                let ownership = state.known_met_save_lock.clone().lock_owned().await;
                let known_path = state.data_dir.join("known.met");
                let mut snapshot = known_files.clone();
                let save_result = tokio::task::spawn_blocking(move || {
                    let _ownership = ownership;
                    snapshot.save(&known_path)
                })
                .await
                .map_err(|e| format!("known.met priority save task failed: {e}"))
                .and_then(|result| result.map_err(|e| e.to_string()));
                if let Err(e) = save_result {
                    *known_files = before;
                    let _ = tx.send(Err(format!("Failed to persist upload priority: {e}")));
                    return;
                }
            }
            let _ = tx.send(Ok(()));
        }

        NetworkCommand::SetFilesShared { updates, tx } => {
            let mut parsed = Vec::with_capacity(updates.len());
            let mut error = None;
            for (file_hash_hex, shared) in updates {
                match hex::decode(&file_hash_hex) {
                    Ok(bytes) if bytes.len() == 16 => {
                        let mut hash = [0u8; 16];
                        hash.copy_from_slice(&bytes);
                        if known_files.find_by_hash(&hash).is_none() {
                            error =
                                Some(format!("No known.met record for file hash {file_hash_hex}"));
                            break;
                        }
                        parsed.push((hash, shared));
                    }
                    Ok(bytes) => {
                        error = Some(format!(
                            "File hash {file_hash_hex} has {} bytes, expected 16",
                            bytes.len()
                        ));
                        break;
                    }
                    Err(e) => {
                        error = Some(format!("Invalid file hash {file_hash_hex}: {e}"));
                        break;
                    }
                }
            }
            if let Some(error) = error {
                let _ = tx.send(Err(error));
                return;
            }
            let before = known_files.clone();
            for (hash, shared) in &parsed {
                if let Some(record) = known_files.find_by_hash_mut(hash) {
                    record.is_shared = *shared;
                }
            }
            if !parsed.is_empty() {
                known_files.mark_dirty();
                // See SetUploadPriorities: persist before acknowledging so
                // share/unshare cannot appear successful and then revert on
                // the next application start.
                let ownership = state.known_met_save_lock.clone().lock_owned().await;
                let known_path = state.data_dir.join("known.met");
                let mut snapshot = known_files.clone();
                let save_result = tokio::task::spawn_blocking(move || {
                    let _ownership = ownership;
                    snapshot.save(&known_path)
                })
                .await
                .map_err(|e| format!("known.met share-state save task failed: {e}"))
                .and_then(|result| result.map_err(|e| e.to_string()));
                if let Err(e) = save_result {
                    *known_files = before;
                    let _ = tx.send(Err(format!("Failed to persist file sharing state: {e}")));
                    return;
                }
                if let Err(e) = crate::storage::share_intent::set_explicit_batch(&parsed) {
                    *known_files = before.clone();
                    let ownership = state.known_met_save_lock.clone().lock_owned().await;
                    let known_path = state.data_dir.join("known.met");
                    let mut rollback = before;
                    let rollback_result = tokio::task::spawn_blocking(move || {
                        let _ownership = ownership;
                        rollback.save(&known_path)
                    })
                    .await;
                    let detail = match rollback_result {
                        Ok(Ok(())) => e.to_string(),
                        Ok(Err(rollback_error)) => {
                            format!("{e}; known.met rollback failed: {rollback_error}")
                        }
                        Err(rollback_error) => {
                            format!("{e}; known.met rollback task failed: {rollback_error}")
                        }
                    };
                    let _ = tx.send(Err(format!(
                        "Failed to persist independent share intent: {detail}"
                    )));
                    return;
                }
            }
            let _ = tx.send(Ok(parsed.len()));
        }

        NetworkCommand::OfferFileToFriend {
            ember_hash: friend_eh,
            file_hash,
            tx,
        } => {
            if !friend_hashes.read().await.contains(&friend_eh) {
                let _ = tx.send(Err("Can only send files to friends".into()));
                return;
            }
            // Only offer something we would actually serve. Resolving the
            // name and size here also means the recipient's prompt describes
            // the real file rather than anything the sender typed.
            let hash_hex = hex::encode(file_hash);
            let entry = {
                let idx = local_index.read().await;
                idx.get_by_hash(&hash_hex)
                    .filter(|f| f.is_friend_visible())
                    .map(|f| (f.name.clone(), f.size, f.ember_file_hash.clone()))
            };
            let Some((file_name, file_size, ember_hex)) = entry else {
                let _ = tx.send(Err("File is not shared".into()));
                return;
            };
            let ember_file_hash = if ember_hex.len() == 64 {
                let mut digest = [0u8; 32];
                hex::decode_to_slice(&ember_hex, &mut digest)
                    .ok()
                    .map(|_| digest)
            } else {
                None
            };
            // A friends-only file is only offerable to a mutual friend, for
            // the same reason it is only servable to one.
            let restricted = {
                let idx = local_index.read().await;
                idx.get_by_hash(&hash_hex).is_some_and(|f| f.friends_only)
            };
            if restricted && !mutual_friend_hashes.read().await.contains(&friend_eh) {
                let _ = tx.send(Err("File is restricted to mutual friends".into()));
                return;
            }
            let payload = ed2k::messages::build_ember_file_offer(&ed2k::messages::EmberFileOffer {
                file_hash,
                file_size,
                file_name,
                ember_file_hash,
            });
            let sessions = state.ember_sessions.read().await;
            let Some(session) = sessions
                .get(&friend_eh)
                .filter(|h| h.is_fresh() && h.is_secure_v2())
            else {
                drop(sessions);
                let _ = tx.send(Err("Friend is offline".into()));
                return;
            };
            let mut framed = Vec::with_capacity(6 + payload.len());
            framed.push(OP_EMULEPROT);
            framed.extend_from_slice(&((1 + payload.len()) as u32).to_le_bytes());
            framed.push(ed2k::messages::OP_EMBER_FILE_OFFER);
            framed.extend_from_slice(&payload);
            let result = session.tx.try_send(framed);
            drop(sessions);
            match result {
                Ok(()) => {
                    info!("Offered {hash_hex} to friend {}", hex::encode(friend_eh));
                    let _ = tx.send(Ok(()));
                }
                Err(_) => {
                    let _ = tx.send(Err("Connection to friend closed".into()));
                }
            }
        }

        NetworkCommand::SetFilesFriendsOnly { updates, tx } => {
            let mut parsed = Vec::with_capacity(updates.len());
            let mut error = None;
            for (file_hash_hex, friends_only) in updates {
                match hex::decode(&file_hash_hex) {
                    Ok(bytes) if bytes.len() == 16 => {
                        let mut hash = [0u8; 16];
                        hash.copy_from_slice(&bytes);
                        if known_files.find_by_hash(&hash).is_none() {
                            error =
                                Some(format!("No known.met record for file hash {file_hash_hex}"));
                            break;
                        }
                        parsed.push((hash, friends_only));
                    }
                    Ok(bytes) => {
                        error = Some(format!(
                            "File hash {file_hash_hex} has {} bytes, expected 16",
                            bytes.len()
                        ));
                        break;
                    }
                    Err(e) => {
                        error = Some(format!("Invalid file hash {file_hash_hex}: {e}"));
                        break;
                    }
                }
            }
            if let Some(error) = error {
                let _ = tx.send(Err(error));
                return;
            }
            let before = known_files.clone();
            for (hash, friends_only) in &parsed {
                if let Some(record) = known_files.find_by_hash_mut(hash) {
                    record.friends_only = *friends_only;
                }
            }
            if !parsed.is_empty() {
                known_files.mark_dirty();
                // Persist before acknowledging, exactly as SetFilesShared
                // does. Restricting a file to friends is a privacy decision:
                // reporting success and then losing it on the next start
                // would silently republish the file to the open network.
                let ownership = state.known_met_save_lock.clone().lock_owned().await;
                let known_path = state.data_dir.join("known.met");
                let mut snapshot = known_files.clone();
                let save_result = tokio::task::spawn_blocking(move || {
                    let _ownership = ownership;
                    snapshot.save(&known_path)
                })
                .await
                .map_err(|e| format!("known.met share-scope save task failed: {e}"))
                .and_then(|result| result.map_err(|e| e.to_string()));
                if let Err(e) = save_result {
                    *known_files = before;
                    let _ = tx.send(Err(format!("Failed to persist file share scope: {e}")));
                    return;
                }
            }
            let _ = tx.send(Ok(parsed.len()));
        }

        NetworkCommand::SharedFilesChangedAck { tx: reconcile_ack } => {
            let all_index_files = {
                let index = local_index.read().await;
                index.all_files().to_vec()
            };
            let independent_denies: Vec<([u8; 16], bool)> = all_index_files
                .iter()
                .filter(|file| !file.shared)
                .filter_map(|file| {
                    let bytes = hex::decode(&file.hash).ok()?;
                    if bytes.len() != 16 {
                        return None;
                    }
                    let mut hash = [0u8; 16];
                    hash.copy_from_slice(&bytes);
                    known_files
                        .find_by_hash(&hash)
                        .is_none()
                        .then_some((hash, false))
                })
                .collect();
            if !independent_denies.is_empty() {
                if let Err(error) =
                    crate::storage::share_intent::set_explicit_batch(&independent_denies)
                {
                    let _ = reconcile_ack.send(Err(format!(
                        "Failed to persist independent unshare intent: {error}"
                    )));
                    return;
                }
            }
            for f in &all_index_files {
                if let Ok(hash_bytes) = hex::decode(&f.hash) {
                    if hash_bytes.len() == 16 {
                        let mut fh = [0u8; 16];
                        fh.copy_from_slice(&hash_bytes);
                        // Always drain the hash-pass handoff, including when
                        // known.met already matches this file. Otherwise a
                        // correct existing record leaves the freshly-produced
                        // vector resident forever.
                        let fresh_part_hashes_for_file =
                            take_fresh_part_hashes(fresh_part_hashes, &fh).await;
                        // Refresh-on-drift fix: if a record already
                        // exists for this hash but its `file_path`
                        // or `modified_at` no longer match what we
                        // just discovered on disk, rewrite the
                        // record with the current values. See
                        // `KnownFileList::record_needs_refresh` for
                        // the full rationale — short version, this
                        // breaks the "permanent rehash loop" that
                        // surfaces whenever an external process
                        // touches a shared file's metadata.
                        if known_files.record_needs_refresh(
                            &fh,
                            &f.path,
                            f.size,
                            f.modified_at,
                            &f.name,
                            &f.aich_hash,
                            &f.ember_file_hash,
                        ) {
                            use crate::storage::known_files::KnownFileRecord;
                            // Preserve cumulative counters from the
                            // existing record (uploaded bytes /
                            // request totals shouldn't reset just
                            // because mtime drifted).
                            let existing = known_files.find_by_hash(&fh).cloned();
                            let (att, atr, ata, prio, lps, is_shared, sources) = match &existing {
                                Some(r) => (
                                    r.all_time_transferred.max(f.bytes_transferred),
                                    r.all_time_requested.max(f.requests),
                                    r.all_time_accepted.max(f.accepted),
                                    r.upload_priority,
                                    r.last_publish_src,
                                    // Preserve the persisted share flag across a
                                    // metadata-drift refresh — a user's unshare/
                                    // share toggle goes through `SetFileShared`,
                                    // not this path, so this rewrite must never
                                    // silently flip it back.
                                    r.is_shared,
                                    // Preserve the last-known Peers count too — a
                                    // metadata-drift refresh has nothing to do
                                    // with source availability, so it must not
                                    // reset the count back to 0. The periodic
                                    // source-count sync is the only place that
                                    // should ever change this value.
                                    r.complete_sources,
                                ),
                                // Brand-new record: seed both from the file's
                                // current live state (its priority may already
                                // reflect a shared-folder default; a file can
                                // only be unshared here if it was toggled off
                                // before its very first known.met record existed).
                                None => (
                                    f.bytes_transferred,
                                    f.requests,
                                    f.accepted,
                                    crate::storage::known_files::priority_str_to_u8(&f.priority),
                                    0,
                                    f.shared,
                                    f.complete_sources,
                                ),
                            };
                            let is_shared =
                                crate::storage::share_intent::effective_shared(&fh, is_shared);
                            let mut part_hashes = existing
                                .as_ref()
                                .map(|r| r.part_hashes.clone())
                                .unwrap_or_default();
                            if part_hashes.len()
                                != ed2k::hash::ed2k_known_met_part_hash_count(f.size)
                            {
                                // Prefer the part hashes already produced as a
                                // byproduct of the initial ED2K+AICH combined
                                // hash pass (`hash_file_combined_cancellable`,
                                // stashed by the hashing task into
                                // `fresh_part_hashes`) over re-reading the
                                // whole file from disk a second time. Every
                                // never-before-known file used to take the
                                // fallback branch below on its first
                                // SharedFilesChanged, so on a fresh share of a
                                // large library this loop ran a full re-hash
                                // for many files in a row — sequentially, on
                                // this same network event loop task — which is
                                // what starved KAD UDP/timers/IPC snapshots
                                // (contacts, search activity) for the whole
                                // hashing pass. spawn_blocking alone didn't
                                // fix that: it only keeps the disk I/O off the
                                // async worker threads, not off *this* task.
                                if let Some(cached) = fresh_part_hashes_for_file {
                                    part_hashes = cached;
                                } else {
                                    // Do not await a full-file re-hash on the
                                    // network task — that starved KAD/IPC for
                                    // large libraries. Empty part hashes here
                                    // are filled on the next combined hash pass.
                                    debug!(
                                        "Deferring part-hash re-read for {}; using empty until next hash pass",
                                        f.path
                                    );
                                    part_hashes = Vec::new();
                                }
                            }
                            known_files.add_or_update(KnownFileRecord {
                                file_hash: fh,
                                part_hashes,
                                file_name: f.name.clone(),
                                file_size: f.size,
                                file_path: f.path.clone(),
                                aich_hash: if !f.aich_hash.is_empty() {
                                    f.aich_hash.clone()
                                } else {
                                    existing
                                        .as_ref()
                                        .map(|r| r.aich_hash.clone())
                                        .unwrap_or_default()
                                },
                                ember_file_hash: if !f.ember_file_hash.is_empty() {
                                    f.ember_file_hash.clone()
                                } else {
                                    existing
                                        .as_ref()
                                        .map(|r| r.ember_file_hash.clone())
                                        .unwrap_or_default()
                                },
                                modified_at: f.modified_at,
                                all_time_transferred: att,
                                all_time_requested: atr,
                                all_time_accepted: ata,
                                upload_priority: prio,
                                last_publish_src: lps,
                                last_shared: chrono::Utc::now().timestamp() as u32,
                                is_shared,
                                // Fail closed. A rediscovered or rehashed file
                                // arrives with `friends_only = false` straight
                                // from `discover_file`, and letting that win
                                // would quietly republish content the user had
                                // restricted. Lifting a restriction goes
                                // through `SetFilesFriendsOnly`, which clears
                                // the record before any reconcile runs, so an
                                // intentional unrestrict is unaffected.
                                friends_only: f.friends_only
                                    || existing.as_ref().is_some_and(|r| r.friends_only),
                                complete_sources: sources,
                                last_ember_source_publish: existing
                                    .as_ref()
                                    .map(|r| r.last_ember_source_publish)
                                    .unwrap_or(0),
                                last_ember_keyword_publish: existing
                                    .as_ref()
                                    .map(|r| r.last_ember_keyword_publish)
                                    .unwrap_or(0),
                            });
                            // Real BLAKE3 just landed (or was refreshed) —
                            // drop publish timers so the next tick advertises
                            // the digest instead of waiting out a zeros publish.
                            if !f.ember_file_hash.is_empty() {
                                state.ember_source_publish_at.remove(&fh);
                                state.ember_keyword_publish_at.remove(&fh);
                                state.ember_source_publish_unix.remove(&fh);
                                state.ember_keyword_publish_unix.remove(&fh);
                            }
                        }
                    }
                }
            }
            let mut seen_hashes = std::collections::HashSet::new();
            let files: Vec<PublishableFile> = all_index_files
                .iter()
                .filter(|f| f.is_public_listable())
                .filter_map(|f| {
                    if f.hash.is_empty() || !seen_hashes.insert(f.hash.clone()) {
                        return None;
                    }
                    let hash_bytes = hex::decode(&f.hash).ok()?;
                    if hash_bytes.len() < 16 {
                        return None;
                    }
                    Some(PublishableFile {
                        file_hash: md4_bytes_to_kad_id(&hash_bytes[..16]),
                        file_name: f.name.clone(),
                        file_size: f.size,
                        file_type: crate::search::index::infer_file_type(&f.extension),
                        complete_sources: f.complete_sources,
                        keyword_publishable: true,
                        last_source_publish: {
                            let mut raw = [0u8; 16];
                            raw.copy_from_slice(&hash_bytes[..16]);
                            known_files
                                .find_by_hash(&raw)
                                .map(|r| r.last_publish_src as i64)
                                .unwrap_or(0)
                        },
                    })
                })
                .collect();
            let shared_count = files.len();
            // Reconcile rather than wipe. The old `clear_all()` here threw
            // away every in-memory keyword publish timestamp on each
            // shared-file change; since keyword times (unlike source times)
            // are not persisted to known.met, that re-queued the whole
            // keyword set and keyword publishing never settled to its 24h
            // interval. `add_files_batch` updates file metadata while
            // keeping existing keyword timestamps (`or_insert`); the
            // `retain_files` call after the partials loop then evicts
            // anything no longer shared. `desired` accumulates every hash
            // we re-register so retain knows what to keep.
            let mut desired: std::collections::HashSet<KadId> =
                files.iter().map(|f| f.file_hash).collect();
            state.publish_manager.add_files_batch(files);

            // Re-add active partial downloads to KAD publish.
            let mut partial_count = 0u32;
            {
                let mgr = transfer_manager.read().await;
                for transfer in mgr.active.values().chain(mgr.queue.iter()) {
                    if transfer.direction != TransferDirection::Download {
                        continue;
                    }
                    if matches!(
                        transfer.status,
                        TransferStatus::Completed | TransferStatus::Failed
                    ) {
                        continue;
                    }
                    if transfer.file_hash.is_empty()
                        || !seen_hashes.insert(transfer.file_hash.clone())
                    {
                        continue;
                    }
                    let hash_bytes = match hex::decode(&transfer.file_hash) {
                        Ok(bytes) if bytes.len() >= 16 => bytes,
                        _ => continue,
                    };
                    let ext = std::path::Path::new(&transfer.file_name)
                        .extension()
                        .map(|e| e.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let partial_hash = md4_bytes_to_kad_id(&hash_bytes[..16]);
                    desired.insert(partial_hash);
                    state.publish_manager.add_file(PublishableFile {
                        file_hash: partial_hash,
                        file_name: transfer.file_name.clone(),
                        file_size: transfer.total_size,
                        file_type: crate::search::index::infer_file_type(&ext),
                        complete_sources: 0,
                        keyword_publishable: false,
                        last_source_publish: {
                            let mut raw = [0u8; 16];
                            raw.copy_from_slice(&hash_bytes[..16]);
                            known_files
                                .find_by_hash(&raw)
                                .map(|r| r.last_publish_src as i64)
                                .unwrap_or(0)
                        },
                    });
                    partial_count += 1;
                }
            }
            // Evict publish records for files no longer shared/downloading
            // and drop their source-ack counters; orphaned keyword targets
            // are pruned inside `retain_files`. Retained files keep their
            // source and keyword publish timestamps, so already-published
            // work is not needlessly repeated.
            state.publish_manager.retain_files(&desired);
            // The rendezvous advert is deliberately not a library file, so it
            // is never in `desired`. Dropping its counter mid-publish made the
            // completion handler read zero acks, conclude the advert had not
            // been stored, and re-advertise on the next tick — every time a
            // library change happened to overlap a rendezvous publish.
            let rendezvous_key = kad::publish::ember_rendezvous_key();
            state
                .source_publish_acks
                .retain(|hash, _| desired.contains(hash) || *hash == rendezvous_key);
            // Same eviction for the Ember badge set. Ember publishes only
            // complete, publicly listable files (no partials), so unsharing
            // one must darken its badge exactly as it does for KAD.
            let ember_keep: HashSet<[u8; 16]> = all_index_files
                .iter()
                .filter(|f| f.is_public_listable())
                .filter_map(|f| parse_ed2k_hash16(&f.hash))
                .collect();
            state
                .ember_published_sources
                .retain(|hash| ember_keep.contains(hash));
            info!("Re-populated publish manager with {shared_count} shared + {partial_count} partial downloads after change");

            // eMule: re-send OP_OFFERFILES to the server when shared files change
            if state.server_connected {
                let mut seen_offer_hashes = std::collections::HashSet::new();
                let mut offer_files: Vec<ed2k::server::OfferFile> = all_index_files
                    .iter()
                    .filter(|f| f.is_public_listable())
                    .filter_map(|f| {
                        if f.hash.is_empty() || !seen_offer_hashes.insert(f.hash.clone()) {
                            return None;
                        }
                        let hash_bytes = hex::decode(&f.hash).ok()?;
                        if hash_bytes.len() < 16 {
                            return None;
                        }
                        let mut h = [0u8; 16];
                        h.copy_from_slice(&hash_bytes[..16]);
                        Some(ed2k::server::OfferFile {
                            hash: h,
                            name: f.name.clone(),
                            size: f.size,
                            is_complete: true,
                            file_type: String::new(),
                        })
                    })
                    .collect();
                let temp_dir = PathBuf::from(&settings.download_folder).join("Temp");
                {
                    let mgr = transfer_manager.read().await;
                    for transfer in mgr.active.values().chain(mgr.queue.iter()) {
                        if transfer.direction != TransferDirection::Download {
                            continue;
                        }
                        if matches!(
                            transfer.status,
                            TransferStatus::Completed | TransferStatus::Failed
                        ) {
                            continue;
                        }
                        if transfer.file_hash.is_empty()
                            || !seen_offer_hashes.insert(transfer.file_hash.clone())
                        {
                            continue;
                        }
                        let hash_bytes = match hex::decode(&transfer.file_hash) {
                            Ok(bytes) if bytes.len() >= 16 => bytes,
                            _ => continue,
                        };
                        let part_path = temp_dir.join(format!("{}.part", transfer.id));
                        if !part_path.exists() {
                            continue;
                        }
                        let mut h = [0u8; 16];
                        h.copy_from_slice(&hash_bytes[..16]);
                        offer_files.push(ed2k::server::OfferFile {
                            hash: h,
                            name: transfer.file_name.clone(),
                            size: transfer.total_size,
                            is_complete: false,
                            file_type: String::new(),
                        });
                    }
                }
                let signature = offer_files_signature(&offer_files);
                if state.last_offer_files_signature == Some(signature) {
                    debug!(
                        "Skipping OP_OFFERFILES resend: offer set unchanged ({} files)",
                        offer_files.len()
                    );
                    replace_offered_ed2k_hashes(state, &offer_files);
                } else {
                    // Defer the actual send to the main loop's chunked drain so
                    // this Ack returns immediately and does not block IPC.
                    state.request_offer_files = true;
                }
            }
            let _ = reconcile_ack.send(Ok(()));
        }

        NetworkCommand::SetFileComment {
            file_hash,
            rating,
            comment,
        } => {
            state.comment_manager.write().await.set_our_comment(
                &file_hash,
                rating,
                comment.clone(),
            );
            if let Err(e) = db.save_file_comment(&file_hash, rating, &comment) {
                warn!("Failed to save comment: {e}");
            }
        }

        NetworkCommand::GetFileComments { file_hash, tx } => {
            let cm = state.comment_manager.read().await;
            let avg = cm.average_rating(&file_hash);
            let fake = cm.has_fake_rating(&file_hash);
            let (_our_rating, _our_comment) = cm.get_our_comment(&file_hash);
            if fake {
                debug!("File {} has fake rating reports", file_hash);
            }
            if avg > 0.0 {
                debug!("File {} average rating: {:.1}", file_hash, avg);
            }
            let info = cm.get_comments(&file_hash).cloned();
            let _ = tx.send(info);
        }

        NetworkCommand::MergeServerMet { data, tx } => {
            let result = state.server_list.merge_from_bytes_filtered(
                &data,
                settings.filter_servers_by_ip,
                Some(&mut state.ip_filter),
            );
            if result.is_ok() {
                let met_path = state.data_dir.join("server.met");
                spawn_save_server_met(
                    &state.server_list,
                    met_path,
                    &state.server_met_save_generation,
                    &state.server_met_save_lock,
                );
            }
            let _ = tx.send(result);
        }

        NetworkCommand::PreviewFile { transfer_id, tx } => {
            let download_folder = settings.download_folder.clone();
            let tm = transfer_manager.clone();
            tokio::spawn(async move {
                let result = async {
                    let mgr_guard = tm.read().await;
                    let transfer = mgr_guard
                        .get_transfer(&transfer_id)
                        .ok_or_else(|| "Transfer not found".to_string())?;

                    let file_name = transfer.file_name.clone();
                    let file_size = transfer.total_size;
                    let expected_aich = transfer.expected_aich.clone();
                    let tid = transfer.id.clone();
                    drop(mgr_guard);

                    let temp_dir = PathBuf::from(&download_folder).join("Temp");
                    let part_path = temp_dir.join(format!("{tid}.part"));

                    if !part_path.exists() {
                        return Err(
                            "Part file not found — download may not have started".to_string(),
                        );
                    }

                    let part_path = crate::security::filesystem::verify_existing_path(
                        &part_path,
                        &[download_folder.clone()],
                    )
                    .map_err(|e| format!("Invalid or changed part-file path: {e}"))?;
                    let file_name_for_preview = file_name.clone();

                    tokio::task::spawn_blocking(move || {
                        let tracker =
                            ed2k::part_tracker::PartTracker::new(file_size, &part_path);
                        let completed_bytes = tracker.completed_bytes();
                        let has_part_hashes = !tracker.part_hashes().is_empty();
                        let verified_complete_parts = tracker.verified_parts();
                        let part_size = ed2k::hash::PARTSIZE;

                        if !ed2k::preview::can_preview(
                            &file_name_for_preview,
                            file_size,
                            completed_bytes,
                            has_part_hashes,
                            &verified_complete_parts,
                            part_size,
                        ) {
                            return Err(
                                "File is not ready for preview (need the first 256KB downloaded and MD4-verified, and a previewable file type)".to_string(),
                            );
                        }
                        if let Some(expected) = expected_aich {
                            if !tracker.all_complete() {
                                return Err(
                                    "AICH-pinned previews require final AICH verification"
                                        .to_string(),
                                );
                            }
                            let set =
                                ed2k::aich::AICHRecoveryHashSet::build_from_file(&part_path)
                                    .map_err(|e| format!("AICH preview verification failed: {e}"))?;
                            if !hex::encode(set.root_hash).eq_ignore_ascii_case(&expected) {
                                return Err("Expected AICH hash mismatch; preview blocked".into());
                            }
                        }
                        let verified_ranges: Vec<ed2k::preview::FilledRange> =
                            verified_complete_parts
                                .iter()
                                .enumerate()
                                .filter(|(_, verified)| **verified)
                                .map(|(index, _)| {
                                    let start = index as u64 * part_size;
                                    ed2k::preview::FilledRange {
                                        start,
                                        end: (start + part_size).min(file_size),
                                    }
                                })
                                .collect();

                        let preview_path = ed2k::preview::create_preview_file(
                            &part_path,
                            &verified_ranges,
                            &file_name_for_preview,
                        )
                        .map_err(|e| format!("Failed to create preview file: {e}"))?;

                        ed2k::preview::launch_preview(&preview_path)
                            .map_err(|e| format!("Failed to launch preview: {e}"))?;

                        Ok(format!("Preview launched: {}", preview_path.display()))
                    })
                    .await
                    .map_err(|e| format!("Preview task panicked: {e}"))?
                }
                .await;
                let _ = tx.send(result);
            });
        }

        // UpdateIpFilterFromUrl removed — download now happens directly in the command handler with DNS-pinned client
        NetworkCommand::SendChatMessage {
            ember_hash: friend_eh,
            message,
            tx,
        } => {
            if settings.friend_chat_disabled {
                let _ = tx.send(Err("Chat is disabled in Friends settings".into()));
            } else if !friend_hashes.read().await.contains(&friend_eh) {
                let _ = tx.send(Err("Can only chat with friends".into()));
            } else {
                // Only reuse the session if it's actually fresh (see
                // `EmberSessionHandle::is_fresh`). A stale entry's mpsc
                // channel is usually still open — its receiver lives in a
                // writer loop that hasn't yet noticed the peer is gone —
                // so `try_send` below would silently "succeed" into a
                // socket write that never reaches anyone, and the caller
                // would see `Ok(())` for a message that's actually lost.
                // Falling through to the reconnect branch instead gives
                // the message a real chance of delivery.
                let sender = {
                    let sessions = state.ember_sessions.read().await;
                    sessions
                        .get(&friend_eh)
                        .filter(|h| h.is_fresh() && h.is_secure_v2())
                        .cloned()
                };
                if let Some(sender) = sender {
                    // Every friend session's `EmberSessionHandle` carries
                    // the peer's PoP-verified Ed25519 pubkey (see its doc
                    // comment), so encryption is always possible for a
                    // live session — there is no plaintext-fallback path.
                    let peer_pubkey = sender.peer_ember_pubkey();
                    match crate::network::ember::crypto::encrypt_chat_for_peer(
                        &ed25519_secret_key,
                        &peer_pubkey,
                        message.as_bytes(),
                    ) {
                        None => {
                            // Can only happen if the peer's already-PoP-verified
                            // pubkey somehow isn't a valid curve point, which
                            // `perform_ember_auth` should have ruled out —
                            // treat as an internal error rather than ever
                            // silently sending plaintext.
                            let _ = tx.send(Err("ChatEncryptFailed".into()));
                        }
                        Some(envelope) => {
                            let mut packet = Vec::with_capacity(6 + envelope.len());
                            packet.push(OP_EMULEPROT);
                            let size = (1 + envelope.len()) as u32;
                            packet.extend_from_slice(&size.to_le_bytes());
                            packet.push(ed2k::messages::OP_EMBER_CHAT_MSG);
                            packet.extend_from_slice(&envelope);
                            if !friend_hashes.read().await.contains(&friend_eh) {
                                let _ = tx.send(Err("Can only chat with friends".into()));
                                return;
                            }
                            let hash_hex = hex::encode(friend_eh);
                            let pending_id = match queue_outbound_chat_message(
                                db.clone(),
                                hash_hex,
                                message.clone(),
                            )
                            .await
                            {
                                Ok(id) => id,
                                Err(error) => {
                                    warn!(
                                        "Refusing to hand off chat without a durable outbox row: {error}"
                                    );
                                    let _ = tx.send(Err(error));
                                    return;
                                }
                            };
                            match sender.tx.try_send(packet) {
                                Ok(()) => {
                                    match mark_outbound_chat_delivered(db.clone(), pending_id).await
                                    {
                                        Ok(()) => {
                                            let _ = app_handle.emit(
                                                "ember:chat-message",
                                                serde_json::json!({
                                                    "user_hash": hex::encode(friend_eh),
                                                    "message": message,
                                                    "direction": "sent",
                                                    "timestamp": chrono::Utc::now().timestamp(),
                                                }),
                                            );
                                            let _ = tx.send(Ok(()));
                                        }
                                        Err(error) => {
                                            warn!(
                                                "Sent chat message remains queued because delivery persistence failed: {error}"
                                            );
                                            let _ = tx.send(Err(format!(
                                                "ChatAlreadyQueued:{pending_id}"
                                            )));
                                        }
                                    }
                                }
                                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                    let _ = tx.send(Err(format!("ChatAlreadyQueued:{pending_id}")));
                                }
                                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                    let _ = tx.send(Err(format!("ChatAlreadyQueued:{pending_id}")));
                                }
                            }
                        }
                    }
                } else {
                    // Queue before initiating a connection. The successful
                    // `EmberFriendConnected` event flushes this durable row;
                    // sending a separate direct copy after connect races that
                    // flush and can duplicate the chat packet.
                    let queued_hash = hex::encode(friend_eh);
                    let queued_id = match queue_outbound_chat_message(
                        db.clone(),
                        queued_hash,
                        message.clone(),
                    )
                    .await
                    {
                        Ok(id) => id,
                        Err(error) => {
                            warn!(
                                    "Refusing to auto-connect chat without a durable outbox row: {error}"
                                );
                            let _ = tx.send(Err(error));
                            return;
                        }
                    };
                    let _ = tx.send(Err(format!("ChatAlreadyQueued:{queued_id}")));
                    if state.outbound_session_tasks.contains_key(&friend_eh) {
                        debug!("Chat remains queued while an existing friend connection attempt finishes");
                    } else {
                        let db2 = db.clone();
                        let hash_hex = hex::encode(friend_eh);
                        let addr_opt =
                            tokio::task::spawn_blocking(move || db2.get_friend_address(&hash_hex))
                                .await
                                .ok()
                                .and_then(|r| r.ok())
                                .flatten();
                        if let Some((ip_str, port)) = addr_opt {
                            if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                                let addr = SocketAddr::new(ip.into(), port);
                                state
                                    .outbound_session_tasks
                                    .insert(friend_eh, std::time::Instant::now());
                                let our_user_hash = state.user_hash;
                                let our_ember_hash = ember_hash;
                                let nickname = settings.nickname.clone();
                                let client_id = state
                                    .external_ip
                                    .map(|eip| u32::from_le_bytes(eip.octets()))
                                    .unwrap_or(0);
                                let tcp = advertised_tcp_port(&state);
                                let udp = advertised_udp_port(&state);
                                let obfs = settings.friend_session_encryption;
                                let sessions_clone = state.ember_sessions.clone();
                                let ul_tx = ul_event_tx.clone();
                                let fh = friend_hashes.clone();
                                let db3 = db.clone();
                                let ul_tx2 = ul_event_tx.clone();
                                let rv_url = settings.rendezvous_url.clone();
                                let nat_ctx = state.friend_nat_context.clone();
                                // debug! (not info!) because the Ember hash + address pair
                                // is identity-correlatable PII; we keep it for troubleshooting
                                // but don't surface it in the default log stream.
                                debug!(
                                    "Auto-connecting to friend {} for chat at {}",
                                    hex::encode(friend_eh),
                                    addr
                                );
                                tokio::spawn(async move {
                                    match ed2k::friend_connect::connect_friend_with_fallback(
                                        addr,
                                        friend_eh,
                                        our_user_hash,
                                        our_ember_hash,
                                        nickname,
                                        client_id,
                                        tcp,
                                        udp,
                                        obfs,
                                        sessions_clone.clone(),
                                        ul_tx,
                                        fh.clone(),
                                        Some(ed25519_pubkey),
                                        Some(ed25519_secret_key),
                                        rv_url,
                                        nat_ctx,
                                    )
                                    .await
                                    {
                                        Ok(_handle) => {
                                            if !fh.read().await.contains(&friend_eh) {
                                                debug!(
                                                    "Friend was removed while auto-connecting queued chat"
                                                );
                                                let _ = ul_tx2.send(upload_server::UploadEvent {
                                                    transfer_id: String::new(),
                                                    kind: upload_server::UploadEventKind::EmberFriendSearchFailed { ember_hash: friend_eh },
                                                }).await;
                                                return;
                                            }
                                            // `EmberFriendConnected` flushes the
                                            // already-queued row, so no direct
                                            // packet is sent here. Emit it
                                            // ourselves: `connect_friend_with_fallback`
                                            // returns Ok *without* emitting when it
                                            // reuses an existing session, which
                                            // would otherwise leave the message
                                            // queued indefinitely while the friend
                                            // shows online. A redundant emit is safe
                                            // — the flush is a no-op once the rows
                                            // are marked delivered. The endpoint
                                            // sentinels keep the handler's address
                                            // update and source reseed out of it;
                                            // that arm is gated on a real ip/port,
                                            // and the dial already recorded them.
                                            let _ = ul_tx2.send(upload_server::UploadEvent {
                                                transfer_id: String::new(),
                                                kind: upload_server::UploadEventKind::EmberFriendConnected {
                                                    ember_hash: friend_eh,
                                                    peer_user_hash: [0u8; 16],
                                                    ip: std::net::Ipv4Addr::UNSPECIFIED,
                                                    port: 0,
                                                },
                                            }).await;
                                        }
                                        Err(e) => {
                                            debug!(
                                                "Auto-connect for chat to {} failed: {e}",
                                                hex::encode(friend_eh)
                                            );
                                            // Stored IP is dead — clear it so the
                                            // next chat attempt skips the
                                            // multi-second TCP timeout against
                                            // the same address and goes straight
                                            // to rendezvous.
                                            let hash_hex_clear = hex::encode(friend_eh);
                                            let db_for_clear = db3.clone();
                                            let _ = tokio::task::spawn_blocking(move || {
                                                db_for_clear.clear_friend_address(&hash_hex_clear)
                                            })
                                            .await;
                                        }
                                    }
                                    // Always release the outbound-task slot
                                    // (success or failure). On Ok the live
                                    // session lives in ember_sessions; the
                                    // slot only gated this connect attempt.
                                    let _ = ul_tx2.send(upload_server::UploadEvent {
                                        transfer_id: String::new(),
                                        kind: upload_server::UploadEventKind::EmberFriendSearchFailed { ember_hash: friend_eh },
                                    }).await;
                                });
                            } else {
                                // Stored IP wasn't a parseable v4 address —
                                // wipe it so the next attempt falls through
                                // to rendezvous instead of repeating the
                                // same parse failure. No `outbound_session_tasks`
                                // entry was inserted in this branch, so no
                                // cleanup event is required here.
                                let hash_hex_clear = hex::encode(friend_eh);
                                let db_for_clear = db.clone();
                                let _ = tokio::task::spawn_blocking(move || {
                                    db_for_clear.clear_friend_address(&hash_hex_clear)
                                })
                                .await;
                                debug!("Queued chat cannot use stored invalid friend IP address");
                            }
                        } else {
                            let rv_url = settings.rendezvous_url.clone();
                            let our_uh = state.user_hash;
                            let our_eh = ember_hash;
                            let nick = settings.nickname.clone();
                            let cid = state
                                .external_ip
                                .map(|eip| u32::from_le_bytes(eip.octets()))
                                .unwrap_or(0);
                            let tcp = advertised_tcp_port(&state);
                            let udp = advertised_udp_port(&state);
                            let obfs = settings.friend_session_encryption;
                            let sess = state.ember_sessions.clone();
                            let ultx = ul_event_tx.clone();
                            let fh = friend_hashes.clone();
                            let ultx2 = ul_event_tx.clone();
                            let nat_ctx = state.friend_nat_context.clone();
                            state
                                .outbound_session_tasks
                                .insert(friend_eh, std::time::Instant::now());
                            debug!(
                                "No stored address for {}, trying rendezvous for chat",
                                hex::encode(friend_eh)
                            );
                            tokio::spawn(async move {
                                match crate::network::rendezvous::lookup(
                                    &rv_url,
                                    &our_eh,
                                    &ed25519_pubkey,
                                    &ed25519_secret_key,
                                    &friend_eh,
                                )
                                .await
                                {
                                    Ok(Some((ip, port))) => {
                                        let addr = std::net::SocketAddr::new(ip.into(), port);
                                        match ed2k::friend_connect::connect_friend_with_fallback(
                                            addr,
                                            friend_eh,
                                            our_uh,
                                            our_eh,
                                            nick,
                                            cid,
                                            tcp,
                                            udp,
                                            obfs,
                                            sess,
                                            ultx,
                                            fh.clone(),
                                            Some(ed25519_pubkey),
                                            Some(ed25519_secret_key),
                                            rv_url.clone(),
                                            nat_ctx,
                                        )
                                        .await
                                        {
                                            Ok(_handle) => {
                                                if !fh.read().await.contains(&friend_eh) {
                                                    debug!(
                                                        "Friend was removed while rendezvous-connecting queued chat"
                                                    );
                                                    let _ = ultx2.send(upload_server::UploadEvent {
                                                        transfer_id: String::new(),
                                                        kind: upload_server::UploadEventKind::EmberFriendSearchFailed { ember_hash: friend_eh },
                                                    }).await;
                                                    return;
                                                }
                                                // `EmberFriendConnected` flushes the
                                                // durable outbox row created before
                                                // this attempt. Emit it ourselves:
                                                // the connect returns Ok *without*
                                                // emitting when it reuses an existing
                                                // session, which would leave the
                                                // message queued while the friend
                                                // shows online. A redundant emit is
                                                // safe, and the endpoint sentinels
                                                // keep the handler's address update
                                                // and source reseed out of it.
                                                let _ = ultx2.send(upload_server::UploadEvent {
                                                    transfer_id: String::new(),
                                                    kind: upload_server::UploadEventKind::EmberFriendConnected {
                                                        ember_hash: friend_eh,
                                                        peer_user_hash: [0u8; 16],
                                                        ip: std::net::Ipv4Addr::UNSPECIFIED,
                                                        port: 0,
                                                    },
                                                }).await;
                                            }
                                            Err(e) => {
                                                debug!(
                                                    "Queued chat rendezvous connection failed: {e}"
                                                );
                                            }
                                        }
                                    }
                                    _ => {
                                        debug!("Queued chat friend is offline");
                                    }
                                }
                                // Always release the outbound-task slot
                                // (success or failure) so the next chat /
                                // browse / auto-retry isn't blocked for
                                // the 10-min TTL. EmberFriendSearchFailed
                                // (not EmberFriendDisconnected) avoids
                                // misleading offline UI events.
                                let _ = ultx2.send(upload_server::UploadEvent {
                                    transfer_id: String::new(),
                                    kind: upload_server::UploadEventKind::EmberFriendSearchFailed { ember_hash: friend_eh },
                                }).await;
                            });
                        }
                    }
                }
            }
        }

        NetworkCommand::CancelBrowseFriend {
            ember_hash: friend_eh,
            request_id,
        } => {
            if let Some((retired_session_id, invalidated)) =
                cancel_browse_request(&mut state.pending_browse_requests, friend_eh, &request_id)
            {
                if let Some(session_id) = retired_session_id.filter(|id| *id != 0) {
                    // A browse response cannot be cancelled on the ED2K wire.
                    // Retire this canonical session so its late response is
                    // never attributed to a later local request.
                    let _ =
                        retire_ember_session(&state.ember_sessions, friend_eh, session_id).await;
                    for invalidated_id in invalidated {
                        let _ = app_handle.emit(
                            "ember:browse-error",
                            serde_json::json!({
                                "user_hash": hex::encode(friend_eh),
                                "request_id": invalidated_id,
                                "reason": "Browse session was reset after cancellation",
                            }),
                        );
                    }
                }
                dispatch_browse_head(state, &app_handle, friend_eh).await;
            }
        }

        NetworkCommand::BrowseFriend {
            ember_hash: friend_eh,
            request_id,
            tx,
        } => {
            if settings.friend_browse_disabled {
                let _ = tx.send(Err("Browse is disabled in Friends settings".into()));
            } else if !friend_hashes.read().await.contains(&friend_eh) {
                let _ = tx.send(Err("Can only browse friends".into()));
            } else {
                // See the identical `filter(|h| h.is_fresh())` in
                // `SendChatMessage` above: reusing a stale session here
                // would queue the browse request into a channel whose
                // socket write never reaches a live peer.
                let sender = state
                    .ember_sessions
                    .read()
                    .await
                    .get(&friend_eh)
                    .filter(|handle| handle.is_fresh() && handle.is_secure_v2())
                    .cloned();
                if let Some(sender) = sender {
                    match enqueue_browse_request(
                        &mut state.pending_browse_requests,
                        friend_eh,
                        request_id.clone(),
                        sender.session_id(),
                    ) {
                        Err(()) => {
                            let _ = tx.send(Err("Duplicate browse request".into()));
                        }
                        Ok(()) => {
                            dispatch_browse_head(state, &app_handle, friend_eh).await;
                            if browse_request_is_pending(
                                &state.pending_browse_requests,
                                friend_eh,
                                &request_id,
                            ) {
                                let _ = tx.send(Ok(()));
                            } else {
                                let _ = tx.send(Err(
                                    "Friend session closed before browse could be sent".into(),
                                ));
                            }
                        }
                    }
                } else {
                    if state.outbound_session_tasks.contains_key(&friend_eh) {
                        let _ =
                            tx.send(Err("Connecting to friend, please retry in a moment".into()));
                    } else {
                        if enqueue_browse_request(
                            &mut state.pending_browse_requests,
                            friend_eh,
                            request_id.clone(),
                            0,
                        )
                        .is_err()
                        {
                            let _ = tx.send(Err("Duplicate browse request".into()));
                            return;
                        }
                        let db2 = db.clone();
                        let hash_hex = hex::encode(friend_eh);
                        let addr_opt =
                            tokio::task::spawn_blocking(move || db2.get_friend_address(&hash_hex))
                                .await
                                .ok()
                                .and_then(|r| r.ok())
                                .flatten();
                        if let Some((ip_str, port)) = addr_opt {
                            if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                                let addr = SocketAddr::new(ip.into(), port);
                                state
                                    .outbound_session_tasks
                                    .insert(friend_eh, std::time::Instant::now());
                                let our_user_hash = state.user_hash;
                                let our_ember_hash = ember_hash;
                                let nickname = settings.nickname.clone();
                                let client_id = state
                                    .external_ip
                                    .map(|eip| u32::from_le_bytes(eip.octets()))
                                    .unwrap_or(0);
                                let tcp = advertised_tcp_port(&state);
                                let udp = advertised_udp_port(&state);
                                let obfs = settings.friend_session_encryption;
                                let sessions_clone = state.ember_sessions.clone();
                                let ul_tx = ul_event_tx.clone();
                                let fh = friend_hashes.clone();
                                let browse_event_tx = ul_event_tx.clone();
                                let ul_tx2 = ul_event_tx.clone();
                                let rv_url = settings.rendezvous_url.clone();
                                let nat_ctx = state.friend_nat_context.clone();
                                info!(
                                    "Auto-connecting to friend {} for browse at {}",
                                    hex::encode(friend_eh),
                                    addr
                                );
                                let db3 = db.clone();
                                tokio::spawn(async move {
                                    match ed2k::friend_connect::connect_friend_with_fallback(
                                        addr,
                                        friend_eh,
                                        our_user_hash,
                                        our_ember_hash,
                                        nickname,
                                        client_id,
                                        tcp,
                                        udp,
                                        obfs,
                                        sessions_clone.clone(),
                                        ul_tx,
                                        fh,
                                        Some(ed25519_pubkey),
                                        Some(ed25519_secret_key),
                                        rv_url,
                                        nat_ctx,
                                    )
                                    .await
                                    {
                                        Ok(handle) => {
                                            let _ = browse_event_tx
                                                .send(upload_server::UploadEvent {
                                                    transfer_id: String::new(),
                                                    kind: upload_server::UploadEventKind::EmberBrowseSessionReady {
                                                        ember_hash: friend_eh,
                                                        request_id,
                                                        session_id: handle.session_id,
                                                        tx,
                                                    },
                                                })
                                                .await;
                                        }
                                        Err(e) => {
                                            info!(
                                                "Auto-connect for browse to {} failed: {e}",
                                                hex::encode(friend_eh)
                                            );
                                            let _ = browse_event_tx
                                                .send(upload_server::UploadEvent {
                                                    transfer_id: String::new(),
                                                    kind: upload_server::UploadEventKind::EmberBrowseSessionFailed {
                                                        ember_hash: friend_eh,
                                                        request_id,
                                                        error: format!("Could not connect: {e}"),
                                                        tx,
                                                    },
                                                })
                                                .await;
                                            // Stored IP is dead; clear it so
                                            // the next browse / chat attempt
                                            // jumps straight to rendezvous
                                            // instead of paying for the same
                                            // dial timeout. Same rationale as
                                            // the chat path above.
                                            let hash_hex_clear = hex::encode(friend_eh);
                                            let _ = tokio::task::spawn_blocking(move || {
                                                db3.clear_friend_address(&hash_hex_clear)
                                            })
                                            .await;
                                        }
                                    }
                                    // Always release the outbound-task slot
                                    // (success or failure). On Ok the live
                                    // session lives in ember_sessions; the
                                    // slot only gated this connect attempt.
                                    let _ = ul_tx2.send(upload_server::UploadEvent {
                                        transfer_id: String::new(),
                                        kind: upload_server::UploadEventKind::EmberFriendSearchFailed { ember_hash: friend_eh },
                                    }).await;
                                });
                            } else {
                                // Stored IP isn't a parseable v4 address; wipe
                                // it so the next attempt falls through to
                                // rendezvous. No outbound-task slot was
                                // inserted in this branch.
                                let hash_hex_clear = hex::encode(friend_eh);
                                let db_for_clear = db.clone();
                                let _ = tokio::task::spawn_blocking(move || {
                                    db_for_clear.clear_friend_address(&hash_hex_clear)
                                })
                                .await;
                                let _ = cancel_browse_request(
                                    &mut state.pending_browse_requests,
                                    friend_eh,
                                    &request_id,
                                );
                                let _ = tx.send(Err("Invalid friend IP address".into()));
                            }
                        } else {
                            let rv_url = settings.rendezvous_url.clone();
                            let our_uh = state.user_hash;
                            let our_eh = ember_hash;
                            let nick = settings.nickname.clone();
                            let cid = state
                                .external_ip
                                .map(|eip| u32::from_le_bytes(eip.octets()))
                                .unwrap_or(0);
                            let tcp = advertised_tcp_port(&state);
                            let udp = advertised_udp_port(&state);
                            let obfs = settings.friend_session_encryption;
                            let sess = state.ember_sessions.clone();
                            let ultx = ul_event_tx.clone();
                            let fh = friend_hashes.clone();
                            let app2 = app_handle.clone();
                            let browse_event_tx = ul_event_tx.clone();
                            let ultx2 = ul_event_tx.clone();
                            let nat_ctx = state.friend_nat_context.clone();
                            state
                                .outbound_session_tasks
                                .insert(friend_eh, std::time::Instant::now());
                            info!(
                                "No stored address for {}, trying rendezvous for browse",
                                hex::encode(friend_eh)
                            );
                            tokio::spawn(async move {
                                match crate::network::rendezvous::lookup(
                                    &rv_url,
                                    &our_eh,
                                    &ed25519_pubkey,
                                    &ed25519_secret_key,
                                    &friend_eh,
                                )
                                .await
                                {
                                    Ok(Some((ip, port))) => {
                                        let addr = std::net::SocketAddr::new(ip.into(), port);
                                        match ed2k::friend_connect::connect_friend_with_fallback(
                                            addr,
                                            friend_eh,
                                            our_uh,
                                            our_eh,
                                            nick,
                                            cid,
                                            tcp,
                                            udp,
                                            obfs,
                                            sess,
                                            ultx,
                                            fh,
                                            Some(ed25519_pubkey),
                                            Some(ed25519_secret_key),
                                            rv_url.clone(),
                                            nat_ctx,
                                        )
                                        .await
                                        {
                                            Ok(handle) => {
                                                let _ = app2.emit(
                                                    "ember:friend-online",
                                                    serde_json::json!({
                                                        "user_hash": hex::encode(friend_eh),
                                                    }),
                                                );
                                                let _ = browse_event_tx
                                                    .send(upload_server::UploadEvent {
                                                        transfer_id: String::new(),
                                                        kind: upload_server::UploadEventKind::EmberBrowseSessionReady {
                                                            ember_hash: friend_eh,
                                                            request_id,
                                                            session_id: handle.session_id,
                                                            tx,
                                                        },
                                                    })
                                                    .await;
                                            }
                                            Err(e) => {
                                                let _ = browse_event_tx
                                                    .send(upload_server::UploadEvent {
                                                        transfer_id: String::new(),
                                                        kind: upload_server::UploadEventKind::EmberBrowseSessionFailed {
                                                            ember_hash: friend_eh,
                                                            request_id,
                                                            error: format!("Could not connect: {e}"),
                                                            tx,
                                                        },
                                                    })
                                                    .await;
                                            }
                                        }
                                    }
                                    _ => {
                                        let _ = browse_event_tx
                                            .send(upload_server::UploadEvent {
                                                transfer_id: String::new(),
                                                kind: upload_server::UploadEventKind::EmberBrowseSessionFailed {
                                                    ember_hash: friend_eh,
                                                    request_id,
                                                    error: "Friend is offline".into(),
                                                    tx,
                                                },
                                            })
                                            .await;
                                    }
                                }
                                // Always release the outbound-task slot
                                // (success or failure). EmberFriendSearchFailed
                                // not EmberFriendDisconnected — see chat path.
                                let _ = ultx2.send(upload_server::UploadEvent {
                                    transfer_id: String::new(),
                                    kind: upload_server::UploadEventKind::EmberFriendSearchFailed { ember_hash: friend_eh },
                                }).await;
                            });
                        }
                    }
                }
            }
        }

        NetworkCommand::FriendRemoved {
            ember_hash: removed_hash,
            tx,
        } => {
            upload_server::revoke_all_secure_sessions(removed_hash);
            state.online_friends.remove(&removed_hash);
            let _ = retire_current_ember_session(&state.ember_sessions, removed_hash).await;
            // Also drop any pending outbound-search slot so a remove
            // immediately followed by re-add isn't blocked for up to
            // 10 minutes by a stale entry.
            state.outbound_session_tasks.remove(&removed_hash);
            state.friend_reconnect_last.remove(&removed_hash);
            state.recent_ember_chat.remove(&removed_hash);

            if let Some(pending) = state.pending_browse_requests.remove(&removed_hash) {
                for request in pending {
                    let _ = app_handle.emit(
                        "ember:browse-error",
                        serde_json::json!({
                            "user_hash": hex::encode(removed_hash),
                            "request_id": request.request_id,
                            "reason": "Friend was removed",
                        }),
                    );
                }
            }

            // Queue entries outlive their originating TCP connection for
            // eMule seniority.  Strip only the friend-priority bit; standard
            // queue/file-transfer behavior and verified Ember accounting stay
            // intact.
            {
                let mut queue = upload_queue.lock().await;
                for entry in queue.iter_mut() {
                    let matches_removed = entry.ember_pubkey.is_some_and(|pk| {
                        crate::network::ember::crypto::verifying_key_from_bytes(&pk).is_some_and(
                            |vk| {
                                crate::network::ember::crypto::node_id_from_public_key(&vk)
                                    == removed_hash
                            },
                        )
                    });
                    if matches_removed {
                        entry.is_friend_slot = false;
                    }
                }
            }
            let _ = tx.send(());
        }

        NetworkCommand::FindFriendAndConnect {
            ember_hash: target_hash,
        } => {
            // Skip if the friend is already online or has a live
            // session. Mirrors the pre-existing guard in
            // `RetryFriendSearch`. Without this, the new
            // `EmberFriendSearchFailed` cleanup (which clears
            // `outbound_session_tasks[target_hash]` even when a
            // session for `target_hash` is alive) would let a
            // subsequent `FindFriendAndConnect` re-trigger a
            // wasteful rendezvous + dial against a peer we're
            // already talking to.
            if state.online_friends.contains_key(&target_hash)
                || state
                    .ember_sessions
                    .read()
                    .await
                    .get(&target_hash)
                    .is_some_and(|h| h.is_fresh())
            {
                debug!(
                    "FindFriendAndConnect: {} already online/connected, skipping",
                    hex::encode(target_hash),
                );
            } else if !state.outbound_session_tasks.contains_key(&target_hash) {
                state
                    .outbound_session_tasks
                    .insert(target_hash, std::time::Instant::now());
                let _ = app_handle.emit(
                    "ember:friend-searching",
                    serde_json::json!({
                        "user_hash": hex::encode(target_hash),
                    }),
                );
                spawn_rendezvous_friend_lookup(
                    &settings,
                    &state,
                    ember_hash,
                    target_hash,
                    &app_handle,
                    &friend_hashes,
                    &ul_event_tx,
                    ed25519_pubkey,
                    ed25519_secret_key,
                );
            }
        }

        NetworkCommand::ForceRendezvousRegister => {
            // Expire the heartbeat clock so the network loop's next tick
            // re-publishes intro + pairwise presence without waiting ~120s.
            state.rendezvous_last_register = None;
        }

        NetworkCommand::RetryFriendSearch {
            ember_hash: target_hash,
            tx,
        } => {
            let hash_hex = hex::encode(target_hash);

            if !friend_hashes.read().await.contains(&target_hash) {
                let _ = tx.send(Err("Can only retry search for friends".into()));
                return;
            }

            if state.online_friends.contains_key(&target_hash)
                || state
                    .ember_sessions
                    .read()
                    .await
                    .get(&target_hash)
                    .is_some_and(|h| h.is_fresh())
            {
                info!("RetryFriendSearch: {} already online/connected", hash_hex);
                let _ = tx.send(Ok(()));
                return;
            }

            // Same in-flight guard `FindFriendAndConnect` applies. Without it a
            // retry pressed while the first attempt is still running dogpiles
            // the rendezvous and races two `connect_friend_with_fallback` dials
            // at one identity — and `outbound_session_tasks` holds a single
            // entry per target, so the insert below would overwrite the running
            // attempt's marker and leave the cleanup sweep able to see only one
            // of the two. A search is already underway, which is what the user
            // asked for, so this reports success rather than an error.
            if state.outbound_session_tasks.contains_key(&target_hash) {
                info!(
                    "RetryFriendSearch: {} already has a search in flight",
                    hash_hex
                );
                let _ = tx.send(Ok(()));
                return;
            }

            state
                .outbound_session_tasks
                .insert(target_hash, std::time::Instant::now());
            let _ = app_handle.emit(
                "ember:friend-searching",
                serde_json::json!({
                    "user_hash": hash_hex,
                }),
            );

            spawn_rendezvous_friend_lookup(
                &settings,
                &state,
                ember_hash,
                target_hash,
                &app_handle,
                &friend_hashes,
                &ul_event_tx,
                ed25519_pubkey,
                ed25519_secret_key,
            );

            let _ = tx.send(Ok(()));
        }

        NetworkCommand::GetPeerReputation { user_hash, tx } => {
            // Apply any pending hourly decay before snapshotting so the UI
            // shows the same score the tracker would act on, not a stale
            // pre-decay value.
            state.reputation.maybe_decay();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let manual_banned = shared_banned_hashes
                .read()
                .map(|s| s.contains(&user_hash))
                .unwrap_or(false);
            let info = match state.reputation.get_peer(&user_hash) {
                Some(p) => Some(PeerReputationInfo {
                    score: p.score,
                    successful_transfers: p.successful_transfers,
                    failed_transfers: p.failed_transfers,
                    is_banned: p.is_banned(now) || manual_banned,
                    first_seen: p.first_seen,
                    last_interaction: p.last_interaction,
                }),
                // Manual ban with no tracker history still needs a row so
                // the Known Clients Trust column shows "banned".
                None if manual_banned => Some(PeerReputationInfo {
                    score: 0,
                    successful_transfers: 0,
                    failed_transfers: 0,
                    is_banned: true,
                    first_seen: now,
                    last_interaction: now,
                }),
                None => None,
            };
            let _ = tx.send(info);
        }

        NetworkCommand::GetReputationStats { tx } => {
            let _ = tx.send(ReputationStatsInfo {
                tracked_peers: state.reputation.tracked_count(),
                banned_peers: state.reputation.banned_count(),
                banned_ips: state.banned_ips.len(),
            });
        }

        NetworkCommand::Shutdown { .. } => {}
    }
}
