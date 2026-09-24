//! The Ember search tick: cold-join rendezvous lookups, driving Ember DHT
//! searches, publishes and maintenance pings, turning their results into
//! sources and search rows, and channel moderation and origin retries.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_ember_search_tick(
    udp_socket: &Arc<UdpSocket>,
    state: &mut NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    settings: &AppSettings,
    dl_event_tx: &mpsc::Sender<DownloadEvent>,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    credit_manager: &Arc<RwLock<CreditManager>>,
    stats_manager: &StatsManager,
    shared_banned_ips: &upload_server::SharedBannedIps,
    shared_ember_payload: &ember::SharedEmberPayload,
    ember_payload_generation: &ember::EmberPayloadGeneration,
    geoip: &crate::geoip::GeoIpReader,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    ember_hash: [u8; 16],
    ed25519_pubkey: [u8; 32],
    ed25519_secret_key: [u8; 32],
    comment_manager: &Arc<RwLock<CommentManager>>,
    connect_serve_tx: &mpsc::Sender<upload_server::ConnectServeRequest>,
    identity: &Arc<crate::storage::identity::NodeIdentity>,
    pending_kad_callbacks: &upload_server::PendingKadCallbacks,
    spam_filter: &Arc<RwLock<crate::search::spam::SpamFilter>>,
) {
    // Cold join, and deliberately ahead of the idle guard below: a
    // node that cannot reach anyone has nothing in flight, so it
    // takes the early return every tick. The 60-second maintenance
    // tick owns this gate in steady state, but it evaluates first at
    // t≈0 — before KAD has decoded a single packet, so
    // `kad_has_fresh_contact` is false — and not again for a full
    // minute. That left the one cold-join path unused for the first
    // minute of every launch, and unused entirely by any session
    // shorter than that.
    //
    // Self-limiting: `looked_up_at` is only non-zero once a lookup
    // has actually started, after which this stops re-checking for
    // the rest of the session and the maintenance tick takes over.
    if state.ember_rendezvous_looked_up_at == 0 {
        maybe_start_ember_rendezvous_lookup(
            state,
            app_handle,
            settings.ember_native_enabled,
        );
    }

    // And dial what that lookup finds, for the same reason. The
    // bridge belongs to the 60-second maintenance tick, but the
    // lookup feeding it completes mid-interval, so a node that had
    // just learned the only peers it could reach waited out the rest
    // of the minute before trying them — 46s of a measured cold
    // start. Restricted to the starved case so a healthy node keeps
    // bridging on the maintenance cadence, and to its own small
    // budget and spacing so shortening the *latency* does not also
    // multiply the ping *rate* — see `EMBER_BRIDGE_FAST_MAX_PINGS`.
    // Gates are ordered cheapest first because this runs every
    // second; `verified_len` walks the table, so it goes last.
    if settings.ember_native_enabled
        && (!state.ember_noise_keys.is_empty()
            || !state.ember_keyless_peers.is_empty())
        && state
            .ember_bridge_fast_at
            .is_none_or(|at| at.elapsed() >= EMBER_BRIDGE_FAST_INTERVAL)
        && state.ember_dht.routing().verified_len()
            < EMBER_KAD_BRIDGE_UNTIL_CONTACTS
    {
        state.ember_bridge_fast_at = Some(std::time::Instant::now());
        run_ember_kad_bridge(
            udp_socket,
            state,
            false,
            EMBER_BRIDGE_FAST_MAX_PINGS,
        )
        .await;
    }

    // Cheap when idle: the maps are empty unless an iterative
    // lookup, a publish, or a maintenance liveness ping is in
    // flight.
    if state.ember_dht_search_requests.is_empty()
        && state.ember_search.active_count() == 0
        && state.ember_dht_publish_requests.is_empty()
        && state.ember_publish.active_count() == 0
        && state.ember_dht_maint_pings.is_empty()
        && state.ember_pending_source_injections.is_empty()
        && state.ember_pending_callback_connects.is_empty()
        && state.ember_pending_proxy_overlay.is_empty()
        && state.ember_pending_keyword_results.is_empty()
        && state.ember_pending_channel_presence.is_empty()
        && state.ember_channel_presence_buffer.is_empty()
        && state.ember_pending_channel_moderation.is_empty()
        && state.ember_pending_channel_handoff.is_empty()
        && state.ember_pending_channel_epoch.is_empty()
        && state.ember_pending_channel_claim.is_empty()
        // The batch publisher is on an entirely separate path from
        // the maps above — `flush_ember_batch_publish` only ever
        // writes `in_flight` — and `expire()` below is its only
        // reaper. Leaving it out of the guard meant that whenever
        // unacked batches were the only outstanding work (an idle
        // window with a warm table), abandoned batches piled up
        // with no ceiling and `ember_dht_stores_failed` never
        // moved, so acks and failures permanently disagreed.
        && state.ember_batch_publish.in_flight.is_empty()
    {
        return;
    }

    let now = std::time::Instant::now();

    // 1) Expire search queries unanswered too long, marking
    //    their shortlist entry failed.
    let stale: Vec<u32> = state
        .ember_dht_search_requests
        .iter()
        .filter(|(_, r)| now >= r.deadline)
        .map(|(wire_id, _)| *wire_id)
        .collect();

    let mut touched: HashSet<u32> = HashSet::new();
    for wire_id in stale {
        if let Some(req) = state.ember_dht_search_requests.remove(&wire_id) {
            let failed = state
                .ember_search
                .get_mut(req.search_id)
                .and_then(|search| search.mark_failed(req.per_search_req_id));
            // Also hold it against the table, or the same dead lead
            // seeds the next lookup and stalls that one too — but
            // only when the peer has actually gone quiet. A lookup
            // answer can arrive under a request id this sweep is
            // not watching, and a busy peer often replies to
            // something else first.
            if let Some(node_id) = failed {
                let last_seen =
                    state.ember_dht.contact_for(&node_id).map(|c| c.last_seen);
                if ember_ping_timeout_is_a_fault(last_seen, req.sent_unix) {
                    fault_ember_search_contact(state, &node_id);
                }
            }
            touched.insert(req.search_id);
        }
    }

    // 2) Drive every search that had a timeout (send the next
    //    batch and/or resolve it if it has now converged).
    for search_id in touched {
        drive_ember_search(udp_socket, state, search_id).await;
    }

    // 2b) Retire searches that have converged or run past
    //     `SEARCH_TIMEOUT_SECS` without a wire event to notice it.
    //     Completion was only ever re-evaluated on a response, an
    //     expired query, or a dispatched batch, so a walk with
    //     nothing outstanding — every send in its first batch
    //     failed, or its last answer completed it — kept its search
    //     slot until the 120 s backstop below, twice the timeout it
    //     is backstopping. The slot is the scarce part: the cap
    //     counts held searches, not active ones, and background
    //     walkers alone (channel presence starts one a second, plus
    //     source lookups and bucket refreshes) can hold all 64 while
    //     most are already done, which then refuses the user's own
    //     search. Placed before the backstop so a reaped search is
    //     still streamed and emitted by steps 7 and 8 in this tick.
    for search_id in state.ember_search.active_ids() {
        maybe_finish_ember_search(state, search_id);
    }

    // 3) Backstop: reap searches the SearchManager considers
    //    long-expired and fail their still-waiting callers so
    //    no Tauri command hangs past the overall timeout. A
    //    given id is either a node- or value-lookup; draining
    //    both maps resolves whichever waiter exists.
    for search in state.ember_search.cleanup_expired() {
        record_ember_find_value_quality(&mut state.ember_diagnostics, &search);
        release_ember_search_state(state, app_handle, search.id);
    }

    // 4) Same lifecycle for publishes: expire unanswered
    //    STOREs (mark the target failed), drive the affected
    //    publishes, then backstop-reap long-expired ones.
    let stale_pubs: Vec<u32> = state
        .ember_dht_publish_requests
        .iter()
        .filter(|(_, r)| now >= r.deadline)
        .map(|(wire_id, _)| *wire_id)
        .collect();

    let mut touched_pubs: HashSet<u32> = HashSet::new();
    for wire_id in stale_pubs {
        if let Some(req) = state.ember_dht_publish_requests.remove(&wire_id) {
            if let Some(op) = state.ember_publish.get_mut(req.publish_id) {
                op.mark_failed(req.per_pub_req_id);
            }
            touched_pubs.insert(req.publish_id);
        }
    }

    for publish_id in touched_pubs {
        maybe_finish_ember_publish(state, publish_id);
    }

    for publish_id in state.ember_publish.cleanup_expired() {
        if let Some(tx) = state.ember_dht_pending_publishes.remove(&publish_id) {
            let _ = tx.send(EmberPublishResult { stored_on: 0, targets: 0 });
        }
        state
            .ember_dht_publish_requests
            .retain(|_, r| r.publish_id != publish_id);
    }

    // 5) Maintenance liveness pings: a PONG would have cleared
    //    the pending entry, so anything left past its deadline is
    //    an unanswered query. Count a failure against the
    //    contact and evict it once it has missed
    //    `MAX_FAILED_QUERIES` in a row.
    let expired: Vec<(u32, ember::dht::EmberNodeId, i64)> = state
        .ember_dht_maint_pings
        .iter()
        .filter(|(_, ping)| now > ping.deadline)
        .map(|(wire_id, ping)| (*wire_id, ping.node_id, ping.sent_unix))
        .collect();

    for (wire_id, node_id, sent_unix) in expired {
        state.ember_dht_maint_pings.remove(&wire_id);
        // A missing PONG is not evidence of a dead peer if the
        // peer has spoken to us since we asked. Every signed frame
        // refreshes `last_seen`, so a contact answering our
        // FIND_NODE, storing a record, or gossiping a PEER_LIST is
        // demonstrably alive — and only the PONG's own request id
        // clears this entry, so its reply arriving under any other
        // message type left the entry to expire and charged a
        // strike against a live contact. Three of those evict it.
        let last_seen = state.ember_dht.contact_for(&node_id).map(|c| c.last_seen);
        if !ember_ping_timeout_is_a_fault(last_seen, sent_unix) {
            continue;
        }
        // Silence is also the answer to "was this lead real?", so
        // it is charged to whoever named it. Only reached when the
        // peer has said nothing since we asked — a lead that spoke
        // was already credited where its frame arrived.
        state.ember_gossip_reputation.note_silent(&node_id);
        fault_ember_contact(state, &node_id, "unresponsive");
    }

    // Batches whose ack never arrived: forget them so the map
    // stays bounded. The files they carried were never marked
    // published, so the next tick retries them — but count the
    // records, or the acked/failed pair on the diagnostics page
    // would show acks with no matching failures.
    //
    // This is also the only place a publish is *known* to have
    // reached the wire and failed, so it is where the backoff is
    // charged. Charging at selection instead penalised files whose
    // records the flush had discarded before sending.
    let abandoned = state.ember_batch_publish.expire(now);
    if !abandoned.is_empty() {
        state.ember_diagnostics.ember_dht_stores_failed = state
            .ember_diagnostics
            .ember_dht_stores_failed
            .saturating_add(abandoned.len() as u32);
        for reference in abandoned {
            note_ember_store_attempt_failed(state, reference, now);
        }
    }

    // 6) Inject sources discovered by completed download source
    //    lookups (slice 9). Completion is detected synchronously
    //    in `maybe_finish_ember_search`, which buffers the parsed
    //    sources here for the async injection below.
    if !state.ember_pending_source_injections.is_empty() {
        let entries = std::mem::take(&mut state.ember_pending_source_injections);
        let we_are_unreachable = ember_tcp_firewalled(state);

        // Firewalled records that name a usable buddy, when we can
        // accept a TCP connect-back, take the Ember CALLBACK_REQ
        // path instead of being parked as LowToLowIp. An unusable
        // or unendorsed buddy falls through to the park path rather
        // than dropping the source — FIREWALLED exempts the record
        // from the storer's sender-IP bind, so an endpoint the
        // buddy did not sign for is a reflection target, not a
        // route.
        let mut epx_entries: Vec<([u8; 16], Vec<(Ipv4Addr, u16, u16, u8)>)> =
            Vec::new();
        let mut callback_jobs: Vec<([u8; 16], ember::dht::publish::DiscoveredSource)> =
            Vec::new();
        let now_ts = chrono::Utc::now().timestamp();
        for (fh, sources) in &entries {
            let mut rest = Vec::new();
            for src in sources {
                let buddy_blocked_or_banned = src.buddy.is_some_and(|b| {
                    state.banned_ips.contains(&b.ip)
                        || state.ip_filter.is_blocked(b.ip)
                });
                // The endorsement is signed under a key the
                // publisher supplies, so it names nobody on its
                // own. Require a contact we have actually heard
                // from to hold this address and these keys.
                let buddy_corroborated = src
                    .buddy
                    .is_some_and(|b| state.ember_dht.buddy_endpoint_corroborated(&b));
                if ember_source_uses_callback(
                    src,
                    we_are_unreachable,
                    buddy_blocked_or_banned,
                    buddy_corroborated,
                    now_ts,
                ) {
                    callback_jobs.push((*fh, *src));
                } else {
                    if src.buddy.is_some_and(|b| {
                        !b.endorsement_covers(&src.publisher_id, now_ts)
                    }) {
                        state.ember_diagnostics.ember_dht_buddy_unendorsed = state
                            .ember_diagnostics
                            .ember_dht_buddy_unendorsed
                            .saturating_add(1);
                    } else if !buddy_corroborated && src.buddy.is_some() {
                        // Endorsement is well-formed but the named
                        // identity is not one we have met at that
                        // endpoint. Parked, and retried on the
                        // reask cadence once it verifies.
                        state.ember_diagnostics.ember_dht_buddy_uncorroborated = state
                            .ember_diagnostics
                            .ember_dht_buddy_uncorroborated
                            .saturating_add(1);
                    }
                    rest.push((src.ip, src.tcp_port, src.udp_port, src.flags));
                }
            }
            if !rest.is_empty() {
                epx_entries.push((*fh, rest));
            }
        }

        // (a) Record every discovered source in the source manager.
        //     This is what lets a *pending* no-seed download (started
        //     purely by ed2k hash) get promoted below — there is no
        //     server/KAD here to drive promotion — and it stores the
        //     connect options so the eventual c2c dial can obfuscate
        //     when the source advertised it. The DHT record's IP is
        //     already bound to the publisher's observed sender IP by
        //     the storer's anti-reflection check, so a forged
        //     third-party/special-use address can't reach us here.
        {
            let mut sm = source_manager.write().await;
            for (fh, sources) in &entries {
                for src in sources {
                    if state.ip_filter.is_blocked(src.ip)
                        || state.banned_ips.contains(&src.ip)
                    {
                        continue;
                    }
                    // Firewalled records are reached by CALLBACK_REQ
                    // or parked as LowToLowIp. SourceManager has no
                    // firewalled bit, so registering the claimed NAT
                    // IP would let pending promotion TCP-dial it.
                    if !ember_source_is_sm_dialable(src) {
                        continue;
                    }
                    let connect_options =
                        if src.flags & ember::SOURCE_FLAG_OBFUSCATION != 0 {
                            0x02
                        } else {
                            0
                        };
                    sm.register_source_full_opts(
                        *fh,
                        src.ip,
                        src.tcp_port,
                        src.udp_port,
                        src.user_hash.unwrap_or([0u8; 16]),
                        connect_options,
                        Some(crate::types::SourceOrigin::Ember),
                    );
                }
            }
        }

        // (b) Inject HighID / uncallable-firewalled sources into
        //     already-active transfers. Reuses the EPX/KAD ingest.
        if !epx_entries.is_empty() {
            handle_epx_sources(
                state,
                transfer_manager,
                source_manager,
                local_index,
                &epx_entries,
                &[],
                &[],
                &[],
                // Our own DHT lookup results, not a peer's forward.
                None,
                "ember-dht",
                true,
                we_are_unreachable,
            )
            .await;
        }

        // (b2) Firewalled sources with a signed buddy: park as
        //      WaitCallbackKad and send CALLBACK_REQ.
        if !callback_jobs.is_empty() {
            let crypt_options = if settings.obfuscation_enabled {
                0x03
            } else {
                0
            };
            let searcher_tcp = advertised_tcp_port(state);
            let searcher_uh = state.user_hash;
            let mut callback_tids: Vec<String> = Vec::new();
            for (fh, src) in callback_jobs {
                let Some(buddy) = src.buddy else {
                    continue;
                };
                if buddy.udp_port == 0
                    || state.ip_filter.is_blocked(buddy.ip)
                    || state.banned_ips.contains(&buddy.ip)
                    || crate::security::is_special_use_v4(buddy.ip)
                {
                    continue;
                }
                // Same defence-in-depth as the address checks
                // above: the selection loop already required it,
                // but nothing may open a handshake to an endpoint
                // its owner did not sign for. Both halves are
                // re-checked — the endorsement proves the trailer
                // was not tampered with after signing, and the
                // corroboration proves the signing key belongs to
                // a node we have actually reached at this address
                // rather than one the publisher minted.
                if !buddy.endorsement_covers(&src.publisher_id, now_ts)
                    || !state.ember_dht.buddy_endpoint_corroborated(&buddy)
                {
                    continue;
                }
                // Infallible once the endorsement verified — the
                // key had to decompress for that.
                let Some(buddy_id) = buddy.node_id() else {
                    continue;
                };
                if src.publisher_id == [0u8; 16] {
                    continue;
                }
                let Some(token) = src.callback_token.filter(|t| *t != [0u8; 16]) else {
                    continue;
                };
                let matching_ids = {
                    let mgr = transfer_manager.read().await;
                    let hash_hex = hex::encode(fh);
                    let mut ids = matching_active_transfer_ids_for_hash(
                        state, &mgr, &hash_hex,
                    );
                    for (tid, pd) in &state.pending_downloads {
                        if pd.file_hash == hash_hex && !ids.contains(tid) {
                            ids.push(tid.clone());
                        }
                    }
                    ids
                };
                for tid in &matching_ids {
                    let pfs = state.per_file_sources.entry(tid.clone()).or_insert_with(
                        || ed2k::sources::PerFileSourceList::new(fh),
                    );
                    let added = pfs.add_source_with_identity(
                        src.ip,
                        src.tcp_port,
                        src.udp_port,
                        src.user_hash,
                    );
                    pfs.set_ember_callback_buddy(
                        src.ip,
                        src.tcp_port,
                        buddy.ip,
                        buddy.udp_port,
                        buddy.noise_pub,
                        buddy_id,
                        src.publisher_id,
                        src.user_hash,
                        src.callback_token,
                        buddy.endorsed_until,
                        added,
                    );
                }
                if matching_ids.is_empty() {
                    continue;
                }
                {
                    let mut mgr = transfer_manager.write().await;
                    let now_ts = chrono::Utc::now().timestamp();
                    for tid in &matching_ids {
                        let ip_s = upload_server::kad_callback_display_key(
                            src.ip,
                            src.user_hash,
                        );
                        if !mgr.has_source_detail_for_ip(tid, &ip_s) {
                            mgr.update_source_detail(
                                tid,
                                crate::types::SourceInfo {
                                    ip: ip_s.clone(),
                                    port: src.tcp_port,
                                    status: crate::types::SourceStatus::WaitCallback,
                                    queue_rank: None,
                                    speed: 0,
                                    transferred: 0,
                                    client_software: String::new(),
                                    peer_name: String::new(),
                                    available_parts: None,
                                    total_parts: None,
                                    country_code: crate::geoip::lookup_country(
                                        geoip,
                                        std::net::IpAddr::V4(src.ip),
                                    ),
                                    user_hash: src.user_hash,
                                    origin: Some(crate::types::SourceOrigin::Ember),
                                    placeholder: true,
                                },
                            );
                        }
                        state.callback_row_pending_since.insert(
                            (tid.clone(), ip_s, src.tcp_port),
                            now_ts,
                        );
                        if !callback_tids.contains(tid) {
                            callback_tids.push(tid.clone());
                        }
                    }
                }
                if send_ember_callback_req(
                    udp_socket,
                    state,
                    buddy.ip,
                    buddy.udp_port,
                    buddy.noise_pub,
                    buddy_id,
                    ember::dht::EmberNodeId(src.publisher_id),
                    fh,
                    searcher_tcp,
                    crypt_options,
                    searcher_uh,
                    token,
                )
                .await
                {
                    for tid in &matching_ids {
                        if let Some(pfs) = state.per_file_sources.get_mut(tid) {
                            pfs.mark_callback_requested(
                                src.ip,
                                src.tcp_port,
                                src.user_hash,
                            );
                        }
                    }
                    register_or_refresh_pending_kad_callback(
                        pending_kad_callbacks,
                        src.ip,
                        src.tcp_port,
                        fh,
                        src.user_hash,
                        crate::types::SourceOrigin::Ember,
                    )
                    .await;
                    info!(
                        "Sent Ember CALLBACK_REQ to buddy {}:{} for source {}:{} file {}",
                        buddy.ip,
                        buddy.udp_port,
                        src.ip,
                        src.tcp_port,
                        hex::encode(fh),
                    );
                }
            }
            for tid in callback_tids {
                let _ = app_handle.emit(
                    "transfer:sources-updated",
                    serde_json::json!({ "transfer_id": tid }),
                );
            }
        }

        // (c) Promote any pending no-seed download for these hashes
        //     now that a live source exists for it.
        let pending_tids: Vec<String> = {
            let mut tids: Vec<String> = Vec::new();
            for (fh, _) in &entries {
                let hash_hex = hex::encode(fh);
                for (tid, pd) in &state.pending_downloads {
                    if pd.file_hash == hash_hex && !tids.contains(tid) {
                        tids.push(tid.clone());
                    }
                }
            }
            tids
        };
        for tid in pending_tids {
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
            )
            .await;
        }
    }

    drain_ember_callback_connects(state, connect_serve_tx).await;

    // 7) Stream keyword hits out of lookups that are still walking.
    //    `FIND_VALUE` is deliberately excluded from early
    //    convergence, so a lookup on a cold table can run most of
    //    the 60-second cap; buffering until it converged meant the
    //    user watched KAD rows land with nothing from Ember until
    //    the very end. Cadence matches the KAD path: the first
    //    record goes out at once, then every 20.
    if !state.ember_keyword_searches.is_empty() {
        let search_ids: Vec<u32> =
            state.ember_keyword_searches.keys().copied().collect();
        for search_id in search_ids {
            let Some((gathered, nodes_contacted)) = state
                .ember_search
                .get(search_id)
                .map(|s| (s.results.len(), s.queried_count()))
            else {
                continue;
            };
            let Some(cursor) = state
                .ember_keyword_searches
                .get(&search_id)
                .map(|kw| kw.last_streamed_count)
            else {
                continue;
            };
            // Progress first, and on every tick rather than only
            // when a batch is due: an Ember-only search on a cold
            // table can walk most of the 60-second cap before its
            // first record, and the search page's spinner has
            // nothing else to say during it. KAD reports this from
            // its own sweep, so Ember-only searches were the one
            // case that showed a bare spinner.
            if let Some(kw) = state.ember_keyword_searches.get(&search_id) {
                let _ = app_handle.emit(
                    "search-progress",
                    SearchProgressEvent {
                        request_id: kw.request_id,
                        nodes_contacted,
                        results_so_far: kw.streamed_files.len(),
                        // The same two labels KAD's phases carry, so
                        // the page's existing strings cover this
                        // without a phase vocabulary of its own.
                        // Ember runs one combined walk, so the
                        // distinction is "has anything come back
                        // yet" rather than a state machine.
                        phase: if gathered == 0 { "Lookup" } else { "Fetch" }
                            .to_string(),
                    },
                );
            }
            let threshold = if cursor == 0 { 1 } else { 20 };
            if gathered < cursor + threshold {
                continue;
            }
            let Some(records) = state.ember_search.get(search_id).map(|s| {
                s.results[cursor..]
                    .iter()
                    .map(|r| r.data.clone())
                    .collect::<Vec<_>>()
            }) else {
                continue;
            };
            let Some(kw) = state.ember_keyword_searches.get_mut(&search_id) else {
                continue;
            };
            // Advanced even when the rows below all fail the query
            // filter: those records have been considered, and not
            // moving the cursor would re-examine them every tick.
            kw.last_streamed_count = gathered;
            let built = build_ember_keyword_built(
                &records,
                &kw.keywords,
                kw.query_expr.as_ref(),
            );
            for row in &built.results {
                kw.streamed_files.insert(row.file.hash.clone());
            }
            // Streamed pages deliberately do not seed the enforced
            // digest map. Corroboration is computed per batch, so a
            // slice holding two early publishers "agrees" on a digest
            // the finished walk may well contradict — and the closing
            // batch below re-derives every plurality across *all*
            // records anyway. Pinning here only risked enforcing the
            // partial answer, which fails completion for good.
            let batch = EmberKeywordResultBatch {
                request_id: kw.request_id,
                results: built.results,
                keywords: kw.keywords.clone(),
                file_type_filter: kw.file_type_filter.clone(),
                min_size: kw.min_size,
                max_size: kw.max_size,
                file_extension: kw.file_extension.clone(),
                min_availability: kw.min_availability,
                final_batch: false,
            };
            if batch.results.is_empty() {
                continue;
            }
            state.ember_pending_keyword_results.push(batch);
        }
    }

    // 8) Emit keyword search results gathered by Ember DHT keyword
    //    lookups (slice 10) — the streamed batches queued above and
    //    the closing one queued by `maybe_finish_ember_search`.
    //    Emitting needs the async enrich pipeline + app_handle, so
    //    batches are buffered and drained here. Only the final
    //    batch clears its request's `ember_pending` and re-checks
    //    `search-complete`, so results always precede completion.
    if !state.ember_pending_keyword_results.is_empty() {
        let batches = std::mem::take(&mut state.ember_pending_keyword_results);
        for batch in batches {
            let EmberKeywordResultBatch {
                request_id,
                keywords,
                file_type_filter,
                min_size,
                max_size,
                file_extension,
                min_availability,
                mut results,
                final_batch,
            } = batch;
            // A hash KAD or a server already streamed arrives as an
            // availability update rather than a second row for the
            // same file.
            let resights = dedup_streamed_batch(
                &mut state.active_search_request,
                request_id,
                &mut results,
            );
            // The closing batch is rebuilt from every record the walk
            // gathered (see `maybe_finish_ember_search`), so it is
            // the total rather than an addition to it.
            let batch_kind = if final_batch {
                DhtBatchKind::Cumulative
            } else {
                DhtBatchKind::Incremental
            };
            if !results.is_empty() {
                let mut batch_spam = take_search_batch_spam(state, request_id);
                let mut emitted = enrich_and_emit_search_results(
                    app_handle,
                    spam_filter,
                    comment_manager,
                    settings,
                    request_id,
                    results,
                    &file_type_filter,
                    min_size,
                    max_size,
                    file_extension.as_deref(),
                    min_availability,
                    &keywords,
                    None,
                    Some(&mut batch_spam),
                )
                .await;
                store_search_batch_spam(state, request_id, batch_spam);
                if let Some(active) = state.active_search_request.as_mut() {
                    if active.request_id == request_id {
                        mark_streamed_hashes(active, &emitted);
                        note_dht_availability(active, &mut emitted, batch_kind);
                    }
                }
            }
            if !resights.is_empty() {
                if let Some(active) = state.active_search_request.as_mut() {
                    if active.request_id == request_id {
                        let mut resights = resights;
                        note_dht_availability(active, &mut resights, batch_kind);
                        // Ember origins never advance the ed2k stop
                        // counter, so nothing is skipped here.
                        let no_skip = HashSet::new();
                        emit_search_resight_updates(
                            app_handle,
                            request_id,
                            resights,
                            active,
                            &no_skip,
                        );
                    }
                }
            }
            if final_batch {
                if let Some(active) = state.active_search_request.as_mut() {
                    if active.request_id == request_id {
                        active.ember_pending = false;
                    }
                }
                maybe_finish_active_search(state, app_handle, request_id);
            }
        }
    }
    if !state.ember_pending_channel_presence.is_empty() {
        let pending = std::mem::take(&mut state.ember_pending_channel_presence);
        let mut any_new = false;
        let mut updated_ids = HashSet::new();
        for (channel_id, records) in pending {
            let ingest = ingest_channel_presence_records(
                state,
                db,
                &ed25519_pubkey,
                channel_id,
                &records,
            );
            if ingest.new_neighbors {
                any_new = true;
                // Members we did not know a moment ago, who
                // therefore do not know us either. Clearing the
                // stamp beats at them on the next tick instead of
                // leaving both sides to wait out the interval —
                // which is the whole of the join case, since a
                // joiner has nobody to announce to until this walk
                // tells them who is there.
                state.channel_beacon_beat_at.remove(&channel_id);
            }
            if ingest.roster_changed {
                updated_ids.insert(hex::encode(channel_id));
            }
        }
        if any_new {
            // New XOR neighbors: re-register channel capabilities
            // without waiting out the friend heartbeat.
            state.rendezvous_last_register = None;
            drain_channel_origin_retry(udp_socket, state, db).await;
        }
        for channel_id in updated_ids {
            let _ = app_handle.emit(
                "ember:channel-members",
                serde_json::json!({ "channel_id": channel_id }),
            );
        }
    }
    if !state.ember_pending_channel_moderation.is_empty() {
        let pending = std::mem::take(&mut state.ember_pending_channel_moderation);
        let checked_at = chrono::Utc::now().timestamp();
        for (channel_id, records, answered) in pending {
            // Only a search some peer actually answered counts as
            // having looked. Finding no owner record because nobody
            // replied is not evidence the owner has gone, and
            // succession is the one feature that acts on absence.
            if answered > 0 {
                let _ = db.touch_channel_moderation_checked(
                    &hex::encode(channel_id),
                    checked_at,
                );
            }
            if ingest_channel_moderation_records(db, channel_id, &records) {
                // The snapshot carries the owner's whole ban list, so
                // this is where most bans actually land on a member's
                // device — and a ban has to reach the transfer engine
                // and not just the roster.
                drop_banned_channel_transfers(
                    state,
                    db,
                    app_handle,
                    channel_id,
                );
                let _ = app_handle.emit(
                    "ember:channel-moderation",
                    serde_json::json!({ "channel_id": hex::encode(channel_id) }),
                );
            }
        }
    }
    if !state.ember_pending_channel_claim.is_empty() {
        let pending = std::mem::take(&mut state.ember_pending_channel_claim);
        for (channel_id, records) in pending {
            if let Some(successor_id) =
                ingest_channel_claim_records(db, channel_id, &records)
            {
                let _ = app_handle.emit(
                    "ember:channel-handoff",
                    serde_json::json!({
                        "channel_id": hex::encode(channel_id),
                        "successor_id": hex::encode(successor_id),
                        "phase": "claimed",
                    }),
                );
            }
        }
    }
    if !state.ember_pending_channel_epoch.is_empty() {
        let pending = std::mem::take(&mut state.ember_pending_channel_epoch);
        for (channel_id, epoch, records) in pending {
            if ingest_channel_epoch_records(db, identity, channel_id, epoch, &records)
            {
                // The room is readable again, so the list's badges
                // and the composer state want refreshing.
                let _ = app_handle.emit(
                    "ember:channel-moderation",
                    serde_json::json!({ "channel_id": hex::encode(channel_id) }),
                );
            }
        }
    }
    if !state.ember_pending_channel_handoff.is_empty() {
        let pending = std::mem::take(&mut state.ember_pending_channel_handoff);
        for (channel_id, records) in pending {
            if let Some(successor_id) =
                ingest_channel_handoff_records(db, channel_id, &records)
            {
                let _ = app_handle.emit(
                    "ember:channel-handoff",
                    serde_json::json!({
                        "channel_id": hex::encode(channel_id),
                        "successor_id": hex::encode(successor_id),
                        "phase": "followed",
                    }),
                );
            }
        }
    }
}
