//! The source retry tick: refreshes the inbound reconnect index, expires
//! KAD-callback placeholders, asks the server, KAD and UDP for more sources,
//! and holds back downloads short of disk space.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_source_retry_tick(
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
    stats_manager: &mut StatsManager,
    shared_banned_ips: &upload_server::SharedBannedIps,
    shared_ember_payload: &ember::SharedEmberPayload,
    ember_payload_generation: &ember::EmberPayloadGeneration,
    geoip: &crate::geoip::GeoIpReader,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    ember_hash: [u8; 16],
    ed25519_pubkey: [u8; 32],
    ed25519_secret_key: [u8; 32],
    a4af_shared: &Arc<RwLock<A4AFManager>>,
    pending_kad_callbacks: &upload_server::PendingKadCallbacks,
    pending_lowid_callback_queue: &mut VecDeque<([u8; 16], u32)>,
    transfer_status_writes: &Arc<TransferStatusWriteClock>,
) {
    let now = chrono::Utc::now().timestamp();
    let kad_available = kad_ready_for_sources(state);
    let server_connected = state.server_connected;

    // Path B: refresh the inbound reconnect index from the current
    // OnQueue source set of live downloads, so an uploader that
    // connects back to grant a slot (HighID push-grant) is
    // recognised on the upload path and its stream diverted into
    // the waiting download. Rebuilt wholesale each tick (~5s) so
    // stale entries self-heal. See `upload_server::ReconnectIndex`.
    {
        let mut idx_map = upload_server::ReconnectIndex::new();
        for (tid, pfs) in &state.per_file_sources {
            let is_live = state.pending_downloads.contains_key(tid)
                || state.active_source_senders.contains_key(tid);
            if !is_live {
                continue;
            }
            for src in &pfs.sources {
                if matches!(
                    src.state,
                    ed2k::sources::DownloadSourceState::OnQueue { .. }
                ) {
                    idx_map
                        .entry(src.ip)
                        .or_default()
                        .push((
                            pfs.file_hash,
                            upload_server::reconnect_user_hash(src.source_user_hash),
                        ));
                }
            }
        }
        if let Ok(mut guard) = upload_server::reconnect_index().write() {
            *guard = idx_map;
        }
    }

    // Expire stale KAD-callback placeholder rows. A placeholder
    // sits in `Connecting` state until either (a) the LowID
    // peer calls back and the `SourceDetail` handler removes
    // it, or (b) this timeout fires because the peer's buddy
    // never relayed our CallbackReq (most common outcome —
    // buddies only relay callbacks for peers currently
    // connected to them, which is a small fraction).
    // Without this sweep the UI accumulates "forever-
    // Connecting" rows and the user rightly wonders why
    // nothing ever transitions. The next KAD source search
    // for this transfer (~30-60s cadence) will re-insert the
    // row if the peer is still in results, producing a
    // visible "still trying" rhythm instead of stale rows.
    {
        let expired_keys: Vec<(String, String, u16)> = state
            .callback_row_pending_since
            .iter()
            .filter(|(_, &since)| now - since >= KAD_CALLBACK_PLACEHOLDER_TIMEOUT_SECS)
            .map(|(k, _)| k.clone())
            .collect();
        if !expired_keys.is_empty() {
            let removed_rows: Vec<(String, String, u16)> = {
                let mut mgr = transfer_manager.write().await;
                let mut out = Vec::new();
                for (tid, ip, port) in &expired_keys {
                    if mgr.remove_placeholder_row(tid, ip, *port) {
                        out.push((tid.clone(), ip.clone(), *port));
                    }
                }
                out
            };
            for (tid, ip, port) in &removed_rows {
                let _ = app_handle.emit(
                    "transfer-source-detail",
                    serde_json::json!({
                        "transfer_id": tid,
                        "ip": ip,
                        "port": port,
                        "status": "failed",
                        "queue_rank": null,
                        "speed": 0,
                        "transferred": 0,
                        "client_software": "",
                        "peer_name": "",
                        "available_parts": null,
                        "total_parts": null,
                        "country_code": null,
                    }),
                );
            }
            // Drop timestamp entries for all expired keys —
            // whether we actually removed a row (placeholder
            // was still there) or the row had already
            // transitioned to a real peer state in the
            // interval between our snapshot and the write
            // lock. In both cases the timestamp no longer
            // tracks a live placeholder.
            for key in &expired_keys {
                state.callback_row_pending_since.remove(key);
            }
        }
    }

    // eMule-style: re-send KAD CallbackReq on the short callback
    // cadence (KAD_CALLBACK_REASK_SECS) for sources still in
    // WaitCallbackKad state that haven't connected back yet.
    if kad_available {
        struct KadCallbackReaskJob {
            transfer_id: String,
            file_hash: [u8; 16],
            src_ip: Ipv4Addr,
            src_port: u16,
            buddy_ip: Ipv4Addr,
            buddy_port: u16,
            buddy_hash: KadId,
            user_hash: Option<[u8; 16]>,
            /// Chooses which candidate buddy port this try uses; see
            /// `kad_callback_buddy_port`.
            attempt: u32,
        }
        let mut reask_jobs: Vec<KadCallbackReaskJob> = Vec::new();
        for (tid, pfs) in &state.per_file_sources {
            let is_live = state.pending_downloads.contains_key(tid)
                || state.active_source_senders.contains_key(tid);
            if !is_live {
                continue;
            }
            for src in &pfs.sources {
                if !src.kad_callback_reask_due() {
                    continue;
                }
                let (Some(buddy_ip), Some(buddy_port), Some(buddy_hash)) = (
                    src.callback_buddy_ip,
                    src.callback_buddy_port,
                    src.callback_buddy_hash,
                ) else {
                    continue;
                };
                reask_jobs.push(KadCallbackReaskJob {
                    transfer_id: tid.clone(),
                    file_hash: pfs.file_hash,
                    src_ip: src.ip,
                    src_port: src.tcp_port,
                    buddy_ip,
                    buddy_port,
                    buddy_hash: KadId(buddy_hash),
                    user_hash: src.source_user_hash,
                    attempt: src.callback_reasks_sent,
                });
            }
        }
        for job in reask_jobs {
            if send_kad_callback_req(
                udp_socket,
                state,
                job.buddy_ip,
                job.buddy_port,
                job.buddy_hash,
                job.file_hash,
                job.attempt,
            ).await {
                if let Some(pfs) = state.per_file_sources.get_mut(&job.transfer_id) {
                    pfs.mark_callback_requested(job.src_ip, job.src_port, job.user_hash);
                }
                register_or_refresh_pending_kad_callback(
                    pending_kad_callbacks,
                    job.src_ip,
                    job.src_port,
                    job.file_hash,
                    job.user_hash,
                    // Only KAD answers carry a KAD buddy.
                    crate::types::SourceOrigin::Kad,
                ).await;
                let ip_s = upload_server::kad_callback_display_key(job.src_ip, job.user_hash);
                state.callback_row_pending_since.insert(
                    (job.transfer_id.clone(), ip_s, job.src_port),
                    now,
                );
                info!(
                    "Re-sent KAD CallbackReq to buddy {} for source {}:{} file {}",
                    job.buddy_hash,
                    job.src_ip,
                    job.src_port,
                    hex::encode(job.file_hash),
                );
            }
        }
    }

    // Ember CALLBACK_REQ reask: independent of KAD. Same short
    // cadence as KAD so a lost Noise frame is retried promptly.
    {
        struct EmberCallbackReaskJob {
            transfer_id: String,
            file_hash: [u8; 16],
            src_ip: Ipv4Addr,
            src_port: u16,
            buddy_ip: Ipv4Addr,
            buddy_port: u16,
            buddy_noise: [u8; 32],
            buddy_node_id: [u8; 16],
            publisher_id: [u8; 16],
            callback_token: [u8; 16],
            user_hash: Option<[u8; 16]>,
        }
        let mut reask_jobs: Vec<EmberCallbackReaskJob> = Vec::new();
        let reask_now_ts = chrono::Utc::now().timestamp();
        for (tid, pfs) in &state.per_file_sources {
            let is_live = state.pending_downloads.contains_key(tid)
                || state.active_source_senders.contains_key(tid);
            if !is_live {
                continue;
            }
            for src in &pfs.sources {
                if !src.ember_callback_reask_due(reask_now_ts) {
                    continue;
                }
                let (Some(buddy_ip), Some(buddy_port), Some(buddy_noise), Some(buddy_node_id), Some(publisher_id), Some(callback_token)) = (
                    src.callback_buddy_ip,
                    src.callback_buddy_port,
                    src.callback_ember_buddy_noise,
                    src.callback_ember_buddy_id,
                    src.callback_ember_publisher,
                    src.callback_ember_token,
                ) else {
                    continue;
                };
                // Re-check the endpoint against the routing table on
                // every reask, not just at ingest. The stored
                // address is a firewalled publisher's claim, and a
                // contact can go stale or change address between
                // reasks — the initial dial's corroboration does not
                // carry forward. Matching on the persisted node ID
                // implies the Ed25519 key, since routing admission
                // enforces `node_id == BLAKE3(pubkey)[..16]`.
                let corroborated = state
                    .ember_dht
                    .contact_for(&ember::dht::EmberNodeId(buddy_node_id))
                    .is_some_and(|c| {
                        c.is_verified()
                            && c.addr
                                == SocketAddr::new(
                                    IpAddr::V4(buddy_ip),
                                    buddy_port,
                                )
                            && c.noise_pub == buddy_noise
                    });
                if !corroborated {
                    continue;
                }
                reask_jobs.push(EmberCallbackReaskJob {
                    transfer_id: tid.clone(),
                    file_hash: pfs.file_hash,
                    src_ip: src.ip,
                    src_port: src.tcp_port,
                    buddy_ip,
                    buddy_port,
                    buddy_noise,
                    buddy_node_id,
                    publisher_id,
                    callback_token,
                    user_hash: src.source_user_hash,
                });
            }
        }
        if !reask_jobs.is_empty() {
            let crypt_options = if settings.obfuscation_enabled {
                0x03
            } else {
                0
            };
            let searcher_tcp = advertised_tcp_port(state);
            let searcher_uh = state.user_hash;
            for job in reask_jobs {
                if send_ember_callback_req(
                    udp_socket,
                    state,
                    job.buddy_ip,
                    job.buddy_port,
                    job.buddy_noise,
                    job.buddy_node_id,
                    ember::dht::EmberNodeId(job.publisher_id),
                    job.file_hash,
                    searcher_tcp,
                    crypt_options,
                    searcher_uh,
                    job.callback_token,
                )
                .await
                {
                    if let Some(pfs) = state.per_file_sources.get_mut(&job.transfer_id)
                    {
                        pfs.mark_callback_requested(
                            job.src_ip,
                            job.src_port,
                            job.user_hash,
                        );
                    }
                    register_or_refresh_pending_kad_callback(
                        pending_kad_callbacks,
                        job.src_ip,
                        job.src_port,
                        job.file_hash,
                        job.user_hash,
                        // Only Ember DHT answers carry an Ember buddy.
                        crate::types::SourceOrigin::Ember,
                    )
                    .await;
                    let ip_s = upload_server::kad_callback_display_key(
                        job.src_ip,
                        job.user_hash,
                    );
                    state.callback_row_pending_since.insert(
                        (job.transfer_id.clone(), ip_s, job.src_port),
                        now,
                    );
                }
            }
        }
    }

    // Always process cancellations even when offline.
    {
        let to_cancel: Vec<String> = state.pending_downloads.iter()
            .filter(|(_, pd)| pd.control.is_cancelled())
            .map(|(tid, _)| tid.clone())
            .collect();
        for tid in &to_cancel {
            // Resume/promote cancels the old control and registers a
            // fresh one before StartDownload replaces pending. If a
            // live non-cancelled control already exists, this pending
            // entry is stale — drop it without failing the transfer.
            let live_control_active = {
                let mgr = transfer_manager.read().await;
                mgr.get_control(tid)
                    .is_some_and(|c| !c.is_cancelled())
            };
            if live_control_active {
                if let Some(_pending) = state.pending_downloads.remove(tid) {
                    let stale_sids: Vec<SearchId> = state
                        .download_source_searches
                        .iter()
                        .filter(|(_, (t, _))| t == tid)
                        .map(|(sid, _)| *sid)
                        .collect();
                    for sid in &stale_sids {
                        state.download_source_searches.remove(sid);
                        if let Some(removed) = state.search_manager.remove(sid) {
                            state
                                .routing_table
                                .release_contacts_in_use(&removed.in_use_ids);
                        }
                    }
                }
                continue;
            }
            // Stop/Pause/Insufficient already cancelled the control
            // and removed it from the manager. Prefer those statuses
            // over rewriting the row as Failed ("Cancelled").
            let skip_fail = {
                let mgr = transfer_manager.read().await;
                mgr.get_transfer(tid)
                    .map(|t| {
                        matches!(
                            t.status,
                            TransferStatus::Stopped
                                | TransferStatus::Paused
                                | TransferStatus::Insufficient
                        )
                    })
                    .unwrap_or(false)
            };
            if let Some(_pending) = state.pending_downloads.remove(tid) {
                let stale_sids: Vec<SearchId> = state.download_source_searches.iter()
                    .filter(|(_, (t, _))| t == tid)
                    .map(|(sid, _)| *sid)
                    .collect();
                for sid in &stale_sids {
                    state.download_source_searches.remove(sid);
                    if let Some(removed) = state.search_manager.remove(sid) {
                        state.routing_table.release_contacts_in_use(&removed.in_use_ids);
                    }
                }

                if skip_fail {
                    continue;
                }

                {
                    let mut mgr = transfer_manager.write().await;
                    mgr.update_status(tid, TransferStatus::Failed);
                    mgr.fail(
                        tid,
                        ed2k::transfer::TransferFailureCode::Cancelled,
                        Some("transient".to_string()),
                        Some("cancelled".to_string()),
                    );
                }
                // Offload the DB write so a WAL commit can't stall the
                // event loop, and never hold `transfer_manager` across it.
                spawn_transfer_status_write(
                    transfer_status_writes,
                    db.clone(),
                    tid.clone(),
                    "failed",
                );
                let _ = app_handle.emit("transfer-status", serde_json::json!({
                    "id": tid,
                    "status": "failed",
                    "error": ed2k::transfer::TransferFailureCode::Cancelled.message(),
                    "failure_code": ed2k::transfer::TransferFailureCode::Cancelled.as_code(),
                }));
            }
        }
    }

    // Skip source searches and warm-start dials until KAD is
    // Connected or an eD2k server session exists. `Connecting`
    // (nodes.dat bootstrap) must not count — otherwise restored
    // downloads dial cached HighIDs and fire FindSource/UDP
    // before either network is usable.
    if !network_ready_for_sources(state) {
        return;
    }

    let mut to_retry: Vec<(String, u32)> = Vec::new();
    let mut insufficient_downloads: Vec<(String, String)> = Vec::new();

    let dl_dir = PathBuf::from(&settings.download_folder);
    let is_retry_candidate =
        |pd: &PendingDownload| !pd.control.is_cancelled() && !pd.control.is_paused();
    // Every download in the folder shares one volume, so one cached
    // reading serves the whole tick, including the start paths below.
    let disk_probe = if state.pending_downloads.values().any(is_retry_candidate) {
        DiskSpaceMonitor::global().reading_and_refresh(&dl_dir)
    } else {
        DiskSpaceProbe::Unknown
    };
    {
        let mgr = transfer_manager.read().await;
        for (tid, pd) in &state.pending_downloads {
            if !is_retry_candidate(pd) {
                continue;
            }
            // Bytes on disk only. This used to take
            // `transferred.max(completed_size)`, which was harmless
            // while the two were equal but now overstates progress —
            // `transferred` counts re-fetched bytes and can exceed the
            // file size, so the space still needed would come out too
            // small and let a download start that cannot fit.
            let completed = mgr.get_transfer(tid)
                .map(|t| t.completed_size)
                .unwrap_or(0);
            let needed = remaining_download_bytes(pd.file_size, completed);
            if !disk_space_suffices(disk_probe, &dl_dir, needed) {
                debug!("Skipping source retry for {} ({}): insufficient disk space", tid, pd.file_name);
                insufficient_downloads.push((tid.clone(), pd.file_name.clone()));
                continue;
            }
            let retry_interval = pending_download_retry_interval(pd.search_count);
            if now.saturating_sub(pd.last_search_at) >= retry_interval {
                to_retry.push((tid.clone(), pd.priority));
            }
        }
    }
    for (tid, file_name) in insufficient_downloads {
        state.pending_downloads.remove(&tid);
        let freed = mark_download_insufficient(
            transfer_manager,
            db,
            app_handle,
            &tid,
            &file_name,
            transfer_status_writes,
        )
        .await;
        for t in freed {
            crate::commands::transfers::emit_transfer_status(
                app_handle,
                &t.id,
                &t.status,
            );
            let control = reregister_transfer_control(transfer_manager, &t.id).await;
            insert_pending_download_bounded(&mut state.pending_downloads,
                t.id.clone(),
                PendingDownload {
                    transfer_id: t.id.clone(),
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
            let _ = try_start_pending_download_from_known_sources(
                state,
                &t.id,
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

    // High-priority downloads get processed first
    to_retry.sort_by_key(|entry| std::cmp::Reverse(entry.1));

    // eMule-style: check persistent per-file source lists for sources
    // whose reask timer has expired. These are sources we already know
    // about from previous connection attempts -- much cheaper than a
    // new KAD search.
    let mut started_from_persistent: Vec<String> = Vec::new();
    let a4af_snap = a4af_shared.read().await;
    for (tid, _) in &to_retry {
        if let Some(pfs) = state.per_file_sources.get_mut(tid) {
            pfs.purge_dead_sources();
            let sm_guard = source_manager.read().await;
            let ready = pfs.sources_ready_for_reask_with_reputation(
                |ip, port| {
                    sm_guard.find_user_hash_by_addr(ip, port)
                        .is_some_and(|uh| state.reputation.is_banned(&uh))
                },
                |ip, port| {
                    sm_guard.find_user_hash_by_addr(ip, port)
                        .map_or(0, |uh| state.reputation.score(&uh))
                },
            );
            let file_hash = pfs.file_hash;
            let live: Vec<(String, u16)> = ready
                .into_iter()
                .filter_map(|(ip, port)| sm_guard.remap_dial_target(&file_hash, ip, port))
                .filter(|(ip, port)| {
                    !state.dead_sources.is_dead_source_for_file(
                        &file_hash,
                        u32::from(*ip),
                        *port,
                    )
                })
                .filter(|(ip, port)| {
                    let addr = SocketAddr::new((*ip).into(), *port);
                    !a4af_snap.is_swap_candidate(addr, &file_hash)
                })
                .map(|(ip, port)| (ip.to_string(), port))
                .collect();
            drop(sm_guard);
            if !live.is_empty() {
                debug!(
                    "Persistent source list has {} sources ready for reask for {}",
                    live.len(), tid
                );
                started_from_persistent.push(tid.clone());
            }
        }
    }
    drop(a4af_snap);

    // First pass: check if SourceManager has accumulated sources for
    // any pending download (from server TCP/UDP responses). If so, start
    // the download immediately instead of waiting for a new Kad search.
    let mut started_from_sm: Vec<String> = Vec::new();
    {
        let sm = source_manager.read().await;
        for (tid, _) in &to_retry {
            if started_from_persistent.contains(tid) { continue; }
            if let Some(pd) = state.pending_downloads.get(tid) {
                if let Ok(hash_bytes) = hex::decode(&pd.file_hash) {
                    if hash_bytes.len() == 16 {
                        let mut fh = [0u8; 16];
                        fh.copy_from_slice(&hash_bytes);
                        let sm_sources = sm.get_sources(&fh);
                        let live_sources: Vec<(String, u16)> = sm_sources.into_iter()
                            .filter(|(ip, port)| !state.dead_sources.is_dead_source_for_file(&fh, u32::from(*ip), *port))
                            .map(|(ip, port)| (ip.to_string(), port))
                            .collect();
                        if !live_sources.is_empty() {
                            started_from_sm.push(tid.clone());
                        }
                    }
                }
            }
        }
    }
    // Handle downloads from persistent source list
    for tid in &started_from_persistent {
        if let Some(pending) = state.pending_downloads.remove(tid) {
            let hash_bytes = match hex::decode(&pending.file_hash) {
                Ok(b) if b.len() == 16 => {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(&b);
                    arr
                }
                _ => {
                    insert_pending_download_bounded(&mut state.pending_downloads, tid.clone(), pending);
                    continue;
                }
            };
            let sm_guard2 = source_manager.read().await;
            let a4af_snap = a4af_shared.read().await;
            let ready_sources: Vec<(String, u16)> = state.per_file_sources
                .get(tid)
                .map(|pfs| pfs.sources_ready_for_reask_with_reputation(
                    |ip, port| {
                        sm_guard2.find_user_hash_by_addr(ip, port)
                            .is_some_and(|uh| state.reputation.is_banned(&uh))
                    },
                    |ip, port| {
                        sm_guard2.find_user_hash_by_addr(ip, port)
                            .map_or(0, |uh| state.reputation.score(&uh))
                    },
                ).into_iter()
                    .filter_map(|(ip, port)| {
                        sm_guard2.remap_dial_target(&hash_bytes, ip, port)
                    })
                    .filter(|(ip, port)| !state.dead_sources.is_dead_source_for_file(&hash_bytes, u32::from(*ip), *port))
                    .filter(|(ip, port)| {
                        let addr = SocketAddr::new((*ip).into(), *port);
                        !a4af_snap.is_swap_candidate(addr, &hash_bytes)
                    })
                    .map(|(ip, port)| (ip.to_string(), port))
                    .collect())
                .unwrap_or_default();
            // Captured while the source lock is still held. The row
            // writes below happen under the transfer lock, and the
            // canonical order (transfer before source, see the
            // comment there) forbids reaching back for this then.
            // These sources come from the accumulated per-file pool,
            // so they are a mix of everything that ever found this
            // file — there is no single origin to stamp them with.
            let ready_origins: std::collections::HashMap<(String, u16), crate::types::SourceOrigin> =
                ready_sources
                    .iter()
                    .filter_map(|(ip, port)| {
                        let v4 = ip.parse::<Ipv4Addr>().ok()?;
                        let origin = sm_guard2.get_source_origin(&hash_bytes, v4, *port)?;
                        Some(((ip.clone(), *port), origin))
                    })
                    .collect();
            drop(a4af_snap);
            drop(sm_guard2);
            if ready_sources.is_empty() {
                insert_pending_download_bounded(&mut state.pending_downloads, tid.clone(), pending);
                continue;
            }
            let completed = {
                let mgr = transfer_manager.read().await;
                mgr.get_transfer(tid)
                    .map(|t| t.completed_size)
                    .unwrap_or(0)
            };
            let needed = remaining_download_bytes(pending.file_size, completed);
            if !disk_space_suffices(disk_probe, &dl_dir, needed) {
                warn!("Skipping download {} ({}): insufficient disk space", tid, pending.file_name);
                let freed = mark_download_insufficient(
                    transfer_manager,
                    db,
                    app_handle,
                    tid,
                    &pending.file_name,
                    transfer_status_writes,
                )
                .await;
                for t in freed {
                    crate::commands::transfers::emit_transfer_status(
                        app_handle,
                        &t.id,
                        &t.status,
                    );
                    let control =
                        reregister_transfer_control(transfer_manager, &t.id).await;
                    insert_pending_download_bounded(&mut state.pending_downloads,
                        t.id.clone(),
                        PendingDownload {
                            transfer_id: t.id.clone(),
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
                }
                continue;
            }
            let source_count = ready_sources.len() as u32;
            {
                // Canonical lock order: transfer_manager before
                // source_manager. Every other nested hold in the
                // network loop acquires the transfer lock first;
                // this site is kept consistent so the two locks can
                // never be taken in opposing orders (deadlock-safe).
                let mut mgr = transfer_manager.write().await;
                mgr.update_status(tid, TransferStatus::Active);
                mgr.update_sources(tid, source_count, 0, 0);
                for (ip_s, port) in &ready_sources {
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
                            origin: ready_origins.get(&(ip_s.clone(), *port)).copied(),
                            placeholder: false,
                        },
                    );
                }
            }
            let _ = app_handle.emit("transfer-status", serde_json::json!({
                "id": tid,
                "status": "active",
                "sources": source_count,
                "active_sources": 0,
                "queued_sources": 0,
            }));
            info!("Reasking {} persistent sources for download {}", source_count, tid);
            let download_sources: Vec<DownloadSource> = {
                let sm = source_manager.read().await;
                ready_sources.iter()
                    .map(|(ip, port)| {
                        let uh = ip.parse::<Ipv4Addr>().ok()
                            .and_then(|v4| sm.get_user_hash(&hash_bytes, v4, *port));
                        let co = ip.parse::<Ipv4Addr>().ok()
                            .and_then(|v4| sm.get_connect_options(&hash_bytes, v4, *port));
                        DownloadSource {
                            peer_ip: ip.clone(),
                            peer_port: *port,
                            available_parts: vec![],
                            peer_user_hash: uh,
                            peer_connect_options: co,
                        }
                    })
                    .collect()
            };
            let (new_source_tx, new_source_rx) = mpsc::channel::<DownloadSource>(64);
            let (new_established_tx, new_established_rx) =
                mpsc::channel::<ed2k::multi_source::EstablishedSource>(ESTABLISHED_SOURCE_CHANNEL_CAP);
            state.active_source_senders.insert(tid.clone(), new_source_tx);
            state.active_established_senders.insert(tid.clone(), new_established_tx);
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
                new_source_rx: Some(new_source_rx),
                new_established_rx: Some(new_established_rx),
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
            let tx = dl_event_tx.clone();
            let dl_tid = ms_download.transfer_id.clone();
            let dl_tid2 = dl_tid.clone();
            let tx2 = tx.clone();
            if let Some(old_handle) = state.download_handles.remove(&dl_tid2) {
                old_handle.abort();
            }
            let handle = tokio::spawn(async move {
                if let Err(e) = ms_download.run(tx).await {
                    error!("Persistent source download failed: {e}");
                    let kind = classify_error(&e.to_string());
                    let _ = tx2.send(DownloadEvent::Failed { transfer_id: dl_tid, error: e.to_string(), failure_kind: kind }).await;
                }
            });
            state.download_handles.insert(dl_tid2, handle);
        }
    }

    for tid in &started_from_sm {
        if started_from_persistent.contains(tid) { continue; }
        if let Some(pending) = state.pending_downloads.remove(tid) {
            let hash_bytes = match hex::decode(&pending.file_hash) {
                Ok(b) if b.len() == 16 => {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(&b);
                    arr
                }
                _ => {
                    insert_pending_download_bounded(&mut state.pending_downloads, tid.clone(), pending);
                    continue;
                }
            };
            // Origins are read in the same guard as the addresses:
            // the rows below are written under the transfer lock,
            // and the canonical order forbids taking the source
            // lock underneath it. This is the persistent pool, so
            // each source keeps whichever network found it.
            let (sm_sources, sm_origins) = {
                let sm = source_manager.read().await;
                let sources = sm.get_sources(&hash_bytes);
                let origins: std::collections::HashMap<(String, u16), crate::types::SourceOrigin> =
                    sources
                        .iter()
                        .filter_map(|(ip, port)| {
                            let origin = sm.get_source_origin(&hash_bytes, *ip, *port)?;
                            Some(((ip.to_string(), *port), origin))
                        })
                        .collect();
                (sources, origins)
            };
            let live_sources: Vec<(String, u16)> = sm_sources.into_iter()
                .filter(|(ip, port)| {
                    !state.dead_sources.is_dead_source_for_file(&hash_bytes, u32::from(*ip), *port)
                        && is_source_admissible(state, *ip, *port, None)
                })
                .map(|(ip, port)| (ip.to_string(), port))
                .collect();
            if live_sources.is_empty() {
                insert_pending_download_bounded(&mut state.pending_downloads, tid.clone(), pending);
                continue;
            }
            let completed = {
                let mgr = transfer_manager.read().await;
                mgr.get_transfer(tid)
                    .map(|t| t.completed_size)
                    .unwrap_or(0)
            };
            let needed = remaining_download_bytes(pending.file_size, completed);
            if !disk_space_suffices(disk_probe, &dl_dir, needed) {
                warn!("Skipping download {} ({}): insufficient disk space", tid, pending.file_name);
                let freed = mark_download_insufficient(
                    transfer_manager,
                    db,
                    app_handle,
                    tid,
                    &pending.file_name,
                    transfer_status_writes,
                )
                .await;
                for t in freed {
                    crate::commands::transfers::emit_transfer_status(
                        app_handle,
                        &t.id,
                        &t.status,
                    );
                    let control =
                        reregister_transfer_control(transfer_manager, &t.id).await;
                    insert_pending_download_bounded(&mut state.pending_downloads,
                        t.id.clone(),
                        PendingDownload {
                            transfer_id: t.id.clone(),
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
                }
                continue;
            }
            let source_count = live_sources.len() as u32;
            {
                let mut mgr = transfer_manager.write().await;
                mgr.update_status(tid, TransferStatus::Active);
                mgr.update_sources(tid, source_count, 0, 0);
                for (ip_s, port) in &live_sources {
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
                            origin: sm_origins.get(&(ip_s.clone(), *port)).copied(),
                            placeholder: false,
                        },
                    );
                }
            }
            let _ = app_handle.emit("transfer-status", serde_json::json!({
                "id": tid,
                "status": "active",
                "sources": source_count,
                "active_sources": 0,
                "queued_sources": 0,
            }));
            info!("Starting download {} from {} accumulated sources", tid, source_count);
            {
                let pfs = state.per_file_sources
                    .entry(tid.clone())
                    .or_insert_with(|| ed2k::sources::PerFileSourceList::new(hash_bytes));
                let udp_sources = {
                    let sm = source_manager.read().await;
                    sm.get_udp_sources(&hash_bytes)
                };
                for (ip_s, port) in &live_sources {
                    if let Ok(v4) = ip_s.parse::<Ipv4Addr>() {
                        let udp_port = udp_sources
                            .iter()
                            .find(|(ip, tcp_port, _)| ip == &v4 && tcp_port == port)
                            .map(|(_, _, udp)| *udp)
                            .unwrap_or(0);
                        if pfs.add_source_full(v4, *port, udp_port) {
                            state.ember_payload_dirty = true;
                        }
                    }
                }
            }
            {
                let mut sm = source_manager.write().await;
                for (ip, port) in &live_sources {
                    if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                        sm.register_source(hash_bytes, v4, *port, None);
                    }
                }
            }
            let download_sources: Vec<DownloadSource> = {
                let sm = source_manager.read().await;
                live_sources.iter()
                    .map(|(ip, port)| {
                        let uh = ip.parse::<Ipv4Addr>().ok()
                            .and_then(|v4| sm.get_user_hash(&hash_bytes, v4, *port));
                        let co = ip.parse::<Ipv4Addr>().ok()
                            .and_then(|v4| sm.get_connect_options(&hash_bytes, v4, *port));
                        DownloadSource {
                            peer_ip: ip.clone(),
                            peer_port: *port,
                            available_parts: Vec::new(),
                            peer_user_hash: uh,
                            peer_connect_options: co,
                        }
                    })
                    .collect()
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
            let dl_tid = ms_download.transfer_id.clone();
            let dl_tid2 = dl_tid.clone();
            state.active_source_senders.insert(dl_tid.clone(), src_inject_tx);
            state.active_established_senders.insert(dl_tid.clone(), est_inject_tx);
            let tx = dl_event_tx.clone();
            let tx2 = tx.clone();
            if let Some(old_handle) = state.download_handles.remove(&dl_tid2) {
                old_handle.abort();
            }
            let handle = tokio::spawn(async move {
                if let Err(e) = ms_download.run(tx).await {
                    error!("Multi-source download failed: {e}");
                    let kind = classify_error(&e.to_string());
                    let _ = tx2.send(DownloadEvent::Failed { transfer_id: dl_tid, error: e.to_string(), failure_kind: kind }).await;
                }
            });
            state.download_handles.insert(dl_tid2, handle);
        }
    }

    // Warm-started downloads (resumed this tick from persisted /
    // SourceManager sources) were just removed from
    // `pending_downloads`, so they skip the aggressive *initial*
    // discovery burst that the pending-retry loop below performs
    // (immediate KAD source search + server OP_GETSOURCES). Without
    // this, a resumed download is stuck with only its stale on-disk
    // source set: it never surfaces fresh server sources or new KAD
    // callback sources, and only crawls along on the slow active
    // cadence. eMule always (re)asks the server and KAD for a
    // file's sources when the download starts, regardless of any
    // cached sources — replicate that one-shot kick here.
    {
        let mut warm_started: Vec<String> = started_from_persistent.clone();
        for tid in &started_from_sm {
            if !warm_started.contains(tid) {
                warm_started.push(tid.clone());
            }
        }
        if !warm_started.is_empty() {
            let targets: Vec<(String, [u8; 16], u64)> = {
                let mgr = transfer_manager.read().await;
                warm_started
                    .iter()
                    .filter_map(|tid| {
                        let t = mgr.get_transfer(tid)?;
                        let raw = hex::decode(&t.file_hash).ok()?;
                        if raw.len() != 16 {
                            return None;
                        }
                        let mut fh = [0u8; 16];
                        fh.copy_from_slice(&raw[..16]);
                        Some((tid.clone(), fh, t.total_size))
                    })
                    .collect()
            };
            for (tid, fh, file_size) in &targets {
                // Immediate KAD source search. Seed
                // `active_kad_search_state` so the active-download
                // KAD loop later in this tick doesn't double-fire.
                if kad_available {
                    let kad_hash = md4_bytes_to_kad_id(fh);
                    let closest = state
                        .routing_table
                        .find_closest_prefer_verified(&kad_hash, SEARCH_INITIAL_CONTACTS);
                    if !closest.is_empty() {
                        let sid = start_kad_search(
                            state,
                            app_handle,
                            kad_hash,
                            SearchType::FindSource { file_size: *file_size },
                            closest,
                        );
                        if sid != SearchId(0) {
                            state
                                .download_source_searches
                                .insert(sid, (tid.clone(), *fh));
                            let entry = state
                                .active_kad_search_state
                                .entry(tid.clone())
                                .or_insert((0, 0));
                            entry.0 = now;
                            entry.1 += 1;
                            debug!(
                                "Warm-start: kicked off initial KAD source search for resumed download {}",
                                tid
                            );
                        }
                    }
                }
                // Immediate UDP OP_GETSOURCES to known servers.
                let packets = build_all_getsources_packets(state, fh, *file_size);
                if !packets.is_empty() {
                    let room = MAX_UDP_SOURCE_QUEUE
                        .saturating_sub(state.udp_source_queue.len());
                    state.udp_source_queue.extend(packets.into_iter().take(room));
                }
            }
            // TCP OP_GETSOURCES over the connected server — but only
            // once the connection has settled past its post-login
            // welcome (see `SERVER_SOURCE_SETTLE_SECS`). Before then
            // the periodic source timer (fast-forwarded on connect)
            // sends the initial batch; this on-demand kick would just
            // add to a premature, flood-prone burst.
            if !state.low_id
                && state.server_connection.is_some()
                && server_tcp_srcreq_frame_open(state, now)
            {
                // Bounded, and it stops at the first write failure.
                // Each `send_get_sources` is a TCP write on the
                // network task with a 30 s timeout
                // (`SERVER_WRITE_TIMEOUT_SECS`), and resuming a
                // session can warm-start thousands of rows
                // (`MAX_PENDING_DOWNLOADS` is 10,000). Walking that
                // list one blocking write at a time against a server
                // that has stopped reading parked all networking for
                // hours. The periodic sweep below carries whatever
                // this tick does not reach, which is why dropping
                // the tail costs nothing but a few seconds of
                // discovery latency.
                close_server_tcp_srcreq_frame(state, now);
                if let Some(conn) = state.server_connection.as_mut() {
                    for (tid, fh, file_size) in
                        targets.iter().take(SERVER_TCP_SRCREQ_MAX_PER_FRAME)
                    {
                        match conn.send_get_sources(fh, *file_size).await {
                            Ok(bytes) => {
                                if bytes > 0 {
                                    stats_manager.add_overhead(
                                        crate::storage::statistics::OverheadCategory::SourceExchange,
                                        crate::storage::statistics::OverheadDirection::Upload,
                                        bytes,
                                    );
                                    info!(
                                        "Warm-start: sent OP_GETSOURCES to server for resumed download {} ({})",
                                        tid,
                                        hex::encode(fh),
                                    );
                                }
                            }
                            Err(e) => {
                                // One timed-out write means the
                                // server is not draining; the rest
                                // of the batch would each cost
                                // another full timeout.
                                warn!(
                                    "Warm-start OP_GETSOURCES for {tid} failed: {e} — abandoning the rest of this batch"
                                );
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    let mut to_retry: Vec<String> = to_retry.into_iter()
        .filter(|(tid, _)| !started_from_sm.contains(tid) && !started_from_persistent.contains(tid))
        .map(|(tid, _)| tid)
        .collect();

    // UDP reask pass: for sources with known UDP ports, send enhanced
    // OP_REASKFILEPING with part status bitmap + complete source count
    // (eMule udp_ver > 3 format). Sources whose SX is due are skipped
    // so the normal TCP reask path can carry OP_REQUESTSOURCES.
    {
        let reask_interval = ed2k::dead_sources::FILEREASKTIME_SECS;
        // Plan every UDP reask packet while holding the SourceManager
        // lock (no `.await` in this scope), then drop the lock and do
        // the actual `send_to` calls. Holding `source_manager.write()`
        // across UDP `.await`s previously stalled the whole network
        // task (and download workers that share the lock) whenever the
        // socket applied backpressure or the source list was large.
        let mut to_send: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
        let mut reask_ids = to_retry.clone();
        for tid in state.active_source_senders.keys() {
            if !reask_ids.iter().any(|existing| existing == tid) {
                reask_ids.push(tid.clone());
            }
        }
        let mut reask_targets: HashMap<String, ([u8; 16], u64)> = HashMap::new();
        for tid in &reask_ids {
            if let Some(pd) = state.pending_downloads.get(tid) {
                if let Ok(b) = hex::decode(&pd.file_hash) {
                    if b.len() == 16 {
                        let mut fh = [0u8; 16];
                        fh.copy_from_slice(&b);
                        reask_targets.insert(tid.clone(), (fh, pd.file_size));
                        continue;
                    }
                }
            }
        }
        {
            let mgr = transfer_manager.read().await;
            for tid in &reask_ids {
                if reask_targets.contains_key(tid) {
                    continue;
                }
                if let Some(t) = mgr.get_transfer(tid) {
                    if let Ok(b) = hex::decode(&t.file_hash) {
                        if b.len() == 16 {
                            let mut fh = [0u8; 16];
                            fh.copy_from_slice(&b);
                            reask_targets.insert(tid.clone(), (fh, t.total_size));
                        }
                    }
                }
            }
        }
        let mut reask_bitmaps: HashMap<String, Vec<bool>> = HashMap::new();
        for tid in &reask_ids {
            if let Some(parts) = udp_reask_serveable_parts(state, tid).await {
                reask_bitmaps.insert(tid.clone(), parts);
            }
        }
        let mut sm = source_manager.write().await;
        for tid in &reask_ids {
            let Some((fh, file_size)) = reask_targets.get(tid).copied() else {
                continue;
            };

            let complete_sources = state.per_file_sources
                .get(tid)
                .map(|pfs| pfs.complete_source_count())
                .unwrap_or(0);

            let Some(reask_payload) = ed2k::messages::build_reask_file_ping(
                &fh,
                file_size,
                complete_sources,
                reask_bitmaps.get(tid).map(Vec::as_slice),
            ) else {
                warn!(
                    "Skipping UDP reask for {tid}: file exceeds standard ED2K wire part-count limit"
                );
                continue;
            };

            let total_udp = sm.get_udp_sources(&fh).len();
            let udp_sources = sm.get_udp_sources_due_for_reask(&fh, reask_interval);
            // Track which (ip, tcp_port) pairs we sent to in this
            // tick so the persistent-list pass below doesn't
            // double-fire to the same peer. This set is the only
            // dedup between the two passes: the SourceManager
            // cooldown is bumped by `mark_asked` below, but the
            // persistent pass keys on its own `last_udp_reask`.
            let mut sent_this_tick: HashSet<(Ipv4Addr, u16)> =
                HashSet::with_capacity(udp_sources.len());
            let mut sent = 0usize;
            for (ip, tcp_port, udp_port) in &udp_sources {
                if state.dead_sources.is_dead_source_for_file(&fh, u32::from(*ip), *tcp_port) {
                    continue;
                }
                // Deliberately NOT gated on the source-exchange
                // cooldown. eMule drives `OP_REASKFILEPING` purely
                // off the reask timer and the source's queue state
                // (`CPartFile::Process` → `UDPReaskForDownload`);
                // `OP_REQUESTSOURCES` piggybacks on a *TCP* reask
                // when its own interval allows, but never suppresses
                // the UDP ping. Gating on it here did two harmful
                // things: `can_request_sources_for` returns true when
                // `last_sx_sent == 0`, so a source we had never
                // source-exchanged with — every row loaded from
                // `sources.met` — was never reasked at all; and for
                // the rest the ping stopped once the 40-minute SX
                // window lapsed, because `last_sx_sent` only advances
                // on a live TCP connection. The population that
                // depends on this ping is precisely the detached
                // `OnQueue` sources of *active* downloads, and the
                // TCP reask path only runs for pending ones, so the
                // deep queue positions the detach model is built to
                // accumulate were being dropped.
                let addr = SocketAddr::new((*ip).into(), *udp_port);
                let mut pkt = vec![OP_EMULEPROT, ed2k::messages::OP_REASKFILEPING];
                pkt.extend_from_slice(&reask_payload);
                // Mark optimistically under the lock; the send happens
                // after the lock is released below.
                sm.mark_asked(&fh, *ip, *tcp_port);
                state
                    .pending_udp_reasks
                    .insert((*ip, *udp_port), (fh, chrono::Utc::now().timestamp()));
                to_send.push((addr, pkt));
                sent_this_tick.insert((*ip, *tcp_port));
                sent += 1;
            }
            if sent > 0 {
                debug!(
                    "Sent UDP reask to {}/{} UDP sources for pending download {}",
                    sent, total_udp, tid
                );
            }

            // Also check persistent per-file source list for UDP reask candidates.
            if let Some(pfs) = state.per_file_sources.get_mut(tid) {
                let udp_due = pfs.sources_needing_udp_reask();
                let mut pfs_sent = 0usize;
                for (orig_ip, orig_tcp, orig_udp) in &udp_due {
                    // Skip inbound session-only TCP ports — their
                    // UDP pairing (if any) was attached to an
                    // ephemeral connection, not a dialable peer.
                    let Some((ip, tcp_port)) =
                        sm.remap_dial_target(&pfs.file_hash, *orig_ip, *orig_tcp)
                    else {
                        // Still clear the due timer on the
                        // ephemeral row so we don't spin every
                        // 5s trying to reask an undialable port.
                        pfs.mark_udp_reask_sent(*orig_ip, *orig_tcp);
                        continue;
                    };
                    let udp_port = sm
                        .get_udp_sources(&pfs.file_hash)
                        .into_iter()
                        .find(|(uip, utcp, _)| *uip == ip && *utcp == tcp_port)
                        .map(|(_, _, u)| u)
                        .unwrap_or(*orig_udp);
                    if udp_port == 0 {
                        pfs.mark_udp_reask_sent(*orig_ip, *orig_tcp);
                        continue;
                    }
                    if sent_this_tick.contains(&(ip, tcp_port)) {
                        // Already pinged via SourceManager this tick.
                        pfs.mark_udp_reask_sent(*orig_ip, *orig_tcp);
                        continue;
                    }
                    if state.dead_sources.is_dead_source_for_file(&pfs.file_hash, u32::from(ip), tcp_port) {
                        pfs.mark_udp_reask_sent(*orig_ip, *orig_tcp);
                        continue;
                    }
                    // Not gated on the source-exchange cooldown —
                    // see the SourceManager pass above. This pass
                    // is the one that maintains queue position for
                    // an active download's detached sources, so the
                    // gate hit it hardest.
                    let addr = SocketAddr::new(ip.into(), udp_port);
                    let mut pkt = vec![OP_EMULEPROT, ed2k::messages::OP_REASKFILEPING];
                    pkt.extend_from_slice(&reask_payload);
                    // Bump last_asked so this entry isn't "due" again
                    // until the next full FILEREASKTIME window — without
                    // this the 5s timer pings the same peer every tick
                    // forever. Marked optimistically under the lock; the
                    // send happens after the lock is released below.
                    pfs.mark_udp_reask_sent(*orig_ip, *orig_tcp);
                    if (ip, tcp_port) != (*orig_ip, *orig_tcp) {
                        pfs.mark_udp_reask_sent(ip, tcp_port);
                    }
                    state.pending_udp_reasks.insert(
                        (ip, udp_port),
                        (pfs.file_hash, chrono::Utc::now().timestamp()),
                    );
                    to_send.push((addr, pkt));
                    sent_this_tick.insert((ip, tcp_port));
                    pfs_sent += 1;
                }
                if pfs_sent > 0 {
                    debug!("Sent UDP reask to {} persistent sources for {}", pfs_sent, tid);
                }
            }
        }
        // Release the SourceManager lock BEFORE doing any network I/O.
        drop(sm);
        for (addr, pkt) in &to_send {
            let _ = udp_socket.send_to(pkt, *addr).await;
        }
    }

    // Second pass: for remaining pending downloads, start new Kad + server searches.
    // Limit KAD searches per tick to avoid overwhelming the routing table when
    // many downloads are queued (eMule staggers source searches).
    const MAX_KAD_SEARCHES_PER_TICK: usize = 8;
    let mut kad_searches_started = 0usize;
    // Rotate the list so different downloads get the limited KAD search
    // slots each tick instead of the same ones always winning.
    if to_retry.len() > MAX_KAD_SEARCHES_PER_TICK {
        let rotate_by = state.kad_source_search_cursor % to_retry.len();
        to_retry.rotate_left(rotate_by);
    }
    let to_retry_len = to_retry.len();
    for tid in to_retry {
        let (hash_bytes, file_size) = {
            let Some(pd) = state.pending_downloads.get_mut(&tid) else { continue; };
            if pd.control.is_cancelled() {
                continue;
            }
            let hash_bytes = match hex::decode(&pd.file_hash) {
                Ok(b) if b.len() == 16 => b,
                _ => continue,
            };
            (hash_bytes, pd.file_size)
        };

        let mut did_search = false;
        let mut fh = [0u8; 16];
        fh.copy_from_slice(&hash_bytes);

        if kad_available && kad_searches_started < MAX_KAD_SEARCHES_PER_TICK {
            let kad_hash = md4_bytes_to_kad_id(&hash_bytes);
            let closest = state.routing_table.find_closest_prefer_verified(&kad_hash, SEARCH_INITIAL_CONTACTS);
            if !closest.is_empty() {
                let sid = start_kad_search(
                    state,
                    app_handle,
                    kad_hash,
                    SearchType::FindSource { file_size },
                    closest,
                );
                if sid != SearchId(0) {
                    state.download_source_searches.insert(sid, (tid.clone(), fh));
                    kad_searches_started += 1;
                    did_search = true;
                } else {
                    warn!(
                        "FindSource retry for {} deferred: active search cap reached",
                        tid
                    );
                }
            } else {
                debug!("Routing table empty for retry of {tid}, continuing with server-only source refresh");
            }
        }
        let src_count = {
            let sm = source_manager.read().await;
            sm.source_count(&fh)
        };
        if src_count < MAX_SOURCES_FOR_UDP {
            let packets = build_all_getsources_packets(
                state,
                &fh,
                file_size,
            );
            if !packets.is_empty() {
                let room = MAX_UDP_SOURCE_QUEUE.saturating_sub(state.udp_source_queue.len());
                let to_queue: Vec<_> = packets.into_iter().take(room).collect();
                if !to_queue.is_empty() { did_search = true; }
                state.udp_source_queue.extend(to_queue);
            }
        }

        if !state.low_id && state.server_connected && state.server_connection.is_some() {
            let current_server = state.server_addr.and_then(|addr| {
                match addr.ip() {
                    std::net::IpAddr::V4(v4) => {
                        Some((u32::from_le_bytes(v4.octets()), addr.port()))
                    }
                    _ => None,
                }
            });
            if let Some((srv_ip, srv_port)) = current_server {
                let mut fh = [0u8; 16];
                fh.copy_from_slice(&hash_bytes);
                let needing_callback = {
                    let sm = source_manager.read().await;
                    sm.get_lowid_sources_needing_callback(
                        &fh,
                        srv_ip,
                        srv_port,
                        ed2k::dead_sources::FILEREASKTIME_SECS,
                    )
                };
                if !needing_callback.is_empty() {
                    // Hand the batch to the rate-limited drain rather
                    // than writing it here. The source list is uncapped
                    // and every `request_callback` is a TCP write bounded
                    // only by SERVER_WRITE_TIMEOUT_SECS, so a slow or
                    // stalled server held this arm — and with it the whole
                    // single-task event loop: KAD UDP, every timer,
                    // transfer events and IPC — for that long per source
                    // in the batch. The drain sends at most
                    // MAX_LOWID_CALLBACKS_PER_TURN per loop turn, stops at
                    // the first failure, and owns the `mark_callback_sent`
                    // bookkeeping for the ones it actually got out, so
                    // nothing is marked sent here.
                    let queued = queue_lowid_callbacks(
                        pending_lowid_callback_queue,
                        needing_callback.iter().map(|cid| (fh, *cid)),
                    );
                    if queued > 0 {
                        did_search = true;
                        debug!("Queued {queued} LowID callback requests for pending download");
                    }
                }
            }
        }

        if did_search {
            if let Some(pd) = state.pending_downloads.get_mut(&tid) {
                pd.search_count += 1;
                pd.last_search_at = now;
            }
        }

        let search_count = state.pending_downloads.get(&tid).map(|pd| pd.search_count).unwrap_or(0);
        info!(
            "Retrying source search for {} (attempt {})",
            tid, search_count
        );
    }
    if to_retry_len > MAX_KAD_SEARCHES_PER_TICK {
        state.kad_source_search_cursor = state.kad_source_search_cursor.wrapping_add(MAX_KAD_SEARCHES_PER_TICK);
    }

    // Active-download LowID callback flush: SX / KAD Type-2 peers
    // are registered without waiting for FoundSources. Without this,
    // busy files (source_count ≥ MAX_SOURCES_FOR_UDP) never request
    // OP_CALLBACKREQUEST for those LowIDs.
    if !state.low_id && state.server_connected && state.server_connection.is_some() {
        let current_server = state.server_addr.and_then(|addr| match addr.ip() {
            std::net::IpAddr::V4(v4) => {
                Some((u32::from_le_bytes(v4.octets()), addr.port()))
            }
            _ => None,
        });
        if let Some((srv_ip, srv_port)) = current_server {
            let active_hashes: Vec<[u8; 16]> = {
                let mgr = transfer_manager.read().await;
                state
                    .active_source_senders
                    .keys()
                    .filter_map(|tid| {
                        mgr.get_transfer(tid).and_then(|t| {
                            let raw = hex::decode(&t.file_hash).ok()?;
                            if raw.len() == 16 {
                                let mut fh = [0u8; 16];
                                fh.copy_from_slice(&raw);
                                Some(fh)
                            } else {
                                None
                            }
                        })
                    })
                    .collect()
            };
            let mut to_queue: Vec<([u8; 16], u32)> = Vec::new();
            {
                let sm = source_manager.read().await;
                for fh in &active_hashes {
                    for cid in sm.get_lowid_sources_needing_callback(
                        fh,
                        srv_ip,
                        srv_port,
                        ed2k::dead_sources::FILEREASKTIME_SECS,
                    ) {
                        to_queue.push((*fh, cid));
                    }
                }
            }
            if !to_queue.is_empty() {
                let n = queue_lowid_callbacks(
                    pending_lowid_callback_queue,
                    to_queue,
                );
                if n > 0 {
                    debug!(
                        "Queued {n} LowID callbacks for active downloads via {srv_ip}:{srv_port}"
                    );
                }
            }
        }
    }

    // eMule: every downloading file periodically searches KAD for
    // additional sources, not just files waiting for their first
    // source.  Use remaining budget from MAX_KAD_SEARCHES_PER_TICK.
    let mut active_kad_started = 0usize;
    if kad_available && kad_searches_started < MAX_KAD_SEARCHES_PER_TICK {
        let mut active_needing_kad: Vec<(String, [u8; 16], u64)> = Vec::new();
        {
            let mgr = transfer_manager.read().await;
            let sm = source_manager.read().await;
            for tid in state.active_source_senders.keys() {
                if state.pending_downloads.contains_key(tid) { continue; }
                let (last_at, count) = state.active_kad_search_state
                    .get(tid)
                    .copied()
                    .unwrap_or((0, 0));
                let interval = active_download_kad_interval(count);
                if now.saturating_sub(last_at) < interval { continue; }
                if let Some(transfer) = mgr.get_transfer(tid) {
                    if let Ok(raw) = hex::decode(&transfer.file_hash) {
                        if raw.len() == 16 {
                            let mut fh = [0u8; 16];
                            fh.copy_from_slice(&raw[..16]);
                            if sm.source_count(&fh) >= MAX_SOURCES_FOR_UDP { continue; }
                            active_needing_kad.push((tid.clone(), fh, transfer.total_size));
                        }
                    }
                }
            }
        }
        for (tid, fh, file_size) in active_needing_kad {
            if kad_searches_started >= MAX_KAD_SEARCHES_PER_TICK { break; }
            let kad_hash = md4_bytes_to_kad_id(&fh);
            let closest = state.routing_table.find_closest_prefer_verified(&kad_hash, SEARCH_INITIAL_CONTACTS);
            if !closest.is_empty() {
                let sid = start_kad_search(
                    state,
                    app_handle,
                    kad_hash,
                    SearchType::FindSource { file_size },
                    closest,
                );
                if sid != SearchId(0) {
                    state.download_source_searches.insert(sid, (tid.clone(), fh));
                    kad_searches_started += 1;
                    active_kad_started += 1;
                    let entry = state.active_kad_search_state.entry(tid.clone()).or_insert((0, 0));
                    entry.0 = now;
                    entry.1 += 1;
                    debug!("Started KAD source search for active download {} (attempt {})", tid, entry.1);
                } else {
                    warn!(
                        "Active FindSource for {} deferred: active search cap reached",
                        tid
                    );
                }
            }
        }
    }

    // Ember DHT source discovery for downloads (slice 9). Gated on
    // the Ember transport + overlay peers (routing table or firsthand
    // session contacts the table refused). Independent of KAD.
    // Covers BOTH active downloads (live source sender) and pending
    // no-seed downloads still hunting for their first source (the
    // "download by hash" case); results inject via handle_epx_sources.
    if settings.ember_native_enabled && ember_overlay_contact_count(state) > 0 {
        const MAX_EMBER_SOURCE_SEARCHES_PER_TICK: usize = 5;
        // Drop throttle state for downloads that are entirely gone
        // (neither active nor pending) so the map can't grow without
        // bound across a long session.
        let stale_ember: Vec<String> = state
            .ember_source_search_state
            .keys()
            .filter(|tid| {
                !state.active_source_senders.contains_key(*tid)
                    && !state.pending_downloads.contains_key(*tid)
            })
            .cloned()
            .collect();
        for tid in stale_ember {
            state.ember_source_search_state.remove(&tid);
        }

        let ember_needing: Vec<(String, [u8; 16])> = {
            let mgr = transfer_manager.read().await;
            let sm = source_manager.read().await;
            let mut out: Vec<(String, [u8; 16])> = Vec::new();
            let mut seen: std::collections::HashSet<String> =
                std::collections::HashSet::new();

            // (transfer_id, file_hash_hex) candidates: active
            // downloads (live source sender) first, then pending
            // no-seed downloads. Clone out so the map borrows drop
            // before the backoff/cap filtering below.
            let mut candidates: Vec<(String, String)> = Vec::new();
            for tid in state.active_source_senders.keys() {
                if let Some(t) = mgr.get_transfer(tid) {
                    candidates.push((tid.clone(), t.file_hash.clone()));
                }
            }
            for (tid, pd) in &state.pending_downloads {
                candidates.push((tid.clone(), pd.file_hash.clone()));
            }

            for (tid, hash_hex) in candidates {
                if !seen.insert(tid.clone()) {
                    continue;
                }
                let Some(fh) = hex::decode(&hash_hex)
                    .ok()
                    .and_then(|v| <[u8; 16]>::try_from(v).ok())
                else {
                    continue;
                };
                let (last_at, count) = state
                    .ember_source_search_state
                    .get(&tid)
                    .copied()
                    .unwrap_or((0, 0));
                let interval = ember_source_search_interval(count).as_secs() as i64;
                if now.saturating_sub(last_at) < interval {
                    continue;
                }
                // Already saturated with sources — don't spend a DHT
                // lookup we don't need.
                if sm.source_count(&fh) >= MAX_SOURCES_FOR_UDP {
                    continue;
                }
                out.push((tid, fh));
            }
            out
        };
        let mut ember_started = 0usize;
        for (tid, fh) in ember_needing {
            if ember_started >= MAX_EMBER_SOURCE_SEARCHES_PER_TICK {
                break;
            }
            if start_ember_source_search(udp_socket, state, &tid, fh).await {
                let entry = state
                    .ember_source_search_state
                    .entry(tid)
                    .or_insert((0, 0));
                entry.0 = now;
                entry.1 += 1;
                ember_started += 1;
            }
        }
    }

    // Starved-download fast server re-ask. eMule keeps pulling the
    // connected server's (growing) source list for a file that has
    // no working sources; our 4-minute TCP batch is far too slow to
    // recover when the initial source set is dead (e.g. all HighID
    // sources reset, all KAD callbacks unanswered). For ACTIVE
    // downloads with zero throughput we re-ask the connected server
    // for that file's sources on a flood-safe per-file cadence
    // (STARVED_SERVER_REASK_SECS). This is the path that surfaces
    // the LowID server sources eMule reaches via OP_CALLBACKREQUEST.
    // Gated on the shared frame budget, so the 45 s per-file clock
    // only decides *which* starved files ride the next frame.
    if state.server_connection.is_some() && server_tcp_srcreq_frame_open(state, now) {
        let starved: Vec<(String, [u8; 16], u64)> = {
            let mgr = transfer_manager.read().await;
            let mut out = Vec::new();
            for tid in state.active_source_senders.keys() {
                // Pending downloads are already re-asked aggressively
                // by the loop above; only handle started transfers.
                if state.pending_downloads.contains_key(tid) { continue; }
                let last = state.starved_server_reask_at.get(tid).copied().unwrap_or(0);
                if now.saturating_sub(last) < STARVED_SERVER_REASK_SECS { continue; }
                if let Some(transfer) = mgr.get_transfer(tid) {
                    // Starved == no bytes currently flowing.
                    if transfer.speed > 0 { continue; }
                    if let Ok(raw) = hex::decode(&transfer.file_hash) {
                        if raw.len() == 16 {
                            let mut fh = [0u8; 16];
                            fh.copy_from_slice(&raw[..16]);
                            out.push((tid.clone(), fh, transfer.total_size));
                        }
                    }
                }
                if out.len() >= SERVER_TCP_SRCREQ_MAX_PER_FRAME { break; }
            }
            out
        };
        if !starved.is_empty() {
            close_server_tcp_srcreq_frame(state, now);
            if let Some(conn) = state.server_connection.as_mut() {
                for (tid, fh, file_size) in &starved {
                    // Stop at the first failed write: these are
                    // sequential 30 s-timeout TCP writes on the
                    // network task, so a server that has stopped
                    // reading turns a capped batch into
                    // `SERVER_TCP_SRCREQ_MAX_PER_FRAME` back-to-back
                    // stalls of everything else.
                    match conn.send_get_sources(fh, *file_size).await {
                        Ok(bytes) => {
                            if bytes > 0 {
                                stats_manager.add_overhead(
                                    crate::storage::statistics::OverheadCategory::SourceExchange,
                                    crate::storage::statistics::OverheadDirection::Upload,
                                    bytes,
                                );
                                info!(
                                    "Starved re-ask: sent OP_GETSOURCES to server for active download {} ({})",
                                    tid,
                                    hex::encode(fh),
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Starved re-ask OP_GETSOURCES for {tid} failed: {e} — abandoning the rest of this batch"
                            );
                            break;
                        }
                    }
                }
            }
            for (tid, _, _) in &starved {
                state.starved_server_reask_at.insert(tid.clone(), now);
            }
            // Bound the cooldown map: drop entries for downloads no
            // longer active so a long session can't accumulate them.
            if state.starved_server_reask_at.len() > 256 {
                let active: std::collections::HashSet<String> =
                    state.active_source_senders.keys().cloned().collect();
                state.starved_server_reask_at.retain(|k, _| active.contains(k));
            }
        }
    }

    {
        let total_pending = state.pending_downloads.len();
        let active_downloads = state.download_handles.len();
        if total_pending > 0 || kad_searches_started > 0 {
            info!(
                "Source retry tick: {} pending, {} active, {} started(persistent={}, sm={}), {} KAD searches ({}+{} active), server={}",
                total_pending, active_downloads,
                started_from_persistent.len() + started_from_sm.len(),
                started_from_persistent.len(), started_from_sm.len(),
                kad_searches_started, kad_searches_started - active_kad_started, active_kad_started,
                if server_connected { "yes" } else { "no" }
            );
        }
    }

    // Auto-priority adjustment (eMule: CPartFile::UpdateAutoDownPriority)
    {
        let mgr = transfer_manager.read().await;
        let auto_tids: Vec<(String, [u8; 16])> = state.pending_downloads.iter()
            .filter_map(|(tid, pd)| {
                let t = mgr.active.get(tid)?;
                if t.priority != "auto" { return None; }
                let raw = hex::decode(&pd.file_hash).ok()?;
                if raw.len() < 16 { return None; }
                let mut fh = [0u8; 16];
                fh.copy_from_slice(&raw[..16]);
                Some((tid.clone(), fh))
            })
            .collect();
        drop(mgr);
        if !auto_tids.is_empty() {
            let sm = source_manager.read().await;
            for (tid, fh) in &auto_tids {
                let src_count = sm.source_count(fh);
                let effective = if src_count > 100 { "low" } else if src_count > 20 { "normal" } else { "high" };
                let effective_u32 = priority_str_to_u32(effective);
                if let Some(pd) = state.pending_downloads.get_mut(tid) {
                    pd.priority = effective_u32;
                }
                debug!("Auto-priority for {tid}: {src_count} sources -> {effective} ({})", effective_u32);
            }
        }
    }

    // The 60s friend-xfer gate is only useful if expiry runs at or
    // below 60s; evaluating it only on cleanup_timer's 300s tick
    // left a second file free to arm another FriendEmber callback.
    {
        let now = std::time::Instant::now();
        let timed_out: Vec<(([u8; 16], [u8; 16]), String)> = state
            .friend_xfer_attempts
            .iter()
            .filter(|(_, attempt)| {
                now.saturating_duration_since(attempt.sent_at).as_secs()
                    >= FRIEND_XFER_ATTEMPT_TIMEOUT_SECS
            })
            .map(|(key, attempt)| (*key, attempt.transfer_id.clone()))
            .collect();
        for (key, transfer_id) in timed_out {
            if state
                .per_file_sources
                .get(&transfer_id)
                .is_some_and(|pfs| !pfs.friend_connect_sources(now).is_empty())
            {
                state.friend_xfer_stats.timed_out =
                    state.friend_xfer_stats.timed_out.saturating_add(1);
                info!(
                    "Friend {} never connected back for {}; releasing source",
                    hex::encode(key.0),
                    hex::encode(key.1)
                );
                drop_pending_friend_callback(pending_kad_callbacks, key.0, key.1).await;
                release_friend_connect_sources(
                    state,
                    transfer_manager,
                    app_handle,
                    &transfer_id,
                )
                .await;
            }
            // Past the retry ceiling the entry is useless: drop it
            // so a much later attempt (after the friend has been
            // offline and come back) starts from a clean slate
            // instead of being permanently refused.
            if state
                .friend_xfer_attempts
                .get(&key)
                .is_some_and(|a| a.attempts >= FRIEND_XFER_MAX_ATTEMPTS)
                && now
                    .saturating_duration_since(
                        state.friend_xfer_attempts[&key].sent_at,
                    )
                    .as_secs()
                    >= FRIEND_XFER_COOLDOWN_SECS * 4
            {
                state.friend_xfer_attempts.remove(&key);
            }
        }
    }
}
