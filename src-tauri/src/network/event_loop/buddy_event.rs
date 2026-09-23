//! Events from our KAD buddy while we are firewalled: pings, callback
//! requests relayed to us, re-ask callbacks, and losing the buddy.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_buddy_event(
    event: Option<BuddyEvent>,
    udp_socket: &Arc<UdpSocket>,
    state: &mut NetworkState,
    settings: &AppSettings,
    dl_event_tx: &mpsc::Sender<DownloadEvent>,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
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
    connect_serve_tx: &mpsc::Sender<upload_server::ConnectServeRequest>,
) {
    match event {
        Some(BuddyEvent::PingReceived) => {
            state.buddy_manager.send_pong_to_buddy().await;
        }
        Some(BuddyEvent::PongReceived) => {
            debug!("Buddy pong received");
        }
        Some(BuddyEvent::Callback { file_hash, dest_ip, dest_port }) => {
            // `OP_CALLBACK` carries the file id in CUInt128 order,
            // the way the requester wrote it into
            // `KADEMLIA_CALLBACK_REQ` and the way a relaying buddy
            // forwards it. eMule's `ListenSocket` does
            // `ToByteArray` before looking the file up; without the
            // matching swap here the bytes never equal a pending
            // download's ed2k hash and the source registers under a
            // hash nothing else uses.
            let file_hash = kad::publish::kad_id_to_md4_bytes(&KadId(file_hash));
            info!("Buddy callback: connect to {dest_ip}:{dest_port} for file {}", hex::encode(file_hash));

            // eMule parity (KAD buddy OP_CALLBACK -> TryToConnect -> serve): a peer
            // reached us (LowID) through our buddy relay because it wants to interact
            // over a connection *we* open. Dial back and serve it via the upload
            // listener's outbound path, so a firewalled node can upload. buddy.rs
            // already validated the callback (crypto check token, non-zero port, not
            // special-use); we add the runtime ip-filter / ban gate here before dialing.
            // The KAD callback carries no crypt options or user hash, so we dial plain
            // (crypt_options=0, user_hash=None) and let the peer's Hello drive the rest.
            // We still keep the download-direction handling below (the peer may also be
            // a source of a file we want). Non-blocking hand-off; a full queue drops it.
            let buddy_target_safe = !state.ip_filter.is_blocked(dest_ip)
                && !state.banned_ips.contains(&dest_ip)
                && connect_serve_target_ok(
                    dest_ip,
                    dest_port,
                    state.external_ip,
                    state.tcp_port,
                    advertised_tcp_port(state),
                    None,
                    &state.user_hash,
                );
            if buddy_target_safe {
                let cb_addr = SocketAddr::new(dest_ip.into(), dest_port);
                if let Err(e) = connect_serve_tx.try_send(
                    upload_server::ConnectServeRequest {
                        peer_addr: cb_addr,
                        crypt_options: 0,
                        user_hash: None,
                        push_grant_file_hash: None,
                        push_grant_accepted: None,
                        secure_friend_ember_hash: None,
                    },
                ) {
                    debug!("Could not enqueue buddy callback-serve for {cb_addr}: {e}");
                }
            }

            let matching_tid = state.pending_downloads.iter()
                .find(|(_, pd)| {
                    hex::decode(&pd.file_hash).ok()
                        .filter(|b| b.len() == 16 && b[..] == file_hash[..])
                        .is_some()
                })
                .map(|(tid, _)| tid.clone());

            if let Some(tid) = matching_tid {
                // Respect pause/cancel and the concurrency cap exactly as the
                // KAD-callback arm below does. A paused download deliberately
                // stays in `pending_downloads` with a cancelled control, so
                // without this guard a buddy connect-back resurrected it: the
                // worker bails at once on the cancelled control, its `Failed` is
                // classified as a user cancel and suppressed, and the row is left
                // `Active` with no worker and no pending entry — a slot consumed
                // for the rest of the session that `resume()` cannot reach,
                // because `resume` is a no-op for a row already reading `Active`.
                // The `active` membership test additionally keeps a row still
                // waiting in the queue from starting a worker outside its slot
                // (`try_start_pending_download_from_known_sources` checks the
                // same thing, since a queued download legitimately keeps a
                // pending entry for source discovery).
                let blocked = state
                    .pending_downloads
                    .get(&tid)
                    .map(|pd| pd.control.is_paused() || pd.control.is_cancelled())
                    .unwrap_or(true)
                    || !transfer_manager.read().await.active.contains_key(&tid);
                if blocked {
                    debug!(
                        "Ignoring buddy callback for {tid}: paused, cancelled, or not holding an active slot"
                    );
                } else if let Some(pd) = state.pending_downloads.remove(&tid) {
                    let source_addr = SocketAddr::new(dest_ip.into(), dest_port);
                    info!("Starting callback download {} to {source_addr}", pd.transfer_id);

                    {
                        let mut sm = source_manager.write().await;
                        // A buddy callback answers a request we
                        // made for a peer some network already
                        // told us about, so it names no origin of
                        // its own.
                        sm.register_source(file_hash, dest_ip, dest_port, None);
                    }
                    {
                        let pfs = state
                            .per_file_sources
                            .entry(pd.transfer_id.clone())
                            .or_insert_with(|| ed2k::sources::PerFileSourceList::new(file_hash));
                        if pfs.add_source_full(dest_ip, dest_port, 0) {
                            state.ember_payload_dirty = true;
                        }
                    }
                    {
                        let mut mgr = transfer_manager.write().await;
                        mgr.update_status(&tid, TransferStatus::Active);
                        mgr.update_sources(&tid, 1, 0, 0);
                    }
                    let _ = app_handle.emit("transfer-status", serde_json::json!({
                        "id": tid,
                        "status": "active",
                        "sources": 1,
                        "active_sources": 0,
                        "queued_sources": 0,
                    }));

                    let uh = {
                        let sm = source_manager.read().await;
                        sm.get_user_hash(&file_hash, dest_ip, dest_port)
                    };
                    let co = {
                        let sm = source_manager.read().await;
                        sm.get_connect_options(&file_hash, dest_ip, dest_port)
                    };
                    let download_sources = vec![DownloadSource {
                        peer_ip: dest_ip.to_string(),
                        peer_port: dest_port,
                        available_parts: Vec::new(),
                        peer_user_hash: uh,
                        peer_connect_options: co,
                    }];

                    let (src_inject_tx, src_inject_rx) = mpsc::channel::<DownloadSource>(32);
                    let (est_inject_tx, est_inject_rx) =
                        mpsc::channel::<ed2k::multi_source::EstablishedSource>(ESTABLISHED_SOURCE_CHANNEL_CAP);
                    let expected_aich_master =
                        expected_aich_bytes(pd.expected_aich.as_deref());
                    let ms_download = MultiSourceDownload {
                        transfer_id: pd.transfer_id.clone(),
                        file_hash,
                        file_name: pd.file_name,
                        file_size: pd.file_size,
                        sources: download_sources,
                        download_dir: PathBuf::from(&settings.download_folder),
                        user_hash: state.user_hash,
                        nickname: settings.nickname.clone(),
                        tcp_port: advertised_tcp_port(state),
                        udp_port: advertised_udp_port(state),
                        bandwidth_limiter: bandwidth_limiter.clone(),
                        control: pd.control,
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
                            .or_else(|| state.aich_root_map.get(&file_hash).copied()),
                        expected_aich_master,
                        ember_file_hash: state
                            .ember_content_hashes
                            .get(&file_hash)
                            .map(|pin| pin.digest)
                            .unwrap_or([0u8; 32]),
                        geoip: geoip.clone(),
                        tracker_registry: Some(state.tracker_registry.clone()),
                        sx_overhead: stats_manager.sx_counters.clone(),
                        file_req_overhead: stats_manager.file_req_counters.clone(),
                        epx_overhead: stats_manager.epx_counters.clone(),
                    };
                    let dl_tid = ms_download.transfer_id.clone();
                    state.active_source_senders.insert(dl_tid.clone(), src_inject_tx);
                    state.active_established_senders.insert(dl_tid.clone(), est_inject_tx);
                    let tx = dl_event_tx.clone();
                    let tx2 = tx.clone();
                    if let Some(old_handle) = state.download_handles.remove(&dl_tid) {
                        debug!("Aborting existing download task for {dl_tid} before starting callback multi-source download");
                        old_handle.abort();
                    }
                    let dl_tid2 = dl_tid.clone();
                    let handle = tokio::spawn(async move {
                        if let Err(e) = ms_download.run(tx).await {
                            warn!("Callback download failed: {e}");
                            let kind = classify_error(&e.to_string());
                            let _ = tx2.send(DownloadEvent::Failed { transfer_id: dl_tid, error: e.to_string(), failure_kind: kind }).await;
                        }
                    });
                    state.download_handles.insert(dl_tid2, handle);
                }
            } else {
                // The buddy can callback after a transfer has
                // already left `pending_downloads` and is running
                // as a multi-source download. Treat that as a
                // normal newly discovered source instead of
                // dropping it; this mirrors the KAD/server callback
                // receiver path and keeps firewalled sources useful
                // throughout the download, not only before the
                // first worker starts.
                let hash_hex = hex::encode(file_hash);
                let matching_ids = {
                    let mgr = transfer_manager.read().await;
                    matching_active_transfer_ids_for_hash(state, &mgr, &hash_hex)
                };
                if matching_ids.is_empty() {
                    debug!(
                        "No pending or active download for buddy callback file hash {}",
                        hash_hex
                    );
                } else if state.dead_sources.is_dead_source_for_file(
                    &file_hash,
                    u32::from(dest_ip),
                    dest_port,
                ) {
                    debug!(
                        "Ignoring buddy callback from dead source {}:{} for {}",
                        dest_ip, dest_port, hash_hex
                    );
                } else {
                    {
                        let mut sm = source_manager.write().await;
                        // A buddy callback answers a request we
                        // made for a peer some network already
                        // told us about, so it names no origin of
                        // its own.
                        sm.register_source(file_hash, dest_ip, dest_port, None);
                    }
                    let source = DownloadSource {
                        peer_ip: dest_ip.to_string(),
                        peer_port: dest_port,
                        available_parts: Vec::new(),
                        peer_user_hash: None,
                        peer_connect_options: None,
                    };
                    let stats = inject_source_into_active_transfers(
                        state,
                        file_hash,
                        &matching_ids,
                        &source,
                        0,
                    );
                    if stats.injected > 0 {
                        info!(
                            "Buddy callback injected {} active source(s) for {}",
                            stats.injected, hash_hex
                        );
                    }
                }
            }
        }
        Some(BuddyEvent::ReaskCallback { dest_ip, dest_port, file_hash }) => {
            let hash_hex = hex::encode(file_hash);
            let pending_match = state
                .pending_downloads
                .iter()
                .find(|(_, pd)| pd.file_hash == hash_hex)
                .map(|(tid, pd)| (tid.clone(), pd.file_size));
            let (pending_tid, file_size) = match pending_match {
                Some((tid, fs)) => (Some(tid), fs),
                None => {
                    let mgr = transfer_manager.read().await;
                    (
                        None,
                        mgr.active.values().chain(mgr.queue.iter())
                            .find(|t| t.file_hash == hash_hex)
                            .map(|t| t.total_size)
                            .unwrap_or(0),
                    )
                }
            };
            let serveable_parts = match pending_tid.as_deref() {
                Some(tid) => udp_reask_serveable_parts(state, tid).await,
                None => None,
            };
            let complete_sources = state.per_file_sources.values()
                .find(|pfs| pfs.file_hash == file_hash)
                .map(|pfs| pfs.complete_source_count())
                .unwrap_or(0);
            let addr = SocketAddr::new(dest_ip.into(), dest_port);
            let Some(reask_payload) = ed2k::messages::build_reask_file_ping(
                &file_hash,
                file_size,
                complete_sources,
                serveable_parts.as_deref(),
            ) else {
                warn!("Skipping buddy UDP reask: file exceeds standard ED2K wire part-count limit");
                return;
            };
            let mut pkt = vec![OP_EMULEPROT, ed2k::messages::OP_REASKFILEPING];
            pkt.extend_from_slice(&reask_payload);
            // Register like the source-timer senders do: an answer to
            // a reask that is not in this map is dropped as
            // unsolicited by both reply branches.
            state.pending_udp_reasks.insert(
                (dest_ip, dest_port),
                (file_hash, chrono::Utc::now().timestamp()),
            );
            let _ = udp_socket.send_to(&pkt, addr).await;
            debug!("Sent UDP reask to {}:{} via buddy relay for file {}", dest_ip, dest_port, hash_hex);
        }
        Some(BuddyEvent::Disconnected) | None => {
            // Retire the receiver unconditionally, and only ask the
            // manager to disconnect if it still thinks it is
            // connected. The two are not the same condition: a send
            // helper that finds its writer dead disconnects the
            // session itself, so by the time the channel's close
            // reaches us the manager is already `NoBuddy`. A closed
            // channel yields `None` from `recv()` immediately and
            // forever, so leaving the receiver installed made this
            // `select!` arm ready on every iteration and pinned a
            // core at 100% for the rest of the session — something
            // the peer could induce by accepting our connection and
            // then stopping reading.
            if state.buddy_manager.state() == BuddyState::Connected {
                state.buddy_manager.disconnect_buddy().await;
            }
            state.buddy_event_rx = None;
            *state.shared_buddy_info.write().await = None;
        }
    }
}
