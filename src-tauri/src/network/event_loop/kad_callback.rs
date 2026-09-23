//! Adopting a connection a LowID peer made in answer to our KAD callback
//! request, and running the download over it.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_kad_callback_conn(
    cb_conn: Option<upload_server::KadCallbackParts>,
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
) {
    if let Some(parts) = cb_conn {
        let hash_hex = hex::encode(parts.file_hash);
        let active_parts: Option<upload_server::KadCallbackParts> =
            if let Some(tid) = state.pending_downloads.iter()
                .find(|(_, pd)| pd.file_hash == hash_hex)
                .map(|(tid, _)| tid.clone())
            {
                // Respect pause/cancel the same way
                // `try_start_pending_download_from_known_sources`
                // does — a paused download stays in
                // pending_downloads and must not be started
                // by a KAD/buddy callback connect-back.
                let blocked = state
                    .pending_downloads
                    .get(&tid)
                    .map(|pd| pd.control.is_paused() || pd.control.is_cancelled())
                    .unwrap_or(true);
                if blocked {
                    None
                } else if let Some(pd) = state.pending_downloads.remove(&tid) {
                let source_addr = SocketAddr::new(parts.peer_ip.into(), parts.peer_port);
                let expected_aich_master =
                    expected_aich_bytes(pd.expected_aich.as_deref());
                info!("Starting callback download {tid} from {source_addr}");
                let download = Ed2kDownload {
                    transfer_id: pd.transfer_id.clone(),
                    file_hash: parts.file_hash,
                    file_name: pd.file_name,
                    file_size: pd.file_size,
                    source_addr,
                    download_dir: PathBuf::from(&settings.download_folder),
                    tcp_port: advertised_tcp_port(state),
                    udp_port: advertised_udp_port(state),
                    bandwidth_limiter: bandwidth_limiter.clone(),
                    control: pd.control,
                    source_manager: Some(source_manager.clone()),
                    comment_manager: Some(state.comment_manager.clone()),
                    credit_manager: Some(credit_manager.clone()),
                    obfuscation_enabled: state.obfuscation_enabled,
            ed2k_limits: settings.ed2k_download_limits(),
            ember_hash,
            ed25519_public_key: ed25519_pubkey,
            ed25519_secret_key,
            our_nickname: settings.nickname.clone(),
            friend_hashes: Some(friend_hashes.clone()),
                    ember_payload: shared_ember_payload.clone(),
                    ember_payload_generation: ember_payload_generation.clone(),
                    ip_filter: Some(state.shared_ip_filter.clone()),
                    banned_ips: Some(shared_banned_ips.clone()),
                    external_ip: state.external_ip,
                    aich_pending: Some(state.aich_recovery_pending.clone()),
                    trusted_aich_master: expected_aich_master
                        .or_else(|| state.aich_root_map.get(&parts.file_hash).copied()),
                    expected_aich_master,
                    ember_file_hash: state.ember_content_hashes.get(&parts.file_hash).map(|pin| pin.digest).unwrap_or([0u8; 32]),
                    geoip: geoip.clone(),
                    sx_overhead: stats_manager.sx_counters.clone(),
                    file_req_overhead: stats_manager.file_req_counters.clone(),
                    epx_overhead: stats_manager.epx_counters.clone(),
                };
                {
                    let mut mgr = transfer_manager.write().await;
                    mgr.update_status(&tid, TransferStatus::Active);
                }
                let _ = app_handle.emit("transfer-status", serde_json::json!({
                    "id": tid,
                    "status": "active",
                    "peer_id": source_addr.to_string(),
                }));
                let tx = dl_event_tx.clone();
                let tid2 = tid.clone();
                let tid3 = tid.clone();
                let tx2 = tx.clone();
                if let Some(old_handle) = state.download_handles.remove(&tid3) {
                    old_handle.abort();
                }
                let handle = tokio::spawn(async move {
                    if let Err(e) = download.run_from_callback(
                        parts.reader,
                        parts.writer,
                        parts.peer_user_hash,
                        parts.peer_caps,
                        parts.emule_info_done,
                        tx,
                    ).await {
                        warn!("Callback download failed: {e}");
                        let kind = classify_error(&e.to_string());
                        let _ = tx2.send(DownloadEvent::Failed { transfer_id: tid2, error: e.to_string(), failure_kind: kind }).await;
                    }
                });
                state.download_handles.insert(tid3.clone(), handle);
                // The LowID peer successfully called back. The
                // real source-detail row will materialise
                // under `(peer_ip, ephemeral_port)` as the
                // download progresses; drop the
                // `(peer_ip, listed_port)` placeholder we
                // seeded earlier from the KAD source
                // response so the UI doesn't show two rows
                // (one forever-Connecting, one actually
                // transferring) for the same peer.
                //
                // We emit `transfer-source-detail` with
                // `status=failed` to match the frontend's
                // existing remove-on-terminal-status
                // protocol (see `transfers/+page.svelte`'s
                // `transfer-source-detail` handler — rows
                // with `status='failed'` are filtered out
                // of the expanded list rather than kept as
                // failed entries, so this does NOT inflate
                // the "N failed sources hidden" counter).
                let peer_ip_str = parts.peer_ip.to_string();
                let uh_key = if parts.peer_user_hash != [0u8; 16] {
                    Some(upload_server::kad_callback_display_key(
                        Ipv4Addr::UNSPECIFIED,
                        Some(parts.peer_user_hash),
                    ))
                } else {
                    None
                };
                let removed = {
                    let mut mgr = transfer_manager.write().await;
                    let mut removed =
                        mgr.remove_callback_placeholders_for_ip(&tid3, &peer_ip_str);
                    if let Some(key) = uh_key {
                        removed.extend(mgr.remove_callback_placeholders_for_ip(&tid3, &key));
                    }
                    removed
                };
                for (ip, port) in removed {
                    state.callback_row_pending_since
                        .remove(&(tid3.clone(), ip.clone(), port));
                    let _ = app_handle.emit(
                        "transfer-source-detail",
                        serde_json::json!({
                            "transfer_id": &tid3,
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
                None
            } else {
                Some(parts)
            }
        } else {
            Some(parts)
        };

        if let Some(parts) = active_parts {
            // Download already active (or not in pending_downloads)
            // — the LowID peer connected *back* to us (server-relay or KAD
            // callback). Hand the live, post-handshake
            // stream to the running multi-source worker
            // so it adopts the connection rather than
            // dialing the LowID peer's NAT'd address —
            // which can't accept inbound TCP and would
            // always fail at `stage:hello_wait: forcibly
            // closed`. Falls back to the legacy metadata
            // injection only if the established channel
            // can't accept the stream (no matching active
            // download, channel full, channel closed),
            // mirroring the pre-fix behaviour as a
            // last resort.

            // Extract Copy / clonable fields up front so
            // we can keep them after the stream itself is
            // moved into the EstablishedSource.
            let cb_peer_ip = parts.peer_ip;
            let cb_peer_port = parts.peer_port;
            let cb_peer_hello_port = parts.peer_hello_port;
            let cb_peer_user_hash = parts.peer_user_hash;
            let cb_file_hash = parts.file_hash;
            let cb_emule_info_done = parts.emule_info_done;
            let cb_peer_caps = parts.peer_caps.clone();
            let cb_friend_ember_hash = parts.friend_ember_hash;

            // Apply the same reputation gate that
            // `inject_source_into_active_transfers` uses
            // for metadata-only injection. Without this,
            // a peer banned by user-hash reputation could
            // bypass the ban via a LowID callback — the
            // metadata path checked, the
            // established-stream fast path didn't.
            // All-zero hash means "unknown identity" and
            // is exempt from reputation checks (treated
            // as "no identity to ban yet"); only verified
            // hashes carry reputation entries.
            // `continue` here returns to the outer event
            // loop; the moved-but-not-yet-consumed
            // `parts.reader` / `parts.writer` go out of
            // scope and the TCP socket is dropped.
            if cb_peer_user_hash != [0u8; 16]
                && state.reputation.is_banned(&cb_peer_user_hash)
            {
                debug!(
                    "Dropping LowID callback from {cb_peer_ip}:{cb_peer_port} for {hash_hex}: peer is reputation-banned",
                );
                return;
            }

            let server_info = state.server_addr.and_then(|sa| {
                if let std::net::IpAddr::V4(v4) = sa.ip() {
                    Some((u32::from_le_bytes(v4.octets()), sa.port()))
                } else {
                    None
                }
            });
            {
                let mut sm = source_manager.write().await;
                if let Some((srv_ip, srv_port)) = server_info {
                    // Link this callback to the LowID row we already
                    // track (matched by the peer's *listening* port
                    // from its Hello, not this connection's ephemeral
                    // port) so the peer isn't counted twice. It stays
                    // a LowID row — reconnects still go via a fresh
                    // server callback.
                    sm.link_lowid_callback_identity(
                        srv_ip,
                        srv_port,
                        cb_peer_hello_port,
                        cb_peer_user_hash,
                    );
                }
                // Ephemeral inbound port = live-session only.
                // HighID Path-B also registers the Hello listening
                // port as the reconnectable dial address.
                sm.register_inbound_callback_ports(
                    cb_file_hash,
                    cb_peer_ip,
                    cb_peer_port,
                    cb_peer_hello_port,
                    cb_peer_user_hash,
                    0,
                    cb_peer_caps.is_high_id(),
                );
            }
            let matching_tids = {
                let mgr = transfer_manager.read().await;
                matching_active_transfer_ids_for_hash(state, &mgr, &hash_hex)
            };
            let uh = if cb_peer_user_hash != [0u8; 16] { Some(cb_peer_user_hash) } else { None };
            // Adopted streams must keep the ephemeral connection
            // port in `DownloadSource` — that is the live TCP
            // remote port the worker keys UI/PFS rows on. Metadata
            // fallback inject (no live stream) prefers the Hello
            // listening port for HighID so we never seed a dial
            // of an undialable ephemeral address.
            let download_source = DownloadSource {
                peer_ip: cb_peer_ip.to_string(),
                peer_port: cb_peer_port,
                available_parts: Vec::new(),
                peer_user_hash: uh,
                peer_connect_options: None,
            };
            let inject_source = DownloadSource {
                peer_ip: cb_peer_ip.to_string(),
                peer_port: if cb_peer_caps.is_high_id()
                    && cb_peer_hello_port > 0
                {
                    cb_peer_hello_port
                } else {
                    cb_peer_port
                },
                available_parts: Vec::new(),
                peer_user_hash: uh,
                peer_connect_options: None,
            };

            // Try to hand off the live stream to the first
            // matching active download. A single inbound
            // TCP connection can only be adopted by one
            // downloader, so we pick the first matching
            // active transfer; if no established sender
            // takes it, the stream is dropped and we fall
            // back to the legacy metadata path so the
            // peer at least appears as a known source for
            // retry rounds.
            let mut stream_dispatched = false;
            let mut pending_stream = Some(ed2k::multi_source::EstablishedStream {
                reader: parts.reader,
                writer: parts.writer,
                peer_user_hash: cb_peer_user_hash,
                emule_info_done: cb_emule_info_done,
                peer_caps: cb_peer_caps,
            });
            let mut closed_senders: Vec<String> = Vec::new();
            for tid in &matching_tids {
                let stream = match pending_stream.take() {
                    Some(s) => s,
                    None => break,
                };
                let est_source = ed2k::multi_source::EstablishedSource {
                    source: download_source.clone(),
                    stream,
                };
                match state.active_established_senders.get(tid) {
                    Some(tx) => match tx.try_send(est_source) {
                        Ok(()) => {
                            info!(
                                "Adopted LowID callback stream from {cb_peer_ip}:{cb_peer_port} into active download {tid} for {hash_hex}",
                            );
                            stream_dispatched = true;
                            // Clean up the placeholder row for
                            // this peer on this transfer. See
                            // the mirrored cleanup in the
                            // first-time-callback branch
                            // above for the detailed
                            // rationale — in short, the
                            // placeholder was keyed by the
                            // listed listening port while
                            // the real stream lands on the
                            // peer's ephemeral outgoing
                            // port; removing the placeholder
                            // keeps a single row per peer
                            // in the UI.
                            let peer_ip_str = cb_peer_ip.to_string();
                            let uh_key = if cb_peer_user_hash != [0u8; 16] {
                                Some(upload_server::kad_callback_display_key(
                                    Ipv4Addr::UNSPECIFIED,
                                    Some(cb_peer_user_hash),
                                ))
                            } else {
                                None
                            };
                            let removed = {
                                let mut mgr = transfer_manager.write().await;
                                let mut removed =
                                    mgr.remove_callback_placeholders_for_ip(tid, &peer_ip_str);
                                if let Some(key) = uh_key {
                                    removed.extend(
                                        mgr.remove_callback_placeholders_for_ip(tid, &key),
                                    );
                                }
                                removed
                            };
                            for (ip, port) in removed {
                                state.callback_row_pending_since
                                    .remove(&(tid.clone(), ip.clone(), port));
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
                            break;
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Full(es)) => {
                            match tokio::time::timeout(
                                std::time::Duration::from_millis(250),
                                tx.reserve(),
                            )
                            .await
                            {
                                Ok(Ok(permit)) => {
                                    permit.send(es);
                                    info!(
                                        "Adopted LowID callback stream from {cb_peer_ip}:{cb_peer_port} into active download {tid} after bounded wait for {hash_hex}",
                                    );
                                    stream_dispatched = true;
                                    break;
                                }
                                Ok(Err(_closed)) => {
                                    debug!(
                                        "Established-stream channel closed for {tid} while waiting; trying next match",
                                    );
                                    closed_senders.push(tid.clone());
                                    pending_stream = Some(es.stream);
                                }
                                Err(_) => {
                                    warn!(
                                        "Established-stream channel full for {tid}; preserving callback stream for another match",
                                    );
                                    pending_stream = Some(es.stream);
                                }
                            }
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(es)) => {
                            debug!(
                                "Established-stream channel closed for {tid}; trying next match",
                            );
                            // Sender is stale; mark for
                            // cleanup and try the next
                            // matching download.
                            closed_senders.push(tid.clone());
                            pending_stream = Some(es.stream);
                        }
                    },
                    None => {
                        debug!(
                            "No established-stream channel for {tid}; trying next match",
                        );
                        pending_stream = Some(est_source.stream);
                    }
                }
            }
            // Reap any closed senders we encountered above
            // so we don't keep retrying them.
            // Reap any closed senders we encountered. A
            // `Closed` on the established channel means the
            // multi-source worker is gone, so the paired
            // metadata sender is also dead — keep both maps
            // in lockstep (see field doc on
            // `active_established_senders`).
            for tid in &closed_senders {
                state.active_established_senders.remove(tid);
                state.active_source_senders.remove(tid);
            }
            // If nothing took the stream it's dropped here
            // (`pending_stream` goes out of scope).
            drop(pending_stream);

            // Only a stream that came from the friend diversion
            // retires a friend request. A genuine server/KAD LowID
            // callback can be adopted for the very same download
            // while a friend connect-back is still outstanding, and
            // treating that as the friend's answer would release the
            // wait (and the retry budget) early.
            if let (true, Some(friend_eh)) = (stream_dispatched, cb_friend_ember_hash) {
                state.friend_xfer_stats.connected =
                    state.friend_xfer_stats.connected.saturating_add(1);
                // The parked row is keyed by the friend's
                // *listening* port while this stream lives on their
                // ephemeral one, so nothing else clears it; left
                // alone it would show as a phantom "waiting" source
                // until the attempt-timeout sweep. Releasing it to
                // `Failed` also restores it as a re-dialable (and
                // re-escalatable) source should this stream die.
                state
                    .friend_xfer_attempts
                    .remove(&(friend_eh, cb_file_hash));
                for tid in matching_tids.clone() {
                    release_friend_connect_sources(
                        state,
                        transfer_manager,
                        app_handle,
                        &tid,
                    )
                    .await;
                }
            }

            if !stream_dispatched {
                // Last-resort: legacy metadata injection.
                // The live stream is gone, so the dial-
                // back will likely fail for true LowID
                // peers — but the call mirrors the
                // pre-fix behaviour and at least registers
                // the peer for SX / future retry rounds.
                let stats = inject_source_into_active_transfers(
                    state,
                    cb_file_hash,
                    &matching_tids,
                    &inject_source,
                    0,
                );
                if stats.injected > 0 {
                    info!(
                        "Injected LowID callback peer {}:{} (metadata-only fallback) into {} active download(s) for {}",
                        inject_source.peer_ip, inject_source.peer_port, stats.injected, hash_hex,
                    );
                } else {
                    debug!("No active download accepts callback peer for {hash_hex}");
                }
            }
        }
    }
}
