//! The bootstrap tick (eMule BigTimer style): KAD bootstrap and self-lookup,
//! firewall and NAT checks, the QUIC listener and connection broker, UPnP
//! upkeep, rendezvous registration, and friend presence and searches.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_bootstrap_tick(
    udp_socket: &Arc<UdpSocket>,
    state: &mut NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    settings: &AppSettings,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    known_files: &KnownFileList,
    firewall_probe_ips: &upload_server::FirewallProbeSet,
    shared_banned_ips: &upload_server::SharedBannedIps,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    ember_hash: [u8; 16],
    ul_event_tx: &mpsc::Sender<UploadEvent>,
    ed25519_pubkey: [u8; 32],
    ed25519_secret_key: [u8; 32],
    bootstrap_attempts: &mut u32,
    hardcoded_bootstrap_backoff_shift: &mut u32,
    inbound_stream_tx: &mpsc::Sender<upload_server::InboundStreamRequest>,
    last_hardcoded_bootstrap_ts: &mut i64,
    last_sampled_bootstrap_ts: &mut i64,
    nat_probe_in_flight: &mut bool,
    nat_probe_packet_tx: &mut Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>,
    nat_probe_result_tx: &mpsc::UnboundedSender<NatProbeResult>,
    nat_probe_started_at: &mut Option<tokio::time::Instant>,
    rendezvous_register_in_flight: &mut bool,
    rendezvous_register_result_tx: &mpsc::UnboundedSender<RendezvousRegisterResult>,
    rendezvous_register_started_at: &mut Option<tokio::time::Instant>,
    sampled_bootstrap_backoff_shift: &mut u32,
    upnp_enabled: bool,
    upnp_maintain_handle: &mut Option<tokio::task::JoinHandle<()>>,
    upnp_maintain_in_flight: &mut bool,
    upnp_maintain_result_tx: &mpsc::UnboundedSender<UpnpMaintainResult>,
    upnp_maintain_started_at: &mut Option<tokio::time::Instant>,
    upnp_mappings: &upnp::UpnpMappings,
) {
    // Only the KAD bootstrap below depends on KAD being up. The
    // friend-presence and friend-search work after this block must
    // not: `stats.status` is only ever advanced by KAD code paths,
    // so a session where the user disconnected KAD sits at
    // `Disconnected` until they reconnect. Returning here left the
    // connection broker unbuilt, no QUIC listener, and the node
    // never registered with rendezvous — friends could not find it
    // at all, with no event emitted to say so.
    'kad_bootstrap: {
    if state.stats.status == NetworkStatus::Disconnected { break 'kad_bootstrap; }
    let table_size = state.routing_table.len();

    if table_size == 0 {
        *bootstrap_attempts += 1;
        if *bootstrap_attempts == 5 {
            warn!("No peers found after {} bootstrap attempts", *bootstrap_attempts);
            // `transient` tells the UI this one resolves on its own,
            // so a later Connected may clear it. The other emitters
            // (bind failures, port-in-use, task panic) describe
            // conditions that persist for the session and must stay
            // on screen even once KAD finishes bootstrapping.
            let _ = app_handle.emit("network-error", serde_json::json!({
                "message": "Unable to connect to the KAD network. Try downloading the latest nodes.dat from Settings > Network.",
                "transient": true,
            }));
        }
    } else {
        *bootstrap_attempts = 0;
    }

    // Self-lookup: FindNode for our own ID to populate close-to-home buckets.
    // eMule: m_tNextSelfLookup = start + MIN2S(3), then + HR2S(4) after each run.
    const SELF_LOOKUP_FIRST_DELAY_SECS: i64 = 3 * 60;
    // Warm-start floor + verified-contact threshold for an early
    // first self-lookup (see below).
    const SELF_LOOKUP_WARM_DELAY_SECS: i64 = 20;
    const SELF_LOOKUP_WARM_VERIFIED: usize = 16;
    const SELF_LOOKUP_REPEAT_SECS: i64 = 4 * 3600;
    let now_ts = chrono::Utc::now().timestamp();
    let self_lookup_due = if !state.self_lookup_done {
        let elapsed = now_ts - state.kad_started_at;
        // eMule waits a flat 3 minutes before the first self-lookup.
        // On a warm start (a populated nodes.dat) the table can be
        // healthy within seconds, so once we already hold a solid
        // set of *verified* contacts there's no reason to idle for
        // the full ceiling — fill the close-to-home buckets right
        // away so we become publishable/discoverable sooner. The
        // 3-minute ceiling still applies as the upper bound for cold
        // starts that bootstrap slowly.
        elapsed >= SELF_LOOKUP_FIRST_DELAY_SECS
            || (elapsed >= SELF_LOOKUP_WARM_DELAY_SECS
                && state.routing_table.verified_len() >= SELF_LOOKUP_WARM_VERIFIED)
    } else {
        now_ts - state.last_self_lookup >= SELF_LOOKUP_REPEAT_SECS
    };
    if table_size >= 2 && self_lookup_due {
        let closest = state.routing_table.find_closest(&state.local_id, SEARCH_INITIAL_CONTACTS);
        if !closest.is_empty() {
            let self_id = state.local_id;
            let sid = start_kad_search(
                state,
                app_handle,
                self_id,
                SearchType::FindNode,
                closest,
            );
            if sid != SearchId(0) {
                info!("Started self-lookup (FindNode for own ID), search {}, table has {table_size} contacts", sid.0);
                state.self_lookup_done = true;
                state.last_self_lookup = now_ts;
            }
        }
    }

    // Yield between major bootstrap sections so Tauri IPC handlers
    // aren't starved in debug builds where this work is slow.
    tokio::task::yield_now().await;

    // Keep bootstrapping until we have a healthy routing table (~200 contacts)
    if table_size < 200 {
        // eMule: only send BootstrapReq to hardcoded nodes while NOT connected.
        // Once connected, rely on FindNode searches and eMule big-timer RandomLookup for growth.
        if state.stats.status != NetworkStatus::Connected {
            let due_interval =
                hardcoded_bootstrap_backoff_interval(*hardcoded_bootstrap_backoff_shift);
            if now_ts - *last_hardcoded_bootstrap_ts >= due_interval {
                *last_hardcoded_bootstrap_ts = now_ts;
                *hardcoded_bootstrap_backoff_shift =
                    hardcoded_bootstrap_backoff_shift.saturating_add(1);
                for contact in &bootstrap::default_bootstrap_contacts() {
                    let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                    let msg = KadMessage::BootstrapReq;
                    if let Ok(packet) = messages::encode_packet(&msg) {
                        if !kad_request_allowed(state, addr, &packet) {
                            continue;
                        }
                        // Track the outgoing request (opcode 0x01) so the
                        // matching `BootstrapRes` (0x09) passes
                        // `validate_response`. The sampled-contact path
                        // below already does this; without it, every
                        // hardcoded-node bootstrap reply was dropped as
                        // "unsolicited", stalling cold-start bootstrap.
                        state.flood_protection.track_request(addr, 0x01);
                        let _ = udp_socket.send_to(&packet, addr).await;
                    }
                }
            }
        } else {
            *hardcoded_bootstrap_backoff_shift = 0;
        }

        // Query a sample of known contacts with BootstrapReq to discover
        // new peers from their routing tables. Same exponential backoff
        // as the hardcoded seeds so a table stuck under 200 does not
        // re-hit the same contacts every 10s for the life of the process.
        let sample_interval =
            hardcoded_bootstrap_backoff_interval(*sampled_bootstrap_backoff_shift);
        if now_ts - *last_sampled_bootstrap_ts >= sample_interval {
            *last_sampled_bootstrap_ts = now_ts;
            *sampled_bootstrap_backoff_shift =
                sampled_bootstrap_backoff_shift.saturating_add(1);
            let bootstrap_sample_size = if table_size < 50 { 10 } else { 5 };
            let sample: Vec<KadContact> = {
                let target = KadId::random();
                state.routing_table.find_closest(&target, bootstrap_sample_size)
            };
            for contact in &sample {
                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                let msg = KadMessage::BootstrapReq;
                if let Ok(packet) = messages::encode_packet(&msg) {
                    if send_kad_packet(udp_socket, &packet, addr, state, &contact.id)
                        .await
                        .is_ok()
                    {
                        state.flood_protection.track_request(addr, 0x01);
                    }
                }
            }
        }
    } else {
        *sampled_bootstrap_backoff_shift = 0;
    }

    tokio::task::yield_now().await;

    // Firewall detection using FirewallChecker
    if !state.firewall_checker.is_checking() && state.firewall_checker.should_recheck() && table_size >= 10 {
        state.firewall_checker.start_check();
        clear_external_udp_for_firewall_recheck(state);
        if let Ok(mut probes) = firewall_probe_ips.lock() { probes.clear(); }
        let checks = state.firewall_checker.checks_to_send() as usize;

        let fw_contacts: Vec<KadContact> = state
            .routing_table
            .all_contacts()
            .filter(|c| c.verified && !c.is_dead())
            .take(checks)
            .cloned()
            .collect();
        let fw_tcp_port = advertised_tcp_port(state);
        for contact in &fw_contacts {
            let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
            let (msg, track_opcode) = if contact.version > KADEMLIA_VERSION6_49ABETA {
                (KadMessage::Firewalled2Req {
                    tcp_port: fw_tcp_port,
                    user_hash: state.user_hash,
                    connect_options: build_kad_connect_options(state),
                }, 0x53u8)
            } else {
                (KadMessage::FirewalledReq { tcp_port: fw_tcp_port }, 0x50u8)
            };
            if let Ok(packet) = messages::encode_packet(&msg) {
                // In the probe set before the request leaves, since the peer's
                // connect-back races our return from the send; out again if it
                // never left, so the checker waits only on requests it made.
                let newly_probed = firewall_probe_ips
                    .lock()
                    .is_ok_and(|mut probes| probes.insert(contact.ip));
                if send_kad_packet(udp_socket, &packet, addr, state, &contact.id)
                    .await
                    .is_ok()
                {
                    state.flood_protection.track_request(addr, track_opcode);
                    state.firewall_checker.record_tcp_request_sent(contact.ip);
                } else if newly_probed {
                    if let Ok(mut probes) = firewall_probe_ips.lock() {
                        probes.remove(&contact.ip);
                    }
                }
            }
        }
        let udp_contacts: Vec<KadContact> = state
            .routing_table
            .all_contacts()
            .filter(|c| c.verified && !c.is_dead())
            .skip(checks)
            .take(checks)
            .cloned()
            .collect();
        for contact in &udp_contacts {
            let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
            let msg = KadMessage::Ping;
            if let Ok(packet) = messages::encode_packet(&msg) {
                if send_kad_packet(udp_socket, &packet, addr, state, &contact.id)
                    .await
                    .is_ok()
                {
                    state.flood_protection.track_request(addr, 0x60);
                    state.firewall_checker.record_udp_port_probe_sent();
                }
            }
        }
        // Eagerly dispatch UDP firewall probes now. If a previous
        // cycle already learned the external UDP port it is still
        // available in firewall_checker; otherwise the function
        // falls back to settings.udp_port.  The Pong handler will
        // also call dispatch again once fresh pongs refine the port.
        dispatch_udp_firewall_probe_requests(state, app_handle, settings);
    }

    if state.firewall_checker.evaluate() {
        let was_tcp_fw = state.firewalled;
        let had_ip = state.external_ip.is_some();
        state.firewalled = state.firewall_checker.tcp_firewalled();
        state.udp_firewalled = state.firewall_checker.udp_firewalled();
        // The UI "Firewalled" badge reflects TCP reachability (HighID vs LowID),
        // matching eMule's traditional meaning.  TCP/UDP Reachability are shown
        // separately in the UI for detailed status.
        state.stats.firewalled = state.firewalled;
        state.firewalled_shared.store(state.firewalled, std::sync::atomic::Ordering::Relaxed);
        kad::firewall::publish_local_firewall(state.firewalled, state.udp_firewalled);
        update_publish_manager_state(state);
        let tcp_status = state.firewall_checker.tcp_status();
        let udp_status = state.firewall_checker.udp_status();
        state.stats.tcp_status = format!("{:?}", tcp_status);
        state.stats.udp_status = format!("{:?}", udp_status);
        if let Some(ip) = state.firewall_checker.external_ip() {
            // KAD votes fill a gap; they must not displace HighID or STUN.
            if state.external_ip.is_none() {
                set_external_ip(state, Some(ip));
                state.stats.external_ip = ip.to_string();
            }
        }
        info!("Firewall check result: TCP={:?} UDP={:?} (ports tcp={} udp={})",
            tcp_status, udp_status, state.tcp_port, state.udp_port);
        // Initial NAT probe as soon as we learn our external IP
        if !had_ip && state.external_ip.is_some() && state.nat_info.nat_type == ember::nat::NatType::Unknown {
            if !*nat_probe_in_flight {
                info!("External IP discovered via firewall check — scheduling initial NAT probe");
                *nat_probe_in_flight = true;
                *nat_probe_started_at = Some(tokio::time::Instant::now());
                state.nat_probe_generation =
                    state.nat_probe_generation.saturating_add(1);
                *nat_probe_packet_tx = Some(spawn_nat_probe(
                    udp_socket.clone(),
                    nat_probe_result_tx.clone(),
                    state.nat_probe_generation,
                    "firewall check",
                ));
            }
        }
        // Always publish after evaluate — tcp/udp can move
        // Unknown→Open/Firewalled without flipping aggregate
        // `firewalled` (e.g. UPnP already cleared it).
        let _ = app_handle.emit("firewall-status", serde_json::json!({
            "firewalled": state.firewalled,
            "external_ip": state.stats.external_ip,
            "tcp_status": format!("{:?}", tcp_status),
            "udp_status": format!("{:?}", udp_status),
        }));
        if was_tcp_fw && !state.firewalled {
            if state.buddy_manager.state() == BuddyState::FindingBuddy {
                state.buddy_manager.find_failed();
                info!("Cancelled buddy search: TCP firewall is open, no buddy needed");
            }
        }
    }

    tokio::task::yield_now().await;

    // Sync firewalled status from TCP connect-back detection or UPnP.
    // Only allow the atomic to CLEAR the firewalled flag, never re-assert it,
    // so it doesn't overwrite the FirewallChecker's determination.
    //
    // Real KAD probe connect-backs set `tcp_connect_back_shared`; that is
    // the only path that promotes `tcp_status` to Open here. UPnP clearing
    // `firewalled_shared` may clear the aggregate firewalled flag, but must
    // not pretend a connect-back happened. An active LowID session must not
    // be overridden by UPnP optimism — but a real connect-back still updates
    // KAD `tcp_status` so proof is not discarded.
    let connect_back = state
        .tcp_connect_back_shared
        .swap(false, std::sync::atomic::Ordering::Relaxed);
    let fw_from_shared = state.firewalled_shared.load(std::sync::atomic::Ordering::Relaxed);
    if state.low_id {
        if !fw_from_shared {
            state.firewalled_shared.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        if !state.firewalled {
            state.firewalled = true;
            // Re-assert LowID aggregate firewalled, but do not erase
            // KAD/server TCP Open proof via note_tcp_firewalled.
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
        }
        // Keep ed2k LowID/firewalled sticky, but still record KAD TCP
        // reachability proof so it survives until HighID / disconnect.
        if connect_back {
            info!("TCP connect-back during LowID — updating tcp_status only");
            state.firewall_checker.handle_tcp_connect_back();
            state.stats.tcp_status =
                format!("{:?}", state.firewall_checker.tcp_status());
            state.stats.udp_status =
                format!("{:?}", state.firewall_checker.udp_status());
            let _ = app_handle.emit("firewall-status", serde_json::json!({
                "firewalled": state.firewalled,
                "external_ip": state.stats.external_ip,
                "tcp_status": state.stats.tcp_status,
                "udp_status": state.stats.udp_status,
            }));
        }
    } else if connect_back {
        if state.firewalled {
            info!("TCP connect-back confirms port open, clearing TCP firewalled status");
            state.firewalled = false;
        } else {
            info!("TCP connect-back confirms port open (updating tcp_status)");
        }
        state.firewalled_shared.store(false, std::sync::atomic::Ordering::Relaxed);
        state.firewall_checker.handle_tcp_connect_back();
        update_publish_manager_state(state);
        state.stats.firewalled = state.firewalled;
        if let Some(ip) = state.external_ip {
            state.stats.external_ip = ip.to_string();
        }
        state.stats.upnp_mapped = state.upnp_mapped;
        let tcp_status = state.firewall_checker.tcp_status();
        let udp_status = state.firewall_checker.udp_status();
        state.stats.tcp_status = format!("{:?}", tcp_status);
        state.stats.udp_status = format!("{:?}", udp_status);
        let _ = app_handle.emit("firewall-status", serde_json::json!({
            "firewalled": state.firewalled,
            "external_ip": state.stats.external_ip,
            "tcp_status": format!("{:?}", tcp_status),
            "udp_status": format!("{:?}", udp_status),
        }));
    } else if state.firewalled && !fw_from_shared {
        // UPnP (or similar) cleared the shared flag without a
        // connect-back — drop the aggregate firewalled badge only.
        info!("Clearing firewalled flag (UPnP/shared), leaving tcp_status unchanged");
        state.firewalled = false;
        update_publish_manager_state(state);
        state.stats.firewalled = false;
        let _ = app_handle.emit("firewall-status", serde_json::json!({
            "firewalled": state.firewalled,
            "external_ip": state.stats.external_ip,
            "tcp_status": state.stats.tcp_status,
            "udp_status": state.stats.udp_status,
        }));
    }

    let count = state.routing_table.len() as u32;
    info!("Routing table: {count} contacts");
    promote_kad_connected_and_first_publish(
        state,
        app_handle,
        local_index,
        transfer_manager,
        known_files,
    )
    .await;

    // Start initial KAD source searches for pending downloads once KAD
    // is Connected (not merely Connecting / nodes.dat loaded).
    if state.stats.status == NetworkStatus::Connected
        && count > 0
        && !state.kad_initial_source_burst_done
        && !state.pending_downloads.is_empty()
    {
            let pending_count = state.pending_downloads.len();
            info!("KAD connected: triggering source search for {pending_count} pending downloads");
            let now = chrono::Utc::now().timestamp();
            let mut tids: Vec<String> = state.pending_downloads.keys().cloned().collect();
            let mut kad_started = 0usize;
            let mut kad_capacity_blocked = false;
            const MAX_INITIAL_KAD: usize = 20;
            if tids.len() > MAX_INITIAL_KAD {
                let rotate_by = state.kad_source_search_cursor % tids.len();
                tids.rotate_left(rotate_by);
                state.kad_source_search_cursor = state.kad_source_search_cursor.wrapping_add(MAX_INITIAL_KAD);
            }
            for tid in tids {
                let (hash_bytes, file_size) = {
                    let Some(pd) = state.pending_downloads.get_mut(&tid) else { continue; };
                    if pd.control.is_cancelled() { continue; }
                    let hash_bytes = match hex::decode(&pd.file_hash) {
                        Ok(b) if b.len() == 16 => b,
                        _ => continue,
                    };
                    (hash_bytes, pd.file_size)
                };

                let mut did_search = false;
                let mut file_hash_arr = [0u8; 16];
                file_hash_arr.copy_from_slice(&hash_bytes[..16]);

                if kad_started < MAX_INITIAL_KAD {
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
                            state.download_source_searches.insert(sid, (tid.clone(), file_hash_arr));
                            kad_started += 1;
                            did_search = true;
                        } else {
                            // Search manager at capacity — defer the rest of
                            // the burst so we retry when a slot frees instead
                            // of treating this as a completed empty search.
                            kad_capacity_blocked = true;
                            warn!(
                                "FindSource for pending download {} deferred: active search cap reached",
                                tid
                            );
                        }
                    }
                }

                let mut fh = [0u8; 16];
                fh.copy_from_slice(&hash_bytes);
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

                if did_search {
                    if let Some(pd) = state.pending_downloads.get_mut(&tid) {
                        pd.search_count += 1;
                        pd.last_search_at = now;
                    }
                }
            }
            // Only mark the burst done when every attempted KAD start
            // either succeeded or had an empty closest set. Capacity
            // rejects leave the flag clear so the next tick retries.
            if !kad_capacity_blocked {
                state.kad_initial_source_burst_done = true;
            }
            if pending_count > MAX_INITIAL_KAD {
                info!("Started {kad_started} KAD searches initially; remaining {} will search on next retry cycle", pending_count - kad_started);
            }
    }
    state.stats.connected_peers = count;
    } // 'kad_bootstrap

    // Register with the rendezvous server as soon as we have a
    // confirmed external IP so other Ember clients can find us.
    if !state.friend_presence_initial_done
        && state.external_ip.is_some()
        && !*rendezvous_register_in_flight
    {
        // Initialize the LowID-to-LowID connection broker
        // **before** registering with rendezvous. Rendezvous
        // advertises the port other clients should QUIC-dial,
        // so we have to know the QUIC endpoint's actual bound
        // port first — `build_server_client_endpoint` may
        // fall back from `tcp_port` if it's already in use
        // (e.g. tcp_port == udp_port).
        if state.connection_broker.is_none() {
            // Capacity 1024 (was 32): every broker producer
            // already calls `try_send`, so the cap acts as
            // pure cushion against burst bookkeeping events
            // (StartRelay / ConnectionReady / *Failed). Small
            // caps used to drop legitimate
            // events under load; this gives the periodic
            // drain plenty of headroom while staying well
            // under the per-attempt MAX_ACTIVE_ATTEMPTS=8.
            let (broker_tx, broker_rx) = mpsc::channel(1024);
            let mut broker = ember::broker::ConnectionBroker::new(
                settings.rendezvous_url.clone(),
                broker_tx,
            );

            match ember::quic::generate_self_signed_cert(&ed25519_secret_key) {
                Ok((cert_der, key_der)) => {
                    match ember::quic::build_server_client_endpoint(
                        &cert_der,
                        &key_der,
                        state.tcp_port,
                        true,
                    ).await {
                        Ok((ep, public_port)) => {
                            let bound_port = ep
                                .local_addr()
                                .map(|a| a.port())
                                .unwrap_or(state.tcp_port);
                            state.quic_port = Some(bound_port);
                            // Only the socket's own STUN reading can
                            // say where a peer reaches QUIC; see
                            // `advertised_quic_port`.
                            state.quic_public_port = public_port;
                            let ep_arc = std::sync::Arc::new(ep);
                            broker.set_quic_endpoint(ep_arc.clone());
                            tracing::info!(
                                "Broker: QUIC server+client endpoint ready on UDP port {bound_port}",
                            );

                            let relay_mgr = state.relay_manager.clone();
                            let quic_cb_tx = inbound_stream_tx.clone();
                            tokio::spawn(ember::relay::run_quic_accept_loop(
                                ep_arc,
                                relay_mgr,
                                quic_cb_tx,
                                friend_hashes.clone(),
                                // The accept task cannot reach
                                // `NetworkState`, so the operator's
                                // filter and ban list travel to it
                                // as the same shared handles the
                                // eD2K listener reads. Without
                                // them the Ember transport ignored
                                // both, and a relay target — an
                                // address a remote peer names for
                                // us to dial — was checked only
                                // for being publicly routable.
                                ember::relay::RelayAddressPolicy {
                                    ip_filter: state.shared_ip_filter.clone(),
                                    banned_ips: shared_banned_ips.clone(),
                                    filter_incoming: state
                                        .filter_incoming_shared
                                        .clone(),
                                },
                                bandwidth_limiter.clone(),
                                // Chat attachments are served on
                                // this endpoint too. The loop cannot
                                // reach `NetworkState`, so the grant
                                // table and our identity key travel
                                // to it the same way the operator's
                                // filter does.
                                Some(ember::relay::AttachServeContext {
                                    db: db.clone(),
                                    our_ed25519_seed: ed25519_secret_key,
                                    app_handle: app_handle.clone(),
                                }),
                                Some(ember::relay::RoomXferServeContext {
                                    grants: state.xfer_grants.clone(),
                                }),
                            ));
                            tracing::info!("QUIC accept loop spawned");

                            // Windows Firewall already allows KAD UDP
                            // (`udp_port`) and, at startup, anticipated
                            // QUIC on `tcp_port`. If bind landed on a
                            // fallback neighbour, open that port too —
                            // otherwise inbound punch/relay is dropped
                            // even when UPnP forwarded it.
                            #[cfg(target_os = "windows")]
                            {
                                let fw_quic = bound_port;
                                let fw_kad_udp = state.udp_port;
                                tokio::task::spawn_blocking(move || {
                                    crate::security::firewall::ensure_quic_udp_firewall_rule(
                                        fw_quic, fw_kad_udp,
                                    );
                                });
                            }

                            // Forward the QUIC UDP port via UPnP. QUIC binds
                            // its socket here — after the initial UPnP setup
                            // and on a port distinct from the KAD UDP port —
                            // so without this, inbound QUIC (relay target /
                            // hole-punch accept) stays unreachable behind NAT
                            // even when TCP/KAD are mapped. Called even when
                            // no gateway is known yet: `map_quic_port` then
                            // just records the port so the periodic
                            // `maintain` maps it once discovery succeeds.
                            if upnp_enabled && !*upnp_maintain_in_flight {
                                let mut mappings = upnp_mappings.clone();
                                let revision = mappings.revision();
                                let tx = upnp_maintain_result_tx.clone();
                                *upnp_maintain_in_flight = true;
                                *upnp_maintain_started_at =
                                    Some(tokio::time::Instant::now());
                                *upnp_maintain_handle = Some(tokio::spawn(async move {
                                    let mapped = mappings.map_quic_port(bound_port).await;
                                    if mapped {
                                        tracing::info!("UPnP: QUIC UDP port {bound_port} mapped");
                                    }
                                    let _ = tx.send(UpnpMaintainResult {
                                        revision,
                                        mappings,
                                        mapped,
                                    });
                                }));
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Broker: failed to create QUIC endpoint: {e}");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Broker: failed to generate QUIC cert: {e}");
                }
            }

            // Publish the QUIC endpoint to spawned friend-dial
            // tasks — see `FriendNatContext`. Broker creation
            // only happens once per session (this is the sole
            // `state.connection_broker = Some(..)` site), but a
            // dial spawned before this point would otherwise
            // have captured `quic_endpoint: None` forever.
            if let Some(ep) = broker.quic_endpoint() {
                let mut ctx = state.friend_nat_context.write().unwrap_or_else(|p| p.into_inner());
                ctx.quic_endpoint = Some(ep.clone());
                ctx.quic_public_port = state.quic_public_port;
            }
            state.connection_broker = Some(broker);
            state.broker_event_rx = Some(broker_rx);
        }

        // Advertise our TCP listener port. Friend dialers
        // call `friend_connect::open_and_run_friend_session`,
        // which opens a `TcpStream` to whatever (ip, port)
        // the rendezvous lookup returns and immediately does
        // the Hello / HelloAnswer / EmuleInfo / OP_EMBER_HELLO
        // handshake over TCP. Earlier this site used
        // `state.quic_port.unwrap_or(settings.tcp_port)`,
        // which silently broke every node whose QUIC
        // endpoint had to fall back to a different port
        // (the common cause is `tcp_port == udp_port` —
        // Kad UDP grabs the port first, QUIC binds on
        // `tcp_port + 1`, the warning at startup is
        // exactly that). On those nodes the rendezvous
        // entry advertised a UDP/QUIC port that has no
        // TCP listener at all, so any friend dialing us
        // saw "waiting for HelloAnswer" timeouts and the
        // user reported "it never finds my friend
        // online". The QUIC port is still discovered via
        // the broker / relay path, which has its own
        // `(ip, advertised_port)` keying — rendezvous is
        // exclusively about friend-presence over TCP.
        // `advertised_tcp_port` (not the raw `settings.tcp_port`)
        // so a STUN-confirmed CGNAT/full-cone remap is what
        // friends actually get told to dial — still "the TCP
        // listener port" per the rationale above, just the
        // correct current value of it.
        let rv_url = settings.rendezvous_url.clone();
        let rv_port = advertised_tcp_port(state);
        let rv_udp_port = advertised_udp_port(state);
        let rv_hash = ember_hash;
        // The outer `if !state.friend_presence_initial_done
        // && state.external_ip.is_some()` already guarantees
        // `external_ip` is `Some` here. The expect is purely
        // a tripwire in case the gate is ever loosened —
        // rendezvous::register now requires a confirmed
        // IPv4 (no client_ip fallback on the server) so we
        // must never spawn this task without one.
        // The outer gate already requires external_ip.is_some();
        // guard defensively so a future change there degrades to
        // "not discoverable yet" instead of panicking this task.
        //
        // Never registered, so there is no success clock: the failure
        // backoff alone decides, or a server that is down or 503ing gets
        // every unregistered client retrying on every tick.
        let initial_retry_due = register_retry_due(
            None,
            state.rendezvous_last_attempt.map(|t| t.elapsed()),
            state.rendezvous_register_fail_streak,
            &ember_hash,
        );
        match state.external_ip {
        _ if !initial_retry_due => {}
        Some(rv_ip) => {
            let rv_pubkey = ed25519_pubkey;
            let rv_secret = ed25519_secret_key;
            let rv_focused = state.channel_focused;
            let rv_beat = state.rendezvous_room_beat;
            let tx = rendezvous_register_result_tx.clone();
            *rendezvous_register_in_flight = true;
            *rendezvous_register_started_at = Some(tokio::time::Instant::now());
            state.rendezvous_last_attempt = Some(std::time::Instant::now());
            state.rendezvous_register_generation =
                state.rendezvous_register_generation.saturating_add(1);
            let generation = state.rendezvous_register_generation;
            let rv_db = db.clone();
            tokio::spawn(async move {
                let (rv_friends, rv_channel_neighbors) =
                    load_rendezvous_register_targets(&rv_db, rv_pubkey, rv_focused, rv_beat)
                        .await;
                let result =
                    crate::network::friends::register_presence(
                        rv_db,
                        &rv_url,
                        &rv_hash,
                        rv_port,
                        rv_udp_port,
                        rv_ip,
                        &rv_pubkey,
                        &rv_secret,
                        &rv_friends,
                        &rv_channel_neighbors,
                    )
                        .await;
                let _ = tx.send(RendezvousRegisterResult {
                    generation,
                    initial: true,
                    result,
                });
            });
        }
        None => {
            debug!("Initial rendezvous register skipped: external_ip unexpectedly None");
        }
        }
    }

    // Presence heartbeat on this 10s timer so the 120s constant is
    // what we actually honour. `should_refresh_presence` still
    // refuses until `PRESENCE_HEARTBEAT_SECS` have elapsed since
    // the last *success*, so steady-state `/register` mutations
    // stay one per that interval. Failed attempts clear that
    // clock so the first retry is a single bootstrap tick; after
    // that [`presence_failure_retry_secs`] doubles 10→20→40→80
    // and caps at the success interval.
    if *rendezvous_register_in_flight
        && rendezvous_register_started_at
            .is_some_and(|started| started.elapsed() > RENDEZVOUS_REGISTER_WATCHDOG)
    {
        warn!("Rendezvous registration exceeded watchdog timeout; allowing retry");
        state.rendezvous_register_generation =
            state.rendezvous_register_generation.saturating_add(1);
        *rendezvous_register_in_flight = false;
        *rendezvous_register_started_at = None;
    }
    if should_refresh_presence(
        state.friend_presence_initial_done,
        *rendezvous_register_in_flight,
        state.rendezvous_last_register.map(|t| t.elapsed()),
    ) && register_retry_due(
        state.rendezvous_last_register.map(|t| t.elapsed()),
        state.rendezvous_last_attempt.map(|t| t.elapsed()),
        state.rendezvous_register_fail_streak,
        &ember_hash,
    ) {
        if let Some(rv_ip) = state.external_ip {
            let rv_url = settings.rendezvous_url.clone();
            let rv_port = advertised_tcp_port(state);
            let rv_udp_port = advertised_udp_port(state);
            let rv_hash = ember_hash;
            let rv_pubkey = ed25519_pubkey;
            let rv_secret = ed25519_secret_key;
            let rv_focused = state.channel_focused;
            let rv_beat = state.rendezvous_room_beat;
            let tx = rendezvous_register_result_tx.clone();
            *rendezvous_register_in_flight = true;
            *rendezvous_register_started_at = Some(tokio::time::Instant::now());
            state.rendezvous_last_attempt = Some(std::time::Instant::now());
            state.rendezvous_register_generation =
                state.rendezvous_register_generation.saturating_add(1);
            let generation = state.rendezvous_register_generation;
            let rv_db = db.clone();
            tokio::spawn(async move {
                let (rv_friends, rv_channel_neighbors) =
                    load_rendezvous_register_targets(&rv_db, rv_pubkey, rv_focused, rv_beat)
                        .await;
                let result = crate::network::friends::register_presence(
                    rv_db,
                    &rv_url,
                    &rv_hash,
                    rv_port,
                    rv_udp_port,
                    rv_ip,
                    &rv_pubkey,
                    &rv_secret,
                    &rv_friends,
                    &rv_channel_neighbors,
                )
                .await;
                let _ = tx.send(RendezvousRegisterResult {
                    generation,
                    initial: false,
                    result,
                });
            });
        } else {
            debug!("Rendezvous heartbeat skipped: external_ip not currently known");
        }
    }

    // Startup presence sweep: every friend gets a rendezvous lookup
    // once Ember has an external IP, so the friend list opens with
    // real online state instead of whatever the last session left.
    //
    // Queued rather than searched outright, and drained a few per
    // tick below. This used to look up three friends and call it a
    // burst, which left everyone after the third looking offline
    // until the five-minute auto-retry reached them — ten per
    // sweep, so a forty-friend list took twenty minutes to
    // resolve, and the log claimed all of them had been looked up.
    //
    // Not before a dial can actually reach a friend behind a NAT, though:
    // see `startup_sweep_ready`.
    if !state.friend_search_initial_done
        && state.external_ip.is_some()
    {
        let waited = state
            .friend_search_waiting_since
            .get_or_insert_with(std::time::Instant::now)
            .elapsed();
        let punch_inputs_ready = state
            .friend_nat_context
            .read()
            .map(|ctx| ctx.external_addr.is_some() && ctx.quic_endpoint.is_some())
            .unwrap_or(false);
        if startup_sweep_ready(state.rendezvous_registered, punch_inputs_ready, waited) {
            state.friend_search_initial_done = true;
            state.friend_search_started_at = Some(std::time::Instant::now());
            state.friend_search_initial_queue =
                friend_hashes.read().await.iter().copied().collect();
            if !state.friend_search_initial_queue.is_empty() {
                info!(
                    "Startup friend presence sweep: {} friend(s) queued, {} per tick \
                     ({:.0}s after the external IP; registered: {}, NAT traversal ready: {})",
                    state.friend_search_initial_queue.len(),
                    INITIAL_FRIEND_SEARCH_PER_TICK,
                    waited.as_secs_f64(),
                    state.rendezvous_registered,
                    punch_inputs_ready,
                );
            }
        }
    }

    // One follow-up pass over whoever the sweep left offline, a minute after
    // its last lookup went out. A friend who launched at the same moment we
    // did was not registered yet when we looked them up; without this they
    // waited for the five-minute auto-retry. Anyone online or still being
    // dialled is passed over by the drain below.
    if state.friend_search_initial_done
        && !state.friend_search_followup_done
        && state.friend_search_initial_queue.is_empty()
    {
        let now = std::time::Instant::now();
        match state.friend_search_followup_at {
            None => state.friend_search_followup_at = Some(now + STARTUP_SWEEP_FOLLOWUP_AFTER),
            Some(due) if now >= due => {
                state.friend_search_followup_done = true;
                state.friend_search_followup_at = None;
                state.friend_search_initial_queue =
                    friend_hashes.read().await.iter().copied().collect();
                debug!(
                    "Startup friend presence follow-up: re-checking {} friend(s)",
                    state.friend_search_initial_queue.len()
                );
            }
            Some(_) => {}
        }
    }

    if !state.friend_search_initial_queue.is_empty() {
        let friends_now = friend_hashes.read().await.clone();
        let sessions = state.ember_sessions.read().await;
        // Drained into a local list first, because
        // `spawn_rendezvous_friend_lookup` borrows the whole state
        // and the queue cannot still be held open across it.
        let targets = drain_initial_friend_search(
            &mut state.friend_search_initial_queue,
            INITIAL_FRIEND_SEARCH_PER_TICK,
            |fh| {
                !friends_now.contains(fh)
                    || state.online_friends.contains_key(fh)
                    || sessions.get(fh).is_some_and(|h| h.is_fresh())
                    || state.outbound_session_tasks.contains_key(fh)
            },
        );
        drop(sessions);

        for target_hash in &targets {
            state.outbound_session_tasks.insert(*target_hash, std::time::Instant::now());
            let _ = app_handle.emit("ember:friend-searching", serde_json::json!({
                "user_hash": hex::encode(target_hash),
            }));
            spawn_rendezvous_friend_lookup(
                settings, state, ember_hash, *target_hash,
                app_handle, friend_hashes, ul_event_tx,
                ed25519_pubkey, ed25519_secret_key,
            );
        }
    }

}

/// Most the failure backoff is stretched, in thousandths: up to half again.
const REGISTER_RETRY_JITTER_MAX_PERMILLE: u32 = 500;

/// How far this node stretches the failure backoff at `fail_streak`.
///
/// Every client loses the server at the same moment, so unjittered they all
/// come back on the same schedule. Derived from our hash and the streak rather
/// than rolled per tick: a fresh roll on every 10 s tick would make each tick a
/// coin flip and collapse the spread back towards the base interval.
fn register_retry_jitter_permille(ember_hash: &[u8; 16], fail_streak: u32) -> u32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ember/rendezvous-register-retry-jitter");
    hasher.update(ember_hash);
    hasher.update(&fail_streak.to_le_bytes());
    let digest = hasher.finalize();
    let bytes = digest.as_bytes();
    u32::from(u16::from_le_bytes([bytes[0], bytes[1]])) % (REGISTER_RETRY_JITTER_MAX_PERMILLE + 1)
}

/// [`presence_failure_retry_due`] with this node's jitter applied to the
/// failure backoff. The success-path interval is left exact.
fn register_retry_due(
    since_last_register: Option<std::time::Duration>,
    since_last_attempt: Option<std::time::Duration>,
    fail_streak: u32,
    ember_hash: &[u8; 16],
) -> bool {
    let jitter = register_retry_jitter_permille(ember_hash, fail_streak);
    // Shrinking the elapsed time by the stretch factor is the same test as
    // stretching the backoff it is compared against.
    presence_failure_retry_due(
        since_last_register,
        since_last_attempt.map(|elapsed| elapsed * 1000 / (1000 + jitter)),
        fail_streak,
    )
}

#[cfg(test)]
mod register_retry_tests {
    use super::*;
    use std::time::Duration;

    const HASH: [u8; 16] = [7; 16];

    #[test]
    fn the_first_attempt_is_immediate() {
        assert!(register_retry_due(None, None, 0, &HASH));
    }

    #[test]
    fn a_failed_first_registration_backs_off_like_a_failed_heartbeat() {
        for streak in 1..8u32 {
            let base = Duration::from_secs(presence_failure_retry_secs(streak));
            assert!(
                !register_retry_due(None, Some(base - Duration::from_millis(1)), streak, &HASH),
                "streak {streak} retried before its backoff"
            );
            let stretched = base * (1000 + REGISTER_RETRY_JITTER_MAX_PERMILLE) / 1000;
            assert!(
                register_retry_due(None, Some(stretched + Duration::from_millis(1)), streak, &HASH),
                "streak {streak} still waiting past the jitter ceiling"
            );
        }
    }

    #[test]
    fn a_reset_backoff_lets_the_first_registration_go_straight_out() {
        // What a disconnect after a run of failed heartbeats used to leave behind.
        let carried_streak = 6;
        let carried_attempt = Some(Duration::from_secs(30));
        assert!(!register_retry_due(None, carried_attempt, carried_streak, &HASH));
        // The disconnect handler clears the streak and the attempt clock.
        assert!(register_retry_due(None, None, 0, &HASH));
    }

    #[test]
    fn a_live_success_clock_is_not_jittered() {
        assert!(register_retry_due(Some(Duration::ZERO), Some(Duration::ZERO), 9, &HASH));
    }

    #[test]
    fn jitter_is_bounded_stable_and_differs_between_nodes() {
        let mut distinct = std::collections::HashSet::new();
        for n in 0..64u8 {
            let hash = [n; 16];
            let j = register_retry_jitter_permille(&hash, 3);
            assert!(j <= REGISTER_RETRY_JITTER_MAX_PERMILLE);
            assert_eq!(j, register_retry_jitter_permille(&hash, 3));
            distinct.insert(j);
        }
        assert!(distinct.len() > 16, "jitter barely varies across nodes: {distinct:?}");
    }
}
