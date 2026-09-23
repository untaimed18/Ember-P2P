//! The A4AF tick: moves sources between downloads that share them.

use super::*;

pub(in crate::network) async fn on_a4af_tick(
    udp_socket: &Arc<UdpSocket>,
    state: &mut NetworkState,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    a4af_shared: &Arc<RwLock<A4AFManager>>,
    pending_dl_hashes: &Arc<RwLock<Vec<[u8; 16]>>>,
) {
    // A4AF only retasks existing eD2K peer sources. It has no
    // KAD dependency, so a KAD-only status gate silently disabled
    // it for the default server-only configuration. Empty pending
    // downloads/source lists make the work below a no-op.
    let mut file_priorities: HashMap<[u8; 16], ed2k::a4af::FileSwapInfo> = HashMap::new();
    let mut dl_hashes_vec: Vec<[u8; 16]> = Vec::new();

    // Every download a source could be swapped *to* or *from* needs an
    // entry here: `process_swaps` skips a candidate whose target or
    // assigned file is missing from this map.
    //
    // It used to be built from `pending_downloads` alone, while the
    // NNP candidates below are harvested from `per_file_sources` —
    // the *active* downloads, which are a disjoint set (see the
    // `pending_downloads.contains_key` guards on the retry paths). So
    // both halves of every candidate were absent and the swap engine
    // could never act, where eMule reconsiders each `DS_NONEEDEDPARTS`
    // source on every downloading file's `Process()` pass
    // (`PartFile.cpp:2320-2324`).
    let mut swap_files: Vec<(String, [u8; 16])> = Vec::new();
    for (tid, pd) in &state.pending_downloads {
        if let Some(hash) = parse_ed2k_hash16(&pd.file_hash) {
            swap_files.push((tid.clone(), hash));
        }
    }
    for (tid, pfs) in &state.per_file_sources {
        if state.pending_downloads.contains_key(tid) {
            continue;
        }
        swap_files.push((tid.clone(), pfs.file_hash));
    }

    for (tid, hash) in &swap_files {
        let active_sources = state.active_source_senders
            .get(tid)
            .map(|s| s.max_capacity().saturating_sub(s.capacity()))
            .unwrap_or(0);
        let has_active = state.active_source_senders.contains_key(tid);
        let priority = {
            let mgr = transfer_manager.read().await;
            let prio_str = mgr.active.get(tid)
                .map(|t| t.priority.as_str())
                .unwrap_or("normal");
            if prio_str == "auto" {
                let sm = source_manager.read().await;
                let src_count = sm.source_count(hash);
                if src_count > 100 { 2 } else if src_count > 20 { 7 } else { 9 }
            } else {
                match prio_str {
                    "release" => 10,
                    "high" => 9,
                    "low" => 2,
                    "verylow" => 1,
                    _ => 7,
                }
            }
        };
        file_priorities.insert(*hash, ed2k::a4af::FileSwapInfo {
            priority,
            active_source_count: if has_active { active_sources.max(1) } else { 0 },
            // A file we are downloading wants bytes by definition. This
            // is the *file's* appetite, not the peer's usefulness to it
            // — `evaluate_swap` takes that separately as
            // `has_needed_parts_on_assigned`.
            has_needed_parts: true,
        });
        dl_hashes_vec.push(*hash);
    }

    {
        let mut pdh = pending_dl_hashes.write().await;
        *pdh = dl_hashes_vec;
    }

    // Feed NNP sources from persistent per-file lists into A4AF.
    // A source with NNP on file X should be offered to all OTHER
    // active downloads, not back to file X itself.
    //
    // Both sides are collected before the lock is taken, and the
    // dry list is de-duplicated by address. A peer that has run
    // dry on several files is still one candidate per target, so
    // feeding the raw per-file lists in walked every target once
    // per file the peer appeared on, for no added coverage.
    {
        let all_file_hashes: Vec<[u8; 16]> = state.per_file_sources
            .values()
            .map(|pfs| pfs.file_hash)
            .collect();
        let mut seen_dry: HashSet<SocketAddr> = HashSet::new();
        let mut dry_sources: Vec<(SocketAddr, [u8; 16])> = Vec::new();
        for pfs in state.per_file_sources.values() {
            for src in &pfs.sources {
                if matches!(src.state, ed2k::sources::DownloadSourceState::NoneNeededParts) {
                    let addr = SocketAddr::new(src.ip.into(), src.tcp_port);
                    if seen_dry.insert(addr) {
                        dry_sources.push((addr, pfs.file_hash));
                    }
                }
            }
        }
        if !dry_sources.is_empty() {
            a4af_shared
                .write()
                .await
                .offer_dry_sources(&all_file_hashes, &dry_sources);
        }
    }

    // Surface the candidate counts the feed just built, so the `+aa`
    // term of the Sources column reflects them.
    {
        let a4af = a4af_shared.read().await;
        let counts: Vec<(String, u32)> = swap_files
            .iter()
            .map(|(tid, hash)| (tid.clone(), a4af.a4af_count(hash) as u32))
            .collect();
        drop(a4af);
        let mut mgr = transfer_manager.write().await;
        for (tid, count) in counts {
            mgr.set_a4af_count(&tid, count);
        }
    }

    let swaps = {
        let a4af = a4af_shared.read().await;
        a4af.process_swaps(&file_priorities)
    };
    if !swaps.is_empty() {
        info!("A4AF: {} swap actions to execute", swaps.len());
        for swap in &swaps {
            debug!("A4AF swap: {} -> {}", hex::encode(swap.from_file), hex::encode(swap.to_file));
            // Canonical lock order is transfer_manager before
            // source_manager. Do all source_manager mutations and
            // extract the data we need up front, then RELEASE the
            // source write guard before acquiring transfer_manager
            // below — never hold the exclusive source lock across
            // the transfer read await. (Previously `sm` was held
            // across that await, inverting the documented order and
            // stalling upload/download tasks that need the source
            // lock for the duration of each swap.)
            let (uh, co) = {
                let sm = source_manager.read().await;
                if let std::net::IpAddr::V4(v4) = swap.peer_addr.ip() {
                    (
                        sm.get_user_hash(&swap.from_file, v4, swap.peer_addr.port()),
                        sm.get_connect_options(&swap.from_file, v4, swap.peer_addr.port()),
                    )
                } else {
                    (None, None)
                }
            };

            // Inject source into active download if one exists for the target file
            let target_hex = hex::encode(swap.to_file);
            let matching_transfer_ids = {
                let mgr = transfer_manager.read().await;
                matching_active_transfer_ids_for_hash(state, &mgr, &target_hex)
            };
            if !matching_transfer_ids.is_empty() {
                let new_source = ed2k::multi_source::DownloadSource {
                    peer_ip: swap.peer_addr.ip().to_string(),
                    peer_port: swap.peer_addr.port(),
                    available_parts: Vec::new(),
                    peer_user_hash: uh,
                    peer_connect_options: co,
                };
                let stats = inject_source_into_active_transfers(
                    state,
                    swap.to_file,
                    &matching_transfer_ids,
                    &new_source,
                    0,
                );
                if stats.dropped_full > 0 || stats.dropped_closed > 0 {
                    debug!(
                        "A4AF swap: source {} for {} matched {} active downloads, injected={}, preserved={}, full={}, overflowed={}, closed={}",
                        swap.peer_addr,
                        target_hex,
                        stats.matched_transfers,
                        stats.injected,
                        stats.persisted,
                        stats.dropped_full,
                        stats.overflowed,
                        stats.dropped_closed,
                    );
                } else {
                    info!(
                        "A4AF swap: injected {} into {} active download(s) for {}",
                        swap.peer_addr,
                        stats.injected,
                        target_hex,
                    );
                }
            } else {
                // No active download — check pending downloads and reset search timer
                for pd in state.pending_downloads.values_mut() {
                    if pd.file_hash == target_hex {
                        pd.last_search_at = 0;
                        break;
                    }
                }
                info!(
                    "A4AF swap: registered {} for pending download {}",
                    swap.peer_addr, target_hex,
                );
            }

            // Move source between per-file source lists so the
            // persistent reask state follows the swap.
            if let std::net::IpAddr::V4(v4) = swap.peer_addr.ip() {
                let port = swap.peer_addr.port();
                let mut moved_udp_port = 0u16;
                for pfs in state.per_file_sources.values_mut() {
                    if pfs.file_hash == swap.from_file {
                        moved_udp_port = pfs
                            .sources
                            .iter()
                            .find(|s| s.ip == v4 && s.tcp_port == port)
                            .map(|s| s.udp_port)
                            .unwrap_or(0);
                        pfs.sources.retain(|s| !(s.ip == v4 && s.tcp_port == port));
                        break;
                    }
                }
                let (moved_user_hash, moved_connect_options, moved_session_only) = {
                    let sm = source_manager.read().await;
                    (
                        sm.get_user_hash(&swap.from_file, v4, port),
                        sm.get_connect_options(&swap.from_file, v4, port)
                            .unwrap_or(0),
                        sm.is_session_only_port(&swap.from_file, v4, port),
                    )
                };
                {
                    let mut sm = source_manager.write().await;
                    sm.remove_source(&swap.from_file, &v4, port);
                    // Preserve inbound session-only ports across
                    // A4AF moves — registering them as ordinary
                    // reconnectable HighID rows would reintroduce
                    // the ephemeral-port duplication this swap
                    // path was otherwise undoing.
                    if moved_session_only {
                        sm.register_live_session_port(
                            swap.to_file,
                            v4,
                            port,
                            moved_user_hash.unwrap_or([0u8; 16]),
                            moved_connect_options,
                        );
                    } else if let Some(user_hash) = moved_user_hash {
                        // A4AF: the peer itself told us, mid-session,
                        // that it also holds the target file. That is
                        // not something any of the four networks
                        // said, and copying the origin it carries for
                        // the file it was found for would attribute
                        // this one to a network that never mentioned
                        // it. So: no origin.
                        sm.register_source_full_opts(
                            swap.to_file,
                            v4,
                            port,
                            moved_udp_port,
                            user_hash,
                            moved_connect_options,
                            None,
                        );
                    } else {
                        sm.register_source_full(
                            swap.to_file,
                            v4,
                            port,
                            moved_udp_port,
                            [0u8; 16],
                            None,
                        );
                    }
                }
                let mut complete_sources = 0u16;
                for pfs in state.per_file_sources.values_mut() {
                    if pfs.file_hash == swap.to_file {
                        if pfs.add_source_full(v4, port, moved_udp_port) {
                            state.ember_payload_dirty = true;
                        }
                        complete_sources = pfs.complete_source_count();
                        break;
                    }
                }
                if moved_udp_port != 0 {
                    let file_size = state
                        .pending_downloads
                        .values()
                        .find(|pd| pd.file_hash == target_hex)
                        .map(|pd| pd.file_size)
                        .or_else(|| {
                            let mgr = transfer_manager.try_read().ok()?;
                            mgr.active
                                .values()
                                .chain(mgr.queue.iter())
                                .find(|t| t.file_hash == target_hex)
                                .map(|t| t.total_size)
                        })
                        .unwrap_or(0);
                    if file_size > 0 {
                        let Some(reask_payload) = ed2k::messages::build_reask_file_ping(
                            &swap.to_file,
                            file_size,
                            complete_sources,
                            None,
                        ) else {
                            warn!("Skipping swapped UDP reask: file exceeds standard ED2K wire part-count limit");
                            continue;
                        };
                        let mut pkt = vec![OP_EMULEPROT, ed2k::messages::OP_REASKFILEPING];
                        pkt.extend_from_slice(&reask_payload);
                        let addr = SocketAddr::new(v4.into(), moved_udp_port);
                        // Both reply branches resolve the file through
                        // this map, so a reask that skips it has its
                        // answer discarded as unsolicited — the queue
                        // rank and state this swap just asked for.
                        state.pending_udp_reasks.insert(
                            (v4, moved_udp_port),
                            (swap.to_file, chrono::Utc::now().timestamp()),
                        );
                        let _ = udp_socket.send_to(&pkt, addr).await;
                    }
                }
            }
        }
        let mut a4af = a4af_shared.write().await;
        for swap in &swaps {
            a4af.mark_swapped(swap.peer_addr);
            a4af.remove_source(swap.peer_addr);
        }
    }
    {
        let mut a4af = a4af_shared.write().await;
        a4af.cleanup_stale(3600);
    }
}
