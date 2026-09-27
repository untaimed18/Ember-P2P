//! eMule ProcessLocalRequests(): batched TCP OP_GETSOURCES over the server
//! connection, within the shared frame budget.

use super::*;

pub(in crate::network) async fn on_server_tcp_source_tick(
    state: &mut NetworkState,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    stats_manager: &mut StatsManager,
    app_handle: &tauri::AppHandle,
) {
    if state.server_connection.is_none() { return; }
    // Shares the frame budget with the starved re-ask and warm-start
    // paths, so this 4-minute tick is a poll rather than a licence:
    // whichever path last spent the frame sets the floor for all
    // three. See `SERVER_TCP_SRCREQ_INTERVAL_SECS`.
    let srcreq_now = chrono::Utc::now().timestamp();
    if !server_tcp_srcreq_frame_open(state, srcreq_now) { return; }

    // Explicit asks lead the frame, oldest first, as eMule serves
    // `m_localServerReqQueue`. One whose download has gone, or whose file
    // was asked within the per-file floor since it was queued, is dropped.
    let asks = {
        let NetworkState {
            server_tcp_srcreq_asks,
            server_tcp_srcreq_file_at,
            pending_downloads,
            active_source_senders,
            download_handles,
            ..
        } = &mut *state;
        take_frame_source_asks(
            server_tcp_srcreq_asks,
            SERVER_TCP_SRCREQ_MAX_PER_FRAME,
            |tid, fh| {
                (pending_downloads.contains_key(tid)
                    || active_source_senders.contains_key(tid)
                    || download_handles.contains_key(tid))
                    && server_tcp_srcreq_file_due(server_tcp_srcreq_file_at, fh, srcreq_now)
            },
        )
    };
    let mut frame: Vec<(Option<String>, [u8; 16], u64)> = asks
        .into_iter()
        .map(|(tid, fh, file_size)| (Some(tid), fh, file_size))
        .collect();

    // The rest of the frame comes from the sweep's own rotation.
    let room = SERVER_TCP_SRCREQ_MAX_PER_FRAME - frame.len();
    let mut rotation: Option<(usize, usize, usize)> = None;
    if room > 0 {
        let mut all_downloads: Vec<(String, [u8; 16], u64, usize)> = Vec::new();

        {
            let sm = source_manager.read().await;
            for (tid, pd) in &state.pending_downloads {
                if pd.control.is_cancelled() { continue; }
                if let Ok(raw) = hex::decode(&pd.file_hash) {
                    if raw.len() == 16 {
                        let mut fh = [0u8; 16];
                        fh.copy_from_slice(&raw[..16]);
                        let src_count = sm.source_count(&fh);
                        all_downloads.push((tid.clone(), fh, pd.file_size, src_count));
                    }
                }
            }
        }

        // Also include active downloads
        {
            let mgr = transfer_manager.read().await;
            let sm = source_manager.read().await;
            let seen: std::collections::HashSet<String> = all_downloads.iter().map(|(t, _, _, _)| t.clone()).collect();
            for tid in state.active_source_senders.keys() {
                if seen.contains(tid) { continue; }
                if let Some(transfer) = mgr.get_transfer(tid) {
                    if let Ok(raw) = hex::decode(&transfer.file_hash) {
                        if raw.len() == 16 {
                            let mut fh = [0u8; 16];
                            fh.copy_from_slice(&raw[..16]);
                            let src_count = sm.source_count(&fh);
                            all_downloads.push((tid.clone(), fh, transfer.total_size, src_count));
                        }
                    }
                }
            }
        }

        // Prioritize files with fewer sources; skip files already
        // at the soft source cap (same gate as UDP/KAD sweeps), files
        // any path asked the server for within the per-file floor, and
        // files the explicit asks above already put in this frame.
        all_downloads.retain(|(_, fh, _, sc)| {
            *sc < MAX_SOURCES_FOR_UDP
                && server_tcp_srcreq_file_due(&state.server_tcp_srcreq_file_at, fh, srcreq_now)
                && !frame.iter().any(|(_, queued, _)| queued == fh)
        });
        all_downloads.sort_by_key(|(_, _, _, sc)| *sc);

        let total = all_downloads.len();
        if total > 0 {
            let cursor = state.server_tcp_getsources_cursor % total;
            let taken = room.min(total);
            for i in 0..taken {
                let (_, fh, file_size, _) = all_downloads[(cursor + i) % total];
                frame.push((None, fh, file_size));
            }
            rotation = Some((cursor, taken, total));
        }
    }
    if frame.is_empty() { return; }

    let batch_size = frame.len();
    let mut sent = 0u32;
    close_server_tcp_srcreq_frame(state, srcreq_now);

    let mut frame = frame.into_iter();
    while let Some((tid, fh, file_size)) = frame.next() {
        match send_server_get_sources(state, &fh, file_size, srcreq_now) {
            Ok(bytes) => {
                if bytes > 0 {
                    sent += 1;
                    stats_manager.add_overhead(
                        crate::storage::statistics::OverheadCategory::SourceExchange,
                        crate::storage::statistics::OverheadDirection::Upload,
                        bytes,
                    );
                    if let Some(tid) = tid {
                        let _ = app_handle.emit(
                            "transfer:source-search",
                            serde_json::json!({
                                "transfer_id": tid,
                                "kind": "server_query",
                            }),
                        );
                    }
                }
            }
            Err(e) => {
                // The writer queue is full or the session is broken;
                // the rest of the frame would be refused the same way.
                // Explicit asks that did not go out keep their place at
                // the head of the line; the rotation cursor still
                // advances, so the next sweep starts elsewhere.
                warn!(
                    "TCP source batch: OP_GETSOURCES not queued: {e} — abandoning the rest of this frame"
                );
                let unsent: Vec<(String, [u8; 16], u64)> = std::iter::once((tid, fh, file_size))
                    .chain(frame.by_ref())
                    .filter_map(|(tid, fh, file_size)| tid.map(|tid| (tid, fh, file_size)))
                    .collect();
                for ask in unsent.into_iter().rev() {
                    state.server_tcp_srcreq_asks.push_front(ask);
                }
                break;
            }
        }
    }

    if let Some((cursor, taken, total)) = rotation {
        state.server_tcp_getsources_cursor = (cursor + taken) % total;
    }
    if sent > 0 {
        info!("TCP source batch: sent OP_GETSOURCES for {sent}/{batch_size} downloads (cursor at {})", state.server_tcp_getsources_cursor);
    }
}
