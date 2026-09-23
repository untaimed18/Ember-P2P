//! eMule ProcessLocalRequests(): batched TCP OP_GETSOURCES over the server
//! connection, within the shared frame budget.

use super::*;

pub(in crate::network) async fn on_server_tcp_source_tick(
    state: &mut NetworkState,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    stats_manager: &mut StatsManager,
) {
    if state.server_connection.is_none() { return; }
    // Shares the frame budget with the starved re-ask and warm-start
    // paths, so this 4-minute tick is a poll rather than a licence:
    // whichever path last spent the frame sets the floor for all
    // three. See `SERVER_TCP_SRCREQ_INTERVAL_SECS`.
    let srcreq_now = chrono::Utc::now().timestamp();
    if !server_tcp_srcreq_frame_open(state, srcreq_now) { return; }

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
    // at the soft source cap (same gate as UDP/KAD sweeps).
    all_downloads.retain(|(_, _, _, sc)| *sc < MAX_SOURCES_FOR_UDP);
    if all_downloads.is_empty() { return; }
    all_downloads.sort_by_key(|(_, _, _, sc)| *sc);

    let total = all_downloads.len();
    let cursor = state.server_tcp_getsources_cursor % total;
    let batch_size = SERVER_TCP_SRCREQ_MAX_PER_FRAME.min(total);
    let mut sent = 0u32;
    close_server_tcp_srcreq_frame(state, srcreq_now);

    if let Some(conn) = state.server_connection.as_mut() {
        for i in 0..batch_size {
            let idx = (cursor + i) % total;
            let (_, ref fh, file_size, _) = all_downloads[idx];
            match conn.send_get_sources(fh, file_size).await {
                Ok(bytes) => {
                    if bytes > 0 {
                        sent += 1;
                        // Periodic TCP source-asking sweep also counts as
                        // SourceExchange overhead — same wire flow as the
                        // login-time and on-demand requests below.
                        stats_manager.add_overhead(
                            crate::storage::statistics::OverheadCategory::SourceExchange,
                            crate::storage::statistics::OverheadDirection::Upload,
                            bytes,
                        );
                    }
                }
                Err(e) => {
                    // Sequential 30 s-timeout TCP writes on the
                    // network task: continuing past a failure makes
                    // the whole frame cost `batch_size` timeouts
                    // with nothing to show for it. The cursor still
                    // advances, so the next sweep starts elsewhere.
                    warn!(
                        "TCP source batch: OP_GETSOURCES write failed: {e} — abandoning the rest of this frame"
                    );
                    break;
                }
            }
        }
    }

    state.server_tcp_getsources_cursor = (cursor + batch_size) % total;
    if sent > 0 {
        info!("TCP source batch: sent OP_GETSOURCES for {sent}/{batch_size} downloads (cursor at {}/{})", state.server_tcp_getsources_cursor, total);
    }
}
