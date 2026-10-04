//! Periodic UDP source requests to eD2K servers (eMule UDPSERVERREASKTIME).

use super::*;

pub(in crate::network) async fn on_server_udp_source_tick(
    state: &mut NetworkState,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
) {
    if !network_ready_for_sources(state) {
        return;
    }
    let mut all_for_udp: Vec<([u8; 16], u64)> = state.pending_downloads.values()
        .filter(|pd| !pd.control.is_cancelled())
        .filter_map(|pd| {
            let hash_bytes = hex::decode(&pd.file_hash).ok()?;
            if hash_bytes.len() != 16 {
                return None;
            }
            let mut fh = [0u8; 16];
            fh.copy_from_slice(&hash_bytes);
            Some((fh, pd.file_size))
        })
        .collect();

    // Also query servers for active downloads (not just pending)
    {
        let mgr = transfer_manager.read().await;
        let mut seen: std::collections::HashSet<[u8; 16]> = all_for_udp.iter().map(|(fh, _)| *fh).collect();
        for tid in state.active_source_senders.keys() {
            if let Some(transfer) = mgr.get_transfer(tid) {
                if let Ok(hash_bytes) = hex::decode(&transfer.file_hash) {
                    if hash_bytes.len() == 16 {
                        let mut fh = [0u8; 16];
                        fh.copy_from_slice(&hash_bytes);
                        if seen.insert(fh) {
                            all_for_udp.push((fh, transfer.total_size));
                        }
                    }
                }
            }
        }
    }

    if all_for_udp.is_empty() { return; }
    let total_downloads = all_for_udp.len();
    // Filter out files that already have enough sources
    let mut need_sources: Vec<([u8; 16], u64)> = Vec::new();
    {
        let sm = source_manager.read().await;
        for (fh, file_size) in all_for_udp {
            if sm.wants_more_sources(&fh) {
                need_sources.push((fh, file_size));
            }
        }
    }
    if !need_sources.is_empty() {
        // eMule packs multiple file hashes per server packet (up to 35)
        let packets = build_all_getsources_packets_multi(state, &need_sources);
        if !packets.is_empty() {
            let room = MAX_UDP_SOURCE_QUEUE.saturating_sub(state.udp_source_queue.len());
            let queued = packets.len().min(room);
            debug!("Queuing {}/{} packed UDP source packets for {} files across servers",
                queued, packets.len(), need_sources.len());
            state.udp_source_queue.extend(packets.into_iter().take(room));
        }
    }
    debug!("Periodic UDP source sweep for {} downloads ({} need sources)",
        total_downloads, need_sources.len());
}
