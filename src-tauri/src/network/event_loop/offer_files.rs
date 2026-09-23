//! Offering shared files to the connected eD2K server: at most one
//! OP_OFFERFILES chunk per `ED2K_OFFER_PACKET_INTERVAL`, as eMule's
//! `CSharedFileList::Process` does.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn drain_offer_files(
    state: &mut NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    settings: &AppSettings,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    known_files: &KnownFileList,
    next_offer_packet_at: &mut Option<tokio::time::Instant>,
    pending_offer_files: &mut Option<Vec<ed2k::server::OfferFile>>,
    pending_offer_signature: &mut Option<(usize, u64)>,
) {
    // Drain at most one OP_OFFERFILES chunk per `ED2K_OFFER_PACKET_INTERVAL`,
    // as eMule's `CSharedFileList::Process` does; the first packet after
    // login goes out at once.
    if state.request_offer_files && pending_offer_files.is_none() {
        state.request_offer_files = false;
        if state.server_connected {
            let mut seen_offer_hashes = std::collections::HashSet::new();
            let (mut offer_files, restricted) = {
                let index = local_index.read().await;
                let restricted = collect_friends_only_hashes(&index, known_files);
                let offer_files: Vec<ed2k::server::OfferFile> = index
                    .all_files()
                    .iter()
                    .filter(|f| kad_may_advertise_complete(f, known_files, &restricted))
                    .filter_map(|f| {
                        let hash_bytes = hex::decode(&f.hash).ok()?;
                        if hash_bytes.len() < 16 {
                            return None;
                        }
                        if !seen_offer_hashes.insert(f.hash.clone()) {
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
                (offer_files, restricted)
            };
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
                    if !kad_may_advertise_partial(
                        known_files,
                        &restricted,
                        &transfer.file_hash,
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
            if offer_files.is_empty() {
                *pending_offer_signature = Some(signature);
                if state.offered_ed2k_hashes.is_empty() {
                    state.last_offer_files_signature = Some(signature);
                    *pending_offer_files = None;
                } else {
                    // Tell the server we no longer share anything. Do not
                    // republish the old list on the way out.
                    *pending_offer_files = Some(Vec::new());
                }
            } else {
                let incremental =
                    incremental_ed2k_offers(offer_files, &state.offered_ed2k_hashes);
                *pending_offer_signature = Some(signature);
                if incremental.is_empty() {
                    state.last_offer_files_signature = Some(signature);
                    *pending_offer_files = None;
                } else {
                    *pending_offer_files = Some(incremental);
                }
            }
        }
    }
    let offer_packet_due =
        next_offer_packet_at.is_none_or(|at| tokio::time::Instant::now() >= at);
    if let Some(files) = pending_offer_files.as_mut().filter(|_| offer_packet_due) {
        if state.server_connection.is_some() {
            let limit = state
                .server_connection
                .as_ref()
                .map(|c| c.offer_files_chunk_limit())
                .unwrap_or(200);
            let end = limit.min(files.len());
            let chunk: Vec<_> = files.drain(..end).collect();
            let offer_tcp_port = advertised_tcp_port(state);
            if let Some(conn) = state.server_connection.as_mut() {
                if !chunk.is_empty() {
                    match conn.offer_files_chunk(&chunk, offer_tcp_port).await {
                        Ok(()) => {
                            *next_offer_packet_at =
                                Some(tokio::time::Instant::now() + ED2K_OFFER_PACKET_INTERVAL);
                            record_offered_ed2k_hashes(state, &chunk);
                            if files.is_empty() {
                                *pending_offer_files = None;
                                if let Some(sig) = pending_offer_signature.take() {
                                    state.last_offer_files_signature = Some(sig);
                                }
                            }
                        }
                        Err(e) => {
                            debug!("Failed to send OP_OFFERFILES chunk: {e}");
                            // Put the failed chunk back at the front so it is
                            // retried on a later turn instead of being dropped.
                            let mut rest = std::mem::take(files);
                            let mut retry = chunk;
                            retry.append(&mut rest);
                            *files = retry;
                        }
                    }
                } else if files.is_empty() {
                    // An empty offer is a real message — it tells the
                    // server we no longer share anything, and
                    // `offer_files_chunk` deliberately supports the
                    // count=0 form. Dropping it here meant a user who
                    // unshared their library (or removed their last
                    // shared folder, or marked everything friends-only)
                    // stayed listed as a source for all of it until they
                    // disconnected, with peers still being handed their
                    // address. It also left `last_offer_files_signature`
                    // stale, so every later reconcile re-armed this same
                    // no-op.
                    match conn.offer_files_chunk(&chunk, offer_tcp_port).await {
                        Ok(()) => {
                            *next_offer_packet_at =
                                Some(tokio::time::Instant::now() + ED2K_OFFER_PACKET_INTERVAL);
                            *pending_offer_files = None;
                            state.offered_ed2k_hashes.clear();
                            if let Some(sig) = pending_offer_signature.take() {
                                state.last_offer_files_signature = Some(sig);
                            }
                        }
                        Err(e) => {
                            debug!("Failed to send the clearing OP_OFFERFILES: {e}");
                        }
                    }
                }
            }
        } else {
            *pending_offer_files = None;
            *pending_offer_signature = None;
        }
    }
}
