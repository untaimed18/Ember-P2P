//! Offering shared files to the connected eD2K server: at most one
//! OP_OFFERFILES chunk per `ED2K_OFFER_PACKET_INTERVAL`, as eMule's
//! `CSharedFileList::Process` does.

use super::*;

/// How long a chunk the server link refused (writer queue full, or the session
/// breaking) waits before the next try, rather than being retried on every
/// turn of the loop.
const OFFER_RETRY_AFTER_REFUSAL: std::time::Duration = std::time::Duration::from_secs(1);

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
    let offer_packet_due =
        next_offer_packet_at.is_none_or(|at| tokio::time::Instant::now() >= at);
    // A request to re-read the shared list is eMule's dirty flag: it is
    // folded in when the list is idle, or just before the next due packet so
    // files that turned up since the last one ride in it. Nothing is
    // advertisable until known.met is absorbed, so the list is not read before.
    if state.request_offer_files
        && (pending_offer_files.is_none() || offer_packet_due)
        && known_files.is_authoritative()
    {
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
                            file_type: ed2k::server::offer_file_type(&f.name),
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
                    if !transfer_may_advertise_partial(known_files, &restricted, transfer) {
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
                        file_type: ed2k::server::offer_file_type(&transfer.file_name),
                    });
                }
            }
            let signature = offer_files_signature(&offer_files);
            // Files that left the list are not unpublished, because eD2K has
            // no message for it: an empty OP_OFFERFILES is eMule's keep-alive
            // (`ServerConnect.cpp:561-579`) and a server treats it as one. As
            // in eMule, an unshared or friends-only file stays listed on this
            // server until the next session. It also stays in
            // `offered_ed2k_hashes`, so sharing it again is not a republish.
            let incremental = incremental_ed2k_offers(offer_files, &state.offered_ed2k_hashes);
            *pending_offer_signature = Some(signature);
            if incremental.is_empty() {
                state.last_offer_files_signature = Some(signature);
                *pending_offer_files = None;
            } else {
                *pending_offer_files = Some(incremental);
            }
        }
    }
    if let Some(files) = pending_offer_files.as_mut().filter(|_| offer_packet_due) {
        let Some((limit, server_flags)) = state
            .server_connection
            .as_ref()
            .map(|c| (c.offer_files_chunk_limit(), c.session.server_flags))
        else {
            *pending_offer_files = None;
            *pending_offer_signature = None;
            return;
        };
        let end = limit.min(files.len());
        // A server without large-file support cannot index a file past the
        // old 4 GiB limit, and eMule leaves such files out of the list
        // (`SharedFileList.cpp:812`): neither sent nor recorded as offered.
        let drained: Vec<_> = files
            .drain(..end)
            .filter(|f| ed2k::server::server_indexes_file_size(f.size, server_flags))
            .collect();
        let chunk = still_offerable(
            state,
            local_index,
            transfer_manager,
            known_files,
            drained,
        )
        .await;
        if chunk.is_empty() {
            // Everything in this slice went friends-only, unshared, is too
            // large for this server, or was already offered since it was
            // queued. Nothing to send: an empty OP_OFFERFILES is only a
            // keep-alive.
            if files.is_empty() {
                *pending_offer_files = None;
                if let Some(sig) = pending_offer_signature.take() {
                    state.last_offer_files_signature = Some(sig);
                }
            }
            return;
        }
        let offer_tcp_port = advertised_tcp_port(state);
        if let Some(conn) = state.server_connection.as_mut() {
            match conn.offer_files_chunk(&chunk, offer_tcp_port) {
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
                    *next_offer_packet_at =
                        Some(tokio::time::Instant::now() + OFFER_RETRY_AFTER_REFUSAL);
                }
            }
        }
    }
}

/// The part of a queued OP_OFFERFILES slice that may still go out.
///
/// The backlog is built from the shared list and drained a slice a minute, so a
/// large library takes many minutes to offer. A file the user marks
/// friends-only or unshares in that window, or one that already went out in an
/// earlier slice, must not be offered from the stale list: the first leaks a
/// restricted file to the public server, the second re-offers a hash the
/// server already has.
async fn still_offerable(
    state: &NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    known_files: &KnownFileList,
    files: Vec<ed2k::server::OfferFile>,
) -> Vec<ed2k::server::OfferFile> {
    if files.is_empty() {
        return files;
    }
    let index = local_index.read().await;
    let restricted = collect_friends_only_hashes(&index, known_files);
    let mgr = transfer_manager.read().await;
    files
        .into_iter()
        .filter(|f| {
            if state.offered_ed2k_hashes.contains(&f.hash) {
                return false;
            }
            let hex = hex::encode(f.hash);
            if f.is_complete {
                index
                    .get_by_hash(&hex)
                    .is_some_and(|file| kad_may_advertise_complete(file, known_files, &restricted))
            } else {
                mgr.active.values().chain(mgr.queue.iter()).any(|t| {
                    t.direction == TransferDirection::Download
                        && t.file_hash.eq_ignore_ascii_case(&hex)
                        && !matches!(t.status, TransferStatus::Completed | TransferStatus::Failed)
                        && transfer_may_advertise_partial(known_files, &restricted, t)
                })
            }
        })
        .collect()
}
