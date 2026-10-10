//! Upload listener events as the loop receives them: Library byte accounting,
//! friend relay and file offers, chat attachments, Ember peer exchange and DHT
//! contacts, friend presence, requests, chat, browse and transfer requests,
//! upload-side reputation, then `handle_upload_event` behind `catch_unwind`.

use super::*;

/// Per-file upload counters as the Library shows them, sent on
/// `shared-file-stats` instead of `shared-files-changed`. Upload progress
/// arrives up to every 200 ms per slot, and every `shared-files-changed`
/// makes its listeners re-read the whole library, so these are coalesced
/// per hash (latest absolute values win) and flushed at most once per
/// [`SHARED_FILE_STATS_INTERVAL`] across all files.
#[derive(Clone, serde::Serialize)]
struct SharedFileStats {
    hash: String,
    requests: u32,
    accepted: u32,
    bytes_transferred: u64,
    alltime_requests: u32,
    alltime_accepted: u32,
    alltime_transferred: u64,
}

impl SharedFileStats {
    fn of(file: &FileInfo) -> Self {
        Self {
            hash: file.hash.clone(),
            requests: file.requests,
            accepted: file.accepted,
            bytes_transferred: file.bytes_transferred,
            alltime_requests: file.alltime_requests,
            alltime_accepted: file.alltime_accepted,
            alltime_transferred: file.alltime_transferred,
        }
    }
}

/// The counters of `hash_hex`'s index rows, by path, for [`copy_counters_to_cache`].
fn index_counters(
    index: &crate::search::index::LocalIndex,
    hash_hex: &str,
) -> HashMap<String, SharedFileStats> {
    index
        .files_with_hash(hash_hex)
        .map(|f| (crate::search::index::normalize_path_key(&f.path), SharedFileStats::of(f)))
        .collect()
}

/// Copy index counters onto the cached snapshot's matching rows, absolute.
///
/// The cache used to be bumped by the same delta as the index, separately. A
/// cache refresh landing between the two counted that delta twice, and one
/// landing just before the index bump lost it, until the next refresh.
fn copy_counters_to_cache(
    cached: &mut [FileInfo],
    hash_hex: &str,
    counters: &HashMap<String, SharedFileStats>,
) -> Option<SharedFileStats> {
    let mut updated = None;
    for file in cached.iter_mut().filter(|f| f.hash.eq_ignore_ascii_case(hash_hex)) {
        let Some(c) = counters.get(&crate::search::index::normalize_path_key(&file.path)) else {
            continue;
        };
        file.requests = c.requests;
        file.accepted = c.accepted;
        file.bytes_transferred = c.bytes_transferred;
        file.alltime_requests = c.alltime_requests;
        file.alltime_accepted = c.alltime_accepted;
        file.alltime_transferred = c.alltime_transferred;
        updated = Some(SharedFileStats::of(file));
    }
    updated
}

const SHARED_FILE_STATS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// `Some` while a flush is scheduled; the flush task takes the batch.
static PENDING_SHARED_FILE_STATS: std::sync::Mutex<Option<HashMap<String, SharedFileStats>>> =
    std::sync::Mutex::new(None);

fn queue_shared_file_stats(app_handle: &tauri::AppHandle, stats: SharedFileStats) {
    let key = stats.hash.to_ascii_lowercase();
    {
        let mut pending = PENDING_SHARED_FILE_STATS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(batch) = pending.as_mut() {
            batch.insert(key, stats);
            return;
        }
        *pending = Some(HashMap::from([(key, stats)]));
    }
    let app_handle = app_handle.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(SHARED_FILE_STATS_INTERVAL).await;
        let batch = PENDING_SHARED_FILE_STATS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(batch) = batch.filter(|b| !b.is_empty()) {
            let _ = app_handle.emit(
                "shared-file-stats",
                batch.into_values().collect::<Vec<_>>(),
            );
        }
    });
}

/// Hashes of library files already reported as missing from known.met.
static WARNED_NO_KNOWN_RECORD: std::sync::Mutex<Option<HashSet<String>>> = std::sync::Mutex::new(None);

/// Report upload counters known.met had no record to take. A file served from
/// a download still in progress has none until it completes, which is routine
/// and arrives with every progress update, so it stays at debug. A completed
/// library file without one is worth a warning, once per file.
fn note_no_known_record(index: &LocalIndex, hash_hex: &str, what: &str) {
    let hash = hash_hex.to_ascii_lowercase();
    if index.get_by_hash(&hash).is_none() {
        debug!("{what} for {hash} is a download in progress, with no known.met record yet");
        return;
    }
    let first = WARNED_NO_KNOWN_RECORD
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashSet::new)
        .insert(hash.clone());
    if first {
        warn!("{what} for library file {hash} has no known.met record; keeping session stats only");
    }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_upload_event(
    event: UploadEvent,
    udp_socket: &Arc<UdpSocket>,
    state: &mut NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    fresh_part_hashes: &Arc<RwLock<HashMap<[u8; 16], Vec<[u8; 16]>>>>,
    settings: &AppSettings,
    dl_event_tx: &mpsc::Sender<DownloadEvent>,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    credit_manager: &Arc<RwLock<CreditManager>>,
    stats_manager: &mut StatsManager,
    known_files: &mut KnownFileList,
    server_udp: &ServerUdpSocket,
    firewall_probe_ips: &upload_server::FirewallProbeSet,
    shared_banned_ips: &upload_server::SharedBannedIps,
    shared_banned_hashes: &upload_server::SharedBannedHashes,
    shared_friends_only_hashes: &upload_server::SharedFriendsOnlyHashes,
    shared_server_addr: &Arc<RwLock<Option<SocketAddr>>>,
    shared_ember_payload: &ember::SharedEmberPayload,
    ember_payload_generation: &ember::EmberPayloadGeneration,
    geoip: &crate::geoip::GeoIpReader,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    mutual_friend_hashes: &crate::app_state::SharedFriendHashes,
    ember_hash: [u8; 16],
    ul_event_tx: &mpsc::Sender<UploadEvent>,
    ed25519_pubkey: [u8; 32],
    ed25519_secret_key: [u8; 32],
    connect_serve_tx: &mpsc::Sender<upload_server::ConnectServeRequest>,
    pending_kad_callbacks: &upload_server::PendingKadCallbacks,
    shared_files: &Arc<RwLock<Vec<FileInfo>>>,
    transfer_status_writes: &Arc<TransferStatusWriteClock>,
    upload_queue_handle: &ed2k::upload::UploadQueueRef,
    upload_raw_progress: &mut HashMap<String, u64>,
) {
    // Attribute payload bytes to the Library as Progress events
    // arrive. The old completion-only path depended on finding a
    // still-live transfer row at session teardown; in real uploads
    // that lookup frequently missed, leaving known.met counters at
    // zero despite gigabytes in aggregate Statistics. Events from
    // one upload connection are ordered, and the manager still
    // contains the previous progress snapshot here (the generic
    // handler below applies this event afterward), so the delta is
    // exact and cannot double-count repeated/coalesced updates.
    let library_upload_delta = if let UploadEventKind::Progress {
        uploaded,
        ..
    } = &event.kind
    {
        let manager = transfer_manager.read().await;
        manager.get_transfer(&event.transfer_id).and_then(|transfer| {
            let previous = upload_raw_progress
                .get(&event.transfer_id)
                .copied()
                .unwrap_or_default();
            let next = (*uploaded).max(previous);
            upload_raw_progress.insert(event.transfer_id.clone(), next);
            let delta = next.saturating_sub(previous);
            (delta > 0 && !transfer.file_hash.is_empty())
                .then(|| (transfer.file_hash.clone(), delta))
        })
    } else {
        None
    };
    if let Some((hash_hex, uploaded_bytes)) = library_upload_delta {
        if let Ok(bytes) = hex::decode(&hash_hex) {
            if bytes.len() == 16 {
                let mut file_hash = [0u8; 16];
                file_hash.copy_from_slice(&bytes);
                let persisted_alltime = known_files
                    .add_all_time_transferred(&file_hash, uploaded_bytes);
                let counters = {
                    let mut index = local_index.write().await;
                    if !persisted_alltime {
                        note_no_known_record(&index, &hash_hex, "Upload progress");
                    }
                    index.apply_upload_completed_bytes(
                        &hash_hex,
                        uploaded_bytes,
                        persisted_alltime,
                    );
                    index_counters(&index, &hash_hex)
                };
                let updated = copy_counters_to_cache(
                    &mut shared_files.write().await,
                    &hash_hex,
                    &counters,
                );
                if let Some(stats) = updated {
                    queue_shared_file_stats(app_handle, stats);
                }
            }
        }
    }
    if matches!(
        &event.kind,
        UploadEventKind::Completed { .. } | UploadEventKind::Failed { .. }
    ) {
        upload_raw_progress.remove(&event.transfer_id);
    }

    if let UploadEventKind::SharesBrowsed {
        peer_addr,
        ref peer_name,
        ref client_software,
        allowed,
    } = event.kind
    {
        report_ed2k_shares_browsed(
            state,
            app_handle,
            peer_addr,
            peer_name,
            client_software,
            allowed,
        );
    }

    if let UploadEventKind::ShareInterest {
        ref file_hash,
        inc_requests,
        inc_accepted,
    } = event.kind
    {
        if inc_requests > 0 || inc_accepted > 0 {
            if let Ok(bytes) = hex::decode(file_hash) {
                if bytes.len() == 16 {
                    let mut fh = [0u8; 16];
                    fh.copy_from_slice(&bytes);
                    let persisted_alltime = known_files.bump_share_interest(
                        &fh,
                        inc_requests,
                        inc_accepted,
                    );
                    let counters = {
                        let mut idx = local_index.write().await;
                        if !persisted_alltime {
                            note_no_known_record(&idx, file_hash, "Upload interest");
                        }
                        idx.apply_upload_share_deltas(
                            file_hash,
                            inc_requests,
                            inc_accepted,
                            persisted_alltime,
                        );
                        index_counters(&idx, file_hash)
                    };
                    // Target-update only the matching rows in the
                    // cached snapshot rather than cloning the
                    // entire file list. The old `all_files().to_vec()`
                    // reallocated every FileInfo (often thousands
                    // of entries with strings) for every peer file
                    // request; counters on the one file that
                    // changed are all the UI needs.
                    let updated = copy_counters_to_cache(
                        &mut shared_files.write().await,
                        file_hash,
                        &counters,
                    );
                    if let Some(stats) = updated {
                        queue_shared_file_stats(app_handle, stats);
                    }
                }
            }
        }
    }

    // A friend forwarded the relay attestations it knows. Each is
    // verified against its own signature before admission, so the
    // friend is trusted only to deliver bytes, not to vouch for
    // them — the same standard the EPX trailer is held to.
    if let UploadEventKind::EmberRelayOffer {
        ember_hash: relay_eh,
        ref attestations,
    } = event.kind
    {
        let now = std::time::Instant::now();
        let too_soon = state
            .friend_relay_offer_seen
            .get(&relay_eh)
            .is_some_and(|last| {
                now.saturating_duration_since(*last)
                    < FRIEND_RELAY_OFFER_MIN_INTERVAL
            });
        if too_soon {
            debug!(
                "Ignoring relay offer from friend {} — arrived inside the {}s throttle",
                hex::encode(relay_eh),
                FRIEND_RELAY_OFFER_MIN_INTERVAL.as_secs()
            );
        } else if friend_hashes.read().await.contains(&relay_eh) {
            state.friend_relay_offer_seen.insert(relay_eh, now);
            // Bounded alongside the live-session sweep the sender
            // side runs, but capped here too: the throttle map is
            // written from an inbound path, so a peer that
            // connects, offers once and leaves must not leave a
            // permanent entry behind.
            if state.friend_relay_offer_seen.len() > MAX_FRIEND_RELAY_OFFER_TRACKED {
                state
                    .friend_relay_offer_seen
                    .retain(|_, last| {
                        now.saturating_duration_since(*last)
                            < FRIEND_RELAY_OFFER_MIN_INTERVAL
                    });
            }
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let admitted = admit_relay_attestations(
                state,
                attestations,
                now_unix,
                Some(relay_eh),
                &format!("friend relay offer from {}", hex::encode(relay_eh)),
            );
            debug!(
                "Friend {} offered {} relay attestation(s), admitted {admitted}",
                hex::encode(relay_eh),
                attestations.len()
            );
        }
    }

    // A friend offered us a file. Surface it for an explicit
    // accept and immediately ack receipt — the ack says "your
    // offer arrived", not "I want it", so the sender can drop its
    // pending state without waiting on a human.
    if let UploadEventKind::EmberFileOffer { ember_hash: offer_eh, ref offer, ref reply_tx } = event.kind {
        // Throttled like inbound transfer requests and relay
        // offers. Each accepted offer raises a prompt in the UI, so
        // without a floor between them a friend — or something that
        // has taken over their client — can bury the user under
        // dialogs, and every one of them is a decision they have to
        // make. Declining outright rather than dropping keeps the
        // sender's request from hanging until its own timeout.
        let offer_now = std::time::Instant::now();
        let offer_too_soon = state
            .friend_file_offer_seen
            .get(&offer_eh)
            .is_some_and(|last| {
                offer_now.saturating_duration_since(*last)
                    < FRIEND_FILE_OFFER_MIN_INTERVAL
            });
        if offer_too_soon {
            debug!(
                "Declining file offer from friend {} — inside the {}s throttle",
                hex::encode(offer_eh),
                FRIEND_FILE_OFFER_MIN_INTERVAL.as_secs()
            );
            let ack = ed2k::messages::build_ember_file_offer_ack(
                ed2k::messages::OFFER_STATUS_THROTTLED,
                &offer.file_hash,
            );
            let mut framed = Vec::with_capacity(6 + ack.len());
            framed.push(OP_EMULEPROT);
            framed.extend_from_slice(&((1 + ack.len()) as u32).to_le_bytes());
            framed.push(ed2k::messages::OP_EMBER_FILE_OFFER_ACK);
            framed.extend_from_slice(&ack);
            let _ = reply_tx.try_send(framed);
        } else if friend_hashes.read().await.contains(&offer_eh) {
            let status = if !settings.files_allowed_from(&offer_eh) {
                // Reuse the chat switch as the "no unsolicited
                // contact from friends" control rather than adding
                // a second one that could disagree with it; a
                // friend's own files setting narrows it.
                ed2k::messages::OFFER_STATUS_DECLINED
            } else {
                ed2k::messages::OFFER_STATUS_ACCEPTED
            };
            if status == ed2k::messages::OFFER_STATUS_ACCEPTED {
                // Charged only when a prompt is actually raised.
                // What the throttle protects is the user's
                // attention, so an offer that never reaches them —
                // because unsolicited contact is switched off —
                // costs nothing and must not consume the budget.
                // Stamping it regardless made the next offer inside
                // the window answer "too many at once" when the
                // truthful answer was the same steady refusal.
                state.friend_file_offer_seen.insert(offer_eh, offer_now);
                // Bounded here as well as by the periodic sweep:
                // this map is written from an inbound path, so a
                // peer that connects, offers once and leaves must
                // not leave an entry behind for the life of the
                // process.
                if state.friend_file_offer_seen.len() > MAX_FRIEND_RELAY_OFFER_TRACKED {
                    state.friend_file_offer_seen.retain(|_, last| {
                        offer_now.saturating_duration_since(*last)
                            < FRIEND_FILE_OFFER_MIN_INTERVAL
                    });
                }
                // The name is peer-supplied, so strip the same
                // bidi/control primitives chat text goes through
                // before it reaches the UI.
                let safe_name = crate::security::sanitize_chat_text(&offer.file_name);
                crate::network::browse::record_friend_offer(
                    offer_eh,
                    offer.file_hash,
                    offer.friends_only,
                );
                let _ = app_handle.emit(
                    "ember:file-offer",
                    serde_json::json!({
                        "user_hash": hex::encode(offer_eh),
                        "file_hash": hex::encode(offer.file_hash),
                        "file_name": safe_name,
                        "file_size": offer.file_size,
                        "ember_file_hash": offer.ember_file_hash.map(hex::encode),
                        "friends_only": offer.friends_only,
                    }),
                );
            }
            let ack = ed2k::messages::build_ember_file_offer_ack(status, &offer.file_hash);
            let mut framed = Vec::with_capacity(6 + ack.len());
            framed.push(OP_EMULEPROT);
            framed.extend_from_slice(&((1 + ack.len()) as u32).to_le_bytes());
            framed.push(ed2k::messages::OP_EMBER_FILE_OFFER_ACK);
            framed.extend_from_slice(&ack);
            let _ = reply_tx.try_send(framed);
        }
    }

    // Chat attachments. The readers only surface these from a
    // session that already holds friend privileges; the friend set
    // is checked again here because it is the one this loop acts on.
    if let UploadEventKind::EmberAttachOffer { ember_hash: attach_eh, ref offer, peer_addr } = event.kind {
        if friend_hashes.read().await.contains(&attach_eh) {
            chat_attach::on_offer(
                state,
                db,
                app_handle,
                settings,
                attach_eh,
                offer.clone(),
                peer_addr,
            )
            .await;
        }
    }
    if let UploadEventKind::EmberAttachReply { ember_hash: attach_eh, xfer_id, reply, quic_port, peer_addr } = event.kind {
        chat_attach::on_reply(
            state,
            db,
            app_handle,
            settings,
            attach_eh,
            xfer_id,
            reply,
            quic_port,
            peer_addr,
        )
        .await;
        // An answer frees a place for the next queued file.
        if friend_hashes.read().await.contains(&attach_eh) {
            chat_attach::send_queued(state, db, app_handle, settings, attach_eh).await;
        }
    }
    if let UploadEventKind::EmberAttachCancel { ember_hash: attach_eh, xfer_id, reason } = event.kind {
        chat_attach::on_cancel(
            state,
            db,
            app_handle,
            settings,
            attach_eh,
            xfer_id,
            reason,
        );
    }

    if let UploadEventKind::EmberFileOfferAck { ember_hash: ack_eh, status, file_hash } = event.kind {
        let _ = app_handle.emit(
            "ember:file-offer-ack",
            serde_json::json!({
                "user_hash": hex::encode(ack_eh),
                "file_hash": hex::encode(file_hash),
                "accepted": status == ed2k::messages::OFFER_STATUS_ACCEPTED,
                // Kept apart from `accepted` so the sender does not
                // report a rate-limited offer as a refusal — nobody
                // on the other end has seen it, let alone decided.
                "throttled": status == ed2k::messages::OFFER_STATUS_THROTTLED,
            }),
        );
    }

    // Inject Ember Peer Exchange sources from upload-side peers
    if let UploadEventKind::EmberSources { ref entries, ref aich_roots, ref ember_peers, ref relay_attestations, from_ember_hash } = event.kind {
        let we_are_unreachable = state.firewalled || state.low_id;
        handle_epx_sources(state, transfer_manager, source_manager, local_index, entries, aich_roots, ember_peers, relay_attestations, from_ember_hash, "upload", false, we_are_unreachable, &HashMap::new()).await;
    }

    if let UploadEventKind::EmberPeerDiscovered { ip, tcp_port, udp_port } = event.kind {
        note_connected_ember_peer(
            udp_socket,
            state,
            settings.ember_native_enabled,
            ip,
            tcp_port,
            udp_port,
        )
        .await;
    }

    // The friend contact exchange. Gated on the overlay being on,
    // because with it off there is neither a table to share nor one
    // to fill.
    if let UploadEventKind::EmberDhtContactRequest { ember_hash, target, ref reply_tx } = event.kind {
        if settings.ember_native_enabled {
            answer_friend_ember_contact_request(
                state,
                ember_hash,
                target,
                reply_tx,
            )
            .await;
        }
    }

    if let UploadEventKind::EmberDhtContacts { ember_hash, ref contacts } = event.kind {
        if settings.ember_native_enabled {
            ingest_friend_ember_contacts(
                udp_socket,
                state,
                ember_hash,
                contacts,
            )
            .await;
        }
    }

    if let UploadEventKind::EmberDhtMeet { ember_hash, peer_ip, udp_port, answer, ref reply_tx } = event.kind {
        if settings.ember_native_enabled && friend_hashes.read().await.contains(&ember_hash) {
            answer_friend_meet(udp_socket, state, ember_hash, peer_ip, udp_port, answer, reply_tx).await;
        }
    }

    // Any inbound friend activity implies they're online — update
    // status if we haven't already so the UI card flips immediately.
    {
        let activity_eh = match &event.kind {
            UploadEventKind::EmberChatMessage { ember_hash, .. }
            | UploadEventKind::EmberChatTyping { ember_hash, .. }
            | UploadEventKind::EmberChatRead { ember_hash, .. }
            | UploadEventKind::EmberBrowseRequest { ember_hash, .. }
            | UploadEventKind::EmberBrowseResponse { ember_hash, .. }
            // An unverified request is only a claimed hash. Counting it would
            // let anyone mark a friend online, and online friends are skipped
            // by every reconnect path.
            | UploadEventKind::EmberFriendRequest { ember_hash, verified: true, .. } => {
                Some(*ember_hash)
            }
            _ => None,
        };
        if let Some(eh) = activity_eh {
            if friend_hashes.read().await.contains(&eh) {
                let was_new = !state.online_friends.contains_key(&eh);
                state.online_friends.insert(eh, chrono::Utc::now().timestamp());
                if was_new {
                    let _ = app_handle.emit("ember:friend-online", serde_json::json!({
                        "user_hash": hex::encode(eh),
                    }));
                }
            }
        }
    }

    match &event.kind {
        UploadEventKind::EmberFriendConnected {
            ember_hash,
            peer_user_hash,
            ip,
            port,
        } => {
            // Outbound session just came up. Mirror the inbound-activity
            // block above: mark online (if not already) and notify the
            // UI. `friend_hashes` re-check guards the same removal race
            // documented on the `FriendSeen` handlers.
            let still_friend = friend_hashes.read().await.contains(ember_hash);
            if still_friend {
                let was_new = !state.online_friends.contains_key(ember_hash);
                state
                    .online_friends
                    .insert(*ember_hash, chrono::Utc::now().timestamp());
                if was_new {
                    let _ = app_handle.emit(
                        "ember:friend-online",
                        serde_json::json!({
                            "user_hash": hex::encode(ember_hash),
                        }),
                    );
                }
            }
            // The session is live, so anything the user typed
            // while this friend was unreachable can go out now —
            // unless chat with them was turned off since, which
            // holds it until it is back on or ages out.
            if still_friend && settings.chat_allowed_with(ember_hash) {
                flush_pending_chat(
                    db,
                    app_handle,
                    &state.ember_sessions,
                    &ed25519_secret_key,
                    *ember_hash,
                )
                .await;
                if settings.read_receipts_with(ember_hash) {
                    flush_pending_read_receipt(
                        db,
                        &state.ember_sessions,
                        &ed25519_secret_key,
                        *ember_hash,
                    )
                    .await;
                }
                // Files queued while they were away, the same way.
                chat_attach::send_queued(state, db, app_handle, settings, *ember_hash).await;
            }
            if still_friend && !ip.is_unspecified() && *port > 0 {
                let hash_hex = hex::encode(ember_hash);
                let ip_str = ip.to_string();
                let db2 = db.clone();
                let h2 = hash_hex;
                let ip2 = ip_str;
                let port = *port;
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = db2.update_friend_address(&h2, &ip2, port) {
                        warn!("Failed to persist friend {h2} address {ip2}:{port}: {e}");
                    }
                });
                reseed_friend_endpoint(
                    state,
                    source_manager,
                    credit_manager,
                    transfer_manager,
                    friend_hashes,
                    *ember_hash,
                    Some(*peer_user_hash),
                    *ip,
                    port,
                )
                .await;
            }
            // A friend session coming up is the moment a starved
            // table has something to ask, and waiting for the 60s
            // maintenance tick is most of a short visit. The ask
            // rate-limits per friend, so a session that flaps
            // cannot turn this into a burst.
            if still_friend && settings.ember_native_enabled {
                ask_friends_for_ember_contacts(state).await;
            }
        }
        UploadEventKind::FriendEndpointDiscovered {
            ember_hash,
            ip,
            port,
        } => {
            if friend_hashes.read().await.contains(ember_hash) {
                let hash_hex = hex::encode(ember_hash);
                let ip_str = ip.to_string();
                let db2 = db.clone();
                let h2 = hash_hex;
                let ip2 = ip_str;
                let port = *port;
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = db2.update_friend_address(&h2, &ip2, port) {
                        warn!("Failed to persist friend {h2} address {ip2}:{port}: {e}");
                    }
                });
                reseed_friend_endpoint(
                    state,
                    source_manager,
                    credit_manager,
                    transfer_manager,
                    friend_hashes,
                    *ember_hash,
                    None,
                    *ip,
                    port,
                )
                .await;
            }
        }
        UploadEventKind::FriendSeen {
            ember_hash,
            ip,
            port,
        }
            // Gate on current membership: FriendSeen fires post-PoP for a
            // peer that was a friend at emit time, but a concurrent
            // removal can still race it. Without this a just-removed
            // friend could be resurrected as "online" in the UI until the
            // 5-minute sweep.
            if friend_hashes.read().await.contains(ember_hash) => {
                let hash_hex = hex::encode(ember_hash);
                let now = chrono::Utc::now().timestamp();
                state.online_friends.insert(*ember_hash, now);
                // Mirror the download-side FriendSeen handler: clear any
                // reconnect backoff so a later disconnect can re-dial
                // promptly instead of waiting out the cooldown.
                state.friend_reconnect_last.remove(ember_hash);
                let ip_str = match ip {
                    std::net::IpAddr::V4(v4) => v4.to_string(),
                    std::net::IpAddr::V6(v6) => v6.to_string(),
                };
                let db2 = db.clone();
                let h2 = hash_hex.clone();
                let ip2 = ip_str.clone();
                let port = *port;
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = db2.update_friend_address(&h2, &ip2, port) {
                        warn!("Failed to persist friend {h2} address {ip2}:{port}: {e}");
                    }
                });
                // `FriendSeen` now carries the peer's Hello listen
                // port (see the emission sites in upload.rs), so
                // it's safe to reseed download sources from it too.
                if let std::net::IpAddr::V4(v4) = ip {
                    reseed_friend_endpoint(
                        state,
                        source_manager,
                        credit_manager,
                        transfer_manager,
                        friend_hashes,
                        *ember_hash,
                        None,
                        *v4,
                        port,
                    )
                    .await;
                }
                let _ = app_handle.emit(
                    "ember:friend-online",
                    serde_json::json!({
                        "user_hash": hash_hex,
                        "ip": ip_str,
                        "port": port,
                    }),
                );
                // A friend who dials *us* never produces
                // `EmberFriendConnected` (that is emitted only by
                // the outbound dial path), so without flushing
                // here queued chat would sit unsent while the UI
                // showed the friend online and new sends worked.
                if settings.chat_allowed_with(ember_hash) {
                    flush_pending_chat(
                        db,
                        app_handle,
                        &state.ember_sessions,
                        &ed25519_secret_key,
                        *ember_hash,
                    )
                    .await;
                    chat_attach::send_queued(state, db, app_handle, settings, *ember_hash).await;
                }
                if settings.read_receipts_with(ember_hash) {
                    flush_pending_read_receipt(
                        db,
                        &state.ember_sessions,
                        &ed25519_secret_key,
                        *ember_hash,
                    )
                    .await;
                }
            }
        _ => {}
    }

    if let UploadEventKind::EmberFriendRequest { ember_hash: req_hash, pubkey, ref nickname, ref peer_ip, peer_port, verified } = event.kind {
        process_inbound_friend_request(
            db,
            app_handle,
            &mut state.online_friends,
            mutual_friend_hashes,
            req_hash,
            pubkey,
            nickname,
            peer_ip,
            peer_port,
            verified,
        )
        .await;
    }

    if let UploadEventKind::EmberFriendRetract { ember_hash: retract_hash } = event.kind {
        let hash_hex = hex::encode(retract_hash);
        // Only the queued request goes. Reaching into `friends`
        // here would turn a withdrawal into a way to remove
        // yourself from someone else's friend list, and if they
        // accepted a moment ago there is simply no row left to
        // delete.
        let db_retract = db.clone();
        let h_retract = hash_hex.clone();
        match tokio::task::spawn_blocking(move || {
            db_retract.remove_friend_request(&h_retract)
        })
        .await
        {
            Ok(Ok(())) => {
                info!("Cleared withdrawn friend request from {hash_hex}");
                let _ = app_handle.emit(
                    "ember:friend-request-withdrawn",
                    serde_json::json!({
                        "sender_hash": hash_hex,
                    }),
                );
            }
            Ok(Err(e)) => warn!("Failed to clear withdrawn request from {hash_hex}: {e}"),
            Err(e) => warn!("Withdrawn-request task failed for {hash_hex}: {e}"),
        }
    }

    if let UploadEventKind::EmberFriendDecline { ember_hash: decline_hash } = event.kind {
        let hash_hex = hex::encode(decline_hash);
        // Only a row they have never accepted. `decline_friend_request`
        // is written to refuse a mutual friendship outright, so this
        // cannot become a way to remove yourself from somebody
        // else's friend list — and if they accepted a moment ago,
        // there is nothing one-sided left to delete.
        let db_decline = db.clone();
        let h_decline = hash_hex.clone();
        match tokio::task::spawn_blocking(move || {
            db_decline.decline_friend_request(&h_decline)
        })
        .await
        {
            Ok(Ok(true)) => {
                info!("Friend request to {hash_hex} was declined");
                // We added them, which granted them friend access
                // to this node; their refusal ends that. Dropping
                // the hash alone leaves any stream they already
                // hold authenticated, so the grant has to be
                // revoked the same way removal revokes it.
                friend_hashes.write().await.remove(&decline_hash);
                mutual_friend_hashes.write().await.remove(&decline_hash);
                crate::network::friend_intro::forget_friend_intro_secret(&decline_hash);
                crate::network::friends::forget_friend_network_state(
                    state,
                    settings,
                    app_handle,
                    upload_queue_handle,
                    decline_hash,
                    "Friend request was declined",
                )
                .await;
                // As removal does. Off this loop: the save hands the
                // settings back to it and would wait on itself.
                let clear_app = app_handle.clone();
                tokio::spawn(async move {
                    use tauri::Manager;
                    let Some(state) = clear_app.try_state::<crate::app_state::AppState>() else {
                        return;
                    };
                    if let Err(e) =
                        crate::commands::settings::clear_friend_overrides(&clear_app, &state, &decline_hash).await
                    {
                        warn!("Could not clear a declined friend's settings: {e}");
                    }
                });
                let _ = app_handle.emit(
                    "ember:friend-request-declined",
                    serde_json::json!({
                        "user_hash": hash_hex,
                    }),
                );
            }
            // Nothing one-sided on file: they accepted first, or we
            // had already removed them. Either way the decline has
            // nothing to act on and is not worth telling anyone.
            Ok(Ok(false)) => {
                debug!("Ignoring a decline from {hash_hex} with no pending request")
            }
            Ok(Err(e)) => warn!("Failed to clear declined request to {hash_hex}: {e}"),
            Err(e) => warn!("Declined-request task failed for {hash_hex}: {e}"),
        }
    }

    if let UploadEventKind::EmberChatMessage { ember_hash: chat_eh, ref message } = event.kind {
        if !friend_hashes.read().await.contains(&chat_eh) {
            debug!("Dropping secure chat event after friend removal");
            return;
        }
        // Nothing can be stored while chat is locked, and surfacing
        // a message we cannot keep is worse than not surfacing it:
        // it would appear, contradict the banner explaining that
        // chat is unusable, and disappear on the next reload.
        if db.chat_locked() {
            debug!(
                "Dropping inbound chat from {} — history is locked",
                hex::encode(chat_eh)
            );
            return;
        }
        if settings.chat_allowed_with(&chat_eh) {
            let hash_hex = hex::encode(chat_eh);
            // L20: same ingress sanitisation as the
            // download-event path above. Inbound chat
            // arrives via two upload-listener routes
            // (`upload.rs` direct, plus the
            // friend-session reader in
            // `friend_connect.rs`) and both ultimately
            // land here, so this single call covers
            // every inbound chat persistence point.
            let cleaned = crate::security::sanitize_chat_text(message);
            // Dedup against the `DownloadEvent::EmberChatMessage`
            // path above — see `recent_ember_chat`'s doc comment.
            // The two upload-listener routes feeding *this* arm
            // already can't double-deliver on their own (both
            // honour `ember_sessions` slot ownership), but an
            // ordinary download connection to the same friend
            // deliberately doesn't participate in that ownership
            // check, so this shared map is what catches it.
            let now = chrono::Utc::now().timestamp();
            let is_dup = state
                .recent_ember_chat
                .get(&chat_eh)
                .is_some_and(|(last_msg, last_at)| {
                    *last_msg == cleaned
                        && now.saturating_sub(*last_at) <= EMBER_CHAT_DEDUP_WINDOW_SECS
                });
            if !is_dup {
                match persist_chat_history_message(
                    db.clone(),
                    hash_hex.clone(),
                    "received",
                    cleaned.clone(),
                )
                .await
                {
                    Ok(id) => {
                        state
                            .recent_ember_chat
                            .insert(chat_eh, (cleaned.clone(), now));
                        let _ = app_handle.emit("ember:chat-message", serde_json::json!({
                            "user_hash": hash_hex,
                            "id": id,
                            "message": cleaned,
                            "direction": "received",
                            "timestamp": now,
                        }));
                    }
                    Err(error) => {
                        warn!(
                            "Received chat message was not emitted because history persistence failed: {error}"
                        );
                    }
                }
            }
        }
    }

    if let UploadEventKind::EmberChatTyping { ember_hash: typing_eh, typing } = event.kind {
        if settings.chat_allowed_with(&typing_eh)
            && friend_hashes.read().await.contains(&typing_eh)
        {
            let _ = app_handle.emit(
                "ember:chat-typing",
                serde_json::json!({
                    "user_hash": hex::encode(typing_eh),
                    "typing": typing,
                }),
            );
        }
    }

    if let UploadEventKind::EmberChatRead { ember_hash: read_eh, body_hash } = event.kind
    {
        // Same gate as outbound send/flush: off means we neither
        // tell friends we have read nor record that they have read
        // us. Persisting while the setting is off would still paint
        // "Seen" the moment it is turned back on.
        if !settings.read_receipts_with(&read_eh)
            || !friend_hashes.read().await.contains(&read_eh)
        {
            return;
        }
        let hash_hex = hex::encode(read_eh);
        let body_hex = hex::encode(body_hash);
        let db_seen = db.clone();
        let hash_for_db = hash_hex.clone();
        match tokio::task::spawn_blocking(move || {
            db_seen.mark_sent_seen_by_hash(&hash_for_db, &body_hex)
        })
        .await
        {
            Ok(Ok(Some(until_id))) => {
                let _ = app_handle.emit(
                    "ember:chat-read",
                    serde_json::json!({
                        "user_hash": hash_hex,
                        "until_id": until_id,
                    }),
                );
            }
            Ok(Ok(None)) => {}
            Ok(Err(e)) => warn!("Failed to apply chat read receipt from {hash_hex}: {e}"),
            Err(e) => warn!("Chat read-receipt task failed for {hash_hex}: {e}"),
        }
    }

    if let UploadEventKind::EmberBrowseRequest {
        ember_hash: browse_eh,
        session_id,
        ref reply_tx,
        supports_ebr1,
        supports_scope,
    } = event.kind
    {
        // Mutual, not merely listed. The UI already hides Browse
        // until a friendship is mutual, but that is cosmetic: the
        // wire has to enforce it, or anyone who learns our Ember
        // hash could add us one-sidedly and read our library.
        let is_mutual_friend = mutual_friend_hashes.read().await.contains(&browse_eh);
        if settings.browse_allowed_for(&browse_eh) && is_mutual_friend {
            let files = {
                let idx = local_index.read().await;
                idx.all_files().to_vec()
            };
            // Cap both entry count and total payload bytes. The
            // receiving side's inbound frame reader
            // (`read_packet_with_first_byte` in upload.rs) rejects
            // any packet over 512 KiB outright with no partial
            // delivery, so an oversized answer silently loses the
            // *entire* browse response rather than a truncated
            // one — cap well under that so a large library still
            // gets a usable (if truncated) reply. The entry count
            // also matches `MAX_BROWSE_ENTRIES` in
            // `multi_source::parse_browse_response`, which is what
            // the peer receiving our answer actually keeps.
            const MAX_BROWSE_ANSWER_FILES: usize = 1_000;
            const MAX_BROWSE_ANSWER_BYTES: usize = 400 * 1024;
            let mut encoded_entries: Vec<(
                [u8; 16],
                u64,
                Vec<u8>,
                Option<[u8; 20]>,
                Option<[u8; 32]>,
            )> = Vec::new();
            let mut restricted_entries: Vec<[u8; 16]> = Vec::new();
            // Fail closed until known.met is absorbed: a friends-only row
            // can still read public in the index during that window, and
            // the friend would then republish it.
            let catalog_authoritative = known_files.is_authoritative();
            // Mutual friends see friends-only files alongside
            // public ones — that is the whole point of the scope.
            // Newest first, so a library too large for one answer shows
            // what was added most recently rather than index order; and
            // one row per hash, so copies of a file in two shared folders
            // don't spend two of the answer's slots.
            let mut visible: Vec<&FileInfo> =
                files.iter().filter(|f| f.is_friend_visible()).collect();
            visible.sort_by_key(|f| std::cmp::Reverse(f.modified_at));
            let mut seen_hashes: std::collections::HashSet<[u8; 16]> =
                std::collections::HashSet::new();
            let mut total_unique: u32 = 0;
            let mut approx_bytes = 8usize;
            let mut answer_full = false;
            for f in visible {
                let Ok(hash_bytes) = hex::decode(&f.hash) else {
                    continue;
                };
                if hash_bytes.len() != 16 {
                    continue;
                }
                let mut hash = [0u8; 16];
                hash.copy_from_slice(&hash_bytes);
                if !seen_hashes.insert(hash) {
                    continue;
                }
                total_unique = total_unique.saturating_add(1);
                // Keep walking once the answer is full: the rest still
                // count toward the total the summary frame reports.
                if answer_full || encoded_entries.len() >= MAX_BROWSE_ANSWER_FILES {
                    continue;
                }
                let name_bytes = f.name.as_bytes().to_vec();
                let aich = if f.aich_hash.len() == 40 {
                    let mut root = [0u8; 20];
                    if hex::decode_to_slice(&f.aich_hash, &mut root).is_ok() {
                        Some(root)
                    } else {
                        None
                    }
                } else {
                    None
                };
                let ember = if f.ember_file_hash.len() == 64 {
                    let mut digest = [0u8; 32];
                    if hex::decode_to_slice(&f.ember_file_hash, &mut digest).is_ok() {
                        Some(digest)
                    } else {
                        None
                    }
                } else {
                    None
                };
                if !catalog_authoritative
                    || f.friends_only
                    || known_files.find_by_hash(&hash).is_some_and(|r| r.friends_only)
                    || upload_server::friends_only_snapshot_contains(
                        shared_friends_only_hashes,
                        &hash,
                    )
                {
                    restricted_entries.push(hash);
                }
                // Rough pre-cap so encode stays under the frame budget.
                approx_bytes += 16
                    + 8
                    + 2
                    + name_bytes.len()
                    + 1
                    + if aich.is_some() { 20 } else { 0 }
                    + 32;
                encoded_entries.push((hash, f.size, name_bytes, aich, ember));
                if approx_bytes >= MAX_BROWSE_ANSWER_BYTES {
                    answer_full = true;
                }
            }
            let mut scope_delivered = true;
            // A requester that has not said it understands the scope
            // frame would drop it, file friends-only entries as public
            // and republish them. Leave them out instead.
            if !(supports_ebr1 && supports_scope) && !restricted_entries.is_empty() {
                encoded_entries.retain(|(h, ..)| !restricted_entries.contains(h));
                restricted_entries.clear();
                scope_delivered = false;
            }
            // It goes first on the same stream so it is already attached
            // to the pending request when the answer lands.
            if !restricted_entries.is_empty() {
                let scope = crate::network::browse::encode_browse_scope(restricted_entries.iter());
                let frame = ed2k::messages::build_ember_ext_frame(
                    ed2k::messages::EMBER_EXT_BROWSE_SCOPE,
                    &scope,
                );
                if let Err(e) = send_browse_response_to_origin(reply_tx, frame) {
                    tracing::warn!(
                        "Browse scope to {} on session {} dropped, listing public files only: {e}",
                        hex::encode(browse_eh),
                        session_id,
                    );
                    encoded_entries.retain(|(h, ..)| !restricted_entries.contains(h));
                    scope_delivered = false;
                }
            }
            // Skipped when the scope was lost: the answer then omits
            // friends-only rows the total still counts, and a total that
            // disagrees with the listing is worse than none.
            if supports_ebr1 && scope_delivered {
                let summary = crate::network::browse::encode_browse_summary(total_unique);
                let frame = ed2k::messages::build_ember_ext_frame(
                    ed2k::messages::EMBER_EXT_BROWSE_SUMMARY,
                    &summary,
                );
                if let Err(e) = send_browse_response_to_origin(reply_tx, frame) {
                    tracing::debug!(
                        "Browse summary to {} on session {} dropped: {e}",
                        hex::encode(browse_eh),
                        session_id,
                    );
                }
            }
            let res_payload = if supports_ebr1 {
                ed2k::multi_source::encode_browse_response_v1(
                    encoded_entries.iter().map(|(h, s, n, a, e)| {
                        (h, *s, n.as_slice(), a.as_ref(), e.as_ref())
                    }),
                )
            } else {
                ed2k::multi_source::encode_browse_response_legacy(
                    encoded_entries
                        .iter()
                        .map(|(h, s, n, _, _)| (h, *s, n.as_slice())),
                )
            };
            let mut packet = Vec::with_capacity(6 + res_payload.len());
            packet.push(OP_EMULEPROT);
            let size = (1 + res_payload.len()) as u32;
            packet.extend_from_slice(&size.to_le_bytes());
            packet.push(ed2k::messages::OP_EMBER_BROWSE_RES);
            packet.extend_from_slice(&res_payload);
            if let Err(e) = send_browse_response_to_origin(reply_tx, packet) {
                tracing::warn!(
                    "Browse response to {} on session {} dropped: {e}",
                    hex::encode(browse_eh),
                    session_id,
                );
            }
            report_friend_shares_browsed(state, app_handle, browse_eh, true);
        } else {
            // Complete the requester's wait. Dropping the packet
            // left their UI spinning until the 30s browse timeout
            // — the same "no files" answer they would get from an
            // empty library, without leaking whether we refused
            // for policy or had nothing to show.
            let res_payload = if supports_ebr1 {
                ed2k::multi_source::encode_browse_response_v1(std::iter::empty())
            } else {
                ed2k::multi_source::encode_browse_response_legacy(std::iter::empty())
            };
            let mut packet = Vec::with_capacity(6 + res_payload.len());
            packet.push(OP_EMULEPROT);
            let size = (1 + res_payload.len()) as u32;
            packet.extend_from_slice(&size.to_le_bytes());
            packet.push(ed2k::messages::OP_EMBER_BROWSE_RES);
            packet.extend_from_slice(&res_payload);
            if let Err(e) = send_browse_response_to_origin(reply_tx, packet) {
                tracing::debug!(
                    "Browse refusal to {} on session {} dropped: {e}",
                    hex::encode(browse_eh),
                    session_id,
                );
            }
            // Only a real friend is worth mentioning: they were refused because
            // friend browsing is off. Anyone else is refused silently, and
            // saying so would let a stranger put text on the user's screen.
            if is_mutual_friend {
                report_friend_shares_browsed(state, app_handle, browse_eh, false);
            }
        }
    }

    if let UploadEventKind::EmberBrowseSessionReady {
        ember_hash: browse_eh,
        request_id,
        session_id,
        tx,
    } = event.kind
    {
        let Some(()) = bind_browse_request_to_session(
            &mut state.pending_browse_requests,
            browse_eh,
            &request_id,
            session_id,
        ) else {
            let _ = tx.send(Err(
                "Browse request was cancelled before the friend session opened".into(),
            ));
            return;
        };
        dispatch_browse_head(state, app_handle, browse_eh).await;
        if browse_request_is_pending(
            &state.pending_browse_requests,
            browse_eh,
            &request_id,
        ) {
            let _ = tx.send(Ok(()));
        } else {
            let _ = tx.send(Err(
                "Browse session was replaced before the request was sent".into(),
            ));
        }
        return;
    }

    if let UploadEventKind::EmberBrowseSessionFailed {
        ember_hash: browse_eh,
        request_id,
        error,
        tx,
    } = event.kind
    {
        let _ = remove_browse_request(
            &mut state.pending_browse_requests,
            browse_eh,
            &request_id,
        );
        dispatch_browse_head(state, app_handle, browse_eh).await;
        let _ = tx.send(Err(error));
        return;
    }

    if let UploadEventKind::EmberBrowseScope {
        ember_hash: scope_eh,
        session_id,
        ref body,
    } = event.kind
    {
        if !friend_hashes.read().await.contains(&scope_eh) {
            return;
        }
        match crate::network::browse::parse_browse_scope(body) {
            Some(restricted) => {
                if !crate::network::browse::attach_browse_scope(
                    &mut state.pending_browse_requests,
                    scope_eh,
                    session_id,
                    restricted,
                ) {
                    debug!(
                        "Ignoring browse scope from {} with no request pending on session {}",
                        hex::encode(scope_eh),
                        session_id
                    );
                }
            }
            None => debug!(
                "Friend {} sent an unparseable browse scope ({} bytes)",
                hex::encode(scope_eh),
                body.len()
            ),
        }
        return;
    }

    if let UploadEventKind::EmberBrowseSummary {
        ember_hash: summary_eh,
        session_id,
        ref body,
    } = event.kind
    {
        if !friend_hashes.read().await.contains(&summary_eh) {
            return;
        }
        match crate::network::browse::parse_browse_summary(body) {
            Some(total) => {
                if !crate::network::browse::attach_browse_summary(
                    &mut state.pending_browse_requests,
                    summary_eh,
                    session_id,
                    total,
                ) {
                    debug!(
                        "Ignoring browse summary from {} with no request pending on session {}",
                        hex::encode(summary_eh),
                        session_id
                    );
                }
            }
            None => debug!(
                "Friend {} sent an unparseable browse summary ({} bytes)",
                hex::encode(summary_eh),
                body.len()
            ),
        }
        return;
    }

    if let UploadEventKind::EmberBrowseResponse {
        ember_hash: browse_eh,
        session_id,
        ref entries,
    } = event.kind
    {
        if !friend_hashes.read().await.contains(&browse_eh) {
            debug!("Dropping secure browse response after friend removal");
            return;
        }
        let hash_hex = hex::encode(browse_eh);
        let restricted = crate::network::browse::take_browse_scope(
            &mut state.pending_browse_requests,
            browse_eh,
            session_id,
        )
        .unwrap_or_default();
        let total = crate::network::browse::take_browse_total(
            &mut state.pending_browse_requests,
            browse_eh,
            session_id,
        );
        let listed: Vec<[u8; 16]> = entries
            .iter()
            .filter_map(|(hash, ..)| parse_ed2k_hash16(hash))
            .collect();
        let files: Vec<serde_json::Value> = entries
            .iter()
            .map(|(hash, size, name, aich, ember)| {
                let clean_name = crate::security::sanitize_display_name(name);
                let mut obj = serde_json::json!({
                    "hash": hash,
                    "size": size,
                    "name": clean_name,
                });
                if parse_ed2k_hash16(hash).is_some_and(|h| restricted.contains(&h)) {
                    obj.as_object_mut()
                        .unwrap()
                        .insert("friends_only".into(), serde_json::Value::Bool(true));
                }
                if let Some(aich_hash) = aich.as_ref().filter(|h| h.len() == 40) {
                    obj.as_object_mut().unwrap().insert(
                        "aich_hash".into(),
                        serde_json::Value::String(aich_hash.clone()),
                    );
                }
                if let Some(ember_file_hash) = ember.as_ref().filter(|h| h.len() == 64)
                {
                    obj.as_object_mut().unwrap().insert(
                        "ember_file_hash".into(),
                        serde_json::Value::String(ember_file_hash.clone()),
                    );
                }
                obj
            })
            .collect();
        match complete_browse_request(
            &mut state.pending_browse_requests,
            browse_eh,
            session_id,
        ) {
            Some(completion) => {
                crate::network::browse::record_friend_listing(
                    browse_eh,
                    listed.iter(),
                    &restricted,
                );
                if let crate::network::browse::BrowseCompletion::Deliver(request_id) = completion {
                    let _ = app_handle.emit("ember:browse-result", serde_json::json!({
                        "user_hash": hash_hex,
                        "request_id": request_id,
                        "files": files,
                        "total": total,
                    }));
                }
                dispatch_browse_head(state, app_handle, browse_eh).await;
            }
            None => {
                debug!(
                    "Ignoring stale or unbound browse response from {} session {}",
                    hash_hex, session_id
                );
            }
        }
    }

    if let UploadEventKind::EmberFriendDisconnected {
        ember_hash: dc_eh,
        session_id,
    } = event.kind
    {
        let hash_hex = hex::encode(dc_eh);
        for request_id in remove_browse_requests_for_session(
            &mut state.pending_browse_requests,
            dc_eh,
            session_id,
        ) {
            let _ = app_handle.emit("ember:browse-error", serde_json::json!({
                "user_hash": hash_hex,
                "request_id": request_id,
                "reason": "Friend disconnected",
            }));
        }
        // The queue may still contain requests already bound to a
        // newer replacement session. Re-enter the sole dispatcher
        // so the new head is sent instead of being stranded.
        dispatch_browse_head(state, app_handle, dc_eh).await;
        let newer_session_active = state
            .ember_sessions
            .read()
            .await
            .get(&dc_eh)
            .is_some_and(|handle| {
                handle.session_id() != session_id && handle.is_fresh()
            });
        if newer_session_active {
            debug!(
                "Ignoring disconnect from retired friend session {} for {}",
                session_id, hash_hex
            );
        } else {
            state.online_friends.remove(&dc_eh);
            state.outbound_session_tasks.remove(&dc_eh);
            let _ = app_handle.emit("ember:friend-offline", serde_json::json!({
                "user_hash": hash_hex,
            }));
        }

        if !newer_session_active
            && friend_hashes.read().await.contains(&dc_eh)
            && !state.ember_sessions.read().await.get(&dc_eh).is_some_and(|h| h.is_fresh())
        {
            let now_inst = std::time::Instant::now();
            let can_reconnect = match state.friend_reconnect_last.get(&dc_eh) {
                Some(last) => now_inst.saturating_duration_since(*last).as_secs() >= 60,
                None => true,
            };
            if can_reconnect {
                state.friend_reconnect_last.insert(dc_eh, now_inst);
                state.outbound_session_tasks.insert(dc_eh, now_inst);
                info!("Friend {} disconnected, reconnect via rendezvous", hash_hex);
                let _ = app_handle.emit("ember:friend-searching", serde_json::json!({
                    "user_hash": hash_hex,
                }));
                spawn_rendezvous_friend_lookup(
                    settings, state, ember_hash, dc_eh,
                    app_handle, friend_hashes, ul_event_tx,
                    ed25519_pubkey, ed25519_secret_key,
                );
            } else {
                debug!("Friend {} reconnect skipped (backoff cooldown)", hash_hex);
            }
        }
    }

    // A friend cannot dial us and is asking us to dial them
    // instead so they can download a file we share. This is the
    // friend-layer counterpart of an inbound eD2K
    // `OP_CALLBACKREQUESTED`, and needs neither a server login
    // nor a HighID on either side — the ask arrived over the
    // friend session, and the dial goes out from us.
    if let UploadEventKind::EmberTransferRequest {
        ember_hash: xfer_eh,
        request,
        ref reply_tx,
        peer_addr: xfer_peer_addr,
    } = event.kind
    {
        let mut status = friend_transfer_request_status(
            state,
            local_index,
            xfer_eh,
            &request,
            xfer_peer_addr,
            friend_hashes,
            mutual_friend_hashes,
        )
        .await;

        // Enqueue the dial *before* acking, so an accept is never
        // sent for a connect-back that never happens: the friend
        // would then park its source waiting on us for the full
        // attempt timeout instead of retrying promptly.
        //
        // Only a connect-back dials. A punch carries `tcp_port` 0
        // and is answered by the punch responder taking the serve
        // role, so dialing here would target `peer_ip:0`.
        if status == ed2k::messages::XFER_STATUS_ACCEPTED
            && request.method == ed2k::messages::EmberXferMethod::ConnectBack
        {
            // Dial the address the friend session is actually
            // connected to, never one from the payload, with the
            // listening port they advertised. `secure_friend_ember_hash`
            // makes this a Noise IK dial so they can route our
            // connection into the right download by proven identity.
            let dial_addr = SocketAddr::new(xfer_peer_addr.ip(), request.tcp_port);
            match connect_serve_tx.try_send(
                upload_server::ConnectServeRequest {
                    peer_addr: dial_addr,
                    crypt_options: 0,
                    user_hash: None,
                    push_grant_file_hash: None,
                    push_grant_accepted: None,
                    secure_friend_ember_hash: Some(xfer_eh),
                },
            ) {
                Ok(()) => info!(
                    "Friend {} asked us to connect back to {dial_addr} for {}; dialing",
                    hex::encode(xfer_eh),
                    hex::encode(request.file_hash)
                ),
                Err(e) => {
                    debug!(
                        "Could not enqueue friend transfer dial to {dial_addr}: {e}"
                    );
                    // Our dialer is saturated, not the friend's
                    // fault and not permanent — "try later" is
                    // exactly what rate-limited means to them.
                    status = ed2k::messages::XFER_STATUS_DECLINED_RATE_LIMITED;
                    // Don't let a request we couldn't act on start
                    // the inbound cooldown.
                    state.friend_xfer_inbound_last.remove(&xfer_eh);
                }
            }
        }

        let ack = ed2k::messages::build_ember_xfer_ack(status, &request.nonce);
        let mut packet = Vec::with_capacity(6 + ack.len());
        packet.push(OP_EMULEPROT);
        packet.extend_from_slice(&((1 + ack.len()) as u32).to_le_bytes());
        packet.push(ed2k::messages::OP_EMBER_XFER_ACK);
        packet.extend_from_slice(&ack);
        let _ = reply_tx.try_send(packet);
    }

    // A friend answered our own `OP_EMBER_XFER_REQ`. An accept
    // needs no action here — the pending expectation was already
    // registered when we sent the request, precisely so their dial
    // can't arrive before we're ready for it. A decline releases
    // the source immediately instead of letting it idle out the
    // full attempt timeout.
    if let UploadEventKind::EmberTransferAck {
        ember_hash: ack_eh,
        status,
        nonce,
    } = event.kind
    {
        handle_friend_transfer_ack(
            state,
            transfer_manager,
            pending_kad_callbacks,
            app_handle,
            ul_event_tx,
            settings,
            ed25519_secret_key,
            ember_hash,
            ack_eh,
            status,
            nonce,
        )
        .await;
    }

    if let UploadEventKind::FriendTransferPunchFailed { friend, nonce } = event.kind {
        abandon_friend_transfer_attempt(
            state,
            transfer_manager,
            pending_kad_callbacks,
            app_handle,
            friend,
            nonce,
        )
        .await;
    }

    if let UploadEventKind::EmberFriendSearchFailed { ember_hash: failed_eh } = event.kind {
        // Pure cleanup signal from the rendezvous /
        // chat-auto-connect / browse-auto-connect spawns.
        // Distinct from `EmberFriendDisconnected` so we
        // don't fire `ember:friend-offline` /
        // `ember:browse-error` for a peer who was never
        // online in this session, and don't kick off a
        // reconnect attempt (the spawn just gave up — an
        // immediate retry would dogpile rendezvous and
        // hammer the same dead address). The user-facing
        // `ember:friend-search-failed` event with a
        // structured reason is emitted from inside the
        // spawn itself; here we only mutate state.
        state.outbound_session_tasks.remove(&failed_eh);
    }

    // Reputation: record upload-side events
    match &event.kind {
        UploadEventKind::Started {
            user_hash: Some(ref uh_hex),
            ref peer_addr,
            ..
        } => {
            if let Ok(bytes) = hex::decode(uh_hex) {
                if bytes.len() == 16 {
                    let mut uh = [0u8; 16];
                    uh.copy_from_slice(&bytes);
                    if let Some(ip) = peer_addr
                        .parse::<SocketAddr>()
                        .ok()
                        .and_then(|addr| match addr.ip() {
                            std::net::IpAddr::V4(ip) => Some(ip),
                            _ => None,
                        })
                    {
                        state.reputation.record_event_with_ip(
                            &uh,
                            ip,
                            ember::reputation::ReputationEvent::SuccessfulHandshake,
                        );
                    } else {
                        state.reputation.record_event(
                            &uh,
                            ember::reputation::ReputationEvent::SuccessfulHandshake,
                        );
                    }
                }
            }
        }
        UploadEventKind::Completed { .. } => {
            let mgr = transfer_manager.read().await;
            if let Some(t) = mgr.get_transfer(&event.transfer_id) {
                if let Some(ref uh_hex) = t.user_hash {
                    if let Ok(bytes) = hex::decode(uh_hex) {
                        if bytes.len() == 16 {
                            let mut uh = [0u8; 16];
                            uh.copy_from_slice(&bytes);
                            if let Some(ip) = t
                                .peer_id
                                .split(':')
                                .next()
                                .and_then(|value| value.parse::<Ipv4Addr>().ok())
                            {
                                state.reputation.record_event_with_ip(
                                    &uh,
                                    ip,
                                    ember::reputation::ReputationEvent::SuccessfulChunk,
                                );
                            } else {
                                state.reputation.record_event(
                                    &uh,
                                    ember::reputation::ReputationEvent::SuccessfulChunk,
                                );
                            }
                        }
                    }
                }
            }
            drop(mgr);
        }
        UploadEventKind::Failed { ref error } => {
            // Pull the peer identity out first, then drop the
            // transfer-manager lock before touching the source
            // manager / reputation state. Skip queue/session
            // mechanics that are not evidence of bad peer data.
            if is_neutral_upload_failure(error) {
                // no reputation strike
            } else {
            let peer_info: Option<([u8; 16], Option<Ipv4Addr>)> = {
                let mgr = transfer_manager.read().await;
                mgr.get_transfer(&event.transfer_id).and_then(|t| {
                    t.user_hash.as_ref().and_then(|uh_hex| hex::decode(uh_hex).ok()).and_then(|bytes| {
                        if bytes.len() == 16 {
                            let mut uh = [0u8; 16];
                            uh.copy_from_slice(&bytes);
                            let peer_ip =
                                split_peer_id(&t.peer_id).0.parse::<Ipv4Addr>().ok();
                            Some((uh, peer_ip))
                        } else {
                            None
                        }
                    })
                })
            };
            if let Some((uh, peer_ip)) = peer_info {
                let (node_banned, ip_banned) = if let Some(ip) = peer_ip {
                    state.reputation.record_event_with_ip(
                        &uh,
                        ip,
                        ember::reputation::ReputationEvent::FailedChunk,
                    )
                } else {
                    (
                        state.reputation.record_event(
                            &uh,
                            ember::reputation::ReputationEvent::FailedChunk,
                        ),
                        false,
                    )
                };
                if node_banned || ip_banned {
                    // The address on the transfer only. Other addresses filed
                    // under this user hash came from source records and
                    // exchanges anyone can forge; the identity itself is
                    // refused by hash from now on, whatever address it uses.
                    apply_reputation_ban_ips(state, shared_banned_ips, peer_ip, &uh);
                }
            }
            }
        }
        UploadEventKind::PeerAutoBanned { ip, reason, user_hash } => {
            // Manual live-session capture (hash-banned peer caught
            // mid-upload): persist against the peer row only — not
            // the 7-day auto-ban table — so unban_peer remains the
            // sole lifetime authority.
            let is_manual_capture = user_hash.is_some()
                && reason.starts_with("manual peer ban");
            if is_manual_capture {
                if state.banned_ips.insert(*ip) {
                    warn!("Manual ban capture: banning IP {ip} ({reason})");
                }
                if let Ok(mut shared) = shared_banned_ips.write() {
                    *shared = state.banned_ips.clone();
                }
                if let Some(uh) = user_hash {
                    let peer_id_hex = hex::encode(uh);
                    if let Err(e) = db.add_banned_peer_address(&peer_id_hex, *ip) {
                        warn!("Failed to record captured ban IP {ip} for peer {peer_id_hex}: {e}");
                    }
                }
            } else {
                // Abuse / AddRequestCount: a timing heuristic, so it
                // gets eMule's `CLIENTBANTIME` rather than the long
                // ban reserved for content evidence.
                apply_persistent_ip_ban(
                    &mut state.banned_ips,
                    shared_banned_ips,
                    db,
                    *ip,
                    reason,
                    AUTO_BAN_TTL_BEHAVIOUR_SECS,
                );
            }
        }
        _ => {}
    }

    let mut promoted = Vec::new();
    if let Err(p) = std::panic::AssertUnwindSafe(handle_upload_event(event, app_handle, transfer_manager, &mut promoted, stats_manager, bandwidth_limiter.effective_upload_rate())).catch_unwind().await {
        error!("handle_upload_event panicked, dropping event: {}", describe_panic(&*p));
    }
    for t in promoted {
        // The transfer just moved from the queue into the active set
        // with a fresh waiting status (Searching/Queued). Announce it
        // now so the row leaves "Queued" in real time instead of
        // waiting for the next reconciling poll.
        crate::commands::transfers::emit_transfer_status(
            app_handle,
            &t.id,
            &t.status,
        );
        let control = reregister_transfer_control(transfer_manager, &t.id).await;
        let (resume_peer_ip, resume_peer_port) = split_peer_id(&t.peer_id);
        handle_command(
            udp_socket,
            NetworkCommand::StartDownload {
                file_hash: t.file_hash.clone(),
                file_name: t.file_name.clone(),
                file_size: t.total_size,
                peer_ip: resume_peer_ip,
                peer_port: resume_peer_port,
                extra_sources: Vec::new(),
                ember_file_hash: t.ember_file_hash.clone().unwrap_or_default(),
                expected_aich: t.expected_aich.clone(),
                transfer_id: t.id.clone(),
                control,
                discovery_only: false,
                friend_ember_hash: None,
            },
            state,
            local_index,
            fresh_part_hashes,
            settings,
            dl_event_tx,
            bandwidth_limiter,
            db,
            app_handle,
            transfer_manager,
            source_manager,
            credit_manager,
            stats_manager,
            known_files,
            server_udp,
            firewall_probe_ips,
            shared_banned_ips,
            shared_banned_hashes,
            shared_friends_only_hashes,
            shared_server_addr,
            shared_ember_payload,
            ember_payload_generation,
            geoip,
            friend_hashes,
            mutual_friend_hashes,
            ember_hash,
            ul_event_tx,
            ed25519_pubkey,
            ed25519_secret_key,
            upload_queue_handle,
            transfer_status_writes,
        ).await;
    }
}
