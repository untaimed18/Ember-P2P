//! Download worker events as the loop receives them: part-file and completion
//! bookkeeping, sources from source exchange and Ember peer exchange, friend
//! and Ember messages carried on download sessions, part verification and
//! corruption tracking, then `handle_download_event` behind `catch_unwind`.

use super::*;

/// How often a download's progress is written to SQLite between terminal
/// state changes; `start_network` explains why this is throttled.
const DB_PROGRESS_PERSIST_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);

/// Tell the UI, at most once per this many seconds, that downloads are being
/// refused by the download folder. Every waiting download hits the same wall on
/// each retry, and one notice says everything the next hundred would.
const DOWNLOAD_FOLDER_NOTICE_INTERVAL_SECS: i64 = 300;

fn emit_download_folder_unavailable(app_handle: &tauri::AppHandle) {
    static LAST_NOTICE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
    let now = chrono::Utc::now().timestamp();
    let last = LAST_NOTICE.load(std::sync::atomic::Ordering::Relaxed);
    if now.saturating_sub(last) < DOWNLOAD_FOLDER_NOTICE_INTERVAL_SECS
        || LAST_NOTICE
            .compare_exchange(last, now, std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed)
            .is_err()
    {
        return;
    }
    let _ = app_handle.emit("download-folder-unavailable", ());
}

/// Per transfer: re-queues in a row without gaining bytes, and the completed
/// size at the last one.
///
/// `PendingDownload::search_count` cannot carry this across a restart: every
/// start path removes the pending entry, so each failure re-queued at count 1.
fn requeue_history() -> &'static std::sync::Mutex<HashMap<String, (u32, u64)>> {
    static HISTORY: std::sync::OnceLock<std::sync::Mutex<HashMap<String, (u32, u64)>>> =
        std::sync::OnceLock::new();
    HISTORY.get_or_init(Default::default)
}

/// Search count for a re-queue. It grows while failures arrive without
/// progress, which backs off `pending_download_retry_interval`; bytes gained
/// since the last re-queue restart it, so a download that was working keeps
/// the quick first retry it always had.
fn next_requeue_search_count(
    prev_pending: Option<u32>,
    last: Option<(u32, u64)>,
    completed_now: u64,
) -> u32 {
    let carried = match last {
        Some((count, completed_then)) if completed_now <= completed_then => count,
        _ => 0,
    };
    carried.max(prev_pending.unwrap_or(0)).saturating_add(1)
}

/// `last_search_at` for a re-queued download. The first re-queue after
/// progress retries at once, as before; later ones wait out the interval
/// their count earned instead of retrying on the next tick.
fn requeue_last_search_at(search_count: u32, now: i64) -> i64 {
    if search_count <= 1 {
        0
    } else {
        now
    }
}

fn note_requeue(transfer_id: &str, prev_pending: Option<u32>, completed_now: u64) -> u32 {
    let Ok(mut history) = requeue_history().lock() else {
        return prev_pending.unwrap_or(0).saturating_add(1);
    };
    let count =
        next_requeue_search_count(prev_pending, history.get(transfer_id).copied(), completed_now);
    history.insert(transfer_id.to_string(), (count, completed_now));
    count
}

fn forget_requeue_history(transfer_id: &str) {
    if let Ok(mut history) = requeue_history().lock() {
        history.remove(transfer_id);
    }
}

/// Scope of a finished download's known.met record. An existing record is the
/// user's own decision about this content and wins either way: re-downloading
/// something they restricted must not republish it, and a friend's restriction
/// must not take back something they already share openly. Only new content
/// inherits the friend's restriction (still shared, but only with friends).
fn completed_download_friends_only(
    from_restricting_friend: bool,
    existing_record: Option<bool>,
) -> bool {
    existing_record.unwrap_or(from_restricting_friend)
}

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_download_event(
    event: DownloadEvent,
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
    a4af_shared: &Arc<RwLock<A4AFManager>>,
    aich_set_tx: &mpsc::Sender<ed2k::aich::AICHRecoveryHashSet>,
    db_progress_last_persist: &mut HashMap<String, std::time::Instant>,
    ember_digest_result_tx: &mpsc::UnboundedSender<([u8; 16], [u8; 32])>,
    part_hashset_result_tx: &mpsc::UnboundedSender<([u8; 16], Vec<[u8; 16]>)>,
    pending_kad_callbacks: &upload_server::PendingKadCallbacks,
    shared_files: &Arc<RwLock<Vec<FileInfo>>>,
    spam_filter: &Arc<RwLock<crate::search::spam::SpamFilter>>,
    transfer_status_writes: &Arc<TransferStatusWriteClock>,
    upload_queue_handle: &ed2k::upload::UploadQueueRef,
) {
    if let DownloadEvent::PartFileReady { ref transfer_id, ref file_hash, file_size, ref file_name } = event {
        info!("Part file ready for {} ({}) — queuing server offer and publishing to KAD",
            transfer_id, hex::encode(file_hash));
        let from_restricting_friend = {
            let mgr = transfer_manager.read().await;
            mgr.get_transfer(transfer_id).is_some_and(|t| t.friends_only)
        };
        let restricted = from_restricting_friend || {
            let index = local_index.read().await;
            !known_files.is_authoritative()
                || hash16_is_friends_only(file_hash, &index, known_files)
        };
        if !restricted {
        // Flag the shared list dirty rather than offering at once: eMule
        // batches new files into the next `SendListToServer`, at most one per
        // ED2KREPUBLISHTIME (`SharedFileList.cpp:653-663`, `:1226-1233`).
        // The drain skips hashes this session has already offered, since
        // re-sending one is the republish Lugdunum penalises.
        if state.server_connected && !state.offered_ed2k_hashes.contains(file_hash) {
            state.request_offer_files = true;
        }
        let kad_hash = md4_bytes_to_kad_id(file_hash);
        let ext = std::path::Path::new(file_name.as_str())
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();
        state.publish_manager.add_file(PublishableFile {
            file_hash: kad_hash,
            file_size,
            file_name: file_name.clone(),
            file_type: crate::search::index::infer_file_type(&ext),
            complete_sources: 0,
            keyword_publishable: false,
            last_source_publish: known_files
                .find_by_hash(file_hash)
                .map(|r| r.last_publish_src as i64)
                .unwrap_or(0),
        });
        }
    }
    if let DownloadEvent::Completed {
        ref transfer_id,
        ref final_path,
        part_hashes: ref event_part_hashes,
        ..
    } = event
    {
        {
            let mgr_snap = transfer_manager.read().await;
            if let Some(t) = mgr_snap.get_transfer(transfer_id) {
                info!(
                    "Download COMPLETED: {} \"{}\" ({}, {:.1} MB)",
                    transfer_id, t.file_name, t.file_hash,
                    t.total_size as f64 / (1024.0 * 1024.0)
                );
            } else {
                info!("Download COMPLETED: {}", transfer_id);
            }
        }
        state.active_source_senders.remove(transfer_id);
        state.active_established_senders.remove(transfer_id);
        state.active_source_overflow.remove(transfer_id);
        state.active_kad_search_state.remove(transfer_id);
        state.per_file_sources.remove(transfer_id);
        state.download_handles.remove(transfer_id);
        forget_requeue_history(transfer_id);
        {
            let mgr_snap = transfer_manager.read().await;
            if let Some(t) = mgr_snap.get_transfer(transfer_id) {
                if let Ok(fh_bytes) = hex::decode(&t.file_hash) {
                    if fh_bytes.len() == 16 {
                        let mut fh = [0u8; 16];
                        fh.copy_from_slice(&fh_bytes);
                        if let Ok(mut map) = state.aich_recovery_pending.write() {
                            map.retain(|(h, _), _| *h != fh);
                        }
                    }
                }
            }
        }
        let stale_sids: Vec<SearchId> = state.download_source_searches.iter()
            .filter(|(_, (tid, _))| tid == transfer_id)
            .map(|(sid, _)| *sid)
            .collect();
        for sid in &stale_sids {
            state.download_source_searches.remove(sid);
            if let Some(removed) = state.search_manager.remove(sid) {
                state.routing_table.release_contacts_in_use(&removed.in_use_ids);
            }
        }
        // Snapshot only the fields we need, then release the
        // `transfer_manager` read lock immediately. The rest of
        // this handler runs several `.await`s (source_manager
        // read, local_index write/read, shared_files write). Holding the
        // read lock across them previously stalled the whole
        // network `select!` loop and blocked download workers that
        // need `transfer_manager.write()`.
        let completed_snapshot = {
            let mgr = transfer_manager.read().await;
            mgr.get_transfer(transfer_id).map(|t| (
                t.peer_id.clone(),
                t.file_hash.clone(),
                t.file_name.clone(),
                t.total_size,
                t.transferred,
                t.friends_only,
            ))
        };
        if let Some((peer_id, file_hash, file_name, file_size, _transferred, from_restricting_friend)) =
            completed_snapshot
        {
            if let Some((ip_str, port_str)) = peer_id.split_once(':') {
                if let (Ok(ip), Ok(port)) = (ip_str.parse::<Ipv4Addr>(), port_str.parse::<u16>()) {
                    state.dead_sources.remove(0, u32::from(ip), port);
                }
            }
            // Clear all per-file dead source entries for this completed file
            if let Ok(fh_bytes) = hex::decode(&file_hash) {
                if fh_bytes.len() == 16 {
                    let mut fh = [0u8; 16];
                    fh.copy_from_slice(&fh_bytes);
                    let sm = source_manager.read().await;
                    for (ip, port) in sm.get_sources(&fh) {
                        state.dead_sources.remove_for_file(&fh, u32::from(ip), port);
                    }
                }
            }
            let sanitized_name = crate::security::sanitize_filename(&file_name);
            let default_completed_path = PathBuf::from(&settings.download_folder)
                .join("Downloads")
                .join(&sanitized_name);
            // The transfer owns final-name claiming and may choose a
            // deduplicated path. Using a reconstructed default path
            // here creates a second transient LocalIndex row when the
            // file watcher observes the actual path.
            let completed_path = final_path
                .as_deref()
                .filter(|path| !path.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| default_completed_path.clone());
            let completed_name = completed_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .filter(|name| !name.is_empty())
                .unwrap_or(sanitized_name);
            let now = chrono::Utc::now().timestamp();

            if let Ok(hash_bytes) = hex::decode(&file_hash) {
                if hash_bytes.len() == 16 {
                    let mut fh = [0u8; 16];
                    fh.copy_from_slice(&hash_bytes);
                    use crate::storage::known_files::KnownFileRecord;
                    let existing = known_files.find_by_hash(&fh).cloned();
                    // Prefer the hashset already verified during
                    // the transfer, then a valid cached set, before
                    // re-reading the completed file.
                    let part_hashes = if !event_part_hashes.is_empty() {
                        event_part_hashes.clone()
                    } else if existing.as_ref().is_some_and(|record| {
                        record.part_hashes.len()
                            == ed2k::hash::ed2k_known_met_part_hash_count(file_size)
                    }) {
                        existing
                            .as_ref()
                            .map(|record| record.part_hashes.clone())
                            .unwrap_or_default()
                    } else {
                        // Recompute off the loop and fold it in
                        // when it lands, exactly as the BLAKE3
                        // digest below does. Awaiting a sequential
                        // end-to-end read of a multi-GB file here
                        // suspended the whole `select!` — no UDP
                        // receive, no timers, no command handling —
                        // on every completion that arrives without
                        // a hashset (callback and single-source
                        // downloads, and restore re-verification).
                        let hash_path = completed_path.clone();
                        let hashset_tx = part_hashset_result_tx.clone();
                        tokio::task::spawn_blocking(move || {
                            // Another whole-file read the library
                            // scheduler would otherwise not see. It
                            // rations reads per physical drive, and
                            // this one lands on the same spindle a
                            // scan may be working through.
                            let _drive_busy =
                                crate::sharing::disk::note_external_read(&hash_path);
                            if let Ok(hashes) =
                                ed2k::hash::ed2k_part_hashes_file(&hash_path)
                            {
                                if !hashes.is_empty() {
                                    let _ = hashset_tx.send((fh, hashes));
                                }
                            }
                        });
                        Vec::new()
                    };
                    let record = KnownFileRecord {
                        file_hash: fh,
                        part_hashes,
                        file_name: completed_name.clone(),
                        file_size,
                        file_path: completed_path.to_string_lossy().to_string(),
                        aich_hash: existing
                            .as_ref()
                            .map(|record| record.aich_hash.clone())
                            .unwrap_or_default(),
                        ember_file_hash: {
                            // Prefer a digest verified/learned this
                            // session, then any prior known.met value,
                            // then compute BLAKE3 of the completed
                            // file so deep-link / paste downloads
                            // still get content integrity for share.
                            let ember_hex = state
                                .ember_content_hashes
                                .get(&fh)
                                .map(|pin| pin.digest)
                                .filter(|d| *d != [0u8; 32])
                                .map(hex::encode)
                                .or_else(|| {
                                    existing.as_ref().and_then(|record| {
                                        if record.ember_file_hash.is_empty() {
                                            None
                                        } else {
                                            Some(record.ember_file_hash.clone())
                                        }
                                    })
                                })
                                .unwrap_or_default();
                            if ember_hex.is_empty() {
                                // Compute it off the loop and fold
                                // it in when it lands. Awaiting the
                                // hash here suspended the whole
                                // `select!` for as long as it took
                                // to read the file end to end — no
                                // UDP receive, no timers, no
                                // command handling, on every plain
                                // eD2K completion (the fallback is
                                // the common case: only an Ember
                                // DHT hit or a prior known.met
                                // record fills the field above).
                                let hash_path = completed_path.clone();
                                let digest_tx = ember_digest_result_tx.clone();
                                tokio::task::spawn_blocking(move || {
                                    if let Ok(digest) =
                                        crate::network::ember::crypto::blake3_hash_file_path(
                                            &hash_path,
                                        )
                                    {
                                        let _ = digest_tx.send((fh, digest));
                                    }
                                });
                            }
                            ember_hex
                        },
                        modified_at: now,
                        // The dropped `_transferred` field on the
                        // completed-download snapshot is this
                        // transfer's *downloaded* byte count, not
                        // anything uploaded. Seeding
                        // all_time_transferred with it (as this code
                        // used to) credited every freshly-downloaded,
                        // auto-shared file with a full-file-size
                        // "upload" the moment it finished
                        // downloading, even with zero real uploads —
                        // inflating the Library's Top Uploads panel
                        // for every completed download. Only ever
                        // preserve a pre-existing record's real
                        // upload total (e.g. re-downloading
                        // previously-shared content); a genuinely new
                        // hash starts at 0 and accumulates only
                        // through real upload events (see
                        // `add_all_time_transferred`).
                        all_time_transferred: existing
                            .as_ref()
                            .map(|record| record.all_time_transferred)
                            .unwrap_or(0),
                        all_time_requested: existing
                            .as_ref()
                            .map(|record| record.all_time_requested)
                            .unwrap_or(0),
                        all_time_accepted: existing
                            .as_ref()
                            .map(|record| record.all_time_accepted)
                            .unwrap_or(0),
                        upload_priority: existing
                            .as_ref()
                            .map(|record| record.upload_priority)
                            .unwrap_or_else(|| {
                                crate::storage::known_files::priority_str_to_u8(
                                    "normal",
                                )
                            }),
                        last_publish_src: existing
                            .as_ref()
                            .map(|record| record.last_publish_src)
                            .unwrap_or(0),
                        last_shared: existing
                            .as_ref()
                            .map(|record| record.last_shared)
                            .unwrap_or(0),
                        is_shared: crate::storage::share_intent::effective_shared(
                            &fh,
                            existing
                                .as_ref()
                                .map(|record| record.is_shared)
                                .unwrap_or(true),
                        ),
                        friends_only: completed_download_friends_only(
                            from_restricting_friend,
                            existing.as_ref().map(|record| record.friends_only),
                        ),
                        complete_sources: existing
                            .as_ref()
                            .map(|record| record.complete_sources)
                            .unwrap_or(0),
                        last_ember_source_publish: existing
                            .as_ref()
                            .map(|record| record.last_ember_source_publish)
                            .unwrap_or(0),
                        last_ember_keyword_publish: existing
                            .as_ref()
                            .map(|record| record.last_ember_keyword_publish)
                            .unwrap_or(0),
                        media: existing.as_ref().and_then(|r| r.media.clone()),
                        media_scanned: existing
                            .as_ref()
                            .is_some_and(|r| r.media_scanned),
                    };
                    let completed_friends_only = record.friends_only;
                    known_files.add_or_update(record.clone());
                    if completed_friends_only {
                        sync_shared_friends_only_hashes(shared_friends_only_hashes, known_files);
                    }

                    // Auto-share completed download (eMule: CPartFile::PerformFileCompleteEnd)
                    let ext = completed_path.extension()
                        .map(|e| e.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let folder = completed_path.parent()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let shared_file = FileInfo {
                        id: file_hash.clone(),
                        name: completed_name,
                        path: completed_path.to_string_lossy().to_string(),
                        size: file_size,
                        hash: file_hash,
                        aich_hash: record.aich_hash.clone(),
                        ember_file_hash: record.ember_file_hash.clone(),
                        extension: ext,
                        modified_at: now,
                        priority: existing
                            .as_ref()
                            .map(|record| {
                                crate::storage::known_files::priority_u8_to_str(
                                    record.upload_priority,
                                )
                                .to_string()
                            })
                            .unwrap_or_else(|| "normal".to_string()),
                        requests: 0,
                        accepted: 0,
                        bytes_transferred: 0,
                        alltime_requests: existing
                            .as_ref()
                            .map(|record| record.all_time_requested)
                            .unwrap_or(0),
                        alltime_accepted: existing
                            .as_ref()
                            .map(|record| record.all_time_accepted)
                            .unwrap_or(0),
                        alltime_transferred: existing
                            .as_ref()
                            .map(|record| record.all_time_transferred)
                            .unwrap_or(0),
                        complete_sources: existing
                            .as_ref()
                            .map(|record| record.complete_sources)
                            .unwrap_or(0),
                        folder,
                        shared: crate::storage::share_intent::effective_shared(
                            &fh,
                            existing
                                .as_ref()
                                .map(|record| record.is_shared)
                                .unwrap_or(true),
                        ),
                        friends_only: completed_friends_only,
                        shared_kad: false,
                        shared_ed2k: false,
                        shared_ember: false,
                    };
                    let shared_file = {
                        let mut index = local_index.write().await;
                        // Clean up the old reconstructed-default row
                        // only when it is an on-disk orphan carrying
                        // this exact completed hash/size. A pending
                        // or merely same-named row is not proof that
                        // it represents this physical completion.
                        if default_completed_path != completed_path
                            && !default_completed_path.exists()
                        {
                            let default_path =
                                default_completed_path.to_string_lossy().to_string();
                            let is_proven_orphan = index
                                .get_by_path(&default_path)
                                .is_some_and(|file| {
                                    file.hash.eq_ignore_ascii_case(&shared_file.hash)
                                        && file.size == shared_file.size
                                });
                            if is_proven_orphan {
                                index.remove_file_by_path(&default_path);
                            }
                        }
                        // Always upsert. LocalIndex preserves
                        // runtime/shared flags from an existing
                        // same-path (including pending) row.
                        index.add_file(shared_file.clone());
                        // `add_file` keeps a pre-existing row's flag, and a
                        // row the watcher found first reads public. Only this
                        // path is ours to restrict; other copies of the hash
                        // keep their own scope.
                        if completed_friends_only {
                            if let Some(mut row) = index
                                .get_by_path(&shared_file.path)
                                .filter(|row| !row.friends_only)
                                .cloned()
                            {
                                row.friends_only = true;
                                index.remove_file_by_path(&shared_file.path);
                                index.add_file(row);
                            }
                        }
                        index
                            .get_by_path(&shared_file.path)
                            .cloned()
                            .unwrap_or(shared_file)
                    };
                    {
                        let mut snap = local_index.read().await.all_files().to_vec();
                        let kad_connected =
                            state.stats.status == NetworkStatus::Connected;
                        let kad_published =
                            state.publish_manager.source_published_md4_hashes();
                        apply_publish_badges(
                            &mut snap,
                            kad_connected,
                            state.server_connected,
                            settings.ember_native_enabled
                                && state.ember_dht.routing().verified_len() > 0,
                            &kad_published,
                            &state.offered_ed2k_hashes,
                            &state.ember_published_sources,
                        );
                        *shared_files.write().await = snap;
                    }

                    if kad_may_advertise_complete(
                        &shared_file,
                        known_files,
                        &{
                            let index = local_index.read().await;
                            collect_friends_only_hashes(&index, known_files)
                        },
                    ) {
                        // Publish to KAD
                        state.publish_manager.add_file(PublishableFile {
                            file_hash: md4_bytes_to_kad_id(&hash_bytes[..16]),
                            file_name: shared_file.name.clone(),
                            file_size: shared_file.size,
                            file_type: crate::search::index::infer_file_type(&shared_file.extension),
                            complete_sources: shared_file.complete_sources,
                            keyword_publishable: true,
                            last_source_publish: {
                                let mut raw = [0u8; 16];
                                raw.copy_from_slice(&hash_bytes[..16]);
                                known_files
                                    .find_by_hash(&raw)
                                    .map(|r| r.last_publish_src as i64)
                                    .unwrap_or(0)
                            },
                        });

                        // Offer to eD2K server through the batched drain, like
                        // any other new shared file. A hash already offered as
                        // a partial is republished only to a server with
                        // SRV_TCPFLG_COMPRESSION, whose index records complete
                        // vs. partial (eMule `RepublishFile`,
                        // `SharedFileList.cpp:667-674`, called from
                        // `PartFile.cpp:3015-3016`); to any other server the
                        // earlier offer already says everything it can hold.
                        if state.server_connected {
                            let server_compresses = state.server_connection.as_ref().is_some_and(|c| {
                                c.session.server_flags & ed2k::server::SRV_TCPFLG_COMPRESSION != 0
                            });
                            if server_compresses {
                                state.offered_ed2k_hashes.remove(&fh);
                            }
                            state.request_offer_files = true;
                        }
                    }

                    let _ = app_handle.emit("shared-files-changed", serde_json::json!({
                        "phase": "download-complete",
                        "count": 1,
                    }));
                    info!(
                        "Indexed completed download: {} (shared={})",
                        file_name, shared_file.shared
                    );

                    // Build full AICH hash set for the completed file
                    // (enables AICH-based verification when serving to other peers)
                    let aich_path = completed_path.clone();
                    let aich_data_dir = state.data_dir.clone();
                    let aich_tx = aich_set_tx.clone();
                    tokio::task::spawn_blocking(move || {
                        match ed2k::aich::AICHRecoveryHashSet::build_from_file(&aich_path) {
                            Ok(hs) => {
                                let aich_hex = hex::encode(hs.root_hash);
                                let cache_path = aich_data_dir.join("aich_cache.dat");
                                if let Err(error) =
                                    persist_aich_cache_entry(&cache_path, fh, hs.root_hash)
                                {
                                    tracing::warn!(
                                        "Failed to persist AICH cache entry: {error}"
                                    );
                                }
                                tracing::info!("Computed AICH root for completed download: {aich_hex}");
                                if let Err(e) = aich_tx.try_send(hs) {
                                    tracing::warn!("AICH hash-set queue full/closed, hash set not stored: {e}");
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Failed to compute AICH for completed download: {e}");
                            }
                        }
                    });
                }
            }
        }
    }
    if let DownloadEvent::Failed { ref transfer_id, ref error, ref failure_kind } = event {
        state.active_source_senders.remove(transfer_id);
        state.active_established_senders.remove(transfer_id);
        state.active_source_overflow.remove(transfer_id);
        state.active_kad_search_state.remove(transfer_id);
        state.download_handles.remove(transfer_id);
        if let Some(pfs) = state.per_file_sources.get_mut(transfer_id) {
            pfs.reset_active_states();
        }

        // Cancel stale KAD source searches so they don't waste
        // bandwidth while the download is re-queued.
        let stale_sids: Vec<SearchId> = state.download_source_searches.iter()
            .filter(|(_, (tid, _))| tid == transfer_id)
            .map(|(sid, _)| *sid)
            .collect();
        for sid in &stale_sids {
            state.download_source_searches.remove(sid);
            if let Some(removed) = state.search_manager.remove(sid) {
                state.routing_table.release_contacts_in_use(&removed.in_use_ids);
            }
        }
        let failure_stage = ed2k::transfer::infer_stage_from_error(error).to_string();
        let failure_kind_name = ed2k::transfer::failure_kind_name(failure_kind);
        let failure_code = ed2k::transfer::classify_failure(error, failure_kind);
        let failure_summary = failure_code.message();
        // Our own folder refused the write; no peer was involved, so none is
        // blamed or penalized. The row still re-queues below and recovers by
        // itself once the folder is fixed, which is what eMule does too.
        let is_folder_error =
            failure_code == ed2k::transfer::TransferFailureCode::DownloadFolderUnavailable;
        if is_folder_error {
            warn!("Download {transfer_id} cannot use its download folder: {error}");
            emit_download_folder_unavailable(app_handle);
        }
        // The finished `.part` could not be read back. Also local: no source
        // is blamed, the same as a folder error.
        let is_local_read_error = matches!(
            failure_code,
            ed2k::transfer::TransferFailureCode::FinalVerifyInconclusive
                | ed2k::transfer::TransferFailureCode::LocalReadFailed
        );
        let blames_source = !is_folder_error && !is_local_read_error;

        // Prefer is_user_cancel_error for source-failure classification;
        // also honour an already-cancelled control (cancel race).
        // `settled_by_user` covers the rest of the same story: Pause
        // and Stop cancel the control, which tears the part writer
        // down under any in-flight write and surfaces here as a
        // source failure. The row is already Paused/Stopped by the
        // IPC command, so labelling its source as failed is noise
        // about a teardown the user asked for. The status guards
        // further down already keep the *transfer* out of Failed;
        // this keeps the label off the row too.
        let (is_user_cancel, peer_id_str, settled_by_user) = {
            let mgr = transfer_manager.read().await;
            let t = mgr.get_transfer(transfer_id);
            (
                ed2k::transfer::is_user_cancel_error(error)
                    || mgr.is_control_cancelled(transfer_id),
                t.map(|t| t.peer_id.clone()).unwrap_or_default(),
                t.is_some_and(|t| matches!(
                    t.status,
                    TransferStatus::Paused
                        | TransferStatus::Stopped
                        | TransferStatus::Insufficient
                        | TransferStatus::Completed
                )),
            )
        };

        if !is_user_cancel && !settled_by_user && blames_source {
            let _ = app_handle.emit("transfer:source-failed", serde_json::json!({
                "transfer_id": transfer_id,
                "source": peer_id_str,
                "stage": &failure_stage,
                "kind": &failure_kind_name,
                "reason": failure_summary,
                "reason_code": failure_code.as_code(),
            }));
        }

        // Dead source marking for individual sources is handled by
        // SourceDetail "failed" events (which carry the actual IP/port).
        // For single-source downloads that set peer_id, apply a
        // belt-and-suspenders mark here as well.
        if blames_source {
            // Sources retired below are also dropped from the
            // registry, which is what makes the count honest — see
            // `retire_dead_source_from_registry`. Collected while the
            // manager lock is held and applied after it is released.
            let mut retire: Option<([u8; 16], Ipv4Addr, u16)> = None;
            let mgr = transfer_manager.read().await;
            if let Some(t) = mgr.get_transfer(transfer_id) {
                if let Some((ip_str, port_str)) = t.peer_id.split_once(':') {
                    if let (Ok(ip), Ok(port)) = (ip_str.parse::<Ipv4Addr>(), port_str.parse::<u16>()) {
                        if *failure_kind == SourceFailureKind::Permanent {
                            // The block time follows the *source's*
                            // reachability, not ours — see
                            // `add_dead_source`.
                            let src_fw = state
                                .per_file_sources
                                .get(transfer_id)
                                .is_some_and(|pfs| pfs.source_is_firewalled(ip, port, None));
                            state.dead_sources.add_dead_source(0, u32::from(ip), port, src_fw);
                            if let Ok(fh_bytes) = hex::decode(&t.file_hash) {
                                if fh_bytes.len() == 16 {
                                    let mut fh = [0u8; 16];
                                    fh.copy_from_slice(&fh_bytes);
                                    state.dead_sources.add_dead_source_for_file(fh, u32::from(ip), port);
                                    retire = Some((fh, ip, port));
                                }
                            }
                            debug!("Marked source {}:{} as dead after permanent failure: {}", ip, port, error);
                        } else {
                            if let Ok(fh_bytes) = hex::decode(&t.file_hash) {
                                if fh_bytes.len() == 16 {
                                    let mut fh = [0u8; 16];
                                    fh.copy_from_slice(&fh_bytes);
                                    state.dead_sources.add_transient_dead_source_for_file(fh, u32::from(ip), port);
                                }
                            }
                        }
                    }
                }
            }
            drop(mgr);
            if let Some((fh, ip, port)) = retire {
                retire_dead_source_from_registry(source_manager, &fh, ip, port).await;
            }
        }

        // eMule-style: downloads never auto-fail. Re-queue for source
        // retry unless the user explicitly cancelled — or the local
        // disk is full (Insufficient), which is transfer-level —
        // or the Ember BLAKE3 pin missed. That last one is also
        // transfer-level: the ed2k parts already matched, so
        // searching more sources cannot change the digest.
        // `is_user_cancel` was resolved above, before the
        // `transfer:source-failed` emit it also gates.
        let is_disk_full = *failure_kind == SourceFailureKind::InsufficientDisk
            || ed2k::transfer::is_disk_full_error(error);
        let is_ember_pin_fail = ed2k::transfer::is_ember_blake3_mismatch(error)
            || failure_code
                == ed2k::transfer::TransferFailureCode::EmberContentHashMismatch;
        let is_aich_pin_fail = ed2k::transfer::is_expected_aich_mismatch(error)
            || failure_code == ed2k::transfer::TransferFailureCode::AichHashMismatch;
        if (is_ember_pin_fail || is_aich_pin_fail) && !is_user_cancel {
            state.pending_downloads.remove(transfer_id);
            // A remote-derived digest that fails the content check is
            // worse than no digest at all: every later start for this
            // hash re-reads it from the map, so the file can never
            // complete however many honest sources turn up, and the
            // ed2k/AICH hashes that *did* match count for nothing.
            // Drop it so a better-corroborated walk — or an explicit
            // click — can pin again. A digest computed from local
            // bytes stays: that one is evidence the downloaded bytes
            // are wrong, not evidence the pin is.
            if is_ember_pin_fail {
                let file_hash = {
                    let mgr = transfer_manager.read().await;
                    mgr.get_transfer(transfer_id)
                        .and_then(|t| hex::decode(&t.file_hash).ok())
                        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
                };
                if let Some(fh) = file_hash {
                    let remote_pin = state
                        .ember_content_hashes
                        .get(&fh)
                        .is_some_and(|pin| {
                            pin.provenance != EmberDigestProvenance::Local
                        });
                    if remote_pin {
                        state.ember_content_hashes.remove(&fh);
                        warn!(
                            "Cleared unverifiable Ember digest pin for {} after a content mismatch",
                            hex::encode(fh)
                        );
                    }
                }
            }
            info!(
                "{} pin failed for {transfer_id} — not re-queuing",
                if is_ember_pin_fail { "Ember BLAKE3" } else { "AICH" }
            );
        } else if failure_code == ed2k::transfer::TransferFailureCode::LocalReadFailed
            && !is_user_cancel
        {
            // The worker already retried and re-read part by part; another
            // attempt would read the same drive. Falls through to Failed so
            // the row says why, and a manual resume starts the count afresh.
            state.pending_downloads.remove(transfer_id);
            forget_requeue_history(transfer_id);
            warn!("Download {transfer_id} cannot be read back from disk — not re-queuing");
        } else if is_disk_full && !is_user_cancel {
            let file_name = {
                let mgr = transfer_manager.read().await;
                mgr.get_transfer(transfer_id)
                    .map(|t| t.file_name.clone())
                    .unwrap_or_default()
            };
            state.pending_downloads.remove(transfer_id);
            let freed_slots = mark_download_insufficient(
                transfer_manager,
                db,
                app_handle,
                transfer_id,
                &file_name,
                transfer_status_writes,
            )
            .await;
            // Start any downloads promoted into the freed concurrent
            // slots before continuing (T2).
            for t in freed_slots {
                crate::commands::transfers::emit_transfer_status(
                    app_handle,
                    &t.id,
                    &t.status,
                );
                let control =
                    reregister_transfer_control(transfer_manager, &t.id).await;
                handle_command(
                    udp_socket,
                    NetworkCommand::StartDownload {
                        file_hash: t.file_hash.clone(),
                        file_name: t.file_name.clone(),
                        file_size: t.total_size,
                        peer_ip: t
                            .peer_id
                            .split(':')
                            .next()
                            .unwrap_or("")
                            .to_string(),
                        peer_port: t
                            .peer_id
                            .split(':')
                            .nth(1)
                            .and_then(|p| p.parse().ok())
                            .unwrap_or(0),
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
                )
                .await;
            }
            // Must not fall through to handle_download_event →
            // fail()/transfer-failed, which would overwrite the
            // resumable Insufficient state as Failed.
            return;
        } else {
        // Re-queue all non-cancel failures (including final-hash
        // mismatch after part reopen) so recovery can continue.
        if !is_user_cancel {
            let transfer_info = {
                let mgr = transfer_manager.read().await;
                mgr.get_transfer(transfer_id).cloned()
            };
            if let Some(t) = transfer_info {
                // Pause/Stop/Insufficient must not be undone by a
                // late Failed requeue (T1/T3).
                //
                // `Completed`/`Failed` belong here for the reason the
                // `Failed` arm of `handle_download_event` documents: a
                // worker that raced completion must not persist a
                // failure for a download whose bytes verified. That
                // guard cannot help us — this block ends in `continue`,
                // so it is never reached. Without these two states a
                // late duplicate `Failed` wrote `failure_reason` and a
                // "Retrying after …" health onto the terminal row
                // (`get_transfer_mut` searches `completed` too),
                // re-registered a control `complete()` had removed,
                // re-inserted a pending entry that can never start, and
                // queued a `"searching"` status write whose sequence is
                // NEWER than the completion write — so the DB row
                // regressed from `completed` and the finished file was
                // re-downloaded on the next launch.
                if matches!(
                    t.status,
                    TransferStatus::Paused
                        | TransferStatus::Stopped
                        | TransferStatus::Insufficient
                        | TransferStatus::Completed
                        | TransferStatus::Failed
                ) {
                    return;
                }
                let control = TransferControl::new();
                let health_update = {
                    let mut mgr = transfer_manager.write().await;
                    // Re-check under write lock — status can flip
                    // between the read above and here.
                    let blocked = mgr.get_transfer(transfer_id).is_some_and(|row| {
                        matches!(
                            row.status,
                            TransferStatus::Paused
                                | TransferStatus::Stopped
                                | TransferStatus::Insufficient
                                | TransferStatus::Completed
                                | TransferStatus::Failed
                        )
                    });
                    if blocked {
                        None
                    } else {
                        if let Some(active_t) = mgr.active.get_mut(transfer_id) {
                            active_t.status = TransferStatus::Searching;
                            active_t.speed = 0;
                        }
                        mgr.set_failure_context(
                            transfer_id,
                            Some(failure_code),
                            Some(failure_kind_name.clone()),
                            Some(failure_stage.clone()),
                        );
                        let update = mgr.set_retrying_after(transfer_id, failure_code);
                        mgr.register_control(transfer_id, control.clone());
                        Some(update)
                    }
                };
                let Some(health_update) = health_update else {
                    return;
                };
                {
                    if let Some(update) = health_update.as_ref() {
                        emit_transfer_health(app_handle, update);
                    }
                }
                let prev_search_count = state.pending_downloads
                    .get(transfer_id)
                    .map(|pd| pd.search_count);
                let search_count = note_requeue(transfer_id, prev_search_count, t.completed_size);
                insert_pending_download_bounded(&mut state.pending_downloads, transfer_id.clone(), PendingDownload {
                    transfer_id: transfer_id.clone(),
                    file_hash: t.file_hash.clone(),
                    file_name: t.file_name.clone(),
                    file_size: t.total_size,
                    expected_aich: t.expected_aich.clone(),
                    control,
                    search_count,
                    last_search_at: requeue_last_search_at(search_count, chrono::Utc::now().timestamp()),
                    priority: priority_str_to_u32(&t.priority),
                });
                info!("Re-queued failed download {} for source retry: {}", transfer_id, error);
                spawn_transfer_status_write(
                    transfer_status_writes,
                    db.clone(),
                    transfer_id.clone(),
                    "searching",
                );

                let _ = app_handle.emit("transfer-status", serde_json::json!({
                    "id": transfer_id,
                    "status": "searching",
                    "failure_reason": failure_summary,
                    "failure_code": failure_code.as_code(),
                    "failure_kind": failure_kind_name,
                    "failure_stage": failure_stage,
                    "health": "degraded",
                    "health_reason": TransferHealthCode::retrying_after(failure_code),
                    "health_code": TransferHealthCode::RetryingAfter.as_code(),
                }));
                return;
            }
        }
        if is_user_cancel {
            // cancel_transfer / CancelDownload already removed the
            // row and recorded history as "cancelled". Falling
            // through would emit transfer-failed and paint the
            // download bar red for a moment before the UI drops it.
            forget_requeue_history(transfer_id);
            return;
        }
        } // end else (!is_disk_full)
    }
    // Inject source-exchange-discovered sources into the active download
    if let DownloadEvent::SourceExchange { ref transfer_id, ref file_hash, ref sources } = event {
        let matching_ids = {
            let mgr = transfer_manager.read().await;
            let hash_hex = hex::encode(file_hash);
            matching_active_transfer_ids_for_hash(state, &mgr, &hash_hex)
        };
        let mut injected = 0usize;
        for sx in sources {
            if state.dead_sources.is_dead_source_for_file(file_hash, u32::from(sx.ip), sx.tcp_port) {
                continue;
            }
            let uh = if sx.user_hash != [0u8; 16] { Some(sx.user_hash) } else { None };
            let co = if sx.crypt_options != 0 { Some(sx.crypt_options) } else { None };
            let ds = ed2k::multi_source::DownloadSource {
                peer_ip: sx.ip.to_string(),
                peer_port: sx.tcp_port,
                available_parts: Vec::new(),
                peer_user_hash: uh,
                peer_connect_options: co,
            };
            let stats = inject_source_into_active_transfers(
                state,
                *file_hash,
                &matching_ids,
                &ds,
                0,
            );
            injected += stats.injected;
        }
        if injected > 0 {
            info!(
                "Source Exchange: injected {} sources into active download {}",
                injected, transfer_id
            );
        }
    }
    // Inject Ember Peer Exchange sources into matching active downloads
    if let DownloadEvent::EmberSources { ref transfer_id, ref entries, ref aich_roots, ref ember_peers, ref relay_attestations, from_ember_hash } = event {
        let we_are_unreachable = state.firewalled || state.low_id;
        handle_epx_sources(state, transfer_manager, source_manager, local_index, entries, aich_roots, ember_peers, relay_attestations, from_ember_hash, &format!("download {transfer_id}"), false, we_are_unreachable).await;
    }

    if let DownloadEvent::EmberPeerDiscovered { ip, tcp_port, udp_port } = event {
        // A live eD2K session is an introduction. Do not apply
        // `block_private_ips` here — that would hide a LAN 1.5.x
        // neighbour from Ember DHT even though TCP already accepted it.
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

    if let DownloadEvent::FriendSeen { ember_hash: friend_eh, ip, port } = event {
        // FriendSeen is only emitted post-PoP for a peer that was a
        // friend at emit time, but a concurrent removal can race the
        // event. Don't resurrect a just-removed friend as "online"
        // or proactively re-dial them.
        if !friend_hashes.read().await.contains(&friend_eh) {
            return;
        }
        // The inbound counterpart to the ask on `EmberFriendConnected`:
        // a friend that dialled us never raises that event, and a
        // starved node should not wait out a 60s tick for the one
        // bootstrap path that does not need their UDP port.
        if settings.ember_native_enabled {
            ask_friends_for_ember_contacts(state).await;
        }
        let hash_hex = hex::encode(friend_eh);
        let now = chrono::Utc::now().timestamp();
        state.online_friends.insert(friend_eh, now);
        state.friend_reconnect_last.remove(&friend_eh);
        let ip_str = match ip { std::net::IpAddr::V4(v4) => v4.to_string(), std::net::IpAddr::V6(v6) => v6.to_string() };
        let db2 = db.clone();
        let h2 = hash_hex.clone();
        let ip2 = ip_str.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = db2.update_friend_address(&h2, &ip2, port) {
                warn!("Failed to persist friend {h2} address {ip2}:{port}: {e}");
            }
        });
        // `FriendSeen` now carries the peer's Hello listen port
        // (not the connection's ephemeral socket port — see the
        // emission sites in multi_source.rs/transfer.rs), so it's
        // safe to reseed download sources from it too.
        if let std::net::IpAddr::V4(v4) = ip {
            reseed_friend_endpoint(
                state,
                source_manager,
                credit_manager,
                transfer_manager,
                friend_eh,
                None,
                v4,
                port,
            )
            .await;
        }
        let _ = app_handle.emit("ember:friend-online", serde_json::json!({
            "user_hash": hash_hex,
            "ip": ip_str,
            "port": port,
        }));
        if !state.ember_sessions.read().await.get(&friend_eh).is_some_and(|h| h.is_fresh())
            && !state.outbound_session_tasks.contains_key(&friend_eh)
        {
            if let std::net::IpAddr::V4(v4) = ip {
                state.outbound_session_tasks.insert(friend_eh, std::time::Instant::now());
                let our_uh = state.user_hash;
                let our_eh = ember_hash;
                let nick = settings.nickname.clone();
                let cid = state.external_ip.map(|eip| u32::from_le_bytes(eip.octets())).unwrap_or(0);
                let tcp = advertised_tcp_port(state);
                let udp = advertised_udp_port(state);
                let obfs = settings.friend_session_encryption;
                let sess = state.ember_sessions.clone();
                let offline = state.user_offline.clone();
                let ultx = ul_event_tx.clone();
                let fh = friend_hashes.clone();
                let friend_addr = SocketAddr::new(v4.into(), port);
                info!("Proactively opening friend session to {} at {}", hex::encode(friend_eh), friend_addr);
                let ultx2 = ul_event_tx.clone();
                // NAT-fallback context — see `spawn_rendezvous_friend_lookup`'s
                // identical capture for why a plain TCP-only dial isn't enough.
                let rv_url = settings.rendezvous_url.clone();
                let nat_ctx = state.friend_nat_context.clone();
                tokio::spawn(async move {
                    if let Err(e) = ed2k::friend_connect::connect_friend_with_fallback(
                        friend_addr, friend_eh, our_uh, our_eh, nick,
                        cid, tcp, udp, obfs, sess, offline, ultx, fh,
                        Some(ed25519_pubkey), Some(ed25519_secret_key),
                        rv_url, nat_ctx,
                    ).await {
                        info!("Proactive friend session to {} failed: {e}", hex::encode(friend_eh));
                        let _ = ultx2.send(upload_server::UploadEvent {
                            transfer_id: String::new(),
                            kind: upload_server::UploadEventKind::EmberFriendSearchFailed { ember_hash: friend_eh },
                        }).await;
                    }
                });
            }
        }
        return;
    }

    if let DownloadEvent::EmberFriendRequest {
        ember_hash,
        pubkey,
        nickname,
        peer_ip,
        peer_port,
        verified,
    } = event
    {
        // File-transfer sockets (the downloader's side of an
        // upload) are how Add Friend on the uploads pane
        // delivers `OP_EMBER_FRIEND_REQ` when the peer is
        // firewalled and FindFriendAndConnect cannot dial
        // back. `verified` is PoP/Noise; unverified *strangers*
        // still queue with the unverified badge. Reciprocal
        // accepts from someone we already added auto-confirm
        // when verified and are ignored when not.
        process_inbound_friend_request(
            db,
            app_handle,
            &mut state.online_friends,
            mutual_friend_hashes,
            ember_hash,
            pubkey,
            &nickname,
            &peer_ip,
            peer_port,
            verified,
        )
        .await;
        return;
    }

    if let DownloadEvent::EmberChatMessage { ember_hash, .. } = event {
        debug!(
            "Dropping unbound chat event from generic download connection for {}",
            hex::encode(ember_hash)
        );
        return;
    }

    if let DownloadEvent::EmberBrowseResponse {
        ember_hash,
        ref entries,
    } = event
    {
        // Browse requests are dispatched only over a canonical
        // friend session. A generic download connection has no
        // session generation, so accepting its response could
        // reintroduce cross-reconnect mis-correlation.
        debug!(
            "Ignoring unbound browse response from download connection for {} ({} entries)",
            hex::encode(ember_hash),
            entries.len()
        );
        return;
    }

    // eMule-style: only mark per-source connections dead for
    // permanent failures (FNF, hash mismatch).  Transient TCP
    // errors are expected in P2P and should not block the source.
    if let DownloadEvent::SourceDetail { ref transfer_id, ref ip, port, ref status, ref queue_rank, ref failure_kind, .. } = event {
        // Update persistent per-file source state
        if let Ok(v4) = ip.parse::<Ipv4Addr>() {
            if let Some(pfs) = state.per_file_sources.get_mut(transfer_id) {
                match status.as_str() {
                    // `v4` at this call site always comes from an active
                    // per-source connection worker (see `DownloadEvent::
                    // SourceDetail`'s emitters), which by construction
                    // requires a real, dialable IP — never the identity-only
                    // `UNSPECIFIED` placeholder rows KAD/server LowID
                    // publishes create — so `None` here can't collide with
                    // an unrelated peer's row (see `PerFileSourceList::
                    // resolve_idx`).
                    "connecting" => pfs.set_connecting(v4, port, None),
                    "queued" => pfs.set_on_queue(v4, port, *queue_rank, None),
                    "queue_full" => pfs.set_on_queue(v4, port, None, None),
                    // Slot granted, waiting on the first block —
                    // eMule is already DS_DOWNLOADING here.
                    "stalled" | "transferring" => pfs.set_downloading(v4, port, None),
                    "completed" => pfs.set_transfer_ended(v4, port, None),
                    "failed" => {
                        if state.banned_ips.contains(&v4) {
                            pfs.set_banned(v4, port, None);
                        } else {
                            let penalty = match failure_kind {
                                Some(SourceFailureKind::Transient) => 1,
                                Some(SourceFailureKind::DownloadTimeout) => 2,
                                Some(SourceFailureKind::Permanent) => 4,
                                // Disk-full is transfer-level, not a peer fault —
                                // don't punish the source.
                                Some(SourceFailureKind::InsufficientDisk) => 0,
                                None => 1,
                            };
                            pfs.set_failed_with_penalty(v4, port, penalty, None);
                        }
                    }
                    "no_needed_parts" => pfs.set_none_needed_parts(v4, port, None),
                    "parts_busy" => pfs.set_parts_busy(v4, port, None),
                    "duplicate" => pfs.clear_duplicate_route(v4, port, None),
                    "too_many_conns" => pfs.set_too_many_conns(v4, port, None),
                    _ => {}
                }
            }
        }

        // Soft defer only — do not push a Failed row into the UI.
        if status == "parts_busy" {
            return;
        }

        if status == "failed" {
            let failure_kind_name = match failure_kind {
                Some(SourceFailureKind::Permanent) => "permanent",
                Some(SourceFailureKind::DownloadTimeout) => "timeout",
                Some(SourceFailureKind::InsufficientDisk) => "insufficient_disk",
                Some(SourceFailureKind::Transient) | None => "transient",
            };
            let _ = app_handle.emit("transfer:source-failed", serde_json::json!({
                "transfer_id": transfer_id,
                "source": format!("{}:{}", ip, port),
                "kind": failure_kind_name,
            }));
            // Before writing this source off, check whether it is
            // the friend this download came from. A friend behind
            // NAT can't be dialed but can dial us, and asking them
            // over their friend session needs no eD2K server, no
            // KAD buddy, and no HighID on either side — so a friend
            // transfer no longer depends on ID status the way the
            // callback paths below do.
            let friend_escalated = if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                maybe_escalate_to_friend_transfer(
                    state,
                    transfer_manager,
                    credit_manager,
                    friend_hashes,
                    pending_kad_callbacks,
                    app_handle,
                    transfer_id,
                    v4,
                    port,
                )
                .await
            } else {
                false
            };
            if let (false, Ok(v4)) = (friend_escalated, ip.parse::<Ipv4Addr>()) {
                let is_permanent = matches!(failure_kind, Some(SourceFailureKind::Permanent));
                if is_permanent {
                    let src_fw = state
                        .per_file_sources
                        .get(transfer_id)
                        .is_some_and(|pfs| pfs.source_is_firewalled(v4, port, None));
                    state.dead_sources.add_dead_source(0, u32::from(v4), port, src_fw);
                    let mut retire: Option<[u8; 16]> = None;
                    let mgr = transfer_manager.read().await;
                    if let Some(t) = mgr.get_transfer(transfer_id) {
                        if let Ok(fh_bytes) = hex::decode(&t.file_hash) {
                            if fh_bytes.len() == 16 {
                                let mut fh = [0u8; 16];
                                fh.copy_from_slice(&fh_bytes);
                                state.dead_sources.add_dead_source_for_file(fh, u32::from(v4), port);
                                retire = Some(fh);
                            }
                        }
                    }
                    drop(mgr);
                    if let Some(fh) = retire {
                        retire_dead_source_from_registry(source_manager, &fh, v4, port)
                            .await;
                    }
                    debug!("Marked source {}:{} as dead (permanent failure)", ip, port);
                } else {
                    let mgr = transfer_manager.read().await;
                    if let Some(t) = mgr.get_transfer(transfer_id) {
                        if let Ok(fh_bytes) = hex::decode(&t.file_hash) {
                            if fh_bytes.len() == 16 {
                                let mut fh = [0u8; 16];
                                fh.copy_from_slice(&fh_bytes);
                                state.dead_sources.add_transient_dead_source_for_file(fh, u32::from(v4), port);
                            }
                        }
                    }
                }
            }
            // Escalated to a friend connect-back: the source is
            // parked, not failed. Stop the event here — same soft
            // defer as `parts_busy` above — so `handle_download_event`
            // can't overwrite the `FriendConnect` row with `Failed`
            // and emit a trailing `"failed"` that makes the drawer
            // drop the row. Skipping the reputation block below is
            // deliberate: we are not treating this as the friend's
            // fault.
            if friend_escalated {
                return;
            }
        }
        // Reputation: record handshake success; only score real
        // download timeouts as Timeout (not our disk-full, permanent
        // "no file", or other non-timeout failures).
        if status == "transferring" {
            if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                let sm = source_manager.read().await;
                let maybe_uh = sm.find_user_hash_by_addr(v4, port);
                drop(sm);
                if let Some(uh) = maybe_uh {
                    let (node_banned, ip_banned) =
                        state.reputation.record_event_with_ip(
                            &uh,
                            v4,
                            ember::reputation::ReputationEvent::SuccessfulHandshake,
                        );
                    if node_banned || ip_banned {
                        apply_reputation_ban_ips(
                            state,
                            shared_banned_ips,
                            std::iter::once(v4),
                            &uh,
                        );
                    }
                }
            }
        } else if status == "failed"
            && matches!(failure_kind, Some(SourceFailureKind::DownloadTimeout))
        {
            if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                let sm = source_manager.read().await;
                let maybe_uh = sm.find_user_hash_by_addr(v4, port);
                drop(sm);
                if let Some(uh) = maybe_uh {
                    let (node_banned, ip_banned) =
                        state.reputation.record_event_with_ip(
                            &uh,
                            v4,
                            ember::reputation::ReputationEvent::Timeout,
                        );
                    if node_banned || ip_banned {
                        apply_reputation_ban_ips(
                            state,
                            shared_banned_ips,
                            std::iter::once(v4),
                            &uh,
                        );
                    }
                }
            }
        }
    }
    if let DownloadEvent::DataReceived { ref file_hash, start, end, sender_ip, .. } = event {
        state.corruption_blackbox.record_data(*file_hash, start, end, sender_ip);
    }
    if let DownloadEvent::PartVerified { ref file_hash, part_start, part_end, ref sender_user_hash, .. } = event {
        state.corruption_blackbox.verified_part(file_hash, part_start, part_end);
        if let Some(ref uh) = sender_user_hash {
            state.reputation.record_event(uh, ember::reputation::ReputationEvent::SuccessfulChunk);
        }
    }
    if let DownloadEvent::PartCorrupted { ref file_hash, part_start, part_end, ref sender_user_hash, .. } = event {
        // Snapshot who contributed still-unverified bytes to this
        // exact part range BEFORE `corrupted_part` marks them
        // corrupt (marking doesn't change which IP owns a block,
        // so ordering isn't strictly required, but doing it first
        // keeps the "who could plausibly be blamed" question
        // independent of the mutation below).
        let contributors = state
            .corruption_blackbox
            .corrupted_part_contributors(file_hash, part_start, part_end);
        let fully_attributed = state
            .corruption_blackbox
            .part_fully_attributed(file_hash, part_start, part_end);
        let ban_list = state.corruption_blackbox.corrupted_part(file_hash, part_start, part_end);
        for ip in ban_list {
            // Sustained corruption is a deterministic, serious
            // signal — persist it so the ban survives a restart and
            // the periodic banned_ips cap reset.
            let reason = format!("corruption blackbox (high corruption ratio for file {})", hex::encode(file_hash));
            apply_persistent_ip_ban(
                &mut state.banned_ips,
                shared_banned_ips,
                db,
                ip,
                &reason,
                AUTO_BAN_TTL_CONTENT_SECS,
            );
        }
        // `sender_user_hash` is whichever peer's connection
        // happened to deliver the bytes that completed this part
        // and triggered verification — in a multi-source
        // download that is NOT necessarily the peer whose bytes
        // were actually bad. Only apply the per-connection
        // reputation strike when that peer was the sole
        // contributor of unverified data in this part; the
        // byte-ratio ban above (which is genuinely per-IP
        // attributed) already covers the ambiguous multi-source
        // case without punishing an innocent connection. With no
        // contributor on record, or bytes in the part nobody here is
        // on record for (a resumed `.part`), the finisher is no more
        // likely to be at fault than anyone else.
        if contributors.len() == 1 && fully_attributed {
            if let Some(ref uh) = sender_user_hash {
                let contributor_ip = contributors.iter().next().copied();
                let (node_banned, ip_banned) = if let Some(ip) = contributor_ip {
                    state.reputation.record_event_with_ip(
                        uh,
                        ip,
                        ember::reputation::ReputationEvent::CorruptData,
                    )
                } else {
                    (
                        state.reputation.record_event(
                            uh,
                            ember::reputation::ReputationEvent::CorruptData,
                        ),
                        false,
                    )
                };
                if node_banned || ip_banned {
                    // Only the address that sent the bytes. Other addresses
                    // filed under this user hash came from source records and
                    // exchanges that anyone can forge; the identity itself is
                    // refused by hash from now on.
                    apply_reputation_ban_ips(state, shared_banned_ips, contributor_ip, uh);
                }
            }
        }
    }
    if let DownloadEvent::ProtocolViolation { sender_ip, ref sender_user_hash } = event {
        // Reputation-scored, not a deterministic abuse ban: a
        // single violation just nudges the score down, and only a
        // repeat offender crosses the ban threshold. We therefore
        // don't DB-persist here — reputation lifetime (and its
        // per-user-hash enforcement) is governed by reputation.json,
        // mirroring the other reputation-driven IP bans.
        if let Some(ref uh) = sender_user_hash {
            let (node_banned, ip_banned) =
                state.reputation.record_event_with_ip(
                    uh,
                    sender_ip,
                    ember::reputation::ReputationEvent::ProtocolViolation,
                );
            if node_banned || ip_banned {
                // The offending address only; see the CorruptData arm.
                apply_reputation_ban_ips(state, shared_banned_ips, [sender_ip], uh);
            }
        } else {
            // No user hash to score against — fall back to a
            // durable IP ban so the offender cannot reconnect
            // for the auto-ban TTL (and so over-cap rebuilds
            // do not silently drop the entry).
            apply_persistent_ip_ban(
                &mut state.banned_ips,
                shared_banned_ips,
                db,
                sender_ip,
                "protocol violation (no user hash)",
                AUTO_BAN_TTL_CONTENT_SECS,
            );
        }
    }
    if let DownloadEvent::AichRecoveryFailed { ref file_hash, part_index, failed_ip, .. } = event {
        if let Ok(mut map) = state.aich_recovery_pending.write() {
            let entry = map.entry((*file_hash, part_index)).or_insert_with(|| (Vec::new(), 0));
            if !entry.0.contains(&failed_ip) {
                entry.0.push(failed_ip);
            }
            entry.1 += 1;
            let retry_count = entry.1;
            let failed_ips = entry.0.clone();
            drop(map);

            if retry_count < 3 {
                let hash_hex = hex::encode(file_hash);
                let candidate = state.per_file_sources.values().find(|pfs| pfs.file_hash == *file_hash).and_then(|pfs| {
                    pfs.sources.iter().find(|s| {
                        !failed_ips.contains(&s.ip)
                            && matches!(
                                s.state,
                                ed2k::sources::DownloadSourceState::OnQueue { .. }
                                    | ed2k::sources::DownloadSourceState::New
                            )
                    })
                });
                if let Some(src) = candidate {
                    debug!(
                        "AICH retry {retry_count}/3 for file {} part {part_index}: next candidate {}:{}",
                        hash_hex, src.ip, src.tcp_port
                    );
                } else {
                    debug!(
                        "AICH retry {retry_count}/3 for file {} part {part_index}: no eligible source yet, will try when one connects",
                        hash_hex
                    );
                }
            } else {
                debug!(
                    "AICH retries exhausted (3/3) for file {} part {part_index}",
                    hex::encode(file_hash)
                );
            }
        }
    }
    if let DownloadEvent::Completed { ref transfer_id, .. } | DownloadEvent::Failed { ref transfer_id, .. } = event {
        let mgr = transfer_manager.read().await;
        if let Some(t) = mgr.get_transfer(transfer_id) {
            if let Ok(fh_bytes) = hex::decode(&t.file_hash) {
                if fh_bytes.len() == 16 {
                    let mut fh = [0u8; 16];
                    fh.copy_from_slice(&fh_bytes);
                    state.corruption_blackbox.remove_file(&fh);
                    if let Ok(mut map) = state.aich_recovery_pending.write() {
                        map.retain(|(file_hash, _), _| *file_hash != fh);
                    }
                }
            }
        }
        drop(mgr);
    }
    let completed_file_hash = if let DownloadEvent::Completed { ref transfer_id, .. } = event {
        let mgr = transfer_manager.read().await;
        mgr.get_transfer(transfer_id).map(|t| t.file_hash.clone())
    } else {
        None
    };
    let mut promoted = Vec::new();
    // Isolate per-event panics so one malformed/unexpected download
    // event can't unwind the whole network loop (→ outer catch →
    // shutdown). Mirrors the handle_command_inner/handle_udp_packet_inner
    // catch_unwind pattern.
    if let Err(p) = std::panic::AssertUnwindSafe(handle_download_event(event, app_handle, transfer_manager, source_manager, db, &mut promoted, stats_manager, settings.remove_finished_downloads, a4af_shared, &settings.download_folder, db_progress_last_persist, DB_PROGRESS_PERSIST_INTERVAL, &mut state.callback_row_pending_since, transfer_status_writes)).catch_unwind().await {
        error!("handle_download_event panicked, dropping event: {}", describe_panic(&*p));
    }

    if let Some(ref file_hash) = completed_file_hash {
        let mut sf = spam_filter.write().await;
        sf.auto_mark_not_spam(file_hash);
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

    // Do not auto-resume user-paused downloads when a transfer
    // completes — Pausing is an explicit user action. Concurrent
    // slot refill for queued (not paused) work is handled elsewhere.
}

#[cfg(test)]
mod friends_only_completion_tests {
    use super::*;

    #[test]
    fn new_copy_of_a_friends_restricted_file_completes_friends_only() {
        assert!(completed_download_friends_only(true, None));
    }

    #[test]
    fn a_friends_restriction_does_not_override_our_public_record() {
        assert!(!completed_download_friends_only(true, Some(false)));
    }

    #[test]
    fn prior_restriction_is_kept_and_public_stays_public() {
        assert!(completed_download_friends_only(false, Some(true)));
        assert!(completed_download_friends_only(true, Some(true)));
        assert!(!completed_download_friends_only(false, Some(false)));
        assert!(!completed_download_friends_only(false, None));
    }
}

#[cfg(test)]
mod requeue_tests {
    use super::*;

    #[test]
    fn failures_without_progress_back_off_across_restarts() {
        let first = next_requeue_search_count(None, None, 500);
        assert_eq!(first, 1);
        let second = next_requeue_search_count(None, Some((first, 500)), 500);
        let third = next_requeue_search_count(None, Some((second, 500)), 500);
        assert_eq!((second, third), (2, 3));
        assert_eq!(requeue_last_search_at(first, 1_000), 0, "first retry is immediate");
        assert_eq!(requeue_last_search_at(third, 1_000), 1_000, "later ones wait");
    }

    #[test]
    fn progress_since_the_last_requeue_restarts_the_count() {
        assert_eq!(next_requeue_search_count(None, Some((7, 500)), 900), 1);
        // Re-opened parts lower the completed size; that is not progress.
        assert_eq!(next_requeue_search_count(None, Some((7, 500)), 200), 8);
    }

    #[test]
    fn a_surviving_pending_count_is_never_lowered() {
        assert_eq!(next_requeue_search_count(Some(12), Some((2, 500)), 500), 13);
        assert_eq!(next_requeue_search_count(Some(4), None, 0), 5);
    }

    #[test]
    fn history_is_per_transfer_and_forgettable() {
        let id = "requeue-tests-history";
        forget_requeue_history(id);
        assert_eq!(note_requeue(id, None, 10), 1);
        assert_eq!(note_requeue(id, None, 10), 2);
        forget_requeue_history(id);
        assert_eq!(note_requeue(id, None, 10), 1);
        forget_requeue_history(id);
    }
}
