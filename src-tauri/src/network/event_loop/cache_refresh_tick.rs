//! Refreshing the shared peer and stats caches the frontend reads, without
//! blocking the loop.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_cache_refresh_tick(
    state: &mut NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    settings: &AppSettings,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    known_files: &KnownFileList,
    cache_write_handle: &mut Option<tokio::task::JoinHandle<()>>,
    last_cache_refresh_started_at: &mut i64,
    last_file_snapshot_inputs: &mut Option<(u64, u64)>,
    shared_connected_server: &Arc<RwLock<Option<ServerInfo>>>,
    shared_contacts: &Arc<RwLock<Vec<KadContactInfo>>>,
    shared_files: &Arc<RwLock<Vec<FileInfo>>>,
    shared_peers: &Arc<RwLock<Vec<PeerInfo>>>,
    shared_searches: &Arc<RwLock<Vec<KadSearchInfo>>>,
    shared_servers: &Arc<RwLock<Vec<ServerInfo>>>,
    shared_stats: &Arc<RwLock<NetworkStats>>,
) {
    // Skip if previous write task hasn't finished yet — avoids
    // accumulating queued writers on the RwLocks which would starve
    // Tauri IPC read handlers and freeze the UI.
    if cache_write_handle.as_ref().is_some_and(|h| !h.is_finished()) {
        return;
    }

    // Collect raw contact data quickly (no hex/distance computation).
    // The expensive conversions happen in the spawned background task.
    let local_id = state.local_id;
    let raw_contacts: Vec<_> = state.routing_table.all_contacts()
        .take(500)
        .map(|c| {
            let nick = state.peer_nicknames.get(&c.id).cloned().unwrap_or_default();
            (c.clone(), nick)
        })
        .collect();

    state.stats.connected_peers = state.routing_table.len() as u32;
    state.stats.kad_users_estimate = state.routing_table.estimate_count();
    state.stats.upload_speed = bandwidth_limiter.smoothed_upload_speed();
    state.stats.download_speed = bandwidth_limiter.smoothed_download_speed();
    state.stats.total_uploaded = bandwidth_limiter.total_uploaded();
    state.stats.total_downloaded = bandwidth_limiter.total_downloaded();
    state.stats.upnp_mapped = state.upnp_mapped;
    state.stats.buddy_status = match state.buddy_manager.state() {
        BuddyState::NoBuddy => {
            if let Some(bid) = state.buddy_manager.serving_for() {
                format!("serving:{}", bid)
            } else {
                "none".to_string()
            }
        }
        BuddyState::FindingBuddy => "searching".to_string(),
        BuddyState::Connected => {
            if let Some(bid) = state.buddy_manager.buddy_id() {
                format!("connected:{}", bid)
            } else {
                "connected".to_string()
            }
        }
    };
    state.stats.external_ip = state
        .external_ip
        .map(|ip| ip.to_string())
        .unwrap_or_default();
    // Do not swap `tcp_connect_back_shared` here — the firewall-sync
    // arm is the sole consumer. Dual swap was discarding probe proof
    // under LowID before that arm could record it.
    let fw_shared = state.firewalled_shared.load(std::sync::atomic::Ordering::Relaxed);
    if state.low_id {
        if !fw_shared {
            state.firewalled_shared.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        if !state.firewalled {
            // Sticky LowID keeps the aggregate badge; do not wipe
            // tcp_status Open via note_tcp_firewalled.
            state.firewalled = true;
        }
    } else if state.firewalled && !fw_shared {
        // UPnP optimism only — do not mark tcp_status Open.
        state.firewalled = false;
    }
    state.stats.firewalled = state.firewalled;
    // Keep polled NetworkStats in lockstep with the checker.
    // Connect-backs used to flip the checker to Open while leaving
    // stats.tcp_status as "Unknown", so the UI poll briefly
    // clobbered a correct firewall-status event back to Unknown.
    state.stats.tcp_status =
        format!("{:?}", state.firewall_checker.tcp_status());
    state.stats.udp_status =
        format!("{:?}", state.firewall_checker.udp_status());
    update_publish_manager_state(state);

    // Was a second, hand-copied transcription of
    // `kad_searches_snapshot` kept in sync by comment alone, and it
    // had already drifted: the copy never grew the routing-walk
    // branch of the `responses` count, so whichever of the poll and
    // the cache answered first decided what FindNode/FindBuddy rows
    // reported. Call the one implementation instead.
    let cached_s: Vec<KadSearchInfo> = kad_searches_snapshot(state);

    state.stats.ed2k_low_id = state.server_connected.then_some(state.low_id);
    let stats_snapshot = state.stats.clone();

    // Both of these were hand-copied transcriptions too, and the
    // connected-server one had drifted in the same way the Kad
    // copy above had: it zeroed `description`, `max_users`,
    // `soft_files`, `hard_files` and `is_static`, so the row for
    // the server the user was actually on lost the very fields
    // `connected_server_info` exists to borrow from the list
    // entry — depending on whether the poll or this cache
    // answered first. Call the one implementation instead.
    let cached_srv: Vec<ServerInfo> =
        state.server_list.servers().iter().map(server_entry_to_info).collect();

    let cached_conn_srv: Option<ServerInfo> = connected_server_info(state);

    let kad_connected = state.stats.status == NetworkStatus::Connected;
    let srv_connected = state.server_connected;
    let ember_live =
        settings.ember_native_enabled && state.ember_dht.routing().verified_len() > 0;
    let kad_published = state.publish_manager.source_published_md4_hashes();
    let ed2k_offered = state.offered_ed2k_hashes.clone();
    let ember_published = state.ember_published_sources.clone();

    // The peer/contact/stats half of this bundle genuinely changes
    // every tick, but the file snapshot underneath it depends on
    // exactly two things: the all-time counters in known.met and the
    // publish-badge inputs. Index *content* edits are pushed by
    // `refresh_file_cache` at each of its mutation sites, so this
    // timer never had to re-derive them. Rebuilding regardless meant
    // an idle node took `local_index.write()` every 5s and deep-cloned
    // every `FileInfo` behind it — on a large library that starves
    // hashing, scans and IPC readers for as long as it runs.
    let known_generation = known_files.dirty_generation();
    let badge_fingerprint = publish_badge_fingerprint(
        kad_connected,
        srv_connected,
        ember_live,
        &kad_published,
        &ed2k_offered,
        &ember_published,
    );
    let file_snapshot_stale =
        *last_file_snapshot_inputs != Some((known_generation, badge_fingerprint));

    // Collect known-file stats for the background task (can't move
    // known_files into spawn). Skipped entirely when the snapshot is
    // current: at a full library this is ~140k tuples per tick.
    let known_stats: Vec<([u8; 16], u32, u32, u64)> = if file_snapshot_stale {
        known_files
            .all_records()
            .map(|r| (r.file_hash, r.all_time_requested, r.all_time_accepted, r.all_time_transferred))
            .collect()
    } else {
        Vec::new()
    };

    // Spawn ALL heavy work (hex conversion, distance computation, writes,
    // and the local_index stats merge) as a background task so the event
    // loop isn't blocked by any RwLock contention.
    let sp = shared_peers.clone();
    let ss = shared_stats.clone();
    let sc = shared_contacts.clone();
    let ssrch = shared_searches.clone();
    let s_srv = shared_servers.clone();
    let s_conn = shared_connected_server.clone();
    let s_files = shared_files.clone();
    let db_ref = db.clone();
    let li_ref = local_index.clone();
    let app_for_cache = app_handle.clone();
    *last_cache_refresh_started_at = chrono::Utc::now().timestamp();
    // Marked applied here rather than inside the task: the watchdog
    // never aborts this one, and a task that panics only costs a
    // delayed merge, which the next known.met change re-triggers.
    *last_file_snapshot_inputs = Some((known_generation, badge_fingerprint));
    *cache_write_handle = Some(tokio::spawn(async move {
        // Merge all-time stats from known.met into local_index, then
        // snapshot the file list for frontend IPC reads.
        // IMPORTANT: release the local_index lock before acquiring
        // cached_shared_files -- never nest these two locks.
        let file_snap = if file_snapshot_stale {
            let mut index = li_ref.write().await;
            index.update_alltime_stats_bulk(&known_stats);
            let mut snap = index.all_files().to_vec();
            apply_publish_badges(
                &mut snap,
                kad_connected,
                srv_connected,
                ember_live,
                &kad_published,
                &ed2k_offered,
                &ember_published,
            );
            Some(snap)
        } else {
            None
        };
        // Do the expensive hex/distance conversions here, off the event loop
        let mut peers: Vec<PeerInfo> = Vec::new();
        let mut cached_c: Vec<KadContactInfo> = Vec::new();
        for (c, nick) in &raw_contacts {
            let hex_id = c.id.to_hex();
            if peers.len() < 200 {
                peers.push(PeerInfo {
                    id: hex_id.clone(),
                    addresses: vec![format!("{}:{}", c.ip, c.udp_port)],
                    nickname: nick.clone(),
                    last_seen: c.last_seen,
                    files_shared: 0,
                    banned: false,
                });
            }
            let distance = c.id.xor_distance(&local_id);
            cached_c.push(KadContactInfo {
                id: hex_id,
                contact_type: c.contact_type,
                version: c.version,
                distance: distance.to_hex(),
                ip_verified: c.verified,
                bootstrap: c.contact_type == CONTACT_TYPE_NEW && c.version == 0,
            });
        }

        let saved_peers = tokio::task::spawn_blocking(move || {
            db_ref.get_peers().unwrap_or_default()
        }).await.unwrap_or_default();
        for saved in saved_peers {
            if let Some(existing) = peers.iter_mut().find(|peer| peer.id == saved.id) {
                if !saved.nickname.is_empty() {
                    existing.nickname = saved.nickname;
                }
                if !saved.addresses.is_empty() {
                    existing.addresses = saved.addresses;
                }
                existing.last_seen = existing.last_seen.max(saved.last_seen);
                existing.files_shared = existing.files_shared.max(saved.files_shared);
                existing.banned = saved.banned;
            } else if saved.banned {
                peers.push(saved);
            }
        }
        *sp.write().await = peers;
        *ss.write().await = stats_snapshot;
        *sc.write().await = cached_c;
        *ssrch.write().await = cached_s;
        *s_srv.write().await = cached_srv;
        *s_conn.write().await = cached_conn_srv;
        // Apply the file snapshot last, after every expensive/fallible
        // preparation step. The watchdog never aborts this task, so
        // a refresh cannot leave only the leading subset of this
        // cache bundle updated.
        //
        // This is also the only place the KAD / eD2K / Ember publish
        // badges are computed, and a file that has just finished
        // publishing gives the Library no other reason to re-read the
        // list — it reloads on `shared-files-changed` alone. Emit when
        // a badge actually flips, so the flags land in the UI without
        // waiting on unrelated activity and without reloading the
        // whole list on a five-second clock.
        let badges_changed = match file_snap {
            Some(file_snap) => {
                let mut cache = s_files.write().await;
                let changed = badge_counts(&file_snap) != badge_counts(&cache);
                *cache = file_snap;
                changed
            }
            // Neither the known.met counters nor any badge input
            // moved, so the cache already holds this exact list and
            // no badge can have flipped.
            None => false,
        };
        if badges_changed {
            let _ = app_for_cache.emit(
                "shared-files-changed",
                serde_json::json!({
                    "phase": "publish-badges",
                    "count": 0,
                }),
            );
        }
    }));
}
