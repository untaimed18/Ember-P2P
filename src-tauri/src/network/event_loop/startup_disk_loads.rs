//! Applying the disk loads deferred out of startup once they finish: the IP
//! filter, known.met, and the AICH hash sets and root map, merged with anything
//! the session changed while they were loading.

use super::*;

/// Tell the user the file catalog could not be read this session.
///
/// Until it is, Ember publishes nothing to KAD, eD2K servers or the Ember DHT
/// and uploads only to friends, so that a friends-only file cannot be offered
/// as public. That held every session until the file was repaired by hand,
/// with a log line as the only sign. Latched for the frontend to take, and the
/// event delayed like the config and database notices.
fn notify_catalog_unreadable(app_handle: &tauri::AppHandle) {
    crate::commands::settings::raise_known_met_notice(false);
    let app_handle = app_handle.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let _ = app_handle.emit("known-met-unreadable", ());
    });
}

/// If this session lost the catalog (damaged and set aside, or gone after it
/// had been seen), sharing now fails closed: nothing is offered unless the
/// user shared it themselves, which otherwise looked like a Library emptied
/// for no reason. Asked after the delay: the share-intent store that decides
/// it is initialized in the background and may not have yet.
fn notify_catalog_reset_if_lost(app_handle: &tauri::AppHandle) {
    let app_handle = app_handle.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        if crate::storage::share_intent::fail_closed_this_session() {
            crate::commands::settings::raise_known_met_notice(true);
            let _ = app_handle.emit("known-met-unreadable", ());
        }
    });
}

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn apply_deferred_disk_loads(
    state: &mut NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    settings: &AppSettings,
    app_handle: &tauri::AppHandle,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    known_files: &mut KnownFileList,
    shared_friends_only_hashes: &upload_server::SharedFriendsOnlyHashes,
    shared_server_addr: &Arc<RwLock<Option<SocketAddr>>>,
    deferred_disk_loads: &mut Option<tokio::task::JoinHandle<DeferredDiskLoads>>,
    known_met_ready: &mut bool,
) {
    if let Some(handle) = deferred_disk_loads.as_mut() {
        if handle.is_finished() {
            match deferred_disk_loads.take().unwrap().await {
                Ok(loads) => {
                    // Preserve enable/private flags and any ranges the
                    // user added while the deferred load was in flight.
                    // If ReloadIpFilter (or a manual add that loaded the
                    // file) already replaced the live list, do not write
                    // the stale startup snapshot back over it.
                    if state.ip_filter.has_loaded_ranges() {
                        info!(
                            "Deferred IP filter load skipped: live filter already loaded"
                        );
                    } else {
                        let live_enabled = state.ip_filter.is_enabled();
                        let live_block_private = state.ip_filter.blocks_private();
                        let mut loaded = loads.ip_filter;
                        // Capture before set_enabled(true), which clears ranges_ready.
                        let deferred_load_ready = loaded.ranges_ready();
                        loaded.merge_ranges_from(&state.ip_filter);
                        loaded.set_enabled(live_enabled);
                        loaded.set_block_private(live_block_private);
                        if live_enabled {
                            if deferred_load_ready {
                                loaded.mark_ranges_ready();
                            } else {
                                warn!(
                                    "Deferred IP filter load failed; leaving fail-closed until a successful reload"
                                );
                            }
                        }
                        state.ip_filter = loaded;
                        state
                            .ip_filter
                            .update_shared_snapshot(&state.shared_ip_filter);
                        state.routing_table.evict_filtered_contacts();
                        purge_ember_ip_blocked_peers(state);
                        state.ember_dht.evict_filtered_contacts();
                    }
                    known_files.absorb_missing_from(loads.known_files);
                    sync_shared_friends_only_hashes(shared_friends_only_hashes, known_files);
                    or_index_friends_only_from_known(local_index, known_files).await;
                    *known_met_ready = true;
                    if !known_files.is_authoritative() {
                        notify_catalog_unreadable(app_handle);
                    } else {
                        notify_catalog_reset_if_lost(app_handle);
                    }
                    // Startup scan often finishes (and no-ops AnnounceFiles)
                    // against the placeholder catalog a few hundred ms
                    // before this absorb. KAD auto-connect is off, so
                    // `first_publish_done` is still false here — gating
                    // the backfill on it left the publish manager empty
                    // for the rest of the session. Always register now;
                    // friends-only hashes stay out inside the helpers.
                    let shared_n = publish_kad_completes_from_index(
                        state,
                        local_index,
                        known_files,
                    )
                    .await;
                    let partial_n = publish_kad_partials_from_transfers(
                        state,
                        transfer_manager,
                        local_index,
                        known_files,
                    )
                    .await;
                    if shared_n + partial_n as usize > 0 {
                        info!(
                            "Backfilled {shared_n} public shares + {partial_n} partial downloads into KAD publish after known.met load"
                        );
                        // The library is registered, so the KAD-connect
                        // promotion does not need to sweep it again — that
                        // second pass re-derives every keyword, and on the
                        // UDP promotion path it runs inside packet
                        // handling. Left false when nothing registered
                        // (index still scanning) so that path retries.
                        state.first_publish_done = true;
                    }
                    state.request_offer_files = true;
                    hydrate_ember_publish_schedule(
                        known_files,
                        state.ember_source_address.since,
                        &mut state.ember_source_publish_at,
                        &mut state.ember_source_publish_unix,
                        &mut state.ember_keyword_publish_at,
                        &mut state.ember_keyword_publish_unix,
                        &mut state.ember_published_sources,
                    );
                    if let Some(store) = loads.known2 {
                        *ed2k::aich::known2_store().write() = Some(store);
                    }
                    for (k, v) in loads.aich_root_map {
                        if state.aich_root_map.len() >= MAX_AICH_ROOT_MAP_SOFT_CAP {
                            break;
                        }
                        state.aich_root_map.entry(k).or_insert(v);
                    }
                    if settings.filter_servers_by_ip {
                        apply_server_ip_filter(
                            state,
                            shared_server_addr,
                            app_handle,
                            true,
                        )
                        .await;
                    }
                }
                Err(e) => {
                    warn!("Deferred disk load task panicked: {e}");
                    *known_met_ready = true;
                    // Absorbing the catalog is the *only* thing that makes
                    // it authoritative, and authoritative is what un-gates
                    // every advertise and serve path: `kad_may_advertise_*`
                    // and `mark_friends_only_snapshot_ready`. Leaving it
                    // unset because an unrelated part of that task (the IP
                    // filter, the AICH sets) panicked would silently turn
                    // off KAD and Ember publishing, `OP_OFFERFILES`, and
                    // every upload to a non-friend for the whole session,
                    // with this one log line as the only signal. The
                    // deferred handle is already taken and never retried,
                    // so recover the catalog on its own here.
                    let known_path = state.data_dir.join("known.met");
                    match tokio::task::spawn_blocking(move || {
                        KnownFileList::load_checked(&known_path)
                    })
                    .await
                    {
                        Ok(Ok(loaded)) => {
                            known_files.absorb_missing_from(loaded);
                            if !known_files.is_authoritative() {
                                notify_catalog_unreadable(app_handle);
                            }
                            sync_shared_friends_only_hashes(
                                shared_friends_only_hashes,
                                known_files,
                            );
                            or_index_friends_only_from_known(local_index, known_files).await;
                            let shared_n = publish_kad_completes_from_index(
                                state,
                                local_index,
                                known_files,
                            )
                            .await;
                            let partial_n = publish_kad_partials_from_transfers(
                                state,
                                transfer_manager,
                                local_index,
                                known_files,
                            )
                            .await;
                            if shared_n + partial_n as usize > 0 {
                                state.first_publish_done = true;
                            }
                            state.request_offer_files = true;
                            info!(
                                "Recovered known.met after the deferred load panicked: \
                                 {shared_n} public shares + {partial_n} partial downloads \
                                 registered; sharing stays enabled"
                            );
                        }
                        Ok(Err(load_err)) => {
                            error!(
                                "known.met could not be read after the deferred load panicked \
                                 ({load_err}); sharing and publishing stay disabled for this \
                                 session to avoid advertising a friends-only file"
                            );
                            notify_catalog_unreadable(app_handle);
                        }
                        Err(join_err) => {
                            error!(
                                "known.met recovery task panicked as well ({join_err}); \
                                 sharing and publishing stay disabled for this session"
                            );
                            notify_catalog_unreadable(app_handle);
                        }
                    }
                    // A failed deferred read must not turn an enabled
                    // filter into an intentional empty one. Keep the
                    // peer paths fail-closed until a successful reload.
                    if state.ip_filter.is_enabled() {
                        state.ip_filter.mark_ranges_not_ready();
                        state
                            .ip_filter
                            .update_shared_snapshot(&state.shared_ip_filter);
                    }
                }
            }
        }
    }
}
