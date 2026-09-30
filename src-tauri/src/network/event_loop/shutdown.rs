//! The shutdown sequence once the event loop has ended: finishing transfer
//! verifications, stopping downloads, and saving every piece of persistent
//! state within the shutdown deadline.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn save_on_shutdown(
    udp_socket: &Arc<UdpSocket>,
    state: &mut NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    settings: &AppSettings,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    credit_manager: &Arc<RwLock<CreditManager>>,
    stats_manager: &StatsManager,
    known_files: &mut KnownFileList,
    ember_hash: [u8; 16],
    ed25519_secret_key: [u8; 32],
    aich_set_rx: &mut mpsc::Receiver<ed2k::aich::AICHRecoveryHashSet>,
    cache_write_handle: &mut Option<tokio::task::JoinHandle<()>>,
    credit_flush_handle: &mut Option<tokio::task::JoinHandle<()>>,
    credit_save_ownership: &Arc<tokio::sync::Mutex<()>>,
    known2_save_in_flight: &mut bool,
    known_met_save_in_flight: bool,
    known_met_save_result_rx: &mut mpsc::UnboundedReceiver<KnownMetSaveResult>,
    periodic_save_result_rx: &mut mpsc::UnboundedReceiver<PeriodicSaveResult>,
    reputation_save_in_flight: &mut bool,
    shutdown_deadline: tokio::time::Instant,
    stats_save_in_flight: &mut bool,
    upnp_enabled: bool,
    upnp_mappings: &mut upnp::UpnpMappings,
    xfer_finish_rx: &mut mpsc::UnboundedReceiver<XferFinishResult>,
    upload_queue: &ed2k::upload::UploadQueueRef,
) {
    // Apply any transfer verification the blocking pool is still working on,
    // before anything below tears down the paths its completion frame needs.
    // `finish_xfer_recv` renames the file into place on that pool, so the
    // download itself survives a quit either way — what is lost by exiting
    // early is the `XFER_DONE` frame, and the sender has no other way to learn
    // the transfer succeeded: it answers block requests and then waits, so its
    // own stall timer reports a file we actually received as failed.
    //
    // Runs before the QUIC endpoint closes because `send_xfer_frame` falls
    // back to the relay for a peer we have no direct path to. Bounded, and
    // deliberately tighter than the save phases below: this is a courtesy to
    // the sender, and a 100 MB hash on a spinning disk is not worth delaying
    // the writes that protect our own state.
    let xfer_drain_deadline =
        shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(3));
    while state.xfer_finish_in_flight > 0 {
        match tokio::time::timeout_at(xfer_drain_deadline, xfer_finish_rx.recv()).await {
            Ok(Some(finished)) => {
                apply_xfer_finish(udp_socket, state, db, app_handle, finished).await;
            }
            // Only `state` holds a sender, so this cannot happen while the
            // loop owns it — treat it as "nothing more is coming" regardless.
            Ok(None) => break,
            Err(_) => {
                warn!(
                    "{} Ember transfer verification(s) still hashing 3s into shutdown; \
                     the file is already saved but the sender will time it out",
                    state.xfer_finish_in_flight
                );
                break;
            }
        }
    }

    // Abort pending server connection if any
    if let Some(handle) = state.pending_server_connect.take() {
        handle.abort();
    }
    if let Some(handle) = state.pending_outgoing_buddy.take() {
        handle.abort();
    }

    // Close the QUIC endpoint so `run_quic_accept_loop` sees `accept() == None`
    // and exits, instead of lingering as a detached task (and refusing inbound
    // relay handshakes) until the process dies. This also tears down in-flight
    // relay connections gracefully.
    if let Some(endpoint) = state
        .connection_broker
        .as_ref()
        .and_then(|broker| broker.quic_endpoint())
    {
        endpoint.close(0u32.into(), b"shutting down");
    }

    if let Some(handle) = cache_write_handle.take() {
        match tokio::time::timeout_at(
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(2)),
            handle,
        )
        .await
        {
            Ok(Ok(())) => debug!("Cache refresh task finished before shutdown"),
            Ok(Err(_)) => debug!("Cache refresh task cancelled during shutdown"),
            Err(_) => warn!("Cache refresh task did not finish before shutdown"),
        }
    }

    {
        let mgr = transfer_manager.read().await;
        for tid in state.download_handles.keys() {
            if let Some(control) = mgr.get_control(tid) {
                control.cancel();
            }
        }
    }
    tokio::time::sleep_until(shutdown_phase_deadline(
        shutdown_deadline,
        std::time::Duration::from_millis(300),
    ))
    .await;

    // Cancel and await all active download tasks. Abort every task first, then
    // await them *concurrently* under one global deadline. Awaiting each task's
    // 5s timeout sequentially made total shutdown time scale with the number of
    // active downloads, which could overrun the bounded window the UI thread
    // waits on (SHUTDOWN_WAIT in lib.rs) and let the process exit mid-save.
    let download_handles: Vec<_> = state.download_handles.drain().collect();
    for (_, handle) in &download_handles {
        handle.abort();
    }
    if !download_handles.is_empty() {
        let await_all = futures::future::join_all(download_handles.into_iter().map(
            |(tid, handle)| async move {
                match handle.await {
                    Ok(()) => debug!("Download task {tid} shut down cleanly"),
                    Err(_) => debug!("Download task {tid} cancelled/aborted"),
                }
            },
        ));
        if tokio::time::timeout_at(
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(5)),
            await_all,
        )
        .await
        .is_err()
        {
            warn!("Some download tasks did not finish within the shutdown abort window");
        }
    }

    // Persist .part.met for any downloads that were in progress when aborted.
    //
    // Snapshot the registry's Arc handles, then release the registry lock
    // BEFORE awaiting each tracker's read lock. The previous non-blocking
    // `try_read()` silently skipped (and lost the resume metadata for) any
    // tracker whose worker hadn't fully released its write lock yet — the
    // download tasks are aborted just above, but an abort that landed mid
    // write-guard could still be releasing it. A short bounded `read().await`
    // waits for that hand-off instead of dropping the save, while the timeout
    // still guarantees shutdown can't hang on a genuinely stuck tracker.
    let trackers: Vec<_> = state
        .tracker_registry
        .lock()
        .iter()
        .map(|(tid, t)| (tid.clone(), t.clone()))
        .collect();
    if !trackers.is_empty() {
        let count = trackers.len();
        // Save every .part.met *concurrently* under one global deadline. Done
        // sequentially, each tracker's internal 2s+5s timeouts summed across
        // many active downloads could exceed the UI's shutdown wait and cut a
        // save off mid-write, losing resume metadata. `save_part_tracker_snapshot`
        // is self-bounded; the outer timeout is a backstop against a stall.
        let saves =
            futures::future::join_all(trackers.into_iter().map(|(tid, tracker)| async move {
                save_part_tracker_snapshot(tracker, &tid, "shutdown").await;
            }));
        if tokio::time::timeout_at(
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(8)),
            saves,
        )
        .await
        .is_err()
        {
            warn!("Timed out saving some .part.met file(s) within the shutdown window");
        }
        info!("Saved {count} download tracker(s) on shutdown");
    }
    state.active_source_senders.clear();
    // Lockstep — every download is dead at shutdown, both sender
    // maps must be cleared together (see field doc).
    state.active_established_senders.clear();
    state.active_source_overflow.clear();
    state.active_kad_search_state.clear();

    // Save all state on shutdown
    info!("Shutting down network");
    // Final Path B tally so even a short test run (under the 60 s periodic
    // cadence) always captures the queued-source-model counters.
    if let Some((in_use, max, acquires, contended)) = ed2k::multi_source::global_conn_stats() {
        let (detaches, diversions, rotations) = ed2k::multi_source::pathb_event_counts();
        info!(
            "Path B final stats: dl-conns {in_use}/{max} in use at shutdown, {acquires} acquires \
             ({contended} contended), {detaches} detaches, {diversions} push-grant diversions, \
             {rotations} slow-source rotations",
        );
    }
    // The upload waiting queue, so the peers queued here keep their place
    // across a restart (`ed2k::upload_queue_store`). Bounded like every phase
    // here: the listener may still hold the lock, and a queue that cannot be
    // saved in time costs the waiters their place, not the user their data.
    let queue_phase_deadline =
        shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(2));
    match tokio::time::timeout_at(queue_phase_deadline, upload_queue.lock()).await {
        Ok(queue) => {
            let mut entries = queue.clone();
            drop(queue);
            // Last session's waiters, if this one ended before they could
            // rejoin. Live rows come first, so they win a duplicate.
            if let Some(pending) = state.restored_upload_queue.take() {
                entries.extend(pending.into_entries());
            }
            let dir = state.data_dir.clone();
            let writer = tokio::task::spawn_blocking(move || {
                ed2k::upload_queue_store::save(&dir, &entries)
            });
            match tokio::time::timeout_at(queue_phase_deadline, writer).await {
                Ok(Ok(Ok(count))) => info!("Saved {count} upload queue waiter(s) on shutdown"),
                Ok(Ok(Err(e))) => error!("Failed to save the upload queue on shutdown: {e}"),
                Ok(Err(e)) => error!("Upload queue shutdown writer failed: {e}"),
                Err(_) => warn!("Upload queue save did not finish within its shutdown phase"),
            }
        }
        Err(_) => warn!("Skipping the upload queue save: the queue stayed locked into shutdown"),
    }

    let contacts = state.routing_table.export_bootstrap_contacts(200);
    let nodes_path = state.data_dir.join("nodes.dat");
    match tokio::time::timeout_at(
        shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(5)),
        state.nodes_save_lock.lock(),
    )
    .await
    {
        Ok(_ownership) => {
            if let Err(e) = bootstrap::save_nodes_dat(&nodes_path, &contacts) {
                error!("Failed to save nodes.dat: {e}");
            }
        }
        Err(_) => {
            warn!("Final nodes.dat save skipped: serialized periodic writer still owns the file")
        }
    }

    // Persist the remembered peer set (slice 7) so the next session can rejoin
    // the DHT immediately.
    //
    // The only place an address is ever forgotten, and only ever for want of
    // room. A session long enough to have pinged the peers it offered the table
    // sinks each silent one in the ranking; the trim then keeps the best
    // `EMBER_PERSIST_MAX_CONTACTS` of them, proven addresses ahead of gossip. A peer that is merely offline
    // tonight is still here tomorrow — which matters most on a small overlay,
    // where the addresses of a handful of peers who happen to be asleep are the
    // only way back in. Charging misses per save instead would turn a session
    // into five minutes and put the old ratchet back.
    let live = ember_persistable_contacts(state);
    state.ember_bootstrap_cache.observe(live.iter());
    let now_secs = chrono::Utc::now().timestamp();
    let sunk = state.ember_bootstrap_cache.charge_silent_session(now_secs);
    let local_id = state.ember_dht.local_id();
    let dropped = state
        .ember_bootstrap_cache
        .trim_to(&local_id, EMBER_PERSIST_MAX_CONTACTS);
    let ember_contacts = state
        .ember_bootstrap_cache
        .snapshot(&local_id, EMBER_PERSIST_MAX_CONTACTS);
    info!(
        "Ember bootstrap cache: remembering {} peer(s) ({sunk} silent this session, \
         {dropped} dropped for room)",
        ember_contacts.len(),
    );
    if !ember_contacts.is_empty() {
        let ember_nodes_path = state.data_dir.join("nodes_ember.dat");
        // Wait out a periodic save that is still in flight, bounded by the shared
        // shutdown budget, and skip the write if it will not let go — exactly as
        // the nodes.dat path above does. Writing anyway would race that task on
        // the same file: whichever rename landed last would win, so the older
        // periodic snapshot could bury this newer one.
        //
        // The write itself goes to the blocking pool under the same deadline:
        // `save_nodes` fsyncs the file and its directory, and inline on the
        // runtime nothing would bound that stall.
        let phase_deadline =
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(2));
        match tokio::time::timeout_at(
            phase_deadline,
            state.ember_nodes_save_lock.clone().lock_owned(),
        )
        .await
        {
            Ok(ownership) => {
                let nodes_file_state = state.ember_nodes_file;
                let writer = tokio::task::spawn_blocking(move || {
                    let _ownership = ownership;
                    ember::dht::bootstrap::save_nodes(
                        &ember_nodes_path,
                        &ember_contacts,
                        nodes_file_state,
                    )
                });
                match tokio::time::timeout_at(phase_deadline, writer).await {
                    Ok(Ok(Ok(()))) => {}
                    Ok(Ok(Err(e))) => error!("Failed to save nodes_ember.dat on shutdown: {e}"),
                    Ok(Err(e)) => error!("nodes_ember.dat shutdown writer failed: {e}"),
                    Err(_) => warn!(
                        "Stopped waiting for the nodes_ember.dat shutdown writer at its phase \
                         deadline; the save may not complete"
                    ),
                }
            }
            Err(_) => {
                warn!(
                    "Skipping the nodes_ember.dat shutdown save: a periodic save still holds the \
                     lock, and its snapshot is the one on disk"
                );
            }
        }
    }

    if state.ember_verified_highwater_dirty
        || state.ember_verified_highwater.alltime > 0
        || state.ember_verified_highwater.daily > 0
    {
        // Behind a maintenance-tick write still in flight, so this newer
        // snapshot is the one that lands; off the runtime and bounded, like
        // the saves around it.
        let phase_deadline =
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(2));
        match tokio::time::timeout_at(
            phase_deadline,
            state.ember_highwater_save_lock.clone().lock_owned(),
        )
        .await
        {
            Ok(ownership) => {
                let path = ember_highwater_path(&state.data_dir);
                let hw = state.ember_verified_highwater.clone();
                let writer = tokio::task::spawn_blocking(move || {
                    let _ownership = ownership;
                    save_ember_verified_highwater(&path, &hw);
                });
                if tokio::time::timeout_at(phase_deadline, writer).await.is_err() {
                    warn!(
                        "Stopped waiting for the Ember high-water shutdown writer at its phase \
                         deadline; the save may not complete"
                    );
                }
            }
            Err(_) => warn!(
                "Skipping the Ember high-water shutdown save: a periodic save still holds the lock"
            ),
        }
    }
    if state.ember_source_address_dirty {
        let phase_deadline =
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(2));
        match tokio::time::timeout_at(
            phase_deadline,
            state.ember_source_address_save_lock.clone().lock_owned(),
        )
        .await
        {
            Ok(ownership) => {
                let path = ember_source_address_path(&state.data_dir);
                let address = state.ember_source_address;
                let writer = tokio::task::spawn_blocking(move || {
                    let _ownership = ownership;
                    save_ember_source_address(&path, &address);
                });
                if tokio::time::timeout_at(phase_deadline, writer).await.is_err() {
                    warn!(
                        "Stopped waiting for the Ember source-address shutdown writer at its \
                         phase deadline; the save may not complete"
                    );
                }
            }
            Err(_) => warn!(
                "Skipping the Ember source-address shutdown save: a periodic save still holds \
                 the lock"
            ),
        }
    }

    // Drain any in-flight periodic statistics save before the final write.
    // The 60s timer spawns a detached `spawn_blocking` with a snapshot of
    // `cumulative_save_pairs()` — the same stale-overwrite race we already
    // document for known.met. If that task lands after this final save, it
    // silently rolls back session bytes (and completed counts) accrued
    // after the snapshot was taken.
    if *stats_save_in_flight {
        let deadline =
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(5));
        while *stats_save_in_flight {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                warn!(
                    "Periodic statistics save still in flight 5s into shutdown; \
                     proceeding with the final save anyway"
                );
                break;
            }
            match tokio::time::timeout(remaining, periodic_save_result_rx.recv()).await {
                Ok(Some(result)) => match result.job {
                    PeriodicSaveJob::Stats => {
                        *stats_save_in_flight = false;
                        if let Err(e) = result.result {
                            error!("Periodic statistics save (drained at shutdown) failed: {e}");
                        }
                    }
                    // Sibling periodic jobs may finish while we wait for Stats;
                    // update their flags too so the authoritative shutdown
                    // writers below know those stale snapshots are joined.
                    other => {
                        match other {
                            PeriodicSaveJob::Reputation => *reputation_save_in_flight = false,
                            // Known2 belongs here too: consuming its completion
                            // while leaving the flag set left the join below
                            // waiting on a message already taken, which burns its
                            // wait and can push the later sources.met/server.met
                            // saves past the global deadline.
                            PeriodicSaveJob::Known2 => *known2_save_in_flight = false,
                            PeriodicSaveJob::Nodes => {}
                            PeriodicSaveJob::Stats => unreachable!(),
                        }
                        if let Err(e) = result.result {
                            let name = match other {
                                PeriodicSaveJob::Reputation => "reputation.json",
                                PeriodicSaveJob::Known2 => "known2_64.met",
                                PeriodicSaveJob::Nodes => "nodes.dat",
                                PeriodicSaveJob::Stats => unreachable!(),
                            };
                            error!("Periodic {name} save (drained at shutdown) failed: {e}");
                        }
                    }
                },
                Ok(None) => break,
                Err(_) => {
                    warn!(
                        "Periodic statistics save still in flight 5s into shutdown; \
                         proceeding with the final save anyway"
                    );
                    break;
                }
            }
        }
    }

    stats_manager.save_cumulative(db);
    info!("Statistics saved on shutdown");

    // Drain any in-flight periodic known.met background save before doing
    // this shutdown's own authoritative save below. `known_met_save_timer`
    // (every 120s) spawns each save via a detached `tokio::spawn` holding
    // its own up-to-120s-old clone of `known_files` — breaking out of the
    // event loop on `Shutdown` does not wait for it. Left alone, that
    // background task's `atomic_write`/rename can land *after* the
    // checkpoint+save below and silently revert it to the stale snapshot,
    // reintroducing the exact "AICH rehash restarts from scratch" bug this
    // checkpoint exists to fix — intermittently, only when a save happened
    // to be in flight at quit time. Bounded so a genuinely stuck save can't
    // hang shutdown.
    if known_met_save_in_flight {
        match tokio::time::timeout_at(
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(5)),
            known_met_save_result_rx.recv(),
        )
        .await
        {
            Ok(Some(result)) => match result.result {
                Ok(true) => known_files.mark_saved_if_generation(result.generation),
                Ok(false) => known_files.mark_save_failed(),
                Err(e) => {
                    known_files.mark_save_failed();
                    error!("Periodic known.met save (drained at shutdown) failed: {e}");
                }
            },
            Ok(None) => {}
            Err(_) => {
                warn!(
                    "Periodic known.met save still in flight 5s into shutdown; \
                     proceeding with the final save anyway"
                );
            }
        }
    }

    // Final digest checkpoint before the shutdown save: fold any freshly
    // recomputed AICH roots and Ember BLAKE3 digests from the live index into
    // known.met so a hash pass interrupted by this shutdown (either one-time
    // migration re-hash) resumes next launch instead of restarting. This
    // mirrors the digest arms of the SharedFilesChanged reconcile, minus the
    // publish-set rebuild that's pointless during shutdown, and preserves
    // every other field.
    {
        let idx = local_index.read().await;
        let mut any_updated = false;
        for f in idx.all_files() {
            if f.hash.is_empty() || (f.aich_hash.is_empty() && f.ember_file_hash.is_empty()) {
                continue;
            }
            if let Ok(hb) = hex::decode(&f.hash) {
                if hb.len() == 16 {
                    let mut fh = [0u8; 16];
                    fh.copy_from_slice(&hb);
                    if let Some(record) = known_files.find_by_hash_mut(&fh) {
                        if !f.aich_hash.is_empty() && record.aich_hash != f.aich_hash {
                            record.aich_hash = f.aich_hash.clone();
                            any_updated = true;
                        }
                        if !f.ember_file_hash.is_empty()
                            && record.ember_file_hash != f.ember_file_hash
                        {
                            record.ember_file_hash = f.ember_file_hash.clone();
                            any_updated = true;
                        }
                    }
                }
            }
        }
        if any_updated {
            known_files.mark_dirty();
        }
    }

    let known_path = state.data_dir.join("known.met");
    sync_ember_publish_to_known(
        &state.ember_source_publish_unix,
        &state.ember_keyword_publish_unix,
        known_files,
    );
    match tokio::time::timeout_at(
        shutdown_phase_deadline(
            shutdown_deadline,
            std::time::Duration::from_secs(5),
        ),
        state.known_met_save_lock.lock(),
    )
    .await
    {
        Ok(_ownership) => {
            if let Err(e) = known_files.save(&known_path) {
                error!("Failed to save known.met on shutdown: {e}");
            }
        }
        Err(_) => warn!(
            "Final known.met save skipped: serialized periodic writer still owns the file; refusing a racing overwrite"
        ),
    }
    // Drain remaining AICH sets into the append queue, bounded as the
    // periodic timer bounds it.
    let mut shutdown_dropped = 0usize;
    while let Ok(hs) = aich_set_rx.try_recv() {
        if state.pending_known2_sets.len() >= MAX_AICH_HASH_SETS {
            shutdown_dropped = shutdown_dropped.saturating_add(1);
            continue;
        }
        state.pending_known2_sets.push(hs);
    }
    if shutdown_dropped > 0 {
        warn!(
            "Shutdown drain hit AICH cap {}; dropped {} new set(s)",
            MAX_AICH_HASH_SETS, shutdown_dropped,
        );
    }
    if !state.pending_known2_sets.is_empty() {
        // Wait out a periodic writer still in flight. Every sibling shutdown
        // save drains its in-flight flag or takes its lock; this one did
        // neither, so a 120-second periodic save that happened to be running
        // could rename its older snapshot over the one written here. The
        // writes are atomic, so the file could not be corrupted — but the
        // shutdown snapshot is strictly newer (it drains `aich_set_rx` just
        // above), and losing it discards the AICH recovery sets computed
        // since that save began.
        if *known2_save_in_flight {
            // Charged to the shared shutdown budget like every sibling phase. A
            // bare 5s of wall clock was not deducted from any phase but still
            // advanced the clock, so it could silently consume the headroom the
            // reputation / sources.met / server.met saves below depend on.
            let known2_join_deadline =
                shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(5));
            while *known2_save_in_flight && tokio::time::Instant::now() < known2_join_deadline {
                match tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    periodic_save_result_rx.recv(),
                )
                .await
                {
                    Ok(Some(result)) => {
                        // One shared channel carries every periodic save, so clear
                        // whichever flag this result belongs to. Dropping a
                        // sibling's completion left its own join below waiting on a
                        // message already consumed here, burning that phase's slice
                        // of the *shared* shutdown budget and reporting it as a
                        // deadline exhaustion — which can then push the later
                        // sources.met / server.met saves past the global deadline.
                        match result.job {
                            PeriodicSaveJob::Known2 => *known2_save_in_flight = false,
                            PeriodicSaveJob::Reputation => *reputation_save_in_flight = false,
                            PeriodicSaveJob::Nodes | PeriodicSaveJob::Stats => {}
                        }
                        if let Err(error) = result.result {
                            error!("Periodic shutdown writer failed before final save: {error}");
                        }
                    }
                    Ok(None) => break,
                    Err(_) => {}
                }
            }
            if *known2_save_in_flight {
                warn!(
                    "Periodic known2_64.met save still in flight 5s into shutdown; \
                     writing the final snapshot anyway"
                );
            }
        }
        // The periodic append that may just have finished covered a prefix of
        // this queue; appending the whole of it again is harmless, since the
        // store skips masters it already holds.
        let hash_sets = std::mem::take(&mut state.pending_known2_sets);
        if tokio::time::Instant::now() >= shutdown_deadline {
            error!(
                "Shutdown deadline exhausted before known2_64.met save; shutdown result is explicitly truncated"
            );
        } else {
            let writer =
                tokio::task::spawn_blocking(move || ed2k::aich::append_known2_sets(&hash_sets));
            match tokio::time::timeout_at(shutdown_deadline, writer).await {
                Ok(Ok(Ok(added))) => info!(
                    "Appended {added} AICH hash sets to known2_64.met"
                ),
                Ok(Ok(Err(e))) => error!("Failed to save known2_64.met on shutdown: {e}"),
                Ok(Err(e)) => error!("known2_64.met shutdown writer failed: {e}"),
                Err(_) => error!(
                    "Shutdown deadline exhausted joining known2_64.met writer; shutdown result is explicitly truncated"
                ),
            }
        }
    }
    if let Some(mut handle) = credit_flush_handle.take() {
        if tokio::time::timeout_at(
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(5)),
            &mut handle,
        )
        .await
        .is_err()
        {
            warn!(
                "Periodic credit flush still running at shutdown; aborting its async owner and retrying the final flush through serialized save ownership"
            );
            handle.abort();
            let _ = handle.await;
        }
    }
    match tokio::time::timeout_at(
        shutdown_phase_deadline(
            shutdown_deadline,
            std::time::Duration::from_secs(8),
        ),
        flush_credit_state(
            credit_manager,
            db,
            &state.data_dir,
            true,
            credit_save_ownership,
        ),
    )
    .await
    {
        Ok(()) => info!("Credit state saved on shutdown"),
        Err(_) => warn!(
            "Final credit flush could not acquire/finish serialized save ownership within shutdown timeout"
        ),
    }

    // Reputation carries active automatic bans. Join any stale periodic
    // writer before the final authoritative snapshot so it cannot rename an
    // older ban set over the shutdown save.
    let reputation_join_deadline =
        shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(5));
    while *reputation_save_in_flight {
        match tokio::time::timeout_at(reputation_join_deadline, periodic_save_result_rx.recv())
            .await
        {
            Ok(Some(result)) => {
                match result.job {
                    PeriodicSaveJob::Reputation => *reputation_save_in_flight = false,
                    PeriodicSaveJob::Known2 | PeriodicSaveJob::Nodes | PeriodicSaveJob::Stats => {}
                }
                if let Err(error) = result.result {
                    error!("Periodic shutdown writer failed before final save: {error}");
                }
            }
            Ok(None) => break,
            Err(_) => {
                error!(
                    "Shutdown deadline exhausted joining the periodic reputation/ban writer; shutdown result is explicitly truncated"
                );
                break;
            }
        }
    }

    let rep_path = state.data_dir.join("reputation.json");
    if tokio::time::Instant::now() >= shutdown_deadline {
        error!(
            "Shutdown deadline exhausted before reputation/ban save; shutdown result is explicitly truncated"
        );
    } else {
        let reputation_snapshot = state.reputation.clone();
        let tracked = reputation_snapshot.tracked_count();
        let writer = tokio::task::spawn_blocking(move || reputation_snapshot.save(&rep_path));
        match tokio::time::timeout_at(shutdown_deadline, writer).await {
            Ok(Ok(Ok(()))) => {
                info!("Reputation data saved on shutdown ({tracked} peers tracked)")
            }
            Ok(Ok(Err(error))) => {
                error!("Failed to save reputation.json on shutdown: {error}")
            }
            Ok(Err(error)) => error!("Reputation shutdown writer failed: {error}"),
            Err(_) => error!(
                "Shutdown deadline exhausted joining reputation/ban writer; shutdown result is explicitly truncated"
            ),
        }
    }

    // Persist the record store so the next session starts holding what this one
    // held. Shutdown only, deliberately: the store can be several megabytes and
    // writing that every few minutes is the disk hitch the peer-list save was
    // changed to avoid. An abnormal exit falls back to replication refilling the
    // store, which is what happened on every exit before this.
    //
    // After known.met, credits and the bans, and in a phase of its own: it is
    // the one save here that replication can replace, and it used to run first
    // with the whole remaining deadline, so a slow disk spent the time the ban
    // save needed and a restart silently lifted automatic bans.
    let ember_records = state
        .ember_dht
        .persistable_records(EMBER_PERSIST_MAX_RECORDS);
    let store_ember_path = state.data_dir.join("store_ember.dat");
    let ember_store_loaded = state.ember_store_loaded;
    if tokio::time::Instant::now() >= shutdown_deadline {
        error!(
            "Shutdown deadline exhausted before store_ember.dat save; shutdown result is explicitly truncated"
        );
    } else {
        let writer = tokio::task::spawn_blocking(move || {
            ember::dht::bootstrap::save_store(
                &store_ember_path,
                &ember_records,
                ember_store_loaded,
            )
        });
        let store_deadline =
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(3));
        match tokio::time::timeout_at(store_deadline, writer).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => error!("Failed to save store_ember.dat on shutdown: {e}"),
            Ok(Err(e)) => error!("store_ember.dat shutdown writer failed: {e}"),
            Err(_) => error!(
                "store_ember.dat writer still running at the end of its shutdown phase; the next session refills the store by replication"
            ),
        }
    }

    // Persist the source cache (peer user hashes + crypt options) so the next
    // session can obfuscate connections to the same crypt-required peers
    // immediately, mirroring eMule's persisted source identities.
    if tokio::time::Instant::now() < shutdown_deadline {
        let sources_met = state.data_dir.join("sources.met");
        let source_snapshot = source_manager.read().await.clone();
        let writer =
            tokio::task::spawn_blocking(move || source_snapshot.save_to_disk(&sources_met));
        match tokio::time::timeout_at(shutdown_deadline, writer).await {
            Ok(Ok(Ok(count))) => {
                info!("Saved {count} cached sources (with user hashes) to sources.met")
            }
            Ok(Ok(Err(error))) => error!("Failed to save sources.met on shutdown: {error}"),
            Ok(Err(error)) => error!("sources.met shutdown writer failed: {error}"),
            Err(_) => error!(
                "Shutdown deadline exhausted joining sources.met writer; shutdown result is explicitly truncated"
            ),
        }
    } else {
        error!(
            "Shutdown deadline exhausted before sources.met; shutdown result is explicitly truncated"
        );
    }

    let server_met_path = state.data_dir.join("server.met");
    if tokio::time::Instant::now() < shutdown_deadline {
        match state.server_list.to_server_met_bytes() {
            Ok(bytes) => {
                let generation = state.server_met_save_generation.clone();
                let save_lock = state.server_met_save_lock.clone();
                let gen = generation.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let writer = tokio::task::spawn_blocking(move || {
                    let _guard = match save_lock.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    if generation.load(std::sync::atomic::Ordering::Relaxed) != gen {
                        return Ok(());
                    }
                    ed2k::server_list::ServerList::write_server_met_bytes(&server_met_path, &bytes)
                });
                match tokio::time::timeout_at(shutdown_deadline, writer).await {
                    Ok(Ok(Ok(()))) => info!("server.met writer joined on shutdown"),
                    Ok(Ok(Err(error))) => {
                        error!("Failed to save server.met on shutdown: {error}")
                    }
                    Ok(Err(error)) => error!("server.met shutdown writer failed: {error}"),
                    Err(_) => error!(
                        "Shutdown deadline exhausted while joining server.met writer; shutdown result is explicitly truncated"
                    ),
                }
            }
            Err(error) => error!("Failed to serialize server.met on shutdown: {error}"),
        }
    } else {
        error!(
            "Shutdown deadline exhausted before server.met; shutdown result is explicitly truncated"
        );
    }

    // Unregister from the rendezvous server LAST and with a short bound.
    // This is a best-effort courtesy call to a remote host that may be slow
    // or unreachable; running it before the local saves above (with the
    // client's full 10s request timeout) could exhaust the app's ~12s
    // shutdown budget and cut off nodes.dat / known.met / credit / reputation
    // persistence. All local state is already on disk by this point, so a slow
    // unregister can no longer cost us durability.
    if state.rendezvous_registered {
        let rv_url = settings.rendezvous_url.clone();
        let rv_hash = ember_hash;
        match tokio::time::timeout_at(
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(3)),
            rendezvous::unregister(&rv_url, &rv_hash, &ed25519_secret_key),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => debug!("Failed to unregister from rendezvous server: {e}"),
            Err(_) => debug!("Rendezvous unregister timed out on shutdown; skipping"),
        }
    }

    if upnp_enabled {
        // Best-effort removal; don't let an unresponsive gateway stall app
        // shutdown on TCP connect timeouts. Timed leases expire on their own
        // within the hour, and permanent-lease mappings (the error-725
        // fallback) are reclaimed by the next session's conflict handling.
        let _ = tokio::time::timeout_at(
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(5)),
            upnp_mappings.teardown(),
        )
        .await;
    }
}
