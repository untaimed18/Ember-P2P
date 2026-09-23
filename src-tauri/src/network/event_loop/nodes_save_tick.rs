//! The periodic nodes.dat save, so a crash does not lose the routing table.

use super::*;

pub(in crate::network) async fn on_nodes_save_tick(
    state: &mut NetworkState,
    nodes_save_in_flight: &mut bool,
    nodes_save_started_at: &mut Option<tokio::time::Instant>,
    periodic_save_result_tx: &mpsc::UnboundedSender<PeriodicSaveResult>,
) {
    if !*nodes_save_in_flight {
        let ownership = state.nodes_save_lock.clone().lock_owned().await;
        let contacts = state.routing_table.export_bootstrap_contacts(200);
        let nodes_path = state.data_dir.join("nodes.dat");
        let tx = periodic_save_result_tx.clone();
        *nodes_save_in_flight = true;
        *nodes_save_started_at = Some(tokio::time::Instant::now());
        tokio::spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                let _ownership = ownership;
                bootstrap::save_nodes_dat(&nodes_path, &contacts)
                    .map_err(|e| e.to_string())
            })
            .await
            .map_err(|e| format!("nodes.dat save task failed: {e}"))
            .and_then(|r| r);
            let _ = tx.send(PeriodicSaveResult {
                job: PeriodicSaveJob::Nodes,
                result,
            });
        });
    }
    // Fold the live overlay into the remembered set and persist that
    // (slice 7). Additive by construction: a peer that has just been
    // evicted as an unresponsive lead stays in the cache, so this
    // write can grow the file or refresh it but never cuts it down
    // to whatever the table happens to hold five minutes into a
    // session. Retiring an address is a once-per-session decision
    // and belongs to the shutdown path. Still skipped when empty, so
    // a brand-new profile doesn't churn a zero-contact file.
    let live = ember_persistable_contacts(state);
    state.ember_bootstrap_cache.observe(live.iter());
    let local_id = state.ember_dht.local_id();
    // Bound the in-memory set here too, not only on the way out. It
    // takes the whole replacement cache and every session peer every
    // five minutes, and a peer answering FIND_NODE with invented
    // contacts can inject fresh ids at will, so over a long session
    // it would grow into the tens of thousands — and each save sorts
    // the lot. Trimming to the same ceiling the file is written under
    // discards only entries that could never have been saved anyway,
    // and is a no-op below it.
    state
        .ember_bootstrap_cache
        .trim_to(&local_id, EMBER_PERSIST_MAX_CONTACTS);
    let ember_contacts = state
        .ember_bootstrap_cache
        .snapshot(&local_id, EMBER_PERSIST_MAX_CONTACTS);
    if !ember_contacts.is_empty() {
        let ember_path = state.data_dir.join("nodes_ember.dat");
        // Off the loop, like the nodes.dat write above and for the
        // reason `spawn_save_server_met` documents: `save_nodes`
        // commits through `atomic_write`, so it fsyncs the file *and*
        // the parent directory inline. Running that in the select arm
        // stalled UDP receive, every timer and every transfer event for
        // the duration, and a full receive buffer drops KAD and Ember
        // packets outright.
        // Take ownership for the write so the shutdown writer, which
        // waits on the same lock, cannot have its newer snapshot
        // renamed over by a save spawned just before the loop exits.
        // `try_lock` rather than `lock().await`: this arm must never
        // block the event loop on disk I/O, and skipping a periodic
        // save is free — the next tick writes the same state. It gets
        // its own lock because `nodes_save_lock` is still held by the
        // nodes.dat task spawned a few lines above.
        let Ok(ownership) = state.ember_nodes_save_lock.clone().try_lock_owned() else {
            return;
        };
        let nodes_file_state = state.ember_nodes_file;
        tokio::task::spawn_blocking(move || {
            let _ownership = ownership;
            if let Err(e) = ember::dht::bootstrap::save_nodes(
                &ember_path,
                &ember_contacts,
                nodes_file_state,
            ) {
                error!("Failed periodic nodes_ember.dat save: {e}");
            }
        });
    }
}
