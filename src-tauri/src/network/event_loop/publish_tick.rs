//! The 60 s publish tick: Ember DHT source and keyword publishing, Ember's
//! publish heartbeat, and KAD publish diagnostics.

use super::*;

pub(in crate::network) async fn on_publish_tick(
    udp_socket: &Arc<UdpSocket>,
    state: &mut NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    settings: &AppSettings,
    known_files: &mut KnownFileList,
) {
    // Ember DHT source publishing (slice 9) runs independently of
    // KAD connectivity, so it must come before the KAD-status gate
    // and the KAD-routing-table check below: it works on a
    // KAD-less network as long as the Ember routing table is warm.
    maybe_publish_ember_sources(
        udp_socket,
        state,
        settings,
        local_index,
        known_files,
    )
    .await;

    // Ember DHT keyword publishing (slice 8), same independence
    // from KAD connectivity as source publishing above.
    maybe_publish_ember_keywords(
        udp_socket,
        state,
        settings,
        local_index,
        known_files,
    )
    .await;

    // Ember's own publish heartbeat. Every other publish line in
    // the log comes from KAD, so without this there was no way to
    // tell a tick that delivered its records from one that dropped
    // them — which for a long time was most of them.
    if settings.ember_native_enabled {
        let (contacts, verified) = ember_dht_ui_contact_counts(state);
        let queued = state.ember_batch_publish.queued_count;
        let in_flight = state.ember_batch_publish.in_flight.len();
        let unplaced = state.ember_publish_unplaced.len();
        let pass = state.ember_publish_pass;
        let acked_at_last_beat = state.ember_publish_beat_acked;
        let failed_at_last_beat = state.ember_publish_beat_failed;
        state.ember_publish_beat_acked =
            state.ember_diagnostics.ember_dht_stores_acked;
        state.ember_publish_beat_failed =
            state.ember_diagnostics.ember_dht_stores_failed;
        // An empty overlay short-circuits both publishers before
        // they count what is due, so the usual stats would print
        // a row of zeros that reads as "nothing to publish" when
        // the truth is "nowhere to publish it". Name that instead,
        // and never fall silent: a tick that does nothing is the
        // one worth reading. Session peers the public table
        // refused count here the same way the publishers do.
        //
        // Unverified leads count as overlay contacts (bootstrap
        // still needs them) but not as STORE targets. Flooding
        // them used to log selected=82 / failed=102 against a
        // single seed that never completed a Noise handshake.
        let publishable = ember_publishable_peer_count(state);
        if contacts == 0 {
            info!(
                "Ember publish cycle: idle, Ember overlay is empty so there is \
                 nobody to publish to — queued={queued}, in-flight={in_flight}, \
                 awaiting placement={unplaced}"
            );
        } else if publishable == 0 {
            info!(
                "Ember publish cycle: idle, holding STOREs until a verified peer \
                 answers — contacts={contacts} ({verified} verified), \
                 queued={queued}, in-flight={in_flight}, \
                 awaiting placement={unplaced}"
            );
        } else {
            info!(
                "Ember publish cycle: contacts={contacts} ({verified} verified), \
                 due={}, selected={}, awaiting placement={unplaced}, queued={queued}, \
                 in-flight={in_flight}, sent={} in {} frame(s), behind handshake={} \
                 in {} frame(s), held over={}, dropped={}, re-armed={}, \
                 acked={} of {} total, failed={} of {} total",
                pass.due,
                pass.selected,
                pass.flush.records_sent,
                pass.flush.frames_sent,
                pass.flush.records_behind_handshake,
                pass.flush.frames_behind_handshake,
                pass.flush.records_carried,
                pass.flush.records_dropped,
                pass.flush.records_rearmed,
                // Every other field on this line is per-cycle
                // (`ember_publish_pass` is reset just below), but
                // these two counters are session totals, so a cycle
                // that acked nothing read as though it had acked
                // thousands. Report the delta and keep the total.
                state
                    .ember_diagnostics
                    .ember_dht_stores_acked
                    .saturating_sub(acked_at_last_beat),
                state.ember_diagnostics.ember_dht_stores_acked,
                state
                    .ember_diagnostics
                    .ember_dht_stores_failed
                    .saturating_sub(failed_at_last_beat),
                state.ember_diagnostics.ember_dht_stores_failed,
            );
        }
        state.ember_publish_pass = EmberPublishPassStats::default();
    }

    // KAD publish diagnostics only. Presence heartbeat lives on
    // `bootstrap_timer` so an eD2K-only session (status stays
    // `Disconnected`) still refreshes rendezvous.
    if state.stats.status == NetworkStatus::Disconnected
        || state.routing_table.is_empty()
    {
        debug!("Skipping publish cycle: KAD is not connected or its routing table is empty");
    } else {
    let total_files = state.publish_manager.file_count();
    let needing_source = state.publish_manager.files_needing_source_publish().len();
    let needing_keyword = state.publish_manager.keywords_needing_publish_count();
    info!(
        "Publish cycle: {total_files} files registered, {needing_source} need source publish, \
         {needing_keyword} keyword targets need publish, {} confirmed, {} outstanding pending ack, \
         PublishRes plain_seen={} obf_decoded={}/{} wire={} received={} unmatched={}, \
         firewalled={}, routing_table={}",
        state.publish_confirmed,
        state.publish_pending.len(),
        state.publish_res_plain_seen,
        state.publish_res_obf_decoded,
        state.obf_decoded_total,
        state.publish_res_wire,
        state.publish_res_received,
        state.publish_res_unmatched,
        state.publish_manager.firewalled,
        state.routing_table.len(),
    );
    } // end routing-table guard: publish diagnostics only

    // Rendezvous presence heartbeat lives on `bootstrap_timer`
    // (10s) so it actually honours `PRESENCE_HEARTBEAT_SECS`.
    // Punch polling was split onto `punch_poll_timer` for the
    // same reason: this 60s arm quantized both past their TTLs.

}
