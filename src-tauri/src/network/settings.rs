//! Applying network settings at runtime, disabling Ember, and the
//! anti-leech pattern list.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

pub(super) fn antileech_file_path(state: &NetworkState) -> std::path::PathBuf {
    state
        .data_dir
        .join(crate::security::antileech::DEFAULT_FILE_NAME)
}

pub(super) fn antileech_snapshot(state: &NetworkState) -> crate::types::AntiLeechSnapshot {
    let f = state.antileech.read();
    crate::types::AntiLeechSnapshot {
        enabled: f.enabled(),
        patterns: f.patterns().to_vec(),
        file_path: antileech_file_path(state).to_string_lossy().to_string(),
        pattern_count: f.pattern_count() as u32,
    }
}

pub(super) fn antileech_set_patterns(
    state: &NetworkState,
    patterns: Vec<String>,
) -> Result<crate::types::AntiLeechReplaceResult, String> {
    let explicitly_empty = patterns.iter().all(|pattern| {
        let pattern = pattern.trim();
        pattern.is_empty() || pattern.starts_with('#')
    });
    let enabled = state.antileech.read().enabled();
    let (replacement, errors) =
        crate::security::antileech::AntiLeechFilter::from_patterns(patterns, enabled);
    if !explicitly_empty && replacement.pattern_count() == 0 {
        return Err(
            "Every anti-leech pattern was invalid; the current filter was preserved".into(),
        );
    }
    if let Err(e) = replacement.save_to_file(&antileech_file_path(state)) {
        return Err(format!("Failed to persist anti-leech patterns: {e}"));
    }
    *state.antileech.write() = replacement;
    Ok(crate::types::AntiLeechReplaceResult {
        snapshot: antileech_snapshot(state),
        compile_errors: errors
            .into_iter()
            .map(|(p, e)| (p, e.to_string()))
            .collect(),
    })
}

pub(super) fn antileech_set_enabled(state: &NetworkState, enabled: bool) -> Result<(), String> {
    let mut f = state.antileech.write();
    f.set_enabled(enabled)
}

pub(super) fn antileech_reset_defaults(
    state: &NetworkState,
) -> Result<crate::types::AntiLeechSnapshot, String> {
    let was_enabled = state.antileech.read().enabled();
    let defaults = crate::security::antileech::AntiLeechFilter::with_defaults(was_enabled);
    {
        let mut f = state.antileech.write();
        *f = defaults;
    }
    {
        let f = state.antileech.read();
        if let Err(e) = f.save_to_file(&antileech_file_path(state)) {
            return Err(format!(
                "Defaults restored in memory but persist failed: {e}"
            ));
        }
    }
    Ok(antileech_snapshot(state))
}

/// Tear down Ember-native runtime state when the feature flag flips off.
///
/// Sessions established while "on" must not survive into a later re-enable
/// (different intent, and the peer's Noise key may have rotated), and the
/// mesh caches / in-flight operation maps would otherwise leak memory and
/// strand `oneshot` waiters that can no longer be answered. Dropping the
/// pending-operation senders also lets any blocked command return promptly
/// instead of waiting out its full timeout.
///
/// The DHT engine itself (routing table + record store) is deliberately
/// *kept*: it's small, it's the warm state that lets a re-enable rejoin
/// instantly without a cold bootstrap, and it's re-persisted to
/// `nodes_ember.dat` on shutdown regardless. Only the volatile session and
/// discovery state tied to a live transport is cleared here.
///
/// Returns the active search `request_id` if an in-flight Ember search leg
/// was cancelled so the caller can emit `search-complete`.
///
/// Kept for the (now unreachable) disable path: the overlay is always on
/// and settings can no longer flip it off.
#[allow(dead_code)]
pub(super) fn ember_disable_cleanup(state: &mut NetworkState) -> Option<u64> {
    // Encrypted sessions + their control-ping waiters.
    state.ember_transport.cleanup_all();
    state.ember_pending_pings.clear();

    // In-flight DHT operations and their waiters.
    state.ember_dht_pending_pings.clear();
    state.ember_dht_pending_finds.clear();
    state.ember_dht_pending_lookups.clear();
    state.ember_dht_pending_value_lookups.clear();
    state.ember_dht_pending_publishes.clear();
    state.ember_dht_search_requests.clear();
    state.ember_dht_publish_requests.clear();
    state.ember_dht_maint_pings.clear();
    state.ember_download_source_searches.clear();
    state.ember_source_search_state.clear();
    state.ember_pending_source_injections.clear();
    state.ember_pending_callback_connects.clear();
    state.ember_pending_proxy_overlay.clear();
    state.ember_keyword_searches.clear();
    state.ember_pending_keyword_results.clear();
    state.ember_channel_presence_searches.clear();
    state.ember_channel_presence_buffer.clear();
    state.ember_pending_channel_presence.clear();
    state.ember_channel_ingest = None;
    state.channel_presence_fetch_at.clear();
    state.channel_focused = None;
    state.channel_beacon_beat_at.clear();
    state.channel_beacons.clear();
    state.channel_beacon_flood_at.clear();
    state.channel_beacon_inserts.clear();
    state.channel_presence_dirty.clear();
    state.ember_channel_moderation_searches.clear();
    state.ember_pending_channel_moderation.clear();
    state.channel_moderation_fetch_at.clear();
    state.channel_moderation_publish_at.clear();
    state.channel_username_refresh_at = 0;
    state.ember_channel_noise_keys.clear();
    state.channel_roster_cache = None;
    state.channel_member_touch_flushed_at = None;
    state.channel_neighbor_lookup_at.clear();
    state.channel_neighbor_lookup_inflight.clear();
    state.channel_neighbor_scan_after = None;
    state.channel_relay_outboxes.clear();
    state.channel_relay_pending.clear();
    state.channel_relay_offer_at.clear();
    state.ember_channel_handoff_searches.clear();
    state.ember_pending_channel_handoff.clear();
    state.channel_handoff_fetch_at.clear();
    state.channel_handoff_absent_at.clear();
    state.xfer_send.clear();
    state.xfer_recv.clear();
    state.xfer_pending.clear();
    state.xfer_block_times.clear();
    state.xfer_upload_credit = 0;
    state.ember_channel_epoch_searches.clear();
    state.ember_pending_channel_epoch.clear();
    state.channel_epoch_fetch_at.clear();
    state.ember_channel_claim_searches.clear();
    state.ember_pending_channel_claim.clear();
    state.channel_gossip_from_times.clear();
    state.channel_gossip_author_times.clear();
    state.channel_typing_recv_times.clear();
    state.channel_typing_sent_times.clear();
    state.channel_history_sync_at.clear();
    state.channel_history_sync_mark.clear();
    state.channel_history_sync_ingested.clear();
    // Nothing is left to carry a waiting line, so it fails now: the startup
    // sweep only settles lines left by an earlier run, and would never reach
    // one from this session. Verdicts already reached are written out with
    // them rather than discarded.
    for (_, body) in std::mem::take(&mut state.channel_origin_retry) {
        if let Some(gossip) = ember::channel::ChannelGossip::decode(&body) {
            note_channel_delivery(
                state,
                gossip.channel_id,
                gossip.msg_id,
                crate::storage::database::CHAT_FAILED,
            );
        }
    }
    if !state.channel_delivery_notes.is_empty() {
        let (db, app_handle) = state.channel_delivery_sink.clone();
        let notes: Vec<([u8; 16], [u8; 16], i64)> =
            std::mem::take(&mut state.channel_delivery_notes).into();
        tokio::spawn(async move {
            write_channel_delivery_notes(notes, &db, &app_handle).await;
        });
    }
    // Forget the per-file publish schedule so a re-enable republishes every
    // shared file promptly instead of waiting out the republish interval.
    state.ember_source_publish_at.clear();
    state.ember_source_publish_unix.clear();
    state.ember_keyword_publish_at.clear();
    state.ember_keyword_publish_unix.clear();
    // Library badges must go dark with the feature: the records we placed
    // will age out of the network and we are no longer republishing them.
    state.ember_published_sources.clear();
    state.ember_search = ember::dht::search::SearchManager::new();
    state.ember_publish = ember::dht::publish::PublishManager::new();
    state.ember_batch_publish.clear();
    state.ember_proxy_buddies.clear();
    state.ember_announced_at.clear();
    state.ember_publish_unplaced.clear();
    state.ember_publish_placed.clear();
    state.ember_publish_partial.clear();
    state.ember_keyword_retries_spent.clear();
    state.ember_publish_attempts.clear();
    state.ember_publish_pass = EmberPublishPassStats::default();

    // KAD-bridge discovery caches: only meaningful while the transport is
    // live, and the attempted-set in particular would otherwise grow
    // unbounded across the session.
    state.ember_noise_keys.clear();
    state.ember_kad_bridge_attempted.clear();
    state.known_ember_peers.clear();
    state.ember_keyless_peers.clear();
    state.ember_session_dht_contacts.clear();
    // `ember_content_hashes` deliberately survives: it holds the expected BLAKE3
    // for downloads in flight, seeded from deep links as well as DHT hits, and
    // clearing it here would drop the digest a running transfer verifies against.
    // It is bounded by `prune_ember_content_hashes` instead.

    // Stop claiming to be an Ember node on KAD.
    //
    // The advert under `ember_rendezvous_key` says "DHT-ping me to join"; with
    // the overlay off we drop every Ember-magic packet those peers send. Leaving
    // the timestamp alone meant we neither withdrew the claim nor re-advertised,
    // so for up to a full republish interval other nodes spent their bridge ping
    // budget — eight a minute — on a peer that would never answer. Zeroing it
    // means a re-enable re-advertises on the next publish tick instead of
    // waiting the interval out, and an in-flight lookup is dropped rather than
    // resolving into a table we are no longer maintaining.
    state.ember_rendezvous_published_at = 0;
    state.ember_rendezvous_looked_up_at = 0;
    state.ember_rendezvous_empty_streak = 0;
    state.ember_rendezvous_search = None;

    // A re-enable is a fresh join: redo the self-lookup and restart the
    // disconnect clock rather than carrying over the old session's state.
    state.ember_started_at = chrono::Utc::now().timestamp();
    state.ember_self_lookup_done = false;
    state.ember_last_self_lookup = 0;
    state.ember_last_inbound = None;
    state.ember_rearmed_at = None;
    state.ember_last_overlay_contacts = 0;
    state.ember_empty_rearmed_at = 0;
    state.ember_publish_targets.clear();
    state.ember_publish_target_queue.clear();
    state.ember_publish_target_lookups.clear();
    state.ember_udp_reachable_at = None;
    state.ember_reach_witness = None;
    state.ember_reach_external_ip = None;

    // Cumulative dev-console counters: start each enable-session clean
    // (matching the session reset above). The live fields — session count,
    // contact count, etc. — are recomputed from state on each read.
    state.ember_diagnostics = EmberDiagnostics::default();

    // Cancel any in-flight Ember search leg so Global/Ember searches don't
    // hang waiting on `ember_pending` after the transport is gone.
    let finish_request_id = state.active_search_request.as_mut().and_then(|active| {
        if active.ember_pending {
            active.ember_pending = false;
            Some(active.request_id)
        } else {
            None
        }
    });

    info!("Ember-native transport disabled — cleared sessions, caches, and in-flight DHT state");
    finish_request_id
}

pub(super) fn apply_network_settings(
    state: &mut NetworkState,
    settings: &mut AppSettings,
    mut new_settings: AppSettings,
    _app_handle: &tauri::AppHandle,
) -> bool {
    let stun_was_enabled = state.stun_keepalive_enabled;
    state.stun_keepalive_enabled = new_settings.stun_keepalive_enabled;
    if !new_settings.stun_keepalive_enabled {
        reset_stun_keepalive_session(state);
    } else if !stun_was_enabled {
        // User turned STUN back on: clear auto-suspend so it can try again.
        // Do not clear on unrelated settings saves while already enabled.
        reset_stun_keepalive_session(state);
    }
    state.xfer_offer_policy = new_settings.channel_file_offers.clone();
    state.obfuscation_enabled = new_settings.obfuscation_enabled;
    state.obfuscation_enabled_shared.store(
        new_settings.obfuscation_enabled,
        std::sync::atomic::Ordering::Relaxed,
    );
    state.skip_compress_video_shared.store(
        new_settings.skip_compress_video,
        std::sync::atomic::Ordering::Relaxed,
    );
    *state.download_folders.write() = new_settings.download_folders();
    state.filter_incoming_shared.store(
        new_settings.filter_incoming_connections,
        std::sync::atomic::Ordering::Relaxed,
    );
    state.share_browsing_shared.store(
        new_settings.allow_shared_files_browse,
        std::sync::atomic::Ordering::Relaxed,
    );
    // Same value, second consumer: the Hello builder has no settings handle,
    // and until it was told, bit 2 of CT_EMULE_MISCOPTIONS1 was hardcoded to
    // "no view shared files" — so enabling the setting never reached the wire
    // and eMule peers never offered "View Files", let alone asked.
    ed2k::messages::set_share_browsing_allowed(new_settings.allow_shared_files_browse);
    state.uss_enabled_flag.store(
        new_settings.uss_enabled,
        std::sync::atomic::Ordering::Relaxed,
    );
    state.upload_max_slots.store(
        new_settings.max_concurrent_uploads as usize,
        std::sync::atomic::Ordering::Relaxed,
    );
    ed2k::multi_source::set_new_connections_per_five(
        new_settings.max_connections_per_five_secs as usize,
    );
    ed2k::multi_source::set_global_conn_limit(new_settings.max_connections as usize);
    crate::sharing::manager::set_global_preview_priority(new_settings.preview_priority_all);
    state.max_sources_per_file = ed2k::sources::max_sources_per_file(new_settings.max_sources_per_file);
    for pfs in state.per_file_sources.values_mut() {
        pfs.set_max_sources(state.max_sources_per_file);
    }
    if !new_settings.uss_enabled {
        if let Some((addr, _)) = state.uss_host.take() {
            state.uss_prev_host = Some(addr);
        }
        state.pending_uss_pings.clear();
        state.uss_missed_pongs = 0;
    }
    let mut needs_ipfilter_load = false;
    if state.ip_filter.is_enabled() != new_settings.ip_filter_enabled {
        state.ip_filter.set_enabled(new_settings.ip_filter_enabled);
        let mut load_ready = true;
        if new_settings.ip_filter_enabled && !state.ip_filter.has_loaded_ranges() {
            let default_path = state.data_dir.join("ipfilter.dat");
            if default_path.exists() {
                // Realistic lists take 150ms–2s; parse on the blocking pool.
                needs_ipfilter_load = true;
                load_ready = false;
            }
        }
        // Clear fail-closed only after a successful load or intentional empty/absent.
        if new_settings.ip_filter_enabled && load_ready {
            state.ip_filter.mark_ranges_ready();
        }
        state
            .ip_filter
            .update_shared_snapshot(&state.shared_ip_filter);
        if new_settings.ip_filter_enabled {
            state.routing_table.evict_filtered_contacts();
            purge_ember_ip_blocked_peers(state);
            state.ember_dht.evict_filtered_contacts();
        }
    }
    if state.ip_filter.blocks_private() != new_settings.block_private_ips {
        state
            .ip_filter
            .set_block_private(new_settings.block_private_ips);
        state
            .ip_filter
            .update_shared_snapshot(&state.shared_ip_filter);
        // Keep KAD contact admission in sync with the live setting and
        // drop any contacts that the newly-enabled private block rejects.
        state
            .routing_table
            .set_block_private_ips(new_settings.block_private_ips);
        // Ember shares the user's IP policy: both stacks dial peers from the
        // same socket, so a contact the user has blocked must be refused by
        // whichever table would otherwise hand it to us.
        purge_ember_ip_blocked_peers(state);
        state
            .ember_dht
            .set_block_private_ips(new_settings.block_private_ips);
    }
    // Overlay is always on; ignore any payload that tries to disable it.
    new_settings.ember_native_enabled = true;
    info!(
        "Network settings updated: obfuscation={}, uss={}, nickname={}, max_uploads={}, ip_filter={}, block_private={}, ember_native={}",
        new_settings.obfuscation_enabled,
        new_settings.uss_enabled,
        new_settings.nickname,
        new_settings.max_concurrent_uploads,
        new_settings.ip_filter_enabled,
        new_settings.block_private_ips,
        new_settings.ember_native_enabled,
    );
    *settings = new_settings;
    needs_ipfilter_load
}

/// Applies an `UpdateSettings` command to the loop-owned `settings` and to
/// everything that caches a setting. The command drain and the `cmd_rx` arm
/// both route it here, since `handle_command` cannot reach `settings`.
#[allow(clippy::too_many_arguments)]
pub(super) async fn apply_settings_update(
    udp_socket: &Arc<UdpSocket>,
    state: &mut NetworkState,
    settings: &mut AppSettings,
    new_settings: AppSettings,
    db: &Arc<Database>,
    identity: &Arc<crate::storage::identity::NodeIdentity>,
    app_handle: &tauri::AppHandle,
    shared_nickname: &Arc<tokio::sync::RwLock<String>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    shared_server_addr: &Arc<RwLock<Option<SocketAddr>>>,
) {
    let old_channel_username = settings.channel_username.clone();
    if apply_network_settings(state, settings, new_settings, app_handle) {
        load_ipfilter_on_enable(state).await;
    }
    publish_presence_under_new_username(
        udp_socket,
        state,
        db,
        settings,
        identity,
        &old_channel_username,
    )
    .await;
    state
        .relay_manager
        .lock()
        .await
        .set_policy(settings.relay_for_peers, settings.max_relay_sessions);
    {
        let mut nick = shared_nickname.write().await;
        *nick = settings.nickname.clone();
    }
    source_manager
        .write()
        .await
        .set_max_per_file(settings.max_sources_per_file);
    if settings.filter_servers_by_ip {
        apply_server_ip_filter(state, shared_server_addr, app_handle, true).await;
    }
}
