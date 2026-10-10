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
    crate::storage::category_folders::set_folders(&new_settings.download_category_folders);
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
        // Ember shares the private-IP preference (though not the range
        // filter): both stacks dial peers from the same socket, so a contact
        // the user has blocked must be refused by whichever table would
        // otherwise hand it to us.
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
