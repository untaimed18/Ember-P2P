//! The 1 s statistics tick: records transfer rates, keeps the Statistics cache
//! in step, and applies work that finished off the loop (download digests,
//! enforced-ban rebuilds, part hashsets, channel neighbor lookups and relay
//! events).

use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_stats_tick(
    udp_socket: &Arc<UdpSocket>,
    state: &mut NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    settings: &AppSettings,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    stats_manager: &mut StatsManager,
    known_files: &mut KnownFileList,
    shared_banned_ips: &upload_server::SharedBannedIps,
    ember_hash: [u8; 16],
    ed25519_pubkey: [u8; 32],
    ed25519_secret_key: [u8; 32],
    banned_ips_sync_in_flight: &mut bool,
    banned_ips_sync_rx: &mut mpsc::UnboundedReceiver<Option<BannedIpsSyncInputs>>,
    channel_neighbor_lookup_rx: &mut mpsc::UnboundedReceiver<ChannelNeighborLookupResult>,
    channel_neighbor_lookup_tx: &mpsc::UnboundedSender<ChannelNeighborLookupResult>,
    channel_relay_event_rx: &mut mpsc::UnboundedReceiver<ChannelRelayEvent>,
    channel_relay_event_tx: &mpsc::UnboundedSender<ChannelRelayEvent>,
    ember_digest_result_rx: &mut mpsc::UnboundedReceiver<([u8; 16], [u8; 32])>,
    part_hashset_result_rx: &mut mpsc::UnboundedReceiver<([u8; 16], Vec<[u8; 16]>)>,
    shared_ip_filter: &kad::ip_filter::SharedIpFilter,
    shared_transfer_stats: &Arc<RwLock<TransferStats>>,
) {
    // Fold in any completed-download BLAKE3 digests finished on the
    // blocking pool since the last tick, so the file can be
    // published to the Ember DHT and verified on later transfers.
    // Drained here rather than in its own `select!` arm because
    // this loop is already at tokio's 64-branch ceiling.
    while let Ok((digest_hash, digest)) = ember_digest_result_rx.try_recv() {
        // Hashed from the completed bytes on this disk, so it
        // outranks any DHT claim about the same file.
        seed_ember_content_hash(
            &mut state.ember_content_hashes,
            digest_hash,
            digest,
            EmberDigestProvenance::Local,
        );
        let digest_hex = hex::encode(digest);
        if let Some(record) = known_files.find_by_hash_mut(&digest_hash) {
            if record.ember_file_hash != digest_hex {
                record.ember_file_hash = digest_hex.clone();
                known_files.mark_dirty();
            }
        }
        let hash_hex = hex::encode(digest_hash);
        let changed = {
            let mut index = local_index.write().await;
            index.set_ember_file_hash_by_hash(&hash_hex, &digest_hex)
        };
        if changed {
            debug!("Ember digest for {hash_hex} computed after completion");
        }
    }
    // Apply any enforced-ban rebuild whose DB reads finished on the
    // blocking pool. A failed read arrives as `None` and keeps the
    // current set (fail-closed) rather than wiping bans.
    while let Ok(inputs) = banned_ips_sync_rx.try_recv() {
        *banned_ips_sync_in_flight = false;
        if let Some((peers, auto_bans)) = inputs {
            let before = state.banned_ips.len();
            {
                let sm = source_manager.read().await;
                apply_enforced_banned_ips(
                    state,
                    shared_banned_ips,
                    peers,
                    auto_bans,
                    &sm,
                );
            }
            if state.banned_ips.len() > MAX_BANNED_IPS {
                warn!(
                    "banned_ips still over cap after sync ({} → {}); durable sources exceed MAX_BANNED_IPS",
                    before,
                    state.banned_ips.len()
                );
            }
        }
    }
    // Same deal for ed2k part hashsets recomputed after a
    // completion that arrived without one: the record is written
    // immediately with an empty hashset and patched here, so
    // `known.met` gains the parts needed to serve the file without
    // the completion path having blocked on the read.
    while let Ok((hashset_hash, part_hashes)) = part_hashset_result_rx.try_recv() {
        if let Some(record) = known_files.find_by_hash_mut(&hashset_hash) {
            if record.part_hashes != part_hashes {
                record.part_hashes = part_hashes;
                known_files.mark_dirty();
                debug!(
                    "ed2k hashset for {} computed after completion",
                    hex::encode(hashset_hash)
                );
            }
        }
    }
    while let Ok(lookup) = channel_neighbor_lookup_rx.try_recv() {
        apply_channel_neighbor_lookup(
            udp_socket,
            state,
            lookup,
            settings,
            ember_hash,
            ed25519_pubkey,
            ed25519_secret_key,
            channel_relay_event_tx,
        )
        .await;
    }
    while let Ok(event) = channel_relay_event_rx.try_recv() {
        apply_channel_relay_event(
            udp_socket,
            state,
            db,
            app_handle,
            event,
        )
        .await;
    }
    if settings.ember_native_enabled {
        maybe_dial_channel_neighbors(
            udp_socket,
            state,
            db,
            settings,
            ember_hash,
            ed25519_pubkey,
            ed25519_secret_key,
            channel_neighbor_lookup_tx,
        )
        .await;
        // Driven from the one-second tick rather than the minute
        // one it used to share with DHT maintenance. Its own
        // per-room gates decide when a walk actually happens, and
        // on the slow tick the shorter of those gates could not
        // mean anything: a room we are alone in asks every twenty
        // seconds, which a sixty-second caller rounds up to sixty
        // whatever the constant says.
        maybe_refresh_channel_members(udp_socket, state, db, settings).await;
        // On the same tick and for the same reason: the beat is
        // tens of seconds, which a minute-granularity caller cannot
        // express. Its own per-room gate decides when one is due.
        maybe_beat_channel_presence(udp_socket, state, db, settings).await;
        // Ahead of the emit, so a member heard from during this
        // tick is reported on this tick rather than the next.
        flush_channel_member_touches(state, db);
        emit_channel_presence_deltas(state, app_handle);
        maybe_sync_channel_history(udp_socket, state, db, settings).await;
        drain_channel_origin_retry(udp_socket, state, db).await;
        // After the drain, so a verdict reached on this tick is
        // reported on this tick rather than the next.
        flush_channel_delivery_notes(state, db, app_handle).await;
    }
    stats_manager.session_down_counter.store(bandwidth_limiter.total_downloaded(), std::sync::atomic::Ordering::Relaxed);
    stats_manager.session_up_counter.store(bandwidth_limiter.total_uploaded(), std::sync::atomic::Ordering::Relaxed);
    // Fold lock-free SX / file-request / EPX / Ember-DHT
    // bytes into their Statistics-page categories. Without
    // this drain, those rows only show traffic recorded
    // directly on the network loop (server packets, KAD
    // recv) and read zero for peer TCP / Ember UDP.
    stats_manager.drain_sx_counters();
    stats_manager.record_rate(chrono::Utc::now().timestamp());
    // Keep the Statistics IPC cache in lock-step with the 1s rate
    // tick. The heavy 5s cache refresh can skip while a prior write
    // is still running; without this, the page lagged several
    // seconds behind StatsManager under load.
    {
        let snap = stats_manager.get_stats();
        *shared_transfer_stats.write().await = snap;
    }
    state.ip_filter.collect_shared_hits(shared_ip_filter);
    for (transfer_id, injected, remaining) in drain_active_source_overflow(state) {
        debug!(
            "Drained {} overflow source(s) for active download {}, {} remaining queued",
            injected,
            transfer_id,
            remaining
        );
    }
    let (health_updates, speed_resets) = {
        let mut mgr = transfer_manager.write().await;
        mgr.refresh_health(chrono::Utc::now().timestamp())
    };
    for update in &health_updates {
        emit_transfer_health(app_handle, update);
    }
    for sr in &speed_resets {
        let _ = app_handle.emit(
            "transfer-speed-decay",
            serde_json::json!({
                "id": sr.id,
                "speed": 0,
            }),
        );
    }
}
