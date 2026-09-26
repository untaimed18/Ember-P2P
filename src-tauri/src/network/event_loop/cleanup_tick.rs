//! The 5-minute cleanup tick: expires searches, DHT records and callback
//! expectations, sweeps queued chat and friend-request withdrawals, flushes
//! credits, and re-probes NAT when needed.

use super::*;

/// How often the queued-chat expiry sweep runs. The age ceiling it enforces
/// is measured in days, so this only has to be small relative to that.
const CHAT_EXPIRY_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60 * 60);
/// Withdrawal dials started per sweep. Cancelling a batch of requests at
/// once should not turn one tick into a burst of connects to peers that are
/// probably still offline; the rest are picked up on the next tick.
const MAX_RETRACTION_RETRIES_PER_SWEEP: usize = 4;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_cleanup_tick(
    udp_socket: &Arc<UdpSocket>,
    state: &mut NetworkState,
    settings: &AppSettings,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    credit_manager: &Arc<RwLock<CreditManager>>,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    ember_hash: [u8; 16],
    ul_event_tx: &mpsc::Sender<UploadEvent>,
    ed25519_pubkey: [u8; 32],
    ed25519_secret_key: [u8; 32],
    channel_queue_settled: &mut bool,
    channel_sweep_cutoff: i64,
    credit_flush_handle: &mut Option<tokio::task::JoinHandle<()>>,
    credit_save_ownership: &Arc<tokio::sync::Mutex<()>>,
    db_progress_last_persist: &mut HashMap<String, std::time::Instant>,
    last_chat_expiry_sweep: &mut Option<std::time::Instant>,
    nat_probe_in_flight: &mut bool,
    nat_probe_packet_tx: &mut Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>,
    nat_probe_result_tx: &mpsc::UnboundedSender<NatProbeResult>,
    nat_probe_started_at: &mut Option<tokio::time::Instant>,
    pending_kad_callbacks: &upload_server::PendingKadCallbacks,
) {
    // Deliberately not gated on KAD status. This sweep is the only
    // bound on `pending_udp_reasks` and `server_udp_source_reask_at`,
    // both of which are filled by server-driven source discovery
    // that needs no KAD at all — so in an eD2K-only session (which
    // never leaves `Disconnected`) they grew for the whole session.
    // Every step below is a no-op on empty KAD state.
    let (removed_sids, released_in_use) = state.search_manager.cleanup(120);
    finalize_removed_searches(state, app_handle, &removed_sids, &released_in_use);
    state.dht_store.cleanup_expired();
    // Same cadence for the Ember DHT's signed-record store. This is the
    // only periodic sweep of it, and being ungated matters: a store
    // restored at startup is swept even in a session where Ember never
    // comes up. Admission does not wait on this cadence — `DhtStore::store`
    // reclaims a key's lapsed records itself, or a key sitting at its cap
    // would refuse arrivals until the next sweep.
    let ember_expired = state.ember_dht.expire_records();
    if ember_expired > 0 {
        debug!("Ember DHT: expired {ember_expired} stored records");
    }

    // Prune the DB-progress throttle map so cancelled/removed
    // downloads (whose handles are gone) don't leave dead entries
    // accumulating for the lifetime of the session. Completed and
    // failed transfers are already pruned in handle_download_event;
    // this catches the cancel/pause paths that bypass it.
    db_progress_last_persist.retain(|tid, _| state.download_handles.contains_key(tid));

    // Drop expired inbound-callback expectations. UI placeholders
    // are managed separately by `source_retry_timer`.
    {
        let now = chrono::Utc::now().timestamp();
        let mut cbs = pending_kad_callbacks.lock().await;
        for entries in cbs.values_mut() {
            entries.retain(|e| now - e.registered_at < ed2k::dead_sources::PENDING_KAD_CALLBACK_SECS);
        }
        cbs.retain(|_, v| !v.is_empty());
    }

    // Drop friend bindings and request records for transfers that no
    // longer exist, so neither map accumulates over a long session.
    // Attempts below the retry ceiling are otherwise never removed
    // (the ceiling cleanup on source_retry_timer only fires at max
    // attempts), and a client that downloads from friends all day
    // would grow one entry per `(friend, file)` forever.
    {
        let mgr = transfer_manager.read().await;
        state
            .transfer_friend_hint
            .retain(|tid, _| mgr.get_transfer(tid).is_some());
        state
            .friend_xfer_attempts
            .retain(|_, attempt| mgr.get_transfer(&attempt.transfer_id).is_some());
    }

    // Forget neighbour-lookup throttle stamps once they can no
    // longer suppress a lookup. Keyed by remote member pubkey, so
    // this map grows with other people's room churn rather than
    // with anything the user does, and its sibling
    // `channel_neighbor_lookup_inflight` is already cleared on
    // completion. A stamp past its interval also keeps suppressing
    // nothing, so holding it only costs memory.
    {
        let now = std::time::Instant::now();
        state.channel_neighbor_lookup_at.retain(|_, at| {
            now.saturating_duration_since(*at) < CHANNEL_NEIGHBOR_LOOKUP_INTERVAL
        });
    }

    // Drop publish-ack counters for files no longer being
    // published. The field documents itself as reset at the start
    // of each source-publish cycle, but nothing ever removed an
    // entry, so a session that rotates shares accumulated one row
    // per file ever published — and the 60s source-count sync
    // probes this map once per shared file.
    // The Ember rendezvous advert is deliberately absent from the
    // publish record set, so it is kept by key.
    {
        let rendezvous_key = kad::publish::ember_rendezvous_key();
        let publish = &state.publish_manager;
        state
            .source_publish_acks
            .retain(|id, _| *id == rendezvous_key || publish.has_record(id));
    }

    // Forget inbound rate-limit stamps once they can no longer
    // reject anything.
    {
        let now = std::time::Instant::now();
        state.friend_xfer_inbound_last.retain(|_, last| {
            now.saturating_duration_since(*last).as_secs()
                < FRIEND_XFER_INBOUND_MIN_INTERVAL_SECS
        });
        state.friend_file_offer_seen.retain(|_, last| {
            now.saturating_duration_since(*last) < FRIEND_FILE_OFFER_MIN_INTERVAL
        });
    }

    // Abandon chat that has been queued past its age limit. Done on
    // a slow cadence from here rather than inside the flush, so a
    // conversation the user never reopens still resolves and the
    // queue, the badge and the message list cannot disagree about
    // the same row. Hourly: the ceiling is measured in days, and the
    // predicate scans `chat_messages`.
    if last_chat_expiry_sweep
        .map(|at: std::time::Instant| at.elapsed() >= CHAT_EXPIRY_SWEEP_INTERVAL)
        .unwrap_or(true)
    {
        *last_chat_expiry_sweep = Some(std::time::Instant::now());
        let db_expire = db.clone();
        match tokio::task::spawn_blocking(move || db_expire.expire_stale_queued_chat())
            .await
        {
            Ok(Ok(expired)) => emit_chat_delivery_failed(app_handle, &expired),
            Ok(Err(e)) => debug!("Queued-chat expiry sweep failed: {e}"),
            Err(e) => debug!("Queued-chat expiry sweep panicked: {e}"),
        }

        let db_attachments = db.clone();
        let now = chrono::Utc::now().timestamp();
        match tokio::task::spawn_blocking(move || db_attachments.expire_chat_attachments(now)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => debug!("Chat attachment expiry sweep failed: {e}"),
            Err(e) => debug!("Chat attachment expiry sweep panicked: {e}"),
        }

        // Same cadence, same reason: the ceiling is in days, and a
        // withdrawal nobody can deliver is holding the address of
        // someone the user removed.
        // A room line queued before this run started was left
        // mid-flight by a previous run: the retry that would have
        // settled it lived in memory and went with the process, so
        // nothing else will ever move it off "sending". Lines from
        // this run are left to the retry queue that holds them.
        if !*channel_queue_settled {
            *channel_queue_settled = true;
            let db_channel = db.clone();
            match tokio::task::spawn_blocking(move || {
                db_channel.fail_stale_queued_channel_messages(channel_sweep_cutoff)
            })
            .await
            {
                Ok(Ok(0)) => {}
                Ok(Ok(n)) => {
                    debug!("Marked {n} room line(s) left sending by a previous run")
                }
                Ok(Err(e)) => debug!("Stale channel-send sweep failed: {e}"),
                Err(e) => debug!("Stale channel-send sweep panicked: {e}"),
            }
        }

        let db_retract = db.clone();
        match tokio::task::spawn_blocking(move || {
            db_retract.expire_stale_friend_request_retractions()
        })
        .await
        {
            Ok(Ok(0)) => {}
            Ok(Ok(dropped)) => debug!(
                "Gave up on {dropped} undelivered friend-request withdrawal(s)"
            ),
            Ok(Err(e)) => debug!("Withdrawal expiry sweep failed: {e}"),
            Err(e) => debug!("Withdrawal expiry sweep panicked: {e}"),
        }

        // And the other direction, on the same ceiling: a refusal
        // nobody can deliver is holding the address of someone the
        // user declined to know.
        let db_decline = db.clone();
        match tokio::task::spawn_blocking(move || {
            db_decline.expire_stale_friend_request_declines()
        })
        .await
        {
            Ok(Ok(0)) => {}
            Ok(Ok(dropped)) => {
                debug!("Gave up on {dropped} undelivered friend-request decline(s)")
            }
            Ok(Err(e)) => debug!("Decline expiry sweep failed: {e}"),
            Err(e) => debug!("Decline expiry sweep panicked: {e}"),
        }
    }

    // Retry withdrawals whose peer was unreachable when the user
    // cancelled. Without this the request stays on their Friends
    // page for good simply because they happened to be offline at
    // that moment, which is the whole point of persisting the row.
    {
        let db_pending = db.clone();
        let pending = tokio::task::spawn_blocking(move || {
            db_pending.pending_friend_request_retractions()
        })
        .await
        .ok()
        .and_then(|rows| rows.ok())
        .unwrap_or_default();
        // Parse before taking, not after: a row whose hash will not
        // decode used to consume one of the attempt slots and starve
        // the deliverable rows behind it for as long as it sat there.
        // A missing address is no longer disqualifying, because the
        // rendezvous fallback can still find them.
        let deliverable = pending.into_iter().filter_map(|(hash_hex, ip, port)| {
            let target = hex::decode(&hash_hex)
                .ok()
                .and_then(|raw| <[u8; 16]>::try_from(raw.as_slice()).ok())?;
            let stored = ip
                .parse::<std::net::IpAddr>()
                .ok()
                .filter(|_| port > 0)
                .map(|ip| SocketAddr::new(ip, port));
            Some((hash_hex, target, stored))
        });
        for (hash_hex, target, stored) in
            deliverable.take(MAX_RETRACTION_RETRIES_PER_SWEEP)
        {
            tokio::spawn(deliver_friend_request_verdict(
                FriendRequestVerdict::Withdraw,
                db.clone(),
                settings.rendezvous_url.clone(),
                hash_hex,
                target,
                stored,
                state.user_hash,
                ember_hash,
                settings.nickname.clone(),
                state
                    .external_ip
                    .map(|eip| u32::from_le_bytes(eip.octets()))
                    .unwrap_or(0),
                advertised_tcp_port(state),
                advertised_udp_port(state),
                settings.friend_session_encryption,
                ed25519_pubkey,
                ed25519_secret_key,
            ));
        }
    }

    // The same retry for refusals. A request the user rejected
    // while its sender happened to be offline would otherwise stay
    // on that sender's screen for good, which is the state this
    // whole path exists to end.
    {
        let db_pending = db.clone();
        let pending = tokio::task::spawn_blocking(move || {
            db_pending.pending_friend_request_declines()
        })
        .await
        .ok()
        .and_then(|rows| rows.ok())
        .unwrap_or_default();
        let deliverable = pending.into_iter().filter_map(|(hash_hex, ip, port)| {
            let target = hex::decode(&hash_hex)
                .ok()
                .and_then(|raw| <[u8; 16]>::try_from(raw.as_slice()).ok())?;
            let stored = ip
                .parse::<std::net::IpAddr>()
                .ok()
                .filter(|_| port > 0)
                .map(|ip| SocketAddr::new(ip, port));
            Some((hash_hex, target, stored))
        });
        for (hash_hex, target, stored) in
            deliverable.take(MAX_RETRACTION_RETRIES_PER_SWEEP)
        {
            tokio::spawn(deliver_friend_request_verdict(
                FriendRequestVerdict::Decline,
                db.clone(),
                settings.rendezvous_url.clone(),
                hash_hex,
                target,
                stored,
                state.user_hash,
                ember_hash,
                settings.nickname.clone(),
                state
                    .external_ip
                    .map(|eip| u32::from_le_bytes(eip.octets()))
                    .unwrap_or(0),
                advertised_tcp_port(state),
                advertised_udp_port(state),
                settings.friend_session_encryption,
                ed25519_pubkey,
                ed25519_secret_key,
            ));
        }
    }

    // Disarm the punch serve role once the punch that justified it
    // can no longer arrive. A stale entry would make a later
    // *social* punch from the same friend wrongly take the serve
    // role, and both sides would wait on each other's Hello.
    {
        let now = std::time::Instant::now();
        state.friend_xfer_punch_serve.retain(|_, accepted| {
            now.saturating_duration_since(*accepted).as_secs()
                < FRIEND_XFER_PUNCH_SERVE_TTL_SECS
        });
    }

    // Reconcile the inbound friend expectations against the requests
    // that justify them. An orphan would otherwise keep diverting a
    // late connect-back into a download that no longer exists until
    // its own TTL lapsed.
    {
        let live: HashSet<([u8; 16], [u8; 16])> =
            state.friend_xfer_attempts.keys().copied().collect();
        let mut cbs = pending_kad_callbacks.lock().await;
        reconcile_friend_pending_callbacks(&mut cbs, &live);
    }

    // Prune stale outbound session tasks (older than 10 minutes)
    {
        let now = std::time::Instant::now();
        state.outbound_session_tasks.retain(|_, started| now.duration_since(*started).as_secs() < 600);
    }

    // Sweep `ember_sessions` for entries that have gone stale
    // (see `EmberSessionHandle::is_fresh`) but were never
    // touched by an insert-time eviction because nothing
    // happened to try reusing them — e.g. a friend nobody
    // chatted with or browsed after their connection died
    // silently. Without this sweep such an entry sits in the
    // map (harmlessly, since every consumer already checks
    // freshness) until something finally races to reclaim the
    // slot; proactively clearing it here just keeps
    // `GetOnlineFriends`-adjacent map state tidy and bounds it
    // to genuinely live sessions between friend-search bursts.
    {
        let hashes: Vec<[u8; 16]> = state.ember_sessions.read().await.keys().copied().collect();
        for h in hashes {
            upload_server::evict_stale_ember_session(&state.ember_sessions, &h).await;
        }
    }

    // Prune the server UDP source-reask throttle map. Once an entry is
    // older than the reask interval it no longer throttles anything
    // (the next ask just re-inserts it), so dropping it bounds the map
    // instead of letting it grow one entry per (server, file_hash) for
    // the entire session.
    {
        let now = chrono::Utc::now().timestamp();
        state
            .server_udp_source_reask_at
            .retain(|_, last| now.saturating_sub(*last) < SERVER_UDP_SOURCE_REASK_SECS);
    }

    // Bound `pending_udp_reasks`. Entries are removed when the matching
    // OP_REASKACK arrives, but sources that never ack (firewalled,
    // offline, or address-spoofed) would otherwise accumulate one entry
    // per (ip, udp_port) for the entire session. Cap the table; a dropped
    // entry only means a single reask goes unmatched and the source is
    // re-asked on the next reask cycle (~seconds later).
    {
        const MAX_PENDING_UDP_REASKS: usize = 4096;
        if state.pending_udp_reasks.len() > MAX_PENDING_UDP_REASKS {
            // Oldest-first: an ack normally arrives within a few
            // round-trip seconds of the reask being sent, so an
            // entry surviving past this age is almost certainly a
            // source that will never ack (dead/firewalled) rather
            // than one about to. Evicting by age instead of
            // clearing the whole table preserves correlation for
            // every reask sent in roughly the last reask cycle.
            const MAX_PENDING_UDP_REASK_AGE_SECS: i64 = 30;
            let now = chrono::Utc::now().timestamp();
            state
                .pending_udp_reasks
                .retain(|_, (_, sent_at)| now.saturating_sub(*sent_at) < MAX_PENDING_UDP_REASK_AGE_SECS);
            // Pathological fallback: if a flood of reasks was sent
            // inside the same age window and age-based eviction
            // couldn't bring the table back under budget, fall
            // back to the old behavior rather than growing
            // unbounded.
            if state.pending_udp_reasks.len() > MAX_PENDING_UDP_REASKS {
                state.pending_udp_reasks.clear();
            }
        }
    }

    // (broker.tick() and broker event drain are now handled
    // by their own 200 ms `broker_timer` arm — the 5-minute
    // cadence here was longer than PUNCH_TIMEOUT/RELAY_TIMEOUT
    // and effectively disabled hole-punch + LowID-to-LowID.)

    // Clean up expired relay sessions
    {
        let mut relay_mgr = state.relay_manager.lock().await;
        let expired = relay_mgr.cleanup();
        if !expired.is_empty() {
            tracing::debug!("Relay cleanup: expired {} sessions", expired.len());
        }
    }

    // (broker event drain moved to its own 200ms `broker_timer`
    // arm — see below. Leaving it on cleanup_timer's 5-min
    // cadence made every queued punch/relay event obsolete
    // before it was ever processed.)

    // Periodic NAT reprobe (every 5 minutes)
    if state.nat_info.needs_reprobe()
        && state.external_ip.is_some()
        && mapping_probe_has_active_reason(state)
    {
        if !*nat_probe_in_flight {
            *nat_probe_in_flight = true;
            *nat_probe_started_at = Some(tokio::time::Instant::now());
            state.nat_probe_generation =
                state.nat_probe_generation.saturating_add(1);
            *nat_probe_packet_tx = Some(spawn_nat_probe(
                udp_socket.clone(),
                nat_probe_result_tx.clone(),
                state.nat_probe_generation,
                "periodic reprobe",
            ));
        }
    }

    // Auto-retry offline friends via rendezvous for the
    // entire session. First 30 min: every tick (5 min).
    // After that: every other tick (10 min) to reduce load.
    if let Some(started) = state.friend_search_started_at {
        let elapsed = std::time::Instant::now().duration_since(started).as_secs();
        let should_retry = if elapsed <= 1800 {
            true
        } else {
            (elapsed / 300).is_multiple_of(2)
        };
        if should_retry {
            let all_friends: Vec<[u8; 16]> = friend_hashes.read().await.iter().copied().collect();
            let sessions = state.ember_sessions.read().await;

            let mut retry_targets: Vec<[u8; 16]> = Vec::new();
            for fh in &all_friends {
                if state.online_friends.contains_key(fh) { continue; }
                if sessions.get(fh).is_some_and(|h| h.is_fresh()) { continue; }
                if state.outbound_session_tasks.contains_key(fh) { continue; }
                retry_targets.push(*fh);
            }
            drop(sessions);

            if !retry_targets.is_empty() {
                info!("Friend auto-retry ({:.0}s since connect): looking up {} offline friend(s) via rendezvous",
                    elapsed as f64, retry_targets.len());
            }
            for target_hash in retry_targets.iter().take(10) {
                state.outbound_session_tasks.insert(*target_hash, std::time::Instant::now());
                let _ = app_handle.emit("ember:friend-searching", serde_json::json!({
                    "user_hash": hex::encode(target_hash),
                }));
                spawn_rendezvous_friend_lookup(
                    settings, state, ember_hash, *target_hash,
                    app_handle, friend_hashes, ul_event_tx,
                    ed25519_pubkey, ed25519_secret_key,
                );
            }
        }
    }

    // Prune stale outbound session tasks (older than 10 minutes)
    {
        let mut sm = source_manager.write().await;
        sm.cleanup_expired();
    }

    // Request a stale-credit prune/flush (older than 90 days).
    // L6: previously this only mutated
    // the in-memory map; the next `credit_save_timer` tick
    // (up to 60 s away) was the only thing that wrote the
    // pruned snapshot back. A crash inside that window
    // would lose the prune (the DB still held the stale
    // rows, which got reloaded into memory on next start),
    // and any operator who'd correlated metrics off the
    // pruned in-memory count would see them re-appear. The
    // periodic flush still runs; serialized ownership prevents
    // this request from overlapping an existing writer.
    if credit_flush_handle.as_ref().is_some_and(|handle| handle.is_finished()) {
        if let Some(handle) = credit_flush_handle.take() {
            if let Err(e) = handle.await {
                warn!("Credit cleanup flush task failed: {e}");
            }
        }
    }
    if credit_flush_handle.is_none() {
        *credit_flush_handle = Some(spawn_credit_flush(
            credit_manager.clone(),
            db.clone(),
            state.data_dir.clone(),
            true,
            credit_save_ownership.clone(),
        ));
    } else {
        debug!("Deferring credit cleanup flush: a save is already in flight");
    }

    // Remove contacts not seen in 2 hours
    let stale_removed = state.routing_table.remove_stale(7200);
    if stale_removed > 0 {
        debug!("Removed {stale_removed} stale contacts from routing table");
        state.stats.connected_peers = state.routing_table.len() as u32;
    }

    let now = chrono::Utc::now().timestamp();
    // Collect stale per-(target, peer) entries, then dedupe by
    // file_hash so we reset publish_manager at most once per
    // file regardless of how many peers we had outstanding.
    let stale_keys: Vec<((KadId, SocketAddr), KadId, bool)> = state.publish_pending
        .iter()
        .filter(|(_, (_, sent_at, _, _))| now - sent_at > 120)
        .map(|(k, (file_hash, _, is_source, _))| (*k, *file_hash, *is_source))
        .collect();
    let mut retried_files: std::collections::HashSet<(KadId, bool)> = std::collections::HashSet::new();
    for (key, file_hash, is_source) in &stale_keys {
        state.publish_pending.remove(key);
        // Skip stale-retry bookkeeping if any peer for this file
        // has already succeeded (file_hash still in
        // publish_pending under a different key → recently acked).
        // The dedupe set covers the common "all peers timed out"
        // path.
        if retried_files.insert((*file_hash, *is_source)) {
            if *is_source {
                state.publish_manager.reset_source_publish(file_hash);
            } else {
                state
                    .publish_manager
                    .reset_keyword_target_publish(file_hash);
            }
            debug!("Retrying unconfirmed publish for target {} (peer {})", key.0, key.1);
        }
    }
}
