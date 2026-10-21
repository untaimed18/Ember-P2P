//! Cleaning up flood-protection tracking and capping the peer nickname cache.

use super::*;

pub(in crate::network) async fn on_flood_cleanup_tick(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    banned_ips_sync_in_flight: &mut bool,
    banned_ips_sync_tx: &mpsc::UnboundedSender<Option<BannedIpsSyncInputs>>,
) {
    state.flood_protection.cleanup();

    // Disappearing messages, on this tick's half-minute so the shortest timer
    // is kept to within it. An open conversation hides each one at its exact
    // time on its own; this is what deletes it.
    let db_expire = db.clone();
    let expire_now = chrono::Utc::now().timestamp();
    match tokio::task::spawn_blocking(move || db_expire.expire_disappearing_chat(expire_now)).await {
        Ok(Ok(gone)) => {
            for (friend_hash, ids, xfer_ids) in gone {
                emit_chat_removed(app_handle, &friend_hash, &ids, &xfer_ids);
            }
        }
        Ok(Err(e)) => debug!("Disappearing-message sweep failed: {e}"),
        Err(e) => debug!("Disappearing-message sweep panicked: {e}"),
    }

    // Chat attachments nobody answered, on the same half-minute: an offer
    // lapses five minutes after it went, and an open conversation shows it
    // from its last update, which would otherwise still read "waiting".
    let db_attachments = db.clone();
    match tokio::task::spawn_blocking(move || db_attachments.expire_chat_attachments(expire_now)).await {
        Ok(Ok(expired)) => {
            for xfer_hex in expired {
                crate::network::chat_attach::emit_expired(app_handle, db, &xfer_hex);
            }
        }
        Ok(Err(e)) => debug!("Chat attachment expiry sweep failed: {e}"),
        Err(e) => debug!("Chat attachment expiry sweep panicked: {e}"),
    }
    crate::network::chat_attach::check_held_sources(state, db);
    crate::network::chat_attach::retry_owed_holds(state).await;

    // Prevent unbounded growth of peer_nicknames
    const MAX_NICKNAME_ENTRIES: usize = 500;
    if state.peer_nicknames.len() > MAX_NICKNAME_ENTRIES {
        let current_contacts: HashSet<KadId> = state.routing_table
            .all_contacts()
            .map(|c| c.id)
            .collect();
        state.peer_nicknames.retain(|id, _| current_contacts.contains(id));
    }

    // Expire overloaded node entries after 10 minutes
    let now = crate::network::monotonic_secs();
    state.overloaded_nodes.retain(|_, &mut ts| now - ts < 600);

    // Expire online_friends entries not seen in 5 minutes, but only
    // when no live Ember session is still fresh. Keepalives refresh
    // `EmberSessionHandle`, not this map, so a healthy idle session
    // must not flip the friend Offline / disable Browse.
    {
        let now = chrono::Utc::now().timestamp();
        let sessions = state.ember_sessions.read().await;
        let mut refresh = Vec::new();
        let mut expired = Vec::new();
        for (eh, &ts) in &state.online_friends {
            if now - ts < 300 {
                continue;
            }
            if sessions.get(eh).is_some_and(|h| h.is_fresh()) {
                refresh.push(*eh);
            } else {
                expired.push(*eh);
            }
        }
        drop(sessions);
        for eh in refresh {
            state.online_friends.insert(eh, now);
        }
        for eh in &expired {
            state.online_friends.remove(eh);
            let _ = app_handle.emit("ember:friend-offline", serde_json::json!({
                "user_hash": hex::encode(eh),
            }));
        }
    }

    // Cap banned_ips to prevent unbounded growth: rebuild from
    // durable sources + active reputation bans (same path as the
    // periodic reputation-timer sync). The rebuild is asynchronous
    // now, so the over-cap check moved to where the result is
    // applied.
    if state.banned_ips.len() > MAX_BANNED_IPS {
        request_banned_ips_sync(
            banned_ips_sync_in_flight,
            db,
            banned_ips_sync_tx,
        );
    }

    // Sweep orphaned Ember ping waiters. Each entry is created
    // when we send `EmberControlMessage::Ping` to a peer; the
    // entry is normally removed when the matching `Pong` lands
    // in `handle_udp_packet`. If the peer never replies (lost
    // packet, peer dropped, peer doesn't speak the protocol),
    // the entry would otherwise stay until process exit and
    // eventually saturate `MAX_EMBER_PENDING_PINGS=1024` so
    // no further pings could register. The awaiting caller's
    // own `tokio::time::timeout` already returned long ago by
    // the time `MAX_PING_AGE` elapses, so dropping the
    // oneshot here only frees backend memory — no
    // user-visible behaviour change.
    {
        const MAX_PING_AGE: std::time::Duration =
            std::time::Duration::from_secs(120);
        let now = std::time::Instant::now();
        let stale: Vec<u64> = state
            .ember_pending_pings
            .iter()
            .filter(|(_, (sent_at, _))| now.duration_since(*sent_at) >= MAX_PING_AGE)
            .map(|(nonce, _)| *nonce)
            .collect();
        if !stale.is_empty() {
            for nonce in &stale {
                state.ember_pending_pings.remove(nonce);
            }
            debug!(
                "Ember: swept {} orphaned pending ping(s) older than {}s",
                stale.len(),
                MAX_PING_AGE.as_secs(),
            );
        }

        // The dev-panel DHT harness has the same two maps and had
        // no sweep at all: `ember_dht_pending_pings` and
        // `ember_dht_pending_finds` were only ever drained by a
        // matching wire reply. Every probe that timed out — a peer
        // that never answered, or a send that only reached
        // `OutgoingResult::Queued` because the handshake never
        // completed, so nothing went on the wire to be answered —
        // left its entry behind. A thousand of those and
        // `MAX_EMBER_PENDING_PINGS` refuses every further DHT ping
        // and find for the rest of the run, which reads as the
        // dev panel being broken.
        let before = state.ember_dht_pending_pings.len()
            + state.ember_dht_pending_finds.len();
        state
            .ember_dht_pending_pings
            .retain(|_, (sent_at, _, _)| now.duration_since(*sent_at) < MAX_PING_AGE);
        state
            .ember_dht_pending_finds
            .retain(|_, (sent_at, _, _)| now.duration_since(*sent_at) < MAX_PING_AGE);
        let swept = before
            - (state.ember_dht_pending_pings.len()
                + state.ember_dht_pending_finds.len());
        if swept > 0 {
            debug!(
                "Ember: swept {swept} orphaned DHT harness waiter(s) older than {}s",
                MAX_PING_AGE.as_secs(),
            );
        }
    }

    // Reap idle Noise sessions and pending handshakes. The
    // documented TTLs in `EmberTransport::cleanup` (300s
    // session, 30s pending) were previously dead code — only
    // the absolute caps (`MAX_SESSIONS=4096`, `MAX_PENDING=512`)
    // bounded growth. Calling the sweep on the same 30s
    // cadence as flood-protection cleanup makes the TTL the
    // primary eviction signal again, so memory tracks live
    // peer activity instead of accumulating until the cap
    // forces eviction.
    state.ember_transport.cleanup();
}
