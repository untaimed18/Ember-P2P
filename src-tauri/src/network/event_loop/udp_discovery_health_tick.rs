//! The 30 s heartbeat: offers our relay attestations to live friend sessions,
//! and logs UDP source-discovery counters when they change.

use super::*;

pub(in crate::network) async fn on_udp_discovery_health_tick(
    state: &mut NetworkState,
    settings: &AppSettings,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    ed25519_pubkey: [u8; 32],
    ed25519_secret_key: [u8; 32],
    last_udp_discovery_health: &mut UdpDiscoveryHealthSnapshot,
) {
    // Forward what we know about relays to every live friend
    // session. This is the only channel that does not depend on
    // sharing a swarm with the peer, which is exactly the case the
    // relay broker starves in: attestations otherwise arrive only
    // on EPX exchanges for files already being traded, so two
    // friends alone together never accumulate any.
    //
    // Re-sent only when the set actually changes. A digest of the
    // offered attestation hashes is cheaper to compare than the
    // block and is stable across reorderings that carry no new
    // information, so a steady-state pair exchanges nothing.
    {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut offer = state
            .connection_broker
            .as_ref()
            .map(|b| b.gossipable_attestations(now_unix))
            .unwrap_or_default();
        // Lead with ourselves when we are usable as a relay. We
        // are never in our own candidate list — that only holds
        // relays learned from others — yet for a friend who has no
        // peers at all we may be the only relay they can reach,
        // and they cannot discover us any other way.
        if let Some(mine) = sign_local_relay_attestation(
            state,
            settings,
            &ed25519_secret_key,
            ed25519_pubkey,
        ) {
            // Register the hash before advertising it. A friend that
            // acts on this attestation presents its hash when dialling
            // us as a relay, and `accepts_attestation_hash` refuses
            // anything it was never told to expect. Signing mints a
            // fresh expiry each tick, so the hash differs every time
            // and the EPX path cannot cover it: without this the offer
            // advertised a relay that answers every taker with
            // REJECT_AUTH, and a node with no swarm traffic — the one
            // this feature is for — never registered a hash at all.
            let hash = ember::relay_attestation_hash(&mine);
            state
                .relay_manager
                .lock()
                .await
                .set_current_attestation_hash(hash, mine.expires_at_unix);
            offer.truncate(ember::MAX_RELAY_ATTESTATIONS.saturating_sub(1));
            offer.insert(0, mine);
        }
        if !offer.is_empty() {
            let digest = relay_offer_digest(&offer, now_unix);
            let body = ember::build_relay_attestation_block(&offer);
            let payload =
                ed2k::messages::build_ember_ext(
                    ed2k::messages::EMBER_EXT_RELAY_OFFER,
                    &body,
                );
            let mut packet = Vec::with_capacity(6 + payload.len());
            packet.push(OP_EMULEPROT);
            packet.extend_from_slice(&((1 + payload.len()) as u32).to_le_bytes());
            packet.push(ed2k::messages::OP_EMBER_EXT);
            packet.extend_from_slice(&payload);

            // Friends only, matching who the relay will actually
            // serve. `run_quic_accept_loop` admits a RELAY_REQUEST
            // only from a friend, so offering to every
            // authenticated session advertised a service that
            // answers `REJECT_AUTH` — and a rejected relay
            // candidate is one the requester spent a QUIC
            // handshake to discover was useless. The field name has
            // always said friends; the send did not.
            // Two sequential reads rather than one nested pair.
            // Holding a `friend_hashes` guard across an
            // `ember_sessions` acquisition would introduce a lock
            // order that no other site follows, and tokio's
            // `RwLock` is fair — a queued writer makes even
            // read-on-read nesting deadlockable if some other task
            // takes the two the other way round. Neither critical
            // section is long enough for the split to matter.
            let candidates: Vec<([u8; 16], u64, tokio::sync::mpsc::Sender<Vec<u8>>)> = {
                let sessions = state.ember_sessions.read().await;
                sessions
                    .iter()
                    .filter(|(_, h)| h.is_fresh() && h.is_secure_v2())
                    .map(|(eh, h)| (*eh, h.session_id(), h.tx.clone()))
                    .collect()
            };
            let live: Vec<([u8; 16], u64, tokio::sync::mpsc::Sender<Vec<u8>>)> = {
                let friends = friend_hashes.read().await;
                candidates
                    .into_iter()
                    .filter(|(eh, _, _)| friends.contains(eh))
                    .collect()
            };
            for (eh, session_id, tx) in live {
                if state.friend_relay_offer_sent.get(&eh)
                    == Some(&(session_id, digest))
                {
                    continue;
                }
                if tx.try_send(packet.clone()).is_ok() {
                    state
                        .friend_relay_offer_sent
                        .insert(eh, (session_id, digest));
                }
            }
        }
        // Prune outside the "we have something to offer" branch:
        // when every candidate expires at once the offer goes
        // empty, and skipping the sweep then would let entries for
        // departed friends accumulate for the life of the process
        // — the exact leak this guards against. Also ensures a
        // reconnecting friend is offered the set again.
        {
            let sessions = state.ember_sessions.read().await;
            state
                .friend_relay_offer_sent
                .retain(|eh, _| sessions.contains_key(eh));
        }
    }

    // Only the eD2K UDP-discovery diagnostics below are KAD-scoped.
    // The friend relay-offer work above must not be: `stats.status`
    // is advanced only by KAD paths, so an eD2K-only session (the
    // default) sits at `Disconnected` for its whole life — and this
    // gate then meant we never registered our own attestation hash,
    // so every friend that tried to use us as a relay was answered
    // with REJECT_AUTH, starving the one discovery channel that does
    // not need a shared swarm.
    if state.stats.status == NetworkStatus::Disconnected { return; }

    let cur = UdpDiscoveryHealthSnapshot {
        sent: state.udp_discovery_sent,
        send_errs: state.udp_discovery_send_errs,
        replies: state.udp_discovery_replies,
        sources_found: state.udp_discovery_sources_found,
    };
    let prev = *last_udp_discovery_health;
    let any_change = cur.sent != prev.sent
        || cur.send_errs != prev.send_errs
        || cur.replies != prev.replies
        || cur.sources_found != prev.sources_found;
    if any_change {
        let d_sent = cur.sent.saturating_sub(prev.sent);
        let d_errs = cur.send_errs.saturating_sub(prev.send_errs);
        let d_replies = cur.replies.saturating_sub(prev.replies);
        let d_sources = cur.sources_found.saturating_sub(prev.sources_found);
        // `ok` and `fail` are disjoint counts of the
        // **attempted** sends since the last beat (each
        // `send_to` call bumps exactly one). The totals
        // are cumulative since process start (each kind
        // separately). Earlier wording put them in the
        // same paren which read as "errs are a subset
        // of sent" — they aren't.
        info!(
            "UDP source-discovery health (30s): sends ok=+{d_sent} fail=+{d_errs} (totals ok={} fail={}), replies=+{d_replies} (total {}), sources_found=+{d_sources} (total {})",
            cur.sent, cur.send_errs,
            cur.replies,
            cur.sources_found,
        );

        // Per-server breakdown so the user can see which
        // entries in their server.met are actually
        // useful for source discovery. Three categories:
        //   * source-responsive: ever returned
        //     OP_GLOBFOUNDSOURCES (= actually has source
        //     data we can use). The good column.
        //   * status-only: responds to status pings but
        //     never to GETSOURCES — server is alive but
        //     doesn't index our specific file hashes.
        //     Most servers fall here for any given user
        //     because the long tail of file hashes is
        //     vast and individual servers index small
        //     subsets.
        //   * silent: never replied to anything.
        //   * pruned: > MAX_UDP_CONSECUTIVE_FAILURES
        //     consecutive unanswered queries.
        //
        // Previously this was one "alive" bucket which
        // misled readers into thinking source discovery
        // was working when servers were just answering
        // status pings.
        let now_ts = chrono::Utc::now().timestamp();
        let mut source_responsive: Vec<String> = Vec::new();
        let mut status_only: Vec<String> = Vec::new();
        let mut silent: Vec<String> = Vec::new();
        let mut pruned: Vec<String> = Vec::new();
        for s in state.server_list.servers().iter() {
            let label = if s.name.is_empty() {
                format!("{}:{}", s.ip, s.port)
            } else {
                format!("{} ({}:{})", s.name, s.ip, s.port)
            };
            if s.udp_consecutive_failures >= MAX_UDP_CONSECUTIVE_FAILURES {
                pruned.push(label);
            } else if s.last_udp_source_reply_at > 0 {
                let ago = (now_ts - s.last_udp_source_reply_at).max(0);
                source_responsive.push(format!("{label} (last sources {ago}s ago)"));
            } else if s.last_udp_reply_at > 0 {
                let ago = (now_ts - s.last_udp_reply_at).max(0);
                status_only.push(format!("{label} (status reply {ago}s ago, never returned sources)"));
            } else {
                silent.push(format!("{label} (fails={})", s.udp_consecutive_failures));
            }
        }
        info!(
            "UDP server health: {} source-responsive, {} status-only (alive but never returned sources), {} silent, {} pruned (>= {MAX_UDP_CONSECUTIVE_FAILURES} unanswered queries)",
            source_responsive.len(), status_only.len(), silent.len(), pruned.len(),
        );
        if !source_responsive.is_empty() {
            info!("UDP source-responsive servers: {}", source_responsive.join("; "));
        }
        if !status_only.is_empty() {
            info!("UDP status-only servers: {}", status_only.join("; "));
        }
        if !silent.is_empty() {
            info!("UDP silent servers: {}", silent.join("; "));
        }
        if !pruned.is_empty() {
            info!("UDP pruned servers (re-eligible on any inbound UDP): {}", pruned.join("; "));
        }
    }
    *last_udp_discovery_health = cur;
}
