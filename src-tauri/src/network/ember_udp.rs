//! Ember native UDP ingress: filtering, dispatch, and control messages.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// IP-filter half of Ember UDP ingest.
///
/// Fail-closed (`enabled && !ranges_ready`) is for *strangers*. Contacts we
/// already hold, just dialled, or introduced over a live session must still
/// get their replies — otherwise `nodes_ember.dat` bootstrap pongs are dropped
/// for the whole `ipfilter.dat` parse and the overlay never rejoins. Once
/// ranges are ready, only a LAN/CGNAT session introduction may bypass a real
/// block (same as before).
///
/// `known_peer` and `session_introduced` read the routing table and the
/// session maps, so they are only asked when the verdict turns on them.
pub(super) fn ember_udp_ip_filter_allows(
    blocked: bool,
    fail_closed: bool,
    known_peer: impl FnOnce() -> bool,
    lan_or_cgnat: bool,
    session_introduced: impl FnOnce() -> bool,
) -> bool {
    if fail_closed {
        return known_peer() || session_introduced();
    }
    if blocked {
        return lan_or_cgnat && session_introduced();
    }
    true
}

/// The node ID of the verified contact behind the Noise session `session_key`
/// at `from`, if we hold one. An unverified gossip entry at the address names
/// whatever node ID its introducer chose, so crediting it would let a peer
/// charge its frames to someone else.
pub(super) fn verified_session_node_id(
    routing: &ember::dht::routing::RoutingTable,
    from: SocketAddr,
    session_key: &[u8; 32],
) -> Option<[u8; 16]> {
    routing
        .contact_at(from)
        .filter(|c| c.is_verified() && c.noise_pub == *session_key)
        .map(|c| c.node_id.0)
}

/// Security gate for inbound Ember-native UDP, mirroring the IP-filter +
/// ban-list + per-IP rate-limit checks `handle_udp_packet` applies to
/// KAD/eD2K traffic. The event loop's Ember fast-path dispatches *above*
/// `handle_udp_packet` (so Ember keeps working while KAD is disconnected),
/// so without running these checks here a peer could drive unbounded Noise
/// handshakes — pure CPU for us — straight past flood protection.
///
/// Returns `true` if the packet may be processed, `false` if it should be
/// dropped. Takes `&mut NetworkState` because the rate limiter records the
/// hit. IP-filter and ban-list are IPv4 structures: they're enforced for
/// any v4 / v4-mapped source, while a genuinely v6-only Ember peer skips
/// those two (they can't represent it) but is still rate-limited.
pub(super) fn ember_udp_recv_allowed(state: &mut NetworkState, from: SocketAddr) -> bool {
    // Both the IP filter and the rate limiter may ask; the answer cannot change
    // in between, so it is computed at most once per datagram.
    let mut ember_known = None;
    let mut ember_known_peer = |state: &NetworkState| {
        *ember_known.get_or_insert_with(|| ember_udp_is_known_peer(state, from))
    };
    if let Some(v4) = match from.ip() {
        std::net::IpAddr::V4(v4) => Some(v4),
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    } {
        if crate::security::is_bogus_v4(v4) {
            debug!("Dropping Ember UDP from blocked IP {from}");
            return false;
        }
        if state.banned_ips.contains(&v4) {
            debug!("Dropping Ember UDP from banned peer {from}");
            return false;
        }
        let fail_closed = state.ip_filter.is_enabled() && !state.ip_filter.ranges_ready();
        let blocked = !fail_closed && state.ip_filter.is_blocked_readonly(v4);
        if !ember_udp_ip_filter_allows(
            blocked,
            fail_closed,
            || ember_known_peer(state),
            crate::security::is_lan_or_cgnat_v4(v4),
            || ember_session_introduced(state, v4, from.port()),
        ) {
            debug!("Dropping Ember UDP from blocked IP {from}");
            return false;
        }
    }

    // Per-IP UDP rate limit on Ember's own window. Ember rides the KAD
    // socket, and while the two shared one counter an ordinary KAD exchange
    // with a dual-stack peer could spend the budget Ember needed to finish a
    // Noise handshake with that same peer, so it never became a DHT contact.
    // A contact already in the Ember or KAD table — or one we've recently
    // exchanged UDP with — is treated as "known" so the limiter gives it the
    // higher steady-state budget instead of the stricter stranger cap.
    let known_peer = match from.ip() {
        std::net::IpAddr::V4(v4) => {
            state.routing_table.has_contact_ip(v4)
                || state.flood_protection.has_recent_ip(from.ip())
                || ember_known_peer(state)
        }
        _ => state.flood_protection.has_recent_ip(from.ip()) || ember_known_peer(state),
    };
    if state
        .flood_protection
        .check_ember_rate_limit(from.ip(), known_peer)
    {
        debug!("Rate limit exceeded for Ember UDP from {from}, dropping packet");
        return false;
    }
    true
}

/// Drive `EmberTransport` for an inbound Ember-magic UDP packet,
/// send any side-effect packets back over the same socket, and
/// update diagnostics + the pending-ping registry. Pure transport
/// state-machine work lives in `EmberTransport::dispatch_incoming`
/// so it can be exercised by `cargo test` over loopback UDP without
/// constructing a `NetworkState`.
/// Panic-isolating wrapper around [`handle_ember_native_udp_inner`]. A panic
/// while processing one packet must never tear down the whole network event
/// loop (which would be a remote DoS), so we catch it, log it, and let the
/// loop continue with the next event.
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_ember_native_udp(
    socket: &UdpSocket,
    data: &[u8],
    from: SocketAddr,
    state: &mut NetworkState,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    local_index: &Arc<RwLock<LocalIndex>>,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
) {
    if let Err(p) = std::panic::AssertUnwindSafe(handle_ember_native_udp_inner(
        socket,
        data,
        from,
        state,
        transfer_manager,
        source_manager,
        local_index,
        db,
        app_handle,
        bandwidth_limiter,
    ))
    .catch_unwind()
    .await
    {
        error!(
            "Ember UDP handler panicked (recovered, network loop continues): {}",
            describe_panic(&*p)
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_ember_native_udp_inner(
    socket: &UdpSocket,
    data: &[u8],
    from: SocketAddr,
    state: &mut NetworkState,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    local_index: &Arc<RwLock<LocalIndex>>,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
) {
    let outcome = state.ember_transport.dispatch_incoming(data, from);

    if outcome.rejected {
        debug!("Ember transport rejected UDP packet from {from}");
        return;
    }

    // Classify the datagram after decrypt so EPX Exchange* does not land
    // in the Ember DHT row (and vice versa). Handshake-only packets and
    // transport Ping/Pong have no EPX control and no DHT app payload —
    // they are the cost of the Ember DHT channel, so they count as DHT.
    // A mixed datagram (DHT app + EPX control) is counted as DHT so the
    // same UDP packet is never billed twice.
    let is_epx = outcome.controls.iter().any(|c| {
        matches!(
            c,
            ember::transport::EmberControlMessage::ExchangeRequest
                | ember::transport::EmberControlMessage::ExchangeData { .. }
        )
    });
    if is_epx && outcome.app_payloads.is_empty() {
        state.epx_overhead.record_download(data.len() as u64);
    } else {
        state.ember_dht_overhead.record_download(data.len() as u64);
    }

    let reply_overhead = if is_epx && outcome.app_payloads.is_empty() {
        state.epx_overhead.clone()
    } else {
        state.ember_dht_overhead.clone()
    };
    for pkt in &outcome.responses {
        if let Err(e) = send_ember_udp(socket, pkt, from, &reply_overhead).await {
            debug!("Ember transport: failed to send packet to {from}: {e}");
        }
    }

    // DHT (and future Ember-native) frames ride the same Noise session
    // as the control Ping/Pong but are larger than the 10-byte control
    // frame, so the transport surfaces them here as `app_payloads` with
    // the peer's Noise key attached for the reply path.
    //
    // Plural because one datagram can yield more than one: an IK_INIT's
    // embedded request is withheld until the source address proves
    // routable, so it is released alongside whatever frame proved it.
    // Order is preserved within each list, but app payloads are drained
    // ahead of controls, so a deferred control released by a DHT frame is
    // handled after it. Nothing here depends on the relative order of the
    // two kinds.
    if let Some(remote_noise_pub) = outcome.remote_noise_pub {
        for payload in &outcome.app_payloads {
            handle_ember_dht_message(
                socket,
                payload,
                from,
                remote_noise_pub,
                state,
                db,
                app_handle,
                bandwidth_limiter,
            )
            .await;
        }
    }

    for control in outcome.controls {
        handle_ember_control_message(
            socket,
            control,
            from,
            outcome.remote_noise_pub,
            state,
            transfer_manager,
            source_manager,
            local_index,
        )
        .await;
    }
}

/// Handle one decoded Ember control frame.
///
/// Split out of `handle_ember_native_udp_inner` because a single datagram can
/// carry more than one: the frame that proves a source address routable also
/// releases whatever the peer's `IK_INIT` was holding. An early return has to
/// abandon just that frame, not the rest of the batch.
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_ember_control_message(
    socket: &UdpSocket,
    control: ember::transport::EmberControlMessage,
    from: SocketAddr,
    // Static key of the session that decrypted this frame. Always `Some` for a
    // decoded control frame: `dispatch_incoming` only produces controls from
    // `Message` / `HandshakeComplete`, both of which set it.
    remote_noise_pub: Option<[u8; 32]>,
    state: &mut NetworkState,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    local_index: &Arc<RwLock<LocalIndex>>,
) {
    use ember::transport::EmberControlMessage;

    match control {
        EmberControlMessage::Ping { .. } => {
            state.ember_diagnostics.ember_pings_received = state
                .ember_diagnostics
                .ember_pings_received
                .saturating_add(1);
        }
        EmberControlMessage::Pong { nonce } => {
            state.ember_diagnostics.ember_pongs_received = state
                .ember_diagnostics
                .ember_pongs_received
                .saturating_add(1);

            if let Some((sent_at, tx)) = state.ember_pending_pings.remove(&nonce) {
                let _ = tx.send(sent_at.elapsed());
            } else {
                debug!(
                    "Ember transport: Pong nonce {nonce} from {from} did not match a pending ping"
                );
            }
        }
        EmberControlMessage::ExchangeRequest => {
            // Scope both the authentication check and the reply to the session
            // that actually decrypted this request. Sessions are keyed by
            // `(addr, static key)` and several identities can hold slots at one
            // address, so the address-scoped check would let an XX peer borrow a
            // neighbour's IK, and an unkeyed `prepare_outgoing` would seal the
            // answer to whichever session sorts highest — not the asker.
            let Some(session_key) = remote_noise_pub else {
                debug!("ember-udp: EPX exchange request from {from} carried no session key");
                return;
            };
            if !state
                .ember_transport
                .session_is_ik_authenticated(&from, &session_key)
            {
                debug!(
                    "ember-udp: refusing EPX exchange request from unauthenticated XX session {from}"
                );
                return;
            }
            if !check_and_record_udp_epx_rate(&mut state.ember_udp_epx_req_rate, from) {
                debug!(
                    "ember-udp: rate-limiting EPX ExchangeRequest from {from} ({} per {:?} window)",
                    ember::MAX_EPX_PACKETS_PER_CONNECTION,
                    EPX_UDP_RATE_WINDOW,
                );
                return;
            }
            state.ember_diagnostics.ember_exchange_requests_received = state
                .ember_diagnostics
                .ember_exchange_requests_received
                .saturating_add(1);

            // Answer with the datagram-sized build of our EPX payload, not
            // the TCP one: `MAX_EPX_PAYLOAD` (64KB) assumes a stream, and a
            // UDP reply over that budget is dropped by the receiver before
            // decryption — which looks like a successful send here and like
            // silence there. `build_udp_exchange_payload` packs the same
            // entries to `MAX_EPX_UDP_PAYLOAD` instead, so a busy node sends
            // fewer files rather than nothing at all.
            let payload_arc = state.ember_udp_payload.clone();
            // The builder honours the budget, so this is a backstop against a
            // future change to the framing overhead rather than an expected
            // path. Counted, because silently skipping is exactly the failure
            // mode this replaced.
            if payload_arc.len() > ember::MAX_EPX_UDP_PAYLOAD {
                state.ember_diagnostics.epx_udp_oversized_skipped = state
                    .ember_diagnostics
                    .epx_udp_oversized_skipped
                    .saturating_add(1);
                debug!(
                    "ember-udp: EPX payload unexpectedly over the datagram budget ({} bytes > {} budget); skipping ExchangeData reply to {from}",
                    payload_arc.len(),
                    ember::MAX_EPX_UDP_PAYLOAD,
                );
                return;
            }
            if payload_arc.is_empty() {
                debug!(
                    "ember-udp: no EPX payload built yet; skipping ExchangeData reply to {from}"
                );
                return;
            }
            let msg = EmberControlMessage::ExchangeData {
                payload: (*payload_arc).clone(),
            }
            .encode();
            match state
                .ember_transport
                .prepare_outgoing(from, Some(&session_key), &msg)
            {
                ember::transport::OutgoingResult::Ready { packet } => {
                    if let Err(e) = send_ember_udp(socket, &packet, from, &state.epx_overhead).await
                    {
                        debug!("ember-udp: failed to send ExchangeData reply to {from}: {e}");
                    } else {
                        state.ember_diagnostics.ember_exchange_sent = state
                            .ember_diagnostics
                            .ember_exchange_sent
                            .saturating_add(1);
                    }
                }
                // The session is established (we just decrypted the
                // request), so anything other than Ready is unexpected —
                // log and drop rather than queue a stale reply.
                _ => {
                    debug!("ember-udp: no ready session to answer ExchangeRequest from {from}");
                }
            }
        }
        EmberControlMessage::ExchangeData { payload } => {
            // Session-scoped for the same reason as `ExchangeRequest`: the
            // sources in this payload are trusted as far as the sender's
            // authentication goes, so it must be the sender's own.
            let Some(session_key) = remote_noise_pub else {
                debug!("ember-udp: EPX ExchangeData from {from} carried no session key");
                return;
            };
            if !state
                .ember_transport
                .session_is_ik_authenticated(&from, &session_key)
            {
                debug!(
                    "ember-udp: refusing EPX ExchangeData from unauthenticated XX session {from}"
                );
                return;
            }
            if !check_and_record_udp_epx_rate(&mut state.ember_udp_epx_rate, from) {
                debug!(
                    "ember-udp: rate-limiting EPX ExchangeData from {from} ({} per {:?} window)",
                    ember::MAX_EPX_PACKETS_PER_CONNECTION,
                    EPX_UDP_RATE_WINDOW,
                );
                return;
            }
            state.ember_diagnostics.ember_exchange_received = state
                .ember_diagnostics
                .ember_exchange_received
                .saturating_add(1);

            // Reuse the exact eD2K-TCP EPX ingestion path so UDP-delivered
            // source/peer hints get the same validation, dedup, AICH
            // pinning, relay-attestation verification and mesh learning.
            match ember::parse_exchange_payload(&payload) {
                Ok(result)
                    if !result.files.is_empty()
                        || !result.peers.is_empty()
                        || !result.relay_attestations.is_empty() =>
                {
                    let (entries, aich_roots) = ed2k::transfer::epx_result_to_entries(&result);
                    let ember_peers: Vec<(Ipv4Addr, u16)> =
                        result.peers.iter().map(|p| (p.ip, p.tcp_port)).collect();
                    // The Noise session proves who we are talking to but
                    // carries no Ember identity, so any relay attestations are
                    // charged against the routing table's binding for this
                    // address. A peer we hold no contact for stays uncharged,
                    // bounded by the global relay-pool cap alone.
                    let from_ember_hash =
                        verified_session_node_id(state.ember_dht.routing(), from, &session_key);
                    let we_are_unreachable = state.firewalled || state.low_id;
                    let injected = handle_epx_sources(
                        state,
                        transfer_manager,
                        source_manager,
                        local_index,
                        &entries,
                        &aich_roots,
                        &ember_peers,
                        &result.relay_attestations,
                        from_ember_hash,
                        "ember-udp",
                        false,
                        we_are_unreachable,
                        &HashMap::new(),
                    )
                    .await;
                    debug!("ember-udp: ingested EPX from {from} ({injected} sources injected)");
                }
                Ok(_) => {
                    // Well-formed but empty (peer had nothing to share).
                }
                Err(e) => {
                    debug!("ember-udp: failed to parse EPX payload from {from}: {e}");
                }
            }
        }
    }
}
