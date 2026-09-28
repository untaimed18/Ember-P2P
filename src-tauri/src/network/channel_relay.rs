//! Channel neighbor discovery, hole-punching, and relayed channel sessions.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// Result of a background rendezvous lookup for a channel gossip neighbor.
/// Applied on the 1s stats tick so we do not add another `select!` arm
/// (the loop is already at tokio's 64-branch ceiling). Never writes
/// `friend_hashes`.
pub(super) struct ChannelNeighborLookupResult {
    pub(super) peer_pubkey: [u8; 32],
    pub(super) channel_id: [u8; 16],
    pub(super) endpoint: Option<(Ipv4Addr, u16)>,
}

/// Channel-scoped WebSocket relay events. Drained on the stats tick.
pub(super) enum ChannelRelayEvent {
    Opened {
        peer_pubkey: [u8; 32],
        /// Which session this is. See [`ChannelRelayEvent::Closed`].
        session_id: u64,
        outbound_tx: mpsc::Sender<Vec<u8>>,
    },
    Frame {
        peer_pubkey: [u8; 32],
        body: Vec<u8>,
        /// Counts this frame against its session until the event is dropped.
        _queued: QueuedRelayFrame,
    },
    Closed {
        peer_pubkey: [u8; 32],
        /// The session that ended, so its close cannot evict a newer one.
        ///
        /// This carried only the peer, and the handler removed whatever outbox
        /// was registered for it. Two sessions to one peer overlap routinely —
        /// both sides run `maybe_offer_channel_relay` over the same roster, so
        /// a mutual simultaneous offer is the normal case, and the duplicate
        /// guard reads a map that is not populated until `Opened` arrives,
        /// which is after up to ~55s of ticket negotiation. The result was
        /// deterministic rather than racy: session B registers, session A dies,
        /// A's close deletes *B's* outbox, and B's reader and socket stay alive
        /// so inbound frames keep arriving while every send is silently
        /// discarded. That peer is one-way for the rest of the session, and the
        /// map now undercounts, so `MAX_CHANNEL_RELAY_SESSIONS` can be exceeded
        /// by zombies.
        session_id: u64,
    },
}

/// Sends [`ChannelRelayEvent::Closed`] however a session task ends.
///
/// The task has several early returns — a ticket that is never accepted, a
/// WebSocket that will not connect, a handshake that times out — and none of
/// them used to report anything, so the peer stayed marked as negotiating with
/// nothing to clear it. A guard covers those, the normal end, and a panic.
pub(super) struct ChannelRelaySessionGuard {
    pub(super) event_tx: mpsc::UnboundedSender<ChannelRelayEvent>,
    pub(super) peer_pubkey: [u8; 32],
    pub(super) session_id: u64,
}

impl Drop for ChannelRelaySessionGuard {
    fn drop(&mut self) {
        let _ = self.event_tx.send(ChannelRelayEvent::Closed {
            peer_pubkey: self.peer_pubkey,
            session_id: self.session_id,
        });
    }
}

/// Frames one relay session may pass to the event loop per second: the most
/// the loop's own per-hop admission could take from that peer, transfer
/// allowance included. The loop still applies the exact check; this one runs
/// before anything is queued, so a peer sending faster costs a dropped buffer
/// rather than a growing queue.
pub(super) const CHANNEL_RELAY_FRAMES_PER_SEC: usize =
    ember::channel::CHANNEL_GOSSIP_IN_PER_PEER_PER_SEC
        + ember::channel::CHANNEL_XFER_IN_PER_PEER_PER_SEC;

/// Frames one session may have queued for the event loop and not yet had
/// applied. The loop drains relay events once a tick, so a second's worth is
/// what an honest peer can have waiting; past it, a loop that has fallen
/// behind sheds new frames instead of holding them.
pub(super) const CHANNEL_RELAY_FRAMES_QUEUED_MAX: usize = CHANNEL_RELAY_FRAMES_PER_SEC;

/// One frame a relay session has queued for the event loop. Dropping it,
/// which happens once the loop has applied the event, releases its place.
pub(super) struct QueuedRelayFrame(Arc<std::sync::atomic::AtomicUsize>);

impl QueuedRelayFrame {
    fn new(queued: &Arc<std::sync::atomic::AtomicUsize>) -> Self {
        queued.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Self(queued.clone())
    }
}

impl Drop for QueuedRelayFrame {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// Whether a relay session may queue one more inbound frame now, given the
/// frames it has admitted this second and how many still wait on the loop.
pub(super) fn relay_frame_admissible(
    admitted: &mut VecDeque<std::time::Instant>,
    queued: usize,
    now: std::time::Instant,
) -> bool {
    queued < CHANNEL_RELAY_FRAMES_QUEUED_MAX
        && ember::channel::rate_window_allow(
            admitted,
            now,
            CHANNEL_GOSSIP_RATE_WINDOW,
            CHANNEL_RELAY_FRAMES_PER_SEC,
        )
}

/// Process-wide source of relay session ids. Monotonic, so a stale close can
/// always be told from a live one.
pub(super) fn next_channel_relay_session_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

pub(super) async fn maybe_dial_channel_neighbors(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Database,
    settings: &AppSettings,
    ember_hash: [u8; 16],
    our_pubkey: [u8; 32],
    our_secret: [u8; 32],
    result_tx: &mpsc::UnboundedSender<ChannelNeighborLookupResult>,
) {
    if !settings.ember_native_enabled || db.chat_locked() {
        return;
    }
    if settings.rendezvous_url.is_empty() {
        return;
    }
    // The per-peer gates that decide whether any lookup actually happens are
    // evaluated *after* the roster read below, so a pass that starts nothing
    // still paid for up to `CHANNEL_RENDEZVOUS_MAX_CHANNELS`
    // `list_channel_members` queries — blocking `rusqlite` behind one
    // `Mutex<Connection>`, run directly on the Tokio worker driving the network
    // `select!`, contending with every `spawn_blocking` writer including
    // `wal_checkpoint(TRUNCATE)` and `VACUUM`. Driven at 1 Hz against a 30s
    // per-peer retry, ~29 of every 30 passes were exactly that. Back off after
    // an idle pass; `CHANNEL_NEIGHBOR_IDLE_RESCAN` is far below the retry
    // interval, so a newly joined member is still picked up promptly.
    let now = std::time::Instant::now();
    if state
        .channel_neighbor_scan_after
        .is_some_and(|resume_at| now < resume_at)
    {
        return;
    }
    let Some(roster) = channels_lite_cached(state, db) else {
        return;
    };
    // Same beat the registration used, so we dial neighbors in the rooms this
    // heartbeat actually published us for rather than a different slice.
    let beat = state.rendezvous_published_beat;
    let Ok(neighbors) =
        collect_channel_neighbor_caps(db, &roster, &our_pubkey, state.channel_focused, beat)
    else {
        return;
    };
    let mut started = 0usize;
    let mut find_nodes = 0usize;
    let mut pending_find = Vec::new();
    let punch = state.external_ip.map(|ip| (ip, advertised_udp_port(state), state.nat_info.nat_type.as_u8()));
    for (channel_id, peer_pubkey) in neighbors {
        if started >= CHANNEL_NEIGHBOR_LOOKUPS_PER_TICK {
            break;
        }
        if state.channel_neighbor_lookup_inflight.contains(&peer_pubkey) {
            continue;
        }
        if state
            .channel_neighbor_lookup_at
            .get(&peer_pubkey)
            .is_some_and(|at| now.saturating_duration_since(*at) < CHANNEL_NEIGHBOR_LOOKUP_INTERVAL)
        {
            continue;
        }
        let node_id = ember::dht::EmberNodeId(ember::channel::channel_id_from_pubkey(&peer_pubkey));
        if state.ember_dht.routing().get_contact(&node_id).is_some() {
            continue;
        }
        state.channel_neighbor_lookup_at.insert(peer_pubkey, now);
        state.channel_neighbor_lookup_inflight.insert(peer_pubkey);
        spawn_channel_neighbor_lookup(
            settings.rendezvous_url.clone(),
            ember_hash,
            our_pubkey,
            our_secret,
            peer_pubkey,
            channel_id,
            punch,
            result_tx.clone(),
        );
        started += 1;
        if find_nodes < CHANNEL_NEIGHBOR_FIND_NODE_PER_TICK {
            if let Some(search_id) = state
                .ember_search
                .start_background_find_node(node_id, state.ember_dht.routing())
            {
                find_nodes += 1;
                pending_find.push(search_id);
            }
        }
    }
    // A pass that dialled someone keeps scanning every tick so the rest of the
    // candidate set is picked up without waiting; one that found nothing to do
    // would find nothing to do next second either.
    state.channel_neighbor_scan_after = if started > 0 {
        None
    } else {
        Some(now + CHANNEL_NEIGHBOR_IDLE_RESCAN)
    };
    for search_id in pending_find {
        drive_ember_search(socket, state, search_id).await;
    }
}

pub(super) fn spawn_channel_neighbor_lookup(
    rv_url: String,
    our_ember_hash: [u8; 16],
    our_pubkey: [u8; 32],
    our_secret: [u8; 32],
    peer_pubkey: [u8; 32],
    channel_id: [u8; 16],
    punch: Option<(Ipv4Addr, u16, u8)>,
    result_tx: mpsc::UnboundedSender<ChannelNeighborLookupResult>,
) {
    tokio::spawn(async move {
        let mut endpoint = rendezvous::lookup_channel_presence(
            &rv_url,
            &our_ember_hash,
            &our_pubkey,
            &our_secret,
            &peer_pubkey,
            &channel_id,
        )
        .await
        .ok()
        .flatten();
        if endpoint.is_none() {
            if let Some((ip, port, nat_type)) = punch {
                endpoint = punch_channel_neighbor(
                    &rv_url,
                    our_ember_hash,
                    our_pubkey,
                    our_secret,
                    peer_pubkey,
                    channel_id,
                    ip,
                    port,
                    nat_type,
                )
                .await;
            }
        }
        let _ = result_tx.send(ChannelNeighborLookupResult {
            peer_pubkey,
            channel_id,
            endpoint,
        });
    });
}

/// Coordinated UDP punch keyed by the channel presence capability.
/// Advertises the Ember UDP port (not QUIC). Does not ack punches whose
/// capability belongs to a friend slot.
pub(super) async fn punch_channel_neighbor(
    rendezvous_url: &str,
    our_ember_hash: [u8; 16],
    our_pubkey: [u8; 32],
    our_secret: [u8; 32],
    peer_pubkey: [u8; 32],
    channel_id: [u8; 16],
    advertised_ip: Ipv4Addr,
    port: u16,
    nat_type: u8,
) -> Option<(Ipv4Addr, u16)> {
    if port == 0 {
        return None;
    }
    let ts = rendezvous::current_timestamp();
    let epoch = ember::crypto::pairwise_capability_epoch(ts);
    let register_cap = ember::channel::derive_channel_presence_capability(
        &our_secret,
        &peer_pubkey,
        &peer_pubkey,
        &channel_id,
        epoch,
    )?;
    let expected_cap = ember::channel::derive_channel_presence_capability(
        &our_secret,
        &peer_pubkey,
        &our_pubkey,
        &channel_id,
        epoch,
    )?;
    let peer_hash = ember::channel::channel_id_from_pubkey(&peer_pubkey);
    let expected_from = rendezvous::hashed_id(&peer_hash);
    if ember::relay::register_punch_with_capability(
        rendezvous_url,
        &our_ember_hash,
        &peer_hash,
        register_cap,
        epoch,
        port,
        nat_type,
        IpAddr::V4(advertised_ip),
        &our_secret,
    )
    .await
    .is_err()
    {
        return None;
    }
    for _ in 0..CHANNEL_PUNCH_POLL_ATTEMPTS {
        tokio::time::sleep(CHANNEL_PUNCH_POLL_INTERVAL).await;
        match ember::relay::poll_punch(rendezvous_url, &our_ember_hash, &our_secret).await {
            Ok(Some(info)) => {
                if info.from_id != expected_from || info.capability != expected_cap {
                    continue;
                }
                let Ok(IpAddr::V4(ip)) = info.ip.parse::<IpAddr>() else {
                    let _ = ember::relay::ack_punch(
                        rendezvous_url,
                        &our_ember_hash,
                        &info.punch_id,
                        &info.capability,
                        info.epoch,
                        &our_secret,
                    )
                    .await;
                    continue;
                };
                if crate::security::is_special_use_v4(ip) || info.port == 0 {
                    let _ = ember::relay::ack_punch(
                        rendezvous_url,
                        &our_ember_hash,
                        &info.punch_id,
                        &info.capability,
                        info.epoch,
                        &our_secret,
                    )
                    .await;
                    continue;
                }
                let _ = ember::relay::ack_punch(
                    rendezvous_url,
                    &our_ember_hash,
                    &info.punch_id,
                    &info.capability,
                    info.epoch,
                    &our_secret,
                )
                .await;
                return Some((ip, info.port));
            }
            Ok(None) => {}
            Err(e) => {
                debug!("Ember channel punch poll error: {e}");
            }
        }
    }
    None
}

pub(super) async fn apply_channel_neighbor_lookup(
    socket: &UdpSocket,
    state: &mut NetworkState,
    result: ChannelNeighborLookupResult,
    settings: &AppSettings,
    ember_hash: [u8; 16],
    our_pubkey: [u8; 32],
    our_secret: [u8; 32],
    relay_event_tx: &mpsc::UnboundedSender<ChannelRelayEvent>,
) {
    state
        .channel_neighbor_lookup_inflight
        .remove(&result.peer_pubkey);
    if let Some((ip, port)) = result.endpoint {
        if !(state.external_ip == Some(ip) && port == advertised_udp_port(state)) {
            // Channel peers resolve over Ember UDP and must never enter the
            // friend-privilege set. This path only DHT-PINGs.
            let addr = SocketAddr::new(IpAddr::V4(ip), port);
            let noise = state
                .ember_channel_noise_keys
                .get(&result.peer_pubkey)
                .copied();
            if let Some(noise_pub) = noise {
                state
                    .ember_noise_keys
                    .insert((ip, port), (noise_pub, std::time::Instant::now()));
            }
            ping_ember_udp_peer(socket, state, addr, noise.as_ref()).await;
            return;
        }
    }
    maybe_offer_channel_relay(
        state,
        settings,
        ember_hash,
        our_pubkey,
        our_secret,
        result.peer_pubkey,
        result.channel_id,
        relay_event_tx,
    );
}

pub(super) async fn ping_ember_udp_peer(
    socket: &UdpSocket,
    state: &mut NetworkState,
    addr: SocketAddr,
    noise_pub: Option<&[u8; 32]>,
) {
    let (_rid, frame) = state.ember_dht.build_ping();
    match state
        .ember_transport
        .prepare_outgoing(addr, noise_pub, &frame)
    {
        ember::transport::OutgoingResult::Ready { packet }
        | ember::transport::OutgoingResult::HandshakeStarted { packet } => {
            if let Err(e) = socket.send_to(&packet, addr).await {
                debug!("Ember channel neighbor: ping to {addr} failed: {e}");
            }
        }
        ember::transport::OutgoingResult::Queued => {}
        ember::transport::OutgoingResult::Error(e) => {
            debug!("Ember channel neighbor: transport error pinging {addr}: {e}");
        }
    }
}

pub(super) const CHANNEL_RELAY_OFFER_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
pub(super) const CHANNEL_RELAY_WS_MAGIC: &[u8; 4] = b"ECR1";
pub(super) const MAX_CHANNEL_RELAY_SESSIONS: usize = 8;
/// How long a relay counterpart has to exchange the 4-byte magic once the
/// WebSocket upgrade completes.
///
/// Bounded because everything a session costs is claimed on the far side of
/// it: one of [`MAX_CHANNEL_RELAY_SESSIONS`] outbox slots, and on the
/// responder path one `friend_relay_ticket_sessions_in_flight` entry that is
/// only released after the session returns. A peer that upgrades and then
/// says nothing used to hold both for the life of the process.
pub(super) const CHANNEL_RELAY_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub(super) fn maybe_offer_channel_relay(
    state: &mut NetworkState,
    settings: &AppSettings,
    ember_hash: [u8; 16],
    our_pubkey: [u8; 32],
    our_secret: [u8; 32],
    peer_pubkey: [u8; 32],
    channel_id: [u8; 16],
    relay_event_tx: &mpsc::UnboundedSender<ChannelRelayEvent>,
) {
    if settings.rendezvous_url.is_empty() {
        return;
    }
    // Pending counts as a session for both guards below. It is the whole point:
    // negotiation takes up to ~55 seconds, and reading only the outbox map left
    // that window open for a second session to the same peer — and for the cap
    // to be exceeded by sessions that had not registered yet.
    if state.channel_relay_outboxes.contains_key(&peer_pubkey)
        || state.channel_relay_pending.contains(&peer_pubkey)
    {
        return;
    }
    if state.channel_relay_outboxes.len() + state.channel_relay_pending.len()
        >= MAX_CHANNEL_RELAY_SESSIONS
    {
        return;
    }
    let now = std::time::Instant::now();
    if state
        .channel_relay_offer_at
        .get(&peer_pubkey)
        .is_some_and(|at| now.saturating_duration_since(*at) < CHANNEL_RELAY_OFFER_INTERVAL)
    {
        return;
    }
    state.channel_relay_offer_at.insert(peer_pubkey, now);
    state.channel_relay_pending.insert(peer_pubkey);
    let rv_url = settings.rendezvous_url.clone();
    let peer_hash = ember::channel::channel_id_from_pubkey(&peer_pubkey);
    let event_tx = relay_event_tx.clone();
    let session_id = next_channel_relay_session_id();
    tokio::spawn(async move {
        // Clears `channel_relay_pending` on every exit below, including the
        // ticket and handshake failures that return without ever opening.
        let _session = ChannelRelaySessionGuard {
            event_tx: event_tx.clone(),
            peer_pubkey,
            session_id,
        };
        let offer = match rendezvous::offer_channel_relay_ticket(
            &rv_url,
            &ember_hash,
            &peer_hash,
            &our_pubkey,
            &our_secret,
            &channel_id,
        )
        .await
        {
            Ok(offer) => offer,
            Err(e) => {
                debug!("Ember channel relay offer failed: {e}");
                return;
            }
        };
        let deadline = tokio::time::Instant::now() + rendezvous::FRIEND_RELAY_TICKET_INITIATOR_WAIT;
        let mut delay = std::time::Duration::from_secs(1);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                debug!("Ember channel relay ticket was not accepted before timeout");
                return;
            }
            tokio::time::sleep(remaining.min(delay)).await;
            match rendezvous::friend_relay_ticket_accepted(
                &rv_url,
                &ember_hash,
                &offer.ticket_id,
                &our_secret,
            )
            .await
            {
                Ok(true) => break,
                Ok(false) => delay = std::time::Duration::from_secs(1),
                Err(e) => {
                    if rendezvous::is_transient_relay_ticket_read_error(&e) {
                        delay = (delay * 2).min(std::time::Duration::from_secs(5));
                        continue;
                    }
                    debug!("Ember channel relay ticket status failed: {e}");
                    return;
                }
            }
        }
        match ember::relay::connect_server_relay(&rv_url, &offer.ticket_id, &offer.initiator_token)
            .await
        {
            Ok(ws) => run_channel_relay_session(ws, peer_pubkey, session_id, event_tx).await,
            Err(e) => debug!("Ember channel relay join failed: {e}"),
        }
    });
}

pub(super) async fn run_channel_relay_session(
    ws: ember::relay::WsStream,
    peer_pubkey: [u8; 32],
    session_id: u64,
    event_tx: mpsc::UnboundedSender<ChannelRelayEvent>,
) {
    let (mut reader, mut writer) = tokio::io::split(ws);

    // Handshake first, under a deadline, and only then announce the outbox.
    //
    // Announcing it first meant a counterpart that completed the WebSocket
    // upgrade and then went silent parked here forever holding a session slot
    // and (on the responder path) an in-flight ticket, because `Closed` is
    // only sent from paths this one never reached. Worse, room messages were
    // `try_send` into that outbox and counted as delivered while nothing was
    // ever going to read them — the exact failure the delivery accounting
    // exists to prevent. Nothing is claimed until the peer has proved it
    // speaks this protocol, so giving up here has nothing to release.
    let handshake = tokio::time::timeout(CHANNEL_RELAY_HANDSHAKE_TIMEOUT, async {
        writer.write_all(CHANNEL_RELAY_WS_MAGIC).await?;
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic).await?;
        if magic != *CHANNEL_RELAY_WS_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "channel relay magic mismatch",
            ));
        }
        Ok(())
    })
    .await;
    match handshake {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            debug!("Ember channel relay handshake failed: {e}");
            return;
        }
        Err(_) => {
            debug!("Ember channel relay handshake timed out");
            return;
        }
    }

    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(32);
    if event_tx
        .send(ChannelRelayEvent::Opened {
            peer_pubkey,
            session_id,
            outbound_tx,
        })
        .is_err()
    {
        return;
    }

    // Framing lives in its own task, for the reason `upload.rs` spells out at
    // its own reader: a frame is a 4-byte length prefix followed by a body,
    // and `read_exact` is not cancellation-safe. Racing it directly against
    // `outbound_rx.recv()` in an unbiased `select!` meant that a prefix split
    // across reads — which `WsStream::poll_read` produces whenever a frame
    // straddles a WebSocket frame boundary, since it returns `Ready` after a
    // partial fill — lost the bytes already consumed the moment the write arm
    // won the race. The next iteration then read a length from the middle of a
    // frame: usually nonsense that killed the session, otherwise a plausible
    // figure that left the stream permanently misaligned. Whole bodies arrive
    // over a channel here, which is trivially cancel-safe.
    let (frame_tx, mut frame_rx) = mpsc::channel::<Vec<u8>>(4);
    let reader_task = tokio::spawn(async move {
        let mut len_buf = [0u8; 4];
        loop {
            if reader.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            if len == 0 || len > ember::dht::messages::MAX_DHT_PAYLOAD {
                break;
            }
            let mut body = vec![0u8; len];
            if reader.read_exact(&mut body).await.is_err() {
                break;
            }
            if frame_tx.send(body).await.is_err() {
                break;
            }
        }
    });

    let queued = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut admitted: VecDeque<std::time::Instant> = VecDeque::new();
    let mut shed = 0u64;
    loop {
        tokio::select! {
            body = outbound_rx.recv() => {
                let Some(body) = body else { break; };
                if body.len() > ember::dht::messages::MAX_DHT_PAYLOAD {
                    continue;
                }
                let len = (body.len() as u32).to_le_bytes();
                if writer.write_all(&len).await.is_err() || writer.write_all(&body).await.is_err() {
                    break;
                }
            }
            // `None` once the reader task has stopped, which is how a closed
            // or desynced stream ends the session now that the read no longer
            // happens here.
            frame = frame_rx.recv() => {
                let Some(body) = frame else { break; };
                let waiting = queued.load(std::sync::atomic::Ordering::Acquire);
                if !relay_frame_admissible(&mut admitted, waiting, std::time::Instant::now()) {
                    shed += 1;
                    continue;
                }
                if event_tx
                    .send(ChannelRelayEvent::Frame {
                        peer_pubkey,
                        body,
                        _queued: QueuedRelayFrame::new(&queued),
                    })
                    .is_err()
                {
                    break;
                }
            }
        }
    }
    reader_task.abort();
    if shed > 0 {
        debug!("Ember channel relay: shed {shed} inbound frame(s) over the session budget");
    }
    // `Closed` is sent by `ChannelRelaySessionGuard` as this task unwinds, so
    // that every exit path reports — not only this one.
}

pub(super) async fn apply_channel_relay_event(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    event: ChannelRelayEvent,
) {
    match event {
        ChannelRelayEvent::Opened {
            peer_pubkey,
            session_id,
            outbound_tx,
        } => {
            state.channel_relay_pending.remove(&peer_pubkey);
            state
                .channel_relay_outboxes
                .insert(peer_pubkey, (session_id, outbound_tx));
        }
        ChannelRelayEvent::Closed {
            peer_pubkey,
            session_id,
        } => {
            state.channel_relay_pending.remove(&peer_pubkey);
            // Only if this is the session that registered it. A close from an
            // older, overlapping session must not take the live one's outbox
            // with it.
            if state
                .channel_relay_outboxes
                .get(&peer_pubkey)
                .is_some_and(|(registered, _)| *registered == session_id)
            {
                state.channel_relay_outboxes.remove(&peer_pubkey);
            }
        }
        ChannelRelayEvent::Frame { peer_pubkey, body, .. } => {
            let from_id =
                ember::dht::EmberNodeId(ember::channel::channel_id_from_pubkey(&peer_pubkey));
            handle_inbound_channel_gossip(
                socket,
                state,
                db,
                app_handle,
                body,
                from_id,
                HopMetering::Charge,
            )
            .await;
        }
    }
}

pub(super) fn ember_has_live_session(
    state: &NetworkState,
    contact: &ember::dht::EmberContact,
) -> bool {
    state
        .ember_transport
        .has_live_session(&contact.addr, &contact.noise_pub)
}

#[cfg(test)]
mod relay_frame_budget_tests {
    use super::{
        relay_frame_admissible, QueuedRelayFrame, CHANNEL_RELAY_FRAMES_PER_SEC,
        CHANNEL_RELAY_FRAMES_QUEUED_MAX,
    };
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// A neighbour sending faster than the loop could ever admit from it is
    /// shed at the session, and the budget comes back as the window rolls.
    #[test]
    fn a_session_admits_at_most_its_rate_per_second() {
        let mut admitted = VecDeque::new();
        let now = Instant::now();
        let taken = (0..CHANNEL_RELAY_FRAMES_PER_SEC * 3)
            .filter(|_| relay_frame_admissible(&mut admitted, 0, now))
            .count();
        assert_eq!(taken, CHANNEL_RELAY_FRAMES_PER_SEC);
        assert!(relay_frame_admissible(&mut admitted, 0, now + Duration::from_millis(1_100)));
    }

    /// Frames still waiting on a loop that has fallen behind stop the session
    /// queuing more, whatever the rate allows, until they are applied.
    #[test]
    fn a_session_stops_queuing_while_the_loop_holds_a_backlog() {
        let queued = Arc::new(AtomicUsize::new(0));
        let backlog: Vec<QueuedRelayFrame> = (0..CHANNEL_RELAY_FRAMES_QUEUED_MAX)
            .map(|_| QueuedRelayFrame::new(&queued))
            .collect();
        let mut admitted = VecDeque::new();
        assert!(!relay_frame_admissible(
            &mut admitted,
            queued.load(Ordering::Acquire),
            Instant::now()
        ));
        drop(backlog);
        assert_eq!(queued.load(Ordering::Acquire), 0);
        assert!(relay_frame_admissible(&mut admitted, 0, Instant::now()));
    }
}
