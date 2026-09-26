//! Channel gossip: dedupe and rate limits, fan-out and inbound handling,
//! edits, reactions, handoff messages, and history sync.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;
use crate::storage::database::ChannelHandoffCommitOutcome;

pub(super) const CHANNEL_GOSSIP_RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);

pub(super) fn remember_channel_gossip(state: &mut NetworkState, msg_id: [u8; 16]) -> bool {
    ember::channel::remember_gossip_id(
        &mut state.channel_gossip_seen,
        &mut state.channel_gossip_seen_order,
        ember::channel::CHANNEL_GOSSIP_SEEN_CAP,
        msg_id,
        std::time::Instant::now(),
    )
}

pub(super) fn channel_author_gossip_ok(
    state: &mut NetworkState,
    channel_id: [u8; 16],
    author: &[u8; 32],
) -> bool {
    ember::channel::author_gossip_allow(
        &mut state.channel_gossip_author_times,
        channel_id,
        author,
        std::time::Instant::now(),
    )
}

pub(super) fn channel_history_sync_ok(
    state: &mut NetworkState,
    channel_id: [u8; 16],
    author: &[u8; 32],
) -> bool {
    ember::channel::history_sync_allow(
        &mut state.channel_history_sync_times,
        channel_id,
        author,
        std::time::Instant::now(),
    )
}

pub(super) fn forget_channel_gossip(state: &mut NetworkState, msg_id: &[u8; 16]) {
    ember::channel::forget_gossip_id(
        &mut state.channel_gossip_seen,
        &mut state.channel_gossip_seen_order,
        msg_id,
    );
}

/// Whether the roster already holds this member, unbanned.
///
/// What a frame opened under a retired key needs before anything in it is
/// kept: such a frame can refresh a member, never introduce one.
pub(super) fn channel_member_on_roster(
    state: &mut NetworkState,
    db: &Database,
    channel_id: [u8; 16],
    member: &[u8; 32],
) -> bool {
    channel_member_status_cached(state, db, channel_id, member) == Some(false)
}

pub(super) fn channel_member_banned(
    state: &mut NetworkState,
    db: &Database,
    channel_id: [u8; 16],
    member: &[u8; 32],
) -> bool {
    channel_member_status_cached(state, db, channel_id, member) == Some(true)
}

/// Most delivery verdicts held between ticks.
///
/// The drain runs once a second, so this only fills if something is
/// originating faster than the tick. A full buffer is flushed on the spot
/// rather than trimmed: nothing refreshes a verdict once it is dropped, so a
/// line that had reached the room stayed queued and the next start's sweep
/// marked it failed — inviting the user to send it a second time.
pub(super) const CHANNEL_DELIVERY_NOTE_CAP: usize = 256;

/// Note what became of an originated line, for the tick to persist and emit.
///
/// Buffered rather than written here because the fanout path holds neither the
/// `AppHandle` the event needs nor a place to await a blocking write — and
/// threading both through every caller of `fanout_channel_gossip_retry` to
/// record one integer would be a far larger change than the fact deserves.
pub(super) fn note_channel_delivery(
    state: &mut NetworkState,
    channel_id: [u8; 16],
    msg_id: [u8; 16],
    delivery: i64,
) {
    if state.channel_delivery_notes.len() >= CHANNEL_DELIVERY_NOTE_CAP {
        let (db, app_handle) = state.channel_delivery_sink.clone();
        let notes: Vec<([u8; 16], [u8; 16], i64)> =
            std::mem::take(&mut state.channel_delivery_notes).into();
        tokio::spawn(async move {
            write_channel_delivery_notes(notes, &db, &app_handle).await;
        });
    }
    state
        .channel_delivery_notes
        .push_back((channel_id, msg_id, delivery));
}

/// Persist buffered delivery verdicts and tell the UI about the ones that moved.
pub(super) async fn flush_channel_delivery_notes(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
) {
    if state.channel_delivery_notes.is_empty() {
        return;
    }
    let notes: Vec<([u8; 16], [u8; 16], i64)> =
        std::mem::take(&mut state.channel_delivery_notes).into();
    write_channel_delivery_notes(notes, db, app_handle).await;
}

pub(super) async fn write_channel_delivery_notes(
    notes: Vec<([u8; 16], [u8; 16], i64)>,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
) {
    let db_write = db.clone();
    let written = tokio::task::spawn_blocking(move || {
        let mut moved = Vec::new();
        for (channel_id, msg_id, delivery) in notes {
            let channel_hex = hex::encode(channel_id);
            match db_write.set_channel_delivery(&channel_hex, &hex::encode(msg_id), delivery) {
                // `None` is the ordinary case for a line already in that
                // state, or one the user has since removed locally.
                Ok(Some(row_id)) => moved.push((channel_hex, row_id, delivery)),
                Ok(None) => {}
                Err(e) => warn!("Could not record channel delivery in {channel_hex}: {e}"),
            }
        }
        moved
    })
    .await
    .unwrap_or_default();
    for (channel_id, id, delivery) in written {
        let label = crate::storage::database::Database::delivery_label(delivery);
        let _ = app_handle.emit(
            "ember:channel-delivery",
            serde_json::json!({
                "channel_id": channel_id,
                "id": id,
                "delivery": label,
            }),
        );
    }
}

pub(super) fn queue_channel_origin_retry(
    state: &mut NetworkState,
    body: Vec<u8>,
    queued_at: std::time::Instant,
) {
    while state.channel_origin_retry.len() >= ember::channel::CHANNEL_ORIGIN_RETRY_CAP {
        // Evicted means never retried, so say so rather than leave the row
        // reading "sending" until the next start's sweep.
        let Some((_, evicted)) = state.channel_origin_retry.pop_front() else {
            break;
        };
        if let Some(gossip) = ember::channel::ChannelGossip::decode(&evicted) {
            note_channel_delivery(
                state,
                gossip.channel_id,
                gossip.msg_id,
                crate::storage::database::CHAT_FAILED,
            );
        }
    }
    state
        .channel_origin_retry
        .push_back((queued_at, body));
}

pub(super) async fn drain_channel_origin_retry(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
) {
    if state.channel_origin_retry.is_empty() {
        return;
    }
    let pending = std::mem::take(&mut state.channel_origin_retry);
    let now = std::time::Instant::now();
    let ttl = std::time::Duration::from_secs(ember::channel::CHANNEL_ORIGIN_RETRY_SECS);
    // Decided once per room per pass. What a queue is almost always waiting
    // on is a room with nobody else in it, and every body queued there would
    // otherwise walk the whole fanout to learn that again, once a second for
    // up to ten minutes.
    let mut alone: HashMap<[u8; 16], bool> = HashMap::new();
    for (queued_at, body) in pending {
        let gossip = ember::channel::ChannelGossip::decode(&body);
        if now.saturating_duration_since(queued_at) >= ttl {
            // Ten minutes of finding nobody. This is the state that used to
            // vanish silently, leaving the sender a line their room never had.
            if let Some(gossip) = gossip {
                note_channel_delivery(
                    state,
                    gossip.channel_id,
                    gossip.msg_id,
                    crate::storage::database::CHAT_FAILED,
                );
            }
            continue;
        }
        if let Some(gossip) = gossip {
            let room_alone = match alone.get(&gossip.channel_id) {
                Some(known) => *known,
                None => {
                    let known = channel_room_is_empty_but_us(state, db, gossip.channel_id);
                    alone.insert(gossip.channel_id, known);
                    known
                }
            };
            if room_alone {
                queue_channel_origin_retry(state, body, queued_at);
                continue;
            }
        }
        fanout_channel_gossip_retry(socket, state, db, body, None, Some(queued_at)).await;
    }
}

/// A room we are in whose fresh roster names nobody but us — the case in which
/// the fanout would only queue the frame again. Anything else, including a
/// room we have left, is for the fanout to settle.
fn channel_room_is_empty_but_us(state: &mut NetworkState, db: &Database, channel_id: [u8; 16]) -> bool {
    let in_room = cached_channel_view(state, db, channel_id).is_some_and(|view| view.row.in_room_now());
    if !in_room {
        return false;
    }
    let local = state.local_ed25519_pubkey;
    channel_member_pubkeys_cached(state, db, channel_id)
        .iter()
        .all(|pk| *pk == local)
}

/// Admit one outbound fanout, against the bucket that fits where it came from.
///
/// A relay is charged the shared allowance, which is what stops this node
/// amplifying a flood. Something the user typed is charged its own, so a room
/// busy enough to spend the relay budget cannot silently swallow their message.
/// Failed origination is queued and retried; unbounded sending would still
/// turn a send loop into an outbound flood with no ceiling at all.
pub(super) fn channel_gossip_rate_ok(state: &mut NetworkState, local_origin: bool) -> bool {
    let (times, limit) = if local_origin {
        (
            &mut state.channel_gossip_local_times,
            ember::channel::CHANNEL_GOSSIP_LOCAL_PER_SEC,
        )
    } else {
        (
            &mut state.channel_gossip_sent_times,
            ember::channel::CHANNEL_GOSSIP_OUT_PER_SEC,
        )
    };
    ember::channel::rate_window_allow(
        times,
        std::time::Instant::now(),
        CHANNEL_GOSSIP_RATE_WINDOW,
        limit,
    )
}

/// Whether the per-hop admission bucket has already been charged for this
/// datagram further up the call chain.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum HopMetering {
    /// First time this node has handled the frame — charge the hop.
    Charge,
    /// The relay envelope carrying it was charged to the same hop already.
    /// Charging the inner frame too bills one datagram twice, which halved
    /// what a firewalled member — the whole reason the relay path exists —
    /// was allowed to receive.
    AlreadyCharged,
}

/// How a hop's Ember Transfer allowance is attributed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum XferAttribution {
    /// The hop speaks for itself — a direct Noise session, or a per-peer
    /// WebSocket relay whose outbox is already keyed by the peer. Only a
    /// transfer running with *them* earns the allowance.
    Hop,
    /// The hop is forwarding for somebody else. The inner frame is sealed, so
    /// the real sender cannot be known here; any live transfer earns the
    /// allowance, because a relayed one necessarily arrives from a hop that is
    /// not its peer. Still bounded — `XFER_MAX_ACTIVE` transfers per direction,
    /// each flow-controlled by the receiver's own outstanding window.
    Relayed,
}

/// True when an Ember Transfer is live with the peer behind this hop, or with
/// anyone at all when the hop is only forwarding.
///
/// Bounded by `XFER_MAX_ACTIVE` per direction, so this walks at most a handful
/// of entries.
pub(super) fn channel_xfer_active_with(
    state: &NetworkState,
    from_id: &ember::dht::EmberNodeId,
    attribution: XferAttribution,
) -> bool {
    let is_peer = |peer: &[u8; 32]| {
        attribution == XferAttribution::Relayed
            || ember::channel::channel_id_from_pubkey(peer) == from_id.0
    };
    state.xfer_recv.values().any(|s| is_peer(&s.peer))
        || state.xfer_send.values().any(|s| is_peer(&s.peer))
}

/// Admit one inbound channel frame from a DHT hop, or shed it.
///
/// Shedding here is deliberately **not** scored against the peer. Tripping our
/// own bucket is not evidence of misbehaviour — most often it is the far end
/// doing exactly what the protocol told it to — and scoring it meant a
/// `ProtocolViolation` (-20) per refused frame against a -200 ban threshold,
/// so ten shed frames earned an honest neighbor a 24-hour ban. Reputation is
/// for frames that are malformed or forged, which the decode and signature
/// checks downstream already catch.
pub(super) fn channel_gossip_inbound_ok(
    state: &mut NetworkState,
    from_id: &ember::dht::EmberNodeId,
    attribution: XferAttribution,
) -> bool {
    let now = std::time::Instant::now();
    if state.channel_gossip_from_times.len() >= ember::channel::CHANNEL_GOSSIP_IN_PEER_CAP
        && !state.channel_gossip_from_times.contains_key(&from_id.0)
    {
        return false;
    }
    // A hop carrying a transfer is answering block requests this node sent out
    // by name, so it gets the transfer rate on top of the base allowance.
    // Every other hop keeps the tight budget.
    let limit = ember::channel::CHANNEL_GOSSIP_IN_PER_PEER_PER_SEC
        + if channel_xfer_active_with(state, from_id, attribution) {
            ember::channel::CHANNEL_XFER_IN_PER_PEER_PER_SEC
        } else {
            0
        };
    let times = state
        .channel_gossip_from_times
        .entry(from_id.0)
        .or_default();
    ember::channel::rate_window_allow(times, now, CHANNEL_GOSSIP_RATE_WINDOW, limit)
}

/// Handshake-capable send. Channel gossip, transfer, and CHANNEL_RELAY
/// must not use this: `HandshakeStarted` used to count as delivered and
/// skip overlay + the WebSocket outbox. DHT lookups still start sessions
/// through their own `prepare_outgoing` paths.
#[allow(dead_code)]
pub(super) async fn send_ember_dht_frame(
    socket: &UdpSocket,
    state: &mut NetworkState,
    contact: &ember::dht::EmberContact,
    frame: &[u8],
) -> bool {
    match state
        .ember_transport
        .prepare_outgoing(contact.addr, Some(&contact.noise_pub), frame)
    {
        ember::transport::OutgoingResult::Ready { packet }
        | ember::transport::OutgoingResult::HandshakeStarted { packet } => {
            if let Err(e) = socket.send_to(&packet, contact.addr).await {
                debug!("Ember channel gossip: send to {} failed: {e}", contact.addr);
                false
            } else {
                true
            }
        }
        ember::transport::OutgoingResult::Queued => true,
        ember::transport::OutgoingResult::Error(e) => {
            debug!(
                "Ember channel gossip: transport error for {}: {e}",
                contact.addr
            );
            false
        }
    }
}

/// Seal and send only if a Noise session for this identity already exists.
/// Does not start a handshake — `prepare_outgoing` is not called unless
/// [`ember_has_live_session`] is true, so CHANNEL_RELAY cannot re-seal an
/// attacker body under our identity.
pub(super) async fn send_ember_dht_frame_established(
    socket: &UdpSocket,
    state: &mut NetworkState,
    contact: &ember::dht::EmberContact,
    frame: &[u8],
) -> bool {
    if !ember_has_live_session(state, contact) {
        return false;
    }
    match state
        .ember_transport
        .prepare_outgoing(contact.addr, Some(&contact.noise_pub), frame)
    {
        ember::transport::OutgoingResult::Ready { packet } => {
            socket.send_to(&packet, contact.addr).await.is_ok()
        }
        _ => false,
    }
}

pub(super) async fn fanout_channel_gossip_body(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    body: Vec<u8>,
    exclude: Option<ember::dht::EmberNodeId>,
) {
    fanout_channel_gossip_retry(socket, state, db, body, exclude, None).await;
}

pub(super) async fn fanout_channel_gossip_retry(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    body: Vec<u8>,
    exclude: Option<ember::dht::EmberNodeId>,
    origin_queued_at: Option<std::time::Instant>,
) {
    // `exclude` names the hop a frame arrived from, so its absence is what
    // marks this as something we originated rather than are passing on.
    let local_origin = exclude.is_none();
    let retry_at = origin_queued_at.unwrap_or_else(std::time::Instant::now);
    let Some(gossip) = ember::channel::ChannelGossip::decode(&body) else {
        return;
    };
    let in_room = cached_channel_view(state, db, gossip.channel_id)
        .is_some_and(|view| view.row.in_room_now());
    if !in_room {
        // Dropped with no retry entry, so nothing downstream will ever settle
        // it — a line written queued and then abandoned here would read as
        // sending for the rest of the session. Leaving the room is a definite
        // answer, not a pending one.
        if local_origin {
            note_channel_delivery(
                state,
                gossip.channel_id,
                gossip.msg_id,
                crate::storage::database::CHAT_FAILED,
            );
        }
        return;
    }
    let members = channel_member_pubkeys_cached(state, db, gossip.channel_id);
    let others: Vec<[u8; 32]> = members
        .iter()
        .copied()
        .filter(|pk| pk != &state.local_ed25519_pubkey)
        .collect();
    if local_origin && others.is_empty() {
        // Alone in the roster: keep the frame until presence names someone.
        // Relays of other people's frames do not wait.
        queue_channel_origin_retry(state, body, retry_at);
        return;
    }
    // Charged only once the frame is known to be one we can actually fan out.
    // Above the decode and the roster checks, an undecodable body or a room we
    // have left spent relay allowance for nothing, and every pass of
    // `drain_channel_origin_retry` burned a local token for a message that was
    // only ever waiting on a neighbor to appear.
    if !channel_gossip_rate_ok(state, local_origin) {
        if local_origin {
            queue_channel_origin_retry(state, body, retry_at);
        }
        return;
    }
    let neighbors = ember::channel::gossip_neighbors(
        &state.local_ed25519_pubkey,
        &members,
        ember::channel::CHANNEL_NEIGHBOR_COUNT,
    );
    let mut direct = Vec::new();
    let mut missing = Vec::new();
    for pk in &neighbors {
        let node_id = ember::dht::EmberNodeId(ember::channel::channel_id_from_pubkey(pk));
        if exclude == Some(node_id) {
            continue;
        }
        if let Some(contact) = state.ember_dht.routing().get_contact(&node_id).cloned() {
            if ember::channel::channel_fanout_uses_direct_session(ember_has_live_session(
                state, &contact,
            )) {
                direct.push((*pk, contact));
                continue;
            }
        }
        missing.push(*pk);
    }
    if direct.len() + missing.len() < ember::channel::CHANNEL_NEIGHBOR_COUNT {
        for pk in &members {
            if direct.len() + missing.len() >= ember::channel::CHANNEL_NEIGHBOR_COUNT {
                break;
            }
            let node_id = ember::dht::EmberNodeId(ember::channel::channel_id_from_pubkey(pk));
            if exclude == Some(node_id)
                || *pk == state.local_ed25519_pubkey
                || direct.iter().any(|(p, _)| p == pk)
                || missing.contains(pk)
            {
                continue;
            }
            if let Some(contact) = state.ember_dht.routing().get_contact(&node_id).cloned() {
                if ember::channel::channel_fanout_uses_direct_session(ember_has_live_session(
                    state, &contact,
                )) {
                    direct.push((*pk, contact));
                    continue;
                }
            }
            missing.push(*pk);
        }
    }
    // Whether any rung actually handed the frame to somebody. A line the user
    // typed is stored and on screen before this runs, so one that reaches
    // nobody has to come back here rather than be counted as sent.
    let mut delivered = false;
    for (pk, contact) in direct {
        let (_rid, frame) = state.ember_dht.build_channel_msg(body.clone());
        if send_ember_dht_frame_established(socket, state, &contact, &frame).await {
            delivered = true;
        } else {
            missing.push(pk);
        }
    }
    // Every unreachable neighbor is tried over the overlay, which is UDP
    // between members, before the rendezvous tunnel, which is a TCP WebSocket
    // through a server. The tunnel is not skipped for the peers that hold one:
    // an overlay hop only forwards to a target it already has a contact for and
    // says nothing when it cannot, so overlay delivery is best-effort and
    // indistinguishable from silence. Dropping a working tunnel on the strength
    // of an attempt that reports nothing would trade a delivery for a hope.
    //
    // Sending both is close to free. Receivers deduplicate on `msg_id`, so a
    // line that arrives twice is stored and forwarded once, and only neighbors
    // we could not reach directly cost anything at all.
    if !missing.is_empty()
        && overlay_forward_channel_gossip(
            socket,
            state,
            &gossip.channel_id,
            &body,
            &missing,
            &members,
        )
        .await
    {
        delivered = true;
    }
    for pk in &missing {
        if let Some((_, tx)) = state.channel_relay_outboxes.get(pk) {
            if tx.try_send(body.clone()).is_ok() {
                delivered = true;
            }
        }
    }
    // Nothing took it. Every rung's result used to be discarded, so a roster
    // whose members were all momentarily unreachable — no live session, no
    // tunnel, no overlay hop that knew them — produced a completely silent
    // drop: the line sat in the sender's own history looking delivered and
    // nobody ever received it. Relays of other people's frames still do not
    // wait; the mesh will carry those again from somewhere else.
    if local_origin && !delivered {
        queue_channel_origin_retry(state, body, retry_at);
    } else if local_origin {
        // Somebody took it, so the line is as sent as this node can make it.
        // The row was written queued; this is what settles it.
        note_channel_delivery(
            state,
            gossip.channel_id,
            gossip.msg_id,
            crate::storage::database::CHAT_DELIVERED,
        );
    }
}

pub(super) async fn overlay_forward_channel_gossip(
    socket: &UdpSocket,
    state: &mut NetworkState,
    channel_id: &[u8; 16],
    body: &[u8],
    missing: &[[u8; 32]],
    roster: &[[u8; 32]],
) -> bool {
    let (hops, via_members) = overlay_channel_hops(state, missing, roster);
    overlay_send_channel_gossip(socket, state, channel_id, body, missing, &hops, via_members).await
}

/// Live-session hops an overlay relay for `missing` could go through, and
/// whether they are room members rather than the non-member fallback.
pub(super) fn overlay_channel_hops(
    state: &NetworkState,
    missing: &[[u8; 32]],
    roster: &[[u8; 32]],
) -> (Vec<ember::dht::EmberContact>, bool) {
    // After inbound CHANNEL_RELAY refuses hops that are not in this room,
    // random routing-table contacts drop the envelope. Prefer other members
    // we already have a live session with.
    let local = state.local_ed25519_pubkey;
    let mut hops: Vec<ember::dht::EmberContact> = roster
        .iter()
        .filter(|pk| **pk != local && !missing.iter().any(|m| m == *pk))
        .filter_map(|pk| {
            let node_id = ember::dht::EmberNodeId(ember::channel::channel_id_from_pubkey(pk));
            state.ember_dht.routing().get_contact(&node_id).cloned()
        })
        .filter(|c| ember_has_live_session(state, c))
        .take(3)
        .collect();
    // A non-member hop is still tried, since it costs one frame, but current
    // builds refuse to forward for a room they are not in, so a send to one is
    // not evidence of anything. Reporting it as sent settled the line as
    // delivered when no member had been reached at all.
    let via_members = !hops.is_empty();
    if hops.is_empty() {
        hops = state
            .ember_dht
            .contacts()
            .into_iter()
            .filter(|c| {
                ember_has_live_session(state, c)
                    && !missing
                        .iter()
                        .any(|pk| ember::channel::channel_id_from_pubkey(pk) == c.node_id.0)
            })
            .take(3)
            .collect();
    }
    (hops, via_members)
}

pub(super) async fn overlay_send_channel_gossip(
    socket: &UdpSocket,
    state: &mut NetworkState,
    channel_id: &[u8; 16],
    body: &[u8],
    missing: &[[u8; 32]],
    hops: &[ember::dht::EmberContact],
    via_members: bool,
) -> bool {
    if hops.is_empty() {
        return false;
    }
    let mut sent = false;
    for pk in missing {
        let target = ember::channel::channel_id_from_pubkey(pk);
        let envelope = ember::channel::encode_channel_relay_envelope(channel_id, &target, body);
        let (_rid, frame) = state.ember_dht.build_channel_relay(envelope);
        for hop in hops {
            if send_ember_dht_frame_established(socket, state, hop, &frame).await {
                sent = true;
            }
        }
    }
    sent && via_members
}

pub(super) async fn handle_inbound_channel_relay(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    body: Vec<u8>,
    from_id: ember::dht::EmberNodeId,
) {
    let Some((channel_id, target_id, inner)) = ember::channel::decode_channel_relay_envelope(&body)
    else {
        return;
    };
    if !channel_gossip_inbound_ok(state, &from_id, XferAttribution::Relayed) {
        debug!("Ember channel relay: shed a frame from {from_id} over the per-hop budget");
        return;
    }
    let local = state.ember_dht.local_id();
    if target_id == local.0 {
        handle_inbound_channel_gossip(
            socket,
            state,
            db,
            app_handle,
            inner.to_vec(),
            from_id,
            HopMetering::AlreadyCharged,
        )
        .await;
        return;
    }
    let in_room = cached_channel_view(state, db, channel_id)
        .is_some_and(|view| view.row.in_room_now());
    let roster = if in_room {
        channel_member_pubkeys_cached(state, db, channel_id)
    } else {
        Vec::new()
    };
    let target_on_roster = if roster.is_empty() {
        None
    } else {
        Some(
            roster
                .iter()
                .any(|pk| ember::channel::channel_id_from_pubkey(pk) == target_id),
        )
    };
    let Some(contact) = state
        .ember_dht
        .routing()
        .get_contact(&ember::dht::EmberNodeId(target_id))
        .cloned()
    else {
        return;
    };
    let live = ember_has_live_session(state, &contact);
    if !ember::channel::inbound_channel_relay_may_forward(in_room, target_on_roster, live) {
        return;
    }
    let (_rid, frame) = state.ember_dht.build_channel_msg(inner.to_vec());
    send_ember_dht_frame_established(socket, state, &contact, &frame).await;
}

pub(super) async fn handle_inbound_channel_gossip(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    body: Vec<u8>,
    from_id: ember::dht::EmberNodeId,
    metering: HopMetering,
) {
    let Some(gossip) = ember::channel::ChannelGossip::decode(&body) else {
        return;
    };
    // Every caller that charges here is talking to the hop directly — a UDP
    // `CHANNEL_MSG`, or a WebSocket relay outbox already keyed by the peer —
    // so the transfer allowance is attributed to that hop. Frames arriving
    // inside a relay envelope were charged by the relay handler instead.
    if metering == HopMetering::Charge
        && !channel_gossip_inbound_ok(state, &from_id, XferAttribution::Hop)
    {
        debug!("Ember channel gossip: shed a frame from {from_id} over the per-hop budget");
        return;
    }
    let body_key = ember::channel::gossip_body_key(&gossip);
    let admission = ember::channel::admit_gossip(
        &mut state.channel_gossip_seen,
        &mut state.channel_gossip_seen_order,
        ember::channel::CHANNEL_GOSSIP_SEEN_CAP,
        gossip.msg_id,
        body_key,
        std::time::Instant::now(),
    );
    let variant = match admission {
        ember::channel::GossipAdmission::Fresh => false,
        ember::channel::GossipAdmission::Variant => true,
        ember::channel::GossipAdmission::Duplicate => return,
    };
    // Releasing the id for a variant would re-admit the frame that claimed it.
    let dedup_key = if variant { body_key } else { gossip.msg_id };
    if !ember::channel::gossip_timestamp_ok(
        gossip.timestamp,
        chrono::Utc::now().timestamp(),
    ) {
        forget_channel_gossip(state, &dedup_key);
        return;
    }
    if db.chat_locked() {
        forget_channel_gossip(state, &dedup_key);
        return;
    }
    let channel_id_hex = hex::encode(gossip.channel_id);
    let Some(view) = cached_channel_view(state, db, gossip.channel_id) else {
        forget_channel_gossip(state, &dedup_key);
        return;
    };
    let ch = view.row;
    if !ch.in_room_now() {
        forget_channel_gossip(state, &dedup_key);
        return;
    }
    // Decrypt may succeed under an older epoch; that key is only used to
    // *read*. Replies (history sync) are sealed under the current epoch so a
    // banned member who still holds a retired key cannot be handed new chat.
    //
    // Which key it was decides the rest. An evicted member keeps every retired
    // key and can mint a fresh identity the ban list has never heard of, so a
    // frame opened under one is read-only: it may be shown, and may refresh a
    // member the roster already holds, but it admits nobody, is not served
    // history, cannot offer a transfer, and moves no moderation. Otherwise the
    // owner's next key republish would seal the new epoch to that identity.
    let Some((plain, opened)) =
        ember::channel::open_with_content_keys(&view.content_keys, |candidate| {
            gossip.decrypt(candidate)
        })
    else {
        debug!("Ember channel gossip: decrypt failed for {channel_id_hex}");
        forget_channel_gossip(state, &dedup_key);
        return;
    };
    if variant
        && ember::channel::decode_channel_chat_plain(
            &plain,
            &gossip.channel_id,
            &gossip.msg_id,
            gossip.timestamp,
        )
        .is_none()
    {
        return;
    }
    // Ember Transfer frames are addressed to one member and never relayed on,
    // so they are matched before the gossip types and always return.
    //
    // One gate for all of them: the frame has to name us, and its
    // authenticator has to check out under the key only we and the claimed
    // sender can derive. Everything past this point can treat `sender` as the
    // member it says it is, which the room's shared content key alone would
    // not establish.
    if let Some((sender, target, xfer_id)) = ember::channel::xfer_frame_peek(&plain) {
        if target != state.local_ed25519_pubkey {
            return;
        }
        let Some(key) = ember::channel::derive_xfer_key(
            &state.local_ed25519_seed,
            &sender,
            &gossip.channel_id,
            &xfer_id,
        ) else {
            return;
        };
        let Some(body) = ember::channel::xfer_verify(&key, &plain) else {
            debug!(
                "Ember Transfer: dropped a frame in {channel_id_hex} whose authenticator did not \
                 match the member it named"
            );
            return;
        };
        // The pairwise key that just authenticated this frame can be derived
        // only by us and the member it names, so a transfer in flight is proof
        // of presence every bit as good as a beacon — and it was already on the
        // wire. A member moving a file through the room could still be shown
        // offline while doing it.
        note_channel_member_alive(
            state,
            gossip.channel_id,
            &sender,
            chrono::Utc::now().timestamp(),
        );
        if let Some((_, _, _, offset, data)) = ember::channel::decode_xfer_block_data(&key, body) {
            apply_xfer_block_data(state, app_handle, xfer_id, sender, offset, &data);
        } else if let Some((_, _, _, offset, count)) =
            ember::channel::decode_xfer_block_request(body)
        {
            apply_xfer_block_request(state, xfer_id, sender, offset, count);
        } else if let Some(offer) = ember::channel::decode_xfer_offer(body) {
            // The pairwise key already names the sender; under a retired key
            // they must also be somebody the roster holds, since that is what
            // an evicted member's fresh identity is not.
            if opened == ember::channel::OpenedUnder::Current
                || channel_member_on_roster(state, db, gossip.channel_id, &sender)
            {
                apply_xfer_offer(socket, state, db, app_handle, &ch, &gossip, offer, key).await;
            } else {
                debug!("Ember Transfer: ignored an offer in {channel_id_hex} under a retired key");
            }
        } else if let Some((_, _, _, reply)) = ember::channel::decode_xfer_reply(body) {
            apply_xfer_reply(state, app_handle, xfer_id, sender, reply).await;
        } else if let Some((_, _, _, reason)) = ember::channel::decode_xfer_cancel(body) {
            apply_xfer_cancel(state, app_handle, xfer_id, sender, reason);
        } else if ember::channel::decode_xfer_done(body).is_some() {
            apply_xfer_done(state, app_handle, xfer_id, sender);
        } else if let Some((_, _, _, role, ports)) = ember::channel::decode_xfer_stream(body) {
            apply_xfer_stream(state, xfer_id, sender, role, ports);
        }
        return;
    }
    // Ahead of the rest because it is the frame this room sends most often once
    // nobody is talking, and every decoder below it would otherwise be tried
    // against each one first.
    if let Some(beacons) = ember::channel::decode_channel_presence_beacons(
        &plain,
        &gossip.channel_id,
        ch.key_epoch,
        chrono::Utc::now().timestamp(),
    ) {
        // Only a private room needs the proof: a public room's key is derived
        // from its pubkey, so proving it would prove nothing.
        let admission_key = (ch.visibility == ember::channel::CHANNEL_KIND_PRIVATE)
            .then(|| view.content_keys.first().copied())
            .flatten();
        apply_channel_presence_beacons(
            socket,
            state,
            db,
            app_handle,
            &ch,
            &gossip,
            beacons,
            from_id,
            admission_key,
        )
        .await;
        return;
    }
    if let Some((member, typing)) = ember::channel::decode_channel_typing(
        &plain,
        &gossip.channel_id,
        &gossip.msg_id,
        gossip.timestamp,
    ) {
        apply_channel_typing(
            state,
            db,
            app_handle,
            gossip.channel_id,
            gossip.timestamp,
            member,
            typing,
        );
        return;
    }
    // Handoff frames are not gated on `opened`. Each carries its own authority —
    // the room's signature on an offer, the pending nominee's on a ready — so
    // the key that sealed it adds nothing, and a nominee who has not fetched
    // the newest epoch yet must still be able to answer.
    let channel_pk = hex::decode(&ch.pubkey)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok());
    if let Some((sender_pk, target_pk, version)) = channel_pk.and_then(|pk| {
        ember::channel::decode_channel_handoff_offer(&plain, &gossip.channel_id, &pk)
    }) {
        apply_channel_handoff_offer(
            socket,
            state,
            db,
            app_handle,
            &ch,
            &gossip,
            from_id,
            sender_pk,
            target_pk,
            version,
        )
        .await;
        return;
    }
    if let Some((sender_pk, successor_pk, version)) =
        ember::channel::decode_channel_handoff_ready(&plain, &gossip.channel_id)
    {
        apply_channel_handoff_ready(
            socket,
            state,
            db,
            app_handle,
            &ch,
            &gossip,
            from_id,
            sender_pk,
            successor_pk,
            version,
        )
        .await;
        return;
    }
    if let Some((sender_pk, since_ts)) = ember::channel::decode_channel_sync_request(
        &plain,
        &gossip.channel_id,
        &gossip.msg_id,
        gossip.timestamp,
    ) {
        if channel_member_banned(state, db, gossip.channel_id, &sender_pk) {
            return;
        }
        // Signature-verified above, so asking for catch-up is itself evidence
        // the asker is here — and a member who has just come back online and is
        // filling in what they missed is exactly the one a roster should not be
        // calling offline.
        note_channel_member_alive(
            state,
            gossip.channel_id,
            &sender_pk,
            chrono::Utc::now().timestamp(),
        );
        // Nothing we could send back would help: a reply is sealed under our
        // current key, which a member still on a retired one cannot open, and
        // the one asker who holds only retired keys by design is the member a
        // rotation evicted.
        if opened == ember::channel::OpenedUnder::Retired {
            return;
        }
        // Its own budget, and the tightest one here. Every other branch costs
        // the sender roughly what it costs us; this one answers a single small
        // request with up to `CHANNEL_HISTORY_SYNC_MAX` separately sealed
        // unicasts, so without a ceiling any content-key holder — which in a
        // public room is anyone, the key comes from the room's own pubkey —
        // turns each packet they send into thirty-two that we send.
        if !channel_history_sync_ok(state, gossip.channel_id, &sender_pk) {
            // Refused for rate, not validity, so the dedup slot goes back and a
            // genuine retry once the window rolls off is still admissible.
            forget_channel_gossip(state, &gossip.msg_id);
            debug!("Ember channel gossip: rate-limited history sync in {channel_id_hex}");
            return;
        }
        reply_channel_history_sync(
            socket,
            state,
            db,
            &ch,
            sender_pk,
            since_ts,
        )
        .await;
        return;
    }
    if let Some((sender_pk, target_pk, banned)) = ember::channel::decode_channel_mod_action(
        &plain,
        &gossip.channel_id,
        &gossip.msg_id,
        gossip.timestamp,
    ) {
        // Not gated on `opened`: the action is signed by its moderator, and the
        // moderator list comes from the owner's own signed snapshot, so a
        // moderator still on the previous epoch is exactly as trustworthy as
        // one on the current — and an evicted member's fresh identity is on
        // neither list.
        let sender_hex = hex::encode(sender_pk);
        if channel_member_banned(state, db, gossip.channel_id, &sender_pk) {
            return;
        }
        if !db
            .channel_member_is_moderator(&channel_id_hex, &sender_hex)
            .unwrap_or(false)
        {
            return;
        }
        note_channel_member_alive(
            state,
            gossip.channel_id,
            &sender_pk,
            chrono::Utc::now().timestamp(),
        );
        // Same author budget as chat: a moderator spraying ban/unban actions
        // rewrites every peer's member list as fast as they can send.
        if !channel_author_gossip_ok(state, gossip.channel_id, &sender_pk) {
            forget_channel_gossip(state, &gossip.msg_id);
            debug!("Ember channel gossip: rate-limited mod action in {channel_id_hex}");
            return;
        }
        // A moderator cannot ban the room owner, on anyone's device.
        //
        // `ch.owner_pubkey` comes from the owner's signed moderation record, so
        // every member can apply this rule rather than only the owner's own
        // machine — which was the hole: elsewhere the ban landed and the
        // owner's messages were silently dropped by every peer. The `is_owner`
        // arm still covers us before we have ingested our own record. Not
        // relayed either, to stop it spreading further. An unban still applies:
        // that direction only ever clears a bad row.
        let target_hex_lower = hex::encode(target_pk);
        let targets_owner = ch.owner_pubkey.eq_ignore_ascii_case(&target_hex_lower)
            || (ch.is_owner && target_pk == state.local_ed25519_pubkey);
        if banned && targets_owner {
            debug!("Ember channel gossip: refused a moderator ban on the owner of {channel_id_hex}");
            return;
        }
        let target_hex = hex::encode(target_pk);
        let applied = db
            .apply_channel_ban_action(&channel_id_hex, &target_hex, banned, gossip.timestamp)
            .unwrap_or(false);
        if banned {
            // A moderator cannot rotate the room key — the epoch record is
            // signed by the room identity, and only the owner holds its seed —
            // so in a private room we own, their ban was a label the evicted
            // member could read straight through. Queue it for the owner-record
            // loop, which holds the seed and publishes the snapshot that has to
            // announce the new epoch, and bring that pass forward.
            //
            // On disk, so closing the app before that pass runs postpones the
            // rotation rather than losing it.
            if applied && ch.is_owner && ch.visibility == ember::channel::CHANNEL_KIND_PRIVATE {
                let _ = db.mark_channel_rotate_pending(&channel_id_hex);
                state
                    .channel_moderation_publish_at
                    .remove(&gossip.channel_id);
            }
            // Ours to stop as well when we are the one evicted: their entries
            // name us as the peer, not themselves, so a member-scoped sweep
            // would find nothing.
            let scope = if target_pk == state.local_ed25519_pubkey {
                None
            } else {
                Some(target_pk)
            };
            drop_channel_transfers_for(
                state,
                app_handle,
                gossip.channel_id,
                scope,
                "not_allowed",
            );
        }
        let _ = app_handle.emit(
            "ember:channel-moderation",
            serde_json::json!({ "channel_id": channel_id_hex }),
        );
        if let Some(next) = gossip.decremented_ttl() {
            fanout_channel_gossip_body(socket, state, db, next.encode(), Some(from_id)).await;
        }
        return;
    }
    if let Some(edit) = ember::channel::decode_channel_chat_edit(&plain, &gossip.channel_id) {
        handle_inbound_channel_edit(
            socket,
            state,
            db,
            app_handle,
            &gossip,
            &channel_id_hex,
            edit,
            from_id,
            opened,
        )
        .await;
        return;
    }
    if let Some(entries) = ember::channel::decode_channel_reactions(&plain, &gossip.channel_id) {
        handle_inbound_channel_reactions(
            socket,
            state,
            db,
            app_handle,
            &gossip,
            &channel_id_hex,
            entries,
            from_id,
            opened,
        )
        .await;
        return;
    }
    let Some((sender_pk, text, author_sig)) = ember::channel::decode_channel_chat_plain(
        &plain,
        &gossip.channel_id,
        &gossip.msg_id,
        gossip.timestamp,
    ) else {
        debug!(
            "Ember channel gossip: dropped a chat line in {channel_id_hex} that did not carry a \
             signature from the member it named"
        );
        return;
    };
    let sender_hex = hex::encode(sender_pk);
    let msg_id_hex = hex::encode(gossip.msg_id);
    // Ahead of the rate charge: our own lines echo back as variants, and a line
    // we already hold says nothing new to us or to the mesh.
    if variant
        && db
            .channel_message_known(&channel_id_hex, &msg_id_hex, &sender_hex, gossip.timestamp)
            .unwrap_or(true)
    {
        return;
    }
    // Ahead of any DB work, and ahead of the relay below: a member flooding a
    // room must not be forwarded on by us, or the mesh amplifies it.
    if !channel_author_gossip_ok(state, gossip.channel_id, &sender_pk) {
        // Release the dedup slot: this was refused for rate, not validity, so a
        // retransmit once the window rolls off has to still be admissible.
        forget_channel_gossip(state, &dedup_key);
        debug!("Ember channel gossip: rate-limited author in {channel_id_hex}");
        return;
    }
    if channel_member_banned(state, db, gossip.channel_id, &sender_pk) {
        return;
    }
    // A member already on the roster who is still on the previous epoch keeps
    // talking while the rotation propagates. Anyone else under a retired key is
    // indistinguishable from the member it evicted under a new name.
    if opened == ember::channel::OpenedUnder::Retired
        && !channel_member_on_roster(state, db, gossip.channel_id, &sender_pk)
    {
        // The same line may still arrive under the current key — a catch-up
        // re-serve keeps its id — so it must not be burned as seen.
        forget_channel_gossip(state, &dedup_key);
        debug!(
            "Ember channel gossip: dropped a line in {channel_id_hex} from an unknown author \
             under a retired key"
        );
        return;
    }
    let cleaned = crate::security::sanitize_chat_text(&text);
    if cleaned.is_empty() || cleaned.len() > 4096 {
        return;
    }
    let now = gossip.timestamp;
    // Keep the author's signature only when sanitising left the text alone.
    // The signature covers what they wrote; if we had to change it, the two no
    // longer agree, and storing the signature anyway would produce a re-serve
    // that every recipient rejects. Such a line stays readable here and simply
    // is not passed on.
    let stored_sig = if cleaned == text {
        hex::encode(author_sig)
    } else {
        String::new()
    };
    let joins_roster = ember::channel::chat_author_joins_gossip_roster(
        ch.visibility == ember::channel::CHANNEL_KIND_PRIVATE,
        opened,
        gossip.ttl,
    );
    // The same derivation `insert_channel_message` stores, so the event and the
    // row agree on what this line answers.
    let reply_to = ember::channel::chat_reply_parent_hex(&cleaned, &msg_id_hex);
    // Awaited, not detached: the dedup verdict, the stored row and the roster
    // write decide what this frame does next, and the next frame for the same
    // line has to see this one's row. What moves is the blocking itself — the
    // three statements now run on the blocking pool rather than pinning the
    // runtime worker that carries the network `select!`.
    let ingest = {
        let db = db.clone();
        let channel_id_hex = channel_id_hex.clone();
        let sender_hex = sender_hex.clone();
        let msg_id_hex = msg_id_hex.clone();
        let cleaned = cleaned.clone();
        let local_hex = hex::encode(state.local_ed25519_pubkey);
        let reply_to = reply_to.clone();
        tokio::task::spawn_blocking(move || {
            // Either we already hold the line, or we held it and were told to
            // forget it. Both mean do not store it again; both still pass it
            // on, because forgetting a line here is a local decision and not a
            // claim about the room. Holding only the id is not holding the
            // line: a row that cannot prove the id is its own gives way to this
            // one inside `insert_channel_message`.
            if db
                .channel_message_known(&channel_id_hex, &msg_id_hex, &sender_hex, now)
                .unwrap_or(false)
            {
                return ChatLineIngest::Known;
            }
            match db.insert_channel_message(
                &channel_id_hex,
                &sender_hex,
                "received",
                &cleaned,
                &msg_id_hex,
                now,
                &stored_sig,
                false,
            ) {
                Ok(row_id) => ChatLineIngest::Stored {
                    row_id,
                    // A parent that fails to read is a quote drawn as
                    // unavailable, not a line lost.
                    reply: reply_to
                        .as_deref()
                        .and_then(|parent| db.channel_reply_lookup(&channel_id_hex, parent).ok())
                        .unwrap_or_default(),
                    // First line from someone this device did not already
                    // hold: the roster has to grow, and XOR-neighbors may have
                    // changed, so do not wait for the next presence walk or the
                    // friend heartbeat.
                    member: joins_roster.then(|| {
                        db.upsert_channel_member(
                            &channel_id_hex,
                            &sender_hex,
                            "",
                            now,
                            Some(&local_hex),
                        )
                        .ok()
                    }),
                },
                Err(e) => ChatLineIngest::Failed(e.to_string()),
            }
        })
        .await
        .unwrap_or_else(|e| ChatLineIngest::Failed(e.to_string()))
    };
    match ingest {
        ChatLineIngest::Known => {
            if let Some(next) = gossip.decremented_ttl() {
                fanout_channel_gossip_body(socket, state, db, next.encode(), Some(from_id)).await;
            }
            return;
        }
        ChatLineIngest::Stored {
            row_id,
            reply,
            member,
        } => {
            note_channel_sync_ingest(state, gossip.channel_id, gossip.ttl);
            if let Some(member) = member {
                match member {
                    Some(ChannelMemberWrite::Inserted) => {
                        state.rendezvous_last_register = None;
                        let _ = app_handle.emit(
                            "ember:channel-members",
                            serde_json::json!({ "channel_id": channel_id_hex }),
                        );
                    }
                    // Chat carries no nickname, so `Updated` is unreachable
                    // here; both are folded in anyway so a future caller that
                    // does pass one cannot silently stop refreshing the row.
                    Some(ChannelMemberWrite::Touched) => {
                        mark_channel_presence_dirty(state, gossip.channel_id, &sender_pk, now);
                    }
                    Some(ChannelMemberWrite::Updated) => {
                        let _ = app_handle.emit(
                            "ember:channel-members",
                            serde_json::json!({ "channel_id": channel_id_hex }),
                        );
                    }
                    _ => {}
                }
            } else {
                // Public rooms do not INSERT strangers from chat (anti-eclipse),
                // and no room does on a seal that is not the author's own under
                // the current key. A line from someone already on the roster
                // still refreshes last_seen so they do not age out while visibly
                // talking.
                note_channel_member_alive(state, gossip.channel_id, &sender_pk, now);
            }
            let reply_to_me =
                reply_parent_is_ours(reply.parent.as_ref(), &state.local_ed25519_pubkey);
            let _ = app_handle.emit(
                "ember:channel-message",
                serde_json::json!({
                    "id": row_id,
                    "channel_id": channel_id_hex,
                    "sender_pubkey": sender_hex,
                    "direction": "received",
                    // The body. The stored copy keeps the signed trailer.
                    "message": ember::channel::chat_display_text(&cleaned),
                    // The author's signed send time (`now` above is
                    // `gossip.timestamp`), not when it reached us: catch-up
                    // serves old lines through this same event, and this is how
                    // the UI tells them from live ones and keeps them quiet.
                    "timestamp": now,
                    // Carried so a line that arrives live can be reacted to
                    // straight away. Reactions name a message by its wire id, and
                    // without this the bubble held no way to be addressed until
                    // the room was next read from disk.
                    "msg_id": msg_id_hex,
                    "reply_to": reply_to,
                    // Someone answering one of our lines, which notifications
                    // treat the way they treat a mention.
                    "reply_to_me": reply_to_me,
                    "reply_parent": reply.parent,
                    "reply_parent_deleted": reply.deleted,
                }),
            );
        }
        ChatLineIngest::Failed(e) => {
            debug!("Ember channel gossip: persist failed for {channel_id_hex}: {e}");
        }
    }
    if let Some(next) = gossip.decremented_ttl() {
        fanout_channel_gossip_body(socket, state, db, next.encode(), Some(from_id)).await;
    }
}

/// What the blocking half of a chat line's ingest found.
enum ChatLineIngest {
    /// Already held, or held and forgotten: relay, do not store.
    Known,
    /// `member` is the roster write, when the line was one that may grow it;
    /// its inner `None` is a write that failed.
    Stored {
        row_id: i64,
        reply: crate::storage::database::ChannelReplyLookup,
        member: Option<Option<ChannelMemberWrite>>,
    },
    Failed(String),
}

/// Whether a reply's parent was written by this device's identity.
///
/// Compared by key, not by the parent row's `direction`: our own line can come
/// back to us as `received` — restored from a catch-up after this device lost
/// its copy — and is still ours.
fn reply_parent_is_ours(
    parent: Option<&crate::storage::database::ChannelReplyParent>,
    local_pubkey: &[u8; 32],
) -> bool {
    parent.is_some_and(|parent| {
        parent
            .sender_pubkey
            .eq_ignore_ascii_case(&hex::encode(local_pubkey))
    })
}

pub(super) async fn apply_channel_handoff_offer(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    ch: &crate::storage::database::StoredChannel,
    gossip: &ember::channel::ChannelGossip,
    from_id: ember::dht::EmberNodeId,
    _sender_pk: [u8; 32],
    target_pk: [u8; 32],
    version: u64,
) {
    // A lapsed offer is a replay: the owner will not accept a ready for it, and
    // answering would only mint a seed over the one a live offer may need.
    // Nobody passes it on, either.
    if !ember::channel::handoff_offer_live_at_target(version, chrono::Utc::now().timestamp()) {
        debug!("Ember channel handoff: ignored a lapsed offer for {}", ch.channel_id);
        return;
    }
    if target_pk == state.local_ed25519_pubkey {
        // Never answer with a successor key that is not on disk: the owner
        // publishes whatever pubkey the ready names, and a seed held only in
        // memory is a room nobody can ever sign for again.
        let ident = match db.load_handoff_pending_row(&ch.channel_id) {
            Ok(Some((_pk, ver, seed))) if ver == version => {
                Some(ember::channel::ChannelIdentity::from_seed(&seed))
            }
            Ok(Some((_pk, ver, _seed))) if ver > version => {
                debug!(
                    "Ember channel handoff: ignored offer v{version} for {} behind held v{ver}",
                    ch.channel_id
                );
                None
            }
            _ => {
                let ident = ember::channel::ChannelIdentity::generate();
                match db.store_handoff_pending_seed(
                    &ch.channel_id,
                    version,
                    &hex::encode(ident.pubkey),
                    &ident.seed(),
                ) {
                    Ok(true) => Some(ident),
                    Ok(false) => None,
                    Err(e) => {
                        debug!(
                            "Ember channel handoff: could not hold the successor seed for {}: {e}",
                            ch.channel_id
                        );
                        None
                    }
                }
            }
        };
        if let (Some(ident), Some(key)) = (ident, channel_content_key(db, ch)) {
            let signing = ember::crypto::signing_key_from_bytes(&state.local_ed25519_seed);
            let plain = ember::channel::encode_channel_handoff_ready(
                &signing,
                &gossip.channel_id,
                &state.local_ed25519_pubkey,
                &ident.pubkey,
                version,
            );
            let reply = ember::channel::ChannelGossip::new_plaintext(
                gossip.channel_id,
                &key,
                version,
                &plain,
                ember::channel::CHANNEL_MSG_TTL_DEFAULT,
            );
            let _ = remember_channel_gossip(state, reply.msg_id);
            fanout_channel_gossip_body(socket, state, db, reply.encode(), None).await;
            let _ = app_handle.emit(
                "ember:channel-handoff",
                serde_json::json!({
                    "channel_id": ch.channel_id,
                    "phase": "ready",
                }),
            );
        }
    }
    if let Some(next) = gossip.decremented_ttl() {
        fanout_channel_gossip_body(socket, state, db, next.encode(), Some(from_id)).await;
    }
}

pub(super) async fn apply_channel_handoff_ready(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    ch: &crate::storage::database::StoredChannel,
    gossip: &ember::channel::ChannelGossip,
    from_id: ember::dht::EmberNodeId,
    sender_pk: [u8; 32],
    successor_pk: [u8; 32],
    version: u64,
) {
    if ch.is_owner {
        if let Ok(Some((pending, pending_ver))) = db.channel_pending_handoff(&ch.channel_id) {
            let sender_hex = hex::encode(sender_pk);
            // The pending mark only gates offering to somebody else, so it can
            // outlive both the offer's window and the target's standing in the
            // room. Completing on either would hand the room to someone the
            // owner no longer meant it for.
            let acceptable = pending.eq_ignore_ascii_case(&sender_hex)
                && pending_ver == version
                && ember::channel::handoff_offer_live(version, chrono::Utc::now().timestamp())
                && !db
                    .channel_member_is_banned(&ch.channel_id, &sender_hex)
                    .unwrap_or(true);
            if acceptable {
                // Committed before anything is published: from the first
                // publish on, the record may be stored without our hearing so,
                // and a second handoff beside it would split the room.
                let now = chrono::Utc::now().timestamp();
                match db.commit_channel_handoff(
                    &ch.channel_id,
                    &sender_hex,
                    version,
                    &hex::encode(successor_pk),
                    now,
                ) {
                    Ok(ChannelHandoffCommitOutcome::Committed(commit)) => {
                        publish_committed_channel_handoff(
                            socket,
                            state,
                            db,
                            app_handle,
                            ch,
                            gossip.channel_id,
                            &commit,
                        )
                        .await;
                    }
                    Ok(ChannelHandoffCommitOutcome::Held(commit)) => {
                        if commit.confirmed {
                            spawn_owned_channel_handoff_completion(
                                state,
                                db,
                                app_handle.clone(),
                                gossip.channel_id,
                            );
                        } else if !channel_handoff_publish_in_flight(state, gossip.channel_id) {
                            // The nominee answering again re-drives a publish
                            // that ran out of attempts.
                            let _ = db.restart_channel_handoff_commit(&ch.channel_id, now);
                            publish_committed_channel_handoff(
                                socket,
                                state,
                                db,
                                app_handle,
                                ch,
                                gossip.channel_id,
                                &commit,
                            )
                            .await;
                        }
                    }
                    Ok(ChannelHandoffCommitOutcome::Conflict) => {
                        debug!(
                            "Ember channel handoff: ignored a ready for v{version} of {}; \
                             committed to another",
                            ch.channel_id
                        );
                    }
                    Ok(ChannelHandoffCommitOutcome::NotPending) => {}
                    Err(e) => {
                        debug!(
                            "Ember channel handoff: could not commit {} to its successor: {e}",
                            ch.channel_id
                        );
                    }
                }
            }
        }
    }
    if let Some(next) = gossip.decremented_ttl() {
        fanout_channel_gossip_body(socket, state, db, next.encode(), Some(from_id)).await;
    }
}

/// Whether a publish of this room's handoff record is still out.
pub(super) fn channel_handoff_publish_in_flight(state: &mut NetworkState, channel_id: [u8; 16]) -> bool {
    let Some(publish_id) = state
        .channel_handoff_publishes
        .get(&channel_id)
        .and_then(|(publish_id, _)| *publish_id)
    else {
        return false;
    };
    state.ember_publish.get_mut(publish_id).is_some()
}

/// Publish the handoff record a room we own is committed to.
///
/// Ownership is given up only once some node is known to hold the record:
/// applying the handoff drops our seed, and a record stored nowhere tells
/// nobody the room moved, which would leave it with no owner at all. Until
/// then [`maybe_drive_channel_handoffs`] keeps republishing on its own
/// schedule.
pub(super) async fn publish_committed_channel_handoff(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    ch: &crate::storage::database::StoredChannel,
    channel_id: [u8; 16],
    commit: &crate::storage::database::ChannelHandoffCommit,
) {
    let now = chrono::Utc::now().timestamp();
    // Stamped before anything can fail, so a publish that cannot even start
    // still waits out the schedule rather than being retried every tick.
    state.channel_handoff_publishes.insert(channel_id, (None, now));
    let Ok(Some(seed)) = db.load_channel_owner_seed(&ch.channel_id) else {
        return;
    };
    let Some(successor_pk) = hex::decode(&commit.successor_pubkey)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    else {
        return;
    };
    let ident = ember::channel::ChannelIdentity::from_seed(&seed);
    let record = ember::dht::publish::SignedRecord::channel_handoff(
        commit.version,
        successor_pk,
        channel_id,
        ident.pubkey,
        ch.visibility == ember::channel::CHANNEL_KIND_PRIVATE,
        &ident.signing_key,
    );
    let Some(publish_id) = state
        .ember_publish
        .start_publish(record, state.ember_dht.routing())
    else {
        debug!(
            "Ember channel handoff: could not start publishing {}; still its owner",
            ch.channel_id
        );
        return;
    };
    state
        .channel_handoff_publishes
        .insert(channel_id, (Some(publish_id), now));
    let (tx, rx) = oneshot::channel();
    state.ember_dht_pending_publishes.insert(publish_id, tx);
    let finish_db = db.clone();
    let finish_app = app_handle.clone();
    let registry_url = (!state.rendezvous_url.is_empty()).then(|| state.rendezvous_url.clone());
    let completing = state.channel_handoff_completing.clone();
    let channel_hex = ch.channel_id.clone();
    let version = commit.version;
    let successor_hex = commit.successor_pubkey.clone();
    tokio::spawn(async move {
        // A dropped sender is a publish that went away without a verdict,
        // which is not evidence it landed either.
        if !rx.await.is_ok_and(|result| result.stored_on > 0) {
            tracing::debug!(
                channel_id = %channel_hex,
                "handoff record stored on nobody yet; keeping ownership"
            );
            return;
        }
        let confirm_db = finish_db.clone();
        let confirmed = tokio::task::spawn_blocking(move || {
            confirm_db.confirm_channel_handoff(
                &channel_hex,
                version,
                &successor_hex,
                chrono::Utc::now().timestamp(),
                false,
            )
        })
        .await
        .is_ok_and(|result| result.unwrap_or(false));
        if confirmed {
            complete_owned_channel_handoff(finish_db, finish_app, registry_url, completing, channel_id)
                .await;
        }
    });
    drive_ember_publish(socket, state, publish_id).await;
}

pub(super) fn spawn_owned_channel_handoff_completion(
    state: &NetworkState,
    db: &Arc<Database>,
    app_handle: tauri::AppHandle,
    channel_id: [u8; 16],
) {
    let registry_url = (!state.rendezvous_url.is_empty()).then(|| state.rendezvous_url.clone());
    tokio::spawn(complete_owned_channel_handoff(
        db.clone(),
        app_handle,
        registry_url,
        state.channel_handoff_completing.clone(),
        channel_id,
    ));
}

/// Finish a handoff whose record is known to be stored: hand the registry name
/// over, then give the room up.
///
/// In that order, and from whichever path learned of the record first — the
/// publish's own acknowledgement or our handoff fetch finding it. The name can
/// only be signed over with the seed the apply deletes, so doing it after, or
/// letting a path that knows nothing of the name apply first, cost the room its
/// name for good. With the seed still on disk until the apply, a crash between
/// the two only means the next pass signs the name over again, which the
/// registry answers the same way.
async fn complete_owned_channel_handoff(
    db: Arc<Database>,
    app_handle: tauri::AppHandle,
    registry_url: Option<String>,
    completing: Arc<std::sync::Mutex<HashSet<[u8; 16]>>>,
    channel_id: [u8; 16],
) {
    struct Completing(Arc<std::sync::Mutex<HashSet<[u8; 16]>>>, [u8; 16]);
    impl Drop for Completing {
        fn drop(&mut self) {
            if let Ok(mut set) = self.0.lock() {
                set.remove(&self.1);
            }
        }
    }
    {
        let Ok(mut set) = completing.lock() else {
            return;
        };
        if !set.insert(channel_id) {
            return;
        }
    }
    let _completing = Completing(completing.clone(), channel_id);
    let channel_hex = hex::encode(channel_id);
    let prepare_db = db.clone();
    let prepare_hex = channel_hex.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        let commit = prepare_db
            .channel_handoff_commit(&prepare_hex)
            .ok()
            .flatten()
            .filter(|commit| commit.confirmed)?;
        prepare_db
            .get_channel_lite(&prepare_hex)
            .ok()
            .flatten()
            .filter(|row| row.is_owner && row.successor_id.is_empty())?;
        let seed = prepare_db.load_channel_owner_seed(&prepare_hex).ok().flatten()?;
        Some((commit, seed))
    })
    .await
    .ok()
    .flatten();
    let Some((commit, seed)) = prepared else {
        return;
    };
    let Some(successor_pk) = hex::decode(&commit.successor_pubkey)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    else {
        return;
    };
    let successor_id = ember::channel::channel_id_from_pubkey(&successor_pk);
    if let Some(url) = registry_url {
        let old_pk = ember::channel::ChannelIdentity::from_seed(&seed).pubkey;
        hand_over_channel_name(&url, channel_id, successor_id, successor_pk, old_pk, seed).await;
    }
    let apply_db = db.clone();
    let apply_hex = channel_hex.clone();
    let applied = match tokio::task::spawn_blocking(move || {
        apply_db.apply_owned_channel_handoff(&apply_hex)
    })
    .await
    {
        Ok(Ok(applied)) => applied,
        Ok(Err(error)) => {
            tracing::warn!(
                channel_id = %channel_hex,
                %error,
                "could not apply a handoff whose record is published"
            );
            false
        }
        Err(_) => false,
    };
    if applied {
        let _ = app_handle.emit(
            "ember:channel-handoff",
            serde_json::json!({
                "channel_id": channel_hex,
                "successor_id": hex::encode(successor_id),
                "phase": "published",
            }),
        );
    }
}

/// Keep every committed handoff moving: finish the confirmed ones, republish
/// the rest on [`ember::channel::handoff_republish_due`]'s schedule, and tell
/// the owner once when one has run out of attempts.
pub(super) async fn maybe_drive_channel_handoffs(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
) {
    let Ok(commits) = db.list_channel_handoff_commits() else {
        return;
    };
    if commits.is_empty() {
        state.channel_handoff_publishes.clear();
        state.channel_handoff_failure_noted.clear();
        return;
    }
    let now = chrono::Utc::now().timestamp();
    let app_handle = state.channel_delivery_sink.1.clone();
    let mut live: HashSet<[u8; 16]> = HashSet::new();
    for (channel_hex, commit) in commits {
        let Some(channel_id) = hex::decode(&channel_hex)
            .ok()
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
        else {
            continue;
        };
        let Ok(Some(ch)) = db.get_channel_lite(&channel_hex) else {
            let _ = db.drop_channel_handoff_commit(&channel_hex);
            continue;
        };
        if !ch.is_owner || !ch.successor_id.is_empty() {
            let _ = db.drop_channel_handoff_commit(&channel_hex);
            continue;
        }
        live.insert(channel_id);
        if commit.confirmed {
            spawn_owned_channel_handoff_completion(state, db, app_handle.clone(), channel_id);
            continue;
        }
        if channel_handoff_publish_in_flight(state, channel_id) {
            continue;
        }
        let last = state
            .channel_handoff_publishes
            .get(&channel_id)
            .map(|(_, at)| *at)
            .unwrap_or(0);
        match ember::channel::handoff_republish_due(commit.version, commit.committed_at, last, now) {
            ember::channel::HandoffRepublish::Publish => {
                state.channel_handoff_failure_noted.remove(&channel_id);
                publish_committed_channel_handoff(
                    socket,
                    state,
                    db,
                    &app_handle,
                    &ch,
                    channel_id,
                    &commit,
                )
                .await;
            }
            ember::channel::HandoffRepublish::Wait => {
                state.channel_handoff_failure_noted.remove(&channel_id);
            }
            ember::channel::HandoffRepublish::GiveUp => {
                if state.channel_handoff_failure_noted.insert(channel_id) {
                    let _ = app_handle.emit(
                        "ember:channel-handoff",
                        serde_json::json!({
                            "channel_id": channel_hex,
                            "phase": "failed",
                        }),
                    );
                }
            }
        }
    }
    state.channel_handoff_publishes.retain(|id, _| live.contains(id));
    state.channel_handoff_failure_noted.retain(|id| live.contains(id));
}

/// Move the room's registry name to the successor, signing with the old seed.
///
/// The successor's key has never held our name, and the new owner cannot sign
/// for one that is still ours, so this is the name's only way across.
///
/// Being the only chance, a blip does not get to cost the room its name for a
/// year: retry while the registry is merely unreachable, and give up at once on
/// a refusal, which retrying cannot change.
async fn hand_over_channel_name(
    url: &str,
    old_id: [u8; 16],
    successor_id: [u8; 16],
    successor_pk: [u8; 32],
    old_pk: [u8; 32],
    old_seed: [u8; 32],
) {
    for backoff_secs in [0u64, 3, 12, 45] {
        if backoff_secs > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
        }
        match crate::network::rendezvous::handover_channel_name(
            url,
            &old_id,
            &successor_id,
            &successor_pk,
            &old_pk,
            &old_seed,
        )
        .await
        {
            Ok(()) => return,
            Err(error @ crate::network::rendezvous::ChannelRegistryError::Unavailable) => {
                tracing::debug!(?error, "name handover to the successor did not land; retrying");
            }
            Err(error) => {
                tracing::debug!(?error, "the registry refused to hand the channel name over");
                return;
            }
        }
    }
}

pub(super) async fn send_channel_gossip_unicast(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    channel_id: [u8; 16],
    peer: [u8; 32],
    body: Vec<u8>,
) -> ChannelUnicast {
    // History catch-up, in both directions: automated mesh traffic rather than
    // anything the user typed, and it retries on its own timer, so it belongs
    // on the shared allowance and not the one reserved for a line that gets no
    // second attempt.
    //
    // Charged once, and only when some rung has a live path to try: this is
    // the allowance relaying the room's chat runs on, and a catch-up aimed at
    // an unreachable neighbor must not spend it on frames that never leave
    // this machine.
    let mut charged = false;
    // Same ladder as `send_xfer_frame`: a routing-table hit (including the
    // unverified replacement cache) is not a live path. History catch-up used
    // to return here after `get_contact`, which skipped overlay and the
    // WebSocket relay for every peer we merely had a lead for.
    let node_id = ember::dht::EmberNodeId(ember::channel::channel_id_from_pubkey(&peer));
    if let Some(contact) = state.ember_dht.routing().get_contact(&node_id).cloned() {
        if ember_has_live_session(state, &contact) {
            if !channel_gossip_rate_ok(state, false) {
                return ChannelUnicast::RateLimited;
            }
            charged = true;
            let (_rid, frame) = state.ember_dht.build_channel_msg(body.clone());
            if send_ember_dht_frame_established(socket, state, &contact, &frame).await {
                return ChannelUnicast::Sent;
            }
        }
    }
    if state.channel_relay_outboxes.contains_key(&peer) {
        if !charged && !channel_gossip_rate_ok(state, false) {
            return ChannelUnicast::RateLimited;
        }
        charged = true;
        if let Some((_, tx)) = state.channel_relay_outboxes.get(&peer) {
            if tx.try_send(body.clone()).is_ok() {
                return ChannelUnicast::Sent;
            }
        }
    }
    // Member hops only. The non-member fallback the fanout keeps is a frame to
    // a node that current builds make drop it, so here it would be charged to
    // the relay allowance and counted as a path for nothing.
    let roster = channel_member_pubkeys_cached(state, db, channel_id);
    let (hops, via_members) = overlay_channel_hops(state, &[peer], &roster);
    if hops.is_empty() || !via_members {
        return ChannelUnicast::NoPath;
    }
    if !charged && !channel_gossip_rate_ok(state, false) {
        return ChannelUnicast::RateLimited;
    }
    if overlay_send_channel_gossip(socket, state, &channel_id, &body, &[peer], &hops, via_members)
        .await
    {
        ChannelUnicast::Sent
    } else {
        ChannelUnicast::NoPath
    }
}

/// What became of one [`send_channel_gossip_unicast`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ChannelUnicast {
    Sent,
    /// No live session, relay tunnel or member hop reaches the peer.
    NoPath,
    /// A path exists but the shared relay allowance is spent for this second.
    /// Says nothing about the peer, so it must not count against them.
    RateLimited,
}

// --- Ember Transfer -------------------------------------------------------

/// Show a member's verified typing signal, or drop it.
///
/// The whole of what one does here: no storage, no presence touch, no relay,
/// and no dedup slot released on refusal, since nobody retransmits a typing
/// frame. Anything that entered the database would be something catch-up
/// could serve, and a signal is only true for the few seconds after it left.
pub(super) fn apply_channel_typing(
    state: &mut NetworkState,
    db: &Database,
    app_handle: &tauri::AppHandle,
    channel_id: [u8; 16],
    timestamp: i64,
    member: [u8; 32],
    typing: bool,
) {
    let local = state.local_ed25519_pubkey;
    let roster_status = channel_member_status_cached(state, db, channel_id, &member);
    let verdict = ember::channel::admit_channel_typing(
        &member,
        &local,
        roster_status,
        timestamp,
        chrono::Utc::now().timestamp(),
        || {
            ember::channel::typing_recv_allow(
                &mut state.channel_typing_recv_times,
                channel_id,
                &member,
                std::time::Instant::now(),
            )
        },
    );
    if let Err(reason) = verdict {
        debug!(
            "Ember channel gossip: dropped a typing signal in {} ({reason:?})",
            hex::encode(channel_id)
        );
        return;
    }
    let _ = app_handle.emit(
        "ember:channel-typing",
        serde_json::json!({
            "channel_id": hex::encode(channel_id),
            "member_pubkey": hex::encode(member),
            "typing": typing,
        }),
    );
}

/// Tell the members we hold a live session with that we are (or have stopped)
/// composing in `channel_id`. Fire-and-forget: nothing is queued or retried,
/// because a late typing signal is a wrong one.
pub(super) async fn send_channel_typing(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    channel_id: [u8; 16],
    typing: bool,
) {
    if db.chat_locked() {
        return;
    }
    let Some(view) = cached_channel_view(state, db, channel_id) else {
        return;
    };
    if !view.row.in_room_now() {
        return;
    }
    let local = state.local_ed25519_pubkey;
    // A banned member's frames are dropped by everyone, so sending would only
    // spend datagrams; the UI hides the composer in that state regardless.
    if channel_member_banned(state, db, channel_id, &local) {
        return;
    }
    let Some(key) = view.content_keys.first().copied() else {
        return;
    };
    let present = channel_member_pubkeys_cached(state, db, channel_id);
    let mut contacts: HashMap<[u8; 32], ember::dht::EmberContact> = HashMap::new();
    let Some(recipients) = ember::channel::typing_recipients(&local, &present, |pk| {
        let node_id = ember::dht::EmberNodeId(ember::channel::channel_id_from_pubkey(pk));
        let Some(contact) = state.ember_dht.routing().get_contact(&node_id).cloned() else {
            return false;
        };
        if !ember_has_live_session(state, &contact) {
            return false;
        }
        contacts.insert(*pk, contact);
        true
    }) else {
        return;
    };
    if recipients.is_empty() {
        return;
    }
    // Charged only once there is somebody to send to, so a room with nobody
    // reachable does not use up the allowance a moment later needs.
    if !ember::channel::typing_send_allow(
        &mut state.channel_typing_sent_times,
        channel_id,
        std::time::Instant::now(),
    ) {
        return;
    }
    let ts = chrono::Utc::now().timestamp();
    let mut msg_id = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut msg_id);
    let signing = ember::crypto::signing_key_from_bytes(&state.local_ed25519_seed);
    let plain =
        ember::channel::encode_channel_typing(&signing, &local, &channel_id, &msg_id, ts, typing);
    let body = ember::channel::ChannelGossip::sealed(
        channel_id,
        msg_id,
        &key,
        ts.max(0) as u64,
        &plain,
        ember::channel::CHANNEL_TYPING_TTL,
        ts,
    )
    .encode();
    // Seen before it leaves, so a peer echoing it back is dropped at dedup.
    let _ = remember_channel_gossip(state, msg_id);
    for pk in recipients {
        let Some(contact) = contacts.get(&pk) else {
            continue;
        };
        let (_rid, frame) = state.ember_dht.build_channel_msg(body.clone());
        send_ember_dht_frame_established(socket, state, contact, &frame).await;
    }
}

/// Apply a member's revision of their own line and pass it on.
///
/// Every check that decides whether the revision is legitimate is in
/// `apply_channel_message_edit`, so this path and a catch-up cannot disagree
/// about it. Relayed on the same terms as chat: refused for rate or for a banned
/// author, forwarded otherwise, and forwarded even when *we* refuse to apply it —
/// our window closing is a fact about this device's clock, not about the frame,
/// and a neighbour who was away may still legitimately accept it.
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_inbound_channel_edit(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    gossip: &ember::channel::ChannelGossip,
    channel_id_hex: &str,
    edit: ember::channel::ChannelChatEdit,
    from_id: ember::dht::EmberNodeId,
    opened: ember::channel::OpenedUnder,
) {
    if !channel_author_gossip_ok(state, gossip.channel_id, &edit.sender) {
        forget_channel_gossip(state, &gossip.msg_id);
        debug!("Ember channel edit: rate-limited author in {channel_id_hex}");
        return;
    }
    let sender_hex = hex::encode(edit.sender);
    if channel_member_banned(state, db, gossip.channel_id, &edit.sender) {
        return;
    }
    // A catch-up revision can create the line it revises, so it is held to the
    // same rule as a chat line under a retired key.
    if opened == ember::channel::OpenedUnder::Retired
        && !channel_member_on_roster(state, db, gossip.channel_id, &edit.sender)
    {
        forget_channel_gossip(state, &gossip.msg_id);
        return;
    }
    let cleaned = crate::security::sanitize_chat_text(&edit.text);
    if cleaned.is_empty() || cleaned.len() > 4096 {
        return;
    }
    // Only the text the author signed may be stored, so a body that does not
    // survive sanitising unchanged is dropped rather than silently altered — a
    // stored line that differs from its signature could never be re-served.
    if cleaned != edit.text {
        debug!("Ember channel edit: body in {channel_id_hex} did not survive sanitising");
        return;
    }
    let target_hex = hex::encode(edit.target_msg_id);
    let now = chrono::Utc::now().timestamp();
    match db.apply_channel_message_edit(
        channel_id_hex,
        &target_hex,
        &sender_hex,
        edit.original_timestamp,
        edit.edited_at,
        &cleaned,
        &hex::encode(edit.signature),
        now,
    ) {
        Ok(crate::storage::database::ChannelEditOutcome::Applied(id)) => {
            let _ = app_handle.emit(
                "ember:channel-message-edited",
                serde_json::json!({
                    "channel_id": channel_id_hex,
                    "id": id,
                    "msg_id": target_hex,
                    "message": ember::channel::chat_display_text(&cleaned),
                    "edited_at": edit.edited_at,
                }),
            );
        }
        Ok(crate::storage::database::ChannelEditOutcome::Created(id)) => {
            note_channel_sync_ingest(state, gossip.channel_id, gossip.ttl);
            // Catch-up serves a revised line as the revision alone, so this is
            // the first time the room has seen it at all. An edit event only
            // patches a bubble that is already on screen, which left the row
            // stored-but-invisible until the conversation was next remounted —
            // and stored unread, so the sidebar could light up for the room the
            // user was looking at. It is a new line here, so announce it as one
            // and let the live path append it and settle its unread state.
            let reply_to = ember::channel::chat_reply_parent_hex(&cleaned, &target_hex);
            let reply = reply_to
                .as_deref()
                .and_then(|parent| db.channel_reply_lookup(channel_id_hex, parent).ok())
                .unwrap_or_default();
            let _ = app_handle.emit(
                "ember:channel-message",
                serde_json::json!({
                    "id": id,
                    "channel_id": channel_id_hex,
                    "sender_pubkey": sender_hex,
                    "direction": "received",
                    "message": ember::channel::chat_display_text(&cleaned),
                    "timestamp": edit.original_timestamp,
                    "msg_id": target_hex,
                    "edited_at": edit.edited_at,
                    "reply_to": reply_to,
                    "reply_to_me": reply_parent_is_ours(
                        reply.parent.as_ref(),
                        &state.local_ed25519_pubkey,
                    ),
                    "reply_parent": reply.parent,
                    "reply_parent_deleted": reply.deleted,
                }),
            );
        }
        Ok(outcome) => {
            debug!("Ember channel edit in {channel_id_hex} not applied: {outcome:?}");
        }
        Err(error) => {
            debug!("Ember channel edit in {channel_id_hex} failed: {error}");
        }
    }
    if let Some(next) = gossip.decremented_ttl() {
        fanout_channel_gossip_body(socket, state, db, next.encode(), Some(from_id)).await;
    }
}

/// Record a batch of reactions and pass it on.
///
/// Rate is charged per *distinct member named in the batch*, not once for the
/// frame. Charging the frame to a single author would shed a member's own
/// reactions the moment somebody else's arrived beside them, which a catch-up
/// reply does by design; charging nothing at all would leave the per-hop budget
/// as the only bound, and at a full batch per frame that is over a thousand
/// database writes a second from one peer. Per member, a flood costs the flooder
/// their own allowance and nobody else's.
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_inbound_channel_reactions(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    gossip: &ember::channel::ChannelGossip,
    channel_id_hex: &str,
    entries: Vec<ember::channel::ChannelReaction>,
    from_id: ember::dht::EmberNodeId,
    opened: ember::channel::OpenedUnder,
) {
    let now = chrono::Utc::now().timestamp();
    let mut changed = false;
    // Charged once per member per frame — a batch legitimately carries several of
    // one member's reactions, and that is one round of work rather than one per
    // entry. The refused set is what makes the decision stick: keyed only on
    // "have we charged this member yet", a member who failed the check would have
    // every *later* entry of theirs in the same batch sail through.
    let mut allowed: HashSet<[u8; 32]> = HashSet::new();
    let mut refused: HashSet<[u8; 32]> = HashSet::new();
    for entry in entries {
        // A reaction dated in the future would pin itself against every later
        // claim under the newer-wins rule, which is the same trick
        // `gossip_timestamp_ok` exists to refuse for envelopes.
        if !ember::channel::gossip_timestamp_ok(entry.reacted_at, now) {
            continue;
        }
        if refused.contains(&entry.member) {
            continue;
        }
        if !allowed.contains(&entry.member) {
            if channel_author_gossip_ok(state, gossip.channel_id, &entry.member) {
                allowed.insert(entry.member);
            } else {
                refused.insert(entry.member);
                debug!("Ember channel reactions: rate-limited member in {channel_id_hex}");
                continue;
            }
        }
        let member_hex = hex::encode(entry.member);
        if channel_member_banned(state, db, gossip.channel_id, &entry.member) {
            continue;
        }
        if opened == ember::channel::OpenedUnder::Retired
            && !channel_member_on_roster(state, db, gossip.channel_id, &entry.member)
        {
            continue;
        }
        match db.set_channel_message_reaction(
            channel_id_hex,
            &hex::encode(entry.target_msg_id),
            &member_hex,
            entry.reaction,
            entry.reacted_at,
            &hex::encode(entry.signature),
        ) {
            Ok(true) => changed = true,
            Ok(false) => {}
            Err(error) => debug!("Ember channel reaction in {channel_id_hex} failed: {error}"),
        }
    }
    // One event for the batch: the UI re-reads the room's tallies rather than
    // patching a count per entry, so telling it once per frame is enough.
    if changed {
        let _ = app_handle.emit(
            "ember:channel-reactions",
            serde_json::json!({ "channel_id": channel_id_hex }),
        );
    }
    if let Some(next) = gossip.decremented_ttl() {
        fanout_channel_gossip_body(socket, state, db, next.encode(), Some(from_id)).await;
    }
}

pub(super) async fn reply_channel_history_sync(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    ch: &crate::storage::database::StoredChannel,
    to: [u8; 32],
    since_ts: i64,
) {
    let Some(key) = channel_content_key(db, ch) else {
        return;
    };
    let Ok(mut rows) = db.list_channel_messages_for_sync(
        &ch.channel_id,
        since_ts.max(0),
        ember::channel::CHANNEL_HISTORY_SYNC_MAX as i64,
    ) else {
        return;
    };
    // Serve in author order whichever way the rows were selected. A cold room is
    // answered with the *newest* lines, and sending those newest-first would give
    // the requester row ids that run backwards against their timestamps — the
    // transcript is paged by id, so its first screen would come out reversed.
    rows.sort_by_key(|row| (row.timestamp, row.msg_id.clone()));
    let Ok(id_bytes) = hex::decode(&ch.channel_id) else {
        return;
    };
    let Ok(channel_id) = <[u8; 16]>::try_from(id_bytes) else {
        return;
    };
    // Frames, not rows. A reply used to be one frame per line, so the message cap
    // was the whole budget; now a line may go out as a revision and the room's
    // reactions ride along behind, and the receiver sheds anything past
    // `CHANNEL_GOSSIP_IN_PER_PEER_PER_SEC` from one hop. Shedding is self-healing
    // — the requester's watermark does not advance past what it stored, so the
    // next round asks again — but spending the budget on lines first and
    // reactions with what is left is the order that makes a room readable
    // soonest.
    let mut budget = ember::channel::CHANNEL_HISTORY_SYNC_FRAME_MAX;
    let mut served: Vec<String> = Vec::with_capacity(rows.len());
    for row in rows {
        if budget == 0 {
            break;
        }
        let Ok(msg_id_bytes) = hex::decode(&row.msg_id) else {
            continue;
        };
        let Ok(msg_id) = <[u8; 16]>::try_from(msg_id_bytes) else {
            continue;
        };
        let Ok(sender_bytes) = hex::decode(&row.sender_pubkey) else {
            continue;
        };
        let Ok(sender_pk) = <[u8; 32]>::try_from(sender_bytes) else {
            continue;
        };
        // Replaying the author's own signature, never one of ours. This loop
        // re-serves lines other members wrote, so signing here would let any
        // node answer a catch-up with a conversation that never happened.
        //
        // A revised line goes out as the revision alone. The edit frame carries
        // the original's timestamp so it stands on its own, and serving the
        // superseded text as well would put words back on the wire that their
        // author has already replaced.
        //
        // A revision also needs a *fresh* envelope id, where a plain re-serve
        // must keep the original's. The two signatures differ on purpose: a
        // chat signature covers the envelope id, so replaying one under a new
        // id would not verify — and a peer who already holds that line is right
        // to drop the repeat. An edit signature covers only the line it
        // revises, and every peer worth serving already has the original, so
        // reusing that id here put the revision behind their duplicate filter
        // and the edit never arrived.
        let (plain, envelope_id) = if row.edited_at > 0 && !row.edit_sig.is_empty() {
            let Ok(sig_bytes) = hex::decode(&row.edit_sig) else {
                continue;
            };
            let Ok(edit_sig) = <[u8; 64]>::try_from(sig_bytes) else {
                continue;
            };
            let mut envelope_id = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut envelope_id);
            (
                ember::channel::encode_channel_chat_edit_presigned(
                    &sender_pk,
                    &msg_id,
                    row.timestamp,
                    row.edited_at,
                    &edit_sig,
                    &row.message,
                ),
                envelope_id,
            )
        } else {
            let Ok(sig_bytes) = hex::decode(&row.author_sig) else {
                continue;
            };
            let Ok(author_sig) = <[u8; 64]>::try_from(sig_bytes) else {
                continue;
            };
            (
                ember::channel::encode_channel_chat_plain_presigned(
                    &sender_pk,
                    &author_sig,
                    &row.message,
                ),
                msg_id,
            )
        };
        let gossip = ember::channel::ChannelGossip::sealed(
            channel_id,
            envelope_id,
            &key,
            row.timestamp.max(0) as u64,
            &plain,
            1,
            row.timestamp,
        );
        // Every later frame would meet the same missing path or spent budget.
        if send_channel_gossip_unicast(socket, state, db, channel_id, to, gossip.encode()).await
            != ChannelUnicast::Sent
        {
            break;
        }
        budget -= 1;
        served.push(row.msg_id);
    }
    if budget > 0 && !served.is_empty() {
        reply_channel_reaction_sync(socket, state, db, ch, to, channel_id, &key, &served, budget)
            .await;
    }
}

/// Hand a catching-up member the reactions on the lines we just served.
///
/// Batched hard, because one datagram per reaction would exhaust the receiver's
/// per-hop allowance on a busy room before any of them landed. Cleared reactions
/// travel too: a member who missed both a reaction and its withdrawal needs the
/// withdrawal, or they show a thumb its owner has taken back.
#[allow(clippy::too_many_arguments)]
pub(super) async fn reply_channel_reaction_sync(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    ch: &crate::storage::database::StoredChannel,
    to: [u8; 32],
    channel_id: [u8; 16],
    key: &[u8; 32],
    served: &[String],
    mut budget: usize,
) {
    let want = budget.saturating_mul(ember::channel::CHANNEL_REACTION_MAX_PER_FRAME);
    let Ok(rows) = db.list_channel_reactions_for_sync(&ch.channel_id, served, want as i64) else {
        return;
    };
    let mut batch: Vec<ember::channel::ChannelReaction> = Vec::new();
    let mut flush_at = ember::channel::CHANNEL_REACTION_MAX_PER_FRAME;
    for (msg_id_hex, member_hex, reaction, reacted_at, sig_hex) in rows {
        let Ok(target) = hex::decode(&msg_id_hex).and_then(|b| {
            <[u8; 16]>::try_from(b).map_err(|_| hex::FromHexError::InvalidStringLength)
        }) else {
            continue;
        };
        let Ok(member) = hex::decode(&member_hex).and_then(|b| {
            <[u8; 32]>::try_from(b).map_err(|_| hex::FromHexError::InvalidStringLength)
        }) else {
            continue;
        };
        let Ok(signature) = hex::decode(&sig_hex).and_then(|b| {
            <[u8; 64]>::try_from(b).map_err(|_| hex::FromHexError::InvalidStringLength)
        }) else {
            continue;
        };
        batch.push(ember::channel::ChannelReaction {
            target_msg_id: target,
            member,
            reaction,
            reacted_at,
            signature,
        });
        if batch.len() >= flush_at {
            if !send_channel_reaction_batch(socket, state, db, channel_id, to, key, &batch).await {
                return;
            }
            batch.clear();
            budget -= 1;
            if budget == 0 {
                return;
            }
            flush_at = ember::channel::CHANNEL_REACTION_MAX_PER_FRAME;
        }
    }
    if !batch.is_empty() && budget > 0 {
        send_channel_reaction_batch(socket, state, db, channel_id, to, key, &batch).await;
    }
}

/// Seal and unicast one reaction batch. Returns whether it went out.
pub(super) async fn send_channel_reaction_batch(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    channel_id: [u8; 16],
    to: [u8; 32],
    key: &[u8; 32],
    batch: &[ember::channel::ChannelReaction],
) -> bool {
    let plain = ember::channel::encode_channel_reactions(batch);
    let now = chrono::Utc::now().timestamp();
    let mut envelope_id = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut envelope_id);
    let gossip = ember::channel::ChannelGossip::sealed(
        channel_id,
        envelope_id,
        key,
        now.max(0) as u64,
        &plain,
        1,
        now,
    );
    send_channel_gossip_unicast(socket, state, db, channel_id, to, gossip.encode()).await
        == ChannelUnicast::Sent
}

/// How long this neighbor's last ask holds before we may ask again.
///
/// The short walk interval while catch-up lines have landed since we asked
/// them — a backlog is being fed to us and the next batch is waiting — and the
/// idle interval otherwise. Falling back to `interval` when no mark is
/// recorded keeps a fresh stamp behaving exactly as it did before.
///
/// A neighbor whose last attempts found no path at all is on its own backoff
/// instead: short at first, since a session may be moments from coming up,
/// and doubling until it is no more often than an idle neighbor.
pub(super) fn history_sync_gate(
    state: &NetworkState,
    channel_id: [u8; 16],
    peer: &[u8; 32],
    interval: std::time::Duration,
    walk: std::time::Duration,
) -> std::time::Duration {
    if let Some(failures) = state
        .channel_history_sync_failures
        .get(&(channel_id, *peer))
        .copied()
        .filter(|failures| *failures > 0)
    {
        return std::time::Duration::from_secs(ember::channel::history_sync_retry_secs(failures))
            .min(interval);
    }
    let ingested = state
        .channel_history_sync_ingested
        .get(&channel_id)
        .copied()
        .unwrap_or(0);
    let mark = state.channel_history_sync_mark.get(&(channel_id, *peer)).copied();
    if ember::channel::history_sync_walking(mark, ingested) {
        walk
    } else {
        interval
    }
}

/// Count a stored line toward the room's catch-up progress when it arrived
/// the way a catch-up reply sends it.
pub(super) fn note_channel_sync_ingest(state: &mut NetworkState, channel_id: [u8; 16], ttl: u8) {
    if ember::channel::gossip_is_catch_up_shaped(ttl) {
        let count = state.channel_history_sync_ingested.entry(channel_id).or_insert(0);
        *count = count.saturating_add(1);
    }
}

pub(super) async fn maybe_sync_channel_history(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    settings: &AppSettings,
) {
    if !settings.ember_native_enabled || db.chat_locked() {
        return;
    }
    let Some(channels) = channels_lite_cached(state, db) else {
        return;
    };
    let now = std::time::Instant::now();
    let interval = std::time::Duration::from_secs(ember::channel::CHANNEL_HISTORY_SYNC_SECS);
    let walk = std::time::Duration::from_secs(ember::channel::CHANNEL_HISTORY_WALK_SECS);
    let our_pk = state.local_ed25519_pubkey;
    let focused_hex = state.channel_focused.map(hex::encode);
    let mut rooms: Vec<&crate::storage::database::StoredChannel> = channels
        .iter()
        .filter(|ch| ch.in_room_now())
        .collect();
    rooms.sort_by_key(|ch| {
        if focused_hex
            .as_ref()
            .is_some_and(|id| ch.channel_id.eq_ignore_ascii_case(id))
        {
            0
        } else {
            1
        }
    });
    prune_channel_history_sync_stamps(state, &rooms, now, interval);
    let mut attempts = 0usize;
    'rooms: for ch in rooms {
        if attempts >= ember::channel::CHANNEL_HISTORY_SYNC_ATTEMPTS_PER_TICK {
            break;
        }
        let Ok(id_bytes) = hex::decode(&ch.channel_id) else {
            continue;
        };
        let Ok(channel_id) = <[u8; 16]>::try_from(id_bytes) else {
            continue;
        };
        // Cheap per-room gate: if every neighbor slot was asked recently,
        // skip loading the roster. A room with fewer stamps may have grown
        // new XOR-neighbors and still needs the member list. A slot that has
        // had catch-up lines land since the ask is not "recent" for this
        // purpose — that neighbor is mid-walk and gets the shorter interval.
        // Ahead of every query: this runs each second for every joined room.
        let recent_stamps = state
            .channel_history_sync_at
            .iter()
            .filter(|((cid, pk), at)| {
                if *cid != channel_id {
                    return false;
                }
                let gate = history_sync_gate(state, channel_id, pk, interval, walk);
                now.saturating_duration_since(**at) < gate
            })
            .count();
        if recent_stamps >= ember::channel::CHANNEL_NEIGHBOR_COUNT {
            continue;
        }
        let members = channel_member_pubkeys_cached(state, db, channel_id);
        // Same set the fanout uses, so catch-up reaches across the id space
        // instead of asking the same local cluster the flood already covered.
        let neighbors = ember::channel::gossip_neighbors(
            &our_pk,
            &members,
            ember::channel::CHANNEL_NEIGHBOR_COUNT,
        );
        let due: Vec<[u8; 32]> = neighbors
            .into_iter()
            .filter(|pk| {
                let stamp_key = (channel_id, *pk);
                let gate = history_sync_gate(state, channel_id, pk, interval, walk);
                !state
                    .channel_history_sync_at
                    .get(&stamp_key)
                    .is_some_and(|at| now.saturating_duration_since(*at) < gate)
            })
            .collect();
        if due.is_empty() {
            continue;
        }
        let Some(key) = channel_content_key(db, ch) else {
            continue;
        };
        let wall = chrono::Utc::now().timestamp();
        let latest = db
            .latest_channel_message_timestamp(&ch.channel_id)
            .unwrap_or(0)
            .min(wall)
            .max(0);
        let ingested = state
            .channel_history_sync_ingested
            .get(&channel_id)
            .copied()
            .unwrap_or(0);
        // Ask from the frontier, not from a window behind it. Asking for the
        // last six hours got the same newest 32 lines back every round: the
        // watermark is `MAX(timestamp)`, so storing that batch advanced it past
        // everything still missing underneath, and a gap wider than 32 lines
        // was never recoverable. A responder serves oldest-first for any
        // non-zero watermark, so each round now walks the hole forward instead.
        let since = latest;
        let signing = ember::crypto::signing_key_from_bytes(&state.local_ed25519_seed);
        for pk in due {
            if attempts >= ember::channel::CHANNEL_HISTORY_SYNC_ATTEMPTS_PER_TICK {
                break;
            }
            let stamp_key = (channel_id, pk);
            let ts = chrono::Utc::now().timestamp();
            let mut msg_id = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut msg_id);
            let plain = ember::channel::encode_channel_sync_request(
                &signing,
                &our_pk,
                &channel_id,
                &msg_id,
                ts,
                since,
            );
            let gossip = ember::channel::ChannelGossip::sealed(
                channel_id,
                msg_id,
                &key,
                ts.max(0) as u64,
                &plain,
                1,
                ts,
            );
            // Stamped on the attempt, not the send: this runs every second, and
            // an unreachable neighbor must wait out its backoff rather than be
            // due again on the next tick.
            attempts += 1;
            let previous = state.channel_history_sync_at.insert(stamp_key, now);
            match send_channel_gossip_unicast(socket, state, db, channel_id, pk, gossip.encode())
                .await
            {
                ChannelUnicast::Sent => {
                    state.channel_history_sync_failures.remove(&stamp_key);
                    // Catch-up progress as it stood when we asked. If more has
                    // landed by the next pass, a reply brought lines and the
                    // walk interval applies instead of the idle one.
                    state.channel_history_sync_mark.insert(stamp_key, ingested);
                }
                ChannelUnicast::NoPath => {
                    let failures = state
                        .channel_history_sync_failures
                        .entry(stamp_key)
                        .or_insert(0);
                    *failures = failures.saturating_add(1);
                }
                // Our budget, not their reachability: the ask never happened,
                // so it stays due, and nothing else this tick will fare better.
                ChannelUnicast::RateLimited => {
                    match previous {
                        Some(at) => state.channel_history_sync_at.insert(stamp_key, at),
                        None => state.channel_history_sync_at.remove(&stamp_key),
                    };
                    break 'rooms;
                }
            }
        }
    }
}

/// Drop catch-up bookkeeping that can no longer gate anything.
///
/// A stamp past `interval` is due under every gate, so it only still matters
/// while it carries a failure count — that is what keeps a neighbor that
/// stays unreachable at the top of its backoff rather than starting over.
/// Twice the interval covers that, since an attempt at the capped backoff
/// re-stamps it well before then. Rooms we have left go at once. The walk
/// marks and failure counts mean nothing without their stamp.
pub(super) fn prune_channel_history_sync_stamps(
    state: &mut NetworkState,
    rooms: &[&crate::storage::database::StoredChannel],
    now: std::time::Instant,
    interval: std::time::Duration,
) {
    if state.channel_history_sync_at.is_empty()
        && state.channel_history_sync_mark.is_empty()
        && state.channel_history_sync_failures.is_empty()
    {
        return;
    }
    let joined: HashSet<[u8; 16]> = rooms
        .iter()
        .filter_map(|ch| {
            hex::decode(&ch.channel_id)
                .ok()
                .and_then(|b| <[u8; 16]>::try_from(b).ok())
        })
        .collect();
    let failures = &state.channel_history_sync_failures;
    state.channel_history_sync_at.retain(|key, at| {
        let keep_for = if failures.get(key).is_some_and(|n| *n > 0) {
            interval.saturating_mul(2)
        } else {
            interval
        };
        joined.contains(&key.0) && now.saturating_duration_since(*at) < keep_for
    });
    let stamps = &state.channel_history_sync_at;
    state
        .channel_history_sync_mark
        .retain(|key, _| stamps.contains_key(key));
    state
        .channel_history_sync_failures
        .retain(|key, _| stamps.contains_key(key));
}
