//! Answering the friend relay tickets a background rendezvous poll returned:
//! filtering offers to real friends and channel members, and starting a
//! bounded number of relay join sessions.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_friend_relay_ticket_poll_result(
    result: FriendRelayTicketPollResult,
    state: &mut NetworkState,
    settings: &AppSettings,
    db: &Arc<Database>,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    ember_hash: [u8; 16],
    ed25519_secret_key: [u8; 32],
    channel_relay_event_tx: &mpsc::UnboundedSender<ChannelRelayEvent>,
    friend_relay_ticket_poll_not_before: &mut tokio::time::Instant,
    friend_relay_ticket_poll_retry_delay: &mut std::time::Duration,
    friend_relay_ticket_poll_round_started_at: &mut Option<tokio::time::Instant>,
    friend_relay_ticket_poll_timer: &mut tokio::time::Interval,
    friend_relay_ticket_polls_in_flight: &mut usize,
    friend_relay_ticket_session_done_tx: &mpsc::UnboundedSender<String>,
    friend_relay_ticket_sessions_in_flight: &mut HashSet<String>,
    inbound_stream_tx: &mpsc::Sender<upload_server::InboundStreamRequest>,
) {
    *friend_relay_ticket_polls_in_flight =
        friend_relay_ticket_polls_in_flight.saturating_sub(1);
    let page = match result.result {
        Ok(page) => page,
        Err(e) => {
            tracing::trace!("Friend relay ticket poll: {e}");
            if rendezvous::is_transient_relay_ticket_read_error(&e)
                || e.contains("timed out")
            {
                *friend_relay_ticket_poll_not_before =
                    tokio::time::Instant::now()
                        + *friend_relay_ticket_poll_retry_delay;
                *friend_relay_ticket_poll_retry_delay =
                    (*friend_relay_ticket_poll_retry_delay * 2)
                        .min(std::time::Duration::from_secs(5));
            }
            return;
        }
    };
    *friend_relay_ticket_poll_retry_delay = std::time::Duration::from_secs(1);
    if *friend_relay_ticket_polls_in_flight == 0 {
        let now = tokio::time::Instant::now();
        let delay = friend_relay_ticket_poll_round_started_at
            .take()
            .map(|started_at| relay_ticket_next_round_delay(started_at, now))
            .unwrap_or(rendezvous::FRIEND_RELAY_TICKET_RESPONDER_POLL_INTERVAL);
        // Reset to the scheduled cadence boundary, not
        // immediately: fast responses must never create a
        // tight poll loop, while a completion just after a
        // missed tick can still begin the next round now.
        *friend_relay_ticket_poll_not_before = now + delay;
        friend_relay_ticket_poll_timer.reset_after(delay);
    }
    let offers = page.tickets;

    // The server only sees identities, not local friend
    // relationships. Filter offers locally, then keep at most the
    // accepted-ticket capacity worth of join/session tasks alive.
    //
    // Rosters are read at most once per room per response. A peer
    // that can enqueue many tickets for one room used to turn a
    // single poll into one `list_channel_members` query per
    // ticket, each taking the global connection lock on the
    // network loop.
    let mut rosters: HashMap<[u8; 16], Vec<[u8; 32]>> = HashMap::new();
    for offer in offers {
        if let Some(channel_id) = offer.channel_id {
            if state.channel_relay_outboxes.len()
                + state.channel_relay_pending.len()
                >= MAX_CHANNEL_RELAY_SESSIONS
            {
                continue;
            }
            let members = rosters.entry(channel_id).or_insert_with(|| {
                channel_member_pubkeys(db, &hex::encode(channel_id))
            });
            let Some(peer_pubkey) = members.iter().copied().find(|pk| {
                let hash = ember::channel::channel_id_from_pubkey(pk);
                rendezvous::hashed_id(&hash)
                    .eq_ignore_ascii_case(&offer.initiator_id)
            }) else {
                tracing::debug!(
                    "Ignoring channel relay ticket from an unknown member"
                );
                continue;
            };
            // Keyed by peer, not only by `ticket_id`. The in-flight
            // set below is per ticket, so it never stopped a second
            // session to the *same peer* from a different ticket —
            // which is exactly what a mutual simultaneous offer
            // produces, since this side's own outbound offer is in
            // negotiation at the same time.
            if state.channel_relay_outboxes.contains_key(&peer_pubkey)
                || state.channel_relay_pending.contains(&peer_pubkey)
            {
                continue;
            }
            let ticket_id = offer.ticket_id;
            if !friend_relay_ticket_sessions_in_flight.insert(ticket_id.clone()) {
                continue;
            }
            state.channel_relay_pending.insert(peer_pubkey);
            let rv_url = settings.rendezvous_url.clone();
            let done_tx = friend_relay_ticket_session_done_tx.clone();
            let event_tx = channel_relay_event_tx.clone();
            let fc_our_ember_hash = ember_hash;
            let session_id = next_channel_relay_session_id();
            tokio::spawn(async move {
                // Clears `channel_relay_pending` however this task
                // ends, including the accept failures below.
                let _session = ChannelRelaySessionGuard {
                    event_tx: event_tx.clone(),
                    peer_pubkey,
                    session_id,
                };
                let responder_token = match tokio::time::timeout(
                    rendezvous::FRIEND_RELAY_TICKET_ACTION_TIMEOUT,
                    rendezvous::accept_friend_relay_ticket(
                        &rv_url,
                        &fc_our_ember_hash,
                        &ticket_id,
                        &ed25519_secret_key,
                    ),
                )
                .await
                {
                    Ok(Ok(token)) => token,
                    Ok(Err(e)) => {
                        tracing::debug!("Channel relay ticket accept failed: {e}");
                        let _ = done_tx.send(ticket_id);
                        return;
                    }
                    Err(_) => {
                        tracing::debug!("Channel relay ticket accept timed out");
                        let _ = done_tx.send(ticket_id);
                        return;
                    }
                };
                match ember::relay::connect_server_relay(
                    &rv_url,
                    &ticket_id,
                    &responder_token,
                )
                .await
                {
                    Ok(ws) => {
                        // The ticket is spent once joined, and the session's
                        // own lifetime is bounded by `channel_relay_pending` /
                        // `channel_relay_outboxes` against
                        // `MAX_CHANNEL_RELAY_SESSIONS`. Held until the session
                        // ended (up to the server's 30-minute cap), room
                        // sessions filled the slots friend tickets count
                        // against, and two friends behind NAT could not meet.
                        let _ = done_tx.send(ticket_id);
                        run_channel_relay_session(
                            ws, peer_pubkey, session_id, event_tx,
                        )
                        .await;
                    }
                    Err(e) => {
                        tracing::debug!("Channel relay ticket join failed: {e}");
                        let _ = done_tx.send(ticket_id);
                    }
                }
            });
            continue;
        }

        if friend_relay_ticket_sessions_in_flight.len()
            >= MAX_FRIEND_RELAY_TICKET_SESSIONS
        {
            break;
        }
        let peer_ember_hash = {
            let friends = friend_hashes.read().await;
            friends.iter().copied().find(|hash| {
                rendezvous::hashed_id(hash)
                    .eq_ignore_ascii_case(&offer.initiator_id)
            })
        };
        let Some(peer_ember_hash) = peer_ember_hash else {
            tracing::debug!("Ignoring relay ticket from a non-friend identity");
            continue;
        };

        let ticket_id = offer.ticket_id;
        if !friend_relay_ticket_sessions_in_flight.insert(ticket_id.clone()) {
            continue;
        }

        let rv_url = settings.rendezvous_url.clone();
        let done_tx = friend_relay_ticket_session_done_tx.clone();
        let fc_our_ember_hash = ember_hash;
        let relay_inbound_tx = inbound_stream_tx.clone();

        tokio::spawn(async move {
            let responder_token = match tokio::time::timeout(
                rendezvous::FRIEND_RELAY_TICKET_ACTION_TIMEOUT,
                rendezvous::accept_friend_relay_ticket(
                    &rv_url,
                    &fc_our_ember_hash,
                    &ticket_id,
                    &ed25519_secret_key,
                ),
            )
            .await
            {
                Ok(Ok(token)) => token,
                Ok(Err(e)) => {
                    tracing::debug!("Friend relay ticket accept failed: {e}");
                    let _ = done_tx.send(ticket_id);
                    return;
                }
                Err(_) => {
                    tracing::debug!("Friend relay ticket accept timed out");
                    let _ = done_tx.send(ticket_id);
                    return;
                }
            };

            match ember::relay::connect_server_relay(
                &rv_url,
                &ticket_id,
                &responder_token,
            )
            .await
            {
                Ok(ws) => {
                    let (reader, writer) = tokio::io::split(ws);
                    let addr = SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        0,
                    );
                    if let Err(e) = relay_inbound_tx
                        .send(upload_server::InboundStreamRequest {
                            peer_addr: addr,
                            reader: Box::new(reader),
                            writer: Box::new(writer),
                            // Social relay session: the friend that
                            // opened it sends Hello first.
                            serve_friend_ember_hash: None,
                            relayed: true,
                        })
                        .await
                    {
                        tracing::debug!(
                            "Friend relay responder handoff failed for {}: {e}",
                            hex::encode(peer_ember_hash),
                        );
                    }
                }
                Err(e) => {
                    tracing::debug!("Friend relay ticket join failed: {e}");
                }
            }
            let _ = done_tx.send(ticket_id);
        });
    }
}
