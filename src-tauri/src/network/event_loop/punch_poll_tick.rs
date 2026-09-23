//! The punch mailbox responder: answers hole-punch requests from the rendezvous
//! server, polling every tick while a transfer punch is in flight.

use super::*;

/// Idle cadence for the same poll, preserving the old behaviour when no
/// transfer punch is pending so an idle client does not poll every 3 s.
const PUNCH_POLL_IDLE_SECS: u64 = 60;

pub(in crate::network) async fn on_punch_poll_tick(
    state: &NetworkState,
    settings: &AppSettings,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    ember_hash: [u8; 16],
    ed25519_secret_key: [u8; 32],
    inbound_stream_tx: &mpsc::Sender<upload_server::InboundStreamRequest>,
    last_punch_poll: &mut Option<tokio::time::Instant>,
) {
    // Adaptive gate: poll every tick while a transfer punch is in
    // flight in either direction, otherwise fall back to the
    // historical idle cadence.
    //
    // Both roles need the fast cadence. The uploader polls to learn
    // where to dial; the downloader polls to find the uploader's
    // reciprocal registration and dial *out* itself, which is what
    // opens its own NAT mapping toward the uploader — without that
    // outbound packet the uploader's stream would be dropped by the
    // downloader's NAT.
    let now = tokio::time::Instant::now();
    let owe_serve_punch = !state.friend_xfer_punch_serve.is_empty();
    let awaiting_punch = state.friend_xfer_attempts.values().any(|attempt| {
        matches!(attempt.transport, FriendXferTransport::Punch { .. })
            && now
                .duration_since(tokio::time::Instant::from_std(attempt.sent_at))
                .as_secs()
                < FRIEND_XFER_ATTEMPT_TIMEOUT_SECS
    });
    let idle_due = last_punch_poll.is_none_or(|last| {
        now.duration_since(last) >= std::time::Duration::from_secs(PUNCH_POLL_IDLE_SECS)
    });
    if !owe_serve_punch && !awaiting_punch && !idle_due {
        return;
    }
    *last_punch_poll = Some(now);

    // Poll signed v2 punch requests addressed to our registered
    // Ember identity. Only known friends are accepted; anonymous
    // LowID sources bypass punch and use relay.
    if state.rendezvous_registered {
        if let (Some(_ext_ip), Some(broker)) =
            (state.external_ip, state.connection_broker.as_ref())
        {
            if let Some(endpoint) = broker.quic_endpoint().cloned() {
                // Friends we owe an uploader-role punch, keyed by the
                // same hashed rendezvous id the mailbox reports, so
                // the task can match without re-deriving.
                let punch_serve_friends: HashMap<String, [u8; 16]> = state
                    .friend_xfer_punch_serve
                    .keys()
                    .map(|hash| (rendezvous::hashed_id(hash), *hash))
                    .collect();
                let known_punch_friends: HashMap<String, [u8; 16]> = friend_hashes
                    .read()
                    .await
                    .iter()
                    .map(|hash| (rendezvous::hashed_id(hash), *hash))
                    .collect();
                let our_punch_hash = ember_hash;
                let punch_secret = ed25519_secret_key;
                // The port we ask the initiator to dial back on IS
                // the QUIC port (opposite of the id above): this is
                // the payload value carried in the signed v2 punch record,
                // not the lookup key, and the initiator's
                // `punch_quic` call connects over QUIC — so it must
                // land on our actual QUIC socket, not the
                // NAT-probed KAD UDP port `nat_info.external_addr`
                // reflects. Behind a re-mapping NAT the bound port
                // isn't reachable either, hence the public one.
                let advertised_quic_port =
                    advertised_quic_port(state).unwrap_or(state.tcp_port);
                let rv_url = settings.rendezvous_url.clone();
                let our_nat_type = state.nat_info.nat_type;
                let our_ext_addr = state.nat_info.external_addr;
                let punch_cb_tx = inbound_stream_tx.clone();
                tokio::spawn(async move {
                    let info = match ember::relay::poll_punch(
                        &rv_url,
                        &our_punch_hash,
                        &punch_secret,
                    ).await {
                        Ok(Some(info)) => info,
                        Ok(None) => return,
                        Err(e) => {
                            tracing::trace!("Punch responder poll: {e}");
                            return;
                        }
                    };
                    let Some(friend_hash) = known_punch_friends.get(&info.from_id).copied() else {
                        let _ = ember::relay::ack_punch(
                            &rv_url,
                            &our_punch_hash,
                            &info.punch_id,
                            &info.capability,
                            info.epoch,
                            &punch_secret,
                        ).await;
                        return;
                    };
                    let expected_capability =
                        match rendezvous::fetch_identity_pubkey_authenticated(
                            &rv_url,
                            &friend_hash,
                            &our_punch_hash,
                            &ed25519_dalek::SigningKey::from_bytes(&punch_secret)
                                .verifying_key()
                                .to_bytes(),
                            &punch_secret,
                        )
                        .await
                        {
                            Ok(Some(pubkey)) => {
                                let owner_pubkey =
                                    ed25519_dalek::SigningKey::from_bytes(
                                        &punch_secret,
                                    )
                                    .verifying_key()
                                    .to_bytes();
                                ember::crypto::derive_pairwise_presence_capability(
                                    &punch_secret,
                                    &pubkey,
                                    &owner_pubkey,
                                    info.epoch,
                                )
                            }
                            _ => None,
                        };
                    if expected_capability != Some(info.capability) {
                        let _ = ember::relay::ack_punch(
                            &rv_url,
                            &our_punch_hash,
                            &info.punch_id,
                            &info.capability,
                            info.epoch,
                            &punch_secret,
                        )
                        .await;
                        return;
                    }
                    let Ok(ip) = info.ip.parse::<std::net::IpAddr>() else {
                        let _ = ember::relay::ack_punch(
                            &rv_url,
                            &our_punch_hash,
                            &info.punch_id,
                            &info.capability,
                            info.epoch,
                            &punch_secret,
                        )
                        .await;
                        return;
                    };
                    let routable = match ip {
                        std::net::IpAddr::V4(v4) => !crate::security::is_special_use_v4(v4),
                        std::net::IpAddr::V6(_) => !crate::security::is_private_ip(ip),
                    };
                    if !routable || info.port == 0 {
                        tracing::debug!(
                            "Punch responder: ignoring non-routable initiator {ip}:{}",
                            info.port
                        );
                        let _ = ember::relay::ack_punch(
                            &rv_url,
                            &our_punch_hash,
                            &info.punch_id,
                            &info.capability,
                            info.epoch,
                            &punch_secret,
                        )
                        .await;
                        return;
                    }
                    let initiator_addr = SocketAddr::new(ip, info.port);
                    tracing::info!(
                        "Punch responder: reciprocating for initiator {} at {initiator_addr}",
                        &info.from_id[..8.min(info.from_id.len())]
                    );

                    // Reciprocate so the initiator's own `poll_punch`
                    // (keyed on its own id) finds us and learns our
                    // real external address to dial. The registered
                    // port is our QUIC port, not `our_addr.port()`
                    // (the KAD UDP NAT mapping) — the initiator
                    // dials this port over QUIC, not UDP/KAD.
                    if let Some(ext_addr) = our_ext_addr {
                        if let Err(e) = ember::relay::register_punch_with_ip(
                            &rv_url,
                            &our_punch_hash,
                            &friend_hash,
                            advertised_quic_port,
                            our_nat_type.as_u8(),
                            ext_addr.ip(),
                            &punch_secret,
                            &our_punch_hash,
                        ).await {
                            tracing::debug!("Punch responder: reciprocal register failed: {e}");
                        }
                    } else {
                        tracing::debug!("Punch responder: no external address known yet, skipping reciprocal register");
                    }

                    // Also dial out ourselves. If this succeeds, treat
                    // it as a normal inbound connection — we remain the
                    // upload/server role at the eD2K protocol level
                    // (the initiator sends OP_HELLO first regardless
                    // of which side's transport-level `connect()` won
                    // the race), so hand the punched stream to the
                    // upload listener's inbound-stream path rather
                    // than the download-adoption `kad_callback_tx`
                    // (which has no consumer for a connection with no
                    // matching active download / zero file hash). If
                    // it fails, that's fine: the initiator's own
                    // connect attempt may still land in our
                    // already-running QUIC accept loop.
                    //
                    // The one exception is a punch we ourselves
                    // agreed to as the *uploader* of a friend
                    // transfer: there the friend is the downloader
                    // and is waiting for OUR Hello, so this stream
                    // must take the serve role instead. Without
                    // this both sides would wait on each other.
                    // There is a single punch mailbox per identity
                    // with 5 s leases, so this decision has to be
                    // made here rather than by a second poller
                    // competing for the same entries.
                    let serve_friend = punch_serve_friends
                        .get(&info.from_id)
                        .copied();
                    // Pin to the initiator's node id: `friend_hash`
                    // came from `known_punch_friends` keyed on
                    // `info.from_id`, and the pairwise presence
                    // capability was verified above, so the peer's
                    // identity is established from a signed source
                    // before we dial back.
                    match ember::broker::punch_quic_pinned(
                        &endpoint,
                        initiator_addr,
                        &punch_secret,
                        friend_hash,
                    )
                    .await
                    {
                        Ok((send, recv)) => {
                            if serve_friend.is_some() {
                                tracing::info!(
                                    "Punch responder: taking the serve role for friend transfer with {}",
                                    &info.from_id[..8.min(info.from_id.len())]
                                );
                            }
                            let req = crate::network::ed2k::upload::InboundStreamRequest {
                                peer_addr: initiator_addr,
                                reader: Box::new(recv),
                                writer: Box::new(send),
                                serve_friend_ember_hash: serve_friend,
                                relayed: false,
                            };
                            if let Err(e) = punch_cb_tx.try_send(req) {
                                tracing::debug!("Punch responder: dropping punched stream: {e}");
                            }
                        }
                        Err(e) => {
                            tracing::debug!(
                                "Punch responder: outbound punch to {initiator_addr} failed (initiator's own connect may still land): {e}"
                            );
                        }
                    }
                    let _ = ember::relay::ack_punch(
                        &rv_url,
                        &our_punch_hash,
                        &info.punch_id,
                        &info.capability,
                        info.epoch,
                        &punch_secret,
                    ).await;
                });
            }
        }
    }

}
