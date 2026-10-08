//! The 200 ms connection-broker tick: advances punch and relay attempts and
//! drains the broker's events.

use super::*;

pub(in crate::network) async fn on_broker_tick(
    state: &mut NetworkState,
    settings: &AppSettings,
    ember_hash: [u8; 16],
    ed25519_pubkey: [u8; 32],
    ed25519_secret_key: [u8; 32],
    kad_callback_tx: &mpsc::Sender<upload_server::KadCallbackParts>,
) {
    // Not gated on KAD status: the broker serves friend connections
    // over rendezvous, which has nothing to do with Kademlia, and
    // an eD2K-only session never leaves `Disconnected`. Both halves
    // below are already no-ops when no broker exists.
    if let Some(ref mut broker) = state.connection_broker {
        broker.tick().await;
    }

    if let Some(ref mut rx) = state.broker_event_rx {
        while let Ok(event) = rx.try_recv() {
            match event {
                ember::broker::BrokerEvent::StartRelay { ref attempt_key, source_ip, source_port, target_quic_port, target_node_id, file_hash, relay_addr, relay_attestation_hash, relay_ember_hash } => {
                    tracing::info!("Broker: initiating relay for {} -> {}:{} (relay={:?})", attempt_key, source_ip, source_port, relay_addr);

                    let attempt_key_owned = attempt_key.clone();

                    let (attempt_transfer_id, _) = state.connection_broker.as_ref()
                        .and_then(|b| b.get_attempt_info(&attempt_key_owned))
                        .map(|(tid, _, _, _)| (tid, ()))
                        .unwrap_or_default();

                    let broker_tx = state.connection_broker.as_ref()
                        .map(|b| b.event_sender());

                    if let Some(ref mut broker) = state.connection_broker {
                        broker.set_relay_phase(&attempt_key_owned);
                    }

                    if let Some((relay_ip, relay_port)) = relay_addr {
                        let quic_ep = state.connection_broker.as_ref()
                            .and_then(|b| b.quic_endpoint().cloned());
                        let transfer_id = attempt_transfer_id.clone();

                        tokio::spawn(async move {
                            let Some(broker_tx) = broker_tx else { return; };
                            let Some(endpoint) = quic_ep else {
                                tracing::warn!("Broker: no QUIC endpoint for relay {attempt_key_owned}");
                                if let Err(send_err) = broker_tx.try_send(ember::broker::BrokerEvent::RelayFailed {
                                    attempt_key: attempt_key_owned,
                                    reason: "no QUIC endpoint".into(),
                                    // Our endpoint, not their fault.
                                    relay_at_fault: false,
                                    refused_us: false,
                                    relay_busy: false,
                                }) {
                                    tracing::debug!("Broker: dropping relay failure event (queue full/closed): {send_err}");
                                }
                                return;
                            };

                            let relay_addr = SocketAddr::new(
                                std::net::IpAddr::V4(relay_ip), relay_port,
                            );

                            // `pin` for `connect_to_peer_relay` must be *our own*
                            // QUIC cert/key DER bytes (proving to the relay who
                            // we are) paired with the *relay's* expected node id
                            // (so our verifier confirms we actually reached that
                            // relay, not an impostor). This used to pass our raw
                            // 32-byte Ed25519 identity key bytes directly as if
                            // they were DER-encoded cert/key material — rustls
                            // would fail to parse them as X.509/PKCS8 on every
                            // single pinned relay attempt, so pinned peer-relay
                            // connects never succeeded. Derive a real (cert_der,
                            // key_der) pair from our identity key on demand
                            // instead — cheap and deterministic, see
                            // `generate_self_signed_cert`'s doc comment.
                            let relay_pin_material = relay_ember_hash.and_then(|hash| {
                                match ember::quic::generate_self_signed_cert(&ed25519_secret_key) {
                                    Ok(cert_and_key) => Some((cert_and_key, hash)),
                                    Err(e) => {
                                        tracing::warn!(
                                            "Broker: failed to derive QUIC cert for relay pin, connecting unpinned: {e}"
                                        );
                                        None
                                    }
                                }
                            });
                            let relay_pin = relay_pin_material
                                .as_ref()
                                .map(|((cert_der, key_der), hash)| {
                                    (cert_der.as_slice(), key_der.as_slice(), *hash)
                                });
                            let Some(attestation_hash) = relay_attestation_hash else {
                                tracing::warn!(
                                    "Broker: peer relay {attempt_key_owned} missing attestation hash"
                                );
                                if let Err(send_err) = broker_tx.try_send(ember::broker::BrokerEvent::RelayFailed {
                                    attempt_key: attempt_key_owned,
                                    reason: "missing relay attestation hash".into(),
                                    // Missing on our side, before we ever dialled.
                                    relay_at_fault: false,
                                    refused_us: false,
                                    relay_busy: false,
                                }) {
                                    tracing::debug!("Broker: dropping relay failure event (queue full/closed): {send_err}");
                                }
                                return;
                            };
                            match ember::relay::connect_to_peer_relay(
                                &endpoint,
                                relay_addr,
                                source_ip,
                                target_quic_port,
                                target_node_id,
                                &file_hash,
                                &attestation_hash,
                                &ed25519_pubkey,
                                &ember_hash,
                                &ed25519_secret_key,
                                relay_pin,
                            ).await {
                                Ok((send, recv)) => {
                                    tracing::info!("Broker: peer relay connected via {relay_addr}");
                                    let _ = broker_tx.send(ember::broker::BrokerEvent::ConnectionReady(
                                        ember::broker::BrokerConnection {
                                            transfer_id,
                                            file_hash,
                                            source_ip,
                                            source_port,
                                            method: ember::broker::ConnectionMethod::PeerRelay,
                                            relay_addr: Some((relay_ip, relay_port)),
                                            reader: Box::new(recv),
                                            writer: Box::new(send),
                                        },
                                    )).await;
                                }
                                Err(e) => {
                                    tracing::debug!("Broker: peer relay failed: {e}");
                                    if let Err(send_err) = broker_tx.try_send(ember::broker::BrokerEvent::RelayFailed {
                                            attempt_key: attempt_key_owned,
                                            // Attribution comes from the
                                            // dial itself: unreachable or
                                            // misbehaving counts against
                                            // the relay, a proper refusal
                                            // does not.
                                            relay_at_fault: e.relay_at_fault,
                                            refused_us: e.refused_us,
                                            relay_busy: e.relay_busy,
                                            reason: e.reason,
                                        }) {
                                        tracing::debug!("Broker: dropping relay failure event (queue full/closed): {send_err}");
                                    }
                                }
                            }
                        });
                    } else {
                        tracing::debug!(
                            "Broker: no peer relay candidate for {attempt_key_owned}; \
                             authenticated server relay is restricted to known friends"
                        );
                        tokio::spawn(async move {
                            let Some(broker_tx) = broker_tx else { return; };
                            if let Err(send_err) = broker_tx.try_send(ember::broker::BrokerEvent::RelayFailed {
                                attempt_key: attempt_key_owned,
                                reason: "anonymous LowID sources cannot use server relay".into(),
                                // No relay was involved at all.
                                relay_at_fault: false,
                                refused_us: false,
                                relay_busy: false,
                            }) {
                                tracing::debug!("Broker: dropping relay failure event (queue full/closed): {send_err}");
                            }
                        });
                    }
                }
                ember::broker::BrokerEvent::ConnectionReady(conn) => {
                    tracing::info!("Broker: connection ready for transfer {} from {}:{} via {:?}", conn.transfer_id, conn.source_ip, conn.source_port, conn.method);
                    let key = format!("{}:{}:{}", conn.transfer_id, conn.source_ip, conn.source_port);
                    // An attempt that already timed out was failed then, and
                    // its source has moved on; greeting the stream now would
                    // count the same attempt as a success too.
                    if !state.connection_broker.as_ref().is_some_and(|b| b.has_attempt(&key)) {
                        tracing::debug!("Broker: dropping a relayed stream for {key} that arrived after its attempt ended");
                        continue;
                    }
                    // The Hello below is part of the attempt; restart its clock
                    // so a slow dial does not leave it to expire mid-greeting.
                    let Some(broker) = state.connection_broker.as_mut() else {
                        continue;
                    };
                    broker.set_greeting_phase(&key);
                    let greet_time_left = broker.attempt_time_left(&key).unwrap_or_default();
                    let greet_broker_tx = broker.event_sender();
                    let bridge = broker.bridge_token(&key);

                    // The broker stream is freshly established and
                    // NOT yet greeted: WE initiated it (QUIC
                    // hole-punch / relay), so the peer's upload
                    // listener is waiting to RECEIVE our eMule Hello
                    // before it will answer. Greet it here with the
                    // client Hello (plain — a hole-punched QUIC hop
                    // is end-to-end encrypted, and on the relay path
                    // RC4 obfuscation would not help anyway: the
                    // relay terminates QUIC and bridges cleartext,
                    // so integrity there rests on MD4/AICH part
                    // verification), then hand the worker a properly
                    // greeted stream carrying the peer's real
                    // capabilities. Without this the worker adopts an
                    // ungreeted stream with default (ext_ver=0) caps
                    // and both sides stall — the "stranded callback"
                    // failure. Done in a spawned task so the Hello
                    // round-trip never blocks the network event loop;
                    // `send().await` is safe off-loop (it cannot
                    // self-deadlock the select! arm that drains the
                    // channel).
                    let greet_tx = kad_callback_tx.clone();
                    let greet_user_hash = state.user_hash;
                    let greet_client_id = state
                        .external_ip
                        .map(|ip| u32::from_le_bytes(ip.octets()))
                        .unwrap_or(0);
                    // The active broker-event receiver prevents a
                    // whole-struct borrow here. Inline the same
                    // STUN-over-TCP-confirmed fallback used by
                    // `advertised_tcp_port`.
                    let greet_tcp_port = state
                        .external_tcp_port
                        .filter(|port| *port != 0)
                        .unwrap_or(state.tcp_port);
                    // Same STUN-aware fallback as TCP above (via
                    // `advertised_udp_port`, inlined for the same
                    // borrow-conflict reason as `greet_tcp_port`).
                    let greet_udp_port = state
                        .external_udp_port
                        .filter(|p| *p != 0)
                        .unwrap_or(state.udp_port);
                    let greet_nickname = settings.nickname.clone();
                    let greet_peer_ip = conn.source_ip;
                    let greet_peer_port = conn.source_port;
                    let greet_file_hash = conn.file_hash;
                    let greet_attempt_key = key.clone();
                    let mut greet_reader: Box<dyn tokio::io::AsyncRead + Unpin + Send> =
                        Box::new(ember::broker::BridgedReader::new(conn.reader, bridge));
                    let mut greet_writer = conn.writer;
                    tokio::spawn(async move {
                        let greeted = ember::broker::greet_within_attempt(
                            ed2k::multi_source::perform_outbound_hello(
                                &mut *greet_reader,
                                &mut *greet_writer,
                                &greet_user_hash,
                                greet_client_id,
                                greet_tcp_port,
                                greet_udp_port,
                                &greet_nickname,
                            ),
                            greet_time_left,
                            greet_attempt_key,
                            &greet_broker_tx,
                        )
                        .await;
                        let Some((peer_user_hash, peer_caps)) = greeted else {
                            return;
                        };
                        let parts = upload_server::KadCallbackParts {
                            peer_ip: greet_peer_ip,
                            peer_port: greet_peer_port,
                            peer_hello_port: 0,
                            peer_user_hash,
                            file_hash: greet_file_hash,
                            reader: greet_reader,
                            writer: greet_writer,
                            emule_info_done: false,
                            peer_caps,
                            friend_ember_hash: None,
                            origin: None,
                            answers_server_callback: false,
                        };
                        if let Err(e) = greet_tx.send(parts).await {
                            tracing::debug!(
                                "Broker: kad-callback channel closed; dropping greeted connection for {greet_peer_ip}:{greet_peer_port}: {e}"
                            );
                        }
                    });
                }
                ember::broker::BrokerEvent::RelayGreeted { ref attempt_key, live } => {
                    let still_live = state.connection_broker.as_mut().is_some_and(|broker| {
                        broker.mark_succeeded(attempt_key, ember::broker::ConnectionMethod::PeerRelay)
                    });
                    if !still_live {
                        tracing::debug!("Broker: dropping a greeted stream for {attempt_key} whose attempt already ended");
                    }
                    let _ = live.send(still_live);
                }
                ember::broker::BrokerEvent::ConnectionFailed { ref transfer_id, source_ip, source_port, ref reason } => {
                    tracing::debug!("Broker: all methods failed for {}:{} (transfer {}): {}", source_ip, source_port, transfer_id, reason);
                    if let Some(pfs) = state.per_file_sources.get_mut(transfer_id) {
                        // `BrokerEvent::ConnectionFailed` doesn't carry the
                        // source's user hash, so an unspecified-IP source
                        // (LowID buddy publish with no real IP) can't be
                        // resolved here — safer to no-op than risk mutating
                        // an unrelated peer's row that happens to share the
                        // same advertised port (see `PerFileSourceList::
                        // resolve_idx`).
                        pfs.set_low_to_low(source_ip, source_port, None);
                    }
                }
                ember::broker::BrokerEvent::RelayFailed { ref attempt_key, ref reason, relay_at_fault, refused_us, relay_busy } => {
                    if let Some(ref mut broker) = state.connection_broker {
                        if refused_us {
                            broker.relay_refused_us(attempt_key, reason).await;
                        } else if relay_busy {
                            broker.relay_was_busy(attempt_key, reason, relay_at_fault).await;
                        } else {
                            broker.relay_failed(attempt_key, reason, relay_at_fault).await;
                        }
                    }
                }
            }
        }
    }
}
