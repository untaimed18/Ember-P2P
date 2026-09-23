//! The Ember refresh tick: when the advertised Ember payload is dirty, prunes
//! stale peers and Noise keys and rebuilds the exchange payload (AICH roots,
//! relay attestation, known peers).

use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_ember_refresh_tick(
    state: &mut NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    settings: &AppSettings,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    known_files: &KnownFileList,
    shared_ember_payload: &ember::SharedEmberPayload,
    ember_payload_generation: &ember::EmberPayloadGeneration,
    ed25519_pubkey: [u8; 32],
    ed25519_secret_key: [u8; 32],
) {
    if !state.ember_payload_dirty {
        return;
    }
    // Also look up AICH roots from local shared file index
    {
        let index = local_index.read().await;
        let mgr = transfer_manager.read().await;
        for transfer in mgr.active.values().chain(mgr.queue.iter()) {
            if let Ok(ed2k_bytes) = hex::decode(&transfer.file_hash) {
                if ed2k_bytes.len() == 16 {
                    let mut fh = [0u8; 16];
                    fh.copy_from_slice(&ed2k_bytes);
                    if !state.aich_root_map.contains_key(&fh)
                        && state.aich_root_map.len() < MAX_AICH_ROOT_MAP_SOFT_CAP
                    {
                        if let Some(fi) = index.get_by_hash(&transfer.file_hash) {
                            if !fi.aich_hash.is_empty() {
                                if let Ok(ab) = hex::decode(&fi.aich_hash) {
                                    if ab.len() == 20 {
                                        let mut ah = [0u8; 20];
                                        ah.copy_from_slice(&ab);
                                        state.aich_root_map.insert(fh, ah);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let local_relay_attestation = sign_local_relay_attestation(
        state,
        settings,
        &ed25519_secret_key,
        ed25519_pubkey,
    );
    let local_relay_ip = local_relay_attestation.as_ref().map(|a| a.relay_ip);

    let entries = {
        let restricted = {
            let idx = local_index.read().await;
            collect_friends_only_hashes(&idx, known_files)
        };
        let mgr = transfer_manager.read().await;
        let sm = source_manager.read().await;
        let mut file_entries = Vec::new();
        let mut seen_hashes = HashSet::new();

        // Include active/queued downloads
        for transfer in mgr.active.values().chain(mgr.queue.iter()) {
            if transfer.direction != TransferDirection::Download {
                continue;
            }
            if matches!(transfer.status, TransferStatus::Completed | TransferStatus::Failed) {
                continue;
            }
            if !kad_may_advertise_partial(known_files, &restricted, &transfer.file_hash) {
                continue;
            }
            let hash_bytes = match hex::decode(&transfer.file_hash) {
                Ok(b) if b.len() == 16 => {
                    let mut h = [0u8; 16];
                    h.copy_from_slice(&b);
                    h
                }
                _ => continue,
            };
            seen_hashes.insert(transfer.file_hash.clone());
            let aich_root = state.aich_root_map.get(&hash_bytes).copied();
            let sources: Vec<ember::EmberSource> = state
                .per_file_sources
                .get(&transfer.id)
                .map(|pfs| {
                    pfs.sources
                        .iter()
                        .filter(|s| s.tcp_port > 0
                            && !s.ip.is_unspecified()
                            && !s.ip.is_private()
                            && !s.ip.is_loopback()
                            && !s.ip.is_link_local())
                        .take(ember::MAX_EPX_SOURCES_PER_FILE)
                        .map(|s| {
                            let mut flags = 0u8;
                            if epx_advertises_source_firewalled(&s.state) {
                                flags |= ember::SOURCE_FLAG_FIREWALLED;
                            }
                            if local_relay_ip == Some(s.ip) {
                                flags |= ember::SOURCE_FLAG_RELAY_CAPABLE;
                            }
                            if sm.get_connect_options(&hash_bytes, s.ip, s.tcp_port).is_some_and(|co| co & 0x07 != 0) {
                                flags |= ember::SOURCE_FLAG_OBFUSCATION;
                            }
                            ember::EmberSource {
                                ip: s.ip,
                                tcp_port: s.tcp_port,
                                udp_port: s.udp_port,
                                flags,
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            file_entries.push(ember::EmberFileEntry {
                file_hash: hash_bytes,
                file_size: transfer.total_size,
                aich_root,
                sources,
            });
        }

        // Include completed (seeded) files that have known sources
        for transfer in mgr.active.values().chain(mgr.queue.iter()) {
            if transfer.status != TransferStatus::Completed {
                continue;
            }
            if !kad_may_advertise_partial(known_files, &restricted, &transfer.file_hash) {
                continue;
            }
            if seen_hashes.contains(&transfer.file_hash) {
                continue;
            }
            if file_entries.len() >= ember::MAX_EPX_FILES {
                break;
            }
            let hash_bytes = match hex::decode(&transfer.file_hash) {
                Ok(b) if b.len() == 16 => {
                    let mut h = [0u8; 16];
                    h.copy_from_slice(&b);
                    h
                }
                _ => continue,
            };
            let aich_root = state.aich_root_map.get(&hash_bytes).copied();
            let sources: Vec<ember::EmberSource> = state
                .per_file_sources
                .get(&transfer.id)
                .map(|pfs| {
                    pfs.sources
                        .iter()
                        .filter(|s| s.tcp_port > 0
                            && !s.ip.is_unspecified()
                            && !s.ip.is_private()
                            && !s.ip.is_loopback()
                            && !s.ip.is_link_local())
                        .take(ember::MAX_EPX_SOURCES_PER_FILE)
                        .map(|s| {
                            let mut flags = 0u8;
                            if epx_advertises_source_firewalled(&s.state) {
                                flags |= ember::SOURCE_FLAG_FIREWALLED;
                            }
                            if local_relay_ip == Some(s.ip) {
                                flags |= ember::SOURCE_FLAG_RELAY_CAPABLE;
                            }
                            if sm.get_connect_options(&hash_bytes, s.ip, s.tcp_port).is_some_and(|co| co & 0x07 != 0) {
                                flags |= ember::SOURCE_FLAG_OBFUSCATION;
                            }
                            ember::EmberSource {
                                ip: s.ip,
                                tcp_port: s.tcp_port,
                                udp_port: s.udp_port,
                                flags,
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            if sources.is_empty() {
                continue;
            }
            seen_hashes.insert(transfer.file_hash.clone());
            file_entries.push(ember::EmberFileEntry {
                file_hash: hash_bytes,
                file_size: transfer.total_size,
                aich_root,
                sources,
            });
        }

        file_entries
    };

    // Drop entries older than `KNOWN_EMBER_PEER_TTL` before
    // building the wire list so we never advertise a peer
    // we haven't heard from in a day. Cheap O(N) sweep — N
    // is hard-capped at MAX_KNOWN_EMBER_PEERS = 500. The
    // sibling Noise-key cache uses the same TTL so prune
    // it on the same cadence.
    let pruned_before = state.known_ember_peers.len();
    prune_stale_ember_peers(&mut state.known_ember_peers);
    prune_stale_ember_noise_keys(&mut state.ember_noise_keys);
    prune_stale_ember_peers(&mut state.ember_keyless_peers);
    // Keep a session contact while it is still talking to us, not
    // merely while one of the two sibling caches remembers it.
    // Those are refreshed by `note_connected_ember_peer` on an eD2K
    // introduction, so a session that stays up longer than the TTL
    // without reconnecting used to lose its pin — and
    // `ember_session_introduced` then refuses to re-learn it from
    // the signed frames the peer is still sending, which silently
    // drops the LAN publisher this pin exists to reach.
    // `sender_contact` stamps `last_seen` on every signed frame, so
    // an active peer now renews its own entry.
    let session_contact_cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .saturating_sub(KNOWN_EMBER_PEER_TTL.as_secs())
        as i64;
    state
        .ember_session_dht_contacts
        .retain(|(ip, port), contact| {
            contact.last_seen > session_contact_cutoff
                || state.ember_keyless_peers.contains_key(&(*ip, *port))
                || state.known_ember_peers.keys().any(|(peer_ip, _)| peer_ip == ip)
        });
    // The bridge's "already attempted" set has no TTL of its own;
    // bound it to the two caches it mirrors. Once a peer ages out
    // of both (and is later re-learned) we want to be able to
    // bridge-ping it again, and this also stops the set growing
    // without limit over a long session. Both caches must be
    // consulted — retaining against the Noise keys alone would
    // evict every Noise_XX peer immediately and re-ping it on the
    // very next tick.
    state.ember_kad_bridge_attempted.retain(|key, _| {
        state.ember_noise_keys.contains_key(key)
            || state.ember_keyless_peers.contains_key(key)
    });
    prune_ember_content_hashes(state, transfer_manager, local_index);
    let pruned_after = state.known_ember_peers.len();
    if pruned_after != pruned_before {
        state.stats.ember_peers = pruned_after as u32;
        tracing::debug!(
            "Pruned {} stale Ember peer(s) (now {})",
            pruned_before - pruned_after,
            pruned_after
        );
    }

    // Build peer discovery list from previously-discovered peers
    // (we don't have IP:port for session keys — they're ember
    // hashes — so the EPX peer section is sourced entirely from
    // the timestamped `known_ember_peers` map). Prefer most
    // recently-seen peers so the wire payload reflects current
    // mesh activity rather than whatever the HashMap iteration
    // order happens to surface.
    let ember_peers: Vec<ember::EmberPeer> = {
        let mut candidates: Vec<((Ipv4Addr, u16), std::time::Instant)> = state
            .known_ember_peers
            .iter()
            .filter(|((ip, _), _)| !state.ip_filter.is_blocked_readonly(*ip))
            .map(|((ip, port), ts)| ((*ip, *port), *ts))
            .collect();
        candidates.sort_by_key(|c| std::cmp::Reverse(c.1));
        candidates
            .into_iter()
            .take(ember::MAX_EPX_PEERS)
            .map(|((ip, port), _)| ember::EmberPeer { ip, tcp_port: port })
            .collect()
    };

    let relay_attestations = local_relay_attestation
        .as_ref()
        .map(|a| vec![a.clone()])
        .unwrap_or_default();
    if let Some(attestation) = local_relay_attestation.as_ref() {
        let hash = ember::relay_attestation_hash(attestation);
        state
            .relay_manager
            .lock()
            .await
            .set_current_attestation_hash(hash, attestation.expires_at_unix);
    }

    let payload = ember::build_exchange_payload_with_relay_attestations(
        &entries,
        &ember_peers,
        &relay_attestations,
    );
    // Same entries, datagram-sized. Built here rather than per
    // request so an inbound `ExchangeRequest` stays cheap to
    // answer, and from the same inputs so the two payloads cannot
    // describe different sources.
    state.ember_udp_payload = Arc::new(ember::build_udp_exchange_payload(
        &entries,
        &ember_peers,
        &relay_attestations,
    ));
    *shared_ember_payload.write().await = Arc::new(payload);
    ember_payload_generation.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    state.ember_payload_dirty = false;
}
