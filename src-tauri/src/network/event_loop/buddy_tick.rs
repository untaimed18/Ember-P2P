//! The buddy system: finding and keeping a KAD relay buddy while firewalled on
//! both TCP and UDP.

use super::*;

pub(in crate::network) async fn on_buddy_tick(
    udp_socket: &Arc<UdpSocket>,
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
) {
    if state.stats.status == NetworkStatus::Disconnected { return; }
    let tcp_fw = state.firewall_checker.tcp_status();
    let udp_fw = state.firewall_checker.udp_status();
    // eMule (ClientList.cpp:604-629): a buddy is only useful while we
    // are firewalled on BOTH TCP and UDP -- a UDP-open client is
    // reachable via direct UDP callback, so it needs no relay. If our
    // firewall status improved (TCP or UDP opened), proactively drop
    // the relay / cancel the in-flight search instead of holding a
    // buddy slot we no longer need (eMule's `else if (m_pBuddy)` drop).
    let need_buddy = state.firewall_checker.tcp_firewalled()
        && state.firewall_checker.udp_firewalled();
    if !need_buddy {
        match state.buddy_manager.state() {
            BuddyState::Connected => {
                state.buddy_manager.disconnect_buddy().await;
                state.buddy_event_rx = None;
                *state.shared_buddy_info.write().await = None;
                info!("Dropped buddy: no longer firewalled on both TCP and UDP");
            }
            BuddyState::FindingBuddy => {
                state.buddy_manager.find_failed();
                let findbuddy_sids: Vec<_> = state.search_manager.active.iter()
                    .filter(|(_, s)| matches!(s.search_type, SearchType::FindBuddy))
                    .map(|(sid, _)| *sid)
                    .collect();
                for sid in findbuddy_sids {
                    if let Some(removed) = state.search_manager.remove(&sid) {
                        state.routing_table.release_contacts_in_use(&removed.in_use_ids);
                    }
                }
                info!("Cancelled buddy search: no longer firewalled on both TCP and UDP");
            }
            BuddyState::NoBuddy => {}
        }
    }
    let buddy_state = state.buddy_manager.state();
    if buddy_state != BuddyState::Connected {
        debug!("Buddy tick: state={:?}, tcp_fw={:?}, udp_fw={:?}, routing_table={}", buddy_state, tcp_fw, udp_fw, state.routing_table.len());
    }
    if buddy_state == BuddyState::Connected {
        state.buddy_manager.send_buddy_ping().await;
    }
    if state.buddy_manager.finding_timed_out() {
        state.buddy_manager.find_failed();
        info!("Buddy search timed out waiting for FindBuddyRes");
    }
    if state.buddy_manager.should_find_buddy(tcp_fw, udp_fw) {
        state.buddy_manager.start_finding();
        let target = state.buddy_manager.find_buddy_target();
        let local_tcp = state.buddy_manager.tcp_port();
        let user_id_for_buddy = KadId(cuint128_swap(&state.user_hash));
        info!(
            "FindBuddy identities: local_kad_id={}, buddy_target={}, user_hash_wire={}, tcp_port={}, obfuscation={}",
            state.local_id, target, user_id_for_buddy, local_tcp, state.obfuscation_enabled
        );
        let closest = state.routing_table.find_closest(&target, SEARCH_INITIAL_CONTACTS);
        if !closest.is_empty() {
            let sid = start_kad_search(
                state,
                app_handle,
                target,
                SearchType::FindBuddy,
                closest,
            );
            if sid == SearchId(0) {
                // Search manager at capacity — do not sit in
                // FindingBuddy with zero requests until timeout.
                state.buddy_manager.find_failed();
                warn!(
                    "FindBuddy search rejected: active search cap reached"
                );
            } else {

            // Send FindBuddyReq to a broad sample of verified contacts.
            // Any non-firewalled node can be buddy, so sample from across
            // the entire routing table, not just close to the target.
            let mut sent_addrs = std::collections::HashSet::new();
            let mut initial_sent = 0u32;

            // 1) 10 contacts closest to the inverted-ID target
            let target_contacts = state.routing_table.find_closest_verified(&target, 10);
            let mut logged_wire = false;
            let mut obf_count = 0u32;
            let mut plain_count = 0u32;
            for contact in &target_contacts {
                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                if !state
                    .search_manager
                    .get_mut(&sid)
                    .map(|search| search.reserve_find_buddy_request(contact.id))
                    .unwrap_or(false)
                {
                    continue;
                }
                let msg = KadMessage::FindBuddyReq {
                    buddy_id: target,
                    user_id: user_id_for_buddy,
                    tcp_port: local_tcp,
                };
                match messages::encode_packet(&msg) {
                    Ok(packet) => {
                        if !logged_wire {
                            let preview: Vec<u8> =
                                packet.iter().take(10).copied().collect();
                            info!(
                                "FindBuddyReq wire: {:02X?} (len={}, buddy_target={}, user_id={}, tcp={})",
                                preview, packet.len(), target, user_id_for_buddy, local_tcp
                            );
                            logged_wire = true;
                        }
                        let c_obf = state.obfuscation_enabled
                            && state
                                .routing_table
                                .get_contact(&contact.id)
                                .is_some_and(|c| c.supports_obfuscation());
                        if c_obf {
                            obf_count += 1;
                        } else {
                            plain_count += 1;
                        }
                        if send_kad_packet(
                            udp_socket,
                            &packet,
                            addr,
                            state,
                            &contact.id,
                        )
                        .await
                        .is_ok()
                        {
                            state.flood_protection.track_request(addr, 0x51);
                            sent_addrs.insert(addr);
                            initial_sent += 1;
                        } else if let Some(search) =
                            state.search_manager.get_mut(&sid)
                        {
                            search.release_find_buddy_request(contact.id);
                        }
                    }
                    Err(_) => {
                        if let Some(search) = state.search_manager.get_mut(&sid) {
                            search.release_find_buddy_request(contact.id);
                        }
                    }
                }
            }

            // 2) Up to 20 random verified contacts from across the
            //    routing table (different part of keyspace).
            let all_contacts: Vec<_> = state
                .routing_table
                .all_contacts()
                .filter(|c| c.verified && !c.is_dead() && !c.is_udp_firewalled())
                .collect();
            let random_contacts: Vec<KadContact> = {
                use rand::seq::SliceRandom;
                let mut rng = rand::thread_rng();
                let mut shuffled: Vec<_> = all_contacts.iter().collect();
                shuffled.shuffle(&mut rng);
                shuffled
                    .into_iter()
                    .take(20)
                    .cloned()
                    .cloned()
                    .collect()
            };
            for contact in &random_contacts {
                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                if sent_addrs.contains(&addr) {
                    continue;
                }
                if !state
                    .search_manager
                    .get_mut(&sid)
                    .map(|search| search.reserve_find_buddy_request(contact.id))
                    .unwrap_or(false)
                {
                    continue;
                }
                let msg = KadMessage::FindBuddyReq {
                    buddy_id: target,
                    user_id: user_id_for_buddy,
                    tcp_port: local_tcp,
                };
                match messages::encode_packet(&msg) {
                    Ok(packet) => {
                        let c_obf = state.obfuscation_enabled
                            && state
                                .routing_table
                                .get_contact(&contact.id)
                                .is_some_and(|c| c.supports_obfuscation());
                        if c_obf {
                            obf_count += 1;
                        } else {
                            plain_count += 1;
                        }
                        if send_kad_packet(
                            udp_socket,
                            &packet,
                            addr,
                            state,
                            &contact.id,
                        )
                        .await
                        .is_ok()
                        {
                            state.flood_protection.track_request(addr, 0x51);
                            sent_addrs.insert(addr);
                            initial_sent += 1;
                        } else if let Some(search) =
                            state.search_manager.get_mut(&sid)
                        {
                            search.release_find_buddy_request(contact.id);
                        }
                    }
                    Err(_) => {
                        if let Some(search) = state.search_manager.get_mut(&sid) {
                            search.release_find_buddy_request(contact.id);
                        }
                    }
                }
            }

            if initial_sent > 0 {
                info!("Sent initial FindBuddyReq to {} contacts ({} target-close + random from {} verified, {} obfuscated/{} plaintext)",
                    initial_sent, target_contacts.len(), all_contacts.len(), obf_count, plain_count);
            }
            } // sid != SearchId(0)
        }
    }

}
