//! eMule SmallTimer: probes expired KAD contacts, removes dead ones, and falls
//! back to Connecting after KADEMLIADISCONNECTDELAY without a contact.

use super::*;

pub(in crate::network) async fn on_small_tick(
    udp_socket: &Arc<UdpSocket>,
    state: &mut NetworkState,
    settings: &AppSettings,
    app_handle: &tauri::AppHandle,
) {
    if state.stats.status == NetworkStatus::Disconnected { return; }

    // eMule KADEMLIADISCONNECTDELAY: if no valid KAD contact for 20 minutes,
    // transition back to Connecting so bootstrap re-engages. Do NOT tear
    // down eD2K here — temporary KAD quiet must not yank a working server
    // (and would flap Connected↔Connecting against stale verified rows).
    const KAD_DISCONNECT_DELAY_SECS: i64 = 1200;
    if state.stats.status == NetworkStatus::Connected {
        if let Some(last_contact) = state.last_kad_contact {
            let now_dc = chrono::Utc::now().timestamp();
            if now_dc - last_contact > KAD_DISCONNECT_DELAY_SECS {
                debug!(
                    "No KAD contact for {}s, resetting to Connecting (eMule KADEMLIADISCONNECTDELAY)",
                    now_dc - last_contact
                );
                state.stats.status = NetworkStatus::Connecting;
                state.self_lookup_done = false;
                state.last_self_lookup = 0;
                // Clear so bootstrap cannot promote back to Connected
                // until a fresh decoded packet updates last_kad_contact.
                state.last_kad_contact = None;
                state.routing_table.reset_big_timer_global(now_dc);
                let _ = app_handle.emit("network-status", NetworkStatus::Connecting);
            }
        }
    }

    let dead_removed = state.routing_table.remove_dead_contacts();
    if dead_removed > 0 {
        debug!("SmallTimer: removed {dead_removed} dead contacts");
        state.stats.connected_peers = state.routing_table.len() as u32;
    }

    let to_probe = state.routing_table.get_contacts_to_probe();
    for contact in to_probe {
        let our_options: u8 = 0x04
            | if state.udp_firewalled { 0x01 } else { 0 }
            | if state.firewalled { 0x02 } else { 0 };
        let mut hello_tags = vec![
            KadTag {
                name: TagName::Id(TAG_KADMISCOPTIONS),
                value: TagValue::Uint8(our_options),
            },
        ];
        if !settings.nickname.is_empty() {
            hello_tags.push(KadTag {
                name: TagName::Id(TAG_FILENAME),
                value: TagValue::String(settings.nickname.clone()),
            });
        }
        let msg = match messages::build_hello_req(
            &state.local_id,
            advertised_tcp_port(state),
            KADEMLIA_VERSION,
            &hello_tags,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to encode hello req: {e}");
                continue;
            }
        };
        let dest = std::net::SocketAddr::new(
            std::net::IpAddr::V4(contact.ip),
            contact.udp_port,
        );
        state.flood_protection.track_request(dest, 0x11);
        let _ = send_kad_packet(
            udp_socket,
            &msg,
            dest,
            state,
            &contact.id,
        )
        .await;
    }

}
