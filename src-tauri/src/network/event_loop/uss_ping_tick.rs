//! Upload slot scheduling (USS): pinging the selected host over KAD to measure
//! RTT.

use super::*;

pub(in crate::network) async fn on_uss_ping_tick(
    udp_socket: &Arc<UdpSocket>,
    state: &mut NetworkState,
) {
    if state.stats.status == NetworkStatus::Disconnected { return; }
    if !state.uss_enabled_flag.load(std::sync::atomic::Ordering::Relaxed) {
        if let Some((addr, _)) = state.uss_host.take() {
            state.uss_prev_host = Some(addr);
        }
        state.pending_uss_pings.clear();
        state.uss_missed_pongs = 0;
        return;
    }
    let now_ts = chrono::Utc::now().timestamp();
    const USS_PING_TIMEOUT_SECS: u64 = 3;
    // Half the outbound governor's window: two pings per window, evenly spaced.
    const USS_PING_MIN_GAP: std::time::Duration = std::time::Duration::from_millis(31_500);

    // Count timed-out in-flight pings as misses, then drop them.
    // Do NOT increment on send — that falsely rotates hosts when
    // RTT is merely slower than the 2s timer interval.
    let timed_out: Vec<SocketAddr> = state
        .pending_uss_pings
        .iter()
        .filter(|(_, sent)| sent.elapsed().as_secs() >= USS_PING_TIMEOUT_SECS)
        .map(|(addr, _)| *addr)
        .collect();
    for addr in timed_out {
        state.pending_uss_pings.remove(&addr);
        state.uss_missed_pongs = state.uss_missed_pongs.saturating_add(1);
    }

    // Rotate host every 5 minutes or after 3 consecutive timed-out pings
    let should_rotate = state.uss_host.is_some()
        && (state.uss_missed_pongs >= 3 || now_ts.saturating_sub(state.uss_host_selected_at) > 300);
    if should_rotate {
        debug!(
            "USS: rotating ping host (missed={}, age={}s)",
            state.uss_missed_pongs,
            now_ts.saturating_sub(state.uss_host_selected_at)
        );
        if let Some((addr, _)) = state.uss_host.take() {
            state.uss_prev_host = Some(addr);
            state.pending_uss_pings.remove(&addr);
        }
    }

    // Select a host if needed (prefer not re-picking the just-rotated
    // one, but fall back to it when it is the only eligible contact —
    // otherwise a single-peer KAD table leaves USS stuck with no host
    // and the Preparing min upload forever).
    if state.uss_host.is_none() {
        let exclude = state.uss_prev_host;
        let all_eligible: Vec<_> = state
            .routing_table
            .all_contacts()
            .filter(|c| c.verified && !c.is_dead() && !c.is_udp_firewalled())
            .cloned()
            .collect();
        let mut candidates: Vec<_> = all_eligible
            .iter()
            .filter(|c| {
                let addr = SocketAddr::new(c.ip.into(), c.udp_port);
                exclude != Some(addr)
            })
            .cloned()
            .collect();
        if candidates.is_empty() {
            candidates = all_eligible;
        }
        // Prefer a stable pick among eligible contacts rather than
        // always the first table entry (which caused sticky reselect
        // of the same dead peer after rotation when alternatives exist).
        let candidate = if candidates.is_empty() {
            None
        } else {
            let idx = (now_ts.unsigned_abs() as usize) % candidates.len();
            Some(candidates[idx].clone())
        };
        if let Some(contact) = candidate {
            let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
            state.uss_host = Some((addr, contact.id));
            state.uss_missed_pongs = 0;
            state.uss_host_selected_at = now_ts;
            info!("USS: selected ping host {addr}");
        }
    }

    // Send at most one in-flight Ping per host so a late pong cannot
    // measure against a newer overwrite of the send timestamp.
    //
    // eMule takes two KADEMLIA2_PING a minute from one IP (see
    // `kad::outbound`), and a different host would give USS a different RTT
    // baseline, so one host is pinged no faster than that allows. Checked
    // here rather than left to the send's refusal, which this 2 s timer would
    // otherwise hit on almost every tick.
    if let Some((addr, ref contact_id)) = state.uss_host {
        if !state.pending_uss_pings.contains_key(&addr)
            && kad_request_ready(state, addr, messages::KADEMLIA2_PING, USS_PING_MIN_GAP)
        {
            let msg = KadMessage::Ping;
            if let Ok(packet) = messages::encode_packet(&msg) {
                match send_kad_packet(udp_socket, &packet, addr, state, contact_id).await {
                    Ok(_) => {
                        state.pending_uss_pings.insert(addr, std::time::Instant::now());
                    }
                    Err(e) => {
                        debug!("USS: failed to send ping to {addr}: {e}");
                    }
                }
            }
        }
    }
}
