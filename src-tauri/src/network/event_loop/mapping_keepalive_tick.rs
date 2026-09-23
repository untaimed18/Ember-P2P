//! The STUN/UDP mapping keep-alive: starts a keep-alive cycle when due, and
//! retries a suspended one after its cooldown.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_mapping_keepalive_tick(
    udp_socket: &Arc<UdpSocket>,
    state: &mut NetworkState,
    mapping_ka_cycle_success: &mut bool,
    mapping_ka_server_index: &mut usize,
    next_mapping_ka_at: &mut tokio::time::Instant,
    tcp_map_ka_gen: &mut Option<u64>,
    tcp_map_ka_in_flight: &mut bool,
    tcp_map_ka_result_tx: &mpsc::UnboundedSender<TcpMappingKeepaliveResult>,
    tcp_map_ka_started_at: &mut Option<tokio::time::Instant>,
    udp_map_ka_gen: &mut Option<u64>,
    udp_map_ka_in_flight: &mut bool,
    udp_map_ka_packet_tx: &mut Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>,
    udp_map_ka_result_tx: &mpsc::UnboundedSender<UdpMappingKeepaliveResult>,
    udp_map_ka_started_at: &mut Option<tokio::time::Instant>,
) {
    let now = tokio::time::Instant::now();
    if !state.stun_keepalive_enabled {
        state.stats.stun_keepalive_active = false;
        *next_mapping_ka_at = now
            + ember::mapping_keepalive::MAPPING_KEEPALIVE_INTERVAL;
        return;
    }
    if state.stun_ka_auto_suspended {
        state.stats.stun_keepalive_active = false;
        // Retry every ~5 minutes in case the path became full-cone/CGNAT.
        let cooldown = std::time::Duration::from_secs(300);
        let ready = state
            .stun_ka_suspended_at
            .is_none_or(|at| at.elapsed() >= cooldown);
        if !ready {
            *next_mapping_ka_at = now
                + ember::mapping_keepalive::MAPPING_KEEPALIVE_INTERVAL;
            return;
        }
        info!("STUN keepalive: retrying after auto-suspend cooldown");
        state.stun_ka_auto_suspended = false;
        state.stun_ka_suspended_at = None;
        state.stun_ka_candidate_port = None;
        state.stun_ka_stable_hits = 0;
        state.stun_ka_tcp_candidate_port = None;
        state.stun_ka_tcp_stable_hits = 0;
    }
    // Wait for any in-flight cycle; retry soon (not a full extra
    // interval) so a slow STUN/TCP hold delays the next round by
    // as little as possible. Realistic worst case is still 79s
    // (3×(5+8)+4×(5+5) DNS+connect timeouts): UDP runs in
    // parallel (≤ 5+5=10s). Pathological (~139s: every STUN
    // write/read stage also times out) is abandoned at 90s on
    // purpose — a cycle still running then has already missed four
    // 20s keep-alive intervals.
    if *udp_map_ka_in_flight || *tcp_map_ka_in_flight {
        *next_mapping_ka_at = now + std::time::Duration::from_secs(1);
        return;
    }
    *next_mapping_ka_at = now
        + ember::mapping_keepalive::MAPPING_KEEPALIVE_INTERVAL;
    // Probe UDP and TCP independently. Equal numeric port values
    // do not conflict because each transport has its own socket
    // namespace. QUIC is a fire-and-forget datagram from the real
    // endpoint (no result to wait on) and is skipped until the
    // endpoint exists. UDP and QUIC use adjacent STUN indices so
    // they do not hit the same reflector in one cycle; the index
    // then advances by one so UDP still walks sequentially.
    state.mapping_ka_generation = state.mapping_ka_generation.wrapping_add(1);
    *mapping_ka_cycle_success = false;
    let gen = state.mapping_ka_generation;
    let ka_index = *mapping_ka_server_index;
    *mapping_ka_server_index = mapping_ka_server_index.wrapping_add(1);
    *udp_map_ka_in_flight = true;
    *udp_map_ka_started_at = Some(tokio::time::Instant::now());
    *udp_map_ka_gen = Some(gen);
    *udp_map_ka_packet_tx = Some(spawn_udp_mapping_keepalive(
        udp_socket.clone(),
        udp_map_ka_result_tx.clone(),
        gen,
        ka_index,
    ));
    *tcp_map_ka_in_flight = true;
    *tcp_map_ka_started_at = Some(tokio::time::Instant::now());
    *tcp_map_ka_gen = Some(gen);
    let tcp_port = state.tcp_port;
    let tx = tcp_map_ka_result_tx.clone();
    tokio::spawn(async move {
        let (hold_ok, mapped) =
            ember::mapping_keepalive::tcp_mapping_cycle(tcp_port).await;
        let _ = tx.send(TcpMappingKeepaliveResult {
            generation: gen,
            hold_ok,
            mapped,
        });
    });
    if let Some(quic_ep) = state
        .connection_broker
        .as_ref()
        .and_then(|b| b.quic_endpoint().cloned())
    {
        let quic_index = ka_index.wrapping_add(1);
        tokio::spawn(async move {
            ember::mapping_keepalive::quic_mapping_keepalive(quic_ep, quic_index)
                .await;
        });
    }
}
