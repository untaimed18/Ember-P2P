//! The paced UDP source-request drain: a small burst of queued packets per
//! ~200 ms tick.

use super::*;

/// Max UDP source-query packets to dispatch per `udp_source_timer` tick.
/// Combined with the 200ms tick this yields a peak rate of 15 packets/sec
/// during bursts (e.g. just after a download is added) while remaining idle
/// when the queue is empty.
const UDP_SOURCE_BURST_PER_TICK: usize = 3;

pub(in crate::network) async fn on_udp_source_tick(
    state: &mut NetworkState,
    stats_manager: &mut StatsManager,
    server_udp: &ServerUdpSocket,
) {
    for _ in 0..UDP_SOURCE_BURST_PER_TICK {
        let Some((packet, addr)) = state.udp_source_queue.pop_front() else {
            break;
        };
        let sock = server_udp.socket_handle();
        let pkt_len = packet.len() as u64;
        // Compute the canonical (TCP_port) lookup key from the
        // wire dest port (TCP+4 for plain, obfuscation_port_udp
        // for obfuscated). The recv path canonicalises to the
        // TCP+4 port; we mirror that so per-server pruning
        // tracks the right entry.
        let server_tcp_port = state
            .server_list
            .lookup_for_udp_addr(
                match addr.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => std::net::Ipv4Addr::UNSPECIFIED,
                },
                addr.port(),
            )
            .map(|(_key, tcp_port)| tcp_port);
        match sock.send_to(&packet, addr).await {
            Ok(_) => {
                // Outbound source-asking traffic to non-connected
                // servers. The queue is exclusively populated by
                // `build_all_getsources_packets[_multi]`, so every
                // byte that leaves here is `OP_GLOBGETSOURCES`
                // (or `OP_GLOBGETSOURCES2`) for source discovery.
                stats_manager.add_overhead(
                    crate::storage::statistics::OverheadCategory::SourceExchange,
                    crate::storage::statistics::OverheadDirection::Upload,
                    pkt_len,
                );
                state.udp_discovery_sent = state.udp_discovery_sent.saturating_add(1);
                // Per-server pruning: bump
                // udp_consecutive_failures. The recv path
                // resets it on any inbound UDP reply, so a
                // genuinely responsive server ratchets back
                // to zero immediately. Servers that never
                // reply hit MAX_UDP_CONSECUTIVE_FAILURES
                // and get excluded from future UDP queries
                // by `is_eligible_udp_server`.
                if let Some(tcp_port) = server_tcp_port {
                    let ip_str = addr.ip().to_string();
                    state.server_list.record_udp_query_sent(&ip_str, tcp_port);
                }
            }
            Err(e) => {
                // Don't double-count failed sends in stats.
                // Failed sends to dead/unreachable servers are
                // expected (each cycle queues to *every*
                // eligible server in `server.met`, many of
                // which are stale). Per-server failure is
                // tracked via `state.udp_discovery_send_errs`
                // for the periodic health log; debug here
                // gives detail when needed without spamming.
                debug!("UDP source send_to {addr} failed: {e}");
                state.udp_discovery_send_errs = state.udp_discovery_send_errs.saturating_add(1);
            }
        }
    }
}
