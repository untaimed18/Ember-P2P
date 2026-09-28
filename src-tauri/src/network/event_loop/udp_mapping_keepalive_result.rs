//! Applying the result of a UDP mapping keep-alive cycle.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_udp_mapping_keepalive_result(
    result: UdpMappingKeepaliveResult,
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    mapping_ka_cycle_success: &mut bool,
    tcp_map_ka_in_flight: bool,
    udp_map_ka_gen: &mut Option<u64>,
    udp_map_ka_in_flight: &mut bool,
    udp_map_ka_packet_tx: &mut Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>,
    udp_map_ka_started_at: &mut Option<tokio::time::Instant>,
) {
    // Flags/sender are keyed by this cycle's local generation.
    // `mapping_ka_generation` can be bumped by
    // `reset_stun_keepalive_session` (STUN toggle / KAD
    // disconnect) without touching those locals; a matching
    // local generation must still release them so the timer
    // is not stuck until the 90s watchdog. Payload is applied
    // only while the global generation still matches, so a
    // superseded cycle cannot re-populate advertise ports.
    if Some(result.generation) != *udp_map_ka_gen {
        return;
    }
    *udp_map_ka_in_flight = false;
    *udp_map_ka_started_at = None;
    *udp_map_ka_gen = None;
    *udp_map_ka_packet_tx = None;
    if result.generation == state.mapping_ka_generation {
        if let Some(mapped) = result.mapped {
            if apply_udp_mapping_keepalive(state, mapped, app_handle) {
                *mapping_ka_cycle_success = true;
                // Confirmed (1:1 or 2-hit stable) — this is the
                // freshest known-good mapping, so it always wins
                // over whatever a NAT probe last found. A later
                // probe result restores this too (see
                // nat_probe_result_rx / stun_udp_mapping_active).
                // Deliberately does NOT set nat_type here — see the
                // matching comment in apply_udp_mapping_keepalive's
                // 1:1 branch for why inferring PortRestricted from a
                // keep-alive confirmation defeats the dedicated
                // NAT-type probe (and therefore auto-suspend).
                state.nat_info.external_addr = Some(mapped);
                // Friend dials read the address from here, and the
                // hole-punch is skipped outright while it is `None`.
                // The re-mapped branch of `apply_udp_mapping_keepalive`
                // publishes it, but the 1:1 branch — the common
                // outcome, and one that lands within seconds of
                // startup — used to leave friends waiting for the
                // dedicated probe to finish before punch was possible.
                {
                    let mut ctx = state
                        .friend_nat_context
                        .write()
                        .unwrap_or_else(|p| p.into_inner());
                    ctx.external_addr = Some(mapped);
                }
            }
        }
    }
    if !*udp_map_ka_in_flight
        && !tcp_map_ka_in_flight
        && !*mapping_ka_cycle_success
    {
        if state.stats.stun_keepalive_active {
            info!(
                "STUN keepalive: cycle {} without a confirmed UDP mapping or TCP hold — marking inactive until the next cycle",
                if result.mapped.is_none() { "timed out" } else { "completed" }
            );
        }
        state.stats.stun_keepalive_active = false;
    }
}
