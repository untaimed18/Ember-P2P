//! Applying the result of a TCP mapping keep-alive cycle.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_tcp_mapping_keepalive_result(
    result: TcpMappingKeepaliveResult,
    state: &mut NetworkState,
    settings: &AppSettings,
    app_handle: &tauri::AppHandle,
    shared_server_addr: &Arc<RwLock<Option<SocketAddr>>>,
    mapping_ka_cycle_success: &mut bool,
    tcp_map_ka_gen: &mut Option<u64>,
    tcp_map_ka_in_flight: &mut bool,
    tcp_map_ka_started_at: &mut Option<tokio::time::Instant>,
    udp_map_ka_in_flight: bool,
) {
    // Same local-vs-global split as the UDP arm: release this
    // cycle's in-flight flag even after an external generation
    // bump, but do not apply a superseded mapped port or fire a
    // LowID remap reconnect from that payload.
    if Some(result.generation) != *tcp_map_ka_gen {
        return;
    }
    *tcp_map_ka_in_flight = false;
    *tcp_map_ka_started_at = None;
    *tcp_map_ka_gen = None;
    if result.generation == state.mapping_ka_generation {
        if apply_tcp_mapping_keepalive(state, result.hold_ok, result.mapped, app_handle) {
            *mapping_ka_cycle_success = true;
        }
        // A reconnect that fails just falls back to the existing
        // backoff-driven auto-reconnect (which will use the
        // now-current `advertised_tcp_port` anyway) — see
        // `should_reconnect_for_tcp_remap` for the full rationale.
        let cooldown_elapsed = state
            .last_tcp_remap_reconnect_at
            .is_none_or(|at| at.elapsed() >= TCP_REMAP_RECONNECT_COOLDOWN);
        // Deliberately not gated on UPnP: a LowID session is exactly
        // where a UPnP forward has been shown not to work, and
        // `advertised_tcp_port` already falls back to the STUN port in
        // that state, so this reconnect re-logs in on a port that has
        // not been tried yet rather than re-sending the same one.
        if should_reconnect_for_tcp_remap(
            state.low_id,
            state.server_connected,
            state.pending_server_connect.is_some(),
            state.external_tcp_port,
            state.server_login_tcp_port,
            cooldown_elapsed,
        ) {
            if let Some(addr) = state.server_addr {
                info!(
                    "STUN keepalive: public TCP port confirmed as {:?} (server has {:?}) while LowID — reconnecting to eD2k server for a fresh HighID check",
                    state.external_tcp_port, state.server_login_tcp_port
                );
                state.last_tcp_remap_reconnect_at = Some(std::time::Instant::now());
                initiate_server_connect(
                    state,
                    settings,
                    app_handle,
                    shared_server_addr,
                    addr.ip().to_string(),
                    addr.port(),
                )
                .await;
            }
        }
    }
    if !udp_map_ka_in_flight
        && !*tcp_map_ka_in_flight
        && !*mapping_ka_cycle_success
    {
        if state.stats.stun_keepalive_active {
            info!(
                "STUN keepalive: cycle completed without a confirmed UDP mapping or TCP hold (tcp_hold_ok={}) — marking inactive until the next cycle",
                result.hold_ok
            );
        }
        state.stats.stun_keepalive_active = false;
    }
}
