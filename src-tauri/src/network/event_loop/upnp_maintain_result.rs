//! Applying the result of a UPnP maintenance pass.

use super::*;

pub(in crate::network) async fn on_upnp_maintain_result(
    result: UpnpMaintainResult,
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    upnp_maintain_handle: &mut Option<tokio::task::JoinHandle<()>>,
    upnp_maintain_in_flight: &mut bool,
    upnp_maintain_started_at: &mut Option<tokio::time::Instant>,
    upnp_mappings: &mut upnp::UpnpMappings,
) {
    *upnp_maintain_in_flight = false;
    *upnp_maintain_started_at = None;
    // The pass that produced this result has finished; dropping a
    // completed handle is what keeps the watchdog from aborting
    // whichever pass happens to be running next.
    *upnp_maintain_handle = None;
    if result.revision == upnp_mappings.revision() {
        let was_mapped = state.upnp_mapped;
        upnp_mappings.adopt(result.mappings);
        let mapped = result.mapped;
        state.upnp_mapped = mapped;
        state.stats.upnp_mapped = mapped;
        state.stats.upnp_stood_down = upnp_mappings.stood_down();
        // A live inbound forward is `tcp_port -> tcp_port`, so it
        // is authoritative for what peers should dial. Re-run the
        // publish state whenever that changes so the advertise
        // atomic the upload listener reads follows immediately
        // rather than at the next unrelated update.
        let upnp_tcp_port = upnp_mappings.tcp_mapped().then_some(state.tcp_port);
        let tcp_forward_lost = state.upnp_tcp_port.is_some() && upnp_tcp_port.is_none();
        if state.upnp_tcp_port != upnp_tcp_port {
            state.upnp_tcp_port = upnp_tcp_port;
            update_publish_manager_state(state);
        }
        if mapped && !was_mapped {
            // Same semantics as startup (`firewalled:
            // !upnp_success`): a fresh mapping means inbound
            // TCP should now reach us. The shared atomic is
            // only ever allowed to clear the firewalled flag
            // (see the sweep that consumes it), never assert
            // it, so this can't override a FirewallChecker
            // determination in the other direction.
            // Do not clear while the ed2k server has us on
            // LowID — that assignment is authoritative until
            // the server gives HighID.
            if !state.low_id {
                state.firewalled_shared.store(false, std::sync::atomic::Ordering::Relaxed);
            }
        }
        if tcp_forward_lost {
            reassert_checker_firewalled(state, app_handle);
        }
        // Always emit so deferred startup's first result (and
        // mid-session maintain) update the UI, including the
        // `gateway_found` bit when mapping stayed false.
        let _ = app_handle.emit(
            "upnp-status",
            serde_json::json!({
                "mapped": mapped,
                "gateway_found": upnp_mappings.has_gateway(),
                "stood_down": upnp_mappings.stood_down(),
                "tcp_port": state.tcp_port,
                "udp_port": state.udp_port,
            }),
        );
    } else {
        debug!("Discarding stale UPnP maintenance result after mapping state changed");
    }
}

/// The mirror of a fresh mapping clearing the aggregate flag: with the forward
/// gone, the FirewallChecker's own measurement of TCP stands again. Only a
/// measured `Firewalled` is restored; HighID records itself in the checker as
/// a connect-back, so it reads `Open` and is left alone.
fn reassert_checker_firewalled(state: &mut NetworkState, app_handle: &tauri::AppHandle) {
    if state.firewalled || !state.firewall_checker.tcp_firewalled() {
        return;
    }
    info!("UPnP forward gone; restoring the firewall check's TCP verdict (firewalled)");
    state.firewalled = true;
    state.firewalled_shared.store(true, std::sync::atomic::Ordering::Relaxed);
    state.stats.firewalled = true;
    kad::firewall::publish_local_firewall(state.firewalled, state.udp_firewalled);
    update_publish_manager_state(state);
    let _ = app_handle.emit(
        "firewall-status",
        serde_json::json!({
            "firewalled": state.firewalled,
            "external_ip": state.stats.external_ip,
            "tcp_status": state.stats.tcp_status,
            "udp_status": state.stats.udp_status,
        }),
    );
}
