//! NAT probing, STUN and UPnP mapping keep-alives, and the ports we
//! advertise.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

pub(super) fn spawn_nat_probe(
    udp_socket: Arc<UdpSocket>,
    result_tx: mpsc::UnboundedSender<NatProbeResult>,
    generation: u64,
    reason: &'static str,
) -> mpsc::Sender<(Vec<u8>, SocketAddr)> {
    let (packet_tx, packet_rx) = mpsc::channel(32);
    tokio::spawn(async move {
        let info = ember::nat::probe_nat_with_replies(udp_socket, packet_rx).await;
        let _ = result_tx.send(NatProbeResult {
            generation,
            reason,
            info,
        });
    });
    packet_tx
}

pub(super) fn route_stun_binding_packet(
    probe_tx: &mut Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>,
    keepalive_tx: &mut Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>,
    data: &[u8],
    from: SocketAddr,
) -> bool {
    if !ember::nat::is_stun_binding_response(data) {
        return false;
    }
    for slot in [probe_tx, keepalive_tx] {
        let Some(tx) = slot.as_ref() else {
            continue;
        };
        match tx.try_send((data.to_vec(), from)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                debug!("Dropping STUN response from {from}: channel full");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                *slot = None;
            }
        }
    }
    true
}

pub(super) fn spawn_udp_mapping_keepalive(
    udp_socket: Arc<UdpSocket>,
    result_tx: mpsc::UnboundedSender<UdpMappingKeepaliveResult>,
    generation: u64,
    server_index: usize,
) -> mpsc::Sender<(Vec<u8>, SocketAddr)> {
    let (packet_tx, packet_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        let mapped = ember::mapping_keepalive::stun_keepalive_with_replies(
            udp_socket,
            packet_rx,
            server_index,
        )
        .await;
        let _ = result_tx.send(UdpMappingKeepaliveResult { generation, mapped });
    });
    packet_tx
}

/// The TCP port a *peer* should connect back to, in descending order of
/// authority: a live UPnP mapping, then a STUN-over-TCP-confirmed public port
/// (see `apply_tcp_mapping_keepalive`), then the raw configured listener port.
///
/// UPnP outranks STUN because the two measure different things. UPnP installs
/// an explicit *inbound* forward for `tcp_port -> tcp_port`, so while it is
/// live that is exactly where an unsolicited connection lands. STUN over TCP
/// observes the mapping a NAT created for an *outbound* connection from the
/// listen port, and plenty of gateways allocate a fresh external port for that
/// flow even while honouring a static UPnP forward. Preferring the STUN port
/// there told every KAD peer and the eD2K server to dial a port the router was
/// not forwarding: every connect-back failed, so we reported Firewalled while
/// the router's own UPnP page correctly showed the real mapping wide open.
///
/// The exception is LowID. That assignment is the eD2K server reporting that it
/// could not reach the port we advertised, which is direct evidence the forward
/// is not carrying traffic however healthy the router claims it is — a CGNAT
/// layer above a UPnP-capable inner router being the usual cause. There the
/// STUN mapping is the only candidate with a chance of being reachable, so it
/// wins until a HighID proves the forward works.
pub(super) fn advertised_tcp_port(state: &NetworkState) -> u16 {
    advertised_tcp_port_from(
        state.upnp_tcp_port,
        state.external_tcp_port,
        state.tcp_port,
        state.low_id,
    )
}

pub(super) fn advertised_tcp_port_from(
    upnp_tcp_port: Option<u16>,
    external_tcp_port: Option<u16>,
    configured_tcp_port: u16,
    server_assigned_low_id: bool,
) -> u16 {
    let stun_port = external_tcp_port.filter(|port| *port != 0);
    if server_assigned_low_id {
        if let Some(port) = stun_port {
            return port;
        }
    }
    upnp_tcp_port
        .filter(|port| *port != 0)
        .or(stun_port)
        .unwrap_or(configured_tcp_port)
}

/// Port captured for `OP_LOGINREQUEST` *before* session teardown clears
/// `low_id`. That flag is evidence our own forward is not carrying traffic;
/// capturing after it is cleared would advertise the UPnP port that just
/// earned the LowID.
pub(super) fn capture_advertised_tcp_port_then_reset_low_id(
    upnp_tcp_port: Option<u16>,
    external_tcp_port: Option<u16>,
    configured_tcp_port: u16,
    low_id: &mut bool,
) -> u16 {
    let tcp_port = advertised_tcp_port_from(
        upnp_tcp_port,
        external_tcp_port,
        configured_tcp_port,
        *low_id,
    );
    *low_id = false;
    tcp_port
}

/// UDP counterpart of `advertised_tcp_port` — the KAD-peer-voted or
/// STUN-confirmed public UDP port when known, otherwise the raw bind port.
pub(super) fn advertised_udp_port(state: &NetworkState) -> u16 {
    state
        .external_udp_port
        .filter(|p| *p != 0)
        .unwrap_or(state.udp_port)
}

/// The QUIC port a *peer* should dial: the public port STUN found for the QUIC
/// socket at bind time, falling back to the bound port.
///
/// The two differ only on a NAT that re-maps ports (CGNAT), and only the public
/// one is reachable there. This is deliberately not `advertised_udp_port`: that
/// tracks the KAD socket, and NAT mappings are per-socket, so its public port
/// says nothing about where QUIC can be reached. `None` means no QUIC endpoint
/// is bound yet. Mapping keep-alive transmits from this socket to hold the
/// mapping open; it does not re-sample the public port.
pub(super) fn advertised_quic_port(state: &NetworkState) -> Option<u16> {
    state
        .quic_public_port
        .filter(|p| *p != 0)
        .or(state.quic_port)
        .filter(|p| *p != 0)
}

/// Keep the DHT engine's advertised buddy identity in sync with STUN/UPnP.
pub(super) fn refresh_ember_advertised_buddy(state: &mut NetworkState) {
    let ip = state.external_ip.unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
    state.ember_dht.set_advertised_buddy(
        *state.ember_transport.local_noise_public_key(),
        ip,
        advertised_udp_port(state),
    );
}

/// Whether STUN keep-alive should actively refresh/advertise mappings.
/// Symmetric / unstable remapping (typical VPN) must not override Settings ports.
pub(super) fn mapping_probe_allowed_by_activity(
    server_connected: bool,
    kad_connected: bool,
    active_transfer: bool,
    active_friend_connection: bool,
) -> bool {
    server_connected || kad_connected || active_transfer || active_friend_connection
}

pub(super) fn mapping_probe_has_active_reason(state: &NetworkState) -> bool {
    mapping_probe_allowed_by_activity(
        state.server_connected,
        kad_ready_for_sources(state),
        !state.pending_downloads.is_empty() || !state.active_source_senders.is_empty(),
        !state.online_friends.is_empty() || !state.outbound_session_tasks.is_empty(),
    )
}

pub(super) fn stun_keepalive_should_run(state: &NetworkState) -> bool {
    state.stun_keepalive_enabled
        && !state.stun_ka_auto_suspended
        && mapping_probe_has_active_reason(state)
}

/// Whether `external_udp_port` currently holds a STUN-confirmed mapping that
/// keep-alive is actively maintaining. KAD firewall Pong/FirewallUdp peer
/// votes must not silently clobber this — otherwise a stale or minority vote
/// for the internal bind port can undo a live full-cone/CGNAT remap advertise.
pub(super) fn stun_udp_mapping_active(state: &NetworkState) -> bool {
    stun_keepalive_should_run(state)
        && state.stun_sourced_udp_port.is_some()
        && state.stun_sourced_udp_port == state.external_udp_port
}

/// Fully reset STUN keep-alive session state: clears auto-suspend, all
/// candidate/stability tracking (UDP + TCP), and reverts advertise ports to
/// Settings. Used for state transitions where prior STUN progress is no
/// longer meaningful — disabling the feature, re-enabling it after it was
/// off, and KAD disconnect (a new session may be a different network).
pub(super) fn reset_stun_keepalive_session(state: &mut NetworkState) {
    state.stun_ka_auto_suspended = false;
    state.stun_ka_suspended_at = None;
    state.stun_ka_candidate_port = None;
    state.stun_ka_stable_hits = 0;
    state.stun_ka_tcp_candidate_port = None;
    state.stun_ka_tcp_stable_hits = 0;
    // Invalidate any UDP/TCP mapping keep-alive cycle still in flight from
    // before this reset (mirrors nat_probe_generation) — otherwise a stale
    // result computed against pre-reset conditions can land right after and
    // silently re-populate the fields this function just cleared.
    state.mapping_ka_generation = state.mapping_ka_generation.wrapping_add(1);
    revert_stun_advertise_to_settings(state);
}

pub(super) fn revert_stun_advertise_to_settings(state: &mut NetworkState) {
    // Only clear UDP when the current external port was STUN-sourced, so
    // KAD firewall peer votes survive STUN disable/suspend. Prefer the
    // firewall checker's vote when available.
    if let Some(stun_port) = state.stun_sourced_udp_port.take() {
        if state.external_udp_port == Some(stun_port) {
            state.external_udp_port = state.firewall_checker.external_udp_port();
        }
    }
    state.external_tcp_port = None;
    state.stats.public_tcp_port = 0;
    state.stats.public_udp_port = 0;
    state.stats.stun_keepalive_active = false;
    state.publish_manager.tcp_port = state.tcp_port;
    update_publish_manager_state(state);
}

/// Clear `external_udp_port` for a firewall recheck without wiping a
/// STUN-confirmed remapping (shared field; advertise must stay coherent).
pub(super) fn clear_external_udp_for_firewall_recheck(state: &mut NetworkState) {
    if state
        .stun_sourced_udp_port
        .is_some_and(|p| state.external_udp_port == Some(p))
    {
        return;
    }
    state.external_udp_port = None;
}

pub(super) fn suspend_stun_keepalive(state: &mut NetworkState, reason: &'static str) {
    if state.stun_ka_auto_suspended {
        return;
    }
    state.stun_ka_auto_suspended = true;
    state.stun_ka_suspended_at = Some(std::time::Instant::now());
    state.stun_ka_candidate_port = None;
    state.stun_ka_stable_hits = 0;
    state.stun_ka_tcp_candidate_port = None;
    state.stun_ka_tcp_stable_hits = 0;
    revert_stun_advertise_to_settings(state);
    debug!(
        "STUN keepalive auto-suspended ({reason}); advertising Settings ports TCP {} / UDP {}",
        state.tcp_port, state.udp_port
    );
}

pub(super) fn maybe_suspend_stun_from_nat_type(state: &mut NetworkState) {
    match state.nat_info.nat_type {
        ember::nat::NatType::Symmetric => {
            suspend_stun_keepalive(state, "symmetric NAT — public port is per-destination");
        }
        ember::nat::NatType::Open => {
            // No remapping needed; Settings ports are already correct.
            suspend_stun_keepalive(state, "open internet — STUN advertise unnecessary");
        }
        _ => {}
    }
}

/// Apply a UDP STUN keep-alive observation. Returns `true` when the mapping
/// is confirmed (1:1 hold or stable remapped advertise).
pub(super) fn apply_udp_mapping_keepalive(
    state: &mut NetworkState,
    mapped: SocketAddr,
    app: &tauri::AppHandle,
) -> bool {
    if !stun_keepalive_should_run(state) {
        return false;
    }

    let port = mapped.port();
    if port == 0 {
        return false;
    }
    // UI always shows the latest observed mapping.
    state.stats.public_udp_port = port;

    // 1:1 mapping (public port == local bind): good for keep-alive hold, no
    // need to override advertise (Settings already match).
    if port == state.udp_port {
        if let Some(stun_port) = state.stun_sourced_udp_port.take() {
            if state.external_udp_port == Some(stun_port) {
                state.external_udp_port = state.firewall_checker.external_udp_port();
            }
            update_publish_manager_state(state);
        }
        // `stun_ka_candidate_port`/`stun_ka_stable_hits` track an
        // *unconfirmed remap* only (see the match below) — they must NOT
        // hold the 1:1 bind port, or the very first genuine remap after a
        // 1:1 period would see a "changed" candidate and be misdiagnosed as
        // flapping/unstable, auto-suspending on exactly the transition this
        // feature exists to handle.
        state.stun_ka_candidate_port = None;
        state.stun_ka_stable_hits = 0;
        // Log only on the false->true transition — the steady-state 1:1
        // case (the common CGNAT/port-forward outcome) would otherwise be
        // completely silent every cycle at INFO level, making it
        // indistinguishable in the logs from the feature not running at
        // all. See the analogous "stable public UDP mapping" log below for
        // the remapped case.
        if !state.stats.stun_keepalive_active {
            info!("STUN keepalive: confirmed 1:1 UDP mapping {mapped} (no remap needed)");
        }
        state.stats.stun_keepalive_active = true;
        if let Some(ip) = ember::mapping_keepalive::ipv4_from_mapped(mapped) {
            adopt_stun_mapped_external_ip(state, ip);
        }
        return true;
    }

    // Remapped public port: only advertise after two consecutive identical
    // observations (stable full-cone / CGNAT). Flapping ⇒ auto-suspend
    // (VPN / symmetric behavior).
    match state.stun_ka_candidate_port {
        Some(prev) if prev == port => {
            state.stun_ka_stable_hits = state.stun_ka_stable_hits.saturating_add(1);
        }
        Some(prev) => {
            info!("STUN keepalive: public UDP port changed {prev} → {port}; treating as unstable");
            suspend_stun_keepalive(state, "unstable public UDP port (not full-cone)");
            state.stats.public_udp_port = port; // still show last observation
            return false;
        }
        None => {
            state.stun_ka_candidate_port = Some(port);
            state.stun_ka_stable_hits = 1;
            info!("STUN keepalive: candidate public UDP mapping {mapped} (awaiting confirm)");
            return false;
        }
    }

    if state.stun_ka_stable_hits < 2 {
        return false;
    }

    let prev = state.external_udp_port;
    state.external_udp_port = Some(port);
    state.stun_sourced_udp_port = Some(port);
    state.stats.stun_keepalive_active = true;
    state
        .advertise_udp_port
        .store(port, std::sync::atomic::Ordering::Relaxed);

    if let Some(ip) = ember::mapping_keepalive::ipv4_from_mapped(mapped) {
        adopt_stun_mapped_external_ip(state, ip);
        if state.nat_info.external_addr != Some(mapped) {
            state.nat_info.external_addr = Some(mapped);
            state.nat_info.last_probed = std::time::Instant::now();
            // Deliberately do NOT infer `nat_type` from a 1:1 keep-alive
            // confirmation. This used to assume PortRestricted here, which
            // closes the `nat_type == Unknown` gate that all three NAT-probe
            // trigger sites depend on — since this 1:1 path fires within
            // ~3s of startup (often before the dedicated multi-server probe
            // even gets a chance to run), it was permanently short-circuiting
            // the real Open/Symmetric classification that `maybe_suspend_
            // stun_from_nat_type` needs, so auto-suspend could never fire.
            // Leave nat_type to the dedicated probe (and its own
            // apply_highid_fallback) to determine.
            if let Ok(mut ctx) = state.friend_nat_context.write() {
                ctx.external_addr = Some(mapped);
                ctx.nat_type = state.nat_info.nat_type;
            }
        }
    }

    update_publish_manager_state(state);
    if prev != Some(port) {
        info!("STUN keepalive: stable public UDP mapping {mapped} (was {prev:?})");
        let _ = app.emit(
            "stun-keepalive",
            serde_json::json!({
                "public_udp_port": port,
                "public_tcp_port": state.stats.public_tcp_port,
                "tcp_hold_ok": state.stats.tcp_mapping_hold_ok,
            }),
        );
    }
    true
}

/// Minimum gap between mapping-keep-alive-triggered eD2k reconnects (see the
/// `tcp_map_ka_result_rx` arm). The two-hit confirmation gate already makes
/// back-to-back *different* confirmed values ~40s apart at best; this is an
/// explicit floor on top of that so a pathologically unstable mapping can't
/// reconnect-thrash the server session faster than this.
pub(super) const TCP_REMAP_RECONNECT_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(60);

/// Whether the mapping keep-alive should force a reconnect to the currently
/// connected eD2k server to push a STUN-confirmed TCP port remap that
/// arrived after login. eD2k has no "update my port" message once logged
/// in, so a remap confirmed later (the common case — confirmation needs two
/// keep-alive cycles, ~40s, which can easily land after an
/// already-in-progress login) would otherwise sit unused until some
/// unrelated reconnect. Only reconnects when it can actually help (still
/// LowID, actually connected, no reconnect already in flight), only for a
/// value the server doesn't already have on file, and never faster than
/// `TCP_REMAP_RECONNECT_COOLDOWN` — a per-value cooldown already falls out
/// of the two-hit confirmation gate, but this adds an explicit floor so a
/// pathologically unstable mapping can't reconnect-thrash the session.
pub(super) fn should_reconnect_for_tcp_remap(
    low_id: bool,
    server_connected: bool,
    reconnect_in_flight: bool,
    confirmed_port: Option<u16>,
    server_login_tcp_port: Option<u16>,
    cooldown_elapsed: bool,
) -> bool {
    low_id
        && server_connected
        && !reconnect_in_flight
        && cooldown_elapsed
        && confirmed_port.is_some()
        && confirmed_port != server_login_tcp_port
}

/// Decide whether a TCP STUN reading should be trusted immediately, needs
/// another consecutive confirmation, or should keep accumulating. A 1:1
/// result is safe immediately; a remapped result must repeat once to avoid
/// advertising a transient/flapping mapping. UDP observations are
/// intentionally excluded because TCP and UDP NAT mappings are independent.
pub(super) fn tcp_port_confirmation(
    configured_tcp_port: u16,
    candidate_port: Option<u16>,
    stable_hits: u8,
    observed_port: u16,
) -> TcpPortConfirmation {
    if observed_port == 0 {
        return TcpPortConfirmation {
            candidate_port,
            stable_hits,
            confirmed_port: None,
        };
    }
    if observed_port == configured_tcp_port {
        return TcpPortConfirmation {
            candidate_port: None,
            stable_hits: 0,
            confirmed_port: Some(observed_port),
        };
    }
    let (next_candidate, next_hits) = match candidate_port {
        Some(prev) if prev == observed_port => (Some(prev), stable_hits.saturating_add(1)),
        _ => (Some(observed_port), 1),
    };
    if next_hits >= 2 {
        TcpPortConfirmation {
            candidate_port: None,
            stable_hits: 0,
            confirmed_port: Some(observed_port),
        }
    } else {
        TcpPortConfirmation {
            candidate_port: next_candidate,
            stable_hits: next_hits,
            confirmed_port: None,
        }
    }
}

/// Apply a TCP mapping keep-alive result discovered with STUN over TCP from
/// the listener's local port.
/// Returns `true` when the cycle contributed something useful (a successful
/// hold and/or a confirmed public TCP mapping), so the caller can decide
/// whether the overall keep-alive "Active" indicator should stay on.
pub(super) fn apply_tcp_mapping_keepalive(
    state: &mut NetworkState,
    hold_ok: bool,
    mapped: Option<SocketAddr>,
    app: &tauri::AppHandle,
) -> bool {
    if !stun_keepalive_should_run(state) {
        return false;
    }
    let hold_changed = state.stats.tcp_mapping_hold_ok != hold_ok;
    state.stats.tcp_mapping_hold_ok = hold_ok;
    let mut changed = hold_changed;
    let mut confirmed = hold_ok;
    if let Some(addr) = mapped {
        let result = tcp_port_confirmation(
            state.tcp_port,
            state.stun_ka_tcp_candidate_port,
            state.stun_ka_tcp_stable_hits,
            addr.port(),
        );
        state.stun_ka_tcp_candidate_port = result.candidate_port;
        state.stun_ka_tcp_stable_hits = result.stable_hits;
        if let Some(port) = result.confirmed_port {
            confirmed = true;
            if state.external_tcp_port != Some(port) {
                changed = true;
            }
            state.external_tcp_port = Some(port);
            state.stats.public_tcp_port = port;
            if let Some(ip) = ember::mapping_keepalive::ipv4_from_mapped(addr) {
                adopt_stun_mapped_external_ip(state, ip);
            }
            update_publish_manager_state(state);
        } else {
            debug!("STUN keepalive: candidate public TCP mapping {addr} (awaiting confirm)");
        }
    } else if hold_ok {
        // TCP hold alone (TCP STUN unavailable) is still a successful
        // keep-alive contribution. Same false->true
        // transition logging rationale as the UDP 1:1 case above — this
        // path is otherwise silent every cycle.
        if !state.stats.stun_keepalive_active {
            info!(
                "STUN keepalive: TCP mapping hold confirmed (local port {})",
                state.tcp_port
            );
        }
    }
    if confirmed {
        state.stats.stun_keepalive_active = true;
    }
    if changed {
        info!("STUN keepalive: public TCP mapping {mapped:?} hold_ok={hold_ok}");
        let _ = app.emit(
            "stun-keepalive",
            serde_json::json!({
                "public_udp_port": state.stats.public_udp_port,
                "public_tcp_port": state.stats.public_tcp_port,
                "tcp_hold_ok": hold_ok,
            }),
        );
    }
    confirmed
}
