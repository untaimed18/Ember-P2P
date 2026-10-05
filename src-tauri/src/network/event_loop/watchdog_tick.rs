//! The watchdog tick: drops a server connection that has gone silent, releases
//! background saves, probes and keep-alives that overran their deadline, and
//! notices when KAD has gone quiet.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_watchdog_tick(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    shared_server_addr: &Arc<RwLock<Option<SocketAddr>>>,
    cache_write_handle: &Option<tokio::task::JoinHandle<()>>,
    known2_save_in_flight: bool,
    known2_save_started_at: Option<tokio::time::Instant>,
    last_cache_refresh_started_at: &mut i64,
    last_kad_activity_at: &mut i64,
    last_server_activity_at: i64,
    nat_probe_backoff_until: &mut Option<tokio::time::Instant>,
    nat_probe_in_flight: &mut bool,
    nat_probe_packet_tx: &mut Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>,
    nat_probe_started_at: &mut Option<tokio::time::Instant>,
    nodes_save_in_flight: bool,
    nodes_save_started_at: Option<tokio::time::Instant>,
    reputation_save_in_flight: bool,
    reputation_save_started_at: Option<tokio::time::Instant>,
    spam_save_in_flight: &mut bool,
    spam_save_started_at: &mut Option<tokio::time::Instant>,
    stats_save_in_flight: &mut bool,
    stats_save_started_at: &mut Option<tokio::time::Instant>,
    tcp_map_ka_gen: &mut Option<u64>,
    tcp_map_ka_in_flight: &mut bool,
    tcp_map_ka_started_at: &mut Option<tokio::time::Instant>,
    udp_map_ka_gen: &mut Option<u64>,
    udp_map_ka_in_flight: &mut bool,
    udp_map_ka_packet_tx: &mut Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>,
    udp_map_ka_started_at: &mut Option<tokio::time::Instant>,
    upnp_maintain_handle: &mut Option<tokio::task::JoinHandle<()>>,
    upnp_maintain_in_flight: &mut bool,
    upnp_maintain_started_at: &mut Option<tokio::time::Instant>,
) {
    let now = crate::network::monotonic_secs();

    if let Some(reason) = server_watchdog_disconnect_reason(
        state.server_connected,
        state.server_connection.is_some(),
        now.saturating_sub(last_server_activity_at),
    ) {
        handle_server_disconnect(state, shared_server_addr, app_handle, reason).await;
    }

    if cache_write_handle.as_ref().is_some_and(|h| !h.is_finished())
        && *last_cache_refresh_started_at > 0
        && now.saturating_sub(*last_cache_refresh_started_at) > 20
    {
        warn!(
            "Watchdog: cache refresh still running after {}s; leaving it owned so the cache bundle cannot be partially applied by abort",
            now.saturating_sub(*last_cache_refresh_started_at)
        );
        *last_cache_refresh_started_at = 0;
    }

    let timed_out = |started: Option<tokio::time::Instant>, limit: std::time::Duration| {
        started.is_some_and(|started| started.elapsed() > limit)
    };
    if nodes_save_in_flight && timed_out(nodes_save_started_at, SHORT_IO_WATCHDOG) {
        warn!(
            "Watchdog: nodes.dat save exceeded timeout; suppressing overlapping retry until serialized writer finishes"
        );
    }
    if *spam_save_in_flight && timed_out(*spam_save_started_at, SHORT_IO_WATCHDOG) {
        warn!("Watchdog: spam-filter save exceeded timeout; allowing next retry");
        *spam_save_in_flight = false;
        *spam_save_started_at = None;
    }
    if *stats_save_in_flight && timed_out(*stats_save_started_at, PERIODIC_SAVE_WATCHDOG) {
        warn!("Watchdog: statistics save exceeded timeout; allowing next retry");
        *stats_save_in_flight = false;
        *stats_save_started_at = None;
    }
    if reputation_save_in_flight
        && timed_out(reputation_save_started_at, PERIODIC_SAVE_WATCHDOG)
    {
        warn!(
            "Watchdog: reputation save exceeded timeout; suppressing overlapping retry until serialized writer finishes"
        );
    }
    if known2_save_in_flight && timed_out(known2_save_started_at, PERIODIC_SAVE_WATCHDOG) {
        warn!(
            "Watchdog: known2_64.met save exceeded timeout; suppressing overlapping retry until serialized writer finishes"
        );
    }
    if *upnp_maintain_in_flight
        && timed_out(*upnp_maintain_started_at, PERIODIC_SAVE_WATCHDOG)
    {
        warn!("Watchdog: UPnP maintenance exceeded timeout; aborting it and allowing next retry");
        // Abort before clearing the flag. Left running it is
        // unobservable — nothing joins it and its result is
        // discarded on arrival by the revision check — so it would
        // only sit on a gateway socket while the pass we are about
        // to allow does the same work.
        if let Some(handle) = upnp_maintain_handle.take() {
            handle.abort();
        }
        *upnp_maintain_in_flight = false;
        *upnp_maintain_started_at = None;
    }
    if *nat_probe_in_flight && timed_out(*nat_probe_started_at, NAT_PROBE_WATCHDOG) {
        warn!("Watchdog: NAT probe exceeded timeout; allowing next retry");
        state.nat_probe_generation =
            state.nat_probe_generation.saturating_add(1);
        *nat_probe_in_flight = false;
        *nat_probe_started_at = None;
        *nat_probe_packet_tx = None;
        *nat_probe_backoff_until = Some(
            tokio::time::Instant::now() + std::time::Duration::from_secs(300),
        );
    }
    if (*udp_map_ka_in_flight
        && timed_out(*udp_map_ka_started_at, MAPPING_KA_WATCHDOG))
        || (*tcp_map_ka_in_flight
            && timed_out(*tcp_map_ka_started_at, MAPPING_KA_WATCHDOG))
    {
        warn!(
            "Watchdog: STUN mapping keepalive exceeded timeout; allowing next retry"
        );
        state.mapping_ka_generation =
            state.mapping_ka_generation.wrapping_add(1);
        *udp_map_ka_in_flight = false;
        *tcp_map_ka_in_flight = false;
        *udp_map_ka_started_at = None;
        *tcp_map_ka_started_at = None;
        *udp_map_ka_gen = None;
        *tcp_map_ka_gen = None;
        *udp_map_ka_packet_tx = None;
        state.stats.stun_keepalive_active = false;
    }

    if !state.pending_downloads.is_empty()
        && network_ready_for_sources(state)
        && now.saturating_sub(*last_kad_activity_at) > 180
    {
        for pending in state.pending_downloads.values_mut() {
            pending.last_search_at = None;
        }
        debug!(
            "Watchdog: no UDP activity for {}s with {} pending downloads; forcing immediate source refresh",
            now.saturating_sub(*last_kad_activity_at),
            state.pending_downloads.len()
        );
        *last_kad_activity_at = now;
    }
}

/// Why the watchdog should drop the eD2K session, if it should.
///
/// The server tick takes the link out of `state` while it works on it, so a
/// panic there loses the link and leaves `server_connected` set. Nothing else
/// clears that pair: reconnecting waits for `!server_connected`, and the
/// silence check below needs a link to judge.
fn server_watchdog_disconnect_reason(
    server_connected: bool,
    has_server_link: bool,
    secs_since_server_activity: i64,
) -> Option<&'static str> {
    if !server_connected {
        return None;
    }
    if !has_server_link {
        return Some("watchdog: server marked connected without a live session");
    }
    (secs_since_server_activity > 120).then_some("watchdog: no server activity for 120s")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watchdog_resets_a_connected_status_whose_session_was_lost() {
        assert_eq!(
            server_watchdog_disconnect_reason(true, false, 0),
            Some("watchdog: server marked connected without a live session")
        );
    }

    #[test]
    fn watchdog_drops_a_silent_server_session() {
        assert_eq!(server_watchdog_disconnect_reason(true, true, 120), None);
        assert_eq!(
            server_watchdog_disconnect_reason(true, true, 121),
            Some("watchdog: no server activity for 120s")
        );
    }

    #[test]
    fn watchdog_leaves_a_disconnected_server_alone() {
        assert_eq!(server_watchdog_disconnect_reason(false, false, 10_000), None);
        assert_eq!(server_watchdog_disconnect_reason(false, true, 10_000), None);
    }
}
