//! Applying the result of a background NAT probe.

use super::*;

pub(in crate::network) async fn on_nat_probe_result(
    result: NatProbeResult,
    state: &mut NetworkState,
    nat_probe_backoff_until: &mut Option<tokio::time::Instant>,
    nat_probe_in_flight: &mut bool,
    nat_probe_packet_tx: &mut Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>,
    nat_probe_started_at: &mut Option<tokio::time::Instant>,
) {
    if result.generation != state.nat_probe_generation {
        debug!(
            "Ignoring stale NAT probe result generation {} (current {})",
            result.generation, state.nat_probe_generation
        );
        return;
    }
    *nat_probe_in_flight = false;
    *nat_probe_started_at = None;
    *nat_probe_packet_tx = None;
    let probe_mapped_v4 = result.info.external_addr.and_then(|a| match a.ip() {
        std::net::IpAddr::V4(ip) => Some(ip),
        std::net::IpAddr::V6(_) => None,
    });
    state.nat_info = result.info;
    // A STUN keep-alive-confirmed mapping is more current than
    // whatever this probe found (or failed to find) — restore it
    // so a failed/partial probe cannot silently drop it.
    if stun_udp_mapping_active(state) {
        if let (Some(ip), Some(port)) =
            (state.external_ip, state.stun_sourced_udp_port)
        {
            let confirmed = SocketAddr::new(std::net::IpAddr::V4(ip), port);
            state.nat_info.external_addr = Some(confirmed);
            if state.nat_info.nat_type == ember::nat::NatType::Unknown {
                state.nat_info.nat_type = ember::nat::NatType::PortRestricted;
            }
        }
    }
    if state.nat_info.nat_type == ember::nat::NatType::Unknown {
        *nat_probe_backoff_until = Some(
            tokio::time::Instant::now() + std::time::Duration::from_secs(300),
        );
    } else {
        *nat_probe_backoff_until = None;
    }
    // STUN may replace a KAD/Ember vote that won the startup race.
    // A live HighID is left alone (TCP connect-back vs UDP mapping).
    if let Some(ip) = probe_mapped_v4 {
        adopt_stun_mapped_external_ip(state, ip);
    }
    if let Some(ext_ip) = state.external_ip {
        if state.nat_info.apply_highid_fallback(
            std::net::IpAddr::V4(ext_ip),
            state.udp_port,
        ) {
            info!(
                "NAT probe ({}) failed but external IP {} is confirmed — assuming PortRestricted (mapped {}:{})",
                result.reason, ext_ip, ext_ip, state.udp_port,
            );
        }
    }
    // Publish the final (post-fallback) nat_type/external_addr to
    // spawned friend-dial tasks — see `FriendNatContext`.
    {
        let mut ctx = state.friend_nat_context.write().unwrap_or_else(|p| p.into_inner());
        ctx.nat_type = state.nat_info.nat_type;
        ctx.external_addr = state.nat_info.external_addr;
    }
    // Surface the class to the UI so the Friends page can be honest
    // about a symmetric NAT, where friend hole-punching cannot work.
    state.stats.nat_type = format!("{:?}", state.nat_info.nat_type);
    maybe_suspend_stun_from_nat_type(state);
}
