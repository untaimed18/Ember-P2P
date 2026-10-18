//! Upload slot scheduling (USS): pinging KAD contacts to measure RTT.

use super::*;

/// Contacts USS rotates its pings over.
///
/// eMule takes two KADEMLIA2_PING a minute from one IP (see `kad::outbound`),
/// so a single host gave USS one sample per 31.5 s: a two-minute baseline and
/// minutes to notice congestion. Rotating over a pool, one ping in flight at a
/// time, gives a sample about every `USS_SAMPLE_INTERVAL`. The pool is the
/// longest-known eligible contacts, so it only changes when one leaves the
/// routing table and USS keeps the per-host baselines it measured.
const USS_PING_POOL: usize = 16;
/// Aimed-for spacing of samples across the pool.
const USS_SAMPLE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(4);
const USS_PING_TIMEOUT_SECS: u64 = 3;
/// Half the outbound governor's window: two pings per window, evenly spaced.
/// The most a host is ever pinged, used only when the pool is small.
const USS_PING_MIN_GAP: std::time::Duration = std::time::Duration::from_millis(31_500);
/// A full pool pings each host once per governor window. Two a minute is the
/// whole of the per-IP bucket `kad::outbound` keeps, which would leave the
/// pool's contacts — the oldest, so the ones lookups favour — no room for
/// anything else.
const USS_PING_MAX_GAP: std::time::Duration = std::time::Duration::from_secs(63);

/// Per-host spacing that keeps the pool's samples `USS_SAMPLE_INTERVAL` apart.
fn per_host_gap(pool_len: usize) -> std::time::Duration {
    (USS_SAMPLE_INTERVAL * pool_len.max(1) as u32).clamp(USS_PING_MIN_GAP, USS_PING_MAX_GAP)
}

/// Spacing between pings to the pool as a whole: the per-host gap shared out
/// across its hosts. Without it every host came ready together, the pool was
/// pinged in one burst, and nothing was measured until the gap ran out.
fn pool_spacing(pool_len: usize) -> std::time::Duration {
    per_host_gap(pool_len) / pool_len.max(1) as u32
}

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

    // Count timed-out in-flight pings as misses, then drop them. A host that
    // just missed is skipped for the next pick when the pool has another.
    let timed_out: Vec<SocketAddr> = state
        .pending_uss_pings
        .iter()
        .filter(|(_, sent)| sent.elapsed().as_secs() >= USS_PING_TIMEOUT_SECS)
        .map(|(addr, _)| *addr)
        .collect();
    for addr in timed_out {
        state.pending_uss_pings.remove(&addr);
        state.uss_missed_pongs = state.uss_missed_pongs.saturating_add(1);
        state.uss_prev_host = Some(addr);
        debug!(
            "USS: ping to {addr} timed out ({} in a row, sent {}s after selection)",
            state.uss_missed_pongs,
            now_ts.saturating_sub(state.uss_host_selected_at)
        );
    }

    // One ping in flight at a time: `udp.rs` only takes a pong from
    // `uss_host`, so moving on before the answer would discard it.
    if !state.pending_uss_pings.is_empty() {
        return;
    }

    let mut pool: Vec<_> = state
        .routing_table
        .all_contacts()
        .filter(|c| c.verified && !c.is_dead() && !c.is_udp_firewalled())
        .map(|c| (c.created_at, c.id.0, SocketAddr::new(c.ip.into(), c.udp_port), c.id))
        .collect();
    pool.sort_unstable_by_key(|(created_at, id, _, _)| (*created_at, *id));
    pool.truncate(USS_PING_POOL);
    if state
        .uss_last_ping_at
        .is_some_and(|at| at.elapsed() < pool_spacing(pool.len()))
    {
        return;
    }

    // Checked here rather than left to the send's refusal, which this 2 s
    // timer would otherwise hit on almost every tick.
    let gap = per_host_gap(pool.len());
    let ready: Vec<(SocketAddr, KadId)> = pool
        .iter()
        .filter(|(_, _, addr, _)| kad_request_ready(state, *addr, messages::KADEMLIA2_PING, gap))
        .map(|(_, _, addr, id)| (*addr, *id))
        .collect();
    let next = {
        let governor = state.kad_outbound.lock();
        next_ping_host(&ready, state.uss_prev_host, |addr| {
            governor.since_last(addr.ip(), messages::KADEMLIA2_PING)
        })
    };
    let Some((addr, contact_id)) = next else {
        return;
    };
    if state.uss_host.map(|(a, _)| a) != Some(addr) {
        state.uss_host = Some((addr, contact_id));
        state.uss_host_selected_at = now_ts;
    }

    let msg = KadMessage::Ping;
    if let Ok(packet) = messages::encode_packet(&msg) {
        match send_kad_packet(udp_socket, &packet, addr, state, &contact_id).await {
            Ok(_) => {
                let sent = std::time::Instant::now();
                state.pending_uss_pings.insert(addr, sent);
                state.uss_last_ping_at = Some(sent);
            }
            Err(e) => {
                debug!("USS: failed to send ping to {addr}: {e}");
            }
        }
    }
}

/// The ready host pinged longest ago (never, within the governor's window,
/// first), skipping `exclude` — the host that last missed — unless it is the
/// only one ready.
fn next_ping_host(
    ready: &[(SocketAddr, KadId)],
    exclude: Option<SocketAddr>,
    since_last: impl Fn(SocketAddr) -> Option<std::time::Duration>,
) -> Option<(SocketAddr, KadId)> {
    let pick = |skip: Option<SocketAddr>| {
        ready
            .iter()
            .filter(|(addr, _)| Some(*addr) != skip)
            .max_by_key(|(addr, _)| since_last(*addr).unwrap_or(std::time::Duration::MAX))
            .copied()
    };
    pick(exclude).or_else(|| pick(None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn host(n: u8) -> (SocketAddr, KadId) {
        (SocketAddr::from(([192, 0, 2, n], 4672)), KadId([n; 16]))
    }

    #[test]
    fn rotates_to_the_host_pinged_longest_ago() {
        let ready = [host(1), host(2), host(3)];
        let ages = |addr: SocketAddr| match addr.ip().to_string().as_str() {
            "192.0.2.1" => Some(Duration::from_secs(40)),
            "192.0.2.2" => Some(Duration::from_secs(50)),
            _ => Some(Duration::from_secs(35)),
        };
        assert_eq!(next_ping_host(&ready, None, ages), Some(host(2)));
        let never = |addr: SocketAddr| (addr != host(3).0).then_some(Duration::from_secs(50));
        assert_eq!(next_ping_host(&ready, None, never), Some(host(3)), "never pinged goes first");
    }

    /// Never past eMule's two a minute per IP, never more than one a window
    /// once the pool is big enough to keep the cadence without it.
    #[test]
    fn per_host_gap_stays_inside_the_kad_ping_budget() {
        assert_eq!(per_host_gap(0), USS_PING_MIN_GAP);
        assert_eq!(per_host_gap(1), USS_PING_MIN_GAP);
        assert_eq!(per_host_gap(10), Duration::from_secs(40));
        assert_eq!(per_host_gap(USS_PING_POOL), USS_PING_MAX_GAP);
        assert!(USS_PING_MAX_GAP / USS_PING_POOL as u32 <= USS_SAMPLE_INTERVAL);
    }

    /// The pool is pinged evenly through each host's gap, not in one burst at
    /// its start: never sooner than a host's own gap allows, never in a run.
    #[test]
    fn pings_are_spread_across_the_per_host_gap() {
        for n in [1usize, 4, 10, USS_PING_POOL] {
            let spacing = pool_spacing(n);
            assert!(spacing * n as u32 <= per_host_gap(n) + Duration::from_millis(n as u64));
            assert!(spacing <= USS_PING_MIN_GAP);
        }
        assert_eq!(pool_spacing(1), USS_PING_MIN_GAP);
        assert!(pool_spacing(USS_PING_POOL) <= USS_SAMPLE_INTERVAL);
    }

    #[test]
    fn skips_the_host_that_just_missed_unless_it_is_alone() {
        let ready = [host(1), host(2)];
        assert_eq!(next_ping_host(&ready, Some(host(1).0), |_| None), Some(host(2)));
        assert_eq!(next_ping_host(&ready[..1], Some(host(1).0), |_| None), Some(host(1)));
        assert_eq!(next_ping_host(&[], None, |_| None), None);
    }
}
