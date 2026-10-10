//! Ember peer bookkeeping: known peers, Noise keys, bridge candidates,
//! session DHT contacts, announces, and relay attestations.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// How long an Ember peer entry is considered fresh in `known_ember_peers`
/// before `prune_stale_ember_peers` evicts it. 24h gives enough headroom
/// that a peer who briefly went offline (NAT renewal, brief uptime gap)
/// is still in the mesh on their next visit, while keeping advertisements
/// from being polluted with weeks-old dead addresses.
pub(super) const KNOWN_EMBER_PEER_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// Hard cap on `known_ember_peers` size. Set to 10x `MAX_EPX_PEERS` so
/// rebuilds have a diverse pool to rotate from while still keeping
/// per-session memory bounded (≈12 KB worst case).
pub(super) const MAX_KNOWN_EMBER_PEERS: usize = 500;

/// Hard cap on `ember_noise_keys` size. Each entry is roughly 50 bytes
/// (key + timestamp + map overhead), so the same 500-entry cap bounds
/// the noise-key cache to ≈25 KB in the worst case while letting the
/// harness scale to a few hundred peers without churn.
pub(super) const MAX_KNOWN_EMBER_NOISE_KEYS: usize = 500;

/// Most distinct ports one host may hold in the noise-key cache before we
/// have reached it. The cache feeds bridge dials, and unreached entries come
/// from unauthenticated KAD source records, so without a cap one lookup reply
/// could fill it with a single third party's address on hundreds of ports and
/// have a cold node send it a handshake on each.
const MAX_EMBER_NOISE_KEYS_PER_IP: usize = 3;

/// Insert or refresh an Ember peer in `known_ember_peers`. Returns true
/// when this is the first time we've seen the address (caller uses that
/// signal to mark `ember_payload_dirty`). When the map is at capacity
/// and we're inserting a brand-new entry, the oldest existing entry is
/// evicted to make room — matches the LRU-by-timestamp policy that the
/// pruner enforces against TTL.
pub(super) fn record_known_ember_peer(
    map: &mut HostPortMap<std::time::Instant>,
    ip: Ipv4Addr,
    port: u16,
) -> bool {
    let now = std::time::Instant::now();
    let key = (ip, port);
    if let Some(slot) = map.get_mut(&key) {
        *slot = now;
        return false;
    }
    if map.len() >= MAX_KNOWN_EMBER_PEERS {
        if let Some(oldest_key) = map.iter().min_by_key(|(_, ts)| *ts).map(|(k, _)| *k) {
            map.remove(&oldest_key);
        }
    }
    map.insert(key, now);
    true
}

/// Drop entries older than `KNOWN_EMBER_PEER_TTL`. Called lazily before
/// the EPX rebuild iterates the map so we never advertise a peer we
/// haven't heard about in a day.
pub(super) fn prune_stale_ember_peers(map: &mut HostPortMap<std::time::Instant>) {
    prune_stale_ember_peers_at(map, std::time::Instant::now());
}

/// `prune_stale_ember_peers` factored to take an explicit "now". Used by
/// tests so they can forward-shift the comparison clock instead of
/// trying to backdate timestamps with `Instant::checked_sub`, which
/// fails on platforms where the monotonic counter origin is younger
/// than `KNOWN_EMBER_PEER_TTL` (notably Windows shortly after boot or
/// inside short-lived CI containers).
pub(super) fn prune_stale_ember_peers_at(
    map: &mut HostPortMap<std::time::Instant>,
    now: std::time::Instant,
) {
    map.retain(|_, ts| now.duration_since(*ts) < KNOWN_EMBER_PEER_TTL);
}

/// Rolling window for the UDP EPX rate limit. Chosen to match the TCP EPX
/// re-send cadence (`EPX_RESEND_INTERVAL` in transfer.rs/upload.rs/
/// multi_source.rs) so a well-behaved peer requesting a fresh exchange
/// roughly once per rebuild cycle never trips it.
pub(super) const EPX_UDP_RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(300);
/// Hard cap on `NetworkState::ember_udp_epx_rate` size, bounding memory
/// under a flood of distinct source addresses.
pub(super) const MAX_EMBER_UDP_EPX_RATE_ENTRIES: usize = 2000;

/// Returns `true` if `addr` is still under `ember::MAX_EPX_PACKETS_PER_CONNECTION`
/// accepted `ExchangeData` packets within the current `EPX_UDP_RATE_WINDOW`,
/// and records this acceptance. TCP EPX gets this cap for free from
/// `MAX_EPX_PACKETS_PER_CONNECTION` resetting whenever the TCP connection
/// closes; a Noise_IK UDP session has no such natural connection boundary,
/// so an authenticated peer could otherwise send unlimited `ExchangeData`
/// packets bounded only by `MAX_EPX_TOTAL_SOURCES` per packet.
///
/// Charged to the source IP, not the socket address: a new source port is
/// only a new Noise session away, so a per-port budget would be a fresh budget
/// for the asking. Peers sharing one public address share its allowance.
pub(super) fn check_and_record_udp_epx_rate(
    map: &mut HashMap<IpAddr, (u32, std::time::Instant)>,
    addr: SocketAddr,
) -> bool {
    let now = std::time::Instant::now();
    let ip = addr.ip().to_canonical();
    if let Some((count, window_start)) = map.get_mut(&ip) {
        if now.duration_since(*window_start) >= EPX_UDP_RATE_WINDOW {
            *count = 1;
            *window_start = now;
            return true;
        }
        if *count >= ember::MAX_EPX_PACKETS_PER_CONNECTION as u32 {
            return false;
        }
        *count += 1;
        return true;
    }
    if map.len() >= MAX_EMBER_UDP_EPX_RATE_ENTRIES {
        if let Some(oldest_key) = map.iter().min_by_key(|(_, (_, ts))| *ts).map(|(k, _)| *k) {
            map.remove(&oldest_key);
        }
    }
    map.insert(ip, (1, now));
    true
}

/// Insert or refresh an Ember Noise pubkey for `(ip, port)`. Mirrors
/// `record_known_ember_peer`'s LRU-by-timestamp eviction policy at the
/// `MAX_KNOWN_EMBER_NOISE_KEYS` cap.
///
/// KAD `"ember_npub"` tags are unauthenticated, so a poisoner could
/// otherwise last-write-wins overwrite a legitimate peer's key and
/// redirect Noise_IK dials. We **pin on first sight**: a different key
/// for the same `(ip, port)` is ignored while the existing entry is
/// still within `KNOWN_EMBER_PEER_TTL`. Same-key re-publishes refresh
/// the timestamp. After TTL expiry the entry is pruned and a new key
/// (including a legitimate rotation) can be learned again.
///
/// Returns the *previous* pubkey only when a conflicting advertise was
/// rejected (caller may log a poison/rotation attempt). Returns `None`
/// on first insert or same-key refresh.
pub(super) fn cache_bound_ember_noise_key(
    map: &mut HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)>,
    ip: Ipv4Addr,
    udp_port: u16,
    noise_pub: [u8; 32],
    established: bool,
) -> Option<[u8; 32]> {
    if udp_port == 0 || noise_pub == [0u8; 32] || crate::security::is_bogus_v4(ip) {
        return None;
    }
    if !established {
        if !map.contains_key(&(ip, udp_port))
            && map.keys().filter(|(known_ip, _)| *known_ip == ip).count()
                >= MAX_EMBER_NOISE_KEYS_PER_IP
        {
            return None;
        }
        // Nothing to protect yet. The pin exists to stop an unauthenticated
        // KAD tag redirecting dials to a peer we already talk to; holding a
        // first sighting we have never reached does the opposite, because a
        // wrong key is exactly why we cannot reach it. The IK dial then fails
        // for the full TTL and the XX pass skips the address for having a
        // "known" key, so one bad or stale tag could hide a peer for a day.
        record_ember_noise_key_forced(map, ip, udp_port, noise_pub);
        return None;
    }
    record_ember_noise_key(map, ip, udp_port, noise_pub)
}

pub(super) fn record_ember_noise_key(
    map: &mut HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)>,
    ip: Ipv4Addr,
    port: u16,
    noise_pub: [u8; 32],
) -> Option<[u8; 32]> {
    record_ember_noise_key_at(map, ip, port, noise_pub, std::time::Instant::now())
}

/// Overwrite whatever is cached for `(ip, port)`. Only for addresses we hold no
/// live Ember contact at — see [`cache_bound_ember_noise_key`].
pub(super) fn record_ember_noise_key_forced(
    map: &mut HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)>,
    ip: Ipv4Addr,
    port: u16,
    noise_pub: [u8; 32],
) {
    map.remove(&(ip, port));
    record_ember_noise_key(map, ip, port, noise_pub);
}

/// `record_ember_noise_key` with an explicit comparison clock — same
/// testability rationale as `prune_stale_ember_peers_at`.
pub(super) fn record_ember_noise_key_at(
    map: &mut HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)>,
    ip: Ipv4Addr,
    port: u16,
    noise_pub: [u8; 32],
    now: std::time::Instant,
) -> Option<[u8; 32]> {
    let key = (ip, port);
    if let Some((existing, ts)) = map.get_mut(&key) {
        if now.duration_since(*ts) >= KNOWN_EMBER_PEER_TTL {
            // Stale pin — treat as a fresh insert below.
            map.remove(&key);
        } else if *existing == noise_pub {
            *ts = now;
            return None;
        } else {
            // Conflicting key while pin is live: keep the first-seen key.
            return Some(*existing);
        }
    }
    if map.len() >= MAX_KNOWN_EMBER_NOISE_KEYS {
        if let Some(oldest_key) = map.iter().min_by_key(|(_, (_, ts))| *ts).map(|(k, _)| *k) {
            map.remove(&oldest_key);
        }
    }
    map.insert(key, (noise_pub, now));
    None
}

/// Look up a peer's Ember Noise pubkey, respecting `KNOWN_EMBER_PEER_TTL`.
/// Returns `None` for unknown peers and for entries past their TTL —
/// stale entries are not pruned here so the lookup can stay `&` not
/// `&mut`; the periodic prune (or a fresh insert on the next observed
/// publish) reaps them.
pub(super) fn lookup_ember_noise_key(
    map: &HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)>,
    ip: Ipv4Addr,
    port: u16,
) -> Option<[u8; 32]> {
    lookup_ember_noise_key_at(map, ip, port, std::time::Instant::now())
}

/// `lookup_ember_noise_key` with an explicit comparison clock. Same
/// rationale as `prune_stale_ember_peers_at` — lets tests forward-shift
/// `now` instead of relying on `Instant::checked_sub`.
pub(super) fn lookup_ember_noise_key_at(
    map: &HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)>,
    ip: Ipv4Addr,
    port: u16,
    now: std::time::Instant,
) -> Option<[u8; 32]> {
    let (key, ts) = map.get(&(ip, port))?;
    if now.duration_since(*ts) < KNOWN_EMBER_PEER_TTL {
        Some(*key)
    } else {
        None
    }
}

/// How long a bridge peer is left alone after a ping attempt before it may be
/// tried again.
///
/// One attempt used to be final for the session. That interacted badly with
/// the discovery caches: a peer's timestamp is refreshed every time it is
/// re-observed, so the attempted-set entry (bounded by those caches) never
/// aged out either. A node whose first ping was simply lost — dropped UDP, a
/// peer that was briefly down, a NAT needing a punch — could therefore never
/// bootstrap for the rest of the session while continuously re-learning the
/// very peers it needed, and the maintenance gate stayed open the whole time
/// so it looked healthy.
///
/// That fix left a flat five-minute window, which is poorly matched to the
/// causes it lists: a dropped datagram or a peer that blinked resolves in
/// seconds, not minutes. On a small overlay the cost is the whole join — a node
/// holding two candidates spent one ping on each and then sat silent, so a
/// session shorter than five minutes got exactly one chance per peer. Retry
/// quickly at first and back off to the original ceiling, mirroring
/// [`ember_rendezvous_retry_secs`], which solves the same problem for the
/// rendezvous lookup.
///
/// Retrying sooner is close to free: the bridge only runs below
/// [`EMBER_KAD_BRIDGE_UNTIL_CONTACTS`] verified contacts, it is capped at
/// [`EMBER_KAD_BRIDGE_MAX_PINGS`] per cycle, and the maintenance tick that
/// drives it is itself 60 seconds — so that is the real floor no matter what
/// this returns.
pub(super) const EMBER_BRIDGE_RETRY_FIRST: std::time::Duration = std::time::Duration::from_secs(60);

/// Ceiling on the backoff, unchanged from the flat window it replaces, so a
/// genuinely dead peer settles at exactly the rate it always did.
pub(super) const EMBER_BRIDGE_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(300);

/// How long to leave a bridge peer alone after `failed_attempts` unanswered
/// pings. Doubles from [`EMBER_BRIDGE_RETRY_FIRST`] up to
/// [`EMBER_BRIDGE_RETRY_MAX`].
///
/// `starved` flattens the curve to its first step. The backoff exists so a
/// genuinely dead address stops costing a datagram a minute forever, which is
/// the right trade once the table is healthy and the peer is one candidate
/// among many — but below [`EMBER_KAD_BRIDGE_UNTIL_CONTACTS`] verified contacts
/// those same candidates *are* the join, and backing off to five minutes prices
/// a lost datagram at the whole session. A friend is the sharpest case: you
/// have explicitly trusted them, there is a live authenticated session to them,
/// and their routing table is exactly what you are missing — yet one dropped
/// bridge PING put the next attempt five minutes out, and a shorter visit than
/// that never got a second chance.
///
/// Costing nothing is what makes this safe rather than merely helpful. The
/// flattening only holds while the join is still finding peers (see
/// [`ember_dht_starved`]), the bridge is capped at
/// [`EMBER_KAD_BRIDGE_MAX_PINGS`] per cycle, and the maintenance tick driving it
/// is 60 seconds — so the flattened rate is one datagram per candidate per
/// minute, and it returns to the ordinary backoff once the join settles.
pub(super) fn bridge_retry_after(failed_attempts: u32, starved: bool) -> std::time::Duration {
    if starved {
        return EMBER_BRIDGE_RETRY_FIRST;
    }
    let doublings = failed_attempts.saturating_sub(1).min(8);
    let secs = EMBER_BRIDGE_RETRY_FIRST
        .as_secs()
        .saturating_mul(1u64 << doublings)
        .min(EMBER_BRIDGE_RETRY_MAX.as_secs());
    std::time::Duration::from_secs(secs)
}

/// Whether a bridge peer may be pinged now: either never attempted, or its last
/// attempt is older than the backoff its attempt count has earned.
pub(super) fn bridge_retry_due(
    attempted: &HashMap<(Ipv4Addr, u16), (std::time::Instant, u32)>,
    key: &(Ipv4Addr, u16),
    now: std::time::Instant,
    starved: bool,
) -> bool {
    match attempted.get(key) {
        None => true,
        Some((at, failed_attempts)) => {
            now.duration_since(*at) >= bridge_retry_after(*failed_attempts, starved)
        }
    }
}

/// Pick KAD-learned Ember peers to fold into the DHT via a bridge `PING`
/// (slice 13). Returns up to `max` `(ip, port, noise_pub)` entries from the
/// `ember_noise_keys` cache whose retry backoff in `attempted` has run out,
/// ranked by [`bridge_candidate_rank`]. The caller sends each a DHT `PING`;
/// the signed `PONG` carries the peer's Ed25519 key, which is what actually
/// turns it into a verified routing-table contact.
pub(super) fn kad_bridge_candidates(
    noise_keys: &HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)>,
    attempted: &HashMap<(Ipv4Addr, u16), (std::time::Instant, u32)>,
    max: usize,
    starved: bool,
) -> Vec<(Ipv4Addr, u16, [u8; 32])> {
    kad_bridge_candidates_at(
        noise_keys,
        attempted,
        max,
        std::time::Instant::now(),
        starved,
    )
}

/// Order in which due bridge candidates are dialled: fewest unanswered pings
/// first, then most recently observed.
///
/// Freshness alone used to be the key. That was fine while a miss earned a
/// longer wait, because a dead address dropped out of the due set and the
/// next-freshest got its turn. A starved table flattens the wait to one tick
/// ([`bridge_retry_after`]), so every address is due on every tick, and the
/// freshest few — re-observed by every KAD lookup whether or not they ever
/// answer — were dialled again and again while candidates further down the
/// list, which had never been tried at all, waited behind them indefinitely.
/// An answered ping clears the entry (see the PONG path), so the count here is
/// exactly the number of times the address has ignored us.
pub(super) fn bridge_candidate_rank(
    attempted: &HashMap<(Ipv4Addr, u16), (std::time::Instant, u32)>,
    key: &(Ipv4Addr, u16),
    seen: std::time::Instant,
) -> (u32, std::cmp::Reverse<std::time::Instant>) {
    let misses = attempted.get(key).map(|(_, n)| *n).unwrap_or(0);
    (misses, std::cmp::Reverse(seen))
}

/// `kad_bridge_candidates` with an explicit "now", so the retry window is
/// testable without sleeping.
pub(super) fn kad_bridge_candidates_at(
    noise_keys: &HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)>,
    attempted: &HashMap<(Ipv4Addr, u16), (std::time::Instant, u32)>,
    max: usize,
    now: std::time::Instant,
    starved: bool,
) -> Vec<(Ipv4Addr, u16, [u8; 32])> {
    if max == 0 {
        return Vec::new();
    }
    let mut candidates: Vec<(Ipv4Addr, u16, [u8; 32], std::time::Instant)> = noise_keys
        .iter()
        .filter(|(key, _)| {
            !crate::security::is_bogus_v4(key.0) && bridge_retry_due(attempted, key, now, starved)
        })
        .map(|(key, (noise_pub, seen))| (key.0, key.1, *noise_pub, *seen))
        .collect();
    candidates.sort_by_key(|c| bridge_candidate_rank(attempted, &(c.0, c.1), c.3));
    candidates
        .into_iter()
        .take(max)
        .map(|(ip, port, noise_pub, _)| (ip, port, noise_pub))
        .collect()
}

/// Learn Noise static keys from the sources a KAD search returned.
///
/// Every source record an Ember node publishes carries its Noise key, so any
/// source lookup doubles as Ember peer discovery — which is what lets the DHT
/// bridge dial those peers on the 1-RTT IK path. Cached under the peer's *UDP*
/// port: Ember's transport rides the shared KAD UDP socket, so a source that
/// advertised no UDP port can never be Ember-dialed and is skipped.
/// `established` is the set of addresses we currently hold an Ember DHT
/// contact at. Only those get the first-seen key pin; see
/// [`cache_bound_ember_noise_key`].
///
/// A source carrying `local_noise_pub` is our own record echoed back — any
/// lookup for a file we share returns it — so it is never cached, whatever
/// address it names.
pub(super) fn harvest_ember_noise_keys(
    noise_keys: &mut HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)>,
    sources: &[KadSource],
    established: &HashSet<(Ipv4Addr, u16)>,
    local_noise_pub: &[u8; 32],
) {
    for s in sources {
        if s.ip.is_unspecified() || s.tcp_port == 0 || s.udp_port == 0 {
            continue;
        }
        let Some(npub) = s.ember_noise_pub else {
            continue;
        };
        if npub == *local_noise_pub {
            continue;
        }
        let pinned = established.contains(&(s.ip, s.udp_port));
        if cache_bound_ember_noise_key(noise_keys, s.ip, s.udp_port, npub, pinned).is_some() {
            debug!(
                "Ignoring conflicting KAD ember_npub for {}:{} (key of a live contact is pinned)",
                s.ip, s.udp_port
            );
        }
    }
}

/// Addresses we currently hold an Ember DHT contact at, so a KAD `ember_npub`
/// tag can be told apart from an unverified first sighting.
pub(super) fn ember_established_addrs(state: &NetworkState) -> HashSet<(Ipv4Addr, u16)> {
    state
        .ember_dht
        .contacts()
        .into_iter()
        .filter_map(|c| match c.addr.ip() {
            IpAddr::V4(v4) => Some((v4, c.addr.port())),
            IpAddr::V6(_) => None,
        })
        .collect()
}

/// How many rendezvous-listed peers are already overlay contacts.
pub(super) fn ember_rendezvous_converted_contacts(state: &NetworkState, peers: &[KadSource]) -> usize {
    let established = ember_established_addrs(state);
    let listed: Vec<(Ipv4Addr, u16)> = peers.iter().map(|s| (s.ip, s.udp_port)).collect();
    let session: HashSet<(Ipv4Addr, u16)> =
        state.ember_session_dht_contacts.keys().copied().collect();
    ember_rendezvous_converted_among(&listed, &established, &session)
}

/// Same membership rule as [`ember_rendezvous_converted_contacts`], for tests
/// that cannot construct a `NetworkState`.
pub(super) fn ember_rendezvous_converted_among(
    listed: &[(Ipv4Addr, u16)],
    established: &HashSet<(Ipv4Addr, u16)>,
    session: &HashSet<(Ipv4Addr, u16)>,
) -> usize {
    listed
        .iter()
        .filter(|addr| established.contains(*addr) || session.contains(*addr))
        .count()
}

/// Remember an Ember peer we met over eD2K but hold no Noise key for, so the
/// bridge can reach it with a 2-RTT Noise_XX handshake.
///
/// A peer that advertised no UDP port is unreachable on the Ember transport,
/// so it is dropped rather than stored under a port we'd never be able to
/// dial. Otherwise this shares `record_known_ember_peer`'s TTL-and-LRU policy.
pub(super) fn record_ember_keyless_peer(
    map: &mut HostPortMap<std::time::Instant>,
    ip: Ipv4Addr,
    udp_port: u16,
) -> bool {
    if udp_port == 0 {
        return false;
    }
    record_known_ember_peer(map, ip, udp_port)
}

/// Pick Ember peers to fold into the DHT with a Noise_XX bridge `PING`.
///
/// The counterpart to [`kad_bridge_candidates`], for peers learned from eD2K
/// client-to-client sessions rather than KAD source tags. Anything we already
/// hold a Noise key for is skipped so the cheaper 1-RTT IK path wins; the rest
/// pay one extra round trip, which is the price of joining without KAD.
/// Ranked by [`bridge_candidate_rank`], same as the IK side.
pub(super) fn xx_bridge_candidates(
    keyless: &HashMap<(Ipv4Addr, u16), std::time::Instant>,
    noise_keys: &HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)>,
    attempted: &HashMap<(Ipv4Addr, u16), (std::time::Instant, u32)>,
    max: usize,
    starved: bool,
) -> Vec<(Ipv4Addr, u16)> {
    xx_bridge_candidates_at(
        keyless,
        noise_keys,
        attempted,
        max,
        std::time::Instant::now(),
        starved,
    )
}

/// `xx_bridge_candidates` with an explicit "now", for the same reason.
pub(super) fn xx_bridge_candidates_at(
    keyless: &HashMap<(Ipv4Addr, u16), std::time::Instant>,
    noise_keys: &HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)>,
    attempted: &HashMap<(Ipv4Addr, u16), (std::time::Instant, u32)>,
    max: usize,
    now: std::time::Instant,
    starved: bool,
) -> Vec<(Ipv4Addr, u16)> {
    if max == 0 {
        return Vec::new();
    }
    let mut candidates: Vec<(Ipv4Addr, u16, std::time::Instant)> = keyless
        .iter()
        .filter(|(key, _)| {
            !crate::security::is_bogus_v4(key.0)
                && bridge_retry_due(attempted, key, now, starved)
                && !noise_keys.contains_key(*key)
        })
        .map(|(key, seen)| (key.0, key.1, *seen))
        .collect();
    candidates.sort_by_key(|c| bridge_candidate_rank(attempted, &(c.0, c.1), c.2));
    candidates
        .into_iter()
        .take(max)
        .map(|(ip, port, _)| (ip, port))
        .collect()
}

/// Share of one bridge pass held back for the Noise_XX candidates.
///
/// The IK pass used to run first and hand the XX pass only what it left, which
/// on a healthy table was fine: dead IK addresses backed off, the due set
/// thinned, and the budget reached the keyless peers within a few ticks. A
/// starved table flattens that backoff, so with more due IK addresses than the
/// budget — a KAD-fed key cache holds up to `MAX_KNOWN_EMBER_NOISE_KEYS`, most
/// of them stale source records — the IK pass spent the whole budget every
/// tick and the XX pass never ran. The keyless peers are the live eD2K sessions
/// that advertised Ember without a key: LAN friends under `block_private_ips`,
/// LowID peers — the ones most likely to actually answer.
///
/// A quarter, with a floor of one so the 1 Hz fast pass (four pings) still
/// reaches them. Only held back while there are keyless peers to spend it on,
/// and anything the reserve does not use goes to the IK pass, so a node with
/// nothing on the XX side loses no throughput.
pub(super) const EMBER_BRIDGE_XX_RESERVE_DIVISOR: usize = 4;

pub(super) fn xx_bridge_reserve(max_pings: usize, keyless_known: bool) -> usize {
    if !keyless_known || max_pings == 0 {
        return 0;
    }
    (max_pings / EMBER_BRIDGE_XX_RESERVE_DIVISOR).clamp(1, max_pings)
}

/// Hard cap on firsthand DHT contacts learned from live eD2K Ember sessions.
/// These sit beside the routing table so a LAN peer can be asked without
/// being gossiped onto the public overlay.
pub(super) const MAX_EMBER_SESSION_DHT_CONTACTS: usize = 64;

/// Whether a firsthand session contact still earns the place it holds beside
/// the routing table.
///
/// A contact here is exempt from everything that disciplines a routing
/// contact — no liveness ping reaches it, so `failed_queries` never rises and
/// the table's own staleness purge never sees it. That left the map with no
/// expiry at all, only the LRU in [`record_ember_session_dht_contact`], and 64
/// slots take a long time to turn over on a LAN.
///
/// `last_seen == 0` is kept: that is a peer we learned from a LAN `PEER_LIST`
/// and have not asked yet, not one that went quiet. The LRU already ranks
/// those first for eviction, which is the right order — an unproven lead
/// should lose its slot to a proven peer, not to the clock.
pub(super) fn ember_session_contact_is_live(contact: &ember::dht::EmberContact, now_secs: i64) -> bool {
    contact.last_seen == 0 || now_secs.saturating_sub(contact.last_seen) < EMBER_CONTACT_STALE_SECS
}

pub(super) fn record_ember_session_dht_contact(
    map: &mut HostPortMap<ember::dht::EmberContact>,
    contact: ember::dht::EmberContact,
) {
    let IpAddr::V4(ip) = contact.addr.ip() else {
        return;
    };
    if contact.addr.port() == 0 || crate::security::is_bogus_v4(ip) {
        return;
    }
    let key = (ip, contact.addr.port());
    // A NAT remap records a second UDP port for the same host. Keep at most
    // two so the IP-filter exemption cannot grow with every mapping change.
    let other_ports = map.host_port_count(ip) - usize::from(map.contains_key(&key));
    if other_ports >= 2 {
        if let Some(oldest) = map
            .iter()
            .filter(|((peer_ip, port), _)| *peer_ip == ip && *port != contact.addr.port())
            .min_by_key(|(_, c)| c.last_seen)
            .map(|(k, _)| *k)
        {
            map.remove(&oldest);
        }
    }
    if map.len() >= MAX_EMBER_SESSION_DHT_CONTACTS && !map.contains_key(&key) {
        if let Some(oldest) = map
            .iter()
            .min_by_key(|(_, c)| c.last_seen)
            .map(|(k, _)| *k)
        {
            map.remove(&oldest);
        }
    }
    map.insert(key, contact);
}

pub(super) fn ember_session_introduced(state: &NetworkState, ip: Ipv4Addr, udp_port: u16) -> bool {
    ember_session_introduced_among(
        &state.ember_keyless_peers,
        &state.ember_session_dht_contacts,
        &state.known_ember_peers,
        || state.ember_transport.recently_dialled(IpAddr::V4(ip)),
        ip,
        udp_port,
    )
}

/// [`ember_session_introduced`] over the maps it reads, for tests that cannot
/// construct a `NetworkState`.
pub(super) fn ember_session_introduced_among(
    keyless: &HostPortMap<std::time::Instant>,
    session: &HostPortMap<ember::dht::EmberContact>,
    known: &HostPortMap<std::time::Instant>,
    recently_dialled: impl FnOnce() -> bool,
    ip: Ipv4Addr,
    udp_port: u16,
) -> bool {
    // `known_ember_peers` is keyed by TCP port, so it can only ever vouch for
    // the host, not for the datagram's source port. When we hold no UDP port
    // for the host that is the last resort that lets a LAN peer whose UDP port
    // we never learned join the overlay. When we do, a datagram from another
    // port is a NAT remap (or a Hello UDP change), not unsolicited LAN gossip,
    // but only while an eD2K Ember session still vouches for the IP. Without
    // that, matching on the bare IP would exempt every other port on the
    // machine for as long as the session TTL lasts. Either way the answer
    // past the exact-port checks is whether that session vouches for the host.
    keyless.contains_key(&(ip, udp_port))
        || session.contains_key(&(ip, udp_port))
        || recently_dialled()
        || known.has_host(ip)
}

/// Whether a peer that sent us a signed frame may join the session-contact map.
///
/// Stricter than [`ember_session_introduced_among`], which also lets in any
/// address we recently sent to so the IP filter passes replies from peers a
/// search dialled. That includes the reply to a stranger's own ping, so used
/// here it let any public host that pinged twice be pinned onto every lookup
/// and offered as a publish target, outside the routing table's /24 limits.
/// A dial vouches only for a LAN or CGNAT host, the peers the map exists for.
pub(super) fn ember_session_contact_admitted_among(
    keyless: &HostPortMap<std::time::Instant>,
    session: &HostPortMap<ember::dht::EmberContact>,
    known: &HostPortMap<std::time::Instant>,
    recently_dialled: impl FnOnce() -> bool,
    ip: Ipv4Addr,
    udp_port: u16,
) -> bool {
    ember_session_introduced_among(keyless, session, known, || false, ip, udp_port)
        || (crate::security::is_lan_or_cgnat_v4(ip) && recently_dialled())
}

pub(super) fn remember_ember_session_dht_contact(state: &mut NetworkState, contact: ember::dht::EmberContact) {
    let IpAddr::V4(ip) = contact.addr.ip() else {
        return;
    };
    let admitted = ember_session_contact_admitted_among(
        &state.ember_keyless_peers,
        &state.ember_session_dht_contacts,
        &state.known_ember_peers,
        || state.ember_transport.recently_dialled(IpAddr::V4(ip)),
        ip,
        contact.addr.port(),
    );
    if !admitted {
        return;
    }
    record_ember_session_dht_contact(&mut state.ember_session_dht_contacts, contact);
}

/// What the user's IP policy says about talking to an Ember DHT peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EmberIpVerdict {
    Allowed,
    /// Unroutable space, or LAN/CGNAT while `block_private_ips` is on.
    Blocked,
    /// A ban. Refused like a block, but bans expire and are per IP, where one
    /// misbehaving client can share its address with other Ember peers behind
    /// the same NAT, so it is no reason to forget the peers cached there.
    Banned,
}

impl EmberIpVerdict {
    /// Whether nothing may be sent to the peer.
    pub(super) fn refuses(self) -> bool {
        matches!(self, Self::Blocked | Self::Banned)
    }
}

/// The user's IP policy for an Ember DHT peer at `ip`, on the terms
/// [`ember_udp_recv_allowed`] applies to inbound traffic. The `ipfilter.dat`
/// ranges are not part of it; see
/// [`ember::dht::routing::RoutingTable::admits_addr`]. A LAN/CGNAT peer
/// introduced over a live session is exempt from `block_private_ips` — that is
/// what keeps a LAN friend reachable — and a ban holds regardless.
///
/// `session_introduced` walks the session maps, so it is only asked when its
/// answer can change the verdict.
pub(super) fn ember_ip_verdict(
    block_private: bool,
    banned: &HashSet<Ipv4Addr>,
    ip: Ipv4Addr,
    session_introduced: impl FnOnce() -> bool,
) -> EmberIpVerdict {
    if crate::security::is_bogus_v4(ip) {
        return EmberIpVerdict::Blocked;
    }
    if block_private && crate::security::is_lan_or_cgnat_v4(ip) && !session_introduced() {
        return EmberIpVerdict::Blocked;
    }
    if banned.contains(&ip) {
        EmberIpVerdict::Banned
    } else {
        EmberIpVerdict::Allowed
    }
}

pub(super) fn ember_peer_ip_verdict(state: &NetworkState, ip: Ipv4Addr, udp_port: u16) -> EmberIpVerdict {
    ember_ip_verdict(state.ip_filter.blocks_private(), &state.banned_ips, ip, || {
        ember_session_introduced(state, ip, udp_port)
    })
}

/// Whether the ban list holds `addr`'s IPv4 address.
///
/// For the dial paths that check the routing table's IP gate instead of
/// [`ember_addr_ip_verdict`]: the table knows the private-IP policy but not the
/// ban list, so without this a banned address kept being queried, pinged and
/// re-learned from gossip after it faulted out.
pub(super) fn ember_addr_banned(state: &NetworkState, addr: SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => state.banned_ips.contains(&v4),
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .is_some_and(|v4| state.banned_ips.contains(&v4)),
    }
}

/// [`ember_peer_ip_verdict`] for a socket address. A genuinely IPv6 peer is
/// outside what the IPv4 ban list can represent.
pub(super) fn ember_addr_ip_verdict(state: &NetworkState, addr: SocketAddr) -> EmberIpVerdict {
    let v4 = match addr.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4,
            None => return EmberIpVerdict::Allowed,
        },
    };
    ember_peer_ip_verdict(state, v4, addr.port())
}

/// Forget cached Ember peers the user's IP policy now refuses, and stop the
/// queued STOREs and buddy proxy publishes aimed at them.
///
/// `set_block_private_ips` covers the routing table; these are the caches
/// beside it that feed the bridge, search seeding and the publish top-up, so
/// every site that changes the policy calls both — this one first, while the
/// table still holds the address of a buddy it is about to evict. Only a firm
/// [`EmberIpVerdict::Blocked`] forgets cached peers; a ban only stops the
/// queued work.
pub(super) fn purge_ember_ip_blocked_peers(state: &mut NetworkState) {
    // Every verdict is taken before anything is removed: a LAN peer's exemption
    // rests on the very session maps this clears.
    let blocked: HashSet<(Ipv4Addr, u16)> = state
        .ember_noise_keys
        .keys()
        .chain(state.ember_keyless_peers.keys())
        .chain(state.ember_session_dht_contacts.keys())
        .copied()
        .filter(|(ip, port)| ember_peer_ip_verdict(state, *ip, *port) == EmberIpVerdict::Blocked)
        .collect();
    let refused: HashSet<ember::dht::EmberNodeId> = state
        .ember_batch_publish
        .queued
        .iter()
        .filter(|(_, (contact, _))| ember_addr_ip_verdict(state, contact.addr).refuses())
        .map(|(node_id, _)| *node_id)
        .collect();
    // The buddy's PROXY_STORE_ACK is what releases one of these, and inbound
    // drops anything from a refused address, so the record would otherwise sit
    // out `EMBER_PROXY_OVERLAY_TTL` before its file could be selected again.
    let stranded: Vec<(ember::dht::EmberNodeId, u32)> = state
        .ember_pending_proxy_overlay
        .keys()
        .filter(|(buddy, _)| {
            let held = state.ember_dht.contact_for(buddy).map(|c| c.addr).or_else(|| {
                state
                    .ember_session_dht_contacts
                    .values()
                    .find(|c| c.node_id == *buddy)
                    .map(|c| c.addr)
            });
            held.is_some_and(|addr| ember_addr_ip_verdict(state, addr).refuses())
        })
        .copied()
        .collect();

    for key in &blocked {
        state.ember_noise_keys.remove(key);
        state.ember_keyless_peers.remove(key);
        state.ember_session_dht_contacts.remove(key);
        state.ember_kad_bridge_attempted.remove(key);
    }
    let dropped = state
        .ember_batch_publish
        .drop_destinations(|contact| refused.contains(&contact.node_id));
    release_ember_queued_records(state, dropped);
    for key in stranded {
        if let Some(pending) = state.ember_pending_proxy_overlay.remove(&key) {
            drop_ember_record_pending(state, pending.reference);
        }
    }

    if !blocked.is_empty() {
        debug!(
            "Ember: forgot {} cached peer address(es) the IP policy now refuses",
            blocked.len()
        );
    }
}

/// Hand queued records that will not be sent back to the publish schedule, so
/// their files are selected again rather than left waiting on a placement that
/// cannot come. A record another replica still carries is left to that replica.
///
/// Returns `(dropped, rearmed)` in the flush heartbeat's terms: a replication
/// record handed back to the store's republish clock is rearmed, anything else
/// is dropped.
pub(super) fn release_ember_queued_records(
    state: &mut NetworkState,
    records: Vec<super::ember_publish::EmberQueuedRecord>,
) -> (usize, usize) {
    let outstanding: HashSet<EmberRecordRef> = records
        .iter()
        .map(|queued| queued.reference)
        .filter(|reference| state.ember_batch_publish.record_still_outstanding(*reference))
        .collect();
    let released = settle_released_ember_records(state.publish_schedule(), records, |reference| {
        outstanding.contains(&reference)
    });
    for record in &released.rearm {
        state
            .ember_dht
            .mark_republish_due(&record.key, &record.record_signature);
    }
    for reference in released.published {
        note_ember_file_published(state, reference.file_hash, reference.kind);
    }
    (released.dropped, released.rearm.len())
}

/// Verified routing-table (and cache) contacts plus firsthand session peers
/// the table refused (typically LAN while `block_private_ips` is on).
///
/// Session extras only count toward the verified figure when they have
/// answered us — LAN PEER_LIST copies arrive with `last_seen == 0` and must
/// not inflate the high-water mark.
pub(super) fn ember_dht_ui_contact_counts(state: &NetworkState) -> (u32, u32) {
    let extra = ember_session_overlay_extras(state, false);
    let verified_extra = ember_session_overlay_extras(state, true);
    (
        (state.ember_dht.routing().held_len() + extra) as u32,
        (state.ember_dht.routing().verified_held() + verified_extra) as u32,
    )
}

/// Routing-table contacts (including the replacement cache) plus firsthand
/// session peers the table refused.
///
/// Source search and self-lookup key off this rather than
/// `ember_dht.contact_count()` so a LAN island with `block_private_ips` on
/// still searches — FIND_VALUE already pins those session peers. Cache-only
/// contacts (fail-closed parking, full-bucket) count too: `contact_for`
/// includes the cache, so treating that as "already in the table" without
/// adding `cached_len` made overlay/publishable read 0 while a firsthand peer
/// sat only in the cache. Publish STOREs use [`ember_publishable_peer_count`]
/// and the empty-overlay re-arm [`ember_rearm_contact_count`] instead.
pub(super) fn ember_overlay_contact_count(state: &NetworkState) -> usize {
    state.ember_dht.routing().held_len() + ember_session_overlay_extras(state, false)
}

/// Peers we can actually STORE to: proven table/cache contacts plus firsthand
/// verified session peers the public table refused.
///
/// [`ember_overlay_contact_count`] also includes unverified leads, which is
/// right for bootstrap (a seed we have not pinged yet is still a
/// reason not to declare the overlay empty) and wrong for publish: STOREs
/// queued at a lead sit behind a Noise handshake that never completes and
/// expire as failures — 82 records / 102 failures in one measured minute
/// against a single `nodes_ember.dat` seed that never answered.
pub(super) fn ember_publishable_peer_count(state: &NetworkState) -> usize {
    state.ember_dht.routing().verified_held() + ember_session_overlay_extras(state, true)
}

/// What the "overlay emptied" re-arm counts: every routing-table and cache
/// entry, plus the session peers the table refused that have answered us.
///
/// Not [`ember_overlay_contact_count`], which also counts unverified session
/// copies. Those arrive from a LAN `PEER_LIST` with `last_seen == 0`, no
/// liveness ping ever reaches them, and [`ember_session_contact_is_live`] keeps
/// them until the LRU needs the slot — so one of them would hold that count
/// above zero indefinitely, and the re-arm, the only way a spent address book
/// becomes offerable again, would never fire. A table lead is different: it is
/// pinged, and faults out if it never answers.
pub(super) fn ember_rearm_contact_count(
    dht: &ember::dht::engine::EmberDht,
    session: &HashMap<(Ipv4Addr, u16), ember::dht::EmberContact>,
) -> usize {
    dht.routing().held_len()
        + session
            .values()
            .filter(|c| c.is_verified() && dht.contact_for(&c.node_id).is_none())
            .count()
}

/// Everything worth writing to `nodes_ember.dat`, from all three places a
/// contact can live.
///
/// [`ember_dht_ui_contact_counts`] counts bucket contacts, replacement-cache
/// entries and session peers alike, but only the first of those was ever
/// persisted — so the overlay figure on screen could be several times what the
/// file held, and the peers a LAN or CGNAT node was actually talking to were
/// never remembered at all.
///
/// The bucket set comes through [`ember::dht::engine::EmberDht::bootstrap_contacts`],
/// which keeps its existing rule: proven contacts first, then untried leads to
/// fill the remaining slots. Elsewhere only *verified* contacts qualify. That
/// preserves the reason the replacement cache was excluded in the first place —
/// it is where unproven gossip accumulates, and a file full of hearsay is worse
/// than a short one — while no longer throwing away a peer we have genuinely
/// spoken to merely because a full bucket or the IP filter put it there.
pub(super) fn ember_persistable_contacts(state: &NetworkState) -> Vec<ember::dht::EmberContact> {
    let mut out = state
        .ember_dht
        .bootstrap_contacts(EMBER_PERSIST_MAX_CONTACTS);
    out.extend(
        state
            .ember_dht
            .cached_contacts()
            .into_iter()
            .chain(state.ember_session_dht_contacts.values().cloned())
            .filter(|c| {
                c.is_verified()
                    && c.is_dialable()
                    && c.failed_queries < ember::dht::MAX_FAILED_QUERIES
            }),
    );
    out
}

pub(super) fn ember_session_overlay_extras(state: &NetworkState, verified_only: bool) -> usize {
    state
        .ember_session_dht_contacts
        .values()
        .filter(|c| {
            if verified_only && !c.is_verified() {
                return false;
            }
            state.ember_dht.contact_for(&c.node_id).is_none()
        })
        .count()
}

pub(super) fn ember_announce_due(
    announced_at: &HashMap<ember::dht::EmberNodeId, i64>,
    node_id: &ember::dht::EmberNodeId,
    now: i64,
    min_interval: i64,
) -> bool {
    match announced_at.get(node_id) {
        Some(at) => now.saturating_sub(*at) >= min_interval,
        None => true,
    }
}

/// Whether the gossip leads in `inbound` arrived in a frame we asked for, or
/// one that cost its sender a lookup token: an `ANNOUNCE_PEER`, a `PEER_LIST`
/// from a peer we announced to within the last two maintenance cycles, or a
/// `FOUND_NODE` answering a query outstanding to its sender. Only those have
/// their leads probed; see `handle_ember_dht_message`.
pub(super) fn ember_leads_were_asked_for(
    state: &NetworkState,
    inbound: &ember::dht::engine::DhtInbound,
    from: SocketAddr,
    now: i64,
) -> bool {
    if inbound.announce_peer_received {
        return true;
    }
    let Some(sender) = inbound.sender_id else {
        return false;
    };
    if inbound.peer_list.is_some() {
        let window = 2 * EMBER_MAINT_INTERVAL.as_secs() as i64;
        return state
            .ember_announced_at
            .get(&sender)
            .is_some_and(|at| now.saturating_sub(*at) <= window);
    }
    if let Some((rid, _)) = &inbound.found_node {
        if state
            .ember_dht_pending_finds
            .get(rid)
            .is_some_and(|(_, dest, _)| *dest == from)
        {
            return true;
        }
        return state
            .ember_dht_search_requests
            .get(rid)
            .and_then(|req| {
                state
                    .ember_search
                    .get(req.search_id)
                    .and_then(|search| search.pending_query(req.per_search_req_id))
            })
            .is_some_and(|(node, _)| node == sender);
    }
    true
}

/// Whether `inbound` is a reply to a request we sent its sender and still hold
/// open, bound the way each reply's own handler binds it. Request ids come from
/// counters, so an id alone proves nothing; the reply also has to come from the
/// node or address the request went to. Read before the handlers consume the
/// pending entries.
pub(super) fn ember_reply_was_solicited(
    state: &NetworkState,
    inbound: &ember::dht::engine::DhtInbound,
    from: SocketAddr,
) -> bool {
    let Some(sender) = inbound.sender_id else {
        return false;
    };
    let search_query_to_sender = |rid: u32| {
        state
            .ember_dht_search_requests
            .get(&rid)
            .and_then(|req| {
                state
                    .ember_search
                    .get(req.search_id)
                    .and_then(|search| search.pending_query(req.per_search_req_id))
            })
            .is_some_and(|(node, _)| node == sender)
    };
    if let Some(rid) = inbound.pong_request_id {
        return state
            .ember_dht_pending_pings
            .get(&rid)
            .is_some_and(|(_, dest, _)| *dest == from)
            || state
                .ember_dht_maint_pings
                .get(&rid)
                .is_some_and(|ping| ping.node_id == sender);
    }
    if let Some((rid, _)) = &inbound.found_node {
        return state
            .ember_dht_pending_finds
            .get(rid)
            .is_some_and(|(_, dest, _)| *dest == from)
            || search_query_to_sender(*rid);
    }
    if let Some(page) = &inbound.found_value {
        return search_query_to_sender(page.request_id);
    }
    if let Some(rid) = inbound.store_ack_request_id {
        return state
            .ember_dht_publish_requests
            .get(&rid)
            .is_some_and(|req| req.node_id == sender);
    }
    if let Some((rid, _)) = inbound.store_batch_ack {
        return state.ember_batch_publish.awaits_ack(rid, sender);
    }
    // The engine reports a PROXY_STORE_ACK only when it echoes an ask we sent
    // this buddy.
    inbound.proxy_store_ack.is_some()
}

/// Public-table contacts plus firsthand session peers, least-recently-announced
/// first. `ANNOUNCE_PEER` used to walk only the public table, so a friend the
/// IP policy kept in the session map (LAN / CGNAT with `block_private_ips`)
/// was never asked for their contact list.
pub(super) fn ember_dht_announce_targets(
    table: Vec<ember::dht::EmberContact>,
    session: &HashMap<(Ipv4Addr, u16), ember::dht::EmberContact>,
    announced_at: &HashMap<ember::dht::EmberNodeId, i64>,
    local_id: ember::dht::EmberNodeId,
    budget: usize,
) -> Vec<ember::dht::EmberContact> {
    if budget == 0 {
        return Vec::new();
    }
    let mut by_id: HashMap<ember::dht::EmberNodeId, ember::dht::EmberContact> = HashMap::new();
    for contact in table {
        if contact.node_id != local_id {
            by_id.insert(contact.node_id, contact);
        }
    }
    for contact in session.values() {
        if contact.node_id != local_id {
            by_id
                .entry(contact.node_id)
                .or_insert_with(|| contact.clone());
        }
    }
    // Least-recently-announced first, then cut to the budget. Deliberately no
    // "announced too recently" filter: the sweep already runs on the announce
    // interval, so re-testing it here made a tick that fired a hair early skip
    // the only contact a thin table had.
    let mut all: Vec<_> = by_id.into_values().collect();
    all.sort_by_key(|c| announced_at.get(&c.node_id).copied().unwrap_or(0));
    all.truncate(budget);
    all
}

/// Contacts to dump on `ANNOUNCE_PEER`. Session/LAN extras ride only when
/// the peer we are telling is itself on LAN/CGNAT — never to the public net.
pub(super) fn ember_announce_gossip(
    table_closest: Vec<ember::dht::EmberContact>,
    session: &HashMap<(Ipv4Addr, u16), ember::dht::EmberContact>,
    peer: &ember::dht::EmberContact,
    local_id: ember::dht::EmberNodeId,
) -> Vec<ember::dht::EmberContact> {
    let mut gossip: Vec<_> = table_closest
        .into_iter()
        .filter(|c| c.node_id != peer.node_id && c.node_id != local_id)
        .collect();
    if ember_share_session_contacts_with(peer.addr) {
        for extra in session.values() {
            if gossip.len() >= ember::dht::MAX_CONTACTS_PER_RESPONSE {
                break;
            }
            if extra.node_id == peer.node_id
                || extra.node_id == local_id
                || gossip.iter().any(|c| c.node_id == extra.node_id)
            {
                continue;
            }
            gossip.push(extra.clone());
        }
    }
    gossip
}

pub(super) fn ember_share_session_contacts_with(from: SocketAddr) -> bool {
    match from.ip() {
        IpAddr::V4(v4) => crate::security::is_lan_or_cgnat_v4(v4),
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .is_some_and(crate::security::is_lan_or_cgnat_v4),
    }
}

/// Keep LAN/CGNAT gossip from a firsthand island neighbour. `add_contact`
/// refuses those addresses while `block_private_ips` is on, so without this
/// a PEER_LIST of the friend's other LAN peers never becomes visible.
pub(super) fn remember_ember_lan_gossip(
    state: &mut NetworkState,
    contacts: &[ember::dht::EmberContact],
    from: SocketAddr,
) {
    if !ember_share_session_contacts_with(from) {
        return;
    }
    let v4 = match from.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4,
            None => return,
        },
    };
    if !ember_session_introduced(state, v4, from.port()) {
        return;
    }
    for contact in contacts {
        if state.ember_dht.contact_for(&contact.node_id).is_some() {
            continue;
        }
        let IpAddr::V4(ip) = contact.addr.ip() else {
            continue;
        };
        if !crate::security::is_lan_or_cgnat_v4(ip) {
            continue;
        }
        record_ember_session_dht_contact(&mut state.ember_session_dht_contacts, contact.clone());
    }
}

/// Whether this Ember UDP source already has a session, a table slot, or a
/// recent dial — the "known peer" side of the shared KAD/Ember flood limiter.
///
/// The limiter used to consult only the KAD routing table and KAD's outbound
/// `recent_ips` map. Ember-only, KAD-off, and LAN session peers then sat on
/// the stranger budget and could be dropped under load after introduction.
pub(super) fn ember_udp_is_known_peer(state: &NetworkState, from: SocketAddr) -> bool {
    if state.ember_transport.recently_dialled(from.ip()) {
        return true;
    }
    if let IpAddr::V4(v4) = from.ip() {
        if state.ember_session_dht_contacts.has_host(v4) || state.ember_keyless_peers.has_host(v4) {
            return true;
        }
    }
    state.ember_dht.routing().contact_at(from).is_some()
}

/// Fill a publish target set from firsthand session peers the public table
/// refused (typically LAN while `block_private_ips` is on). Does not gossip
/// those addresses; it only gives this node somewhere to STORE.
pub(super) fn ember_top_up_session_targets(
    session: &HashMap<(Ipv4Addr, u16), ember::dht::EmberContact>,
    targets: &mut Vec<ember::dht::EmberContact>,
) {
    if targets.len() >= K_EMBER_REPLICAS {
        return;
    }
    for contact in session.values() {
        if targets.len() >= K_EMBER_REPLICAS {
            break;
        }
        if !contact.is_verified() {
            continue;
        }
        if !targets.iter().any(|held| held.node_id == contact.node_id) {
            targets.push(contact.clone());
        }
    }
}

/// Lookup-backed publish targets for one of our own records, topped up with
/// session peers.
pub(super) fn ember_overlay_publish_targets(
    state: &mut NetworkState,
    key: [u8; 16],
) -> Vec<ember::dht::EmberContact> {
    ember_overlay_publish_targets_within(state, key, EMBER_PUBLISH_TARGET_QUEUE_MAX)
}

/// Target-lookup queue slots a buddy's `PROXY_STORE` forwards may occupy.
///
/// The queue drains at most [`EMBER_MAINT_MAX_TARGET_LOOKUPS`] keys a cycle and is
/// first come, first served, so every key queued on someone else's behalf
/// delays one of ours. A forwarded key is as distant as any of ours, so it
/// still gets a share — just not one that can crowd our own keys out.
pub(super) const EMBER_FORWARDED_TARGET_QUEUE_MAX: usize = EMBER_PUBLISH_TARGET_QUEUE_MAX / 4;

/// [`ember_overlay_publish_targets`], queueing a lookup for `key` only while the
/// queue holds fewer than `queue_limit` keys.
///
/// Replication passes zero. A record we replicate is one we were asked to hold
/// because its key is near our own ID, which is where our table is already
/// accurate, and a store holds far more keys than the lookup cache, so letting
/// it queue would fill the queue with replicated keys and refuse our own.
pub(super) fn ember_overlay_publish_targets_within(
    state: &mut NetworkState,
    key: [u8; 16],
    queue_limit: usize,
) -> Vec<ember::dht::EmberContact> {
    let now = chrono::Utc::now().timestamp();
    let mut targets = ember_publish_targets_for(
        &state.ember_publish_targets,
        &mut state.ember_publish_target_queue,
        queue_limit,
        state.ember_dht.routing(),
        key,
        now,
    );
    // A lookup-found node the table did not keep never passed the table's
    // ban-aware dial paths, so the ban list is applied here.
    targets.retain(|c| !ember_addr_banned(state, c.addr));
    ember_top_up_session_targets(&state.ember_session_dht_contacts, &mut targets);
    targets
}

/// Start storing one of our own channel records, on the same lookup-backed
/// replica set library records use.
///
/// Our table's closest contacts to an arbitrary key are often not the network's,
/// and a searcher's walk ends at the network's, so a room's governance, listing
/// or owned-rooms list stored only on the former could go unfound. Presence and
/// key-epoch records reuse a lookup already cached but never queue one. A
/// presence key changes every [`ember::channel::PRESENCE_EPOCH_SECS`], so its
/// lookup would land after the only publish that could use it. Key epochs are
/// one key per member, so a large room's republish would fill the queue, which
/// drains a few keys a minute, and hold back every other key behind it.
pub(super) fn start_own_channel_publish(
    state: &mut NetworkState,
    record: ember::dht::publish::SignedRecord,
) -> Option<u32> {
    let queue_limit = own_record_target_queue_limit(&record.data);
    let targets = ember_overlay_publish_targets_within(state, record.keyword_hash, queue_limit);
    state.ember_publish.start_publish_to(record, targets)
}

/// The target-lookup queue limit for one of our own records; see
/// [`start_own_channel_publish`].
pub(super) fn own_record_target_queue_limit(data: &[u8]) -> usize {
    use ember::dht::publish::{channel_kind_from_data, CHANNEL_KIND_EPOCH, CHANNEL_KIND_PRESENCE};
    match channel_kind_from_data(data) {
        Some(CHANNEL_KIND_PRESENCE | CHANNEL_KIND_EPOCH) => 0,
        _ => EMBER_PUBLISH_TARGET_QUEUE_MAX,
    }
}

/// Drop expired entries from the noise-key cache. Called next to
/// `prune_stale_ember_peers` so the two Ember-mesh caches stay in
/// step on the same TTL.
pub(super) fn prune_stale_ember_noise_keys(
    map: &mut HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)>,
) {
    prune_stale_ember_noise_keys_at(map, std::time::Instant::now());
}

/// `prune_stale_ember_noise_keys` with an explicit "now" for the same
/// testability rationale as `prune_stale_ember_peers_at`.
pub(super) fn prune_stale_ember_noise_keys_at(
    map: &mut HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)>,
    now: std::time::Instant,
) {
    map.retain(|_, (_, ts)| now.duration_since(*ts) < KNOWN_EMBER_PEER_TTL);
}

/// Expected-digest entries tolerated before `prune_ember_content_hashes` starts
/// discarding the ones nothing is waiting on.
///
/// Every distinct file hash a keyword search returns lands in the map, and a
/// search can carry three hundred records, so a session spent searching grows it
/// without limit. Generous enough that the prune is rare, small enough to bound
/// the map at a few megabytes.
pub(super) const MAX_EMBER_CONTENT_HASHES: usize = 20_000;

/// Bound the expected-BLAKE3 map to digests something could still verify against.
///
/// Deliberately not a TTL or an LRU. The map's whole purpose is to hold the
/// digest a transfer checks at *completion*, which can be hours after the search
/// hit that taught it to us, so evicting by age or by insertion order is exactly
/// the wrong rule — it would drop the entry for the longest download. Instead
/// this keeps every digest referenced by a live transfer or by the library and
/// discards the rest, which are search results nothing acted on.
pub(super) fn prune_ember_content_hashes(
    state: &mut NetworkState,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    local_index: &Arc<RwLock<LocalIndex>>,
) {
    if state.ember_content_hashes.len() <= MAX_EMBER_CONTENT_HASHES {
        return;
    }
    // `try_read`, not `read().await`. This runs inside the network `select!`,
    // and a library scan holds the index write lock across `rebuild_indices` —
    // so blocking here parked UDP receive, every timer and every IPC request
    // behind a full re-index. The prune is a soft bound on a map that is merely
    // larger than it needs to be: skipping a tick costs a few more megabytes
    // until the next one, whereas dropping an entry because a lock was busy
    // would silently disable the content check for a running download.
    let Ok(mgr) = transfer_manager.try_read() else {
        debug!("Ember content digests: transfer manager busy, deferring the prune");
        return;
    };
    let Ok(idx) = local_index.try_read() else {
        debug!("Ember content digests: library index busy, deferring the prune");
        return;
    };
    let mut keep: HashSet<[u8; 16]> = HashSet::new();
    for transfer in mgr.active.values().chain(mgr.queue.iter()) {
        if let Some(hash) = parse_ed2k_hash16(&transfer.file_hash) {
            keep.insert(hash);
        }
    }
    for hash in state.pending_downloads.values() {
        if let Some(parsed) = parse_ed2k_hash16(&hash.file_hash) {
            keep.insert(parsed);
        }
    }
    for file in idx.all_files() {
        if let Some(hash) = parse_ed2k_hash16(&file.hash) {
            keep.insert(hash);
        }
    }
    drop(idx);
    drop(mgr);
    let before = state.ember_content_hashes.len();
    state
        .ember_content_hashes
        .retain(|hash, _| keep.contains(hash));
    debug!(
        "Ember content digests: pruned {} unreferenced entr(ies) (now {})",
        before - state.ember_content_hashes.len(),
        state.ember_content_hashes.len()
    );
}

/// Minimum spacing between relay offers accepted from one friend. Comfortably
/// under the 30s send cadence, so an honest peer is never throttled, while an
/// abusive one cannot spend our CPU on signature checks faster than this.
pub(super) const FRIEND_RELAY_OFFER_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// Floor between unsolicited file offers accepted from one friend. Longer than
/// the relay-offer throttle because each offer that gets through raises a
/// prompt the user has to answer, so the cost of a flood is their attention
/// rather than a signature check.
pub(super) const FRIEND_FILE_OFFER_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Cap on tracked relay-offer senders, so peers that offer once and disappear
/// cannot grow the throttle map without bound.
pub(super) const MAX_FRIEND_RELAY_OFFER_TRACKED: usize = 512;

/// Self-sign an attestation advertising this node as a relay, if we are
/// actually usable as one and the user has not opted out.
///
/// Advertising is a choice. Staying silent when relaying is off matters more
/// than refusing requests later: an unadvertised node is never asked, so peers
/// spend their attempts on someone who will actually carry the traffic.
///
/// Shared by the EPX payload builder and the friend-session relay offer so the
/// two cannot advertise different things — in particular so that turning the
/// setting off silences both.
pub(super) fn sign_local_relay_attestation(
    state: &NetworkState,
    settings: &AppSettings,
    ed25519_secret_key: &[u8; 32],
    ed25519_pubkey: [u8; 32],
) -> Option<ember::RelayAttestation> {
    if !settings.relay_for_peers {
        return None;
    }
    let relay_ip = state.external_ip?;
    // Peers dial this over QUIC from outside, so it must be the public port,
    // not the bound one (see `advertised_quic_port`).
    let relay_port = advertised_quic_port(state)?;
    state
        .connection_broker
        .as_ref()
        .and_then(|b| b.quic_endpoint())?;
    if relay_port == 0 || relay_ip.is_multicast() || crate::security::is_special_use_v4(relay_ip) {
        return None;
    }
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let signing_key = ember::crypto::signing_key_from_bytes(ed25519_secret_key);
    Some(ember::sign_relay_attestation(
        &signing_key,
        ed25519_pubkey,
        relay_ip,
        relay_port,
        now_unix + ember::RELAY_ATTESTATION_MAX_TTL_SECS,
        ember::RELAY_ATTESTATION_CAP_RELAY_V1 | ember::RELAY_ATTESTATION_CAP_PINNED_TARGET,
    ))
}

/// How often a friend is re-offered a relay set that has not otherwise
/// changed. Comfortably inside [`ember::RELAY_ATTESTATION_MAX_TTL_SECS`] so
/// their copy is refreshed well before it expires, while still collapsing the
/// 30s send cadence into one message per bucket.
pub(super) const RELAY_OFFER_REFRESH_SECS: u64 = 600;

/// Order-independent fingerprint of a relay offer, used to suppress re-sending
/// a set a friend already has.
///
/// Deliberately keyed on relay *identity* — the signing key and the address it
/// claims — rather than the attestation hash. The hash covers `expires_at`,
/// and our own attestation is re-signed with a fresh expiry every time it is
/// built, so hashing it would change the digest on every tick and defeat the
/// suppression entirely.
///
/// A coarse time bucket is mixed in so an unchanged set is still refreshed
/// periodically; without it a friend's copy would quietly age out and never be
/// renewed. XOR over the entries keeps it commutative, so a reordering — which
/// carries no information — does not count as a change.
pub(super) fn relay_offer_digest(attestations: &[ember::RelayAttestation], now_unix: u64) -> u64 {
    let mut acc: u64 = now_unix / RELAY_OFFER_REFRESH_SECS;
    for attestation in attestations {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(&attestation.ed25519_pubkey, &mut hasher);
        std::hash::Hash::hash(&attestation.relay_ip.octets(), &mut hasher);
        std::hash::Hash::hash(&attestation.relay_port, &mut hasher);
        acc ^= std::hash::Hasher::finish(&hasher);
    }
    acc
}

/// Verify relay attestations and admit the survivors as broker candidates.
///
/// Shared by the EPX trailer and the friend-session relay offer, because the
/// trust model is identical and must stay that way: every attestation is
/// self-signed by the relay it names and checked here against its signature,
/// expiry, TTL bound, capability bit and address class. Nothing about *who
/// handed it over* is consulted, which is exactly what makes it safe for a
/// friend to forward attestations it did not sign — a courier cannot forge one
/// and cannot silently alter one.
/// `introduced_by` identifies the peer that handed us this set, so the broker
/// can bound any one of them. It plays no part in whether an attestation is
/// accepted — that is decided by its own signature alone.
pub(super) fn admit_relay_attestations(
    state: &mut NetworkState,
    relay_attestations: &[ember::RelayAttestation],
    now_unix: u64,
    introduced_by: Option<[u8; 16]>,
    label: &str,
) -> usize {
    let mut admitted = 0usize;
    for attestation in relay_attestations {
        // Our own attestation, handed back to us. It is perfectly valid — we
        // signed it — so verification would pass and the broker would happily
        // list us as our own relay, then try to bridge a transfer through
        // ourselves. Routine now that friends forward the sets they receive.
        if attestation.ed25519_pubkey == state.local_ed25519_pubkey {
            continue;
        }
        if !ember::verify_relay_attestation(attestation, now_unix) {
            debug!(
                "{label}: rejected invalid relay attestation for {}:{}",
                attestation.relay_ip, attestation.relay_port
            );
            continue;
        }
        if let Some(ref mut broker) = state.connection_broker {
            let relay_ember_hash =
                ember::crypto::verifying_key_from_bytes(&attestation.ed25519_pubkey)
                    .map(|vk| ember::crypto::node_id_from_public_key(&vk));
            broker.add_relay_candidate(attestation.clone(), relay_ember_hash, introduced_by);
            admitted += 1;
        }
    }
    admitted
}

/// Retire whatever session `friend` currently holds, whichever one it is.
///
/// Takes the write lock once and does the lookup inside it, so a caller cannot
/// find the session under a read guard and still be holding it when the retire
/// asks for the write lock. Written the other way round — the id read in an
/// `if let` scrutinee, the retire in its body — the guard outlives the lookup
/// on this edition and tokio's `RwLock` turns it into an unconditional
/// self-deadlock. The whole network runs on one task, so that stopped every
/// timer, every datagram, and shutdown along with it.
///
/// Unlike [`retire_ember_session`] there is no session-id filter: the caller
/// wants this peer gone, not one particular session of it.
pub(super) async fn retire_current_ember_session(
    sessions: &upload_server::EmberSessionMap,
    friend: [u8; 16],
) -> bool {
    let mut sessions = sessions.write().await;
    let Some(handle) = sessions.remove(&friend) else {
        return false;
    };
    handle.close();
    true
}

/// Retire `friend`'s session only if it is still the one identified by
/// `session_id`, so a late cancel cannot close a newer session.
pub(super) async fn retire_ember_session(
    sessions: &upload_server::EmberSessionMap,
    friend: [u8; 16],
    session_id: u64,
) -> bool {
    let mut sessions = sessions.write().await;
    let Some(handle) = sessions
        .get(&friend)
        .filter(|handle| handle.session_id() == session_id)
        .cloned()
    else {
        return false;
    };
    handle.close();
    sessions.remove(&friend);
    true
}

/// Record a live eD2K Ember session as a DHT introduction and ping it now.
///
/// A connected peer is not unsolicited LAN gossip: the TCP session already
/// passed PoP. Skipping `block_private_ips` here is what lets a 1.5.x LAN
/// neighbour join the overlay. Loopback/multicast/docs ranges stay out.
pub(super) async fn note_connected_ember_peer(
    socket: &UdpSocket,
    state: &mut NetworkState,
    ember_native_enabled: bool,
    ip: Ipv4Addr,
    tcp_port: u16,
    udp_port: u16,
) {
    if crate::security::is_bogus_v4(ip) {
        return;
    }
    if tcp_port > 0 && record_known_ember_peer(&mut state.known_ember_peers, ip, tcp_port) {
        state.stats.ember_peers = state.known_ember_peers.len() as u32;
        state.ember_payload_dirty = true;
    }
    if udp_port == 0 {
        // The peer is now a known Ember host and will never be a DHT contact:
        // the overlay rides the shared UDP socket, so with no port there is
        // nothing to bridge to, and every later step keys on `(ip, udp_port)`.
        // Silence here is what makes that indistinguishable from a bridge ping
        // that was sent and ignored, which is a very different fault — one is
        // the peer's hello, the other is the network in between.
        debug!(
            "Ember bridge: {ip} advertised no UDP port, so it can be a known peer \
             but never a DHT contact"
        );
        return;
    }
    record_ember_keyless_peer(&mut state.ember_keyless_peers, ip, udp_port);
    if !ember_native_enabled {
        return;
    }
    let key = (ip, udp_port);
    if ember_verified_addrs(state).contains(&key) {
        return;
    }
    let starved = ember_dht_starved(state);
    if !bridge_retry_due(
        &state.ember_kad_bridge_attempted,
        &key,
        std::time::Instant::now(),
        starved,
    ) {
        return;
    }
    let noise = lookup_ember_noise_key(&state.ember_noise_keys, ip, udp_port);
    send_ember_bridge_ping(socket, state, ip, udp_port, noise.as_ref()).await;
}

/// DHT-PING an Ember address so the signed PONG can teach us its node ID.
pub(super) async fn send_ember_bridge_ping(
    socket: &UdpSocket,
    state: &mut NetworkState,
    ip: Ipv4Addr,
    udp_port: u16,
    noise_pub: Option<&[u8; 32]>,
) -> bool {
    // Candidates come from KAD tags and eD2K sessions, neither of which the
    // user's IP policy or ban list has seen. A firm block is forgotten here so
    // the address stops taking a candidate slot; a ban is rested on the retry
    // backoff like an unanswered dial, since it lifts.
    match ember_peer_ip_verdict(state, ip, udp_port) {
        EmberIpVerdict::Allowed => {}
        EmberIpVerdict::Blocked => {
            state.ember_noise_keys.remove(&(ip, udp_port));
            state.ember_keyless_peers.remove(&(ip, udp_port));
            state.ember_kad_bridge_attempted.remove(&(ip, udp_port));
            return false;
        }
        EmberIpVerdict::Banned => {
            note_ember_bridge_attempt(state, ip, udp_port);
            return false;
        }
    }
    let addr = SocketAddr::new(IpAddr::V4(ip), udp_port);
    let sent = send_ember_dht_ping(socket, state, addr, noise_pub).await;
    // A peer we never transmitted to has told us nothing, so holding it out of
    // the candidate list for the full retry window spends the bridge's only
    // means of converting a lead on our own transport hiccup. A lost or
    // unanswered ping still counts — that is what the window is for.
    if sent.is_some() {
        note_ember_bridge_attempt(state, ip, udp_port);
    }
    let sent = sent == Some(true);
    if sent {
        state.ember_diagnostics.ember_dht_kad_bridge_pings = state
            .ember_diagnostics
            .ember_dht_kad_bridge_pings
            .saturating_add(1);
    }
    sent
}

/// Build a DHT `PING` and send it to `addr`. `None` when our own transport
/// declined to build it, so the peer was never dialled; otherwise whether the
/// datagram went out (or was queued behind a handshake).
async fn send_ember_dht_ping(
    socket: &UdpSocket,
    state: &mut NetworkState,
    addr: SocketAddr,
    noise_pub: Option<&[u8; 32]>,
) -> Option<bool> {
    let (_wire_req_id, frame) = state.ember_dht.build_ping();
    match state
        .ember_transport
        .prepare_outgoing(addr, noise_pub, &frame)
    {
        ember::transport::OutgoingResult::Ready { packet }
        | ember::transport::OutgoingResult::HandshakeStarted { packet } => {
            match send_ember_udp(socket, &packet, addr, &state.ember_dht_overhead).await {
                Ok(_) => Some(true),
                Err(e) => {
                    debug!("Ember DHT: ping to {addr} failed: {e}");
                    Some(false)
                }
            }
        }
        ember::transport::OutgoingResult::Queued => Some(true),
        ember::transport::OutgoingResult::Error(e) => {
            debug!("Ember DHT: transport error pinging {addr}: {e}");
            None
        }
    }
}

fn note_ember_bridge_attempt(state: &mut NetworkState, ip: Ipv4Addr, udp_port: u16) {
    let now = std::time::Instant::now();
    let entry = state
        .ember_kad_bridge_attempted
        .entry((ip, udp_port))
        .or_insert((now, 0));
    entry.0 = now;
    entry.1 = entry.1.saturating_add(1);
}

/// Ask live friend sessions for the Ember DHT contacts they hold.
///
/// A friend is the strongest bootstrap signal the app has, and almost none of
/// it was used: the route from a friend to a DHT contact ran entirely through
/// the eD2K hello's UDP port and a single bridge `PING`, so a friend whose
/// hello named no port — or whose address `EmberPeerDiscovered`'s guards
/// reject, which is the normal case for a relayed or NAT-traversed session —
/// was never a candidate at all, and no retry policy helps something that is
/// never attempted. Field evidence: a node holding three contacts sat beside a
/// friend holding fourteen, over a working friend session, with `Known peers`
/// at 0.
///
/// The overlay rides UDP, so a friend we cannot ping can never *be* a contact.
/// It can still hand over the contacts it already has, and those enter as
/// unverified leads through the same admission and probe path as any other
/// gossip — nothing here is trusted further than a `FOUND_NODE` would be.
///
/// Only while the table is short of a working set, so a healthy node never
/// spends a byte on this. Thin rather than still joining: a friend can come
/// online long after a small overlay has settled, and for a node behind a
/// relay it may be the only way in. Returns how many friends were asked.
pub(super) async fn ask_friends_for_ember_contacts(state: &mut NetworkState) -> usize {
    if state.ember_dht.routing().verified_len() >= EMBER_KAD_BRIDGE_UNTIL_CONTACTS {
        return 0;
    }
    let now = std::time::Instant::now();
    let live: Vec<([u8; 16], tokio::sync::mpsc::Sender<Vec<u8>>)> = {
        let sessions = state.ember_sessions.read().await;
        sessions
            .iter()
            .filter(|(_, h)| h.is_fresh() && h.is_secure_v2())
            .map(|(eh, h)| (*eh, h.tx.clone()))
            .collect()
    };
    let target = state.ember_dht.local_id();
    let frame =
        ed2k::messages::build_ember_ext_frame(ed2k::messages::EMBER_EXT_DHT_CONTACT_REQ, &target.0);

    let due = ember_friend_ask_order(live, &state.ember_friend_contacts_asked, now);
    let mut asked = 0usize;
    for (eh, tx) in due {
        if asked >= EMBER_FRIEND_CONTACT_ASKS_PER_TICK {
            break;
        }
        // A full queue means the session is already backed up; the next tick
        // asks again, so nothing is lost by not waiting for room here.
        if tx.try_send(frame.clone()).is_err() {
            continue;
        }
        state.ember_friend_contacts_asked.insert(eh, now);
        asked += 1;
        state.ember_diagnostics.ember_dht_friend_contact_asks = state
            .ember_diagnostics
            .ember_dht_friend_contact_asks
            .saturating_add(1);
    }
    if asked > 0 {
        debug!("Ember DHT: asked {asked} friend session(s) for contacts while the table is thin");
    }
    asked
}

/// Friends due to be asked for contacts, least recently asked first.
///
/// The ordering is not cosmetic. [`EMBER_FRIEND_CONTACT_ASK_INTERVAL`] equals
/// the maintenance tick, so every friend asked last cycle is due again this
/// cycle — and taking the first [`EMBER_FRIEND_CONTACT_ASKS_PER_TICK`] in
/// session-map order would then ask the same few for the life of the process
/// while a fifth friend was never asked at all. `ember_dht_announce_targets`
/// had the same failure for the same reason, and this is the same fix.
///
/// Never-asked friends come first, which `Option`'s own ordering gives for
/// free (`None` before `Some`).
pub(super) fn ember_friend_ask_order<T>(
    live: Vec<([u8; 16], T)>,
    asked: &HashMap<[u8; 16], std::time::Instant>,
    now: std::time::Instant,
) -> Vec<([u8; 16], T)> {
    least_recently_asked_due(live, asked, now, EMBER_FRIEND_CONTACT_ASK_INTERVAL)
}

/// [`ember_friend_ask_order`] for any per-friend `interval`.
pub(super) fn least_recently_asked_due<T>(
    live: Vec<([u8; 16], T)>,
    asked: &HashMap<[u8; 16], std::time::Instant>,
    now: std::time::Instant,
    interval: std::time::Duration,
) -> Vec<([u8; 16], T)> {
    let mut due: Vec<([u8; 16], T)> = live
        .into_iter()
        .filter(|(eh, _)| match asked.get(eh) {
            Some(last) => now.saturating_duration_since(*last) >= interval,
            None => true,
        })
        .collect();
    due.sort_by_key(|(eh, _)| asked.get(eh).copied());
    due
}

/// The contacts to hand a friend that asked: closest to `target`, and only
/// ones that have answered us.
///
/// `find_closest` already prefers verified contacts, but falls back to leads
/// when it holds no verified ones at all — which is exactly the node whose
/// leads are least worth passing on. Filtering after it is what makes a
/// starved node answer with an empty list rather than with its own guesses,
/// and an empty answer still tells the asker the difference between a friend
/// that has nothing and a friend whose build predates the question.
pub(super) fn ember_friend_contact_answer(
    routing: &ember::dht::routing::RoutingTable,
    target: &ember::dht::EmberNodeId,
) -> Vec<ember::dht::EmberContact> {
    let mut contacts = routing.find_closest(target, ember::dht::MAX_CONTACTS_PER_RESPONSE);
    contacts.retain(|c| c.is_verified());
    contacts
}

/// Answer a friend's request for our Ember DHT contacts.
///
/// Passing on our own unverified leads would spread exactly the noise
/// [`ember::dht::gossip`] exists to price, so only proven contacts travel —
/// see [`ember_friend_contact_answer`].
///
/// `target` decides only *which* of our contacts are closest, so taking the
/// asker's word for it grants nothing.
pub(super) async fn answer_friend_ember_contact_request(
    state: &mut NetworkState,
    friend: [u8; 16],
    target: Option<[u8; 16]>,
    reply_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    let now = std::time::Instant::now();
    if let Some(last) = state.ember_friend_contacts_served.get(&friend) {
        if now.saturating_duration_since(*last) < EMBER_FRIEND_CONTACT_SERVE_INTERVAL {
            return;
        }
    }
    // Stamped before the work, not after a successful send. What this throttle
    // protects is the table walk and the kilobyte it produces, and a friend
    // whose writer queue is full would otherwise buy an unthrottled walk per
    // request by never accepting the answer.
    state.ember_friend_contacts_served.insert(friend, now);

    let target = ember::dht::EmberNodeId(target.unwrap_or(state.ember_dht.local_id().0));
    let contacts = ember_friend_contact_answer(state.ember_dht.routing(), &target);
    let body = ember::dht::messages::encode_contact_list(&contacts);
    let frame =
        ed2k::messages::build_ember_ext_frame(ed2k::messages::EMBER_EXT_DHT_CONTACTS, &body);
    if reply_tx.try_send(frame).is_ok() {
        debug!(
            "Ember DHT: answered friend {} with {} verified contact(s)",
            crate::security::short_hash(&friend),
            contacts.len()
        );
    }
}

/// Fold a friend's answer into the routing table and probe what it named.
///
/// The contacts arrive unverified (the wire list carries no `last_seen`), so
/// they go through `offer_contact` — the full IP policy and diversity gate —
/// and then through the ordinary gossip probe.
///
/// Only ever an answer to a question we asked, inside
/// [`EMBER_FRIEND_CONTACT_ANSWER_WINDOW`]. Acting on an unsolicited list would
/// hand a friend the whole gossip probe budget on demand — the one thing
/// [`ember::dht::gossip`] rations a DHT peer for. Requiring the ask is what
/// lets a friend go unscored, and it also drops a list that arrives long after
/// the table it was meant to fill.
///
/// No reputation record is kept for the friend, even though it could be: an
/// Ember hash *is* a DHT node ID (`BLAKE3(ed25519_pub)[..16]` — see
/// [`ember::dht::engine::EmberDht::new`]), so the two are the same namespace.
/// Scoring is for a peer whose introductions we did not solicit; here the ask
/// and its window are the bound, and rationing a friend we deliberately
/// queried would only starve the path we opened it for.
pub(super) async fn ingest_friend_ember_contacts(
    socket: &UdpSocket,
    state: &mut NetworkState,
    friend: [u8; 16],
    body: &[u8],
) {
    let asked_recently = state
        .ember_friend_contacts_asked
        .get(&friend)
        .is_some_and(|at| {
            std::time::Instant::now().saturating_duration_since(*at)
                < EMBER_FRIEND_CONTACT_ANSWER_WINDOW
        });
    if !asked_recently {
        debug!(
            "Ember DHT: ignoring a contact list from friend {} that answers no recent ask",
            crate::security::short_hash(&friend)
        );
        return;
    }
    let contacts = match ember::dht::messages::decode_contact_list(body) {
        Ok(contacts) => contacts,
        Err(e) => {
            debug!(
                "Ember DHT: friend {} sent an undecodable contact list: {e}",
                crate::security::short_hash(&friend)
            );
            return;
        }
    };
    if contacts.is_empty() {
        debug!(
            "Ember DHT: friend {} has no verified contacts to share",
            crate::security::short_hash(&friend)
        );
        return;
    }
    let (learned, pressure) = offer_friend_ember_contacts(&mut state.ember_dht, &contacts);
    if learned > 0 {
        state.ember_diagnostics.ember_dht_friend_contacts_learned = state
            .ember_diagnostics
            .ember_dht_friend_contacts_learned
            .saturating_add(learned as u32);
    }
    info!(
        "Ember DHT: friend {} shared {} contact(s), {learned} new",
        crate::security::short_hash(&friend),
        contacts.len()
    );
    probe_bucket_oldest(socket, state, &pressure, chrono::Utc::now().timestamp()).await;
    // No introducer: see the note above. The probe budget and its one-second
    // window still apply, so this cannot outspend ordinary gossip.
    probe_ember_gossip_leads(socket, state, &contacts, None).await;
}

/// Whether `friend` already answers us as a DHT contact. An Ember hash is the
/// friend's DHT node ID (see [`ingest_friend_ember_contacts`]), so this needs
/// no address at all.
fn friend_is_verified_contact(state: &NetworkState, friend: &[u8; 16]) -> bool {
    state
        .ember_dht
        .routing()
        .get_contact(&ember::dht::EmberNodeId(*friend))
        .is_some_and(|contact| contact.is_verified())
}

/// Ask friends we hold a direct session with, but no verified DHT contact
/// for, to meet over UDP (`EMBER_EXT_DHT_MEET`).
///
/// This is the half of the friend route the contact ask cannot cover: a
/// friend can hand over the contacts it holds, but cannot *become* one while
/// neither side can reach the other's UDP socket unsolicited. The meet makes
/// both `PING`s solicited. The friend `PING`s us as it answers, we `PING` it
/// on reading the answer, and each `PING` opens the path back through its
/// sender's own NAT.
///
/// Asked at any table size, since the condition — this friend is not a
/// contact — is exact rather than a starvation guess. Skipped while our own
/// NAT is symmetric: the port the friend would aim at is then not the one our
/// next datagram leaves from. Relayed sessions are skipped too, because the
/// friend's half has to `PING` the address the session is connected from.
/// Returns how many friends were asked.
pub(super) async fn ask_friends_to_meet(state: &mut NetworkState) -> usize {
    let now = std::time::Instant::now();
    let pending: Vec<[u8; 16]> = state.ember_friend_meets_asked.keys().copied().collect();
    for friend in pending {
        if friend_is_verified_contact(state, &friend) {
            state.ember_friend_meets_asked.remove(&friend);
            state.ember_diagnostics.ember_dht_friend_meets_converted = state
                .ember_diagnostics
                .ember_dht_friend_meets_converted
                .saturating_add(1);
            info!(
                "Ember DHT: friend {} is a contact after meeting over UDP",
                crate::security::short_hash(&friend)
            );
        }
    }
    if state.nat_info.nat_type == ember::nat::NatType::Symmetric {
        return 0;
    }
    let udp_port = advertised_udp_port(state);
    if udp_port == 0 {
        return 0;
    }
    let live: Vec<([u8; 16], tokio::sync::mpsc::Sender<Vec<u8>>)> = {
        let sessions = state.ember_sessions.read().await;
        sessions
            .iter()
            .filter(|(_, h)| {
                h.is_fresh()
                    && h.is_secure_v2()
                    && !h.is_relayed()
                    && h.peer_addr().is_some_and(|addr| addr.is_ipv4())
            })
            .map(|(eh, h)| (*eh, h.tx.clone()))
            .collect()
    };
    // A secure session is not always a friend's, and only a friend answers.
    let live: Vec<_> = {
        let friends = state.xfer_friend_hashes.read().await;
        live.into_iter()
            .filter(|(eh, _)| friends.contains(eh) && !friend_is_verified_contact(state, eh))
            .collect()
    };
    let due = least_recently_asked_due(live, &state.ember_friend_meets_asked, now, EMBER_FRIEND_MEET_INTERVAL);
    let frame = ed2k::messages::build_ember_ext_frame(
        ed2k::messages::EMBER_EXT_DHT_MEET,
        &ed2k::messages::encode_dht_meet(udp_port, false),
    );
    let mut asked = 0usize;
    for (eh, tx) in due {
        if asked >= EMBER_FRIEND_MEETS_PER_TICK {
            break;
        }
        if tx.try_send(frame.clone()).is_err() {
            continue;
        }
        state.ember_friend_meets_asked.insert(eh, now);
        asked += 1;
        state.ember_diagnostics.ember_dht_friend_meets = state
            .ember_diagnostics
            .ember_dht_friend_meets
            .saturating_add(1);
    }
    if asked > 0 {
        debug!("Ember DHT: asked {asked} friend(s) to meet over UDP");
    }
    asked
}

/// Act on a friend's `EMBER_EXT_DHT_MEET`: `PING` it at the address its
/// session is connected from and the port it claimed, and, unless this is the
/// answer to our own ask, answer with ours so it `PING`s us back.
///
/// An answer is only acted on inside [`EMBER_FRIEND_MEET_ANSWER_WINDOW`] of our
/// ask, and a friend is `PING`ed for a meet at most once per window whichever
/// frame asked for it, so no run of frames has us `PING` it on demand. When
/// both sides ask at once, each answer then lands inside the window its own
/// ask already used, which is right: both `PING`s have gone out. Nothing here
/// touches the routing table; only the `PONG` can, through the ordinary path.
pub(super) async fn answer_friend_meet(
    socket: &UdpSocket,
    state: &mut NetworkState,
    friend: [u8; 16],
    peer_ip: Ipv4Addr,
    udp_port: u16,
    answer: bool,
    reply_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    if crate::security::is_bogus_v4(peer_ip) {
        return;
    }
    let now = std::time::Instant::now();
    let within_window =
        |at: Option<&std::time::Instant>| at.is_some_and(|at| now.saturating_duration_since(*at) < EMBER_FRIEND_MEET_ANSWER_WINDOW);
    if answer && !within_window(state.ember_friend_meets_asked.get(&friend)) {
        return;
    }
    if within_window(state.ember_friend_meets_pinged.get(&friend)) {
        return;
    }
    // The user's IP policy and bans hold for a friend's address too; this is
    // not a bridge attempt, so none of the bridge's bookkeeping applies.
    if !matches!(ember_peer_ip_verdict(state, peer_ip, udp_port), EmberIpVerdict::Allowed) {
        return;
    }
    state.ember_friend_meets_pinged.insert(friend, now);
    let noise = lookup_ember_noise_key(&state.ember_noise_keys, peer_ip, udp_port);
    let addr = SocketAddr::new(IpAddr::V4(peer_ip), udp_port);
    send_ember_dht_ping(socket, state, addr, noise.as_ref()).await;
    if answer {
        return;
    }
    let our_port = advertised_udp_port(state);
    if our_port == 0 || state.nat_info.nat_type == ember::nat::NatType::Symmetric {
        return;
    }
    let frame = ed2k::messages::build_ember_ext_frame(
        ed2k::messages::EMBER_EXT_DHT_MEET,
        &ed2k::messages::encode_dht_meet(our_port, true),
    );
    let _ = reply_tx.try_send(frame);
}

/// Offer a friend's contacts to the routing table. Returns how many took a
/// slot that no contact of ours held before, and the incumbents of the full
/// buckets the rest were parked behind — which [`probe_bucket_oldest`] has to
/// probe, or those contacts wait on an eviction nothing will trigger.
pub(super) fn offer_friend_ember_contacts(
    dht: &mut ember::dht::engine::EmberDht,
    contacts: &[ember::dht::EmberContact],
) -> (usize, Vec<(SocketAddr, ember::dht::EmberNodeId, [u8; 32])>) {
    let local_id = dht.local_id();
    let mut learned = 0usize;
    let mut pressure = Vec::new();
    for contact in contacts {
        if contact.node_id == local_id {
            continue;
        }
        let known = dht.contact_for(&contact.node_id).is_some();
        match dht.offer_contact(contact.clone()) {
            ember::dht::routing::AddResult::Added => {
                if !known {
                    learned += 1;
                }
            }
            ember::dht::routing::AddResult::PingOldest {
                addr,
                node_id,
                noise_pub,
            } => pressure.push((addr, node_id, noise_pub)),
            ember::dht::routing::AddResult::Rejected => {}
        }
    }
    (learned, pressure)
}

/// Pin connected eD2K Ember peers onto a FIND_VALUE walk. Their records live
/// on that node; XOR-closest public contacts will not have them.
pub(super) fn seed_ember_session_search_contacts(state: &mut NetworkState, search_id: u32) {
    if state.ember_session_dht_contacts.is_empty() {
        return;
    }
    let extras: Vec<_> = state.ember_session_dht_contacts.values().cloned().collect();
    let seeded = state.ember_search.seed_extra_contacts(search_id, extras);
    if seeded > 0 {
        debug!("Ember DHT: pinned {seeded} session contact(s) onto search {search_id}");
    }
}

/// Every FIND_NODE the app walks on its own is maintenance, which takes
/// [`start_ember_background_find_node`] to yield the reserve. Only the debug
/// diagnostics panel asks for one directly, so this is gated to match its
/// single caller rather than riding along dead in release builds.
#[cfg(debug_assertions)]
pub(super) fn start_ember_find_node(
    state: &mut NetworkState,
    target: ember::dht::EmberNodeId,
) -> Option<u32> {
    let search_id = state
        .ember_search
        .start_find_node(target, state.ember_dht.routing())?;
    seed_ember_session_search_contacts(state, search_id);
    Some(search_id)
}

/// [`start_ember_find_node`] for the maintenance tick's own walks — the
/// self-lookup, bucket refresh and publish-target resolution. Each is re-queued
/// and retried on the next tick, so they yield the reserve that keeps a slot
/// available for whatever the user asked for. See `MAX_BACKGROUND_SEARCHES`.
pub(super) fn start_ember_background_find_node(
    state: &mut NetworkState,
    target: ember::dht::EmberNodeId,
) -> Option<u32> {
    let search_id = state
        .ember_search
        .start_background_find_node(target, state.ember_dht.routing())?;
    seed_ember_session_search_contacts(state, search_id);
    Some(search_id)
}

/// Exchange contact lists with one live peer. Used by the maintenance tick
/// and by the inbound path while the table is still too thin to wait a minute.
pub(super) async fn send_ember_announce_peer(
    socket: &UdpSocket,
    state: &mut NetworkState,
    contact: &ember::dht::EmberContact,
) -> bool {
    let local_id = state.ember_dht.local_id();
    let closest = state
        .ember_dht
        .routing()
        .find_closest(&contact.node_id, ember::dht::MAX_CONTACTS_PER_RESPONSE);
    let gossip = ember_announce_gossip(
        closest,
        &state.ember_session_dht_contacts,
        contact,
        local_id,
    );
    state
        .ember_announced_at
        .insert(contact.node_id, chrono::Utc::now().timestamp());
    let (_wire_req_id, frame) = state.ember_dht.build_announce_peer(gossip);
    match state.ember_transport.prepare_outgoing(
        contact.addr,
        Some(&contact.noise_pub),
        &frame,
    ) {
        ember::transport::OutgoingResult::Ready { packet }
        | ember::transport::OutgoingResult::HandshakeStarted { packet } => {
            match send_ember_udp(socket, &packet, contact.addr, &state.ember_dht_overhead).await {
                Ok(_) => true,
                Err(e) => {
                    debug!("Ember DHT: announce to {} failed: {e}", contact.addr);
                    false
                }
            }
        }
        ember::transport::OutgoingResult::Queued => true,
        ember::transport::OutgoingResult::Error(e) => {
            debug!(
                "Ember DHT: transport error announcing to {}: {e}",
                contact.addr
            );
            false
        }
    }
}

/// Ping unverified gossip as soon as we hear it, so a PEER_LIST of the
/// friend's other contacts does not sit idle until the next 60s tick.
///
/// `introducer` is the peer whose frame carried these leads: it is skipped if it
/// named itself, and it is who the outcome of each probe is charged to. See
/// [`ember::dht::gossip`].
pub(super) async fn probe_ember_gossip_leads(
    socket: &UdpSocket,
    state: &mut NetworkState,
    leads: &[ember::dht::EmberContact],
    introducer: Option<ember::dht::EmberNodeId>,
) {
    if leads.is_empty() {
        return;
    }
    let local_id = state.ember_dht.local_id();
    let starved = ember_dht_starved(state);
    let budget = if starved {
        EMBER_MAINT_MAX_PINGS_STARVED
    } else {
        EMBER_MAINT_MAX_PINGS
    };
    // The budget is shared across a one-second window rather than granted per
    // call. These constants are sized as *per maintenance tick* allowances, but
    // this runs once per inbound ANNOUNCE_PEER / PEER_LIST / FOUND_NODE, each of
    // which may carry `MAX_CONTACTS_PER_RESPONSE` fresh keypairs — so the
    // per-contact dedup below never fires and the effective probe rate became
    // frame-rate times budget, aimed at addresses the sender chooses.
    let now = std::time::Instant::now();
    if now.duration_since(state.ember_gossip_probe_window.0) >= std::time::Duration::from_secs(1) {
        state.ember_gossip_probe_window = (now, 0);
    }
    let budget = budget.saturating_sub(state.ember_gossip_probe_window.1);
    if budget == 0 {
        return;
    }
    let mut sent = 0usize;
    for contact in leads {
        if sent >= budget {
            break;
        }
        if contact.node_id == local_id || Some(contact.node_id) == introducer {
            continue;
        }
        if contact.noise_pub == [0u8; 32] || contact.addr.port() == 0 {
            continue;
        }
        // A gossiped address is one the sender named, so the user's own filter
        // has to apply before we dial it — `is_bogus_v4` alone let `ipfilter.dat`
        // be bypassed for every address learned this way.
        if !state.ember_dht.routing().admits_addr(&contact.addr)
            || ember_addr_banned(state, contact.addr)
        {
            continue;
        }
        if state
            .ember_dht
            .contact_for(&contact.node_id)
            .is_some_and(|c| c.is_verified())
        {
            continue;
        }
        // By address as well as by identity: the address is whatever the
        // introducer wrote beside a free keypair, so one frame naming many IDs
        // at a single address would otherwise spend a probe on each of them —
        // the whole budget aimed wherever the sender likes.
        if state
            .ember_dht_maint_pings
            .values()
            .any(|p| p.node_id == contact.node_id || p.addr == contact.addr)
        {
            continue;
        }
        let IpAddr::V4(ip) = contact.addr.ip() else {
            continue;
        };
        if crate::security::is_bogus_v4(ip) {
            continue;
        }
        // Whose word this is on, and whether that word has been worth a probe.
        // Not asked while starved: a node with nothing has to try everything,
        // because probing junk costs bandwidth and failing to join costs the
        // overlay. Asked last, so a lead skipped for any of the reasons above
        // does not read as an introducer being rationed.
        if !starved {
            if let Some(intro) = introducer {
                if !state.ember_gossip_reputation.should_probe(&intro) {
                    state.ember_diagnostics.ember_dht_gossip_leads_rationed = state
                        .ember_diagnostics
                        .ember_dht_gossip_leads_rationed
                        .saturating_add(1);
                    continue;
                }
            }
        }
        let (wire_req_id, frame) = state.ember_dht.build_ping();
        let mut behind_handshake = false;
        let mut delivery_certain = true;
        let send_ok = match state.ember_transport.prepare_outgoing(
            contact.addr,
            Some(&contact.noise_pub),
            &frame,
        ) {
            ember::transport::OutgoingResult::Ready { packet } => {
                match send_ember_udp(socket, &packet, contact.addr, &state.ember_dht_overhead).await
                {
                    Ok(_) => true,
                    Err(e) => {
                        debug!("Ember DHT: gossip probe to {} failed: {e}", contact.addr);
                        false
                    }
                }
            }
            ember::transport::OutgoingResult::HandshakeStarted { packet } => {
                behind_handshake = true;
                match send_ember_udp(socket, &packet, contact.addr, &state.ember_dht_overhead).await
                {
                    Ok(_) => true,
                    Err(e) => {
                        debug!("Ember DHT: gossip probe to {} failed: {e}", contact.addr);
                        false
                    }
                }
            }
            ember::transport::OutgoingResult::Queued => {
                behind_handshake = true;
                // See `probe_bucket_oldest`: a frame parked behind an XX dial
                // may be discarded at flush rather than sent, so it is not
                // booked and cannot fault the lead.
                delivery_certain = state
                    .ember_transport
                    .queued_delivery_is_certain(contact.addr, &contact.noise_pub);
                true
            }
            ember::transport::OutgoingResult::Error(e) => {
                debug!(
                    "Ember DHT: transport error probing gossip {}: {e}",
                    contact.addr
                );
                false
            }
        };
        // `delivery_certain` is only ever false on the `Queued` path, so this
        // is "the frame is on the wire, or will be when the handshake it is
        // parked behind completes with the peer we addressed it to".
        let issued = send_ok && delivery_certain;
        if issued {
            state.ember_dht_maint_pings.insert(
                wire_req_id,
                new_ember_maint_ping(
                    contact.node_id,
                    contact.addr,
                    behind_handshake,
                    chrono::Utc::now().timestamp(),
                ),
            );
            state.ember_diagnostics.ember_dht_liveness_pings_sent = state
                .ember_diagnostics
                .ember_dht_liveness_pings_sent
                .saturating_add(1);
            sent += 1;
            state.ember_gossip_probe_window.1 =
                state.ember_gossip_probe_window.1.saturating_add(1);
            // Attribution starts here rather than at the naming, so an
            // introducer is never charged for a lead our own budget never
            // reached.
            if let Some(intro) = introducer {
                state.ember_gossip_reputation.note_probe(
                    intro,
                    contact.node_id,
                    contact.addr,
                    std::time::Instant::now(),
                );
            }
        } else if !starved {
            // The probe never reached the wire — the send failed, or it was
            // parked behind a handshake that may discard it. Either way the
            // sampling slot `should_probe` spent to allow it bought nothing, so
            // hand it back; otherwise a rationed introducer is held at arm's
            // length by our own send failures rather than by anything it did.
            // Gated on `!starved` because that is the only branch that calls
            // `should_probe` at all — refunding a sample never spent would let
            // the counter grant one early.
            if let Some(intro) = introducer {
                state.ember_gossip_reputation.refund_probe(&intro);
            }
        }
    }
}
