//! Observed-IP voting for Ember DHT (slice 19).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

pub const MIN_OBSERVED_IP_VOTES: usize = 3;

/// How long a vote counts toward the quorum.
///
/// Without expiry the three-vote threshold was cumulative over the whole
/// process lifetime rather than a statement about what peers see *now*, so a
/// stale address stayed qualified indefinitely and a genuine address change
/// could not displace it.
const VOTE_TTL: Duration = Duration::from_secs(15 * 60);

/// Distinct reported addresses tracked at once. Every entry costs memory and
/// a peer can report a different address on each reply, so the map is capped
/// and the least-recently-updated entry is dropped.
const MAX_TRACKED_ADDRS: usize = 64;

#[derive(Debug, Default)]
struct AddrVotes {
    /// Reporter /24 → when it last voted for this address.
    nets: HashMap<[u8; 3], Instant>,
    last_update: Option<Instant>,
}

#[derive(Debug, Default)]
pub struct EmberObservedIpVotes {
    votes: HashMap<SocketAddr, AddrVotes>,
    confirmed: Option<SocketAddr>,
}

impl EmberObservedIpVotes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn confirmed(&self) -> Option<SocketAddr> {
        self.confirmed
    }

    pub fn record_vote(&mut self, reported: SocketAddr, reporter: IpAddr) -> Option<SocketAddr> {
        self.record_vote_at(reported, reporter, Instant::now())
    }

    /// `record_vote` with an explicit clock, so the expiry window is testable.
    pub fn record_vote_at(
        &mut self,
        reported: SocketAddr,
        reporter: IpAddr,
        now: Instant,
    ) -> Option<SocketAddr> {
        if !is_public_vote_addr(reported) {
            return None;
        }
        // Reject private/loopback reporters so LAN Sybils cannot vote.
        if !is_public_reporter(reporter) {
            return None;
        }
        let Some(net) = reporter_net24(reporter) else {
            return None;
        };

        self.prune(now);

        if self.votes.len() >= MAX_TRACKED_ADDRS && !self.votes.contains_key(&reported) {
            // Drop the least-recently-updated address to make room, so a peer
            // reporting a fresh address on every reply cannot grow this map.
            //
            // Never the confirmed one, however quiet it has gone: `prune` reads
            // its quorum back out of this map, so evicting it retracts a
            // confirmation whose votes are all still live — and in this very
            // call `current_count` would then read zero, letting a merely tied
            // rival take the address over, which is the takeover the tie rule
            // exists to refuse. The plain minimum is still the fallback so the
            // cap holds even when the confirmed entry is the only candidate.
            let confirmed = self.confirmed;
            let victim = self
                .votes
                .iter()
                .filter(|(addr, _)| Some(**addr) != confirmed)
                .min_by_key(|(_, v)| v.last_update)
                .map(|(k, _)| *k)
                .or_else(|| {
                    self.votes
                        .iter()
                        .min_by_key(|(_, v)| v.last_update)
                        .map(|(k, _)| *k)
                });
            if let Some(oldest) = victim {
                self.votes.remove(&oldest);
            }
        }

        let new_count = {
            let entry = self.votes.entry(reported).or_default();
            entry.nets.insert(net, now);
            entry.last_update = Some(now);
            entry.nets.len()
        };
        let quorum = new_count >= MIN_OBSERVED_IP_VOTES;

        // Only a genuine transition counts. Re-assigning on every qualifying
        // vote meant whichever address was voted for most recently won, so an
        // attacker could displace a correct confirmation just by repeating
        // themselves. A rival that merely ties the current quorum is the same
        // trick with more hosts: three coordinated /24s must not overwrite an
        // address that still has a live quorum. Switch only when nothing is
        // confirmed (prune already dropped a lapsed one) or the new address
        // has strictly more distinct nets.
        if quorum && self.confirmed != Some(reported) {
            let current_count = self
                .confirmed
                .and_then(|addr| self.votes.get(&addr))
                .map(|v| v.nets.len())
                .unwrap_or(0);
            if current_count == 0 || new_count > current_count {
                self.confirmed = Some(reported);
                return Some(reported);
            }
        }
        None
    }

    /// Drop votes and addresses that have aged out.
    fn prune(&mut self, now: Instant) {
        self.votes.retain(|_, v| {
            v.nets
                .retain(|_, at| now.saturating_duration_since(*at) < VOTE_TTL);
            !v.nets.is_empty()
        });
        // A confirmation only stands while its quorum does.
        if let Some(addr) = self.confirmed {
            let still_backed = self
                .votes
                .get(&addr)
                .map(|v| v.nets.len() >= MIN_OBSERVED_IP_VOTES)
                .unwrap_or(false);
            if !still_backed {
                self.confirmed = None;
            }
        }
    }
}

fn reporter_net24(ip: IpAddr) -> Option<[u8; 3]> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some([o[0], o[1], o[2]])
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            Some([o[0], o[1], o[2]])
        }
    }
}

fn is_public_vote_addr(addr: SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => is_public_v4(ip) && addr.port() != 0,
        // Do not accept IPv6 observed addresses for IPv4 external_ip voting.
        IpAddr::V6(_) => false,
    }
}

fn is_public_reporter(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                && !v6.is_unicast_link_local()
                // Unique local addresses (fc00::/7).
                && (v6.segments()[0] & 0xfe00) != 0xfc00
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    !crate::security::is_special_use_v4(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;

    fn addr(last: u8, port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, last), port))
    }

    fn reporter(a: u8, b: u8, c: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, 10))
    }

    #[test]
    fn confirms_after_three_distinct_slash24s() {
        let mut votes = EmberObservedIpVotes::new();
        let target = addr(50, 4672);
        assert!(votes.record_vote(target, reporter(203, 0, 1)).is_none());
        assert!(votes.record_vote(target, reporter(203, 0, 2)).is_none());
        assert!(votes.record_vote(target, reporter(203, 0, 1)).is_none());
        let confirmed = votes.record_vote(target, reporter(1, 1, 1));
        assert_eq!(confirmed, Some(target));
        assert_eq!(votes.confirmed(), Some(target));
    }

    #[test]
    fn rejects_private_reported_ip() {
        let mut votes = EmberObservedIpVotes::new();
        let private = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4672));
        assert!(votes.record_vote(private, reporter(8, 8, 8)).is_none());
        assert!(votes.confirmed().is_none());
    }

    #[test]
    fn rejects_private_reporter() {
        let mut votes = EmberObservedIpVotes::new();
        let target = addr(50, 4672);
        assert!(votes.record_vote(target, reporter(10, 0, 1)).is_none());
        assert!(votes.confirmed().is_none());
    }

    #[test]
    fn rejects_documentation_reported_ip() {
        let mut votes = EmberObservedIpVotes::new();
        let docs = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 50), 4672));
        assert!(votes.record_vote(docs, reporter(8, 8, 8)).is_none());
        assert!(votes.record_vote(docs, reporter(1, 1, 1)).is_none());
        assert!(votes.record_vote(docs, reporter(9, 9, 9)).is_none());
        assert!(votes.confirmed().is_none());
    }

    #[test]
    fn rejects_cgnat_reported_ip() {
        let mut votes = EmberObservedIpVotes::new();
        let cgnat = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 1), 4672));
        assert!(votes.record_vote(cgnat, reporter(8, 8, 8)).is_none());
        assert!(votes.confirmed().is_none());
    }

    #[test]
    fn rejects_ipv6_ula_reporter() {
        let mut votes = EmberObservedIpVotes::new();
        let target = addr(50, 4672);
        let ula: IpAddr = "fd12:3456:789a::1".parse().unwrap();
        assert!(votes.record_vote(target, ula).is_none());
    }

    #[test]
    fn rejects_ipv6_link_local_reporter() {
        let mut votes = EmberObservedIpVotes::new();
        let target = addr(50, 4672);
        let link_local: IpAddr = "fe80::1".parse().unwrap();
        assert!(votes.record_vote(target, link_local).is_none());
    }

    /// Re-confirming on every qualifying vote let whichever address was voted
    /// for most recently win, so a repeat vote could displace a correct
    /// confirmation.
    #[test]
    fn only_a_genuine_transition_confirms() {
        let mut votes = EmberObservedIpVotes::new();
        let target = addr(50, 4672);
        let now = Instant::now();

        assert!(votes
            .record_vote_at(target, reporter(203, 0, 1), now)
            .is_none());
        assert!(votes
            .record_vote_at(target, reporter(198, 51, 1), now)
            .is_none());
        assert_eq!(
            votes.record_vote_at(target, reporter(192, 0, 1), now),
            Some(target),
            "the third distinct /24 confirms"
        );
        assert_eq!(
            votes.record_vote_at(target, reporter(203, 0, 1), now),
            None,
            "a repeat vote for the already-confirmed address is not a transition"
        );
        assert_eq!(votes.confirmed(), Some(target));
    }

    /// A rival address that only ties the live quorum must not displace it.
    /// Three coordinated public nets used to overwrite `confirmed` on the
    /// spot, which is enough to move the external IP used for reachability
    /// and source advertise.
    #[test]
    fn a_tied_rival_quorum_does_not_displace_a_live_confirmation() {
        let mut votes = EmberObservedIpVotes::new();
        let current = addr(50, 4672);
        let rival = addr(51, 4672);
        let now = Instant::now();

        votes.record_vote_at(current, reporter(1, 0, 1), now);
        votes.record_vote_at(current, reporter(1, 1, 1), now);
        assert_eq!(
            votes.record_vote_at(current, reporter(1, 2, 1), now),
            Some(current)
        );

        votes.record_vote_at(rival, reporter(8, 8, 1), now);
        votes.record_vote_at(rival, reporter(8, 8, 2), now);
        assert_eq!(
            votes.record_vote_at(rival, reporter(9, 9, 1), now),
            None,
            "a 3-net rival must not overwrite a still-backed confirmation"
        );
        assert_eq!(votes.confirmed(), Some(current));

        assert_eq!(
            votes.record_vote_at(rival, reporter(4, 4, 1), now),
            Some(rival),
            "strictly more distinct nets may take over"
        );
        assert_eq!(votes.confirmed(), Some(rival));
    }

    /// Once the current confirmation's votes expire, a new address can
    /// confirm with a fresh three-net quorum — the genuine IP-change case.
    #[test]
    fn a_new_address_confirms_after_the_old_quorum_expires() {
        let mut votes = EmberObservedIpVotes::new();
        let first = addr(50, 4672);
        let second = addr(51, 4672);
        let t0 = Instant::now();

        votes.record_vote_at(first, reporter(1, 0, 1), t0);
        votes.record_vote_at(first, reporter(1, 1, 1), t0);
        assert_eq!(
            votes.record_vote_at(first, reporter(1, 2, 1), t0),
            Some(first)
        );

        let later = t0 + VOTE_TTL + Duration::from_secs(1);
        votes.record_vote_at(second, reporter(8, 8, 1), later);
        votes.record_vote_at(second, reporter(8, 8, 2), later);
        assert_eq!(
            votes.record_vote_at(second, reporter(9, 9, 1), later),
            Some(second),
            "after the old quorum lapses a new address may confirm"
        );
        assert_eq!(votes.confirmed(), Some(second));
    }

    /// The quorum has to be contemporaneous: three votes spread across hours
    /// say nothing about where we are reachable now.
    #[test]
    fn votes_expire_so_the_quorum_stays_current() {
        let mut votes = EmberObservedIpVotes::new();
        let target = addr(50, 4672);
        let t0 = Instant::now();

        votes.record_vote_at(target, reporter(203, 0, 1), t0);
        votes.record_vote_at(target, reporter(198, 51, 1), t0);

        // Long after the first two, a third vote must not complete a quorum
        // with votes that have since aged out.
        let later = t0 + VOTE_TTL + Duration::from_secs(1);
        assert_eq!(
            votes.record_vote_at(target, reporter(192, 0, 1), later),
            None,
            "stale votes must not count toward the quorum"
        );
        assert_eq!(votes.confirmed(), None);
    }

    /// The tracked-address cap must not be able to evict the address a live
    /// quorum has confirmed. `prune` reads that quorum out of `votes`, so
    /// dropping the entry retracts a confirmation nothing was wrong with — and
    /// it makes `current_count` read zero, so the very next three-net rival
    /// walks in, which is exactly what
    /// `a_tied_rival_quorum_does_not_displace_a_live_confirmation` forbids.
    #[test]
    fn the_address_cap_never_evicts_the_confirmed_address() {
        let mut votes = EmberObservedIpVotes::new();
        let current = addr(50, 4672);
        let rival = addr(51, 4672);
        let t0 = Instant::now();

        votes.record_vote_at(current, reporter(1, 0, 1), t0);
        votes.record_vote_at(current, reporter(1, 1, 1), t0);
        assert_eq!(
            votes.record_vote_at(current, reporter(1, 2, 1), t0),
            Some(current)
        );

        // Every filler is strictly newer, so the confirmed address is the LRU
        // victim on every insert once the map is full.
        let later = t0 + Duration::from_secs(1);
        for i in 0..(MAX_TRACKED_ADDRS as u16 * 2) {
            let filler = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 9, 1), 5000 + i));
            votes.record_vote_at(filler, reporter(2, 2, 2), later);
        }

        assert_eq!(
            votes.confirmed(),
            Some(current),
            "a live quorum must survive the tracked-address cap"
        );
        assert!(
            votes.votes.len() <= MAX_TRACKED_ADDRS,
            "and the cap still has to hold, tracking {}",
            votes.votes.len()
        );
        assert_eq!(
            votes.record_vote_at(rival, reporter(3, 0, 1), later),
            None,
            "nor may the eviction hand the address to a rival that only ties"
        );
        votes.record_vote_at(rival, reporter(3, 1, 1), later);
        assert_eq!(
            votes.record_vote_at(rival, reporter(3, 2, 1), later),
            None,
            "a 3-net rival must still be refused against a still-backed confirmation"
        );
        assert_eq!(votes.confirmed(), Some(current));
    }

    /// A peer answering with a different address each time must not grow the
    /// map without bound.
    #[test]
    fn the_vote_map_is_bounded() {
        let mut votes = EmberObservedIpVotes::new();
        let now = Instant::now();
        for i in 0..(MAX_TRACKED_ADDRS as u16 * 3) {
            let reported = SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(8, 8, 8, (i % 250) as u8 + 1),
                4000 + i,
            ));
            votes.record_vote_at(reported, reporter(1, 1, 1), now);
        }
        assert!(
            votes.votes.len() <= MAX_TRACKED_ADDRS,
            "tracked {} addresses, above the cap",
            votes.votes.len()
        );
    }
}
