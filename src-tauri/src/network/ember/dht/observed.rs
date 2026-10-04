//! Observed-IP voting for Ember DHT (slice 19).
//!
//! The quorum is on the IP alone. A NAT that picks a fresh external port per
//! destination shows every reporter a different port, so a quorum on `ip:port`
//! would never form for exactly the hosts that most need to learn their address
//! from peers. The port rides along as the most-reported one, and callers that
//! would use it can ask whether it has a quorum of its own.

use std::collections::{HashMap, HashSet};
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

/// Distinct reported IPs tracked at once. Every entry costs memory and a peer
/// can report a different address on each reply, so the map is capped and the
/// least-recently-updated entry is dropped.
const MAX_TRACKED_ADDRS: usize = 64;

/// Reporter nets remembered as having voted for the confirmed address, the
/// most recent kept when there are more. Keeping the first ones instead left a
/// long uptime remembering only the nets of its first hours, which are not the
/// peers that see the address move.
const MAX_TRACKED_BACKERS: usize = 256;

/// The diversity unit one vote is charged to.
///
/// Deliberately family-tagged rather than a bare byte array. The two widths
/// differ, and a shared array would let an IPv6 prefix whose leading bytes
/// happen to read as an IPv4 /24 share that /24's single vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ReporterNet {
    /// IPv4 /24.
    V4([u8; 3]),
    /// IPv6 /48 — the same unit [`super::EmberContact::subnet_key`] uses, and
    /// the smallest block routinely assigned to one site. Charging the first
    /// three *bytes* instead, as this once did, is a /24 of IPv6: it folds
    /// unrelated networks onto one key, so honest reporters spread across a
    /// region count as a single vote and a genuine address change struggles to
    /// reach quorum.
    V6([u8; 6]),
}

#[derive(Debug, Default)]
struct AddrVotes {
    /// Reporter network → when it last voted for this IP, and the port it saw.
    /// One entry per net, so a net that sees a new port moves its vote rather
    /// than casting a second one.
    nets: HashMap<ReporterNet, (Instant, u16)>,
    last_update: Option<Instant>,
}

impl AddrVotes {
    /// The port the most reporter nets saw, and how many saw it. A tie goes to
    /// `incumbent` when it is one of the tied ports — the same rule the IP
    /// quorum applies, so coordinated nets that only match the honest count
    /// cannot move the port — and otherwise to the port voted for most
    /// recently.
    fn leading_port(&self, incumbent: Option<u16>) -> Option<(u16, usize)> {
        let mut tally: HashMap<u16, (usize, Instant)> = HashMap::new();
        for (at, port) in self.nets.values() {
            let entry = tally.entry(*port).or_insert((0, *at));
            entry.0 += 1;
            entry.1 = entry.1.max(*at);
        }
        tally
            .into_iter()
            .max_by_key(|(port, (count, at))| (*count, Some(*port) == incumbent, *at))
            .map(|(port, (count, _))| (port, count))
    }

    fn votes_for_port(&self, port: u16) -> usize {
        self.nets.values().filter(|(_, p)| *p == port).count()
    }
}

/// A confirmation that lapsed for want of fresh votes.
#[derive(Debug)]
struct LapsedConfirmation {
    addr: IpAddr,
    /// The most distinct nets that backed it at once.
    peak: usize,
    /// The nets that voted for it while it stood.
    backers: HashSet<ReporterNet>,
    at: Instant,
}

#[derive(Debug, Default)]
pub struct EmberObservedIpVotes {
    votes: HashMap<IpAddr, AddrVotes>,
    confirmed: Option<IpAddr>,
    /// The port [`Self::confirmed`] reports, re-read after every vote and prune
    /// with itself as the incumbent.
    confirmed_port: Option<u16>,
    /// The most distinct nets that backed [`Self::confirmed`] at once.
    confirmed_peak: usize,
    /// The nets that have voted for [`Self::confirmed`] while it stood, and
    /// when each last did, up to [`MAX_TRACKED_BACKERS`].
    confirmed_backers: HashMap<ReporterNet, Instant>,
    /// The last confirmation to lapse, for one vote lifetime.
    ///
    /// Honest peers that talk to us constantly rarely need to ask, so their
    /// votes age out, while a quiet peer we ping votes every time. Counting a
    /// lapsed incumbent as zero let any three /24s take the address over at
    /// that moment, so a rival has to beat its peak instead — unless a quorum
    /// of the rival's nets are ones that backed the lapsed address. That is
    /// what a genuine address change looks like, the same peers now seeing us
    /// somewhere else, and on a network with no more nets than the old peak it
    /// is the only way the change can confirm before the lapse ages out.
    lapsed: Option<LapsedConfirmation>,
}

impl EmberObservedIpVotes {
    pub fn new() -> Self {
        Self::default()
    }

    /// The confirmed IP with the port most reporters saw on it.
    pub fn confirmed(&self) -> Option<SocketAddr> {
        Some(SocketAddr::new(self.confirmed?, self.confirmed_port?))
    }

    /// Whether the port [`Self::confirmed`] reports has a quorum of its own.
    ///
    /// False behind a NAT that maps a fresh port per destination: the IP is
    /// agreed, but the port is only the most common of several and says
    /// nothing about where a new peer's packets would land. It can turn true
    /// on a later vote without the confirmed IP moving, so a caller waiting on
    /// the port has to ask again rather than rely on the transition
    /// [`Self::record_vote`] reports.
    pub fn confirmed_port_has_quorum(&self) -> bool {
        match (self.confirmed.and_then(|ip| self.votes.get(&ip)), self.confirmed_port) {
            (Some(votes), Some(port)) => votes.votes_for_port(port) >= MIN_OBSERVED_IP_VOTES,
            _ => false,
        }
    }

    fn refresh_confirmed_port(&mut self) {
        self.confirmed_port = self
            .confirmed
            .and_then(|ip| self.votes.get(&ip))
            .and_then(|v| v.leading_port(self.confirmed_port))
            .map(|(port, _)| port);
    }

    pub fn record_vote(&mut self, reported: SocketAddr, reporter: IpAddr) -> Option<SocketAddr> {
        self.record_vote_at(reported, reporter, Instant::now())
    }

    /// `record_vote` with an explicit clock, so the expiry window is testable.
    ///
    /// Returns the newly confirmed address when this vote moves the confirmed
    /// IP; see [`Self::confirmed`] for the port it carries.
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
        let net = reporter_net(reporter)?;
        let reported_ip = reported.ip();

        self.prune(now);

        if self.votes.len() >= MAX_TRACKED_ADDRS && !self.votes.contains_key(&reported_ip) {
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
            let entry = self.votes.entry(reported_ip).or_default();
            entry.nets.insert(net, (now, reported.port()));
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
        if self.confirmed == Some(reported_ip) {
            self.confirmed_peak = self.confirmed_peak.max(new_count);
            if self.confirmed_backers.len() >= MAX_TRACKED_BACKERS
                && !self.confirmed_backers.contains_key(&net)
            {
                let oldest = self
                    .confirmed_backers
                    .iter()
                    .min_by_key(|(_, at)| **at)
                    .map(|(n, _)| *n);
                if let Some(oldest) = oldest {
                    self.confirmed_backers.remove(&oldest);
                }
            }
            self.confirmed_backers.insert(net, now);
        }
        if quorum && self.confirmed != Some(reported_ip) {
            let rival_nets = || {
                self.votes
                    .get(&reported_ip)
                    .into_iter()
                    .flat_map(|v| v.nets.iter())
                    .map(|(net, (at, _))| (*net, *at))
            };
            let displaces = match self.confirmed {
                Some(ip) => new_count > self.votes.get(&ip).map_or(0, |v| v.nets.len()),
                None => match self.lapsed.as_ref().filter(|l| l.addr != reported_ip) {
                    None => true,
                    Some(lapsed) => {
                        new_count > lapsed.peak
                            || rival_nets().filter(|(n, _)| lapsed.backers.contains(n)).count()
                                >= MIN_OBSERVED_IP_VOTES
                    }
                },
            };
            if displaces {
                self.confirmed_backers = rival_nets().take(MAX_TRACKED_BACKERS).collect();
                self.confirmed = Some(reported_ip);
                self.confirmed_port = None;
                self.confirmed_peak = new_count;
                self.lapsed = None;
                self.refresh_confirmed_port();
                return self.confirmed();
            }
        }
        self.refresh_confirmed_port();
        None
    }

    /// Drop votes and addresses that have aged out.
    fn prune(&mut self, now: Instant) {
        self.votes.retain(|_, v| {
            v.nets
                .retain(|_, (at, _)| now.saturating_duration_since(*at) < VOTE_TTL);
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
                self.lapsed = Some(LapsedConfirmation {
                    addr,
                    peak: self.confirmed_peak,
                    backers: std::mem::take(&mut self.confirmed_backers).into_keys().collect(),
                    at: now,
                });
                self.confirmed_peak = 0;
            }
        }
        if self
            .lapsed
            .as_ref()
            .is_some_and(|l| now.saturating_duration_since(l.at) >= VOTE_TTL)
        {
            self.lapsed = None;
        }
        self.refresh_confirmed_port();
    }
}

fn reporter_net(ip: IpAddr) -> Option<ReporterNet> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(ReporterNet::V4([o[0], o[1], o[2]]))
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            Some(ReporterNet::V6([o[0], o[1], o[2], o[3], o[4], o[5]]))
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

        // Just after the lapse a rival has to beat the old peak of three.
        let later = t0 + VOTE_TTL + Duration::from_secs(1);
        votes.record_vote_at(second, reporter(8, 8, 1), later);
        votes.record_vote_at(second, reporter(8, 8, 2), later);
        assert_eq!(
            votes.record_vote_at(second, reporter(9, 9, 1), later),
            None,
            "three nets only tie the lapsed incumbent"
        );
        assert_eq!(
            votes.record_vote_at(second, reporter(9, 9, 2), later),
            Some(second),
            "four beat it"
        );
        assert_eq!(votes.confirmed(), Some(second));

        // Once the lapse is a vote lifetime old, an ordinary quorum is enough.
        let mut votes = EmberObservedIpVotes::new();
        votes.record_vote_at(first, reporter(1, 0, 1), t0);
        votes.record_vote_at(first, reporter(1, 1, 1), t0);
        votes.record_vote_at(first, reporter(1, 2, 1), t0);
        let lapse = t0 + VOTE_TTL + Duration::from_secs(1);
        votes.record_vote_at(second, reporter(8, 8, 1), lapse);
        let much_later = lapse + VOTE_TTL + Duration::from_secs(1);
        votes.record_vote_at(second, reporter(8, 8, 2), much_later);
        votes.record_vote_at(second, reporter(8, 8, 3), much_later);
        assert_eq!(
            votes.record_vote_at(second, reporter(9, 9, 1), much_later),
            Some(second)
        );
    }

    /// On a network with no more nets than the old peak nothing can beat it,
    /// so a genuine address change sat unconfirmed until the lapse aged out.
    /// The peers that used to see us at the old address now reporting the new
    /// one is that change, and confirms it; strangers are still held to the
    /// peak.
    #[test]
    fn the_old_addresss_own_reporters_move_it_without_waiting_out_the_lapse() {
        let mut votes = EmberObservedIpVotes::new();
        let first = addr(50, 4672);
        let second = addr(51, 4672);
        let t0 = Instant::now();
        for net in 0..4u8 {
            votes.record_vote_at(first, reporter(1, net, 1), t0);
        }
        assert_eq!(votes.confirmed(), Some(first));

        let later = t0 + VOTE_TTL + Duration::from_secs(1);
        votes.record_vote_at(second, reporter(1, 0, 1), later);
        votes.record_vote_at(second, reporter(1, 1, 1), later);
        assert_eq!(votes.confirmed(), None, "the old address has lapsed");
        assert_eq!(
            votes.record_vote_at(second, reporter(1, 2, 1), later),
            Some(second),
            "three of its four reporters moved, which a peak of four cannot outvote"
        );

        let mut votes = EmberObservedIpVotes::new();
        for net in 0..4u8 {
            votes.record_vote_at(first, reporter(1, net, 1), t0);
        }
        votes.record_vote_at(second, reporter(1, 0, 1), later);
        votes.record_vote_at(second, reporter(1, 1, 1), later);
        assert_eq!(
            votes.record_vote_at(second, reporter(8, 8, 1), later),
            None,
            "two former reporters and a stranger are not a quorum of them"
        );
        votes.record_vote_at(second, reporter(8, 8, 2), later);
        assert_eq!(
            votes.record_vote_at(second, reporter(8, 8, 3), later),
            Some(second),
            "but five nets beat the peak of four"
        );
    }

    /// The backers list used to keep the first nets that voted and nothing
    /// after them, so once a long uptime had filled it the peers still talking
    /// to us when the address moved were not in it, and the shortcut above
    /// never fired.
    #[test]
    fn the_former_reporters_are_the_most_recent_ones() {
        let mut votes = EmberObservedIpVotes::new();
        let first = addr(50, 4672);
        let second = addr(51, 4672);
        let t0 = Instant::now();
        for net in 0..=255u8 {
            votes.record_vote_at(first, reporter(1, net, 1), t0);
        }
        assert_eq!(votes.confirmed(), Some(first));

        // Long after those voted, the peers we talk to now keep it confirmed.
        let mid = t0 + VOTE_TTL / 2;
        for net in 0..3u8 {
            votes.record_vote_at(first, reporter(2, net, 1), mid);
        }
        let later = t0 + VOTE_TTL + Duration::from_secs(1);
        votes.record_vote_at(first, reporter(2, 0, 1), later);
        assert_eq!(votes.confirmed(), Some(first), "still backed by the newer nets");

        // Then the address moves and those same peers report the new one.
        let moved = mid + VOTE_TTL + Duration::from_secs(1);
        votes.record_vote_at(second, reporter(2, 1, 1), moved);
        votes.record_vote_at(second, reporter(2, 2, 1), moved);
        assert_eq!(votes.confirmed(), None, "the old address has lapsed");
        assert_eq!(
            votes.record_vote_at(second, reporter(2, 0, 1), moved),
            Some(second),
            "three of the peers that backed it most recently moved it"
        );
    }

    /// The incumbent that lapsed is not held to its own bar: its peers voting
    /// again restore it.
    #[test]
    fn a_lapsed_incumbent_reconfirms_on_its_own_votes() {
        let mut votes = EmberObservedIpVotes::new();
        let first = addr(50, 4672);
        let t0 = Instant::now();
        votes.record_vote_at(first, reporter(1, 0, 1), t0);
        votes.record_vote_at(first, reporter(1, 1, 1), t0);
        votes.record_vote_at(first, reporter(1, 2, 1), t0);
        let later = t0 + VOTE_TTL + Duration::from_secs(1);
        votes.record_vote_at(first, reporter(1, 0, 1), later);
        votes.record_vote_at(first, reporter(1, 1, 1), later);
        assert_eq!(votes.record_vote_at(first, reporter(1, 2, 1), later), Some(first));
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
        for i in 0..(MAX_TRACKED_ADDRS as u8 * 2) {
            let filler = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 9, i + 1), 5000));
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

    /// IPv6 reporters are charged a /48, the unit `EmberContact::subnet_key`
    /// uses and the smallest block routinely assigned to one site. Charging the
    /// first three *bytes* — a /24 of IPv6 — folded unrelated networks onto one
    /// key, so three genuinely independent reporters counted as one and a real
    /// address change could not reach quorum.
    #[test]
    fn ipv6_reporters_are_distinguished_at_a_48() {
        let mut votes = EmberObservedIpVotes::new();
        let target = addr(50, 4672);
        let now = Instant::now();

        // Three distinct /48s that share their first three bytes, which is what
        // the old key looked at.
        let nets: [IpAddr; 3] = [
            "2001:db8:1::1".parse().unwrap(),
            "2001:db8:2::1".parse().unwrap(),
            "2001:db8:3::1".parse().unwrap(),
        ];
        assert!(votes.record_vote_at(target, nets[0], now).is_none());
        assert!(votes.record_vote_at(target, nets[1], now).is_none());
        assert_eq!(
            votes.record_vote_at(target, nets[2], now),
            Some(target),
            "three distinct /48s are three votes, not one"
        );

        // And two addresses inside one /48 remain a single vote.
        let mut same_site = EmberObservedIpVotes::new();
        let other = addr(51, 4672);
        for host in ["2001:db8:9::1", "2001:db8:9::2", "2001:db8:9:ffff::3"] {
            assert!(same_site
                .record_vote_at(other, host.parse().unwrap(), now)
                .is_none());
        }
        assert_eq!(
            same_site.confirmed(),
            None,
            "one site cannot reach quorum by itself, however many hosts it uses"
        );
    }

    /// The two families are separate key spaces. Sharing one byte array would
    /// let an IPv6 prefix whose leading bytes read as an IPv4 /24 be charged to
    /// that /24's single vote.
    #[test]
    fn an_ipv6_prefix_does_not_collide_with_the_ipv4_slash24_it_reads_as() {
        let mut votes = EmberObservedIpVotes::new();
        let target = addr(50, 4672);
        let now = Instant::now();

        // 32.1.13.x as IPv4, and an IPv6 address whose first three bytes are
        // the same 20 01 0d.
        votes.record_vote_at(target, IpAddr::from([32, 1, 13, 10]), now);
        votes.record_vote_at(target, "2001:d00::1".parse().unwrap(), now);
        assert_eq!(
            votes.confirmed(),
            None,
            "two reporters are two votes, not a quorum"
        );
        assert_eq!(
            votes.record_vote_at(target, reporter(9, 9, 9), now),
            Some(target),
            "and they did count as two distinct nets, so a third completes it"
        );
    }

    /// A NAT that maps a fresh port per destination shows each reporter a
    /// different port. A quorum keyed on `ip:port` never formed for those
    /// hosts, though every reporter agreed on the IP.
    #[test]
    fn a_port_randomising_nat_still_confirms_its_ip() {
        let mut votes = EmberObservedIpVotes::new();
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1);
        let t2 = t1 + Duration::from_secs(1);
        assert!(votes.record_vote_at(addr(50, 40001), reporter(1, 0, 1), t0).is_none());
        assert!(votes.record_vote_at(addr(50, 40002), reporter(1, 1, 1), t1).is_none());
        let confirmed = votes
            .record_vote_at(addr(50, 40003), reporter(1, 2, 1), t2)
            .expect("three nets agree on the IP");
        assert_eq!(confirmed.ip(), addr(50, 0).ip());
        assert_eq!(confirmed.port(), 40003, "a tie goes to the latest port");
        assert!(
            !votes.confirmed_port_has_quorum(),
            "but no port was seen by a quorum, so none is vouched for"
        );
    }

    /// The port rides along as the one most nets saw, and earns a quorum of its
    /// own once enough of them agree on it. A net that sees a new port moves
    /// its vote rather than casting a second one.
    #[test]
    fn the_confirmed_port_is_the_most_reported_one() {
        let mut votes = EmberObservedIpVotes::new();
        let now = Instant::now();
        votes.record_vote_at(addr(50, 4672), reporter(1, 0, 1), now);
        votes.record_vote_at(addr(50, 4672), reporter(1, 1, 1), now);
        assert_eq!(
            votes.record_vote_at(addr(50, 9999), reporter(1, 2, 1), now),
            Some(addr(50, 4672)),
        );
        assert!(!votes.confirmed_port_has_quorum());

        votes.record_vote_at(addr(50, 4672), reporter(1, 3, 1), now);
        assert_eq!(votes.confirmed(), Some(addr(50, 4672)));
        assert!(votes.confirmed_port_has_quorum());

        // Two of the 4672 nets move to 9999: one vote each, not two.
        let later = now + Duration::from_secs(1);
        votes.record_vote_at(addr(50, 9999), reporter(1, 0, 1), later);
        votes.record_vote_at(addr(50, 9999), reporter(1, 1, 1), later);
        assert_eq!(votes.confirmed(), Some(addr(50, 9999)));
        assert!(votes.confirmed_port_has_quorum());
        assert_eq!(votes.votes[&addr(50, 0).ip()].nets.len(), 4);
    }

    /// Nets that only match the honest count for another port must not move
    /// the port, any more than a tied rival may move the IP.
    #[test]
    fn a_tied_rival_port_does_not_displace_the_confirmed_one() {
        let mut votes = EmberObservedIpVotes::new();
        let now = Instant::now();
        for net in 0..3u8 {
            votes.record_vote_at(addr(50, 4672), reporter(1, net, 1), now);
        }
        assert!(votes.confirmed_port_has_quorum());

        let later = now + Duration::from_secs(1);
        for net in 0..3u8 {
            votes.record_vote_at(addr(50, 9999), reporter(8, net, 1), later);
        }
        assert_eq!(votes.confirmed(), Some(addr(50, 4672)), "a tie keeps the incumbent");

        votes.record_vote_at(addr(50, 9999), reporter(8, 3, 1), later);
        assert_eq!(votes.confirmed(), Some(addr(50, 9999)), "strictly more nets move it");
    }

    /// The IP can confirm on a vote whose port has no quorum yet. The port
    /// earning one later is not a transition of the IP, so it has to be
    /// readable without one.
    #[test]
    fn the_port_can_earn_its_quorum_after_the_ip_confirmed() {
        let mut votes = EmberObservedIpVotes::new();
        let now = Instant::now();
        votes.record_vote_at(addr(50, 4672), reporter(1, 0, 1), now);
        votes.record_vote_at(addr(50, 5000), reporter(1, 1, 1), now);
        assert_eq!(
            votes.record_vote_at(addr(50, 4672), reporter(1, 2, 1), now),
            Some(addr(50, 4672))
        );
        assert!(!votes.confirmed_port_has_quorum());

        assert_eq!(votes.record_vote_at(addr(50, 4672), reporter(1, 3, 1), now), None);
        assert!(votes.confirmed_port_has_quorum());
        assert_eq!(votes.confirmed(), Some(addr(50, 4672)));
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
