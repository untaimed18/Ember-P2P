//! Observed-IP voting for Ember DHT (slice 19).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub const MIN_OBSERVED_IP_VOTES: usize = 3;

#[derive(Debug, Default)]
pub struct EmberObservedIpVotes {
    votes: HashMap<SocketAddr, HashSet<[u8; 3]>>,
    confirmed: Option<SocketAddr>,
}

impl EmberObservedIpVotes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn confirmed(&self) -> Option<SocketAddr> {
        self.confirmed
    }

    pub fn record_vote(
        &mut self,
        reported: SocketAddr,
        reporter: IpAddr,
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

        let entry = self.votes.entry(reported).or_default();
        entry.insert(net);
        if entry.len() >= MIN_OBSERVED_IP_VOTES {
            let newly = self.confirmed != Some(reported);
            self.confirmed = Some(reported);
            if newly {
                return Some(reported);
            }
        }
        None
    }

    pub fn vote_count(&self, addr: &SocketAddr) -> usize {
        self.votes.get(addr).map(|s| s.len()).unwrap_or(0)
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
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_broadcast()
        && !ip.is_unspecified()
        && !ip.is_multicast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;

    fn addr(last: u8, port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, last), port))
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
        let confirmed = votes.record_vote(target, reporter(198, 51, 100));
        assert_eq!(confirmed, Some(target));
        assert_eq!(votes.confirmed(), Some(target));
    }

    #[test]
    fn rejects_private_reported_ip() {
        let mut votes = EmberObservedIpVotes::new();
        let private = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4672));
        assert!(votes.record_vote(private, reporter(203, 0, 113)).is_none());
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
}
