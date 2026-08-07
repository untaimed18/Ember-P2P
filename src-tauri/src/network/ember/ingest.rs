//! Decisions Ember makes about EPX data that has arrived.
//!
//! The network task owns the *effects* of ingesting a source exchange —
//! writing to `SourceManager`, waking transfers, charging the connection
//! broker. What lives here is the part that decides, for one offered source,
//! whether it is worth having at all.
//!
//! It is a separate module because of how it has to be reached otherwise.
//! `handle_epx_sources` takes `&mut NetworkState`, a struct with well over a
//! hundred fields and live sockets behind several of them, so there is no
//! practical way to call it from a test — which is why the caps and filters it
//! applies had no direct coverage, despite being the boundary between a
//! hostile peer and our download list. Taking only the handful of facts a
//! decision actually depends on is the same move `record_known_ember_peer`
//! makes by accepting a `HashMap` rather than the whole state, and it buys the
//! same thing: the rules can be stated as tests.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use super::{SOURCE_FLAG_FIREWALLED, SOURCE_FLAG_RELAY_CAPABLE};
use crate::network::ed2k::dead_sources::DeadSourceList;
use crate::network::kad::ip_filter::IpFilter;

/// Why an offered EPX source was not injected into a download.
///
/// Named rather than a bare `bool` so the ingest path can say which rule
/// turned a source away: a peer feeding us junk and a peer offering good
/// sources we simply cannot reach look identical in a count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceRejection {
    /// The peer is firewalled, so are we, and it offered no relay path.
    NoRouteToFirewalledPeer,
    /// Our own address, handed back to us.
    SelfAddress,
    /// Already known not to answer for this file.
    KnownDead,
    /// Refused by the user's IP filter.
    IpFiltered,
    /// On the live banlist.
    Banned,
}

impl SourceRejection {
    /// Short, stable tag for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            SourceRejection::NoRouteToFirewalledPeer => "no-route-to-firewalled-peer",
            SourceRejection::SelfAddress => "self-address",
            SourceRejection::KnownDead => "known-dead",
            SourceRejection::IpFiltered => "ip-filtered",
            SourceRejection::Banned => "banned",
        }
    }
}

/// The facts one source decision depends on, borrowed from `NetworkState`.
///
/// Built per source at the call site rather than once per exchange: both
/// filters need `&mut` (each keeps hit counters), so holding this across the
/// injection that follows would conflict with the rest of the state.
pub struct SourceAdmission<'a> {
    /// True when we cannot accept an inbound connection — firewalled or LowID.
    /// A firewalled peer is then unreachable unless it offers a relay path.
    pub we_are_unreachable: bool,
    /// Our own external address, when known.
    pub external_ip: Option<Ipv4Addr>,
    pub dead_sources: &'a mut DeadSourceList,
    pub ip_filter: &'a mut IpFilter,
    pub banned_ips: &'a HashSet<Ipv4Addr>,
}

impl SourceAdmission<'_> {
    /// Whether this source is worth adding to the download for `file_hash`.
    ///
    /// Order decides only which reason is reported; a source refused by one
    /// rule would not become acceptable under a later one.
    pub fn check(
        &mut self,
        file_hash: &[u8; 16],
        ip: Ipv4Addr,
        port: u16,
        flags: u8,
    ) -> Result<(), SourceRejection> {
        // Two firewalled peers cannot reach each other. The relay-capable bit
        // keeps the source eligible for the KAD-callback broker path instead
        // of dropping it outright; the bit is advisory, so it buys the source
        // a chance at a relay, never a relay itself.
        if flags & SOURCE_FLAG_FIREWALLED != 0
            && self.we_are_unreachable
            && flags & SOURCE_FLAG_RELAY_CAPABLE == 0
        {
            return Err(SourceRejection::NoRouteToFirewalledPeer);
        }

        // EPX carries no provenance, so sources we advertise travel outward
        // and eventually come back pointing at us. Without this a download
        // dials itself.
        if Some(ip) == self.external_ip {
            return Err(SourceRejection::SelfAddress);
        }

        if self
            .dead_sources
            .is_dead_source_for_file(file_hash, u32::from(ip), port)
        {
            return Err(SourceRejection::KnownDead);
        }

        // `is_blocked` rather than the unconditional `is_special_use_v4`,
        // which would ignore the user's `block_private_ips` preference.
        if self.ip_filter.is_blocked(ip) {
            return Err(SourceRejection::IpFiltered);
        }

        if self.banned_ips.contains(&ip) {
            return Err(SourceRejection::Banned);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: [u8; 16] = [7u8; 16];

    /// A permissive baseline: reachable node, filter off, nothing banned.
    struct Fixture {
        dead: DeadSourceList,
        filter: IpFilter,
        banned: HashSet<Ipv4Addr>,
        unreachable: bool,
        external_ip: Option<Ipv4Addr>,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                dead: DeadSourceList::new(),
                filter: IpFilter::new(false, false),
                banned: HashSet::new(),
                unreachable: false,
                external_ip: None,
            }
        }

        fn check(&mut self, ip: Ipv4Addr, flags: u8) -> Result<(), SourceRejection> {
            SourceAdmission {
                we_are_unreachable: self.unreachable,
                external_ip: self.external_ip,
                dead_sources: &mut self.dead,
                ip_filter: &mut self.filter,
                banned_ips: &self.banned,
            }
            .check(&FILE, ip, 4662, flags)
        }
    }

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(80, 1, 1, last)
    }

    #[test]
    fn an_ordinary_source_is_admitted() {
        let mut f = Fixture::new();
        assert_eq!(f.check(ip(10), 0), Ok(()));
    }

    /// Two firewalled peers have no path to each other, so such a source is
    /// only worth keeping if something can bridge it.
    #[test]
    fn a_firewalled_peer_is_refused_only_when_we_are_also_unreachable() {
        let mut f = Fixture::new();
        assert_eq!(
            f.check(ip(11), SOURCE_FLAG_FIREWALLED),
            Ok(()),
            "reachable ourselves, so the peer can dial us"
        );

        f.unreachable = true;
        assert_eq!(
            f.check(ip(11), SOURCE_FLAG_FIREWALLED),
            Err(SourceRejection::NoRouteToFirewalledPeer)
        );
    }

    /// The relay-capable bit keeps a firewalled source alive for the broker
    /// rather than admitting a relay, which only a verified ERAT can do.
    #[test]
    fn a_relay_capable_firewalled_peer_survives_for_the_broker() {
        let mut f = Fixture::new();
        f.unreachable = true;
        assert_eq!(
            f.check(ip(12), SOURCE_FLAG_FIREWALLED | SOURCE_FLAG_RELAY_CAPABLE),
            Ok(())
        );
    }

    /// Sources propagate peer to peer with no record of origin, so one
    /// eventually arrives back pointing at us.
    #[test]
    fn our_own_address_is_refused() {
        let mut f = Fixture::new();
        f.external_ip = Some(ip(20));
        assert_eq!(f.check(ip(20), 0), Err(SourceRejection::SelfAddress));
        assert_eq!(f.check(ip(21), 0), Ok(()), "a neighbour is still fine");
    }

    /// Not knowing our own address must not turn into refusing everything.
    #[test]
    fn an_unknown_external_address_refuses_nothing() {
        let mut f = Fixture::new();
        f.external_ip = None;
        assert_eq!(f.check(ip(22), 0), Ok(()));
    }

    #[test]
    fn a_banned_address_is_refused() {
        let mut f = Fixture::new();
        f.banned.insert(ip(30));
        assert_eq!(f.check(ip(30), 0), Err(SourceRejection::Banned));
    }

    /// A private address is admissible only while the user allows it, which is
    /// why this consults the filter rather than a fixed special-use test.
    #[test]
    fn private_addresses_follow_the_users_filter_setting() {
        let lan = Ipv4Addr::new(192, 168, 1, 50);

        let mut allowed = Fixture::new();
        assert_eq!(allowed.check(lan, 0), Ok(()));

        let mut blocked = Fixture::new();
        blocked.filter = IpFilter::new(true, true);
        assert_eq!(blocked.check(lan, 0), Err(SourceRejection::IpFiltered));
    }

    /// A source proven not to answer for this file is not worth re-adding
    /// every time some peer mentions it again.
    #[test]
    fn a_known_dead_source_is_refused() {
        let mut f = Fixture::new();
        let addr = ip(40);
        assert_eq!(f.check(addr, 0), Ok(()), "unknown until it fails");

        f.dead.add_dead_source_for_file(FILE, u32::from(addr), 4662);
        assert_eq!(f.check(addr, 0), Err(SourceRejection::KnownDead));
    }

    /// Death is scoped to the file it was observed on: the same host may well
    /// be serving something else perfectly happily.
    #[test]
    fn a_dead_source_for_one_file_is_still_offered_for_another() {
        let mut f = Fixture::new();
        let addr = ip(41);
        f.dead.add_dead_source_for_file(FILE, u32::from(addr), 4662);

        let other = [9u8; 16];
        let verdict = SourceAdmission {
            we_are_unreachable: false,
            external_ip: None,
            dead_sources: &mut f.dead,
            ip_filter: &mut f.filter,
            banned_ips: &f.banned,
        }
        .check(&other, addr, 4662, 0);
        assert_eq!(verdict, Ok(()));
    }
}
