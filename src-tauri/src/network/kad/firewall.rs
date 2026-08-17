use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use tracing::{debug, info};

/// Minimum unique IPs needed to confirm external IP
const MIN_IP_VOTES: usize = 3;
/// Number of firewall check requests to send per cycle.
/// Higher than eMule's default (4) because some contacts won't respond to
/// FirewalledReq if their RequestTCP fails on their end.
const FIREWALL_CHECK_COUNT: u32 = 8;
/// Maximum UDP firewall probes to send across all batches in a single cycle.
/// Each batch picks a few contacts; the Pong handler and periodic tick can
/// dispatch additional batches until this cap is reached.  Set high because
/// many KAD contacts have firewalled TCP and probes require TCP.
const MAX_UDP_FIREWALL_PROBES: u32 = 12;
/// Recheck interval (1 hour)
pub const FIREWALL_RECHECK_SECS: i64 = 3600;
/// How long to wait for firewall responses before concluding
const RESPONSE_WINDOW_SECS: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallStatus {
    Unknown,
    Open,
    Firewalled,
}

pub struct FirewallChecker {
    /// Per-reported-IP: set of /24 networks of the voters who reported it.
    /// K7: counting raw votes lets a Sybil cluster (or one attacker with
    /// many spoofed source IPs) dominate external-IP confirmation.
    /// Counting distinct /24s raises the bar — at least 3 different
    /// networks must agree before we trust the reported IP.
    external_ip_votes: HashMap<Ipv4Addr, HashSet<[u8; 3]>>,
    confirmed_external_ip: Option<Ipv4Addr>,
    tcp_status: FirewallStatus,
    udp_status: FirewallStatus,
    tcp_responses_received: u32,
    tcp_requests_sent: u32,
    udp_firewall_responses_received: u32,
    udp_requests_sent: u32,
    last_check_start: i64,
    external_udp_port: Option<u16>,
    /// Per-reported-UDP-port: set of /24 networks of the voters who reported
    /// it. Same distinct-/24 weighting as `external_ip_votes` (K7) so a
    /// single-subnet Sybil cluster can't bias our perceived external UDP port.
    udp_port_votes: HashMap<u16, HashSet<[u8; 3]>>,
    checking: bool,
    /// IPs we sent FirewalledReq to (eMule: IsKadFirewallCheckIP).
    /// Only accept FirewalledRes from these IPs to prevent spoofing.
    pending_check_ips: HashSet<Ipv4Addr>,
    /// IPs we sent TCP-side UDP firewall probes to (eMule UDPFirewallTester).
    pending_udp_check_ips: HashSet<Ipv4Addr>,
    udp_firewall_succeeded: bool,
}

impl FirewallChecker {
    pub fn new() -> Self {
        Self {
            external_ip_votes: HashMap::new(),
            confirmed_external_ip: None,
            tcp_status: FirewallStatus::Unknown,
            udp_status: FirewallStatus::Unknown,
            tcp_responses_received: 0,
            tcp_requests_sent: 0,
            udp_firewall_responses_received: 0,
            udp_requests_sent: 0,
            last_check_start: 0,
            external_udp_port: None,
            udp_port_votes: HashMap::new(),
            checking: false,
            pending_check_ips: HashSet::new(),
            pending_udp_check_ips: HashSet::new(),
            udp_firewall_succeeded: false,
        }
    }

    pub fn is_checking(&self) -> bool {
        self.checking
    }

    pub fn start_check(&mut self) {
        let now = chrono::Utc::now().timestamp();
        self.checking = true;
        self.last_check_start = now;
        self.tcp_responses_received = 0;
        self.tcp_requests_sent = 0;
        self.udp_firewall_responses_received = 0;
        self.udp_requests_sent = 0;
        self.pending_check_ips.clear();
        self.pending_udp_check_ips.clear();
        self.udp_firewall_succeeded = false;
        // Clear IP votes so a new check cycle can detect external IP changes.
        self.external_ip_votes.clear();
        // Also drop the previously confirmed IP so this cycle must re-confirm
        // it. Without this a changed external IP (new ISP lease, reconnect)
        // could stick forever: KAD votes only fill `state.external_ip` when it
        // is still unset, so a stale KAD confirmation that never reaches the
        // 3-distinct-/24 threshold again would never replace a previous vote.
        // HighID/STUN remain authoritative and are not blanked here.
        // Consumers (`external_ip()`) only ever overwrite `state.external_ip`
        // on a fresh confirmation when it is still `None`, so the last-known
        // IP is retained during the ~30s re-confirmation window.
        self.confirmed_external_ip = None;
        // Preserve external_udp_port from previous cycle so UDP firewall
        // probes can be dispatched immediately without waiting for new pongs.
        // Port votes are cleared so pongs from this cycle can refine it.
        self.udp_port_votes.clear();
        info!(
            "Starting firewall check cycle (current TCP={:?}, UDP={:?}, ext_udp={:?})",
            self.tcp_status, self.udp_status, self.external_udp_port
        );
    }

    pub fn record_tcp_request_sent(&mut self, peer_ip: Ipv4Addr) {
        self.tcp_requests_sent += 1;
        self.pending_check_ips.insert(peer_ip);
    }

    pub fn record_udp_firewall_request_sent(&mut self, peer_ip: Ipv4Addr) {
        self.udp_requests_sent += 1;
        self.pending_udp_check_ips.insert(peer_ip);
    }

    /// Pings are only used to learn the external UDP port. They do not prove
    /// whether we are UDP-firewalled.
    pub fn record_udp_port_probe_sent(&mut self) {}

    pub fn is_udp_firewall_check_ip(&self, ip: Ipv4Addr) -> bool {
        self.pending_udp_check_ips.contains(&ip)
    }

    /// Validate that a FirewalledRes came from a peer we actually sent a
    /// FirewalledReq to (eMule: IsKadFirewallCheckIP).
    pub fn is_firewall_check_ip(&self, ip: Ipv4Addr) -> bool {
        self.pending_check_ips.contains(&ip)
    }

    /// Handle KADEMLIA_FIREWALLED_RES: a peer reports our external IP.
    /// This message arrives via UDP, so it only proves UDP connectivity --
    /// it does NOT indicate TCP is open (the separate TCP connect-back does).
    /// The caller must validate the sender via is_firewall_check_ip() first
    /// and pass the reporter's source IP so we can enforce distinct-voter
    /// (distinct-/24) confirmation.
    pub fn handle_firewalled_response(&mut self, reported_ip: Ipv4Addr, reporter: Ipv4Addr) {
        if crate::security::is_special_use_v4(reported_ip) {
            debug!("Ignoring private/reserved external IP vote: {reported_ip}");
            return;
        }
        // K7: require votes from distinct /24 networks. Sybil clusters
        // (one attacker holding many IPs in the same /24, spoofed source
        // IPs in a single subnet) can no longer set our external IP.
        let reporter_octets = reporter.octets();
        let reporter_net: [u8; 3] = [reporter_octets[0], reporter_octets[1], reporter_octets[2]];
        self.external_ip_votes
            .entry(reported_ip)
            .or_default()
            .insert(reporter_net);

        let best_ip = self
            .external_ip_votes
            .iter()
            .max_by_key(|(_, nets)| nets.len())
            .map(|(&ip, _)| ip);

        if let Some(ip) = best_ip {
            let distinct_nets = self.external_ip_votes[&ip].len();
            if distinct_nets >= MIN_IP_VOTES {
                if self.confirmed_external_ip != Some(ip) {
                    // Keep the milestone at info but the user's own public IP at
                    // debug — logs (and support bundles) shouldn't deanonymize the
                    // local node by default. Mirrors rendezvous.rs.
                    info!("External IP confirmed ({distinct_nets} distinct-/24 votes)");
                    debug!("Confirmed external IP: {ip}");
                }
                self.confirmed_external_ip = Some(ip);
            }
        }

        if self.external_ip_votes.len() > 1 {
            let tally: Vec<String> = self
                .external_ip_votes
                .iter()
                .map(|(ip, nets)| format!("{}={}", ip, nets.len()))
                .collect();
            // Keep the disagreement signal (possible spoof/Sybil) at info, but the
            // candidate IPs themselves at debug.
            info!(
                "External IP votes disagree across {} candidates (distinct /24s)",
                self.external_ip_votes.len()
            );
            debug!(
                "External IP vote tally (distinct /24s): [{}]",
                tally.join(", ")
            );
        } else {
            debug!(
                "External IP vote for {reported_ip} (distinct /24 voters: {})",
                self.external_ip_votes
                    .get(&reported_ip)
                    .map(|s| s.len())
                    .unwrap_or(0)
            );
        }
    }

    /// Trusted-source path: the ed2k server we're connected to told us our
    /// HighID. The server is one reporter so distinct-/24 voting can't
    /// apply, but a TCP connect-back from a user-chosen server beats KAD
    /// votes: three colluding /24s must not pin a bogus `external_ip` that
    /// then blocks HighID from correcting it. RFC1918 is allowed (LAN
    /// servers); documentation / class-E / loopback are not.
    pub fn handle_server_highid_response(&mut self, reported_ip: Ipv4Addr) {
        if crate::security::is_bogus_v4(reported_ip) {
            return;
        }
        match self.confirmed_external_ip {
            None => {
                self.confirmed_external_ip = Some(reported_ip);
                info!("External IP confirmed by ed2k server");
                debug!("Server-reported external IP: {reported_ip}");
            }
            Some(existing) if existing == reported_ip => {}
            Some(existing) => {
                info!("Ed2k server HighID replacing KAD-confirmed external IP");
                debug!("Server reported {reported_ip} vs previous {existing}");
                self.confirmed_external_ip = Some(reported_ip);
            }
        }
    }

    /// Record that a peer successfully connected back to our TCP port,
    /// proving we are reachable (not firewalled on TCP).
    pub fn handle_tcp_connect_back(&mut self) {
        self.tcp_responses_received += 1;
        self.tcp_status = FirewallStatus::Open;
        debug!(
            "TCP firewall check: open (connect-back received, {} total)",
            self.tcp_responses_received
        );
    }

    /// Record that an ed2k server assigned us LowID — inbound TCP to our
    /// advertised port failed from the server's perspective.
    ///
    /// Does **not** overwrite a stronger TCP Open proof from a real
    /// connect-back (KAD probe or successful server port-test). Callers may
    /// still set aggregate `firewalled` for LowID; this only protects
    /// `tcp_status` from being wiped back to Firewalled.
    pub fn note_tcp_firewalled(&mut self) {
        if self.tcp_status == FirewallStatus::Open && self.tcp_responses_received > 0 {
            debug!(
                "TCP firewall: keeping Open despite LowID note ({} connect-back(s) already proved reachability)",
                self.tcp_responses_received
            );
            return;
        }
        self.tcp_status = FirewallStatus::Firewalled;
        debug!("TCP firewall check: firewalled (server LowID)");
    }

    /// Handle KADEMLIA2_PONG: peer reports what UDP port it sees us on.
    /// `reporter` is the responding contact's source IP; votes are weighted by
    /// distinct /24 (K7) so a single-subnet cluster can't bias the result.
    pub fn handle_pong(&mut self, reported_udp_port: u16, reporter: Ipv4Addr) {
        let o = reporter.octets();
        let reporter_net: [u8; 3] = [o[0], o[1], o[2]];
        self.udp_port_votes
            .entry(reported_udp_port)
            .or_default()
            .insert(reporter_net);

        let best_port = self
            .udp_port_votes
            .iter()
            .max_by_key(|(_, nets)| nets.len())
            .map(|(&port, nets)| (port, nets.len()));

        if let Some((port, distinct_nets)) = best_port {
            if distinct_nets >= MIN_IP_VOTES {
                if self.external_udp_port != Some(port) {
                    info!(
                        "External UDP port confirmed: {port} ({distinct_nets} distinct-/24 votes)"
                    );
                }
                self.external_udp_port = Some(port);
            }
        }
    }

    /// Handle KADEMLIA2_FIREWALLUDP response.
    pub fn handle_udp_firewall_result(&mut self, success: bool) {
        if !self.checking {
            debug!("Ignoring late UDP firewall result outside an active check window");
            return;
        }
        self.udp_firewall_responses_received += 1;
        if success {
            self.udp_firewall_succeeded = true;
            self.udp_status = FirewallStatus::Open;
            debug!("UDP firewall check: open");
        } else {
            debug!("UDP firewall check: negative result");
        }
    }

    pub fn needs_udp_firewall_probes(&self) -> bool {
        self.checking
            && self.udp_requests_sent < MAX_UDP_FIREWALL_PROBES
            && !self.udp_firewall_succeeded
    }

    /// Called periodically to evaluate results if the response window has elapsed.
    /// Returns true only if meaningful data was collected and status was updated.
    pub fn evaluate(&mut self) -> bool {
        if !self.checking {
            return false;
        }
        let now = chrono::Utc::now().timestamp();
        if now - self.last_check_start < RESPONSE_WINDOW_SECS {
            return false;
        }

        self.checking = false;
        self.pending_check_ips.clear();
        self.pending_udp_check_ips.clear();

        // If no requests were sent at all this cycle, don't change any status --
        // we have no data to make a determination and shouldn't overwrite whatever
        // the caller already has.
        if self.tcp_requests_sent == 0 && self.udp_requests_sent == 0 {
            debug!(
                "Firewall check cycle completed with no requests sent, preserving existing status"
            );
            return false;
        }

        // Never downgrade a confirmed-Open status to Firewalled based on a single
        // check cycle where contacts didn't respond (they might just be offline).
        // Only mark Firewalled if we've never been confirmed Open.
        if self.tcp_responses_received > 0 {
            self.tcp_status = FirewallStatus::Open;
        } else if self.tcp_requests_sent > 0 && self.tcp_status != FirewallStatus::Open {
            self.tcp_status = FirewallStatus::Firewalled;
            info!(
                "TCP firewall check complete: FIREWALLED (0/{} responses)",
                self.tcp_requests_sent
            );
        }

        if self.udp_firewall_succeeded {
            self.udp_status = FirewallStatus::Open;
        } else if self.udp_status != FirewallStatus::Open && self.udp_requests_sent > 0 {
            // We sent probes but never got a success response.
            // If we were already confirmed Open, keep that (transient non-response
            // shouldn't downgrade). Otherwise, conclude Firewalled — including
            // transitioning out of Unknown, which is the initial state.
            self.udp_status = FirewallStatus::Firewalled;
            info!(
                "UDP firewall check complete: FIREWALLED (probes_sent={}, responses={}, success=0)",
                self.udp_requests_sent, self.udp_firewall_responses_received
            );
        } else if self.udp_requests_sent == 0 && self.udp_status == FirewallStatus::Unknown {
            info!("UDP firewall check: no probes dispatched, status remains Unknown");
        }

        true
    }

    pub fn should_recheck(&self) -> bool {
        if self.checking {
            return false;
        }
        let now = chrono::Utc::now().timestamp();
        now - self.last_check_start > FIREWALL_RECHECK_SECS
    }

    pub fn tcp_firewalled(&self) -> bool {
        self.tcp_status == FirewallStatus::Firewalled
    }

    pub fn udp_firewalled(&self) -> bool {
        self.udp_status == FirewallStatus::Firewalled
    }

    pub fn external_ip(&self) -> Option<Ipv4Addr> {
        self.confirmed_external_ip
    }

    pub fn ip_vote_count(&self) -> u32 {
        // K7: votes are now keyed by distinct-/24 sets; return the max
        // distinct-voter count across all reported IPs for diagnostics.
        self.external_ip_votes
            .values()
            .map(|nets| nets.len() as u32)
            .max()
            .unwrap_or(0)
    }

    pub fn external_udp_port(&self) -> Option<u16> {
        self.external_udp_port
    }

    pub fn tcp_status(&self) -> FirewallStatus {
        self.tcp_status
    }

    pub fn udp_status(&self) -> FirewallStatus {
        self.udp_status
    }

    pub fn checks_to_send(&self) -> u32 {
        FIREWALL_CHECK_COUNT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_tcp_firewalled_does_not_wipe_connect_back_open() {
        let mut fw = FirewallChecker::new();
        fw.handle_tcp_connect_back();
        assert_eq!(fw.tcp_status(), FirewallStatus::Open);
        fw.note_tcp_firewalled();
        assert_eq!(
            fw.tcp_status(),
            FirewallStatus::Open,
            "LowID sticky must not erase proven TCP Open"
        );
    }

    #[test]
    fn note_tcp_firewalled_sets_firewalled_without_prior_proof() {
        let mut fw = FirewallChecker::new();
        assert_eq!(fw.tcp_status(), FirewallStatus::Unknown);
        fw.note_tcp_firewalled();
        assert_eq!(fw.tcp_status(), FirewallStatus::Firewalled);
    }

    #[test]
    fn firewalled_response_rejects_documentation_and_cgnat() {
        let mut fw = FirewallChecker::new();
        let reporters = [
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(9, 9, 9, 9),
        ];
        for reporter in reporters {
            fw.handle_firewalled_response(Ipv4Addr::new(203, 0, 113, 50), reporter);
            fw.handle_firewalled_response(Ipv4Addr::new(100, 64, 0, 1), reporter);
            fw.handle_firewalled_response(Ipv4Addr::new(240, 0, 0, 1), reporter);
        }
        assert!(fw.external_ip().is_none());
    }

    #[test]
    fn server_highid_replaces_conflicting_kad_confirmation() {
        let mut fw = FirewallChecker::new();
        let kad = Ipv4Addr::new(203, 0, 113, 1);
        let highid = Ipv4Addr::new(8, 8, 8, 8);
        fw.handle_firewalled_response(kad, Ipv4Addr::new(1, 0, 0, 1));
        fw.handle_firewalled_response(kad, Ipv4Addr::new(1, 1, 0, 1));
        fw.handle_firewalled_response(kad, Ipv4Addr::new(1, 2, 0, 1));
        assert!(
            fw.external_ip().is_none(),
            "documentation IPs must not confirm via KAD"
        );

        let kad_public = Ipv4Addr::new(4, 4, 4, 4);
        fw.handle_firewalled_response(kad_public, Ipv4Addr::new(1, 0, 0, 1));
        fw.handle_firewalled_response(kad_public, Ipv4Addr::new(1, 1, 0, 1));
        fw.handle_firewalled_response(kad_public, Ipv4Addr::new(1, 2, 0, 1));
        assert_eq!(fw.external_ip(), Some(kad_public));

        fw.handle_server_highid_response(highid);
        assert_eq!(fw.external_ip(), Some(highid));
    }

    #[test]
    fn server_highid_rejects_bogus_addresses() {
        let mut fw = FirewallChecker::new();
        fw.handle_server_highid_response(Ipv4Addr::new(203, 0, 113, 1));
        fw.handle_server_highid_response(Ipv4Addr::new(127, 0, 0, 1));
        fw.handle_server_highid_response(Ipv4Addr::new(240, 0, 0, 1));
        assert!(fw.external_ip().is_none());
        fw.handle_server_highid_response(Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(
            fw.external_ip(),
            Some(Ipv4Addr::new(10, 0, 0, 5)),
            "LAN HighID from a local server is adoptable"
        );
    }
}
