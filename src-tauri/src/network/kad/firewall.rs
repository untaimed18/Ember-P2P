use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use tracing::{debug, info};

/// Minimum unique IPs needed to confirm external IP
const MIN_IP_VOTES: usize = 3;
/// Number of firewall check requests to send per cycle.
/// Higher than eMule's default (4) because some contacts won't respond to
/// FirewalledReq if their RequestTCP fails on their end.
const FIREWALL_CHECK_COUNT: u32 = 8;
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
    external_ip_votes: HashMap<Ipv4Addr, u32>,
    confirmed_external_ip: Option<Ipv4Addr>,
    tcp_status: FirewallStatus,
    udp_status: FirewallStatus,
    tcp_responses_received: u32,
    tcp_requests_sent: u32,
    udp_firewall_responses_received: u32,
    udp_requests_sent: u32,
    last_check_start: i64,
    external_udp_port: Option<u16>,
    udp_port_votes: HashMap<u16, u32>,
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
        // Preserve external_udp_port from previous cycle so UDP firewall
        // probes can be dispatched immediately without waiting for new pongs.
        // Port votes are cleared so pongs from this cycle can refine it.
        self.udp_port_votes.clear();
        info!("Starting firewall check cycle (current TCP={:?}, UDP={:?}, ext_udp={:?})", self.tcp_status, self.udp_status, self.external_udp_port);
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
    pub fn record_udp_port_probe_sent(&mut self) {
    }

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
    /// The caller must validate the sender via is_firewall_check_ip() first.
    pub fn handle_firewalled_response(&mut self, reported_ip: Ipv4Addr) {
        if reported_ip.is_private()
            || reported_ip.is_loopback()
            || reported_ip.is_unspecified()
            || reported_ip.is_broadcast()
            || reported_ip.is_link_local()
        {
            debug!("Ignoring private/reserved external IP vote: {reported_ip}");
            return;
        }
        *self.external_ip_votes.entry(reported_ip).or_insert(0) += 1;

        let best_ip = self.external_ip_votes.iter()
            .max_by_key(|(_, &count)| count)
            .map(|(&ip, _)| ip);

        if let Some(ip) = best_ip {
            let count = self.external_ip_votes[&ip];
            if count >= MIN_IP_VOTES as u32 {
                if self.confirmed_external_ip != Some(ip) {
                    info!("External IP confirmed: {ip} ({count} votes)");
                }
                self.confirmed_external_ip = Some(ip);
            }
        }

        if self.external_ip_votes.len() > 1 {
            let tally: Vec<String> = self.external_ip_votes.iter().map(|(ip, c)| format!("{}={}", ip, c)).collect();
            info!("External IP votes disagree: [{}]", tally.join(", "));
        } else {
            debug!("External IP vote for {reported_ip} ({} total votes)", self.external_ip_votes.values().sum::<u32>());
        }
    }

    /// Record that a peer successfully connected back to our TCP port,
    /// proving we are reachable (not firewalled on TCP).
    pub fn handle_tcp_connect_back(&mut self) {
        self.tcp_responses_received += 1;
        self.tcp_status = FirewallStatus::Open;
        debug!("TCP firewall check: open (connect-back received, {} total)", self.tcp_responses_received);
    }

    /// Handle KADEMLIA2_PONG: peer reports what UDP port it sees us on.
    pub fn handle_pong(&mut self, reported_udp_port: u16) {
        *self.udp_port_votes.entry(reported_udp_port).or_insert(0) += 1;

        let best_port = self.udp_port_votes.iter()
            .max_by_key(|(_, &count)| count)
            .map(|(&port, _)| port);

        if let Some(port) = best_port {
            self.external_udp_port = Some(port);
        }
    }

    /// Handle KADEMLIA2_FIREWALLUDP response.
    pub fn handle_udp_firewall_result(&mut self, success: bool) {
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
        self.checking && self.udp_requests_sent == 0 && !self.udp_firewall_succeeded
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

        // If no requests were sent at all this cycle, don't change any status --
        // we have no data to make a determination and shouldn't overwrite whatever
        // the caller already has.
        if self.tcp_requests_sent == 0 && self.udp_requests_sent == 0 {
            debug!("Firewall check cycle completed with no requests sent, preserving existing status");
            return false;
        }

        // Never downgrade a confirmed-Open status to Firewalled based on a single
        // check cycle where contacts didn't respond (they might just be offline).
        // Only mark Firewalled if we've never been confirmed Open.
        if self.tcp_responses_received > 0 {
            self.tcp_status = FirewallStatus::Open;
        } else if self.tcp_requests_sent > 0 && self.tcp_status != FirewallStatus::Open {
            self.tcp_status = FirewallStatus::Firewalled;
            info!("TCP firewall check complete: FIREWALLED (0/{} responses)", self.tcp_requests_sent);
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
                "UDP firewall check complete: FIREWALLED (sent {}, success_replies 0)",
                self.udp_requests_sent
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

    #[allow(dead_code)]
    pub fn tcp_status_known(&self) -> bool {
        self.tcp_status != FirewallStatus::Unknown
    }

    pub fn external_ip(&self) -> Option<Ipv4Addr> {
        self.confirmed_external_ip
    }

    pub fn ip_vote_count(&self) -> u32 {
        self.external_ip_votes.values().copied().max().unwrap_or(0)
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
