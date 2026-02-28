use std::collections::HashMap;
use std::net::Ipv4Addr;

use tracing::{debug, info};

/// Minimum unique IPs needed to confirm external IP
const MIN_IP_VOTES: usize = 3;
/// Number of firewall check requests to send per cycle
const FIREWALL_CHECK_COUNT: u32 = 4;
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
    udp_responses_received: u32,
    udp_requests_sent: u32,
    last_check_start: i64,
    external_udp_port: Option<u16>,
    udp_port_votes: HashMap<u16, u32>,
    checking: bool,
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
            udp_responses_received: 0,
            udp_requests_sent: 0,
            last_check_start: 0,
            external_udp_port: None,
            udp_port_votes: HashMap::new(),
            checking: false,
        }
    }

    pub fn is_checking(&self) -> bool {
        self.checking
    }

    pub fn start_check(&mut self) {
        let now = chrono::Utc::now().timestamp();
        self.checking = true;
        self.last_check_start = now;
        // Reset per-cycle counters but preserve tcp_status/udp_status
        // so a confirmed-Open status isn't lost between cycles.
        self.tcp_responses_received = 0;
        self.tcp_requests_sent = 0;
        self.udp_responses_received = 0;
        self.udp_requests_sent = 0;
        info!("Starting firewall check cycle (current TCP={:?}, UDP={:?})", self.tcp_status, self.udp_status);
    }

    pub fn record_tcp_request_sent(&mut self) {
        self.tcp_requests_sent += 1;
    }

    pub fn record_udp_request_sent(&mut self) {
        self.udp_requests_sent += 1;
    }

    /// Handle KADEMLIA_FIREWALLED_RES: a peer reports our external IP.
    /// This message arrives via UDP, so it only proves UDP connectivity --
    /// it does NOT indicate TCP is open (the separate TCP connect-back does).
    pub fn handle_firewalled_response(&mut self, reported_ip: Ipv4Addr) {
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

        debug!("External IP vote for {reported_ip} ({} total votes)", self.external_ip_votes.values().sum::<u32>());
    }

    /// Record that a peer successfully connected back to our TCP port,
    /// proving we are reachable (not firewalled on TCP).
    #[allow(dead_code)]
    pub fn handle_tcp_connect_back(&mut self) {
        self.tcp_responses_received += 1;
        self.tcp_status = FirewallStatus::Open;
        debug!("TCP firewall check: open (connect-back received, {} total)", self.tcp_responses_received);
    }

    /// Handle KADEMLIA2_PONG: peer reports what UDP port it sees us on.
    pub fn handle_pong(&mut self, reported_udp_port: u16) {
        self.udp_responses_received += 1;
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
        if success {
            self.udp_status = FirewallStatus::Open;
            debug!("UDP firewall check: open");
        }
    }

    /// Called periodically to evaluate results if the response window has elapsed.
    pub fn evaluate(&mut self) -> bool {
        if !self.checking {
            return false;
        }
        let now = chrono::Utc::now().timestamp();
        if now - self.last_check_start < RESPONSE_WINDOW_SECS {
            return false;
        }

        self.checking = false;

        // Never downgrade a confirmed-Open status to Firewalled based on a single
        // check cycle where contacts didn't respond (they might just be offline).
        // Only mark Firewalled if we've never been confirmed Open.
        if self.tcp_responses_received > 0 {
            self.tcp_status = FirewallStatus::Open;
        } else if self.tcp_requests_sent > 0 && self.tcp_status != FirewallStatus::Open {
            self.tcp_status = FirewallStatus::Firewalled;
            info!("TCP firewall check complete: FIREWALLED (0/{} responses)", self.tcp_requests_sent);
        }

        if self.udp_responses_received > 0 {
            self.udp_status = FirewallStatus::Open;
        } else if self.udp_requests_sent > 0 && self.udp_status != FirewallStatus::Open {
            self.udp_status = FirewallStatus::Firewalled;
            info!("UDP firewall check complete: FIREWALLED");
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
