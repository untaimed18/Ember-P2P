use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

const MAX_PACKETS_PER_SEC: u32 = 10;
const TRACKER_EXPIRY_SECS: u64 = 30;
/// Max outgoing packets per IP per second
const MAX_OUTGOING_PER_IP_PER_SEC: u32 = 10;

pub struct FloodProtection {
    ip_counters: HashMap<IpAddr, (u32, Instant)>,
    outgoing_requests: HashSet<(SocketAddr, u8)>,
    request_times: HashMap<(SocketAddr, u8), Instant>,
    outgoing_counters: HashMap<IpAddr, (u32, Instant)>,
}

impl FloodProtection {
    pub fn new() -> Self {
        FloodProtection {
            ip_counters: HashMap::new(),
            outgoing_requests: HashSet::new(),
            request_times: HashMap::new(),
            outgoing_counters: HashMap::new(),
        }
    }

    /// Returns true if the packet should be dropped (rate exceeded).
    pub fn check_rate_limit(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let entry = self.ip_counters.entry(ip).or_insert((0, now));

        if now.duration_since(entry.1).as_secs() >= 1 {
            entry.0 = 1;
            entry.1 = now;
            false
        } else {
            entry.0 += 1;
            entry.0 > MAX_PACKETS_PER_SEC
        }
    }

    /// Returns true if a packet from port 53 should be dropped (unencrypted).
    pub fn is_dns_port(addr: &SocketAddr) -> bool {
        addr.port() == 53
    }

    /// Check if we should throttle an outgoing packet to this IP.
    /// Returns true if we've sent too many packets to this IP recently.
    pub fn check_outgoing_rate(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let entry = self.outgoing_counters.entry(ip).or_insert((0, now));

        if now.duration_since(entry.1).as_secs() >= 1 {
            entry.0 = 1;
            entry.1 = now;
            false
        } else {
            entry.0 += 1;
            entry.0 > MAX_OUTGOING_PER_IP_PER_SEC
        }
    }

    /// Record an outgoing request so we can validate incoming responses.
    pub fn track_request(&mut self, addr: SocketAddr, opcode: u8) {
        let key = (addr, opcode);
        self.outgoing_requests.insert(key);
        self.request_times.insert(key, Instant::now());
    }

    /// Check if we have a matching outgoing request for this response.
    /// Returns true if valid (we sent a request), false if unsolicited.
    pub fn validate_response(&mut self, addr: SocketAddr, response_opcode: u8) -> bool {
        let request_opcode = match response_opcode {
            0x09 => Some(0x01u8), // BootstrapRes -> BootstrapReq
            0x19 => Some(0x11),   // HelloRes -> HelloReq
            0x29 => Some(0x21),   // KadRes -> KadReq
            0x3B => Some(0x33),   // SearchRes -> SearchKeyReq (or 0x34, 0x35)
            0x4B => Some(0x43),   // PublishRes -> PublishKeyReq (or 0x44, 0x45)
            0x61 => Some(0x60),   // Pong -> Ping
            0x58 => Some(0x50),   // FirewalledRes -> FirewalledReq
            _ => None,
        };

        if let Some(req_op) = request_opcode {
            let key = (addr, req_op);
            if self.outgoing_requests.remove(&key) {
                self.request_times.remove(&key);
                return true;
            }
            // For SearchRes, also check SearchSourceReq and SearchNotesReq
            if response_opcode == 0x3B {
                let key2 = (addr, 0x34);
                if self.outgoing_requests.remove(&key2) {
                    self.request_times.remove(&key2);
                    return true;
                }
                let key3 = (addr, 0x35);
                if self.outgoing_requests.remove(&key3) {
                    self.request_times.remove(&key3);
                    return true;
                }
            }
            // For PublishRes, also check PublishSourceReq and PublishNotesReq
            if response_opcode == 0x4B {
                let key2 = (addr, 0x44);
                if self.outgoing_requests.remove(&key2) {
                    self.request_times.remove(&key2);
                    return true;
                }
                let key3 = (addr, 0x45);
                if self.outgoing_requests.remove(&key3) {
                    self.request_times.remove(&key3);
                    return true;
                }
            }
        }

        // Allow responses from addresses we've recently communicated with
        // (within the tracker expiry window), even if the exact opcode
        // doesn't match -- obfuscation can make opcode matching imprecise.
        self.has_recent_communication(&addr)
    }

    /// Check if we've had any tracked communication with this address recently.
    /// For P2P networks, NAT can cause responses to arrive from a different port
    /// than the one we sent to, so we match on IP alone.
    fn has_recent_communication(&self, addr: &SocketAddr) -> bool {
        let now = Instant::now();
        let ip = addr.ip();
        self.request_times.iter().any(|((tracked_addr, _), time)| {
            tracked_addr.ip() == ip
                && now.duration_since(*time).as_secs() < TRACKER_EXPIRY_SECS
        })
    }

    /// Clean up stale tracking entries.
    pub fn cleanup(&mut self) {
        let now = Instant::now();

        self.ip_counters.retain(|_, (_, last)| {
            now.duration_since(*last).as_secs() < 60
        });

        self.outgoing_counters.retain(|_, (_, last)| {
            now.duration_since(*last).as_secs() < 60
        });

        let stale: Vec<(SocketAddr, u8)> = self.request_times
            .iter()
            .filter(|(_, time)| now.duration_since(**time).as_secs() > TRACKER_EXPIRY_SECS)
            .map(|(key, _)| *key)
            .collect();
        for key in stale {
            self.outgoing_requests.remove(&key);
            self.request_times.remove(&key);
        }
    }
}
