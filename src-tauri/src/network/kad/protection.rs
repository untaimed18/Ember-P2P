use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

/// eMule PacketTracking.cpp: per-opcode limits within a 15-second window.
/// Global per-IP caps remain as a second layer of defense.
const OPCODE_WINDOW_SECS: u64 = 15;
const DEFAULT_OPCODE_LIMIT: u32 = 5;
const TRACKER_EXPIRY_SECS: u64 = 30;
const MAX_OUTGOING_PER_IP_PER_SEC: u32 = 30;

/// Per-IP global cap (second-level, matching eMule's "massive flood" detection).
const MAX_PACKETS_PER_SEC_UNKNOWN: u32 = 20;
const MAX_PACKETS_PER_SEC_KNOWN: u32 = 40;

fn opcode_limit(opcode: u8) -> u32 {
    match opcode {
        0x01 => 2,   // BootstrapReq
        0x11 => 3,   // HelloReq
        0x21 => 10,  // KadReq (searches generate bursts)
        0x33 => 5,   // SearchKeyReq
        0x34 => 5,   // SearchSourceReq
        0x35 => 5,   // SearchNotesReq
        0x43 => 8,   // PublishKeyReq
        0x44 => 8,   // PublishSourceReq
        0x45 => 8,   // PublishNotesReq
        0x50 => 3,   // FirewalledReq
        0x53 => 3,   // Firewalled2Req
        0x60 => 3,   // Ping
        _ => DEFAULT_OPCODE_LIMIT,
    }
}

pub struct FloodProtection {
    ip_counters: HashMap<IpAddr, (u32, Instant)>,
    /// Per-(IP, opcode) tracking within OPCODE_WINDOW_SECS
    opcode_counters: HashMap<(IpAddr, u8), (u32, Instant)>,
    outgoing_requests: HashSet<(SocketAddr, u8)>,
    request_times: HashMap<(SocketAddr, u8), Instant>,
    outgoing_counters: HashMap<IpAddr, (u32, Instant)>,
    recent_ips: HashMap<IpAddr, Instant>,
}

impl FloodProtection {
    pub fn new() -> Self {
        FloodProtection {
            ip_counters: HashMap::new(),
            opcode_counters: HashMap::new(),
            outgoing_requests: HashSet::new(),
            request_times: HashMap::new(),
            outgoing_counters: HashMap::new(),
            recent_ips: HashMap::new(),
        }
    }

    /// Rate-limit with opcode awareness matching eMule PacketTracking.cpp.
    pub fn check_rate_limit_with_opcode(&mut self, ip: IpAddr, known_peer: bool, opcode: u8) -> bool {
        let now = Instant::now();

        // Layer 1: per-(IP, opcode) within OPCODE_WINDOW_SECS
        let op_key = (ip, opcode);
        let op_entry = self.opcode_counters.entry(op_key).or_insert((0, now));
        if now.duration_since(op_entry.1).as_secs() >= OPCODE_WINDOW_SECS {
            op_entry.0 = 1;
            op_entry.1 = now;
        } else {
            op_entry.0 += 1;
            let limit = opcode_limit(opcode);
            let effective = if known_peer { limit * 2 } else { limit };
            if op_entry.0 > effective {
                return true;
            }
        }

        // Layer 2: global per-IP per-second cap
        let entry = self.ip_counters.entry(ip).or_insert((0, now));
        let max_packets = if known_peer { MAX_PACKETS_PER_SEC_KNOWN } else { MAX_PACKETS_PER_SEC_UNKNOWN };
        if now.duration_since(entry.1).as_secs() >= 1 {
            entry.0 = 1;
            entry.1 = now;
            false
        } else {
            entry.0 += 1;
            entry.0 > max_packets
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
        let now = Instant::now();
        let key = (addr, opcode);
        self.outgoing_requests.insert(key);
        self.request_times.insert(key, now);
        self.recent_ips.insert(addr.ip(), now);
    }

    /// Check if we have a matching outgoing request for this response.
    /// Returns true if valid (we sent a request), false if unsolicited.
    pub fn validate_response(&mut self, addr: SocketAddr, response_opcode: u8) -> bool {
        let request_opcode = match response_opcode {
            0x09 => Some(0x01u8), // BootstrapRes -> BootstrapReq
            0x19 => Some(0x11),   // HelloRes -> HelloReq
            0x22 => Some(0x19),   // HelloResAck -> HelloRes
            0x29 => Some(0x21),   // KadRes -> KadReq
            0x3B => Some(0x33),   // SearchRes -> SearchKeyReq (or 0x34, 0x35)
            0x4B => Some(0x43),   // PublishRes -> PublishKeyReq (or 0x44, 0x45)
            0x4C => Some(0x4B),   // PublishResAck -> PublishRes
            0x5A => Some(0x51),   // FindBuddyRes -> FindBuddyReq
            0x61 => Some(0x60),   // Pong -> Ping
            0x58 => Some(0x50),   // FirewalledRes -> FirewalledReq or Firewalled2Req
            _ => None,
        };

        if let Some(req_op) = request_opcode {
            if response_opcode == 0x3B {
                // KAD peers send multiple SearchRes packets per SearchKeyReq
                // (one per batch of results). Do NOT remove the tracking entry
                // on first response; keep it alive for subsequent batches.
                let key = (addr, req_op);
                if self.outgoing_requests.contains(&key) {
                    return true;
                }
                let key2 = (addr, 0x34);
                if self.outgoing_requests.contains(&key2) {
                    return true;
                }
                let key3 = (addr, 0x35);
                if self.outgoing_requests.contains(&key3) {
                    return true;
                }
                return false;
            }
            let key = (addr, req_op);
            if self.outgoing_requests.remove(&key) {
                self.request_times.remove(&key);
                return true;
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
            // For FirewalledRes, also check Firewalled2Req (0x53)
            if response_opcode == 0x58 {
                let key2 = (addr, 0x53);
                if self.outgoing_requests.remove(&key2) {
                    self.request_times.remove(&key2);
                    return true;
                }
            }
        }
        false
    }

    /// O(1) check if we've communicated with this IP recently.
    pub fn has_recent_ip(&self, ip: IpAddr) -> bool {
        if let Some(last) = self.recent_ips.get(&ip) {
            Instant::now().duration_since(*last).as_secs() < TRACKER_EXPIRY_SECS
        } else {
            false
        }
    }

    /// Clean up stale tracking entries.
    pub fn cleanup(&mut self) {
        let now = Instant::now();

        self.ip_counters.retain(|_, (_, last)| {
            now.duration_since(*last).as_secs() < 60
        });

        self.opcode_counters.retain(|_, (_, last)| {
            now.duration_since(*last).as_secs() < OPCODE_WINDOW_SECS * 2
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

        self.recent_ips.retain(|_, last| {
            now.duration_since(*last).as_secs() < TRACKER_EXPIRY_SECS
        });
    }
}
