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

const MAX_IP_ENTRIES: usize = 10_000;
const MAX_OPCODE_ENTRIES: usize = 50_000;

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
    /// K21: per-IP compressed-packet counter within a 1-second window so
    /// we can decline to decompress over-quota traffic. Tracks (count,
    /// window_start). 10 compressed packets/sec is far more than any
    /// legit eMule client ever sends us but cheap to enforce.
    compressed_counters: HashMap<IpAddr, (u32, Instant)>,
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
            compressed_counters: HashMap::new(),
        }
    }

    /// K21: returns true when `ip` has exceeded its compressed-packet
    /// decompression budget for the current 1-second window. Callers
    /// should drop the packet (skip decompression) when this is true.
    pub fn over_compressed_budget(&mut self, ip: IpAddr) -> bool {
        const MAX_COMPRESSED_PER_SEC: u32 = 10;
        const MAX_COMPRESSED_ENTRIES: usize = 10_000;
        let now = Instant::now();
        if self.compressed_counters.len() >= MAX_COMPRESSED_ENTRIES
            && !self.compressed_counters.contains_key(&ip)
        {
            if let Some(oldest) = self
                .compressed_counters
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| *k)
            {
                self.compressed_counters.remove(&oldest);
            } else {
                return true;
            }
        }
        let entry = self.compressed_counters.entry(ip).or_insert((0, now));
        if now.saturating_duration_since(entry.1).as_secs() >= 1 {
            entry.0 = 1;
            entry.1 = now;
            false
        } else {
            entry.0 += 1;
            entry.0 > MAX_COMPRESSED_PER_SEC
        }
    }

    /// Rate-limit with opcode awareness matching eMule PacketTracking.cpp.
    pub fn check_rate_limit_with_opcode(&mut self, ip: IpAddr, known_peer: bool, opcode: u8) -> bool {
        let now = Instant::now();

        // Layer 1: per-(IP, opcode) within OPCODE_WINDOW_SECS
        let op_key = (ip, opcode);
        if self.opcode_counters.len() >= MAX_OPCODE_ENTRIES && !self.opcode_counters.contains_key(&op_key) {
            // K19: previous behaviour rejected the new peer outright as
            // soon as the per-opcode table filled — an attacker that fills
            // the table with one-shot spam permanently locks out legit
            // peers. We now LRU-evict: drop the entry whose window-start
            // timestamp is oldest, freeing a slot for the new peer.
            if let Some(oldest_key) = self
                .opcode_counters
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| *k)
            {
                self.opcode_counters.remove(&oldest_key);
            } else {
                return true;
            }
        }
        let op_entry = self.opcode_counters.entry(op_key).or_insert((0, now));
        if now.saturating_duration_since(op_entry.1).as_secs() >= OPCODE_WINDOW_SECS {
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
        if self.ip_counters.len() >= MAX_IP_ENTRIES && !self.ip_counters.contains_key(&ip) {
            // K19: same LRU eviction rationale as above.
            if let Some(oldest_ip) = self
                .ip_counters
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| *k)
            {
                self.ip_counters.remove(&oldest_ip);
            } else {
                return true;
            }
        }
        let entry = self.ip_counters.entry(ip).or_insert((0, now));
        let max_packets = if known_peer { MAX_PACKETS_PER_SEC_KNOWN } else { MAX_PACKETS_PER_SEC_UNKNOWN };
        if now.saturating_duration_since(entry.1).as_secs() >= 1 {
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
        if self.outgoing_counters.len() >= MAX_IP_ENTRIES && !self.outgoing_counters.contains_key(&ip) {
            // K19: LRU-evict instead of hard-failing.
            if let Some(oldest_ip) = self
                .outgoing_counters
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| *k)
            {
                self.outgoing_counters.remove(&oldest_ip);
            } else {
                return true;
            }
        }
        let entry = self.outgoing_counters.entry(ip).or_insert((0, now));

        if now.saturating_duration_since(entry.1).as_secs() >= 1 {
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
            Instant::now().saturating_duration_since(*last).as_secs() < TRACKER_EXPIRY_SECS
        } else {
            false
        }
    }

    /// Clean up stale tracking entries.
    pub fn cleanup(&mut self) {
        let now = Instant::now();

        self.ip_counters.retain(|_, (_, last)| {
            now.saturating_duration_since(*last).as_secs() < 60
        });

        self.opcode_counters.retain(|_, (_, last)| {
            now.saturating_duration_since(*last).as_secs() < OPCODE_WINDOW_SECS * 2
        });

        self.outgoing_counters.retain(|_, (_, last)| {
            now.saturating_duration_since(*last).as_secs() < 60
        });

        let stale: Vec<(SocketAddr, u8)> = self.request_times
            .iter()
            .filter(|(_, time)| now.saturating_duration_since(**time).as_secs() > TRACKER_EXPIRY_SECS)
            .map(|(key, _)| *key)
            .collect();
        for key in stale {
            self.outgoing_requests.remove(&key);
            self.request_times.remove(&key);
        }

        self.recent_ips.retain(|_, last| {
            now.saturating_duration_since(*last).as_secs() < TRACKER_EXPIRY_SECS
        });
        // K21: compressed-packet budget table follows the same 60s cleanup.
        self.compressed_counters.retain(|_, (_, last)| {
            now.saturating_duration_since(*last).as_secs() < 60
        });
    }
}

#[cfg(test)]
mod kad_protection_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// K19: when the opcode-tracker table is full, a new IP should still
    /// be accepted by LRU-evicting the oldest entry.
    #[test]
    fn lru_evicts_when_opcode_table_full() {
        let mut fp = FloodProtection::new();
        // Fill the table with distinct (IP, opcode) pairs up to the cap.
        for i in 0..MAX_OPCODE_ENTRIES {
            let ip = IpAddr::V4(Ipv4Addr::new(
                ((i >> 24) & 0xFF) as u8,
                ((i >> 16) & 0xFF) as u8,
                ((i >> 8) & 0xFF) as u8,
                (i & 0xFF) as u8,
            ));
            let _ = fp.check_rate_limit_with_opcode(ip, false, 0x21);
        }
        assert_eq!(fp.opcode_counters.len(), MAX_OPCODE_ENTRIES);
        // Introduce a brand new IP. With the LRU fix this must succeed
        // (return false meaning "not rate-limited").
        let new_ip = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 254));
        assert!(
            !fp.check_rate_limit_with_opcode(new_ip, false, 0x21),
            "LRU eviction must admit a fresh peer even when the table is full"
        );
    }

    /// K21: 11th compressed packet from same IP in 1s should be declined.
    #[test]
    fn compressed_budget_enforced() {
        let mut fp = FloodProtection::new();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        for _ in 0..10 {
            assert!(!fp.over_compressed_budget(ip));
        }
        assert!(fp.over_compressed_budget(ip), "11th compressed packet must trip the budget");
    }
}
