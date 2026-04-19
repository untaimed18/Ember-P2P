use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

/// eMule PacketTracking.cpp: per-opcode limits within a 15-second window.
/// Global per-IP caps remain as a second layer of defense.
const OPCODE_WINDOW_SECS: u64 = 15;
const DEFAULT_OPCODE_LIMIT: u32 = 5;
/// Matches eMule's `SEC2MS(180)` outgoing-request expiry. We were using 30s,
/// which silently expired slow publish/search acks (KAD peers routinely take
/// several seconds to ack, and a full search cycle can sit in the `Lookup`
/// phase for >60s before the matching response arrives).
const TRACKER_EXPIRY_SECS: u64 = 180;
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

/// Mirrors eMule's `InTrackListIsAllowedPacket` switch — only **request**
/// opcodes are flood-checked; responses fall through to `default: return 0`.
/// Using this gate on the incoming path was the missing piece that made
/// `PublishRes` (0x4B, or 0xFF for obfuscated-unknown) get rate-limited away
/// before ever reaching `decode_packet`, which is why `publish_confirmed`
/// stayed at 0 despite 100+ outstanding pending acks.
fn is_request_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        0x01 // KADEMLIA2_BOOTSTRAP_REQ
        | 0x08 // legacy BootstrapReq
        | 0x11 // KADEMLIA2_HELLO_REQ
        | 0x21 // KADEMLIA2_REQ
        | 0x33 // KADEMLIA2_SEARCH_KEY_REQ
        | 0x34 // KADEMLIA2_SEARCH_SOURCE_REQ
        | 0x35 // KADEMLIA2_SEARCH_NOTES_REQ
        | 0x43 // KADEMLIA2_PUBLISH_KEY_REQ
        | 0x44 // KADEMLIA2_PUBLISH_SOURCE_REQ
        | 0x45 // KADEMLIA2_PUBLISH_NOTES_REQ
        | 0x50 // KADEMLIA_FIREWALLED_REQ
        | 0x51 // KADEMLIA_FINDBUDDY_REQ
        | 0x52 // KADEMLIA_CALLBACK_REQ
        | 0x53 // KADEMLIA_FIREWALLED2_REQ
        | 0x60 // KADEMLIA2_PING
    )
}

pub struct FloodProtection {
    ip_counters: HashMap<IpAddr, (u32, Instant)>,
    /// Per-(IP, opcode) tracking within OPCODE_WINDOW_SECS
    opcode_counters: HashMap<(IpAddr, u8), (u32, Instant)>,
    /// Count of *outstanding* outgoing requests per (peer_ip, opcode).
    /// Previously a `HashSet`, which meant that if we sent e.g. five
    /// PublishSourceReqs to the same peer in a burst (common during a
    /// publish cycle that picks the same top-K closest peers for
    /// multiple files), only the first ack validated — every
    /// subsequent ack was rejected as "unsolicited" because the set
    /// entry was already consumed. With a counter we decrement per ack,
    /// so N requests can be matched by N acks in any order.
    ///
    /// Keyed by `IpAddr` (not `SocketAddr`) to match eMule's
    /// `AddTrackedOutPacket(uint32 dwIP, uint8 byOpcode)` — peers behind
    /// NAT sometimes reply from a different source port than we sent to,
    /// and eMule allows that.
    outgoing_requests: HashMap<(IpAddr, u8), u32>,
    request_times: HashMap<(IpAddr, u8), Instant>,
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
            outgoing_requests: HashMap::new(),
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
    ///
    /// `opcode` is the byte at `data[1]` for a plain 0xE4/0xE5 packet or
    /// `0xFF` when we can't peek inside (obfuscated envelope). It is *not*
    /// trustworthy for classifying responses — an obfuscated PublishRes
    /// looks identical to any other obfuscated packet until we decrypt it.
    pub fn check_rate_limit_with_opcode(&mut self, ip: IpAddr, known_peer: bool, opcode: u8) -> bool {
        let now = Instant::now();

        // Layer 1: per-(IP, opcode) within OPCODE_WINDOW_SECS.
        //
        // Matches eMule `InTrackListIsAllowedPacket`'s `default: return 0;`
        // branch: responses bypass the flood check entirely. Applying it to
        // responses was dropping PublishRes/KadRes/SearchRes packets before
        // `decode_packet` could tell them apart, which manifested as
        // `publish_confirmed` stuck at 0 with `wire=0` in diagnostics.
        //
        // Obfuscated packets (opcode == 0xFF) also bypass Layer 1 because we
        // can't tell a request from a response until after decryption. The
        // Layer 2 per-IP per-second cap below is what keeps an obfuscated
        // flood from burning CPU; rate-limiting by opcode before we know
        // what the opcode is punishes the responder for us, not the flooder.
        if opcode != 0xFF && is_request_opcode(opcode) {
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
    /// Counter-based: sending N requests to the same (ip, opcode) leaves
    /// N entries to be matched by N replies. Any ordering is acceptable.
    ///
    /// Keyed by IP only — not (IP, port) — to match eMule
    /// `AddTrackedOutPacket(dwIP, byOpcode)`. Some NATs rewrite the source
    /// port on reply, so an SocketAddr-keyed table silently dropped those
    /// acks.
    pub fn track_request(&mut self, addr: SocketAddr, opcode: u8) {
        let now = Instant::now();
        let key = (addr.ip(), opcode);
        let count = self.outgoing_requests.entry(key).or_insert(0);
        *count = count.saturating_add(1);
        self.request_times.insert(key, now);
        self.recent_ips.insert(addr.ip(), now);
    }

    /// Helper: decrement the counter for `key` and return whether an
    /// entry was consumed. The entry is removed entirely (along with
    /// `request_times`) when the count reaches zero.
    fn consume_outgoing(&mut self, key: &(IpAddr, u8)) -> bool {
        if let Some(count) = self.outgoing_requests.get_mut(key) {
            if *count > 0 {
                *count -= 1;
                if *count == 0 {
                    self.outgoing_requests.remove(key);
                    self.request_times.remove(key);
                }
                return true;
            }
        }
        false
    }

    /// Check if we have a matching outgoing request for this response.
    /// Returns true if valid (we sent a request), false if unsolicited.
    pub fn validate_response(&mut self, addr: SocketAddr, response_opcode: u8) -> bool {
        let ip = addr.ip();
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
                // (one per batch of results). Do NOT decrement on any single
                // response; just check presence so subsequent batches still
                // validate. The entry will expire via `TRACKER_EXPIRY_SECS`.
                if self.outgoing_requests.contains_key(&(ip, req_op))
                    || self.outgoing_requests.contains_key(&(ip, 0x34))
                    || self.outgoing_requests.contains_key(&(ip, 0x35))
                {
                    return true;
                }
                return false;
            }
            // PublishRes (0x4B) is ambiguous: it could ack any of
            // {0x43 PublishKeyReq, 0x44 PublishSourceReq, 0x45
            // PublishNotesReq}. The protection layer can't see the
            // target hash inside the response payload, so it can't
            // know which specific publish is being acked. To avoid
            // systematically biasing 0x43 (which leaves the other
            // counters elevated until expiry), consume the *oldest*
            // pending publish across the three — peers typically
            // respond in roughly send order. The actual confirmation
            // count is tracked at the higher layer via
            // `publish_pending` keyed by `(target_hash, addr)`, which
            // is the source of truth for user-visible counts.
            if response_opcode == 0x4B {
                let mut oldest_op: Option<u8> = None;
                let mut oldest_t: Option<Instant> = None;
                for cand in [req_op, 0x44, 0x45] {
                    if let Some(&t) = self.request_times.get(&(ip, cand)) {
                        if oldest_t.map_or(true, |ot| t < ot) {
                            oldest_t = Some(t);
                            oldest_op = Some(cand);
                        }
                    }
                }
                if let Some(op) = oldest_op {
                    if self.consume_outgoing(&(ip, op)) {
                        return true;
                    }
                }
            } else if self.consume_outgoing(&(ip, req_op)) {
                return true;
            }
            // For FirewalledRes, also check Firewalled2Req (0x53)
            if response_opcode == 0x58 && self.consume_outgoing(&(ip, 0x53)) {
                return true;
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

        let stale: Vec<(IpAddr, u8)> = self.request_times
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

    /// outgoing_requests is multiset: sending N requests to the same
    /// (addr, opcode) pair must validate N replies in any order, not
    /// just the first. This was the root cause of `publish_confirmed`
    /// being stuck at 0 — the old `HashSet` collapsed duplicates so only
    /// the first ack per peer ever validated.
    #[test]
    fn outgoing_requests_multiset_counts_each_ack() {
        let mut fp = FloodProtection::new();
        let addr: SocketAddr = "203.0.113.9:4672".parse().unwrap();
        // Track five PublishSourceReq sends to the same peer.
        for _ in 0..5 {
            fp.track_request(addr, 0x44);
        }
        // Each incoming PublishRes should validate against one of
        // those entries until all are consumed.
        for i in 0..5 {
            assert!(
                fp.validate_response(addr, 0x4B),
                "PublishRes #{} must match a tracked request",
                i + 1
            );
        }
        // The sixth PublishRes has no backing request and must be
        // rejected as unsolicited.
        assert!(
            !fp.validate_response(addr, 0x4B),
            "6th PublishRes must be rejected once all 5 tracked requests are consumed"
        );
    }

    /// eMule matches acks by IP only (`AddTrackedOutPacket(dwIP, …)`).
    /// A peer behind NAT may reply from a different source port than we
    /// sent to; the old SocketAddr-keyed table dropped those acks as
    /// unsolicited, which was a second cause of `publish_confirmed=0`.
    #[test]
    fn validate_response_matches_across_source_ports() {
        let mut fp = FloodProtection::new();
        let sent_to: SocketAddr = "203.0.113.9:4672".parse().unwrap();
        let reply_from: SocketAddr = "203.0.113.9:54321".parse().unwrap();
        fp.track_request(sent_to, 0x44);
        assert!(
            fp.validate_response(reply_from, 0x4B),
            "reply from a different source port on the same IP must still validate"
        );
    }

    /// Regression test for the `publish_confirmed=0, wire=0` symptom: an
    /// obfuscated PublishRes presents as `opcode_hint=0xFF` before
    /// decryption, and eMule's `InTrackListIsAllowedPacket` falls through
    /// to `default: return 0;` for anything that isn't a tracked request
    /// opcode. So responses — encrypted or not — must never be
    /// rate-limited by the opcode layer.
    #[test]
    fn responses_bypass_per_opcode_rate_limit() {
        let mut fp = FloodProtection::new();
        let res_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        // Plain PublishRes (0x4B): 15 in a row from a known peer must
        // all pass the opcode layer. Under the old rules we'd stop at
        // DEFAULT_OPCODE_LIMIT*2 = 10 per 15s. Cap at 15 so Layer 2's
        // 40-pkt/s known-peer ceiling doesn't confuse the signal.
        for i in 0..15 {
            assert!(
                !fp.check_rate_limit_with_opcode(res_ip, true, 0x4B),
                "PublishRes #{} must not be rate-limited by opcode layer",
                i + 1
            );
        }
        // Obfuscated envelope: opcode_hint=0xFF. Must also fall through
        // the opcode layer because we can't classify it pre-decryption.
        let obf_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 43));
        for _ in 0..15 {
            assert!(!fp.check_rate_limit_with_opcode(obf_ip, true, 0xFF));
        }
        // Requests still get rate-limited. Bootstrap req limit is 2 per
        // 15s for unknown peers, so packet #3 must trip.
        let req_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 44));
        assert!(!fp.check_rate_limit_with_opcode(req_ip, false, 0x01));
        assert!(!fp.check_rate_limit_with_opcode(req_ip, false, 0x01));
        assert!(
            fp.check_rate_limit_with_opcode(req_ip, false, 0x01),
            "3rd BootstrapReq from unknown peer must be rate-limited"
        );
    }
}
