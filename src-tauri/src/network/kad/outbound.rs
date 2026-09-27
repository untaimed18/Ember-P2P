//! Outbound KAD request pacing per destination IP.
//!
//! eMule tracks every request opcode it receives per source IP
//! (`CPacketTracking::InTrackListIsAllowedPacket`). Over the budget the
//! packets are dropped, and far enough over it the sender's IP is banned
//! with `AddBannedClient` for `CLIENTBANTIME` (2 h), which also refuses our
//! eD2K TCP connections. Two algorithms are in the wild:
//!
//! - eMule 0.49/0.50a and aMule: a per-opcode counter that forgives one
//!   request every `60 s / N`; over `N` drops, over `5 * N` bans.
//! - eMule 0.60+ (`emulesource/kademlia/net/PacketTracking.cpp:100-208`): a
//!   one-minute token bucket costing `60 s / N` per request; below zero
//!   drops (and still debits), below minus three minutes bans. The lookup of
//!   the bucket to charge is inverted (`:168-170` stops at the last entry
//!   whose opcode *differs* from the incoming one), so as shipped the first
//!   opcode an IP sends starts a fresh bucket each time and every other
//!   opcode is charged to that one shared bucket.
//!
//! Two limits cover both. At most `N` requests of one opcode per rolling
//! window of a little over a minute keeps every per-opcode counter and
//! bucket at or above zero. And [`IpBucket`] charges every request, whatever
//! its opcode, at 0.72's price to one bucket per IP: that bucket never holds
//! more than the one eMule actually charges, so holding it above
//! [`AGGREGATE_FLOOR_MS`] keeps the shared bucket there too, a full two
//! minutes short of the ban. Every Ember lookup, publish, callback, firewall
//! check and ping shares these budgets per node, which is what stops
//! concurrent work that happens to converge on the same contacts from adding
//! up to a ban.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Slightly longer than eMule's one-minute window, so jitter that brings two
/// of our packets closer together in transit cannot push the `N+1`th inside
/// the peer's minute.
const WINDOW: Duration = Duration::from_secs(63);

/// Hard ceiling on tracked `(ip, opcode)` pairs, and separately on tracked
/// IPs. A full window at this size would mean ~800 distinct request targets
/// a second; past it we refuse rather than send untracked.
const MAX_ENTRIES: usize = 50_000;

/// How often the tables are swept of windows that have fully lapsed and
/// buckets that have refilled.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// eMule 0.72's bucket: one minute of tokens, in milliseconds
/// (`PacketTracking.cpp:176-177`).
const BUCKET_MS: i64 = 60_000;

/// Lowest the per-IP bucket may be driven. eMule bans below minus three
/// minutes (`PacketTracking.cpp:187`); stopping at minus one leaves two
/// minutes of margin, while still letting a lookup, a publish and a
/// firewall check land on one node inside the same minute.
const AGGREGATE_FLOOR_MS: i64 = -60_000;

/// Requests per rolling window for each tracked request opcode: the lower of
/// eMule 0.50a / aMule and eMule 0.72 wherever the two differ
/// (`PUBLISH_KEY_REQ` 3 vs 4, `PUBLISH_SOURCE_REQ` 2 vs 3). `None` for
/// responses and anything eMule does not track.
///
/// `KADEMLIA_FIREWALLED2_REQ` is folded onto `KADEMLIA_FIREWALLED_REQ` by
/// the caller, as eMule does, so the two share one budget.
fn budget(opcode: u8) -> Option<u8> {
    Some(match opcode {
        0x01 => 2,  // KADEMLIA2_BOOTSTRAP_REQ
        0x11 => 3,  // KADEMLIA2_HELLO_REQ
        0x21 => 10, // KADEMLIA2_REQ
        0x33 => 3,  // KADEMLIA2_SEARCH_KEY_REQ
        0x34 => 3,  // KADEMLIA2_SEARCH_SOURCE_REQ
        0x35 => 3,  // KADEMLIA2_SEARCH_NOTES_REQ
        0x43 => PUBLISH_KEY_REQS_PER_WINDOW as u8,
        0x44 => 2,  // KADEMLIA2_PUBLISH_SOURCE_REQ
        0x45 => 2,  // KADEMLIA2_PUBLISH_NOTES_REQ
        0x50 => 2,  // KADEMLIA_FIREWALLED_REQ (and FIREWALLED2_REQ)
        0x51 => 2,  // KADEMLIA_FINDBUDDY_REQ
        0x52 => 1,  // KADEMLIA_CALLBACK_REQ
        0x60 => 2,  // KADEMLIA2_PING
        _ => return None,
    })
}

/// `KADEMLIA2_PUBLISH_KEY_REQ` per destination per window. A keyword batch
/// is sized to this (`kad::publish`), so one whole batch always fits.
pub const PUBLISH_KEY_REQS_PER_WINDOW: usize = 3;

/// What one request costs in eMule 0.72's bucket: `MIN2MS(1) / N` with
/// 0.72's `N` (`PacketTracking.cpp:115-149`).
fn emule_072_cost_ms(opcode: u8) -> Option<i64> {
    let per_minute = match opcode {
        0x01 => 2,
        0x11 => 3,
        0x21 => 10,
        0x33..=0x35 => 3,
        0x43 => 4,
        0x44 => 3,
        0x45 => 2,
        0x50 | 0x51 => 2,
        0x52 => 1,
        0x60 => 2,
        _ => return None,
    };
    Some(BUCKET_MS / per_minute)
}

fn tracked_opcode(opcode: u8) -> u8 {
    if opcode == 0x53 {
        0x50
    } else {
        opcode
    }
}

/// Opcode of a plaintext KAD packet (`0xE4`/`0xE5` header, opcode second).
pub fn kad_packet_opcode(packet: &[u8]) -> Option<u8> {
    match packet {
        [0xE4 | 0xE5, opcode, ..] => Some(*opcode),
        _ => None,
    }
}

/// Our estimate of the bucket eMule 0.72 charges for one IP.
#[derive(Clone, Copy)]
struct IpBucket {
    tokens_ms: i64,
    latest: Instant,
}

impl IpBucket {
    fn refilled(&self, now: Instant) -> i64 {
        let elapsed = now.saturating_duration_since(self.latest).as_millis();
        let elapsed = i64::try_from(elapsed).unwrap_or(i64::MAX);
        self.tokens_ms.saturating_add(elapsed).min(BUCKET_MS)
    }
}

#[derive(Default)]
pub struct KadOutboundGovernor {
    sends: HashMap<(IpAddr, u8), VecDeque<Instant>>,
    buckets: HashMap<IpAddr, IpBucket>,
    last_sweep: Option<Instant>,
}

impl KadOutboundGovernor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `count` requests with `opcode` may all go to `ip` now. Records
    /// all of them when they may and none when they may not, so a multi-packet
    /// request never goes out partially. Responses and untracked opcodes
    /// always may.
    pub fn allow_many(&mut self, ip: IpAddr, opcode: u8, count: usize) -> bool {
        self.allow_at(ip, opcode, count, Instant::now())
    }

    /// Whether one request would be allowed right now, without recording
    /// anything.
    pub fn would_allow(&self, ip: IpAddr, opcode: u8) -> bool {
        self.permits(ip, tracked_opcode(opcode), 1, Instant::now())
    }

    /// How long ago the last request with `opcode` went to `ip`, if one is
    /// still inside the window.
    pub fn since_last(&self, ip: IpAddr, opcode: u8) -> Option<Duration> {
        let now = Instant::now();
        self.sends
            .get(&(ip, tracked_opcode(opcode)))
            .and_then(|window| window.back())
            .map(|t| now.saturating_duration_since(*t))
            .filter(|age| *age < WINDOW)
    }

    fn permits(&self, ip: IpAddr, opcode: u8, count: usize, now: Instant) -> bool {
        let (Some(limit), Some(cost)) = (budget(opcode), emule_072_cost_ms(opcode)) else {
            return true;
        };
        let in_window = self.sends.get(&(ip, opcode)).map_or(0, |window| {
            window
                .iter()
                .filter(|t| now.saturating_duration_since(**t) < WINDOW)
                .count()
        });
        if in_window + count > usize::from(limit) {
            return false;
        }
        let tokens = self.buckets.get(&ip).map_or(BUCKET_MS, |b| b.refilled(now));
        let charge = cost.saturating_mul(i64::try_from(count).unwrap_or(i64::MAX));
        tokens.saturating_sub(charge) >= AGGREGATE_FLOOR_MS
    }

    fn allow_at(&mut self, ip: IpAddr, opcode: u8, count: usize, now: Instant) -> bool {
        let opcode = tracked_opcode(opcode);
        let Some(cost) = emule_072_cost_ms(opcode) else {
            return true;
        };
        if budget(opcode).is_none() || count == 0 {
            return true;
        }
        self.maybe_sweep(now);
        let key = (ip, opcode);
        if (!self.sends.contains_key(&key) && self.sends.len() >= MAX_ENTRIES)
            || (!self.buckets.contains_key(&ip) && self.buckets.len() >= MAX_ENTRIES)
        {
            self.sweep(now);
            if (!self.sends.contains_key(&key) && self.sends.len() >= MAX_ENTRIES)
                || (!self.buckets.contains_key(&ip) && self.buckets.len() >= MAX_ENTRIES)
            {
                return false;
            }
        }
        if !self.permits(ip, opcode, count, now) {
            return false;
        }
        let window = self.sends.entry(key).or_default();
        while window
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= WINDOW)
        {
            window.pop_front();
        }
        window.extend(std::iter::repeat_n(now, count));
        let bucket = self.buckets.entry(ip).or_insert(IpBucket {
            tokens_ms: BUCKET_MS,
            latest: now,
        });
        bucket.tokens_ms = bucket
            .refilled(now)
            .saturating_sub(cost.saturating_mul(i64::try_from(count).unwrap_or(i64::MAX)));
        bucket.latest = now;
        true
    }

    fn maybe_sweep(&mut self, now: Instant) {
        if self
            .last_sweep
            .is_none_or(|last| now.saturating_duration_since(last) >= SWEEP_INTERVAL)
        {
            self.sweep(now);
        }
    }

    fn sweep(&mut self, now: Instant) {
        self.last_sweep = Some(now);
        self.sends.retain(|_, window| {
            window
                .back()
                .is_some_and(|t| now.saturating_duration_since(*t) < WINDOW)
        });
        // A bucket that has refilled is indistinguishable from a fresh one.
        self.buckets.retain(|_, bucket| bucket.refilled(now) < BUCKET_MS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    fn allow(g: &mut KadOutboundGovernor, ip: IpAddr, opcode: u8, at: Instant) -> bool {
        g.allow_at(ip, opcode, 1, at)
    }

    #[test]
    fn caps_each_opcode_per_destination_per_window() {
        let mut g = KadOutboundGovernor::new();
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(allow(&mut g, ip(1), 0x34, t0));
        }
        assert!(!allow(&mut g, ip(1), 0x34, t0), "fourth SEARCH_SOURCE_REQ in a minute");
        assert!(allow(&mut g, ip(2), 0x34, t0), "other destinations have their own budget");
        assert!(
            !allow(&mut g, ip(1), 0x34, t0 + Duration::from_secs(62)),
            "the window, not the bucket, is what still refuses this"
        );
        assert!(allow(&mut g, ip(1), 0x34, t0 + WINDOW));
    }

    #[test]
    fn callback_requests_are_one_per_window() {
        let mut g = KadOutboundGovernor::new();
        let t0 = Instant::now();
        assert!(allow(&mut g, ip(1), 0x52, t0));
        assert!(!allow(&mut g, ip(1), 0x52, t0 + Duration::from_secs(30)));
        assert!(allow(&mut g, ip(1), 0x52, t0 + WINDOW));
    }

    #[test]
    fn firewalled2_shares_the_firewalled_budget() {
        let mut g = KadOutboundGovernor::new();
        let t0 = Instant::now();
        assert!(allow(&mut g, ip(1), 0x50, t0));
        assert!(allow(&mut g, ip(1), 0x53, t0));
        assert!(!allow(&mut g, ip(1), 0x53, t0));
        assert!(!allow(&mut g, ip(1), 0x50, t0));
    }

    #[test]
    fn responses_are_never_paced() {
        let mut g = KadOutboundGovernor::new();
        let t0 = Instant::now();
        for _ in 0..100 {
            assert!(allow(&mut g, ip(1), 0x3B, t0), "SEARCH_RES");
            assert!(allow(&mut g, ip(1), 0x19, t0), "HELLO_RES");
            assert!(allow(&mut g, ip(1), 0x61, t0), "PONG");
        }
    }

    /// Opcodes that each fit their own window still add up per IP: two
    /// minutes of 0.72 tokens is all one node gets at once.
    #[test]
    fn different_opcodes_share_one_bucket_per_ip() {
        let mut g = KadOutboundGovernor::new();
        let t0 = Instant::now();
        // 30 s + 30 s + 20 s + 20 s + 20 s = 120 s of tokens: 60 s full, down to the floor.
        assert!(allow(&mut g, ip(1), 0x60, t0));
        assert!(allow(&mut g, ip(1), 0x51, t0));
        assert!(allow(&mut g, ip(1), 0x34, t0));
        assert!(allow(&mut g, ip(1), 0x33, t0));
        assert!(allow(&mut g, ip(1), 0x11, t0));
        assert!(
            !allow(&mut g, ip(1), 0x21, t0),
            "a REQ with its own window untouched is still over the IP's bucket"
        );
        assert!(allow(&mut g, ip(2), 0x21, t0), "another IP has its own bucket");
        assert!(
            allow(&mut g, ip(1), 0x21, t0 + Duration::from_secs(6)),
            "six seconds of refill buy one REQ"
        );
    }

    #[test]
    fn allow_many_is_all_or_nothing() {
        let mut g = KadOutboundGovernor::new();
        let t0 = Instant::now();
        assert!(g.allow_at(ip(1), 0x43, PUBLISH_KEY_REQS_PER_WINDOW, t0));
        assert!(!g.allow_at(ip(1), 0x43, 1, t0), "the batch used the whole window");

        assert!(allow(&mut g, ip(2), 0x43, t0));
        assert!(
            !g.allow_at(ip(2), 0x43, PUBLISH_KEY_REQS_PER_WINDOW, t0),
            "a batch that does not fit is refused whole"
        );
        assert!(
            g.allow_at(ip(2), 0x43, PUBLISH_KEY_REQS_PER_WINDOW - 1, t0),
            "and charged nothing, so what does fit still does"
        );
    }

    #[test]
    fn would_allow_and_since_last_do_not_charge() {
        let mut g = KadOutboundGovernor::new();
        assert!(g.would_allow(ip(1), 0x60));
        assert!(g.since_last(ip(1), 0x60).is_none());
        assert!(g.allow_many(ip(1), 0x60, 1));
        assert!(g.since_last(ip(1), 0x60).is_some());
        assert!(g.would_allow(ip(1), 0x60));
        assert!(g.would_allow(ip(1), 0x60), "asking twice spends nothing");
        assert!(g.allow_many(ip(1), 0x60, 1));
        assert!(!g.would_allow(ip(1), 0x60));
    }

    /// eMule 0.72a's `InTrackListIsAllowedPacket` for one source IP, as
    /// shipped (`inverted`) or with the lookup it was meant to have.
    struct Emule072Tracker {
        inverted: bool,
        entries: Vec<(u8, i64, i64)>,
        lowest: i64,
    }

    impl Emule072Tracker {
        fn new(inverted: bool) -> Self {
            Self {
                inverted,
                entries: Vec::new(),
                lowest: BUCKET_MS,
            }
        }

        fn receive(&mut self, opcode: u8, now_ms: i64) {
            let opcode = tracked_opcode(opcode);
            let token = emule_072_cost_ms(opcode).expect("tracked request");
            let found = if self.inverted {
                // `while (--i >= 0 && m_aTrackedRequests[i].m_byOpcode == byOpcode);`
                self.entries.iter().rposition(|(op, _, _)| *op != opcode)
            } else {
                self.entries.iter().rposition(|(op, _, _)| *op == opcode)
            };
            match found {
                Some(i) => {
                    let (_, tokens, latest) = &mut self.entries[i];
                    *tokens = (*tokens + (now_ms - *latest)).min(BUCKET_MS) - token;
                    *latest = now_ms;
                    self.lowest = self.lowest.min(*tokens);
                }
                None => self.entries.push((opcode, BUCKET_MS - token, now_ms)),
            }
        }
    }

    /// Offers far more mixed traffic to one IP than it may take — a request
    /// every 250 ms for twenty minutes, cycling every tracked opcode — and
    /// replays what the governor lets through against both forms of eMule
    /// 0.72's tracker. The shipped form is started on an opcode that is then
    /// never sent again, the case where every later request lands on one
    /// shared bucket.
    #[test]
    fn paced_traffic_stays_clear_of_emule_072_bans() {
        let cycle = [0x21u8, 0x34, 0x33, 0x35, 0x43, 0x44, 0x45, 0x50, 0x53, 0x51, 0x52, 0x60, 0x01];
        let mut g = KadOutboundGovernor::new();
        let t0 = Instant::now();
        let mut shipped = Emule072Tracker::new(true);
        let mut intended = Emule072Tracker::new(false);
        assert!(allow(&mut g, ip(1), 0x11, t0));
        shipped.receive(0x11, 0);
        intended.receive(0x11, 0);
        let mut sent = 0usize;
        for step in 1..4800i64 {
            let at_ms = step * 250;
            let opcode = cycle[step as usize % cycle.len()];
            if !allow(&mut g, ip(1), opcode, t0 + Duration::from_millis(at_ms as u64)) {
                continue;
            }
            sent += 1;
            shipped.receive(opcode, at_ms);
            intended.receive(opcode, at_ms);
        }
        // Twenty minutes of refill is about forty requests at an average price.
        assert!(sent > 30, "the governor must still let real traffic through ({sent})");
        assert!(
            shipped.lowest >= AGGREGATE_FLOOR_MS,
            "shared bucket reached {} ms",
            shipped.lowest
        );
        assert!(shipped.lowest > -180_000, "that would be a ban");
        assert!(
            intended.lowest >= 0,
            "a per-opcode bucket dipped to {} ms, so a request was dropped",
            intended.lowest
        );
    }

    /// Per opcode alone, the paced sends never even dip an intended 0.72
    /// bucket below zero.
    #[test]
    fn paced_single_opcode_never_dips_emule_072_bucket() {
        for opcode in [0x21u8, 0x34, 0x52, 0x44, 0x43, 0x60] {
            let mut g = KadOutboundGovernor::new();
            let t0 = Instant::now();
            let mut tracker = Emule072Tracker::new(false);
            for step in 0..857i64 {
                let at_ms = step * 700;
                if allow(&mut g, ip(1), opcode, t0 + Duration::from_millis(at_ms as u64)) {
                    tracker.receive(opcode, at_ms);
                }
            }
            assert!(tracker.lowest >= 0, "opcode {opcode:#x} dipped to {}", tracker.lowest);
        }
    }

    #[test]
    fn sweep_drops_refilled_buckets() {
        let mut g = KadOutboundGovernor::new();
        let t0 = Instant::now();
        assert!(allow(&mut g, ip(1), 0x21, t0));
        g.sweep(t0 + Duration::from_secs(1));
        assert!(g.buckets.contains_key(&ip(1)));
        g.sweep(t0 + WINDOW);
        assert!(g.buckets.is_empty());
        assert!(g.sends.is_empty());
    }

    #[test]
    fn packet_opcode_reads_plain_and_packed_headers() {
        assert_eq!(kad_packet_opcode(&[0xE4, 0x34, 0]), Some(0x34));
        assert_eq!(kad_packet_opcode(&[0xE5, 0x43, 0]), Some(0x43));
        assert_eq!(kad_packet_opcode(&[0xC5, 0x90]), None);
        assert_eq!(kad_packet_opcode(&[0xE4]), None);
    }
}
