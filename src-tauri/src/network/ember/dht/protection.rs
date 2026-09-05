//! Rate limits for the Ember DHT.
//!
//! Transport-layer AEAD already rejects verbatim UDP replays; STORE
//! signature replay collapse lives in [super::engine::EmberDht]. This module
//! caps per-address frame rates and per-peer STORE rates once a Noise session
//! is up. STORE budgets are keyed on the peer's verified node ID where one is
//! known, so peers sharing a NAT do not throttle each other.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::messages::{
    MSG_BUDDY_ENDORSE_REQ, MSG_CALLBACK_REQ, MSG_FIND_NODE, MSG_FIND_VALUE, MSG_PROXY_STORE,
    MSG_STORE_BATCH, MSG_STORE_RECORD,
};

/// Sliding window for per-IP message counts.
const MSG_WINDOW: Duration = Duration::from_secs(1);
/// Max DHT frames accepted from one IP per [MSG_WINDOW].
///
/// The sustained rate this permits is about twice the number, because
/// [`WindowCounter`] measures over a trailing half window — see
/// [`MAX_LOOKUPS_PER_WINDOW`], which explains the arithmetic. Every limit in this
/// file reads the same way.
const MAX_MSGS_PER_WINDOW: u32 = 40;

/// Sliding window for lookup queries (`FIND_NODE` / `FIND_VALUE` / `CALLBACK_REQ`).
const LOOKUP_WINDOW: Duration = Duration::from_secs(10);
/// Lookup queries accepted from one address per [`LOOKUP_WINDOW`].
///
/// The frame cap above is one number for every message type, and answering a
/// lookup is far from the cheapest thing a frame can ask for: a `FIND_VALUE`
/// costs a store lookup, and both kinds cost a signature over a reply that can
/// be a hundred times the size of the question. At the flat cap one peer could ask
/// eighty times a second indefinitely — forty by the constant, doubled by the
/// half-window rule below. KAD, which has no session to hide
/// behind, holds keyword searches to five per fifteen seconds; Ember can afford
/// to be looser because a query only counts once its sender has completed a
/// Noise handshake, so its source address cannot be forged.
///
/// Two things about the effective rate, both easy to get wrong from the numbers
/// alone. [`WindowCounter`] enforces its limit over a trailing *half* window, so
/// this admits roughly twelve a second sustained rather than six. And the budget
/// is keyed on the address, not the peer's identity: the caller only resolves an
/// identity for STORE frames, because doing it for every datagram would put a
/// routing-table scan in front of the gate that exists to make junk cheap to
/// reject. Peers behind one NAT therefore share this allowance, which is
/// tolerable for a query but would not be for a STORE — hence the split.
const MAX_LOOKUPS_PER_WINDOW: u32 = 60;
/// Sliding window for STORE floods. The per-peer budget within it is adaptive
/// — see [`super::scale::NetworkScale::max_stores_per_minute`], and read it as
/// roughly double per minute sustained, for the half-window reason in
/// [`MAX_LOOKUPS_PER_WINDOW`].
const STORE_WINDOW: Duration = Duration::from_secs(60);

/// How many full per-node STORE budgets one address may spend in total.
///
/// The per-node budget is keyed on a node ID, which costs an attacker a keypair,
/// so without an address ceiling identity rotation buys an unbounded store rate
/// from a single host. This is what makes the split defensible rather than a
/// hole: peers behind one NAT still get their own allowances, up to eight of
/// them publishing flat out.
///
/// Eight, not two or three, because the honest case this protects is a NAT or a
/// seedbox host running several instances, each republishing its own library on
/// the same two-hour cadence — and refusing an honest publisher's STOREs is
/// worse than admitting a slow flood, which the operator can see and filter.
const MAX_STORE_IDENTITIES_PER_ADDR: u32 = 8;

const MAX_IP_ENTRIES: usize = 10_000;

/// A two-bucket approximation of a sliding window.
///
/// A single counter that resets wholesale is a *fixed* window, which lets a
/// sender straddle the boundary and spend twice the limit in quick
/// succession. Keeping the previous half-window's count and weighting it by
/// how far into the current half we are removes that burst while staying O(1)
/// in both time and space.
#[derive(Debug, Default)]
struct WindowCounter {
    /// Requests counted in the current half-window.
    count: u32,
    /// Requests counted in the half-window before it.
    previous: u32,
    /// Start of the current half-window.
    window_start: Option<Instant>,
}

impl WindowCounter {
    fn allow(&mut self, now: Instant, window: Duration, limit: u32) -> bool {
        self.allow_n(now, window, limit, 1)
    }

    /// Charge `cost` units against the window at once, for a frame whose work
    /// is proportional to something other than the frame itself.
    fn allow_n(&mut self, now: Instant, window: Duration, limit: u32, cost: u32) -> bool {
        if !self.would_allow_n(now, window, limit, cost) {
            return false;
        }
        self.commit_n(cost);
        true
    }

    /// [`Self::allow_n`] split in two, for a caller that has to consult a
    /// second window before either may be spent. The buckets still age here —
    /// a refused frame ages them today as well — but nothing is charged until
    /// [`Self::commit_n`].
    fn would_allow_n(&mut self, now: Instant, window: Duration, limit: u32, cost: u32) -> bool {
        let half = window / 2;
        match self.window_start {
            Some(start) if now.saturating_duration_since(start) < half => {}
            Some(start) if now.saturating_duration_since(start) < window => {
                // One half-window has elapsed: age the buckets.
                self.previous = self.count;
                self.count = 0;
                self.window_start = Some(start + half);
            }
            _ => {
                // Idle for a full window or longer: start clean.
                self.previous = 0;
                self.count = 0;
                self.window_start = Some(now);
            }
        }

        // Every arm above sets it, so the fallback is unreachable — but this
        // runs on the packet path, where a future regression that left it unset
        // would panic the network task on every rate-limit check rather than
        // mis-count one window.
        let start = self.window_start.unwrap_or(now);
        let elapsed = now.saturating_duration_since(start).min(half);
        // Weight the previous half by how much of it still overlaps the
        // trailing `window` we are approximating.
        let carry_fraction = 1.0 - (elapsed.as_secs_f64() / half.as_secs_f64().max(f64::EPSILON));
        let effective = self.count as f64 + self.previous as f64 * carry_fraction;

        effective + cost as f64 <= limit as f64
    }

    /// Spend `cost` on a counter [`Self::would_allow_n`] has just agreed to.
    fn commit_n(&mut self, cost: u32) {
        self.count = self.count.saturating_add(cost);
    }

    /// When this counter last saw traffic, for the idle-entry sweep.
    fn last_activity(&self) -> Option<Instant> {
        self.window_start
    }
}

/// Who a STORE budget belongs to.
///
/// Preferring the cryptographic node ID over the address is something KAD
/// cannot do, and it matters: peers behind one NAT would otherwise share a
/// budget and throttle each other, while an attacker with many addresses got
/// a fresh budget per address. The IP is used only until a peer's identity is
/// known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreBudgetKey {
    Node([u8; 16]),
    Addr(IpAddr),
}

/// Flood gate consulted before EmberDht::handle_message.
pub struct DhtProtection {
    msg_counters: HashMap<IpAddr, WindowCounter>,
    store_counters: HashMap<StoreBudgetKey, WindowCounter>,
    /// Lookup budgets. Shares `StoreBudgetKey` so an identity can be used if a
    /// caller ever supplies one, but in practice this is address-keyed — see
    /// [`MAX_LOOKUPS_PER_WINDOW`].
    lookup_counters: HashMap<StoreBudgetKey, WindowCounter>,
    dropped_rate: u64,
    /// STORE frames allowed per peer per [`STORE_WINDOW`], refreshed from the
    /// routing table's view of network size.
    max_stores: u32,
}

impl Default for DhtProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl DhtProtection {
    pub fn new() -> Self {
        Self {
            msg_counters: HashMap::new(),
            store_counters: HashMap::new(),
            lookup_counters: HashMap::new(),
            dropped_rate: 0,
            max_stores: super::scale::NetworkScale::Bootstrap.max_stores_per_minute(),
        }
    }

    /// Track how permissive the STORE budget should currently be.
    pub fn set_scale(&mut self, scale: super::scale::NetworkScale) {
        self.max_stores = scale.max_stores_per_minute();
    }

    /// Set the STORE budget directly.
    ///
    /// Every real budget is larger than the per-second frame cap, which would
    /// otherwise fire first and mask the behaviour under test.
    #[cfg(test)]
    fn set_max_stores_for_test(&mut self, max: u32) {
        self.max_stores = max;
    }

    /// Count of frames refused by the rate limiter. Read by this module's
    /// tests; kept for the diagnostics surface to report drops.
    #[allow(dead_code)]
    pub fn dropped_rate_limited(&self) -> u64 {
        self.dropped_rate
    }

    /// Both halves, in the order production runs them.
    ///
    /// Test-only: the packet path calls [`Self::allow_frame`] first and only
    /// then does the work needed to describe the frame, so combining them
    /// there would reinstate the table scan the split exists to move behind
    /// the gate.
    #[cfg(test)]
    fn allow_message(
        &mut self,
        ip: IpAddr,
        msg_type: u8,
        sender_id: Option<[u8; 16]>,
        store_records: u32,
    ) -> bool {
        self.allow_frame(ip) && self.allow_typed(ip, msg_type, sender_id, store_records)
    }

    /// The flat per-address frame gate on its own.
    ///
    /// Split out of [`Self::allow_message`] so a caller that has to do real
    /// work to *describe* a frame can refuse an address already over its rate
    /// before paying for it. Resolving the STORE budget's sender identity walks
    /// the whole routing table, which put a full scan in front of the gate that
    /// exists to make junk cheap to reject — so a peer holding one session
    /// could buy a table scan per datagram right up to the cap, and then the
    /// scan happened again for the frame the cap refused.
    ///
    /// Charges on success, so a caller must call this exactly once per frame
    /// and pass only frames it admitted to [`Self::allow_typed`].
    pub fn allow_frame(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        self.maybe_trim(now);

        if self.msg_counters.len() >= MAX_IP_ENTRIES && !self.msg_counters.contains_key(&ip) {
            self.dropped_rate = self.dropped_rate.saturating_add(1);
            return false;
        }

        let msg_ok =
            self.msg_counters
                .entry(ip)
                .or_default()
                .allow(now, MSG_WINDOW, MAX_MSGS_PER_WINDOW);
        if !msg_ok {
            self.dropped_rate = self.dropped_rate.saturating_add(1);
            return false;
        }
        true
    }

    /// The per-type budgets — STORE and lookup — for a frame that has already
    /// passed [`Self::allow_frame`]. Returns true when it should be processed.
    ///
    /// `sender_id` is the peer's verified node ID when one is already known
    /// for this address; the STORE budget is keyed on it in preference to the
    /// address.
    /// `store_records` is how many records the frame carries — one for a
    /// single `STORE_RECORD`, the batch count for a `STORE_BATCH`. The store
    /// budget is charged per record because that is what the work scales
    /// with: every record costs two Ed25519 verifications regardless of how
    /// many share a datagram. Charging per frame let a batch packed with the
    /// smallest legal records buy roughly twenty times the admitted work of a
    /// well-behaved publisher.
    pub fn allow_typed(
        &mut self,
        ip: IpAddr,
        msg_type: u8,
        sender_id: Option<[u8; 16]>,
        store_records: u32,
    ) -> bool {
        let now = Instant::now();

        if matches!(
            msg_type,
            MSG_STORE_RECORD | MSG_PROXY_STORE | MSG_STORE_BATCH
        ) {
            let budget_key = match sender_id {
                Some(id) => StoreBudgetKey::Node(id),
                None => StoreBudgetKey::Addr(ip),
            };
            if self.store_counters.len() >= MAX_IP_ENTRIES
                && !self.store_counters.contains_key(&budget_key)
            {
                self.dropped_rate = self.dropped_rate.saturating_add(1);
                return false;
            }
            // Peeked, not charged. Both windows have to agree before either is
            // spent: charging this one first and only then asking the address
            // gate meant a frame the address gate refused had already cost the
            // node its allowance, and a refused `STORE_BATCH` is never acked, so
            // the sender pays for the whole batch as well. That lands on exactly
            // the population the split exists for — several honest instances
            // behind one NAT, each double-charged once their shared ceiling
            // saturates.
            let cost = store_records.max(1);
            let store_ok = self
                .store_counters
                .entry(budget_key)
                .or_default()
                .would_allow_n(now, STORE_WINDOW, self.max_stores, cost);
            if !store_ok {
                self.dropped_rate = self.dropped_rate.saturating_add(1);
                return false;
            }

            // Then an aggregate ceiling on the *address*, because the budget
            // above is keyed on a node ID and a node ID is a free keypair.
            //
            // Rotating identities bought a fresh per-node budget each time, and
            // `STORE_BATCH` charges per record while the per-IP frame cap above
            // charges per frame — so one host could place records at
            // `MAX_MSGS_PER_WINDOW * MAX_STORE_BATCH_RECORDS` per second and
            // fill a 50,000-key store in well under a minute. That is the
            // supply side of the store's per-publisher share problem: the share
            // is keyed on a keypair too, so a Sybil spending one identity per
            // record is never "over share" and eviction falls back to pure XOR
            // distance from our node ID, which an attacker can grind toward.
            //
            // This does not solve that — bounding it properly still needs
            // something scarcer than a keypair — but it prices it, turning
            // "under a minute from one host" into a sustained flood that a rate
            // graph and an IP filter can act on.
            //
            // Only reached when the sender has a verified identity; without one
            // `budget_key` is already this address, and charging it twice would
            // halve the budget of the peers with the least to prove.
            let addr_key = sender_id.map(|_| StoreBudgetKey::Addr(ip));
            if let Some(addr_key) = addr_key {
                if self.store_counters.len() >= MAX_IP_ENTRIES
                    && !self.store_counters.contains_key(&addr_key)
                {
                    self.dropped_rate = self.dropped_rate.saturating_add(1);
                    return false;
                }
                let addr_ok = self
                    .store_counters
                    .entry(addr_key)
                    .or_default()
                    .would_allow_n(
                        now,
                        STORE_WINDOW,
                        self.max_stores
                            .saturating_mul(MAX_STORE_IDENTITIES_PER_ADDR),
                        cost,
                    );
                if !addr_ok {
                    self.dropped_rate = self.dropped_rate.saturating_add(1);
                    return false;
                }
            }

            self.charge_store(budget_key, cost);
            if let Some(addr_key) = addr_key {
                self.charge_store(addr_key, cost);
            }
        }

        // `BUDDY_ENDORSE_REQ` shares this budget because answering one costs a
        // signature, the same order of work as serving a lookup.
        if matches!(
            msg_type,
            MSG_FIND_NODE | MSG_FIND_VALUE | MSG_CALLBACK_REQ | MSG_BUDDY_ENDORSE_REQ
        ) {
            let budget_key = match sender_id {
                Some(id) => StoreBudgetKey::Node(id),
                None => StoreBudgetKey::Addr(ip),
            };
            if self.lookup_counters.len() >= MAX_IP_ENTRIES
                && !self.lookup_counters.contains_key(&budget_key)
            {
                self.dropped_rate = self.dropped_rate.saturating_add(1);
                return false;
            }
            let lookup_ok = self.lookup_counters.entry(budget_key).or_default().allow(
                now,
                LOOKUP_WINDOW,
                MAX_LOOKUPS_PER_WINDOW,
            );
            if !lookup_ok {
                self.dropped_rate = self.dropped_rate.saturating_add(1);
                return false;
            }
        }

        true
    }

    /// Spend an already-peeked STORE budget. The entry exists — `allow_message`
    /// created it to peek — so a miss here is unreachable rather than tolerated.
    fn charge_store(&mut self, key: StoreBudgetKey, cost: u32) {
        if let Some(counter) = self.store_counters.get_mut(&key) {
            counter.commit_n(cost);
        }
    }

    fn maybe_trim(&mut self, now: Instant) {
        if self.msg_counters.len() > MAX_IP_ENTRIES / 2 {
            self.msg_counters.retain(|_, c| {
                c.last_activity()
                    .map(|s| now.saturating_duration_since(s) < MSG_WINDOW * 4)
                    .unwrap_or(false)
            });
        }
        if self.store_counters.len() > MAX_IP_ENTRIES / 2 {
            self.store_counters.retain(|_, c| {
                c.last_activity()
                    .map(|s| now.saturating_duration_since(s) < STORE_WINDOW * 2)
                    .unwrap_or(false)
            });
        }
        if self.lookup_counters.len() > MAX_IP_ENTRIES / 2 {
            self.lookup_counters.retain(|_, c| {
                c.last_activity()
                    .map(|s| now.saturating_duration_since(s) < LOOKUP_WINDOW * 2)
                    .unwrap_or(false)
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::messages::MSG_PING;
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn rate_limits_messages_per_ip() {
        let mut p = DhtProtection::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        for _ in 0..MAX_MSGS_PER_WINDOW {
            assert!(p.allow_message(ip, MSG_PING, None, 1));
        }
        assert!(!p.allow_message(ip, MSG_PING, None, 1));
        assert_eq!(p.dropped_rate_limited(), 1);
    }

    #[test]
    fn store_budget_independent_window() {
        let mut p = DhtProtection::new();
        p.set_max_stores_for_test(5);
        let ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
        for _ in 0..5 {
            assert!(p.allow_message(ip, MSG_STORE_RECORD, None, 1));
        }
        assert!(!p.allow_message(ip, MSG_STORE_RECORD, None, 1));
        // A batch counts against the same budget as a single store.
        assert!(!p.allow_message(ip, MSG_STORE_BATCH, None, 1));
        // Non-store traffic from the same peer is unaffected.
        assert!(p.allow_message(ip, MSG_PING, None, 1));
    }

    /// One flat frame cap treated a `FIND_VALUE` — a store lookup plus a signed
    /// reply many times the size of the question — as costing the same as a
    /// `PING`, so one peer could ask forty times a second indefinitely.
    ///
    /// Note what this deliberately does *not* claim. An earlier version of this
    /// test passed an identity and asserted that moving address bought nothing,
    /// which production never does: the caller resolves an identity for STORE
    /// frames only, so lookups are address-keyed. Asserting the stronger property
    /// made the test certify a guarantee the code does not provide, which is
    /// worse than having no test at all.
    #[test]
    fn lookups_get_a_tighter_budget_than_the_flat_frame_rate() {
        // The relationship the cap exists for: over one window, far fewer
        // lookups than the flat frame cap would allow.
        assert!(
            MAX_LOOKUPS_PER_WINDOW < MAX_MSGS_PER_WINDOW * LOOKUP_WINDOW.as_secs().max(1) as u32,
            "the lookup cap has to be tighter than the flat frame cap to mean anything"
        );

        // Driven against the counter with an injected clock, because the lookup cap
        // cannot be reached through `allow_message` in real time: the 40-per-second
        // frame cap refuses first, so a tight loop only ever demonstrates *that*
        // limit. An earlier version of this test did exactly that and would have
        // stayed green with the whole lookup budget deleted.
        let mut counter = WindowCounter::default();
        let t0 = Instant::now();
        let mut allowed = 0u32;
        // Ten seconds of steady lookups, paced so the frame cap is irrelevant.
        for tick in 0..LOOKUP_WINDOW.as_secs() * 20 {
            let now = t0 + Duration::from_millis(tick * 50);
            if counter.allow(now, LOOKUP_WINDOW, MAX_LOOKUPS_PER_WINDOW) {
                allowed += 1;
            }
        }
        assert!(
            allowed < MAX_LOOKUPS_PER_WINDOW * 2,
            "the window must refuse a sustained flood: {allowed} admitted"
        );
        assert!(
            allowed >= MAX_LOOKUPS_PER_WINDOW,
            "and must not refuse an honest burst either: only {allowed} admitted"
        );

        // Then the wiring: a lookup frame is charged to this budget, both kinds
        // share it, and it is address-keyed because the caller supplies no identity.
        let mut p = DhtProtection::new();
        let noisy = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let quiet = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(p.allow_message(noisy, MSG_FIND_VALUE, None, 1));
        assert!(p.allow_message(noisy, MSG_FIND_NODE, None, 1));
        assert_eq!(
            p.lookup_counters.len(),
            1,
            "both lookup kinds draw on one budget per address"
        );
        assert!(p.allow_message(quiet, MSG_FIND_NODE, None, 1));
        assert_eq!(
            p.lookup_counters.len(),
            2,
            "and a different address gets its own"
        );
        // A cheap frame is not charged to it at all.
        assert!(p.allow_message(quiet, MSG_PING, None, 1));
        assert_eq!(p.lookup_counters.len(), 2);
    }

    /// Two instances behind one NAT must not eat each other's STORE budget.
    /// Ember can tell them apart because their node IDs are bound to distinct
    /// keypairs, which is a distinction KAD cannot make.
    #[test]
    fn peers_sharing_an_address_get_separate_store_budgets() {
        let mut p = DhtProtection::new();
        p.set_max_stores_for_test(5);
        let ip = IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7));

        for _ in 0..5 {
            assert!(p.allow_message(ip, MSG_STORE_RECORD, Some([1u8; 16]), 1));
        }
        assert!(
            !p.allow_message(ip, MSG_STORE_RECORD, Some([1u8; 16]), 1),
            "the first peer has spent its budget"
        );
        assert!(
            p.allow_message(ip, MSG_STORE_RECORD, Some([2u8; 16]), 1),
            "a different identity at the same address keeps its own budget"
        );
    }

    /// The per-node STORE budget is keyed on a node ID, and a node ID costs a
    /// keypair. Without an address ceiling, rotating identities bought a fresh
    /// budget per identity — and since a batch charges per record while the
    /// per-IP frame cap charges per frame, one host could fill a 50,000-key
    /// store in under a minute.
    #[test]
    fn rotating_node_ids_cannot_buy_unlimited_store_budget_from_one_address() {
        let mut p = DhtProtection::new();
        p.set_max_stores_for_test(50);
        let ip = IpAddr::V4(Ipv4Addr::new(6, 6, 6, 6));

        // Eight identities may each spend a full per-node budget.
        for id in 0..MAX_STORE_IDENTITIES_PER_ADDR as u8 {
            assert!(
                p.allow_message(ip, MSG_STORE_BATCH, Some([id; 16]), 50),
                "identity {id} is within the address ceiling"
            );
        }
        // The ninth has an untouched per-node budget and is refused anyway.
        assert!(
            !p.allow_message(ip, MSG_STORE_BATCH, Some([0xFF; 16]), 1),
            "a fresh identity must not reset the address's aggregate budget"
        );
        // A different host is unaffected: the ceiling is per address. It needs a
        // fresh identity to show that, because the per-node budget is keyed on
        // the node ID and follows a peer across addresses.
        assert!(p.allow_message(
            IpAddr::V4(Ipv4Addr::new(6, 6, 6, 7)),
            MSG_STORE_BATCH,
            Some([0xFE; 16]),
            50
        ));
    }

    /// Both STORE windows are consulted before either is charged. Charging the
    /// per-node budget first and only then asking the address gate spent an
    /// honest peer's allowance on a frame that was never processed — and since
    /// a refused `STORE_BATCH` is never acked, the sender had already paid for
    /// the whole batch. The victims are the case the split exists for: several
    /// instances behind one NAT, double-charged from the moment their shared
    /// ceiling saturates.
    #[test]
    fn a_frame_the_address_gate_refuses_leaves_the_node_budget_unspent() {
        let mut p = DhtProtection::new();
        p.set_max_stores_for_test(5);
        let crowded = IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4));

        // Saturate the address ceiling with other identities.
        for id in 0..MAX_STORE_IDENTITIES_PER_ADDR as u8 {
            assert!(p.allow_message(crowded, MSG_STORE_BATCH, Some([id; 16]), 5));
        }

        let honest = Some([0xAA; 16]);
        assert!(
            !p.allow_message(crowded, MSG_STORE_RECORD, honest, 1),
            "the shared address ceiling is spent"
        );

        // The per-node budget follows the identity, so an address with room
        // shows whether the refusal above cost it anything. All five must
        // still be there.
        let quiet = IpAddr::V4(Ipv4Addr::new(4, 4, 4, 5));
        for i in 0..5 {
            assert!(
                p.allow_message(quiet, MSG_STORE_RECORD, honest, 1),
                "store {i} of an untouched per-node budget"
            );
        }
        assert!(
            !p.allow_message(quiet, MSG_STORE_RECORD, honest, 1),
            "and no more than five, or the budget is not being charged at all"
        );
    }

    /// A batch does N records' worth of signature verification for one frame,
    /// so charging it as one frame let a densely packed batch buy many times
    /// the admitted work of a well-behaved publisher.
    #[test]
    fn a_batch_is_charged_for_the_records_it_carries() {
        let mut p = DhtProtection::new();
        p.set_max_stores_for_test(10);
        let ip = IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5));

        // One batch of eight spends eight units, not one.
        assert!(p.allow_message(ip, MSG_STORE_BATCH, None, 8));
        // Only two units remain, so a batch of three does not fit.
        assert!(!p.allow_message(ip, MSG_STORE_BATCH, None, 3));
        // But two single stores do.
        assert!(p.allow_message(ip, MSG_STORE_RECORD, None, 1));
        assert!(p.allow_message(ip, MSG_STORE_RECORD, None, 1));
        assert!(!p.allow_message(ip, MSG_STORE_RECORD, None, 1));
    }

    /// A fixed window lets a sender spend twice the limit across a boundary.
    #[test]
    fn the_window_does_not_allow_a_double_burst_at_the_boundary() {
        let mut c = WindowCounter::default();
        let window = Duration::from_secs(60);
        let limit = 10u32;
        let t0 = Instant::now();

        // Spend the whole budget late in the first window.
        for _ in 0..limit {
            assert!(c.allow(t0, window, limit));
        }
        assert!(!c.allow(t0, window, limit));

        // Just past the halfway roll, most of the previous half still counts,
        // so a fresh full burst must not be allowed.
        let t1 = t0 + window / 2 + Duration::from_millis(10);
        let mut allowed_after_roll = 0;
        for _ in 0..limit {
            if c.allow(t1, window, limit) {
                allowed_after_roll += 1;
            }
        }
        assert!(
            allowed_after_roll < limit,
            "a fixed window would have allowed a second full burst ({allowed_after_roll})"
        );

        // A full window of silence resets cleanly.
        let t2 = t1 + window * 2;
        assert!(c.allow(t2, window, limit));
    }
}
