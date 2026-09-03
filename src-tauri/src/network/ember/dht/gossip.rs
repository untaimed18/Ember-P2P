//! Whether a peer's introductions are worth spending a probe on.
//!
//! Gossip is the overlay's main source of contacts and the one input nothing
//! prices. The routing table's diversity caps are keyed on address and /24, so
//! a keypair buys no bucket share on its own — but *naming* a contact is free
//! and unscored, so a peer can hand out addresses that never answer, forever,
//! at the cost of one frame. Each name costs us a probe: a datagram, usually a
//! Noise handshake behind it, and a slot in the in-flight ping map that a real
//! lead then cannot have. One `FOUND_NODE` carries up to
//! [`MAX_CONTACTS_PER_RESPONSE`](super::MAX_CONTACTS_PER_RESPONSE) of them.
//!
//! This tracks, per introducer, how many of the leads we actually probed went
//! on to answer, and trickles the probes for one whose leads almost never do.
//!
//! Three properties are deliberate, because each is a way this could do more
//! harm than the problem it addresses:
//!
//! - **An introducer with no record is trusted.** The first contacts a node
//!   ever hears about arrive this way, so a scheme that has to earn trust
//!   before it grants any closes the only door in.
//! - **It never refuses a contact.** Only probing is rationed. The table's own
//!   caps decide what may hold a slot, and a lead that answers is worth having
//!   however it arrived — this only declines to keep paying to find out.
//! - **A rationed introducer still gets sampled.** One lead in
//!   [`NOISY_SAMPLE_EVERY`] is probed regardless, so a peer whose contacts went
//!   dark during a netsplit recovers on its own instead of being written off
//!   for the life of the process. Counting tallies also decay, so old
//!   behaviour cannot pin the verdict.
//!
//! The caller decides *when* to consult this at all, and must not while its
//! own table is starved: a node with nothing has to try everything, since
//! probing junk costs only bandwidth while failing to join costs the overlay.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::EmberNodeId;

/// Probed leads an introducer must have resolved before its record decides
/// anything. Below this, one unlucky netsplit — or a single peer that went
/// offline between being named and being probed — would be the whole sample.
const MIN_SAMPLE: u32 = 8;

/// The answered share an introducer has to beat, as a reciprocal: one lead in
/// `ANSWER_RATE_FLOOR` answering is enough to stay funded.
///
/// Deliberately far below what an honest peer achieves. Gossip is *expected*
/// to be lossy — contacts churn, and a peer's table is a snapshot of who
/// answered *it* minutes ago — so the floor is set to catch an introducer whose
/// leads are essentially never real, not to grade table freshness.
const ANSWER_RATE_FLOOR: u32 = 8;

/// While an introducer is below the floor, one lead in this many is still
/// probed. This is what makes the verdict recoverable: at the floor's own
/// ratio, a reformed introducer is back to fully funded within a handful of
/// leads.
const NOISY_SAMPLE_EVERY: u32 = 8;

/// Resolved leads after which both tallies are halved, so a record reflects
/// recent behaviour rather than the whole session. Halving keeps the ratio
/// while letting new outcomes move it.
const DECAY_AFTER: u32 = 64;

/// Introducers tracked at once. Past this the least recently heard from are
/// dropped, which only forgives them.
const MAX_INTRODUCERS: usize = 512;

/// Leads awaiting an outcome. A probe resolves in seconds, so this is far
/// above steady state; it exists so a peer naming contacts faster than we
/// probe them cannot grow the map.
const MAX_PENDING_LEADS: usize = 1024;

/// How long a probed lead may sit unresolved before it is forgotten rather
/// than counted either way. The ping sweep resolves these within its own
/// timeout; this is the backstop for a probe that never reached the sweep at
/// all, and forgetting is the neutral outcome.
const PENDING_TTL: Duration = Duration::from_secs(300);

/// How long an introducer's record outlives its last lead.
const INTRODUCER_TTL: Duration = Duration::from_secs(3600);

/// One introducer's record.
#[derive(Debug, Clone, Copy)]
struct Introducer {
    /// Leads it named that we probed and that answered.
    answered: u32,
    /// Leads it named that we probed and that never answered.
    silent: u32,
    /// Leads skipped since it was last allowed one, driving
    /// [`NOISY_SAMPLE_EVERY`].
    skipped: u32,
    /// Last time it named a lead, for eviction.
    seen: Instant,
}

impl Introducer {
    fn new(now: Instant) -> Self {
        Self {
            answered: 0,
            silent: 0,
            skipped: 0,
            seen: now,
        }
    }

    fn resolved(&self) -> u32 {
        self.answered.saturating_add(self.silent)
    }

    /// Whether its leads have earned a full probe budget. `true` while the
    /// sample is too small to say, which is what keeps a cold join open.
    fn funded(&self) -> bool {
        let resolved = self.resolved();
        resolved < MIN_SAMPLE || self.answered.saturating_mul(ANSWER_RATE_FLOOR) >= resolved
    }

    fn decay(&mut self) {
        if self.resolved() >= DECAY_AFTER {
            self.answered /= 2;
            self.silent /= 2;
        }
    }
}

/// A probed lead, waiting to answer or time out.
#[derive(Debug, Clone, Copy)]
struct PendingLead {
    introducer: EmberNodeId,
    probed_at: Instant,
}

/// Per-introducer gossip reputation. See the module docs.
#[derive(Debug, Default)]
pub struct GossipReputation {
    introducers: HashMap<EmberNodeId, Introducer>,
    /// Leads probed on someone's word, keyed by the lead so an answer can find
    /// its introducer. At most one probe per lead is ever in flight — the
    /// caller skips a lead it is already pinging — so one entry per lead is
    /// enough.
    pending: HashMap<EmberNodeId, PendingLead>,
}

impl GossipReputation {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether to spend a probe on a lead this peer named.
    ///
    /// Mutates: refusing is what advances the sampling counter that later lets
    /// one through, so this must be called once per lead actually considered.
    pub fn should_probe(&mut self, introducer: &EmberNodeId) -> bool {
        let Some(record) = self.introducers.get_mut(introducer) else {
            return true;
        };
        if record.funded() {
            record.skipped = 0;
            return true;
        }
        record.skipped = record.skipped.saturating_add(1);
        if record.skipped >= NOISY_SAMPLE_EVERY {
            record.skipped = 0;
            return true;
        }
        false
    }

    /// Note that we have just probed `lead` on `introducer`'s word.
    ///
    /// Attribution starts at the probe, not at the naming: a lead we never
    /// probed can never answer, so counting it would charge an introducer for
    /// our own budget running out.
    pub fn note_probe(&mut self, introducer: EmberNodeId, lead: EmberNodeId, now: Instant) {
        self.introducers
            .entry(introducer)
            .or_insert_with(|| Introducer::new(now))
            .seen = now;
        if self.pending.len() >= MAX_PENDING_LEADS && !self.pending.contains_key(&lead) {
            return;
        }
        self.pending.insert(
            lead,
            PendingLead {
                introducer,
                probed_at: now,
            },
        );
    }

    /// A lead answered. Credits whoever named it, if anyone still has a claim.
    pub fn note_answered(&mut self, lead: &EmberNodeId) {
        let Some(entry) = self.pending.remove(lead) else {
            return;
        };
        if let Some(record) = self.introducers.get_mut(&entry.introducer) {
            record.answered = record.answered.saturating_add(1);
            record.decay();
        }
    }

    /// A probed lead never answered.
    pub fn note_silent(&mut self, lead: &EmberNodeId) {
        let Some(entry) = self.pending.remove(lead) else {
            return;
        };
        if let Some(record) = self.introducers.get_mut(&entry.introducer) {
            record.silent = record.silent.saturating_add(1);
            record.decay();
        }
    }

    /// Introducers whose leads are currently rationed — a gauge worth showing,
    /// because it separates "the table will not grow because nobody is talking
    /// to us" from "it will not grow because what we are being told is junk".
    pub fn rationed_len(&self) -> usize {
        self.introducers.values().filter(|r| !r.funded()).count()
    }

    /// Drop stale entries and hold both maps under their caps.
    pub fn prune(&mut self, now: Instant) {
        self.pending
            .retain(|_, lead| now.saturating_duration_since(lead.probed_at) < PENDING_TTL);
        self.introducers
            .retain(|_, record| now.saturating_duration_since(record.seen) < INTRODUCER_TTL);

        // Over the cap, the least recently heard from go first: an introducer
        // that has stopped talking to us cannot be spending our probes, so
        // forgetting it costs nothing.
        if self.introducers.len() > MAX_INTRODUCERS {
            let mut by_age: Vec<(EmberNodeId, Instant)> = self
                .introducers
                .iter()
                .map(|(id, record)| (*id, record.seen))
                .collect();
            by_age.sort_by_key(|(_, seen)| *seen);
            let excess = self.introducers.len() - MAX_INTRODUCERS;
            for (id, _) in by_age.into_iter().take(excess) {
                self.introducers.remove(&id);
            }
        }
        if self.pending.len() > MAX_PENDING_LEADS {
            let mut by_age: Vec<(EmberNodeId, Instant)> = self
                .pending
                .iter()
                .map(|(id, lead)| (*id, lead.probed_at))
                .collect();
            by_age.sort_by_key(|(_, probed_at)| *probed_at);
            let excess = self.pending.len() - MAX_PENDING_LEADS;
            for (id, _) in by_age.into_iter().take(excess) {
                self.pending.remove(&id);
            }
        }
    }

    #[cfg(test)]
    fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> EmberNodeId {
        EmberNodeId([n; 16])
    }

    /// Resolve `count` leads from one introducer, `answered` of them by
    /// answering. Every lead is distinct, since the pending map is keyed on it.
    fn resolve_batch(
        rep: &mut GossipReputation,
        introducer: EmberNodeId,
        count: u32,
        answered: u32,
        first_lead: u8,
    ) {
        let now = Instant::now();
        for i in 0..count {
            let lead = id(first_lead.wrapping_add(i as u8));
            rep.note_probe(introducer, lead, now);
            if i < answered {
                rep.note_answered(&lead);
            } else {
                rep.note_silent(&lead);
            }
        }
    }

    /// The first peer to talk to a cold node has no record, and refusing it
    /// would close the only route in.
    #[test]
    fn an_introducer_we_know_nothing_about_is_funded() {
        let mut rep = GossipReputation::new();
        for _ in 0..100 {
            assert!(rep.should_probe(&id(1)));
        }
        assert_eq!(rep.rationed_len(), 0);
    }

    /// Gossip is lossy by nature, so a sample too small to distinguish a
    /// netsplit from a liar must not decide anything.
    #[test]
    fn a_short_record_of_silence_is_not_enough_to_ration() {
        let mut rep = GossipReputation::new();
        resolve_batch(&mut rep, id(1), MIN_SAMPLE - 1, 0, 10);
        assert!(
            rep.should_probe(&id(1)),
            "under {MIN_SAMPLE} resolved leads there is no verdict to act on"
        );
        assert_eq!(rep.rationed_len(), 0);
    }

    /// The case this exists for: a peer naming addresses that never answer.
    #[test]
    fn an_introducer_whose_leads_never_answer_is_rationed() {
        let mut rep = GossipReputation::new();
        resolve_batch(&mut rep, id(1), MIN_SAMPLE, 0, 10);
        assert_eq!(rep.rationed_len(), 1);

        // Still sampled, so the verdict can be revisited — but only one lead in
        // `NOISY_SAMPLE_EVERY`.
        let allowed = (0..NOISY_SAMPLE_EVERY * 4)
            .filter(|_| rep.should_probe(&id(1)))
            .count();
        assert_eq!(
            allowed, 4,
            "one lead in {NOISY_SAMPLE_EVERY} still gets through"
        );
    }

    /// A peer whose table is merely stale is not the target. One answer in
    /// `ANSWER_RATE_FLOOR` keeps it fully funded.
    #[test]
    fn a_lossy_but_honest_introducer_stays_funded() {
        let mut rep = GossipReputation::new();
        resolve_batch(&mut rep, id(1), ANSWER_RATE_FLOOR, 1, 10);
        assert!(rep.should_probe(&id(1)));
        assert_eq!(rep.rationed_len(), 0);
    }

    /// Being written off must not be permanent, or a netsplit would cost a
    /// peer for the life of the process.
    #[test]
    fn a_rationed_introducer_earns_its_budget_back() {
        let mut rep = GossipReputation::new();
        resolve_batch(&mut rep, id(1), MIN_SAMPLE, 0, 10);
        assert_eq!(rep.rationed_len(), 1);

        // The sampled leads start answering.
        resolve_batch(&mut rep, id(1), 2, 2, 40);
        assert_eq!(
            rep.rationed_len(),
            0,
            "2 answered of 10 resolved beats a one-in-{ANSWER_RATE_FLOOR} floor"
        );
        assert!(rep.should_probe(&id(1)));
    }

    /// One peer's behaviour must not be readable as another's, or naming a
    /// contact would be a way to discredit whoever else named it.
    #[test]
    fn a_bad_introducer_does_not_taint_a_good_one() {
        let mut rep = GossipReputation::new();
        resolve_batch(&mut rep, id(1), MIN_SAMPLE * 2, 0, 10);
        resolve_batch(&mut rep, id(2), MIN_SAMPLE * 2, MIN_SAMPLE * 2, 60);

        assert!(!rep.should_probe(&id(1)));
        assert!(rep.should_probe(&id(2)));
        assert_eq!(rep.rationed_len(), 1);
    }

    /// Attribution starts at the probe. A lead the budget never reached says
    /// nothing about whoever named it.
    #[test]
    fn a_lead_we_never_probed_is_charged_to_nobody() {
        let mut rep = GossipReputation::new();
        rep.note_answered(&id(99));
        rep.note_silent(&id(98));
        assert_eq!(rep.rationed_len(), 0);
        assert!(rep.should_probe(&id(1)));
    }

    /// An outcome consumes its claim, so one probe cannot be counted twice.
    #[test]
    fn an_outcome_is_counted_once() {
        let mut rep = GossipReputation::new();
        let now = Instant::now();
        rep.note_probe(id(1), id(50), now);
        assert_eq!(rep.pending_len(), 1);
        rep.note_silent(&id(50));
        rep.note_silent(&id(50));
        rep.note_silent(&id(50));
        assert_eq!(rep.pending_len(), 0);

        // One silent lead of one resolved is below the floor but under the
        // minimum sample, so it still decides nothing.
        assert!(rep.should_probe(&id(1)));
    }

    /// A peer naming contacts faster than we resolve them must not grow the
    /// map without bound.
    #[test]
    fn pending_leads_stay_bounded() {
        let mut rep = GossipReputation::new();
        let now = Instant::now();
        for i in 0..(MAX_PENDING_LEADS * 2) {
            let mut raw = [0u8; 16];
            raw[..8].copy_from_slice(&(i as u64).to_le_bytes());
            rep.note_probe(id(1), EmberNodeId(raw), now);
        }
        assert!(rep.pending_len() <= MAX_PENDING_LEADS);
    }

    /// A probe that never reaches the ping sweep is forgotten rather than
    /// counted, because forgetting is the outcome that assumes nothing.
    #[test]
    fn an_unresolved_probe_expires_without_a_verdict() {
        let mut rep = GossipReputation::new();
        let probed = Instant::now();
        rep.note_probe(id(1), id(50), probed);
        rep.prune(probed + PENDING_TTL + Duration::from_secs(1));
        assert_eq!(rep.pending_len(), 0);

        // And the late answer finds no claim to credit.
        rep.note_answered(&id(50));
        assert!(rep.should_probe(&id(1)));
    }

    /// Old behaviour must not outweigh current behaviour forever.
    #[test]
    fn tallies_decay_so_a_verdict_tracks_recent_behaviour() {
        let mut rep = GossipReputation::new();
        resolve_batch(&mut rep, id(1), DECAY_AFTER, 0, 100);
        let record = rep.introducers[&id(1)];
        assert!(
            record.resolved() < DECAY_AFTER,
            "a record past {DECAY_AFTER} resolved leads is halved, not kept whole"
        );
        assert!(!record.funded(), "halving preserves the ratio");
    }

    /// An introducer that stopped talking to us cannot be spending probes, so
    /// its record is not worth memory.
    #[test]
    fn a_silent_introducers_record_is_forgotten() {
        let mut rep = GossipReputation::new();
        let then = Instant::now();
        rep.note_probe(id(1), id(50), then);
        rep.note_silent(&id(50));
        rep.prune(then + INTRODUCER_TTL + Duration::from_secs(1));
        assert_eq!(rep.rationed_len(), 0);
        assert!(rep.introducers.is_empty());
    }
}
