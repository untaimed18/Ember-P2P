//! Cross-session bootstrap cache for the Ember DHT.
//!
//! `nodes_ember.dat` used to be written straight from the routing table, which
//! made the file a *mirror* of live state rather than an address book. Two
//! consequences followed, and together they cost a node most of what it knew on
//! every restart:
//!
//! * The table is only one of the three places a contact can live. The
//!   replacement cache holds contacts a full bucket or a not-yet-loaded IP
//!   filter turned away, and `ember_session_dht_contacts` holds firsthand peers
//!   the public table refuses outright (LAN and CGNAT while `block_private_ips`
//!   is on). Both are counted in the overlay figure the UI shows, and neither
//!   was ever persisted — so the number on screen could be several times what
//!   the file held.
//! * Restored contacts come back unverified by design (see
//!   [`super::bootstrap::load_nodes`]), so a peer that is not reachable in the
//!   first three maintenance ticks is evicted about three minutes in. The
//!   five-minute periodic save then wrote the culled table back over the file it
//!   had just been loaded from. Because the file's only input was the set that
//!   had just been decimated, it could never recover: every restart during which
//!   peers happened to be offline permanently shrank it, one way, until a single
//!   contact was left.
//!
//! This cache breaks that ratchet by separating "we cannot route through this
//! peer right now" from "stop remembering this peer". Eviction from the table
//! stays as aggressive as it was — a lead that will not answer must not hold a
//! bucket slot — while the cache forgets an address only when it runs out of
//! room for it.
//!
//! Capacity is the only reason to forget, deliberately. Silence is recorded as a
//! per-entry miss count, but that count ranks an address rather than condemning
//! it: dead entries sink, and are pushed out of the file by better ones as they
//! are found. Deleting on a miss threshold instead reads as sound until you
//! apply it to a small network — this overlay currently has about six reachable
//! nodes, so "drop anything silent for five sessions" would discard five of the
//! six addresses a node knows because their owners had their laptops shut for a
//! few evenings, at exactly the moment those addresses were the only way back
//! in. Under a cap nothing is ever forgotten while there is room to keep it, and
//! a node that has met thousands of peers still keeps only the best of them.

use std::collections::{HashMap, HashSet};

use super::{EmberContact, EmberNodeId};

/// How long a session must have run before its silence counts as evidence.
///
/// A miss is supposed to mean "we tried this peer and it did not answer". A
/// session that lasted twenty seconds tried nobody: liveness pings go out on a
/// 60-second tick and a lead needs three unanswered ones to be considered dead,
/// so anything shorter than that is silence about the peer, not from it.
/// Without this floor a handful of quick restarts — exactly what happens while
/// testing, or when an update relaunches the app — would sink every address in
/// the book for something none of their owners did.
pub const MIN_RETIREMENT_SESSION_SECS: i64 = 300;

/// A remembered peer, plus how many consecutive sessions have tried it and
/// heard nothing back.
#[derive(Debug, Clone)]
pub struct CachedContact {
    pub contact: EmberContact,
    pub misses: u8,
}

impl CachedContact {
    pub fn new(contact: EmberContact) -> Self {
        Self { contact, misses: 0 }
    }
}

/// Every Ember peer this node remembers, across restarts.
pub struct BootstrapCache {
    entries: HashMap<EmberNodeId, CachedContact>,
    /// Entries that came off disk at launch. Only these can be charged a miss:
    /// an address learned mid-session has not yet had a session's worth of
    /// opportunity to answer, and charging it on the way out would count one
    /// unlucky moment as a failed session.
    loaded: HashSet<EmberNodeId>,
    /// Entries already handed to the routing table this session, so a batch is
    /// offered once rather than re-offered every time its contents are evicted.
    /// See [`Self::seed_batch`]. Cleared by [`Self::rearm_offers`].
    offered: HashSet<EmberNodeId>,
    /// Entries the table actually accepted this session.
    ///
    /// Deliberately separate from `offered`, which carries a different meaning
    /// and a different lifetime. `offered` answers "don't hand this out again"
    /// and is cleared when the overlay collapses; this answers "we really did
    /// try this address, so its silence is evidence" and must only ever grow.
    /// Sharing one set meant the re-arm threw away the miss evidence — and it
    /// fires precisely when the book is full of addresses that did not answer,
    /// so the sessions with the most to record were the ones that recorded
    /// least. An address the table refused never belongs here either: it was
    /// never dialled, so its silence says nothing.
    dialled: HashSet<EmberNodeId>,
    /// When this session began, in the same epoch as [`EmberContact::last_seen`].
    /// A stored contact counts as proven *this* session when its timestamp is at
    /// or past this, which is what separates "answered us since launch" from
    /// "answered a previous run" without a second set of bookkeeping.
    session_started_at: i64,
}

impl Default for BootstrapCache {
    fn default() -> Self {
        Self::new()
    }
}

impl BootstrapCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            loaded: HashSet::new(),
            offered: HashSet::new(),
            dialled: HashSet::new(),
            session_started_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Seed the cache from `nodes_ember.dat`.
    ///
    /// The persisted `last_seen` is kept here — it is what ranks the file and
    /// what [`Self::trim_to`] compares against — but deliberately
    /// *not* carried into the routing table; see [`Self::seed_batch`].
    pub fn load(&mut self, mut entries: Vec<CachedContact>) {
        for entry in &mut entries {
            // Force every restored timestamp strictly before this session.
            //
            // `reached_someone` asks whether any entry was heard from at or
            // after `session_started_at`, and answers "did we reach anybody, or
            // are we the ones offline". A file written by a session whose clock
            // ran fast — or corrected by NTP since — would otherwise answer yes
            // on the strength of its own stale contents, in the one case the
            // guard exists for. Such an entry could also never be superseded,
            // because an observation only wins if it is strictly newer, so it
            // would hold the top of the ranking permanently.
            //
            // `min` rather than `clamp`: `clamp` panics when its bounds cross,
            // which a pre-1970 system clock would do.
            entry.contact.last_seen = entry
                .contact
                .last_seen
                .min(self.session_started_at.saturating_sub(1))
                .max(0);
            self.loaded.insert(entry.contact.node_id);
        }
        for entry in entries {
            self.entries.insert(entry.contact.node_id, entry);
        }
    }

    /// Fold the current overlay into the cache.
    ///
    /// Callers pass everything worth remembering from wherever it currently
    /// lives — bucket contacts, verified replacement-cache entries, verified
    /// session peers — and this keeps the better of what it is told and what it
    /// already holds. An unverified copy never overwrites a proven one: gossip
    /// re-announcing a peer we have actually spoken to must not erase the
    /// timestamp that says so, or the next shutdown would read it as a session
    /// that failed to reach the peer.
    pub fn observe<'a>(&mut self, contacts: impl Iterator<Item = &'a EmberContact>) {
        for contact in contacts {
            match self.entries.get_mut(&contact.node_id) {
                Some(entry) => {
                    if contact.last_seen > entry.contact.last_seen {
                        entry.contact = contact.clone();
                        entry.misses = 0;
                    }
                }
                None => {
                    self.entries
                        .insert(contact.node_id, CachedContact::new(contact.clone()));
                }
            }
        }
    }

    /// Charge a miss against every loaded entry this session never heard from,
    /// so silence sinks an address in the ranking. Returns how many were
    /// charged. Nothing is deleted here — see [`Self::trim_to`].
    ///
    /// Run once, on the way out. From the periodic save it would turn a session
    /// into five minutes and give a merely-busy peer a miss every tick.
    ///
    /// Nothing is charged unless this session reached *somebody*. Silence from
    /// every peer at once is far better evidence that our own connectivity was
    /// down — no uplink, a firewall, a UDP socket that never bound — than that
    /// every remembered address died simultaneously, and blaming the address
    /// book for it would sink every entry we own over a few offline launches. A
    /// node that really is isolated therefore keeps its ranking intact, which is
    /// exactly what it needs to get back in.
    pub fn charge_silent_session(&mut self, now: i64) -> usize {
        if now.saturating_sub(self.session_started_at) < MIN_RETIREMENT_SESSION_SECS {
            return 0;
        }
        let reached_someone = self
            .entries
            .values()
            .any(|entry| entry.contact.last_seen >= self.session_started_at);
        if !reached_someone {
            return 0;
        }
        let mut charged = 0;
        for id in &self.loaded {
            // Only addresses the routing table actually took, and therefore
            // dialled. A batch is 32 and a top-up runs every few minutes, so a
            // short session never tries most of a full book — and charging the
            // untried tail is both untrue and self-reinforcing, since misses
            // also sink an address in `seed_batch` and make it even less likely
            // to be tried next time. This is precisely the "session's worth of
            // opportunity" the `loaded` field exists to require.
            if !self.dialled.contains(id) {
                continue;
            }
            let Some(entry) = self.entries.get_mut(id) else {
                continue;
            };
            if entry.contact.last_seen >= self.session_started_at {
                entry.misses = 0;
            } else {
                entry.misses = entry.misses.saturating_add(1);
                charged += 1;
            }
        }
        charged
    }

    /// How many addresses we handed the table are still sitting there unproven.
    ///
    /// What the top-up gate has to measure. Counting *every* unverified bucket
    /// entry instead conflates our seeds with ordinary gossip, and gossip
    /// arrives far faster: two answered `FIND_NODE`s put forty leads in the
    /// table, which pins the gate shut while the verified count is still ~2 and
    /// the rest of the address book — the entries with real history — never
    /// gets dialled at all.
    pub fn offers_outstanding(&self, held_leads: &HashSet<EmberNodeId>) -> usize {
        self.offered.iter().filter(|id| held_leads.contains(id)).count()
    }

    /// How many addresses the book holds.
    ///
    /// The network loop's maintenance gate reads this. That gate asks whether
    /// there is anything worth running a cycle for, and it used to ask only
    /// about live state — routing contacts, session contacts, cached Noise
    /// keys, keyless eD2K peers, a fresh friend session. A remembered address
    /// is none of those and is exactly what a cycle would act on: both the
    /// top-up that offers this book to the table and the
    /// [`Self::rearm_offers`] that makes a spent book offerable again run
    /// *inside* the cycle. So a node that lost all its live state kept an
    /// address book it could no longer reach, which is the restart-only
    /// ratchet this whole module exists to break.
    pub fn remembered_len(&self) -> usize {
        self.entries.len()
    }

    /// Allow every remembered address to be offered to the table again.
    ///
    /// `offered` otherwise only grows, and once the book has been walked
    /// through `seed_batch` returns nothing for the rest of the session. That
    /// is right while the table is holding what it was given, and wrong the
    /// moment the table loses it — a suspend/resume, an interface or VPN
    /// change, an `ipfilter.dat` reload or a `block_private_ips` toggle can
    /// empty it outright, and without this the node cannot re-dial a single
    /// remembered peer until it is restarted, however reachable they all are.
    pub fn rearm_offers(&mut self) {
        self.offered.clear();
    }

    /// Record that the routing table accepted these addresses, so their silence
    /// counts against them at shutdown. See the `dialled` field.
    pub fn note_offered(&mut self, admitted: impl Iterator<Item = EmberNodeId>) {
        self.dialled.extend(admitted);
    }

    /// Forget the worst-ranked entries until at most `max` remain. Returns how
    /// many were dropped.
    ///
    /// The only thing that removes an address, and it only fires when a better
    /// one needs the slot. `max` is the same ceiling the file is written under,
    /// so anything trimmed here would not have been persisted anyway — this just
    /// stops a long session's in-memory set from growing past what it can ever
    /// save.
    pub fn trim_to(&mut self, local_id: &EmberNodeId, max: usize) -> usize {
        if self.entries.len() <= max {
            return 0;
        }
        let keep: HashSet<EmberNodeId> = self
            .snapshot(local_id, max)
            .into_iter()
            .map(|entry| entry.contact.node_id)
            .collect();
        let before = self.entries.len();
        self.entries.retain(|id, _| keep.contains(id));
        // The side sets are keyed by the same ids, so they have to shrink with
        // them or they accumulate ids for entries that no longer exist — which
        // over a long session is exactly the unbounded growth this bounds.
        self.offered.retain(|id| keep.contains(id));
        self.dialled.retain(|id| keep.contains(id));
        self.loaded.retain(|id| keep.contains(id));
        before - self.entries.len()
    }

    /// The entries to write, best first, capped at `max`.
    ///
    /// Ordered by how much we trust the address: peers that have never missed a
    /// session, then ones we have actually heard from, then — as the original
    /// table export did, and for the same reason KAD does — by XOR distance, so
    /// the buckets closest to home are the ones a restart can refill first.
    pub fn snapshot(&self, local_id: &EmberNodeId, max: usize) -> Vec<CachedContact> {
        let mut out: Vec<&CachedContact> = self.entries.values().collect();
        out.sort_by_key(|entry| Self::rank(local_id, entry));
        out.into_iter().take(max).cloned().collect()
    }

    /// How much an address is worth keeping and trying, best first.
    ///
    /// Having actually reached a peer outranks everything, and that ordering
    /// matters more than it looks. Ranking on `misses` first put every
    /// never-contacted gossip lead — which enters at zero — ahead of a peer we
    /// have talked to for months but which was asleep last night and so carries
    /// one miss. [`Self::trim_to`] would then delete the real address to keep
    /// the hearsay, which is the opposite of the job. It was reachable without
    /// an adversary and trivial with one: a peer answering `FIND_NODE` with
    /// twenty invented contacts, repeated, injects unlimited zero-miss entries
    /// and flushes the whole book.
    ///
    /// Within each tier, fewer missed sessions first, then XOR distance, so a
    /// proven address that has stopped answering still sinks — just never below
    /// something we have only been told about.
    fn rank(local_id: &EmberNodeId, entry: &CachedContact) -> (bool, u8, [u8; 16]) {
        (
            !entry.contact.is_verified(),
            entry.misses,
            local_id.distance(&entry.contact.node_id).0,
        )
    }

    /// The next batch of remembered peers to hand the routing table, best
    /// first, skipping anything it already holds or has already been offered
    /// this session.
    ///
    /// Handed over a batch at a time rather than all at once, because the table
    /// cannot preserve the ranking. `contacts_due_for_ping` reads leads out of
    /// the buckets in index order and ranks them only by how many pings they
    /// have already missed, so once a contact is in the table there is nothing
    /// left to say it was the one we trusted most. Seeding a full address book
    /// therefore buried the peers most likely to answer behind whatever
    /// happened to be closest in XOR space: at 32 pings a tick and three ticks
    /// before a dead lead gives up its slot, 200 remembered peers is upwards of
    /// twenty minutes before the useful ones are even dialled — the opposite of
    /// what remembering them was for. A batch the ping budget can clear in a
    /// single tick keeps the ranking meaningful, and the table is topped up as
    /// leads fail.
    ///
    /// `last_seen` and `failed_queries` are cleared: a contact we have not
    /// spoken to since launch has proven nothing to *this* session, and the
    /// table's staleness purge would delete the whole bootstrap set before a
    /// single ping went out if it were handed timestamps from the last run.
    /// Zero also sorts them first for liveness probing, which is the order we
    /// want. The cache keeps the real timestamps either way.
    ///
    /// Offers are remembered so a batch cannot be handed over twice. Without
    /// that, a dead lead evicted after three missed pings would leave the table,
    /// stop being excluded, and be offered straight back — the top-up would
    /// re-dial the same corpses forever and never reach the rest of the book.
    pub fn seed_batch(
        &mut self,
        local_id: &EmberNodeId,
        held: &HashSet<EmberNodeId>,
        max: usize,
    ) -> Vec<EmberContact> {
        if max == 0 {
            return Vec::new();
        }
        let mut ranked: Vec<&CachedContact> = self
            .entries
            .values()
            .filter(|entry| {
                !self.offered.contains(&entry.contact.node_id)
                    && !held.contains(&entry.contact.node_id)
            })
            .collect();
        ranked.sort_by_key(|entry| Self::rank(local_id, entry));

        let batch: Vec<EmberContact> = ranked
            .into_iter()
            .take(max)
            .map(|entry| EmberContact {
                last_seen: 0,
                failed_queries: 0,
                ..entry.contact.clone()
            })
            .collect();
        for contact in &batch {
            self.offered.insert(contact.node_id);
        }
        batch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn contact(seed: u8, last_seen: i64) -> EmberContact {
        let vk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key();
        EmberContact {
            node_id: EmberNodeId(crate::network::ember::crypto::node_id_from_public_key(&vk)),
            addr: SocketAddr::from(([80, 1, 2, seed], 4672)),
            noise_pub: [seed; 32],
            ed25519_pub: vk.to_bytes(),
            last_seen,
            failed_queries: 0,
        }
    }

    /// Stand-in for `EMBER_PERSIST_MAX_CONTACTS`, which lives in the network
    /// layer; only its relation to the fixture sizes matters here.
    const EMBER_TEST_CAP: usize = 200;

    fn cache_started_at(started_at: i64) -> BootstrapCache {
        let mut cache = BootstrapCache::new();
        cache.session_started_at = started_at;
        cache
    }

    fn cache_of(entries: &[CachedContact]) -> BootstrapCache {
        let mut cache = cache_started_at(1_000);
        cache.load(entries.to_vec());
        cache
    }

    /// The bug this type exists for: the table is culled a few minutes into a
    /// session, and the save that follows must not take the file down with it.
    #[test]
    fn a_save_after_the_table_is_culled_does_not_shrink_the_file() {
        let local = EmberNodeId([0; 16]);
        let mut cache = cache_started_at(1_000);
        cache.load((1..=6).map(|i| CachedContact::new(contact(i, 900))).collect());

        // One peer answers; the other five are evicted as unreachable leads, so
        // the routing table now offers exactly one contact to persist.
        let survivor = contact(1, 1_100);
        cache.observe(std::iter::once(&survivor));

        assert_eq!(
            cache.snapshot(&local, 200).len(),
            6,
            "the five evicted peers must still be remembered"
        );
    }

    /// Forgetting is allowed, but only on evidence gathered across restarts.
    #[test]
    fn an_address_is_forgotten_only_after_repeated_silent_sessions() {
        let local = EmberNodeId([0; 16]);
        let dead = contact(1, 900);
        let reachable = contact(2, 1_100);
        let mut entries = vec![CachedContact::new(dead.clone())];

        // Ten restarts in which it never answers, far past any threshold a
        // punishment-based policy would have used.
        for _ in 0..10 {
            let mut cache = cache_started_at(1_000);
            cache.load(entries.clone());
            // Handed to the table *and accepted by it*, so its silence is
            // something we actually tried for — silence from an address we
            // never dialled is not evidence and is not charged.
            let batch = cache.seed_batch(&local, &HashSet::new(), 200);
            cache.note_offered(batch.iter().map(|c| c.node_id));
            // Somebody answers, so this session's silence is evidence about
            // that one address rather than about our own connectivity.
            cache.observe(std::iter::once(&reachable));
            cache.charge_silent_session(1_000 + MIN_RETIREMENT_SESSION_SECS);
            cache.trim_to(&local, 200);
            entries = cache.snapshot(&local, 200);
        }

        let dead_entry = entries
            .iter()
            .find(|e| e.contact.node_id == dead.node_id)
            .expect("an address is never forgotten while there is room to keep it");
        assert!(
            dead_entry.misses >= 10,
            "but its silence is recorded, so better addresses outrank it"
        );
        let ranked = cache_of(&entries).snapshot(&local, 200);
        assert_eq!(
            ranked[0].contact.node_id, reachable.node_id,
            "and the peer that answers is offered first"
        );
    }

    /// The small-network case that makes a miss threshold the wrong policy: a
    /// handful of peers who happen to be asleep are the only way back in.
    #[test]
    fn a_tiny_address_book_is_never_thinned() {
        let local = EmberNodeId([0; 16]);
        let mut entries: Vec<CachedContact> =
            (1..=6).map(|i| CachedContact::new(contact(i, 900))).collect();

        for _ in 0..20 {
            let mut cache = cache_started_at(1_000);
            cache.load(entries.clone());
            let one_answers = contact(1, 1_100);
            cache.observe(std::iter::once(&one_answers));
            cache.charge_silent_session(1_000 + MIN_RETIREMENT_SESSION_SECS);
            cache.trim_to(&local, EMBER_TEST_CAP);
            entries = cache.snapshot(&local, EMBER_TEST_CAP);
        }

        assert_eq!(
            entries.len(),
            6,
            "all six addresses survive twenty sessions of five of them being offline"
        );
    }

    /// Room is the only reason to forget, and the worst-ranked go first.
    #[test]
    fn trimming_drops_the_least_trusted_first() {
        let local = EmberNodeId([0; 16]);
        let mut cache = cache_started_at(1_000);
        cache.load(
            (1..=6)
                .map(|i| CachedContact {
                    contact: contact(i, if i <= 2 { 1_100 } else { 0 }),
                    misses: if i <= 2 { 0 } else { 7 },
                })
                .collect(),
        );

        assert_eq!(cache.trim_to(&local, 2), 4);
        let kept = cache.snapshot(&local, 10);
        assert_eq!(kept.len(), 2);
        assert!(
            kept.iter().all(|e| e.misses == 0),
            "the proven pair is what survives the squeeze"
        );
        assert_eq!(cache.trim_to(&local, 2), 0, "trimming again is a no-op");
    }

    /// Handing an address to the table is not the same as the table taking it:
    /// the IP policy and the diversity caps refuse contacts outright, and a
    /// refused one is never dialled, so its silence proves nothing. Charging it
    /// anyway would let a whole book be spent without a single peer contacted.
    #[test]
    fn an_address_the_table_refused_is_not_counted_as_tried() {
        let mut cache = cache_started_at(1_000);
        let local = EmberNodeId([0; 16]);
        cache.load((1..=4).map(|i| CachedContact::new(contact(i, 900))).collect());

        let batch = cache.seed_batch(&local, &HashSet::new(), 4);
        assert_eq!(batch.len(), 4);
        // The table accepted only one of them.
        cache.note_offered(std::iter::once(batch[0].node_id));

        // With somebody reached, only the admitted one is charged.
        let answered = EmberContact {
            last_seen: 1_100,
            ..contact(9, 0)
        };
        cache.observe(std::iter::once(&answered));
        assert_eq!(
            cache.charge_silent_session(1_000 + MIN_RETIREMENT_SESSION_SECS),
            1,
            "only the address the table actually took owes a miss"
        );
    }

    /// The maintenance gate in the network loop asks the book whether a cycle
    /// is worth running, and the case that matters is the one where every other
    /// signal has already gone: contacts faulted out, the Noise-key cache
    /// expired, the eD2K side quiet. The book has to keep saying it remembers
    /// someone even after its entries have been offered and nobody answered —
    /// reporting "empty" there is what left a node dark until it was restarted,
    /// holding a perfectly good address book it could no longer reach.
    #[test]
    fn a_spent_book_still_reports_that_it_remembers_someone() {
        let mut cache = cache_started_at(1_000);
        let local = EmberNodeId([0; 16]);
        cache.load(
            (1..=3)
                .map(|i| CachedContact::new(contact(i, 900)))
                .collect(),
        );
        assert_eq!(cache.remembered_len(), 3);

        let batch = cache.seed_batch(&local, &HashSet::new(), 3);
        cache.note_offered(batch.iter().map(|c| c.node_id));
        assert!(
            cache.seed_batch(&local, &HashSet::new(), 3).is_empty(),
            "the offers are spent"
        );
        assert_eq!(
            cache.remembered_len(),
            3,
            "but a spent book is not an empty one, and the gate reads this"
        );

        // Which is what makes the re-arm reachable at all: the cycle that calls
        // it only runs because the gate above stayed open.
        cache.rearm_offers();
        assert_eq!(cache.seed_batch(&local, &HashSet::new(), 3).len(), 3);
    }

    /// Re-arming must not throw away the record of what we tried. It fires when
    /// the overlay has collapsed — the one moment the book is full of addresses
    /// that did not answer, and so the moment the evidence matters most.
    #[test]
    fn rearming_offers_keeps_the_record_of_what_was_dialled() {
        let mut cache = cache_started_at(1_000);
        let local = EmberNodeId([0; 16]);
        cache.load((1..=3).map(|i| CachedContact::new(contact(i, 900))).collect());

        let batch = cache.seed_batch(&local, &HashSet::new(), 3);
        cache.note_offered(batch.iter().map(|c| c.node_id));
        assert!(
            cache.seed_batch(&local, &HashSet::new(), 3).is_empty(),
            "the book is spent until re-armed"
        );

        cache.rearm_offers();
        assert_eq!(
            cache.seed_batch(&local, &HashSet::new(), 3).len(),
            3,
            "and re-arming hands them out again"
        );

        let answered = EmberContact {
            last_seen: 1_100,
            ..contact(9, 0)
        };
        cache.observe(std::iter::once(&answered));
        assert_eq!(
            cache.charge_silent_session(1_000 + MIN_RETIREMENT_SESSION_SECS),
            3,
            "while every address we dialled before the re-arm still owes its miss"
        );
    }

    /// A file written by a session whose clock ran fast — or corrected by NTP
    /// since — must not be able to answer "did we reach anybody this run" on
    /// the strength of its own contents. That is the one case the isolation
    /// guard exists for, and after a correction it is every entry at once.
    #[test]
    fn a_future_dated_entry_cannot_fake_having_been_reached() {
        let local = EmberNodeId([0; 16]);
        let mut cache = cache_started_at(1_000);
        let mut ahead = CachedContact::new(contact(1, 0));
        ahead.contact.last_seen = 9_999_999;
        cache.load(vec![ahead]);

        let held = cache.snapshot(&local, 10);
        assert!(
            held[0].contact.last_seen < 1_000,
            "a restored timestamp must land strictly before the session start"
        );
        // So the isolation guard still sees a session that reached nobody, and
        // charges nothing rather than wiping the ledger.
        assert_eq!(
            cache.charge_silent_session(1_000 + MIN_RETIREMENT_SESSION_SECS * 10),
            0
        );
    }

    /// If nothing answered at all, we were almost certainly the offline one.
    /// Sinking every address for that would bury a perfectly good book.
    #[test]
    fn a_session_that_reached_nobody_blames_no_one() {
        let local = EmberNodeId([0; 16]);
        let mut cache = cache_started_at(1_000);
        cache.load((1..=4).map(|i| CachedContact::new(contact(i, 900))).collect());

        assert_eq!(
            cache.charge_silent_session(1_000 + MIN_RETIREMENT_SESSION_SECS * 10),
            0
        );
        let kept = cache.snapshot(&local, 200);
        assert_eq!(kept.len(), 4);
        assert!(kept.iter().all(|e| e.misses == 0));
    }

    /// Answering once wipes the slate, so an intermittent peer never sinks.
    #[test]
    fn answering_resets_the_miss_count() {
        let local = EmberNodeId([0; 16]);
        let mut cache = cache_started_at(1_000);
        cache.load(vec![CachedContact {
            contact: contact(1, 900),
            misses: 4,
        }]);
        let answered = contact(1, 1_050);
        cache.observe(std::iter::once(&answered));
        cache.charge_silent_session(1_000 + MIN_RETIREMENT_SESSION_SECS);

        let entries = cache.snapshot(&local, 200);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].misses, 0, "a peer that answered owes nothing");
    }

    /// A run too short to have pinged anyone proves nothing, so a few quick
    /// restarts must not sink the whole book.
    #[test]
    fn a_session_too_short_to_have_tried_anyone_charges_nothing() {
        let local = EmberNodeId([0; 16]);
        let mut cache = cache_started_at(1_000);
        cache.load(vec![CachedContact::new(contact(1, 900))]);

        assert_eq!(
            cache.charge_silent_session(1_000 + MIN_RETIREMENT_SESSION_SECS - 1),
            0
        );
        assert_eq!(cache.snapshot(&local, 200)[0].misses, 0);
    }

    /// Peers the public table refuses — LAN and CGNAT session peers, and
    /// replacement-cache entries — are exactly what was being dropped before,
    /// and they enter the cache through the same door as everything else.
    #[test]
    fn contacts_the_routing_table_never_held_are_remembered() {
        let local = EmberNodeId([0; 16]);
        let mut cache = cache_started_at(1_000);

        let session_peer = contact(9, 1_100);
        cache.observe(std::iter::once(&session_peer));

        let saved = cache.snapshot(&local, 200);
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].contact.node_id, session_peer.node_id);
    }

    /// Gossip re-announcing a peer we have spoken to arrives unverified. If it
    /// overwrote the stored timestamp, shutdown would read a session that did
    /// reach the peer as one that never did.
    #[test]
    fn unverified_gossip_cannot_overwrite_a_proven_contact() {
        let local = EmberNodeId([0; 16]);
        let mut cache = cache_started_at(1_000);

        let answered = contact(1, 1_100);
        cache.observe(std::iter::once(&answered));
        let gossip = contact(1, 0);
        cache.observe(std::iter::once(&gossip));

        assert_eq!(cache.snapshot(&local, 200)[0].contact.last_seen, 1_100);
        assert_eq!(
            cache.charge_silent_session(1_000 + MIN_RETIREMENT_SESSION_SECS),
            0
        );
    }

    /// The table must never be handed last session's timestamps, or the
    /// staleness purge deletes the bootstrap set before a ping goes out.
    #[test]
    fn the_routing_seed_is_always_unproven() {
        let local = EmberNodeId([0; 16]);
        let mut cache = cache_started_at(1_000);
        cache.load(vec![CachedContact::new(contact(1, 900))]);

        let seed = cache.seed_batch(&local, &HashSet::new(), 200);
        assert_eq!(seed.len(), 1);
        assert!(seed.iter().all(|c| !c.is_verified()));
        assert!(seed.iter().all(|c| c.failed_queries == 0));
        assert_eq!(
            cache.snapshot(&local, 200)[0].contact.last_seen,
            900,
            "the cache keeps the real timestamp even though the table does not"
        );
    }

    /// The table cannot preserve the cache's ranking, so a batch has to be
    /// small enough for one tick's ping budget to clear. Handing over the whole
    /// book at once buried the peers most likely to answer.
    #[test]
    fn seeding_hands_over_the_best_peers_a_batch_at_a_time() {
        let local = EmberNodeId([0; 16]);
        let mut cache = cache_started_at(1_000);
        cache.load(
            (1..=10)
                .map(|i| CachedContact {
                    contact: contact(i, if i <= 3 { 900 } else { 0 }),
                    misses: if i <= 3 { 0 } else { 2 },
                })
                .collect(),
        );

        let first = cache.seed_batch(&local, &HashSet::new(), 3);
        assert_eq!(first.len(), 3);
        let proven: Vec<_> = (1..=3).map(|i| contact(i, 0).node_id).collect();
        assert!(
            first.iter().all(|c| proven.contains(&c.node_id)),
            "the peers we have actually reached go first"
        );

        // The table now holds them; the next top-up must move on rather than
        // re-offer, and must never hand back one already in the table.
        let held: HashSet<EmberNodeId> = first.iter().map(|c| c.node_id).collect();
        let second = cache.seed_batch(&local, &held, 3);
        assert_eq!(second.len(), 3);
        assert!(second.iter().all(|c| !held.contains(&c.node_id)));
    }

    /// A dead lead leaves the table after three missed pings, which stops it
    /// being excluded. Without the offered set the top-up would hand the same
    /// corpse straight back and never reach the rest of the book.
    #[test]
    fn an_evicted_lead_is_not_offered_back() {
        let local = EmberNodeId([0; 16]);
        let mut cache = cache_started_at(1_000);
        cache.load((1..=4).map(|i| CachedContact::new(contact(i, 0))).collect());

        let first = cache.seed_batch(&local, &HashSet::new(), 2);
        assert_eq!(first.len(), 2);

        // Every one of them was evicted, so the table holds nothing at all.
        let second = cache.seed_batch(&local, &HashSet::new(), 2);
        assert_eq!(second.len(), 2);
        assert!(
            second
                .iter()
                .all(|c| !first.iter().any(|f| f.node_id == c.node_id)),
            "an offered peer is not offered again this session"
        );

        assert!(
            cache.seed_batch(&local, &HashSet::new(), 2).is_empty(),
            "and the walk stops once the book is exhausted"
        );
    }

    /// Ranking decides what survives the cap, so the peers most likely to
    /// answer have to come first — and having actually reached one has to
    /// outrank never having tried.
    ///
    /// Ranking on misses first put every never-contacted gossip lead, which
    /// enters at zero, ahead of a peer proven over months that merely missed a
    /// session. `trim_to` would then delete the real address to keep the
    /// hearsay.
    #[test]
    fn a_proven_address_outranks_gossip_even_after_missing_sessions() {
        let local = EmberNodeId([0; 16]);
        let mut cache = cache_started_at(1_000);
        cache.load(vec![
            CachedContact {
                contact: contact(1, 900),
                misses: 3,
            },
            CachedContact {
                contact: contact(2, 0),
                misses: 0,
            },
            CachedContact {
                contact: contact(3, 900),
                misses: 0,
            },
        ]);

        let ranked = cache.snapshot(&local, 3);
        assert_eq!(
            ranked[0].contact.node_id,
            contact(3, 0).node_id,
            "proven and never missing comes first"
        );
        assert_eq!(
            ranked[1].contact.node_id,
            contact(1, 0).node_id,
            "then proven but silent for three sessions"
        );
        assert_eq!(
            ranked[2].contact.node_id,
            contact(2, 0).node_id,
            "and hearsay last, however clean its record"
        );

        // Which is what the trim then acts on.
        assert_eq!(cache.trim_to(&local, 2), 1);
        assert!(
            cache
                .snapshot(&local, 10)
                .iter()
                .all(|e| e.contact.is_verified()),
            "the squeeze drops the gossip, not the addresses we have reached"
        );
    }

    /// Silence only counts against an address the session actually dialled. A
    /// batch is 32 and a short run offers a fraction of a full book, so
    /// charging the untried tail is both untrue and self-reinforcing — misses
    /// also sink an entry in `seed_batch`, making it less likely to be tried at
    /// all next time.
    #[test]
    fn an_address_never_offered_is_never_charged() {
        let local = EmberNodeId([0; 16]);
        let mut cache = cache_started_at(1_000);
        cache.load((1..=6).map(|i| CachedContact::new(contact(i, 900))).collect());

        // Only two get handed over and taken by the table, and one answers.
        let offered = cache.seed_batch(&local, &HashSet::new(), 2);
        assert_eq!(offered.len(), 2);
        cache.note_offered(offered.iter().map(|c| c.node_id));
        let answered = EmberContact {
            last_seen: 1_100,
            ..offered[0].clone()
        };
        cache.observe(std::iter::once(&answered));

        assert_eq!(
            cache.charge_silent_session(1_000 + MIN_RETIREMENT_SESSION_SECS),
            1,
            "only the offered peer that stayed silent is charged"
        );
        let charged = cache
            .snapshot(&local, 10)
            .into_iter()
            .filter(|e| e.misses > 0)
            .count();
        assert_eq!(charged, 1, "the four never dialled owe nothing");
    }
}
