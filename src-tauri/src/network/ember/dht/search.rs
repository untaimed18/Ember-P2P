use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use tracing::{debug, trace, warn};

use super::publish::SignedRecord;
use super::routing::RoutingTable;
use super::{EmberContact, EmberNodeId, ALPHA, K_BUCKET_SIZE};

/// Maximum concurrent searches.
const MAX_ACTIVE_SEARCHES: usize = 64;

/// How long a search can run before being considered timed out.
const SEARCH_TIMEOUT_SECS: u64 = 60;

/// Maximum results returned from a single search.
const MAX_SEARCH_RESULTS: usize = 300;

/// How much of that budget our own store may fill before the walk begins.
///
/// Half, so the network always has room. The local seed used to be limited to
/// whatever fitted one datagram — about five records — purely as a side effect of
/// sharing the wire packer, and lifting that (correctly: nothing is being sent)
/// exposed the real hazard. A node that stores a popular key could seed all 300
/// results, and `check_complete` ends a `FIND_VALUE` the moment the budget is
/// full, so the first remote reply would finish the search and nothing remote
/// would ever be merged — the node would answer every search from its own store
/// alone.
const MAX_LOCAL_SEED_RESULTS: usize = MAX_SEARCH_RESULTS / 2;

/// Blobs one node may offer a single search, whether or not they are kept.
///
/// `check_complete` ends a `FIND_VALUE` the moment the result budget is full,
/// so whoever fills it decides when the walk stops. A datagram carries at most
/// a few dozen records and a node is asked [`MAX_QUERY_ATTEMPTS`] times, which
/// puts an honest contribution well under a quarter of the budget — while a
/// flooder now needs four distinct nodes on the shortlist to crowd the walk
/// out early, instead of managing it alone.
///
/// Charged per *distinct* blob offered, not per blob accepted. Counting only
/// what survives verification would leave junk free: a forged blob costs a slot
/// in the dedup set and a signature check either way, and a peer that sends
/// nothing but junk would never reach its own limit.
///
/// A repeat of a blob this search already holds is the one thing not charged,
/// because the responder is not the only reason one arrives: a page resuming at
/// a record it passed over re-sends the tail of the previous page by design.
/// Duplicates cannot fill the result budget this cap protects — dedup drops
/// them before `MAX_SEARCH_RESULTS` sees them — so charging for them only ever
/// cut a well-stocked storer off part-way through its own key.
const MAX_RESULTS_PER_NODE: usize = MAX_SEARCH_RESULTS / 4;

/// How many times one node may be queried within a single search.
///
/// A timeout is not proof a node is gone — it may have been mid-handshake,
/// briefly saturated, or the datagram may simply have been lost. Marking it
/// failed forever on the first miss threw away real peers on lossy paths. Two
/// is the smallest value that tolerates a single loss, and it bounds the extra
/// work at one repeat query per node so a search still converges.
const MAX_QUERY_ATTEMPTS: u8 = 2;

/// Firsthand session peers [`IterativeSearch::seed_extra_contacts`] may pin
/// onto one shortlist.
///
/// Pins are exempt from the k-trim, so they are additive to the Kademlia
/// shortlist rather than competing with it, and `FIND_VALUE` exhausts the
/// shortlist rather than converging early. Half a bucket keeps the LAN/island
/// publishers this exists to reach without letting them dominate the walk —
/// the session table can hold 64, more than three times `K_BUCKET_SIZE`, and
/// querying all of them at `MAX_QUERY_ATTEMPTS` does not fit inside
/// `SEARCH_TIMEOUT_SECS` at ALPHA concurrency.
const MAX_PINNED_EXTRA_CONTACTS: usize = super::K_BUCKET_SIZE / 2;

/// Consecutive responses that bring nothing closer before a `FIND_NODE` walk
/// calls itself converged.
///
/// One round's worth: with [`ALPHA`] queries outstanding, this many answers in a
/// row that fail to improve on the best node we have seen means the frontier has
/// stopped moving. Kademlia's own termination rule is that a lookup ends once it
/// has heard from the k closest nodes it knows of, and continuing past that is
/// spending round trips to re-learn what we already have.
///
/// Deliberately not applied to `FIND_VALUE`. There, every extra node asked is
/// another chance at a record the closer ones did not hold, so recall is worth
/// more than the saved traffic — the walk keeps going until it runs out of
/// shortlist.
const STALE_RESPONSES_TO_CONVERGE: u8 = ALPHA as u8;

/// Extra `FIND_VALUE` pages one node may be asked for within a single search.
///
/// A datagram carries roughly five keyword records, so on a popular key the
/// first answer is a small fraction of what the responder holds. Paging is how
/// the rest becomes reachable, but it is also the one mechanism here that lets a
/// *responder* decide how many queries we send — it reports the total — so it
/// needs a ceiling that does not depend on that claim.
///
/// Eight keeps the round trips to one node bounded while reaching roughly forty
/// records from it, comfortably inside the [`MAX_RESULTS_PER_NODE`] allowance
/// that caps what one peer may contribute anyway. Both limits apply, so the
/// tighter one binds: a node serving large records runs out of allowance first,
/// one serving small records runs out of pages.
const MAX_PAGES_PER_NODE: u8 = 8;

/// Nodes that must have answered before convergence may end a `FIND_NODE`.
///
/// Guards the case where the first few answers happen to arrive from the nodes
/// we already had: without a floor, a walk seeded from a thin table could
/// declare itself converged after a handful of replies and never reach the
/// neighbourhood it was looking for. Half a bucket matches the bar KAD sets
/// before its own stale-round rule may fire.
const MIN_RESPONSES_TO_CONVERGE: usize = K_BUCKET_SIZE / 2;

/// Diagnostic row for one in-flight Ember DHT search (slice 16).
#[derive(Debug, Clone)]
pub struct SearchSnapshot {
    pub id: u32,
    pub search_type: String,
    pub target: String,
    pub keyword_count: u32,
    pub results: u32,
    pub queried: u32,
    pub in_flight: u32,
    pub responded: u32,
    pub pending: u32,
    pub complete: bool,
    /// Seconds since the search started (wall-clock relative).
    pub started_at_secs: u64,
}

/// What a response did for the search that received it.
///
/// The two answers are genuinely independent and collapsing them into one
/// boolean was a real bug. The caller needs `accepted` to decide whether to
/// retire the wire-request correlation entry and drive the next round; it used
/// to read `new_closer` for that, which is false for *every* `FOUND_VALUE`
/// (that path carries no contacts at all) and for any `FOUND_NODE` on a
/// converged hop. Correct answers were therefore treated as unaccepted, so the
/// lookup could not advance until the query deadline expired — a full timeout
/// per hop, against a whole-search cap only a few timeouts wide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseOutcome {
    /// The response correlated with an outstanding query and was applied.
    /// False means it was refused — unknown request id, or a sender other than
    /// the node we asked — and that query is still legitimately outstanding.
    pub accepted: bool,
    /// The response contributed a node strictly closer than the best already
    /// on the shortlist, so the search has somewhere new to go.
    pub new_closer: bool,
}

impl ResponseOutcome {
    /// A response that did not correlate with any outstanding query.
    pub const REFUSED: Self = Self {
        accepted: false,
        new_closer: false,
    };
}

/// Why a query will never be answered, which decides whether the node may be
/// asked again inside this search.
///
/// The distinction is about the caller, not the node. Returning a node with
/// attempts left to `Pending` only means anything if something is going to
/// drive the search again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryFailure {
    /// The query reached the wire and its deadline passed. The 1 Hz sweep that
    /// reports it drives the search again immediately afterwards, so a node put
    /// back on the queue really does get asked.
    TimedOut,
    /// The query never left this process — transport error, unroutable
    /// address, unusable `noise_pub`. No wire request is registered for it, so
    /// no deadline exists that could expire and re-drive the walk.
    NotSent,
}

/// State of a node in the search shortlist.
#[derive(Debug, Clone, PartialEq)]
enum NodeState {
    /// Not yet queried.
    Pending,
    /// Query sent, awaiting response.
    InFlight,
    /// Responded successfully.
    Responded,
    /// Failed or timed out.
    Failed,
}

/// A single entry in the iterative search shortlist.
struct ShortlistEntry {
    contact: EmberContact,
    distance: EmberNodeId,
    state: NodeState,
    /// Live eD2K-session peers. Kept past the k-cap and queried first so a
    /// connected publisher is asked even when it is not XOR-closest to the key.
    pinned: bool,
}

/// Type of iterative search.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SearchType {
    /// FIND_NODE: looking for nodes closest to a target.
    FindNode,
    /// FIND_VALUE: looking for records associated with keys.
    FindValue,
}

/// What a `FOUND_VALUE` reported about the records it did not carry.
///
/// Both fields are the responder's claim about its own store, so nothing here is
/// trusted beyond deciding whether to send one more query: see
/// [`IterativeSearch::queue_next_page`] for the progress and budget checks.
#[derive(Debug, Clone, Copy)]
pub struct ValuePage {
    pub next_position: u16,
    pub total_available: u16,
}

/// One query the driver should send on a search's behalf.
#[derive(Debug, Clone)]
pub struct QueryTarget {
    pub contact: EmberContact,
    /// Per-search correlation token, echoed back through
    /// [`IterativeSearch::process_response`].
    pub request_id: u32,
    /// Record offset for a `FIND_VALUE`. Zero for a `FIND_NODE` and for the
    /// first query sent to any node.
    pub start_position: u16,
}

/// A query awaiting an answer.
struct PendingQuery {
    node: EmberNodeId,
    /// The offset this query asked for. Kept so a `FOUND_VALUE` can be required
    /// to advance past it, and so a page follow-up is distinguishable from a
    /// first query (only the latter is ever zero).
    start_position: u16,
}

impl PendingQuery {
    /// Whether this query was a page follow-up rather than a node's first.
    fn is_page(&self) -> bool {
        self.start_position > 0
    }
}

/// A search result record from a FOUND_VALUE response.
#[derive(Debug, Clone)]
pub struct SearchResultRecord {
    pub data: Vec<u8>,
    /// Which node returned this record. Recorded for provenance in
    /// diagnostics and `Debug` output; callers trust the record's own
    /// publisher signature rather than the peer that relayed it.
    #[allow(dead_code)]
    pub from_node: EmberNodeId,
}

/// An active iterative search.
pub struct IterativeSearch {
    pub id: u32,
    pub search_type: SearchType,
    pub target: EmberNodeId,
    /// For multi-keyword searches: additional keyword hashes to include.
    pub keyword_hashes: Vec<[u8; 16]>,
    shortlist: Vec<ShortlistEntry>,
    /// Collected value results (for FIND_VALUE searches).
    pub results: Vec<SearchResultRecord>,
    /// BLAKE3 of every blob already in `results`.
    ///
    /// A popular record is held by many nodes, and a Kademlia walk asks twenty
    /// of them, so without this the same signed blob took a slot per peer that
    /// returned it. On a well-replicated keyword that filled
    /// [`MAX_SEARCH_RESULTS`] with copies of a handful of files and completed
    /// the search, hiding everything the later hops would have found.
    seen_results: HashSet<[u8; 32]>,
    /// Blobs each node has offered, against [`MAX_RESULTS_PER_NODE`]. Bounded
    /// by the number of nodes that answer, which the shortlist bounds.
    offered_results: HashMap<EmberNodeId, usize>,
    /// Nodes with a query currently outstanding or permanently given up on.
    /// A node that failed but has attempts left is removed, which is what
    /// makes it eligible to be picked again.
    queried: HashSet<EmberNodeId>,
    /// Queries sent per node this search, against [`MAX_QUERY_ATTEMPTS`].
    attempts: HashMap<EmberNodeId, u8>,
    /// When this search started.
    pub started_at: Instant,
    /// True when the search has converged or found enough results.
    pub complete: bool,
    /// Monotonic per-search request-ID counter. Per-call random
    /// `u32`s collide with measurable probability over a long
    /// search; on collision the previous mapping was silently
    /// overwritten and the displaced node became un-ackable until
    /// timeout. Using a counter scoped to the search makes
    /// collisions impossible within one search lifetime.
    next_request_id: u32,
    /// Request IDs we've sent mapped to what we asked for.
    pending_requests: HashMap<u32, PendingQuery>,
    /// Nodes that reported records past the page they served, with the offset to
    /// resume at. Drained by [`Self::next_to_query`].
    page_queue: VecDeque<(EmberNodeId, u16)>,
    /// Page follow-ups queued per node, against [`MAX_PAGES_PER_NODE`].
    pages_queued: HashMap<EmberNodeId, u8>,
    /// Answers in a row that brought nothing closer than the best node already
    /// on the shortlist. See [`STALE_RESPONSES_TO_CONVERGE`].
    stale_responses: u8,
}

impl IterativeSearch {
    fn new(
        id: u32,
        search_type: SearchType,
        target: EmberNodeId,
        keyword_hashes: Vec<[u8; 16]>,
        initial_contacts: Vec<EmberContact>,
    ) -> Self {
        let mut shortlist: Vec<ShortlistEntry> = initial_contacts
            .into_iter()
            .filter(|c| c.is_dialable())
            .map(|c| {
                let distance = target.distance(&c.node_id);
                ShortlistEntry {
                    contact: c,
                    distance,
                    state: NodeState::Pending,
                    pinned: false,
                }
            })
            .collect();
        shortlist.sort_by_key(|a| a.distance.0);
        shortlist.truncate(K_BUCKET_SIZE);

        Self {
            id,
            search_type,
            target,
            keyword_hashes,
            shortlist,
            results: Vec::new(),
            seen_results: HashSet::new(),
            offered_results: HashMap::new(),
            queried: HashSet::new(),
            attempts: HashMap::new(),
            started_at: Instant::now(),
            complete: false,
            pending_requests: HashMap::new(),
            page_queue: VecDeque::new(),
            pages_queued: HashMap::new(),
            next_request_id: 1,
            stale_responses: 0,
        }
    }

    /// Pull the next request id, keeping the counter monotonic within a search.
    fn take_request_id(&mut self) -> u32 {
        let req_id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);
        req_id
    }

    /// Page follow-ups currently awaiting an answer.
    fn pages_in_flight(&self) -> usize {
        self.pending_requests
            .values()
            .filter(|p| p.is_page())
            .count()
    }

    /// Get the next batch of queries to send (up to ALPHA outstanding).
    ///
    /// Two kinds of work share the budget: nodes on the shortlist that have not
    /// been asked yet, and page follow-ups to nodes that already answered with
    /// more records than their datagram could carry.
    pub fn next_to_query(&mut self) -> Vec<QueryTarget> {
        let in_flight = self
            .shortlist
            .iter()
            .filter(|e| e.state == NodeState::InFlight)
            .count()
            + self.pages_in_flight();

        let can_send = ALPHA.saturating_sub(in_flight);
        if can_send == 0 {
            return Vec::new();
        }

        let mut batch = Vec::new();

        // Page follow-ups are the cheaper half of the budget: the node has
        // already answered, so a Noise session is live and the records are known
        // to exist, where a fresh shortlist node may hold nothing. They still
        // only get half the batch while there is anywhere left to descend to —
        // a hot key would otherwise page one node for the whole search while the
        // frontier stood still, which is how a walk misses the closer nodes that
        // hold the rest of the index.
        let has_descent = self
            .shortlist
            .iter()
            .any(|e| e.state == NodeState::Pending && !self.queried.contains(&e.contact.node_id));
        let page_budget = if has_descent {
            (can_send / 2).max(1)
        } else {
            can_send
        };
        while batch.len() < page_budget {
            let Some((node_id, start)) = self.page_queue.pop_front() else {
                break;
            };
            // The shortlist is trimmed as the walk progresses, so a node that
            // answered may no longer be on it. Nothing else holds its address,
            // so the page is simply dropped.
            let Some(contact) = self
                .shortlist
                .iter()
                .find(|e| e.contact.node_id == node_id)
                .map(|e| e.contact.clone())
            else {
                continue;
            };
            let req_id = self.take_request_id();
            self.pending_requests.insert(
                req_id,
                PendingQuery {
                    node: node_id,
                    start_position: start,
                },
            );
            batch.push(QueryTarget {
                contact,
                request_id: req_id,
                start_position: start,
            });
        }
        if batch.len() >= can_send {
            return batch;
        }
        // The class preference — pinned session peers, then verified contacts,
        // then mute leads — applies to the *opening* batch only, and exists so
        // the first round does not lead with a lead the routing table happened
        // to sort first.
        //
        // It must not outrank XOR distance after that. Every contact learned
        // mid-walk decodes with `last_seen: 0`, so `is_verified()` is false and
        // it always lands in the last class, while a healthy table seeds the
        // search entirely with verified contacts. Applying the preference on
        // every batch therefore asked — and, since a fault returns the entry to
        // `Pending`, retried — all ~20 seeds before the closest node the walk
        // had actually discovered. With quiet seeds that spent roughly 40s of
        // the 60s `SEARCH_TIMEOUT_SECS` without descending toward the target at
        // all: keyword searches missed, and publish lookups resolved to far
        // nodes that storers then refuse on proximity. It also broke the
        // invariant `routing.rs` states explicitly — that seed order cannot
        // matter because the search re-sorts by distance and walks that order.
        //
        // `queried` is only empty before the very first query of a search (it
        // retains nodes whose retries are spent), so this is exactly the
        // opening batch.
        let seed_round = self.queried.is_empty();
        let passes = if seed_round { 3 } else { 1 };
        for prefer in 0..passes {
            for entry in &mut self.shortlist {
                if batch.len() >= can_send {
                    break;
                }
                if seed_round {
                    let class = if entry.pinned {
                        0
                    } else if entry.contact.is_verified() {
                        1
                    } else {
                        2
                    };
                    if class != prefer {
                        continue;
                    }
                }
                if entry.state == NodeState::Pending
                    && !self.queried.contains(&entry.contact.node_id)
                {
                    entry.state = NodeState::InFlight;
                    self.queried.insert(entry.contact.node_id);
                    *self.attempts.entry(entry.contact.node_id).or_insert(0) += 1;
                    let req_id = self.next_request_id;
                    self.next_request_id = self.next_request_id.wrapping_add(1);
                    self.pending_requests.insert(
                        req_id,
                        PendingQuery {
                            node: entry.contact.node_id,
                            start_position: 0,
                        },
                    );
                    batch.push(QueryTarget {
                        contact: entry.contact.clone(),
                        request_id: req_id,
                        start_position: 0,
                    });
                }
            }
            if batch.len() >= can_send {
                break;
            }
        }
        batch
    }

    /// Keep firsthand session peers on the shortlist even when they are not
    /// among the k XOR-closest routing-table contacts.
    ///
    /// Keyword records on a LAN or island publisher never reach the public
    /// walk unless that peer is asked directly.
    ///
    /// Capped, because a pin is exempt from the k-trim and `FIND_VALUE`
    /// deliberately never converges early — it exhausts the shortlist. The
    /// session table holds up to `MAX_EMBER_SESSION_DHT_CONTACTS` (64) against
    /// a `K_BUCKET_SIZE` of 20, so pinning all of them could outnumber the
    /// entire Kademlia shortlist three to one; with those peers slow or gone,
    /// which is the LAN/CGNAT case this mechanism exists for, 84 entries at
    /// `MAX_QUERY_ATTEMPTS` is well past what `SEARCH_TIMEOUT_SECS` allows at
    /// ALPHA concurrency, and the search expired having never descended toward
    /// the target. Most-recently-seen first, so the cap keeps the peers most
    /// likely to answer.
    pub fn seed_extra_contacts(&mut self, mut contacts: Vec<EmberContact>) -> usize {
        // Ranked, then capped on what is actually *pinned* — not on candidates.
        // Truncating the input first spent slots on peers the filters below
        // discard, and the commonest discard is "already on the shortlist",
        // which adds nothing. Session peers are exactly the peers most likely
        // to be routing-table contacts already seeding it, so on the small
        // overlay this exists for, the LAN publisher that is *not* in the table
        // — the one the pin is for — was the one ordered out.
        contacts.sort_by_key(|c| std::cmp::Reverse(c.last_seen));
        let mut added = 0;
        for contact in contacts {
            if added >= MAX_PINNED_EXTRA_CONTACTS {
                break;
            }
            if !contact.is_dialable() {
                continue;
            }
            if contact.node_id == self.target {
                continue;
            }
            if let Some(existing) = self
                .shortlist
                .iter_mut()
                .find(|e| e.contact.node_id == contact.node_id)
            {
                existing.pinned = true;
                continue;
            }
            if self.queried.contains(&contact.node_id) {
                continue;
            }
            let distance = self.target.distance(&contact.node_id);
            self.shortlist.push(ShortlistEntry {
                contact,
                distance,
                state: NodeState::Pending,
                pinned: true,
            });
            added += 1;
        }
        self.shortlist
            .sort_by_key(|a| a.distance.0);
        added
    }

    /// Process a FOUND_NODE / FOUND_VALUE response from a peer.
    ///
    /// See [`ResponseOutcome`] for why acceptance and progress are reported
    /// separately rather than as one boolean.
    pub fn process_response(
        &mut self,
        request_id: u32,
        from_id: &EmberNodeId,
        closer_nodes: Vec<EmberContact>,
        mut value_records: Vec<Vec<u8>>,
        mut page: Option<ValuePage>,
    ) -> ResponseOutcome {
        // Reject responses we didn't ask for: an attacker (or a buggy
        // peer) sending arbitrary `(request_id, from_id)` pairs must
        // not be able to flip a node to `Responded`, merge `closer_nodes`,
        // or contribute to `value_records`. The caller is responsible
        // for transport-layer auth; this is the request-correlation
        // gate.
        let expected = self.pending_requests.remove(&request_id);
        if expected.as_ref().map(|p| p.node) != Some(*from_id) {
            debug!(
                "Search {}: rejected response from {} (request_id {} expected {:?})",
                self.id,
                from_id,
                request_id,
                expected.as_ref().map(|p| p.node)
            );
            // Re-insert if we removed a real pending request for a
            // different node — we still want it to be matchable when
            // the right response arrives. (No-op when `expected` was
            // None.)
            if let Some(real) = expected {
                self.pending_requests.insert(request_id, real);
            }
            return ResponseOutcome::REFUSED;
        }
        let asked_start = expected.map(|p| p.start_position).unwrap_or(0);

        for entry in &mut self.shortlist {
            if entry.contact.node_id == *from_id {
                entry.state = NodeState::Responded;
                break;
            }
        }

        // Collect value results. Bind each FOUND_VALUE blob to the queried
        // DHT key: blobs are `record_data || 64-byte sig` with keyword_hash
        // at bytes [1..17]. Without this check a malicious LOOKUP peer can
        // return any publisher-signed keyword records as hits for the query.
        // A `FIND_NODE` asked for contacts, so a value answer to it is unasked
        // for and nothing downstream reads it: `maybe_finish_ember_search`'s
        // `FindNode` arm never looks at `results`. Taking it anyway meant a peer
        // we sent `FIND_NODE` could reply `FOUND_VALUE` under that request id
        // and buy up to 300 Ed25519 verifications and a few hundred KB of dead
        // buffer per search, aimed at the task that also drives eD2K, KAD and
        // the UI. The key binding below is scoped to value searches too, so
        // these were the blobs entering unchecked.
        //
        // The paging half has to go with it. `queue_next_page` has no search
        // type of its own, and `next_to_query` reserves half the α budget for
        // pages — so a single peer could take half a `FIND_NODE` walk's
        // concurrency for repeat queries to itself, which cannot even make
        // progress: the driver builds a plain `FIND_NODE` for a page follow-up
        // and ignores `start_position`.
        let value_answer_expected = self.search_type == SearchType::FindValue;
        if !value_answer_expected {
            if !value_records.is_empty() {
                debug!(
                    "Search {}: ignoring {} record(s) offered to a FIND_NODE",
                    self.id,
                    value_records.len()
                );
                value_records = Vec::new();
            }
            page = None;
        }
        for data in value_records {
            if self.search_type == SearchType::FindValue {
                if data.len() < 17 + 64 {
                    continue;
                }
                let mut kh = [0u8; 16];
                kh.copy_from_slice(&data[1..17]);
                if kh != self.target.0 {
                    debug!(
                        "Search {}: dropping FOUND_VALUE blob whose keyword_hash does not match target",
                        self.id
                    );
                    continue;
                }
            }
            // No single peer gets to fill the budget. See
            // [`MAX_RESULTS_PER_NODE`]: the walk ends when the budget is full,
            // so without this the node that answers first also decides how far
            // the search gets to go.
            let offered = self.offered_results.entry(*from_id).or_insert(0);
            if *offered >= MAX_RESULTS_PER_NODE {
                continue;
            }
            // Dedup before the cap, not after: counting copies against
            // `MAX_SEARCH_RESULTS` is what let a well-replicated record end
            // the search before the closer hops were reached.
            if !self.seen_results.insert(*blake3::hash(&data).as_bytes()) {
                // And before the *allowance*, because a page that resumes at a
                // record it passed over deliberately re-sends everything
                // between that record and the end of the previous page. Those
                // duplicates cost bandwidth either way, but charging them here
                // spent a well-stocked storer's offer allowance on records we
                // already had, cutting it off before it ran out of either pages
                // or key — so the searcher saw fewer *distinct* records than
                // paging exists to reach.
                continue;
            }
            *offered += 1;
            // Check the signature before the blob takes a slot. Consumers
            // re-parse through `from_value_blob` and drop anything forged, so
            // a junk blob was never going to reach the caller — but until it
            // was checked here it still cost a result slot, and filling those
            // slots is what ends the walk. Unsigned bytes carrying the right
            // sixteen at `[1..17]` were enough, which is free to produce.
            if !SignedRecord::value_blob_is_authentic(&data) {
                debug!(
                    "Search {}: dropping FOUND_VALUE blob with no valid publisher signature",
                    self.id
                );
                continue;
            }
            if self.results.len() < MAX_SEARCH_RESULTS {
                self.results.push(SearchResultRecord {
                    data,
                    from_node: *from_id,
                });
            }
        }

        if let Some(page) = page {
            self.queue_next_page(from_id, asked_start, page);
        }

        // Merge closer nodes into shortlist
        let mut new_closer = false;
        let current_best = self
            .shortlist
            .first()
            .map(|e| e.distance)
            .unwrap_or(EmberNodeId([0xFF; 16]));

        for contact in closer_nodes {
            if !contact.is_dialable() {
                continue;
            }
            if self.queried.contains(&contact.node_id) {
                continue;
            }
            if contact.node_id == self.target {
                continue; // skip if it's the target itself
            }

            let distance = self.target.distance(&contact.node_id);

            // Check if we already have this node
            if self
                .shortlist
                .iter()
                .any(|e| e.contact.node_id == contact.node_id)
            {
                continue;
            }

            if distance.0 < current_best.0 {
                new_closer = true;
            }

            self.shortlist.push(ShortlistEntry {
                contact,
                distance,
                state: NodeState::Pending,
                pinned: false,
            });
        }

        // Re-sort and trim. One response can carry enough closer contacts to
        // push an entry we are still waiting on past the cap, and trimming
        // purely by distance would drop it: the search would then see no
        // in-flight work and could declare itself complete while a response
        // is genuinely outstanding, and `next_to_query` would undercount the
        // in-flight total and exceed ALPHA. Entries awaiting a reply are kept
        // regardless of rank, which bounds the list at K + ALPHA.
        self.shortlist
            .sort_by_key(|a| a.distance.0);
        if self.shortlist.len() > K_BUCKET_SIZE {
            // A node we still owe a page to is kept for the same reason as one
            // with a reply outstanding: `next_to_query` can only reach a page
            // through the shortlist, so trimming the entry silently drops the
            // rest of that node's records. It has already proved it holds
            // matching records, which is more than most of the list has done,
            // and gossip contacts answer with `last_seen: 0` so the verified
            // clause does not cover them.
            let owed: HashSet<EmberNodeId> = self.page_queue.iter().map(|(id, _)| *id).collect();
            let mut kept = 0usize;
            self.shortlist.retain(|e| {
                kept += 1;
                kept <= K_BUCKET_SIZE
                    || e.state == NodeState::InFlight
                    || e.pinned
                    || e.contact.is_verified()
                    || owed.contains(&e.contact.node_id)
            });
        }

        // An answer that moved the frontier resets the convergence count; one
        // that did not brings a `FIND_NODE` walk closer to finishing.
        if new_closer {
            self.stale_responses = 0;
        } else {
            self.stale_responses = self.stale_responses.saturating_add(1);
        }

        // Check convergence
        self.check_complete();

        ResponseOutcome {
            accepted: true,
            new_closer,
        }
    }

    /// Decide whether a `FOUND_VALUE` earns one more query to the same node.
    ///
    /// Every check here exists because `page` is the *responder's* account of
    /// its own store, and this is the one place a peer's claim can cause us to
    /// send traffic. A node that reports an enormous total, or one that keeps
    /// naming a position it has already served, must cost a bounded number of
    /// queries either way.
    fn queue_next_page(&mut self, node: &EmberNodeId, asked_start: u16, page: ValuePage) {
        if self.search_type != SearchType::FindValue {
            return;
        }
        // The responder says the key is exhausted.
        if page.next_position >= page.total_available {
            return;
        }
        // Require forward progress. Without this a responder answering with the
        // offset we just asked for — by bug or on purpose — would have us re-ask
        // the same window until the search timed out, and every answer would
        // dedup to nothing while still costing a round trip.
        if page.next_position <= asked_start {
            return;
        }
        // Nothing left to put the records in.
        if self.results.len() >= MAX_SEARCH_RESULTS {
            return;
        }
        // This node has already offered everything one peer is allowed to
        // contribute, so a further page could only be discarded.
        if self.offered_results.get(node).copied().unwrap_or(0) >= MAX_RESULTS_PER_NODE {
            return;
        }
        let queued = self.pages_queued.entry(*node).or_insert(0);
        if *queued >= MAX_PAGES_PER_NODE {
            return;
        }
        *queued += 1;
        self.page_queue.push_back((*node, page.next_position));
    }

    /// Mark a node's request as failed (timeout, error).
    ///
    /// Returns which node it was, so the caller can also hold the failure
    /// against the routing table. Without that, a dead gossip lead stayed a
    /// lookup seed until the liveness sweep happened to reach it.
    ///
    /// A node with attempts left goes back to `Pending` rather than `Failed`,
    /// so one lost datagram does not permanently remove it from this search.
    /// See [`MAX_QUERY_ATTEMPTS`].
    pub fn mark_failed(&mut self, request_id: u32) -> Option<EmberNodeId> {
        self.mark_failed_with(request_id, QueryFailure::TimedOut)
    }

    /// [`Self::mark_failed`] for a caller that can say whether a retry is
    /// actually coming.
    ///
    /// [`QueryFailure::NotSent`] leaves the entry `Failed` even with attempts
    /// to spare. The send-failure path registers no wire request, so no
    /// deadline will ever expire and re-drive the search: a node returned to
    /// `Pending` there is work `check_complete` keeps seeing as outstanding
    /// forever. A one-entry shortlist — the shape of a handful-of-nodes
    /// deployment — then held its search slot and its waiter until the
    /// whole-search backstop, two minutes later.
    pub fn mark_failed_with(
        &mut self,
        request_id: u32,
        failure: QueryFailure,
    ) -> Option<EmberNodeId> {
        let Some(pending) = self.pending_requests.remove(&request_id) else {
            self.check_complete();
            return None;
        };
        let node_id = pending.node;
        // A page follow-up that went unanswered leaves the node exactly as it
        // was: it has already answered this search at least once, so it is not a
        // dead contact, and returning it to `Pending` would have the walk re-ask
        // it from offset zero for records it has already handed us.
        if !pending.is_page() {
            let spent = self
                .attempts
                .get(&node_id)
                .copied()
                .unwrap_or(MAX_QUERY_ATTEMPTS);
            let retryable = failure == QueryFailure::TimedOut && spent < MAX_QUERY_ATTEMPTS;
            for entry in &mut self.shortlist {
                if entry.contact.node_id == node_id {
                    entry.state = if retryable {
                        NodeState::Pending
                    } else {
                        NodeState::Failed
                    };
                    break;
                }
            }
            if retryable {
                // Eligible for `next_to_query` again. The attempt count is
                // kept, so this can only happen `MAX_QUERY_ATTEMPTS` times.
                self.queried.remove(&node_id);
            }
        }
        self.check_complete();
        Some(node_id)
    }

    /// Re-evaluate and return the completion state. Unlike the internal
    /// [`Self::check_complete`] (only run on a response or failure), the
    /// driver calls this after dispatching a batch so a search that has
    /// nothing left to query — e.g. started against an empty routing
    /// table, or already exhausted — is recognised as complete
    /// immediately instead of stalling until the overall timeout.
    pub fn poll_complete(&mut self) -> bool {
        self.check_complete();
        self.complete
    }

    fn check_complete(&mut self) {
        if self.complete {
            return;
        }

        // Complete if timed out
        if self.started_at.elapsed().as_secs() > SEARCH_TIMEOUT_SECS {
            self.complete = true;
            return;
        }

        // Complete if no more nodes to query and nothing in flight.
        //
        // Queued and outstanding pages count as work: a walk that has asked
        // every node it knows of may still be owed most of the records, and
        // finishing here would discard them along with the search.
        let has_pending = self.shortlist.iter().any(|e| e.state == NodeState::Pending);
        let has_in_flight = self
            .shortlist
            .iter()
            .any(|e| e.state == NodeState::InFlight);
        let has_pages = !self.page_queue.is_empty() || self.pages_in_flight() > 0;

        if !has_pending && !has_in_flight && !has_pages {
            self.complete = true;
            return;
        }

        // A FIND_NODE walk whose frontier has stopped moving has the answer it
        // came for; querying the rest of the shortlist only re-learns nodes we
        // already hold. FIND_VALUE is excluded on purpose — see
        // [`STALE_RESPONSES_TO_CONVERGE`].
        if self.search_type == SearchType::FindNode
            && self.head_has_responded()
            && self.stale_responses >= STALE_RESPONSES_TO_CONVERGE
            && self.responded_count() >= MIN_RESPONSES_TO_CONVERGE
        {
            trace!(
                "Search {}: converged after {} answers brought nothing closer",
                self.id,
                self.stale_responses
            );
            self.complete = true;
            return;
        }

        // For FIND_VALUE, complete if we have enough results
        if self.search_type == SearchType::FindValue && self.results.len() >= MAX_SEARCH_RESULTS {
            self.complete = true;
        }
    }

    /// Whether the closest node we know of has actually answered.
    ///
    /// Required before a walk may converge early, and it is what stops one
    /// fabricated contact ending every lookup. Progress is measured against the
    /// head of the shortlist, and contacts arrive inside `FOUND_NODE` unverified,
    /// so a peer queried in the first round can return an invented ID one bit
    /// from the target. It is not the target itself, so the only exclusion misses
    /// it; it sorts to the head; and it is never removed, even once it has failed
    /// to answer. From then on no real node can be "closer", every later answer
    /// counts as stale, and the walk would stop at the response floor having
    /// reached the attacker's node and a few of our own existing contacts —
    /// which, for a publish-target lookup, then became the cached target set for
    /// four hours.
    ///
    /// An invented ID cannot answer, so requiring the head to have *responded*
    /// (not merely to have been resolved — a failed entry stays at the head)
    /// makes the pin block convergence instead of forcing it, and the walk falls
    /// back to exhausting its shortlist. A node close enough to the target to
    /// hold the head legitimately has to answer to keep it, which is the
    /// ordinary eclipse cost rather than a free lunch.
    ///
    /// The fallback is not rare, and is not meant to be: any dead contact at the
    /// head does the same thing, which stale gossip near a popular target produces
    /// often enough. That costs a walk roughly the difference between the response
    /// floor and a full shortlist — around six extra queries — and it is the right
    /// side to err on, since the alternative is ending walks on the word of a peer
    /// that never spoke.
    fn head_has_responded(&self) -> bool {
        self.shortlist
            .first()
            .is_some_and(|entry| entry.state == NodeState::Responded)
    }

    /// Shortlist entries that have answered us.
    pub fn responded_count(&self) -> usize {
        self.shortlist
            .iter()
            .filter(|e| e.state == NodeState::Responded)
            .count()
    }

    /// Get the closest responded nodes (useful for FIND_NODE results).
    ///
    /// Capped at k. The shortlist keeps pinned session peers past rank k and
    /// `next_to_query` asks them first, so a walk that exhausts its shortlist
    /// can leave more than k entries `Responded`. `network/mod.rs` files this
    /// set as the key's publish targets and trusts it for hours, so without the
    /// cap a record fans out past `K_EMBER_REPLICAS`. The shortlist is ordered
    /// by distance, so what drops off is the farthest — the nodes likeliest to
    /// refuse the store on proximity anyway.
    pub fn closest_responded(&self) -> Vec<EmberContact> {
        self.shortlist
            .iter()
            .filter(|e| e.state == NodeState::Responded)
            .take(K_BUCKET_SIZE)
            .map(|e| e.contact.clone())
            .collect()
    }
}

/// Manages multiple concurrent iterative searches.
pub struct SearchManager {
    searches: HashMap<u32, IterativeSearch>,
    next_id: u32,
}

impl SearchManager {
    pub fn new() -> Self {
        Self {
            searches: HashMap::new(),
            next_id: 1,
        }
    }

    /// Start a new FIND_NODE search.
    /// Returns `None` when the active-search cap is reached so the
    /// caller can surface a "busy" state instead of unbounded growth.
    pub fn start_find_node(
        &mut self,
        target: EmberNodeId,
        routing_table: &RoutingTable,
    ) -> Option<u32> {
        let initial = routing_table.find_closest_prefer_verified(&target, K_BUCKET_SIZE);
        let id = self.alloc_id()?;
        let search = IterativeSearch::new(id, SearchType::FindNode, target, vec![], initial);
        trace!("Starting FIND_NODE search {} for target {}", id, target);
        self.searches.insert(id, search);
        Some(id)
    }

    /// Start a new FIND_VALUE search with multiple keyword hashes.
    /// Returns `None` when the active-search cap is reached.
    pub fn start_find_value(
        &mut self,
        primary_key: EmberNodeId,
        keyword_hashes: Vec<[u8; 16]>,
        routing_table: &RoutingTable,
    ) -> Option<u32> {
        let initial = routing_table.find_closest_prefer_verified(&primary_key, K_BUCKET_SIZE);
        let id = self.alloc_id()?;
        let search = IterativeSearch::new(
            id,
            SearchType::FindValue,
            primary_key,
            keyword_hashes,
            initial,
        );
        trace!(
            "Starting FIND_VALUE search {} for key {} ({} keywords)",
            id,
            primary_key,
            search.keyword_hashes.len()
        );
        self.searches.insert(id, search);
        Some(id)
    }

    /// Pin firsthand session peers onto a search that has just started.
    pub fn seed_extra_contacts(
        &mut self,
        search_id: u32,
        contacts: Vec<EmberContact>,
    ) -> usize {
        self.searches
            .get_mut(&search_id)
            .map(|s| s.seed_extra_contacts(contacts))
            .unwrap_or(0)
    }

    /// Fold records we already hold locally into a fresh `FIND_VALUE`.
    ///
    /// The shortlist only ever contains *other* nodes, so a record in our own
    /// store would otherwise never reach the search that is looking for it.
    /// Attributed to `local_id` for provenance; callers verify the publisher
    /// signature on every blob regardless of who supplied it.
    pub fn seed_local_results(
        &mut self,
        search_id: u32,
        local_id: EmberNodeId,
        records: Vec<Vec<u8>>,
    ) -> usize {
        let Some(search) = self.searches.get_mut(&search_id) else {
            return 0;
        };
        let mut added = 0;
        for data in records {
            if search.results.len() >= MAX_LOCAL_SEED_RESULTS {
                break;
            }
            // The same key binding the wire path applies to FOUND_VALUE
            // blobs. `DhtStore::store_attributed` re-derives the key from the
            // signed body and refuses a mismatch, so this should never reject
            // anything; keeping the two paths identical means the invariant
            // holds here even if that gate ever moves.
            if data.len() < 17 + 64 || data[1..17] != search.target.0 {
                continue;
            }
            // Register the blob exactly as the wire path does. A record we hold
            // is one the peers closest to this key are also likely to hold, so
            // without this every seeded record could take a second slot when a
            // peer returns the identical bytes. That was near-free when the
            // local read inherited the datagram packer's limit of about five
            // records; at `MAX_LOCAL_SEED_RESULTS` it is up to half the result
            // budget, and filling `MAX_SEARCH_RESULTS` with copies ends the walk
            // before the closer hops are reached.
            if !search.seen_results.insert(*blake3::hash(&data).as_bytes()) {
                continue;
            }
            search.results.push(SearchResultRecord {
                data,
                from_node: local_id,
            });
            added += 1;
        }
        added
    }

    /// Get a mutable reference to an active search.
    pub fn get_mut(&mut self, search_id: u32) -> Option<&mut IterativeSearch> {
        self.searches.get_mut(&search_id)
    }

    /// Get a reference to an active search.
    pub fn get(&self, search_id: u32) -> Option<&IterativeSearch> {
        self.searches.get(&search_id)
    }

    /// Remove a completed search and return it.
    pub fn remove(&mut self, search_id: u32) -> Option<IterativeSearch> {
        self.searches.remove(&search_id)
    }

    /// Clean up timed-out searches. Returns the searches that were removed
    /// so the caller can record outcome quality before dropping them.
    pub fn cleanup_expired(&mut self) -> Vec<IterativeSearch> {
        let expired: Vec<u32> = self
            .searches
            .iter()
            .filter(|(_, s)| s.started_at.elapsed().as_secs() > SEARCH_TIMEOUT_SECS * 2)
            .map(|(id, _)| *id)
            .collect();
        let mut removed = Vec::with_capacity(expired.len());
        for id in &expired {
            if let Some(search) = self.searches.remove(id) {
                removed.push(search);
            }
        }
        if !removed.is_empty() {
            debug!("Cleaned up {} expired searches", removed.len());
        }
        removed
    }

    /// Number of active searches.
    pub fn active_count(&self) -> usize {
        self.searches.len()
    }

    /// Diagnostic snapshot of every in-flight iterative search (slice 16).
    pub fn snapshot(&self) -> Vec<SearchSnapshot> {
        self.searches
            .values()
            .map(|s| {
                let in_flight = s
                    .shortlist
                    .iter()
                    .filter(|e| e.state == NodeState::InFlight)
                    .count() as u32;
                let responded = s
                    .shortlist
                    .iter()
                    .filter(|e| e.state == NodeState::Responded)
                    .count() as u32;
                let pending = s
                    .shortlist
                    .iter()
                    .filter(|e| e.state == NodeState::Pending)
                    .count() as u32;
                SearchSnapshot {
                    id: s.id,
                    search_type: match s.search_type {
                        SearchType::FindNode => "Node",
                        SearchType::FindValue => "Value",
                    }
                    .to_string(),
                    target: s.target.to_hex(),
                    keyword_count: 1 + s.keyword_hashes.len() as u32,
                    results: s.results.len() as u32,
                    queried: s.queried.len() as u32,
                    in_flight,
                    responded,
                    pending,
                    complete: s.complete,
                    started_at_secs: s.started_at.elapsed().as_secs(),
                }
            })
            .collect()
    }

    /// Nodes that an unfinished search is still relying on.
    ///
    /// A lookup walks a shortlist of contacts; if the routing table drops one
    /// mid-walk the search loses that branch and any records behind it. The
    /// staleness purge consults this so table hygiene cannot sabotage a
    /// lookup already in progress.
    pub fn nodes_in_use(&self) -> HashSet<EmberNodeId> {
        self.searches
            .values()
            .filter(|s| !s.complete)
            .flat_map(|s| s.shortlist.iter())
            .filter(|e| matches!(e.state, NodeState::Pending | NodeState::InFlight))
            .map(|e| e.contact.node_id)
            .collect()
    }

    fn alloc_id(&mut self) -> Option<u32> {
        if self.searches.len() >= MAX_ACTIVE_SEARCHES {
            warn!(
                "Too many active Ember searches ({}), rejecting new search",
                self.searches.len()
            );
            return None;
        }
        // Skip IDs that are already in use (defends against the
        // pathological case where wrapping returns to a still-active
        // ID). The cap above means at most MAX_ACTIVE_SEARCHES
        // iterations, so this is bounded.
        for _ in 0..=MAX_ACTIVE_SEARCHES {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            if !self.searches.contains_key(&id) {
                return Some(id);
            }
        }
        None
    }
}

/// Compute the BLAKE3-based keyword hash used as a DHT key.
pub fn keyword_hash(keyword: &str) -> [u8; 16] {
    let normalized = keyword.to_lowercase();
    let hash = blake3::hash(normalized.as_bytes());
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash.as_bytes()[..16]);
    key
}

/// Compute keyword hashes for a multi-word query. Returns `(hash, text)` pairs
/// sorted by keyword length descending (longest / most selective first). The
/// first entry is the primary DHT walk key; the rest ride on FIND_VALUE for
/// peer-side `file_hash` intersection.
///
/// Tokenized by the same function that splits a filename on the publish side,
/// so this cannot walk to a key no publisher ever wrote to. A DHT keyword index
/// is only navigable when both ends agree where a word ends, and splitting on
/// whitespace alone would hash `blade-runner` whole while the publisher stored
/// `blade` and `runner`.
///
/// In practice the live callers pass terms [`crate::search::query`] has already
/// tokenized with the same rules, so this is belt-and-braces rather than a
/// behaviour change — but it is what keeps the two ends from drifting apart if
/// a caller ever hands over a raw query.
pub fn compute_keyword_hashes(query: &str) -> Vec<([u8; 16], String)> {
    // Already lowercased and deduplicated (case-insensitively) by the
    // tokenizer; this only imposes the most-selective-first ordering the
    // primary/secondary split depends on.
    let mut keywords = crate::network::kad::publish::extract_query_keywords(query);
    keywords.sort_by_key(|kw| std::cmp::Reverse(kw.len()));

    keywords
        .into_iter()
        .map(|kw| (keyword_hash(&kw), kw))
        .collect()
}

/// Remaining keyword hashes attached to FIND_VALUE for peer-side `file_hash`
/// intersection. Pass `intersect = false` for OR queries: that intersection
/// is AND semantics and would drop the non-matching half at any peer that
/// also stored a secondary key.
pub fn extra_keyword_hashes(hashed: &[([u8; 16], String)], intersect: bool) -> Vec<[u8; 16]> {
    if !intersect {
        Vec::new()
    } else {
        hashed.iter().skip(1).map(|(h, _)| *h).collect()
    }
}

/// Shorthands for the tests that predate `FIND_VALUE` paging.
///
/// Both of those tests' concerns — which node a batch picked, and what a search
/// does with an answer — are unchanged by paging, so they keep asserting on the
/// narrower shape rather than restating `start_position: 0` and `None` several
/// dozen times. The paging tests use the real signatures directly.
#[cfg(test)]
impl IterativeSearch {
    /// [`Self::next_to_query`] reduced to `(contact, request_id)`.
    fn query_pairs(&mut self) -> Vec<(EmberContact, u32)> {
        self.next_to_query()
            .into_iter()
            .map(|q| (q.contact, q.request_id))
            .collect()
    }

    /// [`Self::process_response`] for an answer that carried no page
    /// information: every `FOUND_NODE`, and any `FOUND_VALUE` from a peer with
    /// nothing left to offer.
    fn process_unpaged(
        &mut self,
        request_id: u32,
        from_id: &EmberNodeId,
        closer_nodes: Vec<EmberContact>,
        value_records: Vec<Vec<u8>>,
    ) -> ResponseOutcome {
        self.process_response(request_id, from_id, closer_nodes, value_records, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_id(byte: u8) -> EmberNodeId {
        let mut id = [0u8; 16];
        id[0] = byte;
        EmberNodeId(id)
    }

    fn make_contact(id_byte: u8) -> EmberContact {
        EmberContact {
            node_id: make_id(id_byte),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 1, id_byte, 1)), 4662),
            noise_pub: [id_byte; 32],
            ed25519_pub: [id_byte; 32],
            last_seen: chrono::Utc::now().timestamp(),
            failed_queries: 0,
        }
    }

    /// A FOUND_VALUE blob — `record_data || 64-byte publisher signature` —
    /// for `keyword`, made a distinct record by `filler`.
    ///
    /// Genuinely signed rather than merely shaped right: `process_response`
    /// verifies every blob before it takes a result slot, so a hand-rolled one
    /// exercises the rejection path and nothing else.
    fn signed_value_blob(keyword: &str, filler: u16) -> Vec<u8> {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let mut file_hash = [0u8; 16];
        file_hash[..2].copy_from_slice(&filler.to_le_bytes());
        let rec = SignedRecord::keyword(keyword, file_hash, [0u8; 32], 100, "file.iso", &sk);
        let mut blob = rec.data.clone();
        blob.extend_from_slice(&rec.signature);
        blob
    }

    /// The key records for `keyword` land under, and therefore the target a
    /// search has to walk to in order to find them.
    fn keyword_target(keyword: &str) -> EmberNodeId {
        EmberNodeId(keyword_hash(keyword))
    }

    /// A blob with the right sixteen bytes at `[1..17]` and noise behind them
    /// — what costs an attacker nothing to produce.
    fn unsigned_value_blob(target: EmberNodeId, filler: u8) -> Vec<u8> {
        let mut blob = vec![0x01u8];
        blob.extend_from_slice(&target.0);
        blob.extend_from_slice(&[filler; 160]);
        blob
    }

    /// A blob whose framing is impeccable and whose signature is not: a real
    /// record with one bit of the signature flipped. The framing checks let
    /// this through, so only the verification can turn it away.
    fn forged_value_blob(keyword: &str, filler: u16) -> Vec<u8> {
        let mut blob = signed_value_blob(keyword, filler);
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        blob
    }

    /// A table with a full bucket's worth of contacts, each in its own /24 so
    /// the diversity caps never refuse one.
    fn table_with_contacts(local: EmberNodeId, count: u8) -> RoutingTable {
        let mut rt = RoutingTable::new(local, false);
        for i in 0..count {
            rt.add_contact(make_contact(0x40 + i));
        }
        rt
    }

    /// Answer every query with nothing closer, until the walk either finishes
    /// or runs out of shortlist. Returns how many nodes answered.
    fn walk_until_done(search: &mut IterativeSearch) -> usize {
        let mut answered = 0usize;
        while !search.complete {
            let batch = search.query_pairs();
            if batch.is_empty() {
                break;
            }
            for (contact, req_id) in batch {
                search.process_unpaged(req_id, &contact.node_id, vec![], vec![]);
                answered += 1;
            }
        }
        answered
    }

    /// A lookup used to query every entry that ever reached the shortlist, so a
    /// walk whose frontier had already stopped moving still spent round trips
    /// re-learning nodes it held. Kademlia ends a lookup once it has heard from
    /// the closest nodes it knows of.
    #[test]
    fn a_find_node_walk_stops_once_the_frontier_stops_moving() {
        let target = make_id(0x01);
        let rt = table_with_contacts(make_id(0x00), K_BUCKET_SIZE as u8);

        let mut sm = SearchManager::new();
        let sid = sm.start_find_node(target, &rt).expect("slot");
        let search = sm.get_mut(sid).unwrap();
        let answered = walk_until_done(search);

        assert!(search.complete, "the walk must finish");
        assert!(
            answered >= MIN_RESPONSES_TO_CONVERGE,
            "convergence must not fire before the response floor, got {answered}"
        );
        assert!(
            answered < K_BUCKET_SIZE,
            "stopping early is the point: asked {answered} of {K_BUCKET_SIZE}"
        );
    }

    /// Contacts inside a `FOUND_NODE` are unverified, so the first peer queried
    /// can return an invented ID one bit from the target. It pins the head of the
    /// shortlist for the rest of the walk — it is not the target itself, so the
    /// only exclusion misses it, and a failed entry is never removed. Every later
    /// answer then counts as stale, and convergence would end the walk at the
    /// response floor having reached the attacker and a few contacts we already
    /// had. For a publish-target lookup that set was then cached for four hours.
    #[test]
    fn one_invented_contact_cannot_end_a_find_node_walk() {
        let target = make_id(0x40);
        let rt = table_with_contacts(make_id(0x00), K_BUCKET_SIZE as u8);

        let mut sm = SearchManager::new();
        let sid = sm.start_find_node(target, &rt).expect("slot");
        let search = sm.get_mut(sid).unwrap();

        // Round one: the first peer answers with an ID one bit off the target,
        // which sorts ahead of every real node and can never answer.
        let batch = search.query_pairs();
        let mut phantom_id = target.0;
        phantom_id[15] ^= 1;
        let phantom = EmberContact {
            node_id: EmberNodeId(phantom_id),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 4672),
            noise_pub: [0xEE; 32],
            ed25519_pub: [0xEE; 32],
            last_seen: 0,
            failed_queries: 0,
        };
        let mut answered = 0usize;
        for (i, (contact, req_id)) in batch.into_iter().enumerate() {
            let closer = if i == 0 {
                vec![phantom.clone()]
            } else {
                vec![]
            };
            search.process_unpaged(req_id, &contact.node_id, closer, vec![]);
            answered += 1;
        }

        // Everyone else answers honestly with nothing closer, and the phantom
        // never answers at all.
        loop {
            let batch = search.query_pairs();
            if batch.is_empty() {
                break;
            }
            for (contact, req_id) in batch {
                if contact.node_id == phantom.node_id {
                    search.mark_failed(req_id);
                } else {
                    search.process_unpaged(req_id, &contact.node_id, vec![], vec![]);
                    answered += 1;
                }
            }
        }

        assert!(
            answered > MIN_RESPONSES_TO_CONVERGE,
            "the pin must not be able to end the walk at the convergence floor: \
             only {answered} peers were asked"
        );
        // Verified seeds stay on the shortlist even after a closer unverified
        // phantom is merged, so the walk still asks every real contact.
        assert_eq!(
            answered,
            K_BUCKET_SIZE,
            "the walk must still ask every verified seed"
        );
        assert!(search.complete, "and it must still terminate");
    }

    /// The same rule must not touch FIND_VALUE. There, one more node asked is
    /// one more chance at a record the closer ones did not hold, so recall is
    /// worth more than the round trips convergence would save.
    #[test]
    fn a_find_value_walk_keeps_asking_after_the_frontier_settles() {
        let target = make_id(0x01);
        let rt = table_with_contacts(make_id(0x00), K_BUCKET_SIZE as u8);

        let mut sm = SearchManager::new();
        let sid = sm.start_find_value(target, vec![], &rt).expect("slot");
        let search = sm.get_mut(sid).unwrap();
        let answered = walk_until_done(search);

        assert_eq!(
            answered, K_BUCKET_SIZE,
            "every peer on the shortlist must still be asked for records"
        );
    }

    /// Two peers holding the same record is the normal case for anything
    /// worth finding, and a walk asks twenty of them. Counting each copy
    /// against the result cap let one popular record end the search.
    #[test]
    fn the_same_record_from_two_peers_is_kept_once() {
        let target = keyword_target("ubuntu");
        let mut rt = RoutingTable::new(make_id(0x00), false);
        let a = make_contact(0xF0);
        let b = make_contact(0xE0);
        rt.add_contact(a.clone());
        rt.add_contact(b.clone());

        let mut sm = SearchManager::new();
        let sid = sm.start_find_value(target, vec![], &rt).expect("slot");
        let search = sm.get_mut(sid).unwrap();
        let batch = search.query_pairs();

        let shared = signed_value_blob("ubuntu", 0x11);
        let only_b = signed_value_blob("ubuntu", 0x22);
        for (contact, req_id) in batch {
            let records = if contact.node_id == b.node_id {
                vec![shared.clone(), only_b.clone()]
            } else {
                vec![shared.clone()]
            };
            search.process_unpaged(req_id, &contact.node_id, vec![], records);
        }

        assert_eq!(
            search.results.len(),
            2,
            "the duplicate must not take a second slot"
        );
        assert!(search.results.iter().any(|r| r.data == shared));
        assert!(search.results.iter().any(|r| r.data == only_b));
    }

    /// Dedup has to be by content, not by responder: a peer returning the
    /// same blob twice in one response must not get two slots either.
    #[test]
    fn one_peer_repeating_itself_gains_nothing() {
        let target = keyword_target("ubuntu");
        let mut rt = RoutingTable::new(make_id(0x00), false);
        let peer = make_contact(0xF0);
        rt.add_contact(peer.clone());

        let mut sm = SearchManager::new();
        let sid = sm.start_find_value(target, vec![], &rt).expect("slot");
        let search = sm.get_mut(sid).unwrap();
        let (_, req_id) = search.query_pairs().remove(0);

        let blob = signed_value_blob("ubuntu", 0x33);
        search.process_unpaged(req_id, &peer.node_id, vec![], vec![blob.clone(); 50]);

        assert_eq!(search.results.len(), 1);
    }

    /// Taking a result slot has to cost a signature. A slot is what ends a
    /// `FIND_VALUE` walk, and bytes carrying the queried key and nothing else
    /// are free to produce — which used to be enough to take one.
    #[test]
    fn only_signed_records_take_a_result_slot() {
        let target = keyword_target("ubuntu");
        let mut rt = RoutingTable::new(make_id(0x00), false);
        let peer = make_contact(0xF0);
        rt.add_contact(peer.clone());

        let mut sm = SearchManager::new();
        let sid = sm.start_find_value(target, vec![], &rt).expect("slot");
        let search = sm.get_mut(sid).unwrap();
        let (_, req_id) = search.query_pairs().remove(0);

        let genuine = signed_value_blob("ubuntu", 0x01);
        let mut offered: Vec<Vec<u8>> = (0..20).map(|i| unsigned_value_blob(target, i)).collect();
        offered.extend((0..20).map(|i| forged_value_blob("ubuntu", 0x40 + i)));
        offered.push(genuine.clone());

        search.process_unpaged(req_id, &peer.node_id, vec![], offered);

        assert_eq!(search.results.len(), 1, "only the signed record survives");
        assert_eq!(search.results[0].data, genuine);
    }

    /// Filling the result budget ends the walk, so no one peer may fill it.
    /// Otherwise whoever answers first decides how far the search goes, and
    /// the closer hops it existed to reach are never asked.
    #[test]
    fn one_peer_cannot_fill_the_result_budget() {
        let target = keyword_target("ubuntu");
        let mut rt = RoutingTable::new(make_id(0x00), false);
        let flooder = make_contact(0xF0);
        rt.add_contact(flooder.clone());
        rt.add_contact(make_contact(0xE0));

        let mut sm = SearchManager::new();
        let sid = sm.start_find_value(target, vec![], &rt).expect("slot");
        let search = sm.get_mut(sid).unwrap();
        let batch = search.query_pairs();
        let (_, req_id) = batch
            .iter()
            .find(|(c, _)| c.node_id == flooder.node_id)
            .expect("the flooder is queried");

        // Every one of them genuinely signed and distinct, so the per-node cap
        // is the only thing left that can turn any of them away — and there
        // are more than the whole budget, so without it this one answer would
        // both fill the results and end the walk.
        let flood: Vec<Vec<u8>> = (0..(MAX_SEARCH_RESULTS as u16 + 20))
            .map(|i| signed_value_blob("ubuntu", i))
            .collect();
        assert!(flood.len() > MAX_SEARCH_RESULTS);

        search.process_unpaged(*req_id, &flooder.node_id, vec![], flood);

        assert_eq!(search.results.len(), MAX_RESULTS_PER_NODE);
        assert!(
            !search.complete,
            "one peer's answer must not end the walk while another is outstanding"
        );
    }

    /// A single-peer `FIND_VALUE` search against a node holding more than one
    /// datagram's worth: the search must go back to that same node at the offset
    /// it named, and keep going until the key is exhausted.
    #[test]
    fn a_search_pages_a_node_that_reports_more_records() {
        let target = keyword_target("ubuntu");
        let mut rt = RoutingTable::new(make_id(0x00), false);
        let peer = make_contact(0xF0);
        rt.add_contact(peer.clone());

        let mut sm = SearchManager::new();
        let sid = sm.start_find_value(target, vec![], &rt).expect("slot");
        let search = sm.get_mut(sid).unwrap();

        // Five records a page, fifteen held.
        const TOTAL: u16 = 15;
        const PER_PAGE: u16 = 5;
        let mut asked: Vec<u16> = Vec::new();
        let mut served = 0u16;
        loop {
            let batch = search.next_to_query();
            if batch.is_empty() {
                break;
            }
            assert_eq!(batch.len(), 1, "only one node is known");
            let query = &batch[0];
            assert_eq!(query.contact.node_id, peer.node_id);
            asked.push(query.start_position);

            let page_end = (query.start_position + PER_PAGE).min(TOTAL);
            let blobs: Vec<Vec<u8>> = (query.start_position..page_end)
                .map(|i| signed_value_blob("ubuntu", i))
                .collect();
            served += blobs.len() as u16;
            search.process_response(
                query.request_id,
                &peer.node_id,
                vec![],
                blobs,
                Some(ValuePage {
                    next_position: page_end,
                    total_available: TOTAL,
                }),
            );
        }

        assert_eq!(
            asked,
            vec![0, 5, 10],
            "the search must follow the offsets the peer reported"
        );
        assert_eq!(served, TOTAL);
        assert_eq!(search.results.len(), TOTAL as usize);
        assert!(
            search.poll_complete(),
            "an exhausted key with nothing left to ask ends the search"
        );
    }

    /// A queued page is outstanding work. Completing while one is pending would
    /// throw away most of the records on any key big enough to need paging —
    /// and on a one-node search there is nothing else keeping the walk alive.
    #[test]
    fn a_search_does_not_complete_while_a_page_is_owed() {
        let target = keyword_target("ubuntu");
        let mut rt = RoutingTable::new(make_id(0x00), false);
        let peer = make_contact(0xF0);
        rt.add_contact(peer.clone());

        let mut sm = SearchManager::new();
        let sid = sm.start_find_value(target, vec![], &rt).expect("slot");
        let search = sm.get_mut(sid).unwrap();
        let batch = search.next_to_query();
        let query = &batch[0];

        search.process_response(
            query.request_id,
            &peer.node_id,
            vec![],
            vec![signed_value_blob("ubuntu", 0)],
            Some(ValuePage {
                next_position: 1,
                total_available: 40,
            }),
        );

        // The only node has answered, so without the page this search is done.
        assert!(
            !search.poll_complete(),
            "a queued page must keep the search alive"
        );
        let follow_up = search.next_to_query();
        assert_eq!(follow_up.len(), 1);
        assert_eq!(follow_up[0].start_position, 1);
    }

    /// `next_position` and `total_available` are the responder's claims about
    /// its own store, and they are the only thing here that can make us send
    /// more traffic. A peer must not be able to buy unbounded queries with them.
    #[test]
    fn a_peer_cannot_page_a_search_forever() {
        let target = keyword_target("ubuntu");
        let mut rt = RoutingTable::new(make_id(0x00), false);
        let peer = make_contact(0xF0);
        rt.add_contact(peer.clone());

        let mut sm = SearchManager::new();
        let sid = sm.start_find_value(target, vec![], &rt).expect("slot");
        let search = sm.get_mut(sid).unwrap();

        let mut pages = 0u32;
        let mut offset = 0u16;
        loop {
            let batch = search.next_to_query();
            if batch.is_empty() {
                break;
            }
            let query = &batch[0];
            offset = offset.saturating_add(1);
            pages += 1;
            assert!(pages < 100, "paging must terminate");
            // One record per page against a claimed total of 60,000: honest in
            // shape, ruinous if believed without limit.
            search.process_response(
                query.request_id,
                &peer.node_id,
                vec![],
                vec![signed_value_blob("ubuntu", offset)],
                Some(ValuePage {
                    next_position: offset,
                    total_available: 60_000,
                }),
            );
        }
        assert_eq!(
            pages as u8,
            MAX_PAGES_PER_NODE + 1,
            "the first query plus MAX_PAGES_PER_NODE follow-ups, and no more"
        );
    }

    /// A responder resuming at a record it passed over re-sends the tail of the
    /// page it just served: the packer skips a record too large for the budget
    /// *left*, then rewinds so a later page can lead with it. Those duplicates
    /// cost bandwidth, and nothing can be done about that from here — but
    /// charging them to the per-node offer allowance as well spent a
    /// well-stocked storer's budget on records this search already held, cutting
    /// it off before it ran out of either pages or key.
    #[test]
    fn a_re_sent_record_costs_bandwidth_but_not_offer_allowance() {
        let target = keyword_target("ubuntu");
        let mut rt = RoutingTable::new(make_id(0x00), false);
        let peer = make_contact(0xF0);
        rt.add_contact(peer.clone());

        let mut sm = SearchManager::new();
        let sid = sm.start_find_value(target, vec![], &rt).expect("slot");
        let search = sm.get_mut(sid).unwrap();

        // Four records that do not divide evenly into a datagram: record 1 is
        // too large for the budget left after record 0, so page one takes 0, 2
        // and 3 and resumes at 1. Page two leads with 1 — where it always fits —
        // and re-sends 2 and 3 behind it.
        const TOTAL: u16 = 4;
        let script: [(u16, &[u16], u16); 2] = [(0, &[0, 2, 3], 1), (1, &[1, 2, 3], TOTAL)];

        let mut blobs_on_the_wire = 0usize;
        for (expected_start, served, next_position) in script {
            let batch = search.next_to_query();
            assert_eq!(batch.len(), 1, "only one node is known");
            let query = &batch[0];
            assert_eq!(query.start_position, expected_start);
            blobs_on_the_wire += served.len();
            let blobs = served
                .iter()
                .map(|i| signed_value_blob("ubuntu", *i))
                .collect();
            search.process_response(
                query.request_id,
                &peer.node_id,
                vec![],
                blobs,
                Some(ValuePage {
                    next_position,
                    total_available: TOTAL,
                }),
            );
        }

        assert_eq!(
            blobs_on_the_wire, 6,
            "the rewind is what puts two of the four records on the wire twice"
        );
        assert_eq!(
            search.results.len(),
            TOTAL as usize,
            "and every distinct record still reaches the caller exactly once"
        );
        assert_eq!(
            search.offered_results.get(&peer.node_id).copied(),
            Some(TOTAL as usize),
            "the allowance is charged per distinct record, not per blob received"
        );
        assert!(
            search.next_to_query().is_empty(),
            "the key is exhausted, so there is nothing left to page"
        );
        assert!(search.poll_complete());
    }

    /// A responder that names an offset it has already served would otherwise
    /// have the search re-ask the same window until the timeout, every answer
    /// deduping to nothing while still costing a round trip.
    #[test]
    fn a_page_that_does_not_advance_earns_no_follow_up() {
        let target = keyword_target("ubuntu");
        let mut rt = RoutingTable::new(make_id(0x00), false);
        let peer = make_contact(0xF0);
        rt.add_contact(peer.clone());

        let mut sm = SearchManager::new();
        let sid = sm.start_find_value(target, vec![], &rt).expect("slot");
        let search = sm.get_mut(sid).unwrap();
        let batch = search.next_to_query();
        let query = &batch[0];
        assert_eq!(query.start_position, 0);

        search.process_response(
            query.request_id,
            &peer.node_id,
            vec![],
            vec![signed_value_blob("ubuntu", 0)],
            // Claims plenty more, but points back at the window just served.
            Some(ValuePage {
                next_position: 0,
                total_available: 900,
            }),
        );

        assert!(
            search.next_to_query().is_empty(),
            "a page that does not advance must not be followed"
        );
        assert!(search.poll_complete());
    }

    /// A page that goes unanswered must not put the node back on the walk as if
    /// it had never replied: it would be re-asked from offset zero for records
    /// it has already handed over, and a well-stocked peer would be re-served
    /// its own first page for the life of the search.
    #[test]
    fn an_unanswered_page_does_not_requery_the_node_from_the_start() {
        let target = keyword_target("ubuntu");
        let mut rt = RoutingTable::new(make_id(0x00), false);
        let peer = make_contact(0xF0);
        rt.add_contact(peer.clone());

        let mut sm = SearchManager::new();
        let sid = sm.start_find_value(target, vec![], &rt).expect("slot");
        let search = sm.get_mut(sid).unwrap();
        let first = search.next_to_query();
        search.process_response(
            first[0].request_id,
            &peer.node_id,
            vec![],
            vec![signed_value_blob("ubuntu", 0)],
            Some(ValuePage {
                next_position: 1,
                total_available: 40,
            }),
        );

        let page = search.next_to_query();
        assert_eq!(page[0].start_position, 1);
        assert_eq!(search.mark_failed(page[0].request_id), Some(peer.node_id));

        assert!(
            search.next_to_query().is_empty(),
            "a timed-out page must not re-open the node's first query"
        );
        assert!(search.poll_complete());
    }

    /// A timeout is not proof a node is gone. Giving up on the first miss
    /// removed reachable peers from the walk on any lossy path.
    #[test]
    fn a_node_that_times_out_once_is_asked_again() {
        let target = make_id(0x01);
        let mut rt = RoutingTable::new(make_id(0x00), false);
        let peer = make_contact(0xF0);
        rt.add_contact(peer.clone());

        let mut sm = SearchManager::new();
        let sid = sm.start_find_node(target, &rt).expect("slot");
        let search = sm.get_mut(sid).unwrap();

        let (_, first) = search.query_pairs().remove(0);
        assert_eq!(search.mark_failed(first), Some(peer.node_id));
        assert!(!search.complete, "one miss must not end a one-peer search");

        let retry = search.query_pairs();
        assert_eq!(retry.len(), 1, "the node is eligible again");
        assert_eq!(retry[0].0.node_id, peer.node_id);
    }

    /// Only if something is going to ask again. The send-failure path registers
    /// no wire request, so no deadline exists to expire and re-drive the walk —
    /// a node put back on `Pending` there is work `check_complete` sees as
    /// outstanding forever, and a one-entry shortlist held its search slot and
    /// its waiter until the whole-search backstop two minutes later.
    #[test]
    fn a_query_that_never_reached_the_wire_ends_a_one_peer_search() {
        let target = make_id(0x01);
        let mut rt = RoutingTable::new(make_id(0x00), false);
        let peer = make_contact(0xF0);
        rt.add_contact(peer.clone());

        let mut sm = SearchManager::new();
        let sid = sm.start_find_node(target, &rt).expect("slot");
        let search = sm.get_mut(sid).unwrap();

        let (_, first) = search.query_pairs().remove(0);
        assert_eq!(
            search.mark_failed_with(first, QueryFailure::NotSent),
            Some(peer.node_id)
        );
        const _: () = assert!(
            MAX_QUERY_ATTEMPTS > 1,
            "the point is that the node still had an attempt to spare"
        );
        assert!(
            search.complete,
            "a walk nothing will re-drive has to finish on the spot"
        );
        assert!(
            search.query_pairs().is_empty(),
            "and must not queue a retry no one is going to send"
        );
    }

    /// The other arm has to keep the retry, since the deadline sweep that
    /// reports a timeout drives the search again straight afterwards.
    #[test]
    fn a_timed_out_query_is_still_retried_when_asked_for_explicitly() {
        let target = make_id(0x01);
        let mut rt = RoutingTable::new(make_id(0x00), false);
        let peer = make_contact(0xF0);
        rt.add_contact(peer.clone());

        let mut sm = SearchManager::new();
        let sid = sm.start_find_node(target, &rt).expect("slot");
        let search = sm.get_mut(sid).unwrap();

        let (_, first) = search.query_pairs().remove(0);
        assert_eq!(
            search.mark_failed_with(first, QueryFailure::TimedOut),
            Some(peer.node_id)
        );
        assert!(!search.complete, "one miss must not end a one-peer search");
        let retry = search.query_pairs();
        assert_eq!(retry.len(), 1, "the node is eligible again");
        assert_eq!(retry[0].0.node_id, peer.node_id);
    }

    /// A publish-target lookup resolves through `closest_responded`, and
    /// `network/mod.rs` files that set as the key's replicas for hours. Pinned
    /// session peers are kept past rank k and asked first, so a walk that has
    /// to exhaust its shortlist — which a dead contact at the head forces, and
    /// that is not rare — leaves more than k nodes responded and fans the
    /// record out past `K_EMBER_REPLICAS`.
    #[test]
    fn a_lookup_resolves_with_at_most_k_nodes() {
        let target = make_id(0x00);
        let rt = table_with_contacts(make_id(0xFF), K_BUCKET_SIZE as u8);

        let mut sm = SearchManager::new();
        let sid = sm.start_find_node(target, &rt).expect("slot");
        // Connected session peers, pinned exactly as `start_ember_find_node`
        // does, and far enough out to sit past the k-trim.
        let extras: Vec<EmberContact> = (0..4).map(|i| make_contact(0xF0 + i)).collect();
        assert_eq!(sm.seed_extra_contacts(sid, extras), 4);

        let search = sm.get_mut(sid).unwrap();
        // The closest contact never answers, so the head can never be
        // `Responded` and convergence cannot fire: the walk exhausts instead.
        let dead_head = make_id(0x40);
        let mut responded = 0usize;
        loop {
            let batch = search.query_pairs();
            if batch.is_empty() {
                break;
            }
            for (contact, req_id) in batch {
                if contact.node_id == dead_head {
                    search.mark_failed(req_id);
                } else {
                    search.process_unpaged(req_id, &contact.node_id, vec![], vec![]);
                    responded += 1;
                }
            }
        }

        assert!(
            responded > K_BUCKET_SIZE,
            "the walk has to leave more than k nodes responded for this to bite, \
             got {responded}"
        );
        let resolved = search.closest_responded();
        assert_eq!(
            resolved.len(),
            K_BUCKET_SIZE,
            "a lookup must not resolve with more replicas than a key is meant to have"
        );
        assert!(
            !resolved.iter().any(|c| c.node_id == make_id(0xF3)),
            "and the entries dropped must be the farthest ones"
        );
    }

    /// Retry has to be bounded, or a dead node keeps a search alive forever.
    #[test]
    fn retries_are_capped_so_a_dead_node_ends_the_search() {
        let target = make_id(0x01);
        let mut rt = RoutingTable::new(make_id(0x00), false);
        rt.add_contact(make_contact(0xF0));

        let mut sm = SearchManager::new();
        let sid = sm.start_find_node(target, &rt).expect("slot");
        let search = sm.get_mut(sid).unwrap();

        for attempt in 1..=MAX_QUERY_ATTEMPTS {
            let batch = search.query_pairs();
            assert_eq!(batch.len(), 1, "attempt {attempt} should go out");
            search.mark_failed(batch[0].1);
        }

        assert!(
            search.query_pairs().is_empty(),
            "the node is spent after {MAX_QUERY_ATTEMPTS} attempts"
        );
        assert!(search.poll_complete(), "and the search converges");
    }

    #[test]
    fn keyword_hash_deterministic() {
        let h1 = keyword_hash("test");
        let h2 = keyword_hash("test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn keyword_hash_case_insensitive() {
        let h1 = keyword_hash("Hello");
        let h2 = keyword_hash("hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_keyword_hashes_sorts_by_length() {
        let hashes = compute_keyword_hashes("a longer short");
        assert_eq!(hashes.len(), 2); // "a" filtered out (under 3 bytes)
        assert_eq!(hashes[0].1, "longer"); // longest first
        assert_eq!(hashes[1].1, "short");
    }

    /// The publisher splits a filename on separators, so a query carrying one
    /// has to be split the same way or it walks to a key nothing was stored
    /// under.
    #[test]
    fn a_query_is_tokenized_exactly_like_the_filename_it_should_match() {
        let published = crate::network::kad::publish::extract_keywords("Blade.Runner.2049.mkv");
        let searched: Vec<String> = compute_keyword_hashes("Blade.Runner.2049")
            .into_iter()
            .map(|(_, kw)| kw)
            .collect();
        for token in ["blade", "runner", "2049"] {
            assert!(
                published.contains(&token.to_string()),
                "publisher stores {token}"
            );
            assert!(
                searched.contains(&token.to_string()),
                "search must ask for {token}"
            );
        }
    }

    /// Pasting a filename into the search box is the ordinary case, so the key
    /// it walks must be one the publisher of that filename wrote to.
    #[test]
    fn pasting_a_filename_walks_a_key_the_publisher_wrote_to() {
        let name = "ubuntu-24.04-desktop.iso";
        let publisher_keys: Vec<[u8; 16]> = crate::network::kad::publish::extract_keywords(name)
            .iter()
            .map(|kw| keyword_hash(kw))
            .collect();
        let primary = compute_keyword_hashes(name)
            .first()
            .map(|(hash, _)| *hash)
            .expect("a filename yields at least one query key");
        assert!(
            publisher_keys.contains(&primary),
            "the walked key must be one the publisher stored under"
        );
    }

    /// The trailing-three-character strip exists to drop `.mkv` off a filename.
    /// Applied to a query it would throw away the last word typed, which is
    /// usually the most specific one.
    #[test]
    fn a_query_keeps_its_last_short_word() {
        let searched: Vec<String> = compute_keyword_hashes("the big cat")
            .into_iter()
            .map(|(_, kw)| kw)
            .collect();
        assert_eq!(searched.len(), 3);
        assert!(
            searched.contains(&"cat".to_string()),
            "the most specific word must survive"
        );
    }

    #[test]
    fn compute_keyword_hashes_drops_non_adjacent_duplicates() {
        // "iso" repeats with a same-length word between the two copies, so
        // sorting by length alone leaves them non-adjacent.
        let hashes = compute_keyword_hashes("iso abc iso");
        assert_eq!(hashes.len(), 2, "the repeated keyword is counted once");
        assert_eq!(hashes.iter().filter(|(_, k)| k == "iso").count(), 1);
    }

    #[test]
    fn extra_keyword_hashes_skip_on_or_keep_on_and() {
        let hashed = compute_keyword_hashes("ubuntu server");
        assert_eq!(hashed.len(), 2);
        assert!(extra_keyword_hashes(&hashed, false).is_empty());
        assert_eq!(extra_keyword_hashes(&hashed, true).len(), 1);
        assert_eq!(extra_keyword_hashes(&hashed, true)[0], hashed[1].0);
    }

    #[test]
    fn a_shortlist_trim_never_drops_a_query_in_flight() {
        // One peer can answer with a full K contacts, all closer than another
        // peer we are still waiting on. Trimming the shortlist purely by
        // distance would evict that outstanding entry, hiding it from the
        // in-flight check and from ALPHA accounting.
        let target = make_id(0x01);
        let local = make_id(0x00);
        let mut rt = RoutingTable::new(local, false);
        let responder = make_contact(0xF0);
        let still_waiting = make_contact(0xE0);
        rt.add_contact(responder.clone());
        rt.add_contact(still_waiting.clone());

        let mut sm = SearchManager::new();
        let sid = sm.start_find_node(target, &rt).expect("search slot");
        let search = sm.get_mut(sid).unwrap();

        let batch = search.query_pairs();
        assert_eq!(batch.len(), 2, "both known contacts go out together");
        let req_id = batch
            .iter()
            .find(|(c, _)| c.node_id == responder.node_id)
            .map(|(_, r)| *r)
            .expect("responder was queried");

        // A full response, every contact closer to the target than either
        // peer already on the shortlist.
        let closer: Vec<EmberContact> = (2..=(K_BUCKET_SIZE as u8 + 1)).map(make_contact).collect();
        assert_eq!(closer.len(), K_BUCKET_SIZE);
        search.process_unpaged(req_id, &responder.node_id, closer, vec![]);

        let waiting = search
            .shortlist
            .iter()
            .find(|e| e.contact.node_id == still_waiting.node_id)
            .expect("the outstanding query must survive the trim");
        assert_eq!(waiting.state, NodeState::InFlight);
        assert!(!search.complete, "a reply is still outstanding");
    }

    #[test]
    fn search_manager_find_node() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        rt.add_contact(make_contact(0x80));
        rt.add_contact(make_contact(0x40));
        rt.add_contact(make_contact(0x20));

        let mut sm = SearchManager::new();
        let search_id = sm.start_find_node(make_id(0xFF), &rt).expect("search slot");

        let search = sm.get_mut(search_id).unwrap();
        let to_query = search.query_pairs();
        assert!(!to_query.is_empty());
        assert!(to_query.len() <= ALPHA);
    }

    #[test]
    fn search_converges() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        rt.add_contact(make_contact(0x80));

        let mut sm = SearchManager::new();
        let search_id = sm.start_find_node(make_id(0xFF), &rt).expect("search slot");

        let search = sm.get_mut(search_id).unwrap();
        let batch = search.query_pairs();
        assert!(!batch.is_empty());

        // Simulate response with no new nodes
        let (_, req_id) = &batch[0];
        search.process_unpaged(*req_id, &make_id(0x80), vec![], vec![]);

        // No more pending, no in-flight → complete
        assert!(search.complete);
    }

    /// The driver retires a query's wire-correlation entry and dispatches the
    /// next round only when a response is *accepted*. Reporting acceptance as
    /// "found something closer" made a value hit — which carries no contacts
    /// at all — and a converged final hop both look like refusals, so the
    /// lookup stalled for a full query timeout at every hop that mattered.
    #[test]
    fn a_correct_answer_is_accepted_even_when_it_brings_nothing_closer() {
        let local = make_id(0x00);
        let mut rt = RoutingTable::new(local, false);
        rt.add_contact(make_contact(0x80));

        let mut sm = SearchManager::new();
        let sid = sm.start_find_node(make_id(0xFF), &rt).expect("search slot");
        let search = sm.get_mut(sid).unwrap();
        let (_, req_id) = search.query_pairs().into_iter().next().unwrap();

        let outcome = search.process_unpaged(req_id, &make_id(0x80), vec![], vec![]);
        assert!(
            outcome.accepted,
            "a peer that knows nobody closer still answered the question"
        );
        assert!(!outcome.new_closer);

        // And a reply from someone we did not ask is still refused, so the
        // query stays outstanding for the peer that owes us one.
        let mut sm = SearchManager::new();
        let sid = sm.start_find_node(make_id(0xFF), &rt).expect("search slot");
        let search = sm.get_mut(sid).unwrap();
        let (_, req_id) = search.query_pairs().into_iter().next().unwrap();
        let outcome = search.process_unpaged(req_id, &make_id(0x7F), vec![], vec![]);
        assert_eq!(outcome, ResponseOutcome::REFUSED);
        assert!(
            search.pending_requests.contains_key(&req_id),
            "the real responder's slot must survive an impostor's answer"
        );
    }

    #[test]
    fn search_discovers_closer_node_multi_hop() {
        // We only know B at the start; B points us at a much closer C;
        // the search must hop to C and then converge with both responded.
        let local = make_id(0x00);
        let mut rt = RoutingTable::new(local, false);
        rt.add_contact(make_contact(0x80)); // B

        let target = make_id(0x01);
        let mut sm = SearchManager::new();
        let sid = sm.start_find_node(target, &rt).expect("search slot");
        let search = sm.get_mut(sid).unwrap();

        // Round 1: the only pending node is B.
        let batch = search.query_pairs();
        assert_eq!(batch.len(), 1);
        let (b_contact, b_req) = batch.into_iter().next().unwrap();
        assert_eq!(b_contact.node_id, make_id(0x80));

        // B answers with a closer node C (dist 0x02 < B's 0x81).
        let c = make_contact(0x03);
        let outcome = search.process_unpaged(b_req, &make_id(0x80), vec![c], vec![]);
        assert!(outcome.accepted);
        assert!(outcome.new_closer, "C is closer than B → search continues");
        assert!(!search.complete, "C is still pending");

        // Round 2: hop to C.
        let batch2 = search.query_pairs();
        assert_eq!(batch2.len(), 1);
        let (c_contact, c_req) = batch2.into_iter().next().unwrap();
        assert_eq!(c_contact.node_id, make_id(0x03));

        // C knows no one closer → search converges.
        search.process_unpaged(c_req, &make_id(0x03), vec![], vec![]);
        assert!(search.complete);

        let responded = search.closest_responded();
        assert_eq!(
            responded.first().map(|x| x.node_id),
            Some(make_id(0x03)),
            "closest responded node should be C"
        );
        assert!(responded.iter().any(|x| x.node_id == make_id(0x80)));
    }

    #[test]
    fn poll_complete_finishes_empty_search() {
        // A search seeded from an empty routing table has nothing to
        // query; the driver relies on poll_complete to recognise this
        // instead of stalling until the overall timeout.
        let local = make_id(0x00);
        let rt = RoutingTable::new(local, false);
        let mut sm = SearchManager::new();
        let sid = sm.start_find_node(make_id(0xFF), &rt).expect("search slot");
        let search = sm.get_mut(sid).unwrap();

        assert!(search.query_pairs().is_empty());
        assert!(search.poll_complete(), "empty search must complete on poll");
        assert!(search.closest_responded().is_empty());
    }

    #[test]
    fn search_processes_value_results() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        rt.add_contact(make_contact(0x80));

        let target = keyword_target("ubuntu");
        let mut sm = SearchManager::new();
        let search_id = sm
            .start_find_value(target, vec![], &rt)
            .expect("search slot");

        let search = sm.get_mut(search_id).unwrap();
        let batch = search.query_pairs();
        let (_, req_id) = &batch[0];

        let matching = signed_value_blob("ubuntu", 0x01);
        // A second, genuinely different record under the same key — two
        // publishers, or one publisher with two files. Distinct content
        // matters: identical blobs are deduplicated, so repeating one here
        // would test the dedup rather than the keyword binding this covers.
        let other_matching = signed_value_blob("ubuntu", 0x02);
        // Signed just as properly, but filed under another word, so it is the
        // key binding alone that turns it away.
        let mismatched = signed_value_blob("debian", 0x03);

        search.process_unpaged(
            *req_id,
            &make_id(0x80),
            vec![],
            vec![matching, mismatched, other_matching],
        );

        assert_eq!(
            search.results.len(),
            2,
            "both distinct records kept, the wrong-key one dropped"
        );
    }

    /// The extra keys on a `FIND_VALUE` are an AND filter for multi-word
    /// search, never a union. The walk converges on the primary alone, and a
    /// record filed under a secondary is dropped the moment it arrives — so
    /// batching independent keys into one search returns a fraction of them
    /// and reports success. That is how the public-channel index came to serve
    /// two of its sixteen shards; `commands::channels::gather_channels` runs
    /// one search per shard, and this is the property that says it must.
    #[test]
    fn a_multi_key_find_value_returns_nothing_for_its_secondary_keys() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        rt.add_contact(make_contact(0x80));

        let primary = keyword_target("ubuntu");
        let secondary = keyword_target("debian");
        let mut sm = SearchManager::new();
        let search_id = sm
            .start_find_value(primary, vec![secondary.0], &rt)
            .expect("search slot");

        let search = sm.get_mut(search_id).unwrap();
        let batch = search.query_pairs();
        let (_, req_id) = &batch[0];

        search.process_unpaged(
            *req_id,
            &make_id(0x80),
            vec![],
            vec![
                signed_value_blob("ubuntu", 0x01),
                signed_value_blob("debian", 0x02),
            ],
        );

        assert_eq!(
            search.results.len(),
            1,
            "a record filed under a secondary key must not reach the caller"
        );
    }

    #[test]
    fn seed_extra_contacts_are_queried_first_and_survive_the_k_trim() {
        let local = make_id(0);
        let target = make_id(0);
        let rt = table_with_contacts(local, K_BUCKET_SIZE as u8);
        let mut extra = make_contact(0xFE);
        extra.addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 4672);

        let mut sm = SearchManager::new();
        let sid = sm
            .start_find_value(target, vec![], &rt)
            .expect("search slot");
        assert_eq!(sm.seed_extra_contacts(sid, vec![extra.clone()]), 1);

        let search = sm.get_mut(sid).unwrap();
        let batch = search.query_pairs();
        assert_eq!(
            batch[0].0.node_id, extra.node_id,
            "a connected session peer is asked before XOR-closest public nodes"
        );

        let responder = batch
            .iter()
            .find(|(c, _)| c.node_id != extra.node_id)
            .expect("the first batch still includes a routing-table contact");
        let closer: Vec<EmberContact> = (2..=(K_BUCKET_SIZE as u8 + 1)).map(make_contact).collect();
        search.process_unpaged(responder.1, &responder.0.node_id, closer, vec![]);
        assert!(
            search
                .shortlist
                .iter()
                .any(|e| e.contact.node_id == extra.node_id && e.pinned),
            "a pinned session peer must not be trimmed off by closer gossip"
        );
    }
}
