use std::collections::{HashMap, HashSet};
use std::time::Instant;

use tracing::{debug, trace, warn};

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

/// How many times one node may be queried within a single search.
///
/// A timeout is not proof a node is gone — it may have been mid-handshake,
/// briefly saturated, or the datagram may simply have been lost. Marking it
/// failed forever on the first miss threw away real peers on lossy paths. Two
/// is the smallest value that tolerates a single loss, and it bounds the extra
/// work at one repeat query per node so a search still converges.
const MAX_QUERY_ATTEMPTS: u8 = 2;

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
}

/// Type of iterative search.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SearchType {
    /// FIND_NODE: looking for nodes closest to a target.
    FindNode,
    /// FIND_VALUE: looking for records associated with keys.
    FindValue,
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
    /// Request IDs we've sent mapped to the node we sent them to.
    pending_requests: HashMap<u32, EmberNodeId>,
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
            .map(|c| {
                let distance = target.distance(&c.node_id);
                ShortlistEntry {
                    contact: c,
                    distance,
                    state: NodeState::Pending,
                }
            })
            .collect();
        shortlist.sort_by(|a, b| a.distance.0.cmp(&b.distance.0));
        shortlist.truncate(K_BUCKET_SIZE);

        Self {
            id,
            search_type,
            target,
            keyword_hashes,
            shortlist,
            results: Vec::new(),
            seen_results: HashSet::new(),
            queried: HashSet::new(),
            attempts: HashMap::new(),
            started_at: Instant::now(),
            complete: false,
            pending_requests: HashMap::new(),
            next_request_id: 1,
            stale_responses: 0,
        }
    }

    /// Get the next batch of nodes to query (up to ALPHA at a time).
    /// Returns contacts that are Pending and haven't been queried yet.
    pub fn next_to_query(&mut self) -> Vec<(EmberContact, u32)> {
        let in_flight = self
            .shortlist
            .iter()
            .filter(|e| e.state == NodeState::InFlight)
            .count();

        let can_send = ALPHA.saturating_sub(in_flight);
        if can_send == 0 {
            return Vec::new();
        }

        let mut batch = Vec::new();
        for entry in &mut self.shortlist {
            if batch.len() >= can_send {
                break;
            }
            if entry.state == NodeState::Pending && !self.queried.contains(&entry.contact.node_id) {
                entry.state = NodeState::InFlight;
                self.queried.insert(entry.contact.node_id);
                *self.attempts.entry(entry.contact.node_id).or_insert(0) += 1;
                let req_id = self.next_request_id;
                self.next_request_id = self.next_request_id.wrapping_add(1);
                self.pending_requests.insert(req_id, entry.contact.node_id);
                batch.push((entry.contact.clone(), req_id));
            }
        }
        batch
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
        value_records: Vec<Vec<u8>>,
    ) -> ResponseOutcome {
        // Reject responses we didn't ask for: an attacker (or a buggy
        // peer) sending arbitrary `(request_id, from_id)` pairs must
        // not be able to flip a node to `Responded`, merge `closer_nodes`,
        // or contribute to `value_records`. The caller is responsible
        // for transport-layer auth; this is the request-correlation
        // gate.
        let expected = self.pending_requests.remove(&request_id);
        if expected.as_ref() != Some(from_id) {
            debug!(
                "Search {}: rejected response from {} (request_id {} expected {:?})",
                self.id, from_id, request_id, expected
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
            // Dedup before the cap, not after: counting copies against
            // `MAX_SEARCH_RESULTS` is what let a well-replicated record end
            // the search before the closer hops were reached.
            if !self.seen_results.insert(*blake3::hash(&data).as_bytes()) {
                continue;
            }
            if self.results.len() < MAX_SEARCH_RESULTS {
                self.results.push(SearchResultRecord {
                    data,
                    from_node: *from_id,
                });
            }
        }

        // Merge closer nodes into shortlist
        let mut new_closer = false;
        let current_best = self
            .shortlist
            .first()
            .map(|e| e.distance)
            .unwrap_or(EmberNodeId([0xFF; 16]));

        for contact in closer_nodes {
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
            .sort_by(|a, b| a.distance.0.cmp(&b.distance.0));
        if self.shortlist.len() > K_BUCKET_SIZE {
            let mut kept = 0usize;
            self.shortlist.retain(|e| {
                kept += 1;
                kept <= K_BUCKET_SIZE || e.state == NodeState::InFlight
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
        let failed = self.pending_requests.remove(&request_id);
        if let Some(node_id) = failed {
            let spent = self.attempts.get(&node_id).copied().unwrap_or(MAX_QUERY_ATTEMPTS);
            let retryable = spent < MAX_QUERY_ATTEMPTS;
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
        failed
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

        // Complete if no more nodes to query and nothing in flight
        let has_pending = self.shortlist.iter().any(|e| e.state == NodeState::Pending);
        let has_in_flight = self
            .shortlist
            .iter()
            .any(|e| e.state == NodeState::InFlight);

        if !has_pending && !has_in_flight {
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
    fn responded_count(&self) -> usize {
        self.shortlist
            .iter()
            .filter(|e| e.state == NodeState::Responded)
            .count()
    }

    /// Get the closest responded nodes (useful for FIND_NODE results).
    pub fn closest_responded(&self) -> Vec<EmberContact> {
        self.shortlist
            .iter()
            .filter(|e| e.state == NodeState::Responded)
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
            // blobs. The store already refuses a record whose embedded key
            // differs from the key it is filed under, so this should never
            // reject anything; keeping the two paths identical means the
            // invariant holds here even if that gate ever moves.
            if data.len() < 17 + 64 || data[1..17] != search.target.0 {
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

    /// Clean up timed-out searches. Returns IDs of removed searches.
    pub fn cleanup_expired(&mut self) -> Vec<u32> {
        let expired: Vec<u32> = self
            .searches
            .iter()
            .filter(|(_, s)| s.started_at.elapsed().as_secs() > SEARCH_TIMEOUT_SECS * 2)
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            self.searches.remove(id);
        }
        if !expired.is_empty() {
            debug!("Cleaned up {} expired searches", expired.len());
        }
        expired
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
pub fn compute_keyword_hashes(query: &str) -> Vec<([u8; 16], String)> {
    let mut keywords: Vec<String> = query
        .split_whitespace()
        .filter(|w| w.len() >= 2)
        .map(|w| w.to_lowercase())
        .collect();

    keywords.sort_by(|a, b| b.len().cmp(&a.len()));
    // Not `dedup()`: it only collapses adjacent equals, and sorting by length
    // alone can leave two copies of a keyword separated by a same-length one.
    // A duplicate would spend one of the few FIND_VALUE key slots on a key
    // already being queried.
    let mut seen = std::collections::HashSet::new();
    keywords.retain(|k| seen.insert(k.clone()));

    keywords
        .into_iter()
        .map(|kw| (keyword_hash(&kw), kw))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
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

    /// A FOUND_VALUE blob shaped the way `process_response` validates it:
    /// record type, the queried keyword hash at [1..17], a body, then the
    /// 64-byte publisher signature.
    fn value_blob(target: EmberNodeId, filler: u8) -> Vec<u8> {
        let mut blob = vec![0x01u8];
        blob.extend_from_slice(&target.0);
        blob.extend_from_slice(&[filler; 16]);
        blob.extend_from_slice(&[filler; 64]);
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
            let batch = search.next_to_query();
            if batch.is_empty() {
                break;
            }
            for (contact, req_id) in batch {
                search.process_response(req_id, &contact.node_id, vec![], vec![]);
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
        let batch = search.next_to_query();
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
            let closer = if i == 0 { vec![phantom.clone()] } else { vec![] };
            search.process_response(req_id, &contact.node_id, closer, vec![]);
            answered += 1;
        }

        // Everyone else answers honestly with nothing closer, and the phantom
        // never answers at all.
        loop {
            let batch = search.next_to_query();
            if batch.is_empty() {
                break;
            }
            for (contact, req_id) in batch {
                if contact.node_id == phantom.node_id {
                    search.mark_failed(req_id);
                } else {
                    search.process_response(req_id, &contact.node_id, vec![], vec![]);
                    answered += 1;
                }
            }
        }

        assert!(
            answered > MIN_RESPONSES_TO_CONVERGE,
            "the pin must not be able to end the walk at the convergence floor: \
             only {answered} peers were asked"
        );
        // The phantom holds one of the K shortlist slots, so exhausting the walk
        // means every other entry answered.
        assert_eq!(
            answered,
            K_BUCKET_SIZE - 1,
            "the walk must fall back to exhausting its shortlist"
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
        let target = make_id(0x01);
        let mut rt = RoutingTable::new(make_id(0x00), false);
        let a = make_contact(0xF0);
        let b = make_contact(0xE0);
        rt.add_contact(a.clone());
        rt.add_contact(b.clone());

        let mut sm = SearchManager::new();
        let sid = sm.start_find_value(target, vec![], &rt).expect("slot");
        let search = sm.get_mut(sid).unwrap();
        let batch = search.next_to_query();

        let shared = value_blob(target, 0x11);
        let only_b = value_blob(target, 0x22);
        for (contact, req_id) in batch {
            let records = if contact.node_id == b.node_id {
                vec![shared.clone(), only_b.clone()]
            } else {
                vec![shared.clone()]
            };
            search.process_response(req_id, &contact.node_id, vec![], records);
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
        let target = make_id(0x01);
        let mut rt = RoutingTable::new(make_id(0x00), false);
        let peer = make_contact(0xF0);
        rt.add_contact(peer.clone());

        let mut sm = SearchManager::new();
        let sid = sm.start_find_value(target, vec![], &rt).expect("slot");
        let search = sm.get_mut(sid).unwrap();
        let (_, req_id) = search.next_to_query().remove(0);

        let blob = value_blob(target, 0x33);
        search.process_response(req_id, &peer.node_id, vec![], vec![blob.clone(); 50]);

        assert_eq!(search.results.len(), 1);
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

        let (_, first) = search.next_to_query().remove(0);
        assert_eq!(search.mark_failed(first), Some(peer.node_id));
        assert!(!search.complete, "one miss must not end a one-peer search");

        let retry = search.next_to_query();
        assert_eq!(retry.len(), 1, "the node is eligible again");
        assert_eq!(retry[0].0.node_id, peer.node_id);
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
            let batch = search.next_to_query();
            assert_eq!(batch.len(), 1, "attempt {attempt} should go out");
            search.mark_failed(batch[0].1);
        }

        assert!(
            search.next_to_query().is_empty(),
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
        assert_eq!(hashes.len(), 2); // "a" filtered out (< 2 chars)
        assert_eq!(hashes[0].1, "longer"); // longest first
        assert_eq!(hashes[1].1, "short");
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

        let batch = search.next_to_query();
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
        search.process_response(req_id, &responder.node_id, closer, vec![]);

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
        let to_query = search.next_to_query();
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
        let batch = search.next_to_query();
        assert!(!batch.is_empty());

        // Simulate response with no new nodes
        let (_, req_id) = &batch[0];
        search.process_response(*req_id, &make_id(0x80), vec![], vec![]);

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
        let (_, req_id) = search.next_to_query().into_iter().next().unwrap();

        let outcome = search.process_response(req_id, &make_id(0x80), vec![], vec![]);
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
        let (_, req_id) = search.next_to_query().into_iter().next().unwrap();
        let outcome = search.process_response(req_id, &make_id(0x7F), vec![], vec![]);
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
        let batch = search.next_to_query();
        assert_eq!(batch.len(), 1);
        let (b_contact, b_req) = batch.into_iter().next().unwrap();
        assert_eq!(b_contact.node_id, make_id(0x80));

        // B answers with a closer node C (dist 0x02 < B's 0x81).
        let c = make_contact(0x03);
        let outcome = search.process_response(b_req, &make_id(0x80), vec![c], vec![]);
        assert!(outcome.accepted);
        assert!(outcome.new_closer, "C is closer than B → search continues");
        assert!(!search.complete, "C is still pending");

        // Round 2: hop to C.
        let batch2 = search.next_to_query();
        assert_eq!(batch2.len(), 1);
        let (c_contact, c_req) = batch2.into_iter().next().unwrap();
        assert_eq!(c_contact.node_id, make_id(0x03));

        // C knows no one closer → search converges.
        search.process_response(c_req, &make_id(0x03), vec![], vec![]);
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

        assert!(search.next_to_query().is_empty());
        assert!(search.poll_complete(), "empty search must complete on poll");
        assert!(search.closest_responded().is_empty());
    }

    #[test]
    fn search_processes_value_results() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        rt.add_contact(make_contact(0x80));

        let target = make_id(0xFF);
        let mut sm = SearchManager::new();
        let search_id = sm
            .start_find_value(target, vec![], &rt)
            .expect("search slot");

        let search = sm.get_mut(search_id).unwrap();
        let batch = search.next_to_query();
        let (_, req_id) = &batch[0];

        // Blobs are `record_data || 64-byte sig` with keyword_hash at [1..17].
        let mut matching = vec![0u8; 17 + 64];
        matching[1..17].copy_from_slice(&target.0);
        // A second, genuinely different record under the same key — two
        // publishers, or one publisher with two files. Distinct content
        // matters: identical blobs are deduplicated, so repeating one here
        // would test the dedup rather than the keyword binding this covers.
        let mut other_matching = matching.clone();
        other_matching[17] = 0xAB;
        let mut mismatched = matching.clone();
        mismatched[1] ^= 0xFF;

        search.process_response(
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
}
