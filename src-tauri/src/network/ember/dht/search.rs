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
    /// Nodes we've already queried (to avoid duplicates).
    queried: HashSet<EmberNodeId>,
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
            queried: HashSet::new(),
            started_at: Instant::now(),
            complete: false,
            pending_requests: HashMap::new(),
            next_request_id: 1,
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
                let req_id = self.next_request_id;
                self.next_request_id = self.next_request_id.wrapping_add(1);
                self.pending_requests.insert(req_id, entry.contact.node_id);
                batch.push((entry.contact.clone(), req_id));
            }
        }
        batch
    }

    /// Process a FOUND_NODE / FOUND_VALUE response from a peer.
    /// Returns true if new closer nodes were discovered (search should continue).
    pub fn process_response(
        &mut self,
        request_id: u32,
        from_id: &EmberNodeId,
        closer_nodes: Vec<EmberContact>,
        value_records: Vec<Vec<u8>>,
    ) -> bool {
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
            return false;
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

        // Check convergence
        self.check_complete();

        new_closer
    }

    /// Mark a node's request as failed (timeout, error).
    ///
    /// Returns which node it was, so the caller can also hold the failure
    /// against the routing table. Without that, a dead gossip lead stayed a
    /// lookup seed until the liveness sweep happened to reach it.
    pub fn mark_failed(&mut self, request_id: u32) -> Option<EmberNodeId> {
        let failed = self.pending_requests.remove(&request_id);
        if let Some(node_id) = failed {
            for entry in &mut self.shortlist {
                if entry.contact.node_id == node_id {
                    entry.state = NodeState::Failed;
                    break;
                }
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

        // For FIND_VALUE, complete if we have enough results
        if self.search_type == SearchType::FindValue && self.results.len() >= MAX_SEARCH_RESULTS {
            self.complete = true;
        }
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
            if search.results.len() >= MAX_SEARCH_RESULTS {
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
        let progressed = search.process_response(b_req, &make_id(0x80), vec![c], vec![]);
        assert!(progressed, "C is closer than B → search continues");
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
        let mut mismatched = matching.clone();
        mismatched[1] ^= 0xFF;

        search.process_response(
            *req_id,
            &make_id(0x80),
            vec![],
            vec![matching.clone(), mismatched, matching],
        );

        assert_eq!(search.results.len(), 2);
    }
}
