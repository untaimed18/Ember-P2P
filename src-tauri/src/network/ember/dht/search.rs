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

        // Collect value results
        for data in value_records {
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

        // Re-sort and trim
        self.shortlist
            .sort_by(|a, b| a.distance.0.cmp(&b.distance.0));
        self.shortlist.truncate(K_BUCKET_SIZE);

        // Check convergence
        self.check_complete();

        new_closer
    }

    /// Mark a node's request as failed (timeout, error).
    pub fn mark_failed(&mut self, request_id: u32) {
        if let Some(node_id) = self.pending_requests.remove(&request_id) {
            for entry in &mut self.shortlist {
                if entry.contact.node_id == node_id {
                    entry.state = NodeState::Failed;
                    break;
                }
            }
        }
        self.check_complete();
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
        let initial = routing_table.find_closest(&target, K_BUCKET_SIZE);
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
        let initial = routing_table.find_closest(&primary_key, K_BUCKET_SIZE);
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
/// Multi-keyword search hashes each keyword individually and searches
/// for the primary (longest) keyword, then intersects results client-side
/// for secondary keywords.
pub fn keyword_hash(keyword: &str) -> [u8; 16] {
    let normalized = keyword.to_lowercase();
    let hash = blake3::hash(normalized.as_bytes());
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash.as_bytes()[..16]);
    key
}

/// Compute keyword hashes for a multi-word query. Returns a list of
/// (keyword_hash, keyword_text) pairs, sorted by keyword length descending
/// (so the first entry is the primary keyword used for DHT lookup).
pub fn compute_keyword_hashes(query: &str) -> Vec<([u8; 16], String)> {
    let mut keywords: Vec<String> = query
        .split_whitespace()
        .filter(|w| w.len() >= 2)
        .map(|w| w.to_lowercase())
        .collect();

    keywords.sort_by(|a, b| b.len().cmp(&a.len()));
    keywords.dedup();

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
    fn search_manager_find_node() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local);
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
        let mut rt = RoutingTable::new(local);
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
    fn search_processes_value_results() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local);
        rt.add_contact(make_contact(0x80));

        let mut sm = SearchManager::new();
        let search_id = sm
            .start_find_value(make_id(0xFF), vec![], &rt)
            .expect("search slot");

        let search = sm.get_mut(search_id).unwrap();
        let batch = search.next_to_query();
        let (_, req_id) = &batch[0];

        search.process_response(
            *req_id,
            &make_id(0x80),
            vec![],
            vec![b"record1".to_vec(), b"record2".to_vec()],
        );

        assert_eq!(search.results.len(), 2);
    }
}
