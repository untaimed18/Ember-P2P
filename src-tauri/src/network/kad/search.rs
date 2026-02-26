use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use tracing::{debug, info};

use super::messages::*;
use super::types::*;

const KEYWORD_SEARCH_MAX_RESULTS: usize = 500;
const PENDING_TIMEOUT_SECS: i64 = 10;
const LOOKUP_CONVERGE_COUNT: usize = 5;
const LOOKUP_MIN_QUERIES: usize = 20;

/// eMule seeds searches with 50 contacts (Search.cpp Go() -> GetClosestTo(..., 50, ...))
pub const SEARCH_INITIAL_CONTACTS: usize = 50;

// Per-type timeouts matching eMule
const TIMEOUT_FIND_NODE: i64 = 45;
const TIMEOUT_KEYWORD: i64 = 90;
const TIMEOUT_SOURCE: i64 = 45;
const TIMEOUT_NOTES: i64 = 45;
const TIMEOUT_STORE_KEYWORD: i64 = 140;
const TIMEOUT_STORE_NOTES: i64 = 100;
const TIMEOUT_FIND_BUDDY: i64 = 100;
const FETCH_TIMEOUT_SECS: i64 = 45;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchType {
    FindNode,
    FindKeyword,
    FindSource { file_size: u64 },
    FindNotes { file_size: u64 },
    FindBuddy,
    StoreKeyword,
    StoreNotes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchPhase {
    /// Walking the DHT to find nodes closest to the target.
    Lookup,
    /// Querying closest nodes for actual keyword/source results.
    Fetch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SearchId(pub u64);

#[derive(Debug)]
pub struct SearchState {
    pub id: SearchId,
    pub target: KadId,
    pub search_type: SearchType,
    pub phase: SearchPhase,
    pub queried: HashSet<KadId>,
    pub pending: HashSet<KadId>,
    pub pending_times: HashMap<KadId, i64>,
    /// Contacts discovered during lookup phase, sorted by distance to target.
    pub closest: Vec<KadContact>,
    /// Contacts that have been sent the fetch query (SearchKeyReq/SearchSourceReq).
    pub fetched: HashSet<KadId>,
    pub results: Vec<SearchResultEntry>,
    pub started_at: i64,
    pub completed: bool,
    /// Set when entering fetch phase; used for fetch-specific timeout.
    fetch_started_at: Option<i64>,
    /// Tracks how many lookup rounds returned no closer contacts.
    lookup_stale_rounds: usize,
    prev_closest_distance: Option<KadId>,
    /// Contacts that responded during the lookup phase (verified alive).
    pub responded_during_lookup: HashSet<KadId>,
}

impl SearchState {
    pub fn new(id: SearchId, target: KadId, search_type: SearchType) -> Self {
        let phase = SearchPhase::Lookup;
        SearchState {
            id,
            target,
            search_type,
            phase,
            queried: HashSet::new(),
            pending: HashSet::new(),
            pending_times: HashMap::new(),
            closest: Vec::new(),
            fetched: HashSet::new(),
            results: Vec::new(),
            started_at: chrono::Utc::now().timestamp(),
            completed: false,
            fetch_started_at: None,
            lookup_stale_rounds: 0,
            prev_closest_distance: None,
            responded_during_lookup: HashSet::new(),
        }
    }

    pub fn seed(&mut self, contacts: Vec<KadContact>) {
        for c in contacts {
            if !self.queried.contains(&c.id) {
                self.closest.push(c);
            }
        }
        self.sort_closest();
    }

    /// Get the next batch of contacts to query (up to ALPHA).
    pub fn next_to_query(&mut self) -> Vec<KadContact> {
        let now = chrono::Utc::now().timestamp();
        let mut batch = Vec::new();

        match self.phase {
            SearchPhase::Lookup => {
                for contact in &self.closest {
                    if batch.len() >= ALPHA {
                        break;
                    }
                    if !self.queried.contains(&contact.id) && !self.pending.contains(&contact.id) {
                        batch.push(contact.clone());
                    }
                }
            }
            SearchPhase::Fetch => {
                // First, query contacts that responded during lookup (verified alive)
                for contact in &self.closest {
                    if batch.len() >= ALPHA {
                        break;
                    }
                    if !self.fetched.contains(&contact.id)
                        && !self.pending.contains(&contact.id)
                        && self.responded_during_lookup.contains(&contact.id)
                    {
                        batch.push(contact.clone());
                    }
                }
                // Then fall back to unverified contacts
                if batch.len() < ALPHA {
                    for contact in &self.closest {
                        if batch.len() >= ALPHA {
                            break;
                        }
                        if !self.fetched.contains(&contact.id)
                            && !self.pending.contains(&contact.id)
                            && !self.responded_during_lookup.contains(&contact.id)
                        {
                            batch.push(contact.clone());
                        }
                    }
                }
            }
        }

        for c in &batch {
            self.pending.insert(c.id);
            self.pending_times.insert(c.id, now);
            if self.phase == SearchPhase::Fetch {
                self.fetched.insert(c.id);
            }
        }
        batch
    }

    /// Process a KadRes (node lookup response) during lookup phase.
    pub fn handle_response(&mut self, from: &KadId, contacts: Vec<KadContact>) {
        self.queried.insert(*from);
        self.pending.remove(from);
        self.pending_times.remove(from);
        if self.phase == SearchPhase::Lookup {
            self.responded_during_lookup.insert(*from);
        }

        let old_best = self.closest.first().map(|c| self.target.xor_distance(&c.id));

        for c in contacts {
            if c.id != self.target && !self.queried.contains(&c.id) {
                if !self.closest.iter().any(|existing| existing.id == c.id) {
                    self.closest.push(c);
                }
            }
        }
        self.sort_closest();

        let new_best = self.closest.first().map(|c| self.target.xor_distance(&c.id));
        let improved = match (&old_best, &new_best) {
            (Some(old), Some(new)) => new < old,
            (None, Some(_)) => true,
            _ => false,
        };

        if !improved {
            self.lookup_stale_rounds += 1;
        } else {
            self.lookup_stale_rounds = 0;
        }

        self.check_phase_transition();
        self.check_completion();
    }

    /// Process search results (keyword/source results) during fetch phase.
    /// In eMule, when the same file hash arrives from multiple KAD nodes,
    /// the source counts are accumulated. We keep all entries so that
    /// `convert_search_results()` can properly sum TAG_SOURCES across nodes.
    pub fn handle_search_results(&mut self, from: &KadId, entries: Vec<SearchResultEntry>) {
        self.fetched.insert(*from);
        self.pending.remove(from);
        self.pending_times.remove(from);

        for entry in entries {
            self.results.push(entry);
        }
        self.check_completion();
    }

    pub fn handle_timeout(&mut self, id: &KadId) {
        self.queried.insert(*id);
        self.pending.remove(id);
        self.pending_times.remove(id);
        self.lookup_stale_rounds += 1;
        self.check_phase_transition();
        self.check_completion();
    }

    pub fn expire_pending(&mut self) -> Vec<KadId> {
        let now = chrono::Utc::now().timestamp();
        let timed_out: Vec<KadId> = self
            .pending_times
            .iter()
            .filter(|(_, &sent_at)| now - sent_at >= PENDING_TIMEOUT_SECS)
            .map(|(&id, _)| id)
            .collect();
        for id in &timed_out {
            self.handle_timeout(id);
        }
        timed_out
    }

    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        if let Some(fetch_start) = self.fetch_started_at {
            return now - fetch_start >= FETCH_TIMEOUT_SECS;
        }
        let timeout = match self.search_type {
            SearchType::FindNode => TIMEOUT_FIND_NODE,
            SearchType::FindKeyword => TIMEOUT_KEYWORD,
            SearchType::FindSource { .. } => TIMEOUT_SOURCE,
            SearchType::FindNotes { .. } => TIMEOUT_NOTES,
            SearchType::StoreKeyword => TIMEOUT_STORE_KEYWORD,
            SearchType::StoreNotes => TIMEOUT_STORE_NOTES,
            SearchType::FindBuddy => TIMEOUT_FIND_BUDDY,
        };
        now - self.started_at >= timeout
    }

    pub fn has_enough_results(&self) -> bool {
        if !matches!(self.search_type, SearchType::FindKeyword) {
            return false;
        }
        // Count unique file hashes, not raw entries (duplicates carry
        // TAG_SOURCES from different KAD nodes and must be kept).
        let unique: HashSet<&KadId> = self.results.iter().map(|r| &r.id).collect();
        unique.len() >= KEYWORD_SEARCH_MAX_RESULTS
    }

    fn check_phase_transition(&mut self) {
        if self.phase != SearchPhase::Lookup {
            return;
        }
        if matches!(self.search_type, SearchType::FindNode | SearchType::FindBuddy) {
            return;
        }

        let all_queried = self.pending.is_empty()
            && !self.closest.iter().any(|c| !self.queried.contains(&c.id));

        let enough_queried = self.queried.len() >= LOOKUP_MIN_QUERIES
            && self.lookup_stale_rounds >= LOOKUP_CONVERGE_COUNT;

        let max_lookup_reached = self.queried.len() >= SEARCH_INITIAL_CONTACTS;

        if all_queried || enough_queried || max_lookup_reached {
            info!(
                "Search {}: lookup converged (queried={}, stale_rounds={}, closest={}, verified={}), switching to fetch",
                self.id.0, self.queried.len(), self.lookup_stale_rounds, self.closest.len(),
                self.responded_during_lookup.len()
            );
            self.phase = SearchPhase::Fetch;
            self.pending.clear();
            self.pending_times.clear();
            self.fetch_started_at = Some(chrono::Utc::now().timestamp());
        }
    }

    fn sort_closest(&mut self) {
        let target = self.target;
        self.closest.sort_by(|a, b| {
            let da = target.xor_distance(&a.id);
            let db = target.xor_distance(&b.id);
            da.cmp(&db)
        });
        self.closest.truncate(SEARCH_INITIAL_CONTACTS);

        // Update prev_closest_distance for convergence tracking
        self.prev_closest_distance = self
            .closest
            .first()
            .map(|c| target.xor_distance(&c.id));
    }

    fn check_completion(&mut self) {
        if self.has_enough_results() {
            self.completed = true;
            return;
        }

        match self.phase {
            SearchPhase::Lookup => {
                if matches!(self.search_type, SearchType::FindNode | SearchType::FindBuddy) {
                    if self.pending.is_empty() {
                        let has_unqueried = self
                            .closest
                            .iter()
                            .any(|c| !self.queried.contains(&c.id));
                        if !has_unqueried {
                            self.completed = true;
                        }
                    }
                }
            }
            SearchPhase::Fetch => {
                if self.pending.is_empty() {
                    let has_unfetched = self
                        .closest
                        .iter()
                        .any(|c| !self.fetched.contains(&c.id));
                    if !has_unfetched {
                        self.completed = true;
                    }
                }
            }
        }
    }

    pub fn build_query_message(&self, receiver: &KadContact) -> KadMessage {
        match self.phase {
            SearchPhase::Lookup => {
                let search_type = match self.search_type {
                    SearchType::FindNode | SearchType::FindBuddy => KADEMLIA_FIND_NODE,
                    SearchType::StoreKeyword | SearchType::StoreNotes => KADEMLIA_STORE,
                    _ => KADEMLIA_FIND_VALUE,
                };
                KadMessage::KadReq {
                    search_type,
                    target: self.target,
                    receiver: receiver.id,
                }
            }
            SearchPhase::Fetch => match self.search_type {
                SearchType::FindKeyword | SearchType::StoreKeyword => KadMessage::SearchKeyReq {
                    target: self.target,
                    start_position: 0,
                },
                SearchType::FindSource { file_size } => KadMessage::SearchSourceReq {
                    target: self.target,
                    start_position: 0,
                    file_size,
                },
                SearchType::FindNotes { file_size } => {
                    KadMessage::SearchNotesReq {
                        target: self.target,
                        file_size,
                    }
                }
                SearchType::StoreNotes => {
                    KadMessage::SearchNotesReq {
                        target: self.target,
                        file_size: 0,
                    }
                }
                SearchType::FindNode | SearchType::FindBuddy => KadMessage::KadReq {
                    search_type: KADEMLIA_FIND_NODE,
                    target: self.target,
                    receiver: receiver.id,
                },
            },
        }
    }
}

/// Manages all active searches.
#[derive(Debug)]
pub struct SearchManager {
    next_id: u64,
    pub active: HashMap<SearchId, SearchState>,
    target_map: HashMap<KadId, SearchId>,
}

impl SearchManager {
    pub fn new() -> Self {
        SearchManager {
            next_id: 1,
            active: HashMap::new(),
            target_map: HashMap::new(),
        }
    }

    pub fn start_search(
        &mut self,
        target: KadId,
        search_type: SearchType,
        initial_contacts: Vec<KadContact>,
    ) -> SearchId {
        if let Some(existing_id) = self.target_map.get(&target) {
            if let Some(state) = self.active.get(existing_id) {
                if !state.completed {
                    return *existing_id;
                }
            }
        }

        let id = SearchId(self.next_id);
        self.next_id += 1;

        let mut state = SearchState::new(id, target, search_type);
        state.seed(initial_contacts);
        self.target_map.insert(target, id);
        self.active.insert(id, state);
        debug!("Started search {}: target={}", id.0, target);
        id
    }

    pub fn get_mut(&mut self, id: &SearchId) -> Option<&mut SearchState> {
        self.active.get_mut(id)
    }

    pub fn get(&self, id: &SearchId) -> Option<&SearchState> {
        self.active.get(id)
    }

    pub fn poll_queries(&mut self) -> Vec<(SearchId, SocketAddr, KadMessage)> {
        let mut queries = Vec::new();
        let search_ids: Vec<SearchId> = self.active.keys().cloned().collect();

        for sid in search_ids {
            let state = match self.active.get_mut(&sid) {
                Some(s) => s,
                None => continue,
            };
            if state.completed {
                continue;
            }

            let timed_out = state.expire_pending();
            if !timed_out.is_empty() {
                debug!(
                    "Search {}: {} pending nodes timed out",
                    sid.0,
                    timed_out.len()
                );
            }

            // If search is still in lookup phase after 30s, force transition to fetch
            let elapsed = chrono::Utc::now().timestamp() - state.started_at;
            if state.phase == SearchPhase::Lookup
                && state.search_type != SearchType::FindNode
                && elapsed >= 30
            {
                info!(
                    "Search {}: forcing transition to fetch after {}s in lookup (queried={}, verified={})",
                    sid.0, elapsed, state.queried.len(), state.responded_during_lookup.len()
                );
                state.phase = SearchPhase::Fetch;
                state.pending.clear();
                state.pending_times.clear();
                state.fetch_started_at = Some(chrono::Utc::now().timestamp());
            }

            if state.is_expired() && !state.completed {
                let elapsed = chrono::Utc::now().timestamp() - state.started_at;
                info!(
                    "Search {} expired after {}s with {} results (phase={:?})",
                    sid.0,
                    elapsed,
                    state.results.len(),
                    state.phase,
                );
                state.completed = true;
                continue;
            }

            let batch = state.next_to_query();
            for contact in &batch {
                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                let msg = state.build_query_message(contact);
                queries.push((sid, addr, msg));
            }
        }
        queries
    }

    pub fn cleanup(&mut self, max_age_secs: i64) {
        let now = chrono::Utc::now().timestamp();
        let to_remove: Vec<SearchId> = self
            .active
            .iter()
            .filter(|(_, s)| s.completed && now - s.started_at > max_age_secs)
            .map(|(id, _)| *id)
            .collect();
        for id in to_remove {
            if let Some(state) = self.active.remove(&id) {
                self.target_map.remove(&state.target);
            }
        }
    }

    pub fn remove(&mut self, id: &SearchId) -> Option<SearchState> {
        if let Some(state) = self.active.remove(id) {
            self.target_map.remove(&state.target);
            Some(state)
        } else {
            None
        }
    }
}
