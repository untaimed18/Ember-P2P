use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};

use tracing::{debug, info};

use super::messages::*;
use super::types::*;

/// eMule Defines.h SEARCHKEYWORD_TOTAL
const KEYWORD_SEARCH_MAX_RESULTS: usize = 300;
const PENDING_TIMEOUT_SECS: i64 = 10;
const LOOKUP_CONVERGE_COUNT: usize = 5;
const LOOKUP_MIN_QUERIES: usize = 10;
const LOOKUP_MAX_QUERIES: usize = 200;
const LOOKUP_CONTACT_POOL: usize = 200;

/// eMule seeds searches with 50 contacts (Search.cpp Go() -> GetClosestTo(..., 50, ...))
pub const SEARCH_INITIAL_CONTACTS: usize = 50;

/// eMule Defines.h search lifetime values (in seconds)
const TIMEOUT_FIND_NODE: i64 = 45;    // SEARCHNODE_LIFETIME
const TIMEOUT_KEYWORD: i64 = 45;      // SEARCHKEYWORD_LIFETIME
const TIMEOUT_SOURCE: i64 = 45;       // SEARCHFINDSOURCE_LIFETIME
const TIMEOUT_NOTES: i64 = 45;        // SEARCHNOTES_LIFETIME
const TIMEOUT_STORE_KEYWORD: i64 = 140; // SEARCHSTOREKEYWORD_LIFETIME
const TIMEOUT_STORE_NOTES: i64 = 100; // SEARCHSTORENOTES_LIFETIME
const TIMEOUT_FIND_BUDDY: i64 = 100;  // SEARCHFINDBUDDY_LIFETIME
/// Grace period after entering fetch phase for late results (eMule PrepareToStop gives 15s)
const FETCH_TIMEOUT_SECS: i64 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchType {
    FindNode,
    FindKeyword,
    FindSource { file_size: u64 },
    FindNotes { file_size: u64 },
    FindBuddy,
    StoreFile,
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
    /// eMule JumpStart behavior: one-time re-ask for "more contacts" (11)
    /// to a previously responding node when FIND_VALUE lookup stalls.
    lookup_reask_more_target: Option<KadId>,
    lookup_reask_more_done: bool,
    /// eMule m_mapBest: contacts that should be queried with high priority
    /// because they are closer to target than their referring contact and
    /// made it into the top ALPHA closest. Set during handle_response().
    priority_queries: Vec<KadContact>,
    /// eMule m_mapTried: maps (IP, port) to KadId for every contact we've
    /// sent a query to. Used for reliable sender identification in KadRes
    /// responses, even if the contact was evicted from the routing table.
    pub tried: HashMap<(Ipv4Addr, u16), KadId>,
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
            lookup_reask_more_target: None,
            lookup_reask_more_done: false,
            priority_queries: Vec::new(),
            tried: HashMap::new(),
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
    /// eMule Search.cpp: NODE searches use batch size 1, all others use ALPHA (3).
    pub fn next_to_query(&mut self) -> Vec<KadContact> {
        let now = chrono::Utc::now().timestamp();
        let mut batch = Vec::new();
        let max_batch = if matches!(self.search_type, SearchType::FindNode) { 1 } else { ALPHA };

        match self.phase {
            SearchPhase::Lookup => {
                while !self.priority_queries.is_empty() && batch.len() < max_batch {
                    let c = self.priority_queries.remove(0);
                    if !self.queried.contains(&c.id) && !self.pending.contains(&c.id) {
                        batch.push(c);
                    }
                }

                for contact in &self.closest {
                    if batch.len() >= max_batch {
                        break;
                    }
                    if !self.queried.contains(&contact.id) && !self.pending.contains(&contact.id) {
                        batch.push(contact.clone());
                    }
                }

                // eMule JumpStart: if FIND_VALUE lookup stalls and we already have at least
                // one responder, re-ask one responder for a larger contact set (11).
                if batch.is_empty()
                    && !self.lookup_reask_more_done
                    && self.lookup_stale_rounds >= 3
                    && matches!(
                        self.search_type,
                        SearchType::FindKeyword
                            | SearchType::FindSource { .. }
                            | SearchType::FindNotes { .. }
                            | SearchType::StoreFile
                    )
                {
                    if let Some(contact) = self.closest.iter().find(|c| {
                        self.responded_during_lookup.contains(&c.id)
                            && self.queried.contains(&c.id)
                            && !self.pending.contains(&c.id)
                    }) {
                        self.lookup_reask_more_target = Some(contact.id);
                        self.lookup_reask_more_done = true;
                        batch.push(contact.clone());
                    }
                }
            }
            SearchPhase::Fetch => {
                // eMule-like fetch eligibility:
                // - node must have responded during lookup (verified alive)
                // - node must be in SEARCH_TOLERANCE zone (or LAN)
                for contact in &self.closest {
                    if batch.len() >= ALPHA {
                        break;
                    }
                    if !self.fetched.contains(&contact.id)
                        && !self.pending.contains(&contact.id)
                        && self.is_fetch_candidate(contact)
                    {
                        batch.push(contact.clone());
                    }
                }
            }
        }

        for c in &batch {
            self.pending.insert(c.id);
            self.pending_times.insert(c.id, now);
            self.tried.insert((c.ip, c.udp_port), c.id);
            if self.phase == SearchPhase::Fetch {
                self.fetched.insert(c.id);
            }
        }
        batch
    }

    /// Process a KadRes (node lookup response) during lookup phase.
    /// Implements eMule's ProcessResponse m_mapBest behavior: contacts closer
    /// to target than the responder that make it into the top ALPHA closest
    /// are flagged for immediate priority query.
    pub fn handle_response(&mut self, from: &KadId, contacts: Vec<KadContact>) {
        self.queried.insert(*from);
        self.pending.remove(from);
        self.pending_times.remove(from);
        if self.lookup_reask_more_target == Some(*from) {
            self.lookup_reask_more_target = None;
        }
        if self.phase == SearchPhase::Lookup {
            self.responded_during_lookup.insert(*from);
        }

        let from_distance = self.target.xor_distance(from);
        let old_best = self.closest.first().map(|c| self.target.xor_distance(&c.id));

        let mut new_contacts = Vec::new();
        for c in contacts {
            if c.id != self.target && !self.queried.contains(&c.id) {
                if !self.closest.iter().any(|existing| existing.id == c.id) {
                    new_contacts.push(c.clone());
                    self.closest.push(c);
                }
            }
        }
        self.sort_closest();

        // eMule m_mapBest: for each new contact closer than the responder,
        // check if it's in the top ALPHA closest overall. If so, immediately
        // queue it for priority query (matching eMule's SendFindValue in ProcessResponse).
        if self.phase == SearchPhase::Lookup {
            for nc in &new_contacts {
                let nc_distance = self.target.xor_distance(&nc.id);
                if nc_distance >= from_distance {
                    continue;
                }
                let rank = self.closest.iter()
                    .position(|c| c.id == nc.id)
                    .unwrap_or(usize::MAX);
                if rank < ALPHA && !self.queried.contains(&nc.id) && !self.pending.contains(&nc.id) {
                    if !self.priority_queries.iter().any(|p| p.id == nc.id) {
                        self.priority_queries.push(nc.clone());
                    }
                }
            }
        }

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
            if self.results.len() < 3000 {
                self.results.push(entry);
            }
        }
        self.check_completion();
    }

    pub fn handle_timeout(&mut self, id: &KadId) {
        self.queried.insert(*id);
        self.pending.remove(id);
        self.pending_times.remove(id);
        if self.lookup_reask_more_target == Some(*id) {
            self.lookup_reask_more_target = None;
        }
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
        let lifetime = match self.search_type {
            SearchType::FindNode => TIMEOUT_FIND_NODE,
            SearchType::FindKeyword => TIMEOUT_KEYWORD,
            SearchType::FindSource { .. } => TIMEOUT_SOURCE,
            SearchType::FindNotes { .. } => TIMEOUT_NOTES,
            SearchType::StoreFile => TIMEOUT_STORE_KEYWORD, // eMule SEARCHSTOREFILE_LIFETIME = 140
            SearchType::StoreKeyword => TIMEOUT_STORE_KEYWORD,
            SearchType::StoreNotes => TIMEOUT_STORE_NOTES,
            SearchType::FindBuddy => TIMEOUT_FIND_BUDDY,
        };
        // eMule: PrepareToStop fires at lifetime, then 15s grace for late results.
        // Overall cap: search lifetime + grace period.
        let overall_expired = now - self.started_at >= lifetime + FETCH_TIMEOUT_SECS;
        // Fetch phase also has its own timeout (grace period for results).
        let fetch_expired = self.fetch_started_at
            .map_or(false, |fs| now - fs >= FETCH_TIMEOUT_SECS);
        overall_expired || fetch_expired
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

        // eMule converges when m_mapPossible is exhausted or closest responded contacts
        // are encountered in JumpStart. We approximate this: converge when we've done
        // at least LOOKUP_MIN_QUERIES and had LOOKUP_CONVERGE_COUNT consecutive stale rounds.
        let enough_queried = self.queried.len() >= LOOKUP_MIN_QUERIES
            && self.lookup_stale_rounds >= LOOKUP_CONVERGE_COUNT;

        let max_lookup_reached = self.queried.len() >= LOOKUP_MAX_QUERIES;

        if all_queried || enough_queried || max_lookup_reached {
            let tolerance_candidates: Vec<&KadContact> = self.closest.iter()
                .filter(|c| self.responded_during_lookup.contains(&c.id)
                    && within_search_tolerance(&self.target, &c.id))
                .collect();
            let responded_candidates: Vec<&KadContact> = self.closest.iter()
                .filter(|c| self.responded_during_lookup.contains(&c.id))
                .collect();
            info!(
                "Search {}: lookup converged (queried={}, stale_rounds={}, closest={}, verified={}, \
                within_tolerance={}, responded_in_closest={}), switching to fetch",
                self.id.0, self.queried.len(), self.lookup_stale_rounds, self.closest.len(),
                self.responded_during_lookup.len(), tolerance_candidates.len(), responded_candidates.len()
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
        self.closest.truncate(LOOKUP_CONTACT_POOL);

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
                // Don't complete if we haven't sent any fetch queries yet.
                // The poll loop needs at least one cycle to dispatch queries
                // after transitioning from Lookup to Fetch.
                if self.fetched.is_empty() && self.pending.is_empty() {
                    return;
                }
                if self.pending.is_empty() {
                    let has_unfetched = self
                        .closest
                        .iter()
                        .any(|c| self.is_fetch_candidate(c) && !self.fetched.contains(&c.id));
                    if !has_unfetched {
                        self.completed = true;
                    }
                }
            }
        }
    }

    fn is_fetch_candidate(&self, contact: &KadContact) -> bool {
        if is_lan_ip(contact.ip) {
            return true;
        }
        if within_search_tolerance(&self.target, &contact.id) {
            return self.responded_during_lookup.contains(&contact.id);
        }
        // Fallback: if no contacts are within strict tolerance, allow the
        // closest contacts that responded during lookup. This handles the
        // common case where the routing table is small and the iterative
        // lookup couldn't walk close enough to the target.
        if !self.has_any_tolerance_candidates() {
            return self.responded_during_lookup.contains(&contact.id);
        }
        false
    }

    fn has_any_tolerance_candidates(&self) -> bool {
        self.closest.iter().any(|c| {
            self.responded_during_lookup.contains(&c.id)
                && within_search_tolerance(&self.target, &c.id)
        })
    }

    /// Returns the expected number of contacts in a response.
    /// Matches eMule's GetRequestContactCount for validating KADEMLIA2_RES.
    pub fn get_expected_response_count(&self) -> u8 {
        match self.search_type {
            SearchType::FindNode => KADEMLIA_FIND_NODE,
            SearchType::FindKeyword | SearchType::FindSource { .. } | SearchType::FindNotes { .. } => KADEMLIA_FIND_VALUE,
            SearchType::FindBuddy | SearchType::StoreFile | SearchType::StoreKeyword | SearchType::StoreNotes => KADEMLIA_STORE,
        }
    }

    /// Build the wire message for this search phase.
    /// Matches eMule's GetRequestContactCount:
    /// - NODE/NODECOMPLETE → KADEMLIA_FIND_NODE (11)
    /// - FILE/KEYWORD/FINDSOURCE/NOTES → KADEMLIA_FIND_VALUE (2)
    /// - FINDBUDDY/STOREFILE/STOREKEYWORD/STORENOTES → KADEMLIA_STORE (4)
    pub fn build_query_message(&mut self, receiver: &KadContact) -> KadMessage {
        match self.phase {
            SearchPhase::Lookup => {
                let search_type = match self.search_type {
                    SearchType::StoreFile | SearchType::StoreKeyword | SearchType::StoreNotes | SearchType::FindBuddy => {
                        KADEMLIA_STORE
                    }
                    SearchType::FindNode => KADEMLIA_FIND_NODE,
                    SearchType::FindKeyword
                    | SearchType::FindSource { .. }
                    | SearchType::FindNotes { .. } => {
                        if self.lookup_reask_more_target == Some(receiver.id) {
                            KADEMLIA_FIND_NODE
                        } else {
                            KADEMLIA_FIND_VALUE
                        }
                    }
                };
                KadMessage::KadReq {
                    search_type,
                    target: self.target,
                    receiver: receiver.id,
                }
            }
            SearchPhase::Fetch => match self.search_type {
                SearchType::FindKeyword => KadMessage::SearchKeyReq {
                    target: self.target,
                    start_position: 0,
                },
                SearchType::StoreKeyword | SearchType::StoreFile | SearchType::StoreNotes => {
                    // Store searches don't fetch -- they complete immediately
                    // after lookup so mod.rs can send the actual publish requests.
                    // Return a dummy Ping that won't be sent (search marked complete).
                    self.completed = true;
                    KadMessage::Ping
                }
                SearchType::FindSource { file_size } => {
                    KadMessage::SearchSourceReq {
                        target: self.target,
                        start_position: 0,
                        file_size,
                    }
                }
                SearchType::FindNotes { file_size } => {
                    KadMessage::SearchNotesReq {
                        target: self.target,
                        file_size,
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

fn within_search_tolerance(target: &KadId, contact_id: &KadId) -> bool {
    let distance = target.xor_distance(contact_id);
    let d = u32::from_le_bytes([distance.0[0], distance.0[1], distance.0[2], distance.0[3]]);
    d <= SEARCH_TOLERANCE
}

fn is_lan_ip(ip: std::net::Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local()
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

        // Prevent search storms: if too many active searches, evict oldest completed ones
        // and reject low-priority new searches.
        const MAX_ACTIVE_SEARCHES: usize = 20;
        let active = self.active_count();
        if active >= MAX_ACTIVE_SEARCHES {
            // Evict completed searches first
            let completed: Vec<SearchId> = self.active.iter()
                .filter(|(_, s)| s.completed)
                .map(|(id, _)| *id)
                .collect();
            for id in completed {
                if let Some(s) = self.active.remove(&id) {
                    self.target_map.remove(&s.target);
                }
            }
            // If still too many, reject non-essential searches (FindNode)
            if self.active_count() >= MAX_ACTIVE_SEARCHES && matches!(search_type, SearchType::FindNode) {
                debug!("Rejecting FindNode search: {} active searches at cap", self.active_count());
                return SearchId(0);
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

    /// Get the expected response contact count for a target (eMule GetExpectedResponseContactCount).
    /// Returns 0 if no active search for this target (meaning the response should be rejected).
    pub fn get_expected_response_count(&self, target: &KadId) -> u8 {
        if let Some(search_id) = self.target_map.get(target) {
            if let Some(search) = self.active.get(search_id) {
                if !search.completed {
                    return search.get_expected_response_count();
                }
            }
        }
        0
    }

    pub fn active_count(&self) -> usize {
        self.active.values().filter(|s| !s.completed).count()
    }

    pub fn poll_queries(&mut self) -> Vec<(SearchId, SocketAddr, KadMessage, KadId)> {
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

            // eMule's total search lifetime is 45s for keyword searches. Force
            // transition to fetch after 30s so there's still time for fetch results.
            let elapsed = chrono::Utc::now().timestamp() - state.started_at;
            if state.phase == SearchPhase::Lookup
                && !matches!(state.search_type, SearchType::FindNode | SearchType::FindBuddy)
                && elapsed >= 30
                && state.queried.len() >= ALPHA
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
                queries.push((sid, addr, msg, contact.id));
            }
        }
        queries
    }

    pub fn cleanup(&mut self, max_age_secs: i64) -> Vec<SearchId> {
        let now = chrono::Utc::now().timestamp();
        let hard_timeout = max_age_secs * 3;
        let to_remove: Vec<SearchId> = self
            .active
            .iter()
            .filter(|(_, s)| {
                let age = now - s.started_at;
                (s.completed && age > max_age_secs) || age > hard_timeout
            })
            .map(|(id, _)| *id)
            .collect();
        for &id in &to_remove {
            if let Some(state) = self.active.remove(&id) {
                self.target_map.remove(&state.target);
            }
        }
        to_remove
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
