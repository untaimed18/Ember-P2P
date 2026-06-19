use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};

use tracing::{debug, info};

use super::messages::*;
use super::types::*;

/// eMule Defines.h SEARCHKEYWORD_TOTAL -- this is a RAW answer count (not unique).
/// eMule calls PrepareToStop() at this threshold: no new queries are sent but
/// late responses from already-queried nodes continue to be accepted.
const KEYWORD_SEARCH_STOP_THRESHOLD: usize = 300;
const PENDING_TIMEOUT_SECS: i64 = 10;
const LOOKUP_CONVERGE_COUNT: usize = 3;
const LOOKUP_MIN_QUERIES: usize = 10;
const LOOKUP_MAX_QUERIES: usize = 200;
const LOOKUP_CONTACT_POOL: usize = 200;
const LOOKUP_FORCE_FETCH_SECS: i64 = 15;
pub const STORE_PUBLISH_TARGET_TOTAL: usize = 10;

/// eMule seeds searches with 50 contacts (Search.cpp Go() -> GetClosestTo(..., 50, ...))
pub const SEARCH_INITIAL_CONTACTS: usize = 50;

/// eMule Defines.h search lifetime values (in seconds)
const TIMEOUT_FIND_NODE: i64 = 45; // SEARCHNODE_LIFETIME
const TIMEOUT_KEYWORD: i64 = 45; // SEARCHKEYWORD_LIFETIME
const TIMEOUT_SOURCE: i64 = 45; // SEARCHFINDSOURCE_LIFETIME
const TIMEOUT_NOTES: i64 = 45; // SEARCHNOTES_LIFETIME
const TIMEOUT_STORE_KEYWORD: i64 = 140; // SEARCHSTOREKEYWORD_LIFETIME
const TIMEOUT_STORE_NOTES: i64 = 100; // SEARCHSTORENOTES_LIFETIME
const TIMEOUT_FIND_BUDDY: i64 = 100; // SEARCHFINDBUDDY_LIFETIME
/// Grace period after entering fetch phase for late results (eMule PrepareToStop gives 15s)
const FETCH_TIMEOUT_SECS: i64 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// K13: discriminator used as part of the `target_map` key so two
/// searches that share a KadId (e.g. `FindSource` + `StoreFile` on the
/// same file-hash target) do not collide and starve each other of
/// dispatches. Mirrors `SearchType` discriminants without payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchKind {
    FindNode,
    FindKeyword,
    FindSource,
    FindNotes,
    FindBuddy,
    StoreFile,
    StoreKeyword,
    StoreNotes,
}

impl SearchType {
    pub fn kind(&self) -> SearchKind {
        match self {
            SearchType::FindNode => SearchKind::FindNode,
            SearchType::FindKeyword => SearchKind::FindKeyword,
            SearchType::FindSource { .. } => SearchKind::FindSource,
            SearchType::FindNotes { .. } => SearchKind::FindNotes,
            SearchType::FindBuddy => SearchKind::FindBuddy,
            SearchType::StoreFile => SearchKind::StoreFile,
            SearchType::StoreKeyword => SearchKind::StoreKeyword,
            SearchType::StoreNotes => SearchKind::StoreNotes,
        }
    }
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

fn should_force_fetch_after_lookup(
    phase: SearchPhase,
    search_type: SearchType,
    elapsed_secs: i64,
    queried_len: usize,
    responded_count: usize,
) -> bool {
    phase == SearchPhase::Lookup
        && !matches!(
            search_type,
            SearchType::FindNode
                | SearchType::FindBuddy
                | SearchType::StoreKeyword
                | SearchType::StoreFile
                | SearchType::StoreNotes
        )
        && elapsed_secs >= LOOKUP_FORCE_FETCH_SECS
        && queried_len >= ALPHA
        && responded_count > 0
}

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
    /// eMule m_bStoping: set when enough results have been received.
    /// Prevents new queries from being sent but keeps the search alive
    /// so that late responses from already-queried nodes are still accepted.
    stop_querying: bool,
    /// Set when entering fetch phase; used for fetch-specific timeout.
    fetch_started_at: Option<i64>,
    /// Tracks how many lookup rounds returned no closer contacts.
    lookup_stale_rounds: usize,
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
    /// Binary search expression for keyword searches (eMule AND tree format).
    /// Sent in KADEMLIA2_SEARCH_KEY_REQ so remote nodes filter results server-side.
    pub search_terms_data: Vec<u8>,
    /// eMule InUse tracking: contact IDs referenced by this search. Released
    /// when the search is removed to allow dead-contact cleanup.
    pub in_use_ids: Vec<KadId>,
    /// Newly discovered in-use IDs since last drain (for mid-lookup contacts).
    pub new_in_use_ids: Vec<KadId>,
    /// Next start_position for pagination: re-fetch contacts that returned a
    /// full page (200 results) with an incremented offset to get more.
    fetch_page_offset: HashMap<KadId, u16>,
    /// eMule StorePacket: contacts that have been sent a keyword/source search
    /// request during the Lookup phase (before the formal Fetch transition).
    /// This overlaps fetch with lookup, matching eMule's JumpStart behavior
    /// where StorePacket is called for already-responded contacts.
    pub store_sent: HashSet<KadId>,
    /// Contacts with pending store query (SearchSourceReq/SearchKeyReq) responses.
    /// Prevents the search from completing before responses arrive. Separate from
    /// `pending` (which tracks routing KadReq queries) to avoid breaking convergence.
    pub store_pending: HashSet<KadId>,
    store_pending_times: HashMap<KadId, i64>,
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
            stop_querying: false,
            fetch_started_at: None,
            lookup_stale_rounds: 0,
            responded_during_lookup: HashSet::new(),
            lookup_reask_more_target: None,
            lookup_reask_more_done: false,
            priority_queries: Vec::new(),
            tried: HashMap::new(),
            search_terms_data: Vec::new(),
            in_use_ids: Vec::new(),
            new_in_use_ids: Vec::new(),
            fetch_page_offset: HashMap::new(),
            store_sent: HashSet::new(),
            store_pending: HashSet::new(),
            store_pending_times: HashMap::new(),
        }
    }

    pub fn seed(&mut self, contacts: Vec<KadContact>) {
        for c in contacts {
            if !self.queried.contains(&c.id)
                && !self.closest.iter().any(|existing| existing.id == c.id)
            {
                self.in_use_ids.push(c.id);
                self.closest.push(c);
            }
        }
        self.sort_closest();
    }

    /// Get the next batch of contacts to query (up to ALPHA).
    /// eMule Search.cpp: NODE searches use batch size 1, all others use ALPHA (3).
    pub fn next_to_query(&mut self) -> Vec<KadContact> {
        if self.completed || self.stop_querying {
            return Vec::new();
        }
        let now = chrono::Utc::now().timestamp();
        let mut batch = Vec::new();
        let max_batch = if matches!(self.search_type, SearchType::FindNode) {
            1
        } else {
            ALPHA
        };

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

                // eMule JumpStart: if lookup stalls, re-ask a responder once
                // for a larger contact set (FIND_NODE returns 11 vs STORE's 4).
                if batch.is_empty()
                    && !self.lookup_reask_more_done
                    && self.lookup_stale_rounds >= 3
                    && matches!(
                        self.search_type,
                        SearchType::FindKeyword
                            | SearchType::FindSource { .. }
                            | SearchType::FindNotes { .. }
                    )
                {
                    if let Some(contact) = self.closest.iter().find(|c| {
                        self.responded_during_lookup.contains(&c.id)
                            && self.queried.contains(&c.id)
                            && !self.pending.contains(&c.id)
                    }) {
                        self.lookup_reask_more_done = true;
                        self.lookup_reask_more_target = Some(contact.id);
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

    /// eMule StorePacket equivalent: during Lookup phase, generate keyword/source
    /// search requests for contacts that have already responded to routing queries.
    /// This matches eMule's JumpStart behavior where StorePacket is called for
    /// responded contacts while the routing lookup is still in progress, rather
    /// than waiting for a strict Lookup → Fetch phase transition.
    pub fn next_store_queries(&mut self) -> Vec<(KadContact, KadMessage)> {
        if self.completed || self.stop_querying || self.phase != SearchPhase::Lookup {
            return Vec::new();
        }
        if !matches!(
            self.search_type,
            SearchType::FindKeyword | SearchType::FindSource { .. } | SearchType::FindNotes { .. }
        ) {
            return Vec::new();
        }

        let remaining = STORE_PUBLISH_TARGET_TOTAL.saturating_sub(self.store_sent.len());
        if remaining == 0 {
            return Vec::new();
        }

        let mut contacts = Vec::new();
        for contact in &self.closest {
            if contacts.len() >= ALPHA.min(remaining) {
                break;
            }
            if self.responded_during_lookup.contains(&contact.id)
                && !self.store_sent.contains(&contact.id)
                && self.is_fetch_candidate(contact)
            {
                contacts.push(contact.clone());
            }
        }

        let mut result = Vec::new();
        let now = chrono::Utc::now().timestamp();
        for c in contacts {
            self.store_sent.insert(c.id);
            self.fetched.insert(c.id);
            self.store_pending.insert(c.id);
            self.store_pending_times.insert(c.id, now);
            self.tried.insert((c.ip, c.udp_port), c.id);
            let msg = self.build_fetch_message_for(&c);
            result.push((c, msg));
        }
        result
    }

    /// eMule StorePacket for publish searches: during Lookup, return within-tolerance
    /// responded contacts that haven't been published to yet. The caller sends the
    /// actual PublishSourceReq/PublishKeyReq to these contacts. This ensures publish
    /// data reaches the same verified-alive nodes that searchers will find.
    pub fn next_publish_candidates(&mut self) -> Vec<KadContact> {
        if self.completed || self.phase != SearchPhase::Lookup {
            return Vec::new();
        }
        if !matches!(
            self.search_type,
            SearchType::StoreFile | SearchType::StoreKeyword | SearchType::StoreNotes
        ) {
            return Vec::new();
        }

        let mut contacts = Vec::new();
        for contact in &self.closest {
            if contacts.len() >= ALPHA {
                break;
            }
            if self.responded_during_lookup.contains(&contact.id)
                && !self.store_sent.contains(&contact.id)
                && within_search_tolerance(&self.target, &contact.id)
            {
                contacts.push(contact.clone());
            }
        }

        for c in &contacts {
            self.store_sent.insert(c.id);
            self.tried.insert((c.ip, c.udp_port), c.id);
        }
        contacts
    }

    /// Build a fetch-phase message (keyword/source/notes search request) for a
    /// specific contact. Used by both `next_store_queries` (during Lookup) and
    /// `build_query_message` (during Fetch).
    fn build_fetch_message_for(&self, receiver: &KadContact) -> KadMessage {
        match self.search_type {
            SearchType::FindKeyword => {
                let offset = self
                    .fetch_page_offset
                    .get(&receiver.id)
                    .copied()
                    .unwrap_or(0);
                KadMessage::SearchKeyReq {
                    target: self.target,
                    start_position: offset,
                    search_terms: self.search_terms_data.clone(),
                }
            }
            SearchType::FindSource { file_size } => {
                let offset = self
                    .fetch_page_offset
                    .get(&receiver.id)
                    .copied()
                    .unwrap_or(0);
                KadMessage::SearchSourceReq {
                    target: self.target,
                    start_position: offset,
                    file_size,
                }
            }
            SearchType::FindNotes { file_size } => KadMessage::SearchNotesReq {
                target: self.target,
                file_size,
            },
            _ => KadMessage::Ping,
        }
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
        // Record every responder, not only those that reply while still in the
        // Lookup phase. A KADEMLIA2_RES whose REQ was sent during lookup but
        // that lands just after we converged and switched to Fetch would
        // otherwise never be eligible as a fetch candidate
        // (`is_fetch_candidate` requires membership here), so that node would
        // never be queried for keyword/source/note results. This is bounded by
        // the set of nodes we actually queried, and re-entering
        // `check_phase_transition` from Fetch is a no-op.
        self.responded_during_lookup.insert(*from);

        let from_distance = self.target.xor_distance(from);
        let old_best = self
            .closest
            .first()
            .map(|c| self.target.xor_distance(&c.id));

        let mut new_contacts = Vec::new();
        for c in contacts {
            if c.id != self.target && !self.queried.contains(&c.id) {
                if !self.closest.iter().any(|existing| existing.id == c.id) {
                    self.in_use_ids.push(c.id);
                    self.new_in_use_ids.push(c.id);
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
                let rank = self
                    .closest
                    .iter()
                    .position(|c| c.id == nc.id)
                    .unwrap_or(usize::MAX);
                if rank < ALPHA && !self.queried.contains(&nc.id) && !self.pending.contains(&nc.id)
                {
                    if !self.priority_queries.iter().any(|p| p.id == nc.id) {
                        self.priority_queries.push(nc.clone());
                    }
                }
            }
        }

        let new_best = self
            .closest
            .first()
            .map(|c| self.target.xor_distance(&c.id));
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
        self.store_pending.remove(from);
        self.store_pending_times.remove(from);

        let count = entries.len();
        for entry in entries {
            if self.results.len() < 5000 {
                self.results.push(entry);
            }
        }

        const FETCH_PAGE_SIZE: usize = 200;
        const MAX_PAGES_PER_PEER: u16 = 3;
        if count >= FETCH_PAGE_SIZE
            && !self.stop_querying
            && self.results.len() < 5000
            && matches!(
                self.search_type,
                SearchType::FindKeyword | SearchType::FindSource { .. }
            )
        {
            let current_offset = self.fetch_page_offset.get(from).copied().unwrap_or(0);
            let next_offset = current_offset + FETCH_PAGE_SIZE as u16;
            if current_offset / FETCH_PAGE_SIZE as u16 + 1 < MAX_PAGES_PER_PEER {
                self.fetch_page_offset.insert(*from, next_offset);
                self.fetched.remove(from);
            }
        }

        self.check_completion();
    }

    pub fn handle_timeout(&mut self, id: &KadId) {
        self.queried.insert(*id);
        self.pending.remove(id);
        self.pending_times.remove(id);
        self.store_pending.remove(id);
        self.store_pending_times.remove(id);
        if self.lookup_reask_more_target == Some(*id) {
            self.lookup_reask_more_target = None;
        }
        self.check_phase_transition();
        self.check_completion();
    }

    pub fn expire_pending(&mut self) -> Vec<KadId> {
        let now = chrono::Utc::now().timestamp();
        // Time out when the request is older than the timeout. A negative
        // elapsed means the wall clock jumped backwards since we recorded
        // `sent_at`; treat that as timed out too so the entry can't get stuck
        // pending for the whole search lifetime (the previous `now - sent_at`
        // never reached the threshold while `sent_at` was in the future).
        let is_timed_out = |sent_at: i64| {
            let elapsed = now - sent_at;
            elapsed < 0 || elapsed >= PENDING_TIMEOUT_SECS
        };
        let timed_out: Vec<KadId> = self
            .pending_times
            .iter()
            .filter(|(_, &sent_at)| is_timed_out(sent_at))
            .map(|(&id, _)| id)
            .collect();
        let store_timed_out: Vec<KadId> = self
            .store_pending_times
            .iter()
            .filter(|(_, &sent_at)| is_timed_out(sent_at))
            .filter(|(id, _)| !timed_out.contains(id))
            .map(|(&id, _)| id)
            .collect();
        for id in &timed_out {
            self.handle_timeout(id);
        }
        for id in &store_timed_out {
            self.store_pending.remove(id);
            self.store_pending_times.remove(id);
            self.check_completion();
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
            SearchType::StoreFile => TIMEOUT_STORE_KEYWORD,
            SearchType::StoreKeyword => TIMEOUT_STORE_KEYWORD,
            SearchType::StoreNotes => TIMEOUT_STORE_NOTES,
            SearchType::FindBuddy => TIMEOUT_FIND_BUDDY,
        };
        // eMule: PrepareToStop fires at the lifetime mark, then a 15s grace
        // period allows late results to arrive. The overall cap is therefore
        // search-lifetime + FETCH_TIMEOUT_SECS.
        now - self.started_at >= lifetime + FETCH_TIMEOUT_SECS
    }

    /// eMule checks `GetAnswers() >= SEARCHKEYWORD_TOTAL` which counts raw
    /// individual results (including duplicates from different nodes).  When
    /// the threshold is reached eMule calls PrepareToStop(): new queries stop
    /// but late responses from already-queried nodes keep flowing in.
    fn should_stop_querying(&self) -> bool {
        if !matches!(self.search_type, SearchType::FindKeyword) {
            return false;
        }
        self.results.len() >= KEYWORD_SEARCH_STOP_THRESHOLD
    }

    fn check_phase_transition(&mut self) {
        if self.phase != SearchPhase::Lookup {
            return;
        }
        if matches!(
            self.search_type,
            SearchType::FindNode | SearchType::FindBuddy
        ) {
            return;
        }

        // eMule requires actual responses (m_mapResponded) before fetching.
        // If no contacts have responded, do not transition; let the search
        // expire at its lifetime instead.
        if self.responded_during_lookup.is_empty() {
            return;
        }

        let all_queried =
            self.pending.is_empty() && !self.closest.iter().any(|c| !self.queried.contains(&c.id));

        let enough_queried = self.queried.len() >= LOOKUP_MIN_QUERIES
            && self.lookup_stale_rounds >= LOOKUP_CONVERGE_COUNT;

        let max_lookup_reached = self.queried.len() >= LOOKUP_MAX_QUERIES;

        let tolerance_candidates: Vec<&KadContact> = self
            .closest
            .iter()
            .filter(|c| {
                self.responded_during_lookup.contains(&c.id)
                    && within_search_tolerance(&self.target, &c.id)
            })
            .collect();

        let is_store = matches!(
            self.search_type,
            SearchType::StoreKeyword | SearchType::StoreFile | SearchType::StoreNotes
        );

        if all_queried || enough_queried || max_lookup_reached {
            let responded_candidates: Vec<&KadContact> = self
                .closest
                .iter()
                .filter(|c| self.responded_during_lookup.contains(&c.id))
                .collect();
            info!(
                "Search {}: lookup converged (queried={}, stale_rounds={}, closest={}, verified={}, \
                within_tolerance={}, responded_in_closest={}, store_pending={}), switching to fetch",
                self.id.0, self.queried.len(), self.lookup_stale_rounds, self.closest.len(),
                self.responded_during_lookup.len(), tolerance_candidates.len(), responded_candidates.len(),
                self.store_pending.len()
            );
            self.pending.clear();
            self.pending_times.clear();
            self.fetch_started_at = Some(chrono::Utc::now().timestamp());
            if is_store {
                self.completed = true;
            }
            self.phase = SearchPhase::Fetch;
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
    }

    fn check_completion(&mut self) {
        // eMule PrepareToStop: stop sending queries once we have enough raw
        // results, but keep the search alive to receive late responses.
        if !self.stop_querying && self.should_stop_querying() {
            self.stop_querying = true;
        }

        match self.phase {
            SearchPhase::Lookup => {
                if matches!(
                    self.search_type,
                    SearchType::FindNode | SearchType::FindBuddy
                ) {
                    if self.pending.is_empty() {
                        let has_unqueried =
                            self.closest.iter().any(|c| !self.queried.contains(&c.id));
                        // Strict completion: every contact in `closest` has
                        // been queried (the original eMule rule).
                        if !has_unqueried {
                            self.completed = true;
                        // Convergence completion: with batch size 1 and
                        // continuous discovery from KadRes responses, the
                        // strict rule above will almost never fire before
                        // the 60s expiry — `closest` keeps growing as long
                        // as routing nodes hand out fresh contacts. Mirror
                        // the logic used by Store/Find* fetch transitions:
                        // once we've queried at least the minimum number
                        // of nodes and seen N consecutive "stale" rounds
                        // (no closer contact discovered), we've effectively
                        // converged on the closest neighbourhood — the
                        // routing table has all the useful contacts already.
                        // Without this, every FindNode ties up a search slot
                        // for the full 60s lifetime even though the walk
                        // finished much earlier.
                        } else if self.queried.len() >= LOOKUP_MIN_QUERIES
                            && self.lookup_stale_rounds >= LOOKUP_CONVERGE_COUNT
                        {
                            self.completed = true;
                        }
                    }
                }
            }
            SearchPhase::Fetch => {
                // Don't complete if we haven't sent any fetch queries yet.
                // The poll loop needs at least one cycle to dispatch queries
                // after transitioning from Lookup to Fetch. However, if
                // store_sent is non-empty, fetch queries were already sent
                // during Lookup (eMule StorePacket pattern).
                if self.fetched.is_empty() && self.pending.is_empty() && self.store_sent.is_empty()
                {
                    return;
                }
                // Wait for both routing query and store query responses
                if self.pending.is_empty() && self.store_pending.is_empty() {
                    let has_unfetched = !self.stop_querying
                        && self
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
            SearchType::FindKeyword
            | SearchType::FindSource { .. }
            | SearchType::FindNotes { .. } => KADEMLIA_FIND_VALUE,
            SearchType::FindBuddy
            | SearchType::StoreFile
            | SearchType::StoreKeyword
            | SearchType::StoreNotes => KADEMLIA_STORE,
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
                    SearchType::StoreFile
                    | SearchType::StoreKeyword
                    | SearchType::StoreNotes
                    | SearchType::FindBuddy => KADEMLIA_STORE,
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
                SearchType::StoreKeyword | SearchType::StoreFile | SearchType::StoreNotes => {
                    self.completed = true;
                    KadMessage::Ping
                }
                SearchType::FindNode | SearchType::FindBuddy => KadMessage::KadReq {
                    search_type: KADEMLIA_FIND_NODE,
                    target: self.target,
                    receiver: receiver.id,
                },
                _ => self.build_fetch_message_for(receiver),
            },
        }
    }
}

fn within_search_tolerance(target: &KadId, contact_id: &KadId) -> bool {
    let distance = target.xor_distance(contact_id);
    distance.chunk(0) <= SEARCH_TOLERANCE
}

pub fn within_search_tolerance_pub(target: &KadId, contact_id: &KadId) -> bool {
    within_search_tolerance(target, contact_id)
}

fn is_lan_ip(ip: std::net::Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local()
}

/// Manages all active searches.
#[derive(Debug)]
pub struct SearchManager {
    next_id: u64,
    pub active: HashMap<SearchId, SearchState>,
    /// K13: keyed by (target, kind) so concurrent `FindSource` +
    /// `StoreFile` on the same file-hash target don't collide.
    target_map: HashMap<(KadId, SearchKind), SearchId>,
    /// Contact IDs that need to be marked in-use on the routing table.
    /// Accumulated by start_search, drained by the caller via `drain_in_use_ids`.
    pending_in_use: Vec<KadId>,
    /// In-use contact IDs of searches that were evicted *outside* the normal
    /// `cleanup()` path (currently the search-storm eviction in `start_search`).
    /// Those evictions remove the search before `cleanup()` would, so their
    /// in-use marks must be released here or the routing table would pin those
    /// contacts as in-use forever (blocking dead-contact eviction). Drained by
    /// the main loop via `drain_pending_release`.
    pending_release: Vec<KadId>,
}

impl SearchManager {
    fn reuses_existing_search(search_type: SearchType) -> bool {
        matches!(
            search_type,
            SearchType::FindNode | SearchType::FindBuddy | SearchType::FindSource { .. }
        )
    }

    pub fn new() -> Self {
        SearchManager {
            next_id: 1,
            active: HashMap::new(),
            target_map: HashMap::new(),
            pending_in_use: Vec::new(),
            pending_release: Vec::new(),
        }
    }

    pub fn start_search(
        &mut self,
        target: KadId,
        search_type: SearchType,
        initial_contacts: Vec<KadContact>,
    ) -> SearchId {
        let key = (target, search_type.kind());
        if Self::reuses_existing_search(search_type) {
            if let Some(existing_id) = self.target_map.get(&key) {
                if let Some(state) = self.active.get(existing_id) {
                    if !state.completed && state.search_type == search_type {
                        return *existing_id;
                    }
                }
            }
        }

        // Prevent search storms: if too many active searches, evict oldest completed ones
        // and reject low-priority new searches.
        const MAX_ACTIVE_SEARCHES: usize = 20;
        let active = self.active_count();
        if active >= MAX_ACTIVE_SEARCHES {
            let completed: Vec<SearchId> = self
                .active
                .iter()
                .filter(|(_, s)| s.completed)
                .map(|(id, _)| *id)
                .collect();
            for id in completed {
                if let Some(s) = self.active.remove(&id) {
                    let k = (s.target, s.search_type.kind());
                    if self.target_map.get(&k) == Some(&id) {
                        self.target_map.remove(&k);
                    }
                    // Release this evicted search's in-use marks (see
                    // `pending_release`). Without this the routing table would
                    // keep these contacts pinned in-use indefinitely.
                    self.pending_release.extend(s.in_use_ids);
                }
            }
            if self.active_count() >= MAX_ACTIVE_SEARCHES {
                debug!(
                    "Rejecting search ({search_type:?}): {} active searches at cap",
                    self.active_count()
                );
                return SearchId(0);
            }
        }

        let id = SearchId(self.next_id);
        self.next_id += 1;

        let mut state = SearchState::new(id, target, search_type);
        state.seed(initial_contacts);
        let in_use = state.in_use_ids.clone();
        self.target_map.insert(key, id);
        self.active.insert(id, state);
        self.pending_in_use.extend(in_use);
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
        // K13: target_map is keyed by (target, kind) so we can't look up
        // by target alone. Scan active searches instead — this is the
        // response-routing hot path and ties are rare (typically a single
        // FindNode/FindSource search per target at any time). Preferring
        // the search with the highest expected count matches the earlier
        // behaviour of returning whichever search was registered last.
        self.active
            .values()
            .filter(|s| s.target == *target && !s.completed)
            .map(|s| s.get_expected_response_count())
            .max()
            .unwrap_or(0)
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
            // transition to fetch late enough to allow slower lookups, while still
            // leaving room for fetch responses before overall expiry.
            let elapsed = chrono::Utc::now().timestamp() - state.started_at;
            if should_force_fetch_after_lookup(
                state.phase,
                state.search_type,
                elapsed,
                state.queried.len(),
                state.responded_during_lookup.len(),
            ) {
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
                let type_label = match state.search_type {
                    SearchType::FindNode => "FindNode",
                    SearchType::FindKeyword => "FindKeyword",
                    SearchType::FindSource { .. } => "FindSource",
                    SearchType::FindNotes { .. } => "FindNotes",
                    SearchType::FindBuddy => "FindBuddy",
                    SearchType::StoreFile => "StoreFile",
                    SearchType::StoreKeyword => "StoreKeyword",
                    SearchType::StoreNotes => "StoreNotes",
                };
                // FindNode / FindBuddy never populate `results` (they're
                // routing-table walks, not fetches). The shared
                // "with N results" phrasing made these expiries look
                // like failures even when the walk had successfully
                // populated the routing table — print contact-pool /
                // verified counts instead so the line reads honestly.
                if matches!(
                    state.search_type,
                    SearchType::FindNode | SearchType::FindBuddy
                ) {
                    info!(
                        "Search {} ({}) lookup ended after {}s (queried={}, responded={}, closest_pool={})",
                        sid.0,
                        type_label,
                        elapsed,
                        state.queried.len(),
                        state.responded_during_lookup.len(),
                        state.closest.len(),
                    );
                } else {
                    info!(
                        "Search {} ({}) expired after {}s with {} results (phase={:?}, queried={}, responded={})",
                        sid.0,
                        type_label,
                        elapsed,
                        state.results.len(),
                        state.phase,
                        state.queried.len(),
                        state.responded_during_lookup.len(),
                    );
                }
                state.completed = true;
                continue;
            }

            let batch = state.next_to_query();
            for contact in &batch {
                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                let msg = state.build_query_message(contact);
                queries.push((sid, addr, msg, contact.id));
            }

            // eMule StorePacket: during Lookup phase, also send keyword/source
            // search requests to contacts that have already responded to routing
            // queries. This overlaps fetch with lookup, matching eMule's JumpStart
            // behavior where StorePacket is called for responded contacts rather
            // than waiting for a strict phase transition.
            let store_batch = state.next_store_queries();
            for (contact, msg) in store_batch {
                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                queries.push((sid, addr, msg, contact.id));
            }
        }
        queries
    }

    /// Returns (removed_search_ids, all_in_use_contact_ids_to_release).
    pub fn cleanup(&mut self, max_age_secs: i64) -> (Vec<SearchId>, Vec<KadId>) {
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
        let mut released_ids = Vec::new();
        for &id in &to_remove {
            if let Some(state) = self.active.remove(&id) {
                let k = (state.target, state.search_type.kind());
                if self.target_map.get(&k) == Some(&id) {
                    self.target_map.remove(&k);
                }
                released_ids.extend(state.in_use_ids);
            }
        }
        (to_remove, released_ids)
    }

    /// Drain contact IDs that need to be marked in-use on the routing table.
    /// Called periodically by the main loop to sync with RoutingTable.
    /// Also collects any new in-use IDs accumulated by active searches
    /// (e.g. contacts discovered mid-lookup via handle_response).
    pub fn drain_pending_in_use(&mut self) -> Vec<KadId> {
        let mut ids = std::mem::take(&mut self.pending_in_use);
        for search in self.active.values_mut() {
            if !search.new_in_use_ids.is_empty() {
                ids.append(&mut search.new_in_use_ids);
            }
        }
        ids
    }

    /// Drain contact IDs that should be released from the routing table's
    /// in-use set because their owning search was evicted outside the normal
    /// `cleanup()` path. Called by the main loop alongside
    /// `drain_pending_in_use`.
    pub fn drain_pending_release(&mut self) -> Vec<KadId> {
        std::mem::take(&mut self.pending_release)
    }

    pub fn remove(&mut self, id: &SearchId) -> Option<SearchState> {
        if let Some(state) = self.active.remove(id) {
            let k = (state.target, state.search_type.kind());
            if self.target_map.get(&k) == Some(id) {
                self.target_map.remove(&k);
            }
            Some(state)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kad_id(byte: u8) -> KadId {
        KadId([byte; KAD_ID_SIZE])
    }

    #[test]
    fn expire_pending_uses_relaxed_timeout() {
        let mut state = SearchState::new(SearchId(1), kad_id(1), SearchType::FindKeyword);
        let old = kad_id(2);
        let fresh = kad_id(3);
        let now = chrono::Utc::now().timestamp();
        state.pending.insert(old);
        state.pending.insert(fresh);
        state.pending_times.insert(old, now - PENDING_TIMEOUT_SECS);
        state
            .pending_times
            .insert(fresh, now - (PENDING_TIMEOUT_SECS - 1));

        let timed_out = state.expire_pending();

        assert_eq!(timed_out, vec![old]);
        assert!(!state.pending.contains(&old));
        assert!(state.pending.contains(&fresh));
    }

    #[test]
    fn force_fetch_requires_responders_and_elapsed_time() {
        assert!(!should_force_fetch_after_lookup(
            SearchPhase::Lookup,
            SearchType::FindKeyword,
            LOOKUP_FORCE_FETCH_SECS - 1,
            ALPHA,
            1,
        ));
        assert!(should_force_fetch_after_lookup(
            SearchPhase::Lookup,
            SearchType::FindKeyword,
            LOOKUP_FORCE_FETCH_SECS,
            ALPHA,
            1,
        ));
        assert!(!should_force_fetch_after_lookup(
            SearchPhase::Lookup,
            SearchType::FindNode,
            LOOKUP_FORCE_FETCH_SECS,
            ALPHA,
            1,
        ));
        assert!(
            !should_force_fetch_after_lookup(
                SearchPhase::Lookup,
                SearchType::FindKeyword,
                LOOKUP_FORCE_FETCH_SECS,
                ALPHA,
                0,
            ),
            "must not force fetch with 0 responders"
        );
    }

    #[test]
    fn keyword_searches_do_not_reuse_existing_search() {
        let target = kad_id(9);
        let mut manager = SearchManager::new();

        let first = manager.start_search(target, SearchType::FindKeyword, Vec::new());
        let second = manager.start_search(target, SearchType::FindKeyword, Vec::new());

        assert_ne!(first, second);
        assert_eq!(
            manager.target_map.get(&(target, SearchKind::FindKeyword)),
            Some(&second),
            "target_map should point to newest search for response routing"
        );
    }

    #[test]
    fn findnode_searches_still_reuse_existing_search() {
        let target = kad_id(7);
        let mut manager = SearchManager::new();

        let first = manager.start_search(target, SearchType::FindNode, Vec::new());
        let second = manager.start_search(target, SearchType::FindNode, Vec::new());

        assert_eq!(first, second);
    }

    #[test]
    fn findsource_reuses_when_same_file_size() {
        let target = kad_id(11);
        let mut manager = SearchManager::new();

        let first = manager.start_search(
            target,
            SearchType::FindSource { file_size: 50000 },
            Vec::new(),
        );
        let second = manager.start_search(
            target,
            SearchType::FindSource { file_size: 50000 },
            Vec::new(),
        );

        assert_eq!(first, second, "same target + same file_size should reuse");
    }

    #[test]
    fn findsource_does_not_reuse_when_different_file_size() {
        let target = kad_id(13);
        let mut manager = SearchManager::new();

        let download = manager.start_search(
            target,
            SearchType::FindSource { file_size: 50000 },
            Vec::new(),
        );
        let friend =
            manager.start_search(target, SearchType::FindSource { file_size: 1 }, Vec::new());

        assert_ne!(
            download, friend,
            "different file_size must not reuse (friend vs download)"
        );
    }

    #[test]
    fn get_expected_response_count_works_for_keyword_searches() {
        let target = kad_id(5);
        let mut manager = SearchManager::new();

        let sid = manager.start_search(target, SearchType::FindKeyword, Vec::new());
        assert_ne!(sid, SearchId(0));

        let expected = manager.get_expected_response_count(&target);
        assert!(
            expected > 0,
            "keyword search must have nonzero expected response count"
        );
    }
}
