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
const SOURCE_SEARCH_STOP_THRESHOLD: usize = 20;
const NOTES_SEARCH_STOP_THRESHOLD: usize = 50;
/// eMule caps a FindBuddy search at `SEARCHFINDBUDDY` (10) distinct
/// contacts queried. Both the stop-querying check and the reservation
/// cap below must use this same value — a previous `+ 1` fudge factor
/// let an 11th contact be queried before `stop_querying` engaged.
pub const FIND_BUDDY_REQUEST_TOTAL: usize = 10;

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
/// eMule deletes a "stopping" search ~15s after `PrepareToStop()` (Search.cpp
/// back-dates `m_tCreated` to `now - LIFETIME + SEC(15)`) and runs the prune
/// every second via `CSearchManager::JumpStart()`. We mirror that: once a
/// search is `completed` (shown as "STOPPING" in the UI) it is held this long
/// so late packets/publish acks can still be processed, then reaped by
/// `SearchManager::prune_stopped` on the 1s poll tick — instead of lingering
/// until the slow periodic `cleanup()` sweep.
pub const STOP_GRACE_SECS: i64 = 15;

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

impl SearchType {
    /// Whether this search kind issues `SEARCH_*_REQ` and therefore expects
    /// `KADEMLIA2_SEARCH_RES` (0x3B) replies. Only the fetch-capable `Find*`
    /// kinds do; `FindNode`/`FindBuddy` walk with `KADEMLIA2_REQ` and the
    /// `Store*` kinds publish instead of fetching. Used to keep a
    /// `SearchRes` from being misrouted to a same-target `Store*` search
    /// (which would silently starve the real `Find*` search of its results).
    pub fn accepts_search_results(&self) -> bool {
        matches!(
            self,
            SearchType::FindKeyword | SearchType::FindSource { .. } | SearchType::FindNotes { .. }
        )
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
    /// Wall-clock time `completed` was first set. Drives the eMule
    /// PrepareToStop → JumpStart-delete reap in `SearchManager::prune_stopped`
    /// so a finished ("stopping") search doesn't sit in the active map until
    /// the slow periodic `cleanup()` sweep. Always set via `mark_completed`.
    completed_at: Option<i64>,
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
    find_buddy_sent: HashSet<KadId>,
    /// eMule `CSearch::m_uAnswers` for Store searches: count of
    /// KADEMLIA2_PUBLISH_RES acks received (incremented by
    /// `record_publish_ack`, called from `CSearchManager::ProcessPublishResult`'s
    /// equivalent in the network loop). Crossing `STORE_PUBLISH_TARGET_TOTAL`
    /// ends the search early instead of waiting out the full lifetime.
    store_acks_received: u32,
    /// When this Store search parked in Lookup with `stop_querying` set
    /// (see `check_phase_transition`). Used by `store_search_exhausted` to
    /// require a short settle window — mirroring eMule's `PENDING_TIMEOUT`
    /// grace — before declaring the search out of work, so trailing
    /// responses to queries sent just before parking still get a chance.
    parked_at: Option<i64>,
    /// eMule `CSearch::NODEFWCHECKUDP`: this lookup only exists to *discover*
    /// fresh contacts to seed the UDP firewall test. Its discovered contacts
    /// must never be queried over UDP (doing so would open a NAT mapping and
    /// defeat the reachability test), so `handle_response` records the
    /// responder and stops instead of chasing closer nodes. The mod.rs
    /// KADEMLIA2_RES handler siphons the returned contacts into the firewall
    /// test pool and keeps them out of the routing table.
    pub is_udp_fw_probe_search: bool,
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
            completed_at: None,
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
            find_buddy_sent: HashSet::new(),
            store_acks_received: 0,
            parked_at: None,
            is_udp_fw_probe_search: false,
        }
    }

    /// eMule `PrepareToStop()` entry point: move the search into its terminal
    /// ("stopping") state and stamp when it happened, so the JumpStart-style
    /// reap (`SearchManager::prune_stopped`) can remove it after a short grace
    /// period for late packets. Idempotent: the timestamp is set once so
    /// re-entering completion logic (e.g. a late result calling
    /// `check_completion`) doesn't keep pushing the reap deadline out.
    pub fn mark_completed(&mut self) {
        if !self.completed {
            self.completed = true;
            self.completed_at = Some(chrono::Utc::now().timestamp());
        }
    }

    /// eMule `CSearchManager::ProcessPublishResult`: every KADEMLIA2_PUBLISH_RES
    /// increments `CSearch::m_uAnswers`, and `StorePacket` refuses to send (and
    /// calls `PrepareToStop`) once that count exceeds `SEARCHSTOREFILE_TOTAL` /
    /// `SEARCHSTOREKEYWORD_TOTAL` (both `STORE_PUBLISH_TARGET_TOTAL` here) — a
    /// search that already has enough nodes confirmed doesn't need to sit
    /// around for its full 140s/100s lifetime. The caller (the network loop's
    /// PublishRes handler) calls this once per ack it can attribute to a
    /// Store search's target.
    pub fn record_publish_ack(&mut self) {
        let is_store = matches!(
            self.search_type,
            SearchType::StoreKeyword | SearchType::StoreFile | SearchType::StoreNotes
        );
        if !is_store || self.completed {
            return;
        }
        self.store_acks_received = self.store_acks_received.saturating_add(1);
        if self.store_acks_received as usize > STORE_PUBLISH_TARGET_TOTAL {
            info!(
                "Search {}: {} publish acks confirmed (target {}), ending early instead of waiting out the lifetime",
                self.id.0, self.store_acks_received, STORE_PUBLISH_TARGET_TOTAL
            );
            self.mark_completed();
        }
    }

    /// Read-only equivalent of `next_publish_candidates` (which mutates
    /// `store_sent`): true if a responded, in-tolerance contact still exists
    /// that hasn't been published to and the target quota isn't already met.
    fn has_publish_candidates_remaining(&self) -> bool {
        if self.store_sent.len() >= STORE_PUBLISH_TARGET_TOTAL {
            return false;
        }
        self.closest.iter().any(|c| {
            self.responded_during_lookup.contains(&c.id)
                && !self.store_sent.contains(&c.id)
                && within_search_tolerance(&self.target, &c.id)
        })
    }

    /// eMule `CSearch::JumpStart`: an empty `m_mapPossible` triggers
    /// `PrepareToStop()` immediately rather than waiting out the lifetime —
    /// there's nothing left the search could still do. A parked Store search
    /// (see `check_phase_transition`) is the Ember analogue of a fully-drained
    /// `m_mapPossible`: no publish candidates left, and no outstanding routing
    /// query that could surface a new one. The settle window since parking
    /// (`PENDING_TIMEOUT_SECS`, the same grace the search gives its own
    /// queries) guards against declaring victory before a response to a query
    /// sent just before parking has had a chance to land.
    pub fn store_search_exhausted(&self) -> bool {
        let is_store = matches!(
            self.search_type,
            SearchType::StoreKeyword | SearchType::StoreFile | SearchType::StoreNotes
        );
        if !is_store || self.completed || !self.stop_querying || !self.pending.is_empty() {
            return false;
        }
        let settled = self
            .parked_at
            .is_some_and(|t| chrono::Utc::now().timestamp() - t >= PENDING_TIMEOUT_SECS);
        settled && !self.has_publish_candidates_remaining()
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
            if self.phase == SearchPhase::Fetch {
                self.fetched.insert(c.id);
            }
        }
        batch
    }

    /// eMule `CSearch::ProcessResponse` immediate dispatch (`SendFindValue`):
    /// when a KADEMLIA2_RES reveals contacts that fall inside the top-`ALPHA`
    /// closest set (`m_mapBest`), eMule fires the follow-up query to them
    /// *synchronously in the packet handler* rather than waiting for the next
    /// one-second `JumpStart`. `handle_response` fills `priority_queries` with
    /// exactly those contacts; this drains them and applies the identical
    /// `pending`/`pending_times` reservation that `next_to_query` uses, so the
    /// caller can encode and send the queries right away. Endpoint `tried`
    /// tracking is committed separately after the UDP send succeeds. Regular
    /// (non-best) contacts still flow through the periodic `poll_queries` tick,
    /// matching eMule where only `m_mapBest` additions are queried immediately
    /// and the remaining `m_mapPossible` pool is drained by `JumpStart`.
    ///
    /// Returns `(contact, query_message)` pairs ready to encode and send.
    /// Bounded by the same per-round batch size as `next_to_query` so a burst
    /// of responses can never emit an unbounded flight of packets.
    pub fn take_priority_queries(&mut self) -> Vec<(KadContact, KadMessage)> {
        if self.completed || self.stop_querying || self.phase != SearchPhase::Lookup {
            return Vec::new();
        }
        let max_batch = if matches!(self.search_type, SearchType::FindNode) {
            1
        } else {
            ALPHA
        };
        let now = chrono::Utc::now().timestamp();
        let mut out = Vec::new();
        while !self.priority_queries.is_empty() && out.len() < max_batch {
            let c = self.priority_queries.remove(0);
            if self.queried.contains(&c.id) || self.pending.contains(&c.id) {
                continue;
            }
            self.pending.insert(c.id);
            self.pending_times.insert(c.id, now);
            let msg = self.build_query_message(&c);
            out.push((c, msg));
        }
        out
    }

    /// Roll back the reservation made by `next_to_query`,
    /// `next_store_queries`, or `take_priority_queries` when the caller could
    /// not put the packet on the UDP socket. Reservations are deliberately
    /// made before returning a query so a second poll cannot select the same
    /// contact concurrently; they must not become permanent merely because
    /// the outgoing rate gate fired or `send_to` failed.
    pub fn rollback_unsent_query(&mut self, contact_id: KadId, message: &KadMessage) {
        self.pending.remove(&contact_id);
        self.pending_times.remove(&contact_id);

        match message {
            KadMessage::SearchKeyReq { .. }
            | KadMessage::SearchSourceReq { .. }
            | KadMessage::SearchNotesReq { .. } => {
                self.fetched.remove(&contact_id);
                self.store_sent.remove(&contact_id);
                self.store_pending.remove(&contact_id);
                self.store_pending_times.remove(&contact_id);
            }
            KadMessage::KadReq { .. } => {
                // `take_priority_queries` removes the contact from the eager
                // queue. Reinsert every unsent lookup request at the front;
                // regular `next_to_query` contacts are safe here too, and this
                // preserves the intended immediate priority on the retry.
                if !self.queried.contains(&contact_id)
                    && !self.priority_queries.iter().any(|c| c.id == contact_id)
                {
                    if let Some(contact) = self.closest.iter().find(|c| c.id == contact_id).cloned()
                    {
                        self.priority_queries.insert(0, contact);
                    }
                }
            }
            _ => {}
        }
    }

    /// Commit endpoint tracking only after the caller confirms `send_to`
    /// succeeded. This keeps anti-poisoning's `tried` map from accepting a
    /// response for a packet that was merely reserved but never transmitted.
    pub fn commit_query_sent(&mut self, contact_id: KadId, addr: SocketAddr) {
        if let std::net::IpAddr::V4(ip) = addr.ip() {
            self.tried.insert((ip, addr.port()), contact_id);
        }
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

        let mut contacts = Vec::new();
        for contact in &self.closest {
            if contacts.len() >= ALPHA {
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
                && within_search_tolerance(&self.target, &contact.id)
            {
                contacts.push(contact.clone());
            }
        }

        contacts
    }

    pub fn mark_publish_sent(&mut self, contact: &KadContact) {
        self.store_sent.insert(contact.id);
        self.tried
            .insert((contact.ip, contact.udp_port), contact.id);
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

        // eMule NODEFWCHECKUDP (CSearch::ProcessResponse): a UDP-firewall
        // probe lookup deliberately does NOT feed the returned contacts back
        // into its own candidate lists — querying them over UDP would open a
        // NAT mapping to exactly the peers we want to stay "fresh". Record the
        // responder for bookkeeping and stop here; the KADEMLIA2_RES handler
        // in the network loop harvests the returned contacts into the firewall
        // test pool (and keeps them out of the routing table).
        if self.is_udp_fw_probe_search {
            self.check_completion();
            return;
        }

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
            let next_offset = current_offset.saturating_add(FETCH_PAGE_SIZE as u16);
            if current_offset / FETCH_PAGE_SIZE as u16 + 1 < MAX_PAGES_PER_PEER {
                self.fetch_page_offset.insert(*from, next_offset);
                self.fetched.remove(from);
                // JumpStart `next_store_queries` gates on `!store_sent`. Without
                // clearing it, page-2+ SearchKey/Source requests never fire
                // during Lookup and popular keywords stop at one full page.
                self.store_sent.remove(from);
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
            // Unlike routing timeouts (`handle_timeout`), a StorePacket /
            // Search*Req timeout must not permanently consume the contact.
            // Leaving `store_sent`/`fetched` set blocked `next_store_queries`
            // and made Fetch treat the peer as done, so slow nodes never got
            // another keyword/source/notes page.
            self.store_sent.remove(id);
            self.fetched.remove(id);
            self.check_completion();
        }
        timed_out
    }

    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        let lifetime = self.lifetime_secs();
        // eMule: PrepareToStop fires at the lifetime mark, then a 15s grace
        // period allows late results to arrive. The overall cap is therefore
        // search-lifetime + FETCH_TIMEOUT_SECS.
        now - self.started_at >= lifetime + FETCH_TIMEOUT_SECS
    }

    fn lifetime_secs(&self) -> i64 {
        match self.search_type {
            SearchType::FindNode => TIMEOUT_FIND_NODE,
            SearchType::FindKeyword => TIMEOUT_KEYWORD,
            SearchType::FindSource { .. } => TIMEOUT_SOURCE,
            SearchType::FindNotes { .. } => TIMEOUT_NOTES,
            SearchType::StoreFile => TIMEOUT_STORE_KEYWORD,
            SearchType::StoreKeyword => TIMEOUT_STORE_KEYWORD,
            SearchType::StoreNotes => TIMEOUT_STORE_NOTES,
            SearchType::FindBuddy => TIMEOUT_FIND_BUDDY,
        }
    }

    /// eMule checks `GetAnswers() >= SEARCHKEYWORD_TOTAL` which counts raw
    /// individual results (including duplicates from different nodes).  When
    /// the threshold is reached eMule calls PrepareToStop(): new queries stop
    /// but late responses from already-queried nodes keep flowing in.
    fn should_stop_querying(&self) -> bool {
        let threshold_reached = match self.search_type {
            SearchType::FindKeyword => self.results.len() >= KEYWORD_SEARCH_STOP_THRESHOLD,
            SearchType::FindSource { .. } => self.results.len() >= SOURCE_SEARCH_STOP_THRESHOLD,
            SearchType::FindNotes { .. } => self.results.len() >= NOTES_SEARCH_STOP_THRESHOLD,
            SearchType::FindBuddy => self.find_buddy_sent.len() >= FIND_BUDDY_REQUEST_TOTAL,
            _ => false,
        };
        let now = chrono::Utc::now().timestamp();
        let early_lifetime_stop = (self.search_type.accepts_search_results()
            || matches!(self.search_type, SearchType::FindBuddy))
            && now.saturating_sub(self.started_at) >= self.lifetime_secs().saturating_sub(20);
        threshold_reached || early_lifetime_stop
    }

    pub fn find_buddy_requests_sent(&self) -> usize {
        self.find_buddy_sent.len()
    }

    pub fn reserve_find_buddy_request(&mut self, contact_id: KadId) -> bool {
        if !matches!(self.search_type, SearchType::FindBuddy) {
            return false;
        }
        if self.find_buddy_sent.contains(&contact_id) {
            return false;
        }
        if self.find_buddy_sent.len() >= FIND_BUDDY_REQUEST_TOTAL {
            return false;
        }
        self.find_buddy_sent.insert(contact_id);
        if self.find_buddy_sent.len() >= FIND_BUDDY_REQUEST_TOTAL {
            self.stop_querying = true;
        }
        true
    }

    /// Undo [`reserve_find_buddy_request`] when the FindBuddyReq never left
    /// the UDP socket (encode/send failure). Keeps the buddy request budget
    /// and `find_buddy_sent` aligned with packets that were actually tracked.
    pub fn release_find_buddy_request(&mut self, contact_id: KadId) {
        self.find_buddy_sent.remove(&contact_id);
    }

    /// Mark in-flight routing queries as queried and drop their pending
    /// reservations. Used when leaving Lookup for Fetch so we neither re-send
    /// KadReq to the same contacts nor leave them as eternally pending.
    fn settle_in_flight_routing_queries(&mut self) {
        for id in self.pending.iter().copied().collect::<Vec<_>>() {
            self.queried.insert(id);
        }
        self.pending.clear();
        self.pending_times.clear();
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

        let is_store = matches!(
            self.search_type,
            SearchType::StoreKeyword | SearchType::StoreFile | SearchType::StoreNotes
        );

        // A Store search that already converged stays parked here (see the
        // `is_store` branch below) so `next_publish_candidates` keeps
        // streaming to late responders instead of being force-completed.
        // Without this guard, every further response would re-run the
        // convergence branch below and re-log "lookup converged" forever.
        if is_store && self.stop_querying {
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

        if all_queried || enough_queried || max_lookup_reached {
            let responded_candidates: Vec<&KadContact> = self
                .closest
                .iter()
                .filter(|c| self.responded_during_lookup.contains(&c.id))
                .collect();
            info!(
                "Search {}: lookup converged (queried={}, stale_rounds={}, closest={}, verified={}, \
                within_tolerance={}, responded_in_closest={}, store_pending={}), {}",
                self.id.0, self.queried.len(), self.lookup_stale_rounds, self.closest.len(),
                self.responded_during_lookup.len(), tolerance_candidates.len(), responded_candidates.len(),
                self.store_pending.len(),
                if is_store { "holding open to publish" } else { "switching to fetch" },
            );
            self.settle_in_flight_routing_queries();
            if is_store {
                // eMule's StoreFile/StoreKeyword/StoreNotes searches have no
                // real "fetch" step — publishing IS the lookup's side effect
                // (`next_publish_candidates`, which only runs during Lookup).
                // Switching phase here would both stop that eager publishing
                // and (via the Store arm of `build_query_message`'s Fetch
                // branch) mark the search completed within one more tick —
                // which is what made every Store search finish in ~1-3s
                // instead of occupying its slot for close to the full eMule
                // lifetime (140s/100s). That turned the 3/4-concurrent-search
                // cap in the publish scheduler into a no-op: instead of eMule's
                // "a few searches busy for ~2.5 minutes, then quiet", Ember
                // free-lists a slot and starts the next due keyword/source
                // every ~2s, so publishing never visibly stops. Halting new
                // routing queries here (like eMule backing off once responses
                // stop improving the lookup) while staying in Lookup lets late
                // in-tolerance responders still get eagerly published to until
                // the search finally expires via `is_expired()`, or finishes
                // early via `record_publish_ack`/`store_search_exhausted`
                // once it's done all the work it can (see those for eMule's
                // matching early-exit paths in `StorePacket`/`JumpStart`).
                self.stop_querying = true;
                self.parked_at = Some(chrono::Utc::now().timestamp());
            } else {
                self.fetch_started_at = Some(chrono::Utc::now().timestamp());
                self.phase = SearchPhase::Fetch;
            }
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
                            self.mark_completed();
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
                            self.mark_completed();
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
                        self.mark_completed();
                    }
                }
            }
        }
    }

    fn is_fetch_candidate(&self, contact: &KadContact) -> bool {
        // eMule StorePacket / fetch gate: SEARCHTOLERANCE or LAN only — never
        // widen to out-of-zone lookup responders when the tolerance set is empty.
        if is_lan_ip(contact.ip) {
            return self.responded_during_lookup.contains(&contact.id);
        }
        within_search_tolerance(&self.target, &contact.id)
            && self.responded_during_lookup.contains(&contact.id)
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
                // Defensive fallback only: `check_phase_transition` no longer
                // moves Store searches into `Fetch` (they park in `Lookup`
                // with `stop_querying` set instead, see there for why), so
                // this arm should not be reachable in practice. Kept so a
                // Store search can never spin forever if some future code
                // path does flip its phase.
                SearchType::StoreKeyword | SearchType::StoreFile | SearchType::StoreNotes => {
                    self.mark_completed();
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
    /// Keyed by the full search type so concurrent `FindSource` requests for
    /// the same hash but different file sizes cannot overwrite each other.
    target_map: HashMap<(KadId, SearchType), SearchId>,
    /// Contact IDs that need to be marked in-use on the routing table.
    /// Accumulated by start_search, drained by the caller via `drain_in_use_ids`.
    pending_in_use: Vec<KadId>,
    /// In-use contact IDs of searches that were removed *outside* the normal
    /// `cleanup()` / `start_search` return path. Reserved for future callers;
    /// search-storm eviction now returns released ids directly from
    /// `start_search` so finalize can run immediately. Drained by the main
    /// loop via `drain_pending_release`.
    pending_release: Vec<KadId>,
}

impl SearchManager {
    fn reuses_existing_search(search_type: SearchType) -> bool {
        // FindSource is intentionally *not* reused across callers: each
        // download (and each find_sources IPC) owns its own search id so
        // `download_source_searches` / `pending_source_searches` cannot be
        // overwritten when a second transfer looks up the same hash. FindNode
        // / FindBuddy are still safe to coalesce (no per-caller result map).
        matches!(
            search_type,
            SearchType::FindNode | SearchType::FindBuddy
        )
    }

    fn search_importance(search_type: SearchType) -> u8 {
        match search_type {
            SearchType::StoreFile | SearchType::StoreKeyword | SearchType::StoreNotes => 0,
            SearchType::FindNode | SearchType::FindBuddy => 1,
            SearchType::FindKeyword
            | SearchType::FindSource { .. }
            | SearchType::FindNotes { .. } => 2,
        }
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

    /// Start a search. Returns `(new_id, evicted_ids, released_in_use, preserved_results)`.
    ///
    /// `new_id` is `SearchId(0)` when the request is rejected (capacity /
    /// priority). `evicted_ids` are searches removed by the capacity reap or
    /// live eviction; callers **must** run the same finalize path used by
    /// `CancelKadSearch` (`finalize_removed_searches`) so pending-result maps
    /// keyed by those ids are cleared. `released_in_use` are the evicted
    /// searches' routing-table in-use marks (pass them to finalize together
    /// with the ids). `preserved_results` carries any FindKeyword / FindSource /
    /// FindNotes entries collected before eviction so finalize can deliver or
    /// inject them instead of answering with empty success. When nothing is
    /// evicted the vecs/map are empty.
    pub fn start_search(
        &mut self,
        target: KadId,
        search_type: SearchType,
        initial_contacts: Vec<KadContact>,
    ) -> (
        SearchId,
        Vec<SearchId>,
        Vec<KadId>,
        HashMap<SearchId, Vec<SearchResultEntry>>,
    ) {
        let key = (target, search_type);
        if Self::reuses_existing_search(search_type) {
            if let Some(existing_id) = self.target_map.get(&key) {
                if let Some(state) = self.active.get(existing_id) {
                    if !state.completed && state.search_type == search_type {
                        return (*existing_id, Vec::new(), Vec::new(), HashMap::new());
                    }
                }
            }
        }

        // Prevent search storms. Completed rows do not count toward
        // `active_count`, so evicting only those could never make room at the
        // active cap. Reap them first for memory hygiene, then evict the
        // oldest least-important live search when it is no more important
        // than the new request.
        const MAX_ACTIVE_SEARCHES: usize = 20;
        let mut evicted_ids: Vec<SearchId> = Vec::new();
        let mut released_in_use: Vec<KadId> = Vec::new();
        let mut preserved_results: HashMap<SearchId, Vec<SearchResultEntry>> = HashMap::new();
        let active = self.active_count();
        if active >= MAX_ACTIVE_SEARCHES {
            let completed: Vec<SearchId> = self
                .active
                .iter()
                .filter(|(_, s)| s.completed)
                .map(|(id, _)| *id)
                .collect();
            for id in completed {
                if let Some(mut s) = self.active.remove(&id) {
                    let k = (s.target, s.search_type);
                    if self.target_map.get(&k) == Some(&id) {
                        self.target_map.remove(&k);
                    }
                    // Caller finalizes pending maps for these ids; in-use
                    // marks go back via `released_in_use` (not pending_release)
                    // so finalize can release them immediately.
                    if s.search_type.accepts_search_results() && !s.results.is_empty() {
                        preserved_results.insert(s.id, std::mem::take(&mut s.results));
                    }
                    released_in_use.extend(s.in_use_ids);
                    evicted_ids.push(id);
                }
            }
            if self.active_count() >= MAX_ACTIVE_SEARCHES {
                let new_importance = Self::search_importance(search_type);
                let eviction = self
                    .active
                    .iter()
                    .filter(|(_, state)| {
                        !state.completed
                            && Self::search_importance(state.search_type) <= new_importance
                    })
                    .min_by_key(|(_, state)| {
                        (
                            Self::search_importance(state.search_type),
                            state.started_at,
                            state.id.0,
                        )
                    })
                    .map(|(id, _)| *id);

                if let Some(id) = eviction {
                    if let Some(mut state) = self.active.remove(&id) {
                        let old_key = (state.target, state.search_type);
                        if self.target_map.get(&old_key) == Some(&id) {
                            self.target_map.remove(&old_key);
                        }
                        if state.search_type.accepts_search_results() && !state.results.is_empty()
                        {
                            preserved_results
                                .insert(state.id, std::mem::take(&mut state.results));
                        }
                        released_in_use.extend(state.in_use_ids);
                        evicted_ids.push(id);
                        debug!(
                            "Evicted oldest lower/equal-priority search {} ({:?}) to start {:?}",
                            id.0, state.search_type, search_type
                        );
                    }
                } else {
                    debug!(
                        "Rejecting search ({search_type:?}): {} more-important active searches at cap",
                        self.active_count()
                    );
                    // Still return any completed rows we reaped above so the
                    // caller can finalize their pending maps.
                    return (SearchId(0), evicted_ids, released_in_use, preserved_results);
                }
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
        (id, evicted_ids, released_in_use, preserved_results)
    }

    pub fn get_mut(&mut self, id: &SearchId) -> Option<&mut SearchState> {
        self.active.get_mut(id)
    }

    pub fn get(&self, id: &SearchId) -> Option<&SearchState> {
        self.active.get(id)
    }

    /// Whether any incomplete search is walking `target` (existence gate for
    /// unsolicited KadRes). Per-search acceptance uses
    /// [`Self::max_accepted_response_count_for`].
    pub fn has_active_search_for_target(&self, target: &KadId) -> bool {
        self.active
            .values()
            .any(|s| s.target == *target && !s.completed)
    }

    /// Expected response contact count for a specific active search
    /// (eMule GetExpectedResponseContactCount / GetRequestContactCount).
    /// Returns 0 if the id is missing or already completed.
    #[allow(dead_code)] // exercised by unit tests; KadRes uses max_accepted_response_count_for
    pub fn get_expected_response_count(&self, id: &SearchId) -> u8 {
        self.active
            .get(id)
            .filter(|s| !s.completed)
            .map(|s| s.get_expected_response_count())
            .unwrap_or(0)
    }

    /// Maximum contacts accepted in a KadRes for the matched search `id`
    /// from `from_id`.
    ///
    /// Matches eMule `ProcessResponse`: normally `GetRequestContactCount()`,
    /// but when this responder is that search's FIND_VALUE_MORE re-ask
    /// target, allow up to `KADEMLIA_FIND_NODE` (11). Oversized responses
    /// must be dropped for that search, not truncated — and must not borrow
    /// a higher expected count from a different same-target search.
    pub fn max_accepted_response_count_for(
        &self,
        id: &SearchId,
        from_id: Option<&KadId>,
    ) -> u8 {
        let Some(search) = self.active.get(id).filter(|s| !s.completed) else {
            return 0;
        };
        let expected = search.get_expected_response_count();
        if expected == 0 {
            return 0;
        }
        if let Some(from_id) = from_id {
            if search.lookup_reask_more_target == Some(*from_id) {
                return KADEMLIA_FIND_NODE;
            }
        }
        expected
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
                state.settle_in_flight_routing_queries();
                state.fetch_started_at = Some(chrono::Utc::now().timestamp());
            }

            // eMule `JumpStart`: `m_mapPossible.empty()` -> `PrepareToStop()`
            // immediately, rather than waiting out the search's base lifetime.
            let exhausted = !state.is_expired() && state.store_search_exhausted();
            if (state.is_expired() || exhausted) && !state.completed {
                let elapsed = chrono::Utc::now().timestamp() - state.started_at;
                let end_reason = if exhausted {
                    "no publish candidates left, ending early"
                } else {
                    "expired"
                };
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
                        "Search {} ({}) {} after {}s with {} results (phase={:?}, queried={}, responded={})",
                        sid.0,
                        type_label,
                        end_reason,
                        elapsed,
                        state.results.len(),
                        state.phase,
                        state.queried.len(),
                        state.responded_during_lookup.len(),
                    );
                }
                state.mark_completed();
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
                let k = (state.target, state.search_type);
                if self.target_map.get(&k) == Some(&id) {
                    self.target_map.remove(&k);
                }
                released_ids.extend(state.in_use_ids);
            }
        }
        (to_remove, released_ids)
    }

    /// eMule `CSearchManager::JumpStart()` deletion path: reap searches that
    /// have been in their terminal ("stopping"/`completed`) state for at least
    /// `grace_secs`. eMule runs this every second (`SEARCH_JUMPSTART`) and the
    /// stopping → delete delay is ~15s (`PrepareToStop` back-dates `m_tCreated`).
    ///
    /// The happy-path removal in the network poll loop already drops a
    /// completed search as soon as its work is done, but fire-and-forget
    /// `Store*` publishes stay parked while waiting on publish acks that may
    /// never arrive (`store_publish_pending`). Without this bounded reap they
    /// linger in the active map — shown as "STOPPING" in the UI — until the
    /// slow periodic `cleanup()` sweep. Returns the same
    /// `(removed_ids, in_use_to_release)` shape as `cleanup`.
    pub fn prune_stopped(&mut self, grace_secs: i64) -> (Vec<SearchId>, Vec<KadId>) {
        let now = chrono::Utc::now().timestamp();
        let to_remove: Vec<SearchId> = self
            .active
            .iter()
            .filter(|(_, s)| s.completed_at.is_some_and(|t| now - t >= grace_secs))
            .map(|(id, _)| *id)
            .collect();
        let mut released_ids = Vec::new();
        for &id in &to_remove {
            if let Some(state) = self.active.remove(&id) {
                let k = (state.target, state.search_type);
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
            let k = (state.target, state.search_type);
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

    fn near_kad_id(last_byte: u8) -> KadId {
        let mut id = [0u8; KAD_ID_SIZE];
        id[KAD_ID_SIZE - 1] = last_byte;
        KadId(id)
    }

    fn contact(id: KadId, host: u8) -> KadContact {
        KadContact {
            id,
            ip: Ipv4Addr::new(203, 0, 113, host),
            udp_port: 4672 + host as u16,
            tcp_port: 4662 + host as u16,
            version: KADEMLIA_VERSION,
            last_seen: chrono::Utc::now().timestamp(),
            verified: true,
            contact_type: CONTACT_TYPE_VERIFIED,
            udp_key: None,
            kad_options: 0,
            created_at: chrono::Utc::now().timestamp(),
            expires_at: chrono::Utc::now().timestamp() + 3600,
            last_type_set: chrono::Utc::now().timestamp(),
            received_hello: false,
        }
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
    fn expire_store_pending_clears_store_sent_and_fetched_for_retry() {
        let mut state = SearchState::new(SearchId(1), kad_id(1), SearchType::FindKeyword);
        let peer = kad_id(2);
        let now = chrono::Utc::now().timestamp();
        state.store_pending.insert(peer);
        state
            .store_pending_times
            .insert(peer, now - PENDING_TIMEOUT_SECS);
        state.store_sent.insert(peer);
        state.fetched.insert(peer);

        let timed_out = state.expire_pending();

        assert!(timed_out.is_empty(), "routing pending should be untouched");
        assert!(!state.store_pending.contains(&peer));
        assert!(!state.store_sent.contains(&peer));
        assert!(!state.fetched.contains(&peer));
    }

    #[test]
    fn release_find_buddy_request_frees_budget_after_failed_send() {
        let mut state = SearchState::new(SearchId(1), kad_id(1), SearchType::FindBuddy);
        let peer = kad_id(42);
        assert!(state.reserve_find_buddy_request(peer));
        assert_eq!(state.find_buddy_requests_sent(), 1);
        state.release_find_buddy_request(peer);
        assert_eq!(state.find_buddy_requests_sent(), 0);
        assert!(
            state.reserve_find_buddy_request(peer),
            "same contact must be reservable again after release"
        );
    }

    #[test]
    fn reserve_find_buddy_request_caps_at_request_total_not_one_more() {
        let mut state = SearchState::new(SearchId(1), kad_id(1), SearchType::FindBuddy);
        for i in 0..FIND_BUDDY_REQUEST_TOTAL {
            assert!(
                state.reserve_find_buddy_request(kad_id(i as u8 + 10)),
                "request {i} should be accepted"
            );
        }
        assert_eq!(state.find_buddy_requests_sent(), FIND_BUDDY_REQUEST_TOTAL);
        assert!(
            !state.reserve_find_buddy_request(kad_id(200)),
            "must not allow more than FIND_BUDDY_REQUEST_TOTAL distinct contacts queried"
        );
        assert!(
            state.should_stop_querying(),
            "stop_querying must engage once the cap is reached, not one request later"
        );
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
    fn store_publish_candidates_stop_at_emule_total() {
        let target = near_kad_id(0);
        let mut state = SearchState::new(SearchId(1), target, SearchType::StoreFile);
        let contacts: Vec<KadContact> = (1..=20).map(|i| contact(near_kad_id(i), i)).collect();
        for c in &contacts {
            state.responded_during_lookup.insert(c.id);
        }
        state.closest = contacts;

        let mut published = 0;
        loop {
            let batch = state.next_publish_candidates();
            if batch.is_empty() {
                break;
            }
            assert!(
                batch.len() <= ALPHA,
                "lookup-time store publishing should still respect ALPHA batches"
            );
            published += batch.len();
            for contact in &batch {
                state.mark_publish_sent(contact);
            }
        }

        assert_eq!(published, STORE_PUBLISH_TARGET_TOTAL);
        assert_eq!(state.store_sent.len(), STORE_PUBLISH_TARGET_TOTAL);
        assert!(
            state.next_publish_candidates().is_empty(),
            "eMule caps store publishes at 10 target nodes per search"
        );
    }

    #[test]
    fn failed_publish_attempt_does_not_consume_target_slot() {
        let target = near_kad_id(0);
        let mut state = SearchState::new(SearchId(1), target, SearchType::StoreFile);
        let contact = contact(near_kad_id(1), 1);
        state.responded_during_lookup.insert(contact.id);
        state.closest.push(contact.clone());

        assert_eq!(state.next_publish_candidates()[0].id, contact.id);
        assert_eq!(state.next_publish_candidates()[0].id, contact.id);
        assert!(state.store_sent.is_empty());
    }

    #[test]
    fn record_publish_ack_completes_search_once_target_exceeded() {
        let mut state = SearchState::new(SearchId(1), near_kad_id(0), SearchType::StoreKeyword);
        for _ in 0..STORE_PUBLISH_TARGET_TOTAL {
            state.record_publish_ack();
            assert!(
                !state.completed,
                "must not complete before exceeding SEARCHSTOREKEYWORD_TOTAL, like eMule's `m_uAnswers > SEARCHSTOREKEYWORD_TOTAL`"
            );
        }
        state.record_publish_ack();
        assert!(
            state.completed,
            "eMule's StorePacket calls PrepareToStop once m_uAnswers exceeds the total"
        );
    }

    #[test]
    fn record_publish_ack_is_a_no_op_for_non_store_searches() {
        let mut state = SearchState::new(SearchId(1), near_kad_id(0), SearchType::FindKeyword);
        for _ in 0..=STORE_PUBLISH_TARGET_TOTAL + 5 {
            state.record_publish_ack();
        }
        assert!(
            !state.completed,
            "publish acks are meaningless for Find-type searches and must not affect them"
        );
    }

    #[test]
    fn store_search_not_exhausted_before_parking_or_before_settle_window() {
        let target = near_kad_id(0);
        let mut state = SearchState::new(SearchId(1), target, SearchType::StoreFile);
        assert!(
            !state.store_search_exhausted(),
            "a search that hasn't converged/parked yet must not be treated as exhausted"
        );

        // Park it (mirrors the `is_store` branch of `check_phase_transition`)
        // with no publish candidates left, but *just now* — still inside the
        // settle window, so it must not yet report exhausted.
        state.stop_querying = true;
        state.parked_at = Some(chrono::Utc::now().timestamp());
        assert!(
            !state.store_search_exhausted(),
            "must wait out the settle window for trailing responses before ending early"
        );
    }

    #[test]
    fn store_search_exhausted_after_settle_window_with_no_candidates_left() {
        let target = near_kad_id(0);
        let mut state = SearchState::new(SearchId(1), target, SearchType::StoreKeyword);
        state.stop_querying = true;
        state.parked_at = Some(chrono::Utc::now().timestamp() - PENDING_TIMEOUT_SECS);

        assert!(
            state.store_search_exhausted(),
            "no responded/in-tolerance contacts and nothing pending means eMule's \
            m_mapPossible.empty() equivalent — should end early rather than idle for the full lifetime"
        );
    }

    #[test]
    fn store_search_not_exhausted_while_candidates_remain() {
        let target = near_kad_id(0);
        let mut state = SearchState::new(SearchId(1), target, SearchType::StoreFile);
        let c = contact(near_kad_id(1), 1);
        state.responded_during_lookup.insert(c.id);
        state.closest = vec![c];
        state.stop_querying = true;
        state.parked_at = Some(chrono::Utc::now().timestamp() - PENDING_TIMEOUT_SECS);

        assert!(
            !state.store_search_exhausted(),
            "an unpublished in-tolerance responder is still a valid publish candidate"
        );
    }

    #[test]
    fn keyword_searches_do_not_reuse_existing_search() {
        let target = kad_id(9);
        let mut manager = SearchManager::new();

        let (first, ..) = manager.start_search(target, SearchType::FindKeyword, Vec::new());
        let (second, ..) = manager.start_search(target, SearchType::FindKeyword, Vec::new());

        assert_ne!(first, second);
        assert_eq!(
            manager.target_map.get(&(target, SearchType::FindKeyword)),
            Some(&second),
            "target_map should point to newest search for response routing"
        );
    }

    #[test]
    fn findnode_searches_still_reuse_existing_search() {
        let target = kad_id(7);
        let mut manager = SearchManager::new();

        let (first, ..) = manager.start_search(target, SearchType::FindNode, Vec::new());
        let (second, ..) = manager.start_search(target, SearchType::FindNode, Vec::new());

        assert_eq!(first, second);
    }

    #[test]
    fn findsource_does_not_reuse_existing_search() {
        let target = kad_id(11);
        let mut manager = SearchManager::new();

        let (first, ..) = manager.start_search(
            target,
            SearchType::FindSource { file_size: 50000 },
            Vec::new(),
        );
        let (second, ..) = manager.start_search(
            target,
            SearchType::FindSource { file_size: 50000 },
            Vec::new(),
        );

        assert_ne!(
            first, second,
            "FindSource must not reuse across callers (download map overwrite)"
        );
    }

    #[test]
    fn findsource_does_not_reuse_when_different_file_size() {
        let target = kad_id(13);
        let mut manager = SearchManager::new();

        let (download, ..) = manager.start_search(
            target,
            SearchType::FindSource { file_size: 50000 },
            Vec::new(),
        );
        let (friend, ..) =
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

        let (sid, ..) = manager.start_search(target, SearchType::FindKeyword, Vec::new());
        assert_ne!(sid, SearchId(0));

        let expected = manager.get_expected_response_count(&sid);
        assert!(
            expected > 0,
            "keyword search must have nonzero expected response count"
        );
        assert_eq!(
            manager.max_accepted_response_count_for(&sid, None),
            expected,
            "default max accepted must equal GetRequestContactCount"
        );
    }

    #[test]
    fn max_accepted_uses_matched_search_not_max_across_target() {
        let target = kad_id(17);
        let mut manager = SearchManager::new();
        let (keyword_sid, ..) =
            manager.start_search(target, SearchType::FindKeyword, Vec::new());
        let (node_sid, ..) = manager.start_search(target, SearchType::FindNode, Vec::new());
        assert_ne!(keyword_sid, SearchId(0));
        assert_ne!(node_sid, SearchId(0));

        assert_eq!(
            manager.max_accepted_response_count_for(&keyword_sid, None),
            KADEMLIA_FIND_VALUE,
            "keyword search must not inherit FindNode's higher expected count"
        );
        assert_eq!(
            manager.max_accepted_response_count_for(&node_sid, None),
            KADEMLIA_FIND_NODE,
        );
    }

    #[test]
    fn max_accepted_allows_find_node_for_reask_more_target() {
        let target = kad_id(9);
        let mut manager = SearchManager::new();
        let responder = contact(near_kad_id(1), 1);
        let (sid, ..) =
            manager.start_search(target, SearchType::FindKeyword, vec![responder.clone()]);
        assert_ne!(sid, SearchId(0));

        let search = manager.get_mut(&sid).unwrap();
        search.lookup_reask_more_target = Some(responder.id);
        search.responded_during_lookup.insert(responder.id);

        assert_eq!(
            manager.max_accepted_response_count_for(&sid, Some(&responder.id)),
            KADEMLIA_FIND_NODE,
            "FIND_VALUE_MORE re-ask responder may return up to FIND_NODE contacts"
        );
        assert_eq!(
            manager.max_accepted_response_count_for(&sid, Some(&kad_id(99))),
            KADEMLIA_FIND_VALUE,
            "other responders stay at FIND_VALUE"
        );
    }

    #[test]
    fn prune_stopped_reaps_completed_after_grace() {
        let mut manager = SearchManager::new();
        let target = kad_id(5);
        let (sid, ..) = manager.start_search(target, SearchType::StoreKeyword, Vec::new());

        // An active (not-yet-completed) search is never reaped, regardless of grace.
        let (removed, _) = manager.prune_stopped(0);
        assert!(removed.is_empty(), "active searches must not be pruned");
        assert!(manager.get(&sid).is_some());

        // Once completed, it is held for the grace period (eMule PrepareToStop),
        // then reaped. completed_at is "now", so a positive grace keeps it.
        manager.get_mut(&sid).unwrap().mark_completed();
        let (removed, _) = manager.prune_stopped(STOP_GRACE_SECS);
        assert!(
            removed.is_empty(),
            "a just-completed search must survive the grace window"
        );
        assert!(manager.get(&sid).is_some());

        // With the grace already elapsed (0s) it is reaped, and its in-use
        // contacts/target mapping are released so the routing table can evict them.
        let (removed, _released) = manager.prune_stopped(0);
        assert_eq!(removed, vec![sid]);
        assert!(manager.get(&sid).is_none());
        assert!(manager.active.is_empty());
        assert!(manager.target_map.is_empty());
    }
}
