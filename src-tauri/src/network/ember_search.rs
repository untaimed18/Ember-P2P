//! Ember DHT searches: driving and finishing searches, parsing source and
//! keyword records, and publisher digest corroboration.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// Push an iterative lookup forward: pull the next α-bounded batch of
/// contacts from the search, send each a signed `FIND_NODE` over the
/// Noise transport, and record the in-flight wire requests. Then check
/// whether the search has converged (or had nothing to do) and, if so,
/// resolve its waiter.
///
/// Called when a lookup starts, when a `FOUND_NODE` advances it, and
/// from the staleness sweep after a query is marked failed.
///
/// The first drive of a user keyword search is also where its other walks
/// start, if its query needs any (see [`start_ember_companion_walks`]): every
/// caller that starts a keyword search drives it straight away.
pub(super) async fn drive_ember_search(socket: &UdpSocket, state: &mut NetworkState, search_id: u32) {
    if let Some(ember::dht::search::Companion::FeedsInto(main)) =
        state.ember_search.get(search_id).map(|s| s.companion)
    {
        // The search it was gathering for is gone — cancelled, or reaped.
        if state.ember_search.get(main).is_none() {
            state.ember_search.remove(search_id);
            state
                .ember_dht_search_requests
                .retain(|_, r| r.search_id != search_id);
            return;
        }
    }
    if state.ember_keyword_searches.contains_key(&search_id) {
        if let Some(search) = state.ember_search.get_mut(search_id) {
            search.mark_keyword_lookup();
        }
    }
    let walks = start_ember_companion_walks(state, search_id);
    drive_ember_search_once(socket, state, search_id).await;
    for walk in walks {
        drive_ember_search_once(socket, state, walk).await;
    }
}

/// Most branches of an `OR` query one keyword search walks, its own walk's
/// included. Within [`MAX_EMBER_FEEDING_WALKS`].
const MAX_EMBER_OR_BRANCHES: usize = 3;

/// Most walks one keyword search runs besides its own — its second spelling
/// and its `OR` branches, each branch with one second spelling at most. Each is
/// a slot of the pool shared with every other lookup, and those the user's
/// searches can take are held back from background work, so one search may not
/// spend them all; the pool also keeps its last slots from these walks
/// (`start_feeding_find_value`).
const MAX_EMBER_FEEDING_WALKS: usize = 4;

/// Start the other walks a keyword search needs, each feeding its records into
/// the search's own (see `Companion::FeedsInto`):
///
/// - Its *companion*, when the word its own walk is on hashes, as typed, to a
///   different key than its normalised form. The normalised key is what the
///   search itself walks (`compute_keyword_hashes` normalises). A publisher
///   from before normalisation filed the same spelling under the other key, so
///   without this walk a search typed in, say, decomposed accents would stop
///   finding what every older release publishes.
/// - One per branch of an `OR` its own key does not cover.
///
/// See [`ember_walk_plan`]. Asked once per search, on its first drive. Returns
/// the walks started; a walk the pool has no slot for is left out.
fn start_ember_companion_walks(state: &mut NetworkState, search_id: u32) -> Vec<u32> {
    use ember::dht::search::Companion;
    let mut started = Vec::new();
    let Some(search) = state.ember_search.get_mut(search_id) else {
        return started;
    };
    if search.companion != Companion::Unconsidered {
        return started;
    }
    search.companion = Companion::None;
    let constraints = search.value_constraints().clone();
    let Some(kw) = state.ember_keyword_searches.get(&search_id) else {
        return started;
    };
    let plan = ember_walk_plan(&kw.keywords, kw.query_expr.as_ref());
    if let Some((legacy, extras)) = plan.companion {
        if let Some(walk) = start_ember_feeding_walk(state, search_id, legacy, extras, &constraints) {
            if let Some(search) = state.ember_search.get_mut(search_id) {
                search.companion = Companion::Running(walk);
            }
            started.push(walk);
        }
    }
    for (key, extras) in plan.branches {
        if let Some(walk) = start_ember_feeding_walk(state, search_id, key, extras, &constraints) {
            if let Some(search) = state.ember_search.get_mut(search_id) {
                search.branch_walks.push(walk);
            }
            started.push(walk);
        }
    }
    started
}

/// One walk that feeds `main` (see [`start_ember_companion_walks`]), asking
/// what `main` asks.
fn start_ember_feeding_walk(
    state: &mut NetworkState,
    main: u32,
    key: [u8; 16],
    extras: Vec<[u8; 16]>,
    constraints: &ember::dht::messages::ValueConstraints,
) -> Option<u32> {
    let walk = state.ember_search.start_feeding_find_value(
        ember::dht::EmberNodeId(key),
        extras.clone(),
        state.ember_dht.routing(),
    )?;
    if let Some(search) = state.ember_search.get_mut(walk) {
        search.companion = ember::dht::search::Companion::FeedsInto(main);
        search.set_value_constraints(constraints.clone());
        search.mark_keyword_lookup();
    }
    seed_ember_local_records(state, walk, &key, &extras);
    seed_ember_session_search_contacts(state, walk);
    Some(walk)
}

/// The walks still running that feed `search_id`: its companion and its `OR`
/// branch walks.
pub(super) fn ember_feeding_walks(searches: &ember::dht::search::SearchManager, search_id: u32) -> Vec<u32> {
    use ember::dht::search::Companion;
    let Some(search) = searches.get(search_id) else {
        return Vec::new();
    };
    let companion = match search.companion {
        Companion::Running(walk) => Some(walk),
        _ => None,
    };
    companion
        .into_iter()
        .chain(search.branch_walks.iter().copied())
        .filter(|walk| {
            searches
                .get(*walk)
                .is_some_and(|w| w.companion == Companion::FeedsInto(search_id))
        })
        .collect()
}

/// The key a keyword search's companion walk goes to and the extra keys it
/// sends: the word `walked` was hashed from, as typed, when that hashes
/// elsewhere, with the rest of the query as typed as a peer that predates
/// normalisation would send it — none for a query with an `OR`, like the main
/// walk.
///
/// The typed word is the one whose normalised form is `walked`, which need not
/// be the longest typed word: the two spellings can differ in length. Walking
/// the longest instead could put the companion on a word of another `OR`
/// branch, leaving the search's own word unwalked in its older spelling. A
/// query whose typed words none normalise to `walked` falls back to its longest
/// typed word, unless it has an `OR`.
pub(super) fn ember_spelling_walk_keys(
    keywords: &[String],
    query_expr: Option<&crate::search::query::QueryExpr>,
    walked: &[u8; 16],
) -> Option<([u8; 16], Vec<[u8; 16]>)> {
    use ember::dht::search::{compute_keyword_hashes, extra_keyword_hashes, legacy_keyword_hashes};
    let query = ember_walk_query(keywords, query_expr);
    let mut hashed = legacy_keyword_hashes(&query);
    let intersect = !query_expr.is_some_and(|e| e.contains_or());
    let own = hashed
        .iter()
        .position(|(_, word)| compute_keyword_hashes(word).iter().any(|(key, _)| key == walked));
    match own {
        Some(at) => {
            let word = hashed.remove(at);
            hashed.insert(0, word);
        }
        None if !intersect => return None,
        None => {}
    }
    let legacy = hashed.first()?.0;
    if legacy == *walked {
        return None;
    }
    let extras = extra_keyword_hashes(&hashed, intersect)
        .into_iter()
        .filter(|key| *key != legacy)
        .collect();
    Some((legacy, extras))
}

/// The walks a keyword search runs besides its own, as `(key, extra keys)`.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct EmberWalkPlan {
    /// Its own word in its older spelling (see [`ember_spelling_walk_keys`]).
    pub(super) companion: Option<([u8; 16], Vec<[u8; 16]>)>,
    /// The `OR` branches its own key does not cover.
    pub(super) branches: Vec<([u8; 16], Vec<[u8; 16]>)>,
}

impl EmberWalkPlan {
    fn keys(&self) -> impl Iterator<Item = [u8; 16]> + '_ {
        self.companion.iter().chain(&self.branches).map(|(key, _)| *key)
    }
}

/// Every walk a keyword search runs besides its own, at most
/// [`MAX_EMBER_FEEDING_WALKS`], none on a key another walk of the search
/// already takes.
///
/// The `OR` branches come in only for a query no term of which every match
/// contains: otherwise the search's own walk is on such a term
/// ([`ember_walk_query`]) and finds every match. Without one it walks the
/// longest positive term, which covers only the branches that contain it, and
/// the files matching through any other branch live under keys it never
/// visits. At most [`MAX_EMBER_OR_BRANCHES`] branches are walked, the
/// search's own included. A branch's terms are all in every file it matches,
/// so its walk sends its other terms as extra keys; branches sharing a key share
/// one walk, sending the extra keys they have in common. A branch is walked in
/// its spelling as typed too, where that hashes elsewhere, once at most — after
/// every branch has its normalised walk, and as the cap allows.
pub(super) fn ember_walk_plan(
    keywords: &[String],
    query_expr: Option<&crate::search::query::QueryExpr>,
) -> EmberWalkPlan {
    use ember::dht::search::{compute_keyword_hashes, legacy_keyword_hashes};
    let mut plan = EmberWalkPlan::default();
    let Some((own_key, _)) = compute_keyword_hashes(&ember_walk_query(keywords, query_expr))
        .first()
        .cloned()
    else {
        return plan;
    };
    plan.companion = ember_spelling_walk_keys(keywords, query_expr, &own_key);
    let Some(expr) = query_expr.filter(|expr| expr.required_terms().is_empty()) else {
        return plan;
    };
    let mut taken: Vec<[u8; 16]> = std::iter::once(own_key).chain(plan.keys()).collect();
    // The branches each walk serves, by its normalised key.
    let mut groups: Vec<([u8; 16], Vec<String>)> = Vec::new();
    for branch in ember_or_branches(expr) {
        let query = branch.join(" ");
        let hashed = compute_keyword_hashes(&query);
        let Some((key, _)) = hashed.first() else {
            continue;
        };
        if hashed.iter().any(|(k, _)| *k == own_key) {
            continue;
        }
        if let Some((_, queries)) = groups.iter_mut().find(|(k, _)| k == key) {
            queries.push(query);
        } else if !taken.contains(key) && groups.len() + 1 < MAX_EMBER_OR_BRANCHES {
            groups.push((*key, vec![query]));
        }
    }
    let mut typed_walks = Vec::new();
    for (key, queries) in &groups {
        taken.push(*key);
        plan.branches.push((*key, common_extra_keys(queries.iter(), compute_keyword_hashes, *key)));
        let typed_key = |query: &String| legacy_keyword_hashes(query).first().map(|(k, _)| *k);
        if let Some(typed) = queries.iter().filter_map(typed_key).find(|typed| typed != key) {
            let spelled = queries.iter().filter(|query| typed_key(query) == Some(typed));
            typed_walks.push((typed, common_extra_keys(spelled, legacy_keyword_hashes, typed)));
        }
    }
    for (typed, extras) in typed_walks {
        if !taken.contains(&typed) {
            taken.push(typed);
            plan.branches.push((typed, extras));
        }
    }
    let room = MAX_EMBER_FEEDING_WALKS.saturating_sub(usize::from(plan.companion.is_some()));
    plan.branches.truncate(room);
    plan
}

/// The extra keys every one of `queries` sends when hashed by `hash`, its
/// primary key aside: what a walk serving all of them may ask responders to
/// intersect on.
fn common_extra_keys<'a>(
    queries: impl IntoIterator<Item = &'a String>,
    hash: fn(&str) -> Vec<([u8; 16], String)>,
    primary: [u8; 16],
) -> Vec<[u8; 16]> {
    let mut common: Option<Vec<[u8; 16]>> = None;
    for query in queries {
        let mine: Vec<[u8; 16]> = ember::dht::search::extra_keyword_hashes(&hash(query), true)
            .into_iter()
            .filter(|key| *key != primary)
            .collect();
        common = Some(match common {
            None => mine,
            Some(held) => held.into_iter().filter(|key| mine.contains(key)).collect(),
        });
    }
    common.unwrap_or_default()
}

/// Sets of terms that between them cover a query: every file it matches
/// contains every term of at least one set. One set per side of each `OR`; an
/// `AND` takes the side with fewer sets, each joined by what the other side
/// requires; the excluded side of a `NOT` adds nothing.
fn ember_or_branches(expr: &crate::search::query::QueryExpr) -> Vec<Vec<String>> {
    use crate::search::query::QueryExpr;
    match expr {
        QueryExpr::Term(term) => vec![vec![term.clone()]],
        QueryExpr::Or(l, r) => {
            let mut branches = ember_or_branches(l);
            for branch in ember_or_branches(r) {
                if !branches.contains(&branch) {
                    branches.push(branch);
                }
            }
            branches
        }
        QueryExpr::And(l, r) => {
            let (left, right) = (ember_or_branches(l), ember_or_branches(r));
            let (mut branches, other) = if right.len() < left.len() { (right, l) } else { (left, r) };
            let required = other.required_terms();
            for branch in &mut branches {
                for term in &required {
                    if !branch.contains(term) {
                        branch.push(term.clone());
                    }
                }
            }
            branches
        }
        QueryExpr::Not(l, _) => ember_or_branches(l),
    }
}

/// What [`maybe_finish_ember_search`] does with a completed search, as far as
/// the walks feeding it are concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CompanionStep {
    /// Report the search as usual.
    Report,
    /// Hold it: a walk feeding it, or the one it feeds, is still walking.
    Wait,
    /// It fed this search and has handed its records over; the search should
    /// now be looked at again.
    HandedTo(u32),
    /// It fed a search that is gone; it has been dropped.
    Dropped,
}

/// Settle a search's links to the walks feeding it, or to the one it feeds,
/// once it may need reporting. A walk feeding a search is settled whether or
/// not it has finished when that search is gone, so a cancelled search's walks
/// stop at the next sweep.
pub(super) fn settle_ember_companion(
    searches: &mut ember::dht::search::SearchManager,
    search_id: u32,
    complete: bool,
) -> CompanionStep {
    use ember::dht::search::Companion;
    let Some(companion) = searches.get(search_id).map(|s| s.companion) else {
        return CompanionStep::Report;
    };
    match companion {
        Companion::FeedsInto(main) if searches.get(main).is_none() => {
            searches.remove(search_id);
            CompanionStep::Dropped
        }
        Companion::FeedsInto(main) if complete => {
            if let Some(walk) = searches.remove(search_id) {
                if let Some(search) = searches.get_mut(main) {
                    search.absorb_walk(walk);
                    if search.companion == Companion::Running(search_id) {
                        search.companion = Companion::None;
                    }
                    search.branch_walks.retain(|w| *w != search_id);
                }
            }
            CompanionStep::HandedTo(main)
        }
        Companion::FeedsInto(_) => CompanionStep::Wait,
        _ if !ember_feeding_walks(searches, search_id).is_empty() => CompanionStep::Wait,
        _ => CompanionStep::Report,
    }
}

/// One round of [`drive_ember_search`] for one search.
async fn drive_ember_search_once(socket: &UdpSocket, state: &mut NetworkState, search_id: u32) {
    // A FIND_NODE search queries by target id; a FIND_VALUE search queries
    // by the record key(s) (the primary key plus any extra keyword hashes
    // for multi-keyword lookups), and a peer answers either with the
    // records (FOUND_VALUE) or the closest contacts (FOUND_NODE).
    let (target, search_type, extra_keys, constraints) = match state.ember_search.get(search_id) {
        Some(s) => (
            s.target,
            s.search_type,
            s.keyword_hashes.clone(),
            s.value_constraints().clone(),
        ),
        None => return,
    };

    let mut batch_sent = 0u32;
    // Keep pulling batches until one of them actually reaches the wire.
    //
    // Nothing re-drives a search except a response or a query deadline, and a
    // query that was never sent has neither — so a call that retires its whole
    // batch without transmitting leaves the walk idle until `cleanup_expired`
    // reaps it two minutes later, holding a search slot and resolving its
    // waiter empty. A scattered send failure rarely takes a whole batch, but an
    // address the IP policy refuses is *systematically* correlated: an attacker
    // can choose node ids near the target (the id is theirs to pick, which is
    // the premise of the gate below) with addresses in a blocked range and
    // occupy the head of the shortlist deliberately.
    let mut barren_rounds = 0usize;
    loop {
        let batch = match state.ember_search.get_mut(search_id) {
            Some(s) => s.next_to_query(),
            None => return,
        };
        if batch.is_empty() {
            break;
        }
        for query in batch {
        let ember::dht::search::QueryTarget {
            contact,
            request_id: per_search_req_id,
            start_position,
            resume_after,
            find_node,
            narrow,
        } = query;
        let asks_for_nodes = find_node || search_type == ember::dht::search::SearchType::FindNode;
        // The shortlist is not the routing table, and its contents arrive
        // straight out of a peer's `FOUND_NODE`. The table refuses an address
        // its IP policy blocks, but a search dialled its own shortlist
        // directly, so a peer could name any IPv4 address it liked —
        // special-use space, a LAN under `block_private_ips`, or a banned
        // host — and have us open unsolicited Noise handshakes to it. Getting
        // into the top of the shortlist is cheap, since the node id is the
        // attacker's to choose. Every other Ember dial path already consults
        // this gate.
        //
        // A session peer is judged as every other session dial is, by
        // `ember_addr_ip_verdict`: a LAN address an eD2K session introduced is
        // allowed under `block_private_ips`, and bans still apply. The table's
        // gate refuses it outright — which is the reason the peer is held as a
        // session contact and pinned onto value searches in the first place —
        // so judging the pin by that gate meant it was never asked.
        let session_peer = match contact.addr.ip() {
            IpAddr::V4(v4) => state
                .ember_session_dht_contacts
                .contains_key(&(v4, contact.addr.port())),
            IpAddr::V6(_) => false,
        };
        let refused = if session_peer {
            matches!(
                ember_addr_ip_verdict(state, contact.addr),
                EmberIpVerdict::Blocked | EmberIpVerdict::Banned
            )
        } else {
            state.ember_dht.routing().definitely_blocked(&contact.addr)
                || ember_addr_banned(state, contact.addr)
        };
        if refused {
            debug!(
                "Ember search {search_id}: refusing to query {} — the IP policy blocks it",
                contact.addr
            );
            if let Some(search) = state.ember_search.get_mut(search_id) {
                let _ = search.mark_failed_with(
                    per_search_req_id,
                    ember::dht::search::QueryFailure::NotSent,
                );
            }
            continue;
        }
        let (wire_req_id, frame) = ember_search_query_frame(
            &mut state.ember_dht,
            target,
            asks_for_nodes,
            &extra_keys,
            &constraints,
            (start_position, resume_after, narrow),
        );

        // Tracked separately from `send_ok`: a query still sitting behind a
        // handshake has not reached the peer yet, so the ordinary query budget
        // would expire it before it was ever asked anything.
        let mut behind_handshake = false;
        let send_ok = match state.ember_transport.prepare_outgoing(
            contact.addr,
            Some(&contact.noise_pub),
            &frame,
        ) {
            ember::transport::OutgoingResult::Ready { packet } => {
                match send_ember_udp(socket, &packet, contact.addr, &state.ember_dht_overhead).await
                {
                    Ok(_) => true,
                    Err(e) => {
                        debug!(
                            "Ember DHT search {search_id}: send to {} failed: {e}",
                            contact.addr
                        );
                        false
                    }
                }
            }
            ember::transport::OutgoingResult::HandshakeStarted { packet } => {
                behind_handshake = true;
                match send_ember_udp(socket, &packet, contact.addr, &state.ember_dht_overhead).await
                {
                    Ok(_) => true,
                    Err(e) => {
                        debug!(
                            "Ember DHT search {search_id}: send to {} failed: {e}",
                            contact.addr
                        );
                        false
                    }
                }
            }
            // A handshake to this peer is already in flight; the frame is
            // queued and will ride out when it completes — treat as sent, but
            // give it the longer budget below.
            ember::transport::OutgoingResult::Queued => {
                behind_handshake = true;
                true
            }
            ember::transport::OutgoingResult::Error(e) => {
                debug!(
                    "Ember DHT search {search_id}: transport error for {}: {e}",
                    contact.addr
                );
                false
            }
        };

        if !send_ok {
            // Couldn't get the query out — fail this shortlist entry so
            // the search doesn't wait on a node we never reached.
            //
            // `NotSent`, not the default timeout semantics: those deliberately
            // return a retryable entry to `Pending` because the deadline sweep
            // re-drives the search afterwards. Nothing re-drives this path — we
            // never registered a wire request to time out — so leaving the entry
            // pending stalled the whole walk. With a one-entry shortlist (the
            // small overlay this actually runs on) a single ENETUNREACH held the
            // search, and its waiter, until the 120s backstop reaped it.
            //
            // Count the miss like a lookup timeout, not a liveness ping:
            // `prepare_outgoing` Error (handshake in flight for another
            // identity) used to 3-strike the only `nodes_ember.dat` seed on a
            // cold join. Unverified leads still skip `fault_ember_search_contact`.
            let failed = state
                .ember_search
                .get_mut(search_id)
                .and_then(|s| {
                    s.mark_failed_with(
                        per_search_req_id,
                        ember::dht::search::QueryFailure::NotSent,
                    )
                });
            if failed.is_some() {
                fault_ember_search_contact(state, &contact);
            }
            continue;
        }

        if !behind_handshake {
            if asks_for_nodes {
                state.ember_diagnostics.ember_dht_find_nodes_sent = state
                    .ember_diagnostics
                    .ember_dht_find_nodes_sent
                    .saturating_add(1);
            } else {
                state.ember_diagnostics.ember_dht_find_values_sent = state
                    .ember_diagnostics
                    .ember_dht_find_values_sent
                    .saturating_add(1);
            }
        }
        batch_sent = batch_sent.saturating_add(1);
        let budget = if behind_handshake {
            EMBER_SEARCH_QUEUED_QUERY_TIMEOUT
        } else {
            EMBER_SEARCH_QUERY_TIMEOUT
        };
        state.ember_dht_search_requests.insert(
            wire_req_id,
            EmberSearchRequest {
                search_id,
                per_search_req_id,
                deadline: std::time::Instant::now() + budget,
                sent_unix: chrono::Utc::now().timestamp(),
                handshake_to: behind_handshake.then_some((contact.addr, contact.noise_pub)),
            },
        );
        }
        if batch_sent > 0 {
            break;
        }
        // Nothing left this call. Bounded so a shortlist of entries we cannot
        // dial costs one pass, not a spin: every barren round retires its
        // whole batch, so the shortlist strictly shrinks and this terminates
        // well before the cap on any real search.
        barren_rounds += 1;
        if barren_rounds >= EMBER_SEARCH_MAX_BARREN_ROUNDS {
            debug!(
                "Ember search {search_id}: gave up after {barren_rounds} batches that could \
                 not be dialled"
            );
            break;
        }
    }

    if batch_sent > 0 {
        state.ember_diagnostics.ember_dht_search_rounds = state
            .ember_diagnostics
            .ember_dht_search_rounds
            .saturating_add(1);
    }

    maybe_finish_ember_search(state, search_id);
}

/// The frame one search query goes out as: a `FIND_NODE` for `target`, or a
/// `FIND_VALUE` for it — with the search's extra keys and constraints only
/// when the query is `narrow` (see `QueryTarget::narrow`), and from
/// `start_position` past the `resume_after` anchors for a page follow-up.
fn ember_search_query_frame(
    dht: &mut ember::dht::engine::EmberDht,
    target: ember::dht::EmberNodeId,
    asks_for_nodes: bool,
    extra_keys: &[[u8; 16]],
    constraints: &ember::dht::messages::ValueConstraints,
    (start_position, resume_after, narrow): (u16, ember::dht::messages::ResumeAnchors, bool),
) -> (u32, Vec<u8>) {
    if asks_for_nodes {
        return dht.build_find_node(target);
    }
    let mut keys = Vec::with_capacity(1 + extra_keys.len());
    keys.push(target.0);
    if narrow {
        keys.extend_from_slice(extra_keys);
    }
    dht.build_find_value_resuming(
        keys,
        start_position,
        if narrow {
            constraints.clone()
        } else {
            ember::dht::messages::ValueConstraints::default()
        },
        resume_after,
    )
}

/// Resolve and tear down an iterative lookup if it has converged. Safe
/// to call after every batch / response; a no-op while the search is
/// still in progress.
pub(super) fn maybe_finish_ember_search(state: &mut NetworkState, search_id: u32) {
    let (complete, search_type) = match state.ember_search.get_mut(search_id) {
        Some(s) => (s.poll_complete(), s.search_type),
        None => return,
    };
    // A companion walk hands what it found to its search, which then reports
    // for both; that search is held until then, or the rows of the companion's
    // key would arrive after it had reported complete — bounded by the
    // companion's own timeout, which runs from the same moment.
    match settle_ember_companion(&mut state.ember_search, search_id, complete) {
        CompanionStep::Report if complete => {}
        CompanionStep::Report | CompanionStep::Wait => return,
        CompanionStep::Dropped => {
            state
                .ember_dht_search_requests
                .retain(|_, r| r.search_id != search_id);
            return;
        }
        CompanionStep::HandedTo(main) => {
            state
                .ember_dht_search_requests
                .retain(|_, r| r.search_id != search_id);
            maybe_finish_ember_search(state, main);
            return;
        }
    }

    // A FIND_NODE lookup resolves with the closest contacts that
    // responded; a FIND_VALUE lookup resolves with the raw record blobs
    // the search gathered (the command re-verifies each signature before
    // surfacing it).
    match search_type {
        ember::dht::search::SearchType::FindNode => {
            let contacts = state
                .ember_search
                .get(search_id)
                .map(|s| s.closest_responded())
                .unwrap_or_default();
            if let Some(tx) = state.ember_dht_pending_lookups.remove(&search_id) {
                let local_id = state.ember_dht.local_id();
                let infos = contacts
                    .iter()
                    .map(|c| ember_dht_contact_info(c, local_id))
                    .collect();
                let _ = tx.send(infos);
            }
            // A publish-target lookup: file the closest nodes that answered
            // under the key they were found for. An empty result is not cached,
            // so a walk that reached nobody leaves the key queued rather than
            // pinning an empty target set for the whole TTL.
            if let Some(key) = state.ember_publish_target_lookups.remove(&search_id) {
                note_ember_target_lookup_ended(state, key);
                if contacts.is_empty() {
                    debug!(
                        "Ember DHT: target lookup for {} found nobody; keeping the table's answer",
                        hex::encode(key)
                    );
                } else {
                    if state.ember_publish_targets.len() >= EMBER_PUBLISH_TARGETS_MAX
                        && !state.ember_publish_targets.contains_key(&key)
                    {
                        // Drop whichever set we learned longest ago: it is the
                        // one closest to needing a fresh lookup anyway.
                        if let Some(stalest) = state
                            .ember_publish_targets
                            .iter()
                            .min_by_key(|(_, (_, at))| *at)
                            .map(|(k, _)| *k)
                        {
                            state.ember_publish_targets.remove(&stalest);
                        }
                    }
                    let now = chrono::Utc::now().timestamp();
                    // Each answered this walk over a Noise session to the
                    // address and key the shortlist holds, so that is what is
                    // kept, stamped as heard from — the shortlist's copy of a
                    // contact learned from `FOUND_NODE` never reads as verified.
                    // See `NetworkState::ember_publish_targets` for how long an
                    // address the table did not keep is trusted.
                    let found: Vec<ember::dht::EmberContact> = contacts
                        .into_iter()
                        .map(|mut c| {
                            c.last_seen = now;
                            c.failed_queries = 0;
                            c
                        })
                        .collect();
                    let learned = found.len();
                    state.ember_publish_targets.insert(key, (found, now));
                    debug!(
                        "Ember DHT: {learned} publish targets learned for {}",
                        hex::encode(key)
                    );
                }
            }
        }
        ember::dht::search::SearchType::FindValue => {
            // Removed before the consumers below so the gathered records move to
            // them instead of being copied. None of them look the search up.
            let mut search = state.ember_search.remove(search_id);
            if let Some(search) = &search {
                record_ember_find_value_quality(&mut state.ember_diagnostics, search);
            }
            // Before the records, so a waiter that has them reads this too.
            if let Some(responded) = state.ember_dht_value_lookup_responded.remove(&search_id) {
                let count = search.as_ref().map_or(0, |s| s.responded_count());
                responded.store(count, std::sync::atomic::Ordering::Release);
            }
            let held = search
                .as_mut()
                .map(|s| std::mem::take(&mut s.results))
                .unwrap_or_default();
            let into_blobs = |held: Vec<ember::dht::search::SearchResultRecord>| -> Vec<Vec<u8>> {
                held.into_iter().map(|r| r.data).collect()
            };
            if held.is_empty() {
                state.ember_diagnostics.ember_dht_search_misses = state
                    .ember_diagnostics
                    .ember_dht_search_misses
                    .saturating_add(1);
            } else {
                state.ember_diagnostics.ember_dht_search_hits = state
                    .ember_diagnostics
                    .ember_dht_search_hits
                    .saturating_add(1);
            }
            if let Some(tx) = state.ember_dht_pending_value_lookups.remove(&search_id) {
                // Dev/command value lookup: hand the raw blobs to the waiter.
                let _ = tx.send(into_blobs(held));
            } else if let Some((_transfer_id, file_hash)) =
                state.ember_download_source_searches.remove(&search_id)
            {
                // Download source lookup (slice 9): parse the gathered blobs
                // into connectable sources and queue them for async injection
                // into the matching download on the next sweep tick.
                let self_ip = state.external_ip;
                let local_noise_pub = *state.ember_transport.local_noise_public_key();
                let established = ember_established_addrs(state);
                let sources = parse_ember_source_records(
                    &held,
                    file_hash,
                    self_ip,
                    &local_noise_pub,
                    &mut state.ember_diagnostics,
                    &mut state.ember_noise_keys,
                    &established,
                    &mut state.ember_content_hashes,
                );
                if !sources.is_empty() {
                    state
                        .ember_pending_source_injections
                        .push((file_hash, sources));
                }
            } else if let Some(kw) = state.ember_keyword_searches.remove(&search_id) {
                // User keyword search (slice 10): build SearchResults from
                // the gathered keyword records and buffer them for the async
                // emit on the next sweep tick (which has the enrich pipeline
                // + app_handle). Always queued -- even when empty -- so the
                // sweep clears `ember_pending` and `search-complete` fires.
                //
                // Deliberately every record, not just the tail the streaming
                // sweep has yet to send. `build_ember_keyword_built`
                // aggregates across the records it is handed: `availability` is
                // the number of distinct publishers, and a row carries a
                // plurality digest for display/click while automatic map
                // seeding still requires two publishers, vouched for by two
                // responders, to agree with no rival digest doing the same.
                // Handing it one batch at a time
                // computes both per batch, so a file whose
                // publishers arrived in different batches is under-counted and
                // loses its corroborated digest — which silently drops the
                // BLAKE3 check the corroboration rule exists to guarantee.
                //
                // Re-emitting a streamed row is not a duplicate: `dedup_streamed_batch`
                // in the emit sweep turns any hash already streamed into an
                // availability update carrying these corrected values.
                let built =
                    build_ember_keyword_built(&held, &kw.keywords, kw.query_expr.as_ref());
                for (ed2k, digest, responders) in &built.corroborated {
                    seed_ember_content_hash(
                        &mut state.ember_content_hashes,
                        *ed2k,
                        *digest,
                        EmberDigestProvenance::Corroborated(*responders),
                    );
                }
                let results = built.results;
                state
                    .ember_pending_keyword_results
                    .push(EmberKeywordResultBatch {
                        request_id: kw.request_id,
                        keywords: kw.keywords,
                        file_type_filter: kw.file_type_filter,
                        min_size: kw.min_size,
                        max_size: kw.max_size,
                        file_extension: kw.file_extension,
                        min_availability: kw.min_availability,
                        results,
                        final_batch: true,
                    });
            } else if let Some(channel_id) =
                state.ember_channel_presence_searches.remove(&search_id)
            {
                buffer_channel_presence_records(state, channel_id, into_blobs(held));
            } else if let Some(channel_id) =
                state.ember_channel_claim_searches.remove(&search_id)
            {
                state
                    .ember_pending_channel_claim
                    .push((channel_id, into_blobs(held)));
            } else if let Some((channel_id, epoch)) =
                state.ember_channel_epoch_searches.remove(&search_id)
            {
                state
                    .ember_pending_channel_epoch
                    .push((channel_id, epoch, into_blobs(held)));
            } else if let Some(channel_id) =
                state.ember_channel_moderation_searches.remove(&search_id)
            {
                // How many peers actually answered. An empty result from a
                // search nobody answered says nothing about the owner — it says
                // we could not reach the network — and succession must not read
                // the two the same way.
                let answered = search.as_ref().map_or(0, |s| s.responded_count());
                state
                    .ember_pending_channel_moderation
                    .push((channel_id, into_blobs(held), answered));
            } else if let Some(channel_id) =
                state.ember_channel_handoff_searches.remove(&search_id)
            {
                // Same as moderation: finding nothing because nobody answered
                // must not read, for a room we own, as our record being stored
                // nowhere, which is what lets a banned nominee's commitment go.
                let answered = search.as_ref().map_or(0, |s| s.responded_count());
                let blobs = into_blobs(held);
                if answered > 0 || !blobs.is_empty() {
                    state.ember_pending_channel_handoff.push((channel_id, blobs));
                }
            }
        }
    }

    state.ember_search.remove(search_id);
    state
        .ember_dht_search_requests
        .retain(|_, r| r.search_id != search_id);
}

/// Parse the blobs returned by an Ember DHT source `FIND_VALUE` into
/// verified [`ember::dht::publish::DiscoveredSource`]s (slice 9).
///
/// Each blob is re-verified (`from_value_blob` checks the publisher
/// signature), filtered to source records whose embedded file hash matches
/// the download we asked about, self-filtered against our own external IP
/// and Noise key, and counted for diagnostics. When a record carries a Noise pubkey and
/// UDP port, it is cached under that UDP endpoint so later Ember dials
/// (bridge / native) can find it. Dedup / ban / cap handling is left to
/// `handle_epx_sources` downstream; the drain path applies the same
/// `ip_filter` / banlist gates before writing SourceManager.
pub(super) fn parse_ember_source_records(
    held: &[ember::dht::search::SearchResultRecord],
    file_hash: [u8; 16],
    self_ip: Option<Ipv4Addr>,
    local_noise_pub: &[u8; 32],
    diag: &mut crate::types::EmberDiagnostics,
    noise_keys: &mut HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)>,
    established: &HashSet<(Ipv4Addr, u16)>,
    content_hashes: &mut HashMap<[u8; 16], EmberDigestPin>,
) -> Vec<ember::dht::publish::DiscoveredSource> {
    let mut out = Vec::new();
    // Expected-digest votes, keyed by publisher. A source record is signed
    // only by a key the record carries itself, so there is no trust anchor —
    // any node can assert any digest for any file hash, and mint as many
    // publishers as it likes. Collect the claims with the responders behind
    // them and take the corroborated plurality below (same defence the keyword
    // path applies) instead of believing whichever record parsed last.
    let mut publisher_digests = EmberDigestVotes::new();
    // Every HighID source here is an address we are about to dial, and a
    // responder is not an honest storer that checked it: it can mint keys and
    // name any host. Records two independent responders returned, or our own
    // store bound to the storer's address, go first, and the rest are capped
    // per responder, so one node answering a popular hash cannot aim every
    // downloader of it at a victim.
    let vouched = |record: &ember::dht::search::SearchResultRecord| {
        record.confirmed_by.is_some() || record.from_local_store
    };
    let mut order: Vec<&ember::dht::search::SearchResultRecord> = held.iter().collect();
    order.sort_by_key(|record| !vouched(record));
    let mut unconfirmed_from: HashMap<EmberResponder, usize> = HashMap::new();
    for held_record in order {
        let Some(rec) = ember::dht::publish::SignedRecord::from_value_blob(&held_record.data)
        else {
            continue;
        };
        if rec.record_type != ember::dht::publish::RECORD_TYPE_SOURCE {
            continue;
        }
        // The record must actually be for the file we asked about; a peer
        // can't smuggle unrelated sources under our key.
        if rec.file_hash != file_hash {
            continue;
        }
        if rec.ember_file_hash != [0u8; 32] {
            note_ember_digest_vote(
                &mut publisher_digests,
                rec.publisher_key,
                rec.ember_file_hash,
                held_record,
            );
        }
        let Some(sc) = rec.source_contact else {
            continue;
        };
        diag.ember_dht_source_records_found = diag.ember_dht_source_records_found.saturating_add(1);
        // Never inject ourselves, and drop unusable contacts. Our external IP
        // is unknown until it is confirmed and stale after an address change,
        // so our own record is also recognised by the Noise key it carries —
        // which would otherwise be cached as a peer's under our own address.
        let ours = Some(sc.ip) == self_ip
            || (sc.noise_pub != [0u8; 32] && sc.noise_pub == *local_noise_pub);
        if ours || sc.tcp_port == 0 {
            continue;
        }
        if out.len() >= MAX_EMBER_SOURCES_PER_LOOKUP {
            continue;
        }
        if !vouched(held_record) && sc.flags & ember::SOURCE_FLAG_FIREWALLED == 0 {
            let responder = EmberResponder::of(held_record.from_node, held_record.from_subnet);
            let taken = unconfirmed_from.entry(responder).or_insert(0);
            if *taken >= MAX_UNCONFIRMED_SOURCES_PER_RESPONDER {
                continue;
            }
            *taken += 1;
        }
        if sc.udp_port != 0 && sc.noise_pub != [0u8; 32] {
            // Firewalled contacts skip the STORE IP-bind, so their claimed
            // address is unauthenticated. Caching that (ip, udp) → noise_pub
            // would let a publisher eclipse Noise_IK to a third party.
            if sc.flags & ember::SOURCE_FLAG_FIREWALLED == 0 {
                let _ = cache_bound_ember_noise_key(
                    noise_keys,
                    sc.ip,
                    sc.udp_port,
                    sc.noise_pub,
                    established.contains(&(sc.ip, sc.udp_port)),
                );
            }
        }
        out.push(ember::dht::publish::DiscoveredSource {
            ip: sc.ip,
            tcp_port: sc.tcp_port,
            udp_port: sc.udp_port,
            flags: sc.flags,
            user_hash: sc.user_hash,
            buddy: sc.buddy,
            callback_token: sc.callback_token,
            publisher_id: ember::crypto::node_id_from_ed25519_bytes(&rec.publisher_key)
                .unwrap_or([0u8; 16]),
            quic_port: sc.quic_port,
        });
    }
    // Only ever on corroboration, and only if this plurality rests on more
    // responders than whatever is already pinned. This map is the digest the
    // transfer enforces at completion, so a careless overwrite fails the
    // download at the very end: the eD2K parts all match, the content check
    // does not, and the transfer is failed rather than re-queued, since no
    // source can change the digest — which is why `seed_ember_content_hash`
    // demands strictly better evidence rather than taking the newest claim.
    if let Some((digest, responders)) = corroborated_ember_digest_with_count(&publisher_digests) {
        seed_ember_content_hash(
            content_hashes,
            file_hash,
            digest,
            EmberDigestProvenance::Corroborated(responders),
        );
    }
    out
}

pub(super) struct EmberKeywordBuilt {
    pub(super) results: Vec<SearchResult>,
    /// Digests at least [`MIN_EMBER_DIGEST_PUBLISHERS`] publishers agree on,
    /// vouched for by at least [`MIN_EMBER_DIGEST_RESPONDERS`] responders, for
    /// files no rival digest also clears that bar — with how many responders
    /// that was. What automatic seeding of `ember_content_hashes` may use; see
    /// [`corroborated_ember_digest_with_count`] for what that does and does not
    /// bound. The count travels with the digest so a later or more complete
    /// walk can supersede a pin made on thinner evidence.
    pub(super) corroborated: Vec<([u8; 16], [u8; 32], usize)>,
    /// `(file hash, publisher key)` of every publisher a file's rows count —
    /// [`Self::counted_rows`] without the sizes.
    #[cfg(test)]
    pub(super) counted_publishers: Vec<([u8; 16], [u8; 32])>,
    /// Every publisher a row's `availability` counts — verified, under a
    /// walked key, and past the query filter — by the row that counts it. The
    /// streaming path compares these between rebuilds to tell which rows moved.
    pub(super) counted_rows: Vec<(EmberRowKey, [u8; 32])>,
}

/// The rows of a streaming rebuild worth sending, with `stream` (see
/// `EmberKeywordSearch::streamed_publishers`) brought up to date.
///
/// A row already sent goes out again when the publishers it counts differ
/// from those the last batch carrying it counted — as sets rather than counts,
/// so a row whose plurality digest flipped to as many other publishers still
/// goes. A row not yet sent waits until two publishers give it, or until the
/// next rebuild, whichever comes first: the search page keeps the name a row
/// first arrives with, and a row sent off the first record to arrive would
/// show whatever that one record says. The closing batch sends every row.
///
/// The digest is taken off every row sent: only the closing build can say a
/// digest is contested, which it does with an empty field, and a merge cannot
/// tell that from "no claim" and so would leave a streamed digest pinned — the
/// one a click enforces at completion.
pub(super) fn ember_stream_rows(stream: &mut HashSet<EmberStreamMark>, built: EmberKeywordBuilt) -> Vec<SearchResult> {
    let mut counted: HashMap<EmberRowKey, HashSet<[u8; 32]>> = HashMap::new();
    for (row, publisher) in built.counted_rows {
        counted.entry(row).or_default().insert(publisher);
    }
    let mut sent: HashMap<EmberRowKey, HashSet<[u8; 32]>> = HashMap::new();
    for mark in stream.iter() {
        if let EmberStreamMark::Sent(row, publisher) = mark {
            sent.entry(*row).or_default().insert(*publisher);
        }
    }
    let mut out = Vec::new();
    let mut resent: HashMap<EmberRowKey, HashSet<[u8; 32]>> = HashMap::new();
    for mut row in built.results {
        let Some(key) = ember_row_key(&row) else {
            continue;
        };
        let now = counted.remove(&key).unwrap_or_default();
        let due = match sent.get(&key) {
            Some(before) => *before != now,
            None => now.len() >= 2 || stream.contains(&EmberStreamMark::Held(key)),
        };
        if !due {
            if !sent.contains_key(&key) {
                stream.insert(EmberStreamMark::Held(key));
            }
            continue;
        }
        row.file.ember_file_hash.clear();
        out.push(row);
        resent.insert(key, now);
    }
    stream.retain(|mark| match mark {
        EmberStreamMark::Sent(row, _) | EmberStreamMark::Held(row) => !resent.contains_key(row),
    });
    for (row, publishers) in resent {
        stream.extend(publishers.into_iter().map(|publisher| EmberStreamMark::Sent(row, publisher)));
    }
    out
}

/// Whether a streaming rebuild holds a row back for the next one.
pub(super) fn ember_rows_held(stream: &HashSet<EmberStreamMark>) -> bool {
    stream.iter().any(|mark| matches!(mark, EmberStreamMark::Held(_)))
}

fn ember_row_key(row: &SearchResult) -> Option<EmberRowKey> {
    let hash: [u8; 16] = hex::decode(&row.file.hash).ok()?.try_into().ok()?;
    Some((hash, row.file.size))
}

/// Count the rows of one Ember batch that are on screen toward the progress
/// figure of the lookup running for `request_id`
/// (`EmberKeywordSearch::streamed_files`): those the emit accepted, as it
/// returned them, and those already shown that the lookup found again. A row
/// the emit's filters dropped is in neither. The closing batch finds no lookup:
/// it is gone by the time that batch is emitted.
pub(super) fn note_ember_rows_shown(
    keyword_searches: &mut HashMap<u32, EmberKeywordSearch>,
    request_id: u64,
    emitted: &[SearchResult],
    resights: &[SearchResult],
) {
    if let Some(kw) = keyword_searches
        .values_mut()
        .find(|kw| kw.request_id == request_id)
    {
        kw.streamed_files
            .extend(emitted.iter().chain(resights).map(|row| row.file.hash.clone()));
    }
}

/// The text an Ember keyword search hashes its walk key from: the terms every
/// match contains when there are any ([`QueryExpr::required_terms`]), else
/// every positive keyword. The lookup and [`build_ember_keyword_built`] both
/// take the key from here, because a record under any other key is dropped.
///
/// [`QueryExpr::required_terms`]: crate::search::query::QueryExpr::required_terms
pub(super) fn ember_walk_query(
    keywords: &[String],
    query_expr: Option<&crate::search::query::QueryExpr>,
) -> String {
    let required = query_expr.map(|e| e.required_terms()).unwrap_or_default();
    if required.is_empty() {
        keywords.join(" ")
    } else {
        required.join(" ")
    }
}

/// Which keyword records an Ember keyword search may show: those its walk could
/// legitimately have found.
///
/// Anyone may STORE a signed record under any key, and a record proves only the
/// key it was signed for. A record under `ubuntu` whose name has no `ubuntu` in
/// it was not put there by a publisher deriving keys from that name, so it is
/// dropped however it got there. Asked of the raw name the record signs, with
/// the publishers' own derivations, so no honest record is lost.
///
/// A name long enough to have been shortened to fit the record (see
/// `publish::record_name_may_be_clamped`) is the one exception: a publisher
/// before 1.7.4 derived its keys from the whole name and signed the shortened
/// one, so the key's word may be past the cut. Such a record is not held to the
/// derivation or to carrying the key's own word; every other required word it
/// must still carry.
pub(super) struct EmberKeywordMatcher {
    /// Keys the search walks: the normalised primary key and those of
    /// [`ember_walk_plan`]. Empty only for a query with no word long enough to
    /// hash, which never starts a walk.
    walk_keys: Vec<[u8; 16]>,
    /// Every word each match must contain — all the keywords, or the terms on
    /// every side of a boolean query — as the key of its typed spelling and the
    /// keys of its normalised form. A match must carry each as a word of its
    /// name in one spelling or the other.
    words: Vec<RequiredWord>,
}

struct RequiredWord {
    typed: [u8; 16],
    normalised: Vec<[u8; 16]>,
}

impl EmberKeywordMatcher {
    pub(super) fn new(
        keywords: &[String],
        query_expr: Option<&crate::search::query::QueryExpr>,
    ) -> Self {
        use ember::dht::search::{compute_keyword_hashes, legacy_keyword_hashes};
        let query = ember_walk_query(keywords, query_expr);
        let mut walk_keys = Vec::new();
        let own = compute_keyword_hashes(&query).first().map(|(key, _)| *key);
        let plan = ember_walk_plan(keywords, query_expr);
        for key in own.into_iter().chain(plan.keys()) {
            if !walk_keys.contains(&key) {
                walk_keys.push(key);
            }
        }
        let required = match query_expr {
            Some(expr) => expr.required_terms().join(" "),
            None => keywords.join(" "),
        };
        let words = legacy_keyword_hashes(&required)
            .into_iter()
            .map(|(typed, word)| RequiredWord {
                typed,
                normalised: compute_keyword_hashes(&word)
                    .into_iter()
                    .map(|(k, _)| k)
                    .collect(),
            })
            .collect();
        Self { walk_keys, words }
    }

    /// `clamped` says the record's name may have been shortened to fit it.
    pub(super) fn accepts(&self, rec: &ember::dht::publish::SignedRecord, clamped: bool) -> bool {
        if self.walk_keys.is_empty() {
            return true;
        }
        if !self.walk_keys.contains(&rec.keyword_hash) {
            return false;
        }
        if !clamped && !ember::dht::search::name_hashes_to_key(&rec.file_name, &rec.keyword_hash) {
            return false;
        }
        if self.words.len() < 2 && !clamped {
            return true;
        }
        let name_keys = ember::dht::search::name_word_keys(&rec.file_name);
        self.words.iter().all(|word| {
            name_keys.contains(&word.typed)
                || (!word.normalised.is_empty()
                    && word.normalised.iter().all(|k| name_keys.contains(k)))
                || (clamped
                    && (word.typed == rec.keyword_hash || word.normalised.contains(&rec.keyword_hash)))
        })
    }
}

/// A boolean query with each term held in both spellings, so a name matches
/// a term written either way: the term as typed against the name lowercased
/// as typed, or both normalised (see `normalize_keyword_text`). Built once per
/// rebuild rather than per row.
enum SpelledExpr {
    Term { typed: String, normalised: String },
    And(Box<SpelledExpr>, Box<SpelledExpr>),
    Or(Box<SpelledExpr>, Box<SpelledExpr>),
    Not(Box<SpelledExpr>, Box<SpelledExpr>),
}

impl SpelledExpr {
    fn new(expr: &crate::search::query::QueryExpr) -> Self {
        use crate::search::query::QueryExpr;
        let both = |l: &QueryExpr, r: &QueryExpr| (Box::new(Self::new(l)), Box::new(Self::new(r)));
        match expr {
            QueryExpr::Term(term) => Self::Term {
                typed: term.clone(),
                normalised: ember::dht::search::normalize_keyword_text(term),
            },
            QueryExpr::And(l, r) => {
                let (l, r) = both(l, r);
                Self::And(l, r)
            }
            QueryExpr::Or(l, r) => {
                let (l, r) = both(l, r);
                Self::Or(l, r)
            }
            QueryExpr::Not(l, r) => {
                let (l, r) = both(l, r);
                Self::Not(l, r)
            }
        }
    }

    /// `typed` is the name lowercased as `QueryExpr::matches_name` does it,
    /// `normalised` the same name normalised. A term is present when it is
    /// present in either, which is also what a `NOT` excludes.
    fn matches(&self, typed: &str, normalised: &str) -> bool {
        match self {
            Self::Term { typed: t, normalised: n } => typed.contains(t.as_str()) || normalised.contains(n.as_str()),
            Self::And(l, r) => l.matches(typed, normalised) && r.matches(typed, normalised),
            Self::Or(l, r) => l.matches(typed, normalised) || r.matches(typed, normalised),
            Self::Not(l, r) => l.matches(typed, normalised) && !r.matches(typed, normalised),
        }
    }
}

/// Build search rows from Ember DHT keyword `FIND_VALUE` blobs (slice 10).
///
/// Each blob is re-verified (`from_value_blob` checks the publisher
/// signature) and kept only if it is a keyword record filed under a key the
/// search walked by a name that derives that key, carrying every word of the
/// walked query (see [`EmberKeywordMatcher`]), and -- for multi-word queries --
/// AND-filtered so every query keyword appears in the file name. Multi-keyword
/// queries already ask peers to intersect on the wire; the filename filter is
/// defense-in-depth (and for peers that predate that intersection). Records
/// are deduped by eD2K file hash, with `availability`
/// reflecting the number of distinct publishers, and the name and size the
/// most of those publishers give (see [`ember_row_description`]). Sources are
/// empty: a
/// keyword hit identifies the file, and source discovery runs separately
/// via the slice-9 source lookup when a download starts.
///
/// `complete_sources` is that same publisher count, not zero. Only complete
/// public shares are keyword-published (`is_ember_publishable` requires a
/// listable index row with a content digest), so every distinct publisher of
/// a keyword record holds the whole file — the count is a floor on the
/// complete sources rather than an unknown. Leaving it zero meant the Min
/// Complete filter silently dropped every Ember row (0 is below any
/// threshold), the Complete column read as unknown, and `sort_search_results`,
/// which ranks that field first, put Ember last. It is also the honest side of
/// the comparison with KAD, whose `TAG_COMPLETE_SOURCES` is one peer's claim
/// about a swarm it cannot see; this one is counted from distinct signatures.
/// Signatures are free to mint, so what one responder can add on its own word
/// is bounded where the records are collected, by the search's
/// `MAX_PUBLISHERS_PER_FILE_PER_NODE` share per file and digest, and here, by
/// counting only publishers that name the row's digest or none.
///
/// Each row's `ember_file_hash` is the plurality digest (shown so a click
/// can pin a unique file), ranked first by how many responders vouch for it —
/// or empty when the file is [contested](ember_digest_contested). Automatic
/// seeding of the enforced map uses only [`EmberKeywordBuilt::corroborated`].
pub(super) fn build_ember_keyword_built(
    held: &[ember::dht::search::SearchResultRecord],
    keywords: &[String],
    query_expr: Option<&crate::search::query::QueryExpr>,
) -> EmberKeywordBuilt {
    let reader = EmberRecordReader::new(keywords, query_expr);
    let readings: Vec<_> = held
        .iter()
        .filter_map(|record| {
            let reading = reader.read(record, ember::dht::publish::SignedRecord::from_value_blob)?;
            Some((record, reading))
        })
        .collect();
    fold_ember_keyword_rows(readings.iter().map(|(record, reading)| (*record, reading)))
}

/// Read the records `search` gathered since the last call into
/// `IterativeSearch::keyword_readings`, for the streaming rebuild, which then
/// folds the rows from the readings ([`ember_keyword_readings`]) instead of
/// parsing, tokenizing and matching every record again each time a slice is
/// due.
///
/// Without verifying signatures a second time: every record in
/// `IterativeSearch::results` has had its signature checked on the way in — a
/// remote one by the search, our own by the store that admitted it. The
/// closing build ([`build_ember_keyword_built`]) still verifies.
pub(super) fn read_ember_keyword_records(
    search: &mut ember::dht::search::IterativeSearch,
    reader: &EmberRecordReader,
) {
    read_ember_keyword_records_with(search, reader, |blob| {
        let split = blob.len().checked_sub(64)?;
        let (data, signature) = blob.split_at(split);
        ember::dht::publish::SignedRecord::parse_unverified(data, signature.try_into().ok()?)
    });
}

fn read_ember_keyword_records_with(
    search: &mut ember::dht::search::IterativeSearch,
    reader: &EmberRecordReader,
    parse: impl Fn(&[u8]) -> Option<ember::dht::publish::SignedRecord>,
) {
    let read = search.keyword_readings.len().min(search.results.len());
    search.keyword_readings.truncate(read);
    for record in &search.results[read..] {
        search.keyword_readings.push(reader.read(record, &parse));
    }
}

/// The records of `search` it shows, beside how they were read, as far as
/// [`read_ember_keyword_records`] has got.
pub(super) fn ember_keyword_readings(
    search: &ember::dht::search::IterativeSearch,
) -> impl Iterator<Item = (&ember::dht::search::SearchResultRecord, &ember::dht::search::KeywordReading)> {
    search
        .results
        .iter()
        .zip(&search.keyword_readings)
        .filter_map(|(record, reading)| Some((record, reading.as_ref()?)))
}

/// Which records one keyword search shows, asked of each record once.
pub(super) struct EmberRecordReader {
    /// Must be the keys the lookup walked, so they are derived the same way
    /// rather than re-implemented: picking the longest keyword independently
    /// disagrees with `compute_keyword_hashes` whenever two keywords tie on
    /// length (a stable descending sort keeps the first, `max_by_key` returns
    /// the last), which drops every hit for queries like "ubuntu server".
    matcher: EmberKeywordMatcher,
    /// Boolean queries get the same treatment as the KAD result path. Falling
    /// back to the flat AND would reject the non-matching half of an `OR` and
    /// ignore the excluded side of a `NOT`.
    expr: Option<SpelledExpr>,
    kw_lower: Vec<String>,
    kw_normalised: Vec<String>,
}

impl EmberRecordReader {
    pub(super) fn new(keywords: &[String], query_expr: Option<&crate::search::query::QueryExpr>) -> Self {
        let kw_lower: Vec<String> = keywords.iter().map(|k| k.to_lowercase()).collect();
        let kw_normalised = kw_lower
            .iter()
            .map(|k| ember::dht::search::normalize_keyword_text(k))
            .collect();
        Self {
            matcher: EmberKeywordMatcher::new(keywords, query_expr),
            expr: query_expr.filter(|e| !e.is_trivial()).map(SpelledExpr::new),
            kw_lower,
            kw_normalised,
        }
    }

    /// The record and the name it shows under, or `None` for a record this
    /// search does not show.
    fn read(
        &self,
        held_record: &ember::dht::search::SearchResultRecord,
        parse: impl Fn(&[u8]) -> Option<ember::dht::publish::SignedRecord>,
    ) -> Option<ember::dht::search::KeywordReading> {
        let rec = parse(&held_record.data)?;
        if rec.record_type != ember::dht::publish::RECORD_TYPE_KEYWORD {
            return None;
        }
        let clamped = ember::dht::publish::record_name_may_be_clamped(
            held_record.data.len().saturating_sub(64),
        );
        if !self.matcher.accepts(&rec, clamped) {
            return None;
        }
        // The record's signed bytes keep the publisher's raw name; only the
        // display/derived copy is sanitized, as on the KAD result path.
        let name = crate::security::sanitize_remote_text(&rec.file_name, 8192);
        if name.is_empty() {
            return None;
        }
        // Local re-filter, mirroring the KAD keyword path: the DHT key only
        // matched the primary keyword, so the rest of the query is applied
        // against the file name here — in either spelling, as the key was.
        if let Some(expr) = &self.expr {
            let typed = crate::network::kad::publish::kad_keyword_lowercase(&name);
            let normalised = ember::dht::search::normalize_keyword_text(&name);
            if !expr.matches(&typed, &normalised) {
                return None;
            }
        } else if self.kw_lower.len() > 1 {
            let typed = name.to_lowercase();
            let normalised = ember::dht::search::normalize_keyword_text(&name);
            if !self
                .kw_lower
                .iter()
                .zip(&self.kw_normalised)
                .all(|(k, n)| typed.contains(k.as_str()) || normalised.contains(n.as_str()))
            {
                return None;
            }
        }
        Some(ember::dht::search::KeywordReading { record: rec, name })
    }
}

/// Fold the records a search shows into its rows: one per file and size.
///
/// A file's digest votes, and with them its digest, the publishers it counts
/// and its corroboration, are taken across every size, since one file has one
/// content digest; each size's row then counts the counted publishers giving
/// that size. Rows are kept apart by size as every other leg keeps them, and
/// one publisher gives one size, its first record's.
pub(super) fn fold_ember_keyword_rows<'a>(
    readings: impl IntoIterator<
        Item = (
            &'a ember::dht::search::SearchResultRecord,
            &'a ember::dht::search::KeywordReading,
        ),
    >,
) -> EmberKeywordBuilt {
    // file_hash -> (publisher_key -> ember digest votes, each publisher's
    // description of the file in arrival order)
    let mut dedup: HashMap<[u8; 16], (EmberDigestVotes, Vec<EmberRowClaim>)> = HashMap::new();
    for (held_record, reading) in readings {
        let rec = &reading.record;
        let (votes, claims) = dedup.entry(rec.file_hash).or_default();
        if !votes.contains_key(&rec.publisher_key) {
            claims.push(EmberRowClaim {
                publisher: rec.publisher_key,
                name: reading.name.clone(),
                size: rec.file_size,
                media: rec.media.clone(),
            });
        }
        note_ember_digest_vote(votes, rec.publisher_key, rec.ember_file_hash, held_record);
    }

    // The digest on the row is what the search page hands to start_download
    // on click (user-chosen pin, even a plurality of one). Automatic fills
    // of ember_content_hashes still require corroboration.
    let mut corroborated = Vec::new();
    let mut counted_rows = Vec::new();
    let mut results = Vec::new();
    for (hash, (votes, claims)) in &dedup {
        let plurality = majority_ember_digest(votes);
        // A click pins whatever the row carries, so a contested row carries
        // nothing: showing the plurality would let whoever planted more
        // records choose the pin that way instead.
        let contested = ember_digest_contested(votes);
        let digest_hex = if contested {
            String::new()
        } else {
            plurality.map(hex::encode).unwrap_or_default()
        };
        // The search holds one node's word to a share per file *and digest*, so
        // a node inventing digests gets a share for each. Counting only the
        // publishers that agree with the row, or name no digest, holds it to
        // two shares whatever it invents. A contested row has no digest of its
        // own; it counts the claim most publishers make, so a planted digest
        // that outranks the real one on responders cannot also shrink the
        // count to its own publishers.
        let counted = if contested {
            let mut publishers: HashMap<[u8; 32], usize> = HashMap::new();
            for vote in votes.values().filter(|v| v.digest != [0u8; 32]) {
                *publishers.entry(vote.digest).or_insert(0) += 1;
            }
            publishers
                .into_iter()
                .max_by_key(|(digest, n)| (*n, *digest))
                .map(|(digest, _)| digest)
        } else {
            plurality
        };
        let counts =
            |vote: &EmberDigestVote| vote.digest == [0u8; 32] || Some(vote.digest) == counted;
        // Each size's claims from the publishers counted, sizes in the order
        // they first arrived.
        let mut sizes: Vec<(u64, Vec<&EmberRowClaim>)> = Vec::new();
        for claim in claims.iter().filter(|claim| votes.get(&claim.publisher).is_some_and(counts)) {
            match sizes.iter_mut().find(|(size, _)| *size == claim.size) {
                Some((_, group)) => group.push(claim),
                None => sizes.push((claim.size, vec![claim])),
            }
        }
        for (size, group) in sizes {
            let Some((name, media)) = ember_row_description(&group) else {
                continue;
            };
            counted_rows.extend(group.iter().map(|claim| ((*hash, size), claim.publisher)));
            results.push(ember_keyword_row(*hash, size, name, media, group.len() as u32, digest_hex.clone()));
        }
        if let Some((digest, responders)) = corroborated_ember_digest_with_count(votes) {
            corroborated.push((*hash, digest, responders));
        }
    }
    EmberKeywordBuilt {
        results,
        corroborated,
        #[cfg(test)]
        counted_publishers: counted_rows.iter().map(|((file, _), publisher)| (*file, *publisher)).collect(),
        counted_rows,
    }
}

/// What one publisher's record says about the file a row shows: its first
/// record's, if it published several.
struct EmberRowClaim {
    publisher: [u8; 32],
    name: String,
    size: u64,
    media: Option<crate::types::MediaMetadata>,
}

/// The name and media of one size's row, from the claims of the publishers it
/// counts in the order they arrived: the name most of them give, a tie going
/// to the claim that arrived first. Arrival order is what a responder decides,
/// so it settles only what the publishers leave even.
///
/// The media is that claim's, or failing that the first any of them carries —
/// publishers predating the media block carry none, and one that has it fills
/// the columns for everyone.
fn ember_row_description(claims: &[&EmberRowClaim]) -> Option<(String, Option<crate::types::MediaMetadata>)> {
    let mut tally: HashMap<&str, (usize, usize)> = HashMap::new();
    for (at, claim) in claims.iter().enumerate() {
        tally.entry(claim.name.as_str()).or_insert((0, at)).0 += 1;
    }
    let (_, at) = tally
        .into_values()
        .max_by_key(|&(votes, at)| (votes, std::cmp::Reverse(at)))?;
    let chosen = claims[at];
    let media = std::iter::once(chosen)
        .chain(claims.iter().copied())
        .find_map(|claim| claim.media.clone());
    Some((chosen.name.clone(), media))
}

/// One Ember row: `availability` counted publishers give file `hash` this
/// `size` and, by plurality, this `name`.
fn ember_keyword_row(
    hash: [u8; 16],
    size: u64,
    name: String,
    media: Option<crate::types::MediaMetadata>,
    availability: u32,
    ember_file_hash: String,
) -> SearchResult {
    let extension = ember_row_extension(&name);
    let file_type = crate::search::index::infer_file_type(&extension);
    let hash_hex = hex::encode(hash);
    SearchResult {
        file: FileInfo {
            id: hash_hex.clone(),
            name,
            path: String::new(),
            size,
            hash: hash_hex,
            aich_hash: String::new(),
            ember_file_hash,
            extension,
            modified_at: 0,
            priority: "normal".to_string(),
            requests: 0,
            accepted: 0,
            bytes_transferred: 0,
            alltime_requests: 0,
            alltime_accepted: 0,
            alltime_transferred: 0,
            complete_sources: availability,
            folder: String::new(),
            shared: false,
            friends_only: false,
            shared_kad: false,
            shared_ed2k: false,
            shared_ember: false,
        },
        peer_id: String::new(),
        peer_name: String::new(),
        availability,
        file_type,
        source_addresses: Vec::new(),
        rating: None,
        comment: None,
        media,
        spam_rating: 0,
        is_spam: false,
        clean_name: String::new(),
        result_origin: crate::search::merge::ORIGIN_EMBER.to_string(),
        origin_server_ip: None,
        spam_reasons: Vec::new(),
        spam_reason_details: Vec::new(),
    }
}

/// The extension a row shows for `name`: what follows its last dot.
fn ember_row_extension(name: &str) -> String {
    name.rsplit_once('.')
        .map(|(_, extension)| extension.to_string())
        .unwrap_or_default()
}

/// Sources one source lookup hands to the download. KAD takes 20
/// (`SEARCHFINDSOURCE_TOTAL`); a little more, since Ember records are signed
/// and a real swarm under one key can be larger than a KAD answer.
const MAX_EMBER_SOURCES_PER_LOOKUP: usize = 50;
/// HighID sources one responder may contribute that no other responder also
/// returned. Enough for the honest storer that happens to hold a key alone.
pub(super) const MAX_UNCONFIRMED_SOURCES_PER_RESPONDER: usize = 10;

/// One publisher's digest claim and the responders that carried it.
#[derive(Debug, Clone, Default)]
pub(super) struct EmberDigestVote {
    /// The digest this publisher named; all zero when it named none.
    pub(super) digest: [u8; 32],
    /// Every responder that returned one of this publisher's records.
    pub(super) responders: Vec<EmberResponder>,
}

/// One independent party behind a record, for counting how many stand behind a
/// claim. A /24 where the search knows it: node ids are keypairs, so counting
/// them let one host answering under three keys corroborate a digest alone. A
/// node falls back to its own id when its address is unknown, which is also
/// how our own store counts, once. Honest storers sharing one /24 (a LAN, one
/// CGNAT pool) count once too, so a digest they alone hold does not
/// corroborate; that fails safe, since the eD2K and AICH checks still run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum EmberResponder {
    Subnet(u64),
    Node(ember::dht::EmberNodeId),
}

impl EmberResponder {
    fn of(node: ember::dht::EmberNodeId, subnet: Option<u64>) -> Self {
        subnet.map_or(Self::Node(node), Self::Subnet)
    }
}

/// Digest votes keyed by publisher key.
pub(super) type EmberDigestVotes = HashMap<[u8; 32], EmberDigestVote>;

/// Count one record's claim. A later non-zero digest from the same publisher
/// replaces an earlier one; a record naming none leaves what is there.
pub(super) fn note_ember_digest_vote(
    votes: &mut EmberDigestVotes,
    publisher_key: [u8; 32],
    digest: [u8; 32],
    held: &ember::dht::search::SearchResultRecord,
) {
    let vote = votes.entry(publisher_key).or_default();
    if digest != [0u8; 32] {
        vote.digest = digest;
    }
    let first = EmberResponder::of(held.from_node, held.from_subnet);
    let second = held
        .confirmed_by
        .map(|node| EmberResponder::of(node, held.confirmed_subnet));
    for responder in std::iter::once(first).chain(second) {
        if !vote.responders.contains(&responder) {
            vote.responders.push(responder);
        }
    }
}

/// The best-supported non-zero Ember BLAKE3 for a file: the digest the most
/// responders vouch for, then the most distinct publishers name, or `None`
/// when none of them published one.
///
/// Responders rank first because publishers do not: a responder may return as
/// many freshly keyed records as it likes, so a count of publishers alone lets
/// the one node that minted them out-vote every storer holding the real
/// file's records. This is a plurality with no minimum, which is right for
/// display — one publisher's claim is worth showing — but not for anything
/// enforced. Use [`corroborated_ember_digest`] for that.
pub(super) fn majority_ember_digest(publisher_digests: &EmberDigestVotes) -> Option<[u8; 32]> {
    ranked_ember_digest(publisher_digests).map(|(digest, _, _)| digest)
}

/// Every non-zero digest named, with `(publishers, responders)` behind it.
fn ember_digest_tallies(
    publisher_digests: &EmberDigestVotes,
) -> impl Iterator<Item = ([u8; 32], usize, usize)> {
    let mut tallies: HashMap<[u8; 32], (usize, HashSet<EmberResponder>)> = HashMap::new();
    for vote in publisher_digests.values() {
        if vote.digest != [0u8; 32] {
            let (publishers, responders) = tallies.entry(vote.digest).or_default();
            *publishers += 1;
            responders.extend(vote.responders.iter().copied());
        }
    }
    tallies
        .into_iter()
        .map(|(digest, (publishers, responders))| (digest, publishers, responders.len()))
}

/// The top digest with `(publishers, responders)` behind it.
fn ranked_ember_digest(publisher_digests: &EmberDigestVotes) -> Option<([u8; 32], usize, usize)> {
    ember_digest_tallies(publisher_digests)
        .max_by_key(|(_, publishers, responders)| (*responders, *publishers))
}

/// Distinct publishers that must agree before a DHT-sourced digest is allowed
/// into the map a transfer *enforces* at completion.
///
/// Publisher keys are free to mint, so on its own this only stops a single
/// record from deciding — which is what a plurality of one amounted to — and
/// [`MIN_EMBER_DIGEST_RESPONDERS`] is what stops a single node's reply. The
/// cost of being wrong is asymmetric: a missing digest just means the ed2k/AICH
/// hashes carry the verification, while a wrong one fails the download at the
/// end — every eD2K part matches, the content check does not, and the transfer
/// is failed rather than re-queued, since no other source can change the digest.
pub(super) const MIN_EMBER_DIGEST_PUBLISHERS: usize = 2;

/// Distinct responders whose answers must carry those publishers.
///
/// What this bounds is fabrication inside one reply: a responder can mint any
/// number of publishers and sign a record from each, and none of them count
/// for more than that one responder until a second node returns a record
/// naming the same digest. A record two nodes both returned counts as two,
/// which is the ordinary case for an honest record: it was stored on every node
/// near its key. Our own store's seed counts as one responder.
///
/// It does not bound what a node can STORE. A storer returns planted records
/// as its own, so records planted on the storers near a keyword arrive with as
/// many responders as the real ones. What keeps planting from choosing the pin
/// is [`corroborated_ember_digest_with_count`] refusing a contested file: a
/// fake digest corroborated beside the real one pins nothing. Colluding nodes
/// are not bounded by either rule.
pub(super) const MIN_EMBER_DIGEST_RESPONDERS: usize = 2;

/// Digests that clear both [`MIN_EMBER_DIGEST_PUBLISHERS`] and
/// [`MIN_EMBER_DIGEST_RESPONDERS`], with the responders behind each.
fn corroborated_ember_digests(publisher_digests: &EmberDigestVotes) -> Vec<([u8; 32], usize)> {
    ember_digest_tallies(publisher_digests)
        .filter(|(_, publishers, responders)| {
            *publishers >= MIN_EMBER_DIGEST_PUBLISHERS && *responders >= MIN_EMBER_DIGEST_RESPONDERS
        })
        .map(|(digest, _, responders)| (digest, responders))
        .collect()
}

/// Whether more than one digest is corroborated for the same file.
///
/// A file has one content digest, so two corroborated claims mean at least one
/// set of records is planted, and nothing here can tell which.
pub(super) fn ember_digest_contested(publisher_digests: &EmberDigestVotes) -> bool {
    corroborated_ember_digests(publisher_digests).len() > 1
}

/// The corroborated digest, when exactly one digest is — see
/// [`corroborated_ember_digest_with_count`].
///
/// Runtime callers need the responder count as well, so they use that; this is
/// the shape the corroboration tests assert against.
#[cfg(test)]
pub(super) fn corroborated_ember_digest(publisher_digests: &EmberDigestVotes) -> Option<[u8; 32]> {
    corroborated_ember_digest_with_count(publisher_digests).map(|(digest, _)| digest)
}

/// The digest automatic pinning may use, and how many responders vouched for
/// it: the one digest that clears both thresholds, or nothing when none does or
/// the file is [contested](ember_digest_contested).
///
/// Refusing a contested file is what turns planting records on honest storers
/// into, at worst, suppressing the pin rather than choosing it. Picking the
/// better-supported claim instead would hand the choice to whoever planted
/// more.
///
/// The count is what lets a later, more complete walk supersede a pin an
/// earlier one made on thinner evidence — see [`EmberDigestProvenance`]. It is
/// responders rather than publishers for the reason they rank first in
/// [`majority_ember_digest`].
pub(super) fn corroborated_ember_digest_with_count(
    publisher_digests: &EmberDigestVotes,
) -> Option<([u8; 32], usize)> {
    match corroborated_ember_digests(publisher_digests).as_slice() {
        [only] => Some(*only),
        _ => None,
    }
}

/// How much evidence stands behind an entry in
/// [`NetworkState::ember_content_hashes`].
///
/// That map is what a transfer *enforces* at completion, so which of several
/// competing digests wins has to be decided by evidence, not by arrival order.
/// Ordering by arrival was wrong in two ways at once. An incremental
/// `FIND_VALUE` page corroborates within its own slice, so two early publishers
/// could pin a digest that the finished walk then contradicts — and once pinned,
/// nothing could correct it. And the digest on the row the user actually clicked
/// lost to whatever a partial page had already seeded, so an explicit choice was
/// silently overridden by a guess.
///
/// Derived `Ord` is the precedence, so variants are declared weakest first:
/// more vouching responders beat fewer, an explicit user pick beats any DHT
/// plurality, and bytes hashed on this machine beat everything remote.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum EmberDigestProvenance {
    /// A corroborated plurality, vouched for by this many distinct responders
    /// — see [`corroborated_ember_digest_with_count`]. Responders are dearer
    /// than publisher keys but not scarce, so this only ranks claims against
    /// each other; it is not a trust anchor.
    Corroborated(usize),
    /// The digest carried by the search row the user clicked to download. One
    /// publisher is enough here because the user chose it.
    UserSelected,
    /// Computed from bytes on this machine — known.met, the library index, or a
    /// completed local hash. Nothing remote may outrank it.
    Local,
}

/// An expected Ember BLAKE3 together with the evidence behind it.
#[derive(Clone, Copy, Debug)]
pub(super) struct EmberDigestPin {
    pub(super) digest: [u8; 32],
    pub(super) provenance: EmberDigestProvenance,
}

/// Record `digest` as the expected content hash for `file_hash`, keeping
/// whichever of the incumbent and the newcomer rests on better evidence.
///
/// Replacement is strict: equal evidence leaves the incumbent alone, so two
/// publishers asserting a rival digest cannot flip a live pin back and forth
/// mid-transfer. An all-zero digest means "no claim" and is ignored.
pub(super) fn seed_ember_content_hash(
    pins: &mut HashMap<[u8; 16], EmberDigestPin>,
    file_hash: [u8; 16],
    digest: [u8; 32],
    provenance: EmberDigestProvenance,
) {
    if digest == [0u8; 32] {
        return;
    }
    let pin = EmberDigestPin { digest, provenance };
    match pins.entry(file_hash) {
        std::collections::hash_map::Entry::Vacant(slot) => {
            slot.insert(pin);
        }
        std::collections::hash_map::Entry::Occupied(mut slot) => {
            if provenance > slot.get().provenance {
                slot.insert(pin);
            }
        }
    }
}

/// Start an Ember DHT `FIND_VALUE` for the sources of `file_hash` on behalf
/// of a download (slice 9). Returns whether a search was started (`false`
/// if the search-manager slot cap is hit). Results are delivered
/// asynchronously: `maybe_finish_ember_search` parses them into
/// `ember_pending_source_injections`, which the search-timer sweep drains
/// through `handle_epx_sources` into the download.
pub(super) async fn start_ember_source_search(
    socket: &UdpSocket,
    state: &mut NetworkState,
    transfer_id: &str,
    file_hash: [u8; 16],
) -> bool {
    let source_key = ember::dht::publish::source_key(&file_hash);
    let target = ember::dht::EmberNodeId(source_key);
    let Some(search_id) =
        state
            .ember_search
            .start_background_find_value(target, Vec::new(), state.ember_dht.routing())
    else {
        return false;
    };
    seed_ember_local_records(state, search_id, &source_key, &[]);
    seed_ember_session_search_contacts(state, search_id);
    state
        .ember_download_source_searches
        .insert(search_id, (transfer_id.to_string(), file_hash));
    state.ember_diagnostics.ember_dht_source_searches = state
        .ember_diagnostics
        .ember_dht_source_searches
        .saturating_add(1);
    drive_ember_search(socket, state, search_id).await;
    true
}

#[cfg(test)]
mod ember_digest_corroboration_tests {
    use super::*;

    /// Each publisher's claim, returned by a node of its own.
    fn digests(pairs: &[(u8, u8)]) -> EmberDigestVotes {
        pairs
            .iter()
            .map(|(publisher, digest)| {
                (
                    [*publisher; 32],
                    EmberDigestVote {
                        digest: [*digest; 32],
                        responders: vec![EmberResponder::Subnet(u64::from(*publisher))],
                    },
                )
            })
            .collect()
    }

    /// A record from `node`, confirmed by another; each in a /24 of its own.
    fn held_from(node: u8, confirmed_by: Option<u8>) -> ember::dht::search::SearchResultRecord {
        ember::dht::search::SearchResultRecord {
            data: Vec::new(),
            from_node: ember::dht::EmberNodeId([node; 16]),
            confirmed_by: confirmed_by.map(|n| ember::dht::EmberNodeId([n; 16])),
            from_subnet: Some(u64::from(node)),
            confirmed_subnet: confirmed_by.map(u64::from),
            from_local_store: false,
        }
    }

    /// One host answering under several keypairs is one responder: node ids
    /// are free, a /24 is not.
    #[test]
    fn keypairs_in_one_subnet_do_not_corroborate() {
        let mut votes = EmberDigestVotes::new();
        for (publisher, node) in [(1u8, 1u8), (2, 2), (3, 3)] {
            let held = ember::dht::search::SearchResultRecord {
                from_subnet: Some(0xC0FFEE),
                ..held_from(node, None)
            };
            note_ember_digest_vote(&mut votes, [publisher; 32], [0xEE; 32], &held);
        }
        assert_eq!(corroborated_ember_digest(&votes), None, "three keys, one host");

        let other_host = ember::dht::search::SearchResultRecord {
            from_subnet: Some(0xBEEF),
            ..held_from(4, None)
        };
        note_ember_digest_vote(&mut votes, [4; 32], [0xEE; 32], &other_host);
        assert_eq!(corroborated_ember_digest(&votes), Some([0xEE; 32]));
    }

    /// Publisher keys are free, so any number of them agreeing means nothing
    /// while one node returned them all — however many it minted.
    #[test]
    fn publishers_from_one_responder_do_not_corroborate() {
        let mut votes = EmberDigestVotes::new();
        for publisher in 1..=40u8 {
            note_ember_digest_vote(&mut votes, [publisher; 32], [0xEE; 32], &held_from(9, None));
        }
        assert_eq!(corroborated_ember_digest(&votes), None);

        // Two honest publishers the other storers returned outrank the forty on
        // display, because more responders stand behind them.
        note_ember_digest_vote(&mut votes, [0xA1; 32], [0xAA; 32], &held_from(1, None));
        note_ember_digest_vote(&mut votes, [0xA2; 32], [0xAA; 32], &held_from(2, None));
        assert_eq!(majority_ember_digest(&votes), Some([0xAA; 32]));
        assert_eq!(corroborated_ember_digest_with_count(&votes), Some(([0xAA; 32], 2)));
    }

    /// An honest record is stored on every node near its key, so the walk
    /// usually sees it from more than one — and the second copy is what makes
    /// publishers that all first arrived from one storer corroborate.
    #[test]
    fn a_record_a_second_node_also_returned_counts_both() {
        let mut votes = EmberDigestVotes::new();
        note_ember_digest_vote(&mut votes, [1; 32], [0xAA; 32], &held_from(1, None));
        note_ember_digest_vote(&mut votes, [2; 32], [0xAA; 32], &held_from(1, None));
        assert_eq!(corroborated_ember_digest(&votes), None, "one storer's word");

        note_ember_digest_vote(&mut votes, [2; 32], [0u8; 32], &held_from(1, Some(3)));
        assert_eq!(
            corroborated_ember_digest_with_count(&votes),
            Some(([0xAA; 32], 2)),
            "a record naming no digest keeps its publisher's claim and adds a voucher"
        );
    }

    #[test]
    fn one_publisher_is_not_a_majority() {
        let single = digests(&[(1, 0xAA)]);
        assert_eq!(
            majority_ember_digest(&single),
            Some([0xAA; 32]),
            "display still shows a lone claim"
        );
        assert_eq!(
            corroborated_ember_digest(&single),
            None,
            "but nothing enforced may rest on it"
        );
    }

    #[test]
    fn two_agreeing_publishers_corroborate() {
        assert_eq!(
            corroborated_ember_digest(&digests(&[(1, 0xAA), (2, 0xAA)])),
            Some([0xAA; 32])
        );
    }

    #[test]
    fn disagreeing_publishers_do_not_corroborate() {
        assert_eq!(
            corroborated_ember_digest(&digests(&[(1, 0xAA), (2, 0xBB), (3, 0xCC)])),
            None,
            "a plurality of one each is still one each"
        );
        // A real majority inside a disputed set still wins.
        assert_eq!(
            corroborated_ember_digest(&digests(&[(1, 0xAA), (2, 0xAA), (3, 0xCC)])),
            Some([0xAA; 32])
        );
    }

    #[test]
    fn publishers_that_named_no_digest_are_not_counted() {
        assert_eq!(
            corroborated_ember_digest(&digests(&[(1, 0xAA), (2, 0x00), (3, 0x00)])),
            None
        );
    }

    #[test]
    fn two_corroborated_digests_pin_neither() {
        let mut votes = EmberDigestVotes::new();
        for (publisher, node, digest) in [(1u8, 1u8, 0xAA), (2, 2, 0xAA), (3, 1, 0xBB), (4, 2, 0xBB)] {
            note_ember_digest_vote(&mut votes, [publisher; 32], [digest; 32], &held_from(node, None));
        }
        assert!(ember_digest_contested(&votes));
        assert_eq!(corroborated_ember_digest_with_count(&votes), None);
    }

    const FILE: [u8; 16] = [0xF1; 16];
    const REAL: [u8; 32] = [0x77; 32];
    const FAKE: [u8; 32] = [0xEE; 32];

    /// A keyword record for [`FILE`] under a key of its own.
    fn publisher_blob(key_seed: u16, digest: [u8; 32]) -> Vec<u8> {
        let mut seed = [0x5Au8; 32];
        seed[..2].copy_from_slice(&key_seed.to_le_bytes());
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let rec = ember::dht::publish::SignedRecord::keyword(
            "ubuntu", FILE, digest, 100, "ubuntu.iso", &sk,
        );
        let mut blob = rec.data.clone();
        blob.extend_from_slice(&rec.signature);
        blob
    }

    /// Run a keyword search over `storers` nodes that each answer with
    /// `answer`, and build its rows as the finished search would.
    fn search_storers(storers: u8, answer: &[Vec<u8>]) -> EmberKeywordBuilt {
        use ember::dht::{routing::RoutingTable, search::SearchManager, EmberContact, EmberNodeId};
        use std::net::{IpAddr, SocketAddr};

        let mut rt = RoutingTable::new(EmberNodeId([0; 16]), false);
        for i in 1..=storers {
            let mut id = [0u8; 16];
            id[0] = 0x40 + i;
            rt.add_contact(EmberContact {
                node_id: EmberNodeId(id),
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 1, i, 1)), 4662),
                noise_pub: [i; 32],
                ed25519_pub: [i; 32],
                last_seen: chrono::Utc::now().timestamp(),
                failed_queries: 0,
            });
        }
        let target = EmberNodeId(ember::dht::search::keyword_hash("ubuntu"));
        let mut sm = SearchManager::new();
        let sid = sm.start_find_value(target, vec![], &rt).expect("slot");
        let search = sm.get_mut(sid).expect("held");
        loop {
            let batch = search.next_to_query();
            if batch.is_empty() {
                break;
            }
            for query in batch {
                search.process_response(
                    query.request_id,
                    &query.contact.node_id,
                    vec![],
                    answer.to_vec(),
                    None,
                );
            }
        }
        assert!(search.poll_complete());
        build_ember_keyword_built(&search.results, &["ubuntu".to_string()], None)
    }

    /// One node STOREs forty freshly keyed records naming a fake digest onto
    /// every honest storer near the keyword, ahead of the real publishers in
    /// each storer's order. Every storer returns them as its own, so the fake
    /// has as many responders as the real digest: nothing may be pinned, by the
    /// map or by a click.
    #[test]
    fn records_planted_on_honest_storers_pin_nothing() {
        let mut held: Vec<Vec<u8>> = (0..40).map(|i| publisher_blob(1000 + i, FAKE)).collect();
        held.extend((0..6).map(|i| publisher_blob(i, REAL)));

        let built = search_storers(4, &held);
        assert_eq!(built.results.len(), 1);
        assert!(built.corroborated.is_empty(), "a contested file is not pinned");
        assert_eq!(
            built.results[0].file.ember_file_hash, "",
            "nor does its row carry a digest a click would pin"
        );
    }

    /// The same storers holding only the real publishers still pin them.
    #[test]
    fn an_uncontested_file_answered_by_honest_storers_still_pins() {
        let held: Vec<Vec<u8>> = (0..6).map(|i| publisher_blob(i, REAL)).collect();

        let built = search_storers(4, &held);
        assert_eq!(built.results.len(), 1);
        assert_eq!(built.results[0].file.ember_file_hash, hex::encode(REAL));
        assert_eq!(built.results[0].availability, 6);
        // A record notes its first two responders, so two however many held it.
        assert_eq!(built.corroborated, vec![(FILE, REAL, 2)]);
    }

    /// The search gives one node a share per digest, so a node inventing
    /// digests would get a share for each. The row counts only publishers that
    /// agree with it, or name none.
    #[test]
    fn invented_digests_do_not_add_to_a_rows_sources() {
        let from = |node: u8, data: Vec<u8>| ember::dht::search::SearchResultRecord {
            data,
            from_node: ember::dht::EmberNodeId([node; 16]),
            confirmed_by: None,
            from_subnet: None,
            confirmed_subnet: None,
            from_local_store: false,
        };
        let mut held = Vec::new();
        for invented in 0..10u16 {
            let mut digest = FAKE;
            digest[..2].copy_from_slice(&invented.to_le_bytes());
            held.extend((0..5).map(|i| from(9, publisher_blob(invented * 10 + i, digest))));
        }
        held.extend((0..3).map(|i| from(9, publisher_blob(500 + i, [0u8; 32]))));

        let built = build_ember_keyword_built(&held, &["ubuntu".to_string()], None);
        assert_eq!(built.results.len(), 1);
        assert_eq!(
            built.results[0].availability, 8,
            "one digest's share plus the publishers naming none"
        );
    }
}

#[cfg(test)]
mod ember_source_self_filter_tests {
    use super::*;

    /// Our own source record comes back from any walk for a file we share.
    /// Before our external IP is confirmed, or after it changes, the IP check
    /// cannot recognise it; the Noise key still does, so we neither cache our
    /// own key as a peer's nor offer ourselves as a source.
    /// One responder naming many HighID sources that nobody else returned gets
    /// a few of them dialled, not all; sources a second responder confirmed
    /// are taken regardless, and first.
    #[test]
    fn one_responder_cannot_aim_a_lookup_at_every_address_it_names() {
        let file_hash = [0x62u8; 16];
        let record = |i: u8, confirmed: bool| {
            let sk = ed25519_dalek::SigningKey::from_bytes(&[i.wrapping_add(90); 32]);
            let rec = ember::dht::publish::SignedRecord::source(
                file_hash,
                [0u8; 32],
                1,
                "big.iso",
                ember::dht::publish::SourceContact {
                    ip: Ipv4Addr::new(81, 7, 7, i),
                    tcp_port: 4662,
                    flags: 0,
                    ..Default::default()
                },
                &sk,
            );
            let mut data = rec.data.clone();
            data.extend_from_slice(&rec.signature);
            ember::dht::search::SearchResultRecord {
                data,
                from_node: ember::dht::EmberNodeId([1; 16]),
                confirmed_by: confirmed.then_some(ember::dht::EmberNodeId([2; 16])),
                from_subnet: Some(1),
                confirmed_subnet: confirmed.then_some(2),
                from_local_store: false,
            }
        };
        let mut held: Vec<_> = (1..=40u8).map(|i| record(i, false)).collect();
        held.extend((41..=43u8).map(|i| record(i, true)));

        let sources = parse_ember_source_records(
            &held,
            file_hash,
            None,
            &[0u8; 32],
            &mut crate::types::EmberDiagnostics::default(),
            &mut HashMap::new(),
            &HashSet::new(),
            &mut HashMap::new(),
        );
        assert_eq!(sources.len(), 3 + MAX_UNCONFIRMED_SOURCES_PER_RESPONDER);
        for confirmed in 41..=43u8 {
            assert!(sources.iter().any(|s| s.ip == Ipv4Addr::new(81, 7, 7, confirmed)));
        }
    }

    /// Our own store took each HighID source only from the address it names,
    /// so on a network of two or three nodes a file's whole swarm is dialled
    /// rather than the ten one remote responder would be allowed.
    #[test]
    fn our_own_stores_sources_are_not_capped_as_one_responder() {
        let file_hash = [0x63u8; 16];
        let record = |i: u8, local: bool| {
            let sk = ed25519_dalek::SigningKey::from_bytes(&[i.wrapping_add(90); 32]);
            let rec = ember::dht::publish::SignedRecord::source(
                file_hash,
                [0u8; 32],
                1,
                "big.iso",
                ember::dht::publish::SourceContact {
                    ip: Ipv4Addr::new(81, 7, 8, i),
                    tcp_port: 4662,
                    flags: 0,
                    ..Default::default()
                },
                &sk,
            );
            let mut data = rec.data.clone();
            data.extend_from_slice(&rec.signature);
            ember::dht::search::SearchResultRecord {
                data,
                from_node: ember::dht::EmberNodeId([u8::from(!local); 16]),
                confirmed_by: None,
                from_subnet: (!local).then_some(1),
                confirmed_subnet: None,
                from_local_store: local,
            }
        };
        let mut held: Vec<_> = (1..=20u8).map(|i| record(i, false)).collect();
        held.extend((21..=45u8).map(|i| record(i, true)));

        let sources = parse_ember_source_records(
            &held,
            file_hash,
            None,
            &[0u8; 32],
            &mut crate::types::EmberDiagnostics::default(),
            &mut HashMap::new(),
            &HashSet::new(),
            &mut HashMap::new(),
        );
        assert_eq!(sources.len(), 25 + MAX_UNCONFIRMED_SOURCES_PER_RESPONDER);
        for local in 21..=45u8 {
            assert!(sources.iter().any(|s| s.ip == Ipv4Addr::new(81, 7, 8, local)));
        }
    }

    #[test]
    fn our_own_source_record_is_skipped_by_its_noise_key() {
        let ours = [0x5Cu8; 32];
        let file_hash = [0x61u8; 16];
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x31; 32]);
        let rec = ember::dht::publish::SignedRecord::source(
            file_hash,
            [0u8; 32],
            1,
            "shared.iso",
            ember::dht::publish::SourceContact {
                ip: Ipv4Addr::new(81, 2, 3, 4),
                tcp_port: 4662,
                udp_port: 4672,
                flags: 0,
                noise_pub: ours,
                ..Default::default()
            },
            &sk,
        );
        let mut blob = rec.data.clone();
        blob.extend_from_slice(&rec.signature);
        let held = vec![ember::dht::search::SearchResultRecord {
            data: blob,
            from_node: ember::dht::EmberNodeId([1; 16]),
            confirmed_by: None,
            from_subnet: None,
            confirmed_subnet: None,
            from_local_store: false,
        }];

        let parse = |self_ip: Option<Ipv4Addr>, local: [u8; 32]| {
            let mut noise_keys = HashMap::new();
            let sources = parse_ember_source_records(
                &held,
                file_hash,
                self_ip,
                &local,
                &mut crate::types::EmberDiagnostics::default(),
                &mut noise_keys,
                &HashSet::new(),
                &mut HashMap::new(),
            );
            (sources.len(), noise_keys.len())
        };

        assert_eq!(parse(None, ours), (0, 0), "unknown external IP");
        assert_eq!(
            parse(Some(Ipv4Addr::new(82, 1, 1, 1)), ours),
            (0, 0),
            "stale external IP"
        );
        assert_eq!(parse(None, [0x5Du8; 32]), (1, 1), "a peer's record is kept");
    }
}

#[cfg(test)]
mod ember_keyword_sanitize_tests {
    use super::*;

    fn kw_blob(name: &str) -> ember::dht::search::SearchResultRecord {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let rec = ember::dht::publish::SignedRecord::keyword(
            "holiday",
            [0x11; 16],
            [0u8; 32],
            1234,
            name,
            &sk,
        );
        let mut blob = rec.data.clone();
        blob.extend_from_slice(&rec.signature);
        ember::dht::search::SearchResultRecord {
            data: blob,
            from_node: ember::dht::EmberNodeId([1; 16]),
            confirmed_by: None,
            from_subnet: None,
            confirmed_subnet: None,
            from_local_store: false,
        }
    }

    #[test]
    fn ember_keyword_build_strips_bidi_override_from_name() {
        let blobs = vec![kw_blob("holiday \u{202E}gpj.exe\u{200B}")];
        let results = build_ember_keyword_built(&blobs, &["holiday".to_string()], None).results;
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.file.name, "holiday gpj.exe");
        assert_eq!(r.file.extension, "exe");
    }

    #[test]
    fn ember_keyword_build_drops_names_that_are_only_controls() {
        let blobs = vec![kw_blob("\u{202E}\u{200B}")];
        let results = build_ember_keyword_built(&blobs, &["holiday".to_string()], None).results;
        assert!(results.is_empty());
    }
}

#[cfg(test)]
mod ember_keyword_match_tests {
    use super::*;

    /// A keyword record signed by its own key, filed under `keyword`.
    fn record_under(keyword: &str, file: u8, name: &str) -> ember::dht::search::SearchResultRecord {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[file; 32]);
        let rec = ember::dht::publish::SignedRecord::keyword(keyword, [file; 16], [0u8; 32], 1, name, &sk);
        let mut data = rec.data.clone();
        data.extend_from_slice(&rec.signature);
        ember::dht::search::SearchResultRecord {
            data,
            from_node: ember::dht::EmberNodeId([file; 16]),
            confirmed_by: None,
            from_subnet: Some(u64::from(file)),
            confirmed_subnet: None,
            from_local_store: false,
        }
    }

    fn names(built: &EmberKeywordBuilt) -> Vec<String> {
        let mut names: Vec<String> = built.results.iter().map(|r| r.file.name.clone()).collect();
        names.sort();
        names
    }

    /// Anyone may store a signed record under any key, so a one-word search
    /// keeps only the names that derive the word's key.
    #[test]
    fn a_single_word_search_shows_only_names_filed_under_that_word() {
        let held = vec![
            record_under("ubuntu", 1, "ubuntu-24.04-desktop.iso"),
            record_under("ubuntu", 2, "totally unrelated.exe"),
            record_under("ubuntu", 3, "ubuntux.iso"),
            // The publisher strips a trailing three-letter token as an
            // extension, so it never files a name under it.
            record_under("iso", 4, "debian.iso"),
        ];
        let built = build_ember_keyword_built(&held, &["ubuntu".to_string()], None);
        assert_eq!(names(&built), vec!["ubuntu-24.04-desktop.iso"]);
        let built = build_ember_keyword_built(&held, &["iso".to_string()], None);
        assert!(built.results.is_empty(), "debian.iso was never published under iso");
    }

    /// Every word of an AND query has to be a word of the name, not just a
    /// substring of it — the same test responders order their answers by.
    #[test]
    fn a_multi_word_search_needs_every_word_in_the_name() {
        let held = vec![
            record_under("ubuntu", 1, "ubuntu-server-24.04.iso"),
            record_under("ubuntu", 2, "ubuntu-servers.iso"),
            record_under("ubuntu", 3, "ubuntu desktop.iso"),
            record_under("ubuntu", 4, "server ubuntux.iso"),
        ];
        let keywords = vec!["ubuntu".to_string(), "server".to_string()];
        let built = build_ember_keyword_built(&held, &keywords, None);
        assert_eq!(names(&built), vec!["ubuntu-server-24.04.iso"]);

        // The trailing token counts as a word of the name for a second word,
        // even though the publisher did not file the name under it.
        let keywords = vec!["ubuntu".to_string(), "iso".to_string()];
        let built = build_ember_keyword_built(&held, &keywords, None);
        assert_eq!(built.results.len(), 3);
    }

    /// Only the required side of a boolean query is demanded of every name.
    #[test]
    fn an_or_query_demands_only_the_words_every_match_contains() {
        let held = vec![
            record_under("ubuntu", 1, "ubuntu desktop.iso"),
            record_under("ubuntu", 2, "ubuntu serverx.iso"),
            record_under("ubuntu", 3, "ubuntu minimal.iso"),
        ];
        let expr = crate::search::query::parse("ubuntu (desktop OR serverx)").expect("parses");
        let built = build_ember_keyword_built(&held, &expr.positive_terms(), Some(&expr));
        assert_eq!(names(&built), vec!["ubuntu desktop.iso", "ubuntu serverx.iso"]);
    }

    /// A newer publisher files a decomposed name under the normalised key as
    /// well, and that record has to survive the searcher's check.
    #[test]
    fn a_record_under_the_normalised_key_matches_its_decomposed_name() {
        let normalised = ember::dht::search::compute_keyword_hashes("café")[0].1.clone();
        let held = vec![record_under(&normalised, 1, "Cafe\u{301} del Mar.mp3")];
        let built = build_ember_keyword_built(&held, &["Café".to_string()], None);
        assert_eq!(built.results.len(), 1);

        // Typed decomposed, the search walks the normalised key and the typed
        // one, and accepts a record under either.
        let typed = "cafe\u{301}";
        let held = vec![
            record_under(&normalised, 1, "Cafe\u{301} del Mar.mp3"),
            record_under(typed, 2, "Cafe\u{301} Society.mp3"),
        ];
        let built = build_ember_keyword_built(&held, &[typed.to_string()], None);
        assert_eq!(built.results.len(), 2);
    }

    /// The companion walk is only for a query whose typed spelling hashes
    /// elsewhere, and it sends the typed spelling's other words — none for a
    /// query with an `OR`.
    #[test]
    fn only_a_query_that_hashes_two_ways_gets_a_second_walk() {
        use ember::dht::search::keyword_hash;
        let walked = |q: &str| ember::dht::search::compute_keyword_hashes(q)[0].0;
        for query in ["ubuntu", "Ubuntu Server", "café"] {
            assert_eq!(
                ember_spelling_walk_keys(&[query.to_string()], None, &walked(query)),
                None,
                "{query}"
            );
        }
        let typed = "cafe\u{301}";
        assert_eq!(
            ember_spelling_walk_keys(&[typed.to_string()], None, &walked(typed)),
            Some((keyword_hash(typed), vec![]))
        );

        let keywords = vec!["cafe\u{301}del".to_string(), "mar".to_string()];
        let query = keywords.join(" ");
        assert_eq!(
            ember_spelling_walk_keys(&keywords, None, &walked(&query)),
            Some((keyword_hash("cafe\u{301}del"), vec![keyword_hash("mar")])),
            "the typed spelling's own extra keys, not the normalised ones"
        );
        let expr = crate::search::query::parse("cafe\u{301}del (mar OR sol)").expect("parses");
        let (_, extras) = ember_spelling_walk_keys(&expr.positive_terms(), Some(&expr), &walked(&query))
            .expect("hashes two ways");
        assert!(extras.is_empty(), "an OR sends no keys to intersect on");
    }

    /// Two words, one of them spelled differently in the name than in the query,
    /// in each direction. The key's word is matched in either spelling, and so
    /// is the filter run on the rest of the query.
    #[test]
    fn a_multi_word_search_matches_across_spellings_both_ways() {
        let normalised = |w: &str| ember::dht::search::compute_keyword_hashes(w)[0].1.clone();
        let decomposed_name = "Cafe\u{301} del Mar.mp3";
        let held = vec![record_under(&normalised("café"), 1, decomposed_name)];
        let built = build_ember_keyword_built(&held, &["café".to_string(), "del".to_string()], None);
        assert_eq!(names(&built), vec![decomposed_name], "composed query, decomposed name");

        let composed_name = "Café del Mar.mp3";
        let held = vec![record_under("café", 2, composed_name)];
        let keywords = vec!["cafe\u{301}".to_string(), "del".to_string()];
        let built = build_ember_keyword_built(&held, &keywords, None);
        assert_eq!(names(&built), vec![composed_name], "decomposed query, composed name");

        let expr = crate::search::query::parse("cafe\u{301} del").expect("parses");
        let built = build_ember_keyword_built(&held, &expr.positive_terms(), Some(&expr));
        assert_eq!(built.results.len(), 1, "a boolean query matches across spellings too");

        // An excluded term is excluded in either spelling.
        let expr = crate::search::query::parse("del -cafe\u{301}").expect("parses");
        let held = vec![record_under("del", 3, composed_name)];
        let built = build_ember_keyword_built(&held, &expr.positive_terms(), Some(&expr));
        assert!(built.results.is_empty());
    }

    /// A name shortened to fit its record may have lost the word its key was
    /// derived from. A publisher before 1.7.4 derived keys from the full name,
    /// so the searcher does not hold such a record to the derivation or to the
    /// key's own word; every other required word still has to be in what is
    /// left.
    #[test]
    fn a_record_whose_name_was_shortened_to_fit_is_not_dropped() {
        let long = |tail: &str| {
            let filler: String = (0..400).map(|i| format!("w{i:03} ")).collect();
            let mut name = format!("ubuntu {filler}");
            while name.len() < 1500 {
                name.push_str("pad ");
            }
            name.push_str(tail);
            name
        };
        let held = vec![
            record_under("serverlongword", 1, &long("serverlongword.iso")),
            record_under("ubuntu", 2, &long("x.iso")),
        ];
        for record in &held {
            let body = record.data.len() - 64;
            assert!(ember::dht::publish::record_name_may_be_clamped(body), "the name was clamped");
        }
        let built = build_ember_keyword_built(&held, &["serverlongword".to_string()], None);
        assert_eq!(built.results.len(), 1, "filed under a word the cut removed");
        let built = build_ember_keyword_built(&held, &["ubuntu".to_string(), "w001".to_string()], None);
        assert_eq!(built.results.len(), 1, "a word left in the name is found");
        let built = build_ember_keyword_built(&held, &["ubuntu".to_string(), "missing".to_string()], None);
        assert!(built.results.is_empty(), "the words left in the name are still required");

        // A name that fits is held to the derivation as before.
        let short = vec![record_under("serverlongword", 3, "ubuntu.iso")];
        assert!(build_ember_keyword_built(&short, &["serverlongword".to_string()], None)
            .results
            .is_empty());
    }

    /// One node plants five records under a fake digest ahead of six real
    /// publishers on four storers. Each streaming rebuild counts what has been
    /// gathered so far, so once the real publishers arrive the row carries their
    /// six — never the five and the six added together.
    #[test]
    fn streamed_counts_never_exceed_a_rebuild_of_what_was_gathered() {
        let fake = [0xEEu8; 32];
        let real = [0x77u8; 32];
        let file = [0xF1u8; 16];
        let blob = |seed: u16, digest: [u8; 32]| {
            let mut key = [0x5Au8; 32];
            key[..2].copy_from_slice(&seed.to_le_bytes());
            let sk = ed25519_dalek::SigningKey::from_bytes(&key);
            let rec = ember::dht::publish::SignedRecord::keyword("ubuntu", file, digest, 1, "ubuntu.iso", &sk);
            let mut data = rec.data.clone();
            data.extend_from_slice(&rec.signature);
            data
        };
        let from = |node: u8, data: Vec<u8>| ember::dht::search::SearchResultRecord {
            data,
            from_node: ember::dht::EmberNodeId([node; 16]),
            confirmed_by: None,
            from_subnet: Some(u64::from(node)),
            confirmed_subnet: None,
            from_local_store: false,
        };
        let keywords = vec!["ubuntu".to_string()];
        let (mut sm, sid) = one_walk();
        let mut stream = HashSet::new();
        let gather = |sm: &mut ember::dht::search::SearchManager, records: Vec<_>| {
            sm.get_mut(sid).unwrap().results.extend(records);
        };

        gather(&mut sm, (0..5).map(|i| from(9, blob(1000 + i, fake))).collect());
        let first = stream_once(&mut sm, sid, &mut stream, &keywords, None);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].availability, 5);

        gather(
            &mut sm,
            [1u8, 2, 3, 4, 1, 2]
                .into_iter()
                .enumerate()
                .map(|(i, node)| from(node, blob(i as u16, real)))
                .collect(),
        );
        let second = stream_once(&mut sm, sid, &mut stream, &keywords, None);
        assert_eq!(second.len(), 1, "the row's publishers changed");
        assert_eq!(second[0].availability, 6, "the real digest's six, not 5 + 6");

        let closing = build_ember_keyword_built(&sm.get(sid).unwrap().results, &keywords, None);
        assert_eq!(closing.results[0].availability, second[0].availability);

        assert!(
            stream_once(&mut sm, sid, &mut stream, &keywords, None).is_empty(),
            "nothing new, nothing to send"
        );
    }

    /// A value walk to push gathered records into, as a running search holds
    /// them.
    fn one_walk() -> (ember::dht::search::SearchManager, u32) {
        let rt = ember::dht::routing::RoutingTable::new(ember::dht::EmberNodeId([0; 16]), false);
        let mut sm = ember::dht::search::SearchManager::new();
        let sid = sm
            .start_find_value(ember::dht::EmberNodeId([1; 16]), vec![], &rt)
            .expect("slot");
        (sm, sid)
    }

    /// The rows one streaming rebuild of `sid` sends, as the search tick
    /// builds them.
    fn stream_once(
        sm: &mut ember::dht::search::SearchManager,
        sid: u32,
        stream: &mut HashSet<EmberStreamMark>,
        keywords: &[String],
        query_expr: Option<&crate::search::query::QueryExpr>,
    ) -> Vec<SearchResult> {
        let reader = EmberRecordReader::new(keywords, query_expr);
        let search = sm.get_mut(sid).unwrap();
        read_ember_keyword_records(search, &reader);
        ember_stream_rows(stream, fold_ember_keyword_rows(ember_keyword_readings(search)))
    }

    fn two_linked_walks() -> (ember::dht::search::SearchManager, u32, u32) {
        use ember::dht::search::{Companion, SearchManager};
        let rt = ember::dht::routing::RoutingTable::new(ember::dht::EmberNodeId([0; 16]), false);
        let mut sm = SearchManager::new();
        let main = sm
            .start_find_value(ember::dht::EmberNodeId([1; 16]), vec![], &rt)
            .expect("slot");
        let walk = sm
            .start_find_value(ember::dht::EmberNodeId([2; 16]), vec![], &rt)
            .expect("slot");
        sm.get_mut(main).unwrap().companion = Companion::Running(walk);
        sm.get_mut(walk).unwrap().companion = Companion::FeedsInto(main);
        (sm, main, walk)
    }

    /// A finished search waits while its companion walks, then reports with
    /// the companion's records.
    #[test]
    fn a_search_is_held_for_its_companion_and_then_takes_its_records() {
        let (mut sm, main, walk) = two_linked_walks();
        sm.get_mut(walk)
            .unwrap()
            .results
            .push(record_under("ubuntu", 1, "ubuntu.iso"));

        assert_eq!(settle_ember_companion(&mut sm, main, true), CompanionStep::Wait);
        assert_eq!(settle_ember_companion(&mut sm, walk, false), CompanionStep::Wait);
        assert_eq!(settle_ember_companion(&mut sm, walk, true), CompanionStep::HandedTo(main));
        assert!(sm.get(walk).is_none(), "the companion is gone once it has handed over");
        assert_eq!(sm.get(main).unwrap().results.len(), 1);
        assert_eq!(settle_ember_companion(&mut sm, main, true), CompanionStep::Report);
    }

    /// A companion whose search was cancelled is dropped at the next sweep,
    /// finished or not, rather than walking on for nobody.
    #[test]
    fn a_companion_of_a_cancelled_search_is_dropped() {
        let (mut sm, main, walk) = two_linked_walks();
        sm.remove(main);
        assert_eq!(settle_ember_companion(&mut sm, walk, false), CompanionStep::Dropped);
        assert!(sm.get(walk).is_none());

        // A search whose companion vanished some other way is not held for it.
        let (mut sm, main, walk) = two_linked_walks();
        sm.remove(walk);
        assert_eq!(settle_ember_companion(&mut sm, main, true), CompanionStep::Report);
    }

    /// Keys are derived from the name the record will sign, so a word cut off
    /// to fit is not published as a key the name cannot vouch for.
    #[test]
    fn keywords_come_from_the_name_as_the_record_signs_it() {
        let filler: String = (0..400).map(|i| format!("w{i:03} ")).collect();
        let name = format!("ubuntu {filler}finalword.iso");
        let signed = ember::dht::publish::keyword_record_signed_name(&name, None);
        assert!(signed.len() < name.len());
        let keywords = ember::dht::search::ember_publish_keywords(signed);
        assert!(keywords.contains(&"ubuntu".to_string()));
        assert!(!keywords.contains(&"finalword".to_string()));
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let rec = ember::dht::publish::SignedRecord::keyword("ubuntu", [1; 16], [0; 32], 1, &name, &sk);
        assert_eq!(rec.file_name, signed, "the record signs exactly that name");
        let short = "ubuntu server.iso";
        assert_eq!(ember::dht::publish::keyword_record_signed_name(short, None), short);
    }

    /// A lookup timeout is charged only to the table entry at the address and
    /// key that were dialled. A `FOUND_NODE` naming a real node's id at an
    /// address that goes nowhere must not cost that node its place.
    #[test]
    fn a_bad_referral_does_not_fault_the_honest_contact_it_names() {
        let held = ember::dht::EmberContact {
            node_id: ember::dht::EmberNodeId([0x42; 16]),
            addr: "81.2.3.4:4672".parse().unwrap(),
            noise_pub: [0x11; 32],
            ed25519_pub: [0x11; 32],
            last_seen: 1_000,
            failed_queries: 0,
        };
        assert!(ember_search_fault_lands(&held, &held.clone()));
        let elsewhere = ember::dht::EmberContact {
            addr: "203.0.113.9:4672".parse().unwrap(),
            last_seen: 0,
            ..held.clone()
        };
        assert!(!ember_search_fault_lands(&held, &elsewhere), "another address");
        let other_key = ember::dht::EmberContact {
            noise_pub: [0x22; 32],
            ..held.clone()
        };
        assert!(!ember_search_fault_lands(&held, &other_key), "another key");
        let unverified = ember::dht::EmberContact { last_seen: 0, ..held.clone() };
        assert!(!ember_search_fault_lands(&unverified, &unverified.clone()), "a lead");
    }

    /// A record of one file filed under `ubuntu` by publisher `publisher`.
    fn claim(
        publisher: u8,
        name: &str,
        size: u64,
        media: Option<&crate::types::MediaMetadata>,
    ) -> ember::dht::search::SearchResultRecord {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[publisher; 32]);
        let rec = ember::dht::publish::SignedRecord::keyword_with_media(
            "ubuntu", [0xF7; 16], [0u8; 32], size, name, media, &sk,
        );
        let mut data = rec.data.clone();
        data.extend_from_slice(&rec.signature);
        ember::dht::search::SearchResultRecord {
            data,
            from_node: ember::dht::EmberNodeId([publisher; 16]),
            confirmed_by: None,
            from_subnet: Some(u64::from(publisher)),
            confirmed_subnet: None,
            from_local_store: false,
        }
    }

    /// Each size of a file is a row of its own, counting the publishers giving
    /// it and named as most of them name it, a tie going to the first. A row
    /// is first streamed once two publishers give it or at the rebuild after
    /// the one that first built it, so a lone first record does not decide the
    /// name the page keeps; the closing batch has every row.
    #[test]
    fn a_rows_name_and_size_are_the_ones_most_publishers_give() {
        let keywords = vec!["ubuntu".to_string()];
        let (mut sm, sid) = one_walk();
        let mut stream = HashSet::new();
        let media = crate::types::MediaMetadata {
            duration: Some(60),
            ..Default::default()
        };
        let mut gather = |sm: &mut ember::dht::search::SearchManager, records: Vec<_>| {
            sm.get_mut(sid).unwrap().results.extend(records);
            let mut batch = stream_once(sm, sid, &mut stream, &keywords, None);
            batch.sort_by_key(|row| row.file.size);
            batch
                .into_iter()
                .map(|row| (row.file.size, row.file.name, row.availability, row.media))
                .collect::<Vec<_>>()
        };

        let first = gather(&mut sm, vec![claim(1, "ubuntu typo.iso", 100, None)]);
        assert!(first.is_empty(), "one record does not name a row yet");

        let second = gather(
            &mut sm,
            vec![
                claim(2, "ubuntu 24.04.iso", 100, None),
                claim(3, "ubuntu 24.04.iso", 100, Some(&media)),
                claim(4, "ubuntu setup.exe", 10, None),
            ],
        );
        assert_eq!(
            second,
            vec![(100, "ubuntu 24.04.iso".to_string(), 3, Some(media.clone()))],
            "first sent named as most of its publishers name it; the new size waits"
        );

        let third = gather(&mut sm, vec![]);
        assert_eq!(
            third,
            vec![(10, "ubuntu setup.exe".to_string(), 1, None)],
            "a held row goes out at the next rebuild"
        );
        assert!(gather(&mut sm, vec![]).is_empty(), "nothing moved");

        let closing = build_ember_keyword_built(&sm.get(sid).unwrap().results, &keywords, None);
        let mut rows: Vec<_> = closing
            .results
            .iter()
            .map(|row| (row.file.size, row.file.name.clone(), row.file.extension.clone(), row.file_type.clone()))
            .collect();
        rows.sort();
        let iso = crate::search::index::infer_file_type("iso");
        let exe = crate::search::index::infer_file_type("exe");
        assert_eq!(
            rows,
            vec![
                (10, "ubuntu setup.exe".to_string(), "exe".to_string(), exe),
                (100, "ubuntu 24.04.iso".to_string(), "iso".to_string(), iso),
            ]
        );

        let row = |held: &[ember::dht::search::SearchResultRecord]| {
            let built = build_ember_keyword_built(held, &keywords, None);
            assert_eq!(built.results.len(), 1);
            built.results.into_iter().next().unwrap()
        };
        let tie = row(&[claim(1, "ubuntu a.iso", 100, None), claim(2, "ubuntu b.iso", 100, None)]);
        assert_eq!(tie.file.name, "ubuntu a.iso");
        // One publisher's several records are one vote.
        let repeats = row(&[
            claim(1, "ubuntu a.iso", 100, None),
            claim(1, "ubuntu b.iso", 100, None),
            claim(1, "ubuntu c.iso", 100, None),
            claim(2, "ubuntu b.iso", 100, None),
        ]);
        assert_eq!(repeats.file.name, "ubuntu a.iso");
    }

    /// A rebuild reads only the records added since the last one, and reading
    /// them is what the closing build would make of them.
    #[test]
    fn a_streaming_rebuild_reads_each_record_once() {
        let keywords = vec!["ubuntu".to_string()];
        let (mut sm, sid) = one_walk();
        let reader = EmberRecordReader::new(&keywords, None);
        let parsed = std::cell::Cell::new(0usize);
        let parse = |blob: &[u8]| {
            parsed.set(parsed.get() + 1);
            ember::dht::publish::SignedRecord::from_value_blob(blob)
        };
        let search = sm.get_mut(sid).unwrap();
        search.results.extend([
            record_under("ubuntu", 1, "ubuntu.iso"),
            record_under("ubuntu", 2, "unrelated.iso"),
        ]);
        read_ember_keyword_records_with(search, &reader, parse);
        read_ember_keyword_records_with(search, &reader, parse);
        assert_eq!(parsed.get(), 2);
        search.results.push(record_under("ubuntu", 3, "ubuntu server.iso"));
        read_ember_keyword_records_with(search, &reader, parse);
        assert_eq!(parsed.get(), 3, "only the new record");

        let streamed = fold_ember_keyword_rows(ember_keyword_readings(search));
        let closing = build_ember_keyword_built(&search.results, &keywords, None);
        let names = |built: &EmberKeywordBuilt| {
            let mut names: Vec<_> = built.results.iter().map(|r| r.file.name.clone()).collect();
            names.sort();
            names
        };
        assert_eq!(names(&streamed), vec!["ubuntu server.iso", "ubuntu.iso"]);
        assert_eq!(names(&streamed), names(&closing));
    }

    /// The frames a walk sends: a pinned session peer is asked the whole query
    /// wherever it sorts; a node outside the k closest when first asked gets
    /// the primary key alone, and so do its pages.
    #[test]
    fn far_hops_hear_only_the_primary_key_but_pinned_peers_hear_it_all() {
        use ember::dht::{messages, EmberContact, EmberNodeId};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let target = EmberNodeId(ember::dht::search::keyword_hash("ubuntu"));
        let at = |distance: u8, last_seen: i64, subnet: u8| EmberContact {
            node_id: EmberNodeId(std::array::from_fn(|i| {
                target.0[i] ^ if i == 0 { distance } else { 0 }
            })),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 1, subnet, 1)), 4662),
            noise_pub: [distance; 32],
            ed25519_pub: [distance; 32],
            last_seen,
            failed_queries: 0,
        };
        let now = chrono::Utc::now().timestamp();
        let mut rt = ember::dht::routing::RoutingTable::new(EmberNodeId([0; 16]), false);
        let seeds: Vec<EmberContact> = (0..ember::dht::K_BUCKET_SIZE as u8)
            .map(|i| at(0x40 + i, now, i))
            .collect();
        for seed in &seeds {
            rt.add_contact(seed.clone());
        }
        let far_seeds: Vec<EmberNodeId> = seeds[seeds.len() - 4..].iter().map(|c| c.node_id).collect();
        let pin = EmberContact {
            node_id: EmberNodeId(std::array::from_fn(|i| target.0[i] ^ 0xFF)),
            ..at(0xFF, now, 200)
        };
        let extra = [0x22u8; 16];
        let constraints = messages::ValueConstraints {
            min_size: Some(1024),
            ..Default::default()
        };
        let mut sm = ember::dht::search::SearchManager::new();
        let sid = sm.start_find_value(target, vec![extra], &rt).expect("slot");
        assert_eq!(sm.seed_extra_contacts(sid, vec![pin.clone()]), 1);
        let mut dht = ember::dht::engine::EmberDht::new([9; 32], [9; 32], false);
        let mut sent = |query: &ember::dht::search::QueryTarget| {
            let (_, frame) = ember_search_query_frame(
                &mut dht,
                target,
                query.find_node,
                &[extra],
                &constraints,
                (query.start_position, query.resume_after, query.narrow),
            );
            match messages::decode_message(&frame, true, &[9; 32]).expect("decodes").payload {
                messages::DhtPayload::FindValue { keys, constraints, start_position, .. } => {
                    (keys, constraints, start_position)
                }
                other => panic!("expected FIND_VALUE, got {other:?}"),
            }
        };
        let whole = (vec![target.0, extra], constraints.clone());
        let primary_only = (vec![target.0], messages::ValueConstraints::default());

        let search = sm.get_mut(sid).unwrap();
        let mut leads: Vec<EmberContact> = (2..6).map(|d| at(d, 0, 100 + d)).collect();
        let (mut far_first, mut far_page) = (false, false);
        for _ in 0..64 {
            let batch = search.next_to_query();
            if batch.is_empty() {
                break;
            }
            for query in batch {
                let (keys, got, start) = sent(&query);
                let node = query.contact.node_id;
                let (records, page) = if node == pin.node_id {
                    assert_eq!((keys, got), whole, "a pinned peer far from the key");
                    (vec![], None)
                } else if far_seeds.contains(&node) {
                    assert_eq!((keys, got), primary_only, "a far hop, start {start}");
                    if start == 0 {
                        far_first = true;
                        let blob = record_under("ubuntu", 7, "ubuntu.iso").data;
                        (vec![blob], Some(ember::dht::search::ValuePage { next_position: 1, total_available: 9 }))
                    } else {
                        far_page = true;
                        (vec![], None)
                    }
                } else {
                    assert_eq!((keys, got), whole, "a hop near the key");
                    (vec![], None)
                };
                search.process_response(query.request_id, &node, std::mem::take(&mut leads), records, page);
            }
        }
        assert!(far_first && far_page, "the walk reached a far hop and paged it");
    }

    /// The typed-spelling walk is on the search's own word, and no branch walk
    /// repeats a key another walk of the search takes.
    #[test]
    fn the_second_spelling_walk_follows_the_searchs_own_word() {
        use ember::dht::search::{compute_keyword_hashes, keyword_hash};
        let plan = |query: &str| {
            let expr = crate::search::query::parse(query).expect("parses");
            ember_walk_plan(&expr.positive_terms(), Some(&expr))
        };
        // `abcde` and the normalised `café` tie on length, so the search walks
        // `abcde`; typed, `cafe\u{301}` is the longer word, but it is another
        // branch's.
        let mixed = plan("abcde OR cafe\u{301}");
        assert_eq!(mixed.companion, None, "abcde has one spelling");
        assert_eq!(
            mixed.branches,
            vec![
                (compute_keyword_hashes("café")[0].0, vec![]),
                (keyword_hash("cafe\u{301}"), vec![]),
            ]
        );

        let own = plan("cafe\u{301}del OR mar");
        assert_eq!(own.companion, Some((keyword_hash("cafe\u{301}del"), vec![])));
        assert_eq!(own.branches, vec![(keyword_hash("mar"), vec![])]);
    }

    /// However many branches and spellings a query has, one search runs a
    /// bounded number of extra walks, each on a key of its own.
    #[test]
    fn a_search_runs_a_bounded_number_of_extra_walks() {
        let query = "ubuntu OR cafe\u{301} OR nai\u{308}ve OR re\u{301}sume\u{301} OR jalapen\u{303}o";
        let expr = crate::search::query::parse(query).expect("parses");
        let plan = ember_walk_plan(&expr.positive_terms(), Some(&expr));
        let keys: Vec<[u8; 16]> = plan.keys().collect();
        assert_eq!(keys.len(), MAX_EMBER_FEEDING_WALKS);
        let distinct: HashSet<[u8; 16]> = keys.iter().copied().collect();
        assert_eq!(distinct.len(), keys.len());
    }

    /// With no term common to every match, a search walks the longest term,
    /// and each `OR` branch that does not contain it gets a walk of its own —
    /// under its other terms as extra keys, a branch's every match carrying
    /// them — up to three branches in all.
    #[test]
    fn each_or_branch_the_search_key_misses_gets_a_walk() {
        use ember::dht::search::keyword_hash;
        let walks = |query: &str| {
            let expr = crate::search::query::parse(query).expect("parses");
            ember_walk_plan(&expr.positive_terms(), Some(&expr)).branches
        };
        assert!(walks("ubuntu").is_empty());
        assert!(walks("ubuntu (desktop OR server)").is_empty(), "ubuntu is in every match");
        assert_eq!(walks("ubuntu OR debian"), vec![(keyword_hash("debian"), vec![])]);
        assert_eq!(walks("(ubuntu server) OR debian"), vec![(keyword_hash("debian"), vec![])]);
        assert_eq!(
            walks("alpha OR (gamma delta)"),
            vec![(keyword_hash("gamma"), vec![keyword_hash("delta")])]
        );
        assert_eq!(
            walks("aaaa OR (bbbb cccc) OR (bbbb dddd)"),
            vec![(keyword_hash("bbbb"), vec![])],
            "branches sharing a key share a walk, intersecting on nothing they do not all carry"
        );
        assert_eq!(walks("aaaa OR bbbb OR cccc OR dddd OR eeee").len(), 2);

        let normalised = ember::dht::search::compute_keyword_hashes("café")[0].0;
        assert_eq!(
            walks("ubuntu OR cafe\u{301}"),
            vec![(normalised, vec![]), (keyword_hash("cafe\u{301}"), vec![])],
            "a branch whose spelling hashes two ways is walked under both"
        );
    }

    /// Rows found under a branch's key are kept like those under the search's
    /// own key.
    #[test]
    fn records_found_by_an_or_branch_walk_are_kept() {
        let held = vec![
            record_under("ubuntu", 1, "ubuntu.iso"),
            record_under("debian", 2, "debian.iso"),
            record_under("fedora", 3, "fedora debian.iso"),
        ];
        let expr = crate::search::query::parse("ubuntu OR debian").expect("parses");
        let built = build_ember_keyword_built(&held, &expr.positive_terms(), Some(&expr));
        assert_eq!(names(&built), vec!["debian.iso", "ubuntu.iso"]);
    }

    /// A search waits for every walk feeding it, and each hands its records
    /// over without disturbing the others' links.
    #[test]
    fn a_search_waits_for_its_branch_walks_and_its_companion() {
        let (mut sm, main, walk) = two_linked_walks();
        let rt = ember::dht::routing::RoutingTable::new(ember::dht::EmberNodeId([0; 16]), false);
        let branch = sm
            .start_find_value(ember::dht::EmberNodeId([3; 16]), vec![], &rt)
            .expect("slot");
        sm.get_mut(branch).unwrap().companion = ember::dht::search::Companion::FeedsInto(main);
        sm.get_mut(main).unwrap().branch_walks.push(branch);
        sm.get_mut(branch)
            .unwrap()
            .results
            .push(record_under("debian", 2, "debian.iso"));
        assert_eq!(ember_feeding_walks(&sm, main), vec![walk, branch]);

        assert_eq!(settle_ember_companion(&mut sm, main, true), CompanionStep::Wait);
        assert_eq!(settle_ember_companion(&mut sm, branch, true), CompanionStep::HandedTo(main));
        let search = sm.get(main).unwrap();
        assert_eq!(search.results.len(), 1);
        assert!(search.branch_walks.is_empty());
        assert_eq!(search.companion, ember::dht::search::Companion::Running(walk), "the companion still runs");
        assert_eq!(settle_ember_companion(&mut sm, main, true), CompanionStep::Wait);
        assert_eq!(settle_ember_companion(&mut sm, walk, true), CompanionStep::HandedTo(main));
        assert_eq!(settle_ember_companion(&mut sm, main, true), CompanionStep::Report);
    }

    /// The progress figure counts the rows that reached the page — what the
    /// emit returned as accepted, and rows found again — credited to the lookup
    /// running for that request. A row the emit's filters dropped is not
    /// returned, and not counted.
    #[test]
    fn rows_shown_count_toward_their_own_lookups_progress() {
        let row = |hash: &str| {
            let mut row = ember_keyword_row([0; 16], 1, "x.iso".to_string(), None, 1, String::new());
            row.file.hash = hash.to_string();
            row
        };
        let lookup = |request_id: u64| EmberKeywordSearch {
            request_id,
            keywords: vec!["ubuntu".to_string()],
            query_expr: None,
            file_type_filter: None,
            min_size: None,
            max_size: None,
            file_extension: None,
            min_availability: None,
            last_streamed_count: 0,
            streamed_files: HashSet::new(),
            streamed_publishers: HashSet::new(),
        };
        let mut searches = HashMap::from([(1u32, lookup(10)), (2u32, lookup(20))]);
        // Built: aa, bb, dd. The emit's filters dropped dd.
        let emitted = vec![row("aa"), row("bb")];
        let resights = vec![row("aa"), row("ee")];
        note_ember_rows_shown(&mut searches, 20, &emitted, &resights);
        note_ember_rows_shown(&mut searches, 99, &[row("cc")], &[]);
        assert!(searches[&1].streamed_files.is_empty());
        let mut counted: Vec<_> = searches[&2].streamed_files.iter().cloned().collect();
        counted.sort();
        assert_eq!(counted, vec!["aa", "bb", "ee"], "dd, filtered out, is not counted");
    }
}
