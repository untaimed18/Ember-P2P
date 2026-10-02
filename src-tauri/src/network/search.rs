//! Search lifecycle: search legs, result noting and filtering, enrichment,
//! and finishing or cancelling a search.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// Mirrors `MAX_UDP_SOURCE_QUEUE`. Without this cap a single
/// `start_search` call enqueues one packet per known server, so a user
/// who imported a 5000-entry server.met would buffer 5000 packets and
/// drain at one packet per `udp_search_timer` tick (~750 ms each), i.e.
/// over an hour of useless trailing search traffic. The drained packet
/// is small (~50 B), so 500 ≈ 25 KB peak, comfortably under any
/// realistic working-set memory budget while letting eMule's typical
/// 100–200 servers fit without truncation.
pub(super) const MAX_UDP_SEARCH_QUEUE: usize = 500;

/// Extra safety margin (seconds) added on top of the queued-packet drain
/// estimate to compute `ActiveSearchRequest::udp_search_deadline`. Covers
/// the post-drain grace window (`search_timeout_secs / 10`, clamped 10-30s)
/// plus headroom for a few of its resets by legitimately slow stragglers
/// before the hard deadline steps in.
pub(super) const UDP_SEARCH_HARD_DEADLINE_BUFFER_SECS: i64 = 90;

/// Backstop on the UDP global sweep: stop querying further servers once the
/// replies *from that sweep* have summed to this many sources. Counts are
/// per-result FT_SOURCES, spam-capped at 5 (eMule `AddResultCount`), so this is
/// roughly 200–1000 distinct files depending on how well-sourced they are.
///
/// Two things about this number are deliberate, because getting either wrong is
/// what made a "Global" search stop being global.
///
/// It is a *backstop*, not the thing that normally ends the sweep. The sweep's
/// real limits are the 750 ms send throttle, the post-drain grace period and
/// `udp_search_deadline`; this only exists so a query that is pulling in
/// thousands of sources does not keep working through a 500-entry server list
/// for results nobody will scroll to. At 100 — where it used to sit — it was
/// the *first* limit to fire rather than the last, and it ended the sweep after
/// twenty-odd files.
///
/// And it counts only what the UDP leg itself brought back. It used to be one
/// counter shared with the TCP leg, which is the same bug in a more damaging
/// form: the connected server answers in a single ~200-row batch on a 2 s
/// timer, while UDP leaves at one packet per 750 ms — so the first TCP reply
/// spent the whole budget before three of the other servers had been asked, and
/// `stop_ed2k_udp_search_if_capped` then cleared the rest of the queue. A global
/// search reached two or three of a hundred servers. What the connected server
/// indexes says nothing about what the others do; that is the entire reason the
/// global leg exists.
pub(super) const MAX_UDP_SEARCH_SOURCES: u32 = 1_000;
pub(super) const ED2K_SEARCH_SOURCE_CAP: u32 = 5;

/// `OP_QUERY_MORE_RESULT` pages we will ask the connected server for, on top of
/// the first batch: eMule's `MAX_MORE_SEARCH_REQ` (`Opcodes.h:61`).
pub(super) const MAX_SERVER_MORE_REQUESTS: u8 = 5;

/// How long after a page that flagged more results the next one is asked for.
///
/// eMule asks only when the user presses "More" (`SearchResultsWnd.cpp:1266`),
/// so a server never sees a page requested in the same instant the last one
/// arrived. Asking automatically is ours; doing it at that pace is not.
pub(super) const SERVER_MORE_RESULTS_DELAY: std::time::Duration =
    std::time::Duration::from_secs(5);

/// Whether a server page earns a request for the next one: the server set
/// its "more results" byte (`SearchList.cpp:264-281`), fewer than
/// `MAX_SERVER_MORE_REQUESTS` pages have been asked for
/// (`SearchResultsWnd.cpp:463`), and the search is still under its result cap.
pub(super) fn server_should_ask_for_more(
    server_has_more: bool,
    more_requests_sent: u8,
    under_result_cap: bool,
) -> bool {
    server_has_more && under_result_cap && more_requests_sent < MAX_SERVER_MORE_REQUESTS
}

#[cfg(test)]
mod server_more_results_tests {
    use super::{server_should_ask_for_more, MAX_SERVER_MORE_REQUESTS};

    #[test]
    fn only_a_page_the_server_flagged_earns_another() {
        assert!(server_should_ask_for_more(true, 0, true));
        assert!(!server_should_ask_for_more(false, 0, true), "a full page alone is not a flag");
    }

    #[test]
    fn the_follow_ups_stop_at_emules_cap_and_the_result_ceiling() {
        assert!(server_should_ask_for_more(true, MAX_SERVER_MORE_REQUESTS - 1, true));
        assert!(!server_should_ask_for_more(true, MAX_SERVER_MORE_REQUESTS, true));
        assert!(!server_should_ask_for_more(true, 0, false));
    }
}

/// Whether the UDP global-search leg should be force-completed this tick.
/// True once the post-drain quiet-period grace expires (`server_udp_search_age`
/// exceeds `udp_grace_secs` — this counter resets on every non-empty
/// `SearchResult` batch, letting a genuinely slow server keep contributing)
/// OR once `now` reaches the absolute `udp_search_deadline` set when the leg
/// was queued, whichever comes first. The deadline is what actually bounds a
/// server (or spoofed sender) that keeps trickling results forever.
pub(super) fn udp_search_leg_should_complete(
    server_udp_search_age: u32,
    udp_grace_secs: u64,
    now: i64,
    udp_search_deadline: i64,
) -> bool {
    let grace_expired = u64::from(server_udp_search_age) > udp_grace_secs;
    let hard_deadline_passed = now >= udp_search_deadline;
    grace_expired || hard_deadline_passed
}

/// How many 2-second `server_timer` ticks before the TCP search age expires.
/// Floor 30s (the historic bound); cap 60s so a 600s user timeout does not
/// leave a silent server leg hanging for minutes.
pub(super) fn server_search_age_limit(search_timeout_secs: u64) -> u32 {
    const TICK_SECS: u64 = 2;
    let wait_secs = (search_timeout_secs / 10).clamp(30, 60);
    (wait_secs / TICK_SECS).saturating_sub(1) as u32
}

#[cfg(test)]
mod server_search_age_limit_tests {
    use super::server_search_age_limit;

    #[test]
    fn tcp_age_scales_between_thirty_and_sixty_seconds() {
        // Comparison is `age > limit` on 2s ticks, so 14 → 30s, 29 → 60s.
        assert_eq!(server_search_age_limit(30), 14);
        assert_eq!(server_search_age_limit(300), 14);
        assert_eq!(server_search_age_limit(450), 21);
        assert_eq!(server_search_age_limit(600), 29);
        assert_eq!(server_search_age_limit(10_000), 29);
    }
}

/// Which search expression the connected server is asked first, and which — if
/// any — is queued to follow it.
///
/// A related search has two questions for the one server it can put them to:
/// the keyword query derived from the seed's filename, and eMule's co-share
/// request for the seed hashes. A connection carries one search at a time, so
/// they are sent in sequence; the keyword query leads because it is the half
/// the user can see in the search box. Only when there are no keywords to send
/// at all — a file named `S01E02.mkv` is all marker and no title — does the
/// co-share request carry the whole search.
pub(super) fn server_search_phases(
    keyword_expr: &[u8],
    co_share_expr: Option<Vec<u8>>,
    has_keyword_query: bool,
) -> (Vec<u8>, Option<Vec<u8>>) {
    match co_share_expr {
        Some(co_share) if has_keyword_query => (keyword_expr.to_vec(), Some(co_share)),
        Some(co_share) => (co_share, None),
        None => (keyword_expr.to_vec(), None),
    }
}

#[cfg(test)]
mod server_search_phases_tests {
    use super::server_search_phases;

    const KEYWORD: &[u8] = b"keyword-expr";
    const CO_SHARE: &[u8] = b"co-share-expr";

    /// The bug this guards: a related search on a file with a usable title
    /// asked the connected server *only* the co-share question, so the title
    /// never reached the leg most likely to answer it. Worse where the seed is
    /// a file the user already has — Library and Transfers — because the local
    /// index's one match is the seed, which the plan withholds by design,
    /// leaving the search with nothing to find at all.
    #[test]
    fn keyword_query_leads_and_the_co_share_request_follows_it() {
        let (first, followup) = server_search_phases(KEYWORD, Some(CO_SHARE.to_vec()), true);
        assert_eq!(first, KEYWORD);
        assert_eq!(followup.as_deref(), Some(CO_SHARE));
    }

    #[test]
    fn co_share_request_carries_a_search_that_has_no_keywords() {
        let (first, followup) = server_search_phases(KEYWORD, Some(CO_SHARE.to_vec()), false);
        assert_eq!(first, CO_SHARE);
        assert!(followup.is_none(), "nothing left to ask after it");
    }

    /// No `SRV_TCPFLG_RELATEDSEARCH`, or no valid seed hash: an ordinary
    /// one-phase keyword search, related or not.
    #[test]
    fn without_a_co_share_request_nothing_is_queued() {
        let (first, followup) = server_search_phases(KEYWORD, None, true);
        assert_eq!(first, KEYWORD);
        assert!(followup.is_none());
    }
}

/// Which legs of a search actually get asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SearchLegs {
    /// The connected eD2k server, over its TCP session.
    pub(super) server: bool,
    /// `OP_GLOBSEARCH` to the rest of the server list, over UDP.
    pub(super) udp: bool,
    pub(super) kad: bool,
    pub(super) ember: bool,
}

/// Work out which legs a search runs on.
///
/// `has_keyword_query` is whether a keyword leg has anything at all to send
/// (terms, or filters that stand on their own); `has_keywords` is whether the
/// parsed query left a positive term *the keyword DHTs can look up*, which is
/// what Kad and Ember walk to. A query that is nothing but a server directive
/// (`ed2k::<hash>` / `related::<hash>`) leaves none: the term is an instruction
/// to a server, so its MD4 is a key no publisher has ever written.
///
/// The rule worth naming here: `Server` asks that one connection and nothing
/// else. It is what keeps "Search Related Files" the server-side feature it is
/// in eMule — the co-share request is a question only the connected server can
/// answer, and the keyword half of a related plan is put to that same server
/// rather than fanned out to Kad, the Ember DHT or the rest of the server
/// list.
pub(super) fn search_legs(
    method: SearchMethod,
    has_keyword_query: bool,
    has_keywords: bool,
    user_offline: bool,
) -> SearchLegs {
    SearchLegs {
        server: matches!(method, SearchMethod::Global | SearchMethod::Server),
        // Global's UDP leg does not need a server *session*, so it kept
        // spraying `OP_GLOBSEARCH` at the whole server list after the user had
        // gone offline. Ember still answers a Global query, which is the
        // documented offline fallback; talking to eD2K servers is not.
        //
        // `has_keyword_query` is what stops a co-share-only related search
        // here: the search expression is empty in that case, and this leg
        // would queue a keywordless `OP_GLOBSEARCH` to every server in the
        // list. Only the one connected server can answer a co-share request,
        // and it is asked over TCP.
        udp: has_keyword_query && matches!(method, SearchMethod::Global) && !user_offline,
        kad: has_keywords && matches!(method, SearchMethod::Global | SearchMethod::Kad),
        // Gated on `has_keywords` for the same reason Kad is: the Ember DHT
        // walks to a keyword hash, so with no lookupable term there is no walk
        // to start. Starting one already required `compute_keyword_hashes` to
        // yield a key, so this only makes the leg honest about it rather than
        // leaving a leg claimed here and quietly abandoned there.
        ember: has_keywords && matches!(method, SearchMethod::Global | SearchMethod::Ember),
    }
}

#[cfg(test)]
mod search_legs_tests {
    use super::{search_legs, SearchLegs, SearchMethod};

    /// eMule's "Search Related Files" is server-side, and this is the gate that
    /// keeps ours the same: a related search is issued as a `Server` search, so
    /// neither half of its plan — not even the keyword query derived from the
    /// seed's name — reaches Kad or the Ember DHT.
    #[test]
    fn server_asks_the_server_and_nothing_else() {
        assert_eq!(
            search_legs(SearchMethod::Server, true, true, false),
            SearchLegs {
                server: true,
                udp: false,
                kad: false,
                ember: false,
            },
        );
    }

    #[test]
    fn global_asks_every_leg_it_can() {
        assert_eq!(
            search_legs(SearchMethod::Global, true, true, false),
            SearchLegs {
                server: true,
                udp: true,
                kad: true,
                ember: true,
            },
        );
    }

    #[test]
    fn kad_and_ember_methods_stay_on_their_own_network() {
        assert_eq!(
            search_legs(SearchMethod::Kad, true, true, false),
            SearchLegs {
                server: false,
                udp: false,
                kad: true,
                ember: false,
            },
        );
        assert_eq!(
            search_legs(SearchMethod::Ember, true, true, false),
            SearchLegs {
                server: false,
                udp: false,
                kad: false,
                ember: true,
            },
        );
    }

    #[test]
    fn going_offline_stops_the_ed2k_udp_spray_and_leaves_ember() {
        let legs = search_legs(SearchMethod::Global, true, true, true);
        assert!(!legs.udp, "no OP_GLOBSEARCH at the server list while offline");
        assert!(legs.ember, "Ember is the documented offline fallback");
    }

    /// A co-share-only related search: the seed's name yielded no searchable
    /// word, so there is nothing to put on a keyword leg and the hashes go to
    /// the server on their own.
    #[test]
    fn a_search_with_no_keywords_asks_no_keyword_leg() {
        let legs = search_legs(SearchMethod::Global, false, false, false);
        assert!(!legs.udp, "a keywordless OP_GLOBSEARCH is not a search");
        assert!(!legs.kad);
        assert!(!legs.ember, "the Ember DHT walk needs a keyword hash");
        assert!(legs.server, "the co-share request still goes over TCP");
    }

    /// A query that is only an `ed2k::<hash>` / `related::<hash>` directive:
    /// the servers resolve it from their own index, and the caller reports no
    /// DHT-lookupable keyword so neither keyword DHT is sent after a key that
    /// was never published.
    #[test]
    fn a_server_directive_query_asks_no_dht_leg() {
        let legs = search_legs(SearchMethod::Global, true, false, false);
        assert!(legs.server, "the directive goes to the connected server");
        assert!(legs.udp, "the rest of the server list can resolve it too");
        assert!(
            !legs.kad,
            "the MD4 of the directive text is not a published key"
        );
        assert!(!legs.ember);
    }
}

/// Contribute one ed2k result's sources toward the running ed2k totals — the
/// diagnostic `ed2k_found_sources` and, for a UDP reply, the sweep's own
/// [`MAX_UDP_SEARCH_SOURCES`] backstop (eMule spam-caps each result at 5).
pub(super) fn ed2k_result_source_contribution(availability: u32) -> u32 {
    availability.clamp(1, ED2K_SEARCH_SOURCE_CAP)
}

/// Hashes already shared or downloading — eMule `AddResultCount` skips these
/// when updating the search stop counter (`sharedfiles` / `downloadqueue`
/// `GetFileByID`). Results are still shown; only the cap counter ignores them.
pub(super) fn owned_or_downloading_search_hashes(
    hashes: impl IntoIterator<Item = impl AsRef<str>>,
    local_index: &LocalIndex,
    transfer_manager: &TransferManager,
    pending_downloads: &HashMap<String, PendingDownload>,
) -> HashSet<String> {
    let mut owned = HashSet::new();
    for hash in hashes {
        let hash = hash.as_ref();
        if hash.is_empty() || owned.contains(hash) {
            continue;
        }
        if local_index.get_by_hash(hash).is_some()
            || transfer_manager.has_pending_for_hash(hash)
            || pending_downloads.values().any(|pd| pd.file_hash == hash)
        {
            owned.insert(hash.to_string());
        }
    }
    owned
}

/// Record ed2k (TCP/UDP) result availability toward the global-search cap.
/// UDP re-sights **sum** availability (cross-server); TCP/Server re-sights use
/// **max** (OP_QUERY_MORE can re-list the same sources). Only the spam-capped
/// contribution *delta* is added to `ed2k_found_sources`.
///
/// `skip_hashes` are shared/downloading files (eMule `AddResultCount`): their
/// availability is still tracked for UI resights, but they do not advance the
/// stop counter.
pub(super) fn note_ed2k_search_results(
    active: &mut ActiveSearchRequest,
    results: &[SearchResult],
    skip_hashes: &HashSet<String>,
) -> bool {
    for r in results {
        let from_udp = crate::search::merge::is_ed2k_network_origin(&r.result_origin)
            && r.result_origin
                .split('·')
                .any(|p| p.trim() == crate::search::merge::ORIGIN_SERVER_UDP);
        if r.file.hash.is_empty() {
            let contribution = ed2k_result_source_contribution(r.availability);
            active.ed2k_found_sources = active.ed2k_found_sources.saturating_add(contribution);
            if from_udp {
                active.udp_found_sources = active.udp_found_sources.saturating_add(contribution);
            }
            continue;
        }
        let skip_count = skip_hashes.contains(&r.file.hash);
        // Bounded exactly as `streamed_hashes` and `dht_noted_availability`
        // are, and for the reason they are: a global sweep of every server in
        // the list can answer with far more distinct hashes than any user will
        // look at, and these two maps were the only per-hash state in a search
        // with nothing above them. A file already being tracked keeps
        // accumulating; a new one past the cap simply goes untracked and
        // carries its own slice, which beats abandoning the totals outright.
        //
        // One gate for both maps: every row writes to each of them, so their
        // key sets are the same and splitting the decision could only let them
        // disagree about a hash.
        let tracked = active.ed2k_noted_availability.len() < MAX_STREAMED_HASHES_SOFT_CAP
            || active
                .ed2k_noted_availability
                .contains_key(&r.file.hash);
        let prev = active.ed2k_noted_availability.get(&r.file.hash).copied();
        // A UDP reply is a different server than the last one that reported this
        // file, so its sources add; a TCP "More" re-list is the same server
        // repeating itself, so its figure replaces.
        let sum_incoming = from_udp;
        let (new_avail, old_contrib) = match prev {
            Some(p) => {
                let merged = crate::search::merge::clamp_source_count(if sum_incoming {
                    p.saturating_add(r.availability)
                } else {
                    p.max(r.availability)
                });
                (merged, ed2k_result_source_contribution(p))
            }
            None => (
                crate::search::merge::clamp_source_count(r.availability),
                0,
            ),
        };
        let new_contrib = ed2k_result_source_contribution(new_avail);
        // Untracked hashes must not advance the stop counters either. With no
        // stored previous value, `old_contrib` is 0 on *every* sighting, so a
        // past-the-cap file re-listed by each server in a global sweep added its
        // whole slice again each time instead of a delta. That inflates
        // `udp_found_sources` against `MAX_UDP_SEARCH_SOURCES` and ends the
        // sweep early — truncating the very results the sweep was asked for.
        // A number that cannot be computed correctly is better left out than
        // counted wrong: past 20,000 distinct files the sweep's other bounds
        // govern, and erring toward running the full course loses nothing.
        if !skip_count && tracked && new_contrib > old_contrib {
            let delta = new_contrib - old_contrib;
            active.ed2k_found_sources = active.ed2k_found_sources.saturating_add(delta);
            // Only a UDP reply advances the sweep's own backstop.
            if from_udp {
                active.udp_found_sources = active.udp_found_sources.saturating_add(delta);
            }
        }
        if tracked {
            active
                .ed2k_noted_availability
                .insert(r.file.hash.clone(), new_avail);
        }

        // Complete sources ride along on the same rule, and deliberately do not
        // feed `ed2k_found_sources`: the result cap counts sources, and a
        // complete source has already been counted as one.
        let new_complete = match active.ed2k_noted_complete_sources.get(&r.file.hash) {
            Some(&p) => crate::search::merge::clamp_source_count(if sum_incoming {
                p.saturating_add(r.file.complete_sources)
            } else {
                p.max(r.file.complete_sources)
            }),
            None => crate::search::merge::clamp_source_count(r.file.complete_sources),
        };
        if tracked {
            active
                .ed2k_noted_complete_sources
                .insert(r.file.hash.clone(), new_complete);
        }
    }
    active.udp_found_sources > MAX_UDP_SEARCH_SOURCES
}

/// Mark hashes as streamed only after a row was actually accepted/emitted
/// (so a type-filter miss does not permanently block later Kad sightings).
pub(super) fn mark_streamed_hashes(active: &mut ActiveSearchRequest, results: &[SearchResult]) {
    for r in results {
        if r.file.hash.is_empty() {
            continue;
        }
        if active.streamed_hashes.len() >= MAX_STREAMED_HASHES_SOFT_CAP
            && !active.streamed_hashes.contains(&r.file.hash)
        {
            continue;
        }
        active.streamed_hashes.insert(r.file.hash.clone());
    }
}

/// Running per-file source totals for the DHT legs of one search.
///
/// Kept apart from `ed2k_noted_availability`, and from each other, because the
/// rule for combining counts is per-leg: inside a leg the answers add up (each
/// KAD node and each Ember publisher is a separate claim on a separate file),
/// while across legs the biggest wins — a file on both the server and KAD is
/// one swarm being counted twice, not twice the sources. Since the UI merges a
/// row's counts by taking the max, holding the legs separately here is what
/// keeps that cross-leg max from quietly becoming a sum.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct DhtNotedAvailability {
    pub(super) kad: u32,
    pub(super) ember: u32,
}

/// How a DHT batch's counts relate to what its leg has already reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DhtBatchKind {
    /// Records the leg has not handed over before — the cursor-advanced tail
    /// slice both streaming paths send. Their counts add to the total.
    Incremental,
    /// A rebuild over every record the walk gathered, which is what the closing
    /// batch of either leg is. It *is* the total, so it replaces rather than
    /// adds — folding it in as an increment would double every count at the
    /// exact moment the search finished.
    Cumulative,
}

/// Fold a DHT batch into the request's running per-file totals for that leg,
/// and put the total on each row.
///
/// Both DHT legs convert only the records they have not converted before, so a
/// batch's `availability` counts that slice and nothing else: a file published
/// by thirty KAD nodes arrives as a dozen small batches. The UI merges counts
/// by max, so without a running total the row showed the largest single slice —
/// three or four sources for a file with thirty — until the leg finished and
/// pushed its rebuild over everything gathered. Which was correct, and up to a
/// minute late on a cold routing table. The server legs never had this because
/// they have kept a running total all along; this is that, for KAD and Ember.
pub(super) fn note_dht_availability(
    active: &mut ActiveSearchRequest,
    results: &mut [SearchResult],
    kind: DhtBatchKind,
) {
    for r in results {
        if r.file.hash.is_empty() {
            continue;
        }
        // Bounded the way `streamed_hashes` is: at the cap, files already being
        // tracked keep accumulating and a new one simply goes untracked, which
        // beats abandoning the totals for the rest of the search.
        let noted = if active.dht_noted_availability.len() >= MAX_STREAMED_HASHES_SOFT_CAP {
            active.dht_noted_availability.get_mut(&r.file.hash)
        } else {
            Some(
                active
                    .dht_noted_availability
                    .entry(r.file.hash.clone())
                    .or_default(),
            )
        };
        let Some(noted) = noted else { continue };
        let slot = match r.result_origin.as_str() {
            crate::search::merge::ORIGIN_KAD => &mut noted.kad,
            crate::search::merge::ORIGIN_EMBER => &mut noted.ember,
            // Anything else is a server row (handled by the ed2k total) or an
            // already-merged origin, which no streamed batch carries.
            _ => continue,
        };
        *slot = match kind {
            DhtBatchKind::Incremental => slot.saturating_add(r.availability),
            DhtBatchKind::Cumulative => (*slot).max(r.availability),
        }
        .min(MAX_KAD_AVAILABILITY);
        r.availability = r.availability.max(*slot);
    }
}

/// Fold ed2k re-sights into the request's running per-file totals and put that
/// **absolute** total on each row, which is what the UI's max-merge has to land
/// on for a row to end up showing the sum of every server that answered.
///
/// Runs before the client-constraint filter, because a re-sight is an increment
/// to a row that is already on screen — it only exists for a hash in
/// `streamed_hashes`, which nothing enters until it has been emitted. Filtering
/// it first compared "Min sources" against one server's slice instead of the
/// file's count: a second server answering with 4 sources for a row already
/// showing 25 was discarded under a minimum of 10, and its 4 left the total for
/// good. Now the filter sees the summed count, so a displayed row's own number
/// is what decides, and it can no longer drop its own increments.
pub(super) fn note_ed2k_resight_availability(
    active: &mut ActiveSearchRequest,
    updates: &mut [SearchResult],
    skip_hashes: &HashSet<String>,
) {
    for r in updates {
        if crate::search::merge::is_ed2k_network_origin(&r.result_origin) {
            let _ = note_ed2k_search_results(active, std::slice::from_ref(r), skip_hashes);
            if let Some(&total) = active.ed2k_noted_availability.get(&r.file.hash) {
                r.availability = total;
            }
            if let Some(&total) = active.ed2k_noted_complete_sources.get(&r.file.hash) {
                r.file.complete_sources = total;
            }
        }
    }
}

/// Emit already-seen-hash updates without spam re-scoring. Ed2k rows update
/// the cap map and carry **absolute** summed/max availability for the UI
/// (frontend takes max). Kad rows only refresh availability/sources/origin.
pub(super) fn emit_search_resight_updates(
    app_handle: &tauri::AppHandle,
    request_id: u64,
    mut updates: Vec<SearchResult>,
    active: &mut ActiveSearchRequest,
    skip_hashes: &HashSet<String>,
) {
    if updates.is_empty() {
        return;
    }
    note_ed2k_resight_availability(active, &mut updates, skip_hashes);
    let updates = filter_results_by_client_constraints(updates, active);
    if updates.is_empty() {
        return;
    }
    emit_search_results_event(app_handle, request_id, &updates);
}

pub(super) fn stop_ed2k_udp_search_if_capped(state: &mut NetworkState, app_handle: &tauri::AppHandle) {
    let Some(active) = state.active_search_request.as_mut() else {
        return;
    };
    if !active.udp_pending {
        return;
    }
    if active.udp_found_sources <= MAX_UDP_SEARCH_SOURCES {
        return;
    }
    let request_id = active.request_id;
    active.udp_pending = false;
    state.server_udp_search_age = 0;
    state.udp_search_queue.clear();
    debug!(
        "Stopping ed2k UDP global sweep: it has returned {} summed sources (backstop {})",
        active.udp_found_sources, MAX_UDP_SEARCH_SOURCES
    );
    maybe_finish_active_search(state, app_handle, request_id);
}

pub(super) struct PendingKeywordSearch {
    pub(super) tx: oneshot::Sender<Vec<SearchResult>>,
    pub(super) local_results: Vec<SearchResult>,
    /// Positive (non-negated) keywords, used for spam scoring of streamed
    /// results. The full boolean tree lives in `query_expr`.
    pub(super) keywords: Vec<String>,
    /// Parsed boolean query tree. Drives local re-filtering of Kad results
    /// (which are looked up by a single keyword hash, so the responding node
    /// can only partially apply OR/NOT branches it doesn't store).
    pub(super) query_expr: crate::search::query::QueryExpr,
    pub(super) request_id: u64,
    pub(super) last_streamed_count: usize,
    pub(super) file_type_filter: Option<String>,
}

pub(super) struct PendingServerSearch {
    pub(super) tx: Option<oneshot::Sender<Vec<SearchResult>>>,
    pub(super) results: Vec<SearchResult>,
    pub(super) request_id: u64,
}

#[derive(Clone)]
pub(super) struct ActiveSearchRequest {
    pub(super) request_id: u64,
    pub(super) server_pending: bool,
    pub(super) kad_pending: bool,
    pub(super) udp_pending: bool,
    /// True while an Ember DHT keyword `FIND_VALUE` for this request is in
    /// flight (slice 10). Like the other `*_pending` flags it gates
    /// `search-complete`; cleared when the Ember results are emitted or the
    /// lookup expires.
    pub(super) ember_pending: bool,
    /// Whether each keyword DHT leg was actually started for this request, as
    /// opposed to merely permitted by the search method.
    ///
    /// The `*_pending` flags cannot answer this at completion, because by then
    /// both are false whether the leg ran and finished or never ran at all.
    /// Only a request where both ran can say anything about their relative
    /// recall — see `note_dht_recall_sample`.
    pub(super) kad_ran: bool,
    pub(super) ember_ran: bool,
    /// Absolute unix timestamp after which the UDP global-search leg is
    /// force-completed regardless of `server_udp_search_age`. That age
    /// counter resets to 0 every time a non-empty `SearchResult` batch
    /// arrives (see the `ServerUdpResponse::SearchResult` handler) so a
    /// straggler server can still contribute — intentional — but without
    /// an absolute ceiling a server that keeps trickling results
    /// indefinitely would keep `udp_pending`, and so the whole search's
    /// `search-complete` event, alive forever. Only meaningful while
    /// `udp_pending` is true; see `UDP_SEARCH_HARD_DEADLINE_BUFFER_SECS`.
    pub(super) udp_search_deadline: i64,
    /// IPv4s we successfully sent an `OP_GLOBSEARCHREQ*` to for this
    /// request (eMule `SentUDPRequestNotification`). UDP search replies
    /// from any other IP are ignored as unsolicited / late.
    pub(super) udp_search_sent_ips: HashSet<Ipv4Addr>,
    /// Running sum of ed2k (TCP/UDP) result availability (eMule
    /// `m_foundSourcesCount`). Diagnostic only — no leg stops on it. Kept
    /// because it is the one number that says how much the ed2k side of a
    /// search actually found.
    pub(super) ed2k_found_sources: u32,
    /// The part of `ed2k_found_sources` that the UDP global sweep brought in,
    /// which is what that sweep's backstop ([`MAX_UDP_SEARCH_SOURCES`]) reads.
    /// Held separately so the connected server's TCP reply cannot spend it.
    pub(super) udp_found_sources: u32,
    /// Per-hash summed availability already folded into `ed2k_found_sources`
    /// (so a later UDP/TCP re-sight only adds the spam-capped contribution
    /// delta after summing, matching eMule `UpdateResultCount`).
    pub(super) ed2k_noted_availability: HashMap<String, u32>,
    /// Per-hash running total of `FT_COMPLETE_SOURCES`, accumulated by the same
    /// rule as `ed2k_noted_availability` because eMule accumulates it by the
    /// same rule: `AddCompleteSources` is `AddSources` with a different tag.
    ///
    /// Needed separately from the merge in `search::merge` because a streamed
    /// re-sight carries one server's slice and the row has to be emitted with
    /// the file's absolute total — the frontend merges batches by max, so
    /// without this the Complete column kept whichever single server answered
    /// with the most instead of the sum across them.
    pub(super) ed2k_noted_complete_sources: HashMap<String, u32>,
    /// The same running per-file total for the DHT legs; see
    /// [`DhtNotedAvailability`] for why theirs is kept apart from the ed2k one.
    pub(super) dht_noted_availability: HashMap<String, DhtNotedAvailability>,
    pub(super) file_type_filter: Option<String>,
    pub(super) min_size: Option<u64>,
    pub(super) max_size: Option<u64>,
    pub(super) file_extension: Option<String>,
    pub(super) min_availability: Option<u32>,
    /// Keywords extracted from the original query, used by the spam-filter
    /// scorer when streamed results arrive from the network event loop.
    /// Empty for queries where extraction yielded nothing (no spam scoring
    /// applied — those queries shouldn't reach the streaming paths anyway,
    /// since we early-return when `keywords.is_empty()` at request start).
    pub(super) keywords: Vec<String>,
    /// Source IP of the connected eD2k server at request-start time, used
    /// as an extra signal by the spam filter (`spam_server_ips` set). Only
    /// meaningful for the TCP-server streaming path; the UDP-server and
    /// KAD paths pass `None` because results from those origins don't
    /// uniquely belong to one server / origin IP.
    pub(super) server_ip: Option<String>,
    pub(super) server_result_count: usize,
    /// File hashes already forwarded to the UI for this request, across
    /// *all* origins (KAD tail-slice batches, UDP global-search per-server
    /// batches, TCP server "more results" pages). Each streaming call site
    /// only sees its own small batch, so without this a popular file
    /// re-announced later by a different KAD node / different eD2K server
    /// gets spam-scored a second time by `BatchSpamContext::analyze`'s
    /// batch-local heuristics — `is_spam` can flip false→true (never back,
    /// since the frontend merges with OR) well after the row was already
    /// shown, making it vanish under "hide spam" and look like the same
    /// file flickering. Once a hash has been streamed, every further sighting
    /// of it — Kad, Ember and ed2k (Server/UDP) alike — is returned separately
    /// as a lightweight availability/origin update instead of a second row (no
    /// spam re-score), which is what lets the UI sum sources like eMule and
    /// show one row carrying every network that has the file.
    /// Bounded well below `MAX_STREAMED_HASHES_SOFT_CAP` in practice since
    /// KAD/TCP/UDP each cap their own result counts, but a hard cap keeps
    /// a pathological all-servers global search from growing this
    /// unboundedly for the lifetime of one search.
    pub(super) streamed_hashes: std::collections::HashSet<String>,
    /// Hashes never to forward to the UI for this request. Set only by a
    /// related search, to the seed files it was started from: a co-share
    /// request and a title probe both return the seed itself, and listing the
    /// file you just right-clicked as one of its own related files is noise.
    /// Kept separate from `streamed_hashes` so these are dropped outright
    /// rather than being reported back as availability re-sights.
    pub(super) exclude_hashes: std::collections::HashSet<String>,
    /// Cross-packet spam batch context for this search (same-name/many-hashes
    /// across UDP/Kad/server pages, not only inside one emit).
    pub(super) batch_spam: crate::search::spam::BatchSpamContext,
}

/// Ceiling on the sources a single file may be credited with from one DHT leg,
/// well under the u16 the ed2k wire uses. Publisher counts are unverifiable
/// claims that arrive one node at a time, so the running total in
/// `ActiveSearchRequest::dht_noted_availability` is held to the same number the
/// per-batch tags are, and a Sybil cannot rank a file by asserting millions.
pub(super) const MAX_KAD_AVAILABILITY: u32 = 5_000;

/// Soft cap on `ActiveSearchRequest::streamed_hashes`. Once reached, the set
/// stops growing (bounding memory for a pathological all-servers global
/// search) but dedup itself doesn't stop: hashes already tracked before the
/// cap was hit are still filtered on every subsequent sighting — only a
/// *new* hash first seen after the cap goes untracked (and so can't be
/// deduped against a later repeat of itself). That's strictly better than
/// giving up on dedup entirely once the cap is reached.
pub(super) const MAX_STREAMED_HASHES_SOFT_CAP: usize = 20_000;

/// Rows the `search_files` oneshot carries back.
///
/// The reply is a second channel, not the main one: every row it holds that
/// the UI can use has either been streamed already or is a local hit, and the
/// ones left are whatever the KAD leg gathered but never emitted. Bounded
/// because it is serialized across IPC in one go, and sorted by availability
/// first so the cut falls on the least-sourced rows.
pub(super) const SEARCH_INVOKE_REPLY_MAX: usize = 2000;

/// Move the request's cross-packet spam context out for one enrichment pass,
/// leaving an empty one in its place.
///
/// Moved rather than cloned. `BatchSpamContext` holds up to 4096 name keys and
/// 4096 hash keys (each with up to 1024 members) plus 1024 row snapshots, and
/// this runs on the network task once per inbound result packet — so the clone
/// was O(context) per packet for the life of a search. Every call site is
/// `take` → enrich → [`store_search_batch_spam`] with nothing in between that
/// reads the field, so the empty stand-in is never observed.
pub(super) fn take_search_batch_spam(
    state: &mut NetworkState,
    request_id: u64,
) -> crate::search::spam::BatchSpamContext {
    state
        .active_search_request
        .as_mut()
        .filter(|a| a.request_id == request_id)
        .map(|a| std::mem::take(&mut a.batch_spam))
        .unwrap_or_default()
}

pub(super) fn store_search_batch_spam(
    state: &mut NetworkState,
    request_id: u64,
    batch: crate::search::spam::BatchSpamContext,
) {
    if let Some(active) = state.active_search_request.as_mut() {
        if active.request_id == request_id {
            active.batch_spam = batch;
        }
    }
}

/// Borrows the batch: the streaming enrichment path emits every batch it is
/// about to hand back to its caller, and these vectors are long runs of
/// multi-`String` rows, so serializing in place avoids cloning each one.
#[derive(Clone, serde::Serialize)]
pub(super) struct SearchResultsEvent<'a> {
    pub(super) request_id: u64,
    pub(super) results: &'a [SearchResult],
}

#[derive(Clone, serde::Serialize)]
pub(super) struct SearchProgressEvent {
    pub(super) request_id: u64,
    pub(super) nodes_contacted: usize,
    pub(super) results_so_far: usize,
    pub(super) phase: String,
}

#[derive(Clone, serde::Serialize)]
pub(super) struct SearchCompleteEvent {
    pub(super) request_id: u64,
}

/// A note (comment/rating) we have explicitly published to the KAD DHT via
/// `PublishNote`. DHT note entries expire after ~24h, so these are
/// re-published periodically (see the publish-timer notes block) and persisted
/// in the `published_notes` table so republishing survives restarts.
#[derive(Clone, Debug)]
pub(super) struct PublishedNote {
    pub(super) rating: u8,
    pub(super) comment: String,
    pub(super) file_name: Option<String>,
    pub(super) file_size: Option<u64>,
    /// Unix timestamp of the most recent (re)publish.
    pub(super) last_publish: i64,
}

#[derive(Clone, Debug)]
pub(super) struct PendingNotePublish {
    pub(super) file_hash: KadId,
    pub(super) rating: u8,
    pub(super) comment: String,
    pub(super) file_name: Option<String>,
    pub(super) file_size: Option<u64>,
    pub(super) message: KadMessage,
}

pub(super) fn build_publish_notes_message(
    local_id: KadId,
    file_hash: KadId,
    local_file: Option<FileInfo>,
    file_name: Option<&str>,
    file_size: Option<u64>,
    rating: u8,
    comment: &str,
) -> KadMessage {
    let mut tags = Vec::new();
    if let Some(file) = local_file {
        tags.push(KadTag {
            name: TagName::Id(TAG_FILENAME),
            value: TagValue::String(file.name),
        });
        tags.push(KadTag {
            name: TagName::Id(TAG_FILESIZE),
            value: TagValue::Uint64(file.size),
        });
    } else {
        if let Some(name) = file_name.filter(|name| !name.is_empty()) {
            tags.push(KadTag {
                name: TagName::Id(TAG_FILENAME),
                value: TagValue::String(name.to_string()),
            });
        }
        if let Some(size) = file_size.filter(|size| *size > 0) {
            tags.push(KadTag {
                name: TagName::Id(TAG_FILESIZE),
                value: TagValue::Uint64(size),
            });
        }
    }
    if !comment.is_empty() {
        tags.push(KadTag {
            name: TagName::Id(TAG_DESCRIPTION),
            value: TagValue::String(comment.to_string()),
        });
    }
    if rating > 0 {
        tags.push(KadTag {
            name: TagName::Id(TAG_FILERATING),
            value: TagValue::Uint8(rating),
        });
    }
    KadMessage::PublishNotesReq {
        target: file_hash,
        sender_id: local_id,
        tags,
    }
}

/// Filter search results by client constraints (type / size / extension /
/// min availability), matching eMule's AddToList post-filter behavior.
pub(super) fn filter_results_by_client_constraints(
    mut results: Vec<SearchResult>,
    active: &ActiveSearchRequest,
) -> Vec<SearchResult> {
    results.retain(|r| {
        crate::search::merge::result_matches_client_filters(
            r,
            active.file_type_filter.as_deref(),
            active.min_size,
            active.max_size,
            active.file_extension.as_deref(),
            active.min_availability,
        )
    });
    results
}

pub(super) fn filter_results_by_type(
    results: Vec<SearchResult>,
    file_type_filter: &Option<String>,
) -> Vec<SearchResult> {
    let mut results = results;
    if let Some(ref ft) = file_type_filter {
        results.retain(|r| {
            crate::search::merge::result_matches_client_filters(
                r,
                Some(ft.as_str()),
                None,
                None,
                None,
                None,
            )
        });
    }
    results
}

/// Partition a streamed batch for `request_id`:
/// - **New** hashes stay in `results` for full spam enrichment (hashes are
///   recorded in `streamed_hashes` only after a successful emit).
/// - **Already-streamed** hashes are returned as lightweight availability /
///   origin updates (no spam re-score) — ed2k and Kad alike.
///
/// A no-op (passes everything through, returns empty updates) if there's no
/// matching active search. Must run before spam enrichment so repeats never
/// reach `BatchSpamContext`.
pub(super) fn dedup_streamed_batch(
    active_search_request: &mut Option<ActiveSearchRequest>,
    request_id: u64,
    results: &mut Vec<SearchResult>,
) -> Vec<SearchResult> {
    let Some(active) = active_search_request.as_mut() else {
        return Vec::new();
    };
    if active.request_id != request_id {
        return Vec::new();
    }
    let mut resights = Vec::new();
    let mut kept = Vec::with_capacity(results.len());
    for r in results.drain(..) {
        if active.exclude_hashes.contains(&r.file.hash) {
            continue;
        }
        if !r.file.hash.is_empty() && active.streamed_hashes.contains(&r.file.hash) {
            resights.push(r);
        } else {
            kept.push(r);
        }
    }
    *results = kept;
    resights
}

/// Whether the currently connected eD2k server can answer eMule's native
/// co-share request (`related::<HASH>`), i.e. "what else do the clients holding
/// this file share".
///
/// Servers without the capability treat the term as an ordinary filename
/// substring and answer with nothing, so a related search must fall back to its
/// derived keyword query instead of sending the co-share term blindly.
pub(super) fn server_supports_related_search(state: &NetworkState) -> bool {
    state.server_connected
        && state
            .server_connection
            .as_ref()
            .is_some_and(|c| related_search_flag_set(c.session.server_flags))
}

/// `SRV_TCPFLG_RELATEDSEARCH` in the TCP capability flags a server sends with
/// `OP_IDCHANGE`.
pub(super) fn related_search_flag_set(server_flags: u32) -> bool {
    server_flags & ed2k::server::SRV_TCPFLG_RELATEDSEARCH != 0
}

pub(super) fn emit_search_results_event(
    app_handle: &tauri::AppHandle,
    request_id: u64,
    results: &[SearchResult],
) {
    if results.is_empty() {
        return;
    }
    let _ = app_handle.emit(
        "search-results",
        SearchResultsEvent {
            request_id,
            results,
        },
    );
}

/// Shared source-admissibility gate used by injection, StartDownload,
/// live-source collection, and the search UI. Order matches
/// `inject_source_into_active_transfers`: IP filter → banlist → self
/// address → port 0 → reputation / self user-hash.
///
/// Always uses `IpFilter::is_blocked_readonly` so call sites that only
/// hold `&NetworkState` (search enrichment, live-source filters) work;
/// the cache-miss cost is negligible next to dial / inject work.
pub(super) fn is_source_admissible(
    state: &NetworkState,
    ip: Ipv4Addr,
    port: u16,
    user_hash: Option<&[u8; 16]>,
) -> bool {
    if port == 0 {
        return false;
    }
    if state.ip_filter.is_blocked_readonly(ip) {
        return false;
    }
    if state.banned_ips.contains(&ip) {
        return false;
    }
    if let Some(ext) = state.external_ip {
        // Compare against both the raw bind port and whatever we actually
        // publish (which may be STUN-remapped) — see `is_self_source`.
        if ip == ext && (port == state.tcp_port || port == advertised_tcp_port(state)) {
            return false;
        }
    }
    if let Some(uh) = user_hash {
        if state.reputation.is_banned(uh) {
            return false;
        }
        if *uh != [0u8; 16] && *uh == state.user_hash {
            return false;
        }
    }
    true
}

/// Search-result IP gate: filter + banlist only (no port / hash yet).
pub(super) fn is_search_source_safe(state: &NetworkState, ip: Ipv4Addr) -> bool {
    is_source_admissible(state, ip, 1, None)
}

/// Apply spam scoring + filename cleanup + comment URL stripping to a
/// batch of streamed search results, then forward them to the existing
/// `emit_search_results` pipeline. This is the streaming counterpart to
/// `commands::search::enrich_results` (used by the synchronous local
/// search path).
///
/// Without this, network-discovered results — which is where spam
/// actually lives — would reach the UI with `spam_rating: 0` /
/// `is_spam: false` regardless of the user's spam-filter settings,
/// because the construction sites stub those fields and the frontend
/// trusts them.
///
/// Acquires only a read lock on `spam_filter`, so it's safe to call
/// Enrich, type/size/ext/avail-filter, and emit. Returns the rows this batch
/// newly accepted — not everything the emit carried — so ed2k callers count
/// only accepted results toward their running totals. Hashes must be marked
/// streamed by the caller via [`mark_streamed_hashes`] after this returns.
///
/// The distinction matters because the emit also carries spam *upgrades*: rows
/// an earlier packet already put on screen, re-sent because this packet pushed
/// them over a batch-collision bar. They are not new sightings, and the callers
/// treat what comes back as one — `note_dht_availability` adds a row's
/// availability onto the leg's running total, so handing an upgrade back would
/// count the same publishers a second time.
#[allow(clippy::too_many_arguments)]
pub(super) async fn enrich_and_emit_search_results(
    app_handle: &tauri::AppHandle,
    spam_filter: &Arc<RwLock<crate::search::spam::SpamFilter>>,
    comment_manager: &Arc<RwLock<CommentManager>>,
    settings: &AppSettings,
    request_id: u64,
    mut results: Vec<SearchResult>,
    file_type_filter: &Option<String>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    file_extension: Option<&str>,
    min_availability: Option<u32>,
    keywords: &[String],
    server_ip: Option<&str>,
    accumulated_batch: Option<&mut crate::search::spam::BatchSpamContext>,
) -> Vec<SearchResult> {
    if results.is_empty() {
        return Vec::new();
    }
    let spam_enabled = settings.spam_filter_enabled;
    let spam_profile =
        crate::search::spam::SpamFilterProfile::from_setting(&settings.spam_filter_profile);
    let cleanup_strings =
        crate::search::cleanup::parse_cleanup_strings(&settings.filename_cleanups);

    if let Some(sip) = server_ip {
        for result in &mut results {
            if result.origin_server_ip.is_none() {
                result.origin_server_ip = Some(sip.to_string());
            }
        }
    }

    let mut upgrades = Vec::new();
    let analyzed_batch;
    // Nothing downstream reads batch statistics with the filter off or under
    // `relaxed`: `apply_search_enrichment_with_batch` ignores the context, and
    // `colliding_hashes` walks every name and hash key — up to 4096 each — and
    // clones a `String` per hash in every colliding bucket. `absorb` is the
    // heavier half and used to run regardless, allocating a normalized name, a
    // normalized hash and a snapshot per result, on the network task, for every
    // inbound packet of a search whose results nobody was going to score.
    //
    // The cost of skipping it: a filter switched on *during* a search starts
    // with whatever the context has absorbed since, not the whole search. The
    // settings change already triggers `rescoreOpenTabs`, which re-scores
    // without batch context at all, so this changes nothing a user sees.
    let batch_stats_wanted =
        spam_enabled && spam_profile != crate::search::spam::SpamFilterProfile::Relaxed;
    let batch_for_score: Option<&crate::search::spam::BatchSpamContext> =
        if let Some(acc) = accumulated_batch {
            if batch_stats_wanted {
                let prev_colliding = acc.colliding_hashes();
                acc.absorb(&results);
                let skip: std::collections::HashSet<String> = results
                    .iter()
                    .map(|r| r.file.hash.trim().to_ascii_lowercase())
                    .collect();
                upgrades = acc.upgrade_rows(&prev_colliding, &skip);
            }
            // Handed over even when the statistics are off, because this context
            // also carries the owned-file exemption. With nothing absorbed it
            // reports `enabled = false`, so not one of the collision signals can
            // fire off the back of it.
            Some(&*acc)
        } else if batch_stats_wanted {
            analyzed_batch = crate::search::spam::BatchSpamContext::analyze(&results);
            Some(&analyzed_batch)
        } else {
            None
        };

    let community: std::collections::HashMap<String, crate::search::spam::CommunityRating> = {
        let cm = comment_manager.read().await;
        let mut map = crate::commands::search::community_ratings_for(
            &cm,
            &results,
            spam_enabled,
            spam_profile,
        );
        if !upgrades.is_empty() {
            map.extend(crate::commands::search::community_ratings_for(
                &cm,
                &upgrades,
                spam_enabled,
                spam_profile,
            ));
        }
        map
    };

    {
        let spam = spam_filter.read().await;
        crate::commands::search::apply_search_enrichment_with_batch(
            &mut results,
            &spam,
            keywords,
            server_ip,
            spam_enabled,
            spam_profile,
            &cleanup_strings,
            &community,
            false,
            batch_for_score,
        );
        if !upgrades.is_empty() {
            crate::commands::search::apply_search_enrichment_with_batch(
                &mut upgrades,
                &spam,
                keywords,
                server_ip,
                spam_enabled,
                spam_profile,
                &cleanup_strings,
                &community,
                false,
                batch_for_score,
            );
            upgrades.retain(|r| r.is_spam);
        }
    }

    // Auto-redemption: if a server's results came back mostly clean, decay its
    // learned spam reputation (escalation stays user-driven). Only relevant for
    // server-sourced batches, so it's gated on a known server IP.
    if spam_enabled {
        if let Some(sip) = server_ip {
            let total = results.len();
            let clean = results.iter().filter(|r| !r.is_spam).count();
            if clean > 0 {
                spam_filter
                    .write()
                    .await
                    .record_server_clean_batch(sip, clean, total);
            }
        }
    }

    results.retain(|r| {
        crate::search::merge::result_matches_client_filters(
            r,
            file_type_filter.as_deref(),
            min_size,
            max_size,
            file_extension,
            min_availability,
        )
    });
    // Upgrades ride along in the emit but are deliberately not filtered: each
    // one is a re-send of a row this search already showed, so it has passed
    // these constraints once. Judging it again on the fields the rebuilt row
    // carries is the wrong question, and asking it is how every upgrade in a
    // search narrowed by type, extension or Min sources used to be discarded.
    //
    // Appended for the emit and then split off again, so the caller gets only
    // this packet's own rows (see the note on the return value above).
    let accepted = results.len();
    results.append(&mut upgrades);
    emit_search_results_event(app_handle, request_id, &results);
    results.truncate(accepted);
    results
}

/// Whether a second TCP server search is queued for `request_id`.
pub(super) fn has_queued_server_followup(state: &NetworkState, request_id: u64) -> bool {
    state
        .server_followup_search
        .as_ref()
        .is_some_and(|(rid, _)| *rid == request_id)
}

/// Forget the queued second server search for `request_id`, for the paths that
/// stop a search rather than let it run its course (the ed2k source cap, a
/// silent server, cancel). Leaves a follow-up belonging to another request
/// alone.
pub(super) fn drop_queued_server_followup(state: &mut NetworkState, request_id: u64) {
    if has_queued_server_followup(state, request_id) {
        state.server_followup_search = None;
    }
}

/// End the TCP server leg for `request_id` now that its results are in — or
/// keep it pending when a second request is queued for it, so the server tick
/// sends that, `SERVER_MORE_RESULTS_DELAY` from now, before anything reports
/// the search complete.
pub(super) fn end_or_continue_server_search_leg(
    state: &mut NetworkState,
    request_id: u64,
    finished_search_requests: &mut Vec<u64>,
) {
    if has_queued_server_followup(state, request_id) {
        state.server_followup_due_at =
            Some(std::time::Instant::now() + SERVER_MORE_RESULTS_DELAY);
        return;
    }
    if let Some(active) = state.active_search_request.as_mut() {
        if active.request_id == request_id {
            active.server_pending = false;
        }
    }
    finished_search_requests.push(request_id);
}

/// Fold one finished search into the Ember-versus-KAD recall tally.
///
/// The tripwire for "richer keyword indexing (stemming, more than space-split
/// tokens) **if recall lags KAD on real libraries**". Nothing measured that:
/// the search-quality averages describe how a walk *ran* — nodes answered,
/// milliseconds, records returned — not whether Ember found the files KAD did.
///
/// Read as a triple. `both` climbing with the two `_only` counts near zero is
/// the tokenizers agreeing, which is the case for doing nothing. `kad_only`
/// pulling ahead of `ember_only` is recall lagging, and by how much; the
/// reverse is Ember finding files KAD's index missed, which is worth knowing
/// before anyone "fixes" the tokenizer toward KAD's.
///
/// Only counted when both legs actually ran, or an Ember-only search would
/// report every file as `ember_only` and an unavailable KAD leg would look like
/// Ember winning. Presence, not availability: a leg's count for a file is zero
/// or it is not, so it does not matter that Ember counts publishers where KAD
/// counts a claimed swarm. The sample is bounded by whatever
/// `note_dht_availability` was able to track, which is deliberate — it caps the
/// per-search cost of a diagnostic nobody is waiting on.
pub(super) fn note_dht_recall_sample(state: &mut NetworkState) {
    let Some(active) = state.active_search_request.as_ref() else {
        return;
    };
    if !(active.kad_ran && active.ember_ran) {
        return;
    }
    let (mut both, mut kad_only, mut ember_only) = (0u32, 0u32, 0u32);
    for seen in active.dht_noted_availability.values() {
        match (seen.kad > 0, seen.ember > 0) {
            (true, true) => both += 1,
            (true, false) => kad_only += 1,
            (false, true) => ember_only += 1,
            (false, false) => {}
        }
    }
    let diag = &mut state.ember_diagnostics;
    diag.ember_dht_recall_searches = diag.ember_dht_recall_searches.saturating_add(1);
    diag.ember_dht_recall_both = diag.ember_dht_recall_both.saturating_add(both);
    diag.ember_dht_recall_kad_only = diag.ember_dht_recall_kad_only.saturating_add(kad_only);
    diag.ember_dht_recall_ember_only = diag.ember_dht_recall_ember_only.saturating_add(ember_only);
}

pub(super) fn maybe_finish_active_search(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    request_id: u64,
) {
    let should_complete = state.active_search_request.as_ref().is_some_and(|active| {
        active.request_id == request_id
            && !active.server_pending
            && !active.kad_pending
            && !active.udp_pending
            && !active.ember_pending
    });
    if should_complete {
        // Before the request is dropped: it owns the per-leg tallies.
        note_dht_recall_sample(state);
        state.active_search_request = None;
        state.server_search_age = 0;
        state.server_udp_search_age = 0;
        let _ = app_handle.emit("search-complete", SearchCompleteEvent { request_id });
    }
}

/// Per-search teardown shared by the periodic `cleanup()` sweep and the
/// eMule-style fast `prune_stopped()` reap. Releases the removed searches'
/// in-use contacts back to the routing table and resolves/drops any result
/// channels and publish bookkeeping keyed by those search ids. Idempotent:
/// a second call for the same id is a no-op (every lookup returns `None`),
/// so it's safe for the cleanup sweep and the fast reap to overlap.
///
/// `rendezvous_target` is [`rendezvous_search_target`] read before the
/// removal.
pub(super) fn finalize_removed_searches(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    removed_sids: &[SearchId],
    released_in_use: &[KadId],
    rendezvous_target: Option<KadId>,
) {
    finalize_removed_searches_with_keyword_results(
        state,
        app_handle,
        removed_sids,
        released_in_use,
        &HashMap::new(),
        rendezvous_target,
    );
}

/// The target of the search `ember_rendezvous_search` names, while the manager
/// still holds it. Read before any removal, so teardown can tell the rendezvous
/// lookup from an unrelated search that reused its id.
pub(super) fn rendezvous_search_target(state: &NetworkState) -> Option<KadId> {
    state
        .ember_rendezvous_search
        .and_then(|rendezvous| state.search_manager.get(&rendezvous))
        .map(|search| search.target)
}

/// Like [`finalize_removed_searches`], but when capacity eviction already
/// extracted FindKeyword / FindSource / FindNotes result entries, deliver or
/// inject those instead of dropping them with the removed `SearchState`.
///
/// `rendezvous_target` is the target of the search `ember_rendezvous_search`
/// named, read before the removal took it out of the manager; see
/// [`ember_rendezvous_id_reused`].
pub(super) fn finalize_removed_searches_with_keyword_results(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    removed_sids: &[SearchId],
    released_in_use: &[KadId],
    preserved_results: &HashMap<SearchId, Vec<kad::messages::SearchResultEntry>>,
    rendezvous_target: Option<KadId>,
) {
    if !released_in_use.is_empty() {
        state.routing_table.release_contacts_in_use(released_in_use);
    }
    for sid in removed_sids {
        if ember_rendezvous_id_reused(state.ember_rendezvous_search, *sid, rendezvous_target) {
            state.ember_rendezvous_search = None;
        }
        if let Some(PendingKeywordSearch {
            tx,
            mut local_results,
            query_expr,
            request_id,
            ..
        }) = state.pending_keyword_searches.remove(sid)
        {
            if let Some(entries) = preserved_results.get(sid) {
                if !entries.is_empty() {
                    let mut network_results =
                        convert_search_results(entries, |ip| is_search_source_safe(state, ip));
                    if !query_expr.is_trivial() {
                        network_results.retain(|r| query_expr.matches(&r.file.name.to_lowercase()));
                    }
                    if let Some(active) = state.active_search_request.as_mut() {
                        if active.request_id == request_id {
                            // Same rebuild as the completion path, reaching the
                            // UI through the invoke reply instead of an event.
                            note_dht_availability(
                                active,
                                &mut network_results,
                                DhtBatchKind::Cumulative,
                            );
                            network_results =
                                filter_results_by_client_constraints(network_results, active);
                        }
                    }
                    local_results.extend(network_results);
                }
            }
            let _ = tx.send(local_results);
            if let Some(active) = state.active_search_request.as_mut() {
                if active.request_id == request_id {
                    active.kad_pending = false;
                }
            }
            maybe_finish_active_search(state, app_handle, request_id);
        }
        // Ember rendezvous lookup: nobody is waiting on the result, the point
        // is purely the Noise keys it carries. Clear the slot either way so a
        // later tick can retry.
        if state.ember_rendezvous_search == Some(*sid) {
            state.ember_rendezvous_search = None;
            let peers: Vec<KadSource> = preserved_results
                .get(sid)
                .map(|entries| {
                    extract_kad_sources(entries)
                        .into_iter()
                        .filter(|s| !is_self_source(s, state))
                        .collect()
                })
                .unwrap_or_default();
            let established = ember_established_addrs(state);
            harvest_ember_noise_keys(
                &mut state.ember_noise_keys,
                &peers,
                &established,
                state.ember_transport.local_noise_public_key(),
            );
            note_ember_rendezvous_lookup(
                state,
                peers.len(),
                ember_rendezvous_converted_contacts(state, &peers),
            );
        }
        if let Some((_, tx)) = state.pending_notes_searches.remove(sid) {
            if let Some(entries) = preserved_results.get(sid) {
                // Notes conversion forces the searched file hash onto results;
                // use the first entry id (Kad key) or zeros if empty after filter.
                let target = entries.first().map(|e| e.id).unwrap_or(KadId([0u8; 16]));
                let notes = convert_note_search_results(entries, &target);
                let _ = tx.send(Ok(notes));
            } else {
                let _ = tx.send(Err(
                    "Notes search busy: KAD search capacity reached".to_string()
                ));
            }
        }
        // Download-backed FindSource: inject any collected sources before
        // dropping the mapping so capacity eviction does not discard them (S9).
        if let Some((transfer_id, file_hash)) = state.download_source_searches.remove(sid) {
            if let Some(entries) = preserved_results.get(sid) {
                let all = extract_kad_sources(entries);
                let established = ember_established_addrs(state);
                harvest_ember_noise_keys(
                    &mut state.ember_noise_keys,
                    &all,
                    &established,
                    state.ember_transport.local_noise_public_key(),
                );
                let kad_sources: Vec<KadSource> = all
                    .into_iter()
                    .filter(|s| !is_self_source(s, state))
                    .collect();
                let direct: Vec<&KadSource> = kad_sources
                    .iter()
                    .filter(|s| {
                        s.buddy_ip.is_none()
                            && s.tcp_port != 0
                            && !s.ip.is_unspecified()
                            && s.lowid == 0
                    })
                    .collect();
                if !direct.is_empty() {
                    let matching = [transfer_id.clone()];
                    let mut injected = 0usize;
                    state.evicted_kad_sources.extend(direct.iter().map(|ds| {
                        (
                            file_hash,
                            ds.ip,
                            ds.tcp_port,
                            ds.udp_port,
                            ds.source_user_hash.unwrap_or([0u8; 16]),
                            ds.connect_options,
                        )
                    }));
                    for ds in &direct {
                        let source = DownloadSource {
                            peer_ip: ds.ip.to_string(),
                            peer_port: ds.tcp_port,
                            available_parts: Vec::new(),
                            peer_user_hash: ds.source_user_hash,
                            peer_connect_options: Some(ds.connect_options),
                        };
                        let stats = inject_source_into_active_transfers(
                            state,
                            file_hash,
                            &matching,
                            &source,
                            ds.udp_port,
                        );
                        injected += stats.injected + stats.persisted;
                    }
                    if let Some(pd) = state.pending_downloads.get_mut(&transfer_id) {
                        pd.last_search_at = None;
                    }
                    if injected > 0 {
                        info!(
                            "Evicted download source search {}: preserved {} source(s) for {}",
                            sid.0, injected, transfer_id
                        );
                        let _ = app_handle.emit(
                            "transfer:sources-updated",
                            serde_json::json!({ "transfer_id": transfer_id }),
                        );
                    }
                }
            }
            state.source_search_stream_cursor.remove(sid);
        }
        state.store_keyword_searches.remove(sid);
        let removed_store_src = state.store_source_searches.remove(sid);
        forget_rendezvous_publish(state, removed_store_src.as_ref());
        state.pending_note_publishes.remove(sid);
    }
}

/// Start a KAD search and immediately finalize any searches evicted by the
/// search-storm capacity path. Without this, `start_search` would drop those
/// SearchIds from the manager while leaving `pending_keyword_searches` /
/// `download_source_searches` / store maps orphaned until their own timeouts.
pub(super) fn start_kad_search(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    target: KadId,
    search_type: SearchType,
    initial_contacts: Vec<KadContact>,
) -> SearchId {
    let rendezvous_target = rendezvous_search_target(state);
    let (sid, evicted, released, preserved_results) =
        state
            .search_manager
            .start_search(target, search_type, initial_contacts);
    if !evicted.is_empty() {
        finalize_removed_searches_with_keyword_results(
            state,
            app_handle,
            &evicted,
            &released,
            &preserved_results,
            rendezvous_target,
        );
    }
    sid
}

/// eMule `CSearch::SetGUIName`: record what the KAD → Searches list should show
/// in its Name column for a just-started search. Publish searches are the ones
/// that need it — their target is a hash of the file or keyword, so the row is
/// unreadable without the subject being carried alongside. Call right after
/// `start_kad_search`; a rejected start (`SearchId(0)`, search-storm cap) and an
/// empty name are both no-ops.
pub(super) fn name_kad_search(state: &mut NetworkState, sid: SearchId, name: &str) {
    if sid == SearchId(0) || name.is_empty() {
        return;
    }
    if let Some(search) = state.search_manager.get_mut(&sid) {
        search.display_name = name.to_string();
    }
}

/// Split a `Transfer::peer_id` into its address and port halves.
///
/// `peer_id` is a display string, not a parsed socket address, and it can carry
/// a bracketed IPv6 literal (`[2001:db8::1]:4662`). Splitting on the *first*
/// colon turned that into address `"[2001"` and a port that does not parse, so
/// a resume-after-restart or a disk-full promotion rebuilt `StartDownload` with
/// an address nothing could dial — and it failed quietly, surfacing only as a
/// transfer that never found a source. Parsing as a `SocketAddr` first and
/// falling back to the *last* colon handles both forms; the IPv4-only download
/// path then rejects an IPv6 address on its own terms rather than on a
/// tokenizing accident. Mirrors `parse_peer_ip` / `parse_peer_port` in the IPC
/// layer.
pub(super) fn split_peer_id(peer_id: &str) -> (String, u16) {
    if let Ok(addr) = peer_id.parse::<SocketAddr>() {
        return (addr.ip().to_string(), addr.port());
    }
    match peer_id.rsplit_once(':') {
        Some((ip, port)) => (
            ip.trim_start_matches('[').trim_end_matches(']').to_string(),
            port.parse().unwrap_or(0),
        ),
        None => (String::new(), 0),
    }
}

/// Release every piece of state keyed by an Ember `search_id` and settle
/// whatever was waiting on it.
///
/// Shared by the expiry backstop and `CancelEmberSearch` so the two cannot
/// drift — and they had. Cancel dropped only the search slot and the dev value
/// waiter, leaving the keyword, claim, epoch, moderation, handoff,
/// publish-target and download-source entries behind. `alloc_id` only refuses
/// ids still present in `searches`, so releasing the slot alone let the very
/// same id be handed to an unrelated walk, whose records were then delivered
/// into the abandoned caller's map.
pub(super) fn release_ember_search_state(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    search_id: u32,
) {
    // A given id is either a node- or a value-lookup; draining both maps
    // resolves whichever waiter exists.
    if let Some(tx) = state.ember_dht_pending_lookups.remove(&search_id) {
        let _ = tx.send(Vec::new());
    }
    if let Some(tx) = state.ember_dht_pending_value_lookups.remove(&search_id) {
        let _ = tx.send(Vec::new());
    }
    // An abandoned download source lookup just means "no sources found this
    // round"; drop its bookkeeping so the map cannot leak across a
    // long-running download.
    state.ember_download_source_searches.remove(&search_id);
    // A user keyword lookup (slice 10) must still clear `ember_pending` and
    // re-check `search-complete`, or the UI spins forever on the Ember leg.
    if let Some(kw) = state.ember_keyword_searches.remove(&search_id) {
        if let Some(active) = state.active_search_request.as_mut() {
            if active.request_id == kw.request_id {
                active.ember_pending = false;
            }
        }
        maybe_finish_active_search(state, app_handle, kw.request_id);
    }
    if let Some(channel_id) = state.ember_channel_presence_searches.remove(&search_id) {
        flush_channel_presence_if_idle(state, channel_id);
    }
    state.ember_channel_moderation_searches.remove(&search_id);
    state.ember_channel_handoff_searches.remove(&search_id);
    state.ember_channel_epoch_searches.remove(&search_id);
    state.ember_channel_claim_searches.remove(&search_id);
    // A publish-target lookup can end here rather than through
    // `maybe_finish_ember_search`: if every send in its first batch fails, the
    // whole shortlist goes back to Pending, so the search never reports
    // complete, and with no wire request registered nothing re-drives it. The
    // key recovers on its own — the next publish re-queues it.
    state.ember_publish_target_lookups.remove(&search_id);
    state.ember_search.remove(search_id);
    state
        .ember_dht_search_requests
        .retain(|_, r| r.search_id != search_id);
}

pub(super) fn cancel_search_request(state: &mut NetworkState, app_handle: &tauri::AppHandle, request_id: u64) {
    // Drop in-flight Ember DHT keyword lookups for this request so a
    // cancelled search stops walking (not just unmapping bookkeeping while
    // FIND_VALUE continues until the 60s expiry).
    let ember_sids: Vec<u32> = state
        .ember_keyword_searches
        .iter()
        .filter(|(_, kw)| kw.request_id == request_id)
        .map(|(sid, _)| *sid)
        .collect();
    state
        .ember_keyword_searches
        .retain(|_, kw| kw.request_id != request_id);
    state
        .ember_pending_keyword_results
        .retain(|b| b.request_id != request_id);
    for sid in ember_sids {
        state.ember_search.remove(sid);
        state
            .ember_dht_search_requests
            .retain(|_, r| r.search_id != sid);
    }

    // Match by `request_id` across both IPC-facing search kinds that carry one
    // (keyword `search_files` and `find_notes`, which used to have no cancel
    // path at all and so kept their KAD search alive — wasting a routing-table
    // in-use slot and a search-manager slot — until the search's own lifetime
    // expired well after the IPC caller had already timed out and moved on).
    let cancelled: Vec<SearchId> = state
        .pending_keyword_searches
        .iter()
        .filter(|(_, pending)| pending.request_id == request_id)
        .map(|(sid, _)| *sid)
        .chain(
            state
                .pending_notes_searches
                .iter()
                .filter(|(_, (rid, _))| *rid == request_id)
                .map(|(sid, _)| *sid),
        )
        .collect();

    for sid in &cancelled {
        if let Some(search) = state.search_manager.get_mut(sid) {
            search.mark_completed();
        }
    }

    for sid in &cancelled {
        if let Some(PendingKeywordSearch {
            tx, local_results, ..
        }) = state.pending_keyword_searches.remove(sid)
        {
            let _ = tx.send(local_results);
        }
        if let Some(removed) = state.search_manager.remove(sid) {
            state
                .routing_table
                .release_contacts_in_use(&removed.in_use_ids);
        }
        // Clear any auxiliary per-search bookkeeping keyed by the same sid so a
        // cancelled search can't leave dangling channels/entries behind. Mirrors
        // `finalize_removed_searches`; idempotent (each lookup is a no-op when
        // absent).
        if let Some((_, tx)) = state.pending_notes_searches.remove(sid) {
            let _ = tx.send(Ok(Vec::new()));
        }
        state.download_source_searches.remove(sid);
        state.store_keyword_searches.remove(sid);
        let removed_store_src = state.store_source_searches.remove(sid);
        forget_rendezvous_publish(state, removed_store_src.as_ref());
        state.pending_note_publishes.remove(sid);
    }

    if state
        .pending_server_search
        .as_ref()
        .is_some_and(|pending| pending.request_id == request_id)
    {
        if let Some(mut pending) = state.pending_server_search.take() {
            if let Some(tx) = pending.tx.take() {
                let _ = tx.send(pending.results);
            }
        }
        state.server_search_age = 0;
    }
    drop_queued_server_followup(state, request_id);

    if state
        .active_search_request
        .as_ref()
        .is_some_and(|active| active.request_id == request_id)
    {
        state.active_search_request = None;
        state.server_search_age = 0;
        state.server_udp_search_age = 0;
        state.udp_search_queue.clear();
        let _ = app_handle.emit("search-complete", SearchCompleteEvent { request_id });
    }
}
