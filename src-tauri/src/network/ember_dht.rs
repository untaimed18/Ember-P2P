//! Ember DHT maintenance: contact health, pings, rendezvous lookups, the
//! KAD bridge, and inbound DHT message handling.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

pub(super) fn ember_highwater_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("ember_dht_highwater.json")
}

/// Whether two unsolicited senders are far enough apart to corroborate that our
/// UDP port is open: different /16s for IPv4, different /48s for IPv6.
///
/// Two addresses anyone holds, a pair of VPS in one provider block, would
/// otherwise make a firewalled node drop its firewalled flag and its buddy
/// fan-out.
pub(super) fn ember_reach_witnesses_independent(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a.octets()[..2] != b.octets()[..2],
        (IpAddr::V6(a), IpAddr::V6(b)) => a.octets()[..6] != b.octets()[..6],
        _ => true,
    }
}

/// What a newly confirmed observed address does to `external_ip`.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ObservedIpAction {
    Adopt,
    Reprobe,
    Keep,
}

/// The votes fill an empty `external_ip` unless STUN disagrees, but never move
/// one we hold: STUN decides that, so a confirmed address that differs asks for
/// a re-probe. Without one an idle node, which nothing else re-probes for, kept
/// advertising its old address after an IP change. Not while a live HighID
/// holds it, since STUN does not move that either.
pub(super) fn observed_ip_action(
    current: Option<Ipv4Addr>,
    voted: Ipv4Addr,
    stun: Option<Ipv4Addr>,
    highid: Option<Ipv4Addr>,
) -> ObservedIpAction {
    match current {
        None if stun.is_none_or(|stun| stun == voted) => ObservedIpAction::Adopt,
        Some(current) if current != voted && highid != Some(current) => ObservedIpAction::Reprobe,
        _ => ObservedIpAction::Keep,
    }
}

pub(super) fn load_ember_verified_highwater(path: &std::path::Path) -> EmberVerifiedHighwater {
    crate::security::recover_interrupted_replace(path);
    let Ok(bytes) = std::fs::read(path) else {
        return EmberVerifiedHighwater::default();
    };
    match serde_json::from_slice(&bytes) {
        Ok(hw) => hw,
        Err(e) => {
            // Falling back to `default()` silently is a load-then-overwrite:
            // the first `note_ember_verified_contacts` raises the zeroed peaks
            // and `save_ember_verified_highwater` writes them over the real
            // file, destroying the all-time number for good. Copy the
            // unparseable bytes aside first, the same guard
            // `kad::bootstrap::backup_if_short_load` gives `nodes.dat`.
            let bak = path.with_extension(format!("json.bak.{}", chrono::Utc::now().timestamp()));
            match std::fs::copy(path, &bak) {
                Ok(written) => warn!(
                    "Ember verified-contact high-water file is unparseable ({e}); backup written to {} ({written} bytes) — the next save resets the live peaks to 0",
                    bak.display(),
                ),
                Err(copy_error) => warn!(
                    "Ember verified-contact high-water file is unparseable ({e}) and the backup to {} failed: {copy_error}; the next save resets the live peaks to 0",
                    bak.display(),
                ),
            }
            EmberVerifiedHighwater::default()
        }
    }
}

pub(super) fn save_ember_verified_highwater(path: &std::path::Path, hw: &EmberVerifiedHighwater) {
    let Ok(bytes) = serde_json::to_vec(hw) else {
        return;
    };
    if let Err(e) = crate::security::atomic_write(path, &bytes, true) {
        debug!("Failed to persist Ember verified-contact high-water: {e}");
    }
}

/// Raise today's / all-time verified-contact peaks. Returns whether the
/// persisted copy needs rewriting. "Today" is the local calendar day, because
/// that is the day the user reading "peak today" means.
pub(super) fn note_ember_verified_contacts(hw: &mut EmberVerifiedHighwater, verified: u32) -> bool {
    note_ember_verified_contacts_on(hw, verified, &chrono::Local::now().date_naive().to_string())
}

/// [`note_ember_verified_contacts`] for an explicit `today` (`YYYY-MM-DD`).
pub(super) fn note_ember_verified_contacts_on(
    hw: &mut EmberVerifiedHighwater,
    verified: u32,
    today: &str,
) -> bool {
    let mut dirty = false;
    if hw.day != today {
        hw.day = today.to_string();
        hw.daily = verified;
        dirty = true;
    } else if verified > hw.daily {
        hw.daily = verified;
        dirty = true;
    }
    if verified > hw.alltime {
        hw.alltime = verified;
        dirty = true;
    }
    dirty
}

pub(super) fn record_ember_find_value_quality(
    diag: &mut EmberDiagnostics,
    search: &ember::dht::search::IterativeSearch,
) {
    if search.search_type != ember::dht::search::SearchType::FindValue {
        return;
    }
    diag.ember_dht_search_outcomes = diag.ember_dht_search_outcomes.saturating_add(1);
    diag.ember_dht_search_nodes_answered = diag
        .ember_dht_search_nodes_answered
        .saturating_add(search.responded_count() as u64);
    diag.ember_dht_search_elapsed_ms_sum = diag
        .ember_dht_search_elapsed_ms_sum
        .saturating_add(search.started_at.elapsed().as_millis() as u64);
    diag.ember_dht_search_records_sum = diag
        .ember_dht_search_records_sum
        .saturating_add(search.results.len() as u64);
}

/// Last outstanding STORE for this record failed (every replica refused or
/// timed out). Remove this key from the pending set; settle the file only
/// when none of its keys remain, so a mixed ACK cannot wipe siblings.
///
/// A round that placed any of its other keys is then published, not failed;
/// one that placed nothing is charged. Returns whether the file was stamped
/// published, which the caller owes [`note_ember_file_published`].
pub(super) fn fail_ember_record_pending(
    mut schedule: EmberPublishSchedule<'_>,
    reference: EmberRecordRef,
    now: std::time::Instant,
) -> bool {
    if reference.kind == EmberPublishKind::Replication {
        return false;
    }
    let slot = (reference.file_hash, reference.kind);
    let Some(unplaced) = schedule.unplaced.get_mut(&slot) else {
        return false;
    };
    unplaced.remove(&reference.key);
    let round_open = !unplaced.is_empty();
    schedule.partial.insert(slot);
    if round_open {
        return false;
    }
    if schedule.finish_round(slot, now) {
        return true;
    }
    charge_ember_publish_round(schedule, reference.file_hash, reference.kind, now);
    false
}

pub(super) fn note_ember_store_attempt_failed(
    state: &mut NetworkState,
    reference: EmberRecordRef,
    now: std::time::Instant,
) {
    if state.ember_batch_publish.record_still_outstanding(reference) {
        return;
    }
    if fail_ember_record_pending(state.publish_schedule(), reference, now) {
        note_ember_file_published(state, reference.file_hash, reference.kind);
    }
}

/// Charge one failed publish round against a file and, once it has gone
/// unconfirmed too many times, defer it a full republish interval so it stops
/// holding a selection slot every tick.
///
/// Only ever called after the last outstanding replica for a `(file, kind)`
/// slot has failed. It used to be called at *selection*, before the record
/// was even queued, which meant a file whose records the flush discarded —
/// the common case on a small table, where every key resolves to the same
/// few peers — burned all three of its attempts and was parked for hours
/// without a single record having left the host.
///
/// A round sends the same record to `K_EMBER_REPLICAS` peers in separate
/// batches, and they all time out within a moment of each other, so charges
/// are collapsed inside one [`EMBER_BATCH_ACK_TIMEOUT`] window. Rounds are
/// a publish tick apart, comfortably wider, so consecutive rounds still
/// count separately.
pub(super) fn charge_ember_publish_round(
    mut schedule: EmberPublishSchedule<'_>,
    file_hash: [u8; 16],
    kind: EmberPublishKind,
    now: std::time::Instant,
) {
    let slot = (file_hash, kind);
    let attempts = schedule
        .attempts
        .entry(slot)
        .or_insert(EmberPublishAttempts {
            rounds_failed: 0,
            last_charged: now.checked_sub(EMBER_BATCH_ACK_TIMEOUT).unwrap_or(now),
        });
    if now.duration_since(attempts.last_charged) < EMBER_BATCH_ACK_TIMEOUT {
        return;
    }
    attempts.rounds_failed += 1;
    attempts.last_charged = now;
    if attempts.rounds_failed <= EMBER_PUBLISH_MAX_ATTEMPTS {
        return;
    }
    // Treat it as done for scheduling purposes so the staleness ranking stops
    // putting it first. It gets one more try after a full interval.
    schedule.attempts.remove(&slot);
    schedule.unplaced.remove(&slot);
    schedule.stamp(file_hash, kind, now);
    debug!(
        "Ember publish: {} records for {} went unconfirmed {EMBER_PUBLISH_MAX_ATTEMPTS} rounds; deferring a full interval",
        match kind {
            EmberPublishKind::Keyword => "keyword",
            EmberPublishKind::Source => "source",
            EmberPublishKind::Replication => "replication",
        },
        hex::encode(file_hash)
    );
}

/// Record one completed lookup of the Ember rendezvous key.
///
/// `listed` is advertised peers after dropping this node's own advert.
/// `converted` is how many of those are already overlay (or session)
/// contacts, measured against the live table — so it reflects conversions
/// from *earlier* lookups, not this one's. A listed peer that never became a
/// contact is a cold-join miss: a stale advert is otherwise indistinguishable
/// from a live one.
///
/// The streak resets whenever any listed peer is already a contact. This
/// lookup only runs below [`EMBER_KAD_BRIDGE_UNTIL_CONTACTS`] verified
/// contacts, so a node stuck in that band that also advertises itself under
/// the rendezvous key resets on every lookup and never escalates. That is
/// pre-existing; the backoff is for a table that converted nobody.
pub(super) fn note_ember_rendezvous_lookup(state: &mut NetworkState, listed: usize, converted: usize) {
    state.ember_diagnostics.ember_dht_rendezvous_lookups = state
        .ember_diagnostics
        .ember_dht_rendezvous_lookups
        .saturating_add(1);
    state.ember_diagnostics.ember_dht_rendezvous_last_peers = listed.min(u32::MAX as usize) as u32;
    if listed == 0 {
        state.ember_diagnostics.ember_dht_rendezvous_empty = state
            .ember_diagnostics
            .ember_dht_rendezvous_empty
            .saturating_add(1);
    }
    state.ember_rendezvous_empty_streak =
        ember_rendezvous_empty_streak_after(state.ember_rendezvous_empty_streak, converted);
}

pub(super) fn ember_rendezvous_empty_streak_after(streak: u32, converted: usize) -> u32 {
    if converted == 0 {
        streak.saturating_add(1)
    } else {
        0
    }
}

/// Clear the rendezvous "published" mark if `removed` was its publish search.
///
/// The mark is written when the publish search *starts*, so a search torn
/// down before completing — capacity eviction, cancellation, a KAD
/// disconnect — would otherwise leave this node believing it is listed as a
/// bootstrap contact, and therefore undiscoverable, for a full republish
/// interval.
pub(super) fn forget_rendezvous_publish(state: &mut NetworkState, removed: Option<&(KadId, KadMessage)>) {
    if let Some((hash, _)) = removed {
        if *hash == kad::publish::ember_rendezvous_key() {
            state.ember_rendezvous_published_at = 0;
        }
    }
}

/// A cumulative `u64` counter as a `u32` diagnostics field, pinned at the
/// ceiling rather than wrapping back to a small number.
pub(super) fn saturating_u32(n: u64) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Copy the counters the DHT store, engine and frame limiter keep themselves
/// into `diag`. Done when diagnostics are read, not per frame: several of them
/// only move on frames that are refused, so a copy taken on the accept path
/// would lag exactly the numbers it exists to show.
pub(super) fn mirror_ember_dht_counters(state: &NetworkState, diag: &mut EmberDiagnostics) {
    let store_rejects = state.ember_dht.store_reject_stats();
    diag.ember_dht_store_key_cap_rejections = saturating_u32(store_rejects.key_cap);
    diag.ember_dht_store_reject_signature = saturating_u32(store_rejects.signature);
    diag.ember_dht_store_reject_timestamp = saturating_u32(store_rejects.timestamp);
    diag.ember_dht_store_reject_source_ip_cap = saturating_u32(store_rejects.source_ip_cap);
    diag.ember_dht_store_reject_publisher_cap = saturating_u32(store_rejects.publisher_cap);
    diag.ember_dht_store_reject_per_key_cap = saturating_u32(store_rejects.per_key_cap);
    diag.ember_dht_store_reject_verify = saturating_u32(state.ember_dht.store_reject_verify());
    diag.ember_dht_store_reject_source_ip = saturating_u32(state.ember_dht.store_reject_source_ip());
    diag.ember_dht_store_reject_proximity = saturating_u32(state.ember_dht.store_reject_proximity());
    diag.ember_dht_keyword_key_off_name = saturating_u32(state.ember_dht.keyword_key_off_name());
    diag.ember_dht_unknown_record_types =
        saturating_u32(state.ember_dht.unknown_record_types_stored());
    diag.ember_dht_version_advertisers =
        saturating_u32(state.ember_dht.peers_advertising_versions() as u64);
    diag.ember_dht_rate_limited = saturating_u32(state.ember_dht_protection.dropped_rate_limited());
    diag.ember_dht_store_addr_ceiling =
        saturating_u32(state.ember_dht_protection.dropped_store_addr_ceiling());
}

/// Whether this node may advertise itself under the rendezvous key: an
/// unsolicited DHT `PING` has to be able to reach it, because that is the
/// whole join path — a cold node reads the address off the advert and
/// bridge-pings it over UDP.
///
/// Either proof will do. KAD's UDP firewall check is answered by KAD peers, so
/// it needs no Ember peer to exist yet, and the advert only goes out while KAD
/// is up; the first nodes on an empty overlay therefore still list themselves.
/// [`ember_udp_reachable`] covers a node whose KAD check has not run or has
/// lapsed.
pub(super) fn ember_rendezvous_advert_reachable(
    udp_fw_verified: bool,
    udp_firewalled: bool,
    ember_udp_reachable: bool,
) -> bool {
    (udp_fw_verified && !udp_firewalled) || ember_udp_reachable
}

/// Whether the tracked rendezvous lookup id `tracked` has come to name some
/// other search: `sid` matches it but the search's `target` is not the
/// rendezvous key. KAD search ids restart at 1 whenever the search manager is
/// rebuilt, and an unrelated search consumed as the rendezvous lookup never
/// reaches its own completion branch. `None` (the search is already gone)
/// cannot be told apart and reads as not reused.
pub(super) fn ember_rendezvous_id_reused(tracked: Option<SearchId>, sid: SearchId, target: Option<KadId>) -> bool {
    tracked == Some(sid) && target.is_some_and(|t| t != kad::publish::ember_rendezvous_key())
}

/// Count a failed query against an Ember DHT contact, evicting it once it has
/// missed `MAX_FAILED_QUERIES` in a row and promoting a replacement if the
/// bucket has one waiting.
pub(super) fn fault_ember_contact(state: &mut NetworkState, node_id: &ember::dht::EmberNodeId, why: &str) {
    // Drop any Noise session with this peer. Sessions are one-sided state:
    // if the peer forgot its half (restart, eviction under session pressure,
    // the transport being toggled off) every frame we send is rejected as
    // "no session". Clearing it here means the next attempt re-handshakes
    // instead of talking into a black hole. `cleanup` would get there on its
    // own — it ages a session from the last frame the *peer* sent — but only
    // after `SESSION_TIMEOUT`, and a missed ping is the earlier, sharper
    // signal for a peer we hold a contact for.
    //
    // Keyed by this contact's identity, not just its address: sessions are
    // per `(addr, static key)` so peers sharing a NAT coexist, and an
    // address-wide drop punished every one of them for this peer's silence.
    if let Some(contact) = state.ember_dht.contact_for(node_id) {
        let addr = contact.addr;
        let noise_pub = contact.noise_pub;
        state.ember_transport.remove_session_for(&addr, &noise_pub);
    }
    evict_ember_contact_if_dead(state, node_id, why);
}

/// Count a failed *lookup* query against a contact, without tearing down its
/// Noise session.
///
/// Weaker evidence than an unanswered liveness ping: a lookup query can time
/// out because the peer is busy or because our own 5-second budget is tight, so
/// dropping the session — and paying a handshake to rebuild it — would be
/// premature. Counting it still matters. Before this, search timeouts touched
/// only the search's own shortlist, so a dead gossip lead kept being chosen as
/// a seed for every later lookup until the liveness sweep happened to reach it,
/// which at eight pings a minute can be many minutes of five-second stalls.
pub(super) fn fault_ember_search_contact(state: &mut NetworkState, node_id: &ember::dht::EmberNodeId) {
    // Unverified leads have no `last_seen` and are the only bootstrap we
    // hold on a cold join. Publish-target FIND_NODEs (two per tick) plus the
    // liveness ping all land on that one contact; each lookup timeout is 12s
    // behind a handshake, so three strikes evicted the seed in ~20s — before
    // the rendezvous keys had a chance to convert. Liveness pings still
    // fault leads; a dead seed drops after three unanswered pings (~3 min).
    if !state
        .ember_dht
        .contact_for(node_id)
        .is_some_and(|c| c.is_verified())
    {
        return;
    }
    evict_ember_contact_if_dead(state, node_id, "unresponsive in lookup");
}

/// Charge one failure against a contact and evict it once it has missed
/// `MAX_FAILED_QUERIES` in a row, promoting a replacement if one is waiting.
pub(super) fn evict_ember_contact_if_dead(
    state: &mut NetworkState,
    node_id: &ember::dht::EmberNodeId,
    why: &str,
) {
    if !state.ember_dht.mark_failed_contact(node_id) {
        return;
    }
    if state.ember_dht.evict_contact(node_id) {
        debug!("Ember DHT: evicted {why} contact {node_id} (promoted replacement)");
    } else {
        debug!("Ember DHT: evicted {why} contact {node_id} (no replacement)");
    }
    state.ember_diagnostics.ember_dht_contacts_evicted = state
        .ember_diagnostics
        .ember_dht_contacts_evicted
        .saturating_add(1);
}

/// Whether an expired liveness ping should be charged against the contact.
///
/// Only the `PONG`'s own request id clears the pending entry, so a peer that
/// replied to the ping under a different message type — or simply spoke to us
/// about something else while it was outstanding — left the entry to expire.
/// Charging that was wrong: every signed frame refreshes `last_seen`, so the
/// peer had already proven it was alive, and three such "timeouts" evicted a
/// working contact.
///
/// `last_seen` is `None` when the contact is no longer in the table, in which
/// case there is nothing to fault.
pub(super) fn ember_ping_timeout_is_a_fault(last_seen: Option<i64>, sent_unix: i64) -> bool {
    match last_seen {
        Some(seen) => seen < sent_unix,
        None => false,
    }
}

/// Build the pending-ping record, choosing the deadline from whether the frame
/// actually reached the wire or is still queued behind a Noise handshake.
pub(super) fn new_ember_maint_ping(
    node_id: ember::dht::EmberNodeId,
    behind_handshake: bool,
    now_unix: i64,
) -> EmberMaintPing {
    let budget = if behind_handshake {
        EMBER_MAINT_PING_QUEUED_TIMEOUT
    } else {
        EMBER_MAINT_PING_TIMEOUT
    };
    EmberMaintPing {
        node_id,
        deadline: std::time::Instant::now() + budget,
        sent_unix: now_unix,
    }
}

/// One in-flight Ember DHT liveness `PING`, awaiting a `PONG` or its deadline.
pub(super) struct EmberMaintPing {
    /// The contact the ping went to. A `PONG` only clears the entry when it
    /// comes from this identity, so a guessed request id cannot keep a dead
    /// contact alive.
    pub(super) node_id: ember::dht::EmberNodeId,
    /// When silence becomes a failure. Held per ping rather than as one
    /// constant because a frame queued behind a Noise handshake has not left
    /// yet, and charging it the same budget as one already on the wire faulted
    /// peers for our own handshake latency.
    pub(super) deadline: std::time::Instant,
    /// Unix time the ping was issued, so the sweep can tell whether the peer
    /// has been heard from *since*. Any signed frame proves liveness — a peer
    /// answering our `FIND_NODE` while its `PING` is still outstanding is not
    /// unresponsive.
    pub(super) sent_unix: i64,
}

/// One in-flight publish `STORE_RECORD`, tracked by the network task so a
/// matching `STORE_ACK` (or a timeout) can be applied to the owning
/// [`ember::dht::publish::PublishManager`] operation.
pub(super) struct EmberPublishRequest {
    /// The owning publish operation.
    pub(super) publish_id: u32,
    /// The per-publish request id `next_to_store` handed out (the
    /// correlation token `process_ack` / `mark_failed` expect).
    pub(super) per_pub_req_id: u32,
    /// The node this store went to. A `STORE_ACK` is only applied when it
    /// comes from this node: request ids are a plain monotonic counter, so
    /// without the binding any peer could guess one and be credited with
    /// storing a record it never saw, which both inflates the replication
    /// count and consumes the pending entry so the real target is never
    /// faulted.
    pub(super) node_id: ember::dht::EmberNodeId,
    /// When this store must be treated as failed if still unanswered.
    /// Queued-behind-handshake uses the longer FIND budget so a cold Noise
    /// session is not expired before the STORE ever leaves.
    pub(super) deadline: std::time::Instant,
}

/// Context for an in-flight Ember DHT keyword search started on behalf of
/// a user search (slice 10). Carries everything the completion path needs
/// to build and emit `SearchResult`s into the streaming pipeline.
pub(super) struct EmberKeywordSearch {
    /// The user-facing search request this lookup belongs to.
    pub(super) request_id: u64,
    /// All query keywords, used for the multi-word local AND-filter (the
    /// DHT key only matched the primary keyword).
    pub(super) keywords: Vec<String>,
    /// Parsed boolean query tree, used to re-filter hits the same way the KAD
    /// result path does. `keywords` alone cannot express the query: it is the
    /// flattened positive terms, so it turns `OR` into `AND` and loses the
    /// negated side of a `NOT` entirely.
    pub(super) query_expr: Option<crate::search::query::QueryExpr>,
    /// Optional file-type filter applied at emit time.
    pub(super) file_type_filter: Option<String>,
    pub(super) min_size: Option<u64>,
    pub(super) max_size: Option<u64>,
    pub(super) file_extension: Option<String>,
    pub(super) min_availability: Option<u32>,
    /// How many of the search's gathered records have already been handed to
    /// the emit pipeline. A cursor rather than a flag because
    /// `IterativeSearch::results` is append-only and deduped before push, so
    /// everything past this index is new.
    pub(super) last_streamed_count: usize,
    /// Distinct eD2K file hashes this lookup has built a row for, for the
    /// `results_so_far` the search page shows while the walk runs.
    ///
    /// Counted here rather than from `IterativeSearch::results`, which holds
    /// one entry per *record*: a file three publishers announced is three
    /// records and one result, so that length would over-report what the user
    /// is about to see. Re-deriving it per tick instead would mean verifying
    /// every gathered signature again once a second.
    pub(super) streamed_files: HashSet<String>,
    /// `(file hash, publisher key)` of every record a streamed slice has
    /// counted. A republished record is a new blob, so the blob dedup keeps
    /// both versions and they can land in different slices; slice counts are
    /// added up, and counting that publisher twice would stick, since the UI
    /// merges counts by max. Bounded by the search's result-blob cap.
    pub(super) streamed_publishers: HashSet<([u8; 16], [u8; 32])>,
}

/// A batch of Ember DHT keyword results ready to emit (slice 10).
pub(super) struct EmberKeywordResultBatch {
    pub(super) request_id: u64,
    pub(super) keywords: Vec<String>,
    pub(super) file_type_filter: Option<String>,
    pub(super) min_size: Option<u64>,
    pub(super) max_size: Option<u64>,
    pub(super) file_extension: Option<String>,
    pub(super) min_availability: Option<u32>,
    pub(super) results: Vec<SearchResult>,
    /// The last batch this lookup will produce, so the emit sweep knows which
    /// one clears `ember_pending`. Intermediate batches must not, or
    /// `search-complete` fires while the walk is still going.
    pub(super) final_batch: bool,
}

/// Maximum concurrent pending Ember pings tracked in `NetworkState`.
/// Each entry costs ~24 B + a oneshot; this cap keeps the map under
/// 50 KB even in a degenerate flood, while still allowing a harness
/// to fan out hundreds of probes in parallel.
/// Read only by the `debug_assertions` harness command arms that populate
/// those maps, so gated with them.
#[cfg(debug_assertions)]
pub(super) const MAX_EMBER_PENDING_PINGS: usize = 1024;

/// How long an iterative-lookup `FIND_NODE` query may sit unanswered
/// before the staleness sweep marks it failed and lets the search move
/// on to the next contact. Short enough that one dead node doesn't stall
/// a lookup, long enough to tolerate a Noise handshake round trip.
pub(super) const EMBER_SEARCH_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The same budget for a query still sitting behind a Noise handshake.
///
/// The transport reports such a frame as queued and rides it out once the
/// handshake completes, so the peer has not been asked anything yet when the
/// clock starts. Charging it the ordinary budget failed the contact before it
/// could possibly answer — and on a cold table every contact is a first
/// contact, so a fresh node's lookups failed almost everything they touched.
/// Covers a Noise_XX 2-RTT setup plus the query round trip, and stays well
/// inside the 60-second whole-search cap.
pub(super) const EMBER_SEARCH_QUEUED_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);

// ── DHT maintenance (slice 6) ──

/// How often the maintenance loop runs (bucket refresh, liveness pings,
/// record republish). Each task is internally gated on its own much
/// longer interval, so a 60-second cadence is cheap.
pub(super) const EMBER_MAINT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// How long a maintenance liveness `PING` may sit unanswered before the
/// 1-second sweep counts it as a failure against the contact. Generous
/// enough for a cold Noise handshake plus a round trip.
pub(super) const EMBER_MAINT_PING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// The same, for a ping still queued behind an in-flight Noise handshake.
///
/// `OutgoingResult::Queued` means the frame has not been transmitted at all
/// yet — it flushes when the handshake completes. Starting the 8-second clock
/// there charged the peer for our own handshake round trips: a cold Noise_XX
/// dial is two before the ping even leaves, so a perfectly healthy contact on
/// a 2-second path was faulted every time. The lookup path already draws this
/// distinction; liveness pings now do too.
pub(super) const EMBER_MAINT_PING_QUEUED_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// A bucket idle for longer than this is refreshed with a random-target
/// `FIND_NODE` (standard Kademlia bucket refresh ≈ 1 hour).
pub(super) const EMBER_BUCKET_REFRESH_SECS: i64 = 3600;

/// A contact not heard from in longer than this is liveness-pinged.
pub(super) const EMBER_CONTACT_PING_SECS: i64 = ember::dht::CONTACT_TIMEOUT_SECS;

/// Locally-stored records are re-published (replicated) to the current
/// closest nodes at least this often, so they survive node churn.
///
/// Two hours rather than one. This is storer-side replication, and what it can
/// buy is narrower than the old cadence assumed: expiry is derived from the
/// publisher's *signed* creation timestamp and a storer re-sends the identical
/// bytes, so every recipient computes the same absolute death time and no
/// amount of re-sending extends a record's life. What it does buy is churn
/// coverage — copies reaching nodes that joined since the publisher's last
/// round — which is worth paying for, but not twice over: at
/// `EMBER_MAINT_MAX_REPUBLISH` records per cycle to 20 replicas, hourly made
/// this the single largest traffic item on the overlay, roughly double its
/// entire publish load. Each record already has 20 replicas and lives at most
/// 24 hours.
pub(super) const EMBER_RECORD_REPUBLISH_SECS: u64 = 7200;

/// Per-maintenance-cycle fan-out caps, so one tick can't flood the
/// network with refreshes, pings, or republishes.
pub(super) const EMBER_MAINT_MAX_REFRESH: usize = 3;
pub(super) const EMBER_MAINT_MAX_PINGS: usize = 8;

/// The liveness-ping budget while the table has too few proven contacts to
/// work with.
///
/// A ping is the only way an unverified lead becomes usable, so this budget is
/// also the rate at which a node joins. Eight a minute is a sensible steady-state
/// trickle and a poor join: a table holding dozens of leads and one proven peer
/// needs many minutes to find out which of them are real, and until it does,
/// publishes replicate to that single peer and lookups walk a frontier of one.
/// Verification is cheap — one small frame each — so the starved case gets a
/// wider budget.
pub(super) const EMBER_MAINT_MAX_PINGS_STARVED: usize = 32;

/// Verified contacts below which the starved ping budget applies. One
/// k-bucket, the same bar the bridge and rendezvous lookup use for "joined".
pub(super) const EMBER_PING_STARVED_BELOW: usize = ember::dht::K_BUCKET_SIZE;

/// Liveness pings this cycle, from how many contacts have answered and how many
/// there are to keep an eye on.
///
/// A flat eight a minute is the same absolute rate whether the table holds
/// twenty contacts or two thousand, and the table can hold `128 * K` of them.
/// At eight a minute a full table takes hours to work through, so entries in
/// buckets no lookup happens to touch sit there dead until the much later stale
/// sweep. Aiming instead to reach every contact within the window that decides
/// whether one is stale keeps the sweep proportional to the work in front of it.
///
/// Bounded above by the starved budget rather than by a new number: the join
/// path already sustains that rate, so this cannot ask for more traffic than
/// the code already treats as acceptable. Bucket refresh deliberately does not
/// scale the same way — there are always exactly `ID_BITS` buckets however
/// large the network gets, and three a minute already rotates all of them well
/// inside `EMBER_BUCKET_REFRESH_SECS`.
pub(super) fn ember_maint_ping_budget(verified: usize, contacts: usize) -> usize {
    if verified < EMBER_PING_STARVED_BELOW {
        return EMBER_MAINT_MAX_PINGS_STARVED;
    }
    let ticks_per_window =
        (EMBER_CONTACT_PING_SECS.max(1) as u64 / EMBER_MAINT_INTERVAL.as_secs().max(1)).max(1);
    let per_tick = contacts.div_ceil(ticks_per_window as usize);
    per_tick.clamp(EMBER_MAINT_MAX_PINGS, EMBER_MAINT_MAX_PINGS_STARVED)
}
/// Records a storer replicates onward per maintenance cycle.
///
/// At five per minute this capped storer-side replication at 300 records an
/// hour against an hourly interval, so a node holding more than that could
/// never finish a pass — and with the scan restarting from the beginning each
/// time, the tail was never reached at all. Batching means these now cost a
/// handful of datagrams rather than one each.
pub(super) const EMBER_MAINT_MAX_REPUBLISH: usize = 200;
/// Contact-list exchanges per maintenance cycle (`ANNOUNCE_PEER`).
pub(super) const EMBER_MAINT_MAX_ANNOUNCE: usize = 2;
/// The same, while the table is still too thin to run a lookup on.
///
/// `ANNOUNCE_PEER` is the cheapest frame in the stack and the highest-yield one
/// when cold — a single round trip returns a contact list — and it was being
/// rationed hardest exactly when it was worth most, at two per minute whether the
/// table held four hundred contacts or none. Joining took minutes against KAD's
/// seconds, mostly for want of this.
///
/// Self-limiting: the wider budget applies only below
/// [`EMBER_KAD_BRIDGE_UNTIL_CONTACTS`] verified contacts, so it stops of its own
/// accord as soon as the table is usable. Half the starved liveness ping budget,
/// which is a rate the code already treats as acceptable on a node that is trying
/// to join — and an announce is answered with a contact list, so it buys more per
/// datagram than a ping does.
pub(super) const EMBER_MAINT_MAX_ANNOUNCE_STARVED: usize = 16;

/// KAD-bridge bootstrap (slice 13). While the Ember DHT routing table holds
/// fewer than this many *verified* contacts, the maintenance loop folds in
/// Ember peers learned from the live KAD network by DHT-pinging them; once the
/// table reaches this size it's self-sustaining and the bridge goes quiet. One
/// k-bucket's worth is plenty to seed iterative lookups + ongoing refresh.
///
/// Counted against contacts that have answered us, not `contact_count()`.
/// Against the total, a node that had been handed twenty unverified gossip
/// leads switched off both the bridge and the rendezvous lookup while holding
/// exactly one peer it could actually reach — and unverified leads are
/// precisely what the bridge exists to convert. That state is self-sustaining
/// in the wrong direction: one usable contact is too thin a frontier for a
/// lookup to discover anyone new.
pub(super) const EMBER_KAD_BRIDGE_UNTIL_CONTACTS: usize = ember::dht::K_BUCKET_SIZE;

/// Minimum spacing between asking one friend for its Ember DHT contacts.
///
/// Matches the maintenance tick, because the ask only happens below
/// [`EMBER_KAD_BRIDGE_UNTIL_CONTACTS`] verified contacts and a starved node
/// wants its next chance now rather than in five minutes — the same reasoning
/// that flattened the bridge backoff while starved. One small packet per friend
/// per minute, which stops entirely once the table is usable.
pub(super) const EMBER_FRIEND_CONTACT_ASK_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(60);

/// How long after asking a friend we will act on its answer.
///
/// Held apart from the interval above because the two want different lengths:
/// the ask stamp has to outlive its own interval for
/// `ask_friends_for_ember_contacts` to rank by least-recently-asked, while the
/// window in which an answer is still wanted is one round trip. Tying the
/// acceptance window to however long the stamp happens to be kept is how a
/// four-minute window would appear by accident.
pub(super) const EMBER_FRIEND_CONTACT_ANSWER_WINDOW: std::time::Duration =
    std::time::Duration::from_secs(60);

/// How long an ask stamp is kept at all.
///
/// Longer than the interval on purpose. The stamp is the rotation key, and
/// dropping it the moment it stops throttling would reset every friend to
/// "never asked" each cycle — which is precisely how the four friends the
/// per-tick budget reaches first keep reaching it first. Past this the map is
/// bounded by forgetting, since a friend not asked in four minutes is not in a
/// rotation that matters.
pub(super) const EMBER_FRIEND_CONTACT_STAMP_TTL: std::time::Duration =
    std::time::Duration::from_secs(240);

/// Minimum spacing between *answering* one friend's contact request.
///
/// Longer than the ask interval on purpose: answering costs a table walk and a
/// kilobyte on the wire, and the asker's own schedule is not ours to trust. A
/// friend that asks more often than this simply gets its extra asks dropped.
pub(super) const EMBER_FRIEND_CONTACT_SERVE_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(30);

/// Friends asked per maintenance tick. A user with a large friends list should
/// not turn a starved table into a burst of traffic; the ask walks through them
/// over successive ticks instead, and one answer is enough to bootstrap.
pub(super) const EMBER_FRIEND_CONTACT_ASKS_PER_TICK: usize = 4;

/// How often we re-advertise ourselves under the Ember rendezvous key.
/// Deliberately the same 5 hours KAD itself uses for source records, so the
/// entry is renewed just inside the `SOURCE_TTL_SECS` window storing peers
/// enforce and we never ask them to hold it longer than a normal source.
pub(super) const EMBER_RENDEZVOUS_REPUBLISH_SECS: i64 = 5 * 3600;

/// How long an advert no peer acknowledged waits before the next attempt.
/// Retrying at once restarted the store lookup every 15-25 s against the same
/// handful of nodes nearest the fixed key.
pub(super) const EMBER_RENDEZVOUS_UNACKED_RETRY_SECS: i64 = 10 * 60;

/// Minimum spacing between rendezvous *lookups*. The lookup only runs while
/// the Ember routing table is below `EMBER_KAD_BRIDGE_UNTIL_CONTACTS`, but a
/// node that genuinely cannot reach anyone would otherwise re-run a 45-second
/// KAD source search every maintenance tick forever. Ten minutes keeps a
/// stuck node's contribution to KAD search load negligible while still
/// recovering within a reasonable time once peers do appear.
pub(super) const EMBER_RENDEZVOUS_LOOKUP_INTERVAL_SECS: i64 = 600;

/// Spacing for the *first* retry after a lookup that converted nobody.
///
/// Ten minutes is right for a node that genuinely cannot reach anyone, but it
/// was also being applied to the first miss, and this key is the only cold-join
/// path there is. A node that started a minute before its first peer advertised
/// sat out the next ten. Back off from here to the steady-state interval so a
/// stuck node still costs almost nothing.
pub(super) const EMBER_RENDEZVOUS_FIRST_RETRY_SECS: i64 = 60;

/// How long to wait before the next rendezvous lookup, given how many in a
/// row converted nobody. Doubles per empty result up to
/// [`EMBER_RENDEZVOUS_LOOKUP_INTERVAL_SECS`]. A lookup that finds even one
/// already-known contact resets the streak (and this interval) to the
/// steady cadence; that includes a node whose 1–19 contacts include a
/// listed peer, which therefore never escalates.
pub(super) fn ember_rendezvous_retry_secs(empty_streak: u32) -> i64 {
    if empty_streak == 0 {
        return EMBER_RENDEZVOUS_LOOKUP_INTERVAL_SECS;
    }
    let doublings = empty_streak.saturating_sub(1).min(16);
    EMBER_RENDEZVOUS_FIRST_RETRY_SECS
        .saturating_mul(1i64 << doublings)
        .min(EMBER_RENDEZVOUS_LOOKUP_INTERVAL_SECS)
}

/// Start the Ember rendezvous lookup if every gate allows it, reporting whether
/// a search was actually started.
///
/// Other Ember nodes advertise themselves under a well-known KAD key, and a
/// plain source lookup there returns them with the Noise keys the DHT bridge
/// needs. That makes this the only cold-join path Ember has when
/// `nodes_ember.dat` is empty or stale and no eD2K session has produced an
/// Ember-capable peer.
///
/// Extracted from the 60-second maintenance tick so the 1 Hz search timer can
/// drive it too. Owned by one tick alone it could not work on a cold start: the
/// maintenance timer's first evaluation lands within a tenth of a second of
/// launch, when `kad_has_fresh_contact` is necessarily false because KAD has
/// not received a packet yet, and the next evaluation is a full minute later.
/// Any session shorter than that never looked anyone up at all, and a node with
/// no reachable seeds could not rejoin no matter how long it ran.
pub(super) fn maybe_start_ember_rendezvous_lookup(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    ember_native_enabled: bool,
) -> bool {
    // Cheapest gates first: this is re-evaluated every second while the table
    // is cold, so the O(n) table scans below must stay behind O(1) rejects.
    if !ember_native_enabled || state.ember_rendezvous_search.is_some() {
        return false;
    }
    let now = chrono::Utc::now().timestamp();
    if now.saturating_sub(state.ember_rendezvous_looked_up_at)
        <= ember_rendezvous_retry_secs(state.ember_rendezvous_empty_streak)
    {
        return false;
    }
    // Ahead of the table walk below: on a cold start this is false for the first
    // several seconds, and it is the reject this runs into every tick.
    //
    // A table loaded from `nodes.dat` is not the same as a live KAD: at startup
    // it is full of contacts nothing has spoken to yet, and a lookup against
    // those spends a 60-second search slot to return nothing. Worse, that empty
    // result now counts against the retry backoff, so a miss caused by KAD
    // simply not being up yet slows the next real attempt. Requiring recent KAD
    // traffic keeps the timestamp and the streak untouched until a lookup can
    // actually succeed.
    if !kad_has_fresh_contact(state) {
        return false;
    }
    // Gated on the same table size the bridge uses, so this stops once we are
    // self-sufficient and gossip takes over.
    if state.ember_dht.routing().verified_len() >= EMBER_KAD_BRIDGE_UNTIL_CONTACTS {
        return false;
    }
    let key = kad::publish::ember_rendezvous_key();
    let closest = state
        .routing_table
        .find_closest_prefer_verified(&key, SEARCH_INITIAL_CONTACTS);
    if closest.is_empty() {
        return false;
    }
    let sid = start_kad_search(
        state,
        app_handle,
        key,
        SearchType::FindSource { file_size: 0 },
        closest,
    );
    if sid == SearchId(0) {
        return false;
    }
    state.ember_rendezvous_search = Some(sid);
    state.ember_rendezvous_looked_up_at = now;
    let verified = state.ember_dht.routing().verified_len();
    if verified == 0 {
        info!("Ember rendezvous: looking up {key} to seed an empty DHT table");
    } else {
        info!(
            "Ember rendezvous: looking up {key} to grow a thin DHT table \
             ({verified} verified, want {EMBER_KAD_BRIDGE_UNTIL_CONTACTS})"
        );
    }
    true
}

/// Max KAD-bridge `PING`s per maintenance cycle, so even a large KAD-learned
/// peer cache can't burst the DHT with handshakes in one tick.
///
/// Matched to [`EMBER_MAINT_MAX_PINGS_STARVED`] rather than left at eight. The
/// bridge only runs below [`EMBER_KAD_BRIDGE_UNTIL_CONTACTS`] verified contacts,
/// which is exactly the state the starved liveness budget was widened for and for
/// the same reason: a bridge ping is one small frame, and it is the only way a
/// KAD-learned lead becomes an Ember contact. Converting them at a quarter of the
/// rate the node is already willing to ping at made the join needlessly slow, and
/// the bridge switching itself off at k contacts bounds the whole thing anyway.
pub(super) const EMBER_KAD_BRIDGE_MAX_PINGS: usize = EMBER_MAINT_MAX_PINGS_STARVED;

/// Ping budget and minimum spacing for the cold-start bridge pass the 1 Hz
/// timer drives, which must be far smaller than the per-cycle budget above.
///
/// That constant is a *per-maintenance-cycle* cap, and its whole point is that a
/// large peer cache "can't burst the DHT with handshakes in one tick". Handing
/// the same 32 to a caller that runs every second would sustain 32 handshakes
/// per second: both feeding caches hold up to `MAX_KNOWN_EMBER_NOISE_KEYS` /
/// `MAX_KNOWN_EMBER_PEERS` (500 each), so the pool is nowhere near spent after
/// one pass, and the Noise_XX half is the slow 2-RTT handshake against exactly
/// the LowID peers least likely to answer. That fills the transport's 512-slot
/// pending-handshake table and starts evicting handshakes belonging to the
/// searches a cold join depends on — the burst would degrade the thing it is
/// meant to accelerate.
///
/// The latency is the bug, not the rate. Four pings every five seconds is
/// ~0.8/s against the maintenance path's 32-per-60s (~0.53/s), the same order of
/// magnitude, while the first dial still lands about a second after the
/// rendezvous lookup that found the peer instead of up to a minute later.
pub(super) const EMBER_BRIDGE_FAST_MAX_PINGS: usize = 4;
pub(super) const EMBER_BRIDGE_FAST_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// How many contacts `nodes_ember.dat` keeps. Matching KAD's 200: enough to
/// rejoin from cold even if most have churned, without persisting the whole
/// table (which also meant persisting gossip we had never reached).
pub(super) const EMBER_PERSIST_MAX_CONTACTS: usize = 200;

/// Remembered peers handed to the routing table at once, at launch and on each
/// top-up.
///
/// Equal to the starved liveness budget, so a batch is fully probed in the tick
/// it arrives and resolves — answered or three-struck — before the next one is
/// needed. Larger batches do not join faster: the table cannot preserve the
/// cache's ranking (see [`ember::dht::peer_cache::BootstrapCache::seed_batch`]),
/// so anything past what one tick can dial just queues in XOR order and delays
/// the peers most likely to answer.
pub(super) const EMBER_SEED_BATCH: usize = EMBER_MAINT_MAX_PINGS_STARVED;

/// Batches `drive_ember_search` will pull in one call while none of them reach
/// the wire.
///
/// Each barren round retires its whole batch, so the shortlist shrinks by at
/// least ALPHA every pass and this is a safety net rather than a working limit
/// — a shortlist is bounded by k plus its pins plus what is in flight, so eight
/// passes at ALPHA covers any real one several times over.
pub(super) const EMBER_SEARCH_MAX_BARREN_ROUNDS: usize = 8;

// ── Self-lookup and disconnect detection ──

/// How long after start the join-time self-lookup runs on a cold table.
///
/// A `FIND_NODE` for our *own* ID is what fills the buckets closest to us,
/// and those are exactly the buckets that decide which keys we are
/// responsible for storing. Generic bucket refresh only visits buckets idle
/// for an hour, a few per cycle, so without this the close-to-home region
/// fills slowly and by accident. KAD runs the same lookup for the same
/// reason.
pub(super) const EMBER_SELF_LOOKUP_FIRST_DELAY_SECS: i64 = 180;
/// Shortcut delay once we have someone to ask: a warm public table, or a
/// live session neighbour the public table refused (LAN with
/// `block_private_ips`). Waiting the full cold delay in that case just
/// sat on a friend who already knew other contacts.
pub(super) const EMBER_SELF_LOOKUP_WARM_DELAY_SECS: i64 = 20;
/// Verified contacts that count as a warm table for the shortcut above.
pub(super) const EMBER_SELF_LOOKUP_WARM_VERIFIED: usize = ember::dht::K_BUCKET_SIZE / 2;
/// How often the self-lookup repeats, to recover the close-to-home buckets
/// after churn.
pub(super) const EMBER_SELF_LOOKUP_REPEAT_SECS: i64 = 4 * 3600;
/// Silence after which the DHT is treated as disconnected and re-bootstraps.
pub(super) const EMBER_DISCONNECT_SECS: i64 = 20 * 60;
/// Floor on how often emptying the overlay may re-arm bootstrap. The re-arm
/// itself fires only on the transition to zero (staying empty is left to the
/// rendezvous backoff). This stops a node whose lookups keep listing stale
/// leads — add, three-strike evict, empty again — from zeroing
/// `ember_rendezvous_looked_up_at` every eviction cycle and hammering the
/// rendezvous key. 300s matches [`EMBER_BRIDGE_RETRY_MAX`]: long enough that
/// one failed conversion (~2 min in the field) does not immediately re-arm,
/// far shorter than [`EMBER_DISCONNECT_SECS`].
pub(super) const EMBER_EMPTY_REARM_SECS: i64 = 300;

/// How long a remembered peer that was offered and did not stick waits before
/// a thin table offers it again. Long against a dead address's three missed
/// pings, short against a laptop coming back online.
pub(super) const EMBER_REOFFER_AFTER_SECS: i64 = 30 * 60;

/// How long a verified contact may go unheard before it is purged outright,
/// matching KAD's two hours. Well beyond the liveness-ping interval, so this
/// only catches contacts the ping budget never got around to probing — which
/// holds only while the maintenance tick has been running; see
/// [`ember_stale_purge_hold`].
pub(super) const EMBER_CONTACT_STALE_SECS: i64 = 2 * 3600;

/// A gap between maintenance ticks longer than this means the liveness pings
/// were not going out — the machine was suspended, or the loop was stalled —
/// so the silence it produced says nothing about the contacts.
pub(super) const EMBER_MAINT_GAP_SECS: i64 = EMBER_CONTACT_PING_SECS;

/// How long the staleness purge is held after a suspend, for a table holding
/// `verified` verified contacts: long enough for the liveness pings to reach
/// every one of them.
///
/// [`ember_maint_ping_budget`] covers the table in one liveness window up to
/// its ceiling of [`EMBER_MAINT_MAX_PINGS_STARVED`] a tick; past that the table
/// takes more ticks than the window has. While leads are waiting the engine
/// holds a share of the budget for them, so verified contacts are counted
/// against what is left. Never shorter than the window and never longer than
/// [`EMBER_CONTACT_STALE_SECS`], past which the hold would outlast the silence
/// it exists to excuse.
pub(super) fn ember_suspend_hold_secs(verified: usize) -> i64 {
    let per_tick = EMBER_MAINT_MAX_PINGS_STARVED
        - EMBER_MAINT_MAX_PINGS_STARVED.div_ceil(ember::dht::engine::LEAD_PING_RESERVE_DIVISOR);
    let ticks = verified.div_ceil(per_tick) as i64;
    ticks
        .saturating_mul(EMBER_MAINT_INTERVAL.as_secs() as i64)
        .clamp(EMBER_CONTACT_PING_SECS, EMBER_CONTACT_STALE_SECS)
}

/// Session contacts the maintenance tick pings while the staleness purge is
/// held: ones that have answered us before, have gone a liveness window
/// unheard, and have not been asked yet during this hold. A copy we have never
/// heard from is not at risk — the purge keeps those — so it is not asked.
pub(super) fn ember_session_contacts_to_ask_during_hold(
    session: &HostPortMap<ember::dht::EmberContact>,
    asked: &HashSet<(Ipv4Addr, u16)>,
    now: i64,
) -> Vec<ember::dht::EmberContact> {
    session
        .iter()
        .filter(|(key, c)| {
            c.last_seen > 0
                && now.saturating_sub(c.last_seen) >= EMBER_CONTACT_PING_SECS
                && !asked.contains(*key)
        })
        .map(|(_, c)| c.clone())
        .collect()
}

/// Until when the staleness purge must age nothing out, given the unix time of
/// the previous maintenance tick, the hold already in force, `now`, and how many
/// verified contacts the table holds.
///
/// The purge's premise is that the liveness pings kept running, so a contact
/// still unheard after two hours is one the budget never reached. A suspend
/// longer than that breaks it for every contact at once: an unheld first tick
/// after resume would purge each verified contact before a single ping had gone
/// out, leaving the node to rejoin from nothing. Held for as long as the pings
/// need to reach the whole table — see [`ember_suspend_hold_secs`] — so every
/// contact is asked first, and whatever still has not answered when the hold
/// lifts is purged as before.
///
/// Skipping the purge was preferred to demoting the stale contacts to leads.
/// Demotion throws away the verified state the table leans on — the
/// `noise_pub` pin that stops a replayed frame from rebinding a slot, the
/// verified count the diversity tier is read from, and first claim on a slot
/// against leads — for contacts most of which answer within minutes. Holding
/// risks only keeping dead contacts one window longer, the same exposure the
/// three-strike eviction already accepts.
///
/// Capped at one hold past `now`, so a backwards clock step cannot hold the
/// purge off for however far the clock moved.
pub(super) fn ember_stale_purge_hold(
    last_run: Option<i64>,
    held_until: i64,
    now: i64,
    verified: usize,
) -> i64 {
    let window_end = now.saturating_add(ember_suspend_hold_secs(verified));
    let held_until = match last_run {
        Some(prev) if now.saturating_sub(prev) > EMBER_MAINT_GAP_SECS => window_end,
        _ => held_until,
    };
    held_until.min(window_end)
}

// ── Bucket pressure and the KAD bridge ──

/// Probe the oldest contact of each bucket a newcomer could not enter.
///
/// Kademlia bucket pressure: `add_contact` answers `PingOldest` when the bucket
/// is full. The newcomer is already parked in that bucket's replacement cache,
/// and whether it ever gets a slot depends entirely on this probe. If the
/// incumbent answers it keeps its slot (proven-live contacts win, and the
/// newcomer ages out of the cache); if it stays silent past
/// `EMBER_MAINT_PING_TIMEOUT` the 1-second sweep faults and evicts it,
/// promoting the newcomer. Registering the probe in the same
/// `ember_dht_maint_pings` map the liveness sweep drains is what makes that
/// fault/evict/promote path fire for free.
///
/// Shared by the inbound path and the bootstrap-cache top-up so the two cannot
/// drift — the top-up originally discarded `PingOldest` entirely, which left
/// the peers it parked waiting on an eviction nothing would ever trigger.
pub(super) async fn probe_bucket_oldest(
    socket: &UdpSocket,
    state: &mut NetworkState,
    targets: &[(SocketAddr, ember::dht::EmberNodeId, [u8; 32])],
    now: i64,
) {
    for (oldest_addr, oldest_id, oldest_noise) in targets {
        // One probe per contact: if a liveness or earlier bucket-pressure
        // ping to it is already outstanding, that one already decides its
        // fate — piling on would over-count failures and waste packets.
        if state
            .ember_dht_maint_pings
            .values()
            .any(|p| p.node_id == *oldest_id)
        {
            continue;
        }
        // Not sent to, and faulted like any contact we cannot reach, which is
        // what hands the waiting newcomer its slot.
        if ember_addr_banned(state, *oldest_addr) {
            fault_ember_contact(state, oldest_id, "banned");
            continue;
        }
        let (wire_req_id, frame) = state.ember_dht.build_ping();
        let mut behind_handshake = false;
        let mut delivery_certain = true;
        let sent =
            match state
                .ember_transport
                .prepare_outgoing(*oldest_addr, Some(oldest_noise), &frame)
            {
                ember::transport::OutgoingResult::Ready { packet } => {
                    match send_ember_udp(socket, &packet, *oldest_addr, &state.ember_dht_overhead)
                        .await
                    {
                        Ok(_) => true,
                        Err(e) => {
                            debug!("Ember DHT: bucket-pressure ping to {oldest_addr} failed: {e}");
                            false
                        }
                    }
                }
                ember::transport::OutgoingResult::HandshakeStarted { packet } => {
                    behind_handshake = true;
                    match send_ember_udp(socket, &packet, *oldest_addr, &state.ember_dht_overhead)
                        .await
                    {
                        Ok(_) => true,
                        Err(e) => {
                            debug!("Ember DHT: bucket-pressure ping to {oldest_addr} failed: {e}");
                            false
                        }
                    }
                }
                ember::transport::OutgoingResult::Queued => {
                    behind_handshake = true;
                    // Parked behind a handshake that may complete with someone
                    // else, in which case this frame is discarded rather than
                    // sent. Not booked, so its silence cannot fault a contact
                    // we never actually probed; bucket pressure simply retries
                    // on the next tick.
                    delivery_certain = state
                        .ember_transport
                        .queued_delivery_is_certain(*oldest_addr, oldest_noise);
                    true
                }
                ember::transport::OutgoingResult::Error(e) => {
                    debug!("Ember DHT: transport error pinging oldest {oldest_addr}: {e}");
                    false
                }
            };
        if sent && delivery_certain {
            state.ember_dht_maint_pings.insert(
                wire_req_id,
                new_ember_maint_ping(*oldest_id, behind_handshake, now),
            );
            state.ember_diagnostics.ember_dht_liveness_pings_sent = state
                .ember_diagnostics
                .ember_dht_liveness_pings_sent
                .saturating_add(1);
        } else if !sent {
            // A probe that never left the machine records no pending entry, so
            // the timeout sweep cannot fault this contact either — and this is
            // the path that services bucket pressure, so the newcomer waiting
            // in the replacement cache is waiting on a promotion that can only
            // come from the incumbent being faulted. An address family the
            // socket cannot dial (an IPv6 contact learned by gossip on an IPv4
            // socket) fails here every time, and the liveness sweep will not
            // cover it while it is still recent enough not to be due a ping.
            // Same reasoning as the unreachable arm in `ping_ember_contact`.
            fault_ember_contact(state, oldest_id, "unreachable");
        }
    }
}

/// Dial Ember peers we know of but have never spoken to, so the signed `PONG`
/// can teach us a verified contact through the normal inbound path.
///
/// Two sources feed it. KAD source publishes carry a peer's Noise key but not
/// its Ed25519 key or node ID, so we cannot build a contact directly — we
/// DHT-`PING` `(addr, noise_pub)` on the 1-RTT Noise_IK path instead. A live
/// eD2K client session is an introduction too, and one worth taking even when
/// the public table is full, because a LAN or island 1.5.x peer would otherwise
/// never be DHT-pinged and `FIND_VALUE` would never ask it; those go over
/// Noise_XX. Returns how many pings went out.
///
/// The IK pass self-disables once the table is bootstrapped so steady-state KAD
/// traffic does not spray DHT pings. `force` (the dev-panel button) bypasses
/// that size gate.
///
/// Split out of [`run_ember_maintenance`] so the 1 Hz search timer can drive it
/// during a cold join. Owned by the 60-second maintenance tick alone, it was
/// always a tick behind the thing that feeds it: the rendezvous lookup caches
/// Noise keys mid-interval, so a node that had just discovered the only peers
/// it could reach sat on them for the rest of the minute — 46 seconds of it in
/// a measured cold start. Re-running it is close to free once the candidates
/// are spent, because `bridge_retry_due` holds every attempted peer until its
/// backoff expires and the extra passes just build an empty candidate list.
pub(super) async fn run_ember_kad_bridge(
    socket: &UdpSocket,
    state: &mut NetworkState,
    force: bool,
    max_pings: usize,
) -> usize {
    // `starved` is what flattens the retry backoff, and it has to be the real
    // table state: a forced run against a healthy table is still a healthy
    // table, and letting `force` stand in for it re-dialled every address the
    // backoff was resting.
    let starved = state.ember_dht.routing().verified_len() < EMBER_KAD_BRIDGE_UNTIL_CONTACTS;
    if !(force || starved) {
        return 0;
    }
    let mut sent = 0usize;
    let mut xx_sent = 0usize;
    // The budget has to be charged against peers *dialled*, not datagrams that
    // left. `send_ember_bridge_ping` returns false for a local send error too,
    // and a run of those would otherwise leave `max_pings` untouched and hand
    // the next pass a full second budget — up to twice the documented cap in
    // one call, spent on the slower 2-RTT handshake.
    let mut dialled = 0usize;

    // XX first, up to its reserve, so the IK pass cannot crowd it out; see
    // `EMBER_BRIDGE_XX_RESERVE_DIVISOR`. Whatever the reserve does not find a
    // candidate for is still on the table for the IK pass below.
    let reserve = xx_bridge_reserve(max_pings, !state.ember_keyless_peers.is_empty());
    let reserved_xx = xx_bridge_candidates(
        &state.ember_keyless_peers,
        &state.ember_noise_keys,
        &state.ember_kad_bridge_attempted,
        reserve,
        starved,
    );
    for (ip, port) in &reserved_xx {
        dialled += 1;
        if send_ember_bridge_ping(socket, state, *ip, *port, None).await {
            xx_sent += 1;
            sent += 1;
        }
    }

    let candidates = kad_bridge_candidates(
        &state.ember_noise_keys,
        &state.ember_kad_bridge_attempted,
        max_pings.saturating_sub(dialled),
        starved,
    );
    for (ip, port, noise_pub) in candidates {
        dialled += 1;
        if send_ember_bridge_ping(socket, state, ip, port, Some(&noise_pub)).await {
            sent += 1;
        }
    }

    // Whatever the IK pass left over goes to the XX side as before. A peer the
    // reserve already dialled is excluded explicitly rather than trusting the
    // attempted set alone: a transport error there records no attempt, and the
    // same address must not be charged twice in one pass.
    let xx_candidates = xx_bridge_candidates(
        &state.ember_keyless_peers,
        &state.ember_noise_keys,
        &state.ember_kad_bridge_attempted,
        max_pings.saturating_sub(dialled),
        starved,
    );
    for (ip, port) in xx_candidates {
        if reserved_xx.contains(&(ip, port)) {
            continue;
        }
        if send_ember_bridge_ping(socket, state, ip, port, None).await {
            xx_sent += 1;
            sent += 1;
        }
    }
    if sent > 0 {
        debug!("Ember bridge: pinged {sent} peer(s) to seed the DHT ({xx_sent} over Noise_XX)");
    }
    sent
}

/// Run one Ember DHT maintenance cycle (slice 6): refresh stale buckets,
/// liveness-ping stale contacts, and republish locally-stored records to
/// the current closest nodes. Each task is bounded per cycle and, unless
/// `force` is set (the on-demand dev command), gated on its own staleness
/// interval so the 60-second timer is cheap.
///
/// Returns a tally of what was initiated; the pings/refreshes resolve
/// asynchronously afterwards (eviction happens in the 1-second sweep when
/// a ping goes unanswered).
pub(super) async fn run_ember_maintenance(
    socket: &UdpSocket,
    state: &mut NetworkState,
    force: bool,
) -> EmberMaintenanceResult {
    let mut result = EmberMaintenanceResult::default();

    // 0) Disconnect / empty-table re-arm *before* the bridge. Both paths
    //    clear `ember_kad_bridge_attempted` so the peers we already tried
    //    become candidates again; running the bridge first spent this
    //    cycle's starved budget against the old backoff, then cleared it,
    //    so an "overlay emptied" tick logged `bridge=0` with cached Noise
    //    keys sitting unused. Drop `ember_bridge_fast_at` too, or the 1 Hz
    //    pass still waits out its own 5 s spacing.
    let now_secs = chrono::Utc::now().timestamp();
    {
        // Falling back to the start time matters: a node that has never heard
        // from anyone is exactly the one that most needs the kick, and gating
        // on "we heard something once" skipped it entirely.
        let last_inbound = state.ember_last_inbound.unwrap_or(state.ember_started_at);
        // Debounced against the last re-arm rather than against the inbound
        // clock. Stamping `ember_last_inbound` here was what kept this from
        // firing every tick, at the cost of telling the diagnostics we had just
        // heard from someone when the whole reason we were here is that we had
        // not. A separate stamp buys the same once-per-stretch behaviour and
        // leaves the observation alone.
        let last_rearm = state.ember_rearmed_at.unwrap_or(state.ember_started_at);
        if now_secs.saturating_sub(last_inbound) > EMBER_DISCONNECT_SECS
            && now_secs.saturating_sub(last_rearm) > EMBER_DISCONNECT_SECS
        {
            info!(
                "Ember DHT: no traffic for {}s, re-bootstrapping",
                now_secs.saturating_sub(last_inbound)
            );
            state.ember_self_lookup_done = false;
            state.ember_kad_bridge_attempted.clear();
            state.ember_bridge_fast_at = None;
            state.ember_rendezvous_looked_up_at = 0;
            // A re-bootstrap is a fresh join: an earlier stretch of empty
            // lookups says nothing about the network we are rejoining.
            state.ember_rendezvous_empty_streak = 0;
            // Only re-arm once per silent stretch, not on every tick.
            state.ember_rearmed_at = Some(now_secs);
        }

        let contacts =
            ember_rearm_contact_count(&state.ember_dht, &state.ember_session_dht_contacts);
        // Whether the "overlay just emptied" edge was acted on. It used to be
        // consumed either way, so a transition suppressed by the rate limiter
        // was lost for good: empty at t=100 re-arms, the fresh batch is
        // admitted, all of it is three-struck by t=160, the count returns to
        // zero — but 60s is inside `EMBER_EMPTY_REARM_SECS`, so nothing fires,
        // and with the edge already spent it can never recur. The node then
        // holds a fully-consumed `offered` set and cannot re-dial a single
        // remembered peer for the rest of the session, however reachable they
        // become. This is the cache's only recovery path, so it must survive
        // being rate-limited.
        let mut rearmed = false;
        if contacts == 0
            && state.ember_last_overlay_contacts > 0
            && now_secs.saturating_sub(state.ember_empty_rearmed_at) >= EMBER_EMPTY_REARM_SECS
        {
            rearmed = true;
            info!("Ember DHT: overlay emptied, re-arming bootstrap");
            state.ember_kad_bridge_attempted.clear();
            state.ember_bridge_fast_at = None;
            state.ember_rendezvous_looked_up_at = 0;
            // Let the remembered peers be offered again. Each is handed to the
            // table once per session, which is right while the table still
            // holds them and wrong the moment it does not — a suspend/resume,
            // an interface change or an `ipfilter.dat` reload can empty it, and
            // without this the address book is unusable until a restart.
            state.ember_bootstrap_cache.rearm_offers();
            state.ember_empty_rearmed_at = now_secs;
        }
        // Hold the edge open while it is still pending, so a suppressed
        // transition is retried once the floor passes.
        if contacts > 0 || rearmed {
            state.ember_last_overlay_contacts = contacts;
        }
        // Short of an empty table, re-offer the book on a slow clock while the
        // table is still thin; see `BootstrapCache::rearm_stale_offers`.
        if state.ember_dht.routing().verified_len() < EMBER_KAD_BRIDGE_UNTIL_CONTACTS {
            let reoffered = state
                .ember_bootstrap_cache
                .rearm_stale_offers(now_secs, EMBER_REOFFER_AFTER_SECS);
            if reoffered > 0 {
                debug!("Ember DHT: {reoffered} remembered peer(s) may be offered to the table again");
            }
        }
    }

    // 0a) KAD-bridge bootstrap (slice 13). See `run_ember_kad_bridge`.
    result.kad_bridge_pings_sent =
        run_ember_kad_bridge(socket, state, force, EMBER_KAD_BRIDGE_MAX_PINGS).await;

    // 0a1) Ask friends for contacts, for the friends the bridge above can never
    //      reach: the bridge dials an address from the eD2K hello, and a friend
    //      that named no UDP port or sits behind a relayed session has no such
    //      address. See `ask_friends_for_ember_contacts`. Self-limiting — it
    //      stops entirely once the table holds a working set.
    result.friend_contact_asks = ask_friends_for_ember_contacts(state).await;

    // 0b) Staleness purge. Liveness pings alone need three consecutive
    //     misses to evict, and the ping budget is small, so a contact that
    //     quietly disappeared could hold its slot for hours — blocking the
    //     newcomer that should replace it. Runs before the self-lookup so
    //     that lookup sees a table worth walking.
    //
    //     Held after a gap in these ticks — see `ember_stale_purge_hold`. The
    //     call still runs while held, with an age nothing reaches, because it
    //     is also what repairs timestamps a backwards clock step left in the
    //     future.
    state.ember_stale_purge_held_until = ember_stale_purge_hold(
        state.ember_maint_last_run,
        state.ember_stale_purge_held_until,
        now_secs,
        state.ember_dht.routing().verified_len(),
    );
    state.ember_maint_last_run = Some(now_secs);
    let stale_after = if now_secs < state.ember_stale_purge_held_until {
        i64::MAX
    } else {
        EMBER_CONTACT_STALE_SECS
    };
    let in_use = state.ember_search.nodes_in_use();
    let purged = state
        .ember_dht
        .remove_stale_contacts(now_secs, stale_after, &in_use);
    if purged > 0 {
        state.ember_diagnostics.ember_dht_contacts_evicted = state
            .ember_diagnostics
            .ember_dht_contacts_evicted
            .saturating_add(purged as u32);
    }

    // 0b0) The same purge for the firsthand session contacts that sit beside
    //      the table. Nothing removed one, ever: `record_ember_session_dht_contact`
    //      bounds the map by an LRU at `MAX_EMBER_SESSION_DHT_CONTACTS` and two
    //      ports per host, and the only wholesale clear is on the disable path
    //      that settings can no longer reach. So a LAN peer that went away kept
    //      being counted in the overlay figure the UI shows, kept being pinned
    //      onto every search shortlist — `SearchManager` exempts these from the
    //      k-trim on purpose — kept being offered as a publish target by
    //      `ember_top_up_session_targets`, and kept its known-peer UDP handling,
    //      because `ember_session_introduced` treats presence in this map as its
    //      own justification. A quiet LAN host is the common case here, and 64
    //      slots is few enough that the LRU would not reclaim them for a long
    //      time.
    //
    //      Only contacts that have answered us are aged out. A copy learned from
    //      a LAN `PEER_LIST` arrives with `last_seen == 0`, and that is not
    //      silence — it is a peer we have not asked yet, which the LRU already
    //      ranks first for eviction. Nothing here consults
    //      `SearchManager::nodes_in_use`: a search pins its own copies of these
    //      contacts onto its shortlist when it starts, so a walk in flight
    //      cannot lose a branch to this sweep the way it could to the table's.
    //
    //      Held with the table's purge after a suspend, for the same reason:
    //      the silence is the node's, not theirs. Step 2b asks each of them
    //      while the hold lasts.
    let session_extras_before = state.ember_session_dht_contacts.len();
    if now_secs >= state.ember_stale_purge_held_until {
        state
            .ember_session_dht_contacts
            .retain(|_, c| ember_session_contact_is_live(c, now_secs));
    }
    let session_extras_purged = session_extras_before - state.ember_session_dht_contacts.len();
    if session_extras_purged > 0 {
        debug!(
            "Ember DHT: purged {session_extras_purged} session contact(s) unheard for {}s",
            EMBER_CONTACT_STALE_SECS
        );
    }

    // 0b1) The other direction: residents a tier we have since grown into
    //      would not admit today. Admission has always tightened as the table
    //      fills, but nothing re-read a contact once it held a slot, so a peer
    //      admitted under the cold-start allowance kept its share of a bucket
    //      for the life of the process however crowded its /24 turned out to
    //      be. Runs before the promotion below so the slots it frees are
    //      available to the cache in the same tick.
    // The STORE budget's tier, refreshed here rather than per datagram. It was
    // recomputed on every inbound STORE, and `scale()` walks all 128 buckets —
    // pure waste, since the tier only moves when the verified count crosses 10
    // or 80 and this tick is where that changes. A minute of staleness on a
    // limit that only ever tightens by a third is not worth a table scan per
    // frame.
    state
        .ember_dht_protection
        .set_scale(state.ember_dht.routing().scale());

    let demoted = state.ember_dht.enforce_scale_quotas();
    if demoted > 0 {
        // Not `ember_dht_contacts_evicted`: these peers answered us and are
        // still held in a replacement cache, so counting them as evictions made
        // a table reclaiming its cold-start allowance read exactly like peers
        // going dark.
        state.ember_diagnostics.ember_dht_contacts_demoted = state
            .ember_diagnostics
            .ember_dht_contacts_demoted
            .saturating_add(demoted as u32);
    }

    // Leads parked while the IP filter could not be consulted, plus any the
    // diversity limits turned away when the table was tighter than it is now.
    // Without this the cache only ever drains when a resident contact dies,
    // which on a table with free slots is never.
    let admitted = state.ember_dht.promote_cached_contacts();
    if admitted > 0 {
        debug!("Ember DHT: promoted {admitted} cached contact(s) into free bucket slots");
    }

    // Advertised version ranges follow the table rather than accumulating
    // beside it. Runs after the demote/promote passes so it prunes against the
    // membership this tick settled on, and a peer that comes back through the
    // replacement cache re-advertises on its next ping anyway.
    // Proxy asks and grants sweep here too, because the only other caller runs
    // while we are actively sending `PROXY_STORE` — so a node that stopped
    // publishing (HighID acquired, library unshared, transport disabled) never
    // swept them again and froze the map at its high-water mark for the life of
    // the process. This tick is unconditional.
    state
        .ember_dht
        .prune_proxy_asks(std::time::Instant::now());
    let forgotten = state.ember_dht.prune_peer_versions();
    if forgotten > 0 {
        debug!("Ember DHT: forgot {forgotten} advertised version range(s) for departed peers");
    }

    // 0b2) Top the table up from the remembered set. Runs after the purge and
    //      the eviction sweep it follows, so the slots the last batch just
    //      vacated are refilled in time for this tick's liveness pings.
    //
    //      Only while the table is still short of a working set: once we hold a
    //      bucket's worth of proven contacts, gossip and lookups keep it fed and
    //      dialling an address book is pointless traffic. Each peer is offered
    //      once per session, so this walks steadily through the book instead of
    //      re-dialling whatever died most recently, and stops on its own when
    //      there is nothing left to offer.
    //
    //      Held back while a batch of *ours* is still outstanding, or the
    //      timer's immediate first tick would stack a second batch on the one
    //      seeded at launch and put back the queueing this is here to avoid.
    //      Counted as seeds still sitting unproven in the table, not as bucket
    //      leads at large: gossip is also unverified and arrives far faster, so
    //      measuring all leads let two answered FIND_NODEs pin the gate shut
    //      while the verified count was still nearly zero and leave the rest of
    //      the address book — the entries with real history — undialled.
    let held: HashSet<ember::dht::EmberNodeId> = state
        .ember_dht
        .contacts()
        .into_iter()
        .chain(state.ember_dht.cached_contacts())
        .map(|c| c.node_id)
        .chain(state.ember_session_dht_contacts.values().map(|c| c.node_id))
        .collect();
    // Cache entries count too, or a seed the table parked there is neither
    // re-offered (it is in `held`, which includes the cache) nor counted as
    // outstanding — so it would silently open the gate for another batch.
    let held_leads: HashSet<ember::dht::EmberNodeId> = state
        .ember_dht
        .contacts()
        .into_iter()
        .chain(state.ember_dht.cached_contacts())
        .filter(|c| !c.is_verified())
        .map(|c| c.node_id)
        .collect();
    let outstanding = state.ember_bootstrap_cache.offers_outstanding(&held_leads);
    if state.ember_dht.routing().verified_len() < EMBER_KAD_BRIDGE_UNTIL_CONTACTS
        && outstanding < EMBER_SEED_BATCH
    {
        let local_id = state.ember_dht.local_id();
        // Only what the outstanding seeds leave of one batch, or 31 unproven
        // seeds earned 32 more and the two shared one batch's ping budget.
        let batch = state.ember_bootstrap_cache.seed_batch(
            &local_id,
            &held,
            EMBER_SEED_BATCH - outstanding,
        );
        if !batch.is_empty() {
            let offered_count = batch.len();
            // One at a time through the admission gate, not `load_contacts`:
            // that detaches the range filter, which is right only at startup,
            // where it is fail-closed because `ipfilter.dat` has not parsed yet.
            // By now it has, and bypassing it here would dial addresses the user
            // blocked.
            let mut admitted = Vec::with_capacity(batch.len());
            let mut pressure = Vec::new();
            for contact in batch {
                match state.ember_dht.offer_contact(contact.clone()) {
                    ember::dht::routing::AddResult::Added => admitted.push(contact.node_id),
                    // The bucket is full; the newcomer is parked in its
                    // replacement cache and gets a slot only if the incumbent
                    // fails the probe the table just asked for. Dropping this
                    // would leave it waiting on an eviction nothing triggers.
                    ember::dht::routing::AddResult::PingOldest {
                        addr,
                        node_id,
                        noise_pub,
                    } => pressure.push((addr, node_id, noise_pub)),
                    ember::dht::routing::AddResult::Rejected => {}
                }
            }
            // Only what the table actually took counts as tried. Marking the
            // whole batch would let a book be consumed without a single peer
            // being dialled — a contact the IP policy or a diversity cap
            // refuses never enters the table, so it would never appear in
            // `held_leads` either, and the gate would reopen immediately.
            state
                .ember_bootstrap_cache
                .note_offered(admitted.iter().copied());
            debug!(
                "Ember DHT: offered {offered_count} remembered peer(s) to the routing table, \
                 {} admitted, {} behind a full bucket",
                admitted.len(),
                pressure.len()
            );
            probe_bucket_oldest(socket, state, &pressure, now_secs).await;
        }
    }

    // Announce bookkeeping only means anything for contacts we still hold,
    // and under churn it would otherwise accumulate an entry per peer we
    // ever met.
    if !state.ember_announced_at.is_empty() {
        let mut live: HashSet<ember::dht::EmberNodeId> = state
            .ember_dht
            .contacts()
            .into_iter()
            .map(|c| c.node_id)
            .collect();
        live.extend(state.ember_session_dht_contacts.values().map(|c| c.node_id));
        state.ember_announced_at.retain(|id, _| live.contains(id));
    }

    // 0c) Self-lookup. Filling the buckets nearest our own ID is what makes
    //     store responsibility meaningful, so it is worth an explicit lookup
    //     rather than waiting for generic refresh to wander there.
    let verified = state.ember_dht.routing().verified_len();
    let since_start = now_secs.saturating_sub(state.ember_started_at);
    let first_due = !state.ember_self_lookup_done
        && (since_start >= EMBER_SELF_LOOKUP_FIRST_DELAY_SECS
            || ((verified >= EMBER_SELF_LOOKUP_WARM_VERIFIED
                || ember_overlay_contact_count(state) > 0)
                && since_start >= EMBER_SELF_LOOKUP_WARM_DELAY_SECS));
    let repeat_due = state.ember_self_lookup_done
        && now_secs.saturating_sub(state.ember_last_self_lookup) >= EMBER_SELF_LOOKUP_REPEAT_SECS;
    if ember_overlay_contact_count(state) > 0 && (force || first_due || repeat_due) {
        let self_target = state.ember_dht.local_id();
        if let Some(search_id) = start_ember_background_find_node(state, self_target) {
            state.ember_self_lookup_done = true;
            state.ember_last_self_lookup = now_secs;
            result.buckets_refreshed += 1;
            debug!("Ember DHT: self-lookup for {self_target} to fill close-to-home buckets");
            drive_ember_search(socket, state, search_id).await;
        }
    }

    // 1) Bucket refresh — a random-target FIND_NODE per stale bucket keeps
    //    the table broad and current. The launched searches have no
    //    waiter; their side effect (learning contacts, marking the bucket
    //    active) is the point.
    let buckets = state.ember_dht.buckets_for_refresh(
        EMBER_BUCKET_REFRESH_SECS,
        EMBER_MAINT_MAX_REFRESH,
        force,
    );
    for bucket_idx in buckets {
        let target = state.ember_dht.random_target_in_bucket(bucket_idx);
        if let Some(search_id) = start_ember_background_find_node(state, target) {
            result.buckets_refreshed += 1;
            state.ember_diagnostics.ember_dht_refreshes = state
                .ember_diagnostics
                .ember_dht_refreshes
                .saturating_add(1);
            drive_ember_search(socket, state, search_id).await;
        } else {
            // Search cap reached — stop trying to refresh more this cycle.
            break;
        }
    }

    // 1b) Publish-target lookups — resolve the nodes genuinely closest to keys
    //     we publish under, a few per cycle, so republishes stop relying on
    //     our own table's answer for a distant key. Same shape as a bucket
    //     refresh: the search has no waiter, and `maybe_finish_ember_search`
    //     files the result under the key it was resolving.
    //
    //     Skip while nobody has answered: the first publish tick queues every
    //     selected key, and with only the nodes_ember.dat lead to ask, those
    //     FIND_NODEs are two more unanswered queries on the same handshake
    //     that the liveness ping is already waiting on.
    if state.ember_dht.routing().verified_len() > 0 {
        let lookups = ember_target_lookups_this_cycle(state.ember_publish_target_queue.len());
        for _ in 0..lookups {
            let Some(key) = state.ember_publish_target_queue.pop_front() else {
                break;
            };
            let target = ember::dht::EmberNodeId(key);
            match start_ember_background_find_node(state, target) {
                Some(search_id) => {
                    state.ember_publish_target_lookups.insert(search_id, key);
                    drive_ember_search(socket, state, search_id).await;
                }
                None => {
                    // Search cap reached. Put it back so the key is not silently
                    // dropped from the rotation, and stop for this cycle.
                    state.ember_publish_target_queue.push_front(key);
                    break;
                }
            }
        }
    }

    // 2) Liveness pings — probe contacts we haven't heard from recently.
    //    A PONG refreshes the contact; silence past EMBER_MAINT_PING_TIMEOUT
    //    faults it (and eventually evicts it) in the 1-second sweep.
    let now = chrono::Utc::now().timestamp();
    let ping_budget = ember_maint_ping_budget(
        state.ember_dht.routing().verified_len(),
        state.ember_dht.contact_count(),
    );
    let due =
        state
            .ember_dht
            .contacts_due_for_ping(now, EMBER_CONTACT_PING_SECS, ping_budget, force);
    for contact in due {
        // One probe per contact at a time. The gossip-probe and bucket-pressure
        // paths already check this; without it here, a contact could carry two
        // outstanding pings and be charged two strikes for one silence.
        if state
            .ember_dht_maint_pings
            .values()
            .any(|p| p.node_id == contact.node_id)
        {
            continue;
        }
        if ember_addr_banned(state, contact.addr) {
            fault_ember_contact(state, &contact.node_id, "banned");
            continue;
        }
        let (wire_req_id, frame) = state.ember_dht.build_ping();
        let mut behind_handshake = false;
        let mut delivery_certain = true;
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
                            "Ember DHT maintenance: ping to {} failed: {e}",
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
                            "Ember DHT maintenance: ping to {} failed: {e}",
                            contact.addr
                        );
                        false
                    }
                }
            }
            ember::transport::OutgoingResult::Queued => {
                behind_handshake = true;
                // See `probe_bucket_oldest`: parked behind a handshake that may
                // complete with a different identity, in which case this frame
                // is dropped at flush rather than sent. Neither booked nor
                // faulted — the next cycle re-pings it, by which time the
                // handshake has resolved one way or the other.
                delivery_certain = state
                    .ember_transport
                    .queued_delivery_is_certain(contact.addr, &contact.noise_pub);
                true
            }
            ember::transport::OutgoingResult::Error(e) => {
                debug!(
                    "Ember DHT maintenance: transport error pinging {}: {e}",
                    contact.addr
                );
                false
            }
        };
        if send_ok && delivery_certain {
            state.ember_dht_maint_pings.insert(
                wire_req_id,
                new_ember_maint_ping(contact.node_id, behind_handshake, now),
            );
            result.liveness_pings_sent += 1;
            state.ember_diagnostics.ember_dht_liveness_pings_sent = state
                .ember_diagnostics
                .ember_dht_liveness_pings_sent
                .saturating_add(1);
        } else if !send_ok {
            // A contact we cannot even transmit to is as dead as one that
            // never answers, and it is the only case the timeout sweep can't
            // see: with no pending entry recorded, nothing would ever fault
            // it. It would then hold its bucket slot forever, and because a
            // full bucket makes every newcomer wait on a probe to the oldest
            // contact, one unreachable entry can keep real peers out
            // permanently. An address family the socket cannot dial (an IPv6
            // contact learned by gossip on an IPv4 socket) fails here every
            // single time.
            fault_ember_contact(state, &contact.node_id, "unreachable");
        }
    }

    // 2b) The session contacts beside the table, while the staleness purge is
    //     held. No liveness ping reaches them otherwise, and any signed frame
    //     they send renews their entry, so without an ask each one that went
    //     quiet only because we were asleep would be purged when the hold
    //     lifts. Once per hold: there are at most
    //     `MAX_EMBER_SESSION_DHT_CONTACTS`, and an answer is all it takes.
    if now < state.ember_stale_purge_held_until {
        let quiet = ember_session_contacts_to_ask_during_hold(
            &state.ember_session_dht_contacts,
            &state.ember_session_hold_pinged,
            now,
        );
        for contact in quiet {
            let std::net::IpAddr::V4(ip) = contact.addr.ip() else {
                continue;
            };
            state
                .ember_session_hold_pinged
                .insert((ip, contact.addr.port()));
            let (_, frame) = state.ember_dht.build_ping();
            match state.ember_transport.prepare_outgoing(
                contact.addr,
                Some(&contact.noise_pub),
                &frame,
            ) {
                ember::transport::OutgoingResult::Ready { packet }
                | ember::transport::OutgoingResult::HandshakeStarted { packet } => {
                    if let Err(e) =
                        send_ember_udp(socket, &packet, contact.addr, &state.ember_dht_overhead)
                            .await
                    {
                        debug!(
                            "Ember DHT maintenance: session ping to {} failed: {e}",
                            contact.addr
                        );
                    }
                }
                ember::transport::OutgoingResult::Queued => {}
                ember::transport::OutgoingResult::Error(e) => {
                    debug!(
                        "Ember DHT maintenance: transport error pinging session contact {}: {e}",
                        contact.addr
                    );
                }
            }
        }
    } else {
        state.ember_session_hold_pinged.clear();
    }

    // 3) Republish — re-store records we hold to the current closest nodes
    //    so they survive churn (Kademlia replication).
    //
    //    Queued through the batch publisher rather than opened as one publish
    //    operation each. A per-record operation costs k datagrams and one of
    //    the 128 concurrent publish slots, so at this budget most records
    //    would be refused a slot outright and the rest would arrive as a
    //    burst far past what a peer accepts per second — the records would be
    //    dropped, unacked, and retried forever.
    //    Sized from what the flush can actually deliver, and yielding to our
    //    own publishing.
    //
    //    This shares one queue — and one backpressure gate — with source and
    //    keyword publishing, but took a flat `EMBER_MAINT_MAX_REPUBLISH` while
    //    both of those size themselves from the routing table. On a small table
    //    that over-subscribes badly: twenty or fewer contacts means every peer
    //    receives every record, so the whole tick lands on each of them against
    //    a per-peer minute budget. The surplus was dropped by carry-over, and
    //    `mark_republish_due` below makes a dropped replication record due again
    //    on the very next tick regardless of the interval — so the queue settled
    //    above the backpressure threshold and stayed there, at which point both
    //    `maybe_publish_ember_sources` and `maybe_publish_ember_keywords`
    //    returned without selecting anything, every tick. A node holding a large
    //    foreign store therefore stopped publishing its *own* files while
    //    spending its uplink re-sending other people's records it could never
    //    drain.
    //
    //    Half the deliverable budget, because replication is altruistic churn
    //    coverage while our own records are what the user actually shared; and
    //    nothing at all while the queue is already backed up, so replication can
    //    never be the reason our own publishing is skipped.
    let republish_interval = std::time::Duration::from_secs(EMBER_RECORD_REPUBLISH_SECS);
    result.republish_due = state.ember_dht.republish_backlog(republish_interval);
    let republish_budget = if ember_publish_queue_is_backed_up(state) {
        0
    } else {
        (ember_deliverable_records_per_tick(ember_publishable_peer_count(state)) / 2)
            .min(EMBER_MAINT_MAX_REPUBLISH)
    };
    let republish_batch = if republish_budget == 0 {
        Vec::new()
    } else {
        state
            .ember_dht
            .take_republish_batch(republish_interval, republish_budget, force)
    };
    result.republish_selected = republish_batch.len();
    for (data, signature) in republish_batch {
        let record = match ember::dht::publish::SignedRecord::from_wire(&data, signature) {
            Some(r) => r,
            None => {
                // take_republish_batch already stamped last_republished.
                if data.len() >= 17 {
                    let mut key = [0u8; 16];
                    key.copy_from_slice(&data[1..17]);
                    state.ember_dht.mark_republish_due(&key, &signature);
                    result.republish_rearmed += 1;
                }
                continue;
            }
        };
        let targets = ember_overlay_publish_targets_within(state, record.keyword_hash, 0);
        // Replication carries someone else's record, so there is no local
        // file schedule to advance; the reference is only used to line the
        // ack bitmap up.
        let reference = EmberRecordRef {
            file_hash: record.file_hash,
            kind: EmberPublishKind::Replication,
            key: record.keyword_hash,
        };
        if state.ember_batch_publish.enqueue(
            &targets,
            reference,
            ember::dht::messages::BatchedRecord {
                key: record.keyword_hash,
                record: record.data.clone(),
                record_signature: record.signature,
            },
        ) {
            result.records_republished += 1;
            state.ember_diagnostics.ember_dht_records_republished = state
                .ember_diagnostics
                .ember_dht_records_republished
                .saturating_add(1);
        } else {
            // The batch already stamped this record as republished, so
            // without re-arming it the drop would cost a full republish
            // interval of silence for a record we still hold.
            state
                .ember_dht
                .mark_republish_due(&record.keyword_hash, &record.signature);
            result.republish_rearmed += 1;
        }
    }
    flush_ember_batch_publish(socket, state).await;

    // 4) Peer announce — exchange contact lists with a few live peers so
    //    the table fills beyond FIND_NODE lookup paths (churn recovery).
    //
    //    Chosen by least-recently-announced, not by freshest `last_seen`.
    //    Announcing produces a PEER_LIST reply, which refreshes that
    //    contact's `last_seen`, so "freshest first" made the same two peers
    //    the freshest again every cycle and pinned the mechanism to them for
    //    the life of the process.
    let announce_budget =
        if state.ember_dht.routing().verified_len() < EMBER_KAD_BRIDGE_UNTIL_CONTACTS {
            EMBER_MAINT_MAX_ANNOUNCE_STARVED
        } else {
            EMBER_MAINT_MAX_ANNOUNCE
        };
    let announce_targets = ember_dht_announce_targets(
        state.ember_dht.contacts(),
        &state.ember_session_dht_contacts,
        &state.ember_announced_at,
        state.ember_dht.local_id(),
        announce_budget,
    );
    for contact in announce_targets {
        if send_ember_announce_peer(socket, state, &contact).await {
            result.announces_sent += 1;
        }
    }

    let verified_now = ember_dht_ui_contact_counts(state).1;
    if note_ember_verified_contacts(&mut state.ember_verified_highwater, verified_now) {
        state.ember_verified_highwater_dirty = true;
    }
    if state.ember_verified_highwater_dirty {
        // A write still in flight keeps the flag set, so the next cycle saves
        // whatever has changed since.
        if let Ok(ownership) = state.ember_highwater_save_lock.clone().try_lock_owned() {
            let path = ember_highwater_path(&state.data_dir);
            let hw = state.ember_verified_highwater.clone();
            tokio::task::spawn_blocking(move || {
                let _ownership = ownership;
                save_ember_verified_highwater(&path, &hw);
            });
            state.ember_verified_highwater_dirty = false;
        }
    }
    if state.ember_source_address_dirty {
        if let Ok(ownership) = state.ember_source_address_save_lock.clone().try_lock_owned() {
            let path = ember_source_address_path(&state.data_dir);
            let address = state.ember_source_address;
            tokio::task::spawn_blocking(move || {
                let _ownership = ownership;
                save_ember_source_address(&path, &address);
            });
            state.ember_source_address_dirty = false;
        }
    }

    // Introducer records only change on a probe outcome, and pruning them is
    // per-cycle work, so the gauge is refreshed here rather than per frame.
    let prune_now = std::time::Instant::now();
    state.ember_gossip_reputation.prune(prune_now);
    let introducers_rationed = state.ember_gossip_reputation.rationed_len() as u32;
    state
        .ember_diagnostics
        .ember_dht_gossip_introducers_rationed = introducers_rationed;

    // The friend contact-exchange throttles, by age rather than by which
    // sessions are still live, so neither needs a session lock to bound. The
    // ask side outlives its own interval because it doubles as the rotation
    // key — see `EMBER_FRIEND_CONTACT_STAMP_TTL`. Runs outside the starved gate
    // above, or a node that recovered would keep whatever it had asked for the
    // life of the process.
    state
        .ember_friend_contacts_asked
        .retain(|_, at| prune_now.saturating_duration_since(*at) < EMBER_FRIEND_CONTACT_STAMP_TTL);
    state.ember_friend_contacts_served.retain(|_, at| {
        prune_now.saturating_duration_since(*at) < EMBER_FRIEND_CONTACT_SERVE_INTERVAL
    });

    // Everything the overlay's health depends on, in one line. A node that is
    // not growing is the hard case to diagnose from the outside: "1 contact"
    // alone cannot distinguish "nobody is telling us about anyone" from "we
    // are told and cannot reach them" from "we never ask". Announces, leads,
    // and bridge/rendezvous state separate those three.
    let verified_now_len = state.ember_dht.routing().verified_len();
    info!(
        "Ember DHT cycle: contacts={} ({verified_now_len} verified, {} leads, {} session), \
         announced={}, peer_lists={}, gossip={} (new {}, refused {}, rationed {} from {} \
         introducer(s)), pings={}, bridge={}, friend_asks={}, \
         noise_keys={}, keyless={}, records due={} selected={} queued={} re-armed={} \
         backlog={}",
        state.ember_dht.contact_count(),
        state
            .ember_dht
            .contact_count()
            .saturating_sub(verified_now_len),
        state.ember_session_dht_contacts.len(),
        result.announces_sent,
        state.ember_diagnostics.ember_dht_peer_lists_received,
        state.ember_diagnostics.ember_dht_gossip_contacts,
        state.ember_diagnostics.ember_dht_gossip_new,
        state.ember_diagnostics.ember_dht_gossip_refused,
        state.ember_diagnostics.ember_dht_gossip_leads_rationed,
        introducers_rationed,
        result.liveness_pings_sent,
        result.kad_bridge_pings_sent,
        result.friend_contact_asks,
        state.ember_noise_keys.len(),
        state.ember_keyless_peers.len(),
        result.republish_due,
        result.republish_selected,
        result.records_republished,
        result.republish_rearmed,
        state
            .ember_dht
            .republish_backlog(std::time::Duration::from_secs(EMBER_RECORD_REPUBLISH_SECS)),
    );

    result
}

/// Whether `EmberDht::handle_incoming` reads `session_contacts` for a frame of
/// this type. Only the requests it answers with a contact list do, so every
/// other frame can skip copying the session map. Keep in step with the engine's
/// `closest_excluding` callers.
pub(super) fn ember_dht_frame_reads_session_contacts(msg_type: u8) -> bool {
    matches!(
        msg_type,
        ember::dht::messages::MSG_FIND_NODE
            | ember::dht::messages::MSG_ANNOUNCE_PEER
            | ember::dht::messages::MSG_FIND_VALUE
    )
}

/// Handle one decrypted Ember DHT frame: feed it to the DHT engine
/// (which verifies the signature/identity binding, learns the sender as
/// a contact, and produces any signed reply), then encrypt and send the
/// replies back over the Noise session and update counters / pending
/// pings.
pub(super) async fn handle_ember_dht_message(
    socket: &UdpSocket,
    payload: &[u8],
    from: SocketAddr,
    remote_noise_pub: [u8; 32],
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
) {
    // Slice 14: per-IP rate limit before any crypto/table work. Wire layout
    // is version(1) + msg_type(1) + …; a truncated frame is dropped by the
    // engine anyway.
    let msg_type = payload.get(1).copied().unwrap_or(0);
    let is_store = matches!(
        msg_type,
        ember::dht::messages::MSG_STORE_RECORD
            | ember::dht::messages::MSG_PROXY_STORE
            | ember::dht::messages::MSG_STORE_BATCH
    );

    // The flat per-address frame gate first, before anything expensive. Only
    // STORE traffic needs the identity lookup below, and that walks the whole
    // routing table: leaving it in front of the gate meant a peer already over
    // its frame rate still bought a table scan per datagram, which is the
    // opposite of what a gate that exists to make junk cheap to reject is for.
    // Channel frames carry room transfers and have a budget of their own.
    let admitted = if matches!(
        msg_type,
        ember::dht::messages::MSG_CHANNEL_MSG | ember::dht::messages::MSG_CHANNEL_RELAY
    ) {
        state.ember_dht_protection.allow_channel_frame(from.ip())
    } else {
        state.ember_dht_protection.allow_frame(from.ip())
    };
    if !admitted {
        return;
    }

    let (known_sender, store_records, held_at_from) = if is_store {
        // Prefer the peer's cryptographic identity for the STORE budget when
        // we already know it, so several genuine peers behind one NAT do not
        // share (and exhaust) a single allowance.
        //
        // Which identity is decided by the Noise session, not by the address
        // alone. `contact_at` falls back to an unverified gossip entry, and
        // gossip names both an address and a node ID: a peer could have a
        // victim announced at its own address and then have its STORE traffic —
        // including frames that never pass signature verification — charged to
        // the victim's allowance, so the victim's real publishes were refused
        // here. Requiring a contact we have actually heard from *and* whose
        // static key matches this session ties the budget to the peer that
        // encrypted the frame. Anyone else falls back to the address budget,
        // which is where an unproven sender belongs.
        let held = state.ember_dht.routing().contact_at(from);
        let sender = held
            .filter(|c| c.is_verified() && c.noise_pub == remote_noise_pub)
            .map(|c| c.node_id.0);
        // A batch's record count is its first payload byte. Reading it here
        // is what lets the budget be charged for the work the frame implies
        // rather than for the frame itself; the decoder re-validates it.
        let records = if msg_type == ember::dht::messages::MSG_STORE_BATCH {
            ember::dht::messages::peek_store_batch_count(payload).unwrap_or(1)
        } else {
            1
        };
        (sender, records, Some(held.is_some()))
    } else {
        (None, 0, None)
    };

    if !state
        .ember_dht_protection
        .allow_typed(from.ip(), msg_type, known_sender, store_records)
    {
        return;
    }

    let now = chrono::Utc::now().timestamp();
    // Whether this address was a stranger, read before `handle_message`, which
    // adds the asker to the routing table at its top. Nothing between the STORE
    // lookup above and here touches the table, so that answer still holds.
    let was_stranger =
        !held_at_from.unwrap_or_else(|| state.ember_dht.routing().contact_at(from).is_some());
    let session_extras: Vec<_> = if ember_dht_frame_reads_session_contacts(msg_type)
        && ember_share_session_contacts_with(from)
    {
        state
            .ember_session_dht_contacts
            .values()
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    refresh_ember_advertised_buddy(state);
    let inbound = state.ember_dht.handle_incoming(
        payload,
        from,
        remote_noise_pub,
        now,
        &session_extras,
    );

    // Read now, before the handlers below consume the pending query a
    // FOUND_NODE answers.
    let leads_asked_for = ember_leads_were_asked_for(state, &inbound, from, now);
    if ember_reply_was_solicited(state, &inbound, from) {
        if let Some(id) = inbound.sender_id {
            state.ember_dht.note_answered(id, std::time::Instant::now());
        }
    }

    // A STORE that did not authenticate cost nothing the budget exists to
    // ration, so give the charge back. `sender_id` is set for every frame that
    // decoded, so its absence here is precisely "the version, the signature, the
    // session binding or the identity binding was wrong". See
    // `DhtProtection::refund_store`.
    if is_store && inbound.sender_id.is_none() {
        state
            .ember_dht_protection
            .refund_store(from.ip(), msg_type, known_sender, store_records);
    }

    // Any frame that decoded proves the DHT is still reachable; prolonged
    // silence is what triggers a re-bootstrap in the maintenance loop.
    if inbound.sender_id.is_some() {
        state.ember_last_inbound = Some(now);
        // It also proves *this* peer is reachable, so it must not keep an
        // unanswered-ping count. The bridge does not exclude peers we already
        // hold a contact for, so a peer that answers is re-dialled on every
        // expiry and was accumulating strikes for pings it had in fact
        // answered — pushing the peers most likely to respond out to the 300s
        // ceiling. That is exactly backwards, and it bit hardest right after a
        // staleness eviction, when re-bridging a known-good peer is the fastest
        // way back.
        if let std::net::IpAddr::V4(v4) = from.ip() {
            state.ember_kad_bridge_attempted.remove(&(v4, from.port()));
        }
        // And if this peer was a lead somebody named, that name has just been
        // shown to be worth something. Any signed frame counts, not only the
        // `PONG`: what the probe was asking is whether the address is real —
        // which is also why it only counts from the address that was named.
        if let Some(id) = inbound.sender_id {
            state.ember_gossip_reputation.note_answered(&id, from);
        }
    }
    if let Some(contact) = inbound.sender_contact.clone() {
        remember_ember_session_dht_contact(state, contact);
    }
    // Counted before admission, and separately from the frames that carried
    // them: "nobody answered our announce" and "everyone answered with an
    // empty list" both leave the table flat and need different fixes.
    if inbound.peer_list.is_some() {
        state.ember_diagnostics.ember_dht_peer_lists_received = state
            .ember_diagnostics
            .ember_dht_peer_lists_received
            .saturating_add(1);
    }
    if !inbound.gossip_leads.is_empty() {
        state.ember_diagnostics.ember_dht_gossip_contacts = state
            .ember_diagnostics
            .ember_dht_gossip_contacts
            .saturating_add(inbound.gossip_leads.len().min(u32::MAX as usize) as u32);
        state.ember_diagnostics.ember_dht_gossip_new = state
            .ember_diagnostics
            .ember_dht_gossip_new
            .saturating_add(inbound.gossip_new);
        state.ember_diagnostics.ember_dht_gossip_refused = state
            .ember_diagnostics
            .ember_dht_gossip_refused
            .saturating_add(inbound.gossip_refused);
    }
    remember_ember_lan_gossip(state, &inbound.gossip_leads, from);

    // A PING from a public address we have neither a contact for nor ever dialled
    // is evidence our own UDP port is open to the internet: it cannot be an
    // answer to anything of ours, and it arrived inside a Noise session, so its
    // source was not spoofed. That leaves no NAT mapping of ours for it to have
    // come through.
    //
    // "Never dialled" has to be asked separately, because the routing table does
    // not answer it. Several paths deliberately send to peers we hold no contact
    // for: both bootstrap bridges ping addresses harvested from KAD, which carry a
    // Noise key but no node ID, and an iterative search dials whatever its
    // shortlist holds — including contacts that arrived by gossip and were then
    // refused a bucket by the diversity caps or the IP filter. Any of those can
    // ping us back through the mapping we just opened and arrive looking like a
    // stranger. Believing that drops `SOURCE_FLAG_FIREWALLED` and the buddy
    // fan-out from a node whose port is in fact filtered, withdrawing the relay
    // path from exactly the peers who need it.
    //
    // Two sources answer it, and neither is complete on its own. The transport
    // records every address Ember dialled, which covers searches and both bridges,
    // and every address QUIC sent to while it shares this socket (relays, sources,
    // friend punches, attachments, room streams).
    // But Ember rides the KAD socket, so a KAD query to the same host opens the very
    // mapping in question — `has_recent_ip` is KAD's own record of that, written
    // only for outbound requests.
    //
    // Even together they are not exhaustive: eD2K peer-UDP replies leave from the
    // same port and are tracked by neither, and there are 39 send sites on that
    // socket with no choke point to hang this on. Two attempts at enumerating the
    // dials have now each missed a path, so the rule does not rely on the
    // enumeration being complete. It requires two *different* stranger addresses
    // instead: one uncovered dial can no longer be mistaken for proof on its own,
    // since a false positive would need two of them, from two hosts, inside the
    // same window. The cost of being wrong is why — dropping
    // `SOURCE_FLAG_FIREWALLED` and the buddy fan-out on a node whose port is in
    // fact filtered puts an unreachable address into source lists and withdraws
    // the relay path from exactly the peer that needed it.
    let unsolicited = inbound.ping_received
        && was_stranger
        && !state.ember_transport.recently_dialled(from.ip())
        && !state.flood_protection.has_recent_ip(from.ip())
        && !crate::security::is_private_ip(from.ip());
    if unsolicited {
        // A witness older than the conclusion's own TTL is not evidence any more,
        // so it is replaced rather than paired with. Two sightings hours apart
        // would otherwise satisfy a rule whose whole point is that one uncovered
        // dial must not be mistaken for proof: the enumeration of paths that dial
        // strangers is known to be incomplete, so over a long enough session two
        // of them are ordinary rather than corroborating.
        let witness = state
            .ember_reach_witness
            .filter(|(_, at)| now.saturating_sub(*at) < EMBER_UDP_REACHABLE_TTL_SECS);
        match witness {
            Some((first, _)) if ember_reach_witnesses_independent(first, from.ip()) => {
                if state.ember_udp_reachable_at.is_none() {
                    info!(
                        "Ember DHT: strangers at {first} and {} both reached us unsolicited, \
                         treating our UDP port as open",
                        from.ip()
                    );
                }
                state.ember_udp_reachable_at = Some(now);
                state.ember_reach_external_ip = state.external_ip;
            }
            Some(_) => {}
            None => {
                state.ember_reach_witness = Some((from.ip(), now));
                state.ember_reach_external_ip = state.external_ip;
            }
        }
    }

    if inbound.store_replay_rejected {
        state.ember_diagnostics.ember_dht_store_replays = state
            .ember_diagnostics
            .ember_dht_store_replays
            .saturating_add(1);
    }

    if let Some(version) = inbound.version_mismatch {
        state.ember_diagnostics.ember_dht_version_mismatch = state
            .ember_diagnostics
            .ember_dht_version_mismatch
            .saturating_add(1);
        if ember::dht::messages::dht_version_is_newer_than_us(version) {
            state.ember_diagnostics.ember_dht_version_peer_newer = state
                .ember_diagnostics
                .ember_dht_version_peer_newer
                .saturating_add(1);
        } else {
            state.ember_diagnostics.ember_dht_version_peer_older = state
                .ember_diagnostics
                .ember_dht_version_peer_older
                .saturating_add(1);
        }
        debug!(
            "Ember DHT: dropping frame from {from}: unsupported version {version} \
             (this build speaks {}..={})",
            ember::dht::EMBER_DHT_MIN_VERSION,
            ember::dht::EMBER_DHT_VERSION
        );
        return;
    }

    if let Some(err) = inbound.error {
        state.ember_diagnostics.ember_dht_malformed = state
            .ember_diagnostics
            .ember_dht_malformed
            .saturating_add(1);
        debug!("Ember DHT: dropping frame from {from}: {err}");
        return;
    }

    if inbound.ping_received {
        state.ember_diagnostics.ember_dht_pings_received = state
            .ember_diagnostics
            .ember_dht_pings_received
            .saturating_add(1);
    }

    if inbound.find_node_received {
        state.ember_diagnostics.ember_dht_find_nodes_received = state
            .ember_diagnostics
            .ember_dht_find_nodes_received
            .saturating_add(1);
    }

    if inbound.stored_record {
        // Count records, not frames: a batch stores many at once, and the
        // acked counter on the publishing side counts records too, so
        // measuring frames here would make the two incomparable.
        let stored = inbound.batch_records_stored.max(1) as u32;
        state.ember_diagnostics.ember_dht_stores_received = state
            .ember_diagnostics
            .ember_dht_stores_received
            .saturating_add(stored);
    }

    if inbound.find_value_received {
        state.ember_diagnostics.ember_dht_find_values_received = state
            .ember_diagnostics
            .ember_dht_find_values_received
            .saturating_add(1);
        if inbound.find_value_hit {
            state.ember_diagnostics.ember_dht_find_value_hits = state
                .ember_diagnostics
                .ember_dht_find_value_hits
                .saturating_add(1);
            if inbound.find_value_withheld > 0 {
                state.ember_diagnostics.ember_dht_found_value_truncated = state
                    .ember_diagnostics
                    .ember_dht_found_value_truncated
                    .saturating_add(1);
                state.ember_diagnostics.ember_dht_found_value_withheld = state
                    .ember_diagnostics
                    .ember_dht_found_value_withheld
                    .saturating_add(u32::from(inbound.find_value_withheld));
            }
        } else {
            state.ember_diagnostics.ember_dht_find_value_misses = state
                .ember_diagnostics
                .ember_dht_find_value_misses
                .saturating_add(1);
        }
    }

    // Buddy accepted a PROXY_STORE: fan the publisher-signed firewalled
    // source record out via the normal publish driver. Charge budget and
    // remember the publisher only after start_publish_to succeeds so a full
    // publish table does not spend quota on a silent drop.
    //
    // When file uploads already own a configured cap, skip the fan-out
    // (and the ACK). The publisher retries; taking the uplink now would
    // steal tokens from peers we are already serving.
    if let Some((proxy_rid, forward)) = inbound.proxy_store_forward {
        if bandwidth_limiter.file_uploads_own_uplink() {
            debug!(
                "Ember DHT: deferring PROXY_STORE fan-out from {from}; file uploads own the uplink"
            );
        } else if let Some(publisher) = inbound.sender_id {
            let now_inst = std::time::Instant::now();
            if state.ember_dht.can_accept_proxy_forward(publisher, from.ip(), now_inst) {
                let key = forward.keyword_hash;
                let targets =
                    ember_overlay_publish_targets_within(state, key, EMBER_FORWARDED_TARGET_QUEUE_MAX);
                let replica = forward.clone();
                if let Some(publish_id) =
                    state.ember_publish.start_publish_to(forward, targets)
                {
                    if state.ember_dht.commit_proxy_store(
                        publisher,
                        from,
                        remote_noise_pub,
                        &replica,
                        now_inst,
                    ) {
                        state.ember_diagnostics.ember_dht_buddy_forwards = state
                            .ember_diagnostics
                            .ember_dht_buddy_forwards
                            .saturating_add(1);
                        drive_ember_publish(socket, state, publish_id).await;
                        let ack_bytes =
                            state.ember_dht.build_proxy_store_ack_frame(proxy_rid, key);
                        match state.ember_transport.prepare_outgoing(
                            from,
                            Some(&remote_noise_pub),
                            &ack_bytes,
                        ) {
                            ember::transport::OutgoingResult::Ready { packet }
                            | ember::transport::OutgoingResult::HandshakeStarted { packet } => {
                                if let Err(e) = send_ember_udp(
                                    socket,
                                    &packet,
                                    from,
                                    &state.ember_dht_overhead,
                                )
                                .await
                                {
                                    debug!(
                                        "Ember DHT: failed to send PROXY_STORE_ACK to {from}: {e}"
                                    );
                                }
                            }
                            ember::transport::OutgoingResult::Queued => {
                                debug!(
                                    "Ember DHT: PROXY_STORE_ACK to {from} queued behind handshake"
                                );
                            }
                            ember::transport::OutgoingResult::Error(e) => {
                                debug!(
                                    "Ember DHT: transport error sending PROXY_STORE_ACK to {from}: {e}"
                                );
                            }
                        }
                    } else {
                        // Slot was granted; replica/budget refused. Free it so
                        // a failed store cannot occupy the publish table until
                        // PUBLISH_TIMEOUT_SECS.
                        let _ = state.ember_publish.remove(publish_id);
                    }
                }
            }
        }
    }

    if let Some((dest, noise, frame)) = inbound.callback_forward {
        match state
            .ember_transport
            .prepare_outgoing(dest, Some(&noise), &frame)
        {
            ember::transport::OutgoingResult::Ready { packet }
            | ember::transport::OutgoingResult::HandshakeStarted { packet } => {
                if send_ember_udp(socket, &packet, dest, &state.ember_dht_overhead)
                    .await
                    .is_ok()
                {
                    state.ember_diagnostics.ember_dht_callback_forwards = state
                        .ember_diagnostics
                        .ember_dht_callback_forwards
                        .saturating_add(1);
                }
            }
            ember::transport::OutgoingResult::Queued => {
                state.ember_diagnostics.ember_dht_callback_forwards = state
                    .ember_diagnostics
                    .ember_dht_callback_forwards
                    .saturating_add(1);
            }
            ember::transport::OutgoingResult::Error(_) => {}
        }
    }

    if let Some(connect) = inbound.callback_connect {
        state.ember_pending_callback_connects.push(connect);
    }

    if let (Some(rid), Some(sender)) = (inbound.proxy_store_ack, inbound.sender_id) {
        flush_ember_proxy_overlay_ack(socket, state, sender, rid).await;
    }

    // Encrypt and send any signed DHT replies (e.g. the PONG answering
    // a PING, the FOUND_NODE answering a FIND_NODE, or the STORE_ACK /
    // FOUND_VALUE answering a STORE / FIND_VALUE) back over the
    // established session.
    for resp in &inbound.responses {
        match state
            .ember_transport
            .prepare_outgoing(from, Some(&remote_noise_pub), resp)
        {
            ember::transport::OutgoingResult::Ready { packet }
            | ember::transport::OutgoingResult::HandshakeStarted { packet } => {
                if let Err(e) =
                    send_ember_udp(socket, &packet, from, &state.ember_dht_overhead).await
                {
                    debug!("Ember DHT: failed to send reply to {from}: {e}");
                }
            }
            ember::transport::OutgoingResult::Queued => {}
            ember::transport::OutgoingResult::Error(e) => {
                debug!("Ember DHT: transport error sending reply to {from}: {e}");
            }
        }
    }

    probe_bucket_oldest(socket, state, &inbound.ping_oldest, now).await;

    // While the public table is still too thin to run lookups, ask this
    // peer for their contact list now instead of waiting for the 60s tick.
    // A session-only friend (LAN with `block_private_ips`) was previously
    // never an announce target at all.
    if inbound.sender_id.is_some()
        && state.ember_dht.routing().verified_len() < EMBER_KAD_BRIDGE_UNTIL_CONTACTS
    {
        if let Some(contact) = inbound.sender_contact.clone() {
            if ember_announce_due(
                &state.ember_announced_at,
                &contact.node_id,
                now,
                EMBER_MAINT_INTERVAL.as_secs() as i64,
            ) {
                let _ = send_ember_announce_peer(socket, state, &contact).await;
            }
        }
    }
    // Probed only when the frame carrying them answers something we asked this
    // peer, or cost a lookup token to send (ANNOUNCE_PEER). An unsolicited
    // FOUND_NODE or PEER_LIST is charged to nothing, so one peer sending them
    // as fast as the frame gate allows used up the shared probe budget with
    // leads it chose and starved the probes of real ones. Their contacts are
    // still merged into the table, unverified.
    if leads_asked_for {
        probe_ember_gossip_leads(socket, state, &inbound.gossip_leads, inbound.sender_id).await;
    }

    if inbound.pong_received {
        state.ember_diagnostics.ember_dht_pongs_received = state
            .ember_diagnostics
            .ember_dht_pongs_received
            .saturating_add(1);
        // Observed-IP votes are only accepted from PONGs that answer one of
        // our outbound PINGs (pending control or maintenance). Unsolicited
        // PONGs with forged `observed` must not drive external_ip.
        let correlated_pong = inbound.pong_request_id.is_some_and(|rid| {
            state
                .ember_dht_pending_pings
                .get(&rid)
                .is_some_and(|(_, dest, _)| *dest == from)
                || state
                    .ember_dht_maint_pings
                    .get(&rid)
                    .zip(inbound.sender_id)
                    .is_some_and(|(ping, from_id)| ping.node_id == from_id)
        });
        if correlated_pong {
            if let Some(observed) = inbound.pong_observed {
                state.ember_diagnostics.ember_dht_observed_votes = state
                    .ember_diagnostics
                    .ember_dht_observed_votes
                    .saturating_add(1);
                if let Some(confirmed) = state.ember_observed_votes.record_vote(observed, from.ip())
                {
                    let stun_ip = state.nat_info.external_addr.and_then(|a| match a.ip() {
                        std::net::IpAddr::V4(v4) => Some(v4),
                        std::net::IpAddr::V6(_) => None,
                    });
                    if let std::net::IpAddr::V4(v4) = confirmed.ip() {
                        match observed_ip_action(
                            state.external_ip,
                            v4,
                            stun_ip,
                            live_highid_external_ip(state),
                        ) {
                            ObservedIpAction::Adopt => {
                                set_external_ip(state, Some(v4));
                                state.stats.external_ip = v4.to_string();
                            }
                            ObservedIpAction::Reprobe => state.ember_observed_ip_moved = true,
                            ObservedIpAction::Keep => {}
                        }
                    }
                }
                // The quorum is on the IP; behind a NAT that maps a port per
                // destination the port is only the most common one, and
                // punching or advertising it would aim peers nowhere. It can
                // earn a quorum of its own on any later vote, so this is asked
                // on every one until STUN or the votes have filled it in.
                if state.nat_info.external_addr.is_none()
                    && state.ember_observed_votes.confirmed_port_has_quorum()
                {
                    if let Some(confirmed) = state.ember_observed_votes.confirmed() {
                        if state.external_ip.map(std::net::IpAddr::V4) == Some(confirmed.ip()) {
                            state.nat_info.external_addr = Some(confirmed);
                        }
                    }
                }
            }
        }
        if let Some(rid) = inbound.pong_request_id {
            // The maintenance entry is cleared only by the contact it was
            // sent to. Clearing it is what spares a contact from being
            // faulted, so an unbound match would let any peer keep dead
            // contacts alive in our table by guessing request ids.
            let answered_maint_ping = state
                .ember_dht_maint_pings
                .get(&rid)
                .zip(inbound.sender_id)
                .is_some_and(|(ping, from_id)| ping.node_id == from_id);
            if let Some((sent_at, dest, tx)) = state.ember_dht_pending_pings.remove(&rid) {
                if dest == from {
                    let _ = tx.send(sent_at.elapsed());
                } else {
                    state
                        .ember_dht_pending_pings
                        .insert(rid, (sent_at, dest, tx));
                }
            } else if answered_maint_ping {
                state.ember_dht_maint_pings.remove(&rid);
                // The engine's inbound path already refreshed this contact's
                // last_seen (and reset its failure count) when it learned the
                // sender, so just clearing the pending entry keeps the
                // timeout sweep from later faulting a live contact.
            } else {
                debug!("Ember DHT: PONG request_id {rid} from {from} matched no pending ping");
            }
        }
    }

    // A FOUND_NODE either answers a single-hop dev `FIND_NODE` (resolve
    // its waiter directly) or advances an iterative lookup (feed it to
    // the search, then drive the next round). The engine already merged
    // the contacts into the routing table. Unmatched request_ids are
    // unsolicited and ignored.
    if let Some((rid, contacts)) = inbound.found_node {
        // Bound to the address the query went to, like the PONG path above. A
        // wrong-sender answer is put back rather than consumed, so the peer we
        // actually asked can still resolve its own waiter.
        let harness_waiter = match state.ember_dht_pending_finds.remove(&rid) {
            Some((_sent_at, dest, tx)) if dest == from => Some(tx),
            Some((sent_at, dest, tx)) => {
                state
                    .ember_dht_pending_finds
                    .insert(rid, (sent_at, dest, tx));
                None
            }
            None => None,
        };
        if let Some(tx) = harness_waiter {
            let local_id = state.ember_dht.local_id();
            let infos = contacts
                .iter()
                .map(|c| ember_dht_contact_info(c, local_id))
                .collect();
            let _ = tx.send(infos);
        } else if let Some((search_id, per_search_req_id)) = state
            .ember_dht_search_requests
            .get(&rid)
            .map(|req| (req.search_id, req.per_search_req_id))
        {
            // `process_response` gates on `(per_search_req_id, from_id)`,
            // so a forged or misrouted answer can't advance the search.
            //
            // Only drop the wire-id entry once the answer is accepted.
            // Removing first meant a wrong-sender reply — request ids come
            // from one guessable counter — permanently unhooked the query:
            // `process_response` re-inserted its own pending entry and
            // refused it, but the deadline sweep could no longer expire
            // anything, the shortlist slot stayed `InFlight` against ALPHA,
            // and the real peer's later answer matched nothing. Any peer
            // with a session could stall lookups this way.
            //
            // `accepted`, not `new_closer`: a converged hop returns nothing
            // closer and is still a perfectly good answer. Gating on progress
            // held every such query open until its deadline expired.
            let consumed = if let Some(from_id) = inbound.sender_id {
                match state.ember_search.get_mut(search_id) {
                    Some(search) => {
                        search
                            .process_response(
                                per_search_req_id,
                                &from_id,
                                contacts,
                                Vec::new(),
                                // A FOUND_NODE answer to a FIND_VALUE means the
                                // peer holds nothing under the key, so there is
                                // no page to follow up.
                                None,
                            )
                            .accepted
                    }
                    // Search is gone; nothing will ever match this id again.
                    None => true,
                }
            } else {
                // No verified sender id (should not happen post-decode) —
                // treat as a failed query so the search can move on.
                if let Some(search) = state.ember_search.get_mut(search_id) {
                    search.mark_failed(per_search_req_id);
                }
                true
            };
            if consumed {
                state.ember_dht_search_requests.remove(&rid);
                drive_ember_search(socket, state, search_id).await;
            } else {
                debug!(
                    "Ember DHT: FOUND_NODE {rid} from {from} did not come from the queried node; \
                     leaving the query outstanding"
                );
            }
        } else {
            debug!("Ember DHT: FOUND_NODE request_id {rid} from {from} matched no pending find or search");
        }
    }

    // A STORE_ACK confirms one targeted node stored our published record;
    // apply it to the owning publish and resolve its waiter if that was
    // the last outstanding store.
    // A batch ack is the only proof that a queued record actually landed, so
    // it is what advances the per-file republish schedule. A file whose
    // records went nowhere stays due and is retried on the next tick instead
    // of being locked out for the full republish interval.
    if let Some((rid, accepted)) = inbound.store_batch_ack {
        if let Some(from_id) = inbound.sender_id {
            let outcome = state.ember_batch_publish.note_ack(rid, accepted, from_id);
            state.ember_diagnostics.ember_dht_stores_acked = state
                .ember_diagnostics
                .ember_dht_stores_acked
                .saturating_add(outcome.placed.len() as u32);
            for reference in outcome.placed {
                confirm_ember_record_placed(state, reference);
            }
            // Refusals are charged exactly like an unanswered batch: the round
            // reached the wire and did not place these records. The charge is
            // a no-op once another replica has confirmed the same record, and
            // a round's replica batches collapse into one charge, so this
            // cannot punish a file for being turned away by a single storer.
            if !outcome.refused.is_empty() {
                let now = std::time::Instant::now();
                state.ember_diagnostics.ember_dht_stores_failed = state
                    .ember_diagnostics
                    .ember_dht_stores_failed
                    .saturating_add(outcome.refused.len() as u32);
                for reference in outcome.refused {
                    note_ember_store_attempt_failed(state, reference, now);
                }
            }
        }
    }

    if let Some(rid) = inbound.store_ack_request_id {
        // Bound to the node the store went to, the same way FOUND_NODE is
        // bound to its responder: the ack is otherwise correlated only by a
        // guessable counter.
        let matches_target = state
            .ember_dht_publish_requests
            .get(&rid)
            .zip(inbound.sender_id)
            .is_some_and(|(req, from_id)| req.node_id == from_id);
        if matches_target {
            if let Some(req) = state.ember_dht_publish_requests.remove(&rid) {
                if let Some(op) = state.ember_publish.get_mut(req.publish_id) {
                    op.process_ack(req.per_pub_req_id);
                }
                maybe_finish_ember_publish(state, req.publish_id);
            }
        } else if state.ember_dht_publish_requests.contains_key(&rid) {
            debug!("Ember DHT: STORE_ACK request_id {rid} from {from} came from a node we did not store to");
        } else {
            debug!("Ember DHT: STORE_ACK request_id {rid} from {from} matched no pending publish");
        }
    }

    // A FOUND_VALUE answers an iterative FIND_VALUE: feed the records into
    // the owning search (no closer nodes ride a value answer), then drive
    // the next round. A value search can also receive FOUND_NODE answers
    // (handled above) when a peer has no record.
    if let Some(page) = inbound.found_value {
        let rid = page.request_id;
        if let Some((search_id, per_search_req_id)) = state
            .ember_dht_search_requests
            .get(&rid)
            .map(|req| (req.search_id, req.per_search_req_id))
        {
            // Same rule as FOUND_NODE above: keep the correlation entry until
            // the answer is accepted, so a wrong-sender reply cannot orphan
            // the query past the reach of the deadline sweep.
            // `accepted`, not `new_closer`: this path carries no contacts at
            // all, so progress is false for every single value hit. Reading it
            // as acceptance meant a search that had just been handed exactly
            // what it asked for still sat out its whole query timeout.
            let consumed = if let Some(from_id) = inbound.sender_id {
                match state.ember_search.get_mut(search_id) {
                    Some(search) => {
                        // Only hand the search a page when the peer claims
                        // records past this answer; "nothing more" and "did not
                        // say" mean the same thing to it. The search re-checks
                        // anyway — its budgets have to hold whatever a caller
                        // passes — but there is no reason to walk them for an
                        // answer that already said it was the last one.
                        let value_page =
                            page.has_more().then_some(ember::dht::search::ValuePage {
                                next_position: page.next_position,
                                total_available: page.total_available,
                            });
                        search
                            .process_response(
                                per_search_req_id,
                                &from_id,
                                Vec::new(),
                                page.records,
                                value_page,
                            )
                            .accepted
                    }
                    None => true,
                }
            } else {
                if let Some(search) = state.ember_search.get_mut(search_id) {
                    search.mark_failed(per_search_req_id);
                }
                true
            };
            if consumed {
                state.ember_dht_search_requests.remove(&rid);
                drive_ember_search(socket, state, search_id).await;
            } else {
                debug!(
                    "Ember DHT: FOUND_VALUE {rid} from {from} did not come from the queried node; \
                     leaving the query outstanding"
                );
            }
        } else {
            debug!("Ember DHT: FOUND_VALUE request_id {rid} from {from} matched no pending search");
        }
    }

    if let Some(body) = inbound.channel_msg {
        if let Some(from_id) = inbound.sender_id {
            handle_inbound_channel_gossip(
                socket,
                state,
                db,
                app_handle,
                body,
                from_id,
                HopMetering::Charge,
            )
            .await;
        }
    }
    if let Some(body) = inbound.channel_relay {
        if let Some(from_id) = inbound.sender_id {
            handle_inbound_channel_relay(socket, state, db, app_handle, body, from_id).await;
        }
    }
}
