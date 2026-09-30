//! Ember DHT publishing: the publish schedule, source and keyword records,
//! batch flushes, publish targets, and buddy endorsements.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// Feed records we already hold for `key` into a lookup that has just started.
///
/// A search only ever queries *other* nodes, so our own store is invisible to
/// our own lookups without this. That is wrong at any size — we may well be
/// among the closest nodes to the key — and on a small network it is the
/// difference between finding everything and finding nothing. Every
/// `start_find_value` call site needs it, so it lives here rather than being
/// repeated at each one.
pub(super) fn seed_ember_local_records(
    state: &mut NetworkState,
    search_id: u32,
    key: &[u8; 16],
    extra_keys: &[[u8; 16]],
) {
    // The search's own constraints, so the seed narrows the way a responder
    // would. Set by the caller before seeding; empty for lookups that set none.
    let constraints = state
        .ember_search
        .get(search_id)
        .map(|search| search.value_constraints().clone())
        .unwrap_or_default();
    let local = state.ember_dht.local_records(key, extra_keys, &constraints);
    if local.is_empty() {
        return;
    }
    let local_id = state.ember_dht.local_id();
    let seeded = state
        .ember_search
        .seed_local_results(search_id, local_id, local);
    debug!("Ember DHT: seeded {seeded} local record(s) into search {search_id}");
}

/// The per-file publish schedule, borrowed as a unit.
///
/// The maps only mean anything together: a file is due when `*_at` says so
/// *and* `unplaced` says its last round finished, `placed` says whether that
/// round has landed anything yet, and `attempts` decides when a file that keeps
/// failing is parked. Passing them as a bundle is also what lets
/// the state machine be exercised without standing up a whole [`NetworkState`],
/// which is where the bugs were — an attempt charged before the record reached
/// the wire, and a pending marker that outlived the records it tracked.
pub(super) struct EmberPublishSchedule<'a> {
    pub(super) unplaced: &'a mut HashMap<([u8; 16], EmberPublishKind), HashSet<[u8; 16]>>,
    /// Rounds still in progress that have already placed at least one record.
    pub(super) placed: &'a mut HashSet<([u8; 16], EmberPublishKind)>,
    /// Rounds still in progress in which a key has failed on every replica.
    pub(super) partial: &'a mut HashSet<([u8; 16], EmberPublishKind)>,
    pub(super) attempts: &'a mut HashMap<([u8; 16], EmberPublishKind), EmberPublishAttempts>,
    /// When each file's source record next falls due.
    pub(super) source_at: &'a mut HashMap<[u8; 16], std::time::Instant>,
    /// When each file's keyword records next fall due.
    pub(super) keyword_at: &'a mut HashMap<[u8; 16], std::time::Instant>,
}

impl EmberPublishSchedule<'_> {
    pub(super) fn reborrow(&mut self) -> EmberPublishSchedule<'_> {
        EmberPublishSchedule {
            unplaced: self.unplaced,
            placed: self.placed,
            partial: self.partial,
            attempts: self.attempts,
            source_at: self.source_at,
            keyword_at: self.keyword_at,
        }
    }

    /// Advance the republish clock for `kind` from `at`, so selection stops
    /// offering the file until its interval has passed again.
    pub(super) fn stamp(&mut self, file_hash: [u8; 16], kind: EmberPublishKind, at: std::time::Instant) {
        match kind {
            EmberPublishKind::Keyword => {
                self.keyword_at.insert(file_hash, at + EMBER_KEYWORD_REPUBLISH);
            }
            EmberPublishKind::Source => {
                self.source_at.insert(file_hash, at + EMBER_SOURCE_REPUBLISH);
            }
            // Replication carries someone else's record; there is no local
            // schedule for it.
            EmberPublishKind::Replication => {}
        }
    }

    /// Close `slot`'s round once none of its records remain unplaced, stamping
    /// the file if any record in the round landed. Returns whether it did.
    ///
    /// Which of a file's keys resolves last is an accident of timing — a
    /// timeout always resolves after the acks — so the verdict has to rest on
    /// the round as a whole rather than on the final reply.
    ///
    /// A keyword round that placed some keys but lost one on every replica is
    /// still published, but comes back after [`EMBER_KEYWORD_PARTIAL_RETRY`]
    /// rather than the twelve-hour interval: its siblings used to hide the
    /// failure, and on a file's first publish that word stayed unsearchable
    /// for twelve hours. Counted against [`EMBER_PUBLISH_MAX_ATTEMPTS`] like a
    /// failed round, so a word that never lands stops being retried.
    pub(super) fn finish_round(&mut self, slot: ([u8; 16], EmberPublishKind), now: std::time::Instant) -> bool {
        self.unplaced.remove(&slot);
        let partial = self.partial.remove(&slot);
        if !self.placed.remove(&slot) {
            return false;
        }
        if partial && slot.1 == EmberPublishKind::Keyword {
            let attempts = self.attempts.entry(slot).or_insert(EmberPublishAttempts {
                rounds_failed: 0,
                last_charged: now,
            });
            attempts.rounds_failed += 1;
            attempts.last_charged = now;
            if attempts.rounds_failed <= EMBER_PUBLISH_MAX_ATTEMPTS {
                self.keyword_at.insert(slot.0, now + EMBER_KEYWORD_PARTIAL_RETRY);
                return true;
            }
        }
        self.attempts.remove(&slot);
        self.stamp(slot.0, slot.1, now);
        true
    }
}

impl NetworkState {
    pub(super) fn publish_schedule(&mut self) -> EmberPublishSchedule<'_> {
        EmberPublishSchedule {
            unplaced: &mut self.ember_publish_unplaced,
            placed: &mut self.ember_publish_placed,
            partial: &mut self.ember_publish_partial,
            attempts: &mut self.ember_publish_attempts,
            source_at: &mut self.ember_source_publish_at,
            keyword_at: &mut self.ember_keyword_publish_at,
        }
    }
}

/// How stale a file's records of `kind` are, or `None` when it must not be
/// selected this tick.
///
/// The `unplaced` check is the load-bearing part: a file whose previous round is
/// still queued or awaiting an ack must not be picked again, because
/// re-enqueueing puts a second copy of every record on the wire, and the flush's
/// carry-over means a backlog can legitimately span several ticks.
///
/// `due_at` holds when each file next falls due; `interval` turns that back
/// into seconds since the last publish, which is what the ranking orders by.
pub(super) fn ember_publish_staleness(
    unplaced: &HashMap<([u8; 16], EmberPublishKind), HashSet<[u8; 16]>>,
    due_at: &HashMap<[u8; 16], std::time::Instant>,
    file_hash: [u8; 16],
    kind: EmberPublishKind,
    interval: std::time::Duration,
    now: std::time::Instant,
) -> Option<u64> {
    if unplaced.contains_key(&(file_hash, kind)) {
        return None;
    }
    match due_at.get(&file_hash) {
        // Never published ranks above anything with a timestamp.
        None => Some(u64::MAX),
        Some(due) if now < *due => None,
        Some(due) => Some(
            now.duration_since(*due)
                .as_secs()
                .saturating_add(interval.as_secs()),
        ),
    }
}

/// Note that `reference`'s record has been queued for publishing, so the file
/// is not considered published until it lands somewhere.
pub(super) fn track_ember_record_pending(schedule: EmberPublishSchedule<'_>, reference: EmberRecordRef) {
    if reference.kind == EmberPublishKind::Replication {
        return;
    }
    let slot = (reference.file_hash, reference.kind);
    let placed = schedule.placed;
    schedule
        .unplaced
        .entry(slot)
        .or_insert_with(|| {
            // A new round starts with nothing placed.
            placed.remove(&slot);
            HashSet::new()
        })
        .insert(reference.key);
}

/// Forget a queued record we have given up on sending, without treating it as
/// placed.
///
/// The counterpart to [`track_ember_record_pending`] for the give-up paths. A
/// file that stays marked pending is skipped by selection, so a record dropped
/// by the flush would otherwise take its file out of the rotation permanently.
/// The republish clock is stamped only if another key of the same round
/// landed; otherwise the file comes back around as due. Returns whether it was
/// stamped, which the caller owes [`note_ember_file_published`].
///
/// The failure count is left alone: a dropped round says nothing about whether
/// peers will take the file, and clearing it here would let a file whose rounds
/// alternate between refusals and drops escape the [`EMBER_PUBLISH_MAX_ATTEMPTS`]
/// park and return every tick without backoff.
pub(super) fn untrack_ember_record_pending(
    mut schedule: EmberPublishSchedule<'_>,
    reference: EmberRecordRef,
) -> bool {
    if reference.kind == EmberPublishKind::Replication {
        return false;
    }
    let slot = (reference.file_hash, reference.kind);
    let Some(unplaced) = schedule.unplaced.get_mut(&slot) else {
        return false;
    };
    unplaced.remove(&reference.key);
    if !unplaced.is_empty() {
        return false;
    }
    schedule.finish_round(slot, std::time::Instant::now())
}

/// [`untrack_ember_record_pending`] against the live schedule, counting the
/// file as published when the round it closes had placed something.
pub(super) fn drop_ember_record_pending(state: &mut NetworkState, reference: EmberRecordRef) {
    if untrack_ember_record_pending(state.publish_schedule(), reference) {
        note_ember_file_published(state, reference.file_hash, reference.kind);
    }
}

/// What handing queued records back to the schedule left for the caller.
#[derive(Default)]
pub(super) struct EmberReleasedRecords {
    /// Records given up on, including those left to another replica's copy.
    pub(super) dropped: usize,
    /// Replication records the store must re-arm for republish.
    pub(super) rearm: Vec<ember::dht::messages::BatchedRecord>,
    /// Records whose release closed a round that had placed something; each
    /// owes [`note_ember_file_published`].
    pub(super) published: Vec<EmberRecordRef>,
}

/// Untrack `records` from `schedule`, skipping any whose reference
/// `still_outstanding` reports is still queued or in flight elsewhere.
pub(super) fn settle_released_ember_records(
    mut schedule: EmberPublishSchedule<'_>,
    records: Vec<super::ember_publish::EmberQueuedRecord>,
    still_outstanding: impl Fn(EmberRecordRef) -> bool,
) -> EmberReleasedRecords {
    let mut released = EmberReleasedRecords::default();
    for queued in records {
        if still_outstanding(queued.reference) {
            released.dropped += 1;
        } else if queued.reference.kind == EmberPublishKind::Replication {
            released.rearm.push(queued.record);
        } else {
            if untrack_ember_record_pending(schedule.reborrow(), queued.reference) {
                released.published.push(queued.reference);
            }
            released.dropped += 1;
        }
    }
    released
}

/// Mark `reference`'s record as placed, closing its file's round once none of
/// its records remain unplaced. Returns whether the file was stamped published,
/// which the caller owes [`note_ember_file_published`].
pub(super) fn place_ember_record_pending(
    mut schedule: EmberPublishSchedule<'_>,
    reference: EmberRecordRef,
    now: std::time::Instant,
) -> bool {
    let slot = (reference.file_hash, reference.kind);
    // No pending set means this round was already accounted for; a later
    // duplicate ack from another storer should not re-stamp anything.
    let Some(unplaced) = schedule.unplaced.get_mut(&slot) else {
        return false;
    };
    unplaced.remove(&reference.key);
    let finished = unplaced.is_empty();
    schedule.placed.insert(slot);
    finished && schedule.finish_round(slot, now)
}

/// Apply a storer's confirmation that `reference`'s record landed, advancing
/// the file's republish schedule once none of its records remain unplaced.
pub(super) fn confirm_ember_record_placed(state: &mut NetworkState, reference: EmberRecordRef) {
    if place_ember_record_pending(state.publish_schedule(), reference, std::time::Instant::now()) {
        note_ember_file_published(state, reference.file_hash, reference.kind);
    }
}

/// Bookkeeping for a file whose round has just been stamped as published.
///
/// Counted here rather than at enqueue: this is the point at which the file is
/// genuinely published, so the figure means what its label says instead of
/// counting attempts that may have been dropped or refused.
pub(super) fn note_ember_file_published(state: &mut NetworkState, file_hash: [u8; 16], kind: EmberPublishKind) {
    match kind {
        EmberPublishKind::Keyword => {
            state.ember_diagnostics.ember_dht_keywords_published = state
                .ember_diagnostics
                .ember_dht_keywords_published
                .saturating_add(1);
            let unix = chrono::Utc::now().timestamp().max(0) as u32;
            state.ember_keyword_publish_unix.insert(file_hash, unix);
        }
        EmberPublishKind::Source => {
            state.ember_published_sources.insert(file_hash);
            state.ember_diagnostics.ember_dht_sources_published = state
                .ember_diagnostics
                .ember_dht_sources_published
                .saturating_add(1);
            let unix = chrono::Utc::now().timestamp().max(0) as u32;
            state.ember_source_publish_unix.insert(file_hash, unix);
        }
        // Replication has no local schedule; the ack is already counted by
        // the acked-records diagnostic.
        EmberPublishKind::Replication => {}
    }
}

/// Convert a persisted Ember publish unix timestamp into the in-session
/// `Instant` at which the file next falls due, or `None` when it is due now.
///
/// A deadline rather than the publish time itself, because `Instant` counts
/// from boot on Windows: a publish older than the machine's uptime has no
/// `Instant` of its own, and an app started at login would see every such stamp
/// as never published and republish the whole library. What is left of the
/// interval always lies ahead, so it is always representable.
pub(super) fn ember_publish_instant(
    last_unix: u32,
    now_unix: i64,
    now_inst: std::time::Instant,
    interval: std::time::Duration,
) -> Option<std::time::Instant> {
    if last_unix == 0 {
        return None;
    }
    let elapsed = (now_unix.max(0) as u64).saturating_sub(last_unix as u64);
    let remaining = interval.checked_sub(std::time::Duration::from_secs(elapsed))?;
    (!remaining.is_zero()).then(|| now_inst + remaining)
}

/// Load the persisted publish stamps into the in-session schedule.
///
/// `source_valid_since` is when our source records' address last changed (see
/// [`EmberSourceAddress`]). A source stamp from before it vouches for a record
/// naming the old address, so it keeps the badge and the TTL bookkeeping but
/// does not hold the file out of publishing.
pub(super) fn hydrate_ember_publish_schedule(
    known_files: &KnownFileList,
    source_valid_since: i64,
    source_dest: &mut HashMap<[u8; 16], std::time::Instant>,
    source_unix: &mut HashMap<[u8; 16], u32>,
    keyword_dest: &mut HashMap<[u8; 16], std::time::Instant>,
    keyword_unix: &mut HashMap<[u8; 16], u32>,
    published_sources: &mut HashSet<[u8; 16]>,
) {
    let now_unix = chrono::Utc::now().timestamp();
    let now_inst = std::time::Instant::now();
    for record in known_files.iter_records() {
        // A stamp says a record was placed once, not that the file is still
        // offered. known.met outlives unsharing, outlives a friends-only
        // restriction, and outlives deletion entirely — `delete_shared_file`
        // drops the index row and leaves the catalog record standing. Hydrating
        // those lit the Ember badge, and inflated the published-files figure the
        // Ember page shows, for files nobody could ask us for; the reconcile
        // that would have pruned the set is skipped on the startup pass because
        // it runs before known.met is absorbed and therefore is not yet
        // authoritative.
        //
        // Skipping the clocks alongside the badge is the safe direction: a file
        // that becomes publishable again is then due immediately rather than
        // waiting out an interval on the strength of records that have since
        // lapsed.
        if !record.is_shared || record.friends_only {
            continue;
        }
        if record.last_ember_source_publish != 0 {
            source_unix
                .entry(record.file_hash)
                .or_insert(record.last_ember_source_publish);
            let age = (now_unix.max(0) as u64)
                .saturating_sub(record.last_ember_source_publish as u64);
            if age < EMBER_SOURCE_RECORD_TTL.as_secs() {
                published_sources.insert(record.file_hash);
            }
            let schedulable = if i64::from(record.last_ember_source_publish) > source_valid_since {
                record.last_ember_source_publish
            } else {
                0
            };
            if let std::collections::hash_map::Entry::Vacant(e) = source_dest.entry(record.file_hash) {
                if let Some(at) = ember_publish_instant(
                    schedulable,
                    now_unix,
                    now_inst,
                    EMBER_SOURCE_REPUBLISH,
                ) {
                    e.insert(at);
                }
            }
        }
        if record.last_ember_keyword_publish != 0 {
            keyword_unix
                .entry(record.file_hash)
                .or_insert(record.last_ember_keyword_publish);
            if let std::collections::hash_map::Entry::Vacant(e) = keyword_dest.entry(record.file_hash) {
                if let Some(at) = ember_publish_instant(
                    record.last_ember_keyword_publish,
                    now_unix,
                    now_inst,
                    EMBER_KEYWORD_REPUBLISH,
                ) {
                    e.insert(at);
                }
            }
        }
    }
}

#[cfg(test)]
mod ember_publish_hydration_tests {
    use super::*;
    use crate::storage::known_files::KnownFileRecord;

    fn published_record(hash: [u8; 16], is_shared: bool, friends_only: bool) -> KnownFileRecord {
        let now = chrono::Utc::now().timestamp().max(0) as u32;
        KnownFileRecord {
            file_hash: hash,
            part_hashes: Vec::new(),
            file_name: "clip.mkv".into(),
            file_size: 1,
            file_path: format!("C:/Library/{}.mkv", hex::encode(hash)),
            aich_hash: String::new(),
            ember_file_hash: String::new(),
            modified_at: 0,
            all_time_transferred: 0,
            all_time_requested: 0,
            all_time_accepted: 0,
            upload_priority: 0,
            last_publish_src: 0,
            last_shared: 0,
            is_shared,
            friends_only,
            complete_sources: 0,
            last_ember_source_publish: now,
            last_ember_keyword_publish: now,
            media: None,
            media_scanned: false,
        }
    }

    fn hydrate(known: &KnownFileList) -> (HashSet<[u8; 16]>, HashMap<[u8; 16], u32>) {
        let mut source_at = HashMap::new();
        let mut source_unix = HashMap::new();
        let mut keyword_at = HashMap::new();
        let mut keyword_unix = HashMap::new();
        let mut published = HashSet::new();
        hydrate_ember_publish_schedule(
            known,
            0,
            &mut source_at,
            &mut source_unix,
            &mut keyword_at,
            &mut keyword_unix,
            &mut published,
        );
        (published, source_unix)
    }

    #[test]
    fn a_fresh_stamp_on_a_public_share_still_lights_the_badge() {
        let mut known = KnownFileList::new();
        known.add_or_update(published_record([0x11; 16], true, false));
        let (published, source_unix) = hydrate(&known);
        assert!(published.contains(&[0x11; 16]));
        assert!(source_unix.contains_key(&[0x11; 16]));
    }

    #[test]
    fn a_stamp_left_behind_by_an_unshare_or_a_delete_does_not_light_the_badge() {
        // Unsharing persists `is_shared = false`; deleting leaves the record
        // saying `is_shared = true`, which is why the delete path names its
        // hashes to `UnpublishEmberFiles` instead of relying on this filter.
        let mut known = KnownFileList::new();
        known.add_or_update(published_record([0x22; 16], false, false));
        let (published, source_unix) = hydrate(&known);
        assert!(
            published.is_empty(),
            "an unshared file has no live source record to report"
        );
        assert!(
            source_unix.is_empty(),
            "and no schedule either, so re-sharing publishes it promptly"
        );
    }

    #[test]
    fn a_friends_only_restriction_survives_a_restart() {
        let mut known = KnownFileList::new();
        known.add_or_update(published_record([0x33; 16], true, true));
        let (published, _) = hydrate(&known);
        assert!(
            published.is_empty(),
            "a restricted file must never be reported as published on the open DHT"
        );
    }

    /// A source stamp earned under an address we have since left vouches for a
    /// record naming the wrong address. The record is still out there, so the
    /// badge and TTL bookkeeping stay, but the file must be due again.
    #[test]
    fn a_source_stamp_from_before_an_address_change_does_not_hold_the_file_back() {
        let mut known = KnownFileList::new();
        known.add_or_update(published_record([0x44; 16], true, false));
        let stamped = known
            .iter_records()
            .next()
            .expect("one record")
            .last_ember_source_publish;
        for (valid_since, scheduled) in [(i64::from(stamped) - 60, true), (i64::from(stamped), false)] {
            let mut source_at = HashMap::new();
            let mut source_unix = HashMap::new();
            let mut keyword_at = HashMap::new();
            let mut keyword_unix = HashMap::new();
            let mut published = HashSet::new();
            hydrate_ember_publish_schedule(
                &known,
                valid_since,
                &mut source_at,
                &mut source_unix,
                &mut keyword_at,
                &mut keyword_unix,
                &mut published,
            );
            assert_eq!(source_at.contains_key(&[0x44; 16]), scheduled);
            assert!(published.contains(&[0x44; 16]));
            assert!(source_unix.contains_key(&[0x44; 16]));
            assert!(
                keyword_at.contains_key(&[0x44; 16]),
                "keyword records carry no address"
            );
        }
    }

    /// Only a move to a different address voids the source schedule. Knowing no
    /// address counts as a move, because nothing then says which address the
    /// saved stamps were earned under.
    #[test]
    fn the_source_address_changes_only_when_a_different_one_is_adopted() {
        let a = Ipv4Addr::new(203, 0, 113, 7);
        let b = Ipv4Addr::new(198, 51, 100, 9);
        let mut address = EmberSourceAddress::default();
        assert!(address.adopt(a, 1_000));
        assert_eq!(address, EmberSourceAddress { ip: Some(a), since: 1_000 });
        assert!(!address.adopt(a, 2_000), "the same address is not a move");
        assert_eq!(address.since, 1_000, "and keeps its original date");
        assert!(address.adopt(b, 3_000));
        assert_eq!(address, EmberSourceAddress { ip: Some(b), since: 3_000 });
    }

    #[test]
    fn the_source_address_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!(
            "ember-source-address-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = ember_source_address_path(&dir);
        assert_eq!(load_ember_source_address(&path), EmberSourceAddress::default());

        let saved = EmberSourceAddress {
            ip: Some(Ipv4Addr::new(203, 0, 113, 7)),
            since: 1_700_000_000,
        };
        save_ember_source_address(&path, &saved);
        assert_eq!(load_ember_source_address(&path), saved);

        std::fs::write(&path, b"not json").expect("overwrite");
        assert_eq!(
            load_ember_source_address(&path),
            EmberSourceAddress::default(),
            "unreadable is unknown, which republishes once"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

pub(super) fn sync_ember_source_publish_to_known(
    unix_map: &HashMap<[u8; 16], u32>,
    known_files: &mut KnownFileList,
) {
    for (hash, ts) in unix_map {
        known_files.set_last_ember_source_publish(hash, *ts);
    }
}

pub(super) fn sync_ember_keyword_publish_to_known(
    unix_map: &HashMap<[u8; 16], u32>,
    known_files: &mut KnownFileList,
) {
    for (hash, ts) in unix_map {
        known_files.set_last_ember_keyword_publish(hash, *ts);
    }
}

pub(super) fn sync_ember_publish_to_known(
    source_unix: &HashMap<[u8; 16], u32>,
    keyword_unix: &HashMap<[u8; 16], u32>,
    known_files: &mut KnownFileList,
) {
    sync_ember_source_publish_to_known(source_unix, known_files);
    sync_ember_keyword_publish_to_known(keyword_unix, known_files);
}

impl EmberSourceAddress {
    /// Take `ip` as the address source records are published under from
    /// `now_unix` on. Returns whether that is a change, including from no
    /// address at all — in which case nothing says which address the saved
    /// stamps were earned under, and republishing is the safe direction.
    pub(super) fn adopt(&mut self, ip: Ipv4Addr, now_unix: i64) -> bool {
        if self.ip == Some(ip) {
            return false;
        }
        *self = Self {
            ip: Some(ip),
            since: now_unix,
        };
        true
    }
}

pub(super) fn ember_source_address_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("ember_source_address.json")
}

/// Unreadable is treated as unknown: the cost is one republish of the library.
pub(super) fn load_ember_source_address(path: &std::path::Path) -> EmberSourceAddress {
    crate::security::recover_interrupted_replace(path);
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub(super) fn save_ember_source_address(path: &std::path::Path, address: &EmberSourceAddress) {
    let Ok(bytes) = serde_json::to_vec(address) else {
        return;
    };
    if let Err(e) = crate::security::atomic_write(path, &bytes, true) {
        debug!("Failed to persist the Ember source-record address: {e}");
    }
}

/// Note that source records will carry `ip` from now on, and when that differs
/// from the address they were published under, drop everything that vouches
/// for records naming the old one.
///
/// The republish clock goes so the next tick re-announces with the new
/// address; the per-tick budget spreads a large library out. Records not yet
/// sent go too — storers bind a source record to its sender's address and
/// refuse the stale ones, charging their files failed rounds — as do the
/// pending sets, and copies already in flight are voided, so a late ack or
/// timeout for a record that went out under the old address cannot settle the
/// round that republishes it.
pub(super) fn note_ember_source_address(state: &mut NetworkState, ip: Ipv4Addr) {
    if !state
        .ember_source_address
        .adopt(ip, chrono::Utc::now().timestamp())
    {
        return;
    }
    state.ember_source_address_dirty = true;
    state.ember_source_publish_at.clear();
    state
        .ember_batch_publish
        .drop_kind(EmberPublishKind::Source);
    state
        .ember_batch_publish
        .void_in_flight_kind(EmberPublishKind::Source);
    state.ember_pending_proxy_overlay.clear();
    state
        .ember_publish_unplaced
        .retain(|(_, kind), _| *kind != EmberPublishKind::Source);
    state
        .ember_publish_placed
        .retain(|(_, kind)| *kind != EmberPublishKind::Source);
    state
        .ember_publish_partial
        .retain(|(_, kind)| *kind != EmberPublishKind::Source);
}

/// How often we re-announce an Ember DHT *source* record for each shared
/// file. Source records are never relayed by other nodes (the publisher's
/// IP is bound at store time), so the publisher must re-announce within the
/// record TTL. 2 h is deliberately tighter than KAD's own source cadence
/// (`kad::publish::REPUBLISH_SOURCE_SECS`, 5 h) and leaves three times the margin
/// against the 6 h `SOURCE_RECORD_TTL`.
///
/// That margin is what covers a library too large for a pass to finish in one
/// interval. `ember_source_files_per_tick` sizes a pass to fit this interval, but
/// only up to `EMBER_SOURCE_PUBLISH_MAX_PER_TICK` (256 a tick, on 60 s ticks):
/// past roughly 30,000 publishable files a pass runs longer than 2 h, and past
/// roughly 90,000 longer than the 6 h TTL, at which point the oldest records lapse
/// before the round-robin returns to them. (The 25 % headroom above is gone a
/// little earlier, around 24,500, which is not the same thing as overrunning.) A
/// small routing table lowers both figures, since the same function will not queue
/// more than the flush can deliver. Raising the ceiling would trade that for more
/// traffic per tick on every node, so it stays where it is and the limit is
/// recorded here instead.
pub(super) const EMBER_SOURCE_REPUBLISH: std::time::Duration = std::time::Duration::from_secs(2 * 3600);
/// Live window for a source record on the DHT (matches `dht/store.rs`).
pub(super) const EMBER_SOURCE_RECORD_TTL: std::time::Duration = std::time::Duration::from_secs(6 * 3600);

/// Floor on shared-file source records (re)published per `publish_timer`
/// tick, so a nearly-idle library still makes progress every minute.
pub(super) const EMBER_SOURCE_PUBLISH_MIN_PER_TICK: usize = 5;

/// Hard ceiling on the same, so one tick's selection cannot become an
/// arbitrarily long queue however large the library or the table.
///
/// The binding limit in practice is [`ember_deliverable_records_per_tick`]; this
/// only bounds the extreme.
pub(super) const EMBER_SOURCE_PUBLISH_MAX_PER_TICK: usize = 256;

/// Records a publish tick may queue and still expect the flush to deliver.
///
/// A record goes to `min(contacts, K_EMBER_REPLICAS)` peers, so with a table at
/// or below k every peer receives every record and the deliverable total is one
/// peer's minute of allowance. Above k the target sets diverge and the total
/// scales with the table.
///
/// Queueing past this is not free. The overflow is held over by
/// `flush_ember_batch_publish`, and past
/// [`ember_publish::EMBER_MAX_CARRY_OVER_PER_PEER`] it is
/// dropped and its files return to the due pool having achieved nothing — so a
/// budget the flush cannot drain converts directly into wasted signing, wasted
/// cloning, and files that never publish. The keyword path had exactly that
/// shape: up to 96 files a tick, several records each, all landing on the same
/// few peers on a small table.
pub(super) fn ember_deliverable_records_per_tick(contacts: usize) -> usize {
    let per_peer = EMBER_STORE_RECORDS_PER_PEER_PER_MIN as usize;
    if contacts <= K_EMBER_REPLICAS {
        per_peer
    } else {
        per_peer.saturating_mul(contacts) / K_EMBER_REPLICAS.max(1)
    }
}

/// Keyword records a filename is assumed to yield, for budgeting only.
///
/// `extract_keywords` splits on separators so the real count varies per name;
/// budgeting on an estimate keeps selection O(1) per file rather than tokenising
/// the library every tick. Erring high is the safe direction: underestimating
/// produces a queue the flush cannot drain.
///
/// Four was an under-estimate of about half, which is the unsafe direction. That
/// function splits on nineteen separators plus whitespace, keeps every deduplicated
/// token of three bytes or more, and has no upper bound — a name in the ordinary
/// `Some.Movie.Title.2021.1080p.BluRay.x264-GROUP.mkv` shape yields eight, and
/// scene names commonly run six to ten. So each tick queued roughly twice what the
/// flush could carry, the surplus was held over and eventually dropped, and every
/// dropped record had already cost a signature and a clone and charged its file a
/// publish attempt.
pub(super) const EMBER_KEYWORDS_PER_FILE_ESTIMATE: usize = 8;

/// How many ticks a backlog of due source records should take to drain.
///
/// Only shapes a cold start — a first run, a re-enable (which clears the
/// schedule), or a return from a long outage. In the steady state the backlog
/// is one interval's worth of files and the floor covers it.
pub(super) const EMBER_SOURCE_BACKLOG_DRAIN_TICKS: usize = 10;

/// Media probes one keyword publish tick may perform.
///
/// The probe is awaited from the network `select!`, so however long it takes is
/// time eD2K, KAD and Ember are all suspended — the hazard the download path names
/// explicitly where it refuses to await a file hash inline. The tick's own budget
/// is not a tight enough bound: it reaches `EMBER_KEYWORD_PUBLISH_MAX_PER_TICK`,
/// and that many header reads on a slow or networked disk is a visible stall in
/// every transfer on the first ticks after a library is added.
///
/// Nothing is lost by going slower, because a file whose turn has not come
/// publishes without media now and gains it on republish.
pub(super) const MEDIA_PROBES_PER_TICK: usize = 8;

/// Which of this tick's due files still need reading for media.
///
/// `scanned` answers "has this hash been probed", or `None` for a hash known.met
/// has never heard of — which is not the same as unprobed and must not be treated
/// as a reason to read a disk, since there would be nowhere to record the answer.
///
/// Split out from [`maybe_publish_ember_keywords`] to be testable: the selection is
/// where the cost lives, and dropping the already-probed check would silently
/// re-read the whole library on every republish tick — exactly what the durable
/// scanned marker exists to prevent.
pub(super) fn files_needing_media_probe(
    due: &[([u8; 16], u64, String, [u8; 32], String)],
    scanned: impl Fn(&[u8; 16]) -> Option<bool>,
    limit: usize,
) -> Vec<([u8; 16], String)> {
    due.iter()
        .filter(|(hash, _, _, _, path)| {
            // An empty path is a row with nothing to read; it is skipped rather
            // than marked scanned, because a later scan may fill the path in.
            !path.is_empty() && scanned(hash) == Some(false)
        })
        .take(limit)
        .map(|(hash, _, _, _, path)| (*hash, path.clone()))
        .collect()
}

/// The constraints an Ember keyword search attaches to its `FIND_VALUE`s.
///
/// A function so the choice is testable and stated once. Availability is
/// deliberately absent: KAD can filter on it because its keyword entries carry a
/// publisher-claimed source count, while an Ember record carries none and the
/// number the search page shows counts distinct publishers across the network,
/// which no single responder can see.
///
/// A size of zero is the search page's "no limit", as on every other search
/// path, so it is not sent: a responder reads `max_size` as a hard ceiling.
pub(super) fn ember_keyword_constraints(
    file_type_filter: Option<String>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    file_extension: Option<String>,
) -> ember::dht::messages::ValueConstraints {
    ember::dht::messages::ValueConstraints {
        min_size: min_size.filter(|v| *v > 0),
        max_size: max_size.filter(|v| *v > 0),
        file_type: file_type_filter,
        file_extension,
        extra_keys: Vec::new(),
    }
}

/// Files whose source records go out this tick, for a library of
/// `publishable` files with `due` of them currently past their interval.
///
/// Two things have to hold. A full pass must fit inside
/// [`EMBER_SOURCE_REPUBLISH`], or the files past the cut are never published
/// at all — a fixed five per tick covered only 600 files, the same silent
/// cliff [`ember_keyword_files_per_tick`] exists to avoid. And a cold start
/// should not take a whole pass to become findable: at five per tick a
/// 160-file library needed half an hour before its last file existed on the
/// network. The steady-state term guarantees the first, the backlog term the
/// second, and the ceiling keeps either from outrunning the flush.
///
/// `contacts` is the routing-table size, which decides how much the flush can
/// actually deliver — see [`ember_deliverable_records_per_tick`]. A source file
/// is one record, so files and records are the same currency here.
pub(super) fn ember_source_files_per_tick(publishable: usize, due: usize, contacts: usize) -> usize {
    let ticks_per_cycle =
        (EMBER_SOURCE_REPUBLISH.as_secs() / EMBER_MAINT_INTERVAL.as_secs()).max(1) as usize;
    // Round up, then add ~25% headroom for ticks lost to an empty routing
    // table or a failed flush.
    let steady = publishable.div_ceil(ticks_per_cycle);
    let steady = steady + steady.div_ceil(4);
    let drain = due.div_ceil(EMBER_SOURCE_BACKLOG_DRAIN_TICKS);
    let deliverable =
        ember_deliverable_records_per_tick(contacts).max(EMBER_SOURCE_PUBLISH_MIN_PER_TICK);
    steady
        .max(drain)
        .clamp(
            EMBER_SOURCE_PUBLISH_MIN_PER_TICK,
            EMBER_SOURCE_PUBLISH_MAX_PER_TICK,
        )
        .min(deliverable)
}

// ── DHT keyword publishing (slice 8) ──

/// How often we re-announce Ember DHT *keyword* records for each shared
/// file. Unlike source records, keyword records are replicated by other
/// nodes (`take_republish_batch`), so the publisher's own re-announce
/// cadence can be slower; 12 h matches the KAD keyword-republish spirit
/// and sits inside the 24 h record TTL.
pub(super) const EMBER_KEYWORD_REPUBLISH: std::time::Duration = std::time::Duration::from_secs(12 * 3600);

/// When a keyword round that lost one of its keys comes back for another go.
/// See [`EmberPublishSchedule::finish_round`].
pub(super) const EMBER_KEYWORD_PARTIAL_RETRY: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// Floor on how many files' keyword records are (re)published per tick.
///
/// The real budget is derived from library size by
/// [`ember_keyword_files_per_tick`] so a whole library cycles inside the
/// record TTL; this is only the minimum for a small library.
pub(super) const EMBER_KEYWORD_PUBLISH_MIN_PER_TICK: usize = 2;

/// Ceiling on files per tick, so one tick cannot queue an unbounded burst
/// even for an enormous library. At the batch sizes the publisher produces
/// this is a few hundred datagrams, spread across the k closest peers.
pub(super) const EMBER_KEYWORD_PUBLISH_MAX_PER_TICK: usize = 96;

/// Files whose keyword records should go out this tick for a library of
/// `publishable` files to complete a full cycle within its republish
/// interval.
///
/// Publishing a fixed two files per minute caps the library at about 1,400
/// files before the cycle stops fitting inside the 12-hour interval, and
/// everything beyond that silently never gets republished. The budget
/// therefore follows library size: one full pass per interval, plus a little
/// headroom for ticks lost to an empty routing table or a failed flush.
///
/// Then bounded by what the flush can deliver. Unlike a source file, a keyword
/// file is *several* records — one per keyword, each to its own target set — so
/// the file budget has to be divided by
/// [`EMBER_KEYWORDS_PER_FILE_ESTIMATE`] before comparing against
/// [`ember_deliverable_records_per_tick`]. Without that division a small table
/// was asked for several hundred records a tick and could carry a few dozen.
pub(super) fn ember_keyword_files_per_tick(publishable: usize, contacts: usize) -> usize {
    let ticks_per_cycle =
        (EMBER_KEYWORD_REPUBLISH.as_secs() / EMBER_MAINT_INTERVAL.as_secs()).max(1) as usize;
    // Round up, then add ~25% headroom.
    let per_tick = publishable.div_ceil(ticks_per_cycle);
    let with_headroom = per_tick + per_tick.div_ceil(4);
    let deliverable_files = (ember_deliverable_records_per_tick(contacts)
        / EMBER_KEYWORDS_PER_FILE_ESTIMATE.max(1))
    .max(EMBER_KEYWORD_PUBLISH_MIN_PER_TICK);
    with_headroom
        .clamp(
            EMBER_KEYWORD_PUBLISH_MIN_PER_TICK,
            EMBER_KEYWORD_PUBLISH_MAX_PER_TICK,
        )
        .min(deliverable_files)
}

/// How often a download re-queries the Ember DHT for sources, indexed by
/// how many times it has already searched (slice 9). Mirrors the spirit of
/// the KAD `active_download_kad_interval` backoff: eager at first, then
/// progressively calmer so a long-running download isn't a steady DHT load.
pub(super) fn ember_source_search_interval(search_count: u32) -> std::time::Duration {
    let secs = match search_count {
        0 => 0,
        1 => 30,
        2 => 60,
        3 => 300,
        4 => 900,
        _ => 1800,
    };
    std::time::Duration::from_secs(secs)
}

/// Send everything the batch publisher has queued, one or more `STORE_BATCH`
/// datagrams per destination.
///
/// Whatever a destination's frame budget could not carry is held over for the
/// next flush rather than discarded. Dropping it looked harmless because the
/// file stayed due, but the file had already been charged a publish attempt at
/// selection: three ticks of that parked it for a full republish interval
/// without one of its records ever having left the host.
/// Totals accumulate into `state.ember_publish_pass.flush` rather than being
/// returned, because the drain runs both from the publish tick and from its own
/// timer and the heartbeat wants the sum of both.
pub(super) async fn flush_ember_batch_publish(socket: &UdpSocket, state: &mut NetworkState) {
    let mut stats = EmberFlushStats::default();
    let flush_at = std::time::Instant::now();
    state.ember_batch_publish.prune_sent_window(flush_at);
    // A record is released only once no other copy of it is still queued or in
    // flight; those can still place it, and settle its file when they resolve.
    let stale = state.ember_batch_publish.expire_queued(flush_at);
    let (dropped, rearmed) = release_ember_queued_records(state, stale);
    stats.records_dropped += dropped;
    stats.records_rearmed += rearmed;
    let destinations: Vec<ember::dht::EmberNodeId> =
        state.ember_batch_publish.queued.keys().copied().collect();

    for node_id in destinations {
        let Some((contact, mut queued)) = state.ember_batch_publish.queued.remove(&node_id) else {
            continue;
        };
        // What this peer will still accept this minute. Sending past it wastes
        // the records outright: the storer's rate limiter refuses them and
        // never acks, so they would be republished from scratch forever.
        let allowance = state
            .ember_batch_publish
            .record_allowance(node_id, flush_at);
        state.ember_batch_publish.queued_count = state
            .ember_batch_publish
            .queued_count
            .saturating_sub(queued.len());
        // A ban or filter change can land between queueing and this flush.
        if ember_addr_ip_verdict(state, contact.addr).refuses() {
            let (dropped, rearmed) = release_ember_queued_records(state, queued);
            stats.records_dropped += dropped;
            stats.records_rearmed += rearmed;
            continue;
        }
        // Materialise the wire records once and walk them with an offset.
        // Rebuilding the remainder for every batch would clone each record
        // about as many times as there are batches for this destination.
        let wire: Vec<ember::dht::messages::BatchedRecord> =
            queued.iter().map(|q| q.record.clone()).collect();
        let mut offset = 0usize;
        let mut frames_sent = 0usize;
        let mut records_sent = 0usize;
        let mut charged = 0usize;
        // Records that can never be sent, as opposed to ones merely held over.
        let mut unsendable: Vec<EmberRecordRef> = Vec::new();

        while offset < wire.len()
            && frames_sent < EMBER_MAX_BATCH_FRAMES_PER_PEER
            && records_sent < allowance
        {
            // A record too large for any batch would otherwise stall this
            // destination forever and take every record behind it with it.
            // Skip just that one and carry on.
            if !ember::dht::engine::EmberDht::record_fits_a_batch(wire[offset].record.len()) {
                warn!(
                    "Ember batch publish: skipping a {}-byte record that cannot fit a datagram",
                    wire[offset].record.len()
                );
                unsendable.push(queued[offset].reference);
                offset += 1;
                continue;
            }
            // Offer the packer only as many records as the peer's remaining
            // allowance covers, so a full datagram cannot overshoot it.
            let window = (offset + (allowance - records_sent)).min(wire.len());
            let Some((wire_req_id, frame, taken)) =
                state.ember_dht.build_store_batch(&wire[offset..window])
            else {
                break;
            };

            let mut behind_handshake = false;
            let sent = match state.ember_transport.prepare_outgoing(
                contact.addr,
                Some(&contact.noise_pub),
                &frame,
            ) {
                ember::transport::OutgoingResult::Ready { packet } => {
                    match send_ember_udp(socket, &packet, contact.addr, &state.ember_dht_overhead)
                        .await
                    {
                        Ok(_) => true,
                        Err(e) => {
                            debug!("Ember batch publish: send to {} failed: {e}", contact.addr);
                            false
                        }
                    }
                }
                ember::transport::OutgoingResult::HandshakeStarted { packet } => {
                    behind_handshake = true;
                    match send_ember_udp(socket, &packet, contact.addr, &state.ember_dht_overhead)
                        .await
                    {
                        Ok(_) => true,
                        Err(e) => {
                            debug!("Ember batch publish: send to {} failed: {e}", contact.addr);
                            false
                        }
                    }
                }
                ember::transport::OutgoingResult::Queued => {
                    behind_handshake = true;
                    true
                }
                ember::transport::OutgoingResult::Error(e) => {
                    debug!(
                        "Ember batch publish: transport error for {}: {e}",
                        contact.addr
                    );
                    false
                }
            };

            let carried: Vec<EmberRecordRef> = queued[offset..offset + taken]
                .iter()
                .map(|q| q.reference)
                .collect();

            if !sent {
                // Leave `offset` alone so this frame's records are held over
                // with the rest of the tail rather than counted as delivered.
                break;
            }
            offset += taken;
            frames_sent += 1;
            records_sent += taken;
            // Charged whether or not the bytes have left the socket yet. A
            // frame the transport queued behind an in-progress handshake is
            // committed — it flushes the moment the handshake completes — so
            // it spends this peer's minute exactly like one already on the
            // wire.
            //
            // Excluding it was a hole in the pacing, not a rounding detail:
            // `charged` is all that `note_records_sent` records, so a peer
            // mid-handshake was charged nothing, and the flush six seconds
            // later saw the full allowance again. Over a handshake's lifetime
            // that let one cold peer be committed several times its per-minute
            // ceiling. The transport only holds a bounded queue per handshake
            // and discards the *oldest* frame past it, so the surplus did not
            // just arrive late — the earliest batches were dropped silently
            // while their `in_flight` entries lived on to expire, charge their
            // files a failed round, and eventually park them.
            charged += taken;
            if behind_handshake {
                stats.frames_behind_handshake += 1;
                stats.records_behind_handshake += taken;
            } else {
                stats.frames_sent += 1;
                stats.records_sent += taken;
            }
            state.ember_batch_publish.in_flight.insert(
                wire_req_id,
                EmberBatchInFlight {
                    node_id,
                    records: carried,
                    deadline: ember_batch_ack_deadline(
                        std::time::Instant::now(),
                        behind_handshake,
                    ),
                    voided: 0,
                },
            );
        }

        state
            .ember_batch_publish
            .note_records_sent(node_id, flush_at, charged);

        if offset < queued.len() {
            let tail = queued.split_off(offset);
            let held = tail.len();
            let dropped = state
                .ember_batch_publish
                .carry_over(node_id, &contact, tail);
            stats.records_carried += held - dropped.len();
            // A record we gave up on must stop counting against its file, or
            // the file sits marked as pending a placement that will never come
            // and `skip-pending` selection never offers it again — unless
            // another replica's copy is still queued or in flight, which can
            // still place it and settles the round when it resolves.
            //
            // Replication is the exception, and it needs the opposite treatment.
            // `take_republish_batch` stamped the record as republished when it
            // handed it over, before anything had been sent, so a drop here does
            // not merely fail to place it — it costs the record a full republish
            // interval of silence for something we still hold and still owe the
            // network. `untrack_ember_record_pending` cannot do this itself: it
            // deliberately ignores replication, which has no per-file schedule to
            // untrack, and it never sees the signature this needs.
            //
            // Counted as rescheduled rather than dropped, so the heartbeat's
            // `dropped` stays what it claims to be: work that was thrown away.
            let (dropped, rearmed) = release_ember_queued_records(state, dropped);
            stats.records_dropped += dropped;
            stats.records_rearmed += rearmed;
        }
        stats.records_dropped += unsendable.len();
        for reference in unsendable {
            drop_ember_record_pending(state, reference);
        }
    }

    let window = &mut state.ember_publish_pass.flush;
    window.frames_sent += stats.frames_sent;
    window.records_sent += stats.records_sent;
    window.frames_behind_handshake += stats.frames_behind_handshake;
    window.records_behind_handshake += stats.records_behind_handshake;
    window.records_dropped += stats.records_dropped;
    window.records_rearmed += stats.records_rearmed;
    // Not cumulative: this is the depth still waiting, not a rate.
    window.records_carried = stats.records_carried;
}

/// Push a publish forward: pull the targets not yet stored on, send each
/// a signed `STORE_RECORD` over the Noise transport, and record the
/// in-flight wire requests. Then resolve the waiter if the publish has
/// finished (all targets acked/failed, or nothing to do).
///
/// Called when a publish starts, when a `STORE_ACK` advances it, and from
/// the staleness sweep after a store is marked failed.
pub(super) async fn drive_ember_publish(socket: &UdpSocket, state: &mut NetworkState, publish_id: u32) {
    // The record bytes, signature, and key are fixed for the publish.
    let (key, record_bytes, record_sig) = match state.ember_publish.get_mut(publish_id) {
        Some(op) => (
            op.record.keyword_hash,
            op.record.data.clone(),
            op.record.signature,
        ),
        None => return,
    };

    let batch = match state.ember_publish.get_mut(publish_id) {
        Some(op) => op.next_to_store(),
        None => return,
    };

    for (contact, per_pub_req_id) in batch {
        let (wire_req_id, frame) =
            state
                .ember_dht
                .build_store(key, record_bytes.clone(), record_sig);

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
                            "Ember DHT publish {publish_id}: send to {} failed: {e}",
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
                            "Ember DHT publish {publish_id}: send to {} failed: {e}",
                            contact.addr
                        );
                        false
                    }
                }
            }
            ember::transport::OutgoingResult::Queued => {
                behind_handshake = true;
                true
            }
            ember::transport::OutgoingResult::Error(e) => {
                debug!(
                    "Ember DHT publish {publish_id}: transport error for {}: {e}",
                    contact.addr
                );
                false
            }
        };

        if !send_ok {
            // Couldn't reach this target — mark it failed so the publish
            // doesn't wait on a node we never stored to.
            if let Some(op) = state.ember_publish.get_mut(publish_id) {
                op.mark_failed(per_pub_req_id);
            }
            continue;
        }

        let budget = if behind_handshake {
            EMBER_SEARCH_QUEUED_QUERY_TIMEOUT
        } else {
            EMBER_SEARCH_QUERY_TIMEOUT
        };
        state.ember_dht_publish_requests.insert(
            wire_req_id,
            EmberPublishRequest {
                publish_id,
                per_pub_req_id,
                node_id: contact.node_id,
                deadline: std::time::Instant::now() + budget,
            },
        );
    }

    maybe_finish_ember_publish(state, publish_id);
}

/// Resolve and tear down a publish once every targeted node has acked,
/// failed, or timed out. Safe to call after every batch / ack; a no-op
/// while stores are still outstanding.
pub(super) fn maybe_finish_ember_publish(state: &mut NetworkState, publish_id: u32) {
    let result = match state.ember_publish.get_mut(publish_id) {
        Some(op) => {
            if !op.poll_complete() {
                return;
            }
            let acked = op.acked.len() as u32;
            let failed = (op.targets.len().saturating_sub(op.acked.len())) as u32;
            state.ember_diagnostics.ember_dht_stores_acked = state
                .ember_diagnostics
                .ember_dht_stores_acked
                .saturating_add(acked);
            state.ember_diagnostics.ember_dht_stores_failed = state
                .ember_diagnostics
                .ember_dht_stores_failed
                .saturating_add(failed);
            state.ember_diagnostics.ember_dht_replication_sum = state
                .ember_diagnostics
                .ember_dht_replication_sum
                .saturating_add(acked as u64);
            state.ember_diagnostics.ember_dht_publishes_completed = state
                .ember_diagnostics
                .ember_dht_publishes_completed
                .saturating_add(1);
            EmberPublishResult {
                stored_on: op.acked.len(),
                targets: op.targets.len(),
            }
        }
        None => return,
    };

    if let Some(tx) = state.ember_dht_pending_publishes.remove(&publish_id) {
        let _ = tx.send(result);
    }

    state.ember_publish.remove(publish_id);
    state
        .ember_dht_publish_requests
        .retain(|_, r| r.publish_id != publish_id);
}

/// Whether the batch queue still holds more than a tick's deliverable work.
///
/// Backpressure for the selection paths. The flush holds over what it cannot
/// send, so a tick that selects while the queue is already deep only pushes the
/// backlog closer to [`ember_publish::EMBER_MAX_CARRY_OVER_PER_PEER`], where it
/// is dropped and
/// the files return to the due pool having cost a signature and a clone each.
/// Waiting a tick for the drain to catch up is strictly better.
///
/// Both sides have to be counted in the same unit, and getting that wrong was
/// silently switching keyword publishing off. `queued_count` counts one entry per
/// *(record x replica)* — `enqueue` increments it inside the fan-out loop —
/// whereas `ember_deliverable_records_per_tick` counts distinct records. Comparing
/// them directly made the gate up to `K_EMBER_REPLICAS` times too strict: on a
/// twenty-contact table it declared a backlog at six real records.
///
/// The consequence was invisible in the worst way. Source selection runs first
/// each tick and leaves its ordinary fan-out queued, so keyword selection — which
/// runs second behind the same gate — returned without doing anything. On a
/// twenty-contact table the old threshold was 120 queue entries, i.e. six records,
/// which one tick of source publishing exceeds at only a few dozen due files; and
/// a first run, a re-enable or an address change makes the whole library due at
/// once. Sources kept publishing, so files stayed downloadable by hash
/// while their keyword records expired and the files quietly left search.
pub(super) fn ember_publish_queue_is_backed_up(state: &NetworkState) -> bool {
    ember_publish_queue_is_backed_up_at(
        state.ember_batch_publish.queued_count,
        ember_publishable_peer_count(state),
    )
}

/// The queue depth, in entries, at which selection should wait a tick.
pub(super) fn ember_publish_backpressure_threshold(contacts: usize) -> usize {
    // What one tick's worth of records actually occupies in the queue.
    let fan_out = contacts.clamp(1, K_EMBER_REPLICAS);
    // Capped at half the queue, or the gate stops existing on a table above about
    // seventy contacts: the threshold grows with the table while the queue does
    // not, so past that point only `enqueue`'s hard ceiling pushes back — and it
    // pushes back by refusing records mid-tick, after their signature and clone
    // have already been paid for. Half leaves room for the tick in flight.
    ember_deliverable_records_per_tick(contacts)
        .saturating_mul(fan_out)
        .min(EMBER_BATCH_QUEUE_MAX / 2)
}

/// Split from the `NetworkState` reader so the rule can be tested directly. The
/// previous test built the arithmetic a second time and never called the gate,
/// which meant it asserted only that its own expression was self-consistent.
pub(super) fn ember_publish_queue_is_backed_up_at(queued_count: usize, contacts: usize) -> bool {
    queued_count >= ember_publish_backpressure_threshold(contacts)
}

/// Whether a library file may be advertised on the Ember DHT.
///
/// Scope is decided by `is_public_listable`, never by `shared` alone: a
/// friends-only file is served to mutual friends over the friend path, and
/// publishing it here would make it worldwide-discoverable — the same leak
/// that predicate already prevents on the KAD and ed2k-server paths.
///
/// The BLAKE3 gate rides along because both publishers need it: an all-zero
/// digest makes downloaders skip verification, and the record would carry
/// those zeros until its republish interval elapsed.
pub(super) fn is_ember_publishable(file: &FileInfo) -> bool {
    file.is_public_listable() && !file.hash.is_empty() && !file.ember_file_hash.is_empty()
}

#[cfg(test)]
mod ember_publish_scope_tests {
    use super::*;

    fn public_share() -> FileInfo {
        FileInfo {
            id: "0123456789abcdef0123456789abcdef".to_string(),
            name: "movie.mkv".to_string(),
            path: "C:/Library/movie.mkv".to_string(),
            size: 1024,
            hash: "0123456789abcdef0123456789abcdef".to_string(),
            aich_hash: String::new(),
            ember_file_hash: "ab".repeat(32),
            extension: "mkv".to_string(),
            modified_at: 0,
            priority: "normal".to_string(),
            requests: 0,
            accepted: 0,
            bytes_transferred: 0,
            alltime_requests: 0,
            alltime_accepted: 0,
            alltime_transferred: 0,
            complete_sources: 0,
            folder: String::new(),
            shared: true,
            friends_only: false,
            shared_kad: false,
            shared_ed2k: false,
            shared_ember: false,
        }
    }

    /// Both Ember publishers used to test `shared` directly, which let a
    /// friends-only file through as a source *and* a keyword record — the
    /// exact leak `is_public_listable` exists to stop. It is worse here than
    /// on the browse path: a DHT record is replicated to peers and outlives
    /// the session that published it.
    #[test]
    fn a_friends_only_file_is_never_published_to_the_dht() {
        let mut restricted = public_share();
        restricted.friends_only = true;
        assert!(!is_ember_publishable(&restricted));
    }

    #[test]
    fn a_public_share_with_a_digest_is_published() {
        assert!(is_ember_publishable(&public_share()));
    }

    #[test]
    fn unshared_or_unhashed_files_are_skipped() {
        let mut unshared = public_share();
        unshared.shared = false;
        assert!(!is_ember_publishable(&unshared));

        // Without a BLAKE3 digest the record would tell downloaders to skip
        // verification, and would carry that gap until its next republish.
        let mut undigested = public_share();
        undigested.ember_file_hash = String::new();
        assert!(!is_ember_publishable(&undigested));

        let mut unhashed = public_share();
        unhashed.hash = String::new();
        assert!(!is_ember_publishable(&unhashed));
    }
}

/// Records carried across a restart in `store_ember.dat`.
///
/// Each one costs an Ed25519 verification on the way back in, so this bounds
/// startup work as well as file size: twenty thousand is a fraction of a second
/// of verification and a few megabytes on disk, and more than a node holding a
/// healthy share of a young network's keys will have.
pub(super) const EMBER_PERSIST_MAX_RECORDS: usize = 20_000;

/// How long a looked-up target set is trusted before the key queues again.
///
/// Long enough that a republish reuses the lookup rather than paying for a new
/// one, short enough that the set still reflects a network peers join and leave.
pub(super) const EMBER_PUBLISH_TARGETS_TTL_SECS: i64 = 4 * 3600;

/// Fewest target lookups started per maintenance cycle while any are queued.
pub(super) const EMBER_MAINT_MIN_TARGET_LOOKUPS: usize = 2;
/// Most target lookups started per maintenance cycle.
///
/// A lookup is a handful of round trips and occupies a background search slot
/// for well under a minute, so this many a minute stays far inside the
/// background share of the search pool.
pub(super) const EMBER_MAINT_MAX_TARGET_LOOKUPS: usize = 8;

/// Target lookups to start this cycle with `queued` keys waiting.
///
/// Enough to drain the queue within a quarter of a target set's lifetime. A
/// fixed two a minute assumed one key per file; there are about eight (the
/// source key plus each keyword), so at two a minute a large library held
/// fewer fresh target sets than it had keys, a full queue took longer to drain
/// than a set lived, and most records went to our own table's closest, which
/// on a large overlay refuse on proximity.
pub(super) fn ember_target_lookups_this_cycle(queued: usize) -> usize {
    let cycles = (EMBER_PUBLISH_TARGETS_TTL_SECS as u64 / 4 / EMBER_MAINT_INTERVAL.as_secs()).max(1) as usize;
    queued
        .div_ceil(cycles)
        .clamp(EMBER_MAINT_MIN_TARGET_LOOKUPS, EMBER_MAINT_MAX_TARGET_LOOKUPS)
}

/// Keys that may be waiting for a target lookup at once.
pub(super) const EMBER_PUBLISH_TARGET_QUEUE_MAX: usize = 512;

/// Looked-up target sets kept. Each is at most `K_EMBER_REPLICAS` contacts.
pub(super) const EMBER_PUBLISH_TARGETS_MAX: usize = 2048;

/// The nodes to store a record under `key` on.
///
/// Prefers the set a real lookup found, and falls back to our own table's
/// closest while no lookup has resolved yet — queueing the key so the next
/// republish does better. See [`NetworkState::ember_publish_targets`] for why
/// the table's answer is not the same as the network's.
///
/// The key is queued only while the queue holds fewer than `queue_limit` keys
/// (capped at [`EMBER_PUBLISH_TARGET_QUEUE_MAX`]).
pub(super) fn ember_publish_targets_for(
    cache: &HashMap<[u8; 16], (Vec<ember::dht::EmberNodeId>, i64)>,
    queue: &mut std::collections::VecDeque<[u8; 16]>,
    queue_limit: usize,
    routing: &ember::dht::routing::RoutingTable,
    key: [u8; 16],
    now: i64,
) -> Vec<ember::dht::EmberContact> {
    let target = ember::dht::EmberNodeId(key);
    let fresh = match cache.get(&key) {
        Some((ids, learned_at))
            if !ids.is_empty()
                && now.saturating_sub(*learned_at) < EMBER_PUBLISH_TARGETS_TTL_SECS =>
        {
            Some(ids)
        }
        _ => None,
    };

    // Resolve the remembered IDs against the table as it is now. Anyone since
    // evicted, faulted or filtered out simply drops away, and whoever remains is
    // addressed where the table says they are rather than where the lookup found
    // them.
    let mut out: Vec<ember::dht::EmberContact> = fresh
        .map(|ids| {
            ids.iter()
                .filter_map(|id| routing.get_contact(id).cloned())
                .filter(|c| c.is_verified())
                .collect()
        })
        .unwrap_or_default();

    // Whether the lookup's answer still gives us anywhere to send. Counted before
    // the top-up, because it is what decides if this key needs asking about again.
    let resolved = out.len();

    // Top up from our own closest. Two cases need it: a lookup that converged
    // once its frontier settled returns only the nodes that answered, which can
    // be half a bucket, and an entry thinned by eviction would otherwise fan out
    // to fewer replicas the longer it lived. Either way a publish should reach
    // K_EMBER_REPLICAS nodes, not however many survived.
    if out.len() < K_EMBER_REPLICAS {
        for contact in routing.find_closest_prefer_verified(&target, K_EMBER_REPLICAS) {
            if out.len() >= K_EMBER_REPLICAS {
                break;
            }
            if !contact.is_verified() {
                continue;
            }
            if !out.iter().any(|held| held.node_id == contact.node_id) {
                out.push(contact);
            }
        }
    }

    // Queue a lookup whenever the cache no longer supplies most of where this
    // publish is actually going, which covers more than an empty or aged entry: an
    // entry can be well inside its TTL and still resolve to few or none of its
    // nodes, if they have since been evicted, faulted or filtered out. Keying this
    // on freshness alone left that case publishing to fallbacks for the rest of the
    // entry's life — worse than holding no entry, which at least asks.
    //
    // Measured against what we are actually sending to rather than against
    // `K_EMBER_REPLICAS`, so the threshold means the same thing on a small table as
    // on a full one: one survivor out of twenty is the same situation as none, while
    // one out of two is a table with nothing better to offer. An entry carrying most
    // of its set does not re-queue.
    //
    // That only holds because `get_contact` also searches the replacement cache.
    // While it did not, a lookup's answers — all close to the key, so all in one
    // already-full bucket — resolved to almost nothing, every key re-queued on
    // every publish, and the 512-slot queue stayed pinned, silently dropping
    // genuinely new keys.
    //
    // It does not stop the queue filling, though: every key the cache does not
    // hold queues once, the queue drains two a minute, and the cache holds far
    // fewer keys than a storer can. So records that are not ours queue under a
    // lower `queue_limit`, or none — see [`ember_overlay_publish_targets_within`].
    if resolved * 2 < out.len()
        && queue.len() < queue_limit.min(EMBER_PUBLISH_TARGET_QUEUE_MAX)
        && !queue.contains(&key)
    {
        queue.push_back(key);
    }
    out
}

/// How long a stranger's PING keeps proving our UDP port is open.
///
/// Long enough that the evidence does not lapse between arrivals — once we are
/// in the network, gossip keeps bringing strangers to us, but on no fixed
/// schedule — and short enough that a network change we did not otherwise
/// notice stops us claiming reachability we have lost. An address change clears
/// the evidence outright (see [`set_external_ip`]), which catches the common
/// case long before this expires.
pub(super) const EMBER_UDP_REACHABLE_TTL_SECS: i64 = 3600;

/// [`ember_udp_reachable`] over its inputs alone, so the rule can be tested
/// without standing up a whole `NetworkState`.
pub(super) fn ember_udp_reachable_from(
    nat_type: ember::nat::NatType,
    proven_at: Option<i64>,
    now: i64,
) -> bool {
    // No NAT at all. The prober reports `Open` only when our own socket address
    // is the address the world sees, so there is nothing between us and inbound
    // traffic. This is the one case we can settle without waiting for a peer,
    // and it covers the dedicated-IP nodes that make the best relays.
    if nat_type == ember::nat::NatType::Open {
        return true;
    }
    match proven_at {
        Some(at) => now.saturating_sub(at) < EMBER_UDP_REACHABLE_TTL_SECS,
        None => false,
    }
}

/// Whether Ember has its own evidence that our UDP port is reachable from the
/// internet, so `udp_firewalled` does not force relayed publishing on a node
/// that does not need it. See [`NetworkState::ember_udp_reachable_at`].
pub(super) fn ember_udp_reachable(state: &NetworkState) -> bool {
    ember_udp_reachable_from(
        state.nat_info.nat_type,
        state.ember_udp_reachable_at,
        chrono::Utc::now().timestamp(),
    )
}

/// Same TCP-firewalled predicate publish uses for `SOURCE_FLAG_FIREWALLED`
/// and consume uses before sending `CALLBACK_REQ`. `state.firewalled` starts
/// as `!upnp_success` and Ember-only nodes never clear it, so consume must
/// not use that flag.
pub(super) fn ember_tcp_firewalled_from(
    low_id: bool,
    tcp_status: crate::network::kad::firewall::FirewallStatus,
) -> bool {
    low_id || tcp_status == crate::network::kad::firewall::FirewallStatus::Firewalled
}

pub(super) fn ember_tcp_firewalled(state: &NetworkState) -> bool {
    ember_tcp_firewalled_from(state.low_id, state.firewall_checker.tcp_status())
}

/// The buddy trailer we may write for `contact`, from the endorsement that
/// contact signed for us.
///
/// Every byte comes from the endorsement, not from our observation of the
/// contact: the endpoint a searcher dials has to be one the buddy signed, or
/// the signature will not verify there. That also means a buddy whose own
/// `(ip, udp)` self-view differs from the address we reach it at is named at
/// *its* view — which is the address its endorsement makes checkable.
pub(super) fn ember_named_source_buddy(
    state: &NetworkState,
    contact: &ember::dht::EmberContact,
    now: i64,
) -> Option<ember::dht::publish::SourceBuddy> {
    let endorsement = state.ember_dht.buddy_endorsement(&contact.node_id, now)?;
    // A record lives six hours and is republished every two, and searchers
    // refuse an endorsement past its expiry. Naming one that dies before the
    // next republish left each record published in its last two hours
    // uncallable until that republish; see `ember_buddy_endorsement_renew_due`.
    if !ember_buddy_endorsement_outlives_republish(endorsement.expires_at, now) {
        return None;
    }
    let buddy = endorsement.as_source_buddy();
    buddy.is_routable().then_some(buddy)
}

/// Life an endorsement must have left for a record to name it: past the next
/// republish, with half an hour to spare for a slow cycle.
const EMBER_BUDDY_ENDORSEMENT_MIN_LIFE_SECS: i64 = EMBER_SOURCE_REPUBLISH.as_secs() as i64 + 1800;
/// Asking this much before the minimum gives the buddy a few maintenance cycles
/// to answer before records stop naming it.
const EMBER_BUDDY_ENDORSEMENT_RENEW_SECS: i64 = EMBER_BUDDY_ENDORSEMENT_MIN_LIFE_SECS + 3600;

pub(super) fn ember_buddy_endorsement_outlives_republish(expires_at: i64, now: i64) -> bool {
    expires_at >= now.saturating_add(EMBER_BUDDY_ENDORSEMENT_MIN_LIFE_SECS)
}

/// Whether the named buddy should be asked for a fresh endorsement now, while
/// the one we hold can still be named.
pub(super) fn ember_buddy_endorsement_renew_due(expires_at: i64, now: i64) -> bool {
    expires_at < now.saturating_add(EMBER_BUDDY_ENDORSEMENT_RENEW_SECS)
}

/// Whether consume should `CALLBACK_REQ` this source. Unusable, unendorsed,
/// uncorroborated or locally blocked buddies fall through to the firewalled park
/// path instead of being dropped.
///
/// `buddy_endpoint_corroborated` must be
/// `EmberDht::buddy_endpoint_corroborated` for this source's buddy — the
/// endorsement alone is signed under a publisher-supplied key and so names no
/// one. See [`ember::dht::publish::DiscoveredSource::takes_callback`].
pub(super) fn ember_source_uses_callback(
    src: &ember::dht::publish::DiscoveredSource,
    we_are_unreachable: bool,
    buddy_blocked_or_banned: bool,
    buddy_endpoint_corroborated: bool,
    now: i64,
) -> bool {
    src.takes_callback(we_are_unreachable, buddy_endpoint_corroborated, now)
        && !buddy_blocked_or_banned
}

/// PFS states whose declared IP must not be gossiped as a HighID EPX source.
///
/// `EmberRelay` is the LowID↔LowID broker park. Omitting it here advertised
/// Ember DHT firewalled contacts as ordinary dialable sources after ingest
/// started the broker.
pub(super) fn epx_advertises_source_firewalled(state: &ed2k::sources::DownloadSourceState) -> bool {
    matches!(
        state,
        ed2k::sources::DownloadSourceState::WaitCallbackKad
            | ed2k::sources::DownloadSourceState::LowToLowIp
            | ed2k::sources::DownloadSourceState::EmberRelay
    )
}

/// LowID↔LowID: both sides firewalled, source asked downloaders to use the
/// Ember broker (`SOURCE_FLAG_RELAY_CAPABLE`). Same gate KAD uses via
/// `is_ember_capable` before `attempt_low_to_low`.
pub(super) fn ember_firewalled_source_should_broker(
    we_are_unreachable: bool,
    flags: u8,
    ip: Ipv4Addr,
    port: u16,
) -> bool {
    we_are_unreachable
        && flags & ember::SOURCE_FLAG_FIREWALLED != 0
        && flags & ember::SOURCE_FLAG_RELAY_CAPABLE != 0
        && port != 0
        && !ip.is_unspecified()
}

/// Start the punch/relay broker for a firewalled Ember source. Advertises
/// our QUIC bind port, not a KAD-UDP-probed one. No-op when the broker
/// was never constructed (no confirmed external IP / QUIC endpoint yet).
pub(super) async fn start_ember_low_to_low_broker(
    state: &mut NetworkState,
    transfer_id: &str,
    file_hash: [u8; 16],
    source_ip: Ipv4Addr,
    source_port: u16,
    target: ember::broker::RelayTarget,
) -> bool {
    let ext = state.nat_info.external_addr.map(|addr| {
        SocketAddr::new(
            addr.ip(),
            advertised_quic_port(state).unwrap_or(state.tcp_port),
        )
    });
    let nat_type = state.nat_info.nat_type;
    let Some(broker) = state.connection_broker.as_mut() else {
        return false;
    };
    broker
        .attempt_low_to_low(
            transfer_id,
            file_hash,
            source_ip,
            source_port,
            target,
            nat_type,
            ext,
        )
        .await
}

/// SourceManager has no firewalled bit. FIREWALLED Ember DHT contacts must
/// never be registered there — pending promotion would TCP-dial the claimed
/// NAT IP.
pub(super) fn ember_source_is_sm_dialable(src: &ember::dht::publish::DiscoveredSource) -> bool {
    src.flags & ember::SOURCE_FLAG_FIREWALLED == 0
}

pub(super) fn pending_download_has_parked_ember_sources(state: &NetworkState, transfer_id: &str) -> bool {
    state.per_file_sources.get(transfer_id).is_some_and(|pfs| {
        pfs.sources.iter().any(|s| {
            matches!(
                s.state,
                ed2k::sources::DownloadSourceState::WaitCallbackKad
                    | ed2k::sources::DownloadSourceState::LowToLowIp
                    | ed2k::sources::DownloadSourceState::EmberRelay
            )
        })
    })
}

/// Drop publish-set entries whose source record has outlived
/// `EMBER_SOURCE_RECORD_TTL`.
///
/// `ember_source_publish_unix` is written in lockstep with
/// `ember_published_sources`, so it dates each entry without the set having to
/// carry timestamps of its own. An entry with no stamp is left alone: the only
/// way to hold one is to have been placed this session by a path that also
/// stamps it, and guessing would darken a live badge.
pub(super) fn prune_expired_ember_published_sources(state: &mut NetworkState) {
    if state.ember_published_sources.is_empty() {
        return;
    }
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let ttl = EMBER_SOURCE_RECORD_TTL.as_secs();
    let stamps = &state.ember_source_publish_unix;
    state.ember_published_sources.retain(|hash| {
        stamps
            .get(hash)
            .is_none_or(|placed| now.saturating_sub(*placed as u64) < ttl)
    });
}

/// Withdraw everything we hold for `file_hashes`' Ember publications, because
/// those files have stopped being publicly listable — unshared, restricted to
/// friends, or gone from the library altogether.
///
/// Takes the whole set at once because every caller is a bulk operation and the
/// expensive parts here (the resident record store, the queued publish batches)
/// are whole-collection walks. One walk per file would make unsharing a folder
/// O(files x store) on the network task.
///
/// What this cannot do is recall the replicas already sitting on other nodes.
/// There is no delete in the DHT wire protocol, so those lapse on their own
/// TTL (6 h for a source record, 24 h for a keyword record) and the upload path
/// refuses the file throughout, which makes the residue a stale search hit
/// rather than a served byte.
///
/// Dropping our *own* copies is the part that is not merely tidiness.
/// [`ember::dht::store::DhtStore::persistable`] carries keyword records across
/// restarts, and `take_republish_batch` re-pushes whatever the store holds to
/// the nodes currently closest to each key. So a node that unshared a file and
/// left its store alone kept answering `FIND_VALUE` for it, and kept seeding
/// fresh storers with it, for as long as the signed body stayed inside its TTL
/// — with nothing left in the library to explain where the hit came from.
///
/// The persisted stamps go for the same reason in the other direction:
/// [`hydrate_ember_publish_schedule`] reads them back on the next launch, so
/// leaving them behind both re-lit the Ember badge for a file that no longer
/// has a record and held the file out of publishing for the rest of a
/// republish interval if it was shared again.
pub(super) fn retract_ember_publish(
    state: &mut NetworkState,
    known_files: &mut KnownFileList,
    file_hashes: &HashSet<[u8; 16]>,
) {
    if file_hashes.is_empty() {
        return;
    }
    state.ember_dht.drop_own_file_records(file_hashes);
    state.ember_batch_publish.drop_files(file_hashes);
    let awaiting_buddy: Vec<(ember::dht::EmberNodeId, u32)> = state
        .ember_pending_proxy_overlay
        .iter()
        .filter(|(_, pending)| file_hashes.contains(&pending.reference.file_hash))
        .map(|(key, _)| *key)
        .collect();
    for key in awaiting_buddy {
        state.ember_pending_proxy_overlay.remove(&key);
    }
    for file_hash in file_hashes {
        for kind in [EmberPublishKind::Keyword, EmberPublishKind::Source] {
            state.ember_publish_unplaced.remove(&(*file_hash, kind));
            state.ember_publish_placed.remove(&(*file_hash, kind));
            state.ember_publish_partial.remove(&(*file_hash, kind));
            state.ember_publish_attempts.remove(&(*file_hash, kind));
        }
        state.ember_published_sources.remove(file_hash);
        state.ember_source_publish_at.remove(file_hash);
        state.ember_source_publish_unix.remove(file_hash);
        state.ember_keyword_publish_at.remove(file_hash);
        state.ember_keyword_publish_unix.remove(file_hash);
        known_files.set_last_ember_source_publish(file_hash, 0);
        known_files.set_last_ember_keyword_publish(file_hash, 0);
    }
}

pub(super) fn prune_ember_pending_proxy_overlay(state: &mut NetworkState) {
    let now = std::time::Instant::now();
    let expired: Vec<(ember::dht::EmberNodeId, u32, EmberRecordRef, std::time::Instant)> = state
        .ember_pending_proxy_overlay
        .iter()
        .filter(|(_, pending)| now.duration_since(pending.queued_at) >= EMBER_PROXY_OVERLAY_TTL)
        .map(|(k, pending)| (k.0, k.1, pending.reference, pending.queued_at))
        .collect();
    for (buddy, rid, reference, asked_at) in expired {
        state.ember_pending_proxy_overlay.remove(&(buddy, rid));
        state.ember_proxy_buddies.note_expired(buddy, asked_at, now);
        drop_ember_record_pending(state, reference);
    }
}

pub(super) async fn flush_ember_proxy_overlay_ack(
    socket: &UdpSocket,
    state: &mut NetworkState,
    buddy: ember::dht::EmberNodeId,
    request_id: u32,
) {
    prune_ember_pending_proxy_overlay(state);
    let Some(pending) = state
        .ember_pending_proxy_overlay
        .remove(&(buddy, request_id))
    else {
        return;
    };
    state
        .ember_proxy_buddies
        .note_acked(buddy, std::time::Instant::now());
    state.ember_dht.store_own_record(&pending.record);
    if !enqueue_ember_source_overlay(state, &pending.record, pending.reference) {
        drop_ember_record_pending(state, pending.reference);
    }
    flush_ember_batch_publish(socket, state).await;
}

pub(super) fn enqueue_ember_source_overlay(
    state: &mut NetworkState,
    record: &ember::dht::publish::SignedRecord,
    reference: EmberRecordRef,
) -> bool {
    let targets = ember_overlay_publish_targets(state, record.keyword_hash);
    state.ember_batch_publish.enqueue(
        &targets,
        reference,
        ember::dht::messages::BatchedRecord {
            key: record.keyword_hash,
            record: record.data.clone(),
            record_signature: record.signature,
        },
    )
}

/// Auto-publish Ember DHT source records for our shared files (slice 9 + 15).
///
/// Runs on the 60-second publish tick, gated on `ember_native_enabled`
/// plus a non-empty Ember routing table (NOT on KAD connectivity), so the
/// DHT advertises us as a source even on a KAD-less network.
///
/// HighID / TCP-open peers publish a direct contact. LowID / TCP-Firewalled
/// peers (KAD or server) also self-publish when we have an observed external
/// IPv4 (eD2K/KAD/STUN) — the Noise UDP path still reaches DHT storers,
/// satisfying the anti-reflection IP bind — and set
/// `SOURCE_FLAG_FIREWALLED | SOURCE_FLAG_RELAY_CAPABLE` so downloaders
/// route LowID↔LowID via the Ember broker instead of a doomed TCP dial.
/// Ember-only nodes with no TCP proof do not advertise FIREWALLED just
/// because UPnP failed at startup. UDP-unreachable still asks a buddy and
/// still advertises relay, without parking the TCP contact.
pub(super) async fn maybe_publish_ember_sources(
    socket: &UdpSocket,
    state: &mut NetworkState,
    settings: &AppSettings,
    local_index: &Arc<RwLock<LocalIndex>>,
    known_files: &KnownFileList,
) {
    refresh_ember_advertised_buddy(state);
    let tcp_port = advertised_tcp_port(state);
    let udp_port = advertised_udp_port(state);
    // Refresh firewall-awareness gauges every tick (slice 15), even when
    // we skip publishing (empty table / no IP yet).
    let firewalled_like = ember_tcp_firewalled(state);
    // SOURCE_FLAG_FIREWALLED tells downloaders not to TCP-dial. That is a TCP
    // fact: LowID, or KAD/server concluding Firewalled. The pessimistic
    // startup `state.firewalled` (`!upnp_success`) is not — Ember-only never
    // clears it, and an open UDP port is not proof TCP accepts connections
    // either. UDP-unreachable still advertises relay without parking the TCP
    // contact. PROXY_STORE is only for TCP-firewalled records: the buddy
    // rejects a HighID source, and consume only CALLBACK_REQs FIREWALLED
    // trailers.
    let udp_needs_help = state.udp_firewalled && !ember_udp_reachable(state);
    let needs_buddy = firewalled_like || udp_needs_help;

    // TTL-expire source records still held for a buddy ACK, genuinely before
    // anything can return early. It needs no peers, no external IP and no TCP
    // port, and it must not be reachable only on the paths that get that far:
    // three of the returns below (empty publishable table, no external IPv4,
    // IPv6-only mapping) sat above it, and the first of those is exactly what a
    // node hits when `evict_filtered_contacts` momentarily empties the table on
    // an ipfilter reload.
    //
    // This is the only periodic sweep of `ember_pending_proxy_overlay`, and
    // `ember_publish_staleness` returns `None` for any file with an `unplaced`
    // entry. So a firewalled node whose named buddy never ACKs (it can legally
    // send nothing: budget refused, publish table full, or replica rejected)
    // pinned its whole library within a couple of ticks on the 5-file-per-tick
    // floor and never again ran the sweep that would release it — publishing no
    // Ember source record for the rest of the session while ~10 signed records
    // stayed resident. The 256-entry cap never fired either, because the map
    // never grew that far.
    prune_ember_pending_proxy_overlay(state);
    // A publish set entry only means "we placed a record"; the record itself
    // lapses after `EMBER_SOURCE_RECORD_TTL` whether or not we ever re-STORE.
    // Unshare and friends-only both prune this set, but nothing did when a
    // replica simply expired — so a node that lost its buddy kept reporting
    // those files as published for the rest of the session.
    prune_expired_ember_published_sources(state);
    state.ember_proxy_buddies.prune(std::time::Instant::now());

    // Prefer the confirmed external IP (eD2K HighID / KAD firewall vote).
    // Fall back to the STUN-mapped address so a KAD-less Ember seeder
    // (HighID or LowID) can still advertise sources after a NAT probe.
    let known_ipv4 = state.external_ip.or(match state.nat_info.external_addr.map(|a| a.ip()) {
        Some(std::net::IpAddr::V4(ip)) => Some(ip),
        _ => None,
    });
    // The HighID named in the trailer — and the only contact we PROXY_STORE.
    let (buddy_candidates, named_buddy) = if firewalled_like {
        ember_source_buddy_choice(state)
    } else {
        (Vec::new(), None)
    };
    let waiting_buddy = firewalled_like && named_buddy.is_none();
    // Set before any of the returns below, which is what makes them truthful on
    // a cold start or an empty table: the /ember page reads all three false as
    // "Direct". With no routable IPv4 yet, firewalled seeders can't satisfy
    // anti-reflection and HighID seeders have nothing to claim, so both are
    // still being worked out. A firewalled node with no buddy is not reported as
    // "relayed / sharing still works" while its source STORE is skipped.
    state.ember_diagnostics.ember_dht_udp_unreachable = known_ipv4.is_none();
    state.ember_diagnostics.ember_dht_waiting_buddy = known_ipv4.is_some() && waiting_buddy;
    state.ember_diagnostics.ember_dht_firewalled_publishing =
        known_ipv4.is_some() && !waiting_buddy && needs_buddy;
    state.ember_diagnostics.ember_dht_reachability_known = true;

    // Not serving: the upload listener is refusing every inbound connection,
    // so a source record placed now names a node that will not hand the file
    // over — and it outlives the decision by a full source TTL, which is DHT
    // pollution rather than a local UX quirk.
    //
    // `uploads_halted_for_shutdown` is the right signal and `ember_tcp_firewalled`
    // is not: the firewall verdict reads `Unknown` after any event that rebuilds
    // the checker, and a node would then publish itself as a *reachable* HighID
    // source while refusing every connect. This flag names the one state in which
    // the listener really is refusing everything.
    //
    // Note that going offline is not that state — it leaves the listener up, so a
    // record placed before a disconnect stays honest and is deliberately left to
    // lapse on its own TTL.
    if state
        .uploads_halted_for_shutdown
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return;
    }

    if !settings.ember_native_enabled || tcp_port == 0 || ember_publishable_peer_count(state) == 0 {
        return;
    }
    let Some(external_ip) = known_ipv4 else {
        return;
    };
    if state.external_ip.is_none() {
        set_external_ip(state, Some(external_ip));
        state.stats.external_ip = external_ip.to_string();
    }

    if waiting_buddy {
        // Nobody has endorsed an endpoint for us yet, so there is
        // no buddy we may name. This used to fall back to the
        // pre-endorsement trailer, which named a verified contact's
        // observed address on nobody's authority but ours.
        //
        // That trailer has no consumer left. It shipped before wire
        // v4, so every peer that can still exchange frames with us
        // speaks endorsements, and a current-build searcher refuses
        // to dial an unendorsed buddy — the record was published,
        // proxied, replicated twenty ways and then parked by
        // everyone who found it. Publishing nothing this tick and
        // asking again is strictly cheaper, and the ask below is
        // answered in one round trip by any peer that could have
        // served as the buddy anyway.
        //
        // Nothing is stamped for a file we skip, so it stays due and
        // the next tick retries it; `ember_dht_waiting_buddy` is
        // what surfaces the wait.
        ask_ember_buddy_endorsements(socket, state, &buddy_candidates).await;
    }

    if firewalled_like {
        let now_ts = chrono::Utc::now().timestamp();
        let named_id = named_buddy.as_ref().map(|(contact, _)| contact.node_id);
        // A new buddy, including the one that replaces a buddy gone quiet:
        // records naming the old one would send searchers to a peer that no
        // longer relays for us until each came up for republish, up to two
        // hours later. Making them all due lets the per-tick budget pace them.
        if named_id.is_some() && named_id != state.ember_named_source_buddy {
            if state.ember_named_source_buddy.is_some() {
                state.ember_source_publish_at.clear();
            }
            state.ember_named_source_buddy = named_id;
        }
        if let Some((contact, _)) = named_buddy.as_ref() {
            let renew = state
                .ember_dht
                .buddy_endorsement(&contact.node_id, now_ts)
                .is_some_and(|e| ember_buddy_endorsement_renew_due(e.expires_at, now_ts));
            if renew {
                ask_ember_buddy_endorsements(socket, state, std::slice::from_ref(contact)).await;
            }
        }
    }

    // The endorsement ask above is wanted every tick, so this comes after it.
    if ember_publish_queue_is_backed_up(state) {
        return;
    }

    // Select shared files whose source record is missing or past its
    // republish interval, bounded per tick. Snapshot under a short read lock
    // so it isn't held across the publish awaits below.
    //
    // Rank by staleness rather than index order: never-published files rank
    // highest, then the oldest publish first. A library larger than the
    // per-tick budget therefore republishes every file round-robin instead
    // of starving everything past the first `MAX_PER_TICK` entries. Only the
    // chosen few clone their name.
    let now = std::time::Instant::now();
    // A firewalled file is one PROXY_STORE to the named buddy, which refuses
    // whatever exceeds its per-sender allowance without an ack.
    let proxy_allowance = match &named_buddy {
        Some((buddy, _)) => state.ember_proxy_buddies.allowance(buddy.node_id, now),
        None if firewalled_like => 0,
        None => usize::MAX,
    };
    let due: Vec<([u8; 16], u64, String, [u8; 32])> = {
        let idx = local_index.read().await;
        let files = idx.all_files();
        let restricted = collect_friends_only_hashes(&idx, known_files);
        let mut ranked: Vec<(u64, usize)> = Vec::new();
        let mut publishable = 0usize;
        for (i, f) in files.iter().enumerate() {
            if !is_ember_publishable(f)
                || !kad_may_advertise_partial(known_files, &restricted, &f.hash)
            {
                continue;
            }
            let Some(hash) = hex::decode(&f.hash)
                .ok()
                .and_then(|v| <[u8; 16]>::try_from(v).ok())
            else {
                continue;
            };
            publishable += 1;
            let Some(staleness) = ember_publish_staleness(
                &state.ember_publish_unplaced,
                &state.ember_source_publish_at,
                hash,
                EmberPublishKind::Source,
                EMBER_SOURCE_REPUBLISH,
                now,
            ) else {
                continue;
            };
            ranked.push((staleness, i));
        }
        ranked.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.0));
        state.ember_publish_pass.due += ranked.len();
        ranked.truncate(
            ember_source_files_per_tick(
                publishable,
                ranked.len(),
                ember_publishable_peer_count(state),
            )
            .min(proxy_allowance),
        );
        state.ember_publish_pass.selected += ranked.len();
        ranked
            .into_iter()
            .filter_map(|(_, i)| {
                let f = &files[i];
                let hash = hex::decode(&f.hash)
                    .ok()
                    .and_then(|v| <[u8; 16]>::try_from(v).ok())?;
                Some((
                    hash,
                    f.size,
                    f.name.clone(),
                    parse_ember_file_hash(&f.ember_file_hash),
                ))
            })
            .collect()
    };
    if due.is_empty() {
        return;
    }

    let mut flags = 0u8;
    if settings.obfuscation_enabled {
        flags |= ember::SOURCE_FLAG_OBFUSCATION;
    }
    if firewalled_like {
        flags |= ember::SOURCE_FLAG_FIREWALLED | ember::SOURCE_FLAG_RELAY_CAPABLE;
    } else if needs_buddy {
        flags |= ember::SOURCE_FLAG_RELAY_CAPABLE;
    }

    let mut contact = ember::dht::publish::SourceContact {
        ip: external_ip,
        tcp_port,
        udp_port,
        flags,
        noise_pub: *state.ember_transport.local_noise_public_key(),
        user_hash: None,
        buddy: None,
        callback_token: None,
        // Only a firewalled source is reached through a relay, and HighID
        // records stay at their 41 bytes.
        quic_port: firewalled_like.then(|| advertised_quic_port(state)).flatten(),
    };
    if let Some((_, buddy)) = &named_buddy {
        contact.buddy = Some(*buddy);
        contact.user_hash = Some(state.user_hash);
    }

    for (file_hash, file_size, file_name, ember_file_hash) in due {
        let mut file_contact = contact;
        if file_contact.buddy.is_some() {
            file_contact.callback_token = Some(state.ember_dht.callback_token(&file_hash));
        }
        let record = state.ember_dht.build_source_record(
            file_hash,
            ember_file_hash,
            file_size,
            &file_name,
            file_contact,
        );
        let reference = EmberRecordRef {
            file_hash,
            kind: EmberPublishKind::Source,
            key: record.keyword_hash,
        };

        // Overlay STORE names the buddy in the trailer. Hold it until that
        // buddy ACKs PROXY_STORE so FIND_VALUE cannot succeed while
        // callback_clients is still empty.
        if let Some((buddy, _)) = &named_buddy {
            if let Some(rid) = ask_ember_source_buddy(socket, state, &record, buddy).await {
                if state.ember_pending_proxy_overlay.len() >= MAX_EMBER_PENDING_PROXY_OVERLAY {
                    if let Some(oldest) = state
                        .ember_pending_proxy_overlay
                        .iter()
                        .min_by_key(|(_, p)| p.queued_at)
                        .map(|(k, _)| *k)
                    {
                        if let Some(dropped) = state.ember_pending_proxy_overlay.remove(&oldest) {
                            drop_ember_record_pending(state, dropped.reference);
                        }
                    }
                }
                track_ember_record_pending(state.publish_schedule(), reference);
                state.ember_pending_proxy_overlay.insert(
                    (buddy.node_id, rid),
                    EmberPendingProxyOverlay {
                        record,
                        reference,
                        queued_at: std::time::Instant::now(),
                    },
                );
            }
            continue;
        }

        state.ember_dht.store_own_record(&record);
        if enqueue_ember_source_overlay(state, &record, reference) {
            track_ember_record_pending(state.publish_schedule(), reference);
        }
    }

    flush_ember_batch_publish(socket, state).await;
}

/// Contacts a firewalled publisher may name as its buddy, most recently seen
/// first, and the first of them holding a live endorsement for us.
///
/// A buddy that has let [`ember_publish::EMBER_BUDDY_SILENT_ROUNDS_BEFORE_SKIP`]
/// rounds of asks in a row expire unanswered is left out of both for
/// [`ember_publish::EMBER_BUDDY_SKIP`], so the next endorsed contact is named in
/// its place and endorsement asks go to others. It is still named when no other
/// endorsed contact is left: without a buddy no firewalled source publishes at
/// all, which is never better than asking one that may yet answer.
pub(super) fn ember_source_buddy_choice(
    state: &mut NetworkState,
) -> (
    Vec<ember::dht::EmberContact>,
    Option<(ember::dht::EmberContact, ember::dht::publish::SourceBuddy)>,
) {
    let now_ts = chrono::Utc::now().timestamp();
    let now = std::time::Instant::now();
    state.ember_dht.prune_buddy_endorsements(now_ts);
    let mut c = state.ember_dht.contacts();
    for extra in state.ember_session_dht_contacts.values() {
        if !c.iter().any(|held| held.node_id == extra.node_id) {
            c.push(extra.clone());
        }
    }
    c.retain(|x| {
        x.node_id != state.ember_dht.local_id() && x.failed_queries == 0 && x.is_verified()
    });
    c.sort_by_key(|contact| std::cmp::Reverse(contact.last_seen));
    let (live, skipped): (Vec<_>, Vec<_>) = c
        .into_iter()
        .partition(|x| !state.ember_proxy_buddies.is_skipped(&x.node_id, now));
    let endorsed = |pool: &[ember::dht::EmberContact]| {
        pool.iter().find_map(|contact| {
            ember_named_source_buddy(state, contact, now_ts).map(|buddy| (contact.clone(), buddy))
        })
    };
    let named = endorsed(&live).or_else(|| endorsed(&skipped));
    (live, named)
}

/// Ask the best few candidates to endorse their own endpoints for us.
///
/// A firewalled publisher cannot name a buddy it holds no endorsement from, so
/// this is what unblocks firewalled source publish. Bounded per tick, and the
/// engine suppresses re-asking a candidate that has not answered — a peer too
/// old to speak `BUDDY_ENDORSE_REQ` decodes it as an unknown type and stays
/// silent, so this must never become a per-tick retry loop.
pub(super) async fn ask_ember_buddy_endorsements(
    socket: &UdpSocket,
    state: &mut NetworkState,
    candidates: &[ember::dht::EmberContact],
) {
    /// Candidates asked per tick. The first routable few are the ones the
    /// selection loop would name anyway.
    const MAX_ASKS_PER_TICK: usize = 3;
    let now = std::time::Instant::now();
    let mut asked = 0usize;
    for contact in candidates {
        if asked >= MAX_ASKS_PER_TICK {
            break;
        }
        if !matches!(contact.addr.ip(), std::net::IpAddr::V4(ip)
            if !crate::security::is_special_use_v4(ip))
            || contact.addr.port() == 0
        {
            continue;
        }
        let Some((_rid, frame)) = state
            .ember_dht
            .build_buddy_endorse_req(contact.node_id, now)
        else {
            continue;
        };
        asked += 1;
        match state.ember_transport.prepare_outgoing(
            contact.addr,
            Some(&contact.noise_pub),
            &frame,
        ) {
            ember::transport::OutgoingResult::Ready { packet }
            | ember::transport::OutgoingResult::HandshakeStarted { packet } => {
                let _ = send_ember_udp(
                    socket,
                    &packet,
                    contact.addr,
                    &state.ember_dht_overhead,
                )
                .await;
            }
            ember::transport::OutgoingResult::Queued
            | ember::transport::OutgoingResult::Error(_) => {}
        }
    }
}

/// Send `PROXY_STORE` to the HighID named in the source trailer.
pub(super) async fn ask_ember_source_buddy(
    socket: &UdpSocket,
    state: &mut NetworkState,
    record: &ember::dht::publish::SignedRecord,
    buddy: &ember::dht::EmberContact,
) -> Option<u32> {
    let key = record.keyword_hash;
    let (rid, frame) =
        state
            .ember_dht
            .build_proxy_store(key, record.data.clone(), record.signature);
    let sent =
        match state
            .ember_transport
            .prepare_outgoing(buddy.addr, Some(&buddy.noise_pub), &frame)
        {
            ember::transport::OutgoingResult::Ready { packet }
            |             ember::transport::OutgoingResult::HandshakeStarted { packet } => {
                send_ember_udp(socket, &packet, buddy.addr, &state.ember_dht_overhead)
                    .await
                    .is_ok()
            }
            ember::transport::OutgoingResult::Queued => {
                // Handshake already in flight; the frame is queued and
                // will flush when the session completes — same as
                // `drive_ember_publish`. Treating this as failure skipped
                // buddy fan-out for the whole tick.
                true
            }
            ember::transport::OutgoingResult::Error(_) => false,
        };
    if sent {
        let now = std::time::Instant::now();
        state
            .ember_dht
            .note_proxy_store_sent(buddy.node_id, rid, record.file_hash, now);
        state.ember_proxy_buddies.note_asked(buddy.node_id, now);
        state.ember_diagnostics.ember_dht_buddy_publishes = state
            .ember_diagnostics
            .ember_dht_buddy_publishes
            .saturating_add(1);
        Some(rid)
    } else {
        None
    }
}

/// Send Ember `CALLBACK_REQ` to the HighID buddy named in a firewalled source record.
///
/// `buddy_node_id` is the DHT identity the signed trailer named. It is required
/// — and the callers corroborate it against a contact they already hold —
/// because `SOURCE_FLAG_FIREWALLED` exempts the record from the storer's
/// anti-reflection sender-IP bind, so the address alone is only the publisher's
/// claim. Refusing a zero ID here keeps every send site honest about that.
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_ember_callback_req(
    socket: &UdpSocket,
    state: &mut NetworkState,
    buddy_ip: Ipv4Addr,
    buddy_udp: u16,
    buddy_noise: [u8; 32],
    buddy_node_id: [u8; 16],
    publisher_id: ember::dht::EmberNodeId,
    file_hash: [u8; 16],
    searcher_tcp_port: u16,
    crypt_options: u8,
    searcher_user_hash: [u8; 16],
    callback_token: [u8; 16],
) -> bool {
    if buddy_udp == 0 || crate::security::is_special_use_v4(buddy_ip) {
        return false;
    }
    if buddy_node_id == [0u8; 16] {
        return false;
    }
    if callback_token == [0u8; 16] {
        return false;
    }
    let addr = SocketAddr::new(std::net::IpAddr::V4(buddy_ip), buddy_udp);
    let (_rid, frame) = state.ember_dht.build_callback_req(
        publisher_id,
        file_hash,
        searcher_tcp_port,
        crypt_options,
        searcher_user_hash,
        callback_token,
    );
    let sent = match state
        .ember_transport
        .prepare_outgoing(addr, Some(&buddy_noise), &frame)
    {
        ember::transport::OutgoingResult::Ready { packet }
        | ember::transport::OutgoingResult::HandshakeStarted { packet } => {
            send_ember_udp(socket, &packet, addr, &state.ember_dht_overhead)
                .await
                .is_ok()
        }
        ember::transport::OutgoingResult::Queued => true,
        ember::transport::OutgoingResult::Error(_) => false,
    };
    if sent {
        state.ember_diagnostics.ember_dht_callback_sent = state
            .ember_diagnostics
            .ember_dht_callback_sent
            .saturating_add(1);
    }
    sent
}

/// Publish Ember DHT *keyword* records for shared files (slice 8) so a
/// keyword search can find them on a KAD-less network. Mirrors
/// `maybe_publish_ember_sources`, but keys off each filename keyword and
/// (unlike source records) does NOT require us to be reachable: the record
/// is stored on other nodes, so our firewall / LowID status is irrelevant.
/// Selection is staleness-ranked and bounded per tick so a large library
/// republishes round-robin instead of starving everything past the budget.
pub(super) async fn maybe_publish_ember_keywords(
    socket: &UdpSocket,
    state: &mut NetworkState,
    settings: &AppSettings,
    local_index: &Arc<RwLock<LocalIndex>>,
    known_files: &mut KnownFileList,
) {
    if !settings.ember_native_enabled || ember_publishable_peer_count(state) == 0 {
        return;
    }
    if ember_publish_queue_is_backed_up(state) {
        return;
    }

    let now = std::time::Instant::now();
    // The path trails the fields the publish itself needs, for the one-time media
    // probe below.
    let due: Vec<([u8; 16], u64, String, [u8; 32], String)> = {
        let idx = local_index.read().await;
        let files = idx.all_files();
        let restricted = collect_friends_only_hashes(&idx, known_files);
        let mut ranked: Vec<(u64, usize)> = Vec::new();
        for (i, f) in files.iter().enumerate() {
            if !is_ember_publishable(f)
                || !kad_may_advertise_partial(known_files, &restricted, &f.hash)
            {
                continue;
            }
            let Some(hash) = hex::decode(&f.hash)
                .ok()
                .and_then(|v| <[u8; 16]>::try_from(v).ok())
            else {
                continue;
            };
            let Some(staleness) = ember_publish_staleness(
                &state.ember_publish_unplaced,
                &state.ember_keyword_publish_at,
                hash,
                EmberPublishKind::Keyword,
                EMBER_KEYWORD_REPUBLISH,
                now,
            ) else {
                continue;
            };
            ranked.push((staleness, i));
        }
        // Budget follows library size so the whole library completes a cycle
        // inside the republish interval. A fixed budget silently stopped
        // republishing everything past the first few thousand files.
        let publishable = files.iter().filter(|f| is_ember_publishable(f)).count();
        ranked.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.0));
        state.ember_publish_pass.due += ranked.len();
        ranked.truncate(ember_keyword_files_per_tick(
            publishable,
            ember_publishable_peer_count(state),
        ));
        state.ember_publish_pass.selected += ranked.len();
        ranked
            .into_iter()
            .filter_map(|(_, i)| {
                let f = &files[i];
                let hash = hex::decode(&f.hash)
                    .ok()
                    .and_then(|v| <[u8; 16]>::try_from(v).ok())?;
                Some((
                    hash,
                    f.size,
                    f.name.clone(),
                    parse_ember_file_hash(&f.ember_file_hash),
                    f.path.clone(),
                ))
            })
            .collect()
    };
    if due.is_empty() {
        return;
    }

    // Read the media off files that have never been probed, and remember the
    // answer — including "none", which is the answer for most of a library and has
    // to be as durable as a positive one or every archive is re-read on every
    // pass.
    //
    // Held to a small slice of the tick rather than all of `due`. This is awaited
    // from the network `select!`, so its duration is time eD2K, KAD and Ember are
    // all suspended — the hazard the download path names explicitly where it
    // refuses to await a file hash inline. `due` alone is not a tight enough
    // bound: it reaches EMBER_KEYWORD_PUBLISH_MAX_PER_TICK, and 96 header reads on
    // a slow or networked disk is a visible stall in every transfer.
    //
    // Nothing is lost by going slower. A file whose turn has not come publishes
    // without media now and gains it on republish, and at this rate a library of
    // several thousand is fully probed inside one republish interval anyway.
    let unscanned = files_needing_media_probe(
        &due,
        |hash| known_files.media_for(hash).map(|(seen, _)| seen),
        MEDIA_PROBES_PER_TICK,
    );
    if !unscanned.is_empty() {
        let probed = tokio::task::spawn_blocking(move || {
            unscanned
                .into_iter()
                .map(|(hash, path)| {
                    (
                        hash,
                        crate::commands::sharing::extract_media_metadata(&path),
                    )
                })
                .collect::<Vec<_>>()
        })
        .await;
        match probed {
            Ok(results) => {
                for (hash, media) in results {
                    known_files.set_media(&hash, media);
                }
            }
            Err(e) => debug!("Ember keyword publish: media probe task failed: {e}"),
        }
    }

    let mut files_with_no_keywords: Vec<[u8; 16]> = Vec::new();
    for (file_hash, file_size, file_name, ember_file_hash, _path) in due {
        // Whatever the probe above (or an earlier pass) found. Announced with the
        // record so an Ember-only search hit can fill the Length, Bitrate, Codec
        // and tag columns a server result fills — something KAD has no room for
        // in a keyword entry at all.
        let media = known_files
            .media_for(&file_hash)
            .and_then(|(_, media)| media);
        // Same tokenization as KAD keyword publishing/search so an Ember
        // search hashes the identical keyword set.
        let keywords = kad::publish::extract_keywords(&file_name);
        if keywords.is_empty() {
            // Nothing to publish for this name, ever. Mark it done so it does
            // not get re-selected every tick and starve the rest of the
            // library.
            files_with_no_keywords.push(file_hash);
            continue;
        }
        let mut planned: Vec<(
            EmberRecordRef,
            ember::dht::publish::SignedRecord,
            Vec<ember::dht::EmberContact>,
        )> = Vec::new();
        for keyword in keywords {
            let record = state.ember_dht.build_keyword_record_with_media(
                &keyword,
                file_hash,
                ember_file_hash,
                file_size,
                &file_name,
                media.as_ref(),
            );
            state.ember_dht.store_own_record(&record);
            let targets = ember_overlay_publish_targets(state, record.keyword_hash);
            let reference = EmberRecordRef {
                file_hash,
                kind: EmberPublishKind::Keyword,
                key: record.keyword_hash,
            };
            planned.push((reference, record, targets));
        }
        // All-or-nothing: tracking only the keywords that fit the queue let
        // the ones that landed stamp the file, locking the skipped terms out
        // for a full republish interval.
        if planned.iter().any(|(_, _, t)| t.is_empty()) {
            continue;
        }
        let need: usize = planned.iter().map(|(_, _, t)| t.len()).sum();
        if state
            .ember_batch_publish
            .queued_count
            .saturating_add(need)
            > EMBER_BATCH_QUEUE_MAX
        {
            continue;
        }
        for (reference, record, targets) in planned {
            if state.ember_batch_publish.enqueue(
                &targets,
                reference,
                ember::dht::messages::BatchedRecord {
                    key: record.keyword_hash,
                    record: record.data.clone(),
                    record_signature: record.signature,
                },
            ) {
                track_ember_record_pending(state.publish_schedule(), reference);
            }
        }
    }
    for hash in files_with_no_keywords {
        state
            .publish_schedule()
            .stamp(hash, EmberPublishKind::Keyword, now);
    }

    flush_ember_batch_publish(socket, state).await;
}
