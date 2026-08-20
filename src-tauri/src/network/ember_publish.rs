//! Ember DHT record publishing: batch queueing, pacing and ack accounting.
//!
//! What belongs here: the types describing *what* is being published (record
//! references, publish kinds, per-file backoff), the destination-grouped
//! `EmberBatchPublisher` and its bookkeeping, and the tuning constants that
//! pace it against what a storer will accept. All of it is self-contained —
//! it never touches `NetworkState`, so it can be reasoned about and unit
//! tested on its own.
//!
//! What does not belong here: anything that reads or advances the publish
//! *schedule* on `NetworkState` (`EmberPublishSchedule`,
//! `fail_ember_record_pending`, `confirm_ember_record_placed`), and the
//! socket-facing passes (`flush_ember_batch_publish`,
//! `maybe_publish_ember_sources`). Those need the live state and stay in the
//! parent module.

use std::collections::HashMap;

use super::ember;
use super::EMBER_SEARCH_QUEUED_QUERY_TIMEOUT;

/// Which per-file republish schedule a queued record belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum EmberPublishKind {
    Keyword,
    Source,
    /// Storer-side replication of a record someone else published. There is
    /// no local schedule to advance, so a confirmation is bookkeeping only.
    Replication,
}

/// Identifies one published record: which file and schedule it belongs to,
/// and the DHT key it lives under.
///
/// A file contributes one record per keyword, each to a different key and so
/// a different set of storers. The key is carried because a file counts as
/// published only once *every* one of its records has landed somewhere —
/// retiring it when the first one lands would leave its other keywords
/// unsearchable for a full republish interval.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct EmberRecordRef {
    pub(crate) file_hash: [u8; 16],
    pub(crate) kind: EmberPublishKind,
    pub(crate) key: [u8; 16],
}

/// Backoff state for one file's records of a given kind.
///
/// `last_charged` exists so that the `K_EMBER_REPLICAS` batches carrying one
/// round all count as the single round they are. See
/// [`super::charge_ember_publish_round`].
pub(crate) struct EmberPublishAttempts {
    pub(crate) rounds_failed: u32,
    pub(crate) last_charged: std::time::Instant,
}

/// A record waiting to be sent to one destination.
pub(crate) struct EmberQueuedRecord {
    pub(crate) reference: EmberRecordRef,
    pub(crate) record: ember::dht::messages::BatchedRecord,
}

/// What one publish pass picked up and what its flush achieved.
///
/// Reported by the publish heartbeat so `due` versus `selected` shows whether
/// the budget or the library is the limit, and `flush` shows whether the
/// selected work actually left the host.
#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct EmberPublishPassStats {
    /// Files past their republish interval and not already awaiting placement.
    pub(crate) due: usize,
    /// How many of those the per-tick budget took.
    pub(crate) selected: usize,
    pub(crate) flush: EmberFlushStats,
}

/// What one `flush_ember_batch_publish` pass actually managed to do.
///
/// Reported by the publish heartbeat: without it there is no way to tell a
/// tick that delivered everything from one that dropped most of it, and the
/// terminal's only publish lines come from KAD.
#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct EmberFlushStats {
    pub(crate) frames_sent: usize,
    pub(crate) records_sent: usize,
    /// Frames handed to the transport while a Noise handshake was still in
    /// progress. They are committed and will go out when it completes, but no
    /// bytes have left yet, so they are counted apart from `frames_sent`
    /// rather than folded in — otherwise a heartbeat reporting `sent=0` while
    /// a dozen batches sit in `in_flight` looks like an accounting error.
    pub(crate) frames_behind_handshake: usize,
    pub(crate) records_behind_handshake: usize,
    pub(crate) records_carried: usize,
    pub(crate) records_dropped: usize,
    /// Replication records the flush could not carry and put back on the
    /// republish schedule. Counted apart from `records_dropped` so that number
    /// stays what it says it is: work thrown away.
    pub(crate) records_rearmed: usize,
}

/// One `STORE_BATCH` awaiting its ack, in the order its records were packed
/// so the ack bitmap lines up.
pub(crate) struct EmberBatchInFlight {
    pub(crate) node_id: ember::dht::EmberNodeId,
    pub(crate) records: Vec<EmberRecordRef>,
    pub(crate) deadline: std::time::Instant,
}

/// Groups a publish tick's records by destination so each peer receives one
/// datagram instead of one per record.
///
/// Publishing a large library record-by-record puts the frame count in
/// proportion to (records x replicas), which both saturates the uplink and
/// trips the receiver's per-peer STORE rate limit — so a big library could
/// never finish a republish cycle inside the record TTL. Grouping by
/// destination puts the frame count in proportion to peers instead.
#[derive(Default)]
pub(crate) struct EmberBatchPublisher {
    pub(crate) queued:
        HashMap<ember::dht::EmberNodeId, (ember::dht::EmberContact, Vec<EmberQueuedRecord>)>,
    /// Running total across `queued`. A tick enqueues one entry per
    /// (record x replica) — thousands for a large library — so the cap check
    /// cannot afford to re-sum every destination on each call.
    pub(crate) queued_count: usize,
    pub(crate) in_flight: HashMap<u32, EmberBatchInFlight>,
    /// Records sent to each peer in the current minute, so the flush can run
    /// often without exceeding what a storer will accept. See
    /// [`EMBER_STORE_RECORDS_PER_PEER_PER_MIN`].
    pub(crate) sent_window: HashMap<ember::dht::EmberNodeId, (u32, std::time::Instant)>,
}

/// How one storer's `STORE_BATCH_ACK` resolved the records it was sent.
#[derive(Default)]
pub(crate) struct EmberBatchAckOutcome {
    /// Records this storer took. One acceptance anywhere places the record.
    pub(crate) placed: Vec<EmberRecordRef>,
    /// Records this storer turned away — full, too distant, over a cap. Another
    /// replica may still take them, so this is a failed *attempt*, not a lost
    /// record; it is charged the same way an unanswered batch is.
    pub(crate) refused: Vec<EmberRecordRef>,
}

/// Records the queue may hold before it starts refusing work, so a tick that
/// cannot flush (transport down) cannot grow without bound.
pub(crate) const EMBER_BATCH_QUEUE_MAX: usize = 8192;

/// Consecutive publish rounds a file may leave unconfirmed before it is made
/// to wait out a full republish interval.
///
/// Selection is staleness-ranked and a never-confirmed file sits at maximum
/// staleness forever, so a file that no peer will store — rejected on
/// proximity, or over a storer's capacity — would be re-picked at the top of
/// the ranking on every tick. Once enough such files exist to fill the
/// per-tick budget, nothing else in the library is ever published again.
pub(crate) const EMBER_PUBLISH_MAX_ATTEMPTS: u32 = 3;

/// `STORE_BATCH` frames we will send one peer in a single flush.
///
/// A receiver drops everything past `MAX_MSGS_PER_WINDOW` frames per second,
/// so a burst larger than that is simply thrown away — and discarded frames
/// are never acked, so the files they carried are republished from scratch on
/// the next tick, forever. This sits well under that allowance to leave room
/// for the searches, pings and gossip that share it. Whatever does not fit is
/// held over by [`super::flush_ember_batch_publish`] for the next flush.
///
/// The case that makes this matter is a *small* table: `find_closest` returns
/// every peer it knows for every key, so each destination's queue holds the
/// entire tick's output rather than a twentieth of it.
pub(crate) const EMBER_MAX_BATCH_FRAMES_PER_PEER: usize = 12;

/// Records we will send one peer per minute.
///
/// The binding limit is the *receiver's*, not ours:
/// [`scale::NetworkScale::max_stores_per_minute`] charges a storer's budget per
/// record and refuses the rest, and a refused record is never acked, so
/// overshooting means republishing it forever. A storer with a healthy table
/// enforces the strictest tier and we cannot see which tier a given peer is in,
/// so pace to that rather than to the more generous bootstrap figure.
pub(crate) const EMBER_STORE_RECORDS_PER_PEER_PER_MIN: u32 = 120;

/// How often the queued records are drained.
///
/// Publishing used to flush only on the 60-second publish tick, so whatever a
/// destination's frame budget could not carry waited a whole minute even on an
/// idle link — and before carry-over existed it was simply discarded. Draining
/// on a short cadence clears a backlog in minutes instead of tens of minutes,
/// while [`EMBER_STORE_RECORDS_PER_PEER_PER_MIN`] still holds the average to
/// what a storer will accept and [`EMBER_MAX_BATCH_FRAMES_PER_PEER`] keeps any
/// single flush well under the receiver's per-second frame limit.
pub(crate) const EMBER_FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(6);

/// Records one destination may hold over to later flushes.
///
/// Carry-over exists so that work already selected is not silently lost, not
/// as an unbounded spool. Without a per-peer bound, one peer that never drains
/// would fill [`EMBER_BATCH_QUEUE_MAX`] on its own and `enqueue` would then
/// refuse work for every other destination too. Past this the excess is
/// dropped and its files are returned to the due pool, which is the honest
/// outcome: it is the selection budget that should come down, and
/// [`super::ember_keyword_files_per_tick`] and
/// [`super::ember_source_files_per_tick`] size themselves so this is not
/// reached in the steady state.
pub(crate) const EMBER_MAX_CARRY_OVER_PER_PEER: usize = 256;
/// How many nodes each record is replicated to. Kademlia's k, and the same
/// value `PublishManager` uses for the single-record path.
pub(crate) const K_EMBER_REPLICAS: usize = ember::dht::K_BUCKET_SIZE;
/// How long to wait for a `STORE_BATCH_ACK` before giving up on it. The file
/// simply stays due, so the next tick retries it.
pub(crate) const EMBER_BATCH_ACK_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(30);

/// When a batch is queued behind Noise, wait out the handshake budget on top
/// of the ordinary ack window. Single-record publish already does this
/// (`EMBER_SEARCH_QUEUED_QUERY_TIMEOUT` instead of 5s); batches used a flat
/// 30s from stamp time, so a handshake that had not flushed still occupied
/// `in_flight` and an ACK after the session completed could miss the entry.
pub(crate) fn ember_batch_ack_deadline(
    now: std::time::Instant,
    behind_handshake: bool,
) -> std::time::Instant {
    let budget = if behind_handshake {
        EMBER_BATCH_ACK_TIMEOUT + EMBER_SEARCH_QUEUED_QUERY_TIMEOUT
    } else {
        EMBER_BATCH_ACK_TIMEOUT
    };
    now + budget
}

impl EmberBatchPublisher {
    /// Queue `record` for every target. Returns whether it was accepted (the
    /// cap can refuse it), so the caller knows whether to expect an ack.
    pub(crate) fn enqueue(
        &mut self,
        targets: &[ember::dht::EmberContact],
        reference: EmberRecordRef,
        record: ember::dht::messages::BatchedRecord,
    ) -> bool {
        // Counted against the whole fan-out, not just the first replica: the
        // check used to run once and the loop then added one entry per target,
        // so the documented ceiling could be overshot by `K_EMBER_REPLICAS - 1`.
        if targets.is_empty()
            || self.queued_count.saturating_add(targets.len()) > EMBER_BATCH_QUEUE_MAX
        {
            return false;
        }
        for contact in targets {
            let entry = self
                .queued
                .entry(contact.node_id)
                .or_insert_with(|| (contact.clone(), Vec::new()));
            entry.1.push(EmberQueuedRecord {
                reference,
                record: record.clone(),
            });
            self.queued_count += 1;
        }
        true
    }

    /// Apply a `STORE_BATCH_ACK`, splitting the batch into what the storer took
    /// and what it turned away.
    ///
    /// `accepted` is a bitmap over the batch's record positions. Acceptance is
    /// decided per record by the storer, so treating a partial batch as wholly
    /// successful would retire files that were never stored anywhere — and
    /// discarding the rejected half was just as wrong in the other direction:
    /// those records stayed marked as awaiting placement with nothing left to
    /// resolve them, because only an ack *timeout* charged a failed round. An
    /// ack that accepted nothing took neither path, and the file was locked out
    /// of selection for the rest of the session.
    pub(crate) fn note_ack(
        &mut self,
        request_id: u32,
        accepted: u64,
        from: ember::dht::EmberNodeId,
    ) -> EmberBatchAckOutcome {
        let Some(batch) = self.in_flight.get(&request_id) else {
            return EmberBatchAckOutcome::default();
        };
        // Bind the ack to the node the batch went to, like the single-record
        // STORE_ACK path: request ids are a plain counter.
        if batch.node_id != from {
            return EmberBatchAckOutcome::default();
        }
        let batch = self.in_flight.remove(&request_id).expect("just checked");
        let mut outcome = EmberBatchAckOutcome::default();
        for (i, reference) in batch.records.into_iter().enumerate() {
            if accepted & (1u64 << i) != 0 {
                outcome.placed.push(reference);
            } else {
                outcome.refused.push(reference);
            }
        }
        outcome
    }

    /// Drop batches whose ack never came, returning the records they carried.
    ///
    /// The references are returned rather than merely counted because these are
    /// the only publishes known to have reached the wire and failed, which is
    /// what [`super::charge_ember_publish_round`] is allowed to hold against
    /// a file.
    pub(crate) fn expire(&mut self, now: std::time::Instant) -> Vec<EmberRecordRef> {
        let mut abandoned = Vec::new();
        self.in_flight.retain(|_, b| {
            let live = now < b.deadline;
            if !live {
                abandoned.extend_from_slice(&b.records);
            }
            live
        });
        abandoned
    }

    /// Whether `reference` still sits in a queued or in-flight batch, so a
    /// refusal or timeout from one replica must not retire it yet.
    pub(crate) fn record_still_outstanding(&self, reference: EmberRecordRef) -> bool {
        self.in_flight
            .values()
            .any(|b| b.records.contains(&reference))
            || self
                .queued
                .values()
                .any(|(_, recs)| recs.iter().any(|q| q.reference == reference))
    }

    /// Put records the flush could not send back under their destination,
    /// newest work behind them, returning the ones that had to be dropped because
    /// the destination is already holding its limit.
    ///
    /// Whole records rather than bare references, because the caller has to be
    /// able to re-arm a dropped *replication* record, and that needs the signature
    /// the reference does not carry.
    pub(crate) fn carry_over(
        &mut self,
        node_id: ember::dht::EmberNodeId,
        contact: &ember::dht::EmberContact,
        mut tail: Vec<EmberQueuedRecord>,
    ) -> Vec<EmberQueuedRecord> {
        let entry = self
            .queued
            .entry(node_id)
            .or_insert_with(|| (contact.clone(), Vec::new()));
        let room = EMBER_MAX_CARRY_OVER_PER_PEER.saturating_sub(entry.1.len());
        let dropped: Vec<EmberQueuedRecord> = tail.split_off(tail.len().min(room));
        self.queued_count += tail.len();
        // Ahead of anything queued since, so the oldest work still goes first.
        let held = std::mem::replace(&mut entry.1, tail);
        entry.1.extend(held);
        if entry.1.is_empty() {
            self.queued.remove(&node_id);
        }
        dropped
    }

    /// Records this peer may still be sent this minute.
    pub(crate) fn record_allowance(
        &mut self,
        node_id: ember::dht::EmberNodeId,
        now: std::time::Instant,
    ) -> usize {
        match self.sent_window.get(&node_id) {
            Some((used, since))
                if now.duration_since(*since) < std::time::Duration::from_secs(60) =>
            {
                EMBER_STORE_RECORDS_PER_PEER_PER_MIN.saturating_sub(*used) as usize
            }
            _ => EMBER_STORE_RECORDS_PER_PEER_PER_MIN as usize,
        }
    }

    pub(crate) fn note_records_sent(
        &mut self,
        node_id: ember::dht::EmberNodeId,
        now: std::time::Instant,
        records: usize,
    ) {
        if records == 0 {
            return;
        }
        let entry = self.sent_window.entry(node_id).or_insert((0, now));
        if now.duration_since(entry.1) >= std::time::Duration::from_secs(60) {
            *entry = (0, now);
        }
        entry.0 = entry.0.saturating_add(records as u32);
    }

    /// Forget pacing state for peers we have not sent to in a while, so a long
    /// session's churn cannot grow the map without bound.
    pub(crate) fn prune_sent_window(&mut self, now: std::time::Instant) {
        self.sent_window.retain(|_, (_, since)| {
            now.duration_since(*since) < std::time::Duration::from_secs(300)
        });
    }

    pub(crate) fn clear(&mut self) {
        self.queued.clear();
        self.queued_count = 0;
        self.in_flight.clear();
        self.sent_window.clear();
    }
}
