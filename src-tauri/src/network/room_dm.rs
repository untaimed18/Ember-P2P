//! Private messages between room members: what arrives, and the frames this
//! device sends. The codec is `ember::room_dm`; storage is `room_dm_*` in the
//! database; choosing the room, the send command and resends are in
//! `commands::room_dm`.
//!
//! Shares the parent module's namespace through `use super::*`.

use super::*;
use crate::network::ember::room_dm::{DmPayload, PairwiseBase};
use crate::storage::database::DmIncoming;
use crate::types::IgnoredMember;

/// Oldest private-message frame acted on: the relay window, inside which a
/// frame is also charged to its author's rate. Resends go out under fresh
/// envelopes, so nothing honest is older.
pub(crate) const DM_MAX_AGE_SECS: i64 = ember::channel::CHANNEL_GOSSIP_RELAY_FRESH_SECS;

/// Emitted for a message that arrived and was kept: `{ member_pubkey, name,
/// message_id, text, timestamp, request, new_thread }`.
pub(crate) const DM_MESSAGE_EVENT: &str = "ember:dm-message";
/// Emitted when one of ours changes state: `{ member_pubkey, message_id,
/// status }`.
pub(crate) const DM_STATUS_EVENT: &str = "ember:dm-status";
/// Emitted when a conversation changed in a way a list shows: `{
/// member_pubkey }`.
pub(crate) const DM_THREAD_EVENT: &str = "ember:dm-thread";

/// Who may write, and who is ignored, as settings last said. Read on the
/// network loop for every message that arrives, so a change applies at once.
struct DmPolicy {
    policy: String,
    ignored: Vec<IgnoredMember>,
}

fn dm_policy() -> &'static parking_lot::RwLock<DmPolicy> {
    static POLICY: std::sync::OnceLock<parking_lot::RwLock<DmPolicy>> = std::sync::OnceLock::new();
    POLICY.get_or_init(|| {
        parking_lot::RwLock::new(DmPolicy {
            policy: crate::types::ROOM_DM_POLICY_ASK.to_string(),
            ignored: Vec::new(),
        })
    })
}

/// Take up what settings say: at startup and whenever they change.
pub(crate) fn set_dm_policy(policy: &str, ignored: Option<&[IgnoredMember]>) {
    let mut current = dm_policy().write();
    current.policy = policy.to_string();
    current.ignored = ignored.map(<[IgnoredMember]>::to_vec).unwrap_or_default();
}

fn dm_ignored(member_hex: &str, channel_hex: &str) -> bool {
    ignored_in(&dm_policy().read().ignored, member_hex, channel_hex)
}

fn ignored_in(list: &[IgnoredMember], member_hex: &str, channel_hex: &str) -> bool {
    list.iter()
        .any(|entry| entry.pubkey.eq_ignore_ascii_case(member_hex) && entry.covers(channel_hex))
}

/// Replies (receipts, declines) one member can draw from us in
/// [`DM_REPLY_WINDOW`]. Each is a frame of ours in the room, charged to our
/// own rate at every member it passes, so a member writing as fast as relays
/// allow must not be able to spend that rate for us and crowd out our chat.
const DM_REPLIES_PER_WINDOW: usize = 30;
const DM_REPLY_WINDOW: std::time::Duration = std::time::Duration::from_secs(600);
/// Declines one member draws from us in [`DM_REPLY_WINDOW`]: one says it.
const DM_DECLINES_PER_WINDOW: usize = 1;

/// Whether a reply of `kind` to `peer` is within its allowance now, taking
/// it if so.
fn dm_reply_allowed(peer: &[u8; 32], decline: bool) -> bool {
    type Sent = HashMap<([u8; 32], bool), std::collections::VecDeque<std::time::Instant>>;
    static SENT: std::sync::OnceLock<std::sync::Mutex<Sent>> = std::sync::OnceLock::new();
    const MAX_PEERS: usize = 4096;
    let mut sent = SENT.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
    let now = std::time::Instant::now();
    if sent.len() >= MAX_PEERS {
        sent.retain(|_, times| times.back().is_some_and(|at| now.saturating_duration_since(*at) < DM_REPLY_WINDOW));
    }
    let limit = if decline { DM_DECLINES_PER_WINDOW } else { DM_REPLIES_PER_WINDOW };
    let times = sent.entry((*peer, decline)).or_default();
    ember::channel::rate_window_allow(times, now, DM_REPLY_WINDOW, limit)
}

/// Pairwise secrets with the members whose private-message frames we check
/// or send, per room: each costs an X25519 exchange to derive, and every
/// frame of kind 66 in a room has to be checked against its sender's. The
/// least recently used half goes when it fills, so a crowd of senders costs
/// a derivation each rather than flushing the members already known.
fn pairwise_base(seed: &[u8; 32], channel_id: &[u8; 16], peer: &[u8; 32]) -> Option<Arc<PairwiseBase>> {
    type Bases = HashMap<([u8; 16], [u8; 32]), (Arc<PairwiseBase>, std::time::Instant)>;
    static BASES: std::sync::OnceLock<std::sync::Mutex<Bases>> = std::sync::OnceLock::new();
    const MAX_BASES: usize = 1024;
    let mut bases = BASES.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
    let now = std::time::Instant::now();
    if let Some((base, used)) = bases.get_mut(&(*channel_id, *peer)) {
        *used = now;
        return Some(base.clone());
    }
    let base = Arc::new(PairwiseBase::derive(seed, peer, channel_id)?);
    if bases.len() >= MAX_BASES {
        let mut ages: Vec<std::time::Instant> = bases.values().map(|(_, used)| *used).collect();
        ages.sort_unstable();
        let cutoff = ages[ages.len() / 2];
        bases.retain(|_, (_, used)| *used > cutoff);
    }
    bases.insert((*channel_id, *peer), (base.clone(), now));
    Some(base)
}

/// Replies waiting to go out: `(due, room, peer, payload)`.
type PendingReplies = Vec<(std::time::Instant, [u8; 16], [u8; 32], DmPayload)>;

fn pending_replies() -> &'static std::sync::Mutex<PendingReplies> {
    static PENDING: std::sync::OnceLock<std::sync::Mutex<PendingReplies>> = std::sync::OnceLock::new();
    PENDING.get_or_init(Default::default)
}

/// The most replies held back at once.
const MAX_PENDING_REPLIES: usize = 512;
/// A reply waits this long, give or take, before it goes out.
const DM_REPLY_DELAY_SECS: std::ops::RangeInclusive<u64> = 10..=90;
/// Replies sent per tick of the loop's one-second timer, from every member
/// together.
const DM_REPLIES_PER_TICK: usize = 2;

/// Hold a reply back a random while before it goes out. Every member sees
/// who sent each frame of kind 66, so a receipt that followed a message at
/// once would say whom the message was for.
fn queue_reply(channel_id: [u8; 16], peer: [u8; 32], payload: DmPayload) {
    let delay = rand::Rng::gen_range(&mut rand::thread_rng(), DM_REPLY_DELAY_SECS);
    let due = std::time::Instant::now() + std::time::Duration::from_secs(delay);
    let mut pending = pending_replies().lock().unwrap_or_else(|e| e.into_inner());
    if pending.len() < MAX_PENDING_REPLIES {
        pending.push((due, channel_id, peer, payload));
    }
}

/// Frames of kind 66 this device sends into one room in any
/// [`DM_PACE_WINDOW`], of every type together: new messages, resends and
/// replies. Relays admit
/// `CHANNEL_GOSSIP_PER_AUTHOR_PER_SEC` frames a second from one author in a
/// room, chat lines included, so this leaves the rest to chat; a frame over
/// it waits its turn rather than going out to be dropped.
const DM_FRAMES_PER_ROOM_PER_SEC: usize = 2;
const _: () = assert!(DM_FRAMES_PER_ROOM_PER_SEC < ember::channel::CHANNEL_GOSSIP_PER_AUTHOR_PER_SEC);
/// Frames waiting on their room's pace at once. Past this a receipt, decline
/// or message is dropped: a message goes again with its next resend, and a
/// resend of theirs can draw its receipt or decline again. The user's
/// answers are never dropped to make room: one takes the place of the oldest
/// frame that is not an answer.
const MAX_PACED_FRAMES: usize = 256;
/// What a room's slots are counted over. Relays count an author's frames over
/// a second, one exactly a second old still inside, and see them arrive with
/// some jitter: no window they can draw may hold more than
/// [`DM_FRAMES_PER_ROOM_PER_SEC`] of ours, so this is a second and a margin.
/// The drain takes one frame a room each tick, so a backlogged room still
/// sends one a second: the previous tick's stamp is inside the window, the
/// one before it never is.
const DM_PACE_WINDOW: std::time::Duration = std::time::Duration::from_millis(1_200);
const _: () = assert!(DM_PACE_WINDOW.as_millis() >= 1_200 && DM_PACE_WINDOW.as_millis() < 1_800);
/// The longest a frame waits on its room's pace. Older, it is dropped at the
/// drain rather than sent late: a message goes again with its next resend.
const DM_PACED_MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// Why a frame of kind 66 goes out, which decides what is checked again
/// before one that waited goes, and what gives way when the queue is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DmFrameKind {
    /// One of our messages, new or resent.
    Message,
    /// A receipt or decline drawn by something that arrived.
    Reply,
    /// The user's Accept or Decline of a request.
    Answer,
}

#[derive(Debug, Clone)]
struct PacedFrame {
    room: [u8; 16],
    peer: [u8; 32],
    payload: DmPayload,
    kind: DmFrameKind,
    queued_at: std::time::Instant,
}

/// What has gone into each room lately, and the frames waiting for room
/// there. A room's answers go before its other frames; otherwise oldest
/// first.
#[derive(Default)]
struct DmPace {
    sent: HashMap<[u8; 16], std::collections::VecDeque<std::time::Instant>>,
    waiting: std::collections::VecDeque<PacedFrame>,
}

impl DmPace {
    fn take_slot(&mut self, room: [u8; 16], now: std::time::Instant) -> bool {
        let times = self.sent.entry(room).or_default();
        ember::channel::rate_window_allow(times, now, DM_PACE_WINDOW, DM_FRAMES_PER_ROOM_PER_SEC)
    }

    /// Whether a frame for `room` may go out now. If not, it waits behind
    /// those already waiting there that go before it, so a room's frames
    /// keep their order.
    fn offer(
        &mut self,
        room: [u8; 16],
        peer: [u8; 32],
        payload: &DmPayload,
        kind: DmFrameKind,
        now: std::time::Instant,
    ) -> bool {
        let ahead = |w: &PacedFrame| w.room == room && (kind != DmFrameKind::Answer || w.kind == DmFrameKind::Answer);
        if !self.waiting.iter().any(ahead) && self.take_slot(room, now) {
            return true;
        }
        if self.waiting.len() >= MAX_PACED_FRAMES {
            if kind != DmFrameKind::Answer {
                return false;
            }
            if let Some(at) = self.waiting.iter().position(|w| w.kind != DmFrameKind::Answer) {
                self.waiting.remove(at);
            }
        }
        self.waiting.push_back(PacedFrame { room, peer, payload: payload.clone(), kind, queued_at: now });
        false
    }

    /// The waiting frames whose room has a slot now, one a room, taking
    /// their slots. Those that waited past [`DM_PACED_MAX_WAIT`] are dropped.
    fn due(&mut self, now: std::time::Instant) -> Vec<PacedFrame> {
        let (answers, rest): (std::collections::VecDeque<_>, std::collections::VecDeque<_>) = std::mem::take(&mut self.waiting)
            .into_iter()
            .filter(|frame| now.saturating_duration_since(frame.queued_at) <= DM_PACED_MAX_WAIT)
            .partition(|frame| frame.kind == DmFrameKind::Answer);
        let mut out: Vec<PacedFrame> = Vec::new();
        for frame in answers.into_iter().chain(rest) {
            if !out.iter().any(|taken| taken.room == frame.room) && self.take_slot(frame.room, now) {
                out.push(frame);
            } else {
                self.waiting.push_back(frame);
            }
        }
        // Rooms quiet for a window keep nothing.
        self.sent
            .retain(|_, times| times.back().is_some_and(|at| now.saturating_duration_since(*at) <= DM_PACE_WINDOW));
        out
    }

    /// Move the room's newest slot up to `at`, when the frame [`Self::due`]
    /// took it for went out after the tick: the window counts from when a
    /// frame left.
    fn went_at(&mut self, room: [u8; 16], at: std::time::Instant) {
        if let Some(last) = self.sent.get_mut(&room).and_then(|times| times.back_mut()) {
            *last = (*last).max(at);
        }
    }
}

fn dm_pace() -> &'static std::sync::Mutex<DmPace> {
    static PACE: std::sync::OnceLock<std::sync::Mutex<DmPace>> = std::sync::OnceLock::new();
    PACE.get_or_init(Default::default)
}

fn is_reply(payload: &DmPayload) -> bool {
    !matches!(payload, DmPayload::Message { .. })
}

/// Drop every reply and answer still waiting to go to `peer`, delayed or
/// paced: their request was removed without a word, and a receipt or
/// decline arriving after would tell them it was seen.
pub(crate) fn drop_replies_to(peer: &[u8; 32]) {
    pending_replies()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|(_, _, to, payload)| to != peer || !is_reply(payload));
    dm_pace()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .waiting
        .retain(|frame| frame.peer != *peer || frame.kind == DmFrameKind::Message);
}

/// Drop everything waiting to go out, delayed or paced: Ember is off or chat
/// is locked, and what waited would go out late, on terms that may no longer
/// hold, once it is back. Messages go again with their next resend.
pub(super) fn forget_queued_frames() {
    pending_replies().lock().unwrap_or_else(|e| e.into_inner()).clear();
    dm_pace().lock().unwrap_or_else(|e| e.into_inner()).waiting.clear();
}

/// Whether a reply queued a while ago still says what is true when its time
/// comes. Nothing to a member ignored or banned since (`reachable` false).
/// A decline only while it would still be the answer: the policy is off, or
/// the user's refusal of them holds; accepting them, writing to them or a
/// change of policy since makes it false.
fn reply_still_true(payload: &DmPayload, reachable: bool, policy_off: bool, refused: impl FnOnce() -> bool) -> bool {
    if !reachable {
        return false;
    }
    *payload != DmPayload::Decline || policy_off || refused()
}

fn dm_policy_off() -> bool {
    dm_policy().read().policy == crate::types::ROOM_DM_POLICY_OFF
}

/// What the frames going out on one tick are checked against.
#[derive(Default)]
struct DmChecks {
    /// The roster of each of their rooms.
    rosters: HashMap<[u8; 16], Arc<ChannelRosterSnapshot>>,
    /// Our messages still being sent: `(member, message id)`.
    sending: std::collections::HashSet<([u8; 32], [u8; 16])>,
    /// Members our refusal still answers.
    refused: std::collections::HashSet<[u8; 32]>,
}

impl DmChecks {
    /// Whether `peer` may still be answered in a room: not ignored there, and
    /// on its roster unbanned.
    fn reachable(&self, room: [u8; 16], peer: &[u8; 32]) -> bool {
        !dm_ignored(&hex::encode(peer), &hex::encode(room))
            && self.rosters.get(&room).is_some_and(|roster| roster.status(peer) == Some(false))
    }

    /// Whether a frame that waited still holds: a reply as
    /// [`reply_still_true`] says, an answer while its member is reachable,
    /// and a message while private messages are on and it is still being
    /// sent, not stopped by their decline or given up on meanwhile.
    fn goes(&self, frame: &PacedFrame, policy_off: bool) -> bool {
        match (frame.kind, &frame.payload) {
            (DmFrameKind::Message, DmPayload::Message { id, .. }) => {
                !policy_off && self.sending.contains(&(frame.peer, *id))
            }
            (DmFrameKind::Message, _) => false,
            (DmFrameKind::Answer, _) => self.reachable(frame.room, &frame.peer),
            (DmFrameKind::Reply, payload) => {
                let reachable = self.reachable(frame.room, &frame.peer);
                reply_still_true(payload, reachable, policy_off, || self.refused.contains(&frame.peer))
            }
        }
    }
}

/// Read what `frames` are checked against in one blocking task: whether
/// each message is still being sent, whether each decline still answers,
/// and the roster of every room whose held snapshot is no longer exact. The
/// loop reads none of it. Rosters read are kept for the room's next callers.
/// If the task fails, nothing checked by it goes.
async fn read_dm_checks(state: &mut NetworkState, db: &Arc<Database>, frames: &[PacedFrame], policy_off: bool) -> DmChecks {
    let mut checks = DmChecks::default();
    let mut stale = Vec::new();
    let mut messages = Vec::new();
    let mut declines = std::collections::HashSet::new();
    for frame in frames {
        if !checks.rosters.contains_key(&frame.room) && !stale.contains(&frame.room) {
            match channel_roster_held(state, db, frame.room) {
                Some(roster) => {
                    checks.rosters.insert(frame.room, roster);
                }
                None => stale.push(frame.room),
            }
        }
        match (frame.kind, &frame.payload) {
            (DmFrameKind::Message, DmPayload::Message { id, .. }) if !policy_off => messages.push((frame.peer, *id)),
            (DmFrameKind::Reply, DmPayload::Decline) if !policy_off => {
                declines.insert(frame.peer);
            }
            _ => {}
        }
    }
    if stale.is_empty() && messages.is_empty() && declines.is_empty() {
        return checks;
    }
    let task_db = db.clone();
    let now = chrono::Utc::now().timestamp();
    let read = tokio::task::spawn_blocking(move || {
        let rosters: Vec<([u8; 16], Arc<ChannelRosterSnapshot>)> =
            stale.into_iter().map(|room| (room, Arc::new(read_channel_roster(&task_db, room)))).collect();
        let sending = messages
            .into_iter()
            .filter(|(member, id)| task_db.dm_still_sending(&hex::encode(member), &hex::encode(id)).unwrap_or(false))
            .collect();
        let refused = declines
            .into_iter()
            .filter(|member| task_db.dm_declines(&hex::encode(member), now).unwrap_or(false))
            .collect();
        (rosters, sending, refused)
    })
    .await;
    if let Ok((rosters, sending, refused)) = read {
        for (room, roster) in rosters {
            hold_channel_roster(state, room, &roster);
            checks.rosters.insert(room, roster);
        }
        checks.sending = sending;
        checks.refused = refused;
    }
    checks
}

/// Send the frames waiting on their room's pace, then the replies whose time
/// has come, a few at a time, each only while it still holds
/// ([`DmChecks::goes`]). From the network loop's one-second timer.
pub(super) async fn send_due_replies(socket: &UdpSocket, state: &mut NetworkState, db: &Arc<Database>) {
    let now = std::time::Instant::now();
    let paced = dm_pace().lock().unwrap_or_else(|e| e.into_inner()).due(now);
    let replies: Vec<PacedFrame> = {
        let mut pending = pending_replies().lock().unwrap_or_else(|e| e.into_inner());
        let mut taken = Vec::new();
        pending.retain(|(at, room, peer, payload)| {
            if *at <= now && taken.len() < DM_REPLIES_PER_TICK {
                taken.push(PacedFrame {
                    room: *room,
                    peer: *peer,
                    payload: payload.clone(),
                    kind: DmFrameKind::Reply,
                    queued_at: now,
                });
                false
            } else {
                true
            }
        });
        taken
    };
    if paced.is_empty() && replies.is_empty() {
        return;
    }
    let policy_off = dm_policy_off();
    let checks = read_dm_checks(state, db, &[paced.as_slice(), replies.as_slice()].concat(), policy_off).await;
    for frame in paced {
        if checks.goes(&frame, policy_off) && seal_and_send(socket, state, db, frame.room, frame.peer, &frame.payload).await {
            dm_pace().lock().unwrap_or_else(|e| e.into_inner()).went_at(frame.room, std::time::Instant::now());
        }
    }
    for frame in replies {
        if checks.goes(&frame, policy_off) {
            send_paced(socket, state, db, frame.room, frame.peer, &frame.payload, DmFrameKind::Reply).await;
        }
    }
}

/// Whether a frame's envelope time is recent enough to act on.
fn dm_fresh(timestamp: i64, now: i64) -> bool {
    timestamp >= now.saturating_sub(DM_MAX_AGE_SECS)
        && timestamp <= now.saturating_add(ember::channel::CHANNEL_GOSSIP_MAX_FUTURE_SKEW_SECS)
}

/// A frame of kind 66 that met every rule a relay holds it to, and was passed
/// on. If it is to us, read it and do what it says.
///
/// Only under the room's current key: a frame opened under a retired one may
/// be from someone evicted, who is owed no answer.
pub(super) async fn on_private_message(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    gossip: &ember::channel::ChannelGossip,
    channel_id_hex: &str,
    ext: &ember::channel::ChannelExtFrame,
    opened: ember::channel::OpenedUnder,
) {
    let now = chrono::Utc::now().timestamp();
    // `flags` is 0 on every frame of this kind: one marked displayable would
    // have older builds tell the whole room a private message passed.
    if ext.sender == state.local_ed25519_pubkey
        || ext.flags != 0
        || opened != ember::channel::OpenedUnder::Current
        || !dm_fresh(gossip.timestamp, now)
    {
        return;
    }
    // Nothing is derived for a sender the roster does not hold: a crowd of
    // made-up identities would otherwise cost an exchange each.
    if !channel_member_on_roster(state, db, gossip.channel_id, &ext.sender) {
        return;
    }
    let Some(base) = pairwise_base(&state.local_ed25519_seed, &gossip.channel_id, &ext.sender) else {
        return;
    };
    let Some(payload) = base.open(&gossip.channel_id, &gossip.msg_id, gossip.timestamp, &ext.sender, &ext.body) else {
        return;
    };
    let member = hex::encode(ext.sender);
    // Before anything is kept or answered: an ignored member learns nothing,
    // not even that the message arrived.
    if dm_ignored(&member, channel_id_hex) {
        return;
    }
    match payload {
        DmPayload::Message { id, text } => {
            let message_id = hex::encode(id);
            let policy = dm_policy().read().policy.clone();
            let task_db = db.clone();
            let (channel, from, mid, body, at) =
                (channel_id_hex.to_string(), member.clone(), message_id.clone(), text.clone(), gossip.timestamp);
            let outcome = tokio::task::spawn_blocking(move || {
                // Only a member the room's roster holds: their name comes from
                // there, and a stranger has no standing to ask.
                let name = task_db.dm_member_in_room(&channel, &from).ok().flatten()?;
                let kept = task_db.dm_record_incoming(&from, &name, &channel, &mid, &body, at, &policy, now);
                Some((name, kept))
            })
            .await
            .ok()
            .flatten();
            let Some((name, kept)) = outcome else {
                return;
            };
            match kept {
                Ok(DmIncoming::Stored { request, new_thread }) => {
                    if dm_reply_allowed(&ext.sender, false) {
                        queue_reply(gossip.channel_id, ext.sender, DmPayload::Receipt { id });
                    }
                    let _ = app_handle.emit(
                        DM_MESSAGE_EVENT,
                        serde_json::json!({
                            "member_pubkey": member,
                            "name": name,
                            "message_id": message_id,
                            "text": text,
                            "timestamp": gossip.timestamp,
                            "request": request,
                            "new_thread": new_thread,
                        }),
                    );
                }
                Ok(DmIncoming::Duplicate) => {
                    if dm_reply_allowed(&ext.sender, false) {
                        queue_reply(gossip.channel_id, ext.sender, DmPayload::Receipt { id });
                    }
                }
                Ok(DmIncoming::Declined) => {
                    if dm_reply_allowed(&ext.sender, true) {
                        queue_reply(gossip.channel_id, ext.sender, DmPayload::Decline);
                    }
                }
                // Dropped unanswered: an answer would only invite more.
                Ok(DmIncoming::Capped) => {
                    debug!("Room private message: request cap reached in {channel_id_hex}");
                }
                Ok(DmIncoming::Full) => {
                    debug!("Room private message: a sender's allowance is used up in {channel_id_hex}");
                }
                Err(e) => debug!("Room private message: could not keep one: {e}"),
            }
        }
        DmPayload::Receipt { id } => {
            let message_id = hex::encode(id);
            let task_db = db.clone();
            let (from, mid) = (member.clone(), message_id.clone());
            let moved = tokio::task::spawn_blocking(move || task_db.dm_mark_delivered(&from, &mid))
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(false);
            if moved {
                let _ = app_handle.emit(
                    DM_STATUS_EVENT,
                    serde_json::json!({ "member_pubkey": member, "message_id": message_id, "status": "delivered" }),
                );
            }
        }
        DmPayload::Accept | DmPayload::Decline => {
            let accepted = payload == DmPayload::Accept;
            let task_db = db.clone();
            let from = member.clone();
            // Recorded only in a conversation open on our side, and only if
            // newer than the answer already held, by the envelope's time: a
            // replayed old answer cannot undo a later one (see
            // `dm_note_peer_answer`).
            let answered_at = gossip.timestamp;
            let (moved, stopped) = tokio::task::spawn_blocking(move || {
                task_db.dm_note_peer_answer(&from, accepted, answered_at).unwrap_or_default()
            })
            .await
            .unwrap_or_default();
            for message_id in stopped {
                let _ = app_handle.emit(
                    DM_STATUS_EVENT,
                    serde_json::json!({ "member_pubkey": member, "message_id": message_id, "status": "failed" }),
                );
            }
            if moved {
                let _ = app_handle.emit(DM_THREAD_EVENT, serde_json::json!({ "member_pubkey": member }));
            }
        }
    }
}

/// Send a frame the user's commands produced to `peer` in a room: a message
/// of ours, or the user's answer to a request. Returns whether it went out
/// now.
pub(super) async fn send_private_frame(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    channel_id: [u8; 16],
    peer: [u8; 32],
    payload: &DmPayload,
) -> bool {
    let kind = if is_reply(payload) { DmFrameKind::Answer } else { DmFrameKind::Message };
    send_paced(socket, state, db, channel_id, peer, payload, kind).await
}

/// Send `payload` to `peer` in a room: now if the room's pace allows, else
/// once it does. Every frame of kind 66 this device sends comes through here.
/// Returns whether it went out now.
async fn send_paced(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    channel_id: [u8; 16],
    peer: [u8; 32],
    payload: &DmPayload,
    kind: DmFrameKind,
) -> bool {
    let now = std::time::Instant::now();
    if !dm_pace().lock().unwrap_or_else(|e| e.into_inner()).offer(channel_id, peer, payload, kind, now) {
        return false;
    }
    seal_and_send(socket, state, db, channel_id, peer, payload).await
}

/// Seal `payload` to `peer` and send it into the room under its current key.
/// Nothing when the room is not one this device is in.
async fn seal_and_send(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    channel_id: [u8; 16],
    peer: [u8; 32],
    payload: &DmPayload,
) -> bool {
    let Some(key) = cached_channel_view(state, db, channel_id)
        .filter(|view| view.row.in_room_now())
        .and_then(|view| view.content_keys.first().copied())
    else {
        return false;
    };
    let seed = state.local_ed25519_seed;
    let Some(base) = pairwise_base(&seed, &channel_id, &peer) else {
        return false;
    };
    let our_pk = state.local_ed25519_pubkey;
    let mut msg_id = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut msg_id);
    let ts = chrono::Utc::now().timestamp();
    let Some(body) = base.seal(&channel_id, &msg_id, ts, &our_pk, payload) else {
        return false;
    };
    let kind = ember::channel::EXT_KIND_PRIVATE_MESSAGE;
    let signing = ember::crypto::signing_key_from_bytes(&seed);
    let signature = ember::channel::ext_author_signature(&signing, &channel_id, &msg_id, ts, kind, 0, &body);
    let frame = ember::channel::encode_channel_ext_frame_presigned(kind, 0, &our_pk, &signature, &body);
    let gossip = ember::channel::ChannelGossip::sealed(
        channel_id,
        msg_id,
        &key,
        ts.max(0) as u64,
        &frame,
        ember::channel::CHANNEL_MSG_TTL_DEFAULT,
        ts,
    );
    remember_originated_gossip(state, &gossip);
    fanout_channel_gossip_body(socket, state, db, gossip.encode(), None).await;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ignored_member_is_dropped_everywhere_or_in_the_rooms_named() {
        let list = [
            IgnoredMember { pubkey: "AA".into(), name: String::new(), rooms: None },
            IgnoredMember { pubkey: "bb".into(), name: String::new(), rooms: Some(vec!["r1".into()]) },
        ];
        assert!(ignored_in(&list, "aa", "anywhere"));
        assert!(ignored_in(&list, "bb", "R1"));
        assert!(!ignored_in(&list, "bb", "r2"));
        assert!(!ignored_in(&list, "cc", "r1"));
        assert!(!ignored_in(&[], "aa", "anywhere"));
    }

    #[test]
    fn a_member_draws_only_so_many_replies_and_one_decline() {
        let peer = [0x77u8; 32];
        assert!(dm_reply_allowed(&peer, true));
        assert!(!dm_reply_allowed(&peer, true), "one decline says it");
        let other = [0x78u8; 32];
        for _ in 0..DM_REPLIES_PER_WINDOW {
            assert!(dm_reply_allowed(&other, false));
        }
        assert!(!dm_reply_allowed(&other, false));
        assert!(dm_reply_allowed(&[0x79u8; 32], false), "per member");
    }

    fn receipt(n: u8) -> DmPayload {
        DmPayload::Receipt { id: [n; 16] }
    }

    #[test]
    fn a_backlogged_room_gets_a_frame_every_tick_in_order() {
        let mut pace = DmPace::default();
        let (room, other, peer) = ([1u8; 16], [2u8; 16], [9u8; 32]);
        let t0 = std::time::Instant::now();
        let sent_now: Vec<bool> =
            (0..32).map(|n| pace.offer(room, peer, &receipt(n), DmFrameKind::Reply, t0)).collect();
        assert_eq!(sent_now.iter().filter(|now| **now).count(), DM_FRAMES_PER_ROOM_PER_SEC);
        assert!(pace.offer(other, peer, &receipt(99), DmFrameKind::Reply, t0), "per room");
        assert!(pace.due(t0).is_empty(), "nothing more this tick");
        assert!(pace.due(t0 + std::time::Duration::from_secs(1)).is_empty(), "the burst is still in the window");

        let mut order = Vec::new();
        for tick in 2..=31u64 {
            let due = pace.due(t0 + std::time::Duration::from_millis(1_000 * tick));
            assert_eq!(due.len(), 1, "tick {tick}");
            order.extend(due.into_iter().map(|frame| frame.payload));
        }
        assert_eq!(order, (2..32).map(receipt).collect::<Vec<_>>(), "all of them, oldest first");

        let later = t0 + std::time::Duration::from_secs(90);
        assert!(pace.offer(room, peer, &receipt(1), DmFrameKind::Reply, later), "a quiet room sends at once");
        assert!(pace.sent.len() <= 2);
    }

    /// Ticks that come early and late, frames sent the moment they are
    /// offered between them, and a slot whose frame left after its tick: no
    /// window of [`DM_PACE_WINDOW`] holds more than the room's share, and a
    /// tick that drains nothing gave its slot to an answer or came early.
    #[test]
    fn no_window_holds_more_than_a_rooms_share() {
        let mut pace = DmPace::default();
        let (room, peer) = ([6u8; 16], [9u8; 32]);
        let t0 = std::time::Instant::now();
        let ms = std::time::Duration::from_millis;
        let mut sent = Vec::new();
        for n in 0..60u8 {
            if pace.offer(room, peer, &receipt(n), DmFrameKind::Reply, t0) {
                sent.push(t0);
            }
        }
        let gaps = [1_000u64, 920, 1_090, 870, 1_130, 1_000, 950, 1_200, 40, 1_000];
        let mut at = t0;
        let (mut idle_ticks, mut early_ticks, mut answers) = (0, 0, 0);
        for tick in 0..50usize {
            let gap = gaps[tick % gaps.len()];
            at += ms(gap);
            let next = gaps[(tick + 1) % gaps.len()];
            let due = pace.due(at);
            assert!(due.len() <= 1, "one a tick");
            if gap < 500 {
                early_ticks += 1;
            }
            if due.is_empty() {
                idle_ticks += 1;
            } else {
                let left = at + ms(if tick % 4 == 0 { next / 8 } else { 1 });
                pace.went_at(room, left);
                sent.push(left);
            }
            let between = at + ms(next / 2);
            if tick % 3 == 1 && pace.offer(room, peer, &DmPayload::Accept, DmFrameKind::Answer, between) {
                answers += 1;
                sent.push(between);
            }
        }
        sent.sort();
        for (i, three) in sent.windows(DM_FRAMES_PER_ROOM_PER_SEC + 1).enumerate() {
            let span = three[DM_FRAMES_PER_ROOM_PER_SEC].duration_since(three[0]);
            assert!(span > ms(1_200), "frames {i}.. span only {span:?}");
        }
        assert!(answers > 0);
        assert!(
            idle_ticks <= answers + early_ticks,
            "{idle_ticks} ticks drained nothing, for {answers} answers and {early_ticks} early ticks"
        );
    }

    #[test]
    fn a_frame_waits_behind_its_rooms_queue_and_the_queue_is_bounded() {
        let mut pace = DmPace::default();
        let (room, peer) = ([3u8; 16], [9u8; 32]);
        let t0 = std::time::Instant::now();
        for n in 0..=DM_FRAMES_PER_ROOM_PER_SEC as u8 {
            pace.offer(room, peer, &receipt(n), DmFrameKind::Reply, t0);
        }
        let t1 = t0 + std::time::Duration::from_millis(1_500);
        assert!(!pace.offer(room, peer, &DmPayload::Decline, DmFrameKind::Reply, t1), "not ahead of the one waiting");
        let due = pace.due(t1);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].payload, receipt(DM_FRAMES_PER_ROOM_PER_SEC as u8));
        for n in 0..MAX_PACED_FRAMES + 10 {
            pace.offer(room, peer, &receipt(n as u8), DmFrameKind::Reply, t1);
        }
        assert_eq!(pace.waiting.len(), MAX_PACED_FRAMES);
    }

    /// A full queue gives way to the user's answers, and a room's answers go
    /// before the receipts and resends waiting there.
    #[test]
    fn an_answer_is_never_dropped_for_room_and_goes_first() {
        let mut pace = DmPace::default();
        let (room, peer) = ([4u8; 16], [9u8; 32]);
        let t0 = std::time::Instant::now();
        for n in 0..MAX_PACED_FRAMES + DM_FRAMES_PER_ROOM_PER_SEC {
            pace.offer(room, peer, &receipt(n as u8), DmFrameKind::Reply, t0);
        }
        assert_eq!(pace.waiting.len(), MAX_PACED_FRAMES);
        let oldest = pace.waiting.front().map(|frame| frame.payload.clone());
        assert!(!pace.offer(room, peer, &DmPayload::Accept, DmFrameKind::Answer, t0));
        assert_eq!(pace.waiting.len(), MAX_PACED_FRAMES);
        assert!(pace.waiting.iter().any(|frame| frame.kind == DmFrameKind::Answer));
        assert_ne!(pace.waiting.front().map(|frame| frame.payload.clone()), oldest, "the oldest receipt gave way");

        let due = pace.due(t0 + std::time::Duration::from_secs(2));
        assert_eq!(due[0].payload, DmPayload::Accept);
        assert_eq!(due[0].kind, DmFrameKind::Answer);
    }

    #[test]
    fn a_frame_that_waited_too_long_is_dropped_at_the_drain() {
        let mut pace = DmPace::default();
        let (room, peer) = ([5u8; 16], [9u8; 32]);
        let t0 = std::time::Instant::now();
        for n in 0..DM_FRAMES_PER_ROOM_PER_SEC as u8 + 3 {
            pace.offer(room, peer, &receipt(n), DmFrameKind::Reply, t0);
        }
        let late = t0 + DM_PACED_MAX_WAIT + std::time::Duration::from_secs(1);
        assert!(pace.due(late).is_empty());
        assert!(pace.waiting.is_empty());
    }

    #[test]
    fn a_queued_reply_goes_only_while_it_is_still_true() {
        let receipt = DmPayload::Receipt { id: [1; 16] };
        assert!(reply_still_true(&receipt, true, false, || false));
        assert!(!reply_still_true(&receipt, false, false, || true), "ignored or banned since");
        assert!(!reply_still_true(&DmPayload::Decline, false, true, || true), "ignored or banned since");
        assert!(reply_still_true(&DmPayload::Decline, true, true, || false), "the policy is off");
        assert!(reply_still_true(&DmPayload::Decline, true, false, || true), "our refusal holds");
        assert!(
            !reply_still_true(&DmPayload::Decline, true, false, || false),
            "accepted, written to, or the policy back on since"
        );
    }

    #[test]
    fn a_waiting_frame_goes_only_on_what_the_ticks_read_found() {
        let (room, peer, banned) = ([0x6au8; 16], [0x71u8; 32], [0x72u8; 32]);
        let row = |member: &[u8; 32], banned: bool| crate::storage::database::StoredChannelMember {
            member_pubkey: hex::encode(member),
            nickname: String::new(),
            last_seen: 0,
            banned,
            moderator: false,
            language: String::new(),
        };
        let frame = |peer: [u8; 32], payload: DmPayload, kind: DmFrameKind| PacedFrame {
            room,
            peer,
            payload,
            kind,
            queued_at: std::time::Instant::now(),
        };
        let message = DmPayload::Message { id: [3; 16], text: "hi".into() };
        let mut checks = DmChecks::default();
        assert!(!checks.goes(&frame(peer, receipt(1), DmFrameKind::Reply), false), "no roster read, nobody reachable");

        let roster = ChannelRosterSnapshot::from_rows(vec![row(&peer, false), row(&banned, true)], 0, std::time::Instant::now());
        checks.rosters.insert(room, Arc::new(roster));
        assert!(checks.goes(&frame(peer, receipt(1), DmFrameKind::Reply), false));
        assert!(checks.goes(&frame(peer, DmPayload::Accept, DmFrameKind::Answer), false));
        assert!(!checks.goes(&frame(banned, DmPayload::Accept, DmFrameKind::Answer), false), "banned");
        assert!(!checks.goes(&frame(peer, DmPayload::Decline, DmFrameKind::Reply), false), "not refused");
        assert!(checks.goes(&frame(peer, DmPayload::Decline, DmFrameKind::Reply), true), "the policy is off");
        assert!(!checks.goes(&frame(peer, message.clone(), DmFrameKind::Message), false), "not still sending");

        checks.refused.insert(peer);
        checks.sending.insert((peer, [3; 16]));
        assert!(checks.goes(&frame(peer, DmPayload::Decline, DmFrameKind::Reply), false));
        assert!(checks.goes(&frame(peer, message.clone(), DmFrameKind::Message), false));
        assert!(!checks.goes(&frame(peer, message, DmFrameKind::Message), true), "private messages are off");
    }

    /// Removing a request silently leaves nothing waiting to tell its sender:
    /// no receipt or decline, delayed or paced. Others' replies stay.
    #[test]
    fn dropping_a_request_sends_its_sender_nothing() {
        let (room, gone, other) = ([0x5au8; 16], [0x61u8; 32], [0x62u8; 32]);
        queue_reply(room, gone, DmPayload::Receipt { id: [1; 16] });
        queue_reply(room, gone, DmPayload::Decline);
        queue_reply(room, other, DmPayload::Receipt { id: [2; 16] });
        let paced = |peer: [u8; 32], n: u8| PacedFrame {
            room,
            peer,
            payload: receipt(n),
            kind: DmFrameKind::Reply,
            queued_at: std::time::Instant::now(),
        };
        {
            let mut pace = dm_pace().lock().unwrap();
            pace.waiting.push_back(paced(gone, 3));
            pace.waiting.push_back(paced(other, 4));
        }
        drop_replies_to(&gone);
        let pending = pending_replies().lock().unwrap();
        assert!(pending.iter().all(|(_, _, to, _)| *to != gone), "nothing delayed for them");
        assert!(pending.iter().any(|(_, _, to, _)| *to == other));
        let pace = dm_pace().lock().unwrap();
        assert!(pace.waiting.iter().all(|frame| frame.peer != gone), "nothing paced for them");
        assert!(pace.waiting.iter().any(|frame| frame.peer == other));
    }

    #[test]
    fn only_a_recent_frame_is_acted_on() {
        let now = 1_900_000_000;
        assert!(dm_fresh(now - DM_MAX_AGE_SECS, now));
        assert!(!dm_fresh(now - DM_MAX_AGE_SECS - 1, now));
        assert!(!dm_fresh(now + 3_600, now));
    }
}
