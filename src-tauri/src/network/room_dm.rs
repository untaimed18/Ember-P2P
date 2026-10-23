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

/// Send the replies whose time has come, a few at a time. From the network
/// loop's one-second timer.
pub(super) async fn send_due_replies(socket: &UdpSocket, state: &mut NetworkState, db: &Arc<Database>) {
    let due: Vec<([u8; 16], [u8; 32], DmPayload)> = {
        let mut pending = pending_replies().lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        let mut taken = Vec::new();
        pending.retain(|(at, channel, peer, payload)| {
            if *at <= now && taken.len() < DM_REPLIES_PER_TICK {
                taken.push((*channel, *peer, payload.clone()));
                false
            } else {
                true
            }
        });
        taken
    };
    for (channel_id, peer, payload) in due {
        send_private_frame(socket, state, db, channel_id, peer, &payload).await;
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

/// Seal `payload` to `peer` and send it into the room under its current key.
/// Nothing when the room is not one this device is in.
pub(super) async fn send_private_frame(
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

    #[test]
    fn only_a_recent_frame_is_acted_on() {
        let now = 1_900_000_000;
        assert!(dm_fresh(now - DM_MAX_AGE_SECS, now));
        assert!(!dm_fresh(now - DM_MAX_AGE_SECS - 1, now));
        assert!(!dm_fresh(now + 3_600, now));
    }
}
