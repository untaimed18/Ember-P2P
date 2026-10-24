//! Private messages between room members: the commands, choosing the room a
//! conversation goes through, and resending what has not been answered. The
//! frames themselves are `network::room_dm`.

use rand::RngCore;
use tauri::{Emitter, Manager};

use crate::app_state::AppState;
use crate::commands::errors::{coded, coded_ctx};
use crate::network::ember::room_dm::{DmPayload, DM_TEXT_MAX_BYTES};
use crate::network::room_dm::{DM_STATUS_EVENT, DM_THREAD_EVENT};
use crate::network::NetworkCommand;
use crate::storage::database::{Database, DmMessage, DmThread};
use crate::types::IgnoredMember;

/// How long after one attempt the next goes out, while unanswered.
const DM_RESEND_SECS: i64 = 2 * 60;
/// Up to this much more is added to each wait, at random, so messages
/// written or resent together do not stay together for every attempt.
const DM_RESEND_JITTER_SECS: i64 = 30;
/// New private messages this device writes through one room a minute, as
/// room chat allows its lines, and counted apart from them. Each is resent
/// until answered, so this also bounds what the resend loop carries.
const DM_SEND_PER_ROOM_MINUTE: usize = 20;
/// How long a message of ours is tried before it is marked not delivered:
/// a recipient online in that time gets it.
const DM_GIVE_UP_SECS: i64 = 20 * 60;
/// How often the resend loop looks.
const DM_RESEND_TICK: std::time::Duration = std::time::Duration::from_secs(30);
/// Rooms looked through for one both members are in.
const DM_SHARED_ROOMS_LOOKED_AT: usize = 8;
/// The most the ignore list holds.
const MAX_IGNORED_MEMBERS: usize = 2_000;

/// A conversation, with what the page needs to offer next.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DmThreadInfo {
    #[serde(flatten)]
    pub thread: DmThread,
    /// A room both are still in carries messages; without one, nothing can
    /// be sent and the page offers Add friend instead.
    pub can_send: bool,
    /// They are a friend: friend chat is the place to talk.
    pub is_friend: bool,
}

fn member_key(member: &str) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    hex::decode_to_slice(member.trim(), &mut key)
        .map_err(|_| coded("channels_dm_bad_member", "That member could not be found"))?;
    Ok(key)
}

/// A member key as every query takes it: lowercase hex, nothing around it.
fn member_hex(member: &str) -> Result<String, String> {
    member_key(member).map(hex::encode)
}

/// Why nothing may be sent to `member` now, checked by sending and by Try
/// again alike, or the room to send through.
fn send_route(db: &Database, key: &[u8; 32], member: &str, ours: &str, now: i64) -> anyhow::Result<Result<String, String>> {
    if is_friend(db, key) {
        return Ok(Err(coded("channels_dm_friend", "You are friends: write to them in friend chat")));
    }
    let thread = db.dm_thread(member, now)?;
    if thread.as_ref().is_some_and(|t| t.peer_state == "declined") {
        return Ok(Err(coded("channels_dm_declined", "They do not take private messages from you")));
    }
    let preferred = thread.as_ref().map(|t| t.channel_id.clone()).unwrap_or_default();
    Ok(shared_room(db, member, ours, &preferred)
        .ok_or_else(|| coded("channels_dm_no_shared_room", "You are no longer in a room together")))
}

async fn refuse_when_off(state: &AppState) -> Result<(), String> {
    if state.config.read().await.settings.room_dm_policy == crate::types::ROOM_DM_POLICY_OFF {
        return Err(coded("channels_dm_off", "Private messages are turned off in Settings"));
    }
    Ok(())
}

fn channel_key(channel_id: &str) -> Option<[u8; 16]> {
    let mut id = [0u8; 16];
    hex::decode_to_slice(channel_id, &mut id).ok()?;
    Some(id)
}

/// A room both are in, `preferred` if it still is one: the room a
/// conversation started in carries it while both remain.
fn shared_room(db: &Database, member: &str, ours: &str, preferred: &str) -> Option<String> {
    let rooms = db.rooms_shared_with(member, ours, DM_SHARED_ROOMS_LOOKED_AT).ok()?;
    rooms
        .iter()
        .find(|room| room.eq_ignore_ascii_case(preferred))
        .or_else(|| rooms.first())
        .cloned()
}

fn is_friend(db: &Database, member: &[u8; 32]) -> bool {
    crate::network::ember::crypto::node_id_from_ed25519_bytes(member)
        .is_some_and(|hash| db.is_unblocked_mutual_friend(&hex::encode(hash)).unwrap_or(false))
}

async fn blocking<T: Send + 'static>(
    task: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
    code: &'static str,
    message: &'static str,
) -> Result<T, String> {
    tokio::task::spawn_blocking(task)
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx(code, message, e))
}

/// When the next attempt at a message tried at `now` is due.
fn next_attempt_at(now: i64) -> i64 {
    now + DM_RESEND_SECS + rand::Rng::gen_range(&mut rand::thread_rng(), 0..=DM_RESEND_JITTER_SECS)
}

type DmSendTimes = std::collections::HashMap<String, std::collections::VecDeque<std::time::Instant>>;

/// Our own new private messages per room, for [`DM_SEND_PER_ROOM_MINUTE`].
/// For this session only: it stops a runaway loop or a wall of pastes, both
/// of which happen inside one.
fn dm_send_times() -> &'static std::sync::Mutex<DmSendTimes> {
    static TIMES: std::sync::OnceLock<std::sync::Mutex<DmSendTimes>> = std::sync::OnceLock::new();
    TIMES.get_or_init(Default::default)
}

/// Whether `channel_id` has room in its minute for one more message, taking
/// it if so.
fn dm_send_allowed(channel_id: &str) -> bool {
    let window = std::time::Duration::from_secs(60);
    let now = std::time::Instant::now();
    let mut map = dm_send_times().lock().unwrap_or_else(|e| e.into_inner());
    map.retain(|_, times| times.back().is_some_and(|at| now.saturating_duration_since(*at) <= window));
    let times = map.entry(channel_id.to_string()).or_default();
    crate::network::ember::channel::rate_window_allow(times, now, window, DM_SEND_PER_ROOM_MINUTE)
}

/// Hand back the slot a message took when it was not sent after all.
fn refund_dm_send(channel_id: &str) {
    let mut map = dm_send_times().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(times) = map.get_mut(channel_id) {
        times.pop_back();
    }
}

fn send_frame(state: &AppState, channel_id: &str, member: [u8; 32], payload: DmPayload) {
    let Some(channel_id) = channel_key(channel_id) else {
        return;
    };
    if let Err(e) = state
        .network_tx
        .try_send(NetworkCommand::SendRoomDm { channel_id, member, payload })
    {
        tracing::debug!("Room private message: could not hand a frame to the network: {e}");
    }
}

/// Every conversation, newest first.
#[tauri::command]
pub async fn list_room_dm_threads(state: tauri::State<'_, AppState>) -> Result<Vec<DmThreadInfo>, String> {
    let db = state.db.clone();
    let ours = hex::encode(state.identity.ed25519_public_key);
    let now = chrono::Utc::now().timestamp();
    blocking(
        move || {
            Ok(db
                .dm_threads(now)?
                .into_iter()
                .map(|thread| {
                    let key = member_key(&thread.member_pubkey).unwrap_or_default();
                    DmThreadInfo {
                        can_send: shared_room(&db, &thread.member_pubkey, &ours, &thread.channel_id).is_some(),
                        is_friend: is_friend(&db, &key),
                        thread,
                    }
                })
                .collect())
        },
        "channels_dm_failed",
        "Could not read private messages",
    )
    .await
}

/// A conversation's messages, oldest first: the newest `limit` before
/// `before`, or the newest of all.
#[tauri::command]
pub async fn get_room_dm_messages(
    state: tauri::State<'_, AppState>,
    member: String,
    before: Option<i64>,
    limit: Option<u32>,
) -> Result<Vec<DmMessage>, String> {
    let member = member_hex(&member)?;
    let db = state.db.clone();
    let limit = limit.unwrap_or(100).clamp(1, 500) as usize;
    blocking(move || db.dm_messages(&member, limit, before), "channels_dm_failed", "Could not read private messages").await
}

/// Write to a member privately, through a room both are in.
#[tauri::command]
pub async fn send_room_dm(
    state: tauri::State<'_, AppState>,
    member: String,
    text: String,
) -> Result<DmMessage, String> {
    let key = member_key(&member)?;
    let member = hex::encode(key);
    if key == state.identity.ed25519_public_key {
        return Err(coded("channels_dm_bad_member", "That member could not be found"));
    }
    if state.db.chat_locked() {
        return Err(coded("channels_chat_locked", "Chat history is locked; restore the key file to manage channels"));
    }
    crate::commands::channels::require_ember(&state).await?;
    let text = text.trim().to_string();
    if text.is_empty() {
        return Err(coded("channels_dm_empty", "Write something first"));
    }
    if text.len() > DM_TEXT_MAX_BYTES {
        return Err(coded("channels_dm_too_long", "This message is too long. Shorten it and try again."));
    }
    refuse_when_off(&state).await?;
    let db = state.db.clone();
    let ours = hex::encode(state.identity.ed25519_public_key);
    let now = chrono::Utc::now().timestamp();
    let mut id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id);
    let message_id = hex::encode(id);
    let (task_member, task_text, task_id) = (member.clone(), text.clone(), message_id.clone());
    let channel = blocking(
        move || {
            let channel = match send_route(&db, &key, &task_member, &ours, now)? {
                Ok(channel) => channel,
                Err(refused) => return Ok(Err(refused)),
            };
            if !dm_send_allowed(&channel) {
                return Ok(Err(coded(
                    "channels_dm_rate_limited",
                    "You are sending private messages too fast. Wait a moment and try again.",
                )));
            }
            let recorded = db.dm_member_in_room(&channel, &task_member).and_then(|name| {
                db.dm_record_outgoing(
                    &task_member,
                    &name.unwrap_or_default(),
                    &channel,
                    &task_id,
                    &task_text,
                    now,
                    next_attempt_at(now),
                    now + DM_GIVE_UP_SECS,
                )
            });
            if recorded.is_err() {
                refund_dm_send(&channel);
            }
            recorded?;
            Ok(Ok(channel))
        },
        "channels_dm_failed",
        "Could not send the message",
    )
    .await??;
    send_frame(&state, &channel, key, DmPayload::Message { id, text: text.clone() });
    Ok(DmMessage {
        message_id,
        member_pubkey: member,
        direction: "out".into(),
        text,
        timestamp: now,
        status: "sending".into(),
    })
}

/// Accept or decline someone's first messages. They are told either way.
#[tauri::command]
pub async fn answer_room_dm_request(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    member: String,
    accept: bool,
) -> Result<(), String> {
    let key = member_key(&member)?;
    let member = hex::encode(key);
    let db = state.db.clone();
    let ours = hex::encode(state.identity.ed25519_public_key);
    let now = chrono::Utc::now().timestamp();
    let task_member = member.clone();
    let channel = blocking(
        move || {
            let preferred = db.dm_thread(&task_member, now)?.map(|t| t.channel_id).unwrap_or_default();
            if !db.dm_answer_request(&task_member, accept, now)? {
                return Ok(None);
            }
            Ok(shared_room(&db, &task_member, &ours, &preferred))
        },
        "channels_dm_failed",
        "Could not answer the request",
    )
    .await?;
    if let Some(channel) = channel {
        send_frame(&state, &channel, key, if accept { DmPayload::Accept } else { DmPayload::Decline });
    }
    let _ = app.emit(DM_THREAD_EVENT, serde_json::json!({ "member_pubkey": member }));
    Ok(())
}

#[tauri::command]
pub async fn mark_room_dm_read(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    member: String,
) -> Result<(), String> {
    let member = member_hex(&member)?;
    let db = state.db.clone();
    let task_member = member.clone();
    blocking(move || db.dm_mark_read(&task_member), "channels_dm_failed", "Could not update private messages").await?;
    // The other window's counts follow from this.
    let _ = app.emit(DM_THREAD_EVENT, serde_json::json!({ "member_pubkey": member }));
    Ok(())
}

/// Delete a conversation and everything in it, here only. A request deleted
/// is declined, without telling its sender, and that refusal is answered
/// with a decline if they write again while it holds.
#[tauri::command]
pub async fn delete_room_dm_thread(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    member: String,
) -> Result<(), String> {
    let member = member_hex(&member)?;
    let db = state.db.clone();
    let task_member = member.clone();
    let now = chrono::Utc::now().timestamp();
    blocking(move || db.dm_delete_thread(&task_member, now), "channels_dm_failed", "Could not delete the conversation").await?;
    let _ = app.emit(DM_THREAD_EVENT, serde_json::json!({ "member_pubkey": member }));
    Ok(())
}

/// Remove someone's request here and send them nothing, not even a reply
/// already waiting: for a sender being ignored, who sees their messages go
/// undelivered as if we were offline. Ignore them first, so nothing they
/// send next opens a new one.
#[tauri::command]
pub async fn drop_room_dm_request(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    member: String,
) -> Result<(), String> {
    let key = member_key(&member)?;
    let member = hex::encode(key);
    let db = state.db.clone();
    let task_member = member.clone();
    let removed =
        blocking(move || db.dm_forget_request(&task_member), "channels_dm_failed", "Could not answer the request").await?;
    crate::network::room_dm::drop_replies_to(&key);
    if removed {
        let _ = app.emit(DM_THREAD_EVENT, serde_json::json!({ "member_pubkey": member }));
    }
    Ok(())
}

/// Try a message that was not delivered again, on the terms a new one meets:
/// the same refusals, and a place in its room's [`DM_SEND_PER_ROOM_MINUTE`],
/// handed back if it is not retried after all.
#[tauri::command]
pub async fn retry_room_dm(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    member: String,
    message_id: String,
) -> Result<(), String> {
    let key = member_key(&member)?;
    let member = hex::encode(key);
    let mut id = [0u8; 16];
    hex::decode_to_slice(message_id.trim(), &mut id)
        .map_err(|_| coded("channels_dm_failed", "Could not send the message"))?;
    let message_id = hex::encode(id);
    refuse_when_off(&state).await?;
    let db = state.db.clone();
    let ours = hex::encode(state.identity.ed25519_public_key);
    let now = chrono::Utc::now().timestamp();
    let (task_member, task_id) = (member.clone(), message_id.clone());
    // Due at once: the resend loop sends it on its next look.
    let retried = blocking(
        move || {
            let channel = match send_route(&db, &key, &task_member, &ours, now)? {
                Ok(channel) => channel,
                Err(refused) => return Ok(Err(refused)),
            };
            if !dm_send_allowed(&channel) {
                return Ok(Err(coded(
                    "channels_dm_rate_limited",
                    "You are sending private messages too fast. Wait a moment and try again.",
                )));
            }
            let retried = db.dm_retry(&task_member, &task_id, now, now + DM_GIVE_UP_SECS);
            if !matches!(retried, Ok(true)) {
                refund_dm_send(&channel);
            }
            Ok(Ok(retried?))
        },
        "channels_dm_failed",
        "Could not send the message",
    )
    .await??;
    if retried {
        let _ = app.emit(
            DM_STATUS_EVENT,
            serde_json::json!({ "member_pubkey": member, "message_id": message_id, "status": "sending" }),
        );
    }
    Ok(())
}

/// Replace the ignore list. The webview keeps a copy to hide lines with; this
/// is the one private messages are dropped by. In force when this returns,
/// not only once the network loop takes up the settings, so a request
/// dropped next cannot be reopened by a message already on its way.
#[tauri::command]
pub async fn set_ignored_members(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    members: Vec<IgnoredMember>,
) -> Result<(), String> {
    let cleaned = clean_ignored_members(members);
    crate::commands::settings::save_settings_change(&app, &state, move |settings| {
        let changed = settings.ignored_members.as_ref() != Some(&cleaned);
        settings.ignored_members = Some(cleaned);
        Ok(changed)
    })
    .await?;
    // From the settings as they stand, not as this call left them: a save
    // since must not be undone here.
    let config = state.config.read().await;
    crate::network::room_dm::set_dm_policy(
        crate::types::room_dm_policy_in_force(&config.settings.room_dm_policy),
        config.settings.ignored_members.as_deref(),
    );
    Ok(())
}

/// Rooms one ignore entry may name.
const MAX_IGNORED_ROOMS: usize = 64;

/// An ignore list as it is kept: valid keys only, once each, lowercase, at
/// most [`MAX_IGNORED_MEMBERS`]. An entry whose rooms were all invalid is
/// dropped rather than kept ignoring nowhere, or widened to everywhere.
pub(crate) fn clean_ignored_members(members: Vec<IgnoredMember>) -> Vec<IgnoredMember> {
    let mut seen = std::collections::HashSet::new();
    let mut cleaned = Vec::new();
    for mut entry in members {
        if cleaned.len() >= MAX_IGNORED_MEMBERS {
            break;
        }
        let Ok(pubkey) = member_hex(&entry.pubkey) else {
            continue;
        };
        if !seen.insert(pubkey.clone()) {
            continue;
        }
        entry.pubkey = pubkey;
        entry.name = entry.name.trim().chars().take(64).collect();
        if let Some(rooms) = entry.rooms.take() {
            let mut rooms: Vec<String> = rooms
                .iter()
                .filter_map(|room| channel_key(room.trim()).map(hex::encode))
                .collect();
            rooms.sort();
            rooms.dedup();
            rooms.truncate(MAX_IGNORED_ROOMS);
            if rooms.is_empty() {
                continue;
            }
            entry.rooms = Some(rooms);
        }
        cleaned.push(entry);
    }
    cleaned
}

/// Resend ours that have not been answered, and mark those tried for long
/// enough as not delivered. Runs for the life of the app.
pub fn spawn_resends(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(DM_RESEND_TICK).await;
            let Some(state) = app.try_state::<AppState>() else {
                return;
            };
            if state.db.chat_locked() {
                continue;
            }
            let db = state.db.clone();
            let ours = hex::encode(state.identity.ed25519_public_key);
            let now = chrono::Utc::now().timestamp();
            let off = state.config.read().await.settings.room_dm_policy == crate::types::ROOM_DM_POLICY_OFF;
            let work = tokio::task::spawn_blocking(move || {
                let _ = db.dm_prune_declined(now);
                // Turned off: nothing of ours goes out any more, and what was
                // still going says so rather than waiting out its time.
                if off {
                    return (db.dm_fail_all_sending().unwrap_or_default(), Vec::new());
                }
                let failed = db.dm_fail_unanswered(now).unwrap_or_default();
                let due = db
                    .dm_due_resends(now)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|resend| {
                        let room = shared_room(&db, &resend.member_pubkey, &ours, &resend.channel_id);
                        let channel = room.clone().unwrap_or_else(|| resend.channel_id.clone());
                        let _ = db.dm_note_attempt(&resend.member_pubkey, &resend.message_id, &channel, next_attempt_at(now));
                        (resend, room)
                    })
                    .collect::<Vec<_>>();
                (failed, due)
            })
            .await;
            let Ok((failed, due)) = work else {
                continue;
            };
            for (member, message_id) in failed {
                let _ = app.emit(
                    DM_STATUS_EVENT,
                    serde_json::json!({ "member_pubkey": member, "message_id": message_id, "status": "failed" }),
                );
            }
            for (resend, room) in due {
                let mut id = [0u8; 16];
                let (Some(room), Ok(key), Ok(())) = (
                    room,
                    member_key(&resend.member_pubkey),
                    hex::decode_to_slice(&resend.message_id, &mut id),
                ) else {
                    continue;
                };
                send_frame(&state, &room, key, DmPayload::Message { id, text: resend.text });
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(pubkey: &str, rooms: Option<Vec<&str>>) -> IgnoredMember {
        IgnoredMember {
            pubkey: pubkey.to_string(),
            name: " Name ".into(),
            rooms: rooms.map(|r| r.into_iter().map(str::to_string).collect()),
        }
    }

    #[test]
    fn an_ignore_list_is_kept_clean_and_bounded() {
        let a = "AA".repeat(32);
        let room = "c0".repeat(16);
        let cleaned = clean_ignored_members(vec![
            entry(&format!(" {a} "), Some(vec![&room.to_uppercase(), &room, "zz"])),
            entry(&a.to_lowercase(), None),
            entry("not-a-key", None),
            entry(&"bb".repeat(32), Some(vec!["zz"])),
            entry(&"cc".repeat(32), None),
        ]);
        assert_eq!(cleaned.len(), 2, "{cleaned:?}");
        assert_eq!(cleaned[0].pubkey, a.to_lowercase());
        assert_eq!(cleaned[0].rooms, Some(vec![room.clone()]), "sorted, once, valid only");
        assert_eq!(cleaned[0].name, "Name");
        assert!(cleaned.iter().all(|e| e.pubkey != "bb".repeat(32)), "rooms all invalid: dropped, not widened");

        let many = (0..MAX_IGNORED_MEMBERS + 10).map(|i| entry(&format!("{i:064x}"), None)).collect();
        assert_eq!(clean_ignored_members(many).len(), MAX_IGNORED_MEMBERS);
    }

    #[test]
    fn resends_are_spread_over_a_window_rather_than_kept_together() {
        let now = 1_900_000_000;
        let times: std::collections::HashSet<i64> = (0..200).map(|_| next_attempt_at(now)).collect();
        assert!(times.iter().all(|at| (now + DM_RESEND_SECS..=now + DM_RESEND_SECS + DM_RESEND_JITTER_SECS).contains(at)));
        assert!(times.len() > 10, "spread, not one time for the batch: {times:?}");
    }

    #[test]
    fn a_room_takes_only_so_many_new_messages_a_minute() {
        let room = format!("{:032x}", rand::random::<u128>());
        let other = format!("{:032x}", rand::random::<u128>());
        for i in 0..DM_SEND_PER_ROOM_MINUTE {
            assert!(dm_send_allowed(&room), "{i}");
        }
        assert!(!dm_send_allowed(&room));
        assert!(dm_send_allowed(&other), "per room");
        refund_dm_send(&room);
        assert!(dm_send_allowed(&room), "a message not sent gives its slot back");
        assert!(!dm_send_allowed(&room));
    }
}
