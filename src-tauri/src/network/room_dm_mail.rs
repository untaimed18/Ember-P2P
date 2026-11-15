//! Room mail: private messages between room members, left sealed on the
//! rendezvous server for a member who was not online to take them, and
//! collected by that member later. The friend chat mailbox's server and seal,
//! under boxes of their own (`derive_room_dm_mailbox_box`).
//!
//! Only within conversations that exist: a member collects from those it has
//! a thread with, so a stranger's first message still needs them online. Only
//! to members who said they collect (`DmPayload::Collects`), since an older
//! build never would. A message left there is no longer resent live, and
//! waits for its receipt, or a decline, for as long as the server keeps it.
//! Runs inside the chat mailbox's round, so it shares its schedule and its
//! setting.

use super::*;
use crate::network::ember::crypto::{
    chat_mailbox_day, derive_room_dm_mailbox_box, open_mailbox_payload, seal_mailbox_payload, MailboxPayload,
    MAX_MAILBOX_RECEIPT_IDS,
};
use crate::network::room_dm::{dm_ignored, dm_policy_now, note_peer_answer, DM_MESSAGE_EVENT, DM_STATUS_EVENT};
use crate::storage::database::{DmIncoming, DM_STATE_REQUEST};

/// How long one of ours goes unanswered live before it is left in the mailbox:
/// its first resend, by when a recipient online has had it.
const MAIL_AFTER_SECS: i64 = 2 * 60;
/// How long a member's word that it collects is taken for. It is said again
/// with the first receipt of every session.
const COLLECTS_FOR_SECS: i64 = 30 * 86_400;
/// Days of boxes collected from, and how long a message left there waits for
/// its receipt: as long as the server keeps an entry.
const LOOKBACK_DAYS: i64 = 7;
/// Boxes read per member: the lookback, today, and tomorrow.
const BOX_DAYS: usize = LOOKBACK_DAYS as usize + 2;
/// Boxes named in one fetch: whole members only, under the server's 400.
const BOXES_PER_FETCH: usize = (400 / BOX_DAYS) * BOX_DAYS;
/// Pages of collected entries per round; the rest wait for the next.
const FETCH_PAGES_PER_ROUND: usize = 4;
/// Conversations collected for in one round, the newest first.
const THREADS_PER_ROUND: usize = 200;
/// A copy left this long ago is gone from the server whatever it answers.
const FORGET_AFTER_SECS: i64 = (LOOKBACK_DAYS + 1) * 86_400;

fn key32(hex_str: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut out).ok()?;
    Some(out)
}

fn key16(hex_str: &str) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    hex::decode_to_slice(hex_str, &mut out).ok()?;
    Some(out)
}

/// Take back copies whose message no longer waits for one. Run whatever the
/// setting says, so turning it off still clears what was left.
pub(super) async fn take_back_stale(db: &Arc<Database>, base_url: &str) {
    let task_db = db.clone();
    let Ok(Ok(stale)) = tokio::task::spawn_blocking(move || task_db.dm_mail_stale()).await else {
        return;
    };
    let now = chrono::Utc::now().timestamp();
    let mut gone = Vec::new();
    for (member, message_id, mailbox, item, deposited_at) in stale {
        let taken = match (key32(&mailbox), key16(&item)) {
            _ if deposited_at <= now - FORGET_AFTER_SECS => true,
            (Some(mailbox), Some(item)) => rendezvous::chat_mailbox_delete(base_url, &mailbox, &[item]).await.is_ok(),
            _ => true,
        };
        if taken {
            gone.push((member, message_id));
        }
    }
    if !gone.is_empty() {
        let db = db.clone();
        let _ = tokio::task::spawn_blocking(move || db.dm_forget_mailed(&gone)).await;
    }
}

/// Collect what members left us, then leave what is waiting for those not
/// online to take it.
pub(super) async fn run_round(
    db: &Arc<Database>,
    app_handle: &crate::host::AppHandle,
    base_url: &str,
    seed: &[u8; 32],
    our_pubkey: &[u8; 32],
) {
    let now = chrono::Utc::now().timestamp();
    let day = chat_mailbox_day(now);
    // Collected with private messages off too, as live frames still arrive
    // then: what was left draws the decline a live one would. Nothing of ours
    // goes.
    collect(db, app_handle, base_url, seed, our_pubkey, day, now).await;
    if dm_policy_now() != crate::types::ROOM_DM_POLICY_OFF {
        deposit(db, app_handle, base_url, seed, day, now).await;
    }
}

struct MailMember {
    hex: String,
    key: [u8; 32],
    channel: String,
}

#[allow(clippy::too_many_arguments)]
async fn collect(
    db: &Arc<Database>,
    app_handle: &crate::host::AppHandle,
    base_url: &str,
    seed: &[u8; 32],
    our_pubkey: &[u8; 32],
    day: i64,
    now: i64,
) {
    let task_db = db.clone();
    let Ok(Ok(threads)) = tokio::task::spawn_blocking(move || task_db.dm_mail_threads()).await else {
        return;
    };
    let members: Vec<MailMember> = threads
        .into_iter()
        .take(THREADS_PER_ROUND)
        .filter_map(|(hex, _, channel)| Some(MailMember { key: key32(&hex)?, hex, channel }))
        .collect();
    let mut boxes: HashMap<[u8; 32], usize> = HashMap::new();
    let mut all: Vec<[u8; 32]> = Vec::with_capacity(members.len() * BOX_DAYS);
    for (index, member) in members.iter().enumerate() {
        for d in (day - LOOKBACK_DAYS)..=(day + 1) {
            if let Some(mailbox) = derive_room_dm_mailbox_box(seed, &member.key, our_pubkey, d) {
                boxes.insert(mailbox, index);
                all.push(mailbox);
            }
        }
    }
    'chunks: for chunk in all.chunks(BOXES_PER_FETCH) {
        for _ in 0..FETCH_PAGES_PER_ROUND {
            let page = match rendezvous::chat_mailbox_fetch(base_url, chunk).await {
                Ok(page) => page,
                Err(e) => {
                    debug!("Room mail: collect failed: {e}");
                    break 'chunks;
                }
            };
            let mut clear: HashMap<[u8; 32], Vec<[u8; 16]>> = HashMap::new();
            let mut taken: HashMap<usize, Vec<([u8; 16], [u8; 32], [u8; 16])>> = HashMap::new();
            let mut declined: HashMap<usize, Vec<([u8; 32], [u8; 16])>> = HashMap::new();
            let mut left_behind = false;
            for item in &page.items {
                let Some(&index) = boxes.get(&item.mailbox) else {
                    continue;
                };
                let member = &members[index];
                match open_mailbox_payload(seed, &member.key, &item.mailbox, &item.blob) {
                    Some(MailboxPayload::Message { msg_id, ttl_secs, text }) => {
                        match receive(db, app_handle, member, msg_id, ttl_secs, &text, now).await {
                            Received::Kept => {
                                taken.entry(index).or_default().push((msg_id, item.mailbox, item.id));
                                continue;
                            }
                            Received::Declined => {
                                declined.entry(index).or_default().push((item.mailbox, item.id));
                                continue;
                            }
                            Received::Dropped => {}
                            Received::Later => {
                                left_behind = true;
                                continue;
                            }
                        }
                    }
                    Some(MailboxPayload::Receipt { msg_ids }) => confirm(db, app_handle, member, msg_ids, now).await,
                    // Never dated past now, so it cannot outrank an answer
                    // they give later.
                    Some(MailboxPayload::Decline { at }) => {
                        note_peer_answer(db, app_handle, &member.hex, false, at.min(now)).await;
                    }
                    None => {}
                }
                clear.entry(item.mailbox).or_default().push(item.id);
            }
            // An entry goes only once its receipt is left, as in chat mail.
            for (index, entries) in taken {
                let ids: Vec<[u8; 16]> = entries.iter().map(|(msg_id, _, _)| *msg_id).collect();
                if leave_receipt(base_url, seed, &members[index].key, day, &ids).await {
                    for (_, mailbox, item_id) in entries {
                        clear.entry(mailbox).or_default().push(item_id);
                    }
                } else {
                    left_behind = true;
                }
            }
            // And one declined once the decline is, one for all of a member's.
            for (index, entries) in declined {
                if leave(base_url, seed, &members[index].key, day, &MailboxPayload::Decline { at: now }).await {
                    for (mailbox, item_id) in entries {
                        clear.entry(mailbox).or_default().push(item_id);
                    }
                } else {
                    left_behind = true;
                }
            }
            for (mailbox, ids) in clear {
                if let Err(e) = rendezvous::chat_mailbox_delete(base_url, &mailbox, &ids).await {
                    debug!("Room mail: clearing collected entries failed: {e}");
                    left_behind = true;
                }
            }
            if !page.more || left_behind {
                break;
            }
        }
    }
}

/// What became of a message a member left for us.
#[derive(Debug, PartialEq, Eq)]
enum Received {
    /// Kept, or kept already: a receipt is owed.
    Kept,
    /// Refused for good, and they are told, as a live decline tells them.
    Declined,
    /// Refused without a word, as live: from someone ignored or no longer in
    /// the room, not well formed, or past what their request may hold.
    Dropped,
    /// Not now: past their hourly allowance, or not stored. It stays on the
    /// server for a later round.
    Later,
}

/// Keep a message a member left for us, on the terms a live one is kept on.
async fn receive(
    db: &Arc<Database>,
    app_handle: &crate::host::AppHandle,
    member: &MailMember,
    msg_id: [u8; 16],
    ttl_secs: u32,
    text: &str,
    now: i64,
) -> Received {
    if dm_ignored(&member.hex, &member.channel)
        || text.is_empty()
        || text.len() > crate::network::ember::room_dm::DM_TEXT_MAX_BYTES
    {
        return Received::Dropped;
    }
    let policy = dm_policy_now();
    let task_db = db.clone();
    let (from, channel, mid, body) = (member.hex.clone(), member.channel.clone(), hex::encode(msg_id), text.to_string());
    let outcome = tokio::task::spawn_blocking(move || {
        // Only from a member still in the room unbanned, as live.
        let Some(name) = task_db.dm_member_in_room(&channel, &from)? else {
            return Ok(None);
        };
        let kept = task_db.dm_record_incoming(&from, &name, &channel, &mid, &body, now, &policy, now)?;
        if matches!(kept, DmIncoming::Stored { .. } | DmIncoming::Duplicate) && ttl_secs > 0 {
            let ttl = i64::from(
                ttl_secs.clamp(crate::types::CHAT_DISAPPEAR_PEER_MIN_SECS, crate::types::CHAT_DISAPPEAR_PEER_MAX_SECS),
            );
            task_db.dm_set_received_timer(&from, &mid, ttl, now)?;
        }
        // Full is a request holding all it may until it is answered, which
        // may be never, or an hour's allowance, which passes.
        let requested = kept == DmIncoming::Full
            && task_db.dm_thread(&from, now)?.is_some_and(|thread| thread.state == DM_STATE_REQUEST);
        anyhow::Ok(Some((name, kept, requested)))
    })
    .await;
    let Ok(Ok(outcome)) = outcome else {
        return Received::Later;
    };
    let Some((name, kept, requested)) = outcome else {
        return Received::Dropped;
    };
    if let DmIncoming::Stored { request, new_thread } = kept {
        let _ = app_handle.emit(
            DM_MESSAGE_EVENT,
            serde_json::json!({
                "member_pubkey": member.hex,
                "name": name,
                "message_id": hex::encode(msg_id),
                "text": text,
                "timestamp": now,
                "request": request,
                "new_thread": new_thread,
            }),
        );
    }
    received(kept, requested)
}

/// What keeping a message left in the mailbox came to. `requested` when it
/// was refused as full because it is a request holding all it may.
fn received(kept: DmIncoming, requested: bool) -> Received {
    match kept {
        DmIncoming::Stored { .. } | DmIncoming::Duplicate => Received::Kept,
        DmIncoming::Declined => Received::Declined,
        DmIncoming::Full if !requested => Received::Later,
        DmIncoming::Full | DmIncoming::Capped => Received::Dropped,
    }
}

/// The member collected these of ours: delivered, and their timers start.
async fn confirm(db: &Arc<Database>, app_handle: &crate::host::AppHandle, member: &MailMember, msg_ids: Vec<[u8; 16]>, now: i64) {
    let task_db = db.clone();
    let from = member.hex.clone();
    let delivered = tokio::task::spawn_blocking(move || {
        let mut delivered = Vec::new();
        for id in msg_ids {
            let mid = hex::encode(id);
            if task_db.dm_mark_delivered(&from, &mid)? {
                task_db.dm_start_sent_timer(&from, &mid, now)?;
                delivered.push(mid);
            }
        }
        anyhow::Ok(delivered)
    })
    .await
    .ok()
    .and_then(Result::ok)
    .unwrap_or_default();
    for message_id in delivered {
        let _ = app_handle.emit(
            DM_STATUS_EVENT,
            serde_json::json!({ "member_pubkey": member.hex, "message_id": message_id, "status": "delivered" }),
        );
    }
}

/// Tell the member these were collected, in today's box to them.
async fn leave_receipt(base_url: &str, seed: &[u8; 32], member: &[u8; 32], day: i64, msg_ids: &[[u8; 16]]) -> bool {
    for ids in msg_ids.chunks(MAX_MAILBOX_RECEIPT_IDS) {
        if !leave(base_url, seed, member, day, &MailboxPayload::Receipt { msg_ids: ids.to_vec() }).await {
            return false;
        }
    }
    true
}

/// Leave `payload` for the member in today's box to them.
async fn leave(base_url: &str, seed: &[u8; 32], member: &[u8; 32], day: i64, payload: &MailboxPayload) -> bool {
    let Some(mailbox) = derive_room_dm_mailbox_box(seed, member, member, day) else {
        return false;
    };
    let Some(blob) = seal_mailbox_payload(seed, member, &mailbox, payload) else {
        return false;
    };
    match rendezvous::chat_mailbox_put(base_url, &mailbox, &blob).await {
        Ok(_) => true,
        Err(e) => {
            debug!("Room mail: leaving a reply failed: {e}");
            false
        }
    }
}

/// Leave ours that went unanswered live in today's box for each member who
/// collects.
async fn deposit(db: &Arc<Database>, app_handle: &crate::host::AppHandle, base_url: &str, seed: &[u8; 32], day: i64, now: i64) {
    let task_db = db.clone();
    let Ok(Ok(due)) =
        tokio::task::spawn_blocking(move || task_db.dm_mail_due(now, MAIL_AFTER_SECS, COLLECTS_FOR_SECS)).await
    else {
        return;
    };
    let mut full: std::collections::HashSet<String> = std::collections::HashSet::new();
    for message in due {
        let (Some(member), Some(msg_id)) = (key32(&message.member_pubkey), key16(&message.message_id)) else {
            continue;
        };
        if full.contains(&message.member_pubkey) {
            continue;
        }
        let Some(mailbox) = derive_room_dm_mailbox_box(seed, &member, &member, day) else {
            continue;
        };
        let payload = MailboxPayload::Message {
            msg_id,
            ttl_secs: u32::try_from(message.ttl_secs).unwrap_or(0),
            text: message.text,
        };
        let Some(blob) = seal_mailbox_payload(seed, &member, &mailbox, &payload) else {
            continue;
        };
        let item = match rendezvous::chat_mailbox_put(base_url, &mailbox, &blob).await {
            Ok(item) => item,
            // Their box full: the rest of theirs waits a round, and the others
            // go on.
            Err(e) if rendezvous::chat_mailbox_full(&e) => {
                debug!("Room mail: a member's box is full: {e}");
                full.insert(message.member_pubkey.clone());
                continue;
            }
            // A busy server: everything waits a round.
            Err(e) => {
                debug!("Room mail: deposit stopped: {e}");
                return;
            }
        };
        let task_db = db.clone();
        let (who, mid) = (message.member_pubkey.clone(), message.message_id.clone());
        let noted = tokio::task::spawn_blocking(move || {
            task_db.dm_note_mailed(
                &who,
                &mid,
                &hex::encode(mailbox),
                &hex::encode(item),
                now,
                now + LOOKBACK_DAYS * 86_400,
            )
        })
        .await;
        // Not recorded, so the next round would leave it again: take this
        // copy back. One that stays is only shown once there.
        if !matches!(noted, Ok(Ok(()))) {
            let _ = rendezvous::chat_mailbox_delete(base_url, &mailbox, &[item]).await;
            continue;
        }
        let _ = app_handle.emit(
            DM_STATUS_EVENT,
            serde_json::json!({
                "member_pubkey": message.member_pubkey,
                "message_id": message.message_id,
                "status": "sending",
                "mailboxed": true,
            }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_message_past_an_hours_allowance_waits_on_the_server() {
        let stored = DmIncoming::Stored { request: false, new_thread: false };
        assert_eq!(received(stored, false), Received::Kept);
        assert_eq!(received(DmIncoming::Duplicate, false), Received::Kept);
        assert_eq!(received(DmIncoming::Declined, false), Received::Declined);
        assert_eq!(received(DmIncoming::Full, false), Received::Later, "the hour passes");
        assert_eq!(received(DmIncoming::Full, true), Received::Dropped, "a request may never be answered");
        assert_eq!(received(DmIncoming::Capped, false), Received::Dropped);
    }
}
