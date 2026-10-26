//! Friend chat delivery: the outbox, persistence, and read receipts.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// Tell the UI about outbound chat the age ceiling just abandoned.
///
/// The `failed` bubble state already exists in the frontend, but nothing used
/// to reach it live: the sweep wrote `CHAT_FAILED` straight to SQLite, so an
/// open conversation kept showing the message as "queued" until it was
/// reloaded. Mirrors the `delivered` emit in `mark_chat_delivered`.
pub(super) fn emit_chat_delivery_failed(app_handle: &tauri::AppHandle, expired: &[(i64, String)]) {
    for (id, friend_hash) in expired {
        let _ = app_handle.emit(
            "ember:chat-delivery",
            serde_json::json!({
                "user_hash": friend_hash,
                "id": id,
                "delivery": "failed",
            }),
        );
    }
}

/// Flushes a schedule gets before what is left waits for the next session.
const CHAT_FLUSH_TRIES: u32 = 6;
/// The first retry of a message that could not go out live.
pub(super) const CHAT_RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(2);

/// Flush `friend`'s queued chat from the loop again after `after`, while
/// their session stays up. For a message that stays queued with the session
/// live (its queue was full, or an older message is still queued ahead of
/// it): nothing else sends it before the next session, and messages typed
/// meanwhile would go out live ahead of it.
pub(super) fn schedule_chat_flush(state: &mut NetworkState, friend: [u8; 16], after: std::time::Duration) {
    let at = std::time::Instant::now() + after;
    state
        .chat_flush_due
        .entry(friend)
        .and_modify(|(due, _)| *due = (*due).min(at))
        .or_insert((at, 0));
}

/// How long after a session starts a read receipt may be the one the friend
/// re-sends as it starts, about a line read before.
const RECEIPT_RESEND_WINDOW: std::time::Duration = std::time::Duration::from_secs(30);

/// Note what the flush at a friend's session start delivered.
pub(super) fn note_session_flush(state: &mut NetworkState, friend: [u8; 16], delivered: Vec<i64>) {
    if delivered.is_empty() {
        state.chat_session_flushed.remove(&friend);
    } else {
        state
            .chat_session_flushed
            .insert(friend, (std::time::Instant::now(), delivered));
    }
}

/// Sent rows a read receipt from `friend` should not resolve to first.
///
/// A receipt names a line by its text, and the friend re-sends their last one
/// as each session starts, about a line read in an earlier one. If that
/// session's flush just delivered another line with the same text ("ok"
/// twice), the receipt would resolve to the new copy and mark it, and all
/// before it, seen although the friend has not read it. So soon after a
/// session starts, the lines that flush delivered are passed over when an
/// older line matches; one with no older match is the one they read.
pub(super) fn receipt_excludes(state: &mut NetworkState, friend: &[u8; 16]) -> Vec<i64> {
    match state.chat_session_flushed.get(friend) {
        Some((at, ids)) if at.elapsed() < RECEIPT_RESEND_WINDOW => ids.clone(),
        Some(_) => {
            state.chat_session_flushed.remove(friend);
            Vec::new()
        }
        None => Vec::new(),
    }
}

/// Run the flushes [`schedule_chat_flush`] made due. A friend whose session
/// is gone is dropped: the next session flushes everything anyway.
pub(super) async fn flush_due_chat(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    settings: &AppSettings,
    ed25519_secret_key: &[u8; 32],
) {
    if state.chat_flush_due.is_empty() {
        return;
    }
    let now = std::time::Instant::now();
    let due: Vec<([u8; 16], u32)> = state
        .chat_flush_due
        .iter()
        .filter(|(_, (at, _))| *at <= now)
        .map(|(friend, (_, tries))| (*friend, *tries))
        .collect();
    for (friend, tries) in due {
        state.chat_flush_due.remove(&friend);
        let live = state
            .ember_sessions
            .read()
            .await
            .get(&friend)
            .is_some_and(|h| h.is_fresh() && h.is_secure_v2());
        if !live || !settings.chat_allowed_with(&friend) {
            continue;
        }
        flush_pending_chat(db, app_handle, &state.ember_sessions, ed25519_secret_key, friend).await;
        let (db_left, hash_hex) = (db.clone(), hex::encode(friend));
        let left = tokio::task::spawn_blocking(move || db_left.pending_chat_messages(&hash_hex, 1))
            .await
            .ok()
            .and_then(Result::ok)
            .is_some_and(|rows| !rows.is_empty());
        if left && tries + 1 < CHAT_FLUSH_TRIES {
            let backoff = std::time::Duration::from_secs(2u64 << tries.min(4));
            state
                .chat_flush_due
                .insert(friend, (std::time::Instant::now() + backoff, tries + 1));
        }
    }
}

/// Replay outbound chat that was queued while a friend was unreachable.
///
/// Called whenever a session to `friend` becomes live. Messages go out oldest
/// first so a conversation replays in the order it was typed, and each row is
/// only marked delivered after its packet is accepted by the session channel —
/// a mid-flush disconnect leaves the remainder queued for the next attempt.
///
/// Best-effort by design: a failure here simply leaves rows queued, so it
/// never propagates into the session-establishment path that called it.
/// Returns the ids it delivered.
pub(super) async fn flush_pending_chat(
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    ember_sessions: &ed2k::upload::EmberSessionMap,
    ed25519_secret_key: &[u8; 32],
    friend: [u8; 16],
) -> Vec<i64> {
    // Bounded so a friend who was offline for a very long time cannot stall
    // the network task; the rest flush on the next reconnect.
    const MAX_FLUSH_PER_SESSION: i64 = 200;

    let hash_hex = hex::encode(friend);
    let db_read = db.clone();
    let hash_for_read = hash_hex.clone();
    let pending = tokio::task::spawn_blocking(move || {
        // Abandon anything past the age ceiling before reading, in the same
        // blocking hop. The periodic sweep runs only hourly, and a reconnect can
        // land inside that window — so relying on it alone would deliver text
        // typed over a week ago, which is precisely what the ceiling exists to
        // prevent. Expiring here keeps one writer for the state while making the
        // flush self-consistent whenever it happens to run.
        // Logged rather than discarded, and deliberately not fatal: a failure
        // here means the age ceiling goes unenforced for this flush, so some
        // over-age messages may still go out — but refusing to flush at all
        // would hold back every legitimate queued message over a transient
        // database error, which is the worse outcome of the two.
        let expired = match db_read.expire_stale_queued_chat() {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(
                    "Could not expire over-age queued chat before flushing to \
                     {hash_for_read}; the age limit is unenforced this round: {e}"
                );
                Vec::new()
            }
        };
        let pending = db_read.pending_chat_messages(&hash_for_read, MAX_FLUSH_PER_SESSION);
        // Each one's disappearing timer, to follow it out. A failed lookup
        // sends them without one rather than not at all.
        let ids: Vec<i64> = pending
            .as_ref()
            .map(|rows| rows.iter().map(|(id, _, _)| *id).collect())
            .unwrap_or_default();
        let ttls = db_read.chat_ttls(&hash_for_read, &ids).unwrap_or_default();
        // Mailbox ids for a friend who collects, sent ahead of each message
        // so the friend shows it once even if a round leaves a copy too. A
        // failed lookup sends them without, which can only show one twice.
        let mailbox_ids = db_read
            .assign_chat_mailbox_ids(&hash_for_read, &ids)
            .unwrap_or_default();
        (expired, pending, ttls, mailbox_ids)
    })
    .await
    .ok()
    .map(|(expired, pending, ttls, mailbox_ids)| {
        emit_chat_delivery_failed(app_handle, &expired);
        pending.map(|rows| (rows, ttls, mailbox_ids))
    })
    .and_then(|r| r.ok());
    let Some((pending, ttls, mailbox_ids)) = pending else {
        return Vec::new();
    };

    if pending.is_empty() {
        return Vec::new();
    }
    info!(
        "Flushing {} queued chat message(s) to friend {hash_hex}",
        pending.len()
    );

    let mut sent: Vec<i64> = Vec::with_capacity(pending.len());
    {
        let sessions = ember_sessions.read().await;
        for (id, message, _stored_at) in pending {
            let Some((session_tx, envelope, peer_pubkey)) = sessions
                .get(&friend)
                .filter(|h| h.is_fresh() && h.is_secure_v2())
                .and_then(|sender| {
                    let peer_pubkey = sender.peer_ember_pubkey();
                    crate::network::ember::crypto::encrypt_chat_for_peer(
                        ed25519_secret_key,
                        &peer_pubkey,
                        message.as_bytes(),
                    )
                    .map(|envelope| (sender.tx.clone(), envelope, peer_pubkey))
                })
            else {
                // No usable session. Everything from here stays queued.
                break;
            };
            let mut framed = Vec::with_capacity(6 + envelope.len());
            framed.push(OP_EMULEPROT);
            framed.extend_from_slice(&((1 + envelope.len()) as u32).to_le_bytes());
            framed.push(ed2k::messages::OP_EMBER_CHAT_MSG);
            framed.extend_from_slice(&envelope);
            let mut frames = Vec::with_capacity(3);
            if let Some((msg_id, _)) = mailbox_ids.get(&id) {
                let Some(sealed) =
                    crate::network::ember::crypto::encrypt_chat_id(ed25519_secret_key, &peer_pubkey, msg_id)
                else {
                    break;
                };
                frames.push(ed2k::messages::build_ember_ext_frame(
                    ed2k::messages::EMBER_EXT_CHAT_ID,
                    &sealed,
                ));
            }
            frames.push(framed);
            if let Some(&ttl) = ttls.get(&id) {
                let target = crate::network::ember::crypto::ChatExpireTarget::Message(
                    crate::network::ember::crypto::chat_body_hash(&message),
                );
                // Without its timer the message stays queued: sent bare, it
                // would expire here and stay with the friend.
                let Some(frame) = chat_expire_frame(ed25519_secret_key, &peer_pubkey, target, ttl)
                else {
                    debug!("Queued chat {id} to {hash_hex} stays queued: its disappearing timer could not be sealed");
                    break;
                };
                frames.push(frame);
            }
            if try_send_frames_together(&session_tx, frames).is_err() {
                break;
            }
            sent.push(id);
        }
    }
    if sent.is_empty() {
        return Vec::new();
    }

    // One transaction for the whole flush rather than a commit per row: under
    // `synchronous=FULL` each was its own fsync, awaited in turn by the network
    // task that called this, up to 200 times over.
    let db_mark = db.clone();
    let ids = sent.clone();
    let hash_for_mark = hash_hex.clone();
    let marked = tokio::task::spawn_blocking(move || {
        let matched =
            db_mark.set_chat_delivery_many(&ids, crate::storage::database::CHAT_DELIVERED)?;
        let expiries: std::collections::HashMap<i64, i64> = db_mark
            .chat_expiries(&hash_for_mark, &ids)
            .unwrap_or_default()
            .into_iter()
            .collect();
        Ok::<_, anyhow::Error>((matched, expiries))
    })
    .await;
    // A mark that silently failed left the row queued, so the next session
    // with this friend sent the same message again and they saw it twice.
    // We cannot un-send it, so log loudly rather than discarding the result.
    let (matched, expiries) = match marked {
        Ok(Ok(marked)) => marked,
        Ok(Err(e)) => {
            tracing::warn!(
                "{} chat message(s) to {hash_hex} were sent but could not be marked \
                 delivered ({e}); they may be re-sent on the next session",
                sent.len()
            );
            return Vec::new();
        }
        Err(e) => {
            tracing::warn!(
                "{} chat message(s) to {hash_hex} were sent but the marking task failed \
                 ({e}); they may be re-sent on the next session",
                sent.len()
            );
            return Vec::new();
        }
    };
    let mut delivered = Vec::with_capacity(sent.len());
    for (id, matched) in sent.into_iter().zip(matched) {
        if !matched {
            // Only a deleted row misses: the user withdrew it in the moment
            // it was going out. It reached them, and is gone here.
            tracing::warn!(
                "Chat message {id} to {hash_hex} was deleted while it was being sent; \
                 the friend has it"
            );
            continue;
        }
        delivered.push(id);
        let _ = app_handle.emit(
            "ember:chat-delivery",
            serde_json::json!({
                "user_hash": hash_hex,
                "id": id,
                "delivery": "delivered",
                "expires_at": expiries.get(&id),
            }),
        );
    }
    delivered
}

/// Hand a typing or read-receipt signal to a live friend session. Returns
/// false when there is no fresh session or the writer queue is full — the
/// caller decides whether to retry (receipts) or drop (typing).
pub(super) async fn send_encrypted_chat_ext(
    ember_sessions: &ed2k::upload::EmberSessionMap,
    ed25519_secret_key: &[u8; 32],
    friend: [u8; 16],
    ext_type: u8,
    plaintext: &[u8],
) -> bool {
    let Some((session_tx, envelope)) = ({
        let sessions = ember_sessions.read().await;
        sessions
            .get(&friend)
            .filter(|h| h.is_fresh() && h.is_secure_v2())
            .and_then(|sender| {
                let peer_pubkey = sender.peer_ember_pubkey();
                let envelope = match ext_type {
                    ed2k::messages::EMBER_EXT_CHAT_TYPING => {
                        crate::network::ember::crypto::encrypt_chat_typing(
                            ed25519_secret_key,
                            &peer_pubkey,
                            plaintext.first().copied().unwrap_or(0) != 0,
                        )
                    }
                    ed2k::messages::EMBER_EXT_STATUS => {
                        crate::network::ember::crypto::encrypt_chat_status(
                            ed25519_secret_key,
                            &peer_pubkey,
                            plaintext.first().copied().unwrap_or(0),
                        )
                    }
                    ed2k::messages::EMBER_EXT_CHAT_READ => plaintext.try_into().ok().and_then(
                        |body_hash: [u8; crate::network::ember::crypto::CHAT_BODY_HASH_LEN]| {
                            crate::network::ember::crypto::encrypt_chat_read(
                                ed25519_secret_key,
                                &peer_pubkey,
                                &body_hash,
                            )
                        },
                    ),
                    _ => crate::network::ember::crypto::encrypt_chat_for_peer(
                        ed25519_secret_key,
                        &peer_pubkey,
                        plaintext,
                    ),
                };
                envelope.map(|envelope| (sender.tx.clone(), envelope))
            })
    }) else {
        return false;
    };
    session_tx
        .try_send(ed2k::messages::build_ember_ext_frame(ext_type, &envelope))
        .is_ok()
}

/// The frame that follows something we sent a friend with our disappearing
/// timer for it. `None` only if the peer's key cannot produce an envelope.
pub(super) fn chat_expire_frame(
    ed25519_secret_key: &[u8; 32],
    peer_pubkey: &[u8; 32],
    target: crate::network::ember::crypto::ChatExpireTarget,
    ttl_secs: u32,
) -> Option<Vec<u8>> {
    let envelope = crate::network::ember::crypto::encrypt_chat_expire(
        ed25519_secret_key,
        peer_pubkey,
        target,
        ttl_secs,
    )?;
    Some(ed2k::messages::build_ember_ext_frame(
        ed2k::messages::EMBER_EXT_CHAT_EXPIRE,
        &envelope,
    ))
}

/// Queue `frames` on a friend's session all together or not at all. A chat
/// message whose timer frame did not fit would expire on our side and stay on
/// theirs.
pub(super) fn try_send_frames_together(
    tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    frames: Vec<Vec<u8>>,
) -> Result<(), tokio::sync::mpsc::error::TrySendError<()>> {
    let permits = tx.try_reserve_many(frames.len())?;
    for (permit, frame) in permits.zip(frames) {
        permit.send(frame);
    }
    Ok(())
}

/// How long a timer that arrived ahead of its message is held for it.
pub(super) const CHAT_EXPIRE_HOLD_SECS: i64 = 120;

/// Timers held at once, across friends. A friend cannot grow it past this by
/// naming messages that never come.
pub(super) const MAX_HELD_CHAT_EXPIRES: usize = 256;

/// Timers held at once for one friend, so one naming messages that never come
/// cannot crowd out everyone else's.
pub(super) const MAX_HELD_CHAT_EXPIRES_PER_FRIEND: usize = 32;

/// Apply the disappearing timer `friend` named for something they sent us,
/// or hold it until that arrives.
///
/// Held rather than dropped because the timer can overtake its message on the
/// way to the database, and a dropped one leaves our copy without the expiry
/// the sender asked for. Clamped to [`crate::types::CHAT_DISAPPEAR_PEER_MAX_SECS`]:
/// a longer timer still deletes, just sooner than a sender on a future build
/// might have asked, which never keeps anything longer than it wanted. And
/// raised to [`crate::types::CHAT_DISAPPEAR_PEER_MIN_SECS`], so what it names
/// can still be read.
pub(super) async fn apply_peer_chat_expire(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    friend: [u8; 16],
    target: crate::network::ember::crypto::ChatExpireTarget,
    ttl_secs: u32,
) {
    if ttl_secs == 0 {
        return;
    }
    let ttl_secs = ttl_secs.clamp(
        crate::types::CHAT_DISAPPEAR_PEER_MIN_SECS,
        crate::types::CHAT_DISAPPEAR_PEER_MAX_SECS,
    );
    let friend_hex = hex::encode(friend);
    let db_apply = db.clone();
    let hash_for_db = friend_hex.clone();
    let applied = tokio::task::spawn_blocking(move || match target {
        crate::network::ember::crypto::ChatExpireTarget::Message(body_hash) => db_apply
            .apply_peer_chat_ttl(&hash_for_db, &hex::encode(body_hash), ttl_secs)
            .map(|row| row.map(|(id, at)| at.map(|at| (id, at)))),
        crate::network::ember::crypto::ChatExpireTarget::Attachment(xfer_id) => db_apply
            .set_received_chat_attachment_ttl(&hash_for_db, &hex::encode(xfer_id), ttl_secs)
            .map(|matched| matched.then_some(None)),
    })
    .await;
    match applied {
        Ok(Ok(Some(started))) => {
            if let Some(item) = started {
                emit_chat_expiry(app_handle, &friend_hex, &[item]);
            }
        }
        Ok(Ok(None)) => {
            let now = chrono::Utc::now().timestamp();
            state
                .held_chat_expires
                .retain(|_, (_, at)| now.saturating_sub(*at) < CHAT_EXPIRE_HOLD_SECS);
            let from_friend = state
                .held_chat_expires
                .keys()
                .filter(|(held_from, _)| *held_from == friend)
                .count();
            if state.held_chat_expires.len() < MAX_HELD_CHAT_EXPIRES
                && from_friend < MAX_HELD_CHAT_EXPIRES_PER_FRIEND
            {
                state.held_chat_expires.insert((friend, target), (ttl_secs, now));
            }
        }
        Ok(Err(e)) => warn!("Failed to apply a disappearing timer from {friend_hex}: {e}"),
        Err(e) => warn!("Disappearing-timer task failed for {friend_hex}: {e}"),
    }
}

/// The timer held for `target` from `friend`, if one arrived ahead of it.
pub(super) fn take_held_chat_expire(
    state: &mut NetworkState,
    friend: [u8; 16],
    target: crate::network::ember::crypto::ChatExpireTarget,
) -> Option<u32> {
    let (ttl, at) = state.held_chat_expires.remove(&(friend, target))?;
    (chrono::Utc::now().timestamp().saturating_sub(at) < CHAT_EXPIRE_HOLD_SECS).then_some(ttl)
}

/// Tell an open conversation when these messages now disappear.
pub(super) fn emit_chat_expiry(app_handle: &tauri::AppHandle, friend_hash: &str, items: &[(i64, i64)]) {
    if items.is_empty() {
        return;
    }
    let _ = app_handle.emit(
        "ember:chat-expiry",
        serde_json::json!({
            "user_hash": friend_hash,
            "items": items
                .iter()
                .map(|(id, at)| serde_json::json!({ "id": id, "expires_at": at }))
                .collect::<Vec<_>>(),
        }),
    );
}

/// Tell open conversations what just disappeared or was deleted.
pub(super) fn emit_chat_removed(
    app_handle: &tauri::AppHandle,
    friend_hash: &str,
    ids: &[i64],
    xfer_ids: &[String],
) {
    if ids.is_empty() && xfer_ids.is_empty() {
        return;
    }
    let _ = app_handle.emit(
        "ember:chat-removed",
        serde_json::json!({
            "user_hash": friend_hash,
            "ids": ids,
            "xfer_ids": xfer_ids,
        }),
    );
}

pub(super) async fn flush_pending_read_receipt(
    db: &Arc<Database>,
    ember_sessions: &ed2k::upload::EmberSessionMap,
    ed25519_secret_key: &[u8; 32],
    friend: [u8; 16],
) {
    let hash_hex = hex::encode(friend);
    let db_read = db.clone();
    let Ok(Ok(Some(hash_hex_str))) =
        tokio::task::spawn_blocking(move || db_read.latest_read_received_hash(&hash_hex)).await
    else {
        return;
    };
    let Ok(bytes) = hex::decode(&hash_hex_str) else {
        return;
    };
    let Ok(body_hash) = <[u8; 16]>::try_from(bytes.as_slice()) else {
        return;
    };
    let _ = send_encrypted_chat_ext(
        ember_sessions,
        ed25519_secret_key,
        friend,
        ed2k::messages::EMBER_EXT_CHAT_READ,
        &body_hash,
    )
    .await;
}

/// Persist a chat-history row before it is exposed as delivered to the UI.
///
/// Wire delivery and SQLite durability are distinct operations, but claiming
/// a message is delivered before the latter succeeds creates history entries
/// that vanish after reload. Callers therefore await this helper before
/// emitting their corresponding chat event or acknowledging the IPC request.
pub(super) async fn persist_chat_history_message(
    db: Arc<Database>,
    user_hash: String,
    direction: &'static str,
    message: String,
    ttl_secs: u32,
) -> Result<i64, String> {
    tokio::task::spawn_blocking(move || {
        db.insert_chat_message_ttl(
            &user_hash,
            direction,
            &message,
            crate::storage::database::CHAT_DELIVERED,
            ttl_secs,
        )
    })
        .await
        .map_err(|error| format!("Chat history persistence task failed: {error}"))?
        .map_err(|error| format!("Failed to persist chat history: {error}"))
}

/// Ceiling on marking a chat outbox row delivered, measured from the network
/// task.
///
/// Bounded because the loop should not wait indefinitely on `Database`'s
/// `Mutex<Connection>` — the insert itself is sub-millisecond, but a library
/// scan or statistics flush already inside that mutex holds the loop for as
/// long as it takes. Safe to bound here specifically because a timeout is
/// reported as `ChatAlreadyQueued`, the packet has already been handed to the
/// session writer, and the abandoned write marking the row delivered later is
/// the outcome we wanted anyway.
pub(super) const CHAT_OUTBOX_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Create a durable outbox row before handing a chat packet to a session
/// writer. The row makes a failed writer handoff recoverable on the next
/// session instead of leaving a peer-visible message with no local history.
///
/// Deliberately *not* bounded by [`CHAT_OUTBOX_WRITE_TIMEOUT`], unlike its
/// sibling. `spawn_blocking` cannot be cancelled, so a timeout here would
/// abandon an insert that then lands anyway — while the error it returns sends
/// `send_chat_message` down its "could not reach them right now" path, which
/// inserts a pending row of its own. Two rows for one message means the next
/// session flush delivers it twice. The write therefore stays unbounded: this
/// is one insert, ordered before the handoff on purpose, and a duplicate
/// message the user never typed is a worse failure than a loop that waits out
/// whatever else is holding the connection.
pub(super) async fn queue_outbound_chat_message(
    db: Arc<Database>,
    user_hash: String,
    message: String,
    ttl_secs: u32,
) -> Result<i64, String> {
    tokio::task::spawn_blocking(move || {
        db.insert_chat_message_ttl(
            &user_hash,
            "sent",
            &message,
            crate::storage::database::CHAT_QUEUED,
            ttl_secs,
        )
    })
        .await
        .map_err(|error| format!("Chat outbox persistence task failed: {error}"))?
        .map_err(|error| format!("Failed to persist chat outbox row: {error}"))
}

/// Mark an outbox row delivered only after its packet was accepted by the
/// current live session's writer queue. Returns when it disappears, if it
/// carries a timer — delivery is what starts it.
pub(super) async fn mark_outbound_chat_delivered(
    db: Arc<Database>,
    friend_hash: String,
    message_id: i64,
) -> Result<Option<i64>, String> {
    let write = tokio::task::spawn_blocking(move || {
        db.set_chat_delivery(message_id, crate::storage::database::CHAT_DELIVERED)?;
        Ok::<_, anyhow::Error>(
            db.chat_expiries(&friend_hash, &[message_id])?
                .first()
                .map(|(_, at)| *at),
        )
    });
    // Same reasoning as `CHAT_OUTBOX_WRITE_TIMEOUT`. A timeout here leaves the
    // row pending, which the caller surfaces as "already queued" — the message
    // is on the wire either way, and the flush path treats a pending row as
    // something to retry rather than as loss.
    tokio::time::timeout(CHAT_OUTBOX_WRITE_TIMEOUT, write)
        .await
        .map_err(|_| "Chat delivery write did not complete in time".to_string())?
        .map_err(|error| format!("Chat delivery persistence task failed: {error}"))?
        .map_err(|error| format!("Failed to mark chat delivered: {error}"))
}

/// Window for suppressing an exact-text repeat of a friend's chat message
/// arriving via a second connection (see `NetworkState::recent_ember_chat`).
/// Short enough that a friend deliberately re-sending the same text twice
/// in a real conversation is very unlikely to be swallowed, long enough to
/// cover the realistic skew between two TCP connections both delivering
/// the same peer-side send.
pub(super) const EMBER_CHAT_DEDUP_WINDOW_SECS: i64 = 5;
