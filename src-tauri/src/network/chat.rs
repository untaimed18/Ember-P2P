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

/// Replay outbound chat that was queued while a friend was unreachable.
///
/// Called whenever a session to `friend` becomes live. Messages go out oldest
/// first so a conversation replays in the order it was typed, and each row is
/// only marked delivered after its packet is accepted by the session channel —
/// a mid-flush disconnect leaves the remainder queued for the next attempt.
///
/// Best-effort by design: a failure here simply leaves rows queued, so it
/// never propagates into the session-establishment path that called it.
pub(super) async fn flush_pending_chat(
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    ember_sessions: &ed2k::upload::EmberSessionMap,
    ed25519_secret_key: &[u8; 32],
    friend: [u8; 16],
) {
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
        (
            expired,
            db_read.pending_chat_messages(&hash_for_read, MAX_FLUSH_PER_SESSION),
        )
    })
    .await
    .ok()
    .map(|(expired, pending)| {
        emit_chat_delivery_failed(app_handle, &expired);
        pending
    })
    .and_then(|r| r.ok())
    .unwrap_or_default();

    if pending.is_empty() {
        return;
    }
    info!(
        "Flushing {} queued chat message(s) to friend {hash_hex}",
        pending.len()
    );

    for (id, message, _stored_at) in pending {
        let Some(packet) = ({
            let sessions = ember_sessions.read().await;
            sessions
                .get(&friend)
                .filter(|h| h.is_fresh() && h.is_secure_v2())
                .and_then(|sender| {
                    let peer_pubkey = sender.peer_ember_pubkey();
                    crate::network::ember::crypto::encrypt_chat_for_peer(
                        ed25519_secret_key,
                        &peer_pubkey,
                        message.as_bytes(),
                    )
                    .map(|envelope| (sender.tx.clone(), envelope))
                })
        }) else {
            // Session went away mid-flush. Everything from here stays queued.
            break;
        };
        let (session_tx, envelope) = packet;
        let mut framed = Vec::with_capacity(6 + envelope.len());
        framed.push(OP_EMULEPROT);
        framed.extend_from_slice(&((1 + envelope.len()) as u32).to_le_bytes());
        framed.push(ed2k::messages::OP_EMBER_CHAT_MSG);
        framed.extend_from_slice(&envelope);
        if session_tx.try_send(framed).is_err() {
            break;
        }
        let db_mark = db.clone();
        // A mark that silently failed left the row queued, so the next session
        // with this friend sent the same message again and they saw it twice.
        // We cannot un-send it, so log loudly rather than discarding the result.
        let marked_delivered = match tokio::task::spawn_blocking(move || {
            db_mark.set_chat_delivery(id, crate::storage::database::CHAT_DELIVERED)
        })
        .await
        {
            Ok(Ok(_n @ 1..)) => true,
            Ok(Ok(0)) => {
                tracing::warn!(
                    "Chat message {id} to {hash_hex} was sent but matched no row to mark \
                     delivered; it may be re-sent on the next session"
                );
                false
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    "Chat message {id} to {hash_hex} was sent but could not be marked \
                     delivered ({e}); it may be re-sent on the next session"
                );
                false
            }
            Err(e) => {
                tracing::warn!(
                    "Chat message {id} to {hash_hex} was sent but the marking task failed \
                     ({e}); it may be re-sent on the next session"
                );
                false
            }
        };
        if marked_delivered {
            let _ = app_handle.emit(
                "ember:chat-delivery",
                serde_json::json!({
                    "user_hash": hash_hex,
                    "id": id,
                    "delivery": "delivered",
                }),
            );
        }
    }
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
) -> Result<i64, String> {
    tokio::task::spawn_blocking(move || db.insert_chat_message(&user_hash, direction, &message))
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
) -> Result<i64, String> {
    tokio::task::spawn_blocking(move || db.insert_pending_chat_message(&user_hash, &message))
        .await
        .map_err(|error| format!("Chat outbox persistence task failed: {error}"))?
        .map_err(|error| format!("Failed to persist chat outbox row: {error}"))
}

/// Mark an outbox row delivered only after its packet was accepted by the
/// current live session's writer queue.
pub(super) async fn mark_outbound_chat_delivered(db: Arc<Database>, message_id: i64) -> Result<(), String> {
    let write = tokio::task::spawn_blocking(move || {
        db.set_chat_delivery(message_id, crate::storage::database::CHAT_DELIVERED)
    });
    // Same reasoning as `CHAT_OUTBOX_WRITE_TIMEOUT`. A timeout here leaves the
    // row pending, which the caller surfaces as "already queued" — the message
    // is on the wire either way, and the flush path treats a pending row as
    // something to retry rather than as loss.
    tokio::time::timeout(CHAT_OUTBOX_WRITE_TIMEOUT, write)
        .await
        .map_err(|_| "Chat delivery write did not complete in time".to_string())?
        .map_err(|error| format!("Chat delivery persistence task failed: {error}"))?
        .map(|_| ())
        .map_err(|error| format!("Failed to mark chat delivered: {error}"))
}

/// Window for suppressing an exact-text repeat of a friend's chat message
/// arriving via a second connection (see `NetworkState::recent_ember_chat`).
/// Short enough that a friend deliberately re-sending the same text twice
/// in a real conversation is very unlikely to be swallowed, long enough to
/// cover the realistic skew between two TCP connections both delivering
/// the same peer-side send.
pub(super) const EMBER_CHAT_DEDUP_WINDOW_SECS: i64 = 5;
