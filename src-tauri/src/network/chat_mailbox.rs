//! The chat mailbox: chat for a friend who is offline, left sealed on the
//! rendezvous server and collected by them later.
//!
//! The server only shortens the wait. A message left there stays queued here
//! until the friend's own receipt comes back through the mailbox, and goes
//! out directly the next time both are online if it has not; that direct copy
//! carries its mailbox id (`EMBER_EXT_CHAT_ID`), so a friend who already
//! collected it shows it once. Nothing is lost if the server forgets.
//!
//! Only friends who have said they collect (`EMBER_EXT_MAILBOX_AWARE`) are
//! left anything, since an older build never would. A round runs on its own
//! task: one at a time, every few minutes, and early when a friend's session
//! comes up or a message is queued.

use super::*;
use crate::network::ember::crypto::{
    chat_mailbox_day, derive_chat_mailbox_box, open_mailbox_payload,
    seal_mailbox_payload, MailboxPayload, MAX_MAILBOX_RECEIPT_IDS,
};
use crate::storage::database::CHAT_DELIVERED;

/// How often a round runs on its own.
pub(super) const CHAT_MAILBOX_INTERVAL: std::time::Duration = std::time::Duration::from_secs(180);
/// Least time between two rounds started early.
const CHAT_MAILBOX_KICK_GAP: std::time::Duration = std::time::Duration::from_secs(15);
/// Messages left for one friend per round. The server holds 64 per box a day.
const DEPOSITS_PER_FRIEND_PER_ROUND: usize = 32;
/// Pages of collected entries per round; the rest wait for the next.
const FETCH_PAGES_PER_ROUND: usize = 8;
/// Days of boxes collected from: as long as the server keeps an entry.
const MAILBOX_LOOKBACK_DAYS: i64 = 7;
/// Boxes read per friend: the lookback, today, and tomorrow.
const BOX_DAYS: usize = MAILBOX_LOOKBACK_DAYS as usize + 2;
/// Boxes named in one fetch: as many whole friends as fit the server's
/// ceiling of 400, so one friend's boxes are never split across two.
const BOXES_PER_FETCH: usize = (400 / BOX_DAYS) * BOX_DAYS;

/// Start a round if one is allowed and none is running. `early` is a round
/// asked for by an event rather than the timer, held to
/// [`CHAT_MAILBOX_KICK_GAP`].
pub(super) fn start_chat_mailbox_round(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    settings: &AppSettings,
    ed25519_secret_key: [u8; 32],
    ed25519_pubkey: [u8; 32],
    early: bool,
) {
    // With the mailbox setting off, a round still takes back what earlier ones
    // left and has since been delivered or deleted; it leaves and collects
    // nothing. With Ember off or chat locked there is no round at all.
    if !settings.ember_native_enabled || db.chat_locked() {
        return;
    }
    if chat_mailbox_round_running(state) {
        state.chat_mailbox_rerun |= early;
        return;
    }
    if early
        && state
            .chat_mailbox_last_round
            .is_some_and(|at| at.elapsed() < CHAT_MAILBOX_KICK_GAP)
    {
        state.chat_mailbox_rerun = true;
        return;
    }
    state.chat_mailbox_last_round = Some(std::time::Instant::now());
    state.chat_mailbox_rerun = false;
    // A live session flushes the queue directly; a friend merely seen lately
    // may have none, and is left mail.
    let online = state
        .ember_sessions
        .try_read()
        .map(|sessions| {
            sessions
                .iter()
                .filter(|(_, handle)| handle.is_fresh() && handle.is_secure_v2())
                .map(|(hash, _)| *hash)
                .collect()
        })
        .unwrap_or_else(|_| state.online_friends.keys().copied().collect());
    let round = MailboxRound {
        db: db.clone(),
        app_handle: app_handle.clone(),
        settings: settings.clone(),
        base_url: settings.rendezvous_url.clone(),
        seed: ed25519_secret_key,
        our_pubkey: ed25519_pubkey,
        online,
    };
    state.chat_mailbox_round = Some(tokio::spawn(async move {
        round.run().await;
    }));
}

pub(super) fn chat_mailbox_round_running(state: &NetworkState) -> bool {
    state
        .chat_mailbox_round
        .as_ref()
        .is_some_and(|round| !round.is_finished())
}

/// An early round held back by [`CHAT_MAILBOX_KICK_GAP`] or a running round
/// may start now.
pub(super) fn chat_mailbox_rerun_due(state: &NetworkState) -> bool {
    state.chat_mailbox_rerun
        && !chat_mailbox_round_running(state)
        && state
            .chat_mailbox_last_round
            .is_none_or(|at| at.elapsed() >= CHAT_MAILBOX_KICK_GAP)
}

/// Whether a round collects what `friend` leaves us.
pub(super) fn collects_chat_mail_from(settings: &AppSettings, friend: &[u8; 16]) -> bool {
    settings.ember_native_enabled && settings.chat_mailbox_enabled && settings.chat_allowed_with(friend)
}

/// Tell a friend whose session just came up whether we collect from the
/// mailbox. Said either way, so a friend who left us mail before we turned it
/// off stops.
pub(super) async fn on_friend_session_for_mailbox(
    state: &NetworkState,
    settings: &AppSettings,
    friend: [u8; 16],
) {
    let sessions = state.ember_sessions.read().await;
    if let Some(session) = sessions
        .get(&friend)
        .filter(|h| h.is_fresh() && h.is_secure_v2())
    {
        let _ = session.tx.try_send(ed2k::messages::build_ember_ext_frame(
            ed2k::messages::EMBER_EXT_MAILBOX_AWARE,
            &[u8::from(collects_chat_mail_from(settings, &friend))],
        ));
    }
}

/// The friend said whether they collect from the mailbox.
pub(super) async fn on_friend_mailbox_aware(db: &Arc<Database>, friend: [u8; 16], collects: bool) {
    let db_write = db.clone();
    let hex = hex::encode(friend);
    if let Ok(Err(e)) =
        tokio::task::spawn_blocking(move || db_write.set_friend_chat_mailbox(&hex, collects)).await
    {
        debug!("Could not record whether a friend collects chat mail: {e}");
    }
}

struct MailboxFriend {
    hash: [u8; 16],
    hex: String,
    pubkey: [u8; 32],
}

struct MailboxRound {
    db: Arc<Database>,
    app_handle: tauri::AppHandle,
    settings: AppSettings,
    base_url: String,
    seed: [u8; 32],
    our_pubkey: [u8; 32],
    /// Friends with a live session, whose queue is flushed directly instead.
    online: HashSet<[u8; 16]>,
}

impl MailboxRound {
    async fn run(self) {
        // First and whatever else the round does: ids handed out for direct
        // sends, and ones seen from friends, pile up even when nothing here
        // reaches the server.
        let db = self.db.clone();
        let now = chrono::Utc::now().timestamp();
        let _ = tokio::task::spawn_blocking(move || db.prune_chat_mailbox(now)).await;
        if !rendezvous::chat_mailbox_supported(&self.base_url).await {
            return;
        }
        self.withdraw_stale().await;
        if !self.settings.chat_mailbox_enabled {
            return;
        }
        let db = self.db.clone();
        let Ok(Ok((friends, collectors))) = tokio::task::spawn_blocking(move || {
            Ok::<_, anyhow::Error>((db.get_friend_public_keys()?, db.chat_mailbox_friends()?))
        })
        .await
        else {
            return;
        };
        let friends: Vec<MailboxFriend> = friends
            .into_iter()
            .filter(|(hash, _)| self.settings.chat_allowed_with(hash))
            .map(|(hash, pubkey)| MailboxFriend {
                hash,
                hex: hex::encode(hash),
                pubkey,
            })
            .collect();
        if friends.is_empty() {
            return;
        }
        let now = chrono::Utc::now().timestamp();
        let day = chat_mailbox_day(now);
        // Collecting first: a long queue of deposits can use up the server's
        // per-address allowance, and what friends left matters more.
        self.collect(&friends, day, now).await;
        for friend in &friends {
            if collectors.contains(&friend.hex) && !self.online.contains(&friend.hash) {
                self.deposit(friend, day, now).await;
            }
        }
    }

    /// Take back copies of messages no longer queued here. A copy is
    /// forgotten only once the server confirms; otherwise the next round tries
    /// again, until the server would have dropped it anyway.
    async fn withdraw_stale(&self) {
        let db = self.db.clone();
        let Ok(Ok(stale)) = tokio::task::spawn_blocking(move || db.chat_mailbox_stale_deposits()).await
        else {
            return;
        };
        let mut by_box: HashMap<[u8; 32], Vec<(i64, [u8; 16])>> = HashMap::new();
        for (message_id, mailbox, item_id) in stale {
            by_box.entry(mailbox).or_default().push((message_id, item_id));
        }
        let mut taken_back = Vec::new();
        for (mailbox, entries) in by_box {
            for chunk in entries.chunks(64) {
                let ids: Vec<[u8; 16]> = chunk.iter().map(|(_, id)| *id).collect();
                match rendezvous::chat_mailbox_delete(&self.base_url, &mailbox, &ids).await {
                    Ok(()) => taken_back.extend(chunk.iter().map(|(message_id, _)| *message_id)),
                    Err(e) => debug!("Chat mailbox: could not take back {} entries: {e}", ids.len()),
                }
            }
        }
        if !taken_back.is_empty() {
            let db = self.db.clone();
            let _ = tokio::task::spawn_blocking(move || db.forget_chat_mailbox_sent(&taken_back)).await;
        }
    }

    /// Leave what is queued for `friend` in today's box.
    async fn deposit(&self, friend: &MailboxFriend, day: i64, now: i64) {
        let Some(mailbox) = derive_chat_mailbox_box(&self.seed, &friend.pubkey, &friend.pubkey, day)
        else {
            return;
        };
        let db = self.db.clone();
        let hex = friend.hex.clone();
        let Ok(Ok((expired, pending, assigned, ttls))) = tokio::task::spawn_blocking(move || {
            // Past the queue's age ceiling first, as a flush does: the hourly
            // sweep alone would let a message older than that be left.
            let expired = db.expire_stale_queued_chat().unwrap_or_default();
            let pending = db.pending_chat_messages(&hex, 200)?;
            let ids: Vec<i64> = pending.iter().map(|(id, _, _)| *id).collect();
            Ok::<_, anyhow::Error>((
                expired,
                pending,
                db.chat_mailbox_ids(&hex, &ids)?,
                db.chat_ttls(&hex, &ids)?,
            ))
        })
        .await
        else {
            return;
        };
        emit_chat_delivery_failed(&self.app_handle, &expired);
        let mut left = 0usize;
        for (id, text, _) in pending {
            if left >= DEPOSITS_PER_FRIEND_PER_ROUND {
                break;
            }
            let msg_id = match assigned.get(&id) {
                Some((_, true)) => continue,
                Some((msg_id, false)) => *msg_id,
                None => {
                    let mut msg_id = [0u8; 16];
                    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut msg_id);
                    let db = self.db.clone();
                    let hex = friend.hex.clone();
                    // A direct send may have given the row an id since it
                    // was read; the copy left here must carry that one.
                    match tokio::task::spawn_blocking(move || {
                        db.record_chat_mailbox_sent(id, &hex, &msg_id)
                    })
                    .await
                    {
                        Ok(Ok(stored)) => stored,
                        _ => return,
                    }
                }
            };
            let Some(blob) = seal_mailbox_payload(
                &self.seed,
                &friend.pubkey,
                &mailbox,
                &MailboxPayload::Message {
                    msg_id,
                    ttl_secs: ttls.get(&id).copied().unwrap_or(0),
                    text,
                },
            ) else {
                continue;
            };
            let item_id = match rendezvous::chat_mailbox_put(&self.base_url, &mailbox, &blob).await {
                Ok(item_id) => item_id,
                Err(e) => {
                    // A full box or a busy server: what is left goes
                    // directly, or in a later round.
                    debug!(
                        "Chat mailbox: deposit for {} stopped: {e}",
                        crate::security::short_hash(&friend.hash)
                    );
                    return;
                }
            };
            let db = self.db.clone();
            let still_queued = tokio::task::spawn_blocking(move || {
                db.mark_chat_mailbox_deposited(id, now, &mailbox, &item_id)?;
                db.chat_message_still_queued(id)
            })
            .await;
            // Sent directly, or deleted, while the copy was on its way: take it
            // back now, or the friend shows it twice or gets what the user
            // withdrew. What fails here the next round's `withdraw_stale` gets.
            if !matches!(still_queued, Ok(Ok(true))) {
                if rendezvous::chat_mailbox_delete(&self.base_url, &mailbox, &[item_id]).await.is_ok() {
                    let db = self.db.clone();
                    let _ = tokio::task::spawn_blocking(move || db.forget_chat_mailbox_sent(&[id])).await;
                }
                continue;
            }
            left += 1;
        }
        if left > 0 {
            debug!(
                "Chat mailbox: left {left} message(s) for {}",
                crate::security::short_hash(&friend.hash)
            );
        }
    }

    /// Collect what friends left for us over the last week: store their
    /// messages, act on their receipts, clear the entries, and send a receipt
    /// for what was taken.
    async fn collect(&self, friends: &[MailboxFriend], day: i64, now: i64) {
        // Each friend's boxes together and oldest day first, so the server
        // answers in that order and their messages are stored in the order
        // they were left. Tomorrow's too: a sender whose clock is ahead files
        // under it.
        let mut boxes: HashMap<[u8; 32], usize> = HashMap::new();
        let mut all: Vec<[u8; 32]> = Vec::with_capacity(friends.len() * BOX_DAYS);
        for (index, friend) in friends.iter().enumerate() {
            for d in (day - MAILBOX_LOOKBACK_DAYS)..=(day + 1) {
                if let Some(mailbox) =
                    derive_chat_mailbox_box(&self.seed, &friend.pubkey, &self.our_pubkey, d)
                {
                    boxes.insert(mailbox, index);
                    all.push(mailbox);
                }
            }
        }
        'chunks: for chunk in all.chunks(BOXES_PER_FETCH) {
            for _ in 0..FETCH_PAGES_PER_ROUND {
                let page = match rendezvous::chat_mailbox_fetch(&self.base_url, chunk).await {
                    Ok(page) => page,
                    Err(e) => {
                        debug!("Chat mailbox: collect failed: {e}");
                        break 'chunks;
                    }
                };
                let mut clear: HashMap<[u8; 32], Vec<[u8; 16]>> = HashMap::new();
                // Messages stored, per friend, with the entries they came in.
                let mut taken: HashMap<usize, Vec<([u8; 16], [u8; 32], [u8; 16])>> = HashMap::new();
                let mut confirmed: HashMap<usize, Vec<[u8; 16]>> = HashMap::new();
                // Something stays on the server that the next page would
                // serve again, so this chunk waits for the next round.
                let mut left_behind = false;
                for item in &page.items {
                    let Some(&index) = boxes.get(&item.mailbox) else {
                        continue;
                    };
                    let friend = &friends[index];
                    match open_mailbox_payload(&self.seed, &friend.pubkey, &item.mailbox, &item.blob) {
                        Some(MailboxPayload::Message {
                            msg_id,
                            ttl_secs,
                            text,
                        }) => {
                            // Left on the server if it could not be stored,
                            // so the next round tries again.
                            if self.receive(friend, msg_id, ttl_secs, &text, now).await {
                                taken.entry(index).or_default().push((msg_id, item.mailbox, item.id));
                            } else {
                                left_behind = true;
                            }
                            continue;
                        }
                        Some(MailboxPayload::Receipt { msg_ids }) => {
                            confirmed.entry(index).or_default().extend(msg_ids);
                        }
                        // Not sealed by this friend for this box: nothing a
                        // round can ever read, so it goes too.
                        None => {}
                    }
                    clear.entry(item.mailbox).or_default().push(item.id);
                }
                for (index, msg_ids) in confirmed {
                    self.confirm_delivered(&friends[index], msg_ids).await;
                }
                // A message's entry goes only once the receipt for it is left.
                // Until then the next round collects it again, finds it shown,
                // and retries the receipt; without one the sender would mark
                // it failed after a week though the friend has it.
                for (index, entries) in taken {
                    let msg_ids: Vec<[u8; 16]> = entries.iter().map(|(msg_id, _, _)| *msg_id).collect();
                    if self.leave_receipt(&friends[index], day, &msg_ids).await {
                        for (_, mailbox, item_id) in entries {
                            clear.entry(mailbox).or_default().push(item_id);
                        }
                    } else {
                        left_behind = true;
                    }
                }
                for (mailbox, ids) in clear {
                    if let Err(e) = rendezvous::chat_mailbox_delete(&self.base_url, &mailbox, &ids).await {
                        debug!("Chat mailbox: clearing collected entries failed: {e}");
                        left_behind = true;
                    }
                }
                if !page.more || left_behind {
                    break;
                }
            }
        }
    }

    /// Tell `friend` these messages were collected, in today's box to them.
    /// `true` once every receipt is on the server.
    async fn leave_receipt(&self, friend: &MailboxFriend, day: i64, msg_ids: &[[u8; 16]]) -> bool {
        let Some(mailbox) = derive_chat_mailbox_box(&self.seed, &friend.pubkey, &friend.pubkey, day)
        else {
            return false;
        };
        for ids in msg_ids.chunks(MAX_MAILBOX_RECEIPT_IDS) {
            let Some(blob) = seal_mailbox_payload(
                &self.seed,
                &friend.pubkey,
                &mailbox,
                &MailboxPayload::Receipt {
                    msg_ids: ids.to_vec(),
                },
            ) else {
                return false;
            };
            if let Err(e) = rendezvous::chat_mailbox_put(&self.base_url, &mailbox, &blob).await {
                debug!("Chat mailbox: receipt failed: {e}");
                return false;
            }
        }
        true
    }

    /// Store a message a friend left for us, unless its direct copy (or an
    /// earlier round) already did. `false` when it could not be stored.
    async fn receive(
        &self,
        friend: &MailboxFriend,
        msg_id: [u8; 16],
        ttl_secs: u32,
        text: &str,
        now: i64,
    ) -> bool {
        let cleaned = crate::security::sanitize_chat_text(text);
        let own_ttl = self.settings.chat_disappear_secs_for(&friend.hash);
        let peer_ttl = (ttl_secs > 0).then(|| {
            ttl_secs.clamp(
                crate::types::CHAT_DISAPPEAR_PEER_MIN_SECS,
                crate::types::CHAT_DISAPPEAR_PEER_MAX_SECS,
            )
        });
        let db = self.db.clone();
        let hex = friend.hex.clone();
        let message = cleaned.clone();
        let stored = tokio::task::spawn_blocking(move || {
            db.insert_received_chat_once(&hex, &message, own_ttl, &msg_id, now, peer_ttl)
        })
        .await;
        match stored {
            Ok(Ok(Some((id, expiry)))) => {
                let _ = self.app_handle.emit(
                    "ember:chat-message",
                    serde_json::json!({
                        "user_hash": friend.hex,
                        "id": id,
                        "message": cleaned,
                        "direction": "received",
                        "timestamp": now,
                    }),
                );
                if let Some(item) = expiry {
                    emit_chat_expiry(&self.app_handle, &friend.hex, &[item]);
                }
                true
            }
            // Already shown: still cleared and receipted.
            Ok(Ok(None)) => true,
            Ok(Err(e)) => {
                warn!("Chat mailbox: could not store a collected message: {e}");
                false
            }
            Err(_) => false,
        }
    }

    /// The friend collected these: the rows are delivered, and their timers
    /// start, exactly as for a direct send.
    async fn confirm_delivered(&self, friend: &MailboxFriend, msg_ids: Vec<[u8; 16]>) {
        let db = self.db.clone();
        let hex = friend.hex.clone();
        let Ok(Ok((rows, expiries))) = tokio::task::spawn_blocking(move || {
            let rows = db.chat_mailbox_receipted(&hex, &msg_ids)?;
            db.set_chat_delivery_many(&rows, CHAT_DELIVERED)?;
            let expiries: HashMap<i64, i64> = db.chat_expiries(&hex, &rows)?.into_iter().collect();
            Ok::<_, anyhow::Error>((rows, expiries))
        })
        .await
        else {
            return;
        };
        for id in rows {
            let _ = self.app_handle.emit(
                "ember:chat-delivery",
                serde_json::json!({
                    "user_hash": friend.hex,
                    "id": id,
                    "delivery": "delivered",
                    "expires_at": expiries.get(&id),
                }),
            );
        }
    }
}
