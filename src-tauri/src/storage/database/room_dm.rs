//! Private messages between room members: one thread per person, keyed by
//! their member key, and its messages, the bodies sealed with the chat key as
//! friend chat's are. See `network::ember::room_dm` for the wire side.

use super::*;

const DM_CIPHERTEXT_PREFIX: &str = "EMBRDM1:";
const DM_AAD_DOMAIN: &[u8] = b"ember-room-dm-db-row-v1\0";

/// Someone's first messages wait for an answer this long before a new
/// request from the same room is refused: a few an hour, as room friend
/// requests are.
pub const DM_REQUESTS_PER_ROOM_HOUR: i64 = 5;
/// How long someone declined cannot ask again, and how long their decline
/// keeps us from writing to them.
pub const DM_DECLINE_MEMORY_SECS: i64 = 7 * 86_400;
/// Messages a request holds before the user answers it. Past this, more are
/// dropped unanswered: someone not yet accepted gets a few lines, not a disk.
pub const DM_REQUEST_MESSAGES_MAX: i64 = 20;
/// Messages kept from one member in an hour, accepted or not. Far past any
/// conversation, and what bounds how fast one member can grow the table.
pub const DM_STORED_PER_SENDER_HOUR: i64 = 120;
/// Messages a conversation keeps, newest first; older ones are pruned.
pub const DM_THREAD_MESSAGES_KEPT: i64 = 2_000;

/// Where a thread stands, from this side.
pub const DM_STATE_REQUEST: &str = "request";
pub const DM_STATE_OPEN: &str = "open";
pub const DM_STATE_DECLINED: &str = "declined";

/// A conversation with one member.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DmThread {
    pub member_pubkey: String,
    /// What they were last called in a room.
    pub name: String,
    /// [`DM_STATE_REQUEST`], [`DM_STATE_OPEN`] or [`DM_STATE_DECLINED`].
    pub state: String,
    /// What they said to us: `""`, `"accepted"` or `"declined"`. A decline
    /// reads as `""` once [`DM_DECLINE_MEMORY_SECS`] have passed.
    pub peer_state: String,
    /// The room last used to reach them.
    pub channel_id: String,
    pub updated_at: i64,
    pub unread: i64,
    /// The newest message, opened, for the list.
    pub last_text: String,
    pub last_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DmMessage {
    pub message_id: String,
    pub member_pubkey: String,
    /// `"in"` or `"out"`.
    pub direction: String,
    pub text: String,
    pub timestamp: i64,
    /// Ours: `"sending"`, `"delivered"` or `"failed"`. Theirs: `"received"`.
    pub status: String,
}

/// What became of a message that arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmIncoming {
    /// Kept. `request` while the thread waits on the user's answer, which
    /// nothing shows as unread.
    Stored { request: bool, new_thread: bool },
    /// Kept already: a resend. Answered again, nothing else.
    Duplicate,
    /// The user declined them, or takes no private messages: they are told.
    Declined,
    /// Too many new requests from that room this hour: dropped unanswered.
    Capped,
    /// Their request holds all it may until answered, or they have sent all
    /// that is kept from one member in an hour: dropped unanswered.
    Full,
}

/// One of ours due to go out again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmResend {
    pub message_id: String,
    pub member_pubkey: String,
    pub text: String,
    pub channel_id: String,
    pub attempts: i64,
}

impl Database {
    /// What a room's roster knows of `member`: their nickname, if they have
    /// been seen there and are not banned.
    pub fn dm_member_in_room(&self, channel_id: &str, member: &str) -> anyhow::Result<Option<String>> {
        let conn = self.conn.lock();
        Ok(conn
            .query_row(
                "SELECT nickname FROM channel_members
                 WHERE channel_id = lower(?1) AND member_pubkey = lower(?2) AND banned = 0 AND last_seen > 0",
                params![channel_id, member],
                |row| row.get(0),
            )
            .optional()?)
    }

    fn ensure_room_dm_locked(conn: &Connection) -> anyhow::Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS room_dm_threads (
                member_pubkey TEXT PRIMARY KEY,
                name TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL,
                peer_state TEXT NOT NULL DEFAULT '',
                channel_id TEXT NOT NULL DEFAULT '',
                request_channel TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                declined_at INTEGER NOT NULL DEFAULT 0,
                peer_answered_at INTEGER NOT NULL DEFAULT 0,
                unread INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_room_dm_threads_requests
                ON room_dm_threads(request_channel, created_at);
            CREATE TABLE IF NOT EXISTS room_dm_messages (
                message_id TEXT NOT NULL,
                member_pubkey TEXT NOT NULL,
                direction TEXT NOT NULL,
                body TEXT NOT NULL,
                ts INTEGER NOT NULL,
                status TEXT NOT NULL,
                channel_id TEXT NOT NULL DEFAULT '',
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER NOT NULL DEFAULT 0,
                give_up_at INTEGER NOT NULL DEFAULT 0,
                received_at INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (member_pubkey, direction, message_id)
            );
            CREATE INDEX IF NOT EXISTS idx_room_dm_messages_thread ON room_dm_messages(member_pubkey, ts);
            CREATE INDEX IF NOT EXISTS idx_room_dm_messages_received
                ON room_dm_messages(member_pubkey, received_at) WHERE direction = 'in';
            CREATE INDEX IF NOT EXISTS idx_room_dm_messages_sending
                ON room_dm_messages(next_attempt_at) WHERE direction = 'out' AND status = 'sending';",
        )?;
        Ok(())
    }

    fn dm_row_aad(message_id: &str, member: &str, direction: &str, timestamp: i64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(DM_AAD_DOMAIN.len() + 32 + 64 + 3 + 8 + 12);
        aad.extend_from_slice(DM_AAD_DOMAIN);
        for part in [message_id, member, direction] {
            aad.extend_from_slice(&(part.len() as u32).to_le_bytes());
            aad.extend_from_slice(part.as_bytes());
        }
        aad.extend_from_slice(&timestamp.to_le_bytes());
        aad
    }

    fn seal_dm_body(&self, message_id: &str, member: &str, direction: &str, timestamp: i64, text: &str) -> anyhow::Result<String> {
        let key = self.require_chat_key()?;
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let aad = Self::dm_row_aad(message_id, member, direction, timestamp);
        let sealed = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: text.as_bytes(), aad: &aad })
            .map_err(|_| anyhow::anyhow!("Failed to encrypt a private message"))?;
        let mut envelope = nonce.to_vec();
        envelope.extend_from_slice(&sealed);
        Ok(format!("{DM_CIPHERTEXT_PREFIX}{}", STANDARD_NO_PAD.encode(envelope)))
    }

    fn open_dm_body(key: Option<&[u8; 32]>, message_id: &str, member: &str, direction: &str, timestamp: i64, stored: &str) -> Option<String> {
        let key = key?;
        let envelope = STANDARD_NO_PAD.decode(stored.strip_prefix(DM_CIPHERTEXT_PREFIX)?).ok()?;
        if envelope.len() < 24 + 16 {
            return None;
        }
        let aad = Self::dm_row_aad(message_id, member, direction, timestamp);
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
        let plain = cipher
            .decrypt(XNonce::from_slice(&envelope[..24]), Payload { msg: &envelope[24..], aad: &aad })
            .ok()?;
        String::from_utf8(plain).ok()
    }

    /// Record a message of ours going out, opening the thread if this is the
    /// first, or answering a request by replying to it.
    #[allow(clippy::too_many_arguments)]
    pub fn dm_record_outgoing(
        &self,
        member: &str,
        name: &str,
        channel_id: &str,
        message_id: &str,
        text: &str,
        now: i64,
        next_attempt_at: i64,
        give_up_at: i64,
    ) -> anyhow::Result<()> {
        let member = member.to_ascii_lowercase();
        let body = self.seal_dm_body(message_id, &member, "out", now, text)?;
        let conn = self.conn.lock();
        Self::ensure_room_dm_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO room_dm_threads (member_pubkey, name, state, channel_id, created_at, updated_at)
             VALUES (?1, ?2, 'open', ?3, ?4, ?4)
             ON CONFLICT(member_pubkey) DO UPDATE SET
                state = 'open',
                name = CASE WHEN excluded.name = '' THEN name ELSE excluded.name END,
                channel_id = excluded.channel_id,
                updated_at = excluded.updated_at,
                declined_at = 0",
            params![member, name, channel_id, now],
        )?;
        tx.execute(
            "INSERT INTO room_dm_messages
                (message_id, member_pubkey, direction, body, ts, status, channel_id, attempts, next_attempt_at, give_up_at)
             VALUES (?1, ?2, 'out', ?3, ?4, 'sending', ?5, 1, ?6, ?7)",
            params![message_id, member, body, now, channel_id, next_attempt_at, give_up_at],
        )?;
        Self::prune_dm_thread_locked(&tx, &member)?;
        tx.commit()?;
        Ok(())
    }

    /// A message from `member` arrived through `channel_id`. Decides, in one
    /// write, whether it is kept and how the thread moves; the caller has
    /// already dropped an ignored sender.
    #[allow(clippy::too_many_arguments)]
    pub fn dm_record_incoming(
        &self,
        member: &str,
        name: &str,
        channel_id: &str,
        message_id: &str,
        text: &str,
        timestamp: i64,
        policy: &str,
        now: i64,
    ) -> anyhow::Result<DmIncoming> {
        let member = member.to_ascii_lowercase();
        let body = self.seal_dm_body(message_id, &member, "in", timestamp, text)?;
        let conn = self.conn.lock();
        Self::ensure_room_dm_locked(&conn)?;
        // "Off" takes nothing, not even a resend of what an open conversation
        // already holds: the answer is a decline either way.
        if policy == crate::types::ROOM_DM_POLICY_OFF {
            return Ok(DmIncoming::Declined);
        }
        let tx = conn.unchecked_transaction()?;
        let seen: bool = tx
            .query_row(
                "SELECT 1 FROM room_dm_messages WHERE member_pubkey = ?1 AND direction = 'in' AND message_id = ?2",
                params![member, message_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if seen {
            return Ok(DmIncoming::Duplicate);
        }
        let thread: Option<(String, i64)> = tx
            .query_row(
                "SELECT state, declined_at FROM room_dm_threads WHERE member_pubkey = ?1",
                params![member],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let declined_lately = |at: i64| now.saturating_sub(at) < DM_DECLINE_MEMORY_SECS;
        let stored_lately: i64 = tx.query_row(
            "SELECT COUNT(*) FROM room_dm_messages
             WHERE member_pubkey = ?1 AND direction = 'in' AND received_at > ?2",
            params![member, now - 3600],
            |row| row.get(0),
        )?;
        if stored_lately >= DM_STORED_PER_SENDER_HOUR {
            return Ok(DmIncoming::Full);
        }
        let (state, new_thread) = match thread.as_ref().map(|(s, at)| (s.as_str(), *at)) {
            Some((DM_STATE_DECLINED, at)) if declined_lately(at) => return Ok(DmIncoming::Declined),
            Some((DM_STATE_OPEN, _)) => (DM_STATE_OPEN, false),
            Some((DM_STATE_REQUEST, _)) => {
                let held: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM room_dm_messages WHERE member_pubkey = ?1 AND direction = 'in'",
                    params![member],
                    |row| row.get(0),
                )?;
                if held >= DM_REQUEST_MESSAGES_MAX {
                    return Ok(DmIncoming::Full);
                }
                (DM_STATE_REQUEST, false)
            }
            _ if policy == crate::types::ROOM_DM_POLICY_ANYONE => (DM_STATE_OPEN, true),
            _ => {
                let recent: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM room_dm_threads
                     WHERE request_channel = ?1 AND created_at > ?2 AND member_pubkey != ?3
                       AND state IN ('request', 'declined')",
                    params![channel_id, now - 3600, member],
                    |row| row.get(0),
                )?;
                if recent >= DM_REQUESTS_PER_ROOM_HOUR {
                    return Ok(DmIncoming::Capped);
                }
                (DM_STATE_REQUEST, true)
            }
        };
        if new_thread {
            // A thread declined long enough ago starts over, as a new one.
            tx.execute("DELETE FROM room_dm_messages WHERE member_pubkey = ?1", params![member])?;
            tx.execute(
                "INSERT INTO room_dm_threads
                    (member_pubkey, name, state, channel_id, request_channel, created_at, updated_at, unread)
                 VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?5, 1)
                 ON CONFLICT(member_pubkey) DO UPDATE SET
                    name = excluded.name, state = excluded.state, peer_state = '',
                    channel_id = excluded.channel_id, request_channel = excluded.request_channel,
                    created_at = excluded.created_at, updated_at = excluded.updated_at,
                    declined_at = 0, unread = 1",
                params![member, name, state, channel_id, now],
            )?;
        } else {
            // Writing to us is taking our messages, as of the message's date:
            // an answer dated before it cannot take that back, and it cannot
            // take back an answer dated after it.
            tx.execute(
                "UPDATE room_dm_threads SET
                    name = CASE WHEN ?2 = '' THEN name ELSE ?2 END,
                    peer_state = CASE WHEN state = 'open' AND ?5 >= peer_answered_at THEN 'accepted' ELSE peer_state END,
                    peer_answered_at = CASE WHEN state = 'open' AND ?5 >= peer_answered_at THEN ?5 ELSE peer_answered_at END,
                    channel_id = ?3, updated_at = ?4, unread = unread + 1
                 WHERE member_pubkey = ?1",
                params![member, name, channel_id, now, timestamp],
            )?;
        }
        tx.execute(
            "INSERT INTO room_dm_messages (message_id, member_pubkey, direction, body, ts, status, channel_id, received_at)
             VALUES (?1, ?2, 'in', ?3, ?4, 'received', ?5, ?6)",
            params![message_id, member, body, timestamp, channel_id, now],
        )?;
        Self::prune_dm_thread_locked(&tx, &member)?;
        tx.commit()?;
        Ok(DmIncoming::Stored { request: state == DM_STATE_REQUEST, new_thread })
    }

    /// Keep a conversation to its newest [`DM_THREAD_MESSAGES_KEPT`] messages.
    fn prune_dm_thread_locked(conn: &Connection, member: &str) -> anyhow::Result<()> {
        conn.execute(
            "DELETE FROM room_dm_messages WHERE member_pubkey = ?1 AND rowid NOT IN (
                 SELECT rowid FROM room_dm_messages WHERE member_pubkey = ?1
                 ORDER BY ts DESC, rowid DESC LIMIT ?2)",
            params![member, DM_THREAD_MESSAGES_KEPT],
        )?;
        Ok(())
    }

    /// The user's answer to a request. Declining forgets what they sent.
    /// Returns whether there was a request to answer.
    pub fn dm_answer_request(&self, member: &str, accept: bool, now: i64) -> anyhow::Result<bool> {
        let member = member.to_ascii_lowercase();
        let conn = self.conn.lock();
        Self::ensure_room_dm_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        let changed = if accept {
            tx.execute(
                "UPDATE room_dm_threads SET state = 'open', updated_at = ?2
                 WHERE member_pubkey = ?1 AND state = 'request'",
                params![member, now],
            )?
        } else {
            let n = tx.execute(
                "UPDATE room_dm_threads SET state = 'declined', declined_at = ?2, updated_at = ?2, unread = 0
                 WHERE member_pubkey = ?1 AND state = 'request'",
                params![member, now],
            )?;
            if n > 0 {
                tx.execute("DELETE FROM room_dm_messages WHERE member_pubkey = ?1", params![member])?;
            }
            n
        };
        tx.commit()?;
        Ok(changed > 0)
    }

    /// They told us whether they take our messages, in a frame dated
    /// `answered_at`. Only in a conversation open on our side, which is one
    /// we wrote in or accepted: an answer to anything else is nobody's to
    /// record. And only if newer than the answer held, so a replayed old one
    /// cannot undo a later one. A decline stays stored once it has run out,
    /// so a new one after it is told apart from a repeat by its age. Returns
    /// whether the answer was new, and the messages of ours a decline
    /// stopped.
    pub fn dm_note_peer_answer(&self, member: &str, accepted: bool, answered_at: i64) -> anyhow::Result<(bool, Vec<String>)> {
        let member = member.to_ascii_lowercase();
        let conn = self.conn.lock();
        Self::ensure_room_dm_locked(&conn)?;
        let answer = if accepted { "accepted" } else { "declined" };
        let tx = conn.unchecked_transaction()?;
        let held: Option<(String, i64)> = tx
            .query_row(
                "SELECT peer_state, peer_answered_at FROM room_dm_threads WHERE member_pubkey = ?1 AND state = 'open'",
                params![member],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((was, was_at)) = held.filter(|(_, at)| *at < answered_at) else {
            return Ok((false, Vec::new()));
        };
        tx.execute(
            "UPDATE room_dm_threads SET peer_state = ?2, peer_answered_at = ?3 WHERE member_pubkey = ?1",
            params![member, answer, answered_at],
        )?;
        // A newer copy of the answer in force only dates it; nothing of ours
        // is stopped again.
        let lapsed = was == "declined" && answered_at.saturating_sub(was_at) >= DM_DECLINE_MEMORY_SECS;
        let moved = was != answer || lapsed;
        let mut stopped = Vec::new();
        if !accepted && moved {
            // Nothing more of ours will be read: stop sending it.
            {
                let mut stmt = tx.prepare(
                    "SELECT message_id FROM room_dm_messages
                     WHERE member_pubkey = ?1 AND direction = 'out' AND status = 'sending'",
                )?;
                stopped = stmt
                    .query_map(params![member], |row| row.get(0))?
                    .collect::<Result<Vec<String>, _>>()?;
            }
            tx.execute(
                "UPDATE room_dm_messages SET status = 'failed', next_attempt_at = 0
                 WHERE member_pubkey = ?1 AND direction = 'out' AND status = 'sending'",
                params![member],
            )?;
        }
        tx.commit()?;
        Ok((moved, stopped))
    }

    /// Whether the user's refusal of `member` holds at `now`: declined, and
    /// not so long ago that it ran out. Writing to them since lifts it.
    pub fn dm_declines(&self, member: &str, now: i64) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::ensure_room_dm_locked(&conn)?;
        Ok(conn
            .query_row(
                "SELECT 1 FROM room_dm_threads WHERE member_pubkey = ?1 AND state = 'declined' AND declined_at > ?2",
                params![member.to_ascii_lowercase(), now - DM_DECLINE_MEMORY_SECS],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Stop every message of ours still being sent: private messages were
    /// turned off. `(member, message_id)` of each.
    pub fn dm_fail_all_sending(&self) -> anyhow::Result<Vec<(String, String)>> {
        let conn = self.conn.lock();
        Self::ensure_room_dm_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        let stopped = {
            let mut stmt = tx.prepare(
                "SELECT member_pubkey, message_id FROM room_dm_messages
                 WHERE direction = 'out' AND status = 'sending'",
            )?;
            let rows = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<Result<Vec<(String, String)>, _>>()?;
            rows
        };
        tx.execute(
            "UPDATE room_dm_messages SET status = 'failed', next_attempt_at = 0
             WHERE direction = 'out' AND status = 'sending'",
            [],
        )?;
        tx.commit()?;
        Ok(stopped)
    }

    /// Whether one of ours is still being sent: not delivered, and not
    /// stopped by their decline, by private messages being turned off, or by
    /// running out of time.
    pub fn dm_still_sending(&self, member: &str, message_id: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::ensure_room_dm_locked(&conn)?;
        Ok(conn
            .query_row(
                "SELECT 1 FROM room_dm_messages
                 WHERE member_pubkey = ?1 AND direction = 'out' AND message_id = ?2 AND status = 'sending'",
                params![member.to_ascii_lowercase(), message_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// A receipt for one of ours. Returns whether it moved it to delivered.
    pub fn dm_mark_delivered(&self, member: &str, message_id: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::ensure_room_dm_locked(&conn)?;
        Ok(conn.execute(
            "UPDATE room_dm_messages SET status = 'delivered', next_attempt_at = 0
             WHERE member_pubkey = ?1 AND direction = 'out' AND message_id = ?2 AND status != 'delivered'",
            params![member.to_ascii_lowercase(), message_id],
        )? > 0)
    }

    /// Ours still unanswered whose next attempt is due at `now`, opened. One
    /// that does not open (the chat key changed under it) is marked failed,
    /// so it cannot hold a place in every later batch.
    pub fn dm_due_resends(&self, now: i64) -> anyhow::Result<Vec<DmResend>> {
        let key = self.chat_key.as_deref();
        let conn = self.conn.lock();
        Self::ensure_room_dm_locked(&conn)?;
        let mut stmt = conn.prepare(
            "SELECT message_id, member_pubkey, body, ts, channel_id, attempts FROM room_dm_messages
             WHERE direction = 'out' AND status = 'sending' AND next_attempt_at > 0
               AND next_attempt_at <= ?1 AND give_up_at > ?1
             ORDER BY next_attempt_at LIMIT 32",
        )?;
        let rows = stmt
            .query_map(params![now], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        let mut due = Vec::with_capacity(rows.len());
        for (message_id, member, body, ts, channel_id, attempts) in rows {
            match Self::open_dm_body(key, &message_id, &member, "out", ts, &body) {
                Some(text) => due.push(DmResend { message_id, member_pubkey: member, text, channel_id, attempts }),
                None => {
                    conn.execute(
                        "UPDATE room_dm_messages SET status = 'failed', next_attempt_at = 0
                         WHERE member_pubkey = ?1 AND direction = 'out' AND message_id = ?2",
                        params![member, message_id],
                    )?;
                }
            }
        }
        Ok(due)
    }

    /// One more attempt went out; the next is due at `next_attempt_at`.
    pub fn dm_note_attempt(&self, member: &str, message_id: &str, channel_id: &str, next_attempt_at: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_room_dm_locked(&conn)?;
        conn.execute(
            "UPDATE room_dm_messages SET attempts = attempts + 1, next_attempt_at = ?3, channel_id = ?4
             WHERE member_pubkey = ?1 AND direction = 'out' AND message_id = ?2 AND status = 'sending'",
            params![member, message_id, next_attempt_at, channel_id],
        )?;
        Ok(())
    }

    /// Ours that went unanswered for as long as they are tried, now marked
    /// failed: `(member, message_id)`.
    pub fn dm_fail_unanswered(&self, now: i64) -> anyhow::Result<Vec<(String, String)>> {
        let conn = self.conn.lock();
        Self::ensure_room_dm_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        let failed = {
            let mut stmt = tx.prepare(
                "SELECT member_pubkey, message_id FROM room_dm_messages
                 WHERE direction = 'out' AND status = 'sending' AND give_up_at <= ?1",
            )?;
            let rows = stmt
                .query_map(params![now], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<Result<Vec<(String, String)>, _>>()?;
            rows
        };
        tx.execute(
            "UPDATE room_dm_messages SET status = 'failed', next_attempt_at = 0
             WHERE direction = 'out' AND status = 'sending' AND give_up_at <= ?1",
            params![now],
        )?;
        tx.commit()?;
        Ok(failed)
    }

    /// Send a failed message of ours again, from now.
    pub fn dm_retry(&self, member: &str, message_id: &str, next_attempt_at: i64, give_up_at: i64) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::ensure_room_dm_locked(&conn)?;
        Ok(conn.execute(
            "UPDATE room_dm_messages SET status = 'sending', attempts = 0, next_attempt_at = ?3, give_up_at = ?4
             WHERE member_pubkey = ?1 AND direction = 'out' AND message_id = ?2 AND status = 'failed'",
            params![member.to_ascii_lowercase(), message_id, next_attempt_at, give_up_at],
        )? > 0)
    }

    /// One conversation, as it stands at `now`.
    pub fn dm_thread(&self, member: &str, now: i64) -> anyhow::Result<Option<DmThread>> {
        let member = member.to_ascii_lowercase();
        Ok(self.dm_threads_where(Some(&member), now)?.into_iter().next())
    }

    /// Every conversation, newest first, as they stand at `now`.
    pub fn dm_threads(&self, now: i64) -> anyhow::Result<Vec<DmThread>> {
        self.dm_threads_where(None, now)
    }

    fn dm_threads_where(&self, member: Option<&str>, now: i64) -> anyhow::Result<Vec<DmThread>> {
        let key = self.chat_key.as_deref();
        let declines_from = now - DM_DECLINE_MEMORY_SECS;
        let conn = self.conn.lock();
        Self::ensure_room_dm_locked(&conn)?;
        // One lookup by key, or all: kept as two statements so the first can
        // use the primary key, which `?1 IS NULL OR` would hide from it.
        let select = "SELECT t.member_pubkey, t.name, t.state,
                    CASE WHEN t.peer_state = 'declined' AND t.peer_answered_at <= ?1 THEN '' ELSE t.peer_state END,
                    t.channel_id, t.updated_at, t.unread,
                    m.message_id, m.direction, m.ts, m.body
             FROM room_dm_threads t
             LEFT JOIN room_dm_messages m ON m.rowid = (
                 SELECT rowid FROM room_dm_messages WHERE member_pubkey = t.member_pubkey
                 ORDER BY ts DESC, rowid DESC LIMIT 1)";
        let sql = match member {
            Some(_) => format!("{select} WHERE t.member_pubkey = ?2"),
            None => format!("{select} ORDER BY t.updated_at DESC"),
        };
        let mut stmt = conn.prepare(&sql)?;
        let binds: Vec<rusqlite::types::Value> = match member {
            Some(member) => vec![declines_from.into(), member.to_string().into()],
            None => vec![declines_from.into()],
        };
        let rows = stmt
            .query_map(rusqlite::params_from_iter(binds), |row| {
                let last: Option<(String, String, i64, String)> = match row.get::<_, Option<String>>(7)? {
                    Some(id) => Some((id, row.get(8)?, row.get(9)?, row.get(10)?)),
                    None => None,
                };
                Ok((
                    DmThread {
                        member_pubkey: row.get(0)?,
                        name: row.get(1)?,
                        state: row.get(2)?,
                        peer_state: row.get(3)?,
                        channel_id: row.get(4)?,
                        updated_at: row.get(5)?,
                        unread: row.get(6)?,
                        last_text: String::new(),
                        last_at: 0,
                    },
                    last,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            .map(|(mut thread, last)| {
                if let Some((id, direction, ts, body)) = last {
                    thread.last_text = Self::open_dm_body(key, &id, &thread.member_pubkey, &direction, ts, &body)
                        .unwrap_or_default();
                    thread.last_at = ts;
                }
                thread
            })
            .collect())
    }

    /// A conversation's messages, oldest first: the newest `limit` before
    /// `before` (Unix seconds), or the newest of all.
    pub fn dm_messages(&self, member: &str, limit: usize, before: Option<i64>) -> anyhow::Result<Vec<DmMessage>> {
        let member = member.to_ascii_lowercase();
        let key = self.chat_key.as_deref();
        let conn = self.conn.lock();
        Self::ensure_room_dm_locked(&conn)?;
        let mut stmt = conn.prepare(
            "SELECT message_id, direction, ts, status, body FROM room_dm_messages
             WHERE member_pubkey = ?1 AND (?2 IS NULL OR ts < ?2)
             ORDER BY ts DESC, rowid DESC LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![member, before, limit as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut out: Vec<DmMessage> = rows
            .into_iter()
            .filter_map(|(message_id, direction, timestamp, status, body)| {
                let text = Self::open_dm_body(key, &message_id, &member, &direction, timestamp, &body)?;
                Some(DmMessage { message_id, member_pubkey: member.clone(), direction, text, timestamp, status })
            })
            .collect();
        out.reverse();
        Ok(out)
    }

    pub fn dm_mark_read(&self, member: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_room_dm_locked(&conn)?;
        conn.execute(
            "UPDATE room_dm_threads SET unread = 0 WHERE member_pubkey = ?1",
            params![member.to_ascii_lowercase()],
        )?;
        Ok(())
    }

    /// Delete a conversation and every message in it. A declined thread is
    /// kept as a bare row, so the refusal still holds, and deleting a request
    /// declines it: deleting must not be a way to let its sender ask again at
    /// once, nor take it out of its room's request count.
    pub fn dm_delete_thread(&self, member: &str, now: i64) -> anyhow::Result<()> {
        let member = member.to_ascii_lowercase();
        let conn = self.conn.lock();
        Self::ensure_room_dm_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM room_dm_messages WHERE member_pubkey = ?1", params![member])?;
        tx.execute(
            "UPDATE room_dm_threads SET state = 'declined', declined_at = ?2, unread = 0
             WHERE member_pubkey = ?1 AND state = 'request'",
            params![member, now],
        )?;
        tx.execute(
            "DELETE FROM room_dm_threads WHERE member_pubkey = ?1 AND state != 'declined'",
            params![member],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Remove a request and what it holds as if it never came, for a sender
    /// being ignored. No refusal is kept: the ignore list already drops them,
    /// and a refusal would answer them with a decline once they are no longer
    /// ignored. Anything but a request is left alone. Returns whether there
    /// was one.
    pub fn dm_forget_request(&self, member: &str) -> anyhow::Result<bool> {
        let member = member.to_ascii_lowercase();
        let conn = self.conn.lock();
        Self::ensure_room_dm_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        let removed = tx.execute(
            "DELETE FROM room_dm_threads WHERE member_pubkey = ?1 AND state = 'request'",
            params![member],
        )?;
        if removed > 0 {
            tx.execute("DELETE FROM room_dm_messages WHERE member_pubkey = ?1", params![member])?;
        }
        tx.commit()?;
        Ok(removed > 0)
    }

    /// Forget declined conversations whose refusal has run out: nothing is
    /// left of them but the row that held it.
    pub fn dm_prune_declined(&self, now: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_room_dm_locked(&conn)?;
        conn.execute(
            "DELETE FROM room_dm_threads WHERE state = 'declined' AND declined_at <= ?1
               AND NOT EXISTS (SELECT 1 FROM room_dm_messages m WHERE m.member_pubkey = room_dm_threads.member_pubkey)",
            params![now - DM_DECLINE_MEMORY_SECS],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ROOM_DM_POLICY_ANYONE, ROOM_DM_POLICY_ASK, ROOM_DM_POLICY_OFF};

    fn db(tag: &str) -> (Database, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("ember-room-dm-{tag}-{}-{}.db", std::process::id(), rand::random::<u64>()));
        let _ = std::fs::remove_file(&path);
        (Database::open_at(&path).expect("open db"), path)
    }

    fn drop_db(db: Database, path: std::path::PathBuf) {
        drop(db);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    const ANN: &str = "aa11";
    const ROOM: &str = "c0ffee";

    #[test]
    fn a_first_message_waits_as_a_request_and_accepting_opens_the_thread() {
        let (db, path) = db("request");
        let got = db.dm_record_incoming(ANN, "Ann", ROOM, "m1", "hi there", 100, ROOM_DM_POLICY_ASK, 100).unwrap();
        assert_eq!(got, DmIncoming::Stored { request: true, new_thread: true });
        assert_eq!(db.dm_record_incoming(ANN, "Ann", ROOM, "m1", "hi there", 100, ROOM_DM_POLICY_ASK, 101).unwrap(), DmIncoming::Duplicate);
        let thread = db.dm_thread(ANN, 400).unwrap().unwrap();
        assert_eq!((thread.state.as_str(), thread.last_text.as_str()), (DM_STATE_REQUEST, "hi there"));

        assert!(db.dm_answer_request(ANN, true, 102).unwrap());
        assert_eq!(db.dm_thread(ANN, 400).unwrap().unwrap().state, DM_STATE_OPEN);
        let next = db.dm_record_incoming(ANN, "Ann", ROOM, "m2", "thanks", 103, ROOM_DM_POLICY_ASK, 103).unwrap();
        assert_eq!(next, DmIncoming::Stored { request: false, new_thread: false });
        let texts: Vec<String> = db.dm_messages(ANN, 10, None).unwrap().into_iter().map(|m| m.text).collect();
        assert_eq!(texts, vec!["hi there", "thanks"]);
        drop_db(db, path);
    }

    #[test]
    fn a_declined_sender_is_refused_for_a_while_and_what_they_sent_is_gone() {
        let (db, path) = db("decline");
        db.dm_record_incoming(ANN, "Ann", ROOM, "m1", "buy now", 100, ROOM_DM_POLICY_ASK, 100).unwrap();
        assert!(db.dm_answer_request(ANN, false, 110).unwrap());
        assert!(db.dm_messages(ANN, 10, None).unwrap().is_empty());
        assert_eq!(db.dm_record_incoming(ANN, "Ann", ROOM, "m2", "again", 200, ROOM_DM_POLICY_ASK, 200).unwrap(), DmIncoming::Declined);
        db.dm_delete_thread(ANN, 250).unwrap();
        assert_eq!(
            db.dm_record_incoming(ANN, "Ann", ROOM, "m3", "and again", 300, ROOM_DM_POLICY_ASK, 300).unwrap(),
            DmIncoming::Declined,
            "deleting the conversation keeps the refusal"
        );
        let later = 110 + DM_DECLINE_MEMORY_SECS;
        assert_eq!(
            db.dm_record_incoming(ANN, "Ann", ROOM, "m4", "hello", later, ROOM_DM_POLICY_ASK, later).unwrap(),
            DmIncoming::Stored { request: true, new_thread: true }
        );
        drop_db(db, path);
    }

    #[test]
    fn the_policy_decides_what_a_stranger_gets_and_requests_are_capped_per_room() {
        let (db, path) = db("policy");
        assert_eq!(db.dm_record_incoming("b1", "", ROOM, "m", "x", 1, ROOM_DM_POLICY_OFF, 1).unwrap(), DmIncoming::Declined);
        db.dm_record_outgoing("b3", "", ROOM, "o", "hi", 1, 2, 3).unwrap();
        assert_eq!(
            db.dm_record_incoming("b3", "", ROOM, "m", "x", 1, ROOM_DM_POLICY_OFF, 1).unwrap(),
            DmIncoming::Declined,
            "off takes nothing, not even from an open conversation"
        );
        assert_eq!(
            db.dm_record_incoming("b2", "", ROOM, "m", "x", 1, ROOM_DM_POLICY_ANYONE, 1).unwrap(),
            DmIncoming::Stored { request: false, new_thread: true }
        );
        for i in 0..DM_REQUESTS_PER_ROOM_HOUR {
            let got = db.dm_record_incoming(&format!("c{i}"), "", ROOM, "m", "x", 10, ROOM_DM_POLICY_ASK, 10).unwrap();
            assert!(matches!(got, DmIncoming::Stored { request: true, .. }));
        }
        assert_eq!(db.dm_record_incoming("cz", "", ROOM, "m", "x", 11, ROOM_DM_POLICY_ASK, 11).unwrap(), DmIncoming::Capped);
        assert!(matches!(
            db.dm_record_incoming("cz", "", "other", "m", "x", 11, ROOM_DM_POLICY_ASK, 11).unwrap(),
            DmIncoming::Stored { .. }
        ));
        assert!(matches!(
            db.dm_record_incoming("c0", "", ROOM, "m2", "y", 12, ROOM_DM_POLICY_ASK, 12).unwrap(),
            DmIncoming::Stored { request: true, new_thread: false }
        ), "a request already waiting keeps coming");
        drop_db(db, path);
    }

    #[test]
    fn ours_are_resent_until_a_receipt_and_then_fail_when_time_is_up() {
        let (db, path) = db("resend");
        db.dm_record_outgoing(ANN, "Ann", ROOM, "o1", "ping", 100, 160, 1_300).unwrap();
        db.dm_record_outgoing(ANN, "Ann", ROOM, "o2", "pong", 100, 160, 1_300).unwrap();
        assert!(db.dm_due_resends(150).unwrap().is_empty());
        let due = db.dm_due_resends(160).unwrap();
        assert_eq!(due.iter().map(|r| r.text.as_str()).collect::<Vec<_>>(), vec!["ping", "pong"]);
        db.dm_note_attempt(ANN, "o1", ROOM, 280).unwrap();
        assert!(db.dm_mark_delivered(ANN, "o2").unwrap());
        assert!(!db.dm_mark_delivered(ANN, "o2").unwrap(), "once");
        assert_eq!(db.dm_due_resends(200).unwrap().len(), 0);
        assert_eq!(db.dm_fail_unanswered(1_300).unwrap(), vec![(ANN.to_string(), "o1".to_string())]);
        let status: Vec<String> = db.dm_messages(ANN, 10, None).unwrap().into_iter().map(|m| m.status).collect();
        assert_eq!(status, vec!["failed", "delivered"]);
        assert!(db.dm_retry(ANN, "o1", 1_400, 2_600).unwrap());
        assert_eq!(db.dm_due_resends(1_400).unwrap().len(), 1);
        drop_db(db, path);
    }

    #[test]
    fn their_decline_stops_our_resends_and_bodies_are_sealed() {
        let (db, path) = db("peer-decline");
        db.dm_record_outgoing(ANN, "Ann", ROOM, "o1", "secret words", 100, 160, 1_300).unwrap();
        let stored: String = db
            .conn
            .lock()
            .query_row("SELECT body FROM room_dm_messages WHERE message_id = 'o1'", [], |r| r.get(0))
            .unwrap();
        assert!(stored.starts_with(DM_CIPHERTEXT_PREFIX) && !stored.contains("secret"));
        assert_eq!(db.dm_note_peer_answer(ANN, false, 120).unwrap(), (true, vec!["o1".to_string()]));
        assert!(db.dm_due_resends(200).unwrap().is_empty());
        assert_eq!(db.dm_thread(ANN, 400).unwrap().unwrap().peer_state, "declined");
        assert_eq!(
            db.dm_thread(ANN, 120 + DM_DECLINE_MEMORY_SECS).unwrap().unwrap().peer_state,
            "",
            "their decline runs out as ours does"
        );
        db.dm_record_incoming(ANN, "Ann", ROOM, "m1", "changed my mind", 300, ROOM_DM_POLICY_ASK, 300).unwrap();
        assert_eq!(db.dm_thread(ANN, 400).unwrap().unwrap().peer_state, "accepted", "writing to us takes ours");
        drop_db(db, path);
    }

    #[test]
    fn a_replayed_old_answer_cannot_undo_a_later_one() {
        let (db, path) = db("replay");
        db.dm_record_outgoing(ANN, "Ann", ROOM, "o1", "hi", 100, 160, 1_300).unwrap();
        assert!(db.dm_note_peer_answer(ANN, true, 200).unwrap().0);
        assert_eq!(db.dm_note_peer_answer(ANN, false, 150).unwrap(), (false, vec![]), "older than the accept");
        assert_eq!(db.dm_thread(ANN, 210).unwrap().unwrap().peer_state, "accepted");
        assert!(db.dm_note_peer_answer(ANN, false, 250).unwrap().0, "a newer decline counts");
        drop_db(db, path);
    }

    #[test]
    fn a_decline_after_one_ran_out_counts_again_and_a_repeat_stops_nothing() {
        let (db, path) = db("decline-again");
        db.dm_record_outgoing(ANN, "Ann", ROOM, "o1", "hi", 100, 160, 1_300).unwrap();
        assert_eq!(db.dm_note_peer_answer(ANN, false, 120).unwrap(), (true, vec!["o1".to_string()]));
        assert_eq!(db.dm_note_peer_answer(ANN, false, 120).unwrap(), (false, vec![]), "a replay");

        let day8 = 120 + 8 * 86_400;
        assert_eq!(db.dm_thread(ANN, day8).unwrap().unwrap().peer_state, "", "the first has run out");
        db.dm_record_outgoing(ANN, "Ann", ROOM, "o2", "hello again", day8, day8 + 120, day8 + 1_200).unwrap();
        db.dm_record_outgoing(ANN, "Ann", ROOM, "o3", "still there?", day8, day8 + 120, day8 + 1_200).unwrap();
        db.dm_note_attempt(ANN, "o3", ROOM, day8 + 120).unwrap();
        let (moved, mut stopped) = db.dm_note_peer_answer(ANN, false, day8 + 10).unwrap();
        stopped.sort();
        assert_eq!((moved, stopped), (true, vec!["o2".to_string(), "o3".to_string()]));
        assert_eq!(db.dm_thread(ANN, day8 + 20).unwrap().unwrap().peer_state, "declined");
        assert!(db.dm_due_resends(day8 + 200).unwrap().is_empty());

        assert!(db.dm_retry(ANN, "o2", day8 + 30, day8 + 1_230).unwrap());
        assert_eq!(
            db.dm_note_peer_answer(ANN, false, day8 + 40).unwrap(),
            (false, vec![]),
            "a newer copy of the decline in force stops nothing again"
        );
        assert_eq!(db.dm_thread(ANN, day8 + 10 + DM_DECLINE_MEMORY_SECS).unwrap().unwrap().peer_state, "declined", "but dates it");
        drop_db(db, path);
    }

    #[test]
    fn a_message_from_them_dates_their_accept_so_an_older_decline_cannot_undo_it() {
        let (db, path) = db("implicit-accept");
        db.dm_record_outgoing(ANN, "Ann", ROOM, "o1", "hi", 100, 160, 1_300).unwrap();
        db.dm_record_incoming(ANN, "Ann", ROOM, "m1", "hey you", 300, ROOM_DM_POLICY_ASK, 300).unwrap();
        assert_eq!(db.dm_note_peer_answer(ANN, false, 250).unwrap(), (false, vec![]), "sent before their message");
        assert_eq!(db.dm_thread(ANN, 310).unwrap().unwrap().peer_state, "accepted");
        assert_eq!(db.dm_note_peer_answer(ANN, false, 350).unwrap(), (true, vec!["o1".to_string()]), "sent after it");
        drop_db(db, path);
    }

    #[test]
    fn a_message_dated_before_their_decline_does_not_undo_it() {
        let (db, path) = db("late-message");
        db.dm_record_outgoing(ANN, "Ann", ROOM, "o1", "hi", 100, 160, 1_300).unwrap();
        db.dm_record_incoming(ANN, "Ann", ROOM, "m1", "hey", 200, ROOM_DM_POLICY_ASK, 200).unwrap();
        assert!(db.dm_note_peer_answer(ANN, false, 300).unwrap().0);
        db.dm_record_incoming(ANN, "Ann", ROOM, "m2", "sent earlier", 250, ROOM_DM_POLICY_ASK, 310).unwrap();
        assert_eq!(db.dm_thread(ANN, 320).unwrap().unwrap().peer_state, "declined");
        db.dm_record_incoming(ANN, "Ann", ROOM, "m3", "sent later", 330, ROOM_DM_POLICY_ASK, 330).unwrap();
        assert_eq!(db.dm_thread(ANN, 340).unwrap().unwrap().peer_state, "accepted");
        drop_db(db, path);
    }

    #[test]
    fn a_message_is_sending_until_delivered_stopped_or_given_up() {
        let (db, path) = db("still-sending");
        db.dm_record_outgoing(ANN, "Ann", ROOM, "o1", "one", 100, 160, 1_300).unwrap();
        db.dm_record_outgoing(ANN, "Ann", ROOM, "o2", "two", 100, 160, 1_300).unwrap();
        assert!(db.dm_still_sending(&ANN.to_uppercase(), "o1").unwrap());
        assert!(db.dm_mark_delivered(ANN, "o1").unwrap());
        assert!(!db.dm_still_sending(ANN, "o1").unwrap(), "delivered");
        db.dm_note_peer_answer(ANN, false, 120).unwrap();
        assert!(!db.dm_still_sending(ANN, "o2").unwrap(), "stopped by their decline");
        assert!(!db.dm_still_sending(ANN, "nope").unwrap());
        drop_db(db, path);
    }

    #[test]
    fn our_refusal_holds_until_it_runs_out_or_we_write() {
        let (db, path) = db("refusal");
        assert!(!db.dm_declines(ANN, 100).unwrap(), "no conversation");
        db.dm_record_incoming(ANN, "Ann", ROOM, "m1", "psst", 100, ROOM_DM_POLICY_ASK, 100).unwrap();
        assert!(!db.dm_declines(ANN, 101).unwrap(), "a request waiting");
        db.dm_answer_request(ANN, false, 110).unwrap();
        assert!(db.dm_declines(&ANN.to_uppercase(), 111).unwrap());
        assert!(!db.dm_declines(ANN, 110 + DM_DECLINE_MEMORY_SECS).unwrap(), "run out");
        db.dm_record_outgoing(ANN, "Ann", ROOM, "o1", "sorry, hi", 120, 240, 1_320).unwrap();
        assert!(!db.dm_declines(ANN, 121).unwrap(), "we wrote to them");
        drop_db(db, path);
    }

    /// Someone not yet accepted gets a few lines, and nobody gets more than
    /// a conversation's worth an hour.
    #[test]
    fn a_request_and_an_hour_of_messages_hold_only_so_much() {
        let (db, path) = db("caps");
        for i in 0..DM_REQUEST_MESSAGES_MAX {
            let got = db.dm_record_incoming(ANN, "Ann", ROOM, &format!("r{i}"), "hi", 10, ROOM_DM_POLICY_ASK, 10).unwrap();
            assert!(matches!(got, DmIncoming::Stored { request: true, .. }), "{i}: {got:?}");
        }
        assert_eq!(db.dm_record_incoming(ANN, "Ann", ROOM, "rx", "hi", 10, ROOM_DM_POLICY_ASK, 10).unwrap(), DmIncoming::Full);

        let bob = "bb22";
        for i in 0..DM_STORED_PER_SENDER_HOUR {
            let got = db.dm_record_incoming(bob, "Bob", ROOM, &format!("o{i}"), "yo", 10, ROOM_DM_POLICY_ANYONE, 10).unwrap();
            assert!(matches!(got, DmIncoming::Stored { request: false, .. }), "{i}: {got:?}");
        }
        assert_eq!(db.dm_record_incoming(bob, "Bob", ROOM, "ox", "yo", 10, ROOM_DM_POLICY_ANYONE, 10).unwrap(), DmIncoming::Full);
        let an_hour_on = 10 + 3_601;
        assert!(matches!(
            db.dm_record_incoming(bob, "Bob", ROOM, "oy", "yo", an_hour_on, ROOM_DM_POLICY_ANYONE, an_hour_on).unwrap(),
            DmIncoming::Stored { .. }
        ));
        drop_db(db, path);
    }

    #[test]
    fn off_declines_a_resend_too_and_an_answer_counts_only_where_we_wrote() {
        let (db, path) = db("answers");
        db.dm_record_outgoing(ANN, "Ann", ROOM, "o1", "hi", 1, 2, 3).unwrap();
        db.dm_record_incoming(ANN, "Ann", ROOM, "m1", "hey", 5, ROOM_DM_POLICY_ASK, 5).unwrap();
        assert_eq!(db.dm_record_incoming(ANN, "Ann", ROOM, "m1", "hey", 5, ROOM_DM_POLICY_OFF, 6).unwrap(), DmIncoming::Declined);

        let bob = "bb22";
        db.dm_record_incoming(bob, "Bob", ROOM, "m1", "hello?", 5, ROOM_DM_POLICY_ASK, 5).unwrap();
        assert_eq!(db.dm_note_peer_answer(bob, false, 6).unwrap(), (false, vec![]), "a request of theirs is not ours to be answered");
        assert_eq!(db.dm_thread(bob, 7).unwrap().unwrap().peer_state, "");
        drop_db(db, path);
    }

    /// Deleting a request declines it: its sender cannot ask again at once,
    /// and it still counts against its room's requests.
    #[test]
    fn deleting_a_request_declines_it_and_an_open_one_starts_over() {
        let (db, path) = db("delete");
        db.dm_record_incoming(ANN, "Ann", ROOM, "m1", "psst", 5, ROOM_DM_POLICY_ASK, 5).unwrap();
        db.dm_delete_thread(ANN, 6).unwrap();
        assert_eq!(db.dm_thread(ANN, 7).unwrap().unwrap().state, DM_STATE_DECLINED);
        assert_eq!(db.dm_record_incoming(ANN, "Ann", ROOM, "m2", "psst", 8, ROOM_DM_POLICY_ASK, 8).unwrap(), DmIncoming::Declined);

        let bob = "bb22";
        db.dm_record_outgoing(bob, "Bob", ROOM, "o1", "hi", 5, 6, 7).unwrap();
        db.dm_delete_thread(bob, 6).unwrap();
        assert!(db.dm_thread(bob, 7).unwrap().is_none());
        assert!(matches!(
            db.dm_record_incoming(bob, "Bob", ROOM, "m1", "hi?", 8, ROOM_DM_POLICY_ASK, 8).unwrap(),
            DmIncoming::Stored { request: true, new_thread: true }
        ));

        db.dm_prune_declined(6 + DM_DECLINE_MEMORY_SECS).unwrap();
        assert!(db.dm_thread(ANN, 6 + DM_DECLINE_MEMORY_SECS).unwrap().is_none(), "a refusal run out leaves nothing");
        drop_db(db, path);
    }

    /// Forgetting an ignored sender's request keeps no refusal, so nothing is
    /// ever answered on its account, and touches no other conversation.
    #[test]
    fn forgetting_a_request_leaves_nothing_to_answer_with() {
        let (db, path) = db("forget");
        db.dm_record_incoming(ANN, "Ann", ROOM, "m1", "psst", 5, ROOM_DM_POLICY_ASK, 5).unwrap();
        db.dm_record_incoming(ANN, "Ann", ROOM, "m2", "hello?", 6, ROOM_DM_POLICY_ASK, 6).unwrap();
        assert!(db.dm_forget_request(&ANN.to_uppercase()).unwrap());
        assert!(db.dm_thread(ANN, 7).unwrap().is_none());
        assert!(db.dm_messages(ANN, 10, None).unwrap().is_empty());
        assert!(!db.dm_declines(ANN, 7).unwrap(), "no refusal kept");
        assert!(!db.dm_forget_request(ANN).unwrap(), "once");
        assert_eq!(
            db.dm_record_incoming(ANN, "Ann", ROOM, "m3", "hi", 8, ROOM_DM_POLICY_ASK, 8).unwrap(),
            DmIncoming::Stored { request: true, new_thread: true },
            "no longer ignored, they ask again rather than draw a decline"
        );

        let bob = "bb22";
        db.dm_record_outgoing(bob, "Bob", ROOM, "o1", "hi", 5, 6, 7).unwrap();
        assert!(!db.dm_forget_request(bob).unwrap(), "an open conversation is not a request");
        assert_eq!(db.dm_messages(bob, 10, None).unwrap().len(), 1);
        drop_db(db, path);
    }

    #[test]
    fn a_row_moved_to_another_time_or_member_does_not_open() {
        let (db, path) = db("aad");
        let sealed = db.seal_dm_body("m1", ANN, "in", 100, "words").unwrap();
        let key = db.chat_key.as_deref();
        assert_eq!(Database::open_dm_body(key, "m1", ANN, "in", 100, &sealed).as_deref(), Some("words"));
        assert!(Database::open_dm_body(key, "m1", ANN, "in", 101, &sealed).is_none());
        assert!(Database::open_dm_body(key, "m1", "bb22", "in", 100, &sealed).is_none());
        assert!(Database::open_dm_body(key, "m1", ANN, "out", 100, &sealed).is_none());
        drop_db(db, path);
    }
}
