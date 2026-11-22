//! What the rendezvous registry says has been deleted, as far as it concerns
//! this device: rooms it holds or has in its Discover cache. Kept, so a
//! registry that cannot be reached does not put a deleted room back, and with
//! when each held room's signed delete was last looked for. See
//! `commands::room_deletion`.

use std::collections::HashSet;

use super::*;

/// How long a room the registry lists as deleted waits, once its signed
/// delete was looked for and not found, before it is looked for again.
pub const DELETE_PROOF_RECHECK_SECS: i64 = 24 * 3600;

impl Database {
    /// Created on first use, outside the numbered migrations, so 1.7.0 can
    /// still open this database.
    fn ensure_registry_deleted_locked(conn: &Connection) -> anyhow::Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS channel_registry_deleted (
                channel_id TEXT PRIMARY KEY,
                noted_at INTEGER NOT NULL,
                proof_checked_at INTEGER NOT NULL DEFAULT 0
            );",
        )?;
        Ok(())
    }

    /// Note the registry's list of deleted rooms. Only the ids that name a
    /// room here or in the Discover cache are kept, and the cache forgets
    /// them. Unless `complete`, the list may have been cut short, so nothing
    /// is taken off what was noted before.
    pub fn note_registry_deleted(&self, ids: &[String], complete: bool, now: i64) -> anyhow::Result<()> {
        let listed: HashSet<String> = ids.iter().map(|id| id.to_ascii_lowercase()).collect();
        let conn = self.conn.lock();
        Self::ensure_registry_deleted_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        let relevant: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT channel_id FROM channels UNION SELECT channel_id FROM channel_index_cache",
            )?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|id| listed.contains(&id.to_ascii_lowercase()))
                .collect()
        };
        for id in &relevant {
            tx.execute(
                "INSERT OR IGNORE INTO channel_registry_deleted (channel_id, noted_at) VALUES (?1, ?2)",
                params![id.to_ascii_lowercase(), now],
            )?;
            tx.execute("DELETE FROM channel_index_cache WHERE channel_id = ?1", params![id])?;
        }
        if complete {
            let noted: Vec<String> = {
                let mut stmt = tx.prepare("SELECT channel_id FROM channel_registry_deleted")?;
                let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
                rows.collect::<Result<Vec<_>, _>>()?
            };
            for id in noted.iter().filter(|id| !listed.contains(*id)) {
                tx.execute("DELETE FROM channel_registry_deleted WHERE channel_id = ?1", params![id])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// The rooms the registry was last seen to list as deleted, of those that
    /// concern this device.
    pub fn registry_deleted_ids(&self) -> anyhow::Result<HashSet<String>> {
        let conn = self.conn.lock();
        Self::ensure_registry_deleted_locked(&conn)?;
        let mut stmt = conn.prepare("SELECT channel_id FROM channel_registry_deleted")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<Result<HashSet<_>, _>>()?)
    }

    /// Whether the registry lists `channel_id` as deleted, as last seen.
    pub fn registry_lists_deleted(&self, channel_id: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::ensure_registry_deleted_locked(&conn)?;
        Ok(conn
            .query_row(
                "SELECT 1 FROM channel_registry_deleted WHERE channel_id = ?1",
                params![channel_id.to_ascii_lowercase()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Rooms this device is in, and does not own, that the registry lists as
    /// deleted.
    pub fn rooms_listed_deleted_in(&self) -> anyhow::Result<Vec<String>> {
        let conn = self.conn.lock();
        Self::ensure_registry_deleted_locked(&conn)?;
        let mut stmt = conn.prepare(
            "SELECT c.channel_id FROM channels c
               JOIN channel_registry_deleted d ON d.channel_id = lower(c.channel_id)
              WHERE c.in_room = 1 AND c.deleted = 0 AND c.is_owner = 0",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Rooms held here, not owned and not already removed, that the registry
    /// lists as deleted and whose signed delete is due to be looked for:
    /// `(channel_id, pubkey)`.
    pub fn rooms_awaiting_delete_proof(&self, now: i64) -> anyhow::Result<Vec<(String, String)>> {
        let conn = self.conn.lock();
        Self::ensure_registry_deleted_locked(&conn)?;
        let mut stmt = conn.prepare(
            "SELECT c.channel_id, c.pubkey FROM channels c
               JOIN channel_registry_deleted d ON d.channel_id = lower(c.channel_id)
              WHERE c.deleted = 0 AND c.is_owner = 0
                AND (d.proof_checked_at = 0 OR d.proof_checked_at <= ?1)",
        )?;
        let rows = stmt.query_map(params![now - DELETE_PROOF_RECHECK_SECS], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// The signed deletes of `channel_ids` were looked for at `now`.
    pub fn note_delete_proofs_looked_for(&self, channel_ids: &[String], now: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_registry_deleted_locked(&conn)?;
        for id in channel_ids {
            conn.execute(
                "UPDATE channel_registry_deleted SET proof_checked_at = ?2 WHERE channel_id = ?1",
                params![id.to_ascii_lowercase(), now],
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db(tag: &str) -> (Database, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "ember-room-deletion-{tag}-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        (Database::open_at(&path).expect("open db"), path)
    }

    fn drop_db(db: Database, path: std::path::PathBuf) {
        drop(db);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    fn room(db: &Database, n: u8, in_room: bool, is_owner: bool) -> String {
        let id = hex::encode([n; 16]);
        db.insert_channel(&id, &hex::encode([n; 32]), "Room", "private", is_owner, None, Some(&[n; 32]))
            .unwrap();
        db.set_channel_in_room(&id, in_room).unwrap();
        id
    }

    #[test]
    fn only_rooms_that_concern_this_device_are_noted_and_a_partial_list_takes_none_off() {
        let (db, path) = db("note");
        let inside = room(&db, 1, true, false);
        let left = room(&db, 2, false, false);
        let owned = room(&db, 3, true, true);
        let stranger = hex::encode([9u8; 16]);
        let all = vec![inside.clone(), left.clone(), owned.clone(), stranger.to_ascii_uppercase()];
        db.note_registry_deleted(&all, true, 100).unwrap();
        let noted = db.registry_deleted_ids().unwrap();
        assert_eq!(noted.len(), 3, "a room this device never heard of is not kept");
        assert!(db.registry_lists_deleted(&left).unwrap());
        assert!(!db.registry_lists_deleted(&stranger).unwrap());

        assert_eq!(db.rooms_listed_deleted_in().unwrap(), vec![inside.clone()], "not the owner's, not one left");
        let mut awaiting: Vec<String> = db.rooms_awaiting_delete_proof(100).unwrap().into_iter().map(|(id, _)| id).collect();
        awaiting.sort();
        assert_eq!(awaiting, vec![inside.clone(), left.clone()]);
        db.note_delete_proofs_looked_for(std::slice::from_ref(&inside), 100).unwrap();
        let awaiting: Vec<String> = db.rooms_awaiting_delete_proof(200).unwrap().into_iter().map(|(id, _)| id).collect();
        assert_eq!(awaiting, vec![left.clone()], "looked for a moment ago");
        assert_eq!(db.rooms_awaiting_delete_proof(100 + DELETE_PROOF_RECHECK_SECS).unwrap().len(), 2);

        // A list that may be cut short takes nothing off.
        db.note_registry_deleted(std::slice::from_ref(&inside), false, 300).unwrap();
        assert_eq!(db.registry_deleted_ids().unwrap().len(), 3);
        // A complete one does.
        db.note_registry_deleted(std::slice::from_ref(&inside), true, 300).unwrap();
        assert_eq!(db.registry_deleted_ids().unwrap(), HashSet::from([inside]));
        drop_db(db, path);
    }

    #[test]
    fn a_deleted_room_leaves_the_discover_cache() {
        let (db, path) = db("cache");
        let id = hex::encode([4u8; 16]);
        db.cache_channel_listings(&[CachedChannel {
            channel_id: id.clone(),
            pubkey: hex::encode([4u8; 32]),
            name: "Gone".into(),
            language: String::new(),
            first_seen: 0,
        }])
        .unwrap();
        assert_eq!(db.list_cached_channels().unwrap().len(), 1);
        db.note_registry_deleted(std::slice::from_ref(&id), true, 100).unwrap();
        assert!(db.list_cached_channels().unwrap().is_empty());
        assert!(db.registry_lists_deleted(&id).unwrap(), "noted while it was cached");
        drop_db(db, path);
    }
}
