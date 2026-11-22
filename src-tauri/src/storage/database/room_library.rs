//! Room libraries: per room, whether this member's library is open to it and
//! which folders it holds. See `sharing::room_library`, whose registry every
//! change here is written through to.

use super::*;
use crate::sharing::room_library::RoomLibrary;

impl Database {
    /// Created on first use, outside the numbered migrations, so 1.7.0 can
    /// still open this database.
    fn ensure_room_library_locked(conn: &Connection) -> anyhow::Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS room_library_rooms (
                channel_id TEXT PRIMARY KEY,
                open INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS room_library_folders (
                channel_id TEXT NOT NULL,
                path TEXT NOT NULL,
                added_at INTEGER NOT NULL,
                PRIMARY KEY (channel_id, path)
            );",
        )?;
        Ok(())
    }

    fn room_library_locked(conn: &Connection, channel_id: &str) -> anyhow::Result<RoomLibrary> {
        let open = conn
            .query_row(
                "SELECT open FROM room_library_rooms WHERE channel_id = ?1",
                params![channel_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some_and(|open| open != 0);
        let mut stmt = conn.prepare(
            "SELECT path FROM room_library_folders WHERE channel_id = ?1 ORDER BY added_at, rowid",
        )?;
        let folders = stmt
            .query_map(params![channel_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RoomLibrary { open, folders })
    }

    /// Every room with a library, for `sharing::room_library::load`.
    pub fn room_libraries(&self) -> anyhow::Result<Vec<(String, RoomLibrary)>> {
        let conn = self.conn.lock();
        Self::ensure_room_library_locked(&conn)?;
        let mut stmt = conn.prepare(
            "SELECT channel_id FROM room_library_rooms
             UNION SELECT channel_id FROM room_library_folders",
        )?;
        let rooms = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        rooms
            .into_iter()
            .map(|room| Ok((room.clone(), Self::room_library_locked(&conn, &room)?)))
            .collect()
    }

    pub fn room_library(&self, channel_id: &str) -> anyhow::Result<RoomLibrary> {
        let conn = self.conn.lock();
        Self::ensure_room_library_locked(&conn)?;
        Self::room_library_locked(&conn, &channel_id.to_ascii_lowercase())
    }

    /// Open the room's library to it, or close it. Returns the library.
    pub fn set_room_library_open(&self, channel_id: &str, open: bool) -> anyhow::Result<RoomLibrary> {
        let channel_id = channel_id.to_ascii_lowercase();
        let conn = self.conn.lock();
        Self::ensure_room_library_locked(&conn)?;
        conn.execute(
            "INSERT INTO room_library_rooms (channel_id, open) VALUES (?1, ?2)
             ON CONFLICT(channel_id) DO UPDATE SET open = excluded.open",
            params![channel_id, i64::from(open)],
        )?;
        let library = Self::room_library_locked(&conn, &channel_id)?;
        crate::sharing::room_library::set(&channel_id, library.clone());
        Ok(library)
    }

    /// Add a folder, already checked, to the room's library. Returns the
    /// library.
    pub fn add_room_library_folder(&self, channel_id: &str, path: &str, now: i64) -> anyhow::Result<RoomLibrary> {
        let channel_id = channel_id.to_ascii_lowercase();
        let conn = self.conn.lock();
        Self::ensure_room_library_locked(&conn)?;
        conn.execute(
            "INSERT OR IGNORE INTO room_library_folders (channel_id, path, added_at) VALUES (?1, ?2, ?3)",
            params![channel_id, path, now],
        )?;
        let library = Self::room_library_locked(&conn, &channel_id)?;
        crate::sharing::room_library::set(&channel_id, library.clone());
        Ok(library)
    }

    /// Take a folder out of the room's library, named exactly as stored.
    /// Returns whether it was there, and the library.
    pub fn remove_room_library_folder(&self, channel_id: &str, path: &str) -> anyhow::Result<(bool, RoomLibrary)> {
        let channel_id = channel_id.to_ascii_lowercase();
        let conn = self.conn.lock();
        Self::ensure_room_library_locked(&conn)?;
        let removed = conn.execute(
            "DELETE FROM room_library_folders WHERE channel_id = ?1 AND path = ?2",
            params![channel_id, path],
        )? > 0;
        let library = Self::room_library_locked(&conn, &channel_id)?;
        crate::sharing::room_library::set(&channel_id, library.clone());
        Ok((removed, library))
    }

    /// The room's library goes with the room. The caller writes the empty
    /// library through to the registry once its transaction commits.
    pub(super) fn delete_room_library_locked(conn: &Connection, channel_id: &str) -> anyhow::Result<()> {
        Self::ensure_room_library_locked(conn)?;
        let channel_id = channel_id.to_ascii_lowercase();
        conn.execute("DELETE FROM room_library_rooms WHERE channel_id = ?1", params![channel_id])?;
        conn.execute("DELETE FROM room_library_folders WHERE channel_id = ?1", params![channel_id])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOM: &str = "AB00000000000000000000000000c0de";

    #[test]
    fn a_room_library_is_kept_in_the_order_folders_were_added_and_goes_with_the_room() {
        let path = std::env::temp_dir().join(format!(
            "ember-room-library-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let db = Database::open_at(&path).expect("open db");
        assert_eq!(db.room_library(ROOM).unwrap(), RoomLibrary::default());
        db.add_room_library_folder(ROOM, "/b", 20).unwrap();
        db.add_room_library_folder(ROOM, "/a", 10).unwrap();
        db.add_room_library_folder(ROOM, "/a", 30).unwrap();
        let library = db.set_room_library_open(ROOM, true).unwrap();
        assert_eq!(library, RoomLibrary { open: true, folders: vec!["/a".into(), "/b".into()] });
        assert_eq!(crate::sharing::room_library::get(ROOM), library, "written through");
        assert_eq!(db.room_libraries().unwrap(), vec![(ROOM.to_ascii_lowercase(), library)]);

        let (removed, library) = db.remove_room_library_folder(ROOM, "/A").unwrap();
        assert!(!removed, "named exactly as stored");
        assert_eq!(library.folders.len(), 2);
        let (removed, library) = db.remove_room_library_folder(ROOM, "/a").unwrap();
        assert!(removed);
        assert_eq!(library.folders, vec!["/b".to_string()]);

        {
            let conn = db.conn.lock();
            Database::delete_room_library_locked(&conn, ROOM).unwrap();
        }
        assert_eq!(db.room_library(ROOM).unwrap(), RoomLibrary::default());
        assert!(db.room_libraries().unwrap().is_empty());
        crate::sharing::room_library::set(ROOM, RoomLibrary::default());
        drop(db);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
