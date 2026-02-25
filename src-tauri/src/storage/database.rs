use std::sync::Mutex;

use rusqlite::{params, Connection};
use tauri::Manager;
use tracing::info;

use crate::types::*;

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn new(app_handle: &tauri::AppHandle) -> anyhow::Result<Self> {
        let app_dir = app_handle
            .path()
            .app_data_dir()
            .map_err(|e| anyhow::anyhow!("Failed to get app data dir: {e}"))?;

        std::fs::create_dir_all(&app_dir)?;
        let db_path = app_dir.join("nexus.db");
        let conn = Connection::open(db_path)?;

        conn.execute_batch(
            "PRAGMA journal_mode=WAL;\
             PRAGMA foreign_keys=ON;\
             PRAGMA secure_delete=ON;\
             PRAGMA auto_vacuum=INCREMENTAL;",
        )?;

        let db = Self {
            conn: Mutex::new(conn),
        };
        db.run_migrations()?;

        info!("Database initialized");
        Ok(db)
    }

    fn run_migrations(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS shared_files (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                path TEXT NOT NULL UNIQUE,
                size INTEGER NOT NULL,
                hash TEXT NOT NULL,
                aich_hash TEXT NOT NULL DEFAULT '',
                extension TEXT NOT NULL DEFAULT '',
                modified_at INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS peers (
                id TEXT PRIMARY KEY,
                addresses TEXT NOT NULL DEFAULT '[]',
                nickname TEXT NOT NULL DEFAULT '',
                last_seen INTEGER NOT NULL DEFAULT 0,
                files_shared INTEGER NOT NULL DEFAULT 0,
                banned INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS transfers (
                id TEXT PRIMARY KEY,
                file_name TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                peer_id TEXT NOT NULL,
                peer_name TEXT NOT NULL DEFAULT '',
                direction TEXT NOT NULL,
                status TEXT NOT NULL,
                progress REAL NOT NULL DEFAULT 0.0,
                speed INTEGER NOT NULL DEFAULT 0,
                total_size INTEGER NOT NULL DEFAULT 0,
                transferred INTEGER NOT NULL DEFAULT 0,
                started_at INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_shared_files_hash ON shared_files(hash);
            CREATE INDEX IF NOT EXISTS idx_transfers_status ON transfers(status);
            ",
        )?;

        // Add columns that may be missing from older schema versions
        Self::add_column_if_missing(&conn, "shared_files", "aich_hash", "TEXT NOT NULL DEFAULT ''");

        Ok(())
    }

    fn add_column_if_missing(conn: &Connection, table: &str, column: &str, col_type: &str) {
        let has_column = conn
            .prepare(&format!("SELECT {column} FROM {table} LIMIT 0"))
            .is_ok();
        if !has_column {
            let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {col_type}");
            match conn.execute(&sql, []) {
                Ok(_) => info!("Added column {table}.{column}"),
                Err(e) => tracing::warn!("Failed to add column {table}.{column}: {e}"),
            }
        }
    }

    pub fn save_shared_file(&self, file: &FileInfo) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO shared_files (id, name, path, size, hash, aich_hash, extension, modified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                file.id,
                file.name,
                file.path,
                file.size,
                file.hash,
                file.aich_hash,
                file.extension,
                file.modified_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_shared_files(&self) -> anyhow::Result<Vec<FileInfo>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, path, size, hash, aich_hash, extension, modified_at FROM shared_files",
        )?;

        let files = stmt
            .query_map([], |row| {
                Ok(FileInfo {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    path: row.get(2)?,
                    size: row.get(3)?,
                    hash: row.get(4)?,
                    aich_hash: row.get::<_, String>(5).unwrap_or_default(),
                    extension: row.get(6)?,
                    modified_at: row.get(7)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(files)
    }

    pub fn save_peer(&self, peer: &PeerInfo) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        let addresses = serde_json::to_string(&peer.addresses)?;
        conn.execute(
            "INSERT OR REPLACE INTO peers (id, addresses, nickname, last_seen, files_shared, banned)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                peer.id,
                addresses,
                peer.nickname,
                peer.last_seen,
                peer.files_shared,
                peer.banned as i32,
            ],
        )?;
        Ok(())
    }

    pub fn get_peers(&self) -> anyhow::Result<Vec<PeerInfo>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, addresses, nickname, last_seen, files_shared, banned FROM peers",
        )?;

        let peers = stmt
            .query_map([], |row| {
                let addresses_str: String = row.get(1)?;
                let addresses: Vec<String> =
                    serde_json::from_str(&addresses_str).unwrap_or_default();
                Ok(PeerInfo {
                    id: row.get(0)?,
                    addresses,
                    nickname: row.get(2)?,
                    last_seen: row.get(3)?,
                    files_shared: row.get(4)?,
                    banned: row.get::<_, i32>(5)? != 0,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(peers)
    }

    pub fn ban_peer(&self, peer_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO peers (id, banned) VALUES (?1, 1)
             ON CONFLICT(id) DO UPDATE SET banned = 1",
            params![peer_id],
        )?;
        Ok(())
    }

    pub fn unban_peer(&self, peer_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE peers SET banned = 0 WHERE id = ?1",
            params![peer_id],
        )?;
        Ok(())
    }

    pub fn banned_peer_ids(&self) -> Vec<String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = match conn.prepare("SELECT id FROM peers WHERE banned = 1") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let result: Vec<String> = match stmt.query_map([], |row| row.get(0)) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        };
        result
    }

    pub fn clear_shared_files(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM shared_files", [])?;
        Ok(())
    }

    pub fn save_transfer(&self, transfer: &Transfer) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO transfers (id, file_name, file_hash, peer_id, peer_name, direction, status, progress, speed, total_size, transferred, started_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                transfer.id,
                transfer.file_name,
                transfer.file_hash,
                transfer.peer_id,
                transfer.peer_name,
                serde_json::to_string(&transfer.direction).unwrap_or_default(),
                serde_json::to_string(&transfer.status).unwrap_or_default(),
                transfer.progress,
                transfer.speed as i64,
                transfer.total_size as i64,
                transfer.transferred as i64,
                transfer.started_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_incomplete_downloads(&self) -> anyhow::Result<Vec<Transfer>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, file_name, file_hash, peer_id, peer_name, direction, status, progress, speed, total_size, transferred, started_at
             FROM transfers WHERE status NOT IN ('\"completed\"', '\"failed\"') AND direction = '\"download\"'"
        )?;

        let transfers = stmt
            .query_map([], |row| {
                let direction_str: String = row.get(5)?;
                let status_str: String = row.get(6)?;
                Ok(Transfer {
                    id: row.get(0)?,
                    file_name: row.get(1)?,
                    file_hash: row.get(2)?,
                    peer_id: row.get(3)?,
                    peer_name: row.get(4)?,
                    direction: serde_json::from_str(&direction_str).unwrap_or(TransferDirection::Download),
                    status: serde_json::from_str(&status_str).unwrap_or(TransferStatus::Searching),
                    progress: row.get(7)?,
                    speed: row.get::<_, i64>(8)? as u64,
                    total_size: row.get::<_, i64>(9)? as u64,
                    transferred: row.get::<_, i64>(10)? as u64,
                    started_at: row.get(11)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(transfers)
    }

    pub fn remove_transfer(&self, transfer_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM transfers WHERE id = ?1", params![transfer_id])?;
        Ok(())
    }

    pub fn update_transfer_status(&self, transfer_id: &str, status: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE transfers SET status = ?1 WHERE id = ?2",
            params![status, transfer_id],
        )?;
        Ok(())
    }
}
