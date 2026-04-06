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
        let db_path = app_dir.join("ember.db");
        let conn = Connection::open(&db_path)?;
        crate::security::restrict_file_permissions(&db_path);

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
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;

        conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL DEFAULT 0);")?;
        let version: i64 = conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

        let set_version = |tx: &Connection, v: i64| -> anyhow::Result<()> {
            tx.execute("DELETE FROM schema_version", [])?;
            tx.execute("INSERT INTO schema_version (version) VALUES (?1)", params![v])?;
            Ok(())
        };

        if version < 1 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
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
            Self::add_column_if_missing(&tx, "shared_files", "aich_hash", "TEXT NOT NULL DEFAULT ''");
            set_version(&tx, 1)?;
            tx.commit()?;
        }

        if version < 2 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS credits (
                    user_hash BLOB PRIMARY KEY,
                    uploaded INTEGER NOT NULL DEFAULT 0,
                    downloaded INTEGER NOT NULL DEFAULT 0,
                    last_seen INTEGER NOT NULL DEFAULT 0,
                    public_key BLOB NOT NULL DEFAULT x''
                );",
            )?;
            set_version(&tx, 2)?;
            tx.commit()?;
        }

        if version < 3 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS statistics (
                    key TEXT PRIMARY KEY,
                    value INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS file_comments (
                    file_hash TEXT PRIMARY KEY,
                    rating INTEGER NOT NULL DEFAULT 0,
                    comment TEXT NOT NULL DEFAULT ''
                );",
            )?;
            set_version(&tx, 3)?;
            tx.commit()?;
        }

        if version < 4 {
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "shared_files", "shared", "INTEGER NOT NULL DEFAULT 1");
            set_version(&tx, 4)?;
            tx.commit()?;
        }

        if version < 5 {
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "transfers", "priority", "TEXT NOT NULL DEFAULT 'normal'");
            Self::add_column_if_missing(&tx, "transfers", "category", "TEXT NOT NULL DEFAULT ''");
            set_version(&tx, 5)?;
            tx.commit()?;
        }

        if version < 6 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "UPDATE transfers SET status = TRIM(status, '\"') WHERE status LIKE '\"%\"';
                 UPDATE transfers SET direction = TRIM(direction, '\"') WHERE direction LIKE '\"%\"';",
            )?;
            set_version(&tx, 6)?;
            tx.commit()?;
        }

        if version < 7 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS friends (
                    user_hash TEXT PRIMARY KEY,
                    nickname TEXT NOT NULL DEFAULT '',
                    added_at INTEGER NOT NULL DEFAULT 0
                );",
            )?;
            set_version(&tx, 7)?;
            tx.commit()?;
        }

        if version < 8 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "DROP TABLE IF EXISTS shared_files;
                 DROP TABLE IF EXISTS settings;
                 DROP INDEX IF EXISTS idx_shared_files_hash;",
            )?;
            set_version(&tx, 8)?;
            tx.commit()?;
        }

        if version < 9 {
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "friends", "last_ip", "TEXT DEFAULT ''");
            Self::add_column_if_missing(&tx, "friends", "last_port", "INTEGER DEFAULT 0");
            Self::add_column_if_missing(&tx, "friends", "last_seen", "INTEGER DEFAULT 0");
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS chat_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    friend_hash TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    read INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_chat_messages_friend ON chat_messages(friend_hash, timestamp);",
            )?;
            set_version(&tx, 9)?;
            tx.commit()?;
        }

        if version < 10 {
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "friends", "mutual", "INTEGER NOT NULL DEFAULT 0");
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS friend_requests (
                    sender_hash TEXT PRIMARY KEY,
                    sender_nickname TEXT NOT NULL DEFAULT '',
                    received_at INTEGER NOT NULL DEFAULT 0
                );",
            )?;
            set_version(&tx, 10)?;
            tx.commit()?;
        }

        if version < 11 {
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "friend_requests", "sender_ip", "TEXT DEFAULT ''");
            Self::add_column_if_missing(&tx, "friend_requests", "sender_port", "INTEGER DEFAULT 0");
            set_version(&tx, 11)?;
            tx.commit()?;
        }

        if version < 12 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS download_history (
                    file_hash TEXT NOT NULL PRIMARY KEY,
                    file_name TEXT NOT NULL DEFAULT '',
                    file_size INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    timestamp INTEGER NOT NULL
                );"
            )?;
            set_version(&tx, 12)?;
            tx.commit()?;
        }

        Ok(())
    }

    fn add_column_if_missing(conn: &Connection, table: &str, column: &str, col_type: &str) {
        let valid_ident =
            |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        let valid_col_type =
            |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '\'');
        if !valid_ident(table) || !valid_ident(column) || !valid_col_type(col_type) {
            tracing::warn!("Rejecting invalid SQL identifier in migration: {table}.{column} {col_type}");
            return;
        }
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

    pub fn save_peer(&self, peer: &PeerInfo) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let addresses = serde_json::to_string(&peer.addresses)?;
        conn.execute(
            "INSERT INTO peers (id, addresses, nickname, last_seen, files_shared, banned)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
               addresses = excluded.addresses,
               nickname = excluded.nickname,
               last_seen = excluded.last_seen,
               files_shared = excluded.files_shared,
               banned = excluded.banned",
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
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
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
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => { tracing::warn!("Failed to read DB row: {e}"); None }
            })
            .collect();

        Ok(peers)
    }

    pub fn ban_peer(&self, peer_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        conn.execute(
            "INSERT INTO peers (id, banned) VALUES (?1, 1)
             ON CONFLICT(id) DO UPDATE SET banned = 1",
            params![peer_id],
        )?;
        Ok(())
    }

    pub fn unban_peer(&self, peer_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        conn.execute(
            "UPDATE peers SET banned = 0 WHERE id = ?1",
            params![peer_id],
        )?;
        Ok(())
    }

    pub fn save_transfer(&self, transfer: &Transfer) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let direction: &str = match transfer.direction {
            TransferDirection::Upload => "upload",
            TransferDirection::Download => "download",
        };
        let status: &str = match transfer.status {
            TransferStatus::Searching => "searching",
            TransferStatus::Queued => "queued",
            TransferStatus::Active => "active",
            TransferStatus::Paused => "paused",
            TransferStatus::Stopped => "stopped",
            TransferStatus::Verifying => "verifying",
            TransferStatus::Completing => "completing",
            TransferStatus::Completed => "completed",
            TransferStatus::Failed => "failed",
            TransferStatus::Hashing => "hashing",
            TransferStatus::Insufficient => "insufficient",
            TransferStatus::NoneNeeded => "noneneeded",
        };
        conn.execute(
            "INSERT INTO transfers (id, file_name, file_hash, peer_id, peer_name, direction, status, progress, speed, total_size, transferred, started_at, priority, category)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
             ON CONFLICT(id) DO UPDATE SET
               file_name = excluded.file_name,
               file_hash = excluded.file_hash,
               peer_id = excluded.peer_id,
               peer_name = excluded.peer_name,
               direction = excluded.direction,
               status = excluded.status,
               progress = excluded.progress,
               speed = excluded.speed,
               total_size = excluded.total_size,
               transferred = excluded.transferred,
               started_at = excluded.started_at,
               priority = excluded.priority,
               category = excluded.category",
            params![
                transfer.id,
                transfer.file_name,
                transfer.file_hash,
                transfer.peer_id,
                transfer.peer_name,
                direction,
                status,
                transfer.progress,
                i64::try_from(transfer.speed).unwrap_or(i64::MAX),
                i64::try_from(transfer.total_size).unwrap_or(i64::MAX),
                i64::try_from(transfer.transferred).unwrap_or(i64::MAX),
                transfer.started_at,
                transfer.priority,
                transfer.category,
            ],
        )?;
        Ok(())
    }

    pub fn get_incomplete_downloads(&self) -> anyhow::Result<Vec<Transfer>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let mut stmt = conn.prepare(
            "SELECT id, file_name, file_hash, peer_id, peer_name, direction, status, progress, speed, total_size, transferred, started_at, priority, category
             FROM transfers WHERE status NOT IN ('completed', 'failed', 'insufficient', 'noneneeded') AND direction = 'download'"
        )?;

        let transfers = stmt
            .query_map([], |row| {
                let direction_str: String = row.get(5)?;
                let status_str: String = row.get(6)?;
                let transferred_val = row.get::<_, i64>(10)?.max(0) as u64;
                Ok(Transfer {
                    id: row.get(0)?,
                    file_name: row.get(1)?,
                    file_hash: row.get(2)?,
                    peer_id: row.get(3)?,
                    peer_name: row.get(4)?,
                    direction: match direction_str.trim_matches('"') {
                        "upload" => TransferDirection::Upload,
                        _ => TransferDirection::Download,
                    },
                    status: match status_str.trim_matches('"') {
                        "searching" => TransferStatus::Searching,
                        "queued" => TransferStatus::Queued,
                        "active" => TransferStatus::Active,
                        "paused" => TransferStatus::Paused,
                        "stopped" => TransferStatus::Stopped,
                        "verifying" => TransferStatus::Verifying,
                        "completing" => TransferStatus::Completing,
                        "completed" => TransferStatus::Completed,
                        "failed" => TransferStatus::Failed,
                        "hashing" => TransferStatus::Hashing,
                        "insufficient" => TransferStatus::Insufficient,
                        "noneneeded" => TransferStatus::NoneNeeded,
                        _ => TransferStatus::Searching,
                    },
                    progress: row.get(7)?,
                    speed: row.get::<_, i64>(8)?.max(0) as u64,
                    total_size: row.get::<_, i64>(9)?.max(0) as u64,
                    transferred: transferred_val,
                    completed_size: transferred_val,
                    started_at: row.get(11)?,
                    failure_reason: None,
                    failure_kind: None,
                    failure_stage: None,
                    priority: row.get::<_, String>(12).unwrap_or_else(|_| "normal".to_string()),
                    sources: 0,
                    active_sources: 0,
                    queued_sources: 0,
                    queue_rank: None,
                    last_seen_complete: None,
                    last_received: None,
                    health: TransferHealth::Healthy,
                    health_reason: None,
                    stalled_since: None,
                    category: row.get::<_, String>(13).unwrap_or_default(),
                    wait_time: 0,
                    upload_time: 0,
                    a4af_sources: 0,
                    max_sources: 0,
                    preview_priority: false,
                    ember_sources: 0,
                    client_software: String::new(),
                    country_code: None,
                    user_hash: None,
                })
            })?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!("Skipping malformed transfer row: {e}");
                    None
                }
            })
            .collect();

        Ok(transfers)
    }

    pub fn remove_transfer(&self, transfer_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        conn.execute("DELETE FROM transfers WHERE id = ?1", params![transfer_id])?;
        Ok(())
    }

    pub fn update_transfer_status(&self, transfer_id: &str, status: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        conn.execute(
            "UPDATE transfers SET status = ?1 WHERE id = ?2",
            params![status, transfer_id],
        )?;
        Ok(())
    }

    pub fn update_transfer_progress(
        &self,
        transfer_id: &str,
        transferred: u64,
        progress: f64,
        speed: u64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        conn.execute(
            "UPDATE transfers
             SET transferred = ?1, progress = ?2, speed = ?3
             WHERE id = ?4",
            params![i64::try_from(transferred).unwrap_or(i64::MAX), progress, i64::try_from(speed).unwrap_or(i64::MAX), transfer_id],
        )?;
        Ok(())
    }

    pub fn update_transfer_priority(&self, transfer_id: &str, priority: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        conn.execute(
            "UPDATE transfers SET priority = ?1 WHERE id = ?2",
            params![priority, transfer_id],
        )?;
        Ok(())
    }

    pub fn update_transfer_category(&self, transfer_id: &str, category: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        conn.execute(
            "UPDATE transfers SET category = ?1 WHERE id = ?2",
            params![category, transfer_id],
        )?;
        Ok(())
    }

    pub fn load_credits(&self) -> anyhow::Result<Vec<([u8; 16], u64, u64, i64, Vec<u8>)>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let mut stmt = conn.prepare("SELECT user_hash, uploaded, downloaded, last_seen, public_key FROM credits")?;
        let records = stmt
            .query_map([], |row| {
                let hash_blob: Vec<u8> = row.get(0)?;
                if hash_blob.len() < 16 {
                    return Err(rusqlite::Error::InvalidColumnType(0, "user_hash too short".into(), rusqlite::types::Type::Blob));
                }
                let mut hash = [0u8; 16];
                hash.copy_from_slice(&hash_blob[..16]);
                Ok((
                    hash,
                    row.get::<_, i64>(1)?.max(0) as u64,
                    row.get::<_, i64>(2)?.max(0) as u64,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            })?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!("Skipping malformed credit row: {e}");
                    None
                }
            })
            .collect();
        Ok(records)
    }

    pub fn load_statistics(&self) -> anyhow::Result<Vec<(String, i64)>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let mut stmt = conn.prepare("SELECT key, value FROM statistics")?;
        let rows = stmt
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!("Skipping malformed statistics row: {e}");
                    None
                }
            })
            .collect();
        Ok(rows)
    }

    pub fn save_statistics(&self, pairs: &[(&str, i64)]) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare("INSERT OR REPLACE INTO statistics (key, value) VALUES (?1, ?2)")?;
            for (key, value) in pairs {
                stmt.execute(params![key, value])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_file_comments(&self) -> anyhow::Result<Vec<(String, u8, String)>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let mut stmt = conn.prepare("SELECT file_hash, rating, comment FROM file_comments")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    (row.get::<_, i32>(1)?).clamp(0, 5) as u8,
                    row.get::<_, String>(2)?,
                ))
            })?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!("Skipping malformed file comment row: {e}");
                    None
                }
            })
            .collect();
        Ok(rows)
    }

    pub fn save_file_comment(&self, file_hash: &str, rating: u8, comment: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        conn.execute(
            "INSERT OR REPLACE INTO file_comments (file_hash, rating, comment) VALUES (?1, ?2, ?3)",
            params![file_hash, rating as i32, comment],
        )?;
        Ok(())
    }

    pub fn save_all_credits(&self, credits: &[(&[u8; 16], u64, u64, i64, &[u8])]) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR REPLACE INTO credits (user_hash, uploaded, downloaded, last_seen, public_key) VALUES (?1, ?2, ?3, ?4, ?5)"
            )?;
            for (hash, uploaded, downloaded, last_seen, public_key) in credits {
                stmt.execute(params![&hash[..], i64::try_from(*uploaded).unwrap_or(i64::MAX), i64::try_from(*downloaded).unwrap_or(i64::MAX), *last_seen, *public_key])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn add_friend(&self, user_hash: &str, nickname: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO friends (user_hash, nickname, added_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(user_hash) DO UPDATE SET nickname = excluded.nickname",
            params![user_hash, nickname, now],
        )?;
        Ok(())
    }

    pub fn remove_friend(&self, user_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM chat_messages WHERE friend_hash = ?1", params![user_hash])?;
        tx.execute("DELETE FROM friends WHERE user_hash = ?1", params![user_hash])?;
        tx.execute("DELETE FROM friend_requests WHERE sender_hash = ?1", params![user_hash])?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_friends(&self) -> anyhow::Result<Vec<(String, String, i64)>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let mut stmt = conn.prepare("SELECT user_hash, nickname, added_at FROM friends ORDER BY added_at DESC")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn update_friend_nickname(&self, user_hash: &str, nickname: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        conn.execute(
            "UPDATE friends SET nickname = ?2 WHERE user_hash = ?1",
            params![user_hash, nickname],
        )?;
        Ok(())
    }

    pub fn update_friend_address(&self, user_hash: &str, ip: &str, port: u16) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "UPDATE friends SET last_ip = ?2, last_port = ?3, last_seen = ?4 WHERE user_hash = ?1",
            params![user_hash, ip, port as i64, now],
        )?;
        Ok(())
    }

    pub fn clear_friend_address(&self, user_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        conn.execute(
            "UPDATE friends SET last_ip = '', last_port = 0 WHERE user_hash = ?1",
            params![user_hash],
        )?;
        Ok(())
    }

    pub fn get_friend_address(&self, user_hash: &str) -> anyhow::Result<Option<(String, u16)>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let mut stmt = conn.prepare(
            "SELECT COALESCE(last_ip, ''), COALESCE(last_port, 0) FROM friends WHERE user_hash = ?1"
        )?;
        let result = stmt.query_row(params![user_hash], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?.clamp(0, u16::MAX as i64) as u16))
        });
        match result {
            Ok((ip, port)) if !ip.is_empty() && port > 0 => Ok(Some((ip, port))),
            Ok(_) => Ok(None),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_friends_full(&self) -> anyhow::Result<Vec<(String, String, i64, String, u16, i64, bool)>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let mut stmt = conn.prepare(
            "SELECT user_hash, nickname, added_at, COALESCE(last_ip, ''), COALESCE(last_port, 0), COALESCE(last_seen, 0), COALESCE(mutual, 0) FROM friends ORDER BY added_at DESC"
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?.clamp(0, u16::MAX as i64) as u16,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)? != 0,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn set_friend_mutual(&self, user_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        conn.execute(
            "UPDATE friends SET mutual = 1 WHERE user_hash = ?1",
            params![user_hash],
        )?;
        Ok(())
    }

    pub fn add_friend_request(&self, sender_hash: &str, nickname: &str, sender_ip: &str, sender_port: u16) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO friend_requests (sender_hash, sender_nickname, received_at, sender_ip, sender_port)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(sender_hash) DO UPDATE SET sender_nickname = excluded.sender_nickname,
             sender_ip = excluded.sender_ip, sender_port = excluded.sender_port",
            params![sender_hash, nickname, now, sender_ip, sender_port as i64],
        )?;
        Ok(())
    }

    pub fn get_friend_requests(&self) -> anyhow::Result<Vec<(String, String, i64, String, u16)>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let mut stmt = conn.prepare(
            "SELECT sender_hash, sender_nickname, received_at, COALESCE(sender_ip, ''), COALESCE(sender_port, 0) FROM friend_requests ORDER BY received_at DESC"
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?.clamp(0, u16::MAX as i64) as u16,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn remove_friend_request(&self, sender_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        conn.execute("DELETE FROM friend_requests WHERE sender_hash = ?1", params![sender_hash])?;
        Ok(())
    }

    pub fn insert_chat_message(&self, friend_hash: &str, direction: &str, message: &str) -> anyhow::Result<i64> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO chat_messages (friend_hash, direction, message, timestamp, read) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![friend_hash, direction, message, now, if direction == "sent" { 1 } else { 0 }],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_chat_messages(&self, friend_hash: &str, limit: i64, before_id: Option<i64>) -> anyhow::Result<Vec<(i64, String, String, i64, bool)>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        if let Some(bid) = before_id {
            let mut stmt = conn.prepare(
                "SELECT id, direction, message, timestamp, read FROM chat_messages WHERE friend_hash = ?1 AND id < ?2 ORDER BY id DESC LIMIT ?3"
            )?;
            let rows = stmt.query_map(params![friend_hash, bid, limit], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get::<_, i64>(4)? != 0))
            })?.filter_map(|r| r.ok()).collect();
            Ok(rows)
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, direction, message, timestamp, read FROM chat_messages WHERE friend_hash = ?1 ORDER BY id DESC LIMIT ?2"
            )?;
            let rows = stmt.query_map(params![friend_hash, limit], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get::<_, i64>(4)? != 0))
            })?.filter_map(|r| r.ok()).collect();
            Ok(rows)
        }
    }

    pub fn mark_messages_read(&self, friend_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        conn.execute(
            "UPDATE chat_messages SET read = 1 WHERE friend_hash = ?1 AND read = 0",
            params![friend_hash],
        )?;
        Ok(())
    }

    pub fn unread_message_counts(&self) -> anyhow::Result<Vec<(String, i64)>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let mut stmt = conn.prepare(
            "SELECT friend_hash, COUNT(*) FROM chat_messages WHERE read = 0 GROUP BY friend_hash"
        )?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Reclaim unused pages freed by DELETE operations.
    /// Should be called periodically (e.g. alongside credit flush).
    pub fn incremental_vacuum(&self) {
        if let Ok(conn) = self.conn.lock() {
            if let Err(e) = conn.execute_batch("PRAGMA incremental_vacuum(64);") {
                tracing::debug!("incremental_vacuum failed: {e}");
            }
        }
    }

    /// Record a completed or cancelled download in history.
    pub fn record_download_history(
        &self,
        file_hash: &str,
        file_name: &str,
        file_size: u64,
        status: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO download_history (file_hash, file_name, file_size, status, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(file_hash) DO UPDATE SET
               file_name = excluded.file_name,
               file_size = excluded.file_size,
               status = excluded.status,
               timestamp = excluded.timestamp",
            params![file_hash, file_name, i64::try_from(file_size).unwrap_or(i64::MAX), status, now],
        )?;
        Ok(())
    }

    /// Look up download history for a batch of file hashes.
    /// Returns a map of hash → status ("completed" or "cancelled").
    pub fn get_download_history_batch(
        &self,
        hashes: &[String],
    ) -> anyhow::Result<std::collections::HashMap<String, String>> {
        if hashes.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        let placeholders: Vec<String> = (1..=hashes.len()).map(|i| format!("?{i}")).collect();
        let sql = format!(
            "SELECT file_hash, status FROM download_history WHERE file_hash IN ({})",
            placeholders.join(",")
        );
        let mut stmt = conn.prepare(&sql)?;
        let params: Vec<&dyn rusqlite::ToSql> = hashes.iter().map(|h| h as &dyn rusqlite::ToSql).collect();
        let rows = stmt
            .query_map(params.as_slice(), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Remove a specific file from download history (user override).
    pub fn remove_download_history(&self, file_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        conn.execute("DELETE FROM download_history WHERE file_hash = ?1", params![file_hash])?;
        Ok(())
    }

    /// Clear all download history entries of a given status.
    pub fn clear_download_history(&self, status: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock poisoned: {e}"))?;
        conn.execute("DELETE FROM download_history WHERE status = ?1", params![status])?;
        Ok(())
    }
}
