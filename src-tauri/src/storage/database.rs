use parking_lot::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use tracing::info;

use crate::storage::paths;
use crate::types::*;

const MAX_PEERS_ROWS: i64 = 10_000;
const MAX_DOWNLOAD_HISTORY_ROWS: i64 = 5_000;

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn new(app_handle: &tauri::AppHandle) -> anyhow::Result<Self> {
        let app_dir = paths::ensure_data_dir_with_app(app_handle)
            .map_err(|e| anyhow::anyhow!("Failed to prepare data dir: {e}"))?;

        let db_path = app_dir.join("ember.db");
        let conn = Connection::open(&db_path)?;
        crate::security::restrict_file_permissions(&db_path);

        conn.execute_batch(
            "PRAGMA journal_mode=WAL;\
             PRAGMA foreign_keys=ON;\
             PRAGMA secure_delete=ON;\
             PRAGMA auto_vacuum=INCREMENTAL;\
             PRAGMA busy_timeout=5000;",
        )?;

        let db = Self {
            conn: Mutex::new(conn),
        };
        db.run_migrations()?;

        info!("Database initialized");
        Ok(db)
    }

    fn run_migrations(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock();

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL DEFAULT 0);",
        )?;
        let version: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        // Refuse to run against a database that was last opened by a newer
        // Ember build. Silently running would invite subtle data corruption
        // (missing columns, renamed tables, semantic changes). Bump this
        // when introducing a new migration.
        const MAX_SUPPORTED_VERSION: i64 = 19;
        if version > MAX_SUPPORTED_VERSION {
            anyhow::bail!(
                "Database schema version {version} is newer than this Ember build supports \
                 (max {MAX_SUPPORTED_VERSION}). The database was likely written by a more \
                 recent version of Ember. Install that version to access this data; refusing \
                 to start to avoid corruption."
            );
        }

        let set_version = |tx: &Connection, v: i64| -> anyhow::Result<()> {
            tx.execute("DELETE FROM schema_version", [])?;
            tx.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                params![v],
            )?;
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
            Self::add_column_if_missing(
                &tx,
                "shared_files",
                "aich_hash",
                "TEXT NOT NULL DEFAULT ''",
            )?;
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
            Self::add_column_if_missing(
                &tx,
                "shared_files",
                "shared",
                "INTEGER NOT NULL DEFAULT 1",
            )?;
            set_version(&tx, 4)?;
            tx.commit()?;
        }

        if version < 5 {
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "transfers",
                "priority",
                "TEXT NOT NULL DEFAULT 'normal'",
            )?;
            Self::add_column_if_missing(&tx, "transfers", "category", "TEXT NOT NULL DEFAULT ''")?;
            set_version(&tx, 5)?;
            tx.commit()?;
        }

        if version < 6 {
            // Back up the rows we're about to mass-UPDATE. If the TRIM
            // accidentally matches an unusual-but-valid value the original
            // rows can be recovered from `transfers_v5_backup`.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "DROP TABLE IF EXISTS transfers_v5_backup;
                 CREATE TABLE transfers_v5_backup AS
                     SELECT id, status, direction FROM transfers
                     WHERE status LIKE '\"%\"' OR direction LIKE '\"%\"';
                 UPDATE transfers SET status = TRIM(status, '\"') WHERE status LIKE '\"%\"';
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
            // v8 replaces shared_files/settings with file-based storage
            // (known.met + config.json). Preserve the legacy rows in
            // _backup tables instead of dropping outright so users upgrading
            // from v<8 aren't silently wiped — a subsequent admin/dev can
            // recover or export them if needed. These back-up tables are
            // never queried by the live app.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "DROP TABLE IF EXISTS shared_files_v7_backup;
                 DROP TABLE IF EXISTS settings_v7_backup;
                 DROP INDEX IF EXISTS idx_shared_files_hash;",
            )?;
            let has_shared: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='shared_files'",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            if has_shared > 0 {
                tx.execute_batch("ALTER TABLE shared_files RENAME TO shared_files_v7_backup;")?;
            }
            let has_settings: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='settings'",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            if has_settings > 0 {
                tx.execute_batch("ALTER TABLE settings RENAME TO settings_v7_backup;")?;
            }
            set_version(&tx, 8)?;
            tx.commit()?;
        }

        if version < 9 {
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "friends", "last_ip", "TEXT DEFAULT ''")?;
            Self::add_column_if_missing(&tx, "friends", "last_port", "INTEGER DEFAULT 0")?;
            Self::add_column_if_missing(&tx, "friends", "last_seen", "INTEGER DEFAULT 0")?;
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
            Self::add_column_if_missing(&tx, "friends", "mutual", "INTEGER NOT NULL DEFAULT 0")?;
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
            Self::add_column_if_missing(&tx, "friend_requests", "sender_ip", "TEXT DEFAULT ''")?;
            Self::add_column_if_missing(
                &tx,
                "friend_requests",
                "sender_port",
                "INTEGER DEFAULT 0",
            )?;
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
                );",
            )?;
            set_version(&tx, 12)?;
            tx.commit()?;
        }

        if version < 13 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE INDEX IF NOT EXISTS idx_chat_messages_read ON chat_messages(read);
                 CREATE INDEX IF NOT EXISTS idx_download_history_status ON download_history(status);",
            )?;
            set_version(&tx, 13)?;
            tx.commit()?;
        }

        if version < 14 {
            // Record whether each incoming friend request arrived on a
            // TCP channel where the peer's advertised Ed25519 pubkey
            // BLAKE3-bound to their claimed `ember_hash` (the offline
            // identity-binding check in
            // `crate::network::ember::crypto::verify_ember_hash_binding`).
            // Surfaces in the Friends UI as a "Verified" badge and is
            // taken into account by any future server-side checks that
            // gate friend-only features on a positive binding.
            //
            // Default `0` (unverified) for rows migrated from v13: we
            // have no record of the binding state of historical
            // requests, so the safest assumption is that they were
            // unverified. Re-sending a friend request will refresh the
            // flag per the latest exchange.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "friend_requests",
                "verified",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 14)?;
            tx.commit()?;
        }

        if version < 15 {
            // Phase 2 of the Ember Credit System: an enhanced credit
            // ledger keyed on the peer's 32-byte Ed25519 public key.
            // Sits alongside the existing eMule `credits` table rather
            // than replacing it — wire-compatible eMule peers continue
            // using the `credits` table via user_hash, and Ember peers
            // that completed PoP get a second higher-fidelity record
            // here that feeds decayed-ratio + reliability + speed
            // scoring.
            //
            // The pubkey column is `BLOB` (32 bytes) and acts as the
            // identity anchor — unlike user_hash it's cryptographically
            // bound to the peer's secret key, so this row can't be
            // farmed by spoofing the on-wire hash.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS ember_credits (
                    pub_key BLOB PRIMARY KEY,
                    uploaded INTEGER NOT NULL DEFAULT 0,
                    downloaded INTEGER NOT NULL DEFAULT 0,
                    last_upload_time INTEGER NOT NULL DEFAULT 0,
                    last_download_time INTEGER NOT NULL DEFAULT 0,
                    completed_sessions INTEGER NOT NULL DEFAULT 0,
                    total_sessions INTEGER NOT NULL DEFAULT 0,
                    avg_upload_speed INTEGER NOT NULL DEFAULT 0,
                    last_seen INTEGER NOT NULL DEFAULT 0,
                    ident_verified INTEGER NOT NULL DEFAULT 0
                );",
            )?;
            set_version(&tx, 15)?;
            tx.commit()?;
        }

        if version < 16 {
            // Notes (comments/ratings) we have explicitly published to the
            // KAD DHT. DHT note entries expire after ~24h, so we re-publish
            // them periodically; persisting the set here means republishing
            // survives restarts. `last_publish` is a Unix timestamp of the
            // most recent (re)publish. Distinct from `file_comments`, which
            // holds local comments on our *own* shared files exchanged over
            // ed2k and intentionally NOT broadcast to the DHT.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS published_notes (
                    file_hash TEXT PRIMARY KEY,
                    rating INTEGER NOT NULL DEFAULT 0,
                    comment TEXT NOT NULL DEFAULT '',
                    last_publish INTEGER NOT NULL DEFAULT 0
                );",
            )?;
            set_version(&tx, 16)?;
            tx.commit()?;
        }

        if version < 17 {
            // SecureIdent state for eMule credit records. Previously only
            // uploaded/downloaded/last_seen/public_key were persisted, so on
            // every restart `ident_ip` reset to 0 and `ident_state` to
            // Unknown. Because the Known Clients tab derives the last-known
            // IP *and* the country flag purely from `ident_ip`, both vanished
            // after a relaunch until the peer was seen again. Persisting them
            // makes those columns survive restarts. Defaults (0 / Unknown)
            // are correct for rows migrated from v16.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "credits", "ident_ip", "INTEGER NOT NULL DEFAULT 0")?;
            Self::add_column_if_missing(
                &tx,
                "credits",
                "ident_state",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 17)?;
            tx.commit()?;
        }

        if version < 18 {
            // Persistent store for *automatic* IP bans (corruption
            // blackbox, eMule-style AddRequestCount request-flooding).
            // Kept deliberately separate from the `peers` table so
            // machine-generated bans don't pollute the user-facing peer
            // list (and so the manual ban/unban UI, which is keyed on a
            // 32-hex user hash, never has to reason about bare IPs).
            //
            // `expires_at` is a Unix timestamp; 0 means "permanent".
            // Auto-bans set a finite expiry so the list is self-healing
            // and can't grow without bound the way the in-memory
            // `banned_ips` cache could before this existed. The startup
            // loader and the runtime `banned_ips` cap-reset both union
            // the non-expired rows back into the live ban set, so these
            // bans now survive both a restart and the 10k-entry cap
            // reset that previously discarded them.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS banned_ips (
                    ip TEXT PRIMARY KEY,
                    reason TEXT NOT NULL DEFAULT '',
                    banned_at INTEGER NOT NULL DEFAULT 0,
                    expires_at INTEGER NOT NULL DEFAULT 0
                );",
            )?;
            set_version(&tx, 18)?;
            tx.commit()?;
        }

        if version < 19 {
            // Preserve the file metadata that KAD note publishes need when
            // republishing after a restart and the file is not in our library.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "published_notes", "file_name", "TEXT")?;
            Self::add_column_if_missing(&tx, "published_notes", "file_size", "INTEGER")?;
            set_version(&tx, 19)?;
            tx.commit()?;
        }

        Ok(())
    }

    fn add_column_if_missing(
        conn: &Connection,
        table: &str,
        column: &str,
        col_type: &str,
    ) -> anyhow::Result<()> {
        let valid_ident =
            |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        let valid_col_type = |s: &str| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '\'')
        };
        if !valid_ident(table) || !valid_ident(column) || !valid_col_type(col_type) {
            anyhow::bail!("Invalid SQL identifier in migration: {table}.{column} {col_type}");
        }
        let has_column = conn
            .prepare(&format!("SELECT {column} FROM {table} LIMIT 0"))
            .is_ok();
        if !has_column {
            let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {col_type}");
            conn.execute(&sql, [])
                .map_err(|e| anyhow::anyhow!("Failed to add column {table}.{column}: {e}"))?;
            info!("Added column {table}.{column}");
        }
        Ok(())
    }

    pub fn save_peer(&self, peer: &PeerInfo) -> anyhow::Result<()> {
        let conn = self.conn.lock();
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
        conn.execute(
            "DELETE FROM peers WHERE id IN (
                SELECT id FROM peers
                ORDER BY last_seen DESC
                LIMIT -1 OFFSET ?1
            )",
            params![MAX_PEERS_ROWS],
        )?;
        Ok(())
    }

    pub fn get_peers(&self) -> anyhow::Result<Vec<PeerInfo>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, addresses, nickname, last_seen, files_shared, banned
             FROM peers
             ORDER BY last_seen DESC
             LIMIT ?1",
        )?;

        let peers = stmt
            .query_map(params![MAX_PEERS_ROWS], |row| {
                let addresses_str: String = row.get(1)?;
                let addresses: Vec<String> = serde_json::from_str(&addresses_str).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;
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
                Err(e) => {
                    tracing::warn!("Failed to read DB row: {e}");
                    None
                }
            })
            .collect();

        Ok(peers)
    }

    pub fn ban_peer(&self, peer_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO peers (id, banned) VALUES (?1, 1)
             ON CONFLICT(id) DO UPDATE SET banned = 1",
            params![peer_id],
        )?;
        Ok(())
    }

    pub fn unban_peer(&self, peer_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE peers SET banned = 0 WHERE id = ?1",
            params![peer_id],
        )?;
        Ok(())
    }

    /// Record `ip` as one of the addresses belonging to a (banned) peer.
    ///
    /// Used when a live upload session is torn down because its peer was
    /// banned by user-hash: the connecting IP may not have been in the
    /// routing table or peer DB at ban time, so without this it would not
    /// be cleared by `unban_peer` (which reverses a ban by walking the
    /// peer's known addresses). Storing it here makes ban/unban symmetric.
    /// The port is recorded as 0 (placeholder) — only the IP is ever used
    /// by the ban/unban paths, and boot-contact loading skips banned peers
    /// so the placeholder never produces a junk KAD contact. The row is
    /// upserted with `banned = 1` so a peer we only ever saw as an inbound
    /// uploader still exists for `unban_peer` to flip. Idempotent: an IP
    /// already present (under any port) is not duplicated.
    pub fn add_banned_peer_address(
        &self,
        peer_id: &str,
        ip: std::net::Ipv4Addr,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let existing: Option<String> = conn
            .query_row(
                "SELECT addresses FROM peers WHERE id = ?1",
                params![peer_id],
                |row| row.get(0),
            )
            .optional()?;
        let mut addresses: Vec<String> = existing
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();
        let ip_str = ip.to_string();
        let already_present = addresses.iter().any(|addr| {
            addr.rsplit_once(':')
                .map(|(host, _)| host == ip_str)
                .unwrap_or(addr.as_str() == ip_str)
        });
        if !already_present {
            addresses.push(format!("{ip_str}:0"));
        }
        let addresses_json = serde_json::to_string(&addresses)?;
        conn.execute(
            "INSERT INTO peers (id, addresses, banned) VALUES (?1, ?2, 1)
             ON CONFLICT(id) DO UPDATE SET addresses = excluded.addresses, banned = 1",
            params![peer_id, addresses_json],
        )?;
        Ok(())
    }

    /// Persist an automatic IP ban. `expires_at` is a Unix timestamp
    /// (0 = permanent). Re-banning an already-listed IP refreshes the
    /// reason and extends the expiry, never shortening an existing
    /// permanent ban down to a finite one.
    pub fn ban_ip(
        &self,
        ip: std::net::Ipv4Addr,
        reason: &str,
        expires_at: u64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        conn.execute(
            "INSERT INTO banned_ips (ip, reason, banned_at, expires_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(ip) DO UPDATE SET
               reason = excluded.reason,
               expires_at = CASE
                 WHEN banned_ips.expires_at = 0 OR excluded.expires_at = 0 THEN 0
                 ELSE MAX(banned_ips.expires_at, excluded.expires_at)
               END",
            params![
                ip.to_string(),
                reason,
                now as i64,
                expires_at.min(i64::MAX as u64) as i64
            ],
        )?;
        Ok(())
    }

    /// Remove an automatic IP ban.
    pub fn unban_ip(&self, ip: std::net::Ipv4Addr) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM banned_ips WHERE ip = ?1",
            params![ip.to_string()],
        )?;
        Ok(())
    }

    /// Load all auto-banned IPs that have not yet expired. Expired rows
    /// are pruned as a side effect so the table stays bounded.
    pub fn get_banned_ips(&self) -> anyhow::Result<Vec<std::net::Ipv4Addr>> {
        let conn = self.conn.lock();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0) as i64;
        conn.execute(
            "DELETE FROM banned_ips WHERE expires_at != 0 AND expires_at <= ?1",
            params![now],
        )?;
        let mut stmt = conn.prepare("SELECT ip FROM banned_ips")?;
        let ips = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .filter_map(|s| s.parse::<std::net::Ipv4Addr>().ok())
            .collect();
        Ok(ips)
    }

    pub fn save_transfer(&self, transfer: &Transfer) -> anyhow::Result<()> {
        let conn = self.conn.lock();
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
        let conn = self.conn.lock();
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
                    // Defense-in-depth: re-sanitize the persisted name on
                    // restore so a tampered DB row can't reintroduce path
                    // separators/traversal/reserved names into the path that
                    // gets built from it at finalize. Idempotent for names
                    // that were already sanitized when first written.
                    file_name: crate::security::sanitize_filename(&row.get::<_, String>(1)?),
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
                        // A corrupted or future-version status string must
                        // not silently resume as an active "searching"
                        // transfer (which would kick off network activity on
                        // load). Fall back to the inert Stopped state.
                        _ => TransferStatus::Stopped,
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
                    priority: row
                        .get::<_, String>(12)
                        .unwrap_or_else(|_| "normal".to_string()),
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
                    preview_ready: false,
                    ember_sources: 0,
                    client_software: String::new(),
                    country_code: None,
                    user_hash: None,
                    completed_path: None,
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

    pub fn transfer_exists(&self, transfer_id: &str) -> bool {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT 1 FROM transfers WHERE id = ?1",
            params![transfer_id],
            |_| Ok(()),
        )
        .is_ok()
    }

    pub fn remove_transfer(&self, transfer_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM transfers WHERE id = ?1", params![transfer_id])?;
        Ok(())
    }

    pub fn update_transfer_status(&self, transfer_id: &str, status: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
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
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE transfers
             SET transferred = ?1, progress = ?2, speed = ?3
             WHERE id = ?4",
            params![
                i64::try_from(transferred).unwrap_or(i64::MAX),
                progress,
                i64::try_from(speed).unwrap_or(i64::MAX),
                transfer_id
            ],
        )?;
        Ok(())
    }

    pub fn update_transfer_priority(
        &self,
        transfer_id: &str,
        priority: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE transfers SET priority = ?1 WHERE id = ?2",
            params![priority, transfer_id],
        )?;
        Ok(())
    }

    pub fn update_transfer_category(
        &self,
        transfer_id: &str,
        category: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE transfers SET category = ?1 WHERE id = ?2",
            params![category, transfer_id],
        )?;
        Ok(())
    }

    pub fn load_credits(&self) -> anyhow::Result<Vec<([u8; 16], u64, u64, i64, Vec<u8>, u32, u8)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT user_hash, uploaded, downloaded, last_seen, public_key, ident_ip, ident_state FROM credits")?;
        let records = stmt
            .query_map([], |row| {
                let hash_blob: Vec<u8> = row.get(0)?;
                if hash_blob.len() < 16 {
                    return Err(rusqlite::Error::InvalidColumnType(
                        0,
                        "user_hash too short".into(),
                        rusqlite::types::Type::Blob,
                    ));
                }
                let mut hash = [0u8; 16];
                hash.copy_from_slice(&hash_blob[..16]);
                Ok((
                    hash,
                    row.get::<_, i64>(1)?.max(0) as u64,
                    row.get::<_, i64>(2)?.max(0) as u64,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    // ident_ip is a 32-bit IPv4 stored as INTEGER; clamp to the
                    // u32 range defensively in case of a malformed row.
                    row.get::<_, i64>(5)?.clamp(0, u32::MAX as i64) as u32,
                    row.get::<_, i64>(6)?.clamp(0, u8::MAX as i64) as u8,
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
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT key, value FROM statistics")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
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
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt =
                tx.prepare("INSERT OR REPLACE INTO statistics (key, value) VALUES (?1, ?2)")?;
            for (key, value) in pairs {
                stmt.execute(params![key, value])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_file_comments(&self) -> anyhow::Result<Vec<(String, u8, String)>> {
        let conn = self.conn.lock();
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

    pub fn save_file_comment(
        &self,
        file_hash: &str,
        rating: u8,
        comment: &str,
    ) -> anyhow::Result<()> {
        // Defense-in-depth cap matching the IPC layer
        // (`commands/comments.rs::set_file_comment`). The IPC entry point
        // already rejects > 4096-byte comments, but enforcing it again
        // here protects against future internal callers that might skip
        // the validation step. 4096 matches eMule's on-wire limit so we
        // don't write something the protocol couldn't carry.
        const MAX_COMMENT_BYTES: usize = 4096;
        if comment.len() > MAX_COMMENT_BYTES {
            return Err(anyhow::anyhow!(
                "comment too long ({} bytes > {} max)",
                comment.len(),
                MAX_COMMENT_BYTES
            ));
        }
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO file_comments (file_hash, rating, comment) VALUES (?1, ?2, ?3)",
            params![file_hash, rating as i32, comment],
        )?;
        Ok(())
    }

    /// Load every note we have published to the KAD DHT, along with the
    /// timestamp of its last (re)publish. Used at startup to seed the
    /// periodic notes-republish loop so our comments/ratings keep refreshing
    /// after a restart instead of silently expiring from the network.
    pub fn load_published_notes(
        &self,
    ) -> anyhow::Result<Vec<(String, u8, String, i64, Option<String>, Option<u64>)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT file_hash, rating, comment, last_publish, file_name, file_size FROM published_notes",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    (row.get::<_, i32>(1)?).clamp(0, 5) as u8,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<u64>>(5)?,
                ))
            })?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!("Skipping malformed published note row: {e}");
                    None
                }
            })
            .collect();
        Ok(rows)
    }

    /// Record (or refresh) a note we have published to the DHT. `last_publish`
    /// is the Unix timestamp of this publish so the republish loop can tell
    /// when the entry is due to be pushed again.
    pub fn save_published_note(
        &self,
        file_hash: &str,
        rating: u8,
        comment: &str,
        last_publish: i64,
        file_name: Option<&str>,
        file_size: Option<u64>,
    ) -> anyhow::Result<()> {
        const MAX_COMMENT_BYTES: usize = 4096;
        if comment.len() > MAX_COMMENT_BYTES {
            return Err(anyhow::anyhow!(
                "comment too long ({} bytes > {} max)",
                comment.len(),
                MAX_COMMENT_BYTES
            ));
        }
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO published_notes \
             (file_hash, rating, comment, last_publish, file_name, file_size) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                file_hash,
                rating as i32,
                comment,
                last_publish,
                file_name,
                file_size
            ],
        )?;
        Ok(())
    }

    /// Persist the full credit ledger as a single atomic replacement.
    /// The previous implementation only ran `INSERT OR REPLACE` per row,
    /// which meant rows pruned in memory by `CreditManager::cleanup_stale`
    /// were left behind in the database. On the next launch the loader
    /// would resurrect those stale rows and the in-memory eviction
    /// would have to run again — visible as a Known Clients tab that
    /// kept showing months-old "Unknown" peers across restarts even
    /// after the periodic pruner had supposedly cleaned them up.
    ///
    /// `DELETE FROM credits` followed by the INSERTs inside one
    /// transaction guarantees the table mirrors the in-memory snapshot
    /// exactly. SQLite's transaction guarantees that either the whole
    /// replacement lands or nothing changes, so a crash mid-flush won't
    /// leave the table empty.
    // Retained as a focused, unit-tested building block (full-replacement
    // semantics); production flushes go through `save_all_credits_with_ember`.
    #[allow(dead_code)]
    pub fn save_all_credits(
        &self,
        credits: &[(&[u8; 16], u64, u64, i64, &[u8], u32, u8)],
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM credits", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO credits (user_hash, uploaded, downloaded, last_seen, public_key, ident_ip, ident_state) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
            )?;
            for (hash, uploaded, downloaded, last_seen, public_key, ident_ip, ident_state) in
                credits
            {
                stmt.execute(params![
                    &hash[..],
                    i64::try_from(*uploaded).unwrap_or(i64::MAX),
                    i64::try_from(*downloaded).unwrap_or(i64::MAX),
                    *last_seen,
                    *public_key,
                    i64::from(*ident_ip),
                    i64::from(*ident_state)
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Load persisted Ember credit records. Returns raw field tuples so
    /// the caller can rehydrate `EmberCreditRecord` without this layer
    /// depending on the credit types — same pattern as
    /// `load_credits`.
    ///
    /// Field order matches the v15 schema and the
    /// `save_all_ember_credits` INSERT statement: pubkey, uploaded,
    /// downloaded, last_upload_time, last_download_time,
    /// completed_sessions, total_sessions, avg_upload_speed, last_seen,
    /// ident_verified.
    #[allow(clippy::type_complexity)]
    pub fn load_ember_credits(
        &self,
    ) -> anyhow::Result<Vec<([u8; 32], u64, u64, i64, i64, u32, u32, u64, i64, bool)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT pub_key, uploaded, downloaded, last_upload_time, last_download_time, \
                    completed_sessions, total_sessions, avg_upload_speed, last_seen, ident_verified \
             FROM ember_credits",
        )?;
        let records = stmt
            .query_map([], |row| {
                let pk_blob: Vec<u8> = row.get(0)?;
                // M10: strict 32-byte pub_key. Previously a row with
                // a >32 byte blob silently truncated to the first 32
                // bytes, which would alias two distinct Ed25519 keys
                // onto a single credit account if any non-conformant
                // row ever appeared. We now reject anything that
                // isn't exactly 32 bytes; the row is logged + skipped
                // by the `filter_map` below rather than being merged
                // into the wrong account.
                if pk_blob.len() != 32 {
                    return Err(rusqlite::Error::InvalidColumnType(
                        0,
                        format!("pub_key must be 32 bytes, got {}", pk_blob.len()),
                        rusqlite::types::Type::Blob,
                    ));
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&pk_blob);
                Ok((
                    pk,
                    row.get::<_, i64>(1)?.max(0) as u64,
                    row.get::<_, i64>(2)?.max(0) as u64,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?.max(0) as u32,
                    row.get::<_, i64>(6)?.max(0) as u32,
                    row.get::<_, i64>(7)?.max(0) as u64,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)? != 0,
                ))
            })?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!("Skipping malformed ember_credits row: {e}");
                    None
                }
            })
            .collect();
        Ok(records)
    }

    /// Full-replacement save for the Ember credit table — same
    /// contract as `save_all_credits`: DELETE followed by INSERT
    /// inside one transaction so on-disk state matches the
    /// in-memory `CreditManager.ember_credits` snapshot exactly. A
    /// crash mid-flush leaves the pre-save rows intact thanks to
    /// SQLite's all-or-nothing transaction guarantee.
    #[allow(clippy::type_complexity, dead_code)]
    pub fn save_all_ember_credits(
        &self,
        credits: &[(&[u8; 32], u64, u64, i64, i64, u32, u32, u64, i64, bool)],
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM ember_credits", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO ember_credits (\
                    pub_key, uploaded, downloaded, last_upload_time, last_download_time, \
                    completed_sessions, total_sessions, avg_upload_speed, last_seen, ident_verified\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            for (
                pk,
                up,
                down,
                last_up,
                last_down,
                completed,
                total,
                avg_speed,
                last_seen,
                verified,
            ) in credits
            {
                stmt.execute(params![
                    &pk[..],
                    i64::try_from(*up).unwrap_or(i64::MAX),
                    i64::try_from(*down).unwrap_or(i64::MAX),
                    *last_up,
                    *last_down,
                    i64::from(*completed),
                    i64::from(*total),
                    i64::try_from(*avg_speed).unwrap_or(i64::MAX),
                    *last_seen,
                    i64::from(*verified),
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Full-replacement save of BOTH credit tables inside a SINGLE
    /// transaction, so the `credits` and `ember_credits` tables can never
    /// diverge across a crash or a partial failure. The previous code ran
    /// `save_all_credits` and `save_all_ember_credits` as two independent
    /// committed transactions back-to-back; if the second failed (or the
    /// process died between them) the two tables ended up inconsistent
    /// despite a comment claiming "either both land or neither". Both
    /// DELETE+INSERT pairs now share one `tx`, restoring that guarantee.
    #[allow(clippy::type_complexity)]
    pub fn save_all_credits_with_ember(
        &self,
        credits: &[(&[u8; 16], u64, u64, i64, &[u8], u32, u8)],
        ember_credits: &[(&[u8; 32], u64, u64, i64, i64, u32, u32, u64, i64, bool)],
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM credits", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO credits (user_hash, uploaded, downloaded, last_seen, public_key, ident_ip, ident_state) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
            )?;
            for (hash, uploaded, downloaded, last_seen, public_key, ident_ip, ident_state) in
                credits
            {
                stmt.execute(params![
                    &hash[..],
                    i64::try_from(*uploaded).unwrap_or(i64::MAX),
                    i64::try_from(*downloaded).unwrap_or(i64::MAX),
                    *last_seen,
                    *public_key,
                    i64::from(*ident_ip),
                    i64::from(*ident_state)
                ])?;
            }
        }
        tx.execute("DELETE FROM ember_credits", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO ember_credits (\
                    pub_key, uploaded, downloaded, last_upload_time, last_download_time, \
                    completed_sessions, total_sessions, avg_upload_speed, last_seen, ident_verified\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            for (
                pk,
                up,
                down,
                last_up,
                last_down,
                completed,
                total,
                avg_speed,
                last_seen,
                verified,
            ) in ember_credits
            {
                stmt.execute(params![
                    &pk[..],
                    i64::try_from(*up).unwrap_or(i64::MAX),
                    i64::try_from(*down).unwrap_or(i64::MAX),
                    *last_up,
                    *last_down,
                    i64::from(*completed),
                    i64::from(*total),
                    i64::try_from(*avg_speed).unwrap_or(i64::MAX),
                    *last_seen,
                    i64::from(*verified),
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn add_friend(&self, user_hash: &str, nickname: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO friends (user_hash, nickname, added_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(user_hash) DO UPDATE SET nickname = excluded.nickname",
            params![user_hash, nickname, now],
        )?;
        Ok(())
    }

    pub fn remove_friend(&self, user_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM chat_messages WHERE friend_hash = ?1",
            params![user_hash],
        )?;
        tx.execute(
            "DELETE FROM friends WHERE user_hash = ?1",
            params![user_hash],
        )?;
        tx.execute(
            "DELETE FROM friend_requests WHERE sender_hash = ?1",
            params![user_hash],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_friends(&self) -> anyhow::Result<Vec<(String, String, i64)>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT user_hash, nickname, added_at FROM friends ORDER BY added_at DESC")?;
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

    /// Update the nickname for an existing friend. Returns `Ok(true)`
    /// if the row existed and was updated, `Ok(false)` if no friend
    /// matches `user_hash` (so the caller can surface a real error
    /// instead of silently succeeding).
    pub fn update_friend_nickname(&self, user_hash: &str, nickname: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let updated = conn.execute(
            "UPDATE friends SET nickname = ?2 WHERE user_hash = ?1",
            params![user_hash, nickname],
        )?;
        Ok(updated > 0)
    }

    pub fn update_friend_address(
        &self,
        user_hash: &str,
        ip: &str,
        port: u16,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "UPDATE friends SET last_ip = ?2, last_port = ?3, last_seen = ?4 WHERE user_hash = ?1",
            params![user_hash, ip, port as i64, now],
        )?;
        Ok(())
    }

    pub fn clear_friend_address(&self, user_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE friends SET last_ip = '', last_port = 0 WHERE user_hash = ?1",
            params![user_hash],
        )?;
        Ok(())
    }

    pub fn get_friend_address(&self, user_hash: &str) -> anyhow::Result<Option<(String, u16)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT COALESCE(last_ip, ''), COALESCE(last_port, 0) FROM friends WHERE user_hash = ?1"
        )?;
        let result = stmt.query_row(params![user_hash], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?.clamp(0, u16::MAX as i64) as u16,
            ))
        });
        match result {
            Ok((ip, port)) if !ip.is_empty() && port > 0 => Ok(Some((ip, port))),
            Ok(_) => Ok(None),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_friends_full(
        &self,
    ) -> anyhow::Result<Vec<(String, String, i64, String, u16, i64, bool)>> {
        let conn = self.conn.lock();
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

    pub fn add_friend_request(
        &self,
        sender_hash: &str,
        nickname: &str,
        sender_ip: &str,
        sender_port: u16,
        verified: bool,
    ) -> anyhow::Result<()> {
        let mut conn = self.conn.lock();
        let now = chrono::Utc::now().timestamp();
        let tx = conn.transaction()?;

        // M2: cap total inbound `friend_requests` rows. Per-sender
        // UPSERT below already prevents same-hash flooding, but an
        // attacker that iterates random ember_hashes from EPX
        // dumps could otherwise grow this table without bound and
        // (a) consume disk, (b) hide legitimate requests under a
        // sea of spoofed ones in the UI list. We pick 100 unique
        // pending requests as a generous practical ceiling. When
        // overflowing, evict the oldest **unverified** rows first,
        // then the oldest verified row only if every row is
        // verified (which keeps a real request from being
        // displaced by a flood of unverified noise). A repeat
        // request from a sender already present is exempt from
        // the cap — it just refreshes the existing row via the
        // UPSERT.
        const MAX_FRIEND_REQUESTS: i64 = 100;
        let already_present: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM friend_requests WHERE sender_hash = ?1",
                params![sender_hash],
                |row| row.get(0),
            )
            .unwrap_or(0);
        if already_present == 0 {
            let total: i64 = tx
                .query_row("SELECT COUNT(*) FROM friend_requests", [], |row| row.get(0))
                .unwrap_or(0);
            if total >= MAX_FRIEND_REQUESTS {
                let to_evict = (total - MAX_FRIEND_REQUESTS + 1).max(1);
                let evicted_unverified = tx.execute(
                    "DELETE FROM friend_requests WHERE sender_hash IN (
                        SELECT sender_hash FROM friend_requests
                        WHERE COALESCE(verified, 0) = 0
                        ORDER BY received_at ASC
                        LIMIT ?1
                    )",
                    params![to_evict],
                )? as i64;
                let remaining = to_evict - evicted_unverified;
                if remaining > 0 {
                    tx.execute(
                        "DELETE FROM friend_requests WHERE sender_hash IN (
                            SELECT sender_hash FROM friend_requests
                            ORDER BY received_at ASC
                            LIMIT ?1
                        )",
                        params![remaining],
                    )?;
                }
            }
        }

        // Refresh behaviour: a repeat request from the same peer
        // can legitimately change any of the fields on the row,
        // including the verification flag (e.g. an older request
        // arrived on an unverified path, a later one on a verified
        // path). We preserve the "verified once, always verified"
        // monotonicity across refreshes so a spoofer can't silently
        // *downgrade* an existing verified request by flooding
        // unverified requests from another channel — a legitimate
        // re-request from the real user always raises the flag or
        // leaves it unchanged, never lowers it.
        tx.execute(
            "INSERT INTO friend_requests (sender_hash, sender_nickname, received_at, sender_ip, sender_port, verified)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(sender_hash) DO UPDATE SET sender_nickname = excluded.sender_nickname,
             sender_ip = excluded.sender_ip, sender_port = excluded.sender_port,
             verified = MAX(friend_requests.verified, excluded.verified)",
            params![sender_hash, nickname, now, sender_ip, sender_port as i64, verified as i64],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_friend_requests(
        &self,
    ) -> anyhow::Result<Vec<(String, String, i64, String, u16, bool)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT sender_hash, sender_nickname, received_at, COALESCE(sender_ip, ''), COALESCE(sender_port, 0), COALESCE(verified, 0) FROM friend_requests ORDER BY received_at DESC"
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?.clamp(0, u16::MAX as i64) as u16,
                    row.get::<_, i64>(5)? != 0,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn remove_friend_request(&self, sender_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM friend_requests WHERE sender_hash = ?1",
            params![sender_hash],
        )?;
        Ok(())
    }

    /// Atomic "accept friend request" path used by the
    /// `accept_friend_request` Tauri command.
    ///
    /// In a single transaction:
    ///   1. Read the matching `friend_requests` row (if any) so we can
    ///      seed the new friend's nickname and last-known address from
    ///      what the peer sent at request time.
    ///   2. Insert / update the `friends` row with `mutual = 1`,
    ///      preserving the inserted `added_at` for first-time rows.
    ///   3. If the request carried a usable IP / port, write them onto
    ///      the friend so the auto-connect path in `SendChatMessage` /
    ///      `BrowseFriend` can dial directly without paying for a
    ///      rendezvous round trip.
    ///   4. Delete the originating `friend_requests` row.
    ///
    /// Returns the (nickname, ip, port) tuple that was on the request,
    /// or `None` if no matching request existed (e.g. user accepted via
    /// stale UI state). The caller can use the returned address as a
    /// hint for an immediate friend-session dial.
    ///
    /// Doing this transactionally fixes a subtle inconsistency where
    /// the previous implementation issued three independent
    /// `conn.execute` calls; if `set_friend_mutual` failed mid-way the
    /// row would persist with `mutual = 0` while the in-memory
    /// `friend_hashes` set was rolled back, leaving `get_friends()`
    /// reporting an orphan friend that the upload path's
    /// `friend_hashes.contains(&eh)` gate would silently reject.
    pub fn accept_friend_request(
        &self,
        sender_hash: &str,
    ) -> anyhow::Result<Option<(String, String, u16)>> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;

        let request_data: Option<(String, String, u16)> = {
            let mut stmt = tx.prepare(
                "SELECT sender_nickname, COALESCE(sender_ip, ''), COALESCE(sender_port, 0) \
                 FROM friend_requests WHERE sender_hash = ?1",
            )?;
            stmt.query_row(params![sender_hash], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?.clamp(0, u16::MAX as i64) as u16,
                ))
            })
            .ok()
        };

        // Refuse to "accept" a request that no longer exists. Without this a
        // stale accept (the row was withdrawn, rejected in another window, or
        // aged out of the 100-row cap) would still INSERT a `mutual = 1`
        // friend with an empty nickname and no address — a "ghost" friend the
        // user never knowingly added. The caller surfaces this as a "request
        // no longer exists" error and drops the row from the UI.
        let request_data = match request_data {
            Some(data) => data,
            None => anyhow::bail!("friend request not found"),
        };

        let nickname = request_data.0.clone();
        let now = chrono::Utc::now().timestamp();

        // Insert the friend with `mutual = 1` directly (matches the
        // previous `add_friend` + `set_friend_mutual` semantics). On
        // conflict we refresh the nickname and re-assert mutual so a
        // re-accept after a previous demotion still flips the flag.
        // `added_at` is intentionally NOT overwritten on conflict so
        // long-standing friends keep their original add timestamp.
        tx.execute(
            "INSERT INTO friends (user_hash, nickname, added_at, mutual) VALUES (?1, ?2, ?3, 1) \
             ON CONFLICT(user_hash) DO UPDATE SET nickname = excluded.nickname, mutual = 1",
            params![sender_hash, nickname, now],
        )?;

        {
            let (_, ref ip, port) = request_data;
            if !ip.is_empty() && port > 0 {
                tx.execute(
                    "UPDATE friends SET last_ip = ?2, last_port = ?3, last_seen = ?4 WHERE user_hash = ?1",
                    params![sender_hash, ip, port as i64, now],
                )?;
            }
        }

        tx.execute(
            "DELETE FROM friend_requests WHERE sender_hash = ?1",
            params![sender_hash],
        )?;
        tx.commit()?;
        Ok(Some(request_data))
    }

    /// Promote an existing friend to mutual and refresh their last-known
    /// address. Used by the auto-confirm path: an inbound friend request from
    /// a peer we already added, when the user has turned off "require
    /// approval". Unlike `accept_friend_request` this does not touch the
    /// `friend_requests` table (no queued row exists in that flow). Returns
    /// the number of friend rows updated — 0 means the peer wasn't actually in
    /// the friend list, so the caller should fall back to queuing.
    pub fn set_friend_mutual(&self, user_hash: &str, ip: &str, port: u16) -> anyhow::Result<usize> {
        let conn = self.conn.lock();
        let now = chrono::Utc::now().timestamp();
        let updated = if !ip.is_empty() && port > 0 {
            conn.execute(
                "UPDATE friends SET mutual = 1, last_ip = ?2, last_port = ?3, last_seen = ?4 WHERE user_hash = ?1",
                params![user_hash, ip, port as i64, now],
            )?
        } else {
            conn.execute(
                "UPDATE friends SET mutual = 1 WHERE user_hash = ?1",
                params![user_hash],
            )?
        };
        Ok(updated)
    }

    pub fn insert_chat_message(
        &self,
        friend_hash: &str,
        direction: &str,
        message: &str,
    ) -> anyhow::Result<i64> {
        // Cap stored message length. Incoming chat text comes straight off
        // the wire from a peer, so bound it here (on a char boundary, so we
        // never split a multi-byte sequence) to stop a hostile friend from
        // bloating the DB with a single huge message. 4 KiB matches the
        // comment-length ceiling used elsewhere.
        const MAX_CHAT_MESSAGE_LEN: usize = 4096;
        let message: &str = if message.len() > MAX_CHAT_MESSAGE_LEN {
            let mut end = MAX_CHAT_MESSAGE_LEN;
            while end > 0 && !message.is_char_boundary(end) {
                end -= 1;
            }
            &message[..end]
        } else {
            message
        };
        // Per-friend retention cap. The frontend chat sidebar paginates
        // the most-recent messages, so storing more than this provides
        // no UX benefit while letting `chat_messages` grow without
        // bound across long-lived friendships. 5000 messages per friend
        // covers months-to-years of normal conversation; beyond that we
        // age out the oldest entries on insert so the DB stays compact.
        const MAX_MESSAGES_PER_FRIEND: i64 = 5_000;
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let now = chrono::Utc::now().timestamp();
        tx.execute(
            "INSERT INTO chat_messages (friend_hash, direction, message, timestamp, read) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![friend_hash, direction, message, now, if direction == "sent" { 1 } else { 0 }],
        )?;
        let new_id = tx.last_insert_rowid();
        // Trim oldest messages above the cap. SQLite's `LIMIT -1 OFFSET ?`
        // means "everything past the first ? newest rows"; we delete
        // those. Friend hash is already validated upstream so we can
        // pass it directly into the parameterised SQL.
        tx.execute(
            "DELETE FROM chat_messages WHERE id IN (
                 SELECT id FROM chat_messages
                 WHERE friend_hash = ?1
                 ORDER BY id DESC
                 LIMIT -1 OFFSET ?2
             )",
            params![friend_hash, MAX_MESSAGES_PER_FRIEND],
        )?;
        tx.commit()?;
        Ok(new_id)
    }

    pub fn get_chat_messages(
        &self,
        friend_hash: &str,
        limit: i64,
        before_id: Option<i64>,
    ) -> anyhow::Result<Vec<(i64, String, String, i64, bool)>> {
        let conn = self.conn.lock();
        if let Some(bid) = before_id {
            let mut stmt = conn.prepare(
                "SELECT id, direction, message, timestamp, read FROM chat_messages WHERE friend_hash = ?1 AND id < ?2 ORDER BY id DESC LIMIT ?3"
            )?;
            let rows = stmt
                .query_map(params![friend_hash, bid, limit], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get::<_, i64>(4)? != 0,
                    ))
                })?
                .filter_map(|r| r.ok())
                .collect();
            Ok(rows)
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, direction, message, timestamp, read FROM chat_messages WHERE friend_hash = ?1 ORDER BY id DESC LIMIT ?2"
            )?;
            let rows = stmt
                .query_map(params![friend_hash, limit], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get::<_, i64>(4)? != 0,
                    ))
                })?
                .filter_map(|r| r.ok())
                .collect();
            Ok(rows)
        }
    }

    pub fn mark_messages_read(&self, friend_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE chat_messages SET read = 1 WHERE friend_hash = ?1 AND read = 0",
            params![friend_hash],
        )?;
        Ok(())
    }

    pub fn unread_message_counts(&self) -> anyhow::Result<Vec<(String, i64)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT friend_hash, COUNT(*) FROM chat_messages WHERE read = 0 GROUP BY friend_hash",
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
        {
            let conn = self.conn.lock();
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
        // Bound the stored file name (on a char boundary). Names originate
        // from peer-supplied metadata, so a hostile source could otherwise
        // persist an oversized string. eD2K names don't exceed ~255 bytes in
        // practice; 1 KiB is generous headroom.
        const MAX_HISTORY_NAME_LEN: usize = 1024;
        let file_name: &str = if file_name.len() > MAX_HISTORY_NAME_LEN {
            let mut end = MAX_HISTORY_NAME_LEN;
            while end > 0 && !file_name.is_char_boundary(end) {
                end -= 1;
            }
            &file_name[..end]
        } else {
            file_name
        };
        let conn = self.conn.lock();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO download_history (file_hash, file_name, file_size, status, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(file_hash) DO UPDATE SET
               file_name = excluded.file_name,
               file_size = excluded.file_size,
               status = excluded.status,
               timestamp = excluded.timestamp",
            params![
                file_hash,
                file_name,
                i64::try_from(file_size).unwrap_or(i64::MAX),
                status,
                now
            ],
        )?;
        conn.execute(
            "DELETE FROM download_history WHERE file_hash IN (
                SELECT file_hash FROM download_history
                ORDER BY timestamp DESC
                LIMIT -1 OFFSET ?1
            )",
            params![MAX_DOWNLOAD_HISTORY_ROWS],
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
        let conn = self.conn.lock();
        let mut result = std::collections::HashMap::new();
        const CHUNK_SIZE: usize = 900;
        for chunk in hashes.chunks(CHUNK_SIZE) {
            let placeholders: Vec<String> = (1..=chunk.len()).map(|i| format!("?{i}")).collect();
            let sql = format!(
                "SELECT file_hash, status FROM download_history WHERE file_hash IN ({})",
                placeholders.join(",")
            );
            let mut stmt = conn.prepare(&sql)?;
            let params: Vec<&dyn rusqlite::ToSql> =
                chunk.iter().map(|h| h as &dyn rusqlite::ToSql).collect();
            let rows = stmt
                .query_map(params.as_slice(), |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .filter_map(|r| r.ok());
            for (hash, status) in rows {
                result.insert(hash, status);
            }
        }
        Ok(result)
    }

    /// Remove a specific file from download history (per-row user override).
    pub fn remove_download_history(&self, file_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM download_history WHERE file_hash = ?1",
            params![file_hash],
        )?;
        Ok(())
    }

    /// Clear all download history entries of a given status.
    pub fn clear_download_history(&self, status: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM download_history WHERE status = ?1",
            params![status],
        )?;
        Ok(())
    }

    /// Count download-history rows by status for the settings summary.
    pub fn get_download_history_counts(&self) -> anyhow::Result<(i64, i64)> {
        let conn = self.conn.lock();
        let completed: i64 = conn.query_row(
            "SELECT COUNT(*) FROM download_history WHERE status = 'completed'",
            [],
            |row| row.get(0),
        )?;
        let cancelled: i64 = conn.query_row(
            "SELECT COUNT(*) FROM download_history WHERE status = 'cancelled'",
            [],
            |row| row.get(0),
        )?;
        Ok((completed, cancelled))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `Database` backed by an in-memory SQLite connection plus
    /// just the `credits` table, so we can exercise the credit save /
    /// load round-trip without needing a `tauri::AppHandle`.
    fn credits_only_db() -> Database {
        let conn = Connection::open_in_memory().expect("open in-memory");
        conn.execute_batch(
            "CREATE TABLE credits (
                user_hash BLOB PRIMARY KEY,
                uploaded INTEGER NOT NULL DEFAULT 0,
                downloaded INTEGER NOT NULL DEFAULT 0,
                last_seen INTEGER NOT NULL DEFAULT 0,
                public_key BLOB NOT NULL DEFAULT x'',
                ident_ip INTEGER NOT NULL DEFAULT 0,
                ident_state INTEGER NOT NULL DEFAULT 0
            );",
        )
        .expect("create schema");
        Database {
            conn: Mutex::new(conn),
        }
    }

    /// Regression: `save_all_credits` MUST act as a full replacement so
    /// records pruned in memory by `CreditManager::cleanup_stale` are
    /// also dropped from the persisted table. Before this was a bare
    /// `INSERT OR REPLACE`, the database accumulated stale rows
    /// indefinitely — visible as a Known Clients tab that kept showing
    /// months-old peers across restarts even though the in-memory
    /// pruner was running on the periodic timer.
    #[test]
    fn save_all_credits_is_a_full_replacement() {
        let db = credits_only_db();
        let h1 = [0x01u8; 16];
        let h2 = [0x02u8; 16];
        let h3 = [0x03u8; 16];
        let pk: &[u8] = &[0xAA; 4];

        // Seed three records.
        db.save_all_credits(&[
            (&h1, 100, 200, 1_700_000_000, pk, 0, 0),
            (&h2, 300, 400, 1_700_000_001, pk, 0x0102_0304, 1),
            (&h3, 500, 600, 1_700_000_002, pk, 0, 0),
        ])
        .expect("seed");
        let loaded = db.load_credits().expect("reload after seed");
        assert_eq!(loaded.len(), 3, "seed must persist three records");

        // Re-save with only one of the three. The other two represent
        // stale records the in-memory pruner has just dropped — they
        // must NOT survive in the database.
        db.save_all_credits(&[(&h2, 999, 888, 1_700_000_999, pk, 0x0102_0304, 1)])
            .expect("replace");
        let after = db.load_credits().expect("reload after replace");
        assert_eq!(after.len(), 1, "stale records must not persist");
        assert_eq!(after[0].0, h2);
        // And the surviving row must reflect the latest values, not a
        // mix of the original seed and the new save.
        assert_eq!(after[0].1, 999);
        assert_eq!(after[0].2, 888);
        assert_eq!(after[0].3, 1_700_000_999);
        // ident_ip / ident_state must round-trip so the Known Clients tab
        // keeps the peer's last IP + country flag across restarts.
        assert_eq!(after[0].5, 0x0102_0304, "ident_ip must persist");
        assert_eq!(after[0].6, 1, "ident_state must persist");
    }

    /// Saving an empty slice must clear every existing row — the only
    /// way to "wipe credits" is to flush an empty `CreditManager`, and
    /// that has to actually empty the table.
    #[test]
    fn save_all_credits_with_empty_input_clears_table() {
        let db = credits_only_db();
        let h1 = [0x01u8; 16];
        db.save_all_credits(&[(&h1, 1, 1, 0, &[], 0, 0)])
            .expect("seed");
        assert_eq!(db.load_credits().expect("reload").len(), 1);

        db.save_all_credits(&[]).expect("empty save");
        assert!(db.load_credits().expect("reload empty").is_empty());
    }

    /// In-memory `Database` with just the `banned_ips` table for
    /// exercising the auto-ban persistence round-trip.
    fn banned_ips_db() -> Database {
        let conn = Connection::open_in_memory().expect("open in-memory");
        conn.execute_batch(
            "CREATE TABLE banned_ips (
                ip TEXT PRIMARY KEY,
                reason TEXT NOT NULL DEFAULT '',
                banned_at INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER NOT NULL DEFAULT 0
            );",
        )
        .expect("create schema");
        Database {
            conn: Mutex::new(conn),
        }
    }

    #[test]
    fn banned_ip_roundtrip_and_unban() {
        let db = banned_ips_db();
        let ip: std::net::Ipv4Addr = "203.0.113.7".parse().unwrap();
        db.ban_ip(ip, "test", 0).expect("ban");
        assert_eq!(db.get_banned_ips().expect("load"), vec![ip]);
        db.unban_ip(ip).expect("unban");
        assert!(db.get_banned_ips().expect("load after unban").is_empty());
    }

    #[test]
    fn expired_bans_are_pruned_on_load() {
        let db = banned_ips_db();
        let live: std::net::Ipv4Addr = "203.0.113.1".parse().unwrap();
        let expired: std::net::Ipv4Addr = "203.0.113.2".parse().unwrap();
        let permanent: std::net::Ipv4Addr = "203.0.113.3".parse().unwrap();
        db.ban_ip(live, "live", u64::MAX).expect("ban live");
        db.ban_ip(expired, "expired", 1).expect("ban expired"); // expired far in the past
        db.ban_ip(permanent, "permanent", 0).expect("ban permanent");
        let mut loaded = db.get_banned_ips().expect("load");
        loaded.sort();
        assert_eq!(loaded, vec![live, permanent], "expired ban must be pruned");
    }

    /// Re-banning never shortens a permanent ban into a finite one, and
    /// extends a finite ban to the later expiry.
    #[test]
    fn reban_expiry_merge_rules() {
        let db = banned_ips_db();
        let ip: std::net::Ipv4Addr = "203.0.113.9".parse().unwrap();
        db.ban_ip(ip, "perm", 0).expect("perm");
        db.ban_ip(ip, "finite", 100).expect("finite");
        // Still permanent (present despite the finite re-ban being in the past).
        assert_eq!(db.get_banned_ips().expect("load"), vec![ip]);
    }
}
