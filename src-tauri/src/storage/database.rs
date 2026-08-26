use parking_lot::Mutex;

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key as ChaChaKey, XChaCha20Poly1305, XNonce};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, ErrorCode, OptionalExtension};
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::network::ed2k::transfer::TransferFailureCode;
use crate::storage::paths;
use crate::types::*;

const MAX_PEERS_ROWS: i64 = 10_000;
const MAX_DOWNLOAD_HISTORY_ROWS: i64 = 5_000;
/// Rooms kept in the Discover cache. Far more than a browse can usefully show,
/// and small enough that the table stays a rounding error on disk.
const MAX_CHANNEL_CACHE_ROWS: i64 = 500;
/// A cached listing this old has been absent from the DHT for many times the
/// index record's own lifetime, so offering it would only send the user at a
/// room that no longer answers.
const CHANNEL_CACHE_MAX_AGE_SECS: i64 = 30 * 24 * 3600;
/// Highest `schema_version` this build knows how to open. Opening a newer
/// database, or restoring a backup taken from one, would invite subtle
/// corruption (missing columns, renamed tables, changed semantics), so both
/// paths refuse instead. Bump this when introducing a new migration.
pub const MAX_SUPPORTED_SCHEMA_VERSION: i64 = 37;

/// One row of the eD2K `credits` table, in `load_credits` order. The trailing
/// flag is the durable "has ever been cryptographically verified" anchor.
pub type CreditRow = (
    [u8; 16],
    u64,
    u64,
    i64,
    Vec<u8>,
    u32,
    u8,
    Option<[u8; 16]>,
    bool,
);

/// Borrowed form of [`CreditRow`] used by the save path.
pub type CreditRowRef<'a> = (
    &'a [u8; 16],
    u64,
    u64,
    i64,
    &'a [u8],
    u32,
    u8,
    Option<&'a [u8; 16]>,
    bool,
);

/// One public room remembered from an earlier Discover walk.
///
/// A hint for what to draw while the DHT is being asked again, never an
/// assertion that the room is still there. The `last_seen` column behind this
/// orders and expires the cache in SQL; nothing in Rust needs to read it.
#[derive(Debug, Clone)]
pub struct CachedChannel {
    pub channel_id: String,
    pub pubkey: String,
    pub name: String,
}

/// One joined channel, as listed in the Channels page.
#[derive(Debug, Clone)]
pub struct StoredChannel {
    pub channel_id: String,
    pub pubkey: String,
    pub name: String,
    pub visibility: String,
    pub is_owner: bool,
    pub topic: String,
    pub welcome: String,
    pub joined_at: i64,
    pub last_active: i64,
    pub member_count: i64,
    pub unread: i64,
    /// Empty unless this room's owner published a successor mapping.
    pub successor_id: String,
    /// Empty unless we joined this room by following a handoff.
    pub predecessor_id: String,
    /// The owner's user pubkey (64-char hex) as published in their signed
    /// moderation record, or empty when we have not learned it. Load-bearing:
    /// it is the only thing that lets a member refuse a moderator's ban aimed
    /// at the owner.
    pub owner_pubkey: String,
    /// Current content-key epoch for a private room. 0 means the room has
    /// never rotated and still uses `join_secret` as minted.
    pub key_epoch: i64,
    /// Owner-nominated successor (64-char hex), empty when unset.
    pub successor_nominee: String,
    /// Days of owner silence before that nomination may be claimed. 0 disables
    /// succession, which leaves the room frozen if the owner never returns.
    pub claim_after_days: i64,
    /// Epoch the owner last announced. Ahead of `key_epoch` means we are behind
    /// and have an epoch record to go and fetch.
    pub key_epoch_wanted: i64,
    /// Timestamp of the newest owner-signed moderation record applied here.
    /// Doubles as the owner's liveness signal: they republish on a timer, so
    /// silence past `claim_after_days` is what lets a nomination be claimed.
    pub moderation_updated_at: i64,
    /// When we last got an answer back from a search for that record. Silence is
    /// only evidence of an absent owner if we have been asking.
    pub moderation_checked_at: i64,
    /// Whether this device is currently inside the room. Leave walks out
    /// without deleting the local row, so Join can reopen the same door.
    pub in_room: bool,
    /// Owner has permanently deleted this room. The row stays so the owner
    /// cannot recreate the same name by accident on this device.
    pub deleted: bool,
}

impl StoredChannel {
    /// Presence, send, and gossip: only while we are actually in the room
    /// and it has not been tombstoned.
    pub fn in_room_now(&self) -> bool {
        self.in_room && !self.deleted
    }
}

/// One member of a joined channel. `member_pubkey` is 64-char hex.
#[derive(Debug, Clone)]
pub struct StoredChannelMember {
    pub member_pubkey: String,
    pub nickname: String,
    pub last_seen: i64,
    pub banned: bool,
    pub moderator: bool,
}
const CHAT_KEY_FILE: &str = "chat-history.key";
const CHAT_CIPHERTEXT_PREFIX: &str = "EMBRCHAT1:";
const CHAT_UNAVAILABLE_TEXT: &str = "[Message unavailable]";
/// `chat_messages.delivery` states. Added in schema v24; every pre-existing
/// row defaults to `CHAT_DELIVERED` because it was only ever written after a
/// successful handoff.
pub const CHAT_DELIVERED: i64 = 0;
/// Stored locally, still waiting for a session to the friend.
pub const CHAT_QUEUED: i64 = 1;
/// Abandoned after exhausting retries; the user can resend explicitly.
pub const CHAT_FAILED: i64 = 2;
/// How long an outbound message may sit queued before it is abandoned.
///
/// A friend who is merely offline for a while should still receive what was
/// typed to them, so this is generous — but it has to be finite, or a message
/// to someone who never returns is retried on every reconnect forever and
/// counted as unsent for the life of the database.
const CHAT_QUEUE_MAX_AGE_SECS: i64 = 7 * 24 * 60 * 60;
const CHAT_NONCE_LEN: usize = 24;
const CHAT_AAD_DOMAIN: &[u8] = b"ember-chat-db-row-v1\0";
const CHANNEL_MSG_AAD_DOMAIN: &[u8] = b"ember-channel-db-row-v1\0";
const CHANNEL_SECRET_AAD_DOMAIN: &[u8] = b"ember-channel-secret-v1\0";
const CHANNEL_SECRET_PREFIX: &str = "EMBRCSEC1:";

pub struct Database {
    conn: Mutex<Connection>,
    /// Dedicated random key for chat-history encryption. It is stored beside
    /// the database through `secret_store` (DPAPI on Windows) and zeroized
    /// when the last Database handle is dropped.
    /// `None` when chat is locked — the key could not be recovered, so history
    /// stays sealed and nothing new is stored, while the rest of the database
    /// works normally. See [`Self::load_or_create_chat_key`].
    chat_key: Option<Zeroizing<[u8; 32]>>,
    /// Set when `ember.db` was corrupt at open time and replaced after backup.
    /// Startup surfaces a non-silent notice (same pattern as config recovery).
    pub corrupt_backup: Option<std::path::PathBuf>,
}

#[derive(Debug)]
struct CorruptDatabase(String);

impl std::fmt::Display for CorruptDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "database integrity check failed: {}", self.0)
    }
}

impl std::error::Error for CorruptDatabase {}

impl Database {
    pub fn new(app_handle: &tauri::AppHandle) -> anyhow::Result<Self> {
        let app_dir = paths::ensure_data_dir_with_app(app_handle)
            .map_err(|e| anyhow::anyhow!("Failed to prepare data dir: {e}"))?;

        let db_path = app_dir.join("ember.db");
        match Self::open_at(&db_path) {
            Ok(db) => Ok(db),
            Err(e) if db_path.exists() && Self::is_corruption_error(&e) => {
                let backup = Self::backup_corrupt_database(&db_path)?;
                tracing::warn!(
                    "ember.db was corrupt and has been preserved at {}; creating a fresh database",
                    backup.display()
                );
                let mut db = Self::open_at(&db_path).map_err(|retry| {
                    anyhow::anyhow!(
                        "Failed to initialize a fresh database after preserving the corrupt one at {}: {retry}",
                        backup.display()
                    )
                })?;
                db.corrupt_backup = Some(backup);
                Ok(db)
            }
            Err(e) => Err(e),
        }
    }

    /// Open (or create) a database at an explicit path, running migrations.
    ///
    /// `pub(crate)` so callers that already know the path can use it without a
    /// Tauri handle, notably the backup round-trip test.
    pub(crate) fn open_at(db_path: &std::path::Path) -> anyhow::Result<Self> {
        // Repair ACLs before SQLite touches the main file or its WAL/SHM
        // sidecars. A prior ACL-hardening bug could leave those sidecars with
        // an empty DACL, in which case `Connection::open` fails before the
        // post-open permission pass has a chance to repair them.
        #[cfg(target_os = "windows")]
        {
            for path in std::iter::once(db_path.to_path_buf()).chain(
                ["-wal", "-shm"].into_iter().map(|suffix| {
                    let mut sidecar = db_path.as_os_str().to_os_string();
                    sidecar.push(suffix);
                    std::path::PathBuf::from(sidecar)
                }),
            ) {
                match std::fs::symlink_metadata(&path) {
                    Ok(_) => crate::security::restrict_file_permissions_checked(&path)?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    // An empty DACL makes metadata itself fail. Attempt ACL
                    // repair by pathname; the file owner still has WRITE_DAC.
                    Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                        crate::security::restrict_file_permissions_checked(&path)?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }

        let conn = Connection::open(db_path)?;
        crate::security::restrict_file_permissions_checked(db_path)?;
        let chat_key = Self::load_or_create_chat_key(db_path, &conn)?;

        let quick_check: String = conn.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        if !quick_check.eq_ignore_ascii_case("ok") {
            return Err(CorruptDatabase(quick_check).into());
        }

        conn.execute_batch(
            // auto_vacuum must be set before journal_mode writes the DB
            // header. After WAL is enabled (or any table exists), changing
            // auto_vacuum requires an explicit VACUUM — see v21 migration.
            "PRAGMA auto_vacuum=INCREMENTAL;\
             PRAGMA journal_mode=WAL;\
             PRAGMA synchronous=FULL;\
             PRAGMA foreign_keys=ON;\
             PRAGMA secure_delete=ON;\
             PRAGMA busy_timeout=5000;",
        )?;
        // SQLite may create WAL/SHM sidecars as soon as journal_mode changes.
        // They contain the same sensitive rows as the main database.
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = db_path.as_os_str().to_os_string();
            sidecar.push(suffix);
            let sidecar = std::path::PathBuf::from(sidecar);
            if sidecar.exists() {
                crate::security::restrict_file_permissions_checked(&sidecar)?;
            }
        }

        let db = Self {
            conn: Mutex::new(conn),
            chat_key,
            corrupt_backup: None,
        };
        db.run_migrations()?;

        info!("Database initialized");
        Ok(db)
    }

    /// `Ok(None)` means chat is *locked*: the key could not be recovered, so
    /// history stays sealed and no new messages can be stored — but the rest of
    /// the database opens normally.
    ///
    /// This used to abort startup. Refusing to rotate the key or drop history is
    /// right, but taking the whole application down with it was not: downloads,
    /// the library and every setting became unreachable because chat history
    /// could not be read, and the explanation went only to the log. The key file
    /// is deliberately never overwritten here, so restoring it from backup still
    /// recovers the history afterwards.
    fn load_or_create_chat_key(
        db_path: &std::path::Path,
        conn: &Connection,
    ) -> anyhow::Result<Option<Zeroizing<[u8; 32]>>> {
        let key_path = db_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join(CHAT_KEY_FILE);
        // Wrapping a legacy plaintext key rewrites this file, so an interrupted
        // replace can park it. Reading that as missing seals the history behind
        // the "restore it from backup" path below while the key is sitting right
        // next to the database under its backup name.
        crate::security::recover_interrupted_replace(&key_path);
        match std::fs::read(&key_path) {
            Ok(stored) => {
                let was_protected = crate::storage::secret_store::is_protected(&stored);
                let plaintext = match crate::storage::secret_store::unprotect(&stored) {
                    Ok(plaintext) => plaintext,
                    Err(e) => {
                        warn!(
                            "Chat history is locked: the key at {} could not be recovered \
                             ({e}). Restore it under the original Windows account, or from \
                             backup. Nothing has been rotated or deleted.",
                            key_path.display()
                        );
                        return Ok(None);
                    }
                };
                if plaintext.len() != 32 {
                    warn!(
                        "Chat history is locked: the key at {} has invalid length {} \
                         (expected 32). Nothing has been rotated or deleted.",
                        key_path.display(),
                        plaintext.len()
                    );
                    return Ok(None);
                }
                // `Zeroizing` from the moment the key exists, not once it
                // reaches the struct field: a bare `[u8; 32]` local is copied
                // out by value on every return and never wiped, so the key
                // stays readable in the freed stack frames of `Database::new`.
                let mut key = Zeroizing::new([0u8; 32]);
                key.copy_from_slice(&plaintext);
                // Transparently wrap a legacy restricted plaintext key, and
                // likewise one sealed under a superseded scheme — a Unix
                // `EMBRSEC2`/`EMBRSEC3` blob is keyed by `$USER`, which a
                // launcher need not export, so it only stops depending on that
                // variable once rewritten. Never rewrite a key that failed
                // unprotect/validation: this is reached only after a successful
                // one.
                if !was_protected || crate::storage::secret_store::needs_rewrap(&stored) {
                    let protected = crate::storage::secret_store::protect(key.as_slice())?;
                    crate::security::atomic_write(&key_path, &protected, true)?;
                }
                Ok(Some(key))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Losing this file must never silently rotate the key while
                // encrypted rows still exist. That would make valid history
                // look corrupt and could encourage destructive recovery.
                let has_chat_table: bool = conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM sqlite_master \
                         WHERE type='table' AND name='chat_messages')",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap_or(false);
                let has_encrypted_rows = has_chat_table
                    && conn
                        .query_row(
                            // Case-sensitive GLOB, matching `starts_with`
                            // elsewhere: under LIKE a plaintext body beginning
                            // `embrchat1:` counts as ciphertext and seals chat
                            // permanently instead of minting a fresh key.
                            "SELECT EXISTS(SELECT 1 FROM chat_messages \
                             WHERE message GLOB 'EMBRCHAT1:*' LIMIT 1)",
                            [],
                            |row| row.get::<_, bool>(0),
                        )
                        .unwrap_or(false);
                if has_encrypted_rows {
                    // Lock rather than rotate. Writing a new key here would make
                    // the existing history permanently unreadable even if the
                    // original key were restored later, so the file is left
                    // untouched and chat stays sealed until it comes back.
                    warn!(
                        "Chat history is locked: the key is missing at {} while encrypted \
                         history exists. Restore it from backup to read it again. Nothing \
                         has been rotated or deleted.",
                        key_path.display()
                    );
                    return Ok(None);
                }
                let mut key = Zeroizing::new([0u8; 32]);
                OsRng.fill_bytes(key.as_mut_slice());
                let protected = crate::storage::secret_store::protect(key.as_slice())?;
                crate::security::atomic_write(&key_path, &protected, true)?;
                Ok(Some(key))
            }
            Err(error) => {
                // Unreadable for some other reason (permissions, I/O). Same
                // treatment: seal chat, leave the file alone, open everything
                // else.
                warn!(
                    "Chat history is locked: failed to read the key at {}: {error}",
                    key_path.display()
                );
                Ok(None)
            }
        }
    }

    /// Whether chat history is sealed because its key could not be recovered.
    ///
    /// Everything else in the database works; this exists so the UI can say why
    /// chat is empty and unusable instead of leaving the user guessing.
    pub fn chat_locked(&self) -> bool {
        self.chat_key.is_none()
    }

    fn require_chat_key(&self) -> anyhow::Result<&[u8; 32]> {
        self.chat_key.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "Chat history is locked: its encryption key could not be recovered. \
                 Restore the key file from backup to read or send messages."
            )
        })
    }

    fn chat_row_aad(id: i64, friend_hash: &str, direction: &str, timestamp: i64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            CHAT_AAD_DOMAIN.len() + 8 + 8 + 4 + friend_hash.len() + 4 + direction.len(),
        );
        aad.extend_from_slice(CHAT_AAD_DOMAIN);
        aad.extend_from_slice(&id.to_le_bytes());
        aad.extend_from_slice(&timestamp.to_le_bytes());
        aad.extend_from_slice(&(friend_hash.len() as u32).to_le_bytes());
        aad.extend_from_slice(friend_hash.as_bytes());
        aad.extend_from_slice(&(direction.len() as u32).to_le_bytes());
        aad.extend_from_slice(direction.as_bytes());
        aad
    }

    fn encrypt_chat_body(
        key: &[u8; 32],
        id: i64,
        friend_hash: &str,
        direction: &str,
        timestamp: i64,
        plaintext: &str,
    ) -> anyhow::Result<String> {
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
        let mut nonce = [0u8; CHAT_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let aad = Self::chat_row_aad(id, friend_hash, direction, timestamp);
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("Failed to encrypt chat history row"))?;
        let mut envelope = Vec::with_capacity(CHAT_NONCE_LEN + encrypted.len());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&encrypted);
        Ok(format!(
            "{CHAT_CIPHERTEXT_PREFIX}{}",
            STANDARD_NO_PAD.encode(envelope)
        ))
    }

    fn decrypt_chat_body(
        key: &[u8; 32],
        id: i64,
        friend_hash: &str,
        direction: &str,
        timestamp: i64,
        stored: &str,
    ) -> anyhow::Result<String> {
        let encoded = stored.strip_prefix(CHAT_CIPHERTEXT_PREFIX).ok_or_else(|| {
            anyhow::anyhow!("Chat history row {id} is not encrypted; refusing plaintext fallback")
        })?;
        let envelope = STANDARD_NO_PAD
            .decode(encoded)
            .map_err(|_| anyhow::anyhow!("Chat history row {id} has an invalid ciphertext"))?;
        if envelope.len() < CHAT_NONCE_LEN + 16 {
            anyhow::bail!("Chat history row {id} has a truncated ciphertext");
        }
        let aad = Self::chat_row_aad(id, friend_hash, direction, timestamp);
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&envelope[..CHAT_NONCE_LEN]),
                Payload {
                    msg: &envelope[CHAT_NONCE_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "Chat history authentication failed for row {id}; the database or key may \
                     be damaged. Restore both from the same backup."
                )
            })?;
        String::from_utf8(plaintext)
            .map_err(|_| anyhow::anyhow!("Chat history row {id} decrypted to invalid UTF-8"))
    }

    fn channel_secret_aad(channel_id: &str, label: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            CHANNEL_SECRET_AAD_DOMAIN.len() + 4 + channel_id.len() + 4 + label.len(),
        );
        aad.extend_from_slice(CHANNEL_SECRET_AAD_DOMAIN);
        aad.extend_from_slice(&(channel_id.len() as u32).to_le_bytes());
        aad.extend_from_slice(channel_id.as_bytes());
        aad.extend_from_slice(&(label.len() as u32).to_le_bytes());
        aad.extend_from_slice(label.as_bytes());
        aad
    }

    fn encrypt_channel_secret(
        key: &[u8; 32],
        channel_id: &str,
        label: &str,
        plaintext: &[u8; 32],
    ) -> anyhow::Result<String> {
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
        let mut nonce = [0u8; CHAT_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let aad = Self::channel_secret_aad(channel_id, label);
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("Failed to encrypt channel secret"))?;
        let mut envelope = Vec::with_capacity(CHAT_NONCE_LEN + encrypted.len());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&encrypted);
        Ok(format!(
            "{CHANNEL_SECRET_PREFIX}{}",
            STANDARD_NO_PAD.encode(envelope)
        ))
    }

    fn decrypt_channel_secret(
        key: &[u8; 32],
        channel_id: &str,
        label: &str,
        stored: &str,
    ) -> anyhow::Result<[u8; 32]> {
        let encoded = stored
            .strip_prefix(CHANNEL_SECRET_PREFIX)
            .ok_or_else(|| anyhow::anyhow!("Channel secret for {channel_id} is not encrypted"))?;
        let envelope = STANDARD_NO_PAD.decode(encoded).map_err(|_| {
            anyhow::anyhow!("Channel secret for {channel_id} has invalid ciphertext")
        })?;
        if envelope.len() < CHAT_NONCE_LEN + 16 {
            anyhow::bail!("Channel secret for {channel_id} is truncated");
        }
        let aad = Self::channel_secret_aad(channel_id, label);
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&envelope[..CHAT_NONCE_LEN]),
                Payload {
                    msg: &envelope[CHAT_NONCE_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| {
                anyhow::anyhow!("Channel secret authentication failed for {channel_id}")
            })?;
        <[u8; 32]>::try_from(plaintext)
            .map_err(|_| anyhow::anyhow!("Channel secret for {channel_id} has invalid length"))
    }

    fn channel_row_aad(id: i64, channel_id: &str, direction: &str, timestamp: i64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            CHANNEL_MSG_AAD_DOMAIN.len() + 8 + 8 + 4 + channel_id.len() + 4 + direction.len(),
        );
        aad.extend_from_slice(CHANNEL_MSG_AAD_DOMAIN);
        aad.extend_from_slice(&id.to_le_bytes());
        aad.extend_from_slice(&timestamp.to_le_bytes());
        aad.extend_from_slice(&(channel_id.len() as u32).to_le_bytes());
        aad.extend_from_slice(channel_id.as_bytes());
        aad.extend_from_slice(&(direction.len() as u32).to_le_bytes());
        aad.extend_from_slice(direction.as_bytes());
        aad
    }

    fn encrypt_channel_message_body(
        key: &[u8; 32],
        id: i64,
        channel_id: &str,
        direction: &str,
        timestamp: i64,
        plaintext: &str,
    ) -> anyhow::Result<String> {
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
        let mut nonce = [0u8; CHAT_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let aad = Self::channel_row_aad(id, channel_id, direction, timestamp);
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("Failed to encrypt channel message"))?;
        let mut envelope = Vec::with_capacity(CHAT_NONCE_LEN + encrypted.len());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&encrypted);
        Ok(format!(
            "{CHAT_CIPHERTEXT_PREFIX}{}",
            STANDARD_NO_PAD.encode(envelope)
        ))
    }

    fn decrypt_channel_message_body(
        key: &[u8; 32],
        id: i64,
        channel_id: &str,
        direction: &str,
        timestamp: i64,
        stored: &str,
    ) -> anyhow::Result<String> {
        let encoded = stored
            .strip_prefix(CHAT_CIPHERTEXT_PREFIX)
            .ok_or_else(|| anyhow::anyhow!("Channel message {id} is not encrypted"))?;
        let envelope = STANDARD_NO_PAD
            .decode(encoded)
            .map_err(|_| anyhow::anyhow!("Channel message {id} has invalid ciphertext"))?;
        if envelope.len() < CHAT_NONCE_LEN + 16 {
            anyhow::bail!("Channel message {id} is truncated");
        }
        let aad = Self::channel_row_aad(id, channel_id, direction, timestamp);
        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&envelope[..CHAT_NONCE_LEN]),
                Payload {
                    msg: &envelope[CHAT_NONCE_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("Channel message {id} failed authentication"))?;
        String::from_utf8(plaintext)
            .map_err(|_| anyhow::anyhow!("Channel message {id} decrypted to invalid UTF-8"))
    }

    fn is_corruption_error(error: &anyhow::Error) -> bool {
        error.chain().any(|cause| {
            if cause.downcast_ref::<CorruptDatabase>().is_some() {
                return true;
            }
            matches!(
                cause.downcast_ref::<rusqlite::Error>(),
                Some(rusqlite::Error::SqliteFailure(sqlite, _))
                    if matches!(
                        sqlite.code,
                        ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase
                    )
            )
        })
    }

    fn backup_corrupt_database(db_path: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
        let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
        let mut backup = db_path.with_extension(format!("db.{timestamp}.corrupt"));
        let mut suffix = 1u32;
        while backup.exists() && suffix < 1000 {
            backup = db_path.with_extension(format!("db.{timestamp}.{suffix}.corrupt"));
            suffix += 1;
        }

        Self::move_database_file(db_path, &backup)?;
        crate::security::restrict_file_permissions_checked(&backup)?;

        // Preserve WAL sidecars under matching backup names. Leaving a stale
        // sidecar beside the new database could make SQLite associate old
        // pages with the replacement file.
        for sidecar in ["-wal", "-shm"] {
            let mut source_name = db_path.as_os_str().to_os_string();
            source_name.push(sidecar);
            let source = std::path::PathBuf::from(source_name);
            if !source.exists() {
                continue;
            }
            let mut destination_name = backup.as_os_str().to_os_string();
            destination_name.push(sidecar);
            let destination = std::path::PathBuf::from(destination_name);
            Self::move_database_file(&source, &destination)?;
            crate::security::restrict_file_permissions_checked(&destination)?;
        }

        Ok(backup)
    }

    fn move_database_file(
        source: &std::path::Path,
        destination: &std::path::Path,
    ) -> anyhow::Result<()> {
        if std::fs::rename(source, destination).is_ok() {
            return Ok(());
        }
        std::fs::copy(source, destination).map_err(|e| {
            anyhow::anyhow!(
                "Failed to preserve corrupt database file {} at {}: {e}",
                source.display(),
                destination.display()
            )
        })?;
        std::fs::remove_file(source).map_err(|e| {
            anyhow::anyhow!(
                "Copied corrupt database file {} to {}, but could not remove the original: {e}",
                source.display(),
                destination.display()
            )
        })
    }

    /// Encrypt every chat body that is still stored as plaintext, through
    /// `conn` so the caller owns the transaction. Returns how many rows were
    /// rewritten.
    ///
    /// `authenticate_existing` also decrypts the rows that already carry the
    /// ciphertext marker, which the v23 migration requires: a partially
    /// prepared or hand-made database must prove those rows open, not merely
    /// carry the prefix. The deferred pass leaves them untouched and asks
    /// SQLite for the plaintext rows only, so it stays cheap enough to run on
    /// every open and cannot turn a damaged ciphertext row into a failed open.
    fn encrypt_chat_history_rows(
        &self,
        conn: &Connection,
        authenticate_existing: bool,
    ) -> anyhow::Result<usize> {
        let key = self.require_chat_key()?;
        let rows = {
            // GLOB rather than LIKE: SQLite's LIKE is ASCII case-insensitive, so
            // a plaintext body starting with e.g. `embrchat1:` would be filtered
            // out of the deferred pass, never encrypted (v23 has already run, so
            // it never runs again), and then fail the case-sensitive
            // `starts_with` on every read — [Message unavailable] forever.
            let mut stmt = conn.prepare(if authenticate_existing {
                "SELECT id, friend_hash, direction, message, timestamp \
                 FROM chat_messages ORDER BY id"
            } else {
                "SELECT id, friend_hash, direction, message, timestamp \
                 FROM chat_messages WHERE message NOT GLOB 'EMBRCHAT1:*' ORDER BY id"
            })?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut rewritten = 0usize;
        for (id, friend_hash, direction, stored, timestamp) in rows {
            if stored.starts_with(CHAT_CIPHERTEXT_PREFIX) {
                // A partially prepared/manual database must authenticate, not
                // merely carry the marker, before migration completes.
                //
                // A failure here does not fail the migration, because in a
                // pre-v23 database these bodies are plaintext straight off the
                // wire: a friend who opened a message with the marker text
                // produces a row that cannot decrypt, and propagating that error
                // aborted `run_migrations` — and with it every future database
                // open, deterministically, with no corruption path to recover
                // through. Treat it as the plaintext it is and encrypt it.
                if authenticate_existing
                    && Self::decrypt_chat_body(
                        key,
                        id,
                        &friend_hash,
                        &direction,
                        timestamp,
                        &stored,
                    )
                    .is_ok()
                {
                    continue;
                }
                if !authenticate_existing {
                    continue;
                }
                warn!(
                    "Chat message {id} carries the ciphertext marker but does not authenticate; \
                     treating it as plaintext that happened to start with it."
                );
            }
            let encrypted =
                Self::encrypt_chat_body(key, id, &friend_hash, &direction, timestamp, &stored)?;
            conn.execute(
                "UPDATE chat_messages SET message = ?1 WHERE id = ?2",
                params![encrypted, id],
            )?;
            rewritten += 1;
        }
        Ok(rewritten)
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
        // Ember build.
        if version > MAX_SUPPORTED_SCHEMA_VERSION {
            anyhow::bail!(
                "Database schema version {version} is newer than this Ember build supports \
                 (max {MAX_SUPPORTED_SCHEMA_VERSION}). The database was likely written by a \
                 more recent version of Ember. Install that version to access this data; \
                 refusing to start to avoid corruption."
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

        if version < 20 {
            // Link eD2K SecIdent credit rows to Ember node ids so the Known
            // Clients tab can mark friends (friends are keyed by ember hash).
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "credits", "ember_hash", "BLOB")?;
            set_version(&tx, 20)?;
            tx.commit()?;
        }

        if version < 21 {
            // Existing installs were created with `journal_mode=WAL` before
            // `auto_vacuum=INCREMENTAL`, which left auto_vacuum stuck at NONE
            // forever — `PRAGMA incremental_vacuum` then silently no-ops and
            // freed pages never return to the OS. Enable incremental vacuum
            // and drop unused legacy migration backup tables.
            //
            // VACUUM cannot run inside a transaction, so we set the version
            // after the maintenance steps (same pattern as other one-shot
            // maintenance migrations).
            let auto_vacuum: i64 = conn
                .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
                .unwrap_or(0);
            if auto_vacuum == 0 {
                // Must set the pragma, then VACUUM, for the file header to change.
                conn.execute_batch("PRAGMA auto_vacuum=INCREMENTAL; VACUUM;")?;
                info!("Enabled incremental auto_vacuum on existing database (v21)");
            }
            conn.execute_batch(
                "DROP TABLE IF EXISTS transfers_v5_backup;
                 DROP TABLE IF EXISTS shared_files_v7_backup;
                 DROP TABLE IF EXISTS settings_v7_backup;",
            )?;
            let tx = conn.unchecked_transaction()?;
            set_version(&tx, 21)?;
            tx.commit()?;
        }

        if version < 22 {
            // Optional trusted AICH master supplied by an ed2k link or
            // collection. Keeping it on the transfer row carries the pin
            // through pause/restart without changing any eMule wire format.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "transfers", "expected_aich", "TEXT")?;
            set_version(&tx, 22)?;
            tx.commit()?;
        }

        if version < 23 {
            // Encrypt all historical chat bodies atomically. The version is
            // advanced in the same transaction, so a crash leaves either the
            // complete plaintext v22 database (which retries migration) or a
            // complete encrypted v23 database—never a mixed committed state.
            let tx = conn.unchecked_transaction()?;
            // A few valid legacy/test databases carry only schema metadata
            // (for example, after an interrupted old migration or a targeted
            // auto-vacuum repair). Recreate the prerequisite tables before
            // adding v23 columns so migration remains idempotent instead of
            // failing with "no such table".
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS friends (
                    user_hash TEXT PRIMARY KEY,
                    nickname TEXT NOT NULL DEFAULT '',
                    added_at INTEGER NOT NULL DEFAULT 0,
                    last_ip TEXT DEFAULT '',
                    last_port INTEGER DEFAULT 0,
                    last_seen INTEGER DEFAULT 0,
                    mutual INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS friend_requests (
                    sender_hash TEXT PRIMARY KEY,
                    sender_nickname TEXT NOT NULL DEFAULT '',
                    received_at INTEGER NOT NULL DEFAULT 0,
                    sender_ip TEXT DEFAULT '',
                    sender_port INTEGER DEFAULT 0,
                    verified INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS chat_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    friend_hash TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    read INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_chat_messages_friend
                    ON chat_messages(friend_hash, timestamp);",
            )?;
            Self::add_column_if_missing(&tx, "friends", "ed25519_pubkey", "BLOB")?;
            Self::add_column_if_missing(&tx, "friend_requests", "sender_pubkey", "BLOB")?;
            // Encrypting the bodies needs the chat key, which may be
            // unrecoverable: `load_or_create_chat_key` then returns `None`, the
            // deliberate "chat is locked, everything else still works" state.
            // Failing here failed the whole open, so a locked key stopped the
            // application from launching at all. The schema work above must
            // still land — friends and friend requests depend on it — so v23
            // completes and the row pass is deferred to the first open that can
            // recover the key. Nothing is rotated, rewritten or dropped in the
            // meantime; the rows read as unavailable exactly like sealed
            // ciphertext does.
            let encrypted_now = if self.chat_key.is_some() {
                self.encrypt_chat_history_rows(&tx, true)?;
                true
            } else {
                warn!(
                    "Chat history is locked, so the v23 encryption pass is deferred: existing \
                     messages are left exactly as they are and will be encrypted on the first \
                     launch that recovers the key."
                );
                false
            };
            set_version(&tx, 23)?;
            tx.commit()?;

            if encrypted_now {
                // Remove plaintext remnants from WAL/free pages after the
                // transactional rewrite. `secure_delete=ON` protects released
                // cells; checkpoint+VACUUM also rewrites the main file so a raw
                // database scan cannot recover old message canaries.
                conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")?;
                info!("Encrypted local chat history (database v23)");
            }
        }

        if version < 24 {
            // Outbound chat used to be persisted only after a successful
            // handoff to a live session, so a message typed while a friend
            // was unreachable was simply lost. `delivery` lets a send be
            // stored up front and reconciled later.
            //
            // 0 = delivered to the peer's session (and every historical row,
            //     which is why the default matters), 1 = queued for the next
            //     time we reach them, 2 = gave up.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "chat_messages",
                "delivery",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            // Flushing scans by (friend, delivery) and expects oldest-first.
            tx.execute(
                "CREATE INDEX IF NOT EXISTS idx_chat_messages_delivery \
                 ON chat_messages (friend_hash, delivery, id)",
                [],
            )?;
            set_version(&tx, 24)?;
            tx.commit()?;
        }

        if version < 25 {
            // Removing a friend deletes the row, so it cannot also record that
            // the user wants nothing further from that identity: the same peer
            // can send another request straight away and, with approval
            // disabled, be promoted back to mutual without the user ever being
            // asked. Blocks therefore live in their own table, which outlives
            // the friendship it ended.
            //
            // The nickname is denormalised on purpose. Once the `friends` row
            // is gone there is nothing left to join against, and a list of
            // bare 32-character hashes gives the user no way to tell who they
            // blocked or who to unblock.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS friend_blocks (
                    user_hash TEXT PRIMARY KEY,
                    nickname TEXT NOT NULL DEFAULT '',
                    blocked_at INTEGER NOT NULL DEFAULT 0
                );",
            )?;
            set_version(&tx, 25)?;
            tx.commit()?;
        }

        if version < 26 {
            // The anti-credit-theft reset fires unless a record has ever been
            // cryptographically verified by us. That anchor has to be durable
            // and monotonic (eMule persists the equivalent `nKeySize` and only
            // ever writes it inside `Verified()`), because `ident_state` is
            // not: a stranger claiming a peer's user_hash can fail one
            // challenge and knock an established record out of `Verified`.
            // Deriving the anchor from `ident_state` at load would then wipe
            // that peer's accumulated credits on their next verification.
            let tx = conn.unchecked_transaction()?;
            // Guarded on the table existing so a partially-formed database
            // cannot turn this into a failed open, which would stop the app
            // launching entirely.
            let has_credits: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master \
                     WHERE type='table' AND name='credits')",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(false);
            if has_credits {
                Self::add_column_if_missing(
                    &tx,
                    "credits",
                    "crypto_verified_once",
                    "INTEGER NOT NULL DEFAULT 0",
                )?;
                // Existing rows get the one-time benefit of the doubt: a
                // persisted `Verified` (1) can only have been reached through a
                // real challenge, so treat it as the anchor rather than
                // resetting every peer the first time they reconnect after
                // this upgrade.
                tx.execute(
                    "UPDATE credits SET crypto_verified_once = 1 WHERE ident_state = 1",
                    [],
                )?;
            }
            set_version(&tx, 26)?;
            tx.commit()?;
        }

        if version < 27 {
            // Optional Ember content BLAKE3 supplied by an ed2k `eh=` link,
            // friend browse/offer, or collection. Keeping it on the transfer
            // row carries the pin through pause/restart the same way
            // `expected_aich` does.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(&tx, "transfers", "ember_file_hash", "TEXT")?;
            set_version(&tx, 27)?;
            tx.commit()?;
        }

        if version < 28 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS channels (
                    channel_id TEXT PRIMARY KEY,
                    pubkey TEXT NOT NULL,
                    name TEXT NOT NULL,
                    visibility TEXT NOT NULL,
                    is_owner INTEGER NOT NULL DEFAULT 0,
                    owner_seed TEXT,
                    join_secret TEXT,
                    topic TEXT NOT NULL DEFAULT '',
                    welcome TEXT NOT NULL DEFAULT '',
                    joined_at INTEGER NOT NULL,
                    last_active INTEGER NOT NULL DEFAULT 0,
                    presence_published_at INTEGER NOT NULL DEFAULT 0,
                    moderation_updated_at INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS channel_members (
                    channel_id TEXT NOT NULL,
                    member_pubkey TEXT NOT NULL,
                    nickname TEXT NOT NULL DEFAULT '',
                    last_seen INTEGER NOT NULL DEFAULT 0,
                    banned INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (channel_id, member_pubkey)
                );
                CREATE TABLE IF NOT EXISTS channel_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    channel_id TEXT NOT NULL,
                    sender_pubkey TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    read INTEGER NOT NULL DEFAULT 0,
                    msg_id TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_channel_messages_dedup
                    ON channel_messages(channel_id, msg_id);
                CREATE INDEX IF NOT EXISTS idx_channel_messages_chan
                    ON channel_messages(channel_id, id);
                CREATE INDEX IF NOT EXISTS idx_channel_members_chan
                    ON channel_members(channel_id);",
            )?;
            set_version(&tx, 28)?;
            tx.commit()?;
        }

        if version < 29 {
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "moderation_updated_at",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 29)?;
            tx.commit()?;
        }

        if version < 30 {
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channel_members",
                "moderator",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            Self::add_column_if_missing(
                &tx,
                "channel_members",
                "ban_revised_at",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 30)?;
            tx.commit()?;
        }

        if version < 31 {
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "successor_id",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "predecessor_id",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "pending_successor",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "pending_handoff_version",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS channel_handoff_pending (
                    old_channel_id TEXT PRIMARY KEY,
                    version INTEGER NOT NULL,
                    successor_pubkey TEXT NOT NULL,
                    owner_seed TEXT,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS channel_attachments (
                    channel_id TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    sender_pubkey TEXT NOT NULL,
                    complete INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (channel_id, digest)
                );",
            )?;
            set_version(&tx, 31)?;
            tx.commit()?;
        }

        if version < 32 {
            // The owner's own user identity, learned from their signed
            // moderation record. Members need it to refuse a moderator's ban
            // gossip that names the owner: nothing else on the wire says which
            // pubkey owns a room, so before this every member applied such a
            // ban and silently dropped the owner's messages. Empty means "not
            // learned yet" — no record seen, or one predating the field.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "owner_pubkey",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            set_version(&tx, 32)?;
            tx.commit()?;
        }

        if version < 33 {
            // Private rooms rotate their content key so a ban can actually
            // evict: the join secret used to be minted once and baked into
            // every invite, which meant anyone who ever held one could read
            // the room forever. Each epoch's secret is stored under the chat
            // key like the others; `channels.key_epoch` names the current one,
            // and epoch 0 is the pre-rotation `join_secret` still in place.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "key_epoch",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS channel_key_epochs (
                    channel_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    secret_enc TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (channel_id, epoch)
                );",
            )?;
            // Succession: who may take a room over once its owner has gone
            // quiet, and for how long they must have been quiet. Both come
            // from the owner-signed moderation record. Either one empty or
            // zero means the owner has not set it up, and the room simply
            // freezes if they vanish — the status quo.
            Self::add_column_if_missing(
                &tx,
                "channels",
                "successor_nominee",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "claim_after_days",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            // The epoch the owner says is current, against `key_epoch` which is
            // the newest we actually hold a key for. Wanted ahead of held is
            // what sends a member looking for the record sealed to them.
            Self::add_column_if_missing(
                &tx,
                "channels",
                "key_epoch_wanted",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            // When a search for this room's owner record last came back, as
            // against `moderation_updated_at` which is how new that record was.
            // Succession needs both: an owner-silence window is only meaningful
            // if we have actually been asking, and locally "they have gone
            // quiet" is otherwise indistinguishable from "we have not looked".
            // Persisted rather than kept in memory so a restart cannot make a
            // month-old snapshot look freshly confirmed.
            Self::add_column_if_missing(
                &tx,
                "channels",
                "moderation_checked_at",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 33)?;
            tx.commit()?;
        }

        if version < 34 {
            // Room attachments are gone. They broadcast a file to everyone in
            // the room whether or not anybody asked for it, capped at 256 KB,
            // with no acknowledgement and no way to resume — so in practice a
            // transfer died a few kilobytes in and could not recover. Ember
            // Transfer replaces it: one member offers a file to one member,
            // who has to accept before any bytes move.
            //
            // The sealed blobs these rows pointed at live outside the database,
            // so startup removes the `channel-files` directory separately.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch("DROP TABLE IF EXISTS channel_attachments;")?;
            set_version(&tx, 34)?;
            tx.commit()?;
        }

        if version < 35 {
            // Discover began from nothing on every open: a cold DHT walk across
            // sixteen index shards with an empty list on screen until the
            // slowest of them answered, which on a table that had just started
            // warming meant the better part of a minute showing nothing. This
            // remembers what the last walk turned up so the browse can open on
            // it and replace the rows as fresh records land. Cache only — the
            // DHT stays the authority, and a listing here is never treated as
            // proof the room is still alive.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS channel_index_cache (
                    channel_id TEXT PRIMARY KEY,
                    pubkey TEXT NOT NULL,
                    name TEXT NOT NULL,
                    last_seen INTEGER NOT NULL DEFAULT 0
                );",
            )?;
            set_version(&tx, 35)?;
            tx.commit()?;
        }

        if version < 36 {
            // The author's own signature over a chat line, hex, empty when we
            // do not have one.
            //
            // History sync used to re-encode a stored message under whatever
            // `sender_pubkey` the row carried, which meant any member answering
            // a catch-up request could invent a conversation and attribute it to
            // anyone. Chat lines now carry an Ed25519 signature from their
            // author, and a re-serve has to replay that original rather than
            // mint a new one, so the signature has to survive in the row.
            //
            // Rows written before this are left empty and simply are not
            // re-served; their text is still readable locally.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channel_messages",
                "author_sig",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            set_version(&tx, 36)?;
            tx.commit()?;
        }

        if version < 37 {
            // Membership is presence: Leave walks out without wiping the row,
            // so Join can reopen the same door. Existing rows are rooms this
            // device already joined, so they start inside.
            let tx = conn.unchecked_transaction()?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "in_room",
                "INTEGER NOT NULL DEFAULT 1",
            )?;
            Self::add_column_if_missing(
                &tx,
                "channels",
                "deleted",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            set_version(&tx, 37)?;
            tx.commit()?;
        }

        // Finish a v23 encryption pass that was deferred because chat was
        // locked at the time. The version is already 23 or later, so the
        // migration itself will never run again — without this the history
        // would stay in plaintext on disk and unreadable forever, even once the
        // key came back. A database that migrated normally has no plaintext
        // bodies left, so this finds nothing and writes nothing.
        if self.chat_key.is_some() {
            let has_chat_table: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master \
                     WHERE type='table' AND name='chat_messages')",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(false);
            if has_chat_table {
                let tx = conn.unchecked_transaction()?;
                let encrypted = self.encrypt_chat_history_rows(&tx, false)?;
                if encrypted > 0 {
                    tx.commit()?;
                    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")?;
                    info!(
                        "Encrypted {encrypted} chat history row(s) left in plaintext by a \
                         migration that ran while the chat key was unavailable"
                    );
                }
            }
        }

        Ok(())
    }

    /// `schema_version` recorded in the open database.
    pub fn schema_version(&self) -> i64 {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0)
    }

    /// Write a consistent, self-contained copy of the live database to `dest`.
    ///
    /// `VACUUM INTO` runs inside a read transaction and produces a single file
    /// with no WAL sidecar, which is what a backup needs: copying `ember.db`
    /// by hand while the app is running captures a file whose newest
    /// committed rows are still only in `ember.db-wal`.
    pub fn snapshot_to(&self, dest: &std::path::Path) -> anyhow::Result<()> {
        // SQLite refuses to overwrite an existing target.
        if dest.exists() {
            std::fs::remove_file(dest)?;
        }
        let dest_str = dest
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Snapshot path is not valid UTF-8"))?;
        {
            let conn = self.conn.lock();
            conn.execute("VACUUM INTO ?1", params![dest_str])?;
        }
        crate::security::restrict_file_permissions(dest);
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
        // The base tables are only created by the `version < 1` arm, so a
        // database opened at a later version that is missing one never gets it
        // back. Aborting the migration chain over it would still be the wrong
        // trade: that fails every future open of an otherwise usable database,
        // where skipping degrades only the feature backed by that table. Warn
        // rather than `debug!` so the cause is in the log when it does happen,
        // and let a genuine query failure propagate instead of reading as
        // "absent" — that would mark the migration done and never retry it.
        let has_table: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            params![table],
            |row| row.get(0),
        )?;
        if !has_table {
            warn!("Skipping column {table}.{column}: table {table} does not exist");
            return Ok(());
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
        // Banned rows are exempt. A ban is a user decision with no natural
        // refresh — nothing contacts the peer again, so `last_seen` freezes
        // and the row drifts to the bottom of this ordering (a ban placed on
        // a hash we had never met starts at 0 and is evicted immediately).
        // The ban list is rebuilt from `banned = 1` at startup, so eviction
        // silently un-banned peers within days on an active node.
        conn.execute(
            "DELETE FROM peers WHERE id IN (
                SELECT id FROM peers
                WHERE banned = 0
                ORDER BY last_seen DESC
                LIMIT -1 OFFSET ?1
            )",
            params![MAX_PEERS_ROWS],
        )?;
        Ok(())
    }

    /// Every address recorded for one peer id.
    ///
    /// The ban and unban paths used to reach this through `get_peers`, which
    /// reads the whole table *and* deserializes every row's address list to
    /// answer a question about a single id — synchronously on the network task.
    /// It is also `LIMIT MAX_PEERS_ROWS`, so a peer whose row had fallen outside
    /// that window contributed no IPs at all and the ban silently covered only
    /// the user-hash paths.
    pub fn get_peer_addresses(&self, peer_id: &str) -> anyhow::Result<Vec<String>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT addresses FROM peers WHERE id = ?1")?;
        let mut rows = stmt.query(params![peer_id])?;
        let Some(row) = rows.next()? else {
            return Ok(Vec::new());
        };
        let addresses_str: String = row.get(0)?;
        Ok(serde_json::from_str(&addresses_str)?)
    }

    pub fn get_peers(&self) -> anyhow::Result<Vec<PeerInfo>> {
        let conn = self.conn.lock();
        // Banned rows first, then by recency. Exempting them from eviction
        // only kept them in the table; every consumer reads them through
        // here, and a ban's `last_seen` is frozen at the moment it was placed
        // (nothing contacts the peer again), so on an active node they sorted
        // below `MAX_PEERS_ROWS` fresher rows and fell outside this window.
        // The enforcement sets rebuilt at startup and by the periodic resync
        // are both built from this result, so the ban stopped being applied
        // while the row sat in the database looking correct.
        let mut stmt = conn.prepare(
            "SELECT id, addresses, nickname, last_seen, files_shared, banned
             FROM peers
             ORDER BY banned DESC, last_seen DESC
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
        let mut ips = Vec::new();
        for row in stmt.query_map([], |row| row.get::<_, String>(0))? {
            let value = row?;
            let parsed = value.parse::<std::net::Ipv4Addr>().map_err(|error| {
                anyhow::anyhow!("invalid persisted banned IP {value:?}: {error}")
            })?;
            ips.push(parsed);
        }
        Ok(ips)
    }

    /// Strict startup validation for policy-bearing database rows. Runtime UI
    /// loaders may skip malformed non-security rows, but bans must never become
    /// an empty set because one row failed JSON/IP parsing.
    pub fn validate_security_policy(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let mut peers = conn.prepare("SELECT id, addresses FROM peers WHERE banned = 1")?;
        for row in peers.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })? {
            let (peer_id, addresses_json) = row?;
            let addresses: Vec<String> =
                serde_json::from_str(&addresses_json).map_err(|error| {
                    anyhow::anyhow!("invalid addresses for banned peer {peer_id}: {error}")
                })?;
            for address in addresses {
                let host = address
                    .rsplit_once(':')
                    .map(|(host, _)| host)
                    .unwrap_or(address.as_str());
                host.parse::<std::net::Ipv4Addr>().map_err(|error| {
                    anyhow::anyhow!(
                        "invalid address {address:?} for banned peer {peer_id}: {error}"
                    )
                })?;
            }
        }
        let mut banned_ips = conn.prepare("SELECT ip FROM banned_ips")?;
        for row in banned_ips.query_map([], |row| row.get::<_, String>(0))? {
            let value = row?;
            value.parse::<std::net::Ipv4Addr>().map_err(|error| {
                anyhow::anyhow!("invalid persisted banned IP {value:?}: {error}")
            })?;
        }
        Ok(())
    }

    /// Explicit user-authorized reset for policy rows that failed startup
    /// validation. This is never called automatically.
    pub fn reset_security_policy(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        tx.execute("UPDATE peers SET banned = 0", [])?;
        tx.execute("DELETE FROM banned_ips", [])?;
        tx.commit()?;
        Ok(())
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
            "INSERT INTO transfers (id, file_name, file_hash, peer_id, peer_name, direction, status, progress, speed, total_size, transferred, started_at, priority, category, expected_aich, ember_file_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
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
               category = excluded.category,
               expected_aich = excluded.expected_aich,
               ember_file_hash = excluded.ember_file_hash",
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
                transfer.expected_aich,
                transfer.ember_file_hash,
            ],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn get_incomplete_downloads(&self) -> anyhow::Result<Vec<Transfer>> {
        self.get_incomplete_downloads_page(usize::MAX, 0)
    }

    pub fn get_incomplete_downloads_page(
        &self,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Vec<Transfer>> {
        let conn = self.conn.lock();
        // Include `failed` so Temp `.part` files for hash-failed downloads are
        // still owned by a known transfer id and survive orphan sweep. They are
        // restored into the manager as Failed (not auto-started).
        let mut stmt = conn.prepare(
            "SELECT id, file_name, file_hash, peer_id, peer_name, direction, status, progress, speed, total_size, transferred, started_at, priority, category, expected_aich, ember_file_hash
             FROM transfers
             WHERE status NOT IN ('completed', 'noneneeded')
               AND status NOT LIKE 'queue_overflow%'
               AND direction = 'download'
             ORDER BY started_at ASC, id ASC
             LIMIT ?1 OFFSET ?2"
        )?;

        let transfers = stmt
            .query_map(
                params![
                    i64::try_from(limit).unwrap_or(i64::MAX),
                    i64::try_from(offset).unwrap_or(i64::MAX)
                ],
                |row| {
                    let direction_str: String = row.get(5)?;
                    let status_str: String = row.get(6)?;
                    let transferred_val = row.get::<_, i64>(10)?.max(0) as u64;
                    let raw_aich: Option<String> = row.get(14)?;
                    // SQL NULL is the only persisted representation of "no
                    // pin". Empty/whitespace strings can be accepted as absent
                    // at an IPC boundary, but they are never written by Ember;
                    // seeing one in the database is corruption and must not
                    // silently resume an AICH-required transfer unpinned.
                    let (expected_aich, aich_corrupt) = match raw_aich.as_deref() {
                        None => (None, false),
                        Some(value) => match crate::security::parse_expected_aich(Some(value)) {
                            Ok(Some(value)) => (Some(value), false),
                            Ok(None) | Err(_) => (None, true),
                        },
                    };
                    let raw_ember: Option<String> = row.get(15)?;
                    let (ember_file_hash, ember_corrupt) = match raw_ember.as_deref() {
                        None => (None, false),
                        Some(value) => match crate::security::parse_ember_file_hash(Some(value)) {
                            Ok(Some(value)) => (Some(value), false),
                            Ok(None) | Err(_) => (None, true),
                        },
                    };
                    let pin_corrupt = aich_corrupt || ember_corrupt;
                    // Ember first: a row can be corrupt on both pins, and the
                    // Ember digest is the one the user must re-add an `eh=`
                    // link to fix.
                    let pin_failure = if ember_corrupt {
                        Some(TransferFailureCode::EmberPinCorrupt)
                    } else if aich_corrupt {
                        Some(TransferFailureCode::AichPinCorrupt)
                    } else {
                        None
                    };
                    let mut status = match status_str.trim_matches('"') {
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
                    };
                    if pin_corrupt {
                        status = TransferStatus::Failed;
                    }
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
                        status,
                        progress: row.get(7)?,
                        speed: row.get::<_, i64>(8)?.max(0) as u64,
                        total_size: row.get::<_, i64>(9)?.max(0) as u64,
                        transferred: transferred_val,
                        completed_size: transferred_val,
                        started_at: row.get(11)?,
                        failure_reason: pin_failure.map(|f| f.message().to_string()),
                        failure_code: pin_failure.map(|f| f.as_code().to_string()),
                        failure_kind: pin_corrupt.then(|| "permanent".to_string()),
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
                        health_code: None,
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
                        ember_hash: None,
                        expected_aich,
                        ember_file_hash,
                        completed_path: None,
                        up_part_status: None,
                        up_part_count: None,
                        up_peer_part_status: None,
                        // Not persisted (see the `ember_verified` field doc):
                        // completed transfers never come back through this
                        // loader, and an incomplete one hasn't been checked
                        // yet either way.
                        ember_verified: false,
                    })
                },
            )?
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

    /// Deterministically quarantine legacy pending rows beyond the one global
    /// count/remaining-byte budget. Rows are retained (never deleted) and stay
    /// tagged until the frontend acknowledges the migration notice.
    pub fn quarantine_excess_pending_downloads(
        &self,
        max_count: usize,
        max_remaining_bytes: u64,
    ) -> anyhow::Result<usize> {
        let conn = self.conn.lock();
        conn.execute(
            "WITH ranked AS (
                 SELECT id,
                        ROW_NUMBER() OVER (ORDER BY started_at ASC, id ASC) AS row_num,
                        MAX(total_size - transferred, 0) AS remaining
                 FROM transfers
                 WHERE status NOT IN ('completed', 'noneneeded')
                   AND status NOT LIKE 'queue_overflow%'
                   AND direction = 'download'
             ),
             ordered AS (
                 SELECT id,
                        row_num,
                        SUM(
                            CASE
                                WHEN row_num <= ?1 THEN MIN(remaining, ?2 + 1)
                                ELSE 0
                            END
                        ) OVER (ORDER BY row_num ASC) AS remaining_sum
                 FROM ranked
             )
             UPDATE transfers
                SET status = 'queue_overflow'
              WHERE id IN (
                  SELECT id FROM ordered
                   WHERE row_num > ?1 OR remaining_sum > ?2
              )",
            params![
                i64::try_from(max_count).unwrap_or(i64::MAX),
                i64::try_from(max_remaining_bytes).unwrap_or(i64::MAX)
            ],
        )?;
        Ok(conn.changes() as usize)
    }

    /// Mark an overflow migration notice as seen and return its row count.
    pub fn acknowledge_pending_download_overflow(&self) -> anyhow::Result<usize> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM transfers WHERE status = 'queue_overflow'",
            [],
            |row| row.get(0),
        )?;
        if count > 0 {
            tx.execute(
                "UPDATE transfers
                    SET status = 'queue_overflow_acknowledged'
                  WHERE status = 'queue_overflow'",
                [],
            )?;
        }
        tx.commit()?;
        Ok(count.max(0) as usize)
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

    /// Whether a durable, non-terminal download row still owns its `.part`
    /// files even if the row was quarantined instead of restored in memory.
    pub fn incomplete_download_owns_partial(&self, transfer_id: &str) -> bool {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT 1 FROM transfers
              WHERE id = ?1
                AND direction = 'download'
                AND status NOT IN ('completed', 'noneneeded')",
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

    pub fn load_credits(&self) -> anyhow::Result<Vec<CreditRow>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT user_hash, uploaded, downloaded, last_seen, public_key, ident_ip, ident_state, ember_hash, crypto_verified_once FROM credits",
        )?;
        let records = stmt
            .query_map([], |row| {
                let hash_blob: Vec<u8> = row.get(0)?;
                // Exactly 16, not "at least 16", for the reason `load_ember_credits`
                // spells out for its 32-byte key: a longer blob silently truncated
                // to the first 16 bytes would alias two distinct user hashes onto a
                // single credit account. Short blobs were already refused; long ones
                // are now refused too, so the row is skipped rather than merged into
                // the wrong account.
                if hash_blob.len() != 16 {
                    return Err(rusqlite::Error::InvalidColumnType(
                        0,
                        format!("user_hash must be 16 bytes, got {}", hash_blob.len()),
                        rusqlite::types::Type::Blob,
                    ));
                }
                let mut hash = [0u8; 16];
                hash.copy_from_slice(&hash_blob[..16]);
                let ember_blob: Option<Vec<u8>> = row.get(7)?;
                let ember_hash = ember_blob.and_then(|b| {
                    if b.len() == 16 {
                        let mut eh = [0u8; 16];
                        eh.copy_from_slice(&b);
                        Some(eh)
                    } else {
                        None
                    }
                });
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
                    ember_hash,
                    row.get::<_, i64>(8)? != 0,
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
            // Cumulative counters must never shrink: a delayed periodic save
            // started with an older snapshot can otherwise race a newer save
            // (including the shutdown write) and roll totals backwards.
            let mut read_stmt = tx.prepare("SELECT value FROM statistics WHERE key = ?1")?;
            let mut write_stmt =
                tx.prepare("INSERT OR REPLACE INTO statistics (key, value) VALUES (?1, ?2)")?;
            for (key, value) in pairs {
                let to_write = if key.starts_with("cum_") {
                    let existing: i64 = read_stmt
                        .query_row(params![key], |row| row.get(0))
                        .unwrap_or(0);
                    (*value).max(existing)
                } else {
                    *value
                };
                write_stmt.execute(params![key, to_write])?;
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
                    row.get::<_, Option<i64>>(5)?.map(|v| v.max(0) as u64),
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
                file_size.map(|v| v.min(i64::MAX as u64) as i64)
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
    pub fn save_all_credits(&self, credits: &[CreditRowRef<'_>]) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM credits", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO credits (user_hash, uploaded, downloaded, last_seen, public_key, ident_ip, ident_state, ember_hash, crypto_verified_once) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
            )?;
            for (
                hash,
                uploaded,
                downloaded,
                last_seen,
                public_key,
                ident_ip,
                ident_state,
                ember_hash,
                crypto_verified_once,
            ) in credits
            {
                stmt.execute(params![
                    &hash[..],
                    i64::try_from(*uploaded).unwrap_or(i64::MAX),
                    i64::try_from(*downloaded).unwrap_or(i64::MAX),
                    *last_seen,
                    *public_key,
                    i64::from(*ident_ip),
                    i64::from(*ident_state),
                    ember_hash.map(|eh| eh.as_slice()),
                    i64::from(*crypto_verified_once),
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
                    row.get::<_, i64>(5)?.clamp(0, i64::from(u32::MAX)) as u32,
                    row.get::<_, i64>(6)?.clamp(0, i64::from(u32::MAX)) as u32,
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
        credits: &[CreditRowRef<'_>],
        ember_credits: &[(&[u8; 32], u64, u64, i64, i64, u32, u32, u64, i64, bool)],
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM credits", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO credits (user_hash, uploaded, downloaded, last_seen, public_key, ident_ip, ident_state, ember_hash, crypto_verified_once) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
            )?;
            for (
                hash,
                uploaded,
                downloaded,
                last_seen,
                public_key,
                ident_ip,
                ident_state,
                ember_hash,
                crypto_verified_once,
            ) in credits
            {
                stmt.execute(params![
                    &hash[..],
                    i64::try_from(*uploaded).unwrap_or(i64::MAX),
                    i64::try_from(*downloaded).unwrap_or(i64::MAX),
                    *last_seen,
                    *public_key,
                    i64::from(*ident_ip),
                    i64::from(*ident_state),
                    ember_hash.map(|eh| eh.as_slice()),
                    i64::from(*crypto_verified_once),
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

    /// `Ok(false)` means the identity is blocked and nothing was written.
    pub fn add_friend(
        &self,
        user_hash: &str,
        nickname: &str,
        ed25519_pubkey: Option<&[u8; 32]>,
    ) -> anyhow::Result<bool> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let now = chrono::Utc::now().timestamp();
        // The command checks first so it can report this properly; repeating
        // it here closes the window where a block commits in between and
        // leaves the identity listed as a friend and blocked at once.
        //
        // `Ok(false)` rather than an error, matching `add_friend_request`: the
        // caller needs to tell "blocked" from a genuine save failure so it can
        // name the right reason. Bailing here surfaced the race as "Failed to
        // save friend: identity is blocked".
        if Self::blocked_in(&tx, user_hash)? {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO friends (user_hash, nickname, added_at, ed25519_pubkey) \
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(user_hash) DO UPDATE SET nickname = excluded.nickname,
             ed25519_pubkey = COALESCE(excluded.ed25519_pubkey, friends.ed25519_pubkey)",
            params![
                user_hash,
                nickname,
                now,
                ed25519_pubkey.map(|key| key.as_slice())
            ],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn get_friend_public_keys(&self) -> anyhow::Result<Vec<([u8; 16], [u8; 32])>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT user_hash, ed25519_pubkey FROM friends \
             WHERE ed25519_pubkey IS NOT NULL",
        )?;
        let rows = stmt
            .query_map([], |row| {
                let hash_hex: String = row.get(0)?;
                let pubkey: Vec<u8> = row.get(1)?;
                Ok((hash_hex, pubkey))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(hash_hex, pubkey)| {
                let hash_bytes = hex::decode(&hash_hex)?;
                let hash: [u8; 16] = hash_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid friend hash in database"))?;
                let pubkey: [u8; 32] = pubkey
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid friend public key in database"))?;
                if !crate::network::ember::crypto::verify_ember_hash_binding(&pubkey, &hash) {
                    anyhow::bail!("friend public key does not match stored friend hash");
                }
                Ok((hash, pubkey))
            })
            .collect()
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

    /// End a friendship and record that the user wants no further contact.
    ///
    /// Both halves happen in one transaction because either alone is worse
    /// than neither: a removal whose block was lost invites the peer straight
    /// back, and a block whose removal failed leaves them listed as a friend.
    pub fn block_friend(&self, user_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        // Read the name before deleting the rows that hold it — this is the
        // user's only handle on the entry afterwards.
        let nickname: String = tx
            .query_row(
                "SELECT nickname FROM friends WHERE user_hash = ?1",
                params![user_hash],
                |row| row.get(0),
            )
            .or_else(|_| {
                tx.query_row(
                    "SELECT sender_nickname FROM friend_requests WHERE sender_hash = ?1",
                    params![user_hash],
                    |row| row.get(0),
                )
            })
            .unwrap_or_default();
        tx.execute(
            // Re-blocking must not erase what we already knew. By the second
            // call the friend and request rows are long gone, so the lookup
            // above finds nothing and would otherwise overwrite a good name
            // with an empty one. `blocked_at` likewise keeps the date of the
            // original decision rather than the retry.
            "INSERT INTO friend_blocks (user_hash, nickname, blocked_at) \
             VALUES (?1, ?2, ?3) \
             ON CONFLICT(user_hash) DO UPDATE SET \
                 nickname = CASE WHEN excluded.nickname != '' \
                     THEN excluded.nickname ELSE friend_blocks.nickname END",
            params![user_hash, nickname, chrono::Utc::now().timestamp()],
        )?;
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

    /// Lift a block. Deliberately does not restore the friendship: the rows
    /// were deleted when it was applied, so the two have to add each other
    /// again, which is the same handshake any other pair goes through.
    pub fn unblock_friend(&self, user_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM friend_blocks WHERE user_hash = ?1",
            params![user_hash],
        )?;
        Ok(())
    }

    pub fn is_friend_blocked(&self, user_hash: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Ok(Self::blocked_in(&conn, user_hash)?)
    }

    /// The block test as run *inside* an open transaction.
    ///
    /// Every path that can grant an identity access has to consult this
    /// within the same transaction that does the writing. Checking
    /// beforehand only proves they were not blocked at the time of the
    /// check: blocking commits from the UI thread, so it can land in the
    /// window between a caller's test and its insert, and the request or
    /// friendship would then be written over the top of a live block.
    fn blocked_in(conn: &Connection, user_hash: &str) -> rusqlite::Result<bool> {
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM friend_blocks WHERE user_hash = ?1",
            params![user_hash],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// `(user_hash, nickname, blocked_at)`, most recently blocked first.
    pub fn get_blocked_friends(&self) -> anyhow::Result<Vec<(String, String, i64)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT user_hash, nickname, blocked_at FROM friend_blocks \
             ORDER BY blocked_at DESC",
        )?;
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
        sender_pubkey: Option<&[u8; 32]>,
        nickname: &str,
        sender_ip: &str,
        sender_port: u16,
        verified: bool,
    ) -> anyhow::Result<bool> {
        let mut conn = self.conn.lock();
        // The network ingress normalizes this already, but keep the storage
        // boundary bounded for future callers and migrations that bypass the
        // live event path.
        let nickname = crate::security::sanitize_inbound_friend_nickname(nickname);
        let now = chrono::Utc::now().timestamp();
        let tx = conn.transaction()?;

        // Authoritative block test. Callers check first to avoid the work of
        // queueing and notifying, but this is the one that decides, because
        // it cannot be raced by a block committing mid-flight.
        if Self::blocked_in(&tx, sender_hash)? {
            return Ok(false);
        }

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
            "INSERT INTO friend_requests (sender_hash, sender_nickname, received_at, sender_ip, sender_port, verified, sender_pubkey)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(sender_hash) DO UPDATE SET sender_nickname = excluded.sender_nickname,
             sender_ip = excluded.sender_ip, sender_port = excluded.sender_port,
             verified = MAX(friend_requests.verified, excluded.verified),
             sender_pubkey = CASE WHEN excluded.verified != 0
                THEN COALESCE(excluded.sender_pubkey, friend_requests.sender_pubkey)
                ELSE friend_requests.sender_pubkey END",
            params![
                sender_hash,
                nickname,
                now,
                sender_ip,
                sender_port as i64,
                verified as i64,
                sender_pubkey.map(|key| key.as_slice())
            ],
        )?;
        tx.commit()?;
        Ok(true)
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

        let request_data: Option<(String, String, u16, Option<Vec<u8>>)> = {
            let mut stmt = tx.prepare(
                "SELECT sender_nickname, COALESCE(sender_ip, ''), COALESCE(sender_port, 0), sender_pubkey \
                 FROM friend_requests WHERE sender_hash = ?1",
            )?;
            stmt.query_row(params![sender_hash], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?.clamp(0, u16::MAX as i64) as u16,
                    row.get::<_, Option<Vec<u8>>>(3)?,
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

        // A blocked identity should have no request row to accept, but the
        // two can cross: the row may already have been on screen when the
        // block was applied, and the click arrives afterwards. Accepting
        // writes `mutual = 1`, which would hand back chat and browse while
        // the block sat there looking effective.
        if Self::blocked_in(&tx, sender_hash)? {
            anyhow::bail!("identity is blocked");
        }

        let nickname = request_data.0.clone();
        let now = chrono::Utc::now().timestamp();

        // Insert the friend with `mutual = 1` directly (matches the
        // previous `add_friend` + `set_friend_mutual` semantics). On
        // conflict we refresh the nickname and re-assert mutual so a
        // re-accept after a previous demotion still flips the flag.
        // `added_at` is intentionally NOT overwritten on conflict so
        // long-standing friends keep their original add timestamp.
        tx.execute(
            "INSERT INTO friends (user_hash, nickname, added_at, mutual, ed25519_pubkey) \
             VALUES (?1, ?2, ?3, 1, ?4) \
             ON CONFLICT(user_hash) DO UPDATE SET nickname = excluded.nickname, mutual = 1,
             ed25519_pubkey = COALESCE(excluded.ed25519_pubkey, friends.ed25519_pubkey)",
            params![sender_hash, nickname, now, request_data.3.as_deref()],
        )?;

        {
            let (_, ref ip, port, _) = request_data;
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
        Ok(Some((request_data.0, request_data.1, request_data.2)))
    }

    /// Promote an existing friend to mutual and refresh their last-known
    /// address. Used by the auto-confirm path: an inbound friend request from
    /// a peer we already added, when the user has turned off "require
    /// approval". Unlike `accept_friend_request` this does not touch the
    /// `friend_requests` table (no queued row exists in that flow). Returns
    /// the number of friend rows updated — 0 means the peer wasn't actually in
    /// the friend list, so the caller should fall back to queuing.
    pub fn set_friend_mutual(
        &self,
        user_hash: &str,
        ip: &str,
        port: u16,
        ed25519_pubkey: Option<&[u8; 32]>,
    ) -> anyhow::Result<usize> {
        let conn = self.conn.lock();
        let now = chrono::Utc::now().timestamp();
        // Promotion to mutual is the widest grant there is — it opens browse
        // and friends-only serving — so the block test rides along in the
        // UPDATE itself. A blocked identity matches no row, and the caller's
        // "nothing was updated" path already declines to grant anything.
        let updated = if !ip.is_empty() && port > 0 {
            conn.execute(
                "UPDATE friends SET mutual = 1, last_ip = ?2, last_port = ?3, last_seen = ?4,
                 ed25519_pubkey = COALESCE(?5, ed25519_pubkey) WHERE user_hash = ?1
                 AND NOT EXISTS (SELECT 1 FROM friend_blocks WHERE user_hash = ?1)",
                params![
                    user_hash,
                    ip,
                    port as i64,
                    now,
                    ed25519_pubkey.map(|key| key.as_slice())
                ],
            )?
        } else {
            conn.execute(
                "UPDATE friends SET mutual = 1,
                 ed25519_pubkey = COALESCE(?2, ed25519_pubkey) WHERE user_hash = ?1
                 AND NOT EXISTS (SELECT 1 FROM friend_blocks WHERE user_hash = ?1)",
                params![user_hash, ed25519_pubkey.map(|key| key.as_slice())],
            )?
        };
        Ok(updated)
    }

    /// Delivery state of an outbound chat message. Received messages are
    /// always [`ChatDelivery::Delivered`].
    pub fn insert_chat_message(
        &self,
        friend_hash: &str,
        direction: &str,
        message: &str,
    ) -> anyhow::Result<i64> {
        self.insert_chat_message_with_delivery(friend_hash, direction, message, CHAT_DELIVERED)
    }

    /// Store an outbound message that could not be handed to a live session,
    /// so it can be flushed the next time the friend is reachable.
    pub fn insert_pending_chat_message(
        &self,
        friend_hash: &str,
        message: &str,
    ) -> anyhow::Result<i64> {
        self.insert_chat_message_with_delivery(friend_hash, "sent", message, CHAT_QUEUED)
    }

    pub fn insert_chat_message_with_delivery(
        &self,
        friend_hash: &str,
        direction: &str,
        message: &str,
        delivery: i64,
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
            "INSERT INTO chat_messages (friend_hash, direction, message, timestamp, read, delivery) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![friend_hash, direction, CHAT_CIPHERTEXT_PREFIX, now, if direction == "sent" { 1 } else { 0 }, delivery],
        )?;
        let new_id = tx.last_insert_rowid();
        let encrypted = Self::encrypt_chat_body(
            self.require_chat_key()?,
            new_id,
            friend_hash,
            direction,
            now,
            message,
        )?;
        tx.execute(
            "UPDATE chat_messages SET message = ?1 WHERE id = ?2",
            params![encrypted, new_id],
        )?;
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

    /// Outbound messages still waiting on a session, oldest first, so a flush
    /// replays them in the order the user typed them.
    pub fn pending_chat_messages(
        &self,
        friend_hash: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<(i64, String, i64)>> {
        // Nothing can be sent while chat is locked, and these rows must not be
        // marked failed either: the key may yet be restored, and abandoning
        // them would throw away messages that are still perfectly recoverable.
        if self.chat_key.is_none() {
            return Ok(Vec::new());
        }
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, message, timestamp FROM chat_messages \
             WHERE friend_hash = ?1 AND delivery = ?2 AND direction = 'sent' \
             ORDER BY id ASC LIMIT ?3",
        )?;
        let rows: Vec<(i64, String, i64)> = stmt
            .query_map(params![friend_hash, CHAT_QUEUED, limit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();
        drop(stmt);
        drop(conn);
        // Decrypt outside the statement borrow, mirroring `get_chat_messages`.
        let mut out = Vec::with_capacity(rows.len());
        let mut undecryptable = Vec::new();
        for (id, body, ts) in rows {
            match Self::decrypt_chat_body(
                self.require_chat_key()?,
                id,
                friend_hash,
                "sent",
                ts,
                &body,
            ) {
                Ok(plain) => out.push((id, plain, ts)),
                // Cannot be sent and never will be, so record that rather than
                // skipping it. Skipping left the row queued while
                // `pending_chat_counts` went on counting it, so the unsent
                // total never reached zero and nothing could clear it.
                Err(_) => undecryptable.push(id),
            }
        }
        if !undecryptable.is_empty() {
            tracing::warn!(
                "Marking {} undecryptable queued chat message(s) for {friend_hash} as failed",
                undecryptable.len()
            );
            let conn = self.conn.lock();
            for id in undecryptable {
                let _ = conn.execute(
                    "UPDATE chat_messages SET delivery = ?1 WHERE id = ?2",
                    params![CHAT_FAILED, id],
                );
            }
        }
        Ok(out)
    }

    /// Move a stored outbound message between delivery states.
    pub fn set_chat_delivery(&self, id: i64, delivery: i64) -> anyhow::Result<usize> {
        let conn = self.conn.lock();
        Ok(conn.execute(
            "UPDATE chat_messages SET delivery = ?1 WHERE id = ?2",
            params![delivery, id],
        )?)
    }

    /// Count of outbound messages still queued, per friend. Drives the
    /// "unsent" affordance in the chat dock.
    pub fn pending_chat_counts(&self) -> anyhow::Result<Vec<(String, i64)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT friend_hash, COUNT(*) FROM chat_messages \
             WHERE delivery = ?1 AND direction = 'sent' GROUP BY friend_hash",
        )?;
        let rows = stmt
            .query_map(params![CHAT_QUEUED], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Abandon outbound messages that have been queued too long, across every
    /// conversation.
    ///
    /// Deliberately global and eager rather than filtered at each read. Nothing
    /// used to assign [`CHAT_FAILED`] at all, so a message to a friend who never
    /// returned stayed queued for the life of the database. Expiring it lazily
    /// on flush only moved the problem: the flush runs per friend and only when
    /// one reconnects, so the conversation, the unsent badge and the queue
    /// itself could each hold a different view of the same row. One writer that
    /// every reader observes keeps them agreeing.
    /// Returns the `(id, friend_hash)` of every row it abandoned, so the caller
    /// can tell the UI which live bubbles to flip. Without that, an open
    /// conversation keeps rendering an abandoned message as "queued" until it
    /// is reloaded, even though the row on disk already says failed.
    pub fn expire_stale_queued_chat(&self) -> anyhow::Result<Vec<(i64, String)>> {
        // Never while chat is locked. `pending_chat_messages` deliberately
        // refuses to flush *or* fail queued sends in that state, because a
        // restored key can still deliver them; abandoning them here would take
        // that back and mark as failed the very rows that recovery would have
        // rescued. The ceiling resumes applying once the key is back.
        if self.chat_key.is_none() {
            return Ok(Vec::new());
        }
        let cutoff = chrono::Utc::now().timestamp() - CHAT_QUEUE_MAX_AGE_SECS;
        let conn = self.conn.lock();
        // Read the victims and update them under the same lock, so the ids
        // reported are exactly the rows this sweep changed.
        let expired: Vec<(i64, String)> = {
            let mut stmt = conn.prepare(
                "SELECT id, friend_hash FROM chat_messages \
                 WHERE delivery = ?1 AND direction = 'sent' AND timestamp < ?2",
            )?;
            let rows = stmt
                .query_map(params![CHAT_QUEUED, cutoff], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })?
                .filter_map(|r| r.ok())
                .collect();
            rows
        };
        if expired.is_empty() {
            return Ok(expired);
        }
        conn.execute(
            "UPDATE chat_messages SET delivery = ?1 \
             WHERE delivery = ?2 AND direction = 'sent' AND timestamp < ?3",
            params![CHAT_FAILED, CHAT_QUEUED, cutoff],
        )?;
        tracing::info!(
            "Gave up on {} chat message(s) queued longer than {} days",
            expired.len(),
            CHAT_QUEUE_MAX_AGE_SECS / 86_400
        );
        Ok(expired)
    }

    pub fn get_chat_messages(
        &self,
        friend_hash: &str,
        limit: i64,
        before_id: Option<i64>,
    ) -> anyhow::Result<Vec<(i64, String, String, i64, bool, i64)>> {
        let conn = self.conn.lock();
        let rows: Vec<(i64, String, String, i64, bool, i64)> = if let Some(bid) = before_id {
            let mut stmt = conn.prepare(
                "SELECT id, direction, message, timestamp, read, delivery FROM chat_messages WHERE friend_hash = ?1 AND id < ?2 ORDER BY id DESC LIMIT ?3"
            )?;
            let mapped = stmt.query_map(params![friend_hash, bid, limit], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get::<_, i64>(4)? != 0,
                    row.get::<_, i64>(5)?,
                ))
            })?;
            mapped.collect::<Result<Vec<_>, _>>()?
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, direction, message, timestamp, read, delivery FROM chat_messages WHERE friend_hash = ?1 ORDER BY id DESC LIMIT ?2"
            )?;
            let mapped = stmt.query_map(params![friend_hash, limit], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get::<_, i64>(4)? != 0,
                    row.get::<_, i64>(5)?,
                ))
            })?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };
        // Locked: every row is sealed, so report them all as unavailable in one
        // go rather than warning once per row for a condition that is a property
        // of the database, not of any individual message.
        let Some(chat_key) = self.chat_key.as_deref() else {
            return Ok(rows
                .into_iter()
                .map(|(id, direction, _stored, timestamp, read, delivery)| {
                    (
                        id,
                        direction,
                        CHAT_UNAVAILABLE_TEXT.to_string(),
                        timestamp,
                        read,
                        delivery,
                    )
                })
                .collect());
        };
        let mut messages = Vec::with_capacity(rows.len());
        for (id, direction, stored, timestamp, read, delivery) in rows {
            match Self::decrypt_chat_body(chat_key, id, friend_hash, &direction, timestamp, &stored)
            {
                Ok(message) => messages.push((id, direction, message, timestamp, read, delivery)),
                Err(error) => {
                    tracing::warn!(
                        "Chat row {id} for friend {friend_hash} is unavailable; preserving its ciphertext for later recovery: {error}"
                    );
                    messages.push((
                        id,
                        direction,
                        CHAT_UNAVAILABLE_TEXT.to_string(),
                        timestamp,
                        read,
                        delivery,
                    ));
                }
            }
        }
        Ok(messages)
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

    pub fn list_channels(&self) -> anyhow::Result<Vec<StoredChannel>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
                "SELECT c.channel_id, c.pubkey, c.name, c.visibility, c.is_owner, c.topic, c.welcome,
                    c.joined_at, c.last_active,
                    (SELECT COUNT(*) FROM channel_members m WHERE m.channel_id = c.channel_id),
                    (SELECT COUNT(*) FROM channel_messages msg
                     WHERE msg.channel_id = c.channel_id AND msg.read = 0 AND msg.direction = 'received'),
                    c.successor_id, c.predecessor_id, c.owner_pubkey, c.key_epoch,
                    c.successor_nominee, c.claim_after_days, c.key_epoch_wanted,
                    c.moderation_updated_at, c.moderation_checked_at,
                    c.in_room, c.deleted
             FROM channels c
             ORDER BY c.last_active DESC, c.joined_at DESC",
        )?;
        let rows = stmt
            .query_map([], |row| Self::stored_channel_from_row(row))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Remember what a Discover walk turned up.
    ///
    /// Upsert rather than replace-all, because a walk that lost a shard to a
    /// timeout still knows everything the previous one did about the other
    /// fifteen. Clearing the table each time would empty the cache precisely
    /// when the network is least able to refill it.
    pub fn cache_channel_listings(&self, rows: &[(String, String, String)]) -> anyhow::Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let now = chrono::Utc::now().timestamp();
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO channel_index_cache (channel_id, pubkey, name, last_seen)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(channel_id) DO UPDATE SET
                    pubkey = excluded.pubkey,
                    name = excluded.name,
                    last_seen = excluded.last_seen",
            )?;
            for (channel_id, pubkey, name) in rows {
                stmt.execute(params![channel_id, pubkey, name, now])?;
            }
        }
        tx.execute(
            "DELETE FROM channel_index_cache WHERE last_seen < ?1",
            params![now - CHANNEL_CACHE_MAX_AGE_SECS],
        )?;
        tx.execute(
            "DELETE FROM channel_index_cache WHERE channel_id NOT IN (
                 SELECT channel_id FROM channel_index_cache
                 ORDER BY last_seen DESC LIMIT ?1
             )",
            params![MAX_CHANNEL_CACHE_ROWS],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Rooms an earlier Discover walk found, most recently seen first.
    pub fn list_cached_channels(&self) -> anyhow::Result<Vec<CachedChannel>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT channel_id, pubkey, name FROM channel_index_cache
             ORDER BY last_seen DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(CachedChannel {
                    channel_id: row.get(0)?,
                    pubkey: row.get(1)?,
                    name: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_channel(&self, channel_id: &str) -> anyhow::Result<Option<StoredChannel>> {
        let conn = self.conn.lock();
        Self::get_channel_locked(&conn, channel_id)
    }

    fn get_channel_locked(
        conn: &Connection,
        channel_id: &str,
    ) -> anyhow::Result<Option<StoredChannel>> {
        let row = conn
            .query_row(
                "SELECT c.channel_id, c.pubkey, c.name, c.visibility, c.is_owner, c.topic, c.welcome,
                        c.joined_at, c.last_active,
                        (SELECT COUNT(*) FROM channel_members m WHERE m.channel_id = c.channel_id),
                        (SELECT COUNT(*) FROM channel_messages msg
                         WHERE msg.channel_id = c.channel_id AND msg.read = 0 AND msg.direction = 'received'),
                        c.successor_id, c.predecessor_id, c.owner_pubkey, c.key_epoch,
                        c.successor_nominee, c.claim_after_days, c.key_epoch_wanted,
                        c.moderation_updated_at, c.moderation_checked_at,
                        c.in_room, c.deleted
                 FROM channels c WHERE c.channel_id = ?1",
                params![channel_id],
                |row| Self::stored_channel_from_row(row),
            )
            .optional()?;
        Ok(row)
    }

    fn stored_channel_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredChannel> {
        Ok(StoredChannel {
            channel_id: row.get(0)?,
            pubkey: row.get(1)?,
            name: row.get(2)?,
            visibility: row.get(3)?,
            is_owner: row.get::<_, i64>(4)? != 0,
            topic: row.get(5)?,
            welcome: row.get(6)?,
            joined_at: row.get(7)?,
            last_active: row.get(8)?,
            member_count: row.get(9)?,
            unread: row.get(10)?,
            successor_id: row.get::<_, String>(11).unwrap_or_default(),
            predecessor_id: row.get::<_, String>(12).unwrap_or_default(),
            owner_pubkey: row.get::<_, String>(13).unwrap_or_default(),
            key_epoch: row.get::<_, i64>(14).unwrap_or(0),
            successor_nominee: row.get::<_, String>(15).unwrap_or_default(),
            claim_after_days: row.get::<_, i64>(16).unwrap_or(0),
            key_epoch_wanted: row.get::<_, i64>(17).unwrap_or(0),
            moderation_updated_at: row.get::<_, i64>(18).unwrap_or(0),
            moderation_checked_at: row.get::<_, i64>(19).unwrap_or(0),
            in_room: row.get::<_, i64>(20).unwrap_or(1) != 0,
            deleted: row.get::<_, i64>(21).unwrap_or(0) != 0,
        })
    }

    pub fn insert_channel(
        &self,
        channel_id: &str,
        pubkey: &str,
        name: &str,
        visibility: &str,
        is_owner: bool,
        owner_seed: Option<&[u8; 32]>,
        join_secret: Option<&[u8; 32]>,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        self.insert_channel_locked(
            &conn,
            channel_id,
            pubkey,
            name,
            visibility,
            is_owner,
            owner_seed,
            join_secret,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_channel_locked(
        &self,
        conn: &Connection,
        channel_id: &str,
        pubkey: &str,
        name: &str,
        visibility: &str,
        is_owner: bool,
        owner_seed: Option<&[u8; 32]>,
        join_secret: Option<&[u8; 32]>,
    ) -> anyhow::Result<()> {
        let owner_enc = match owner_seed {
            Some(seed) => Some(Self::encrypt_channel_secret(
                self.require_chat_key()?,
                channel_id,
                "owner",
                seed,
            )?),
            None => None,
        };
        let join_enc = match join_secret {
            Some(secret) => Some(Self::encrypt_channel_secret(
                self.require_chat_key()?,
                channel_id,
                "join",
                secret,
            )?),
            None => None,
        };
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO channels (channel_id, pubkey, name, visibility, is_owner, owner_seed,
                 join_secret, topic, welcome, joined_at, last_active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '', '', ?8, ?8)",
            params![
                channel_id,
                pubkey,
                name,
                visibility,
                if is_owner { 1 } else { 0 },
                owner_enc,
                join_enc,
                now
            ],
        )?;
        Ok(())
    }

    /// Walk in or out without dropping secrets or history.
    pub fn set_channel_in_room(&self, channel_id: &str, in_room: bool) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let n = conn.execute(
            "UPDATE channels SET in_room = ?2 WHERE channel_id = ?1 AND deleted = 0",
            params![channel_id, if in_room { 1 } else { 0 }],
        )?;
        Ok(n > 0)
    }

    /// Owner-only permanent delete on this device: leave the door and keep the
    /// row so the same name is not minted again locally.
    pub fn tombstone_channel(&self, channel_id: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let n = conn.execute(
            "UPDATE channels SET in_room = 0, deleted = 1 WHERE channel_id = ?1",
            params![channel_id],
        )?;
        Ok(n > 0)
    }

    /// Walk this device out of rooms the directory has tombstoned.
    pub fn walk_out_deleted_channels(&self, deleted_ids: &[String]) -> anyhow::Result<Vec<String>> {
        if deleted_ids.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn.lock();
        let mut walked = Vec::new();
        for id in deleted_ids {
            let n = conn.execute(
                "UPDATE channels SET in_room = 0, deleted = 1 WHERE channel_id = ?1 AND deleted = 0",
                params![id],
            )?;
            if n > 0 {
                walked.push(id.clone());
            }
        }
        Ok(walked)
    }

    /// Forget a channel. A ban recorded against `keep_banned_member` survives,
    /// because a ban belongs to the room rather than to the membership: wiping
    /// it made leaving and rejoining a client-side ban reset, and the local
    /// flag is what stops the composer accepting sends that every remaining
    /// member will discard. Pass `None` when there is nothing to preserve
    /// (rolling back a room that was never published).
    pub fn delete_channel(
        &self,
        channel_id: &str,
        keep_banned_member: Option<&str>,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM channel_messages WHERE channel_id = ?1",
            params![channel_id],
        )?;
        // Any half-finished handoff goes with the room. Left behind it is an
        // unreachable row keyed to a channel that no longer exists.
        tx.execute(
            "DELETE FROM channel_handoff_pending WHERE old_channel_id = ?1",
            params![channel_id],
        )?;
        tx.execute(
            "DELETE FROM channel_key_epochs WHERE channel_id = ?1",
            params![channel_id],
        )?;
        match keep_banned_member {
            Some(pk) => tx.execute(
                "DELETE FROM channel_members
                 WHERE channel_id = ?1
                   AND NOT (banned = 1 AND lower(member_pubkey) = lower(?2))",
                params![channel_id, pk],
            )?,
            None => tx.execute(
                "DELETE FROM channel_members WHERE channel_id = ?1",
                params![channel_id],
            )?,
        };
        let n = tx.execute(
            "DELETE FROM channels WHERE channel_id = ?1",
            params![channel_id],
        )?;
        tx.commit()?;
        Ok(n > 0)
    }

    pub fn load_channel_owner_seed(&self, channel_id: &str) -> anyhow::Result<Option<[u8; 32]>> {
        let conn = self.conn.lock();
        self.load_channel_secret_locked(&conn, channel_id, "owner_seed", "owner")
    }

    pub fn load_channel_join_secret(&self, channel_id: &str) -> anyhow::Result<Option<[u8; 32]>> {
        let conn = self.conn.lock();
        self.load_channel_secret_locked(&conn, channel_id, "join_secret", "join")
    }

    /// The secret a room is *currently* sealing with: its newest epoch, or the
    /// original `join_secret` if it has never rotated.
    ///
    /// A handoff that carries a secret forward has to carry this one. Rotation
    /// writes new keys to `channel_key_epochs` and never touches `join_secret`,
    /// so inheriting that column would hand the successor room the key the last
    /// ban rotated away from — letting an evicted member who kept their original
    /// invite read the new room, and quietly undoing the eviction.
    fn load_current_channel_secret_locked(
        &self,
        conn: &Connection,
        channel_id: &str,
    ) -> anyhow::Result<Option<[u8; 32]>> {
        let newest: Option<(i64, String)> = conn
            .query_row(
                "SELECT epoch, secret_enc FROM channel_key_epochs
                 WHERE channel_id = ?1 ORDER BY epoch DESC LIMIT 1",
                params![channel_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((epoch, enc)) = newest {
            return Ok(Some(Self::decrypt_channel_secret(
                self.require_chat_key()?,
                channel_id,
                &format!("epoch{epoch}"),
                &enc,
            )?));
        }
        self.load_channel_secret_locked(conn, channel_id, "join_secret", "join")
    }

    /// Shared body for the two secret loaders, callable while the connection
    /// lock is already held — the handoff needs to read and write in one
    /// transaction, and taking the lock again inside it would deadlock.
    fn load_channel_secret_locked(
        &self,
        conn: &Connection,
        channel_id: &str,
        column: &str,
        label: &str,
    ) -> anyhow::Result<Option<[u8; 32]>> {
        let stored: Option<String> = conn
            .query_row(
                &format!("SELECT {column} FROM channels WHERE channel_id = ?1"),
                params![channel_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        match stored {
            Some(enc) => Ok(Some(Self::decrypt_channel_secret(
                self.require_chat_key()?,
                channel_id,
                label,
                &enc,
            )?)),
            None => Ok(None),
        }
    }

    /// How many content-key epochs a room keeps.
    ///
    /// A member who was offline across a rotation still has to read what
    /// arrived in the gap, and history sync replays messages sealed under
    /// whichever epoch was current when they were sent. Four is the margin;
    /// past that a member needs a fresh invite, which is the same position an
    /// evicted member is in and the point of rotating at all.
    pub const CHANNEL_KEY_EPOCHS_KEPT: usize = 4;

    /// Record a rotated content key and make it current, dropping epochs past
    /// the retention window.
    pub fn insert_channel_key_epoch(
        &self,
        channel_id: &str,
        epoch: i64,
        secret: &[u8; 32],
    ) -> anyhow::Result<()> {
        let enc = Self::encrypt_channel_secret(
            self.require_chat_key()?,
            channel_id,
            &format!("epoch{epoch}"),
            secret,
        )?;
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO channel_key_epochs (channel_id, epoch, secret_enc, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(channel_id, epoch) DO UPDATE SET secret_enc = excluded.secret_enc",
            params![channel_id, epoch, enc, chrono::Utc::now().timestamp()],
        )?;
        // Never walk the epoch backwards: an out-of-order record must not
        // demote the room to an older key for everything it sends next.
        tx.execute(
            "UPDATE channels SET key_epoch = ?2 WHERE channel_id = ?1 AND key_epoch < ?2",
            params![channel_id, epoch],
        )?;
        tx.execute(
            "DELETE FROM channel_key_epochs WHERE channel_id = ?1 AND epoch NOT IN (
                 SELECT epoch FROM channel_key_epochs WHERE channel_id = ?1
                 ORDER BY epoch DESC LIMIT ?2
             )",
            params![channel_id, Self::CHANNEL_KEY_EPOCHS_KEPT as i64],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Undo a rotation whose moderation snapshot never got committed.
    ///
    /// The epoch and the snapshot announcing it have to land together: the owner
    /// seals new traffic with whatever `key_epoch` says, and members only go
    /// looking for a key the snapshot names. Keeping a rotation whose snapshot
    /// failed would leave the owner talking under a key nobody knows to fetch.
    pub fn rollback_channel_key_epoch(&self, channel_id: &str, epoch: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM channel_key_epochs WHERE channel_id = ?1 AND epoch = ?2",
            params![channel_id, epoch],
        )?;
        tx.execute(
            "UPDATE channels SET key_epoch = (
                 SELECT COALESCE(MAX(epoch), 0) FROM channel_key_epochs WHERE channel_id = ?1
             ) WHERE channel_id = ?1",
            params![channel_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Retained content-key secrets for a room, newest epoch first.
    ///
    /// Callers try these in order, so the current epoch is attempted before
    /// any older one. Empty when the room has never rotated — the caller then
    /// falls back to `load_channel_join_secret`, which is epoch 0.
    pub fn load_channel_key_epochs(
        &self,
        channel_id: &str,
    ) -> anyhow::Result<Vec<(i64, [u8; 32])>> {
        let stored: Vec<(i64, String)> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare(
                "SELECT epoch, secret_enc FROM channel_key_epochs
                 WHERE channel_id = ?1 ORDER BY epoch DESC",
            )?;
            let mapped = stmt.query_map(params![channel_id], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };
        if stored.is_empty() {
            return Ok(Vec::new());
        }
        let chat_key = self.require_chat_key()?;
        let mut out = Vec::with_capacity(stored.len());
        for (epoch, enc) in stored {
            match Self::decrypt_channel_secret(
                chat_key,
                channel_id,
                &format!("epoch{epoch}"),
                &enc,
            ) {
                Ok(secret) => out.push((epoch, secret)),
                // One unreadable epoch must not hide the others: the current
                // key may well be fine and the room still usable.
                Err(error) => {
                    tracing::warn!(
                        "Channel {channel_id} epoch {epoch} secret is unreadable: {error}"
                    );
                }
            }
        }
        Ok(out)
    }

    /// Note that a search for this room's owner-signed record came back.
    ///
    /// Recorded when results are drained rather than when the search starts:
    /// asking and getting no answer means we could not reach anyone, which is
    /// not evidence that the owner has stopped publishing.
    pub fn touch_channel_moderation_checked(
        &self,
        channel_id: &str,
        checked_at: i64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE channels SET moderation_checked_at = ?2
             WHERE channel_id = ?1 AND moderation_checked_at < ?2",
            params![channel_id, checked_at],
        )?;
        Ok(())
    }

    /// Record the owner's succession settings. Empty nominee or zero days
    /// disables it, which leaves the room frozen if the owner never returns.
    pub fn set_channel_succession(
        &self,
        channel_id: &str,
        nominee: &str,
        claim_after_days: i64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE channels SET successor_nominee = ?2, claim_after_days = ?3
             WHERE channel_id = ?1",
            params![channel_id, nominee, claim_after_days],
        )?;
        Ok(())
    }

    pub fn set_channel_pending_handoff(
        &self,
        channel_id: &str,
        successor_member: &str,
        version: u64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE channels SET pending_successor = ?2, pending_handoff_version = ?3
             WHERE channel_id = ?1",
            params![channel_id, successor_member, version as i64],
        )?;
        Ok(())
    }

    pub fn channel_pending_handoff(
        &self,
        channel_id: &str,
    ) -> anyhow::Result<Option<(String, u64)>> {
        let conn = self.conn.lock();
        let row: Option<(String, i64)> = conn
            .query_row(
                "SELECT pending_successor, pending_handoff_version FROM channels WHERE channel_id = ?1",
                params![channel_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.and_then(|(pk, ver)| {
            if pk.is_empty() || ver <= 0 {
                None
            } else {
                Some((pk, ver as u64))
            }
        }))
    }

    pub fn store_handoff_pending_seed(
        &self,
        old_channel_id: &str,
        version: u64,
        successor_pubkey: &str,
        owner_seed: &[u8; 32],
    ) -> anyhow::Result<()> {
        let enc = Self::encrypt_channel_secret(
            self.require_chat_key()?,
            old_channel_id,
            "handoff",
            owner_seed,
        )?;
        let now = chrono::Utc::now().timestamp();
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO channel_handoff_pending (old_channel_id, version, successor_pubkey, owner_seed, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(old_channel_id) DO UPDATE SET
                version = excluded.version,
                successor_pubkey = excluded.successor_pubkey,
                owner_seed = excluded.owner_seed,
                created_at = excluded.created_at",
            params![old_channel_id, version as i64, successor_pubkey, enc, now],
        )?;
        Ok(())
    }

    pub fn load_handoff_pending_row(
        &self,
        old_channel_id: &str,
    ) -> anyhow::Result<Option<(String, u64, [u8; 32])>> {
        let stored: Option<(String, i64, String)> = {
            let conn = self.conn.lock();
            conn.query_row(
                "SELECT successor_pubkey, version, owner_seed FROM channel_handoff_pending
                 WHERE old_channel_id = ?1",
                params![old_channel_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
        };
        let Some((pk, ver, enc)) = stored else {
            return Ok(None);
        };
        let seed = Self::decrypt_channel_secret(
            self.require_chat_key()?,
            old_channel_id,
            "handoff",
            &enc,
        )?;
        Ok(Some((pk, ver as u64, seed)))
    }

    pub fn load_handoff_pending_seed(
        &self,
        old_channel_id: &str,
        successor_pubkey: &str,
        version: u64,
    ) -> anyhow::Result<Option<[u8; 32]>> {
        let Some((pk, ver, seed)) = self.load_handoff_pending_row(old_channel_id)? else {
            return Ok(None);
        };
        if pk != successor_pubkey || ver != version {
            return Ok(None);
        }
        Ok(Some(seed))
    }

    pub fn clear_handoff_pending(&self, old_channel_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM channel_handoff_pending WHERE old_channel_id = ?1",
            params![old_channel_id],
        )?;
        Ok(())
    }

    /// Follow an owner-signed handoff: create the successor room, copy local
    /// history, and mark the old id as superseded. Never copies `owner_seed`
    /// from the old row.
    pub fn apply_channel_handoff(
        &self,
        old_channel_id: &str,
        successor_pubkey: &str,
        successor_channel_id: &str,
        _version: u64,
        keep_join_secret: bool,
        successor_owner_seed: Option<&[u8; 32]>,
    ) -> anyhow::Result<bool> {
        // The identity-critical part runs as one transaction. Each step used to
        // take the connection lock on its own, so a crash between them could
        // leave a successor room with no seed, or an old room pointed at a
        // successor that was never created — states nothing later repairs.
        //
        // History replay stays outside it: 5,000 inserts is too long to hold
        // the write lock for, and it is safe to resume because `predecessor_id`
        // is already recorded and the message IDs are deterministic.
        //
        // What happens next is decided inside the transaction but acted on after
        // the lock is released — `clear_handoff_pending` and the replay both
        // take the lock themselves, and this mutex is not reentrant.
        let _replayed = {
            let conn = self.conn.lock();
            let tx = conn.unchecked_transaction()?;
            let old = match Self::get_channel_locked(&tx, old_channel_id)? {
                Some(ch) => ch,
                None => return Ok(false),
            };
            if !old.successor_id.is_empty() {
                if old.successor_id != successor_channel_id {
                    return Ok(false);
                }
                // Already applied. Still worth a pass: the nominee may be
                // installing the seed for a successor row a previous run
                // created without it.
                if let Some(seed) = successor_owner_seed {
                    if self
                        .load_channel_secret_locked(&tx, successor_channel_id, "owner_seed", "owner")?
                        .is_none()
                    {
                        let enc = Self::encrypt_channel_secret(
                            self.require_chat_key()?,
                            successor_channel_id,
                            "owner",
                            seed,
                        )?;
                        tx.execute(
                            "UPDATE channels SET is_owner = 1, owner_seed = ?2
                             WHERE channel_id = ?1",
                            params![successor_channel_id, enc],
                        )?;
                    }
                }
                tx.commit()?;
                true
            } else {
                let successor_exists =
                    Self::get_channel_locked(&tx, successor_channel_id)?.is_some();
                if successor_exists {
                    // The owner may have created the successor row first,
                    // without the new seed. The named successor installs it
                    // here — never by copying the old `owner_seed`.
                    if let Some(seed) = successor_owner_seed {
                        let enc = Self::encrypt_channel_secret(
                            self.require_chat_key()?,
                            successor_channel_id,
                            "owner",
                            seed,
                        )?;
                        tx.execute(
                            "UPDATE channels SET is_owner = 1, owner_seed = ?2
                             WHERE channel_id = ?1",
                            params![successor_channel_id, enc],
                        )?;
                    }
                } else {
                    let join_secret = if keep_join_secret {
                        self.load_current_channel_secret_locked(&tx, old_channel_id)?
                    } else {
                        hex::decode(successor_pubkey)
                            .ok()
                            .and_then(|b| <[u8; 32]>::try_from(b).ok())
                            .map(|p| crate::network::ember::channel::public_join_secret(&p))
                    };
                    self.insert_channel_locked(
                        &tx,
                        successor_channel_id,
                        successor_pubkey,
                        &old.name,
                        &old.visibility,
                        successor_owner_seed.is_some(),
                        successor_owner_seed,
                        join_secret.as_ref(),
                    )?;
                    tx.execute(
                        "UPDATE channels SET predecessor_id = ?2, topic = ?3, welcome = ?4
                         WHERE channel_id = ?1",
                        params![successor_channel_id, old_channel_id, old.topic, old.welcome],
                    )?;
                    tx.execute(
                        "INSERT OR IGNORE INTO channel_members
                            (channel_id, member_pubkey, nickname, last_seen, banned, moderator)
                         SELECT ?2, member_pubkey, nickname, last_seen, banned, moderator
                         FROM channel_members WHERE channel_id = ?1",
                        params![old_channel_id, successor_channel_id],
                    )?;
                }
                tx.execute(
                    "UPDATE channels SET successor_id = ?2, is_owner = 0, owner_seed = NULL,
                         pending_successor = '', pending_handoff_version = 0
                     WHERE channel_id = ?1",
                    params![old_channel_id, successor_channel_id],
                )?;
                tx.commit()?;
                true
            }
        };
        let history = self.get_channel_messages(old_channel_id, 5_000, None)?;
        for (id, sender, direction, message, timestamp, read) in history.into_iter().rev() {
            let msg_id = format!("handoff-{old_channel_id}-{id}");
            // No signature travels with a handoff copy. The author signed the
            // line against the *old* room's id, so the original does not verify
            // under the successor's, and re-signing here is the forgery the
            // signature exists to prevent. The copy stays readable locally and
            // is not re-served to anyone else.
            let _ = self.insert_channel_message(
                successor_channel_id,
                &sender,
                &direction,
                &message,
                &msg_id,
                timestamp,
                "",
                read,
            );
        }
        let _ = self.clear_handoff_pending(old_channel_id);
        Ok(true)
    }

    pub fn upsert_channel_member(
        &self,
        channel_id: &str,
        member_pubkey: &str,
        nickname: &str,
        last_seen: i64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO channel_members (channel_id, member_pubkey, nickname, last_seen, banned, moderator)
             VALUES (?1, ?2, ?3, ?4, 0, 0)
             ON CONFLICT(channel_id, member_pubkey) DO UPDATE SET
                nickname = excluded.nickname,
                last_seen = excluded.last_seen",
            params![channel_id, member_pubkey, nickname, last_seen],
        )?;
        Ok(())
    }

    pub fn list_channel_members(
        &self,
        channel_id: &str,
    ) -> anyhow::Result<Vec<StoredChannelMember>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT member_pubkey, nickname, last_seen, banned, moderator
             FROM channel_members WHERE channel_id = ?1
             ORDER BY nickname COLLATE NOCASE, member_pubkey",
        )?;
        let rows = stmt
            .query_map(params![channel_id], |row| {
                Ok(StoredChannelMember {
                    member_pubkey: row.get(0)?,
                    nickname: row.get(1)?,
                    last_seen: row.get(2)?,
                    banned: row.get::<_, i64>(3)? != 0,
                    moderator: row.get::<_, i64>(4)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn channel_member_is_banned(
        &self,
        channel_id: &str,
        member_pubkey: &str,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let banned: Option<i64> = conn
            .query_row(
                "SELECT banned FROM channel_members WHERE channel_id = ?1 AND member_pubkey = ?2",
                params![channel_id, member_pubkey],
                |row| row.get(0),
            )
            .optional()?;
        Ok(banned.unwrap_or(0) != 0)
    }

    pub fn channel_member_is_moderator(
        &self,
        channel_id: &str,
        member_pubkey: &str,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let flag: Option<i64> = conn
            .query_row(
                "SELECT moderator FROM channel_members WHERE channel_id = ?1 AND member_pubkey = ?2",
                params![channel_id, member_pubkey],
                |row| row.get(0),
            )
            .optional()?;
        Ok(flag.unwrap_or(0) != 0)
    }

    fn hex_pubkeys_from_query(
        conn: &Connection,
        sql: &str,
        channel_id: &str,
    ) -> anyhow::Result<Vec<[u8; 32]>> {
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map(params![channel_id], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for pk_hex in rows {
            let Ok(pk_hex) = pk_hex else {
                continue;
            };
            let Ok(bytes) = hex::decode(pk_hex) else {
                continue;
            };
            if let Ok(pk) = <[u8; 32]>::try_from(bytes) {
                out.push(pk);
            }
        }
        Ok(out)
    }

    pub fn list_banned_channel_pubkeys(&self, channel_id: &str) -> anyhow::Result<Vec<[u8; 32]>> {
        let conn = self.conn.lock();
        Self::hex_pubkeys_from_query(
            &conn,
            "SELECT member_pubkey FROM channel_members
             WHERE channel_id = ?1 AND banned = 1
             ORDER BY member_pubkey",
            channel_id,
        )
    }

    pub fn list_moderator_channel_pubkeys(
        &self,
        channel_id: &str,
    ) -> anyhow::Result<Vec<[u8; 32]>> {
        let conn = self.conn.lock();
        Self::hex_pubkeys_from_query(
            &conn,
            "SELECT member_pubkey FROM channel_members
             WHERE channel_id = ?1 AND moderator = 1
             ORDER BY member_pubkey",
            channel_id,
        )
    }

    /// Apply a gossip ban/unban from a delegated moderator. Wins only if newer
    /// than the last owner snapshot *and* any previous revision on that row.
    pub fn apply_channel_ban_action(
        &self,
        channel_id: &str,
        member_pubkey: &str,
        banned: bool,
        timestamp: i64,
    ) -> anyhow::Result<bool> {
        let now = chrono::Utc::now().timestamp();
        if !crate::network::ember::channel::gossip_timestamp_ok(timestamp, now) {
            return Ok(false);
        }
        let timestamp = timestamp.min(now);
        let conn = self.conn.lock();
        let snapshot: i64 = conn
            .query_row(
                "SELECT moderation_updated_at FROM channels WHERE channel_id = ?1",
                params![channel_id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        if timestamp < snapshot {
            return Ok(false);
        }
        let n = conn.execute(
            "INSERT INTO channel_members
                (channel_id, member_pubkey, nickname, last_seen, banned, moderator, ban_revised_at)
             VALUES (?1, ?2, '', 0, ?3, 0, ?4)
             ON CONFLICT(channel_id, member_pubkey) DO UPDATE SET
                banned = excluded.banned,
                ban_revised_at = excluded.ban_revised_at
             WHERE channel_members.ban_revised_at <= excluded.ban_revised_at",
            params![
                channel_id,
                member_pubkey,
                if banned { 1 } else { 0 },
                timestamp
            ],
        )?;
        Ok(n > 0)
    }

    /// Apply an owner-signed moderation snapshot if it is newer than what we hold.
    /// Replaces bans and the moderator list; a later gossip action can still
    /// override an individual ban via `ban_revised_at`.
    /// Apply an owner-signed snapshot.
    ///
    /// Each of the trailing facts is only written when the record actually
    /// carries it, so a record predating a field cannot erase what a newer one
    /// already told us. The owner is never added to the ban list even if the
    /// snapshot names them — the owner is the authority a ban derives from, so
    /// a record banning them is corrupt or hostile either way.
    pub fn apply_channel_moderation(
        &self,
        channel_id: &str,
        topic: &str,
        welcome: &str,
        timestamp: i64,
        banned_pubkeys: &[[u8; 32]],
        moderator_pubkeys: &[[u8; 32]],
        owner_pubkey: Option<&[u8; 32]>,
        successor_nominee: Option<&[u8; 32]>,
        claim_after_days: Option<u16>,
        key_epoch: Option<u64>,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let current: i64 = conn
            .query_row(
                "SELECT moderation_updated_at FROM channels WHERE channel_id = ?1",
                params![channel_id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        if timestamp < current {
            return Ok(false);
        }
        let topic = crate::security::sanitize_remote_text(topic, 64);
        let welcome = crate::security::sanitize_remote_text(welcome, 512);
        let tx = conn.unchecked_transaction()?;
        let n = tx.execute(
            "UPDATE channels SET topic = ?2, welcome = ?3, moderation_updated_at = ?4
             WHERE channel_id = ?1",
            params![channel_id, topic, welcome, timestamp],
        )?;
        if n == 0 {
            return Ok(false);
        }
        tx.execute(
            "UPDATE channel_members SET banned = 0
             WHERE channel_id = ?1 AND ban_revised_at <= ?2",
            params![channel_id, timestamp],
        )?;
        tx.execute(
            "UPDATE channel_members SET moderator = 0 WHERE channel_id = ?1",
            params![channel_id],
        )?;
        let owner_hex = owner_pubkey.map(hex::encode);
        for pk in banned_pubkeys.iter().take(32) {
            let hex_pk = hex::encode(pk);
            // The owner is the authority a ban derives from, so a snapshot
            // naming them is corrupt or hostile either way. Skipping is enough:
            // the sweep above has already cleared their row.
            if owner_hex.as_deref() == Some(hex_pk.as_str()) {
                continue;
            }
            tx.execute(
                "INSERT INTO channel_members
                    (channel_id, member_pubkey, nickname, last_seen, banned, moderator, ban_revised_at)
                 VALUES (?1, ?2, '', 0, 1, 0, ?3)
                 ON CONFLICT(channel_id, member_pubkey) DO UPDATE SET
                    banned = 1,
                    ban_revised_at = excluded.ban_revised_at
                 WHERE channel_members.ban_revised_at <= excluded.ban_revised_at",
                params![channel_id, hex_pk, timestamp],
            )?;
        }
        for pk in moderator_pubkeys.iter().take(16) {
            let hex_pk = hex::encode(pk);
            tx.execute(
                "INSERT INTO channel_members
                    (channel_id, member_pubkey, nickname, last_seen, banned, moderator, ban_revised_at)
                 VALUES (?1, ?2, '', 0, 0, 1, 0)
                 ON CONFLICT(channel_id, member_pubkey) DO UPDATE SET moderator = 1",
                params![channel_id, hex_pk],
            )?;
        }
        // Only overwrite when this record actually carries an owner: a record
        // predating the field must not erase what a newer one already told us.
        if let Some(hex_owner) = owner_hex.as_deref() {
            tx.execute(
                "UPDATE channels SET owner_pubkey = ?2 WHERE channel_id = ?1",
                params![channel_id, hex_owner],
            )?;
            // A ban recorded against the owner before we knew who they were is
            // exactly the state this whole change exists to undo.
            tx.execute(
                "UPDATE channel_members SET banned = 0
                 WHERE channel_id = ?1 AND lower(member_pubkey) = lower(?2)",
                params![channel_id, hex_owner],
            )?;
        }
        if let Some(nominee) = successor_nominee {
            // All zeros is the owner withdrawing the nomination, not a member
            // whose key happens to be zero. Absent (`None`) is a record that
            // does not say, which must leave what we already know alone.
            let hex_nominee = if nominee.iter().all(|b| *b == 0) {
                String::new()
            } else {
                hex::encode(nominee)
            };
            tx.execute(
                "UPDATE channels SET successor_nominee = ?2 WHERE channel_id = ?1",
                params![channel_id, hex_nominee],
            )?;
        }
        if let Some(days) = claim_after_days {
            tx.execute(
                "UPDATE channels SET claim_after_days = ?2 WHERE channel_id = ?1",
                params![channel_id, days as i64],
            )?;
        }
        // Never walk it backwards: an out-of-order record must not send a
        // member hunting for an epoch that has already been superseded.
        if let Some(epoch) = key_epoch {
            tx.execute(
                "UPDATE channels SET key_epoch_wanted = ?2
                 WHERE channel_id = ?1 AND key_epoch_wanted < ?2",
                params![channel_id, epoch as i64],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }

    pub fn touch_channel_presence(&self, channel_id: &str, when: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE channels SET presence_published_at = ?2 WHERE channel_id = ?1",
            params![channel_id, when],
        )?;
        Ok(())
    }

    pub fn channels_due_for_presence(
        &self,
        now: i64,
        interval_secs: i64,
    ) -> anyhow::Result<Vec<String>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT channel_id FROM channels
             WHERE presence_published_at <= ?1 AND successor_id = ''
               AND in_room = 1 AND deleted = 0
             ORDER BY presence_published_at ASC",
        )?;
        let cutoff = now.saturating_sub(interval_secs);
        let rows = stmt
            .query_map(params![cutoff], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// `author_sig` is the author's hex Ed25519 signature over the line, or
    /// empty when we hold none — a locally copied handoff, or a row written
    /// before signatures existed. Only a row that has one can be re-served to
    /// another member, since a re-serve replays the original rather than
    /// signing afresh.
    pub fn insert_channel_message(
        &self,
        channel_id: &str,
        sender_pubkey: &str,
        direction: &str,
        message: &str,
        msg_id: &str,
        timestamp: i64,
        author_sig: &str,
        read: bool,
    ) -> anyhow::Result<i64> {
        const MAX_CHANNEL_MESSAGE_LEN: usize = 4096;
        const MAX_MESSAGES_PER_CHANNEL: i64 = 5_000;
        let message: &str = if message.len() > MAX_CHANNEL_MESSAGE_LEN {
            let mut end = MAX_CHANNEL_MESSAGE_LEN;
            while end > 0 && !message.is_char_boundary(end) {
                end -= 1;
            }
            &message[..end]
        } else {
            message
        };
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let now = if timestamp > 0 {
            timestamp
        } else {
            chrono::Utc::now().timestamp()
        };
        tx.execute(
            "INSERT OR IGNORE INTO channel_messages (channel_id, sender_pubkey, direction, message, timestamp, read, msg_id, author_sig)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                channel_id,
                sender_pubkey,
                direction,
                CHAT_CIPHERTEXT_PREFIX,
                now,
                if read { 1 } else { 0 },
                msg_id,
                author_sig
            ],
        )?;
        if tx.changes() == 0 {
            let existing: i64 = tx.query_row(
                "SELECT id FROM channel_messages WHERE channel_id = ?1 AND msg_id = ?2",
                params![channel_id, msg_id],
                |row| row.get(0),
            )?;
            tx.commit()?;
            return Ok(existing);
        }
        let new_id = tx.last_insert_rowid();
        let encrypted = Self::encrypt_channel_message_body(
            self.require_chat_key()?,
            new_id,
            channel_id,
            direction,
            now,
            message,
        )?;
        tx.execute(
            "UPDATE channel_messages SET message = ?1 WHERE id = ?2",
            params![encrypted, new_id],
        )?;
        tx.execute(
            "UPDATE channels SET last_active = ?2 WHERE channel_id = ?1",
            params![channel_id, now],
        )?;
        tx.execute(
            "DELETE FROM channel_messages WHERE id IN (
                 SELECT id FROM channel_messages
                 WHERE channel_id = ?1
                 ORDER BY id DESC
                 LIMIT -1 OFFSET ?2
             )",
            params![channel_id, MAX_MESSAGES_PER_CHANNEL],
        )?;
        tx.commit()?;
        Ok(new_id)
    }

    /// Substring match over a room's history, newest first.
    ///
    /// Cannot be a SQL `LIKE`: `encrypt_channel_message_body` binds each body
    /// to its own row id, room, direction and timestamp, so the stored column
    /// is ciphertext and every candidate has to be decrypted here. Bounded by
    /// the per-room retention cap above, and stops as soon as `limit` matches
    /// are found so the common case walks only the recent tail.
    pub fn search_channel_messages(
        &self,
        channel_id: &str,
        needle: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<(i64, String, String, String, i64, bool)>> {
        let needle = needle.trim().to_lowercase();
        if needle.is_empty() || limit <= 0 {
            return Ok(Vec::new());
        }
        let rows: Vec<(i64, String, String, String, i64, bool)> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare(
                "SELECT id, sender_pubkey, direction, message, timestamp, read
                 FROM channel_messages WHERE channel_id = ?1
                 ORDER BY id DESC",
            )?;
            let mapped = stmt.query_map(params![channel_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get::<_, i64>(5)? != 0,
                ))
            })?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };
        // No key means no plaintext to match against; report nothing rather
        // than a page of "unavailable" placeholders that all "match".
        let Some(chat_key) = self.chat_key.as_deref() else {
            return Ok(Vec::new());
        };
        let mut hits = Vec::new();
        for (id, sender, direction, stored, timestamp, read) in rows {
            if hits.len() as i64 >= limit {
                break;
            }
            let Ok(message) = Self::decrypt_channel_message_body(
                chat_key, id, channel_id, &direction, timestamp, &stored,
            ) else {
                continue;
            };
            if message.to_lowercase().contains(&needle) {
                hits.push((id, sender, direction, message, timestamp, read));
            }
        }
        Ok(hits)
    }

    /// Forget one message on this device. Local only: the copy every other
    /// member holds is untouched, and nothing is gossiped.
    pub fn delete_channel_message(&self, channel_id: &str, id: i64) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let n = conn.execute(
            "DELETE FROM channel_messages WHERE channel_id = ?1 AND id = ?2",
            params![channel_id, id],
        )?;
        Ok(n > 0)
    }

    pub fn get_channel_messages(
        &self,
        channel_id: &str,
        limit: i64,
        before_id: Option<i64>,
    ) -> anyhow::Result<Vec<(i64, String, String, String, i64, bool)>> {
        let rows: Vec<(i64, String, String, String, i64, bool)> = {
            let conn = self.conn.lock();
            if let Some(bid) = before_id {
                let mut stmt = conn.prepare(
                    "SELECT id, sender_pubkey, direction, message, timestamp, read
                     FROM channel_messages WHERE channel_id = ?1 AND id < ?2
                     ORDER BY id DESC LIMIT ?3",
                )?;
                let mapped = stmt.query_map(params![channel_id, bid, limit], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get::<_, i64>(5)? != 0,
                    ))
                })?;
                mapped.collect::<Result<Vec<_>, _>>()?
            } else {
                let mut stmt = conn.prepare(
                    "SELECT id, sender_pubkey, direction, message, timestamp, read
                     FROM channel_messages WHERE channel_id = ?1
                     ORDER BY id DESC LIMIT ?2",
                )?;
                let mapped = stmt.query_map(params![channel_id, limit], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get::<_, i64>(5)? != 0,
                    ))
                })?;
                mapped.collect::<Result<Vec<_>, _>>()?
            }
        };
        let Some(chat_key) = self.chat_key.as_deref() else {
            return Ok(rows
                .into_iter()
                .map(|(id, sender, direction, _, timestamp, read)| {
                    (
                        id,
                        sender,
                        direction,
                        CHAT_UNAVAILABLE_TEXT.to_string(),
                        timestamp,
                        read,
                    )
                })
                .collect());
        };
        let mut messages = Vec::with_capacity(rows.len());
        for (id, sender, direction, stored, timestamp, read) in rows {
            match Self::decrypt_channel_message_body(
                chat_key, id, channel_id, &direction, timestamp, &stored,
            ) {
                Ok(message) => messages.push((id, sender, direction, message, timestamp, read)),
                Err(error) => {
                    tracing::warn!("Channel message {id} in {channel_id} is unavailable: {error}");
                    messages.push((
                        id,
                        sender,
                        direction,
                        CHAT_UNAVAILABLE_TEXT.to_string(),
                        timestamp,
                        read,
                    ));
                }
            }
        }
        Ok(messages)
    }

    pub fn mark_channel_messages_read(&self, channel_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE channel_messages SET read = 1 WHERE channel_id = ?1 AND read = 0",
            params![channel_id],
        )?;
        Ok(())
    }

    pub fn channel_message_exists(&self, channel_id: &str, msg_id: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM channel_messages WHERE channel_id = ?1 AND msg_id = ?2",
            params![channel_id, msg_id],
            |row| row.get(0),
        )?;
        Ok(n > 0)
    }

    /// Recent decrypted messages for neighbor history catch-up.
    /// Returns `(msg_id, sender_pubkey, body, timestamp, author_sig)` newest-first.
    ///
    /// Rows with no stored signature are skipped: a re-serve has to replay the
    /// author's own signature, and this node cannot produce one on their behalf.
    /// That is the point rather than a shortcoming — it is what stops a member
    /// answering a catch-up with a conversation nobody had.
    pub fn list_channel_messages_for_sync(
        &self,
        channel_id: &str,
        since_ts: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<(String, String, String, i64, String)>> {
        let limit = limit.clamp(1, 64);
        let rows: Vec<(i64, String, String, String, String, i64, String)> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare(
                "SELECT id, msg_id, sender_pubkey, direction, message, timestamp, author_sig
                 FROM channel_messages
                 WHERE channel_id = ?1 AND timestamp >= ?2 AND author_sig <> ''
                 ORDER BY timestamp DESC, id DESC
                 LIMIT ?3",
            )?;
            let mapped = stmt.query_map(params![channel_id, since_ts, limit], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            })?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };
        let Some(chat_key) = self.chat_key.as_ref() else {
            return Ok(Vec::new());
        };
        let mut out = Vec::with_capacity(rows.len());
        for (id, msg_id, sender, direction, stored, timestamp, author_sig) in rows {
            if let Ok(message) = Self::decrypt_channel_message_body(
                chat_key, id, channel_id, &direction, timestamp, &stored,
            ) {
                out.push((msg_id, sender, message, timestamp, author_sig));
            }
        }
        Ok(out)
    }

    pub fn latest_channel_message_timestamp(&self, channel_id: &str) -> anyhow::Result<i64> {
        let conn = self.conn.lock();
        let ts: i64 = conn.query_row(
            "SELECT COALESCE(MAX(timestamp), 0) FROM channel_messages WHERE channel_id = ?1",
            params![channel_id],
            |row| row.get(0),
        )?;
        Ok(ts)
    }

    /// Reclaim unused pages freed by DELETE operations.
    /// Should be called periodically (e.g. alongside credit flush).
    pub fn incremental_vacuum(&self) {
        let conn = self.conn.lock();
        let auto_vacuum: i64 = conn
            .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
            .unwrap_or(0);
        if auto_vacuum == 0 {
            // Should be impossible after v21, but keep the signal if a
            // future regression re-introduces the pragma-order bug.
            tracing::warn!(
                "incremental_vacuum skipped: auto_vacuum is NONE (expected INCREMENTAL)"
            );
            return;
        }
        if let Err(e) = conn.execute_batch("PRAGMA incremental_vacuum(64);") {
            tracing::debug!("incremental_vacuum failed: {e}");
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
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let now = chrono::Utc::now().timestamp();
        tx.execute(
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
        tx.execute(
            "DELETE FROM download_history WHERE file_hash IN (
                SELECT file_hash FROM download_history
                ORDER BY timestamp DESC
                LIMIT -1 OFFSET ?1
            )",
            params![MAX_DOWNLOAD_HISTORY_ROWS],
        )?;
        tx.commit()?;
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
                ident_state INTEGER NOT NULL DEFAULT 0,
                ember_hash BLOB,
                crypto_verified_once INTEGER NOT NULL DEFAULT 0
            );",
        )
        .expect("create schema");
        Database {
            conn: Mutex::new(conn),
            chat_key: Some(Zeroizing::new([0xA5; 32])),
            corrupt_backup: None,
        }
    }

    /// Minimal schema for testing the defensive SQLite-to-memory conversion
    /// used by `load_ember_credits`.
    fn ember_credits_only_db() -> Database {
        let conn = Connection::open_in_memory().expect("open in-memory");
        conn.execute_batch(
            "CREATE TABLE ember_credits (
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
        )
        .expect("create schema");
        Database {
            conn: Mutex::new(conn),
            chat_key: Some(Zeroizing::new([0xA5; 32])),
            corrupt_backup: None,
        }
    }

    /// Build a `Database` with just the friends-related tables, enough to
    /// exercise blocking without a `tauri::AppHandle`.
    fn friends_only_db() -> Database {
        let conn = Connection::open_in_memory().expect("open in-memory");
        conn.execute_batch(
            "CREATE TABLE friends (
                user_hash TEXT PRIMARY KEY,
                nickname TEXT NOT NULL DEFAULT '',
                added_at INTEGER NOT NULL DEFAULT 0,
                last_ip TEXT DEFAULT '',
                last_port INTEGER DEFAULT 0,
                last_seen INTEGER DEFAULT 0,
                mutual INTEGER NOT NULL DEFAULT 0,
                ed25519_pubkey BLOB
            );
            CREATE TABLE friend_requests (
                sender_hash TEXT PRIMARY KEY,
                sender_nickname TEXT NOT NULL DEFAULT '',
                received_at INTEGER NOT NULL DEFAULT 0,
                sender_ip TEXT DEFAULT '',
                sender_port INTEGER DEFAULT 0,
                verified INTEGER NOT NULL DEFAULT 0,
                sender_pubkey BLOB
            );
            CREATE TABLE chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                friend_hash TEXT NOT NULL,
                direction TEXT NOT NULL DEFAULT 'sent',
                message TEXT NOT NULL,
                timestamp INTEGER NOT NULL DEFAULT 0,
                read INTEGER NOT NULL DEFAULT 0,
                delivery INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE friend_blocks (
                user_hash TEXT PRIMARY KEY,
                nickname TEXT NOT NULL DEFAULT '',
                blocked_at INTEGER NOT NULL DEFAULT 0
            );",
        )
        .expect("create schema");
        Database {
            conn: Mutex::new(conn),
            chat_key: Some(Zeroizing::new([0xA5; 32])),
            corrupt_backup: None,
        }
    }

    fn row_count(db: &Database, sql: &str) -> i64 {
        db.conn
            .lock()
            .query_row(sql, [], |r| r.get(0))
            .expect("count")
    }

    #[test]
    fn load_ember_credits_clamps_corrupt_session_counters() {
        let db = ember_credits_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO ember_credits (
                    pub_key, uploaded, downloaded, last_upload_time, last_download_time,
                    completed_sessions, total_sessions, avg_upload_speed, last_seen, ident_verified
                ) VALUES (?1, 0, 0, 0, 0, ?2, ?3, 0, 0, 0)",
                params![vec![0xA5u8; 32], 5_000_000_000i64, -1i64],
            )
            .expect("insert corrupt counters");

        let records = db.load_ember_credits().expect("load credits");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].5, u32::MAX);
        assert_eq!(records[0].6, 0);
    }

    /// The point of a block is that it outlives the friendship it ended.
    /// Removal alone deletes the row and with it any record of the decision,
    /// which is what let a blocked peer re-request their way back in.
    #[test]
    fn blocking_ends_the_friendship_and_outlives_it() {
        let db = friends_only_db();
        {
            let conn = db.conn.lock();
            conn.execute(
                "INSERT INTO friends (user_hash, nickname, mutual) VALUES ('aa', 'Mallory', 1)",
                [],
            )
            .expect("seed friend");
            conn.execute(
                "INSERT INTO chat_messages (friend_hash, message) VALUES ('aa', 'hi')",
                [],
            )
            .expect("seed chat");
        }

        db.block_friend("aa").expect("block");

        assert_eq!(row_count(&db, "SELECT COUNT(*) FROM friends"), 0);
        assert_eq!(row_count(&db, "SELECT COUNT(*) FROM chat_messages"), 0);
        assert!(db.is_friend_blocked("aa").expect("lookup"));

        let blocked = db.get_blocked_friends().expect("list");
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].0, "aa");
        // Carried across from the deleted friend row: without it the user is
        // left staring at a bare hash with no way to tell who it was.
        assert_eq!(blocked[0].1, "Mallory");
    }

    /// A stranger can be blocked straight from the approval queue, before
    /// they were ever a friend, so the name has to come from the request.
    #[test]
    fn blocking_a_pending_requester_keeps_their_name() {
        let db = friends_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO friend_requests (sender_hash, sender_nickname) \
                 VALUES ('bb', 'Stranger')",
                [],
            )
            .expect("seed request");

        db.block_friend("bb").expect("block");

        assert_eq!(row_count(&db, "SELECT COUNT(*) FROM friend_requests"), 0);
        let blocked = db.get_blocked_friends().expect("list");
        assert_eq!(blocked[0].1, "Stranger");
    }

    /// Unblocking clears the block and nothing else. The friendship rows were
    /// deleted when it was applied, so the pair have to add each other again
    /// rather than silently resuming.
    #[test]
    fn unblocking_does_not_restore_the_friendship() {
        let db = friends_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO friends (user_hash, nickname) VALUES ('cc', 'Gone')",
                [],
            )
            .expect("seed friend");

        db.block_friend("cc").expect("block");
        db.unblock_friend("cc").expect("unblock");

        assert!(!db.is_friend_blocked("cc").expect("lookup"));
        assert!(db.get_blocked_friends().expect("list").is_empty());
        assert_eq!(row_count(&db, "SELECT COUNT(*) FROM friends"), 0);
    }

    /// A database whose chat key cannot be recovered must still be usable. It
    /// previously refused to open at all, so an unreadable key file took
    /// downloads, the library and every setting with it — and said so only in a
    /// log. History is sealed instead: rows read as unavailable, sends are
    /// refused, and the ciphertext is left intact so restoring the key recovers
    /// it.
    #[test]
    fn a_locked_chat_key_seals_history_instead_of_failing() {
        let conn = Connection::open_in_memory().expect("open in-memory");
        conn.execute_batch(
            "CREATE TABLE chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                friend_hash TEXT NOT NULL,
                direction TEXT NOT NULL DEFAULT 'sent',
                message TEXT NOT NULL,
                timestamp INTEGER NOT NULL DEFAULT 0,
                read INTEGER NOT NULL DEFAULT 0,
                delivery INTEGER NOT NULL DEFAULT 0
            );",
        )
        .expect("create schema");
        let locked = Database {
            conn: Mutex::new(conn),
            chat_key: None,
            corrupt_backup: None,
        };
        assert!(locked.chat_locked());

        // Seed a row that only the real key could open.
        let ciphertext = format!("{CHAT_CIPHERTEXT_PREFIX}bm90LXJlYWxseS1jaXBoZXJ0ZXh0");
        locked
            .conn
            .lock()
            .execute(
                "INSERT INTO chat_messages (friend_hash, direction, message, timestamp) \
                 VALUES ('aa', 'received', ?1, 1)",
                params![ciphertext],
            )
            .expect("seed row");

        // Reads succeed, reporting the row as unavailable rather than erroring.
        let messages = locked.get_chat_messages("aa", 50, None).expect("read");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].2, CHAT_UNAVAILABLE_TEXT);

        // Writes are refused, so nothing is stored under a key we do not have.
        assert!(locked.insert_chat_message("aa", "sent", "hello").is_err());

        // The queue reports nothing, and crucially does not abandon rows that a
        // restored key could still send.
        assert!(locked
            .pending_chat_messages("aa", 10)
            .expect("pending")
            .is_empty());

        // The ciphertext is untouched, so restoring the key recovers it.
        let stored: String = locked
            .conn
            .lock()
            .query_row("SELECT message FROM chat_messages", [], |r| r.get(0))
            .expect("read raw");
        assert_eq!(stored, ciphertext);

        // And the age sweep leaves queued sends alone while locked, or it would
        // abandon exactly the rows a restored key could still deliver.
        locked
            .conn
            .lock()
            .execute(
                "INSERT INTO chat_messages (friend_hash, direction, message, timestamp, delivery) \
                 VALUES ('aa', 'sent', 'x', ?1, ?2)",
                params![
                    chrono::Utc::now().timestamp() - CHAT_QUEUE_MAX_AGE_SECS - 60,
                    CHAT_QUEUED
                ],
            )
            .expect("seed stale queued");
        assert!(locked.expire_stale_queued_chat().expect("sweep").is_empty());
        assert_eq!(
            row_count(
                &locked,
                &format!("SELECT COUNT(*) FROM chat_messages WHERE delivery = {CHAT_QUEUED}")
            ),
            1,
            "a locked database must not abandon queued sends"
        );
    }

    /// Nothing used to assign `CHAT_FAILED`, so a message to a friend who never
    /// came back was queued forever, counted as unsent forever, and retried on
    /// every reconnect. The sweep has to be global: expiring only on flush left
    /// the conversation, the badge and the queue each holding a different view
    /// of the same row, because a flush runs per friend and only on reconnect.
    #[test]
    fn chat_queued_past_the_age_limit_is_given_up_on() {
        let db = friends_only_db();
        let now = chrono::Utc::now().timestamp();
        {
            let conn = db.conn.lock();
            // One well past the ceiling, one comfortably inside it.
            conn.execute(
                "INSERT INTO chat_messages (friend_hash, direction, message, timestamp, delivery) \
                 VALUES ('aa', 'sent', 'x', ?1, ?2)",
                params![now - CHAT_QUEUE_MAX_AGE_SECS - 60, CHAT_QUEUED],
            )
            .expect("seed stale");
            conn.execute(
                "INSERT INTO chat_messages (friend_hash, direction, message, timestamp, delivery) \
                 VALUES ('aa', 'sent', 'y', ?1, ?2)",
                params![now - 60, CHAT_QUEUED],
            )
            .expect("seed fresh");
        }

        // The abandoned rows come back so the caller can flip the live bubbles.
        let expired = db.expire_stale_queued_chat().expect("sweep");
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].1, "aa");

        // Both views agree afterwards: one row still queued, one abandoned.
        assert_eq!(
            row_count(
                &db,
                &format!("SELECT COUNT(*) FROM chat_messages WHERE delivery = {CHAT_QUEUED}")
            ),
            1
        );
        assert_eq!(
            row_count(
                &db,
                &format!("SELECT COUNT(*) FROM chat_messages WHERE delivery = {CHAT_FAILED}")
            ),
            1
        );
        let counts = db.pending_chat_counts().expect("counts");
        assert_eq!(counts, vec![("aa".to_string(), 1)]);

        // Idempotent: a second sweep finds nothing left to abandon.
        assert!(db
            .expire_stale_queued_chat()
            .expect("sweep again")
            .is_empty());
    }

    /// The check the network loop runs before queueing is only an early-out.
    /// Blocking commits from the UI thread, so it can land after that check
    /// and before the insert; the transaction has to refuse on its own.
    #[test]
    fn a_block_committed_mid_flight_still_stops_the_request() {
        let db = friends_only_db();
        db.block_friend("dd").expect("block");

        let queued = db
            .add_friend_request("dd", None, "Mallory", "1.2.3.4", 4662, true)
            .expect("insert");

        assert!(!queued, "blocked identity must not be queued");
        assert_eq!(row_count(&db, "SELECT COUNT(*) FROM friend_requests"), 0);
    }

    /// The request row may already be on screen when the block is applied, so
    /// the accept can arrive afterwards. Letting it through would write
    /// `mutual = 1` and hand back chat and browse under a live block.
    #[test]
    fn accepting_a_request_from_a_blocked_identity_is_refused() {
        let db = friends_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO friend_requests (sender_hash, sender_nickname) \
                 VALUES ('ee', 'Mallory')",
                [],
            )
            .expect("seed request");
        // Block without going through `block_friend`, which would delete the
        // row: this is the racing order, where the row outlives the block.
        db.conn
            .lock()
            .execute(
                "INSERT INTO friend_blocks (user_hash, nickname) VALUES ('ee', 'Mallory')",
                [],
            )
            .expect("seed block");

        assert!(db.accept_friend_request("ee").is_err());
        assert_eq!(row_count(&db, "SELECT COUNT(*) FROM friends"), 0);
    }

    /// The command checks before calling, so this covers the race: a block
    /// that commits in between must not leave the identity both listed as a
    /// friend and blocked.
    #[test]
    fn adding_a_blocked_identity_is_refused_by_the_transaction() {
        let db = friends_only_db();
        db.block_friend("11").expect("block");

        // `Ok(false)`, not an error: the caller has to tell a block from a
        // genuine save failure so it can name the reason the user must act on.
        assert!(
            !db.add_friend("11", "Mallory", None).expect("no db error"),
            "a blocked identity must be refused, not written"
        );
        assert_eq!(row_count(&db, "SELECT COUNT(*) FROM friends"), 0);
        assert!(
            db.add_friend("22", "Friend", None).expect("no db error"),
            "an unblocked identity must still be added"
        );
    }

    /// Auto-confirm promotes a one-sided friend to mutual without prompting,
    /// which grants browse and friends-only serving. A block has to stop it
    /// even though the `friends` row is still there.
    #[test]
    fn promotion_to_mutual_skips_a_blocked_identity() {
        let db = friends_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO friends (user_hash, nickname, mutual) VALUES ('22', 'Mallory', 0)",
                [],
            )
            .expect("seed friend");
        db.conn
            .lock()
            .execute("INSERT INTO friend_blocks (user_hash) VALUES ('22')", [])
            .expect("seed block");

        let updated = db
            .set_friend_mutual("22", "1.2.3.4", 4662, None)
            .expect("promote");

        assert_eq!(updated, 0, "blocked identity must not be promoted");
        assert_eq!(
            row_count(&db, "SELECT COUNT(*) FROM friends WHERE mutual = 1"),
            0
        );
    }

    /// Blocking twice must not erase the name. By the second call the friend
    /// and request rows are gone, so the lookup finds nothing — easy to hit
    /// when the first attempt persisted the block but reported an error and
    /// the user simply tried again.
    #[test]
    fn re_blocking_keeps_the_name_from_the_first_time() {
        let db = friends_only_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO friends (user_hash, nickname) VALUES ('ff', 'Mallory')",
                [],
            )
            .expect("seed friend");

        db.block_friend("ff").expect("first block");
        db.block_friend("ff").expect("second block");

        let blocked = db.get_blocked_friends().expect("list");
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].1, "Mallory");
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
            (&h1, 100, 200, 1_700_000_000, pk, 0, 0, None, false),
            (&h2, 300, 400, 1_700_000_001, pk, 0x0102_0304, 1, None, true),
            (&h3, 500, 600, 1_700_000_002, pk, 0, 0, None, false),
        ])
        .expect("seed");
        let loaded = db.load_credits().expect("reload after seed");
        assert_eq!(loaded.len(), 3, "seed must persist three records");

        // Re-save with only one of the three. The other two represent
        // stale records the in-memory pruner has just dropped — they
        // must NOT survive in the database.
        db.save_all_credits(&[(&h2, 999, 888, 1_700_000_999, pk, 0x0102_0304, 1, None, true)])
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
        db.save_all_credits(&[(&h1, 1, 1, 0, &[], 0, 0, None, false)])
            .expect("seed");
        assert_eq!(db.load_credits().expect("reload").len(), 1);

        db.save_all_credits(&[]).expect("empty save");
        assert!(db.load_credits().expect("reload empty").is_empty());
    }

    /// The "has ever been cryptographically verified" anchor must survive the
    /// database round-trip. It gates the anti-credit-theft reset, and the DB is
    /// the primary credit store, so an anchor that did not persist would let
    /// every peer's accumulated totals be reset on their first verification
    /// after any restart.
    #[test]
    fn crypto_verified_anchor_round_trips() {
        let db = credits_only_db();
        let anchored = [0x11u8; 16];
        let fresh = [0x22u8; 16];
        let pk: &[u8] = &[0xAA; 4];

        db.save_all_credits(&[
            (&anchored, 10, 20, 1_700_000_000, pk, 0, 1, None, true),
            // Persisted `Failed` (2) with no anchor: exactly the state a
            // stranger can force by failing one challenge under this hash.
            (&fresh, 30, 40, 1_700_000_001, pk, 0, 2, None, false),
        ])
        .expect("seed");

        let loaded = db.load_credits().expect("reload");
        let anchor_of = |hash: [u8; 16]| {
            loaded
                .iter()
                .find(|row| row.0 == hash)
                .map(|row| row.8)
                .expect("row present")
        };
        assert!(anchor_of(anchored), "a verified anchor must persist");
        assert!(
            !anchor_of(fresh),
            "an unanchored record must not gain an anchor from its ident_state"
        );
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
            chat_key: Some(Zeroizing::new([0xA5; 32])),
            corrupt_backup: None,
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

    #[test]
    fn malformed_ban_row_fails_closed() {
        let db = banned_ips_db();
        db.conn
            .lock()
            .execute(
                "INSERT INTO banned_ips (ip, reason, banned_at, expires_at) VALUES ('not-an-ip', '', 0, 0)",
                [],
            )
            .unwrap();
        assert!(db.get_banned_ips().is_err());
        assert!(db.validate_security_policy().is_err());
    }

    #[test]
    fn expected_aich_survives_transfer_restart_load() {
        let path = std::env::temp_dir().join(format!(
            "ember-aich-transfer-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let db = Database::open_at(&path).unwrap();
        let expected = "ab".repeat(20);
        db.conn
            .lock()
            .execute(
                "INSERT INTO transfers (
                    id, file_name, file_hash, peer_id, peer_name, direction, status,
                    progress, speed, total_size, transferred, started_at, priority,
                    category, expected_aich
                 ) VALUES (?1, ?2, ?3, '', '', 'download', 'paused', 0, 0, 4, 0, 1, 'normal', '', ?4)",
                params!["transfer-aich", "file.bin", "11".repeat(16), expected],
            )
            .unwrap();
        let loaded = db.get_incomplete_downloads().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].expected_aich.as_deref(),
            Some("abababababababababababababababababababab")
        );
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn corrupt_expected_aich_restores_as_failed_without_pin() {
        let path = std::env::temp_dir().join(format!(
            "ember-aich-corrupt-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let db = Database::open_at(&path).unwrap();
        {
            let conn = db.conn.lock();
            for (id, value) in [
                ("transfer-empty-aich", ""),
                ("transfer-space-aich", "   "),
                ("transfer-bad-aich", "not-a-valid-aich"),
            ] {
                conn.execute(
                    "INSERT INTO transfers (
                        id, file_name, file_hash, peer_id, peer_name, direction, status,
                        progress, speed, total_size, transferred, started_at, priority,
                        category, expected_aich
                     ) VALUES (?1, ?2, ?3, '', '', 'download', 'paused', 0, 0, 4, 0, 1, 'normal', '', ?4)",
                    params![id, "file.bin", "11".repeat(16), value],
                )
                .unwrap();
            }
        }
        let loaded = db.get_incomplete_downloads().unwrap();
        assert_eq!(loaded.len(), 3);
        for transfer in loaded {
            assert!(transfer.expected_aich.is_none());
            assert_eq!(transfer.status, TransferStatus::Failed);
            assert!(transfer
                .failure_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("AICH")));
        }
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn ember_file_hash_survives_transfer_restart_load() {
        let path = std::env::temp_dir().join(format!(
            "ember-digest-transfer-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let db = Database::open_at(&path).unwrap();
        let expected = "cd".repeat(32);
        db.conn
            .lock()
            .execute(
                "INSERT INTO transfers (
                    id, file_name, file_hash, peer_id, peer_name, direction, status,
                    progress, speed, total_size, transferred, started_at, priority,
                    category, expected_aich, ember_file_hash
                 ) VALUES (?1, ?2, ?3, '', '', 'download', 'paused', 0, 0, 4, 0, 1, 'normal', '', NULL, ?4)",
                params!["transfer-ember", "file.bin", "11".repeat(16), expected],
            )
            .unwrap();
        let loaded = db.get_incomplete_downloads().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].ember_file_hash.as_deref(),
            Some(expected.as_str())
        );
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn pending_restore_is_paginated_and_overflow_is_quarantined_without_deletion() {
        let path = std::env::temp_dir().join(format!(
            "ember-pending-budget-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let db = Database::open_at(&path).unwrap();
        {
            let conn = db.conn.lock();
            for (id, started_at) in [("oldest", 1i64), ("middle", 2), ("newest", 3)] {
                conn.execute(
                    "INSERT INTO transfers (
                        id, file_name, file_hash, peer_id, peer_name, direction, status,
                        progress, speed, total_size, transferred, started_at, priority,
                        category, expected_aich
                     ) VALUES (?1, ?2, ?3, '', '', 'download', 'paused', 0, 0, 10, 0, ?4, 'normal', '', NULL)",
                    params![id, format!("{id}.bin"), "11".repeat(16), started_at],
                )
                .unwrap();
            }
        }

        assert_eq!(db.quarantine_excess_pending_downloads(2, 20).unwrap(), 1);
        let first = db.get_incomplete_downloads_page(1, 0).unwrap();
        let second = db.get_incomplete_downloads_page(1, 1).unwrap();
        assert_eq!(first[0].id, "oldest");
        assert_eq!(second[0].id, "middle");
        assert!(db.get_incomplete_downloads_page(1, 2).unwrap().is_empty());
        assert!(
            db.incomplete_download_owns_partial("newest"),
            "quarantined rows must keep ownership of user .part data"
        );

        let total_rows: i64 = db
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM transfers", [], |row| row.get(0))
            .unwrap();
        assert_eq!(total_rows, 3, "migration must not delete user rows");
        assert_eq!(db.acknowledge_pending_download_overflow().unwrap(), 1);
        assert_eq!(db.acknowledge_pending_download_overflow().unwrap(), 0);

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
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

    #[test]
    fn fresh_database_uses_incremental_auto_vacuum() {
        let path = std::env::temp_dir().join(format!(
            "ember-av-fresh-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open fresh db");
        let auto_vacuum: i64 = db
            .conn
            .lock()
            .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
            .expect("auto_vacuum");
        assert_eq!(
            auto_vacuum, 2,
            "INCREMENTAL auto_vacuum expected on fresh DB"
        );
        let version: i64 = db
            .conn
            .lock()
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |r| r.get(0),
            )
            .expect("version");
        assert_eq!(version, MAX_SUPPORTED_SCHEMA_VERSION);
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn channels_round_trip_secrets_and_messages() {
        let path = std::env::temp_dir().join(format!(
            "ember-channels-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        assert_eq!(db.schema_version(), MAX_SUPPORTED_SCHEMA_VERSION);

        let channel_id = "ab".repeat(16);
        let pubkey = "cd".repeat(32);
        let seed = [0x11u8; 32];
        let join = [0x22u8; 32];
        db.insert_channel(
            &channel_id,
            &pubkey,
            "Lobby",
            "private",
            true,
            Some(&seed),
            Some(&join),
        )
        .expect("insert channel");
        assert_eq!(db.load_channel_owner_seed(&channel_id).unwrap(), Some(seed));
        assert_eq!(
            db.load_channel_join_secret(&channel_id).unwrap(),
            Some(join)
        );

        db.upsert_channel_member(&channel_id, &pubkey, "Ada", 100)
            .unwrap();
        let members = db.list_channel_members(&channel_id).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].nickname, "Ada");

        let banned = [0x33u8; 32];
        let banned_hex = hex::encode(banned);
        assert!(db
            .apply_channel_moderation(&channel_id, "topic", "welcome", 50, &[banned], &[], None, None, None, None)
            .unwrap());
        let ch = db.get_channel(&channel_id).unwrap().unwrap();
        assert_eq!(ch.topic, "topic");
        assert_eq!(ch.welcome, "welcome");
        assert!(db
            .channel_member_is_banned(&channel_id, &banned_hex)
            .unwrap());
        assert!(!db.channel_member_is_banned(&channel_id, &pubkey).unwrap());
        assert!(!db
            .apply_channel_moderation(&channel_id, "older", "stale", 10, &[], &[], None, None, None, None)
            .unwrap());
        let ch = db.get_channel(&channel_id).unwrap().unwrap();
        assert_eq!(ch.topic, "topic");
        assert!(db
            .apply_channel_moderation(&channel_id, "topic", "welcome", 60, &[], &[], None, None, None, None)
            .unwrap());
        assert!(!db
            .channel_member_is_banned(&channel_id, &banned_hex)
            .unwrap());

        let moderator = [0x44u8; 32];
        let mod_hex = hex::encode(moderator);
        assert!(db
            .apply_channel_moderation(&channel_id, "topic", "welcome", 70, &[], &[moderator], None, None, None, None)
            .unwrap());
        assert!(db
            .channel_member_is_moderator(&channel_id, &mod_hex)
            .unwrap());
        assert!(!db
            .channel_member_is_moderator(&channel_id, &pubkey)
            .unwrap());
        assert!(db
            .apply_channel_ban_action(&channel_id, &banned_hex, true, 80)
            .unwrap());
        assert!(
            !db.apply_channel_ban_action(&channel_id, &banned_hex, true, i64::MAX)
                .unwrap(),
            "a far-future gossip timestamp must not stick a ban past every owner snapshot"
        );
        assert!(db
            .channel_member_is_banned(&channel_id, &banned_hex)
            .unwrap());
        assert!(db
            .apply_channel_moderation(&channel_id, "topic", "welcome", 75, &[], &[moderator], None, None, None, None)
            .unwrap());
        assert!(
            db.channel_member_is_banned(&channel_id, &banned_hex)
                .unwrap(),
            "newer gossip ban must survive an older owner snapshot"
        );

        let msg_id = "aa".repeat(16);
        let id = db
            .insert_channel_message(
                &channel_id,
                &pubkey,
                "sent",
                "hello room",
                &msg_id,
                1_700_000_000,
                &"cd".repeat(64),
                true,
            )
            .unwrap();
        let msgs = db.get_channel_messages(&channel_id, 50, None).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].0, id);
        assert_eq!(msgs[0].3, "hello room");
        assert_eq!(msgs[0].4, 1_700_000_000);
        let newer_id = "bb".repeat(16);
        db.insert_channel_message(
            &channel_id,
            &pubkey,
            "sent",
            "later line",
            &newer_id,
            1_700_000_100,
            &"ce".repeat(64),
            true,
        )
        .unwrap();
        let sync = db
            .list_channel_messages_for_sync(&channel_id, 0, 32)
            .unwrap();
        assert_eq!(sync.len(), 2);
        assert_eq!(
            sync[0].0, newer_id,
            "catch-up with since=0 must offer newest first, not oldest"
        );

        let listed = db.list_channels().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "Lobby");
        assert!(listed[0].is_owner);

        assert!(db.delete_channel(&channel_id, None).unwrap());
        assert!(db.list_channels().unwrap().is_empty());
        assert!(
            db.list_channel_members(&channel_id).unwrap().is_empty(),
            "no member is preserved when the caller keeps nobody"
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn leave_keeps_the_row_and_skips_presence() {
        let path = std::env::temp_dir().join(format!(
            "ember-in-room-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let channel_id = "ab".repeat(16);
        db.insert_channel(
            &channel_id,
            &"cd".repeat(32),
            "Lobby",
            "public",
            true,
            Some(&[0x11u8; 32]),
            None,
        )
        .expect("insert");
        let listed = db.list_channels().unwrap();
        assert!(listed[0].in_room);
        assert!(!listed[0].deleted);
        let due = db.channels_due_for_presence(i64::MAX, 1).unwrap();
        assert_eq!(due, vec![channel_id.clone()]);

        assert!(db.set_channel_in_room(&channel_id, false).unwrap());
        let left = db.get_channel(&channel_id).unwrap().unwrap();
        assert!(!left.in_room);
        assert!(db.load_channel_owner_seed(&channel_id).unwrap().is_some());
        assert!(
            db.channels_due_for_presence(i64::MAX, 1)
                .unwrap()
                .is_empty(),
            "a device that walked out must not republish presence"
        );

        assert!(db.set_channel_in_room(&channel_id, true).unwrap());
        assert!(db.get_channel(&channel_id).unwrap().unwrap().in_room);

        assert!(db.tombstone_channel(&channel_id).unwrap());
        let gone = db.get_channel(&channel_id).unwrap().unwrap();
        assert!(!gone.in_room);
        assert!(gone.deleted);
        assert!(
            !db.set_channel_in_room(&channel_id, true).unwrap(),
            "a tombstoned room cannot be re-entered on this device"
        );

        let other_id = "ef".repeat(16);
        db.insert_channel(
            &other_id,
            &"12".repeat(32),
            "Elsewhere",
            "public",
            false,
            None,
            None,
        )
        .expect("insert other");
        let walked = db.walk_out_deleted_channels(&[other_id.clone()]).unwrap();
        assert_eq!(walked, vec![other_id.clone()]);
        let hidden = db.get_channel(&other_id).unwrap().unwrap();
        assert!(!hidden.in_room);
        assert!(hidden.deleted, "a directory tombstone must hide the card");

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// A moderator could name the room owner in ban gossip and every member
    /// applied it, silently dropping the owner's messages — nothing on the wire
    /// said who the owner was, so no recipient had grounds to refuse. The owner
    /// now signs their own identity into the moderation record; this covers the
    /// storage half of that: the key is remembered, a snapshot naming the owner
    /// cannot ban them, and learning who the owner is undoes a ban recorded
    /// before we knew.
    #[test]
    fn a_moderation_snapshot_can_never_ban_the_room_owner() {
        let path = std::env::temp_dir().join(format!(
            "ember-owner-ban-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "3c".repeat(16);
        let channel_pubkey = "4d".repeat(32);
        let owner = [0x0Au8; 32];
        let owner_hex = hex::encode(owner);
        let nuisance = [0x0Bu8; 32];
        let nuisance_hex = hex::encode(nuisance);

        db.insert_channel(
            &channel_id,
            &channel_pubkey,
            "Lobby",
            "public",
            false,
            None,
            None,
        )
        .expect("insert channel");

        // Stand in for the hole: a moderator's gossip ban on the owner, applied
        // before this device had ever seen an owner-signed record.
        assert!(db
            .apply_channel_ban_action(&channel_id, &owner_hex, true, 40)
            .unwrap());
        assert!(db.channel_member_is_banned(&channel_id, &owner_hex).unwrap());
        assert_eq!(db.get_channel(&channel_id).unwrap().unwrap().owner_pubkey, "");

        // The owner's own snapshot arrives. It names them, so the stale ban goes
        // and the identity is remembered for the gossip path to check against.
        assert!(db
            .apply_channel_moderation(
                &channel_id,
                "topic",
                "",
                50,
                &[nuisance],
                &[],
                Some(&owner),
                None,
                None,
                None,
            )
            .unwrap());
        assert!(
            !db.channel_member_is_banned(&channel_id, &owner_hex).unwrap(),
            "learning who the owner is must undo a ban recorded before we knew"
        );
        assert!(
            db.channel_member_is_banned(&channel_id, &nuisance_hex).unwrap(),
            "everyone else in the snapshot is still banned"
        );
        assert_eq!(
            db.get_channel(&channel_id).unwrap().unwrap().owner_pubkey,
            owner_hex
        );

        // And a snapshot that names the owner in its own ban list is refused
        // that one entry rather than being applied wholesale.
        assert!(db
            .apply_channel_moderation(
                &channel_id,
                "topic",
                "",
                60,
                &[owner, nuisance],
                &[],
                Some(&owner),
                None,
                None,
                None,
            )
            .unwrap());
        assert!(
            !db.channel_member_is_banned(&channel_id, &owner_hex).unwrap(),
            "a record banning its own owner is corrupt or hostile either way"
        );
        assert!(db.channel_member_is_banned(&channel_id, &nuisance_hex).unwrap());

        // A later record that predates the field must not erase what we know.
        assert!(db
            .apply_channel_moderation(&channel_id, "topic", "", 70, &[], &[], None, None, None, None)
            .unwrap());
        assert_eq!(
            db.get_channel(&channel_id).unwrap().unwrap().owner_pubkey,
            owner_hex,
            "a record that says nothing about the owner is not a record saying nobody"
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// The handoff writes a successor room, moves the seed, and points the old
    /// room at it. Those used to be separate lock acquisitions, so a crash
    /// between them could strand a successor with no seed or an old room
    /// pointing at a room that was never created. Re-running it has to be safe
    /// and has to converge, because that is what recovery depends on.
    #[test]
    fn applying_a_handoff_twice_converges_on_the_same_state() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-handoff-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let old_id = "7a".repeat(16);
        let successor_id = "8b".repeat(16);
        let successor_pk = "9c".repeat(32);
        db.insert_channel(&old_id, &"a1".repeat(32), "Room", "private", true, None, None)
            .expect("insert channel");
        db.upsert_channel_member(&old_id, &"b2".repeat(32), "Them", 100)
            .unwrap();
        db.insert_channel_message(&old_id, &"b2".repeat(32), "received", "hello", "m1", 100, "", true)
            .unwrap();

        let seed = [0x44u8; 32];
        assert!(db
            .apply_channel_handoff(&old_id, &successor_pk, &successor_id, 1, true, Some(&seed))
            .expect("apply handoff"));

        let successor = db.get_channel(&successor_id).unwrap().expect("successor row");
        assert!(successor.is_owner, "the claimant owns the successor");
        assert_eq!(successor.predecessor_id, old_id);
        assert_eq!(successor.name, "Room");
        assert_eq!(
            db.load_channel_owner_seed(&successor_id).unwrap(),
            Some(seed),
            "the seed lands with the room, not after it"
        );
        let old = db.get_channel(&old_id).unwrap().expect("old row");
        assert_eq!(old.successor_id, successor_id);
        assert!(!old.is_owner, "the old room hands ownership over");
        assert!(
            db.load_channel_owner_seed(&old_id).unwrap().is_none(),
            "the old seed is dropped, never copied forward"
        );
        // Members and history come across.
        assert_eq!(db.list_channel_members(&successor_id).unwrap().len(), 1);
        assert_eq!(
            db.get_channel_messages(&successor_id, 10, None).unwrap().len(),
            1
        );
        let copied = db.get_channel_messages(&successor_id, 10, None).unwrap();
        assert!(
            copied[0].5,
            "a read received line must stay read on the successor"
        );
        assert_eq!(
            db.get_channel(&successor_id).unwrap().unwrap().unread,
            0,
            "handoff must not turn copied history into unread"
        );

        db.insert_channel_message(
            &old_id,
            &"b2".repeat(32),
            "received",
            "after crash",
            "m2",
            101,
            "",
            false,
        )
        .unwrap();
        assert!(db
            .apply_channel_handoff(&old_id, &successor_pk, &successor_id, 1, true, Some(&seed))
            .expect("resume handoff"));
        assert_eq!(
            db.get_channel_messages(&successor_id, 10, None).unwrap().len(),
            2,
            "a second apply must copy lines missed by a crash mid-replay"
        );

        // Replaying is idempotent: same successor, no duplicated history.
        assert!(db
            .apply_channel_handoff(&old_id, &successor_pk, &successor_id, 1, true, Some(&seed))
            .expect("replay handoff"));
        assert_eq!(
            db.get_channel_messages(&successor_id, 10, None).unwrap().len(),
            2,
            "a replay must not duplicate history"
        );

        // And a second, different successor cannot hijack a room already moved.
        assert!(!db
            .apply_channel_handoff(&old_id, &"d4".repeat(32), &"c3".repeat(16), 2, true, None)
            .expect("rival handoff"));
        assert_eq!(
            db.get_channel(&old_id).unwrap().unwrap().successor_id,
            successor_id
        );
    }

    /// Rotation is only useful if the keys survive in a readable window and the
    /// window is actually bounded: too few and a member offline across a ban
    /// cannot read the gap, unbounded and every key a room ever used stays on
    /// disk forever.
    #[test]
    fn rotating_a_room_key_keeps_a_bounded_window_of_readable_epochs() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-epochs-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "3c".repeat(16);
        db.insert_channel(
            &channel_id,
            &"4d".repeat(32),
            "Private",
            "private",
            true,
            None,
            None,
        )
        .expect("insert channel");

        // Rotate well past the retention window.
        let kept = Database::CHANNEL_KEY_EPOCHS_KEPT as i64;
        let total = kept + 3;
        for epoch in 1..=total {
            db.insert_channel_key_epoch(&channel_id, epoch, &[epoch as u8; 32])
                .expect("insert epoch");
        }

        let epochs = db.load_channel_key_epochs(&channel_id).expect("load");
        assert_eq!(epochs.len(), kept as usize, "retention window is bounded");
        // Newest first, because readers try the current key before older ones.
        assert_eq!(epochs[0].0, total);
        assert_eq!(epochs[0].1, [total as u8; 32]);
        assert!(
            epochs.windows(2).all(|w| w[0].0 > w[1].0),
            "candidates must be newest-first"
        );
        assert_eq!(
            epochs.last().map(|(e, _)| *e),
            Some(total - kept + 1),
            "the oldest retained epoch is exactly one window back"
        );

        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert_eq!(row.key_epoch, total, "the newest epoch becomes current");

        // An out-of-order record must not demote the room: everything we send
        // next would be sealed under a key half the members have dropped.
        db.insert_channel_key_epoch(&channel_id, total - 2, &[0xEEu8; 32])
            .expect("insert stale epoch");
        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert_eq!(row.key_epoch, total, "a late arrival cannot walk it back");

        // Dropping the room drops its keys with it.
        db.delete_channel(&channel_id, None).expect("delete");
        assert!(db
            .load_channel_key_epochs(&channel_id)
            .expect("load")
            .is_empty());
    }

    /// A handoff that carries a secret forward has to carry the *current* one.
    /// Rotation writes to `channel_key_epochs` and never touches `join_secret`,
    /// so inheriting that column handed the successor room the key the last ban
    /// rotated away from — which an evicted member still holds, letting them
    /// read the new room and undoing the eviction.
    #[test]
    fn a_successor_room_inherits_the_rotated_key_not_the_original_invite() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-succ-key-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let old_id = "1f".repeat(16);
        let successor_id = "2e".repeat(16);
        let original_invite = [0x01u8; 32];
        db.insert_channel(
            &old_id,
            &"3d".repeat(32),
            "Private",
            "private",
            true,
            None,
            Some(&original_invite),
        )
        .expect("insert channel");

        // Two bans' worth of rotation.
        let rotated = [0x02u8; 32];
        db.insert_channel_key_epoch(&old_id, 1, &[0x09u8; 32]).unwrap();
        db.insert_channel_key_epoch(&old_id, 2, &rotated).unwrap();

        assert!(db
            .apply_channel_handoff(&old_id, &"4c".repeat(32), &successor_id, 1, true, None)
            .expect("apply handoff"));

        let inherited = db
            .load_channel_join_secret(&successor_id)
            .expect("load")
            .expect("successor has a secret");
        assert_eq!(
            inherited, rotated,
            "the successor must start from the newest epoch"
        );
        assert_ne!(
            inherited, original_invite,
            "an evicted member's original invite must not open the successor room"
        );
    }

    /// Succession has to be opt-in and driven only by owner-signed facts: the
    /// nomination and the window both come from the moderation record, and a
    /// record that predates those fields must not silently erase them.
    #[test]
    fn succession_settings_come_only_from_owner_signed_records() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-succession-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "5e".repeat(16);
        db.insert_channel(
            &channel_id,
            &"6f".repeat(32),
            "Room",
            "private",
            false,
            None,
            None,
        )
        .expect("insert channel");

        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert!(row.successor_nominee.is_empty(), "off by default");
        assert_eq!(row.claim_after_days, 0);
        assert_eq!(row.key_epoch_wanted, 0);

        let owner = [0x11u8; 32];
        let nominee = [0x22u8; 32];
        assert!(db
            .apply_channel_moderation(
                &channel_id,
                "Topic",
                "Welcome",
                1_000,
                &[],
                &[],
                Some(&owner),
                Some(&nominee),
                Some(30),
                Some(4),
            )
            .unwrap());
        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert_eq!(row.successor_nominee, hex::encode(nominee));
        assert_eq!(row.claim_after_days, 30);
        assert_eq!(row.key_epoch_wanted, 4);
        assert_eq!(row.moderation_updated_at, 1_000);

        // A newer record carrying none of the trailing fields — an older build,
        // say — leaves what we already learned intact rather than wiping it.
        assert!(db
            .apply_channel_moderation(
                &channel_id, "Topic 2", "Welcome", 2_000, &[], &[], None, None, None, None,
            )
            .unwrap());
        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert_eq!(row.successor_nominee, hex::encode(nominee));
        assert_eq!(row.claim_after_days, 30);
        assert_eq!(row.key_epoch_wanted, 4);

        // And a stale epoch cannot send members hunting for a superseded key.
        assert!(db
            .apply_channel_moderation(
                &channel_id,
                "Topic 3",
                "Welcome",
                3_000,
                &[],
                &[],
                None,
                None,
                None,
                Some(2),
            )
            .unwrap());
        assert_eq!(
            db.get_channel(&channel_id).unwrap().unwrap().key_epoch_wanted,
            4
        );

        // The owner can clear their own nomination.
        db.set_channel_succession(&channel_id, "", 0).unwrap();
        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert!(row.successor_nominee.is_empty());
        assert_eq!(row.claim_after_days, 0);

        // And a withdrawal has to reach members. An all-zero nominee is the
        // owner saying "nobody" — distinct from a record that simply omits the
        // field, which must leave what we already know alone. Without this an
        // owner could never call a nomination back.
        assert!(db
            .apply_channel_moderation(
                &channel_id,
                "Topic 4",
                "Welcome",
                4_000,
                &[],
                &[],
                Some(&owner),
                Some(&nominee),
                Some(21),
                None,
            )
            .unwrap());
        assert_eq!(
            db.get_channel(&channel_id).unwrap().unwrap().successor_nominee,
            hex::encode(nominee)
        );
        assert!(db
            .apply_channel_moderation(
                &channel_id,
                "Topic 5",
                "Welcome",
                5_000,
                &[],
                &[],
                Some(&owner),
                Some(&[0u8; 32]),
                Some(0),
                None,
            )
            .unwrap());
        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert!(
            row.successor_nominee.is_empty(),
            "an all-zero nominee withdraws the nomination"
        );
        assert_eq!(row.claim_after_days, 0);
    }

    /// Succession is the one feature that acts on *absence*, so the record of
    /// having looked must never move backwards — a late-arriving older
    /// confirmation could otherwise make a freshly-checked room look unverified,
    /// or worse, be replayed to make a stale check look current.
    #[test]
    fn the_record_of_having_checked_for_an_owner_only_moves_forward() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-checked-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "9d".repeat(16);
        db.insert_channel(&channel_id, &"ae".repeat(32), "Room", "private", false, None, None)
            .expect("insert channel");
        assert_eq!(
            db.get_channel(&channel_id).unwrap().unwrap().moderation_checked_at,
            0,
            "a room we have never polled has not been checked"
        );

        db.touch_channel_moderation_checked(&channel_id, 5_000).unwrap();
        assert_eq!(
            db.get_channel(&channel_id).unwrap().unwrap().moderation_checked_at,
            5_000
        );

        db.touch_channel_moderation_checked(&channel_id, 4_000).unwrap();
        assert_eq!(
            db.get_channel(&channel_id).unwrap().unwrap().moderation_checked_at,
            5_000,
            "an older confirmation cannot un-verify a room"
        );

        db.touch_channel_moderation_checked(&channel_id, 9_000).unwrap();
        assert_eq!(
            db.get_channel(&channel_id).unwrap().unwrap().moderation_checked_at,
            9_000
        );

        // It belongs to the room, so a fresh successor starts unverified rather
        // than inheriting our confidence about the room it replaced.
        let successor_id = "bf".repeat(16);
        assert!(db
            .apply_channel_handoff(&channel_id, &"c0".repeat(32), &successor_id, 1, false, None)
            .expect("apply handoff"));
        assert_eq!(
            db.get_channel(&successor_id).unwrap().unwrap().moderation_checked_at,
            0,
            "a successor room has its own owner to verify"
        );
    }

    /// A rotation and the snapshot announcing it have to land together. The
    /// owner seals under whatever `key_epoch` says, and members only fetch a key
    /// the snapshot names — so a rotation whose commit failed has to come back
    /// off, or the owner talks under a key nobody knows to look for.
    #[test]
    fn rolling_back_a_rotation_restores_the_previous_epoch() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-rollback-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "6a".repeat(16);
        db.insert_channel(
            &channel_id,
            &"7b".repeat(32),
            "Private",
            "private",
            true,
            None,
            Some(&[0xAAu8; 32]),
        )
        .expect("insert channel");

        db.insert_channel_key_epoch(&channel_id, 1, &[0x01u8; 32]).unwrap();
        db.insert_channel_key_epoch(&channel_id, 2, &[0x02u8; 32]).unwrap();
        assert_eq!(db.get_channel(&channel_id).unwrap().unwrap().key_epoch, 2);

        db.rollback_channel_key_epoch(&channel_id, 2).unwrap();
        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert_eq!(row.key_epoch, 1, "the epoch falls back to the previous one");
        let epochs = db.load_channel_key_epochs(&channel_id).unwrap();
        assert_eq!(epochs.len(), 1);
        assert_eq!(epochs[0], (1, [0x01u8; 32]));

        // Rolling back the only epoch leaves the room on its original invite
        // secret rather than on nothing at all.
        db.rollback_channel_key_epoch(&channel_id, 1).unwrap();
        let row = db.get_channel(&channel_id).unwrap().unwrap();
        assert_eq!(row.key_epoch, 0);
        assert!(db.load_channel_key_epochs(&channel_id).unwrap().is_empty());
        assert_eq!(
            db.load_channel_join_secret(&channel_id).unwrap(),
            Some([0xAAu8; 32])
        );
    }

    /// Leaving used to wipe `channel_members`, so rejoining re-inserted the
    /// member with `banned = 0` and the client offered a composer whose sends
    /// every remaining member discards. A ban belongs to the room, not to the
    /// membership, so it has to outlive an explicit leave.
    #[test]
    fn leaving_keeps_our_own_ban_but_forgets_everything_else() {
        let path = std::env::temp_dir().join(format!(
            "ember-channel-leave-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let channel_id = "1a".repeat(16);
        let channel_pubkey = "2b".repeat(32);
        let us = [0x55u8; 32];
        let us_hex = hex::encode(us);
        let other = [0x66u8; 32];
        let other_hex = hex::encode(other);

        db.insert_channel(
            &channel_id,
            &channel_pubkey,
            "Lobby",
            "public",
            false,
            None,
            None,
        )
        .expect("insert channel");
        db.upsert_channel_member(&channel_id, &us_hex, "Us", 100)
            .unwrap();
        db.upsert_channel_member(&channel_id, &other_hex, "Them", 100)
            .unwrap();
        assert!(db
            .apply_channel_moderation(&channel_id, "", "", 50, &[us, other], &[], None, None, None, None)
            .unwrap());

        assert!(db.delete_channel(&channel_id, Some(&us_hex)).unwrap());
        assert!(db.get_channel(&channel_id).unwrap().is_none());
        assert!(
            db.channel_member_is_banned(&channel_id, &us_hex).unwrap(),
            "our ban must outlive leaving the room"
        );
        assert!(
            !db.channel_member_is_banned(&channel_id, &other_hex).unwrap(),
            "another member's ban is not ours to keep once we have left"
        );

        // Rejoining must not launder the ban: `upsert_channel_member` refreshes
        // the nickname and last-seen but leaves `banned` alone.
        db.insert_channel(
            &channel_id,
            &channel_pubkey,
            "Lobby",
            "public",
            false,
            None,
            None,
        )
        .expect("rejoin channel");
        db.upsert_channel_member(&channel_id, &us_hex, "Us", 200)
            .unwrap();
        assert!(
            db.channel_member_is_banned(&channel_id, &us_hex).unwrap(),
            "rejoining must not clear the ban"
        );

        // The owner lifting it still does, on the next moderation snapshot.
        assert!(db
            .apply_channel_moderation(&channel_id, "", "", 60, &[], &[], None, None, None, None)
            .unwrap());
        assert!(!db.channel_member_is_banned(&channel_id, &us_hex).unwrap());

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn channel_handoff_installs_successor_seed_without_copying_old() {
        use crate::network::ember::channel::ChannelIdentity;

        let path = std::env::temp_dir().join(format!(
            "ember-handoff-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");

        let old = ChannelIdentity::generate();
        let successor = ChannelIdentity::generate();
        let old_id = hex::encode(old.channel_id);
        let new_id = hex::encode(successor.channel_id);
        let old_pk = hex::encode(old.pubkey);
        let new_pk = hex::encode(successor.pubkey);
        let old_seed = old.seed();
        let new_seed = successor.seed();
        let join = [0x55u8; 32];

        db.insert_channel(&old_id, &old_pk, "Lobby", "private", true, Some(&old_seed), Some(&join))
            .unwrap();
        let keep_id = "aa".repeat(16);
        db.insert_channel_message(&old_id, &old_pk, "sent", "keep me", &keep_id, 10, "", true)
            .unwrap();

        assert!(db
            .apply_channel_handoff(&old_id, &new_pk, &new_id, 1, true, None)
            .unwrap());
        let old_row = db.get_channel(&old_id).unwrap().unwrap();
        assert!(!old_row.is_owner);
        assert_eq!(old_row.successor_id, new_id);
        assert!(db.load_channel_owner_seed(&old_id).unwrap().is_none());
        assert!(db.load_channel_owner_seed(&new_id).unwrap().is_none());
        assert_eq!(db.load_channel_join_secret(&new_id).unwrap(), Some(join));

        assert!(db
            .apply_channel_handoff(&old_id, &new_pk, &new_id, 1, true, Some(&new_seed))
            .unwrap());
        assert_eq!(db.load_channel_owner_seed(&new_id).unwrap(), Some(new_seed));
        assert_ne!(db.load_channel_owner_seed(&new_id).unwrap(), Some(old_seed));
        let new_row = db.get_channel(&new_id).unwrap().unwrap();
        assert!(new_row.is_owner);
        assert_eq!(new_row.predecessor_id, old_id);
        let history = db.get_channel_messages(&new_id, 50, None).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].3, "keep me");

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// Queued outbound chat has to survive a restart, otherwise the queue is
    /// no better than the in-memory send it replaced.
    #[test]
    fn queued_chat_survives_restart_and_flush_marks_it_delivered() {
        let path = std::env::temp_dir().join(format!(
            "ember-chat-queue-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let friend = "aa".repeat(16);

        let id = {
            let db = Database::open_at(&path).expect("open db");
            let id = db
                .insert_pending_chat_message(&friend, "held for later")
                .expect("queue message");
            // A delivered message must not be picked up by the flush scan.
            db.insert_chat_message(&friend, "sent", "already gone")
                .expect("insert delivered");
            id
        };

        let db = Database::open_at(&path).expect("reopen db");
        let pending = db.pending_chat_messages(&friend, 100).expect("pending");
        assert_eq!(pending.len(), 1, "only the queued row should be pending");
        assert_eq!(pending[0].0, id);
        assert_eq!(pending[0].1, "held for later");
        assert_eq!(
            db.pending_chat_counts().expect("counts"),
            vec![(friend.clone(), 1)]
        );

        db.set_chat_delivery(id, CHAT_DELIVERED).expect("mark sent");
        assert!(
            db.pending_chat_messages(&friend, 100)
                .expect("pending after")
                .is_empty(),
            "a delivered message must leave the queue"
        );
        // History still shows both, and the flushed one now reads as delivered.
        let history = db.get_chat_messages(&friend, 50, None).expect("history");
        assert_eq!(history.len(), 2);
        assert!(history.iter().all(|row| row.5 == CHAT_DELIVERED));

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn v21_enables_auto_vacuum_on_legacy_none_db() {
        let path = std::env::temp_dir().join(format!(
            "ember-av-legacy-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        {
            // Build a minimal pre-v21 DB with auto_vacuum stuck at NONE
            // (the historical pragma-order bug + existing tables).
            let conn = Connection::open(&path).expect("create legacy");
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE schema_version (version INTEGER NOT NULL DEFAULT 0);
                 INSERT INTO schema_version (version) VALUES (20);
                 CREATE TABLE statistics (key TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0);
                 CREATE TABLE transfers (id TEXT PRIMARY KEY);
                 CREATE TABLE transfers_v5_backup (id TEXT);
                 CREATE TABLE shared_files_v7_backup (id TEXT);
                 CREATE TABLE settings_v7_backup (key TEXT);",
            )
            .expect("seed legacy schema");
            let av: i64 = conn
                .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
                .unwrap();
            assert_eq!(av, 0, "fixture must start with auto_vacuum=NONE");
        }
        let db = Database::open_at(&path).expect("migrate legacy");
        let auto_vacuum: i64 = db
            .conn
            .lock()
            .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
            .expect("auto_vacuum");
        assert_eq!(auto_vacuum, 2, "v21 must enable INCREMENTAL auto_vacuum");
        let backups: i64 = db
            .conn
            .lock()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE '%_backup'",
                [],
                |r| r.get(0),
            )
            .expect("backup count");
        assert_eq!(backups, 0, "v21 must drop legacy backup tables");
        let expected_aich_column: i64 = db
            .conn
            .lock()
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('transfers') WHERE name = 'expected_aich'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            expected_aich_column, 1,
            "v22 must persist optional AICH pins"
        );
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    fn remove_test_database(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_file(parent.join(CHAT_KEY_FILE));
        }
    }

    #[test]
    fn chat_rows_are_encrypted_and_survive_restart_and_pagination() {
        let dir = std::env::temp_dir().join(format!(
            "ember-chat-encrypted-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ember.db");
        let canary = "plaintext-canary-chat-7c61";
        {
            let db = Database::open_at(&path).expect("open");
            let first = db
                .insert_chat_message(&"11".repeat(16), "sent", canary)
                .unwrap();
            let second = db
                .insert_chat_message(&"11".repeat(16), "received", "second")
                .unwrap();
            let raw: String = db
                .conn
                .lock()
                .query_row(
                    "SELECT message FROM chat_messages WHERE id = ?1",
                    params![first],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(raw.starts_with(CHAT_CIPHERTEXT_PREFIX));
            assert!(!raw.contains(canary));

            let newest = db.get_chat_messages(&"11".repeat(16), 1, None).unwrap();
            assert_eq!(newest[0].0, second);
            assert_eq!(newest[0].2, "second");
            let older = db
                .get_chat_messages(&"11".repeat(16), 5, Some(second))
                .unwrap();
            assert_eq!(older[0].0, first);
            assert_eq!(older[0].2, canary);
        }
        {
            let db = Database::open_at(&path).expect("restart");
            let rows = db.get_chat_messages(&"11".repeat(16), 5, None).unwrap();
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[1].2, canary);
        }
        let raw_db = std::fs::read(&path).unwrap();
        assert!(
            !raw_db
                .windows(canary.len())
                .any(|window| window == canary.as_bytes()),
            "database file must not contain the plaintext canary"
        );
        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn chat_ciphertext_tampering_and_wrong_key_fail_closed() {
        let key = [0x44; 32];
        let row =
            Database::encrypt_chat_body(&key, 9, &"22".repeat(16), "sent", 123, "secret").unwrap();
        let mut envelope = STANDARD_NO_PAD
            .decode(row.strip_prefix(CHAT_CIPHERTEXT_PREFIX).unwrap())
            .unwrap();
        *envelope.last_mut().unwrap() ^= 0x80;
        let tampered = format!(
            "{CHAT_CIPHERTEXT_PREFIX}{}",
            STANDARD_NO_PAD.encode(envelope)
        );
        assert!(
            Database::decrypt_chat_body(&key, 9, &"22".repeat(16), "sent", 123, &tampered).is_err()
        );
        assert!(
            Database::decrypt_chat_body(&[0x45; 32], 9, &"22".repeat(16), "sent", 123, &row)
                .is_err()
        );
        assert!(Database::decrypt_chat_body(
            &key,
            9,
            &"22".repeat(16),
            "sent",
            123,
            "legacy plaintext"
        )
        .is_err());
    }

    #[test]
    fn plaintext_chat_migration_is_transactional_and_authenticated() {
        let dir = std::env::temp_dir().join(format!(
            "ember-chat-migrate-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ember.db");
        let canary = "legacy-plaintext-canary-f143";
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL DEFAULT 0);
                 INSERT INTO schema_version(version) VALUES (22);
                 CREATE TABLE friends (
                    user_hash TEXT PRIMARY KEY, nickname TEXT NOT NULL DEFAULT '',
                    added_at INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE friend_requests (
                    sender_hash TEXT PRIMARY KEY, sender_nickname TEXT NOT NULL DEFAULT '',
                    received_at INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE chat_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    friend_hash TEXT NOT NULL, direction TEXT NOT NULL,
                    message TEXT NOT NULL, timestamp INTEGER NOT NULL,
                    read INTEGER NOT NULL DEFAULT 0
                 );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO chat_messages(friend_hash,direction,message,timestamp,read) \
                 VALUES (?1,'received',?2,77,0)",
                params!["33".repeat(16), canary],
            )
            .unwrap();
        }
        let db = Database::open_at(&path).expect("migrate");
        let rows = db.get_chat_messages(&"33".repeat(16), 10, None).unwrap();
        assert_eq!(rows[0].2, canary);
        let stored: String = db
            .conn
            .lock()
            .query_row("SELECT message FROM chat_messages", [], |row| row.get(0))
            .unwrap();
        assert!(stored.starts_with(CHAT_CIPHERTEXT_PREFIX));
        drop(db);
        let raw_db = std::fs::read(&path).unwrap();
        assert!(!raw_db.windows(canary.len()).any(|w| w == canary.as_bytes()));
        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A locked chat key must not turn a pre-v23 database into a failed open.
    /// The migration completes its schema work, leaves the message rows exactly
    /// as it found them, and encrypts them on the first launch that recovers
    /// the key — nothing is rotated, rewritten or lost in between.
    #[test]
    fn locked_chat_key_defers_v23_encryption_instead_of_failing_the_open() {
        let dir = std::env::temp_dir().join(format!(
            "ember-chat-locked-migrate-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ember.db");
        let friend = "55".repeat(16);
        let canary = "locked-migration-canary-90ab";
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL DEFAULT 0);
                 INSERT INTO schema_version(version) VALUES (22);
                 CREATE TABLE friends (
                    user_hash TEXT PRIMARY KEY, nickname TEXT NOT NULL DEFAULT '',
                    added_at INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE friend_requests (
                    sender_hash TEXT PRIMARY KEY, sender_nickname TEXT NOT NULL DEFAULT '',
                    received_at INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE chat_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    friend_hash TEXT NOT NULL, direction TEXT NOT NULL,
                    message TEXT NOT NULL, timestamp INTEGER NOT NULL,
                    read INTEGER NOT NULL DEFAULT 0
                 );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO chat_messages(friend_hash,direction,message,timestamp,read) \
                 VALUES (?1,'received',?2,77,0)",
                params![friend, canary],
            )
            .unwrap();
        }
        // An unrecoverable key file: not DPAPI-wrapped and not 32 bytes, so it
        // is rejected without being rewritten, exactly like a blob protected
        // under another Windows account.
        let key_path = dir.join(CHAT_KEY_FILE);
        std::fs::write(&key_path, b"unrecoverable").unwrap();

        let locked = Database::open_at(&path).expect("a locked chat key must not fail the open");
        assert!(locked.chat_locked());
        assert_eq!(locked.schema_version(), MAX_SUPPORTED_SCHEMA_VERSION);
        let stored: String = locked
            .conn
            .lock()
            .query_row("SELECT message FROM chat_messages", [], |row| row.get(0))
            .unwrap();
        assert_eq!(stored, canary, "the row must be left exactly as it was");
        let sealed = locked.get_chat_messages(&friend, 10, None).unwrap();
        assert_eq!(sealed.len(), 1);
        assert_eq!(sealed[0].2, CHAT_UNAVAILABLE_TEXT);
        drop(locked);

        // With the key recoverable again the deferred pass finishes the job.
        std::fs::remove_file(&key_path).unwrap();
        let recovered = Database::open_at(&path).expect("reopen");
        assert!(!recovered.chat_locked());
        let stored: String = recovered
            .conn
            .lock()
            .query_row("SELECT message FROM chat_messages", [], |row| row.get(0))
            .unwrap();
        assert!(stored.starts_with(CHAT_CIPHERTEXT_PREFIX));
        let messages = recovered.get_chat_messages(&friend, 10, None).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].2, canary);
        drop(recovered);

        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn wrong_chat_key_returns_placeholder_without_destroying_recoverable_ciphertext() {
        let dir = std::env::temp_dir().join(format!(
            "ember-chat-preserve-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ember.db");
        let friend = "44".repeat(16);
        let db = Database::open_at(&path).unwrap();
        let good = db
            .insert_chat_message(&friend, "received", "keep-me")
            .unwrap();
        let correct_key = **db.chat_key.as_ref().expect("test db has a chat key");
        let stored_before: String = db
            .conn
            .lock()
            .query_row(
                "SELECT message FROM chat_messages WHERE id = ?1",
                params![good],
                |row| row.get(0),
            )
            .unwrap();
        assert!(stored_before.starts_with(CHAT_CIPHERTEXT_PREFIX));
        drop(db);

        let wrong_key_db = Database {
            conn: Mutex::new(Connection::open(&path).unwrap()),
            chat_key: Some(Zeroizing::new([0x5A; 32])),
            corrupt_backup: None,
        };
        let unavailable = wrong_key_db.get_chat_messages(&friend, 10, None).unwrap();
        assert_eq!(unavailable.len(), 1);
        assert_eq!(unavailable[0].2, CHAT_UNAVAILABLE_TEXT);
        assert!(!unavailable[0].2.contains(&stored_before));
        let stored_after: String = wrong_key_db
            .conn
            .lock()
            .query_row(
                "SELECT message FROM chat_messages WHERE id = ?1",
                params![good],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_after.as_bytes(), stored_before.as_bytes());
        drop(wrong_key_db);

        let recovered_db = Database {
            conn: Mutex::new(Connection::open(&path).unwrap()),
            chat_key: Some(Zeroizing::new(correct_key)),
            corrupt_backup: None,
        };
        let recovered = recovered_db.get_chat_messages(&friend, 10, None).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].2, "keep-me");
        drop(recovered_db);

        remove_test_database(&path);
        let _ = std::fs::remove_dir_all(dir);
    }
}
