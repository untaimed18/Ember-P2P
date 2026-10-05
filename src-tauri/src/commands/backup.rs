//! Profile backup and restore: one passphrase-encrypted file holding the
//! state a user would otherwise lose on reinstall.
//!
//! This is Ember's answer to the batch files eMule users pass around, which
//! copy `cryptkey.dat`, `preferences.dat`, `clients.met`, `known.met` and
//! friends into a folder. Ember keeps the equivalent state in one data
//! directory ([`crate::storage::paths`]), so a backup is an explicit list of
//! files from it plus a snapshot of `ember.db`.
//!
//! Two things stop it from being a plain zip:
//!
//! 1. `identity.json`, `cryptkey.dat` and `chat-history.key` are DPAPI-wrapped
//!    against the current Windows account ([`crate::storage::secret_store`]).
//!    Copying them verbatim produces a backup that restores into an account
//!    which cannot read its own identity, losing the user hash, credits and
//!    friendships the backup existed to protect. So they are unwrapped on the
//!    way in and re-wrapped for the restoring account on the way out.
//! 2. That makes the archive a container for private keys, so encryption with
//!    a passphrase is mandatory rather than optional.
//!
//! Container layout:
//!
//! ```text
//! "EMBRBAK1" | u32 header_len | header JSON | chunk*
//! chunk := u8 final_flag | u32 ciphertext_len | ciphertext
//! ```
//!
//! The header carries the KDF parameters needed to derive the key and is
//! itself authenticated: every chunk's AAD binds the header hash, the chunk
//! index and the final flag, so a tampered header, a reordered, dropped or
//! duplicated chunk, and a truncated file are all detected rather than
//! silently producing short plaintext.
//!
//! Restores do not overwrite the running installation's files. SQLite holds
//! `ember.db` open, and replacing config or identity under a live process
//! invites half-applied state. Instead the restore is staged into
//! `restore-pending/` and [`apply_pending_restore`] swaps it in at the next
//! launch, before anything is opened, moving displaced originals aside.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key as ChaChaKey, XChaCha20Poly1305, XNonce};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::app_state::AppState;
use crate::commands::errors::{coded, coded_ctx};
use crate::storage::{paths, secret_store};
use tauri_plugin_dialog::DialogExt;

const MAGIC: &[u8; 8] = b"EMBRBAK1";
/// Container format. Bumped only for changes a v1 reader cannot parse.
const FORMAT_VERSION: u32 = 1;
/// Plaintext bytes per AEAD chunk. Keeps memory flat regardless of how large
/// the archive is; the tag overhead at this size is negligible.
const CHUNK_SIZE: usize = 1024 * 1024;
const TAG_LEN: usize = 16;
const NONCE_PREFIX_LEN: usize = 16;
const SALT_LEN: usize = 16;
const MAX_HEADER_LEN: usize = 16 * 1024;

/// Argon2id cost for backups this build writes. Roughly a third of a second on
/// a current desktop, which is a fine price for a manual action and a poor one
/// for anyone grinding guesses against a stolen archive.
const KDF_M_COST: u32 = 65_536;
const KDF_T_COST: u32 = 3;
const KDF_P_COST: u32 = 1;
/// Ceilings applied to the parameters *read from a file*, so a hostile archive
/// cannot make us allocate gigabytes or spin for minutes before it even gets
/// to fail the passphrase check.
const KDF_MAX_M_COST: u32 = 262_144;
const KDF_MAX_T_COST: u32 = 16;
const KDF_MAX_P_COST: u32 = 8;

/// How long a staged restore may wait before a launch refuses to apply it.
///
/// The hazard is applying a restore the user has moved on from, and elapsed
/// time is the only signal that survives the case that creates it: a build
/// without this feature ignores `restore-pending/` entirely and leaves no
/// evidence of having run, so a later upgrade cannot otherwise tell whether
/// its staged restore is from this morning or from last spring.
///
/// This is checked at startup only, so a session left running for weeks is
/// never affected. Reaching a launch a month after staging means either that
/// intervening launches could not apply it, or that the user has not restarted
/// in a month while the Backup screen showed the restore waiting - stale
/// either way. Discarding is also the cheap direction: the backup file still
/// exists and re-importing is two clicks, where applying it late overwrites a
/// profile and is recoverable only by hand from `pre-restore-*`.
const STAGED_RESTORE_MAX_AGE_SECS: i64 = 30 * 24 * 60 * 60;

const MIN_PASSPHRASE_LEN: usize = 10;
const MAX_PASSPHRASE_LEN: usize = 1024;
const MAX_PATH_LEN: usize = 4 * 1024;

const MANIFEST_NAME: &str = "manifest.json";
const STAGING_DIR: &str = "restore-pending";
const STAGING_MARKER: &str = "RESTORE.json";
/// Progress of an apply that has started swapping files; see [`ApplyJournal`].
const APPLY_JOURNAL: &str = "APPLY.json";
/// Left in staging when a finished restore's marker could not be removed, so
/// the next launch discards the staged copies instead of applying them again.
const APPLIED_SENTINEL: &str = "APPLIED";
/// Left by a Discard that had to wait for a restart: the next launch rolls
/// the interrupted apply back and drops the restore instead of retrying it.
const DISCARD_REQUESTED: &str = "DISCARD";
const BACKUP_DIR_PREFIX: &str = "pre-restore-";
const BACKUP_EXTENSION: &str = "emberbackup";

/// Per-entry and whole-archive ceilings on what a restore will unpack. The
/// declared sizes in a zip's central directory are attacker-controlled, so
/// these are enforced against the bytes actually read.
const MAX_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// A file the backup carries.
#[derive(Debug)]
struct BackupFile {
    name: &'static str,
    /// DPAPI-wrapped on disk: unwrapped into the archive, re-wrapped on restore.
    secret: bool,
    /// Copied with SQLite's `VACUUM INTO` instead of read off disk, so rows
    /// still sitting in the write-ahead log make it into the backup.
    database: bool,
}

const fn plain(name: &'static str) -> BackupFile {
    BackupFile {
        name,
        secret: false,
        database: false,
    }
}

const fn secret(name: &'static str) -> BackupFile {
    BackupFile {
        name,
        secret: true,
        database: false,
    }
}

/// Everything a backup contains, as an explicit allow-list rather than a
/// directory sweep. A sweep would quietly start shipping whatever future code
/// drops in the data directory (logs, crash dumps, someone's partial file) and
/// would also let a hostile archive name any path it liked on restore.
///
/// Deliberately absent: `.part` download data and the shared files themselves
/// (this is a profile backup, not a copy of the user's library), the log
/// directory, and `pending_deep_links.json`, which is a transient queue.
const BACKUP_FILES: &[BackupFile] = &[
    // Settings, shared-folder list, download folder, nickname.
    plain("config.json"),
    // Identity and crypto roots: user hash, KAD ID, Ed25519/Noise keys, the
    // RSA SecIdent keypair, and the chat-history key.
    secret("identity.json"),
    secret("cryptkey.dat"),
    secret("chat-history.key"),
    // Transfers, credits, friends, chat, statistics, history, comments.
    BackupFile {
        name: "ember.db",
        secret: false,
        database: true,
    },
    // eMule-compatible catalogues: known files, AICH recovery data, credits.
    plain("known.met"),
    plain("known_paths.dat"),
    plain("known2_64.met"),
    plain("aich_cache.dat"),
    plain("clients.met"),
    plain("sources.met"),
    // Where to reconnect: servers and Kad contacts.
    plain("server.met"),
    plain("last_ed2k_server.json"),
    plain("nodes.dat"),
    // Filters, reputation and learned spam, all expensive to rebuild.
    plain("ipfilter.dat"),
    plain("antileech.dat"),
    plain("reputation.json"),
    plain("search_spam.json"),
    // Per-file share decisions.
    plain("share_intent.json"),
    // `approved_roots.json` is deliberately absent; see [`LEGACY_IGNORED_FILES`].
];

/// Names that older archives legitimately carry and this build discards.
///
/// Distinct from simply dropping a name out of [`BACKUP_FILES`]: `read_archive`
/// refuses an archive whose manifest names anything outside the allow-list, so
/// a bare removal made every backup written by an earlier version unrestorable
/// with "The backup contains an unexpected file" — the one moment a user cannot
/// work around it. Entries listed here are skipped instead: not read, not
/// checksummed, not staged.
///
/// `approved_roots.json` earned its place because each record binds a folder to
/// a volume serial and file id, so it is meaningful only on the machine that
/// wrote it. Restoring one carried the source machine's records over, which
/// made `initialize_approved_roots` skip the first-run migration (state file
/// present) and then revoke the download folder on identity mismatch — or leave
/// it with no record at all when startup had just created it fresh. Either way
/// every download failed with "target is outside the approved roots" and,
/// unlike a shared folder, there was no in-app way to re-approve it. Skipping it
/// means startup approves a restored profile's download folders on *this*
/// machine.
const LEGACY_IGNORED_FILES: &[&str] = &["approved_roots.json"];

/// The one key an export may leave out: when chat is locked it is unreadable to
/// this account as well, so the backup loses nothing the profile can still use.
const CHAT_KEY_FILE: &str = "chat-history.key";
const DATABASE_FILE: &str = "ember.db";

/// Zip entry holding the preferences the app window keeps in its own storage
/// rather than in the data directory: language, theme, room lists and the like.
/// The frontend hands them over when a backup is made and takes them back with
/// [`take_pending_restored_prefs`] after the restore is applied.
///
/// Described by [`Manifest::webview_prefs`], never listed in `files`. Readers
/// that predate it refuse an archive whose `files` names anything unknown, but
/// ignore an unknown manifest field and a zip entry nothing asks for, so they
/// restore such a backup minus these preferences instead of rejecting it.
const WEBVIEW_PREFS_NAME: &str = "webview-prefs.json";
/// Where an applied restore leaves the preferences for the frontend to take.
const RESTORED_PREFS_FILE: &str = "restored-webview-prefs.json";
/// Serialized size ceiling, on export and on every read back.
const MAX_WEBVIEW_PREFS_BYTES: usize = 1024 * 1024;

/// The app-window storage keys a backup carries. A restore writes only these,
/// so a crafted archive cannot plant arbitrary keys in the window's storage.
/// Keep in step with `BACKED_UP_STORAGE_KEYS` in `src/lib/backupPrefs.ts`.
const WEBVIEW_PREF_KEYS: &[&str] = &[
    "PARAGLIDE_LOCALE",
    "ember-theme",
    "ember.channels.notify.v1",
    "ember.channels.favourites.v1",
    "ember.channels.hidden.v1",
    "ember.channels.ignored.v1",
    "ember.channels.carried.v1",
    "search-recent-queries-v1",
    "search-prefs-v1",
    "transfers-advanced-cols",
    "transfers-column-hidden-DownloadListCtrl",
    "transfers-column-hidden-UploadListCtrlV3",
    "transfers-column-hidden-QueueListCtrlV2",
    "transfers-column-hidden-KnownClientsCtrlV2",
    "transfers-column-hidden-DownloadClientsCtrl",
    "transfers-column-order-DownloadListCtrl",
    "transfers-column-order-UploadListCtrl",
    "transfers-column-order-QueueListCtrlV3",
    "transfers-column-order-KnownClientsCtrlV2",
    "transfers-column-order-DownloadClientsCtrl",
    "library-col-hidden",
    "library-col-order",
    "kad-search-col-hidden",
];

type WebviewPrefs = std::collections::BTreeMap<String, String>;

fn is_webview_pref_key(key: &str) -> bool {
    WEBVIEW_PREF_KEYS.contains(&key)
}

/// Check a snapshot the frontend handed over for a new backup.
fn validate_webview_prefs(prefs: &WebviewPrefs) -> Result<(), String> {
    if let Some(key) = prefs.keys().find(|key| !is_webview_pref_key(key)) {
        return Err(coded_ctx(
            "backup_export_failed",
            "Unexpected app preference for the backup",
            key,
        ));
    }
    let size = serde_json::to_vec(prefs)
        .map_err(|e| coded_ctx("backup_export_failed", "Failed to write the preferences", e))?
        .len();
    if size > MAX_WEBVIEW_PREFS_BYTES {
        return Err(coded_ctx(
            "backup_export_failed",
            "The app preferences are too large to back up",
            format!("{size} bytes"),
        ));
    }
    Ok(())
}

/// Parse a stored snapshot, or `None` if it is oversized or not an object of
/// strings. Keys this build does not restore are dropped rather than refused,
/// so a backup from a later version that carries more still restores the rest.
fn parse_webview_prefs(raw: &[u8]) -> Option<WebviewPrefs> {
    if raw.len() > MAX_WEBVIEW_PREFS_BYTES {
        return None;
    }
    let mut prefs: WebviewPrefs = serde_json::from_slice(raw).ok()?;
    prefs.retain(|key, _| is_webview_pref_key(key));
    Some(prefs)
}

fn backup_file(name: &str) -> Option<&'static BackupFile> {
    BACKUP_FILES.iter().find(|f| f.name == name)
}

/// Whether restoring `files` moves this device's chat-history key aside. A
/// restored database opened under the old key shows its history as unavailable
/// and seals new messages under a key the backup's rows do not use, so chat is
/// left cleanly locked instead.
fn restore_sets_aside_chat_key<S: AsRef<str>>(files: &[S]) -> bool {
    let has = |name: &str| files.iter().any(|f| f.as_ref() == name);
    has(DATABASE_FILE) && !has(CHAT_KEY_FILE)
}

/// Profile files a restore of `files` leaves as they are on this device.
fn files_kept_from_profile<S: AsRef<str>>(files: &[S]) -> Vec<String> {
    let chat_key_set_aside = restore_sets_aside_chat_key(files);
    BACKUP_FILES
        .iter()
        .map(|f| f.name)
        .filter(|name| !files.iter().any(|f| f.as_ref() == *name))
        .filter(|name| !(chat_key_set_aside && *name == CHAT_KEY_FILE))
        .map(str::to_string)
        .collect()
}

/// Whether `name` is a file an older version backed up that this one drops.
fn is_legacy_ignored(name: &str) -> bool {
    LEGACY_IGNORED_FILES.contains(&name)
}

/// Outer, unencrypted framing. Everything here is needed *before* a key
/// exists, and is authenticated by every chunk's AAD.
#[derive(Serialize, Deserialize)]
struct Header {
    format: u32,
    kdf: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: String,
    nonce_prefix: String,
    chunk_size: u32,
}

/// Inventory of the encrypted zip, written as its first entry.
#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    version: u32,
    app_version: String,
    created_at: i64,
    /// `schema_version` of the database in this backup, so a restore can
    /// refuse one written by a newer Ember instead of corrupting itself.
    schema_version: i64,
    files: Vec<ManifestEntry>,
    /// The app window's preferences, when the backup carries them; see
    /// [`WEBVIEW_PREFS_NAME`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    webview_prefs: Option<ManifestEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ManifestEntry {
    name: String,
    size: u64,
    blake3: String,
    /// Stored unwrapped; must be re-wrapped for the local account on restore.
    rewrap: bool,
}

/// Staged restore waiting for the next launch.
#[derive(Serialize, Deserialize)]
struct PendingRestore {
    version: u32,
    staged_at: i64,
    source_app_version: String,
    /// Schema version of the staged database. Checked again when the restore
    /// is applied, because that can happen under a different build than the
    /// one that accepted it.
    #[serde(default)]
    schema_version: i64,
    files: Vec<String>,
    /// Staging also holds [`WEBVIEW_PREFS_NAME`].
    #[serde(default)]
    webview_prefs: bool,
}

#[derive(Serialize)]
pub struct BackupSummary {
    pub path: String,
    pub bytes: u64,
    pub files: usize,
    pub created_at: i64,
    /// Files left out because they could not be read; only [`CHAT_KEY_FILE`].
    pub skipped: Vec<String>,
}

#[derive(Serialize)]
pub struct BackupPreview {
    pub app_version: String,
    pub created_at: i64,
    pub schema_version: i64,
    pub files: Vec<String>,
    pub total_bytes: u64,
    pub includes_identity: bool,
    /// True when the backup's database is newer than this build can open, in
    /// which case restoring it would be refused.
    pub schema_too_new: bool,
    /// Profile files the backup does not carry, which keep this device's copy.
    pub missing: Vec<String>,
    /// The backup brings a database but no chat-history key, so this device's
    /// key is set aside and chat history stays locked after the restore.
    pub chat_key_set_aside: bool,
}

#[derive(Debug, Serialize)]
pub struct RestoreSummary {
    /// Files staged for the swap at next launch.
    pub staged: Vec<String>,
    /// Profile files the backup does not carry, which keep this device's copy.
    pub missing: Vec<String>,
    /// See [`BackupPreview::chat_key_set_aside`].
    pub chat_key_set_aside: bool,
    pub app_version: String,
    pub created_at: i64,
}

// --- Crypto -----------------------------------------------------------------

fn derive_key(
    passphrase: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| coded_ctx("backup_not_an_ember_backup", "Unsupported backup", e))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|e| coded_ctx("backup_export_failed", "Key derivation failed", e))?;
    Ok(key)
}

fn chunk_aad(header_hash: &[u8; 32], index: u64, final_flag: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MAGIC.len() + 32 + 8 + 1);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(header_hash);
    aad.extend_from_slice(&index.to_le_bytes());
    aad.push(final_flag);
    aad
}

fn chunk_nonce(prefix: &[u8; NONCE_PREFIX_LEN], index: u64) -> XNonce {
    let mut nonce = [0u8; 24];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN..].copy_from_slice(&index.to_le_bytes());
    *XNonce::from_slice(&nonce)
}

/// Encrypt `plain_src` into `dest`, chunk by chunk.
fn encrypt_stream(
    plain_src: &mut std::fs::File,
    dest: &Path,
    passphrase: &str,
) -> Result<u64, String> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_prefix);

    let header = Header {
        format: FORMAT_VERSION,
        kdf: "argon2id".to_string(),
        m_cost: KDF_M_COST,
        t_cost: KDF_T_COST,
        p_cost: KDF_P_COST,
        salt: STANDARD.encode(salt),
        nonce_prefix: STANDARD.encode(nonce_prefix),
        chunk_size: CHUNK_SIZE as u32,
    };
    let header_json = serde_json::to_vec(&header)
        .map_err(|e| coded_ctx("backup_export_failed", "Failed to write backup header", e))?;
    let header_hash: [u8; 32] = blake3::hash(&header_json).into();

    let key = derive_key(passphrase, &salt, KDF_M_COST, KDF_T_COST, KDF_P_COST)?;
    let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key.as_ref()));

    let io = |e: std::io::Error| coded_ctx("backup_export_failed", "Failed to write backup", e);
    // `create_new`, not `create`: `dest` here is the per-export scratch file, and
    // truncating an existing one would let a second export in flight interleave
    // its chunk stream with ours. With a randomised scratch name a collision now
    // means something genuinely unexpected, so fail rather than overwrite.
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest)
        .map_err(io)?;
    crate::security::restrict_file_permissions(dest);
    out.write_all(MAGIC).map_err(io)?;
    out.write_all(&(header_json.len() as u32).to_le_bytes())
        .map_err(io)?;
    out.write_all(&header_json).map_err(io)?;

    plain_src.seek(SeekFrom::Start(0)).map_err(io)?;
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut index: u64 = 0;
    loop {
        let mut filled = 0usize;
        // `read` may return short without being at EOF, so fill the buffer
        // before deciding this is the final chunk.
        while filled < CHUNK_SIZE {
            match plain_src.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(io(e)),
            }
        }
        let final_flag = u8::from(filled < CHUNK_SIZE);
        let aad = chunk_aad(&header_hash, index, final_flag);
        let ciphertext = cipher
            .encrypt(
                &chunk_nonce(&nonce_prefix, index),
                Payload {
                    msg: &buf[..filled],
                    aad: &aad,
                },
            )
            .map_err(|e| coded_ctx("backup_export_failed", "Encryption failed", e))?;
        out.write_all(&[final_flag]).map_err(io)?;
        out.write_all(&(ciphertext.len() as u32).to_le_bytes())
            .map_err(io)?;
        out.write_all(&ciphertext).map_err(io)?;
        index += 1;
        if final_flag == 1 {
            break;
        }
    }
    out.flush().map_err(io)?;
    out.sync_all().map_err(io)?;
    let bytes = out.metadata().map_err(io)?.len();
    Ok(bytes)
}

/// Decrypt `src` into `dest`, verifying order, completeness and the header.
fn decrypt_stream(src: &Path, dest: &Path, passphrase: &str) -> Result<(), String> {
    let io = |e: std::io::Error| coded_ctx("backup_corrupt_archive", "Failed to read backup", e);
    let mut input =
        std::io::BufReader::new(std::fs::File::open(src).map_err(|e| {
            coded_ctx("backup_invalid_source", "Failed to open the backup file", e)
        })?);

    let mut magic = [0u8; 8];
    input
        .read_exact(&mut magic)
        .map_err(|_| coded("backup_not_an_ember_backup", "Not an Ember backup file"))?;
    if &magic != MAGIC {
        return Err(coded(
            "backup_not_an_ember_backup",
            "Not an Ember backup file",
        ));
    }
    let mut len_bytes = [0u8; 4];
    input
        .read_exact(&mut len_bytes)
        .map_err(|_| coded("backup_not_an_ember_backup", "Not an Ember backup file"))?;
    let header_len = u32::from_le_bytes(len_bytes) as usize;
    if header_len == 0 || header_len > MAX_HEADER_LEN {
        return Err(coded(
            "backup_not_an_ember_backup",
            "Backup header is not readable",
        ));
    }
    let mut header_json = vec![0u8; header_len];
    input.read_exact(&mut header_json).map_err(io)?;
    let header_hash: [u8; 32] = blake3::hash(&header_json).into();
    let header: Header = serde_json::from_slice(&header_json).map_err(|e| {
        coded_ctx(
            "backup_not_an_ember_backup",
            "Backup header is not readable",
            e,
        )
    })?;
    if header.format != FORMAT_VERSION || header.kdf != "argon2id" {
        return Err(coded_ctx(
            "backup_not_an_ember_backup",
            "This backup was written by a newer version of Ember",
            format!("format {}", header.format),
        ));
    }
    if header.m_cost > KDF_MAX_M_COST
        || header.t_cost > KDF_MAX_T_COST
        || header.p_cost > KDF_MAX_P_COST
        || header.chunk_size == 0
        || header.chunk_size as usize > CHUNK_SIZE * 16
    {
        return Err(coded(
            "backup_not_an_ember_backup",
            "Backup header declares unsupported parameters",
        ));
    }
    let salt = STANDARD.decode(&header.salt).map_err(|e| {
        coded_ctx(
            "backup_not_an_ember_backup",
            "Backup header is not readable",
            e,
        )
    })?;
    let prefix_bytes = STANDARD.decode(&header.nonce_prefix).map_err(|e| {
        coded_ctx(
            "backup_not_an_ember_backup",
            "Backup header is not readable",
            e,
        )
    })?;
    if salt.len() < 8 || prefix_bytes.len() != NONCE_PREFIX_LEN {
        return Err(coded(
            "backup_not_an_ember_backup",
            "Backup header is not readable",
        ));
    }
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    nonce_prefix.copy_from_slice(&prefix_bytes);

    let key = derive_key(
        passphrase,
        &salt,
        header.m_cost,
        header.t_cost,
        header.p_cost,
    )?;
    let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key.as_ref()));

    let mut out = std::fs::File::create(dest)
        .map_err(|e| coded_ctx("backup_restore_failed", "Failed to unpack the backup", e))?;
    crate::security::restrict_file_permissions(dest);
    let max_ciphertext = header.chunk_size as usize + TAG_LEN;
    let mut index: u64 = 0;
    let mut written: u64 = 0;
    loop {
        let mut flag = [0u8; 1];
        match input.read_exact(&mut flag) {
            Ok(()) => {}
            // Running out of frames before the final one means the file was
            // cut short, or an attacker dropped the tail.
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(coded(
                    "backup_corrupt_archive",
                    "The backup file is incomplete",
                ));
            }
            Err(e) => return Err(io(e)),
        }
        input
            .read_exact(&mut len_bytes)
            .map_err(|_| coded("backup_corrupt_archive", "The backup file is incomplete"))?;
        let ct_len = u32::from_le_bytes(len_bytes) as usize;
        if flag[0] > 1 || ct_len < TAG_LEN || ct_len > max_ciphertext {
            return Err(coded(
                "backup_corrupt_archive",
                "The backup file is damaged",
            ));
        }
        let mut ciphertext = vec![0u8; ct_len];
        input
            .read_exact(&mut ciphertext)
            .map_err(|_| coded("backup_corrupt_archive", "The backup file is incomplete"))?;
        let aad = chunk_aad(&header_hash, index, flag[0]);
        let plaintext = cipher
            .decrypt(
                &chunk_nonce(&nonce_prefix, index),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            // The first chunk failing is overwhelmingly a wrong passphrase; a
            // later one means the file itself was altered, since the key has
            // already proved itself.
            .map_err(|_| {
                if index == 0 {
                    coded("backup_wrong_passphrase", "Incorrect passphrase")
                } else {
                    coded("backup_corrupt_archive", "The backup file is damaged")
                }
            })?;
        written = written.saturating_add(plaintext.len() as u64);
        if written > MAX_TOTAL_BYTES {
            return Err(coded("backup_corrupt_archive", "The backup is too large"));
        }
        out.write_all(&plaintext)
            .map_err(|e| coded_ctx("backup_restore_failed", "Failed to unpack the backup", e))?;
        index += 1;
        if flag[0] == 1 {
            break;
        }
    }
    // Anything after the final chunk was appended by something that could not
    // forge a further frame; refuse rather than ignore it.
    let mut trailing = [0u8; 1];
    if input.read(&mut trailing).map_err(io)? != 0 {
        return Err(coded(
            "backup_corrupt_archive",
            "The backup file is damaged",
        ));
    }
    out.flush()
        .map_err(|e| coded_ctx("backup_restore_failed", "Failed to unpack the backup", e))?;
    Ok(())
}

// --- Export -----------------------------------------------------------------

/// Scratch directory for the intermediate plaintext zip. Lives inside the data
/// directory so it inherits the restricted ACL and shares a volume with the
/// database snapshot.
/// Remove `.backup-tmp-*` / `.restore-tmp-*` directories left in the data
/// directory by an export or import that did not finish.
///
/// Export deliberately DPAPI-*unwraps* `identity.json`, `cryptkey.dat` and
/// `chat-history.key` into its scratch directory, because a backup that only
/// restores under the Windows account that made it is not a backup. Those
/// plaintext keys are only removed by the tail of the export closure, which a
/// kill, a crash or a power loss skips — and the directory name carries a pid
/// and a UUID, so nothing ever looked for it again. Living in the data
/// directory rather than `%TEMP%`, the OS never reclaimed it either, leaving
/// the Ed25519, Noise and SecIdent private keys plus the chat-history key
/// unwrapped on disk indefinitely. The ACL is still current-user-only; what
/// this restores is the at-rest wrapping that protects a copied, cloned or
/// cloud-synced profile.
///
/// Startup is the right place because no export or import can be in flight
/// yet, so a directory found here is always abandoned.
pub fn sweep_orphaned_scratch(data_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(".backup-tmp-") && !name.starts_with(".restore-tmp-") {
            continue;
        }
        if !entry.path().is_dir() {
            continue;
        }
        match std::fs::remove_dir_all(entry.path()) {
            Ok(()) => tracing::warn!(
                "Removed an abandoned backup scratch directory ({name}); an export or import \
                 did not finish"
            ),
            Err(e) => tracing::warn!(
                error = %e,
                "could not remove the abandoned backup scratch directory {name}"
            ),
        }
    }
}

fn temp_dir_in(data_dir: &Path, tag: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(data_dir).map_err(|e| {
        coded_ctx(
            "backup_export_failed",
            "Failed to create a temp directory",
            e,
        )
    })?;
    for _ in 0..8 {
        let dir = data_dir.join(format!(
            ".{tag}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        match std::fs::create_dir(&dir) {
            Ok(()) => {
                crate::security::restrict_file_permissions(&dir);
                return Ok(dir);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(coded_ctx(
                    "backup_export_failed",
                    "Failed to create a temp directory",
                    error,
                ));
            }
        }
    }
    Err(coded(
        "backup_export_failed",
        "Failed to allocate a unique temp directory",
    ))
}

/// Build the plaintext zip: `manifest.json` plus one entry per present file,
/// and the app window's preferences when there are any. Also returns the
/// files left out because they could not be read.
fn build_archive(
    data_dir: &Path,
    scratch: &Path,
    db: &crate::storage::database::Database,
    app_version: &str,
    webview_prefs: Option<&WebviewPrefs>,
) -> Result<(PathBuf, Manifest, Vec<String>), String> {
    let zip_path = scratch.join("payload.zip");
    let file = std::fs::File::create(&zip_path)
        .map_err(|e| coded_ctx("backup_export_failed", "Failed to create the archive", e))?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    let mut entries = Vec::new();
    let mut skipped = Vec::new();
    for spec in BACKUP_FILES {
        let bytes = if spec.database {
            let snapshot = scratch.join("ember.db.snapshot");
            db.snapshot_to(&snapshot).map_err(|e| {
                coded_ctx("backup_export_failed", "Failed to snapshot the database", e)
            })?;
            let bytes = std::fs::read(&snapshot)
                .map_err(|e| coded_ctx("backup_export_failed", "Failed to read the snapshot", e))?;
            let _ = std::fs::remove_file(&snapshot);
            Zeroizing::new(bytes)
        } else {
            match std::fs::read(data_dir.join(spec.name)) {
                Ok(raw) if spec.secret => {
                    // Unwrap here or the restored file is unreadable to any
                    // other Windows account, which is the whole point of the
                    // feature. The plaintext is held in a `Zeroizing` buffer so
                    // it is wiped once this entry has been written.
                    match secret_store::unprotect(&raw) {
                        Ok(plaintext) => plaintext,
                        // Only while chat is locked. With it unlocked the key is
                        // the one history is sealed under: a backup without it
                        // could never read the history it carries, and a restore
                        // would set this device's working key aside.
                        Err(e) if spec.name == CHAT_KEY_FILE && db.chat_locked() => {
                            tracing::warn!(
                                "Leaving {CHAT_KEY_FILE} out of the backup: chat is locked and \
                                 the key cannot be read ({e})"
                            );
                            skipped.push(spec.name.to_string());
                            continue;
                        }
                        Err(e) => {
                            return Err(coded_ctx(
                                "backup_export_failed",
                                format!("Could not read the protected {}", spec.name),
                                format!("{}: {e}", spec.name),
                            ))
                        }
                    }
                }
                Ok(raw) => Zeroizing::new(raw),
                // A file that was never created (no Kad contacts yet, no IP
                // filter installed) is simply absent from the backup.
                Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(coded_ctx(
                        "backup_export_failed",
                        format!("Failed to read {}", spec.name),
                        e,
                    ))
                }
            }
        };
        if bytes.len() as u64 > MAX_ENTRY_BYTES {
            return Err(coded_ctx(
                "backup_export_failed",
                format!("{} is too large to back up", spec.name),
                format!("{} bytes", bytes.len()),
            ));
        }
        zip.start_file(spec.name, options)
            .map_err(|e| coded_ctx("backup_export_failed", "Failed to add a file", e))?;
        zip.write_all(&bytes)
            .map_err(|e| coded_ctx("backup_export_failed", "Failed to add a file", e))?;
        entries.push(ManifestEntry {
            name: spec.name.to_string(),
            size: bytes.len() as u64,
            blake3: blake3::hash(&bytes).to_hex().to_string(),
            rewrap: spec.secret,
        });
    }

    let webview_prefs = match webview_prefs {
        Some(prefs) => {
            validate_webview_prefs(prefs)?;
            let bytes = serde_json::to_vec(prefs).map_err(|e| {
                coded_ctx("backup_export_failed", "Failed to write the preferences", e)
            })?;
            zip.start_file(WEBVIEW_PREFS_NAME, options).map_err(|e| {
                coded_ctx("backup_export_failed", "Failed to write the preferences", e)
            })?;
            zip.write_all(&bytes).map_err(|e| {
                coded_ctx("backup_export_failed", "Failed to write the preferences", e)
            })?;
            Some(ManifestEntry {
                name: WEBVIEW_PREFS_NAME.to_string(),
                size: bytes.len() as u64,
                blake3: blake3::hash(&bytes).to_hex().to_string(),
                rewrap: false,
            })
        }
        None => None,
    };

    let manifest = Manifest {
        version: FORMAT_VERSION,
        app_version: app_version.to_string(),
        created_at: chrono::Utc::now().timestamp(),
        schema_version: db.schema_version(),
        files: entries,
        webview_prefs,
    };
    let manifest_json = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| coded_ctx("backup_export_failed", "Failed to write the manifest", e))?;
    zip.start_file(MANIFEST_NAME, options)
        .map_err(|e| coded_ctx("backup_export_failed", "Failed to write the manifest", e))?;
    zip.write_all(&manifest_json)
        .map_err(|e| coded_ctx("backup_export_failed", "Failed to write the manifest", e))?;
    zip.finish()
        .map_err(|e| coded_ctx("backup_export_failed", "Failed to finish the archive", e))?;
    Ok((zip_path, manifest, skipped))
}

fn validate_passphrase(passphrase: &str) -> Result<(), String> {
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(coded_ctx(
            "backup_weak_passphrase",
            "Choose a longer passphrase",
            format!("minimum {MIN_PASSPHRASE_LEN} characters"),
        ));
    }
    if passphrase.len() > MAX_PASSPHRASE_LEN {
        return Err(coded(
            "backup_weak_passphrase",
            "That passphrase is unreasonably long",
        ));
    }
    Ok(())
}

/// Defense-in-depth after a native save dialog: refuse system directories and
/// require `.emberbackup`. The dialog itself is the authorization; this does
/// not accept a renderer-supplied path.
fn validate_destination(path: &Path) -> Result<PathBuf, String> {
    if path.to_string_lossy().len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "backup_invalid_destination",
            "File path is too long",
            format!("{MAX_PATH_LEN} bytes"),
        ));
    }
    if !path.is_absolute() {
        return Err(coded(
            "backup_invalid_destination",
            "Choose a location for the backup file",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| coded("backup_invalid_destination", "Choose a valid location"))?;
    let parent = parent
        .canonicalize()
        .map_err(|e| coded_ctx("backup_invalid_destination", "That folder is not usable", e))?;
    for component in parent.components() {
        if let std::path::Component::Normal(seg) = component {
            let seg = seg.to_string_lossy().to_lowercase();
            if matches!(
                seg.as_str(),
                "windows" | "program files" | "program files (x86)" | "programdata" | "system32"
            ) {
                return Err(coded_ctx(
                    "backup_invalid_destination",
                    "Cannot write a backup into a system directory",
                    parent.display(),
                ));
            }
        }
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .filter(|n| !n.is_empty())
        .ok_or_else(|| coded("backup_invalid_destination", "Choose a file name"))?;
    let final_path = parent.join(name);
    if final_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .as_deref()
        != Some(BACKUP_EXTENSION)
    {
        return Err(coded_ctx(
            "backup_invalid_destination",
            "Backups must be saved with the .emberbackup extension",
            format!(".{BACKUP_EXTENSION}"),
        ));
    }
    Ok(final_path)
}

fn ensure_backup_extension(mut path: PathBuf) -> PathBuf {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case(BACKUP_EXTENSION) => path,
        _ => {
            path.set_extension(BACKUP_EXTENSION);
            path
        }
    }
}

async fn pick_backup_save_path(app: &tauri::AppHandle) -> Result<Option<PathBuf>, String> {
    let default_name = format!(
        "ember-backup-{}.{BACKUP_EXTENSION}",
        chrono::Utc::now().format("%Y-%m-%d")
    );
    let app = app.clone();
    tokio::task::spawn_blocking(move || {
        app.dialog()
            .file()
            .add_filter("Ember Backup", &[BACKUP_EXTENSION])
            .set_file_name(default_name)
            .blocking_save_file()
            .map(|file| {
                file.into_path()
                    .map_err(|e| coded_ctx("backup_invalid_destination", "Invalid backup path", e))
            })
            .transpose()
    })
    .await
    .map_err(|e| coded_ctx("backup_task_failed", "Backup dialog failed", e))?
}

async fn pick_backup_open_path(app: &tauri::AppHandle) -> Result<Option<PathBuf>, String> {
    let app = app.clone();
    tokio::task::spawn_blocking(move || {
        app.dialog()
            .file()
            .add_filter("Ember Backup", &[BACKUP_EXTENSION])
            .blocking_pick_file()
            .map(|file| {
                file.into_path()
                    .map_err(|e| coded_ctx("backup_invalid_source", "Invalid backup path", e))
            })
            .transpose()
    })
    .await
    .map_err(|e| coded_ctx("backup_task_failed", "Backup dialog failed", e))?
}

/// Sibling scratch name for an in-progress export. Sits next to the
/// destination so the final step is a same-volume rename.
///
/// Randomised per call, not just per process. `export_backup` holds no lock, so
/// two overlapping exports to one destination derived the same scratch name and
/// — with the truncating `File::create` that used to open it — interleaved two
/// independently keyed chunk streams into one file. The first rename published
/// that mixture over the user's existing backup and returned `Ok`, leaving a
/// file no passphrase can decrypt where a good backup used to be. Mirrors
/// `security::unique_tmp_path`, and the scratch is now opened with
/// `create_new` so a collision fails loudly instead of truncating.
fn partial_export_path(dest: &Path) -> PathBuf {
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "backup".to_string());
    let mut unique = [0u8; 8];
    OsRng.fill_bytes(&mut unique);
    dest.with_file_name(format!(
        ".{name}.{}.{}.partial",
        std::process::id(),
        hex::encode(unique)
    ))
}

fn validate_source(path: &Path) -> Result<PathBuf, String> {
    if path.to_string_lossy().len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "backup_invalid_source",
            "File path is too long",
            format!("{MAX_PATH_LEN} bytes"),
        ));
    }
    let canonical = path
        .canonicalize()
        .map_err(|e| coded_ctx("backup_invalid_source", "Cannot open that file", e))?;
    if !canonical.is_file() {
        return Err(coded("backup_invalid_source", "That is not a backup file"));
    }
    Ok(canonical)
}

/// Native save-dialog export. The OS dialog *is* the authorization; this
/// command never accepts a renderer-supplied path.
#[tauri::command]
pub async fn export_backup(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    passphrase: String,
    webview_prefs: Option<WebviewPrefs>,
) -> Result<Option<BackupSummary>, String> {
    validate_passphrase(&passphrase)?;
    if let Some(prefs) = &webview_prefs {
        validate_webview_prefs(prefs)?;
    }
    let Some(picked) = pick_backup_save_path(&app).await? else {
        return Ok(None);
    };
    let dest = validate_destination(&ensure_backup_extension(picked))?;
    Ok(Some(
        write_backup(&app, &state, dest, passphrase, webview_prefs).await?,
    ))
}

async fn write_backup(
    app: &tauri::AppHandle,
    state: &AppState,
    dest: PathBuf,
    passphrase: String,
    webview_prefs: Option<WebviewPrefs>,
) -> Result<BackupSummary, String> {
    let db = state.db.clone();
    let app_version = app.package_info().version.to_string();
    let data_dir = paths::resolve_data_dir_with_app(app);
    let passphrase = Zeroizing::new(passphrase);

    tokio::task::spawn_blocking(move || {
        let scratch = temp_dir_in(&data_dir, "backup-tmp")?;
        let partial = partial_export_path(&dest);
        let result = (|| {
            let (zip_path, manifest, skipped) = build_archive(
                &data_dir,
                &scratch,
                &db,
                &app_version,
                webview_prefs.as_ref(),
            )?;
            let mut zip_file = std::fs::File::open(&zip_path)
                .map_err(|e| coded_ctx("backup_export_failed", "Failed to read the archive", e))?;
            let bytes = encrypt_stream(&mut zip_file, &partial, &passphrase)?;
            // Only now replace whatever was at `dest`. Encrypting straight
            // into it would destroy an earlier backup the user chose to
            // overwrite if anything failed halfway through.
            std::fs::rename(&partial, &dest)
                .map_err(|e| coded_ctx("backup_export_failed", "Failed to save the backup", e))?;
            Ok(BackupSummary {
                path: dest.to_string_lossy().to_string(),
                bytes,
                files: manifest.files.len(),
                created_at: manifest.created_at,
                skipped,
            })
        })();
        // The scratch copy is plaintext identity material; never leave it
        // behind, including on the failure path.
        let _ = std::fs::remove_dir_all(&scratch);
        if result.is_err() {
            let _ = std::fs::remove_file(&partial);
        }
        result
    })
    .await
    .map_err(|e| coded_ctx("backup_task_failed", "Backup task failed", e))?
}

/// Native open-dialog for restore. Stores the canonical path server-side so
/// preview/import cannot be aimed at an arbitrary readable file.
#[tauri::command]
pub async fn pick_backup_file(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<Option<String>, String> {
    let Some(picked) = pick_backup_open_path(&app).await? else {
        return Ok(None);
    };
    let source = validate_source(&picked)?;
    let display = source.to_string_lossy().into_owned();
    *state.picked_backup.lock().await = Some(source);
    Ok(Some(display))
}

#[tauri::command]
pub async fn clear_picked_backup(state: tauri::State<'_, AppState>) -> Result<(), String> {
    *state.picked_backup.lock().await = None;
    Ok(())
}

async fn require_picked_backup(state: &AppState) -> Result<PathBuf, String> {
    state.picked_backup.lock().await.clone().ok_or_else(|| {
        coded(
            "backup_invalid_source",
            "Choose a backup file before restoring",
        )
    })
}

// --- Restore ----------------------------------------------------------------

type Archive = zip::ZipArchive<std::fs::File>;

fn open_archive(zip_path: &Path) -> Result<Archive, String> {
    let file = std::fs::File::open(zip_path)
        .map_err(|e| coded_ctx("backup_corrupt_archive", "Failed to read the backup", e))?;
    zip::ZipArchive::new(file)
        .map_err(|e| coded_ctx("backup_corrupt_archive", "The backup is not readable", e))
}

/// Read just the inventory. Enough to describe a backup to the user without
/// unpacking (and hashing) every file it carries.
fn read_manifest(archive: &mut Archive) -> Result<Manifest, String> {
    let manifest: Manifest = {
        let entry = archive
            .by_name(MANIFEST_NAME)
            .map_err(|e| coded_ctx("backup_corrupt_archive", "The backup has no manifest", e))?;
        let mut raw = Vec::new();
        entry
            .take(MAX_HEADER_LEN as u64 * 64)
            .read_to_end(&mut raw)
            .map_err(|e| coded_ctx("backup_corrupt_archive", "Failed to read the manifest", e))?;
        serde_json::from_slice(&raw)
            .map_err(|e| coded_ctx("backup_corrupt_archive", "The manifest is not readable", e))?
    };
    if manifest.version != FORMAT_VERSION {
        return Err(coded_ctx(
            "backup_not_an_ember_backup",
            "This backup was written by a newer version of Ember",
            format!("manifest {}", manifest.version),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for entry in &manifest.files {
        if !seen.insert(entry.name.as_str()) {
            return Err(coded_ctx(
                "backup_corrupt_archive",
                "The backup lists the same file twice",
                &entry.name,
            ));
        }
    }
    Ok(manifest)
}

/// An archive entry that has verified, unpacked into the import's scratch
/// directory.
#[derive(Debug)]
struct UnpackedEntry {
    spec: &'static BackupFile,
    path: PathBuf,
}

/// Passes writes through to `inner` while hashing and counting them.
struct HashingWriter<W> {
    inner: W,
    hasher: blake3::Hasher,
    written: u64,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Read and verify the manifest and every entry of a decrypted archive,
/// unpacking each entry into `unpack_dir` and returning them in manifest order.
///
/// Entries go to the scratch directory, not to staging: nothing is written to
/// the staging directory until the whole archive has verified, so a backup
/// that turns out to be damaged half way through cannot leave a partial
/// profile staged.
fn read_archive(
    zip_path: &Path,
    unpack_dir: &Path,
) -> Result<(Manifest, Vec<UnpackedEntry>), String> {
    let mut archive = open_archive(zip_path)?;
    let manifest = read_manifest(&mut archive)?;
    std::fs::create_dir_all(unpack_dir)
        .map_err(|e| coded_ctx("backup_restore_failed", "Failed to unpack the backup", e))?;

    let mut total = 0u64;
    let mut out = Vec::new();
    for entry in &manifest.files {
        // A file this version no longer restores. Skipped before the
        // allow-list test and never read, so an archive from a version that
        // still backed it up restores cleanly rather than being rejected
        // wholesale. Nothing downstream sees it, so it cannot name a path.
        if is_legacy_ignored(&entry.name) {
            continue;
        }
        // The allow-list is what keeps a crafted archive from naming
        // `..\..\something` or any path outside the data directory.
        let Some(spec) = backup_file(&entry.name) else {
            return Err(coded_ctx(
                "backup_corrupt_archive",
                "The backup contains an unexpected file",
                &entry.name,
            ));
        };
        // Whether a file is re-wrapped is the allow-list's call. Taking the
        // manifest's word would let an archive stage a key unwrapped, or wrap
        // a plain file the app then cannot read.
        if entry.rewrap != spec.secret {
            return Err(coded_ctx(
                "backup_corrupt_archive",
                "The backup does not mark this file's protection correctly",
                &entry.name,
            ));
        }
        if entry.size > MAX_ENTRY_BYTES {
            return Err(coded_ctx(
                "backup_corrupt_archive",
                "The backup contains a file that is too large",
                &entry.name,
            ));
        }
        let mut zipped = archive.by_name(&entry.name).map_err(|e| {
            coded_ctx(
                "backup_corrupt_archive",
                format!("The backup is missing {}", entry.name),
                e,
            )
        })?;
        let path = unpack_dir.join(spec.name);
        let unpack_error = |e: std::io::Error| {
            coded_ctx("backup_restore_failed", "Failed to unpack the backup", e)
        };
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(unpack_error)?;
        crate::security::restrict_file_permissions(&path);
        let mut sink = HashingWriter {
            inner: std::io::BufWriter::new(file),
            hasher: blake3::Hasher::new(),
            written: 0,
        };
        // Cap the bytes actually decompressed: the declared size above is
        // metadata the archive controls, and deflate keeps going regardless.
        std::io::copy(&mut (&mut zipped).take(MAX_ENTRY_BYTES + 1), &mut sink).map_err(|e| {
            coded_ctx(
                "backup_corrupt_archive",
                format!("Failed to read {}", entry.name),
                e,
            )
        })?;
        sink.flush().map_err(unpack_error)?;
        if sink.written > MAX_ENTRY_BYTES {
            return Err(coded_ctx(
                "backup_corrupt_archive",
                "The backup contains a file that is too large",
                &entry.name,
            ));
        }
        total = total.saturating_add(sink.written);
        if total > MAX_TOTAL_BYTES {
            return Err(coded("backup_corrupt_archive", "The backup is too large"));
        }
        if sink.written != entry.size || sink.hasher.finalize().to_hex().to_string() != entry.blake3
        {
            return Err(coded_ctx(
                "backup_corrupt_archive",
                "A file in the backup does not match its checksum",
                &entry.name,
            ));
        }
        out.push(UnpackedEntry { spec, path });
    }
    Ok((manifest, out))
}

/// `schema_version` of the database a backup carries, read from the file
/// rather than taken on the manifest's word.
fn database_schema_version(path: &Path) -> Result<i64, String> {
    let unreadable = |e: rusqlite::Error| {
        coded_ctx(
            "backup_corrupt_archive",
            "The backup's database is not readable",
            e,
        )
    };
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(unreadable)?;
    conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )
    .map_err(unreadable)
}

/// Verify a decrypted archive and stage it for the next launch.
fn stage_archive(
    zip_path: &Path,
    scratch: &Path,
    staging: &Path,
) -> Result<RestoreSummary, String> {
    let (manifest, entries) = read_archive(zip_path, &scratch.join("entries"))?;
    let schema_version = match entries.iter().find(|e| e.spec.database) {
        Some(db) => database_schema_version(&db.path)?,
        None => 0,
    };
    if schema_version > crate::storage::database::MAX_SUPPORTED_SCHEMA_VERSION {
        return Err(coded_ctx(
            "backup_schema_too_new",
            "This backup was made by a newer version of Ember",
            format!(
                "database v{} (this build supports v{})",
                schema_version,
                crate::storage::database::MAX_SUPPORTED_SCHEMA_VERSION
            ),
        ));
    }
    let webview_prefs = read_webview_prefs(zip_path, &manifest)?;
    stage_restore(
        staging,
        &manifest,
        schema_version,
        entries,
        webview_prefs.as_ref(),
    )
}

/// Read and verify the app-window preferences a decrypted archive carries, if
/// any. Held to the same standard as the files: a backup whose manifest
/// promises preferences it cannot deliver intact is damaged, not merely
/// lacking them.
fn read_webview_prefs(
    zip_path: &Path,
    manifest: &Manifest,
) -> Result<Option<WebviewPrefs>, String> {
    let Some(entry) = &manifest.webview_prefs else {
        return Ok(None);
    };
    if entry.name != WEBVIEW_PREFS_NAME {
        return Err(coded_ctx(
            "backup_corrupt_archive",
            "The backup contains an unexpected file",
            &entry.name,
        ));
    }
    if entry.size > MAX_WEBVIEW_PREFS_BYTES as u64 {
        return Err(coded_ctx(
            "backup_corrupt_archive",
            "The backup contains a file that is too large",
            &entry.name,
        ));
    }
    let mut archive = open_archive(zip_path)?;
    let mut zipped = archive.by_name(WEBVIEW_PREFS_NAME).map_err(|e| {
        coded_ctx(
            "backup_corrupt_archive",
            format!("The backup is missing {WEBVIEW_PREFS_NAME}"),
            e,
        )
    })?;
    let mut bytes = Vec::new();
    (&mut zipped)
        .take(MAX_WEBVIEW_PREFS_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| {
            coded_ctx(
                "backup_corrupt_archive",
                format!("Failed to read {WEBVIEW_PREFS_NAME}"),
                e,
            )
        })?;
    if bytes.len() as u64 != entry.size || blake3::hash(&bytes).to_hex().to_string() != entry.blake3
    {
        return Err(coded_ctx(
            "backup_corrupt_archive",
            "A file in the backup does not match its checksum",
            WEBVIEW_PREFS_NAME,
        ));
    }
    parse_webview_prefs(&bytes).map(Some).ok_or_else(|| {
        coded_ctx(
            "backup_corrupt_archive",
            "The backup's app preferences are not readable",
            WEBVIEW_PREFS_NAME,
        )
    })
}

fn staging_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(STAGING_DIR)
}

/// True when a completed staging run is still waiting (or was left behind
/// after a failed / schema-too-new apply). Incomplete directories without
/// a marker are discarded by [`apply_pending_restore`] and do not count.
pub(crate) fn pending_restore_still_staged(data_dir: &Path) -> bool {
    let staging = staging_dir(data_dir);
    staging.join(STAGING_MARKER).is_file()
        && !staging.join(APPLIED_SENTINEL).exists()
        && !staging_already_applied(&staging)
}

/// Leftovers of a restore that landed but whose staging could not be retired.
/// Nothing is waiting there, whatever the marker says.
fn staging_already_applied(staging: &Path) -> bool {
    read_apply_journal(staging).is_some_and(|journal| journal.applied)
}

/// The marker a completed staging run leaves behind, or `None` when there is
/// nothing trustworthy to apply. Written last by [`stage_restore`], so its
/// absence means the staging directory is incomplete.
fn read_pending_marker(staging: &Path) -> Option<PendingRestore> {
    if staging.join(APPLIED_SENTINEL).exists() {
        return None;
    }
    std::fs::read(staging.join(STAGING_MARKER))
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
}

/// What the next launch will apply, if anything. Without this the staging
/// directory is invisible: a user who declines the restart has no way to see
/// that a restore is still queued, and no way to change their mind.
#[derive(Serialize)]
pub struct PendingRestoreStatus {
    pub pending: bool,
    pub staged_at: i64,
    /// When a launch stops applying it and discards it instead; 0 when that
    /// does not apply (nothing staged, or a marker without a timestamp).
    pub expires_at: i64,
    pub app_version: String,
    pub files: usize,
}

/// The [`PendingRestoreStatus::expires_at`] for a restore staged at `staged_at`.
fn staged_restore_expires_at(staged_at: i64) -> i64 {
    if staged_at > 0 {
        staged_at.saturating_add(STAGED_RESTORE_MAX_AGE_SECS)
    } else {
        0
    }
}

#[tauri::command]
pub async fn pending_restore_status(app: tauri::AppHandle) -> Result<PendingRestoreStatus, String> {
    let data_dir = paths::resolve_data_dir_with_app(&app);
    let staging = staging_dir(&data_dir);
    let pending = read_pending_marker(&staging).filter(|_| !staging_already_applied(&staging));
    Ok(match pending {
        Some(p) => PendingRestoreStatus {
            pending: true,
            staged_at: p.staged_at,
            expires_at: staged_restore_expires_at(p.staged_at),
            app_version: p.source_app_version,
            files: p.files.len(),
        },
        None => PendingRestoreStatus {
            pending: false,
            staged_at: 0,
            expires_at: 0,
            app_version: String::new(),
            files: 0,
        },
    })
}

/// Throw away a staged restore. The staged copies are re-wrapped secrets and
/// database contents, so they are deleted rather than left lying around.
#[tauri::command]
pub async fn discard_pending_restore(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    // The import command writes into this same stable directory. Holding the
    // shared guard prevents a discard from deleting an import halfway through
    // staging and lets the next startup trust the marker's file set.
    let _restore_import_guard = state.restore_import_lock.lock().await;
    let staging = staging_dir(&paths::resolve_data_dir_with_app(&app));
    if !staging.exists() {
        return Ok(());
    }
    tokio::task::spawn_blocking(move || discard_staging(&staging))
        .await
        .map_err(|e| coded_ctx("backup_task_failed", "Restore task failed", e))?
}

fn discard_staging(staging: &Path) -> Result<(), String> {
    // A startup rollback that could not put everything back leaves files of
    // this restore live, listed only in the journal staging holds. They cannot
    // be swapped back under the running app, and discarding would leave the
    // profile mixed for good. The request is kept instead, so the next launch
    // finishes the rollback and drops the restore rather than applying it.
    if read_apply_journal(staging)
        .is_some_and(|journal| !journal.applied && !journal.entries.is_empty())
    {
        if let Err(e) = crate::security::atomic_write(&staging.join(DISCARD_REQUESTED), b"1", false)
        {
            tracing::warn!("Could not record the request to discard the staged restore: {e}");
        }
        return Err(coded_ctx(
            "backup_discard_failed",
            "Part of this restore is already in place",
            "restart Ember: it rolls the interrupted restore back and then discards it",
        ));
    }
    std::fs::remove_dir_all(staging).map_err(|e| {
        coded_ctx(
            "backup_discard_failed",
            "Failed to discard the staged restore",
            e,
        )
    })
}

#[tauri::command]
pub async fn preview_backup(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    passphrase: String,
) -> Result<BackupPreview, String> {
    let source = require_picked_backup(&state).await?;
    let data_dir = paths::resolve_data_dir_with_app(&app);
    let passphrase = Zeroizing::new(passphrase);

    tokio::task::spawn_blocking(move || {
        let scratch = temp_dir_in(&data_dir, "restore-tmp")?;
        // The scratch dir holds the decrypted archive, so it has to go even if
        // the preview unwinds.
        struct RemoveOnDrop<'a>(&'a Path);
        impl Drop for RemoveOnDrop<'_> {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(self.0);
            }
        }
        let _cleanup = RemoveOnDrop(&scratch);
        let result = (|| {
            let zip_path = scratch.join("payload.zip");
            decrypt_stream(&source, &zip_path, &passphrase)?;
            let manifest = read_manifest(&mut open_archive(&zip_path)?)?;
            // Report what a restore would actually apply. Listing an entry this
            // version discards would promise the user something the restore
            // then silently skips.
            let restorable = || {
                manifest
                    .files
                    .iter()
                    .filter(|f| !is_legacy_ignored(&f.name))
            };
            // Sizes are the manifest's word, not the archive's; a crafted one
            // must not be able to overflow the total.
            let total_bytes = restorable().fold(0u64, |total, f| total.saturating_add(f.size));
            let names: Vec<&str> = restorable().map(|f| f.name.as_str()).collect();
            Ok(BackupPreview {
                app_version: manifest.app_version.clone(),
                created_at: manifest.created_at,
                schema_version: manifest.schema_version,
                files: restorable().map(|f| f.name.clone()).collect(),
                total_bytes,
                includes_identity: manifest.files.iter().any(|f| f.name == "identity.json"),
                schema_too_new: manifest.schema_version
                    > crate::storage::database::MAX_SUPPORTED_SCHEMA_VERSION,
                missing: files_kept_from_profile(&names),
                chat_key_set_aside: restore_sets_aside_chat_key(&names),
            })
        })();
        result
    })
    .await
    .map_err(|e| coded_ctx("backup_task_failed", "Restore task failed", e))?
}

#[tauri::command]
pub async fn import_backup(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    passphrase: String,
) -> Result<RestoreSummary, String> {
    // `restore-pending` has a fixed name because startup must discover it
    // before the runtime state is initialized. Serialize the full staging
    // transaction so independent IPC calls cannot interleave files or delete
    // one another's incomplete directory.
    let _restore_import_guard = state.restore_import_lock.lock().await;
    let source = require_picked_backup(&state).await?;
    let data_dir = paths::resolve_data_dir_with_app(&app);
    let passphrase = Zeroizing::new(passphrase);

    let summary = tokio::task::spawn_blocking(move || {
        let staging = staging_dir(&data_dir);
        if staging.exists() {
            // Only a directory with a readable marker is a real pending
            // restore. Debris from an import that died mid-write would
            // otherwise block every later attempt until the app restarted,
            // and with a message claiming a restore was queued when none was.
            if read_pending_marker(&staging).is_some() && !staging_already_applied(&staging) {
                return Err(coded(
                    "backup_restore_pending",
                    "A restore is already waiting for the next restart",
                ));
            }
            tracing::warn!(
                "Clearing an incomplete staged restore at {}",
                staging.display()
            );
            std::fs::remove_dir_all(&staging).map_err(|e| {
                coded_ctx(
                    "backup_restore_failed",
                    "Failed to clear an incomplete staged restore",
                    e,
                )
            })?;
        }
        let scratch = temp_dir_in(&data_dir, "restore-tmp")?;
        let result = (|| {
            let zip_path = scratch.join("payload.zip");
            decrypt_stream(&source, &zip_path, &passphrase)?;
            stage_archive(&zip_path, &scratch, &staging)
        })();
        let _ = std::fs::remove_dir_all(&scratch);
        if result.is_err() {
            // A half-written staging directory must never be applied.
            let _ = std::fs::remove_dir_all(&staging);
        }
        result
    })
    .await
    .map_err(|e| coded_ctx("backup_task_failed", "Restore task failed", e))??;
    *state.picked_backup.lock().await = None;
    Ok(summary)
}

/// Write the restored files into the staging directory, re-wrapping secrets
/// for the account that will run the app after the restart.
fn stage_restore(
    staging: &Path,
    manifest: &Manifest,
    schema_version: i64,
    entries: Vec<UnpackedEntry>,
    webview_prefs: Option<&WebviewPrefs>,
) -> Result<RestoreSummary, String> {
    std::fs::create_dir_all(staging)
        .map_err(|e| coded_ctx("backup_restore_failed", "Failed to stage the restore", e))?;
    crate::security::restrict_file_permissions(staging);

    let mut staged = Vec::new();
    for entry in entries {
        let name = entry.spec.name;
        let stage_error = |e: std::io::Error| {
            coded_ctx(
                "backup_restore_failed",
                format!("Failed to stage {name}"),
                e,
            )
        };
        let target = staging.join(name);
        if entry.spec.secret {
            let plaintext = Zeroizing::new(std::fs::read(&entry.path).map_err(stage_error)?);
            // Bind the key material to this machine and account. A DPAPI
            // failure has to fail the restore: writing it in the clear would
            // leave the identity readable to anything that can read the file,
            // and `identity.protected` would then refuse the next launch.
            let payload = Zeroizing::new(secret_store::protect(&plaintext).map_err(|e| {
                coded_ctx(
                    "backup_restore_failed",
                    "Could not protect the restored key material",
                    e,
                )
            })?);
            crate::security::atomic_write(&target, &payload, true).map_err(stage_error)?;
        } else {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&entry.path)
                .and_then(|file| file.sync_all())
                .map_err(stage_error)?;
            if std::fs::rename(&entry.path, &target).is_err() {
                copy_into_place(&entry.path, &target).map_err(stage_error)?;
                crate::security::restrict_file_permissions(&target);
            }
        }
        staged.push(name.to_string());
    }

    if let Some(prefs) = webview_prefs {
        let bytes = serde_json::to_vec(prefs)
            .map_err(|e| coded_ctx("backup_restore_failed", "Failed to stage the restore", e))?;
        crate::security::atomic_write(&staging.join(WEBVIEW_PREFS_NAME), &bytes, true).map_err(
            |e| {
                coded_ctx(
                    "backup_restore_failed",
                    format!("Failed to stage {WEBVIEW_PREFS_NAME}"),
                    e,
                )
            },
        )?;
    }

    let pending = PendingRestore {
        version: FORMAT_VERSION,
        staged_at: chrono::Utc::now().timestamp(),
        source_app_version: manifest.app_version.clone(),
        schema_version,
        files: staged.clone(),
        webview_prefs: webview_prefs.is_some(),
    };
    let marker = serde_json::to_vec_pretty(&pending)
        .map_err(|e| coded_ctx("backup_restore_failed", "Failed to stage the restore", e))?;
    // Written last: its presence is what tells the next launch the staging
    // directory is complete and safe to apply.
    crate::security::atomic_write(&staging.join(STAGING_MARKER), &marker, true)
        .map_err(|e| coded_ctx("backup_restore_failed", "Failed to stage the restore", e))?;

    let staged_len = staged.len();
    let summary = RestoreSummary {
        missing: files_kept_from_profile(&staged),
        chat_key_set_aside: restore_sets_aside_chat_key(&staged),
        staged,
        app_version: manifest.app_version.clone(),
        created_at: manifest.created_at,
    };
    tracing::info!(
        "Staged {} files from a backup made by Ember {}; they will be applied on the next launch",
        staged_len,
        summary.app_version
    );
    Ok(summary)
}

/// Copy `staged` onto `live`, leaving the staged copy where it is.
///
/// Deliberately a copy rather than a rename. [`apply_pending_restore`] rolls
/// back the files that already landed when a later one fails, and keeps
/// `restore-pending/` so the next launch can retry — but a rename consumes the
/// staged copy, so the retry found those files gone, could not tell "rolled
/// back" from "already applied", skipped them, and reported success. The
/// profile was then left holding the machine's original of every rolled-back
/// file beside the backup's copy of the rest, which is precisely the mixed
/// state the rollback exists to prevent. Staging is removed only once the
/// whole set has landed.
///
/// Synced before returning, since staging is deleted once every copy has
/// returned and is then the only other copy of the restored bytes.
fn copy_into_place(staged: &Path, live: &Path) -> std::io::Result<()> {
    std::fs::copy(staged, live)?;
    std::fs::OpenOptions::new()
        .write(true)
        .open(live)?
        .sync_all()
}

/// Make the renames and new entries in `dir` durable.
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// What [`apply_pending_restore`] did with the staging directory.
#[derive(Debug)]
pub enum StartupRestore {
    /// Nothing was applied: none was staged, staging was unusable debris, or
    /// the restore was refused and left staged for a later launch.
    NotApplied,
    /// Applied, with the displaced originals kept in `pre-restore-*`.
    /// `download_folder_replaced` is the local folder that took the place of a
    /// restored download folder on a network share.
    Applied {
        download_folder_replaced: Option<String>,
    },
    /// Staged longer than [`STAGED_RESTORE_MAX_AGE_SECS`] ago, and discarded
    /// without being applied.
    Expired,
    /// Applied at an earlier launch, which could not retire the staged copies.
    /// The profile in use is the restored one, whatever is left on disk.
    AlreadyApplied,
}

/// Swap a staged restore into place. Called during startup before the
/// database, config or identity are opened, because every one of those files
/// is held open (or cached in memory) once the app is running.
///
/// Displaced originals are moved to `pre-restore-<timestamp>/` rather than
/// deleted: a restore from the wrong backup is otherwise unrecoverable. Only
/// files the backup actually carried are touched.
pub fn apply_pending_restore(data_dir: &Path) -> std::io::Result<StartupRestore> {
    let staging = staging_dir(data_dir);
    let marker = staging.join(STAGING_MARKER);
    if staging.join(APPLIED_SENTINEL).exists() {
        tracing::warn!(
            "Removing the staged copies of a restore that was already applied: {}",
            staging.display()
        );
        if let Err(e) = remove_applied_staging(&staging) {
            tracing::error!(
                "Could not remove {} ({e}); delete it by hand",
                staging.display()
            );
        }
        return Ok(StartupRestore::NotApplied);
    }
    // The user asked to discard this restore while part of it was in place.
    // Finish the rollback that left it so, then drop it; what still could not
    // be put back keeps staging, and the request, for the next launch.
    if staging.join(DISCARD_REQUESTED).exists() {
        if staging.join(APPLY_JOURNAL).exists() {
            abandon_interrupted_apply(data_dir, &staging);
        }
        if read_apply_journal(&staging).is_none_or(|journal| journal.entries.is_empty()) {
            tracing::warn!("Discarded the staged restore as asked, after rolling it back");
            let _ = std::fs::remove_dir_all(&staging);
        }
        return Ok(StartupRestore::NotApplied);
    }
    if !marker.is_file() {
        // No marker means either no restore or an interrupted staging run;
        // either way there is nothing trustworthy to apply.
        if staging.exists() {
            tracing::warn!(
                "Discarding an incomplete staged restore at {}",
                staging.display()
            );
            let _ = std::fs::remove_dir_all(&staging);
        }
        return Ok(StartupRestore::NotApplied);
    }
    let pending: PendingRestore = match read_pending_marker(&staging) {
        Some(p) => p,
        None => {
            tracing::warn!("Staged restore marker is unreadable; discarding the staged files");
            let _ = std::fs::remove_dir_all(&staging);
            return Ok(StartupRestore::NotApplied);
        }
    };

    // A marker without a timestamp (an older staging run) is not judged on age.
    // Nor is an apply that already started swapping: discarding staging would
    // take its journal with it and leave the profile half-restored.
    let resuming = staging.join(APPLY_JOURNAL).exists();
    let age_secs = chrono::Utc::now()
        .timestamp()
        .saturating_sub(pending.staged_at);
    if !resuming && pending.staged_at > 0 && age_secs > STAGED_RESTORE_MAX_AGE_SECS {
        tracing::error!(
            "Discarding a staged restore from a backup made by Ember {}: it was prepared {} days \
             ago and is too old to apply safely over the profile in use since. Import the backup \
             again from Settings > Backup if it is still what you want.",
            pending.source_app_version,
            age_secs / 86_400
        );
        let _ = std::fs::remove_dir_all(&staging);
        return Ok(StartupRestore::Expired);
    }

    // Finished at an earlier launch, which could not retire staging. The app
    // has run on the restored profile since, so applying it again would copy
    // the backup over that session and drop the live database's sidecars.
    if read_apply_journal(&staging).is_some_and(|journal| journal.applied) {
        tracing::warn!(
            "Removing the staged copies of a restore that was already applied: {}",
            staging.display()
        );
        retire_applied_staging(&staging);
        return Ok(StartupRestore::AlreadyApplied);
    }

    // Every refusal from here on leaves the restore staged for a later launch.
    // One that interrupts an apply already under way must roll it back first,
    // or the app starts on a mix of restored and original files.
    let refuse = || -> std::io::Result<StartupRestore> {
        if resuming {
            abandon_interrupted_apply(data_dir, &staging);
        }
        Ok(StartupRestore::NotApplied)
    };

    // The build that staged this restore accepted its schema; the build now
    // applying it may be an older one the user reinstalled in between.
    // Installing a database it cannot open would leave Ember unable to start at
    // all, so leave the restore staged: installing the newer build applies it,
    // and Settings > Backup can discard it.
    if pending.schema_version > crate::storage::database::MAX_SUPPORTED_SCHEMA_VERSION {
        tracing::error!(
            "Not applying the staged restore: its database is v{} and this build supports v{}. \
             It stays staged - install the newer Ember to apply it, or discard it from \
             Settings > Backup.",
            pending.schema_version,
            crate::storage::database::MAX_SUPPORTED_SCHEMA_VERSION
        );
        return refuse();
    }

    // Every file the marker lists has to be present before anything moves.
    //
    // The apply is all-or-nothing across *retries*, not only within one run: a
    // rollback leaves staging in place for the next launch, so a staged file
    // that has gone missing means this directory is no longer the complete
    // profile its marker claims. Pressing on past it is what silently produced
    // a half-restored profile — and reported success, because a skipped file
    // sets no failure. A profile staged by a build that consumed its staged
    // copies lands here too, and is refused rather than half-applied.
    let absent: Vec<&str> = pending
        .files
        .iter()
        .filter(|name| backup_file(name).is_some())
        .filter(|name| !staging.join(name.as_str()).is_file())
        .map(|name| name.as_str())
        .collect();
    if !absent.is_empty() {
        tracing::error!(
            "Not applying the staged restore: {} file(s) its marker lists are missing from {} \
             ({}). It stays staged - discard it from Settings > Backup and import again.",
            absent.len(),
            staging.display(),
            absent.join(", ")
        );
        return refuse();
    }

    // Room for the copies before any of them is attempted.
    //
    // `copy_into_place` keeps each staged file until the whole set has landed,
    // which is what makes a retry after a rollback start from a complete
    // profile — but it also means the staged set, the live copies and the
    // displaced originals all exist at once, where the previous rename
    // consumed staging as it went. On a nearly-full disk that turns a restore
    // that used to squeeze through into one that fails part-way. The rollback
    // handles that correctly now, but an upfront refusal that keeps staging
    // intact is a better answer than a mid-apply abort.
    if let Ok(free) = fs2::available_space(data_dir) {
        let journal = if resuming {
            read_apply_journal(&staging)
        } else {
            None
        };
        let needed = restore_space_needed(data_dir, &staging, &pending.files, journal.as_ref());
        if free < needed {
            tracing::error!(
                "Not applying the staged restore: it needs about {} MiB free in {} and only {} MiB \
                 is available. It stays staged - free some space and relaunch, or discard it from \
                 Settings > Backup.",
                needed / (1024 * 1024),
                data_dir.display(),
                free / (1024 * 1024)
            );
            return refuse();
        }
    }

    // Staging and its marker are deliberately left in place on failure: the
    // restore can then be retried on the next launch, or discarded from
    // Settings > Backup if the cause is permanent. Removing staging here is
    // what previously turned a mid-restore failure into an unrecoverable one.
    use crate::commands::transfers::OrphanDisposal;
    if let Err(e) = OrphanDisposal::record_database_replacement(data_dir) {
        tracing::warn!("Could not record that orphaned downloads are to be set aside: {e}");
    }
    let (backup_dir, outcome) =
        swap_in_staged_files(data_dir, &staging, &pending.files, copy_into_place)?;
    let applied = match outcome {
        Ok(applied) => applied,
        Err(reason) => {
            tracing::error!(
                "Staged restore aborted: {reason}. Rolled back the files already swapped; the \
                 staged copy is kept for the next launch and the previous files remain in {}",
                backup_dir.display()
            );
            return Ok(StartupRestore::NotApplied);
        }
    };

    // Before staging goes: while it exists a crash here re-runs the whole
    // apply, which ends up here again, and the repair is idempotent.
    let download_folder_replaced = if pending.files.iter().any(|name| name == "config.json") {
        sanitize_restored_config(data_dir)
    } else {
        None
    };
    hand_over_webview_prefs(data_dir, &staging, pending.webview_prefs);
    mark_apply_finished(&staging);
    retire_applied_staging(&staging);
    tracing::warn!(
        "Applied a staged restore of {applied} file(s) from a backup made by Ember {}; the \
         previous files are preserved in {}",
        pending.source_app_version,
        backup_dir.display()
    );
    Ok(StartupRestore::Applied {
        download_folder_replaced,
    })
}

/// Leave an applied restore's app-window preferences where
/// [`take_pending_restored_prefs`] finds them, replacing any an earlier
/// restore left untaken: those belong to the profile just replaced. Best
/// effort, because failing here must not undo a restore that has landed.
fn hand_over_webview_prefs(data_dir: &Path, staging: &Path, staged: bool) {
    let target = data_dir.join(RESTORED_PREFS_FILE);
    match std::fs::remove_file(&target) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::error!(
                "Could not remove the untaken preferences of an earlier restore ({e}); not \
                 handing over this restore's"
            );
            return;
        }
    }
    if !staged {
        return;
    }
    let Some(prefs) = std::fs::read(staging.join(WEBVIEW_PREFS_NAME))
        .ok()
        .and_then(|raw| parse_webview_prefs(&raw))
    else {
        tracing::warn!("The restored app preferences are missing or unreadable; skipping them");
        return;
    };
    let written = serde_json::to_vec(&prefs)
        .map_err(std::io::Error::other)
        .and_then(|bytes| crate::security::atomic_write(&target, &bytes, true));
    if let Err(e) = written {
        tracing::warn!("Could not hand the restored app preferences to the window: {e}");
    }
}

/// Consume the preferences [`hand_over_webview_prefs`] left. Removed before
/// they are returned, and withheld if removal fails: the window reloads after
/// applying them, so a file that survived would reapply them on every start.
fn take_restored_prefs(data_dir: &Path) -> Option<WebviewPrefs> {
    let path = data_dir.join(RESTORED_PREFS_FILE);
    let raw = match std::fs::read(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!("Could not read the restored app preferences: {e}");
            return None;
        }
    };
    if let Err(e) = std::fs::remove_file(&path) {
        tracing::error!(
            "Could not remove {} ({e}); not applying the restored app preferences",
            path.display()
        );
        return None;
    }
    let prefs = parse_webview_prefs(&raw);
    if prefs.is_none() {
        tracing::warn!("The restored app preferences are unreadable; skipping them");
    }
    prefs
}

/// The app-window preferences a restore applied at this launch brought back,
/// once; `None` on every later call and when there were none.
#[tauri::command]
pub async fn take_pending_restored_prefs(
    app: tauri::AppHandle,
) -> Result<Option<WebviewPrefs>, String> {
    let data_dir = paths::resolve_data_dir_with_app(&app);
    tokio::task::spawn_blocking(move || take_restored_prefs(&data_dir))
        .await
        .map_err(|e| coded_ctx("backup_task_failed", "Restore task failed", e))
}

/// A live file the apply loop has touched, and what it takes to undo that.
#[derive(Clone, Serialize, Deserialize)]
struct Swapped {
    name: String,
    /// Whether a live original was moved into the pre-restore directory. When
    /// there was none, undoing the swap means removing the restored copy.
    displaced: bool,
    /// Sidecars (`ember.db-wal`, `ember.db-shm`) stashed beside the original.
    /// They belong to it and go back only if it does.
    sidecars: Vec<String>,
    /// Set once the live database's sidecars have all been moved aside. After
    /// that, a sidecar found live on a retry was written against a restored
    /// copy, not the original.
    #[serde(default)]
    sidecars_done: bool,
    /// Sidecars a rollback could not return or move aside. The database has
    /// been used without them since, so they must never go back beside it.
    #[serde(default)]
    stranded: Vec<String>,
    /// [`ApplyJournal::attempt`] that last touched this entry.
    #[serde(default)]
    attempt: u32,
    /// What the copy left live, so a later attempt can tell its own copy from
    /// a file the app created or changed after an attempt returned.
    #[serde(default)]
    copied: Option<FileFingerprint>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct FileFingerprint {
    len: u64,
    modified_ns: u64,
}

impl FileFingerprint {
    fn of(path: &Path) -> Option<Self> {
        let meta = std::fs::symlink_metadata(path).ok()?;
        let modified = meta
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        Some(Self {
            len: meta.len(),
            modified_ns: u64::try_from(modified.as_nanos()).ok()?,
        })
    }
}

/// On-disk progress of an apply, kept in staging beside the marker.
///
/// A crash mid-apply must not let the retry mistake a restored or half-copied
/// file for the user's original: moving it aside as the "original" strands the
/// real one, and rolling a failed retry back would then restore the wrong
/// bytes. So every attempt reuses the one pre-restore folder named here, and a
/// file present in that folder is an original an earlier attempt moved aside,
/// whatever sits live now. The entries add what the folder cannot show: which
/// files had no original at all (so a live copy is ours to overwrite or
/// delete), and whether the database's sidecars were already dealt with.
///
/// The apply runs at startup before anything else opens these files, so an
/// attempt that is still `in_progress` when the journal is next read crashed,
/// and nothing has touched the profile since. Once an attempt has returned,
/// the app may have run, and live files may be the user's again.
#[derive(Serialize, Deserialize)]
struct ApplyJournal {
    /// Name of the pre-restore folder under the data directory.
    backup_dir: String,
    #[serde(default)]
    attempt: u32,
    #[serde(default)]
    in_progress: bool,
    /// Every file landed. Recorded before staging is retired, so a staging
    /// folder that survives retirement is never applied over the profile again.
    #[serde(default)]
    applied: bool,
    entries: Vec<Swapped>,
}

impl ApplyJournal {
    /// Whether the live copy of an entry with no original is this apply's own
    /// work, safe to overwrite or delete without preserving it.
    fn live_is_ours(&self, entry: &Swapped, live: &Path, crashed_attempt: Option<u32>) -> bool {
        crashed_attempt == Some(entry.attempt)
            || entry
                .copied
                .is_some_and(|fp| FileFingerprint::of(live) == Some(fp))
    }
}

/// Like `Path::exists`, but an error other than "not found" is an error
/// rather than a no. Taking a permission or sharing failure for absence would
/// skip preserving the original and then copy over it.
fn path_exists(path: &Path) -> std::io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn read_apply_journal(staging: &Path) -> Option<ApplyJournal> {
    std::fs::read(staging.join(APPLY_JOURNAL))
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
}

/// Free space the rest of the apply needs: one further copy of every staged
/// file that has not already landed, plus a margin for the database's WAL and
/// SHM sidecars. The originals are moved aside rather than copied.
///
/// Files an interrupted attempt already copied are not counted: their space is
/// already spent, and counting it again would refuse every later launch the
/// resume that has to finish or roll back.
fn restore_space_needed(
    data_dir: &Path,
    staging: &Path,
    files: &[String],
    journal: Option<&ApplyJournal>,
) -> u64 {
    let landed = |name: &str| {
        journal.is_some_and(|journal| {
            journal.entries.iter().any(|entry| {
                entry.name == name
                    && entry
                        .copied
                        .is_some_and(|fp| FileFingerprint::of(&data_dir.join(name)) == Some(fp))
            })
        })
    };
    let staged_bytes: u64 = files
        .iter()
        .filter(|name| !landed(name))
        .filter_map(|name| std::fs::metadata(staging.join(name)).ok())
        .map(|meta| meta.len())
        .sum();
    staged_bytes.saturating_add(staged_bytes / 4)
}

fn write_apply_journal(staging: &Path, journal: &ApplyJournal) -> std::io::Result<()> {
    let data = serde_json::to_vec_pretty(journal).map_err(std::io::Error::other)?;
    crate::security::atomic_write(&staging.join(APPLY_JOURNAL), &data, true)
}

/// The journal of an apply already under way, or a new one naming a fresh
/// pre-restore folder, on disk before anything is moved.
fn open_apply_journal(data_dir: &Path, staging: &Path) -> std::io::Result<(PathBuf, ApplyJournal)> {
    let invalid = |msg: String| std::io::Error::new(std::io::ErrorKind::InvalidData, msg);
    match std::fs::read(staging.join(APPLY_JOURNAL)) {
        Ok(raw) => {
            let journal: ApplyJournal = serde_json::from_slice(&raw).map_err(|e| {
                invalid(format!("the restore progress journal is unreadable ({e})"))
            })?;
            let mut components = Path::new(&journal.backup_dir).components();
            let plain = matches!(
                (components.next(), components.next()),
                (Some(std::path::Component::Normal(_)), None)
            );
            if !plain || !journal.backup_dir.starts_with(BACKUP_DIR_PREFIX) {
                return Err(invalid(format!(
                    "the restore progress journal names an invalid folder {:?}",
                    journal.backup_dir
                )));
            }
            let dir = data_dir.join(&journal.backup_dir);
            std::fs::create_dir_all(&dir)?;
            Ok((dir, journal))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let stamp = chrono::Utc::now().timestamp();
            let mut attempt = 0u32;
            let (name, dir) = loop {
                let name = match attempt {
                    0 => format!("{BACKUP_DIR_PREFIX}{stamp}"),
                    n => format!("{BACKUP_DIR_PREFIX}{stamp}-{n}"),
                };
                let dir = data_dir.join(&name);
                // Must be new: anything already in it would read as an
                // original this apply had moved aside.
                match std::fs::create_dir(&dir) {
                    Ok(()) => break (name, dir),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt < 1000 => {
                        attempt += 1;
                    }
                    Err(e) => return Err(e),
                }
            };
            crate::security::restrict_file_permissions(&dir);
            let journal = ApplyJournal {
                backup_dir: name,
                attempt: 0,
                in_progress: false,
                applied: false,
                entries: Vec::new(),
            };
            write_apply_journal(staging, &journal)?;
            Ok((dir, journal))
        }
        Err(e) => Err(e),
    }
}

/// Move a stashed sidecar that must never go back beside its database to a
/// name nothing else uses, keeping it for manual recovery. Never replaces an
/// earlier orphan.
fn orphan_sidecar(backup_dir: &Path, sidecar: &str) -> std::io::Result<PathBuf> {
    for n in 1..=1000u32 {
        let target = backup_dir.join(format!("{sidecar}.orphaned-{n}"));
        if !path_exists(&target)? {
            std::fs::rename(backup_dir.join(sidecar), &target)?;
            return Ok(target);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("no free orphan name for {sidecar}"),
    ))
}

/// Drop entries whose original is already back in place — a rollback that
/// was cut short, or whose journal update was lost.
///
/// Sidecars that rollback had not reached go back only when that rollback
/// belonged to the attempt that crashed: then nothing has opened the database
/// since. Otherwise the app has been using it without them, and replaying them
/// now would corrupt it, so they are set aside instead.
fn settle_rolled_back_entries(
    data_dir: &Path,
    backup_dir: &Path,
    journal: &mut ApplyJournal,
    crashed_attempt: Option<u32>,
) {
    journal.entries.retain(|entry| {
        if !entry.displaced || path_exists(&backup_dir.join(&entry.name)).unwrap_or(true) {
            return true;
        }
        let may_return = crashed_attempt == Some(entry.attempt);
        for sidecar in entry.sidecars.iter().chain(&entry.stranded) {
            let stashed = backup_dir.join(sidecar);
            if !stashed.exists() {
                continue;
            }
            let live = data_dir.join(sidecar);
            if may_return && !entry.stranded.contains(sidecar) && !live.exists() {
                if let Err(e) = std::fs::rename(&stashed, &live) {
                    tracing::error!(
                        "Could not return {sidecar} ({e}); recover it from {}",
                        backup_dir.display()
                    );
                }
            } else if let Err(e) = orphan_sidecar(backup_dir, sidecar) {
                tracing::error!(
                    "Could not set aside the stale {sidecar} in {} ({e})",
                    backup_dir.display()
                );
            }
        }
        false
    });
}

/// Move the live original aside unless an earlier attempt already did.
/// Returns whether an original is in the backup folder, and whether this call
/// is what put it there.
fn displace_original(
    live: &Path,
    stashed: &Path,
    live_is_restored: bool,
) -> std::io::Result<(bool, bool)> {
    if path_exists(stashed)? {
        return Ok((true, false));
    }
    if live_is_restored || !path_exists(live)? {
        return Ok((false, false));
    }
    std::fs::rename(live, stashed)?;
    Ok((true, true))
}

/// Move the database's WAL/SHM sidecars out of the way of the restored copy.
///
/// The restored database is a `VACUUM INTO` snapshot with no write-ahead log.
/// Leaving the previous sidecars in place would have SQLite replay an
/// unrelated log over it. Nor may they be deleted: nothing checkpoints at
/// shutdown, so the WAL can hold the most recent commits of the database it
/// was moved aside with.
///
/// `fresh` means the live sidecars (if any) still belong to the original;
/// `moved_now` means the original was moved aside by this attempt.
fn stash_database_sidecars(
    data_dir: &Path,
    backup_dir: &Path,
    entry: &mut Swapped,
    fresh: bool,
    moved_now: bool,
) -> std::io::Result<()> {
    for suffix in ["-wal", "-shm"] {
        let sidecar_name = format!("{}{suffix}", entry.name);
        let live = data_dir.join(&sidecar_name);
        let stashed = backup_dir.join(&sidecar_name);
        if !fresh {
            // Written against a restored copy that is about to be replaced.
            if path_exists(&live)? {
                std::fs::remove_file(&live)?;
            }
            continue;
        }
        if moved_now && path_exists(&stashed)? {
            // Left by an earlier rollback that could not return it. The
            // database has been used without it since, so it must never go
            // back beside it — and must not be overwritten by the live one.
            orphan_sidecar(backup_dir, &sidecar_name)?;
            entry.sidecars.retain(|s| s != &sidecar_name);
            entry.stranded.retain(|s| s != &sidecar_name);
        }
        if path_exists(&live)? {
            std::fs::rename(&live, &stashed)?;
            if !entry.sidecars.contains(&sidecar_name) {
                entry.sidecars.push(sidecar_name);
            }
        } else if path_exists(&stashed)?
            && !entry.sidecars.contains(&sidecar_name)
            && !entry.stranded.contains(&sidecar_name)
        {
            entry.sidecars.push(sidecar_name);
        }
    }
    Ok(())
}

/// Copy every staged file over its live counterpart, moving originals into
/// the pre-restore folder. All or nothing: on any failure everything touched
/// so far — by this attempt or an earlier one that crashed — is put back.
/// Returns the pre-restore folder, and how many files were applied or why the
/// apply was rolled back. An `Err` means the progress journal could not be
/// read or started, and nothing was moved.
///
/// Applying per-file and pressing on left the profile holding a mix of
/// restored and original files — a restored `identity.json` beside the
/// original `ember.db` orphans exactly the credits this feature exists to
/// carry over.
fn swap_in_staged_files(
    data_dir: &Path,
    staging: &Path,
    files: &[String],
    mut copy: impl FnMut(&Path, &Path) -> std::io::Result<()>,
) -> std::io::Result<(PathBuf, Result<usize, String>)> {
    let (backup_dir, mut journal) = open_apply_journal(data_dir, staging)?;
    let crashed_attempt = journal.in_progress.then_some(journal.attempt);
    settle_rolled_back_entries(data_dir, &backup_dir, &mut journal, crashed_attempt);
    journal.attempt = journal.attempt.wrapping_add(1);
    journal.in_progress = true;
    let mut applied = 0usize;
    let mut failure: Option<String> = None;
    // Moved aside like an original, with nothing copied in its place.
    let set_aside = restore_sets_aside_chat_key(files).then_some(CHAT_KEY_FILE);
    for name in files.iter().map(String::as_str).chain(set_aside) {
        let copied_in = set_aside != Some(name);
        if backup_file(name).is_none() {
            tracing::warn!("Ignoring unexpected staged file {name}");
            continue;
        }
        let staged = staging.join(name);
        if copied_in && !staged.is_file() {
            // Checked before the loop, so this is a file that vanished under
            // us mid-apply. A failure rather than a skip, for the reason the
            // pre-flight gives.
            failure = Some(format!(
                "the staged {name} disappeared before it was applied"
            ));
            break;
        }
        let live = data_dir.join(name);
        let prior = journal.entries.iter().position(|e| e.name == name);
        // Anything else live is an original — possibly one the app created
        // after an earlier attempt rolled back — and is preserved like one.
        let live_is_restored = prior.is_some_and(|i| {
            let entry = &journal.entries[i];
            !entry.displaced && journal.live_is_ours(entry, &live, crashed_attempt)
        });
        let (displaced, moved_now) =
            match displace_original(&live, &backup_dir.join(name), live_is_restored) {
                Ok(outcome) => outcome,
                Err(e) => {
                    failure = Some(format!("could not move the current {name} aside ({e})"));
                    break;
                }
            };
        if !copied_in && !displaced {
            continue;
        }
        let index = match prior {
            Some(i) => {
                let entry = &mut journal.entries[i];
                entry.displaced = displaced;
                entry.attempt = journal.attempt;
                entry.copied = None;
                i
            }
            None => {
                journal.entries.push(Swapped {
                    name: name.to_string(),
                    displaced,
                    sidecars: Vec::new(),
                    sidecars_done: false,
                    stranded: Vec::new(),
                    attempt: journal.attempt,
                    copied: None,
                });
                journal.entries.len() - 1
            }
        };
        if name == "ember.db" {
            let entry = &mut journal.entries[index];
            let fresh = moved_now || !entry.sidecars_done;
            if let Err(e) = stash_database_sidecars(data_dir, &backup_dir, entry, fresh, moved_now)
            {
                failure = Some(format!(
                    "could not move the current database sidecars aside ({e})"
                ));
                break;
            }
            entry.sidecars_done = true;
        }
        // Recorded before the copy, so a copy that fails part-way, or a crash
        // during it, leaves a file that is undone rather than taken for the
        // original on the next attempt.
        if let Err(e) = write_apply_journal(staging, &journal) {
            failure = Some(format!("could not record the restore's progress ({e})"));
            break;
        }
        if !copied_in {
            continue;
        }
        match copy(&staged, &live) {
            Ok(()) => {
                crate::security::restrict_file_permissions(&live);
                journal.entries[index].copied = FileFingerprint::of(&live);
                applied += 1;
            }
            Err(e) => {
                tracing::error!("Failed to restore {name}: {e}");
                failure = Some(format!("could not put the restored {name} in place ({e})"));
                break;
            }
        }
    }

    let Some(reason) = failure else {
        for dir in [data_dir, backup_dir.as_path()] {
            if let Err(e) = sync_dir(dir) {
                tracing::warn!("Could not flush {} after the restore ({e})", dir.display());
            }
        }
        // Left in progress: the apply is done only once the config repair and
        // the preference hand-over have run (`mark_apply_finished`). A crash
        // before then re-runs the whole apply, which is safe while the app has
        // not yet run on the restored files.
        return Ok((backup_dir, Ok(applied)));
    };
    roll_back_journal(data_dir, staging, &backup_dir, &mut journal);
    Ok((backup_dir, Err(reason)))
}

/// Record in the journal that the restore has landed and been repaired. From
/// here on the app runs on the restored files, so a later launch that finds
/// staging still there must only retire it, never apply it again.
fn mark_apply_finished(staging: &Path) {
    let Some(mut journal) = read_apply_journal(staging) else {
        return;
    };
    journal.in_progress = false;
    journal.applied = true;
    if let Err(e) = write_apply_journal(staging, &journal) {
        tracing::error!(
            "Could not record that the restore finished ({e}); only retiring its staging \
             keeps the next launch from applying it again"
        );
    }
}

/// Put back everything the journal lists, newest first, so the profile goes
/// back to being internally consistent rather than a mix of two backups.
/// Entries that could not be put back stay in the journal for the next
/// attempt, which is recorded as having returned.
fn roll_back_journal(
    data_dir: &Path,
    staging: &Path,
    backup_dir: &Path,
    journal: &mut ApplyJournal,
) {
    let mut unresolved = Vec::new();
    for mut entry in std::mem::take(&mut journal.entries).into_iter().rev() {
        if !roll_back_swap(data_dir, backup_dir, &mut entry) {
            unresolved.push(entry);
        }
    }
    unresolved.reverse();
    journal.entries = unresolved;
    journal.in_progress = false;
    if let Err(e) = write_apply_journal(staging, journal) {
        tracing::error!("Could not record the rollback of the staged restore ({e})");
        if journal.entries.is_empty() {
            let _ = std::fs::remove_file(staging.join(APPLY_JOURNAL));
        }
    }
}

/// Roll back an apply that crashed part-way and that this launch is not going
/// to resume, so the app never starts on a mix of restored and original files.
fn abandon_interrupted_apply(data_dir: &Path, staging: &Path) {
    let (backup_dir, mut journal) = match open_apply_journal(data_dir, staging) {
        Ok(opened) => opened,
        Err(e) => {
            tracing::error!(
                "Could not read the progress of the interrupted restore ({e}); the profile may \
                 hold a mix of restored and original files"
            );
            return;
        }
    };
    let crashed_attempt = journal.in_progress.then_some(journal.attempt);
    settle_rolled_back_entries(data_dir, &backup_dir, &mut journal, crashed_attempt);
    roll_back_journal(data_dir, staging, &backup_dir, &mut journal);
    tracing::error!(
        "Rolled back the interrupted restore; the previous files remain in {}",
        backup_dir.display()
    );
}

/// Undo one swap. Returns whether everything it touched is back in place.
fn roll_back_swap(data_dir: &Path, backup_dir: &Path, entry: &mut Swapped) -> bool {
    let name = &entry.name;
    let live = data_dir.join(name);
    let original_back = if entry.displaced {
        // No `remove_file` first: `fs::rename` already replaces the
        // destination on every platform we ship, and deleting ahead of it
        // opened a window where a rename that then failed left the profile
        // with no copy of the file at all — for `identity.json` that means the
        // next launch quietly generates a new identity.
        match std::fs::rename(backup_dir.join(name), &live) {
            Ok(()) => true,
            Err(e) => {
                tracing::error!(
                    "Rollback failed for {name} ({e}); recover it from {}",
                    backup_dir.display()
                );
                false
            }
        }
    } else {
        // There was no original, so the backup's copy is the only thing to
        // undo. Staging still holds it for a retry.
        match std::fs::remove_file(&live) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(e) => {
                tracing::error!(
                    "Rollback could not remove the restored {name} ({e}); delete it by hand \
                     before relaunching"
                );
                false
            }
        }
    };
    if !entry.displaced {
        // Sidecars stashed with no original database beside them were orphans;
        // putting them back would have SQLite replay them into whatever
        // database is created there next.
        return original_back;
    }
    if !original_back {
        if !entry.sidecars.is_empty() {
            // Replaying the old log over whatever still sits at `live` would
            // corrupt it; the sidecars stay with the original they belong to.
            tracing::error!(
                "Left the {name} sidecars in {} beside the {name} they belong to",
                backup_dir.display()
            );
        }
        return false;
    }
    let mut complete = true;
    for sidecar in entry.sidecars.clone() {
        let stashed = backup_dir.join(&sidecar);
        if !stashed.exists() {
            continue;
        }
        let Err(e) = std::fs::rename(&stashed, data_dir.join(&sidecar)) else {
            continue;
        };
        // The database is back and about to be opened without this sidecar,
        // so the stashed one can never be returned later.
        match orphan_sidecar(backup_dir, &sidecar) {
            Ok(orphan) => tracing::error!(
                "Could not return {sidecar} ({e}); the database is back without it, and it is \
                 kept at {}",
                orphan.display()
            ),
            Err(orphan_error) => {
                tracing::error!(
                    "Could not return {sidecar} ({e}) or set it aside ({orphan_error}); it stays \
                     in {} and will not be returned",
                    backup_dir.display()
                );
                if !entry.stranded.contains(&sidecar) {
                    entry.stranded.push(sidecar);
                }
                complete = false;
            }
        }
    }
    complete
}

/// Make sure a restore that has been applied is never applied again.
///
/// The staged files are copied into place, not consumed, so a staging folder
/// that survives with its marker would re-apply the backup on the next launch
/// over everything done since. The marker goes first and its removal is
/// checked; only then is the rest of the folder cleaned up.
fn retire_applied_staging(staging: &Path) {
    if !mark_restore_applied(staging) {
        let aside = staging.with_file_name(format!(
            "{STAGING_DIR}-applied-{}",
            chrono::Utc::now().timestamp()
        ));
        match std::fs::rename(staging, &aside) {
            Ok(()) => {
                if let Err(e) = std::fs::remove_dir_all(&aside) {
                    tracing::warn!(
                        "Could not remove {} ({e}); delete it by hand",
                        aside.display()
                    );
                }
            }
            Err(e) => tracing::error!(
                "Could not retire the applied restore at {} ({e}). Delete that folder by hand; \
                 if its progress journal was not recorded either, the next launch applies it \
                 AGAIN.",
                staging.display()
            ),
        }
        return;
    }
    if let Err(e) = remove_applied_staging(staging) {
        tracing::warn!(
            "Could not remove the applied restore's staged copies at {} ({e}); they are \
             discarded on the next launch",
            staging.display()
        );
    }
}

/// Delete an applied restore's staging folder in the one order that is safe
/// to interrupt: the marker first, then everything else, and the
/// [`APPLIED_SENTINEL`] last. A sweep in arbitrary order can take the sentinel
/// while the marker it stands in for survives, and the restore then reads as
/// pending again. Stops at the first failure to remove the marker.
fn remove_applied_staging(staging: &Path) -> std::io::Result<()> {
    let ignore_missing = |result: std::io::Result<()>| match result {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    };
    ignore_missing(std::fs::remove_file(staging.join(STAGING_MARKER)))?;
    let mut first_error = None;
    for entry in std::fs::read_dir(staging)? {
        let path = entry?.path();
        if path.file_name().and_then(|n| n.to_str()) == Some(APPLIED_SENTINEL) {
            continue;
        }
        let removed = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        if let Err(e) = ignore_missing(removed) {
            first_error.get_or_insert(e);
        }
    }
    if let Some(e) = first_error {
        return Err(e);
    }
    ignore_missing(std::fs::remove_file(staging.join(APPLIED_SENTINEL)))?;
    ignore_missing(std::fs::remove_dir(staging))
}

/// Remove the marker, or failing that leave [`APPLIED_SENTINEL`]. Returns
/// whether the next launch is now certain not to apply the staging again.
fn mark_restore_applied(staging: &Path) -> bool {
    match std::fs::remove_file(staging.join(STAGING_MARKER)) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(e) => {
            tracing::error!(
                "Could not remove the marker of the applied restore ({e}); marking it applied instead"
            );
            match crate::security::atomic_write(&staging.join(APPLIED_SENTINEL), b"applied\n", true)
            {
                Ok(()) => true,
                Err(e) => {
                    tracing::error!("Could not mark the applied restore as applied ({e})");
                    false
                }
            }
        }
    }
}

/// Repair paths in a restored config that only made sense on the machine the
/// backup came from.
///
/// Startup creates the download folder and refuses to continue if it cannot,
/// so a backup taken on a machine that downloaded to a second drive would
/// otherwise leave Ember unable to launch at all on a machine without that
/// drive, on the very path this feature exists to serve.
///
/// The media player is always cleared. A download folder that cannot be
/// created, or is on a network share, is replaced by the local default, and
/// every folder on a network share is dropped. Other shared folders are left
/// alone, missing or not: a restore does not approve them (see `run`), so
/// nothing in them is shared until the user re-approves them in the Library,
/// and dropping the missing ones here would silently delete a user's shares
/// whenever they restored with an external drive unplugged.
///
/// Returns the folder that replaced a download folder on a network share, for
/// the notice telling the user to choose theirs again.
///
/// Edited as raw JSON on purpose: this runs before the config is loaded, and
/// round-tripping it through AppSettings here would rewrite fields the
/// loader's own repair pass owns.
fn sanitize_restored_config(data_dir: &Path) -> Option<String> {
    let path = data_dir.join("config.json");
    let raw = std::fs::read(&path).ok()?;
    let mut value = serde_json::from_slice::<serde_json::Value>(&raw).ok()?;
    let obj = value.as_object_mut()?;
    let mut changed = false;
    let mut replaced_share = None;

    // A program Ember will execute. Settings only accepts one the native
    // picker produced this session; an archive is not that, and one carried
    // over from another machine names a binary that may not exist here or may
    // be anything at all once decrypted with a passphrase the attacker chose.
    if obj
        .get("preview_player")
        .and_then(|v| v.as_str())
        .is_some_and(|player| !player.is_empty())
    {
        tracing::warn!(
            "Cleared the media player from the restored config; choose it again in Settings"
        );
        obj.insert(
            "preview_player".to_string(),
            serde_json::Value::String(String::new()),
        );
        changed = true;
    }

    if let Some(folder) = obj
        .get("download_folder")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
    {
        // A share is not kept either: startup approves the restored download
        // folders and opens them, and touching a share connects to its server
        // and offers it the user's credentials, which an archive is not to
        // bring about. The user picks it again in Settings if it was theirs.
        let on_share = crate::security::is_network_path(&folder);
        if !folder.is_empty()
            && (on_share || std::fs::create_dir_all(Path::new(&folder)).is_err())
        {
            let fallback = directories::UserDirs::new()
                .and_then(|dirs| dirs.download_dir().map(|d| d.join("Ember")))
                .unwrap_or_else(|| data_dir.join("Downloads"));
            tracing::warn!(
                "Restored download folder {folder} {} on this machine; using {} instead",
                if on_share { "is on a network share, which a restore does not open" } else { "cannot be created" },
                fallback.display()
            );
            let _ = std::fs::create_dir_all(&fallback);
            let fallback = fallback.to_string_lossy().to_string();
            if on_share {
                replaced_share = Some(fallback.clone());
            }
            obj.insert(
                "download_folder".to_string(),
                serde_json::Value::String(fallback),
            );
            changed = true;
        }
    }

    // The earlier download folders are approved and swept at startup too, and
    // a shared folder without an approval on this machine is still looked at
    // to offer re-approving it.
    for (key, what) in [
        ("previous_download_folders", "earlier download folder(s)"),
        ("shared_folders", "shared folder(s)"),
    ] {
        let Some(folders) = obj.get_mut(key).and_then(|v| v.as_array_mut()) else {
            continue;
        };
        let before = folders.len();
        folders.retain(|folder| {
            !folder
                .as_str()
                .is_some_and(crate::security::is_network_path)
        });
        if folders.len() != before {
            tracing::warn!(
                "Dropped {} {what} on a network share from the restored config",
                before - folders.len()
            );
            changed = true;
        }
    }

    if !changed {
        return None;
    }
    match serde_json::to_vec_pretty(&value) {
        Ok(data) => {
            if let Err(e) = crate::security::atomic_write(&path, &data, true) {
                tracing::error!("Failed to write the repaired config after a restore: {e}");
                return None;
            }
        }
        Err(e) => {
            tracing::error!("Failed to serialize the repaired config after a restore: {e}");
            return None;
        }
    }
    replaced_share
}

#[cfg(test)]
mod tests {
    use super::*;

    impl StartupRestore {
        fn applied(&self) -> bool {
            matches!(self, StartupRestore::Applied { .. })
        }
    }

    /// Apply as startup does, insist that it applied, and return the
    /// pre-restore directory holding the displaced originals.
    fn apply_expecting_success(dir: &Path) -> PathBuf {
        let outcome = apply_pending_restore(dir).unwrap();
        assert!(outcome.applied(), "{outcome:?}");
        assert!(
            dir.join("set-aside-orphans").exists(),
            "orphaned downloads are set aside from the moment the database is replaced"
        );
        let mut backup_dirs = pre_restore_dirs(dir);
        assert_eq!(backup_dirs.len(), 1, "{backup_dirs:?}");
        backup_dirs.pop().unwrap()
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ember-backup-test-{tag}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn encrypt_bytes(dir: &Path, plaintext: &[u8], passphrase: &str) -> PathBuf {
        let plain_path = dir.join("plain.bin");
        std::fs::write(&plain_path, plaintext).unwrap();
        let mut plain = std::fs::File::open(&plain_path).unwrap();
        let dest = dir.join("out.emberbackup");
        encrypt_stream(&mut plain, &dest, passphrase).unwrap();
        dest
    }

    fn roundtrip(plaintext: &[u8]) {
        let dir = scratch("roundtrip");
        let dest = encrypt_bytes(&dir, plaintext, "correct horse battery");
        let back = dir.join("back.bin");
        decrypt_stream(&dest, &back, "correct horse battery").unwrap();
        assert_eq!(std::fs::read(&back).unwrap(), plaintext);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn roundtrips_an_empty_payload() {
        roundtrip(b"");
    }

    #[test]
    fn roundtrips_a_payload_spanning_several_chunks() {
        // Exactly two chunks plus a byte, so both the "a full read is not EOF"
        // and final-chunk paths run.
        let mut data = vec![0u8; CHUNK_SIZE * 2 + 1];
        OsRng.fill_bytes(&mut data);
        roundtrip(&data);
    }

    #[test]
    fn wrong_passphrase_is_reported_as_such() {
        let dir = scratch("wrongpass");
        let dest = encrypt_bytes(&dir, b"secrets", "the right passphrase");
        let err = decrypt_stream(&dest, &dir.join("back.bin"), "the wrong passphrase").unwrap_err();
        assert!(err.contains("backup_wrong_passphrase"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncation_is_detected() {
        let dir = scratch("truncated");
        let dest = encrypt_bytes(&dir, b"a payload worth keeping", "correct horse battery");
        let raw = std::fs::read(&dest).unwrap();
        std::fs::write(&dest, &raw[..raw.len() - 4]).unwrap();
        let err =
            decrypt_stream(&dest, &dir.join("back.bin"), "correct horse battery").unwrap_err();
        assert!(err.contains("backup_corrupt_archive"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn appended_bytes_are_rejected() {
        let dir = scratch("appended");
        let dest = encrypt_bytes(&dir, b"a payload worth keeping", "correct horse battery");
        let mut raw = std::fs::read(&dest).unwrap();
        raw.extend_from_slice(b"extra");
        std::fs::write(&dest, &raw).unwrap();
        let err =
            decrypt_stream(&dest, &dir.join("back.bin"), "correct horse battery").unwrap_err();
        assert!(err.contains("backup_corrupt_archive"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_header_does_not_decrypt() {
        let dir = scratch("header");
        let dest = encrypt_bytes(&dir, b"payload", "correct horse battery");
        let mut raw = std::fs::read(&dest).unwrap();
        // Flip a byte inside the header JSON (after magic + length prefix).
        raw[20] ^= 0x01;
        std::fs::write(&dest, &raw).unwrap();
        let err =
            decrypt_stream(&dest, &dir.join("back.bin"), "correct horse battery").unwrap_err();
        assert!(!err.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_foreign_file_is_not_mistaken_for_a_backup() {
        let dir = scratch("foreign");
        let path = dir.join("random.emberbackup");
        std::fs::write(&path, b"this is not an Ember backup at all").unwrap();
        let err =
            decrypt_stream(&path, &dir.join("back.bin"), "correct horse battery").unwrap_err();
        assert!(err.contains("backup_not_an_ember_backup"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn destination_must_be_an_emberbackup_file() {
        let dir = scratch("dest");
        let bad = dir.join("profile.zip");
        let err = validate_destination(&bad).unwrap_err();
        assert!(err.contains("backup_invalid_destination"), "{err}");
        let good = dir.join("profile.emberbackup");
        assert!(validate_destination(&good).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn short_passphrases_are_refused() {
        assert!(validate_passphrase("short").is_err());
        assert!(validate_passphrase("long enough passphrase").is_ok());
    }

    #[test]
    fn every_backup_entry_is_a_unique_bare_file_name() {
        // The allow-list doubles as the zip-slip defence, so no entry may
        // carry a separator or a parent reference.
        let mut seen = std::collections::HashSet::new();
        for spec in BACKUP_FILES {
            assert!(
                !spec.name.contains('/') && !spec.name.contains('\\') && !spec.name.contains(".."),
                "{} is not a bare file name",
                spec.name
            );
            // A repeated name would have `read_manifest` reject a backup this
            // build produced itself.
            assert!(seen.insert(spec.name), "{} is listed twice", spec.name);
        }
    }

    #[test]
    fn incomplete_staging_is_discarded_rather_than_applied() {
        let dir = scratch("staging");
        let staging = staging_dir(&dir);
        std::fs::create_dir_all(&staging).unwrap();
        // No RESTORE.json: staging was interrupted.
        std::fs::write(staging.join("config.json"), b"{}").unwrap();
        std::fs::write(dir.join("config.json"), b"live").unwrap();
        assert!(!apply_pending_restore(&dir).unwrap().applied());
        assert!(!staging.exists());
        assert_eq!(std::fs::read(dir.join("config.json")).unwrap(), b"live");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn applying_a_staged_restore_preserves_the_displaced_file() {
        let dir = scratch("apply");
        let staging = staging_dir(&dir);
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("config.json"), b"restored").unwrap();
        std::fs::write(dir.join("config.json"), b"live").unwrap();
        let pending = PendingRestore {
            version: FORMAT_VERSION,
            staged_at: chrono::Utc::now().timestamp(),
            source_app_version: "1.3.3".to_string(),
            schema_version: 1,
            files: vec!["config.json".to_string()],
            webview_prefs: false,
        };
        std::fs::write(
            staging.join(STAGING_MARKER),
            serde_json::to_vec(&pending).unwrap(),
        )
        .unwrap();

        let preserved = apply_expecting_success(&dir);
        assert_eq!(std::fs::read(dir.join("config.json")).unwrap(), b"restored");
        assert_eq!(
            std::fs::read(preserved.join("config.json")).unwrap(),
            b"live"
        );
        assert!(!staging.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A staging directory that no longer holds every file its marker lists is
    /// refused outright rather than applied in part.
    ///
    /// This is the state a rollback used to leave: the apply *renamed* each
    /// staged copy into place, so the files it then rolled back were gone from
    /// staging. The retry could not tell that from "already applied", skipped
    /// them, set no failure, deleted staging and returned success — leaving the
    /// machine's original of every rolled-back file beside the backup's copy of
    /// the rest, which is exactly the mixed profile the rollback exists to
    /// prevent.
    #[test]
    fn a_staging_dir_missing_a_listed_file_is_refused_not_half_applied() {
        let dir = scratch("apply-incomplete");
        let staging = staging_dir(&dir);
        std::fs::create_dir_all(&staging).unwrap();
        // `identity.json` is still staged; `config.json` is the one an earlier
        // attempt consumed and then rolled back.
        std::fs::write(staging.join("identity.json"), b"restored-identity").unwrap();
        std::fs::write(dir.join("identity.json"), b"live-identity").unwrap();
        std::fs::write(dir.join("config.json"), b"live-config").unwrap();
        let pending = PendingRestore {
            version: FORMAT_VERSION,
            staged_at: chrono::Utc::now().timestamp(),
            source_app_version: "1.3.3".to_string(),
            schema_version: 1,
            files: vec!["config.json".to_string(), "identity.json".to_string()],
            webview_prefs: false,
        };
        std::fs::write(
            staging.join(STAGING_MARKER),
            serde_json::to_vec(&pending).unwrap(),
        )
        .unwrap();

        assert!(!apply_pending_restore(&dir).unwrap().applied());
        // Nothing swapped: both live files are still the machine's own.
        assert_eq!(
            std::fs::read(dir.join("identity.json")).unwrap(),
            b"live-identity"
        );
        assert_eq!(
            std::fs::read(dir.join("config.json")).unwrap(),
            b"live-config"
        );
        // Left staged, so the startup notice fires and Settings > Backup can
        // still discard it.
        assert!(pending_restore_still_staged(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Staged copies outlive the individual swaps, so a retry after a rollback
    /// starts from a complete staging directory. Staging goes only once the
    /// whole set has landed.
    #[test]
    fn applying_a_multi_file_restore_swaps_every_file_and_keeps_both_originals() {
        let dir = scratch("apply-multi");
        let staging = staging_dir(&dir);
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("config.json"), b"restored-config").unwrap();
        std::fs::write(staging.join("identity.json"), b"restored-identity").unwrap();
        std::fs::write(dir.join("config.json"), b"live-config").unwrap();
        std::fs::write(dir.join("identity.json"), b"live-identity").unwrap();
        let pending = PendingRestore {
            version: FORMAT_VERSION,
            staged_at: chrono::Utc::now().timestamp(),
            source_app_version: "1.3.3".to_string(),
            schema_version: 1,
            files: vec!["config.json".to_string(), "identity.json".to_string()],
            webview_prefs: false,
        };
        std::fs::write(
            staging.join(STAGING_MARKER),
            serde_json::to_vec(&pending).unwrap(),
        )
        .unwrap();

        let preserved = apply_expecting_success(&dir);
        assert_eq!(
            std::fs::read(dir.join("config.json")).unwrap(),
            b"restored-config"
        );
        assert_eq!(
            std::fs::read(dir.join("identity.json")).unwrap(),
            b"restored-identity"
        );
        assert_eq!(
            std::fs::read(preserved.join("config.json")).unwrap(),
            b"live-config"
        );
        assert_eq!(
            std::fs::read(preserved.join("identity.json")).unwrap(),
            b"live-identity"
        );
        assert!(!staging.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A copy step that fails for `fail_on` and copies everything else.
    fn failing_copy(fail_on: &'static str) -> impl FnMut(&Path, &Path) -> std::io::Result<()> {
        move |staged, live| {
            if staged.file_name().and_then(|n| n.to_str()) == Some(fail_on) {
                // Leave a truncated file behind, the way a copy that fails
                // part-way does.
                std::fs::write(live, b"partial")?;
                return Err(std::io::Error::other("injected copy failure"));
            }
            copy_into_place(staged, live)
        }
    }

    /// A copy step that dies for `crash_on` after writing part of the file,
    /// with no chance to roll back: the state a power cut leaves.
    fn crashing_copy(crash_on: &'static str) -> impl FnMut(&Path, &Path) -> std::io::Result<()> {
        move |staged, live| {
            if staged.file_name().and_then(|n| n.to_str()) == Some(crash_on) {
                std::fs::write(live, b"partial").unwrap();
                panic!("simulated crash while copying {crash_on}");
            }
            copy_into_place(staged, live)
        }
    }

    fn stage(dir: &Path, files: &[(&str, &[u8])]) -> (PathBuf, Vec<String>) {
        let staging = staging_dir(dir);
        std::fs::create_dir_all(&staging).unwrap();
        for (name, bytes) in files {
            std::fs::write(staging.join(name), bytes).unwrap();
        }
        let names = files.iter().map(|(name, _)| (*name).to_string()).collect();
        (staging, names)
    }

    fn swap(
        dir: &Path,
        staging: &Path,
        names: &[String],
        copy: impl FnMut(&Path, &Path) -> std::io::Result<()>,
    ) -> (PathBuf, Result<usize, String>) {
        swap_in_staged_files(dir, staging, names, copy).unwrap()
    }

    fn crash(dir: &Path, staging: &Path, names: &[String], crash_on: &'static str) {
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            swap_in_staged_files(dir, staging, names, crashing_copy(crash_on))
        }));
        assert!(crashed.is_err(), "the injected crash must fire");
    }

    fn pre_restore_dirs(dir: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| {
                path.is_dir()
                    && path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with(BACKUP_DIR_PREFIX))
            })
            .collect()
    }

    fn write_all(dir: &Path, files: &[(&str, &[u8])]) {
        for (name, bytes) in files {
            std::fs::write(dir.join(name), bytes).unwrap();
        }
    }

    fn assert_contents(dir: &Path, files: &[(&str, &[u8])]) {
        for (name, bytes) in files {
            assert_eq!(
                std::fs::read(dir.join(name)).unwrap(),
                *bytes,
                "{} in {}",
                name,
                dir.display()
            );
        }
    }

    /// The live database's WAL can hold its most recent commits (nothing
    /// checkpoints at shutdown), so a rollback that restores `ember.db`
    /// without its sidecars silently loses them.
    #[test]
    fn a_rolled_back_restore_puts_the_database_sidecars_back() {
        let dir = scratch("rollback-sidecars");
        for (name, bytes) in [
            ("ember.db", &b"live-db"[..]),
            ("ember.db-wal", b"live-wal"),
            ("ember.db-shm", b"live-shm"),
            ("config.json", b"live-config"),
        ] {
            std::fs::write(dir.join(name), bytes).unwrap();
        }
        let (staging, names) = stage(
            &dir,
            &[
                ("ember.db", b"restored-db"),
                ("config.json", b"restored-config"),
            ],
        );

        let err = swap(&dir, &staging, &names, failing_copy("config.json"))
            .1
            .unwrap_err();
        assert!(err.contains("config.json"), "{err}");
        for (name, bytes) in [
            ("ember.db", &b"live-db"[..]),
            ("ember.db-wal", b"live-wal"),
            ("ember.db-shm", b"live-shm"),
            ("config.json", b"live-config"),
        ] {
            assert_eq!(std::fs::read(dir.join(name)).unwrap(), bytes, "{name}");
        }
        assert!(
            staging.join("ember.db").is_file(),
            "staging kept for a retry"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_database_copy_puts_the_database_and_its_sidecars_back() {
        let dir = scratch("rollback-db-copy");
        std::fs::write(dir.join("ember.db"), b"live-db").unwrap();
        std::fs::write(dir.join("ember.db-wal"), b"live-wal").unwrap();
        let (staging, names) = stage(&dir, &[("ember.db", b"restored-db")]);

        swap(&dir, &staging, &names, failing_copy("ember.db"))
            .1
            .unwrap_err();
        assert_eq!(std::fs::read(dir.join("ember.db")).unwrap(), b"live-db");
        assert_eq!(
            std::fs::read(dir.join("ember.db-wal")).unwrap(),
            b"live-wal"
        );
        assert!(!dir.join("ember.db-shm").exists(), "nothing invented");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file the machine never had must not survive a rollback, or the
    /// profile is left holding the backup's copy beside the machine's own
    /// everything else.
    #[test]
    fn a_rolled_back_restore_removes_files_that_had_no_original() {
        let dir = scratch("rollback-new-files");
        std::fs::write(dir.join("config.json"), b"live-config").unwrap();
        std::fs::write(dir.join("identity.json"), b"live-identity").unwrap();
        let (staging, names) = stage(
            &dir,
            &[
                ("config.json", b"restored-config"),
                ("share_intent.json", b"restored-intent"),
                ("known_paths.dat", b"restored-paths"),
                ("identity.json", b"restored-identity"),
            ],
        );

        swap(&dir, &staging, &names, failing_copy("identity.json"))
            .1
            .unwrap_err();
        assert_eq!(
            std::fs::read(dir.join("config.json")).unwrap(),
            b"live-config"
        );
        assert_eq!(
            std::fs::read(dir.join("identity.json")).unwrap(),
            b"live-identity"
        );
        assert!(!dir.join("share_intent.json").exists());
        assert!(!dir.join("known_paths.dat").exists());
        assert!(staging.join("share_intent.json").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_successful_swap_stashes_the_database_sidecars_with_the_original() {
        let dir = scratch("swap-sidecars");
        std::fs::write(dir.join("ember.db"), b"live-db").unwrap();
        std::fs::write(dir.join("ember.db-wal"), b"live-wal").unwrap();
        let (staging, names) = stage(&dir, &[("ember.db", b"restored-db")]);

        let (backup_dir, outcome) = swap(&dir, &staging, &names, copy_into_place);
        assert_eq!(outcome.unwrap(), 1);
        assert_eq!(std::fs::read(dir.join("ember.db")).unwrap(), b"restored-db");
        assert!(!dir.join("ember.db-wal").exists());
        assert_eq!(
            std::fs::read(backup_dir.join("ember.db-wal")).unwrap(),
            b"live-wal"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    const LIVE_PROFILE: &[(&str, &[u8])] = &[
        ("identity.json", b"live-identity"),
        ("ember.db", b"live-db"),
        ("ember.db-wal", b"live-wal"),
        ("ember.db-shm", b"live-shm"),
        ("config.json", b"live-config"),
    ];
    const STAGED_PROFILE: &[(&str, &[u8])] = &[
        ("identity.json", b"restored-identity"),
        ("ember.db", b"restored-db"),
        ("config.json", b"restored-config"),
    ];

    /// A crash mid-copy leaves a restored `identity.json` and a truncated
    /// `ember.db` live. The retry must treat both as its own work, not move
    /// them aside as the user's originals into a second pre-restore folder.
    #[test]
    fn a_crash_mid_copy_is_resumed_into_the_same_pre_restore_folder() {
        let dir = scratch("crash-resume");
        write_all(&dir, LIVE_PROFILE);
        let (staging, names) = stage(&dir, STAGED_PROFILE);

        crash(&dir, &staging, &names, "ember.db");
        assert_eq!(std::fs::read(dir.join("ember.db")).unwrap(), b"partial");

        let (backup_dir, outcome) = swap(&dir, &staging, &names, copy_into_place);
        assert_eq!(outcome.unwrap(), 3);
        assert_contents(&dir, STAGED_PROFILE);
        assert!(!dir.join("ember.db-wal").exists());
        assert!(!dir.join("ember.db-shm").exists());
        assert_eq!(pre_restore_dirs(&dir), vec![backup_dir.clone()]);
        assert_contents(&backup_dir, LIVE_PROFILE);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A retry that fails must roll back to the machine's originals, including
    /// files an earlier, crashed attempt swapped and this one never reached.
    #[test]
    fn a_failed_retry_after_a_crash_rolls_back_to_the_originals() {
        let dir = scratch("crash-rollback");
        write_all(&dir, LIVE_PROFILE);
        let (staging, names) = stage(&dir, STAGED_PROFILE);

        crash(&dir, &staging, &names, "config.json");
        swap(&dir, &staging, &names, failing_copy("identity.json"))
            .1
            .unwrap_err();

        assert_contents(&dir, LIVE_PROFILE);
        let journal: ApplyJournal =
            serde_json::from_slice(&std::fs::read(staging.join(APPLY_JOURNAL)).unwrap()).unwrap();
        assert!(journal.entries.is_empty(), "everything was put back");

        // And the next attempt starts over cleanly from the originals.
        let (backup_dir, outcome) = swap(&dir, &staging, &names, copy_into_place);
        assert_eq!(outcome.unwrap(), 3);
        assert_contents(&dir, STAGED_PROFILE);
        assert_contents(&backup_dir, LIVE_PROFILE);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Crash after `ember.db` was moved aside but before its sidecars were.
    /// The retry sees no live database; the live WAL/SHM still belong to the
    /// original and must travel with it, never be left for a fresh database.
    #[test]
    fn a_crash_between_moving_the_database_and_its_sidecars_is_recovered() {
        let dir = scratch("crash-sidecars");
        write_all(&dir, LIVE_PROFILE);
        let (staging, names) = stage(&dir, STAGED_PROFILE);
        let (backup_dir, _) = open_apply_journal(&dir, &staging).unwrap();
        std::fs::rename(dir.join("ember.db"), backup_dir.join("ember.db")).unwrap();

        swap(&dir, &staging, &names, failing_copy("config.json"))
            .1
            .unwrap_err();
        assert_contents(&dir, LIVE_PROFILE);

        let (backup_dir, outcome) = swap(&dir, &staging, &names, copy_into_place);
        assert_eq!(outcome.unwrap(), 3);
        assert_contents(&backup_dir, LIVE_PROFILE);
        assert!(!dir.join("ember.db-wal").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file the machine never had, copied in before the crash, is the
    /// backup's copy. The retry must not preserve it as an "original", and a
    /// failed retry must remove it.
    #[test]
    fn a_crash_after_copying_a_file_with_no_original_does_not_adopt_it() {
        let dir = scratch("crash-new-file");
        std::fs::write(dir.join("identity.json"), b"live-identity").unwrap();
        let (staging, names) = stage(
            &dir,
            &[
                ("share_intent.json", b"restored-intent"),
                ("identity.json", b"restored-identity"),
            ],
        );

        crash(&dir, &staging, &names, "identity.json");
        let (backup_dir, outcome) = swap(&dir, &staging, &names, failing_copy("identity.json"));
        outcome.unwrap_err();

        assert!(!dir.join("share_intent.json").exists());
        assert!(!backup_dir.join("share_intent.json").exists());
        assert_eq!(
            std::fs::read(dir.join("identity.json")).unwrap(),
            b"live-identity"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn write_marker(staging: &Path, files: &[&str]) {
        let pending = PendingRestore {
            version: FORMAT_VERSION,
            staged_at: chrono::Utc::now().timestamp(),
            source_app_version: "1.3.3".to_string(),
            schema_version: 1,
            files: files.iter().map(|f| (*f).to_string()).collect(),
            webview_prefs: false,
        };
        std::fs::write(
            staging.join(STAGING_MARKER),
            serde_json::to_vec(&pending).unwrap(),
        )
        .unwrap();
    }

    /// The staged files are copied, not consumed, so a marker that survives
    /// cleanup would re-apply the backup over everything done since.
    #[test]
    fn a_marker_that_cannot_be_removed_is_overridden_by_the_applied_sentinel() {
        let dir = scratch("applied-sentinel");
        let (staging, _) = stage(&dir, &[("config.json", b"restored")]);
        // A directory stands in for a marker an antivirus scanner holds open:
        // `remove_file` refuses it on every platform.
        std::fs::create_dir_all(staging.join(STAGING_MARKER).join("held")).unwrap();

        assert!(mark_restore_applied(&staging));
        assert!(staging.join(APPLIED_SENTINEL).is_file());
        assert!(!pending_restore_still_staged(&dir));
        assert!(read_pending_marker(&staging).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_applied_restore_is_never_applied_again() {
        let dir = scratch("applied-once");
        let (staging, _) = stage(&dir, &[("config.json", b"restored")]);
        write_marker(&staging, &["config.json"]);
        std::fs::write(staging.join(APPLIED_SENTINEL), b"applied\n").unwrap();
        std::fs::write(dir.join("config.json"), b"changed since").unwrap();

        assert!(!apply_pending_restore(&dir).unwrap().applied());
        assert_eq!(
            std::fs::read(dir.join("config.json")).unwrap(),
            b"changed since"
        );
        assert!(!staging.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The config is repaired as part of the apply, not after staging is
    /// gone, and the finished apply leaves nothing to re-apply.
    #[test]
    fn an_applied_restore_repairs_its_config_and_retires_staging() {
        let dir = scratch("apply-sanitize");
        let config = serde_json::to_vec(&serde_json::json!({
            "preview_player": r"\\attacker\share\p.exe",
            "nickname": "kept",
        }))
        .unwrap();
        let (staging, _) = stage(&dir, &[("config.json", &config)]);
        write_marker(&staging, &["config.json"]);

        let backup_dir = apply_expecting_success(&dir);
        let repaired: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("config.json")).unwrap()).unwrap();
        assert_eq!(repaired["preview_player"].as_str().unwrap(), "");
        assert_eq!(repaired["nickname"].as_str().unwrap(), "kept");
        assert!(!staging.exists());
        assert!(backup_dir.is_dir());
        assert!(!apply_pending_restore(&dir).unwrap().applied());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Copies that already landed spent their space. Counting them again would
    /// refuse, on every later launch, the resume that has to finish.
    #[test]
    fn a_resume_needs_space_only_for_the_files_not_yet_copied() {
        let dir = scratch("resume-space");
        write_all(&dir, LIVE_PROFILE);
        let (staging, names) = stage(&dir, STAGED_PROFILE);
        crash(&dir, &staging, &names, "config.json");

        let journal = read_apply_journal(&staging).unwrap();
        let config_len = b"restored-config".len() as u64;
        assert_eq!(
            restore_space_needed(&dir, &staging, &names, Some(&journal)),
            config_len + config_len / 4
        );
        assert!(
            restore_space_needed(&dir, &staging, &names, None)
                > restore_space_needed(&dir, &staging, &names, Some(&journal))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_interrupted_apply_is_resumed_at_the_next_launch() {
        let dir = scratch("resume-apply");
        write_all(&dir, LIVE_PROFILE);
        let (staging, names) = stage(&dir, STAGED_PROFILE);
        write_marker(&staging, &["identity.json", "ember.db", "config.json"]);
        crash(&dir, &staging, &names, "ember.db");

        let backup_dir = apply_expecting_success(&dir);
        assert_contents(&dir, STAGED_PROFILE);
        assert_contents(&backup_dir, LIVE_PROFILE);
        assert!(!staging.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A pre-check that refuses to resume must not leave the app to start on
    /// the half-applied profile.
    #[test]
    fn a_resume_refused_by_a_pre_check_rolls_the_interrupted_apply_back() {
        let dir = scratch("resume-refused");
        write_all(&dir, LIVE_PROFILE);
        let (staging, names) = stage(&dir, STAGED_PROFILE);
        write_marker(&staging, &["identity.json", "ember.db", "config.json"]);
        crash(&dir, &staging, &names, "ember.db");
        std::fs::remove_file(staging.join("config.json")).unwrap();

        assert!(!apply_pending_restore(&dir).unwrap().applied());
        assert_contents(&dir, LIVE_PROFILE);
        assert!(pending_restore_still_staged(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn pre_restore_with(dir: &Path, files: &[(&str, &[u8])]) -> PathBuf {
        let backup_dir = dir.join("pre-restore-test");
        std::fs::create_dir_all(&backup_dir).unwrap();
        write_all(&backup_dir, files);
        backup_dir
    }

    fn db_entry(sidecars: &[&str], attempt: u32) -> Swapped {
        Swapped {
            name: "ember.db".to_string(),
            displaced: true,
            sidecars: sidecars.iter().map(|s| (*s).to_string()).collect(),
            sidecars_done: true,
            stranded: Vec::new(),
            attempt,
            copied: None,
        }
    }

    /// The database goes back and is opened without the sidecar it could not
    /// take along, so that sidecar must be set aside for good, not left where a
    /// later launch would return it.
    #[test]
    fn a_sidecar_rollback_cannot_return_is_set_aside_under_a_unique_name() {
        let dir = scratch("strand-sidecar");
        let backup_dir = pre_restore_with(
            &dir,
            &[("ember.db", b"live-db"), ("ember.db-wal", b"live-wal")],
        );
        std::fs::write(dir.join("ember.db"), b"restored-db").unwrap();
        // A non-empty directory where the WAL goes makes the rename fail.
        std::fs::create_dir_all(dir.join("ember.db-wal").join("busy")).unwrap();

        let mut entry = db_entry(&["ember.db-wal"], 1);
        assert!(roll_back_swap(&dir, &backup_dir, &mut entry));
        assert_eq!(std::fs::read(dir.join("ember.db")).unwrap(), b"live-db");
        assert!(!backup_dir.join("ember.db-wal").exists());
        assert_eq!(
            std::fs::read(backup_dir.join("ember.db-wal.orphaned-1")).unwrap(),
            b"live-wal"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stashed_sidecar_returns_only_after_a_crash_not_after_the_app_ran() {
        for (crashed_attempt, returned) in [(Some(1), true), (None, false)] {
            let dir = scratch("settle-sidecar");
            let backup_dir = pre_restore_with(&dir, &[("ember.db-wal", b"live-wal")]);
            std::fs::write(dir.join("ember.db"), b"live-db").unwrap();
            let mut journal = ApplyJournal {
                backup_dir: "pre-restore-test".to_string(),
                attempt: 1,
                in_progress: crashed_attempt.is_some(),
                applied: false,
                entries: vec![db_entry(&["ember.db-wal"], 1)],
            };

            settle_rolled_back_entries(&dir, &backup_dir, &mut journal, crashed_attempt);
            assert!(journal.entries.is_empty());
            assert_eq!(dir.join("ember.db-wal").exists(), returned);
            assert_eq!(
                backup_dir.join("ember.db-wal.orphaned-1").exists(),
                !returned
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// A stale stash left by an earlier rollback must be set aside, not
    /// replaced, when the live database's sidecar is stashed in its place.
    #[test]
    fn stashing_over_a_stale_sidecar_keeps_both_and_every_earlier_orphan() {
        let dir = scratch("stash-stale");
        let backup_dir = pre_restore_with(
            &dir,
            &[
                ("ember.db-wal", b"stale"),
                ("ember.db-wal.orphaned-1", b"older"),
            ],
        );
        std::fs::write(dir.join("ember.db-wal"), b"current").unwrap();

        let mut entry = db_entry(&[], 2);
        stash_database_sidecars(&dir, &backup_dir, &mut entry, true, true).unwrap();
        assert_contents(
            &backup_dir,
            &[
                ("ember.db-wal", b"current"),
                ("ember.db-wal.orphaned-1", b"older"),
                ("ember.db-wal.orphaned-2", b"stale"),
            ],
        );
        assert_eq!(entry.sidecars, vec!["ember.db-wal".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// After an attempt returned, the app ran and may have created a file the
    /// journal lists as having no original. That file is the user's now.
    #[test]
    fn a_file_created_after_an_attempt_returned_is_preserved_not_overwritten() {
        for (copied_matches, preserved) in [(false, true), (true, false)] {
            let dir = scratch("stale-no-original");
            std::fs::write(dir.join("nodes.dat"), b"created by the app").unwrap();
            let (staging, names) = stage(&dir, &[("nodes.dat", b"restored-nodes")]);
            let (_, mut journal) = open_apply_journal(&dir, &staging).unwrap();
            journal.attempt = 1;
            journal.in_progress = false;
            journal.entries.push(Swapped {
                name: "nodes.dat".to_string(),
                displaced: false,
                sidecars: Vec::new(),
                sidecars_done: false,
                stranded: Vec::new(),
                attempt: 1,
                copied: copied_matches
                    .then(|| FileFingerprint::of(&dir.join("nodes.dat")))
                    .flatten(),
            });
            write_apply_journal(&staging, &journal).unwrap();

            let (backup_dir, outcome) = swap(&dir, &staging, &names, copy_into_place);
            assert_eq!(outcome.unwrap(), 1);
            assert_eq!(
                std::fs::read(dir.join("nodes.dat")).unwrap(),
                b"restored-nodes"
            );
            assert_eq!(backup_dir.join("nodes.dat").exists(), preserved);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// Cleaning up an applied restore whose marker cannot be deleted must keep
    /// the sentinel that stands in for it.
    #[test]
    fn staging_cleanup_never_removes_the_sentinel_before_the_marker() {
        let dir = scratch("sentinel-last");
        let (staging, _) = stage(&dir, &[("config.json", b"restored")]);
        std::fs::create_dir_all(staging.join(STAGING_MARKER).join("held")).unwrap();
        std::fs::write(staging.join(APPLIED_SENTINEL), b"applied\n").unwrap();

        assert!(!apply_pending_restore(&dir).unwrap().applied());
        assert!(staging.join(APPLIED_SENTINEL).is_file());
        assert!(!pending_restore_still_staged(&dir));
        assert!(read_pending_marker(&staging).is_none());

        std::fs::remove_dir_all(staging.join(STAGING_MARKER)).unwrap();
        remove_applied_staging(&staging).unwrap();
        assert!(!staging.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An abandoned export scratch directory holds DPAPI-*unwrapped* identity,
    /// SecIdent and chat keys, so it must not survive a restart.
    #[test]
    fn startup_sweeps_abandoned_backup_scratch_directories() {
        let dir = scratch("scratch-sweep");
        let export = temp_dir_in(&dir, "backup-tmp").unwrap();
        let import = temp_dir_in(&dir, "restore-tmp").unwrap();
        std::fs::write(export.join("payload.zip"), b"plaintext-keys").unwrap();
        // Not ours to remove.
        std::fs::write(dir.join("config.json"), b"live").unwrap();
        let keep = dir.join("pre-restore-123");
        std::fs::create_dir_all(&keep).unwrap();

        sweep_orphaned_scratch(&dir);

        assert!(!export.exists(), "export scratch must be swept");
        assert!(!import.exists(), "import scratch must be swept");
        assert!(keep.is_dir(), "displaced originals must be kept");
        assert!(dir.join("config.json").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_staged_restore_left_for_a_month_is_discarded_rather_than_applied() {
        let dir = scratch("stale-restore");
        let staging = staging_dir(&dir);
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("config.json"), b"restored").unwrap();
        std::fs::write(dir.join("config.json"), b"live").unwrap();
        let pending = PendingRestore {
            version: FORMAT_VERSION,
            staged_at: chrono::Utc::now().timestamp() - (STAGED_RESTORE_MAX_AGE_SECS + 86_400),
            source_app_version: "1.3.3".to_string(),
            schema_version: 1,
            files: vec!["config.json".to_string()],
            webview_prefs: false,
        };
        std::fs::write(
            staging.join(STAGING_MARKER),
            serde_json::to_vec(&pending).unwrap(),
        )
        .unwrap();

        assert!(matches!(
            apply_pending_restore(&dir).unwrap(),
            StartupRestore::Expired
        ));
        // The profile in use wins, and the staged copies do not linger.
        assert_eq!(std::fs::read(dir.join("config.json")).unwrap(), b"live");
        assert!(!staging.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_restore_staged_by_a_newer_build_is_left_staged_rather_than_applied() {
        let dir = scratch("schema-guard");
        let staging = staging_dir(&dir);
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("config.json"), b"restored").unwrap();
        std::fs::write(dir.join("config.json"), b"live").unwrap();
        let pending = PendingRestore {
            version: FORMAT_VERSION,
            staged_at: 0,
            source_app_version: "9.9.9".to_string(),
            schema_version: crate::storage::database::MAX_SUPPORTED_SCHEMA_VERSION + 1,
            files: vec!["config.json".to_string()],
            webview_prefs: false,
        };
        std::fs::write(
            staging.join(STAGING_MARKER),
            serde_json::to_vec(&pending).unwrap(),
        )
        .unwrap();

        assert!(!apply_pending_restore(&dir).unwrap().applied());
        // Left intact for a build that can actually open it, and still
        // discardable from the Backup screen.
        assert!(staging.join(STAGING_MARKER).is_file());
        assert_eq!(std::fs::read(dir.join("config.json")).unwrap(), b"live");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_swap_puts_the_displaced_file_back() {
        let dir = scratch("swap-rollback");
        let live = dir.join("config.json");
        std::fs::write(&live, b"live").unwrap();
        let backup_dir = dir.join("pre-restore-test");
        std::fs::create_dir_all(&backup_dir).unwrap();
        // Displace the live file the way the apply loop does, then fail the
        // swap by pointing it at a staged path that does not exist.
        std::fs::rename(&live, backup_dir.join("config.json")).unwrap();
        assert!(copy_into_place(&dir.join("missing.staged"), &live).is_err());
        std::fs::rename(backup_dir.join("config.json"), &live).unwrap();
        assert_eq!(std::fs::read(&live).unwrap(), b"live");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_staged_file_outside_the_allow_list_is_ignored() {
        let dir = scratch("allowlist");
        let staging = staging_dir(&dir);
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("evil.exe"), b"payload").unwrap();
        let pending = PendingRestore {
            version: FORMAT_VERSION,
            staged_at: 0,
            source_app_version: "1.3.3".to_string(),
            schema_version: 1,
            files: vec!["evil.exe".to_string()],
            webview_prefs: false,
        };
        std::fs::write(
            staging.join(STAGING_MARKER),
            serde_json::to_vec(&pending).unwrap(),
        )
        .unwrap();

        apply_pending_restore(&dir).unwrap();
        assert!(!dir.join("evil.exe").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_restored_config_pointing_at_a_missing_location_is_repaired() {
        let dir = scratch("sanitize");
        // A path under a regular file can never be created, which stands in
        // for the drive that does not exist on this machine.
        let blocker = dir.join("not-a-directory");
        std::fs::write(&blocker, b"x").unwrap();
        let unusable = blocker.join("Ember");
        let real_share = dir.join("shared");
        std::fs::create_dir_all(&real_share).unwrap();
        let config = serde_json::json!({
            "download_folder": unusable.to_string_lossy(),
            "shared_folders": [
                real_share.to_string_lossy(),
                dir.join("gone").to_string_lossy(),
            ],
            "nickname": "kept",
            "preview_player": r"\\attacker\share\p.exe",
        });
        std::fs::write(
            dir.join("config.json"),
            serde_json::to_vec_pretty(&config).unwrap(),
        )
        .unwrap();

        assert_eq!(
            sanitize_restored_config(&dir),
            None,
            "only a download folder on a share is announced"
        );

        let repaired: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("config.json")).unwrap()).unwrap();
        assert_ne!(
            repaired["download_folder"].as_str().unwrap(),
            unusable.to_string_lossy()
        );
        assert_eq!(
            repaired["shared_folders"].as_array().unwrap().len(),
            2,
            "a folder that is merely offline must not be dropped from the config"
        );
        // Untouched fields must survive the raw-JSON edit.
        assert_eq!(repaired["nickname"].as_str().unwrap(), "kept");
        assert_eq!(
            repaired["preview_player"].as_str().unwrap(),
            "",
            "a restored config must never name a program Ember will run"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restored_folders_on_a_network_share_are_not_kept() {
        let dir = scratch("sanitize-share");
        let share = r"\\192.0.2.1\share\Ember";
        let local = dir.join("earlier").to_string_lossy().into_owned();
        let local_share = dir.join("music").to_string_lossy().into_owned();
        std::fs::write(
            dir.join("config.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "download_folder": share,
                "previous_download_folders": [r"\\192.0.2.1\old", local],
                "shared_folders": [r"\\192.0.2.1\media", local_share],
            }))
            .unwrap(),
        )
        .unwrap();

        let replaced = sanitize_restored_config(&dir);

        let repaired: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("config.json")).unwrap()).unwrap();
        let folder = repaired["download_folder"].as_str().unwrap();
        assert!(!crate::security::is_network_path(folder), "{folder}");
        assert_eq!(replaced.as_deref(), Some(folder), "the replacement is announced");
        assert_eq!(
            repaired["previous_download_folders"],
            serde_json::json!([local]),
            "a local earlier folder stays, a share goes"
        );
        assert_eq!(
            repaired["shared_folders"],
            serde_json::json!([local_share]),
            "a local shared folder stays, a share goes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_restored_config_with_only_a_media_player_is_rewritten_without_it() {
        let dir = scratch("sanitize-player");
        std::fs::write(
            dir.join("config.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "preview_player": r"C:\Windows\System32\mshta.exe",
                "nickname": "kept",
            }))
            .unwrap(),
        )
        .unwrap();

        sanitize_restored_config(&dir);

        let repaired: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("config.json")).unwrap()).unwrap();
        assert_eq!(repaired["preview_player"].as_str().unwrap(), "");
        assert_eq!(repaired["nickname"].as_str().unwrap(), "kept");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Build a zip the way `build_archive` does, but with the manifest under
    /// the caller's control so the rejection paths can be exercised.
    fn write_archive(dir: &Path, files: &[(&str, &[u8])], manifest: &Manifest) -> PathBuf {
        let zip_path = dir.join("payload.zip");
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&zip_path).unwrap());
        let options = zip::write::SimpleFileOptions::default();
        for (name, bytes) in files {
            zip.start_file(*name, options).unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.start_file(MANIFEST_NAME, options).unwrap();
        zip.write_all(&serde_json::to_vec(manifest).unwrap())
            .unwrap();
        zip.finish().unwrap();
        zip_path
    }

    fn manifest_for(entries: &[(&str, &[u8])]) -> Manifest {
        Manifest {
            version: FORMAT_VERSION,
            app_version: "1.3.3".to_string(),
            created_at: 1,
            schema_version: 1,
            files: entries
                .iter()
                .map(|(name, bytes)| ManifestEntry {
                    name: (*name).to_string(),
                    size: bytes.len() as u64,
                    blake3: blake3::hash(bytes).to_hex().to_string(),
                    rewrap: false,
                })
                .collect(),
            webview_prefs: None,
        }
    }

    #[test]
    fn a_well_formed_archive_reads_back_its_entries() {
        let dir = scratch("archive-ok");
        let entries: &[(&str, &[u8])] = &[("config.json", b"{}"), ("nodes.dat", b"contacts")];
        let zip_path = write_archive(&dir, entries, &manifest_for(entries));

        let (manifest, read) = read_archive(&zip_path, &dir.join("entries")).unwrap();
        assert_eq!(manifest.app_version, "1.3.3");
        assert_eq!(read.len(), 2);
        assert_eq!(read[0].spec.name, "config.json");
        assert_eq!(std::fs::read(&read[0].path).unwrap(), b"{}");
        assert_eq!(std::fs::read(&read[1].path).unwrap(), b"contacts");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_entry_outside_the_allow_list_is_refused() {
        let dir = scratch("archive-allowlist");
        let entries: &[(&str, &[u8])] = &[("evil.exe", b"payload")];
        let zip_path = write_archive(&dir, entries, &manifest_for(entries));

        let err = read_archive(&zip_path, &dir.join("entries")).unwrap_err();
        // Assert the reason, not just that it failed: a plain "missing entry"
        // rejection would pass a looser check while leaving the allow-list
        // itself unexercised.
        assert!(err.contains("unexpected file"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Dropping a name out of `BACKUP_FILES` is not the same as never having
    /// backed it up. Every archive an earlier version wrote still names
    /// `approved_roots.json`, and the allow-list refuses the *whole* archive on
    /// an unknown entry — so a bare removal made those backups unrestorable at
    /// exactly the moment their owner needed them.
    #[test]
    fn an_archive_from_a_version_that_backed_up_approved_roots_still_restores() {
        let dir = scratch("archive-legacy");
        let entries: &[(&str, &[u8])] = &[
            ("config.json", b"{}"),
            ("approved_roots.json", b"[{\"path\":\"D:/Shared\"}]"),
            ("nodes.dat", b"contacts"),
        ];
        let zip_path = write_archive(&dir, entries, &manifest_for(entries));

        let (_, read) = read_archive(&zip_path, &dir.join("entries"))
            .expect("a 1.3.5 archive must still restore");
        let names: Vec<&str> = read.iter().map(|e| e.spec.name).collect();
        assert_eq!(
            names,
            vec!["config.json", "nodes.dat"],
            "the dropped file is skipped, not restored, and does not fail the archive"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_traversal_name_never_reaches_the_filesystem() {
        let dir = scratch("archive-traversal");
        let entries: &[(&str, &[u8])] = &[("../../evil.exe", b"payload")];
        let zip_path = write_archive(&dir, entries, &manifest_for(entries));

        assert!(read_archive(&zip_path, &dir.join("entries")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_manifest_that_lists_a_file_twice_is_refused() {
        let dir = scratch("archive-dupe");
        let entries: &[(&str, &[u8])] = &[("config.json", b"{}")];
        let mut manifest = manifest_for(entries);
        let duplicate = ManifestEntry {
            name: manifest.files[0].name.clone(),
            size: manifest.files[0].size,
            blake3: manifest.files[0].blake3.clone(),
            rewrap: false,
        };
        manifest.files.push(duplicate);
        let zip_path = write_archive(&dir, entries, &manifest);

        let err = read_archive(&zip_path, &dir.join("entries")).unwrap_err();
        assert!(err.contains("same file twice"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_entry_that_does_not_match_its_checksum_is_refused() {
        let dir = scratch("archive-checksum");
        let claimed: &[(&str, &[u8])] = &[("config.json", b"{}")];
        let tampered: &[(&str, &[u8])] = &[("config.json", b"[]")];
        // Same length, different content, so only the hash catches it.
        let zip_path = write_archive(&dir, tampered, &manifest_for(claimed));

        let err = read_archive(&zip_path, &dir.join("entries")).unwrap_err();
        assert!(err.contains("backup_corrupt_archive"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_archive_without_a_manifest_is_refused() {
        let dir = scratch("archive-nomanifest");
        let zip_path = dir.join("payload.zip");
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&zip_path).unwrap());
        zip.start_file("config.json", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"{}").unwrap();
        zip.finish().unwrap();

        let err = read_archive(&zip_path, &dir.join("entries")).unwrap_err();
        assert!(err.contains("backup_corrupt_archive"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_manifest_entry_missing_from_the_zip_is_refused() {
        let dir = scratch("archive-missing");
        let claimed: &[(&str, &[u8])] = &[("config.json", b"{}"), ("nodes.dat", b"contacts")];
        // Manifest promises two files, the zip only carries one.
        let zip_path = write_archive(&dir, &claimed[..1], &manifest_for(claimed));

        let err = read_archive(&zip_path, &dir.join("entries")).unwrap_err();
        assert!(err.contains("backup_corrupt_archive"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The whole runtime path in one test: build the archive from a real data
    /// directory (real database included), encrypt it, decrypt it back, verify
    /// it, stage it, and apply it the way startup does. The pieces are covered
    /// individually above; what this pins down is that they fit together, which
    /// is the part a user actually depends on.
    #[test]
    fn a_backup_round_trips_through_a_real_data_directory() {
        let root = scratch("e2e");
        let source_dir = root.join("source");
        let restore_dir = root.join("restore");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::create_dir_all(&restore_dir).unwrap();

        // A data directory with the shapes that matter: a live database, a
        // plain file, and a DPAPI-wrapped secret.
        let db = crate::storage::database::Database::open_at(&source_dir.join("ember.db"))
            .expect("open source database");
        let identity_plaintext = br#"{"kad_id":[1,2,3],"user_hash":"abc"}"#;
        std::fs::write(
            source_dir.join("identity.json"),
            secret_store::protect(identity_plaintext).expect("protect identity"),
        )
        .unwrap();
        std::fs::write(source_dir.join("config.json"), br#"{"nickname":"tester"}"#).unwrap();
        std::fs::write(source_dir.join("known.met"), b"known-file-bytes").unwrap();

        // Export.
        let scratch_dir = temp_dir_in(&source_dir, "backup-tmp").expect("scratch");
        let (zip_path, manifest, skipped) =
            build_archive(&source_dir, &scratch_dir, &db, "1.3.3", None).expect("build archive");
        assert!(skipped.is_empty(), "{skipped:?}");
        assert!(
            manifest.files.iter().any(|f| f.name == "ember.db"),
            "the database snapshot must be in the archive"
        );
        assert!(
            manifest
                .files
                .iter()
                .any(|f| f.name == "identity.json" && f.rewrap),
            "identity.json must be marked for re-wrapping"
        );
        let archive = root.join("profile.emberbackup");
        let mut zip_file = std::fs::File::open(&zip_path).unwrap();
        let written = encrypt_stream(&mut zip_file, &archive, "correct horse battery")
            .expect("encrypt archive");
        assert!(written > 0);
        let _ = std::fs::remove_dir_all(&scratch_dir);
        drop(db);

        // The archive must not carry the identity in a form another account
        // could not read, nor the plaintext where the container did not encrypt.
        let raw = std::fs::read(&archive).unwrap();
        assert!(
            !raw.windows(identity_plaintext.len())
                .any(|w| w == identity_plaintext),
            "the identity must not be readable in the archive bytes"
        );

        // Restore into a different directory, as a new machine would.
        let restore_scratch = temp_dir_in(&restore_dir, "restore-tmp").expect("scratch");
        let decrypted = restore_scratch.join("payload.zip");
        decrypt_stream(&archive, &decrypted, "correct horse battery").expect("decrypt");
        let staging = staging_dir(&restore_dir);
        let summary = stage_archive(&decrypted, &restore_scratch, &staging).expect("stage");
        assert_eq!(summary.app_version, "1.3.3");
        assert!(summary.staged.iter().any(|n| n == "ember.db"));
        assert!(
            !summary.chat_key_set_aside,
            "the backup carries its chat key"
        );
        let pending = read_pending_marker(&staging).expect("marker");
        assert_eq!(
            pending.schema_version,
            crate::storage::database::MAX_SUPPORTED_SCHEMA_VERSION,
            "the marker records the staged database's own schema"
        );
        assert!(
            !pending.webview_prefs,
            "a backup without preferences stages none"
        );
        let _ = std::fs::remove_dir_all(&restore_scratch);

        // Nothing is in place until the swap runs, which is what startup does.
        assert!(!restore_dir.join("ember.db").exists());
        let preserved = apply_expecting_success(&restore_dir);
        assert!(!staging.exists(), "the staging directory is consumed");
        assert_eq!(
            take_restored_prefs(&restore_dir),
            None,
            "a backup without app preferences hands none to the window"
        );

        // Plain files come back byte-for-byte.
        assert_eq!(
            std::fs::read(restore_dir.join("config.json")).unwrap(),
            br#"{"nickname":"tester"}"#
        );
        assert_eq!(
            std::fs::read(restore_dir.join("known.met")).unwrap(),
            b"known-file-bytes"
        );

        // The identity is protected again for this account, and unwraps to
        // exactly what was backed up: this is what keeps the user hash and
        // credits after a move.
        let restored_identity = std::fs::read(restore_dir.join("identity.json")).unwrap();
        assert!(
            !cfg!(target_os = "windows") || secret_store::is_protected(&restored_identity),
            "restored identity must be re-wrapped"
        );
        assert_eq!(
            &secret_store::unprotect(&restored_identity).expect("unprotect restored identity")[..],
            &identity_plaintext[..]
        );

        // The restored database opens and reports the schema it was taken at.
        let restored_db =
            crate::storage::database::Database::open_at(&restore_dir.join("ember.db"))
                .expect("open restored database");
        assert_eq!(
            restored_db.schema_version(),
            crate::storage::database::MAX_SUPPORTED_SCHEMA_VERSION
        );
        drop(restored_db);

        // A first restore into an empty directory displaces nothing.
        assert!(preserved.is_dir());
        let _ = std::fs::remove_dir_all(&root);
    }

    fn sample_prefs() -> WebviewPrefs {
        [
            ("PARAGLIDE_LOCALE", "de"),
            ("ember-theme", "dark"),
            (
                "ember.channels.hidden.v1",
                r#"["0123456789abcdef0123456789abcdef"]"#,
            ),
            ("search-recent-queries-v1", r#"["ubuntu iso"]"#),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    /// The preferences travel the whole runtime path: into the encrypted
    /// archive, back out, through staging and the startup apply, and to the
    /// window exactly once.
    #[test]
    fn app_preferences_round_trip_through_a_backup_and_are_handed_over_once() {
        let root = scratch("prefs-e2e");
        let source_dir = root.join("source");
        let restore_dir = root.join("restore");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::create_dir_all(&restore_dir).unwrap();
        let db = crate::storage::database::Database::open_at(&source_dir.join("ember.db"))
            .expect("open source database");
        std::fs::write(source_dir.join("config.json"), br#"{"nickname":"tester"}"#).unwrap();
        let prefs = sample_prefs();

        let scratch_dir = temp_dir_in(&source_dir, "backup-tmp").expect("scratch");
        let (zip_path, manifest, _) =
            build_archive(&source_dir, &scratch_dir, &db, "1.7.1", Some(&prefs))
                .expect("build archive");
        assert!(manifest.webview_prefs.is_some());
        assert!(
            manifest.files.iter().all(|f| f.name != WEBVIEW_PREFS_NAME),
            "listing the preferences in `files` would make older readers refuse the backup"
        );
        let archive = root.join("profile.emberbackup");
        let mut zip_file = std::fs::File::open(&zip_path).unwrap();
        encrypt_stream(&mut zip_file, &archive, "correct horse battery").expect("encrypt");
        drop(zip_file);
        let _ = std::fs::remove_dir_all(&scratch_dir);
        drop(db);
        let raw = std::fs::read(&archive).unwrap();
        assert!(
            !raw.windows(b"ubuntu iso".len()).any(|w| w == b"ubuntu iso"),
            "the preferences must only exist inside the encrypted payload"
        );

        let restore_scratch = temp_dir_in(&restore_dir, "restore-tmp").expect("scratch");
        let decrypted = restore_scratch.join("payload.zip");
        decrypt_stream(&archive, &decrypted, "correct horse battery").expect("decrypt");
        let restored_manifest = read_manifest(&mut open_archive(&decrypted).unwrap()).unwrap();
        let read_prefs = read_webview_prefs(&decrypted, &restored_manifest).expect("read prefs");
        assert_eq!(read_prefs.as_ref(), Some(&prefs));
        let staging = staging_dir(&restore_dir);
        stage_archive(&decrypted, &restore_scratch, &staging).expect("stage");
        let _ = std::fs::remove_dir_all(&restore_scratch);
        assert_eq!(
            take_restored_prefs(&restore_dir),
            None,
            "nothing reaches the window before the restore is applied"
        );

        apply_expecting_success(&restore_dir);
        assert!(!staging.exists());
        assert_eq!(take_restored_prefs(&restore_dir), Some(prefs));
        assert_eq!(
            take_restored_prefs(&restore_dir),
            None,
            "the window reloads after applying them, so a second take must find nothing"
        );
        assert!(!restore_dir.join(RESTORED_PREFS_FILE).exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A previous Ember's reader: the manifest exactly as it was before the
    /// preferences existed, and an allow-list check over `files` alone.
    #[derive(Deserialize)]
    struct PreviousManifest {
        version: u32,
        files: Vec<ManifestEntry>,
    }

    #[test]
    fn a_backup_with_app_preferences_still_reads_in_the_previous_format() {
        let dir = scratch("prefs-compat");
        let prefs_bytes = serde_json::to_vec(&sample_prefs()).unwrap();
        let files: &[(&str, &[u8])] = &[("config.json", b"{}")];
        let mut manifest = manifest_for(files);
        manifest.webview_prefs = Some(ManifestEntry {
            name: WEBVIEW_PREFS_NAME.to_string(),
            size: prefs_bytes.len() as u64,
            blake3: blake3::hash(&prefs_bytes).to_hex().to_string(),
            rewrap: false,
        });
        let in_zip: &[(&str, &[u8])] = &[
            ("config.json", b"{}"),
            (WEBVIEW_PREFS_NAME, prefs_bytes.as_slice()),
        ];
        let zip_path = write_archive(&dir, in_zip, &manifest);

        let mut archive = open_archive(&zip_path).unwrap();
        let mut raw = Vec::new();
        archive
            .by_name(MANIFEST_NAME)
            .unwrap()
            .read_to_end(&mut raw)
            .unwrap();
        let previous: PreviousManifest =
            serde_json::from_slice(&raw).expect("the previous manifest shape still parses");
        assert_eq!(
            previous.version, 1,
            "a format bump would make older Ember refuse it"
        );
        assert!(previous
            .files
            .iter()
            .all(|f| backup_file(&f.name).is_some() || is_legacy_ignored(&f.name)));

        let (_, entries) = read_archive(&zip_path, &dir.join("entries")).unwrap();
        assert_eq!(entries.len(), 1, "the preferences are not a profile file");
        assert_eq!(
            read_webview_prefs(&zip_path, &manifest).unwrap(),
            Some(sample_prefs())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn preferences_that_do_not_match_the_manifest_fail_the_restore() {
        let dir = scratch("prefs-tamper");
        let prefs_bytes = serde_json::to_vec(&sample_prefs()).unwrap();
        let entry = |name: &str, bytes: &[u8]| ManifestEntry {
            name: name.to_string(),
            size: bytes.len() as u64,
            blake3: blake3::hash(bytes).to_hex().to_string(),
            rewrap: false,
        };
        let mut manifest = manifest_for(&[]);
        manifest.webview_prefs = Some(entry(WEBVIEW_PREFS_NAME, b"{}"));
        let zip_path = write_archive(
            &dir,
            &[(WEBVIEW_PREFS_NAME, prefs_bytes.as_slice())],
            &manifest,
        );
        let err = read_webview_prefs(&zip_path, &manifest).unwrap_err();
        assert!(err.contains("checksum"), "{err}");

        manifest.webview_prefs = Some(entry("../../evil.json", &prefs_bytes));
        let err = read_webview_prefs(&zip_path, &manifest).unwrap_err();
        assert!(err.contains("unexpected file"), "{err}");

        let not_strings = br#"{"ember-theme":1}"#;
        manifest.webview_prefs = Some(entry(WEBVIEW_PREFS_NAME, not_strings));
        let zip_path = write_archive(&dir, &[(WEBVIEW_PREFS_NAME, &not_strings[..])], &manifest);
        let err = read_webview_prefs(&zip_path, &manifest).unwrap_err();
        assert!(err.contains("not readable"), "{err}");

        let mut oversized = entry(WEBVIEW_PREFS_NAME, &prefs_bytes);
        oversized.size = MAX_WEBVIEW_PREFS_BYTES as u64 + 1;
        manifest.webview_prefs = Some(oversized);
        let err = read_webview_prefs(&zip_path, &manifest).unwrap_err();
        assert!(err.contains("too large"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_backup_refuses_preferences_outside_the_allow_list_or_too_large() {
        assert!(validate_webview_prefs(&sample_prefs()).is_ok());
        assert!(validate_webview_prefs(&WebviewPrefs::new()).is_ok());

        let mut unknown = sample_prefs();
        unknown.insert(
            "ember.updater.dismissedUpdate".to_string(),
            "1.8.0".to_string(),
        );
        let err = validate_webview_prefs(&unknown).unwrap_err();
        assert!(err.contains("ember.updater.dismissedUpdate"), "{err}");

        let mut huge = WebviewPrefs::new();
        huge.insert(
            "search-recent-queries-v1".to_string(),
            "x".repeat(MAX_WEBVIEW_PREFS_BYTES),
        );
        let err = validate_webview_prefs(&huge).unwrap_err();
        assert!(err.contains("too large"), "{err}");
    }

    #[test]
    fn restored_preferences_keep_only_the_allow_listed_string_values() {
        let parsed = parse_webview_prefs(
            br#"{"ember-theme":"dark","__proto__":"x","ember.chatTabs.v1":"[]"}"#,
        )
        .expect("an object of strings parses");
        assert_eq!(
            parsed.into_iter().collect::<Vec<_>>(),
            vec![("ember-theme".to_string(), "dark".to_string())]
        );
        assert!(parse_webview_prefs(br#"{"ember-theme":true}"#).is_none());
        assert!(parse_webview_prefs(br#"["ember-theme","dark"]"#).is_none());
        assert!(parse_webview_prefs(b"not json").is_none());
        let mut oversized = br#"{"ember-theme":""#.to_vec();
        oversized.extend(vec![b'x'; MAX_WEBVIEW_PREFS_BYTES]);
        oversized.extend_from_slice(br#""}"#);
        assert!(parse_webview_prefs(&oversized).is_none());
    }

    #[test]
    fn a_hand_placed_handover_file_cannot_plant_unknown_keys() {
        let dir = scratch("prefs-take");
        std::fs::write(
            dir.join(RESTORED_PREFS_FILE),
            br#"{"PARAGLIDE_LOCALE":"fr","evil-key":"payload"}"#,
        )
        .unwrap();
        let taken = take_restored_prefs(&dir).expect("readable");
        assert_eq!(
            taken.get("PARAGLIDE_LOCALE").map(String::as_str),
            Some("fr")
        );
        assert!(!taken.contains_key("evil-key"));
        assert!(!dir.join(RESTORED_PREFS_FILE).exists());

        std::fs::write(dir.join(RESTORED_PREFS_FILE), b"garbage").unwrap();
        assert_eq!(take_restored_prefs(&dir), None);
        assert!(
            !dir.join(RESTORED_PREFS_FILE).exists(),
            "an unreadable handover is consumed, not retried forever"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Preferences an earlier restore left untaken belong to the profile the
    /// next restore replaces; applying them afterwards would undo part of it.
    #[test]
    fn a_restore_without_preferences_drops_an_earlier_untaken_handover() {
        let dir = scratch("prefs-stale-handover");
        std::fs::write(dir.join(RESTORED_PREFS_FILE), br#"{"ember-theme":"dark"}"#).unwrap();
        let (staging, names) = stage(&dir, &[("config.json", b"restored")]);
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        write_marker(&staging, &names);

        apply_expecting_success(&dir);
        assert_eq!(take_restored_prefs(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_preference_keys_are_unique_and_never_collide_with_profile_files() {
        let mut seen = std::collections::HashSet::new();
        for key in WEBVIEW_PREF_KEYS {
            assert!(seen.insert(*key), "{key} listed twice");
        }
        assert!(backup_file(WEBVIEW_PREFS_NAME).is_none());
        assert!(backup_file(RESTORED_PREFS_FILE).is_none());
        assert!(!is_legacy_ignored(WEBVIEW_PREFS_NAME));
    }

    #[test]
    fn a_staged_restore_reports_when_it_expires() {
        assert_eq!(
            staged_restore_expires_at(0),
            0,
            "an undated marker never expires"
        );
        assert_eq!(
            staged_restore_expires_at(1_700_000_000),
            1_700_000_000 + STAGED_RESTORE_MAX_AGE_SECS
        );
    }

    #[test]
    fn a_finished_swap_records_the_apply_as_done() {
        let dir = scratch("journal-applied");
        write_all(&dir, LIVE_PROFILE);
        let (staging, names) = stage(&dir, STAGED_PROFILE);

        swap(&dir, &staging, &names, copy_into_place).1.unwrap();
        let journal = read_apply_journal(&staging).unwrap();
        assert!(
            !journal.applied,
            "not done until the config repair and preference hand-over have run"
        );
        mark_apply_finished(&staging);
        let journal = read_apply_journal(&staging).unwrap();
        assert!(journal.applied);
        assert!(!journal.in_progress);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Staging that outlives a finished apply must not be taken for a crash of
    /// it: that re-copied the backup over the session since and deleted the
    /// live database's write-ahead log.
    #[test]
    fn a_finished_apply_whose_staging_survived_is_not_applied_again() {
        let dir = scratch("applied-journal-survives");
        write_all(&dir, LIVE_PROFILE);
        let (staging, names) = stage(&dir, STAGED_PROFILE);
        write_marker(&staging, &["identity.json", "ember.db", "config.json"]);
        swap(&dir, &staging, &names, copy_into_place).1.unwrap();
        mark_apply_finished(&staging);
        let session: &[(&str, &[u8])] = &[
            ("ember.db", b"session-db"),
            ("ember.db-wal", b"session-wal"),
            ("config.json", b"session-config"),
        ];
        write_all(&dir, session);

        assert!(!apply_pending_restore(&dir).unwrap().applied());
        assert_contents(&dir, session);
        assert!(!staging.exists(), "the leftover staging is retired");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_manifest_that_misstates_a_files_protection_is_refused() {
        for name in ["identity.json", "config.json"] {
            let dir = scratch("archive-rewrap");
            let entries: &[(&str, &[u8])] = &[(name, b"{}")];
            let mut manifest = manifest_for(entries);
            manifest.files[0].rewrap = !backup_file(name).unwrap().secret;
            let zip_path = write_archive(&dir, entries, &manifest);

            let err = read_archive(&zip_path, &dir.join("entries")).unwrap_err();
            assert!(err.contains("protection"), "{name}: {err}");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    fn database_at_schema(path: &Path, version: i64) -> Vec<u8> {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE schema_version (version INTEGER NOT NULL DEFAULT 0);
             INSERT INTO schema_version (version) VALUES ({version});"
        ))
        .unwrap();
        drop(conn);
        std::fs::read(path).unwrap()
    }

    #[test]
    fn a_database_newer_than_its_manifest_claims_is_refused_at_import() {
        let dir = scratch("archive-schema");
        let db = database_at_schema(
            &dir.join("newer.db"),
            crate::storage::database::MAX_SUPPORTED_SCHEMA_VERSION + 1,
        );
        let entries: &[(&str, &[u8])] = &[("ember.db", &db)];
        let manifest = manifest_for(entries);
        assert_eq!(manifest.schema_version, 1);
        let zip_path = write_archive(&dir, entries, &manifest);
        let staging = staging_dir(&dir);

        let err = stage_archive(&zip_path, &dir.join("scratch"), &staging).unwrap_err();
        assert!(err.contains("backup_schema_too_new"), "{err}");
        assert!(!staging.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_staged_restore_records_its_databases_own_schema_version() {
        let dir = scratch("archive-schema-real");
        let db = database_at_schema(&dir.join("older.db"), 7);
        let entries: &[(&str, &[u8])] = &[("ember.db", &db), ("config.json", b"{}")];
        let zip_path = write_archive(&dir, entries, &manifest_for(entries));
        let staging = staging_dir(&dir);

        stage_archive(&zip_path, &dir.join("scratch"), &staging).unwrap();
        assert_eq!(read_pending_marker(&staging).unwrap().schema_version, 7);
        assert_eq!(std::fs::read(staging.join("ember.db")).unwrap(), db);
        assert_eq!(std::fs::read(staging.join("config.json")).unwrap(), b"{}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_backup_whose_database_is_not_a_database_is_refused_at_import() {
        let dir = scratch("archive-not-db");
        let entries: &[(&str, &[u8])] = &[("ember.db", b"definitely not sqlite, just some bytes")];
        let zip_path = write_archive(&dir, entries, &manifest_for(entries));
        let staging = staging_dir(&dir);

        let err = stage_archive(&zip_path, &dir.join("scratch"), &staging).unwrap_err();
        assert!(err.contains("database is not readable"), "{err}");
        assert!(!staging.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_entry_failing_verification_leaves_nothing_staged() {
        let dir = scratch("archive-late-damage");
        let claimed: &[(&str, &[u8])] = &[("config.json", b"{}"), ("nodes.dat", b"contacts")];
        let shipped: &[(&str, &[u8])] = &[("config.json", b"{}"), ("nodes.dat", b"tampered")];
        let zip_path = write_archive(&dir, shipped, &manifest_for(claimed));
        let staging = staging_dir(&dir);

        let err = stage_archive(&zip_path, &dir.join("scratch"), &staging).unwrap_err();
        assert!(err.contains("checksum"), "{err}");
        assert!(!staging.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discarding_a_restore_a_rollback_left_partly_in_place_is_refused() {
        let dir = scratch("discard-unresolved");
        let (staging, _) = stage(&dir, &[("ember.db", b"restored-db")]);
        write_marker(&staging, &["ember.db"]);
        let (_, mut journal) = open_apply_journal(&dir, &staging).unwrap();
        journal.attempt = 1;
        journal.entries.push(db_entry(&[], 1));
        write_apply_journal(&staging, &journal).unwrap();

        let err = discard_staging(&staging).unwrap_err();
        assert!(err.contains("backup_discard_failed"), "{err}");
        assert!(
            pending_restore_still_staged(&dir),
            "the journal survives for the next launch"
        );
        assert!(staging.join(DISCARD_REQUESTED).exists(), "the request is kept");

        journal.entries.clear();
        write_apply_journal(&staging, &journal).unwrap();
        discard_staging(&staging).unwrap();
        assert!(!staging.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A Discard that had to wait for a restart is honoured by that restart:
    /// the interrupted apply is rolled back and the restore dropped, never
    /// applied after all.
    #[test]
    fn a_discard_asked_for_mid_rollback_is_not_applied_at_the_next_launch() {
        let dir = scratch("discard-next-launch");
        write_all(&dir, LIVE_PROFILE);
        let (staging, _) = stage(&dir, STAGED_PROFILE);
        write_marker(&staging, &["identity.json", "ember.db", "config.json"]);
        std::fs::write(staging.join(DISCARD_REQUESTED), b"1").unwrap();

        assert!(!apply_pending_restore(&dir).unwrap().applied());
        assert_contents(&dir, LIVE_PROFILE);
        assert!(!staging.exists(), "the discarded restore is gone");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discarding_the_leftovers_of_a_finished_apply_is_allowed() {
        let dir = scratch("discard-applied");
        write_all(&dir, LIVE_PROFILE);
        let (staging, names) = stage(&dir, STAGED_PROFILE);
        write_marker(&staging, &["identity.json", "ember.db", "config.json"]);
        swap(&dir, &staging, &names, copy_into_place).1.unwrap();
        mark_apply_finished(&staging);

        discard_staging(&staging).unwrap();
        assert!(!staging.exists());
        assert_contents(&dir, STAGED_PROFILE);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn source_with_database(dir: &Path) -> crate::storage::database::Database {
        crate::storage::database::Database::open_at(&dir.join("ember.db")).expect("open database")
    }

    /// A wrapped blob this account cannot unwrap on any platform.
    const UNREADABLE_SECRET: &[u8] = b"EMBRSEC1 sealed for someone else";

    #[test]
    fn an_export_leaves_out_an_unreadable_chat_key_and_reports_it() {
        let dir = scratch("export-locked-chat");
        std::fs::write(dir.join(CHAT_KEY_FILE), UNREADABLE_SECRET).unwrap();
        let db = source_with_database(&dir);
        assert!(db.chat_locked());
        std::fs::write(dir.join("config.json"), b"{}").unwrap();
        let scratch_dir = temp_dir_in(&dir, "backup-tmp").unwrap();

        let (_, manifest, skipped) = build_archive(&dir, &scratch_dir, &db, "1.3.3", None)
            .expect("a locked chat must not fail the backup");
        assert_eq!(skipped, vec![CHAT_KEY_FILE.to_string()]);
        assert!(manifest.files.iter().all(|f| f.name != CHAT_KEY_FILE));
        assert!(manifest.files.iter().any(|f| f.name == "config.json"));
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With chat unlocked the key file is the one history is sealed under, so
    /// failing to read it (a keyring locked since startup) fails the export
    /// rather than producing a backup whose history nothing can open.
    #[test]
    fn an_export_with_chat_unlocked_refuses_to_leave_the_key_out() {
        let dir = scratch("export-unlocked-chat");
        let db = source_with_database(&dir);
        assert!(!db.chat_locked());
        std::fs::write(dir.join(CHAT_KEY_FILE), UNREADABLE_SECRET).unwrap();
        let scratch_dir = temp_dir_in(&dir, "backup-tmp").unwrap();

        let Err(error) = build_archive(&dir, &scratch_dir, &db, "1.3.3", None) else {
            panic!("a working chat key that cannot be read fails the export");
        };
        assert!(error.contains(CHAT_KEY_FILE), "{error}");
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_export_that_cannot_read_the_identity_names_the_file() {
        let dir = scratch("export-locked-identity");
        let db = source_with_database(&dir);
        std::fs::write(dir.join("identity.json"), UNREADABLE_SECRET).unwrap();
        let scratch_dir = temp_dir_in(&dir, "backup-tmp").unwrap();

        let err = build_archive(&dir, &scratch_dir, &db, "1.3.3", None).unwrap_err();
        assert!(err.contains("backup_export_failed"), "{err}");
        assert!(err.contains("identity.json"), "{err}");
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_restored_database_without_its_chat_key_sets_the_live_key_aside() {
        let dir = scratch("chat-key-aside");
        write_all(
            &dir,
            &[("ember.db", b"live-db"), (CHAT_KEY_FILE, b"live-key")],
        );
        let (staging, names) = stage(&dir, &[("ember.db", b"restored-db")]);

        let (backup_dir, outcome) = swap(&dir, &staging, &names, copy_into_place);
        assert_eq!(outcome.unwrap(), 1, "the key is set aside, not restored");
        assert!(!dir.join(CHAT_KEY_FILE).exists());
        assert_contents(&backup_dir, &[(CHAT_KEY_FILE, b"live-key")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_rolled_back_restore_returns_the_chat_key_it_set_aside() {
        let dir = scratch("chat-key-aside-rollback");
        write_all(
            &dir,
            &[("ember.db", b"live-db"), (CHAT_KEY_FILE, b"live-key")],
        );
        let (staging, names) = stage(&dir, &[("ember.db", b"restored-db")]);
        let (backup_dir, outcome) = swap(&dir, &staging, &names, copy_into_place);
        outcome.unwrap();
        let mut journal = read_apply_journal(&staging).unwrap();

        roll_back_journal(&dir, &staging, &backup_dir, &mut journal);
        assert_contents(
            &dir,
            &[("ember.db", b"live-db"), (CHAT_KEY_FILE, b"live-key")],
        );
        assert!(journal.entries.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_restore_with_no_live_chat_key_records_nothing_to_set_aside() {
        let dir = scratch("chat-key-none");
        std::fs::write(dir.join("ember.db"), b"live-db").unwrap();
        let (staging, names) = stage(&dir, &[("ember.db", b"restored-db")]);

        swap(&dir, &staging, &names, copy_into_place).1.unwrap();
        let journal = read_apply_journal(&staging).unwrap();
        assert!(journal.entries.iter().all(|e| e.name != CHAT_KEY_FILE));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_files_a_restore_keeps_exclude_a_chat_key_it_sets_aside() {
        let without_key = ["ember.db", "config.json"];
        assert!(restore_sets_aside_chat_key(&without_key));
        let kept = files_kept_from_profile(&without_key);
        assert!(!kept.iter().any(|f| f == CHAT_KEY_FILE), "{kept:?}");
        assert!(kept.iter().any(|f| f == "identity.json"), "{kept:?}");
        assert!(!kept.iter().any(|f| f == "ember.db"), "{kept:?}");

        let config_only = ["config.json"];
        assert!(!restore_sets_aside_chat_key(&config_only));
        assert!(files_kept_from_profile(&config_only)
            .iter()
            .any(|f| f == CHAT_KEY_FILE));
        assert!(!restore_sets_aside_chat_key(&["ember.db", CHAT_KEY_FILE]));
    }
}
