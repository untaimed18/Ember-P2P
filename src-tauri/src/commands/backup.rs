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
const BACKUP_EXTENSION: &str = "emberbackup";

/// Per-entry and whole-archive ceilings on what a restore will unpack. The
/// declared sizes in a zip's central directory are attacker-controlled, so
/// these are enforced against the bytes actually read.
const MAX_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// A file the backup carries.
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
    // Per-file share decisions and the filesystem allow-list.
    plain("share_intent.json"),
    plain("approved_roots.json"),
];

fn backup_file(name: &str) -> Option<&'static BackupFile> {
    BACKUP_FILES.iter().find(|f| f.name == name)
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
}

#[derive(Serialize)]
pub struct BackupSummary {
    pub path: String,
    pub bytes: u64,
    pub files: usize,
    pub created_at: i64,
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
}

#[derive(Serialize)]
pub struct RestoreSummary {
    /// Files staged for the swap at next launch.
    pub staged: Vec<String>,
    /// Files this build knows about that the backup did not carry.
    pub missing: Vec<String>,
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
    let mut out = std::fs::File::create(dest).map_err(io)?;
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

/// Build the plaintext zip: `manifest.json` plus one entry per present file.
fn build_archive(
    data_dir: &Path,
    scratch: &Path,
    db: &crate::storage::database::Database,
    app_version: &str,
) -> Result<(PathBuf, Manifest), String> {
    let zip_path = scratch.join("payload.zip");
    let file = std::fs::File::create(&zip_path)
        .map_err(|e| coded_ctx("backup_export_failed", "Failed to create the archive", e))?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    let mut entries = Vec::new();
    for spec in BACKUP_FILES {
        let bytes = if spec.database {
            let snapshot = scratch.join("ember.db.snapshot");
            db.snapshot_to(&snapshot).map_err(|e| {
                coded_ctx("backup_export_failed", "Failed to snapshot the database", e)
            })?;
            let bytes = std::fs::read(&snapshot)
                .map_err(|e| coded_ctx("backup_export_failed", "Failed to read the snapshot", e))?;
            let _ = std::fs::remove_file(&snapshot);
            bytes
        } else {
            match std::fs::read(data_dir.join(spec.name)) {
                Ok(raw) if spec.secret => {
                    // Unwrap here or the restored file is unreadable to any
                    // other Windows account, which is the whole point of the
                    // feature.
                    secret_store::unprotect(&raw).map_err(|e| {
                        coded_ctx(
                            "backup_export_failed",
                            "Could not read protected key material for backup",
                            e,
                        )
                    })?
                }
                Ok(raw) => raw,
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

    let manifest = Manifest {
        version: FORMAT_VERSION,
        app_version: app_version.to_string(),
        created_at: chrono::Utc::now().timestamp(),
        schema_version: db.schema_version(),
        files: entries,
    };
    let manifest_json = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| coded_ctx("backup_export_failed", "Failed to write the manifest", e))?;
    zip.start_file(MANIFEST_NAME, options)
        .map_err(|e| coded_ctx("backup_export_failed", "Failed to write the manifest", e))?;
    zip.write_all(&manifest_json)
        .map_err(|e| coded_ctx("backup_export_failed", "Failed to write the manifest", e))?;
    zip.finish()
        .map_err(|e| coded_ctx("backup_export_failed", "Failed to finish the archive", e))?;
    Ok((zip_path, manifest))
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

/// Reject paths that are obviously not a user's own document location. The
/// user picked this path in a save dialog, so this guards against a degenerate
/// or hostile frontend caller rather than against the user.
fn validate_destination(raw: &str) -> Result<PathBuf, String> {
    if raw.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "backup_invalid_destination",
            "File path is too long",
            format!("{MAX_PATH_LEN} bytes"),
        ));
    }
    let path = PathBuf::from(raw);
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

/// Sibling scratch name for an in-progress export. Sits next to the
/// destination so the final step is a same-volume rename.
fn partial_export_path(dest: &Path) -> PathBuf {
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "backup".to_string());
    dest.with_file_name(format!(".{name}.{}.partial", std::process::id()))
}

fn validate_source(raw: &str) -> Result<PathBuf, String> {
    if raw.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "backup_invalid_source",
            "File path is too long",
            format!("{MAX_PATH_LEN} bytes"),
        ));
    }
    let path = PathBuf::from(raw);
    let canonical = path
        .canonicalize()
        .map_err(|e| coded_ctx("backup_invalid_source", "Cannot open that file", e))?;
    if !canonical.is_file() {
        return Err(coded("backup_invalid_source", "That is not a backup file"));
    }
    Ok(canonical)
}

#[tauri::command]
pub async fn export_backup(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    dest_path: String,
    passphrase: String,
) -> Result<BackupSummary, String> {
    validate_passphrase(&passphrase)?;
    let dest = validate_destination(&dest_path)?;
    let db = state.db.clone();
    let app_version = app.package_info().version.to_string();
    let data_dir = paths::resolve_data_dir_with_app(&app);
    let passphrase = Zeroizing::new(passphrase);

    tokio::task::spawn_blocking(move || {
        let scratch = temp_dir_in(&data_dir, "backup-tmp")?;
        let partial = partial_export_path(&dest);
        let result = (|| {
            let (zip_path, manifest) = build_archive(&data_dir, &scratch, &db, &app_version)?;
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

/// Read and verify the manifest and every entry of a decrypted archive,
/// returning the entries in manifest order with their bytes.
///
/// Everything is held in memory on purpose: nothing is written to the staging
/// directory until the whole archive has verified, so a backup that turns out
/// to be damaged half way through cannot leave a partial profile staged. The
/// contents are profile state rather than media, and `MAX_TOTAL_BYTES` bounds
/// the worst case.
fn read_archive(zip_path: &Path) -> Result<(Manifest, Vec<(ManifestEntry, Vec<u8>)>), String> {
    let mut archive = open_archive(zip_path)?;
    let manifest = read_manifest(&mut archive)?;

    let mut total = 0u64;
    let mut out = Vec::new();
    for entry in &manifest.files {
        // The allow-list is what keeps a crafted archive from naming
        // `..\..\something` or any path outside the data directory.
        if backup_file(&entry.name).is_none() {
            return Err(coded_ctx(
                "backup_corrupt_archive",
                "The backup contains an unexpected file",
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
        let mut bytes = Vec::new();
        // Cap the bytes actually decompressed: the declared size above is
        // metadata the archive controls, and deflate keeps going regardless.
        (&mut zipped)
            .take(MAX_ENTRY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| {
                coded_ctx(
                    "backup_corrupt_archive",
                    format!("Failed to read {}", entry.name),
                    e,
                )
            })?;
        if bytes.len() as u64 > MAX_ENTRY_BYTES {
            return Err(coded_ctx(
                "backup_corrupt_archive",
                "The backup contains a file that is too large",
                &entry.name,
            ));
        }
        total = total.saturating_add(bytes.len() as u64);
        if total > MAX_TOTAL_BYTES {
            return Err(coded("backup_corrupt_archive", "The backup is too large"));
        }
        if bytes.len() as u64 != entry.size
            || blake3::hash(&bytes).to_hex().to_string() != entry.blake3
        {
            return Err(coded_ctx(
                "backup_corrupt_archive",
                "A file in the backup does not match its checksum",
                &entry.name,
            ));
        }
        out.push((
            ManifestEntry {
                name: entry.name.clone(),
                size: entry.size,
                blake3: entry.blake3.clone(),
                rewrap: entry.rewrap,
            },
            bytes,
        ));
    }
    Ok((manifest, out))
}

fn staging_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(STAGING_DIR)
}

/// The marker a completed staging run leaves behind, or `None` when there is
/// nothing trustworthy to apply. Written last by [`stage_restore`], so its
/// absence means the staging directory is incomplete.
fn read_pending_marker(staging: &Path) -> Option<PendingRestore> {
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
    pub app_version: String,
    pub files: usize,
}

#[tauri::command]
pub async fn pending_restore_status(app: tauri::AppHandle) -> Result<PendingRestoreStatus, String> {
    let data_dir = paths::resolve_data_dir_with_app(&app);
    let pending = read_pending_marker(&staging_dir(&data_dir));
    Ok(match pending {
        Some(p) => PendingRestoreStatus {
            pending: true,
            staged_at: p.staged_at,
            app_version: p.source_app_version,
            files: p.files.len(),
        },
        None => PendingRestoreStatus {
            pending: false,
            staged_at: 0,
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
    tokio::task::spawn_blocking(move || {
        std::fs::remove_dir_all(&staging).map_err(|e| {
            coded_ctx(
                "backup_discard_failed",
                "Failed to discard the staged restore",
                e,
            )
        })
    })
    .await
    .map_err(|e| coded_ctx("backup_task_failed", "Restore task failed", e))?
}

#[tauri::command]
pub async fn preview_backup(
    app: tauri::AppHandle,
    source_path: String,
    passphrase: String,
) -> Result<BackupPreview, String> {
    let source = validate_source(&source_path)?;
    let data_dir = paths::resolve_data_dir_with_app(&app);
    let passphrase = Zeroizing::new(passphrase);

    tokio::task::spawn_blocking(move || {
        let scratch = temp_dir_in(&data_dir, "restore-tmp")?;
        let result = (|| {
            let zip_path = scratch.join("payload.zip");
            decrypt_stream(&source, &zip_path, &passphrase)?;
            let manifest = read_manifest(&mut open_archive(&zip_path)?)?;
            let total_bytes = manifest.files.iter().map(|f| f.size).sum();
            Ok(BackupPreview {
                app_version: manifest.app_version.clone(),
                created_at: manifest.created_at,
                schema_version: manifest.schema_version,
                files: manifest.files.iter().map(|f| f.name.clone()).collect(),
                total_bytes,
                includes_identity: manifest.files.iter().any(|f| f.name == "identity.json"),
                schema_too_new: manifest.schema_version
                    > crate::storage::database::MAX_SUPPORTED_SCHEMA_VERSION,
            })
        })();
        let _ = std::fs::remove_dir_all(&scratch);
        result
    })
    .await
    .map_err(|e| coded_ctx("backup_task_failed", "Restore task failed", e))?
}

#[tauri::command]
pub async fn import_backup(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    source_path: String,
    passphrase: String,
) -> Result<RestoreSummary, String> {
    // `restore-pending` has a fixed name because startup must discover it
    // before the runtime state is initialized. Serialize the full staging
    // transaction so independent IPC calls cannot interleave files or delete
    // one another's incomplete directory.
    let _restore_import_guard = state.restore_import_lock.lock().await;
    let source = validate_source(&source_path)?;
    let data_dir = paths::resolve_data_dir_with_app(&app);
    let passphrase = Zeroizing::new(passphrase);

    tokio::task::spawn_blocking(move || {
        let staging = staging_dir(&data_dir);
        if staging.exists() {
            // Only a directory with a readable marker is a real pending
            // restore. Debris from an import that died mid-write would
            // otherwise block every later attempt until the app restarted,
            // and with a message claiming a restore was queued when none was.
            if read_pending_marker(&staging).is_some() {
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
            let (manifest, entries) = read_archive(&zip_path)?;
            if manifest.schema_version > crate::storage::database::MAX_SUPPORTED_SCHEMA_VERSION {
                return Err(coded_ctx(
                    "backup_schema_too_new",
                    "This backup was made by a newer version of Ember",
                    format!(
                        "database v{} (this build supports v{})",
                        manifest.schema_version,
                        crate::storage::database::MAX_SUPPORTED_SCHEMA_VERSION
                    ),
                ));
            }
            stage_restore(&staging, &manifest, entries)
        })();
        let _ = std::fs::remove_dir_all(&scratch);
        if result.is_err() {
            // A half-written staging directory must never be applied.
            let _ = std::fs::remove_dir_all(&staging);
        }
        result
    })
    .await
    .map_err(|e| coded_ctx("backup_task_failed", "Restore task failed", e))?
}

/// Write the restored files into the staging directory, re-wrapping secrets
/// for the account that will run the app after the restart.
fn stage_restore(
    staging: &Path,
    manifest: &Manifest,
    entries: Vec<(ManifestEntry, Vec<u8>)>,
) -> Result<RestoreSummary, String> {
    std::fs::create_dir_all(staging)
        .map_err(|e| coded_ctx("backup_restore_failed", "Failed to stage the restore", e))?;
    crate::security::restrict_file_permissions(staging);

    let mut staged = Vec::new();
    for (entry, bytes) in entries {
        let payload = if entry.rewrap {
            // Bind the key material to this machine and account. A DPAPI
            // failure has to fail the restore: writing it in the clear would
            // leave the identity readable to anything that can read the file,
            // and `identity.protected` would then refuse the next launch.
            Zeroizing::new(secret_store::protect(&bytes).map_err(|e| {
                coded_ctx(
                    "backup_restore_failed",
                    "Could not protect the restored key material",
                    e,
                )
            })?)
        } else {
            Zeroizing::new(bytes)
        };
        let target = staging.join(&entry.name);
        crate::security::atomic_write(&target, &payload, true).map_err(|e| {
            coded_ctx(
                "backup_restore_failed",
                format!("Failed to stage {}", entry.name),
                e,
            )
        })?;
        staged.push(entry.name.clone());
    }

    let pending = PendingRestore {
        version: FORMAT_VERSION,
        staged_at: chrono::Utc::now().timestamp(),
        source_app_version: manifest.app_version.clone(),
        schema_version: manifest.schema_version,
        files: staged.clone(),
    };
    let marker = serde_json::to_vec_pretty(&pending)
        .map_err(|e| coded_ctx("backup_restore_failed", "Failed to stage the restore", e))?;
    // Written last: its presence is what tells the next launch the staging
    // directory is complete and safe to apply.
    crate::security::atomic_write(&staging.join(STAGING_MARKER), &marker, true)
        .map_err(|e| coded_ctx("backup_restore_failed", "Failed to stage the restore", e))?;

    let missing = BACKUP_FILES
        .iter()
        .map(|f| f.name.to_string())
        .filter(|name| !staged.contains(name))
        .collect();
    let staged_len = staged.len();
    let summary = RestoreSummary {
        staged,
        missing,
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

/// Move `staged` onto `live`, falling back to a copy.
///
/// A rename within one directory should not fail, but a scanner or indexer
/// holding the freshly written file for a moment can make it fail on Windows -
/// and by this point the file being replaced has already been moved aside, so
/// giving up cheaply is expensive.
fn swap_into_place(staged: &Path, live: &Path) -> std::io::Result<()> {
    match std::fs::rename(staged, live) {
        Ok(()) => Ok(()),
        Err(rename_error) => {
            std::fs::copy(staged, live).map_err(|_| rename_error)?;
            let _ = std::fs::remove_file(staged);
            Ok(())
        }
    }
}

/// Swap a staged restore into place. Called during startup before the
/// database, config or identity are opened, because every one of those files
/// is held open (or cached in memory) once the app is running.
///
/// Displaced originals are moved to `pre-restore-<timestamp>/` rather than
/// deleted: a restore from the wrong backup is otherwise unrecoverable. Only
/// files the backup actually carried are touched.
pub fn apply_pending_restore(data_dir: &Path) -> std::io::Result<Option<PathBuf>> {
    let staging = staging_dir(data_dir);
    let marker = staging.join(STAGING_MARKER);
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
        return Ok(None);
    }
    let pending: PendingRestore = match read_pending_marker(&staging) {
        Some(p) => p,
        None => {
            tracing::warn!("Staged restore marker is unreadable; discarding the staged files");
            let _ = std::fs::remove_dir_all(&staging);
            return Ok(None);
        }
    };

    // A marker without a timestamp (an older staging run) is not judged on age.
    let age_secs = chrono::Utc::now()
        .timestamp()
        .saturating_sub(pending.staged_at);
    if pending.staged_at > 0 && age_secs > STAGED_RESTORE_MAX_AGE_SECS {
        tracing::error!(
            "Discarding a staged restore from a backup made by Ember {}: it was prepared {} days \
             ago and is too old to apply safely over the profile in use since. Import the backup \
             again from Settings > Backup if it is still what you want.",
            pending.source_app_version,
            age_secs / 86_400
        );
        let _ = std::fs::remove_dir_all(&staging);
        return Ok(None);
    }

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
        return Ok(None);
    }

    let backup_dir = data_dir.join(format!("pre-restore-{}", chrono::Utc::now().timestamp()));
    std::fs::create_dir_all(&backup_dir)?;
    crate::security::restrict_file_permissions(&backup_dir);

    let mut applied = 0usize;
    for name in &pending.files {
        if backup_file(name).is_none() {
            tracing::warn!("Ignoring unexpected staged file {name}");
            continue;
        }
        let staged = staging.join(name);
        if !staged.is_file() {
            continue;
        }
        let live = data_dir.join(name);
        let mut displaced = false;
        if live.exists() {
            if let Err(e) = std::fs::rename(&live, backup_dir.join(name)) {
                tracing::error!(
                    "Restore skipped for {name}: could not move the current file aside ({e})"
                );
                continue;
            }
            displaced = true;
        }
        // The restored database is a `VACUUM INTO` snapshot with no
        // write-ahead log. Leaving the previous WAL/SHM sidecars in place
        // would have SQLite replay an unrelated log over it.
        if name == "ember.db" {
            for suffix in ["-wal", "-shm"] {
                let mut sidecar = live.as_os_str().to_os_string();
                sidecar.push(suffix);
                let sidecar = PathBuf::from(sidecar);
                if sidecar.exists() {
                    let stashed = backup_dir.join(format!("{name}{suffix}"));
                    if let Err(e) = std::fs::rename(&sidecar, &stashed) {
                        tracing::warn!("Could not move {} aside: {e}", sidecar.display());
                        let _ = std::fs::remove_file(&sidecar);
                    }
                }
            }
        }
        match swap_into_place(&staged, &live) {
            Ok(()) => {
                crate::security::restrict_file_permissions(&live);
                applied += 1;
            }
            Err(e) => {
                tracing::error!("Failed to restore {name}: {e}");
                // The file being replaced was moved aside a moment ago, and the
                // staging directory is deleted below. Without putting it back,
                // the data directory would be left with no copy of the file at
                // all - for `identity.json` that means the next launch quietly
                // generates a new identity, losing the user hash and credits
                // this whole feature exists to preserve.
                if displaced {
                    match std::fs::rename(backup_dir.join(name), &live) {
                        Ok(()) => tracing::warn!(
                            "Kept the existing {name}: the copy from the backup could not be put in place"
                        ),
                        Err(back) => tracing::error!(
                            "Could not put the previous {name} back ({back}); recover it from {}",
                            backup_dir.display()
                        ),
                    }
                }
            }
        }
    }

    let _ = std::fs::remove_dir_all(&staging);
    if pending.files.iter().any(|name| name == "config.json") {
        sanitize_restored_config(data_dir);
    }
    tracing::warn!(
        "Applied a staged restore of {applied} file(s) from a backup made by Ember {}; the \
         previous files are preserved in {}",
        pending.source_app_version,
        backup_dir.display()
    );
    Ok(Some(backup_dir))
}

/// Repair paths in a restored config that only made sense on the machine the
/// backup came from.
///
/// Startup creates the download folder and refuses to continue if it cannot,
/// so a backup taken on a machine that downloaded to a second drive would
/// otherwise leave Ember unable to launch at all on a machine without that
/// drive, on the very path this feature exists to serve.
///
/// Only the download folder is touched. Shared folders that are missing right
/// now are left alone on purpose: `initialize_approved_roots` already treats an
/// absent root as offline and keeps its approval, so dropping them here would
/// silently delete a user's shares whenever they restored with an external
/// drive unplugged.
///
/// Edited as raw JSON on purpose: this runs before the config is loaded, and
/// round-tripping it through AppSettings here would rewrite fields the
/// loader's own repair pass owns.
fn sanitize_restored_config(data_dir: &Path) {
    let path = data_dir.join("config.json");
    let Ok(raw) = std::fs::read(&path) else {
        return;
    };
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&raw) else {
        return;
    };
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    let mut changed = false;

    if let Some(folder) = obj
        .get("download_folder")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
    {
        if !folder.is_empty() && std::fs::create_dir_all(Path::new(&folder)).is_err() {
            let fallback = directories::UserDirs::new()
                .and_then(|dirs| dirs.download_dir().map(|d| d.join("Ember")))
                .unwrap_or_else(|| data_dir.join("Downloads"));
            tracing::warn!(
                "Restored download folder {folder} cannot be created on this machine; using {} instead",
                fallback.display()
            );
            let _ = std::fs::create_dir_all(&fallback);
            obj.insert(
                "download_folder".to_string(),
                serde_json::Value::String(fallback.to_string_lossy().to_string()),
            );
            changed = true;
        }
    }

    if !changed {
        return;
    }
    match serde_json::to_vec_pretty(&value) {
        Ok(data) => {
            if let Err(e) = crate::security::atomic_write(&path, &data, true) {
                tracing::error!("Failed to write the repaired config after a restore: {e}");
            }
        }
        Err(e) => tracing::error!("Failed to serialize the repaired config after a restore: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let err = validate_destination(&bad.to_string_lossy()).unwrap_err();
        assert!(err.contains("backup_invalid_destination"), "{err}");
        let good = dir.join("profile.emberbackup");
        assert!(validate_destination(&good.to_string_lossy()).is_ok());
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
        assert!(apply_pending_restore(&dir).unwrap().is_none());
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
        };
        std::fs::write(
            staging.join(STAGING_MARKER),
            serde_json::to_vec(&pending).unwrap(),
        )
        .unwrap();

        let preserved = apply_pending_restore(&dir).unwrap().unwrap();
        assert_eq!(std::fs::read(dir.join("config.json")).unwrap(), b"restored");
        assert_eq!(
            std::fs::read(preserved.join("config.json")).unwrap(),
            b"live"
        );
        assert!(!staging.exists());
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
        };
        std::fs::write(
            staging.join(STAGING_MARKER),
            serde_json::to_vec(&pending).unwrap(),
        )
        .unwrap();

        assert!(apply_pending_restore(&dir).unwrap().is_none());
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
        };
        std::fs::write(
            staging.join(STAGING_MARKER),
            serde_json::to_vec(&pending).unwrap(),
        )
        .unwrap();

        assert!(apply_pending_restore(&dir).unwrap().is_none());
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
        assert!(swap_into_place(&dir.join("missing.staged"), &live).is_err());
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
        });
        std::fs::write(
            dir.join("config.json"),
            serde_json::to_vec_pretty(&config).unwrap(),
        )
        .unwrap();

        sanitize_restored_config(&dir);

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
        }
    }

    #[test]
    fn a_well_formed_archive_reads_back_its_entries() {
        let dir = scratch("archive-ok");
        let entries: &[(&str, &[u8])] = &[("config.json", b"{}"), ("nodes.dat", b"contacts")];
        let zip_path = write_archive(&dir, entries, &manifest_for(entries));

        let (manifest, read) = read_archive(&zip_path).unwrap();
        assert_eq!(manifest.app_version, "1.3.3");
        assert_eq!(read.len(), 2);
        assert_eq!(read[0].0.name, "config.json");
        assert_eq!(read[0].1, b"{}");
        assert_eq!(read[1].1, b"contacts");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_entry_outside_the_allow_list_is_refused() {
        let dir = scratch("archive-allowlist");
        let entries: &[(&str, &[u8])] = &[("evil.exe", b"payload")];
        let zip_path = write_archive(&dir, entries, &manifest_for(entries));

        let err = read_archive(&zip_path).unwrap_err();
        // Assert the reason, not just that it failed: a plain "missing entry"
        // rejection would pass a looser check while leaving the allow-list
        // itself unexercised.
        assert!(err.contains("unexpected file"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_traversal_name_never_reaches_the_filesystem() {
        let dir = scratch("archive-traversal");
        let entries: &[(&str, &[u8])] = &[("../../evil.exe", b"payload")];
        let zip_path = write_archive(&dir, entries, &manifest_for(entries));

        assert!(read_archive(&zip_path).is_err());
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

        let err = read_archive(&zip_path).unwrap_err();
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

        let err = read_archive(&zip_path).unwrap_err();
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

        let err = read_archive(&zip_path).unwrap_err();
        assert!(err.contains("backup_corrupt_archive"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_manifest_entry_missing_from_the_zip_is_refused() {
        let dir = scratch("archive-missing");
        let claimed: &[(&str, &[u8])] = &[("config.json", b"{}"), ("nodes.dat", b"contacts")];
        // Manifest promises two files, the zip only carries one.
        let zip_path = write_archive(&dir, &claimed[..1], &manifest_for(claimed));

        let err = read_archive(&zip_path).unwrap_err();
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
        let (zip_path, manifest) =
            build_archive(&source_dir, &scratch_dir, &db, "1.3.3").expect("build archive");
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
        let (read_manifest, entries) = read_archive(&decrypted).expect("verify archive");
        assert_eq!(read_manifest.app_version, "1.3.3");
        let staging = staging_dir(&restore_dir);
        let summary = stage_restore(&staging, &read_manifest, entries).expect("stage");
        assert!(summary.staged.iter().any(|n| n == "ember.db"));
        let _ = std::fs::remove_dir_all(&restore_scratch);

        // Nothing is in place until the swap runs, which is what startup does.
        assert!(!restore_dir.join("ember.db").exists());
        let preserved = apply_pending_restore(&restore_dir)
            .expect("apply")
            .expect("a restore was applied");
        assert!(!staging.exists(), "the staging directory is consumed");

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
            secret_store::unprotect(&restored_identity).expect("unprotect restored identity"),
            identity_plaintext
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
}
