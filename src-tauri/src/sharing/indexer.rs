use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::path::Path;
use std::sync::atomic::AtomicBool;

use tracing::{debug, info, warn};

use crate::network::ed2k::aich::compute_aich_root;
use crate::network::ed2k::hash::{ed2k_hash_file, hash_file_combined_cancellable};
use crate::search::index::normalize_path_key;
use crate::types::FileInfo;

pub struct FileIndexer;

const MAX_DISCOVERED_FILES: usize = 100_000;
/// Upper bound on the directory frontier (`pending`) during discovery.
///
/// `MAX_DISCOVERED_FILES` bounds the returned page, but the globally sorted
/// heap holds every sibling of every directory opened so far, and children are
/// enqueued before any cap check: one very wide directory (~500k entries) cost
/// ~100 MB of transient heap on top of the ~50 MB the page itself holds. Twice
/// the page cap, so no tree whose page can be returned in full ever trims.
const MAX_PENDING_FRONTIER: usize = 2 * MAX_DISCOVERED_FILES;

#[derive(Debug, Default)]
pub struct DiscoveryResult {
    pub files: Vec<FileInfo>,
    /// The folder holds more than `MAX_DISCOVERED_FILES`, so this page stopped
    /// at the cap. This is the only condition worth telling the user about.
    pub truncated: bool,
    /// This page does not represent the whole folder — either it hit the cap or
    /// it resumed from a cursor and therefore skipped everything before it.
    /// Callers must not reconcile (delete missing rows) against a partial page.
    /// Kept separate from `truncated`: every resumed page omits its prefix, so
    /// folding the two together raised the cap warning on ordinary reloads.
    pub partial: bool,
    /// Normalized path after which the next bounded scan should continue.
    /// `None` means this page reached the end of the folder.
    pub next_cursor: Option<String>,
}

/// Credential basenames that must never be published, whatever directory they
/// are found in — `SENSITIVE_DIR_NAMES` only covers the well-known homes of
/// these files, and users copy them elsewhere.
///
/// Matched as a whole basename rather than as a substring: the real secrets
/// always use the bare name (`~/.aws/credentials`, `~/.netrc`), while an
/// ordinary file that merely contains one of these words —
/// `credentials-explained.mp4`, `my_credentials_list.txt` — is legitimate
/// shareable content and stays shareable.
const SENSITIVE_SHARE_FILE_NAMES: &[&str] = &[
    "credentials",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ecdsa_sk",
    "id_ed25519",
    "id_ed25519_sk",
    ".env",
    ".netrc",
    "_netrc",
    ".npmrc",
    ".pypirc",
    ".pgpass",
    ".dockercfg",
    // Ember profile material. `is_excluded_share_location` only matches the
    // live data directory; a copy elsewhere would be hashed and announced.
    "identity.json",
    "cryptkey.dat",
    "chat-history.key",
    EMBER_DB_BASENAME,
];

/// Live SQLite file. `storage/database.rs` hard-codes this name with no
/// exported constant. Sidecars (`-wal`, `-shm`) and corrupt-open backups
/// (`ember.db.<timestamp>.corrupt`) are matched from this same base.
const EMBER_DB_BASENAME: &str = "ember.db";

/// Extensions that only ever carry private keys or key stores. Unlike the
/// basenames above these are unambiguous, so any file with one is excluded.
const SENSITIVE_SHARE_FILE_EXTENSIONS: &[&str] =
    &["pem", "ppk", "pfx", "p12", "kdbx", "keystore", "jks"];

/// Names discovery refuses to share: partial downloads, their sidecars, our own
/// temp/backup files, and credential material. Shared with the `known.met`
/// hydration path, which re-admits records without walking the directory tree —
/// a stale record written before one of these rules existed would otherwise
/// come straight back into the shared index.
pub fn is_excluded_share_file_name(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    // Windows filenames are case-insensitive, so every rule matches on the
    // lowercased name; otherwise `identity.PEM` or `Archive.BAK` slips through.
    let name = name.to_ascii_lowercase();
    if SENSITIVE_SHARE_FILE_NAMES.contains(&name.as_str())
        // `.env.local`, `.env.production`, … are the same secret with an
        // environment suffix.
        || name.starts_with(".env.")
        || is_sensitive_share_name_variant(&name, EMBER_DB_BASENAME)
        || is_sensitive_share_name_variant(&name, "identity.json")
        || is_sensitive_share_name_variant(&name, "cryptkey.dat")
        || is_sensitive_share_name_variant(&name, "chat-history.key")
    {
        return true;
    }
    if let Some(extension) = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
    {
        if SENSITIVE_SHARE_FILE_EXTENSIONS.contains(&extension.as_str()) {
            return true;
        }
    }
    name.ends_with(".part")
        || name.ends_with(".part.met")
        || name.ends_with(".met.tmp")
        || (name.starts_with('.') && name.ends_with(".tmp"))
        || name.ends_with(".migration-tmp")
        || name.ends_with(".bak")
        // A profile backup is a key container: it holds the DPAPI-unwrapped
        // identity and SecIdent keys, the chat-history key and the database.
        // Nothing stops the user pointing the export save dialog at a shared
        // folder, and once there it was hashed and announced to KAD, the eD2K
        // offer list and the Ember DHT like any other file — publicly fetchable
        // and attackable offline behind only the passphrase. Excluded by name so
        // archives written before this rule are dropped on the next scan too.
        || name.ends_with(".emberbackup")
        || name.ends_with(".partial")
}

/// App-created copies of a denylisted base (`-wal`, `.*.corrupt`,
/// `.ember-replace-bak`). The `.`/`-` separator avoids `identity.jsonl`.
fn is_sensitive_share_name_variant(name: &str, base: &str) -> bool {
    name.strip_prefix(base)
        .is_some_and(|rest| rest.starts_with('.') || rest.starts_with('-'))
}

/// True when any component of `path` is a directory discovery refuses to
/// descend into, or the path lives under our own data directory.
pub fn is_excluded_share_location(path: &Path) -> bool {
    for component in path.components() {
        if let std::path::Component::Normal(name) = component {
            if crate::sharing::is_sensitive_dir_name(&name.to_string_lossy()) {
                return true;
            }
        }
    }
    let data_dir = crate::storage::paths::resolve_data_dir();
    let data_canon = data_dir.canonicalize().unwrap_or(data_dir);
    if let Ok(canonical) = path.canonicalize() {
        if canonical == data_canon || canonical.starts_with(&data_canon) {
            return true;
        }
    }
    false
}

impl FileIndexer {
    /// Quickly discover files in a directory -- metadata only, no hashing.
    /// Files are returned with empty hash/aich_hash so they can be shown in the
    /// UI immediately.  A temporary id is generated from the path so the file
    /// can be identified until its real ED2K hash is computed.
    pub fn discover_directory(dir: &str) -> DiscoveryResult {
        Self::discover_directory_page(dir, None)
    }

    /// Discover one deterministic page of a directory. The indexer keeps a
    /// bounded, globally sorted page in memory. Cursor pages advance strictly
    /// forward; once the end is reached, a later scan resets to the beginning.
    pub fn discover_directory_page(dir: &str, cursor: Option<&str>) -> DiscoveryResult {
        let mut files = Vec::new();
        let mut truncated = false;
        let mut saw_before_cursor = false;
        let path = Path::new(dir);

        if !path.exists() || !path.is_dir() {
            warn!("Directory does not exist or is not a directory: {dir}");
            // `partial` so a folder that is temporarily unreachable (an
            // unmounted drive) is never treated as an authoritative empty
            // listing that reconciliation would delete every row against.
            return DiscoveryResult {
                files,
                truncated: false,
                partial: true,
                next_cursor: None,
            };
        }

        // Defense in depth: if a parent of the Ember data dir was somehow
        // shared, never walk into it (config, identity, known.met, …).
        let data_dir = crate::storage::paths::resolve_data_dir();
        let data_canon = data_dir.canonicalize().unwrap_or(data_dir);
        if let Ok(root_canon) = path.canonicalize() {
            if root_canon == data_canon || root_canon.starts_with(&data_canon) {
                warn!("Refusing to discover the application data directory: {dir}");
                // `partial`: this is a refusal, not an authoritative empty
                // listing, so nothing should be reconciled away because of it.
                return DiscoveryResult {
                    files,
                    truncated: false,
                    partial: true,
                    next_cursor: None,
                };
            }
        }

        info!("Discovering files in: {dir}");

        // `WalkDir::sort_by` sorts siblings, not the complete DFS traversal:
        // on Windows `a\\child` may arrive before sibling `a0`, even though
        // `a0` sorts first by our cursor key. A best-first directory queue
        // produces a globally ordered stream, making an early page cutoff
        // safe without dropping files between cursor pages.
        let mut pending: BinaryHeap<Reverse<(String, std::path::PathBuf, bool)>> =
            BinaryHeap::new();
        let enqueue_children = |directory: &Path,
                                pending: &mut BinaryHeap<
            Reverse<(String, std::path::PathBuf, bool)>,
        >| {
            let entries = match std::fs::read_dir(directory) {
                Ok(entries) => entries,
                Err(error) => {
                    warn!(
                        "Failed to read shared directory {}: {error}",
                        directory.display()
                    );
                    return false;
                }
            };
            let mut trimmed = false;
            for entry in entries {
                if pending.len() >= MAX_PENDING_FRONTIER {
                    // Stop growing the frontier; the caller marks the page
                    // `partial` so nothing is reconciled away against it.
                    trimmed = true;
                    break;
                }
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(error) => {
                        warn!("Failed to enumerate {}: {error}", directory.display());
                        continue;
                    }
                };
                let entry_path = entry.path();
                let file_type = match entry.file_type() {
                    Ok(file_type) => file_type,
                    Err(error) => {
                        warn!("Failed to inspect {}: {error}", entry_path.display());
                        continue;
                    }
                };
                if file_type.is_symlink() {
                    continue;
                }
                #[cfg(target_os = "windows")]
                {
                    use std::os::windows::fs::MetadataExt;
                    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
                    if let Ok(metadata) = entry.metadata() {
                        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                            continue;
                        }
                    }
                }
                if file_type.is_dir() {
                    if crate::sharing::is_sensitive_dir_name(&entry.file_name().to_string_lossy()) {
                        continue;
                    }
                    if let Ok(canonical) = entry_path.canonicalize() {
                        if canonical == data_canon || canonical.starts_with(&data_canon) {
                            continue;
                        }
                    }
                    let mut key = normalize_path_key(&entry_path.to_string_lossy());
                    key.push(std::path::MAIN_SEPARATOR);
                    pending.push(Reverse((key, entry_path, true)));
                } else if file_type.is_file() {
                    let key = normalize_path_key(&entry_path.to_string_lossy());
                    pending.push(Reverse((key, entry_path, false)));
                }
            }
            trimmed
        };
        let mut frontier_trimmed = enqueue_children(path, &mut pending);

        while let Some(Reverse((_key, entry_path, is_directory))) = pending.pop() {
            if is_directory {
                // A full page cannot take more files, so descending further only
                // grows the frontier. Stop and report the cap: the next scan
                // resumes from the cursor and picks these directories up there.
                if files.len() >= MAX_DISCOVERED_FILES {
                    truncated = true;
                    break;
                }
                frontier_trimmed |= enqueue_children(&entry_path, &mut pending);
                continue;
            }
            if is_excluded_share_file_name(&entry_path) {
                continue;
            }
            match Self::discover_file(&entry_path) {
                Ok(info) => {
                    let key = normalize_path_key(&info.path);
                    if cursor.is_none_or(|value| key.as_str() > value) {
                        if files.len() < MAX_DISCOVERED_FILES {
                            debug!("Discovered: {}", info.name);
                            files.push(info);
                        } else {
                            // The priority queue guarantees this is the next
                            // global path after the returned page.
                            truncated = true;
                            break;
                        }
                    } else {
                        // Never mix paths before the current cursor into this
                        // page: doing so makes the persisted cursor move
                        // backward and cycles pages. Keep the page partial so
                        // callers preserve prior index rows until the cursor
                        // explicitly resets after the end of the traversal.
                        saw_before_cursor = true;
                    }
                }
                Err(error) => {
                    warn!("Failed to discover {}: {error}", entry_path.display());
                }
            }
        }

        // A non-initial page necessarily omits every entry before its cursor,
        // so it can never be reconciled against — but that is not the cap being
        // hit, and only the cap should advance the cursor or warn the user.
        // Conflating them made every resumed page claim truncation, which both
        // pinned the "only the first N files were indexed" banner on ordinary
        // reloads and re-published a cursor for the page that finished the
        // folder, costing an extra full re-walk before the cursor could reset.
        // A trimmed frontier also means entries were never visited, so the page
        // is not an authoritative listing of the folder either.
        let partial = truncated || frontier_trimmed || (cursor.is_some() && saw_before_cursor);
        let next_cursor = truncated
            .then(|| files.last().map(|file| normalize_path_key(&file.path)))
            .flatten();
        if frontier_trimmed {
            warn!(
                "Discovery in {dir} hit the {MAX_PENDING_FRONTIER}-entry traversal \
                 limit; this page is partial"
            );
        }
        if truncated {
            warn!(
                "Discovery page in {dir} reached file cap {MAX_DISCOVERED_FILES}; a later scan resumes after {}",
                next_cursor.as_deref().unwrap_or_default()
            );
        }
        info!("Discovered {} files from {dir}", files.len());
        DiscoveryResult {
            files,
            truncated,
            partial,
            next_cursor,
        }
    }

    /// Collect file metadata WITHOUT hashing (instant).
    /// The file gets a temporary id derived from its path until hashing completes.
    pub fn discover_file(path: &Path) -> anyhow::Result<FileInfo> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.is_symlink() {
            anyhow::bail!("refusing to index symlink: {}", path.display());
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let extension = path
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();
        let modified_at = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let folder = path
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let path_str = path.to_string_lossy().to_string();
        // Use the full path (not a 64-bit hash) so the temporary id is unique
        // per file. A hashed id can collide for two distinct paths, and
        // `remove_file_by_id` removes the first match — which could drop the
        // wrong pending entry during concurrent hashing.
        let temp_id = format!("pending:{path_str}");

        Ok(FileInfo {
            id: temp_id,
            name,
            path: path_str,
            size: metadata.len(),
            hash: String::new(),
            aich_hash: String::new(),
            ember_file_hash: String::new(),
            extension,
            modified_at,
            priority: "normal".to_string(),
            requests: 0,
            accepted: 0,
            bytes_transferred: 0,
            alltime_requests: 0,
            alltime_accepted: 0,
            alltime_transferred: 0,
            complete_sources: 0,
            folder,
            shared: true,
            // Newly discovered files are public. Any persisted friends-only
            // restriction is reapplied from known.met once the hash is known.
            friends_only: false,
            shared_kad: false,
            shared_ed2k: false,
            shared_ember: false,
        })
    }

    #[allow(dead_code)]
    pub fn hash_file(path: &Path) -> anyhow::Result<(String, String)> {
        let ed2k = ed2k_hash_file(path)?;
        // AICH failures must propagate: an empty AICH hex would look like a
        // legitimate (empty-file) hash to callers and be served to peers as
        // authoritative recovery data, which is dangerous.
        let aich = compute_aich_root(path)
            .map(hex::encode)
            .map_err(|e| anyhow::anyhow!("AICH hash failed for {}: {e}", path.display()))?;
        Ok((ed2k, aich))
    }

    /// Cancellable version -- computes ed2k, AICH, part hashes, and ember
    /// BLAKE3 (plus size/mtime) in a single pass for `known.met`.
    pub fn hash_file_cancellable(
        path: &Path,
        cancelled: &AtomicBool,
    ) -> anyhow::Result<(String, String, Vec<[u8; 16]>, String, u64, i64)> {
        let before = std::fs::symlink_metadata(path)?;
        if before.is_symlink() {
            anyhow::bail!("refusing to hash symlink: {}", path.display());
        }
        let before_modified = before.modified().ok();
        let (ed2k, aich, part_hashes, ember) = hash_file_combined_cancellable(path, cancelled)?;
        let after = std::fs::symlink_metadata(path)?;
        let after_modified = after.modified().ok();
        if before.len() != after.len() || before_modified != after_modified {
            anyhow::bail!("file changed while hashing: {}", path.display());
        }
        let modified_at = after_modified
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
        Ok((ed2k, aich, part_hashes, ember, after.len(), modified_at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excludes_credential_files() {
        for name in [
            "credentials",
            "id_rsa",
            "id_ed25519",
            ".env",
            ".env.production",
            ".netrc",
            "_netrc",
            ".npmrc",
            "server.pem",
            "backup.kdbx",
            "release.jks",
            "debug.keystore",
            "client.PFX",
            "identity.json",
            "Identity.JSON",
            "cryptkey.dat",
            "chat-history.key",
            "ember.db",
            "ember.db-wal",
            "ember.db-shm",
            "Ember.DB-WAL",
            "ember.db.20260819120000.corrupt",
            "ember.db.20260819120000.1.corrupt",
            "Ember.DB.20260819120000.corrupt",
            "ember.db.20260819120000.corrupt-wal",
            "identity.json.corrupt",
            "Identity.JSON.corrupt",
            "identity.json.ember-replace-bak",
            "cryptkey.dat.20260819120000.corrupt",
            "chat-history.key.ember-replace-bak",
        ] {
            assert!(
                is_excluded_share_file_name(&Path::new(r"C:\Users\me\Documents").join(name)),
                "{name} must never be shared"
            );
        }
    }

    #[test]
    fn excludes_partials_and_backups_case_insensitively() {
        assert!(is_excluded_share_file_name(Path::new("movie.avi.part")));
        assert!(is_excluded_share_file_name(Path::new(
            "profile.emberbackup"
        )));
        assert!(is_excluded_share_file_name(Path::new("Archive.BAK")));
    }

    #[test]
    fn allows_ordinary_files_that_merely_mention_credentials() {
        // Whole-basename (or an app-owned base plus `.`/`-`), so real content
        // that merely contains these words stays shareable.
        for name in [
            "credentials-explained.mp4",
            "my_credentials_list.txt",
            "id_rsa.pub",
            "environment.txt",
            "keynote deck.key",
            "ember.database.sql",
            "identity.jsonl",
        ] {
            assert!(
                !is_excluded_share_file_name(&Path::new(r"C:\Users\me\Videos").join(name)),
                "{name} is ordinary content and must stay shareable"
            );
        }
    }
}
