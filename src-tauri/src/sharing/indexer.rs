use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64};

use tracing::{debug, info, warn};

use crate::network::ed2k::hash::hash_file_combined_cancellable;
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
/// Directory entries one [`FileIndexer::measure_directories`] call looks at
/// before it settles for a lower bound. Far past what the time budget usually
/// allows on a local disk; it bounds the walk on a filesystem that answers
/// `read_dir` faster than it is worth counting.
const MAX_MEASURED_ENTRIES: u64 = 2_000_000;

/// Files and bytes a share would offer, as counted ahead of the scan.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryMeasure {
    pub files: u64,
    pub bytes: u64,
    /// Every entry was counted. False when the walk was cancelled or ran out
    /// of budget, which makes `files` and `bytes` lower bounds.
    pub complete: bool,
}

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

/// Whether an allowlist of `normalize_path_key` forms offers the file or
/// folder at `key`: it is listed, or sits inside a listed folder.
pub(crate) fn allowlist_permits(allowed: &HashSet<String>, key: &str) -> bool {
    allowed.contains(key)
        || key
            .rmatch_indices(std::path::MAIN_SEPARATOR)
            .any(|(at, _)| allowed.contains(&key[..at]))
}

/// What discovery may return from a folder shared with only some of its
/// contents: the allowlisted files and folders, reached through the folders
/// that lead to them. Nothing else in the folder is offered, so walking and
/// hashing the rest of its tree only cost time and filled the Library with
/// files that could not be shared.
#[derive(Debug, Clone)]
pub struct DiscoveryScope {
    entries: HashSet<String>,
    /// Every folder with an entry somewhere below it.
    ancestors: HashSet<String>,
}

impl DiscoveryScope {
    /// The scope for `root` from the folder allowlists, keyed as settings keys
    /// them. `None` for a folder shared whole.
    pub fn for_root(
        root: &str,
        allowlists: &std::collections::HashMap<String, Vec<String>>,
    ) -> Option<Self> {
        let entries = allowlists.get(&normalize_path_key(root))?;
        Some(Self::new(entries))
    }

    pub fn new(entries: &[String]) -> Self {
        let entries: HashSet<String> = entries.iter().map(|entry| normalize_path_key(entry)).collect();
        let mut ancestors = HashSet::new();
        for entry in &entries {
            for (at, _) in entry.rmatch_indices(std::path::MAIN_SEPARATOR) {
                if !ancestors.insert(entry[..at].to_string()) {
                    break;
                }
            }
        }
        Self { entries, ancestors }
    }

    fn admits_file(&self, key: &str) -> bool {
        allowlist_permits(&self.entries, key)
    }

    fn admits_dir(&self, key: &str) -> bool {
        self.ancestors.contains(key) || allowlist_permits(&self.entries, key)
    }
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
    // Plaintext tokens and shell histories (which routinely hold pasted
    // secrets) that live directly in a home folder.
    ".git-credentials",
    "credentials.toml",
    ".my.cnf",
    ".vault-token",
    ".s3cfg",
    ".bash_history",
    ".zsh_history",
    // fish keeps its under `~/.local/share/fish`.
    "fish_history",
    ".python_history",
    ".psql_history",
    ".mysql_history",
    ".node_repl_history",
    // Browser credential and cookie stores, wherever the profile sits
    // (including Flatpak's `~/.var/app/*`).
    "logins.json",
    "key3.db",
    "key4.db",
    "cookies.sqlite",
    "login data",
    "web data",
    "cookies",
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
/// `keyring` is a GNOME keyring and `kwl` a KDE wallet.
const SENSITIVE_SHARE_FILE_EXTENSIONS: &[&str] =
    &["pem", "ppk", "pfx", "p12", "kdbx", "keystore", "jks", "keyring", "kwl"];

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
        // Another program's in-progress write: a browser download, a torrent
        // client's incomplete file, an Office lock, a save-in-progress temp.
        // Each ends in a rename to the real name (or a delete). `.tmp` is the
        // broad one — a user's own `.tmp` file stops being shareable too,
        // which is rare and costs little next to hashing and announcing a file
        // that is only ever a half-written copy of something else.
        || name.ends_with(".tmp")
        || name.ends_with(".crdownload")
        || name.ends_with(".!qb")
        || name.starts_with("~$")
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

/// Our own data directory, canonicalized once per process.
///
/// `is_excluded_share_location` runs inside the filesystem-watcher callback,
/// which is the thread draining `ReadDirectoryChangesW`. That buffer is a fixed
/// size and a slow handler is how its events get dropped — which would leave
/// files copied into a shared folder unindexed, and so unservable, until a
/// manual reload. Resolving the directory per event put a known-folder lookup
/// and a second `canonicalize` in front of every one. The path is fixed for the
/// life of the process: the env override is read at startup and the OS
/// per-user location does not move.
fn canonical_data_dir() -> &'static Path {
    static CANONICAL: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    CANONICAL.get_or_init(|| {
        let dir = crate::storage::paths::resolve_data_dir();
        dir.canonicalize().unwrap_or(dir)
    })
}

/// True when any component of `path` is a directory discovery refuses to
/// descend into, or the path lives under our own data directory.
pub fn is_excluded_share_location(path: &Path) -> bool {
    for component in path.components() {
        if let std::path::Component::Normal(name) = component {
            if crate::sharing::is_index_skip_dir_name(&name.to_string_lossy()) {
                return true;
            }
        }
    }
    let data_canon = canonical_data_dir();
    if let Ok(canonical) = path.canonicalize() {
        if canonical == data_canon || canonical.starts_with(data_canon) {
            return true;
        }
    }
    false
}

/// Entries discovery refuses on sight, whatever their name: reparse points,
/// and what Windows marks hidden *and* system — how it flags what it owns on a
/// volume (recycle bins, restore points, desktop.ini). A shared drive root
/// walks straight into them.
#[cfg(target_os = "windows")]
fn walk_skips_metadata(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const HIDDEN_SYSTEM: u32 = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
    let attributes = metadata.file_attributes();
    attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || attributes & HIDDEN_SYSTEM == HIDDEN_SYSTEM
}

#[cfg(not(target_os = "windows"))]
fn walk_skips_metadata(_metadata: &std::fs::Metadata) -> bool {
    false
}

/// True when every key under the directory keyed `dir_key` (which ends in a
/// separator, so it prefixes all of them) sorts at or before `cursor`: the
/// cursor is past the directory and not inside it.
fn subtree_sorts_before_cursor(dir_key: &str, cursor: &str) -> bool {
    cursor > dir_key && !cursor.starts_with(dir_key)
}

/// How long a file has to go unmodified before a rescan hashes it. Another
/// program still writing it would otherwise have it read end to end on every
/// rescan its own writes trigger, only for the size/mtime check around the
/// hash to throw the result away.
pub const SETTLE_PERIOD_SECS: i64 = 45;

/// Leeway for a modification time ahead of our clock. Beyond it the time is
/// wrong rather than recent, and waiting for it would defer the file for as
/// long as the skew lasts.
const SETTLE_FUTURE_TOLERANCE_SECS: i64 = 60;

/// True when a file last modified at `modified_at` (Unix seconds) may still be
/// being written.
pub fn still_settling(modified_at: i64, now: i64) -> bool {
    modified_at > now.saturating_sub(SETTLE_PERIOD_SECS)
        && modified_at <= now.saturating_add(SETTLE_FUTURE_TOLERANCE_SECS)
}

/// One path a filesystem event named, resolved for a scoped rescan.
#[derive(Debug)]
pub enum ScopedDiscovery {
    /// Gone, or nothing discovery would ever share: no row may remain at or
    /// under it.
    Removed,
    /// What discovery finds at or under the path now. `partial` as in
    /// [`DiscoveryResult`]: rows it did not list must not be reconciled away.
    Found { files: Vec<FileInfo>, partial: bool },
    /// Could not be examined, or lies outside every shared root as spelled:
    /// leave its rows alone.
    Skip,
}

impl FileIndexer {
    /// Resolve one event path under `roots` the way a full walk of its root
    /// would see it. Blocking.
    ///
    /// The walk's refusals are applied to every directory between the root and
    /// the path, not only to the path: an event inside a recycle bin or a
    /// junction names an ordinary-looking file whose parent the full walk never
    /// enters.
    pub fn discover_scoped_path(
        roots: &[String],
        allowlists: &std::collections::HashMap<String, Vec<String>>,
        path: &Path,
    ) -> ScopedDiscovery {
        // Event paths are the watched root joined with the changed name, so
        // they carry the root exactly as it is stored.
        let Some(root) = roots
            .iter()
            .map(Path::new)
            .filter(|root| path.starts_with(root))
            .max_by_key(|root| root.components().count())
        else {
            return ScopedDiscovery::Skip;
        };
        if is_excluded_share_location(path) {
            return ScopedDiscovery::Removed;
        }
        let scope = DiscoveryScope::for_root(&root.to_string_lossy(), allowlists);
        let key = normalize_path_key(&path.to_string_lossy());
        for ancestor in path.ancestors().skip(1) {
            if ancestor == root || !ancestor.starts_with(root) {
                break;
            }
            match std::fs::symlink_metadata(ancestor) {
                Ok(metadata) if metadata.is_symlink() || walk_skips_metadata(&metadata) => {
                    return ScopedDiscovery::Removed;
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return ScopedDiscovery::Removed;
                }
                Err(_) => return ScopedDiscovery::Skip,
            }
        }
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return ScopedDiscovery::Removed;
            }
            Err(_) => return ScopedDiscovery::Skip,
        };
        if metadata.is_symlink() || walk_skips_metadata(&metadata) {
            return ScopedDiscovery::Removed;
        }
        if metadata.is_dir() {
            if scope.as_ref().is_some_and(|scope| !scope.admits_dir(&key)) {
                return ScopedDiscovery::Removed;
            }
            let result = Self::discover_directory_page_in(&path.to_string_lossy(), None, scope.as_ref());
            return ScopedDiscovery::Found {
                files: result.files,
                partial: result.partial,
            };
        }
        if !metadata.is_file()
            || is_excluded_share_file_name(path)
            || scope.as_ref().is_some_and(|scope| !scope.admits_file(&key))
        {
            return ScopedDiscovery::Removed;
        }
        match Self::discover_file(path) {
            Ok(info) => ScopedDiscovery::Found {
                files: vec![info],
                partial: false,
            },
            Err(error) => {
                warn!("Failed to discover {}: {error}", path.display());
                ScopedDiscovery::Skip
            }
        }
    }

    /// Discover one deterministic page of a directory -- metadata only, no
    /// hashing. Files are returned with empty hash/aich_hash so they can be
    /// shown in the UI immediately, under a temporary id from the path until
    /// their real ED2K hash is computed. The indexer keeps a bounded, globally
    /// sorted page in memory. Cursor pages advance strictly forward; once the
    /// end is reached, a later scan resets to the beginning.
    ///
    /// `scope` limits the walk for a folder shared with only some of its
    /// contents. A scoped page is still the whole of what the folder offers,
    /// so it reconciles like any other.
    pub fn discover_directory_page_in(
        dir: &str,
        cursor: Option<&str>,
        scope: Option<&DiscoveryScope>,
    ) -> DiscoveryResult {
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

        // A recursive walker's sort orders siblings, not the complete DFS
        // traversal: on Windows `a\\child` may arrive before sibling `a0`, even
        // though `a0` sorts first by our cursor key. That is why this is a
        // best-first directory queue rather than `walkdir` (a dependency this
        // tree no longer carries, for the same reason) — it produces a globally
        // ordered stream, which is what makes an early page cutoff safe without
        // dropping files between cursor pages.
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
                    if let Ok(metadata) = entry.metadata() {
                        if walk_skips_metadata(&metadata) {
                            continue;
                        }
                    }
                }
                if file_type.is_dir() {
                    let dir_name = entry.file_name().to_string_lossy().into_owned();
                    if crate::sharing::is_index_skip_dir_name(&dir_name)
                        || crate::sharing::is_private_receive_dir_name(&dir_name)
                    {
                        continue;
                    }
                    let mut key = normalize_path_key(&entry_path.to_string_lossy());
                    if scope.is_some_and(|scope| !scope.admits_dir(&key)) {
                        continue;
                    }
                    if let Ok(canonical) = entry_path.canonicalize() {
                        if canonical == data_canon || canonical.starts_with(&data_canon) {
                            continue;
                        }
                    }
                    key.push(std::path::MAIN_SEPARATOR);
                    pending.push(Reverse((key, entry_path, true)));
                } else if file_type.is_file() {
                    let key = normalize_path_key(&entry_path.to_string_lossy());
                    if scope.is_some_and(|scope| !scope.admits_file(&key)) {
                        continue;
                    }
                    pending.push(Reverse((key, entry_path, false)));
                }
            }
            trimmed
        };
        let mut frontier_trimmed = enqueue_children(path, &mut pending);

        while let Some(Reverse((key, entry_path, is_directory))) = pending.pop() {
            if is_directory {
                // A full page cannot take more files, so descending further only
                // grows the frontier. Stop and report the cap: the next scan
                // resumes from the cursor and picks these directories up there.
                if files.len() >= MAX_DISCOVERED_FILES {
                    truncated = true;
                    break;
                }
                // Everything under it sorts before the cursor, so the page
                // could only discard it after reading the directory.
                if cursor.is_some_and(|value| subtree_sorts_before_cursor(&key, value)) {
                    saw_before_cursor = true;
                    continue;
                }
                frontier_trimmed |= enqueue_children(&entry_path, &mut pending);
                continue;
            }
            if is_excluded_share_file_name(&entry_path) {
                continue;
            }
            // Decided on the key the entry was queued under, before any stat:
            // testing after `discover_file` re-stated every file ahead of the
            // cursor on every page.
            if cursor.is_some_and(|value| key.as_str() <= value) {
                // Never mix paths before the current cursor into this page:
                // doing so makes the persisted cursor move backward and cycles
                // pages. Keep the page partial so callers preserve prior index
                // rows until the cursor explicitly resets after the end of the
                // traversal.
                saw_before_cursor = true;
                continue;
            }
            if files.len() >= MAX_DISCOVERED_FILES {
                // The priority queue guarantees this is the next global path
                // after the returned page.
                truncated = true;
                break;
            }
            match Self::discover_file(&entry_path) {
                Ok(info) => {
                    debug!("Discovered: {}", info.name);
                    files.push(info);
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

    /// Count the files discovery would find under `roots`, and their bytes,
    /// without building a page of them: the share picker's preview of what a
    /// share is about to offer. Walks by the same rules as
    /// [`Self::discover_directory_page`] so the preview agrees with the scan;
    /// order does not matter for a count, so a plain stack replaces the sorted
    /// queue. Roots nested inside another root are counted once.
    ///
    /// Stops early — reporting what it has, with `complete` false — when
    /// `cancel` is set, `deadline` passes, or [`MAX_MEASURED_ENTRIES`] entries
    /// have been looked at. Unreadable folders are skipped the way discovery
    /// skips them, so they do not make a count incomplete.
    pub fn measure_directories(
        roots: &[std::path::PathBuf],
        deadline: std::time::Instant,
        cancel: &AtomicBool,
    ) -> DirectoryMeasure {
        use std::sync::atomic::Ordering;

        let data_canon = canonical_data_dir();
        let mut measure = DirectoryMeasure {
            complete: true,
            ..DirectoryMeasure::default()
        };
        let mut unique: Vec<&std::path::PathBuf> = Vec::new();
        for root in roots {
            if roots.iter().any(|other| other != root && root.starts_with(other)) {
                continue;
            }
            if !unique.contains(&root) {
                unique.push(root);
            }
        }

        let mut stack: Vec<std::path::PathBuf> = Vec::new();
        for root in unique {
            if is_excluded_share_location(root) || !root.is_dir() {
                continue;
            }
            stack.push(root.clone());
        }

        let mut visited: u64 = 0;
        while let Some(directory) = stack.pop() {
            let entries = match std::fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(_) => continue,
            };
            for entry in entries {
                visited += 1;
                // Checked every few hundred entries rather than on each one:
                // `Instant::now` is a syscall on some platforms.
                if visited.is_multiple_of(256)
                    && (cancel.load(Ordering::Relaxed) || std::time::Instant::now() >= deadline)
                {
                    measure.complete = false;
                    return measure;
                }
                if visited > MAX_MEASURED_ENTRIES || stack.len() >= MAX_PENDING_FRONTIER {
                    measure.complete = false;
                    return measure;
                }
                let Ok(entry) = entry else { continue };
                let Ok(file_type) = entry.file_type() else { continue };
                if file_type.is_symlink() {
                    continue;
                }
                let metadata = entry.metadata().ok();
                if metadata.as_ref().is_some_and(walk_skips_metadata) {
                    continue;
                }
                let entry_path = entry.path();
                if file_type.is_dir() {
                    let dir_name = entry.file_name().to_string_lossy().into_owned();
                    if crate::sharing::is_index_skip_dir_name(&dir_name)
                        || crate::sharing::is_private_receive_dir_name(&dir_name)
                    {
                        continue;
                    }
                    if let Ok(canonical) = entry_path.canonicalize() {
                        if canonical == data_canon || canonical.starts_with(data_canon) {
                            continue;
                        }
                    }
                    stack.push(entry_path);
                } else if file_type.is_file() {
                    if is_excluded_share_file_name(&entry_path) {
                        continue;
                    }
                    measure.files += 1;
                    measure.bytes += metadata.map_or(0, |metadata| metadata.len());
                }
            }
        }
        measure
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

    /// Computes ed2k, AICH, part hashes, and ember
    /// BLAKE3 (plus size/mtime) in a single pass for `known.met`.
    ///
    /// Bytes read are added to `progress` as they land, which is how the scan
    /// tells a large file on a slow drive from a read that has stopped.
    pub fn hash_file_cancellable(
        path: &Path,
        cancelled: &AtomicBool,
        progress: &AtomicU64,
    ) -> anyhow::Result<(String, String, Vec<[u8; 16]>, String, u64, i64)> {
        let before = std::fs::symlink_metadata(path)?;
        if before.is_symlink() {
            anyhow::bail!("refusing to hash symlink: {}", path.display());
        }
        let before_modified = before.modified().ok();
        let (ed2k, aich, part_hashes, ember) =
            hash_file_combined_cancellable(path, cancelled, progress)?;
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

    /// Compute only the digests a record is actually missing, carrying forward
    /// the ed2k hash — and, when it is not the thing being recovered, the AICH
    /// root — that `known.met` already holds.
    ///
    /// Same shape and same guarantees as [`Self::hash_file_cancellable`] — the
    /// symlink refusal and the size/mtime check on both sides of the read are
    /// identical — so callers can swap between them per file.
    ///
    /// Two routes, because the cheap one cannot answer for AICH:
    ///
    /// - Digest only. BLAKE3 alone, which runs several times faster than a
    ///   pass that also drives MD4 and SHA-1 (measured at 5.6 GB/s against
    ///   618 MB/s), so a library whose records are otherwise complete is
    ///   limited by the drive rather than the CPU.
    /// - Anything involving AICH. The leaf hashes only exist as a by-product of
    ///   a pass that walks the file in blocks, so this takes the shared
    ///   single-pass reader and asks it for exactly what is missing. It costs
    ///   the ed2k MD4 whether or not we need it, which buys something back:
    ///   see the cross-check below.
    ///
    /// The AICH route returns the part hashes it computed. A record carrying an
    /// ed2k hash does *not* imply it carries them: the reconcile writes an empty
    /// list rather than re-read a file on the network task, and `known.met`
    /// clears a stored list whose length stopped describing the file. Since
    /// `resolve_from_known` sends every matched record here rather than to the
    /// full pass, this is the only pass that opens these files, and the list is
    /// a by-product of the MD4 it runs anyway — so dropping it would strand
    /// those records with no hashset for `OP_HASHSETREQUEST`. The cross-check
    /// below has already proved the list describes the id it is filed under.
    ///
    /// The digest-only route returns an empty list because it computes no MD4 to
    /// derive one from. `fresh_part_hash_handoff` reads empty as "nothing new to
    /// hand over" rather than as an erasure.
    ///
    /// What the digest-only route gives up is that the full pass would have
    /// recomputed the MD4 and noticed a file whose contents changed without its
    /// size or mtime moving. That is not a protection being removed so much as
    /// one that was never offered: every file this scan *doesn't* queue is
    /// accepted on the strength of the same path+size+mtime match, by
    /// `resolve_from_known`.
    ///
    /// The AICH route does not get to make that trade, and must not. Its output
    /// is served to peers as recovery data for bytes they got from us, so a root
    /// computed over contents that no longer match the id it is filed under
    /// would be worse than no root at all — it would point a downloader's repair
    /// at the wrong bytes. Since the MD4 is already running, the recomputed ed2k
    /// is compared against the stored one and a mismatch fails the file rather
    /// than recording anything. The caller leaves it for next time.
    ///
    /// Every digest it does not compute is carried forward from the record,
    /// never returned empty. The caller assigns this tuple straight onto an
    /// index row — `updated_file.ember_file_hash = ember_file_hash` — so a
    /// field left blank because it was not asked for would read as an erasure
    /// and withdraw a digest the record already had.
    pub fn hash_file_top_up_cancellable(
        path: &Path,
        known_ed2k: String,
        known_aich: String,
        known_ember: String,
        want: crate::network::ed2k::hash::WantedDigests,
        cancelled: &AtomicBool,
        progress: &AtomicU64,
    ) -> anyhow::Result<(String, String, Vec<[u8; 16]>, String, u64, i64)> {
        let before = std::fs::symlink_metadata(path)?;
        if before.is_symlink() {
            anyhow::bail!("refusing to hash symlink: {}", path.display());
        }
        let before_modified = before.modified().ok();

        let (aich, ember, part_hashes) = if want.aich {
            let mut file = std::fs::File::open(path)?;
            let digests = crate::network::ed2k::hash::hash_open_file_digests_tracked(
                &mut file, want, cancelled, progress,
            )?;
            if digests.ed2k != known_ed2k {
                anyhow::bail!(
                    "refusing to record an AICH root for {}: contents hash to {} but known.met has {}",
                    path.display(),
                    digests.ed2k,
                    known_ed2k
                );
            }
            (
                digests.aich.map(hex::encode).unwrap_or(known_aich),
                digests.ember.map(hex::encode).unwrap_or(known_ember),
                digests.part_hashes,
            )
        } else {
            (
                known_aich,
                crate::network::ed2k::hash::blake3_file_cancellable(path, cancelled, progress)?,
                Vec::new(),
            )
        };

        let after = std::fs::symlink_metadata(path)?;
        let after_modified = after.modified().ok();
        if before.len() != after.len() || before_modified != after_modified {
            anyhow::bail!("file changed while hashing: {}", path.display());
        }
        let modified_at = after_modified
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
        Ok((
            known_ed2k,
            aich,
            part_hashes,
            ember,
            after.len(),
            modified_at,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digest the migration writes is what a download later verifies
    /// against, so the short-cut pass has to agree with the full one byte for
    /// byte. Everything else it returns is carried through from `known.met`
    /// unchanged. The digest-only route computes no part hashes; the AICH route
    /// runs the MD4 anyway, so it must hand back the same list the full pass
    /// produces — it is the only pass that reopens a record whose hashset was
    /// left empty.
    #[test]
    fn the_digest_only_pass_agrees_with_the_full_one() {
        let dir = std::env::temp_dir().join(format!(
            "ember-digest-only-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("sample.bin");

        // Over PARTSIZE, so the full pass produces real part hashes and the
        // contrast with the short-cut's empty list is meaningful.
        let size = crate::network::ed2k::hash::PARTSIZE as usize + 4096;
        let mut data = vec![0u8; size];
        let mut x: u32 = 0x9E37_79B9;
        for b in data.iter_mut() {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (x >> 24) as u8;
        }
        std::fs::write(&path, &data).expect("write sample");

        let flag = AtomicBool::new(false);
        let full_read = AtomicU64::new(0);
        let (ed2k, aich, parts, ember, full_size, full_mtime) =
            FileIndexer::hash_file_cancellable(&path, &flag, &full_read).expect("full pass");
        assert!(!parts.is_empty(), "a multi-part file has part hashes");

        let short_read = AtomicU64::new(0);
        let (short_ed2k, short_aich, short_parts, short_ember, short_size, short_mtime) =
            FileIndexer::hash_file_top_up_cancellable(
                &path,
                ed2k.clone(),
                aich.clone(),
                String::new(),
                crate::network::ed2k::hash::WantedDigests {
                    aich: false,
                    ember: true,
                },
                &flag,
                &short_read,
            )
            .expect("digest-only pass");

        // What the scan watches to tell a slow read from a stuck one, so both
        // readers have to report the whole file.
        assert_eq!(full_read.into_inner(), size as u64);
        assert_eq!(short_read.into_inner(), size as u64);

        assert_eq!(short_ember, ember, "the digest must match the full pass");
        assert_eq!(short_ed2k, ed2k);
        assert_eq!(short_aich, aich);
        assert_eq!(short_size, full_size);
        assert_eq!(short_mtime, full_mtime);
        assert!(
            short_parts.is_empty(),
            "part hashes stay on the known.met record rather than being recomputed"
        );

        // The AICH route is the one whose output is served to peers as repair
        // data, so it has to agree with the full pass too — and it recomputes
        // the ed2k in passing, which is what lets it refuse a file whose
        // contents no longer match the id they are filed under.
        let (aich_ed2k, recovered_aich, aich_parts, aich_ember, _, _) =
            FileIndexer::hash_file_top_up_cancellable(
                &path,
                ed2k.clone(),
                String::new(),
                String::new(),
                crate::network::ed2k::hash::WantedDigests {
                    aich: true,
                    ember: true,
                },
                &flag,
                &AtomicU64::new(0),
            )
            .expect("aich top-up pass");
        assert_eq!(
            recovered_aich, aich,
            "a recovered root must match the one the full pass computes"
        );
        assert_eq!(aich_ember, ember, "one read still answers for both");
        assert_eq!(aich_ed2k, ed2k);
        assert_eq!(
            aich_parts, parts,
            "the AICH route is the only pass that reopens a record left without \
             a hashset, and it computes these anyway — dropping them leaves \
             OP_HASHSETREQUEST with nothing to answer from"
        );

        // Filed under the wrong id, the root would point a downloader's repair
        // at the wrong bytes, so the mismatch fails the file rather than
        // recording anything.
        let wrong_id = "00".repeat(16);
        let refused = FileIndexer::hash_file_top_up_cancellable(
            &path,
            wrong_id,
            String::new(),
            String::new(),
            crate::network::ed2k::hash::WantedDigests {
                aich: true,
                ember: false,
            },
            &flag,
            &AtomicU64::new(0),
        );
        assert!(
            refused.is_err(),
            "an AICH root must never be recorded against contents that hash to something else"
        );

        // A root recovered on its own must hand the stored digest back
        // untouched, not blank it. The scan consumer assigns this tuple
        // straight onto the row.
        let (_, _, _, carried_ember, _, _) = FileIndexer::hash_file_top_up_cancellable(
            &path,
            ed2k.clone(),
            String::new(),
            ember.clone(),
            crate::network::ed2k::hash::WantedDigests {
                aich: true,
                ember: false,
            },
            &flag,
            &AtomicU64::new(0),
        )
        .expect("aich-only top-up");
        assert_eq!(
            carried_ember, ember,
            "a digest that was not asked for must be carried forward, never returned empty"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Stopping a scan has to stop this pass too, mid-file, the same way the
    /// full one stops — on both routes, since they read the file by different
    /// paths and only one of them was ever exercised here.
    #[test]
    fn the_top_up_pass_honours_cancellation() {
        let dir = std::env::temp_dir().join(format!(
            "ember-digest-cancel-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("sample.bin");
        std::fs::write(&path, vec![7u8; 4 * 1024 * 1024]).expect("write sample");

        let flag = AtomicBool::new(true);
        for want in [
            crate::network::ed2k::hash::WantedDigests {
                aich: false,
                ember: true,
            },
            crate::network::ed2k::hash::WantedDigests {
                aich: true,
                ember: true,
            },
        ] {
            let result = FileIndexer::hash_file_top_up_cancellable(
                &path,
                "ab".repeat(16),
                "cd".repeat(20),
                String::new(),
                want,
                &flag,
                &AtomicU64::new(0),
            );
            assert!(
                result.is_err(),
                "{want:?}: an already-cancelled pass must not return a digest"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Outside the system temp folder: on Windows that sits under `AppData`,
    /// a component the share rules refuse.
    fn scratch_tree(label: &str) -> std::path::PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("ember-indexer-{label}-{:016x}", rand::random::<u64>()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn a_directory_is_skipped_only_when_the_cursor_is_past_all_of_it() {
        let sep = std::path::MAIN_SEPARATOR;
        let dir = format!("{sep}s{sep}a{sep}");
        assert!(subtree_sorts_before_cursor(&dir, &format!("{sep}s{sep}b")));
        assert!(
            !subtree_sorts_before_cursor(&dir, &format!("{sep}s{sep}a{sep}m.bin")),
            "a cursor inside the directory means part of it is still ahead"
        );
        assert!(!subtree_sorts_before_cursor(&dir, &format!("{sep}s{sep}0")));
    }

    /// A resumed page must still return exactly the files after its cursor,
    /// now that the cursor is tested before anything is stat'ed and whole
    /// directories behind it are never opened.
    #[test]
    fn a_resumed_page_lists_exactly_what_follows_its_cursor() {
        let root = scratch_tree("cursor");
        for rel in ["a/1.bin", "a/2.bin", "b/c/3.bin", "b/4.bin", "d.bin"] {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"x").unwrap();
        }
        let root_str = root.to_string_lossy().to_string();
        let full = FileIndexer::discover_directory_page_in(&root_str, None, None);
        let keys: Vec<String> = full.files.iter().map(|f| normalize_path_key(&f.path)).collect();
        assert_eq!(keys.len(), 5);
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "discovery is globally ordered");

        let resumed = FileIndexer::discover_directory_page_in(&root_str, Some(&keys[2]), None);
        let resumed_keys: Vec<String> =
            resumed.files.iter().map(|f| normalize_path_key(&f.path)).collect();
        assert_eq!(resumed_keys, keys[3..].to_vec());
        assert!(resumed.partial, "a resumed page omits its prefix");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn recently_written_files_are_left_to_settle() {
        let now = 1_000_000;
        assert!(still_settling(now, now));
        assert!(still_settling(now - SETTLE_PERIOD_SECS + 1, now));
        assert!(!still_settling(now - SETTLE_PERIOD_SECS, now));
        assert!(!still_settling(0, now), "an unknown mtime does not wait");
        assert!(
            !still_settling(now + 10 * 60, now),
            "a clock-skewed mtime must not defer a file for the length of the skew"
        );
    }

    #[test]
    fn scoped_discovery_resolves_files_folders_and_deletions() {
        let root = scratch_tree("scoped");
        let roots = vec![root.to_string_lossy().to_string()];
        let no_lists = std::collections::HashMap::new();
        let file = root.join("album").join("song.mp3");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, b"x").unwrap();
        std::fs::write(root.join("album").join("cover.jpg"), b"y").unwrap();

        match FileIndexer::discover_scoped_path(&roots, &no_lists, &file) {
            ScopedDiscovery::Found { files, partial } => {
                assert_eq!(files.len(), 1);
                assert!(!partial);
            }
            other => panic!("expected the file, got {other:?}"),
        }
        match FileIndexer::discover_scoped_path(&roots, &no_lists, &root.join("album")) {
            ScopedDiscovery::Found { files, .. } => assert_eq!(files.len(), 2),
            other => panic!("expected the folder's files, got {other:?}"),
        }
        assert!(matches!(
            FileIndexer::discover_scoped_path(&roots, &no_lists, &root.join("gone.mkv")),
            ScopedDiscovery::Removed
        ));
        let part = root.join("album").join("x.part");
        std::fs::write(&part, b"z").unwrap();
        assert!(matches!(
            FileIndexer::discover_scoped_path(&roots, &no_lists, &part),
            ScopedDiscovery::Removed
        ));
        assert!(
            matches!(
                FileIndexer::discover_scoped_path(&roots, &no_lists, Path::new("/elsewhere/a.mkv")),
                ScopedDiscovery::Skip
            ),
            "a path under no shared root is not ours to reconcile"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    fn page_names(result: &DiscoveryResult) -> Vec<String> {
        let mut names: Vec<String> = result.files.iter().map(|f| f.name.clone()).collect();
        names.sort();
        names
    }

    #[test]
    fn a_partly_shared_folder_walks_only_its_allowlist() {
        let root = scratch_tree("allowlist");
        let key = |path: &Path| normalize_path_key(&path.to_string_lossy());
        std::fs::create_dir_all(root.join("sub").join("deep")).unwrap();
        std::fs::create_dir_all(root.join("other")).unwrap();
        for file in ["a.mp3", "b.mp3", "sub/c.mp3", "sub/deep/d.mp3", "other/e.mp3"] {
            std::fs::write(root.join(file), b"x").unwrap();
        }
        let root_str = root.to_string_lossy().to_string();

        // "Include subfolders" off: only the folder's own files that were picked.
        let own_files = DiscoveryScope::new(&[key(&root.join("a.mp3"))]);
        let page = FileIndexer::discover_directory_page_in(&root_str, None, Some(&own_files));
        assert_eq!(page_names(&page), ["a.mp3"]);
        assert!(!page.partial, "a scoped page is the whole of what the folder offers");

        // A dropped subfolder is offered whole, and the walk reaches it
        // through its parent without taking the parent's own files.
        let deep = DiscoveryScope::new(&[key(&root.join("sub").join("deep")), key(&root.join("b.mp3"))]);
        let page = FileIndexer::discover_directory_page_in(&root_str, None, Some(&deep));
        assert_eq!(page_names(&page), ["b.mp3", "d.mp3"]);

        let mut lists = std::collections::HashMap::new();
        lists.insert(key(&root), vec![key(&root.join("a.mp3"))]);
        let roots = vec![root_str.clone()];
        assert!(matches!(
            FileIndexer::discover_scoped_path(&roots, &lists, &root.join("b.mp3")),
            ScopedDiscovery::Removed
        ));
        assert!(matches!(
            FileIndexer::discover_scoped_path(&roots, &lists, &root.join("sub")),
            ScopedDiscovery::Removed
        ));
        match FileIndexer::discover_scoped_path(&roots, &lists, &root.join("a.mp3")) {
            ScopedDiscovery::Found { files, .. } => assert_eq!(files.len(), 1),
            other => panic!("expected the allowlisted file, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

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
            "kdewallet.kwl",
            "login.keyring",
            "fish_history",
            ".vault-token",
            ".s3cfg",
            "Web Data",
            "cookies.sqlite",
        ] {
            assert!(
                is_excluded_share_file_name(&Path::new(r"C:\Users\me\Documents").join(name)),
                "{name} must never be shared"
            );
        }
    }

    /// Discovery and the watcher have to agree on these: a name the watcher
    /// ignores but discovery indexes leaves a row nobody updates.
    #[test]
    fn excludes_other_programs_in_progress_writes() {
        for name in [
            "movie.mkv.crdownload",
            "Linux.iso.!qB",
            "~$report.docx",
            "draft.docx.TMP",
        ] {
            assert!(is_excluded_share_file_name(Path::new(name)), "{name}");
        }
        assert!(!is_excluded_share_file_name(Path::new("template.docx")));
        assert!(!is_excluded_share_file_name(Path::new("tmp-notes.txt")));
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

    fn measure_fixture(tag: &str) -> std::path::PathBuf {
        let dir = scratch_tree(&format!("measure-{tag}"));
        std::fs::create_dir_all(dir.join("sub").join("deeper")).expect("temp dirs");
        std::fs::write(dir.join("a.txt"), b"12345").expect("a");
        std::fs::write(dir.join("sub").join("b.bin"), vec![0u8; 100]).expect("b");
        std::fs::write(dir.join("sub").join("deeper").join("c.dat"), vec![0u8; 1000]).expect("c");
        // Discovery refuses these, so the preview must not count them either.
        std::fs::write(dir.join("sub").join("movie.part"), b"partial").expect("part");
        std::fs::write(dir.join(".env"), b"SECRET=1").expect("env");
        dir
    }

    #[test]
    fn measuring_counts_what_discovery_would_share() {
        let dir = measure_fixture("agree");
        let flag = AtomicBool::new(false);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let measure =
            FileIndexer::measure_directories(std::slice::from_ref(&dir), deadline, &flag);
        let discovered = FileIndexer::discover_directory_page_in(&dir.to_string_lossy(), None, None);
        assert!(measure.complete);
        assert_eq!(measure.files, discovered.files.len() as u64);
        assert_eq!(measure.files, 3);
        assert_eq!(measure.bytes, 1105);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn measuring_a_folder_and_its_subfolder_counts_it_once() {
        let dir = measure_fixture("nested");
        let flag = AtomicBool::new(false);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let measure =
            FileIndexer::measure_directories(&[dir.join("sub"), dir.clone()], deadline, &flag);
        assert_eq!(measure.files, 3);
        assert_eq!(measure.bytes, 1105);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_passed_deadline_reports_an_incomplete_count() {
        let dir = measure_fixture("deadline");
        // Enough entries that the walk reaches its first budget check.
        for i in 0..300 {
            std::fs::write(dir.join(format!("f{i}.txt")), b"x").expect("file");
        }
        let flag = AtomicBool::new(false);
        let measure =
            FileIndexer::measure_directories(std::slice::from_ref(&dir), std::time::Instant::now(), &flag);
        assert!(!measure.complete);
        assert!(measure.files < 303);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
