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

#[derive(Debug, Default)]
pub struct DiscoveryResult {
    pub files: Vec<FileInfo>,
    pub truncated: bool,
    /// Normalized path after which the next bounded scan should continue.
    /// `None` means this page covered the whole folder.
    pub next_cursor: Option<String>,
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
            return DiscoveryResult {
                files,
                truncated: false,
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
                return DiscoveryResult {
                    files,
                    truncated: false,
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
        let enqueue_children =
            |directory: &Path,
             pending: &mut BinaryHeap<Reverse<(String, std::path::PathBuf, bool)>>| {
                let entries = match std::fs::read_dir(directory) {
                    Ok(entries) => entries,
                    Err(error) => {
                        warn!("Failed to read shared directory {}: {error}", directory.display());
                        return;
                    }
                };
                for entry in entries {
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
                        if crate::sharing::is_sensitive_dir_name(
                            &entry.file_name().to_string_lossy(),
                        ) {
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
            };
        enqueue_children(path, &mut pending);

        while let Some(Reverse((_key, entry_path, is_directory))) = pending.pop() {
            if is_directory {
                enqueue_children(&entry_path, &mut pending);
                continue;
            }
            let name = entry_path
                .file_name()
                .map(|name| name.to_string_lossy())
                .unwrap_or_default();
            // Skip temporary/partial download files.
            if name.ends_with(".part")
                || name.ends_with(".part.met")
                || name.ends_with(".met.tmp")
                || (name.starts_with('.') && name.ends_with(".tmp"))
                || name.ends_with(".migration-tmp")
                || name.ends_with(".bak")
            {
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

        // A non-initial page necessarily omits all entries before its cursor.
        // Keep that reload partial even when the post-cursor tail is shorter
        // than the page size, so reconciliation never deletes earlier pages.
        if cursor.is_some() && saw_before_cursor {
            truncated = true;
        }
        let next_cursor = truncated
            .then(|| files.last().map(|file| normalize_path_key(&file.path)))
            .flatten();
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
