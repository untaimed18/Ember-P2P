use std::path::Path;
use std::sync::atomic::AtomicBool;

use tracing::{debug, info, warn};
use walkdir::WalkDir;

use crate::network::ed2k::aich::compute_aich_root;
use crate::network::ed2k::hash::{ed2k_hash_file, hash_file_combined_cancellable};
use crate::types::FileInfo;

pub struct FileIndexer;

impl FileIndexer {
    /// Quickly discover files in a directory -- metadata only, no hashing.
    /// Files are returned with empty hash/aich_hash so they can be shown in the
    /// UI immediately.  A temporary id is generated from the path so the file
    /// can be identified until its real ED2K hash is computed.
    pub fn discover_directory(dir: &str) -> Vec<FileInfo> {
        let mut files = Vec::new();
        let path = Path::new(dir);

        if !path.exists() || !path.is_dir() {
            warn!("Directory does not exist or is not a directory: {dir}");
            return files;
        }

        info!("Discovering files in: {dir}");

        for entry in WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                if e.path_is_symlink() {
                    return false;
                }
                #[cfg(target_os = "windows")]
                {
                    use std::os::windows::fs::MetadataExt;
                    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
                    if let Ok(meta) = e.metadata() {
                        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                            return false;
                        }
                    }
                }
                if e.file_type().is_dir() {
                    let name = e.file_name().to_string_lossy();
                    return !name.eq_ignore_ascii_case("temp");
                }
                true
            })
            .filter_map(|e| match e {
                Ok(entry) => Some(entry),
                Err(e) => { warn!("WalkDir error: {e}"); None }
            })
        {
            if entry.file_type().is_file() {
                let name = entry.file_name().to_string_lossy();
                // Skip temporary/partial download files
                if name.ends_with(".part") || name.ends_with(".part.met")
                    || name.ends_with(".met.tmp") || name.ends_with(".bak")
                {
                    continue;
                }
                match Self::discover_file(entry.path()) {
                    Ok(info) => {
                        debug!("Discovered: {}", info.name);
                        files.push(info);
                    }
                    Err(e) => {
                        warn!("Failed to discover {}: {e}", entry.path().display());
                    }
                }
            }
        }

        info!("Discovered {} files from {dir}", files.len());
        files
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
        let folder = path.parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let path_str = path.to_string_lossy().to_string();
        let temp_id = format!("pending:{:x}", temp_hash(path_str.as_bytes()));

        Ok(FileInfo {
            id: temp_id,
            name,
            path: path_str,
            size: metadata.len(),
            hash: String::new(),
            aich_hash: String::new(),
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
            shared_kad: false,
            shared_ed2k: false,
        })
    }

    #[allow(dead_code)]
    pub fn hash_file(path: &Path) -> anyhow::Result<(String, String)> {
        let ed2k = ed2k_hash_file(path)?;
        let aich = compute_aich_root(path)
            .map(|h| hex::encode(h))
            .unwrap_or_default();
        Ok((ed2k, aich))
    }

    /// Cancellable version -- computes both hashes in a single pass.
    pub fn hash_file_cancellable(path: &Path, cancelled: &AtomicBool) -> anyhow::Result<(String, String)> {
        hash_file_combined_cancellable(path, cancelled)
    }

}

fn temp_hash(data: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    data.hash(&mut h);
    h.finish()
}
