use std::path::Path;

use tracing::{debug, info, warn};
use walkdir::WalkDir;

use crate::network::ed2k::hash::ed2k_hash_file;
use crate::types::FileInfo;

pub struct FileIndexer;

impl FileIndexer {
    pub fn scan_directory(dir: &str) -> Vec<FileInfo> {
        let mut files = Vec::new();
        let path = Path::new(dir);

        if !path.exists() || !path.is_dir() {
            warn!("Directory does not exist or is not a directory: {dir}");
            return files;
        }

        info!("Scanning directory: {dir}");

        for entry in WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                match Self::index_file(entry.path()) {
                    Ok(info) => {
                        debug!("Indexed: {}", info.name);
                        files.push(info);
                    }
                    Err(e) => {
                        warn!("Failed to index {}: {e}", entry.path().display());
                    }
                }
            }
        }

        info!("Scanned {} files from {dir}", files.len());
        files
    }

    pub fn index_file(path: &Path) -> anyhow::Result<FileInfo> {
        let metadata = std::fs::metadata(path)?;
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

        let hash = ed2k_hash_file(path)?;

        Ok(FileInfo {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            path: path.to_string_lossy().to_string(),
            size: metadata.len(),
            hash,
            extension,
            modified_at,
        })
    }
}
