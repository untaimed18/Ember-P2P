use std::collections::{HashMap, HashSet};

use crate::search::merge::ORIGIN_LOCAL;
use crate::types::{FileInfo, SearchResult};

pub struct LocalIndex {
    files: Vec<FileInfo>,
    /// Keyed by `normalize_path_key(file.path)` so Windows paths that differ
    /// only in case resolve to the same index entry.
    path_map: HashMap<String, usize>,
    hash_map: HashMap<String, Vec<usize>>,
    name_tokens: HashMap<String, Vec<usize>>,
}

/// Windows filesystems are (by default) case-insensitive; indexing a path that
/// arrived from the watcher in one casing and lookups that arrive from the UI
/// in another would spuriously miss. Lowercase the path on Windows; preserve
/// it exactly on other platforms where case matters.
#[inline]
fn normalize_path_key(path: &str) -> String {
    if cfg!(windows) {
        path.to_lowercase()
    } else {
        path.to_string()
    }
}

impl LocalIndex {
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            path_map: HashMap::new(),
            hash_map: HashMap::new(),
            name_tokens: HashMap::new(),
        }
    }

    pub fn add_files(&mut self, files: Vec<FileInfo>) {
        for file in files {
            self.upsert_file(file);
        }
        self.rebuild_indices();
    }

    pub fn add_file(&mut self, file: FileInfo) {
        self.upsert_file(file);
        self.rebuild_indices();
    }

    /// Insert/update a file without rebuilding indices. Call `rebuild_indices`
    /// manually after a batch of insertions to amortise the O(n) cost.
    pub fn add_file_no_rebuild(&mut self, file: FileInfo) {
        self.upsert_file(file);
    }

    pub fn rebuild(&mut self) {
        self.rebuild_indices();
    }

    pub fn reconcile_files_for_folders(&mut self, folders: &[String], discovered: Vec<FileInfo>) {
        let discovered_paths: HashSet<String> =
            discovered.iter().map(|file| file.path.clone()).collect();
        self.files.retain(|file| {
            !folders
                .iter()
                .any(|folder| crate::security::path_matches_dir(&file.path, folder))
                || discovered_paths.contains(&file.path)
        });
        for file in discovered {
            self.upsert_file(file);
        }
        self.rebuild_indices();
    }

    #[allow(dead_code)]
    pub fn search(&self, query: &str) -> Vec<SearchResult> {
        let query_lower = query.to_lowercase();
        let query_tokens = tokenize(&query_lower);

        if query_tokens.is_empty() {
            return Vec::new();
        }

        let mut score_map: HashMap<usize, u32> = HashMap::new();

        for token in &query_tokens {
            for (indexed_token, indices) in &self.name_tokens {
                if indexed_token.contains(token.as_str()) {
                    for &idx in indices {
                        *score_map.entry(idx).or_insert(0) += 1;
                    }
                }
            }
        }

        let mut results: Vec<(usize, u32)> = score_map.into_iter().collect();
        results.sort_by(|a, b| b.1.cmp(&a.1));

        results
            .into_iter()
            .take(100)
            .filter_map(|(idx, _score)| {
                self.files.get(idx).map(|file| SearchResult {
                    file: file.clone(),
                    peer_id: "local".to_string(),
                    peer_name: "You".to_string(),
                    availability: 1,
                    file_type: infer_file_type(&file.extension),
                    source_addresses: vec!["local".to_string()],
                    rating: None,
                    comment: None,
                    spam_rating: 0,
                    is_spam: false,
                    clean_name: String::new(),
                    result_origin: ORIGIN_LOCAL.to_string(),
                })
            })
            .collect()
    }

    pub fn get_by_hash(&self, hash: &str) -> Option<&FileInfo> {
        self.hash_map
            .get(hash)
            .and_then(|indices| indices.first())
            .and_then(|&idx| self.files.get(idx))
    }

    pub fn get_by_path(&self, path: &str) -> Option<&FileInfo> {
        self.path_map
            .get(&normalize_path_key(path))
            .and_then(|&idx| self.files.get(idx))
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    pub fn all_files(&self) -> &[FileInfo] {
        &self.files
    }

    /// Return all unique file hashes present in the index.
    pub fn all_hashes(&self) -> Vec<String> {
        self.hash_map.keys().cloned().collect()
    }

    pub fn remove_files_by_path_prefix(&mut self, prefix: &str) {
        self.files
            .retain(|f| !crate::security::path_matches_dir(&f.path, prefix));
        self.rebuild_indices();
    }

    /// Remove all files that still have a "pending:..." temp id (unhashed).
    pub fn remove_pending_files(&mut self) {
        let before = self.files.len();
        self.files.retain(|f| !f.id.starts_with("pending:"));
        if self.files.len() != before {
            self.rebuild_indices();
        }
    }

    /// Remove a file by its `id` field (handles temporary "pending:..." ids
    /// assigned during the discovery phase before hashing completes).
    /// Uses swap_remove + targeted index patching so cost is O(k) in the
    /// removed file's token count, not O(n) per call.
    pub fn remove_file_by_id(&mut self, id: &str) -> Option<FileInfo> {
        let pos = self.files.iter().position(|f| f.id == id)?;
        Some(self.swap_remove_indexed(pos))
    }

    pub fn remove_file_by_path(&mut self, path: &str) -> Option<FileInfo> {
        let pos = *self.path_map.get(&normalize_path_key(path))?;
        Some(self.swap_remove_indexed(pos))
    }

    /// swap_remove the file at `pos` and incrementally patch path_map,
    /// hash_map, and name_tokens so callers don't need a full rebuild.
    fn swap_remove_indexed(&mut self, pos: usize) -> FileInfo {
        let last_idx = self.files.len() - 1;
        let moved = pos != last_idx;
        let moved_key = if moved {
            Some((self.files[last_idx].path.clone(),
                  self.files[last_idx].hash.clone(),
                  tokenize(&self.files[last_idx].name.to_lowercase())))
        } else {
            None
        };

        let removed = self.files.swap_remove(pos);

        self.path_map.remove(&normalize_path_key(&removed.path));
        if !removed.hash.is_empty() {
            if let Some(v) = self.hash_map.get_mut(&removed.hash) {
                v.retain(|&i| i != pos && i != last_idx);
                if v.is_empty() {
                    self.hash_map.remove(&removed.hash);
                }
            }
        }
        for token in tokenize(&removed.name.to_lowercase()) {
            if let Some(v) = self.name_tokens.get_mut(&token) {
                v.retain(|&i| i != pos && i != last_idx);
                if v.is_empty() {
                    self.name_tokens.remove(&token);
                }
            }
        }

        if let Some((moved_path, moved_hash, moved_tokens)) = moved_key {
            self.path_map.insert(normalize_path_key(&moved_path), pos);
            if !moved_hash.is_empty() {
                self.hash_map.entry(moved_hash).or_default().push(pos);
            }
            for token in moved_tokens {
                self.name_tokens.entry(token).or_default().push(pos);
            }
        }

        removed
    }

    pub fn update_alltime_stats(&mut self, hash: &str, alltime_requests: u32, alltime_accepted: u32, alltime_transferred: u64) {
        if let Some(indices) = self.hash_map.get(hash).cloned() {
            for idx in indices {
                if let Some(file) = self.files.get_mut(idx) {
                    file.alltime_requests = alltime_requests;
                    file.alltime_accepted = alltime_accepted;
                    file.alltime_transferred = alltime_transferred;
                }
            }
        }
    }

    /// Session + all-time request/accept counters when peers ask for / get a slot for this file.
    pub fn apply_upload_share_deltas(&mut self, hash_hex: &str, inc_requests: u32, inc_accepted: u32) {
        if inc_requests == 0 && inc_accepted == 0 {
            return;
        }
        if let Some(indices) = self.hash_map.get(hash_hex).cloned() {
            for idx in indices {
                if let Some(file) = self.files.get_mut(idx) {
                    file.requests = file.requests.saturating_add(inc_requests);
                    file.accepted = file.accepted.saturating_add(inc_accepted);
                    file.alltime_requests = file.alltime_requests.saturating_add(inc_requests);
                    file.alltime_accepted = file.alltime_accepted.saturating_add(inc_accepted);
                }
            }
        }
    }

    /// Update the known complete-source count for a file (from SourceManager periodic sync).
    pub fn update_complete_sources(&mut self, hash_hex: &str, count: u32) {
        if let Some(indices) = self.hash_map.get(hash_hex).cloned() {
            for idx in indices {
                if let Some(file) = self.files.get_mut(idx) {
                    file.complete_sources = count;
                }
            }
        }
    }

    /// Add bytes uploaded this session and to the displayed all-time total for this file.
    pub fn apply_upload_completed_bytes(&mut self, hash_hex: &str, bytes: u64) {
        if bytes == 0 {
            return;
        }
        if let Some(indices) = self.hash_map.get(hash_hex).cloned() {
            for idx in indices {
                if let Some(file) = self.files.get_mut(idx) {
                    file.bytes_transferred = file.bytes_transferred.saturating_add(bytes);
                    file.alltime_transferred = file.alltime_transferred.saturating_add(bytes);
                }
            }
        }
    }

    pub fn set_file_priority_by_path(&mut self, path: &str, priority: &str) -> bool {
        if let Some(&idx) = self.path_map.get(&normalize_path_key(path)) {
            if let Some(file) = self.files.get_mut(idx) {
                file.priority = priority.to_string();
                return true;
            }
        }
        false
    }

    pub fn set_file_shared_by_path(&mut self, path: &str, shared: bool) -> bool {
        if let Some(&idx) = self.path_map.get(&normalize_path_key(path)) {
            if let Some(file) = self.files.get_mut(idx) {
                file.shared = shared;
                return true;
            }
        }
        false
    }

    pub fn set_shared_by_path_prefix(&mut self, prefix: &str, shared: bool) -> Vec<String> {
        let mut affected = Vec::new();
        for file in &mut self.files {
            if crate::security::path_matches_dir(&file.path, prefix)
                && !file.hash.is_empty()
                && file.shared != shared
            {
                file.shared = shared;
                affected.push(file.hash.clone());
            }
        }
        affected
    }

    fn upsert_file(&mut self, mut file: FileInfo) {
        if let Some(pos) = self.files.iter().position(|f| f.path == file.path) {
            preserve_runtime_state(&self.files[pos], &mut file);
            self.files[pos] = file;
        } else {
            self.files.push(file);
        }
    }

    fn rebuild_indices(&mut self) {
        self.path_map.clear();
        self.hash_map.clear();
        self.name_tokens.clear();
        for (idx, file) in self.files.iter().enumerate() {
            self.path_map.insert(normalize_path_key(&file.path), idx);
            if !file.hash.is_empty() {
                self.hash_map
                    .entry(file.hash.clone())
                    .or_default()
                    .push(idx);
            }
            let name_lower = file.name.to_lowercase();
            for token in tokenize(&name_lower) {
                self.name_tokens.entry(token).or_default().push(idx);
            }
        }
    }
}

fn preserve_runtime_state(existing: &FileInfo, file: &mut FileInfo) {
    file.priority = existing.priority.clone();
    file.requests = existing.requests;
    file.accepted = existing.accepted;
    file.bytes_transferred = existing.bytes_transferred;
    file.alltime_requests = existing.alltime_requests;
    file.alltime_accepted = existing.alltime_accepted;
    file.alltime_transferred = existing.alltime_transferred;
    file.complete_sources = existing.complete_sources;
    file.shared = existing.shared;
    file.shared_kad = existing.shared_kad;
    file.shared_ed2k = existing.shared_ed2k;
}

fn tokenize(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

/// Categorize a file by its extension, matching eMule's g_aED2KFileTypes table
/// from otherfunctions.cpp. Modern formats (webm, opus, svg, etc.) that postdate
/// eMule are included in the appropriate category.
pub fn infer_file_type(extension: &str) -> String {
    match extension.to_lowercase().as_str() {
        // Audio -- eMule ED2KFT_AUDIO + modern additions (opus)
        "aac" | "ac3" | "aif" | "aifc" | "aiff" | "amr" | "ape" | "au" | "aud"
        | "audio" | "cda" | "dmf" | "dsm" | "dts" | "far" | "flac" | "it"
        | "m1a" | "m2a" | "m4a" | "mdl" | "med" | "mid" | "midi" | "mka"
        | "mod" | "mp1" | "mp2" | "mp3" | "mpa" | "mpc" | "mtm" | "ogg"
        | "opus" | "psm" | "ptm" | "ra" | "rmi" | "s3m" | "snd" | "stm"
        | "umx" | "wav" | "wma" | "xm" => "Audio".into(),

        // Video -- eMule ED2KFT_VIDEO + modern additions (webm)
        "3g2" | "3gp" | "3gp2" | "3gpp" | "amv" | "asf" | "avi" | "bik"
        | "divx" | "dvr-ms" | "flc" | "fli" | "flic" | "flv" | "hdmov"
        | "ifo" | "m1v" | "m2t" | "m2ts" | "m2v" | "m4b" | "m4v" | "mkv"
        | "mov" | "movie" | "mp1v" | "mp2v" | "mp4" | "mpe" | "mpeg"
        | "mpg" | "mpv" | "mpv1" | "mpv2" | "ogm" | "pva" | "qt" | "ram"
        | "ratdvd" | "rm" | "rmm" | "rmvb" | "rv" | "smil" | "smk" | "swf"
        | "tp" | "ts" | "vid" | "video" | "vob" | "vp6" | "webm" | "wm"
        | "wmv" | "xvid" => "Video".into(),

        // Image -- eMule ED2KFT_IMAGE + modern additions (svg, webp)
        "bmp" | "emf" | "gif" | "ico" | "jfif" | "jpe" | "jpeg" | "jpg"
        | "pct" | "pcx" | "pic" | "pict" | "png" | "psd" | "psp" | "svg"
        | "tga" | "tif" | "tiff" | "webp" | "wmf" | "wmp" | "xif" => "Image".into(),

        // Program -- eMule ED2KFT_PROGRAM + modern additions (apk, deb, rpm, scr, app)
        "bat" | "cmd" | "com" | "exe" | "hta" | "js" | "jse" | "msc"
        | "vbe" | "vbs" | "wsf" | "wsh"
        | "apk" | "app" | "deb" | "rpm" | "scr" => "Pro".into(),

        // Document -- eMule ED2KFT_DOCUMENT + modern additions (docx, xlsx, pptx, odt, etc.)
        "chm" | "css" | "diz" | "doc" | "dot" | "hlp" | "htm" | "html"
        | "nfo" | "pdf" | "pps" | "ppt" | "ps" | "rtf" | "text" | "txt"
        | "wri" | "xls" | "xml"
        | "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "epub"
        | "djvu" | "lit" | "mobi" | "azw" => "Doc".into(),

        // Archive -- eMule ED2KFT_ARCHIVE + modern additions (xz)
        "7z" | "ace" | "alz" | "arc" | "arj" | "bz2" | "cab" | "cbr"
        | "cbz" | "gz" | "hqx" | "lha" | "lzh" | "msi" | "pak" | "par"
        | "par2" | "rar" | "sit" | "sitx" | "tar" | "tbz2" | "tgz"
        | "xpi" | "xz" | "z" | "zip" => "Arc".into(),

        // CD-Image -- eMule ED2KFT_CDIMAGE
        "bin" | "bwa" | "bwi" | "bws" | "bwt" | "ccd" | "cue" | "dmg"
        | "img" | "iso" | "mdf" | "mds" | "nrg" | "sub" | "toast" => "Iso".into(),

        // Collection
        "emulecollection" => "EmuleCollection".into(),

        _ => String::new(),
    }
}
