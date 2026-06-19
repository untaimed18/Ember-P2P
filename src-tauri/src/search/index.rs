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
pub(crate) fn normalize_path_key(path: &str) -> String {
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

    /// Insert/update a file and incrementally patch `path_map`/`hash_map`/
    /// `name_tokens` so lookups (`get_by_hash`, `get_by_path`) see the file
    /// immediately, without paying the O(n) `rebuild_indices` cost. Used by the
    /// per-file hashing loop: previously this only touched `files`, so a freshly
    /// hashed share stayed invisible to the upload path (and path lookups) until
    /// the entire folder scan finished and called `rebuild()`.
    pub fn add_file_no_rebuild(&mut self, file: FileInfo) {
        self.upsert_file_indexed(file);
    }

    pub fn rebuild(&mut self) {
        self.rebuild_indices();
    }

    pub fn reconcile_files_for_folders(&mut self, folders: &[String], discovered: Vec<FileInfo>) {
        // Use case-normalized keys so a discovered file isn't dropped (then
        // re-added) just because its path casing differs from the stored one
        // on a case-insensitive filesystem.
        let discovered_keys: HashSet<String> = discovered
            .iter()
            .map(|file| normalize_path_key(&file.path))
            .collect();
        self.files.retain(|file| {
            !folders
                .iter()
                .any(|folder| crate::security::path_matches_dir(&file.path, folder))
                || discovered_keys.contains(&normalize_path_key(&file.path))
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
                    media: None,
                    spam_rating: 0,
                    is_spam: false,
                    clean_name: String::new(),
                    result_origin: ORIGIN_LOCAL.to_string(),
                })
            })
            .collect()
    }

    pub fn get_by_hash(&self, hash: &str) -> Option<&FileInfo> {
        // When multiple shares have the same MD4 (e.g. the user re-added
        // the same file from two folders), pick a deterministic winner
        // rather than `indices.first()` (which depends on insertion order).
        // Preference order: highest upload priority first, then shortest
        // path so results don't flip between runs as folders rescan.
        let indices = self.hash_map.get(hash)?;
        let mut best: Option<&FileInfo> = None;
        for &idx in indices {
            let Some(candidate) = self.files.get(idx) else {
                continue;
            };
            best = Some(match best {
                None => candidate,
                Some(prev) => {
                    let p_prev = crate::network::ed2k::upload::priority_weight(&prev.priority);
                    let p_cand = crate::network::ed2k::upload::priority_weight(&candidate.priority);
                    if p_cand > p_prev
                        || (p_cand == p_prev && candidate.path.len() < prev.path.len())
                    {
                        candidate
                    } else {
                        prev
                    }
                }
            });
        }
        best
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

    /// Remove only the pending (unhashed) entries that fall under one of
    /// `prefixes`. Used when a single folder's scan is cancelled: the global
    /// `remove_pending_files` would also drop the in-progress entries of other
    /// folders that are still being scanned concurrently, making their files
    /// vanish from the library until the next reload.
    pub fn remove_pending_files_under(&mut self, prefixes: &[String]) {
        if prefixes.is_empty() {
            return;
        }
        let before = self.files.len();
        self.files.retain(|f| {
            !(f.id.starts_with("pending:")
                && prefixes
                    .iter()
                    .any(|p| crate::security::path_matches_dir(&f.path, p)))
        });
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
            Some((
                self.files[last_idx].path.clone(),
                self.files[last_idx].hash.clone(),
                tokenize(&self.files[last_idx].name.to_lowercase()),
            ))
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
            // The moved element previously lived at `last_idx`; repoint all of
            // its index entries to `pos`. The removed-file cleanup above only
            // stripped the *removed* file's hash/tokens (which usually differ
            // from the moved file's), so we must explicitly remove the stale
            // `last_idx` from the moved file's own buckets before adding `pos`.
            // Without this, `hash_map`/`name_tokens` accumulate dangling indices
            // (out-of-bounds, or pointing at an unrelated file once the slot is
            // reused) until the next full `rebuild()`.
            self.path_map.insert(normalize_path_key(&moved_path), pos);
            if !moved_hash.is_empty() {
                let v = self.hash_map.entry(moved_hash).or_default();
                v.retain(|&i| i != last_idx && i != pos);
                v.push(pos);
            }
            for token in moved_tokens {
                let v = self.name_tokens.entry(token).or_default();
                v.retain(|&i| i != last_idx && i != pos);
                v.push(pos);
            }
        }

        removed
    }

    pub fn update_alltime_stats(
        &mut self,
        hash: &str,
        alltime_requests: u32,
        alltime_accepted: u32,
        alltime_transferred: u64,
    ) {
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
    pub fn apply_upload_share_deltas(
        &mut self,
        hash_hex: &str,
        inc_requests: u32,
        inc_accepted: u32,
    ) {
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

    /// Apply `priority` to every file that lives under `folder` (the folder
    /// itself or any descendant), mirroring eMule's per-directory priority.
    /// Returns the `(path, hash)` of each file actually changed so the caller
    /// can push the new priority into `known.met`. Files already at `priority`
    /// are skipped so the returned set stays minimal.
    pub fn set_priority_under_folder(
        &mut self,
        folder: &str,
        priority: &str,
    ) -> Vec<(String, String)> {
        let mut changed = Vec::new();
        for file in &mut self.files {
            if crate::security::path_matches_dir(&file.path, folder) && file.priority != priority {
                file.priority = priority.to_string();
                changed.push((file.path.clone(), file.hash.clone()));
            }
        }
        changed
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

    /// Like `upsert_file`, but keeps `path_map`/`hash_map`/`name_tokens`
    /// consistent for the affected slot so no full rebuild is required.
    fn upsert_file_indexed(&mut self, mut file: FileInfo) {
        let key = normalize_path_key(&file.path);
        if let Some(pos) = self
            .files
            .iter()
            .position(|f| normalize_path_key(&f.path) == key)
        {
            let old = self.files[pos].clone();
            self.remove_index_entries(pos, &old);
            preserve_runtime_state(&self.files[pos], &mut file);
            self.files[pos] = file;
            self.add_index_entries(pos);
        } else {
            let idx = self.files.len();
            self.files.push(file);
            self.add_index_entries(idx);
        }
    }

    /// Remove the map contributions of the file currently (or formerly) at
    /// `pos`. `file` must describe the path/hash/name whose entries are being
    /// removed (it may differ from `self.files[pos]` when replacing in place).
    fn remove_index_entries(&mut self, pos: usize, file: &FileInfo) {
        self.path_map.remove(&normalize_path_key(&file.path));
        if !file.hash.is_empty() {
            if let Some(v) = self.hash_map.get_mut(&file.hash) {
                v.retain(|&i| i != pos);
                if v.is_empty() {
                    self.hash_map.remove(&file.hash);
                }
            }
        }
        for token in tokenize(&file.name.to_lowercase()) {
            if let Some(v) = self.name_tokens.get_mut(&token) {
                v.retain(|&i| i != pos);
                if v.is_empty() {
                    self.name_tokens.remove(&token);
                }
            }
        }
    }

    /// Add the map contributions for the file at `pos` (derived from
    /// `self.files[pos]`).
    fn add_index_entries(&mut self, pos: usize) {
        let (path_key, hash, name_lower) = {
            let file = &self.files[pos];
            (
                normalize_path_key(&file.path),
                file.hash.clone(),
                file.name.to_lowercase(),
            )
        };
        self.path_map.insert(path_key, pos);
        if !hash.is_empty() {
            self.hash_map.entry(hash).or_default().push(pos);
        }
        for token in tokenize(&name_lower) {
            self.name_tokens.entry(token).or_default().push(pos);
        }
    }

    fn upsert_file(&mut self, mut file: FileInfo) {
        // Match by the same case-normalized key used for `path_map` (lowercased
        // on Windows). Comparing raw path strings let the same file re-appear
        // under different casing (e.g. C:\Foo vs c:\foo), which pushed a
        // duplicate entry while the index silently collapsed them onto one key.
        let key = normalize_path_key(&file.path);
        if let Some(pos) = self
            .files
            .iter()
            .position(|f| normalize_path_key(&f.path) == key)
        {
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
        "aac" | "ac3" | "aif" | "aifc" | "aiff" | "amr" | "ape" | "au" | "aud" | "audio"
        | "cda" | "dmf" | "dsm" | "dts" | "far" | "flac" | "it" | "m1a" | "m2a" | "m4a" | "mdl"
        | "med" | "mid" | "midi" | "mka" | "mod" | "mp1" | "mp2" | "mp3" | "mpa" | "mpc"
        | "mtm" | "ogg" | "opus" | "psm" | "ptm" | "ra" | "rmi" | "s3m" | "snd" | "stm" | "umx"
        | "wav" | "wma" | "xm" => "Audio".into(),

        // Video -- eMule ED2KFT_VIDEO + modern additions (webm)
        "3g2" | "3gp" | "3gp2" | "3gpp" | "amv" | "asf" | "avi" | "bik" | "divx" | "dvr-ms"
        | "flc" | "fli" | "flic" | "flv" | "hdmov" | "ifo" | "m1v" | "m2t" | "m2ts" | "m2v"
        | "m4b" | "m4v" | "mkv" | "mov" | "movie" | "mp1v" | "mp2v" | "mp4" | "mpe" | "mpeg"
        | "mpg" | "mpv" | "mpv1" | "mpv2" | "ogm" | "pva" | "qt" | "ram" | "ratdvd" | "rm"
        | "rmm" | "rmvb" | "rv" | "smil" | "smk" | "swf" | "tp" | "ts" | "vid" | "video"
        | "vob" | "vp6" | "webm" | "wm" | "wmv" | "xvid" => "Video".into(),

        // Image -- eMule ED2KFT_IMAGE + modern additions (svg, webp)
        "bmp" | "emf" | "gif" | "ico" | "jfif" | "jpe" | "jpeg" | "jpg" | "pct" | "pcx" | "pic"
        | "pict" | "png" | "psd" | "psp" | "svg" | "tga" | "tif" | "tiff" | "webp" | "wmf"
        | "wmp" | "xif" => "Image".into(),

        // Program -- eMule ED2KFT_PROGRAM + modern additions (apk, deb, rpm, scr, app)
        "bat" | "cmd" | "com" | "exe" | "hta" | "js" | "jse" | "msc" | "vbe" | "vbs" | "wsf"
        | "wsh" | "apk" | "app" | "deb" | "rpm" | "scr" => "Pro".into(),

        // Document -- eMule ED2KFT_DOCUMENT + modern additions (docx, xlsx, pptx, odt, etc.)
        "chm" | "css" | "diz" | "doc" | "dot" | "hlp" | "htm" | "html" | "nfo" | "pdf" | "pps"
        | "ppt" | "ps" | "rtf" | "text" | "txt" | "wri" | "xls" | "xml" | "docx" | "xlsx"
        | "pptx" | "odt" | "ods" | "odp" | "epub" | "djvu" | "lit" | "mobi" | "azw" => "Doc".into(),

        // Archive -- eMule ED2KFT_ARCHIVE + modern additions (xz)
        "7z" | "ace" | "alz" | "arc" | "arj" | "bz2" | "cab" | "cbr" | "cbz" | "gz" | "hqx"
        | "lha" | "lzh" | "msi" | "pak" | "par" | "par2" | "rar" | "sit" | "sitx" | "tar"
        | "tbz2" | "tgz" | "xpi" | "xz" | "z" | "zip" => "Arc".into(),

        // CD-Image -- eMule ED2KFT_CDIMAGE
        "bin" | "bwa" | "bwi" | "bws" | "bwt" | "ccd" | "cue" | "dmg" | "img" | "iso" | "mdf"
        | "mds" | "nrg" | "sub" | "toast" => "Iso".into(),

        // Collection
        "emulecollection" => "EmuleCollection".into(),

        _ => String::new(),
    }
}
