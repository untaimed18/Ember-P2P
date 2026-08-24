use std::collections::{HashMap, HashSet};

use crate::search::merge::ORIGIN_LOCAL;
use crate::types::{FileInfo, SearchResult};

pub struct LocalIndex {
    files: Vec<FileInfo>,
    /// Keyed by `normalize_path_key(file.path)` so Windows paths that differ
    /// only in case resolve to the same index entry.
    path_map: HashMap<String, usize>,
    hash_map: HashMap<String, Vec<usize>>,
    /// Keyed by `FileInfo::id`. Buckets rather than a single index because ids
    /// are only unique while a row is a placeholder (those embed the path): a
    /// completed row is keyed by its content hash, so two copies of the same
    /// file share one id exactly as they share one `hash_map` key.
    id_map: HashMap<String, Vec<usize>>,
    name_tokens: HashMap<String, Vec<usize>>,
}

/// Temporary id for a row that has never been hashed, so the index has nothing
/// else to identify it by. Cancelling the scan discards these: without a hash
/// they cannot be served, searched or published.
pub const PENDING_ID_PREFIX: &str = "pending:";

/// Temporary id for an *already hashed* row queued for a one-time digest
/// top-up (the AICH or Ember BLAKE3 migration passes).
///
/// A separate prefix because the two have opposite cancellation semantics and
/// sharing one wiped the Library. On the first launch after the digest
/// migration landed, every record in an older `known.met` needs a top-up, so
/// every row carried a temp id — and `remove_pending_files`, whose contract is
/// "drop the unhashed rows", then deleted the entire library the moment the
/// user pressed Stop. Those rows have a valid eD2K hash and full metadata and
/// lack only an optional digest, so they must survive.
pub const REHASH_ID_PREFIX: &str = "rehash:";

/// Path-unique temp id for a row awaiting a digest top-up. Path-unique rather
/// than content-keyed because `finalize_pending_hash` and `remove_file_by_id`
/// both take the first match, so a shared content hash let one copy's outcome
/// land on a different, healthy copy.
pub fn rehash_id(path: &str) -> String {
    format!("{REHASH_ID_PREFIX}{path}")
}

/// Result of applying a hash-wide share-state change. `hashes` contains each
/// complete file identity once for `known.met` persistence; `changed_paths`
/// also counts pending rows, which have no hash to persist yet.
#[derive(Debug, Default)]
pub struct ShareMutation {
    pub hashes: Vec<String>,
    pub changed_paths: usize,
    pub pending_paths: Vec<String>,
    /// Paths of *hashed* rows that were flipped. Used to clear any stale
    /// pending intent recorded for the same path while the file was hashing,
    /// so the intent cannot resurrect an old share state on a later rehash.
    pub hashed_paths: Vec<String>,
}

/// Windows filesystems are (by default) case-insensitive; indexing a path that
/// arrived from the watcher in one casing and lookups that arrive from the UI
/// in another would spuriously miss. Lowercase the path on Windows; preserve
/// it exactly on other platforms where case matters.
#[inline]
pub(crate) fn normalize_path_key(path: &str) -> String {
    if cfg!(windows) {
        let normalized = path.replace('/', "\\");
        let normalized = normalized
            .strip_prefix(r"\\?\UNC\")
            .map(|rest| format!(r"\\{rest}"))
            .or_else(|| normalized.strip_prefix(r"\\?\").map(str::to_string))
            .unwrap_or(normalized);
        normalized.to_lowercase()
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
            id_map: HashMap::new(),
            name_tokens: HashMap::new(),
        }
    }

    pub fn add_files(&mut self, files: Vec<FileInfo>) {
        let mut lookup = self.path_lookup();
        for file in files {
            self.upsert_file_with_lookup(file, &mut lookup);
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

    pub fn reconcile_files_for_folders(
        &mut self,
        folders: &[String],
        discovered: Vec<FileInfo>,
        remove_missing: bool,
    ) {
        // Use case-normalized keys so a discovered file isn't dropped (then
        // re-added) just because its path casing differs from the stored one
        // on a case-insensitive filesystem.
        if remove_missing {
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
        }
        let mut lookup = self.path_lookup();
        for file in discovered {
            self.upsert_file_with_lookup(file, &mut lookup);
        }
        self.rebuild_indices();
    }

    pub fn search(&self, query: &str) -> Vec<SearchResult> {
        // Same boolean grammar as KAD/server (`AND`/`OR`/`NOT`/`-`/quotes).
        // Token-OR against name_tokens disagreed with network filtering for
        // the same typed query (e.g. `foo OR bar`, `foo -bar`).
        let Some(expr) = crate::search::query::parse(query) else {
            return Vec::new();
        };
        let positive = expr.positive_terms();

        let mut results: Vec<(usize, u32)> = self
            .files
            .iter()
            .enumerate()
            .filter_map(|(idx, file)| {
                let name_lower = file.name.to_lowercase();
                if !expr.matches(&name_lower) {
                    return None;
                }
                let score = if positive.is_empty() {
                    1u32
                } else {
                    positive
                        .iter()
                        .filter(|t| name_lower.contains(t.as_str()))
                        .count()
                        .max(1) as u32
                };
                Some((idx, score))
            })
            .collect();
        results.sort_by_key(|entry| std::cmp::Reverse(entry.1));

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
                    origin_server_ip: None,
                    spam_reasons: Vec::new(),
                    spam_reason_details: Vec::new(),
                })
            })
            .collect()
    }

    pub fn get_by_hash(&self, hash: &str) -> Option<&FileInfo> {
        // When multiple shares have the same MD4 (e.g. the user re-added
        // the same file from two folders), pick a deterministic winner
        // rather than `indices.first()` (which depends on insertion order).
        // Preference order: a currently shared copy first, then highest upload
        // priority, then shortest path so results don't flip between runs as
        // folders rescan. A transient duplicate-state mismatch must never make
        // the upload resolver pick an unshared row and reject a hash that still
        // has another explicitly shared physical copy.
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
                    if (candidate.shared && !prev.shared)
                        || (candidate.shared == prev.shared
                            && (p_cand > p_prev
                                || (p_cand == p_prev && candidate.path.len() < prev.path.len())))
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

    /// Restore a previously captured snapshot when a cross-component
    /// persistence transaction fails after an optimistic in-memory mutation.
    pub fn restore_snapshot(&mut self, files: Vec<FileInfo>) {
        self.files = files;
        self.rebuild_indices();
    }

    /// Replace a pending discovery row with its completed identity while
    /// retaining the *current* user-controlled state. Share/priority edits can
    /// arrive while hashing is in progress, so cloning the stale discovery
    /// snapshot here would undo an explicit Unshare or priority change.
    ///
    /// Returns the completed row only when the pending row still exists. A
    /// folder removal or cancellation that removed it wins over hash completion.
    pub fn finalize_pending_hash(
        &mut self,
        pending_id: &str,
        mut completed: FileInfo,
    ) -> Option<FileInfo> {
        let pos = self.position_by_id(pending_id)?;
        let pending = self.swap_remove_indexed(pos)?;
        completed.shared = pending.shared;
        completed.priority = pending.priority;
        completed.bytes_transferred = pending.bytes_transferred;
        completed.requests = pending.requests;
        completed.accepted = pending.accepted;
        completed.alltime_requests = pending.alltime_requests;
        completed.alltime_accepted = pending.alltime_accepted;
        completed.alltime_transferred = pending.alltime_transferred;
        completed.complete_sources = pending.complete_sources;
        // `set_friends_only_by_paths` deliberately accepts rows that are still
        // hashing, so a restriction applied during that window has to survive
        // completion or it is silently discarded at the moment the file becomes
        // servable.
        completed.friends_only = pending.friends_only;
        self.add_file_no_rebuild(completed.clone());
        Some(completed)
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

    /// Remove indexed rows that are no longer covered by any active shared
    /// root, returning every removed row (including pending/unhashed rows).
    /// Used by whole-settings root topology changes where replacing a parent
    /// with one of its children must retain the child's existing entries.
    pub fn remove_files_outside_folders(&mut self, folders: &[String]) -> Vec<FileInfo> {
        let mut removed = Vec::new();
        self.files.retain(|file| {
            let keep = folders
                .iter()
                .any(|folder| crate::security::path_matches_dir(&file.path, folder));
            if !keep {
                removed.push(file.clone());
            }
            keep
        });
        if !removed.is_empty() {
            self.rebuild_indices();
        }
        removed
    }

    /// Remove all files that still have a "pending:..." temp id (unhashed).
    ///
    /// Deliberately does not touch [`REHASH_ID_PREFIX`] rows. Those are already
    /// hashed and fully described by `known.met`; they are only queued for an
    /// optional digest top-up, so discarding them on cancellation would empty
    /// the Library of files that are perfectly servable.
    pub fn remove_pending_files(&mut self) {
        let before = self.files.len();
        self.files.retain(|f| !f.id.starts_with(PENDING_ID_PREFIX));
        if self.files.len() != before {
            self.rebuild_indices();
        }
    }

    /// Give up on a placeholder row whose hash pass ended without a result,
    /// returning the row only if it was actually removed.
    ///
    /// The two placeholder kinds part company here. An unhashed row goes: with
    /// no hash it cannot be served, searched or published, so keeping it would
    /// only show the user a file that does not work. A re-hash row stays and is
    /// merely put back under its content-hash id — it was already complete, and
    /// what it missed was an optional digest top-up, so dropping it would
    /// unshare a healthy file because an antivirus scanner held it for a moment.
    ///
    /// Only `id` changes on the kept path, so `id_map` is the one index that
    /// needs repointing.
    pub fn abandon_hash_placeholder(&mut self, temp_id: &str) -> Option<FileInfo> {
        let pos = self.position_by_id(temp_id)?;
        if temp_id.starts_with(REHASH_ID_PREFIX) && !self.files[pos].hash.is_empty() {
            let content_id = self.files[pos].hash.clone();
            self.files[pos].id = content_id.clone();
            // The row keeps its slot, so only the id key moves; every other
            // map still points at `pos`.
            if let Some(v) = self.id_map.get_mut(temp_id) {
                v.retain(|&i| i != pos);
                if v.is_empty() {
                    self.id_map.remove(temp_id);
                }
            }
            self.id_map.entry(content_id).or_default().push(pos);
            return None;
        }
        self.swap_remove_indexed(pos)
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
            !(f.id.starts_with(PENDING_ID_PREFIX)
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
        let pos = self.position_by_id(id)?;
        self.swap_remove_indexed(pos)
    }

    /// Lowest index of a row carrying `id`, matching the semantics of the
    /// `files.iter().position(...)` scan this replaces.
    ///
    /// The scan ran once per completed file with the index write lock held and
    /// compared `String` ids, so a full-library hash pass was O(n²) string
    /// comparisons with every reader (upload hash resolution, the UI's shared
    /// file queries) blocked behind it. Bucket entries are re-checked against
    /// `files` so a drifted map can only fail to find a row, never resolve one
    /// caller's completion onto an unrelated file.
    fn position_by_id(&self, id: &str) -> Option<usize> {
        self.id_map
            .get(id)?
            .iter()
            .copied()
            .filter(|&idx| self.files.get(idx).is_some_and(|file| file.id == id))
            .min()
    }

    /// Remove a file by path.
    ///
    /// The stored index is re-checked against `files` for the same reason
    /// [`Self::position_by_id`] re-checks its buckets: a drifted map must only
    /// fail to find a row, never resolve onto an unrelated one — and here a
    /// stale entry would also index past the end of `files`.
    pub fn remove_file_by_path(&mut self, path: &str) -> Option<FileInfo> {
        let key = normalize_path_key(path);
        let pos = *self.path_map.get(&key)?;
        if self.files.get(pos).map(|f| normalize_path_key(&f.path)) != Some(key) {
            return None;
        }
        self.swap_remove_indexed(pos)
    }

    /// swap_remove the file at `pos` and incrementally patch path_map,
    /// hash_map, and name_tokens so callers don't need a full rebuild.
    ///
    /// `None` for an out-of-range `pos`. Callers resolve `pos` from one of the
    /// index maps, so an entry that outlived its row would otherwise panic here
    /// — on the unsigned `len() - 1` when `files` is empty, or inside
    /// `swap_remove` otherwise.
    fn swap_remove_indexed(&mut self, pos: usize) -> Option<FileInfo> {
        if pos >= self.files.len() {
            return None;
        }
        let last_idx = self.files.len() - 1;
        let moved = pos != last_idx;
        let moved_key = if moved {
            Some((
                self.files[last_idx].path.clone(),
                self.files[last_idx].hash.clone(),
                self.files[last_idx].id.clone(),
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
        if !removed.id.is_empty() {
            if let Some(v) = self.id_map.get_mut(&removed.id) {
                v.retain(|&i| i != pos && i != last_idx);
                if v.is_empty() {
                    self.id_map.remove(&removed.id);
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

        if let Some((moved_path, moved_hash, moved_id, moved_tokens)) = moved_key {
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
            if !moved_id.is_empty() {
                let v = self.id_map.entry(moved_id).or_default();
                v.retain(|&i| i != last_idx && i != pos);
                v.push(pos);
            }
            for token in moved_tokens {
                let v = self.name_tokens.entry(token).or_default();
                v.retain(|&i| i != last_idx && i != pos);
                v.push(pos);
            }
        }

        Some(removed)
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

    /// Session request/accept counters when peers ask for / get a slot for
    /// this file. All-time counters advance only when the authoritative
    /// known.met record accepted the same update.
    pub fn apply_upload_share_deltas(
        &mut self,
        hash_hex: &str,
        inc_requests: u32,
        inc_accepted: u32,
        persist_alltime: bool,
    ) {
        if inc_requests == 0 && inc_accepted == 0 {
            return;
        }
        if let Some(indices) = self.hash_map.get(hash_hex).cloned() {
            for idx in indices {
                if let Some(file) = self.files.get_mut(idx) {
                    file.requests = file.requests.saturating_add(inc_requests);
                    file.accepted = file.accepted.saturating_add(inc_accepted);
                    if persist_alltime {
                        file.alltime_requests = file.alltime_requests.saturating_add(inc_requests);
                        file.alltime_accepted = file.alltime_accepted.saturating_add(inc_accepted);
                    }
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
    pub fn apply_upload_completed_bytes(
        &mut self,
        hash_hex: &str,
        bytes: u64,
        persist_alltime: bool,
    ) {
        if bytes == 0 {
            return;
        }
        if let Some(indices) = self.hash_map.get(hash_hex).cloned() {
            for idx in indices {
                if let Some(file) = self.files.get_mut(idx) {
                    file.bytes_transferred = file.bytes_transferred.saturating_add(bytes);
                    if persist_alltime {
                        file.alltime_transferred = file.alltime_transferred.saturating_add(bytes);
                    }
                }
            }
        }
    }

    pub fn set_file_priority_by_path(&mut self, path: &str, priority: &str) -> bool {
        self.set_file_priority_by_path_count(path, priority) > 0
    }

    /// Hash-wide counterpart of [`set_file_priority_by_path`]. Returns every
    /// path that changed so bulk-operation feedback remains accurate when one
    /// selected duplicate updates several physical copies.
    pub fn set_file_priority_by_path_count(&mut self, path: &str, priority: &str) -> usize {
        let key = normalize_path_key(path);
        let Some(selected) = self
            .files
            .iter()
            .find(|file| normalize_path_key(&file.path) == key)
        else {
            return 0;
        };
        let hash = selected.hash.clone();
        let mut changed = 0usize;
        for file in &mut self.files {
            let is_target = if hash.is_empty() {
                normalize_path_key(&file.path) == key
            } else {
                file.hash == hash
            };
            if is_target && file.priority != priority {
                file.priority = priority.to_string();
                changed += 1;
            }
        }
        changed
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
        let hashes: HashSet<String> = self
            .files
            .iter()
            .filter(|file| crate::security::path_matches_dir(&file.path, folder))
            .filter(|&file| !file.hash.is_empty() ).map(|file| file.hash.clone())
            .collect();
        let pending_paths: HashSet<String> = self
            .files
            .iter()
            .filter(|file| {
                file.hash.is_empty() && crate::security::path_matches_dir(&file.path, folder)
            })
            .map(|file| normalize_path_key(&file.path))
            .collect();
        let mut changed = Vec::new();
        for file in &mut self.files {
            if (hashes.contains(&file.hash)
                || (file.hash.is_empty()
                    && pending_paths.contains(&normalize_path_key(&file.path))))
                && file.priority != priority
            {
                file.priority = priority.to_string();
                changed.push((file.path.clone(), file.hash.clone()));
            }
        }
        changed
    }

    /// Like [`set_priority_under_folder`](Self::set_priority_under_folder),
    /// but restricted to paths present in `only_paths`. Used at startup so a
    /// shared folder's configured default priority seeds genuinely new files
    /// (no prior `known.met` record) without clobbering a per-file priority
    /// that was just restored from an existing record — a per-file override
    /// should stick even if it happens to differ from the folder's current
    /// default, exactly like `set_file_priority` intends.
    pub fn set_priority_under_folder_for_paths(
        &mut self,
        folder: &str,
        priority: &str,
        only_paths: &HashSet<String>,
    ) -> Vec<(String, String)> {
        let hashes: HashSet<String> = self
            .files
            .iter()
            .filter(|file| only_paths.contains(&normalize_path_key(&file.path)))
            .filter(|file| crate::security::path_matches_dir(&file.path, folder))
            .filter(|&file| !file.hash.is_empty() ).map(|file| file.hash.clone())
            .collect();
        let pending_paths: HashSet<String> = self
            .files
            .iter()
            .filter(|file| {
                file.hash.is_empty()
                    && only_paths.contains(&normalize_path_key(&file.path))
                    && crate::security::path_matches_dir(&file.path, folder)
            })
            .map(|file| normalize_path_key(&file.path))
            .collect();
        let mut changed = Vec::new();
        for file in &mut self.files {
            if (hashes.contains(&file.hash)
                || (file.hash.is_empty()
                    && pending_paths.contains(&normalize_path_key(&file.path))))
                && file.priority != priority
            {
                file.priority = priority.to_string();
                changed.push((file.path.clone(), file.hash.clone()));
            }
        }
        changed
    }

    /// Record a freshly computed Ember BLAKE3 digest against every copy of
    /// this content. Returns whether anything changed.
    ///
    /// Keyed by content hash rather than path because the digest describes
    /// the bytes, so all duplicates of the same file share it.
    pub fn set_ember_file_hash_by_hash(&mut self, hash: &str, ember_file_hash: &str) -> bool {
        if hash.is_empty() || ember_file_hash.is_empty() {
            return false;
        }
        let mut changed = false;
        for file in &mut self.files {
            if file.hash == hash && file.ember_file_hash != ember_file_hash {
                file.ember_file_hash = ember_file_hash.to_string();
                changed = true;
            }
        }
        changed
    }

    pub fn set_file_shared_by_path(&mut self, path: &str, shared: bool) -> ShareMutation {
        let key = normalize_path_key(path);
        let Some(selected) = self
            .files
            .iter()
            .find(|file| normalize_path_key(&file.path) == key)
        else {
            return ShareMutation::default();
        };
        let hash = selected.hash.clone();
        let mut mutation = ShareMutation::default();
        for file in &mut self.files {
            let is_target = if hash.is_empty() {
                normalize_path_key(&file.path) == key
            } else {
                file.hash == hash
            };
            if is_target && file.shared != shared {
                file.shared = shared;
                mutation.changed_paths += 1;
                if file.hash.is_empty() {
                    mutation.pending_paths.push(file.path.clone());
                } else {
                    mutation.hashed_paths.push(file.path.clone());
                    if !mutation.hashes.contains(&file.hash) {
                        mutation.hashes.push(file.hash.clone());
                    }
                }
            }
        }
        mutation
    }

    pub fn set_shared_by_path_prefix(&mut self, prefix: &str, shared: bool) -> ShareMutation {
        let hashes: HashSet<String> = self
            .files
            .iter()
            .filter(|file| crate::security::path_matches_dir(&file.path, prefix))
            .filter(|&file| !file.hash.is_empty() ).map(|file| file.hash.clone())
            .collect();
        let pending_paths: HashSet<String> = self
            .files
            .iter()
            .filter(|file| {
                file.hash.is_empty() && crate::security::path_matches_dir(&file.path, prefix)
            })
            .map(|file| normalize_path_key(&file.path))
            .collect();
        let mut mutation = ShareMutation::default();
        for file in &mut self.files {
            if (hashes.contains(&file.hash)
                || (file.hash.is_empty()
                    && pending_paths.contains(&normalize_path_key(&file.path))))
                && file.shared != shared
            {
                file.shared = shared;
                mutation.changed_paths += 1;
                if file.hash.is_empty() {
                    mutation.pending_paths.push(file.path.clone());
                } else {
                    mutation.hashed_paths.push(file.path.clone());
                    if !mutation.hashes.contains(&file.hash) {
                        mutation.hashes.push(file.hash.clone());
                    }
                }
            }
        }
        mutation
    }

    /// Bulk variant of [`set_file_shared_by_path`](Self::set_file_shared_by_path)
    /// for an explicit path list (the Library multi-select share/unshare
    /// actions). Returns the ed2k hash of every file actually flipped, so
    /// callers can push a `known.met` persistence command per file without a
    /// second round of path lookups. Files with no hash yet (still hashing)
    /// are skipped — there's no known.met record to persist the flag into
    /// yet, mirroring `set_shared_by_path_prefix`.
    pub fn set_shared_by_paths(&mut self, paths: &[String], shared: bool) -> ShareMutation {
        let keys: HashSet<String> = paths.iter().map(|p| normalize_path_key(p)).collect();
        let hashes: HashSet<String> = self
            .files
            .iter()
            .filter(|file| keys.contains(&normalize_path_key(&file.path)))
            .filter(|&file| !file.hash.is_empty() ).map(|file| file.hash.clone())
            .collect();
        let pending_paths: HashSet<String> = self
            .files
            .iter()
            .filter(|file| file.hash.is_empty() && keys.contains(&normalize_path_key(&file.path)))
            .map(|file| normalize_path_key(&file.path))
            .collect();
        let mut mutation = ShareMutation::default();
        for file in &mut self.files {
            if (hashes.contains(&file.hash)
                || (file.hash.is_empty()
                    && pending_paths.contains(&normalize_path_key(&file.path))))
                && file.shared != shared
            {
                file.shared = shared;
                mutation.changed_paths += 1;
                if file.hash.is_empty() {
                    mutation.pending_paths.push(file.path.clone());
                } else {
                    mutation.hashed_paths.push(file.path.clone());
                    if !mutation.hashes.contains(&file.hash) {
                        mutation.hashes.push(file.hash.clone());
                    }
                }
            }
        }
        mutation
    }

    /// Restrict (or unrestrict) a batch of paths to mutual friends.
    ///
    /// Deliberately independent of `shared`: scope answers "who may see this",
    /// `shared` answers "is it offered at all". Flipping scope on an unshared
    /// file is harmless and takes effect if the user shares it again.
    ///
    /// Mirrors `set_shared_by_paths`, including its content-level semantics —
    /// every copy of the same hash moves together, because scope is a property
    /// of the content we publish, not of one path on disk.
    pub fn set_friends_only_by_paths(
        &mut self,
        paths: &[String],
        friends_only: bool,
    ) -> ShareMutation {
        let keys: HashSet<String> = paths.iter().map(|p| normalize_path_key(p)).collect();
        let hashes: HashSet<String> = self
            .files
            .iter()
            .filter(|file| keys.contains(&normalize_path_key(&file.path)))
            .filter(|&file| !file.hash.is_empty() ).map(|file| file.hash.clone())
            .collect();
        let pending_paths: HashSet<String> = self
            .files
            .iter()
            .filter(|file| file.hash.is_empty() && keys.contains(&normalize_path_key(&file.path)))
            .map(|file| normalize_path_key(&file.path))
            .collect();
        let mut mutation = ShareMutation::default();
        for file in &mut self.files {
            if (hashes.contains(&file.hash)
                || (file.hash.is_empty()
                    && pending_paths.contains(&normalize_path_key(&file.path))))
                && file.friends_only != friends_only
            {
                file.friends_only = friends_only;
                mutation.changed_paths += 1;
                if file.hash.is_empty() {
                    mutation.pending_paths.push(file.path.clone());
                } else {
                    mutation.hashed_paths.push(file.path.clone());
                    if !mutation.hashes.contains(&file.hash) {
                        mutation.hashes.push(file.hash.clone());
                    }
                }
            }
        }
        mutation
    }

    /// OR `friends_only` onto index rows whose MD4 is in `hashes`.
    ///
    /// known.met is the durable source of the restriction. A path/mtime
    /// rematch can insert a public row for a hash that is already restricted
    /// on disk; after that catalog is absorbed, this restores the flag so
    /// advertise, badges, and upload resolution agree.
    pub fn or_friends_only_from_hashes(&mut self, hashes: &HashSet<[u8; 16]>) {
        if hashes.is_empty() {
            return;
        }
        for file in &mut self.files {
            if file.friends_only || file.hash.is_empty() {
                continue;
            }
            let Ok(bytes) = hex::decode(&file.hash) else {
                continue;
            };
            if bytes.len() != 16 {
                continue;
            }
            let mut hash = [0u8; 16];
            hash.copy_from_slice(&bytes);
            if hashes.contains(&hash) {
                file.friends_only = true;
            }
        }
    }

    /// Like `upsert_file`, but keeps `path_map`/`hash_map`/`name_tokens`
    /// consistent for the affected slot so no full rebuild is required.
    fn upsert_file_indexed(&mut self, mut file: FileInfo) {
        let key = normalize_path_key(&file.path);
        // `path_map` is authoritative here: the one caller
        // (`finalize_pending_hash`) arrives straight after
        // `swap_remove_indexed`, which patches the map incrementally. The scan
        // this replaces recomputed `normalize_path_key` (two heap allocations on
        // Windows) for every stored row, per hashed file, with the index write
        // lock held — ~15ms at `MAX_DISCOVERED_FILES`, blocking upload hash
        // resolution and the UI's queries for the length of a scan. Keep the
        // scan as a fallback for a map that has drifted, and verify the hit
        // actually points at this path so a stale entry cannot overwrite an
        // unrelated row.
        let existing = match self.path_map.get(&key) {
            Some(&pos)
                if self
                    .files
                    .get(pos)
                    .is_some_and(|f| normalize_path_key(&f.path) == key) =>
            {
                Some(pos)
            }
            _ => self
                .files
                .iter()
                .position(|f| normalize_path_key(&f.path) == key),
        };
        if let Some(pos) = existing {
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
        if !file.id.is_empty() {
            if let Some(v) = self.id_map.get_mut(&file.id) {
                v.retain(|&i| i != pos);
                if v.is_empty() {
                    self.id_map.remove(&file.id);
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
        let (path_key, hash, id, name_lower) = {
            let file = &self.files[pos];
            (
                normalize_path_key(&file.path),
                file.hash.clone(),
                file.id.clone(),
                file.name.to_lowercase(),
            )
        };
        self.path_map.insert(path_key, pos);
        if !hash.is_empty() {
            self.hash_map.entry(hash).or_default().push(pos);
        }
        if !id.is_empty() {
            self.id_map.entry(id).or_default().push(pos);
        }
        for token in tokenize(&name_lower) {
            self.name_tokens.entry(token).or_default().push(pos);
        }
    }

    /// Snapshot `normalize_path_key -> position` for the current `files`.
    ///
    /// Batch inserts keep this alive across the whole loop and patch it as
    /// they go. `path_map` cannot be used directly because it is only
    /// reconciled by `rebuild_indices` after the loop finishes.
    fn path_lookup(&self) -> HashMap<String, usize> {
        self.files
            .iter()
            .enumerate()
            .map(|(idx, file)| (normalize_path_key(&file.path), idx))
            .collect()
    }

    /// `upsert_file` against a caller-maintained lookup, so a batch insert is
    /// linear rather than quadratic.
    ///
    /// The scan this replaces recomputed `normalize_path_key` (two heap
    /// allocations: a separator rewrite and a lowercase) for every stored row
    /// on every insert. A full-library load or reload therefore cost O(n²)
    /// allocations while holding the index write lock — minutes of apparent
    /// hang on a large share, with every reader (upload hash resolution, the
    /// UI's shared-file queries) blocked behind it.
    fn upsert_file_with_lookup(&mut self, mut file: FileInfo, lookup: &mut HashMap<String, usize>) {
        // Match by the same case-normalized key used for `path_map` (lowercased
        // on Windows). Comparing raw path strings let the same file re-appear
        // under different casing (e.g. C:\Foo vs c:\foo), which pushed a
        // duplicate entry while the index silently collapsed them onto one key.
        let key = normalize_path_key(&file.path);
        match lookup.get(&key) {
            Some(&pos) => {
                preserve_runtime_state(&self.files[pos], &mut file);
                self.files[pos] = file;
            }
            None => {
                lookup.insert(key, self.files.len());
                self.files.push(file);
            }
        }
    }

    fn upsert_file(&mut self, file: FileInfo) {
        let mut lookup = self.path_lookup();
        self.upsert_file_with_lookup(file, &mut lookup);
    }

    fn rebuild_indices(&mut self) {
        self.path_map.clear();
        self.hash_map.clear();
        self.id_map.clear();
        self.name_tokens.clear();
        for (idx, file) in self.files.iter().enumerate() {
            self.path_map.insert(normalize_path_key(&file.path), idx);
            if !file.hash.is_empty() {
                self.hash_map
                    .entry(file.hash.clone())
                    .or_default()
                    .push(idx);
            }
            if !file.id.is_empty() {
                self.id_map.entry(file.id.clone()).or_default().push(idx);
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
    file.shared_ember = existing.shared_ember;
    // Carried for the same reason as `shared`, and more urgently: a rediscovered
    // row is built with `friends_only: false`, so dropping it here silently
    // republishes a restricted file to the open network — the watcher firing or
    // the user reloading a folder is enough. known.met keeps the flag, so the
    // restriction reappears at the next restart, which makes the exposure
    // intermittent and near-invisible rather than obvious.
    file.friends_only = existing.friends_only;
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

#[cfg(all(test, windows))]
mod tests {
    use super::normalize_path_key;

    #[test]
    fn windows_path_keys_collapse_separator_and_case_aliases() {
        assert_eq!(
            normalize_path_key(r"C:\Downloads\Video.mkv"),
            normalize_path_key("c:/downloads/video.mkv"),
        );
    }

    #[test]
    fn windows_path_keys_collapse_extended_path_prefix() {
        assert_eq!(
            normalize_path_key(r"\\?\C:\Downloads\Video.mkv"),
            normalize_path_key(r"C:\Downloads\Video.mkv"),
        );
    }
}

#[cfg(test)]
mod local_index_tests {
    use super::{rehash_id, LocalIndex};
    use crate::types::FileInfo;
    use std::collections::HashSet;

    fn file(path: &str, hash: &str, shared: bool, priority: &str) -> FileInfo {
        FileInfo {
            id: hash.to_string(),
            name: path.rsplit(['/', '\\']).next().unwrap_or(path).to_string(),
            path: path.to_string(),
            size: 1,
            hash: hash.to_string(),
            aich_hash: String::new(),
            ember_file_hash: String::new(),
            extension: "bin".to_string(),
            modified_at: 0,
            priority: priority.to_string(),
            requests: 0,
            accepted: 0,
            bytes_transferred: 0,
            alltime_requests: 0,
            alltime_accepted: 0,
            alltime_transferred: 0,
            complete_sources: 0,
            folder: path
                .rsplit_once(['/', '\\'])
                .map_or_else(String::new, |(folder, _)| folder.to_string()),
            shared,
            friends_only: false,
            shared_kad: false,
            shared_ed2k: false,
            shared_ember: false,
        }
    }

    /// `path_map` entries are patched incrementally, so a bug anywhere in that
    /// bookkeeping leaves an index pointing past the end of `files` or at an
    /// unrelated row. Removal must degrade to "not found" the way
    /// `position_by_id` already does, rather than panicking on the unsigned
    /// `len() - 1` or swap-removing whatever now occupies the slot.
    #[test]
    fn removal_ignores_a_stale_path_map_entry() {
        let mut index = LocalIndex::new();
        index.add_files(vec![file(
            "A/keep.bin",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            true,
            "normal",
        )]);

        // Out of range: the row this entry described is gone entirely.
        index
            .path_map
            .insert(super::normalize_path_key("A/ghost.bin"), 99);
        assert!(index.remove_file_by_path("A/ghost.bin").is_none());

        // In range but pointing at a different file than the key names.
        index
            .path_map
            .insert(super::normalize_path_key("A/wrong.bin"), 0);
        assert!(index.remove_file_by_path("A/wrong.bin").is_none());

        assert!(
            index.get_by_path("A/keep.bin").is_some(),
            "a stale entry must not take an unrelated row with it"
        );

        // An empty index is the case that made `len() - 1` underflow.
        let mut empty = LocalIndex::new();
        empty
            .path_map
            .insert(super::normalize_path_key("A/ghost.bin"), 0);
        assert!(empty.remove_file_by_path("A/ghost.bin").is_none());
    }

    #[test]
    fn path_share_change_is_hash_wide() {
        let mut index = LocalIndex::new();
        index.add_files(vec![
            file(
                "A/copy.bin",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                true,
                "normal",
            ),
            file(
                "B/copy.bin",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                true,
                "normal",
            ),
        ]);

        let mutation = index.set_file_shared_by_path("A/copy.bin", false);

        assert_eq!(mutation.changed_paths, 2);
        assert_eq!(mutation.hashes, vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]);
        assert!(!index.get_by_path("A/copy.bin").unwrap().shared);
        assert!(!index.get_by_path("B/copy.bin").unwrap().shared);
    }

    #[test]
    fn or_friends_only_from_hashes_marks_matching_public_row() {
        let mut index = LocalIndex::new();
        index.add_files(vec![
            file(
                "A/public.bin",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                true,
                "normal",
            ),
            file(
                "B/other.bin",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                true,
                "normal",
            ),
        ]);
        let mut hashes = HashSet::new();
        hashes.insert([0xaa; 16]);
        index.or_friends_only_from_hashes(&hashes);
        assert!(
            index.get_by_path("A/public.bin").unwrap().friends_only,
            "a rematched public row must inherit known.met friends-only"
        );
        assert!(
            !index.get_by_path("B/other.bin").unwrap().friends_only,
            "unrelated hashes must stay public"
        );
    }

    #[test]
    fn share_mutation_reports_hashed_paths_for_intent_cleanup() {
        // Every flipped *hashed* row must surface its path so a stale
        // pending intent recorded for the same path (while the file was
        // hashing) is cleared and cannot resurrect an old share state on a
        // later rehash. Pending rows go to pending_paths instead.
        let mut index = LocalIndex::new();
        let mut pending = file("A/pending.bin", "", true, "normal");
        pending.id = "pending:A/pending.bin".to_string();
        index.add_files(vec![
            file(
                "A/hashed.bin",
                "cccccccccccccccccccccccccccccccc",
                true,
                "normal",
            ),
            file(
                "B/hashed.bin",
                "cccccccccccccccccccccccccccccccc",
                true,
                "normal",
            ),
            pending,
        ]);

        let mutation = index.set_shared_by_paths(
            &["A/hashed.bin".to_string(), "A/pending.bin".to_string()],
            false,
        );

        assert_eq!(mutation.changed_paths, 3);
        let mut hashed_paths = mutation.hashed_paths.clone();
        hashed_paths.sort();
        assert_eq!(hashed_paths, vec!["A/hashed.bin", "B/hashed.bin"]);
        assert_eq!(mutation.pending_paths, vec!["A/pending.bin"]);
    }

    #[test]
    fn path_priority_change_is_hash_wide() {
        let mut index = LocalIndex::new();
        index.add_files(vec![
            file(
                "A/copy.bin",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                true,
                "normal",
            ),
            file(
                "B/copy.bin",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                true,
                "normal",
            ),
        ]);

        assert_eq!(
            index.set_file_priority_by_path_count("A/copy.bin", "high"),
            2
        );
        assert_eq!(index.get_by_path("A/copy.bin").unwrap().priority, "high");
        assert_eq!(index.get_by_path("B/copy.bin").unwrap().priority, "high");
    }

    #[test]
    fn hash_lookup_prefers_a_shared_duplicate() {
        let hash = "abababababababababababababababab";
        let mut index = LocalIndex::new();
        index.add_files(vec![
            file("A/x.bin", hash, false, "release"),
            file("B/longer-shared-copy.bin", hash, true, "verylow"),
        ]);

        let resolved = index.get_by_hash(hash).expect("hash should resolve");
        assert!(resolved.shared);
        assert_eq!(resolved.path, "B/longer-shared-copy.bin");
    }

    #[test]
    fn unpersisted_share_interest_only_updates_session_counters() {
        let hash = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
        let mut index = LocalIndex::new();
        index.add_file(file("A/file.bin", hash, true, "normal"));

        index.apply_upload_share_deltas(hash, 2, 1, false);
        let session_only = index.get_by_hash(hash).unwrap();
        assert_eq!(session_only.requests, 2);
        assert_eq!(session_only.accepted, 1);
        assert_eq!(session_only.alltime_requests, 0);
        assert_eq!(session_only.alltime_accepted, 0);

        index.apply_upload_share_deltas(hash, 3, 2, true);
        let persisted = index.get_by_hash(hash).unwrap();
        assert_eq!(persisted.requests, 5);
        assert_eq!(persisted.accepted, 3);
        assert_eq!(persisted.alltime_requests, 3);
        assert_eq!(persisted.alltime_accepted, 2);
    }

    #[test]
    fn folder_unshare_includes_pending_rows() {
        let mut index = LocalIndex::new();
        index.add_files(vec![file("A/pending.bin", "", true, "normal")]);

        let mutation = index.set_shared_by_path_prefix("A", false);

        assert_eq!(mutation.changed_paths, 1);
        assert!(mutation.hashes.is_empty());
        assert!(!index.get_by_path("A/pending.bin").unwrap().shared);
    }

    /// The one-time digest migration queues *every* already-hashed row for a
    /// top-up, so sharing the `pending:` prefix with genuinely unhashed rows
    /// meant the first press of "Stop hashing" after upgrading emptied the
    /// whole Library — files with valid hashes, metadata and counters, gone
    /// until the next restart, and unservable in the meantime.
    #[test]
    fn cancelling_a_scan_keeps_rows_that_only_wanted_a_digest() {
        let mut index = LocalIndex::new();
        let mut unhashed = file("A/new.bin", "", true, "normal");
        unhashed.id = "pending:A/new.bin".to_string();
        let mut rehashing = file(
            "A/known.bin",
            "dddddddddddddddddddddddddddddddd",
            true,
            "normal",
        );
        rehashing.id = rehash_id("A/known.bin");
        index.add_files(vec![unhashed, rehashing]);

        index.remove_pending_files();

        assert!(
            index.get_by_path("A/new.bin").is_none(),
            "an unhashed row has no hash and cannot be served, so it goes"
        );
        assert_eq!(
            index
                .get_by_path("A/known.bin")
                .expect("an already-hashed row must survive cancellation")
                .hash,
            "dddddddddddddddddddddddddddddddd"
        );
    }

    /// A digest pass that fails — an antivirus lock, a sleeping drive — must
    /// not unshare a file that was already complete. The row goes back to its
    /// content-hash id instead of being dropped.
    #[test]
    fn abandoning_a_digest_pass_restores_the_content_hash_id() {
        let mut index = LocalIndex::new();
        let mut rehashing = file(
            "A/known.bin",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            true,
            "normal",
        );
        rehashing.id = rehash_id("A/known.bin");
        index.add_file(rehashing);

        assert!(
            index
                .abandon_hash_placeholder(&rehash_id("A/known.bin"))
                .is_none(),
            "the row is kept, so nothing is handed back to the caller"
        );
        assert_eq!(
            index.get_by_path("A/known.bin").unwrap().id,
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        );

        // An unhashed row has nothing to fall back on and is still removed.
        let mut unhashed = file("A/new.bin", "", true, "normal");
        unhashed.id = "pending:A/new.bin".to_string();
        index.add_file(unhashed);
        assert!(
            index
                .abandon_hash_placeholder("pending:A/new.bin")
                .is_some(),
            "an unhashed row is removed and returned"
        );
        assert!(index.get_by_path("A/new.bin").is_none());
    }

    #[test]
    fn finalize_pending_hash_keeps_live_share_and_priority() {
        let mut index = LocalIndex::new();
        let mut pending = file("A/pending.bin", "", true, "normal");
        pending.id = "pending:A/pending.bin".to_string();
        index.add_file(pending);

        let _ = index.set_file_shared_by_path("A/pending.bin", false);
        assert_eq!(
            index.set_file_priority_by_path_count("A/pending.bin", "high"),
            1
        );

        let completed = file(
            "A/pending.bin",
            "cccccccccccccccccccccccccccccccc",
            true,
            "normal",
        );
        let finalized = index
            .finalize_pending_hash("pending:A/pending.bin", completed)
            .expect("pending row should still exist");

        assert!(!finalized.shared);
        assert_eq!(finalized.priority, "high");
        assert!(index.get_by_path("A/pending.bin").is_some());
        assert!(!index.get_by_path("A/pending.bin").unwrap().shared);
        assert_eq!(index.get_by_path("A/pending.bin").unwrap().priority, "high");
    }

    #[test]
    fn finalize_pending_hash_lands_on_its_own_row() {
        // `upsert_file_indexed` resolves the row through `path_map` instead of
        // scanning every stored row; with neighbours present the completed
        // identity must still land on its own path and leave the other lookups
        // intact (the pending row is swap_removed first, moving another row).
        let mut index = LocalIndex::new();
        let mut pending = file("A/second.bin", "", true, "normal");
        pending.id = "pending:A/second.bin".to_string();
        index.add_files(vec![
            file("A/first.bin", &"a".repeat(32), true, "normal"),
            pending,
            file("A/third.bin", &"b".repeat(32), true, "normal"),
        ]);

        let completed = file("A/second.bin", &"c".repeat(32), true, "normal");
        index
            .finalize_pending_hash("pending:A/second.bin", completed)
            .expect("pending row should still exist");

        assert_eq!(index.file_count(), 3);
        assert_eq!(
            index.get_by_path("A/second.bin").unwrap().hash,
            "c".repeat(32)
        );
        assert_eq!(
            index.get_by_hash(&"c".repeat(32)).unwrap().path,
            "A/second.bin"
        );
        assert_eq!(
            index.get_by_hash(&"a".repeat(32)).unwrap().path,
            "A/first.bin"
        );
        assert_eq!(
            index.get_by_hash(&"b".repeat(32)).unwrap().path,
            "A/third.bin"
        );
    }

    /// Every stored id must resolve to exactly what the linear scan
    /// `position_by_id` replaced would have found.
    fn assert_id_map_matches_scan(index: &LocalIndex) {
        for (idx, stored) in index.all_files().iter().enumerate() {
            assert!(!stored.id.is_empty(), "test rows must carry an id");
            assert_eq!(
                index.position_by_id(&stored.id),
                index
                    .all_files()
                    .iter()
                    .position(|candidate| candidate.id == stored.id),
                "id_map disagrees with a linear scan at {idx} ({})",
                stored.id
            );
        }
    }

    /// Hash completion resolves its row through `id_map` instead of scanning
    /// every row, so the map has to survive the swap_remove + push that each
    /// completion performs. A drifted map is worse than the scan it replaced:
    /// the completion would be silently lost, or land on another file's row.
    #[test]
    fn id_lookup_tracks_inserts_removals_and_finalizations() {
        let mut index = LocalIndex::new();
        let mut pending_one = file("A/one.bin", "", true, "normal");
        pending_one.id = "pending:A/one.bin".to_string();
        let mut pending_two = file("A/two.bin", "", true, "normal");
        pending_two.id = "pending:A/two.bin".to_string();
        index.add_files(vec![
            file("A/kept.bin", &"a".repeat(32), true, "normal"),
            pending_one,
            pending_two,
        ]);
        assert_id_map_matches_scan(&index);

        // Completing a row that is not last swap_removes it, moving the final
        // row into its slot — both ids have to be repointed.
        index
            .finalize_pending_hash(
                "pending:A/one.bin",
                file("A/one.bin", &"b".repeat(32), true, "normal"),
            )
            .expect("the pending row is still there");
        assert_id_map_matches_scan(&index);

        assert!(index.remove_file_by_id(&"a".repeat(32)).is_some());
        assert_id_map_matches_scan(&index);

        index
            .finalize_pending_hash(
                "pending:A/two.bin",
                file("A/two.bin", &"c".repeat(32), true, "normal"),
            )
            .expect("the second pending row outlives the removal");
        assert_id_map_matches_scan(&index);

        assert_eq!(index.file_count(), 2);
        assert_eq!(index.get_by_path("A/one.bin").unwrap().hash, "b".repeat(32));
        assert_eq!(index.get_by_path("A/two.bin").unwrap().hash, "c".repeat(32));
        assert!(
            index.remove_file_by_id("pending:A/one.bin").is_none(),
            "a consumed placeholder id must not resolve to anything"
        );
    }

    #[test]
    fn indexed_upsert_replaces_the_row_for_a_known_path() {
        let mut index = LocalIndex::new();
        index.add_files(vec![
            file("A/one.bin", &"a".repeat(32), true, "normal"),
            file("A/two.bin", &"b".repeat(32), true, "normal"),
        ]);

        // Same path, new content hash: the `path_map` hit must replace in place
        // rather than append a second row for the same file.
        index.add_file_no_rebuild(file("A/two.bin", &"e".repeat(32), true, "normal"));

        assert_eq!(index.file_count(), 2);
        assert_eq!(index.get_by_path("A/two.bin").unwrap().hash, "e".repeat(32));
        assert!(index.get_by_hash(&"b".repeat(32)).is_none());
        assert_eq!(
            index.get_by_hash(&"e".repeat(32)).unwrap().path,
            "A/two.bin"
        );
        assert_eq!(
            index.get_by_hash(&"a".repeat(32)).unwrap().path,
            "A/one.bin"
        );
    }

    #[test]
    fn active_child_root_keeps_child_and_reports_pending_removal() {
        let mut index = LocalIndex::new();
        index.add_files(vec![
            file(
                "/library/parent/child/kept.bin",
                "dddddddddddddddddddddddddddddddd",
                true,
                "normal",
            ),
            file("/library/parent/other/pending.bin", "", true, "normal"),
        ]);
        let active_roots = vec!["/library/parent/child".to_string()];

        let removed = index.remove_files_outside_folders(&active_roots);

        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].path, "/library/parent/other/pending.bin");
        assert!(index
            .get_by_path("/library/parent/child/kept.bin")
            .is_some());
        assert!(index
            .get_by_path("/library/parent/other/pending.bin")
            .is_none());
    }
}
