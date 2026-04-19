use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tauri::Emitter;

use std::sync::Arc;
use tokio::sync::RwLock;

/// Maximum bytes for any single filesystem path accepted from the
/// frontend. Mirrors `commands::settings::MAX_PATH_LEN` so the
/// pre-canonicalize path length check is consistent across the
/// "save settings" path and the explicit add/remove paths.
const MAX_PATH_LEN: usize = 4 * 1024;
/// Maximum file-id count in a single batch sharing operation. Bounds
/// the IPC payload and the per-call DB transaction size.
const MAX_BATCH_IDS: usize = 10_000;

struct ScanGuard(Arc<AtomicUsize>);
impl Drop for ScanGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

static RELOAD_COUNTER: AtomicUsize = AtomicUsize::new(0);

use crate::app_state::AppState;
use crate::network::NetworkCommand;
use crate::search::index::LocalIndex;
use crate::sharing::indexer::FileIndexer;
use crate::storage::known_files::KnownFileList;
use crate::types::*;
use tracing::{debug, info, warn};

fn paths_equal_ignore_case(a: &str, b: &str) -> bool {
    if cfg!(target_os = "windows") {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

pub(crate) async fn refresh_file_cache(index: &Arc<RwLock<LocalIndex>>, cache: &Arc<RwLock<Vec<FileInfo>>>) {
    let (snap_raw, previous_flags) = tokio::join!(
        async { index.read().await.all_files().to_vec() },
        async {
            let cached = cache.read().await;
            cached
                .iter()
                .map(|file| (file.path.clone(), (file.shared_kad, file.shared_ed2k)))
                .collect::<std::collections::HashMap<_, _>>()
        },
    );
    let mut snap = snap_raw;
    for file in &mut snap {
        if let Some((shared_kad, shared_ed2k)) = previous_flags.get(&file.path) {
            file.shared_kad = file.shared && !file.hash.is_empty() && *shared_kad;
            file.shared_ed2k = file.shared && !file.hash.is_empty() && *shared_ed2k;
        }
    }
    *cache.write().await = snap;
}

fn load_known_files() -> KnownFileList {
    let data_dir = directories::ProjectDirs::from("com", "ember", "p2p")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    KnownFileList::load(&data_dir.join("known.met"))
}

fn shared_access_dirs(config: &crate::storage::config::AppConfig) -> Vec<String> {
    let mut allowed_dirs = config.settings.shared_folders.clone();
    let download_dir = std::path::PathBuf::from(&config.settings.download_folder)
        .join("Downloads")
        .to_string_lossy()
        .to_string();
    allowed_dirs.push(download_dir);
    allowed_dirs.push(config.settings.download_folder.clone());
    allowed_dirs
}

pub(crate) fn file_in_shared_folders(file_path: &str, shared_folders: &[String]) -> bool {
    shared_folders
        .iter()
        .any(|folder| crate::security::path_matches_dir(file_path, folder))
}

async fn delete_file_with_retry(
    path: &std::path::Path,
    max_attempts: u32,
    delay_ms: u64,
) -> Result<(), String> {
    let mut last_error = None;
    for attempt in 1..=max_attempts {
        match tokio::fs::remove_file(path).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_error = Some(e);
                if attempt < max_attempts {
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }
    Err(format!(
        "Failed to delete {}: {}",
        path.display(),
        last_error
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    ))
}

fn resolve_from_known(files: &mut Vec<FileInfo>, known: &KnownFileList) -> Vec<FileInfo> {
    let mut needs_hashing = Vec::new();
    for file in files.iter_mut() {
        if let Some(record) = known.find_by_path_and_meta(&file.path, file.size, file.modified_at) {
            let hash = hex::encode(record.file_hash);
            file.id = hash.clone();
            file.hash = hash;
            file.aich_hash = record.aich_hash.clone();
        } else {
            needs_hashing.push(file.clone());
        }
    }
    needs_hashing
}

/// eMule-style shared folder addition -- returns IMMEDIATELY.
/// All discovery and hashing runs in a background task:
///   Phase 1: discover files (metadata only) → show in UI via event
///   Phase 2: hash files one at a time → update UI + publish to KAD
#[tauri::command]
pub async fn add_shared_folder(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<(), String> {
    if path.len() > MAX_PATH_LEN {
        return Err(format!("Folder path exceeds {MAX_PATH_LEN} bytes"));
    }
    let p = std::path::Path::new(&path);
    if !p.exists() || !p.is_dir() {
        return Err("Path does not exist or is not a directory".into());
    }
    let canonical = p.canonicalize().map_err(|e| format!("Invalid path: {e}"))?;
    let blocked_segments: &[&str] = &[
        "windows", "program files", "program files (x86)",
        "programdata", ".ssh", ".gnupg",
        "etc", "usr", "bin", "sbin", "var", "root",
        "tmp", "temp", "proc", "sys", "dev",
    ];
    for component in canonical.components() {
        if let std::path::Component::Normal(seg) = component {
            let seg_lower = seg.to_string_lossy().to_lowercase();
            if blocked_segments.contains(&seg_lower.as_str()) {
                return Err(format!("Cannot share system directory: {}", canonical.display()));
            }
            if seg_lower == "appdata" {
                let rest: String = canonical.components()
                    .skip_while(|c| {
                        if let std::path::Component::Normal(s) = c {
                            s.to_string_lossy().to_lowercase() != "appdata"
                        } else {
                            true
                        }
                    })
                    .skip(1)
                    .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
                    .collect::<Vec<_>>()
                    .join("/");
                if rest.starts_with("local/temp") || rest.starts_with("local\\temp") {
                    return Err(format!("Cannot share system directory: {}", canonical.display()));
                }
            }
        }
    }

    let canonical_str = canonical.to_string_lossy().to_string();
    let save_data = {
        let mut config = state.config.write().await;
        if !config.settings.shared_folders.contains(&canonical_str) {
            config.settings.shared_folders.push(canonical_str.clone());
            Some(config.prepare_save().map_err(|e| format!("Config save error: {e}"))?)
        } else {
            None
        }
    };
    if save_data.is_none() {
        info!("Folder {canonical_str} is already shared, skipping duplicate scan");
        return Ok(());
    }
    {
        let mut live = state.upload_shared_folders.write().await;
        if !live.contains(&canonical_str) {
            live.push(canonical_str.clone());
        }
    }
    if let Some((data, tmp, final_path)) = save_data {
        tokio::task::spawn_blocking(move || {
            crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
        }).await.map_err(|e| format!("Config save error: {e}"))?.map_err(|e| format!("Config save error: {e}"))?;
    }

    // Start watching the new folder (and anything else currently shared).
    if let Some(watcher) = state.shared_folder_watcher.as_ref() {
        let folders = state.config.read().await.settings.shared_folders.clone();
        watcher.sync_paths(&folders);
    }

    let local_index = state.local_index.clone();
    let file_cache = state.cached_shared_files.clone();
    let network_tx = state.network_tx.clone();
    let scanning = state.scanning_count.clone();
    let cancel_flags = state.hash_cancel_flags.clone();
    let config = state.config.clone();

    let cancel_flag = Arc::new(AtomicBool::new(false));
    let cancel_key = canonical_str.clone();
    cancel_flags.write().await.insert(cancel_key.clone(), cancel_flag.clone());

    tokio::spawn(async move {
        scanning.fetch_add(1, Ordering::Relaxed);
        let _scan_guard = ScanGuard(scanning.clone());

        let discover_path = canonical_str.clone();
        let mut discovered = match tokio::task::spawn_blocking(move || {
            FileIndexer::discover_directory(&discover_path)
        })
        .await
        {
            Ok(files) => files,
            Err(e) => {
                tracing::error!("Discovery failed for {path}: {e}");
                cancel_flags.write().await.remove(&cancel_key);
                return;
            }
        };

        let total_files = discovered.len();
        info!("Discovered {total_files} files in {path}");

        let still_shared = {
            let cfg = config.read().await;
            file_in_shared_folders(&canonical_str, &cfg.settings.shared_folders)
        };
        if cancel_flag.load(Ordering::Relaxed) || !still_shared {
            info!("Hashing cancelled during discovery for {path}");
            cancel_flags.write().await.remove(&cancel_key);
            let _ = app.emit("file-hash-progress", serde_json::json!({ "done": true, "current": 0, "total": 0, "file_name": "" }));
            return;
        }

        let known_list = load_known_files();
        let files_to_hash = resolve_from_known(&mut discovered, &known_list);

        {
            let mut index = local_index.write().await;
            index.add_files(discovered);
        }
        refresh_file_cache(&local_index, &file_cache).await;

        let _ = app.emit("shared-files-changed", serde_json::json!({
            "folder": path,
            "count": total_files,
            "phase": "discovered",
        }));

        let total_to_hash = files_to_hash.len();
        let mut hashed_count: usize = 0;
        let mut last_cache_refresh = std::time::Instant::now();
        let mut was_cancelled = false;

        for file in &files_to_hash {
            if cancel_flag.load(Ordering::Relaxed) {
                info!("Hashing cancelled for {path} at {hashed_count}/{total_to_hash}");
                was_cancelled = true;
                break;
            }

            let file_path = file.path.clone();
            let file_temp_id = file.id.clone();
            let cf = cancel_flag.clone();

            debug!("Hashing file {}/{}: {}", hashed_count + 1, total_to_hash, file.name);

            let _ = app.emit("file-hash-progress", serde_json::json!({
                "current": hashed_count + 1,
                "total": total_to_hash,
                "file_name": file.name,
            }));

            let hash_result = tokio::time::timeout(
                std::time::Duration::from_secs(300),
                tokio::task::spawn_blocking(move || {
                    FileIndexer::hash_file_cancellable(std::path::Path::new(&file_path), &cf)
                }),
            )
            .await;

            match hash_result {
                Ok(Ok(Ok((ed2k_hash, aich_hash)))) => {
                    debug!("Hash complete: {} -> {}", file.name, &ed2k_hash[..ed2k_hash.len().min(8)]);
                    let mut updated_file = file.clone();
                    updated_file.id = ed2k_hash.clone();
                    updated_file.hash = ed2k_hash;
                    updated_file.aich_hash = aich_hash;

                    let still_shared = {
                        let cfg = config.read().await;
                        file_in_shared_folders(&updated_file.path, &cfg.settings.shared_folders)
                    };
                    {
                        let mut index = local_index.write().await;
                        index.remove_file_by_id(&file_temp_id);
                        if !cancel_flag.load(Ordering::Relaxed) && still_shared {
                            index.add_file_no_rebuild(updated_file.clone());
                        }
                    }

                    if !cancel_flag.load(Ordering::Relaxed) && still_shared {
                        hashed_count += 1;
                    }
                    if !cancel_flag.load(Ordering::Relaxed)
                        && still_shared
                        && last_cache_refresh.elapsed() >= std::time::Duration::from_secs(5)
                    {
                        refresh_file_cache(&local_index, &file_cache).await;
                        last_cache_refresh = std::time::Instant::now();
                    }
                }
                Ok(Ok(Err(e))) => {
                    let msg = e.to_string();
                    if msg.contains("cancelled") {
                        info!("Hashing cancelled mid-file for {path}");
                        was_cancelled = true;
                        let mut index = local_index.write().await;
                        index.remove_file_by_id(&file_temp_id);
                        break;
                    }
                    warn!("Failed to hash {}: {e}", file.name);
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
                Ok(Err(e)) => {
                    tracing::error!("Hash task panicked for {}: {e}", file.name);
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
                Err(_) => {
                    warn!("Hash timed out after 5 min for {} (file may be on cloud storage or locked), skipping", file.name);
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
            }
        }

        {
            let mut index = local_index.write().await;
            if was_cancelled {
                index.remove_pending_files();
            }
            index.rebuild();
        }

        refresh_file_cache(&local_index, &file_cache).await;

        if !was_cancelled {
            let all_files = {
                let index = local_index.read().await;
                index.all_files().iter()
                    .filter(|f| crate::security::path_matches_dir(&f.path, &path) && !f.hash.is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
            };
            if !all_files.is_empty() {
                if let Err(e) = network_tx.try_send(NetworkCommand::AnnounceFiles { files: all_files }) {
                    warn!("Failed to queue AnnounceFiles: {e}");
                }
            }
        }

        if let Err(e) = network_tx.try_send(NetworkCommand::SharedFilesChanged) {
            warn!("Failed to queue SharedFilesChanged: {e}");
        }
        cancel_flags.write().await.remove(&cancel_key);

        let from_known = total_files.saturating_sub(total_to_hash);
        if was_cancelled {
            info!("Hashing stopped for {path}: {hashed_count}/{total_to_hash} hashed before cancel, {from_known} from known.met");
        } else {
            info!("Background hashing complete: {hashed_count}/{total_to_hash} hashed, {from_known} from known.met ({path})");
        }

        let _ = app.emit("file-hash-progress", serde_json::json!({
            "current": total_to_hash,
            "total": total_to_hash,
            "file_name": "",
            "done": true,
        }));
        drop(_scan_guard);
    });

    Ok(())
}

#[tauri::command]
pub async fn remove_shared_folder(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<(), String> {
    if path.len() > MAX_PATH_LEN {
        return Err(format!("Folder path exceeds {MAX_PATH_LEN} bytes"));
    }
    let canonical_path = std::path::Path::new(&path)
        .canonicalize()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| path.clone());
    // `add_shared_folder` stores the *canonical* form in
    // `shared_folders` and `upload_shared_folders`; the cancel-flag
    // map is also keyed by canonical paths. Comparing against the
    // raw `path` argument here would let an equivalent-but-not-equal
    // representation (extended `\\?\` form, trailing separator,
    // case difference not handled by `paths_equal_ignore_case`) leak:
    // we'd strip the index entries (which canonicalize internally)
    // but leave `shared_folders` populated, re-sharing on next scan.
    // Use `canonical_path` for every comparison.
    {
        let flags = state.hash_cancel_flags.read().await;
        for (key, flag) in flags.iter() {
            if paths_equal_ignore_case(key, &canonical_path) {
                flag.store(true, Ordering::Relaxed);
            }
        }
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(2000);
    loop {
        let still_active = state.hash_cancel_flags.read().await
            .keys()
            .any(|key| paths_equal_ignore_case(key, &canonical_path));
        if !still_active || std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let save_data = {
        let mut config = state.config.write().await;
        config.settings.shared_folders.retain(|f| !paths_equal_ignore_case(f, &canonical_path));
        config.prepare_save().map_err(|e| format!("Config save error: {e}"))?
    };
    {
        let mut live = state.upload_shared_folders.write().await;
        live.retain(|f| !paths_equal_ignore_case(f, &canonical_path));
    }
    {
        let (data, tmp, final_path) = save_data;
        tokio::task::spawn_blocking(move || {
            crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
        }).await.map_err(|e| format!("Config save error: {e}"))?.map_err(|e| format!("Config save error: {e}"))?;
    }

    {
        let mut index = state.local_index.write().await;
        index.remove_files_by_path_prefix(&canonical_path);
    }
    refresh_file_cache(&state.local_index, &state.cached_shared_files).await;

    // Stop watching the removed folder.
    if let Some(watcher) = state.shared_folder_watcher.as_ref() {
        let folders = state.config.read().await.settings.shared_folders.clone();
        watcher.sync_paths(&folders);
    }

    if let Err(e) = state.network_tx.try_send(NetworkCommand::SharedFilesChanged) {
        warn!("Failed to queue SharedFilesChanged after folder removal: {e}");
    }
    let _ = app.emit("shared-files-changed", serde_json::json!({ "folder": path, "removed": true }));

    Ok(())
}

#[tauri::command]
pub async fn get_shared_files(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<FileInfo>, String> {
    let cached = state.cached_shared_files.read().await;
    Ok(cached.clone())
}

#[tauri::command]
pub async fn get_shared_folders(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let config = state.config.read().await;
    Ok(config.settings.shared_folders.clone())
}

/// Encode a UI priority label into the u8 stored in
/// `KnownFileRecord::upload_priority` (and shipped over the wire as the
/// `FT_ULPRIORITY` known-file tag). Order matches eMule's priority
/// enum: 0=verylow, 1=low, 2=normal, 3=high, 4=release, 5=auto.
/// Unknown labels fall back to `normal` so a malformed UI value never
/// promotes a file to the highest tier silently.
fn priority_str_to_u8(priority: &str) -> u8 {
    match priority {
        "verylow" => 0,
        "low" => 1,
        "normal" => 2,
        "high" => 3,
        "release" => 4,
        "auto" => 5,
        _ => 2,
    }
}

#[tauri::command]
pub async fn set_file_priority(
    state: tauri::State<'_, AppState>,
    file_path: String,
    priority: String,
) -> Result<(), String> {
    let valid = ["verylow", "low", "normal", "high", "release", "auto"];
    if !valid.contains(&priority.as_str()) {
        return Err(format!("Invalid priority: {priority}"));
    }
    let file_hash = {
        let mut index = state.local_index.write().await;
        if !index.set_file_priority_by_path(&file_path, &priority) {
            return Err("File not found".to_string());
        }
        index.get_by_path(&file_path).map(|f| f.hash.clone())
    };
    refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
    // Push the new priority into `known.met` via the network task so
    // the value persists across restarts. `try_send` is fine here —
    // if the channel is briefly full the value still survives in the
    // search index (saved separately) and a future SharedFilesChanged
    // will reconcile it.
    if let Some(hash) = file_hash.filter(|h| !h.is_empty()) {
        if state
            .network_tx
            .try_send(NetworkCommand::SetUploadPriority {
                file_hash_hex: hash,
                priority: priority_str_to_u8(&priority),
            })
            .is_err()
        {
            warn!("Network channel full; upload_priority change not yet flushed to known.met");
        }
    }
    info!("Set priority for {} to {}", file_path, priority);
    Ok(())
}

/// Bulk-set upload priority for many files in a single Tauri call. Returns
/// the number of files actually updated (paths that did not match a known
/// shared file are silently skipped). Cuts N invoke round-trips down to 1
/// for the library multi-select action.
#[tauri::command]
pub async fn batch_set_priority(
    state: tauri::State<'_, AppState>,
    file_paths: Vec<String>,
    priority: String,
) -> Result<u32, String> {
    if file_paths.len() > MAX_BATCH_IDS {
        return Err(format!(
            "Too many file_paths in one batch (max {MAX_BATCH_IDS})"
        ));
    }
    let valid = ["verylow", "low", "normal", "high", "release", "auto"];
    if !valid.contains(&priority.as_str()) {
        return Err(format!("Invalid priority: {priority}"));
    }
    let (count, hashes) = {
        let mut index = state.local_index.write().await;
        let mut n = 0u32;
        let mut hashes = Vec::new();
        for path in &file_paths {
            if index.set_file_priority_by_path(path, &priority) {
                n += 1;
                if let Some(f) = index.get_by_path(path) {
                    if !f.hash.is_empty() {
                        hashes.push(f.hash.clone());
                    }
                }
            }
        }
        (n, hashes)
    };
    if count > 0 {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        // Mirror each priority change into `known.met`. Use `try_send`
        // so the bulk action doesn't block when the network channel is
        // briefly saturated; the search index is still authoritative
        // for live priority and a future SharedFilesChanged reconciles.
        let prio_u8 = priority_str_to_u8(&priority);
        for hash in hashes {
            if state
                .network_tx
                .try_send(NetworkCommand::SetUploadPriority {
                    file_hash_hex: hash,
                    priority: prio_u8,
                })
                .is_err()
            {
                warn!("Network channel full during batch priority push");
                break;
            }
        }
        info!("Batch set priority to {priority} for {count}/{} files", file_paths.len());
    }
    Ok(count)
}

/// Bulk-share many files in a single Tauri call. Returns the count of
/// files actually flipped to shared (already-shared paths and unknown
/// paths contribute 0).
#[tauri::command]
pub async fn batch_share(
    state: tauri::State<'_, AppState>,
    file_paths: Vec<String>,
) -> Result<u32, String> {
    if file_paths.len() > MAX_BATCH_IDS {
        return Err(format!(
            "Too many file_paths in one batch (max {MAX_BATCH_IDS})"
        ));
    }
    let count = {
        let mut index = state.local_index.write().await;
        let mut n = 0u32;
        for path in &file_paths {
            if index.set_file_shared_by_path(path, true) {
                n += 1;
            }
        }
        n
    };
    if count > 0 {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        if let Err(e) = state.network_tx.try_send(NetworkCommand::SharedFilesChanged) {
            warn!("Failed to queue SharedFilesChanged after batch share: {e}");
        }
        info!("Batch shared {count}/{} files", file_paths.len());
    }
    Ok(count)
}

/// Bulk-unshare many files in a single Tauri call. Returns the count of
/// files actually flipped to unshared.
#[tauri::command]
pub async fn batch_unshare(
    state: tauri::State<'_, AppState>,
    file_paths: Vec<String>,
) -> Result<u32, String> {
    if file_paths.len() > MAX_BATCH_IDS {
        return Err(format!(
            "Too many file_paths in one batch (max {MAX_BATCH_IDS})"
        ));
    }
    let count = {
        let mut index = state.local_index.write().await;
        let mut n = 0u32;
        for path in &file_paths {
            if index.set_file_shared_by_path(path, false) {
                n += 1;
            }
        }
        n
    };
    if count > 0 {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        if let Err(e) = state.network_tx.try_send(NetworkCommand::SharedFilesChanged) {
            warn!("Failed to queue SharedFilesChanged after batch unshare: {e}");
        }
        info!("Batch unshared {count}/{} files", file_paths.len());
    }
    Ok(count)
}

#[tauri::command]
pub async fn reload_shared_files(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let folders = {
        let config = state.config.read().await;
        config.settings.shared_folders.clone()
    };

    let local_index = state.local_index.clone();
    let file_cache = state.cached_shared_files.clone();
    let network_tx = state.network_tx.clone();
    let scanning = state.scanning_count.clone();
    let cancel_flags = state.hash_cancel_flags.clone();
    let config = state.config.clone();
    let discovery_folders = folders.clone();

    let cancel_flag = Arc::new(AtomicBool::new(false));
    let reload_key = format!("__reload_{}__", RELOAD_COUNTER.fetch_add(1, Ordering::Relaxed));
    cancel_flags.write().await.insert(reload_key.clone(), cancel_flag.clone());

    tokio::spawn(async move {
        scanning.fetch_add(1, Ordering::Relaxed);
        let _scan_guard = ScanGuard(scanning.clone());

        let mut discovered: Vec<FileInfo> = match tokio::task::spawn_blocking(move || {
            let mut files = Vec::new();
            for folder in &discovery_folders {
                files.extend(FileIndexer::discover_directory(folder));
            }
            files
        })
        .await
        {
            Ok(files) => files,
            Err(e) => {
                tracing::error!("Reload discovery failed: {e}");
                cancel_flags.write().await.remove(&reload_key);
                return;
            }
        };

        let total_files = discovered.len();

        let current_folders = {
            let cfg = config.read().await;
            cfg.settings.shared_folders.clone()
        };
        let reloaded_folders = folders
            .iter()
            .filter(|folder| current_folders.iter().any(|current| paths_equal_ignore_case(current, folder)))
            .cloned()
            .collect::<Vec<_>>();
        discovered.retain(|file| file_in_shared_folders(&file.path, &reloaded_folders));

        if cancel_flag.load(Ordering::Relaxed) {
            info!("Reload cancelled during discovery");
            cancel_flags.write().await.remove(&reload_key);
            let _ = app.emit("file-hash-progress", serde_json::json!({ "done": true, "current": 0, "total": 0, "file_name": "" }));
            return;
        }

        let known_list = load_known_files();
        let files_to_hash = resolve_from_known(&mut discovered, &known_list);

        {
            let mut index = local_index.write().await;
            index.reconcile_files_for_folders(&reloaded_folders, discovered);
        }
        refresh_file_cache(&local_index, &file_cache).await;

        let _ = app.emit("shared-files-changed", serde_json::json!({
            "phase": "discovered",
            "count": total_files,
        }));

        let total_to_hash = files_to_hash.len();
        let mut hashed_count: usize = 0;
        let mut last_cache_refresh = std::time::Instant::now();
        let mut was_cancelled = false;

        for file in &files_to_hash {
            if cancel_flag.load(Ordering::Relaxed) {
                info!("Reload hashing cancelled at {hashed_count}/{total_to_hash}");
                was_cancelled = true;
                break;
            }

            let file_path = file.path.clone();
            let file_temp_id = file.id.clone();
            let cf = cancel_flag.clone();

            debug!("Reload hashing {}/{}: {}", hashed_count + 1, total_to_hash, file.name);

            let _ = app.emit("file-hash-progress", serde_json::json!({
                "current": hashed_count + 1,
                "total": total_to_hash,
                "file_name": file.name,
            }));

            let hash_result = tokio::time::timeout(
                std::time::Duration::from_secs(300),
                tokio::task::spawn_blocking(move || {
                    FileIndexer::hash_file_cancellable(std::path::Path::new(&file_path), &cf)
                }),
            )
            .await;

            match hash_result {
                Ok(Ok(Ok((ed2k_hash, aich_hash)))) => {
                    debug!("Reload hash complete: {} -> {}", file.name, &ed2k_hash[..ed2k_hash.len().min(8)]);
                    let mut updated_file = file.clone();
                    updated_file.id = ed2k_hash.clone();
                    updated_file.hash = ed2k_hash;
                    updated_file.aich_hash = aich_hash;

                    let still_shared = {
                        let cfg = config.read().await;
                        file_in_shared_folders(&updated_file.path, &cfg.settings.shared_folders)
                    };
                    {
                        let mut index = local_index.write().await;
                        index.remove_file_by_id(&file_temp_id);
                        if !cancel_flag.load(Ordering::Relaxed) && still_shared {
                            index.add_file_no_rebuild(updated_file.clone());
                        }
                    }

                    if !cancel_flag.load(Ordering::Relaxed) && still_shared {
                        hashed_count += 1;
                    }
                    if !cancel_flag.load(Ordering::Relaxed)
                        && still_shared
                        && last_cache_refresh.elapsed() >= std::time::Duration::from_secs(5)
                    {
                        refresh_file_cache(&local_index, &file_cache).await;
                        last_cache_refresh = std::time::Instant::now();
                    }
                }
                Ok(Ok(Err(e))) => {
                    let msg = e.to_string();
                    if msg.contains("cancelled") {
                        info!("Reload hashing cancelled mid-file");
                        was_cancelled = true;
                        let mut index = local_index.write().await;
                        index.remove_file_by_id(&file_temp_id);
                        break;
                    }
                    warn!("Failed to hash {}: {e}", file.name);
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
                Ok(Err(e)) => {
                    tracing::error!("Hash task panicked for {}: {e}", file.name);
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
                Err(_) => {
                    warn!("Hash timed out after 5 min for {} (file may be on cloud storage or locked), skipping", file.name);
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
            }
        }

        {
            let mut index = local_index.write().await;
            if was_cancelled {
                index.remove_pending_files();
            }
            index.rebuild();
        }

        refresh_file_cache(&local_index, &file_cache).await;

        if !was_cancelled {
            let all_files = {
                let index = local_index.read().await;
                index.all_files().iter()
                    .filter(|f| !f.hash.is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
            };
            if !all_files.is_empty() {
                if let Err(e) = network_tx.try_send(NetworkCommand::AnnounceFiles { files: all_files }) {
                    warn!("Failed to queue AnnounceFiles on reload: {e}");
                }
            }
        }

        if let Err(e) = network_tx.try_send(NetworkCommand::SharedFilesChanged) {
            warn!("Failed to queue SharedFilesChanged on reload: {e}");
        }
        cancel_flags.write().await.remove(&reload_key);

        let from_known = total_files.saturating_sub(total_to_hash);
        info!("Reload complete: {hashed_count}/{total_to_hash} hashed, {from_known} from known.met{}", if was_cancelled { " (cancelled)" } else { "" });

        let _ = app.emit("file-hash-progress", serde_json::json!({
            "current": total_to_hash,
            "total": total_to_hash,
            "file_name": "",
            "done": true,
        }));
        drop(_scan_guard);
    });

    Ok(())
}

#[tauri::command]
pub async fn get_scan_status(
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    Ok(state.scanning_count.load(Ordering::Relaxed) > 0)
}

#[tauri::command]
pub async fn stop_hashing(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let (shared_folders, index_snap) = tokio::join!(
        async {
            let config = state.config.read().await;
            config.settings.shared_folders.clone()
        },
        async {
            let index = state.local_index.read().await;
            index.all_files().to_vec()
        },
    );
    let pending_folders = shared_folders
        .iter()
        .filter(|folder| {
            index_snap
                .iter()
                .any(|file| crate::security::path_matches_dir(&file.path, folder) && file.hash.is_empty())
        })
        .cloned()
        .collect::<HashSet<_>>();

    let flags = state.hash_cancel_flags.read().await;
    let count = flags.len();
    let mut incomplete_folders = pending_folders;
    for key in flags.keys() {
        if !key.starts_with("__") {
            incomplete_folders.insert(key.clone());
        }
    }
    for flag in flags.values() {
        flag.store(true, Ordering::Relaxed);
    }
    info!("Stop hashing requested, cancelled {count} active tasks");
    let mut result = incomplete_folders.into_iter().collect::<Vec<_>>();
    result.sort();
    Ok(result)
}

#[tauri::command]
pub async fn resume_hashing(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    reload_shared_files(app, state).await
}

#[tauri::command]
pub async fn unshare_file(
    state: tauri::State<'_, AppState>,
    file_path: String,
    file_hash: Option<String>,
) -> Result<(), String> {
    let file = {
        let mut index = state.local_index.write().await;
        if index.set_file_shared_by_path(&file_path, false) {
            index.get_by_path(&file_path).cloned()
        } else {
            None
        }
    };
    if file.is_some() {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        if let Err(e) = state.network_tx.try_send(NetworkCommand::SharedFilesChanged) {
            warn!("Failed to queue SharedFilesChanged after unshare: {e}");
        }
        info!(
            "Unshared file {}{}",
            file_path,
            file_hash
                .filter(|hash| !hash.is_empty())
                .map(|hash| format!(" ({hash})"))
                .unwrap_or_default()
        );
    }
    Ok(())
}

#[tauri::command]
pub async fn share_file(
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<(), String> {
    let file = {
        let mut index = state.local_index.write().await;
        index.set_file_shared_by_path(&file_path, true);
        index.get_by_path(&file_path).cloned()
    };
    if file.is_some() {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        if let Err(e) = state.network_tx.try_send(NetworkCommand::SharedFilesChanged) {
            warn!("Failed to queue SharedFilesChanged after share: {e}");
        }
        info!("Shared file {}", file_path);
    }
    Ok(())
}

#[tauri::command]
pub async fn unshare_folder(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<(), String> {
    let affected_hashes = {
        let mut index = state.local_index.write().await;
        index.set_shared_by_path_prefix(&path, false)
    };
    if !affected_hashes.is_empty() {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        if let Err(e) = state.network_tx.try_send(NetworkCommand::SharedFilesChanged) {
            warn!("Failed to queue SharedFilesChanged after unshare_folder: {e}");
        }
        let _ = app.emit("shared-files-changed", serde_json::json!({ "folder": path, "unshared": true }));
    }
    Ok(())
}

#[tauri::command]
pub async fn delete_shared_file(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    file_path: String,
    file_hash: Option<String>,
) -> Result<(), String> {
    let allowed_dirs = {
        let config = state.config.read().await;
        shared_access_dirs(&config)
    };

    let canonical = tokio::task::spawn_blocking({
        let file_path = file_path.clone();
        move || -> Result<std::path::PathBuf, String> {
            let path = std::path::Path::new(&file_path);
            if !path.exists() {
                return Err("File does not exist".to_string());
            }
            if !path.is_file() {
                return Err("Path is not a file".to_string());
            }
            let canonical = path
                .canonicalize()
                .map_err(|e| format!("Invalid path: {e}"))?;
            if !crate::security::is_path_within_dirs(&canonical, &allowed_dirs) {
                return Err("File is not within a shared or download folder".to_string());
            }
            Ok(canonical)
        }
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))??;

    delete_file_with_retry(&canonical, 6, 250).await?;

    let canonical_str = canonical.to_string_lossy().to_string();
    let removed = {
        let mut index = state.local_index.write().await;
        index.remove_file_by_path(&canonical_str)
            .or_else(|| index.remove_file_by_path(&file_path))
    };
    refresh_file_cache(&state.local_index, &state.cached_shared_files).await;

    if let Err(e) = state.network_tx.try_send(NetworkCommand::SharedFilesChanged) {
        warn!("Failed to queue SharedFilesChanged after file deletion: {e}");
    }
    let _ = app.emit("shared-files-changed", serde_json::json!({ "file_deleted": true }));

    info!(
        "Deleted shared file {}{}{}",
        canonical.display(),
        if removed.is_none() { " (not indexed)" } else { "" },
        file_hash
            .filter(|hash| !hash.is_empty())
            .map(|hash| format!(" ({hash})"))
            .unwrap_or_default()
    );
    Ok(())
}

/// Check the filesystem for every indexed shared file and return the list of
/// paths that no longer exist. This is cheap (a single metadata lookup per
/// file); typical libraries finish in well under a second even with tens of
/// thousands of files. Callers can then display the count and offer a bulk
/// "remove missing" action via `remove_missing_files`.
#[tauri::command]
pub async fn scan_missing_files(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let paths: Vec<String> = {
        let index = state.local_index.read().await;
        index.all_files().iter().map(|f| f.path.clone()).collect()
    };
    let missing = tokio::task::spawn_blocking(move || {
        let mut missing = Vec::new();
        for p in paths {
            if !std::path::Path::new(&p).exists() {
                missing.push(p);
            }
        }
        missing
    })
    .await
    .map_err(|e| format!("Scan task failed: {e}"))?;
    Ok(missing)
}

/// Remove the given paths from the shared-file index if — and only if —
/// they no longer exist on disk. This double-check protects against races
/// where a file reappears (e.g. an external drive mounts back) between the
/// missing-scan and the user's confirmation click.
#[tauri::command]
pub async fn remove_missing_files(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    paths: Vec<String>,
) -> Result<u32, String> {
    if paths.is_empty() {
        return Ok(0);
    }
    let to_check = paths.clone();
    let really_missing = tokio::task::spawn_blocking(move || {
        to_check
            .into_iter()
            .filter(|p| !std::path::Path::new(p).exists())
            .collect::<Vec<_>>()
    })
    .await
    .map_err(|e| format!("Scan task failed: {e}"))?;

    let mut removed = 0u32;
    {
        let mut index = state.local_index.write().await;
        for path in &really_missing {
            if index.remove_file_by_path(path).is_some() {
                removed += 1;
            }
        }
    }
    if removed > 0 {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        if let Err(e) = state.network_tx.try_send(NetworkCommand::SharedFilesChanged) {
            warn!("Failed to queue SharedFilesChanged after remove_missing_files: {e}");
        }
        let _ = app.emit(
            "shared-files-changed",
            serde_json::json!({ "missing_removed": removed }),
        );
        info!("Removed {} missing files from shared index", removed);
    }
    Ok(removed)
}

#[tauri::command]
pub async fn republish_file(
    state: tauri::State<'_, AppState>,
    file_hash: String,
) -> Result<(), String> {
    let cleaned = file_hash.trim().to_lowercase();
    if cleaned.len() != 32 || hex::decode(&cleaned).is_err() {
        return Err("Invalid file hash (expected 32-char hex MD4)".into());
    }
    let file_exists = {
        let index = state.local_index.read().await;
        index
            .all_files()
            .iter()
            .any(|f| !f.hash.is_empty() && f.hash.eq_ignore_ascii_case(&cleaned))
    };
    if !file_exists {
        return Err("File not found in shared index".into());
    }
    state
        .network_tx
        .try_send(NetworkCommand::RepublishFile { file_hash_hex: cleaned })
        .map_err(|e| format!("Network busy: {e}"))?;
    Ok(())
}

#[tauri::command]
pub async fn open_shared_file(
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<(), String> {
    let allowed_dirs = {
        let config = state.config.read().await;
        shared_access_dirs(&config)
    };

    tokio::task::spawn_blocking(move || {
        let path = std::path::Path::new(&file_path);
        if !path.exists() {
            return Err("File does not exist".to_string());
        }
        let canonical = path.canonicalize().map_err(|e| format!("Invalid path: {e}"))?;
        if !crate::security::is_path_within_dirs(&canonical, &allowed_dirs) {
            return Err("File is not within a shared or download folder".to_string());
        }
        if crate::security::is_dangerous_extension(&canonical.to_string_lossy()) {
            return Err("Cannot open potentially dangerous file types".to_string());
        }
        opener::open(&canonical).map_err(|e| format!("Failed to open file: {e}"))?;
        Ok(())
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}

#[tauri::command]
pub async fn open_shared_folder(
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<(), String> {
    let allowed_dirs = {
        let config = state.config.read().await;
        shared_access_dirs(&config)
    };

    tokio::task::spawn_blocking(move || {
        let path = std::path::Path::new(&file_path);
        let folder = path.parent().unwrap_or(path);
        if !folder.exists() {
            return Err("Folder does not exist".to_string());
        }
        let canonical = folder.canonicalize().map_err(|e| format!("Invalid path: {e}"))?;
        if !crate::security::is_path_within_dirs(&canonical, &allowed_dirs) {
            return Err("Folder is not within a shared or download directory".to_string());
        }
        opener::open(&canonical).map_err(|e| format!("Failed to open folder: {e}"))?;
        Ok(())
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}

