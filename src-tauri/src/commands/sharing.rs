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
/// Upper bound on the number of paths accepted by `remove_missing_files` in a
/// single IPC call. Generous enough for any realistic library while bounding a
/// compromised-webview payload (and the per-call stat loop / index lock hold).
const MAX_REMOVE_MISSING_PATHS: usize = 200_000;

struct ScanGuard(Arc<AtomicUsize>);
impl Drop for ScanGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

static RELOAD_COUNTER: AtomicUsize = AtomicUsize::new(0);

use crate::app_state::AppState;
use crate::commands::errors::{coded, coded_ctx};
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

pub(crate) async fn refresh_file_cache(
    index: &Arc<RwLock<LocalIndex>>,
    cache: &Arc<RwLock<Vec<FileInfo>>>,
) {
    let (snap_raw, previous_flags) =
        tokio::join!(async { index.read().await.all_files().to_vec() }, async {
            let cached = cache.read().await;
            cached
                .iter()
                .map(|file| (file.path.clone(), (file.shared_kad, file.shared_ed2k)))
                .collect::<std::collections::HashMap<_, _>>()
        },);
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
    let data_dir = crate::storage::paths::resolve_data_dir();
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
    Err(coded_ctx(
        "sharing_delete_failed",
        format!("Failed to delete {}", path.display()),
        last_error
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string()),
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
        return Err(coded_ctx(
            "sharing_folder_path_too_long",
            format!("Folder path exceeds {MAX_PATH_LEN} bytes"),
            MAX_PATH_LEN,
        ));
    }
    // Run the blocking filesystem checks off the async runtime: on a slow or
    // disconnected network path, exists()/is_dir()/canonicalize() can block a
    // worker thread for the OS timeout.
    let canonical = tokio::task::spawn_blocking({
        let path = path.clone();
        move || -> Result<std::path::PathBuf, String> {
            let p = std::path::Path::new(&path);
            if !p.exists() || !p.is_dir() {
                return Err(coded(
                    "sharing_path_not_dir",
                    "Path does not exist or is not a directory",
                ));
            }
            p.canonicalize()
                .map_err(|e| coded_ctx("sharing_invalid_path", "Invalid path", e))
        }
    })
    .await
    .map_err(|e| coded_ctx("sharing_task_failed", "Task failed", e))??;

    // Reject sharing a filesystem root (e.g. "C:\" or "/"). Sharing a root
    // would index the entire volume and make every path on it pass
    // `is_path_within_dirs`, defeating shared-folder containment. A real
    // shared folder always has at least one named path component.
    if canonical.parent().is_none()
        || !canonical
            .components()
            .any(|c| matches!(c, std::path::Component::Normal(_)))
    {
        return Err(coded_ctx(
            "sharing_cannot_share_root",
            "Cannot share a filesystem root",
            canonical.display(),
        ));
    }

    let blocked_segments: &[&str] = &[
        "windows",
        "program files",
        "program files (x86)",
        "programdata",
        ".ssh",
        ".gnupg",
        "etc",
        "usr",
        "bin",
        "sbin",
        "var",
        "root",
        "tmp",
        "temp",
        "proc",
        "sys",
        "dev",
    ];
    for component in canonical.components() {
        if let std::path::Component::Normal(seg) = component {
            let seg_lower = seg.to_string_lossy().to_lowercase();
            if blocked_segments.contains(&seg_lower.as_str()) {
                return Err(coded_ctx(
                    "sharing_cannot_share_system_dir",
                    "Cannot share system directory",
                    canonical.display(),
                ));
            }
            if seg_lower == "appdata" {
                let rest: String = canonical
                    .components()
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
                    return Err(coded_ctx(
                        "sharing_cannot_share_system_dir",
                        "Cannot share system directory",
                        canonical.display(),
                    ));
                }
            }
        }
    }

    let canonical_str = canonical.to_string_lossy().to_string();
    // Build (but don't yet commit) the settings we intend to save. Persisting to
    // disk before mutating the in-memory config and the live upload list ensures
    // a failed write can't leave them advertising a folder that isn't saved.
    // Case-insensitive on Windows: `Vec::contains` is case-sensitive, so adding
    // `C:\Media` then `c:\media` would store both, double-scan, and make later
    // unshare/remove (which use paths_equal_ignore_case) inconsistent.
    let save_data = {
        let config = state.config.read().await;
        if config
            .settings
            .shared_folders
            .iter()
            .any(|f| paths_equal_ignore_case(f, &canonical_str))
        {
            None
        } else {
            let mut new_settings = config.settings.clone();
            new_settings.shared_folders.push(canonical_str.clone());
            Some(
                config
                    .prepare_save_settings(&new_settings)
                    .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?,
            )
        }
    };
    let Some((data, tmp, final_path)) = save_data else {
        info!("Folder {canonical_str} is already shared, skipping duplicate scan");
        return Ok(());
    };
    tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
    })
    .await
    .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?
    .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?;
    // The addition is durable on disk now; commit it in-memory and to the live
    // upload list. Both re-checks stay idempotent against a concurrent add of
    // the same path.
    {
        let mut config = state.config.write().await;
        if !config
            .settings
            .shared_folders
            .iter()
            .any(|f| paths_equal_ignore_case(f, &canonical_str))
        {
            config.settings.shared_folders.push(canonical_str.clone());
        }
    }
    {
        let mut live = state.upload_shared_folders.write().await;
        if !live
            .iter()
            .any(|f| paths_equal_ignore_case(f, &canonical_str))
        {
            live.push(canonical_str.clone());
        }
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
    cancel_flags
        .write()
        .await
        .insert(cancel_key.clone(), cancel_flag.clone());

    let scan_handle = tokio::spawn(async move {
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
            let _ = app.emit(
                "file-hash-progress",
                serde_json::json!({ "done": true, "current": 0, "total": 0, "file_name": "" }),
            );
            return;
        }

        let known_list = load_known_files();
        let files_to_hash = resolve_from_known(&mut discovered, &known_list);

        {
            let mut index = local_index.write().await;
            // Re-check cancellation after the lock-free known.met read above.
            // `remove_shared_folder` may have flipped our cancel flag (and
            // cleared the index for this folder) in that window; adding the
            // discovered set now would re-index a folder the user just
            // unshared. The cancel flag is set before the config/index are
            // mutated by removal, so this load closes the TOCTOU window.
            if cancel_flag.load(Ordering::Relaxed) {
                drop(index);
                info!("Hashing cancelled before indexing for {path}");
                cancel_flags.write().await.remove(&cancel_key);
                let _ = app.emit(
                    "file-hash-progress",
                    serde_json::json!({ "done": true, "current": 0, "total": 0, "file_name": "" }),
                );
                return;
            }
            index.add_files(discovered);
        }
        refresh_file_cache(&local_index, &file_cache).await;

        let _ = app.emit(
            "shared-files-changed",
            serde_json::json!({
                "folder": path,
                "count": total_files,
                "phase": "discovered",
            }),
        );

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

            debug!(
                "Hashing file {}/{}: {}",
                hashed_count + 1,
                total_to_hash,
                file.name
            );

            let _ = app.emit(
                "file-hash-progress",
                serde_json::json!({
                    "current": hashed_count + 1,
                    "total": total_to_hash,
                    "file_name": file.name,
                }),
            );

            let hash_result = tokio::time::timeout(
                std::time::Duration::from_secs(300),
                tokio::task::spawn_blocking(move || {
                    FileIndexer::hash_file_cancellable(std::path::Path::new(&file_path), &cf)
                }),
            )
            .await;

            match hash_result {
                Ok(Ok(Ok((ed2k_hash, aich_hash)))) => {
                    debug!(
                        "Hash complete: {} -> {}",
                        file.name,
                        &ed2k_hash[..ed2k_hash.len().min(8)]
                    );
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
                // Scope the pending cleanup to THIS folder so a concurrent scan
                // of another folder keeps its in-progress entries (the global
                // `remove_pending_files` would drop them too).
                index.remove_pending_files_under(std::slice::from_ref(&canonical_str));
            }
            index.rebuild();
        }

        refresh_file_cache(&local_index, &file_cache).await;

        if !was_cancelled {
            let all_files = {
                let index = local_index.read().await;
                index
                    .all_files()
                    .iter()
                    .filter(|f| {
                        crate::security::path_matches_dir(&f.path, &path) && !f.hash.is_empty()
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            };
            if !all_files.is_empty() {
                if let Err(e) =
                    network_tx.try_send(NetworkCommand::AnnounceFiles { files: all_files })
                {
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

        let _ = app.emit(
            "file-hash-progress",
            serde_json::json!({
                "current": total_to_hash,
                "total": total_to_hash,
                "file_name": "",
                "done": true,
            }),
        );
        drop(_scan_guard);
    });

    // Track the scan so shutdown can wait for it (and abort it after the grace
    // window) instead of flushing local_index / known.met while a discovery +
    // hash walk is still mutating them.
    state.register_background_scan(scan_handle).await;

    Ok(())
}

#[tauri::command]
pub async fn remove_shared_folder(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<(), String> {
    if path.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "sharing_folder_path_too_long",
            format!("Folder path exceeds {MAX_PATH_LEN} bytes"),
            MAX_PATH_LEN,
        ));
    }
    // Earlier this fell back to the raw `path` string when canonicalize
    // failed. That made the unshare operation silently incomplete: the
    // index keys are stored in canonical form (see `add_shared_folder`),
    // so the index/cancel-flag retain step would no-op while the
    // `shared_folders` config row was happily stripped — causing the
    // folder to come back on the next reload, but with the index
    // already torn down. Reject the call instead so the UI can surface
    // a clear error and the on-disk state stays consistent.
    // Canonicalize off the async runtime (blocking I/O on slow/network paths).
    let canonical_path = tokio::task::spawn_blocking({
        let path = path.clone();
        move || -> Result<String, String> {
            std::path::Path::new(&path)
                .canonicalize()
                .map(|p| p.to_string_lossy().to_string())
                .map_err(|e| {
                    coded_ctx(
                        "sharing_invalid_folder_path",
                        format!("Invalid folder path '{path}'"),
                        e,
                    )
                })
        }
    })
    .await
    .map_err(|e| coded_ctx("sharing_task_failed", "Task failed", e))??;
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
        let still_active = state
            .hash_cancel_flags
            .read()
            .await
            .keys()
            .any(|key| paths_equal_ignore_case(key, &canonical_path));
        if !still_active || std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // Persist the removal to disk before committing it in-memory or to the live
    // upload list, so a failed write can't drop a folder that's still saved.
    let save_data = {
        let config = state.config.read().await;
        let mut new_settings = config.settings.clone();
        new_settings
            .shared_folders
            .retain(|f| !paths_equal_ignore_case(f, &canonical_path));
        config
            .prepare_save_settings(&new_settings)
            .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?
    };
    {
        let (data, tmp, final_path) = save_data;
        tokio::task::spawn_blocking(move || {
            crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
        })
        .await
        .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?
        .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?;
    }
    {
        let mut config = state.config.write().await;
        config
            .settings
            .shared_folders
            .retain(|f| !paths_equal_ignore_case(f, &canonical_path));
    }
    {
        let mut live = state.upload_shared_folders.write().await;
        live.retain(|f| !paths_equal_ignore_case(f, &canonical_path));
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

    if let Err(e) = state
        .network_tx
        .try_send(NetworkCommand::SharedFilesChanged)
    {
        warn!("Failed to queue SharedFilesChanged after folder removal: {e}");
    }
    let _ = app.emit(
        "shared-files-changed",
        serde_json::json!({ "folder": path, "removed": true }),
    );

    Ok(())
}

#[tauri::command]
pub async fn get_shared_files(state: tauri::State<'_, AppState>) -> Result<Vec<FileInfo>, String> {
    let cached = state.cached_shared_files.read().await;
    Ok(cached.clone())
}

/// Count of files the user is *actively sharing* (the `shared` flag is set),
/// which is distinct from the total number of files indexed in the library
/// (the latter includes files the user has unshared). Returns just the
/// number so the always-mounted status bar can show "Files Shared" without
/// shipping the whole `Vec<FileInfo>` over IPC on every refresh.
#[tauri::command]
pub async fn get_shared_file_count(state: tauri::State<'_, AppState>) -> Result<usize, String> {
    let cached = state.cached_shared_files.read().await;
    Ok(cached.iter().filter(|f| f.shared).count())
}

#[tauri::command]
pub async fn get_shared_folders(state: tauri::State<'_, AppState>) -> Result<Vec<String>, String> {
    let config = state.config.read().await;
    Ok(config.settings.shared_folders.clone())
}

/// Map a lofty `FileType` to a short eMule-style codec label.
fn media_file_type_label(ft: lofty::file::FileType) -> String {
    use lofty::file::FileType;
    match ft {
        FileType::Mpeg => "mp3".to_string(),
        FileType::Mp4 => "aac".to_string(),
        FileType::Aac => "aac".to_string(),
        FileType::Flac => "flac".to_string(),
        FileType::Vorbis => "vorbis".to_string(),
        FileType::Opus => "opus".to_string(),
        FileType::Speex => "speex".to_string(),
        FileType::Wav => "wav".to_string(),
        FileType::Aiff => "aiff".to_string(),
        FileType::Ape => "ape".to_string(),
        FileType::WavPack => "wavpack".to_string(),
        other => format!("{other:?}").to_lowercase(),
    }
}

/// Extract media metadata (duration/bitrate/codec/tags) from a media file using
/// lofty (header-only read; no full decode). Returns `None` for non-media files
/// or on any parse error so the caller can treat "no media" uniformly. Audio
/// formats are covered; video files generally return `None`.
fn extract_media_metadata(path: &str) -> Option<crate::types::MediaMetadata> {
    use lofty::file::{AudioFile, TaggedFileExt};
    use lofty::probe::Probe;
    use lofty::tag::Accessor;

    let tagged = Probe::open(path).ok()?.read().ok()?;
    let props = tagged.properties();
    let mut media = crate::types::MediaMetadata::default();

    let secs = props.duration().as_secs();
    if secs > 0 {
        media.duration = Some(secs.min(u32::MAX as u64) as u32);
    }
    media.bitrate = props.audio_bitrate().filter(|b| *b > 0);
    media.codec = Some(media_file_type_label(tagged.file_type()));

    if let Some(tag) = tagged.primary_tag().or_else(|| tagged.first_tag()) {
        media.artist = tag
            .artist()
            .map(|c| c.to_string())
            .filter(|s| !s.is_empty());
        media.album = tag.album().map(|c| c.to_string()).filter(|s| !s.is_empty());
        media.title = tag.title().map(|c| c.to_string()).filter(|s| !s.is_empty());
    }

    media.into_option()
}

/// On-demand media metadata for a single shared file (used by the library
/// properties drawer). Restricted to files inside shared folders so the IPC
/// surface can't be used to probe arbitrary paths. Returns `None` when the
/// file isn't a recognized media file.
#[tauri::command]
pub async fn get_file_media_metadata(
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<Option<crate::types::MediaMetadata>, String> {
    if file_path.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "sharing_file_path_too_long",
            format!("File path exceeds {MAX_PATH_LEN} bytes"),
            MAX_PATH_LEN,
        ));
    }
    let allowed_dirs = {
        let config = state.config.read().await;
        shared_access_dirs(&config)
    };
    tokio::task::spawn_blocking(move || {
        // Canonicalize + containment-check (mirrors open_shared_file /
        // delete_shared_file) rather than a string-prefix match. A path that
        // normalizes under a shared folder but resolves via symlink/junction to
        // an arbitrary location must not be probable through this IPC surface.
        let path = std::path::Path::new(&file_path);
        let canonical = path
            .canonicalize()
            .map_err(|e| coded_ctx("sharing_invalid_path", "Invalid path", e))?;
        if !crate::security::is_path_within_dirs(&canonical, &allowed_dirs) {
            return Err(coded(
                "sharing_file_not_shared",
                "File is not in a shared folder",
            ));
        }
        let cstr = canonical.to_string_lossy();
        Ok(extract_media_metadata(&cstr))
    })
    .await
    .map_err(|e| coded_ctx("sharing_media_task_failed", "Media task failed", e))?
}

/// Current per-folder default upload priorities (folder path -> priority).
#[tauri::command]
pub async fn get_folder_priorities(
    state: tauri::State<'_, AppState>,
) -> Result<std::collections::HashMap<String, String>, String> {
    let config = state.config.read().await;
    Ok(config.settings.folder_priorities.clone())
}

/// Set (or clear, with an empty/`none` priority) the default upload priority
/// for a shared folder. The default is persisted and applied immediately to
/// every file currently indexed under the folder, mirroring eMule's
/// per-directory priority. Returns the number of files updated.
#[tauri::command]
pub async fn set_folder_priority(
    state: tauri::State<'_, AppState>,
    folder_path: String,
    priority: String,
) -> Result<u32, String> {
    let clearing = priority.is_empty() || priority == "none";
    if !clearing {
        let valid = ["verylow", "low", "normal", "high", "release", "auto"];
        if !valid.contains(&priority.as_str()) {
            return Err(coded_ctx(
                "sharing_invalid_priority",
                "Invalid priority",
                &priority,
            ));
        }
    }
    {
        let config = state.config.read().await;
        if !config
            .settings
            .shared_folders
            .iter()
            .any(|f| paths_equal_ignore_case(f, &folder_path))
        {
            return Err(coded(
                "sharing_folder_not_shared",
                "Folder is not a shared folder",
            ));
        }
    }
    // Persist before committing in-memory so a failed write can't leave the
    // live folder-priority map diverged from disk.
    let save_data = {
        let config = state.config.read().await;
        let mut new_settings = config.settings.clone();
        // Drop any case-variant key first so the map never accumulates dupes.
        new_settings
            .folder_priorities
            .retain(|k, _| !paths_equal_ignore_case(k, &folder_path));
        if !clearing {
            new_settings
                .folder_priorities
                .insert(folder_path.clone(), priority.clone());
        }
        config
            .prepare_save_settings(&new_settings)
            .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?
    };
    {
        let (data, tmp, final_path) = save_data;
        tokio::task::spawn_blocking(move || {
            crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
        })
        .await
        .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?
        .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?;
    }
    {
        let mut config = state.config.write().await;
        config
            .settings
            .folder_priorities
            .retain(|k, _| !paths_equal_ignore_case(k, &folder_path));
        if !clearing {
            config
                .settings
                .folder_priorities
                .insert(folder_path.clone(), priority.clone());
        }
    }
    // Clearing only stops the default from being re-applied; existing files
    // keep whatever priority they currently have.
    if clearing {
        info!("Cleared folder priority for {folder_path}");
        return Ok(0);
    }
    let changed = {
        let mut index = state.local_index.write().await;
        index.set_priority_under_folder(&folder_path, &priority)
    };
    if !changed.is_empty() {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        let prio_u8 = priority_str_to_u8(&priority);
        for (_, hash) in &changed {
            if hash.is_empty() {
                continue;
            }
            if state
                .network_tx
                .try_send(NetworkCommand::SetUploadPriority {
                    file_hash_hex: hash.clone(),
                    priority: prio_u8,
                })
                .is_err()
            {
                warn!("Network channel full during folder priority push");
                break;
            }
        }
    }
    info!(
        "Set folder priority {priority} for {folder_path} ({} files)",
        changed.len()
    );
    Ok(changed.len() as u32)
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
        return Err(coded_ctx(
            "sharing_invalid_priority",
            "Invalid priority",
            &priority,
        ));
    }
    let file_hash = {
        let mut index = state.local_index.write().await;
        if !index.set_file_priority_by_path(&file_path, &priority) {
            return Err(coded("sharing_file_not_found", "File not found"));
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
        return Err(coded_ctx(
            "sharing_batch_too_large",
            format!("Too many file_paths in one batch (max {MAX_BATCH_IDS})"),
            MAX_BATCH_IDS,
        ));
    }
    let valid = ["verylow", "low", "normal", "high", "release", "auto"];
    if !valid.contains(&priority.as_str()) {
        return Err(coded_ctx(
            "sharing_invalid_priority",
            "Invalid priority",
            &priority,
        ));
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
        info!(
            "Batch set priority to {priority} for {count}/{} files",
            file_paths.len()
        );
    }
    Ok(count)
}

/// Bulk-share many files in a single Tauri call. Returns the count of
/// files actually flipped to shared (already-shared paths and unknown
/// paths contribute 0).
#[tauri::command]
pub async fn batch_share(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    file_paths: Vec<String>,
) -> Result<u32, String> {
    if file_paths.len() > MAX_BATCH_IDS {
        return Err(coded_ctx(
            "sharing_batch_too_large",
            format!("Too many file_paths in one batch (max {MAX_BATCH_IDS})"),
            MAX_BATCH_IDS,
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
        if let Err(e) = state
            .network_tx
            .try_send(NetworkCommand::SharedFilesChanged)
        {
            warn!("Failed to queue SharedFilesChanged after batch share: {e}");
        }
        let _ = app.emit(
            "shared-files-changed",
            serde_json::json!({ "shared": count }),
        );
        info!("Batch shared {count}/{} files", file_paths.len());
    }
    Ok(count)
}

/// Bulk-unshare many files in a single Tauri call. Returns the count of
/// files actually flipped to unshared.
#[tauri::command]
pub async fn batch_unshare(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    file_paths: Vec<String>,
) -> Result<u32, String> {
    if file_paths.len() > MAX_BATCH_IDS {
        return Err(coded_ctx(
            "sharing_batch_too_large",
            format!("Too many file_paths in one batch (max {MAX_BATCH_IDS})"),
            MAX_BATCH_IDS,
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
        if let Err(e) = state
            .network_tx
            .try_send(NetworkCommand::SharedFilesChanged)
        {
            warn!("Failed to queue SharedFilesChanged after batch unshare: {e}");
        }
        let _ = app.emit(
            "shared-files-changed",
            serde_json::json!({ "unshared": count }),
        );
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
    let reload_key = format!(
        "__reload_{}__",
        RELOAD_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    {
        let mut flags = cancel_flags.write().await;
        // Single-flight: signal any reload already in progress to stop before
        // starting this one. Two concurrent reloads would race on the shared
        // local index and emit conflicting progress events; the newest request
        // wins. (Only `__reload_*` keys are reloads — other entries are
        // per-file hash-cancel flags, which we must not touch.)
        for (key, flag) in flags.iter() {
            if key.starts_with("__reload_") {
                flag.store(true, Ordering::Relaxed);
            }
        }
        flags.insert(reload_key.clone(), cancel_flag.clone());
    }

    let scan_handle = tokio::spawn(async move {
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
            .filter(|folder| {
                current_folders
                    .iter()
                    .any(|current| paths_equal_ignore_case(current, folder))
            })
            .cloned()
            .collect::<Vec<_>>();
        discovered.retain(|file| file_in_shared_folders(&file.path, &reloaded_folders));

        if cancel_flag.load(Ordering::Relaxed) {
            info!("Reload cancelled during discovery");
            cancel_flags.write().await.remove(&reload_key);
            let _ = app.emit(
                "file-hash-progress",
                serde_json::json!({ "done": true, "current": 0, "total": 0, "file_name": "" }),
            );
            return;
        }

        let known_list = load_known_files();
        let files_to_hash = resolve_from_known(&mut discovered, &known_list);

        {
            let mut index = local_index.write().await;
            index.reconcile_files_for_folders(&reloaded_folders, discovered);
        }
        refresh_file_cache(&local_index, &file_cache).await;

        let _ = app.emit(
            "shared-files-changed",
            serde_json::json!({
                "phase": "discovered",
                "count": total_files,
            }),
        );

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

            debug!(
                "Reload hashing {}/{}: {}",
                hashed_count + 1,
                total_to_hash,
                file.name
            );

            let _ = app.emit(
                "file-hash-progress",
                serde_json::json!({
                    "current": hashed_count + 1,
                    "total": total_to_hash,
                    "file_name": file.name,
                }),
            );

            let hash_result = tokio::time::timeout(
                std::time::Duration::from_secs(300),
                tokio::task::spawn_blocking(move || {
                    FileIndexer::hash_file_cancellable(std::path::Path::new(&file_path), &cf)
                }),
            )
            .await;

            match hash_result {
                Ok(Ok(Ok((ed2k_hash, aich_hash)))) => {
                    debug!(
                        "Reload hash complete: {} -> {}",
                        file.name,
                        &ed2k_hash[..ed2k_hash.len().min(8)]
                    );
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
                // Scope the pending cleanup to the folders this reload owns so a
                // concurrent folder-add scan keeps its in-progress entries.
                index.remove_pending_files_under(&reloaded_folders);
            }
            index.rebuild();
        }

        refresh_file_cache(&local_index, &file_cache).await;

        if !was_cancelled {
            let all_files = {
                let index = local_index.read().await;
                index
                    .all_files()
                    .iter()
                    .filter(|f| !f.hash.is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
            };
            if !all_files.is_empty() {
                if let Err(e) =
                    network_tx.try_send(NetworkCommand::AnnounceFiles { files: all_files })
                {
                    warn!("Failed to queue AnnounceFiles on reload: {e}");
                }
            }
        }

        if let Err(e) = network_tx.try_send(NetworkCommand::SharedFilesChanged) {
            warn!("Failed to queue SharedFilesChanged on reload: {e}");
        }
        cancel_flags.write().await.remove(&reload_key);

        let from_known = total_files.saturating_sub(total_to_hash);
        info!(
            "Reload complete: {hashed_count}/{total_to_hash} hashed, {from_known} from known.met{}",
            if was_cancelled { " (cancelled)" } else { "" }
        );

        let _ = app.emit(
            "file-hash-progress",
            serde_json::json!({
                "current": total_to_hash,
                "total": total_to_hash,
                "file_name": "",
                "done": true,
            }),
        );
        drop(_scan_guard);
    });

    // Track the reload scan so shutdown can wait for / abort it before the
    // on-exit known.met / local_index flush (see add_shared_folder).
    state.register_background_scan(scan_handle).await;

    Ok(())
}

#[tauri::command]
pub async fn get_scan_status(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    Ok(state.scanning_count.load(Ordering::Relaxed) > 0)
}

#[tauri::command]
pub async fn stop_hashing(state: tauri::State<'_, AppState>) -> Result<Vec<String>, String> {
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
            index_snap.iter().any(|file| {
                crate::security::path_matches_dir(&file.path, folder) && file.hash.is_empty()
            })
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
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    file_path: String,
    file_hash: Option<String>,
) -> Result<(), String> {
    let file = {
        let mut index = state.local_index.write().await;
        if index.get_by_path(&file_path).is_none() {
            // Surface a desync instead of silently reporting success: the UI
            // asked to unshare a path the backend index doesn't know about.
            return Err(coded(
                "sharing_file_not_in_index",
                "File not found in shared index",
            ));
        }
        if index.set_file_shared_by_path(&file_path, false) {
            index.get_by_path(&file_path).cloned()
        } else {
            None
        }
    };
    if file.is_some() {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        if let Err(e) = state
            .network_tx
            .try_send(NetworkCommand::SharedFilesChanged)
        {
            warn!("Failed to queue SharedFilesChanged after unshare: {e}");
        }
        let _ = app.emit("shared-files-changed", serde_json::json!({ "unshared": 1 }));
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
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<(), String> {
    let file = {
        let mut index = state.local_index.write().await;
        if index.get_by_path(&file_path).is_none() {
            // Surface a desync instead of silently reporting success: the UI
            // asked to share a path the backend index doesn't know about.
            return Err(coded(
                "sharing_file_not_in_index",
                "File not found in shared index",
            ));
        }
        index.set_file_shared_by_path(&file_path, true);
        index.get_by_path(&file_path).cloned()
    };
    if file.is_some() {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        if let Err(e) = state
            .network_tx
            .try_send(NetworkCommand::SharedFilesChanged)
        {
            warn!("Failed to queue SharedFilesChanged after share: {e}");
        }
        let _ = app.emit("shared-files-changed", serde_json::json!({ "shared": 1 }));
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
        if let Err(e) = state
            .network_tx
            .try_send(NetworkCommand::SharedFilesChanged)
        {
            warn!("Failed to queue SharedFilesChanged after unshare_folder: {e}");
        }
        let _ = app.emit(
            "shared-files-changed",
            serde_json::json!({ "folder": path, "unshared": true }),
        );
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
    if file_path.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "sharing_file_path_too_long",
            format!("File path exceeds {MAX_PATH_LEN} bytes"),
            MAX_PATH_LEN,
        ));
    }
    let allowed_dirs = {
        let config = state.config.read().await;
        shared_access_dirs(&config)
    };

    let canonical = tokio::task::spawn_blocking({
        let file_path = file_path.clone();
        move || -> Result<std::path::PathBuf, String> {
            let path = std::path::Path::new(&file_path);
            if !path.exists() {
                return Err(coded("sharing_file_not_exist", "File does not exist"));
            }
            if !path.is_file() {
                return Err(coded("sharing_path_not_file", "Path is not a file"));
            }
            let canonical = path
                .canonicalize()
                .map_err(|e| coded_ctx("sharing_invalid_path", "Invalid path", e))?;
            if !crate::security::is_path_within_dirs(&canonical, &allowed_dirs) {
                return Err(coded(
                    "sharing_file_not_in_shared",
                    "File is not within a shared or download folder",
                ));
            }
            Ok(canonical)
        }
    })
    .await
    .map_err(|e| coded_ctx("sharing_task_failed", "Task failed", e))??;

    delete_file_with_retry(&canonical, 6, 250).await?;

    let canonical_str = canonical.to_string_lossy().to_string();
    let removed = {
        let mut index = state.local_index.write().await;
        index
            .remove_file_by_path(&canonical_str)
            .or_else(|| index.remove_file_by_path(&file_path))
    };
    refresh_file_cache(&state.local_index, &state.cached_shared_files).await;

    if let Err(e) = state
        .network_tx
        .try_send(NetworkCommand::SharedFilesChanged)
    {
        warn!("Failed to queue SharedFilesChanged after file deletion: {e}");
    }
    let _ = app.emit(
        "shared-files-changed",
        serde_json::json!({ "file_deleted": true }),
    );

    info!(
        "Deleted shared file {}{}{}",
        canonical.display(),
        if removed.is_none() {
            " (not indexed)"
        } else {
            ""
        },
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
pub async fn scan_missing_files(state: tauri::State<'_, AppState>) -> Result<Vec<String>, String> {
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
    .map_err(|e| coded_ctx("sharing_scan_task_failed", "Scan task failed", e))?;
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
    if paths.len() > MAX_REMOVE_MISSING_PATHS {
        return Err(coded_ctx(
            "sharing_too_many_paths",
            format!("Too many paths in one call (max {MAX_REMOVE_MISSING_PATHS})"),
            MAX_REMOVE_MISSING_PATHS,
        ));
    }
    // Drop empty / over-long entries up front: they can't name a real shared
    // file and we don't want to spend a stat() syscall on an attacker-sized path.
    let to_check: Vec<String> = paths
        .into_iter()
        .filter(|p| !p.is_empty() && p.len() <= MAX_PATH_LEN)
        .collect();
    if to_check.is_empty() {
        return Ok(0);
    }
    let really_missing = tokio::task::spawn_blocking(move || {
        to_check
            .into_iter()
            .filter(|p| !std::path::Path::new(p).exists())
            .collect::<Vec<_>>()
    })
    .await
    .map_err(|e| coded_ctx("sharing_scan_task_failed", "Scan task failed", e))?;

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
        if let Err(e) = state
            .network_tx
            .try_send(NetworkCommand::SharedFilesChanged)
        {
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
        return Err(coded(
            "sharing_invalid_file_hash",
            "Invalid file hash (expected 32-char hex MD4)",
        ));
    }
    let file_exists = {
        let index = state.local_index.read().await;
        index
            .all_files()
            .iter()
            .any(|f| !f.hash.is_empty() && f.hash.eq_ignore_ascii_case(&cleaned))
    };
    if !file_exists {
        return Err(coded(
            "sharing_file_not_in_index",
            "File not found in shared index",
        ));
    }
    state
        .network_tx
        .try_send(NetworkCommand::RepublishFile {
            file_hash_hex: cleaned,
        })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    Ok(())
}

#[tauri::command]
pub async fn open_shared_file(
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<(), String> {
    if file_path.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "sharing_file_path_too_long",
            format!("File path exceeds {MAX_PATH_LEN} bytes"),
            MAX_PATH_LEN,
        ));
    }
    let allowed_dirs = {
        let config = state.config.read().await;
        shared_access_dirs(&config)
    };

    tokio::task::spawn_blocking(move || {
        let path = std::path::Path::new(&file_path);
        if !path.exists() {
            return Err(coded("sharing_file_not_exist", "File does not exist"));
        }
        let canonical = path
            .canonicalize()
            .map_err(|e| coded_ctx("sharing_invalid_path", "Invalid path", e))?;
        if !crate::security::is_path_within_dirs(&canonical, &allowed_dirs) {
            return Err(coded(
                "sharing_file_not_in_shared",
                "File is not within a shared or download folder",
            ));
        }
        if crate::security::is_dangerous_extension(&canonical.to_string_lossy()) {
            return Err(coded(
                "sharing_dangerous_file",
                "Cannot open potentially dangerous file types",
            ));
        }
        opener::open(&canonical)
            .map_err(|e| coded_ctx("sharing_open_file_failed", "Failed to open file", e))?;
        Ok(())
    })
    .await
    .map_err(|e| coded_ctx("sharing_task_failed", "Task failed", e))?
}

#[tauri::command]
pub async fn open_shared_folder(
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<(), String> {
    if file_path.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "sharing_file_path_too_long",
            format!("File path exceeds {MAX_PATH_LEN} bytes"),
            MAX_PATH_LEN,
        ));
    }
    let allowed_dirs = {
        let config = state.config.read().await;
        shared_access_dirs(&config)
    };

    tokio::task::spawn_blocking(move || {
        let path = std::path::Path::new(&file_path);
        let folder = path.parent().unwrap_or(path);
        if !folder.exists() {
            return Err(coded("sharing_folder_not_exist", "Folder does not exist"));
        }
        let canonical = folder
            .canonicalize()
            .map_err(|e| coded_ctx("sharing_invalid_path", "Invalid path", e))?;
        if !crate::security::is_path_within_dirs(&canonical, &allowed_dirs) {
            return Err(coded(
                "sharing_folder_not_in_shared",
                "Folder is not within a shared or download directory",
            ));
        }
        opener::open(&canonical)
            .map_err(|e| coded_ctx("sharing_open_folder_failed", "Failed to open folder", e))?;
        Ok(())
    })
    .await
    .map_err(|e| coded_ctx("sharing_task_failed", "Task failed", e))?
}
