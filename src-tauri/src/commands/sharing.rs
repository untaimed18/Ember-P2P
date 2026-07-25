use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tauri::Emitter;
use tauri::Manager;
use tauri_plugin_dialog::DialogExt;

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
const MAX_BATCH_PATH_BYTES: usize = 8 * 1024 * 1024;
const MAX_SCAN_MISSING_RESULTS: usize = 10_000;
/// Upper bound on the number of paths accepted by `remove_missing_files` in a
/// single IPC call. Generous enough for any realistic library while bounding a
/// compromised-webview payload (and the per-call stat loop / index lock hold).
const MAX_REMOVE_MISSING_PATHS: usize = 200_000;

fn check_path_batch(paths: &[String], max_count: usize) -> Result<(), String> {
    if paths.len() > max_count {
        return Err(coded_ctx(
            "sharing_batch_too_large",
            format!("Too many paths in one batch (max {max_count})"),
            paths.len(),
        ));
    }
    let mut total = 0usize;
    for path in paths {
        if path.len() > MAX_PATH_LEN {
            return Err(coded_ctx(
                "sharing_file_path_too_long",
                format!("File path exceeds {MAX_PATH_LEN} bytes"),
                path.len(),
            ));
        }
        total = total.saturating_add(path.len());
        if total > MAX_BATCH_PATH_BYTES {
            return Err(coded_ctx(
                "sharing_batch_bytes_too_large",
                format!("Path batch exceeds {MAX_BATCH_PATH_BYTES} bytes"),
                total,
            ));
        }
    }
    Ok(())
}

/// Result of a missing-file filesystem probe. `paths` is capped; when
/// `truncated` is true, `total_missing` is still the full count so the UI can
/// warn instead of silently under-reporting.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissingScanResult {
    pub paths: Vec<String>,
    pub truncated: bool,
    pub total_missing: u32,
}

struct ScanGuard(Arc<AtomicUsize>);
impl Drop for ScanGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

static RELOAD_COUNTER: AtomicUsize = AtomicUsize::new(0);
static RELOAD_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
static MEDIA_METADATA_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

async fn remove_cancel_flag_if_current(
    flags: &Arc<RwLock<std::collections::HashMap<String, Arc<AtomicBool>>>>,
    key: &str,
    ours: &Arc<AtomicBool>,
) {
    let mut flags = flags.write().await;
    if flags
        .get(key)
        .is_some_and(|current| Arc::ptr_eq(current, ours))
    {
        flags.remove(key);
    }
}

use crate::app_state::AppState;
use crate::commands::errors::{await_reply, bounded_send, coded, coded_ctx};
use crate::network::NetworkCommand;
use crate::search::index::LocalIndex;
use crate::sharing::indexer::FileIndexer;
use crate::storage::known_files::{priority_str_to_u8, priority_u8_to_str, KnownFileList};
use crate::types::*;
use tracing::{debug, info, warn};

async fn reconcile_shared_files(
    network_tx: &tokio::sync::mpsc::Sender<NetworkCommand>,
) -> Result<(), String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    bounded_send(network_tx, NetworkCommand::SharedFilesChangedAck { tx }).await?;
    await_reply(
        rx,
        "sharing_reconcile_failed",
        "Failed to reconcile shared files",
    )
    .await?
}

async fn reconcile_shared_files_best_effort(
    network_tx: &tokio::sync::mpsc::Sender<NetworkCommand>,
) {
    if let Err(e) = reconcile_shared_files(network_tx).await {
        warn!("Failed to reconcile shared files (best-effort): {e}");
    }
}

pub(crate) fn fresh_part_hash_key(hash: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(hash).ok()?;
    if bytes.len() != 16 {
        return None;
    }
    let mut key = [0u8; 16];
    key.copy_from_slice(&bytes);
    Some(key)
}

pub(crate) fn fresh_part_hash_handoff(
    hash: &str,
    part_hashes: Vec<[u8; 16]>,
) -> Option<([u8; 16], Vec<[u8; 16]>)> {
    let file_hash = fresh_part_hash_key(hash)?;
    (!part_hashes.is_empty()).then_some((file_hash, part_hashes))
}

pub(crate) async fn cache_fresh_part_hash_handoff(
    fresh_part_hashes: &Arc<RwLock<std::collections::HashMap<[u8; 16], Vec<[u8; 16]>>>>,
    finalized: bool,
    handoff: Option<([u8; 16], Vec<[u8; 16]>)>,
) {
    if finalized {
        if let Some((file_hash, part_hashes)) = handoff {
            fresh_part_hashes
                .write()
                .await
                .insert(file_hash, part_hashes);
        }
    }
}

fn fresh_part_hashes_exclusively_under_roots(
    files: &[FileInfo],
    roots: &[String],
) -> HashSet<[u8; 16]> {
    let removed_hashes = files
        .iter()
        .filter(|file| {
            roots
                .iter()
                .any(|root| crate::security::path_matches_dir(&file.path, root))
        })
        .filter_map(|file| fresh_part_hash_key(&file.hash))
        .collect::<HashSet<_>>();
    let retained_hashes = files
        .iter()
        .filter(|file| {
            !roots
                .iter()
                .any(|root| crate::security::path_matches_dir(&file.path, root))
        })
        .filter_map(|file| fresh_part_hash_key(&file.hash))
        .collect::<HashSet<_>>();
    removed_hashes
        .difference(&retained_hashes)
        .copied()
        .collect()
}

fn unreferenced_fresh_part_hashes(
    files: &[FileInfo],
    candidates: &HashSet<[u8; 16]>,
) -> HashSet<[u8; 16]> {
    let referenced = files
        .iter()
        .filter_map(|file| fresh_part_hash_key(&file.hash))
        .collect::<HashSet<_>>();
    candidates.difference(&referenced).copied().collect()
}

fn fresh_part_hashes_removed_by_reload(
    before: &[FileInfo],
    after: &[FileInfo],
    folders: &[String],
) -> HashSet<[u8; 16]> {
    let candidates = before
        .iter()
        .filter(|file| file_in_shared_folders(&file.path, folders))
        .filter_map(|file| fresh_part_hash_key(&file.hash))
        .collect::<HashSet<_>>();
    unreferenced_fresh_part_hashes(after, &candidates)
}

async fn discard_fresh_part_hashes(
    fresh_part_hashes: &Arc<RwLock<std::collections::HashMap<[u8; 16], Vec<[u8; 16]>>>>,
    hashes: &HashSet<[u8; 16]>,
) {
    if hashes.is_empty() {
        return;
    }
    fresh_part_hashes
        .write()
        .await
        .retain(|hash, _| !hashes.contains(hash));
}

fn effective_shared_root_changes(
    removed_roots: &[String],
    added_roots: &[String],
    active_roots: &[String],
) -> (Vec<String>, Vec<String>) {
    let removed = removed_roots
        .iter()
        .filter(|root| !file_in_shared_folders(root, active_roots))
        .cloned()
        .collect();
    let added = added_roots
        .iter()
        .filter(|root| file_in_shared_folders(root, active_roots))
        .cloned()
        .collect();
    (removed, added)
}

/// Apply a `shared_folders` change made through the generic Settings command.
/// The explicit add/remove commands have equivalent logic, but Settings can
/// replace the entire root list in one save and must revoke removed roots
/// before any fallible network publication work.
pub(crate) async fn reconcile_shared_folder_roots(
    app: &tauri::AppHandle,
    state: &AppState,
    removed_roots: &[String],
    added_roots: &[String],
) {
    // The upload listener consults this list before serving an index row, so
    // update it before waiting for a scan. This is the immediate revocation
    // boundary even while a long-running discovery pass still owns
    // `scan_coordination`.
    let immediate_active_roots = state.config.read().await.settings.shared_folders.clone();
    *state.upload_shared_folders.write().await = immediate_active_roots;

    // Signal per-folder scans under removed roots BEFORE queueing on
    // `scan_coordination`, mirroring `remove_shared_folder`. Signaled only
    // after the lock, the flags could never shorten the wait for a running
    // scan of a root that is being removed. Broad startup/reload generations
    // are deliberately left running (see `scan_can_write_under`).
    if !removed_roots.is_empty() {
        let flags = state.hash_cancel_flags.read().await;
        for (scan_key, flag) in flags.iter() {
            if removed_roots
                .iter()
                .any(|root| scan_can_write_under(scan_key, root))
            {
                flag.store(true, Ordering::Relaxed);
            }
        }
    }

    // Scans persist their resume cursors while holding scan_coordination and
    // then settings_save_lock. Take those locks in that same order here, and
    // snapshot Settings only after acquiring scan_coordination so a later
    // settings save cannot leave the watcher/index on an obsolete root list.
    let scan_coordination_guard = state.scan_coordination.lock().await;
    let settings_save_guard = state.settings_save_lock.lock().await;
    let active_roots = state.config.read().await.settings.shared_folders.clone();
    let (effective_removed_roots, effective_added_roots) =
        effective_shared_root_changes(removed_roots, added_roots, &active_roots);
    *state.upload_shared_folders.write().await = active_roots.clone();

    let (removed_row_count, removed_hashes) = if effective_removed_roots.is_empty() {
        (0, HashSet::new())
    } else {
        {
            let flags = state.hash_cancel_flags.read().await;
            for (scan_key, flag) in flags.iter() {
                if effective_removed_roots
                    .iter()
                    .any(|root| scan_can_write_under(scan_key, root))
                {
                    flag.store(true, Ordering::Relaxed);
                }
            }
        }

        let mut index = state.local_index.write().await;
        let removed_files = index.remove_files_outside_folders(&active_roots);
        let candidates = removed_files
            .iter()
            .filter_map(|file| fresh_part_hash_key(&file.hash))
            .collect::<HashSet<_>>();
        let hashes = unreferenced_fresh_part_hashes(index.all_files(), &candidates);
        (removed_files.len(), hashes)
    };

    if let Some(watcher) = state.shared_folder_watcher.as_ref() {
        watcher.sync_paths(&active_roots);
    }
    {
        let config = state.config.read().await;
        sync_asset_protocol_scope(app, &config);
    }
    drop(settings_save_guard);
    drop(scan_coordination_guard);

    if removed_row_count > 0 {
        discard_fresh_part_hashes(&state.fresh_part_hashes, &removed_hashes).await;
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
    }

    // Do this after local revocation. A saturated or stopped network task may
    // defer publication changes, but must never keep a removed root visible
    // in the local upload/index state.
    reconcile_shared_files_best_effort(&state.network_tx).await;

    if !effective_added_roots.is_empty() {
        // A full reload shares the established bounded discovery/hash path and
        // guarantees every newly-added root is picked up without duplicating
        // the per-folder scan machinery here.
        let state_ref = app.state::<AppState>();
        if let Err(e) = reload_shared_files(app.clone(), state_ref).await {
            warn!("Failed to schedule discovery for newly configured shared folders: {e}");
        }
    }

    let _ = app.emit(
        "shared-files-changed",
        serde_json::json!({
            "removed_folders": effective_removed_roots,
            "added_folders": effective_added_roots,
            "phase": "settings-roots-reconciled",
        }),
    );
}

async fn persist_shared_states(
    network_tx: &tokio::sync::mpsc::Sender<NetworkCommand>,
    hashes: &[String],
    shared: bool,
) -> Result<(), String> {
    if hashes.is_empty() {
        return Ok(());
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    let updates = hashes
        .iter()
        .filter(|hash| !hash.is_empty())
        .map(|hash| (hash.clone(), shared))
        .collect();
    bounded_send(network_tx, NetworkCommand::SetFilesShared { updates, tx }).await?;
    await_reply(
        rx,
        "sharing_persist_state_failed",
        "Failed to persist file sharing state",
    )
    .await??;
    Ok(())
}

async fn persist_upload_priorities(
    network_tx: &tokio::sync::mpsc::Sender<NetworkCommand>,
    hashes: &[String],
    priority: u8,
) -> Result<(), String> {
    let file_hashes = hashes
        .iter()
        .filter(|hash| !hash.is_empty())
        .cloned()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if file_hashes.is_empty() {
        return Ok(());
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    bounded_send(
        network_tx,
        NetworkCommand::SetUploadPriorities {
            file_hashes,
            priority,
            tx,
        },
    )
    .await?;
    await_reply(
        rx,
        "sharing_persist_priority_failed",
        "Failed to persist upload priority",
    )
    .await?
}

async fn persist_priority_snapshot(
    network_tx: &tokio::sync::mpsc::Sender<NetworkCommand>,
    files: &[FileInfo],
) -> Result<(), String> {
    let mut by_priority: std::collections::HashMap<u8, HashSet<String>> =
        std::collections::HashMap::new();
    for file in files {
        if !file.hash.is_empty() {
            by_priority
                .entry(priority_str_to_u8(&file.priority))
                .or_default()
                .insert(file.hash.clone());
        }
    }
    for (priority, hashes) in by_priority {
        persist_upload_priorities(
            network_tx,
            &hashes.into_iter().collect::<Vec<_>>(),
            priority,
        )
        .await?;
    }
    Ok(())
}

fn paths_equal_ignore_case(a: &str, b: &str) -> bool {
    let normalize = |path: &str| {
        crate::search::index::normalize_path_key(path)
            .trim_end_matches(|c| c == '/' || c == '\\')
            .to_string()
    };
    normalize(a) == normalize(b)
}

/// Whether a registered scan generation can add files at or below
/// `removed_folder`.
///
/// Per-folder scan keys are their canonical roots. Startup/reload generations
/// are deliberately not cancelled here: their snapshots may predate a newly
/// added folder and therefore be unrelated. The shared scan-coordination guard
/// below either lets an already-running broad scan finish before removal, or
/// makes a queued broad scan start afterward; startup/reload both re-filter
/// against current config before writes, so neither ordering can resurrect the
/// removed folder.
fn scan_can_write_under(scan_key: &str, removed_folder: &str) -> bool {
    if scan_key.starts_with("__") {
        return false;
    }
    crate::security::path_matches_dir(scan_key, removed_folder)
        || crate::security::path_matches_dir(removed_folder, scan_key)
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
                .map(|file| {
                    (
                        crate::search::index::normalize_path_key(&file.path),
                        (file.shared_kad, file.shared_ed2k),
                    )
                })
                .collect::<std::collections::HashMap<_, _>>()
        },);
    let mut snap = snap_raw;
    for file in &mut snap {
        let key = crate::search::index::normalize_path_key(&file.path);
        if let Some((shared_kad, shared_ed2k)) = previous_flags.get(&key) {
            file.shared_kad = file.shared && !file.hash.is_empty() && *shared_kad;
            file.shared_ed2k = file.shared && !file.hash.is_empty() && *shared_ed2k;
        }
    }
    *cache.write().await = snap;
}

async fn rollback_index_mutation(state: &AppState, snapshot: Vec<FileInfo>) {
    {
        let mut index = state.local_index.write().await;
        index.restore_snapshot(snapshot);
    }
    refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
}

async fn persist_share_mutation(
    state: &AppState,
    mutation: &crate::search::index::ShareMutation,
    shared: bool,
    snapshot: Vec<FileInfo>,
) -> Result<(), String> {
    if let Err(e) = persist_shared_states(&state.network_tx, &mutation.hashes, shared).await {
        rollback_index_mutation(state, snapshot).await;
        return Err(e);
    }
    let pending_updates = mutation
        .pending_paths
        .iter()
        .cloned()
        .map(|path| (path, shared))
        .collect::<Vec<_>>();
    if let Err(e) =
        persist_pending_intents(state, &pending_updates, &[], &mutation.hashed_paths, &[]).await
    {
        // The known.met half already committed. Compensate it before rolling
        // back the optimistic index so a failed config write cannot leave the
        // next restart with the opposite share state.
        let persistence_rollback =
            persist_shared_states(&state.network_tx, &mutation.hashes, !shared).await;
        rollback_index_mutation(state, snapshot).await;
        return match persistence_rollback {
            Ok(()) => Err(e),
            Err(rollback_error) => Err(coded_ctx(
                "sharing_state_rollback_failed",
                "Share-state save and rollback both failed",
                format!("{e}; rollback: {rollback_error}"),
            )),
        };
    }
    reconcile_shared_files_best_effort(&state.network_tx).await;
    Ok(())
}

fn load_known_files() -> KnownFileList {
    let data_dir = crate::storage::paths::resolve_data_dir();
    KnownFileList::load(&data_dir.join("known.met"))
}

pub(crate) fn shared_access_dirs(config: &crate::storage::config::AppConfig) -> Vec<String> {
    let mut allowed_dirs = config.settings.shared_folders.clone();
    let download_dir = std::path::PathBuf::from(&config.settings.download_folder)
        .join("Downloads")
        .to_string_lossy()
        .to_string();
    allowed_dirs.push(download_dir);
    allowed_dirs.push(config.settings.download_folder.clone());
    allowed_dirs
}

/// Legacy call site retained while media moves to the dynamic `ember-media`
/// protocol. The Tauri asset scope is intentionally not granted any folders:
/// `allow_directory` cannot revoke a previous root without making a later
/// re-add permanently inaccessible in this process.
pub(crate) fn sync_asset_protocol_scope(
    _app: &tauri::AppHandle,
    _config: &crate::storage::config::AppConfig,
) {
}

fn percent_decode_path(value: &str) -> Option<String> {
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let high = *bytes.get(i + 1)?;
            let low = *bytes.get(i + 2)?;
            let nibble = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            out.push((nibble(high)? << 4) | nibble(low)?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn media_content_type(path: &std::path::Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" | "opus" => "audio/ogg",
        "aac" => "audio/aac",
        "flac" => "audio/flac",
        "m4a" => "audio/mp4",
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        _ => "application/octet-stream",
    }
}

const MAX_MEDIA_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

fn parse_single_range(range: Option<&str>, length: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(range) = range else {
        return Ok(None);
    };
    let range = range.strip_prefix("bytes=").ok_or(())?;
    let (start, end) = range.split_once('-').ok_or(())?;
    if start.contains(',') || end.contains(',') || length == 0 {
        return Err(());
    }
    if start.is_empty() {
        let suffix = end.parse::<u64>().map_err(|_| ())?.min(length);
        if suffix == 0 {
            return Err(());
        }
        return Ok(Some((
            length.saturating_sub(suffix),
            length.saturating_sub(1),
        )));
    }
    let start = start.parse::<u64>().map_err(|_| ())?;
    if start >= length {
        return Err(());
    }
    let end = if end.is_empty() {
        length - 1
    } else {
        end.parse::<u64>().map_err(|_| ())?.min(length - 1)
    };
    (start <= end).then_some((start, end)).ok_or(()).map(Some)
}

/// Serve in-app media with a containment decision made at request time, not
/// only when the UI originally created the URL. This makes a removed share root
/// immediately inaccessible even if a stale WebView URL is retained.
pub(crate) async fn serve_media_request(
    app: tauri::AppHandle,
    encoded_path: String,
    range: Option<String>,
) -> tauri::http::Response<Vec<u8>> {
    let Some(file_path) = percent_decode_path(&encoded_path) else {
        return tauri::http::Response::builder()
            .status(tauri::http::StatusCode::BAD_REQUEST)
            .body(b"invalid media path".to_vec())
            .unwrap_or_default();
    };
    let (allowed_dirs, indexed_paths) = {
        let state = app.state::<AppState>();
        let config = state.config.read().await;
        let allowed_dirs = shared_access_dirs(&config);
        drop(config);
        let index = state.local_index.read().await;
        let indexed_paths = index
            .all_files()
            .iter()
            .map(|file| {
                (
                    crate::search::index::normalize_path_key(&file.path),
                    file.name.clone(),
                )
            })
            .collect::<std::collections::HashMap<_, _>>();
        (allowed_dirs, indexed_paths)
    };
    let result = tokio::task::spawn_blocking(move || {
        let canonical = crate::security::filesystem::verify_existing_path(
            std::path::Path::new(&file_path),
            &allowed_dirs,
        )?;
        let indexed_name = indexed_paths.get(&crate::search::index::normalize_path_key(
            &canonical.to_string_lossy(),
        ));
        if !canonical.is_file()
            || indexed_name.is_none()
            || !crate::security::filesystem::passive_type_agrees(
                indexed_name.map(String::as_str).unwrap_or_default(),
                &canonical,
            )
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "media path is not currently authorized",
            ));
        }
        let mut file = std::fs::File::open(&canonical)?;
        let length = file.metadata()?.len();
        let selected_range = parse_single_range(range.as_deref(), length)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid range"))?;
        if length == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "empty media file",
            ));
        }
        let (start, requested_end) = selected_range.unwrap_or((0, length - 1));
        // Tauri URI responders take an owned byte buffer, not an async stream.
        // Cap each response so `bytes=0-` and range-less requests cannot turn a
        // multi-gigabyte video into one allocation. Media engines issue follow-up
        // byte ranges after a valid 206 response.
        let end =
            requested_end.min(start.saturating_add(MAX_MEDIA_RESPONSE_BYTES.saturating_sub(1)));
        let partial = start != 0 || end != length - 1;
        let bytes_len = end.saturating_sub(start).saturating_add(1);
        let mut body = vec![0; bytes_len as usize];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut body)?;
        Ok::<_, std::io::Error>((canonical, length, start, end, partial, body))
    })
    .await;
    let (canonical, length, start, end, partial, body) = match result {
        Ok(Ok(response)) => response,
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::InvalidInput => {
            return tauri::http::Response::builder()
                .status(tauri::http::StatusCode::RANGE_NOT_SATISFIABLE)
                .body(b"invalid media range".to_vec())
                .unwrap_or_default();
        }
        _ => {
            return tauri::http::Response::builder()
                .status(tauri::http::StatusCode::NOT_FOUND)
                .body(b"media is unavailable".to_vec())
                .unwrap_or_default();
        }
    };
    let mut response = tauri::http::Response::builder()
        .status(if partial {
            tauri::http::StatusCode::PARTIAL_CONTENT
        } else {
            tauri::http::StatusCode::OK
        })
        .header(
            tauri::http::header::CONTENT_TYPE,
            media_content_type(&canonical),
        )
        .header(tauri::http::header::ACCEPT_RANGES, "bytes")
        .header(tauri::http::header::CONTENT_LENGTH, body.len().to_string());
    if partial {
        response = response.header(
            tauri::http::header::CONTENT_RANGE,
            format!("bytes {start}-{end}/{length}"),
        );
    }
    response.body(body).unwrap_or_default()
}

pub(crate) fn file_in_shared_folders(file_path: &str, shared_folders: &[String]) -> bool {
    shared_folders
        .iter()
        .any(|folder| crate::security::path_matches_dir(file_path, folder))
}

async fn delete_file_with_retry(
    path: &std::path::Path,
    allowed_roots: &[String],
    expected: &crate::security::filesystem::ObjectIdentity,
    max_attempts: u32,
    delay_ms: u64,
) -> Result<(), String> {
    let mut last_error = None;
    for attempt in 1..=max_attempts {
        let delete_path = path.to_path_buf();
        let allowed = allowed_roots.to_vec();
        let expected = expected.clone();
        match tokio::task::spawn_blocking(move || {
            crate::security::filesystem::remove_approved_file_if_identity(
                &delete_path,
                &allowed,
                &expected,
            )
        })
        .await
        {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(e)) => {
                last_error = Some(e);
                if attempt < max_attempts {
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                }
            }
            Err(e) => {
                return Err(coded_ctx(
                    "sharing_delete_failed",
                    format!("Delete task failed for {}", path.display()),
                    e,
                ));
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
            file.ember_file_hash = record.ember_file_hash.clone();
            // Restore the per-file priority and shared/unshared choice from
            // known.met — without this, every rediscovery (folder add,
            // reload, or cold startup) silently reset a custom priority back
            // to "normal" and re-shared a file the user had explicitly
            // unshared.
            file.priority = priority_u8_to_str(record.upload_priority).to_string();
            file.shared =
                crate::storage::share_intent::effective_shared(&record.file_hash, record.is_shared);
            // The Library's Top Uploads panel and all-time activity columns
            // are populated from these persisted known.met counters. Restore
            // them with the hash instead of showing an empty Library until the
            // network cache refresh happens to run.
            file.alltime_requests = record.all_time_requested;
            file.alltime_accepted = record.all_time_accepted;
            file.alltime_transferred = record.all_time_transferred;
            // Restore the last-known Peers count so the UI doesn't flash
            // back to 0 until the next 60s source-count sync completes.
            file.complete_sources = record.complete_sources;
            // Slice 18 migration: known.met entries created before
            // ember_file_hash must be rehashed once so DHT publish and
            // download verify see a real BLAKE3 (zeros skip verify).
            if file.ember_file_hash.is_empty() {
                needs_hashing.push(file.clone());
            }
        } else {
            needs_hashing.push(file.clone());
        }
    }
    needs_hashing
}

/// Apply a folder's configured default priority only to paths that need a new
/// hash. Known files keep their persisted per-file priority, while pending
/// files and their later hash-completion replacements inherit this value.
fn apply_folder_defaults_to_new_files(
    discovered: &mut [FileInfo],
    files_to_hash: &mut [FileInfo],
    folder_priorities: &std::collections::HashMap<String, String>,
) {
    if folder_priorities.is_empty() || files_to_hash.is_empty() {
        return;
    }
    let pending_paths = files_to_hash
        .iter()
        .map(|file| crate::search::index::normalize_path_key(&file.path))
        .collect::<HashSet<_>>();
    let priority_for_path = |path: &str| {
        folder_priorities
            .iter()
            .filter(|(folder, priority)| {
                !priority.is_empty() && crate::security::path_matches_dir(path, folder)
            })
            .max_by_key(|(folder, _)| folder.len())
            .map(|(_, priority)| priority.clone())
    };
    for file in discovered.iter_mut().filter(|file| {
        pending_paths.contains(&crate::search::index::normalize_path_key(&file.path))
    }) {
        if let Some(priority) = priority_for_path(&file.path) {
            file.priority = priority;
        }
    }
    for file in files_to_hash.iter_mut() {
        if let Some(priority) = priority_for_path(&file.path) {
            file.priority = priority;
        }
    }
}

pub(crate) fn apply_pending_intents(
    discovered: &mut [FileInfo],
    files_to_hash: &mut [FileInfo],
    pending_share_states: &std::collections::HashMap<String, bool>,
    pending_file_priorities: &std::collections::HashMap<String, String>,
) {
    let pending_paths = files_to_hash
        .iter()
        .map(|file| crate::search::index::normalize_path_key(&file.path))
        .collect::<HashSet<_>>();
    let apply = |file: &mut FileInfo| {
        let key = crate::search::index::normalize_path_key(&file.path);
        if let Some(shared) = pending_share_states.get(&key) {
            file.shared = *shared;
        }
        if let Some(priority) = pending_file_priorities.get(&key) {
            file.priority = priority.clone();
        }
    };
    for file in discovered.iter_mut().filter(|file| {
        pending_paths.contains(&crate::search::index::normalize_path_key(&file.path))
    }) {
        apply(file);
    }
    for file in files_to_hash {
        apply(file);
    }
}

async fn persist_pending_intents(
    state: &AppState,
    share_updates: &[(String, bool)],
    priority_updates: &[(String, String)],
    share_removals: &[String],
    priority_removals: &[String],
) -> Result<(), String> {
    if share_updates.is_empty()
        && priority_updates.is_empty()
        && share_removals.is_empty()
        && priority_removals.is_empty()
    {
        return Ok(());
    }
    let _settings_save_guard = state.settings_save_lock.lock().await;
    let mut settings = {
        let config = state.config.read().await;
        config.settings.clone()
    };
    for (path, shared) in share_updates {
        settings
            .pending_share_states
            .insert(crate::search::index::normalize_path_key(path), *shared);
    }
    for (path, priority) in priority_updates {
        settings.pending_file_priorities.insert(
            crate::search::index::normalize_path_key(path),
            priority.clone(),
        );
    }
    // A pending intent is a one-shot handoff for a file that was still
    // hashing. Once the file is hashed (or an explicit change is applied to
    // the hashed row), known.met owns the state and the intent must die —
    // a stale entry would re-apply on the next rehash and silently flip a
    // share/priority the user has since changed.
    let mut removed_any = false;
    for path in share_removals {
        removed_any |= settings
            .pending_share_states
            .remove(&crate::search::index::normalize_path_key(path))
            .is_some();
    }
    for path in priority_removals {
        removed_any |= settings
            .pending_file_priorities
            .remove(&crate::search::index::normalize_path_key(path))
            .is_some();
    }
    if share_updates.is_empty() && priority_updates.is_empty() && !removed_any {
        return Ok(());
    }
    // Only user-driven updates bump the visible settings revision; internal
    // intent cleanup must not make an open Settings form spuriously stale
    // (same rationale as `persist_scan_cursors`).
    if !share_updates.is_empty() || !priority_updates.is_empty() {
        settings.settings_revision = settings.settings_revision.saturating_add(1);
    }
    let save_data = {
        let config = state.config.read().await;
        config
            .prepare_save_settings(&settings)
            .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?
    };
    let (data, tmp, final_path) = save_data;
    tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
    })
    .await
    .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?
    .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?;
    state.config.write().await.settings = settings;
    Ok(())
}

/// Sweep pending share/priority intents whose files are now hashed. A pending
/// intent is a one-shot handoff from "user changed a file that was still
/// hashing" to the hash-completion path; once the row is hashed, known.met
/// owns the state. Entries left behind (pre-fix builds, crashes between
/// finalize and cleanup) would re-apply on the next rehash and silently flip
/// share/priority choices the user has since changed. Called after every
/// completed hash pass. Entries whose path has no hashed index row are kept —
/// they may belong to genuinely pending files in a later scan page.
pub(crate) async fn prune_pending_intents_for_hashed(state: &AppState) {
    let hashed_keys: HashSet<String> = {
        let index = state.local_index.read().await;
        index
            .all_files()
            .iter()
            .filter(|f| !f.hash.is_empty())
            .map(|f| crate::search::index::normalize_path_key(&f.path))
            .collect()
    };
    if hashed_keys.is_empty() {
        return;
    }
    let (share_stale, priority_stale) = {
        let config = state.config.read().await;
        (
            config
                .settings
                .pending_share_states
                .keys()
                .filter(|key| hashed_keys.contains(*key))
                .cloned()
                .collect::<Vec<_>>(),
            config
                .settings
                .pending_file_priorities
                .keys()
                .filter(|key| hashed_keys.contains(*key))
                .cloned()
                .collect::<Vec<_>>(),
        )
    };
    if share_stale.is_empty() && priority_stale.is_empty() {
        return;
    }
    if let Err(e) = persist_pending_intents(state, &[], &[], &share_stale, &priority_stale).await {
        warn!(
            "Failed to prune {} stale pending intents: {e}",
            share_stale.len() + priority_stale.len()
        );
    } else {
        info!(
            "Pruned {} pending share and {} pending priority intents for hashed files",
            share_stale.len(),
            priority_stale.len()
        );
    }
}

/// Persist completed shared-folder discovery pages. Cursors are advanced only
/// after the page has entered the in-memory index; if this save fails, a later
/// scan may repeat a page but it can never skip files.
pub(crate) async fn persist_scan_cursors(
    state: &AppState,
    updates: &std::collections::HashMap<String, Option<String>>,
) -> Result<(), String> {
    if updates.is_empty() {
        return Ok(());
    }
    let _settings_save_guard = state.settings_save_lock.lock().await;
    let mut settings = {
        let config = state.config.read().await;
        config.settings.clone()
    };
    for (folder, cursor) in updates {
        match cursor {
            Some(value) => {
                settings.shared_folder_scan_cursors.insert(
                    crate::search::index::normalize_path_key(folder),
                    value.clone(),
                );
            }
            None => {
                settings
                    .shared_folder_scan_cursors
                    .remove(&crate::search::index::normalize_path_key(folder));
            }
        }
    }
    // Scan cursors are internal recovery bookkeeping, not a user setting;
    // changing the visible revision here would make an open Settings form
    // spuriously stale whenever a large folder advances a page.
    let (data, tmp, final_path) = {
        let config = state.config.read().await;
        config
            .prepare_save_settings(&settings)
            .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?
    };
    tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
    })
    .await
    .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?
    .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?;
    state.config.write().await.settings = settings;
    Ok(())
}

/// eMule-style shared folder addition -- returns IMMEDIATELY.
/// All discovery and hashing runs in a background task:
///   Phase 1: discover files (metadata only) → show in UI via event
///   Phase 2: hash files one at a time → update UI + publish to KAD
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

    // Refuse system / sensitive path segments (shared with the indexer so
    // nested `.ssh` etc. are also skipped when walking an allowed parent).
    for component in canonical.components() {
        if let std::path::Component::Normal(seg) = component {
            if crate::sharing::is_sensitive_dir_name(&seg.to_string_lossy()) {
                return Err(coded_ctx(
                    "sharing_cannot_share_system_dir",
                    "Cannot share system directory",
                    canonical.display(),
                ));
            }
        }
    }

    // Refuse Ember's own data directory (config, identity, known.met, …),
    // and refuse a parent that contains it (indexer would otherwise walk in).
    let data_dir = crate::storage::paths::resolve_data_dir();
    let data_canon = data_dir.canonicalize().unwrap_or(data_dir.clone());
    let share_covers_data_dir = data_canon == canonical
        || data_canon.starts_with(&canonical)
        || paths_equal_ignore_case(&canonical.to_string_lossy(), &data_dir.to_string_lossy())
        || crate::security::path_matches_dir(
            &data_canon.to_string_lossy(),
            &canonical.to_string_lossy(),
        );
    if share_covers_data_dir {
        return Err(coded_ctx(
            "sharing_cannot_share_data_dir",
            "Cannot share Ember data directory or a parent of it",
            canonical.display(),
        ));
    }

    let canonical_str = canonical.to_string_lossy().to_string();
    // Build (but don't yet commit) the settings we intend to save. Persisting to
    // disk before mutating the in-memory config and the live upload list ensures
    // a failed write can't leave them advertising a folder that isn't saved.
    // Case-insensitive on Windows: `Vec::contains` is case-sensitive, so adding
    // `C:\Media` then `c:\media` would store both, double-scan, and make later
    // unshare/remove (which use paths_equal_ignore_case) inconsistent.
    let settings_save_guard = state.settings_save_lock.lock().await;
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
            if let Some(existing) = config.settings.shared_folders.iter().find(|existing| {
                crate::commands::settings::shared_paths_overlap(
                    std::path::Path::new(existing),
                    &canonical,
                )
            }) {
                return Err(coded_ctx(
                    "sharing_folder_overlap",
                    "Shared folders must not overlap",
                    format!("{existing} and {canonical_str}"),
                ));
            }
            let mut new_settings = config.settings.clone();
            new_settings.shared_folders.push(canonical_str.clone());
            new_settings.settings_revision = config.settings.settings_revision.saturating_add(1);
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
    let mut roots = {
        let config = state.config.read().await;
        let mut roots = config.settings.shared_folders.clone();
        if !config.settings.download_folder.is_empty() {
            roots.push(config.settings.download_folder.clone());
        }
        roots
    };
    roots.push(canonical_str.clone());
    let registry = state.approved_roots.clone();
    let approved = canonical_str.clone();
    tokio::task::spawn_blocking(move || {
        super::settings::persist_with_root_transaction(
            registry,
            &roots,
            std::slice::from_ref(&approved),
            || crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path),
        )
    })
    .await
    .map_err(|e| coded_ctx("sharing_config_transaction_error", "Config save error", e))?
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
        config.settings.settings_revision = config.settings.settings_revision.saturating_add(1);
    }
    drop(settings_save_guard);
    {
        let mut live = state.upload_shared_folders.write().await;
        if !live
            .iter()
            .any(|f| paths_equal_ignore_case(f, &canonical_str))
        {
            live.push(canonical_str.clone());
        }
    }

    // Adding a folder is an explicit user action that should resume hashing
    // even if a previous Stop left the pause latch set.
    state.hashing_paused.store(false, Ordering::Relaxed);

    // Start watching the new folder (and anything else currently shared).
    if let Some(watcher) = state.shared_folder_watcher.as_ref() {
        let folders = state.config.read().await.settings.shared_folders.clone();
        watcher.sync_paths(&folders);
    }
    {
        let config = state.config.read().await;
        sync_asset_protocol_scope(&app, &config);
    }

    // FS changes deferred during pause must not be lost when add-folder
    // clears the latch but only scans the new path. A full reload covers
    // every share (including the folder just added) and clears the dirty bit.
    if state.hashing_fs_dirty.load(Ordering::Relaxed) {
        info!("FS changes deferred during pause; running full shared-folder reload");
        return reload_shared_files(app, state).await;
    }

    let local_index = state.local_index.clone();
    let file_cache = state.cached_shared_files.clone();
    let network_tx = state.network_tx.clone();
    let scanning = state.scanning_count.clone();
    let scan_coordination = state.scan_coordination.clone();
    let cancel_flags = state.hash_cancel_flags.clone();
    let fresh_part_hashes = state.fresh_part_hashes.clone();
    let config = state.config.clone();
    let scan_truncated = state.library_scan_truncated.clone();

    let cancel_flag = Arc::new(AtomicBool::new(false));
    let cancel_key = canonical_str.clone();
    cancel_flags
        .write()
        .await
        .insert(cancel_key.clone(), cancel_flag.clone());

    let scan_handle = tokio::spawn(async move {
        let _coordination_guard = scan_coordination.lock().await;
        scanning.fetch_add(1, Ordering::Relaxed);
        let _scan_guard = ScanGuard(scanning.clone());

        let discover_path = canonical_str.clone();
        let discovery = match tokio::task::spawn_blocking(move || {
            FileIndexer::discover_directory(&discover_path)
        })
        .await
        {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Discovery failed for {path}: {e}");
                remove_cancel_flag_if_current(&cancel_flags, &cancel_key, &cancel_flag).await;
                return;
            }
        };
        if discovery.truncated {
            warn!(
                "Discovery for {path} reached the per-folder file cap; additional files will be picked up by a later scan"
            );
            scan_truncated.store(true, Ordering::Relaxed);
            let _ = app.emit(
                "shared-files-scan-truncated",
                serde_json::json!({ "folder": path, "limit": 100_000 }),
            );
        }
        let discovery_next_cursor = discovery.next_cursor;
        let mut discovered = discovery.files;

        let total_files = discovered.len();
        info!("Discovered {total_files} files in {path}");

        let still_shared = {
            let cfg = config.read().await;
            file_in_shared_folders(&canonical_str, &cfg.settings.shared_folders)
        };
        if cancel_flag.load(Ordering::Relaxed) || !still_shared {
            info!("Hashing cancelled during discovery for {path}");
            remove_cancel_flag_if_current(&cancel_flags, &cancel_key, &cancel_flag).await;
            let _ = app.emit(
                "file-hash-progress",
                serde_json::json!({ "done": true, "current": 0, "total": 0, "file_name": "" }),
            );
            return;
        }

        let known_list = load_known_files();
        let mut files_to_hash = resolve_from_known(&mut discovered, &known_list);
        let (folder_priorities, pending_share_states, pending_file_priorities) = {
            let cfg = config.read().await;
            (
                cfg.settings.folder_priorities.clone(),
                cfg.settings.pending_share_states.clone(),
                cfg.settings.pending_file_priorities.clone(),
            )
        };
        apply_folder_defaults_to_new_files(&mut discovered, &mut files_to_hash, &folder_priorities);
        apply_pending_intents(
            &mut discovered,
            &mut files_to_hash,
            &pending_share_states,
            &pending_file_priorities,
        );

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
                remove_cancel_flag_if_current(&cancel_flags, &cancel_key, &cancel_flag).await;
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
        let mut page_complete = true;

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
                Ok(Ok(Ok((
                    ed2k_hash,
                    aich_hash,
                    part_hashes,
                    ember_file_hash,
                    hashed_size,
                    hashed_modified_at,
                )))) => {
                    debug!(
                        "Hash complete: {} -> {}",
                        file.name,
                        &ed2k_hash[..ed2k_hash.len().min(8)]
                    );
                    let mut updated_file = file.clone();
                    updated_file.id = ed2k_hash.clone();
                    updated_file.hash = ed2k_hash;
                    updated_file.aich_hash = aich_hash;
                    updated_file.ember_file_hash = ember_file_hash;
                    updated_file.size = hashed_size;
                    updated_file.modified_at = hashed_modified_at;
                    if let Ok(bytes) = hex::decode(&updated_file.hash) {
                        if bytes.len() == 16 {
                            let mut hash = [0u8; 16];
                            hash.copy_from_slice(&bytes);
                            updated_file.shared = crate::storage::share_intent::effective_shared(
                                &hash,
                                updated_file.shared,
                            );
                        }
                    }

                    let still_shared = {
                        let cfg = config.read().await;
                        file_in_shared_folders(&updated_file.path, &cfg.settings.shared_folders)
                    };
                    // Retain the handoff only after its completed index row
                    // is committed. A cancelled folder scan drops its pending
                    // row, and caching first would leave no later
                    // reconciliation path to drain these part hashes.
                    let fresh_handoff = still_shared
                        .then(|| fresh_part_hash_handoff(&updated_file.hash, part_hashes))
                        .flatten();
                    let finalized = {
                        let mut index = local_index.write().await;
                        if !cancel_flag.load(Ordering::Relaxed) && still_shared {
                            // Preserve share/priority changes made while this
                            // pending row was hashing. If it was removed by a
                            // concurrent unshare/cancel, do not resurrect it.
                            index
                                .finalize_pending_hash(&file_temp_id, updated_file.clone())
                                .is_some()
                        } else {
                            index.remove_file_by_id(&file_temp_id);
                            false
                        }
                    };
                    cache_fresh_part_hash_handoff(&fresh_part_hashes, finalized, fresh_handoff)
                        .await;

                    if !cancel_flag.load(Ordering::Relaxed) && still_shared {
                        hashed_count += 1;
                    }
                    if !cancel_flag.load(Ordering::Relaxed)
                        && still_shared
                        && last_cache_refresh.elapsed() >= std::time::Duration::from_secs(5)
                    {
                        refresh_file_cache(&local_index, &file_cache).await;
                        let _ = app.emit(
                            "shared-files-changed",
                            serde_json::json!({ "phase": "hash-progress" }),
                        );
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
                    page_complete = false;
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
                Ok(Err(e)) => {
                    tracing::error!("Hash task panicked for {}: {e}", file.name);
                    page_complete = false;
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
                Err(_) => {
                    // Leave the pending entry so a later reload/retry can
                    // finish hashing; dropping it here made slow/cloud files
                    // disappear from the share list after one timeout.
                    warn!("Hash timed out after 5 min for {} (file may be on cloud storage or locked); leaving pending for retry", file.name);
                    page_complete = false;
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

        if !was_cancelled && page_complete {
            let mut cursor_update = std::collections::HashMap::new();
            cursor_update.insert(canonical_str.clone(), discovery_next_cursor);
            let app_state = app.state::<AppState>();
            if let Err(error) = persist_scan_cursors(&app_state, &cursor_update).await {
                warn!(
                    "Shared-folder page was indexed but its resume cursor was not saved: {error}"
                );
            }
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

        reconcile_shared_files_best_effort(&network_tx).await;
        if !was_cancelled {
            // known.met now owns the state of everything hashed this pass —
            // sweep any pending intents that were handed off (or left stale
            // by an earlier build/crash) so they can't re-apply on a rehash.
            let app_state = app.state::<AppState>();
            prune_pending_intents_for_hashed(&app_state).await;
        }
        remove_cancel_flag_if_current(&cancel_flags, &cancel_key, &cancel_flag).await;

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

/// Open a trusted native directory picker and add the selected folder.
///
/// The renderer never receives authority to submit an arbitrary path to the
/// sharing mutator: the only registered IPC command obtains its path directly
/// from the OS picker. The selected path is returned solely so the Library can
/// update its display; it cannot be replayed as authorization.
#[tauri::command]
pub async fn pick_shared_folder(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    state: tauri::State<'_, AppState>,
) -> Result<Option<String>, String> {
    if window.label() != "main" {
        return Err(coded(
            "sharing_picker_wrong_window",
            "Shared folders can only be selected from the main window",
        ));
    }
    let picker_app = app.clone();
    let selected = tokio::task::spawn_blocking(move || {
        picker_app
            .dialog()
            .file()
            .set_title("Choose a folder to share")
            .blocking_pick_folder()
            .map(|folder| {
                folder.into_path().map_err(|error| {
                    coded_ctx(
                        "sharing_invalid_picker_path",
                        "Invalid selected folder",
                        error,
                    )
                })
            })
            .transpose()
    })
    .await
    .map_err(|error| coded_ctx("sharing_picker_task_failed", "Folder picker failed", error))??;

    let Some(path) = selected else {
        return Ok(None);
    };
    let display_path = path.to_string_lossy().into_owned();
    add_shared_folder(app, state, display_path.clone()).await?;
    Ok(Some(display_path))
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
    // Canonicalize off the async runtime (blocking I/O on slow/network paths).
    // An unavailable USB/network root cannot canonicalize, but it still must
    // be removable. In that case only accept an exact normalized entry already
    // present in configuration; never fall back to an arbitrary raw path.
    let resolved_path = tokio::task::spawn_blocking({
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
    .map_err(|e| coded_ctx("sharing_task_failed", "Task failed", e))?;
    let canonical_path = match resolved_path {
        Ok(path) => path,
        Err(canonical_error) => {
            let config = state.config.read().await;
            config
                .settings
                .shared_folders
                .iter()
                .find(|configured| paths_equal_ignore_case(configured, &path))
                .cloned()
                .ok_or(canonical_error)?
        }
    };
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
        // Cancel only generations whose scan roots can write under the folder
        // being removed. Broad startup/reload generations are safely ordered by
        // `scan_coordination` and may not contain a recently added folder, so
        // leave them (and unrelated per-folder scans) running. Do not remove
        // entries here: each generation owns its flag and generation-aware
        // cleanup removes it only when the Arc still matches the map's current
        // value.
        for (scan_key, flag) in flags.iter() {
            if scan_can_write_under(scan_key, &canonical_path) {
                flag.store(true, Ordering::Relaxed);
            }
        }
    }
    // Persist the removal to disk before committing it in-memory or to the live
    // upload list, so a failed write can't drop a folder that's still saved.
    let settings_save_guard = state.settings_save_lock.lock().await;
    let save_data = {
        let config = state.config.read().await;
        let mut new_settings = config.settings.clone();
        new_settings
            .shared_folders
            .retain(|f| !paths_equal_ignore_case(f, &canonical_path));
        new_settings
            .folder_priorities
            .retain(|folder, _| !paths_equal_ignore_case(folder, &canonical_path));
        new_settings
            .pending_share_states
            .retain(|path, _| !crate::security::path_matches_dir(path, &canonical_path));
        new_settings
            .pending_file_priorities
            .retain(|path, _| !crate::security::path_matches_dir(path, &canonical_path));
        new_settings
            .shared_folder_scan_cursors
            .retain(|folder, _| !paths_equal_ignore_case(folder, &canonical_path));
        new_settings.settings_revision = config.settings.settings_revision.saturating_add(1);
        config
            .prepare_save_settings(&new_settings)
            .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?
    };
    let roots = {
        let config = state.config.read().await;
        let mut roots: Vec<String> = config
            .settings
            .shared_folders
            .iter()
            .filter(|root| !paths_equal_ignore_case(root, &canonical_path))
            .cloned()
            .collect();
        if !config.settings.download_folder.is_empty() {
            roots.push(config.settings.download_folder.clone());
        }
        roots
    };
    let registry = state.approved_roots.clone();
    let (data, tmp, final_path) = save_data;
    tokio::task::spawn_blocking(move || {
        super::settings::persist_with_root_transaction(registry, &roots, &[], || {
            crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
        })
    })
    .await
    .map_err(|e| coded_ctx("sharing_config_transaction_error", "Config save error", e))?
    .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?;
    {
        let mut config = state.config.write().await;
        config
            .settings
            .shared_folders
            .retain(|f| !paths_equal_ignore_case(f, &canonical_path));
        config
            .settings
            .folder_priorities
            .retain(|folder, _| !paths_equal_ignore_case(folder, &canonical_path));
        config
            .settings
            .pending_share_states
            .retain(|path, _| !crate::security::path_matches_dir(path, &canonical_path));
        config
            .settings
            .pending_file_priorities
            .retain(|path, _| !crate::security::path_matches_dir(path, &canonical_path));
        config
            .settings
            .shared_folder_scan_cursors
            .retain(|folder, _| !paths_equal_ignore_case(folder, &canonical_path));
        config.settings.settings_revision = config.settings.settings_revision.saturating_add(1);
    }
    drop(settings_save_guard);
    {
        let mut live = state.upload_shared_folders.write().await;
        live.retain(|f| !paths_equal_ignore_case(f, &canonical_path));
    }

    // Revocation above is intentionally ahead of this wait: a long-running
    // startup/reload scan must not leave the folder uploadable or media-
    // accessible while removal waits for its final index cleanup. Once the
    // existing generation yields, remove any rows it raced to add.
    let scan_coordination_guard = state.scan_coordination.lock().await;
    let removed_hashes = {
        let mut index = state.local_index.write().await;
        let hashes = fresh_part_hashes_exclusively_under_roots(
            index.all_files(),
            std::slice::from_ref(&canonical_path),
        );
        index.remove_files_by_path_prefix(&canonical_path);
        hashes
    };
    discard_fresh_part_hashes(&state.fresh_part_hashes, &removed_hashes).await;
    refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
    drop(scan_coordination_guard);

    // Stop watching the removed folder.
    if let Some(watcher) = state.shared_folder_watcher.as_ref() {
        let folders = state.config.read().await.settings.shared_folders.clone();
        watcher.sync_paths(&folders);
    }
    {
        let config = state.config.read().await;
        sync_asset_protocol_scope(&app, &config);
    }

    reconcile_shared_files_best_effort(&state.network_tx).await;
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

/// Count and total byte size of files the user is *actively sharing*
/// (the `shared` flag is set). Distinct from the total number of files
/// indexed in the library (which includes unshared files). Returns a
/// compact summary so the always-mounted status bar can show
/// "Files Shared N (size)" without shipping the whole `Vec<FileInfo>`
/// over IPC on every refresh.
#[derive(serde::Serialize)]
pub struct SharedFileStats {
    pub count: usize,
    pub total_bytes: u64,
}

#[tauri::command]
pub async fn get_shared_file_count(
    state: tauri::State<'_, AppState>,
) -> Result<SharedFileStats, String> {
    let cached = state.cached_shared_files.read().await;
    let mut count = 0usize;
    let mut total_bytes = 0u64;
    for f in cached.iter().filter(|f| f.shared) {
        count += 1;
        total_bytes = total_bytes.saturating_add(f.size);
    }
    Ok(SharedFileStats { count, total_bytes })
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
    let _single_flight = crate::security::try_begin_single_flight(&MEDIA_METADATA_IN_FLIGHT)
        .ok_or_else(|| {
            coded(
                "sharing_media_request_in_flight",
                "Another media metadata request is already running",
            )
        })?;
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
    let settings_save_guard = state.settings_save_lock.lock().await;
    let (new_settings, save_data) = {
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
        new_settings.settings_revision = config.settings.settings_revision.saturating_add(1);
        let save_data = config
            .prepare_save_settings(&new_settings)
            .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?;
        (new_settings, save_data)
    };

    // Clearing only stops the default from being re-applied; existing files
    // keep whatever priority they currently have.
    if clearing {
        let (data, tmp, final_path) = save_data;
        tokio::task::spawn_blocking(move || {
            crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
        })
        .await
        .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?
        .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))?;
        state.config.write().await.settings = new_settings;
        drop(settings_save_guard);
        info!("Cleared folder priority for {folder_path}");
        return Ok(0);
    }

    // Apply hash-wide file priorities first, but keep a complete snapshot so a
    // known.met or config write failure can restore both persistence domains.
    let (index_snapshot, changed) = {
        let mut index = state.local_index.write().await;
        let snapshot = index.all_files().to_vec();
        let changed = index.set_priority_under_folder(&folder_path, &priority);
        (snapshot, changed)
    };
    if !changed.is_empty() {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        let hashes = changed
            .iter()
            .map(|(_, hash)| hash.clone())
            .filter(|hash| !hash.is_empty())
            .collect::<Vec<_>>();
        if let Err(error) =
            persist_upload_priorities(&state.network_tx, &hashes, priority_str_to_u8(&priority))
                .await
        {
            rollback_index_mutation(&state, index_snapshot).await;
            return Err(error);
        }
    }

    let (data, tmp, final_path) = save_data;
    let config_result = tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
    })
    .await
    .map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))
    .and_then(|result| {
        result.map_err(|e| coded_ctx("sharing_config_save_error", "Config save error", e))
    });
    if let Err(error) = config_result {
        let rollback_result = persist_priority_snapshot(&state.network_tx, &index_snapshot).await;
        rollback_index_mutation(&state, index_snapshot).await;
        return match rollback_result {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(coded_ctx(
                "sharing_priority_rollback_failed",
                "Folder priority save and rollback both failed",
                format!("{error}; rollback: {rollback_error}"),
            )),
        };
    }
    state.config.write().await.settings = new_settings;
    drop(settings_save_guard);
    info!(
        "Set folder priority {priority} for {folder_path} ({} files)",
        changed.len()
    );
    Ok(changed.len() as u32)
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
    let (snapshot, changed, file_hash) = {
        let mut index = state.local_index.write().await;
        let snapshot = index.all_files().to_vec();
        if index.get_by_path(&file_path).is_none() {
            return Err(coded("sharing_file_not_found", "File not found"));
        }
        let changed = index.set_file_priority_by_path(&file_path, &priority);
        (
            snapshot,
            changed,
            index.get_by_path(&file_path).map(|f| f.hash.clone()),
        )
    };
    if !changed {
        return Ok(());
    }
    refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
    if let Some(hash) = file_hash.filter(|h| !h.is_empty()) {
        if let Err(e) =
            persist_upload_priorities(&state.network_tx, &[hash], priority_str_to_u8(&priority))
                .await
        {
            rollback_index_mutation(&state, snapshot).await;
            return Err(e);
        }
        // known.met now owns this priority — drop any intent recorded for the
        // path while it was still hashing, or a later rehash would revert the
        // user's choice. Best-effort: a stale entry is also swept by the
        // post-scan prune.
        if let Err(e) = persist_pending_intents(&state, &[], &[], &[], &[file_path.clone()]).await {
            warn!("Failed to clear pending priority intent for {file_path}: {e}");
        }
    } else {
        if let Err(e) = persist_pending_intents(
            &state,
            &[],
            &[(file_path.clone(), priority.clone())],
            &[],
            &[],
        )
        .await
        {
            rollback_index_mutation(&state, snapshot).await;
            return Err(e);
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
    check_path_batch(&file_paths, MAX_BATCH_IDS)?;
    let valid = ["verylow", "low", "normal", "high", "release", "auto"];
    if !valid.contains(&priority.as_str()) {
        return Err(coded_ctx(
            "sharing_invalid_priority",
            "Invalid priority",
            &priority,
        ));
    }
    let (snapshot, count, hashes, pending_updates, hashed_paths) = {
        let mut index = state.local_index.write().await;
        let snapshot = index.all_files().to_vec();
        let mut n = 0u32;
        let mut hashes = Vec::new();
        let mut pending_updates: Vec<(String, String)> = Vec::new();
        let mut hashed_paths: Vec<String> = Vec::new();
        for path in &file_paths {
            let changed_paths = index.set_file_priority_by_path_count(path, &priority);
            if changed_paths > 0 {
                n = n.saturating_add(changed_paths as u32);
                if let Some(f) = index.get_by_path(path) {
                    if !f.hash.is_empty() {
                        hashes.push(f.hash.clone());
                        hashed_paths.push(path.clone());
                    } else {
                        // Still hashing: record the choice as a pending
                        // intent so it survives a restart, mirroring
                        // `set_file_priority`.
                        pending_updates.push((path.clone(), priority.clone()));
                    }
                }
            }
        }
        (snapshot, n, hashes, pending_updates, hashed_paths)
    };
    if count > 0 {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        if let Err(e) =
            persist_upload_priorities(&state.network_tx, &hashes, priority_str_to_u8(&priority))
                .await
        {
            rollback_index_mutation(&state, snapshot).await;
            return Err(e);
        }
        if let Err(e) =
            persist_pending_intents(&state, &[], &pending_updates, &[], &hashed_paths).await
        {
            rollback_index_mutation(&state, snapshot).await;
            return Err(e);
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
    check_path_batch(&file_paths, MAX_BATCH_IDS)?;
    let (snapshot, mutation) = {
        let mut index = state.local_index.write().await;
        let snapshot = index.all_files().to_vec();
        let mutation = index.set_shared_by_paths(&file_paths, true);
        (snapshot, mutation)
    };
    let count = mutation.changed_paths as u32;
    if count > 0 {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        persist_share_mutation(&state, &mutation, true, snapshot).await?;
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
    check_path_batch(&file_paths, MAX_BATCH_IDS)?;
    let (snapshot, mutation) = {
        let mut index = state.local_index.write().await;
        let snapshot = index.all_files().to_vec();
        let mutation = index.set_shared_by_paths(&file_paths, false);
        (snapshot, mutation)
    };
    let count = mutation.changed_paths as u32;
    if count > 0 {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        persist_share_mutation(&state, &mutation, false, snapshot).await?;
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
    let reload_flight =
        crate::security::try_begin_single_flight(&RELOAD_IN_FLIGHT).ok_or_else(|| {
            coded(
                "sharing_reload_in_flight",
                "A shared-file reload is already running",
            )
        })?;
    // Manual reload / resume always clear the pause latch. The FS watcher
    // never reaches this path while paused (it checks hashing_paused first).
    state.hashing_paused.store(false, Ordering::Relaxed);
    state.hashing_fs_dirty.store(false, Ordering::Relaxed);
    state.library_scan_truncated.store(false, Ordering::Relaxed);

    let (folders, scan_cursors) = {
        let config = state.config.read().await;
        (
            config.settings.shared_folders.clone(),
            config.settings.shared_folder_scan_cursors.clone(),
        )
    };

    let local_index = state.local_index.clone();
    let file_cache = state.cached_shared_files.clone();
    let network_tx = state.network_tx.clone();
    let scanning = state.scanning_count.clone();
    let scan_coordination = state.scan_coordination.clone();
    let cancel_flags = state.hash_cancel_flags.clone();
    let fresh_part_hashes = state.fresh_part_hashes.clone();
    let config = state.config.clone();
    let scan_truncated = state.library_scan_truncated.clone();
    let discovery_folders = folders.clone();
    let discovery_cursors = scan_cursors;

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
        let _reload_flight = reload_flight;
        let _coordination_guard = scan_coordination.lock().await;
        scanning.fetch_add(1, Ordering::Relaxed);
        let _scan_guard = ScanGuard(scanning.clone());

        let (mut discovered, discovery_truncated, discovery_cursor_updates): (
            Vec<FileInfo>,
            bool,
            std::collections::HashMap<String, Option<String>>,
        ) = match tokio::task::spawn_blocking(move || {
            let mut files = Vec::new();
            let mut truncated = false;
            let mut cursor_updates = std::collections::HashMap::new();
            for folder in &discovery_folders {
                let key = crate::search::index::normalize_path_key(folder);
                let result = FileIndexer::discover_directory_page(
                    folder,
                    discovery_cursors.get(&key).map(String::as_str),
                );
                truncated |= result.truncated;
                cursor_updates.insert(folder.clone(), result.next_cursor);
                files.extend(result.files);
            }
            (files, truncated, cursor_updates)
        })
        .await
        {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Reload discovery failed: {e}");
                remove_cancel_flag_if_current(&cancel_flags, &reload_key, &cancel_flag).await;
                return;
            }
        };
        if discovery_truncated {
            warn!(
                "Reload discovery reached the per-folder file cap; retaining existing entries not seen in this partial scan"
            );
            scan_truncated.store(true, Ordering::Relaxed);
            let _ = app.emit(
                "shared-files-scan-truncated",
                serde_json::json!({ "folders": folders, "limit": 100_000 }),
            );
        }

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
            remove_cancel_flag_if_current(&cancel_flags, &reload_key, &cancel_flag).await;
            let _ = app.emit(
                "file-hash-progress",
                serde_json::json!({ "done": true, "current": 0, "total": 0, "file_name": "" }),
            );
            return;
        }

        let known_list = load_known_files();
        let mut files_to_hash = resolve_from_known(&mut discovered, &known_list);
        let (folder_priorities, pending_share_states, pending_file_priorities) = {
            let cfg = config.read().await;
            (
                cfg.settings.folder_priorities.clone(),
                cfg.settings.pending_share_states.clone(),
                cfg.settings.pending_file_priorities.clone(),
            )
        };
        apply_folder_defaults_to_new_files(&mut discovered, &mut files_to_hash, &folder_priorities);
        apply_pending_intents(
            &mut discovered,
            &mut files_to_hash,
            &pending_share_states,
            &pending_file_priorities,
        );

        let removed_fresh_hashes = {
            let mut index = local_index.write().await;
            let before = (!discovery_truncated).then(|| index.all_files().to_vec());
            index.reconcile_files_for_folders(&reloaded_folders, discovered, !discovery_truncated);
            before
                .as_deref()
                .map(|before| {
                    fresh_part_hashes_removed_by_reload(
                        before,
                        index.all_files(),
                        &reloaded_folders,
                    )
                })
                .unwrap_or_default()
        };
        discard_fresh_part_hashes(&fresh_part_hashes, &removed_fresh_hashes).await;
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
        let mut page_complete = true;

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
                Ok(Ok(Ok((
                    ed2k_hash,
                    aich_hash,
                    part_hashes,
                    ember_file_hash,
                    hashed_size,
                    hashed_modified_at,
                )))) => {
                    debug!(
                        "Reload hash complete: {} -> {}",
                        file.name,
                        &ed2k_hash[..ed2k_hash.len().min(8)]
                    );
                    let mut updated_file = file.clone();
                    updated_file.id = ed2k_hash.clone();
                    updated_file.hash = ed2k_hash;
                    updated_file.aich_hash = aich_hash;
                    updated_file.ember_file_hash = ember_file_hash;
                    updated_file.size = hashed_size;
                    updated_file.modified_at = hashed_modified_at;
                    if let Ok(bytes) = hex::decode(&updated_file.hash) {
                        if bytes.len() == 16 {
                            let mut hash = [0u8; 16];
                            hash.copy_from_slice(&bytes);
                            updated_file.shared = crate::storage::share_intent::effective_shared(
                                &hash,
                                updated_file.shared,
                            );
                        }
                    }

                    let still_shared = {
                        let cfg = config.read().await;
                        file_in_shared_folders(&updated_file.path, &cfg.settings.shared_folders)
                    };
                    // Keep the computed hashes only if this scan commits the
                    // completed row. Cancellation removes the pending row, so
                    // an earlier cache insert would be orphaned.
                    let fresh_handoff = still_shared
                        .then(|| fresh_part_hash_handoff(&updated_file.hash, part_hashes))
                        .flatten();
                    let finalized = {
                        let mut index = local_index.write().await;
                        if !cancel_flag.load(Ordering::Relaxed) && still_shared {
                            // The current pending row is authoritative for
                            // user-controlled share state and priority.
                            index
                                .finalize_pending_hash(&file_temp_id, updated_file.clone())
                                .is_some()
                        } else {
                            index.remove_file_by_id(&file_temp_id);
                            false
                        }
                    };
                    cache_fresh_part_hash_handoff(&fresh_part_hashes, finalized, fresh_handoff)
                        .await;

                    if !cancel_flag.load(Ordering::Relaxed) && still_shared {
                        hashed_count += 1;
                    }
                    if !cancel_flag.load(Ordering::Relaxed)
                        && still_shared
                        && last_cache_refresh.elapsed() >= std::time::Duration::from_secs(5)
                    {
                        refresh_file_cache(&local_index, &file_cache).await;
                        let _ = app.emit(
                            "shared-files-changed",
                            serde_json::json!({ "phase": "hash-progress" }),
                        );
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
                    page_complete = false;
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
                Ok(Err(e)) => {
                    tracing::error!("Hash task panicked for {}: {e}", file.name);
                    page_complete = false;
                    let mut index = local_index.write().await;
                    index.remove_file_by_id(&file_temp_id);
                }
                Err(_) => {
                    // Leave the pending entry so a later reload/retry can
                    // finish hashing; dropping it here made slow/cloud files
                    // disappear from the share list after one timeout.
                    warn!("Hash timed out after 5 min for {} (file may be on cloud storage or locked); leaving pending for retry", file.name);
                    page_complete = false;
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

        if !was_cancelled && page_complete {
            let cursor_updates = discovery_cursor_updates
                .into_iter()
                .filter(|(folder, _)| {
                    reloaded_folders
                        .iter()
                        .any(|active| paths_equal_ignore_case(active, folder))
                })
                .collect::<std::collections::HashMap<_, _>>();
            let app_state = app.state::<AppState>();
            if let Err(error) = persist_scan_cursors(&app_state, &cursor_updates).await {
                warn!("Shared-folder scan page was indexed but its resume cursor was not saved: {error}");
            }
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

        reconcile_shared_files_best_effort(&network_tx).await;
        if !was_cancelled {
            // Same post-pass intent sweep as the folder-add scan above.
            let app_state = app.state::<AppState>();
            prune_pending_intents_for_hashed(&app_state).await;
        }
        remove_cancel_flag_if_current(&cancel_flags, &reload_key, &cancel_flag).await;

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
pub async fn get_library_scan_truncated(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    Ok(state.library_scan_truncated.load(Ordering::Relaxed))
}

#[tauri::command]
pub async fn stop_hashing(state: tauri::State<'_, AppState>) -> Result<Vec<String>, String> {
    // Latch pause before signalling cancel so a concurrent FS-watcher tick
    // cannot start a new reload that races past the cancel flags.
    state.hashing_paused.store(true, Ordering::Relaxed);

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
    let (snapshot, mutation) = {
        let mut index = state.local_index.write().await;
        if index.get_by_path(&file_path).is_none() {
            // Surface a desync instead of silently reporting success: the UI
            // asked to unshare a path the backend index doesn't know about.
            return Err(coded(
                "sharing_file_not_in_index",
                "File not found in shared index",
            ));
        }
        let snapshot = index.all_files().to_vec();
        let mutation = index.set_file_shared_by_path(&file_path, false);
        (snapshot, mutation)
    };
    if mutation.changed_paths > 0 {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        persist_share_mutation(&state, &mutation, false, snapshot).await?;
        let _ = app.emit(
            "shared-files-changed",
            serde_json::json!({ "unshared": mutation.changed_paths }),
        );
        info!(
            "Unshared {} file path(s) from {}{}",
            mutation.changed_paths,
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
    let (snapshot, mutation) = {
        let mut index = state.local_index.write().await;
        if index.get_by_path(&file_path).is_none() {
            // Surface a desync instead of silently reporting success: the UI
            // asked to share a path the backend index doesn't know about.
            return Err(coded(
                "sharing_file_not_in_index",
                "File not found in shared index",
            ));
        }
        if index
            .get_by_path(&file_path)
            .is_some_and(|file| file.hash.is_empty())
        {
            return Err(coded(
                "sharing_file_hash_pending",
                "File is still hashing and cannot be shared individually",
            ));
        }
        let snapshot = index.all_files().to_vec();
        let mutation = index.set_file_shared_by_path(&file_path, true);
        (snapshot, mutation)
    };
    if mutation.changed_paths > 0 {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        persist_share_mutation(&state, &mutation, true, snapshot).await?;
        let _ = app.emit(
            "shared-files-changed",
            serde_json::json!({ "shared": mutation.changed_paths }),
        );
        info!(
            "Shared {} file path(s) from {}",
            mutation.changed_paths, file_path
        );
    }
    Ok(())
}

#[tauri::command]
pub async fn unshare_folder(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<(), String> {
    let (snapshot, mutation) = {
        let mut index = state.local_index.write().await;
        let snapshot = index.all_files().to_vec();
        let mutation = index.set_shared_by_path_prefix(&path, false);
        (snapshot, mutation)
    };
    if mutation.changed_paths > 0 {
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        persist_share_mutation(&state, &mutation, false, snapshot).await?;
        let _ = app.emit(
            "shared-files-changed",
            serde_json::json!({
                "folder": path,
                "unshared": mutation.changed_paths,
            }),
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
    // This command is the Library's destructive action. Do not let its broad
    // shared/download containment scope become a generic delete primitive for
    // active `.part` files or any other unindexed download.
    let indexed_path = {
        let index = state.local_index.read().await;
        index
            .get_by_path(&file_path)
            .map(|file| file.path.clone())
            .ok_or_else(|| {
                coded(
                    "sharing_file_not_in_index",
                    "File is not in the shared-file index",
                )
            })?
    };
    let allowed_dirs = {
        let config = state.config.read().await;
        shared_access_dirs(&config)
    };

    let (canonical, expected_identity) = tokio::task::spawn_blocking({
        let file_path = file_path.clone();
        let indexed_path = indexed_path.clone();
        let allowed_dirs = allowed_dirs.clone();
        move || -> Result<
            (
                std::path::PathBuf,
                crate::security::filesystem::ObjectIdentity,
            ),
            String,
        > {
            let path = std::path::Path::new(&file_path);
            let (canonical, opened) =
                crate::security::filesystem::open_existing_approved(path, &allowed_dirs, false)
                    .map_err(|e| {
                        coded_ctx("sharing_invalid_path", "Invalid or changed path", e)
                    })?;
            let indexed_canonical = crate::security::filesystem::verify_existing_path(
                std::path::Path::new(&indexed_path),
                &allowed_dirs,
            )
            .map_err(|e| {
                coded_ctx(
                    "sharing_file_not_in_index",
                    "Indexed file can no longer be resolved",
                    e,
                )
            })?;
            if canonical != indexed_canonical {
                return Err(coded(
                    "sharing_file_not_in_index",
                    "File is not the indexed Library entry",
                ));
            }
            let identity = crate::security::filesystem::opened_file_identity(&opened)
                .map_err(|e| coded_ctx("sharing_invalid_path", "Invalid or changed path", e))?;
            Ok((canonical, identity))
        }
    })
    .await
    .map_err(|e| coded_ctx("sharing_task_failed", "Task failed", e))??;

    delete_file_with_retry(&canonical, &allowed_dirs, &expected_identity, 6, 250).await?;

    let canonical_str = canonical.to_string_lossy().to_string();
    let (removed, removed_hashes) = {
        let mut index = state.local_index.write().await;
        let removed = index
            .remove_file_by_path(&canonical_str)
            .or_else(|| index.remove_file_by_path(&file_path));
        let hashes = removed
            .as_ref()
            .and_then(|file| fresh_part_hash_key(&file.hash))
            .into_iter()
            .collect::<HashSet<_>>();
        let hashes = unreferenced_fresh_part_hashes(index.all_files(), &hashes);
        (removed, hashes)
    };
    discard_fresh_part_hashes(&state.fresh_part_hashes, &removed_hashes).await;
    refresh_file_cache(&state.local_index, &state.cached_shared_files).await;

    reconcile_shared_files_best_effort(&state.network_tx).await;
    let _ = app.emit(
        "shared-files-changed",
        serde_json::json!({ "file_deleted": true }),
    );

    info!(
        "Deleted shared file {}{}{}",
        canonical.display(),
        if removed.is_none() {
            " (index race)"
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
///
/// `paths` is capped at [`MAX_SCAN_MISSING_RESULTS`]; when the cap is hit,
/// `truncated` is true and `total_missing` still reflects the full count so
/// the UI can warn instead of silently under-counting.
#[tauri::command]
pub async fn scan_missing_files(
    state: tauri::State<'_, AppState>,
) -> Result<MissingScanResult, String> {
    let paths: Vec<String> = {
        let index = state.local_index.read().await;
        index.all_files().iter().map(|f| f.path.clone()).collect()
    };
    let result = tokio::task::spawn_blocking(move || {
        let mut missing = Vec::new();
        let mut total_missing: u32 = 0;
        for p in paths {
            if !std::path::Path::new(&p).exists() {
                total_missing = total_missing.saturating_add(1);
                if missing.len() < MAX_SCAN_MISSING_RESULTS {
                    missing.push(p);
                }
            }
        }
        MissingScanResult {
            truncated: (total_missing as usize) > missing.len(),
            total_missing,
            paths: missing,
        }
    })
    .await
    .map_err(|e| coded_ctx("sharing_scan_task_failed", "Scan task failed", e))?;
    Ok(result)
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
    check_path_batch(&paths, MAX_REMOVE_MISSING_PATHS)?;
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

    let (removed, removed_hashes) = {
        let mut removed = 0u32;
        let mut removed_hashes = HashSet::new();
        let mut index = state.local_index.write().await;
        for path in &really_missing {
            if let Some(file) = index.remove_file_by_path(path) {
                removed += 1;
                if let Some(hash) = fresh_part_hash_key(&file.hash) {
                    removed_hashes.insert(hash);
                }
            }
        }
        let removed_hashes = unreferenced_fresh_part_hashes(index.all_files(), &removed_hashes);
        (removed, removed_hashes)
    };
    if removed > 0 {
        discard_fresh_part_hashes(&state.fresh_part_hashes, &removed_hashes).await;
        refresh_file_cache(&state.local_index, &state.cached_shared_files).await;
        reconcile_shared_files_best_effort(&state.network_tx).await;
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
    let (declared_name, indexed_path) = {
        let index = state.local_index.read().await;
        let file = index.get_by_path(&file_path).ok_or_else(|| {
            coded(
                "sharing_file_not_in_index",
                "File is not in the shared-file index",
            )
        })?;
        (file.name.clone(), file.path.clone())
    };

    tokio::task::spawn_blocking(move || {
        let path = std::path::Path::new(&file_path);
        if !path.exists() {
            return Err(coded("sharing_file_not_exist", "File does not exist"));
        }
        let canonical = crate::security::filesystem::verify_existing_path(path, &allowed_dirs)
            .map_err(|e| coded_ctx("sharing_invalid_path", "Invalid or changed path", e))?;
        let indexed_canonical = crate::security::filesystem::verify_existing_path(
            std::path::Path::new(&indexed_path),
            &allowed_dirs,
        )
        .map_err(|e| coded_ctx("sharing_file_not_in_index", "Indexed path changed", e))?;
        if canonical != indexed_canonical {
            return Err(coded(
                "sharing_file_not_in_index",
                "File is not the indexed Library entry",
            ));
        }
        if crate::security::filesystem::passive_type_agrees(&declared_name, &canonical) {
            opener::open(&canonical)
                .map_err(|e| coded_ctx("sharing_open_file_failed", "Failed to open file", e))?;
        } else {
            crate::security::filesystem::reveal_in_file_manager(&canonical).map_err(|e| {
                coded_ctx(
                    "sharing_reveal_unsafe_file_failed",
                    "This file type was revealed instead of opened",
                    e,
                )
            })?;
        }
        Ok(())
    })
    .await
    .map_err(|e| coded_ctx("sharing_task_failed", "Task failed", e))?
}

/// Validate that `file_path` is a real file inside a shared/download folder and
/// return its canonical path for `convertFileSrc` / in-app media playback.
#[tauri::command]
pub async fn resolve_media_asset_path(
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<String, String> {
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
        if !path.is_file() {
            return Err(coded("sharing_not_a_file", "Path is not a file"));
        }
        let canonical = crate::security::filesystem::verify_existing_path(path, &allowed_dirs)
            .map_err(|e| coded_ctx("sharing_invalid_path", "Invalid or changed path", e))?;
        if !crate::security::filesystem::passive_type_agrees(&file_path, &canonical) {
            return Err(coded(
                "sharing_dangerous_file",
                "File type is not approved for in-app media",
            ));
        }
        Ok(canonical.to_string_lossy().into_owned())
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
        let canonical = crate::security::filesystem::verify_existing_path(folder, &allowed_dirs)
            .map_err(|e| coded_ctx("sharing_invalid_path", "Invalid or changed path", e))?;
        crate::security::filesystem::reveal_in_file_manager(&canonical)
            .map_err(|e| coded_ctx("sharing_open_folder_failed", "Failed to open folder", e))?;
        Ok(())
    })
    .await
    .map_err(|e| coded_ctx("sharing_task_failed", "Task failed", e))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn indexed_file(path: &str, hash: &str) -> FileInfo {
        FileInfo {
            id: hash.to_string(),
            name: "file.bin".to_string(),
            path: path.to_string(),
            size: 1,
            hash: hash.to_string(),
            aich_hash: String::new(),
            ember_file_hash: String::new(),
            extension: "bin".to_string(),
            modified_at: 0,
            priority: "normal".to_string(),
            requests: 0,
            accepted: 0,
            bytes_transferred: 0,
            alltime_requests: 0,
            alltime_accepted: 0,
            alltime_transferred: 0,
            complete_sources: 0,
            folder: String::new(),
            shared: true,
            shared_kad: false,
            shared_ed2k: false,
        }
    }

    #[tokio::test]
    async fn cancelled_finalization_does_not_cache_fresh_handoff() {
        let fresh_part_hashes = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let hash = "11".repeat(16);
        let handoff = fresh_part_hash_handoff(&hash, vec![[0xA1; 16]]);

        cache_fresh_part_hash_handoff(&fresh_part_hashes, false, handoff).await;

        assert!(fresh_part_hashes.read().await.is_empty());
    }

    #[tokio::test]
    async fn folder_removal_discards_fresh_part_hash_handoffs() {
        let removed_hash = [0x11; 16];
        let retained_hash = [0x22; 16];
        let fresh_part_hashes = Arc::new(RwLock::new(std::collections::HashMap::from([
            (removed_hash, vec![[0xA1; 16]]),
            (retained_hash, vec![[0xB2; 16]]),
        ])));
        let removed = HashSet::from([removed_hash]);

        discard_fresh_part_hashes(&fresh_part_hashes, &removed).await;

        let fresh = fresh_part_hashes.read().await;
        assert!(!fresh.contains_key(&removed_hash));
        assert_eq!(fresh.get(&retained_hash), Some(&vec![[0xB2; 16]]));
    }

    #[test]
    fn folder_removal_keeps_handoff_still_referenced_by_another_root() {
        let duplicate_hash = "11".repeat(16);
        let removed_only_hash = "22".repeat(16);
        let files = vec![
            indexed_file("/shares/removed/duplicate.bin", &duplicate_hash),
            indexed_file("/shares/retained/duplicate.bin", &duplicate_hash),
            indexed_file("/shares/removed/only.bin", &removed_only_hash),
        ];
        let roots = vec!["/shares/removed".to_string()];

        let discard = fresh_part_hashes_exclusively_under_roots(&files, &roots);

        assert!(!discard.contains(&fresh_part_hash_key(&duplicate_hash).unwrap()));
        assert!(discard.contains(&fresh_part_hash_key(&removed_only_hash).unwrap()));
    }

    #[test]
    fn file_removal_keeps_handoff_still_referenced_by_duplicate() {
        let duplicate_hash = "11".repeat(16);
        let removed_only_hash = "22".repeat(16);
        let candidates = HashSet::from([
            fresh_part_hash_key(&duplicate_hash).unwrap(),
            fresh_part_hash_key(&removed_only_hash).unwrap(),
        ]);
        let remaining = vec![indexed_file(
            "/shares/retained/duplicate.bin",
            &duplicate_hash,
        )];

        let discard = unreferenced_fresh_part_hashes(&remaining, &candidates);

        assert!(!discard.contains(&fresh_part_hash_key(&duplicate_hash).unwrap()));
        assert!(discard.contains(&fresh_part_hash_key(&removed_only_hash).unwrap()));
    }

    #[test]
    fn reload_pruning_discards_only_hashes_no_longer_indexed() {
        let duplicate_hash = "11".repeat(16);
        let removed_only_hash = "22".repeat(16);
        let before = vec![
            indexed_file("/shares/reload/duplicate.bin", &duplicate_hash),
            indexed_file("/shares/reload/gone.bin", &removed_only_hash),
        ];
        let after = vec![indexed_file("/shares/other/duplicate.bin", &duplicate_hash)];
        let folders = vec!["/shares/reload".to_string()];

        let discard = fresh_part_hashes_removed_by_reload(&before, &after, &folders);

        assert!(!discard.contains(&fresh_part_hash_key(&duplicate_hash).unwrap()));
        assert!(discard.contains(&fresh_part_hash_key(&removed_only_hash).unwrap()));
    }

    #[test]
    fn delayed_root_reconciliation_keeps_root_readded_by_newer_save() {
        let removed = vec!["/shares/readded".to_string()];
        let added = Vec::new();
        let active = vec!["/shares/readded".to_string()];

        let (effective_removed, effective_added) =
            effective_shared_root_changes(&removed, &added, &active);

        assert!(effective_removed.is_empty());
        assert!(effective_added.is_empty());
    }

    #[test]
    fn zero_length_suffix_media_range_is_rejected() {
        assert_eq!(parse_single_range(Some("bytes=-0"), 1024), Err(()));
        assert_eq!(
            parse_single_range(Some("bytes=-1"), 1024),
            Ok(Some((1023, 1023)))
        );
    }

    #[test]
    fn path_batches_enforce_count_item_and_aggregate_byte_caps() {
        assert!(check_path_batch(&["a".into(), "b".into()], 2).is_ok());
        assert!(check_path_batch(&["a".into(), "b".into()], 1).is_err());
        assert!(check_path_batch(&["x".repeat(MAX_PATH_LEN + 1)], 1).is_err());
        let many = vec!["x".repeat(MAX_PATH_LEN); MAX_BATCH_PATH_BYTES / MAX_PATH_LEN + 1];
        assert!(check_path_batch(&many, many.len()).is_err());
    }
}
