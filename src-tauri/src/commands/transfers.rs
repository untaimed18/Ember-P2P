use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tauri::Emitter;

use crate::app_state::AppState;
use crate::commands::errors::{await_reply, bounded_send, coded, coded_ctx, CMD_REPLY_TIMEOUT};
use crate::network::ed2k::transfer::TransferFailureCode;
use crate::network::NetworkCommand;
use crate::sharing::manager::TransferControl;
use crate::storage::database::Database;
use crate::types::*;

/// One safety budget shared by every download admission path.
pub(crate) const MAX_PENDING_DOWNLOADS: usize = 10_000;
pub(crate) const MAX_PENDING_REMAINING_BYTES: u64 = 64 * 1024 * 1024 * 1024 * 1024;

fn budget_allows(current_count: usize, current_remaining: u64, additions: &[u64]) -> bool {
    current_count.saturating_add(additions.len()) <= MAX_PENDING_DOWNLOADS
        && current_remaining
            .saturating_add(additions.iter().copied().fold(0u64, u64::saturating_add))
            <= MAX_PENDING_REMAINING_BYTES
}

pub(crate) fn pending_download_usage(
    manager: &crate::sharing::manager::TransferManager,
) -> (usize, u64) {
    manager
        .active
        .values()
        .chain(manager.queue.iter())
        .filter(|transfer| transfer.direction == TransferDirection::Download)
        .fold((0usize, 0u64), |(count, bytes), transfer| {
            // `completed_size` only. `transferred` is now cumulative wire bytes and
            // can exceed the file size after a re-fetch, so folding it in with
            // `max` would report a download as further along than it is and shrink
            // the disk space this budget is reserving for it.
            let completed = transfer.completed_size;
            (
                count.saturating_add(1),
                bytes.saturating_add(transfer.total_size.saturating_sub(completed)),
            )
        })
}

pub(crate) fn ensure_pending_download_budget(
    manager: &crate::sharing::manager::TransferManager,
    additions: &[u64],
) -> Result<(), String> {
    let (count, remaining) = pending_download_usage(manager);
    if budget_allows(count, remaining, additions) {
        return Ok(());
    }
    Err(coded_ctx(
        "transfers_pending_budget_exceeded",
        "Pending download safety budget exceeded",
        format!(
            "max {MAX_PENDING_DOWNLOADS} rows and {MAX_PENDING_REMAINING_BYTES} aggregate remaining bytes"
        ),
    ))
}

async fn db_blocking<F>(f: F)
where
    F: FnOnce() + Send + 'static,
{
    if let Err(e) = tokio::task::spawn_blocking(f).await {
        tracing::warn!("DB task failed: {e}");
    }
}

fn parse_peer_ip(peer_id: &str) -> String {
    if let Ok(addr) = peer_id.parse::<std::net::SocketAddr>() {
        return addr.ip().to_string();
    }
    peer_id
        .rsplit_once(':')
        .map(|(ip, _)| ip.to_string())
        .unwrap_or_default()
}

fn parse_peer_port(peer_id: &str) -> u16 {
    if let Ok(addr) = peer_id.parse::<std::net::SocketAddr>() {
        return addr.port();
    }
    peer_id
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
        .unwrap_or(0)
}

fn transfer_status_key(status: &TransferStatus) -> &'static str {
    match status {
        TransferStatus::Searching => "searching",
        TransferStatus::Queued => "queued",
        TransferStatus::Active => "active",
        TransferStatus::Paused => "paused",
        TransferStatus::Stopped => "stopped",
        TransferStatus::Verifying => "verifying",
        TransferStatus::Completing => "completing",
        TransferStatus::Completed => "completed",
        TransferStatus::Failed => "failed",
        TransferStatus::Hashing => "hashing",
        TransferStatus::Insufficient => "insufficient",
        TransferStatus::NoneNeeded => "noneneeded",
    }
}

/// Emit a `transfer-status` event so the UI reflects a status change
/// immediately, mirroring eMule's synchronous `NotifyStatusChange()` +
/// `UpdateDisplayedInfo()`. Without it the row only updates on the next ~3 s
/// poll, and (before the frontend merge fix) a resumed download could stay
/// visually stuck on Paused/Stopped. Also reused by the network loop to
/// announce queued→active/searching promotions in real time.
pub(crate) fn emit_transfer_status(
    app: &tauri::AppHandle,
    transfer_id: &str,
    status: &TransferStatus,
) {
    let _ = app.emit(
        "transfer-status",
        serde_json::json!({
            "id": transfer_id,
            "status": transfer_status_key(status),
        }),
    );
}

/// One `transfer-status-batch` event for a batch command instead of a
/// `transfer-status` per row. Carries the same `{id, status}` items.
pub(crate) fn emit_transfer_statuses(app: &tauri::AppHandle, statuses: &[(String, TransferStatus)]) {
    if statuses.is_empty() {
        return;
    }
    let items: Vec<serde_json::Value> = statuses
        .iter()
        .map(|(id, status)| {
            serde_json::json!({
                "id": id,
                "status": transfer_status_key(status),
            })
        })
        .collect();
    let _ = app.emit(
        "transfer-status-batch",
        serde_json::json!({ "items": items }),
    );
}

/// Persist a transfer before exposing it to the network worker or UI.
///
/// A transfer without a durable row is unsafe to start: after a restart the
/// orphan sweep cannot distinguish its partial files from abandoned ones.
pub(crate) async fn persist_transfer(state: &AppState, transfer: &Transfer) -> Result<(), String> {
    let db = state.db.clone();
    let short_id = transfer_id_short(&transfer.id).to_string();
    let transfer = transfer.clone();
    tokio::task::spawn_blocking(move || db.save_transfer(&transfer))
        .await
        .map_err(|e| {
            tracing::warn!("Transfer persist task failed for {short_id}: {e}");
            format!("Transfer persistence task failed: {e}")
        })?
        .map_err(|e| {
            tracing::warn!("Failed to persist transfer {short_id}: {e}");
            format!("Failed to persist transfer: {e}")
        })
}

fn transfer_id_short(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

/// The eD2K download transport is IPv4-only. Normalize IPv4-mapped IPv6
/// literals for callers that serialize socket addresses generically, but fail
/// before admission for a pure IPv6 source rather than enqueueing an
/// undialable transfer.
fn normalize_primary_peer_ip(peer_ip: String) -> Result<String, String> {
    if peer_ip.is_empty() {
        return Ok(peer_ip);
    }
    match peer_ip
        .parse::<std::net::IpAddr>()
        .map_err(|_| coded("transfers_invalid_peer_ip", "Invalid peer IP"))?
    {
        std::net::IpAddr::V4(ip) => Ok(ip.to_string()),
        std::net::IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(|mapped| mapped.to_string())
            .ok_or_else(|| {
                coded(
                    "transfers_invalid_peer_ip",
                    "IPv6 primary sources are not supported",
                )
            }),
    }
}

/// Remove a transfer that was admitted in memory but could not be made
/// durable. No network work has started for this transfer yet, so cancelling
/// it is safe; any newly eligible queued downloads are promoted immediately.
async fn rollback_unpersisted_transfer(state: &AppState, transfer_id: &str) {
    let promoted = {
        let mut manager = state.transfer_manager.write().await;
        manager.remove(transfer_id)
    };
    if !promoted.is_empty() {
        start_promoted_downloads(state, &promoted).await;
    }
}

fn verify_recovery_ranges(
    part_path: &std::path::Path,
    file_size: u64,
    allowed_roots: &[String],
    expected_file_hash: [u8; 16],
    transfer_control: Option<&TransferControl>,
    cancellation: &std::sync::atomic::AtomicBool,
) -> anyhow::Result<Vec<(u64, u64)>> {
    use md4::{Digest, Md4};
    use std::io::{Read, Seek};

    let is_cancelled = || {
        cancellation.load(std::sync::atomic::Ordering::Acquire)
            || transfer_control.is_some_and(TransferControl::is_cancelled)
    };
    if is_cancelled() {
        anyhow::bail!("archive recovery cancelled");
    }

    // A `.part.met` is not authenticated, and `PartTracker::new` deliberately
    // adopts whatever ed2k hash the sidecar carries — which meant this function
    // took both the part hashes and the verified bitmap from the same
    // unvalidated file it was supposed to be checking, and `expected_file_hash`
    // only mattered on the single-part branch below. A stale, hand-moved or
    // tampered sidecar could therefore have `.part` content "verified" against
    // its own hashes, and archive recovery would extract from ranges never tied
    // to the file the user asked for.
    //
    // `new_with_identity` refuses a sidecar whose hash disagrees with the
    // caller's file (and takes it at construction time, because a later
    // `set_file_hash` would hide the mismatch), and `verify_hashset` binds the
    // hashset itself back to that hash — so a forged hashset carrying the right
    // file hash cannot pass either. With no trustworthy hashset we fall through
    // to the single-part branch, which demands a full file-level ed2k match.
    let tracker = crate::network::ed2k::part_tracker::PartTracker::new_with_identity(
        file_size,
        part_path,
        expected_file_hash,
    );
    let flags = tracker.verified_parts();
    let hashes: &[[u8; 16]] = if crate::network::ed2k::transfer::verify_hashset(
        &expected_file_hash,
        tracker.part_hashes(),
        file_size,
    ) {
        tracker.part_hashes()
    } else {
        &[]
    };
    // Pin the .part through the approved Temp parent so a symlink swap after
    // verify_existing_path cannot redirect recovery reads.
    let (_, mut file) =
        crate::security::filesystem::open_existing_approved(part_path, allowed_roots, false)?;
    let mut ranges = Vec::new();
    for (index, verified) in flags.into_iter().enumerate() {
        if is_cancelled() {
            anyhow::bail!("archive recovery cancelled");
        }
        if !verified {
            continue;
        }
        let start = index as u64 * crate::network::ed2k::hash::PARTSIZE;
        let end = (start + crate::network::ed2k::hash::PARTSIZE).min(file_size);
        let Some(expected) = hashes.get(index) else {
            // A single-part transfer can have no hashset. Only accept its
            // range after a complete file-level ED2K verification.
            if index == 0
                && end == file_size
                && crate::network::ed2k::hash::ed2k_hash_open_file(&mut file)?
                    == hex::encode(expected_file_hash)
            {
                ranges.push((start, end));
            }
            continue;
        };
        file.seek(std::io::SeekFrom::Start(start))?;
        let mut take = (&mut file).take(end - start);
        let mut hasher = Md4::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            if is_cancelled() {
                anyhow::bail!("archive recovery cancelled");
            }
            let read = take.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let actual: [u8; 16] = hasher.finalize().into();
        if &actual == expected {
            ranges.push((start, end));
        }
    }
    Ok(ranges)
}

/// Persist a status the user just asked for, ordered against the network task's
/// own writes.
///
/// This has to go through `TransferStatusWriteClock` rather than straight to
/// SQLite. The network task issues fire-and-forget status writes onto the
/// blocking pool; a clock only orders writes that take a sequence number from
/// it, so an unsequenced write here could be overtaken by an older queued one
/// and lose. Restore reads the persisted string and only declines to auto-start
/// `Paused`/`Stopped`, so losing that race meant a download the user explicitly
/// paused resumed by itself on the next launch — or a resumed one came back
/// Failed.
async fn persist_transfer_status(state: &AppState, transfer_id: &str, status: &TransferStatus) {
    let db = state.db.clone();
    let tid = transfer_id.to_string();
    let status = transfer_status_key(status).to_string();
    let clock = Arc::clone(crate::network::transfer_status_write_clock());
    let seq = clock.next_seq();
    if let Err(e) = tokio::task::spawn_blocking(move || {
        crate::network::apply_transfer_status_write(&clock, &db, &tid, &status, seq)
    })
    .await
    {
        tracing::warn!("Transfer status persist task panicked: {e}");
    }
}

/// Persist many statuses on **one** blocking thread.
///
/// The "all" commands used to `join_all` one `spawn_blocking` per row with no
/// cap — and unlike the `*_batch` commands they never call `check_batch_size`,
/// so the set is bounded only by `MAX_PENDING_DOWNLOADS` (10,000). Every task
/// then serialized on the single `Mutex<Connection>` anyway, so the concurrency
/// bought nothing but contention: past a few hundred rows it saturated tokio's
/// default blocking pool (no `max_blocking_threads` is configured, and the
/// stack size is 8 MiB) and starved every other consumer of it — MD4 part
/// hashing, `.part.met` saves, approved-path file opens — until it drained,
/// while the IPC call itself did not return.
///
/// Sequence numbers are taken up front so the relative order of these writes is
/// fixed before any of them runs, and the rows that survive the per-id stale
/// check commit in one transaction rather than one fsync each.
async fn persist_transfer_statuses(state: &AppState, statuses: Vec<(String, String)>) {
    if statuses.is_empty() {
        return;
    }
    let db = state.db.clone();
    let clock = Arc::clone(crate::network::transfer_status_write_clock());
    let sequenced: Vec<(String, String, u64)> = statuses
        .into_iter()
        .map(|(id, status)| {
            let seq = clock.next_seq();
            (id, status, seq)
        })
        .collect();
    if let Err(e) = tokio::task::spawn_blocking(move || {
        clock.apply_status_writes(&db, &sequenced);
    })
    .await
    {
        tracing::warn!("Transfer status batch persist task panicked: {e}");
    }
}

/// The ids among `ids` with no source discovery running before a resume: a
/// queued row Stop or a full disk ended (both drop its pending download and
/// its control), or an active row with no worker that the resume may park in
/// the queue when the cap is full (see `TransferManager::resume`). A paused
/// queued row is not one: its pending download survives the pause.
fn rows_needing_discovery(
    manager: &crate::sharing::manager::TransferManager,
    ids: &[String],
) -> Vec<String> {
    ids.iter()
        .filter(|id| {
            manager.queue.iter().any(|t| {
                &t.id == *id
                    && matches!(t.status, TransferStatus::Stopped | TransferStatus::Insufficient)
            }) || manager.active.get(id.as_str()).is_some_and(|t| {
                matches!(t.status, TransferStatus::Paused | TransferStatus::Insufficient)
            })
        })
        .cloned()
        .collect()
}

/// Source discovery for rows a resume left waiting in the queue, as a newly
/// queued download gets: without it they read Searching or Queued and searched
/// for nothing until a slot freed, then started from a cold source list.
/// Rows the resume promoted or restarted are skipped; they get a worker.
async fn start_queued_discovery(state: &AppState, candidates: &[String]) {
    for id in candidates {
        let (transfer, control) = {
            let mut manager = state.transfer_manager.write().await;
            let Some(transfer) = manager
                .queue
                .iter()
                .find(|t| {
                    &t.id == id
                        && matches!(t.status, TransferStatus::Searching | TransferStatus::Queued)
                })
                .cloned()
            else {
                continue;
            };
            let control = match manager.get_control(id) {
                Some(control) => control,
                None => {
                    let control = TransferControl::new();
                    manager.register_control(id, control.clone());
                    control
                }
            };
            (transfer, control)
        };
        if let Err(e) = bounded_send(
            &state.network_tx,
            NetworkCommand::StartDownload {
                file_hash: transfer.file_hash.clone(),
                file_name: transfer.file_name.clone(),
                file_size: transfer.total_size,
                peer_ip: parse_peer_ip(&transfer.peer_id),
                peer_port: parse_peer_port(&transfer.peer_id),
                extra_sources: Vec::new(),
                ember_file_hash: transfer.ember_file_hash.clone().unwrap_or_default(),
                expected_aich: transfer.expected_aich.clone(),
                transfer_id: transfer.id.clone(),
                control,
                friend_ember_hash: None,
                discovery_only: true,
            },
        )
        .await
        {
            tracing::warn!("Failed to restart source discovery for queued {}: {e}", transfer.id);
        }
    }
}

pub(crate) async fn start_promoted_downloads(state: &AppState, promoted: &[Transfer]) {
    for transfer in promoted {
        let control = {
            let mut manager = state.transfer_manager.write().await;
            // Re-read under the lock. A batch collects every row its earlier
            // items promoted, including ones a later item then cancels or
            // stops, and a single cancel can land between a promotion and this
            // call. Started anyway, such a row ran a hidden worker outside the
            // concurrency cap, and with no source `StartDownload` saved the
            // cancelled row back to the database.
            let startable = manager.active.get(&transfer.id).is_some_and(|t| {
                matches!(
                    t.status,
                    TransferStatus::Searching
                        | TransferStatus::Queued
                        | TransferStatus::Active
                        | TransferStatus::Hashing
                )
            });
            if !startable {
                continue;
            }
            // Cancel any control already registered for this transfer before
            // replacing it. A previous worker generation's per-source tasks are
            // detached `tokio::spawn`s that hold a clone of that old control and
            // only stop when it is cancelled — aborting the worker handle does
            // NOT abort them. Without this, a pause→resume (or any respawn)
            // overwrote the registered control with a fresh one and left the old
            // children transferring on an orphaned control, so a later Stop (or
            // disconnect) could never reach them and the download never stopped.
            if let Some(old) = manager.get_control(&transfer.id) {
                old.cancel();
            }
            let control = TransferControl::new();
            manager.register_control(&transfer.id, control.clone());
            control
        };
        if let Err(e) = bounded_send(
            &state.network_tx,
            NetworkCommand::StartDownload {
                file_hash: transfer.file_hash.clone(),
                file_name: transfer.file_name.clone(),
                file_size: transfer.total_size,
                peer_ip: parse_peer_ip(&transfer.peer_id),
                peer_port: parse_peer_port(&transfer.peer_id),
                // Extras were registered into SourceManager at enqueue via
                // discovery_only StartDownload; the network handler reloads
                // them from SM when workers start.
                extra_sources: Vec::new(),
                ember_file_hash: transfer.ember_file_hash.clone().unwrap_or_default(),
                expected_aich: transfer.expected_aich.clone(),
                transfer_id: transfer.id.clone(),
                control,
                friend_ember_hash: None,
                discovery_only: false,
            },
        )
        .await
        {
            tracing::warn!("Failed to start promoted download {}: {e}", transfer.id);
            let mut manager = state.transfer_manager.write().await;
            let _ = manager.fail(
                &transfer.id,
                TransferFailureCode::NetworkChannelUnavailable,
                Some("permanent".to_string()),
                None,
            );
        }
    }
}

/// Try to delete a file, retrying with a delay if it fails (e.g. because
/// the download task still holds the handle on Windows).
async fn delete_with_retry(
    path: &Path,
    allowed_roots: &[String],
    expected: &crate::security::filesystem::ObjectIdentity,
    max_attempts: u32,
    delay_ms: u64,
) {
    for attempt in 0..max_attempts {
        let delete_path = path.to_path_buf();
        let display_path = delete_path.clone();
        let allowed = allowed_roots.to_vec();
        let expected = expected.clone();
        let result = tokio::task::spawn_blocking(move || {
            crate::security::filesystem::remove_approved_file_if_identity(
                &delete_path,
                &allowed,
                &expected,
            )
        })
        .await;
        match result {
            Ok(Ok(())) => {
                tracing::debug!("Deleted {}", display_path.display());
                return;
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                tracing::warn!("Delete task failed for {}: {e}", display_path.display());
                return;
            }
            Ok(Err(e)) if attempt + 1 < max_attempts => {
                tracing::debug!(
                    "Delete {} attempt {}/{} failed ({}), retrying...",
                    display_path.display(),
                    attempt + 1,
                    max_attempts,
                    e
                );
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    "Failed to delete {} after {} attempts: {}",
                    display_path.display(),
                    max_attempts,
                    e
                );
            }
        }
    }
}

fn pin_cleanup_target(
    path: &Path,
    allowed_roots: &[String],
) -> std::io::Result<
    Option<(
        std::path::PathBuf,
        crate::security::filesystem::ObjectIdentity,
    )>,
> {
    match crate::security::filesystem::open_existing_approved(path, allowed_roots, false) {
        Ok((verified, file)) => Ok(Some((
            verified,
            crate::security::filesystem::opened_file_identity(&file)?,
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

async fn cleanup_one_partial(
    path: &Path,
    allowed_roots: &[String],
    max_attempts: u32,
    delay_ms: u64,
) {
    for attempt in 0..max_attempts {
        let pinned = tokio::task::spawn_blocking({
            let (path, allowed_roots) = (path.to_path_buf(), allowed_roots.to_vec());
            move || pin_cleanup_target(&path, &allowed_roots)
        })
        .await
        .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())));
        match pinned {
            Ok(None) => return,
            Ok(Some((pinned, identity))) => {
                delete_with_retry(&pinned, allowed_roots, &identity, max_attempts, delay_ms).await;
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) if attempt + 1 < max_attempts => {
                tracing::debug!(
                    "Pin {} attempt {}/{} failed ({}), retrying...",
                    path.display(),
                    attempt + 1,
                    max_attempts,
                    error
                );
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
            Err(error) => {
                tracing::warn!(
                    "Refusing to delete unverified path {} after {max_attempts} attempts: {error}",
                    path.display()
                );
            }
        }
    }
}

/// How long Cancel and Remove wait on one download folder. A download held
/// for a drive that is not connected must still be cancellable, and an
/// offline share can hold every call into it for tens of seconds.
const PARTIAL_CLEANUP_FOLDER_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// Delete a download's `.part` and `.part.met` from whichever download folder
/// holds them; `download_roots` is every one that may (see
/// `AppSettings::download_roots`). The folders are cleaned in parallel, each
/// for at most [`PARTIAL_CLEANUP_FOLDER_BUDGET`]. Where a folder that may hold
/// them cannot be reached or does not answer in time, they are removed once
/// it can be (`storage::deferred_removals`), and the folder stays a download
/// folder until then.
async fn cleanup_partial_files(db: &Arc<Database>, download_roots: &[String], transfer_id: &str) {
    if uuid::Uuid::parse_str(transfer_id).is_err() {
        tracing::warn!("cleanup_partial_files: invalid transfer_id, skipping");
        return;
    }
    let left = futures::future::join_all(download_roots.iter().map(|root| async move {
        let temp_dir = std::path::PathBuf::from(root).join("Temp");
        let part_path = temp_dir.join(format!("{transfer_id}.part"));
        let met_path = temp_dir.join(format!("{transfer_id}.part.met"));
        crate::network::ed2k::part_tracker::suppress_met_saves(&met_path);
        let allowed = vec![root.clone()];
        let cleanup = async {
            let folder = std::path::PathBuf::from(root);
            let reachable = tokio::task::spawn_blocking(move || {
                crate::storage::part_folders::folder_reachable(&folder)
            })
            .await
            .unwrap_or(false);
            if reachable {
                tokio::join!(
                    cleanup_one_partial(&part_path, &allowed, 6, 500),
                    cleanup_one_partial(&met_path, &allowed, 6, 500),
                );
            }
            reachable
        };
        let cleaned = tokio::time::timeout(PARTIAL_CLEANUP_FOLDER_BUDGET, cleanup)
            .await
            .unwrap_or(false);
        if cleaned
            || !crate::storage::part_folders::may_hold_parts(transfer_id, Path::new(root))
        {
            return Vec::new();
        }
        tracing::warn!("Removing {transfer_id}'s part files from {root} once it answers");
        [part_path, met_path]
            .map(|path| (path.to_string_lossy().into_owned(), root.clone()))
            .to_vec()
    }))
    .await;
    let left: Vec<(String, String)> = left.into_iter().flatten().collect();
    if !left.is_empty() {
        let db = db.clone();
        db_blocking(move || crate::storage::deferred_removals::record(&db, &left)).await;
    }
}

fn spawn_deferred_partial_cleanup(
    db: Arc<Database>,
    download_roots: Vec<String>,
    transfer_id: String,
) {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        cleanup_partial_files(&db, &download_roots, &transfer_id).await;
    });
}

/// Relocate a failed download's `.part` into `Downloads/` so "Remove from List"
/// keeps the bytes instead of deleting Temp/{uuid}.part. Named `*.part` so it
/// is not mistaken for a completed file. `Ok` once the bytes are safe to
/// delete from `Temp`: they were relocated, or there are none in any folder
/// that can be looked at. `Err`, the coded error to show, leaves everything
/// as it was, with the download listed: the move failed, or the folder its
/// part files were last in — the current one when there is none — cannot be
/// reached.
async fn preserve_failed_partial(
    folders: &crate::storage::part_folders::DownloadFolders,
    transfer_id: &str,
    file_name: &str,
) -> Result<(), String> {
    use crate::storage::part_folders::PartLocation;
    if uuid::Uuid::parse_str(transfer_id).is_err() {
        return Ok(());
    }
    let not_moved = || {
        coded(
            "transfers_preserve_partial_failed",
            "The download's progress could not be moved into the Downloads folder",
        )
    };
    let located = {
        let folders = folders.clone();
        let id = transfer_id.to_string();
        tokio::task::spawn_blocking(move || folders.locate_own_part(&id)).await
    };
    let part_root = match located {
        Ok(PartLocation::Found(root)) => root,
        Ok(PartLocation::Absent { unreachable }) if unreachable.is_empty() => return Ok(()),
        Ok(PartLocation::Absent { unreachable }) => {
            tracing::warn!(
                "Keeping failed download {transfer_id} listed: {} holds its bytes and cannot \
                 be reached",
                unreachable[0].display()
            );
            return Err(coded(
                "transfers_part_folder_unreachable",
                "The drive with this download's progress is not connected",
            ));
        }
        Err(error) => {
            tracing::warn!("preserve_failed_partial: folder lookup failed: {error}");
            return Err(not_moved());
        }
    };
    let part_path = part_root.join("Temp").join(format!("{transfer_id}.part"));
    let allowed = vec![part_root.to_string_lossy().into_owned()];
    let pinned = match pin_cleanup_target(&part_path, &allowed) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!("preserve_failed_partial: refusing unverified part path: {error}");
            return Err(not_moved());
        }
    };
    let Some((verified, identity)) = pinned else {
        return Ok(());
    };
    let safe = crate::security::sanitize_filename(file_name);
    let dest_name = if safe
        .rsplit('.')
        .next()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("part"))
    {
        safe
    } else {
        format!("{safe}.part")
    };
    let download_root = folders.current.clone();
    match tokio::task::spawn_blocking(move || {
        crate::network::ed2k::transfer::move_part_to_downloads(
            &verified,
            &part_root,
            &download_root,
            &dest_name,
            &identity,
        )
    })
    .await
    {
        Ok(Ok(path)) => {
            tracing::info!("Preserved failed download partial as {}", path.display());
            Ok(())
        }
        Ok(Err(error)) => {
            tracing::warn!("Failed to preserve partial for {transfer_id}, keeping it: {error}");
            Err(not_moved())
        }
        Err(error) => {
            tracing::warn!("Preserve-partial task failed for {transfer_id}, keeping it: {error}");
            Err(not_moved())
        }
    }
}

/// Walk `<download_folder>/Temp/` and remove any `.part` / `.part.met`
/// files whose `<uuid>` prefix doesn't match a transfer ID the
/// `transfer_manager` knows about. Idempotent and safe to call at
/// process startup once the DB-backed resume logic has populated the
/// manager — workers that own a known `.part` are skipped because
/// their UUID is in `known_ids`.
///
/// Catches:
///   * orphans left over from a previous crash where the cleanup path
///     didn't run,
///   * orphans from a `cleanup_partial_files` attempt that failed
///     because the upload server briefly held the .part open on Windows,
///   * orphans from a cross-device `move_part_to_final` whose source
///     remove step failed after the copy already succeeded, and
///   * .part files left behind by users who wiped or replaced their
///     transfers DB without also clearing the Temp folder.
///
/// Files whose basename isn't a valid UUID are ignored — only Ember-
/// created part files use UUID basenames, so user-managed files in the
/// same folder are never touched.
///
/// Runs in the background, so a slow or offline download folder holds up
/// nothing. `known_ids` is a snapshot taken at `cutoff`, and a download the
/// loop accepts afterwards is not in it: the part files of every download
/// and room transfer this run has opened or located
/// (`part_folders::known_this_run`) are never removed, whatever their dates,
/// and neither is a file modified at or after `cutoff`. Whatever that
/// leaves, the next startup sweeps.
///
/// `download_roots` is every download folder a `.part` may be in
/// (`AppSettings::download_roots`). An earlier one is forgotten at startup
/// only once it holds none of these orphans, so sweeping it here is what
/// lets it go — and what stops a finished file's `.part` whose removal failed
/// after a copy from staying behind in it for good. The folders are swept in
/// parallel, each for at most [`ORPHAN_SWEEP_FOLDER_BUDGET`].
pub async fn sweep_orphan_part_files(
    download_roots: &[String],
    known_ids: &std::collections::HashSet<String>,
    db: &Database,
    cutoff: std::time::SystemTime,
) {
    // Read once, up front, instead of querying per file. This runs inline on
    // the network task's startup gate, so a Temp directory full of stale
    // partials used to mean thousands of blocking queries before the loop
    // could accept its first connection. On failure the set is empty and the
    // sweep falls back to `known_ids` alone, which is the conservative
    // direction only in that it may leave an orphan behind for one more run —
    // never that it deletes a partial a live download still owns, because
    // those ids are in `known_ids`.
    let owns_partial = match db.incomplete_downloads_owning_partials() {
        Ok(set) => set,
        Err(e) => {
            tracing::warn!("Orphan sweep: could not read owned partials; skipping DB check ({e})");
            std::collections::HashSet::new()
        }
    };
    let owns_partial = &owns_partial;
    futures::future::join_all(download_roots.iter().map(|download_folder| async move {
        let sweep = sweep_orphan_part_files_in(download_folder, known_ids, owns_partial, cutoff);
        if tokio::time::timeout(ORPHAN_SWEEP_FOLDER_BUDGET, sweep).await.is_err() {
            tracing::warn!("Orphan sweep: gave up on {download_folder}, which is not answering");
        }
    }))
    .await;
}

/// An offline network share can hold every call into it for tens of seconds.
const ORPHAN_SWEEP_FOLDER_BUDGET: std::time::Duration = std::time::Duration::from_secs(15);

async fn sweep_orphan_part_files_in(
    download_folder: &str,
    known_ids: &std::collections::HashSet<String>,
    owns_partial: &std::collections::HashSet<String>,
    cutoff: std::time::SystemTime,
) {
    let temp_dir = std::path::PathBuf::from(download_folder).join("Temp");
    if !tokio::fs::metadata(&temp_dir).await.is_ok_and(|m| m.is_dir()) {
        return;
    }
    let mut entries = match tokio::fs::read_dir(&temp_dir).await {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("Orphan sweep: failed to read {}: {e}", temp_dir.display());
            return;
        }
    };
    let mut swept_part: u32 = 0;
    let mut swept_met: u32 = 0;
    let mut skipped_known: u32 = 0;
    let mut failed: u32 = 0;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Match `<uuid>.part.met` first (longer suffix) so we don't
        // accidentally treat the `.met` file as a `.part` whose UUID
        // ends in `.met`.
        let (uuid_str, is_met) = if let Some(stem) = name.strip_suffix(".part.met") {
            (stem, true)
        } else if let Some(stem) = name.strip_suffix(".part") {
            (stem, false)
        } else {
            continue;
        };
        // A room transfer lives only in memory, so at startup every one of its
        // part files belongs to a transfer that ended with the last run —
        // except those `known_ids` names, accepted since this run began.
        let room_xfer = !is_met && name.starts_with("ember-xfer-");
        if !room_xfer && uuid::Uuid::parse_str(uuid_str).is_err() {
            // Not an Ember-managed file; leave it alone.
            continue;
        }
        // Whatever its dates say: a network share's clock can make a file
        // this run just created look older than the snapshot.
        if known_ids.contains(uuid_str)
            || owns_partial.contains(uuid_str)
            || crate::storage::part_folders::known_this_run(uuid_str)
        {
            skipped_known += 1;
            continue;
        }
        let older = entry
            .metadata()
            .await
            .and_then(|metadata| metadata.modified())
            .is_ok_and(|modified| modified < cutoff);
        if !older {
            skipped_known += 1;
            continue;
        }
        let allowed = vec![download_folder.to_string()];
        let deletion = tokio::task::spawn_blocking({
            let path = path.clone();
            let allowed = allowed.clone();
            move || crate::security::filesystem::remove_approved_file(&path, &allowed)
        })
        .await;
        match deletion {
            Ok(Ok(())) => {
                if is_met {
                    swept_met += 1;
                } else {
                    swept_part += 1;
                }
                tracing::info!("Orphan sweep: removed {}", path.display());
            }
            Ok(Err(error)) => {
                failed += 1;
                tracing::warn!(
                    "Orphan sweep: refusing changed/unapproved path {}: {error}",
                    path.display()
                );
            }
            Err(error) => {
                failed += 1;
                tracing::warn!(
                    "Orphan sweep delete task failed for {}: {error}",
                    path.display()
                );
            }
        }
    }
    if swept_part > 0 || swept_met > 0 || failed > 0 {
        tracing::info!(
            "Orphan sweep finished: removed {swept_part} .part and {swept_met} .part.met file(s) from {} ({skipped_known} skipped — still in use, {failed} failed to delete)",
            temp_dir.display()
        );
    }
}

#[tauri::command]
pub async fn start_download(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    file_hash: String,
    file_name: String,
    file_size: u64,
    peer_ip: String,
    peer_port: u16,
    // `extra_sources`: additional candidate sources known up-front,
    // e.g. the rest of `result.source_addresses` from a search hit
    // beyond the primary peer the frontend already passes as
    // `peer_ip`/`peer_port`. Each entry is an "ip:port" string.
    // Optional and capped server-side; a missing/empty list is
    // treated as "no extras" and the network task does its own
    // discovery (KAD + server queries) as usual. We cap the parsed
    // result here at 64 to avoid pushing pathological lists across
    // the IPC boundary; the network task applies its own stricter
    // cap (`MAX_SEED_EXTRA_SOURCES = 49`) after IP-filter / ban /
    // dedup validation.
    extra_sources: Option<Vec<String>>,
    // Optional Ember content BLAKE3 hex from search results / library.
    ember_file_hash: Option<String>,
    expected_aich: Option<String>,
    // Set when this download was started from a friend's browse listing.
    // 32-char hex Ember hash. Lets the network task register the primary
    // seed into `SourceManager` *with identity* immediately instead of
    // waiting for a Hello handshake to bind it — see the field doc on
    // `NetworkCommand::StartDownload::friend_ember_hash`.
    friend_ember_hash: Option<String>,
) -> Result<StartDownloadResponse, String> {
    let _download_admission = state.download_admission.lock().await;
    let file_name = crate::security::sanitize_filename(&file_name);

    if file_hash.len() != 32 || hex::decode(&file_hash).is_err() {
        return Err(coded("transfers_invalid_file_hash", "Invalid file hash"));
    }
    // Rows, the duplicate check and source-exchange matching all compare the
    // lowercase hex `hex::encode` writes.
    let file_hash = file_hash.to_ascii_lowercase();
    // Best-effort: a malformed value here shouldn't fail the whole download
    // (it only affects up-front identity-seeding, not correctness), so we
    // log and fall back to `None` instead of rejecting the request.
    let friend_ember_hash = friend_ember_hash.filter(|h| !h.is_empty()).and_then(|h| {
        let bytes = hex::decode(&h).ok()?;
        if bytes.len() != 16 {
            tracing::warn!("start_download: ignoring malformed friend_ember_hash");
            return None;
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Some(arr)
    });
    let expected_aich = crate::security::parse_expected_aich(expected_aich.as_deref())
        .map_err(|message| coded("transfers_invalid_expected_aich", message))?;
    let ember_file_hash = crate::security::parse_ember_file_hash(ember_file_hash.as_deref())
        .map_err(|message| coded("transfers_invalid_ember_file_hash", message))?;

    let peer_ip = normalize_primary_peer_ip(peer_ip)?;

    // Parse + cheap-validate extra sources at the IPC boundary. Anything
    // that doesn't parse as `ip:port` with a non-zero IPv4/IPv6 host and
    // a non-zero port is dropped silently — the search-result feed
    // sometimes carries "0.0.0.0:0" placeholders for LowID rows we can't
    // dial directly. Full security validation (IP filter, banned IPs,
    // dedup against primary, special-use addresses) runs in the network
    // task where the live state is available.
    const MAX_EXTRA_SOURCES_IPC: usize = 64;
    let parsed_extras: Vec<(String, u16)> = extra_sources
        .unwrap_or_default()
        .into_iter()
        .take(MAX_EXTRA_SOURCES_IPC)
        .filter_map(|addr| {
            let addr = addr.trim();
            if addr.is_empty() {
                return None;
            }
            let (ip_part, port_part) = addr.rsplit_once(':')?;
            let port: u16 = port_part.parse().ok()?;
            if port == 0 {
                return None;
            }
            // Strip IPv6 brackets if present so the network task's
            // `Ipv4Addr::parse` path matches. IPv6 sources aren't
            // supported on the eD2K download path; drop them now.
            let ip_str = ip_part
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string();
            ip_str.parse::<std::net::Ipv4Addr>().ok()?;
            Some((ip_str, port))
        })
        .collect();

    // Zero-byte ed2k files are valid (hash must be empty-file MD4 on the network stack).

    // D16: reject oversized files up front instead of enqueueing them and
    // failing later at network-start with a confusing "exceeds maximum"
    // error. The ceiling is the one the download worker enforces: Max file
    // size, which settings keep within 1-593 GiB, so there is always a cap.
    {
        let config = state.config.read().await;
        let cap_bytes = config.settings.ed2k_download_limits().max_download_bytes;
        if file_size > cap_bytes {
            let gib = |bytes: u64| (bytes as f64) / (1024.0 * 1024.0 * 1024.0);
            return Err(coded("transfers_file_size_exceeds_max", format!(
                "File size {:.2} GiB exceeds your maximum of {:.0} GiB — raise Max file size in Settings › Transfers to download this file.",
                gib(file_size),
                gib(cap_bytes)
            )));
        }
    }

    let transfer_id = uuid::Uuid::new_v4().to_string();

    let has_source = !peer_ip.is_empty() && peer_ip != "0.0.0.0" && peer_port > 0;

    let add_paused = {
        let config = state.config.read().await;
        config.settings.add_downloads_paused
    };
    let control = TransferControl::new();
    if add_paused {
        control.pause();
    }

    let transfer = Transfer {
        id: transfer_id.clone(),
        file_name: file_name.clone(),
        file_hash: file_hash.clone(),
        peer_id: if has_source {
            format!("{peer_ip}:{peer_port}")
        } else {
            String::new()
        },
        peer_name: String::new(),
        direction: TransferDirection::Download,
        status: if add_paused {
            TransferStatus::Paused
        } else if has_source {
            TransferStatus::Queued
        } else {
            TransferStatus::Searching
        },
        progress: 0.0,
        speed: 0,
        total_size: file_size,
        transferred: 0,
        completed_size: 0,
        started_at: chrono::Utc::now().timestamp(),
        failure_reason: None,
        failure_code: None,
        failure_kind: None,
        failure_stage: None,
        priority: "auto".to_string(),
        sources: if has_source { 1 } else { 0 },
        active_sources: 0,
        queued_sources: 0,
        queue_rank: None,
        last_seen_complete: None,
        last_received: None,
        health: crate::types::TransferHealth::Healthy,
        health_reason: None,
        health_code: None,
        stalled_since: None,
        category: String::new(),
        wait_time: 0,
        upload_time: 0,
        a4af_sources: 0,
        max_sources: 0,
        preview_priority: false,
        preview_ready: false,
        ember_sources: 0,
        client_software: String::new(),
        country_code: None,
        user_hash: None,
        ember_hash: None,
        expected_aich: expected_aich.clone(),
        ember_file_hash: ember_file_hash.clone(),
        completed_path: None,
        up_part_status: None,
        up_part_count: None,
        up_peer_part_status: None,
        ember_verified: false,
        friends_only: false,
    };

    let active_now = {
        let mut manager = state.transfer_manager.write().await;
        if let Some(existing_id) = manager.pending_transfer_id_for_hash(&file_hash) {
            if let Some(expected) = expected_aich.as_deref() {
                let existing_pin = manager
                    .get_transfer(&existing_id)
                    .and_then(|transfer| transfer.expected_aich.as_deref());
                if existing_pin != Some(expected) {
                    return Err(coded(
                        "transfers_existing_download_aich_mismatch",
                        "This file is already queued without the same trusted AICH pin; cancel it and add the AICH link again",
                    ));
                }
            }
            if let Some(expected) = ember_file_hash.as_deref() {
                let existing_pin = manager
                    .get_transfer(&existing_id)
                    .and_then(|transfer| transfer.ember_file_hash.as_deref());
                if existing_pin != Some(expected) {
                    return Err(coded(
                        "transfers_existing_download_ember_mismatch",
                        "This file is already queued without the same Ember digest; cancel it and add the eh= link again",
                    ));
                }
            }
            return Ok(StartDownloadResponse {
                transfer_id: existing_id,
                already_queued: true,
            });
        }
        ensure_pending_download_budget(&manager, &[file_size])?;
        let active_now = manager.enqueue(transfer.clone());
        manager.register_control(&transfer_id, control.clone());
        active_now
    };

    let persisted_transfer = {
        let manager = state.transfer_manager.read().await;
        manager
            .get_transfer(&transfer_id)
            .cloned()
            .unwrap_or_else(|| transfer.clone())
    };
    if let Err(error) = persist_transfer(&state, &persisted_transfer).await {
        rollback_unpersisted_transfer(&state, &transfer_id).await;
        return Err(coded_ctx(
            "transfers_start_download_failed",
            "Failed to save download before starting it",
            error,
        ));
    }

    let _ = app.emit("transfer-started", &persisted_transfer);

    // Always hand the download to the network task: active starts run
    // MultiSource workers; queued / add-paused use discovery_only so
    // KAD + TCP + UDP source asking still runs (matching restore).
    let discovery_only = !active_now || add_paused;

    if let Err(e) = bounded_send(
        &state.network_tx,
        NetworkCommand::StartDownload {
            file_hash,
            file_name,
            file_size,
            peer_ip,
            peer_port,
            extra_sources: parsed_extras,
            ember_file_hash: ember_file_hash.clone().unwrap_or_default(),
            expected_aich,
            transfer_id: transfer_id.clone(),
            control,
            discovery_only,
            friend_ember_hash,
        },
    )
    .await
    {
        // The network channel is gone, so this transfer will never start.
        // It was already enqueued as active and occupies a download slot;
        // roll it back to Failed so it doesn't pin that slot forever and
        // block promotion of queued downloads.
        {
            let mut manager = state.transfer_manager.write().await;
            let _ = manager.fail(
                &transfer_id,
                TransferFailureCode::NetworkChannelUnavailable,
                Some("permanent".to_string()),
                None,
            );
        }
        if let Some(failed) = {
            let manager = state.transfer_manager.read().await;
            manager.get_transfer(&transfer_id).cloned()
        } {
            if let Err(persist_error) = persist_transfer(&state, &failed).await {
                tracing::error!(
                    "Failed to persist network-start failure for transfer {}: {persist_error}",
                    transfer_id_short(&transfer_id)
                );
            }
            let _ = app.emit("transfer-failed", &failed);
        }
        return Err(coded_ctx(
            "transfers_start_download_failed",
            "Failed to start download",
            e,
        ));
    }

    Ok(StartDownloadResponse {
        transfer_id,
        already_queued: false,
    })
}

/// Consume the startup overflow count once so the app shell can present a
/// user-visible migration notice without repeating it on every route change.
#[tauri::command]
pub async fn take_pending_download_overflow_notice(
    state: tauri::State<'_, AppState>,
) -> Result<usize, String> {
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || db.acknowledge_pending_download_overflow())
        .await
        .map_err(|error| {
            coded_ctx(
                "transfers_overflow_notice_task_failed",
                "Failed to read queue migration notice",
                error,
            )
        })?
        .map_err(|error| {
            coded_ctx(
                "transfers_overflow_notice_failed",
                "Failed to read queue migration notice",
                error,
            )
        })
}

/// Upper bound on how many transfer IDs a single batch command will act on.
/// The UI can only ever select what's on screen, so this is generous; it
/// exists purely to stop a buggy or hostile caller from handing us an
/// unbounded list that would tie up the transfer manager lock in a long loop.
const MAX_BATCH_TRANSFER_IDS: usize = 500;
const MAX_BATCH_TRANSFER_ID_BYTES: usize = 256 * 1024;

fn check_batch_size(transfer_ids: &[String]) -> Result<(), String> {
    if transfer_ids.len() > MAX_BATCH_TRANSFER_IDS {
        return Err(coded_ctx(
            "transfers_batch_too_large",
            "Too many transfers in a single request",
            transfer_ids.len(),
        ));
    }
    let mut total = 0usize;
    for id in transfer_ids {
        if id.len() > 128 {
            return Err(coded_ctx(
                "transfers_invalid_transfer_id",
                "Transfer id is too long",
                id.len(),
            ));
        }
        total = total.saturating_add(id.len());
        if total > MAX_BATCH_TRANSFER_ID_BYTES {
            return Err(coded_ctx(
                "transfers_batch_bytes_too_large",
                "Transfer id batch is too large",
                total,
            ));
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn pause_transfers_batch(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    transfer_ids: Vec<String>,
) -> Result<(), String> {
    check_batch_size(&transfer_ids)?;
    let (paused, promoted) = {
        let mut manager = state.transfer_manager.write().await;
        for transfer_id in &transfer_ids {
            if let Some(control) = manager.get_control(transfer_id) {
                control.pause();
                // Cancel too, exactly as the single-transfer pause does: pause
                // alone leaves detached per-source tasks running on this
                // control, and leaves a verification pass reading the whole
                // file to the end. Safe because a resume routes through
                // `start_promoted_downloads`, which cancels whatever is
                // registered and installs a fresh control.
                control.cancel();
            }
        }
        manager.pause_and_promote_many(&transfer_ids)
    };
    let statuses: Vec<(String, TransferStatus)> = paused
        .iter()
        .map(|id| (id.clone(), TransferStatus::Paused))
        .collect();
    emit_transfer_statuses(&app, &statuses);
    persist_transfer_statuses(
        &state,
        paused
            .into_iter()
            .map(|id| (id, transfer_status_key(&TransferStatus::Paused).to_string()))
            .collect(),
    )
    .await;
    let mut send_error = None;
    for transfer_id in &transfer_ids {
        // `bounded_send`, like the single-row sibling. A raw `send().await` on
        // a full channel with a wedged consumer never returns, so selecting
        // many rows and clicking Pause left the UI spinning with no error
        // where one row would have surfaced `network_timeout` after ten
        // seconds.
        //
        // Stop at the first failure rather than discarding it and carrying on.
        // Every send costs the full `CMD_SEND_TIMEOUT` against a wedged task,
        // so a full batch of `MAX_BATCH_TRANSFER_IDS` spent well over an hour
        // timing out one row at a time and then reported success.
        if let Err(e) = bounded_send(
            &state.network_tx,
            NetworkCommand::PauseDownload {
                transfer_id: transfer_id.clone(),
            },
        )
        .await
        {
            send_error = Some(e);
            break;
        }
    }
    start_promoted_downloads(&state, &promoted).await;
    match send_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Of `ids`, those held for a folder that cannot be reached
/// (`part_folders::start_over_if_held`), now set to start over in the
/// current download folder, which is recorded as theirs: resuming one is how
/// the user lets go of progress on a drive that is not coming back.
async fn start_held_over(state: &AppState, ids: &[String]) -> Vec<String> {
    let current = state.config.read().await.settings.download_folder.clone();
    let restarted: Vec<String> = ids
        .iter()
        .filter(|id| {
            crate::storage::part_folders::start_over_if_held(id, Path::new(&current))
        })
        .cloned()
        .collect();
    if !restarted.is_empty() {
        tracing::info!(
            "Starting {} held download(s) over in the current download folder",
            restarted.len()
        );
        let records: Vec<(String, String)> =
            restarted.iter().map(|id| (id.clone(), current.clone())).collect();
        let db = state.db.clone();
        db_blocking(move || {
            if let Err(e) = db.record_part_folders(&records) {
                tracing::warn!("Could not record where restarted downloads are: {e}");
            }
        })
        .await;
    }
    restarted
}

#[tauri::command]
pub async fn resume_transfers_batch(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    transfer_ids: Vec<String>,
) -> Result<(), String> {
    check_batch_size(&transfer_ids)?;
    // `restart_ids` holds `active` rows resumed from `Insufficient` as well as
    // `Paused`, as in `resume_transfer` and `resume_all_transfers`. `resume`
    // clears that state in place and returns no promotions (the row never
    // left `active`), so without it `start_promoted_downloads` is never
    // called and no `PendingDownload` is re-inserted —
    // `mark_download_insufficient` dropped it. The row then reads `Searching`,
    // which `active_download_count` *does* count, so the cap is oversubscribed
    // and the transfer never dials again: the retry timer only walks
    // `pending_downloads`.
    let held_over = start_held_over(&state, &transfer_ids).await;
    let (outcome, rediscover) = {
        let mut manager = state.transfer_manager.write().await;
        let rediscover = rows_needing_discovery(&manager, &transfer_ids);
        (manager.resume_many(&transfer_ids, true), rediscover)
    };
    emit_transfer_statuses(&app, &outcome.statuses);
    persist_transfer_statuses(
        &state,
        outcome
            .statuses
            .iter()
            .map(|(id, status)| (id.clone(), transfer_status_key(status).to_string()))
            .collect(),
    )
    .await;
    let mut to_start: Vec<Transfer> = outcome.promoted;
    {
        let manager = state.transfer_manager.read().await;
        for id in outcome.restart_ids {
            if let Some(t) = manager.get_transfer(&id) {
                to_start.push(t.clone());
            }
        }
        for id in held_over {
            if to_start.iter().all(|t| t.id != id) {
                if let Some(t) = manager.get_transfer(&id) {
                    to_start.push(t.clone());
                }
            }
        }
    }
    start_promoted_downloads(&state, &to_start).await;
    start_queued_discovery(&state, &rediscover).await;
    Ok(())
}

#[tauri::command]
pub async fn stop_transfers_batch(
    state: tauri::State<'_, AppState>,
    transfer_ids: Vec<String>,
) -> Result<(), String> {
    check_batch_size(&transfer_ids)?;
    let mut promoted_by_id: HashMap<String, Transfer> = HashMap::new();
    let mut send_error = None;
    for transfer_id in transfer_ids {
        let promoted = {
            let mut manager = state.transfer_manager.write().await;
            if let Some(control) = manager.get_control(&transfer_id) {
                control.cancel();
            }
            manager.stop(&transfer_id)
        };
        for p in promoted {
            promoted_by_id.entry(p.id.clone()).or_insert(p);
        }
        persist_transfer_status(&state, &transfer_id, &TransferStatus::Stopped).await;
        // Bounded, and the first failure ends the batch — see the note in
        // `pause_transfers_batch` for why carrying on is worse than stopping.
        if let Err(e) = bounded_send(
            &state.network_tx,
            NetworkCommand::CancelDownload {
                transfer_id: transfer_id.clone(),
                cleanup_ack: None,
            },
        )
        .await
        {
            send_error = Some(e);
            break;
        }
    }
    let promoted: Vec<Transfer> = promoted_by_id.into_values().collect();
    start_promoted_downloads(&state, &promoted).await;
    match send_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[tauri::command]
pub async fn cancel_transfers_batch(
    state: tauri::State<'_, AppState>,
    transfer_ids: Vec<String>,
) -> Result<(), String> {
    check_batch_size(&transfer_ids)?;
    let mut promoted_by_id: HashMap<String, Transfer> = HashMap::new();
    let mut pending_acks = Vec::with_capacity(transfer_ids.len());
    let mut cancelled_ids = Vec::with_capacity(transfer_ids.len());
    let mut history_rows: Vec<(String, String, u64, &str)> =
        Vec::with_capacity(transfer_ids.len());
    let mut teardown_failures = 0usize;
    for transfer_id in transfer_ids {
        let (promoted, cancelled_info) = {
            let mut manager = state.transfer_manager.write().await;
            let info = manager
                .get_transfer(&transfer_id)
                .map(|t| (t.file_hash.clone(), t.file_name.clone(), t.total_size));
            if let Some(control) = manager.get_control(&transfer_id) {
                // Deletes the `.part` — see `cancel_transfer` for why this is
                // `discard` rather than `cancel`.
                control.discard();
            }
            (manager.cancel(&transfer_id), info)
        };
        if let Some((file_hash, file_name, file_size)) = cancelled_info {
            // Collected rather than written here: one transaction for the whole
            // batch below, instead of one fsync per cancelled transfer.
            history_rows.push((file_hash, file_name, file_size, "cancelled"));
        }
        for p in promoted {
            promoted_by_id.entry(p.id.clone()).or_insert(p);
        }
        cancelled_ids.push(transfer_id.clone());

        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        if let Err(e) = state.network_tx.try_send(NetworkCommand::CancelDownload {
            transfer_id: transfer_id.clone(),
            cleanup_ack: Some(ack_tx),
        }) {
            tracing::warn!(
                "cancel_transfers_batch: network task unavailable for {transfer_id}; proceeding with best-effort cleanup ({e})"
            );
            teardown_failures += 1;
        } else {
            pending_acks.push((transfer_id.clone(), ack_rx));
        }
    }

    // Wait for teardown acks concurrently (same wall-clock deadline as single cancel),
    // then always remove DB rows — matching `cancel_transfer`. Retaining rows on
    // ack timeout caused cancelled downloads to resurrect on the next launch.
    let results = futures::future::join_all(pending_acks.into_iter().map(
        |(transfer_id, ack_rx)| async move {
            (
                transfer_id,
                tokio::time::timeout(CMD_REPLY_TIMEOUT, ack_rx).await,
            )
        },
    ))
    .await;
    for (transfer_id, result) in results {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                teardown_failures += 1;
                tracing::warn!(
                    "cancel_transfers_batch: cleanup ack channel closed for {transfer_id}; proceeding with best-effort cleanup"
                );
            }
            Err(_) => {
                teardown_failures += 1;
                tracing::warn!(
                    "cancel_transfers_batch: cleanup ack timed out for {transfer_id}; proceeding with best-effort cleanup"
                );
            }
        }
    }

    let dl_roots = state.config.read().await.settings.download_roots();
    // Both writes go out as one transaction each, before the file cleanup: the
    // rows are what stop a cancelled download resurrecting on the next launch,
    // and per-row writes interleaved with per-row disk deletes held the shared
    // connection mutex across the whole loop.
    {
        let db = state.db.clone();
        let rows = history_rows;
        let ids = cancelled_ids.clone();
        db_blocking(move || {
            if let Err(e) = db.record_download_history_batch(&rows) {
                tracing::warn!("Failed to record cancelled download history: {e}");
            }
            if let Err(e) = db.remove_transfers(&ids) {
                tracing::warn!("Failed to remove cancelled transfers from database: {e}");
            }
        })
        .await;
    }
    for transfer_id in cancelled_ids {
        cleanup_partial_files(&state.db, &dl_roots, &transfer_id).await;
        spawn_deferred_partial_cleanup(state.db.clone(), dl_roots.clone(), transfer_id.clone());
    }
    let promoted: Vec<Transfer> = promoted_by_id.into_values().collect();
    start_promoted_downloads(&state, &promoted).await;
    if teardown_failures > 0 {
        tracing::warn!(
            "cancel_transfers_batch: {teardown_failures} teardown ack failure(s); DB rows still removed to prevent resurrect-on-restart"
        );
    }
    Ok(())
}

#[tauri::command]
pub async fn pause_transfer(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let (status, promoted) = {
        let mut manager = state.transfer_manager.write().await;
        if let Some(control) = manager.get_control(&transfer_id) {
            control.pause();
            // Also cancel so detached per-source tasks exit (pause alone used
            // to leave orphans until hard abort). Resume replaces the control.
            control.cancel();
        }
        let promoted = manager.pause_and_promote(&transfer_id);
        let status = manager.get_transfer(&transfer_id).map(|t| t.status.clone());
        (status, promoted)
    };
    if let Some(status) = &status {
        persist_transfer_status(&state, &transfer_id, status).await;
        // eMule updates the row synchronously on pause (CPartFile::PauseFile ->
        // NotifyStatusChange). Emit the new status now so the UI flips to
        // Paused immediately instead of waiting up to one ~3 s poll cycle. The
        // frontend zeroes the row's speed on a paused/stopped status event.
        emit_transfer_status(&app, &transfer_id, status);
    }
    // The control above is already paused *and* cancelled, so the worker and
    // its detached per-source tasks stop cooperatively; this command is the
    // hard-abort backstop. Dropping its error silently hid the one condition
    // worth seeing here — a network task that cannot accept commands at all.
    if let Err(e) = bounded_send(
        &state.network_tx,
        NetworkCommand::PauseDownload {
            transfer_id: transfer_id.clone(),
        },
    )
    .await
    {
        tracing::warn!(
            "pause_transfer: could not reach the network task for {transfer_id}; the transfer is paused locally but its worker was not hard-aborted ({e})"
        );
    }
    start_promoted_downloads(&state, &promoted).await;
    Ok(())
}

/// eMule "Stop": removes from active download without deleting files.
/// Different from Pause - a stopped file won't automatically resume.
#[tauri::command]
pub async fn stop_transfer(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let promoted = {
        let mut manager = state.transfer_manager.write().await;
        if let Some(control) = manager.get_control(&transfer_id) {
            control.cancel();
        }
        manager.stop(&transfer_id)
    };
    persist_transfer_status(&state, &transfer_id, &TransferStatus::Stopped).await;
    // Reflect the Stop in the UI immediately (eMule CPartFile::StopFile updates
    // synchronously); otherwise the row lingers as Active until the next poll.
    emit_transfer_status(&app, &transfer_id, &TransferStatus::Stopped);
    // As in `pause_transfer`: the control is already cancelled, so this is the
    // hard-abort backstop and its failure is worth a line rather than nothing.
    if let Err(e) = bounded_send(
        &state.network_tx,
        NetworkCommand::CancelDownload {
            transfer_id: transfer_id.clone(),
            cleanup_ack: None,
        },
    )
    .await
    {
        tracing::warn!(
            "stop_transfer: could not reach the network task for {transfer_id}; the transfer is stopped locally but its worker was not hard-aborted ({e})"
        );
    }
    start_promoted_downloads(&state, &promoted).await;
    Ok(())
}

/// Completed file in `Downloads/`, or in-progress `.part` in `Temp/`.
/// Always prefers the final file in Downloads/ over the .part in Temp/ so
/// that a stale in-memory status never misdirects the user.
fn resolve_transfer_reveal_path(
    transfer: &Transfer,
    folders: &crate::storage::part_folders::DownloadFolders,
) -> Result<PathBuf, String> {
    if transfer.direction != TransferDirection::Download {
        return Err(coded("transfers_not_a_download", "Not a download"));
    }
    let completed_dir = folders.current.join("Downloads");
    let safe_name = crate::security::sanitize_filename(&transfer.file_name);
    // Prefer the exact destination recorded at completion (handles the
    // dedup-suffix case); otherwise reconstruct from the file name.
    let final_path = match transfer.completed_path.as_deref() {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => completed_dir.join(&safe_name),
    };
    let part_path = folders.part_path_for(&transfer.id);

    let candidate = if final_path.is_file() {
        final_path
    } else if part_path.is_file() {
        part_path
    } else {
        return Err(coded("transfers_file_not_found", "File not found on disk"));
    };

    crate::security::filesystem::verify_existing_path(&candidate, &folders.roots())
        .map_err(|e| {
            coded_ctx(
                "transfers_invalid_path",
                "Invalid or changed download path",
                e,
            )
        })
}

#[tauri::command]
pub async fn open_transfer_file_location(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let (transfer, dl_folders) = {
        let (mgr, cfg) = tokio::join!(state.transfer_manager.read(), state.config.read(),);
        (
            mgr.get_transfer(&transfer_id).cloned(),
            cfg.settings.download_folders(),
        )
    };
    let transfer =
        transfer.ok_or_else(|| coded("transfers_transfer_not_found", "Transfer not found"))?;
    // `resolve_transfer_reveal_path` performs several `canonicalize()`/`is_file()`
    // syscalls; run path resolution AND the reveal together on the blocking pool
    // so a slow path (network/cloud/AV-locked) can't stall the async runtime and
    // freeze unrelated IPC commands.
    tokio::task::spawn_blocking(move || {
        let path = resolve_transfer_reveal_path(&transfer, &dl_folders)?;
        crate::security::filesystem::reveal_in_file_manager(&path)
            .map_err(|e| coded_ctx("transfers_open_explorer_failed", "Failed to reveal file", e))
    })
    .await
    .map_err(|e| coded_ctx("transfers_reveal_task_failed", "Reveal task failed", e))??;
    Ok(())
}

/// Open the Downloads directory itself in the user's file manager.
///
/// Distinct from [`open_transfer_file_location`], which reveals one file: this
/// is the pane-level action, so it has no transfer to resolve from and has to
/// work when the list is empty — which is exactly when someone reaches for it.
///
/// The directory is created if it is missing. A profile that has never finished
/// a download has no `Downloads/` yet, because it is created when the first file
/// lands there, and refusing to open a folder we are about to create ourselves
/// would be a confusing answer to a reasonable request.
#[tauri::command]
pub async fn open_downloads_folder(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let dl_folder = {
        let cfg = state.config.read().await;
        cfg.settings.download_folder.clone()
    };
    // Same blocking-pool treatment as the reveal path: creating and launching a
    // directory that lives on a network or cloud-synced volume can block for
    // seconds, and stalling the async runtime freezes unrelated IPC.
    tokio::task::spawn_blocking(move || {
        let dir = std::path::PathBuf::from(&dl_folder).join("Downloads");
        std::fs::create_dir_all(&dir).map_err(|e| {
            coded_ctx(
                "transfers_downloads_folder_unavailable",
                "Could not open the Downloads folder",
                e,
            )
        })?;
        // Resolve through the sandbox like every other path the shell is handed
        // (`open_file`, `open_transfer_file_location`). Without it this was the
        // one reveal that followed the raw config string, so a download root
        // retargeted by a junction — the case `verify_root` exists to revoke —
        // would be opened anyway.
        let dir = crate::security::filesystem::verify_existing_path(&dir, std::slice::from_ref(&dl_folder))
            .map_err(|e| {
                coded_ctx(
                    "transfers_invalid_path",
                    "Invalid or changed download path",
                    e,
                )
            })?;
        crate::security::filesystem::open_with_default_app(&dir).map_err(|e| {
            coded_ctx(
                "transfers_open_explorer_failed",
                "Failed to open the Downloads folder",
                e,
            )
        })
    })
    .await
    .map_err(|e| coded_ctx("transfers_reveal_task_failed", "Reveal task failed", e))??;
    Ok(())
}

#[tauri::command]
pub async fn open_file(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let (transfer, dl_folder) = {
        let (mgr, cfg) = tokio::join!(state.transfer_manager.read(), state.config.read(),);
        (
            mgr.get_transfer(&transfer_id).cloned(),
            cfg.settings.download_folder.clone(),
        )
    };
    let transfer =
        transfer.ok_or_else(|| coded("transfers_transfer_not_found", "Transfer not found"))?;
    let safe_name = crate::security::sanitize_filename(&transfer.file_name);
    let download_dir = std::path::PathBuf::from(&dl_folder).join("Downloads");
    // Prefer the exact path recorded at completion time. Falling back to
    // `Downloads/<name>` is only correct when no dedup suffix was applied;
    // the canonical-containment check below still confines either choice to
    // the Downloads directory.
    let file_path = match transfer.completed_path.as_deref() {
        Some(p) if !p.is_empty() => std::path::PathBuf::from(p),
        _ => download_dir.join(&safe_name),
    };
    tokio::task::spawn_blocking(move || {
        if !file_path.exists() {
            return Err(coded(
                "transfers_download_not_finished",
                "Download has not finished yet",
            ));
        }
        let canonical = crate::security::filesystem::verify_existing_path(&file_path, &[dl_folder])
            .map_err(|e| {
                coded_ctx(
                    "transfers_invalid_path",
                    "Invalid or changed download path",
                    e,
                )
            })?;
        if crate::security::filesystem::passive_type_agrees(&transfer.file_name, &canonical) {
            crate::security::filesystem::open_with_default_app(&canonical)
                .map_err(|e| coded_ctx("transfers_open_file_failed", "Failed to open file", e))
        } else {
            crate::security::filesystem::reveal_in_file_manager(&canonical).map_err(|e| {
                coded_ctx(
                    "transfers_reveal_unsafe_file_failed",
                    "This file type was revealed instead of opened",
                    e,
                )
            })
        }
    })
    .await
    .map_err(|e| coded_ctx("transfers_open_task_failed", "Open task failed", e))??;
    Ok(())
}

#[tauri::command]
pub async fn resume_transfer(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let held_over = !start_held_over(&state, std::slice::from_ref(&transfer_id))
        .await
        .is_empty();
    let (was_active_resumable, promoted, rediscover) = {
        let mut manager = state.transfer_manager.write().await;
        let rediscover = rows_needing_discovery(&manager, std::slice::from_ref(&transfer_id));
        // An active row in Paused *or* Insufficient won't be returned by
        // `resume()` as "promoted" (it never left the active map), so the
        // caller must restart its worker explicitly. Stopped rows live in the
        // queue, not active, and are handled by the promoted path below.
        let was_active_resumable = manager
            .active
            .get(&transfer_id)
            .map(|t| {
                matches!(
                    t.status,
                    TransferStatus::Paused | TransferStatus::Insufficient
                )
            })
            .unwrap_or(false);
        // Only for a row Resume can act on. A finished or unknown id kept a
        // control nothing ever removed, and `get_all` then read that row's
        // `preview_ready` from it.
        let resumable_row = manager.active.contains_key(&transfer_id)
            || manager.queue.iter().any(|t| t.id == transfer_id);
        if resumable_row && manager.get_control(&transfer_id).is_none() {
            manager.register_control(&transfer_id, TransferControl::new());
        }
        let promoted = manager.resume(&transfer_id);
        (was_active_resumable, promoted, rediscover)
    };
    let status = {
        let manager = state.transfer_manager.read().await;
        manager.get_transfer(&transfer_id).map(|t| t.status.clone())
    };
    if let Some(status) = &status {
        persist_transfer_status(&state, &transfer_id, status).await;
        // Flip the row out of Paused/Stopped immediately (eMule
        // CPartFile::ResumeFile -> NotifyStatusChange). The worker promotes the
        // row to Active later via its SourcesUpdate event once a source is
        // actually transferring; this just gets it off the stale state now.
        emit_transfer_status(&app, &transfer_id, status);
    }
    if (was_active_resumable || held_over) && promoted.is_empty() {
        let transfer = {
            let manager = state.transfer_manager.read().await;
            manager.get_transfer(&transfer_id).cloned()
        };
        if let Some(t) = transfer {
            start_promoted_downloads(&state, &[t]).await;
        }
    } else {
        start_promoted_downloads(&state, &promoted).await;
    }
    start_queued_discovery(&state, &rediscover).await;
    Ok(())
}

#[tauri::command]
pub async fn cancel_transfer(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let (promoted, cancelled_info) = {
        let mut manager = state.transfer_manager.write().await;
        let info = manager
            .get_transfer(&transfer_id)
            .map(|t| (t.file_hash.clone(), t.file_name.clone(), t.total_size));
        if let Some(control) = manager.get_control(&transfer_id) {
            // Discard, not cancel: this path deletes the `.part`, so the writer
            // should drop its handle without fsyncing it first.
            control.discard();
        }
        (manager.cancel(&transfer_id), info)
    };

    if let Some((file_hash, file_name, file_size)) = cancelled_info {
        let db = state.db.clone();
        db_blocking(move || {
            if let Err(e) =
                db.record_download_history(&file_hash, &file_name, file_size, "cancelled")
            {
                tracing::warn!("Failed to record cancelled download history for {file_hash}: {e}");
            }
        })
        .await;
    }

    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
    let (send_result, dl_roots) = tokio::join!(
        bounded_send(
            &state.network_tx,
            NetworkCommand::CancelDownload {
                transfer_id: transfer_id.clone(),
                cleanup_ack: Some(ack_tx),
            },
        ),
        async { state.config.read().await.settings.download_roots() },
    );
    // Wait for the network task to confirm it released the file before we
    // delete the partials. On timeout / closed channel we still proceed
    // (best-effort cleanup), but log it: deleting while the task may still
    // hold a handle is the race this ack exists to avoid.
    //
    // A send that never landed is reported as itself rather than as a closed
    // ack channel: the ack sender went out with the undelivered command, so
    // awaiting it would only mint a misleading "channel closed" line.
    // `cancel_transfers_batch` already distinguishes the two.
    if let Err(e) = send_result {
        tracing::warn!(
            "cancel_transfer: network task unavailable for {transfer_id}; proceeding with best-effort cleanup ({e})"
        );
    } else {
        match tokio::time::timeout(CMD_REPLY_TIMEOUT, ack_rx).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => tracing::warn!(
                "Cancel cleanup ack channel closed without ack for {transfer_id}; proceeding with best-effort cleanup"
            ),
            Err(_) => tracing::warn!(
                "Timed out waiting for cancel cleanup ack for {transfer_id}; proceeding with best-effort cleanup"
            ),
        }
    }
    cleanup_partial_files(&state.db, &dl_roots, &transfer_id).await;
    spawn_deferred_partial_cleanup(state.db.clone(), dl_roots, transfer_id.clone());

    {
        let db = state.db.clone();
        let tid = transfer_id.clone();
        db_blocking(move || {
            if let Err(e) = db.remove_transfer(&tid) {
                tracing::warn!("Failed to remove transfer {tid} from database: {e}");
            }
        })
        .await;
    }

    start_promoted_downloads(&state, &promoted).await;
    Ok(())
}

#[tauri::command]
pub async fn remove_transfer(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let snapshot = {
        let manager = state.transfer_manager.read().await;
        manager.get_transfer(&transfer_id).cloned()
    };
    let dl_folders = state.config.read().await.settings.download_folders();
    // A failed download's bytes are kept: moved into Downloads before
    // anything else, since the cancel below deletes its `.part.met`. Until
    // they are safe the row, the `.part` and the `.part.met` stay as they
    // are, and the user is told why.
    if let Some(failed) = snapshot.filter(|t| {
        t.status == TransferStatus::Failed && t.direction == TransferDirection::Download
    }) {
        preserve_failed_partial(&dl_folders, &transfer_id, &failed.file_name).await?;
    }
    let promoted = {
        let mut manager = state.transfer_manager.write().await;
        if let Some(control) = manager.get_control(&transfer_id) {
            // Remove-from-List deletes the Temp `.part`/`.part.met` too (a
            // failed download's bytes were relocated above).
            control.discard();
        }
        manager.remove(&transfer_id)
    };

    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
    let send_result = bounded_send(
        &state.network_tx,
        NetworkCommand::CancelDownload {
            transfer_id: transfer_id.clone(),
            cleanup_ack: Some(ack_tx),
        },
    )
    .await;
    // Wait for the network task to confirm it released the file before we
    // delete the partials (best-effort on timeout/closed channel, but log the
    // race window — deleting while the task may still hold a handle is exactly
    // what this ack exists to avoid). An undelivered command is reported as
    // itself; see `cancel_transfer`.
    if let Err(e) = send_result {
        tracing::warn!(
            "remove_transfer: network task unavailable for {transfer_id}; proceeding with best-effort cleanup ({e})"
        );
    } else {
        match tokio::time::timeout(CMD_REPLY_TIMEOUT, ack_rx).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => tracing::warn!(
                "Remove cleanup ack channel closed without ack for {transfer_id}; proceeding with best-effort cleanup"
            ),
            Err(_) => tracing::warn!(
                "Timed out waiting for remove cleanup ack for {transfer_id}; proceeding with best-effort cleanup"
            ),
        }
    }
    let db = state.db.clone();
    let tid = transfer_id.clone();
    let dl_roots = dl_folders.roots();
    tokio::join!(cleanup_partial_files(&state.db, &dl_roots, &transfer_id), async {
        db_blocking(move || {
            if let Err(e) = db.remove_transfer(&tid) {
                tracing::warn!("Failed to remove transfer {tid} from database: {e}");
            }
        })
        .await;
    },);
    spawn_deferred_partial_cleanup(state.db.clone(), dl_roots, transfer_id.clone());
    start_promoted_downloads(&state, &promoted).await;
    Ok(())
}

#[tauri::command]
pub async fn get_transfers(state: tauri::State<'_, AppState>) -> Result<Vec<Transfer>, String> {
    let manager = state.transfer_manager.read().await;
    Ok(manager.get_all())
}

/// What changed since the caller's last answer, for the Transfers poll: only
/// rows whose payload differs, the ids that left, and the revision to pass
/// next time. `since: 0` (or a revision from another run) returns every row.
#[tauri::command]
pub async fn get_transfers_since(
    state: tauri::State<'_, AppState>,
    epoch: Option<u64>,
    since: u64,
) -> Result<crate::sharing::manager::TransferDelta, String> {
    let manager = state.transfer_manager.read().await;
    Ok(manager.get_transfers_since(epoch, since))
}

/// Chunk map and part counters for one download, for the "File Details"
/// window. Read on demand rather than carried on every transfers poll, because
/// a per-part bitmap on every tick would be paid for by every user who never
/// opens the window.
#[tauri::command]
pub async fn get_download_file_details(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<crate::types::DownloadFileDetails, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetDownloadFileDetails { transfer_id, tx })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    await_reply(
        rx,
        "transfers_file_details_failed",
        "Failed to read file details",
    )
    .await
}

/// Snapshot of peers currently waiting in our upload queue. Backs the
/// "Queued" tab in the transfers/uploads pane. Each row already carries
/// resolved file name + credit info so the frontend doesn't need any
/// follow-up commands per row.
#[tauri::command]
pub async fn get_upload_queue(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<UploadQueueClient>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetUploadQueueSnapshot { tx })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    await_reply(
        rx,
        "transfers_upload_queue_failed",
        "Failed to get upload queue",
    )
    .await
}

/// Snapshot of every persisted SecIdent credit record. Backs the
/// "Known Clients" tab — this is the lifetime view of every peer
/// we've ever traded credit with, sorted by most-recently-seen.
#[tauri::command]
pub async fn get_known_clients(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<KnownClient>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetKnownClientsSnapshot { tx })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    await_reply(
        rx,
        "transfers_known_clients_failed",
        "Failed to get known clients",
    )
    .await
}

/// Row counts for the two known-peer tabs.
///
/// The tab labels carry these, so they are polled on whichever tab is showing;
/// `get_known_clients` is far too expensive to run for two integers. See
/// `NetworkCommand::GetKnownClientCounts`.
#[tauri::command]
pub async fn get_known_client_counts(
    state: tauri::State<'_, AppState>,
) -> Result<crate::types::KnownClientCounts, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetKnownClientCounts { tx })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    await_reply(
        rx,
        "transfers_known_client_counts_failed",
        "Failed to get known client counts",
    )
    .await
}

#[tauri::command]
pub async fn set_transfer_priority(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
    priority: String,
) -> Result<(), String> {
    let valid = ["verylow", "low", "normal", "high", "release", "auto"];
    if !valid.contains(&priority.as_str()) {
        return Err(coded_ctx(
            "transfers_invalid_priority",
            format!("Invalid priority: {priority}. Must be one of: {valid:?}"),
            priority,
        ));
    }
    let db = state.db.clone();
    let tid = transfer_id.clone();
    let prio = priority.clone();
    tokio::task::spawn_blocking(move || db.update_transfer_priority(&tid, &prio))
        .await
        .map_err(|e| {
            coded_ctx(
                "transfers_priority_task_failed",
                "Priority update failed",
                e,
            )
        })?
        .map_err(|e| {
            coded_ctx(
                "transfers_priority_persist_failed",
                "Priority update failed",
                e,
            )
        })?;
    {
        let mut manager = state.transfer_manager.write().await;
        manager.set_priority(&transfer_id, &priority);
    }
    Ok(())
}

#[tauri::command]
pub async fn set_transfer_category(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
    category: String,
) -> Result<(), String> {
    if category.len() > 256 {
        return Err(coded(
            "transfers_category_too_long",
            "Category name too long (max 256 bytes)",
        ));
    }
    let db = state.db.clone();
    let tid = transfer_id.clone();
    let cat = category.clone();
    tokio::task::spawn_blocking(move || db.update_transfer_category(&tid, &cat))
        .await
        .map_err(|e| {
            coded_ctx(
                "transfers_category_task_failed",
                "Category update failed",
                e,
            )
        })?
        .map_err(|e| {
            coded_ctx(
                "transfers_category_persist_failed",
                "Category update failed",
                e,
            )
        })?;
    {
        let mut manager = state.transfer_manager.write().await;
        manager.set_category(&transfer_id, &category);
    }
    Ok(())
}

#[tauri::command]
pub async fn rename_transfer(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
    file_name: String,
) -> Result<String, String> {
    let trimmed = file_name.trim();
    if trimmed.is_empty() {
        return Err(coded(
            "transfers_invalid_file_name",
            "Enter a valid file name",
        ));
    }
    let sanitized = crate::security::sanitize_filename(trimmed);
    if sanitized.is_empty() || (sanitized == "unnamed_file" && trimmed != "unnamed_file") {
        return Err(coded(
            "transfers_invalid_file_name",
            "Enter a valid file name",
        ));
    }

    let previous = {
        let manager = state.transfer_manager.read().await;
        let Some(transfer) = manager.get_transfer(&transfer_id) else {
            return Err(coded("transfers_transfer_not_found", "Transfer not found"));
        };
        // Refused once the file is being hashed or moved as well as after it
        // has finished: the completion path has already read the name it will
        // move under, so a rename accepted inside that window would leave the
        // row and the file on disk disagreeing.
        if transfer.direction != TransferDirection::Download
            || matches!(
                transfer.status,
                TransferStatus::Verifying
                    | TransferStatus::Completing
                    | TransferStatus::Hashing
                    | TransferStatus::Completed
            )
        {
            return Err(coded(
                "transfers_cannot_rename",
                "This download cannot be renamed",
            ));
        }
        transfer.file_name.clone()
    };

    // Persisted first, because a failure here has to leave every copy of the
    // name untouched — the rename simply did not happen.
    let db = state.db.clone();
    let tid = transfer_id.clone();
    let name = sanitized.clone();
    tokio::task::spawn_blocking(move || db.update_transfer_file_name(&tid, &name))
        .await
        .map_err(|e| coded_ctx("transfers_rename_task_failed", "Rename failed", e))?
        .map_err(|e| coded_ctx("transfers_rename_persist_failed", "Rename failed", e))?;

    // The network task sets the control flag that completion reads, so the
    // rename reaches the file on disk only once the hand-over has actually
    // happened. Setting it here would let a rename we then reported as failed
    // still name the finished file.
    let (tx, rx) = tokio::sync::oneshot::channel();
    let handed_over = match state.network_tx.try_send(NetworkCommand::RenameDownload {
        transfer_id: transfer_id.clone(),
        file_name: sanitized.clone(),
        tx,
    }) {
        Ok(()) => match await_reply(rx, "transfers_rename_failed", "Failed to rename download").await {
            // Completion read the name after the status check above.
            Ok(false) => Err(coded("transfers_cannot_rename", "This download cannot be renamed")),
            other => other.map(|_| ()),
        },
        Err(e) => Err(coded_ctx("network_busy", "Network busy", e)),
    };
    if let Err(error) = handed_over {
        restore_transfer_file_name(&state, &transfer_id, &previous).await;
        return Err(error);
    }

    let refused = {
        let mut manager = state.transfer_manager.write().await;
        if manager.set_file_name(&transfer_id, &sanitized) {
            None
        } else {
            // Finished or removed between the check above and here. The row
            // keeps the name it has, so the persisted copy has to go back to
            // it or the next restart shows a name nothing else agrees with.
            Some(
                manager
                    .get_transfer(&transfer_id)
                    .map(|transfer| transfer.file_name.clone()),
            )
        }
    };
    if let Some(current) = refused {
        let still_listed = current.is_some();
        restore_transfer_file_name(&state, &transfer_id, &current.unwrap_or(previous)).await;
        return Err(if still_listed {
            coded("transfers_cannot_rename", "This download cannot be renamed")
        } else {
            coded("transfers_transfer_not_found", "Transfer not found")
        });
    }

    Ok(sanitized)
}

/// Put the persisted name back when a rename could not be handed to the
/// network task or the row refused it. Best effort: the command already
/// reports the rename as failed, so a failure here costs only that the
/// persisted name disagrees with the row until the next rename or restart.
async fn restore_transfer_file_name(state: &AppState, transfer_id: &str, previous: &str) {
    let db = state.db.clone();
    let tid = transfer_id.to_string();
    let name = previous.to_string();
    let restored = tokio::task::spawn_blocking(move || db.update_transfer_file_name(&tid, &name))
        .await
        .map_err(|e| e.to_string())
        .and_then(|result| result.map_err(|e| e.to_string()));
    if let Err(error) = restored {
        tracing::warn!(
            "Rename of transfer {} did not take and its persisted name was not rolled back: {error}",
            transfer_id_short(transfer_id)
        );
    }
}

#[tauri::command]
pub async fn set_preview_priority(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
    enabled: bool,
) -> Result<(), String> {
    let transfer = {
        let mut manager = state.transfer_manager.write().await;
        manager.set_preview_priority(&transfer_id, enabled);
        manager.get_transfer(&transfer_id).cloned()
    };
    if let Some(t) = transfer {
        if let Err(error) = persist_transfer(&state, &t).await {
            tracing::warn!(
                "Failed to persist preview-priority change for transfer {}: {error}",
                transfer_id_short(&t.id)
            );
        }
    }
    Ok(())
}

/// Pause every active download.
///
/// L7 note: this operation is eventually-consistent, not atomic. It takes
/// a write lock on the transfer manager to capture the set of active IDs,
/// then fans out individual `NetworkCommand::PauseDownload` messages. If
/// the user resumes a transfer concurrently, the resume and the broadcast
/// pause may interleave; last command wins per transfer. Callers should
/// debounce in the UI rather than expect a transactional guarantee.
#[tauri::command]
pub async fn pause_all_transfers(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let (paused, pause_ids) = {
        let mut manager = state.transfer_manager.write().await;
        let active_ids: Vec<String> = manager
            .active
            .iter()
            .filter(|(_, t)| t.direction == TransferDirection::Download)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &active_ids {
            if let Some(control) = manager.get_control(id) {
                control.pause();
                control.cancel();
            }
        }
        let queued_ids = manager.queue.iter().filter(|t| {
            t.direction == TransferDirection::Download
                && t.status != TransferStatus::Paused
                && t.status != TransferStatus::Stopped
        });
        let pause_ids: Vec<String> = active_ids
            .iter()
            .cloned()
            .chain(queued_ids.map(|t| t.id.clone()))
            .collect();
        let paused = manager.pause_many(&pause_ids);
        (paused, pause_ids)
    };
    // Immediate UI feedback for every paused row (see pause_transfer).
    let statuses: Vec<(String, TransferStatus)> = paused
        .iter()
        .map(|id| (id.clone(), TransferStatus::Paused))
        .collect();
    emit_transfer_statuses(&app, &statuses);
    persist_transfer_statuses(
        &state,
        paused
            .into_iter()
            .map(|id| (id, transfer_status_key(&TransferStatus::Paused).to_string()))
            .collect(),
    )
    .await;
    // Last: with a full channel each send can wait up to `CMD_SEND_TIMEOUT`,
    // and the UI and the database already reflect the pause.
    for id in &pause_ids {
        let _ = bounded_send(
            &state.network_tx,
            NetworkCommand::PauseDownload {
                transfer_id: id.clone(),
            },
        )
        .await;
    }
    Ok(())
}

#[tauri::command]
/// Resume every paused / stopped download. See pause_all_transfers for the
/// same eventual-consistency caveat.
pub async fn resume_all_transfers(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let (outcome, rediscover) = {
        let mut manager = state.transfer_manager.write().await;
        // Every active row goes through `resume`, not only paused ones, so
        // each live control is resumed as before.
        let queued_ids = manager.queue.iter().filter(|t| {
            matches!(
                t.status,
                TransferStatus::Paused | TransferStatus::Stopped | TransferStatus::Insufficient
            )
        });
        let resume_ids: Vec<String> = manager
            .active
            .keys()
            .cloned()
            .chain(queued_ids.map(|t| t.id.clone()))
            .collect();
        let rediscover = rows_needing_discovery(&manager, &resume_ids);
        (manager.resume_many(&resume_ids, false), rediscover)
    };
    let resumed: Vec<(String, TransferStatus)> = outcome
        .statuses
        .into_iter()
        .filter(|(_, status)| {
            matches!(
                status,
                TransferStatus::Searching | TransferStatus::Queued | TransferStatus::Active
            )
        })
        .collect();
    // Immediate UI feedback: flip every resumed row off Paused/Stopped now
    // (see resume_transfer) rather than waiting for the next poll.
    emit_transfer_statuses(&app, &resumed);
    persist_transfer_statuses(
        &state,
        resumed
            .into_iter()
            .map(|(id, status)| (id, transfer_status_key(&status).to_string()))
            .collect(),
    )
    .await;
    let mut to_start = outcome.promoted;
    {
        let manager = state.transfer_manager.read().await;
        for id in outcome.restart_ids {
            if let Some(t) = manager.get_transfer(&id) {
                to_start.push(t.clone());
            }
        }
    }
    start_promoted_downloads(&state, &to_start).await;
    start_queued_discovery(&state, &rediscover).await;
    Ok(())
}

#[tauri::command]
pub async fn get_transfer_sources(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<Vec<crate::types::SourceInfo>, String> {
    let manager = state.transfer_manager.read().await;
    Ok(manager.get_source_details(&transfer_id))
}

#[tauri::command]
pub async fn clear_completed(state: tauri::State<'_, AppState>) -> Result<u32, String> {
    // L1: completed rows have no live network state (their upload/download
    // tasks already returned), so there's nothing for CancelDownload to
    // clean up. Just drop from the manager's completed bucket and delete
    // the on-disk .part file below. This avoids a pointless round-trip
    // through the network command channel for every completed row.
    let mut manager = state.transfer_manager.write().await;
    let mut ids: Vec<String> = Vec::new();
    manager.completed.retain(|t| {
        if t.status == TransferStatus::Completed {
            ids.push(t.id.clone());
            false
        } else {
            true
        }
    });
    let count = u32::try_from(ids.len()).unwrap_or(u32::MAX);
    drop(manager);

    let dl_roots = state.config.read().await.settings.download_roots();

    // One transaction for every row, then the disk cleanup. The per-row loop
    // this replaces had no batch-size cap of its own, so clearing a long
    // completed list issued that many transactions — and that many fsyncs —
    // back to back on the connection mutex the network task also waits on.
    {
        let db = state.db.clone();
        let ids = ids.clone();
        db_blocking(move || {
            if let Err(e) = db.remove_transfers(&ids) {
                tracing::warn!("Failed to clear completed transfers from database: {e}");
            }
        })
        .await;
    }
    for id in &ids {
        cleanup_partial_files(&state.db, &dl_roots, id).await;
    }
    Ok(count)
}

#[tauri::command]
pub async fn recover_archive(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<String, String> {
    static RECOVERY_CONCURRENCY: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    let permit = RECOVERY_CONCURRENCY
        .get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(1)))
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| {
            coded(
                "transfers_recovery_unavailable",
                "Archive recovery unavailable",
            )
        })?;

    let (transfer_info, dl_folders, control) = {
        let (mgr, cfg) = tokio::join!(state.transfer_manager.read(), state.config.read(),);
        let t = mgr
            .get_transfer(&transfer_id)
            .map(|t| (t.file_name.clone(), t.total_size, t.id.clone()));
        (
            t,
            cfg.settings.download_folders(),
            mgr.get_control(&transfer_id),
        )
    };
    let (file_name, file_size, transfer_id_clone) =
        transfer_info.ok_or_else(|| coded("transfers_transfer_not_found", "Transfer not found"))?;

    if !crate::network::ed2k::archive_recovery::is_recoverable_archive(&file_name) {
        return Err(coded(
            "transfers_not_supported_archive",
            "File is not a supported archive format (ZIP, RAR, ACE)",
        ));
    }

    let dl_folder = {
        let id = transfer_id_clone.clone();
        tokio::task::spawn_blocking(move || dl_folders.part_folder_for(&id))
            .await
            .map_err(|e| coded_ctx("transfers_recovery_unavailable", "Archive recovery unavailable", e))?
            .to_string_lossy()
            .into_owned()
    };
    let part_path = std::path::PathBuf::from(&dl_folder)
        .join("Temp")
        .join(format!("{transfer_id_clone}.part"));

    if !part_path.exists() {
        return Err(coded(
            "transfers_part_file_not_found",
            "Part file not found — download may not have started",
        ));
    }
    let canonical_part =
        crate::security::filesystem::verify_existing_path(&part_path, std::slice::from_ref(&dl_folder))
            .map_err(|e| {
                coded_ctx(
                    "transfers_part_path_invalid",
                    "Invalid or changed part path",
                    e,
                )
            })?;
    let canonical_temp = crate::security::filesystem::verify_existing_path(
        &std::path::PathBuf::from(&dl_folder).join("Temp"),
        std::slice::from_ref(&dl_folder),
    )
    .map_err(|e| {
        coded_ctx(
            "transfers_temp_path_invalid",
            "Invalid or changed temp folder",
            e,
        )
    })?;
    crate::security::filesystem::ensure_not_reparse(&canonical_temp)
        .map_err(|e| coded_ctx("transfers_temp_path_reparse", "Unsafe temp folder", e))?;

    let expected_file_hash = {
        let bytes = hex::decode(
            state
                .transfer_manager
                .read()
                .await
                .get_transfer(&transfer_id)
                .map(|transfer| transfer.file_hash.clone())
                .unwrap_or_default(),
        )
        .map_err(|_| coded("transfers_invalid_file_hash", "Invalid transfer hash"))?;
        if bytes.len() != 16 {
            return Err(coded(
                "transfers_invalid_file_hash",
                "Invalid transfer hash",
            ));
        }
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&bytes);
        hash
    };
    let fname = file_name.clone();
    let allowed_for_recovery = vec![dl_folder.clone()];
    let verification_allowed = allowed_for_recovery.clone();
    let recovery_control = control.clone();
    let recovery_cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancellation_for_worker = recovery_cancel.clone();
    enum ArchiveRecoveryJobError {
        PartVerification(anyhow::Error),
        NoVerifiedParts,
        Recovery(anyhow::Error),
    }
    let mut recovery = tokio::task::spawn_blocking(move || {
        // The semaphore belongs to the worker itself, not this IPC future.
        // If the caller is dropped/cancelled, the JoinHandle detaches but the
        // blocking job still retains exclusive recovery ownership until it
        // actually exits.
        let _permit = permit;
        let verified_ranges = verify_recovery_ranges(
            &canonical_part,
            file_size,
            &verification_allowed,
            expected_file_hash,
            recovery_control.as_deref(),
            cancellation_for_worker.as_ref(),
        )
        .map_err(ArchiveRecoveryJobError::PartVerification)?;
        if verified_ranges.is_empty() {
            return Err(ArchiveRecoveryJobError::NoVerifiedParts);
        }
        crate::network::ed2k::archive_recovery::recover_archive(
            &canonical_part,
            &fname,
            &verified_ranges,
            &canonical_temp,
            &allowed_for_recovery,
            recovery_control.as_deref(),
            cancellation_for_worker.as_ref(),
        )
        .map_err(ArchiveRecoveryJobError::Recovery)
    });
    // This ceiling used to wrap `recover_archive` alone, so 130s sat just above
    // its 120s internal budget. Verification now runs inside the same blocking
    // job and MD4-hashes every verified part before recovery's clock even
    // starts, so on a multi-gigabyte archive the old constant expired during
    // verification and recovery became unreachable for exactly the large
    // partials it exists to salvage. Give verification its own allowance,
    // derived from the file size at a deliberately pessimistic floor throughput.
    const VERIFY_FLOOR_BYTES_PER_SEC: u64 = 20 * 1024 * 1024;
    let verify_allowance =
        std::time::Duration::from_secs((file_size / VERIFY_FLOOR_BYTES_PER_SEC).clamp(30, 15 * 60));
    let job_timeout = verify_allowance
        + crate::network::ed2k::archive_recovery::RECOVERY_WALL_TIME
        + std::time::Duration::from_secs(10);
    let recovery_result = match tokio::time::timeout(job_timeout, &mut recovery).await {
        Ok(result) => result,
        Err(_) => {
            // `spawn_blocking` cannot be aborted. Cancel the recovery-local
            // flag and retain the semaphore permit in a reaper task until
            // the worker exits, so a second recovery never overlaps this
            // one and the live download control remains untouched.
            recovery_cancel.store(true, std::sync::atomic::Ordering::Release);
            tokio::spawn(async move {
                if let Err(error) = recovery.await {
                    tracing::warn!(
                        "Timed-out archive recovery task failed while draining: {error}"
                    );
                }
            });
            return Err(coded(
                "transfers_recovery_timed_out",
                "Archive recovery timed out",
            ));
        }
    };
    let result = recovery_result
        .map_err(|e| coded_ctx("transfers_recovery_task_failed", "Recovery task failed", e))?;
    let result = match result {
        Ok(result) => result,
        Err(ArchiveRecoveryJobError::PartVerification(error)) => {
            return Err(coded_ctx(
                "transfers_part_verify_failed",
                "Part verification failed",
                error,
            ));
        }
        Err(ArchiveRecoveryJobError::NoVerifiedParts) => {
            return Err(coded(
                "transfers_no_parts_for_recovery",
                "No completed parts available for recovery",
            ));
        }
        Err(ArchiveRecoveryJobError::Recovery(error)) => {
            return Err(coded_ctx(
                "transfers_recovery_failed",
                "Recovery failed",
                error,
            ));
        }
    };

    Ok(result.to_string_lossy().to_string())
}

#[cfg(test)]
// `await_holding_lock` fires on `test_registry_lock`, held across the awaits on
// purpose: it serialises tests that swap the process-global approved-root
// registry, and the window it has to cover is exactly the asynchronous cleanup
// under test. Dropping it sooner would reintroduce the race it exists to
// prevent. These are `#[tokio::test]`s on the current-thread runtime, so there
// is no executor thread for the guard to strand.
#[allow(clippy::await_holding_lock)]
mod ipc_lifecycle_tests {
    use super::*;

    #[test]
    fn one_budget_rejects_n_plus_one_for_every_admission_source() {
        assert!(budget_allows(MAX_PENDING_DOWNLOADS - 1, 0, &[1],));
        // A direct request racing a collection/deep-link batch is serialized;
        // whichever owns the final slot wins and the combined N+1 transaction
        // is rejected by this shared predicate.
        assert!(!budget_allows(MAX_PENDING_DOWNLOADS - 1, 0, &[1, 1],));
    }

    #[test]
    fn aggregate_remaining_bytes_are_saturating_and_bounded() {
        assert!(budget_allows(0, MAX_PENDING_REMAINING_BYTES - 1, &[1],));
        assert!(!budget_allows(0, MAX_PENDING_REMAINING_BYTES - 1, &[2],));
        assert!(!budget_allows(0, u64::MAX, &[u64::MAX]));
    }

    #[test]
    fn primary_source_rejects_pure_ipv6_before_admission() {
        let error = normalize_primary_peer_ip("2001:db8::1".to_string())
            .expect_err("pure IPv6 eD2K sources are unsupported");
        assert!(error.contains("IPv6 primary sources are not supported"));
        assert_eq!(
            normalize_primary_peer_ip("::ffff:203.0.113.7".to_string()).unwrap(),
            "203.0.113.7"
        );
    }

    fn approved_download_folder(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "ember-cleanup-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let root = base.join("downloads");
        let data = base.join("data");
        std::fs::create_dir_all(root.join("Temp")).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let root_s = root.to_string_lossy().into_owned();
        crate::security::filesystem::initialize_approved_roots(
            &data,
            std::slice::from_ref(&root_s),
        )
        .unwrap();
        (root, base)
    }

    fn test_db(base: &std::path::Path) -> Arc<Database> {
        std::fs::create_dir_all(base.join("data")).unwrap();
        Arc::new(Database::open_at(&base.join("data").join("ember.db")).unwrap())
    }

    #[tokio::test]
    async fn cancel_cleanup_deletes_part_and_part_met() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (root, base) = approved_download_folder("both");
        let transfer_id = uuid::Uuid::new_v4().to_string();
        let temp = root.join("Temp");
        let part = temp.join(format!("{transfer_id}.part"));
        let met = temp.join(format!("{transfer_id}.part.met"));
        std::fs::write(&part, b"partial-bytes").unwrap();
        std::fs::write(&met, b"met").unwrap();

        let db = test_db(&base);
        super::cleanup_partial_files(&db, &[root.to_string_lossy().into_owned()], &transfer_id)
            .await;

        assert!(!part.exists(), ".part must be deleted on cancel cleanup");
        assert!(!met.exists(), ".part.met must be deleted on cancel cleanup");
        let _ = std::fs::remove_dir_all(base);
    }

    /// An earlier download folder still holding a download, and the current
    /// one, both approved.
    fn approved_old_and_new_folders(
        name: &str,
    ) -> (crate::storage::part_folders::DownloadFolders, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "ember-moved-{}-{}-{name}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let old = base.join("old");
        let new = base.join("new");
        let data = base.join("data");
        for dir in [old.join("Temp"), new.join("Temp"), data.clone()] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let folders = crate::storage::part_folders::DownloadFolders::new(
            &new.to_string_lossy(),
            &[old.to_string_lossy().into_owned()],
        );
        crate::security::filesystem::initialize_approved_roots(&data, &folders.roots()).unwrap();
        (folders, base)
    }

    #[tokio::test]
    async fn cancel_cleanup_reaches_a_part_left_in_an_earlier_download_folder() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (folders, base) = approved_old_and_new_folders("cancel");
        let transfer_id = uuid::Uuid::new_v4().to_string();
        let part = folders.previous[0]
            .join("Temp")
            .join(format!("{transfer_id}.part"));
        std::fs::write(&part, b"partial-bytes").unwrap();
        std::fs::write(part.with_extension("part.met"), b"met").unwrap();

        let db = test_db(&base);
        super::cleanup_partial_files(&db, &folders.roots(), &transfer_id).await;

        assert!(!part.exists());
        assert!(!part.with_extension("part.met").exists());
        let _ = std::fs::remove_dir_all(base);
    }

    /// A finished download whose `.part` could not be removed after its
    /// cross-volume copy (an upload held it open) leaves a full-size orphan in
    /// the earlier folder, which startup only forgets once it holds none.
    #[tokio::test]
    async fn the_startup_sweep_removes_orphans_from_earlier_download_folders_too() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (folders, base) = approved_old_and_new_folders("sweep");
        let db = crate::storage::database::Database::open_at(&base.join("data").join("ember.db"))
            .unwrap();
        let old_temp = folders.previous[0].join("Temp");
        let new_temp = folders.current.join("Temp");
        let (orphan, live) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let orphans = [
            old_temp.join(format!("{orphan}.part")),
            old_temp.join(format!("{orphan}.part.met")),
            new_temp.join(format!("{orphan}.part")),
        ];
        for file in &orphans {
            std::fs::write(file, b"finished bytes").unwrap();
        }
        let owned = old_temp.join(format!("{live}.part"));
        std::fs::write(&owned, b"unfinished").unwrap();
        let known: std::collections::HashSet<String> = [live.to_string()].into();

        super::sweep_orphan_part_files(&folders.roots(), &known, &db, std::time::UNIX_EPOCH)
            .await;
        for file in &orphans {
            assert!(
                file.exists(),
                "written since the snapshot, so possibly a download accepted after it: {}",
                file.display()
            );
        }

        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
        super::sweep_orphan_part_files(&folders.roots(), &known, &db, later).await;
        for file in &orphans {
            assert!(!file.exists(), "{}", file.display());
        }
        assert!(owned.exists(), "a download still in the list keeps its part");
        drop(db);
        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn a_failed_partial_left_in_an_earlier_folder_is_kept_in_the_current_downloads() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (folders, base) = approved_old_and_new_folders("preserve");
        let transfer_id = uuid::Uuid::new_v4().to_string();
        let part = folders.previous[0]
            .join("Temp")
            .join(format!("{transfer_id}.part"));
        std::fs::write(&part, b"partial-bytes").unwrap();

        super::preserve_failed_partial(&folders, &transfer_id, "movie.mkv")
            .await
            .unwrap();

        let kept = folders.current.join("Downloads").join("movie.mkv.part");
        assert_eq!(std::fs::read(&kept).unwrap(), b"partial-bytes");
        assert!(!part.exists());
        let _ = std::fs::remove_dir_all(base);
    }

    fn error_code(error: &str) -> String {
        serde_json::from_str::<serde_json::Value>(error).unwrap()["code"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Remove from List deletes a failed download's part files only once its
    /// bytes are safe in Downloads; otherwise nothing is touched — not the
    /// `.part`, not the `.part.met` resuming needs — and the UI is told why.
    #[tokio::test]
    async fn a_failed_partial_that_cannot_be_preserved_is_kept() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (folders, base) = approved_old_and_new_folders("unpreservable");
        let transfer_id = uuid::Uuid::new_v4().to_string();
        let part = folders.previous[0]
            .join("Temp")
            .join(format!("{transfer_id}.part"));
        std::fs::write(&part, b"partial-bytes").unwrap();
        std::fs::write(part.with_extension("part.met"), b"met").unwrap();
        std::fs::write(folders.current.join("Downloads"), b"a file where the folder goes").unwrap();

        let error = super::preserve_failed_partial(&folders, &transfer_id, "movie.mkv")
            .await
            .unwrap_err();
        assert_eq!(error_code(&error), "transfers_preserve_partial_failed");
        assert_eq!(std::fs::read(&part).unwrap(), b"partial-bytes");
        assert_eq!(std::fs::read(part.with_extension("part.met")).unwrap(), b"met");

        let held = uuid::Uuid::new_v4().to_string();
        let volume = base.join("unplugged");
        let offline = volume.join("ember");
        let with_offline = crate::storage::part_folders::DownloadFolders::new(
            &folders.current.to_string_lossy(),
            &[offline.to_string_lossy().into_owned()],
        );
        crate::storage::part_folders::note_located(&held, &offline);
        crate::storage::part_folders::simulate_unplugged(&volume, true);
        let preserved = super::preserve_failed_partial(&with_offline, &held, "movie.mkv").await;
        let unrelated = uuid::Uuid::new_v4().to_string();
        let not_there =
            super::preserve_failed_partial(&with_offline, &unrelated, "movie.mkv").await;
        crate::storage::part_folders::simulate_unplugged(&volume, false);
        assert_eq!(
            error_code(&preserved.unwrap_err()),
            "transfers_part_folder_unreachable",
            "its bytes are on the drive that is not there"
        );
        assert!(
            not_there.is_ok(),
            "a drive this download was never on is no reason to keep it listed"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    /// Regression, one download folder: Remove from List on a failed
    /// download keeps its bytes as before; with the folder unreachable it is
    /// refused with a reason instead of silently doing nothing.
    #[tokio::test]
    async fn remove_from_list_on_a_failed_download_with_one_folder() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (root, base) = approved_download_folder("single-preserve");
        let folders =
            crate::storage::part_folders::DownloadFolders::new(&root.to_string_lossy(), &[]);
        let transfer_id = uuid::Uuid::new_v4().to_string();
        let part = root.join("Temp").join(format!("{transfer_id}.part"));
        std::fs::write(&part, b"partial-bytes").unwrap();
        std::fs::write(part.with_extension("part.met"), b"met").unwrap();

        super::preserve_failed_partial(&folders, &transfer_id, "song.mp3")
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(root.join("Downloads").join("song.mp3.part")).unwrap(),
            b"partial-bytes"
        );
        assert!(!part.exists());
        super::preserve_failed_partial(&folders, &uuid::Uuid::new_v4().to_string(), "x")
            .await
            .unwrap();

        let unplugged = uuid::Uuid::new_v4().to_string();
        crate::storage::part_folders::simulate_unplugged(&root, true);
        let unreachable = super::preserve_failed_partial(&folders, &unplugged, "song.mp3").await;
        crate::storage::part_folders::simulate_unplugged(&root, false);
        assert_eq!(error_code(&unreachable.unwrap_err()), "transfers_part_folder_unreachable");
        let _ = std::fs::remove_dir_all(base);
    }

    /// Cancelling a download held for an unplugged drive removes its part
    /// files once the drive is back, and keeps the folder known till then.
    #[tokio::test]
    async fn cancelling_a_held_download_cleans_its_drive_once_it_is_back() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-held-cancel-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let (current, volume) = (base.join("current"), base.join("unplugged"));
        let held_in = volume.join("ember");
        for dir in [current.join("Temp"), held_in.join("Temp"), base.join("data")] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let folders = crate::storage::part_folders::DownloadFolders::new(
            &current.to_string_lossy(),
            &[held_in.to_string_lossy().into_owned()],
        );
        crate::security::filesystem::initialize_approved_roots(&base.join("data"), &folders.roots())
            .unwrap();
        let db = test_db(&base);
        let held = uuid::Uuid::new_v4().to_string();
        let elsewhere = uuid::Uuid::new_v4().to_string();
        let part = held_in.join("Temp").join(format!("{held}.part"));
        std::fs::write(&part, b"progress").unwrap();
        crate::storage::part_folders::note_located(&held, &held_in);

        crate::storage::part_folders::simulate_unplugged(&volume, true);
        super::cleanup_partial_files(&db, &folders.roots(), &held).await;
        super::cleanup_partial_files(&db, &folders.roots(), &elsewhere).await;
        crate::storage::part_folders::simulate_unplugged(&volume, false);
        assert!(part.exists(), "nothing could be removed from a drive that is not there");
        let deferred = db.deferred_file_removals().unwrap();
        assert_eq!(deferred.len(), 2, "{deferred:?}");
        assert!(
            deferred.iter().all(|(path, _)| path.contains(&held)),
            "only a download that may be on the drive leaves anything to do"
        );

        crate::storage::deferred_removals::retry(&db, &folders);
        assert!(!part.exists(), "removed once the drive is back");
        assert!(db.deferred_file_removals().unwrap().is_empty());
        drop(db);
        let _ = std::fs::remove_dir_all(base);
    }

    /// A share's clock can date a file this run just wrote before the
    /// snapshot; the sweep goes by what this run knows, not by dates.
    #[tokio::test]
    async fn the_startup_sweep_never_removes_a_part_this_run_knows() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (folders, base) = approved_old_and_new_folders("known");
        let db = test_db(&base);
        let started_after_snapshot = uuid::Uuid::new_v4().to_string();
        crate::storage::part_folders::note_located(&started_after_snapshot, &folders.current);
        let part = folders
            .current
            .join("Temp")
            .join(format!("{started_after_snapshot}.part"));
        std::fs::write(&part, b"fresh").unwrap();
        let room = format!("ember-xfer-{}", "ab".repeat(16));
        crate::storage::part_folders::note_part_owner(&room);
        let room_part = folders.current.join("Temp").join(format!("{room}.part"));
        std::fs::write(&room_part, b"fresh").unwrap();

        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
        super::sweep_orphan_part_files(&folders.roots(), &Default::default(), &db, later).await;
        assert!(part.exists());
        assert!(room_part.exists());
        drop(db);
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn reveal_finds_a_download_still_in_an_earlier_folder() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (folders, base) = approved_old_and_new_folders("reveal");
        let transfer_id = uuid::Uuid::new_v4().to_string();
        let part = folders.previous[0]
            .join("Temp")
            .join(format!("{transfer_id}.part"));
        std::fs::write(&part, b"partial-bytes").unwrap();
        let transfer: Transfer = serde_json::from_value(serde_json::json!({
            "id": transfer_id,
            "file_name": "movie.mkv",
            "file_hash": hex::encode([0x5A; 16]),
            "peer_id": "",
            "peer_name": "",
            "direction": "download",
            "status": "paused",
            "progress": 0.0,
            "speed": 0,
            "total_size": 13,
            "transferred": 0,
            "started_at": 0,
        }))
        .unwrap();

        let revealed = super::resolve_transfer_reveal_path(&transfer, &folders).unwrap();
        assert_eq!(revealed, part.canonicalize().unwrap());
        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn cancel_cleanup_deletes_part_met_when_part_is_already_gone() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (root, base) = approved_download_folder("met-only");
        let transfer_id = uuid::Uuid::new_v4().to_string();
        let met = root.join("Temp").join(format!("{transfer_id}.part.met"));
        std::fs::write(&met, b"met").unwrap();

        let db = test_db(&base);
        super::cleanup_partial_files(&db, &[root.to_string_lossy().into_owned()], &transfer_id)
            .await;

        assert!(!met.exists(), ".part.met must still be deleted if .part is missing");
        let _ = std::fs::remove_dir_all(base);
    }
}
