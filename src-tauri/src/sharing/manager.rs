use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::types::*;

/// eMule-style rolling window speed measurement.
/// Stores (cumulative_bytes, timestamp) pairs over a sliding window.
const SPEED_WINDOW_MS: u128 = 10_000;
const MAX_SPEED_SAMPLES: usize = 500;
const ACTIVE_DEGRADED_SECS: i64 = 20;
const ACTIVE_STALLED_SECS: i64 = 60;
const SEARCHING_DEGRADED_SECS: i64 = 45;
const QUEUED_DEGRADED_SECS: i64 = 300;

/// Global "preview priority for all downloads" preference (eMule's global
/// preview option). When set, [`TransferControl::is_preview_priority`] reports
/// `true` for every transfer regardless of its per-file toggle, so the
/// chunk selector front-loads each download's first and last part. Mutated
/// from the network task when settings load / change; read on the hot
/// chunk-selection path, hence a lock-free atomic.
static GLOBAL_PREVIEW_PRIORITY: AtomicBool = AtomicBool::new(false);

/// Set the global preview-priority preference. Takes effect immediately for
/// all in-flight and future downloads (next chunk selection).
pub fn set_global_preview_priority(enabled: bool) {
    GLOBAL_PREVIEW_PRIORITY.store(enabled, Ordering::Release);
}

/// Current global preview-priority preference.
#[allow(dead_code)]
pub fn global_preview_priority() -> bool {
    GLOBAL_PREVIEW_PRIORITY.load(Ordering::Acquire)
}

pub struct TransferControl {
    cancelled: AtomicBool,
    paused: AtomicBool,
    preview_priority: AtomicBool,
    /// Set by the download worker once `preview_file` would succeed for this
    /// transfer (first part verified + previewable media type). Read by
    /// [`TransferManager::get_all`] to drive the UI's Preview-button state.
    preview_ready: AtomicBool,
    /// Download priority ordinal (verylow=0 .. release=5; default normal=2),
    /// mirrored from [`Transfer::priority`] so the multi-source download worker
    /// can bias global connection-slot acquisition without a manager round-trip.
    download_priority: AtomicU8,
}

impl std::fmt::Debug for TransferControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferControl")
            .field("cancelled", &self.is_cancelled())
            .field("paused", &self.is_paused())
            .finish()
    }
}

impl TransferControl {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            cancelled: AtomicBool::new(false),
            paused: AtomicBool::new(false),
            preview_priority: AtomicBool::new(false),
            preview_ready: AtomicBool::new(false),
            download_priority: AtomicU8::new(2),
        })
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn pause(&self) {
        self.paused.store(true, Ordering::Release);
    }

    pub fn resume(&self) {
        self.paused.store(false, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }

    pub fn set_preview_priority(&self, enabled: bool) {
        self.preview_priority.store(enabled, Ordering::Release);
    }

    /// True when first/last-part prioritization should apply to this transfer:
    /// either its own per-file toggle is on, or the global "preview priority
    /// for all downloads" preference is enabled.
    pub fn is_preview_priority(&self) -> bool {
        self.preview_priority.load(Ordering::Acquire)
            || GLOBAL_PREVIEW_PRIORITY.load(Ordering::Acquire)
    }

    /// Mark whether a live preview would currently succeed (set by the worker
    /// as parts verify). Drives the UI Preview-button enablement.
    pub fn set_preview_ready(&self, ready: bool) {
        self.preview_ready.store(ready, Ordering::Release);
    }

    pub fn is_preview_ready(&self) -> bool {
        self.preview_ready.load(Ordering::Acquire)
    }

    pub fn set_download_priority_ordinal(&self, ord: u8) {
        self.download_priority.store(ord, Ordering::Release);
    }

    pub fn download_priority_ordinal(&self) -> u8 {
        self.download_priority.load(Ordering::Acquire)
    }
}

pub struct TransferManager {
    pub active: HashMap<String, Transfer>,
    pub queue: VecDeque<Transfer>,
    pub completed: Vec<Transfer>,
    pub max_concurrent: u32,
    /// Rolling speed history per transfer: VecDeque of (cumulative_bytes, Instant)
    speed_history: HashMap<String, VecDeque<(u64, Instant)>>,
    controls: HashMap<String, Arc<TransferControl>>,
    /// Per-transfer source details (eMule-style per-source tracking)
    source_details: HashMap<String, Vec<crate::types::SourceInfo>>,
}

#[derive(Debug, Clone)]
pub struct TransferHealthUpdate {
    pub id: String,
    pub health: TransferHealth,
    pub health_reason: Option<String>,
    pub stalled_since: Option<i64>,
    pub failure_reason: Option<String>,
    pub failure_kind: Option<String>,
    pub failure_stage: Option<String>,
}

pub struct SpeedReset {
    pub id: String,
}

impl TransferManager {
    pub fn new(max_concurrent: u32) -> Self {
        Self {
            active: HashMap::new(),
            queue: VecDeque::new(),
            completed: Vec::new(),
            max_concurrent,
            speed_history: HashMap::new(),
            controls: HashMap::new(),
            source_details: HashMap::new(),
        }
    }

    pub fn register_control(&mut self, id: &str, control: Arc<TransferControl>) {
        // Seed download priority from the transfer (if already known) so a
        // non-default priority chosen before the download started (e.g. restored
        // from DB) is respected by slot allocation from the first connection.
        let ord = self
            .active
            .get(id)
            .or_else(|| self.queue.iter().find(|t| t.id == id))
            .map(|t| Self::priority_ordinal(&t.priority));
        if let Some(ord) = ord {
            control.set_download_priority_ordinal(ord);
        }
        self.controls.insert(id.to_string(), control);
    }

    pub fn is_control_cancelled(&self, id: &str) -> bool {
        self.controls.get(id).map_or(false, |c| c.is_cancelled())
    }

    fn get_transfer_mut(&mut self, id: &str) -> Option<&mut Transfer> {
        if let Some(transfer) = self.active.get_mut(id) {
            Some(transfer)
        } else if let Some(transfer) = self.queue.iter_mut().find(|t| t.id == id) {
            Some(transfer)
        } else {
            self.completed.iter_mut().find(|t| t.id == id)
        }
    }

    fn clear_runtime_health(transfer: &mut Transfer) {
        transfer.health = TransferHealth::Healthy;
        transfer.health_reason = None;
        transfer.stalled_since = None;
    }

    fn clear_failure_context(transfer: &mut Transfer) {
        transfer.failure_reason = None;
        transfer.failure_kind = None;
        transfer.failure_stage = None;
    }

    fn compute_health_state(transfer: &Transfer, now: i64) -> (TransferHealth, Option<String>) {
        if transfer.direction != TransferDirection::Download {
            return (TransferHealth::Healthy, None);
        }

        match transfer.status {
            TransferStatus::Active => {
                let last_activity = transfer.last_received.unwrap_or(transfer.started_at);
                let idle_secs = now.saturating_sub(last_activity);
                if transfer.speed > 0 && idle_secs < (SPEED_WINDOW_MS / 1000) as i64 {
                    return (TransferHealth::Healthy, None);
                }
                if idle_secs >= ACTIVE_STALLED_SECS {
                    let reason = if transfer.active_sources == 0 && transfer.queued_sources > 0 {
                        "Waiting on queued sources".to_string()
                    } else if transfer.sources == 0 {
                        "Waiting for sources".to_string()
                    } else {
                        "Connected but not receiving data".to_string()
                    };
                    return (TransferHealth::Stalled, Some(reason));
                }
                if idle_secs >= ACTIVE_DEGRADED_SECS {
                    return (
                        TransferHealth::Degraded,
                        Some("Transfer is active but idle".to_string()),
                    );
                }
            }
            TransferStatus::Searching => {
                let age_secs = now.saturating_sub(transfer.started_at);
                if age_secs >= SEARCHING_DEGRADED_SECS {
                    let reason = if transfer.sources > 0 {
                        "Retrying known sources".to_string()
                    } else {
                        "Still searching for sources".to_string()
                    };
                    return (TransferHealth::Degraded, Some(reason));
                }
            }
            TransferStatus::Queued => {
                if transfer.sources == 0 {
                    return (
                        TransferHealth::Degraded,
                        Some("No sources available".to_string()),
                    );
                }
                let age_secs = now.saturating_sub(transfer.started_at);
                if age_secs >= QUEUED_DEGRADED_SECS {
                    return (
                        TransferHealth::Degraded,
                        Some("Waiting for an upload slot".to_string()),
                    );
                }
            }
            _ => {}
        }

        (TransferHealth::Healthy, None)
    }

    pub fn get_control(&self, id: &str) -> Option<Arc<TransferControl>> {
        self.controls.get(id).cloned()
    }

    fn active_download_count(&self) -> usize {
        self.active
            .values()
            .filter(|transfer| {
                transfer.direction == TransferDirection::Download
                    && !matches!(transfer.status, TransferStatus::Paused | TransferStatus::Stopped)
            })
            .count()
    }

    fn can_auto_run(transfer: &Transfer) -> bool {
        transfer.direction == TransferDirection::Download
            && !matches!(
                transfer.status,
                TransferStatus::Paused
                    | TransferStatus::Stopped
                    | TransferStatus::Completed
                    | TransferStatus::Failed
                    | TransferStatus::Hashing
                    | TransferStatus::Insufficient
                    | TransferStatus::NoneNeeded
            )
    }

    fn priority_ordinal(priority: &str) -> u8 {
        match priority {
            "release" => 5,
            "high" => 4,
            "auto" => 3,
            "normal" => 2,
            "low" => 1,
            "verylow" => 0,
            _ => 2,
        }
    }

    fn queued_wait_status(transfer: &Transfer) -> TransferStatus {
        if transfer.direction == TransferDirection::Upload {
            TransferStatus::Active
        } else if transfer.sources == 0 && transfer.queued_sources == 0 {
            TransferStatus::Searching
        } else if transfer.peer_id.is_empty() && transfer.sources == 0 {
            TransferStatus::Searching
        } else {
            TransferStatus::Queued
        }
    }

    /// After a process restart, incomplete downloads are not on the wire yet. The DB may still
    /// hold the last session's `active` status and non-zero `speed`; normalize so the UI does not
    /// show throughput until bytes actually move again.
    pub fn normalize_restored_incomplete_download(transfer: &mut Transfer) {
        if transfer.direction != TransferDirection::Download {
            return;
        }
        transfer.speed = 0;
        if matches!(
            transfer.status,
            TransferStatus::Paused | TransferStatus::Stopped
        ) {
            return;
        }
        if matches!(
            transfer.status,
            TransferStatus::Verifying | TransferStatus::Completing | TransferStatus::Hashing
        ) {
            return;
        }
        if transfer.status == TransferStatus::Active {
            transfer.status = TransferStatus::Searching;
            return;
        }
        if transfer.status == TransferStatus::Queued {
            transfer.status = TransferStatus::Searching;
        }
    }

    pub fn enqueue(&mut self, mut transfer: Transfer) -> bool {
        let id = transfer.id.clone();
        if self.active.contains_key(&id) || self.queue.iter().any(|t| t.id == id) {
            return false;
        }
        self.completed.retain(|t| t.id != id);
        if transfer.direction == TransferDirection::Upload {
            self.active.insert(id, transfer);
            return true;
        }
        if Self::can_auto_run(&transfer)
            && self.active_download_count() < self.max_concurrent as usize
        {
            self.active.insert(id, transfer);
            true
        } else {
            if !matches!(transfer.status, TransferStatus::Paused | TransferStatus::Stopped) {
                transfer.status = Self::queued_wait_status(&transfer);
            }
            self.queue.push_back(transfer);
            false
        }
    }

    pub fn has_pending_for_hash(&self, file_hash: &str) -> bool {
        self.active.values().any(|transfer| transfer.file_hash == file_hash)
            || self.queue.iter().any(|transfer| transfer.file_hash == file_hash)
    }

    pub fn pending_transfer_id_for_hash(&self, file_hash: &str) -> Option<String> {
        self.active
            .values()
            .find(|transfer| transfer.file_hash == file_hash)
            .map(|transfer| transfer.id.clone())
            .or_else(|| {
                self.queue
                    .iter()
                    .find(|transfer| transfer.file_hash == file_hash)
                    .map(|transfer| transfer.id.clone())
            })
    }

    /// eMule-style rolling window speed calculation.
    /// Maintains a history of (cumulative_bytes, timestamp) samples and computes
    /// speed as bytes_delta * 1000 / time_delta_ms over the window.
    pub fn update_progress(&mut self, id: &str, transferred: u64, _speed_hint: u64) {
        if let Some(transfer) = self.active.get_mut(id) {
            let now = Instant::now();

            let history = self.speed_history
                .entry(id.to_string())
                .or_insert_with(VecDeque::new);

            history.push_back((transferred, now));

            // Prune samples older than the rolling window
            while history.len() > MAX_SPEED_SAMPLES {
                history.pop_front();
            }
            while history.len() > 1 {
                let elapsed = now.saturating_duration_since(history.front().unwrap().1).as_millis();
                if elapsed > SPEED_WINDOW_MS {
                    history.pop_front();
                } else {
                    break;
                }
            }

            // Calculate speed from the rolling window
            let speed = if history.len() >= 2 {
                let (oldest_bytes, oldest_time) = history.front().unwrap();
                let elapsed_ms = now.saturating_duration_since(*oldest_time).as_millis();
                if elapsed_ms > 0 {
                    let bytes_delta = transferred.saturating_sub(*oldest_bytes);
                    (bytes_delta as u128 * 1000 / elapsed_ms) as u64
                } else {
                    transfer.speed
                }
            } else {
                0
            };

            transfer.transferred = if transfer.total_size > 0 { transferred.min(transfer.total_size) } else { transferred };
            transfer.completed_size = if transfer.total_size > 0 { transferred.min(transfer.total_size) } else { transferred };
            transfer.speed = speed;
            transfer.last_received = Some(chrono::Utc::now().timestamp());
            Self::clear_failure_context(transfer);
            Self::clear_runtime_health(transfer);
            if transfer.total_size > 0 {
                transfer.progress =
                    ((transferred as f64 / transfer.total_size as f64) * 100.0).min(100.0);
            }
        }
    }

    pub fn complete(&mut self, id: &str) -> Option<Vec<Transfer>> {
        let mut transfer = self.active.remove(id);
        if transfer.is_none() {
            if let Some(idx) = self.queue.iter().position(|t| t.id == id) {
                transfer = Some(self.queue.remove(idx).unwrap());
            }
        }
        if let Some(mut transfer) = transfer {
            transfer.status = TransferStatus::Completed;
            transfer.progress = 100.0;
            // Snap the byte counter to the full size ONLY for downloads. A
            // download reaches Completed after every part is hash-verified, so
            // the terminal row is by definition the whole file; without this a
            // coalesced/late final progress tick could leave `transferred`
            // (and the UI's "x / total") short even though progress is 100%.
            //
            // Uploads also flow through `complete()` (a session ending is
            // reported as Completed, matching eMule UX), but an upload session
            // almost never sends the entire file — the peer pulls a handful of
            // parts. Snapping `transferred` to `total_size` there would falsely
            // claim we uploaded the whole file this session, so we keep the real
            // per-session byte count for uploads.
            if transfer.direction == TransferDirection::Download {
                transfer.transferred = transfer.total_size;
            }
            transfer.speed = 0;
            Self::clear_failure_context(&mut transfer);
            Self::clear_runtime_health(&mut transfer);
            self.completed.push(transfer);
            if self.completed.len() > 1000 {
                self.completed.drain(..self.completed.len() - 1000);
            }
            self.speed_history.remove(id);
            self.controls.remove(id);
            self.source_details.remove(id);
            return Some(self.promote_next());
        }
        None
    }

    pub fn fail(
        &mut self,
        id: &str,
        reason: &str,
        failure_kind: Option<String>,
        failure_stage: Option<String>,
    ) -> Option<Vec<Transfer>> {
        if let Some(mut transfer) = self.active.remove(id) {
            transfer.status = TransferStatus::Failed;
            transfer.speed = 0;
            transfer.failure_reason = Some(reason.to_string());
            transfer.failure_kind = failure_kind;
            transfer.failure_stage = failure_stage;
            Self::clear_runtime_health(&mut transfer);
            self.completed.push(transfer);
            if self.completed.len() > 1000 {
                self.completed.drain(..self.completed.len() - 1000);
            }
            self.speed_history.remove(id);
            self.controls.remove(id);
            self.source_details.remove(id);
            return Some(self.promote_next());
        }
        None
    }

    pub fn update_status(&mut self, id: &str, status: TransferStatus) {
        if let Some(transfer) = self.active.get_mut(id) {
            transfer.status = status;
            if matches!(
                transfer.status,
                TransferStatus::Active
                    | TransferStatus::Verifying
                    | TransferStatus::Completing
                    | TransferStatus::Completed
            ) {
                Self::clear_failure_context(transfer);
                Self::clear_runtime_health(transfer);
            }
        } else if let Some(transfer) = self.queue.iter_mut().find(|t| t.id == id) {
            transfer.status = status;
            if matches!(transfer.status, TransferStatus::Active | TransferStatus::Completed) {
                Self::clear_failure_context(transfer);
                Self::clear_runtime_health(transfer);
            }
        }
    }

    pub fn update_sources(&mut self, id: &str, total: u32, active: u32, queued: u32) {
        if let Some(transfer) = self.get_transfer_mut(id) {
            transfer.sources = total;
            transfer.active_sources = active;
            transfer.queued_sources = queued;
        }
    }

    /// Bump the known-source total without touching live active/queued
    /// counters. Used by KAD/server discovery while a download is already
    /// running so we don't zero out the live counts the multi-source worker
    /// is actively maintaining.
    pub fn update_source_total(&mut self, id: &str, total: u32) {
        if let Some(transfer) = self.get_transfer_mut(id) {
            transfer.sources = transfer.sources.max(total);
        }
    }

    /// Update only the live active/queued counters reported by the
    /// multi-source download worker.
    pub fn update_source_live(&mut self, id: &str, active: u32, queued: u32) {
        if let Some(transfer) = self.get_transfer_mut(id) {
            transfer.active_sources = active;
            transfer.queued_sources = queued;
        }
    }

    pub fn source_counts(&self, id: &str) -> Option<(u32, u32, u32)> {
        self.get_transfer(id).map(|t| (t.sources, t.active_sources, t.queued_sources))
    }

    /// Update or insert a per-source detail entry for a transfer.
    pub fn update_source_detail(&mut self, transfer_id: &str, source: crate::types::SourceInfo) {
        let sources = self.source_details.entry(transfer_id.to_string()).or_default();
        if let Some(existing) = sources.iter_mut().find(|s| s.ip == source.ip && s.port == source.port) {
            existing.status = source.status;
            if source.queue_rank.is_some() {
                existing.queue_rank = source.queue_rank;
            }
            existing.speed = source.speed;
            existing.transferred = source.transferred;
            if !source.client_software.is_empty() {
                existing.client_software = source.client_software;
            }
            if !source.peer_name.is_empty() {
                existing.peer_name = source.peer_name;
            }
            if source.available_parts.is_some() {
                existing.available_parts = source.available_parts;
            }
            if source.total_parts.is_some() {
                existing.total_parts = source.total_parts;
            }
            if source.country_code.is_some() {
                existing.country_code = source.country_code;
            }
        } else {
            const MAX_SOURCES_PER_TRANSFER: usize = 500;
            if sources.len() >= MAX_SOURCES_PER_TRANSFER {
                let evict_idx = sources.iter()
                    .enumerate()
                    .max_by_key(|(_, s)| match s.status {
                        crate::types::SourceStatus::Failed => 4,
                        crate::types::SourceStatus::NoNeededParts => 3,
                        crate::types::SourceStatus::QueueFull => 2,
                        crate::types::SourceStatus::Completed => 1,
                        _ => 0,
                    })
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                sources.remove(evict_idx);
            }
            sources.push(source);
        }

        // eMule's "last seen complete": stamp the moment the file is seen
        // complete on the network. eMule derives it from aggregate per-part
        // availability covering every part (PartFile.cpp:3638); our SourceInfo
        // only carries an available-part *count* (no bitmap), so we use the
        // strongest signal it can express — a single source that holds every
        // part. That captures the common seeder case; partial sources that
        // only together cover 100% aren't detectable from counts alone.
        let seen_complete = sources.iter().any(|s| {
            matches!((s.available_parts, s.total_parts), (Some(a), Some(t)) if t > 0 && a >= t)
        });
        if seen_complete {
            if let Some(transfer) = self.active.get_mut(transfer_id) {
                transfer.last_seen_complete = Some(chrono::Utc::now().timestamp());
            }
        }
    }

    /// Get all source details for a transfer.
    pub fn get_source_details(&self, transfer_id: &str) -> Vec<crate::types::SourceInfo> {
        self.source_details.get(transfer_id).cloned().unwrap_or_default()
    }

    fn is_callback_placeholder_row(s: &crate::types::SourceInfo) -> bool {
        matches!(
            s.status,
            crate::types::SourceStatus::Connecting | crate::types::SourceStatus::WaitCallback
        ) && matches!(
            s.client_software.as_str(),
            "KAD Callback" | "KAD Direct Callback" | "Low ID (Server Relay)"
        )
    }

    /// True if `transfer_id` has any source-detail row for `peer_ip`,
    /// regardless of port or status. Used by the KAD-search-completion
    /// path to skip re-adding a "KAD Callback" placeholder when the
    /// peer has *any* representation — placeholder from an earlier
    /// cycle, or the real `(ip, ephemeral_port)` row that the
    /// successful callback installed. Without this guard, every
    /// ~45s search cycle would reinstall the placeholder alongside
    /// the already-connected real row, producing duplicate UI
    /// entries for the same peer.
    pub fn has_source_detail_for_ip(&self, transfer_id: &str, peer_ip: &str) -> bool {
        self.source_details
            .get(transfer_id)
            .map(|rows| rows.iter().any(|s| s.ip == peer_ip))
            .unwrap_or(false)
    }

    /// Remove any KAD-callback / direct-callback / server-relay
    /// placeholder rows for `transfer_id` whose IP matches `peer_ip`.
    /// Called when the real LowID peer connects back to us — the
    /// live connection carries the peer's *ephemeral* outgoing port
    /// (not the listed listening port we stored in the placeholder),
    /// so the real source-detail row appears under a different
    /// `(ip, port)` key than the placeholder. Removing the stale
    /// placeholder prevents the UI from showing two rows for the
    /// same peer — one permanently "Connecting" next to another
    /// that's "Transferring" or "Queued".
    ///
    /// We only remove rows still in the `Connecting` state so we
    /// never discard a row that has already transitioned to a
    /// real transfer state (defensive: shouldn't happen for
    /// placeholders, but cheap to check).
    ///
    /// Returns the `(ip, port)` pairs that were removed so the
    /// caller can emit matching frontend events signalling the
    /// row has gone away.
    pub fn remove_callback_placeholders_for_ip(
        &mut self,
        transfer_id: &str,
        peer_ip: &str,
    ) -> Vec<(String, u16)> {
        self.remove_callback_placeholders_for_ip_except(transfer_id, peer_ip, None)
    }

    /// Same as [`remove_callback_placeholders_for_ip`], but skips the row
    /// whose port equals `except_port`. Called from the central
    /// `SourceDetail` handler when a live peer row arrives — we want
    /// to drop stale placeholders that share the IP but we must NOT
    /// drop the very row the caller is about to insert/update at
    /// `(peer_ip, except_port)` when it happens to match a placeholder
    /// port (e.g. the peer's ephemeral outbound port randomly coincided
    /// with its advertised listening port). Passing `None` means
    /// "remove all placeholder rows for this IP", matching the
    /// behaviour of the `kad_callback_rx` callers that know for a
    /// fact the live row landed on a different port.
    /// Remove one specific placeholder row at `(transfer_id, peer_ip, peer_port)`
    /// if it is still in the placeholder shape (status=Connecting AND
    /// one of the three placeholder client labels). Returns `true` if
    /// the row was removed, `false` if no matching row exists or the
    /// row has already transitioned out of placeholder shape (e.g. a
    /// late callback just turned it into a real Queued row — we must
    /// NOT drop that). Called by the periodic stale-placeholder
    /// sweep in `source_retry_timer`.
    pub fn remove_placeholder_row(
        &mut self,
        transfer_id: &str,
        peer_ip: &str,
        peer_port: u16,
    ) -> bool {
        let mut removed = false;
        if let Some(rows) = self.source_details.get_mut(transfer_id) {
            rows.retain(|s| {
                let is_expired_placeholder = s.ip == peer_ip
                    && s.port == peer_port
                    && Self::is_callback_placeholder_row(s);
                if is_expired_placeholder {
                    removed = true;
                    false
                } else {
                    true
                }
            });
        }
        removed
    }

    pub fn remove_callback_placeholders_for_ip_except(
        &mut self,
        transfer_id: &str,
        peer_ip: &str,
        except_port: Option<u16>,
    ) -> Vec<(String, u16)> {
        let mut removed = Vec::new();
        if let Some(rows) = self.source_details.get_mut(transfer_id) {
            rows.retain(|s| {
                let is_placeholder = s.ip == peer_ip
                    && Self::is_callback_placeholder_row(s)
                    && Some(s.port) != except_port;
                if is_placeholder {
                    removed.push((s.ip.clone(), s.port));
                    false
                } else {
                    true
                }
            });
        }
        removed
    }

    pub fn pause(&mut self, id: &str) {
        if let Some(transfer) = self.active.get_mut(id) {
            transfer.status = TransferStatus::Paused;
            transfer.speed = 0;
            Self::clear_runtime_health(transfer);
        } else if let Some(transfer) = self.queue.iter_mut().find(|t| t.id == id) {
            transfer.status = TransferStatus::Paused;
            Self::clear_runtime_health(transfer);
        }
        if let Some(control) = self.controls.get(id) {
            control.pause();
        }
        // Pause tears down all peer connections for this transfer, so
        // the per-source detail rows (status=Connecting / Queued /
        // Transferring) no longer reflect live state — keeping them
        // would show the user "31 sources, 6 transferring" for a
        // transfer that has zero live peers. Clear the backend list
        // so the next pull (or resume) rebuilds it from reality. This
        // matches what `stop()` and `cancel()` already do below.
        self.source_details.remove(id);
    }

    /// Pause a transfer and, if this frees an active download slot, promote
    /// the next queued download immediately.
    pub fn pause_and_promote(&mut self, id: &str) -> Vec<Transfer> {
        let mut freed_active_download_slot = false;
        if let Some(transfer) = self.active.get_mut(id) {
            freed_active_download_slot = transfer.direction == TransferDirection::Download
                && !matches!(transfer.status, TransferStatus::Paused | TransferStatus::Stopped);
        }
        self.pause(id);
        if freed_active_download_slot {
            self.promote_next()
        } else {
            Vec::new()
        }
    }

    /// eMule "Stop": remove from active scheduling without deleting partial data.
    pub fn stop(&mut self, id: &str) -> Vec<Transfer> {
        if let Some(control) = self.controls.get(id) {
            control.cancel();
        }
        self.controls.remove(id);
        if let Some(mut transfer) = self.active.remove(id) {
            transfer.status = TransferStatus::Stopped;
            transfer.speed = 0;
            Self::clear_runtime_health(&mut transfer);
            self.speed_history.remove(id);
            self.source_details.remove(id);
            self.queue.push_front(transfer);
            return self.promote_next();
        }
        if let Some(transfer) = self.queue.iter_mut().find(|t| t.id == id) {
            transfer.status = TransferStatus::Stopped;
            Self::clear_runtime_health(transfer);
        }
        Vec::new()
    }

    pub fn resume(&mut self, id: &str) -> Vec<Transfer> {
        if let Some(transfer) = self.active.get_mut(id) {
            if transfer.status == TransferStatus::Paused {
                transfer.status = TransferStatus::Active;
                Self::clear_failure_context(transfer);
                Self::clear_runtime_health(transfer);
            }
            if let Some(control) = self.controls.get(id) {
                control.resume();
            }
            return Vec::new();
        }
        if let Some(idx) = self.queue.iter().position(|t| t.id == id) {
            let Some(mut transfer) = self.queue.remove(idx) else {
                tracing::error!("Queue index {idx} invalid after position() - skipping");
                return Vec::new();
            };
            transfer.status = Self::queued_wait_status(&transfer);
            Self::clear_runtime_health(&mut transfer);
            if let Some(control) = self.controls.get(id) {
                control.resume();
            }
            if transfer.direction == TransferDirection::Upload {
                transfer.status = TransferStatus::Active;
                let promoted = transfer.clone();
                self.active.insert(transfer.id.clone(), transfer);
                return vec![promoted];
            }
            if self.active_download_count() < self.max_concurrent as usize {
                let promoted = transfer.clone();
                self.active.insert(transfer.id.clone(), transfer);
                return vec![promoted];
            }
            self.queue.push_back(transfer);
        }
        if let Some(control) = self.controls.get(id) {
            control.resume();
        }
        Vec::new()
    }

    pub fn cancel(&mut self, id: &str) -> Vec<Transfer> {
        if let Some(control) = self.controls.get(id) {
            control.cancel();
        }
        self.active.remove(id);
        self.queue.retain(|t| t.id != id);
        self.controls.remove(id);
        self.speed_history.remove(id);
        self.source_details.remove(id);
        self.promote_next()
    }

    pub fn remove(&mut self, id: &str) -> Vec<Transfer> {
        if let Some(control) = self.controls.get(id) {
            control.cancel();
        }
        let was_active = self.active.remove(id).is_some();
        self.queue.retain(|t| t.id != id);
        self.completed.retain(|t| t.id != id);
        self.controls.remove(id);
        self.speed_history.remove(id);
        self.source_details.remove(id);
        if was_active {
            self.promote_next()
        } else {
            Vec::new()
        }
    }

    pub fn set_priority(&mut self, id: &str, priority: &str) {
        if let Some(transfer) = self.active.get_mut(id) {
            transfer.priority = priority.to_string();
        } else if let Some(transfer) = self.queue.iter_mut().find(|t| t.id == id) {
            transfer.priority = priority.to_string();
        }
        // Mirror onto the live control so an active download's connection-slot
        // allocation priority takes effect immediately (no restart needed).
        if let Some(control) = self.controls.get(id) {
            control.set_download_priority_ordinal(Self::priority_ordinal(priority));
        }
    }

    pub fn set_category(&mut self, id: &str, category: &str) {
        if let Some(transfer) = self.active.get_mut(id) {
            transfer.category = category.to_string();
        } else if let Some(transfer) = self.queue.iter_mut().find(|t| t.id == id) {
            transfer.category = category.to_string();
        } else if let Some(transfer) = self.completed.iter_mut().find(|t| t.id == id) {
            transfer.category = category.to_string();
        }
    }

    pub fn set_preview_priority(&mut self, id: &str, enabled: bool) {
        if let Some(transfer) = self.active.get_mut(id) {
            transfer.preview_priority = enabled;
        } else if let Some(transfer) = self.queue.iter_mut().find(|t| t.id == id) {
            transfer.preview_priority = enabled;
        }
        if let Some(control) = self.controls.get(id) {
            control.set_preview_priority(enabled);
        }
    }

    pub fn set_failure_context(
        &mut self,
        id: &str,
        reason: Option<String>,
        failure_kind: Option<String>,
        failure_stage: Option<String>,
    ) {
        if let Some(transfer) = self.get_transfer_mut(id) {
            transfer.failure_reason = reason;
            transfer.failure_kind = failure_kind;
            transfer.failure_stage = failure_stage;
        }
    }

    pub fn set_health_state(
        &mut self,
        id: &str,
        health: TransferHealth,
        reason: Option<String>,
        now: i64,
    ) -> Option<TransferHealthUpdate> {
        let transfer = self.get_transfer_mut(id)?;
        let previous = (
            transfer.health.clone(),
            transfer.health_reason.clone(),
            transfer.stalled_since,
        );
        transfer.health = health;
        transfer.health_reason = reason;
        transfer.stalled_since = if transfer.health == TransferHealth::Stalled {
            Some(previous.2.unwrap_or(now))
        } else {
            None
        };
        if previous == (transfer.health.clone(), transfer.health_reason.clone(), transfer.stalled_since) {
            return None;
        }
        Some(TransferHealthUpdate {
            id: transfer.id.clone(),
            health: transfer.health.clone(),
            health_reason: transfer.health_reason.clone(),
            stalled_since: transfer.stalled_since,
            failure_reason: transfer.failure_reason.clone(),
            failure_kind: transfer.failure_kind.clone(),
            failure_stage: transfer.failure_stage.clone(),
        })
    }

    pub fn refresh_health(&mut self, now: i64) -> (Vec<TransferHealthUpdate>, Vec<SpeedReset>) {
        let mut updates = Vec::new();
        let mut speed_resets = Vec::new();
        let stale_threshold = (SPEED_WINDOW_MS / 1000) as i64;

        for transfer in self.active.values_mut() {
            // Decay `speed` to 0 on both directions once no progress event
            // has landed within the speed-averaging window. Without this,
            // upload rows froze their displayed speed forever after a peer
            // stopped requesting blocks: `update_progress` is only called
            // when bytes actually move, so the row retained its last-known
            // rate with no natural path back to 0. Previously this branch
            // was gated on `direction == Download`, which silently skipped
            // uploads — a contributor to the "uploads appear frozen" UX.
            if transfer.speed > 0 {
                let last_activity = transfer.last_received.unwrap_or(transfer.started_at);
                if now.saturating_sub(last_activity) > stale_threshold {
                    speed_resets.push(SpeedReset {
                        id: transfer.id.clone(),
                    });
                    transfer.speed = 0;
                }
            }

            let previous = (
                transfer.health.clone(),
                transfer.health_reason.clone(),
                transfer.stalled_since,
            );
            let (health, reason) = Self::compute_health_state(transfer, now);
            transfer.health = health;
            transfer.health_reason = reason;
            transfer.stalled_since = if transfer.health == TransferHealth::Stalled {
                Some(previous.2.unwrap_or(now))
            } else {
                None
            };
            let current = (
                transfer.health.clone(),
                transfer.health_reason.clone(),
                transfer.stalled_since,
            );
            if previous != current {
                updates.push(TransferHealthUpdate {
                    id: transfer.id.clone(),
                    health: transfer.health.clone(),
                    health_reason: transfer.health_reason.clone(),
                    stalled_since: transfer.stalled_since,
                    failure_reason: transfer.failure_reason.clone(),
                    failure_kind: transfer.failure_kind.clone(),
                    failure_stage: transfer.failure_stage.clone(),
                });
            }
        }

        for transfer in self.queue.iter_mut() {
            let previous = (
                transfer.health.clone(),
                transfer.health_reason.clone(),
                transfer.stalled_since,
            );
            let (health, reason) = Self::compute_health_state(transfer, now);
            transfer.health = health;
            transfer.health_reason = reason;
            transfer.stalled_since = if transfer.health == TransferHealth::Stalled {
                Some(previous.2.unwrap_or(now))
            } else {
                None
            };
            let current = (
                transfer.health.clone(),
                transfer.health_reason.clone(),
                transfer.stalled_since,
            );
            if previous != current {
                updates.push(TransferHealthUpdate {
                    id: transfer.id.clone(),
                    health: transfer.health.clone(),
                    health_reason: transfer.health_reason.clone(),
                    stalled_since: transfer.stalled_since,
                    failure_reason: transfer.failure_reason.clone(),
                    failure_kind: transfer.failure_kind.clone(),
                    failure_stage: transfer.failure_stage.clone(),
                });
            }
        }

        for sr in &speed_resets {
            self.speed_history.remove(&sr.id);
        }

        (updates, speed_resets)
    }

    pub fn get_all(&self) -> Vec<Transfer> {
        let mut all: Vec<Transfer> = self.active.values().cloned().collect();
        all.extend(self.queue.iter().cloned());
        all.extend(self.completed.iter().cloned());
        // Overlay live preview-readiness from each transfer's control. The
        // stored `Transfer` snapshot doesn't track verification; the worker
        // publishes it onto the control as parts verify, so we read it here at
        // snapshot time to keep the UI's Preview button in sync.
        for t in &mut all {
            if let Some(control) = self.controls.get(&t.id) {
                t.preview_ready = control.is_preview_ready();
            }
        }
        all
    }

    pub fn get_transfer(&self, id: &str) -> Option<&Transfer> {
        self.active.get(id)
            .or_else(|| self.queue.iter().find(|t| t.id == id))
            .or_else(|| self.completed.iter().find(|t| t.id == id))
    }

    /// Update the concurrent-download cap and promote any queued downloads
    /// that the new cap now permits. Returns the newly promoted transfers so
    /// the caller can start them (empty when the cap was lowered or no queued
    /// download is eligible).
    pub fn set_max_concurrent(&mut self, max: u32) -> Vec<Transfer> {
        self.max_concurrent = max;
        self.promote_next()
    }

    fn promote_next(&mut self) -> Vec<Transfer> {
        let mut promoted = Vec::new();
        loop {
            if self.active_download_count() >= self.max_concurrent as usize {
                break;
            }
            let next_idx = self.queue.iter()
                .enumerate()
                .filter(|(_, t)| Self::can_auto_run(t))
                .max_by(|(i_a, a), (i_b, b)| {
                    Self::priority_ordinal(&a.priority)
                        .cmp(&Self::priority_ordinal(&b.priority))
                        .then(i_b.cmp(i_a))
                })
                .map(|(i, _)| i);
            let Some(idx) = next_idx else { break };
            let Some(mut transfer) = self.queue.remove(idx) else {
                tracing::error!("Queue index {idx} invalid during promotion - skipping");
                break;
            };
            transfer.status = Self::queued_wait_status(&transfer);
            let t = transfer.clone();
            self.active.insert(transfer.id.clone(), transfer);
            promoted.push(t);
        }
        promoted
    }
}
