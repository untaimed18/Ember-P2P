use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::network::ed2k::transfer::TransferFailureCode;
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

pub struct TransferControl {
    cancelled: AtomicBool,
    /// Set only when this transfer's `.part` is about to be deleted (Cancel /
    /// Remove from List), never on Pause or Stop. Handed to the part-file
    /// writer so it can drop its handle without the trailing fsync — see
    /// [`TransferControl::discard`].
    discarding: Arc<AtomicBool>,
    paused: AtomicBool,
    cancel_notify: tokio::sync::Notify,
    pause_notify: tokio::sync::Notify,
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
            discarding: Arc::new(AtomicBool::new(false)),
            paused: AtomicBool::new(false),
            cancel_notify: tokio::sync::Notify::new(),
            pause_notify: tokio::sync::Notify::new(),
            preview_priority: AtomicBool::new(false),
            preview_ready: AtomicBool::new(false),
            download_priority: AtomicU8::new(2),
        })
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.cancel_notify.notify_waiters();
    }

    pub fn pause(&self) {
        self.paused.store(true, Ordering::Release);
        // Wake any per-source data loop parked on `wait_cancel_or_pause` so it
        // can send a graceful OP_CANCELTRANSFER to its peer (eMule's
        // CPartFile::PauseFile notifies every DS_DOWNLOADING source) before the
        // worker is torn down by the `PauseDownload` network command.
        self.pause_notify.notify_waiters();
    }

    pub fn resume(&self) {
        self.paused.store(false, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Cancel *and* mark this transfer's `.part` as about to be deleted.
    ///
    /// Only for Cancel and Remove-from-List. Pause and Stop must use
    /// [`TransferControl::cancel`]: they keep the `.part` and its `.part.met`
    /// for resume, so the writer still has to drain its queue and fsync.
    /// Discarding skips both, which is what lets Windows delete the file
    /// instead of failing on a handle held open by a multi-GB fsync.
    pub fn discard(&self) {
        self.discarding.store(true, Ordering::Release);
        self.cancel();
    }

    /// Clone of the discard flag for the part-file writer, which runs on a
    /// std thread and cannot await `wait_cancelled`.
    pub fn discarding_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.discarding)
    }

    /// Resolves as soon as the control is cancelled. Used by network tasks
    /// that may be parked in socket I/O: checking `is_cancelled()` between
    /// reads is not enough for an immediate Stop/Disconnect because a pending
    /// read can wait until its timeout. Racing the transfer future against this
    /// notification lets the task drop the socket future immediately.
    pub async fn wait_cancelled(&self) {
        loop {
            // Register the waiter BEFORE checking the flag. `Notify` only
            // wakes already-registered waiters and stores no permit, so a
            // `notify_waiters()` that races the flag check would otherwise be
            // lost — leaving a task parked on a long socket read until it
            // times out. `enable()` arms the future so any cancel after this
            // point is observed by the `.await` below.
            let notified = self.cancel_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
            if self.is_cancelled() {
                return;
            }
        }
    }

    /// Resolves as soon as the control is cancelled **or** paused. The
    /// per-source data-receive loop races its socket read against this so that,
    /// on either a user Stop/Cancel or a user Pause, it can send
    /// OP_CANCELTRANSFER to the peer it is actively downloading from before the
    /// task unwinds — mirroring eMule's `CPartFile::PauseFile`, which walks its
    /// source list and notifies every `DS_DOWNLOADING` peer so the uploader
    /// frees our slot immediately instead of waiting to notice a dropped
    /// socket. Pause keeps the transfer's source knowledge (so resume is fast);
    /// only the active wire transfer is told to stop.
    pub async fn wait_cancel_or_pause(&self) {
        loop {
            // Arm both waiters BEFORE re-checking the flags so a
            // `notify_waiters()` racing the check is not lost (see
            // `wait_cancelled` for the full rationale).
            let cancelled = self.cancel_notify.notified();
            let paused = self.pause_notify.notified();
            tokio::pin!(cancelled, paused);
            cancelled.as_mut().enable();
            paused.as_mut().enable();
            if self.is_cancelled() || self.is_paused() {
                return;
            }
            tokio::select! {
                _ = cancelled => {}
                _ = paused => {}
            }
            if self.is_cancelled() || self.is_paused() {
                return;
            }
        }
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

/// Declares the closed set of health explanations a download row can show,
/// each bound to a stable code.
///
/// Same split, and the same reasons, as `TransferFailureCode` in
/// `network::ed2k::transfer`: the English is for logs and for a UI older than
/// the backend, the code is what the UI translates.
/// `scripts/backend-codes.test.mjs` parses this table to require a translation
/// in all nine locales before a new variant can ship.
macro_rules! transfer_health_codes {
    ($($variant:ident => $code:literal, $message:literal;)+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum TransferHealthCode {
            $($variant,)+
        }

        impl TransferHealthCode {
            /// Every variant, in declaration order. Test-only: production code
            /// always has a variant in hand.
            #[cfg(test)]
            pub const ALL: &'static [TransferHealthCode] = &[$(TransferHealthCode::$variant,)+];

            /// Stable identifier carried to the UI as `Transfer::health_code`.
            pub fn as_code(self) -> &'static str {
                match self {
                    $(Self::$variant => $code,)+
                }
            }

            /// English rendering, stored in `Transfer::health_reason`.
            /// `{reason}` is filled from the row's failure code.
            pub fn message(self) -> &'static str {
                match self {
                    $(Self::$variant => $message,)+
                }
            }
        }
    };
}

transfer_health_codes! {
    QueuedSources => "queued_sources", "Waiting on queued sources";
    WaitingSources => "waiting_sources", "Waiting for sources";
    NoData => "no_data", "Connected but not receiving data";
    Idle => "idle", "Transfer is active but idle";
    RetryingSources => "retrying_sources", "Retrying known sources";
    StillSearching => "still_searching", "Still searching for sources";
    NoSources => "no_sources", "No sources available";
    WaitingSlot => "waiting_slot", "Waiting for an upload slot";
    RetryingAfter => "retrying_after", "Retrying after {reason}";
}

impl TransferHealthCode {
    /// The composed English for [`Self::RetryingAfter`]. The tail is the
    /// case-flattened failure the retry is reacting to, which the row also
    /// carries as `failure_code` — so the UI recomposes it from two translated
    /// halves rather than needing a message per failure.
    pub fn retrying_after(failure: TransferFailureCode) -> String {
        Self::RetryingAfter
            .message()
            .replace("{reason}", &failure.message().to_lowercase())
    }
}

#[derive(Debug, Clone)]
pub struct TransferHealthUpdate {
    pub id: String,
    pub health: TransferHealth,
    pub health_reason: Option<String>,
    pub health_code: Option<String>,
    pub stalled_since: Option<i64>,
    pub failure_reason: Option<String>,
    pub failure_code: Option<String>,
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
        self.controls.get(id).is_some_and(|c| c.is_cancelled())
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
        transfer.health_code = None;
        transfer.stalled_since = None;
    }

    fn clear_failure_context(transfer: &mut Transfer) {
        transfer.failure_reason = None;
        transfer.failure_code = None;
        transfer.failure_kind = None;
        transfer.failure_stage = None;
    }

    /// Write a health verdict onto a row, keeping `health_reason` and
    /// `health_code` derived from the same variant.
    fn apply_health_code(transfer: &mut Transfer, code: Option<TransferHealthCode>) {
        transfer.health_reason = code.map(|c| c.message().to_string());
        transfer.health_code = code.map(|c| c.as_code().to_string());
    }

    fn compute_health_state(
        transfer: &Transfer,
        now: i64,
    ) -> (TransferHealth, Option<TransferHealthCode>) {
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
                    let code = if transfer.active_sources == 0 && transfer.queued_sources > 0 {
                        TransferHealthCode::QueuedSources
                    } else if transfer.sources == 0 {
                        TransferHealthCode::WaitingSources
                    } else {
                        TransferHealthCode::NoData
                    };
                    return (TransferHealth::Stalled, Some(code));
                }
                if idle_secs >= ACTIVE_DEGRADED_SECS {
                    return (TransferHealth::Degraded, Some(TransferHealthCode::Idle));
                }
            }
            TransferStatus::Searching => {
                let age_secs = now.saturating_sub(transfer.started_at);
                if age_secs >= SEARCHING_DEGRADED_SECS {
                    let code = if transfer.sources > 0 {
                        TransferHealthCode::RetryingSources
                    } else {
                        TransferHealthCode::StillSearching
                    };
                    return (TransferHealth::Degraded, Some(code));
                }
            }
            TransferStatus::Queued => {
                if transfer.sources == 0 {
                    return (TransferHealth::Degraded, Some(TransferHealthCode::NoSources));
                }
                let age_secs = now.saturating_sub(transfer.started_at);
                if age_secs >= QUEUED_DEGRADED_SECS {
                    return (
                        TransferHealth::Degraded,
                        Some(TransferHealthCode::WaitingSlot),
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

    pub(crate) fn active_download_count(&self) -> usize {
        self.active
            .values()
            .filter(|transfer| {
                transfer.direction == TransferDirection::Download
                    && !matches!(
                        transfer.status,
                        TransferStatus::Paused
                            | TransferStatus::Stopped
                            // Disk-full rows stay visible but must not block the
                            // concurrent slot budget (T2).
                            | TransferStatus::Insufficient
                    )
            })
            .count()
    }

    /// Promote queued downloads into free concurrent slots.
    pub fn promote_available(&mut self) -> Vec<Transfer> {
        self.promote_next()
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
        // Nothing found at all, or nothing found and nobody to ask.
        } else if (transfer.sources == 0 && transfer.queued_sources == 0)
            || (transfer.peer_id.is_empty() && transfer.sources == 0)
        {
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
            TransferStatus::Paused | TransferStatus::Stopped | TransferStatus::Insufficient
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
        // Keep Insufficient in `active` (eMule ResumeFileInsufficient) so
        // Resume finds the row, the orphan `.part` sweep knows the UUID,
        // and we never rewrite the status to Searching/Queued.
        if transfer.status == TransferStatus::Insufficient {
            self.active.insert(id, transfer);
            return false;
        }
        if Self::can_auto_run(&transfer)
            && self.active_download_count() < self.max_concurrent as usize
        {
            self.active.insert(id, transfer);
            true
        } else {
            if !matches!(
                transfer.status,
                TransferStatus::Paused | TransferStatus::Stopped
            ) {
                transfer.status = Self::queued_wait_status(&transfer);
            }
            self.queue.push_back(transfer);
            false
        }
    }

    pub fn has_pending_for_hash(&self, file_hash: &str) -> bool {
        self.active
            .values()
            .any(|transfer| transfer.file_hash == file_hash)
            || self
                .queue
                .iter()
                .any(|transfer| transfer.file_hash == file_hash)
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
    ///
    /// `unique_completed` is upload-only unique per-part coverage. Downloads
    /// pass `None` and derive `completed_size` / `progress` from `transferred`.
    pub fn update_progress(&mut self, id: &str, transferred: u64, unique_completed: Option<u64>) {
        if let Some(transfer) = self.active.get_mut(id) {
            let now = Instant::now();

            let history = self
                .speed_history
                .entry(id.to_string())
                .or_default();

            history.push_back((transferred, now));

            // Prune samples older than the rolling window
            while history.len() > MAX_SPEED_SAMPLES {
                history.pop_front();
            }
            while history.len() > 1 {
                let elapsed = now
                    .saturating_duration_since(history.front().unwrap().1)
                    .as_millis();
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
                let bytes_delta = transferred.saturating_sub(*oldest_bytes);
                (bytes_delta as u128 * 1000)
                    .checked_div(elapsed_ms)
                    .map_or(transfer.speed, |bytes_per_sec| bytes_per_sec as u64)
            } else {
                0
            };

            // Uploads: `transferred` is cumulative session wire bytes
            // (eMule GetTransferred) and routinely exceeds `total_size`
            // when the peer re-requests overlapping blocks. Capping it
            // made the UI claim the whole file had been sent while unique
            // coverage — and the parts bar — was still halfway.
            // `unique_completed` is that coverage and drives `completed_size`
            // / `progress`. Downloads: cap at `total_size` so a coalesced
            // tick cannot report more than the file.
            let is_upload = transfer.direction == TransferDirection::Upload;
            if is_upload {
                transfer.transferred = transferred;
                if let Some(unique) = unique_completed {
                    let unique_capped = if transfer.total_size > 0 {
                        unique.min(transfer.total_size)
                    } else {
                        unique
                    };
                    transfer.completed_size = unique_capped;
                    if transfer.total_size > 0 {
                        transfer.progress = ((unique_capped as f64 / transfer.total_size as f64)
                            * 100.0)
                            .min(100.0);
                    }
                }
            } else if transfer.total_size > 0 {
                transfer.transferred = transferred.min(transfer.total_size);
                transfer.completed_size = transfer.transferred;
            } else {
                transfer.transferred = transferred;
                transfer.completed_size = transferred;
            }
            transfer.speed = speed;
            transfer.last_received = Some(chrono::Utc::now().timestamp());
            Self::clear_failure_context(transfer);
            Self::clear_runtime_health(transfer);
            if !is_upload && transfer.total_size > 0 {
                transfer.progress =
                    ((transferred as f64 / transfer.total_size as f64) * 100.0).min(100.0);
            }
        }
    }

    /// Record the actual on-disk destination of a finished download so the
    /// Open/Reveal commands can target it directly. Call this while the row is
    /// still in `active`/`queue` (before [`complete`](Self::complete) moves it).
    pub fn set_completed_path(&mut self, id: &str, path: String) {
        if let Some(t) = self.get_transfer_mut(id) {
            t.completed_path = Some(path);
        }
    }

    /// Records whether `DownloadEvent::Completed` actually re-checked this
    /// download's Ember content BLAKE3 hash and matched it, so the Transfers
    /// UI can show a badge for a check that ran rather than inferring one
    /// from `expected_aich`-style presence (which the crash-recovery
    /// re-verify paths would get wrong, since they skip the Ember check).
    pub fn set_ember_verified(&mut self, id: &str, verified: bool) {
        if let Some(t) = self.get_transfer_mut(id) {
            t.ember_verified = verified;
        }
    }

    pub fn complete(&mut self, id: &str) -> Option<Vec<Transfer>> {
        let mut transfer = self.active.remove(id);
        if transfer.is_none() {
            transfer = self
                .queue
                .iter()
                .position(|t| t.id == id)
                .and_then(|idx| self.queue.remove(idx));
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
                transfer.completed_size = transfer.total_size;
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

    /// Move a row to Failed. Takes the code rather than a sentence so a
    /// failure cannot reach the UI without a discriminator to translate.
    pub fn fail(
        &mut self,
        id: &str,
        failure: TransferFailureCode,
        failure_kind: Option<String>,
        failure_stage: Option<String>,
    ) -> Option<Vec<Transfer>> {
        let mut transfer = match self.active.remove(id) {
            Some(t) => t,
            None => {
                // Stopped/queued rows live in `queue`; still move them into
                // completed so Stop/cancel races don't leave a Failed queue
                // entry without the normal Failed lifecycle.
                let pos = self.queue.iter().position(|t| t.id == id)?;
                self.queue.remove(pos).unwrap()
            }
        };
        transfer.status = TransferStatus::Failed;
        transfer.speed = 0;
        transfer.failure_reason = Some(failure.message().to_string());
        transfer.failure_code = Some(failure.as_code().to_string());
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
        Some(self.promote_next())
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
            if matches!(
                transfer.status,
                TransferStatus::Active | TransferStatus::Completed
            ) {
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
            // Replace, don't ratchet upward forever — discovery can shrink
            // when sources expire or a file loses availability.
            transfer.sources = total;
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
        self.get_transfer(id)
            .map(|t| (t.sources, t.active_sources, t.queued_sources))
    }

    /// Update or insert a per-source detail entry for a transfer.
    pub fn update_source_detail(&mut self, transfer_id: &str, source: crate::types::SourceInfo) {
        let sources = self
            .source_details
            .entry(transfer_id.to_string())
            .or_default();
        if let Some(existing) = sources
            .iter_mut()
            .find(|s| s.ip == source.ip && s.port == source.port)
        {
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
            // Backfill the peer identity if we learn it later (e.g. the row
            // was seeded from a hash-less server source list, then the live
            // handshake taught us the user hash). Never downgrade a known
            // identity to `None`.
            if source.user_hash.is_some() {
                existing.user_hash = source.user_hash;
            }
        } else {
            const MAX_SOURCES_PER_TRANSFER: usize = 500;
            if sources.len() >= MAX_SOURCES_PER_TRANSFER {
                let evict_idx = sources
                    .iter()
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
        let seen_complete = sources.iter().any(
            |s| matches!((s.available_parts, s.total_parts), (Some(a), Some(t)) if t > 0 && a >= t),
        );
        if seen_complete {
            if let Some(transfer) = self.active.get_mut(transfer_id) {
                transfer.last_seen_complete = Some(chrono::Utc::now().timestamp());
            }
        }
    }

    /// Get all source details for a transfer.
    pub fn get_source_details(&self, transfer_id: &str) -> Vec<crate::types::SourceInfo> {
        self.source_details
            .get(transfer_id)
            .cloned()
            .unwrap_or_default()
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
                let is_expired_placeholder =
                    s.ip == peer_ip && s.port == peer_port && Self::is_callback_placeholder_row(s);
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

    /// Collapse duplicate rows for the peer whose *live* connection is
    /// reported at `(live_ip, live_port)` into that single row, mirroring
    /// eMule's one-`CUpDownClient`-per-peer model (`CUpDownClient::Compare`,
    /// which matches by user hash first).
    ///
    /// A peer discovered via the server/KAD/source-exchange is seeded at its
    /// *advertised listening* port (or, for a KAD callback, under a synthetic
    /// display key), but when it is a LowID/KAD/server callback or a Path-B
    /// push-grant reconnect, the live connection lands on the peer's
    /// *ephemeral* outbound port — a different `(ip, port)`/key — so the UI
    /// would otherwise show two rows for the same peer (one stuck
    /// "Connecting"/"Queued", one actually transferring). This removes the
    /// other rows that represent the same peer:
    ///   * any row carrying the same user hash (the peer's stable identity),
    ///     regardless of its port or IP-key — this is the primary, precise
    ///     match and is what coalesces the ephemeral live row with the
    ///     discovery/placeholder row even when they were keyed differently;
    ///   * any callback *placeholder* row (KAD/direct/server-relay) at the
    ///     same IP, matching the pre-existing callback-cleanup behaviour.
    ///
    /// We deliberately do NOT drop a hash-less non-callback row just because it
    /// shares the IP: that would remove a *distinct* peer behind the same NAT.
    ///
    /// The live row itself (`live_ip:live_port`) is always kept. Returns the
    /// `(ip, port)` pairs removed so the caller can emit matching
    /// `transfer-source-detail` `status:"failed"` events (the frontend keys
    /// rows by `(ip, port)` and drops them on that terminal status).
    pub fn supersede_duplicate_peer_rows(
        &mut self,
        transfer_id: &str,
        live_ip: &str,
        live_port: u16,
        live_user_hash: Option<[u8; 16]>,
    ) -> Vec<(String, u16)> {
        let uh = live_user_hash.filter(|h| *h != [0u8; 16]);
        let mut removed = Vec::new();
        if let Some(rows) = self.source_details.get_mut(transfer_id) {
            rows.retain(|s| {
                // Never drop the live row we're keeping.
                if s.ip == live_ip && s.port == live_port {
                    return true;
                }
                let same_peer_by_hash = matches!((uh, s.user_hash), (Some(a), Some(b)) if a == b);
                let labeled_callback_placeholder =
                    s.ip == live_ip && Self::is_callback_placeholder_row(s);
                if same_peer_by_hash || labeled_callback_placeholder {
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
            transfer.active_sources = 0;
            transfer.queued_sources = 0;
            Self::clear_runtime_health(transfer);
        } else if let Some(transfer) = self.queue.iter_mut().find(|t| t.id == id) {
            transfer.status = TransferStatus::Paused;
            transfer.speed = 0;
            transfer.active_sources = 0;
            transfer.queued_sources = 0;
            Self::clear_runtime_health(transfer);
        }
        if let Some(control) = self.controls.get(id) {
            control.pause();
        }
        // Pause tears down peer connections, but keep last-known source rows
        // so the UI still shows who was known — mark them offline (Failed)
        // with zero speed rather than wiping the list (network still holds
        // per_file_sources for redial on resume).
        if let Some(rows) = self.source_details.get_mut(id) {
            for s in rows.iter_mut() {
                s.status = crate::types::SourceStatus::Failed;
                s.speed = 0;
                s.queue_rank = None;
            }
        }
    }

    /// Pause a transfer and, if this frees an active download slot, promote
    /// the next queued download immediately.
    pub fn pause_and_promote(&mut self, id: &str) -> Vec<Transfer> {
        let mut freed_active_download_slot = false;
        if let Some(transfer) = self.active.get_mut(id) {
            freed_active_download_slot = transfer.direction == TransferDirection::Download
                && !matches!(
                    transfer.status,
                    TransferStatus::Paused | TransferStatus::Stopped | TransferStatus::Insufficient
                );
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
            transfer.active_sources = 0;
            transfer.queued_sources = 0;
            Self::clear_runtime_health(&mut transfer);
            self.speed_history.remove(id);
            self.source_details.remove(id);
            self.queue.push_front(transfer);
            return self.promote_next();
        }
        if let Some(transfer) = self.queue.iter_mut().find(|t| t.id == id) {
            transfer.status = TransferStatus::Stopped;
            transfer.speed = 0;
            transfer.active_sources = 0;
            transfer.queued_sources = 0;
            Self::clear_runtime_health(transfer);
        }
        Vec::new()
    }

    pub fn resume(&mut self, id: &str) -> Vec<Transfer> {
        if let Some(transfer) = self.active.get_mut(id) {
            if transfer.status == TransferStatus::Paused {
                // Match Insufficient: do not jump straight to Active before a
                // worker is up — Searching/Queued until SourcesUpdate promotes.
                transfer.status = Self::queued_wait_status(transfer);
                Self::clear_failure_context(transfer);
                Self::clear_runtime_health(transfer);
            } else if transfer.status == TransferStatus::Insufficient {
                // eMule ResumeFileInsufficient: clear the insufficient-disk
                // state and let the download re-drive from discovery. Unlike a
                // prior Paused→Active bug, fall back to the normal waiting
                // status and let the caller restart it. Without this, Resume
                // on an "Insufficient disk space" row was a silent no-op: the
                // row had already been dropped from pending_downloads when it
                // went Insufficient, so nothing ever restarted it.
                let next = Self::queued_wait_status(transfer);
                transfer.status = next;
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
        // Also drop any completed/failed copy so a Failed event that raced
        // ahead of cancel can't leave a sticky red "failed" row in memory
        // (and therefore in get_transfers) after the user cancelled.
        self.completed.retain(|t| t.id != id);
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

    /// Record why a row failed without moving it out of the active set (the
    /// re-queue and disk-full paths both keep the row alive).
    pub fn set_failure_context(
        &mut self,
        id: &str,
        failure: Option<TransferFailureCode>,
        failure_kind: Option<String>,
        failure_stage: Option<String>,
    ) {
        if let Some(transfer) = self.get_transfer_mut(id) {
            transfer.failure_reason = failure.map(|f| f.message().to_string());
            transfer.failure_code = failure.map(|f| f.as_code().to_string());
            transfer.failure_kind = failure_kind;
            transfer.failure_stage = failure_stage;
        }
    }

    /// Mark a row as degraded because it is retrying after `failure`.
    ///
    /// Kept apart from [`Self::refresh_health`] because only the network loop
    /// knows which failure is being retried, and apart from a generic setter
    /// because this is the one health reason whose English is composed — the
    /// pairing of `retrying_after` with the failure naming its tail has to be
    /// made in one place or the two halves can disagree.
    pub fn set_retrying_after(
        &mut self,
        id: &str,
        failure: TransferFailureCode,
    ) -> Option<TransferHealthUpdate> {
        let transfer = self.get_transfer_mut(id)?;
        let previous = (
            transfer.health.clone(),
            transfer.health_reason.clone(),
            transfer.stalled_since,
        );
        transfer.health = TransferHealth::Degraded;
        transfer.health_reason = Some(TransferHealthCode::retrying_after(failure));
        transfer.health_code = Some(TransferHealthCode::RetryingAfter.as_code().to_string());
        transfer.stalled_since = None;
        if previous
            == (
                transfer.health.clone(),
                transfer.health_reason.clone(),
                transfer.stalled_since,
            )
        {
            return None;
        }
        Some(Self::health_update(transfer))
    }

    fn health_update(transfer: &Transfer) -> TransferHealthUpdate {
        TransferHealthUpdate {
            id: transfer.id.clone(),
            health: transfer.health.clone(),
            health_reason: transfer.health_reason.clone(),
            health_code: transfer.health_code.clone(),
            stalled_since: transfer.stalled_since,
            failure_reason: transfer.failure_reason.clone(),
            failure_code: transfer.failure_code.clone(),
            failure_kind: transfer.failure_kind.clone(),
            failure_stage: transfer.failure_stage.clone(),
        }
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
            let (health, code) = Self::compute_health_state(transfer, now);
            transfer.health = health;
            Self::apply_health_code(transfer, code);
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
                updates.push(Self::health_update(transfer));
            }
        }

        for transfer in self.queue.iter_mut() {
            let previous = (
                transfer.health.clone(),
                transfer.health_reason.clone(),
                transfer.stalled_since,
            );
            let (health, code) = Self::compute_health_state(transfer, now);
            transfer.health = health;
            Self::apply_health_code(transfer, code);
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
                updates.push(Self::health_update(transfer));
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
        self.active
            .get(id)
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
            let next_idx = self
                .queue
                .iter()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Same contract as the failure codes: the frontend keys a table on these
    /// exact strings, so a duplicate or a stray character costs a translation.
    #[test]
    fn every_health_code_is_a_distinct_identifier() {
        let mut seen = std::collections::HashSet::new();
        for health in TransferHealthCode::ALL {
            let code = health.as_code();
            assert!(
                !code.is_empty()
                    && code
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{code} is not a snake_case identifier"
            );
            assert!(seen.insert(code), "{code} is used by two variants");
            assert!(!health.message().is_empty(), "{code} has no English");
        }
        assert_eq!(seen.len(), TransferHealthCode::ALL.len());
    }

    /// `retrying_after` is the one health reason whose English is composed, so
    /// its placeholder has to survive into the rendered sentence — the UI fills
    /// the same slot with the translated failure.
    #[test]
    fn the_retry_notice_names_the_failure_it_is_retrying() {
        let composed = TransferHealthCode::retrying_after(TransferFailureCode::ConnectionFailed);
        assert_eq!(composed, "Retrying after connection failed");
        assert!(
            !composed.contains('{'),
            "the {{reason}} placeholder was left unfilled"
        );
        assert!(
            TransferHealthCode::RetryingAfter.message().contains("{reason}"),
            "the template must keep a slot for the failure, or the UI has nothing to fill"
        );
    }

    /// Walks every branch of `compute_health_state`. Health text is the other
    /// half of the transfer surface the frontend translates, so a branch that
    /// returns a reason without a code would silently fall back to English.
    #[test]
    fn every_health_verdict_carries_a_code() {
        let stalled = |mutate: fn(&mut Transfer)| {
            let mut t = download("h");
            t.status = TransferStatus::Active;
            t.last_received = Some(t.started_at);
            mutate(&mut t);
            TransferManager::compute_health_state(&t, t.started_at + ACTIVE_STALLED_SECS).1
        };
        assert_eq!(
            stalled(|t| {
                t.active_sources = 0;
                t.queued_sources = 2;
                t.sources = 2;
            }),
            Some(TransferHealthCode::QueuedSources)
        );
        assert_eq!(stalled(|_| {}), Some(TransferHealthCode::WaitingSources));
        assert_eq!(
            stalled(|t| {
                t.sources = 3;
                t.active_sources = 1;
            }),
            Some(TransferHealthCode::NoData)
        );

        let mut active = download("i");
        active.status = TransferStatus::Active;
        active.last_received = Some(active.started_at);
        assert_eq!(
            TransferManager::compute_health_state(&active, active.started_at + ACTIVE_DEGRADED_SECS)
                .1,
            Some(TransferHealthCode::Idle)
        );

        let mut searching = download("j");
        searching.status = TransferStatus::Searching;
        let searched_at = searching.started_at + SEARCHING_DEGRADED_SECS;
        assert_eq!(
            TransferManager::compute_health_state(&searching, searched_at).1,
            Some(TransferHealthCode::StillSearching)
        );
        searching.sources = 1;
        assert_eq!(
            TransferManager::compute_health_state(&searching, searched_at).1,
            Some(TransferHealthCode::RetryingSources)
        );

        let mut queued = download("k");
        queued.status = TransferStatus::Queued;
        assert_eq!(
            TransferManager::compute_health_state(&queued, queued.started_at).1,
            Some(TransferHealthCode::NoSources)
        );
        queued.sources = 4;
        assert_eq!(
            TransferManager::compute_health_state(&queued, queued.started_at + QUEUED_DEGRADED_SECS)
                .1,
            Some(TransferHealthCode::WaitingSlot)
        );

        // `retrying_after` is the only variant `compute_health_state` cannot
        // reach: only the network loop knows a retry is in progress.
        assert!(TransferHealthCode::ALL.contains(&TransferHealthCode::RetryingAfter));
    }

    /// The row the UI renders must never carry one half of the pair: English
    /// with no code degrades the eight non-English locales silently.
    #[test]
    fn a_health_verdict_writes_reason_and_code_together() {
        let mut manager = TransferManager::new(1);
        let mut row = download("a");
        row.status = TransferStatus::Searching;
        manager.enqueue(row);

        let updates = manager
            .refresh_health(1_700_000_000 + SEARCHING_DEGRADED_SECS)
            .0;
        let update = updates.first().expect("a stale search must degrade");
        assert_eq!(
            update.health_reason.as_deref(),
            Some("Still searching for sources")
        );
        assert_eq!(update.health_code.as_deref(), Some("still_searching"));

        let retry = manager
            .set_retrying_after("a", TransferFailureCode::HashsetRequestFailed)
            .expect("the retry notice replaces the search verdict");
        assert_eq!(
            retry.health_reason.as_deref(),
            Some("Retrying after hashset request failed")
        );
        assert_eq!(retry.health_code.as_deref(), Some("retrying_after"));

        manager.set_failure_context(
            "a",
            Some(TransferFailureCode::HashsetRequestFailed),
            None,
            None,
        );
        let row = manager.get_transfer("a").expect("the row is still tracked");
        assert_eq!(
            row.failure_code.as_deref(),
            Some("hashset_request_failed"),
            "the retry tail is recomposed from this code on the frontend"
        );
    }

    /// A download row shaped like the one `start_download` builds: no sources
    /// discovered yet, normal priority, nothing on the wire.
    fn download(id: &str) -> Transfer {
        Transfer {
            id: id.to_string(),
            file_name: format!("{id}.bin"),
            file_hash: format!("{id:_>32}"),
            peer_id: String::new(),
            peer_name: String::new(),
            direction: TransferDirection::Download,
            status: TransferStatus::Searching,
            progress: 0.0,
            speed: 0,
            total_size: 4096,
            transferred: 0,
            completed_size: 0,
            started_at: 1_700_000_000,
            failure_reason: None,
            failure_code: None,
            failure_kind: None,
            failure_stage: None,
            priority: "normal".to_string(),
            sources: 0,
            active_sources: 0,
            queued_sources: 0,
            queue_rank: None,
            last_seen_complete: None,
            last_received: None,
            health: TransferHealth::Healthy,
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
            expected_aich: None,
            ember_file_hash: None,
            completed_path: None,
            up_part_status: None,
            up_part_count: None,
            up_peer_part_status: None,
            ember_verified: false,
        }
    }

    /// A download that has already found sources, so the waiting status it is
    /// given on the way into the queue is `Queued` rather than `Searching`.
    fn sourced(id: &str, sources: u32) -> Transfer {
        let mut transfer = download(id);
        transfer.sources = sources;
        transfer.peer_id = "10.0.0.1:4662".to_string();
        transfer
    }

    fn ids(transfers: &[Transfer]) -> Vec<&str> {
        transfers.iter().map(|t| t.id.as_str()).collect()
    }

    #[test]
    fn completing_a_download_frees_its_slot_for_the_next_queued_one() {
        let mut manager = TransferManager::new(1);
        assert!(manager.enqueue(sourced("a", 3)), "the first row fits the cap");
        assert!(
            !manager.enqueue(sourced("b", 3)),
            "the second row must wait for the slot"
        );

        let promoted = manager.complete("a").expect("a known row must complete");

        assert_eq!(ids(&promoted), ["b"], "the freed slot must be handed on");
        assert!(!manager.active.contains_key("a"));
        assert!(manager.active.contains_key("b"));
        assert!(
            manager.queue.is_empty(),
            "a promoted row must leave the queue, not be duplicated into active"
        );
        let done = manager
            .completed
            .iter()
            .find(|t| t.id == "a")
            .expect("the completed row must be retained for the UI");
        assert_eq!(done.status, TransferStatus::Completed);
        assert_eq!(done.progress, 100.0);
        assert_eq!(
            done.transferred, done.total_size,
            "a verified download is the whole file even if the last tick coalesced"
        );
        assert!(
            manager.complete("a").is_none(),
            "completing twice must not promote a second time"
        );
    }

    /// `fail` promotes unconditionally, so the slot arithmetic has to come from
    /// `active_download_count`: a queued row failing frees nothing, and must not
    /// hand a second row the slot the running download still holds.
    #[test]
    fn failing_a_queued_row_does_not_displace_the_running_download() {
        let mut manager = TransferManager::new(1);
        manager.enqueue(sourced("a", 1));
        manager.enqueue(sourced("b", 1));
        manager.enqueue(sourced("c", 1));

        let promoted = manager
            .fail("b", TransferFailureCode::RemoteMissingFile, None, None)
            .expect("a queued row still gets the Failed lifecycle");
        assert!(
            promoted.is_empty(),
            "the running download's slot was never freed"
        );
        assert!(manager.active.contains_key("a"), "the running row is untouched");
        assert_eq!(manager.active.len(), 1);

        let promoted = manager
            .fail(
                "a",
                TransferFailureCode::InsufficientDisk,
                Some("io".into()),
                Some("write".into()),
            )
            .expect("an active row fails and frees its slot");
        assert_eq!(ids(&promoted), ["c"]);
        let failed = manager
            .completed
            .iter()
            .find(|t| t.id == "a")
            .expect("the failed row must be retained");
        assert_eq!(failed.status, TransferStatus::Failed);
        assert_eq!(
            failed.failure_reason.as_deref(),
            Some("Insufficient disk space")
        );
        assert_eq!(
            failed.failure_code.as_deref(),
            Some("insufficient_disk_space"),
            "the row must carry the discriminator the UI translates, not just the English"
        );
        assert_eq!(failed.failure_kind.as_deref(), Some("io"));
        assert_eq!(failed.speed, 0);
        assert!(
            manager
                .fail("nope", TransferFailureCode::TransientFailure, None, None)
                .is_none(),
            "an unknown id must not promote anything"
        );
    }

    /// The ring drains with `len() - 1000`, which underflows — and, with
    /// `overflow-checks` on in release, panics — if it is ever reached below the
    /// cap. Walk past the boundary and pin which rows survive.
    #[test]
    fn the_completed_ring_drops_its_oldest_rows_at_the_cap() {
        let mut manager = TransferManager::new(1);
        for i in 0..1005 {
            let id = format!("t{i:04}");
            manager.enqueue(download(&id));
            manager.complete(&id).expect("each row completes in turn");
        }

        assert_eq!(manager.completed.len(), 1000, "the ring must cap at 1000");
        assert_eq!(
            manager.completed.first().unwrap().id, "t0005",
            "the five oldest rows are the ones that go"
        );
        assert_eq!(manager.completed.last().unwrap().id, "t1004");
    }

    /// `fail` keeps its own copy of the same drain, so it needs its own case:
    /// the two have to stay in step or one of them starts growing unbounded.
    #[test]
    fn the_completed_ring_caps_failed_rows_the_same_way() {
        let mut manager = TransferManager::new(1);
        for i in 0..1002 {
            let id = format!("f{i:04}");
            manager.enqueue(download(&id));
            manager
                .fail(&id, TransferFailureCode::TransientFailure, None, None)
                .expect("each row fails in turn");
        }

        assert_eq!(manager.completed.len(), 1000);
        assert_eq!(manager.completed.first().unwrap().id, "f0002");
        assert_eq!(manager.completed.last().unwrap().id, "f1001");
    }

    /// One freed slot must produce exactly one promotion. Promoting twice
    /// oversubscribes the concurrency cap; promoting zero times leaks the slot
    /// until some unrelated event happens to call `promote_next` again.
    #[test]
    fn cancelling_a_running_download_refills_its_slot_exactly_once() {
        let mut manager = TransferManager::new(2);
        for id in ["a", "b", "c", "d"] {
            manager.enqueue(sourced(id, 2));
        }
        assert_eq!(manager.active.len(), 2, "the cap admits two");

        let promoted = manager.cancel("a");

        assert_eq!(
            ids(&promoted),
            ["c"],
            "the longest-queued row of equal priority goes first"
        );
        assert_eq!(manager.active.len(), 2, "no slot leaked, none oversubscribed");
        assert!(!manager.active.contains_key("a"));
        assert!(
            !manager.queue.iter().any(|t| t.id == "c"),
            "a promoted row must not remain queued as well"
        );

        assert!(
            manager.cancel("d").is_empty(),
            "cancelling a queued row frees no slot, so nothing may be promoted"
        );
        assert_eq!(manager.active.len(), 2);
        assert!(manager.queue.is_empty());
    }

    /// Stop parks the row at the front of the queue as `Stopped`, which
    /// `can_auto_run` rejects. A Cancel arriving afterwards — the ordinary
    /// stop-then-delete sequence — must therefore find nothing to promote,
    /// rather than handing the already-running row's slot out a second time.
    #[test]
    fn a_cancel_after_a_stop_does_not_promote_the_running_row_again() {
        let mut manager = TransferManager::new(1);
        manager.enqueue(sourced("a", 2));
        manager.enqueue(sourced("b", 2));

        let promoted = manager.stop("a");
        assert_eq!(
            ids(&promoted),
            ["b"],
            "stopping the running download hands its slot to the queue"
        );
        let stopped = manager
            .queue
            .iter()
            .find(|t| t.id == "a")
            .expect("Stop keeps the partial data queued, it does not delete it");
        assert_eq!(stopped.status, TransferStatus::Stopped);
        assert_eq!(stopped.speed, 0);

        assert!(
            manager.cancel("a").is_empty(),
            "the stopped row held no slot, so its cancel promotes nothing"
        );
        assert!(!manager.queue.iter().any(|t| t.id == "a"));
        assert_eq!(manager.active.len(), 1);
        assert!(manager.active.contains_key("b"));
    }

    /// A `Failed` event that raced ahead of the user's Cancel used to leave a
    /// red row in `completed` that nothing could clear, since Cancel only
    /// looked at `active` and `queue`.
    #[test]
    fn cancelling_after_a_failure_event_clears_the_sticky_failed_row() {
        let mut manager = TransferManager::new(1);
        manager.enqueue(sourced("a", 1));
        manager.fail("a", TransferFailureCode::TransientFailure, None, None);
        assert!(manager.completed.iter().any(|t| t.id == "a"));

        manager.cancel("a");

        assert!(
            !manager.completed.iter().any(|t| t.id == "a"),
            "a cancelled transfer must not survive as a failed row"
        );
    }

    /// What the UI shows while a download waits. "Searching" and "Queued" mean
    /// different things to the user — nothing found yet versus found and
    /// waiting behind other people — so the distinction is the source count,
    /// not whether we happen to hold a slot.
    #[test]
    fn queued_wait_status_separates_searching_from_waiting_in_a_queue() {
        let mut upload = download("u");
        upload.direction = TransferDirection::Upload;
        assert_eq!(
            TransferManager::queued_wait_status(&upload),
            TransferStatus::Active,
            "uploads are not subject to the download queue"
        );

        assert_eq!(
            TransferManager::queued_wait_status(&download("a")),
            TransferStatus::Searching,
            "no sources at all is a search, not a queue wait"
        );

        let mut queued_only = download("b");
        queued_only.queued_sources = 2;
        assert_eq!(
            TransferManager::queued_wait_status(&queued_only),
            TransferStatus::Searching,
            "queue slots on peers we can no longer name are not a source yet"
        );

        let mut known_peer = download("c");
        known_peer.peer_id = "10.0.0.1:4662".to_string();
        known_peer.queued_sources = 2;
        assert_eq!(
            TransferManager::queued_wait_status(&known_peer),
            TransferStatus::Queued,
            "a named peer that has us in its queue is a queue wait"
        );

        let mut with_sources = download("d");
        with_sources.sources = 4;
        assert_eq!(
            TransferManager::queued_wait_status(&with_sources),
            TransferStatus::Queued
        );
    }

    #[test]
    fn enqueue_over_the_cap_shows_the_waiting_status_the_ui_expects() {
        let mut manager = TransferManager::new(1);
        assert!(manager.enqueue(download("a")));
        assert!(!manager.enqueue(download("b")));
        assert_eq!(
            manager.queue.front().unwrap().status,
            TransferStatus::Searching,
            "a sourceless row must not claim to be queued behind anyone"
        );

        let mut paused = download("c");
        paused.status = TransferStatus::Paused;
        assert!(!manager.enqueue(paused));
        assert_eq!(
            manager.queue.iter().find(|t| t.id == "c").unwrap().status,
            TransferStatus::Paused,
            "a paused row keeps its status through the queue, or Resume loses it"
        );

        assert_eq!(
            ids(&manager.set_max_concurrent(4)),
            ["b"],
            "raising the cap may only promote rows the user did not pause"
        );
        assert_eq!(
            manager.queue.iter().find(|t| t.id == "c").unwrap().status,
            TransferStatus::Paused
        );
    }
}
