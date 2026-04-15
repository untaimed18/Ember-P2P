use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
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

pub struct TransferControl {
    cancelled: AtomicBool,
    paused: AtomicBool,
    preview_priority: AtomicBool,
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

    pub fn is_preview_priority(&self) -> bool {
        self.preview_priority.load(Ordering::Acquire)
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
        } else if transfer.peer_id.is_empty() {
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
            transfer.status = Self::queued_wait_status(transfer);
            return;
        }
        if transfer.peer_id.is_empty() && transfer.status == TransferStatus::Queued {
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
        if let Some(mut transfer) = self.active.remove(id) {
            transfer.status = TransferStatus::Completed;
            transfer.progress = 100.0;
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
        if let Some(transfer) = self.active.get_mut(id) {
            transfer.sources = total;
            transfer.active_sources = active;
            transfer.queued_sources = queued;
        } else if let Some(transfer) = self.queue.iter_mut().find(|t| t.id == id) {
            transfer.sources = total;
            transfer.active_sources = active;
            transfer.queued_sources = queued;
        }
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
            if source.source_origin.is_some() {
                existing.source_origin = source.source_origin;
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
    }

    /// Get all source details for a transfer.
    pub fn get_source_details(&self, transfer_id: &str) -> Vec<crate::types::SourceInfo> {
        self.source_details.get(transfer_id).cloned().unwrap_or_default()
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
            if transfer.speed > 0 && transfer.direction == TransferDirection::Download {
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
        all
    }

    pub fn get_transfer(&self, id: &str) -> Option<&Transfer> {
        self.active.get(id)
            .or_else(|| self.queue.iter().find(|t| t.id == id))
            .or_else(|| self.completed.iter().find(|t| t.id == id))
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
