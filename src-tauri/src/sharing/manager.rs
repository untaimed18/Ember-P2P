use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::types::*;

/// eMule-style rolling window speed measurement.
/// Stores (cumulative_bytes, timestamp) pairs over a sliding window.
const SPEED_WINDOW_MS: u128 = 10_000;
const MAX_SPEED_SAMPLES: usize = 500;

pub struct TransferControl {
    cancelled: AtomicBool,
    paused: AtomicBool,
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
}

pub struct TransferManager {
    pub active: HashMap<String, Transfer>,
    pub queue: VecDeque<Transfer>,
    pub completed: Vec<Transfer>,
    pub max_concurrent: u32,
    /// Rolling speed history per transfer: VecDeque of (cumulative_bytes, Instant)
    speed_history: HashMap<String, VecDeque<(u64, Instant)>>,
    controls: HashMap<String, Arc<TransferControl>>,
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
        }
    }

    pub fn register_control(&mut self, id: &str, control: Arc<TransferControl>) {
        self.controls.insert(id.to_string(), control);
    }

    pub fn enqueue(&mut self, transfer: Transfer) -> String {
        let id = transfer.id.clone();
        if self.active.len() < self.max_concurrent as usize {
            self.active.insert(id.clone(), transfer);
        } else {
            self.queue.push_back(transfer);
        }
        id
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
                let elapsed = now.duration_since(history.front().unwrap().1).as_millis();
                if elapsed > SPEED_WINDOW_MS {
                    history.pop_front();
                } else {
                    break;
                }
            }

            // Calculate speed from the rolling window
            let speed = if history.len() >= 2 {
                let (oldest_bytes, oldest_time) = history.front().unwrap();
                let elapsed_ms = now.duration_since(*oldest_time).as_millis();
                if elapsed_ms > 0 {
                    let bytes_delta = transferred.saturating_sub(*oldest_bytes);
                    (bytes_delta as u128 * 1000 / elapsed_ms) as u64
                } else {
                    transfer.speed
                }
            } else {
                0
            };

            transfer.transferred = transferred;
            transfer.speed = speed;
            if transfer.total_size > 0 {
                transfer.progress =
                    (transferred as f64 / transfer.total_size as f64) * 100.0;
            }
        }
    }

    pub fn complete(&mut self, id: &str) -> Vec<Transfer> {
        if let Some(mut transfer) = self.active.remove(id) {
            transfer.status = TransferStatus::Completed;
            transfer.progress = 100.0;
            transfer.speed = 0;
            self.completed.push(transfer);
            if self.completed.len() > 1000 {
                self.completed.drain(..self.completed.len() - 1000);
            }
            self.speed_history.remove(id);
            self.controls.remove(id);
            return self.promote_next();
        }
        Vec::new()
    }

    pub fn fail(&mut self, id: &str, reason: &str) -> Vec<Transfer> {
        if let Some(mut transfer) = self.active.remove(id) {
            transfer.status = TransferStatus::Failed;
            transfer.speed = 0;
            transfer.failure_reason = Some(reason.to_string());
            self.completed.push(transfer);
            if self.completed.len() > 1000 {
                self.completed.drain(..self.completed.len() - 1000);
            }
            self.speed_history.remove(id);
            self.controls.remove(id);
            return self.promote_next();
        }
        Vec::new()
    }

    pub fn update_status(&mut self, id: &str, status: TransferStatus) {
        if let Some(transfer) = self.active.get_mut(id) {
            transfer.status = status;
        } else if let Some(transfer) = self.queue.iter_mut().find(|t| t.id == id) {
            transfer.status = status;
        }
    }

    pub fn pause(&mut self, id: &str) {
        if let Some(transfer) = self.active.get_mut(id) {
            transfer.status = TransferStatus::Paused;
            transfer.speed = 0;
        }
        if let Some(control) = self.controls.get(id) {
            control.pause();
        }
    }

    pub fn resume(&mut self, id: &str) {
        if let Some(transfer) = self.active.get_mut(id) {
            transfer.status = TransferStatus::Active;
        }
        if let Some(control) = self.controls.get(id) {
            control.resume();
        }
    }

    pub fn cancel(&mut self, id: &str) -> Vec<Transfer> {
        if let Some(control) = self.controls.get(id) {
            control.cancel();
        }
        self.active.remove(id);
        self.queue.retain(|t| t.id != id);
        self.controls.remove(id);
        self.speed_history.remove(id);
        self.promote_next()
    }

    pub fn remove(&mut self, id: &str) {
        if let Some(control) = self.controls.get(id) {
            control.cancel();
        }
        self.active.remove(id);
        self.queue.retain(|t| t.id != id);
        self.completed.retain(|t| t.id != id);
        self.controls.remove(id);
        self.speed_history.remove(id);
    }

    pub fn set_priority(&mut self, id: &str, priority: &str) {
        if let Some(transfer) = self.active.get_mut(id) {
            transfer.priority = priority.to_string();
        } else if let Some(transfer) = self.queue.iter_mut().find(|t| t.id == id) {
            transfer.priority = priority.to_string();
        }
    }

    pub fn all_controls(&self) -> Vec<Arc<TransferControl>> {
        self.controls.values().cloned().collect()
    }

    /// Cancel all active transfers and move them to completed with a failure reason.
    /// Returns the IDs of transfers that were cancelled.
    pub fn cancel_all_active(&mut self, reason: &str) -> Vec<String> {
        let ids: Vec<String> = self.active.keys().cloned().collect();
        for control in self.controls.values() {
            control.cancel();
        }
        for id in &ids {
            if let Some(mut t) = self.active.remove(id) {
                t.status = TransferStatus::Failed;
                t.speed = 0;
                t.failure_reason = Some(reason.to_string());
                self.completed.push(t);
            }
            self.controls.remove(id);
            self.speed_history.remove(id);
        }
        ids
    }

    pub fn get_all(&self) -> Vec<Transfer> {
        let mut all: Vec<Transfer> = self.active.values().cloned().collect();
        all.extend(self.queue.iter().cloned());
        all.extend(self.completed.iter().cloned());
        all
    }

    fn promote_next(&mut self) -> Vec<Transfer> {
        let mut promoted = Vec::new();
        while self.active.len() < self.max_concurrent as usize {
            if let Some(mut transfer) = self.queue.pop_front() {
                transfer.status = TransferStatus::Active;
                let t = transfer.clone();
                self.active.insert(transfer.id.clone(), transfer);
                promoted.push(t);
            } else {
                break;
            }
        }
        promoted
    }
}
