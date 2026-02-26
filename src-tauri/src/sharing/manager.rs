use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::types::*;

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
    last_progress: HashMap<String, (u64, i64)>,
    controls: HashMap<String, Arc<TransferControl>>,
}

impl TransferManager {
    pub fn new(max_concurrent: u32) -> Self {
        Self {
            active: HashMap::new(),
            queue: VecDeque::new(),
            completed: Vec::new(),
            max_concurrent,
            last_progress: HashMap::new(),
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

    pub fn update_progress(&mut self, id: &str, transferred: u64, _speed_hint: u64) {
        if let Some(transfer) = self.active.get_mut(id) {
            let now = chrono::Utc::now().timestamp();
            let speed = if let Some(&(prev_bytes, prev_time)) = self.last_progress.get(id) {
                let dt = (now - prev_time).max(1) as u64;
                let db = transferred.saturating_sub(prev_bytes);
                db / dt
            } else {
                0
            };

            self.last_progress.insert(id.to_string(), (transferred, now));
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
            self.last_progress.remove(id);
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
            self.last_progress.remove(id);
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
        self.last_progress.remove(id);
        self.promote_next()
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
