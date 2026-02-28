use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::database::Database;

const MAX_RATE_HISTORY: usize = 300;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransferStats {
    pub session_downloaded: u64,
    pub session_uploaded: u64,
    pub session_down_overhead: u64,
    pub session_up_overhead: u64,
    pub session_down_rate: f64,
    pub session_up_rate: f64,
    pub session_completed_down: u32,
    pub session_completed_up: u32,
    pub session_start_time: i64,

    pub cum_downloaded: u64,
    pub cum_uploaded: u64,
    pub cum_down_overhead: u64,
    pub cum_up_overhead: u64,
    pub cum_conn_time: u64,
    pub cum_completed_down: u32,
    pub cum_completed_up: u32,
    pub stat_last_reset: i64,

    pub overhead_server: u64,
    pub overhead_kad: u64,
    pub overhead_source_exchange: u64,
    pub overhead_file_request: u64,
}

pub struct StatsManager {
    pub stats: TransferStats,
    down_rate_history: VecDeque<(i64, u64)>,
    up_rate_history: VecDeque<(i64, u64)>,
    last_down_snapshot: u64,
    last_up_snapshot: u64,
    pub session_down_counter: Arc<AtomicU64>,
    pub session_up_counter: Arc<AtomicU64>,
}

impl StatsManager {
    pub fn new() -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            stats: TransferStats {
                session_start_time: now,
                stat_last_reset: now,
                ..Default::default()
            },
            down_rate_history: VecDeque::with_capacity(MAX_RATE_HISTORY),
            up_rate_history: VecDeque::with_capacity(MAX_RATE_HISTORY),
            last_down_snapshot: 0,
            last_up_snapshot: 0,
            session_down_counter: Arc::new(AtomicU64::new(0)),
            session_up_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn load_cumulative(&mut self, db: &Database) {
        if let Ok(rows) = db.load_statistics() {
            for (key, value) in rows {
                match key.as_str() {
                    "cum_downloaded" => self.stats.cum_downloaded = value as u64,
                    "cum_uploaded" => self.stats.cum_uploaded = value as u64,
                    "cum_down_overhead" => self.stats.cum_down_overhead = value as u64,
                    "cum_up_overhead" => self.stats.cum_up_overhead = value as u64,
                    "cum_conn_time" => self.stats.cum_conn_time = value as u64,
                    "cum_completed_down" => self.stats.cum_completed_down = value as u32,
                    "cum_completed_up" => self.stats.cum_completed_up = value as u32,
                    "stat_last_reset" => self.stats.stat_last_reset = value,
                    _ => {}
                }
            }
        }
    }

    pub fn save_cumulative(&self, db: &Database) {
        let pairs = vec![
            ("cum_downloaded", (self.stats.cum_downloaded + self.stats.session_downloaded) as i64),
            ("cum_uploaded", (self.stats.cum_uploaded + self.stats.session_uploaded) as i64),
            ("cum_down_overhead", (self.stats.cum_down_overhead + self.stats.session_down_overhead) as i64),
            ("cum_up_overhead", (self.stats.cum_up_overhead + self.stats.session_up_overhead) as i64),
            ("cum_conn_time", {
                let session_time = (chrono::Utc::now().timestamp() - self.stats.session_start_time).max(0) as u64;
                (self.stats.cum_conn_time + session_time) as i64
            }),
            ("cum_completed_down", (self.stats.cum_completed_down + self.stats.session_completed_down) as i64),
            ("cum_completed_up", (self.stats.cum_completed_up + self.stats.session_completed_up) as i64),
            ("stat_last_reset", self.stats.stat_last_reset),
        ];
        if let Err(e) = db.save_statistics(&pairs) {
            tracing::warn!("Failed to save statistics: {e}");
        }
    }

    pub fn record_rate(&mut self) {
        let now = chrono::Utc::now().timestamp();
        let down = self.session_down_counter.load(Ordering::Relaxed);
        let up = self.session_up_counter.load(Ordering::Relaxed);

        self.stats.session_downloaded = down;
        self.stats.session_uploaded = up;

        let down_delta = down.saturating_sub(self.last_down_snapshot);
        let up_delta = up.saturating_sub(self.last_up_snapshot);

        self.last_down_snapshot = down;
        self.last_up_snapshot = up;

        self.down_rate_history.push_back((now, down_delta));
        self.up_rate_history.push_back((now, up_delta));
        if self.down_rate_history.len() > MAX_RATE_HISTORY {
            self.down_rate_history.pop_front();
        }
        if self.up_rate_history.len() > MAX_RATE_HISTORY {
            self.up_rate_history.pop_front();
        }

        let window = 10.min(self.down_rate_history.len());
        if window > 0 {
            let sum: u64 = self.down_rate_history.iter().rev().take(window).map(|(_, v)| v).sum();
            self.stats.session_down_rate = sum as f64 / window as f64;
        }
        let window = 10.min(self.up_rate_history.len());
        if window > 0 {
            let sum: u64 = self.up_rate_history.iter().rev().take(window).map(|(_, v)| v).sum();
            self.stats.session_up_rate = sum as f64 / window as f64;
        }
    }

    pub fn add_overhead(&mut self, category: OverheadCategory, bytes: u64) {
        self.stats.session_down_overhead += bytes;
        match category {
            OverheadCategory::Kad => self.stats.overhead_kad += bytes,
            OverheadCategory::FileRequest => self.stats.overhead_file_request += bytes,
        }
    }

    pub fn record_completed_download(&mut self) {
        self.stats.session_completed_down += 1;
    }

    pub fn record_completed_upload(&mut self) {
        self.stats.session_completed_up += 1;
    }

    pub fn get_stats(&self) -> TransferStats {
        self.stats.clone()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum OverheadCategory {
    Kad,
    FileRequest,
}
