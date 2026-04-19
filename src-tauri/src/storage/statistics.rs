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

/// Lock-free counters that the ed2k upload / transfer / multi_source
/// tasks bump on every peer-to-peer Source Exchange packet they send
/// or receive (`OP_REQUESTSOURCES`, `OP_ANSWERSOURCES`, and Ember's
/// `OP_EMBER_SOURCEEXCHANGE`). The network-loop's stats tick swaps
/// them out into `StatsManager::add_overhead` so the SX bytes flow
/// into `overhead_source_exchange` alongside the existing
/// server-source-asking traffic. Without this the SX category was
/// effectively zero for KAD/Ember-only sessions, even when the actual
/// peer-to-peer source-exchange protocol was very active.
#[derive(Debug, Default)]
pub struct SxOverheadCounters {
    pub upload_bytes: AtomicU64,
    pub download_bytes: AtomicU64,
}

impl SxOverheadCounters {
    pub fn record_upload(&self, bytes: u64) {
        if bytes == 0 { return; }
        self.upload_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_download(&self, bytes: u64) {
        if bytes == 0 { return; }
        self.download_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

pub type SharedSxOverheadCounters = Arc<SxOverheadCounters>;

pub struct StatsManager {
    pub stats: TransferStats,
    down_rate_history: VecDeque<(i64, u64)>,
    up_rate_history: VecDeque<(i64, u64)>,
    last_down_snapshot: u64,
    last_up_snapshot: u64,
    pub session_down_counter: Arc<AtomicU64>,
    pub session_up_counter: Arc<AtomicU64>,
    pub sx_counters: SharedSxOverheadCounters,
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
            sx_counters: Arc::new(SxOverheadCounters::default()),
        }
    }

    /// Drain the lock-free peer-SX byte counters into `add_overhead` so
    /// the bytes show up under the `Source Exchange` row on the
    /// Statistics page. Call from the network loop's periodic stats
    /// tick (same cadence as `refresh_rate`) so the UI sees fresh
    /// totals without burdening every send/recv site with a Mutex.
    pub fn drain_sx_counters(&mut self) {
        let up = self.sx_counters.upload_bytes.swap(0, Ordering::Relaxed);
        let down = self.sx_counters.download_bytes.swap(0, Ordering::Relaxed);
        if up > 0 {
            self.add_overhead(OverheadCategory::SourceExchange, OverheadDirection::Upload, up);
        }
        if down > 0 {
            self.add_overhead(OverheadCategory::SourceExchange, OverheadDirection::Download, down);
        }
    }

    pub fn load_cumulative(&mut self, db: &Database) {
        match db.load_statistics() {
            Err(e) => tracing::warn!("Failed to load cumulative statistics: {e}"),
            Ok(rows) => {
                for (key, value) in rows {
                    match key.as_str() {
                        "cum_downloaded" => self.stats.cum_downloaded = value.max(0) as u64,
                        "cum_uploaded" => self.stats.cum_uploaded = value.max(0) as u64,
                        "cum_down_overhead" => self.stats.cum_down_overhead = value.max(0) as u64,
                        "cum_up_overhead" => self.stats.cum_up_overhead = value.max(0) as u64,
                        "cum_conn_time" => self.stats.cum_conn_time = value.max(0) as u64,
                        "cum_completed_down" => self.stats.cum_completed_down = value.max(0).min(u32::MAX as i64) as u32,
                        "cum_completed_up" => self.stats.cum_completed_up = value.max(0).min(u32::MAX as i64) as u32,
                        "stat_last_reset" => self.stats.stat_last_reset = value,
                        _ => {}
                    }
                }
            }
        }
    }

    pub fn save_cumulative(&self, db: &Database) {
        let safe_add = |a: u64, b: u64| -> i64 {
            let sum = a.saturating_add(b);
            if sum > i64::MAX as u64 { i64::MAX } else { sum as i64 }
        };
        let safe_add32 = |a: u32, b: u32| -> i64 {
            (a as i64).saturating_add(b as i64)
        };
        let pairs = vec![
            ("cum_downloaded", safe_add(self.stats.cum_downloaded, self.stats.session_downloaded)),
            ("cum_uploaded", safe_add(self.stats.cum_uploaded, self.stats.session_uploaded)),
            ("cum_down_overhead", safe_add(self.stats.cum_down_overhead, self.stats.session_down_overhead)),
            ("cum_up_overhead", safe_add(self.stats.cum_up_overhead, self.stats.session_up_overhead)),
            ("cum_conn_time", {
                let session_time = (chrono::Utc::now().timestamp() - self.stats.session_start_time).max(0) as u64;
                safe_add(self.stats.cum_conn_time, session_time)
            }),
            ("cum_completed_down", safe_add32(self.stats.cum_completed_down, self.stats.session_completed_down)),
            ("cum_completed_up", safe_add32(self.stats.cum_completed_up, self.stats.session_completed_up)),
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
        if window > 1 {
            let sum: u64 = self.down_rate_history.iter().rev().take(window).map(|(_, v)| v).sum();
            let oldest_ts = self.down_rate_history.iter().rev().nth(window - 1).map(|(t, _)| *t).unwrap_or(now);
            let elapsed = now.saturating_sub(oldest_ts).max(1) as f64;
            self.stats.session_down_rate = sum as f64 / elapsed;
        } else if window == 1 {
            self.stats.session_down_rate = self.down_rate_history.back().map(|(_, v)| *v as f64).unwrap_or(0.0);
        }
        let window = 10.min(self.up_rate_history.len());
        if window > 1 {
            let sum: u64 = self.up_rate_history.iter().rev().take(window).map(|(_, v)| v).sum();
            let oldest_ts = self.up_rate_history.iter().rev().nth(window - 1).map(|(t, _)| *t).unwrap_or(now);
            let elapsed = now.saturating_sub(oldest_ts).max(1) as f64;
            self.stats.session_up_rate = sum as f64 / elapsed;
        } else if window == 1 {
            self.stats.session_up_rate = self.up_rate_history.back().map(|(_, v)| *v as f64).unwrap_or(0.0);
        }
    }

    pub fn add_overhead(&mut self, category: OverheadCategory, direction: OverheadDirection, bytes: u64) {
        match direction {
            OverheadDirection::Download => self.stats.session_down_overhead = self.stats.session_down_overhead.saturating_add(bytes),
            OverheadDirection::Upload => self.stats.session_up_overhead = self.stats.session_up_overhead.saturating_add(bytes),
        }
        match category {
            OverheadCategory::Kad => self.stats.overhead_kad = self.stats.overhead_kad.saturating_add(bytes),
            OverheadCategory::FileRequest => self.stats.overhead_file_request = self.stats.overhead_file_request.saturating_add(bytes),
            OverheadCategory::Server => self.stats.overhead_server = self.stats.overhead_server.saturating_add(bytes),
            OverheadCategory::SourceExchange => self.stats.overhead_source_exchange = self.stats.overhead_source_exchange.saturating_add(bytes),
        }
    }

    pub fn record_completed_download(&mut self) {
        self.stats.session_completed_down = self.stats.session_completed_down.saturating_add(1);
    }

    pub fn record_completed_upload(&mut self) {
        self.stats.session_completed_up = self.stats.session_completed_up.saturating_add(1);
    }

    pub fn get_stats(&self) -> TransferStats {
        self.stats.clone()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum OverheadCategory {
    Kad,
    FileRequest,
    Server,
    SourceExchange,
}

#[derive(Debug, Clone, Copy)]
pub enum OverheadDirection {
    Download,
    Upload,
}
