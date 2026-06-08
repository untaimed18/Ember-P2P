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
    /// Monotonic session-start marker for connection-time accounting.
    /// `session_start_time` is a wall-clock timestamp (used for display);
    /// deriving elapsed connection time from it lets a forward clock jump
    /// (NTP correction, suspend/resume) spike `cum_conn_time`. `Instant` is
    /// immune to wall-clock changes, so we measure session duration with it.
    session_start_instant: std::time::Instant,
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
            session_start_instant: std::time::Instant::now(),
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
                // Monotonic elapsed time — immune to wall-clock jumps that
                // would otherwise spike the cumulative connection time.
                let session_time = self.session_start_instant.elapsed().as_secs();
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

    /// Snapshot the session byte counters and recompute the smoothed
    /// download/upload rates. `now` is the current unix timestamp in
    /// seconds (injected rather than read internally so the rate math is
    /// unit-testable); production callers pass `chrono::Utc::now().timestamp()`.
    pub fn record_rate(&mut self, now: i64) {
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

        self.stats.session_down_rate = Self::windowed_rate(&self.down_rate_history, now);
        self.stats.session_up_rate = Self::windowed_rate(&self.up_rate_history, now);
    }

    /// Moving-average rate (bytes/sec) over the most recent samples of
    /// `history` (each entry is `(timestamp_secs, bytes_since_prev_tick)`).
    ///
    /// The bytes transferred between the oldest sample in the window and
    /// `now` equal the sum of the `window - 1` most recent deltas — the
    /// oldest sample's own delta belongs to the interval *before* the
    /// window begins. Summing all `window` deltas while dividing by the
    /// `(window - 1)`-interval time span overestimated the rate: ≈2× with
    /// only two samples (right after a transfer starts) and ≈11% at steady
    /// state with a full 10-sample window.
    fn windowed_rate(history: &VecDeque<(i64, u64)>, now: i64) -> f64 {
        let window = 10.min(history.len());
        if window > 1 {
            let sum: u64 = history.iter().rev().take(window - 1).map(|(_, v)| v).sum();
            let oldest_ts = history.iter().rev().nth(window - 1).map(|(t, _)| *t).unwrap_or(now);
            let elapsed = now.saturating_sub(oldest_ts).max(1) as f64;
            sum as f64 / elapsed
        } else if window == 1 {
            history.back().map(|(_, v)| *v as f64).unwrap_or(0.0)
        } else {
            0.0
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Steady 100 B/s for a full window must report exactly 100 B/s — not
    /// the old `window / (window - 1)` (~111 B/s) overestimate.
    #[test]
    fn rate_steady_state_is_accurate() {
        let mut mgr = StatsManager::new();
        for t in 0..=10i64 {
            mgr.session_down_counter.store((t as u64) * 100, Ordering::Relaxed);
            mgr.record_rate(t);
        }
        assert!(
            (mgr.stats.session_down_rate - 100.0).abs() < 1e-6,
            "expected 100 B/s steady-state, got {}",
            mgr.stats.session_down_rate
        );
    }

    /// With only two samples spanning one 1-second interval, the rate must
    /// be the single interval's delta — the old code summed the priming
    /// first-tick delta into the same 1s span and roughly doubled it.
    #[test]
    fn rate_two_samples_not_doubled() {
        let mut mgr = StatsManager::new();
        // First tick carries a non-zero priming delta (bytes already moved
        // before the first record_rate call): 500 B.
        mgr.session_down_counter.store(500, Ordering::Relaxed);
        mgr.record_rate(0);
        // Second tick: +100 B over 1 second => 100 B/s.
        mgr.session_down_counter.store(600, Ordering::Relaxed);
        mgr.record_rate(1);
        assert!(
            (mgr.stats.session_down_rate - 100.0).abs() < 1e-6,
            "expected 100 B/s from two samples, got {} (priming delta leaked in?)",
            mgr.stats.session_down_rate
        );
    }

    /// Upload path shares the same helper; verify it is wired up too.
    #[test]
    fn upload_rate_uses_same_window() {
        let mut mgr = StatsManager::new();
        for t in 0..=10i64 {
            mgr.session_up_counter.store((t as u64) * 2048, Ordering::Relaxed);
            mgr.record_rate(t);
        }
        assert!(
            (mgr.stats.session_up_rate - 2048.0).abs() < 1e-6,
            "expected 2048 B/s steady-state upload, got {}",
            mgr.stats.session_up_rate
        );
    }
}
