use std::collections::VecDeque;
use std::time::Instant;

use tracing::{debug, info};

/// USS states matching eMule's LastCommonRouteFinder
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UssState {
    Disabled,
    Preparing,
    Monitoring,
}

const MAX_PING_HISTORY: usize = 50;
const BASELINE_SAMPLES: usize = 5;
const FAST_REACTION_SECS: u64 = 60;
const DEFAULT_PING_TOLERANCE: f64 = 1.5;
const DEFAULT_GOING_UP_DIVIDER: f64 = 2.0;
const DEFAULT_GOING_DOWN_DIVIDER: f64 = 1.5;
const MIN_UPLOAD_BYTES: u64 = 1024;

pub struct UploadSpeedSense {
    state: UssState,
    enabled: bool,
    initial_ping_ms: f64,
    current_limit: u64,
    min_upload: u64,
    max_upload: u64,
    ping_tolerance: f64,
    ping_history: VecDeque<f64>,
    going_up_divider: f64,
    going_down_divider: f64,
    start_time: Option<Instant>,
}

impl UploadSpeedSense {
    pub fn new(min_upload: u64, max_upload: u64) -> Self {
        Self {
            state: UssState::Disabled,
            enabled: false,
            initial_ping_ms: 0.0,
            current_limit: max_upload,
            min_upload: min_upload.max(MIN_UPLOAD_BYTES),
            max_upload,
            ping_tolerance: DEFAULT_PING_TOLERANCE,
            ping_history: VecDeque::with_capacity(MAX_PING_HISTORY),
            going_up_divider: DEFAULT_GOING_UP_DIVIDER,
            going_down_divider: DEFAULT_GOING_DOWN_DIVIDER,
            start_time: None,
        }
    }

    pub fn enable(&mut self) {
        if !self.enabled {
            self.enabled = true;
            self.state = UssState::Preparing;
            self.initial_ping_ms = 0.0;
            self.start_time = Some(Instant::now());
            self.ping_history.clear();
            info!("USS enabled, waiting for RTT baseline");
        }
    }

    pub fn disable(&mut self) {
        let was_enabled = self.enabled;
        self.enabled = false;
        self.state = UssState::Disabled;
        self.ping_history.clear();
        if was_enabled {
            info!("USS disabled");
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Record a real KAD Ping/Pong RTT measurement in milliseconds.
    /// Transitions from Preparing to Monitoring once enough samples establish a baseline.
    pub fn record_ping(&mut self, latency_ms: f64) {
        if !self.enabled {
            return;
        }

        if latency_ms <= 0.0 || latency_ms > 30_000.0 {
            return;
        }

        self.ping_history.push_back(latency_ms);
        if self.ping_history.len() > MAX_PING_HISTORY {
            self.ping_history.pop_front();
        }

        if self.state == UssState::Preparing && self.ping_history.len() >= BASELINE_SAMPLES {
            self.initial_ping_ms = self.compute_median();
            self.state = UssState::Monitoring;
            info!("USS: Baseline RTT established: {:.1}ms (from {} samples)", self.initial_ping_ms, BASELINE_SAMPLES);
        }
    }

    /// Compute the adjusted upload limit based on current latency vs baseline.
    pub fn compute_limit(&mut self) -> Option<u64> {
        if !self.enabled || self.state != UssState::Monitoring || self.initial_ping_ms == 0.0 {
            return None;
        }

        if self.ping_history.len() < 3 {
            return None;
        }

        let current_ping = self.compute_median();
        let target_ping = self.initial_ping_ms * self.ping_tolerance;

        let is_fast_reaction = self.start_time
            .map(|s| s.elapsed().as_secs() < FAST_REACTION_SECS)
            .unwrap_or(false);

        let up_divider = if is_fast_reaction { self.going_up_divider * 0.5 } else { self.going_up_divider };
        let down_divider = if is_fast_reaction { self.going_down_divider * 0.5 } else { self.going_down_divider };

        if current_ping > target_ping {
            let new_limit = (self.current_limit as f64 - (self.current_limit as f64 / down_divider)) as u64;
            self.current_limit = new_limit.max(self.min_upload);
            debug!("USS: RTT {current_ping:.1}ms > target {target_ping:.1}ms, decreasing to {} B/s", self.current_limit);
        } else {
            let headroom = 1.0 - (current_ping / target_ping);
            if headroom > 0.1 {
                let new_limit = (self.current_limit as f64 + (self.current_limit as f64 / up_divider)) as u64;
                self.current_limit = if self.max_upload > 0 {
                    new_limit.min(self.max_upload)
                } else {
                    new_limit
                };
                debug!("USS: RTT {current_ping:.1}ms < target {target_ping:.1}ms, increasing to {} B/s", self.current_limit);
            }
        }

        Some(self.current_limit)
    }

    fn compute_median(&self) -> f64 {
        if self.ping_history.is_empty() {
            return 0.0;
        }
        let mut sorted: Vec<f64> = self.ping_history.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mid = sorted.len() / 2;
        if sorted.len() % 2 == 0 {
            (sorted[mid - 1] + sorted[mid]) / 2.0
        } else {
            sorted[mid]
        }
    }

    pub fn set_limits(&mut self, min_upload: u64, max_upload: u64) {
        self.min_upload = min_upload.max(MIN_UPLOAD_BYTES);
        self.max_upload = max_upload;
    }

    pub fn set_tolerance(&mut self, tolerance: f64) {
        self.ping_tolerance = tolerance.max(1.0);
    }
}
