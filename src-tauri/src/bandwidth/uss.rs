use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use tracing::{debug, info};

/// USS states matching eMule's LastCommonRouteFinder
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UssState {
    Disabled,
    Preparing,
    Monitoring,
    Error,
}

const MAX_PING_HISTORY: usize = 50;
const FAST_REACTION_SECS: u64 = 60;
const DEFAULT_PING_TOLERANCE: f64 = 1.5;
const DEFAULT_GOING_UP_DIVIDER: f64 = 2.0;
const DEFAULT_GOING_DOWN_DIVIDER: f64 = 1.5;
const MIN_UPLOAD_BYTES: u64 = 1024;
const PING_INTERVAL: Duration = Duration::from_secs(2);

pub struct UploadSpeedSense {
    state: UssState,
    enabled: bool,
    /// IPs to ping (from connected peers/servers)
    host_candidates: Vec<Ipv4Addr>,
    /// The host we're pinging for latency measurement
    ping_host: Option<Ipv4Addr>,
    /// Baseline ping (initial measurement)
    initial_ping_ms: f64,
    /// Current computed upload limit
    current_limit: u64,
    /// User-configured min upload
    min_upload: u64,
    /// User-configured max upload
    max_upload: u64,
    ping_tolerance: f64,
    ping_history: VecDeque<f64>,
    going_up_divider: f64,
    going_down_divider: f64,
    start_time: Option<Instant>,
    last_ping_time: Option<Instant>,
    last_adjustment_time: Option<Instant>,
}

impl UploadSpeedSense {
    pub fn new(min_upload: u64, max_upload: u64) -> Self {
        Self {
            state: UssState::Disabled,
            enabled: false,
            host_candidates: Vec::new(),
            ping_host: None,
            initial_ping_ms: 0.0,
            current_limit: max_upload,
            min_upload: min_upload.max(MIN_UPLOAD_BYTES),
            max_upload,
            ping_tolerance: DEFAULT_PING_TOLERANCE,
            ping_history: VecDeque::with_capacity(MAX_PING_HISTORY),
            going_up_divider: DEFAULT_GOING_UP_DIVIDER,
            going_down_divider: DEFAULT_GOING_DOWN_DIVIDER,
            start_time: None,
            last_ping_time: None,
            last_adjustment_time: None,
        }
    }

    pub fn enable(&mut self) {
        if !self.enabled {
            self.enabled = true;
            self.state = UssState::Preparing;
            self.start_time = Some(Instant::now());
            self.ping_history.clear();
            info!("USS enabled, entering preparation phase");
        }
    }

    pub fn disable(&mut self) {
        self.enabled = false;
        self.state = UssState::Disabled;
        self.ping_host = None;
        self.ping_history.clear();
        info!("USS disabled");
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn state(&self) -> UssState {
        self.state
    }

    pub fn add_host_candidate(&mut self, ip: Ipv4Addr) {
        if !self.host_candidates.contains(&ip) && !ip.is_private() && !ip.is_loopback() {
            self.host_candidates.push(ip);
            if self.host_candidates.len() >= 10 && self.state == UssState::Preparing {
                self.select_ping_host();
            }
        }
    }

    fn select_ping_host(&mut self) {
        if let Some(&host) = self.host_candidates.first() {
            self.ping_host = Some(host);
            self.state = UssState::Monitoring;
            info!("USS: Selected ping host {host}, entering monitoring");
        }
    }

    /// Record a ping measurement in milliseconds.
    pub fn record_ping(&mut self, latency_ms: f64) {
        if !self.enabled || self.state != UssState::Monitoring {
            return;
        }

        self.ping_history.push_back(latency_ms);
        if self.ping_history.len() > MAX_PING_HISTORY {
            self.ping_history.pop_front();
        }

        if self.initial_ping_ms == 0.0 && self.ping_history.len() >= 5 {
            self.initial_ping_ms = self.compute_median();
            info!("USS: Baseline ping established: {:.1}ms", self.initial_ping_ms);
        }

        self.last_ping_time = Some(Instant::now());
    }

    /// Compute the adjusted upload limit based on current latency.
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
            debug!("USS: Ping {current_ping:.1}ms > target {target_ping:.1}ms, decreasing to {} B/s", self.current_limit);
        } else {
            let headroom = 1.0 - (current_ping / target_ping);
            if headroom > 0.1 {
                let new_limit = (self.current_limit as f64 + (self.current_limit as f64 / up_divider)) as u64;
                self.current_limit = if self.max_upload > 0 {
                    new_limit.min(self.max_upload)
                } else {
                    new_limit
                };
                debug!("USS: Ping {current_ping:.1}ms < target {target_ping:.1}ms, increasing to {} B/s", self.current_limit);
            }
        }

        self.last_adjustment_time = Some(Instant::now());
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

    pub fn should_ping(&self) -> bool {
        if !self.enabled || self.state != UssState::Monitoring {
            return false;
        }
        match self.last_ping_time {
            Some(t) => t.elapsed() >= PING_INTERVAL,
            None => true,
        }
    }

    pub fn ping_host(&self) -> Option<Ipv4Addr> {
        self.ping_host
    }

    pub fn current_limit(&self) -> u64 {
        self.current_limit
    }

    pub fn set_limits(&mut self, min_upload: u64, max_upload: u64) {
        self.min_upload = min_upload.max(MIN_UPLOAD_BYTES);
        self.max_upload = max_upload;
    }

    pub fn set_tolerance(&mut self, tolerance: f64) {
        self.ping_tolerance = tolerance.max(1.0);
    }
}
