use std::collections::VecDeque;
use std::time::Instant;

use tracing::{debug, info, warn};

/// USS states matching eMule's LastCommonRouteFinder phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UssState {
    Disabled,
    /// Collecting an unloaded RTT baseline at the minimum upload rate.
    Preparing,
    /// Actively adjusting the upload cap from live RTT vs baseline.
    Monitoring,
}

const MAX_PING_HISTORY: usize = 50;
const BASELINE_SAMPLES: usize = 5;
const FAST_REACTION_SECS: u64 = 60;
/// How long the quiet-baseline phase may hold uploads at `min_upload`.
///
/// The network loop pings the selected KAD host every 2s, so `BASELINE_SAMPLES`
/// normally completes in ~10s; 60s covers a host rotation (3 missed pongs) plus
/// reselection with room to spare. Past it we stop throttling, because the RTT
/// feed can be *permanently* empty and nothing else notices: samples only exist
/// while a USS ping host is selected, and none ever is when KAD is disabled,
/// bootstrap failed, no contact verifies behind a restrictive NAT, or the user
/// runs eD2k-only / Ember-only. Without a deadline that pinned uploads at
/// `sanitize_min_upload` (10% of the configured cap) for the whole session.
const PREPARE_BASELINE_TIMEOUT_SECS: u64 = 60;
/// KAD peer RTT is noisier than eMule's last-hop ICMP ping, so allow more
/// headroom than eMule's classic 1.5× before throttling.
const DEFAULT_PING_TOLERANCE: f64 = 2.0;
/// Higher divider ⇒ smaller step. Values near 1.0 used to cut upload by ~90%
/// per second during "fast reaction" and collapse the link.
const DEFAULT_GOING_UP_DIVIDER: f64 = 10.0;
const DEFAULT_GOING_DOWN_DIVIDER: f64 = 5.0;
const MIN_UPLOAD_BYTES: u64 = 4 * 1024;
/// Never cut/raise more than this fraction of the current limit in one tick.
const MAX_DOWN_FRACTION: f64 = 0.20;
const MAX_UP_FRACTION: f64 = 0.15;

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
    /// When the current `Preparing` phase began, so a baseline that never
    /// arrives cannot throttle uploads for the rest of the session.
    prepare_started: Option<Instant>,
    /// `Preparing` outlived its deadline with too few samples: run at the
    /// configured cap instead of `min_upload`. Not a latch — `record_ping`
    /// still promotes to `Monitoring` if samples show up later.
    baseline_stalled: bool,
}

impl UploadSpeedSense {
    pub fn new(min_upload: u64, max_upload: u64) -> Self {
        let min_upload = sanitize_min_upload(min_upload, max_upload);
        Self {
            state: UssState::Disabled,
            enabled: false,
            initial_ping_ms: 0.0,
            current_limit: max_upload,
            min_upload,
            max_upload,
            ping_tolerance: DEFAULT_PING_TOLERANCE,
            ping_history: VecDeque::with_capacity(MAX_PING_HISTORY),
            going_up_divider: DEFAULT_GOING_UP_DIVIDER,
            going_down_divider: DEFAULT_GOING_DOWN_DIVIDER,
            start_time: None,
            prepare_started: None,
            baseline_stalled: false,
        }
    }

    pub fn state(&self) -> UssState {
        self.state
    }

    pub fn enable(&mut self) {
        if !self.enabled {
            self.enabled = true;
            self.state = UssState::Preparing;
            self.initial_ping_ms = 0.0;
            self.start_time = Some(Instant::now());
            self.prepare_started = Some(Instant::now());
            self.baseline_stalled = false;
            self.ping_history.clear();
            // Measure baseline under light load (see `compute_limit` while
            // Preparing). After the baseline is ready we jump to the full cap
            // and throttle from there — matching eMule's prepare→monitor flow.
            self.current_limit = self.min_upload;
            info!("USS enabled, waiting for RTT baseline");
        }
    }

    pub fn disable(&mut self) {
        let was_enabled = self.enabled;
        self.enabled = false;
        self.state = UssState::Disabled;
        self.prepare_started = None;
        self.baseline_stalled = false;
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

        if !latency_ms.is_finite() || latency_ms <= 0.0 || latency_ms > 30_000.0 {
            return;
        }

        self.ping_history.push_back(latency_ms);
        if self.ping_history.len() > MAX_PING_HISTORY {
            self.ping_history.pop_front();
        }

        if self.state == UssState::Preparing && self.ping_history.len() >= BASELINE_SAMPLES {
            // eMule seeds from the *lowest* of the initial samples (unloaded
            // path). Median of a still-warming path overstates baseline and
            // makes USS too tolerant of congestion.
            self.initial_ping_ms = self.compute_min();
            self.state = UssState::Monitoring;
            // A stalled baseline is measured at the full cap rather than at
            // `min_upload`, so it can read high; the Monitoring ratchet below
            // pulls it back down once a genuinely quieter window arrives.
            let was_stalled = self.baseline_stalled;
            self.baseline_stalled = false;
            self.prepare_started = None;
            // Start monitoring from the configured ceiling; RTT will pull it
            // down if the full rate congests the path.
            if self.max_upload > 0 {
                self.current_limit = self.max_upload;
            }
            info!(
                "USS: Baseline RTT established: {:.1}ms (lowest of {} samples{})",
                self.initial_ping_ms,
                BASELINE_SAMPLES,
                if was_stalled { ", after fallback" } else { "" }
            );
        } else if self.state == UssState::Monitoring
            && self.initial_ping_ms > 0.0
            && self.ping_history.len() >= BASELINE_SAMPLES
        {
            // Only lower the baseline when the entire recent window is quieter
            // than the current floor — a single lucky sample must not ratchet.
            // Use the window median (not min) so one older quiet spike still
            // sitting in the window cannot drag the floor unrealistically low.
            let mut window: Vec<f64> = self
                .ping_history
                .iter()
                .rev()
                .take(BASELINE_SAMPLES)
                .copied()
                .collect();
            if window.iter().all(|&p| p < self.initial_ping_ms) {
                window.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                let mid = window.len() / 2;
                let recent = if window.len().is_multiple_of(2) {
                    (window[mid - 1] + window[mid]) / 2.0
                } else {
                    window[mid]
                }
                .max(1.0);
                self.initial_ping_ms = recent;
                debug!(
                    "USS: New lowest baseline RTT: {:.1}ms",
                    self.initial_ping_ms
                );
            }
        }
    }

    /// Compute the adjusted upload limit based on current latency vs baseline.
    ///
    /// While Preparing, returns the minimum upload so baseline RTT is measured
    /// on a quiet path — unless the baseline never arrived, in which case the
    /// configured cap is returned (see `PREPARE_BASELINE_TIMEOUT_SECS`). While
    /// Monitoring, steps the limit up/down from RTT.
    pub fn compute_limit(&mut self) -> Option<u64> {
        if !self.enabled {
            return None;
        }

        if self.state == UssState::Preparing {
            let deadline_passed = self.prepare_started.is_some_and(|started| {
                started.elapsed().as_secs() >= PREPARE_BASELINE_TIMEOUT_SECS
            });
            let starved = self.ping_history.len() < BASELINE_SAMPLES;
            if !self.baseline_stalled && deadline_passed && starved {
                self.baseline_stalled = true;
                warn!(
                    "USS: no RTT baseline after {PREPARE_BASELINE_TIMEOUT_SECS}s \
                     ({}/{BASELINE_SAMPLES} samples); running at the configured \
                     upload cap instead of throttling",
                    self.ping_history.len()
                );
            }
            if self.baseline_stalled {
                // Give the cap back rather than sitting at `min_upload`
                // forever. `record_ping` still promotes to Monitoring the
                // moment enough samples arrive, so a ping host that only
                // appears after a late bootstrap re-engages USS by itself —
                // the fallback must not become a one-way disable.
                if self.max_upload > 0 {
                    self.current_limit = self.max_upload;
                }
                return Some(self.current_limit.max(self.min_upload));
            }
            return Some(self.min_upload);
        }

        if self.state != UssState::Monitoring || self.initial_ping_ms == 0.0 {
            return None;
        }

        if self.ping_history.len() < 3 {
            return Some(
                self.current_limit
                    .clamp(self.min_upload, self.effective_max()),
            );
        }

        let current_ping = self.compute_median();
        let target_ping = self.initial_ping_ms * self.ping_tolerance;

        let is_fast_reaction = self
            .start_time
            .map(|s| s.elapsed().as_secs() < FAST_REACTION_SECS)
            .unwrap_or(false);

        // Fast reaction uses smaller dividers (larger steps) but never below
        // 3.0, so a single tick cannot remove more than ~33% before the hard
        // fraction cap below.
        let up_divider = if is_fast_reaction {
            (self.going_up_divider * 0.5).max(3.0)
        } else {
            self.going_up_divider.max(3.0)
        };
        let down_divider = if is_fast_reaction {
            (self.going_down_divider * 0.5).max(3.0)
        } else {
            self.going_down_divider.max(3.0)
        };

        if current_ping > target_ping {
            let step = (1.0 / down_divider).min(MAX_DOWN_FRACTION);
            let new_limit = (self.current_limit as f64 * (1.0 - step)) as u64;
            self.current_limit = new_limit.max(self.min_upload);
            self.clamp_to_max();
            debug!(
                "USS: RTT {current_ping:.1}ms > target {target_ping:.1}ms, decreasing to {} B/s",
                self.current_limit
            );
        } else {
            let headroom = 1.0 - (current_ping / target_ping);
            if headroom > 0.1 {
                let step = (1.0 / up_divider).min(MAX_UP_FRACTION);
                let new_limit = (self.current_limit as f64 * (1.0 + step)) as u64;
                self.current_limit = new_limit;
                self.clamp_to_max();
                debug!(
                    "USS: RTT {current_ping:.1}ms < target {target_ping:.1}ms, increasing to {} B/s",
                    self.current_limit
                );
            }
        }

        Some(self.current_limit)
    }

    fn clamp_to_max(&mut self) {
        let max = self.effective_max();
        if self.current_limit > max {
            self.current_limit = max.max(self.min_upload.min(max));
        }
    }

    fn effective_max(&self) -> u64 {
        if self.max_upload > 0 {
            self.max_upload
        } else {
            self.current_limit
        }
    }

    fn compute_median(&self) -> f64 {
        if self.ping_history.is_empty() {
            return 0.0;
        }
        let mut sorted: Vec<f64> = self.ping_history.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mid = sorted.len() / 2;
        if sorted.len().is_multiple_of(2) {
            (sorted[mid - 1] + sorted[mid]) / 2.0
        } else {
            sorted[mid]
        }
    }

    fn compute_min(&self) -> f64 {
        self.ping_history
            .iter()
            .copied()
            .fold(f64::INFINITY, f64::min)
            .max(1.0)
    }

    pub fn set_limits(&mut self, min_upload: u64, max_upload: u64) {
        self.min_upload = sanitize_min_upload(min_upload, max_upload);
        self.max_upload = max_upload;
        // Keep the live limit inside the new [min, max] window so a lowered
        // cap is honored on the very next `compute_limit()` rather than
        // letting a stale higher `current_limit` leak through.
        if max_upload > 0 {
            let lo = self.min_upload.min(max_upload);
            self.current_limit = self.current_limit.clamp(lo, max_upload);
        }
    }

    /// Override ping tolerance (multiplier of baseline RTT). Kept for future
    /// settings exposure; the default is tuned for KAD peer RTT noise.
    #[allow(dead_code)]
    pub fn set_tolerance(&mut self, tolerance: f64) {
        self.ping_tolerance = tolerance.max(1.0);
    }
}

/// Floor for USS: at least 4 KiB/s, and at least 10% of the configured cap so
/// a congested path cannot starve uploads down to a useless trickle.
fn sanitize_min_upload(min_upload: u64, max_upload: u64) -> u64 {
    let floor = min_upload.max(MIN_UPLOAD_BYTES);
    if max_upload == 0 {
        return floor;
    }
    let tenths = (max_upload / 10).max(MIN_UPLOAD_BYTES);
    floor.max(tenths).min(max_upload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Pretend the quiet-baseline phase started before its deadline.
    fn expire_prepare_deadline(uss: &mut UploadSpeedSense) {
        uss.prepare_started =
            Instant::now().checked_sub(Duration::from_secs(PREPARE_BASELINE_TIMEOUT_SECS + 1));
        assert!(uss.prepare_started.is_some(), "monotonic clock too young");
    }

    #[test]
    fn preparing_holds_min_until_baseline() {
        let mut uss = UploadSpeedSense::new(0, 100_000);
        uss.enable();
        assert_eq!(uss.state(), UssState::Preparing);
        assert_eq!(uss.compute_limit(), Some(uss.min_upload));

        for _ in 0..BASELINE_SAMPLES {
            uss.record_ping(40.0);
        }
        assert_eq!(uss.state(), UssState::Monitoring);
        assert!((uss.initial_ping_ms - 40.0).abs() < f64::EPSILON);
        // Monitoring starts at the configured ceiling.
        assert_eq!(uss.compute_limit(), Some(100_000));
    }

    #[test]
    fn baseline_uses_lowest_sample() {
        let mut uss = UploadSpeedSense::new(0, 100_000);
        uss.enable();
        uss.record_ping(80.0);
        uss.record_ping(50.0);
        uss.record_ping(60.0);
        uss.record_ping(55.0);
        uss.record_ping(90.0);
        assert_eq!(uss.state(), UssState::Monitoring);
        assert!((uss.initial_ping_ms - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn single_quiet_sample_does_not_ratchet_baseline() {
        let mut uss = UploadSpeedSense::new(0, 100_000);
        uss.enable();
        for _ in 0..BASELINE_SAMPLES {
            uss.record_ping(50.0);
        }
        assert!((uss.initial_ping_ms - 50.0).abs() < f64::EPSILON);

        // One quieter spike must not permanently lower the baseline.
        uss.record_ping(10.0);
        assert!(
            (uss.initial_ping_ms - 50.0).abs() < f64::EPSILON,
            "baseline moved to {} after a single quiet sample",
            uss.initial_ping_ms
        );

        // A sustained quieter window (last BASELINE_SAMPLES all lower) may.
        for _ in 0..BASELINE_SAMPLES {
            uss.record_ping(30.0);
        }
        assert!((uss.initial_ping_ms - 30.0).abs() < f64::EPSILON);
    }

    #[test]
    fn decrease_is_capped_per_tick() {
        let mut uss = UploadSpeedSense::new(0, 100_000);
        uss.enable();
        for _ in 0..BASELINE_SAMPLES {
            uss.record_ping(40.0);
        }
        // Force an immediate overshoot well above target (40 * 2.0 = 80).
        for _ in 0..5 {
            uss.record_ping(400.0);
        }
        let before = uss.current_limit;
        let after = uss.compute_limit().unwrap();
        assert!(after < before);
        // Must not collapse by more than the hard fraction cap in one tick.
        assert!(after as f64 >= before as f64 * (1.0 - MAX_DOWN_FRACTION) - 1.0);
    }

    #[test]
    fn lowered_max_clamps_current_limit() {
        let mut uss = UploadSpeedSense::new(0, 100_000);
        uss.enable();
        for _ in 0..BASELINE_SAMPLES {
            uss.record_ping(40.0);
        }
        assert_eq!(uss.current_limit, 100_000);
        uss.set_limits(0, 20_000);
        assert_eq!(uss.current_limit, 20_000);
    }

    #[test]
    fn min_upload_tracks_ten_percent_of_cap() {
        let uss = UploadSpeedSense::new(0, 500_000);
        assert_eq!(uss.min_upload, 50_000);
    }

    #[test]
    fn baseline_that_never_arrives_falls_back_to_the_cap() {
        let mut uss = UploadSpeedSense::new(0, 1_000_000);
        uss.enable();
        // No KAD ping host (KAD off, failed bootstrap, nothing verified) means
        // `record_ping` is never called at all.
        assert_eq!(uss.compute_limit(), Some(100_000));
        expire_prepare_deadline(&mut uss);
        assert_eq!(uss.compute_limit(), Some(1_000_000));
        // Still Preparing, so a late baseline is still accepted.
        assert_eq!(uss.state(), UssState::Preparing);
    }

    #[test]
    fn starved_baseline_falls_back_yet_late_samples_still_engage_uss() {
        let mut uss = UploadSpeedSense::new(0, 1_000_000);
        uss.enable();
        // A host answered a couple of pings, then went away.
        uss.record_ping(40.0);
        uss.record_ping(42.0);
        assert_eq!(uss.compute_limit(), Some(100_000));
        expire_prepare_deadline(&mut uss);
        assert_eq!(uss.compute_limit(), Some(1_000_000));

        // The fallback must not latch USS off: enough samples still promote to
        // Monitoring and hand control of the cap back to RTT.
        for _ in 0..BASELINE_SAMPLES {
            uss.record_ping(40.0);
        }
        assert_eq!(uss.state(), UssState::Monitoring);
        assert!(!uss.baseline_stalled);
        assert!((uss.initial_ping_ms - 40.0).abs() < f64::EPSILON);
    }

    #[test]
    fn baseline_in_time_is_unaffected_by_the_deadline() {
        let mut uss = UploadSpeedSense::new(0, 1_000_000);
        uss.enable();
        for _ in 0..BASELINE_SAMPLES {
            uss.record_ping(40.0);
        }
        assert_eq!(uss.state(), UssState::Monitoring);
        // An expired-looking start time must not disturb an established
        // baseline; only the Preparing branch consults it.
        expire_prepare_deadline(&mut uss);
        assert!(!uss.baseline_stalled);
        assert_eq!(uss.compute_limit(), Some(1_000_000));
    }
}
