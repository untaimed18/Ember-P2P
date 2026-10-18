use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
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

/// Samples `Preparing` collects before it hands uploads the full cap.
///
/// eMule pings the last common router over ICMP about once a second. Ember
/// pings KAD contacts instead, and eMule drops and then bans past two
/// `KADEMLIA2_PING` a minute from one IP (`kad::outbound`), so `uss_ping_tick`
/// rotates over a pool of contacts — one in flight at a time, each inside that
/// budget — for a sample about every 4 s. Five fill in about 20 s.
const BASELINE_SAMPLES: usize = 5;
/// Fewest quiet samples the `Preparing` deadline still takes as a baseline.
/// With a single eligible contact the cadence falls back to one ping per
/// 31.5 s, and the deadline then sees about two.
const MIN_BASELINE_SAMPLES: usize = 2;
/// Normalized samples the congestion check takes its median over: with a
/// sample every ~4 s, two congested pings in a row (~8 s) move the limit.
const MONITOR_WINDOW: usize = 3;
/// Hosts whose baseline is remembered. The ping pool is smaller; this only
/// bounds churn when contacts leave the routing table.
const MAX_HOSTS: usize = 32;
const FAST_REACTION_SECS: u64 = 60;
/// How long the quiet-baseline phase may hold uploads at `min_upload`.
///
/// Past it we take whatever quiet samples there are (`MIN_BASELINE_SAMPLES`),
/// or stop throttling when there are fewer, because the RTT feed can be
/// *permanently* empty and nothing else notices: samples only exist while a
/// USS ping host is reachable, and none ever is when KAD is disabled,
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

/// One ping host's RTT floor. Hosts sit at different distances, so each
/// sample is judged against its own host's floor, never another's.
#[derive(Debug, Clone, Copy)]
struct HostRtt {
    baseline_ms: f64,
    /// The previous sample, which a lower one needs beside it to move the
    /// baseline.
    last_ms: f64,
    /// `sample_seq` of the latest sample, for evicting the stalest host.
    seen: u64,
}

pub struct UploadSpeedSense {
    state: UssState,
    enabled: bool,
    current_limit: u64,
    min_upload: u64,
    max_upload: u64,
    ping_tolerance: f64,
    hosts: HashMap<SocketAddr, HostRtt>,
    /// Recent samples as a multiple of their host's baseline.
    ratios: VecDeque<f64>,
    /// Samples taken during the current `Preparing` phase.
    prepare_samples: usize,
    sample_seq: u64,
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
    /// A sample arrived since the limit last moved. `compute_limit` runs every
    /// second and samples come every few, so stepping on every call would
    /// move the cap several times on one measurement.
    fresh_sample: bool,
}

impl UploadSpeedSense {
    pub fn new(min_upload: u64, max_upload: u64) -> Self {
        let min_upload = sanitize_min_upload(min_upload, max_upload);
        Self {
            state: UssState::Disabled,
            enabled: false,
            current_limit: max_upload,
            min_upload,
            max_upload,
            ping_tolerance: DEFAULT_PING_TOLERANCE,
            hosts: HashMap::new(),
            ratios: VecDeque::with_capacity(MONITOR_WINDOW),
            prepare_samples: 0,
            sample_seq: 0,
            going_up_divider: DEFAULT_GOING_UP_DIVIDER,
            going_down_divider: DEFAULT_GOING_DOWN_DIVIDER,
            start_time: None,
            prepare_started: None,
            baseline_stalled: false,
            fresh_sample: false,
        }
    }

    pub fn state(&self) -> UssState {
        self.state
    }

    pub fn enable(&mut self) {
        if !self.enabled {
            self.enabled = true;
            self.state = UssState::Preparing;
            self.start_time = Some(Instant::now());
            self.prepare_started = Some(Instant::now());
            self.reset_samples();
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
        self.reset_samples();
        if was_enabled {
            info!("USS disabled");
        }
    }

    fn reset_samples(&mut self) {
        self.baseline_stalled = false;
        self.hosts.clear();
        self.ratios.clear();
        self.prepare_samples = 0;
        self.fresh_sample = false;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Record a real KAD Ping/Pong RTT measurement in milliseconds.
    /// Transitions from Preparing to Monitoring once enough samples establish a baseline.
    pub fn record_ping(&mut self, host: SocketAddr, latency_ms: f64) {
        if !self.enabled {
            return;
        }

        if !latency_ms.is_finite() || latency_ms <= 0.0 || latency_ms > 30_000.0 {
            return;
        }
        let latency_ms = latency_ms.max(1.0);
        self.sample_seq += 1;
        let seq = self.sample_seq;

        match self.state {
            UssState::Disabled => {}
            UssState::Preparing => {
                // eMule seeds from the *lowest* of the initial samples
                // (unloaded path); queueing only ever adds delay.
                let entry = self.hosts.entry(host).or_insert(HostRtt {
                    baseline_ms: latency_ms,
                    last_ms: latency_ms,
                    seen: seq,
                });
                entry.baseline_ms = entry.baseline_ms.min(latency_ms);
                entry.last_ms = latency_ms;
                entry.seen = seq;
                self.prepare_samples += 1;
                self.evict_stale_hosts();
                if self.prepare_samples >= BASELINE_SAMPLES {
                    self.promote();
                }
            }
            UssState::Monitoring => {
                let Some(entry) = self.hosts.get_mut(&host) else {
                    // A host first met under load: its floor reads high until
                    // the ratchet below brings it down, so it is not judged on
                    // this sample.
                    self.hosts.insert(
                        host,
                        HostRtt {
                            baseline_ms: latency_ms,
                            last_ms: latency_ms,
                            seen: seq,
                        },
                    );
                    self.evict_stale_hosts();
                    debug!("USS: ping host {host} joined at {latency_ms:.1}ms");
                    return;
                };
                // Two samples in a row under the floor prove a lower one; a
                // single reading could be a clock or scheduling artefact.
                // The larger of the two, so the floor never undercuts what
                // the path actually showed twice.
                if latency_ms < entry.baseline_ms && entry.last_ms < entry.baseline_ms {
                    entry.baseline_ms = latency_ms.max(entry.last_ms);
                    debug!(
                        "USS: new baseline RTT for {host}: {:.1}ms",
                        entry.baseline_ms
                    );
                }
                entry.last_ms = latency_ms;
                entry.seen = seq;
                let ratio = latency_ms / entry.baseline_ms;
                if self.ratios.len() >= MONITOR_WINDOW {
                    self.ratios.pop_front();
                }
                self.ratios.push_back(ratio);
                self.fresh_sample = true;
            }
        }
    }

    fn promote(&mut self) {
        let was_stalled = self.baseline_stalled;
        self.state = UssState::Monitoring;
        self.baseline_stalled = false;
        self.prepare_started = None;
        self.ratios.clear();
        self.fresh_sample = false;
        // Start monitoring from the configured ceiling; RTT will pull it
        // down if the full rate congests the path.
        if self.max_upload > 0 {
            self.current_limit = self.max_upload;
        }
        let lowest = self
            .hosts
            .values()
            .map(|h| h.baseline_ms)
            .fold(f64::INFINITY, f64::min);
        info!(
            "USS: baseline established from {} samples over {} host(s), lowest {:.1}ms{}",
            self.prepare_samples,
            self.hosts.len(),
            lowest,
            if was_stalled { " (after fallback)" } else { "" }
        );
    }

    fn evict_stale_hosts(&mut self) {
        while self.hosts.len() > MAX_HOSTS {
            let Some(stalest) = self
                .hosts
                .iter()
                .min_by_key(|(_, h)| h.seen)
                .map(|(addr, _)| *addr)
            else {
                break;
            };
            self.hosts.remove(&stalest);
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
            if deadline_passed && !self.baseline_stalled {
                if self.prepare_samples >= MIN_BASELINE_SAMPLES {
                    self.promote();
                    return Some(self.current_limit.clamp(self.min_upload, self.effective_max()));
                }
                self.baseline_stalled = true;
                warn!(
                    "USS: no RTT baseline after {PREPARE_BASELINE_TIMEOUT_SECS}s \
                     ({}/{MIN_BASELINE_SAMPLES} samples); running at the configured \
                     upload cap instead of throttling",
                    self.prepare_samples
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

        if self.state != UssState::Monitoring {
            return None;
        }

        if self.ratios.len() < MONITOR_WINDOW || !self.fresh_sample {
            return Some(
                self.current_limit
                    .clamp(self.min_upload, self.effective_max()),
            );
        }
        self.fresh_sample = false;

        let current_ratio = self.recent_median_ratio();
        let target_ratio = self.ping_tolerance;

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

        if current_ratio > target_ratio {
            let step = (1.0 / down_divider).min(MAX_DOWN_FRACTION);
            let new_limit = (self.current_limit as f64 * (1.0 - step)) as u64;
            self.current_limit = new_limit.max(self.min_upload);
            self.clamp_to_max();
            debug!(
                "USS: RTT {current_ratio:.2}x baseline > {target_ratio:.2}x, decreasing to {} B/s",
                self.current_limit
            );
        } else {
            let headroom = 1.0 - (current_ratio / target_ratio);
            if headroom > 0.1 {
                let step = (1.0 / up_divider).min(MAX_UP_FRACTION);
                let new_limit = (self.current_limit as f64 * (1.0 + step)) as u64;
                self.current_limit = new_limit;
                self.clamp_to_max();
                debug!(
                    "USS: RTT {current_ratio:.2}x baseline < {target_ratio:.2}x, increasing to {} B/s",
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

    fn recent_median_ratio(&self) -> f64 {
        if self.ratios.is_empty() {
            return 0.0;
        }
        let mut sorted: Vec<f64> = self.ratios.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mid = sorted.len() / 2;
        if sorted.len().is_multiple_of(2) {
            (sorted[mid - 1] + sorted[mid]) / 2.0
        } else {
            sorted[mid]
        }
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

    fn host(n: u8) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, n], 4672))
    }

    fn host_a() -> SocketAddr {
        host(1)
    }

    fn host_b() -> SocketAddr {
        "198.51.100.7:4672".parse().unwrap()
    }

    fn ping(uss: &mut UploadSpeedSense, ms: f64) {
        uss.record_ping(host_a(), ms);
    }

    fn baseline(uss: &UploadSpeedSense, addr: SocketAddr) -> f64 {
        uss.hosts[&addr].baseline_ms
    }

    /// Pretend the quiet-baseline phase started before its deadline.
    fn expire_prepare_deadline(uss: &mut UploadSpeedSense) {
        uss.prepare_started =
            Instant::now().checked_sub(Duration::from_secs(PREPARE_BASELINE_TIMEOUT_SECS + 1));
        assert!(uss.prepare_started.is_some(), "monotonic clock too young");
    }

    fn monitoring_at(baseline_ms: f64) -> UploadSpeedSense {
        let mut uss = UploadSpeedSense::new(0, 1_000_000);
        uss.enable();
        for _ in 0..BASELINE_SAMPLES {
            ping(&mut uss, baseline_ms);
        }
        assert_eq!(uss.state(), UssState::Monitoring);
        uss
    }

    #[test]
    fn preparing_holds_min_until_baseline() {
        let mut uss = UploadSpeedSense::new(0, 100_000);
        uss.enable();
        assert_eq!(uss.state(), UssState::Preparing);
        assert_eq!(uss.compute_limit(), Some(uss.min_upload));

        for n in 0..BASELINE_SAMPLES as u8 {
            assert_eq!(uss.compute_limit(), Some(uss.min_upload));
            uss.record_ping(host(n % 3 + 1), 40.0);
        }
        assert_eq!(uss.state(), UssState::Monitoring);
        assert!((baseline(&uss, host(1)) - 40.0).abs() < f64::EPSILON);
        // Monitoring starts at the configured ceiling.
        assert_eq!(uss.compute_limit(), Some(100_000));
    }

    #[test]
    fn baseline_uses_lowest_sample_per_host() {
        let mut uss = UploadSpeedSense::new(0, 100_000);
        uss.enable();
        uss.record_ping(host_a(), 80.0);
        uss.record_ping(host_b(), 200.0);
        uss.record_ping(host_a(), 50.0);
        uss.record_ping(host_b(), 180.0);
        uss.record_ping(host_a(), 90.0);
        assert_eq!(uss.state(), UssState::Monitoring);
        assert!((baseline(&uss, host_a()) - 50.0).abs() < f64::EPSILON);
        assert!((baseline(&uss, host_b()) - 180.0).abs() < f64::EPSILON);
    }

    #[test]
    fn baseline_ratchets_down_on_two_lower_samples_in_a_row() {
        let mut uss = monitoring_at(50.0);

        // One quieter reading must not move the floor.
        ping(&mut uss, 10.0);
        ping(&mut uss, 60.0);
        assert!(
            (baseline(&uss, host_a()) - 50.0).abs() < f64::EPSILON,
            "baseline moved to {} after a single quiet sample",
            baseline(&uss, host_a())
        );

        // Two in a row may, to the higher of the two.
        ping(&mut uss, 30.0);
        ping(&mut uss, 32.0);
        assert!((baseline(&uss, host_a()) - 32.0).abs() < f64::EPSILON);
    }

    /// A baseline taken at the full cap (the stalled fallback, or a host met
    /// under load) has to come down once the path is quiet again, or USS
    /// stays twice as tolerant as it should for the rest of the session.
    #[test]
    fn a_baseline_measured_under_load_comes_down_when_the_path_clears() {
        let mut uss = monitoring_at(40.0);
        uss.record_ping(host_b(), 300.0);
        assert!((baseline(&uss, host_b()) - 300.0).abs() < f64::EPSILON);
        uss.record_ping(host_b(), 120.0);
        uss.record_ping(host_b(), 110.0);
        assert!((baseline(&uss, host_b()) - 120.0).abs() < f64::EPSILON);
    }

    #[test]
    fn decrease_is_capped_per_tick() {
        let mut uss = monitoring_at(40.0);
        // Force an immediate overshoot well above target (40 * 2.0 = 80).
        for _ in 0..MONITOR_WINDOW {
            ping(&mut uss, 400.0);
        }
        let before = uss.current_limit;
        let after = uss.compute_limit().unwrap();
        assert!(after < before);
        // Must not collapse by more than the hard fraction cap in one tick.
        assert!(after as f64 >= before as f64 * (1.0 - MAX_DOWN_FRACTION) - 1.0);
    }

    /// eMule reacts within about a second. Pinging a KAD pool gives a sample
    /// every few seconds, and the limit has to move on the second congested
    /// one, not after a full minute-long window.
    #[test]
    fn congestion_moves_the_limit_on_the_second_congested_sample() {
        let mut uss = monitoring_at(40.0);
        ping(&mut uss, 42.0);
        assert_eq!(uss.compute_limit(), Some(1_000_000));
        ping(&mut uss, 400.0);
        assert_eq!(uss.compute_limit(), Some(1_000_000), "one spike is not congestion");
        ping(&mut uss, 400.0);
        assert!(uss.compute_limit().unwrap() < 1_000_000);
    }

    #[test]
    fn lowered_max_clamps_current_limit() {
        let mut uss = UploadSpeedSense::new(0, 100_000);
        uss.enable();
        for _ in 0..BASELINE_SAMPLES {
            ping(&mut uss, 40.0);
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

    /// With a single eligible contact the cadence is one ping per 31.5 s, so
    /// the deadline sees about two quiet samples. That is a baseline; giving
    /// up and measuring one at the full cap instead is what left USS without
    /// a quiet reference at all.
    #[test]
    fn a_short_quiet_baseline_is_taken_at_the_deadline() {
        let mut uss = UploadSpeedSense::new(0, 1_000_000);
        uss.enable();
        ping(&mut uss, 40.0);
        ping(&mut uss, 45.0);
        assert_eq!(uss.compute_limit(), Some(100_000));
        expire_prepare_deadline(&mut uss);
        assert_eq!(uss.compute_limit(), Some(1_000_000));
        assert_eq!(uss.state(), UssState::Monitoring);
        assert!((baseline(&uss, host_a()) - 40.0).abs() < f64::EPSILON);
    }

    #[test]
    fn starved_baseline_falls_back_yet_late_samples_still_engage_uss() {
        let mut uss = UploadSpeedSense::new(0, 1_000_000);
        uss.enable();
        // A host answered once, then went away.
        ping(&mut uss, 40.0);
        assert_eq!(uss.compute_limit(), Some(100_000));
        expire_prepare_deadline(&mut uss);
        assert_eq!(uss.compute_limit(), Some(1_000_000));
        assert_eq!(uss.state(), UssState::Preparing);

        // The fallback must not latch USS off: enough samples still promote to
        // Monitoring and hand control of the cap back to RTT.
        for _ in 0..BASELINE_SAMPLES {
            ping(&mut uss, 40.0);
        }
        assert_eq!(uss.state(), UssState::Monitoring);
        assert!(!uss.baseline_stalled);
        assert!((baseline(&uss, host_a()) - 40.0).abs() < f64::EPSILON);
    }

    #[test]
    fn baseline_in_time_is_unaffected_by_the_deadline() {
        let mut uss = monitoring_at(40.0);
        // An expired-looking start time must not disturb an established
        // baseline; only the Preparing branch consults it.
        expire_prepare_deadline(&mut uss);
        assert!(!uss.baseline_stalled);
        assert_eq!(uss.compute_limit(), Some(1_000_000));
    }

    #[test]
    fn one_sample_moves_the_limit_once() {
        let mut uss = monitoring_at(40.0);
        assert_eq!(uss.compute_limit(), Some(1_000_000));
        for _ in 0..MONITOR_WINDOW {
            ping(&mut uss, 400.0);
        }
        let first = uss.compute_limit().unwrap();
        assert!(first < 1_000_000);
        for _ in 0..30 {
            assert_eq!(
                uss.compute_limit(),
                Some(first),
                "no new sample, so no new step"
            );
        }
        ping(&mut uss, 400.0);
        assert!(uss.compute_limit().unwrap() < first);
    }

    #[test]
    fn congestion_ending_is_seen_within_the_recent_window() {
        let mut uss = monitoring_at(40.0);
        for _ in 0..30 {
            ping(&mut uss, 400.0);
            uss.compute_limit();
        }
        let throttled = uss.current_limit;
        for _ in 0..MONITOR_WINDOW {
            ping(&mut uss, 40.0);
        }
        assert!(
            uss.compute_limit().unwrap() > throttled,
            "a quiet window must start the climb back, whatever older samples say"
        );
    }

    /// The pool mixes near and far contacts. Each is judged against its own
    /// floor, so a far host is not congestion on an idle link.
    #[test]
    fn hosts_are_judged_against_their_own_baseline() {
        let mut uss = UploadSpeedSense::new(0, 1_000_000);
        uss.enable();
        for n in 0..BASELINE_SAMPLES {
            if n % 2 == 0 {
                uss.record_ping(host_a(), 25.0);
            } else {
                uss.record_ping(host_b(), 250.0);
            }
        }
        assert_eq!(uss.state(), UssState::Monitoring);
        for n in 0..20 {
            if n % 2 == 0 {
                uss.record_ping(host_a(), 27.0);
            } else {
                uss.record_ping(host_b(), 260.0);
            }
            assert_eq!(uss.compute_limit(), Some(1_000_000), "not congestion for either host");
        }
        for n in 0..MONITOR_WINDOW {
            if n % 2 == 0 {
                uss.record_ping(host_a(), 90.0);
            } else {
                uss.record_ping(host_b(), 600.0);
            }
        }
        assert!(uss.compute_limit().unwrap() < 1_000_000, "both hosts slowed down");
    }

    /// A host first met in Monitoring has no quiet floor yet, so its first
    /// sample is a baseline, not a congestion reading.
    #[test]
    fn a_new_host_in_monitoring_is_not_judged_on_its_first_sample() {
        let mut uss = monitoring_at(25.0);
        let before = uss.ratios.len();
        uss.record_ping(host_b(), 100.0);
        assert_eq!(uss.ratios.len(), before);
        assert!((baseline(&uss, host_b()) - 100.0).abs() < f64::EPSILON);
        for _ in 0..10 {
            uss.record_ping(host_b(), 110.0);
            assert_eq!(uss.compute_limit(), Some(1_000_000), "not congestion for this host");
        }
    }

    #[test]
    fn remembered_hosts_are_bounded() {
        let mut uss = monitoring_at(25.0);
        for n in 0..(MAX_HOSTS as u8 + 10) {
            uss.record_ping(SocketAddr::from(([203, 0, 113, n], 4672)), 50.0);
        }
        assert_eq!(uss.hosts.len(), MAX_HOSTS);
        assert!(
            uss.hosts.contains_key(&SocketAddr::from(([203, 0, 113, MAX_HOSTS as u8 + 9], 4672))),
            "the newest host is kept"
        );
    }
}
