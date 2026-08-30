use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

/// eMule-style bandwidth limiter with token bucket and partial acquisition.
///
/// Key differences from a naive token bucket:
/// - Handles pieces larger than max_rate via partial (chunked) acquisition
/// - Token bucket cap = 2 * max_rate to allow short bursts (eMule saves unused bandwidth)
/// - Tracks per-second and smoothed speeds for display
pub struct BandwidthLimiter {
    max_upload_rate: AtomicU64,
    max_download_rate: AtomicU64,
    /// User-configured upload limit, not modified by USS
    configured_upload_rate: AtomicU64,
    upload_tokens: AtomicU64,
    download_tokens: AtomicU64,
    /// Sub-token remainders carried between refill ticks so that very low
    /// rates (where `max_rate * fraction < divisor`) are honored exactly
    /// instead of being rounded up to a 1-token-per-tick floor.
    upload_refill_rem: AtomicU64,
    download_refill_rem: AtomicU64,
    total_uploaded: AtomicU64,
    total_downloaded: AtomicU64,
    upload_speed: AtomicU64,
    download_speed: AtomicU64,
    smoothed_upload: AtomicU64,
    smoothed_download: AtomicU64,
    /// True while the USS controller is actively managing the effective
    /// upload rate. Set by the bandwidth refill task on USS enable/disable
    /// transitions; read by `set_configured_limits` so a settings save does
    /// not slam the effective rate back up to the configured cap and undo an
    /// in-progress USS throttle.
    uss_active: AtomicBool,
    refill_notify: Arc<Notify>,
    /// Starts true so unit tests without a refill task still park on an empty
    /// bucket. The refill task sets this false on Drop so waiters abort
    /// instead of hanging forever.
    refill_alive: AtomicBool,
}

impl BandwidthLimiter {
    pub fn new(max_upload: u64, max_download: u64) -> Self {
        Self {
            max_upload_rate: AtomicU64::new(max_upload),
            max_download_rate: AtomicU64::new(max_download),
            configured_upload_rate: AtomicU64::new(max_upload),
            upload_tokens: AtomicU64::new(max_upload),
            download_tokens: AtomicU64::new(max_download),
            upload_refill_rem: AtomicU64::new(0),
            download_refill_rem: AtomicU64::new(0),
            total_uploaded: AtomicU64::new(0),
            total_downloaded: AtomicU64::new(0),
            upload_speed: AtomicU64::new(0),
            download_speed: AtomicU64::new(0),
            smoothed_upload: AtomicU64::new(0),
            smoothed_download: AtomicU64::new(0),
            uss_active: AtomicBool::new(false),
            refill_notify: Arc::new(Notify::new()),
            refill_alive: AtomicBool::new(true),
        }
    }

    /// Acquire upload bandwidth. Returns `false` if the refill task has died
    /// and tokens cannot be obtained without bypassing the cap. Callers must
    /// abort the transfer rather than send unbounded.
    pub async fn acquire_upload(&self, bytes: u64) -> bool {
        let max = self.max_upload_rate.load(Ordering::Relaxed);
        if max == 0 {
            self.total_uploaded.fetch_add(bytes, Ordering::Relaxed);
            return true;
        }
        if !self
            .drain_tokens(&self.upload_tokens, bytes, &self.max_upload_rate)
            .await
        {
            return false;
        }
        self.total_uploaded.fetch_add(bytes, Ordering::Relaxed);
        true
    }

    /// Take up to `max_bytes` of upload allowance without waiting, returning how
    /// much was taken.
    ///
    /// For callers that cannot park on [`acquire_upload`]: the network event loop
    /// drives Ember channel transfers between polls of every other socket, so
    /// blocking there for tokens would stall KAD, IPC and the DHT along with it.
    /// A partial take is honest — the caller accumulates allowance across ticks
    /// and sends once it has enough — which is what keeps a cap smaller than one
    /// frame from either overshooting or deadlocking.
    ///
    /// Unlimited (0) is reported as fully granted and still counted.
    pub fn try_take_upload(&self, max_bytes: u64) -> u64 {
        if max_bytes == 0 {
            return 0;
        }
        if self.max_upload_rate.load(Ordering::Relaxed) == 0 {
            self.total_uploaded.fetch_add(max_bytes, Ordering::Relaxed);
            return max_bytes;
        }
        loop {
            let current = self.upload_tokens.load(Ordering::Acquire);
            if current == 0 {
                return 0;
            }
            let take = max_bytes.min(current);
            if self
                .upload_tokens
                .compare_exchange_weak(
                    current,
                    current - take,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                self.total_uploaded.fetch_add(take, Ordering::Relaxed);
                return take;
            }
        }
    }

    /// Acquire download bandwidth. Returns `false` if the refill task has died
    /// and tokens cannot be obtained without bypassing the cap.
    pub async fn acquire_download(&self, bytes: u64) -> bool {
        let max = self.max_download_rate.load(Ordering::Relaxed);
        if max == 0 {
            self.total_downloaded.fetch_add(bytes, Ordering::Relaxed);
            return true;
        }
        if !self
            .drain_tokens(&self.download_tokens, bytes, &self.max_download_rate)
            .await
        {
            return false;
        }
        self.total_downloaded.fetch_add(bytes, Ordering::Relaxed);
        true
    }

    /// Core token drain: takes as many tokens as available per iteration,
    /// waiting on a `Notify` signal when the bucket is empty instead of
    /// busy-polling. The refill task notifies after adding tokens.
    ///
    /// Blocks until all `remaining` bytes are acquired. Removing the old
    /// 6000-attempt give-up loop (which returned `remaining > 0` and let the
    /// caller then send the bytes anyway, silently bypassing the rate cap
    /// after ~10 minutes of sustained pressure).
    ///
    /// To avoid a runaway loop if the refill task dies or the limit is set
    /// impossibly low, we log a single warning once the wait exceeds 60s
    /// but keep waiting — shutdown is the caller's responsibility (upload
    /// sessions already poll `network_disconnected`).
    ///
    /// `max_rate` is the live rate atomic (not a snapshot) so we can observe
    /// a runtime switch to "unlimited" (0) mid-drain. Without re-checking it,
    /// a task parked on an empty bucket when the user sets the limit to
    /// unlimited would block forever: `refill_tokens_incremental` adds no
    /// tokens while the rate is 0, so the bucket never refills and the
    /// refill `Notify` never fires for this pool again.
    ///
    /// Returns `false` if the refill task is gone so the caller can abort
    /// instead of treating the remainder as unlimited.
    async fn drain_tokens(&self, tokens: &AtomicU64, mut remaining: u64, max_rate: &AtomicU64) -> bool {
        let start = std::time::Instant::now();
        let mut warned_slow = false;
        while remaining > 0 {
            // Stop throttling immediately if the rate became "unlimited"
            // after this call started draining (0 == unlimited).
            if max_rate.load(Ordering::Relaxed) == 0 {
                return true;
            }
            let current = tokens.load(Ordering::Acquire);
            if current == 0 {
                if !self.refill_alive.load(Ordering::Acquire) {
                    return false;
                }
                // 25 ms wake granularity (was 100 ms). The refill task
                // calls `notify_waiters()` on every refill — which is the
                // primary wakeup — but the timeout is the safety net for
                // the (rare) case where a refill happened between our
                // load and our `notified()` registration. Tightening it
                // to 25 ms keeps worst-case extra latency near the
                // refill cadence (REFILL_INTERVAL_MS = 100 ms / 4 ticks)
                // instead of an order of magnitude slower.
                tokio::time::timeout(Duration::from_millis(25), self.refill_notify.notified())
                    .await
                    .ok();
                if !warned_slow && start.elapsed() > Duration::from_secs(60) {
                    warned_slow = true;
                    tracing::warn!(
                        "drain_tokens: waited >60s for bandwidth tokens (remaining={remaining}); check rate limit / refill task"
                    );
                }
                continue;
            }
            let take = remaining.min(current);
            match tokens.compare_exchange_weak(
                current,
                current - take,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    remaining -= take;
                }
                Err(_) => {
                    continue;
                }
            }
        }
        true
    }

    /// Add a fraction of the rate limit worth of tokens (called at sub-second intervals).
    /// Tokens are capped at 2x the max rate to allow short bursts (eMule behavior).
    pub fn refill_tokens_incremental(&self, fraction: u64, divisor: u64) {
        if divisor == 0 {
            return;
        }
        let max_up = self.max_upload_rate.load(Ordering::Relaxed);
        let max_down = self.max_download_rate.load(Ordering::Relaxed);

        // Carry sub-token remainders between ticks so the long-run refill
        // rate equals exactly `max_rate` even when `max_rate * fraction <
        // divisor` (the old `.max(1)` floor over-served low limits, e.g. a
        // 5 B/s cap refilled at ~10 B/s). The refill timer is the only caller,
        // so the remainder load/store needs no cross-task synchronization.
        if max_up > 0 {
            let prev_rem = self.upload_refill_rem.load(Ordering::Relaxed);
            let numer = max_up.saturating_mul(fraction).saturating_add(prev_rem);
            let add = numer / divisor;
            self.upload_refill_rem
                .store(numer % divisor, Ordering::Relaxed);
            let cap = max_up.saturating_mul(2);
            loop {
                let current = self.upload_tokens.load(Ordering::Relaxed);
                let new_val = (current + add).min(cap);
                if self
                    .upload_tokens
                    .compare_exchange_weak(current, new_val, Ordering::Release, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
        } else {
            self.upload_refill_rem.store(0, Ordering::Relaxed);
        }
        if max_down > 0 {
            let prev_rem = self.download_refill_rem.load(Ordering::Relaxed);
            let numer = max_down.saturating_mul(fraction).saturating_add(prev_rem);
            let add = numer / divisor;
            self.download_refill_rem
                .store(numer % divisor, Ordering::Relaxed);
            let cap = max_down.saturating_mul(2);
            loop {
                let current = self.download_tokens.load(Ordering::Relaxed);
                let new_val = (current + add).min(cap);
                if self
                    .download_tokens
                    .compare_exchange_weak(current, new_val, Ordering::Release, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
        } else {
            self.download_refill_rem.store(0, Ordering::Relaxed);
        }
        self.refill_notify.notify_waiters();
    }

    /// Set ONLY the effective upload rate (used by USS dynamic throttling),
    /// clamping the upload token bucket to the new 2× burst cap. Without the
    /// clamp, lowering the rate would leave stale tokens from the previous
    /// (higher) cap spendable, letting uploads briefly burst above the new
    /// USS limit. The user-configured rate and download side are untouched.
    pub fn set_upload_limit(&self, upload: u64) {
        self.max_upload_rate.store(upload, Ordering::Relaxed);
        if upload > 0 {
            let cap = upload.saturating_mul(2);
            loop {
                let current = self.upload_tokens.load(Ordering::Relaxed);
                if current <= cap {
                    break;
                }
                if self
                    .upload_tokens
                    .compare_exchange_weak(current, cap, Ordering::Release, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
        }
    }

    /// Set ONLY the effective download rate, clamping the download token
    /// bucket to the new 2× burst cap. Symmetric to `set_upload_limit`; used
    /// by `set_configured_limits` so the download side can be applied
    /// independently of the USS-managed upload side.
    pub fn set_download_limit(&self, download: u64) {
        self.max_download_rate.store(download, Ordering::Relaxed);
        if download > 0 {
            let cap = download.saturating_mul(2);
            loop {
                let current = self.download_tokens.load(Ordering::Relaxed);
                if current <= cap {
                    break;
                }
                if self
                    .download_tokens
                    .compare_exchange_weak(current, cap, Ordering::Release, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
        }
    }

    /// Mark whether the USS controller is currently managing the effective
    /// upload rate. Called by the bandwidth refill task on USS enable/disable
    /// transitions so `set_configured_limits` knows not to override an
    /// in-progress throttle.
    pub fn set_uss_active(&self, active: bool) {
        self.uss_active.store(active, Ordering::Relaxed);
    }

    pub fn set_limits(&self, upload: u64, download: u64) {
        self.max_upload_rate.store(upload, Ordering::Relaxed);
        self.max_download_rate.store(download, Ordering::Relaxed);
        // Clamp existing token balances down to the new burst cap (2× max).
        // Without this, lowering a limit at runtime would leave a stale
        // token balance from the previous cap that callers can spend
        // immediately, allowing transfers to run above the user's just-
        // saved limit until those tokens drain. `0` means "unlimited" on
        // the rate side; we leave the token pool alone in that case.
        if upload > 0 {
            let cap = upload.saturating_mul(2);
            loop {
                let current = self.upload_tokens.load(Ordering::Relaxed);
                if current <= cap {
                    break;
                }
                if self
                    .upload_tokens
                    .compare_exchange_weak(current, cap, Ordering::Release, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
        }
        if download > 0 {
            let cap = download.saturating_mul(2);
            loop {
                let current = self.download_tokens.load(Ordering::Relaxed);
                if current <= cap {
                    break;
                }
                if self
                    .download_tokens
                    .compare_exchange_weak(current, cap, Ordering::Release, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
        }
    }

    pub fn set_configured_limits(&self, upload: u64, download: u64) {
        let prev_configured = self.configured_upload_rate.load(Ordering::Relaxed);
        self.configured_upload_rate.store(upload, Ordering::Relaxed);

        // While USS is actively throttling (the effective rate is being held
        // below the configured cap), a settings save must NOT raise the
        // effective upload rate back to the full configured value: that undoes
        // the throttle and lets uploads burst to the cap for up to a second
        // until the USS loop re-clamps — the exact latency spike USS exists to
        // prevent. Detect active throttling as `effective < prev_configured`.
        // In that state we only ever LOWER the effective rate here (a reduced
        // hard cap must take effect immediately); a raised cap is left for USS
        // to ramp toward on its own (it reads `configured_upload_rate` each
        // second). When USS is not throttling (disabled, preparing, or sitting
        // at the cap) we apply the new limits directly so changes take effect
        // at once. The download side is never managed by USS.
        let effective = self.max_upload_rate.load(Ordering::Relaxed);
        let uss_throttling = self.uss_active.load(Ordering::Relaxed)
            && prev_configured > 0
            && effective < prev_configured;

        if uss_throttling {
            self.set_download_limit(download);
            // `upload == 0` means "unlimited" — an explicit user override
            // that must take effect immediately just like a reduced cap;
            // leaving it pinned at the still-throttled `effective` rate
            // until USS releases would mean "Unlimited" silently doesn't
            // apply until USS decides latency has recovered, which can be
            // well after the user expected it to.
            if upload == 0 || upload < effective {
                self.set_upload_limit(upload);
            }
        } else {
            self.set_limits(upload, download);
        }
    }

    pub fn configured_upload_rate(&self) -> u64 {
        self.configured_upload_rate.load(Ordering::Relaxed)
    }

    pub fn effective_upload_rate(&self) -> u64 {
        self.max_upload_rate.load(Ordering::Relaxed)
    }

    pub fn total_uploaded(&self) -> u64 {
        self.total_uploaded.load(Ordering::Relaxed)
    }

    pub fn total_downloaded(&self) -> u64 {
        self.total_downloaded.load(Ordering::Relaxed)
    }

    /// Per-second upload delta (raw, unsmoothed). Kept as part of the
    /// limiter's public API for future consumers; `smoothed_upload_speed` is
    /// what the UI currently reads.
    #[allow(dead_code)]
    pub fn upload_speed(&self) -> u64 {
        self.upload_speed.load(Ordering::Relaxed)
    }

    /// Per-second download delta (raw, unsmoothed). See `upload_speed`.
    #[allow(dead_code)]
    pub fn download_speed(&self) -> u64 {
        self.download_speed.load(Ordering::Relaxed)
    }

    pub fn update_speeds(&self, uploaded_delta: u64, downloaded_delta: u64) {
        self.upload_speed.store(uploaded_delta, Ordering::Relaxed);
        self.download_speed
            .store(downloaded_delta, Ordering::Relaxed);

        let prev_up = self.smoothed_upload.load(Ordering::Relaxed);
        let smoothed_up = uploaded_delta
            .saturating_mul(30)
            .saturating_add(prev_up.saturating_mul(70))
            / 100;
        self.smoothed_upload.store(smoothed_up, Ordering::Relaxed);

        let prev_down = self.smoothed_download.load(Ordering::Relaxed);
        let smoothed_down = downloaded_delta
            .saturating_mul(30)
            .saturating_add(prev_down.saturating_mul(70))
            / 100;
        self.smoothed_download
            .store(smoothed_down, Ordering::Relaxed);
    }

    pub fn smoothed_upload_speed(&self) -> u64 {
        self.smoothed_upload.load(Ordering::Relaxed)
    }

    pub fn smoothed_download_speed(&self) -> u64 {
        self.smoothed_download.load(Ordering::Relaxed)
    }

    fn mark_refill_stopped(&self) {
        self.refill_alive.store(false, Ordering::Release);
        self.refill_notify.notify_waiters();
    }

    #[cfg(test)]
    pub fn stop_refill_for_test(&self) {
        self.mark_refill_stopped();
    }
}

struct RefillAliveGuard {
    limiter: std::sync::Arc<BandwidthLimiter>,
}

impl Drop for RefillAliveGuard {
    fn drop(&mut self) {
        self.limiter.mark_refill_stopped();
    }
}

pub async fn start_token_refill(
    limiter: std::sync::Arc<BandwidthLimiter>,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    uss_rtt_queue: super::UssRttQueue,
    uss_enabled_flag: super::UssEnabledFlag,
) {
    const REFILL_INTERVAL_MS: u64 = 100;
    const TICKS_PER_SECOND: u64 = 1000 / REFILL_INTERVAL_MS;

    limiter.refill_alive.store(true, Ordering::Release);
    let _refill_guard = RefillAliveGuard {
        limiter: limiter.clone(),
    };

    let max_up = limiter.max_upload_rate.load(Ordering::Relaxed);
    let mut uss = super::uss::UploadSpeedSense::new(0, max_up);

    let mut interval = tokio::time::interval(Duration::from_millis(REFILL_INTERVAL_MS));
    // Skip, not the default Burst. After a runtime stall Burst replays one
    // iteration per missed tick; token balances survive that (they cap at
    // 2*max), but `speed_tick_count` fires `uss.compute_limit()` once per
    // simulated second against unchanged `ping_history`, and USS cuts 20% per
    // call — so ~11 catch-up iterations collapse the upload cap to the
    // `sanitize_min_upload` floor and it takes 15-20 real seconds to ramp back.
    // Every timer in `network/mod.rs` sets Skip for the same reason.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_uploaded = limiter.total_uploaded();
    let mut last_downloaded = limiter.total_downloaded();
    let mut speed_tick_count: u64 = 0;

    loop {
        interval.tick().await;
        // Refill before the teardown check, because `bw_shutdown` means "flush
        // state now", not "this process is about to die". The updater raises it
        // before handing the bundle to the installer, and an install that fails
        // returns with the process still running (`commands/updater.rs`).
        // Returning here ended the only task that ever adds tokens, so every
        // rate-limited upload drained the bucket and then parked on it for the
        // rest of the session — the "if the refill task dies" case
        // `drain_tokens` warns about, and invisible unless someone reads the
        // log. Downloads escaped it only when left unlimited, since
        // `acquire_download` returns early at rate 0.
        limiter.refill_tokens_incremental(1, TICKS_PER_SECOND);
        if shutdown.load(Ordering::Relaxed) {
            // Stand USS down once, and hand back any throttle it was holding:
            // `set_configured_limits` treats a still-`uss_active` limiter as
            // mid-throttle and declines to raise the effective rate, waiting for
            // USS to ramp on its own — which never happens again from here.
            if uss.is_enabled() {
                uss.disable();
                limiter.set_uss_active(false);
                limiter.set_upload_limit(limiter.configured_upload_rate());
            }
            // Keep refilling, but stop managing USS: re-reading the settings
            // flag below would re-enable it a tick later.
            continue;
        }

        // Drain real KAD RTT samples from the network loop. Cap drain size so a
        // stuck lock elsewhere cannot leave an ever-growing queue.
        let uss_state_before_drain = uss.state();
        if let Ok(mut queue) = uss_rtt_queue.try_lock() {
            let mut drained = 0;
            while drained < 64 {
                let Some(rtt_ms) = queue.pop_front() else {
                    break;
                };
                uss.record_ping(rtt_ms);
                drained += 1;
            }
            // Drop stale backlog rather than applying minutes-old RTTs.
            if queue.len() > 64 {
                let overflow = queue.len() - 64;
                queue.drain(0..overflow);
            }
        }
        // When Preparing→Monitoring flips mid-interval, apply the new ceiling
        // immediately so uploads are not stuck at the quiet baseline for up to
        // another second waiting on the 1 Hz tick.
        if uss.is_enabled()
            && uss_state_before_drain == super::uss::UssState::Preparing
            && uss.state() == super::uss::UssState::Monitoring
        {
            let configured_max = limiter.configured_upload_rate();
            if let Some(new_limit) = uss.compute_limit() {
                let capped = if configured_max > 0 {
                    new_limit.min(configured_max)
                } else {
                    new_limit
                };
                limiter.set_upload_limit(capped);
            }
        }

        // Sync USS enabled state from user settings
        let want_enabled =
            uss_enabled_flag.load(Ordering::Relaxed) && limiter.configured_upload_rate() > 0;
        if want_enabled && !uss.is_enabled() {
            let max = limiter.configured_upload_rate();
            uss.set_limits(0, max);
            uss.enable();
            limiter.set_uss_active(true);
            // Begin the quiet baseline immediately rather than waiting up to
            // a second for the next compute_limit tick.
            if let Some(prep) = uss.compute_limit() {
                limiter.set_upload_limit(prep);
            }
        } else if !want_enabled && uss.is_enabled() {
            uss.disable();
            limiter.set_uss_active(false);
            // Restore the configured cap through set_upload_limit so the token
            // bucket burst cap is reclamped consistently with other paths.
            limiter.set_upload_limit(limiter.configured_upload_rate());
        }

        speed_tick_count += 1;
        if speed_tick_count >= TICKS_PER_SECOND {
            speed_tick_count = 0;
            let current_up = limiter.total_uploaded();
            let current_down = limiter.total_downloaded();
            let up_speed = current_up.saturating_sub(last_uploaded);
            let down_speed = current_down.saturating_sub(last_downloaded);
            limiter.update_speeds(up_speed, down_speed);
            last_uploaded = current_up;
            last_downloaded = current_down;

            if uss.is_enabled() {
                // Apply the live configured cap *before* computing the next
                // USS limit so a user-lowered max cannot be exceeded for a
                // full second by a stale current_limit.
                let configured_max = limiter.configured_upload_rate();
                if configured_max > 0 {
                    uss.set_limits(0, configured_max);
                }
                if let Some(new_limit) = uss.compute_limit() {
                    let capped = if configured_max > 0 {
                        new_limit.min(configured_max)
                    } else {
                        new_limit
                    };
                    limiter.set_upload_limit(capped);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BandwidthLimiter;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn set_configured_limits_applies_fully_when_uss_inactive() {
        let bw = BandwidthLimiter::new(100, 100);
        // Raise: takes effect immediately.
        bw.set_configured_limits(200, 150);
        assert_eq!(bw.configured_upload_rate(), 200);
        assert_eq!(bw.effective_upload_rate(), 200);
        // Lower: takes effect immediately.
        bw.set_configured_limits(50, 150);
        assert_eq!(bw.effective_upload_rate(), 50);
    }

    #[test]
    fn settings_save_does_not_burst_past_uss_throttle() {
        let bw = BandwidthLimiter::new(100, 100);
        bw.set_uss_active(true);
        // Simulate USS throttling the effective rate well below the cap.
        bw.set_upload_limit(30);
        assert_eq!(bw.effective_upload_rate(), 30);

        // User saves settings raising the cap while USS is throttling: the
        // effective rate must NOT jump back up to the configured cap (the bug),
        // it stays at the USS-controlled value for USS to ramp from.
        bw.set_configured_limits(200, 100);
        assert_eq!(bw.configured_upload_rate(), 200);
        assert_eq!(
            bw.effective_upload_rate(),
            30,
            "effective upload must not burst past the USS throttle on settings save"
        );
    }

    #[test]
    fn lowered_hard_cap_below_throttle_applies_immediately() {
        let bw = BandwidthLimiter::new(100, 100);
        bw.set_uss_active(true);
        bw.set_upload_limit(30); // USS throttle
                                 // User lowers the hard cap below the current throttle: must win now.
        bw.set_configured_limits(20, 100);
        assert_eq!(bw.effective_upload_rate(), 20);
    }

    #[test]
    fn uss_active_but_at_cap_applies_raise_immediately() {
        // USS enabled but not throttling (effective == configured): a raised
        // cap should take effect at once so it isn't stuck while USS prepares.
        let bw = BandwidthLimiter::new(100, 100);
        bw.set_uss_active(true);
        assert_eq!(bw.effective_upload_rate(), 100);
        bw.set_configured_limits(200, 100);
        assert_eq!(bw.effective_upload_rate(), 200);
    }

    #[test]
    fn unlimited_upload_applies_immediately_even_while_uss_throttling() {
        let bw = BandwidthLimiter::new(100, 100);
        bw.set_uss_active(true);
        bw.set_upload_limit(30); // USS throttle in effect
                                 // Saving "Unlimited" (0) is an explicit user override and must win
                                 // immediately, not stay pinned at the USS-throttled rate until USS
                                 // decides to release.
        bw.set_configured_limits(0, 100);
        assert_eq!(bw.configured_upload_rate(), 0);
        assert_eq!(bw.effective_upload_rate(), 0);
    }

    #[tokio::test]
    async fn acquire_returns_when_rate_switched_to_unlimited_midwait() {
        let bw = Arc::new(BandwidthLimiter::new(1000, 1000));
        // Empty the upload bucket (new() seeds it to max_upload = 1000).
        bw.acquire_upload(1000).await;

        // This acquire needs a refill that will never come (no refill task in
        // the test), so it parks on the empty bucket.
        let bw2 = bw.clone();
        let handle = tokio::spawn(async move {
            bw2.acquire_upload(10_000).await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !handle.is_finished(),
            "acquire should be parked on empty bucket"
        );

        // Switch the upload rate to unlimited (0). The in-flight drain must
        // observe this and return instead of waiting forever.
        bw.set_configured_limits(0, 0);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("acquire must return after rate switched to unlimited")
            .expect("spawned task should not panic");
    }

    #[tokio::test]
    async fn acquire_returns_false_when_refill_task_dies() {
        let bw = Arc::new(BandwidthLimiter::new(1000, 1000));
        bw.acquire_upload(1000).await;
        bw.stop_refill_for_test();
        let ok = tokio::time::timeout(Duration::from_secs(2), bw.acquire_upload(10_000))
            .await
            .expect("must not hang after refill death");
        assert!(!ok, "dead refill must not bypass the rate cap");
    }

    /// Poll `done` on a short interval until it holds or the budget runs out.
    /// The refill task ticks at `REFILL_INTERVAL_MS`, so state changes land a
    /// tick or two after the flag that causes them.
    async fn wait_for(mut done: impl FnMut() -> bool) -> bool {
        for _ in 0..100 {
            if done() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    /// `bw_shutdown` is raised by the updater's pre-install flush as well as by
    /// process exit, and an install that fails returns with this process still
    /// running. Returning from the refill loop there left nothing to add tokens
    /// ever again, so with an upload limit set every `acquire_upload` drained
    /// the bucket and then parked on it for the rest of the session.
    #[tokio::test]
    async fn refill_outlives_a_shutdown_the_process_survives() {
        let bw = Arc::new(BandwidthLimiter::new(10_000, 0));
        let shutdown = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(super::start_token_refill(
            bw.clone(),
            shutdown.clone(),
            crate::bandwidth::new_uss_rtt_queue(),
            crate::bandwidth::new_uss_enabled_flag(false),
        ));

        // Spend the seeded bucket so the next acquire has to wait on a refill.
        bw.acquire_upload(10_000).await;
        shutdown.store(true, Ordering::Relaxed);

        tokio::time::timeout(Duration::from_secs(5), bw.acquire_upload(3_000))
            .await
            .expect("uploads must keep flowing after a shutdown the process survived");

        task.abort();
    }

    /// USS holds the effective rate at 10% of the cap while it measures a quiet
    /// baseline. Standing the controller down without clearing `uss_active`
    /// leaves `set_configured_limits` deferring to a controller that is gone,
    /// so the throttle would never lift.
    #[tokio::test]
    async fn teardown_releases_a_uss_throttle() {
        const CAP: u64 = 1_000_000;
        let bw = Arc::new(BandwidthLimiter::new(CAP, 0));
        let shutdown = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(super::start_token_refill(
            bw.clone(),
            shutdown.clone(),
            crate::bandwidth::new_uss_rtt_queue(),
            crate::bandwidth::new_uss_enabled_flag(true),
        ));

        // No RTT samples are produced here, so USS stays in Preparing and holds
        // the quiet-baseline rate.
        assert!(
            wait_for(|| bw.effective_upload_rate() < CAP).await,
            "USS should throttle below the configured cap while preparing"
        );

        shutdown.store(true, Ordering::Relaxed);
        assert!(
            wait_for(|| bw.effective_upload_rate() == CAP).await,
            "teardown must hand the configured cap back, not leave the throttle in place"
        );

        task.abort();
    }
}
