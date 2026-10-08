use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

/// Weight given to the newest one-second sample when smoothing the displayed
/// rate, out of [`SPEED_SMOOTHING_DENOMINATOR`]; the remainder carries the
/// previous value forward. See [`BandwidthLimiter::update_speeds`].
///
/// Named because the per-row rolling window in `sharing::manager` is sized to
/// the settling time these imply — the status-bar total and the transfer rows
/// are the same traffic measured twice, and they have to answer on the same
/// timescale. `speed_window_matches_the_status_bar_smoothing` holds the two
/// together.
pub(crate) const SPEED_SMOOTHING_NEW: u64 = 30;
pub(crate) const SPEED_SMOOTHING_DENOMINATOR: u64 = 100;

/// Percent of each upload refill held for priority uploads while one is
/// running. Not all of it: the eD2K slots still need enough to keep each peer
/// inside the delivery deadline it drops a slot over.
const PRIORITY_UPLOAD_PERCENT: u64 = 80;

/// The most the priority reserve holds, as a fraction of a second of its
/// share. Past this a refill goes to the shared bucket instead, so a priority
/// stream held back by something other than the cap — the friend's downlink,
/// a congested path — leaves the uplink to the slots rather than idle.
const PRIORITY_RESERVE_DIVISOR: u64 = 4;

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
    /// Upload allowance only a [`PriorityUpload`] may spend. Filled from the
    /// upload refill while one is registered, and handed back to
    /// `upload_tokens` on the first refill after the last one ends.
    priority_tokens: AtomicU64,
    /// [`PriorityUpload`] handles alive right now.
    priority_uploads: AtomicUsize,
    /// Sub-token remainders carried between refill ticks so that very low
    /// rates (where `max_rate * fraction < divisor`) are honored exactly
    /// instead of being rounded up to a 1-token-per-tick floor.
    upload_refill_rem: AtomicU64,
    download_refill_rem: AtomicU64,
    /// Upload already sent by [`Self::charge_upload`] beyond the tokens there
    /// were. Paid off from the next refills before anything reaches the bucket.
    upload_debt: AtomicU64,
    total_uploaded: AtomicU64,
    total_downloaded: AtomicU64,
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
            priority_tokens: AtomicU64::new(0),
            priority_uploads: AtomicUsize::new(0),
            upload_refill_rem: AtomicU64::new(0),
            download_refill_rem: AtomicU64::new(0),
            upload_debt: AtomicU64::new(0),
            total_uploaded: AtomicU64::new(0),
            total_downloaded: AtomicU64::new(0),
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

    /// Register an upload that goes ahead of the eD2K slots — a friend reading
    /// a file we offered them in chat. While the handle lives, most of every
    /// refill is held for it; see [`PRIORITY_UPLOAD_PERCENT`].
    ///
    /// eMule gives a friend the same standing with its friend slot, which the
    /// throttler feeds before any other. The slots here pace themselves to
    /// shares that add up to the whole cap, so anything that is not one of them
    /// only ever got what they left, and a chat file stalled every time the
    /// eD2K peers asked for their next blocks.
    pub fn priority_upload(&self) -> PriorityUpload<'_> {
        self.priority_uploads.fetch_add(1, Ordering::AcqRel);
        PriorityUpload { limiter: self }
    }

    /// Spends the reserve, and from the shared bucket only what sits above half
    /// the cap. The shared bucket is the slots' share, and racing them for it
    /// whenever the reserve runs dry leaves them next to nothing; but slots
    /// that are parked on it drain every refill, so a balance above that floor
    /// is one they are leaving unspent, and without it a chat file with the
    /// slots idle could never use more than the reserve's share. Half, not the
    /// quarter [`Self::yield_then_take_upload`] keeps: the band between is
    /// relay bridges', which would otherwise lose every refill to this.
    async fn acquire_priority_upload(&self, bytes: u64) -> bool {
        let start = std::time::Instant::now();
        let mut warned_slow = false;
        let mut remaining = bytes;
        while remaining > 0 {
            let max = self.max_upload_rate.load(Ordering::Relaxed);
            if max == 0 {
                break;
            }
            let mut took = take_tokens(&self.priority_tokens, remaining);
            if took < remaining {
                took += take_tokens_above(&self.upload_tokens, remaining - took, (max / 2).max(1));
            }
            remaining -= took;
            if took == 0 {
                if !self.refill_alive.load(Ordering::Acquire) {
                    return false;
                }
                tokio::time::timeout(Duration::from_millis(25), self.refill_notify.notified())
                    .await
                    .ok();
                if !warned_slow && start.elapsed() > Duration::from_secs(60) {
                    warned_slow = true;
                    tracing::warn!(
                        "acquire_priority_upload: waited >60s for bandwidth tokens (remaining={remaining})"
                    );
                }
            }
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

    /// Bill `bytes` of upload that has already gone out, without waiting.
    ///
    /// For control traffic, which eMule sends ahead of file data rather than
    /// queueing it behind the slots: what the bucket holds is taken now, the
    /// rest is owed and paid from the next refills before the slots see any of
    /// it. The debt is capped at two seconds of the limit, so a burst of
    /// control frames costs the slots at most that.
    pub fn charge_upload(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.total_uploaded.fetch_add(bytes, Ordering::Relaxed);
        let max = self.max_upload_rate.load(Ordering::Relaxed);
        if max == 0 {
            return;
        }
        let mut owed = bytes;
        loop {
            let current = self.upload_tokens.load(Ordering::Acquire);
            let take = owed.min(current);
            if take == 0 {
                break;
            }
            if self
                .upload_tokens
                .compare_exchange_weak(current, current - take, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                owed -= take;
                break;
            }
        }
        if owed > 0 {
            let cap = max.saturating_mul(2);
            let _ = self
                .upload_debt
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |debt| {
                    Some(debt.saturating_add(owed).min(cap))
                });
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
    /// sessions already poll `halted_for_shutdown`).
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
    async fn drain_tokens(&self, pool: &AtomicU64, mut remaining: u64, max_rate: &AtomicU64) -> bool {
        let start = std::time::Instant::now();
        let mut warned_slow = false;
        while remaining > 0 {
            // Stop throttling immediately if the rate became "unlimited"
            // after this call started draining (0 == unlimited).
            if max_rate.load(Ordering::Relaxed) == 0 {
                return true;
            }
            let took = take_tokens(pool, remaining);
            remaining -= took;
            if took == 0 {
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
            let add = match self
                .upload_debt
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |debt| {
                    (debt > 0).then(|| debt - debt.min(add))
                }) {
                Ok(debt) => add - debt.min(add),
                Err(_) => add,
            };
            let add = if self.priority_uploads.load(Ordering::Acquire) > 0 {
                let held = self.priority_tokens.load(Ordering::Acquire);
                let room = priority_reserve_cap(max_up).saturating_sub(held);
                let reserved = (add.saturating_mul(PRIORITY_UPLOAD_PERCENT) / 100).min(room);
                self.priority_tokens.fetch_add(reserved, Ordering::AcqRel);
                add - reserved
            } else {
                add.saturating_add(self.priority_tokens.swap(0, Ordering::AcqRel))
            };
            let cap = max_up.saturating_mul(2);
            loop {
                let current = self.upload_tokens.load(Ordering::Relaxed);
                // Saturating because the release profile sets
                // `overflow-checks = true`, and a panic here is not a panic
                // here: it takes the refill task down, which flips
                // `refill_alive` and aborts every rate-limited transfer for the
                // rest of the session. `MAX_CONFIGURED_SPEED_BPS` is what keeps
                // the sum in range; this is the backstop for a rate that
                // reaches the limiter without passing it.
                let new_val = current.saturating_add(add).min(cap);
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
            self.upload_debt.store(0, Ordering::Relaxed);
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
                // See the upload side above.
                let new_val = current.saturating_add(add).min(cap);
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
            self.priority_tokens
                .fetch_min(priority_reserve_cap(upload), Ordering::AcqRel);
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
            self.priority_tokens
                .fetch_min(priority_reserve_cap(upload), Ordering::AcqRel);
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

    /// Upload tokens sitting unclaimed in the bucket right now.
    ///
    /// eMule's throttler reads the same quantity — `bytesToSpend - spentBytes`,
    /// what the slots collectively left unspent — to decide whether a slot may
    /// send past its equal share (`UploadBandwidthThrottler.cpp:586`). The ed2k
    /// per-slot pacer uses it for exactly that.
    pub fn available_upload_tokens(&self) -> u64 {
        self.upload_tokens.load(Ordering::Relaxed)
    }

    /// True when a configured upload cap is already being spent on file data,
    /// so unmetered overlay egress (the Ember `PROXY_STORE` fan-out) would
    /// steal uplink from peers we are already uploading to.
    ///
    /// The token floor is what distinguishes *file* uploads from overlay work,
    /// and it relies on the reserve in [`Self::yield_then_take_upload`]: paced
    /// callers hold the bucket at or above `cap / 4`, which is above this
    /// `cap / 8` floor, so relay traffic never reports itself as the thief.
    /// Only an unpaced consumer — the eD2K upload slots, which park on
    /// [`Self::acquire_upload`] and drain the bucket dry — trips this. Keep the
    /// two fractions apart if either is ever retuned.
    ///
    /// Unlimited (`effective_upload_rate() == 0`) never trips this: there is
    /// no cap to steal from. The Kad buddy TCP path is what must stay off the
    /// network loop in that case, not a refusal to help.
    pub fn file_uploads_own_uplink(&self) -> bool {
        let cap = self.effective_upload_rate();
        if cap == 0 {
            return false;
        }
        // `.max(1)`: for a cap under 8 the division truncates to zero and the
        // comparison becomes unsatisfiable, which would silently disable the
        // gate rather than trip it.
        let floor = (cap / 8).max(1);
        self.smoothed_upload_speed() >= cap.saturating_mul(3) / 4
            && self.available_upload_tokens() < floor
    }

    /// Charge `bytes` of lower-priority uplink (peer-relay, overlay fan-out
    /// helpers) without taking the share file-upload slots are using.
    ///
    /// While anything is uploading, this spends only what sits *above* a
    /// quarter of the cap, so the reserve `file_uploads_own_uplink` keys on is
    /// genuinely maintained. With the uplink otherwise idle there is nobody to
    /// protect, so the whole bucket is fair game. Unlimited caps just count the
    /// bytes so the UI still sees the traffic.
    pub async fn yield_then_take_upload(&self, bytes: u64) {
        let mut remaining = bytes;
        while remaining > 0 {
            // Re-read each turn rather than snapshotting: USS moves the
            // effective rate every second, and a cap lowered while we were
            // parked left a stale `reserve` above the new bucket ceiling of
            // `2 * cap`, which no amount of refilling could ever satisfy.
            let cap = self.effective_upload_rate();
            if cap == 0 {
                self.total_uploaded.fetch_add(remaining, Ordering::Relaxed);
                return;
            }
            // Nothing will ever add tokens again, so waiting is waiting
            // forever. `drain_tokens` reports this to its caller; here there is
            // no failure channel, so count the bytes and let the transfer that
            // is about to be torn down anyway proceed.
            if !self.refill_alive.load(Ordering::Acquire) {
                self.total_uploaded.fetch_add(remaining, Ordering::Relaxed);
                return;
            }
            let tokens = self.available_upload_tokens();
            let budget = if self.smoothed_upload_speed() > 0 {
                tokens.saturating_sub((cap / 4).max(1))
            } else {
                tokens
            };
            let took = self.try_take_upload(remaining.min(budget));
            if took == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
            remaining -= took;
        }
    }

    pub fn total_uploaded(&self) -> u64 {
        self.total_uploaded.load(Ordering::Relaxed)
    }

    pub fn total_downloaded(&self) -> u64 {
        self.total_downloaded.load(Ordering::Relaxed)
    }

    pub fn update_speeds(&self, uploaded_delta: u64, downloaded_delta: u64) {
        let prev_weight = SPEED_SMOOTHING_DENOMINATOR - SPEED_SMOOTHING_NEW;
        let prev_up = self.smoothed_upload.load(Ordering::Relaxed);
        let smoothed_up = uploaded_delta
            .saturating_mul(SPEED_SMOOTHING_NEW)
            .saturating_add(prev_up.saturating_mul(prev_weight))
            / SPEED_SMOOTHING_DENOMINATOR;
        self.smoothed_upload.store(smoothed_up, Ordering::Relaxed);

        let prev_down = self.smoothed_download.load(Ordering::Relaxed);
        let smoothed_down = downloaded_delta
            .saturating_mul(SPEED_SMOOTHING_NEW)
            .saturating_add(prev_down.saturating_mul(prev_weight))
            / SPEED_SMOOTHING_DENOMINATOR;
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

/// Take up to `max` from `pool` without waiting, returning how much was taken.
fn take_tokens(pool: &AtomicU64, max: u64) -> u64 {
    loop {
        let current = pool.load(Ordering::Acquire);
        let take = max.min(current);
        if take == 0 {
            return 0;
        }
        if pool
            .compare_exchange_weak(current, current - take, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return take;
        }
    }
}

/// [`take_tokens`], leaving at least `floor` in `pool`.
fn take_tokens_above(pool: &AtomicU64, max: u64, floor: u64) -> u64 {
    loop {
        let current = pool.load(Ordering::Acquire);
        let take = max.min(current.saturating_sub(floor));
        if take == 0 {
            return 0;
        }
        if pool
            .compare_exchange_weak(current, current - take, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return take;
        }
    }
}

fn priority_reserve_cap(max_upload: u64) -> u64 {
    (max_upload.saturating_mul(PRIORITY_UPLOAD_PERCENT) / 100 / PRIORITY_RESERVE_DIVISOR).max(1)
}

/// A registered priority upload; see [`BandwidthLimiter::priority_upload`].
/// The reserve is held for as long as this lives.
pub struct PriorityUpload<'a> {
    limiter: &'a BandwidthLimiter,
}

impl PriorityUpload<'_> {
    /// [`BandwidthLimiter::acquire_upload`], spending the reserve first.
    pub async fn acquire(&self, bytes: u64) -> bool {
        self.limiter.acquire_priority_upload(bytes).await
    }
}

impl Drop for PriorityUpload<'_> {
    fn drop(&mut self) {
        self.limiter.priority_uploads.fetch_sub(1, Ordering::AcqRel);
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
                let Some(sample) = queue.pop_front() else {
                    break;
                };
                uss.record_ping(sample.host, sample.rtt_ms);
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

    /// Control traffic is billed after it has gone out: what the bucket holds
    /// now, the rest from the next refills before the slots see them, and
    /// never more than two seconds of the limit owed.
    #[test]
    fn a_charge_past_the_bucket_is_paid_from_the_next_refills() {
        let bw = BandwidthLimiter::new(1_000, 0);
        assert_eq!(bw.available_upload_tokens(), 1_000);
        bw.charge_upload(1_500);
        assert_eq!(bw.available_upload_tokens(), 0);
        assert_eq!(bw.total_uploaded(), 1_500);

        bw.refill_tokens_incremental(1, 2);
        assert_eq!(bw.available_upload_tokens(), 0, "half a second pays the 500 owed");
        bw.refill_tokens_incremental(1, 2);
        assert_eq!(bw.available_upload_tokens(), 500);

        bw.charge_upload(100_000);
        bw.refill_tokens_incremental(2, 1);
        assert_eq!(bw.available_upload_tokens(), 0, "two seconds owed at most");
        bw.refill_tokens_incremental(1, 1);
        assert_eq!(bw.available_upload_tokens(), 1_000);
    }

    #[test]
    fn file_uploads_own_uplink_requires_a_saturated_cap() {
        let bw = BandwidthLimiter::new(10_000, 10_000);
        assert!(
            !bw.file_uploads_own_uplink(),
            "idle cap must not look saturated"
        );
        for _ in 0..20 {
            bw.update_speeds(10_000, 0);
        }
        assert!(
            !bw.file_uploads_own_uplink(),
            "tokens still full: leftover overlay work is fine"
        );
        assert_eq!(bw.try_take_upload(10_000), 10_000);
        assert!(
            bw.file_uploads_own_uplink(),
            "near-cap observed rate plus an empty bucket is the steal case"
        );

        let unlimited = BandwidthLimiter::new(0, 0);
        unlimited.update_speeds(10_000, 0);
        assert!(
            !unlimited.file_uploads_own_uplink(),
            "unlimited must not refuse buddy/overlay help"
        );
    }

    /// `file_uploads_own_uplink` can only tell file uploads apart from overlay
    /// traffic because paced callers leave the bucket above the floor it keys
    /// on. That was documented but not implemented: the take had no floor, so a
    /// single relay chunk could drain the bucket dry and the node would then
    /// report its *own* relay traffic as the thief — suppressing the Ember
    /// `PROXY_STORE` fan-out with no file uploads running at all, which is the
    /// opposite of what the pacing is for.
    #[tokio::test]
    async fn a_paced_caller_parks_rather_than_eating_the_upload_slots_reserve() {
        let bw = BandwidthLimiter::new(10_000, 10_000);
        // Something is uploading, so the reserve applies.
        for _ in 0..20 {
            bw.update_speeds(10_000, 0);
        }
        assert_eq!(bw.available_upload_tokens(), 10_000);

        // More than the headroom above the reserve (10_000 - 2_500). With no
        // refill task running, the remainder can only come out of the reserve.
        let outcome = tokio::time::timeout(
            Duration::from_millis(300),
            bw.yield_then_take_upload(9_000),
        )
        .await;

        assert!(
            outcome.is_err(),
            "a paced caller must wait for refill rather than raid the reserve"
        );
        assert_eq!(
            bw.available_upload_tokens(),
            2_500,
            "the cap/4 reserve the steal gate keys on has to survive"
        );
        assert!(
            !bw.file_uploads_own_uplink(),
            "paced traffic must never report itself as owning the uplink"
        );
    }

    /// The wait had no exit that did not require tokens, so a dead refill task
    /// parked the caller at 20 ms forever. `drain_tokens` reports that case to
    /// its caller; this one has no failure channel, so it has to give up.
    #[tokio::test]
    async fn a_paced_caller_gives_up_when_refill_has_died() {
        let bw = BandwidthLimiter::new(10_000, 10_000);
        assert_eq!(bw.try_take_upload(10_000), 10_000);
        bw.stop_refill_for_test();

        tokio::time::timeout(
            Duration::from_millis(500),
            bw.yield_then_take_upload(5_000),
        )
        .await
        .expect("a dead refill task must not park a paced caller forever");
    }

    /// The eD2K slots pace to shares that sum to the whole cap, so a friend's
    /// chat file only ever got what they left and stalled whenever the eD2K
    /// peers asked for blocks. A refill now holds most of itself for it.
    #[tokio::test]
    async fn a_priority_upload_is_refilled_ahead_of_the_shared_bucket() {
        let bw = BandwidthLimiter::new(10_000, 0);
        assert_eq!(bw.try_take_upload(10_000), 10_000);
        let priority = bw.priority_upload();

        bw.refill_tokens_incremental(1, 10);
        assert_eq!(
            bw.available_upload_tokens(),
            200,
            "the slots keep a fifth of each refill"
        );

        tokio::time::timeout(Duration::from_millis(300), priority.acquire(800))
            .await
            .expect("the reserve covers its own share");
        assert_eq!(bw.priority_tokens.load(Ordering::Relaxed), 0);
        assert_eq!(bw.available_upload_tokens(), 200);
        assert_eq!(bw.total_uploaded(), 10_800);
    }

    /// Once the reserve is spent, a priority upload waits for the next refill
    /// rather than taking the share the eD2K slots were left with.
    #[tokio::test]
    async fn a_starved_priority_upload_leaves_the_slots_their_share() {
        let bw = BandwidthLimiter::new(10_000, 0);
        assert_eq!(bw.try_take_upload(10_000), 10_000);
        let priority = bw.priority_upload();
        bw.refill_tokens_incremental(1, 10);

        let starved =
            tokio::time::timeout(Duration::from_millis(100), priority.acquire(1_000)).await;
        assert!(starved.is_err(), "the reserve alone cannot cover the request");
        assert_eq!(
            bw.available_upload_tokens(),
            200,
            "the shared bucket is the slots', not the priority stream's"
        );
        tokio::time::timeout(Duration::from_millis(100), bw.acquire_upload(200))
            .await
            .expect("the slots spend their share while the priority stream is starved");
    }

    /// With no slot spending it, the shared bucket fills past the floor busy
    /// slots keep it under, and a priority upload may take what is above it
    /// rather than leave a fifth of the uplink idle.
    #[tokio::test]
    async fn a_priority_upload_takes_what_idle_slots_leave_above_the_floor() {
        let bw = BandwidthLimiter::new(10_000, 0);
        let priority = bw.priority_upload();
        assert_eq!(bw.available_upload_tokens(), 10_000);

        tokio::time::timeout(Duration::from_millis(100), priority.acquire(5_000))
            .await
            .expect("the unspent shared balance above the floor covers the request");
        assert_eq!(
            bw.available_upload_tokens(),
            5_000,
            "half the cap is left for slots and relay bridges that start asking"
        );
        let starved =
            tokio::time::timeout(Duration::from_millis(100), priority.acquire(1)).await;
        assert!(starved.is_err(), "the floor itself is not spare");
    }

    /// A request bigger than the reserve can ever hold completes by draining
    /// it across refills.
    #[tokio::test]
    async fn a_priority_upload_larger_than_the_reserve_completes_across_refills() {
        let bw = Arc::new(BandwidthLimiter::new(10_000, 0));
        assert_eq!(bw.try_take_upload(10_000), 10_000);
        let refills = {
            let bw = bw.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    bw.refill_tokens_incremental(1, 10);
                }
            })
        };

        let priority = bw.priority_upload();
        let request = super::priority_reserve_cap(10_000) * 3;
        tokio::time::timeout(Duration::from_secs(5), priority.acquire(request))
            .await
            .expect("a large priority request drains across refills");
        refills.abort();
    }

    #[tokio::test]
    async fn a_priority_upload_still_ends_on_unlimited_and_on_a_dead_refill() {
        let unlimited = BandwidthLimiter::new(0, 0);
        assert!(unlimited.priority_upload().acquire(1_000_000).await);
        assert_eq!(unlimited.total_uploaded(), 1_000_000);

        let bw = BandwidthLimiter::new(10_000, 0);
        assert_eq!(bw.try_take_upload(10_000), 10_000);
        let priority = bw.priority_upload();
        bw.stop_refill_for_test();
        let ok = tokio::time::timeout(Duration::from_secs(2), priority.acquire(1_000))
            .await
            .expect("must not hang after refill death");
        assert!(!ok, "a dead refill must not bypass the cap for a priority upload either");
    }

    /// A priority stream held back by the friend's downlink rather than the
    /// cap must not idle the uplink the slots could be using.
    #[tokio::test]
    async fn an_unspent_reserve_spills_to_the_slots() {
        let bw = BandwidthLimiter::new(10_000, 0);
        assert_eq!(bw.try_take_upload(10_000), 10_000);
        let priority = bw.priority_upload();

        for _ in 0..10 {
            bw.refill_tokens_incremental(1, 10);
        }
        assert_eq!(
            bw.available_upload_tokens(),
            8_000,
            "past the reserve's quarter-second cap a refill goes to the shared bucket"
        );
        assert_eq!(bw.try_take_upload(10_000), 8_000);
        let raided =
            tokio::time::timeout(Duration::from_millis(100), bw.acquire_upload(1)).await;
        assert!(raided.is_err(), "an ordinary upload must not spend the reserve");

        drop(priority);
        bw.refill_tokens_incremental(1, 10);
        assert_eq!(
            bw.available_upload_tokens(),
            3_000,
            "the reserve is handed back once no priority upload is left"
        );
    }

    #[test]
    fn lowering_the_cap_clamps_the_priority_reserve() {
        let bw = BandwidthLimiter::new(10_000, 0);
        assert_eq!(bw.try_take_upload(10_000), 10_000);
        let _priority = bw.priority_upload();
        for _ in 0..5 {
            bw.refill_tokens_incremental(1, 10);
        }
        bw.set_upload_limit(1_000);
        assert_eq!(bw.priority_tokens.load(Ordering::Relaxed), 200);
    }

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
