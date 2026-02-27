use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// eMule-style bandwidth limiter with token bucket and partial acquisition.
///
/// Key differences from a naive token bucket:
/// - Handles pieces larger than max_rate via partial (chunked) acquisition
/// - Token bucket cap = 2 * max_rate to allow short bursts (eMule saves unused bandwidth)
/// - Tracks per-second and smoothed speeds for display
pub struct BandwidthLimiter {
    max_upload_rate: AtomicU64,
    max_download_rate: AtomicU64,
    upload_tokens: AtomicU64,
    download_tokens: AtomicU64,
    total_uploaded: AtomicU64,
    total_downloaded: AtomicU64,
    upload_speed: AtomicU64,
    download_speed: AtomicU64,
    smoothed_upload: AtomicU64,
    smoothed_download: AtomicU64,
}

impl BandwidthLimiter {
    pub fn new(max_upload: u64, max_download: u64) -> Self {
        Self {
            max_upload_rate: AtomicU64::new(max_upload),
            max_download_rate: AtomicU64::new(max_download),
            upload_tokens: AtomicU64::new(max_upload),
            download_tokens: AtomicU64::new(max_download),
            total_uploaded: AtomicU64::new(0),
            total_downloaded: AtomicU64::new(0),
            upload_speed: AtomicU64::new(0),
            download_speed: AtomicU64::new(0),
            smoothed_upload: AtomicU64::new(0),
            smoothed_download: AtomicU64::new(0),
        }
    }

    /// Acquire upload bandwidth. Drains tokens in chunks if the piece is larger
    /// than the current bucket, waiting for refills between chunks.
    pub async fn acquire_upload(&self, bytes: u64) {
        let max = self.max_upload_rate.load(Ordering::Relaxed);
        if max == 0 {
            self.total_uploaded.fetch_add(bytes, Ordering::Relaxed);
            return;
        }
        self.drain_tokens(&self.upload_tokens, bytes, max).await;
        self.total_uploaded.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Acquire download bandwidth. Drains tokens in chunks if the piece is larger
    /// than the current bucket, waiting for refills between chunks.
    pub async fn acquire_download(&self, bytes: u64) {
        let max = self.max_download_rate.load(Ordering::Relaxed);
        if max == 0 {
            self.total_downloaded.fetch_add(bytes, Ordering::Relaxed);
            return;
        }
        self.drain_tokens(&self.download_tokens, bytes, max).await;
        self.total_downloaded.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Core token drain: takes as many tokens as available per iteration,
    /// sleeping when the bucket is empty. Handles pieces of any size.
    async fn drain_tokens(&self, tokens: &AtomicU64, mut remaining: u64, max: u64) {
        while remaining > 0 {
            let current = tokens.load(Ordering::Acquire);
            if current == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
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
                    // CAS failed, retry immediately
                    continue;
                }
            }
            // Yield if we still need more to let the refill task run
            if remaining > 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        let _ = max;
    }

    /// Add a fraction of the rate limit worth of tokens (called at sub-second intervals).
    /// Tokens are capped at 2x the max rate to allow short bursts (eMule behavior).
    pub fn refill_tokens_incremental(&self, fraction: u64, divisor: u64) {
        let max_up = self.max_upload_rate.load(Ordering::Relaxed);
        let max_down = self.max_download_rate.load(Ordering::Relaxed);

        if max_up > 0 {
            let add = (max_up * fraction / divisor).max(1);
            let cap = max_up * 2;
            loop {
                let current = self.upload_tokens.load(Ordering::Relaxed);
                let new_val = (current + add).min(cap);
                if self
                    .upload_tokens
                    .compare_exchange_weak(current, new_val, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
        }
        if max_down > 0 {
            let add = (max_down * fraction / divisor).max(1);
            let cap = max_down * 2;
            loop {
                let current = self.download_tokens.load(Ordering::Relaxed);
                let new_val = (current + add).min(cap);
                if self
                    .download_tokens
                    .compare_exchange_weak(current, new_val, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
        }
    }

    pub fn set_limits(&self, upload: u64, download: u64) {
        self.max_upload_rate.store(upload, Ordering::Relaxed);
        self.max_download_rate.store(download, Ordering::Relaxed);
    }

    pub fn total_uploaded(&self) -> u64 {
        self.total_uploaded.load(Ordering::Relaxed)
    }

    pub fn total_downloaded(&self) -> u64 {
        self.total_downloaded.load(Ordering::Relaxed)
    }

    pub fn upload_speed(&self) -> u64 {
        self.upload_speed.load(Ordering::Relaxed)
    }

    pub fn download_speed(&self) -> u64 {
        self.download_speed.load(Ordering::Relaxed)
    }

    pub fn update_speeds(&self, uploaded_delta: u64, downloaded_delta: u64) {
        self.upload_speed.store(uploaded_delta, Ordering::Relaxed);
        self.download_speed.store(downloaded_delta, Ordering::Relaxed);

        let prev_up = self.smoothed_upload.load(Ordering::Relaxed);
        let smoothed_up = (uploaded_delta * 30 + prev_up * 70) / 100;
        self.smoothed_upload.store(smoothed_up, Ordering::Relaxed);

        let prev_down = self.smoothed_download.load(Ordering::Relaxed);
        let smoothed_down = (downloaded_delta * 30 + prev_down * 70) / 100;
        self.smoothed_download.store(smoothed_down, Ordering::Relaxed);
    }

    pub fn smoothed_upload_speed(&self) -> u64 {
        self.smoothed_upload.load(Ordering::Relaxed)
    }

    pub fn smoothed_download_speed(&self) -> u64 {
        self.smoothed_download.load(Ordering::Relaxed)
    }
}

pub async fn start_token_refill(
    limiter: std::sync::Arc<BandwidthLimiter>,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    const REFILL_INTERVAL_MS: u64 = 100;
    const TICKS_PER_SECOND: u64 = 1000 / REFILL_INTERVAL_MS;

    let max_up = limiter.max_upload_rate.load(Ordering::Relaxed);
    let mut uss = super::uss::UploadSpeedSense::new(1024, max_up);
    if max_up > 0 {
        uss.enable();
    }

    let mut interval = tokio::time::interval(Duration::from_millis(REFILL_INTERVAL_MS));
    let mut last_uploaded = limiter.total_uploaded();
    let mut last_downloaded = limiter.total_downloaded();
    let mut speed_tick_count: u64 = 0;

    loop {
        interval.tick().await;
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        limiter.refill_tokens_incremental(1, TICKS_PER_SECOND);

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

            // USS: use download speed as a latency proxy (higher download = connection
            // not saturated). When upload speed approaches the limit and download drops,
            // it suggests the upload is saturating the connection.
            if uss.is_enabled() && up_speed > 0 {
                let max_rate = limiter.max_upload_rate.load(Ordering::Relaxed);
                if max_rate > 0 {
                    let utilization = (up_speed as f64 / max_rate as f64) * 100.0;
                    uss.record_ping(utilization);
                    if let Some(new_limit) = uss.compute_limit() {
                        limiter.set_limits(new_limit, limiter.max_download_rate.load(Ordering::Relaxed));
                    }
                }
            }
        }
    }
}
