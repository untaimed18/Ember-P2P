use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

pub struct BandwidthLimiter {
    max_upload_rate: AtomicU64,
    max_download_rate: AtomicU64,
    upload_tokens: AtomicU64,
    download_tokens: AtomicU64,
    total_uploaded: AtomicU64,
    total_downloaded: AtomicU64,
    upload_speed: AtomicU64,
    download_speed: AtomicU64,
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
        }
    }

    pub async fn acquire_upload(&self, bytes: u64) -> bool {
        let max = self.max_upload_rate.load(Ordering::Relaxed);
        if max == 0 {
            self.total_uploaded.fetch_add(bytes, Ordering::Relaxed);
            return true;
        }

        loop {
            let current = self.upload_tokens.load(Ordering::Relaxed);
            if current >= bytes {
                if self
                    .upload_tokens
                    .compare_exchange(
                        current,
                        current - bytes,
                        Ordering::SeqCst,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    self.total_uploaded.fetch_add(bytes, Ordering::Relaxed);
                    return true;
                }
            } else {
                tokio::time::sleep(Duration::from_millis(10)).await;
                return false;
            }
        }
    }

    pub async fn acquire_download(&self, bytes: u64) -> bool {
        let max = self.max_download_rate.load(Ordering::Relaxed);
        if max == 0 {
            self.total_downloaded.fetch_add(bytes, Ordering::Relaxed);
            return true;
        }

        loop {
            let current = self.download_tokens.load(Ordering::Relaxed);
            if current >= bytes {
                if self
                    .download_tokens
                    .compare_exchange(
                        current,
                        current - bytes,
                        Ordering::SeqCst,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    self.total_downloaded.fetch_add(bytes, Ordering::Relaxed);
                    return true;
                }
            } else {
                tokio::time::sleep(Duration::from_millis(10)).await;
                return false;
            }
        }
    }

    pub fn refill_tokens(&self) {
        let max_up = self.max_upload_rate.load(Ordering::Relaxed);
        let max_down = self.max_download_rate.load(Ordering::Relaxed);

        if max_up > 0 {
            self.upload_tokens.store(max_up, Ordering::Relaxed);
        }
        if max_down > 0 {
            self.download_tokens.store(max_down, Ordering::Relaxed);
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
    }
}

pub async fn start_token_refill(limiter: std::sync::Arc<BandwidthLimiter>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    let mut last_uploaded = limiter.total_uploaded();
    let mut last_downloaded = limiter.total_downloaded();

    loop {
        interval.tick().await;
        limiter.refill_tokens();

        let current_up = limiter.total_uploaded();
        let current_down = limiter.total_downloaded();
        limiter.update_speeds(
            current_up.saturating_sub(last_uploaded),
            current_down.saturating_sub(last_downloaded),
        );
        last_uploaded = current_up;
        last_downloaded = current_down;
    }
}
