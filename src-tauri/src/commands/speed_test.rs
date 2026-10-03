use crate::app_state::AppState;
use crate::bandwidth::limiter::BandwidthLimiter;
use crate::commands::errors::coded_ctx;
use futures::StreamExt;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

static SPEED_TEST_IN_FLIGHT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

const DOWNLOAD_TEST_URL: &str = "https://speed.cloudflare.com/__down?bytes=25000000";
const UPLOAD_TEST_URL: &str = "https://speed.cloudflare.com/__up";
/// Opens each stream's connection (TCP and TLS) before the clock starts.
const WARM_UP_URL: &str = "https://speed.cloudflare.com/__down?bytes=0";

/// Parallel connections per direction. One TCP stream cannot fill a link
/// whose bandwidth-delay product is larger than its window, and an ISP that
/// shapes per flow would be measured at one flow's share.
const STREAMS: usize = 4;
const UPLOAD_REQUEST_BYTES: u64 = 10 * 1024 * 1024;
const UPLOAD_CHUNK_BYTES: usize = 16 * 1024;
static UPLOAD_CHUNK: [u8; UPLOAD_CHUNK_BYTES] = [0xAB; UPLOAD_CHUNK_BYTES];
// The body has to yield exactly the Content-Length it declares.
const _: () = assert!(UPLOAD_REQUEST_BYTES.is_multiple_of(UPLOAD_CHUNK_BYTES as u64));

/// Covers DNS, connecting every stream and the warm-up request.
const SETUP_TIMEOUT: Duration = Duration::from_secs(4);
const LEG_DURATION: Duration = Duration::from_secs(8);
/// A leg stops early once it has moved this much, so a very fast connection
/// costs a bounded amount of data rather than eight seconds of line rate.
const DOWNLOAD_BYTE_CAP: u64 = 250_000_000;
const UPLOAD_BYTE_CAP: u64 = 100_000_000;

const SAMPLE_INTERVAL: Duration = Duration::from_millis(250);
/// Long enough that the up-to-one-chunk-per-stream lead the upload counter
/// has over the wire stays small next to a slow uplink's window total.
const RATE_WINDOW_SECS: f64 = 2.0;
const WARM_UP_FRACTION: f64 = 0.25;
const MAX_WARM_UP_SECS: f64 = 2.0;
const RATE_PERCENTILE: usize = 90;
const RECOMMENDED_PERCENT: u64 = 80;
/// The most of Ember's own traffic added back, as a percent of what the test
/// measured on its own. The limiter counts every metered byte, LAN peers that
/// never touch the internet link included, so the add-back is only an upper
/// bound on what shared the link. At this cap the recommendation is at most
/// the rate the test itself measured.
const MAX_ADD_BACK_PERCENT: u64 = 100 * 100 / RECOMMENDED_PERCENT - 100;

#[derive(Debug, Clone, Serialize)]
pub struct SpeedTestResult {
    pub download_speed: u64,
    pub upload_speed: u64,
    pub recommended_upload_limit: u64,
    pub recommended_download_limit: u64,
}

#[derive(Debug, Clone, Copy)]
enum Leg {
    Download,
    Upload,
}

impl Leg {
    fn url(self) -> &'static str {
        match self {
            Leg::Download => DOWNLOAD_TEST_URL,
            Leg::Upload => UPLOAD_TEST_URL,
        }
    }

    fn byte_cap(self) -> u64 {
        match self {
            Leg::Download => DOWNLOAD_BYTE_CAP,
            Leg::Upload => UPLOAD_BYTE_CAP,
        }
    }

    /// Ember's own transfer bytes in this direction so far.
    fn own_bytes(self, limiter: &BandwidthLimiter) -> u64 {
        match self {
            Leg::Download => limiter.total_downloaded(),
            Leg::Upload => limiter.total_uploaded(),
        }
    }

    fn failed(self, detail: impl std::fmt::Display) -> String {
        match self {
            Leg::Download => coded_ctx("speed_download_test_failed", "Download test failed", detail),
            Leg::Upload => coded_ctx("speed_upload_test_failed", "Upload test failed", detail),
        }
    }
}

/// Cumulative bytes at `at` seconds into a leg's measured window.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Sample {
    at: f64,
    test_bytes: u64,
    /// Ember's own transfers in the same direction since the window opened,
    /// LAN ones included.
    own_bytes: u64,
}

#[tauri::command]
pub async fn run_speed_test(state: tauri::State<'_, AppState>) -> Result<SpeedTestResult, String> {
    let _single_flight = crate::security::try_begin_single_flight(&SPEED_TEST_IN_FLIGHT)
        .ok_or_else(|| {
            crate::commands::errors::coded(
                "speed_test_already_running",
                "A speed test is already running",
            )
        })?;
    info!("Starting speed test...");
    let limiter = state.bandwidth_limiter.clone();

    // One after the other: a saturated uplink delays the ACKs the download
    // depends on, and the other way round.
    let download = measure(Leg::Download, &limiter).await?;
    let upload = measure(Leg::Upload, &limiter).await?;

    let result = SpeedTestResult {
        download_speed: download,
        upload_speed: upload,
        recommended_upload_limit: recommended_limit(upload),
        recommended_download_limit: recommended_limit(download),
    };

    info!(
        "Speed test complete: down={}/s, up={}/s, recommended upload limit={}/s",
        format_speed(result.download_speed),
        format_speed(result.upload_speed),
        format_speed(result.recommended_upload_limit),
    );

    Ok(result)
}

/// Measures one direction, returning its rate in bytes per second.
async fn measure(leg: Leg, limiter: &BandwidthLimiter) -> Result<u64, String> {
    info!("Speed test: measuring {leg:?}...");
    let (url, clients) = tokio::time::timeout(SETUP_TIMEOUT, connect_streams(leg))
        .await
        .map_err(|_| leg.failed("timed out connecting to the test server"))??;

    let transferred = Arc::new(AtomicU64::new(0));
    let own_start = leg.own_bytes(limiter);
    let start = Instant::now();
    let deadline = start + LEG_DURATION;
    let streams = futures::future::join_all(
        clients
            .iter()
            .map(|client| run_stream(leg, client, &url, transferred.clone())),
    );
    tokio::pin!(streams);

    let mut samples = vec![Sample::default()];
    let mut ticker = tokio::time::interval_at(
        tokio::time::Instant::from_std(start + SAMPLE_INTERVAL),
        SAMPLE_INTERVAL,
    );
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let take_sample = || Sample {
        at: start.elapsed().as_secs_f64(),
        test_bytes: transferred.load(Ordering::Relaxed),
        own_bytes: leg.own_bytes(limiter).saturating_sub(own_start),
    };
    loop {
        tokio::select! {
            errors = &mut streams => {
                // Streams only end by failing; the window closes on time or
                // volume instead, so every stream giving up is the test failing.
                return Err(errors
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| leg.failed("no connection to the test server")));
            }
            _ = ticker.tick() => {
                let sample = take_sample();
                samples.push(sample);
                if sample.test_bytes >= leg.byte_cap() || Instant::now() >= deadline {
                    break;
                }
            }
        }
    }

    let last = samples.last().copied().unwrap_or_default();
    if last.test_bytes == 0 {
        return Err(leg.failed("no data was transferred"));
    }
    let rate = steady_state_rate(&samples)
        .ok_or_else(|| leg.failed("not enough data to measure"))?;
    info!(
        "Speed test: {:?} moved {} bytes in {:.2}s alongside {} bytes of Ember transfers = {}/s",
        leg,
        last.test_bytes,
        last.at,
        last.own_bytes,
        format_speed(rate)
    );
    Ok(rate)
}

/// Resolves the test host once and opens [`STREAMS`] connections to it, each
/// through its own client so none of them share a pooled connection. Streams
/// whose warm-up fails are dropped; the leg fails only if none connect.
async fn connect_streams(leg: Leg) -> Result<(String, Vec<reqwest::Client>), String> {
    // Not `fetch_pinned_get`: the clients are reused for many requests, and
    // `build_pinned_client` keeps its guarantees (https-only, no proxy, DNS
    // pinned, redirects refused) for every one of them.
    let (url, host, addrs) = crate::security::validate_fetch_url(leg.url())
        .await
        .map_err(|e| leg.failed(e))?;
    let warm_ups = (0..STREAMS).map(|_| async {
        let client = crate::security::build_pinned_client(&host, &addrs)
            .map_err(|e| coded_ctx("http_client_failed", "Failed to build HTTP client", e))?;
        client
            .get(WARM_UP_URL)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| leg.failed(e))?
            .bytes()
            .await
            .map_err(|e| leg.failed(e))?;
        Ok::<_, String>(client)
    });
    let mut clients = Vec::with_capacity(STREAMS);
    let mut first_error = None;
    for outcome in futures::future::join_all(warm_ups).await {
        match outcome {
            Ok(client) => clients.push(client),
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    match first_error {
        Some(e) if clients.is_empty() => Err(e),
        _ => Ok((url, clients)),
    }
}

/// Repeats the leg's request on one connection, counting bytes into
/// `transferred` as they move. Never returns except with an error.
async fn run_stream(
    leg: Leg,
    client: &reqwest::Client,
    url: &str,
    transferred: Arc<AtomicU64>,
) -> String {
    loop {
        let outcome = match leg {
            Leg::Download => download_once(client, url, &transferred).await,
            Leg::Upload => upload_once(client, url, transferred.clone()).await,
        };
        if let Err(e) = outcome {
            return e;
        }
    }
}

async fn download_once(
    client: &reqwest::Client,
    url: &str,
    transferred: &AtomicU64,
) -> Result<(), String> {
    let resp = client
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| Leg::Download.failed(e))?;
    let mut body = resp.bytes_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|e| {
            coded_ctx("speed_download_read_failed", "Download test read failed", e)
        })?;
        transferred.fetch_add(chunk.len() as u64, Ordering::Relaxed);
    }
    Ok(())
}

async fn upload_once(
    client: &reqwest::Client,
    url: &str,
    transferred: Arc<AtomicU64>,
) -> Result<(), String> {
    // Counted as the HTTP stack takes each chunk, so the count leads the wire
    // by at most a chunk plus the socket's send buffer, which fills in the
    // warm-up and then drains at the link rate.
    let chunks = UPLOAD_REQUEST_BYTES / UPLOAD_CHUNK_BYTES as u64;
    let body = futures::stream::iter(0..chunks).map(move |_| {
        transferred.fetch_add(UPLOAD_CHUNK_BYTES as u64, Ordering::Relaxed);
        Ok::<_, std::io::Error>(&UPLOAD_CHUNK[..])
    });
    client
        .post(url)
        .header(reqwest::header::CONTENT_LENGTH, UPLOAD_REQUEST_BYTES)
        .body(reqwest::Body::wrap_stream(body))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| Leg::Upload.failed(e))?
        .bytes()
        .await
        .map_err(|e| Leg::Upload.failed(e))?;
    Ok(())
}

/// The rate the link sustains once the streams are up to speed: the
/// [`RATE_PERCENTILE`]th percentile of the test's rates over sliding
/// [`RATE_WINDOW_SECS`] windows, ignoring windows that open during the
/// warm-up (TCP slow start, the send buffer filling). A leg that ended early
/// on its byte cap may have no full window, and then the rate over everything
/// after the warm-up stands in. Ember's own transfers after the warm-up are
/// added back at their average rate, up to [`MAX_ADD_BACK_PERCENT`] of that.
/// `samples` must be in time order.
fn steady_state_rate(samples: &[Sample]) -> Option<u64> {
    let last = samples.last()?;
    if last.at <= 0.0 {
        return None;
    }
    let warm_up = (last.at * WARM_UP_FRACTION).min(MAX_WARM_UP_SECS);
    let settled = samples
        .iter()
        .rev()
        .find(|s| s.at <= warm_up)
        .unwrap_or(&samples[0]);
    let test_bytes = |s: &Sample| s.test_bytes;
    let mut rates: Vec<u64> = samples
        .iter()
        .enumerate()
        .filter(|(_, from)| from.at >= warm_up)
        .filter_map(|(i, from)| {
            samples[i + 1..]
                .iter()
                .find(|to| to.at - from.at >= RATE_WINDOW_SECS)
                .and_then(|to| rate_between(from, to, test_bytes))
        })
        .collect();
    let measured = if rates.is_empty() {
        rate_between(settled, last, test_bytes)?
    } else {
        percentile(&mut rates, RATE_PERCENTILE)
    };
    let own = rate_between(settled, last, |s| s.own_bytes).unwrap_or(0);
    let add_back = own.min(measured.saturating_mul(MAX_ADD_BACK_PERCENT) / 100);
    Some(measured.saturating_add(add_back))
}

fn rate_between(from: &Sample, to: &Sample, bytes: impl Fn(&Sample) -> u64) -> Option<u64> {
    let secs = to.at - from.at;
    if secs <= 0.0 {
        return None;
    }
    Some((bytes(to).saturating_sub(bytes(from)) as f64 / secs) as u64)
}

/// Nearest-rank percentile. `values` must not be empty.
fn percentile(values: &mut [u64], pct: usize) -> u64 {
    values.sort_unstable();
    let rank = (values.len() * pct).div_ceil(100).max(1);
    values[rank.min(values.len()) - 1]
}

/// What "Apply recommended" sets: [`RECOMMENDED_PERCENT`] of the measured
/// rate. Never 0, which the limits read as unlimited.
fn recommended_limit(measured: u64) -> u64 {
    (measured.saturating_mul(RECOMMENDED_PERCENT) / 100)
        .clamp(1, crate::bandwidth::MAX_CONFIGURED_SPEED_BPS)
}

fn format_speed(bytes_per_sec: u64) -> String {
    if bytes_per_sec >= 1_000_000 {
        format!("{:.1} MB", bytes_per_sec as f64 / 1_000_000.0)
    } else if bytes_per_sec >= 1_000 {
        format!("{:.1} KB", bytes_per_sec as f64 / 1_000.0)
    } else {
        format!("{} B", bytes_per_sec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Samples every 250 ms over `secs`, with `bytes_at(t)` cumulative test bytes.
    fn series(secs: f64, bytes_at: impl Fn(f64) -> u64) -> Vec<Sample> {
        let steps = (secs / 0.25).round() as usize;
        (0..=steps)
            .map(|i| {
                let at = i as f64 * 0.25;
                Sample {
                    at,
                    test_bytes: bytes_at(at),
                    own_bytes: 0,
                }
            })
            .collect()
    }

    #[test]
    fn a_steady_link_reads_at_its_rate() {
        let samples = series(8.0, |t| (t * 1_000_000.0) as u64);
        assert_eq!(steady_state_rate(&samples), Some(1_000_000));
    }

    /// The old average over the whole transfer counted slow start against
    /// the link. A ramp that takes the first two seconds must not show.
    #[test]
    fn slow_start_is_left_out() {
        let rate = 1_000_000.0;
        let samples = series(8.0, |t| {
            if t < 2.0 {
                (rate * t * t / 4.0) as u64
            } else {
                (rate * (1.0 + (t - 2.0))) as u64
            }
        });
        let average = samples.last().unwrap().test_bytes as f64 / 8.0;
        assert!(average < rate * 0.9, "the ramp drags the average down");
        assert_eq!(steady_state_rate(&samples), Some(1_000_000));
    }

    #[test]
    fn a_dip_does_not_pull_the_rate_down() {
        // Full rate except for a half-speed second in the middle.
        let samples = series(8.0, |t| {
            let full = t.min(4.0) + (t - 5.0).max(0.0);
            let dip = (t - 4.0).clamp(0.0, 1.0) * 0.5;
            ((full + dip) * 1_000_000.0) as u64
        });
        assert_eq!(steady_state_rate(&samples), Some(1_000_000));
    }

    #[test]
    fn ember_transfers_during_the_test_are_added_back() {
        let mut samples = series(8.0, |t| (t * 900_000.0) as u64);
        for s in &mut samples {
            s.own_bytes = (s.at * 100_000.0) as u64;
        }
        assert_eq!(steady_state_rate(&samples), Some(1_000_000));
    }

    /// The limiter counts LAN peers too, and they never touch the link the
    /// test measures. However much of that there is, the recommendation must
    /// not go above what the test moved over the internet.
    #[test]
    fn lan_traffic_cannot_lift_the_recommendation_above_the_measured_link() {
        let mut samples = series(8.0, |t| (t * 1_000_000.0) as u64);
        for s in &mut samples {
            s.own_bytes = (s.at * 100_000_000.0) as u64;
        }
        let rate = steady_state_rate(&samples).unwrap();
        assert_eq!(rate, 1_250_000, "the add-back is capped at a quarter of the test's rate");
        assert!(recommended_limit(rate) <= 1_000_000);
    }

    /// The percentile picks the test's best windows; Ember's own traffic is
    /// added at its average, so a burst of it lands in no window's favour.
    #[test]
    fn a_burst_of_ember_traffic_is_averaged_not_picked_by_the_percentile() {
        let mut samples = series(8.0, |t| (t * 1_000_000.0) as u64);
        for s in &mut samples {
            s.own_bytes = if s.at < 6.0 { 0 } else { 120_000 };
        }
        // 120 kB after the 2 s warm-up is 20 kB/s on average; the 2 s windows
        // across the burst would have read it as 60 kB/s.
        assert_eq!(steady_state_rate(&samples), Some(1_020_000));
    }

    /// A fast link hits the byte cap before any full window after the warm-up.
    #[test]
    fn a_leg_cut_short_by_its_cap_uses_the_rate_after_warm_up() {
        let samples = series(1.5, |t| {
            if t <= 0.25 {
                0
            } else {
                ((t - 0.25) * 100_000_000.0) as u64
            }
        });
        let rate = steady_state_rate(&samples).unwrap();
        assert!(
            (99_000_000..=100_000_000).contains(&rate),
            "the dead first quarter must not count: {rate}"
        );
    }

    #[test]
    fn no_elapsed_time_has_no_rate() {
        assert_eq!(steady_state_rate(&[]), None);
        assert_eq!(steady_state_rate(&[Sample::default()]), None);
    }

    #[test]
    fn percentile_is_nearest_rank() {
        let mut values: Vec<u64> = (1..=20).collect();
        assert_eq!(percentile(&mut values, 90), 18);
        assert_eq!(percentile(&mut [7], 90), 7);
        assert_eq!(percentile(&mut [3, 1, 2], 100), 3);
        assert_eq!(percentile(&mut [3, 1, 2], 0), 1);
    }

    #[test]
    fn recommendation_is_eighty_percent_and_never_unlimited() {
        assert_eq!(recommended_limit(1_000_000), 800_000);
        assert_eq!(recommended_limit(125_000), 100_000);
        assert_eq!(recommended_limit(1), 1);
        assert_eq!(
            recommended_limit(u64::MAX),
            crate::bandwidth::MAX_CONFIGURED_SPEED_BPS
        );
    }
}
