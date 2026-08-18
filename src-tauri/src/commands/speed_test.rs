use crate::commands::errors::coded_ctx;
use futures::StreamExt;
use serde::Serialize;
use tracing::info;

static SPEED_TEST_IN_FLIGHT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

const DOWNLOAD_TEST_URL: &str = "https://speed.cloudflare.com/__down?bytes=5000000";
const UPLOAD_TEST_URL: &str = "https://speed.cloudflare.com/__up";
const UPLOAD_TEST_BYTES: usize = 2_000_000;
/// Hard cap on the download-test body we will buffer. The endpoint is asked for
/// 5 MB; this bounds memory in case a misbehaving server/proxy/redirect streams
/// far more than requested.
const MAX_DOWNLOAD_TEST_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct SpeedTestResult {
    pub download_speed: u64,
    pub upload_speed: u64,
    pub recommended_upload_limit: u64,
    pub recommended_download_limit: u64,
}

#[tauri::command]
pub async fn run_speed_test() -> Result<SpeedTestResult, String> {
    let _single_flight = crate::security::try_begin_single_flight(&SPEED_TEST_IN_FLIGHT)
        .ok_or_else(|| {
            crate::commands::errors::coded(
                "speed_test_already_running",
                "A speed test is already running",
            )
        })?;
    info!("Starting speed test...");

    let dl_fut = async move {
        info!("Speed test: measuring download...");
        let start = std::time::Instant::now();
        // Through the app's own fetch policy rather than a bare reqwest
        // client: https-only, no environment proxy, and every redirect hop
        // re-validated and DNS-pinned. Left to reqwest's defaults this was
        // the one outbound request that a `Location:` header (or a hostile
        // proxy variable) could steer at a private or loopback address —
        // and the throughput we report back is a timing oracle for whatever
        // it reached.
        let resp = crate::security::fetch_pinned_get(DOWNLOAD_TEST_URL)
            .await
            .map_err(|e| coded_ctx("speed_download_test_failed", "Download test failed", e))?;

        // Stream the body with a hard cap instead of `resp.bytes()` (which
        // would buffer the entire response regardless of size).
        let mut stream = resp.bytes_stream();
        let mut actual_bytes: u64 = 0;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                coded_ctx("speed_download_read_failed", "Download test read failed", e)
            })?;
            actual_bytes += chunk.len() as u64;
            if actual_bytes >= MAX_DOWNLOAD_TEST_BYTES {
                break;
            }
        }

        let elapsed = start.elapsed().as_secs_f64();
        let speed = if elapsed > 0.0 {
            (actual_bytes as f64 / elapsed) as u64
        } else {
            actual_bytes
        };
        info!(
            "Speed test: downloaded {} bytes in {:.2}s = {}/s",
            actual_bytes,
            elapsed,
            format_speed(speed)
        );
        Ok::<u64, String>(speed)
    };

    let ul_fut = async move {
        info!("Speed test: measuring upload...");
        // `fetch_pinned_get` is GET-only, so the upload leg reproduces its
        // guarantees directly: validate the URL, resolve it once, and hand
        // the addresses to `build_pinned_client` (https-only, no proxy,
        // redirects refused). Validation and DNS happen before the clock
        // starts so they don't count against the measured throughput.
        let (url, host, addrs) = crate::security::validate_fetch_url(UPLOAD_TEST_URL)
            .await
            .map_err(|e| coded_ctx("speed_upload_test_failed", "Upload test failed", e))?;
        let client = crate::security::build_pinned_client(&host, &addrs)
            .map_err(|e| coded_ctx("http_client_failed", "Failed to build HTTP client", e))?;
        let payload = vec![0xABu8; UPLOAD_TEST_BYTES];
        let start = std::time::Instant::now();
        let _resp = client
            .post(url)
            .body(payload)
            .send()
            .await
            .map_err(|e| coded_ctx("speed_upload_test_failed", "Upload test failed", e))?;

        let elapsed = start.elapsed().as_secs_f64();
        let speed = if elapsed > 0.0 {
            (UPLOAD_TEST_BYTES as f64 / elapsed) as u64
        } else {
            UPLOAD_TEST_BYTES as u64
        };
        info!(
            "Speed test: uploaded {} bytes in {:.2}s = {}/s",
            UPLOAD_TEST_BYTES,
            elapsed,
            format_speed(speed)
        );
        Ok::<u64, String>(speed)
    };

    let (dl_result, ul_result) = tokio::join!(dl_fut, ul_fut);
    let download_speed = dl_result?;
    let upload_speed = ul_result?;

    let result = SpeedTestResult {
        download_speed,
        upload_speed,
        recommended_upload_limit: (upload_speed as f64 * 0.8) as u64,
        recommended_download_limit: (download_speed as f64 * 0.8) as u64,
    };

    info!(
        "Speed test complete: down={}/s, up={}/s, recommended upload limit={}/s",
        format_speed(result.download_speed),
        format_speed(result.upload_speed),
        format_speed(result.recommended_upload_limit),
    );

    Ok(result)
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
