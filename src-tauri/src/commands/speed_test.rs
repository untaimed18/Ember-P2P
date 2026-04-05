use serde::Serialize;
use tracing::info;

const DOWNLOAD_TEST_URL: &str = "https://speed.cloudflare.com/__down?bytes=5000000";
const UPLOAD_TEST_URL: &str = "https://speed.cloudflare.com/__up";
const UPLOAD_TEST_BYTES: usize = 2_000_000;

#[derive(Debug, Clone, Serialize)]
pub struct SpeedTestResult {
    pub download_speed: u64,
    pub upload_speed: u64,
    pub recommended_upload_limit: u64,
    pub recommended_download_limit: u64,
}

#[tauri::command]
pub async fn run_speed_test() -> Result<SpeedTestResult, String> {
    info!("Starting speed test...");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    let dl_client = client.clone();
    let dl_fut = async move {
        info!("Speed test: measuring download...");
        let start = std::time::Instant::now();
        let resp = dl_client
            .get(DOWNLOAD_TEST_URL)
            .send()
            .await
            .map_err(|e| format!("Download test failed: {e}"))?;

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("Download test read failed: {e}"))?;

        let elapsed = start.elapsed().as_secs_f64();
        let actual_bytes = bytes.len() as u64;
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
        let payload = vec![0xABu8; UPLOAD_TEST_BYTES];
        let start = std::time::Instant::now();
        let _resp = client
            .post(UPLOAD_TEST_URL)
            .body(payload)
            .send()
            .await
            .map_err(|e| format!("Upload test failed: {e}"))?;

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
        recommended_download_limit: 0,
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
