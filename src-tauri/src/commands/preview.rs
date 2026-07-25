use crate::app_state::AppState;
use crate::commands::errors::{coded, coded_ctx};

static PREVIEW_IN_FLIGHT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[tauri::command]
pub async fn preview_file(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<String, String> {
    let _single_flight =
        crate::security::try_begin_single_flight(&PREVIEW_IN_FLIGHT).ok_or_else(|| {
            coded(
                "preview_request_in_flight",
                "Another media preview request is already running",
            )
        })?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(crate::network::NetworkCommand::PreviewFile { transfer_id, tx })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;

    tokio::time::timeout(std::time::Duration::from_secs(30), rx)
        .await
        .map_err(|_| coded("preview_timed_out", "Preview request timed out"))?
        .map_err(|_| coded("preview_file_failed", "Failed to preview file"))?
        .map_err(|e| coded_ctx("preview_failed", "Preview failed", e))
}
