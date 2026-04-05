use crate::app_state::AppState;

#[tauri::command]
pub async fn preview_file(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
) -> Result<String, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(crate::network::NetworkCommand::PreviewFile { transfer_id, tx })
        .map_err(|e| format!("Network busy: {e}"))?;

    tokio::time::timeout(std::time::Duration::from_secs(30), rx)
        .await
        .map_err(|_| "Preview request timed out".to_string())?
        .map_err(|_| "Failed to preview file".to_string())?
        .map_err(|e| format!("Preview failed: {e}"))
}
