use crate::app_state::AppState;
use crate::network::NetworkCommand;
use crate::storage::statistics::TransferStats;

#[tauri::command]
pub async fn get_statistics(
    state: tauri::State<'_, AppState>,
) -> Result<TransferStats, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetStatistics { tx })
        .map_err(|e| format!("Network busy: {e}"))?;

    rx.await.map_err(|_| "Failed to get statistics".to_string())
}
