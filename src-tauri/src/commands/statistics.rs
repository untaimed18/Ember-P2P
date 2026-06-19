use crate::app_state::AppState;
use crate::storage::statistics::TransferStats;

#[tauri::command]
pub async fn get_statistics(state: tauri::State<'_, AppState>) -> Result<TransferStats, String> {
    let stats = state.cached_transfer_stats.read().await;
    Ok(stats.clone())
}
