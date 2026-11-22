use crate::app_state::AppState;
use crate::storage::statistics::TransferStats;

#[ember_macros::command]
pub async fn get_statistics(state: crate::host::State<'_, AppState>) -> Result<TransferStats, String> {
    let stats = state.cached_transfer_stats.read().await;
    Ok(stats.clone())
}
