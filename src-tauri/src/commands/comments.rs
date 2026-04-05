use crate::app_state::AppState;
use crate::network::NetworkCommand;
use crate::network::ed2k::comments::FileCommentInfo;

#[tauri::command]
pub async fn set_file_comment(
    state: tauri::State<'_, AppState>,
    file_hash: String,
    rating: u8,
    comment: String,
) -> Result<(), String> {
    if rating > 5 {
        return Err("Rating must be between 0 and 5".into());
    }
    if file_hash.len() != 32 || !file_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid file hash: expected 32 hex characters".into());
    }
    if comment.len() > 4096 {
        return Err("Comment too long (max 4096 bytes, matching eMule limit)".into());
    }
    state
        .network_tx
        .try_send(NetworkCommand::SetFileComment {
            file_hash,
            rating,
            comment,
        })
        .map_err(|e| format!("Network busy: {e}"))?;
    Ok(())
}

#[tauri::command]
pub async fn get_file_comments(
    state: tauri::State<'_, AppState>,
    file_hash: String,
) -> Result<Option<FileCommentInfo>, String> {
    if file_hash.len() != 32 || !file_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid file hash: expected 32 hex characters".into());
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetFileComments { file_hash, tx })
        .map_err(|e| format!("Network busy: {e}"))?;

    rx.await.map_err(|_| "Failed to get comments".to_string())
}
