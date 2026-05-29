use crate::app_state::AppState;
use crate::commands::errors::{coded, coded_ctx};
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
        return Err(coded("comments_invalid_rating", "Rating must be between 0 and 5"));
    }
    if file_hash.len() != 32 || !file_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(coded("comments_invalid_file_hash", "Invalid file hash: expected 32 hex characters"));
    }
    if comment.len() > 4096 {
        return Err(coded("comments_comment_too_long", "Comment too long (max 4096 bytes, matching eMule limit)"));
    }
    state
        .network_tx
        .try_send(NetworkCommand::SetFileComment {
            file_hash,
            rating,
            comment,
        })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    Ok(())
}

#[tauri::command]
pub async fn get_file_comments(
    state: tauri::State<'_, AppState>,
    file_hash: String,
) -> Result<Option<FileCommentInfo>, String> {
    if file_hash.len() != 32 || !file_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(coded("comments_invalid_file_hash", "Invalid file hash: expected 32 hex characters"));
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetFileComments { file_hash, tx })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;

    rx.await.map_err(|_| coded("comments_get_failed", "Failed to get comments"))
}
