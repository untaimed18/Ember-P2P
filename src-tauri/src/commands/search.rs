use tokio::sync::oneshot;

use crate::app_state::AppState;
use crate::network::NetworkCommand;
use crate::network::ed2k::hash;
use crate::network::kad::publish::md4_bytes_to_kad_id;
use crate::types::SearchResult;

#[tauri::command]
pub async fn search_files(
    state: tauri::State<'_, AppState>,
    query: String,
) -> Result<Vec<SearchResult>, String> {
    let (tx, rx) = oneshot::channel();

    state
        .network_tx
        .send(NetworkCommand::SearchFiles { query, tx })
        .await
        .map_err(|e| format!("Failed to send search command: {e}"))?;

    rx.await.map_err(|e| format!("Search failed: {e}"))
}

#[tauri::command]
pub async fn find_notes(
    state: tauri::State<'_, AppState>,
    file_hash: String,
    file_size: u64,
) -> Result<Vec<SearchResult>, String> {
    let raw_bytes = hex::decode(&file_hash)
        .map_err(|e| format!("Invalid hash: {e}"))?;
    let kad_hash = md4_bytes_to_kad_id(&raw_bytes);

    let (tx, rx) = oneshot::channel();

    state
        .network_tx
        .send(NetworkCommand::FindNotes {
            file_hash: kad_hash,
            file_size,
            tx,
        })
        .await
        .map_err(|e| format!("Failed to send find_notes command: {e}"))?;

    rx.await.map_err(|e| format!("Notes search failed: {e}"))
}

#[tauri::command]
pub async fn find_sources(
    state: tauri::State<'_, AppState>,
    file_hash: String,
    file_size: u64,
) -> Result<Vec<(String, u16)>, String> {
    let raw_bytes = hex::decode(&file_hash)
        .map_err(|e| format!("Invalid hash: {e}"))?;
    let kad_hash = md4_bytes_to_kad_id(&raw_bytes);

    let (tx, rx) = oneshot::channel();

    state
        .network_tx
        .send(NetworkCommand::FindSources {
            file_hash: kad_hash,
            file_size,
            tx,
        })
        .await
        .map_err(|e| format!("Failed to send find_sources command: {e}"))?;

    rx.await.map_err(|e| format!("Source search failed: {e}"))
}

#[tauri::command]
pub async fn publish_note(
    state: tauri::State<'_, AppState>,
    file_hash: String,
    rating: u8,
    comment: String,
) -> Result<(), String> {
    if rating > 5 {
        return Err("Rating must be between 0 and 5".into());
    }

    let raw_bytes = hex::decode(&file_hash)
        .map_err(|e| format!("Invalid hash: {e}"))?;
    let kad_hash = md4_bytes_to_kad_id(&raw_bytes);

    state
        .network_tx
        .send(NetworkCommand::PublishNote {
            file_hash: kad_hash,
            rating,
            comment,
        })
        .await
        .map_err(|e| format!("Failed to send publish_note command: {e}"))?;

    Ok(())
}

/// Compute the ed2k hash of raw bytes (for in-memory content)
#[tauri::command]
pub fn compute_ed2k_hash(data: Vec<u8>) -> Result<String, String> {
    if data.len() > 100 * 1024 * 1024 {
        return Err("Input too large (max 100MB)".into());
    }
    Ok(hash::ed2k_hash_bytes(&data))
}

#[tauri::command]
pub fn format_ed2k_link(name: String, size: u64, file_hash: String) -> String {
    hash::format_ed2k_link(&name, size, &file_hash)
}

#[derive(serde::Serialize)]
pub struct Ed2kLinkInfo {
    pub name: String,
    pub size: u64,
    pub hash: String,
}

#[tauri::command]
pub fn parse_ed2k_link(link: String) -> Result<Ed2kLinkInfo, String> {
    hash::parse_ed2k_link(&link)
        .map(|(name, size, hash)| Ed2kLinkInfo { name, size, hash })
        .ok_or_else(|| "Invalid ed2k link format".to_string())
}
