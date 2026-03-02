use tokio::sync::oneshot;

use crate::app_state::AppState;
use crate::network::{NetworkCommand, SearchMethod};
use crate::network::ed2k::hash;
use crate::network::kad::publish::md4_bytes_to_kad_id;
use crate::search::cleanup::{cleanup_filename, parse_cleanup_strings, strip_comment_urls};
use crate::search::spam::SpamFilter;
use crate::types::SearchResult;

const SEARCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

pub async fn enrich_results(
    results: &mut [SearchResult],
    state: &AppState,
    search_keywords: &[String],
) {
    let config = state.config.read().await;
    let spam_enabled = config.settings.spam_filter_enabled;
    let cleanup_strings = parse_cleanup_strings(&config.settings.filename_cleanups);
    drop(config);

    let spam = state.spam_filter.read().await;

    for result in results.iter_mut() {
        if spam_enabled {
            result.spam_rating = spam.rate_result(result, search_keywords, None);
            result.is_spam = SpamFilter::is_spam(result.spam_rating);
        }
        result.clean_name = cleanup_filename(&result.file.name, &cleanup_strings);
        if let Some(ref comment) = result.comment {
            let cleaned = strip_comment_urls(comment);
            if cleaned != *comment {
                result.comment = Some(cleaned);
            }
        }
    }
}

#[tauri::command]
pub async fn search_files(
    state: tauri::State<'_, AppState>,
    query: String,
    method: Option<SearchMethod>,
) -> Result<Vec<SearchResult>, String> {
    let (tx, rx) = oneshot::channel();

    let keywords: Vec<String> = query
        .split_whitespace()
        .filter(|w| !w.is_empty())
        .map(|w| w.to_lowercase())
        .collect();

    state
        .network_tx
        .try_send(NetworkCommand::SearchFiles {
            query,
            method: method.unwrap_or(SearchMethod::Global),
            tx,
        })
        .map_err(|e| format!("Network busy: {e}"))?;

    let mut results = tokio::time::timeout(SEARCH_TIMEOUT, rx)
        .await
        .map_err(|_| "Search timed out".to_string())?
        .map_err(|e| format!("Search failed: {e}"))?;

    enrich_results(&mut results, &state, &keywords).await;
    Ok(results)
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
        .try_send(NetworkCommand::FindNotes {
            file_hash: kad_hash,
            file_size,
            tx,
        })
        .map_err(|e| format!("Network busy: {e}"))?;

    tokio::time::timeout(SEARCH_TIMEOUT, rx)
        .await
        .map_err(|_| "Notes search timed out".to_string())?
        .map_err(|e| format!("Notes search failed: {e}"))
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
        .try_send(NetworkCommand::FindSources {
            file_hash: kad_hash,
            file_size,
            tx,
        })
        .map_err(|e| format!("Network busy: {e}"))?;

    tokio::time::timeout(SEARCH_TIMEOUT, rx)
        .await
        .map_err(|_| "Source search timed out".to_string())?
        .map_err(|e| format!("Source search failed: {e}"))
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

#[tauri::command]
pub async fn cancel_search(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state
        .network_tx
        .try_send(NetworkCommand::CancelSearch)
        .map_err(|e| format!("Network busy: {e}"))?;
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

#[tauri::command]
pub async fn mark_spam(
    state: tauri::State<'_, AppState>,
    file_hash: String,
    file_name: String,
    file_size: u64,
    source_addresses: Vec<String>,
    search_keywords: Vec<String>,
) -> Result<(), String> {
    let result = SearchResult {
        file: crate::types::FileInfo {
            id: file_hash.clone(),
            name: file_name,
            path: String::new(),
            size: file_size,
            hash: file_hash,
            aich_hash: String::new(),
            extension: String::new(),
            modified_at: 0,
            priority: "normal".to_string(),
            requests: 0,
            accepted: 0,
            bytes_transferred: 0,
            alltime_requests: 0,
            alltime_accepted: 0,
            alltime_transferred: 0,
            complete_sources: 0,
            folder: String::new(),
            shared: false,
            shared_kad: false,
            shared_ed2k: false,
        },
        peer_id: String::new(),
        peer_name: String::new(),
        availability: 0,
        file_type: String::new(),
        source_addresses,
        rating: None,
        comment: None,
        spam_rating: 0,
        is_spam: false,
        clean_name: String::new(),
    };
    let mut spam = state.spam_filter.write().await;
    spam.mark_spam(&result, &search_keywords);
    Ok(())
}

#[tauri::command]
pub async fn mark_not_spam(
    state: tauri::State<'_, AppState>,
    file_hash: String,
) -> Result<(), String> {
    let mut spam = state.spam_filter.write().await;
    spam.mark_not_spam(&file_hash);
    Ok(())
}

#[tauri::command]
pub async fn get_spam_stats(
    state: tauri::State<'_, AppState>,
) -> Result<crate::search::spam::SpamStats, String> {
    let spam = state.spam_filter.read().await;
    Ok(spam.stats())
}
