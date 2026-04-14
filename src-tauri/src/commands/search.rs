use tokio::sync::oneshot;

use crate::app_state::AppState;
use crate::network::{NetworkCommand, SearchMethod};
use crate::network::ed2k::hash;
use crate::network::kad::publish::md4_bytes_to_kad_id;
use crate::search::cleanup::{cleanup_filename, parse_cleanup_strings, strip_comment_urls};
use crate::search::merge;
use crate::search::spam::{SpamFilter, SpamFilterProfile};
use crate::types::SearchResult;

const SEARCH_TIMEOUT_MIN: u64 = 30;
const SEARCH_TIMEOUT_MAX: u64 = 600;

fn parse_exact_file_hash(file_hash: &str) -> Result<[u8; 16], String> {
    if file_hash.len() != 32 || !file_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid file hash: expected 32 hex characters".to_string());
    }
    let raw = hex::decode(file_hash).map_err(|e| format!("Invalid hash: {e}"))?;
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&raw);
    Ok(hash)
}

pub async fn enrich_results(
    results: &mut [SearchResult],
    state: &AppState,
    search_keywords: &[String],
    server_ip: Option<&str>,
) {
    let (config, spam) = tokio::join!(
        state.config.read(),
        state.spam_filter.read(),
    );
    let spam_enabled = config.settings.spam_filter_enabled;
    let spam_profile = SpamFilterProfile::from_setting(&config.settings.spam_filter_profile);
    let cleanup_strings = parse_cleanup_strings(&config.settings.filename_cleanups);
    drop(config);

    for result in results.iter_mut() {
        if spam_enabled {
            result.spam_rating = spam.rate_result(result, search_keywords, server_ip, spam_profile);
            result.is_spam = SpamFilter::is_spam(result.spam_rating, spam_profile);
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
    request_id: u64,
    min_size: Option<u64>,
    max_size: Option<u64>,
    file_type: Option<String>,
    file_extension: Option<String>,
    min_availability: Option<u32>,
) -> Result<Vec<SearchResult>, String> {
    let (tx, rx) = oneshot::channel();

    let keywords: Vec<String> = query
        .split_whitespace()
        .filter(|w| !w.is_empty())
        .map(|w| w.to_lowercase())
        .collect();

    let (local_hits, timeout_secs) = {
        let (li, c) = tokio::join!(
            state.local_index.read(),
            state.config.read(),
        );
        (li.search(query.trim()), c.settings.search_timeout_secs.clamp(SEARCH_TIMEOUT_MIN, SEARCH_TIMEOUT_MAX))
    };

    let file_type_filter = file_type.clone();
    let filters = if min_size.is_some() || max_size.is_some() || file_type.is_some() || file_extension.is_some() || min_availability.is_some() {
        Some(crate::network::SearchFilters {
            min_size,
            max_size,
            file_type,
            file_extension,
            min_availability,
        })
    } else {
        None
    };

    state
        .network_tx
        .try_send(NetworkCommand::SearchFiles {
            query,
            method: method.unwrap_or(SearchMethod::Global),
            request_id,
            tx,
            search_filters: filters,
        })
        .map_err(|e| format!("Network busy: {e}"))?;

    let mut results = match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        rx,
    )
    .await
    {
        Ok(Ok(results)) => results,
        Ok(Err(e)) => return Err(format!("Search failed: {e}")),
        Err(_) => {
            let _ = state
                .network_tx
                .try_send(NetworkCommand::CancelSearch { request_id });
            return Err(format!("Search timed out after {timeout_secs}s"));
        }
    };

    results = merge::merge_search_vecs(results, local_hits);
    if let Some(ref ft) = file_type_filter {
        results.retain(|r| {
            let inferred = crate::search::index::infer_file_type(&r.file.extension);
            let result_type = if !inferred.is_empty() {
                inferred
            } else {
                r.file_type.clone()
            };
            result_type == *ft
        });
    }
    enrich_results(&mut results, &state, &keywords, None).await;
    merge::sort_search_results(&mut results);
    Ok(results)
}

#[tauri::command]
pub async fn find_notes(
    state: tauri::State<'_, AppState>,
    file_hash: String,
    file_size: u64,
) -> Result<Vec<SearchResult>, String> {
    let kad_hash = md4_bytes_to_kad_id(&parse_exact_file_hash(&file_hash)?);

    let (tx, rx) = oneshot::channel();

    state
        .network_tx
        .try_send(NetworkCommand::FindNotes {
            file_hash: kad_hash,
            file_size,
            tx,
        })
        .map_err(|e| format!("Network busy: {e}"))?;

    let timeout_secs = {
        let c = state.config.read().await;
        c.settings.search_timeout_secs.clamp(SEARCH_TIMEOUT_MIN, SEARCH_TIMEOUT_MAX)
    };
    let mut results = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        rx,
    )
        .await
        .map_err(|_| format!("Notes search timed out after {timeout_secs}s"))?
        .map_err(|e| format!("Notes search failed: {e}"))?;
    enrich_results(&mut results, &state, &[], None).await;
    Ok(results)
}

#[tauri::command]
pub async fn find_sources(
    state: tauri::State<'_, AppState>,
    file_hash: String,
    file_size: u64,
) -> Result<Vec<(String, u16)>, String> {
    let kad_hash = md4_bytes_to_kad_id(&parse_exact_file_hash(&file_hash)?);

    let (tx, rx) = oneshot::channel();

    state
        .network_tx
        .try_send(NetworkCommand::FindSources {
            file_hash: kad_hash,
            file_size,
            tx,
        })
        .map_err(|e| format!("Network busy: {e}"))?;

    let timeout_secs = {
        let c = state.config.read().await;
        c.settings.search_timeout_secs.clamp(SEARCH_TIMEOUT_MIN, SEARCH_TIMEOUT_MAX)
    };
    tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), rx)
        .await
        .map_err(|_| format!("Source search timed out after {timeout_secs}s"))?
        .map_err(|e| format!("Source search failed: {e}"))
}

#[tauri::command]
pub async fn publish_note(
    state: tauri::State<'_, AppState>,
    file_hash: String,
    rating: u8,
    comment: String,
) -> Result<String, String> {
    if rating > 5 {
        return Err("Rating must be between 0 and 5".into());
    }
    if comment.len() > 4096 {
        return Err("Comment too long (max 4096 bytes)".into());
    }
    if rating == 0 && comment.trim().is_empty() {
        return Err("Add a rating or a comment before publishing".into());
    }
    if state.cached_contacts.read().await.is_empty() {
        return Err("No Kad contacts available to publish note".into());
    }

    let kad_hash = md4_bytes_to_kad_id(&parse_exact_file_hash(&file_hash)?);

    state
        .network_tx
        .try_send(NetworkCommand::PublishNote {
            file_hash: kad_hash,
            rating,
            comment,
        })
        .map_err(|_| "Network is busy, please try again".to_string())?;

    Ok("Note publish queued".to_string())
}

#[tauri::command]
pub async fn cancel_search(
    state: tauri::State<'_, AppState>,
    request_id: u64,
) -> Result<(), String> {
    state
        .network_tx
        .try_send(NetworkCommand::CancelSearch { request_id })
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
pub fn format_ed2k_link(name: String, size: u64, file_hash: String) -> Result<String, String> {
    if name.is_empty() || name.len() > 4096 {
        return Err("File name is empty or too long".into());
    }
    if file_hash.len() != 32 || !file_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid file hash (expected 32 hex characters)".into());
    }
    Ok(hash::format_ed2k_link(&name, size, &file_hash))
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
    server_ip: Option<String>,
) -> Result<(), String> {
    if file_hash.len() != 32 || hex::decode(&file_hash).is_err() {
        return Err("Invalid file hash".into());
    }
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
        result_origin: String::new(),
    };
    let mut spam = state.spam_filter.write().await;
    spam.mark_spam(&result, &search_keywords, server_ip.as_deref());
    Ok(())
}

#[tauri::command]
pub async fn mark_not_spam(
    state: tauri::State<'_, AppState>,
    file_hash: String,
) -> Result<(), String> {
    if file_hash.len() != 32 || hex::decode(&file_hash).is_err() {
        return Err("Invalid file hash".into());
    }
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

#[derive(serde::Serialize)]
pub struct SpamExplainResponse {
    pub score: u32,
    pub threshold: u32,
    pub profile: String,
    pub is_spam: bool,
    pub reasons: Vec<String>,
}

#[tauri::command]
pub async fn explain_spam_result(
    state: tauri::State<'_, AppState>,
    file_hash: String,
    file_name: String,
    file_size: u64,
    source_addresses: Vec<String>,
    search_keywords: Vec<String>,
    server_ip: Option<String>,
) -> Result<SpamExplainResponse, String> {
    if file_hash.len() != 32 || hex::decode(&file_hash).is_err() {
        return Err("Invalid file hash".into());
    }
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
        result_origin: String::new(),
    };

    let cfg = state.config.read().await;
    let profile = SpamFilterProfile::from_setting(&cfg.settings.spam_filter_profile);
    drop(cfg);

    let spam = state.spam_filter.read().await;
    let details = spam.explain_result(&result, &search_keywords, server_ip.as_deref(), profile);
    Ok(SpamExplainResponse {
        score: details.score,
        threshold: details.threshold,
        profile: details.profile,
        is_spam: details.is_spam,
        reasons: details.reasons,
    })
}

#[tauri::command]
pub async fn reset_spam_filter(
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let mut spam = state.spam_filter.write().await;
    spam.reset();
    Ok("Spam filter learning data cleared.".to_string())
}

/// Look up download history for a batch of file hashes.
/// Returns a map of hash → status ("completed" or "cancelled").
#[tauri::command]
pub async fn get_download_history(
    state: tauri::State<'_, AppState>,
    hashes: Vec<String>,
) -> Result<std::collections::HashMap<String, String>, String> {
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || db.get_download_history_batch(&hashes))
        .await
        .map_err(|e| format!("Task failed: {e}"))?
        .map_err(|e| e.to_string())
}

/// Clear download history entries by status ("completed", "cancelled", or "all").
#[tauri::command]
pub async fn clear_download_history(
    state: tauri::State<'_, AppState>,
    status: String,
) -> Result<(), String> {
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || {
        match status.as_str() {
            "all" => {
                db.clear_download_history("completed")?;
                db.clear_download_history("cancelled")?;
            }
            "completed" | "cancelled" => {
                db.clear_download_history(&status)?;
            }
            _ => return Err(anyhow::anyhow!("Invalid status: {status}. Must be 'completed', 'cancelled', or 'all'")),
        }
        Ok(())
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
    .map_err(|e| e.to_string())
}

/// Remove a single file hash from download history.
#[tauri::command]
pub async fn remove_download_history_entry(
    state: tauri::State<'_, AppState>,
    file_hash: String,
) -> Result<(), String> {
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || db.remove_download_history(&file_hash))
        .await
        .map_err(|e| format!("Task failed: {e}"))?
        .map_err(|e| e.to_string())
}
