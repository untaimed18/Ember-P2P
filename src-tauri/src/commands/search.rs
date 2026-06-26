use tokio::sync::oneshot;

use crate::app_state::AppState;
use crate::commands::errors::{coded, coded_ctx};
use crate::network::ed2k::hash;
use crate::network::kad::publish::md4_bytes_to_kad_id;
use crate::network::{NetworkCommand, SearchMethod};
use crate::search::cleanup::{cleanup_filename, parse_cleanup_strings, strip_comment_urls};
use crate::search::merge;
use crate::search::spam::{BatchSpamContext, CommunityRating, SpamFilter, SpamFilterProfile};
use crate::types::SearchResult;
use std::collections::HashMap;

const SEARCH_TIMEOUT_MIN: u64 = 30;
const SEARCH_TIMEOUT_MAX: u64 = 600;
const LINK_STATS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Maximum query length accepted from the frontend. eMule keyword
/// searches have hard wire limits well under this; the cap is a
/// memory/IPC bound, not a UX limit.
pub(crate) const MAX_SEARCH_QUERY_LEN: usize = 1024;
const MAX_SEARCH_FILTER_LEN: usize = 128;
const MAX_ED2K_LINK_LEN: usize = 8 * 1024;
/// Maximum source-address strings accepted in a `mark_spam` payload.
/// Each is at most 21 bytes ("xxx.xxx.xxx.xxx:port").
const MAX_MARK_SPAM_SOURCES: usize = 64;
/// Maximum filename length in a `mark_spam` payload (eD2k filenames
/// don't exceed 255 bytes in practice; we allow a little headroom).
const MAX_MARK_SPAM_FILENAME: usize = 1024;
/// Maximum search-keyword count in a `mark_spam` payload.
const MAX_MARK_SPAM_KEYWORDS: usize = 32;
/// Maximum keyword length in a `mark_spam` payload.
const MAX_MARK_SPAM_KEYWORD_LEN: usize = 256;

/// Shared input bounds for the spam IPC payloads (`mark_spam` and
/// `explain_spam_result`). Both accept attacker-influenceable strings from
/// the renderer, so they must reject oversized inputs identically before
/// constructing a `SearchResult` / touching the spam filter.
fn validate_spam_payload(
    file_name: &str,
    source_addresses: &[String],
    search_keywords: &[String],
) -> Result<(), String> {
    if file_name.len() > MAX_MARK_SPAM_FILENAME {
        return Err(coded_ctx(
            "search_spam_filename_too_long",
            format!("file_name exceeds {MAX_MARK_SPAM_FILENAME} bytes"),
            MAX_MARK_SPAM_FILENAME,
        ));
    }
    if source_addresses.len() > MAX_MARK_SPAM_SOURCES {
        return Err(coded_ctx(
            "search_spam_too_many_sources",
            format!("Too many source_addresses (max {MAX_MARK_SPAM_SOURCES})"),
            MAX_MARK_SPAM_SOURCES,
        ));
    }
    if search_keywords.len() > MAX_MARK_SPAM_KEYWORDS {
        return Err(coded_ctx(
            "search_spam_too_many_keywords",
            format!("Too many search_keywords (max {MAX_MARK_SPAM_KEYWORDS})"),
            MAX_MARK_SPAM_KEYWORDS,
        ));
    }
    if search_keywords
        .iter()
        .any(|k| k.len() > MAX_MARK_SPAM_KEYWORD_LEN)
    {
        return Err(coded_ctx(
            "search_spam_keyword_too_long",
            format!("a search_keyword exceeds {MAX_MARK_SPAM_KEYWORD_LEN} bytes"),
            MAX_MARK_SPAM_KEYWORD_LEN,
        ));
    }
    Ok(())
}

fn parse_exact_file_hash(file_hash: &str) -> Result<[u8; 16], String> {
    if file_hash.len() != 32 || !file_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(coded(
            "search_invalid_file_hash_hex",
            "Invalid file hash: expected 32 hex characters",
        ));
    }
    let raw =
        hex::decode(file_hash).map_err(|e| coded_ctx("search_invalid_hash", "Invalid hash", e))?;
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&raw);
    Ok(hash)
}

/// Apply spam scoring + filename cleanup + comment URL stripping to a
/// batch of results, given pre-resolved configuration. Pure enrichment
/// — no I/O, no locking. Used by both the synchronous `search_files`
/// command path and the streaming network event loop.
#[allow(clippy::too_many_arguments)]
pub fn apply_search_enrichment(
    results: &mut [SearchResult],
    spam: &SpamFilter,
    search_keywords: &[String],
    server_ip: Option<&str>,
    spam_enabled: bool,
    spam_profile: SpamFilterProfile,
    cleanup_strings: &[String],
    community: &HashMap<String, CommunityRating>,
) {
    // Statistical signals over the whole batch (same-name/many-hashes,
    // same-hash/many-names, source-IP concentration). Computed once and shared
    // across all results. Skipped for the `relaxed` profile (local-only) and
    // when the filter is off; also a no-op below the minimum batch size.
    let batch = if spam_enabled && spam_profile != SpamFilterProfile::Relaxed {
        BatchSpamContext::analyze(results)
    } else {
        BatchSpamContext::default()
    };
    for result in results.iter_mut() {
        if spam_enabled {
            let cr = community
                .get(&result.file.hash)
                .copied()
                .unwrap_or_default();
            result.spam_rating =
                spam.rate_result(result, search_keywords, server_ip, spam_profile, cr, &batch);
            result.is_spam = SpamFilter::is_spam(result.spam_rating, spam_profile);
        }
        result.clean_name = cleanup_filename(&result.file.name, cleanup_strings);
        if let Some(ref comment) = result.comment {
            let cleaned = strip_comment_urls(comment);
            if cleaned != *comment {
                result.comment = Some(cleaned);
            }
        }
    }
}

pub async fn enrich_results(
    results: &mut [SearchResult],
    state: &AppState,
    search_keywords: &[String],
    server_ip: Option<&str>,
) {
    let (config, spam) = tokio::join!(state.config.read(), state.spam_filter.read(),);
    let spam_enabled = config.settings.spam_filter_enabled;
    let spam_profile = SpamFilterProfile::from_setting(&config.settings.spam_filter_profile);
    let cleanup_strings = parse_cleanup_strings(&config.settings.filename_cleanups);
    drop(config);

    // The synchronous command path (local index + initial returned set) has no
    // access to the comment manager, so community ratings aren't applied here.
    // The bulk of network results flow through the streaming path
    // (`enrich_and_emit_search_results`), which does supply them.
    let community = HashMap::new();
    apply_search_enrichment(
        results,
        &spam,
        search_keywords,
        server_ip,
        spam_enabled,
        spam_profile,
        &cleanup_strings,
        &community,
    );
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
    if query.len() > MAX_SEARCH_QUERY_LEN {
        return Err(coded_ctx(
            "search_query_too_long",
            format!("Search query exceeds {MAX_SEARCH_QUERY_LEN} bytes; shorten it"),
            MAX_SEARCH_QUERY_LEN,
        ));
    }
    if file_type
        .as_deref()
        .is_some_and(|s| s.len() > MAX_SEARCH_FILTER_LEN)
    {
        return Err(coded_ctx(
            "search_file_type_too_long",
            format!("file_type exceeds {MAX_SEARCH_FILTER_LEN} bytes"),
            MAX_SEARCH_FILTER_LEN,
        ));
    }
    if file_extension
        .as_deref()
        .is_some_and(|s| s.len() > MAX_SEARCH_FILTER_LEN)
    {
        return Err(coded_ctx(
            "search_file_extension_too_long",
            format!("file_extension exceeds {MAX_SEARCH_FILTER_LEN} bytes"),
            MAX_SEARCH_FILTER_LEN,
        ));
    }
    let (tx, rx) = oneshot::channel();

    let keywords: Vec<String> = query
        .split_whitespace()
        .filter(|w| !w.is_empty())
        .map(|w| w.to_lowercase())
        .collect();

    let (local_hits, timeout_secs) = {
        let (li, c) = tokio::join!(state.local_index.read(), state.config.read(),);
        (
            li.search(query.trim()),
            c.settings
                .search_timeout_secs
                .clamp(SEARCH_TIMEOUT_MIN, SEARCH_TIMEOUT_MAX),
        )
    };

    // Apply the same boolean query semantics (implicit/explicit AND, OR, NOT,
    // `-` exclusion, quoted phrases, parentheses) to our own shared-library
    // hits that the network path applies to KAD/server results, so local
    // results stay at parity. `LocalIndex::search` scores by any-token match
    // (OR-ish) and can't express NOT, so without this a query like
    // `movie -cam` would still surface local `cam` files, and a multi-word
    // query would surface files matching only one of the words. Trivial
    // single-keyword queries are left untouched (no behavior change there).
    let local_hits = match crate::search::query::parse(&query) {
        Some(expr) if !expr.is_trivial() => local_hits
            .into_iter()
            .filter(|r| expr.matches(&r.file.name.to_lowercase()))
            .collect(),
        _ => local_hits,
    };

    let file_type_filter = file_type.clone();
    let filters = if min_size.is_some()
        || max_size.is_some()
        || file_type.is_some()
        || file_extension.is_some()
        || min_availability.is_some()
    {
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
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;

    let mut results =
        match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), rx).await {
            Ok(Ok(results)) => results,
            Ok(Err(e)) => return Err(coded_ctx("search_failed", "Search failed", e)),
            Err(_) => {
                let _ = state
                    .network_tx
                    .try_send(NetworkCommand::CancelSearch { request_id });
                return Err(coded_ctx(
                    "search_timed_out",
                    format!("Search timed out after {timeout_secs}s"),
                    timeout_secs,
                ));
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
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;

    let timeout_secs = {
        let c = state.config.read().await;
        c.settings
            .search_timeout_secs
            .clamp(SEARCH_TIMEOUT_MIN, SEARCH_TIMEOUT_MAX)
    };
    let mut results = tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), rx)
        .await
        .map_err(|_| format!("Notes search timed out after {timeout_secs}s"))?
        .map_err(|e| coded_ctx("search_notes_search_failed", "Notes search failed", e))?;
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
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;

    let timeout_secs = {
        let c = state.config.read().await;
        c.settings
            .search_timeout_secs
            .clamp(SEARCH_TIMEOUT_MIN, SEARCH_TIMEOUT_MAX)
    };
    tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), rx)
        .await
        .map_err(|_| format!("Source search timed out after {timeout_secs}s"))?
        .map_err(|e| coded_ctx("search_source_search_failed", "Source search failed", e))
}

#[tauri::command]
pub async fn publish_note(
    state: tauri::State<'_, AppState>,
    file_hash: String,
    rating: u8,
    comment: String,
) -> Result<String, String> {
    if rating > 5 {
        return Err(coded(
            "search_rating_range",
            "Rating must be between 0 and 5",
        ));
    }
    if comment.len() > 4096 {
        return Err(coded(
            "search_comment_too_long",
            "Comment too long (max 4096 bytes)",
        ));
    }
    if rating == 0 && comment.trim().is_empty() {
        return Err(coded(
            "search_empty_note",
            "Add a rating or a comment before publishing",
        ));
    }
    if state.cached_contacts.read().await.is_empty() {
        return Err(coded(
            "search_no_kad_contacts",
            "No Kad contacts available to publish note",
        ));
    }

    let kad_hash = md4_bytes_to_kad_id(&parse_exact_file_hash(&file_hash)?);

    state
        .network_tx
        .try_send(NetworkCommand::PublishNote {
            file_hash: kad_hash,
            rating,
            comment,
        })
        .map_err(|_| {
            coded(
                "search_network_busy_retry",
                "Network is busy, please try again",
            )
        })?;

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
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    Ok(())
}

/// Compute the ed2k hash of raw bytes (for in-memory content).
///
/// This is the only IPC path that hashes a byte buffer directly
/// (the shared-folder indexer hashes files by path). Intended for
/// UI flows like drag-drop / clipboard paste where the frontend
/// already holds the bytes and wants a canonical ed2k hash without
/// a round-trip through the filesystem. Capped at 100 MiB to
/// bound IPC frame size and blocking-pool work.
#[tauri::command]
pub async fn compute_ed2k_hash(data: Vec<u8>) -> Result<String, String> {
    if data.len() > 100 * 1024 * 1024 {
        return Err(coded(
            "search_input_too_large",
            "Input too large (max 100MB)",
        ));
    }
    tokio::task::spawn_blocking(move || hash::ed2k_hash_bytes(&data))
        .await
        .map_err(|e| coded_ctx("search_hash_task_failed", "Hash task failed", e))
}

#[tauri::command]
pub fn format_ed2k_link(name: String, size: u64, file_hash: String) -> Result<String, String> {
    if name.is_empty() || name.len() > 4096 {
        return Err(coded(
            "search_file_name_invalid",
            "File name is empty or too long",
        ));
    }
    if file_hash.len() != 32 || !file_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(coded(
            "search_link_invalid_hash",
            "Invalid file hash (expected 32 hex characters)",
        ));
    }
    Ok(hash::format_ed2k_link(&name, size, &file_hash))
}

#[derive(serde::Serialize)]
pub struct Ed2kLinkInfo {
    pub name: String,
    pub size: u64,
    pub hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aich: Option<String>,
}

#[tauri::command]
pub fn parse_ed2k_link(link: String) -> Result<Ed2kLinkInfo, String> {
    if link.len() > MAX_ED2K_LINK_LEN {
        return Err(coded_ctx(
            "search_ed2k_link_too_long",
            format!("ed2k link exceeds {MAX_ED2K_LINK_LEN} bytes"),
            MAX_ED2K_LINK_LEN,
        ));
    }
    hash::parse_ed2k_link(&link)
        .map(|(name, size, hash, aich)| Ed2kLinkInfo {
            name,
            size,
            hash,
            aich,
        })
        .ok_or_else(|| coded("search_invalid_ed2k_link", "Invalid ed2k link format"))
}

/// Build an ed2k link with optional AICH and/or our own endpoint as a source,
/// matching eMule's "copy link" submenu variants. `aich_hash` is the 40-char
/// hex AICH root from the library row (re-encoded to base32 for `h=`). When
/// `with_sources` is set we append our reachable IP:port — this only makes
/// sense with a HighID, so a firewalled client returns an error the UI can
/// surface rather than emitting an unreachable source.
#[tauri::command]
pub async fn build_ed2k_link(
    state: tauri::State<'_, AppState>,
    name: String,
    size: u64,
    file_hash: String,
    aich_hash: Option<String>,
    with_sources: bool,
) -> Result<String, String> {
    if name.is_empty() || name.len() > 4096 {
        return Err(coded(
            "search_file_name_invalid",
            "File name is empty or too long",
        ));
    }
    if file_hash.len() != 32 || !file_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(coded(
            "search_link_invalid_hash",
            "Invalid file hash (expected 32 hex characters)",
        ));
    }

    let aich = aich_hash.and_then(|h| {
        let t = h.trim().to_string();
        (t.len() == 40 && t.chars().all(|c| c.is_ascii_hexdigit())).then_some(t)
    });

    let mut sources: Vec<(String, u16)> = Vec::new();
    if with_sources {
        let (tx, rx) = oneshot::channel();
        state
            .network_tx
            .try_send(NetworkCommand::GetNetworkStatsSnapshot { tx })
            .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
        let stats = tokio::time::timeout(LINK_STATS_TIMEOUT, rx)
            .await
            .map_err(|_| {
                coded(
                    "search_link_sources_timeout",
                    "Timed out reading network state",
                )
            })?
            .map_err(|e| {
                coded_ctx(
                    "search_link_sources_failed",
                    "Failed to read network state",
                    e,
                )
            })?;
        if stats.firewalled {
            return Err(coded(
                "search_link_firewalled",
                "Cannot add sources to link while firewalled (LowID)",
            ));
        }
        let ip = stats.external_ip.trim();
        let valid_ip = ip.parse::<std::net::Ipv4Addr>().ok().filter(|a| {
            !a.is_loopback() && !a.is_unspecified() && !a.is_private() && !a.is_link_local()
        });
        let tcp_port = {
            let cfg = state.config.read().await;
            cfg.settings.tcp_port
        };
        match (valid_ip, tcp_port) {
            (Some(addr), port) if port > 0 => sources.push((addr.to_string(), port)),
            _ => {
                return Err(coded(
                    "search_link_no_source",
                    "No reachable public address available for a source link",
                ))
            }
        }
    }

    Ok(hash::format_ed2k_link_ext(
        &name,
        size,
        &file_hash,
        aich.as_deref(),
        &sources,
    ))
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
        return Err(coded("search_invalid_file_hash", "Invalid file hash"));
    }
    validate_spam_payload(&file_name, &source_addresses, &search_keywords)?;
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
        media: None,
        spam_rating: 0,
        is_spam: false,
        clean_name: String::new(),
        result_origin: String::new(),
    };
    let save_data = {
        let mut spam = state.spam_filter.write().await;
        spam.mark_spam(&result, &search_keywords, server_ip.as_deref());
        spam.take_save_data()
    };
    if let Some((data, path, gen)) = save_data {
        tokio::task::spawn_blocking(move || {
            crate::security::atomic_write(&path, data.as_bytes(), false)
        })
        .await
        .map_err(|e| coded_ctx("spam_filter_save_task_failed", "Spam filter save failed", e))?
        .map_err(|e| coded_ctx("spam_filter_save_failed", "Spam filter save failed", e))?;
        state.spam_filter.write().await.mark_saved(gen);
    }
    Ok(())
}

#[tauri::command]
pub async fn mark_not_spam(
    state: tauri::State<'_, AppState>,
    file_hash: String,
) -> Result<(), String> {
    if file_hash.len() != 32 || hex::decode(&file_hash).is_err() {
        return Err(coded("search_invalid_file_hash", "Invalid file hash"));
    }
    let save_data = {
        let mut spam = state.spam_filter.write().await;
        spam.mark_not_spam(&file_hash);
        spam.take_save_data()
    };
    if let Some((data, path, gen)) = save_data {
        let ok = tokio::task::spawn_blocking(move || {
            match crate::security::atomic_write(&path, data.as_bytes(), false) {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!("Failed to save spam filter: {e}");
                    false
                }
            }
        })
        .await
        .unwrap_or(false);
        if ok {
            state.spam_filter.write().await.mark_saved(gen);
        }
    }
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
        return Err(coded("search_invalid_file_hash", "Invalid file hash"));
    }
    validate_spam_payload(&file_name, &source_addresses, &search_keywords)?;
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
        media: None,
        spam_rating: 0,
        is_spam: false,
        clean_name: String::new(),
        result_origin: String::new(),
    };

    let cfg = state.config.read().await;
    let profile = SpamFilterProfile::from_setting(&cfg.settings.spam_filter_profile);
    drop(cfg);

    let spam = state.spam_filter.read().await;
    // The standalone "why is this spam?" view scores a single result, so the
    // batch-statistical and community signals (which need the full result set /
    // comment manager) aren't available here — pass neutral values. The
    // authoritative is_spam flag shown in the result list comes from the
    // streaming enrichment path, which does include them.
    let details = spam.explain_result(
        &result,
        &search_keywords,
        server_ip.as_deref(),
        profile,
        CommunityRating::default(),
        &BatchSpamContext::default(),
    );
    Ok(SpamExplainResponse {
        score: details.score,
        threshold: details.threshold,
        profile: details.profile,
        is_spam: details.is_spam,
        reasons: details.reasons,
    })
}

#[tauri::command]
pub async fn reset_spam_filter(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let save_data = {
        let mut spam = state.spam_filter.write().await;
        spam.reset();
        spam.take_save_data()
    };
    if let Some((data, path, gen)) = save_data {
        let ok = tokio::task::spawn_blocking(move || {
            match crate::security::atomic_write(&path, data.as_bytes(), false) {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!("Failed to save spam filter after reset: {e}");
                    false
                }
            }
        })
        .await
        .unwrap_or(false);
        if ok {
            state.spam_filter.write().await.mark_saved(gen);
        }
    }
    Ok("Spam filter learning data cleared.".to_string())
}

/// Look up download history for a batch of file hashes.
/// Returns a map of hash → status ("completed" or "cancelled").
#[tauri::command]
pub async fn get_download_history(
    state: tauri::State<'_, AppState>,
    hashes: Vec<String>,
) -> Result<std::collections::HashMap<String, String>, String> {
    // Cap the batch size so the IPC frame and the SQL `IN (?,?,…)`
    // query stay bounded. The frontend already chunks search results
    // (5k visible at most); this guards against a buggy/hostile
    // caller pushing a million-element vector.
    const MAX_HISTORY_BATCH: usize = 5_000;
    if hashes.len() > MAX_HISTORY_BATCH {
        return Err(coded_ctx(
            "search_history_batch_too_large",
            format!("Too many hashes in one batch (max {MAX_HISTORY_BATCH}) — chunk the request"),
            MAX_HISTORY_BATCH,
        ));
    }
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || db.get_download_history_batch(&hashes))
        .await
        .map_err(|e| coded_ctx("search_task_failed", "Task failed", e))?
        .map_err(|e| coded_ctx("search_history_fetch_failed", "Failed to fetch history", e))
}

/// Download history row counts for the settings page summary.
#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DownloadHistoryStats {
    pub completed: u64,
    pub cancelled: u64,
    pub total: u64,
}

/// Return completed / cancelled / total download-history counts.
#[tauri::command]
pub async fn get_download_history_stats(
    state: tauri::State<'_, AppState>,
) -> Result<DownloadHistoryStats, String> {
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<DownloadHistoryStats> {
        let (completed, cancelled) = db.get_download_history_counts()?;
        let completed = completed.max(0) as u64;
        let cancelled = cancelled.max(0) as u64;
        Ok(DownloadHistoryStats {
            completed,
            cancelled,
            total: completed + cancelled,
        })
    })
    .await
    .map_err(|e| coded_ctx("search_task_failed", "Task failed", e))?
    .map_err(|e| {
        coded_ctx(
            "search_history_stats_failed",
            "Failed to fetch history stats",
            e,
        )
    })
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
            _ => {
                return Err(anyhow::anyhow!(
                    "Invalid status: {status}. Must be 'completed', 'cancelled', or 'all'"
                ))
            }
        }
        Ok(())
    })
    .await
    .map_err(|e| coded_ctx("search_task_failed", "Task failed", e))?
    .map_err(|e| coded_ctx("search_history_clear_failed", "Failed to clear history", e))
}

/// Remove a single download-history row by file hash.
///
/// `clear_download_history(status)` only erases by status ("completed"
/// / "cancelled" / "all"). This is the only IPC path that deletes a
/// specific entry — use it when the UI surfaces a per-row "remove from
/// history" action (e.g. a search-results context menu on a row the
/// user has previously downloaded and wants re-surfaced as fresh).
#[tauri::command]
pub async fn remove_download_history_entry(
    state: tauri::State<'_, AppState>,
    file_hash: String,
) -> Result<(), String> {
    let _ = parse_exact_file_hash(&file_hash)?;
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || db.remove_download_history(&file_hash))
        .await
        .map_err(|e| coded_ctx("search_task_failed", "Task failed", e))?
        .map_err(|e| {
            coded_ctx(
                "search_history_remove_failed",
                "Failed to remove history entry",
                e,
            )
        })
}
