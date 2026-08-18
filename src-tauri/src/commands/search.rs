use tauri::Emitter;
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

fn is_allowed_emule_file_type(file_type: &str) -> bool {
    matches!(
        file_type,
        "Audio" | "Video" | "Image" | "Pro" | "Doc" | "Arc" | "Iso" | "EmuleCollection"
    )
}

/// Shared input bounds for the spam IPC payloads (`mark_spam` and
/// `explain_spam_result`). Both accept attacker-influenceable strings from
/// the renderer, so they must reject oversized inputs identically before
/// constructing a `SearchResult` / touching the spam filter.
fn validate_spam_payload(
    file_name: &str,
    source_addresses: &[String],
    search_keywords: &[String],
    server_ip: Option<&str>,
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
    if let Some(ip) = server_ip {
        if ip.len() > 64 || ip.parse::<std::net::IpAddr>().is_err() {
            return Err(coded_ctx(
                "search_spam_invalid_server_ip",
                "Invalid spam server IP",
                ip,
            ));
        }
    }
    Ok(())
}

fn keywords_for_spam(search_query: Option<&str>, search_keywords: &[String]) -> Vec<String> {
    if let Some(q) = search_query.map(str::trim).filter(|s| !s.is_empty()) {
        let parsed = crate::search::query::positive_terms_from_query(q);
        if !parsed.is_empty() {
            return parsed;
        }
    }
    search_keywords.to_vec()
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
/// — no I/O, no locking. Used by both the streaming network event loop
/// and the invoke return / rescore paths.
///
/// `use_batch_context: false` skips analysing *this* slice as a fresh
/// batch (same-name/many-hashes). Pass `precomputed_batch` when the
/// caller has already absorbed results into a search-wide context.
#[allow(clippy::too_many_arguments)]
pub fn apply_search_enrichment_with_batch(
    results: &mut [SearchResult],
    spam: &SpamFilter,
    search_keywords: &[String],
    server_ip: Option<&str>,
    spam_enabled: bool,
    spam_profile: SpamFilterProfile,
    cleanup_strings: &[String],
    community: &HashMap<String, CommunityRating>,
    use_batch_context: bool,
    precomputed_batch: Option<&BatchSpamContext>,
) {
    let analyzed;
    let batch: &BatchSpamContext = if let Some(pre) = precomputed_batch {
        pre
    } else if spam_enabled && spam_profile != SpamFilterProfile::Relaxed && use_batch_context {
        analyzed = BatchSpamContext::analyze(results);
        &analyzed
    } else {
        analyzed = BatchSpamContext::default();
        &analyzed
    };
    for result in results.iter_mut() {
        if spam_enabled {
            let cr = community
                .get(&result.file.hash)
                .copied()
                .unwrap_or_default();
            let details =
                spam.explain_result(result, search_keywords, server_ip, spam_profile, cr, batch);
            result.spam_rating = details.score;
            result.is_spam = details.is_spam;
            result.spam_reasons = details.reasons;
        } else {
            result.spam_rating = 0;
            result.is_spam = false;
            result.spam_reasons.clear();
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

pub async fn enrich_results_with_batch(
    results: &mut [SearchResult],
    state: &AppState,
    search_keywords: &[String],
    server_ip: Option<&str>,
    use_batch_context: bool,
) {
    let (config, spam) = tokio::join!(state.config.read(), state.spam_filter.read(),);
    let spam_enabled = config.settings.spam_filter_enabled;
    let spam_profile = SpamFilterProfile::from_setting(&config.settings.spam_filter_profile);
    let cleanup_strings = parse_cleanup_strings(&config.settings.filename_cleanups);
    drop(config);

    let cm = state.comment_manager.read().await;
    let community = community_ratings_for(&*cm, results, spam_enabled, spam_profile);
    apply_search_enrichment_with_batch(
        results,
        &spam,
        search_keywords,
        server_ip,
        spam_enabled,
        spam_profile,
        &cleanup_strings,
        &community,
        use_batch_context,
        None,
    );
}

/// Community "fake" vote stats for a result batch. Shared by the streaming
/// enrich path and the invoke return path so oneshot-only hashes are not
/// scored without KAD/peer fake ratings.
pub(crate) fn community_ratings_for(
    cm: &crate::network::ed2k::comments::CommentManager,
    results: &[SearchResult],
    spam_enabled: bool,
    spam_profile: SpamFilterProfile,
) -> HashMap<String, CommunityRating> {
    if !spam_enabled || spam_profile == SpamFilterProfile::Relaxed {
        return HashMap::new();
    }
    results
        .iter()
        .filter_map(|r| {
            let (fake, total) = cm.fake_rating_stats(&r.file.hash);
            if total > 0 {
                Some((
                    r.file.hash.clone(),
                    CommunityRating {
                        fake_votes: fake,
                        total_votes: total,
                    },
                ))
            } else {
                None
            }
        })
        .collect()
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
    if let Some(ref ft) = file_type {
        if !is_allowed_emule_file_type(ft) {
            return Err(coded_ctx(
                "search_invalid_file_type",
                "Unsupported eMule file_type filter",
                ft,
            ));
        }
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

    let keywords = crate::search::query::parse(query.trim())
        .map(|expression| expression.positive_terms())
        .unwrap_or_default();

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

    let ui_file_type = file_type.clone();
    let client_min_size = min_size;
    let client_max_size = max_size;
    let client_file_extension = file_extension.clone();
    let client_min_availability = min_availability;
    let filters = if min_size.is_some()
        || max_size.is_some()
        || ui_file_type.is_some()
        || file_extension.is_some()
        || min_availability.is_some()
    {
        Some(crate::network::SearchFilters {
            min_size,
            max_size,
            file_type: ui_file_type.clone(),
            file_extension,
            min_availability,
        })
    } else {
        None
    };

    // eMule: Program search clears the local type filter; Archive/CD-Image keep
    // theirs so Pro-wire replies can be narrowed client-side.
    let file_type_filter =
        crate::search::merge::client_search_file_type_filter(ui_file_type.as_deref());

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
    results.retain(|r| {
        merge::result_matches_client_filters(
            r,
            file_type_filter.as_deref(),
            client_min_size,
            client_max_size,
            client_file_extension.as_deref(),
            client_min_availability,
        )
    });
    // No batch spam context: invoke often re-delivers hashes already shown via
    // streamed events; batch heuristics can flip clean → spam.
    enrich_results_with_batch(&mut results, &state, &keywords, None, false).await;
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
    // Generated here (not caller-supplied, unlike `search_files`'s
    // `request_id`) purely to give the network task something to match
    // against on cancel; nothing else needs to know it.
    let request_id: u64 = rand::random();

    state
        .network_tx
        .try_send(NetworkCommand::FindNotes {
            file_hash: kad_hash,
            file_size,
            request_id,
            tx,
        })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;

    let timeout_secs = {
        let c = state.config.read().await;
        c.settings
            .search_timeout_secs
            .clamp(SEARCH_TIMEOUT_MIN, SEARCH_TIMEOUT_MAX)
    };
    let mut results =
        match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), rx).await {
            Ok(Ok(Ok(results))) => results,
            Ok(Ok(Err(e))) => return Err(coded("search_notes_busy", e)),
            Ok(Err(e)) => {
                return Err(coded_ctx(
                    "search_notes_search_failed",
                    "Notes search failed",
                    e,
                ))
            }
            Err(_) => {
                // Without this, the KAD search stayed alive (holding a
                // routing-table in-use ref and a search-manager slot) until its
                // own lifetime expired, well after this call had already
                // returned an error to the caller.
                let _ = state
                    .network_tx
                    .try_send(NetworkCommand::CancelSearch { request_id });
                return Err(coded_ctx(
                    "search_timed_out",
                    format!("Notes search timed out after {timeout_secs}s"),
                    timeout_secs,
                ));
            }
        };
    {
        let mut cm = state.comment_manager.write().await;
        for r in &results {
            let rating = r.rating.unwrap_or(0);
            let comment = r.comment.clone().unwrap_or_default();
            if rating == 0 && comment.is_empty() {
                continue;
            }
            // Publisher identity: Kad notes put the full hex in `peer_id` and
            // a display prefix in `peer_name`. Upsert by the full id so two
            // publishers cannot collapse onto an 8-character prefix.
            let user = if !r.peer_id.is_empty() {
                r.peer_id.clone()
            } else {
                r.peer_name.clone()
            };
            cm.add_peer_comment(&r.file.hash, user, rating, comment, 1);
        }
    }
    // Notes are comments, not search hits: skip spam scoring and batch heuristics.
    enrich_results_with_batch(&mut results, &state, &[], None, false).await;
    for result in &mut results {
        result.spam_rating = 0;
        result.is_spam = false;
        result.spam_reasons.clear();
    }
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
    let request_id: u64 = rand::random();

    state
        .network_tx
        .try_send(NetworkCommand::FindSources {
            file_hash: kad_hash,
            file_size,
            request_id,
            tx,
        })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;

    let timeout_secs = {
        let c = state.config.read().await;
        c.settings
            .search_timeout_secs
            .clamp(SEARCH_TIMEOUT_MIN, SEARCH_TIMEOUT_MAX)
    };
    match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), rx).await {
        Ok(Ok(Ok(results))) => Ok(results),
        Ok(Ok(Err(msg))) => Err(coded_ctx(
            "search_source_search_busy",
            msg,
            "kad search capacity",
        )),
        Ok(Err(e)) => Err(coded_ctx(
            "search_source_search_failed",
            "Source search failed",
            e,
        )),
        Err(_) => {
            let _ = state
                .network_tx
                .try_send(NetworkCommand::CancelSearch { request_id });
            Err(coded_ctx(
                "search_timed_out",
                format!("Source search timed out after {timeout_secs}s"),
                timeout_secs,
            ))
        }
    }
}

#[tauri::command]
pub async fn publish_note(
    state: tauri::State<'_, AppState>,
    file_hash: String,
    file_name: Option<String>,
    file_size: Option<u64>,
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
    if file_name.as_deref().is_some_and(|name| name.len() > 1024) {
        return Err(coded(
            "search_note_file_name_too_long",
            "File name too long (max 1024 bytes)",
        ));
    }
    if rating == 0 && comment.trim().is_empty() {
        return Err(coded(
            "search_empty_note",
            "Add a rating or a comment before publishing",
        ));
    }
    let kad_hash = md4_bytes_to_kad_id(&parse_exact_file_hash(&file_hash)?);
    let (tx, rx) = oneshot::channel();

    state
        .network_tx
        .try_send(NetworkCommand::PublishNote {
            file_hash: kad_hash,
            file_name,
            file_size,
            rating,
            comment,
            tx,
        })
        .map_err(|_| {
            coded(
                "search_network_busy_retry",
                "Network is busy, please try again",
            )
        })?;

    match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
        Ok(Ok(Ok(()))) => Ok("Note publish started".to_string()),
        Ok(Ok(Err(message))) => Err(coded("search_note_publish_unavailable", message)),
        Ok(Err(_)) => Err(coded(
            "search_note_publish_failed",
            "Network task closed the note publish acknowledgement",
        )),
        // Oneshot was delivered; the network task may still complete publish
        // after our wait. Soften timeout to a queued ack so the UI does not
        // treat a slow KAD publish as a hard failure.
        Err(_) => Ok("Note publish queued".to_string()),
    }
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
pub fn format_ed2k_link(
    name: String,
    size: u64,
    file_hash: String,
    ember_file_hash: Option<String>,
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
    let ember = ember_file_hash.as_deref().and_then(|h| {
        let t = h.trim();
        (t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit())).then_some(t)
    });
    Ok(hash::format_ed2k_link_ext(
        &name,
        size,
        &file_hash,
        None,
        ember,
        &[],
    ))
}

/// One file entry for [`format_ed2k_links`] (bulk clipboard / export).
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ed2kLinkFileInput {
    pub name: String,
    pub size: u64,
    pub hash: String,
    #[serde(default)]
    pub ember_file_hash: Option<String>,
}

/// Soft cap for a single clipboard batch. Larger libraries should export a
/// collection / text file instead of stuffing the OS clipboard.
const MAX_ED2K_LINK_BATCH: usize = 50_000;

/// Format many standard eD2K links in one IPC round-trip (newline-separated).
#[tauri::command]
pub fn format_ed2k_links(files: Vec<Ed2kLinkFileInput>) -> Result<String, String> {
    if files.len() > MAX_ED2K_LINK_BATCH {
        return Err(coded_ctx(
            "search_ed2k_link_batch_too_large",
            format!("Too many links in one batch (max {MAX_ED2K_LINK_BATCH})"),
            MAX_ED2K_LINK_BATCH,
        ));
    }
    let mut out = String::new();
    for (i, f) in files.into_iter().enumerate() {
        if f.name.is_empty() || f.name.len() > 4096 {
            return Err(coded(
                "search_file_name_invalid",
                "File name is empty or too long",
            ));
        }
        if f.hash.len() != 32 || !f.hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(coded(
                "search_link_invalid_hash",
                "Invalid file hash (expected 32 hex characters)",
            ));
        }
        if i > 0 {
            out.push('\n');
        }
        let ember = f.ember_file_hash.as_deref().and_then(|h| {
            let t = h.trim();
            (t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit())).then_some(t)
        });
        out.push_str(&hash::format_ed2k_link_ext(
            &f.name,
            f.size,
            &f.hash,
            None,
            ember,
            &[],
        ));
    }
    Ok(out)
}

#[derive(serde::Serialize)]
pub struct Ed2kLinkInfo {
    pub name: String,
    pub size: u64,
    pub hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aich: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ember: Option<String>,
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
    hash::parse_ed2k_link_strict(&link)
        .map(|(name, size, hash, aich, ember)| Ed2kLinkInfo {
            name,
            size,
            hash,
            aich,
            ember,
        })
        .map_err(|error| {
            coded_ctx(
                "search_invalid_ed2k_link",
                "Invalid ed2k link format",
                error,
            )
        })
}

/// Maximum links accepted from one paste. Past this a user is better served by
/// the collection importer, which reads the same one-link-per-line text format
/// from a file and is bounded by `MAX_COLLECTION_FILES` instead.
const MAX_ED2K_PASTE_LINKS: usize = 256;
/// Byte ceiling for the pasted blob, sized to hold `MAX_ED2K_PASTE_LINKS`
/// links of 1 KiB each. Keeps a runaway paste away from the parser entirely.
const MAX_ED2K_PASTE_BYTES: usize = MAX_ED2K_PASTE_LINKS * 1024;

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ed2kLinkBatch {
    /// Successfully parsed links, in the order they appeared.
    pub links: Vec<Ed2kLinkInfo>,
    /// Non-blank lines that did not parse as an ed2k file link.
    pub invalid: usize,
    /// Non-blank lines left unread because the cap was already reached.
    pub skipped: usize,
}

/// Parse a pasted block of newline-separated ed2k links.
///
/// Split out from [`parse_ed2k_link`] because that one is deliberately strict
/// about receiving exactly one link, and feeding it a multi-line paste used to
/// *succeed*: the first link's fields parse, and every later line survives only
/// as unrecognised `|`-segments that the tag loop skips in silence. A user who
/// pasted ten links got one download and a success toast. Reporting the invalid
/// and skipped counts here is what lets the caller say so out loud.
#[tauri::command]
pub fn parse_ed2k_links(text: String) -> Result<Ed2kLinkBatch, String> {
    if text.len() > MAX_ED2K_PASTE_BYTES {
        return Err(coded_ctx(
            "search_ed2k_paste_too_large",
            format!("Pasted text exceeds {MAX_ED2K_PASTE_BYTES} bytes"),
            MAX_ED2K_PASTE_BYTES,
        ));
    }
    let mut links = Vec::new();
    let mut invalid = 0usize;
    let mut skipped = 0usize;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if links.len() >= MAX_ED2K_PASTE_LINKS {
            skipped += 1;
            continue;
        }
        match hash::parse_ed2k_link_strict(line) {
            Ok((name, size, hash, aich, ember)) => links.push(Ed2kLinkInfo {
                name,
                size,
                hash,
                aich,
                ember,
            }),
            Err(_) => invalid += 1,
        }
    }
    Ok(Ed2kLinkBatch {
        links,
        invalid,
        skipped,
    })
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
    ember_file_hash: Option<String>,
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
    let ember = ember_file_hash.and_then(|h| {
        let t = h.trim().to_string();
        (t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit())).then_some(t)
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
        // Prefer the STUN-confirmed public TCP port (may differ from the
        // configured/bind port behind CGNAT/full-cone NAT) so the generated
        // link points somewhere actually reachable; 0 means "not confirmed".
        let tcp_port = if stats.public_tcp_port > 0 {
            stats.public_tcp_port
        } else {
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
        ember.as_deref(),
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
    search_query: Option<String>,
) -> Result<(), String> {
    if file_hash.len() != 32 || hex::decode(&file_hash).is_err() {
        return Err(coded("search_invalid_file_hash", "Invalid file hash"));
    }
    validate_spam_payload(
        &file_name,
        &source_addresses,
        &search_keywords,
        server_ip.as_deref(),
    )?;
    let keywords = keywords_for_spam(search_query.as_deref(), &search_keywords);
    let result = SearchResult {
        file: crate::types::FileInfo {
            id: file_hash.clone(),
            name: file_name,
            path: String::new(),
            size: file_size,
            hash: file_hash,
            aich_hash: String::new(),
            ember_file_hash: String::new(),
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
            friends_only: false,
            shared_kad: false,
            shared_ed2k: false,
            shared_ember: false,
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
        origin_server_ip: server_ip.clone(),
        spam_reasons: Vec::new(),
    };
    let save_data = {
        let mut spam = state.spam_filter.write().await;
        spam.mark_spam(&result, &keywords, server_ip.as_deref());
        spam.take_save_data()
    };
    // Persist off the IPC path so the UI isn't parked on disk I/O. In-memory
    // state is already updated; a crash before the write lands is recovered by
    // the next mark or the periodic spam flush in the network loop.
    spawn_spam_filter_save(state.spam_filter.clone(), save_data);
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
    spawn_spam_filter_save(state.spam_filter.clone(), save_data);
    Ok(())
}

/// Persist off the IPC path so the UI isn't parked on disk I/O. Writers share
/// [`SpamFilter::save_gate`] with the network-loop flush so concurrent marks
/// cannot leave a stale snapshot on disk.
fn spawn_spam_filter_save(
    spam_filter: std::sync::Arc<tokio::sync::RwLock<SpamFilter>>,
    save_data: Option<(String, std::path::PathBuf, u64)>,
) {
    if save_data.is_none() {
        return;
    }
    tokio::spawn(async move {
        if let Err(e) = SpamFilter::drain_saves(&spam_filter).await {
            tracing::warn!("Failed to save spam filter: {e}");
        }
    });
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
    search_query: Option<String>,
    rating: Option<u8>,
    result_origin: Option<String>,
) -> Result<SpamExplainResponse, String> {
    if file_hash.len() != 32 || hex::decode(&file_hash).is_err() {
        return Err(coded("search_invalid_file_hash", "Invalid file hash"));
    }
    validate_spam_payload(
        &file_name,
        &source_addresses,
        &search_keywords,
        server_ip.as_deref(),
    )?;
    let keywords = keywords_for_spam(search_query.as_deref(), &search_keywords);
    let hash_for_comments = file_hash.clone();
    let result = SearchResult {
        file: crate::types::FileInfo {
            id: file_hash.clone(),
            name: file_name,
            path: String::new(),
            size: file_size,
            hash: file_hash,
            aich_hash: String::new(),
            ember_file_hash: String::new(),
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
            friends_only: false,
            shared_kad: false,
            shared_ed2k: false,
            shared_ember: false,
        },
        peer_id: String::new(),
        peer_name: String::new(),
        availability: 0,
        file_type: String::new(),
        source_addresses,
        rating,
        comment: None,
        media: None,
        spam_rating: 0,
        is_spam: false,
        clean_name: String::new(),
        result_origin: result_origin.unwrap_or_default(),
        origin_server_ip: server_ip.clone(),
        spam_reasons: Vec::new(),
    };

    let cfg = state.config.read().await;
    let profile = SpamFilterProfile::from_setting(&cfg.settings.spam_filter_profile);
    drop(cfg);

    let community = {
        let cm = state.comment_manager.read().await;
        let (fake_votes, total_votes) = cm.fake_rating_stats(&hash_for_comments);
        CommunityRating {
            fake_votes,
            total_votes,
        }
    };

    let spam = state.spam_filter.read().await;
    // Batch-local heuristics still need the full result set; those reasons are
    // stored on the row at enrich time (`spam_reasons`) and preferred by the UI.
    let details = spam.explain_result(
        &result,
        &keywords,
        server_ip.as_deref(),
        profile,
        community,
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
    {
        let mut spam = state.spam_filter.write().await;
        spam.reset();
    }
    if let Err(e) = SpamFilter::drain_saves(&state.spam_filter).await {
        tracing::warn!("Failed to save spam filter after reset: {e}");
    }
    Ok("Spam filter learning data cleared.".to_string())
}

/// Re-score an existing search-result list under the current spam profile
/// and community votes. Used when the user changes spam settings so rows
/// already on screen pick up the new classification without a new search.
#[tauri::command]
pub async fn rescore_search_results(
    state: tauri::State<'_, AppState>,
    mut results: Vec<SearchResult>,
    search_keywords: Vec<String>,
    search_query: Option<String>,
) -> Result<Vec<SearchResult>, String> {
    const MAX_RESCORE: usize = 15_000;
    if results.len() > MAX_RESCORE {
        return Err(coded_ctx(
            "search_rescore_too_many",
            format!("Too many results to rescore (max {MAX_RESCORE})"),
            MAX_RESCORE,
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
    let keywords = keywords_for_spam(search_query.as_deref(), &search_keywords);
    let spam_enabled = {
        let config = state.config.read().await;
        config.settings.spam_filter_enabled
    };
    // No batch-local heuristics: this is a re-pass over already-shown rows,
    // and same-name/many-hashes context can flip a clean streamed row to spam.
    // Per-row `origin_server_ip` still feeds server reputation.
    enrich_results_with_batch(&mut results, &state, &keywords, None, false).await;
    if !spam_enabled {
        for result in &mut results {
            result.spam_rating = 0;
            result.is_spam = false;
            result.spam_reasons.clear();
        }
    }
    Ok(results)
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
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    status: String,
) -> Result<(), String> {
    let db = state.db.clone();
    let cleared_status = status.clone();
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
    .map_err(|e| coded_ctx("search_history_clear_failed", "Failed to clear history", e))?;
    // Notify Search badges / history map that the DB was wiped.
    let _ = app.emit(
        "download-history-cleared",
        serde_json::json!({ "status": cleared_status }),
    );
    Ok(())
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

#[cfg(test)]
mod ed2k_paste_tests {
    use super::*;

    fn link(name: &str, size: u64, hash_byte: u8) -> String {
        format!(
            "ed2k://|file|{name}|{size}|{}|/",
            hex::encode([hash_byte; 16])
        )
    }

    #[test]
    fn a_multi_line_paste_yields_every_link() {
        let text = format!(
            "{}\n{}\n{}",
            link("a.bin", 1, 0xAA),
            link("b.bin", 2, 0xBB),
            link("c.bin", 3, 0xCC)
        );
        let batch = parse_ed2k_links(text).expect("parse");
        assert_eq!(batch.links.len(), 3);
        assert_eq!(batch.invalid, 0);
        assert_eq!(batch.skipped, 0);
        assert_eq!(batch.links[0].name, "a.bin");
        assert_eq!(batch.links[2].size, 3);
    }

    #[test]
    fn blank_lines_and_crlf_are_not_counted_as_invalid() {
        // Clipboard content from a Windows text editor arrives CRLF-delimited
        // and usually has a trailing newline; neither is a malformed link.
        let text = format!(
            "{}\r\n\r\n{}\r\n",
            link("a.bin", 1, 0xAA),
            link("b.bin", 2, 0xBB)
        );
        let batch = parse_ed2k_links(text).expect("parse");
        assert_eq!(batch.links.len(), 2);
        assert_eq!(batch.invalid, 0);
    }

    #[test]
    fn unparseable_lines_are_reported_rather_than_dropped() {
        let text = format!(
            "{}\nnot a link\ned2k://|file|broken|\n",
            link("a.bin", 1, 0xAA)
        );
        let batch = parse_ed2k_links(text).expect("parse");
        assert_eq!(batch.links.len(), 1);
        assert_eq!(batch.invalid, 2);
    }

    #[test]
    fn links_past_the_cap_are_counted_as_skipped() {
        let mut text = String::new();
        for i in 0..(MAX_ED2K_PASTE_LINKS + 5) {
            text.push_str(&link("a.bin", i as u64 + 1, 0xAA));
            text.push('\n');
        }
        let batch = parse_ed2k_links(text).expect("parse");
        assert_eq!(batch.links.len(), MAX_ED2K_PASTE_LINKS);
        assert_eq!(batch.skipped, 5);
        assert_eq!(batch.invalid, 0);
    }

    #[test]
    fn an_oversized_paste_is_refused_before_parsing() {
        let text = "e".repeat(MAX_ED2K_PASTE_BYTES + 1);
        assert!(parse_ed2k_links(text).is_err());
    }

    #[test]
    fn a_single_link_still_parses_the_same_as_the_singular_command() {
        let one = link("a.bin", 42, 0xAA);
        let batch = parse_ed2k_links(one.clone()).expect("batch");
        let single = parse_ed2k_link(one).expect("single");
        assert_eq!(batch.links.len(), 1);
        assert_eq!(batch.links[0].hash, single.hash);
        assert_eq!(batch.links[0].size, single.size);
    }
}
