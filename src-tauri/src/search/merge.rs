//! Dedupe and merge search rows by ed2k hash (fallback: name + size) for multi-source results.

use std::collections::HashMap;

use crate::types::SearchResult;

pub const ORIGIN_KAD: &str = "KAD";
pub const ORIGIN_SERVER_TCP: &str = "Server";
pub const ORIGIN_SERVER_UDP: &str = "UDP";
pub const ORIGIN_LOCAL: &str = "Local";
pub const ORIGIN_NOTES: &str = "Notes";
pub const ORIGIN_EMBER: &str = "Ember";

/// Map a UI/eMule file-type filter to the FT_FILETYPE string sent on the wire.
/// Archive (`Arc`) and CD-Image (`Iso`) are client-only; on the wire they are
/// queried as Program (`Pro`) — eMule `GetED2KFileTypeSearchTerm`.
pub fn wire_search_file_type(file_type: Option<&str>) -> Option<&str> {
    match file_type {
        None | Some("") => None,
        Some("Arc") | Some("Iso") => Some("Pro"),
        Some(other) => Some(other),
    }
}

/// Client-side type filter after remapping for the wire.
/// Program clears the local filter (eMule); Arc/Iso keep theirs.
pub fn client_search_file_type_filter(file_type: Option<&str>) -> Option<String> {
    match file_type {
        None | Some("") | Some("Pro") => None,
        Some(other) => Some(other.to_string()),
    }
}

/// Client-side post-filter for size / extension / availability / type.
/// Wire constraints are best-effort; non-compliant peers can still reply.
pub fn result_matches_client_filters(
    r: &SearchResult,
    file_type_filter: Option<&str>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    file_extension: Option<&str>,
    min_availability: Option<u32>,
) -> bool {
    if let Some(ft) = file_type_filter {
        let inferred = crate::search::index::infer_file_type(&r.file.extension);
        let result_type = if !inferred.is_empty() {
            inferred
        } else {
            r.file_type.clone()
        };
        if result_type != ft {
            return false;
        }
    }
    if let Some(min) = min_size {
        if r.file.size < min {
            return false;
        }
    }
    if let Some(max) = max_size {
        if r.file.size > max {
            return false;
        }
    }
    if let Some(ext) = file_extension {
        let want = ext.trim_start_matches('.').to_lowercase();
        if !want.is_empty() {
            let got = r.file.extension.trim_start_matches('.').to_lowercase();
            if got != want {
                return false;
            }
        }
    }
    if let Some(min_av) = min_availability {
        if r.availability < min_av {
            return false;
        }
    }
    true
}

fn result_key(r: &SearchResult) -> String {
    if !r.file.hash.is_empty() {
        r.file.hash.clone()
    } else if r.file.id.starts_with("pending:") {
        format!("nohash-id:{}", r.file.id)
    } else if !r.file.path.is_empty() {
        format!("nohash-path:{}", r.file.path)
    } else {
        format!("nohash:{}:{}", r.file.name, r.file.size)
    }
}

/// Merge two origin labels for display (e.g. `KAD · Server`).
pub fn combine_origin(a: &str, b: &str) -> String {
    if b.is_empty() || a == b {
        return a.to_string();
    }
    if a.is_empty() {
        return b.to_string();
    }
    let mut parts: Vec<String> = a
        .split('·')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .chain(
            b.split('·')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        )
        .collect();
    parts.sort();
    parts.dedup();
    parts.join(" · ")
}

const MAX_SOURCE_ADDRS: usize = 500;

fn merge_into(existing: &mut SearchResult, incoming: SearchResult) {
    let prev_origin = existing.result_origin.clone();
    existing.result_origin = combine_origin(&existing.result_origin, &incoming.result_origin);
    for addr in incoming.source_addresses {
        if existing.source_addresses.len() >= MAX_SOURCE_ADDRS {
            break;
        }
        if !addr.is_empty() && !existing.source_addresses.contains(&addr) {
            existing.source_addresses.push(addr);
        }
    }
    // eMule SearchList: ed2k (server/UDP) hits for the same hash *sum*
    // availability; Kad uses max. Mixed Kad+ed2k keeps max.
    existing.availability = if is_ed2k_network_origin(&prev_origin)
        && is_ed2k_network_origin(&incoming.result_origin)
    {
        existing
            .availability
            .saturating_add(incoming.availability)
            .max(existing.source_addresses.len() as u32)
    } else {
        existing
            .availability
            .max(incoming.availability)
            .max(existing.source_addresses.len() as u32)
    };
    existing.file.complete_sources = existing
        .file
        .complete_sources
        .max(incoming.file.complete_sources);
    if existing.file_type.is_empty() && !incoming.file_type.is_empty() {
        existing.file_type = incoming.file_type;
    }
    if existing.rating.is_none() {
        existing.rating = incoming.rating;
    }
    if existing.comment.is_none() {
        existing.comment = incoming.comment;
    }
    // Fill any media fields the other origin provided that we lack, so a hit
    // found on both KAD and a server keeps whichever side carried the metadata.
    if let Some(inc_media) = incoming.media {
        let em = existing
            .media
            .get_or_insert_with(crate::types::MediaMetadata::default);
        if em.duration.is_none() {
            em.duration = inc_media.duration;
        }
        if em.bitrate.is_none() {
            em.bitrate = inc_media.bitrate;
        }
        if em.codec.is_none() {
            em.codec = inc_media.codec;
        }
        if em.artist.is_none() {
            em.artist = inc_media.artist;
        }
        if em.album.is_none() {
            em.album = inc_media.album;
        }
        if em.title.is_none() {
            em.title = inc_media.title;
        }
    }
    if incoming.file.name.len() > existing.file.name.len() {
        existing.file.name = incoming.file.name;
    }
}

/// True when every non-empty origin part is an eD2k server/UDP label
/// (eMule sums availability across those replies for the same hash).
pub fn is_ed2k_network_origin(origin: &str) -> bool {
    let mut saw = false;
    for part in origin.split('·') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        if p != ORIGIN_SERVER_TCP && p != ORIGIN_SERVER_UDP {
            return false;
        }
        saw = true;
    }
    saw
}

/// Merge two result lists; rows with the same hash are combined. Output is sorted for display.
pub fn merge_search_vecs(
    primary: Vec<SearchResult>,
    secondary: Vec<SearchResult>,
) -> Vec<SearchResult> {
    let mut map: HashMap<String, SearchResult> = HashMap::new();
    for r in primary.into_iter().chain(secondary) {
        let k = result_key(&r);
        if let Some(mut e) = map.remove(&k) {
            merge_into(&mut e, r);
            map.insert(k, e);
        } else {
            map.insert(k, r);
        }
    }
    let mut out: Vec<SearchResult> = map.into_values().collect();
    sort_search_results(&mut out);
    out
}

pub fn sort_search_results(v: &mut [SearchResult]) {
    v.sort_by(|a, b| {
        b.file
            .complete_sources
            .cmp(&a.file.complete_sources)
            .then_with(|| b.availability.cmp(&a.availability))
            .then_with(|| {
                let an = if a.clean_name.is_empty() {
                    &a.file.name
                } else {
                    &a.clean_name
                };
                let bn = if b.clean_name.is_empty() {
                    &b.file.name
                } else {
                    &b.clean_name
                };
                an.to_lowercase().cmp(&bn.to_lowercase())
            })
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FileInfo, SearchResult};

    #[test]
    fn combine_origin_merges_ember_and_kad_sorted() {
        // Combined origins are de-duped and sorted alphabetically, so an
        // Ember+KAD hit renders deterministically.
        assert_eq!(combine_origin(ORIGIN_KAD, ORIGIN_EMBER), "Ember · KAD");
        assert_eq!(combine_origin(ORIGIN_EMBER, ORIGIN_KAD), "Ember · KAD");
    }

    #[test]
    fn combine_origin_handles_empty_and_identical_ember() {
        assert_eq!(combine_origin(ORIGIN_EMBER, ""), "Ember");
        assert_eq!(combine_origin("", ORIGIN_EMBER), "Ember");
        assert_eq!(combine_origin(ORIGIN_EMBER, ORIGIN_EMBER), "Ember");
    }

    fn sample(hash: &str, avail: u32, origin: &str) -> SearchResult {
        SearchResult {
            file: FileInfo {
                id: hash.into(),
                name: "a.bin".into(),
                path: String::new(),
                size: 1,
                hash: hash.into(),
                aich_hash: String::new(),
                extension: "bin".into(),
                modified_at: 0,
                priority: "normal".into(),
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
            availability: avail,
            file_type: String::new(),
            source_addresses: Vec::new(),
            rating: None,
            comment: None,
            media: None,
            spam_rating: 0,
            is_spam: false,
            clean_name: String::new(),
            result_origin: origin.into(),
        }
    }

    #[test]
    fn ed2k_origins_sum_availability_kad_uses_max() {
        let merged = merge_search_vecs(
            vec![sample("aa", 10, ORIGIN_SERVER_TCP)],
            vec![sample("aa", 7, ORIGIN_SERVER_UDP)],
        );
        assert_eq!(merged[0].availability, 17);

        let merged = merge_search_vecs(
            vec![sample("bb", 10, ORIGIN_KAD)],
            vec![sample("bb", 7, ORIGIN_SERVER_TCP)],
        );
        assert_eq!(merged[0].availability, 10);
    }

    #[test]
    fn result_matches_client_filters_size_ext_and_type() {
        let r = sample("aa", 3, ORIGIN_SERVER_TCP);
        assert!(result_matches_client_filters(
            &r,
            None,
            Some(1),
            Some(10),
            Some("bin"),
            Some(2)
        ));
        assert!(!result_matches_client_filters(
            &r,
            None,
            Some(2),
            None,
            None,
            None
        )); // size 1 < min 2
        assert!(!result_matches_client_filters(
            &r,
            None,
            None,
            None,
            Some("mp3"),
            None
        ));
        assert!(!result_matches_client_filters(
            &r,
            Some("Video"),
            None,
            None,
            None,
            None
        ));
    }

    #[test]
    fn arc_and_iso_become_pro_on_wire() {
        assert_eq!(wire_search_file_type(Some("Arc")), Some("Pro"));
        assert_eq!(wire_search_file_type(Some("Iso")), Some("Pro"));
        assert_eq!(wire_search_file_type(Some("Video")), Some("Video"));
        assert_eq!(client_search_file_type_filter(Some("Pro")), None);
        assert_eq!(
            client_search_file_type_filter(Some("Arc")),
            Some("Arc".into())
        );
    }
}
