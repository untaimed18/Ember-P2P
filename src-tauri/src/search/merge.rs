//! Dedupe and merge search rows by ed2k hash (fallback: name + size) for multi-source results.

use std::collections::HashMap;

use crate::types::SearchResult;

pub const ORIGIN_KAD: &str = "KAD";
pub const ORIGIN_SERVER_TCP: &str = "Server";
pub const ORIGIN_SERVER_UDP: &str = "UDP";
pub const ORIGIN_LOCAL: &str = "Local";
pub const ORIGIN_NOTES: &str = "Notes";
pub const ORIGIN_EMBER: &str = "Ember";

fn result_key(r: &SearchResult) -> String {
    if !r.file.hash.is_empty() {
        r.file.hash.clone()
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
    existing.result_origin = combine_origin(&existing.result_origin, &incoming.result_origin);
    for addr in incoming.source_addresses {
        if existing.source_addresses.len() >= MAX_SOURCE_ADDRS {
            break;
        }
        if !addr.is_empty() && !existing.source_addresses.contains(&addr) {
            existing.source_addresses.push(addr);
        }
    }
    existing.availability = existing
        .availability
        .max(incoming.availability)
        .max(existing.source_addresses.len() as u32);
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
        let em = existing.media.get_or_insert_with(crate::types::MediaMetadata::default);
        if em.duration.is_none() { em.duration = inc_media.duration; }
        if em.bitrate.is_none() { em.bitrate = inc_media.bitrate; }
        if em.codec.is_none() { em.codec = inc_media.codec; }
        if em.artist.is_none() { em.artist = inc_media.artist; }
        if em.album.is_none() { em.album = inc_media.album; }
        if em.title.is_none() { em.title = inc_media.title; }
    }
    if incoming.file.name.len() > existing.file.name.len() {
        existing.file.name = incoming.file.name;
    }
}

/// Merge two result lists; rows with the same hash are combined. Output is sorted for display.
pub fn merge_search_vecs(primary: Vec<SearchResult>, secondary: Vec<SearchResult>) -> Vec<SearchResult> {
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
                let an = if a.clean_name.is_empty() { &a.file.name } else { &a.clean_name };
                let bn = if b.clean_name.is_empty() { &b.file.name } else { &b.clean_name };
                an.to_lowercase().cmp(&bn.to_lowercase())
            })
    });
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
