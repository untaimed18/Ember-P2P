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

/// Plausibility ceiling for peer-reported swarm counts.
///
/// `complete_sources` and `availability` arrive straight off the wire, so a
/// peer answering with `u32::MAX` sorted above every honest hit — and the spam
/// filter, the intended counter, only engages at 8+ results and is skipped
/// under the `relaxed` profile, so a small poisoned batch was both unflagged
/// and top-ranked. eD2k carries this same count as a `u16` on the wire
/// (OP_FILESTATUS), and the most-sighted files on the network sit in the low
/// thousands of sources, so `u16::MAX` is protocol-plausible and an order of
/// magnitude above anything real: it never touches an honest row.
///
/// Pinned by `scripts/fixtures/merge-contract.json`, the shared source of truth
/// this and the frontend's mirror in `src/lib/stores/search.ts` are both tested
/// against (see `merge_contract_fixture` below).
const MAX_PLAUSIBLE_SOURCES: u32 = u16::MAX as u32;

#[inline]
pub fn clamp_source_count(count: u32) -> u32 {
    count.min(MAX_PLAUSIBLE_SOURCES)
}

/// Filename ballots for one merged row: name → (votes, first-seen order).
///
/// eMule votes on the filename across the sources advertising a hash. The old
/// rule was "longest name wins", and length is entirely attacker-chosen: ed2k
/// hashes are public, so one reply carrying a real hash with a padded name
/// renamed the merged row — and, because the UI hands `file.name` to
/// `start_download`, the file written to disk as well.
type NameVotes = HashMap<String, (u32, usize)>;

fn vote_name(votes: &mut NameVotes, name: &str) {
    if name.is_empty() {
        return;
    }
    let first_seen = votes.len();
    let entry = votes.entry(name.to_string()).or_insert((0, first_seen));
    entry.0 = entry.0.saturating_add(1);
}

/// Most advertised name, with the first-seen name breaking a tie.
fn elected_name(votes: &NameVotes) -> Option<&str> {
    votes
        .iter()
        .max_by(|(_, a), (_, b)| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)))
        .map(|(name, _)| name.as_str())
}

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
    // availability; Kad uses max. Mixed Kad+ed2k keeps max. Both inputs are
    // peer-supplied, so the result is held to `MAX_PLAUSIBLE_SOURCES` — an
    // uncapped `saturating_add` let a padded claim keep growing across merges.
    existing.availability = clamp_source_count(
        if is_ed2k_network_origin(&prev_origin) && is_ed2k_network_origin(&incoming.result_origin) {
            existing
                .availability
                .saturating_add(incoming.availability)
                .max(existing.source_addresses.len() as u32)
        } else {
            existing
                .availability
                .max(incoming.availability)
                .max(existing.source_addresses.len() as u32)
        },
    );
    existing.file.complete_sources = clamp_source_count(
        existing
            .file
            .complete_sources
            .max(incoming.file.complete_sources),
    );
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
    // The filename is *not* decided here: `merge_search_vecs` elects it by vote
    // (see `NameVotes`). Keep the name we already have until that vote is
    // counted.
    //
    // That vote arbitrates the network row against the local-library row, not
    // "every source that advertised this hash" as this used to say: its only
    // caller receives results that `convert_search_results` has already
    // collapsed to one row per hash, and eD2K server hits never reach it at all.
    // Across DHT publishers the name is still decided upstream by
    // `name_spam_penalty`, which a responder can steer by choosing a name that
    // scores lower than the honest one — better than the old "longest wins", but
    // not a cross-source majority.
    if existing.file.name.is_empty() && !incoming.file.name.is_empty() {
        existing.file.name = incoming.file.name;
    }
    // Prefer a real Ember content digest / AICH root when either side has one
    // (network hits often arrive empty; local library hits carry known.met).
    if existing.file.ember_file_hash.is_empty() && !incoming.file.ember_file_hash.is_empty() {
        existing.file.ember_file_hash = incoming.file.ember_file_hash;
    }
    if existing.file.aich_hash.is_empty() && !incoming.file.aich_hash.is_empty() {
        existing.file.aich_hash = incoming.file.aich_hash;
    }
    if existing.origin_server_ip.is_none() {
        existing.origin_server_ip = incoming.origin_server_ip;
    }
    if (incoming.is_spam && !existing.is_spam) || incoming.spam_rating > existing.spam_rating {
        // Both lists describe the same verdict, so they move together — a row
        // whose English came from one scoring pass and whose codes came from
        // another would render two different explanations.
        existing.spam_reasons = incoming.spam_reasons;
        existing.spam_reason_details = incoming.spam_reason_details;
    }
    existing.spam_rating = existing.spam_rating.max(incoming.spam_rating);
    existing.is_spam = existing.is_spam || incoming.is_spam;
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
    // Ballots live here rather than on `SearchResult`: that type is serialized
    // straight to the frontend, so it must not grow a merge-only field.
    let mut name_votes: HashMap<String, NameVotes> = HashMap::new();
    for r in primary.into_iter().chain(secondary) {
        let k = result_key(&r);
        vote_name(name_votes.entry(k.clone()).or_default(), &r.file.name);
        if let Some(mut e) = map.remove(&k) {
            merge_into(&mut e, r);
            map.insert(k, e);
        } else {
            map.insert(k, r);
        }
    }
    for (key, result) in map.iter_mut() {
        if let Some(elected) = name_votes.get(key).and_then(elected_name) {
            if result.file.name != elected {
                result.file.name = elected.to_string();
            }
        }
    }
    let mut out: Vec<SearchResult> = map.into_values().collect();
    sort_search_results(&mut out);
    out
}

pub fn sort_search_results(v: &mut [SearchResult]) {
    v.sort_by(|a, b| {
        // Rank on clamped counts: both fields are remote-controlled, so a row
        // that has never been merged (and therefore never passed through the
        // cap in `merge_into`) must not buy the top slot with a padded number.
        clamp_source_count(b.file.complete_sources)
            .cmp(&clamp_source_count(a.file.complete_sources))
            .then_with(|| {
                clamp_source_count(b.availability).cmp(&clamp_source_count(a.availability))
            })
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

    #[test]
    fn clamp_source_count_caps_at_u16_max() {
        assert_eq!(clamp_source_count(0), 0);
        assert_eq!(clamp_source_count(MAX_PLAUSIBLE_SOURCES), MAX_PLAUSIBLE_SOURCES);
        assert_eq!(clamp_source_count(u32::MAX), MAX_PLAUSIBLE_SOURCES);
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
                ember_file_hash: String::new(),
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
                friends_only: false,
                shared_kad: false,
                shared_ed2k: false,
                shared_ember: false,
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
            origin_server_ip: None,
            spam_reasons: Vec::new(),
            spam_reason_details: Vec::new(),
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
    fn merge_prefers_nonempty_ember_file_hash() {
        let mut a = sample("cc", 1, ORIGIN_SERVER_TCP);
        let mut b = sample("cc", 1, ORIGIN_EMBER);
        b.file.ember_file_hash = "ab".repeat(32);
        merge_into(&mut a, b);
        assert_eq!(a.file.ember_file_hash, "ab".repeat(32));

        let mut keep = sample("dd", 1, ORIGIN_EMBER);
        keep.file.ember_file_hash = "cd".repeat(32);
        let empty = sample("dd", 2, ORIGIN_KAD);
        merge_into(&mut keep, empty);
        assert_eq!(keep.file.ember_file_hash, "cd".repeat(32));
    }

    fn named(hash: &str, name: &str, origin: &str) -> SearchResult {
        let mut r = sample(hash, 1, origin);
        r.file.name = name.into();
        r
    }

    #[test]
    fn padded_name_cannot_outvote_the_majority_name() {
        // Two honest sources advertise the real name; one attacker answers with
        // the same (public) hash and a padded name. Length used to decide.
        let merged = merge_search_vecs(
            vec![
                named("ee", "ubuntu.iso", ORIGIN_SERVER_TCP),
                named("ee", "ubuntu.iso", ORIGIN_SERVER_UDP),
            ],
            vec![named("ee", "ubuntu.iso.VERIFIED.NO.VIRUS.exe", ORIGIN_KAD)],
        );
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].file.name, "ubuntu.iso");
    }

    #[test]
    fn name_vote_ties_keep_the_first_seen_name() {
        let merged = merge_search_vecs(
            vec![named("ff", "clip.avi", ORIGIN_SERVER_TCP)],
            vec![named("ff", "clip.avi.HD.REPACK.scr", ORIGIN_KAD)],
        );
        assert_eq!(merged[0].file.name, "clip.avi");
    }

    #[test]
    fn merge_fills_an_empty_name_from_the_other_source() {
        let merged = merge_search_vecs(
            vec![named("gg", "", ORIGIN_KAD)],
            vec![named("gg", "real.bin", ORIGIN_SERVER_TCP)],
        );
        assert_eq!(merged[0].file.name, "real.bin");
    }

    #[test]
    fn inflated_source_claims_are_clamped_for_ranking() {
        // A peer claiming u32::MAX must not outrank a result already at the
        // plausibility ceiling: the two tie and the name tiebreak decides.
        let mut liar = named("hh", "zzz-fake.bin", ORIGIN_KAD);
        liar.availability = u32::MAX;
        liar.file.complete_sources = u32::MAX;
        let mut honest = named("ii", "aaa-real.bin", ORIGIN_SERVER_TCP);
        honest.availability = MAX_PLAUSIBLE_SOURCES;
        honest.file.complete_sources = MAX_PLAUSIBLE_SOURCES;
        let mut v = vec![liar, honest];
        sort_search_results(&mut v);
        assert_eq!(v[0].file.name, "aaa-real.bin");
    }

    #[test]
    fn merged_counts_are_capped_at_the_plausible_ceiling() {
        let merged = merge_search_vecs(
            vec![sample("jj", u32::MAX, ORIGIN_SERVER_TCP)],
            vec![sample("jj", u32::MAX, ORIGIN_SERVER_UDP)],
        );
        assert_eq!(merged[0].availability, MAX_PLAUSIBLE_SOURCES);
    }

    /// `src/lib/stores/search.ts` mirrors `result_key`, `combine_origin` and
    /// `MAX_PLAUSIBLE_SOURCES` — it merges the streamed batches a second time,
    /// per tab — and the two were held together only by a code comment.
    /// `scripts/fixtures/merge-contract.json` is the shared source of truth for
    /// the rules that must agree; `scripts/merge-contract.test.mjs` checks the
    /// TypeScript side against the same file, so a divergence fails on whichever
    /// side moved.
    ///
    /// Only genuinely shared rules are in the fixture. The deliberate
    /// divergences stay out of it: the frontend takes `max` where `merge_into`
    /// sums ed2k availability (the backend has already summed within a network),
    /// it keeps the first name where `merge_search_vecs` elects one by vote, and
    /// both sides cap `source_addresses` at `MAX_SOURCE_ADDRS`.
    fn merge_contract_fixture() -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../scripts/fixtures/merge-contract.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_str(&raw).expect("merge-contract.json must be valid JSON")
    }

    #[test]
    fn result_key_matches_the_shared_merge_contract() {
        let fixture = merge_contract_fixture();
        let cases = fixture["result_key_cases"]
            .as_array()
            .expect("fixture has result_key_cases");
        assert!(cases.len() >= 5, "fixture lost its result_key cases");
        for case in cases {
            let f = &case["file"];
            let mut r = sample("", 0, ORIGIN_KAD);
            r.file.hash = f["hash"].as_str().expect("case hash").to_string();
            r.file.id = f["id"].as_str().expect("case id").to_string();
            r.file.path = f["path"].as_str().expect("case path").to_string();
            r.file.name = f["name"].as_str().expect("case name").to_string();
            r.file.size = f["size"].as_u64().expect("case size");
            assert_eq!(
                result_key(&r),
                case["key"].as_str().expect("case key"),
                "{}",
                case["name"].as_str().unwrap_or_default()
            );
        }
    }

    #[test]
    fn combine_origin_matches_the_shared_merge_contract() {
        let fixture = merge_contract_fixture();
        let cases = fixture["combine_origin_cases"]
            .as_array()
            .expect("fixture has combine_origin_cases");
        assert!(cases.len() >= 8, "fixture lost its combine_origin cases");
        for case in cases {
            let a = case["a"].as_str().expect("case a");
            let b = case["b"].as_str().expect("case b");
            assert_eq!(
                combine_origin(a, b),
                case["combined"].as_str().expect("case combined"),
                "combine_origin({a:?}, {b:?})"
            );
        }
    }

    #[test]
    fn source_count_ceiling_matches_the_shared_merge_contract() {
        let fixture = merge_contract_fixture();
        assert_eq!(
            u64::from(MAX_PLAUSIBLE_SOURCES),
            fixture["max_plausible_sources"]
                .as_u64()
                .expect("fixture has max_plausible_sources"),
            "the ceiling drifted from the shared contract"
        );
        let cases = fixture["clamp_source_count_cases"]
            .as_array()
            .expect("fixture has clamp_source_count_cases");
        assert!(cases.len() >= 4, "fixture lost its clamp cases");
        for case in cases {
            let count = case["count"].as_u64().expect("case count");
            let count = u32::try_from(count).expect("counts are u32 on the wire");
            assert_eq!(
                u64::from(clamp_source_count(count)),
                case["clamped"].as_u64().expect("case clamped"),
                "clamp_source_count({count})"
            );
        }
    }

    #[test]
    fn source_address_cap_matches_the_shared_merge_contract() {
        let fixture = merge_contract_fixture();
        assert_eq!(
            MAX_SOURCE_ADDRS as u64,
            fixture["max_source_addrs"]
                .as_u64()
                .expect("fixture has max_source_addrs"),
            "the source-address cap drifted from the shared contract"
        );
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
