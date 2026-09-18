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
    // Zero is "no maximum", which is what every other layer already reads it as:
    // `local_file_matches_filters`, the `has_filters` / `has_usable_filters`
    // gates, the wire encoder (`build_search_expression_with_node` drops zero
    // numerics) and the results table's own filter. This function was the sole
    // dissenter, and it is the one that decides what the user sees — so a `0`
    // typed into Max Size left the constraint off the wire and out of the
    // library scan, then stripped every row with a nonzero size on the way to
    // the UI. An empty tab, no error, and a filter that looked inactive.
    if let Some(max) = max_size {
        if max > 0 && r.file.size > max {
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

/// Peer addresses carried on a single search row.
///
/// Sized to what a download can actually consume, not to what the network can
/// report. `start_download` truncates the frontend's extras at
/// `MAX_EXTRA_SOURCES_IPC` (64) and the network task's seeding stops at
/// `MAX_SEED_EXTRA_SOURCES` (49), so every address past the sixty-fourth was
/// discarded on arrival — while still being merged, deduped, held in memory for
/// up to 15,000 rows per tab, and serialised across IPC on every
/// `search-results` batch. Source discovery finds the rest of a swarm anyway;
/// these are only the seeds that save it a round trip.
const MAX_SOURCE_ADDRS: usize = 64;

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

/// Which Ember content digest a merged row keeps.
///
/// Deliberately not "first non-empty wins", which is what this used to be. An
/// Ember keyword batch carries the plurality digest of the publishers *in that
/// batch*, and the closing batch is rebuilt from every record the walk gathered
/// — so the corrected value always arrives *after* the slice-local one it is
/// meant to replace, and keeping the first pinned a row to a digest a minority
/// of publishers claimed. That is the digest a download enforces at completion
/// on the user's click, and enforcing a wrong one fails verification on every
/// retry.
///
/// The library's own digest still outranks any network claim: it was computed
/// from the bytes on this disk (`known.met`), so a `Local` row is never
/// overwritten. Automatic seeding of the map a transfer enforces *without* a
/// click is unaffected — that still requires two publishers to agree
/// (`corroborated_ember_digest`).
///
/// Mirrored by `pickEmberDigest` in `src/lib/stores/search.ts`, which merges the
/// streamed batches a second time per tab, and pinned for both sides by
/// `scripts/fixtures/merge-contract.json`.
fn pick_ember_digest<'a>(
    existing_digest: &'a str,
    existing_origin: &str,
    incoming_digest: &'a str,
) -> &'a str {
    if incoming_digest.is_empty() {
        return existing_digest;
    }
    if existing_digest.is_empty() {
        return incoming_digest;
    }
    if existing_origin.contains(ORIGIN_LOCAL) {
        existing_digest
    } else {
        incoming_digest
    }
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

/// Whether a merge adopts the incoming row's spam explanation or keeps the one
/// it holds.
///
/// `spam_rating` merges with max and `is_spam` with OR, so the reason lists have
/// to follow the verdict that survived: a row showing a high score above a
/// signal list that only justifies a low one is worse than either alone, because
/// that list is what a user reads to decide whether to trust a file.
///
/// Mirrored by `takesIncomingSpamSignals` in `src/lib/stores/search.ts`, which
/// merges the streamed batches a second time per tab, and pinned for both sides
/// by `scripts/fixtures/merge-contract.json`.
pub(crate) fn takes_incoming_spam_signals(
    existing_is_spam: bool,
    existing_rating: u32,
    incoming_is_spam: bool,
    incoming_rating: u32,
) -> bool {
    (incoming_is_spam && !existing_is_spam) || incoming_rating > existing_rating
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
    // eMule `CSearchFile::AddSources` / `AddCompleteSources`: ed2k (server/UDP)
    // hits for the same hash *sum*; Kad takes the max. Mixed Kad+ed2k keeps
    // max. Both inputs are peer-supplied, so the result is held to
    // `MAX_PLAUSIBLE_SOURCES` — an uncapped `saturating_add` let a padded claim
    // keep growing across merges.
    let both_ed2k =
        is_ed2k_network_origin(&prev_origin) && is_ed2k_network_origin(&incoming.result_origin);
    existing.availability = clamp_source_count(
        if both_ed2k {
            existing.availability.saturating_add(incoming.availability)
        } else {
            existing.availability.max(incoming.availability)
        }
        .max(existing.source_addresses.len() as u32),
    );
    // The same rule, because eMule applies the same rule: `AddCompleteSources`
    // is `AddSources` with a different tag, summing on ed2k and maxing on Kad.
    // This used to max unconditionally, which undercounted every multi-server
    // result — two servers reporting three and five complete sources gave five
    // rather than eight — and, paired with a summed availability, put the two
    // columns on scales that could not be read against each other.
    existing.file.complete_sources = clamp_source_count(if both_ed2k {
        existing
            .file
            .complete_sources
            .saturating_add(incoming.file.complete_sources)
    } else {
        existing
            .file
            .complete_sources
            .max(incoming.file.complete_sources)
    });
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
    existing.file.ember_file_hash = pick_ember_digest(
        &existing.file.ember_file_hash,
        &prev_origin,
        &incoming.file.ember_file_hash,
    )
    .to_string();
    // An AICH root is not voted on the way the Ember digest is — it arrives
    // whole from an `h=` link or known.met — so first non-empty still wins here.
    if existing.file.aich_hash.is_empty() && !incoming.file.aich_hash.is_empty() {
        existing.file.aich_hash = incoming.file.aich_hash;
    }
    if existing.origin_server_ip.is_none() {
        existing.origin_server_ip = incoming.origin_server_ip;
    }
    if takes_incoming_spam_signals(
        existing.is_spam,
        existing.spam_rating,
        incoming.is_spam,
        incoming.spam_rating,
    ) {
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

/// Whether a row's Complete Sources figure means anything, or whether the only
/// honest answer is "unknown".
///
/// eMule decides this in `CSearchFile::IsComplete`, which returns unknown for
/// every Kademlia result, and leaves the Kad rollup of `FT_COMPLETE_SOURCES`
/// commented out in `CSearchList::AddToList` as "not yet supported". The reason
/// is in the shape of the number: a Kad publisher's `TAG_COMPLETE_SOURCES` is
/// its claim about a swarm it cannot see, whereas a server counts from its own
/// source table and an Ember row counts distinct signatures. So a Kad-only row
/// has a figure that should not be shown as if it were one of those.
///
/// `ORIGIN_NOTES` is not enough on its own either — a Kad note carries no
/// source accounting at all.
pub fn complete_sources_known(origin: &str) -> bool {
    origin.split('·').any(|part| {
        matches!(
            part.trim(),
            ORIGIN_SERVER_TCP | ORIGIN_SERVER_UDP | ORIGIN_EMBER | ORIGIN_LOCAL
        )
    })
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
    // Rows whose complete count is unknown rank as zero on that key, so they
    // are not ordered by a figure the UI refuses to show them with. eMule ends
    // up in the same place: the Kad rollup of `FT_COMPLETE_SOURCES` is left at
    // zero, so its Kad rows sort at the bottom of that column too.
    let ranked_complete = |r: &SearchResult| {
        if complete_sources_known(&r.result_origin) {
            clamp_source_count(r.file.complete_sources)
        } else {
            0
        }
    };
    v.sort_by(|a, b| {
        // Rank on clamped counts: both fields are remote-controlled, so a row
        // that has never been merged (and therefore never passed through the
        // cap in `merge_into`) must not buy the top slot with a padded number.
        ranked_complete(b)
            .cmp(&ranked_complete(a))
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

    /// `AddCompleteSources` is `AddSources` with a different tag: eMule sums
    /// both across ed2k replies and maxes both on Kad. Maxing the complete
    /// count while summing availability left the two columns on scales that
    /// could not be compared — a five-server result reporting three complete
    /// sources each showed fifteen sources and three complete.
    #[test]
    fn complete_sources_follow_the_same_rule_as_availability() {
        let with_complete = |hash: &str, avail: u32, complete: u32, origin: &str| {
            let mut r = sample(hash, avail, origin);
            r.file.complete_sources = complete;
            r
        };

        let merged = merge_search_vecs(
            vec![with_complete("aa", 10, 3, ORIGIN_SERVER_TCP)],
            vec![with_complete("aa", 7, 5, ORIGIN_SERVER_UDP)],
        );
        assert_eq!(merged[0].availability, 17);
        assert_eq!(merged[0].file.complete_sources, 8, "ed2k replies sum");

        let merged = merge_search_vecs(
            vec![with_complete("bb", 10, 3, ORIGIN_KAD)],
            vec![with_complete("bb", 7, 5, ORIGIN_SERVER_TCP)],
        );
        assert_eq!(merged[0].availability, 10);
        assert_eq!(
            merged[0].file.complete_sources, 5,
            "a Kad estimate and a server count describe overlapping swarms, so \
             the larger stands rather than their sum"
        );
    }

    /// Summing each responder's complete count cannot exceed the summed
    /// availability, so long as no single responder claims more complete
    /// sources than it has sources. That is the invariant the old max-against-
    /// sum pairing broke, and the reason eMule's two columns can be read as a
    /// ratio.
    #[test]
    fn summed_complete_sources_stay_within_summed_availability() {
        let with_complete = |avail: u32, complete: u32, origin: &str| {
            let mut r = sample("cc", avail, origin);
            r.file.complete_sources = complete;
            r
        };
        let merged = merge_search_vecs(
            vec![with_complete(10, 10, ORIGIN_SERVER_TCP)],
            vec![with_complete(15, 15, ORIGIN_SERVER_UDP)],
        );
        assert_eq!(merged[0].availability, 25);
        assert_eq!(merged[0].file.complete_sources, 25);
        assert!(merged[0].file.complete_sources <= merged[0].availability);
    }

    /// eMule shows no Complete Sources figure for a Kad result at all
    /// (`CSearchFile::IsComplete` returns unknown, and the Kad rollup of
    /// `FT_COMPLETE_SOURCES` is commented out as "not yet supported").
    #[test]
    fn complete_sources_are_known_only_where_something_counted_them() {
        assert!(complete_sources_known(ORIGIN_SERVER_TCP));
        assert!(complete_sources_known(ORIGIN_SERVER_UDP));
        assert!(complete_sources_known(ORIGIN_EMBER));
        assert!(complete_sources_known(ORIGIN_LOCAL));

        assert!(!complete_sources_known(ORIGIN_KAD));
        assert!(!complete_sources_known(ORIGIN_NOTES));
        assert!(!complete_sources_known(""));
        assert!(!complete_sources_known(&combine_origin(
            ORIGIN_KAD,
            ORIGIN_NOTES
        )));

        // One trustworthy counter is enough: the row carries a real count plus
        // a Kad sighting, not a Kad guess.
        assert!(complete_sources_known(&combine_origin(
            ORIGIN_KAD,
            ORIGIN_SERVER_TCP
        )));
        assert!(complete_sources_known(&combine_origin(
            ORIGIN_KAD,
            ORIGIN_EMBER
        )));
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

    /// A zero size bound is how every other layer spells "no bound", so this
    /// one has to agree or the layers contradict each other on the same row.
    /// `search_files` hands the identical `max_size` to the library scan and to
    /// this function: the scan kept the row, this dropped it, and the search
    /// came back empty while the filter panel showed nothing was constraining
    /// it.
    #[test]
    fn a_zero_size_bound_constrains_nothing() {
        let r = sample("aa", 3, ORIGIN_SERVER_TCP); // size 1
        assert!(result_matches_client_filters(
            &r, None, None, Some(0), None, None
        ));
        assert!(result_matches_client_filters(
            &r, None, Some(0), Some(0), None, None
        ));
        // A real bound still bounds.
        let mut big = sample("bb", 3, ORIGIN_SERVER_TCP);
        big.file.size = 100;
        assert!(result_matches_client_filters(
            &big, None, None, Some(100), None, None
        ));
        assert!(!result_matches_client_filters(
            &big, None, None, Some(99), None, None
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

    /// `src/lib/stores/search.ts` mirrors `result_key`, `combine_origin`,
    /// `pick_ember_digest`, `MAX_PLAUSIBLE_SOURCES`, `MAX_SOURCE_ADDRS` and the
    /// first-non-empty field rules — it merges the streamed batches a second time,
    /// per tab — and the two were held together only by a code comment.
    /// `scripts/fixtures/merge-contract.json` is the shared source of truth for
    /// the rules that must agree; `scripts/merge-contract.test.mjs` checks the
    /// TypeScript side against the same file, so a divergence fails on whichever
    /// side moved.
    ///
    /// Only genuinely shared rules are in the fixture. The deliberate
    /// divergences stay out of it: the frontend takes `max` for both source
    /// counts where `merge_into` sums them across ed2k replies — the backend
    /// has already summed within a network, and emits the absolute running
    /// total (`ed2k_noted_availability` / `ed2k_noted_complete_sources`), so a
    /// second sum over the batches would double it — it keeps the first name
    /// where `merge_search_vecs` elects one by vote, and both sides cap
    /// `source_addresses` at `MAX_SOURCE_ADDRS`.
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
    fn ember_digest_choice_matches_the_shared_merge_contract() {
        let fixture = merge_contract_fixture();
        let cases = fixture["ember_digest_cases"]
            .as_array()
            .expect("fixture has ember_digest_cases");
        assert!(cases.len() >= 6, "fixture lost its ember_digest cases");
        for case in cases {
            let existing = case["existing_digest"].as_str().expect("case existing");
            let origin = case["existing_origin"].as_str().expect("case origin");
            let incoming = case["incoming_digest"].as_str().expect("case incoming");
            assert_eq!(
                pick_ember_digest(existing, origin, incoming),
                case["chosen"].as_str().expect("case chosen"),
                "{}",
                case["name"].as_str().unwrap_or_default()
            );
        }
    }

    /// The whole point of the rule: the closing batch of an Ember search rebuilds
    /// the digest from every publisher the walk reached, and it arrives as a
    /// merge into a row an earlier slice already gave a digest to.
    #[test]
    fn a_corrected_ember_digest_replaces_the_one_an_earlier_batch_set() {
        let mut early = sample("aa", 1, ORIGIN_EMBER);
        early.file.ember_file_hash = "ab".repeat(32);
        let mut corrected = sample("aa", 2, ORIGIN_EMBER);
        corrected.file.ember_file_hash = "cd".repeat(32);

        let merged = merge_search_vecs(vec![early], vec![corrected]);
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0].file.ember_file_hash,
            "cd".repeat(32),
            "the cumulative rebuild has to win over the slice it corrects"
        );

        // ...but never over the library's own digest.
        let mut library = sample("bb", 1, ORIGIN_LOCAL);
        library.file.ember_file_hash = "ab".repeat(32);
        let mut network = sample("bb", 2, ORIGIN_EMBER);
        network.file.ember_file_hash = "cd".repeat(32);
        let merged = merge_search_vecs(vec![library], vec![network]);
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0].file.ember_file_hash,
            "ab".repeat(32),
            "known.met beats a publisher plurality"
        );
    }

    /// The rule that decides which spam explanation a merged row shows. The
    /// frontend merges the same batches again per tab, and it used to take the
    /// incoming reasons whenever the incoming row was flagged — ignoring the
    /// score, which merges with max — so a row could show 85/60 above a list
    /// that only justified 40.
    #[test]
    fn spam_signal_choice_matches_the_shared_merge_contract() {
        let fixture = merge_contract_fixture();
        let cases = fixture["spam_signal_cases"]
            .as_array()
            .expect("fixture has spam_signal_cases");
        assert!(cases.len() >= 6, "fixture lost its spam_signal cases");
        for case in cases {
            let existing_is_spam = case["existing_is_spam"].as_bool().expect("case existing flag");
            let existing_rating = case["existing_rating"].as_u64().expect("case existing rating");
            let incoming_is_spam = case["incoming_is_spam"].as_bool().expect("case incoming flag");
            let incoming_rating = case["incoming_rating"].as_u64().expect("case incoming rating");
            assert_eq!(
                takes_incoming_spam_signals(
                    existing_is_spam,
                    existing_rating as u32,
                    incoming_is_spam,
                    incoming_rating as u32,
                ),
                case["takes_incoming"].as_bool().expect("case expectation"),
                "{}",
                case["name"].as_str().unwrap_or_default()
            );
        }
    }

    /// End to end through the real merge: a weaker flagged batch must not swap
    /// the explanation out from under the score that survives.
    #[test]
    fn a_weaker_flagged_batch_does_not_replace_the_explanation() {
        let reason = |text: &str| crate::search::spam::SpamReason {
            code: text.to_string(),
            weight: None,
            percent: None,
            count: None,
            votes: None,
            total: None,
            text: text.to_string(),
        };

        let mut strong = sample("aa", 1, ORIGIN_SERVER_TCP);
        strong.is_spam = true;
        strong.spam_rating = 85;
        strong.spam_reasons = vec!["known_hash".to_string()];
        strong.spam_reason_details = vec![reason("known_hash")];

        let mut weak = sample("aa", 1, ORIGIN_KAD);
        weak.is_spam = true;
        weak.spam_rating = 40;
        weak.spam_reasons = vec!["fake_pattern".to_string()];
        weak.spam_reason_details = vec![reason("fake_pattern")];

        let merged = merge_search_vecs(vec![strong], vec![weak]);
        assert_eq!(merged[0].spam_rating, 85);
        assert_eq!(
            merged[0].spam_reasons,
            vec!["known_hash".to_string()],
            "the explanation has to match the score the row kept"
        );
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
